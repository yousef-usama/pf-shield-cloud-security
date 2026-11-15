"""Unit test suite for PF-Shield S3 Lockdown SOAR Playbook using moto mock_aws."""

from __future__ import annotations

import json
import os
import boto3
import pytest
from moto import mock_aws

# Set test environment credentials
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "me-central-1"


@pytest.fixture
def aws_environment():
    """Setup mock AWS resources for S3 lockdown test."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="me-central-1")
        iam = boto3.client("iam", region_name="me-central-1")
        sns = boto3.client("sns", region_name="me-central-1")

        # 1. Create target test bucket with disabled public access block
        bucket_name = "pf-kyc-vault-test-bucket"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "me-central-1"},
        )
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )

        # 2. Create mock quarantine policy
        quarantine_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        policy_res = iam.create_policy(
            PolicyName="pf-soar-quarantine-deny-all",
            PolicyDocument=json.dumps(quarantine_doc),
        )
        quarantine_policy_arn = policy_res["Policy"]["Arn"]

        # 3. Create mock offending role
        assume_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_name = "compromised-app-role"
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_doc))

        # 4. Create mock SNS topic
        topic_res = sns.create_topic(Name="pf-security-incidents")
        sns_topic_arn = topic_res["TopicArn"]

        os.environ["QUARANTINE_POLICY_ARN"] = quarantine_policy_arn
        os.environ["SNS_TOPIC_ARN"] = sns_topic_arn

        yield {
            "bucket_name": bucket_name,
            "role_name": role_name,
            "quarantine_policy_arn": quarantine_policy_arn,
            "sns_topic_arn": sns_topic_arn,
        }


def test_s3_lockdown_cloudtrail_event(aws_environment):
    """Test that S3 PublicAccessBlock is restored and principal is quarantined on CloudTrail event."""
    from src.soar import playbook_s3_lockdown

    bucket_name = aws_environment["bucket_name"]
    role_name = aws_environment["role_name"]

    # Sample EventBridge event triggered by CloudTrail PutBucketPublicAccessBlock
    event = {
        "version": "0",
        "id": "test-event-id-01",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "detail": {
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPublicAccessBlock",
            "requestParameters": {"bucketName": bucket_name},
            "userIdentity": {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::123456789012:assumed-role/{role_name}/session-1",
            },
        },
    }

    # Execute Lambda handler
    response = playbook_s3_lockdown.lambda_handler(event, None)
    assert response["statusCode"] == 200

    body = json.loads(response["body"])
    assert body["status"] == "CONTAINED"
    assert body["bucket_remediated"] == bucket_name
    assert body["principal_quarantined"] == role_name

    # Verify S3 Public Access Block was strictly enforced (all 4 flags = True)
    s3 = boto3.client("s3", region_name="me-central-1")
    pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    assert pab["BlockPublicAcls"] is True
    assert pab["IgnorePublicAcls"] is True
    assert pab["BlockPublicPolicy"] is True
    assert pab["RestrictPublicBuckets"] is True

    # Verify IAM Quarantine policy was attached to offending role
    iam = boto3.client("iam", region_name="me-central-1")
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    attached_arns = [p["PolicyArn"] for p in attached]
    assert aws_environment["quarantine_policy_arn"] in attached_arns


def test_s3_lockdown_simulated_attack_event(aws_environment):
    """Test that custom attack simulation payloads trigger instant containment."""
    from src.soar import playbook_s3_lockdown

    bucket_name = aws_environment["bucket_name"]
    role_name = aws_environment["role_name"]

    event = {
        "version": "0",
        "source": "pf.security.simulation",
        "detail-type": "Simulated S3 Public Exposure Attack",
        "detail": {
            "affected_bucket": bucket_name,
            "offending_principal": role_name,
            "principal_type": "Role",
        },
    }

    response = playbook_s3_lockdown.lambda_handler(event, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "CONTAINED"
