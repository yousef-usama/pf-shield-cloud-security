"""Unit test suite for PF-Shield IAM Quarantine SOAR Playbook using moto mock_aws."""

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
def iam_environment():
    """Setup mock AWS resources for IAM quarantine test."""
    with mock_aws():
        iam = boto3.client("iam", region_name="me-central-1")
        sns = boto3.client("sns", region_name="me-central-1")

        # 1. Create compromised test user
        user_name = "compromised-broker-service-user"
        iam.create_user(UserName=user_name)

        # 2. Generate active access key for compromised user
        key_res = iam.create_access_key(UserName=user_name)["AccessKey"]
        access_key_id = key_res["AccessKeyId"]

        # 3. Create mock quarantine policy
        quarantine_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        policy_res = iam.create_policy(
            PolicyName="pf-soar-quarantine-deny-all",
            PolicyDocument=json.dumps(quarantine_doc),
        )
        quarantine_policy_arn = policy_res["Policy"]["Arn"]

        # 4. Create mock SNS topic
        topic_res = sns.create_topic(Name="pf-security-incidents")
        sns_topic_arn = topic_res["TopicArn"]

        os.environ["QUARANTINE_POLICY_ARN"] = quarantine_policy_arn
        os.environ["SNS_TOPIC_ARN"] = sns_topic_arn

        yield {
            "user_name": user_name,
            "access_key_id": access_key_id,
            "quarantine_policy_arn": quarantine_policy_arn,
            "sns_topic_arn": sns_topic_arn,
        }


def test_iam_quarantine_deactivates_keys_and_attaches_deny_all(iam_environment):
    """Test that compromised IAM users are frozen and their active keys deactivated."""
    from src.soar import playbook_iam_quarantine

    user_name = iam_environment["user_name"]
    access_key_id = iam_environment["access_key_id"]

    event = {
        "version": "0",
        "id": "iam-event-01",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "detail": {
            "eventSource": "iam.amazonaws.com",
            "eventName": "PutUserPolicy",
            "requestParameters": {
                "userName": user_name,
                "policyName": "UnauthorizedPrivilegeEscalation",
            },
        },
    }

    response = playbook_iam_quarantine.lambda_handler(event, None)
    assert response["statusCode"] == 200

    body = json.loads(response["body"])
    assert body["status"] == "CONTAINED"
    assert body["principal_quarantined"] == user_name
    assert access_key_id in body["revoked_access_keys"]

    # Verify quarantine policy was attached to the user
    iam = boto3.client("iam", region_name="me-central-1")
    attached = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
    attached_arns = [p["PolicyArn"] for p in attached]
    assert iam_environment["quarantine_policy_arn"] in attached_arns

    # Verify access key is now Inactive
    keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    target_key = next(k for k in keys if k["AccessKeyId"] == access_key_id)
    assert target_key["Status"] == "Inactive"


def test_iam_quarantine_simulated_attack_event(iam_environment):
    """Test attack simulation payload against IAM quarantine handler."""
    from src.soar import playbook_iam_quarantine

    user_name = iam_environment["user_name"]

    event = {
        "version": "0",
        "source": "pf.security.simulation",
        "detail-type": "Simulated IAM Credential Compromise",
        "detail": {
            "compromised_principal": user_name,
            "principal_type": "User",
        },
    }

    response = playbook_iam_quarantine.lambda_handler(event, None)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "CONTAINED"
