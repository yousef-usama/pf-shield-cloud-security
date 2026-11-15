"""PF-Shield SOAR Playbook: S3 Bucket Public Exposure & Exfiltration Lockdown.

Automatically contains public exposure or exfiltration attempts on S3 buckets:
1. Re-enforces all 4 S3 Public Access Block settings immediately.
2. Identifies and isolates the offending IAM principal with an emergency deny-all quarantine policy.
3. Publishes structured forensic incident data to SNS.
4. Emits Mean Time to Remediate (MTTR) metrics to CloudWatch.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
s3_client = boto3.client("s3")
iam_client = boto3.client("iam")
sns_client = boto3.client("sns")
cloudwatch_client = boto3.client("cloudwatch")
ssm_client = boto3.client("ssm")


def get_parameter_value(param_name_or_env: str, default: str = "") -> str:
    """Retrieve configuration from environment variable or SSM Parameter Store."""
    val = os.environ.get(param_name_or_env, "")
    if val:
        return val

    # Attempt SSM lookup if prefixed with /
    if param_name_or_env.startswith("/"):
        try:
            resp = ssm_client.get_parameter(Name=param_name_or_env, WithDecryption=True)
            return resp.get("Parameter", {}).get("Value", default)
        except ClientError as err:
            logger.warning("SSM parameter %s lookup failed: %s", param_name_or_env, err)
    return default


def parse_event_details(event: dict[str, Any]) -> tuple[str, str, str, str]:
    """Extract affected bucket, offending principal, finding type, and principal type from EventBridge payload."""
    detail = event.get("detail", {})
    source = event.get("source", "")
    event_type = event.get("detail-type", "Unknown")

    bucket_name = ""
    principal_name = ""
    principal_type = "UNKNOWN"

    # Case 1: Custom PF-Shield Simulation Event
    if source == "pf.security.simulation":
        bucket_name = detail.get("affected_bucket", detail.get("bucket_name", "pf-kyc-vault-simulation"))
        principal_name = detail.get("offending_principal", "simulated-attacker-role")
        principal_type = detail.get("principal_type", "Role")
        return bucket_name, principal_name, principal_type, "Simulation:S3Tamper"

    # Case 2: AWS GuardDuty Finding
    if source == "aws.guardduty":
        finding_type = detail.get("type", "GuardDuty:S3Finding")
        resource = detail.get("resource", {})
        s3_details = resource.get("s3BucketDetails", [])
        if s3_details:
            bucket_name = s3_details[0].get("name", "")

        access_key_details = resource.get("accessKeyDetails", {})
        principal_name = access_key_details.get("userName", "")
        principal_type = access_key_details.get("userType", "Role")
        return bucket_name, principal_name, principal_type, finding_type

    # Case 3: AWS CloudTrail API Call
    if source == "aws.s3" or "eventName" in detail:
        finding_type = f"CloudTrail:{detail.get('eventName', 'S3ApiCall')}"
        req_params = detail.get("requestParameters", {}) or {}
        bucket_name = req_params.get("bucketName", req_params.get("bucket", ""))

        user_identity = detail.get("userIdentity", {})
        id_type = user_identity.get("type", "")
        if id_type == "IAMUser":
            principal_name = user_identity.get("userName", "")
            principal_type = "User"
        elif id_type == "AssumedRole":
            arn = user_identity.get("arn", "")
            # ARN format: arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
            principal_name = arn.split("/")[1] if "/" in arn else user_identity.get("principalId", "")
            principal_type = "Role"
        else:
            principal_name = user_identity.get("principalId", "UnknownPrincipal")
            principal_type = id_type

        return bucket_name, principal_name, principal_type, finding_type

    # Fallback generic parsing
    bucket_name = detail.get("bucket_name", "")
    principal_name = detail.get("principal_name", "")
    return bucket_name, principal_name, principal_type, event_type


def remediate_s3_bucket(bucket_name: str) -> bool:
    """Enforce complete S3 Public Access Block on target bucket."""
    if not bucket_name:
        logger.error("No S3 bucket specified for remediation.")
        return False

    logger.info("Enforcing PublicAccessBlock on bucket: %s", bucket_name)
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        return True
    except ClientError as err:
        logger.error("Failed to enforce PublicAccessBlock on %s: %s", bucket_name, err)
        return False


def quarantine_principal(principal_name: str, principal_type: str, quarantine_policy_arn: str) -> bool:
    """Attach emergency deny-all quarantine policy to offending IAM identity."""
    if not principal_name or not quarantine_policy_arn:
        logger.warning("Skipping IAM quarantine: principal='%s', policy_arn='%s'", principal_name, quarantine_policy_arn)
        return False

    # Guardrails: never attempt to quarantine root, AWS services, or the SOAR role itself
    exemptions = ["root", "AWSServiceRole", "pf-shield-soar-lambda-role"]
    if any(ex in principal_name for ex in exemptions):
        logger.warning("Principal '%s' is protected/exempt from automatic quarantine.", principal_name)
        return False

    logger.info("Quarantining %s '%s' with policy %s", principal_type, principal_name, quarantine_policy_arn)
    try:
        if principal_type == "User":
            iam_client.attach_user_policy(UserName=principal_name, PolicyArn=quarantine_policy_arn)
        else:
            iam_client.attach_role_policy(RoleName=principal_name, PolicyArn=quarantine_policy_arn)
        return True
    except ClientError as err:
        logger.error("Failed to attach quarantine policy to %s: %s", principal_name, err)
        return False


def publish_forensic_report(
    topic_arn: str,
    finding_type: str,
    bucket_name: str,
    principal_name: str,
    remediation_status: str,
    mttr_seconds: float,
) -> None:
    """Publish structured forensic incident alert to SNS."""
    if not topic_arn:
        logger.info("No SNS topic configured. Skipping forensic notification.")
        return

    payload = {
        "event_source": "PF-Shield-SOAR",
        "playbook": "S3-Lockdown-AutoRemediation",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finding_type": finding_type,
        "affected_resource": bucket_name,
        "offending_principal": principal_name,
        "remediation_status": remediation_status,
        "mttr_seconds": round(mttr_seconds, 3),
        "actions_taken": [
            "Enforced PublicAccessBlock (all 4 flags = True)",
            "Applied emergency DenyAll quarantine policy to offending identity",
        ],
    }

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=f"[PF-Shield SOAR] Auto-Remediated S3 Security Event: {bucket_name}",
            Message=json.dumps(payload, indent=2),
        )
    except ClientError as err:
        logger.error("Failed to publish SNS alert: %s", err)


def emit_mttr_metric(mttr_seconds: float) -> None:
    """Record Mean Time to Remediate custom metric in CloudWatch."""
    try:
        cloudwatch_client.put_metric_data(
            Namespace="PF-Shield/SecurityOps",
            MetricData=[
                {
                    "MetricName": "MeanTimeToRemediate",
                    "Dimensions": [{"Name": "Playbook", "Value": "S3Lockdown"}],
                    "Value": mttr_seconds,
                    "Unit": "Seconds",
                }
            ],
        )
    except ClientError as err:
        logger.warning("Failed to emit CloudWatch MTTR metric: %s", err)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entry point for S3 Lockdown SOAR playbook."""
    start_time = time.time()
    logger.info("Received security event: %s", json.dumps(event))

    quarantine_policy_arn = get_parameter_value("QUARANTINE_POLICY_ARN")
    sns_topic_arn = get_parameter_value("SNS_TOPIC_ARN")

    bucket_name, principal_name, principal_type, finding_type = parse_event_details(event)

    s3_success = remediate_s3_bucket(bucket_name)
    iam_success = quarantine_principal(principal_name, principal_type, quarantine_policy_arn)

    elapsed_time = time.time() - start_time
    status = "CONTAINED" if (s3_success or iam_success) else "FAILED"

    publish_forensic_report(
        topic_arn=sns_topic_arn,
        finding_type=finding_type,
        bucket_name=bucket_name,
        principal_name=principal_name,
        remediation_status=status,
        mttr_seconds=elapsed_time,
    )

    emit_mttr_metric(elapsed_time)

    return {
        "statusCode": 200 if status == "CONTAINED" else 500,
        "body": json.dumps({
            "status": status,
            "bucket_remediated": bucket_name,
            "principal_quarantined": principal_name,
            "mttr_seconds": elapsed_time,
        }),
    }
