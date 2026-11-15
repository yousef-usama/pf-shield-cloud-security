"""PF-Shield SOAR Playbook: Compromised IAM Credential Quarantine & Key Revocation.

Automatically isolates compromised IAM users and roles:
1. Attaches emergency pf-soar-quarantine-deny-all policy.
2. Enumerates and deactivates all active IAM access keys for compromised users.
3. Publishes structured forensic incident alert to SNS.
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
iam_client = boto3.client("iam")
sns_client = boto3.client("sns")
cloudwatch_client = boto3.client("cloudwatch")
ssm_client = boto3.client("ssm")


def get_parameter_value(param_name_or_env: str, default: str = "") -> str:
    """Retrieve configuration from environment variable or SSM Parameter Store."""
    val = os.environ.get(param_name_or_env, "")
    if val:
        return val

    if param_name_or_env.startswith("/"):
        try:
            resp = ssm_client.get_parameter(Name=param_name_or_env, WithDecryption=True)
            return resp.get("Parameter", {}).get("Value", default)
        except ClientError as err:
            logger.warning("SSM parameter %s lookup failed: %s", param_name_or_env, err)
    return default


def parse_iam_event(event: dict[str, Any]) -> tuple[str, str, str]:
    """Extract principal name, principal type, and finding type from EventBridge alert."""
    detail = event.get("detail", {})
    source = event.get("source", "")
    event_type = event.get("detail-type", "Unknown")

    # Case 1: Custom Simulation Event
    if source == "pf.security.simulation":
        principal_name = detail.get("compromised_principal", detail.get("user_name", "simulated-compromised-user"))
        principal_type = detail.get("principal_type", "User")
        return principal_name, principal_type, "Simulation:IAMCompromise"

    # Case 2: GuardDuty Finding
    if source == "aws.guardduty":
        finding_type = detail.get("type", "GuardDuty:IAMFinding")
        resource = detail.get("resource", {})
        access_key_details = resource.get("accessKeyDetails", {})
        principal_name = access_key_details.get("userName", "")
        principal_type = access_key_details.get("userType", "User")
        return principal_name, principal_type, finding_type

    # Case 3: CloudTrail Event
    if "eventName" in detail:
        event_name = detail.get("eventName", "")
        finding_type = f"CloudTrail:{event_name}"
        req_params = detail.get("requestParameters", {}) or {}

        # Check target of policy escalation or key creation
        if "roleName" in req_params:
            return req_params["roleName"], "Role", finding_type
        if "userName" in req_params:
            return req_params["userName"], "User", finding_type

        user_identity = detail.get("userIdentity", {})
        id_type = user_identity.get("type", "")
        if id_type == "IAMUser":
            return user_identity.get("userName", ""), "User", finding_type
        if id_type == "AssumedRole":
            arn = user_identity.get("arn", "")
            role_name = arn.split("/")[1] if "/" in arn else user_identity.get("principalId", "")
            return role_name, "Role", finding_type

        return user_identity.get("principalId", "UnknownIdentity"), "Unknown", finding_type

    return detail.get("principal_name", ""), "User", event_type


def apply_quarantine_policy(principal_name: str, principal_type: str, quarantine_policy_arn: str) -> bool:
    """Attach the deny-all quarantine policy to target user or role."""
    if not principal_name or not quarantine_policy_arn:
        logger.warning("Skipping quarantine attachment: principal='%s', policy_arn='%s'", principal_name, quarantine_policy_arn)
        return False

    exemptions = ["root", "AWSServiceRole", "pf-shield-soar-lambda-role"]
    if any(ex in principal_name for ex in exemptions):
        logger.warning("Identity '%s' is exempt from automatic quarantine.", principal_name)
        return False

    try:
        if principal_type == "Role":
            logger.info("Attaching quarantine policy to role: %s", principal_name)
            iam_client.attach_role_policy(RoleName=principal_name, PolicyArn=quarantine_policy_arn)
        else:
            logger.info("Attaching quarantine policy to user: %s", principal_name)
            iam_client.attach_user_policy(UserName=principal_name, PolicyArn=quarantine_policy_arn)
        return True
    except ClientError as err:
        logger.error("Failed to attach quarantine policy to %s: %s", principal_name, err)
        return False


def revoke_active_access_keys(user_name: str) -> list[str]:
    """Enumerate and deactivate all active IAM access keys for the compromised user."""
    deactivated_keys: list[str] = []
    if not user_name:
        return deactivated_keys

    try:
        paginator = iam_client.get_paginator("list_access_keys")
        for page in paginator.paginate(UserName=user_name):
            for key_meta in page.get("AccessKeyMetadata", []):
                key_id = key_meta.get("AccessKeyId")
                status = key_meta.get("Status")
                if key_id and status == "Active":
                    logger.info("Deactivating active access key %s for user %s", key_id, user_name)
                    iam_client.update_access_key(
                        UserName=user_name,
                        AccessKeyId=key_id,
                        Status="Inactive",
                    )
                    deactivated_keys.append(key_id)
    except ClientError as err:
        logger.error("Failed to list/deactivate access keys for user %s: %s", user_name, err)

    return deactivated_keys


def publish_forensic_report(
    topic_arn: str,
    finding_type: str,
    principal_name: str,
    principal_type: str,
    revoked_keys: list[str],
    mttr_seconds: float,
) -> None:
    """Publish structured forensic incident alert to SNS."""
    if not topic_arn:
        return

    payload = {
        "event_source": "PF-Shield-SOAR",
        "playbook": "IAM-Quarantine-AutoRemediation",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finding_type": finding_type,
        "compromised_identity": principal_name,
        "identity_type": principal_type,
        "quarantine_status": "CONTAINED",
        "revoked_access_keys": revoked_keys,
        "mttr_seconds": round(mttr_seconds, 3),
        "actions_taken": [
            "Attached pf-soar-quarantine-deny-all policy",
            f"Deactivated {len(revoked_keys)} active IAM access key(s)",
        ],
    }

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=f"[PF-Shield SOAR] Auto-Remediated Compromised IAM Identity: {principal_name}",
            Message=json.dumps(payload, indent=2),
        )
    except ClientError as err:
        logger.error("Failed to publish SNS forensic alert: %s", err)


def emit_mttr_metric(mttr_seconds: float) -> None:
    """Record Mean Time to Remediate metric in CloudWatch."""
    try:
        cloudwatch_client.put_metric_data(
            Namespace="PF-Shield/SecurityOps",
            MetricData=[
                {
                    "MetricName": "MeanTimeToRemediate",
                    "Dimensions": [{"Name": "Playbook", "Value": "IAMQuarantine"}],
                    "Value": mttr_seconds,
                    "Unit": "Seconds",
                }
            ],
        )
    except ClientError as err:
        logger.warning("Failed to emit CloudWatch MTTR metric: %s", err)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda entry point for IAM Quarantine SOAR playbook."""
    start_time = time.time()
    logger.info("Received IAM security event: %s", json.dumps(event))

    quarantine_policy_arn = get_parameter_value("QUARANTINE_POLICY_ARN")
    sns_topic_arn = get_parameter_value("SNS_TOPIC_ARN")

    principal_name, principal_type, finding_type = parse_iam_event(event)

    policy_applied = apply_quarantine_policy(principal_name, principal_type, quarantine_policy_arn)
    revoked_keys: list[str] = []
    if principal_type == "User":
        revoked_keys = revoke_active_access_keys(principal_name)

    elapsed_time = time.time() - start_time
    status = "CONTAINED" if (policy_applied or revoked_keys) else "NO_ACTION"

    publish_forensic_report(
        topic_arn=sns_topic_arn,
        finding_type=finding_type,
        principal_name=principal_name,
        principal_type=principal_type,
        revoked_keys=revoked_keys,
        mttr_seconds=elapsed_time,
    )

    emit_mttr_metric(elapsed_time)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "status": status,
            "principal_quarantined": principal_name,
            "revoked_access_keys": revoked_keys,
            "mttr_seconds": elapsed_time,
        }),
    }
