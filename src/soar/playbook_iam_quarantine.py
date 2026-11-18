"""PF-Shield SOAR Playbook: Compromised IAM Credential Quarantine & Key Revocation.

Automatically isolates compromised IAM users and roles:
1. Enforces event idempotency via DynamoDB deduplication table.
2. Evaluates protected-principals allowlist (prevents locking out root, admin, CI/CD, break-glass).
3. Supports configurable containment modes (AUTOMATIC vs HUMAN_APPROVAL).
4. Attaches emergency pf-soar-quarantine-deny-all policy.
5. Enumerates and deactivates all active IAM access keys for compromised users.
6. Publishes structured forensic incident alert to SNS.
7. Emits Mean Time to Remediate (MTTR) metrics to CloudWatch.
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
dynamodb_client = boto3.client("dynamodb")
ssm_client = boto3.client("ssm")

DEFAULT_PROTECTED_PRINCIPALS = [
    "root",
    "awsservicerole",
    "pf-shield-github-actions",
    "pf-soar-s3-lockdown",
    "pf-soar-iam-quarantine",
    "break-glass",
    "security-admin",
    "lead-security-engineer",
    "terraform-deployer",
]


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


def parse_iam_event(event: dict[str, Any]) -> tuple[str, str, str, str]:
    """Extract event_id, principal name, principal type, and finding type from EventBridge alert."""
    event_id = event.get("id", "")
    detail = event.get("detail", {})
    source = event.get("source", "")
    event_type = event.get("detail-type", "Unknown")

    if not event_id:
        event_id = detail.get("eventID", "")

    # Case 1: Custom Simulation Event
    if source == "pf.security.simulation":
        principal_name = detail.get("compromised_principal", detail.get("user_name", "simulated-compromised-user"))
        principal_type = detail.get("principal_type", "User")
        if not event_id:
            event_id = f"sim-iam-{principal_name}-{int(time.time() // 60)}"
        return event_id, principal_name, principal_type, "Simulation:IAMCompromise"

    # Case 2: GuardDuty Finding
    if source == "aws.guardduty":
        finding_type = detail.get("type", "GuardDuty:IAMFinding")
        resource = detail.get("resource", {})
        access_key_details = resource.get("accessKeyDetails", {})
        principal_name = access_key_details.get("userName", "")
        principal_type = access_key_details.get("userType", "User")
        if not event_id:
            event_id = detail.get("id", f"gd-iam-{principal_name}-{int(time.time() // 60)}")
        return event_id, principal_name, principal_type, finding_type

    # Case 3: CloudTrail Event
    if "eventName" in detail:
        event_name = detail.get("eventName", "")
        finding_type = f"CloudTrail:{event_name}"
        req_params = detail.get("requestParameters", {}) or {}

        if not event_id:
            event_id = detail.get("eventID", f"ct-iam-{int(time.time() // 60)}")

        # Check target of policy escalation or key creation
        if "roleName" in req_params:
            return event_id, req_params["roleName"], "Role", finding_type
        if "userName" in req_params:
            return event_id, req_params["userName"], "User", finding_type

        user_identity = detail.get("userIdentity", {})
        id_type = user_identity.get("type", "")
        if id_type == "IAMUser":
            return event_id, user_identity.get("userName", ""), "User", finding_type
        if id_type == "AssumedRole":
            arn = user_identity.get("arn", "")
            role_name = arn.split("/")[1] if "/" in arn else user_identity.get("principalId", "")
            return event_id, role_name, "Role", finding_type

        return event_id, user_identity.get("principalId", "UnknownIdentity"), "Unknown", finding_type

    principal_name = detail.get("principal_name", "")
    if not event_id:
        event_id = f"generic-iam-{principal_name}-{int(time.time() // 60)}"
    return event_id, principal_name, "User", event_type


def check_and_record_idempotency(event_id: str, table_name: str) -> bool:
    """Record event in DynamoDB to ensure single execution. Returns True if first time, False if duplicate."""
    if not table_name or not event_id:
        return True

    now = int(time.time())
    ttl = now + 86400  # 24-hour deduplication window

    try:
        dynamodb_client.put_item(
            TableName=table_name,
            Item={
                "event_id": {"S": event_id},
                "playbook": {"S": "iam_quarantine"},
                "processed_at": {"N": str(now)},
                "ttl": {"N": str(ttl)},
            },
            ConditionExpression="attribute_not_exists(event_id)",
        )
        return True
    except ClientError as err:
        err_code = err.response.get("Error", {}).get("Code", "")
        if err_code == "ConditionalCheckFailedException":
            logger.info("Event ID '%s' already processed. Skipping duplicate execution.", event_id)
            return False
        logger.warning("Idempotency check failed (%s), proceeding with remediation.", err)
        return True


def is_protected_principal(principal_name: str, allowlist_raw: str = "") -> bool:
    """Check if the principal is protected from automatic quarantine to prevent DoS on operations."""
    if not principal_name:
        return False

    allowlist = list(DEFAULT_PROTECTED_PRINCIPALS)
    if allowlist_raw:
        allowlist.extend([item.strip().lower() for item in allowlist_raw.split(",") if item.strip()])

    principal_lower = principal_name.lower()
    return any(protected in principal_lower for protected in allowlist)


def apply_quarantine_policy(principal_name: str, principal_type: str, quarantine_policy_arn: str) -> bool:
    """Attach the deny-all quarantine policy to target user or role."""
    if not principal_name or not quarantine_policy_arn:
        logger.warning("Skipping quarantine attachment: principal='%s', policy_arn='%s'", principal_name, quarantine_policy_arn)
        return False

    logger.info("Applying deny-all quarantine to %s '%s'", principal_type, principal_name)
    try:
        if principal_type == "User":
            iam_client.attach_user_policy(UserName=principal_name, PolicyArn=quarantine_policy_arn)
        else:
            iam_client.attach_role_policy(RoleName=principal_name, PolicyArn=quarantine_policy_arn)
        return True
    except ClientError as err:
        logger.error("Failed to attach quarantine policy to %s: %s", principal_name, err)
        return False


def deactivate_user_access_keys(user_name: str) -> list[str]:
    """Identify and deactivate all active IAM access keys for a compromised user."""
    deactivated_keys: list[str] = []
    if not user_name:
        return deactivated_keys

    logger.info("Listing access keys for user: %s", user_name)
    try:
        paginator = iam_client.get_paginator("list_access_keys")
        for page in paginator.paginate(UserName=user_name):
            for key_meta in page.get("AccessKeyMetadata", []):
                key_id = key_meta.get("AccessKeyId")
                status = key_meta.get("Status")
                if key_id and status == "Active":
                    logger.info("Deactivating Active access key: %s", key_id)
                    iam_client.update_access_key(UserName=user_name, AccessKeyId=key_id, Status="Inactive")
                    deactivated_keys.append(key_id)
        return deactivated_keys
    except ClientError as err:
        logger.error("Failed to list/deactivate access keys for user %s: %s", user_name, err)
        return deactivated_keys


def publish_iam_forensic_report(
    topic_arn: str,
    finding_type: str,
    principal_name: str,
    principal_type: str,
    deactivated_keys: list[str],
    status: str,
    mttr_seconds: float,
    actions_taken: list[str],
) -> None:
    """Publish structured forensic incident report to SNS."""
    if not topic_arn:
        logger.info("No SNS topic configured. Skipping forensic notification.")
        return

    payload = {
        "event_source": "PF-Shield-SOAR",
        "playbook": "IAM-Quarantine-AutoRemediation",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finding_type": finding_type,
        "compromised_principal": principal_name,
        "principal_type": principal_type,
        "deactivated_access_keys": deactivated_keys,
        "remediation_status": status,
        "mttr_seconds": round(mttr_seconds, 3),
        "actions_taken": actions_taken,
    }

    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=f"[PF-Shield SOAR] IAM Security Event ({status}): {principal_name}",
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
    idempotency_table = get_parameter_value("IDEMPOTENCY_TABLE_NAME")
    containment_mode = get_parameter_value("CONTAINMENT_MODE", "AUTOMATIC").upper()
    allowlist_raw = get_parameter_value("PROTECTED_PRINCIPALS_ALLOWLIST")

    event_id, principal_name, principal_type, finding_type = parse_iam_event(event)

    # 1. Idempotency Check: Prevent duplicate event execution
    if not check_and_record_idempotency(event_id, idempotency_table):
        return {
            "statusCode": 200,
            "body": json.dumps({
                "status": "SKIPPED_DUPLICATE",
                "event_id": event_id,
                "message": "Event already processed by SOAR deduplication engine.",
            }),
        }

    actions_taken = []
    deactivated_keys: list[str] = []

    # 2. Evaluate Protected Principals Allowlist & Containment Mode
    if is_protected_principal(principal_name, allowlist_raw):
        logger.warning(
            "Principal '%s' is in protected allowlist. Bypassing automatic quarantine to protect operational access.",
            principal_name,
        )
        actions_taken.append(f"Protected principal '{principal_name}' detected: automatic quarantine bypassed; escalated for human review")
        status = "ESCALATED_PROTECTED_PRINCIPAL"
    elif containment_mode == "HUMAN_APPROVAL":
        logger.info("Containment mode is HUMAN_APPROVAL. Drafting remediation proposal without isolating '%s'.", principal_name)
        actions_taken.append(f"Containment mode HUMAN_APPROVAL: quarantine proposal drafted for '{principal_name}', pending human sign-off")
        status = "AWAITING_APPROVAL"
    else:
        # Automatic containment mode
        policy_applied = apply_quarantine_policy(principal_name, principal_type, quarantine_policy_arn)
        if policy_applied:
            actions_taken.append(f"Applied emergency DenyAll quarantine policy to '{principal_name}'")

        if principal_type == "User":
            deactivated_keys = deactivate_user_access_keys(principal_name)
            if deactivated_keys:
                actions_taken.append(f"Deactivated active access keys: {', '.join(deactivated_keys)}")

        status = "CONTAINED" if (policy_applied or deactivated_keys) else "FAILED"

    elapsed_time = time.time() - start_time

    publish_iam_forensic_report(
        topic_arn=sns_topic_arn,
        finding_type=finding_type,
        principal_name=principal_name,
        principal_type=principal_type,
        deactivated_keys=deactivated_keys,
        status=status,
        mttr_seconds=elapsed_time,
        actions_taken=actions_taken,
    )

    if status in ("CONTAINED", "ESCALATED_PROTECTED_PRINCIPAL"):
        emit_mttr_metric(elapsed_time)

    return {
        "statusCode": 200 if status in ("CONTAINED", "AWAITING_APPROVAL", "ESCALATED_PROTECTED_PRINCIPAL") else 500,
        "body": json.dumps({
            "status": status,
            "event_id": event_id,
            "principal": principal_name,
            "principal_quarantined": principal_name if status == "CONTAINED" else "",
            "revoked_access_keys": deactivated_keys,
            "actions_taken": actions_taken,
            "deactivated_keys": deactivated_keys,
            "mttr_seconds": elapsed_time,
        }),
    }
