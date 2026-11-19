"""PF-Shield Real Estate Platform: Asynchronous KYC Document Scan Worker.

Runs as a hardened, non-root microservice on Amazon ECS.
Performs:
1. Event-driven polling from encrypted SQS queue (triggered by S3 ObjectCreated via EventBridge).
2. Strict object-key allowlist validation (^kyc-documents/{tenant}/{broker}/{type}/{uuid}.{ext}$).
3. File integrity & magic-bytes validation (ensuring file matches extension: PDF, JPEG, PNG).
4. Anti-malware scanning (signature verification including EICAR standard test strings).
5. Transitions DynamoDB audit states from 'pending_scan' -> 'clean', 'quarantined', or 'rejected'.
6. Attaches security tags to S3 objects ('SecurityScan=Clean' or 'SecurityScan=Quarantined').
7. Publishes automated forensic alerts to SNS on malware detection.
8. Exposes /healthz container health probe and /scan synchronous fallback endpoint.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
import re
from typing import Any

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("document-scan-worker")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage lifecycle of background SQS worker task."""
    poller_task = None
    if SQS_SCAN_QUEUE_URL:
        poller_task = asyncio.create_task(background_sqs_worker())
    yield
    if poller_task and not poller_task.done():
        poller_task.cancel()
        try:
            await poller_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="PF-Shield Document Scan Worker",
    description="Event-Driven Asynchronous Malware Scanner & File Integrity Validator for KYC Vault",
    version="1.1.0",
    lifespan=lifespan,
)

REGION = os.environ.get("AWS_REGION", "me-central-1")
BUCKET_NAME = os.environ.get("KYC_VAULT_BUCKET_NAME", f"pf-kyc-vault-{os.environ.get('ENVIRONMENT', 'prod-sim')}")
TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", f"pf-properties-metadata-{os.environ.get('ENVIRONMENT', 'prod-sim')}")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
SQS_SCAN_QUEUE_URL = os.environ.get("SQS_SCAN_QUEUE_URL", "")

s3_client = boto3.client("s3", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns_client = boto3.client("sns", region_name=REGION)
sqs_client = boto3.client("sqs", region_name=REGION)

# Strict allowlist regex for KYC Vault object keys
ALLOWED_KEY_PATTERN = re.compile(
    r"^kyc-documents/([a-zA-Z0-9_\-]+)/([a-zA-Z0-9_\-]+)/([a-z_]+)/([a-zA-Z0-9_\-]+)\.([a-z0-9]+)$"
)

# Magic bytes signatures for strict validation
MAGIC_BYTES = {
    "pdf": [b"%PDF-"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "png": [b"\x89PNG\r\n\x1a\n"],
}

# Standard Anti-Virus Test String
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ScanRequest(BaseModel):
    bucket: str = Field(..., description="Target S3 bucket name")
    key: str = Field(..., description="S3 object key to scan")
    pk: str | None = Field(None, description="DynamoDB partition key")
    sk: str | None = Field(None, description="DynamoDB sort key")


def inspect_file_bytes(data: bytes, file_ext: str) -> tuple[str, str]:
    """Inspect file content against magic byte signatures and malware patterns.

    Returns (status, reason): 'clean', 'quarantined', or 'rejected'.
    """
    if len(data) < 1024:
        return "rejected", "File size below 1KB minimum threshold"

    if len(data) > 10 * 1024 * 1024:
        return "rejected", "File size exceeds 10MB maximum limit"

    # Anti-malware signature match
    if EICAR_SIGNATURE in data:
        return "quarantined", "Malware signature detected (EICAR-Test-Pattern)"

    # Magic byte format verification
    expected_signatures = MAGIC_BYTES.get(file_ext.lower(), [])
    if expected_signatures:
        matched = any(data.startswith(sig) for sig in expected_signatures)
        if not matched:
            return "rejected", f"Magic bytes mismatch for extension .{file_ext}"

    return "clean", "Passed heuristic virus scan and magic-byte validation"


def scan_and_remediate_object(bucket: str, key: str, pk: str | None = None, sk: str | None = None) -> dict[str, Any] | None:
    """Core scanning, tagging, and remediation engine for an S3 KYC object."""
    match = ALLOWED_KEY_PATTERN.match(key)
    if not match:
        logger.warning("Object key '%s' does not match allowed KYC key pattern. Rejecting.", key)
        return None

    tenant_id, broker_id, doc_type, doc_id, file_ext = match.groups()
    derived_pk = pk or f"TENANT#{tenant_id}#BROKER#{broker_id}"
    derived_sk = sk or f"KYC#{doc_id}"

    # 1. Fetch object from S3
    try:
        s3_resp = s3_client.get_object(Bucket=bucket, Key=key)
        data = s3_resp["Body"].read()
    except ClientError as err:
        logger.error("Failed to fetch object s3://%s/%s for scan: %s", bucket, key, err)
        return {
            "status": "error",
            "scan_status": "error",
            "reason": f"S3 fetch failed: {err}",
            "object_key": key,
        }

    # 2. Heuristic and Signature Scan
    scan_result, reason = inspect_file_bytes(data, file_ext)
    logger.info("Scan result for s3://%s/%s: status=%s, reason=%s", bucket, key, scan_result, reason)

    # 3. Apply Security Scan Tags to S3 Object
    try:
        tag_value = "Clean" if scan_result == "clean" else ("Quarantined" if scan_result == "quarantined" else "Rejected")
        s3_client.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={
                "TagSet": [
                    {"Key": "SecurityScan", "Value": tag_value},
                    {"Key": "ScanTimestamp", "Value": datetime.now(timezone.utc).isoformat()},
                ]
            },
        )
    except ClientError as err:
        logger.warning("Failed to tag S3 object s3://%s/%s: %s", bucket, key, err)

    # 4. Update DynamoDB Audit State
    try:
        table = dynamodb.Table(TABLE_NAME)
        table.update_item(
            Key={"pk": derived_pk, "sk": derived_sk},
            UpdateExpression="SET scan_status = :st, scan_reason = :rs, scanned_at = :ts",
            ExpressionAttributeValues={
                ":st": scan_result,
                ":rs": reason,
                ":ts": datetime.now(timezone.utc).isoformat(),
            },
        )
    except ClientError as err:
        logger.warning("Failed to update DynamoDB record (%s, %s): %s", derived_pk, derived_sk, err)

    # 5. Dispatch Incident Alert on Malware Detection
    if scan_result == "quarantined" and SNS_TOPIC_ARN:
        try:
            alert_payload = {
                "EventSource": "pf-shield.document-scan-worker",
                "Severity": "CRITICAL",
                "IncidentType": "MALICIOUS_KYC_UPLOAD_DETECTED",
                "Bucket": bucket,
                "ObjectKey": key,
                "TenantId": tenant_id,
                "BrokerId": broker_id,
                "DocumentType": doc_type,
                "ScanResult": scan_result,
                "Reason": reason,
                "Timestamp": datetime.now(timezone.utc).isoformat(),
            }
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="[CRITICAL ALERT] PF-Shield Malware Detected in KYC Vault",
                Message=json.dumps(alert_payload, indent=2),
            )
            logger.info("Published critical malware alert to SNS: %s", SNS_TOPIC_ARN)
        except ClientError as err:
            logger.error("Failed to publish malware alert to SNS: %s", err)

    return {
        "status": "success",
        "scan_status": scan_result,
        "reason": reason,
        "object_key": key,
        "tenant_id": tenant_id,
        "broker_id": broker_id,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def process_sqs_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Parse and process a single message from SQS originating from S3/EventBridge."""
    body_str = message.get("Body", "{}")
    try:
        body = json.loads(body_str)
    except Exception as err:
        logger.error("Invalid JSON body in SQS message: %s", err)
        return None

    # Case 1: EventBridge S3 Notification Envelope
    # {"source": "aws.s3", "detail-type": "Object Created", "detail": {"bucket": {"name": "..."}, "object": {"key": "..."}}}
    if body.get("source") == "aws.s3" and "detail" in body:
        detail = body["detail"]
        bucket = detail.get("bucket", {}).get("name")
        key = detail.get("object", {}).get("key")
        if bucket and key:
            return scan_and_remediate_object(bucket=bucket, key=key)

    # Case 2: Direct S3 Event Notification
    # {"Records": [{"s3": {"bucket": {"name": "..."}, "object": {"key": "..."}}}]}
    records = body.get("Records", [])
    if records:
        for rec in records:
            s3_data = rec.get("s3", {})
            bucket = s3_data.get("bucket", {}).get("name")
            key = s3_data.get("object", {}).get("key")
            if bucket and key:
                return scan_and_remediate_object(bucket=bucket, key=key)

    logger.warning("Unrecognized message schema in SQS event: %s", body_str[:200])
    return None


def poll_and_process_sqs_batch(queue_url: str = SQS_SCAN_QUEUE_URL, max_messages: int = 5) -> int:
    """Poll SQS once, process all received messages, and delete successfully handled items."""
    if not queue_url:
        return 0

    try:
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=2,
            VisibilityTimeout=60,
        )
    except ClientError as err:
        logger.error("SQS receive_message failed: %s", err)
        return 0

    messages = response.get("Messages", [])
    processed_count = 0

    for msg in messages:
        receipt_handle = msg.get("ReceiptHandle")
        try:
            res = process_sqs_message(msg)
            if res:
                processed_count += 1
            # Delete processed message from SQS queue
            if receipt_handle:
                sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        except Exception as err:
            logger.error("Failed to process SQS message %s: %s", msg.get("MessageId"), err)

    return processed_count


async def background_sqs_worker():
    """Continuous background worker polling SQS scan queue."""
    if not SQS_SCAN_QUEUE_URL:
        logger.info("SQS_SCAN_QUEUE_URL is empty; background poller is disabled.")
        return

    logger.info("Starting background SQS poller for %s", SQS_SCAN_QUEUE_URL)
    while True:
        try:
            poll_and_process_sqs_batch(SQS_SCAN_QUEUE_URL, max_messages=5)
        except Exception as err:
            logger.warning("Background SQS poller encountered exception: %s", err)
            await asyncio.sleep(5)
        await asyncio.sleep(0.5)


@app.get("/healthz")
async def health_check() -> dict[str, str]:
    """Worker container health probe."""
    return {
        "status": "healthy",
        "service": "document-scan-worker",
        "region": REGION,
        "runtime": "ecs-fargate-worker",
        "event_driven_sqs": "enabled" if SQS_SCAN_QUEUE_URL else "disabled",
    }


@app.post("/scan")
async def process_scan(req: ScanRequest) -> dict[str, Any]:
    """Synchronous fallback API endpoint for manual scanning invocations."""
    logger.info("Initiating synchronous scan for s3://%s/%s", req.bucket, req.key)
    res = scan_and_remediate_object(bucket=req.bucket, key=req.key, pk=req.pk, sk=req.sk)
    if res.get("status") == "error":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=res.get("reason"))
    return res
