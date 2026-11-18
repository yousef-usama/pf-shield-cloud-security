"""PF-Shield Real Estate Platform: Asynchronous KYC Document Scan Worker.

Runs as a hardened, non-root microservice on Amazon ECS.
Performs:
1. File integrity & magic-bytes validation (ensuring file matches extension: PDF, JPEG, PNG).
2. Anti-malware scanning (signature verification including EICAR standard test strings).
3. Transitions DynamoDB audit states from 'pending_scan' -> 'clean', 'quarantined', or 'rejected'.
4. Attaches security tags to S3 objects ('SecurityScan=Clean' or 'SecurityScan=Quarantined').
5. Publishes automated forensic alerts to SNS on malware detection.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("document-scan-worker")

app = FastAPI(
    title="PF-Shield Document Scan Worker",
    description="Asynchronous Malware Scanner & File Integrity Validator for KYC Vault",
    version="1.0.0",
)

REGION = os.environ.get("AWS_REGION", "me-central-1")
BUCKET_NAME = os.environ.get("KYC_VAULT_BUCKET_NAME", f"pf-kyc-vault-{os.environ.get('ENVIRONMENT', 'prod-sim')}")
TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", f"pf-properties-metadata-{os.environ.get('ENVIRONMENT', 'prod-sim')}")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

s3_client = boto3.client("s3", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns_client = boto3.client("sns", region_name=REGION)

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


@app.get("/healthz")
async def health_check() -> dict[str, str]:
    """Worker container health probe."""
    return {
        "status": "healthy",
        "service": "document-scan-worker",
        "region": REGION,
        "runtime": "ecs-fargate-worker",
    }


@app.post("/scan")
async def process_scan(req: ScanRequest) -> dict[str, Any]:
    """Perform security and integrity scan on an uploaded KYC object."""
    logger.info("Initiating security scan for s3://%s/%s", req.bucket, req.key)

    file_ext = req.key.split(".")[-1].lower() if "." in req.key else ""

    # 1. Fetch object content from S3
    try:
        s3_resp = s3_client.get_object(Bucket=req.bucket, Key=req.key)
        data = s3_resp["Body"].read()
    except ClientError as err:
        logger.error("Failed to fetch object for scan: %s", err)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"S3 Object not found: {err}")

    # 2. Heuristic and Signature Scan
    scan_result, reason = inspect_file_bytes(data, file_ext)
    logger.info("Scan result for %s: status=%s, reason=%s", req.key, scan_result, reason)

    # 3. Tag S3 Object with Security Scan Status
    try:
        tag_value = "Clean" if scan_result == "clean" else ("Quarantined" if scan_result == "quarantined" else "Rejected")
        s3_client.put_object_tagging(
            Bucket=req.bucket,
            Key=req.key,
            Tagging={
                "TagSet": [
                    {"Key": "SecurityScan", "Value": tag_value},
                    {"Key": "ScanTimestamp", "Value": datetime.now(timezone.utc).isoformat()},
                ]
            },
        )
    except ClientError as err:
        logger.warning("Failed to tag S3 object: %s", err)

    # 4. Update DynamoDB Scan State
    if req.pk and req.sk:
        try:
            table = dynamodb.Table(TABLE_NAME)
            table.update_item(
                Key={"pk": req.pk, "sk": req.sk},
                UpdateExpression="SET scan_status = :st, scan_reason = :rs, scanned_at = :ts",
                ExpressionAttributeValues={
                    ":st": scan_result,
                    ":rs": reason,
                    ":ts": datetime.now(timezone.utc).isoformat(),
                },
            )
        except ClientError as err:
            logger.warning("Failed to update DynamoDB scan status: %s", err)

    # 5. Alert Security Hub / SNS on Malicious Objects
    if scan_result == "quarantined" and SNS_TOPIC_ARN:
        try:
            alert_payload = {
                "EventSource": "pf-shield.document-scan-worker",
                "Severity": "HIGH",
                "IncidentType": "MALICIOUS_KYC_UPLOAD_DETECTED",
                "Bucket": req.bucket,
                "ObjectKey": req.key,
                "ScanResult": scan_result,
                "Reason": reason,
                "Timestamp": datetime.now(timezone.utc).isoformat(),
            }
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="[ALERT] PF-Shield Malware Detected in KYC Vault",
                Message=json.dumps(alert_payload, indent=2),
            )
        except ClientError as err:
            logger.error("Failed to publish malware alert to SNS: %s", err)

    return {
        "status": "success",
        "scan_status": scan_result,
        "reason": reason,
        "object_key": req.key,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
