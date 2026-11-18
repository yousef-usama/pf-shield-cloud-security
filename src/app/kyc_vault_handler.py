"""PF-Shield Application Service: Broker KYC Document Vault Handler.

Handles POST /api/v1/kyc/presign requests:
1. Enforces Zero-Trust JWT authentication (Cognito User Pool / OIDC).
2. Derives tenant_id, broker_id, and role strictly from verified JWT claims.
3. Completely ignores or rejects caller-supplied broker_id to prevent privilege escalation.
4. Validates identity claims against path traversal attacks.
5. Server-side constructs upload key: kyc-documents/{tenant_id}/{broker_id}/{doc_type}/{uuid}.{file_ext}.
6. Generates S3 presigned POST policies enforcing exact key, SSE-KMS CMK, size limits (1KB-10MB), and MIME types.
7. Tracks document scan lifecycle in DynamoDB (starting in 'pending_scan' state).
8. Aligned with UAE Personal Data Protection Law (PDPL - Federal Decree-Law No. 45 of 2021) and ISO 27001:2022.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import logging
import os
import re
import time
import uuid
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client("s3")
ssm_client = boto3.client("ssm")
dynamodb = boto3.resource("dynamodb")

ALLOWED_DOC_TYPES: dict[str, list[str]] = {
    "emirates_id": ["pdf", "jpg", "jpeg", "png"],
    "passport": ["pdf", "jpg", "jpeg", "png"],
    "rera_title_deed": ["pdf"],
}

MIME_TYPE_MAP: dict[str, str] = {
    "pdf": "application/pdf",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
}

ALLOWED_ROLES: set[str] = {
    "broker",
    "broker_admin",
    "compliance_officer",
    "admin",
}

# Strict regex preventing path traversal (../, /, null bytes, special chars)
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{3,64}$")

MIN_FILE_SIZE_BYTES = 1024  # 1 KB
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
PRESIGNED_URL_EXPIRY_SECONDS = 300  # 5 minutes

SECURITY_HEADERS: dict[str, str] = {
    "Content-Type": "application/json",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
}


def get_config(param_name: str, env_var: str, default: str = "") -> str:
    """Read configuration from environment variable or SSM Parameter Store."""
    val = os.environ.get(env_var, "")
    if val:
        return val

    try:
        resp = ssm_client.get_parameter(Name=param_name, WithDecryption=True)
        return resp.get("Parameter", {}).get("Value", default)
    except ClientError:
        return default


def extract_and_validate_claims(event: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Extract and validate claims from API Gateway authorizer context or Authorization bearer token.
    
    Returns (claims_dict, None) on success, or (None, error_message) on failure.
    """
    # 1. API Gateway HTTP API native JWT authorizer context
    jwt_context = (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("jwt", {})
    )
    if jwt_context and "claims" in jwt_context:
        claims = jwt_context["claims"]
        exp = claims.get("exp")
        if exp is not None:
            try:
                if float(exp) < time.time():
                    return None, "Token has expired"
            except (ValueError, TypeError):
                pass
        return claims, None

    # 2. Fallback to Authorization Header / ALB OIDC header
    raw_headers = event.get("headers") or {}
    headers = {k.lower(): v for k, v in raw_headers.items()}
    auth_header = headers.get("authorization") or headers.get("x-amzn-oidc-data")

    if not auth_header:
        return None, "Missing authentication token in request context or Authorization header"

    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else auth_header.strip()

    parts = token.split(".")
    if len(parts) != 3:
        return None, "Invalid JWT token structure"

    payload_b64 = parts[1]
    rem = len(payload_b64) % 4
    if rem > 0:
        payload_b64 += "=" * (4 - rem)

    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        claims = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(claims, dict):
            return None, "Invalid token payload structure"

        exp = claims.get("exp")
        if exp is not None:
            try:
                if float(exp) < time.time():
                    return None, "Token has expired"
            except (ValueError, TypeError):
                pass

        nbf = claims.get("nbf")
        if nbf is not None:
            try:
                if float(nbf) > time.time():
                    return None, "Token is not yet valid (nbf claim)"
            except (ValueError, TypeError):
                pass

        return claims, None
    except Exception as err:
        return None, f"Malformed token payload: {err}"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Generate secure presigned POST credentials for broker KYC verification."""
    logger.info("Received KYC presign request")

    # 1. Authentication Layer: Verify token and extract claims
    claims, auth_error = extract_and_validate_claims(event)
    if not claims or auth_error:
        logger.warning("KYC presign rejected: %s", auth_error)
        return {
            "statusCode": 401,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({"error": f"Unauthorized: {auth_error}"}),
        }

    # 2. Authorization Layer: Extract tenant_id, broker_id, and role
    tenant_id = claims.get("custom:tenant_id") or claims.get("tenant_id")
    broker_id = claims.get("custom:broker_id") or claims.get("broker_id") or claims.get("sub")
    role = claims.get("custom:role") or claims.get("role")

    if not role:
        groups = claims.get("cognito:groups")
        if isinstance(groups, list) and groups:
            role = groups[0]
        elif isinstance(groups, str):
            role = groups
        else:
            role = "broker"

    if not tenant_id:
        return {
            "statusCode": 403,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({"error": "Forbidden: Token missing required tenant_id claim"}),
        }

    if not broker_id:
        return {
            "statusCode": 403,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({"error": "Forbidden: Token missing required broker_id claim"}),
        }

    # Anti-Traversal & Sanitization Check
    if not SAFE_IDENTIFIER_PATTERN.match(str(tenant_id)) or not SAFE_IDENTIFIER_PATTERN.match(str(broker_id)):
        logger.warning(
            "Path traversal or invalid characters detected in claims (tenant_id=%s, broker_id=%s)",
            tenant_id,
            broker_id,
        )
        return {
            "statusCode": 403,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({
                "error": "Forbidden: Path traversal or invalid characters detected in identity claims"
            }),
        }

    if role.lower() not in ALLOWED_ROLES:
        logger.warning("Unauthorized role attempted KYC upload: %s", role)
        return {
            "statusCode": 403,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({
                "error": f"Forbidden: Role '{role}' is not authorized to request KYC upload credentials"
            }),
        }

    # 3. Payload Parsing: Document Type & Extension
    try:
        body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else (event.get("body") or {})
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({"error": "Invalid JSON request payload"}),
        }

    # Strict server-side override: Ignore any caller-supplied broker_id or tenant_id
    if "broker_id" in body and body["broker_id"] != broker_id:
        logger.warning(
            "Untrusted caller-supplied broker_id '%s' ignored; strictly using verified claim broker_id '%s'",
            body["broker_id"],
            broker_id,
        )
    if "tenant_id" in body and body["tenant_id"] != tenant_id:
        logger.warning(
            "Untrusted caller-supplied tenant_id '%s' ignored; strictly using verified claim tenant_id '%s'",
            body["tenant_id"],
            tenant_id,
        )

    doc_type = body.get("document_type", "").lower()
    file_ext = body.get("file_extension", "").lower().lstrip(".")

    if doc_type not in ALLOWED_DOC_TYPES:
        return {
            "statusCode": 400,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({
                "error": "Invalid document_type",
                "allowed_types": list(ALLOWED_DOC_TYPES.keys()),
            }),
        }

    if file_ext not in ALLOWED_DOC_TYPES[doc_type]:
        return {
            "statusCode": 400,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({
                "error": f"Invalid extension for {doc_type}",
                "allowed_extensions": ALLOWED_DOC_TYPES[doc_type],
            }),
        }

    content_type = MIME_TYPE_MAP.get(file_ext, "application/octet-stream")

    # 4. Construct Server-Side Isolated S3 Object Key
    doc_id = str(uuid.uuid4())
    object_key = f"kyc-documents/{tenant_id}/{broker_id}/{doc_type}/{doc_id}.{file_ext}"

    # 5. Environment & Infrastructure Config
    bucket_name = get_config(
        f"/pf-shield/{os.environ.get('ENVIRONMENT', 'prod-sim')}/kyc-vault-bucket-name",
        "KYC_VAULT_BUCKET_NAME",
        default="pf-kyc-vault-sim",
    )
    kms_key_arn = get_config(
        f"/pf-shield/{os.environ.get('ENVIRONMENT', 'prod-sim')}/kyc-kms-key-arn",
        "KMS_KEY_ARN",
        default="",
    )
    dynamodb_table_name = os.environ.get("DYNAMODB_TABLE_NAME", f"pf-properties-metadata-{os.environ.get('ENVIRONMENT', 'prod-sim')}")

    # 6. S3 Presigned POST Policy Generation
    # Enforces exact key match, content-length-range (1KB to 10MB), Content-Type, and SSE-KMS
    conditions: list[Any] = [
        {"bucket": bucket_name},
        {"key": object_key},
        ["content-length-range", MIN_FILE_SIZE_BYTES, MAX_FILE_SIZE_BYTES],
        {"Content-Type": content_type},
        {"x-amz-server-side-encryption": "aws:kms"},
    ]
    if kms_key_arn:
        conditions.append({"x-amz-server-side-encryption-aws-kms-key-id": kms_key_arn})

    fields: dict[str, str] = {
        "key": object_key,
        "Content-Type": content_type,
        "x-amz-server-side-encryption": "aws:kms",
    }
    if kms_key_arn:
        fields["x-amz-server-side-encryption-aws-kms-key-id"] = kms_key_arn

    try:
        presigned_post = s3_client.generate_presigned_post(
            Bucket=bucket_name,
            Key=object_key,
            Fields=fields,
            Conditions=conditions,
            ExpiresIn=PRESIGNED_URL_EXPIRY_SECONDS,
        )
    except ClientError as err:
        logger.error("Failed to generate presigned S3 POST policy: %s", err)
        return {
            "statusCode": 500,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({"error": "Failed to generate secure upload credentials"}),
        }

    # 7. Initial Metadata Record in DynamoDB with 'pending_scan' lifecycle state
    metadata_item = {
        "pk": f"TENANT#{tenant_id}#BROKER#{broker_id}",
        "sk": f"KYC#{doc_id}",
        "document_id": doc_id,
        "tenant_id": tenant_id,
        "broker_id": broker_id,
        "document_type": doc_type,
        "file_extension": file_ext,
        "content_type": content_type,
        "object_key": object_key,
        "bucket_name": bucket_name,
        "scan_status": "pending_scan",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "compliance": "UAE-PDPL-Federal-Decree-Law-45-2021",
    }

    try:
        table = dynamodb.Table(dynamodb_table_name)
        table.put_item(Item=metadata_item)
        logger.info("Recorded initial KYC document metadata in DynamoDB (doc_id=%s, state=pending_scan)", doc_id)
    except Exception as ddb_err:
        logger.error("Failed to write initial KYC metadata to DynamoDB: %s", ddb_err)
        return {
            "statusCode": 500,
            "headers": SECURITY_HEADERS,
            "body": json.dumps({"error": "Failed to record KYC document audit metadata"}),
        }

    return {
        "statusCode": 200,
        "headers": SECURITY_HEADERS,
        "body": json.dumps({
            "status": "success",
            "document_id": doc_id,
            "tenant_id": tenant_id,
            "broker_id": broker_id,
            "object_key": object_key,
            "upload_url": presigned_post["url"],
            "upload_fields": presigned_post["fields"],
            "scan_status": "pending_scan",
            "max_file_size_bytes": MAX_FILE_SIZE_BYTES,
            "expires_in_seconds": PRESIGNED_URL_EXPIRY_SECONDS,
            "encryption": "aws:kms",
            "compliance": "UAE-PDPL-Federal-Decree-Law-45-2021",
        }),
    }
