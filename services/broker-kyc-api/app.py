"""PF-Shield Real Estate Platform: Containerized Broker KYC Vault Service.

Runs as a secure, non-root microservice on Amazon ECS behind Application Load Balancer.
Provides:
1. /healthz container health probe.
2. POST /api/v1/kyc/presign with Zero-Trust cryptographic JWT verification and role authorization.
3. Strict server-side prefix derivation: kyc-documents/{tenant_id}/{broker_id}/{doc_type}/{uuid}.{file_ext}.
4. S3 presigned POST policy generation enforcing exact key, SSE-KMS CMK, size limits (1KB-10MB), and MIME types.
5. DynamoDB metadata record insertion with initial state 'pending_scan'.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import logging
import os
import re
import time
import urllib.request
import uuid
from typing import Any

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("broker-kyc-api")

app = FastAPI(
    title="PF-Shield Broker KYC Service",
    description="Zero-Trust Authenticated Broker Document Upload and KYC Presign Microservice",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://*.pf-shield.ae", "https://*.realestate.ae"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    max_age=300,
)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
}

REGION = os.environ.get("AWS_REGION", "me-central-1")
BUCKET_NAME = os.environ.get("KYC_VAULT_BUCKET_NAME", f"pf-kyc-vault-{os.environ.get('ENVIRONMENT', 'prod-sim')}")
KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN", "")
TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", f"pf-properties-metadata-{os.environ.get('ENVIRONMENT', 'prod-sim')}")

COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_ISSUER = (
    f"https://cognito-idp.{REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
    if COGNITO_USER_POOL_ID
    else os.environ.get("COGNITO_ISSUER", "")
)

s3_client = boto3.client("s3", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)

ALLOWED_DOC_TYPES = {
    "emirates_id": ["pdf", "jpg", "jpeg", "png"],
    "passport": ["pdf", "jpg", "jpeg", "png"],
    "rera_title_deed": ["pdf"],
}

MIME_TYPE_MAP = {
    "pdf": "application/pdf",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
}

ALLOWED_ROLES = {"broker", "broker_admin", "compliance_officer", "admin"}
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{3,64}$")
MIN_FILE_SIZE = 1024  # 1 KB
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
EXPIRY_SECONDS = 300  # 5 minutes

# In-memory JWKS cache: {kid: RSAPublicKey}
_JWKS_CACHE: dict[str, Any] = {}
_JWKS_LAST_FETCH: float = 0.0
_JWKS_CACHE_TTL: float = 3600.0


class PresignRequest(BaseModel):
    document_type: str = Field(..., description="Document type: emirates_id, passport, rera_title_deed")
    file_extension: str = Field(..., description="File extension: pdf, jpg, jpeg, png")
    # Untrusted fields if supplied by caller
    broker_id: str | None = None
    tenant_id: str | None = None


def int_from_b64url(s: str) -> int:
    """Convert base64url string to big-endian integer."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    data = base64.urlsafe_b64decode(s.encode("utf-8"))
    return int.from_bytes(data, byteorder="big")


def build_public_key_from_jwk(jwk: dict[str, Any]):
    """Construct an RSA public key from JWK modulus (n) and exponent (e)."""
    n = int_from_b64url(jwk["n"])
    e = int_from_b64url(jwk["e"])
    return RSAPublicNumbers(e, n).public_key()


def get_jwks_keys() -> dict[str, Any]:
    """Retrieve JWKS public keys from Cognito or injected test JWKS."""
    global _JWKS_CACHE, _JWKS_LAST_FETCH

    # Check for programmatic or environment test keys
    test_jwks_env = os.environ.get("COGNITO_TEST_JWKS")
    if test_jwks_env:
        try:
            jwks_data = json.loads(test_jwks_env)
            return {k["kid"]: build_public_key_from_jwk(k) for k in jwks_data.get("keys", [])}
        except Exception as e:
            logger.error("Failed to parse COGNITO_TEST_JWKS: %s", e)

    now = time.time()
    if _JWKS_CACHE and (now - _JWKS_LAST_FETCH) < _JWKS_CACHE_TTL:
        return _JWKS_CACHE

    if not COGNITO_USER_POOL_ID:
        return _JWKS_CACHE

    jwks_url = f"https://cognito-idp.{REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    try:
        req = urllib.request.Request(jwks_url, headers={"User-Agent": "PF-Shield-Broker-KYC-API"})
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            keys_dict = {}
            for k in payload.get("keys", []):
                if k.get("alg") == "RS256" and k.get("use") == "sig" and "kid" in k:
                    keys_dict[k["kid"]] = build_public_key_from_jwk(k)
            _JWKS_CACHE = keys_dict
            _JWKS_LAST_FETCH = now
            return _JWKS_CACHE
    except Exception as err:
        logger.error("Failed to fetch Cognito JWKS from %s: %s", jwks_url, err)
        return _JWKS_CACHE


def decode_and_validate_jwt(token: str) -> dict[str, Any]:
    """Cryptographically verify and validate claims from Cognito JWT token.

    Validates:
    - 3-part JWT structure.
    - Token header alg (RS256) and kid.
    - Cryptographic signature against Cognito JWKS public key.
    - Expiration (exp).
    - Issuer (iss) matches Cognito User Pool.
    - Audience (aud) or Client ID matches configured App Client.
    - Token use (id or access).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token structure: expected header.payload.signature",
        )

    # 1. Parse and validate header
    try:
        header_rem = len(parts[0]) % 4
        header_b64 = parts[0] + ("=" * (4 - header_rem) if header_rem else "")
        header = json.loads(base64.urlsafe_b64decode(header_b64.encode("utf-8")).decode("utf-8"))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Malformed token header: {err}")

    if header.get("alg") != "RS256":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported token algorithm '{header.get('alg')}'; expected RS256",
        )

    kid = header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing key ID (kid) in token header",
        )

    # 2. Retrieve public key and cryptographically verify signature
    jwks_keys = get_jwks_keys()
    if not jwks_keys or kid not in jwks_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to verify token signature: Unknown key ID '{kid}'",
        )

    public_key = jwks_keys[kid]

    try:
        sig_rem = len(parts[2]) % 4
        sig_b64 = parts[2] + ("=" * (4 - sig_rem) if sig_rem else "")
        sig_bytes = base64.urlsafe_b64decode(sig_b64.encode("utf-8"))
        signed_data = f"{parts[0]}.{parts[1]}".encode("utf-8")
        public_key.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA256())
    except Exception as sig_err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cryptographic signature verification failed: {sig_err}",
        )

    # 3. Parse payload
    try:
        payload_rem = len(parts[1]) % 4
        payload_b64 = parts[1] + ("=" * (4 - payload_rem) if payload_rem else "")
        claims = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Malformed token payload: {err}")

    # 4. Enforce standard claims
    # exp
    exp = claims.get("exp")
    if exp is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing required 'exp' claim")
    try:
        if float(exp) < time.time():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except (ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 'exp' claim")

    # iss
    if COGNITO_ISSUER:
        iss = claims.get("iss")
        if iss != COGNITO_ISSUER:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token issuer '{iss}' does not match expected '{COGNITO_ISSUER}'",
            )

    # aud / client_id
    if COGNITO_CLIENT_ID:
        token_use = claims.get("token_use", "id")
        if token_use == "id":
            aud = claims.get("aud")
            if aud != COGNITO_CLIENT_ID:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Token audience '{aud}' does not match client ID '{COGNITO_CLIENT_ID}'",
                )
        elif token_use == "access":
            client_id = claims.get("client_id")
            if client_id != COGNITO_CLIENT_ID:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Token client_id '{client_id}' does not match expected '{COGNITO_CLIENT_ID}'",
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token_use '{token_use}'; expected 'id' or 'access'",
            )

    return claims


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforce defense-in-depth HTTP security response headers."""
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


@app.get("/healthz")
async def health_check() -> dict[str, str]:
    """Container health probe endpoint for ALB target group."""
    return {
        "status": "healthy",
        "service": "broker-kyc-api",
        "region": REGION,
        "runtime": "ecs-fargate-container",
    }


@app.post("/api/v1/kyc/presign")
async def generate_kyc_presign(
    req: PresignRequest,
    authorization: str | None = Header(None),
    x_amzn_oidc_data: str | None = Header(None),
) -> dict[str, Any]:
    """Generate secure S3 presigned POST policy for authenticated broker."""
    # 1. Identity Token Extraction & Validation
    token_str = None
    if authorization and authorization.lower().startswith("bearer "):
        token_str = authorization[7:].strip()
    elif x_amzn_oidc_data:
        token_str = x_amzn_oidc_data.strip()

    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required Bearer authentication token",
        )

    claims = decode_and_validate_jwt(token_str)

    # 2. Extract and Validate Identity Claims
    tenant_id = claims.get("custom:tenant_id") or claims.get("tenant_id")
    broker_id = claims.get("custom:broker_id") or claims.get("broker_id") or claims.get("sub")
    role = claims.get("custom:role") or claims.get("role") or "broker"

    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Token missing required tenant_id claim",
        )

    if not broker_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Token missing required broker_id claim",
        )

    # Path traversal validation
    if not SAFE_IDENTIFIER_PATTERN.match(str(tenant_id)) or not SAFE_IDENTIFIER_PATTERN.match(str(broker_id)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Path traversal or invalid characters detected in identity claims",
        )

    if role.lower() not in ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Role '{role}' is not authorized to request KYC upload credentials",
        )

    # Ignore untrusted caller body overrides
    if req.broker_id and req.broker_id != broker_id:
        logger.warning("Caller body broker identifier ignored; strictly using verified token broker claim")
    if req.tenant_id and req.tenant_id != tenant_id:
        logger.warning("Caller body tenant identifier ignored; strictly using verified token tenant claim")

    # 3. Document Type & Extension Validation
    doc_type = req.document_type.lower()
    file_ext = req.file_extension.lower().lstrip(".")

    if doc_type not in ALLOWED_DOC_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid document_type '{doc_type}'. Allowed types: {list(ALLOWED_DOC_TYPES.keys())}",
        )

    if file_ext not in ALLOWED_DOC_TYPES[doc_type]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid extension '{file_ext}' for {doc_type}. Allowed: {ALLOWED_DOC_TYPES[doc_type]}",
        )

    content_type = MIME_TYPE_MAP[file_ext]

    # 4. Server-Side Derived Isolated Object Key
    doc_id = str(uuid.uuid4())
    object_key = f"kyc-documents/{tenant_id}/{broker_id}/{doc_type}/{doc_id}.{file_ext}"

    # 5. S3 Presigned POST Policy Generation
    conditions: list[Any] = [
        {"bucket": BUCKET_NAME},
        {"key": object_key},
        ["content-length-range", MIN_FILE_SIZE, MAX_FILE_SIZE],
        {"Content-Type": content_type},
        {"x-amz-server-side-encryption": "aws:kms"},
    ]
    if KMS_KEY_ARN:
        conditions.append({"x-amz-server-side-encryption-aws-kms-key-id": KMS_KEY_ARN})

    fields = {
        "key": object_key,
        "Content-Type": content_type,
        "x-amz-server-side-encryption": "aws:kms",
    }
    if KMS_KEY_ARN:
        fields["x-amz-server-side-encryption-aws-kms-key-id"] = KMS_KEY_ARN

    try:
        presigned_post = s3_client.generate_presigned_post(
            Bucket=BUCKET_NAME,
            Key=object_key,
            Fields=fields,
            Conditions=conditions,
            ExpiresIn=EXPIRY_SECONDS,
        )
    except ClientError as err:
        logger.error("Failed to generate presigned S3 POST policy: %s", err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate secure upload credentials",
        )

    # 6. Record Initial Audit State in DynamoDB
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
        "bucket_name": BUCKET_NAME,
        "scan_status": "pending_scan",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "compliance": "UAE-PDPL-Federal-Decree-Law-45-2021",
    }

    try:
        table = dynamodb.Table(TABLE_NAME)
        table.put_item(Item=metadata_item)
    except Exception as ddb_err:
        logger.error("Failed to write initial KYC metadata to DynamoDB: %s", ddb_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record KYC document audit metadata",
        )

    return {
        "status": "success",
        "document_id": doc_id,
        "tenant_id": tenant_id,
        "broker_id": broker_id,
        "object_key": object_key,
        "upload_url": presigned_post["url"],
        "upload_fields": presigned_post["fields"],
        "scan_status": "pending_scan",
        "max_file_size_bytes": MAX_FILE_SIZE,
        "expires_in_seconds": EXPIRY_SECONDS,
        "encryption": "aws:kms",
        "compliance": "UAE-PDPL-Federal-Decree-Law-45-2021",
    }
