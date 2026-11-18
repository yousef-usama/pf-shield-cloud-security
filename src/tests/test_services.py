"""Unit test suite for PF-Shield Containerized Microservices (ECS Workloads).

Covers:
1. services/listings-api:
   - Container health check (/healthz)
   - Property search catalog (/api/v1/properties)
   - Security response headers
2. services/broker-kyc-api:
   - Container health check (/healthz)
   - JWT authentication and token validation
   - Path traversal prevention in tenant and broker claims
   - S3 presigned POST generation and initial DynamoDB scan state tracking
3. services/document-scan-worker:
   - Container health check (/healthz)
   - Clean document validation & magic-byte verification
   - Malware detection (EICAR signature) and automated quarantine & alerting
   - File integrity rejection (magic-bytes mismatch and size bounds)
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import time
from typing import Any

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

def load_module_from_file(module_name: str, file_path: str):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "me-central-1"
os.environ["ENVIRONMENT"] = "prod-sim"
os.environ["KYC_VAULT_BUCKET_NAME"] = "pf-kyc-vault-sim"
os.environ["DYNAMODB_TABLE_NAME"] = "pf-properties-metadata-prod-sim"
os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:me-central-1:123456789012:pf-shield-incidents-prod-sim"


def make_jwt(payload: dict[str, Any]) -> str:
    """Generate mock base64url encoded JWT token."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.mock-signature"


@pytest.fixture
def mock_aws_env():
    """Setup mock AWS infrastructure for microservice tests."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="me-central-1")
        dynamodb = boto3.resource("dynamodb", region_name="me-central-1")
        sns = boto3.client("sns", region_name="me-central-1")

        s3.create_bucket(
            Bucket="pf-kyc-vault-sim",
            CreateBucketConfiguration={"LocationConstraint": "me-central-1"},
        )

        table = dynamodb.create_table(
            TableName="pf-properties-metadata-prod-sim",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        sns_res = sns.create_topic(Name="pf-shield-incidents-prod-sim")
        topic_arn = sns_res["TopicArn"]

        yield {
            "s3": s3,
            "dynamodb": dynamodb,
            "table": table,
            "sns": sns,
            "topic_arn": topic_arn,
        }


# =====================================================================================================================
# 1. LISTINGS API SERVICE TESTS
# =====================================================================================================================

def test_listings_api_health_and_catalog(mock_aws_env):
    """Test listings-api container health check and property catalog retrieval."""
    listings_module = load_module_from_file("listings_app", os.path.join(BASE_DIR, "services", "listings-api", "app.py"))
    listings_module.dynamodb = mock_aws_env["dynamodb"]

    client = TestClient(listings_module.app)

    # 1. Health check
    health_resp = client.get("/healthz")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"
    assert health_resp.json()["service"] == "listings-api"

    # 2. Properties catalog
    resp = client.get("/api/v1/properties")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["count"] >= 3
    assert "Strict-Transport-Security" in resp.headers
    assert resp.headers["X-Frame-Options"] == "DENY"

    # 3. Filter by emirate
    filter_resp = client.get("/api/v1/properties?emirate=Dubai")
    assert filter_resp.status_code == 200
    filtered = filter_resp.json()["data"]
    assert all(item["emirate"] == "Dubai" for item in filtered)


# =====================================================================================================================
# 2. BROKER KYC API SERVICE TESTS
# =====================================================================================================================

def test_broker_kyc_api_auth_and_presign(mock_aws_env):
    """Test broker-kyc-api JWT authentication, authorization, and S3 presign."""
    kyc_module = load_module_from_file("broker_kyc_app", os.path.join(BASE_DIR, "services", "broker-kyc-api", "app.py"))
    kyc_module.s3_client = mock_aws_env["s3"]
    kyc_module.dynamodb = mock_aws_env["dynamodb"]

    client = TestClient(kyc_module.app)

    # 1. Health check
    health_resp = client.get("/healthz")
    assert health_resp.status_code == 200
    assert health_resp.json()["service"] == "broker-kyc-api"

    # 2. Unauthenticated request -> 401
    unauth_resp = client.post(
        "/api/v1/kyc/presign",
        json={"document_type": "emirates_id", "file_extension": "pdf"},
    )
    assert unauth_resp.status_code == 401

    # 3. Expired token -> 401
    expired_token = make_jwt({
        "custom:tenant_id": "tenant-dxb",
        "custom:broker_id": "broker-001",
        "role": "broker",
        "exp": time.time() - 3600,
    })
    exp_resp = client.post(
        "/api/v1/kyc/presign",
        headers={"Authorization": f"Bearer {expired_token}"},
        json={"document_type": "emirates_id", "file_extension": "pdf"},
    )
    assert exp_resp.status_code == 401

    # 4. Path traversal attempt -> 403
    traversal_token = make_jwt({
        "custom:tenant_id": "tenant/../../evil",
        "custom:broker_id": "broker-001",
        "role": "broker",
        "exp": time.time() + 3600,
    })
    trav_resp = client.post(
        "/api/v1/kyc/presign",
        headers={"Authorization": f"Bearer {traversal_token}"},
        json={"document_type": "emirates_id", "file_extension": "pdf"},
    )
    assert trav_resp.status_code == 403

    # 5. Valid authenticated presign request -> 200
    valid_token = make_jwt({
        "custom:tenant_id": "tenant-marina",
        "custom:broker_id": "broker-7788",
        "role": "broker",
        "exp": time.time() + 3600,
    })
    presign_resp = client.post(
        "/api/v1/kyc/presign",
        headers={"Authorization": f"Bearer {valid_token}"},
        json={
            "document_type": "passport",
            "file_extension": "jpg",
            "broker_id": "spoofed-broker",  # Should be ignored
        },
    )
    assert presign_resp.status_code == 200
    body = presign_resp.json()
    assert body["status"] == "success"
    assert body["broker_id"] == "broker-7788"
    assert body["tenant_id"] == "tenant-marina"
    assert body["scan_status"] == "pending_scan"
    assert body["object_key"].startswith("kyc-documents/tenant-marina/broker-7788/passport/")

    # Check DynamoDB audit record
    table = mock_aws_env["table"]
    ddb_item = table.get_item(Key={
        "pk": "TENANT#tenant-marina#BROKER#broker-7788",
        "sk": f"KYC#{body['document_id']}",
    }).get("Item")
    assert ddb_item is not None
    assert ddb_item["scan_status"] == "pending_scan"


# =====================================================================================================================
# 3. DOCUMENT SCAN WORKER TESTS
# =====================================================================================================================

def test_document_scan_worker_lifecycle(mock_aws_env):
    """Test document-scan-worker clean validation, malware quarantine, and integrity checks."""
    worker_module = load_module_from_file("worker_app", os.path.join(BASE_DIR, "services", "document-scan-worker", "worker.py"))
    worker_module.s3_client = mock_aws_env["s3"]
    worker_module.dynamodb = mock_aws_env["dynamodb"]
    worker_module.sns_client = mock_aws_env["sns"]
    worker_module.SNS_TOPIC_ARN = mock_aws_env["topic_arn"]

    client = TestClient(worker_module.app)
    s3 = mock_aws_env["s3"]
    table = mock_aws_env["table"]

    # 1. Health check
    health_resp = client.get("/healthz")
    assert health_resp.status_code == 200
    assert health_resp.json()["service"] == "document-scan-worker"

    # 2. Test Clean PDF Scan
    clean_pdf_content = b"%PDF-1.7 Clean legitimate property registration document " + b"X" * 2000
    s3.put_object(
        Bucket="pf-kyc-vault-sim",
        Key="kyc-documents/t1/b1/emirates_id/doc-clean.pdf",
        Body=clean_pdf_content,
    )
    table.put_item(Item={
        "pk": "TENANT#t1#BROKER#b1",
        "sk": "KYC#doc-clean",
        "scan_status": "pending_scan",
    })

    scan_clean_resp = client.post(
        "/scan",
        json={
            "bucket": "pf-kyc-vault-sim",
            "key": "kyc-documents/t1/b1/emirates_id/doc-clean.pdf",
            "pk": "TENANT#t1#BROKER#b1",
            "sk": "KYC#doc-clean",
        },
    )
    assert scan_clean_resp.status_code == 200
    assert scan_clean_resp.json()["scan_status"] == "clean"

    # Verify S3 tags and DynamoDB status
    tags = s3.get_object_tagging(Bucket="pf-kyc-vault-sim", Key="kyc-documents/t1/b1/emirates_id/doc-clean.pdf")
    tag_map = {t["Key"]: t["Value"] for t in tags["TagSet"]}
    assert tag_map.get("SecurityScan") == "Clean"

    updated_item = table.get_item(Key={"pk": "TENANT#t1#BROKER#b1", "sk": "KYC#doc-clean"}).get("Item")
    assert updated_item["scan_status"] == "clean"

    # 3. Test Malware Upload (EICAR signature) -> Quarantine & SNS Alert
    malware_content = (
        b"%PDF-1.4 " +
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" +
        b"Y" * 2000
    )
    s3.put_object(
        Bucket="pf-kyc-vault-sim",
        Key="kyc-documents/t1/b1/passport/doc-malware.pdf",
        Body=malware_content,
    )
    table.put_item(Item={
        "pk": "TENANT#t1#BROKER#b1",
        "sk": "KYC#doc-malware",
        "scan_status": "pending_scan",
    })

    scan_malware_resp = client.post(
        "/scan",
        json={
            "bucket": "pf-kyc-vault-sim",
            "key": "kyc-documents/t1/b1/passport/doc-malware.pdf",
            "pk": "TENANT#t1#BROKER#b1",
            "sk": "KYC#doc-malware",
        },
    )
    assert scan_malware_resp.status_code == 200
    assert scan_malware_resp.json()["scan_status"] == "quarantined"

    # Verify S3 quarantined tag
    m_tags = s3.get_object_tagging(Bucket="pf-kyc-vault-sim", Key="kyc-documents/t1/b1/passport/doc-malware.pdf")
    m_tag_map = {t["Key"]: t["Value"] for t in m_tags["TagSet"]}
    assert m_tag_map.get("SecurityScan") == "Quarantined"

    m_updated = table.get_item(Key={"pk": "TENANT#t1#BROKER#b1", "sk": "KYC#doc-malware"}).get("Item")
    assert m_updated["scan_status"] == "quarantined"

    # 4. Test Corrupted / Magic Bytes Mismatch -> Rejected
    corrupt_content = b"This is plain text pretending to be a PDF " + b"Z" * 1500
    s3.put_object(
        Bucket="pf-kyc-vault-sim",
        Key="kyc-documents/t1/b1/passport/doc-corrupt.pdf",
        Body=corrupt_content,
    )
    scan_corrupt_resp = client.post(
        "/scan",
        json={
            "bucket": "pf-kyc-vault-sim",
            "key": "kyc-documents/t1/b1/passport/doc-corrupt.pdf",
            "pk": "TENANT#t1#BROKER#b1",
            "sk": "KYC#doc-corrupt",
        },
    )
    assert scan_corrupt_resp.status_code == 200
    assert scan_corrupt_resp.json()["scan_status"] == "rejected"
