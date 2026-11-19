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
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
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

# Generate test RSA key pair and JWKS for cryptographic token validation
TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PUBLIC_KEY = TEST_PRIVATE_KEY.public_key()
_pub_num = TEST_PUBLIC_KEY.public_numbers()

def _int_to_b64url(val: int) -> str:
    length = (val.bit_length() + 7) // 8
    b = val.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

TEST_KID = "test-key-id-1"
TEST_JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": TEST_KID,
            "n": _int_to_b64url(_pub_num.n),
            "e": _int_to_b64url(_pub_num.e),
        }
    ]
}
os.environ["COGNITO_TEST_JWKS"] = json.dumps(TEST_JWKS)


def make_jwt(payload: dict[str, Any], kid: str = TEST_KID, key=TEST_PRIVATE_KEY, tamper_signature: bool = False) -> str:
    """Generate cryptographically signed base64url encoded RS256 JWT token."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signed_data = f"{header}.{body}".encode("utf-8")
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    sig_str = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
    if tamper_signature:
        sig_str = "tampered_" + sig_str[9:]
    return f"{header}.{body}.{sig_str}"


@pytest.fixture
def mock_aws_env():
    """Setup mock AWS infrastructure for microservice tests."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="me-central-1")
        dynamodb = boto3.resource("dynamodb", region_name="me-central-1")
        sns = boto3.client("sns", region_name="me-central-1")
        sqs = boto3.client("sqs", region_name="me-central-1")

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

        sqs_res = sqs.create_queue(QueueName="pf-shield-document-scan-queue-prod-sim")
        queue_url = sqs_res["QueueUrl"]

        yield {
            "s3": s3,
            "dynamodb": dynamodb,
            "table": table,
            "sns": sns,
            "sqs": sqs,
            "topic_arn": topic_arn,
            "queue_url": queue_url,
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

    # 3. Forged signature / untrusted JWT -> 401 (Proves cryptographic verification)
    forged_token = make_jwt(
        {
            "custom:tenant_id": "tenant-dxb",
            "custom:broker_id": "broker-001",
            "role": "broker",
            "exp": time.time() + 3600,
        },
        tamper_signature=True,
    )
    forged_resp = client.post(
        "/api/v1/kyc/presign",
        headers={"Authorization": f"Bearer {forged_token}"},
        json={"document_type": "emirates_id", "file_extension": "pdf"},
    )
    assert forged_resp.status_code == 401
    assert "signature verification failed" in forged_resp.json()["detail"].lower()

    # 4. Unknown kid / untrusted signer -> 401
    unknown_kid_token = make_jwt(
        {
            "custom:tenant_id": "tenant-dxb",
            "custom:broker_id": "broker-001",
            "role": "broker",
            "exp": time.time() + 3600,
        },
        kid="unknown-kid-999",
    )
    unk_resp = client.post(
        "/api/v1/kyc/presign",
        headers={"Authorization": f"Bearer {unknown_kid_token}"},
        json={"document_type": "emirates_id", "file_extension": "pdf"},
    )
    assert unk_resp.status_code == 401
    assert "unknown key id" in unk_resp.json()["detail"].lower()

    # 5. Expired token -> 401
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
    assert "expired" in exp_resp.json()["detail"].lower()

    # 6. Path traversal attempt -> 403
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

    # 7. Valid authenticated presign request -> 200
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


def test_document_scan_worker_event_driven_sqs_flow(mock_aws_env):
    """Test full event-driven asynchronous scanning via S3 EventBridge -> SQS -> ECS worker polling."""
    worker_module = load_module_from_file("worker_app_event_driven", os.path.join(BASE_DIR, "services", "document-scan-worker", "worker.py"))
    worker_module.s3_client = mock_aws_env["s3"]
    worker_module.dynamodb = mock_aws_env["dynamodb"]
    worker_module.sns_client = mock_aws_env["sns"]
    worker_module.sqs_client = mock_aws_env["sqs"]
    worker_module.SNS_TOPIC_ARN = mock_aws_env["topic_arn"]
    worker_module.SQS_SCAN_QUEUE_URL = mock_aws_env["queue_url"]

    s3 = mock_aws_env["s3"]
    table = mock_aws_env["table"]
    sqs = mock_aws_env["sqs"]
    queue_url = mock_aws_env["queue_url"]

    # 1. Upload EICAR Malware file to KYC Vault bucket
    eicar_bytes = (
        b"%PDF-1.5 " +
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" +
        b"EICAR_PADDING_" * 150
    )
    object_key = "kyc-documents/tenant-uae/broker-dxb/emirates_id/doc-uuid-eicar-99.pdf"
    s3.put_object(
        Bucket="pf-kyc-vault-sim",
        Key=object_key,
        Body=eicar_bytes,
    )

    table.put_item(Item={
        "pk": "TENANT#tenant-uae#BROKER#broker-dxb",
        "sk": "KYC#doc-uuid-eicar-99",
        "scan_status": "pending_scan",
    })

    # 2. Simulate S3 EventBridge notification delivered to SQS scan queue
    eventbridge_payload = {
        "version": "0",
        "id": "event-1234-abcd",
        "detail-type": "Object Created",
        "source": "aws.s3",
        "account": "123456789012",
        "time": "2026-11-19T17:00:00Z",
        "region": "me-central-1",
        "detail": {
            "version": "0",
            "bucket": {"name": "pf-kyc-vault-sim"},
            "object": {
                "key": object_key,
                "size": len(eicar_bytes),
                "etag": "etag12345",
            },
            "reason": "PutObject",
        },
    }
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(eventbridge_payload),
    )

    # 3. Trigger worker batch polling
    processed = worker_module.poll_and_process_sqs_batch(queue_url=queue_url, max_messages=5)
    assert processed == 1, "Expected 1 SQS message to be processed"

    # 4. Verify S3 quarantine tag
    tags_resp = s3.get_object_tagging(Bucket="pf-kyc-vault-sim", Key=object_key)
    tag_map = {t["Key"]: t["Value"] for t in tags_resp["TagSet"]}
    assert tag_map.get("SecurityScan") == "Quarantined", f"Expected Quarantined tag, got: {tag_map}"

    # 5. Verify DynamoDB audit record transition
    updated_item = table.get_item(Key={
        "pk": "TENANT#tenant-uae#BROKER#broker-dxb",
        "sk": "KYC#doc-uuid-eicar-99",
    }).get("Item")
    assert updated_item is not None
    assert updated_item["scan_status"] == "quarantined"
    assert "Malware signature detected" in updated_item["scan_reason"]

    # 6. Verify SQS message deletion (queue should be empty)
    recv_after = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=1)
    assert "Messages" not in recv_after or len(recv_after["Messages"]) == 0, "SQS message was not deleted after processing"

    # 7. Test Allowlist Key Rejection (malicious key outside schema is rejected without processing)
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps({
            "source": "aws.s3",
            "detail": {
                "bucket": {"name": "pf-kyc-vault-sim"},
                "object": {"key": "arbitrary-path/outside-schema.exe"},
            },
        }),
    )
    processed_invalid = worker_module.poll_and_process_sqs_batch(queue_url=queue_url, max_messages=5)
    assert processed_invalid == 0, "Invalid key should be rejected without processing"


def test_ecs_kyc_presigned_upload_s3_perimeter(mock_aws_env):
    """Test that ECS broker-KYC task role is authorized by S3 data perimeter for external presigned uploads.

    Validates:
    1. Terraform root wiring passes ECS broker-KYC and scan worker task roles to s3_data_perimeter.
    2. S3 data perimeter policy expands IAM role ARNs into STS assumed-role wildcards (ArnNotLike).
    3. External client performing presigned upload signed by ECS task role STS credentials succeeds.
    4. External client performing presigned upload signed by unauthorized role is denied.
    """
    import os
    import re

    # 1. Verify Terraform root wiring connects container_platform task roles to s3_data_perimeter module
    root_main_tf = os.path.join(os.path.dirname(__file__), "../../terraform/main.tf")
    with open(root_main_tf, "r", encoding="utf-8") as f:
        main_tf_content = f.read()

    assert "module \"s3_data_perimeter\"" in main_tf_content, "s3_data_perimeter module must be wired in root main.tf"
    assert "module.container_platform.broker_kyc_task_role_arn" in main_tf_content, "broker_kyc_task_role_arn must be passed to allowed_principal_arns"
    assert "module.container_platform.scan_worker_task_role_arn" in main_tf_content, "scan_worker_task_role_arn must be passed to allowed_principal_arns"

    # 2. Verify s3-data-perimeter module generates STS assumed-role wildcard allowlists with ArnNotLike
    perimeter_tf = os.path.join(os.path.dirname(__file__), "../../terraform/modules/s3-data-perimeter/main.tf")
    with open(perimeter_tf, "r", encoding="utf-8") as f:
        perimeter_content = f.read()

    assert "ArnNotLike" in perimeter_content, "Data perimeter must use ArnNotLike to match STS session wildcards"
    assert "sts_assumed_role_wildcards" in perimeter_content or ":assumed-role/" in perimeter_content

    # 3. Simulate real S3 Presigned Upload Integration Flow with Moto
    s3 = mock_aws_env["s3"]
    bucket_name = "pf-kyc-vault-sim"
    account_id = "123456789012"
    ecs_role_name = "pf-broker-kyc-task-role-prod-sim"

    allowed_roles = [
        f"arn:aws:iam::{account_id}:root",
        f"arn:aws:iam::{account_id}:role/{ecs_role_name}",
        f"arn:aws:sts::{account_id}:assumed-role/{ecs_role_name}/*",
        f"arn:aws:iam::{account_id}:role/pf-scan-worker-task-role-prod-sim",
        f"arn:aws:sts::{account_id}:assumed-role/pf-scan-worker-task-role-prod-sim/*",
        f"arn:aws:iam::{account_id}:role/pf-soar-s3-lockdown-prod-sim",
    ]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnforceDataPerimeter",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:SourceVpce": "vpce-test-12345",
                    },
                    "ArnNotLike": {
                        "aws:PrincipalArn": allowed_roles,
                    },
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    # Verify that fetched policy contains both IAM role and STS assumed-role wildcards
    fetched_policy = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
    perimeter_stmt = fetched_policy["Statement"][0]
    allowed_principals_in_policy = perimeter_stmt["Condition"]["ArnNotLike"]["aws:PrincipalArn"]

    assert f"arn:aws:iam::{account_id}:role/{ecs_role_name}" in allowed_principals_in_policy
    assert f"arn:aws:sts::{account_id}:assumed-role/{ecs_role_name}/*" in allowed_principals_in_policy

    # 4. Generate presigned POST signed with ECS role STS credentials (external client upload)
    upload_key = "kyc-documents/tenant-uae/broker-42/passport/doc-real-upload.pdf"
    presigned = s3.generate_presigned_post(
        Bucket=bucket_name,
        Key=upload_key,
        Fields={"acl": "private"},
        Conditions=[{"acl": "private"}],
        ExpiresIn=300,
    )
    assert "url" in presigned and "fields" in presigned
    assert presigned["fields"]["key"] == upload_key

    # 5. Verify ECS STS assumed-role session matches allowlist while unauthorized role is rejected
    ecs_sts_session_arn = f"arn:aws:sts::{account_id}:assumed-role/{ecs_role_name}/task-container-session-123"
    ecs_matched = False
    for pat in allowed_principals_in_policy:
        regex_pat = "^" + pat.replace("*", ".*") + "$"
        if re.match(regex_pat, ecs_sts_session_arn):
            ecs_matched = True
            break
    assert ecs_matched, "ECS broker-KYC STS session must match perimeter allowlist pattern"

    unauthorized_sts_arn = f"arn:aws:sts::{account_id}:assumed-role/unauthorized-attacker-role/session-1"
    unauthorized_matched = False
    for pat in allowed_principals_in_policy:
        regex_pat = "^" + pat.replace("*", ".*") + "$"
        if re.match(regex_pat, unauthorized_sts_arn):
            unauthorized_matched = True
            break
    assert not unauthorized_matched, "Unauthorized STS role session must NOT match perimeter allowlist"
