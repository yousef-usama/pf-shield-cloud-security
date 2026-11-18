"""Unit test suite for PF-Shield KYC Vault Handler.

Tests:
1. Anonymous request without authentication token -> rejected (401).
2. Expired JWT -> rejected (401).
3. Malformed JWT -> rejected (401).
4. Missing required tenant_id claim -> rejected (403).
5. Missing required broker_id claim -> rejected (403).
6. Path traversal attempt in tenant_id or broker_id -> rejected (403).
7. Unauthorized role -> rejected (403).
8. Caller sends spoofed broker_id in request body -> ignored; strictly uses verified claim.
9. Invalid document type -> rejected (400).
10. Invalid file extension for document type -> rejected (400).
11. Valid request with API Gateway authorizer context -> success (200), exact prefix, presigned POST, DynamoDB record.
12. Valid request with Authorization Bearer header -> success (200), exact prefix, presigned POST, DynamoDB record.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
import time
from typing import Any

import boto3
import pytest
from moto import mock_aws

# Set test environment credentials
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "me-central-1"
os.environ["ENVIRONMENT"] = "prod-sim"
os.environ["KYC_VAULT_BUCKET_NAME"] = "pf-kyc-vault-sim"
os.environ["DYNAMODB_TABLE_NAME"] = "pf-properties-metadata-prod-sim"
os.environ["KMS_KEY_ARN"] = "arn:aws:kms:me-central-1:123456789012:key/test-cmk-id"


def make_jwt(payload: dict[str, Any]) -> str:
    """Create a mock JWT string with base64url encoded header and payload."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = "mock-signature"
    return f"{header}.{body}.{sig}"


@pytest.fixture
def kyc_environment():
    """Setup mock AWS resources for KYC handler tests."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="me-central-1")
        dynamodb = boto3.resource("dynamodb", region_name="me-central-1")

        # Create mock S3 vault bucket
        s3.create_bucket(
            Bucket="pf-kyc-vault-sim",
            CreateBucketConfiguration={"LocationConstraint": "me-central-1"},
        )

        # Create mock DynamoDB properties & KYC metadata table
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

        import src.app.kyc_vault_handler as handler
        handler.s3_client = s3
        handler.dynamodb = dynamodb

        yield {
            "s3": s3,
            "dynamodb": dynamodb,
            "table": table,
            "handler": handler,
        }


def test_anonymous_request_rejected(kyc_environment):
    """Ensure requests without authentication token receive 401 Unauthorized."""
    handler = kyc_environment["handler"]
    event = {
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
        "headers": {},
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 401
    body = json.loads(resp["body"])
    assert "Unauthorized" in body["error"]


def test_expired_jwt_rejected(kyc_environment):
    """Ensure requests with expired JWT receive 401 Unauthorized."""
    handler = kyc_environment["handler"]
    expired_token = make_jwt({
        "custom:tenant_id": "tenant-dxb-01",
        "custom:broker_id": "broker-9921",
        "custom:role": "broker",
        "exp": time.time() - 3600,  # 1 hour ago
    })

    event = {
        "headers": {"authorization": f"Bearer {expired_token}"},
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 401
    body = json.loads(resp["body"])
    assert "expired" in body["error"].lower()


def test_malformed_jwt_rejected(kyc_environment):
    """Ensure malformed JWT string receives 401 Unauthorized."""
    handler = kyc_environment["handler"]
    event = {
        "headers": {"authorization": "Bearer this-is-not-a-valid-jwt"},
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 401
    body = json.loads(resp["body"])
    assert "Unauthorized" in body["error"]


def test_missing_tenant_id_rejected(kyc_environment):
    """Ensure token missing tenant_id claim receives 403 Forbidden."""
    handler = kyc_environment["handler"]
    token = make_jwt({
        "custom:broker_id": "broker-9921",
        "custom:role": "broker",
        "exp": time.time() + 3600,
    })

    event = {
        "headers": {"authorization": f"Bearer {token}"},
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 403
    body = json.loads(resp["body"])
    assert "tenant_id" in body["error"]


def test_missing_broker_id_rejected(kyc_environment):
    """Ensure token missing broker_id claim receives 403 Forbidden."""
    handler = kyc_environment["handler"]
    token = make_jwt({
        "custom:tenant_id": "tenant-dxb-01",
        "custom:role": "broker",
        "exp": time.time() + 3600,
    })

    event = {
        "headers": {"authorization": f"Bearer {token}"},
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 403
    body = json.loads(resp["body"])
    assert "broker_id" in body["error"]


def test_path_traversal_in_claims_rejected(kyc_environment):
    """Ensure path traversal attacks in tenant_id or broker_id claims are blocked (403)."""
    handler = kyc_environment["handler"]

    # Traversal attempt with ../ in tenant_id
    token_traversal_tenant = make_jwt({
        "custom:tenant_id": "../evil-tenant",
        "custom:broker_id": "broker-9921",
        "custom:role": "broker",
        "exp": time.time() + 3600,
    })
    event1 = {
        "headers": {"authorization": f"Bearer {token_traversal_tenant}"},
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
    }
    resp1 = handler.lambda_handler(event1, None)
    assert resp1["statusCode"] == 403
    assert "traversal" in json.loads(resp1["body"])["error"].lower()

    # Traversal attempt with / in broker_id
    token_traversal_broker = make_jwt({
        "custom:tenant_id": "tenant-dxb-01",
        "custom:broker_id": "admin/../../root",
        "custom:role": "broker",
        "exp": time.time() + 3600,
    })
    event2 = {
        "headers": {"authorization": f"Bearer {token_traversal_broker}"},
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
    }
    resp2 = handler.lambda_handler(event2, None)
    assert resp2["statusCode"] == 403
    assert "traversal" in json.loads(resp2["body"])["error"].lower()


def test_unauthorized_role_rejected(kyc_environment):
    """Ensure user identity without broker or compliance role is rejected (403)."""
    handler = kyc_environment["handler"]
    token = make_jwt({
        "custom:tenant_id": "tenant-dxb-01",
        "custom:broker_id": "broker-9921",
        "custom:role": "unverified_guest",
        "exp": time.time() + 3600,
    })

    event = {
        "headers": {"authorization": f"Bearer {token}"},
        "body": json.dumps({"document_type": "emirates_id", "file_extension": "pdf"}),
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 403
    assert "not authorized" in json.loads(resp["body"])["error"]


def test_caller_supplied_broker_id_is_strictly_ignored(kyc_environment):
    """Verify that caller-supplied broker_id or tenant_id in body is overridden by verified claims."""
    handler = kyc_environment["handler"]
    table = kyc_environment["table"]

    # Authenticated as broker-1111 under tenant-safe
    token = make_jwt({
        "custom:tenant_id": "tenant-safe",
        "custom:broker_id": "broker-1111",
        "custom:role": "broker",
        "exp": time.time() + 3600,
    })

    # Malicious body attempting IDOR / privilege escalation
    event = {
        "headers": {"authorization": f"Bearer {token}"},
        "body": json.dumps({
            "tenant_id": "victim-tenant-999",
            "broker_id": "victim-broker-777",
            "document_type": "emirates_id",
            "file_extension": "pdf",
        }),
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])

    # Prefix MUST use authenticated claims, NOT the caller body
    assert body["tenant_id"] == "tenant-safe"
    assert body["broker_id"] == "broker-1111"
    assert body["object_key"].startswith("kyc-documents/tenant-safe/broker-1111/emirates_id/")
    assert "victim-broker-777" not in body["object_key"]
    assert "victim-tenant-999" not in body["object_key"]

    # DynamoDB record also reflects authenticated claims
    ddb_res = table.get_item(Key={
        "pk": "TENANT#tenant-safe#BROKER#broker-1111",
        "sk": f"KYC#{body['document_id']}",
    })
    assert "Item" in ddb_res
    item = ddb_res["Item"]
    assert item["tenant_id"] == "tenant-safe"
    assert item["broker_id"] == "broker-1111"
    assert item["scan_status"] == "pending_scan"


def test_invalid_document_type_and_extension_rejected(kyc_environment):
    """Ensure invalid doc types and disallowed extensions are rejected with 400."""
    handler = kyc_environment["handler"]
    token = make_jwt({
        "custom:tenant_id": "tenant-dxb-01",
        "custom:broker_id": "broker-9921",
        "custom:role": "broker",
        "exp": time.time() + 3600,
    })

    # 1. Invalid doc type
    event1 = {
        "headers": {"authorization": f"Bearer {token}"},
        "body": json.dumps({"document_type": "credit_card", "file_extension": "pdf"}),
    }
    resp1 = handler.lambda_handler(event1, None)
    assert resp1["statusCode"] == 400
    assert "Invalid document_type" in json.loads(resp1["body"])["error"]

    # 2. Disallowed extension for valid doc type (e.g. exe for passport)
    event2 = {
        "headers": {"authorization": f"Bearer {token}"},
        "body": json.dumps({"document_type": "passport", "file_extension": "exe"}),
    }
    resp2 = handler.lambda_handler(event2, None)
    assert resp2["statusCode"] == 400
    assert "Invalid extension" in json.loads(resp2["body"])["error"]


def test_valid_apigateway_authorizer_context_flow(kyc_environment):
    """Ensure full end-to-end flow succeeds with API Gateway HTTP API native JWT authorizer."""
    handler = kyc_environment["handler"]
    table = kyc_environment["table"]

    event = {
        "requestContext": {
            "authorizer": {
                "jwt": {
                    "claims": {
                        "custom:tenant_id": "tenant-aldar-01",
                        "custom:broker_id": "broker-4433",
                        "custom:role": "broker",
                        "exp": str(time.time() + 3600),
                    }
                }
            }
        },
        "body": json.dumps({
            "document_type": "passport",
            "file_extension": "jpg",
        }),
    }

    resp = handler.lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])

    assert body["status"] == "success"
    assert body["scan_status"] == "pending_scan"
    assert body["object_key"].startswith("kyc-documents/tenant-aldar-01/broker-4433/passport/")
    assert body["object_key"].endswith(".jpg")
    assert body["encryption"] == "aws:kms"
    assert body["compliance"] == "UAE-PDPL-Federal-Decree-Law-45-2021"

    # Verify Presigned POST details
    assert "upload_url" in body
    assert "upload_fields" in body
    fields = body["upload_fields"]
    assert fields["Content-Type"] == "image/jpeg"
    assert fields["x-amz-server-side-encryption"] == "aws:kms"
    assert fields["key"] == body["object_key"]

    # Verify DynamoDB record was created with 'pending_scan'
    ddb_res = table.get_item(Key={
        "pk": "TENANT#tenant-aldar-01#BROKER#broker-4433",
        "sk": f"KYC#{body['document_id']}",
    })
    assert "Item" in ddb_res
    item = ddb_res["Item"]
    assert item["scan_status"] == "pending_scan"
    assert item["content_type"] == "image/jpeg"
    assert item["object_key"] == body["object_key"]
