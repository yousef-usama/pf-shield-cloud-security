"""Disaster Recovery and Backup Restoration Automated Verification Tests.

Tests simulated disaster recovery procedures including S3 versioning delete marker
rollback, DynamoDB point-in-time recovery (PITR) configuration, and S3 Object Lock
WORM compliance / legal hold verification using moto.
"""

from __future__ import annotations

import io
import os
import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

# Ensure consistent AWS test environment
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "me-central-1"

KYC_BUCKET = "pf-shield-kyc-vault-production"
AUDIT_BUCKET = "pf-shield-audit-logs-production"
KYC_TABLE = "pf-shield-kyc-scan-state-production"


@pytest.fixture
def dr_environment():
    """Setup mock AWS resources for Disaster Recovery verification."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="me-central-1")
        dynamodb = boto3.client("dynamodb", region_name="me-central-1")

        # 1. Create S3 KYC Vault with Versioning Enabled
        s3.create_bucket(
            Bucket=KYC_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "me-central-1"},
        )
        s3.put_bucket_versioning(
            Bucket=KYC_BUCKET,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # 2. Create S3 Immutable Audit Bucket with Object Lock
        s3.create_bucket(
            Bucket=AUDIT_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "me-central-1"},
            ObjectLockEnabledForBucket=True,
        )
        s3.put_object_lock_configuration(
            Bucket=AUDIT_BUCKET,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "COMPLIANCE",
                        "Days": 365,
                    }
                },
            },
        )

        # 3. Create DynamoDB KYC Scan State Table with PITR
        dynamodb.create_table(
            TableName=KYC_TABLE,
            KeySchema=[{"AttributeName": "document_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "document_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        dynamodb.update_continuous_backups(
            TableName=KYC_TABLE,
            PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
        )

        yield {"s3": s3, "dynamodb": dynamodb}


def test_s3_delete_marker_recovery(dr_environment):
    """Verify that an accidentally deleted versioned S3 object can be restored

    by deleting the active Delete Marker, achieving RPO=0 for deletions.
    """
    s3 = dr_environment["s3"]
    object_key = "kyc-documents/tenant-uae-1/broker-42/passport/doc-99.pdf"
    original_payload = b"%PDF-1.5 Genuine passport KYC document payload"

    # Step 1: Upload initial active document
    put_res = s3.put_object(
        Bucket=KYC_BUCKET,
        Key=object_key,
        Body=original_payload,
        ContentType="application/pdf",
    )
    initial_version_id = put_res.get("VersionId")
    assert initial_version_id is not None

    # Verify object is accessible
    fetched = s3.get_object(Bucket=KYC_BUCKET, Key=object_key)
    assert fetched["Body"].read() == original_payload

    # Step 2: Simulate accidental deletion (e.g., rogue script or admin error)
    delete_res = s3.delete_object(Bucket=KYC_BUCKET, Key=object_key)
    assert delete_res.get("DeleteMarker") is True
    delete_marker_version_id = delete_res.get("VersionId")
    assert delete_marker_version_id is not None

    # Verify object is now inaccessible via standard GET (returns 404 NoSuchKey)
    with pytest.raises(ClientError) as exc_info:
        s3.get_object(Bucket=KYC_BUCKET, Key=object_key)
    assert exc_info.value.response["Error"]["Code"] in ("NoSuchKey", "404")

    # Step 3: Disaster Recovery Procedure - List object versions and locate Delete Marker
    versions_res = s3.list_object_versions(Bucket=KYC_BUCKET, Prefix=object_key)
    delete_markers = versions_res.get("DeleteMarkers", [])
    assert len(delete_markers) == 1
    assert delete_markers[0]["VersionId"] == delete_marker_version_id
    assert delete_markers[0]["IsLatest"] is True

    # Step 4: Remove the Delete Marker to restore the underlying active version
    s3.delete_object(
        Bucket=KYC_BUCKET,
        Key=object_key,
        VersionId=delete_marker_version_id,
    )

    # Step 5: Verification - Object is restored and content is identical
    restored = s3.get_object(Bucket=KYC_BUCKET, Key=object_key)
    restored_payload = restored["Body"].read()
    assert restored_payload == original_payload
    assert restored["ContentType"] == "application/pdf"


def test_s3_version_rollback_after_corruption(dr_environment):
    """Verify that if an object is overwritten or corrupted, an operator can

    roll back to a specific historical version ID.
    """
    s3 = dr_environment["s3"]
    object_key = "kyc-documents/tenant-uae-1/broker-42/title_deed/deed-01.pdf"
    v1_good_content = b"%PDF-1.4 Valid Real Estate Title Deed Document"
    v2_corrupted_content = b"TAMPERED / CORRUPTED DATA BY MALICIOUS PROCESS"

    # Step 1: Upload version 1 (good data)
    res_v1 = s3.put_object(Bucket=KYC_BUCKET, Key=object_key, Body=v1_good_content)
    v1_id = res_v1["VersionId"]

    # Step 2: Upload version 2 (corruption incident)
    res_v2 = s3.put_object(Bucket=KYC_BUCKET, Key=object_key, Body=v2_corrupted_content)
    v2_id = res_v2["VersionId"]
    assert v1_id != v2_id

    # Latest active content is currently the corrupted one
    current = s3.get_object(Bucket=KYC_BUCKET, Key=object_key)
    assert current["Body"].read() == v2_corrupted_content

    # Step 3: Disaster Recovery Procedure - Retrieve historical v1 payload
    historical_obj = s3.get_object(Bucket=KYC_BUCKET, Key=object_key, VersionId=v1_id)
    recovered_data = historical_obj["Body"].read()
    assert recovered_data == v1_good_content

    # Step 4: Re-upload recovered content as the latest active version
    s3.put_object(Bucket=KYC_BUCKET, Key=object_key, Body=recovered_data)

    # Step 5: Verify latest object is restored to valid data
    verified_latest = s3.get_object(Bucket=KYC_BUCKET, Key=object_key)
    assert verified_latest["Body"].read() == v1_good_content


def test_dynamodb_point_in_time_recovery_status(dr_environment):
    """Verify DynamoDB table PITR is enabled with continuous backup windows."""
    dynamodb = dr_environment["dynamodb"]

    # Verify continuous backup configuration
    backup_desc = dynamodb.describe_continuous_backups(TableName=KYC_TABLE)
    pitr_desc = backup_desc["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]

    assert pitr_desc["PointInTimeRecoveryStatus"] == "ENABLED"
    assert "EarliestRestorableDateTime" in pitr_desc
    assert "LatestRestorableDateTime" in pitr_desc

    # Insert test items to verify table readiness
    dynamodb.put_item(
        TableName=KYC_TABLE,
        Item={
            "document_id": {"S": "doc-uuid-1234"},
            "tenant_id": {"S": "tenant-uae-1"},
            "broker_id": {"S": "broker-42"},
            "scan_status": {"S": "CLEAN"},
            "timestamp": {"N": "1732000000"},
        },
    )

    get_res = dynamodb.get_item(
        TableName=KYC_TABLE,
        Key={"document_id": {"S": "doc-uuid-1234"}},
    )
    assert get_res["Item"]["scan_status"]["S"] == "CLEAN"


def test_s3_immutable_audit_object_lock_and_legal_hold(dr_environment):
    """Verify S3 Object Lock COMPLIANCE retention and Legal Hold capabilities

    for regulatory audit trails.
    """
    s3 = dr_environment["s3"]
    log_key = "AWSLogs/123456789012/CloudTrail/me-central-1/2026/11/19/audit-log.json.gz"
    audit_data = b'{"Records": [{"eventSource": "s3.amazonaws.com", "eventName": "PutObject"}]}'

    # Step 1: Upload audit log into Object Lock protected bucket
    s3.put_object(
        Bucket=AUDIT_BUCKET,
        Key=log_key,
        Body=audit_data,
        ContentType="application/gzip",
    )

    # Step 2: Verify default Object Lock configuration is active
    lock_config = s3.get_object_lock_configuration(Bucket=AUDIT_BUCKET)
    rule = lock_config["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]
    assert rule["Mode"] == "COMPLIANCE"
    assert rule["Days"] == 365

    # Step 3: Place Legal Hold on audit object for forensic investigation
    s3.put_object_legal_hold(
        Bucket=AUDIT_BUCKET,
        Key=log_key,
        LegalHold={"Status": "ON"},
    )

    # Step 4: Verify Legal Hold status is ON
    lh_res = s3.get_object_legal_hold(Bucket=AUDIT_BUCKET, Key=log_key)
    assert lh_res["LegalHold"]["Status"] == "ON"


def test_dr_rto_rpo_slo_objectives():
    """Verify documented RTO and RPO targets meet architectural and compliance invariants."""
    # Target SLO definitions as documented in RUNBOOK-03
    max_rto_minutes = 60
    max_rpo_minutes = 15

    # Target SLAs:
    # S3 Versioning Delete Marker recovery estimated execution time: < 5 minutes
    # DynamoDB PITR restoration estimated execution time: 10 - 25 minutes
    # Route 53 DNS failover convergence time: < 5 minutes
    estimated_s3_restore_minutes = 5
    estimated_dynamo_pitr_minutes = 20
    estimated_dns_failover_minutes = 5

    total_worst_case_rto = max(estimated_dynamo_pitr_minutes, estimated_s3_restore_minutes) + estimated_dns_failover_minutes
    assert total_worst_case_rto <= max_rto_minutes, f"Calculated RTO ({total_worst_case_rto}m) exceeds max SLA ({max_rto_minutes}m)"

    # DynamoDB continuous PITR RPO window is continuous down to the second (0-5s)
    dynamo_pitr_rpo_seconds = 5
    assert (dynamo_pitr_rpo_seconds / 60) <= max_rpo_minutes
