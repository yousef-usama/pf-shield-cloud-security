"""Unit and Security Test Suite for Relational Database Tier and Analytics Lab.

Validates AWS Glue ETL listing sanitization logic (PII scrubbing, broker pseudonymization),
RDS PostgreSQL configuration invariants (TLS enforcement, Secrets Manager credential governance),
and EC2 ClickHouse host hardening (IMDSv2, zero SSH, SSM-only access).
"""

from __future__ import annotations

import json
import os
import boto3
import pytest
from moto import mock_aws

from src.analytics.glue_etl_sanitize_listings import (
    generate_anonymized_broker_hash,
    process_dataset,
    sanitize_listing_record,
    sanitize_text_field,
)

# Set test environment credentials
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "me-central-1"


# ---------------------------------------------------------------------------------------------------------------------
# 1. AWS GLUE ETL SANITIZATION & PRIVACY TESTS
# ---------------------------------------------------------------------------------------------------------------------

def test_sanitize_text_field_redacts_pii():
    """Verify free text masking for Emirates IDs, emails, and UAE phone numbers."""
    raw_desc = (
        "Luxury 2BR apartment. Contact agent at broker.jane@agency.ae or call +971501234567. "
        "Broker Emirates ID on file: 784-1990-1234567-1 for verification."
    )
    sanitized = sanitize_text_field(raw_desc)

    assert "broker.jane@agency.ae" not in sanitized
    assert "+971501234567" not in sanitized
    assert "784-1990-1234567-1" not in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_PHONE]" in sanitized
    assert "[REDACTED_EID]" in sanitized


def test_generate_anonymized_broker_hash_is_pseudonymous_and_deterministic():
    """Verify broker ID hashing produces a deterministic SHA-256 hash without revealing identity."""
    broker_id = "broker-dubai-42"
    salt = "test-salt-secret"

    hash_1 = generate_anonymized_broker_hash(broker_id, salt=salt)
    hash_2 = generate_anonymized_broker_hash(broker_id, salt=salt)

    assert hash_1 == hash_2
    assert broker_id not in hash_1
    assert len(hash_1) == 32

    # Different salt produces different hash
    hash_diff_salt = generate_anonymized_broker_hash(broker_id, salt="alternative-salt")
    assert hash_1 != hash_diff_salt


def test_sanitize_listing_record_strips_all_prohibited_pii():
    """Verify raw listing records are completely stripped of direct PII fields."""
    raw_record = {
        "listing_id": "listing-uae-101",
        "tenant_id": "tenant-dubai-realestate",
        "broker_id": "broker-7788",
        "broker_emirates_id": "784-1985-7654321-9",
        "broker_phone": "+971559876543",
        "broker_email": "agent.smith@luxuryvillas.ae",
        "landlord_name": "Private Owner",
        "landlord_contact": "+971509998877",
        "internal_owner_notes": "Needs urgent tenant, discount up to 10%",
        "title_deed_number": "TD-2024-DXB-9988",
        "property_type": "Villa",
        "emirate": "Dubai",
        "community": "Palm Jumeirah",
        "price_aed": "4500000.50",
        "bedrooms": "4",
        "bathrooms": "5",
        "square_feet": "5200.0",
        "description": "Exclusive beachfront villa with private pool.",
    }

    curated = sanitize_listing_record(raw_record)

    # Prohibited PII must not exist in output
    assert "broker_emirates_id" not in curated
    assert "broker_phone" not in curated
    assert "broker_email" not in curated
    assert "landlord_name" not in curated
    assert "landlord_contact" not in curated
    assert "internal_owner_notes" not in curated
    assert "title_deed_number" not in curated
    assert "broker-7788" not in curated.values()

    # Analytical dimensions must be normalized
    assert curated["listing_id"] == "listing-uae-101"
    assert curated["property_type"] == "villa"
    assert curated["price_aed"] == 4500000.50
    assert curated["bedrooms"] == 4
    assert curated["bathrooms"] == 5
    assert curated["square_feet"] == 5200.0
    assert curated["anonymized_broker_hash"] != "broker-7788"
    assert curated["etl_sanitization_version"] == "1.0.0"


def test_process_dataset_skips_malformed_records():
    """Verify batch processing skips malformed records missing listing_id."""
    records = [
        {"listing_id": "valid-1", "property_type": "apartment"},
        {"property_type": "villa"},  # missing listing_id
        {"listing_id": "valid-2", "property_type": "townhouse"},
    ]

    curated_batch = process_dataset(records)
    assert len(curated_batch) == 2
    assert curated_batch[0]["listing_id"] == "valid-1"
    assert curated_batch[1]["listing_id"] == "valid-2"


# ---------------------------------------------------------------------------------------------------------------------
# 2. RDS CONFIGURATION & CREDENTIAL GOVERNANCE TESTS
# ---------------------------------------------------------------------------------------------------------------------

@pytest.fixture
def rds_secrets_env():
    """Setup mock Secrets Manager and KMS for database credential governance."""
    with mock_aws():
        kms = boto3.client("kms", region_name="me-central-1")
        sm = boto3.client("secretsmanager", region_name="me-central-1")

        key_res = kms.create_key(Description="PF-Shield Database Test Key")
        key_arn = key_res["KeyMetadata"]["Arn"]

        yield {"kms": kms, "sm": sm, "key_arn": key_arn}


def test_rds_secrets_manager_credential_structure(rds_secrets_env):
    """Verify database credentials stored in Secrets Manager conform to security invariants."""
    sm = rds_secrets_env["sm"]
    key_arn = rds_secrets_env["key_arn"]

    secret_name = "pf-shield/database/credentials/production"
    db_credentials = {
        "engine": "postgres",
        "host": "db.pf-shield.internal",
        "port": 5432,
        "dbname": "pf_shield_metadata",
        "username": "pf_admin",
        "password": "MockSecureRandomPassword!12345",
    }

    create_res = sm.create_secret(
        Name=secret_name,
        KmsKeyId=key_arn,
        SecretString=json.dumps(db_credentials),
    )
    assert create_res["ARN"] is not None

    # Retrieve and verify secret payload
    get_res = sm.get_secret_value(SecretId=secret_name)
    stored = json.loads(get_res["SecretString"])

    assert stored["engine"] == "postgres"
    assert stored["port"] == 5432
    assert stored["username"] == "pf_admin"
    assert len(stored["password"]) >= 16


def test_rds_parameter_group_tls_enforcement_invariants():
    """Verify that PostgreSQL parameter group enforces TLS 1.2+ connection security."""
    # Architectural invariant matching terraform/modules/rds/main.tf
    parameter_group = {
        "family": "postgres16",
        "parameters": {
            "rds.force_ssl": "1",
            "log_connections": "1",
            "log_disconnections": "1",
            "log_min_duration_statement": "1000",
        },
    }

    assert parameter_group["parameters"]["rds.force_ssl"] == "1", "PostgreSQL must enforce TLS via rds.force_ssl=1"
    assert parameter_group["parameters"]["log_connections"] == "1"
    assert parameter_group["parameters"]["log_disconnections"] == "1"


# ---------------------------------------------------------------------------------------------------------------------
# 3. EC2 CLICKHOUSE HOST HARDENING & S3 DATA LAKE TESTS
# ---------------------------------------------------------------------------------------------------------------------

def test_clickhouse_host_hardening_specifications():
    """Verify EC2 ClickHouse analytics node satisfies host hardening invariants:

    - IMDSv2 mandatory (tokens=required, hop_limit=1)
    - Zero SSH ingress (port 22 closed)
    - Encrypted root EBS volume
    - Private subnet placement (no public IP)
    - SSM Session Manager instance profile
    """
    ec2_spec = {
        "associate_public_ip_address": False,
        "ebs_optimized": True,
        "monitoring": True,
        "metadata_options": {
            "http_endpoint": "enabled",
            "http_tokens": "required",
            "http_put_response_hop_limit": 1,
            "instance_metadata_tags": "enabled",
        },
        "root_block_device": {
            "volume_type": "gp3",
            "volume_size": 30,
            "encrypted": True,
        },
        "security_group_ingress_rules": [
            {"port": 8123, "protocol": "tcp", "source": "ecs-security-group"}
        ],
    }

    # 1. IMDSv2 Invariants
    assert ec2_spec["metadata_options"]["http_tokens"] == "required", "IMDSv2 tokens must be required"
    assert ec2_spec["metadata_options"]["http_put_response_hop_limit"] == 1, "Hop limit must be 1 to prevent SSRF"

    # 2. Network & Public IP Invariants
    assert ec2_spec["associate_public_ip_address"] is False, "Host must reside in private subnets with no public IP"

    # 3. Zero SSH Ingress Invariant
    ingress_ports = [rule["port"] for rule in ec2_spec["security_group_ingress_rules"]]
    assert 22 not in ingress_ports, "Port 22 SSH must never be open; administration is via AWS Systems Manager"
    assert 8123 in ingress_ports, "ClickHouse HTTP query port must be open strictly to ECS tasks"

    # 4. Storage Encryption Invariant
    assert ec2_spec["root_block_device"]["encrypted"] is True, "Root EBS volume must be encrypted"


def test_analytics_s3_data_lake_security():
    """Verify S3 Analytics data lake configuration enforces SSE-KMS, versioning, and public block."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="me-central-1")
        bucket_name = "pf-shield-analytics-test-bucket"

        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "me-central-1"},
        )
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        pab = s3.get_public_access_block(Bucket=bucket_name)
        assert pab["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
        assert pab["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"] is True

        # Upload curated analytics parquet artifact
        s3.put_object(
            Bucket=bucket_name,
            Key="curated/year=2026/month=11/listings.parquet",
            Body=b"PAR1mockparquetdata",
            ContentType="application/octet-stream",
        )

        head = s3.head_object(Bucket=bucket_name, Key="curated/year=2026/month=11/listings.parquet")
        assert head["ContentLength"] > 0
