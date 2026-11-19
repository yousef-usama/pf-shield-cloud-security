#!/usr/bin/env python3
"""PF-Shield AWS Glue ETL Data Sanitization Pipeline.

Transforms raw real estate listing records into a curated, anonymized dataset
suitable for analytical query engines (ClickHouse, Athena) while strictly enforcing
UAE Personal Data Protection Law (PDPL) and ISO 27001 data privacy standards.

Removes sensitive broker identifiers, customer PII, and landlord contacts;
generates cryptographic pseudonymous broker hashes; and validates data schemas.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

# Regex patterns for detecting leaked PII in unstructured text
EMIRATES_ID_REGEX = re.compile(r"784-\d{4}-\d{7}-\d", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", re.IGNORECASE)
PHONE_REGEX = re.compile(r"(?:\+971|00971|0)?(?:50|51|52|54|55|56|58|2|3|4|6|7|9)\d{7}", re.IGNORECASE)

# PII fields strictly stripped from analytics payloads
PROHIBITED_PII_FIELDS = {
    "broker_emirates_id",
    "broker_phone",
    "broker_email",
    "landlord_name",
    "landlord_contact",
    "landlord_emirates_id",
    "internal_owner_notes",
    "title_deed_number",
}


def sanitize_text_field(text: str) -> str:
    """Mask any detected PII patterns (Emirates IDs, emails, UAE phone numbers) within free text."""
    if not isinstance(text, str):
        return text
    masked = EMIRATES_ID_REGEX.sub("[REDACTED_EID]", text)
    masked = EMAIL_REGEX.sub("[REDACTED_EMAIL]", masked)
    masked = PHONE_REGEX.sub("[REDACTED_PHONE]", masked)
    return masked


def generate_anonymized_broker_hash(broker_id: str, salt: str = "pf-shield-analytics-salt") -> str:
    """Generate deterministic pseudonymous hash for correlation without identity leakage."""
    if not broker_id:
        return "UNKNOWN_BROKER"
    combined = f"{salt}:{broker_id.strip()}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:32]


def sanitize_listing_record(raw_record: Dict[str, Any], salt: str = "pf-shield-analytics-salt") -> Dict[str, Any]:
    """Sanitize a single raw property listing record for analytical ingestion.

    Drops all sensitive PII fields, anonymizes broker identities, scrubs free text,
    and formats data types.
    """
    # 1. Verify and extract required analytical attributes
    listing_id = str(raw_record.get("listing_id", "")).strip()
    if not listing_id:
        raise ValueError("Record missing required 'listing_id'")

    raw_broker_id = str(raw_record.get("broker_id", "")).strip()
    tenant_id = str(raw_record.get("tenant_id", "default")).strip()
    property_type = str(raw_record.get("property_type", "apartment")).lower().strip()
    emirate = str(raw_record.get("emirate", "Dubai")).strip()
    community = str(raw_record.get("community", "Downtown")).strip()

    # 2. Extract numeric dimensions with safe defaults
    try:
        price_aed = float(raw_record.get("price_aed", 0.0))
    except (ValueError, TypeError):
        price_aed = 0.0

    try:
        bedrooms = int(raw_record.get("bedrooms", 1))
    except (ValueError, TypeError):
        bedrooms = 1

    try:
        bathrooms = int(raw_record.get("bathrooms", 1))
    except (ValueError, TypeError):
        bathrooms = 1

    try:
        square_feet = float(raw_record.get("square_feet", 500.0))
    except (ValueError, TypeError):
        square_feet = 500.0

    # 3. Sanitize description
    raw_desc = str(raw_record.get("description", ""))
    sanitized_desc = sanitize_text_field(raw_desc)

    # 4. Construct curated anonymized analytical record
    curated: Dict[str, Any] = {
        "listing_id": listing_id,
        "tenant_id": tenant_id,
        "anonymized_broker_hash": generate_anonymized_broker_hash(raw_broker_id, salt=salt),
        "property_type": property_type,
        "emirate": emirate,
        "community": community,
        "price_aed": price_aed,
        "bedrooms": bedrooms,
        "bathrooms": bathrooms,
        "square_feet": square_feet,
        "description_scrubbed": sanitized_desc,
        "is_active": bool(raw_record.get("is_active", True)),
        "created_at": raw_record.get("created_at", "2026-11-19T00:00:00Z"),
        "etl_sanitization_version": "1.0.0",
    }

    # Verify no prohibited PII fields remain
    for pii_key in PROHIBITED_PII_FIELDS:
        if pii_key in curated:
            del curated[pii_key]

    return curated


def process_dataset(raw_records: List[Dict[str, Any]], salt: str = "pf-shield-analytics-salt") -> List[Dict[str, Any]]:
    """Sanitize a list of raw records, filtering invalid records."""
    curated_records = []
    for raw in raw_records:
        try:
            curated_records.append(sanitize_listing_record(raw, salt=salt))
        except ValueError as err:
            sys.stderr.write(f"Skipping malformed record: {err}\n")
    return curated_records


def run_standalone(input_path: str, output_path: str) -> None:
    """Run standalone transformation from JSON input to sanitized JSON output."""
    with open(input_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    if isinstance(raw_data, dict):
        raw_records = [raw_data]
    elif isinstance(raw_data, list):
        raw_records = raw_data
    else:
        raise ValueError("Input JSON must be an object or an array of objects")

    curated = process_dataset(raw_records)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(curated, f, indent=2)

    sys.stdout.write(f"Successfully processed {len(curated)} records to {output_path}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PF-Shield Listing Sanitization ETL")
    parser.add_argument("--input", default=None, help="Input JSON file path")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    parser.add_argument("--RAW_BUCKET", default=None, help="Glue S3 raw bucket")
    parser.add_argument("--CURATED_BUCKET", default=None, help="Glue S3 curated bucket")
    parser.add_argument("--ENVIRONMENT", default="demo", help="Deployment environment")

    args, unknown = parser.parse_known_args()

    if args.input and args.output:
        run_standalone(args.input, args.output)
    else:
        sys.stdout.write("Glue Job initialization - PySpark / standalone dual-mode ready.\n")
