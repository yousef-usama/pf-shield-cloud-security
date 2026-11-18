"""PF-Shield Real Estate Platform: Containerized Public Property Listings API Service.

Runs as a secure, non-root microservice on Amazon ECS behind Application Load Balancer.
Provides:
1. /healthz container health probe.
2. GET /api/v1/properties with security headers and UAE market data.
3. DynamoDB integration for property metadata retrieval.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("listings-api")

app = FastAPI(
    title="PF-Shield Property Listings Service",
    description="Public real estate search and verified property listing microservice",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://*.pf-shield.ae", "https://*.realestate.ae"],
    allow_credentials=True,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    max_age=300,
)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
    "Cache-Control": "public, max-age=60, s-maxage=300",
}

# Regional DynamoDB Client
REGION = os.environ.get("AWS_REGION", "me-central-1")
TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", f"pf-properties-metadata-{os.environ.get('ENVIRONMENT', 'prod-sim')}")
dynamodb = boto3.resource("dynamodb", region_name=REGION)

SAMPLE_LISTINGS = [
    {
        "id": "pf-dxb-marina-8821",
        "title": "Luxury 2BR Waterfront Apartment — Dubai Marina",
        "price_aed": 2450000,
        "bedrooms": 2,
        "bathrooms": 3,
        "permit_number": "RERA-PERMIT-0928114",
        "broker_verified": True,
        "emirate": "Dubai",
        "coordinates": {"lat": 25.0763, "lng": 55.1405},
        "compliance": "UAE-PDPL-Federal-Decree-Law-45-2021",
    },
    {
        "id": "pf-auh-reem-4019",
        "title": "Modern 3BR Penthouse with Panoramic Sea Views — Al Reem Island",
        "price_aed": 3800000,
        "bedrooms": 3,
        "bathrooms": 4,
        "permit_number": "DMT-PERMIT-6612980",
        "broker_verified": True,
        "emirate": "Abu Dhabi",
        "coordinates": {"lat": 24.4988, "lng": 54.4069},
        "compliance": "UAE-PDPL-Federal-Decree-Law-45-2021",
    },
    {
        "id": "pf-dxb-palm-1102",
        "title": "Signature 5BR Beachfront Villa — Palm Jumeirah Frond M",
        "price_aed": 18500000,
        "bedrooms": 5,
        "bathrooms": 6,
        "permit_number": "RERA-PERMIT-0481903",
        "broker_verified": True,
        "emirate": "Dubai",
        "coordinates": {"lat": 25.1124, "lng": 55.1390},
        "compliance": "UAE-PDPL-Federal-Decree-Law-45-2021",
    },
]


@app.middleware("http")
async def add_security_headers(request, call_next):
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
        "service": "listings-api",
        "region": REGION,
        "runtime": "ecs-fargate-container",
    }


@app.get("/api/v1/properties")
async def get_properties(emirate: str | None = None, limit: int = 10) -> dict[str, Any]:
    """Retrieve verified property listings from DynamoDB or curated baseline."""
    listings = list(SAMPLE_LISTINGS)

    # Attempt dynamic query from DynamoDB metadata table
    try:
        table = dynamodb.Table(TABLE_NAME)
        resp = table.query(
            KeyConditionExpression="pk = :pk_val",
            ExpressionAttributeValues={":pk_val": "PROPERTY_CATALOG"},
            Limit=limit,
        )
        db_items = resp.get("Items", [])
        if db_items:
            listings = db_items
    except ClientError as err:
        logger.warning("DynamoDB catalog query failed, falling back to cached baseline: %s", err)

    if emirate:
        listings = [l for l in listings if l.get("emirate", "").lower() == emirate.lower()]

    return {
        "status": "success",
        "count": len(listings),
        "data": listings,
        "market": "United Arab Emirates",
        "jurisdiction": "me-central-1",
    }
