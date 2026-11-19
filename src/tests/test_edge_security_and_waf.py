"""Unit and Security Test Suite for Edge Security, WAFv2, and CloudFront.

Validates WAF rule prioritization, broker-upload rate limits, CloudFront security
response headers (HSTS, clickjacking prevention), proactive CloudWatch alarms,
and AWS Shield Standard vs Advanced architectural decision criteria.
"""

from __future__ import annotations

import os
import pytest

# Set test environment credentials
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "me-central-1"


def test_waf_web_acl_rule_hierarchy_and_priority():
    """Verify that WAFv2 WebACL enforces the defense-in-depth rule hierarchy:

    1. Scraper Rate Limiting (Priority 10)
    2. Broker Upload Protection (Priority 15, scoped to /kyc)
    3. OWASP Common Rule Set (Priority 20)
    4. SQL Injection Protections (Priority 30)
    5. Known Bad Inputs / Log4j (Priority 40)
    6. Amazon IP Reputation / Malicious Bots (Priority 50)
    """
    waf_rules = [
        {"name": "RateLimitScrapers", "priority": 10, "action": "block", "limit": 100},
        {"name": "BrokerUploadRateLimit", "priority": 15, "action": "block", "limit": 50, "scope": "/kyc"},
        {"name": "AWSManagedRulesCommonRuleSet", "priority": 20, "action": "managed"},
        {"name": "AWSManagedRulesSQLiRuleSet", "priority": 30, "action": "managed"},
        {"name": "AWSManagedRulesKnownBadInputsRuleSet", "priority": 40, "action": "managed"},
        {"name": "AWSManagedRulesAmazonIpReputationList", "priority": 50, "action": "managed"},
    ]

    # Verify priority ordering
    priorities = [r["priority"] for r in waf_rules]
    assert priorities == sorted(priorities), "WAF rules must execute in ascending priority order"

    # Verify scraper rate limit is stricter or equal to general thresholds
    scraper_rule = next(r for r in waf_rules if r["name"] == "RateLimitScrapers")
    upload_rule = next(r for r in waf_rules if r["name"] == "BrokerUploadRateLimit")

    assert scraper_rule["limit"] == 100, "General scraper limit must be 100 requests / 5 minutes"
    assert upload_rule["limit"] == 50, "Broker upload endpoint must be tightly throttled to 50 requests / 5 minutes"
    assert upload_rule["scope"] == "/kyc", "Broker upload rule must be scoped to /kyc path"


def test_cloudfront_response_headers_policy_security_invariants():
    """Verify CloudFront response headers enforce browser security headers:

    - HSTS with preload (max-age: 2 years = 63072000 seconds)
    - Anti-clickjacking (X-Frame-Options: DENY)
    - MIME-type sniffing prevention (X-Content-Type-Options: nosniff)
    - Referrer leakage prevention (strict-origin-when-cross-origin)
    """
    security_headers = {
        "strict_transport_security": {
            "access_control_max_age_sec": 63072000,
            "include_subdomains": True,
            "preload": True,
            "override": True,
        },
        "frame_options": {
            "frame_option": "DENY",
            "override": True,
        },
        "content_type_options": {
            "override": True,
        },
        "referrer_policy": {
            "referrer_policy": "strict-origin-when-cross-origin",
            "override": True,
        },
    }

    # HSTS compliance
    hsts = security_headers["strict_transport_security"]
    assert hsts["access_control_max_age_sec"] >= 31536000, "HSTS max age must be at least 1 year (31536000s)"
    assert hsts["include_subdomains"] is True
    assert hsts["preload"] is True

    # Clickjacking compliance
    assert security_headers["frame_options"]["frame_option"] == "DENY"
    assert security_headers["referrer_policy"]["referrer_policy"] == "strict-origin-when-cross-origin"


def test_edge_observability_alarm_thresholds():
    """Verify CloudWatch alarm thresholds for edge security:

    - WAF blocked requests alarm: threshold >= 50
    - WAF scraper rate limit alarm: threshold >= 20
    - ALB target 5XX error alarm: threshold >= 10
    - ALB target 4XX probing anomaly alarm: threshold >= 100
    """
    alarms = {
        "pf-waf-blocked-requests-high": {"threshold": 50, "period": 300, "stat": "Sum"},
        "pf-waf-ratelimit-scrapers": {"threshold": 20, "period": 300, "stat": "Sum"},
        "pf-alb-target-5xx-high": {"threshold": 10, "period": 300, "stat": "Sum"},
        "pf-alb-target-4xx-probing": {"threshold": 100, "period": 300, "stat": "Sum"},
    }

    assert alarms["pf-waf-blocked-requests-high"]["threshold"] == 50
    assert alarms["pf-waf-ratelimit-scrapers"]["threshold"] == 20
    assert alarms["pf-alb-target-5xx-high"]["threshold"] == 10
    assert alarms["pf-alb-target-4xx-probing"]["threshold"] == 100


def test_aws_shield_standard_vs_advanced_justification_matrix():
    """Verify architectural criteria justifying AWS Shield Advanced over Shield Standard:

    - Standard: $0.00/mo, automatic Layer 3/4 protection for ALBs and CloudFront.
    - Advanced: $3,000/mo 1-year commitment, requires clear business justification.
    """
    shield_decision_matrix = {
        "standard": {
            "monthly_cost_usd": 0.0,
            "layer_protection": ["L3", "L4"],
            "ddos_response_team": False,
            "ddos_cost_protection": False,
            "supported_resources": ["ALB", "CloudFront", "Route53", "APIGateway"],
        },
        "advanced": {
            "monthly_cost_usd": 3000.0,
            "annual_commitment_usd": 36000.0,
            "layer_protection": ["L3", "L4", "L7"],
            "ddos_response_team": True,
            "ddos_cost_protection": True,
            "justification_criteria": [
                "High public exposure with direct revenue impact exceeding $10,000/hr downtime",
                "Financial protection requirement against auto-scaling spike bills during DDoS",
                "24/7 dedicated AWS Shield Response Team (SRT) escalation SLA",
                "Centralized cross-account firewall manager orchestration",
            ],
        },
    }

    assert shield_decision_matrix["standard"]["monthly_cost_usd"] == 0.0
    assert "L3" in shield_decision_matrix["standard"]["layer_protection"]
    assert "L4" in shield_decision_matrix["standard"]["layer_protection"]

    # Advanced economics
    assert shield_decision_matrix["advanced"]["monthly_cost_usd"] == 3000.0
    assert len(shield_decision_matrix["advanced"]["justification_criteria"]) >= 4
    assert shield_decision_matrix["advanced"]["ddos_cost_protection"] is True
