# =====================================================================================================================
# PF-SHIELD PRODUCTION SECURITY BASELINE PROFILE (production.tfvars)
# =====================================================================================================================
# Hardened enterprise baseline enforcing full detective controls, multi-layer edge defense, comprehensive
# audit trails, annual KMS rotation, and strict data residency under UAE PDPL (Federal Decree-Law No. 45 of 2021).
# =====================================================================================================================

environment              = "production"
aws_region               = "me-central-1"
fallback_region          = "me-south-1"
owner                    = "YousefOsama"
alert_email              = "secops@pf-shield.ae"
monthly_budget_limit_usd = "250.0"

# Production Security Baseline
enable_waf                       = true
enable_guardduty_and_securityhub = true
enable_observability_dashboard   = true

# ECS Container Platform (Production HA across Private Subnets)
ecs_desired_count          = 2
enable_deletion_protection = true
enable_cloudfront          = true

# Compliance & Detective Controls (Production Baseline)
enable_aws_config                = true
enable_cloudtrail_s3_data_events = true
audit_retention_days             = 365

# Relational Database & Analytics Lab (Production Baseline)
enable_rds              = true
rds_instance_class      = "db.t4g.micro"
enable_analytics_lab    = true
analytics_instance_type = "t4g.small"
enable_glue_etl         = true

# SOAR Configuration (Human-in-the-loop escalation + Protected Identities)
containment_mode               = "AUTOMATIC"
protected_principals_allowlist = "root,AWSServiceRole,pf-shield-github-actions,pf-soar-s3-lockdown,pf-soar-iam-quarantine,break-glass,security-admin,lead-security-engineer"

# Public Domain & Retention Settings (Production Baseline)
public_domain_name  = "pf-shield.ae"
route53_zone_id     = "Z08392173R82K9L0P2Q1"
container_image_tag = "pf-shield@sha256:ba837841108226011a68ba9b0a6245084988f01b3d7b4202a4d339185a73e670"
container_image_digests = {
  listings_api         = "123456789012.dkr.ecr.me-central-1.amazonaws.com/pf-shield/listings-api-production@sha256:ba837841108226011a68ba9b0a6245084988f01b3d7b4202a4d339185a73e670"
  broker_kyc_api       = "123456789012.dkr.ecr.me-central-1.amazonaws.com/pf-shield/broker-kyc-api-production@sha256:d123456789012345678901234567890123456789012345678901234567890123"
  document_scan_worker = "123456789012.dkr.ecr.me-central-1.amazonaws.com/pf-shield/document-scan-worker-production@sha256:e123456789012345678901234567890123456789012345678901234567890123"
}
log_retention_days      = 365
enable_waf_logging      = true
enable_alb_cognito_auth = true
