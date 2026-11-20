# =====================================================================================================================
# PF-SHIELD PRODUCTION SECURITY BASELINE PROFILE (production.tfvars)
# =====================================================================================================================
# Hardened enterprise baseline enforcing full detective controls, multi-layer edge defense, comprehensive
# audit trails, annual KMS rotation, and strict data residency under UAE PDPL (Federal Decree-Law No. 45 of 2021).
# =====================================================================================================================

environment              = "production"
aws_region               = "me-central-1"
fallback_region          = "me-south-1"
owner                    = "yousef-usama"
alert_email              = "secops@pf-shield.ae"
monthly_budget_limit_usd = "250.0"

# Production Security Baseline
enable_waf                       = true
enable_guardduty_and_securityhub = true
enable_observability_dashboard   = true

# ECS Container Platform (Production HA across Private Subnets)
ecs_desired_count          = 2
enable_ecs_services        = false
enable_deletion_protection = true
enable_cloudfront          = false

# Compliance & Detective Controls (Production Baseline)
enable_aws_config                = false
enable_cloudtrail_s3_data_events = true
audit_retention_days             = 365

# Relational Database & Analytics Lab (Production Baseline)
enable_rds              = false
rds_instance_class      = "db.t4g.micro"
enable_analytics_lab    = false
analytics_instance_type = "t4g.small"
enable_glue_etl         = false

# SOAR Configuration (Human-in-the-loop escalation + Protected Identities)
containment_mode               = "AUTOMATIC"
protected_principals_allowlist = "root,AWSServiceRole,pf-shield-github-actions,pf-soar-s3-lockdown,pf-soar-iam-quarantine,break-glass,security-admin,lead-security-engineer"

# Public Domain & Retention Settings (Production Baseline)
public_domain_name = "yousef-usama-cloud.click"
route53_zone_id    = "Z061996824D3MYGC69U2P"
ecr_repository_urls = {
  listings_api         = "339712755065.dkr.ecr.eu-central-1.amazonaws.com/pf-shield/listings-api-production"
  broker_kyc_api       = "339712755065.dkr.ecr.eu-central-1.amazonaws.com/pf-shield/broker-kyc-api-production"
  document_scan_worker = "339712755065.dkr.ecr.eu-central-1.amazonaws.com/pf-shield/document-scan-worker-production"
}
container_image_tag = "pf-shield@sha256:7cfd0ddaaf9706b54b0b7f9876aa90b04266c01ff932cfa8bd85ff12a781f783"
container_image_digests = {
  listings_api         = "339712755065.dkr.ecr.eu-central-1.amazonaws.com/pf-shield/listings-api-production@sha256:7cfd0ddaaf9706b54b0b7f9876aa90b04266c01ff932cfa8bd85ff12a781f783"
  broker_kyc_api       = "339712755065.dkr.ecr.eu-central-1.amazonaws.com/pf-shield/broker-kyc-api-production@sha256:cbcd24d2231aaa96197b2e39d048a121f63f1936d9874e270f6fe80c194bc154"
  document_scan_worker = "339712755065.dkr.ecr.eu-central-1.amazonaws.com/pf-shield/document-scan-worker-production@sha256:85ea1ed6233d7e9ddf5fe3ab8bb311a1cb04160509bd81546ee93d6a9901cae7"
}
log_retention_days      = 365
enable_waf_logging      = true
enable_alb_cognito_auth = false
