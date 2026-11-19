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
