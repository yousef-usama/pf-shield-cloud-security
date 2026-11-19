# =====================================================================================================================
# PF-SHIELD DEMONSTRATION & TESTING ENVIRONMENT PROFILE (demo.tfvars)
# =====================================================================================================================
# NOTICE: This profile is engineered strictly for low-cost, short-lived evaluation, CI/CD pipeline validation,
# and attack simulation at $0.00 idle cost.
# DO NOT REPRESENT THIS PROFILE AS PRODUCTION-SECURE.
# Paid security services (WAF, GuardDuty, Security Hub) are disabled by default to maintain $0.00 idle spend.
# =====================================================================================================================

environment              = "demo"
aws_region               = "me-central-1"
fallback_region          = "me-south-1"
owner                    = "YousefOsama"
alert_email              = "demo-alerts@example.com"
monthly_budget_limit_usd = "5.0"

# FinOps Guardrails ($0.00 Idle Spend)
enable_waf                       = false
enable_guardduty_and_securityhub = false
enable_observability_dashboard   = true

# ECS Container Platform (Scale-to-Zero for $0.00 Idle Compute)
ecs_desired_count          = 0
enable_deletion_protection = false

# Compliance & Detective Controls ($0.00 Idle Spend)
enable_aws_config                = false
enable_cloudtrail_s3_data_events = false
audit_retention_days             = 7

# SOAR Configuration
containment_mode               = "AUTOMATIC"
protected_principals_allowlist = "root,AWSServiceRole,pf-shield-github-actions,pf-soar-s3-lockdown,pf-soar-iam-quarantine,break-glass,security-admin"
