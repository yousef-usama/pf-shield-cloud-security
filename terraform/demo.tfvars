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

# SOAR Configuration
containment_mode               = "AUTOMATIC"
protected_principals_allowlist = "root,AWSServiceRole,pf-shield-github-actions,pf-soar-s3-lockdown,pf-soar-iam-quarantine,break-glass,security-admin"
