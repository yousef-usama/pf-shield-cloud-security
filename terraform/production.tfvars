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

# SOAR Configuration (Human-in-the-loop escalation + Protected Identities)
containment_mode               = "AUTOMATIC"
protected_principals_allowlist = "root,AWSServiceRole,pf-shield-github-actions,pf-soar-s3-lockdown,pf-soar-iam-quarantine,break-glass,security-admin,lead-security-engineer"
