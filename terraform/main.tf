# =====================================================================================================================
# PF-SHIELD CLUSTER & INFRASTRUCTURE ROOT MODULE
# Property Finder UAE Cloud Security Control Plane & Zero-Trust Architecture
# =====================================================================================================================

# 1. IAM Permission Boundaries & Zero-Trust Identity Guardrails
module "iam_boundaries" {
  source = "./modules/iam-boundaries"

  aws_region  = var.aws_region
  environment = var.environment
}

# 2. FinOps Automated Cost Controls & Budget Guardrails ($5/month cap)
module "finops_budget" {
  source = "./modules/finops-budget"

  monthly_budget_limit_usd = var.monthly_budget_limit_usd
  alert_email              = var.alert_email
  environment              = var.environment
}

# 3. Zero-Trust KYC Document Vault & Private Network Perimeter
module "zero_trust_kyc_vault" {
  source = "./modules/zero-trust-kyc-vault"

  aws_region  = var.aws_region
  environment = var.environment

  # Pre-allow roles that will be deployed in subsequent phases
  allowed_principal_arns = [
    module.soar_engine.s3_lockdown_role_arn
  ]
}

# 4. Automated Cloud Incident Response & SOAR Engine
module "soar_engine" {
  source = "./modules/soar-engine"

  aws_region                       = var.aws_region
  environment                      = var.environment
  alert_email                      = var.alert_email
  kms_key_arn                      = module.zero_trust_kyc_vault.kms_key_arn
  permission_boundary_arn          = module.iam_boundaries.permission_boundary_arn
  quarantine_policy_arn            = module.iam_boundaries.quarantine_policy_arn
  enable_guardduty_and_securityhub = var.enable_guardduty_and_securityhub
}

# 5. Secrets Management & SSM Parameter Store Configuration
module "secrets" {
  source = "./modules/secrets"

  environment           = var.environment
  kms_key_arn           = module.zero_trust_kyc_vault.kms_key_arn
  quarantine_policy_arn = module.iam_boundaries.quarantine_policy_arn
  kyc_vault_bucket_arn  = module.zero_trust_kyc_vault.kyc_vault_bucket_arn
  sns_topic_arn         = module.soar_engine.security_incidents_sns_topic_arn
}
