# =====================================================================================================================
# PF-SHIELD CLUSTER & INFRASTRUCTURE ROOT MODULE
# PF-Shield UAE Cloud Security Control Plane & Zero-Trust Architecture
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

# 3. Multi-Tier Zero-Trust Network Perimeter & Private Subnets
module "network" {
  source = "./modules/network"

  aws_region              = var.aws_region
  environment             = var.environment
  permission_boundary_arn = module.iam_boundaries.permission_boundary_arn
}

# 4. Zero-Trust KYC Document Vault & Envelope Encryption
module "zero_trust_kyc_vault" {
  source = "./modules/zero-trust-kyc-vault"

  aws_region             = var.aws_region
  environment            = var.environment
  s3_gateway_endpoint_id = module.network.s3_gateway_endpoint_id

  # Pre-allow roles that require S3 access through the data perimeter
  allowed_principal_arns = [
    module.soar_engine.s3_lockdown_role_arn,
    module.edge_api_waf.kyc_vault_role_arn
  ]
}

# 5. Automated Cloud Incident Response & SOAR Engine
module "soar_engine" {
  source = "./modules/soar-engine"

  aws_region                       = var.aws_region
  environment                      = var.environment
  alert_email                      = var.alert_email
  kms_key_arn                      = module.zero_trust_kyc_vault.kms_key_arn
  permission_boundary_arn          = module.iam_boundaries.soar_permission_boundary_arn
  quarantine_policy_arn            = module.iam_boundaries.quarantine_policy_arn
  enable_guardduty_and_securityhub = var.enable_guardduty_and_securityhub
  containment_mode                 = var.containment_mode
  protected_principals_allowlist   = var.protected_principals_allowlist
  kyc_vault_bucket_arn             = module.zero_trust_kyc_vault.kyc_vault_bucket_arn
  enable_cloudtrail_s3_data_events = var.enable_cloudtrail_s3_data_events
  audit_retention_days             = var.audit_retention_days
}

# 6. Secrets Management & SSM Parameter Store Configuration
module "secrets" {
  source = "./modules/secrets"

  environment           = var.environment
  kms_key_arn           = module.zero_trust_kyc_vault.kms_key_arn
  quarantine_policy_arn = module.iam_boundaries.quarantine_policy_arn
  kyc_vault_bucket_arn  = module.zero_trust_kyc_vault.kyc_vault_bucket_arn
  sns_topic_arn         = module.soar_engine.security_incidents_sns_topic_arn
}

# 7. Broker Identity & OIDC Provider (Amazon Cognito)
module "identity" {
  source = "./modules/identity"

  environment = var.environment
  aws_region  = var.aws_region
}

# 8. Edge API Gateway & Anti-Scraping WAF Protection
module "edge_api_waf" {
  source = "./modules/edge-api-waf"

  aws_region              = var.aws_region
  environment             = var.environment
  permission_boundary_arn = module.iam_boundaries.permission_boundary_arn
  kms_key_arn             = module.zero_trust_kyc_vault.kms_key_arn
  dynamodb_table_name     = module.zero_trust_kyc_vault.dynamodb_table_name
  kyc_vault_bucket_name   = module.zero_trust_kyc_vault.kyc_vault_bucket_name
  enable_waf              = var.enable_waf
  user_pool_endpoint      = module.identity.user_pool_endpoint
  user_pool_client_id     = module.identity.user_pool_client_id
}

# 9. Container Workload Platform & Microservices (Amazon ECS on Fargate)
module "container_platform" {
  source = "./modules/container-platform"

  aws_region                 = var.aws_region
  environment                = var.environment
  vpc_id                     = module.network.vpc_id
  public_subnet_ids          = module.network.public_subnet_ids
  private_subnet_ids         = module.network.private_app_subnet_ids
  alb_security_group_id      = module.network.alb_security_group_id
  ecs_security_group_id      = module.network.ecs_security_group_id
  permission_boundary_arn    = module.iam_boundaries.permission_boundary_arn
  kms_key_arn                = module.zero_trust_kyc_vault.kms_key_arn
  dynamodb_table_name        = module.zero_trust_kyc_vault.dynamodb_table_name
  kyc_vault_bucket_name      = module.zero_trust_kyc_vault.kyc_vault_bucket_name
  sns_topic_arn              = module.soar_engine.security_incidents_sns_topic_arn
  ecs_desired_count          = var.ecs_desired_count
  enable_deletion_protection = var.enable_deletion_protection
}

# 10. Observability, Security Ops Dashboard & Metric Alarms
module "observability" {
  source = "./modules/observability"

  environment                = var.environment
  api_id                     = module.edge_api_waf.api_id
  s3_lockdown_lambda_name    = module.soar_engine.s3_lockdown_lambda_name
  iam_quarantine_lambda_name = module.soar_engine.iam_quarantine_lambda_name
  s3_lockdown_dlq_name       = module.soar_engine.s3_lockdown_dlq_name
  iam_quarantine_dlq_name    = module.soar_engine.iam_quarantine_dlq_name
  kyc_vault_bucket_name      = module.zero_trust_kyc_vault.kyc_vault_bucket_name
  sns_topic_arn              = module.soar_engine.security_incidents_sns_topic_arn
  enable_dashboard           = var.enable_observability_dashboard
}

# 11. Detective Controls & Continuous Compliance Baseline (AWS Config)
module "compliance_baseline" {
  source = "./modules/compliance-baseline"

  aws_region              = var.aws_region
  environment             = var.environment
  enable_aws_config       = var.enable_aws_config
  audit_bucket_name       = module.soar_engine.audit_logs_bucket_name
  kms_key_arn             = module.zero_trust_kyc_vault.kms_key_arn
  permission_boundary_arn = module.iam_boundaries.permission_boundary_arn
}
