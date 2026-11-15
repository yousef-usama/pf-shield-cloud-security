# ---------------------------------------------------------------------------------------------------------------------
# ROOT OUTPUTS — PF-SHIELD SECURITY CONTROL PLANE
# ---------------------------------------------------------------------------------------------------------------------

output "iam_workload_permission_boundary_arn" {
  description = "Workload IAM Permission Boundary ARN enforcing regional isolation and privilege guardrails"
  value       = module.iam_boundaries.permission_boundary_arn
}

output "iam_soar_quarantine_policy_arn" {
  description = "Quarantine Deny-All IAM Policy ARN used by SOAR automated remediation"
  value       = module.iam_boundaries.quarantine_policy_arn
}

output "finops_budget_id" {
  description = "The ID of the AWS Budget enforcing the monthly $5 cap"
  value       = module.finops_budget.budget_id
}

output "kyc_vpc_id" {
  description = "The isolated VPC ID housing the zero-cost S3 and DynamoDB Gateway Endpoints"
  value       = module.zero_trust_kyc_vault.vpc_id
}

output "kyc_s3_gateway_endpoint_id" {
  description = "The VPC S3 Gateway Endpoint ID routing private traffic without NAT Gateway costs"
  value       = module.zero_trust_kyc_vault.s3_gateway_endpoint_id
}

output "kyc_kms_cmk_arn" {
  description = "Customer Managed Key (CMK) ARN for envelope encryption"
  value       = module.zero_trust_kyc_vault.kms_key_arn
}

output "kyc_vault_bucket_name" {
  description = "S3 KYC Vault bucket protected with zero-trust bucket policy"
  value       = module.zero_trust_kyc_vault.kyc_vault_bucket_name
}

output "dynamodb_metadata_table_name" {
  description = "Properties & KYC metadata DynamoDB table name"
  value       = module.zero_trust_kyc_vault.dynamodb_table_name
}

output "soar_security_incidents_sns_topic_arn" {
  description = "The ARN of the SNS topic receiving SOAR forensic incident alerts"
  value       = module.soar_engine.security_incidents_sns_topic_arn
}

output "soar_s3_lockdown_lambda_arn" {
  description = "The ARN of the S3 Lockdown SOAR Lambda function"
  value       = module.soar_engine.s3_lockdown_lambda_arn
}

output "soar_iam_quarantine_lambda_arn" {
  description = "The ARN of the IAM Quarantine SOAR Lambda function"
  value       = module.soar_engine.iam_quarantine_lambda_arn
}

output "cloudtrail_audit_trail_arn" {
  description = "The ARN of the multi-region management event CloudTrail"
  value       = module.soar_engine.cloudtrail_arn
}

output "edge_api_endpoint" {
  description = "The public base URL endpoint for the PF-Shield Edge HTTP API"
  value       = module.edge_api_waf.api_endpoint
}

output "edge_api_properties_route" {
  description = "Full URL for the public property listings endpoint"
  value       = "${module.edge_api_waf.api_endpoint}/api/v1/properties"
}

output "edge_api_kyc_presign_route" {
  description = "Full URL for the broker KYC presign upload endpoint"
  value       = "${module.edge_api_waf.api_endpoint}/api/v1/kyc/presign"
}

output "observability_dashboard_name" {
  description = "Name of the CloudWatch Security Operations dashboard"
  value       = module.observability.dashboard_name
}
