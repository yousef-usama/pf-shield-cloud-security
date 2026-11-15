# ---------------------------------------------------------------------------------------------------------------------
# ROOT OUTPUTS — PF-SHIELD PHASE 1 FOUNDATION
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
