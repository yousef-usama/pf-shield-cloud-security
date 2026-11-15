variable "aws_region" {
  description = "Target AWS region"
  type        = string
  default     = "me-central-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "prod-sim"
}

variable "permission_boundary_arn" {
  description = "IAM Permission Boundary ARN enforcing zero-trust identity guardrails on Lambda execution roles"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Customer Managed Key ARN for envelope encryption across API Gateway logs, Lambda logs, and data stores"
  type        = string
}

variable "dynamodb_table_name" {
  description = "DynamoDB metadata table name"
  type        = string
}

variable "kyc_vault_bucket_name" {
  description = "S3 KYC Vault bucket name"
  type        = string
}

variable "enable_waf" {
  description = "FinOps toggle to enable AWS WAFv2 WebACL"
  type        = bool
  default     = false
}
