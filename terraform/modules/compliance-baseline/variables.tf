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

variable "enable_aws_config" {
  description = "FinOps toggle to enable AWS Config continuous compliance recording and rules"
  type        = bool
  default     = false
}

variable "audit_bucket_name" {
  description = "Name of the dedicated S3 audit bucket for AWS Config snapshots"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Customer Managed Key ARN for AWS Config delivery channel encryption"
  type        = string
}

variable "permission_boundary_arn" {
  description = "IAM Permission Boundary ARN enforcing zero-trust guardrails on Config service role"
  type        = string
}
