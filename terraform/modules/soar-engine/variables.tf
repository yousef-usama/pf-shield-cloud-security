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

variable "alert_email" {
  description = "Recipient email for security incidents and forensic reports"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Customer Managed Key ARN for envelope encryption across CloudTrail, SQS, SNS, and Lambda logs"
  type        = string
}

variable "permission_boundary_arn" {
  description = "IAM Permission Boundary ARN enforcing zero-trust identity guardrails on SOAR Lambda execution roles"
  type        = string
}

variable "quarantine_policy_arn" {
  description = "Quarantine deny-all IAM policy ARN"
  type        = string
}

variable "enable_guardduty_and_securityhub" {
  description = "FinOps toggle to enable AWS GuardDuty and AWS Security Hub"
  type        = bool
  default     = false
}
