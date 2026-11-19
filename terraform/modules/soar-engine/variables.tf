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

variable "containment_mode" {
  description = "SOAR containment operational mode: AUTOMATIC or HUMAN_APPROVAL"
  type        = string
  default     = "AUTOMATIC"
}

variable "protected_principals_allowlist" {
  description = "Comma-separated list of protected IAM roles or usernames exempt from automatic quarantine"
  type        = string
  default     = "root,AWSServiceRole,pf-shield-github-actions,pf-soar-s3-lockdown,pf-soar-iam-quarantine,break-glass,security-admin"
}

variable "kyc_vault_bucket_arn" {
  description = "ARN of the KYC Vault S3 bucket for CloudTrail S3 data event logging"
  type        = string
  default     = ""
}

variable "enable_cloudtrail_s3_data_events" {
  description = "FinOps toggle to enable CloudTrail S3 data events on KYC vault bucket (enabled in production)"
  type        = bool
  default     = false
}

variable "audit_retention_days" {
  description = "Retention period in days for audit logs (7 for demo, 365 for production)"
  type        = number
  default     = 7
}
