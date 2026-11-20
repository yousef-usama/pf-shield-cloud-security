variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "prod-sim"
}

variable "kms_key_arn" {
  description = "The ARN of the KMS Customer Managed Key used to encrypt SSM parameters"
  type        = string
}

variable "quarantine_policy_arn" {
  description = "The ARN of the SOAR quarantine deny-all policy to store securely"
  type        = string
}

variable "enable_sns_topic_param" {
  description = "Toggle to store SNS topic ARN in SSM Parameter Store"
  type        = bool
  default     = true
}

variable "sns_topic_arn" {
  description = "The ARN of the security incidents SNS topic to store securely"
  type        = string
  default     = ""
}

variable "kyc_vault_bucket_arn" {
  description = "The ARN of the S3 KYC Vault bucket to store securely"
  type        = string
}
