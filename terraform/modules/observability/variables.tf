variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "prod-sim"
}

variable "api_id" {
  description = "HTTP API Gateway ID for monitoring metrics"
  type        = string
}

variable "s3_lockdown_lambda_name" {
  description = "Name of the S3 Lockdown Lambda function"
  type        = string
}

variable "iam_quarantine_lambda_name" {
  description = "Name of the IAM Quarantine Lambda function"
  type        = string
}

variable "s3_lockdown_dlq_name" {
  description = "Name of the S3 Lockdown SQS Dead Letter Queue"
  type        = string
}

variable "iam_quarantine_dlq_name" {
  description = "Name of the IAM Quarantine SQS Dead Letter Queue"
  type        = string
}

variable "kyc_vault_bucket_name" {
  description = "Name of the S3 KYC Vault bucket"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN to receive alarm notifications"
  type        = string
}

variable "enable_dashboard" {
  description = "Toggle to provision the CloudWatch security operations dashboard"
  type        = bool
  default     = true
}

variable "alb_arn_suffix" {
  description = "ARN suffix of the Application Load Balancer for CloudWatch metrics"
  type        = string
  default     = null
}

variable "waf_web_acl_name" {
  description = "Name of the WAFv2 WebACL for CloudWatch metric alarms"
  type        = string
  default     = null
}

variable "enable_waf" {
  description = "Whether WAF is enabled for alarm provisioning"
  type        = bool
  default     = false
}

