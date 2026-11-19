variable "aws_region" {
  description = "Target AWS deployment region aligned with UAE PDPL data residency requirements"
  type        = string
  default     = "me-central-1"
}

variable "fallback_region" {
  description = "Documented secondary AWS region for services lacking feature parity in me-central-1"
  type        = string
  default     = "me-south-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "prod-sim"
}

variable "owner" {
  description = "Owner of the cloud security resources"
  type        = string
  default     = "YousefOsama"
}

variable "alert_email" {
  description = "Security operations recipient email address for FinOps budget alerts and incident reports"
  type        = string
  default     = "security-alerts@example.com"
}

variable "monthly_budget_limit_usd" {
  description = "Monthly maximum spend cap in USD for FinOps cost guardrails"
  type        = string
  default     = "5.0"
}

variable "enable_waf" {
  description = "FinOps toggle to enable AWS WAFv2 WebACL (false by default to maintain $0.00 idle cost)"
  type        = bool
  default     = false
}

variable "enable_guardduty_and_securityhub" {
  description = "FinOps toggle to enable AWS GuardDuty and AWS Security Hub (false by default to maintain $0.00 idle cost)"
  type        = bool
  default     = false
}

variable "enable_observability_dashboard" {
  description = "Toggle to provision the CloudWatch security operations dashboard and metric alarms"
  type        = bool
  default     = true
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

variable "ecs_desired_count" {
  description = "Desired number of ECS tasks per service (0 for idle demo profile, 2 for production HA)"
  type        = number
  default     = 0
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection on production-sensitive load balancers and databases"
  type        = bool
  default     = false
}

variable "enable_aws_config" {
  description = "FinOps toggle to enable AWS Config continuous compliance recording and managed rules"
  type        = bool
  default     = false
}

variable "enable_cloudtrail_s3_data_events" {
  description = "FinOps toggle to capture CloudTrail S3 data events on KYC vault bucket (enabled in production)"
  type        = bool
  default     = false
}

variable "audit_retention_days" {
  description = "Retention period in days for audit logs (7 for demo, 365 for production)"
  type        = number
  default     = 7
}

variable "enable_rds" {
  description = "FinOps toggle to provision the private RDS PostgreSQL metadata database (enabled in production)"
  type        = bool
  default     = false
}

variable "rds_instance_class" {
  description = "Instance class for RDS PostgreSQL database"
  type        = string
  default     = "db.t4g.micro"
}

variable "enable_analytics_lab" {
  description = "FinOps toggle to provision the isolated ClickHouse EC2 analytics node"
  type        = bool
  default     = false
}

variable "analytics_instance_type" {
  description = "Instance type for the ClickHouse analytics host"
  type        = string
  default     = "t4g.small"
}

variable "enable_glue_etl" {
  description = "FinOps toggle to provision the AWS Glue listing sanitization ETL pipeline"
  type        = bool
  default     = false
}

