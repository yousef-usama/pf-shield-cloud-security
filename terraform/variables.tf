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
