variable "monthly_budget_limit_usd" {
  description = "Monthly maximum spend cap in USD"
  type        = string
  default     = "5.0"
}

variable "alert_email" {
  description = "Recipient email address for budget threshold notifications"
  type        = string
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "prod-sim"
}
