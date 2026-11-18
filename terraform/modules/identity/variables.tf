variable "environment" {
  description = "Deployment environment name"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "me-central-1"
}

variable "mfa_configuration" {
  description = "MFA configuration for Cognito User Pool (OFF, OPTIONAL, ON)"
  type        = string
  default     = "OPTIONAL"
}

variable "advanced_security_mode" {
  description = "Cognito User Pool Advanced Security Mode (OFF, AUDIT, ENFORCED)"
  type        = string
  default     = "AUDIT"
}
