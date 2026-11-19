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

variable "vpc_cidr" {
  description = "CIDR block for the isolated multi-tier VPC"
  type        = string
  default     = "10.20.0.0/16"
}

variable "kms_key_arn" {
  description = "Optional KMS Customer Managed Key ARN for VPC flow logs encryption"
  type        = string
  default     = null
}

variable "permission_boundary_arn" {
  description = "IAM Permission Boundary ARN for IAM roles created in networking"
  type        = string
}

variable "log_retention_days" {
  description = "Retention period in days for VPC Flow Logs CloudWatch log group"
  type        = number
  default     = 7
}
