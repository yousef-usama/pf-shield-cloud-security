variable "environment" {
  description = "Target deployment environment (e.g. demo, production)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "me-central-1"
}

variable "enable_rds" {
  description = "Toggle to provision the RDS PostgreSQL instance"
  type        = bool
  default     = false
}

variable "rds_instance_class" {
  description = "Instance class for RDS PostgreSQL database"
  type        = string
  default     = "db.t4g.micro"
}

variable "private_db_subnet_ids" {
  description = "List of private database subnet IDs"
  type        = list(string)
}

variable "database_security_group_id" {
  description = "Security group ID for RDS instance allowing ingress from ECS only"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Customer Managed Key ARN for database storage encryption"
  type        = string
}

variable "internal_hosted_zone_id" {
  description = "Route 53 internal hosted zone ID for internal service discovery"
  type        = string
}

variable "permission_boundary_arn" {
  description = "IAM Permission Boundary ARN for database roles"
  type        = string
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection on the database instance"
  type        = bool
  default     = false
}

variable "audit_retention_days" {
  description = "CloudWatch log retention in days for RDS database exports"
  type        = number
  default     = 7
}
