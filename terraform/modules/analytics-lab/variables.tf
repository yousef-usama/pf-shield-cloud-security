variable "environment" {
  description = "Target deployment environment"
  type        = string
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "me-central-1"
}

variable "vpc_id" {
  description = "VPC ID where the analytics node and endpoints reside"
  type        = string
}

variable "private_app_subnet_ids" {
  description = "List of private application subnet IDs for EC2 analytics node"
  type        = list(string)
}

variable "ecs_security_group_id" {
  description = "Security group ID of ECS tasks allowed to query analytics node"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Customer Managed Key ARN for S3 and EBS encryption"
  type        = string
}

variable "internal_hosted_zone_id" {
  description = "Route 53 internal hosted zone ID for internal service discovery"
  type        = string
}

variable "permission_boundary_arn" {
  description = "IAM Permission Boundary ARN for IAM roles"
  type        = string
}

variable "ssm_ec2_permission_boundary_arn" {
  description = "Dedicated IAM Permission Boundary ARN for EC2 SSM Session Manager role"
  type        = string
  default     = null
}

variable "glue_permission_boundary_arn" {
  description = "Dedicated IAM Permission Boundary ARN for Glue ETL service role"
  type        = string
  default     = null
}

variable "enable_analytics_lab" {
  description = "Toggle to provision the ClickHouse EC2 analytics node"
  type        = bool
  default     = false
}

variable "analytics_instance_type" {
  description = "EC2 instance type for ClickHouse analytics demonstration"
  type        = string
  default     = "t4g.small"
}

variable "ami_id" {
  description = "Optional custom AMI ID for ClickHouse EC2 instance (defaults to latest AL2023 ARM64)"
  type        = string
  default     = null
}

variable "enable_glue_etl" {
  description = "Toggle to provision the AWS Glue ETL sanitization pipeline"
  type        = bool
  default     = false
}
