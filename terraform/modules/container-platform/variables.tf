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

variable "vpc_id" {
  description = "VPC ID where container platform is deployed"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for Application Load Balancer"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnets for ECS tasks (no public IPs)"
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "Security group ID for Application Load Balancer"
  type        = string
}

variable "ecs_security_group_id" {
  description = "Security group ID for ECS microservices"
  type        = string
}

variable "permission_boundary_arn" {
  description = "IAM Permission Boundary ARN for ECS task roles and execution role"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Customer Managed Key ARN for ECR and CloudWatch logs encryption"
  type        = string
}

variable "dynamodb_table_name" {
  description = "DynamoDB metadata table name"
  type        = string
}

variable "kyc_vault_bucket_name" {
  description = "S3 KYC Vault bucket name"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS Topic ARN for security incident notifications"
  type        = string
}

variable "ecs_desired_count" {
  description = "Desired number of ECS tasks per service (0 for idle demo, 2 for production high availability)"
  type        = number
  default     = 0
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection on ALB (disabled for demo teardown)"
  type        = bool
  default     = false
}

variable "waf_web_acl_arn" {
  description = "Optional WAFv2 WebACL ARN to associate with the Application Load Balancer"
  type        = string
  default     = null
}

variable "enable_cloudfront" {
  description = "Toggle to provision CloudFront edge CDN distribution in front of ALB"
  type        = bool
  default     = false
}

