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

variable "allowed_principal_arns" {
  description = "List of IAM Principal ARNs explicitly permitted to access the KYC Vault S3 bucket"
  type        = list(string)
  default     = []
}

variable "s3_gateway_endpoint_id" {
  description = "The VPC S3 Gateway Endpoint ID routing private traffic"
  type        = string
}
