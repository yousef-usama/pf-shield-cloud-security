variable "aws_region" {
  description = "Target AWS Region for deployment (me-central-1)"
  type        = string
  default     = "me-central-1"
}

variable "environment" {
  description = "Deployment environment identifier (demo, production)"
  type        = string
}

variable "bucket_id" {
  description = "Target S3 bucket ID/name to attach perimeter policy"
  type        = string
}

variable "bucket_arn" {
  description = "Target S3 bucket ARN to attach perimeter policy"
  type        = string
}

variable "s3_gateway_endpoint_id" {
  description = "VPC Gateway Endpoint ID for S3 to allow internal traffic"
  type        = string
}

variable "allowed_principal_arns" {
  description = "List of IAM role ARNs permitted to bypass the VPC endpoint perimeter (e.g. KYC ECS task role, SOAR Lambda role)"
  type        = list(string)
  default     = []
}
