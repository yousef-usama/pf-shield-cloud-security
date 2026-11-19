output "ecs_cluster_id" {
  description = "The ID of the ECS cluster"
  value       = aws_ecs_cluster.primary.id
}

output "ecs_cluster_name" {
  description = "The name of the ECS cluster"
  value       = aws_ecs_cluster.primary.name
}

output "alb_arn" {
  description = "Application Load Balancer ARN"
  value       = aws_lb.main.arn
}

output "alb_dns_name" {
  description = "Application Load Balancer DNS name"
  value       = aws_lb.main.dns_name
}

output "ecr_listings_api_repository_url" {
  description = "ECR repository URL for listings-api"
  value       = data.aws_ecr_repository.listings_api.repository_url
}

output "ecr_broker_kyc_api_repository_url" {
  description = "ECR repository URL for broker-kyc-api"
  value       = data.aws_ecr_repository.broker_kyc_api.repository_url
}

output "ecr_document_scan_worker_repository_url" {
  description = "ECR repository URL for document-scan-worker"
  value       = data.aws_ecr_repository.document_scan_worker.repository_url
}

output "listings_api_service_name" {
  description = "The name of the listings API ECS service"
  value       = aws_ecs_service.listings_api.name
}

output "broker_kyc_api_service_name" {
  description = "The name of the broker KYC API ECS service"
  value       = aws_ecs_service.broker_kyc_api.name
}

output "document_scan_worker_service_name" {
  description = "The name of the document scan worker ECS service"
  value       = aws_ecs_service.document_scan_worker.name
}

output "alb_arn_suffix" {
  description = "ARN suffix of the Application Load Balancer for CloudWatch metrics"
  value       = aws_lb.main.arn_suffix
}

output "cloudfront_distribution_id" {
  description = "CloudFront edge CDN distribution ID"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.alb[0].id : null
}

output "cloudfront_domain_name" {
  description = "CloudFront edge CDN domain name"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.alb[0].domain_name : null
}

output "broker_kyc_task_role_arn" {
  description = "The ARN of the broker KYC API ECS task role"
  value       = aws_iam_role.broker_kyc_api_task_role.arn
}

output "scan_worker_task_role_arn" {
  description = "The ARN of the document scan worker ECS task role"
  value       = aws_iam_role.document_scan_worker_task_role.arn
}

output "listings_api_task_role_arn" {
  description = "The ARN of the listings API ECS task role"
  value       = aws_iam_role.listings_api_task_role.arn
}

output "ecs_execution_role_arn" {
  description = "The ARN of the ECS task execution role"
  value       = aws_iam_role.ecs_execution_role.arn
}

