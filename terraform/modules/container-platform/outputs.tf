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
  value       = aws_ecr_repository.listings_api.repository_url
}

output "ecr_broker_kyc_api_repository_url" {
  description = "ECR repository URL for broker-kyc-api"
  value       = aws_ecr_repository.broker_kyc_api.repository_url
}

output "ecr_document_scan_worker_repository_url" {
  description = "ECR repository URL for document-scan-worker"
  value       = aws_ecr_repository.document_scan_worker.repository_url
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
