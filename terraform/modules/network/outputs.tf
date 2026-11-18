output "vpc_id" {
  description = "The ID of the multi-tier VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs (for ALB and NAT)"
  value       = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

output "private_app_subnet_ids" {
  description = "List of private application subnet IDs (for ECS tasks)"
  value       = [aws_subnet.private_app_a.id, aws_subnet.private_app_b.id]
}

output "private_db_subnet_ids" {
  description = "List of private database subnet IDs (for RDS and data stores)"
  value       = [aws_subnet.private_db_a.id, aws_subnet.private_db_b.id]
}

output "s3_gateway_endpoint_id" {
  description = "The VPC S3 Gateway Endpoint ID"
  value       = aws_vpc_endpoint.s3.id
}

output "dynamodb_gateway_endpoint_id" {
  description = "The VPC DynamoDB Gateway Endpoint ID"
  value       = aws_vpc_endpoint.dynamodb.id
}

output "alb_security_group_id" {
  description = "Security group ID for Application Load Balancer"
  value       = aws_security_group.alb.id
}

output "ecs_security_group_id" {
  description = "Security group ID for ECS microservices"
  value       = aws_security_group.ecs.id
}

output "database_security_group_id" {
  description = "Security group ID for relational database tier"
  value       = aws_security_group.database.id
}

output "internal_hosted_zone_id" {
  description = "Route 53 private hosted zone ID"
  value       = aws_route53_zone.internal.zone_id
}
