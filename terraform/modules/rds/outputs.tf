output "db_instance_id" {
  description = "Identifier of the RDS database instance"
  value       = var.enable_rds ? aws_db_instance.main[0].id : null
}

output "db_endpoint" {
  description = "Connection endpoint of the RDS database instance"
  value       = var.enable_rds ? aws_db_instance.main[0].endpoint : null
}

output "db_address" {
  description = "Hostname address of the RDS database instance"
  value       = var.enable_rds ? aws_db_instance.main[0].address : null
}

output "db_credentials_secret_arn" {
  description = "Secrets Manager ARN storing RDS master credentials"
  value       = var.enable_rds ? aws_secretsmanager_secret.db_credentials[0].arn : null
}

output "internal_db_fqdn" {
  description = "Route 53 internal FQDN for the database"
  value       = var.enable_rds ? aws_route53_record.db[0].fqdn : null
}
