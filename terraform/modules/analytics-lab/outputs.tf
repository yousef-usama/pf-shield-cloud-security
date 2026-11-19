output "analytics_bucket_name" {
  description = "Name of the central S3 analytics data lake bucket"
  value       = aws_s3_bucket.analytics.id
}

output "analytics_bucket_arn" {
  description = "ARN of the central S3 analytics data lake bucket"
  value       = aws_s3_bucket.analytics.arn
}

output "clickhouse_instance_id" {
  description = "EC2 instance ID of the ClickHouse analytics host"
  value       = var.enable_analytics_lab ? aws_instance.clickhouse[0].id : null
}

output "clickhouse_private_ip" {
  description = "Private IP address of the ClickHouse analytics host"
  value       = var.enable_analytics_lab ? aws_instance.clickhouse[0].private_ip : null
}

output "internal_analytics_fqdn" {
  description = "Route 53 internal FQDN for the ClickHouse analytics node"
  value       = var.enable_analytics_lab ? aws_route53_record.clickhouse[0].fqdn : null
}

output "glue_job_name" {
  description = "Name of the AWS Glue listing sanitization ETL job"
  value       = var.enable_glue_etl ? aws_glue_job.sanitize_listings[0].name : null
}
