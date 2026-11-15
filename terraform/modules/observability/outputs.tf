output "dashboard_name" {
  description = "Name of the provisioned CloudWatch Security Ops dashboard"
  value       = var.enable_dashboard ? aws_cloudwatch_dashboard.security_ops[0].dashboard_name : null
}

output "dashboard_arn" {
  description = "ARN of the provisioned CloudWatch Security Ops dashboard"
  value       = var.enable_dashboard ? aws_cloudwatch_dashboard.security_ops[0].dashboard_arn : null
}

output "s3_dlq_alarm_arn" {
  description = "ARN of the S3 DLQ metric alarm"
  value       = aws_cloudwatch_metric_alarm.soar_s3_dlq_not_empty.arn
}

output "iam_dlq_alarm_arn" {
  description = "ARN of the IAM DLQ metric alarm"
  value       = aws_cloudwatch_metric_alarm.soar_iam_dlq_not_empty.arn
}

output "api_5xx_alarm_arn" {
  description = "ARN of the API Gateway 5xx spike alarm"
  value       = aws_cloudwatch_metric_alarm.api_5xx_spike.arn
}
