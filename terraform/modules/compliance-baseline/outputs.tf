output "config_recorder_id" {
  description = "The ID of the AWS Config configuration recorder"
  value       = var.enable_aws_config ? aws_config_configuration_recorder.main[0].id : null
}

output "config_role_arn" {
  description = "The ARN of the AWS Config service IAM role"
  value       = var.enable_aws_config ? aws_iam_role.config_role[0].arn : null
}

output "config_rules_count" {
  description = "Number of active AWS Config continuous compliance rules"
  value       = var.enable_aws_config ? 8 : 0
}
