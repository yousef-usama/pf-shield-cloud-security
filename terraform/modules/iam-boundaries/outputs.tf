output "permission_boundary_arn" {
  description = "The ARN of the workload IAM permission boundary"
  value       = aws_iam_policy.workload_permission_boundary.arn
}

output "permission_boundary_name" {
  description = "The name of the workload IAM permission boundary"
  value       = aws_iam_policy.workload_permission_boundary.name
}

output "soar_permission_boundary_arn" {
  description = "The ARN of the dedicated SOAR IAM permission boundary"
  value       = aws_iam_policy.soar_permission_boundary.arn
}

output "soar_permission_boundary_name" {
  description = "The name of the dedicated SOAR IAM permission boundary"
  value       = aws_iam_policy.soar_permission_boundary.name
}

output "quarantine_policy_arn" {
  description = "The ARN of the SOAR quarantine deny-all policy"
  value       = aws_iam_policy.soar_quarantine_deny_all.arn
}

output "quarantine_policy_name" {
  description = "The name of the SOAR quarantine deny-all policy"
  value       = aws_iam_policy.soar_quarantine_deny_all.name
}

# Scoped dedicated boundaries
output "ecs_execution_permission_boundary_arn" {
  description = "The ARN of the dedicated ECS task execution permission boundary"
  value       = aws_iam_policy.ecs_execution_permission_boundary.arn
}

output "ecs_task_permission_boundary_arn" {
  description = "The ARN of the dedicated ECS container task permission boundary"
  value       = aws_iam_policy.ecs_task_permission_boundary.arn
}

output "config_permission_boundary_arn" {
  description = "The ARN of the dedicated AWS Config recording permission boundary"
  value       = aws_iam_policy.config_permission_boundary.arn
}

output "glue_permission_boundary_arn" {
  description = "The ARN of the dedicated AWS Glue ETL permission boundary"
  value       = aws_iam_policy.glue_permission_boundary.arn
}

output "rds_monitoring_permission_boundary_arn" {
  description = "The ARN of the dedicated RDS Enhanced Monitoring permission boundary"
  value       = aws_iam_policy.rds_monitoring_permission_boundary.arn
}

output "ssm_ec2_permission_boundary_arn" {
  description = "The ARN of the dedicated EC2 SSM Session Manager permission boundary"
  value       = aws_iam_policy.ssm_ec2_permission_boundary.arn
}
