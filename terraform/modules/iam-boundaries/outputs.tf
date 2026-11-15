output "permission_boundary_arn" {
  description = "The ARN of the workload IAM permission boundary"
  value       = aws_iam_policy.workload_permission_boundary.arn
}

output "permission_boundary_name" {
  description = "The name of the workload IAM permission boundary"
  value       = aws_iam_policy.workload_permission_boundary.name
}

output "quarantine_policy_arn" {
  description = "The ARN of the SOAR quarantine deny-all policy"
  value       = aws_iam_policy.soar_quarantine_deny_all.arn
}

output "quarantine_policy_name" {
  description = "The name of the SOAR quarantine deny-all policy"
  value       = aws_iam_policy.soar_quarantine_deny_all.name
}
