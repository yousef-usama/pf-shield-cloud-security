output "github_actions_role_arn" {
  description = "The ARN of the IAM role assumed by GitHub Actions via OIDC"
  value       = aws_iam_role.github_actions.arn
}

output "github_oidc_provider_arn" {
  description = "The ARN of the GitHub OIDC provider in IAM"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "github_repository" {
  description = "The authorized GitHub repository condition"
  value       = var.github_repository
}
