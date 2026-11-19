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

output "ecr_repository_urls" {
  description = "URLs of the foundational ECR repositories provisioned in bootstrap stage"
  value = {
    listings_api         = aws_ecr_repository.listings_api.repository_url
    broker_kyc_api       = aws_ecr_repository.broker_kyc_api.repository_url
    document_scan_worker = aws_ecr_repository.document_scan_worker.repository_url
  }
}

output "ecr_repository_arns" {
  description = "ARNs of the foundational ECR repositories provisioned in bootstrap stage"
  value = {
    listings_api         = aws_ecr_repository.listings_api.arn
    broker_kyc_api       = aws_ecr_repository.broker_kyc_api.arn
    document_scan_worker = aws_ecr_repository.document_scan_worker.arn
  }
}
