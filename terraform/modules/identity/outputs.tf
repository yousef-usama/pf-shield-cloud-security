output "user_pool_id" {
  description = "The ID of the Cognito User Pool"
  value       = aws_cognito_user_pool.broker_pool.id
}

output "user_pool_arn" {
  description = "The ARN of the Cognito User Pool"
  value       = aws_cognito_user_pool.broker_pool.arn
}

output "user_pool_client_id" {
  description = "The ID of the Cognito User Pool Client"
  value       = aws_cognito_user_pool_client.broker_app_client.id
}

output "user_pool_endpoint" {
  description = "The endpoint of the Cognito User Pool"
  value       = aws_cognito_user_pool.broker_pool.endpoint
}

output "user_pool_domain" {
  description = "The domain prefix of the Cognito User Pool"
  value       = aws_cognito_user_pool_domain.broker_domain.domain
}

output "alb_client_id" {
  description = "The ID of the Cognito User Pool Client for ALB authenticate-cognito"
  value       = aws_cognito_user_pool_client.alb_client.id
}

output "alb_client_secret" {
  description = "The Client Secret of the Cognito User Pool Client for ALB authenticate-cognito"
  value       = aws_cognito_user_pool_client.alb_client.client_secret
  sensitive   = true
}
