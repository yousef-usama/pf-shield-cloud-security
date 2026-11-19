output "api_endpoint" {
  description = "The base URL endpoint of the HTTP API Gateway"
  value       = aws_apigatewayv2_api.edge_api.api_endpoint
}

output "api_id" {
  description = "The ID of the HTTP API Gateway"
  value       = aws_apigatewayv2_api.edge_api.id
}

output "api_stage_name" {
  description = "The name of the API Gateway default stage"
  value       = aws_apigatewayv2_stage.default.name
}

output "api_stage_arn" {
  description = "The ARN of the API Gateway default stage"
  value       = aws_apigatewayv2_stage.default.arn
}

output "property_api_lambda_arn" {
  description = "The ARN of the property listings Lambda function"
  value       = aws_lambda_function.property_api.arn
}

output "property_api_role_arn" {
  description = "The ARN of the IAM role for the property listings Lambda function"
  value       = aws_iam_role.property_api_role.arn
}

output "kyc_vault_lambda_arn" {
  description = "The ARN of the KYC vault presign Lambda function"
  value       = aws_lambda_function.kyc_vault.arn
}

output "kyc_vault_role_arn" {
  description = "The ARN of the IAM role for the KYC vault presign Lambda function"
  value       = aws_iam_role.kyc_vault_role.arn
}

output "waf_web_acl_arn" {
  description = "The ARN of the WAFv2 WebACL (if enabled)"
  value       = var.enable_waf ? aws_wafv2_web_acl.edge_waf[0].arn : null
}

output "waf_web_acl_name" {
  description = "The name of the WAFv2 WebACL (if enabled)"
  value       = var.enable_waf ? aws_wafv2_web_acl.edge_waf[0].name : null
}
