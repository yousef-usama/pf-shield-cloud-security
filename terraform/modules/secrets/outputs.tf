output "quarantine_policy_param_arn" {
  description = "The ARN of the SSM Parameter storing the quarantine policy ARN"
  value       = aws_ssm_parameter.quarantine_policy_arn.arn
}

output "quarantine_policy_param_name" {
  description = "The name of the SSM Parameter storing the quarantine policy ARN"
  value       = aws_ssm_parameter.quarantine_policy_arn.name
}

output "kyc_kms_key_param_arn" {
  description = "The ARN of the SSM Parameter storing the KMS Key ARN"
  value       = aws_ssm_parameter.kyc_kms_key_arn.arn
}

output "kyc_kms_key_param_name" {
  description = "The name of the SSM Parameter storing the KMS Key ARN"
  value       = aws_ssm_parameter.kyc_kms_key_arn.name
}

output "kyc_vault_bucket_param_arn" {
  description = "The ARN of the SSM Parameter storing the S3 Bucket ARN"
  value       = aws_ssm_parameter.kyc_vault_bucket_arn.arn
}

output "kyc_vault_bucket_param_name" {
  description = "The name of the SSM Parameter storing the S3 Bucket ARN"
  value       = aws_ssm_parameter.kyc_vault_bucket_arn.name
}
