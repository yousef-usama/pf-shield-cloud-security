output "kms_key_arn" {
  description = "The ARN of the KYC Vault KMS Customer Managed Key"
  value       = aws_kms_key.pf_kyc_cmk.arn
}

output "kms_key_id" {
  description = "The ID of the KYC Vault KMS Customer Managed Key"
  value       = aws_kms_key.pf_kyc_cmk.key_id
}

output "kms_key_alias_arn" {
  description = "The ARN of the KMS key alias"
  value       = aws_kms_alias.pf_kyc_cmk_alias.arn
}

output "kyc_vault_bucket_name" {
  description = "The name of the S3 KYC Vault bucket"
  value       = aws_s3_bucket.kyc_vault.id
}

output "kyc_vault_bucket_arn" {
  description = "The ARN of the S3 KYC Vault bucket"
  value       = aws_s3_bucket.kyc_vault.arn
}

output "dynamodb_table_name" {
  description = "The name of the properties & KYC DynamoDB table"
  value       = aws_dynamodb_table.properties_metadata.name
}

output "dynamodb_table_arn" {
  description = "The ARN of the properties & KYC DynamoDB table"
  value       = aws_dynamodb_table.properties_metadata.arn
}
