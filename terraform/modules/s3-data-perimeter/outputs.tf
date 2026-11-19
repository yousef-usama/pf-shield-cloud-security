output "perimeter_policy_id" {
  description = "Resource ID of the applied S3 data perimeter bucket policy"
  value       = aws_s3_bucket_policy.kyc_vault_perimeter.id
}
