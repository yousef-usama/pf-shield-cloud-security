resource "aws_ssm_parameter" "quarantine_policy_arn" {
  name        = "/pf-shield/${var.environment}/quarantine-policy-arn"
  description = "Quarantine deny-all IAM policy ARN used by automated SOAR remediation playbooks"
  type        = "SecureString"
  key_id      = var.kms_key_arn
  value       = var.quarantine_policy_arn

  tags = {
    Name = "pf-shield-ssm-quarantine-policy-${var.environment}"
  }
}

resource "aws_ssm_parameter" "kyc_kms_key_arn" {
  name        = "/pf-shield/${var.environment}/kyc-kms-key-arn"
  description = "KMS Customer Managed Key ARN for KYC envelope encryption"
  type        = "SecureString"
  key_id      = var.kms_key_arn
  value       = var.kms_key_arn

  tags = {
    Name = "pf-shield-ssm-kms-key-${var.environment}"
  }
}

resource "aws_ssm_parameter" "kyc_vault_bucket_arn" {
  name        = "/pf-shield/${var.environment}/kyc-vault-bucket-arn"
  description = "Restricted S3 KYC Vault bucket ARN"
  type        = "SecureString"
  key_id      = var.kms_key_arn
  value       = var.kyc_vault_bucket_arn

  tags = {
    Name = "pf-shield-ssm-bucket-arn-${var.environment}"
  }
}

resource "aws_ssm_parameter" "sns_topic_arn" {
  count       = var.enable_sns_topic_param ? 1 : 0
  name        = "/pf-shield/${var.environment}/sns-topic-arn"
  description = "Security operations notification SNS topic ARN"
  type        = "SecureString"
  key_id      = var.kms_key_arn
  value       = var.sns_topic_arn

  tags = {
    Name = "pf-shield-ssm-sns-topic-${var.environment}"
  }
}
