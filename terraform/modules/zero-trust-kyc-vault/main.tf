data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. ENVELOPE ENCRYPTION: KMS CUSTOMER MANAGED KEY (CMK)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_kms_key" "pf_kyc_cmk" {
  description             = "Customer Managed Key for PF-Shield KYC Vault Envelope Encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsAndSSMUsage"
        Effect = "Allow"
        Principal = {
          Service = [
            "logs.${var.aws_region}.amazonaws.com",
            "ssm.amazonaws.com",
            "events.amazonaws.com",
            "sqs.amazonaws.com",
            "cloudtrail.amazonaws.com",
            "config.amazonaws.com"
          ]
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowS3AndDynamoDBUsage"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "dynamodb.amazonaws.com"
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "pf-kyc-vault-cmk-${var.environment}"
  }
}

resource "aws_kms_alias" "pf_kyc_cmk_alias" {
  name          = "alias/pf-kyc-vault-cmk-${var.environment}"
  target_key_id = aws_kms_key.pf_kyc_cmk.key_id
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. ZERO-TRUST BROKER KYC DOCUMENT VAULT (S3)
# ---------------------------------------------------------------------------------------------------------------------

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "kyc_vault" {
  #checkov:skip=CKV_AWS_18: S3 access logging intentionally disabled to prevent recurring PUT costs on idle demo environment
  #checkov:skip=CKV_AWS_144: Cross-region replication disabled to comply with UAE PDPL data residency requirements
  #checkov:skip=CKV2_AWS_62: S3 event notifications managed by CloudTrail and EventBridge SOAR rules
  bucket        = "pf-kyc-vault-${var.environment}-${random_id.bucket_suffix.hex}"
  force_destroy = var.environment == "production" ? false : true

  tags = {
    Name                 = "pf-kyc-vault-${var.environment}"
    DataClassification   = "Restricted-UAE-PDPL"
    ComplianceRegulation = "UAE-PDPL-Federal-Decree-Law-45-2021"
  }
}

resource "aws_s3_bucket_public_access_block" "kyc_vault_pab" {
  bucket = aws_s3_bucket.kyc_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "kyc_vault_versioning" {
  bucket = aws_s3_bucket.kyc_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kyc_vault_encryption" {
  bucket = aws_s3_bucket.kyc_vault.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.pf_kyc_cmk.arn
      sse_algorithm     = "aws:kms"
    }
    # Bucket Key reduces KMS request costs by 99% for high-throughput KYC uploads
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "kyc_vault_lifecycle" {
  bucket = aws_s3_bucket.kyc_vault.id

  rule {
    id     = "transition-to-standard-ia-and-abort-multipart"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. METADATA STORE: DYNAMODB PROPERTIES & KYC METADATA TABLE
# ---------------------------------------------------------------------------------------------------------------------

#checkov:skip=CKV_AWS_28: "DynamoDB PITR enabled below via point_in_time_recovery block"
resource "aws_dynamodb_table" "properties_metadata" {
  name         = "pf-properties-metadata-${var.environment}"
  billing_mode = "PAY_PER_REQUEST" # $0.00 idle compute cost
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.pf_kyc_cmk.arn
  }

  tags = {
    Name                 = "pf-properties-metadata-${var.environment}"
    DataClassification   = "Restricted-UAE-PDPL"
    ComplianceRegulation = "UAE-PDPL-ISO27001"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. EVENT-DRIVEN MALWARE SCAN PIPELINE (S3 -> EVENTBRIDGE -> SQS -> ECS WORKER)
# ---------------------------------------------------------------------------------------------------------------------

# 4.1 S3 Bucket EventBridge Notifications
resource "aws_s3_bucket_notification" "kyc_vault_events" {
  bucket      = aws_s3_bucket.kyc_vault.id
  eventbridge = true
}

# 4.2 SQS Dead Letter Queue for Scan Failures
resource "aws_sqs_queue" "document_scan_dlq" {
  #checkov:skip=CKV_AWS_72: Dead Letter Queue does not require a secondary dead letter queue
  name                      = "pf-shield-document-scan-dlq-${var.environment}"
  kms_master_key_id         = aws_kms_key.pf_kyc_cmk.arn
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Name        = "pf-shield-document-scan-dlq-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_sqs_queue_policy" "document_scan_dlq_policy" {
  queue_url = aws_sqs_queue.document_scan_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceSecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.document_scan_dlq.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# 4.3 SQS Queue for Asynchronous Document Scanning
resource "aws_sqs_queue" "document_scan_queue" {
  name                       = "pf-shield-document-scan-queue-${var.environment}"
  kms_master_key_id          = aws_kms_key.pf_kyc_cmk.arn
  visibility_timeout_seconds = 60

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.document_scan_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name        = "pf-shield-document-scan-queue-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_sqs_queue_policy" "document_scan_queue_policy" {
  queue_url = aws_sqs_queue.document_scan_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgeSendMessage"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.document_scan_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.kyc_upload_scanner.arn
          }
        }
      },
      {
        Sid       = "EnforceSecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.document_scan_queue.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# 4.4 EventBridge Rule Matching S3 KYC Uploads
resource "aws_cloudwatch_event_rule" "kyc_upload_scanner" {
  name        = "pf-shield-kyc-upload-scanner-${var.environment}"
  description = "Captures S3 KYC Vault ObjectCreated events and enqueues to SQS for malware worker processing"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = {
        name = [aws_s3_bucket.kyc_vault.id]
      }
      object = {
        key = [{
          prefix = "kyc-documents/"
        }]
      }
    }
  })

  tags = {
    Name        = "pf-shield-kyc-upload-scanner-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "kyc_upload_scanner_sqs" {
  rule      = aws_cloudwatch_event_rule.kyc_upload_scanner.name
  target_id = "DocumentScanSQSTarget"
  arn       = aws_sqs_queue.document_scan_queue.arn
}
