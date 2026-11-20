data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. AUDIT LAYER: DEDICATED S3 AUDIT BUCKET & CLOUDTRAIL
# ---------------------------------------------------------------------------------------------------------------------

resource "random_id" "audit_bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "audit_logs" {
  #checkov:skip=CKV_AWS_18: S3 access logging intentionally disabled to prevent recurring PUT costs on idle audit bucket
  #checkov:skip=CKV_AWS_144: Cross-region replication disabled to comply with UAE PDPL data residency requirements
  #checkov:skip=CKV2_AWS_62: S3 event notifications managed by CloudTrail and EventBridge
  bucket              = "pf-shield-audit-${var.environment}-${random_id.audit_bucket_suffix.hex}"
  force_destroy       = var.environment == "production" ? false : true
  object_lock_enabled = true

  tags = {
    Name               = "pf-shield-audit-logs-${var.environment}"
    DataClassification = "Restricted-Audit"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs_pab" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit_logs_versioning" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_logs_lock" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE" # Strict WORM (Write Once, Read Many) compliance
      days = var.audit_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs_encryption" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs_lifecycle" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    id     = "audit-log-retention-and-transition"
    status = "Enabled"

    filter {}

    dynamic "transition" {
      for_each = var.environment == "production" ? [1] : []
      content {
        days          = 90
        storage_class = "GLACIER"
      }
    }

    expiration {
      days = var.audit_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "audit_logs_policy" {
  bucket     = aws_s3_bucket.audit_logs.id
  depends_on = [aws_s3_bucket_public_access_block.audit_logs_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTlsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.audit_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.audit_logs.arn}/prefix/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSConfigAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.audit_logs.arn
      },
      {
        Sid    = "AWSConfigWrite"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.audit_logs.arn}/AWSLogs/${local.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main_audit_trail" {
  #checkov:skip=CKV_AWS_252: CloudWatch Logs ingestion for CloudTrail omitted to satisfy $0.00 idle cost guardrail
  #checkov:skip=CKV2_AWS_10: CloudTrail integrated with dedicated S3 audit bucket with 7-day retention for FinOps
  name                          = "pf-shield-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn

  dynamic "event_selector" {
    for_each = var.enable_cloudtrail_s3_data_events && var.kyc_vault_bucket_arn != "" ? [1] : []
    content {
      read_write_type           = "All"
      include_management_events = true

      data_resource {
        type   = "AWS::S3::Object"
        values = ["${var.kyc_vault_bucket_arn}/*"]
      }
    }
  }

  depends_on = [aws_s3_bucket_policy.audit_logs_policy]

  tags = {
    Name = "pf-shield-cloudtrail-${var.environment}"
  }
}

# Optional GuardDuty and Security Hub (controlled via FinOps feature-flags)
resource "aws_guardduty_detector" "primary" {
  #checkov:skip=CKV2_AWS_3: GuardDuty detector configured conditionally and scoped to primary region
  count  = var.enable_guardduty_and_securityhub ? 1 : 0
  enable = true

  tags = {
    Name = "pf-shield-guardduty-${var.environment}"
  }
}

resource "aws_securityhub_account" "primary" {
  count = var.enable_guardduty_and_securityhub ? 1 : 0
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. INCIDENT NOTIFICATION LAYER: ENCRYPTED SNS TOPIC & SQS DEAD LETTER QUEUES
# ---------------------------------------------------------------------------------------------------------------------

#checkov:skip=CKV_AWS_26: SNS topic encrypted with Customer Managed Key below
resource "aws_sns_topic" "security_incidents" {
  name              = "pf-security-incidents-${var.environment}"
  kms_master_key_id = var.kms_key_arn

  tags = {
    Name = "pf-security-incidents-${var.environment}"
  }
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.security_incidents.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SQS Dead Letter Queues ensure zero dropped security alerts
resource "aws_sqs_queue" "s3_lockdown_dlq" {
  name                              = "pf-soar-s3-lockdown-dlq-${var.environment}"
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600 # 14 days

  tags = {
    Name = "pf-soar-s3-lockdown-dlq-${var.environment}"
  }
}

resource "aws_sqs_queue" "iam_quarantine_dlq" {
  name                              = "pf-soar-iam-quarantine-dlq-${var.environment}"
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600 # 14 days

  tags = {
    Name = "pf-soar-iam-quarantine-dlq-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. SOAR DEDUPLICATION & SERVERLESS REMEDIATION LAMBDAS (ARM64 GRAVITON2)
# ---------------------------------------------------------------------------------------------------------------------

# DynamoDB Event Idempotency & Deduplication Table
resource "aws_dynamodb_table" "soar_idempotency" {
  name         = "pf-soar-idempotency-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = {
    Name       = "pf-soar-idempotency-${var.environment}"
    Purpose    = "SOAR Deduplication and Incident Idempotency"
    Compliance = "UAE-PDPL"
  }
}

data "archive_file" "s3_lockdown_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../src/soar/playbook_s3_lockdown.py"
  output_path = "${path.module}/s3_lockdown.zip"
}

data "archive_file" "iam_quarantine_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../src/soar/playbook_iam_quarantine.py"
  output_path = "${path.module}/iam_quarantine.zip"
}

# Execution Role for S3 Lockdown Lambda
resource "aws_iam_role" "s3_lockdown_role" {
  name                 = "pf-soar-s3-lockdown-role-${var.environment}"
  permissions_boundary = var.permission_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "s3_lockdown_permissions" {
  #checkov:skip=CKV_AWS_286: SOAR automation legitimately attaches quarantine deny-all policies
  #checkov:skip=CKV_AWS_289: SOAR automation requires attaching quarantine policies to arbitrary compromised roles/users
  #checkov:skip=CKV_AWS_290: SOAR automation requires attaching quarantine policies to arbitrary compromised roles/users
  #checkov:skip=CKV_AWS_355: Resource wildcard required for dynamically remediating arbitrary buckets and principals
  name = "pf-soar-s3-lockdown-policy"
  role = aws_iam_role.s3_lockdown_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3PublicAccessBlockEnforcement"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = [
          "arn:aws:s3:::pf-shield-*",
          "arn:aws:s3:::pf-kyc-*"
        ]
      },
      {
        Sid    = "IAMQuarantineAttachment"
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:AttachUserPolicy"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/pf-*",
          "arn:aws:iam::${local.account_id}:user/pf-*"
        ]
      },
      {
        Sid    = "NotificationAndTelemetry"
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "cloudwatch:PutMetricData",
          "sqs:SendMessage"
        ]
        Resource = [
          aws_sns_topic.security_incidents.arn,
          aws_sqs_queue.s3_lockdown_dlq.arn,
          aws_sqs_queue.iam_quarantine_dlq.arn
        ]
      },
      {
        Sid    = "CloudWatchMetricPublishing"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBIdempotency"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.soar_idempotency.arn
      },
      {
        Sid    = "KMSDecryptionAndLogs"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          var.kms_key_arn,
          "${aws_cloudwatch_log_group.s3_lockdown_logs.arn}:*"
        ]
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "s3_lockdown_logs" {
  #checkov:skip=CKV_AWS_338: Parameterized retention (7 days demo, 365 days production)
  name              = "/aws/lambda/pf-soar-s3-lockdown-${var.environment}"
  retention_in_days = var.audit_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "s3_lockdown" {
  #checkov:skip=CKV_AWS_115: Function-level concurrent execution limit omitted to avoid depleting account unreserved concurrency below regional minimum quota
  #checkov:skip=CKV_AWS_116: Dead Letter Queue configured below via dead_letter_config block
  #checkov:skip=CKV_AWS_117: Lambda is intentionally non-VPC to avoid expensive VPC NAT gateways and reach IAM/SNS directly
  #checkov:skip=CKV_AWS_272: Code signing omitted for simplified serverless deployment
  function_name                  = "pf-soar-s3-lockdown-${var.environment}"
  role                           = aws_iam_role.s3_lockdown_role.arn
  handler                        = "playbook_s3_lockdown.lambda_handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  memory_size                    = 128
  timeout                        = 10
  filename                       = data.archive_file.s3_lockdown_zip.output_path
  source_code_hash               = data.archive_file.s3_lockdown_zip.output_base64sha256
  kms_key_arn                    = var.kms_key_arn

  dead_letter_config {
    target_arn = aws_sqs_queue.s3_lockdown_dlq.arn
  }

  environment {
    variables = {
      QUARANTINE_POLICY_ARN          = var.quarantine_policy_arn
      SNS_TOPIC_ARN                  = aws_sns_topic.security_incidents.arn
      IDEMPOTENCY_TABLE_NAME         = aws_dynamodb_table.soar_idempotency.name
      CONTAINMENT_MODE               = var.containment_mode
      PROTECTED_PRINCIPALS_ALLOWLIST = var.protected_principals_allowlist
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.s3_lockdown_logs]
}

# Execution Role for IAM Quarantine Lambda
resource "aws_iam_role" "iam_quarantine_role" {
  name                 = "pf-soar-iam-quarantine-role-${var.environment}"
  permissions_boundary = var.permission_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "iam_quarantine_permissions" {
  #checkov:skip=CKV_AWS_286: SOAR automation legitimately attaches quarantine deny-all policies
  #checkov:skip=CKV_AWS_287: Access key deactivation required for compromised credential containment
  #checkov:skip=CKV_AWS_289: Attaching quarantine policies to arbitrary compromised roles/users is core SOAR capability
  #checkov:skip=CKV_AWS_290: Attaching quarantine policies to arbitrary compromised roles/users is core SOAR capability
  #checkov:skip=CKV_AWS_355: Resource wildcard required for deactivating keys and attaching quarantine policies across accounts
  name = "pf-soar-iam-quarantine-policy"
  role = aws_iam_role.iam_quarantine_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMQuarantineAndKeyRevocation"
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:AttachUserPolicy",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/pf-*",
          "arn:aws:iam::${local.account_id}:user/pf-*"
        ]
      },
      {
        Sid    = "NotificationAndTelemetry"
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sqs:SendMessage"
        ]
        Resource = [
          aws_sns_topic.security_incidents.arn,
          aws_sqs_queue.s3_lockdown_dlq.arn,
          aws_sqs_queue.iam_quarantine_dlq.arn
        ]
      },
      {
        Sid    = "CloudWatchMetricPublishing"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBIdempotency"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.soar_idempotency.arn
      },
      {
        Sid    = "KMSDecryptionAndLogs"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          var.kms_key_arn,
          "${aws_cloudwatch_log_group.iam_quarantine_logs.arn}:*"
        ]
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "iam_quarantine_logs" {
  #checkov:skip=CKV_AWS_338: Parameterized retention (7 days demo, 365 days production)
  name              = "/aws/lambda/pf-soar-iam-quarantine-${var.environment}"
  retention_in_days = var.audit_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "iam_quarantine" {
  #checkov:skip=CKV_AWS_115: Function-level concurrent execution limit omitted to avoid depleting account unreserved concurrency below regional minimum quota
  #checkov:skip=CKV_AWS_116: Dead Letter Queue configured below via dead_letter_config block
  #checkov:skip=CKV_AWS_117: Lambda is intentionally non-VPC to avoid expensive VPC NAT gateways and reach IAM/SNS directly
  #checkov:skip=CKV_AWS_272: Code signing omitted for simplified serverless deployment
  function_name                  = "pf-soar-iam-quarantine-${var.environment}"
  role                           = aws_iam_role.iam_quarantine_role.arn
  handler                        = "playbook_iam_quarantine.lambda_handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  memory_size                    = 128
  timeout                        = 10
  filename                       = data.archive_file.iam_quarantine_zip.output_path
  source_code_hash               = data.archive_file.iam_quarantine_zip.output_base64sha256
  kms_key_arn                    = var.kms_key_arn

  dead_letter_config {
    target_arn = aws_sqs_queue.iam_quarantine_dlq.arn
  }

  environment {
    variables = {
      QUARANTINE_POLICY_ARN          = var.quarantine_policy_arn
      SNS_TOPIC_ARN                  = aws_sns_topic.security_incidents.arn
      IDEMPOTENCY_TABLE_NAME         = aws_dynamodb_table.soar_idempotency.name
      CONTAINMENT_MODE               = var.containment_mode
      PROTECTED_PRINCIPALS_ALLOWLIST = var.protected_principals_allowlist
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.iam_quarantine_logs]
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. EVENT-DRIVEN DETECTION: EVENTBRIDGE RULES & DISPATCH
# ---------------------------------------------------------------------------------------------------------------------

# Rule 1: S3 Tampering, Public Exposure, or Exfiltration
resource "aws_cloudwatch_event_rule" "s3_security_rule" {
  name        = "pf-s3-tamper-or-exfiltration-${var.environment}"
  description = "Triggers S3 lockdown playbook upon S3 tampering, public exposure, or GuardDuty exfiltration detection"

  event_pattern = jsonencode({
    "$or" = [
      {
        source      = ["aws.s3"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName = [
            "PutBucketPublicAccessBlock",
            "DeleteBucketPolicy",
            "PutBucketPolicy",
            "PutBucketAcl"
          ]
        }
      },
      {
        source      = ["aws.guardduty"]
        detail-type = ["GuardDuty Finding"]
        detail = {
          type = [
            "Policy:S3/BucketBlockPublicAccessDisabled",
            "Exfiltration:S3/MaliciousIPCaller",
            "UnauthorizedAccess:S3/TorIPCaller"
          ]
        }
      },
      {
        source      = ["pf.security.simulation"]
        detail-type = ["Simulated S3 Public Exposure Attack", "S3 Exfiltration Simulation"]
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "s3_lockdown_target" {
  rule      = aws_cloudwatch_event_rule.s3_security_rule.name
  target_id = "PFShieldS3LockdownLambda"
  arn       = aws_lambda_function.s3_lockdown.arn

  dead_letter_config {
    arn = aws_sqs_queue.s3_lockdown_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge_s3_lockdown" {
  statement_id  = "AllowExecutionFromEventBridgeS3Rule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_lockdown.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_security_rule.arn
}

# Rule 2: IAM Compromise, Unauthorized Privilege Escalation, or Key Creation
resource "aws_cloudwatch_event_rule" "iam_security_rule" {
  name        = "pf-iam-compromise-or-escalation-${var.environment}"
  description = "Triggers IAM quarantine playbook upon privilege escalation or compromised credentials"

  event_pattern = jsonencode({
    "$or" = [
      {
        source      = ["aws.iam"]
        detail-type = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName = [
            "DeleteRolePermissionsBoundary",
            "PutUserPolicy",
            "AttachRolePolicy",
            "CreateAccessKey"
          ]
        }
      },
      {
        source      = ["aws.guardduty"]
        detail-type = ["GuardDuty Finding"]
        detail = {
          type = [
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
          ]
        }
      },
      {
        source      = ["pf.security.simulation"]
        detail-type = ["Simulated IAM Credential Compromise", "IAM Privilege Escalation Attack"]
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "iam_quarantine_target" {
  rule      = aws_cloudwatch_event_rule.iam_security_rule.name
  target_id = "PFShieldIAMQuarantineLambda"
  arn       = aws_lambda_function.iam_quarantine.arn

  dead_letter_config {
    arn = aws_sqs_queue.iam_quarantine_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge_iam_quarantine" {
  statement_id  = "AllowExecutionFromEventBridgeIAMRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_quarantine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_security_rule.arn
}
