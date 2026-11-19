# =====================================================================================================================
# PF-SHIELD: DETECTIVE CONTROLS & COMPLIANCE BASELINE (AWS CONFIG)
# Continuously audits cloud resources against security guardrails and regulatory benchmarks
# Aligned with UAE PDPL Art. 13, ISO 27001:2022 A.8.15, and CIS AWS Foundations Benchmark
# =====================================================================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. AWS CONFIG SERVICE IAM ROLE
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "config_role" {
  count                = var.enable_aws_config ? 1 : 0
  name                 = "pf-aws-config-role-${var.environment}"
  permissions_boundary = var.permission_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name       = "pf-aws-config-role-${var.environment}"
    Compliance = "CIS-AWS-Benchmark"
  }
}

resource "aws_iam_role_policy" "config_policy" {
  #checkov:skip=CKV_AWS_288: AWS Config service role requires resource configuration enumeration across the account
  #checkov:skip=CKV_AWS_290: AWS Config service role requires resource enumeration across the account
  #checkov:skip=CKV_AWS_355: AWS Config service role requires resource enumeration across the account
  count = var.enable_aws_config ? 1 : 0
  name  = "pf-aws-config-policy"
  role  = aws_iam_role.config_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigInventoryReadOnly"
        Effect = "Allow"
        Action = [
          "config:*",
          "s3:GetBucket*",
          "s3:GetAccountPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:ListAllMyBuckets",
          "s3:ListBucket",
          "ec2:Describe*",
          "rds:Describe*",
          "iam:Get*",
          "iam:List*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AWSConfigAuditBucketDelivery"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl"
        ]
        Resource = [
          "arn:aws:s3:::${var.audit_bucket_name}",
          "arn:aws:s3:::${var.audit_bucket_name}/*"
        ]
      },
      {
        Sid    = "KMSDecryptionAndEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. CONFIGURATION RECORDER & DELIVERY CHANNEL
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_aws_config ? 1 : 0
  name     = "pf-shield-config-recorder-${var.environment}"
  role_arn = aws_iam_role.config_role[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_aws_config ? 1 : 0
  name           = "pf-shield-config-delivery-${var.environment}"
  s3_bucket_name = var.audit_bucket_name
  s3_kms_key_arn = var.kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  count      = var.enable_aws_config ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. CONTINUOUS COMPLIANCE RULES
# ---------------------------------------------------------------------------------------------------------------------

# Rule 1: S3 Public Read Prohibited
resource "aws_config_config_rule" "s3_public_read_prohibited" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "s3-bucket-public-read-prohibited"
  description = "Checks that S3 buckets do not allow public read access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Rule 2: S3 Public Write Prohibited
resource "aws_config_config_rule" "s3_public_write_prohibited" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "s3-bucket-public-write-prohibited"
  description = "Checks that S3 buckets do not allow public write access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Rule 3: Encrypted EBS Volumes
resource "aws_config_config_rule" "encrypted_volumes" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "encrypted-volumes"
  description = "Checks that EBS volumes are encrypted with KMS"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Rule 4: Restricted Administrative Ports (SSH 22, RDP 3389)
resource "aws_config_config_rule" "restricted_common_ports" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "restricted-common-ports"
  description = "Checks that security groups disallow unrestricted incoming traffic on common admin ports"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "22"
    blockedPort2 = "3389"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Rule 5: Default Security Group Closed
resource "aws_config_config_rule" "default_sg_closed" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "vpc-default-security-group-closed"
  description = "Checks that default security groups restrict all inbound and outbound traffic"

  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Rule 6: IMDSv2 Required on EC2 Instances
resource "aws_config_config_rule" "imdsv2_check" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "ec2-imdsv2-check"
  description = "Checks that EC2 instances enforce IMDSv2 token usage to prevent SSRF credential theft"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Rule 7: RDS Instance Public Access Prohibited
resource "aws_config_config_rule" "rds_public_access_check" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "rds-instance-public-access-check"
  description = "Checks that RDS PostgreSQL database instances are private and not publicly accessible"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# Rule 8: IAM Access Key Rotation (90 Days)
resource "aws_config_config_rule" "access_keys_rotated" {
  count       = var.enable_aws_config ? 1 : 0
  name        = "access-keys-rotated"
  description = "Checks that active IAM access keys are rotated within 90 days"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}
