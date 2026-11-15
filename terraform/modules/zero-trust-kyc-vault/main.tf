data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394: Availability zones dynamically queried and indexed strictly to 0 and 1
  state = "available"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # Permit current deployment account identity plus explicitly passed roles (e.g. KYC Lambda, SOAR Lambda)
  effective_allowed_arns = distinct(concat(
    [
      data.aws_caller_identity.current.arn,
      "arn:aws:iam::${local.account_id}:root"
    ],
    var.allowed_principal_arns
  ))
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. NETWORK ISOLATION: VPC & ZERO-COST GATEWAY ENDPOINTS
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_vpc" "kyc_vpc" {
  #checkov:skip=CKV2_AWS_11: VPC Flow Logs disabled to maintain $0.00 idle cost guardrail
  #checkov:skip=CKV2_AWS_12: Default security group restricted with zero inbound/outbound rules
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "pf-shield-vpc-${var.environment}"
  }
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.kyc_vpc.id

  # Zero ingress and zero egress rules enforces baseline isolation (CIS AWS Benchmark)
  tags = {
    Name = "pf-shield-default-sg-locked"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.kyc_vpc.id
  cidr_block        = "10.20.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "pf-shield-subnet-private-a-${var.environment}"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.kyc_vpc.id
  cidr_block        = "10.20.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "pf-shield-subnet-private-b-${var.environment}"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.kyc_vpc.id

  tags = {
    Name = "pf-shield-rt-private-${var.environment}"
  }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# Free Gateway Endpoints: $0.00/hour, routing internal traffic directly to AWS S3 & DynamoDB
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.kyc_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name = "pf-shield-vpce-s3-${var.environment}"
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.kyc_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name = "pf-shield-vpce-dynamodb-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. ENVELOPE ENCRYPTION: KMS CUSTOMER MANAGED KEY (CMK)
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
            "ssm.amazonaws.com"
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
# 3. ZERO-TRUST BROKER KYC DOCUMENT VAULT (S3)
# ---------------------------------------------------------------------------------------------------------------------

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "kyc_vault" {
  #checkov:skip=CKV_AWS_18: S3 access logging intentionally disabled to prevent recurring PUT costs on idle demo environment
  #checkov:skip=CKV_AWS_144: Cross-region replication disabled to comply with UAE PDPL data residency requirements
  #checkov:skip=CKV2_AWS_62: S3 event notifications managed by CloudTrail and EventBridge SOAR rules
  bucket        = "pf-kyc-vault-${var.environment}-${random_id.bucket_suffix.hex}"
  force_destroy = true

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

resource "aws_s3_bucket_policy" "kyc_vault_policy" {
  bucket     = aws_s3_bucket.kyc_vault.id
  depends_on = [aws_s3_bucket_public_access_block.kyc_vault_pab]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.kyc_vault.arn,
          "${aws_s3_bucket.kyc_vault.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.kyc_vault.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "EnforceDataPerimeter"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.kyc_vault.arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.s3.id
          }
          ArnNotEquals = {
            "aws:PrincipalArn" = local.effective_allowed_arns
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. METADATA STORE: DYNAMODB PROPERTIES & KYC METADATA TABLE
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
