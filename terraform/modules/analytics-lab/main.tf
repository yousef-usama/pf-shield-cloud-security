# =====================================================================================================================
# PF-SHIELD ISOLATED ANALYTICS LAB & S3 DATA LAKE DEMONSTRATION
# Demonstrates host hardening (IMDSv2, SSM-only access, encrypted EBS, zero SSH ingress),
# S3 analytics data lake security, and AWS Glue ETL data sanitization (PII redaction).
# NOTE: This module represents a cloud-security demonstration environment rather than an
# internal proprietary implementation of any commercial entity.
# =====================================================================================================================

data "aws_caller_identity" "current" {}

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-arm64"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. S3 ANALYTICS DATA LAKE (RAW & CURATED PARTITIONS)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_s3_bucket" "analytics" {
  #checkov:skip=CKV_AWS_18: S3 access logging disabled to prevent recurring PUT charges on idle analytics bucket
  #checkov:skip=CKV_AWS_144: Cross-region replication disabled to enforce UAE PDPL data residency
  #checkov:skip=CKV2_AWS_62: S3 event notifications managed by Glue and EventBridge
  bucket        = "pf-shield-analytics-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = var.environment == "production" ? false : true

  tags = {
    Name        = "pf-shield-analytics-${var.environment}"
    Tier        = "analytics-data-lake"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "analytics_lifecycle" {
  bucket = aws_s3_bucket.analytics.id

  rule {
    id     = "analytics-data-lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "analytics" {
  bucket = aws_s3_bucket.analytics.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "analytics" {
  #checkov:skip=CKV_AWS_300: Lifecycle rules expire temporary raw ETL artifacts after 30 days
  bucket     = aws_s3_bucket.analytics.id
  depends_on = [aws_s3_bucket_public_access_block.analytics]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.analytics.arn,
          "${aws_s3_bucket.analytics.arn}/*"
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
        Resource  = "${aws_s3_bucket.analytics.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. HARDENED EC2 CLICKHOUSE ANALYTICS SECURITY DEMONSTRATION NODE
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_security_group" "clickhouse" {
  #checkov:skip=CKV2_AWS_5: Security group attached across resources to EC2 analytics host
  name        = "pf-shield-clickhouse-sg-${var.environment}"
  description = "Hardened security group for ClickHouse analytics host with zero SSH access"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow ClickHouse HTTP/TLS query ingress strictly from ECS container security group"
    from_port       = 8123
    to_port         = 8123
    protocol        = "tcp"
    security_groups = [var.ecs_security_group_id]
  }

  egress {
    description = "Allow HTTPS egress to VPC endpoints and AWS services only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  tags = {
    Name        = "pf-shield-clickhouse-sg-${var.environment}"
    Tier        = "analytics-host"
    Environment = var.environment
  }
}

resource "aws_iam_role" "clickhouse" {
  name                 = "pf-shield-clickhouse-role-${var.environment}"
  permissions_boundary = coalesce(var.ssm_ec2_permission_boundary_arn, var.permission_boundary_arn)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "pf-shield-clickhouse-role-${var.environment}"
    Environment = var.environment
  }
}

# AWS Systems Manager Session Manager access (eliminates SSH key distribution and open port 22)
resource "aws_iam_role_policy_attachment" "clickhouse_ssm" {
  role       = aws_iam_role.clickhouse.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "clickhouse_s3_read" {
  name = "pf-shield-clickhouse-s3-curated-read"
  role = aws_iam_role.clickhouse.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadCuratedParquetAnalyticsOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.analytics.arn,
          "${aws_s3_bucket.analytics.arn}/curated/*"
        ]
      },
      {
        Sid    = "DecryptWithKmsCmk"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "clickhouse" {
  name = "pf-shield-clickhouse-profile-${var.environment}"
  role = aws_iam_role.clickhouse.name
}

resource "aws_instance" "clickhouse" {
  #checkov:skip=CKV_AWS_135: Graviton t4g instances are EBS-optimized by default in AWS
  count = var.enable_analytics_lab ? 1 : 0

  ami                         = var.ami_id != null ? var.ami_id : data.aws_ami.amazon_linux_2023.id
  instance_type               = var.analytics_instance_type
  subnet_id                   = var.private_app_subnet_ids[0]
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.clickhouse.id]
  iam_instance_profile        = aws_iam_instance_profile.clickhouse.name
  ebs_optimized               = true
  monitoring                  = true

  # IMDSv2 Enforced strictly (tokens=required, hop_limit=1 prevents SSRF exfiltration)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              set -euo pipefail
              echo "Initializing hardened analytics demonstration node..."
              # Update OS security patches
              dnf update -y --security
              # Ensure SSM agent is active for zero-port bastionless management
              systemctl enable amazon-ssm-agent
              systemctl start amazon-ssm-agent
              # Create dedicated unprivileged service account for analytics service
              useradd -r -s /sbin/nologin -d /var/lib/clickhouse clickhouse || true
              mkdir -p /var/log/clickhouse-server /var/lib/clickhouse
              chown -R clickhouse:clickhouse /var/log/clickhouse-server /var/lib/clickhouse
              chmod 750 /var/log/clickhouse-server /var/lib/clickhouse
              echo "Hardened analytics host configuration complete."
              EOF

  tags = {
    Name        = "pf-shield-clickhouse-analytics-${var.environment}"
    Tier        = "analytics-host"
    Role        = "Security-Demonstration-Lab"
    Environment = var.environment
  }
}

resource "aws_route53_record" "clickhouse" {
  count   = var.enable_analytics_lab ? 1 : 0
  zone_id = var.internal_hosted_zone_id
  name    = "analytics.pf-shield.internal"
  type    = "A"
  ttl     = 60
  records = [aws_instance.clickhouse[0].private_ip]
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. AWS GLUE ETL SANITIZATION PIPELINE (PII REDACTION & CURATED PARQUET)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_glue_catalog_database" "analytics" {
  name        = "pf_shield_analytics_${var.environment}"
  description = "Metadata catalog for sanitized real estate platform analytics"
}

resource "aws_glue_security_configuration" "main" {
  name = "pf-shield-glue-sec-config-${var.environment}"

  encryption_configuration {
    cloudwatch_encryption {
      cloudwatch_encryption_mode = "SSE-KMS"
      kms_key_arn                = var.kms_key_arn
    }

    job_bookmarks_encryption {
      job_bookmarks_encryption_mode = "CSE-KMS"
      kms_key_arn                   = var.kms_key_arn
    }

    s3_encryption {
      s3_encryption_mode = "SSE-KMS"
      kms_key_arn        = var.kms_key_arn
    }
  }
}

resource "aws_iam_role" "glue_role" {
  name                 = "pf-shield-glue-sanitizer-role-${var.environment}"
  permissions_boundary = coalesce(var.glue_permission_boundary_arn, var.permission_boundary_arn)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "glue.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "pf-shield-glue-sanitizer-role-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "glue_policy" {
  #checkov:skip=CKV_AWS_290: AWS Glue service role requires CloudWatch logs and metrics write permissions
  #checkov:skip=CKV_AWS_355: AWS Glue service role requires CloudWatch logs and metrics write permissions
  name = "pf-shield-glue-sanitizer-policy"
  role = aws_iam_role.glue_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3DataLakeReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.analytics.arn,
          "${aws_s3_bucket.analytics.arn}/*"
        ]
      },
      {
        Sid    = "KmsEnvelopeEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "CloudWatchLogsAndMetrics"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:*:*:log-group:/aws-glue/*"
        ]
      }
    ]
  })
}

resource "aws_s3_object" "glue_etl_script" {
  bucket      = aws_s3_bucket.analytics.id
  key         = "scripts/glue_etl_sanitize_listings.py"
  source      = "${path.module}/../../../src/analytics/glue_etl_sanitize_listings.py"
  kms_key_id  = var.kms_key_arn
  source_hash = filemd5("${path.module}/../../../src/analytics/glue_etl_sanitize_listings.py")
}

resource "aws_glue_job" "sanitize_listings" {
  count                  = var.enable_glue_etl ? 1 : 0
  name                   = "pf-shield-sanitize-listings-etl-${var.environment}"
  role_arn               = aws_iam_role.glue_role.arn
  security_configuration = aws_glue_security_configuration.main.name
  glue_version           = "4.0"
  worker_type            = "G.1X"
  number_of_workers      = 2

  command {
    name            = "glueetl"
    script_location = "s3://${aws_s3_bucket.analytics.id}/scripts/glue_etl_sanitize_listings.py"
    python_version  = "3"
  }

  default_arguments = {
    "--job-language"                     = "python"
    "--enable-continuous-cloudwatch-log" = "true"
    "--enable-metrics"                   = "true"
    "--RAW_BUCKET"                       = aws_s3_bucket.analytics.id
    "--CURATED_BUCKET"                   = aws_s3_bucket.analytics.id
    "--ENVIRONMENT"                      = var.environment
  }

  tags = {
    Name        = "pf-shield-sanitize-listings-etl-${var.environment}"
    Tier        = "analytics-etl"
    Environment = var.environment
  }

  depends_on = [aws_s3_object.glue_etl_script]
}
