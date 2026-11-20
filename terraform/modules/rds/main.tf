# =====================================================================================================================
# PF-SHIELD SECURE RELATIONAL DATABASE TIER (AMAZON RDS POSTGRESQL)
# Enforces zero public ingress, KMS CMK encryption at rest, forced TLS, IAM authentication,
# continuous automated backups, enhanced monitoring, and Secrets Manager credential governance.
# =====================================================================================================================

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------------------------------------------------
# 1. PRIVATE DATABASE SUBNET GROUP & HARDENED PARAMETER GROUP
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  count       = var.enable_rds ? 1 : 0
  name        = "pf-shield-db-subnet-group-${var.environment}"
  description = "Isolated private database subnets with zero internet ingress"
  subnet_ids  = var.private_db_subnet_ids

  tags = {
    Name        = "pf-shield-db-subnet-group-${var.environment}"
    Tier        = "private-database"
    Environment = var.environment
  }
}

resource "aws_db_parameter_group" "main" {
  count       = var.enable_rds ? 1 : 0
  name        = "pf-shield-pg16-params-${var.environment}"
  family      = "postgres16"
  description = "Hardened PostgreSQL 16 parameter group enforcing TLS 1.2+ and connection logging"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # Log queries taking > 1 second for performance and security audit
  }

  tags = {
    Name        = "pf-shield-pg16-params-${var.environment}"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. CREDENTIAL MANAGEMENT (AWS SECRETS MANAGER ENCRYPTED WITH KMS CMK)
# ---------------------------------------------------------------------------------------------------------------------

resource "random_password" "db_master_password" {
  count            = var.enable_rds ? 1 : 0
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "db_credentials" {
  #checkov:skip=CKV2_AWS_57: Secrets Manager secret rotation managed via operational rotation playbooks
  count                   = var.enable_rds ? 1 : 0
  name                    = "pf-shield/database/credentials/${var.environment}"
  description             = "Master administrative credentials for PF-Shield RDS PostgreSQL metadata store"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.environment == "production" ? 30 : 0

  tags = {
    Name        = "pf-shield-db-credentials-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  count     = var.enable_rds ? 1 : 0
  secret_id = aws_secretsmanager_secret.db_credentials[0].id
  secret_string = jsonencode({
    engine   = "postgres"
    host     = aws_db_instance.main[0].address
    port     = 5432
    dbname   = "pf_shield_metadata"
    username = "pf_admin"
    password = random_password.db_master_password[0].result
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. ENHANCED MONITORING ROLE & CLOUDWATCH LOG GROUPS
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "rds_monitoring" {
  count                = var.enable_rds && var.environment == "production" ? 1 : 0
  name                 = "pf-shield-rds-monitoring-role-${var.environment}"
  permissions_boundary = coalesce(var.rds_monitoring_permission_boundary_arn, var.permission_boundary_arn)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "pf-shield-rds-monitoring-role-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  count      = var.enable_rds && var.environment == "production" ? 1 : 0
  role       = aws_iam_role.rds_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_cloudwatch_log_group" "rds_logs" {
  for_each          = var.enable_rds ? toset(["postgresql", "upgrade"]) : toset([])
  name              = "/aws/rds/instance/pf-shield-db-${var.environment}/${each.value}"
  retention_in_days = var.audit_retention_days
  kms_key_id        = var.kms_key_arn

  tags = {
    Name        = "pf-shield-rds-logs-${each.value}-${var.environment}"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. SECURE RDS POSTGRESQL INSTANCE
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_db_instance" "main" {
  #checkov:skip=CKV_AWS_157: Multi-AZ is conditionally enabled in production; disabled in demo profile to prevent idle charges
  #checkov:skip=CKV_AWS_118: Enhanced Monitoring is conditionally enabled in production; disabled in demo profile
  #checkov:skip=CKV_AWS_353: Performance Insights is conditionally enabled in production; disabled in demo profile
  #checkov:skip=CKV_AWS_354: Performance Insights is conditionally enabled in production; disabled in demo profile
  #checkov:skip=CKV_AWS_293: Deletion protection is enabled conditionally via var.enable_deletion_protection in production profile
  count = var.enable_rds ? 1 : 0

  identifier = "pf-shield-db-${var.environment}"
  engine     = "postgres"
  # renovate: datasource=aws-rds-engine-version depName=postgres
  engine_version = "16.8"
  instance_class = var.rds_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_name  = "pf_shield_metadata"
  username = "pf_admin"
  password = random_password.db_master_password[0].result

  db_subnet_group_name   = aws_db_subnet_group.main[0].name
  vpc_security_group_ids = [var.database_security_group_id]
  parameter_group_name   = aws_db_parameter_group.main[0].name
  publicly_accessible    = false

  multi_az                  = var.environment == "production" ? true : false
  deletion_protection       = var.enable_deletion_protection
  skip_final_snapshot       = var.environment == "production" ? false : true
  final_snapshot_identifier = var.environment == "production" ? "pf-shield-db-${var.environment}-final-snap" : null

  backup_retention_period = var.environment == "production" ? 35 : 7
  backup_window           = "02:00-03:00"
  maintenance_window      = "Sun:03:00-Sun:04:00"

  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = true
  copy_tags_to_snapshot               = true

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  monitoring_interval = var.environment == "production" ? 60 : 0
  monitoring_role_arn = var.environment == "production" ? aws_iam_role.rds_monitoring[0].arn : null

  performance_insights_enabled          = var.environment == "production" ? true : false
  performance_insights_kms_key_id       = var.environment == "production" ? var.kms_key_arn : null
  performance_insights_retention_period = 7

  tags = {
    Name        = "pf-shield-db-${var.environment}"
    Tier        = "private-database"
    Compliance  = "UAE-PDPL-Encrypted"
    Environment = var.environment
  }

  depends_on = [aws_cloudwatch_log_group.rds_logs]
}

# ---------------------------------------------------------------------------------------------------------------------
# 5. ROUTE 53 INTERNAL PRIVATE SERVICE DISCOVERY RECORD
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_route53_record" "db" {
  count   = var.enable_rds ? 1 : 0
  zone_id = var.internal_hosted_zone_id
  name    = "db.pf-shield.internal"
  type    = "CNAME"
  ttl     = 60
  records = [aws_db_instance.main[0].address]
}
