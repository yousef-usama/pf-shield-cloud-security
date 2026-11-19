data "aws_caller_identity" "current" {}

locals {
  account_id           = data.aws_caller_identity.current.account_id
  boundary_policy_name = "pf-workload-permission-boundary-${var.environment}"
  boundary_policy_arn  = "arn:aws:iam::${local.account_id}:policy/${local.boundary_policy_name}"
}

# 1. Zero-Trust Workload Permission Boundary
# Enforces that no application role can operate outside me-central-1, mutate audit logs, or escalate privileges.
resource "aws_iam_policy" "workload_permission_boundary" {
  name        = local.boundary_policy_name
  description = "Maximum permissions boundary for PF-Shield workload roles with region lock and privilege escalation denial"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowScopedRegionalServices"
        Effect = "Allow"
        Action = [
          "s3:GetObject*",
          "s3:PutObject*",
          "s3:ListBucket*",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "DenyBoundaryTamperingAndRemoval"
        Effect = "Deny"
        Action = [
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:CreatePolicyVersion",
          "iam:DetachRolePolicy",
          "iam:DeleteRolePermissionsBoundary"
        ]
        Resource = local.boundary_policy_arn
      },
      {
        Sid    = "DenyUnboundedRoleCreation"
        Effect = "Deny"
        Action = [
          "iam:CreateRole",
          "iam:PutRolePermissionsBoundary"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "iam:PermissionsBoundary" = local.boundary_policy_arn
          }
        }
      },
      {
        Sid    = "DenyAuditTamperingAndPublicExposure"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy",
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail"
        ]
        Resource = "*"
      }
    ]
  })
}

# 2. SOAR Emergency Quarantine Deny-All Policy
# Applied dynamically by the SOAR Lambda playbook to immediately isolate compromised IAM roles or users.
resource "aws_iam_policy" "soar_quarantine_deny_all" {
  name        = "pf-soar-quarantine-deny-all-${var.environment}"
  description = "Zero-trust emergency quarantine policy attached by SOAR automation to instantly freeze compromised identities"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EmergencyQuarantineDenyAll"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# 3. Dedicated SOAR Permission Boundary
# Permits only authorized containment actions (PAB restoration, quarantine attachment, telemetry, idempotency)
# without inheriting the workload boundary's DenyAuditTamperingAndPublicExposure conflict.
resource "aws_iam_policy" "soar_permission_boundary" {
  #checkov:skip=CKV_AWS_286: SOAR automation boundary must permit attaching emergency deny-all quarantine policies
  #checkov:skip=CKV_AWS_287: SOAR automation boundary must permit deactivating compromised access keys
  #checkov:skip=CKV_AWS_289: Dynamic principal containment requires permissions management within boundary
  #checkov:skip=CKV_AWS_290: SOAR automation requires write access to contain arbitrary compromised identities
  #checkov:skip=CKV_AWS_355: Resource wildcard required for deactivating keys and quarantining identities across arbitrary roles/users
  name        = "pf-soar-permission-boundary-${var.environment}"
  description = "Dedicated maximum permissions boundary for automated SOAR containment roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSOARS3Lockdown"
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
        Sid    = "AllowSOARIAMQuarantine"
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
        Sid    = "AllowSOARIncidentPublishingAndDeadLetter"
        Effect = "Allow"
        Action = [
          "sns:Publish",
          "sqs:SendMessage"
        ]
        Resource = [
          "arn:aws:sns:${var.aws_region}:${local.account_id}:pf-security-incidents-${var.environment}",
          "arn:aws:sqs:${var.aws_region}:${local.account_id}:pf-soar-*-dlq-${var.environment}"
        ]
      },
      {
        Sid    = "AllowSOARTelemetryAndLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowSOARDynamoDBIdempotency"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/pf-soar-idempotency-${var.environment}"
      },
      {
        Sid    = "AllowSOARKMSUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyBoundaryTamperingAndRemoval"
        Effect = "Deny"
        Action = [
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:CreatePolicyVersion",
          "iam:DetachRolePolicy",
          "iam:DeleteRolePermissionsBoundary"
        ]
        Resource = "arn:aws:iam::${local.account_id}:policy/pf-soar-permission-boundary-${var.environment}"
      }
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. DEDICATED SCOPED PERMISSION BOUNDARIES (LEAST-PRIVILEGE SERVICE DECOUPLING)
# ---------------------------------------------------------------------------------------------------------------------

# 4.1 ECS Task Execution Permission Boundary (ECR Image Pull & Container Logging)
resource "aws_iam_policy" "ecs_execution_permission_boundary" {
  #checkov:skip=CKV_AWS_355: ecr:GetAuthorizationToken only operates on Resource = "*" per AWS specification
  name        = "pf-ecs-exec-permission-boundary-${var.environment}"
  description = "Scoped permissions boundary for ECS task execution roles (ECR pulls and CloudWatch Logs)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowECRAuthToken"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowECRImagePullAndLogging"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "DenyBoundaryTamperingAndEscalation"
        Effect = "Deny"
        Action = [
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreateRole",
          "iam:AttachRolePolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

# 4.2 ECS Application Task Permission Boundary (Microservices S3, DynamoDB, SQS, SNS, KMS)
resource "aws_iam_policy" "ecs_task_permission_boundary" {
  name        = "pf-ecs-task-permission-boundary-${var.environment}"
  description = "Scoped permissions boundary for ECS container tasks (S3, DynamoDB, SQS, SNS, KMS)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowScopedAppServices"
        Effect = "Allow"
        Action = [
          "s3:GetObject*",
          "s3:PutObject*",
          "s3:PutObjectTagging",
          "s3:GetObjectTagging",
          "s3:ListBucket*",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility",
          "sns:Publish",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "DenyBoundaryTamperingAndPublicExposure"
        Effect = "Deny"
        Action = [
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreateRole",
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy",
          "cloudtrail:StopLogging"
        ]
        Resource = "*"
      }
    ]
  })
}

# 4.3 AWS Config Continuous Compliance Recording Boundary
resource "aws_iam_policy" "config_permission_boundary" {
  #checkov:skip=CKV_AWS_289: AWS Config requires configuration recording and delivery permissions without arbitrary resource exposure
  #checkov:skip=CKV_AWS_290: AWS Config requires configuration recording write APIs across monitored resources
  #checkov:skip=CKV_AWS_355: AWS Config requires describe and get APIs across account resources for compliance auditing
  name        = "pf-config-permission-boundary-${var.environment}"
  description = "Scoped permissions boundary for AWS Config compliance recorder role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowConfigServiceActions"
        Effect = "Allow"
        Action = [
          "config:Put*",
          "config:Get*",
          "config:Describe*",
          "config:List*",
          "s3:PutObject",
          "s3:GetBucketAcl",
          "s3:ListBucket",
          "ec2:Describe*",
          "s3:GetBucket*",
          "s3:GetAccountPublicAccessBlock",
          "rds:Describe*",
          "iam:Get*",
          "iam:List*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "DenyBoundaryTamperingAndEscalation"
        Effect = "Deny"
        Action = [
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreateRole",
          "s3:PutBucketPublicAccessBlock"
        ]
        Resource = "*"
      }
    ]
  })
}

# 4.4 AWS Glue ETL Data Sanitization Permission Boundary
resource "aws_iam_policy" "glue_permission_boundary" {
  #checkov:skip=CKV_AWS_355: AWS Glue requires service actions across ETL assets within region
  name        = "pf-glue-permission-boundary-${var.environment}"
  description = "Scoped permissions boundary for AWS Glue ETL sanitization role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGlueETLActions"
        Effect = "Allow"
        Action = [
          "glue:Get*",
          "glue:StartJobRun",
          "glue:BatchGetJobs",
          "s3:GetObject*",
          "s3:PutObject*",
          "s3:ListBucket*",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "DenyBoundaryTamperingAndEscalation"
        Effect = "Deny"
        Action = [
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreateRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# 4.5 RDS Enhanced Monitoring Permission Boundary
resource "aws_iam_policy" "rds_monitoring_permission_boundary" {
  name        = "pf-rds-monitoring-permission-boundary-${var.environment}"
  description = "Scoped permissions boundary for Amazon RDS Enhanced Monitoring role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRDSMonitoringLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "DenyBoundaryTamperingAndEscalation"
        Effect = "Deny"
        Action = [
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreateRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# 4.6 EC2 SSM Session Manager Permission Boundary (Bastionless ClickHouse Lab)
resource "aws_iam_policy" "ssm_ec2_permission_boundary" {
  #checkov:skip=CKV_AWS_355: SSM Session Manager messaging APIs require Resource = "*" per AWS specification
  name        = "pf-ssm-ec2-permission-boundary-${var.environment}"
  description = "Scoped permissions boundary for EC2 Systems Manager Session Manager instance profile"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSSMSessionManager"
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetEndpoint",
          "ec2messages:GetMessages",
          "ec2messages:SendReply",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "DenyBoundaryTamperingAndEscalation"
        Effect = "Deny"
        Action = [
          "iam:DeleteRolePermissionsBoundary",
          "iam:CreateRole"
        ]
        Resource = "*"
      }
    ]
  })
}
