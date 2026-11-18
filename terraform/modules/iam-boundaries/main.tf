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
        Resource = "arn:aws:s3:::pf-*"
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
        Resource = "*"
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
