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
        Sid       = "EmergencyQuarantineDenyAll"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
      }
    ]
  })
}
