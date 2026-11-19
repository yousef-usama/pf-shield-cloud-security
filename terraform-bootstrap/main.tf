# =====================================================================================================================
# PF-SHIELD: GITHUB ACTIONS OIDC PROVIDER & BOOTSTRAP IAM ROLE
# =====================================================================================================================
# Separate bootstrap configuration provisioned once to establish secure, keyless authentication
# between GitHub Actions CI/CD workflows and AWS using OpenID Connect (OIDC).
# =====================================================================================================================

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# ---------------------------------------------------------------------------------------------------------------------
# 1. GITHUB OIDC IDENTITY PROVIDER
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github_actions" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c5860a5f6e3b5e75e82b21e15544dd740715703"
  ]

  tags = {
    Name = "github-actions-oidc-provider"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. GITHUB ACTIONS BOOTSTRAP IAM ROLE
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "github_actions" {
  name                 = var.role_name
  description          = "Bootstrap role assumed by GitHub Actions via OIDC for PF-Shield CI/CD and automated operations"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GitHubActionsOIDCAssumeRole"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = [
              "repo:${var.github_repository}:ref:refs/heads/${var.github_branch}",
              "repo:${var.github_repository}:environment:${var.github_environment}",
              "repo:${var.github_repository}:pull_request"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name = var.role_name
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. SCOPED DEPLOYMENT & TEARDOWN IAM POLICY
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_policy" "github_actions_policy" {
  #checkov:skip=CKV_AWS_288: Scoped infrastructure orchestration policy for GitHub Actions CI/CD automation
  #checkov:skip=CKV_AWS_289: IAM permission management required for Terraform role provisioning and cleanup
  #checkov:skip=CKV_AWS_290: Broad action scope required for full Terraform deployment and 1-click teardown
  #checkov:skip=CKV_AWS_355: Multiple AWS resource types do not support resource-level ARN constraints
  name        = "${var.role_name}-policy"
  description = "Allows GitHub Actions to plan, apply, and destroy PF-Shield resources in me-central-1"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformRemoteStateAccess"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::pf-shield-tfstate-*",
          "arn:aws:s3:::pf-shield-tfstate-*/*"
        ]
      },
      {
        Sid    = "TerraformStateLocking"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/pf-shield-tf-locks"
      },
      {
        Sid    = "PFShieldResourceManagement"
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "lambda:*",
          "apigateway:*",
          "events:*",
          "sns:*",
          "sqs:*",
          "kms:*",
          "wafv2:*",
          "ssm:*",
          "logs:*",
          "cloudwatch:*",
          "budgets:*",
          "ec2:Describe*",
          "ec2:CreateVpc*",
          "ec2:DeleteVpc*",
          "ec2:ModifyVpc*",
          "ec2:CreateSubnet*",
          "ec2:DeleteSubnet*",
          "ec2:ModifySubnet*",
          "ec2:CreateRoute*",
          "ec2:DeleteRoute*",
          "ec2:CreateSecurityGroup*",
          "ec2:DeleteSecurityGroup*",
          "ec2:AuthorizeSecurityGroup*",
          "ec2:RevokeSecurityGroup*",
          "ec2:CreateVpcEndpoint*",
          "ec2:DeleteVpcEndpoints",
          "ec2:ModifyVpcEndpoint*",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PassRole",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicyVersions",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:TagPolicy",
          "iam:UntagPolicy",
          "cloudtrail:*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [
              var.aws_region,
              "us-east-1"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "github_actions_attach" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions_policy.arn
}
