data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # For every IAM role ARN, construct the corresponding STS assumed-role patterns:
  # e.g., arn:aws:iam::123:role/foo -> arn:aws:sts::123:assumed-role/foo/*
  # This guarantees that both direct IAM role calls and STS assumed-role sessions
  # (including external client uploads via S3 presigned POST) are recognized by the perimeter.
  sts_assumed_role_arns = [
    for arn in var.allowed_principal_arns :
    replace(arn, "arn:aws:iam::", "arn:aws:sts::") != arn ?
    replace(replace(arn, "arn:aws:iam::", "arn:aws:sts::"), ":role/", ":assumed-role/") : arn
  ]

  sts_assumed_role_wildcards = [
    for sts_arn in local.sts_assumed_role_arns :
    can(regex(":assumed-role/", sts_arn)) ? "${sts_arn}/*" : sts_arn
  ]

  effective_allowed_arns = distinct(concat(
    [
      data.aws_caller_identity.current.arn,
      "arn:aws:iam::${local.account_id}:root"
    ],
    var.allowed_principal_arns,
    local.sts_assumed_role_arns,
    local.sts_assumed_role_wildcards
  ))
}

# ---------------------------------------------------------------------------------------------------------------------
# S3 ZERO-TRUST DATA PERIMETER BUCKET POLICY
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_s3_bucket_policy" "kyc_vault_perimeter" {
  bucket = var.bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          var.bucket_arn,
          "${var.bucket_arn}/*"
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
        Resource  = "${var.bucket_arn}/*"
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
        Resource = "${var.bucket_arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = var.s3_gateway_endpoint_id
          }
          ArnNotLike = {
            "aws:PrincipalArn" = local.effective_allowed_arns
          }
        }
      }
    ]
  })
}
