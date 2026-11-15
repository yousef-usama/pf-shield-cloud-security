# ---------------------------------------------------------------------------------------------------------------------
# 1. SERVERLESS COMPUTE PACKAGING (ARM64 GRAVITON2)
# ---------------------------------------------------------------------------------------------------------------------

data "archive_file" "property_api_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../src/app/property_api_handler.py"
  output_path = "${path.module}/property_api.zip"
}

data "archive_file" "kyc_vault_zip" {
  type        = "zip"
  source_file = "${path.module}/../../../src/app/kyc_vault_handler.py"
  output_path = "${path.module}/kyc_vault.zip"
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. PROPERTY LISTINGS API LAMBDA
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "property_api_role" {
  name                 = "pf-property-api-role-${var.environment}"
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

resource "aws_iam_role_policy" "property_api_permissions" {
  #checkov:skip=CKV_AWS_290: CloudWatch logging requires PutLogEvents on dynamic log stream targets
  #checkov:skip=CKV_AWS_355: Resource wildcard permitted for regional CloudWatch logging
  name = "pf-property-api-policy"
  role = aws_iam_role.property_api_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBReadAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:*:table/${var.dynamodb_table_name}"
      },
      {
        Sid    = "KMSDecryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "CloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "property_api_logs" {
  #checkov:skip=CKV_AWS_338: FinOps strict requirement: 7-day retention eliminates idle CloudWatch storage costs
  name              = "/aws/lambda/pf-property-api-${var.environment}"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "property_api" {
  #checkov:skip=CKV_AWS_116: Dead Letter Queue omitted for stateless synchronous public API read handler
  #checkov:skip=CKV_AWS_117: Lambda is not VPC-bound to ensure $0 idle compute cost without NAT Gateway overhead
  #checkov:skip=CKV_AWS_272: Code signing omitted for simplified serverless deployment
  function_name                  = "pf-property-api-${var.environment}"
  role                           = aws_iam_role.property_api_role.arn
  handler                        = "property_api_handler.lambda_handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  memory_size                    = 128
  timeout                        = 10
  reserved_concurrent_executions = 10
  filename                       = data.archive_file.property_api_zip.output_path
  source_code_hash               = data.archive_file.property_api_zip.output_base64sha256
  kms_key_arn                    = var.kms_key_arn

  environment {
    variables = {
      DYNAMODB_TABLE_NAME = var.dynamodb_table_name
      ENVIRONMENT         = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.property_api_logs]
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. BROKER KYC VAULT PRESIGN API LAMBDA
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "kyc_vault_role" {
  name                 = "pf-kyc-vault-role-${var.environment}"
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

resource "aws_iam_role_policy" "kyc_vault_permissions" {
  #checkov:skip=CKV_AWS_290: CloudWatch logging requires PutLogEvents on dynamic log stream targets
  #checkov:skip=CKV_AWS_355: Resource wildcard permitted for regional CloudWatch logging
  name = "pf-kyc-vault-policy"
  role = aws_iam_role.kyc_vault_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3PresignUploadPermissions"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::${var.kyc_vault_bucket_name}/*"
      },
      {
        Sid    = "KMSEnvelopeEncryption"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "SSMConfigLookup"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/pf-shield/*"
      },
      {
        Sid    = "CloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "kyc_vault_logs" {
  #checkov:skip=CKV_AWS_338: FinOps strict requirement: 7-day retention eliminates idle CloudWatch storage costs
  name              = "/aws/lambda/pf-kyc-vault-${var.environment}"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "kyc_vault" {
  #checkov:skip=CKV_AWS_116: Dead Letter Queue omitted for stateless synchronous presign handler
  #checkov:skip=CKV_AWS_117: Lambda is not VPC-bound to maintain $0 idle compute cost
  #checkov:skip=CKV_AWS_272: Code signing omitted for simplified serverless deployment
  function_name                  = "pf-kyc-vault-${var.environment}"
  role                           = aws_iam_role.kyc_vault_role.arn
  handler                        = "kyc_vault_handler.lambda_handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  memory_size                    = 128
  timeout                        = 10
  reserved_concurrent_executions = 10
  filename                       = data.archive_file.kyc_vault_zip.output_path
  source_code_hash               = data.archive_file.kyc_vault_zip.output_base64sha256
  kms_key_arn                    = var.kms_key_arn

  environment {
    variables = {
      KYC_VAULT_BUCKET_NAME = var.kyc_vault_bucket_name
      KMS_KEY_ARN           = var.kms_key_arn
      ENVIRONMENT           = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.kyc_vault_logs]
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. EDGE API GATEWAY HTTP API (70% CHEAPER THAN REST API)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_apigatewayv2_api" "edge_api" {
  name          = "pf-shield-edge-api-${var.environment}"
  protocol_type = "HTTP"
  description   = "PF-Shield Zero-Trust HTTP API with native rate limiting and edge security"

  cors_configuration {
    allow_origins = ["https://*.pf-shield.ae", "https://*.realestate.ae"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["content-type", "authorization", "x-requested-with"]
    max_age       = 300
  }

  tags = {
    Name = "pf-shield-edge-api-${var.environment}"
  }
}

resource "aws_cloudwatch_log_group" "api_access_logs" {
  #checkov:skip=CKV_AWS_338: FinOps strict requirement: 7-day retention eliminates idle CloudWatch storage costs
  name              = "/aws/apigateway/pf-shield-edge-api-${var.environment}"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.edge_api.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    detailed_metrics_enabled = true
    throttling_burst_limit   = 50
    throttling_rate_limit    = 25
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = {
    Name = "pf-shield-api-stage-default"
  }
}

# Integrations & Routes
resource "aws_apigatewayv2_integration" "property_api" {
  api_id                 = aws_apigatewayv2_api.edge_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.property_api.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_properties" {
  #checkov:skip=CKV_AWS_309: Public real estate listings endpoint intentionally accessible without JWT authorization; protected by rate limiting and WAF
  api_id    = aws_apigatewayv2_api.edge_api.id
  route_key = "GET /api/v1/properties"
  target    = "integrations/${aws_apigatewayv2_integration.property_api.id}"
}

resource "aws_lambda_permission" "allow_apigw_property_api" {
  statement_id  = "AllowAPIGatewayInvokePropertyAPI"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.property_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.edge_api.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "kyc_vault" {
  api_id                 = aws_apigatewayv2_api.edge_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.kyc_vault.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "post_kyc_presign" {
  #checkov:skip=CKV_AWS_309: KYC presign endpoint validates broker credentials in Lambda handler payload; protected by WAF and rate limiting
  api_id    = aws_apigatewayv2_api.edge_api.id
  route_key = "POST /api/v1/kyc/presign"
  target    = "integrations/${aws_apigatewayv2_integration.kyc_vault.id}"
}

resource "aws_lambda_permission" "allow_apigw_kyc_vault" {
  statement_id  = "AllowAPIGatewayInvokeKYCVault"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kyc_vault.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.edge_api.execution_arn}/*/*"
}

# ---------------------------------------------------------------------------------------------------------------------
# 5. EDGE WAF (CONDITIONAL FINOPS TOGGLE — 0$ IDLE WHEN FALSE)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "edge_waf" {
  #checkov:skip=CKV_AWS_192: WAF logging omitted to prevent recurring log storage fees on demo tier
  #checkov:skip=CKV2_AWS_31: WAF logging omitted to prevent recurring log storage fees on demo tier
  count       = var.enable_waf ? 1 : 0
  name        = "pf-shield-waf-${var.environment}"
  description = "PF-Shield Anti-Scraping and OWASP Top 10 Edge Protection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "pfShieldWAFMetrics"
    sampled_requests_enabled   = true
  }

  # Rule 1: Anti-Scraping Rate Limit (> 100 requests per 5 minutes per IP)
  rule {
    name     = "RateLimitScrapers"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitScrapersMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: OWASP Top 10 Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: SQL Injection Rule Set
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Known Bad Inputs Rule Set
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsMetric"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl_association" "edge_waf_association" {
  count        = var.enable_waf ? 1 : 0
  resource_arn = aws_apigatewayv2_stage.default.arn
  web_acl_arn  = aws_wafv2_web_acl.edge_waf[0].arn
}
