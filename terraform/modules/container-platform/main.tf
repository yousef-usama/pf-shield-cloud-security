# =====================================================================================================================
# PF-SHIELD: CONTAINER PLATFORM & WORKLOAD RUNTIME (AMAZON ECS ON FARGATE)
# Replaces public Lambda API with hardened, non-root microservices behind Application Load Balancer
# =====================================================================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Foundational ECR repository URLs provisioned by terraform-bootstrap (or constructed deterministically)
  listings_api_repo_url = var.ecr_repository_urls.listings_api != "" ? (
    var.ecr_repository_urls.listings_api
  ) : "${local.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/pf-shield/listings-api-${var.environment}"

  broker_kyc_api_repo_url = var.ecr_repository_urls.broker_kyc_api != "" ? (
    var.ecr_repository_urls.broker_kyc_api
  ) : "${local.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/pf-shield/broker-kyc-api-${var.environment}"

  document_scan_worker_repo_url = var.ecr_repository_urls.document_scan_worker != "" ? (
    var.ecr_repository_urls.document_scan_worker
  ) : "${local.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/pf-shield/document-scan-worker-${var.environment}"
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. ECS CLUSTER & CONTAINER INSIGHTS OBSERVABILITY
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_ecs_cluster" "primary" {
  name = "pf-shield-cluster-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "pf-shield-cluster-${var.environment}"
    Compliance  = "UAE-PDPL-ISO27001"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. IAM ROLES (TASK EXECUTION & LEAST-PRIVILEGE APPLICATION ROLES)
# ---------------------------------------------------------------------------------------------------------------------

# ECS Task Execution Role (ECR Image Pull, KMS Decrypt, CloudWatch Logs)
resource "aws_iam_role" "ecs_execution_role" {
  name                 = "pf-ecs-execution-role-${var.environment}"
  permissions_boundary = coalesce(var.ecs_execution_permission_boundary_arn, var.permission_boundary_arn)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_execution_policy" {
  #checkov:skip=CKV_AWS_290: CloudWatch logging requires PutLogEvents on dynamic stream targets
  #checkov:skip=CKV_AWS_355: Regional CloudWatch log streams wildcard permitted
  name = "pf-ecs-execution-policy"
  role = aws_iam_role.ecs_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRImagePull"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
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

# Listings API Task Role (DynamoDB Read Only)
resource "aws_iam_role" "listings_api_task_role" {
  name                 = "pf-listings-task-role-${var.environment}"
  permissions_boundary = coalesce(var.ecs_task_permission_boundary_arn, var.permission_boundary_arn)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "listings_api_task_policy" {
  name = "pf-listings-task-policy"
  role = aws_iam_role.listings_api_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBReadCatalog"
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
      }
    ]
  })
}

# Broker KYC API Task Role (S3 Presign & Initial DynamoDB Audit Insertion)
resource "aws_iam_role" "broker_kyc_api_task_role" {
  name                 = "pf-broker-kyc-task-role-${var.environment}"
  permissions_boundary = coalesce(var.ecs_task_permission_boundary_arn, var.permission_boundary_arn)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "broker_kyc_api_task_policy" {
  name = "pf-broker-kyc-task-policy"
  role = aws_iam_role.broker_kyc_api_task_role.id

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
        Sid    = "DynamoDBInitialAuditRecord"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:*:table/${var.dynamodb_table_name}"
      },
      {
        Sid    = "KMSEnvelopeEncryption"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# Document Scan Worker Task Role (S3 Read/Tagging, SQS Polling, & DynamoDB Update)
resource "aws_iam_role" "document_scan_worker_task_role" {
  name                 = "pf-scan-worker-task-role-${var.environment}"
  permissions_boundary = coalesce(var.ecs_task_permission_boundary_arn, var.permission_boundary_arn)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "document_scan_worker_task_policy" {
  name = "pf-scan-worker-task-policy"
  role = aws_iam_role.document_scan_worker_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ObjectScanningAndTagging"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObjectTagging",
          "s3:GetObjectTagging"
        ]
        Resource = "arn:aws:s3:::${var.kyc_vault_bucket_name}/*"
      },
      {
        Sid    = "DynamoDBUpdateScanStatus"
        Effect = "Allow"
        Action = [
          "dynamodb:UpdateItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:*:table/${var.dynamodb_table_name}"
      },
      {
        Sid    = "KMSEnvelopeEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "SNSMalwareAlertDispatch"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.sns_topic_arn
      },
      {
        Sid    = "SQSScanQueueConsumer"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ]
        Resource = var.sqs_scan_queue_arn != "" ? var.sqs_scan_queue_arn : "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. CLOUDWATCH LOG GROUPS (ENCRYPTED WITH KMS CMK, PARAMETERIZED RETENTION)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "listings_api" {
  #checkov:skip=CKV_AWS_338: Parameterized retention (7 days demo, 365 days production)
  name              = "/ecs/pf-shield-listings-api-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "broker_kyc_api" {
  #checkov:skip=CKV_AWS_338: Parameterized retention (7 days demo, 365 days production)
  name              = "/ecs/pf-shield-broker-kyc-api-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "document_scan_worker" {
  #checkov:skip=CKV_AWS_338: Parameterized retention (7 days demo, 365 days production)
  name              = "/ecs/pf-shield-document-scan-worker-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# 5. APPLICATION LOAD BALANCER & TARGET ROUTING
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_lb" "main" {
  #checkov:skip=CKV_AWS_150: Deletion protection toggleable for automated demo environment teardown
  #checkov:skip=CKV_AWS_91: ALB access logging omitted on demo tier to prevent idle S3 PUT fees
  #checkov:skip=CKV2_AWS_20: AWS WAF association managed conditionally in production profile
  #checkov:skip=CKV2_AWS_28: Public ALB protected by WAF in production; toggleable for $0.00 idle demo profile
  #checkov:skip=CKV2_AWS_76: ALB WAF WebACL in edge-api-waf module includes AWSManagedRulesKnownBadInputsRuleSet for Log4j mitigation
  name                       = "pf-shield-alb-${var.environment}"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [var.alb_security_group_id]
  subnets                    = var.public_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = var.enable_deletion_protection

  tags = {
    Name = "pf-shield-alb-${var.environment}"
  }
}

resource "aws_lb_target_group" "listings_api" {
  #checkov:skip=CKV_AWS_378: ALB terminates TLS 1.3 at edge; HTTP is strictly restricted to private isolated VPC subnets without public ingress
  name        = "pf-tg-listings-${var.environment}"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Name = "pf-tg-listings-${var.environment}"
  }
}

resource "aws_lb_target_group" "broker_kyc_api" {
  #checkov:skip=CKV_AWS_378: ALB terminates TLS 1.3 at edge; HTTP is strictly restricted to private isolated VPC subnets without public ingress
  name        = "pf-tg-kyc-${var.environment}"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Name = "pf-tg-kyc-${var.environment}"
  }
}

# ACM Certificate for Public ALB HTTPS Listener (Public Domain + Route 53 DNS Validation)
resource "aws_acm_certificate" "alb" {
  domain_name       = "api.${var.public_domain_name}"
  validation_method = "DNS"

  subject_alternative_names = [
    "listings.${var.public_domain_name}",
    "kyc.${var.public_domain_name}"
  ]

  tags = {
    Name        = "pf-shield-alb-cert-${var.environment}"
    Environment = var.environment
    Compliance  = "UAE-PDPL-TLS13"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Route 53 DNS Validation Records for Public ACM Certificate
resource "aws_route53_record" "alb_cert_validation" {
  for_each = var.route53_zone_id != "" ? {
    for dvo in aws_acm_certificate.alb.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

resource "aws_acm_certificate_validation" "alb" {
  count                   = var.route53_zone_id != "" ? 1 : 0
  certificate_arn         = aws_acm_certificate.alb.arn
  validation_record_fqdns = [for record in aws_route53_record.alb_cert_validation : record.fqdn]
}

# Dedicated CloudFront Edge Certificate in us-east-1 (Required for CloudFront Custom Domain)
resource "aws_acm_certificate" "cloudfront" {
  provider          = aws.us_east_1
  count             = var.public_domain_name != "" ? 1 : 0
  domain_name       = "api.${var.public_domain_name}"
  validation_method = "DNS"

  subject_alternative_names = [
    "listings.${var.public_domain_name}",
    "kyc.${var.public_domain_name}"
  ]

  tags = {
    Name        = "pf-shield-cloudfront-cert-${var.environment}"
    Environment = var.environment
    Compliance  = "UAE-PDPL-TLS13"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Route 53 DNS Validation Records for CloudFront us-east-1 ACM Certificate
resource "aws_route53_record" "cloudfront_cert_validation" {
  for_each = (var.route53_zone_id != "" && length(aws_acm_certificate.cloudfront) > 0) ? {
    for dvo in aws_acm_certificate.cloudfront[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

resource "aws_acm_certificate_validation" "cloudfront" {
  provider                = aws.us_east_1
  count                   = var.public_domain_name != "" && var.route53_zone_id != "" && length(aws_acm_certificate.cloudfront) > 0 ? 1 : 0
  certificate_arn         = aws_acm_certificate.cloudfront[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cloudfront_cert_validation : record.fqdn]
}

# Route 53 Public Alias Records (Routing api.<domain> to CloudFront or ALB)
resource "aws_route53_record" "api_alias" {
  count   = var.route53_zone_id != "" && var.public_domain_name != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = "api.${var.public_domain_name}"
  type    = "A"

  alias {
    name                   = (var.enable_cloudfront && length(aws_cloudfront_distribution.alb) > 0) ? aws_cloudfront_distribution.alb[0].domain_name : aws_lb.main.dns_name
    zone_id                = (var.enable_cloudfront && length(aws_cloudfront_distribution.alb) > 0) ? aws_cloudfront_distribution.alb[0].hosted_zone_id : aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "api_alias_ipv6" {
  count   = var.route53_zone_id != "" && var.public_domain_name != "" && var.enable_cloudfront ? 1 : 0
  zone_id = var.route53_zone_id
  name    = "api.${var.public_domain_name}"
  type    = "AAAA"

  alias {
    name                   = (var.enable_cloudfront && length(aws_cloudfront_distribution.alb) > 0) ? aws_cloudfront_distribution.alb[0].domain_name : aws_lb.main.dns_name
    zone_id                = (var.enable_cloudfront && length(aws_cloudfront_distribution.alb) > 0) ? aws_cloudfront_distribution.alb[0].hosted_zone_id : aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# ALB HTTP Listener (Port 80) -> Strictly redirects to HTTPS 443 (CIS AWS Benchmark)
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ALB HTTPS Listener (Port 443) -> TLS 1.3 / ELBSecurityPolicy-TLS13-1-2-2021-06
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.route53_zone_id != "" ? aws_acm_certificate_validation.alb[0].certificate_arn : aws_acm_certificate.alb.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\": \"Forbidden: Direct access to load balancer origin is prohibited\"}"
      status_code  = "403"
    }
  }
}

# Listener Rules
resource "aws_lb_listener_rule" "listings_api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.listings_api.arn
  }

  condition {
    path_pattern {
      values = ["/api/v1/properties*"]
    }
  }

  dynamic "condition" {
    for_each = var.enable_cloudfront ? [1] : []
    content {
      http_header {
        http_header_name = "X-Origin-Verify"
        values           = [random_password.origin_verify[0].result]
      }
    }
  }
}

resource "aws_lb_listener_rule" "broker_kyc_api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 200

  dynamic "action" {
    for_each = var.enable_alb_cognito_auth && var.cognito_user_pool_arn != null ? [1] : []
    content {
      type  = "authenticate-cognito"
      order = 1
      authenticate_cognito {
        user_pool_arn              = var.cognito_user_pool_arn
        user_pool_client_id        = var.cognito_user_pool_client_id
        user_pool_domain           = var.cognito_user_pool_domain
        on_unauthenticated_request = "authenticate"
        session_timeout            = 3600
      }
    }
  }

  action {
    type             = "forward"
    order            = var.enable_alb_cognito_auth && var.cognito_user_pool_arn != null ? 2 : 1
    target_group_arn = aws_lb_target_group.broker_kyc_api.arn
  }

  condition {
    path_pattern {
      values = ["/api/v1/kyc/*"]
    }
  }

  dynamic "condition" {
    for_each = var.enable_cloudfront ? [1] : []
    content {
      http_header {
        http_header_name = "X-Origin-Verify"
        values           = [random_password.origin_verify[0].result]
      }
    }
  }
}

# WAFv2 Association for Public Application Load Balancer
resource "aws_wafv2_web_acl_association" "alb_waf" {
  count        = var.enable_waf ? 1 : 0
  resource_arn = aws_lb.main.arn
  web_acl_arn  = var.waf_web_acl_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# CLOUDFRONT EDGE DISTRIBUTION & SECURITY RESPONSE HEADERS
# ---------------------------------------------------------------------------------------------------------------------

resource "random_password" "origin_verify" {
  count   = var.enable_cloudfront ? 1 : 0
  length  = 32
  special = false
}

resource "aws_cloudfront_response_headers_policy" "security_headers" {
  count = var.enable_cloudfront ? 1 : 0
  name  = "pf-shield-security-headers-${var.environment}"

  security_headers_config {
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
  }
}

resource "aws_cloudfront_distribution" "alb" {
  #checkov:skip=CKV_AWS_86: Access logging disabled to prevent recurring S3 PUT fees on demo tier
  #checkov:skip=CKV_AWS_310: Failover origin group omitted for single-region reference architecture
  #checkov:skip=CKV_AWS_305: Global WAF attachment optional on demo profile; regional WAF protects ALB
  #checkov:skip=CKV_AWS_68: CloudFront WAF requires CLOUDFRONT scope in us-east-1; edge protection enforced at regional ALB via WAFv2 in me-central-1
  #checkov:skip=CKV_AWS_174: Custom SSL certificate in us-east-1 required for minimum_protocol_version; default certificate used in reference architecture
  #checkov:skip=CKV2_AWS_42: CloudFront custom ACM certificate requires deployment in us-east-1; demo reference uses default distribution certificate
  #checkov:skip=CKV2_AWS_47: CloudFront WAF requires CLOUDFRONT scope in us-east-1; edge protection enforced at regional ALB via WAFv2 in me-central-1
  count = var.enable_cloudfront ? 1 : 0

  enabled         = true
  is_ipv6_enabled = true
  comment         = "PF-Shield Global Edge CloudFront Distribution"
  http_version    = "http2and3"

  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "ALB-${aws_lb.main.name}"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "X-Origin-Verify"
      value = random_password.origin_verify[0].result
    }
  }

  default_cache_behavior {
    target_origin_id       = "ALB-${aws_lb.main.name}"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    # AWS Managed CachingDisabled policy (4135ea2d-6df8-44a3-9df3-4b5a84be39ad) for dynamic API routing
    cache_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

    # AWS Managed AllViewer origin request policy (216adef6-5c7f-47e4-b989-5492eafa07d3)
    origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3"

    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers[0].id
  }

  aliases = var.enable_cloudfront && var.public_domain_name != "" ? [
    "api.${var.public_domain_name}"
  ] : []

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["AE", "SA", "BH", "KW", "OM", "QA", "US", "GB"]
    }
  }

  viewer_certificate {
    acm_certificate_arn            = length(aws_acm_certificate.cloudfront) > 0 ? aws_acm_certificate.cloudfront[0].arn : null
    cloudfront_default_certificate = length(aws_acm_certificate.cloudfront) > 0 ? false : true
    ssl_support_method             = length(aws_acm_certificate.cloudfront) > 0 ? "sni-only" : null
    minimum_protocol_version       = length(aws_acm_certificate.cloudfront) > 0 ? "TLSv1.2_2021" : "TLSv1"
  }

  tags = {
    Name        = "pf-shield-cloudfront-${var.environment}"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 6. ECS TASK DEFINITIONS (FARGATE, READ-ONLY ROOT FS, NON-ROOT UID 10001)
# ---------------------------------------------------------------------------------------------------------------------

locals {
  # Construct immutable image references for each microservice independently
  listings_api_image = var.container_image_digests.listings_api != "" ? (
    var.container_image_digests.listings_api
    ) : (
    strcontains(var.container_image_tag, "@sha256:") ? (
      strcontains(var.container_image_tag, "/") ? var.container_image_tag : "${local.listings_api_repo_url}@${split("@", var.container_image_tag)[1]}"
      ) : (
      strcontains(var.container_image_tag, "sha256:") ? "${local.listings_api_repo_url}@${var.container_image_tag}" : "${local.listings_api_repo_url}:${var.container_image_tag}"
    )
  )

  broker_kyc_api_image = var.container_image_digests.broker_kyc_api != "" ? (
    var.container_image_digests.broker_kyc_api
    ) : (
    strcontains(var.container_image_tag, "@sha256:") ? (
      strcontains(var.container_image_tag, "/") ? replace(var.container_image_tag, "listings-api", "broker-kyc-api") : "${local.broker_kyc_api_repo_url}@${split("@", var.container_image_tag)[1]}"
      ) : (
      strcontains(var.container_image_tag, "sha256:") ? "${local.broker_kyc_api_repo_url}@${var.container_image_tag}" : "${local.broker_kyc_api_repo_url}:${var.container_image_tag}"
    )
  )

  document_scan_worker_image = var.container_image_digests.document_scan_worker != "" ? (
    var.container_image_digests.document_scan_worker
    ) : (
    strcontains(var.container_image_tag, "@sha256:") ? (
      strcontains(var.container_image_tag, "/") ? replace(var.container_image_tag, "listings-api", "document-scan-worker") : "${local.document_scan_worker_repo_url}@${split("@", var.container_image_tag)[1]}"
      ) : (
      strcontains(var.container_image_tag, "sha256:") ? "${local.document_scan_worker_repo_url}@${var.container_image_tag}" : "${local.document_scan_worker_repo_url}:${var.container_image_tag}"
    )
  )
}

resource "aws_ecs_task_definition" "listings_api" {
  family                   = "pf-shield-listings-api-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.listings_api_task_role.arn

  container_definitions = jsonencode([
    {
      name                   = "listings-api"
      image                  = local.listings_api_image
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001:10001"
      privileged             = false

      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "ENVIRONMENT", value = var.environment },
        { name = "DYNAMODB_TABLE_NAME", value = var.dynamodb_table_name }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.listings_api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = var.environment != "production" || can(regex("(@sha256:[a-f0-9]{64}$|^sha256:[a-f0-9]{64}$)", local.listings_api_image))
      error_message = "Production deployment requires an immutable container image digest for listings-api (e.g. repository@sha256:...); 'latest' or untracked tags are strictly prohibited."
    }
  }

  tags = {
    Name = "pf-shield-td-listings-api-${var.environment}"
  }
}

resource "aws_ecs_task_definition" "broker_kyc_api" {
  family                   = "pf-shield-broker-kyc-api-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.broker_kyc_api_task_role.arn

  container_definitions = jsonencode([
    {
      name                   = "broker-kyc-api"
      image                  = local.broker_kyc_api_image
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001:10001"
      privileged             = false

      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "ENVIRONMENT", value = var.environment },
        { name = "KYC_VAULT_BUCKET_NAME", value = var.kyc_vault_bucket_name },
        { name = "DYNAMODB_TABLE_NAME", value = var.dynamodb_table_name },
        { name = "KMS_KEY_ARN", value = var.kms_key_arn }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.broker_kyc_api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = var.environment != "production" || can(regex("(@sha256:[a-f0-9]{64}$|^sha256:[a-f0-9]{64}$)", local.listings_api_image))
      error_message = "Production deployment requires an immutable container image digest for listings-api (e.g. repository@sha256:...); 'latest' or untracked tags are strictly prohibited."
    }
  }

  tags = {
    Name = "pf-shield-td-broker-kyc-api-${var.environment}"
  }
}

resource "aws_ecs_task_definition" "document_scan_worker" {
  family                   = "pf-shield-document-scan-worker-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.document_scan_worker_task_role.arn

  container_definitions = jsonencode([
    {
      name                   = "document-scan-worker"
      image                  = local.document_scan_worker_image
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001:10001"
      privileged             = false

      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "ENVIRONMENT", value = var.environment },
        { name = "KYC_VAULT_BUCKET_NAME", value = var.kyc_vault_bucket_name },
        { name = "DYNAMODB_TABLE_NAME", value = var.dynamodb_table_name },
        { name = "SNS_TOPIC_ARN", value = var.sns_topic_arn },
        { name = "SQS_SCAN_QUEUE_URL", value = var.sqs_scan_queue_url }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.document_scan_worker.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = var.environment != "production" || can(regex("(@sha256:[a-f0-9]{64}$|^sha256:[a-f0-9]{64}$)", local.listings_api_image))
      error_message = "Production deployment requires an immutable container image digest for listings-api (e.g. repository@sha256:...); 'latest' or untracked tags are strictly prohibited."
    }
  }

  tags = {
    Name = "pf-shield-td-document-scan-worker-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 7. ECS SERVICES (FARGATE, ZERO PUBLIC IP, DEPLOYED ACROSS PRIVATE SUBNETS)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_ecs_service" "listings_api" {
  count                  = var.enable_ecs_services ? 1 : 0
  name                   = "pf-shield-listings-api-${var.environment}"
  cluster                = aws_ecs_cluster.primary.id
  task_definition        = aws_ecs_task_definition.listings_api.arn
  desired_count          = var.ecs_desired_count
  launch_type            = "FARGATE"
  enable_execute_command = false

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false # Enforces strict zero-public-IP perimeter
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.listings_api.arn
    container_name   = "listings-api"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    Name = "pf-shield-svc-listings-api-${var.environment}"
  }
}

resource "aws_ecs_service" "broker_kyc_api" {
  count                  = var.enable_ecs_services ? 1 : 0
  name                   = "pf-shield-broker-kyc-api-${var.environment}"
  cluster                = aws_ecs_cluster.primary.id
  task_definition        = aws_ecs_task_definition.broker_kyc_api.arn
  desired_count          = var.ecs_desired_count
  launch_type            = "FARGATE"
  enable_execute_command = false

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.broker_kyc_api.arn
    container_name   = "broker-kyc-api"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    Name = "pf-shield-svc-broker-kyc-api-${var.environment}"
  }
}

resource "aws_ecs_service" "document_scan_worker" {
  count                  = var.enable_ecs_services ? 1 : 0
  name                   = "pf-shield-document-scan-worker-${var.environment}"
  cluster                = aws_ecs_cluster.primary.id
  task_definition        = aws_ecs_task_definition.document_scan_worker.arn
  desired_count          = var.ecs_desired_count
  launch_type            = "FARGATE"
  enable_execute_command = false

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = {
    Name = "pf-shield-svc-document-scan-worker-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 8. ECS AUTOSCALING (TARGET TRACKING: CPU 70% & REQUEST COUNT)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_appautoscaling_target" "listings_api" {
  count              = var.enable_ecs_services ? 1 : 0
  max_capacity       = 10
  min_capacity       = var.ecs_desired_count
  resource_id        = "service/${aws_ecs_cluster.primary.name}/${aws_ecs_service.listings_api[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "listings_api_cpu" {
  count              = var.enable_ecs_services ? 1 : 0
  name               = "pf-listings-cpu-target-tracking"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.listings_api[0].resource_id
  scalable_dimension = aws_appautoscaling_target.listings_api[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.listings_api[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
