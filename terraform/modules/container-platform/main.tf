# =====================================================================================================================
# PF-SHIELD: CONTAINER PLATFORM & WORKLOAD RUNTIME (AMAZON ECS ON FARGATE)
# Replaces public Lambda API with hardened, non-root microservices behind Application Load Balancer
# =====================================================================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. ECR REPOSITORIES (IMMUTABLE, KMS ENCRYPTED, VULNERABILITY SCANNING ON PUSH)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_ecr_repository" "listings_api" {
  name                 = "pf-shield/listings-api-${var.environment}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = {
    Name        = "pf-shield-ecr-listings-api-${var.environment}"
    Compliance  = "CIS-AWS-Benchmark-ECR"
    Environment = var.environment
  }
}

resource "aws_ecr_repository" "broker_kyc_api" {
  name                 = "pf-shield/broker-kyc-api-${var.environment}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = {
    Name        = "pf-shield-ecr-broker-kyc-api-${var.environment}"
    Compliance  = "CIS-AWS-Benchmark-ECR"
    Environment = var.environment
  }
}

resource "aws_ecr_repository" "document_scan_worker" {
  name                 = "pf-shield/document-scan-worker-${var.environment}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = {
    Name        = "pf-shield-ecr-document-scan-worker-${var.environment}"
    Compliance  = "CIS-AWS-Benchmark-ECR"
    Environment = var.environment
  }
}

# Prune untagged or stale images after 7 days to eliminate idle storage costs
resource "aws_ecr_lifecycle_policy" "prune_policy" {
  for_each = {
    listings_api         = aws_ecr_repository.listings_api.name
    broker_kyc_api       = aws_ecr_repository.broker_kyc_api.name
    document_scan_worker = aws_ecr_repository.document_scan_worker.name
  }

  repository = each.value

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
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
  permissions_boundary = var.permission_boundary_arn

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
  permissions_boundary = var.permission_boundary_arn

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
  permissions_boundary = var.permission_boundary_arn

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

# Document Scan Worker Task Role (S3 Read/Tagging & DynamoDB Update)
resource "aws_iam_role" "document_scan_worker_task_role" {
  name                 = "pf-scan-worker-task-role-${var.environment}"
  permissions_boundary = var.permission_boundary_arn

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
      }
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. CLOUDWATCH LOG GROUPS (ENCRYPTED WITH KMS CMK, 7-DAY RETENTION)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "listings_api" {
  #checkov:skip=CKV_AWS_338: FinOps strict requirement: 7-day retention eliminates idle CloudWatch storage costs
  name              = "/ecs/pf-shield-listings-api-${var.environment}"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "broker_kyc_api" {
  #checkov:skip=CKV_AWS_338: FinOps strict requirement: 7-day retention eliminates idle CloudWatch storage costs
  name              = "/ecs/pf-shield-broker-kyc-api-${var.environment}"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "document_scan_worker" {
  #checkov:skip=CKV_AWS_338: FinOps strict requirement: 7-day retention eliminates idle CloudWatch storage costs
  name              = "/ecs/pf-shield-document-scan-worker-${var.environment}"
  retention_in_days = 7
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

# ACM Certificate for ALB HTTPS Listener
resource "aws_acm_certificate" "alb" {
  domain_name       = "api.pf-shield.internal"
  validation_method = "DNS"

  subject_alternative_names = [
    "listings.pf-shield.internal",
    "kyc.pf-shield.internal"
  ]

  tags = {
    Name = "pf-shield-alb-cert-${var.environment}"
  }

  lifecycle {
    create_before_destroy = true
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
  certificate_arn   = aws_acm_certificate.alb.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\": \"Not Found: No matching API route\"}"
      status_code  = "404"
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
}

resource "aws_lb_listener_rule" "broker_kyc_api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 200

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.broker_kyc_api.arn
  }

  condition {
    path_pattern {
      values = ["/api/v1/kyc/*"]
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 6. ECS TASK DEFINITIONS (FARGATE, READ-ONLY ROOT FS, NON-ROOT UID 10001)
# ---------------------------------------------------------------------------------------------------------------------

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
      image                  = "${aws_ecr_repository.listings_api.repository_url}:latest"
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
      image                  = "${aws_ecr_repository.broker_kyc_api.repository_url}:latest"
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
      image                  = "${aws_ecr_repository.document_scan_worker.repository_url}:latest"
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
        { name = "SNS_TOPIC_ARN", value = var.sns_topic_arn }
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

  tags = {
    Name = "pf-shield-td-document-scan-worker-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 7. ECS SERVICES (FARGATE, ZERO PUBLIC IP, DEPLOYED ACROSS PRIVATE SUBNETS)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_ecs_service" "listings_api" {
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
  max_capacity       = 10
  min_capacity       = var.ecs_desired_count
  resource_id        = "service/${aws_ecs_cluster.primary.name}/${aws_ecs_service.listings_api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "listings_api_cpu" {
  name               = "pf-listings-cpu-target-tracking"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.listings_api.resource_id
  scalable_dimension = aws_appautoscaling_target.listings_api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.listings_api.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
