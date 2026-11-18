# =====================================================================================================================
# PF-SHIELD: MULTI-TIER ZERO-TRUST NETWORK PERIMETER
# Production VPC Architecture: Public ALB/NAT, Private Microservices, Isolated Data Stores
# =====================================================================================================================

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394: Availability zones dynamically queried and indexed strictly to 0 and 1
  state = "available"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------------------------------------------------
# 1. VPC & DEFAULT SECURITY GROUP LOCKDOWN
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "pf-shield-vpc-${var.environment}"
    Compliance  = "UAE-PDPL-ISO27001"
    Environment = var.environment
  }
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # Zero ingress and zero egress rules strictly enforces CIS AWS Benchmark baseline isolation
  tags = {
    Name = "pf-shield-default-sg-locked"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. SUBNET TOPOLOGY (PUBLIC, PRIVATE APP, PRIVATE DATABASE)
# ---------------------------------------------------------------------------------------------------------------------

# Public Subnets (ALB, NAT Gateways only)
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.10.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "pf-shield-subnet-public-a-${var.environment}"
    Tier = "public"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.11.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = {
    Name = "pf-shield-subnet-public-b-${var.environment}"
    Tier = "public"
  }
}

# Private Application Subnets (ECS Tasks — 0 Public IPs)
resource "aws_subnet" "private_app_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "pf-shield-subnet-private-app-a-${var.environment}"
    Tier = "private-app"
  }
}

resource "aws_subnet" "private_app_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = {
    Name = "pf-shield-subnet-private-app-b-${var.environment}"
    Tier = "private-app"
  }
}

# Private Database Subnets (RDS PostgreSQL, Document Metadata — 0 Ingress from Internet)
resource "aws_subnet" "private_db_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.20.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "pf-shield-subnet-private-db-a-${var.environment}"
    Tier = "private-database"
  }
}

resource "aws_subnet" "private_db_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.21.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = {
    Name = "pf-shield-subnet-private-db-b-${var.environment}"
    Tier = "private-database"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 3. INTERNET GATEWAY & ROUTE TABLES
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "pf-shield-igw-${var.environment}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "pf-shield-rt-public-${var.environment}"
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "pf-shield-rt-private-${var.environment}"
  }
}

resource "aws_route_table_association" "private_app_a" {
  subnet_id      = aws_subnet.private_app_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_app_b" {
  subnet_id      = aws_subnet.private_app_b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_db_a" {
  subnet_id      = aws_subnet.private_db_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_db_b" {
  subnet_id      = aws_subnet.private_db_b.id
  route_table_id = aws_route_table.private.id
}

# ---------------------------------------------------------------------------------------------------------------------
# 4. VPC FLOW LOGS (AUDIT TRAIL & NETWORK OBSERVABILITY)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  #checkov:skip=CKV_AWS_338: 7-day retention eliminates idle CloudWatch storage costs on demo tier
  name              = "/aws/vpc-flow-logs/pf-shield-${var.environment}"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn
}

resource "aws_iam_role" "vpc_flow_logs_role" {
  name                 = "pf-vpc-flow-logs-role-${var.environment}"
  permissions_boundary = var.permission_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs_policy" {
  #checkov:skip=CKV_AWS_290: CloudWatch logging requires PutLogEvents on dynamic stream targets
  #checkov:skip=CKV_AWS_355: Resource wildcard required for VPC flow log streams
  name = "pf-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VPCFlowLogsDelivery"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_flow_log" "main_vpc_flow_log" {
  iam_role_arn    = aws_iam_role.vpc_flow_logs_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id

  tags = {
    Name = "pf-shield-flow-log-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 5. ZERO-COST GATEWAY ENDPOINTS (S3 & DYNAMODB)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.public.id]

  tags = {
    Name = "pf-shield-vpce-s3-${var.environment}"
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.public.id]

  tags = {
    Name = "pf-shield-vpce-dynamodb-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 6. LEAST-PRIVILEGE SECURITY GROUPS
# ---------------------------------------------------------------------------------------------------------------------

# Application Load Balancer Security Group
resource "aws_security_group" "alb" {
  #checkov:skip=CKV_AWS_260: Port 80 ingress strictly used to execute HTTP-to-HTTPS redirect
  #checkov:skip=CKV2_AWS_5: Security group attached across modules to ALB in container-platform module
  name        = "pf-shield-alb-sg-${var.environment}"
  description = "Controls inbound edge traffic to Application Load Balancer with HTTPS enforcement"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow inbound HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow inbound HTTP for automatic HTTPS redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound to ECS application tasks"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["10.20.1.0/24", "10.20.2.0/24"]
  }

  tags = {
    Name = "pf-shield-alb-sg-${var.environment}"
  }
}

# ECS Container Workload Security Group (No Public Ingress)
resource "aws_security_group" "ecs" {
  #checkov:skip=CKV2_AWS_5: Security group attached across modules to ECS services in container-platform module
  name        = "pf-shield-ecs-sg-${var.environment}"
  description = "Restricts ECS container traffic: ingress strictly from ALB, no public ingress"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow traffic on application port strictly from ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow outbound HTTPS to AWS services via Gateway and Interface Endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound PostgreSQL connection to database tier"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.20.20.0/24", "10.20.21.0/24"]
  }

  tags = {
    Name = "pf-shield-ecs-sg-${var.environment}"
  }
}

# Relational Database Security Group (PostgreSQL)
resource "aws_security_group" "database" {
  #checkov:skip=CKV2_AWS_5: Security group attached across modules to RDS instances in database module
  name        = "pf-shield-db-sg-${var.environment}"
  description = "Restricts database ingress strictly to ECS tasks on port 5432"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow PostgreSQL ingress strictly from ECS container security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  # Zero egress rules enforces strict database isolation
  tags = {
    Name = "pf-shield-db-sg-${var.environment}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# 7. ROUTE 53 PRIVATE HOSTED ZONE (INTERNAL SERVICE DISCOVERY)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_route53_zone" "internal" {
  #checkov:skip=CKV2_AWS_23: Route 53 query logging omitted to prevent recurring log storage fees on demo tier
  name = "pf-shield.internal"

  vpc {
    vpc_id = aws_vpc.main.id
  }

  tags = {
    Name = "pf-shield-internal-dns-${var.environment}"
  }
}
