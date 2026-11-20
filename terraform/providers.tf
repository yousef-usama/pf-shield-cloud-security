terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project            = "PF-Shield"
      Environment        = var.environment
      ManagedBy          = "Terraform"
      CostCenter         = "PF-Cloud-Security"
      DataClassification = "Restricted-UAE-PDPL"
      Owner              = var.owner
    }
  }
}

# Dedicated US-East-1 AWS Provider for CloudFront Edge ACM Certificates
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project            = "PF-Shield"
      Environment        = var.environment
      ManagedBy          = "Terraform"
      CostCenter         = "PF-Cloud-Security"
      DataClassification = "Restricted-UAE-PDPL"
      Owner              = var.owner
    }
  }
}

# Dedicated EU-Central-1 AWS Provider for Cross-Region Cognito & ECR Services
provider "aws" {
  alias  = "eu_central_1"
  region = "eu-central-1"

  default_tags {
    tags = {
      Project            = "PF-Shield"
      Environment        = var.environment
      ManagedBy          = "Terraform"
      CostCenter         = "PF-Cloud-Security"
      DataClassification = "Restricted-UAE-PDPL"
      Owner              = var.owner
    }
  }
}

locals {
  # Documentation of verified regional service availability between UAE (me-central-1) and Bahrain (me-south-1).
  # Used to document architectural trade-offs and provide regional verification rationale.
  regional_service_availability_matrix = {
    primary_region  = var.aws_region
    fallback_region = var.fallback_region
    capabilities = {
      s3_gateway_endpoints       = "me-central-1 (verified $0.00 cost)"
      dynamodb_gateway_endpoints = "me-central-1 (verified $0.00 cost)"
      kms_cmk_encryption         = "me-central-1 (active)"
      lambda_arm64_graviton2     = "me-central-1 (active)"
      api_gateway_http_api       = "me-central-1 (active)"
      eventbridge_rules          = "me-central-1 (active)"
      ssm_parameter_store        = "me-central-1 (active)"
      cloudwatch_dashboards      = "me-central-1 (active)"
      guardduty_s3_protection    = "me-central-1 / me-south-1 fallback"
      security_hub_standards     = "me-central-1 / me-south-1 fallback"
      wafv2_regional_webacl      = "me-central-1 / me-south-1 fallback"
    }
  }
}
