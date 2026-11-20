terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project            = "PF-Shield"
      Environment        = "Bootstrap"
      ManagedBy          = "Terraform"
      CostCenter         = "PF-Cloud-Security"
      DataClassification = "Restricted-UAE-PDPL"
      Owner              = var.owner
    }
  }
}

provider "aws" {
  alias  = "ecr"
  region = var.ecr_region

  default_tags {
    tags = {
      Project            = "PF-Shield"
      Environment        = "Bootstrap"
      ManagedBy          = "Terraform"
      CostCenter         = "PF-Cloud-Security"
      DataClassification = "Restricted-UAE-PDPL"
      Owner              = var.owner
    }
  }
}
