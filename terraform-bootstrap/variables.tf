variable "aws_region" {
  description = "The target AWS region for deployment (locked to me-central-1 for UAE PDPL data residency)"
  type        = string
  default     = "me-central-1"
}

variable "github_repository" {
  description = "GitHub organization/repository allowed to assume the OIDC role (e.g. YousefOsama/pf-shield-cloud-security)"
  type        = string
  default     = "YousefOsama/pf-shield-cloud-security"
}

variable "github_branch" {
  description = "Protected primary GitHub branch allowed to assume the OIDC deployment role"
  type        = string
  default     = "main"
}

variable "github_environment" {
  description = "Protected GitHub environment allowed to assume the production OIDC deployment role"
  type        = string
  default     = "production"
}

variable "role_name" {
  description = "Name of the bootstrap IAM role assumed by GitHub Actions"
  type        = string
  default     = "pf-shield-github-actions-bootstrap-role"
}

variable "owner" {
  description = "Owner tag assigned to bootstrap cloud resources"
  type        = string
  default     = "YousefOsama"
}
