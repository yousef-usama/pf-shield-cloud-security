# =====================================================================================================================
# TERRAFORM REMOTE STATE S3 BACKEND CONFIGURATION
# =====================================================================================================================
# Pre-requisite: S3 bucket and DynamoDB locking table must be bootstrapped via:
#   ./scripts/bootstrap-remote-state.sh
# Or manual AWS CLI commands documented in the README.
#
# To initialize with remote state in production:
#   terraform init -backend-config="bucket=<YOUR_BOOTSTRAPPED_BUCKET>"
#
# For local validation / CI testing without live AWS credentials:
#   terraform init -backend=false
# =====================================================================================================================

terraform {
  backend "s3" {
    bucket         = "pf-shield-tfstate-339712755065"
    key            = "pf-shield/prod-sim/terraform.tfstate"
    region         = "me-central-1"
    dynamodb_table = "pf-shield-tf-locks"
    encrypt        = true
  }
}
