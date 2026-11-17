#!/usr/bin/env bash
# =====================================================================================================================
# PF-SHIELD: TERRAFORM REMOTE STATE BOOTSTRAP SCRIPT
# =====================================================================================================================
# Creates the S3 bucket and DynamoDB locking table outside Terraform to avoid the chicken-and-egg problem.
#
# Prerequisite: AWS CLI configured with administrator permissions.
# Usage:
#   ./scripts/bootstrap-remote-state.sh [AWS_REGION] [BUCKET_NAME] [DYNAMODB_TABLE]
# =====================================================================================================================

set -euo pipefail

# Color palette
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

AWS_REGION="${1:-${AWS_REGION:-"me-central-1"}}"
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text 2>/dev/null || echo "demo-account")
BUCKET_NAME="${2:-${TF_STATE_BUCKET:-"pf-shield-tfstate-${ACCOUNT_ID}"}}"
TABLE_NAME="${3:-${TF_LOCK_TABLE:-"pf-shield-tf-locks"}}"

echo -e "${BLUE}==============================================================================${NC}"
echo -e "${BLUE}    PF-Shield: Terraform Remote State Bootstrap (AWS CLI)                    ${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo -e "Target Region:         ${CYAN}${AWS_REGION}${NC}"
echo -e "Remote State S3 Bucket: ${CYAN}${BUCKET_NAME}${NC}"
echo -e "DynamoDB Lock Table:   ${CYAN}${TABLE_NAME}${NC}"
echo -e "AWS Account ID:        ${CYAN}${ACCOUNT_ID}${NC}"
echo ""

# ---------------------------------------------------------------------------------------------------------------------
# 1. CREATE S3 BUCKET
# ---------------------------------------------------------------------------------------------------------------------
echo -e "${YELLOW}[1/6] Checking S3 state bucket...${NC}"
if aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
  echo -e "${GREEN}✔ S3 bucket '${BUCKET_NAME}' already exists.${NC}"
else
  echo -e "Creating S3 bucket '${BUCKET_NAME}' in '${AWS_REGION}'..."
  if [ "${AWS_REGION}" = "us-east-1" ]; then
    aws s3api create-bucket \
      --bucket "${BUCKET_NAME}" \
      --region "${AWS_REGION}"
  else
    aws s3api create-bucket \
      --bucket "${BUCKET_NAME}" \
      --region "${AWS_REGION}" \
      --create-bucket-configuration LocationConstraint="${AWS_REGION}"
  fi
  echo -e "${GREEN}✔ S3 bucket created.${NC}"
fi

# ---------------------------------------------------------------------------------------------------------------------
# 2. ENABLE S3 VERSIONING
# ---------------------------------------------------------------------------------------------------------------------
echo -e "${YELLOW}[2/6] Enabling S3 bucket versioning...${NC}"
aws s3api put-bucket-versioning \
  --bucket "${BUCKET_NAME}" \
  --versioning-configuration Status=Enabled
echo -e "${GREEN}✔ S3 bucket versioning enabled.${NC}"

# ---------------------------------------------------------------------------------------------------------------------
# 3. CONFIGURE S3 DEFAULT ENCRYPTION (SSE-S3 + BUCKET KEYS)
# ---------------------------------------------------------------------------------------------------------------------
echo -e "${YELLOW}[3/6] Configuring S3 server-side encryption...${NC}"
aws s3api put-bucket-encryption \
  --bucket "${BUCKET_NAME}" \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        },
        "BucketKeyEnabled": true
      }
    ]
  }'
echo -e "${GREEN}✔ SSE-S3 encryption and S3 Bucket Keys configured.${NC}"

# ---------------------------------------------------------------------------------------------------------------------
# 4. BLOCK PUBLIC ACCESS
# ---------------------------------------------------------------------------------------------------------------------
echo -e "${YELLOW}[4/6] Enforcing S3 Public Access Block...${NC}"
aws s3api put-public-access-block \
  --bucket "${BUCKET_NAME}" \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
echo -e "${GREEN}✔ S3 public access completely blocked (all 4 flags active).${NC}"

# ---------------------------------------------------------------------------------------------------------------------
# 5. ATTACH SECURE TRANSPORT BUCKET POLICY (TLS 1.2+ MANDATE)
# ---------------------------------------------------------------------------------------------------------------------
echo -e "${YELLOW}[5/6] Enforcing TLS 1.2+ transport policy...${NC}"
POLICY_DOC=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceSecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
EOF
)
aws s3api put-bucket-policy \
  --bucket "${BUCKET_NAME}" \
  --policy "${POLICY_DOC}"
echo -e "${GREEN}✔ TLS secure transport policy attached.${NC}"

# ---------------------------------------------------------------------------------------------------------------------
# 6. CREATE DYNAMODB LOCK TABLE ($0 IDLE COST ON PAY_PER_REQUEST)
# ---------------------------------------------------------------------------------------------------------------------
echo -e "${YELLOW}[6/6] Checking DynamoDB lock table...${NC}"
if aws dynamodb describe-table --table-name "${TABLE_NAME}" --region "${AWS_REGION}" 2>/dev/null; then
  echo -e "${GREEN}✔ DynamoDB table '${TABLE_NAME}' already exists.${NC}"
else
  echo -e "Creating DynamoDB table '${TABLE_NAME}' in '${AWS_REGION}'..."
  aws dynamodb create-table \
    --table-name "${TABLE_NAME}" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region "${AWS_REGION}" \
    --tags Key=Project,Value=PF-Shield Key=ManagedBy,Value=Manual-Bootstrap Key=Environment,Value=prod-sim
  
  echo "Waiting for DynamoDB table to become ACTIVE..."
  aws dynamodb wait table-exists --table-name "${TABLE_NAME}" --region "${AWS_REGION}"
  echo -e "${GREEN}✔ DynamoDB table active and ready.${NC}"
fi

echo ""
echo -e "${BLUE}==============================================================================${NC}"
echo -e "${GREEN}✔ Remote State Bootstrap Complete!${NC}"
echo -e "${BLUE}==============================================================================${NC}"
echo -e "To configure your Terraform backend, use the following in ${CYAN}terraform/backend.tf${NC}:"
echo ""
cat <<EOF
terraform {
  backend "s3" {
    bucket         = "${BUCKET_NAME}"
    key            = "pf-shield/prod-sim/terraform.tfstate"
    region         = "${AWS_REGION}"
    dynamodb_table = "${TABLE_NAME}"
    encrypt        = true
  }
}
EOF
echo ""
