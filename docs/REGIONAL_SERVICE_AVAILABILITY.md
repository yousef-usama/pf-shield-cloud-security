# PF-Shield Regional Service Availability & Fallback Strategy

## 1. Regional Architecture & Sovereignty Overview

**Primary Region:** `me-central-1` (UAE - Dubai)  
**Fallback Region:** `me-south-1` (Bahrain)  
**Data Residency Law:** UAE Personal Data Protection Law (Federal Decree-Law No. 45 of 2021)

To comply with the UAE Personal Data Protection Law, all personal data relating to UAE property buyers, tenants, and brokers (Emirates IDs, passport scans, and title deeds) must reside within UAE sovereign cloud infrastructure (`me-central-1`).

However, as a newer AWS region (launched in August 2022), `me-central-1` must be audited for service feature parity against established Middle East regions like `me-south-1` (launched July 2019). This document outlines the service parity verification results and fallback architecture.

---

## 2. Service Parity & Availability Verification Matrix

The following table reflects the verified operational status of services utilized in PF-Shield:

| Service / Capability | `me-central-1` (Primary) | `me-south-1` (Fallback) | Verification Command | Architectural Notes |
| :--- | :--- | :--- | :--- | :--- |
| **VPC S3 Gateway Endpoint** | **Supported ($0.00)** | **Supported ($0.00)** | `aws ec2 describe-vpc-endpoint-services --region me-central-1` | Routes S3 traffic over private AWS backplane; eliminates $32+/mo NAT Gateway. |
| **VPC DynamoDB Gateway Endpoint** | **Supported ($0.00)** | **Supported ($0.00)** | `aws ec2 describe-vpc-endpoint-services --region me-central-1` | Zero-cost private database access. |
| **KMS Customer Managed Keys** | **Supported** | **Supported** | `aws kms list-keys --region me-central-1` | Used for envelope encryption; supports annual automatic rotation. |
| **S3 Bucket Keys for KMS** | **Supported** | **Supported** | `aws s3api get-bucket-encryption --bucket ... --region me-central-1` | Crucial FinOps primitive; reduces KMS request charges by 99%. |
| **AWS Lambda (arm64 Graviton2)**| **Supported** | **Supported** | `aws lambda list-functions --region me-central-1` | Lower cold-start latency, 20% price-performance gain over x86. |
| **API Gateway HTTP API (v2)** | **Supported** | **Supported** | `aws apigatewayv2 get-apis --region me-central-1` | 70% cheaper than REST API; native stage burst rate limiting. |
| **Amazon EventBridge** | **Supported** | **Supported** | `aws events list-rules --region me-central-1` | Real-time SOAR event routing bus. |
| **Amazon SNS & SQS (KMS)** | **Supported** | **Supported** | `aws sns list-topics --region me-central-1` | Encrypted alerts and Dead Letter Queues (DLQ). |
| **AWS CloudTrail Multi-Region** | **Supported** | **Supported** | `aws cloudtrail describe-trails --region me-central-1` | Central management event logging with SHA-256 file validation. |
| **AWS SSM Parameter Store** | **Supported** | **Supported** | `aws ssm describe-parameters --region me-central-1` | SecureString encrypted with KMS CMK at $0.00 cost. |
| **CloudWatch Metric Alarms & Dashboards** | **Supported** | **Supported** | `aws cloudwatch list-dashboards --region me-central-1` | Proactive security monitoring and DLQ depth alerting. |
| **AWS GuardDuty S3 Protection** | **Supported** | **Supported** | `aws guardduty list-detectors --region me-central-1` | Controlled via `enable_guardduty_and_securityhub` variable. |
| **AWS Security Hub** | **Supported** | **Supported** | `aws securityhub describe-hub --region me-central-1` | Controlled via `enable_guardduty_and_securityhub` variable. |
| **AWS WAFv2 Regional WebACL** | **Supported** | **Supported** | `aws wafv2 list-web-acls --scope REGIONAL --region me-central-1` | Controlled via `enable_waf` variable. |

---

## 3. Fallback Trigger & Execution Protocol

If an enterprise client or auditing body requires an AWS service configuration not yet certified in `me-central-1`:
1. **Cross-Region IAM Control Plane**: Workload permission boundaries (`terraform/modules/iam-boundaries/`) accept `var.aws_region` and can dynamically expand allowed regions while maintaining UAE PDPL residency for S3 bucket storage.
2. **Terraform Parameter Switch**: To deploy to the fallback region, update `terraform/variables.tf`:
   ```hcl
   variable "aws_region" {
     default = "me-south-1"
   }
   ```
3. **Automated Verification Script**: Run the verification runner before provisioning:
   ```bash
   ./scripts/verify_region_services.sh me-central-1 me-south-1
   ```

---

## 4. Interview Talking Point: Proactive Regional Validation

> *"In the UAE market, junior engineers frequently deploy to `us-east-1` because tutorials use it, directly violating UAE Personal Data Protection Law (Federal Decree-Law No. 45 of 2021). Senior security engineers validate regional service availability before writing a line of Terraform, map residency controls into IAM permission boundaries, and build automated verification scripts like `scripts/verify_region_services.sh` into the deployment toolchain."*
