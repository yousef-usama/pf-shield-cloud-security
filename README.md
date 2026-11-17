# PF-Shield — Zero-Trust Real Estate API & Automated Cloud SOAR

[![DevSecOps Pipeline](https://img.shields.io/badge/CI%2FCD-DevSecOps%20Pipeline-success?style=for-the-badge&logo=github-actions)](.github/workflows/devsecops-pipeline.yml)
[![Monthly Run Rate](https://img.shields.io/badge/FinOps%20Run%20Rate-%240.00%20--%20%241.10%20%2F%20mo-brightgreen?style=for-the-badge&logo=amazon-aws)](docs/WELL_ARCHITECTED_REVIEW.md)
[![Compliance](https://img.shields.io/badge/Compliance-UAE%20PDPL%20%7C%20ISO%2027001%20%7C%20SOC%202-blue?style=for-the-badge&logo=securityscorecard)](docs/COMPLIANCE_MAPPING.md)
[![Checkov Audit](https://img.shields.io/badge/Checkov%20IaC-166%20Passed%20%7C%200%20Failed-success?style=for-the-badge&logo=paloaltonetworks)](docs/EVIDENCE.md)

---

## 1. Executive Overview

**PF-Shield** is a production-grade, cost-optimized AWS cloud security control plane and automated incident response (SOAR) platform engineered for cloud-native real estate platforms in the **United Arab Emirates (UAE)**.

Real estate platforms handle millions of property listings and tens of thousands of sensitive broker and tenant identity documents (Emirates IDs, passport scans, and RERA title deeds). Securing these assets requires reconciling two competing operational demands:
1. **Uncompromising Zero-Trust Security & Sovereign Compliance**: Strict alignment with **UAE Personal Data Protection Law (PDPL - Federal Decree-Law No. 45 of 2021)** data residency mandates in region `me-central-1`, ISO/IEC 27001:2022 Annex A, and SOC 2 Type II trust services criteria.
2. **Aggressive FinOps Cost Optimization**: Delivering a full security control plane — encompassing IAM permission boundaries, triple-deny data perimeters, envelope encryption, automated threat containment (< 1.5s MTTR), observability, and shift-left Kubernetes policies — at an idle run rate of **$0.00 – $1.10 / month**, compared to a naive enterprise deployment costing **$165+/month**.

---

## 2. Contents (Repository Navigation & Table of Contents)

### README Table of Contents
- [1. Executive Overview](#1-executive-overview)
- [2. Contents (Repository Navigation & Table of Contents)](#2-contents-repository-navigation--table-of-contents)
- [3. Visual Architecture Diagram](#3-visual-architecture-diagram)
- [4. Tool Selection Rationale & Tradeoffs](#4-tool-selection-rationale--tradeoffs)
- [5. Architecture & Tenancy Deep Dive](#5-architecture--tenancy-deep-dive)
- [6. Step-by-Step Deployment Runbook](#6-step-by-step-deployment-runbook)
- [7. Production Incident Post-Mortems](#7-production-incident-post-mortems)
- [8. Cost Notes & Teardown Protocol](#8-cost-notes--teardown-protocol)

### Repository Directory Map
- [`terraform/`](terraform/): 100% modular Infrastructure-as-Code root configuration.
  - [`terraform/backend.tf`](terraform/backend.tf): Remote state configuration backed by S3 and DynamoDB state locking.
  - [`terraform/modules/iam-boundaries/`](terraform/modules/iam-boundaries/): Regional permission boundaries (`me-central-1`) and emergency quarantine deny-all policies.
  - [`terraform/modules/finops-budget/`](terraform/modules/finops-budget/): AWS Budgets configuration capping spend at $5.00/mo with proactive alerting.
  - [`terraform/modules/zero-trust-kyc-vault/`](terraform/modules/zero-trust-kyc-vault/): Private VPC, $0.00 S3/DynamoDB Gateway Endpoints, KMS CMK, and S3 Bucket Keys.
  - [`terraform/modules/edge-api-waf/`](terraform/modules/edge-api-waf/): API Gateway HTTP API, Graviton2 Lambda functions, and anti-scraping WAFv2 rules.
  - [`terraform/modules/soar-engine/`](terraform/modules/soar-engine/): Multi-region CloudTrail, EventBridge rules, SQS DLQs, and auto-remediation Lambdas.
  - [`terraform/modules/observability/`](terraform/modules/observability/): CloudWatch Security Operations dashboard and proactive DLQ/error alarms.
  - [`terraform/modules/secrets/`](terraform/modules/secrets/): SSM Parameter Store (SecureString) encrypted with KMS CMK.
- [`terraform-bootstrap/`](terraform-bootstrap/): Isolated one-time bootstrap config provisioning GitHub Actions OIDC identity provider and IAM deployer role.
- [`.github/workflows/`](.github/workflows/): Complete CI/CD and automation suites:
  - [`devsecops-pipeline.yml`](.github/workflows/devsecops-pipeline.yml): Push pipeline running SOAR unit tests, full IaC scan, and Kyverno K8s policies.
  - [`pr-checkov.yml`](.github/workflows/pr-checkov.yml): Targeted PR gate running Checkov static analysis on any Terraform changes.
  - [`terraform-destroy.yml`](.github/workflows/terraform-destroy.yml): Manual-dispatch 1-click teardown workflow for zero idle cost decommissioning.
- [`src/app/`](src/app/): Application handlers (`property_api_handler.py` and `kyc_vault_handler.py`).
- [`src/soar/`](src/soar/): Automated incident response playbooks (`playbook_s3_lockdown.py` and `playbook_iam_quarantine.py`).
- [`src/tests/`](src/tests/): Automated unit test suite using `pytest` and `moto` AWS mocks.
- [`k8s-security-policies/`](k8s-security-policies/): Kyverno ClusterPolicies and hardened Kubernetes manifests demonstrating shift-left container security.
- [`scripts/`](scripts/): Automation scripts:
  - [`bootstrap-remote-state.sh`](scripts/bootstrap-remote-state.sh): One-time AWS CLI bootstrap for S3 remote state bucket and DynamoDB lock table.
  - [`simulate_attack.sh`](scripts/simulate_attack.sh): EventBridge attack simulation runner.
  - [`verify_region_services.sh`](scripts/verify_region_services.sh): Regional service parity verifier (`me-central-1` vs `me-south-1`).
  - [`generate_architecture_diagram.py`](scripts/generate_architecture_diagram.py): Visual architecture diagram generator.
- [`docs/`](docs/): Complete governance documentation:
  - [`docs/EVIDENCE.md`](docs/EVIDENCE.md): Auditable verification proofs and terminal failure screenshots for every section.
  - [`docs/THREAT_MODEL_STRIDE.md`](docs/THREAT_MODEL_STRIDE.md): Comprehensive STRIDE threat model mapped to real estate platform assets.
  - [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md): Regulatory matrix mapping to UAE PDPL, ISO 27001, and SOC 2.
  - [`docs/WELL_ARCHITECTED_REVIEW.md`](docs/WELL_ARCHITECTED_REVIEW.md): Detailed 6-pillar Well-Architected Framework review.
  - [`docs/REGIONAL_SERVICE_AVAILABILITY.md`](docs/REGIONAL_SERVICE_AVAILABILITY.md): `me-central-1` vs `me-south-1` feature parity audit.
  - [`docs/runbooks/`](docs/runbooks/): Step-by-step incident response runbooks for compromised credentials and S3 exfiltration.

---

## 3. Visual Architecture Diagram

![PF-Shield Architecture Overview](docs/architecture-overview.png)

*Figure 1: PF-Shield Zero-Trust Cloud Architecture.*

---

## 4. Tool Selection Rationale & Tradeoffs

| Component | Selected Technology | Considered Alternatives | Rationale for Selection | Architectural Tradeoffs |
| :--- | :--- | :--- | :--- | :--- |
| **VPC Connectivity** | **VPC Gateway Endpoints** (`s3`, `dynamodb`) | AWS NAT Gateway ($32+/mo), Transit Gateway | Eliminates $32.85/mo hourly NAT fee; traffic never leaves AWS internal backplane ($0.00/hr). | Gateway Endpoints support S3 and DynamoDB only; other AWS services require Interface Endpoints or public DNS. |
| **Compute Engine** | **AWS Lambda (`arm64` Graviton2)** | AWS ECS Fargate, EKS Managed Nodes | $0.00 idle compute cost; scale-to-zero; Graviton2 yields 20% lower cost and lower cold-start latency. | 15-minute execution limit; cold starts require optimization (managed by keeping dependencies lightweight). |
| **Edge API Layer** | **API Gateway HTTP API (v2)** | API Gateway REST API, Application Load Balancer | 70% cheaper than REST API; native stage burst rate limiting (50 burst / 25 rate) provides $0 anti-scraping. | Lacks request validation mapping templates (handled within Lambda application code). |
| **Data Encryption** | **KMS CMK + S3 Bucket Keys** | AWS Managed Key (`aws/s3`), Client-Side Encryption | Fulfills UAE PDPL Art. 13 cryptographic separation; S3 Bucket Keys reduce KMS request fees by 99%. | Incurs a baseline $1.00/month fee for the Customer Managed Key. |
| **Event Routing** | **Amazon EventBridge** | CloudWatch Logs Metric Filters, SNS Fanout | Native content filtering on CloudTrail and GuardDuty schemas; decoupled, declarative JSON event rules. | EventBridge bus adds up to ~1.5s latency compared to synchronous webhooks. |
| **Container Governance** | **Kyverno Policy-as-Code (CI CLI)** | Live EKS Cluster + OPA Gatekeeper | Validates Kubernetes security policies shift-left without incurring $73.00/month for an idle EKS control plane. | Policies validated at build time in CI rather than live admission webhook enforcement. |

---

## 5. Architecture & Tenancy Deep Dive

```
[ External Scrapers & Threat Actors ]
                 │
                 ▼
     [ AWS WAFv2 WebACL ]  <─── (Rate-based rules: >100 req/5m blocked)
                 │
                 ▼
  [ API Gateway HTTP API ($default) ]  <─── (Throttling: 25 rps / 50 burst)
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
[ Property Listings ]  [ KYC Presign Handler ]
(DynamoDB Read)       (Issues 300s KMS Presigned URL)
      │                     │
      └──────────┬──────────┘
                 ▼
═════════════════════════════════════════════════════════════════════════
  PRIVATE VPC DATA PERIMETER (10.20.0.0/16 — Zero Public Routes)
═════════════════════════════════════════════════════════════════════════
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
 [ S3 Gateway VPCE ]  [ DynamoDB Gateway VPCE ]
       │                   │
       ▼                   ▼
[ S3 KYC Vault ]     [ Properties Metadata Table ]
 • Triple-Deny Policy  • PAY_PER_REQUEST ($0 idle)
 • S3 Bucket Key (99%) • KMS CMK Encrypted
 • 7-day Log Expiry    • Point-in-Time Recovery
```

### 1. Zero-Trust S3 Data Perimeter
The broker KYC vault (`aws_s3_bucket.kyc_vault`) stores confidential UAE PII. Access is guarded by a triple-deny policy:
- **Statement 1 (`DenyInsecureTransport`)**: Denies all API operations unless `aws:SecureTransport == true`.
- **Statement 2 (`DenyUnencryptedUploads`)**: Denies `s3:PutObject` unless server-side encryption is explicitly set to `aws:kms`.
- **Statement 3 (`EnforceDataPerimeter`)**: Denies `s3:GetObject` and `s3:PutObject` if the caller originates outside the VPC Gateway Endpoint (`aws:SourceVpce != vpce-xxx`) AND is not an explicitly authorized KYC or SOAR Lambda role.

### 2. IAM Permission Boundaries & Privilege Escalation Prevention
All application roles attach `pf-workload-permission-boundary`, enforcing:
- Regional scoping strictly to `me-central-1`.
- Explicit Deny on `iam:DeleteRolePermissionsBoundary` (boundary cannot be removed).
- Explicit Deny on `iam:CreateRole` unless the new role attaches the boundary ARN (prevents privilege escalation).
- Explicit Deny on tampering with S3 Public Access Block, bucket policies, or CloudTrail logging.

### 3. Automated Incident Response (SOAR Engine)
When an unauthorized identity attempts S3 public access exposure or IAM privilege escalation:
1. EventBridge matches the CloudTrail or GuardDuty event pattern.
2. If Lambda execution throttles, the attached SQS Dead Letter Queue captures the event (zero dropped alert SLA).
3. The SOAR Lambda attaches `pf-soar-quarantine-deny-all` to the offending principal, restores all 4 S3 Public Access Block flags to `True`, deactivates all active access keys, and publishes a structured forensic alert to SNS in **< 1.5 seconds**.

---

## 6. Step-by-Step Deployment Runbook

### Prerequisites
- AWS CLI `>= 2.15.0` configured with administrative credentials in region `me-central-1`.
- Terraform `>= 1.6.0`.
- Python `>= 3.12` and `make`.

---

### Step 0: One-Time Bootstrap (Run Once Prior to First Deploy)

#### 0.1 Remote State Bootstrap (S3 + DynamoDB via AWS CLI)
To avoid the architectural **chicken-and-egg problem** (where Terraform cannot store its state in an S3 bucket that it has not yet provisioned), the remote state backend is initialized externally via AWS CLI.

Run the provided automated bootstrap script:
```bash
./scripts/bootstrap-remote-state.sh me-central-1
# Or via Makefile:
make bootstrap-state
```

<details>
<summary><b>Click to view the raw manual AWS CLI commands</b></summary>

```bash
# Variables
AWS_REGION="me-central-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
BUCKET_NAME="pf-shield-tfstate-${ACCOUNT_ID}"
TABLE_NAME="pf-shield-tf-locks"

# 1. Create S3 Bucket in me-central-1
aws s3api create-bucket \
  --bucket "${BUCKET_NAME}" \
  --region "${AWS_REGION}" \
  --create-bucket-configuration LocationConstraint="${AWS_REGION}"

# 2. Enable S3 Bucket Versioning
aws s3api put-bucket-versioning \
  --bucket "${BUCKET_NAME}" \
  --versioning-configuration Status=Enabled

# 3. Enable Default Encryption (SSE-S3 + Bucket Keys for FinOps)
aws s3api put-bucket-encryption \
  --bucket "${BUCKET_NAME}" \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": { "SSEAlgorithm": "AES256" },
        "BucketKeyEnabled": true
      }
    ]
  }'

# 4. Enforce Full Public Access Block
aws s3api put-public-access-block \
  --bucket "${BUCKET_NAME}" \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'

# 5. Enforce TLS 1.2+ Transport Mandate
aws s3api put-bucket-policy \
  --bucket "${BUCKET_NAME}" \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Sid\": \"EnforceSecureTransport\",
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": [\"arn:aws:s3:::${BUCKET_NAME}\", \"arn:aws:s3:::${BUCKET_NAME}/*\"],
        \"Condition\": { \"Bool\": { \"aws:SecureTransport\": \"false\" } }
      }
    ]
  }"

# 6. Create DynamoDB Lock Table ($0 idle on PAY_PER_REQUEST)
aws dynamodb create-table \
  --table-name "${TABLE_NAME}" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "${AWS_REGION}" \
  --tags Key=Project,Value=PF-Shield Key=ManagedBy,Value=Manual-Bootstrap
```
</details>

#### 0.2 GitHub Actions OIDC & Bootstrap Role (`terraform-bootstrap/`)
PF-Shield establishes keyless, zero-secret authentication between GitHub Actions and AWS using OpenID Connect (OIDC). This is isolated in a separate, lightweight Terraform module:

```bash
cd terraform-bootstrap
terraform init
terraform apply -auto-approve -var="github_repository=YOUR_GITHUB_USER/pf-shield-cloud-security"
# Or via Makefile:
make bootstrap-oidc
```

Then add the output `github_actions_role_arn` to GitHub repository secrets:
- **Secret Name**: `AWS_ROLE_TO_ASSUME`
- **Secret Value**: `arn:aws:iam::<ACCOUNT_ID>:role/pf-shield-github-actions-bootstrap-role`

---

### Step 1: Local Verification & Pre-Flight Checks
```bash
# 1. Clone repository
git clone https://github.com/YousefOsama/pf-shield-cloud-security.git
cd pf-shield-cloud-security

# 2. Run unit tests (Moto AWS mocking)
make test

# 3. Run Checkov policy-as-code security scan across main and bootstrap IaC
make scan

# 4. Verify regional service availability
./scripts/verify_region_services.sh me-central-1 me-south-1

# 5. Execute attack simulation & SOAR containment proof
make simulate-attack
```

---

### Step 2: Production Deployment Order
1. **Initialize Terraform with Remote Backend**:
   ```bash
   cd terraform
   terraform init -backend-config="bucket=pf-shield-tfstate-<YOUR_ACCOUNT_ID>"
   ```
2. **Review Execution Plan**:
   ```bash
   terraform plan -out=tfplan
   ```
3. **Provision Infrastructure**:
   ```bash
   terraform apply -auto-approve tfplan
   ```
4. **Live Verification**:
   - Query the public listings API: `curl -i $(terraform output -raw edge_api_properties_route)`
   - Request a presigned KYC upload URL: `curl -i -X POST $(terraform output -raw edge_api_kyc_presign_route) -d '{"document_type":"emirates_id","file_extension":"pdf","broker_id":"brk-991"}'`
   - Trigger attack simulation: `../scripts/simulate_attack.sh`

---

### Step 3: CI/CD Workflows Overview

PF-Shield provides three automated GitHub Actions workflows:

1. **DevSecOps Pipeline ([`devsecops-pipeline.yml`](.github/workflows/devsecops-pipeline.yml))**:
   - Triggers on push to `main`.
   - Executes SOAR unit test suites (`pytest` + `moto`), full IaC static analysis (`Checkov`), and shift-left Kubernetes policies (`Kyverno CLI`).
2. **PR Security Gate ([`pr-checkov.yml`](.github/workflows/pr-checkov.yml))**:
   - Triggers on pull requests affecting `terraform/**` or `terraform-bootstrap/**`.
   - Runs `terraform fmt -check`, `terraform validate`, and scans for security regressions with `Checkov`, blocking non-compliant PRs before merge.
3. **1-Click Manual Teardown ([`terraform-destroy.yml`](.github/workflows/terraform-destroy.yml))**:
   - Triggers via `workflow_dispatch` in the GitHub Actions UI.
   - Assumes the OIDC bootstrap role and executes `terraform destroy` with a required confirmation safety latch (`confirmation: destroy`), restoring spend to **$0.00/month** with one click.

---

## 7. Production Incident Post-Mortems

Technical challenges encountered during implementation are documented below and in [docs/EVIDENCE.md](docs/EVIDENCE.md#7-comprehensive-incident-post-mortem-log):

### Incident 1: S3 Bucket Lifecycle Configuration Rule Filter Deprecation
- **Symptoms**: `Warning: Invalid Attribute Combination: No attribute specified when one of [filter, prefix] is required`.
- **RCA**: AWS Provider `~> 5.0` requires explicit `filter {}` blocks on lifecycle rules to prevent deprecated whole-bucket matching.
- **Resolution**: Injected explicit `filter {}` blocks into all S3 lifecycle resources.
- **Terminal Evidence**: [docs/screenshots/incident-01-terminal-failure.png](docs/screenshots/incident-01-terminal-failure.png).

### Incident 2: Checkov CKV_AWS_286 Privilege Escalation Flag on SOAR IAM Role Policy
- **Symptoms**: Checkov failed on `iam:AttachRolePolicy` and `iam:AttachUserPolicy` inside SOAR remediation role.
- **RCA**: Attaching policies dynamically is an escalation risk for standard roles, but is **the fundamental operational requirement** of SOAR quarantine automation.
- **Resolution**: Documented intentional architectural tradeoff via `#checkov:skip=CKV_AWS_286` inside the resource block with permission boundary scoping.
- **Terminal Evidence**: [docs/screenshots/incident-02-terminal-failure.png](docs/screenshots/incident-02-terminal-failure.png).

---

## 8. Cost Notes & Teardown Protocol

### FinOps Summary
- **Baseline Idle Run Rate**: **$0.00 – $1.10 / month** (1x KMS CMK = $1.00/mo; all compute, networking, and databases operate on scale-to-zero free tiers).
- **Full Security Stack Enabled (WAF + GuardDuty + Security Hub)**: **~$12.00 – $18.00 / month**.
- **Naive Enterprise Equivalent**: **~$235.00 – $260.00 / month** (99.5% cost reduction achieved).

### Ordered Teardown Command
To safely decommission all provisioned resources without leaving orphaned cloud assets:
```bash
make destroy
```
*(Deletes API Gateway stages, Lambda functions, KMS aliases, SQS DLQs, EventBridge rules, VPC Gateway Endpoints, and empties the S3 buckets via `force_destroy = true`)*.

---

## 9. Author & License

- **Author**: Yousef Osama
- **License**: MIT License
