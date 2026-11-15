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
  - [`terraform/modules/iam-boundaries/`](terraform/modules/iam-boundaries/): Regional permission boundaries (`me-central-1`) and emergency quarantine deny-all policies.
  - [`terraform/modules/finops-budget/`](terraform/modules/finops-budget/): AWS Budgets configuration capping spend at $5.00/mo with proactive alerting.
  - [`terraform/modules/zero-trust-kyc-vault/`](terraform/modules/zero-trust-kyc-vault/): Private VPC, $0.00 S3/DynamoDB Gateway Endpoints, KMS CMK, and S3 Bucket Keys.
  - [`terraform/modules/edge-api-waf/`](terraform/modules/edge-api-waf/): API Gateway HTTP API, Graviton2 Lambda functions, and anti-scraping WAFv2 rules.
  - [`terraform/modules/soar-engine/`](terraform/modules/soar-engine/): Multi-region CloudTrail, EventBridge rules, SQS DLQs, and auto-remediation Lambdas.
  - [`terraform/modules/observability/`](terraform/modules/observability/): CloudWatch Security Operations dashboard and proactive DLQ/error alarms.
  - [`terraform/modules/secrets/`](terraform/modules/secrets/): SSM Parameter Store (SecureString) encrypted with KMS CMK.
- [`src/app/`](src/app/): Application handlers (`property_api_handler.py` and `kyc_vault_handler.py`).
- [`src/soar/`](src/soar/): Automated incident response playbooks (`playbook_s3_lockdown.py` and `playbook_iam_quarantine.py`).
- [`src/tests/`](src/tests/): Automated unit test suite using `pytest` and `moto` AWS mocks.
- [`k8s-security-policies/`](k8s-security-policies/): Kyverno ClusterPolicies and hardened Kubernetes manifests demonstrating shift-left container security.
- [`scripts/`](scripts/): Attack simulation runner (`simulate_attack.sh`), regional service parity verifier (`verify_region_services.sh`), and diagram generator (`generate_architecture_diagram.py`).
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

### Quickstart Execution (1-Command Verification)
```bash
# 1. Clone repository
git clone https://github.com/YousefOsama/pf-shield-cloud-security.git
cd pf-shield-cloud-security

# 2. Run unit tests (Moto AWS mocking)
make test

# 3. Run Checkov policy-as-code security scan
make scan

# 4. Verify regional service availability
./scripts/verify_region_services.sh me-central-1 me-south-1

# 5. Execute attack simulation & SOAR containment proof
make simulate-attack
```

### Production Deployment Order
1. **Initialize Terraform**:
   ```bash
   cd terraform && terraform init
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
