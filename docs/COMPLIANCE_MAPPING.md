# PF-Shield Compliance Mapping Matrix

## Regulatory Context & Applicable Standards

As a premier real estate technology platform operating in the United Arab Emirates, Property Finder is subject to strict data sovereignty, privacy, and cybersecurity standards:
1. **UAE Personal Data Protection Law (PDPL - Federal Decree-Law No. 45 of 2021)**
2. **ISO/IEC 27001:2022 Information Security Management System (ISMS) Annex A**
3. **AICPA SOC 2 Type II Trust Services Criteria (Security & Confidentiality)**

The matrix below maps each specific regulatory requirement to the technical and architectural controls implemented in **PF-Shield**.

---

## 1. Compliance Controls Cross-Reference Matrix

| Standard & Article | Mandated Requirement | PF-Shield Architectural Implementation | Implementation Location in Repository |
| :--- | :--- | :--- | :--- |
| **UAE PDPL Art. 13**<br>*(Security of Personal Data)* | Data Controllers must implement appropriate technical and organizational measures to protect personal data from unauthorized access, alteration, destruction, or disclosure. | • S3 KYC Vault protected by triple-deny bucket policy (no unencrypted uploads, TLS required, VPC endpoint required).<br>• Envelope encryption using KMS Customer Managed Key (CMK) with annual rotation.<br>• Automated SOAR S3 lockdown playbook. | `terraform/modules/zero-trust-kyc-vault/main.tf`<br>`src/soar/playbook_s3_lockdown.py` |
| **UAE PDPL Art. 22**<br>*(Cross-Border Transfer & Data Residency)* | Personal data may not be transferred outside the UAE unless adequate protections exist. Storage must remain within sovereign UAE boundaries. | • Primary AWS deployment strictly locked to `me-central-1` (UAE).<br>• IAM Permission Boundary explicitly denies actions where `aws:RequestedRegion != me-central-1`.<br>• Cross-region S3 replication intentionally disabled (`CKV_AWS_144`). | `terraform/providers.tf`<br>`terraform/modules/iam-boundaries/main.tf` |
| **UAE PDPL Art. 9**<br>*(Data Protection by Design & Default)* | Systems must enforce least privilege, data minimization, and automated retention lifecycles by default. | • S3 Lifecycle rules automatically transition KYC documents to `STANDARD_IA` at 30 days and expire temporary logs at 7 days.<br>• Zero NAT Gateway exposure; data routed over private VPC Gateway Endpoints. | `terraform/modules/zero-trust-kyc-vault/main.tf`<br>`terraform/modules/finops-budget/main.tf` |
| **UAE PDPL Art. 14**<br>*(Breach Notification)* | The Controller must immediately notify the UAE Data Office and data subjects upon discovering any breach or exposure of personal data. | • EventBridge rule detects any S3 public access modification or GuardDuty exfiltration finding in real time.<br>• SOAR engine publishes structured forensic report to `pf-security-incidents` SNS topic with calculated Mean Time to Remediate (MTTR). | `terraform/modules/soar-engine/main.tf`<br>`src/soar/playbook_s3_lockdown.py` |
| **ISO 27001:2022 A.5.15**<br>*(Access Control)* | Rules to control physical and logical access to information and systems must be established and documented. | • IAM Permission Boundary enforces maximum permissions ceiling across all workload roles.<br>• Denies unbounded role creation (`iam:CreateRole` requires boundary attachment).<br>• Denies boundary deletion or modification. | `terraform/modules/iam-boundaries/main.tf` |
| **ISO 27001:2022 A.8.12**<br>*(Data Leakage Prevention)* | Data leakage prevention measures must be applied to systems processing sensitive data. | • S3 Data Perimeter enforces `aws:SourceVpce == endpoint.id` AND `aws:PrincipalArn` in authorized KYC roles.<br>• API Gateway stage-level throttling blocks bulk scraping of property listings. | `terraform/modules/zero-trust-kyc-vault/main.tf`<br>`terraform/modules/edge-api-waf/main.tf` |
| **ISO 27001:2022 A.8.20**<br>*(Network Security)* | Networks must be secured and controlled to protect information in systems and applications. | • Private VPC with zero public subnets, zero Internet Gateways, and zero NAT Gateways for data workloads.<br>• Default security group locked down with 0 ingress and 0 egress rules.<br>• Kubernetes NetworkPolicy with default-deny. | `terraform/modules/zero-trust-kyc-vault/main.tf`<br>`k8s-security-policies/hardened-property-service-deployment.yaml` |
| **ISO 27001:2022 A.8.24**<br>*(Use of Cryptography)* | Rules for the effective use of cryptography, including cryptographic key management, must be defined and implemented. | • Dedicated KMS Customer Managed Key (`pf-kyc-cmk`) with yearly automatic rotation.<br>• S3 Bucket Key enabled (`bucket_key_enabled = true`) to cryptographically partition KMS requests while reducing cost by 99%.<br>• TLS 1.2+ transport enforced on all endpoints. | `terraform/modules/zero-trust-kyc-vault/main.tf` |
| **ISO 27001:2022 A.5.24**<br>*(Incident Management Planning)* | The organization must plan and prepare for managing information security incidents. | • Step-by-step incident response runbooks for compromised credentials and S3 exfiltration.<br>• SQS Dead Letter Queues attached to EventBridge SOAR targets (zero dropped security alerts SLA). | `docs/runbooks/RUNBOOK-01-Compromised-IAM-Credentials.md`<br>`docs/runbooks/RUNBOOK-02-S3-KYC-Exfiltration-Attempt.md` |
| **SOC 2 Type II CC6.1**<br>*(Logical Access Controls)* | The entity restricts logical access to registered and authorized users, devices, and applications. | • Workload IAM roles restricted to scoped operations in `me-central-1`.<br>• Presigned URLs for KYC uploads expire in 300 seconds.<br>• Compromised credentials immediately frozen via `pf-soar-quarantine-deny-all`. | `terraform/modules/iam-boundaries/main.tf`<br>`src/soar/playbook_iam_quarantine.py` |
| **SOC 2 Type II CC6.6**<br>*(Boundary Protection)* | The entity implements logical boundaries to protect information assets from unauthorized intrusion. | • VPC Gateway Endpoints route S3 and DynamoDB traffic over AWS private backplanes without traversing the public internet.<br>• WAF rate-limiting protects edge endpoints against bot abuse. | `terraform/modules/zero-trust-kyc-vault/main.tf`<br>`terraform/modules/edge-api-waf/main.tf` |
| **SOC 2 Type II CC7.2 & CC7.3**<br>*(Security Monitoring & Incident Evaluation)* | The entity monitors system components to detect anomalies and evaluates security incidents. | • Multi-region AWS CloudTrail with log file validation enabled.<br>• CloudWatch security operations dashboard monitoring DLQ depths, API error rates, and SOAR execution.<br>• Metric alarms with automated SNS alerting. | `terraform/modules/observability/main.tf`<br>`terraform/modules/soar-engine/main.tf` |

---

## 2. Audit Verification & Evidence Summary

All controls defined above are subject to automated verification:
- **Static IaC Security**: Enforced via Checkov scans in GitHub Actions (`.github/workflows/devsecops-pipeline.yml`).
- **Unit & Logic Verification**: Verified via `pytest` with `moto` AWS mocks (`src/tests/`).
- **Container Shift-Left**: Enforced via Kyverno CLI in CI against `k8s-security-policies/`.
- **Live Incident Containment**: Simulated via `scripts/simulate_attack.sh`.
