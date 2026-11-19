# PF-Shield: Regulatory Compliance Mapping, Privacy Governance & Risk Register

> [!IMPORTANT]
> **Legal Notice & Technical Compliance Boundary**:
> This document details the **technical and architectural security controls** engineered into PF-Shield to support alignment with the UAE Personal Data Protection Law (Federal Decree-Law No. 45 of 2021), ISO/IEC 27001:2022, SOC 2 Type II, NIST CSF 2.0, and CIS AWS Foundations Benchmark v3.0.
> **Selecting an AWS UAE sovereign data center (`me-central-1`) and implementing cloud cryptographic controls represent foundational technical prerequisites, but do not constitute legal compliance on their own.** Full statutory compliance requires formal organizational review, board-approved privacy policies, statutory appointment/registration of a Data Protection Officer (DPO), and continuous legal assessments.

---

## 1. Multi-Standard Compliance Cross-Reference Matrix

| Standard & Article / Control | Mandated Requirement | PF-Shield Architectural Implementation | Repository Enforcement Location |
| :--- | :--- | :--- | :--- |
| **UAE PDPL Art. 13**<br>*(Security of Personal Data)* | Controllers must implement technical and organizational measures to protect personal data from unauthorized access, breach, alteration, or disclosure. | • S3 KYC Vault guarded by triple-deny data perimeter policy.<br>• Envelope encryption via dedicated KMS Customer Managed Key (CMK) with annual rotation.<br>• Automated SOAR lockdown restoring Public Access Block within seconds. | [`terraform/modules/zero-trust-kyc-vault/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/zero-trust-kyc-vault/main.tf)<br>[`src/soar/playbook_s3_lockdown.py`](file:///Users/Yousef/pf-shield-cloud-security/src/soar/playbook_s3_lockdown.py) |
| **UAE PDPL Art. 22 & 23**<br>*(Cross-Border Transfer & Sovereign Residency)* | Personal data may not be transferred outside the UAE unless the destination territory provides an adequate level of protection. Storage must remain within sovereign boundaries. | • Deployment locked to AWS UAE region `me-central-1`.<br>• IAM Permission Boundary denies actions where `aws:RequestedRegion != me-central-1`.<br>• Cross-region replication intentionally disabled (`CKV_AWS_144`). | [`terraform/providers.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/providers.tf)<br>[`terraform/modules/iam-boundaries/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/iam-boundaries/main.tf) |
| **UAE PDPL Art. 9**<br>*(Data Protection by Design & Default)* | Systems must enforce least privilege, data minimization, and automated retention lifecycles by default. | • S3 Lifecycle rules automatically transition KYC documents to `STANDARD_IA` at 30 days and Glacier at 90 days.<br>• Data routed strictly over private VPC Gateway Endpoints ($0.00 internet traversal). | [`terraform/modules/zero-trust-kyc-vault/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/zero-trust-kyc-vault/main.tf)<br>[`terraform/modules/network/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/network/main.tf) |
| **UAE PDPL Art. 14**<br>*(Statutory Breach Notification)* | Controllers must immediately notify the UAE Data Office and data subjects upon discovering any breach or exposure of personal data. | • EventBridge rule captures S3 public access modifications and GuardDuty exfiltration findings in real time.<br>• SOAR engine publishes structured forensic reports to SNS (`pf-security-incidents`) with MTTR telemetry. | [`terraform/modules/soar-engine/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/soar-engine/main.tf)<br>[`src/soar/playbook_s3_lockdown.py`](file:///Users/Yousef/pf-shield-cloud-security/src/soar/playbook_s3_lockdown.py) |
| **ISO/IEC 27001:2022 A.5.15**<br>*(Access Control)* | Rules to control physical and logical access to information and systems must be established and documented. | • IAM Permission Boundary enforces maximum permissions ceiling across all workload roles.<br>• Denies `iam:CreateRole` unless the boundary ARN is attached.<br>• Denies boundary tampering or deletion. | [`terraform/modules/iam-boundaries/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/iam-boundaries/main.tf) |
| **ISO/IEC 27001:2022 A.8.12**<br>*(Data Leakage Prevention)* | Data leakage prevention measures must be applied to systems processing sensitive information. | • S3 Data Perimeter enforces `aws:SourceVpce` and restricts caller principals.<br>• Server-side prefix derivation prevents tenant/broker namespace traversal.<br>• API Gateway & WAF rate limits block bulk scraping. | [`terraform/modules/zero-trust-kyc-vault/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/zero-trust-kyc-vault/main.tf)<br>[`services/broker-kyc-api/app/main.py`](file:///Users/Yousef/pf-shield-cloud-security/services/broker-kyc-api/app/main.py) |
| **ISO/IEC 27001:2022 A.8.20**<br>*(Network Security)* | Networks must be secured and controlled to protect information in systems and applications. | • Multi-tier VPC (`10.20.0.0/16`) with private application and database subnets (no public IPs).<br>• Default security groups closed with 0 ingress and 0 egress rules.<br>• ALB terminates TLS 1.3 at edge; HTTP redirects to HTTPS. | [`terraform/modules/network/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/network/main.tf)<br>[`terraform/modules/container-platform/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/container-platform/main.tf) |
| **ISO/IEC 27001:2022 A.8.24**<br>*(Use of Cryptography)* | Cryptographic controls must be defined and implemented for key management and data protection. | • Dedicated KMS Customer Managed Key with annual automatic rotation.<br>• S3 Bucket Keys enabled reducing KMS request overhead by 99%.<br>• Parameter group enforces `rds.force_ssl = "1"`; TLS 1.2+ on all endpoints. | [`terraform/modules/zero-trust-kyc-vault/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/zero-trust-kyc-vault/main.tf)<br>[`terraform/modules/rds/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/rds/main.tf) |
| **ISO/IEC 27001:2022 A.8.14**<br>*(Redundancy & Availability)* | Information processing facilities must be implemented with redundancy to meet availability requirements. | • Multi-AZ RDS PostgreSQL standby deployment in production.<br>• S3 Versioning Delete Marker rollback (RPO < 15 min).<br>• Continuous DynamoDB Point-in-Time Recovery (PITR) across 35 days. | [`terraform/modules/rds/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/rds/main.tf)<br>[`docs/runbooks/RUNBOOK-03-Disaster-Recovery-And-Backup-Restoration.md`](file:///Users/Yousef/pf-shield-cloud-security/docs/runbooks/RUNBOOK-03-Disaster-Recovery-And-Backup-Restoration.md) |
| **SOC 2 Type II CC6.1**<br>*(Logical Access Controls)* | The entity restricts logical access to registered and authorized users, devices, and applications. | • Amazon Cognito User Pool with JWT token validation at API Gateway.<br>• Application claims verification enforcing tenant and broker boundaries.<br>• Automated IAM quarantine deactivates compromised keys within seconds. | [`terraform/modules/identity/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/identity/main.tf)<br>[`src/soar/playbook_iam_quarantine.py`](file:///Users/Yousef/pf-shield-cloud-security/src/soar/playbook_iam_quarantine.py) |
| **SOC 2 Type II CC6.6**<br>*(Boundary Protection)* | The entity implements logical boundaries to protect assets from unauthorized intrusion. | • VPC Gateway Endpoints keep S3/DynamoDB traffic within AWS internal backplane.<br>• WAF WebACL rate-limiting defends against scrapers and brute-force uploads.<br>• CloudFront origin custom header verification (`X-Origin-Verify`). | [`terraform/modules/edge-api-waf/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/edge-api-waf/main.tf)<br>[`terraform/modules/container-platform/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/container-platform/main.tf) |
| **SOC 2 Type II CC7.2 & CC7.3**<br>*(Monitoring & Incident Evaluation)* | The entity monitors components to detect anomalies and evaluate incidents. | • Multi-region CloudTrail with KMS CMK encryption and S3 data events.<br>• Centralized audit bucket protected with S3 Object Lock in COMPLIANCE mode.<br>• Proactive CloudWatch metric alarms for WAF blocks, DLQ depth, and ALB errors. | [`terraform/modules/soar-engine/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/soar-engine/main.tf)<br>[`terraform/modules/observability/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/observability/main.tf) |
| **NIST CSF 2.0 (PR.DS / DE.CM)**<br>*(Data Security & Continuous Monitoring)* | Data at rest and in transit are protected; network perimeters and configurations are continuously monitored. | • AWS Config continuously records account configuration against 8 managed rules.<br>• Secrets Manager manages database credentials with automated rotation support.<br>• Microservices execute as unprivileged non-root user `10001:10001` with read-only root filesystems. | [`terraform/modules/compliance-baseline/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/compliance-baseline/main.tf)<br>[`services/listings-api/Dockerfile`](file:///Users/Yousef/pf-shield-cloud-security/services/listings-api/Dockerfile) |
| **CIS AWS Benchmark v3.0 (1.x, 2.x, 3.x)**<br>*(IAM, Storage & Logging Baselines)* | Hardened configurations for root credentials, IAM access keys, S3 public access, and CloudTrail audit trails. | • AWS Config rule `access-keys-rotated` flags credentials older than 90 days.<br>• S3 Public Access Block active on all buckets.<br>• CloudTrail log file validation and multi-region tracking enabled. | [`terraform/modules/compliance-baseline/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/compliance-baseline/main.tf)<br>[`terraform/modules/soar-engine/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/soar-engine/main.tf) |

---

## 2. Data Classification & Handling Policy

PF-Shield categorizes all enterprise information into four distinct security tiers:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               DATA CLASSIFICATION TIERS                                │
├─────────────────┬───────────────────────────────────┬──────────────────────────────────┤
│ Classification  │ Data Attributes / Types           │ Minimum Security Controls        │
├─────────────────┼───────────────────────────────────┼──────────────────────────────────┤
│ 1. Public       │ Approved property listings,       │ TLS 1.3 in transit, API Gateway  │
│                 │ public photos, community guides   │ burst rate limiting (anti-scrap) │
├─────────────────┼───────────────────────────────────┼──────────────────────────────────┤
│ 2. Internal     │ System telemetry, CloudWatch logs,│ IAM role authentication, 7-day   │
│                 │ build artifacts, sanitized metrics│ FinOps retention, VPC endpoint   │
├─────────────────┼───────────────────────────────────┼──────────────────────────────────┤
│ 3. Confidential │ Broker registration profiles,     │ Cognito JWT authorizer, KMS CMK  │
│                 │ agency contracts, analytics data  │ encryption at rest, Secrets Mgr  │
├─────────────────┼───────────────────────────────────┼──────────────────────────────────┤
│ 4. Restricted   │ Emirates IDs, Passports, Title    │ Triple-Deny S3 policy, VPC-only  │
│    (PII / KYC)  │ Deeds, biometric/identity proofs  │ access, Object Lock WORM, KMS CMK│
└─────────────────┴───────────────────────────────────┴──────────────────────────────────┘
```

### Specific Handling Standards for Tier 4 (Restricted KYC PII):
1. **Never Accessible via Public Internet**: All retrieval and storage must pass through the VPC S3 Gateway Endpoint (`com.amazonaws.me-central-1.s3`).
2. **Server-Side Prefix Isolation**: Document keys are derived strictly on the server:
   `kyc-documents/{tenant_id}/{broker_id}/{doc_type}/{uuid}.{file_ext}`
3. **Mandatory Envelope Encryption**: Uploads without `x-amz-server-side-encryption: aws:kms` using the dedicated CMK are rejected at the S3 bucket policy boundary.
4. **ETL Scrubbing**: Analytics pipelines ([`glue_etl_sanitize_listings.py`](file:///Users/Yousef/pf-shield-cloud-security/src/analytics/glue_etl_sanitize_listings.py)) must strip and pseudonymize all Tier 4 identifiers before ingestion into analytical engines.

---

## 3. Data Inventory & Asset Register

| Asset ID | Data Description | Classification | Primary Storage | Encryption at Rest | Retention Period | Disposal Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `DA-01` | Broker KYC Documents (Emirates IDs, Passports) | Restricted PII | Amazon S3 (`kyc_vault`) | KMS CMK (`aws:kms`) | 365 Days Prod / 7 Days Demo | S3 Lifecycle Expiration |
| `DA-02` | Real Estate Listings Catalog | Public | DynamoDB (`properties`) | KMS CMK (`aws:kms`) | Active lifecycle | Table record deletion |
| `DA-03` | Relational Metadata Store | Confidential | Amazon RDS PostgreSQL | KMS CMK (`gp3` encrypted) | 35 Days continuous WAL | Automated snapshot purge |
| `DA-04` | Curated Market Analytics Parquet | Internal | Amazon S3 (`analytics`) | KMS CMK (`aws:kms`) | 90 Days IA / 180 Days Glacier | S3 Lifecycle transition |
| `DA-05` | Central CloudTrail Audit Logs | Restricted Audit | Amazon S3 (`audit_logs`) | KMS CMK + Object Lock | 365 Days COMPLIANCE mode | WORM expiration |
| `DA-06` | Database Administrative Credentials | Confidential | AWS Secrets Manager | KMS CMK (`aws:kms`) | Dynamic rotation | Automated rotation schedule |
| `DA-07` | VPC Flow Logs & Telemetry | Internal | CloudWatch Log Groups | KMS CMK (`aws:kms`) | 7 Days FinOps retention | CloudWatch log expiration |

---

## 4. End-to-End Data Flow Architecture (DFD)

```
[ Broker / User ] ──(1. HTTPS/TLS 1.3)──► [ Amazon CloudFront + WAFv2 ]
                                                      │ (2. Validates X-Origin-Verify)
                                                      ▼
                                       [ Application Load Balancer ]
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼ (3. JWT Bearer)                                             ▼ (4. Public Catalog Query)
         [ broker-kyc-api (ECS) ]                                       [ listings-api (ECS) ]
                       │                                                             │
        (Validates claims & derives                                            (Queries DynamoDB
       server-side isolated prefix)                                              via VPC Endpoint)
                       │                                                             │
         5. Issues Presigned POST                                                    ▼
                       │                                                  [ DynamoDB Properties ]
                       ▼
       [ S3 KYC Vault (Private Bucket) ] ◄──(Triple-Deny Data Perimeter)
                       │
             6. S3 Upload Event
                       │
                       ▼
      [ document-scan-worker (ECS) ]
         • Validates magic bytes
         • Scans for EICAR / malware
         • Updates status: CLEAN / REJECTED
                       │
                       ▼
         [ DynamoDB Scan State Table ]
                       │
                       ▼ (Periodic Sanitization Trigger)
         [ AWS Glue PySpark/Python ETL ]
         • Strips Emirates IDs, emails, phone numbers
         • Generates salted SHA-256 broker hashes
                       │
                       ▼
     [ S3 Analytics Data Lake (Curated Parquet) ]
                       │
                       ▼ (Private Subnet Query)
    [ ClickHouse Analytics Demonstration Node ] (IMDSv2, SSM-only, zero SSH)
```

---

## 5. Data Protection Impact Assessment (DPIA) Template & Sample

### DPIA Executive Summary: Real Estate Broker Identity Verification

```markdown
### 1. Context & Scope of Processing
- **Data Controller**: Real Estate Technology Platform
- **Scope**: Processing broker national identity documents (Emirates IDs, Passports, Title Deeds) to satisfy regulatory anti-money laundering (AML) and broker licensing verification in the UAE.
- **Statutory Trigger**: UAE PDPL Article 21 (mandatory DPIA for processing sensitive personal data using automated systems).

### 2. Necessity & Proportionality Assessment
- **Lawful Basis**: Legal obligation (AML & Real Estate Regulatory Authority compliance) and contractual necessity.
- **Data Minimization**: Only the document front, back, and expiration date are processed. Free text fields are scrubbed.

### 3. Risk Identification & Mitigating Controls Matrix

| Risk ID | Identified Threat Vector | Inherent Risk | Implemented Mitigating Technical Controls | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| `R-01` | Unauthorized public exposure of S3 KYC documents | **Critical** | • S3 Public Access Block locked across all 4 flags.<br>• Triple-deny bucket policy enforcing TLS, KMS CMK, and VPC endpoint.<br>• Automated SOAR S3 lockdown playbook (< 1.5s MTTR). | **Low** |
| `R-02` | Cross-tenant broker document access | **High** | • Edge JWT authorizer validates custom claims.<br>• Server-side prefix derivation ignores client-supplied broker IDs.<br>• Presigned POST cryptographic conditions bound to exact key. | **Low** |
| `R-03` | Accidental or malicious document deletion | **High** | • S3 Versioning enabled with Delete Marker soft recovery.<br>• Immutable audit trail in S3 Object Lock COMPLIANCE mode.<br>• 35-day continuous DynamoDB PITR. | **Low** |
| `R-04` | Credential leakage in CI/CD pipeline | **High** | • Keyless GitHub Actions OIDC integration (zero long-lived AWS keys).<br>• Gitleaks pre-commit and push scanning.<br>• 100% immutable action commit SHA pinning. | **Low** |

### 4. DPO & Legal Sign-off Recommendation
Technical safeguards are verified to satisfy UAE PDPL Article 13 & 21 standards. Recommended for production deployment subject to annual re-certification.
```

---

## 6. Record of Processing Activities (RoPA) — UAE PDPL Art. 24

| Field | Record Details |
| :--- | :--- |
| **Controller Name & Jurisdiction** | PF-Shield Real Estate Platform, Dubai, United Arab Emirates |
| **DPO Contact** | `dpo@pf-shield.ae` |
| **Purposes of Processing** | 1. Verification of real estate broker professional licenses and national identity.<br>2. Validation of property listing ownership via title deed verification.<br>3. Aggregated market analytics and valuation indexing. |
| **Categories of Data Subjects** | Licensed Real Estate Brokers, Property Owners, Tenants |
| **Categories of Personal Data** | National Identity Numbers (Emirates ID), Passport Scans, Contact Numbers, Corporate Emails, Title Deed Numbers |
| **Recipient Categories** | Authorized Verification Personnel, AWS Sovereign Cloud Infrastructure (`me-central-1`) |
| **Cross-Border Transfers** | **None.** All personal data is strictly retained within AWS UAE (`me-central-1`). Standby failover is limited to Bahrain (`me-south-1`) under adequacy safeguards. |
| **Retention Schedules** | Active verification documents: 365 days post-verification. Audit trails: 365 days in WORM storage. |
| **Technical Security Summary** | KMS CMK envelope encryption, TLS 1.3, VPC Gateway Endpoints, S3 Object Lock, Automated SOAR Quarantine. |

---

## 7. Data Subject Access Request (DSAR) Protocol (PDPL Art. 15–18)

Data subjects have statutory rights to **Access (Art. 15)**, **Rectification (Art. 16)**, **Erasure (Art. 17)**, and **Restriction of Processing (Art. 18)**:

```
[ Data Subject Request ] ──► [ DPO Intake: dpo@pf-shield.ae ]
                                        │
                                        ▼ (Identity Verification < 48 Hours)
                             [ Cryptographic Proof of Identity ]
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼ (Request: Access / Export)                  ▼ (Request: Erasure / Right to be Forgotten)
   [ Locate Broker Prefix in KYC Vault ]          [ Verify Retention Exceptions ]
   `kyc-documents/{tenant}/{broker_id}/*`         (AML statutory hold vs. marketing PII)
                 │                                             │
                 ▼                                             ▼
   [ Extract Metadata from DynamoDB ]             [ Permanently Delete S3 Versions ]
   • Issue encrypted download link                • Call `delete_object(version_id)`
   • Delivery within 14 business days             • Scrub DynamoDB & RDS metadata records
                                                  • Issue written confirmation to Data Subject
```

- **Statutory Response SLA**: Maximum **30 calendar days** from verified identity receipt.
- **Audit Logging**: Every DSAR action is logged to the immutable CloudTrail audit bucket.

---

## 8. Cross-Border Data Transfer Assessment (PDPL Art. 22–23)

- **Primary Sovereign Data Boundary**: AWS Region `me-central-1` (Abu Dhabi / Dubai, UAE).
- **Secondary Regional Standby**: AWS Region `me-south-1` (Bahrain).
- **Transfer Impact Assessment (TIA)**:
  - UAE PDPL mandates that personal data shall not be transferred outside the UAE unless the destination territory has an adequate level of protection or an approved contractual exemption applies.
  - PF-Shield enforces regional locking via IAM Permission Boundary (`StringEquals aws:RequestedRegion = "me-central-1"`).
  - Cross-region S3 replication is intentionally disabled (`CKV_AWS_144`) to guarantee zero unintended cross-border data leakage.

---

## 9. Third-Party & Vendor Security Register

| Vendor / Service | Service Provided | Data Shared | Security Certifications | Review Frequency |
| :--- | :--- | :--- | :--- | :--- |
| **Amazon Web Services (AWS)** | Cloud Infrastructure (`me-central-1`) | Encrypted KYC Vault, RDS PostgreSQL, DynamoDB | ISO 27001, SOC 1/2/3, PCI-DSS Level 1, CSA STAR | Annual audit review |
| **GitHub Enterprise** | Source Code & CI/CD Runners | Codebase, IaC configs (zero persistent AWS keys) | SOC 2 Type II, ISO 27001 | Annual SOC review |
| **Sigstore / Cosign** | Container Attestation & Signing | Cryptographic signatures (no PII) | Open-source public good | Quarterly tool update |

---

## 10. Cryptographic Key Access & Rotation Review Policy

1. **Dedicated Customer Managed Key (CMK)**: The primary key `pf-kyc-cmk` is provisioned with annual automatic rotation (`enable_key_rotation = true`).
2. **Separation of Duties**: Workload roles have `kms:GenerateDataKey` and `kms:Decrypt` access only within the VPC data perimeter. IAM administration roles cannot decrypt S3 payloads without explicit audit logging.
3. **S3 Bucket Key Governance**: S3 Bucket Keys are enabled across all buckets (`bucket_key_enabled = true`), minimizing direct calls to the KMS API by 99% while preserving distinct cryptographic scopes.
4. **Key Access Review Cycle**: Security operations conducts quarterly audits of KMS grant lists and CloudTrail `KMS:Decrypt` access events.

---

## 11. Enterprise Risk & Control Register

| Risk ID | Threat Description | Inherent Risk | Implemented Control | Compensating Control | Accepted Risk | Control Owner |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-01` | Unauthorized S3 public exposure | High | Public Access Block (all 4 flags true) | EventBridge SOAR Lambda auto-remediation | None | SecOps Lead |
| `SEC-02` | Stolen developer credentials / privilege escalation | Critical | IAM Permission Boundary scoping actions to `me-central-1` | SOAR IAM quarantine auto-deactivates keys | Break-glass admin bypass | Cloud Security Lead |
| `SEC-03` | Supply chain action poisoning in CI/CD | High | 100% immutable 40-char commit SHA action pinning | Dependabot weekly automated updates | Minor delay in upstream patch adoption | DevOps Lead |
| `SEC-04` | Accidental deletion of KYC documents | High | S3 Versioning & DynamoDB continuous PITR | S3 Object Lock COMPLIANCE retention | Increased storage cost in production | Infrastructure Lead |
| `SEC-05` | DDoS volumetric exhaustion | Medium | AWS Shield Standard (Layer 3/4) | WAF rate-limiting (100 req/5m) | Volumetric floods exceeding 100 Gbps require Shield Advanced | Network Security Lead |
