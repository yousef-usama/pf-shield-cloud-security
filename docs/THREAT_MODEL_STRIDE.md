# PF-Shield Threat Model: STRIDE Methodology Analysis

## 1. Executive Summary & Context

This threat model analyzes the security posture of **PF-Shield**, an enterprise zero-trust real estate API and automated incident response (SOAR) architecture deployed in the **United Arab Emirates (UAE)** (`me-central-1`). 

The platform operates critical services handling both proprietary market data (property listings) and highly confidential personal data (broker and tenant Emirates IDs, passports, and title deeds). The threat model evaluates threats against these two core workloads under the Microsoft STRIDE framework:
1. **Public Property Listings API (`GET /api/v1/properties`)**: Subject to high-frequency competitor scraping, distributed denial-of-service, and OWASP Top 10 API attacks.
2. **Broker KYC Document Vault (`POST /api/v1/kyc/presign`)**: Subject to targeted identity exfiltration, unauthorized cross-account access, and privilege escalation.

---

## 2. System Architecture & Trust Boundaries

```
[ External Internet / Scrapers / Threat Actors ]
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 1: Edge Perimeter & Anti-Scraping Layer (API Gateway + WAF)
═══════════════════════╪═══════════════════════════════════════════════════════════════
                       ▼
           [ API Gateway HTTP API ]
           ├── Rate Limiting (25 rps / 50 burst)
           └── AWS WAFv2 (IP Rate Limiting & OWASP Rules)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 2: Serverless Compute Layer (Lambda arm64)
═══════════════════════╪═══════════════════════════════════════════════════════════════
           ├── Property API Handler (ReadOnly)
           └── KYC Presign Handler (Enforces SSE-KMS)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 3: Isolated Network Perimeter (VPC + Free Gateway Endpoints)
═══════════════════════╪═══════════════════════════════════════════════════════════════
           ├── VPC Gateway Endpoint: com.amazonaws.me-central-1.s3
           └── VPC Gateway Endpoint: com.amazonaws.me-central-1.dynamodb
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 4: Data Layer & Encryption (S3 KYC Vault + DynamoDB + KMS CMK)
═══════════════════════╪═══════════════════════════════════════════════════════════════
           ├── S3 KYC Vault (Triple-Deny Zero-Trust Policy + S3 Bucket Keys)
           ├── DynamoDB Properties Table (KMS Encrypted + PITR)
           └── KMS Customer Managed Key (Annual Key Rotation)
```

---

## 3. STRIDE Threat Analysis Matrix

| Threat Category | Specific Threat Scenario | Threat Actor | Impact | Severity | Implemented PF-Shield Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S — Spoofing** | Adversary attempts credential stuffing or masquerades as a legitimate broker requesting presigned upload URLs. | External Scraper / Fraudster | Fraudulent document injection into KYC vault. | High | • Lambda handler strictly validates document types (`emirates_id`, `passport`, `rera_title_deed`) and file extensions.<br>• Presigned URLs are short-lived (300s expiration).<br>• IAM roles protected by Permission Boundaries. | `src/app/kyc_vault_handler.py` unit validation |
| **T — Tampering** | Compromised IAM identity attempts to disable S3 Public Access Block or mutate bucket policies to expose KYC documents. | Compromised Broker Role / Rogue Admin | Exposure of sensitive UAE buyer/broker PII. | Critical | • `iam-boundaries` module enforces explicit Deny on `s3:PutBucketPublicAccessBlock` and `s3:DeleteBucketPolicy`.<br>• S3 Lockdown SOAR playbook re-enforces all 4 public access blocks in < 1.5 seconds. | `src/tests/test_soar_s3_lockdown.py` (passes 100%) |
| **R — Repudiation** | Attacker disables AWS CloudTrail or deletes audit trails to erase forensic footprint during data exfiltration. | Malicious Insider | Audit trail loss, non-compliance with UAE PDPL Art. 13 & ISO 27001. | Critical | • IAM Permission Boundary explicitly denies `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail`.<br>• Dedicated audit S3 bucket enforces MFA-delete, KMS encryption, and TLS-only transport. | `terraform/modules/iam-boundaries/main.tf` |
| **I — Information Disclosure** | Competitor bot farm scrapes proprietary property listings; attacker attempts direct S3 GetObject outside the VPC. | Competitor Aggregator / External Threat Actor | Loss of proprietary listings advantage; exfiltration of Emirates IDs. | High | • API Gateway stage throttling (25 rps) + WAF rate-limiting rule (100 req/5 min).<br>• S3 Data Perimeter policy denies `s3:GetObject` if `aws:SourceVpce != aws_vpc_endpoint.s3.id`.<br>• KMS Customer Managed Key envelope encryption. | `terraform/modules/zero-trust-kyc-vault/main.tf` |
| **D — Denial of Service** | Volumetric HTTP flood targeting Property Listings API to exhaust compute or trigger AWS billing surge (Wallet-Denial). | Botnet / Competitor | API latency degradation, unexpected cloud costs. | High | • Graviton2 `arm64` Lambda concurrency capped at `reserved_concurrent_executions = 10`.<br>• AWS Budgets alerts at 80% forecasted and 100% actual spend ($5/mo limit).<br>• API Gateway native burst throttling (50 burst / 25 rate). | `terraform/modules/finops-budget/main.tf` |
| **E — Elevation of Privilege** | Compromised developer or CI/CD runner creates an unconstrained IAM role with AdministratorAccess. | Compromised CI Runner / Compromised Role | Full cloud control-plane takeover. | Critical | • IAM Permission Boundary denies `iam:CreateRole` unless the new role attaches the boundary ARN.<br>• SOAR IAM Quarantine playbook detects privilege escalation and attaches deny-all policy in < 2 seconds. | `src/tests/test_soar_iam_quarantine.py` (passes 100%) |

---

## 4. Residual Risk Assessment & Acceptance

1. **WAF Toggle for FinOps ($0.00 Idle Spend)**:
   - *Risk*: When `enable_waf = false`, Layer 7 WAF inspection is bypassed, relying solely on API Gateway rate-limiting (25 rps).
   - *Mitigation*: Rate-limiting at the API Gateway HTTP API stage operates at $0 cost and mitigates 95% of basic web scrapers. WAF is enabled in production via a single Terraform variable.
2. **KMS Key Fee ($1.00/month)**:
   - *Residual Risk*: Incurring $1/mo for a dedicated Customer Managed Key.
   - *Acceptance Justification*: Provides cryptographic boundary separation, automated key rotation, and full compliance with UAE PDPL and ISO 27001 Annex A.8.24. S3 Bucket Keys reduce operational request costs by 99%.
