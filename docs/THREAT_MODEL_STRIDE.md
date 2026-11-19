# PF-Shield Threat Model: STRIDE Methodology Analysis

## 1. Executive Summary & Context

This threat model analyzes the security posture of **PF-Shield — Zero-Trust Real Estate API & Automated Cloud SOAR**, an enterprise cloud security control plane and incident response platform deployed in the **United Arab Emirates (UAE)** (`me-central-1`).

Real estate platforms handle two high-value classes of digital assets:
1. **Proprietary Market Data (Listings & Analytics)**: Property catalogs, market pricing indices, and broker directory records subject to automated competitor scraping, inventory scraping, and denial-of-wallet DDoS attacks.
2. **Confidential Personal Data (Broker & Tenant PII)**: UAE Emirates IDs, passport biometric scans, and RERA title deeds subject to targeted data exfiltration, unauthorized cross-tenant access, privilege escalation, and regulatory breach under **UAE Personal Data Protection Law (PDPL - Federal Decree-Law No. 45 of 2021)**.

This threat model decomposes the platform into **8 discrete Trust Boundaries** and systematically evaluates threat vectors using the Microsoft **STRIDE** taxonomy (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

---

## 2. Platform Architecture & Trust Boundaries

```
[ External Internet / Scrapers / Threat Actors ]
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 1: Edge CDN & Global Protection Layer (CloudFront + AWS Shield Standard)
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── CloudFront Distribution (HTTP/3, TLS 1.3, GCC Geo-Restriction)
       ├── Response Security Headers (HSTS Preload, X-Frame-Options, X-Content-Type)
       └── Custom Origin Authentication Header: X-Origin-Verify (High-Entropy Secret)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 2: Web Application Firewall Inspection (AWS WAFv2 Regional)
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── Scraper IP Rate Limiting (>100 req / 5 min)
       ├── Broker Upload Path Protection (>50 req / 5 min on /kyc)
       ├── AWS Managed Common Rule Set (CRS - OWASP Top 10)
       ├── AWS Managed SQL Injection (SQLi) Protections
       ├── AWS Managed Known Bad Inputs & Log4j (CVE-2021-44228) Rule Set
       └── AWS Managed Amazon IP Reputation List (Tor, Scanners, Botnets)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 3: Ingress & Authentication Layer (API Gateway / ALB + Cognito User Pool)
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── Amazon Cognito User Pool (OIDC Issuer, JWT Signing, custom:tenant_id, custom:broker_id)
       ├── API Gateway HTTP API v2 (Native JWT Authorizer, Route Throttling)
       └── Public Application Load Balancer (TLS 1.3 Strict Termination, X-Origin-Verify Validation)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 4: Workload Compute Tier (ECS Fargate Containers & Serverless Handlers)
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── Non-Root Task Execution (Dedicated appuser UID 10001, GID 10001)
       ├── Read-Only Root Filesystem (Prevent runtime binary modification)
       ├── ECR Immutable Repositories (Scan on Push, KMS CMK Encrypted)
       └── Serverless Microservices (Listings API, KYC Presign API, Document Scanner Worker)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 5: Private Network Isolation (Multi-Tier VPC 10.20.0.0/16)
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── Public Subnets (10.20.10.0/24, 10.20.11.0/24): ALB & Ingress Only
       ├── Private Application Subnets (10.20.1.0/24, 10.20.2.0/24): ECS Tasks, Zero Public IP
       ├── Private Database Subnets (10.20.20.0/24, 10.20.21.0/24): RDS PostgreSQL & ClickHouse Lab
       ├── VPC Gateway Endpoints: com.amazonaws.me-central-1.s3 & dynamodb ($0.00 / hr)
       └── VPC Flow Logs: CloudWatch Log Group with KMS CMK Encryption
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 6: Persistent Data Stores & Encryption (RDS + DynamoDB + S3 + KMS CMK)
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── S3 Broker KYC Vault (Triple-Deny Perimeter, S3 Bucket Keys, KMS CMK)
       ├── S3 Immutable Audit Destination (Object Lock in COMPLIANCE mode, WORM)
       ├── S3 Analytics Data Lake (Partitioned raw/ & curated/, Glue ETL PII Scrubbing)
       ├── Amazon RDS PostgreSQL 16 (Forced TLS rds.force_ssl=1, Secrets Manager Credentials)
       ├── ClickHouse Analytics Lab (IMDSv2 Hop Limit 1, Zero SSH, SSM Session Manager Only)
       └── DynamoDB Tables (KMS Encrypted, PAY_PER_REQUEST, Point-in-Time Recovery)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 7: Detective Governance & Automated SOAR Engine
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── CloudTrail Multi-Region Trail + S3 Data Event Logging (kyc-documents/*)
       ├── AWS Config Continuous Compliance (8 Managed Rules)
       ├── EventBridge Rules (Decoupled Schemas, SQS Dead Letter Queues)
       ├── DynamoDB Idempotency Table (pf-soar-idempotency, Conditional Writes)
       ├── Protected-Principals Allowlist (Bypass quarantine for root, break-glass, CI)
       └── Automated Playbooks: S3 Lockdown & IAM Quarantine (MTTR < 1.5s)
                       │
═══════════════════════╪═══════════════════════════════════════════════════════════════
 TRUST BOUNDARY 8: Software Supply Chain & DevSecOps CI/CD
═══════════════════════╪═══════════════════════════════════════════════════════════════
       ├── 100% Immutable Commit SHA Pinning for all GitHub Actions
       ├── GitHub OIDC Assume-Role Trust Scoped to Branch & Environment
       ├── Pre-Merge Multi-Stage Scans: Gitleaks, Semgrep SAST, Checkov IaC, Trivy, CycloneDX
       └── Dependabot Automated Vulnerability Monitoring (Actions, Python, Terraform, Docker)
```

---

## 3. Comprehensive STRIDE Threat Analysis Matrix

| ID | STRIDE Category | Threat Scenario | Threat Actor | Impact | Severity | Implemented Technical Mitigation | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Spoofing** | Adversary crafts forged JWTs or injects caller-supplied `broker_id` / `tenant_id` to impersonate legitimate brokers. | Rogue Broker / Attacker | Unauthorized document upload into arbitrary tenant prefix. | **Critical** | • API Gateway & FastAPI enforce strict cryptographic RS256 signature verification against Cognito JWKS (`kid`, `iss`, `aud`/`client_id`, `token_use`, `exp`).<br>• Server-side handler extracts identity from cryptographically validated claims.<br>• Caller-supplied identity fields in request bodies are rejected and ignored.<br>• Regex validation enforces `^[a-zA-Z0-9_-]{3,64}$`. | [`test_kyc_vault_handler.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_kyc_vault_handler.py), [`test_services.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_services.py) |
| **TH-02** | **Spoofing** | Threat actor queries ALB directly via DNS, bypassing CloudFront WAF and geo-restriction. | Direct Scanner / Botnet | Bypass of rate limiting, geo-fencing, and WAF inspection. | **High** | • Custom domain `api.<domain>` with dedicated `us-east-1` ACM certificate and dual Route 53 A and AAAA ALIAS records routing traffic to CloudFront.<br>• CloudFront forwards high-entropy secret header `X-Origin-Verify`.<br>• ALB listener rules strictly enforce header presence, returning HTTP 403 on missing or invalid secrets.<br>• Public ALB TLS certificate issued via ACM and validated via Route 53 DNS records. | [`test_edge_security_and_waf.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_edge_security_and_waf.py) |
| **TH-03** | **Tampering** | Rogue administrator or compromised role modifies S3 Public Access Block or bucket policy to expose KYC PII. | Compromised Identity / Insider | Public exposure of UAE Emirates IDs and passports. | **Critical** | • IAM Workload Permission Boundary denies `s3:PutBucketPublicAccessBlock` & `s3:DeleteBucketPolicy`.<br>• SOAR EventBridge rule detects public exposure.<br>• Automated S3 Lockdown playbook re-enforces all 4 public access blocks in < 1.5s. | [`test_soar_s3_lockdown.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_soar_s3_lockdown.py) |
| **TH-04** | **Tampering** | Malicious actor modifies container binaries or uploads malware into KYC document repository. | Container Exploit Attacker / Malicious Broker | Backdoored workload container or malware persistence in KYC vault. | **High** | • ECS tasks execute with `readonly_root_filesystem = true` and unprivileged `appuser` (UID 10001).<br>• ECR image immutability (`MUTABLE = false`) and vulnerability scan on push.<br>• Event-driven Document Scanner polls encrypted SQS queue triggered by S3 ObjectCreated via EventBridge.<br>• Enforces object-key allowlist regex, magic-bytes validation, EICAR pattern detection, S3 quarantine tagging, and SNS alerts. | [`test_services.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_services.py) |
| **TH-05** | **Tampering** | Attacker tampers with historical security audit trails or deletes CloudTrail logs to cover tracks. | Advanced Persistent Threat | Inability to perform forensic incident reconstruction; PDPL violation. | **Critical** | • Immutable S3 audit destination with **S3 Object Lock** in **`COMPLIANCE`** mode (WORM).<br>• Retention locked for compliance duration; cannot be deleted even by AWS root.<br>• KMS CMK encryption with restricted key policy. | [`test_disaster_recovery.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_disaster_recovery.py) |
| **TH-06** | **Repudiation** | Rogue insider disables CloudTrail logging or purges EventBridge rules to avoid detection. | Malicious Insider | Undetected exfiltration and unlogged operations. | **Critical** | • Workload Permission Boundary explicitly denies `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, and `events:DeleteRule`.<br>• Dedicated CloudWatch and S3 audit streams with independent IAM trust boundaries. | [`terraform/modules/iam-boundaries/`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/iam-boundaries/) |
| **TH-07** | **Repudiation** | Attacker accesses or exfiltrates KYC documents directly from S3 without leaving audit evidence. | Malicious Caller | Silent PII exfiltration without forensic trace. | **High** | • CloudTrail S3 Data Events enabled on `kyc-documents/*`, recording every `GetObject`, `PutObject`, and `DeleteObject` event with caller ARN, IP, and timestamp. | [`terraform/modules/soar-engine/main.tf`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/soar-engine/main.tf) |
| **TH-08** | **Information Disclosure** | Competitor botnet scrapes public listing catalog, degrading competitive advantage and business value. | Competitor Aggregator | Wholesale real estate catalog extraction. | **High** | • CloudFront GCC geo-restriction (whitelists designated GCC/US/GB regions).<br>• WAF rate limit (100 req / 5 min).<br>• API Gateway stage throttling (25 rps / 50 burst). | [`test_edge_security_and_waf.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_edge_security_and_waf.py) |
| **TH-09** | **Information Disclosure** | External threat actor attempts direct `s3:GetObject` on the KYC vault bucket from outside the corporate perimeter. | External Attacker | PII exfiltration over the public internet. | **Critical** | • S3 Triple-Deny Data Perimeter policy (decoupled into standalone leaf module [`terraform/modules/s3-data-perimeter/`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/s3-data-perimeter/)) denies all access if `aws:SourceVpce != vpce-xxx` AND caller is not an authorized KYC/SOAR role.<br>• Dynamic expansion of allowed IAM roles into STS assumed-role wildcards (`arn:aws:sts::<acct>:assumed-role/<role>/*`) using `ArnNotLike: aws:PrincipalArn` ensures external presigned uploads signed by ECS task roles are not blocked.<br>• Denies unencrypted transport (`aws:SecureTransport == false`).<br>• Denies uploads not encrypted with designated KMS CMK. | [`test_services.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_services.py), [`terraform/modules/s3-data-perimeter/`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/s3-data-perimeter/) |
| **TH-10** | **Information Disclosure** | Man-in-the-Middle (MitM) eavesdropping on database transit traffic between ECS tasks and Amazon RDS. | Network Eavesdropper | Exposure of plaintext customer data and queries. | **High** | • RDS parameter group enforces `rds.force_ssl = "1"`.<br>• Relational database isolated in private subnets with 0 internet routes.<br>• Master database credentials managed via Secrets Manager with KMS CMK encryption. | [`test_analytics_and_database.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_analytics_and_database.py) |
| **TH-11** | **Information Disclosure** | SSRF attack on ClickHouse analytics EC2 host extracts IAM role credentials via legacy IMDSv1. | SSRF Attacker | Cloud account compromise via stolen metadata credentials. | **Critical** | • Host metadata enforces IMDSv2 strictly (`http_tokens = "required"`).<br>• Hop limit locked to `http_put_response_hop_limit = 1` (blocks proxy SSRF).<br>• Zero SSH ingress (port 22 closed); management exclusively via AWS SSM Session Manager. | [`test_analytics_and_database.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_analytics_and_database.py) |
| **TH-12** | **Information Disclosure** | Analytics data lake exposes raw landlord and broker PII in uncurated data dumps. | Analytics User | UAE PDPL violation through unvetted PII exposure. | **High** | • AWS Glue ETL pipeline ([`glue_etl_sanitize_listings.py`](file:///Users/Yousef/pf-shield-cloud-security/src/analytics/glue_etl_sanitize_listings.py)) strips phone numbers, emails, and Emirates IDs.<br>• Produces deterministic salted SHA-256 pseudonyms (`anonymized_broker_hash`). | [`test_analytics_and_database.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_analytics_and_database.py) |
| **TH-13** | **Denial of Service** | Volumetric Layer 3/4 SYN floods or Layer 7 HTTP floods exhaust compute resources and inflate cloud bills. | DDoS Botnet | Platform downtime, wallet-denial (economic exhaustion). | **High** | • AWS Shield Standard native Layer 3/4 protection ($0.00).<br>• CloudFront global CDN absorption.<br>• WAF rate-limiting rules on `/kyc` and root paths.<br>• AWS Budgets alerts at 80% and 100% of $5/mo limit. | [`test_edge_security_and_waf.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_edge_security_and_waf.py) |
| **TH-14** | **Denial of Service** | Malicious event replay floods SOAR engine, quarantining legitimate admin or service roles. | Malicious Insider | Operational denial of service across deployment pipelines. | **High** | • Protected-Principals allowlist protects `root`, `pf-shield-github-actions`, and `break-glass` roles.<br>• DynamoDB deduplication table (`pf-soar-idempotency`) with conditional writes prevents duplicate remediation replays. | [`test_soar_iam_quarantine.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_soar_iam_quarantine.py) |
| **TH-15** | **Elevation of Privilege** | Compromised developer credentials or CI/CD runner creates an unconstrained IAM role with AdministratorAccess. | Compromised Identity | Full AWS account takeover. | **Critical** | • Decoupled scoped permission boundaries (ECS execution, ECS tasks, AWS Config, AWS Glue, RDS monitoring, SSM EC2) enforce least privilege and prevent boundary sprawl.<br>• Workload Permission Boundary denies `iam:CreateRole` unless the new role attaches the boundary ARN.<br>• SOAR IAM Quarantine playbook detects privilege escalation and attaches `pf-soar-quarantine-deny-all` in < 1.5s.<br>• Deactivates all active access keys. | [`test_soar_iam_quarantine.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_soar_iam_quarantine.py), [`terraform/modules/iam-boundaries/`](file:///Users/Yousef/pf-shield-cloud-security/terraform/modules/iam-boundaries/) |
| **TH-16** | **Elevation of Privilege** | Supply chain poisoning: third-party GitHub Action mutates tags to inject malicious code during deployment. | Supply Chain Attacker | Backdoored deployment into AWS production account. | **Critical** | • 100% of GitHub Actions pinned to immutable 40-character commit SHAs.<br>• GitHub Actions OIDC assume-role trust policy strictly scoped to `main` branch, `production` environment, and pull requests.<br>• Dependabot monitors updates with cryptographic SHA references. | [`test_ci_cd_and_supply_chain.py`](file:///Users/Yousef/pf-shield-cloud-security/src/tests/test_ci_cd_and_supply_chain.py) |

---

## 4. Residual Risk Assessment & Acceptance Matrix

| Risk ID | Residual Risk Description | Risk Acceptance Rationale | Compensating Security Controls | Review Frequency |
| :--- | :--- | :--- | :--- | :--- |
| **RR-01** | **WAF Disabled in Demo Profile** (`demo.tfvars`): When running the low-cost evaluation profile, AWS WAFv2 is disabled to achieve $0.00 idle run rate. | Acceptable for non-production demonstration, automated unit testing, and sandbox verification. | API Gateway native stage rate-limiting (25 rps / 50 burst) remains active at $0.00 cost; WAF is unconditionally enabled in `production.tfvars`. | Quarterly |
| **RR-02** | **KMS CMK Baseline Cost ($1.00/mo)**: Incurring $1/month per Customer Managed Key in demo environment. | Justified to demonstrate envelope encryption, cryptographic separation, and key rotation per UAE PDPL Art. 13. | S3 Bucket Keys reduce operational request costs by 99% ($0.003/mo). | Annual |
| **RR-03** | **Shield Standard vs Shield Advanced**: Shield Advanced ($3,000/mo + 1-year commit) is omitted. | Platform volume does not justify $36,000/year minimum spend. | AWS Shield Standard ($0.00) handles Layer 3/4 attacks; CloudFront CDN absorbs volumetric edge traffic; WAF rate-limiting protects Layer 7. | Semi-Annual |
| **RR-04** | **ClickHouse Host Bastionless Administration**: EC2 ClickHouse node relies on SSM Session Manager without direct console access. | Eliminates SSH exposure (port 22 closed), brute-force vectors, and SSH key management overhead. | SSM Session Manager commands are encrypted via KMS and fully logged to CloudWatch Logs with audit retention. | Semi-Annual |
| **RR-05** | **CloudFront Custom Domain & us-east-1 ACM Certificate**: Regional resources reside in `me-central-1`, whereas CloudFront SSL/TLS certificates require global provisioning in `us-east-1`. | Production environment uses aliased provider `aws.us_east_1` to provision dedicated ACM certificate for `api.<domain>` with automated Route 53 validation and dual A/AAAA ALIAS routing; demo profile defaults to standard CloudFront domain. | TLS 1.3 enforced; production custom domains require us-east-1 ACM certificate validation with Route 53 DNS records. | Annual |
