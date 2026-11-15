# Incident Response Runbook 02: S3 KYC Vault Public Exposure & Exfiltration Attempt

## 1. Overview & Severity
- **Incident Code**: `SEC-IR-S3-02`
- **Severity**: **Critical (P1)**
- **Target Systems**: S3 Broker KYC Vault, KMS Customer Managed Key, EventBridge, SOAR Lambda (`pf-soar-s3-lockdown`)
- **Regulatory Framework**: UAE Personal Data Protection Law (Federal Decree-Law No. 45 of 2021) Articles 13 & 14
- **Objective**: Instantly contain attempts to modify S3 Public Access Block, disable encryption, or exfiltrate broker/tenant Emirates IDs, passports, or title deeds.

---

## 2. Automated SOAR Containment Workflow

```
[ Attacker / Compromised Principal ]
              │ (Calls PutBucketPublicAccessBlock [false] or Exfiltrates Objects)
              ▼
    [ AWS CloudTrail / GuardDuty S3 Protection ]
              │ (Emits event within seconds)
              ▼
   [ EventBridge Rule: pf-s3-tamper-or-exfiltration ]
              │
              ├──► [ SQS Dead Letter Queue ] (DLQ Depth Alarm Monitors Alert Drops)
              ▼
   [ SOAR Lambda Playbook: playbook_s3_lockdown.py ]
              ├── 1. Calls s3.put_public_access_block(all 4 flags = True)
              ├── 2. Isolates offending IAM principal with 'pf-soar-quarantine-deny-all'
              ├── 3. Emits 'MeanTimeToRemediate' Metric to CloudWatch
              └── 4. Publishes Structured Forensic Report to SNS
```

---

## 3. Step-by-Step Incident Response Protocol

### Phase 1: Automated Containment Verification (< 5 Minutes)
1. **Verify S3 Public Access Block Restored**:
   ```bash
   aws s3api get-public-access-block --bucket <kyc-vault-bucket-name>
   # Output must strictly verify:
   # "BlockPublicAcls": true,
   # "IgnorePublicAcls": true,
   # "BlockPublicPolicy": true,
   # "RestrictPublicBuckets": true
   ```
2. **Verify Offending Identity Quarantined**:
   - Check SNS forensic email for `offending_principal`.
   - Verify `pf-soar-quarantine-deny-all` is attached to the principal.
3. **Verify S3 Bucket Policy Intact**:
   - Confirm zero-trust data perimeter statements (TLS enforcement, SSE-KMS enforcement, VPC Gateway Endpoint restriction) were not deleted.

### Phase 2: Forensic Analysis & Data Leakage Assessment
1. **Identify Exfiltration Scope via Athena**:
   ```sql
   SELECT eventTime, eventName, requestParameters, responseElements, sourceIPAddress
   FROM cloudtrail_logs
   WHERE requestParameters LIKE '%<kyc-vault-bucket-name>%'
     AND (eventName = 'GetObject' OR eventName = 'PutBucketPublicAccessBlock' OR eventName = 'DeleteBucketPolicy')
     AND eventTime >= current_timestamp - interval '24' hour
   ORDER BY eventTime DESC;
   ```
2. **Determine Personal Data Affected**:
   - Were Emirates IDs, passports, or RERA title deeds downloaded?
   - Count distinct object keys accessed by the compromised principal.

### Phase 3: UAE PDPL Regulatory Breach Assessment (Article 14)
Under UAE Federal Decree-Law No. 45 of 2021 Article 14:
- If personal data was breached or disclosed, the Data Controller **must notify the UAE Data Office immediately**.
- If the breach severely compromises the privacy or rights of data subjects, the affected data subjects must be notified with recommended protective measures.

### Phase 4: Eradication & Hardening
1. Re-verify VPC Gateway Endpoint routing: ensure KYC traffic only flows across `com.amazonaws.me-central-1.s3` route table associations.
2. Confirm KMS key policy: ensure only the KYC Lambda Role and root account have access to `pf_kyc_cmk`.
3. Clear any cached presigned URLs by updating the KMS key grant or revoking role sessions.

---

## 4. UAE Data Office Breach Notification Template

```text
To: UAE Data Office (compliance@dataoffice.gov.ae)
Subject: Incident Notification under Federal Decree-Law No. 45 of 2021 — Property Finder

1. Data Controller Name: Property Finder (UAE)
2. Incident Timestamp: YYYY-MM-DD HH:MM UTC
3. Containment Timestamp: YYYY-MM-DD HH:MM UTC (SOAR MTTR: <X> seconds)
4. Nature & Description of Incident:
   Attempted unauthorized S3 policy modification / access on Broker KYC Vault.
5. Categories of Personal Data Involved:
   [Emirates ID copies / Passport scans / RERA Title Deeds]
6. Approximate Number of Data Subjects Affected: [0 if contained before exfiltration, or N]
7. Remediation & Protective Measures Implemented:
   - Automated SOAR S3 PublicAccessBlock restoration (< 2 seconds)
   - Immediate IAM identity quarantine
   - VPC endpoint data perimeter verified intact
```
