# Incident Response Runbook 03: Disaster Recovery, Data Restoration & Backup Procedures

## 1. Overview & Service Level Objectives (SLOs)
- **Incident Code**: `SEC-DR-REC-03`
- **Severity**: **Critical (P1 / P2)**
- **Target Systems**: Amazon S3 (KYC Vault & Immutable Audit Logs), Amazon DynamoDB, Amazon RDS PostgreSQL, AWS KMS
- **Compliance & Regulatory Framework**: UAE Personal Data Protection Law (Federal Decree-Law No. 45 of 2021), ISO/IEC 27001:2022 A.8.14 (Redundancy), NIST SP 800-34 Rev. 1
- **Disaster Recovery Objectives**:
  - **Recovery Time Objective (RTO)**: **< 60 minutes** (Total elapsed time from disaster declaration to full service availability).
  - **Recovery Point Objective (RPO)**: **< 15 minutes** (Maximum allowable data loss window; guaranteed by DynamoDB continuous PITR and RDS continuous automated snapshot transaction logging).

---

## 2. Architecture & Data Protection Baseline

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                PRIMARY REGION (me-central-1)                           │
│                                                                                        │
│  ┌───────────────────────┐   ┌───────────────────────────┐   ┌──────────────────────┐  │
│  │   Amazon S3 KYC Vault │   │    Amazon DynamoDB Tables │   │ Amazon RDS Aurora/PG │  │
│  │  - S3 Versioning (On) │   │  - Point-in-Time-Recovery │   │  - Automated Backups │  │
│  │  - SSE-KMS CMK        │   │    (PITR continuous 35d)  │   │    (Continuous WAL)  │  │
│  │  - MFA Delete Guard   │   │  - KMS CMK at rest        │   │  - Multi-AZ Failover │  │
│  └──────────┬────────────┘   └─────────────┬─────────────┘   └──────────┬───────────┘  │
│             │                              │                            │              │
│             ▼                              ▼                            ▼              │
│  ┌───────────────────────┐   ┌───────────────────────────┐   ┌──────────────────────┐  │
│  │ Version Rollback      │   │ Point-in-Time Restore     │   │ Point-in-Time / Snap │  │
│  │ Delete Marker Removal │   │ restore-table-to-pit      │   │ restore-db-instance  │  │
│  └───────────────────────┘   └───────────────────────────┘   └──────────────────────┘  │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │   Amazon S3 Immutable Audit Destination (pf-shield-audit-logs)                   │  │
│  │  - S3 Object Lock: COMPLIANCE Mode (WORM - Write Once, Read Many)                │  │
│  │  - Retention: 365 Days Production (7 Days Demo Profile)                          │  │
│  │  - Glacier Lifecycle Transition: 90 Days                                         │  │
│  │  - Cannot be deleted or overridden, even by root or AWS account administrators   │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Disaster Declaration & Triage Protocol

### Phase 1: Disaster Assessment & Scope Identification (< 10 Minutes)
1. **Identify the Failure Domain**:
   - **Scenario A (Data Tampering / Ransomware / Accidental Deletion)**: S3 objects deleted or corrupted; database tables modified or dropped.
   - **Scenario B (Storage Corruption / Component Outage)**: Primary RDS instance failure or DynamoDB table corruption.
   - **Scenario C (Regional Outage)**: Major AWS regional degradation in primary region (`me-central-1`).
2. **Declare Incident Level**:
   - P1: Active data loss, corruption of regulatory KYC documents, or complete API unavailability.
   - P2: Data corruption isolated to non-critical staging or single microservice table.
3. **Notify Disaster Recovery Response Team**:
   - Page Lead Cloud Security Engineer, Lead DevOps Engineer, and Incident Commander.

---

## 4. Step-by-Step Restoration Procedures

### Scenario A: S3 KYC Vault Object Restoration (Accidental Deletion or Tampering)
Because the KYC Vault bucket has **S3 Versioning enabled**, deleting an object without specifying a version ID creates a **Delete Marker** rather than permanently purging the data.

#### Procedure 1: Identifying & Removing Delete Markers
1. **List object versions and delete markers**:
   ```bash
   aws s3api list-object-versions \
     --bucket <kyc-vault-bucket-name> \
     --prefix kyc-documents/<tenant_id>/<broker_id>/
   ```
2. **Identify the Delete Marker version ID** in the output:
   ```json
   {
     "DeleteMarkers": [
       {
         "Owner": { "DisplayName": "aws", "ID": "..." },
         "Key": "kyc-documents/tenant-100/broker-50/passport/a1b2c3d4.pdf",
         "VersionId": "delete_marker_version_id_here",
         "IsLatest": true
       }
     ]
   }
   ```
3. **Remove the Delete Marker to restore the previous active version**:
   ```bash
   aws s3api delete-object \
     --bucket <kyc-vault-bucket-name> \
     --key "kyc-documents/tenant-100/broker-50/passport/a1b2c3d4.pdf" \
     --version-id "delete_marker_version_id_here"
   ```
4. **Verify restoration**:
   ```bash
   aws s3api head-object \
     --bucket <kyc-vault-bucket-name> \
     --key "kyc-documents/tenant-100/broker-50/passport/a1b2c3d4.pdf"
   ```

#### Procedure 2: Rollback to a Known-Good Version (Overwritten Object)
1. **Fetch specific historical version ID**:
   ```bash
   aws s3api get-object \
     --bucket <kyc-vault-bucket-name> \
     --key "kyc-documents/tenant-100/broker-50/passport/a1b2c3d4.pdf" \
     --version-id "historical_version_id" \
     restored_document.pdf
   ```
2. **Re-upload historical version as the latest active object with KMS encryption**:
   ```bash
   aws s3 cp restored_document.pdf \
     s3://<kyc-vault-bucket-name>/kyc-documents/tenant-100/broker-50/passport/a1b2c3d4.pdf \
     --sse aws:kms \
     --sse-kms-key-id <kms-cmk-arn>
   ```

---

### Scenario B: DynamoDB Point-in-Time Recovery (PITR)
Both the SOAR Idempotency table and KYC Scan State table have continuous PITR enabled.

#### Procedure: Restoring Table to Exact Second Before Incident
1. **Determine recovery timestamp** (e.g., 5 minutes prior to malicious injection or corruption, UTC epoch or ISO-8601):
   - Example incident time: `2026-11-19T14:00:00Z`
   - Target restore time: `2026-11-19T13:58:00Z`
2. **Execute PITR restore command**:
   ```bash
   aws dynamodb restore-table-to-point-in-time \
     --source-table-name pf-shield-kyc-scan-state-production \
     --target-table-name pf-shield-kyc-scan-state-restored \
     --restore-date-time "2026-11-19T13:58:00Z"
   ```
3. **Monitor restoration progress**:
   ```bash
   aws dynamodb describe-table \
     --table-name pf-shield-kyc-scan-state-restored \
     --query "Table.TableStatus"
   ```
   *Wait until status transitions from `RESTORING` to `ACTIVE` (typically 10-25 minutes).*
4. **Update Application Configuration or Alias**:
   - Update ECS task definition environment variable `KYC_SCAN_TABLE=pf-shield-kyc-scan-state-restored`.
   - Perform rolling update of the `broker-kyc-api` and `document-scan-worker` ECS services:
     ```bash
     aws ecs update-service \
       --cluster pf-shield-cluster-production \
       --service pf-shield-broker-kyc-api \
       --force-new-deployment
     ```

---

### Scenario C: RDS PostgreSQL Automated Snapshot Restoration
1. **Identify latest continuous recovery point**:
   ```bash
   aws rds describe-db-instances \
     --db-instance-identifier pf-shield-db-production \
     --query "DBInstances[0].LatestRestorableTime"
   ```
2. **Restore RDS instance to point in time**:
   ```bash
   aws rds restore-db-instance-to-point-in-time \
     --source-db-instance-identifier pf-shield-db-production \
     --target-db-instance-identifier pf-shield-db-production-restored \
     --restore-time "2026-11-19T13:58:00Z" \
     --db-subnet-group-name pf-shield-db-subnet-group-production \
     --vpc-security-group-ids <database-security-group-id> \
     --no-publicly-accessible
   ```
3. **Verify Route 53 Private Hosted Zone CNAME update**:
   - Once the new DB instance is `available`, update Route 53 internal DNS record `db.pf-shield.internal` to point to the restored RDS endpoint to avoid application reconfiguration:
     ```bash
     aws route53 change-resource-record-sets \
       --hosted-zone-id <private-zone-id> \
       --change-batch '{
         "Changes": [{
           "Action": "UPSERT",
           "ResourceRecordSet": {
             "Name": "db.pf-shield.internal",
             "Type": "CNAME",
             "TTL": 60,
             "ResourceRecords": [{"Value": "<new-rds-endpoint>"}]
           }
         }]
       }'
     ```

---

### Scenario D: S3 Immutable Audit Destination & Object Lock Operations
The central audit logs bucket (`pf-shield-audit-logs-${env}`) is protected with **S3 Object Lock** in **`COMPLIANCE`** mode.

#### Key Invariants of COMPLIANCE Mode:
- **Write-Once-Read-Many (WORM)**: Objects cannot be overwritten, modified, or deleted by any user, including the AWS account root user.
- **Retention Period**: Guaranteed minimum retention of `audit_retention_days` (365 days in production, 7 days in demo profile).
- **Cannot Shorten Retention**: The retention period can be extended, but never shortened.
- **No Override Flag**: `s3:BypassGovernanceRetention` permissions cannot bypass `COMPLIANCE` mode.

#### Placing a Legal Hold during an Active Forensic Investigation:
If an active security investigation requires retaining specific CloudTrail audit logs beyond the default retention window:
1. **Apply Legal Hold on target audit object**:
   ```bash
   aws s3api put-object-legal-hold \
     --bucket <audit-bucket-name> \
     --key "AWSLogs/<account-id>/CloudTrail/me-central-1/2026/11/19/log.json.gz" \
     --legal-hold Status=ON
   ```
2. **Verify Legal Hold status**:
   ```bash
   aws s3api get-object-legal-hold \
     --bucket <audit-bucket-name> \
     --key "AWSLogs/<account-id>/CloudTrail/me-central-1/2026/11/19/log.json.gz"
   ```
   *An object with a Legal Hold cannot be deleted even after the default retention period expires, until explicitly removed by an authorized forensic auditor.*

---

## 5. Cross-Region Disaster Recovery Contingency Plan

### Geographic & Data Residency Context:
- Primary Region: **AWS UAE (`me-central-1`)**
- Secondary Standby Region: **AWS Bahrain (`me-south-1`)**
- Regulatory Boundary: UAE Personal Data Protection Law (Federal Decree-Law No. 45 of 2021) mandates that sensitive personal data (Emirates IDs, Title Deeds) remain within approved jurisdictions or require statutory consent.

### Multi-Region Standby Protocol (Pilot Light):
1. **Terraform Workspace Initialization**:
   ```bash
   terraform -chdir=terraform workspace select dr-failover || terraform -chdir=terraform workspace new dr-failover
   ```
2. **Apply Infrastructure to Secondary Region**:
   ```bash
   terraform -chdir=terraform apply -var-file=production.tfvars -var="aws_region=me-south-1" -auto-approve
   ```
3. **Route 53 Global Failover**:
   - Update public DNS / CloudFront Origin to route incoming requests from primary ALB to standby ALB.
   - Failover latency: Under 5 minutes via Route 53 health-checked latency or failover routing.

---

## 6. Post-Recovery Verification Checklist

| Step | Verification Check | Validation Command / Tool | Status |
|------|-------------------|--------------------------|--------|
| 1 | S3 KYC Vault Object Integrity | `aws s3api head-object` returns HTTP 200, KMS SSE enabled | [ ] |
| 2 | S3 Audit Object Lock Immutability | Object Lock COMPLIANCE mode active on audit logs | [ ] |
| 3 | DynamoDB Restored Table Online | Table status = `ACTIVE`, item count verified | [ ] |
| 4 | RDS PostgreSQL Reconnected | Health check endpoint `GET /health` returns HTTP 200 | [ ] |
| 5 | ECS Tasks Stable | Running count equals desired count, 0 task crash restarts | [ ] |
| 6 | CloudWatch Alarms Reset | `AlarmState = OK` for all P1/P2 error rate alarms | [ ] |
| 7 | AWS Config Rules Compliance | All 8 managed rules report `COMPLIANT` | [ ] |

---

## 7. Blameless Post-Mortem & Review Protocol
Within 48 hours of any disaster declaration or backup restoration:
1. Convene cross-functional post-mortem with Security, Infrastructure, and Application Engineering teams.
2. Calculate actual RTO and RPO against target objectives (RTO < 60 min, RPO < 15 min).
3. Document root cause, detection lag, remediation friction points, and process improvements.
4. Log all corrective actions in the security risk register with strict 14-day completion SLAs.
