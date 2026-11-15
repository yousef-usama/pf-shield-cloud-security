# Incident Response Runbook 01: Compromised IAM Credentials & Unauthorized Privilege Escalation

## 1. Overview & Severity
- **Incident Code**: `SEC-IR-IAM-01`
- **Severity**: **Critical (P1)**
- **Target Systems**: AWS IAM, EventBridge, CloudTrail, SOAR Lambda (`pf-soar-iam-quarantine`)
- **Objective**: Rapidly detect, isolate, and remediate compromised IAM identities attempting privilege escalation, access key creation, or policy boundary tampering.

---

## 2. Automated SOAR Detection & Containment Workflow

```
[ Compromised IAM Credential ]
              │ (Attempts DeleteRolePermissionsBoundary / PutUserPolicy / CreateAccessKey)
              ▼
    [ AWS CloudTrail / GuardDuty ]
              │ (Emits event within 15 seconds)
              ▼
   [ Amazon EventBridge Rule ] -> (pf-iam-compromise-or-escalation)
              │
              ├──► [ SQS Dead Letter Queue ] (Backup SLA if Lambda throttles)
              ▼
   [ SOAR Lambda Playbook: playbook_iam_quarantine.py ]
              ├── 1. Attaches 'pf-soar-quarantine-deny-all' Policy (Instant Freeze)
              ├── 2. Enumerates & Deactivates Active Access Keys (Status='Inactive')
              ├── 3. Emits 'MeanTimeToRemediate' Metric to CloudWatch
              └── 4. Publishes Structured Forensic Report to SNS ('pf-security-incidents')
```

---

## 3. Step-by-Step Incident Response Protocol

### Phase 1: Automated Containment Verification (< 5 Minutes)
1. **Verify SNS Incident Notification**:
   - Check security operations email or Slack channel for subject `[PF-Shield SOAR] Auto-Remediated Compromised IAM Identity`.
   - Inspect JSON forensic payload for `compromised_identity`, `identity_type`, `revoked_access_keys`, and `mttr_seconds`.
2. **Verify IAM Quarantine Attachment**:
   ```bash
   # Check attached policies on compromised role/user
   aws iam list-attached-user-policies --user-name <compromised-user>
   # Output must contain: arn:aws:iam::<account-id>:policy/pf-soar-quarantine-deny-all
   ```
3. **Verify Access Key Deactivation**:
   ```bash
   aws iam list-access-keys --user-name <compromised-user>
   # Output must show: "Status": "Inactive"
   ```

### Phase 2: Forensic Triage & Blast Radius Assessment
1. **Query CloudTrail via Athena / CloudTrail Lake**:
   ```sql
   SELECT eventTime, eventName, sourceIPAddress, userAgent, requestParameters
   FROM cloudtrail_logs
   WHERE userIdentity.userName = '<compromised-user>'
     AND eventTime >= current_timestamp - interval '24' hour
   ORDER BY eventTime DESC;
   ```
2. **Identify Entry Vector**:
   - Did the key leak in a public Git repository or CI/CD runner log?
   - Was the source IP address a known VPN, Tor exit node, or unusual geolocation?

### Phase 3: Eradication & Remediation
1. **Permanently Delete Compromised Access Keys**:
   ```bash
   aws iam delete-access-key --user-name <compromised-user> --access-key-id <key-id>
   ```
2. **Revoke Active STS Sessions**:
   - If an IAM Role was compromised, attach an inline revocation policy:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Deny",
           "Action": "*",
           "Resource": "*",
           "Condition": {
             "DateLessThan": {
               "aws:TokenIssueTime": "2026-11-15T12:00:00Z"
             }
           }
         }
       ]
     }
     ```

### Phase 4: Recovery & Restoration
1. Rotate credentials following enterprise password/MFA protocols.
2. Detach `pf-soar-quarantine-deny-all` ONLY after root-cause analysis is signed off by the Lead Cloud Security Engineer.
3. Validate that workload Permission Boundaries remain intact.

---

## 4. Blameless Post-Mortem Template

```markdown
## Post-Mortem: Incident SEC-IR-IAM-01

- **Date / Time of Incident**: YYYY-MM-DD HH:MM UTC
- **Incident Commander**: <Name / Title>
- **Automated SOAR MTTR**: <X.XXX> seconds
- **Incident Summary**: <Brief summary of root cause and impacted resources>
- **Timeline**:
  - `T0`: Credential compromised.
  - `T0 + 12s`: CloudTrail registers unauthorized API call.
  - `T0 + 14s`: EventBridge triggers SOAR playbook.
  - `T0 + 15s`: Quarantine deny-all attached; access keys deactivated.
- **Root Cause Analysis (5 Whys)**:
  1. Why did the credential leak? ...
- **Action Items**:
  - [ ] Action item 1 (Owner, Due Date)
```
