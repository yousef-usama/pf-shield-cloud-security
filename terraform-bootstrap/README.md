# PF-Shield: GitHub OIDC & IAM Bootstrap

This directory contains a lightweight, independent Terraform configuration designed to be executed **once** to establish keyless authentication between GitHub Actions and AWS using OpenID Connect (OIDC).

---

## Why Separate from Main Infrastructure?

1. **Chicken-and-Egg Separation**: CI/CD pipelines need an authenticated role *before* they can run `terraform plan`, `apply`, or `destroy` on the main infrastructure.
2. **Blast Radius Isolation**: Bootstrap configurations deal with root-level IAM and OIDC identity providers. Separating them prevents accidental modification or destruction during regular application lifecycle operations.
3. **Keyless Security (Zero Long-Lived Credentials)**: No AWS Access Key IDs or Secret Access Keys are ever stored in GitHub Secrets. Authentication relies on short-lived JWTs exchanged directly via AWS STS (`AssumeRoleWithWebIdentity`).

---

## Provisioned Resources

| Resource | Type | Purpose |
| :--- | :--- | :--- |
| `aws_iam_openid_connect_provider.github_actions` | OIDC Provider | Trusts tokens issued by `https://token.actions.githubusercontent.com`. |
| `aws_iam_role.github_actions` | IAM Role | Assumed by GitHub Actions workflows matching `repo:YousefOsama/pf-shield-cloud-security:*`. |
| `aws_iam_policy.github_actions_policy` | IAM Policy | Scoped to `me-central-1` and `us-east-1` for PF-Shield resource deployment and teardown. |

---

## One-Time Deployment Instructions

### 1. Initialize and Review
```bash
cd terraform-bootstrap
terraform init
terraform plan -var="github_repository=YOUR_GITHUB_ORG_OR_USER/pf-shield-cloud-security"
```

### 2. Apply
```bash
terraform apply -auto-approve -var="github_repository=YOUR_GITHUB_ORG_OR_USER/pf-shield-cloud-security"
```

### 3. Configure GitHub Secrets
Copy the output `github_actions_role_arn` into your GitHub repository settings under:
**Settings** → **Secrets and variables** → **Actions** → **New repository secret**:
- **Name**: `AWS_ROLE_TO_ASSUME`
- **Value**: `arn:aws:iam::<ACCOUNT_ID>:role/pf-shield-github-actions-bootstrap-role`
