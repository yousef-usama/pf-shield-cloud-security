"""Unit and Security Test Suite for CI/CD Pipelines & Software Supply Chain Governance.

Validates that:
1. Every GitHub Action is strictly pinned to an immutable 40-character commit SHA.
2. Dependabot automated vulnerability monitoring covers actions, pip, terraform, and docker.
3. GitHub OIDC trust policy is strictly scoped to the repository, protected branch, and environment.
4. Security scanning gates (Gitleaks, Checkov SARIF, Kyverno, Trivy, SBOM, Cosign) are wired in CI.
"""

from __future__ import annotations

import glob
import os
import re
import pytest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
SHA_PINNING_REGEX = re.compile(r"^[^@]+@[0-9a-f]{40}(?:\s*#.*)?$")


def test_all_github_actions_are_pinned_to_immutable_commit_sha():
    """Verify that every step using a third-party GitHub Action in .github/workflows/

    is pinned to an immutable 40-character commit SHA (e.g., action@<commit-sha>).
    Prohibits mutable tags (@v4, @master, @latest) to prevent supply chain tampering.
    """
    workflow_files = glob.glob(os.path.join(REPO_ROOT, ".github", "workflows", "*.yml"))
    assert len(workflow_files) >= 3, "Expected at least 3 workflow files in .github/workflows/"

    unpinned_actions = []

    for wf_path in workflow_files:
        with open(wf_path, "r", encoding="utf-8") as f:
            content = f.read()
            data = yaml.safe_load(content)

        jobs = data.get("jobs", {})
        for job_name, job_def in jobs.items():
            steps = job_def.get("steps", [])
            for step in steps:
                uses_val = step.get("uses")
                if uses_val:
                    # Docker container actions or local actions starting with ./ or docker:// are exempt
                    if uses_val.startswith("./") or uses_val.startswith("docker://"):
                        continue
                    # Check if pinned to full 40-hex SHA
                    if not SHA_PINNING_REGEX.match(uses_val.strip()):
                        unpinned_actions.append(f"{os.path.basename(wf_path)} -> job '{job_name}' -> '{uses_val}'")

    assert len(unpinned_actions) == 0, f"Found unpinned GitHub Actions (must use 40-char SHA):\n" + "\n".join(unpinned_actions)


def test_dependabot_configuration_coverage():
    """Verify .github/dependabot.yml covers all critical platform package ecosystems:

    github-actions, pip, terraform, and docker base images.
    """
    dependabot_path = os.path.join(REPO_ROOT, ".github", "dependabot.yml")
    assert os.path.exists(dependabot_path), "Missing .github/dependabot.yml"

    with open(dependabot_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert data.get("version") == 2, "Dependabot configuration version must be 2"

    updates = data.get("updates", [])
    assert len(updates) >= 4, "Dependabot must monitor at least actions, pip, terraform, and docker"

    ecosystems = {u.get("package-ecosystem") for u in updates}
    assert "github-actions" in ecosystems, "Dependabot must monitor github-actions"
    assert "pip" in ecosystems, "Dependabot must monitor pip"
    assert "terraform" in ecosystems, "Dependabot must monitor terraform"
    assert "docker" in ecosystems, "Dependabot must monitor docker"


def test_github_oidc_trust_policy_strict_scoping():
    """Verify terraform-bootstrap/main.tf restricts OIDC trust to the repository,

    protected branch, and production environment, prohibiting open wildcards.
    """
    bootstrap_main = os.path.join(REPO_ROOT, "terraform-bootstrap", "main.tf")
    assert os.path.exists(bootstrap_main), "Missing terraform-bootstrap/main.tf"

    with open(bootstrap_main, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify audience is strictly sts.amazonaws.com
    assert '"token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"' in content

    # Verify sub condition is scoped to branch, environment, or pull request
    assert "token.actions.githubusercontent.com:sub" in content
    assert "ref:refs/heads/" in content, "OIDC sub must scope to protected branch"
    assert "environment:" in content, "OIDC sub must scope to protected environment"
    assert 'repo:${var.github_repository}:*' not in content, "OIDC sub must not use unbounded wildcard repo:repo:*"


def test_devsecops_pipeline_security_gates():
    """Verify that devsecops-pipeline.yml includes all required security gates:

    Gitleaks (secrets), Pytest (unit), Semgrep (SAST), Checkov (IaC),
    Trivy/SBOM/Cosign (supply chain), and Kyverno (K8s policies).
    """
    pipeline_path = os.path.join(REPO_ROOT, ".github", "workflows", "devsecops-pipeline.yml")
    assert os.path.exists(pipeline_path), "Missing .github/workflows/devsecops-pipeline.yml"

    with open(pipeline_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify security gates are present in the pipeline text
    assert "gitleaks" in content.lower(), "Pipeline must include Gitleaks secret scanning"
    assert "pytest" in content.lower(), "Pipeline must execute Pytest unit/mock test suite"
    assert "semgrep" in content.lower(), "Pipeline must include Semgrep SAST scanning"
    assert "checkov" in content.lower(), "Pipeline must include Checkov IaC scanning"
    assert "trivy" in content.lower(), "Pipeline must include Trivy container scanning"
    assert "cyclonedx" in content.lower() or "sbom" in content.lower(), "Pipeline must include SBOM generation"
    assert "cosign" in content.lower(), "Pipeline must verify Cosign digital signature capabilities"
    assert "kyverno" in content.lower(), "Pipeline must enforce Kyverno policy verification"
    assert "upload-sarif" in content, "Pipeline must upload SARIF results to GitHub Security"


def test_ci_cd_ecr_naming_cosign_and_remote_backend_invariants():
    """Verify that devsecops-pipeline.yml:
    1. Tags and pushes to ECR repository paths matching pf-shield/<service>-production.
    2. Captures independent digests for listings, broker-kyc, and document-scan-worker.
    3. Mandatory Cosign keyless signing fails the pipeline on signing error (no '|| echo' masking).
    4. Production plan and apply jobs initialize the remote S3/DynamoDB state backend with state locking.
    """
    pipeline_path = os.path.join(REPO_ROOT, ".github", "workflows", "devsecops-pipeline.yml")
    assert os.path.exists(pipeline_path), "Missing .github/workflows/devsecops-pipeline.yml"

    with open(pipeline_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Verify ECR repository names match pf-shield/<service>-production
    assert "pf-shield/listings-api-production" in content, "ECR repo name must match pf-shield/listings-api-production"
    assert "pf-shield/broker-kyc-api-production" in content, "ECR repo name must match pf-shield/broker-kyc-api-production"
    assert "pf-shield/document-scan-worker-production" in content, "ECR repo name must match pf-shield/document-scan-worker-production"

    # Prohibit un-namespaced repository pushes
    assert "/pf-listings-api-production" not in content, "Found un-namespaced pf-listings-api-production push"
    assert "/pf-broker-kyc-api-production" not in content, "Found un-namespaced pf-broker-kyc-api-production push"
    assert "/pf-document-scan-worker-production" not in content, "Found un-namespaced pf-document-scan-worker-production push"

    # 2. Verify independent digest capture
    assert "LISTINGS_DIGEST=" in content
    assert "BROKER_KYC_DIGEST=" in content
    assert "SCAN_WORKER_DIGEST=" in content
    assert "container_image_digests" in content

    # 3. Verify Cosign signing does not mask failures and cosign verify is enforced across all 3 digests
    assert 'cosign sign --yes "${LISTINGS_DIGEST}"' in content
    assert 'cosign sign --yes "${BROKER_KYC_DIGEST}"' in content
    assert 'cosign sign --yes "${SCAN_WORKER_DIGEST}"' in content
    assert 'cosign sign --yes "${LISTINGS_DIGEST}" || echo' not in content, "Cosign failure must not be masked with || echo"

    assert 'cosign verify \\\n            --certificate-identity-regexp "^https://github.com/${{ github.repository }}/" \\\n            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \\\n            "${LISTINGS_DIGEST}"' in content
    assert 'cosign verify \\\n            --certificate-identity-regexp "^https://github.com/${{ github.repository }}/" \\\n            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \\\n            "${BROKER_KYC_DIGEST}"' in content
    assert 'cosign verify \\\n            --certificate-identity-regexp "^https://github.com/${{ github.repository }}/" \\\n            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \\\n            "${SCAN_WORKER_DIGEST}"' in content

    # 4. Verify remote backend initialization for production workflows
    assert '-backend-config="bucket=${STATE_BUCKET}"' in content, "Production workflow must supply remote backend state bucket"
    assert '-backend-config="key=pf-shield/production/terraform.tfstate"' in content, "Production workflow must supply production state key override"
    assert '-backend-config="dynamodb_table=pf-shield-tf-locks"' in content, "Production workflow must supply DynamoDB state lock table"

    # 5. Verify no imperative ECR creation in CI workflow (bootstrap is sole owner)
    assert "aws ecr create-repository" not in content, "CI workflow must not imperatively create ECR repositories; terraform-bootstrap owns ECR creation"

    # 6. Verify fail-fast semantics in production plan and apply jobs (no fallback to -backend=false or simulated runs)
    assert "deploy-production-plan:" in content
    assert "deploy-production-apply:" in content
    plan_job = content.split("deploy-production-plan:")[1].split("deploy-production-apply:")[0]
    apply_job = content.split("deploy-production-apply:")[1]
    assert "-backend=false" not in plan_job, "Production plan job must not fall back to local backend"
    assert "-backend=false" not in apply_job, "Production apply job must not fall back to local backend"
    assert "AWS_ROLE_TO_ASSUME secret is required" in plan_job, "Production plan job must fail fast on missing OIDC credentials"
    assert "AWS_ROLE_TO_ASSUME secret is required" in apply_job, "Production apply job must fail fast on missing OIDC credentials"
