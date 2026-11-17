SHELL := /bin/bash
.PHONY: help test scan fmt validate plan deploy simulate-attack destroy clean diagram bootstrap-state bootstrap-oidc

help:
	@echo "PF-Shield Cloud Security Automation Targets:"
	@echo "  make bootstrap-state  - Bootstrap S3 remote state bucket + DynamoDB locks via AWS CLI"
	@echo "  make bootstrap-oidc   - Provision GitHub Actions OIDC provider and bootstrap role"
	@echo "  make fmt              - Format Terraform configurations"
	@echo "  make validate         - Validate Terraform syntax and configurations"
	@echo "  make test             - Execute unit tests for Python SOAR playbooks (pytest + moto)"
	@echo "  make scan             - Run security and policy-as-code scanners (Checkov)"
	@echo "  make diagram          - Generate Lucidchart-style architecture diagram"
	@echo "  make plan             - Generate Terraform execution plan"
	@echo "  make deploy           - Apply Terraform configuration (me-central-1)"
	@echo "  make simulate-attack  - Execute automated attack injection script against EventBridge"
	@echo "  make destroy          - Safely teardown all provisioned AWS resources"
	@echo "  make clean            - Clean local test cache and build artifacts"

bootstrap-state:
	./scripts/bootstrap-remote-state.sh

bootstrap-oidc:
	terraform -chdir=terraform-bootstrap init
	terraform -chdir=terraform-bootstrap apply -auto-approve

fmt:
	terraform -chdir=terraform fmt -recursive
	terraform -chdir=terraform-bootstrap fmt -recursive

validate:
	terraform -chdir=terraform init -backend=false
	terraform -chdir=terraform validate
	terraform -chdir=terraform-bootstrap init -backend=false
	terraform -chdir=terraform-bootstrap validate

test:
	./.venv/bin/pytest src/tests/ -v --tb=short

scan:
	/Users/Yousef/.local/bin/checkov -d terraform/ --framework terraform --quiet
	/Users/Yousef/.local/bin/checkov -d terraform-bootstrap/ --framework terraform --quiet
	/Users/Yousef/.local/bin/checkov -d k8s-security-policies/ --framework kubernetes --quiet

diagram:
	./scripts/generate-diagram.sh

plan:
	terraform -chdir=terraform plan -out=tfplan

deploy:
	terraform -chdir=terraform apply -auto-approve tfplan

simulate-attack:
	./scripts/simulate_attack.sh

destroy:
	terraform -chdir=terraform destroy -auto-approve

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf terraform/tfplan terraform/.terraform
