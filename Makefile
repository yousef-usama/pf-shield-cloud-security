SHELL := /bin/bash
.PHONY: help test scan fmt validate plan deploy simulate-attack destroy clean

help:
	@echo "PF-Shield Cloud Security Automation Targets:"
	@echo "  make fmt              - Format Terraform and Python code"
	@echo "  make validate         - Validate Terraform configurations"
	@echo "  make test             - Execute unit tests for Python SOAR playbooks (pytest + moto)"
	@echo "  make scan             - Run security and policy-as-code scanners (Checkov)"
	@echo "  make plan             - Generate Terraform execution plan"
	@echo "  make deploy           - Apply Terraform configuration (me-central-1)"
	@echo "  make simulate-attack  - Execute automated attack injection script against EventBridge"
	@echo "  make destroy          - Safely teardown all provisioned AWS resources"
	@echo "  make clean            - Clean local test cache and build artifacts"

fmt:
	terraform -chdir=terraform fmt -recursive
	@if command -v black >/dev/null 2>&1; then black src/; fi

validate:
	terraform -chdir=terraform init -backend=false
	terraform -chdir=terraform validate

test:
	pytest src/tests/ -v --tb=short

scan:
	checkov -d terraform/ --framework terraform

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
