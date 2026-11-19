#!/usr/bin/env python3
"""PF-Shield: Professional Lucidchart-Style Cloud Architecture Diagram Generator.

Generates docs/architecture-overview.png using official AWS and DevOps vector icons via Python diagrams.
"""

import os
from diagrams import Cluster, Diagram, Edge
from diagrams.aws.analytics import Glue
from diagrams.aws.compute import EC2Instance, ECR, ECS, Lambda
from diagrams.aws.database import Dynamodb, RDS
from diagrams.aws.general import Users
from diagrams.aws.integration import Eventbridge, SNS, SQS
from diagrams.aws.management import Cloudtrail, Config
from diagrams.aws.network import ALB, APIGateway, CloudFront, Endpoint, Route53
from diagrams.aws.security import (
    Cognito,
    Guardduty,
    IdentityAndAccessManagementIam,
    KeyManagementService,
    SecretsManager,
    WAF,
)
from diagrams.aws.storage import S3
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.iac import Terraform
from diagrams.onprem.security import Trivy

output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs"))
output_path = os.path.join(output_dir, "architecture-overview")

graph_attr = {
    "fontsize": "24",
    "bgcolor": "white",
    "fontname": "Helvetica-Bold",
    "compound": "true",
    "pad": "0.5",
    "rankdir": "LR",
    "splines": "spline",
}

node_attr = {
    "fontsize": "10",
    "fontname": "Helvetica",
}

cluster_attr = {
    "fontsize": "12",
    "fontname": "Helvetica-Bold",
    "style": "rounded",
}

with Diagram(
    "PF-Shield: Enterprise Zero-Trust Architecture & Automated Cloud SOAR",
    show=False,
    filename=output_path,
    outformat="png",
    graph_attr=graph_attr,
    node_attr=node_attr,
):
    # External Principals & Actors
    users = Users("Legitimate Clients\n& Brokers")
    scrapers = Users("Malicious Scrapers\n& Attackers")

    # DevSecOps & Supply Chain CI/CD
    with Cluster("DevSecOps & Supply Chain CI/CD", graph_attr={"bgcolor": "#f8f9fa", **cluster_attr}):
        gh_actions = GithubActions("GitHub Actions CI/CD\n(OIDC Keyless, SHA Pinned)")
        tf_iac = Terraform("Modular Terraform\n(Remote State & Locks)")
        sec_gates = Trivy("Security Gates\n(Gitleaks/Semgrep/Checkov/Cosign)")

        gh_actions >> Edge(label="OIDC AssumeRole", color="#495057") >> tf_iac
        gh_actions >> Edge(label="Shift-Left Scans", color="#6c757d", style="dashed") >> sec_gates

    # Global Edge Security, CDN & Identity
    with Cluster("Global Edge Security, CDN & Identity", graph_attr={"bgcolor": "#f1f3f5", **cluster_attr}):
        route53 = Route53("Amazon Route 53\n(Hosted Zone & Aliases)")
        waf = WAF("AWS WAFv2\n(Anti-Scraping / Rate Limits / OWASP)")
        cloudfront = CloudFront("CloudFront Global CDN\n(TLS 1.3 / Strict Security Headers)")
        cognito = Cognito("Cognito User Pool\n(RBAC Broker Auth / JWKS)")

        users >> Edge(label="DNS Query", color="#2b8a3e") >> route53
        route53 >> Edge(label="Resolves Alias", color="#2b8a3e") >> cloudfront
        users >> Edge(label="HTTPS Traffic", color="#2b8a3e") >> cloudfront
        users >> Edge(label="Obtains JWT", color="#7950f2", style="dashed") >> cognito
        scrapers >> Edge(label="Scraping Probe", color="#c92a2a", style="dashed") >> waf
        waf >> Edge(label="Inspects & Enforces", color="#e03131") >> cloudfront

    # AWS Sovereign Region: me-central-1
    with Cluster("AWS Sovereign Region: me-central-1 (UAE)", graph_attr={"bgcolor": "#e9ecef", **cluster_attr}):

        # Foundational Platform Assets (Bootstrap)
        with Cluster("Foundational Platform Assets (Bootstrap)", graph_attr={"bgcolor": "#ffffff", **cluster_attr}):
            kms_cmk = KeyManagementService("KMS Customer Managed Key\n(Annual Auto-Rotation)")
            ecr_foundation = ECR("Foundational ECR\n(KMS CMK, Immutable Digests)")
            tf_state_s3 = S3("Terraform State\n(S3 Encrypted Backend)")
            tf_locks_ddb = Dynamodb("State Lock Table\n(DynamoDB Locks)")

            gh_actions >> Edge(label="Push & Cosign Sign", color="#0ca678") >> ecr_foundation
            tf_iac >> Edge(label="Remote State Locking", color="#1c7ed6", style="dashed") >> tf_state_s3
            tf_iac >> Edge(label="State Lock", color="#1c7ed6", style="dashed") >> tf_locks_ddb

        # Multi-Tier VPC
        with Cluster("Multi-Tier VPC (10.20.0.0/16)", graph_attr={"bgcolor": "#e8f5e9", **cluster_attr}):

            # Public Ingress Subnets
            with Cluster("Public Ingress Subnets", graph_attr={"bgcolor": "#ffffff", **cluster_attr}):
                alb = ALB("Public ALB\n(TLS 1.3 + X-PF-Edge-Secret)")
                api_gw = APIGateway("API Gateway HTTP API\n(Serverless Edge Fallback)")

                cloudfront >> Edge(label="Forward HTTPS + Secret", color="#1c7ed6") >> alb
                cloudfront >> Edge(label="Fallback Path", color="#868e96", style="dotted") >> api_gw

            # Private Application Subnets (ECS on Fargate)
            with Cluster("Private Application Subnets (ECS & Serverless)", graph_attr={"bgcolor": "#ffffff", **cluster_attr}):
                listings_api = ECS("Listings API\n(FastAPI / Fargate)")
                broker_kyc = ECS("Broker KYC API\n(Cognito JWKS / Presign)")
                doc_scanner = ECS("Document Scan Worker\n(Event-Driven SQS Consumer)")
                serverless_lambdas = Lambda("Serverless Handlers\n(arm64 Graviton2)")

                alb >> Edge(label="/properties*", color="#2f9e44") >> listings_api
                alb >> Edge(label="/kyc*", color="#1c7ed6") >> broker_kyc
                api_gw >> serverless_lambdas

                ecr_foundation >> Edge(label="Pulls Immutable Digests", color="#0ca678", style="dotted", constraint="false") >> listings_api
                ecr_foundation >> Edge(color="#0ca678", style="dotted", constraint="false") >> broker_kyc
                ecr_foundation >> Edge(color="#0ca678", style="dotted", constraint="false") >> doc_scanner

            # Private Isolated Data Subnets & Data Perimeter
            with Cluster("Private Isolated Data Subnets & Data Perimeter", graph_attr={"bgcolor": "#ffffff", **cluster_attr}):
                s3_vpce = Endpoint("S3 Gateway Endpoint\n($0.00/hr Private Route)")
                ddb_vpce = Endpoint("DynamoDB Endpoint\n($0.00/hr Private Route)")

                kyc_vault = S3("Zero-Trust KYC S3 Vault\n(Triple-Deny Data Perimeter)")
                sqs_scan_queue = SQS("KYC Upload SQS Queue\n(s3:ObjectCreated Event)")
                props_table = Dynamodb("Properties & KYC DynamoDB\n(PAY_PER_REQUEST + PITR)")
                rds_pg = RDS("RDS PostgreSQL 16\n(Multi-AZ / KMS Encrypted / TLS)")
                secrets_mgr = SecretsManager("AWS Secrets Manager\n(Auto Credential Rotation)")

                broker_kyc >> Edge(label="Presigned POST", color="#1c7ed6") >> s3_vpce >> kyc_vault
                listings_api >> Edge(label="Sub-15ms Read", color="#2f9e44") >> ddb_vpce >> props_table
                listings_api >> Edge(label="Relational Queries", color="#2f9e44") >> rds_pg
                rds_pg - Edge(color="#adb5bd", style="dotted") - secrets_mgr

                # S3 event notification triggers SQS which triggers doc scanner
                kyc_vault >> Edge(label="s3:ObjectCreated", color="#e8590c") >> sqs_scan_queue
                sqs_scan_queue >> Edge(label="Processes KYC", color="#e8590c", constraint="false") >> doc_scanner

                kms_cmk >> Edge(label="Envelope Encryption", color="#f08c00", style="dotted", constraint="false") >> kyc_vault
                kms_cmk >> Edge(label="KMS CMK Encryption", color="#f08c00", style="dotted", constraint="false") >> props_table

            # Isolated Analytics Demonstration Lab
            with Cluster("Analytics Demonstration Lab Subnet", graph_attr={"bgcolor": "#fff9db", **cluster_attr}):
                clickhouse_ec2 = EC2Instance("Hardened ClickHouse\n(IMDSv2, SSM-Only, No SSH)")
                data_lake_s3 = S3("Analytics S3 Lake\n(Encrypted Parquet)")
                glue_etl = Glue("AWS Glue ETL\n(Automated PII Sanitization)")

                glue_etl >> Edge(label="Sanitizes", color="#f59f00") >> data_lake_s3
                clickhouse_ec2 >> Edge(label="OLAP Queries", color="#f59f00") >> data_lake_s3

        # Cloud SOAR & Governance Engine
        with Cluster("Automated Incident Response (Cloud SOAR Engine)", graph_attr={"bgcolor": "#fff3bf", **cluster_attr}):
            cloudtrail = Cloudtrail("AWS CloudTrail\n(Multi-Region Audit)")
            guardduty = Guardduty("AWS GuardDuty\n(Threat Detection)")
            aws_config = Config("AWS Config\n(Compliance Recording)")
            event_bus = Eventbridge("Amazon EventBridge\n(Security Dispatch Rules)")

            s3_lockdown = Lambda("S3 Lockdown Playbook\n(Restores PAB < 1.5s)")
            iam_quarantine = Lambda("IAM Quarantine Playbook\n(Deactivates Keys < 2.0s)")

            soar_ddb = Dynamodb("SOAR Idempotency\n(pf-soar-idempotency)")
            dlq = SQS("SQS Dead Letter Queue\n(Zero-Dropped Alerts SLA)")
            sns_alerts = SNS("SNS Alerts Topic\n(SOC Operational Alerts)")
            iam_boundary = IdentityAndAccessManagementIam("IAM Boundary & DenyAll\n(Quarantine Policy)")

            kyc_vault >> Edge(label="Audit Trail", color="#495057", style="dashed", constraint="false") >> cloudtrail
            cloudtrail >> Edge(label="S3 Data Events", color="#c92a2a", style="dotted") >> guardduty
            cloudtrail >> event_bus
            guardduty >> Edge(label="Threat Finding", color="#c92a2a") >> event_bus
            aws_config >> Edge(label="Compliance Drift", color="#495057", style="dashed") >> event_bus

            event_bus >> Edge(label="Security Alert", color="#d6336c") >> s3_lockdown
            event_bus >> Edge(label="Credential Finding", color="#d6336c") >> iam_quarantine
            event_bus >> Edge(label="Failure DLQ", color="#e03131", style="dashed") >> dlq

            s3_lockdown >> Edge(label="Locks Down PAB", color="#2b8a3e", constraint="false") >> kyc_vault
            iam_quarantine >> Edge(label="Attaches DenyAll", color="#c92a2a") >> iam_boundary
            s3_lockdown >> Edge(label="Deduplicates", color="#74c0fc", style="dotted") >> soar_ddb
            iam_quarantine >> Edge(label="Deduplicates", color="#74c0fc", style="dotted") >> soar_ddb

            s3_lockdown >> Edge(label="Forensic Report", color="#f08c00") >> sns_alerts
            iam_quarantine >> Edge(label="Forensic Report", color="#f08c00") >> sns_alerts
