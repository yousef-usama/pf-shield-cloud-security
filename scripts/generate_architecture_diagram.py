#!/usr/bin/env python3
"""PF-Shield: Professional Lucidchart-Style Cloud Architecture Diagram Generator.

Generates docs/architecture-overview.png using official AWS, Kubernetes,
and DevOps vector icons via Python diagrams.
"""

import os
from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import Lambda
from diagrams.aws.database import Dynamodb
from diagrams.aws.management import Cloudtrail
from diagrams.aws.general import Users
from diagrams.aws.integration import Eventbridge, SNS, SQS
from diagrams.aws.network import APIGateway, Endpoint, VPC
from diagrams.aws.security import (
    Guardduty,
    IdentityAndAccessManagementIam,
    KeyManagementService,
    SecurityHub,
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
    "splines": "ortho",
}

node_attr = {
    "fontsize": "11",
    "fontname": "Helvetica",
}

cluster_attr = {
    "fontsize": "13",
    "fontname": "Helvetica-Bold",
    "style": "rounded",
}

with Diagram(
    "PF-Shield: Zero-Trust Real Estate API & Automated Cloud SOAR",
    show=False,
    filename=output_path,
    outformat="png",
    graph_attr=graph_attr,
    node_attr=node_attr,
):
    users = Users("Public Users & Brokers")
    scrapers = Users("Competitor Scrapers / Attackers")

    with Cluster("DevSecOps & Policy-as-Code CI/CD", graph_attr={"bgcolor": "#f8f9fa", **cluster_attr}):
        gh_actions = GithubActions("GitHub Actions CI/CD")
        tf_iac = Terraform("Modular Terraform IaC")
        checkov_scan = Trivy("Checkov Static Scans")
        tf_iac >> Edge(label="Validates & Scans", color="#6c757d", style="dashed") >> checkov_scan
        gh_actions >> tf_iac

    with Cluster("AWS Region: me-central-1 (UAE - Sovereign Cloud)", graph_attr={"bgcolor": "#e9ecef", **cluster_attr}):
        
        # Edge Security Layer
        with Cluster("Edge Security & Anti-Scraping", graph_attr={"bgcolor": "#ffffff", **cluster_attr}):
            waf = WAF("AWS WAFv2\n(Anti-Scraping / OWASP)")
            api_gw = APIGateway("API Gateway HTTP API\n($0 Native Burst Throttling)")
            waf >> Edge(label="Inspects & Filters", color="#e03131") >> api_gw

        users >> Edge(label="HTTPS", color="#2b8a3e") >> api_gw
        scrapers >> Edge(label="Blocked Scrapes", color="#c92a2a", style="dashed") >> waf

        # Serverless Workload Layer
        with Cluster("Serverless Microservices (arm64 Graviton2)", graph_attr={"bgcolor": "#ffffff", **cluster_attr}):
            prop_api = Lambda("Property API\n(GET /properties)")
            kyc_api = Lambda("KYC Presign Handler\n(POST /kyc/presign)")
            api_gw >> prop_api
            api_gw >> kyc_api

        # Isolated Network & Zero-Cost Endpoints
        with Cluster("Private VPC (10.20.0.0/16) — Zero NAT Gateway Cost", graph_attr={"bgcolor": "#e8f5e9", **cluster_attr}):
            s3_vpce = Endpoint("S3 Gateway Endpoint\n($0.00/hr, Private Route)")
            ddb_vpce = Endpoint("DynamoDB Gateway Endpoint\n($0.00/hr, Private Route)")

        # Data & Encryption Layer
        with Cluster("Data Perimeter & Envelope Encryption", graph_attr={"bgcolor": "#ffffff", **cluster_attr}):
            kms_cmk = KeyManagementService("KMS Customer Managed Key\n(Annual Auto-Rotation)")
            kyc_vault = S3("Broker KYC Vault S3\n(Triple-Deny + S3 Bucket Keys)")
            props_table = Dynamodb("Properties & KYC Metadata\n(PAY_PER_REQUEST + PITR)")

            kyc_api >> Edge(label="Private Presigned Uploads", color="#1c7ed6") >> s3_vpce >> kyc_vault
            prop_api >> Edge(label="Private Sub-15ms Queries", color="#2f9e44") >> ddb_vpce >> props_table
            kms_cmk >> Edge(label="Envelope Encryption", color="#f08c00", style="dotted") >> kyc_vault
            kms_cmk >> Edge(label="KMS CMK Encryption", color="#f08c00", style="dotted") >> props_table

        # Incident Response / Cloud SOAR Engine
        with Cluster("Automated Incident Response (SOAR Engine)", graph_attr={"bgcolor": "#fff3bf", **cluster_attr}):
            cloudtrail = Cloudtrail("AWS CloudTrail\n(Multi-Region Audit)")
            guardduty = Guardduty("AWS GuardDuty\n(S3 & IAM Findings)")
            event_bus = Eventbridge("Amazon EventBridge\n(Security Dispatch Rules)")
            
            s3_lockdown = Lambda("S3 Lockdown Playbook\n(Restores PAB < 1.5s)")
            iam_quarantine = Lambda("IAM Quarantine Playbook\n(Deactivates Keys < 2.0s)")
            
            dlq = SQS("SQS Dead Letter Queues\n(Zero-Dropped Alerts SLA)")
            sns_alerts = SNS("SNS Alerts Topic\n(Security Operations Center)")
            iam_boundary = IdentityAndAccessManagementIam("IAM Boundary & DenyAll\n(Zero-Trust Quarantine)")

            kyc_vault >> Edge(label="Audit Events", color="#495057", style="dashed") >> cloudtrail >> event_bus
            kyc_vault >> Edge(label="Exfiltration Findings", color="#c92a2a", style="dashed") >> guardduty >> event_bus
            
            event_bus >> Edge(label="Trigger S3 Lockdown", color="#d6336c") >> s3_lockdown
            event_bus >> Edge(label="Trigger IAM Quarantine", color="#d6336c") >> iam_quarantine
            
            event_bus >> Edge(label="On Lambda Failure", color="#e03131", style="dashed") >> dlq
            s3_lockdown >> Edge(label="Enforces PublicAccessBlock", color="#2b8a3e") >> kyc_vault
            iam_quarantine >> Edge(label="Attaches DenyAll Policy", color="#c92a2a") >> iam_boundary
            
            s3_lockdown >> Edge(label="Forensic Report (MTTR)", color="#f08c00") >> sns_alerts
            iam_quarantine >> Edge(label="Forensic Report (MTTR)", color="#f08c00") >> sns_alerts

    tf_iac >> Edge(label="Provisions 100% via IaC", color="#0ca678", style="bold") >> api_gw
