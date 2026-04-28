# AC3 Platform — AWS Deployment Guide

**Author:** Harrison Cook — [AceofCloud](https://aceofcloud.com)  
**Last Updated:** April 28, 2026  
**Compliance Target:** FedRAMP High Baseline (NIST 800-53 Rev 5)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Initial Setup (One-Time)](#initial-setup-one-time)
4. [Deploying an Environment](#deploying-an-environment)
5. [CI/CD Pipeline](#cicd-pipeline)
6. [Secrets Management](#secrets-management)
7. [Monitoring and Alerting](#monitoring-and-alerting)
8. [Runbook: Common Operations](#runbook-common-operations)
9. [FedRAMP Compliance Controls](#fedramp-compliance-controls)
10. [Cost Estimation](#cost-estimation)
11. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

The AC3 platform deploys on AWS using a defense-in-depth architecture designed to meet FedRAMP High requirements. All compute runs on ECS Fargate in private subnets with no direct internet access. Database traffic is isolated in dedicated subnets that have no route to the internet. All data is encrypted at rest using customer-managed KMS keys and in transit using TLS 1.2+.

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  AWS WAF (OWASP Core, SQLi, Bad Inputs, Rate Limiting)  │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Application Load Balancer (Public Subnets, TLS 1.2+)   │
│  ACM Certificate · Access Logs → S3                      │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  ECS Fargate (Private Subnets)                           │
│  Non-root container · Auto-scaling (CPU/Memory)          │
│  Secrets from AWS Secrets Manager · Logs → CloudWatch    │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Aurora MySQL Serverless v2 (Isolated Database Subnets)  │
│  KMS encryption at rest · TLS required · Audit logging   │
│  Automated backups · Performance Insights                │
└─────────────────────────────────────────────────────────┘
```

### Environment Isolation

Each environment (dev, staging, prod) gets its own VPC with non-overlapping CIDR ranges, ensuring complete network isolation.

| Environment | VPC CIDR | AZs | WAF | GuardDuty | Security Hub | CloudTrail | AWS Config |
|---|---|---|---|---|---|---|---|
| **dev** | 10.10.0.0/16 | 2 | No | No | No | Yes | No |
| **staging** | 10.20.0.0/16 | 3 | Yes | Yes | Yes | Yes | Yes |
| **prod** | 10.30.0.0/16 | 3 | Yes | Yes | Yes | Yes | Yes |

### Subnet Layout (per environment)

| Tier | Purpose | Internet Access | Example CIDRs (prod) |
|---|---|---|---|
| **Public** | ALB only | Inbound via IGW | 10.30.1-3.0/24 |
| **Private** | ECS Fargate tasks | Outbound via NAT | 10.30.11-13.0/24 |
| **Database** | Aurora MySQL | None (isolated) | 10.30.21-23.0/24 |

---

## Prerequisites

Before deploying, ensure the following are in place:

1. **AWS Account** with administrative access (account: `Harrison-cook`)
2. **Terraform** >= 1.7.0 installed locally
3. **AWS CLI** v2 configured with credentials
4. **GitHub repository** `hcook-aoc/AC3` with Actions enabled
5. **Domain name** (optional for dev, required for staging/prod)
6. **ACM Certificate** for the domain (can be created via AWS Console or Terraform)

### Install Terraform

```bash
# macOS
brew install terraform

# Linux
wget https://releases.hashicorp.com/terraform/1.9.0/terraform_1.9.0_linux_amd64.zip
unzip terraform_1.9.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/
```

---

## Initial Setup (One-Time)

### Step 1: Create the Terraform State Backend

Before running Terraform for the first time, create the S3 bucket and DynamoDB table for remote state management. This only needs to be done once per AWS account.

```bash
# Create state bucket
aws s3api create-bucket \
  --bucket ac3-terraform-state \
  --region us-east-1

# Enable versioning (FedRAMP: state recovery)
aws s3api put-bucket-versioning \
  --bucket ac3-terraform-state \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket ac3-terraform-state \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms"
      }
    }]
  }'

# Block public access
aws s3api put-public-access-block \
  --bucket ac3-terraform-state \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Create DynamoDB lock table
aws dynamodb create-table \
  --table-name ac3-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

### Step 2: Configure GitHub Repository Variables

In the `hcook-aoc/AC3` repository, go to **Settings → Secrets and variables → Actions → Variables** and add:

| Variable | Value |
|---|---|
| `AWS_ACCOUNT_ID` | Your AWS account ID |
| `AWS_REGION` | `us-east-1` |

### Step 3: Set Up GitHub Environments

Create three GitHub environments (Settings → Environments):

- **dev** — No protection rules
- **staging** — Require reviewer approval
- **prod** — Require reviewer approval + deployment branch restriction (main only)

---

## Deploying an Environment

### Step 1: Initialize Terraform

```bash
cd infrastructure/terraform

# Initialize with environment-specific backend
terraform init -backend-config=environments/backend-dev.hcl

# For staging:
# terraform init -backend-config=environments/backend-staging.hcl -reconfigure

# For prod:
# terraform init -backend-config=environments/backend-prod.hcl -reconfigure
```

### Step 2: Plan

```bash
terraform plan -var-file=environments/dev.tfvars -out=dev.tfplan
```

Review the plan carefully. For the first deployment, expect approximately 60-80 resources to be created.

### Step 3: Apply

```bash
terraform apply dev.tfplan
```

### Step 4: Note the Outputs

After apply completes, note the key outputs:

```bash
terraform output

# Key outputs:
# ecr_repository_url  = "123456789.dkr.ecr.us-east-1.amazonaws.com/ac3-dev"
# alb_dns_name        = "ac3-dev-alb-1234567890.us-east-1.elb.amazonaws.com"
# ecs_cluster_name    = "ac3-dev"
# ecs_service_name    = "ac3-dev-service"
```

### Step 5: Populate Secrets

After the first Terraform apply, populate the application secrets in AWS Secrets Manager:

```bash
# Example: Set the JWT secret
aws secretsmanager put-secret-value \
  --secret-id ac3/dev/JWT_SECRET \
  --secret-string "your-jwt-secret-here"

# Example: Set the Caldera API key
aws secretsmanager put-secret-value \
  --secret-id ac3/dev/CALDERA_API_KEY \
  --secret-string "your-caldera-api-key"
```

Repeat for all secrets listed in `infrastructure/terraform/modules/secrets/main.tf`.

### Step 6: Build and Push Initial Image

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

# Build using the AWS Dockerfile
docker build -f Dockerfile.aws -t ac3-dev .

# Tag and push
docker tag ac3-dev:latest 123456789.dkr.ecr.us-east-1.amazonaws.com/ac3-dev:sha-initial
docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/ac3-dev:sha-initial
```

After the initial push, subsequent deployments are handled automatically by the `deploy-aws.yml` GitHub Actions workflow.

---

## CI/CD Pipeline

The deployment pipeline is fully automated through GitHub Actions with OIDC federation (no long-lived AWS credentials).

### Workflow: `deploy-aws.yml`

This workflow triggers on every push to `main` in the `hcook-aoc/AC3` repository. It can also be manually triggered with environment selection.

**Pipeline stages:**

1. **Setup** — Determines target environment and constructs resource names
2. **Build & Deploy** — Builds Docker image, pushes to ECR, updates ECS task definition, deploys
3. **Smoke Test** — Hits the `/api/health` endpoint to verify the deployment is healthy

**Manual deployment to staging/prod:**

```
GitHub → Actions → Deploy to AWS → Run workflow → Select environment
```

### Workflow: `ci.yml`

Runs on every push and PR to `main`. Performs TypeScript checking, Vitest unit tests, and Vite build verification. All jobs now use `ubuntu-latest` runners for compatibility with both repos.

### Workflow: `mirror-to-company.yml`

Mirrors pushes from `htcook/caldera-dashboard` to `hcook-aoc/AC3`. Requires a `COMPANY_PAT` secret in the personal repo. This is a backup mechanism — the Manus sandbox also has dual-push configured on the git remote.

---

## Secrets Management

All application secrets are stored in AWS Secrets Manager, encrypted with a customer-managed KMS key. Secrets are injected into ECS tasks at startup via the task definition's `secrets` block — they never appear in plaintext in the task definition or environment variables.

### Listing All Secrets

```bash
aws secretsmanager list-secrets \
  --filter Key=name,Values=ac3/dev/ \
  --query 'SecretList[*].Name' \
  --output table
```

### Rotating a Secret

```bash
# Update the secret value
aws secretsmanager put-secret-value \
  --secret-id ac3/prod/CALDERA_API_KEY \
  --secret-string "new-api-key-value"

# Force ECS to pick up the new value (rolling restart)
aws ecs update-service \
  --cluster ac3-prod \
  --service ac3-prod-service \
  --force-new-deployment
```

---

## Monitoring and Alerting

### CloudWatch Dashboard

Each environment has a pre-configured CloudWatch dashboard at:

> `https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=ac3-{env}`

The dashboard displays ECS CPU/memory, ALB request count/latency, Aurora CPU/connections, and recent application errors.

### Alarms

| Alarm | Threshold | Evaluation | Action |
|---|---|---|---|
| ECS CPU High | > 85% for 15 min | 3 periods × 5 min | SNS notification |
| ECS Memory High | > 90% for 15 min | 3 periods × 5 min | SNS notification |
| ALB 5xx Errors | > 50 in 5 min | 2 periods × 5 min | SNS notification |
| ALB Unhealthy Targets | > 0 for 2 min | 2 periods × 1 min | SNS notification |
| Aurora CPU High | > 80% for 15 min | 3 periods × 5 min | SNS notification |
| Aurora Connections High | > 800 for 10 min | 2 periods × 5 min | SNS notification |

### Log Access

```bash
# Tail ECS logs in real-time
aws logs tail /ecs/ac3-prod --follow

# Search for errors in the last hour
aws logs filter-log-events \
  --log-group-name /ecs/ac3-prod \
  --start-time $(date -d '1 hour ago' +%s000) \
  --filter-pattern "ERROR"
```

---

## Runbook: Common Operations

### Scale ECS Service

```bash
# Scale to 4 tasks
aws ecs update-service \
  --cluster ac3-prod \
  --service ac3-prod-service \
  --desired-count 4

# Auto-scaling handles this normally, but manual override is available
```

### Force Redeployment (Pick Up New Secrets)

```bash
aws ecs update-service \
  --cluster ac3-prod \
  --service ac3-prod-service \
  --force-new-deployment
```

### ECS Exec (Debug Container — Non-Prod Only)

```bash
aws ecs execute-command \
  --cluster ac3-dev \
  --task <task-id> \
  --container ac3-app \
  --interactive \
  --command "/bin/sh"
```

### Database Connection (Via ECS Exec)

```bash
# From inside the container:
mysql -h <aurora-endpoint> -u ac3admin -p --ssl-mode=REQUIRED
```

### Rollback to Previous Task Definition

```bash
# List recent task definitions
aws ecs list-task-definitions \
  --family-prefix ac3-prod \
  --sort DESC \
  --max-items 5

# Update service to use a previous revision
aws ecs update-service \
  --cluster ac3-prod \
  --service ac3-prod-service \
  --task-definition ac3-prod:<previous-revision>
```

### Database Snapshot (Manual)

```bash
aws rds create-db-cluster-snapshot \
  --db-cluster-identifier ac3-prod-aurora \
  --db-cluster-snapshot-identifier ac3-prod-manual-$(date +%Y%m%d)
```

### Terraform State Operations

```bash
# List all resources in state
terraform state list

# Import an existing resource
terraform import module.networking.aws_vpc.main vpc-12345678

# Remove a resource from state (without destroying it)
terraform state rm module.security.aws_guardduty_detector.main[0]
```

---

## FedRAMP Compliance Controls

The following table maps the infrastructure to specific NIST 800-53 Rev 5 controls required for FedRAMP High authorization.

| Control | Description | Implementation |
|---|---|---|
| **AC-6** | Least Privilege | Non-root container user, least-privilege IAM roles, security group restrictions |
| **AU-2** | Audit Events | CloudTrail (API calls), VPC Flow Logs, Aurora audit logs, ALB access logs |
| **AU-3** | Content of Audit Records | All logs include timestamp, source, action, outcome |
| **AU-6** | Audit Review | CloudWatch dashboards, automated alarms, Security Hub findings |
| **AU-12** | Audit Generation | Enabled on all services — CloudTrail, VPC, RDS, ALB, WAF |
| **CA-7** | Continuous Monitoring | Security Hub with NIST 800-53 standard, AWS Config rules |
| **CM-2** | Baseline Configuration | Terraform IaC, immutable container images, parameter groups |
| **CM-6** | Configuration Settings | AWS Config records all resource configurations |
| **CM-7** | Least Functionality | Minimal Docker image, no build tools in production, no SSH |
| **IR-4** | Incident Handling | GuardDuty threat detection, SNS alerting |
| **SC-5** | DoS Protection | WAF rate limiting (2000 req/IP), ALB connection limits |
| **SC-7** | Boundary Protection | WAF (OWASP rules), private subnets, isolated DB subnets, NACLs |
| **SC-8** | Transmission Confidentiality | TLS 1.2+ on ALB, `require_secure_transport` on Aurora |
| **SC-12** | Cryptographic Key Management | KMS CMK with automatic annual rotation |
| **SC-13** | Cryptographic Protection | AES-256 encryption at rest (S3, RDS, Secrets Manager, CloudTrail) |
| **SC-28** | Protection at Rest | KMS encryption on all data stores |
| **SI-2** | Flaw Remediation | ECR image scanning on push, immutable image tags |
| **SI-3** | Malicious Code Protection | WAF managed rules (bad inputs, SQLi, XSS) |
| **SI-4** | Information System Monitoring | GuardDuty, CloudWatch, VPC Flow Logs |

---

## Cost Estimation

Approximate monthly costs per environment (us-east-1, April 2026 pricing):

| Component | Dev | Staging | Prod |
|---|---|---|---|
| **ECS Fargate** (tasks × hours) | ~$30 | ~$60 | ~$120 |
| **Aurora Serverless v2** (ACU-hours) | ~$45 | ~$90 | ~$180 |
| **ALB** | ~$20 | ~$20 | ~$20 |
| **NAT Gateway** (data processing) | ~$35 | ~$35 | ~$35 |
| **WAF** | $0 | ~$10 | ~$10 |
| **CloudWatch** (logs + metrics) | ~$15 | ~$25 | ~$40 |
| **Secrets Manager** | ~$12 | ~$12 | ~$12 |
| **KMS** | ~$1 | ~$1 | ~$1 |
| **S3** (logs, state, CloudTrail) | ~$5 | ~$10 | ~$15 |
| **GuardDuty** | $0 | ~$10 | ~$10 |
| **Security Hub** | $0 | ~$5 | ~$5 |
| **Total** | **~$163/mo** | **~$278/mo** | **~$448/mo** |

These are estimates based on moderate usage. Actual costs will vary based on traffic, data volume, and Aurora scaling behavior. The dev environment can be further reduced by stopping the ECS service when not in use.

---

## Troubleshooting

### ECS Tasks Failing to Start

1. Check CloudWatch logs: `/ecs/ac3-{env}`
2. Verify secrets are populated: `aws secretsmanager get-secret-value --secret-id ac3/{env}/DATABASE_URL`
3. Check security group rules allow outbound traffic (NAT gateway)
4. Verify ECR image exists: `aws ecr describe-images --repository-name ac3-{env}`

### Database Connection Refused

1. Verify Aurora cluster is running: `aws rds describe-db-clusters --db-cluster-identifier ac3-{env}-aurora`
2. Check security group allows port 3306 from ECS security group
3. Verify `require_secure_transport` is ON and the app uses SSL

### GitHub Actions OIDC Failure

1. Verify the OIDC provider exists: `aws iam list-open-id-connect-providers`
2. Check the deploy role's trust policy matches the repo name exactly
3. Ensure `AWS_ACCOUNT_ID` variable is set in GitHub repository settings
4. Verify the GitHub environment name matches the workflow's `environment` field

### Terraform State Lock

```bash
# If a lock is stuck (e.g., after a crash):
terraform force-unlock <lock-id>
```

### WAF Blocking Legitimate Traffic

```bash
# Check WAF logs
aws wafv2 get-logging-configuration \
  --resource-arn <web-acl-arn>

# Temporarily set a rule to COUNT mode instead of BLOCK
# (do this in the Terraform config, not the console, to maintain IaC)
```

---

## File Structure

```
infrastructure/
├── terraform/
│   ├── main.tf                          # Root module — composes all child modules
│   ├── variables.tf                     # Input variables
│   ├── outputs.tf                       # Output values
│   ├── environments/
│   │   ├── dev.tfvars                   # Dev environment config
│   │   ├── staging.tfvars               # Staging environment config
│   │   ├── prod.tfvars                  # Production environment config
│   │   ├── backend-dev.hcl              # Dev state backend config
│   │   ├── backend-staging.hcl          # Staging state backend config
│   │   └── backend-prod.hcl             # Prod state backend config
│   └── modules/
│       ├── networking/                  # VPC, subnets, ALB, WAF
│       ├── ecr/                         # Container registry
│       ├── database/                    # Aurora MySQL Serverless v2
│       ├── ecs/                         # Fargate cluster, service, auto-scaling
│       ├── secrets/                     # Secrets Manager
│       ├── security/                    # KMS, GuardDuty, Security Hub, CloudTrail
│       ├── monitoring/                  # CloudWatch logs, alarms, dashboard
│       └── oidc/                        # GitHub Actions OIDC federation
├── DEPLOYMENT.md                        # This file
.github/workflows/
├── deploy-aws.yml                       # AWS ECS deployment (OIDC)
├── deploy-do.yml                        # DigitalOcean deployment (existing)
├── ci.yml                               # CI pipeline
├── prebuild-client.yml                  # Client asset pre-build
└── mirror-to-company.yml                # Repo mirroring
Dockerfile.aws                           # FedRAMP-hardened multi-stage Dockerfile
```
