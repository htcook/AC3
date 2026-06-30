# AC3 — AWS Standalone Setup Guide

**Author:** Harrison Cook  
**Last Updated:** April 28, 2026  
**Platform:** AceofCloud Cybersecurity Command Center (AC3)

This document captures everything needed to deploy AC3 on AWS independently, without relying on the Manus sandbox session. It consolidates session-only state, credentials, architecture decisions, and step-by-step instructions.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Repository Structure](#repository-structure)
3. [GitHub Repository Setup](#github-repository-setup)
4. [AWS Account Setup](#aws-account-setup)
5. [Environment Variables Reference](#environment-variables-reference)
6. [Terraform Deployment](#terraform-deployment)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Secrets Population](#secrets-population)
9. [DNS and TLS](#dns-and-tls)
10. [Operational Runbook](#operational-runbook)

---

## Architecture Overview

AC3 runs on **AWS ECS Fargate** with the following FedRAMP High-compliant stack:

| Component | AWS Service | Purpose |
|---|---|---|
| Compute | ECS Fargate | Serverless containers, no OS patching |
| Database | Aurora MySQL Serverless v2 | FedRAMP-authorized, KMS-encrypted |
| Secrets | Secrets Manager | KMS-encrypted, injected at runtime |
| Networking | VPC + ALB + WAF | 3-tier isolation, DDoS protection |
| Container Registry | ECR | Image scanning, immutable tags |
| Monitoring | CloudWatch + GuardDuty | Logs, alarms, threat detection |
| Security | Security Hub + CloudTrail + Config | Compliance monitoring, audit trail |
| CI/CD | GitHub Actions + OIDC | No long-lived AWS credentials |

**Three environments:** dev, staging, prod — each in its own VPC with non-overlapping CIDRs.

---

## Repository Structure

The project lives in two Git repositories that mirror each other:

| Repository | Purpose | Access |
|---|---|---|
| `htcook/caldera-dashboard` | Personal development repo (origin) | Harrison's personal GitHub |
| `hcook-aoc/AC3` | Company deployment repo | Harrison's AceofCloud GitHub |
| `aceofcloud/AC3` | Organization repo (future) | AceofCloud org — pending access |

**Dual-push mirroring** is configured so every push to `htcook/caldera-dashboard` also pushes to `hcook-aoc/AC3`. The `mirror-to-company.yml` GitHub Action serves as a backup sync mechanism.

### Key Infrastructure Files

```
infrastructure/
├── AWS-SETUP-GUIDE.md          ← This document
├── DEPLOYMENT.md               ← Detailed deployment runbook
├── scripts/
│   └── bootstrap.sh            ← First-time AWS setup (S3 state bucket + DynamoDB lock)
└── terraform/
    ├── main.tf                 ← Root module composition
    ├── variables.tf            ← Input variables
    ├── outputs.tf              ← Output values
    ├── environments/
    │   ├── dev.tfvars          ← Dev environment config
    │   ├── staging.tfvars      ← Staging environment config
    │   ├── prod.tfvars         ← Production environment config
    │   ├── backend-dev.hcl     ← Dev state backend
    │   ├── backend-staging.hcl ← Staging state backend
    │   └── backend-prod.hcl    ← Prod state backend
    └── modules/
        ├── networking/         ← VPC, subnets, NAT, ALB, WAF
        ├── ecr/                ← Container registry
        ├── database/           ← Aurora MySQL Serverless v2
        ├── ecs/                ← Fargate cluster, service, task def
        ├── secrets/            ← Secrets Manager (all app secrets)
        ├── security/           ← GuardDuty, Security Hub, CloudTrail
        ├── monitoring/         ← CloudWatch logs, alarms, dashboard
        └── oidc/               ← GitHub Actions OIDC federation
```

---

## GitHub Repository Setup

### Secrets (htcook/caldera-dashboard)

These are already configured:

| Secret | Purpose | Status |
|---|---|---|
| `COMPANY_PAT` | PAT for pushing to `hcook-aoc/AC3` | Set (aceofcloud PAT) |
| `DIGITALOCEAN_ACCESS_TOKEN` | DigitalOcean deployment (legacy) | Set |
| `PAT_TOKEN` | General-purpose PAT | Set |

### Variables (htcook/caldera-dashboard)

| Variable | Value | Status |
|---|---|---|
| `AWS_ACCOUNT_ID` | `808038814732` | Set |
| `AWS_REGION` | `us-east-1` | Set |

### Variables Needed on hcook-aoc/AC3

These must be set manually (Settings → Secrets and variables → Actions → Variables):

| Variable | Value |
|---|---|
| `AWS_ACCOUNT_ID` | `808038814732` |
| `AWS_REGION` | `us-east-1` |

### GitHub Environments (hcook-aoc/AC3)

Create three environments (Settings → Environments):

| Environment | Branch Protection | Reviewers |
|---|---|---|
| `development` | None | None |
| `staging` | `main` branch only | Optional |
| `production` | `main` branch only | Required (1+ reviewer) |

---

## AWS Account Setup

**Account ID:** `808038814732`  
**Account Alias:** `Harrison-cook`  
**Region:** `us-east-1` (GovCloud recommended for FedRAMP High production)

### Step 1: Bootstrap Terraform State

Run from a machine with AWS CLI configured:

```bash
cd infrastructure/scripts
chmod +x bootstrap.sh
./bootstrap.sh us-east-1
```

This creates:
- S3 bucket: `ac3-terraform-state-808038814732` (versioned, encrypted)
- DynamoDB table: `ac3-terraform-locks` (state locking)

### Step 2: Configure AWS CLI

```bash
aws configure --profile ac3-dev
# AWS Access Key ID: <your-key>
# AWS Secret Access Key: <your-secret>
# Default region: us-east-1
# Default output: json
```

---

## Environment Variables Reference

This is the **complete list** of environment variables AC3 needs, organized by category. All are defined in `server/_core/env.ts` and provisioned as AWS Secrets Manager entries via the Terraform secrets module.

### Core Platform (Required)

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | MySQL connection string | Auto-constructed by Terraform from Aurora endpoint |
| `JWT_SECRET` | Session cookie signing key | Random 64-char string |
| `OAUTH_SERVER_URL` | Manus OAuth backend URL | `https://api.manus.im` |
| `VITE_APP_ID` | Manus OAuth application ID | From Manus dashboard |
| `OWNER_OPEN_ID` | Owner's Manus Open ID | From Manus dashboard |
| `BUILT_IN_FORGE_API_URL` | Manus Forge API URL | From Manus dashboard |
| `BUILT_IN_FORGE_API_KEY` | Manus Forge API bearer token | From Manus dashboard |
| `OPENAI_API_KEY` | Direct OpenAI API access | `sk-...` |

### Cyber C2 — Caldera (Required for red team ops)

| Variable | Description | Current Value |
|---|---|---|
| `CALDERA_BASE_URL` | Caldera HTTPS proxy | `https://caldera.aceofcloud.io` |
| `CALDERA_API_KEY` | Caldera REST API key | Rotated — stored in Manus secrets |
| `CALDERA_USERNAME` | Caldera service account | `red` |
| `CALDERA_PASSWORD` | Caldera service account password | Stored in Manus secrets |

### GoPhish (Required for phishing simulation)

| Variable | Description | Current Value |
|---|---|---|
| `GOPHISH_BASE_URL` | GoPhish direct IP or proxy | `https://137.184.7.224:3333` |
| `GOPHISH_API_KEY` | GoPhish REST API key | Stored in Manus secrets |

### Passive ASM Connectors

| Variable | Description | Free Tier? |
|---|---|---|
| `SHODAN_API_KEY` | Shodan internet scanner | Yes (limited) |
| `CENSYS_API_ID` | Censys search API ID | Yes (limited) |
| `CENSYS_API_SECRET` | Censys search API secret | Yes (limited) |
| `URLSCAN_API_KEY` | URLScan.io | Yes |
| `SECURITYTRAILS_API_KEY` | SecurityTrails DNS | Yes (limited) |
| `ABUSEIPDB_API_KEY` | IP abuse reputation | Yes |
| `DEHASHED_API_KEY` | Breach data search | Paid |
| `DEHASHED_EMAIL` | DeHashed account email | — |
| `NVD_API_KEY` | NIST NVD vulnerability DB | Free |

### OSINT Pipeline Expansion

| Variable | Description |
|---|---|
| `BINARYEDGE_API_KEY` | BinaryEdge internet scanning |
| `GREYNOISE_API_KEY` | GreyNoise threat intelligence |
| `VIRUSTOTAL_API_KEY` | VirusTotal malware/URL analysis |
| `HIBP_API_KEY` | Have I Been Pwned breach check |
| `WHOISXML_API_KEY` | WHOIS/DNS lookup |
| `LEAKIX_API_KEY` | LeakIX exposure search |
| `FULLHUNT_API_KEY` | FullHunt attack surface |
| `NETLAS_API_KEY` | Netlas internet intelligence |
| `HUNTER_API_KEY` | Hunter.io email finder |
| `PASSIVETOTAL_API_KEY` | RiskIQ PassiveTotal |
| `INTELX_API_KEY` | Intelligence X OSINT |
| `HUDSON_ROCK_API_KEY` | Hudson Rock infostealer DB |
| `LEAKCHECK_API_KEY` | LeakCheck credential exposure |

### GitHub Recon

| Variable | Description |
|---|---|
| `GITHUB_PAT` | Fine-grained PAT for code recon dorks |
| `GITHUB_CLASSIC_TOKEN` | Classic token (rate limit failover) |

### HackerOne Bug Bounty

| Variable | Description |
|---|---|
| `HACKERONE_API_KEY` | HackerOne API key |
| `HACKERONE_API_USERNAME` | HackerOne API username |

### DigitalOcean (Legacy + Storage)

| Variable | Description | Default |
|---|---|---|
| `DIGITALOCEAN_ACCESS_TOKEN` | DO API token (domain purchasing) | — |
| `DO_SPACES_KEY` | Spaces access key | — |
| `DO_SPACES_SECRET` | Spaces secret key | — |
| `DO_SPACES_BUCKET` | Spaces bucket name | `aceofcloud-reports` |
| `DO_SPACES_REGION` | Spaces region | `nyc3` |
| `DO_SPACES_ENDPOINT` | Spaces endpoint URL | `https://nyc3.digitaloceanspaces.com` |

### Scan Server

| Variable | Description | Default |
|---|---|---|
| `SCAN_SERVER_HOST` | Offensive tools droplet IP | — |
| `SCAN_SERVER_USER` | SSH user | `root` |

### ZAP (DAST)

| Variable | Description |
|---|---|
| `ZAP_API_KEY` | OWASP ZAP API key |
| `ZAP_BASE_URL` | ZAP proxy URL |

### C2 Frameworks

**Metasploit MSGRPC:**

| Variable | Description | Default |
|---|---|---|
| `MSF_RPC_HOST` | Metasploit RPC host | — |
| `MSF_RPC_PORT` | Metasploit RPC port | `55553` |
| `MSF_RPC_USER` | RPC username | `msf` |
| `MSF_RPC_PASS` | RPC password | — |
| `MSF_RPC_SSL` | Enable SSL | `false` |

**Cobalt Strike:**

| Variable | Description |
|---|---|
| `CS_TEAM_SERVER_URL` | Team server URL |
| `CS_TEAM_SERVER_PORT` | Team server port (default: `50050`) |
| `CS_API_KEY` | API key |
| `CS_API_PORT` | API port (default: `55553`) |
| `CS_USERNAME` | Username |
| `CS_PASSWORD` | Password |

**Empire C2 (BC Security / Starkiller):**

| Variable | Description | Default |
|---|---|---|
| `EMPIRE_BASE_URL` | Empire REST API URL | — |
| `EMPIRE_API_KEY` | Empire API key | — |
| `EMPIRE_USERNAME` | Admin username | `empireadmin` |
| `EMPIRE_PASSWORD` | Admin password | — |

**Sliver C2 (gRPC):**

| Variable | Description |
|---|---|
| `SLIVER_SERVER_URL` | Sliver gRPC server URL |
| `SLIVER_OPERATOR_TOKEN` | Operator authentication token |
| `SLIVER_OPERATOR_CONFIG` | Base64-encoded operator config JSON |

**Manjusaka C2 (DEPRECATED — REC-LEGAL-001):**

| Variable | Description |
|---|---|
| `MANJUSAKA_SERVER_URL` | Server URL |
| `MANJUSAKA_API_TOKEN` | API token |
| `MANJUSAKA_ADMIN_PASSWORD` | Admin password |

---

## Terraform Deployment

### Initialize (First Time)

```bash
cd infrastructure/terraform

# Dev environment
terraform init -backend-config=environments/backend-dev.hcl

# Plan
terraform plan -var-file=environments/dev.tfvars -out=dev.tfplan

# Apply
terraform apply dev.tfplan
```

### Switch Environments

```bash
# Staging
terraform init -backend-config=environments/backend-staging.hcl -reconfigure
terraform plan -var-file=environments/staging.tfvars -out=staging.tfplan
terraform apply staging.tfplan

# Production
terraform init -backend-config=environments/backend-prod.hcl -reconfigure
terraform plan -var-file=environments/prod.tfvars -out=prod.tfplan
terraform apply prod.tfplan
```

---

## CI/CD Pipeline

### Workflow: deploy-aws.yml

Triggers on push to `main` in `hcook-aoc/AC3`. Uses **OIDC federation** (no long-lived AWS credentials).

**Pipeline stages:**
1. **Setup** — Determines target environment, constructs resource names
2. **Build** — Builds Docker image using `Dockerfile.aws`, pushes to ECR
3. **Deploy** — Updates ECS task definition, deploys new service version
4. **Verify** — Checks service stability and health endpoint

### Workflow: mirror-to-company.yml

Backup sync from `htcook/caldera-dashboard` → `hcook-aoc/AC3`. Requires `COMPANY_PAT` secret.

### Workflow: ci.yml

Runs on every push/PR: TypeScript checking, Vitest tests, Vite build verification.

---

## Secrets Population

After the first `terraform apply`, populate secrets via AWS CLI:

```bash
# Core secrets
aws secretsmanager put-secret-value --secret-id ac3/dev/JWT_SECRET --secret-string "<random-64-char>"
aws secretsmanager put-secret-value --secret-id ac3/dev/CALDERA_API_KEY --secret-string "<your-key>"
aws secretsmanager put-secret-value --secret-id ac3/dev/CALDERA_PASSWORD --secret-string "<your-password>"
aws secretsmanager put-secret-value --secret-id ac3/dev/GOPHISH_API_KEY --secret-string "<your-key>"
aws secretsmanager put-secret-value --secret-id ac3/dev/OPENAI_API_KEY --secret-string "<your-key>"

# Repeat for each secret in the secrets module
# Replace ac3/dev/ with ac3/staging/ or ac3/prod/ for other environments
```

The full list of secrets is defined in `infrastructure/terraform/modules/secrets/main.tf`.

---

## DNS and TLS

### Current DNS Records (DigitalOcean)

| Subdomain | Type | Target |
|---|---|---|
| `caldera.aceofcloud.io` | A/CNAME | Caldera HTTPS proxy (134.199.213.248) |
| `gophish.aceofcloud.io` | A | GoPhish server (137.184.7.224) — DNS not yet created |

### AWS TLS Setup

1. Request an ACM certificate for your domain
2. Add the certificate ARN to the environment tfvars (`certificate_arn`)
3. Terraform will attach it to the ALB listener

---

## Operational Runbook

### View Logs

```bash
aws logs tail /ecs/ac3-dev --follow
```

### ECS Exec (Debug — Non-Prod Only)

```bash
aws ecs execute-command \
  --cluster ac3-dev \
  --task <task-id> \
  --container ac3-app \
  --interactive \
  --command "/bin/sh"
```

### Force Redeployment

```bash
aws ecs update-service \
  --cluster ac3-dev \
  --service ac3-dev-service \
  --force-new-deployment
```

### Rollback

```bash
# List recent task definitions
aws ecs list-task-definitions --family-prefix ac3-dev --sort DESC --max-items 5

# Update service to previous revision
aws ecs update-service \
  --cluster ac3-dev \
  --service ac3-dev-service \
  --task-definition ac3-dev:<previous-revision>
```

---

## Session-Only State (Not in Repo)

The following items exist only in the Manus sandbox session and are **not** stored in the Git repository:

1. **Git remote credentials** — PATs embedded in `user_github` push URLs. These are session-specific and will be re-created by Manus on next session.
2. **Manus platform secrets** — All `webdev_request_secrets` values (CALDERA_API_KEY, CALDERA_PASSWORD, GOPHISH_API_KEY, etc.) are stored in the Manus platform, not in Git. For AWS, these must be manually populated in AWS Secrets Manager.
3. **Database data** — The Manus-hosted TiDB database content is not in the repo. For AWS, Aurora MySQL starts empty; you may need to run migrations (`pnpm db:push`) and seed data.

### Migration Checklist

When moving from Manus hosting to AWS:

- [ ] Run `infrastructure/scripts/bootstrap.sh` to create Terraform state backend
- [ ] Run `terraform apply` for the target environment
- [ ] Populate all secrets in AWS Secrets Manager (see [Secrets Population](#secrets-population))
- [ ] Set `AWS_ACCOUNT_ID` and `AWS_REGION` variables on `hcook-aoc/AC3`
- [ ] Create GitHub environments (development, staging, production)
- [ ] Run `pnpm db:push` against the Aurora MySQL endpoint to create tables
- [ ] Request ACM certificate and update `certificate_arn` in tfvars
- [ ] Verify health endpoint: `curl https://<alb-dns>/api/health`
- [ ] Update DNS records to point to the ALB
