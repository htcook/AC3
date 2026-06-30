# AC3 — AWS Deployment Status

**Author:** Harrison Cook  
**Last Updated:** May 12, 2026  
**Platform:** AceofCloud Cybersecurity Command Center (AC3)

---

## Current Status: Partially Deployed — Blocked on IAM PassRole

The AC3 application Docker image has been successfully built and pushed to ECR. Infrastructure (VPC, ALB, RDS, ECS cluster) is provisioned. The deployment is blocked on a single IAM permission (`iam:PassRole`) that prevents registering ECS task definitions.

---

## Completed Steps

| Step | Status | Details |
|---|---|---|
| Docker image build | **Done** | GitHub Actions `build-push-ecr.yml` run #25736643488 succeeded |
| ECR image push | **Done** | `808038814732.dkr.ecr.us-east-1.amazonaws.com/ac3/caldera-dashboard:latest` (tag: `6ea23249`, ~808 MB) |
| ALB health check fix | **Done** | Target group `ac3-dev-app-tg` health check port changed from 3000 to 8080 |
| Security group fix | **Done** | Added port 8080 inbound rule from ALB SG (`sg-063ffbb6c46c3aaca`) to App SG (`sg-047e3a22d780b0911`) |
| Secrets Manager | **Partial** | Created `ac3/dev/app` with DATABASE_URL; remaining env vars need population |
| ECS task definition | **Prepared** | JSON at `infrastructure/ecs-task-definition.json`, deployment script at `infrastructure/deploy-ecs.sh` |
| PassRole policy | **Prepared** | Inline policy JSON at `infrastructure/passrole-inline-policy.json` |

---

## Blocking Issue: iam:PassRole Denied

The PowerUserAccess SSO permission set for user `harrison-cook` does not include `iam:PassRole`. This is required to register ECS task definitions that reference execution and task roles.

**Error:**

```
AccessDeniedException: User: arn:aws:sts::808038814732:assumed-role/AWSReservedSSO_PowerUserAccess_cb61023952739181/harrison-cook
is not authorized to perform: iam:PassRole on resource: arn:aws:iam::808038814732:role/ac3-dev-ecs-execution-role
```

**Resolution:** The AWS account administrator needs to add an inline policy to the PowerUserAccess SSO permission set. The policy JSON is at `infrastructure/passrole-inline-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPassRoleForAC3ECS",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::808038814732:role/ac3-*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": [
            "ecs-tasks.amazonaws.com",
            "codebuild.amazonaws.com"
          ]
        }
      }
    }
  ]
}
```

**Where to apply:** AWS IAM Identity Center → Permission Sets → PowerUserAccess → Inline Policy → Add the above JSON.

---

## Infrastructure Inventory

### Networking

| Resource | ID / Name | Details |
|---|---|---|
| VPC | `ac3-dev-vpc` | CIDR: 10.0.0.0/16 |
| Public Subnets | `ac3-dev-public-a` (`subnet-02dda7538b22c2eeb`), `ac3-dev-public-b` (`subnet-0765c6310f5246844`) | AZ: us-east-1a/1b |
| App Subnets | `ac3-dev-app-a` (`subnet-00d25f8e4a7dcab53`), `ac3-dev-app-b` (`subnet-0dcde6160e4f644ac`) | Private, AZ: us-east-1a/1b |
| Data Subnets | `ac3-dev-data-a` (`subnet-09369db2749a88c8f`), `ac3-dev-data-b` (`subnet-0f79d45d59793ee19`) | Private, AZ: us-east-1a/1b |
| C2 Subnets | `ac3-dev-c2-a` (`subnet-0f923966128f42357`), `ac3-dev-c2-b` (`subnet-0aa77cad20f8155d7`) | Isolated, AZ: us-east-1a/1b |
| NAT Gateways | `nat-01a76b6e8ec91f086`, `nat-0bf0eee2709688f54` | One per AZ in public subnets |

### Load Balancer

| Resource | Details |
|---|---|
| ALB | `ac3-dev-alb` (DNS: `ac3-dev-alb-1142114658.us-east-1.elb.amazonaws.com`) |
| Listener | Port 80 HTTP → forwards to target group |
| Target Group | `ac3-dev-app-tg` (ARN: `...targetgroup/ac3-dev-app-tg/258e8561a0cf2ce3`) |
| Target Port | 3000 (default), health check port overridden to 8080 |
| Health Check | `GET /api/health` on port 8080 |

### Security Groups

| SG Name | ID | Purpose |
|---|---|---|
| `ac3-dev-sg-alb` | `sg-063ffbb6c46c3aaca` | ALB: HTTP/HTTPS from internet |
| `ac3-dev-sg-app` | `sg-047e3a22d780b0911` | App: port 3000 + 8080 from ALB only |
| `ac3-dev-sg-data` | `sg-0e781705c253154a3` | Data: MySQL 3306 from App SG only |
| `ac3-dev-sg-c2` | `sg-0acb3a3f8955a58a3` | C2: isolated offensive traffic |

### Database

| Resource | Details |
|---|---|
| RDS MySQL | `ac3-dev-mysql.c2d8yioy4rye.us-east-1.rds.amazonaws.com` |
| Port | 3306 |
| Database | `ac3dev` |
| User | `ac3admin` |
| Password | In Secrets Manager `ac3/dev/rds-master` |
| Subnet | Private (data subnets only) |

### IAM Roles

| Role | Purpose |
|---|---|
| `ac3-dev-ecs-execution-role` | ECS task execution (pull ECR images, read Secrets Manager) |
| `ac3-dev-app-task-role` | App container runtime permissions (S3, CloudWatch, etc.) |
| `ac3-dev-c2-task-role` | C2 container runtime permissions (isolated) |
| `ac3-codebuild-service-role` | CodeBuild service role |

### Other Resources

| Resource | Details |
|---|---|
| ECR | `808038814732.dkr.ecr.us-east-1.amazonaws.com/ac3/caldera-dashboard` |
| ECS Cluster | `ac3-dev` (Fargate, 0 services currently) |
| CloudWatch Log Group | `/ecs/ac3-dev` |
| S3 Buckets | `ac3-dev-alb-logs-*`, `ac3-dev-assets-*`, `ac3-dev-codebuild-*`, `ac3-dev-evidence-*`, `ac3-dev-reports-*` |
| Secrets Manager | `ac3/dev/rds-master` (RDS creds), `ac3/dev/app` (app env vars — partial) |

---

## Deployment Steps (Once PassRole is Granted)

### Step 1: Refresh AWS Credentials

The current session token is temporary (STS). Get fresh credentials:

```bash
aws sso login --profile ac3-dev
# Or export new session token to /home/ubuntu/aws-env.sh
```

### Step 2: Populate Secrets Manager

Edit `infrastructure/populate-secrets.sh` with actual values from the DO App Platform environment, then run:

```bash
bash infrastructure/populate-secrets.sh
```

Key values to populate (copy from DO App Platform → Settings → App-Level Environment Variables):

- `JWT_SECRET` — session signing key
- `VITE_APP_ID` — Manus OAuth app ID
- `OAUTH_SERVER_URL` — Manus OAuth backend URL
- `VITE_OAUTH_PORTAL_URL` — Manus login portal URL
- `OWNER_OPEN_ID` — owner's Manus Open ID
- `BUILT_IN_FORGE_API_URL` — Manus Forge API URL
- `BUILT_IN_FORGE_API_KEY` — Manus Forge API token
- `OPENAI_API_KEY` — direct OpenAI API key
- `CALDERA_PASSWORD` — Caldera service account password
- `GOPHISH_API_KEY` — GoPhish API key
- `SHODAN_API_KEY` — Shodan API key
- `DO_SPACES_KEY` / `DO_SPACES_SECRET` — DigitalOcean Spaces credentials

### Step 3: Deploy to ECS

```bash
bash infrastructure/deploy-ecs.sh latest
```

This script:
1. Verifies the ECR image exists
2. Registers the ECS task definition with all env vars from Secrets Manager
3. Creates the ECS service (or updates if it exists)
4. Waits for service stabilization

### Step 4: Verify Health

```bash
curl http://ac3-dev-alb-1142114658.us-east-1.elb.amazonaws.com/api/health
```

### Step 5: Fix ACM Certificate (for HTTPS)

The previous ACM certificate request for `aceofcloud.io` timed out because DNS validation records were never added. To fix:

```bash
# Request new certificate
aws acm request-certificate \
  --domain-name aceofcloud.io \
  --validation-method DNS \
  --subject-alternative-names "*.aceofcloud.io" \
  --region us-east-1

# Get the DNS validation records
aws acm describe-certificate \
  --certificate-arn <new-cert-arn> \
  --query 'Certificate.DomainValidationOptions[*].ResourceRecord'

# Add the CNAME records to your DNS zone (DigitalOcean or Route53)
# Then add HTTPS listener to ALB:
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:us-east-1:808038814732:loadbalancer/app/ac3-dev-alb/186065a622039a31 \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=<new-cert-arn> \
  --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:us-east-1:808038814732:targetgroup/ac3-dev-app-tg/258e8561a0cf2ce3
```

---

## Files Created This Session

| File | Purpose |
|---|---|
| `infrastructure/ecs-task-definition.json` | ECS Fargate task definition (2 vCPU, 4 GB) |
| `infrastructure/deploy-ecs.sh` | One-command ECS deployment script |
| `infrastructure/populate-secrets.sh` | Secrets Manager population script |
| `infrastructure/passrole-inline-policy.json` | IAM inline policy for boss to apply |
| `infrastructure/AWS-DEPLOYMENT-STATUS.md` | This document |
| `Dockerfile.aws` | Multi-stage Docker build (updated with entrypoint) |
| `docker-entrypoint.sh` | Container entrypoint (runs DB migrations) |
| `.github/workflows/build-push-ecr.yml` | GitHub Actions CI/CD for ECR |
