# AC3 AWS Migration — Account Reference

This document captures the AWS Organization account structure for migrating AC3 from Development into Staging and Production environments.

---

## AWS Organization Accounts

| Account Name | Account ID | Purpose |
|---|---|---|
| aceofcloud-aw | 326867334406 | Organization management account |
| **Development** | **808038814732** | Current AC3 deployment (ECS, RDS, ECR) |
| LogArchive | 016042452350 | Centralized logging |
| **Production** | **184974284696** | Target production environment |
| SecurityTooling | 672003402407 | Security tooling and monitoring |
| SharedServices | 890319879326 | Shared infrastructure services |
| **Staging** | **238043187472** | Pre-production validation environment |

---

## Current Development Environment (808038814732)

- **ECS Cluster:** ac3-dev
- **ECS Service:** ac3-dev-app
- **ECR Repository:** ac3/caldera-dashboard
- **RDS Instance:** ac3-dev-mysql (db.t3.medium, MySQL 8.0)
- **RDS Parameter Group:** ac3-dev-mysql80
- **Region:** us-east-1
- **Domain:** ac3.aceofcloud.io

---

## Migration Path

```
Development (808038814732)
    │
    ▼
Staging (238043187472)
    │
    ▼
Production (184974284696)
```

---

## Access Roles

The following accounts have PowerUser access keys configured:

- **Development** — 2 PowerUser roles with access keys
- **Production** — 2 PowerUser roles with access keys
- **Staging** — 2 PowerUser roles with access keys

---

## Migration Checklist (Completed May 15, 2026)

- [x] Configure cross-account ECR access (Staging + Prod pull from Dev ECR 808038814732)
- [x] Create RDS instance in Staging (ac3-staging-mysql, db.t3.micro, MySQL 8.0)
- [x] Create RDS instance in Production (ac3-production-mysql, db.t3.micro, MySQL 8.0)
- [x] Create ECS cluster + service in Staging (ac3-staging / ac3-staging-app)
- [x] Create ECS cluster + service in Production (ac3-production / ac3-production-app)
- [x] Create IAM roles (execution + task) in Staging and Production
- [x] Configure ALBs with security groups in Staging and Production
- [x] Set up DNS: staging.aceofcloud.io → Staging ALB, app.aceofcloud.io → Production ALB
- [x] Request and validate ACM certs for staging.aceofcloud.io and app.aceofcloud.io
- [x] Add HTTPS listeners (TLS 1.3) + HTTP→HTTPS redirect on both ALBs
- [x] Run DB migrations (370+ tables) in both environments
- [x] Create deploy-multi-env.yml CI/CD workflow (build once, deploy everywhere)
- [x] Request Production wildcard cert for aceofcloud.io + *.aceofcloud.io
- [x] Prepare GoDaddy DNS configuration document (references/godaddy-dns-configuration.md)
- [ ] Add GitHub Secrets for Staging/Production to hcook-aoc/AC3
- [ ] Boss enters DNS records in GoDaddy and changes nameservers
- [ ] Update Production ALB cert to wildcard after validation
- [ ] Configure CloudWatch cross-account log aggregation to LogArchive (016042452350)
- [ ] Set up SecurityTooling (672003402407) for cross-account GuardDuty/SecurityHub

---

## Environment Credentials (Session-Based)

These are temporary STS session credentials obtained via IAM Identity Center. They expire and must be refreshed from the SSO portal.

> **REDACTED** — Session credentials are stored in Manus secrets (AWS_PROD_ACCESS_KEY_ID, AWS_PROD_SECRET_ACCESS_KEY, AWS_PROD_SESSION_TOKEN, AWS_STAGING_ACCESS_KEY_ID, AWS_STAGING_SECRET_ACCESS_KEY, AWS_STAGING_SESSION_TOKEN, AWS_DEV_ACCESS_KEY_ID, AWS_DEV_SECRET_ACCESS_KEY, AWS_DEV_SESSION_TOKEN). Refresh from the SSO portal when expired.

---

## AWS SSO Login

| Field | Value |
|---|---|
| Portal URL | `d-90660b5f17.awsapps.com` |
| Username | `Harrison-cook` |
| Password | `<REDACTED — stored in Manus secrets as AC3_USER_PASSWORD>` |

> **Note:** These are temporary STS session tokens from IAM Identity Center. They expire (typically within 1-12 hours). Refresh from the SSO portal at `d-90660b5f17.awsapps.com` using the credentials above.

---

## Notes

- AWS SSO portal: `d-90660b5f17.awsapps.com`
- All accounts accessible via AWS IAM Identity Center (SSO)
- Current GitHub Actions workflow uses OIDC for the deploy workflow (needs trust policy per account)
- Manual build workflow (`build-push-ecr.yml`) uses access key credentials stored in GitHub Secrets
- For migration: each target account needs its own ECR repo, ECS cluster, RDS instance, and GitHub Actions OIDC trust policy
