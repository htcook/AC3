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

## Migration Checklist (Future)

- [ ] Create ECR repository in Staging account (238043187472)
- [ ] Create RDS instance in Staging account
- [ ] Set up ECS cluster and service in Staging
- [ ] Configure cross-account ECR image replication (Dev → Staging → Prod)
- [ ] Set up Staging domain (e.g., staging.aceofcloud.io)
- [ ] Create ECR repository in Production account (184974284696)
- [ ] Create RDS instance in Production account
- [ ] Set up ECS cluster and service in Production
- [ ] Configure Production domain
- [ ] Set up CI/CD pipeline with environment promotion gates
- [ ] Configure CloudWatch cross-account log aggregation to LogArchive (016042452350)
- [ ] Set up SecurityTooling (672003402407) for cross-account GuardDuty/SecurityHub

---

## Environment Credentials (Session-Based)

These are temporary STS session credentials obtained via IAM Identity Center. They expire and must be refreshed from the SSO portal.

### Production (184974284696)

```bash
export AWS_ACCESS_KEY_ID="ASIASWEKTS6MLUPPZE5M"
export AWS_SECRET_ACCESS_KEY="dCk1FRNdRt06vsUza6HHa4OESXs63UM1SOwSzZ/e"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEK///////////wEaCXVzLWVhc3QtMSJIMEYCIQCs9am2vpmifTQa2fOMBQTQnA6BhYphqlxX0p+Hip2aIAIhAJCgTlSRMgaDbqX/N2XaMNzkZ+nHGLFnoT4k0VrL0TLnKvoCCHcQABoMMTg0OTc0Mjg0Njk2IgzEKCcXDhSZKXccdrgq1wJlplDf/V1inx7sqvrGQy+Fs9DmdYfT0GFVhf55ba9g09CdaUc5Uc91g6zeM/WaB7EknuUNBR7sIhiDXCT//pllm5+RLVUZJ+i7pFSm1zoKkLV0dR3+knV9QT/jG/12JODTIHZTFoOmc4U680PYem15jG82h/EzdLRAnzmyUUF5efyIX6U2EypjAN4xJv+h9tTJy1r5sbbDYbAh7KG1Z28Prl6JmGkiM5ErzLVsdVuI/iMzR+IjA0jOFtzQMMlBEGLVg1i0cE6bURgq3fv8uBSIgm5RDRDyOm+97/vQB05U+XLiBgaEs/PqYdrujcv7/Xr6bJNArbcetxeHUTwdLTIGkAxD80VJtA2FvSogibnqZhOzS6vgrPJzi5sOlg2Lz5ECpHk827LDhRNDJDiBYAhFO08MLXegBXpdxABII4EdvPCg3e1gaEbEe9NG/h1UA1yK27yzApeXMKDXnNAGOqQBwMhNO4G1sq13twDuGz/pjQJfSF8bWJEF6tJR9e2dHOd759bva7uV3p0zLONV5tkIi4rNeq/Q3aAim97/Ybv1ovbiYBvJB8ywu/qlS4+2Tz8x11DJkcPX8qCPq5uRRMyaJ1lrHVoe3LJuK+cLAm/g0ucvGNOcAlQ0eRIF7i8+CWbvqxDvaw0VY/fib86beZcbEU5bpWdnsroddrZq8+c7HCxAPto="
```

### Staging (238043187472)

```bash
export AWS_ACCESS_KEY_ID="ASIATO3D2ZEILVV47SOO"
export AWS_SECRET_ACCESS_KEY="PBTi7+pNw2DLmoElf+tLD6zqQnDFUuln8oaob1V+"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEK///////////wEaCXVzLWVhc3QtMSJGMEQCIBSYyRqP/bTXdEK9ns76b3ziMrH+hql6Dh9OwPT7qx36AiAFBXxspoEyfjUkEfqe28amCiV6xYe28AxlcWJOWKOQOCr6Agh3EAAaDDIzODA0MzE4NzQ3MiIMyUCIV15urIsFan6wKtcCvB5dQ2FUlZqv7e5GdsvQsTUrjOLhDvrATh3+LeeR6yE/eCz/sLrt4Z41xbVEbpMGbIfPJ4XJZnyEf/EJHbiaXUZWQnSRZXhb06yD7G0Ix3PHBbQpvdgpXaxQDnWBbRJQ9mxCNf9JQgHnc7qDS0vJnLgZdCYcLSw+e0cnUiwlz9lHYYINT/8fV8l0dGQ34tuvdyN2+J+QDvHsIZAEm6IRZCcaiKwLjH2xJaaMfg4HKB9RINwQjuGk79bPKm+0fQg1w06L5P5Wu0IerQNo7aKG0Dvpu+hGYgYalZKgQws60XqpNERMSV6FktGZG3X8A2UttNEFMw0x6T7j/A130xplJpp4xUAYxGNSyiQMFCW5vD2kplhdvQCBai9eGsCSA3vaSbzZLQxdwyICGTXe/8bDUag9l/BJ+YlchQlEtWLtz1A4Wa6Ikn3+Pz+FiEYySax1Eh0TAWVFSTC/15zQBjqmAetqGDNjdQMiRnJZPQsk9V9KjLFbCd8g9alHiNTniCbcuctWyeZCSxSADczQ7QdHKBn7N5Kw+gdv4T2/76UBlVvPlstZqBEs/TBgfThj6xv/0tCMFJDeeQ680OU5L7Ezfs1yOcr+nqjXFVZ3huS19Cwr6+p0XUhywSQc+nVvn7EWkuLunWyKCkfRVNYNV7BljLFtLogqKfsp3aTw3n6hplB9bfsMy38="
```

### Development (808038814732)

```bash
export AWS_ACCESS_KEY_ID="ASIA3YIW52QGPRJPM2FO"
export AWS_SECRET_ACCESS_KEY="69mPIE4RlE4jEo3zpU7kgiFjIsb4U76Bx+FpaEvj"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEK///////////wEaCXVzLWVhc3QtMSJHMEUCIBJkfxBRqTUmX4YpDSIyhMuHgBJMi3lDrwnUsRiu8eztAiEA96I6x6J8moaV+YXaR2zW2YFiaI4S00fgpvIJInqP/YQq+gIIdxAAGgw4MDgwMzg4MTQ3MzIiDHP1Xfe8H4rRuzzN2SrXAhsVT0oPJA4bLw5TAI7GyexG/HhAAiaBQMz/dzqt3gYadFA7rgQ68jvFNP8pgvlKWyUr3XRyDvvLjWWVTkYPkXTWHV8VW7uywY9U6BYXc6ZnlSVJ1e9NbxhwayQjlco8OhwY0L+e0VsEm5GAOlR0EfJ6iFr5VETLFqp2ti9Ufaf5Pw4K6Um6oSX2bbNtJe8vv2b5ONusvD9dNzYg/omMF84F7R8Y7U/V5uCWITLXz7d7YEwvRX3O2YQlilJ6RcGAGu8CKoMqJ8FkFsjE4MBlemjpzUgSrbZkaqSGEW+bxsJPUlX1lLhQI/MUD8nIzW+nIv/3oaUftW3AaDdRGJrKNfBagdD0Lpu5edEgQN7DMgasAI0zM+cNYHgsmT0XvcogYaxFwEXLeRh1F/o0fF42Z6/kc2ptXYzOQ3GGU/Vi/95V7KbmXi8RB2iEBqaIHXta0ysSTX0j43Qw2tec0AY6pQEoRzggJaQ2NnsxbCWLMeZn5PGSskYDQS/QfQZXifOwSSy62hSVPVRe1WHORcOGPsjbOJuDjVqQvnQXgUJZ9lGAmjOM5Ta3gewQUFBQarAJ4eTkQWPTMkpFh+2QWd4V85ko+I54U52jpSWPlo1h4Z+p3ZZWVrfv/5d0Ch2TQ4yMhSS44SShf3VyvO9624LbaNKr2kq+YjrSlcL+sFTZA9O7DXDxpWc="
```

> **Note:** These are temporary STS session tokens from IAM Identity Center. They expire (typically within 1-12 hours). Refresh from the SSO portal at `d-90660b5f17.awsapps.com` when needed.

---

## Notes

- AWS SSO portal: `d-90660b5f17.awsapps.com`
- All accounts accessible via AWS IAM Identity Center (SSO)
- Current GitHub Actions workflow uses OIDC for the deploy workflow (needs trust policy per account)
- Manual build workflow (`build-push-ecr.yml`) uses access key credentials stored in GitHub Secrets
- For migration: each target account needs its own ECR repo, ECS cluster, RDS instance, and GitHub Actions OIDC trust policy
