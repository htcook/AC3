# Ace C3 — User Accounts, RBAC, and Authentication Architecture for AWS Deployment

**Author:** Manus AI | **Date:** February 25, 2026 | **Status:** Architecture Recommendation

---

## Executive Summary

This document provides a comprehensive architecture plan for transitioning the Ace C3 platform from its current Manus-hosted OAuth authentication to a production-grade, AWS-native identity and access management stack. The analysis covers user account management, role-based access control (RBAC) with granular permissions, and enterprise-grade authentication via OAuth 2.0, SAML 2.0, and OpenID Connect (OIDC). The goal is to support multi-tenant operations, FedRAMP compliance alignment, and seamless integration with enterprise identity providers such as Microsoft Entra ID (Azure AD), Okta, and AWS IAM Identity Center.

Throughout this transition, the existing **red ADMiN123 admin account** will remain active as the platform owner and super-administrator, ensuring uninterrupted access during development, testing, and tuning.

---

## 1. Current State Assessment

The platform currently uses a three-role model defined in the Drizzle schema:

| Role | Description | Current Capabilities |
|------|-------------|---------------------|
| `admin` | Full platform access, all modules | Unrestricted access to all 108+ modules, engagement management, server configuration, user management |
| `user` | Standard operator access | Access to assigned modules, engagement execution, reporting |
| `viewer` | Read-only access | Dashboard viewing, report consumption, no write operations |

The authentication flow currently relies on Manus OAuth with JWT session cookies. The `users` table stores `openId`, `name`, `email`, `loginMethod`, and `role` fields. This is a solid foundation, but it needs significant expansion for enterprise AWS deployment.

---

## 2. Recommended Role Hierarchy and RBAC Model

### 2.1 Expanded Role Architecture

For an offensive security platform operating in regulated environments, a flat three-role model is insufficient. The recommended architecture implements a **hierarchical RBAC model with permission groups** that maps cleanly to NIST 800-53 AC-2 (Account Management), AC-3 (Access Enforcement), and AC-6 (Least Privilege) controls.

| Role | Inherits From | Description | Use Case |
|------|--------------|-------------|----------|
| `super_admin` | — | Platform owner, unrestricted | Your ADMiN123 account; manages tenants, billing, platform config |
| `org_admin` | — | Organization administrator | Client-side admin who manages their org's users and engagements |
| `engagement_lead` | — | Engagement manager | Creates/manages engagements, assigns team members, approves ROE |
| `red_team_operator` | — | Offensive operator | Executes exploits, runs campaigns, deploys agents, accesses C2 |
| `analyst` | — | Intelligence analyst | OSINT, threat intel, vulnerability analysis, reporting |
| `compliance_officer` | — | Compliance/audit role | FedRAMP KSI dashboard, OSCAL export, evidence chain, read-only ops |
| `viewer` | — | Read-only stakeholder | Dashboard viewing, report consumption only |
| `api_service` | — | Machine-to-machine | API integrations, automated pipelines, CI/CD hooks |

### 2.2 Permission Groups

Rather than assigning individual permissions to roles, permissions are organized into **permission groups** that map to the platform's seven operational domains:

| Permission Group | Modules Covered | Example Permissions |
|-----------------|----------------|---------------------|
| `ops.engagements` | Engagement Mgr, ROE Builder, Kill Chain | `create`, `read`, `update`, `delete`, `approve`, `launch` |
| `ops.emulation` | Agents, Campaign Exec, Emulation Playbooks, Purple Team | `deploy_agent`, `execute_campaign`, `manage_c2` |
| `ops.exploit` | Exploit Catalog, Validation Engine, C2 Servers, Post-Exploit | `execute_exploit`, `manage_sessions`, `transfer_files` |
| `ops.phishing` | Phishing Ops, Template Gen, Page Builder, Launch Wizard | `create_campaign`, `send_emails`, `harvest_credentials` |
| `intel.recon` | Domain Intel, Scan History, Scan Scheduler, OSINT connectors | `run_scan`, `schedule_scan`, `view_results` |
| `intel.threat` | Threat Intel Hub, Threat Catalog, IOC Feed, Darkweb Intel | `query_intel`, `manage_feeds`, `export_stix` |
| `intel.vuln` | Vuln Intel, NVD CVE Matcher, Bug Bounty Hub | `correlate_cves`, `manage_programs` |
| `compliance` | KSI Dashboard, Evidence Chain, OSCAL Export, Compliance Mapper | `view_ksi`, `export_oscal`, `manage_evidence` |
| `reporting` | Reports, BIA Report, Post-Engagement Report | `generate_report`, `export_pdf`, `share_report` |
| `admin.platform` | Server Config, Infrastructure, User Management | `manage_users`, `manage_servers`, `view_audit_log` |
| `admin.security` | SIEM Connectors, Evasion Engine, EDR Validation | `configure_siem`, `manage_evasion`, `validate_edr` |

### 2.3 Database Schema Extension

The following schema additions support the expanded RBAC model. These extend the existing `users` table without breaking the current authentication flow:

```sql
-- Extend the role enum on the existing users table
ALTER TABLE users MODIFY COLUMN role ENUM(
  'super_admin', 'org_admin', 'engagement_lead',
  'red_team_operator', 'analyst', 'compliance_officer',
  'viewer', 'api_service'
) NOT NULL DEFAULT 'viewer';

-- Organizations / Tenants
CREATE TABLE organizations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  slug VARCHAR(128) NOT NULL UNIQUE,
  saml_entity_id VARCHAR(512),
  saml_metadata_url TEXT,
  oidc_client_id VARCHAR(255),
  oidc_issuer_url VARCHAR(512),
  auth_method ENUM('local', 'saml', 'oidc', 'mixed') DEFAULT 'local',
  max_users INT DEFAULT 50,
  tier ENUM('free', 'professional', 'enterprise', 'gov') DEFAULT 'professional',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Link users to organizations
ALTER TABLE users ADD COLUMN org_id INT REFERENCES organizations(id);
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN account_locked BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN failed_login_attempts INT DEFAULT 0;
ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP;
ALTER TABLE users ADD COLUMN session_timeout_minutes INT DEFAULT 30;

-- Permission assignments (role -> permission group -> action)
CREATE TABLE role_permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  role VARCHAR(64) NOT NULL,
  permission_group VARCHAR(128) NOT NULL,
  actions JSON NOT NULL, -- ["create","read","update","delete"]
  org_id INT, -- NULL = global, otherwise org-scoped
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit log for compliance (NIST AC-2, AU-2)
CREATE TABLE audit_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  org_id INT,
  action VARCHAR(255) NOT NULL,
  resource_type VARCHAR(128),
  resource_id VARCHAR(255),
  ip_address VARCHAR(45),
  user_agent TEXT,
  details JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_audit_user (user_id),
  INDEX idx_audit_org (org_id),
  INDEX idx_audit_action (action),
  INDEX idx_audit_created (created_at)
);

-- API keys for service accounts
CREATE TABLE api_keys (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  org_id INT,
  key_hash VARCHAR(64) NOT NULL UNIQUE,
  key_prefix VARCHAR(8) NOT NULL, -- first 8 chars for identification
  name VARCHAR(255) NOT NULL,
  scopes JSON NOT NULL, -- ["ops.engagements:read", "intel.recon:run_scan"]
  expires_at TIMESTAMP,
  last_used_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 2.4 Preserving the ADMiN123 Account

Your current admin account will be migrated to the `super_admin` role with the following guarantees:

- The `super_admin` role bypasses all permission checks (equivalent to root).
- The account retains direct database access for emergency operations.
- A "break glass" procedure ensures access even if the IdP is unavailable.
- The account is excluded from automated lockout policies during the testing phase.
- Once the platform is production-ready, the super_admin account should be secured with hardware MFA (FIDO2/WebAuthn) and restricted to a known IP allowlist.

---

## 3. Authentication Architecture for AWS

### 3.1 Recommended Stack

The recommended authentication architecture uses **Amazon Cognito** as the central identity broker, with support for multiple identity federation protocols:

```
┌─────────────────────────────────────────────────────────┐
│                    Ace C3 Platform                       │
│                  (ECS Fargate / EKS)                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   ┌──────────┐    ┌──────────────┐    ┌──────────────┐  │
│   │ React    │───▶│ API Gateway  │───▶│ Express/tRPC │  │
│   │ Frontend │    │ + WAF        │    │ Backend      │  │
│   └──────────┘    └──────────────┘    └──────────────┘  │
│        │                                     │          │
│        ▼                                     ▼          │
│   ┌──────────────────────────────────────────────┐      │
│   │           Amazon Cognito User Pool           │      │
│   │  ┌────────┐ ┌────────┐ ┌────────────────┐   │      │
│   │  │ Local  │ │ SAML   │ │ OIDC           │   │      │
│   │  │ Users  │ │ IdPs   │ │ Providers      │   │      │
│   │  └────────┘ └────────┘ └────────────────┘   │      │
│   └──────────────────────────────────────────────┘      │
│        │              │              │                   │
│        ▼              ▼              ▼                   │
│   ┌────────┐   ┌───────────┐  ┌──────────────┐         │
│   │ Local  │   │ Microsoft │  │ Okta / Ping  │         │
│   │ Login  │   │ Entra ID  │  │ Identity     │         │
│   └────────┘   └───────────┘  └──────────────┘         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Amazon Cognito Configuration

Amazon Cognito serves as the identity broker because it natively supports all three authentication protocols the platform needs, integrates with AWS services, and provides built-in MFA, account recovery, and token management.

**User Pool Configuration:**

| Setting | Value | Rationale |
|---------|-------|-----------|
| MFA | Required for admin roles, optional for others | NIST 800-53 IA-2(1) |
| Password Policy | Min 12 chars, upper/lower/number/special | NIST 800-53 IA-5 |
| Account Lockout | 5 failed attempts, 30-min lockout | NIST 800-53 AC-7 |
| Session Duration | 30 min idle, 8 hr absolute | NIST 800-53 AC-12 |
| Token Lifetime | Access: 1 hr, Refresh: 30 days | Balance security/UX |
| Advanced Security | Enabled (adaptive auth, compromised credential detection) | FedRAMP requirement |

**Custom Attributes for RBAC:**

```
custom:org_id       → Organization/tenant identifier
custom:role         → Platform role (maps to RBAC)
custom:permissions  → JSON-encoded permission overrides
custom:clearance    → Security clearance level (for gov clients)
```

### 3.3 SAML 2.0 Integration

SAML 2.0 is the primary federation protocol for enterprise and government clients. Each organization can configure their own SAML Identity Provider.

**Flow:**

1. User navigates to `https://acec3.example.com/login`
2. Platform detects the user's organization (via email domain or org slug)
3. Cognito redirects to the organization's SAML IdP (e.g., Microsoft Entra ID)
4. User authenticates at the IdP (with their corporate MFA)
5. IdP sends SAML assertion back to Cognito's ACS endpoint
6. Cognito maps SAML attributes to Cognito user attributes via attribute mapping
7. A Pre-Token Generation Lambda enriches the JWT with platform-specific claims (role, org_id, permissions)
8. The platform receives the JWT and establishes a session

**SAML Attribute Mapping:**

| SAML Attribute | Cognito Attribute | Description |
|---------------|-------------------|-------------|
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `email` | User email |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `name` | Display name |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` | `custom:groups` | AD group memberships |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` | `custom:idp_role` | IdP-assigned role |

**Group-to-Role Mapping (configured per organization):**

| IdP Group | Platform Role | Notes |
|-----------|--------------|-------|
| `ACE-C3-Admins` | `org_admin` | Organization administrators |
| `ACE-C3-RedTeam` | `red_team_operator` | Offensive operators |
| `ACE-C3-Analysts` | `analyst` | Intelligence analysts |
| `ACE-C3-Compliance` | `compliance_officer` | Audit/compliance staff |
| `ACE-C3-Viewers` | `viewer` | Read-only stakeholders |
| (default) | `viewer` | Unmapped users get read-only |

### 3.4 OAuth 2.0 / OIDC Integration

For organizations using modern identity providers that support OIDC (Okta, Auth0, Google Workspace, AWS IAM Identity Center), the platform supports OIDC federation through Cognito.

**OIDC Configuration per Organization:**

```json
{
  "provider_name": "OktaCorpSSO",
  "client_id": "0oa1b2c3d4e5f6g7h8i9",
  "client_secret": "encrypted_secret",
  "issuer": "https://corp.okta.com/oauth2/default",
  "authorize_scopes": "openid profile email groups",
  "attribute_mapping": {
    "email": "email",
    "name": "name",
    "custom:groups": "groups",
    "custom:org_id": "org_id"
  }
}
```

### 3.5 Local Authentication (Fallback)

For organizations that do not have an enterprise IdP, or for the platform owner's ADMiN123 account, local authentication remains available through Cognito's built-in user management:

- Username/password with Cognito-managed password hashing (SRP protocol)
- TOTP-based MFA via authenticator apps
- Optional SMS MFA as a backup
- Self-service password reset via verified email
- The ADMiN123 super_admin account always has local auth available as a "break glass" mechanism

---

## 4. AWS Deployment Architecture

### 4.1 Infrastructure Overview

| Component | AWS Service | Configuration |
|-----------|------------|---------------|
| **Compute** | ECS Fargate or EKS | Auto-scaling task definitions, min 2 tasks for HA |
| **Database** | Amazon Aurora MySQL (Serverless v2) | Multi-AZ, encryption at rest (AES-256), automated backups |
| **Identity** | Amazon Cognito | User pool + identity pool, SAML/OIDC federation |
| **API Gateway** | Amazon API Gateway + WAF | Rate limiting, IP allowlisting, request validation |
| **CDN** | Amazon CloudFront | Static asset delivery, DDoS protection |
| **Secrets** | AWS Secrets Manager | API keys, SAML certs, database credentials |
| **Logging** | CloudWatch + CloudTrail | Centralized logging, audit trail |
| **Storage** | Amazon S3 | Engagement artifacts, scan results, report storage |
| **DNS** | Route 53 | Domain management, health checks |
| **Certificates** | ACM | TLS 1.3 certificates, auto-renewal |
| **Monitoring** | CloudWatch + X-Ray | Performance monitoring, distributed tracing |

### 4.2 Network Architecture

```
Internet
    │
    ▼
┌──────────────┐
│  CloudFront  │──── WAF (OWASP rules, rate limiting, geo-blocking)
└──────────────┘
    │
    ▼
┌──────────────┐
│ ALB (Public) │──── ACM TLS 1.3 certificate
└──────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│              VPC (10.0.0.0/16)           │
│                                          │
│  ┌─────────────────────────────────┐     │
│  │  Public Subnets (10.0.1.0/24)  │     │
│  │  NAT Gateway, ALB              │     │
│  └─────────────────────────────────┘     │
│                                          │
│  ┌─────────────────────────────────┐     │
│  │  Private Subnets (10.0.2.0/24) │     │
│  │  ECS Fargate Tasks             │     │
│  │  (Express/tRPC backend)        │     │
│  └─────────────────────────────────┘     │
│                                          │
│  ┌─────────────────────────────────┐     │
│  │  Isolated Subnets (10.0.3.0/24)│     │
│  │  Aurora MySQL, ElastiCache     │     │
│  └─────────────────────────────────┘     │
│                                          │
│  VPC Endpoints: S3, Secrets Manager,     │
│  CloudWatch, ECR                         │
└──────────────────────────────────────────┘
```

### 4.3 Container Architecture

The current Express/tRPC monolith can be containerized as-is for the initial AWS deployment, then progressively decomposed if needed:

**Dockerfile (production):**

```dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:22-alpine AS runner
WORKDIR /app
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./
USER nodejs
EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "dist/server/index.js"]
```

**ECS Task Definition highlights:**

```json
{
  "cpu": "1024",
  "memory": "2048",
  "healthCheck": {
    "command": ["CMD-SHELL", "curl -f http://localhost:3000/api/health || exit 1"],
    "interval": 30,
    "timeout": 5,
    "retries": 3
  },
  "secrets": [
    { "name": "DATABASE_URL", "valueFrom": "arn:aws:secretsmanager:..." },
    { "name": "JWT_SECRET", "valueFrom": "arn:aws:secretsmanager:..." },
    { "name": "COGNITO_USER_POOL_ID", "valueFrom": "arn:aws:secretsmanager:..." }
  ]
}
```

---

## 5. Migration Path

### Phase 1: Foundation (Weeks 1-2)

During this phase, the existing Manus OAuth remains the primary authentication method while the AWS infrastructure is provisioned.

1. **Provision AWS infrastructure** using Terraform/CDK (VPC, subnets, ECS cluster, Aurora, Cognito).
2. **Create the Cognito User Pool** with the password policy, MFA settings, and custom attributes listed above.
3. **Migrate the ADMiN123 account** to Cognito as a local user with `super_admin` role. This account gets both Cognito local auth and the existing JWT-based auth as dual paths.
4. **Deploy the application** to ECS Fargate with the existing authentication still active.
5. **Add the `organizations`, `role_permissions`, `audit_log`, and `api_keys` tables** to the schema.

### Phase 2: Authentication Switchover (Weeks 3-4)

1. **Implement the Cognito authentication middleware** alongside the existing JWT middleware. Use a feature flag to route traffic.
2. **Add SAML IdP configuration UI** in the platform's admin settings (per-organization).
3. **Implement the Pre-Token Generation Lambda** that enriches JWTs with role and permission claims.
4. **Test with the ADMiN123 account** using both local Cognito auth and the existing auth.
5. **Gradually migrate users** from Manus OAuth to Cognito.

### Phase 3: RBAC Enforcement (Weeks 5-6)

1. **Implement the permission middleware** in the tRPC context that checks `role_permissions` for every procedure call.
2. **Add the `adminProcedure`, `operatorProcedure`, `analystProcedure`** etc. middleware chains.
3. **Build the user management UI** for org_admins to invite users, assign roles, and manage permissions.
4. **Implement audit logging** for all state-changing operations.
5. **Test RBAC with multiple user accounts** across different roles.

### Phase 4: Enterprise Federation (Weeks 7-8)

1. **Configure SAML federation** with a test Microsoft Entra ID tenant.
2. **Configure OIDC federation** with a test Okta tenant.
3. **Implement organization-level SSO settings** (SAML metadata upload, OIDC client configuration).
4. **Test group-to-role mapping** with real IdP groups.
5. **Implement Just-In-Time (JIT) user provisioning** for federated users.

### Phase 5: Hardening and Compliance (Weeks 9-10)

1. **Enable Cognito Advanced Security** (adaptive authentication, compromised credential detection).
2. **Implement session management** (idle timeout, absolute timeout, concurrent session limits).
3. **Configure WAF rules** (OWASP Top 10, rate limiting, geo-blocking).
4. **Set up CloudTrail** for API-level audit logging.
5. **Run a security assessment** against the NIST 800-53 AC control family.
6. **Document the SSP (System Security Plan)** for FedRAMP alignment.

---

## 6. Account Tier Model

For SaaS commercialization, the platform should support tiered access:

| Tier | Max Users | Auth Methods | Features | Target |
|------|-----------|-------------|----------|--------|
| **Free** | 3 | Local only | Domain Intel, basic reporting | Individual researchers |
| **Professional** | 25 | Local + OIDC | All modules, 5 concurrent engagements | Small security teams |
| **Enterprise** | 250 | Local + SAML + OIDC | All modules, unlimited engagements, API access, custom roles | Enterprise security teams |
| **Government** | 500 | SAML + PIV/CAC | All modules, FedRAMP controls, OSCAL export, audit logging | Federal agencies |

---

## 7. FedRAMP Alignment

The RBAC and authentication architecture directly addresses the following FedRAMP Key Security Indicators (KSIs) from the platform's existing KSI dashboard:

| KSI Theme | Relevant Controls | How This Architecture Addresses It |
|-----------|------------------|-----------------------------------|
| **IAM** (57% current) | AC-2, AC-3, AC-6, IA-2, IA-5, IA-8 | Cognito MFA, RBAC enforcement, SAML federation, password policy |
| **MLA** (80% current) | AU-2, AU-3, AU-6, AU-12 | Audit log table, CloudTrail, CloudWatch centralized logging |
| **PVA** (75% current) | CA-7, RA-5, SI-4 | Continuous validation scheduler, automated scanning |
| **SVC** (43% current) | SC-8, SC-12, SC-13, SC-28 | TLS 1.3, Secrets Manager, Aurora encryption, S3 encryption |

Implementing this architecture would raise the IAM KSI coverage from 57% to an estimated 85-90%, which is a significant improvement toward FedRAMP authorization readiness.

---

## 8. Key Recommendations

**Immediate Actions (Before AWS Migration):**

The ADMiN123 super_admin account should be documented as the platform's "break glass" account with a recovery procedure stored in a secure location (e.g., a sealed envelope or a hardware security module). All testing and tuning should continue under this account until the Cognito migration is validated.

**Architecture Decisions:**

Amazon Cognito is recommended over building a custom auth system because it provides SAML/OIDC federation, MFA, adaptive authentication, and compliance certifications out of the box. The alternative — implementing SAML assertion parsing, token management, and MFA from scratch — would add months of development time and introduce security risks.

For the database, Aurora MySQL Serverless v2 is recommended because the platform already uses MySQL/TiDB, making the migration straightforward. Aurora provides automatic scaling, Multi-AZ replication, and encryption at rest, which are all FedRAMP requirements.

**Security Hardening:**

All API endpoints should enforce authentication at the API Gateway level before traffic reaches the application. The tRPC middleware should perform authorization (RBAC checks) as a defense-in-depth measure. Rate limiting should be configured at both the WAF and application levels to prevent credential stuffing and API abuse.

**Monitoring:**

Every authentication event (login, logout, MFA challenge, failed attempt, role change) should be logged to both the application's `audit_log` table and CloudTrail. Set up CloudWatch alarms for anomalous patterns: more than 10 failed logins per minute, logins from new geographic regions, or privilege escalation attempts.

---

## References

- [AWS IAM Identity Center — SAML 2.0 Application Setup](https://docs.aws.amazon.com/singlesignon/latest/userguide/customermanagedapps-saml2-setup.html) [1]
- [Amazon Cognito — User Pool Federation with Third-Party IdPs](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-identity-federation.html) [2]
- [NIST SP 800-53 Rev 5 — Access Control Family](https://csf.tools/reference/nist-sp-800-53/r5/ac/) [3]
- [FedRAMP 20x — Key Security Indicators and Persistent Validation](https://www.fedramp.gov/20x/goals/) [4]
- [FedRAMP Minimum Assessment Standard](https://fedramp.gov/docs/20x/phase1/minimum-assessment-standard/) [5]
- [Multi-Tenant RBAC with AWS Verified Permissions](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-api-access-authorization/avp-mt-abac-examples.html) [6]
- [Building RBAC for Multi-Tenant SaaS (Architecture Patterns)](https://medium.com/@my_journey_to_be_an_architect/building-role-based-access-control-for-a-multi-tenant-saas-startup-26b89d603fdb) [7]
