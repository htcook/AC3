# FedRAMP/NIST-Compliant OAuth Configuration Guide

**Prepared for:** AceofCloud — AC3 Platform  
**Date:** May 15, 2026  
**Applicable Standards:** NIST SP 800-63-3/4, NIST SP 800-53 Rev 5, FedRAMP Moderate Baseline  
**Author:** Harrison Cook

---

## Executive Summary

This guide provides a comprehensive checklist and configuration requirements for implementing OAuth 2.0/OIDC authentication that meets FedRAMP Moderate baseline controls and NIST 800-63 Authenticator Assurance Level 2 (AAL2). AC3 must satisfy these requirements to pass penetration testing, achieve FedRAMP authorization, and serve federal customers.

The FedRAMP Moderate baseline requires over 320 security controls [1], with identity and access management being one of the most scrutinized areas during assessment. The controls below are organized by implementation priority — items marked **CRITICAL** will fail a pentest if missing, items marked **REQUIRED** are necessary for FedRAMP authorization, and items marked **RECOMMENDED** strengthen the security posture beyond minimum compliance.

---

## 1. Authentication Assurance Levels (NIST 800-63B)

NIST SP 800-63B defines three Authenticator Assurance Levels (AALs) that determine the strength of authentication required [2]. FedRAMP Moderate mandates **AAL2 at minimum** for all users, including non-privileged accounts.

| Level | Requirements | FedRAMP Applicability |
|-------|-------------|----------------------|
| AAL1 | Single factor (password only) | **NOT acceptable** for FedRAMP Moderate |
| AAL2 | Two authentication factors required | **Minimum** for FedRAMP Moderate |
| AAL3 | Hardware-based authenticator (e.g., FIDO2/PIV) | Required for FedRAMP High; recommended for admin accounts |

### AAL2 Implementation Requirements

To achieve AAL2, the authentication system must enforce multi-factor authentication (MFA) using at least two of the following factor categories [2]:

| Factor Category | Examples | AC3 Implementation |
|----------------|----------|-------------------|
| Something you know | Password, PIN | Password with complexity requirements |
| Something you have | TOTP app, hardware key, push notification | TOTP (Google Authenticator, Authy) or FIDO2 WebAuthn |
| Something you are | Fingerprint, face recognition | WebAuthn biometric (optional enhancement) |

**AC3 must enforce MFA for all users** — not just administrators. The current implementation already supports TOTP-based MFA; this must be made **mandatory** rather than optional for FedRAMP compliance.

---

## 2. OAuth 2.0 / OIDC Protocol Requirements

The following table summarizes the OAuth/OIDC protocol configuration required for FedRAMP compliance. These requirements derive from NIST SP 800-63C (Federation and Assertions) [3] and the FedRAMP 20x Key Security Indicators for Identity and Access Management [4].

### 2.1 Authorization Flow Configuration

| Requirement | Status | Configuration |
|-------------|--------|---------------|
| **Authorization Code Flow only** | CRITICAL | Implicit flow and Resource Owner Password Credentials flow must be disabled. Only Authorization Code flow is acceptable. |
| **PKCE (Proof Key for Code Exchange)** | CRITICAL | Required for ALL clients — both public and confidential. Use S256 challenge method. |
| **State parameter** | CRITICAL | Must be cryptographically random, at least 128 bits of entropy. Validated on callback. |
| **Nonce parameter** | REQUIRED | Required for OIDC flows. Must be bound to the session and validated in the ID token. |
| **Redirect URI validation** | CRITICAL | Exact match only — no wildcard patterns, no open redirects. Register all valid redirect URIs explicitly. |

### 2.2 Token Configuration

| Parameter | FedRAMP Requirement | Recommended Value |
|-----------|-------------------|-------------------|
| Access token lifetime | ≤ 1 hour [3] | 15 minutes |
| Refresh token lifetime | ≤ 24 hours | 8 hours (sliding window) |
| ID token lifetime | ≤ 5 minutes | 5 minutes |
| Authorization code lifetime | ≤ 60 seconds | 30 seconds |
| Token format | Signed JWT (RS256 minimum) | ES256 preferred (ECDSA P-256) |
| Token binding | Sender-constrained preferred | DPoP or mTLS token binding |

### 2.3 Cryptographic Requirements

FedRAMP requires FIPS 140-2 (or 140-3) validated cryptographic modules for all cryptographic operations [5]. In practice, this means:

| Component | Requirement | Implementation |
|-----------|-------------|----------------|
| Token signing | FIPS-approved algorithm | RS256 (RSA-2048) minimum; ES256 (ECDSA P-256) preferred |
| TLS | TLS 1.2+ required; TLS 1.3 preferred | Configure ALB security policy to `ELBSecurityPolicy-TLS13-1-2-2021-06` |
| Session cookies | Signed with HMAC-SHA256+ | Use `JWT_SECRET` with ≥256 bits of entropy |
| Password hashing | FIPS-approved | bcrypt (cost ≥12), scrypt, or Argon2id |
| Key rotation | Keys must be rotatable without downtime | Implement JWKS endpoint with key rotation support |

---

## 3. Access Control Requirements (NIST 800-53)

The following controls from NIST SP 800-53 Rev 5 are directly relevant to the OAuth/authentication implementation [6]:

### 3.1 Account Management (AC-2)

| Sub-Control | Requirement | AC3 Implementation |
|-------------|-------------|-------------------|
| AC-2(1) | Automated account management | Implement account provisioning/deprovisioning API |
| AC-2(2) | Automated temporary/emergency account removal | Auto-disable accounts after 90 days of inactivity |
| AC-2(3) | Disable inactive accounts | Flag accounts with no login for 35 days; disable at 90 days |
| AC-2(4) | Automated audit of account actions | Log all account creation, modification, deletion, enable/disable events |
| AC-2(13) | Disable accounts for high-risk individuals | Admin ability to immediately disable any account |

### 3.2 Access Enforcement (AC-3)

| Requirement | Implementation |
|-------------|----------------|
| Role-based access control (RBAC) | Enforce `admin` vs `user` roles at the procedure level |
| Principle of least privilege | Default to minimum permissions; explicitly grant elevated access |
| Separation of duties | Admin actions require separate confirmation; no self-elevation |

### 3.3 Unsuccessful Login Attempts (AC-7) — CRITICAL

| Parameter | FedRAMP Requirement | Recommended Value |
|-----------|-------------------|-------------------|
| Maximum consecutive failures | Organization-defined (typically 3-5) | 5 consecutive failures |
| Lockout duration | Organization-defined | 30 minutes (or until admin unlock) |
| Lockout scope | Per-account | Lock the specific account, not the IP |
| Notification | Alert on lockout | Notify both user (email) and admin (dashboard alert) |

> **Current Gap:** AC3 must implement account lockout after failed login attempts. This is one of the most common pentest findings and a hard FedRAMP requirement.

### 3.4 System Use Notification (AC-8) — REQUIRED

Before granting access, the system must display a system use notification banner that includes:

- The system is for authorized use only
- Usage may be monitored, recorded, and subject to audit
- Unauthorized use may result in criminal/civil penalties
- Use of the system constitutes consent to monitoring

This banner must appear **before** the login form and require explicit acknowledgment (click-through) for privileged access.

### 3.5 Session Controls

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| AC-11 Session Lock | Lock after 15 minutes of inactivity | Auto-redirect to login after idle timeout |
| AC-12 Session Termination | Terminate after defined conditions | Logout destroys session server-side; invalidate all tokens |
| AC-12(1) User-initiated logout | User can terminate own session | Logout button accessible from all pages |
| SC-23 Session Authenticity | Protect session identifiers | HttpOnly, Secure, SameSite=Strict cookies; no URL-based session IDs |

---

## 4. Identity Proofing and Authenticator Management

### 4.1 Password Requirements (IA-5(1))

NIST 800-63B Rev 4 significantly updated password guidance [2]. The following reflects current requirements:

| Requirement | Value | Notes |
|-------------|-------|-------|
| Minimum length | 8 characters (12+ recommended) | Longer is better; no maximum below 64 characters |
| Complexity rules | **NOT required** | NIST explicitly discourages composition rules (uppercase, special chars) |
| Password screening | **REQUIRED** | Check against breached password lists (e.g., HaveIBeenPwned API) |
| Password rotation | **NOT required** unless compromised | Forced rotation reduces security per NIST guidance |
| Password hints | **PROHIBITED** | No knowledge-based authentication (security questions) |
| Password display | Allow "show password" toggle | Reduces entry errors |
| Paste allowed | **REQUIRED** | Must allow paste into password fields (enables password managers) |

### 4.2 MFA Authenticator Requirements

| Authenticator Type | AAL2 Acceptable | Recommended for AC3 |
|-------------------|-----------------|---------------------|
| TOTP (RFC 6238) | Yes | Primary MFA method — already implemented |
| FIDO2/WebAuthn | Yes (preferred) | Add as option for high-security accounts |
| SMS OTP | **Restricted** — only as backup [2] | Do NOT use as primary MFA; acceptable as recovery only |
| Push notification | Yes | Consider for mobile UX improvement |
| Email OTP | **NOT acceptable** for AAL2 | Do not implement for login MFA |

> **Important:** SMS-based OTP is explicitly called out by NIST as a "restricted" authenticator due to SIM-swap and SS7 vulnerabilities [2]. If used at all, it must be combined with another factor and users must be informed of the risks.

### 4.3 MFA Enrollment Flow

The MFA enrollment process must meet these requirements:

1. **Mandatory enrollment** — All users must enroll in MFA before accessing protected resources
2. **Recovery codes** — Generate and display one-time backup codes during enrollment (store hashed)
3. **Re-authentication before MFA changes** — Require current password + existing MFA to modify MFA settings
4. **Authenticator binding** — The authenticator must be bound to the specific subscriber account

---

## 5. Logging and Audit Requirements (AU-2, AU-3)

All authentication events must be logged with sufficient detail for forensic analysis. FedRAMP requires the following events to be captured [6]:

| Event | Required Fields | Retention |
|-------|----------------|-----------|
| Successful login | Timestamp, user ID, IP, user agent, MFA method used | 1 year minimum |
| Failed login | Timestamp, attempted user ID, IP, user agent, failure reason | 1 year minimum |
| Account lockout | Timestamp, user ID, IP, consecutive failure count | 1 year minimum |
| MFA enrollment/change | Timestamp, user ID, authenticator type, admin who approved | 1 year minimum |
| Password change | Timestamp, user ID, IP, change method (self-service vs admin) | 1 year minimum |
| Session creation/termination | Timestamp, user ID, session duration, termination reason | 1 year minimum |
| Token issuance/revocation | Timestamp, user ID, token type, scope, expiration | 1 year minimum |
| Privilege escalation | Timestamp, user ID, role change, authorized by | 1 year minimum |

Logs must be tamper-evident (write-once storage or cryptographic chaining), transmitted over encrypted channels, and stored in a centralized logging system separate from the application servers.

---

## 6. Implementation Checklist

### Phase 1 — Critical (Pentest Blockers)

These items will cause immediate pentest failures if missing:

| # | Item | Control | Status |
|---|------|---------|--------|
| 1 | Enforce MFA for all users (not optional) | IA-2(1), IA-2(2) | [ ] |
| 2 | Account lockout after 5 failed attempts | AC-7 | [ ] |
| 3 | PKCE on all OAuth flows | SC-13 | [ ] |
| 4 | TLS 1.2+ enforced (no TLS 1.0/1.1) | SC-8, SC-13 | [x] Done — ALB policy set |
| 5 | Secure cookie flags (HttpOnly, Secure, SameSite) | SC-23 | [ ] Verify |
| 6 | No sensitive data in URL parameters | SC-8 | [ ] Verify tokens not in URLs |
| 7 | Authorization code single-use and short-lived | SC-13 | [ ] |
| 8 | Redirect URI exact-match validation | AC-3 | [ ] |
| 9 | Password screening against breach lists | IA-5(1) | [ ] |
| 10 | All API endpoints require authentication (except login) | AC-3 | [x] Done — security hardening pushed |

### Phase 2 — Required (FedRAMP Authorization)

| # | Item | Control | Status |
|---|------|---------|--------|
| 11 | System use notification banner | AC-8 | [ ] |
| 12 | Session idle timeout (15 min) | AC-11 | [ ] |
| 13 | Session termination on logout (server-side invalidation) | AC-12 | [ ] Verify |
| 14 | Automated inactive account disable (90 days) | AC-2(3) | [ ] |
| 15 | Comprehensive authentication event logging | AU-2, AU-3 | [ ] |
| 16 | Log integrity protection (tamper-evident) | AU-9 | [ ] |
| 17 | FIPS 140-2 validated crypto for token signing | SC-13 | [ ] |
| 18 | Token lifetime limits enforced (access ≤1hr, refresh ≤24hr) | SC-13 | [ ] |
| 19 | DNSSEC enabled for aceofcloud.io | SC-20, SC-21 | [ ] Pending GoDaddy config |
| 20 | DMARC/DKIM/SPF for email domain | SI-8 | [x] Done — SES configured |

### Phase 3 — Recommended (Hardening Beyond Minimum)

| # | Item | Control | Notes |
|---|------|---------|-------|
| 21 | FIDO2/WebAuthn support for admin accounts | IA-2 | Phishing-resistant MFA |
| 22 | DPoP or mTLS token binding | SC-13 | Prevents token theft/replay |
| 23 | Continuous authentication / step-up auth for sensitive ops | IA-2 | Re-auth before destructive actions |
| 24 | Rate limiting on all auth endpoints | SC-5 | Prevent brute force and credential stuffing |
| 25 | Certificate-based auth option (PIV/CAC) | IA-2(12) | Required for DoD customers |
| 26 | SCIM provisioning for enterprise customers | AC-2(1) | Automated user lifecycle management |
| 27 | Anomaly detection on login patterns | SI-4 | Alert on impossible travel, new device, etc. |
| 28 | Token revocation endpoint | SC-13 | Allow immediate invalidation of compromised tokens |

---

## 7. OAuth Provider Evaluation Criteria

If selecting or evaluating an OAuth/OIDC identity provider for AC3, the provider must meet these criteria for FedRAMP compliance:

| Criterion | Requirement |
|-----------|-------------|
| FedRAMP authorized | Provider should be FedRAMP authorized (or FedRAMP-equivalent) |
| FIPS 140-2 crypto | All cryptographic operations use FIPS-validated modules |
| SOC 2 Type II | Annual audit report available |
| NIST 800-63 AAL2+ | Supports AAL2 authentication natively |
| SAML 2.0 + OIDC | Supports both federation protocols |
| SCIM 2.0 | Supports automated provisioning |
| Conditional access | IP-based, device-based, and risk-based access policies |
| Audit logging | Comprehensive, exportable, and retainable for 1+ year |

Providers that meet these criteria include: **Okta** (FedRAMP High authorized), **Microsoft Entra ID** (FedRAMP High authorized), **Auth0** (FedRAMP Moderate via Okta), and **AWS Cognito** (FedRAMP High authorized) [7].

---

## 8. AC3-Specific Implementation Notes

### Current State Assessment

AC3 currently uses a custom OAuth implementation with session cookies. The following gaps exist relative to FedRAMP requirements:

| Gap | Severity | Remediation Effort |
|-----|----------|-------------------|
| MFA is optional, not mandatory | Critical | Low — enforce in login flow |
| No account lockout mechanism | Critical | Medium — add counter + lockout logic |
| No system use notification banner | Required | Low — add banner component |
| No session idle timeout | Required | Low — add client-side timer |
| No password breach screening | Critical | Low — integrate HaveIBeenPwned API |
| Auth event logging incomplete | Required | Medium — add structured logging |
| No DNSSEC | Required | Low — enable in GoDaddy (pending) |

### Recommended Architecture for FedRAMP

For FedRAMP authorization, consider migrating from the custom OAuth implementation to a FedRAMP-authorized identity provider. This offloads the compliance burden for identity management to a provider that has already been assessed. The recommended approach is:

1. **Short-term (3 months):** Harden the existing custom OAuth implementation with the Phase 1 items above. This gets you through pentests and initial customer security reviews.

2. **Medium-term (6 months):** Integrate a FedRAMP-authorized IdP (Okta or AWS Cognito) as the primary authentication backend. Keep the existing session management but delegate credential verification and MFA to the IdP.

3. **Long-term (12 months):** Full SCIM provisioning, conditional access policies, and certificate-based authentication for federal customers. This positions AC3 for FedRAMP Moderate authorization.

---

## References

[1]: https://www.fedramp.gov/understanding-baselines-and-impact-levels/ "FedRAMP — Understanding Baselines and Impact Levels"
[2]: https://pages.nist.gov/800-63-3/sp800-63b.html "NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management"
[3]: https://pages.nist.gov/800-63-3/sp800-63c.html "NIST SP 800-63C — Digital Identity Guidelines: Federation and Assertions"
[4]: https://www.fedramp.gov/docs/20x/key-security-indicators/identity-and-access-management/ "FedRAMP 20x Key Security Indicators — Identity and Access Management"
[5]: https://csrc.nist.gov/publications/detail/fips/140/2/final "FIPS 140-2 — Security Requirements for Cryptographic Modules"
[6]: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final "NIST SP 800-53 Rev 5 — Security and Privacy Controls"
[7]: https://marketplace.fedramp.gov/ "FedRAMP Marketplace — Authorized Products"
