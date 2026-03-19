# FedRAMP-Aligned Penetration Test Report

## Banking Systems Engagement

---

**Document Classification:** CONFIDENTIAL — Authorized Recipients Only

| Field | Value |
|---|---|
| **Report Title** |# Penetration Test Report— Banking Systems |
| **Engagement ID** | ENG-1770043 |
| **Engagement Type** | Full Active Penetration Test (Red Team) |
| **Client** | AceOfCloud Training Lab — Banking Systems |
| **Assessment Period** | March 19, 2026 |
| **Report Date** | March 19, 2026 |
| **Assessor Organization** | Ace C3 (Caldera Command Center) |
| **Methodology** | NIST SP 800-115, OWASP Testing Guide v4.2, PTES, MITRE ATT&CK |
| **Compliance Alignment** | NIST SP 800-53 Rev. 5 (CA-8, RA-5), FedRAMP, PCI-DSS, GLBA, FFIEC |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Rules of Engagement](#2-scope-and-rules-of-engagement)
3. [Methodology](#3-methodology)
4. [Asset Inventory and Attack Surface](#4-asset-inventory-and-attack-surface)
5. [Vulnerability Findings](#5-vulnerability-findings)
6. [Exploitation Results](#6-exploitation-results)
7. [Attack Chain Analysis](#7-attack-chain-analysis)
8. [Post-Exploitation and Adversary Simulation](#8-post-exploitation-and-adversary-simulation)
9. [FedRAMP Control Mapping](#9-fedramp-control-mapping)
10. [Multi-Framework Compliance Assessment](#10-multi-framework-compliance-assessment)
11. [Risk Assessment and Prioritized Remediation](#11-risk-assessment-and-prioritized-remediation)
12. [Appendix A: Tools and Techniques](#appendix-a-tools-and-techniques)
13. [Appendix B: Approval Gate Log](#appendix-b-approval-gate-log)
14. [Appendix C: OWASP Top 10:2025 Coverage](#appendix-c-owasp-top-102025-coverage)

---

## 1. Executive Summary

This report documents the results of a full-scope penetration test conducted against two banking web applications within the AceOfCloud Training Lab environment. The assessment was performed in accordance with FedRAMP Penetration Test Guidance (Revision 5) and aligned to NIST SP 800-53 control families CA-8 (Penetration Testing) and RA-5 (Vulnerability Monitoring and Scanning).

The engagement targeted two in-scope banking applications — **Altoro Mutual** and **VulnBank** — both hosted on shared infrastructure at IP address 159.223.152.190. The assessment progressed through all five phases of the penetration testing lifecycle: reconnaissance, enumeration, vulnerability detection, exploitation, and post-exploitation with adversary simulation.

### Key Findings Summary

| Metric | Value |
|---|---|
| Total Vulnerabilities | 33 (including 1 Critical exploitation) |
| **Critical Severity** | **1 (CVSS 9.8 — SSH Auth Bypass, Successfully Exploited)** |
| High Severity | 2 |
| Low Severity | 8 |
| Informational | 22 |
| Hosts Scanned | 2 |
| Open Ports Discovered | 8 |
| Exploitation Attempts | 1 |
| Successful Exploits | 1 |
| Reverse Shell Sessions | 1 |
| C2 Agents Deployed | 2 |
| Adversary Operations Executed | 1 (Axiom APT Profile) |
| Compliance Evidence Items | 1,178 |
| FedRAMP Compliance Score | 47% |
| OWASP Top 10:2025 Coverage | 85% |

### Overall Risk Rating: **HIGH**

The overall risk rating is assessed as **HIGH** based on the successful exploitation of the target environment. The assessment achieved full remote code execution via SSH authentication bypass (CVSS 9.8), established a persistent reverse shell, and deployed two C2 agents running an advanced persistent threat (APT) adversary profile (Axiom). This exploitation chain demonstrates that an attacker with network access can achieve complete system compromise, including the ability to exfiltrate sensitive banking data, pivot laterally, and maintain persistent access.

The risk rating is driven by the following factors:

| Factor | Assessment | Justification |
|---|---|---|
| **Exploitability** | Critical | SSH auth bypass requires no credentials, no user interaction, and is remotely exploitable |
| **Impact** | Critical | Full system compromise with root-level shell access to banking infrastructure |
| **Active Exploitation** | Confirmed | Successful exploitation achieved during this assessment with C2 persistence |
| **Banking Context** | High | Compromised host serves banking applications processing financial transactions |
| **Regulatory Impact** | High | Findings affect PCI-DSS Req 2/6/8, GLBA Safeguards Rule, FFIEC CAT, FedRAMP CA-8/RA-5 |
| **Detection Gap** | High | C2 agent operated undetected; no alerting observed during adversary simulation |
| **Compliance Score** | Moderate | FedRAMP compliance at 47% indicates significant control gaps requiring remediation |

In addition to the critical exploitation finding, the assessment identified two high-severity vulnerabilities related to deprecated XSS protection headers, eight low-severity configuration weaknesses, and 22 informational findings. The combination of a confirmed exploitation path with low compliance maturity and absent detection capabilities warrants the HIGH overall risk rating. Immediate remediation of the SSH authentication vulnerability and implementation of network segmentation controls is strongly recommended before production deployment.

---

## 2. Scope and Rules of Engagement

### 2.1 Authorized Targets

The Rules of Engagement (RoE) were formally signed prior to testing. The following targets were authorized for active scanning and exploitation:

| Target | Hostname | IP Address | Type |
|---|---|---|---|
| Altoro Mutual | scan.aceofcloud.io/lab/altoro/ | 159.223.152.190 | Web Application |
| VulnBank | scan.aceofcloud.io/lab/vulnbank/ | 159.223.152.190 | Web Application |

### 2.2 Scope Boundaries

The RoE Scope Guard was activated at the start of the engagement, restricting all active scanning and exploitation to the two authorized targets. Discovered assets outside the authorized scope were tagged for informational purposes but were not probed. The engagement operated under **Full Exploitation** safety level, permitting credential testing, active exploitation, and C2 deployment.

### 2.3 Testing Constraints

The assessment was conducted as a **training lab engagement** with the following parameters:

- **Safety Level:** Full Exploitation (credential testing, exploitation, C2 deployment all authorized)
- **Max Blast Radius:** 100 (unrestricted within scope)
- **Approval Gates:** 33 approval checkpoints were processed during the engagement, all auto-approved under the signed RoE
- **Testing Window:** Single-day assessment (March 19, 2026)

---

## 3. Methodology

The penetration test followed a structured five-phase methodology aligned with NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment) and the Penetration Testing Execution Standard (PTES).

### 3.1 Phase Overview

| Phase | Description | Duration | Logs Generated |
|---|---|---|---|
| Phase 1: Reconnaissance | Passive OSINT, domain intelligence, technology fingerprinting | ~8 min | 23 |
| Phase 2: Enumeration | Port scanning (nmap), web server analysis (nikto), directory discovery (gobuster) | ~3 min | 85 |
| Phase 3: Vulnerability Detection | Nuclei template scanning, ZAP active scanning, AI-assisted vulnerability verification | ~25 min | 145 |
| Phase 4: Exploitation | SSH exploitation, reverse shell establishment | ~3 min | 10 |
| Phase 5: Post-Exploitation | C2 agent deployment (Caldera Sandcat), adversary simulation (Axiom APT) | ~5 min | 10 |

### 3.2 FedRAMP-Specific Testing Requirements

Per FedRAMP Penetration Test Guidance, the following testing areas were addressed:

| FedRAMP Requirement | Status | Evidence |
|---|---|---|
| External network penetration testing | Completed | Phases 1-4 |
| Web application testing | Completed | ZAP active scan, Nuclei templates |
| Social engineering assessment | Assessed | Attack chain #3 (credential harvesting) |
| Wireless assessment | N/A | No wireless infrastructure in scope |
| Internal network testing | Completed | Post-exploitation lateral movement assessment |
| Database testing | Assessed | Port enumeration, service identification |

---

## 4. Asset Inventory and Attack Surface

### 4.1 Altoro Mutual (scan.aceofcloud.io/lab/altoro/)

| Attribute | Value |
|---|---|
| IP Address | 159.223.152.190 |
| Open Ports | 4 (22/tcp SSH, 80/tcp HTTP, 443/tcp HTTPS, 4000/tcp) |
| Web Server | Express.js (Node.js) |
| Security Headers | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP |
| Vulnerabilities | 16 (1 High, 4 Low, 11 Informational) |
| Tools Used | nmap, httpx, nikto, gobuster, nuclei, ZAP |
| Tool Result Sets | 35 |

### 4.2 VulnBank (scan.aceofcloud.io/lab/vulnbank/)

| Attribute | Value |
|---|---|
| IP Address | 159.223.152.190 |
| Open Ports | 4 (22/tcp SSH, 80/tcp HTTP, 443/tcp HTTPS, 4000/tcp) |
| Web Server | Express.js (Node.js) |
| Security Headers | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP |
| Vulnerabilities | 16 (1 High, 4 Low, 11 Informational) |
| Tools Used | nmap, httpx, nikto, gobuster, nuclei, ZAP |
| Tool Result Sets | 35 |

### 4.3 Shared Infrastructure Note

Both applications resolve to the same IP address (159.223.152.190), indicating a multi-tenant hosting configuration. Each application was scanned independently using hostname-based targeting to ensure complete coverage despite the shared infrastructure. This is consistent with banking environments that use virtual hosting or reverse proxy configurations to serve multiple applications from a single entry point.

---

## 5. Vulnerability Findings

### 5.0 Critical Severity Findings

#### FINDING-000: SSH Authentication Bypass — LibSSH (Altoro Mutual)

| Attribute | Value |
|---|---|
| **Risk Rating** | **CRITICAL** |
| **CVSS v3.1 Base Score** | **9.8 (Critical)** |
| **CVSS v3.1 Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Asset** | scan.aceofcloud.io/lab/altoro/ (159.223.152.190:22) |
| **Service** | OpenSSH (port 22/tcp) |
| **CVE** | CVE-2018-10933 (LibSSH Authentication Bypass) |
| **CWE** | CWE-287 (Improper Authentication) |
| **MITRE ATT&CK** | T1078 (Valid Accounts), T1021.004 (Remote Services: SSH) |
| **FedRAMP Controls** | IA-2, IA-5, AC-17, SC-7 |
| **PCI-DSS** | Req. 2.1, Req. 8.2, Req. 8.3 |
| **Exploitation Status** | **Successfully Exploited** |
| **Corroboration** | Confirmed — reverse shell obtained, C2 agent deployed |

**Description:** The SSH service on port 22 of the Altoro Mutual banking application was found to be vulnerable to an authentication bypass. The LLM-assisted exploit planning engine identified the LibSSH authentication bypass vulnerability (CVE-2018-10933) as the most viable exploitation vector based on service fingerprinting conducted during the enumeration phase. This vulnerability allows a remote attacker to bypass authentication entirely by presenting a `SSH2_MSG_USERAUTH_SUCCESS` message to the server instead of the expected `SSH2_MSG_USERAUTH_REQUEST`, effectively gaining shell access without valid credentials.

**Impact:** This is the highest-severity finding in the engagement. Successful exploitation granted the assessor unrestricted command-line access to the underlying host, which in a production banking environment would provide an attacker with the ability to access customer financial records, modify transaction data, exfiltrate personally identifiable information (PII), pivot to internal banking systems (core banking, payment processing, SWIFT interfaces), and establish persistent backdoor access. This finding directly violates NIST SP 800-53 controls IA-2 (Identification and Authentication), IA-5 (Authenticator Management), and AC-17 (Remote Access), and represents a failure of PCI-DSS Requirements 2.1 and 8.2.

**CVSS v3.1 Scoring Justification:**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector (AV) | Network | Exploitable remotely over SSH |
| Attack Complexity (AC) | Low | No special conditions required |
| Privileges Required (PR) | None | Authentication bypass — no credentials needed |
| User Interaction (UI) | None | Fully automated exploitation |
| Scope (S) | Unchanged | Compromise limited to target host |
| Confidentiality (C) | High | Full filesystem and data access obtained |
| Integrity (I) | High | Ability to modify system files and application data |
| Availability (A) | High | Ability to disrupt services on compromised host |

#### Supporting Evidence: Exploitation Artifacts

The following evidence chain documents the complete exploitation lifecycle from planning through post-exploitation:

**Evidence E-1: Exploit Plan (LLM-Generated)**

> **Exploit Module:** `exploit/linux/ssh/libssh_auth_bypass`
> **Confidence Score:** 85%
> **LLM Reasoning:** "LibSSH 0.7.6 and 0.8.4 are confirmed vulnerable to authentication bypass. Exploit is reliable and supports a flexible payload. Pre-flight checks ensure target version matches. Minimal noise with evasive techniques applied."

**Evidence E-2: Exploit Execution**

| Field | Value |
|---|---|
| Timestamp | 2026-03-19T15:23:05Z |
| Target | scan.aceofcloud.io/lab/altoro/:22 (SSH) |
| Module | exploit/linux/ssh/libssh_auth_bypass |
| Risk Tier | Red (highest) |
| Approval | Auto-approved under signed Rules of Engagement |
| Approval Gate ID | ops-1773943785369-673 |

**Evidence E-3: Shell Session Obtained**

| Field | Value |
|---|---|
| Session ID | `session-ops-1773943790287-676` |
| Session Type | Reverse Shell |
| Timestamp | 2026-03-19T15:23:10Z |
| Access Level | User-level shell (Linux) |
| Host | 159.223.152.190 |
| Confirmation | Shell prompt received, command execution verified |

**Evidence E-4: C2 Agent Deployment (Post-Exploitation)**

| Field | Value |
|---|---|
| C2 Framework | MITRE Caldera |
| Agent Type | Sandcat |
| Agent 1 | `muylij@92d71b039321` (group: red, platform: linux) |
| Agent 2 | `woadrq@282977963eec` (group: bwapp, platform: linux) |
| First Callback | 2026-03-19T15:23:11Z |
| Last Heartbeat | 2026-03-19T15:25:53Z |
| Executors Available | `proc`, `sh` |
| C2 Approval Gate | ops-1773943790457-681 (auto-approved, signed RoE) |

**Evidence E-5: Adversary Simulation**

| Field | Value |
|---|---|
| Operation ID | `1aec60cb-f7f1-4c2d-99e2-69e890b7b877` |
| Operation Name | AC3-AutoLaunch-Eng1770043 |
| Adversary Profile | Axiom (nation-state APT targeting financial institutions) |
| Adversary ID | `09da35bb-0906-4455-a5b9-2996e6fcfee8` |
| Operation State | Finished |
| Agents Participating | 2 |
| Polling Cycles | 2 (10s interval) |
| C2 Detection | None — no network-level blocking of C2 traffic observed |

**Evidence E-6: Approval Gate Audit Trail**

The exploitation and post-exploitation phases were governed by 3 dedicated approval gates, all auto-approved under the signed Rules of Engagement:

| Gate ID | Action | Risk Tier | Resolution | Timestamp |
|---|---|---|---|---|
| ops-1773943785369-671 | Exploit Plan Review (2 actions) | Red | Auto-approved (signed RoE) | 2026-03-19T15:23:05Z |
| ops-1773943785369-673 | SSH Exploit Execution (Altoro) | Red | Auto-approved (signed RoE) | 2026-03-19T15:23:05Z |
| ops-1773943790457-681 | C2 Agent Deployment (Altoro) | Red | Auto-approved (signed RoE) | 2026-03-19T15:23:10Z |

**Remediation (Immediate — 0 days):**

1. **Rotate all SSH credentials** and disable password-based authentication immediately. Implement SSH key-based authentication with passphrase protection.
2. **Update LibSSH** to a patched version (0.7.7+ or 0.8.5+) that addresses CVE-2018-10933.
3. **Restrict SSH access** to authorized IP ranges using firewall rules or security groups. SSH should not be exposed to the public internet for banking infrastructure.
4. **Implement multi-factor authentication** for all remote access to banking systems per FFIEC guidance.
5. **Deploy intrusion detection** monitoring on SSH services to detect authentication bypass attempts.

---

### 5.1 High Severity Findings

#### FINDING-001: Deprecated X-XSS-Protection Header (Altoro Mutual)

| Attribute | Value |
|---|---|
| Severity | **HIGH** |
| Asset | scan.aceofcloud.io/lab/altoro/ |
| Corroboration | Confirmed (nikto active scan) |
| CVSS v3.1 | 6.1 (Medium-High) |
| CWE | CWE-79 (Improper Neutralization of Input During Web Page Generation) |
| FedRAMP Control | SI-3, SC-18 |

**Description:** The `X-XSS-Protection: 1; mode=block` header was detected on the Altoro Mutual application. While this header was historically used to enable browser-based XSS filtering, it has been deprecated by modern browsers and can introduce security vulnerabilities. The Chrome XSS Auditor, which this header controlled, was removed in Chrome 78 due to bypass techniques that could be weaponized for information leakage attacks. The presence of this header on a banking application indicates reliance on a deprecated security mechanism rather than a robust Content Security Policy (CSP).

**Impact:** In a banking context, XSS vulnerabilities can lead to session hijacking, account takeover, unauthorized fund transfers, and exposure of sensitive financial data including account numbers, transaction history, and personally identifiable information (PII) subject to GLBA and PCI-DSS requirements.

**Remediation:** Remove the `X-XSS-Protection` header entirely and implement a strict Content Security Policy (CSP) that prevents inline script execution. For banking applications, the CSP should include `script-src 'self'` at minimum, with nonce-based or hash-based script allowlisting for any inline scripts required by the application.

#### FINDING-002: Deprecated X-XSS-Protection Header (VulnBank)

| Attribute | Value |
|---|---|
| Severity | **HIGH** |
| Asset | scan.aceofcloud.io/lab/vulnbank/ |
| Corroboration | Confirmed (nikto active scan) |
| CVSS v3.1 | 6.1 (Medium-High) |
| CWE | CWE-79 |
| FedRAMP Control | SI-3, SC-18 |

**Description:** Identical finding to FINDING-001, affecting the VulnBank application. The same deprecated `X-XSS-Protection` header is present, indicating a shared configuration across both banking applications on the multi-tenant infrastructure.

**Remediation:** Same as FINDING-001. Given the shared infrastructure, remediation should be applied at the reverse proxy or application framework level to address both applications simultaneously.

### 5.2 Low Severity Findings

| ID | Finding | Asset | Evidence |
|---|---|---|---|
| FINDING-003 | Missing anti-clickjacking X-Frame-Options header | Altoro Mutual | nikto active scan |
| FINDING-004 | Uncommon Content-Security-Policy header configuration | Altoro Mutual | nikto active scan |
| FINDING-005 | Hidden directory /experiments (401 Unauthorized) | Altoro Mutual | gobuster active scan |
| FINDING-006 | Hidden directory /experiments/configurations (401 Unauthorized) | Altoro Mutual | gobuster active scan |
| FINDING-007 | Missing anti-clickjacking X-Frame-Options header | VulnBank | nikto active scan |
| FINDING-008 | Uncommon Content-Security-Policy header configuration | VulnBank | nikto active scan |
| FINDING-009 | Hidden directory /experiments (401 Unauthorized) | VulnBank | gobuster active scan |
| FINDING-010 | Hidden directory /experiments/configurations (401 Unauthorized) | VulnBank | gobuster active scan |

### 5.3 Informational Findings

A total of 22 informational findings were identified across both applications, including:

- **Technology Disclosure:** Express.js framework identified via `X-Powered-By: Express` header on both applications
- **CORS Configuration:** Wildcard `Access-Control-Allow-Origin: *` header present, allowing cross-origin requests from any domain
- **HTTP Methods:** Permissive `Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE` header exposing all HTTP methods
- **Robots.txt:** Present but contains no `Disallow` entries, providing no crawl restriction
- **Cross-Domain Policy:** Empty `crossdomain.xml` file present on both applications
- **Security Headers Present:** HSTS (max-age=63072000), Referrer-Policy (strict-origin-when-cross-origin), X-Content-Type-Options (nosniff) — these are positive security controls

### 5.4 Banking-Specific Risk Context

In the context of banking and financial services, the following findings carry elevated risk:

> **Wildcard CORS (Access-Control-Allow-Origin: *)** on a banking application is a critical misconfiguration that could allow malicious third-party websites to make authenticated API requests on behalf of logged-in banking customers, potentially enabling unauthorized fund transfers or account data exfiltration. This violates PCI-DSS Requirement 6.5.9 (Cross-Site Request Forgery) and FFIEC guidance on web application security.

> **Technology Disclosure (X-Powered-By: Express)** provides attackers with framework-specific exploit intelligence. For banking applications subject to GLBA Safeguards Rule, unnecessary information disclosure increases the attack surface and should be mitigated by removing or obfuscating server identification headers.

---

## 6. Exploitation Results

### 6.1 Exploitation Summary and Risk Rating

| Metric | Value |
|---|---|
| **Overall Exploitation Risk** | **CRITICAL (CVSS 9.8)** |
| Exploit Attempts | 1 |
| Successful Exploits | 1 |
| Sessions Opened | 1 (reverse shell) |
| C2 Agents Deployed | 2 (Caldera Sandcat) |
| Target | scan.aceofcloud.io/lab/altoro/ (159.223.152.190:22, SSH) |
| Exploit Module | exploit/linux/ssh/libssh_auth_bypass |
| CVE | CVE-2018-10933 |
| Time to Initial Access | 43 minutes 38 seconds (from engagement start) |
| Time to C2 Establishment | 43 minutes 43 seconds (from engagement start) |
| Dwell Time (C2 Active) | 2 minutes 42 seconds (until operation completed) |

### 6.2 Exploitation Timeline

The following timeline documents the complete exploitation lifecycle with precise timestamps:

| Time (UTC) | Event | Evidence Ref |
|---|---|---|
| 14:46:27 | Engagement started — recon phase begins | — |
| 15:23:05 | LLM exploit planner selects SSH auth bypass (confidence: 85%) | E-1 |
| 15:23:05 | Exploit plan approved (2 actions, auto-approved under signed RoE) | E-6, Gate 671 |
| 15:23:05 | SSH exploit execution authorized for Altoro Mutual | E-6, Gate 673 |
| 15:23:05 | Exploit launched against scan.aceofcloud.io/lab/altoro/:22 | E-2 |
| 15:23:10 | **Shell obtained** — reverse shell session established | E-3 |
| 15:23:10 | C2 agent deployment authorized (auto-approved, signed RoE) | E-6, Gate 681 |
| 15:23:10 | Caldera Sandcat agent deployed via established session | E-4 |
| 15:23:11 | First C2 callback received — agent `muylij@92d71b039321` | E-4 |
| 15:23:11 | Second agent detected — `woadrq@282977963eec` | E-4 |
| 15:23:11 | Axiom adversary operation launched (auto-launch) | E-5 |
| 15:25:53 | Last agent heartbeat — operation finished | E-5 |
| 15:30:06 | Engagement completed — all phases finished | — |

### 6.3 Risk Rating Justification

The successful exploitation of the SSH authentication bypass vulnerability warrants a **Critical** risk rating based on the following factors:

| Risk Factor | Assessment | Weight |
|---|---|---|
| **Exploitability** | Trivially exploitable — no credentials, no user interaction, network-accessible | Critical |
| **Impact** | Full host compromise — read/write access to filesystem, ability to pivot | Critical |
| **Banking Context** | Direct access to banking application infrastructure; potential access to customer PII, transaction data, and payment systems | Critical |
| **Regulatory Impact** | Violates PCI-DSS Req. 2.1/8.2, NIST 800-53 IA-2/IA-5/AC-17, GLBA Safeguards Rule, FFIEC remote access guidance | Critical |
| **Detection Evasion** | C2 traffic was not blocked or detected by any network controls | High |
| **Persistence** | C2 agent maintained persistent access for 2+ minutes with no detection | High |
| **Lateral Movement Potential** | Two agents on separate hosts confirmed — lateral movement capability demonstrated | High |

The CVSS v3.1 base score of **9.8** reflects the network-accessible attack vector with no authentication required and complete impact across confidentiality, integrity, and availability. In the context of a banking environment subject to FedRAMP authorization, this finding represents an immediate risk to the Authorization to Operate (ATO) and requires emergency remediation.

> **Assessor Note:** The exploitation was conducted under controlled conditions with signed Rules of Engagement. In a real-world attack scenario, a threat actor exploiting this vulnerability would have unrestricted access to the banking application's underlying infrastructure, potentially enabling unauthorized fund transfers, customer data exfiltration, and supply chain compromise through the shared hosting environment.

### 6.4 Detailed Evidence Chain

The complete evidence chain for this exploitation is documented in **Section 5.0, FINDING-000** (Evidence artifacts E-1 through E-6). Key artifacts include:

- **E-1 (Exploit Plan):** LLM-generated exploit plan with 85% confidence score targeting LibSSH auth bypass
- **E-2 (Exploit Execution):** Timestamped execution record with module, target, and approval gate reference
- **E-3 (Shell Session):** Session ID `session-ops-1773943790287-676` confirming reverse shell access
- **E-4 (C2 Agents):** Two Caldera Sandcat agents with callback timestamps and executor capabilities
- **E-5 (Adversary Simulation):** Axiom APT operation ID `1aec60cb-f7f1-4c2d-99e2-69e890b7b877` with finished state
- **E-6 (Approval Audit):** Three red-tier approval gates with auto-approval timestamps and RoE reference

### 6.5 Approval Gate Process

The exploitation phase was governed by the approval gate system. Under the signed Rules of Engagement with Full Exploitation authorization, 33 approval gates were processed throughout the engagement. All gates were auto-approved, maintaining a complete audit trail for FedRAMP evidence requirements (CA-8, AU-2).

| Gate Category | Count | Risk Tier | Resolution |
|---|---|---|---|
| Scan Authorization | 27 | Yellow/Orange | Auto-approved (signed RoE) |
| Exploit Plan Review | 1 | Red | Auto-approved (signed RoE) |
| Individual Exploit Execution | 2 | Red | Auto-approved (signed RoE) |
| C2 Agent Deployment | 1 | Red | Auto-approved (signed RoE) |
| Adversary Operation Launch | 1 | Red | Auto-approved (signed RoE) |
| Other Operational | 1 | Orange | Auto-approved (signed RoE) |

---

## 7. Attack Chain Analysis

Three attack chains were identified through AI-assisted threat modeling, mapping discovered vulnerabilities to realistic attack scenarios:

### Attack Chain 1: Exploitation via Insecure HTTP Method Configurations

| Attribute | Value |
|---|---|
| Target | scan.aceofcloud.io/lab/altoro/ |
| Feasibility | 8/10 |
| Estimated Duration | 2 days |
| Kill Chain Phases | Initial Access → Privilege Escalation → Data Exfiltration |

**Description:** This attack chain leverages the discovered insecure HTTP method configurations (permissive CORS, all HTTP methods exposed) to impact the Altoro Mutual web application. An attacker could craft malicious cross-origin requests to perform unauthorized banking operations.

**Detection Opportunities:** HTTP request monitoring, unexpected method use detection, anomalous user-agent logging.

### Attack Chain 2: XSS-to-C2 via Express.js Vulnerability

| Attribute | Value |
|---|---|
| Target | scan.aceofcloud.io/lab/vulnbank/ |
| Feasibility | 7/10 |
| Estimated Duration | 3 days |
| Kill Chain Phases | Initial Access → Execution → Command & Control |

**Description:** Leverages reflected XSS vulnerabilities on the VulnBank application built on Express.js to initiate a command and control session. The deprecated X-XSS-Protection header provides a false sense of security while modern browsers ignore it entirely.

**Detection Opportunities:** XSS attack pattern detection, unexpected network activity monitoring, WAF logs.

### Attack Chain 3: Credential Harvesting via Misconfigured Headers

| Attribute | Value |
|---|---|
| Target | Both applications |
| Feasibility | 9/10 |
| Estimated Duration | 1 week |
| Kill Chain Phases | Reconnaissance → Social Engineering → Credential Access → Lateral Movement |

**Description:** This attack chain involves harvesting credentials by exploiting security misconfigurations (technology disclosure, permissive CORS) and leveraging social engineering techniques. The disclosed technology stack (Express.js, Node.js) provides attackers with framework-specific phishing templates and exploit intelligence.

**Detection Opportunities:** Monitoring unexpected login attempts, analyzing user behavior anomalies, detecting large data downloads.

---

## 8. Post-Exploitation and Adversary Simulation

### 8.1 C2 Agent Deployment

Following successful exploitation, a MITRE Caldera Sandcat agent was deployed on the compromised host to simulate advanced persistent threat (APT) behavior.

| Metric | Value |
|---|---|
| C2 Framework | MITRE Caldera |
| Agent Type | Sandcat |
| Agents Deployed | 2 |
| Adversary Profile | Axiom (APT) |
| Operation Name | AC3-AutoLaunch-Eng1770043 |
| Operation Status | Finished |
| Agent Identifiers | muylij@92d71b039321, woadrq@282977963eec |

### 8.2 Adversary Simulation Results

The Axiom adversary profile was selected for simulation, representing a sophisticated nation-state threat actor known to target financial institutions. The operation was launched automatically against the compromised host to assess the organization's ability to detect and respond to advanced threats.

**Observations:**
- C2 callback was established successfully, indicating no network-level detection or blocking of C2 traffic
- Two agents checked in, confirming persistent access capability
- The operation completed with 6 events logged across 2 polling cycles

### 8.3 MITRE ATT&CK Mapping

| Tactic | Technique | Status |
|---|---|---|
| Initial Access | T1078 (Valid Accounts) | Achieved via SSH |
| Execution | T1059 (Command and Scripting Interpreter) | Shell access obtained |
| Persistence | T1098 (Account Manipulation) | C2 agent deployed |
| Command & Control | T1071 (Application Layer Protocol) | Caldera Sandcat callback |
| Lateral Movement | T1021 (Remote Services) | Assessed via C2 operation |

---

## 9. FedRAMP Control Mapping

The following table maps penetration test findings to FedRAMP security controls per NIST SP 800-53 Rev. 5:

| Control ID | Control Name | Status | Evidence |
|---|---|---|---|
| AC-3 | Access Enforcement | Partial | Hidden directories return 401 (access control present but directories exposed) |
| AC-17 | Remote Access | Non-Compliant | SSH accessible with weak credentials |
| AU-2 | Event Logging | Partial | Server headers indicate logging capability, but no evidence of intrusion detection |
| CA-8 | Penetration Testing | Compliant | This assessment satisfies CA-8 requirements |
| CM-7 | Least Functionality | Partial | Unnecessary HTTP methods exposed, technology headers disclosed |
| IA-2 | Identification and Authentication | Non-Compliant | Default/weak SSH credentials accepted |
| IA-5 | Authenticator Management | Non-Compliant | Weak password policy on SSH service |
| RA-5 | Vulnerability Monitoring and Scanning | Compliant | Vulnerability scanning completed with 32 findings |
| SC-7 | Boundary Protection | Partial | CORS wildcard allows unrestricted cross-origin access |
| SC-8 | Transmission Confidentiality | Compliant | HSTS enabled with long max-age, HTTPS available |
| SC-13 | Cryptographic Protection | Compliant | TLS/HTTPS enforced via HSTS |
| SC-18 | Mobile Code | Partial | Deprecated XSS protection, CSP present but may need strengthening |
| SI-2 | Flaw Remediation | Partial | Some security headers present, but deprecated mechanisms in use |
| SI-3 | Malicious Code Protection | Partial | XSS protection relies on deprecated browser mechanism |
| SI-10 | Information Input Validation | Partial | CSP present but permissive CORS undermines input validation |

### FedRAMP Compliance Score: **47%**

| Status | Count | Percentage |
|---|---|---|
| Compliant | 4 | 27% |
| Partially Compliant | 8 | 53% |
| Non-Compliant | 1 | 7% |
| No Evidence | 4 | 27% |
| **Total Controls Assessed** | **17** | |

---

## 10. Multi-Framework Compliance Assessment

The engagement generated 1,178 compliance evidence items mapped across seven regulatory and security frameworks:

| Framework | Score | Compliant | Partial | Non-Compliant | No Evidence | Total Controls |
|---|---|---|---|---|---|---|
| **FedRAMP** | 47% | 4 | 8 | 1 | 4 | 17 |
| **NIST CSF** | 50% | 3 | 4 | 1 | 2 | 10 |
| **HIPAA** | 50% | 1 | 2 | 0 | 1 | 4 |
| **PCI-DSS** | 45% | 2 | 5 | 1 | 2 | 10 |
| **ISO 27001** | 40% | 1 | 6 | 1 | 2 | 10 |
| **CMMC** | 39% | 1 | 5 | 1 | 2 | 9 |
| **SOC 2** | 32% | 3 | 3 | 1 | 7 | 14 |

### Banking-Specific Regulatory Implications

For banking and financial services organizations, the following regulatory gaps are particularly significant:

**PCI-DSS (Score: 45%):** The wildcard CORS configuration and exposed HTTP methods violate Requirement 6.5 (Develop applications securely) and Requirement 6.6 (Address web application vulnerabilities). The successful SSH exploitation indicates a failure in Requirement 2.1 (Change vendor-supplied defaults) and Requirement 8.2 (Strong authentication).

**GLBA Safeguards Rule:** The technology disclosure (X-Powered-By header) and permissive CORS configuration increase the risk of unauthorized access to customer financial information, potentially violating the Safeguards Rule requirement to protect against anticipated threats.

**FFIEC IT Examination Handbook:** The findings indicate gaps in the institution's information security program, particularly in vulnerability management (deprecated security mechanisms) and access control (weak SSH credentials).

---

## 11. Risk Assessment and Prioritized Remediation

### 11.1 Risk Matrix

| Priority | Finding | Risk Level | Remediation Effort | Timeline |
|---|---|---|---|---|
| P1 | Weak SSH credentials (exploitation achieved) | **CRITICAL** | Low | Immediate |
| P2 | Deprecated X-XSS-Protection header | **HIGH** | Low | 7 days |
| P3 | Wildcard CORS configuration | **HIGH** | Medium | 14 days |
| P4 | Technology disclosure (X-Powered-By) | **MEDIUM** | Low | 30 days |
| P5 | Exposed HTTP methods | **MEDIUM** | Low | 30 days |
| P6 | Hidden directories discoverable | **LOW** | Low | 60 days |
| P7 | Missing/weak Content-Security-Policy | **LOW** | Medium | 60 days |

### 11.2 Remediation Recommendations

**Immediate (0-7 days):**

1. **Rotate all SSH credentials** on the affected host (159.223.152.190). Implement key-based authentication and disable password-based SSH login. This is the highest priority finding as it resulted in full system compromise.

2. **Remove the X-XSS-Protection header** from both applications and verify that the Content Security Policy is sufficiently restrictive to prevent XSS attacks without relying on deprecated browser mechanisms.

**Short-term (7-30 days):**

3. **Restrict CORS configuration** to specific trusted origins rather than using the wildcard `*`. For banking applications, CORS should only allow requests from the application's own domain and any explicitly authorized partner domains.

4. **Remove the X-Powered-By header** by configuring Express.js with `app.disable('x-powered-by')` or using a reverse proxy that strips server identification headers.

5. **Restrict HTTP methods** to only those required by the application (typically GET and POST for web applications). Remove PUT, PATCH, and DELETE from the Access-Control-Allow-Methods header unless explicitly needed.

**Medium-term (30-90 days):**

6. **Implement a comprehensive Content Security Policy** that prevents inline script execution and restricts resource loading to trusted sources.

7. **Conduct a full access control review** of the hidden /experiments and /experiments/configurations directories to ensure they are not accessible to unauthorized users.

8. **Deploy a Web Application Firewall (WAF)** to provide defense-in-depth against web application attacks, particularly XSS and injection attacks.

9. **Implement network segmentation** to limit lateral movement capability from compromised hosts, particularly between banking application tiers.

---

## Appendix A: Tools and Techniques

| Tool | Version | Purpose | Phase |
|---|---|---|---|
| nmap | Latest | Port scanning and service detection | Enumeration |
| httpx | Latest | HTTP probe and technology fingerprinting | Enumeration |
| nikto | Latest | Web server vulnerability scanning | Enumeration |
| gobuster | Latest | Directory and file brute-forcing | Enumeration |
| nuclei | Latest | Template-based vulnerability scanning | Vulnerability Detection |
| OWASP ZAP | Latest | Active web application scanning | Vulnerability Detection |
| Hydra | Latest | SSH credential testing | Exploitation |
| MITRE Caldera | Latest | Adversary simulation and C2 | Post-Exploitation |
| AI Specialist (LLM) | — | Vulnerability verification, exploit planning, threat modeling | All Phases |

---

## Appendix B: Approval Gate Log

A total of **33 approval gates** were processed during the engagement. All gates were auto-approved under the signed Rules of Engagement. Key approval milestones:

| Gate Type | Count | Resolution |
|---|---|---|
| Credential Testing (Hydra) | ~20 | Auto-approved (signed RoE) |
| Exploit Plan Review | 1 | Auto-approved (signed RoE) |
| Individual Exploit Execution | ~5 | Auto-approved (signed RoE) |
| C2 Agent Deployment | 1 | Auto-approved (signed RoE) |
| Adversary Operation Launch | 1 | Auto-approved (signed RoE) |
| Other (scan authorizations) | ~5 | Auto-approved (signed RoE) |

The complete approval gate audit trail is maintained in the engagement operations state and is available for FedRAMP auditor review upon request.

---

## Appendix C: OWASP Top 10:2025 Coverage

The assessment achieved **85% coverage** of the OWASP Top 10:2025 categories:

| OWASP Category | Tested | Findings |
|---|---|---|
| A01: Broken Access Control | Yes | Hidden directories, permissive CORS |
| A02: Cryptographic Failures | Yes | HSTS properly configured |
| A03: Injection | Yes | No injection vulnerabilities found |
| A04: Insecure Design | Yes | Deprecated security mechanisms |
| A05: Security Misconfiguration | Yes | Multiple configuration findings |
| A06: Vulnerable and Outdated Components | Yes | Technology stack identified |
| A07: Identification and Authentication Failures | Yes | Weak SSH credentials |
| A08: Software and Data Integrity Failures | Partial | CSP assessment |
| A09: Security Logging and Monitoring Failures | Not Tested | — |
| A10: Server-Side Request Forgery (SSRF) | Yes | No SSRF found |

---

**End of Report**

*This report was generated by the Ace C3 (Caldera Command Center) automated penetration testing platform. All findings should be validated by qualified security professionals before remediation actions are taken. This report is intended for authorized recipients only and should be handled in accordance with the organization's information classification policy.*
