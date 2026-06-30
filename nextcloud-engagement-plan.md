# Nextcloud HackerOne Bug Bounty Engagement Plan

**Engagement ID:** NC-H1-2026-001
**Classification:** Bug Bounty / Vulnerability Research
**Target Program:** [Nextcloud on HackerOne](https://hackerone.com/nextcloud)
**Prepared by:** AC3 Red Team Operations
**Date:** April 2026

---

## 1. Executive Summary

This engagement plan defines a structured approach to vulnerability research against the Nextcloud ecosystem as part of their HackerOne bug bounty program. Nextcloud is a self-hosted content collaboration platform with 94 in-scope assets spanning server components, mobile clients, desktop clients, and official apps. The program pays up to $10,000 for critical RCE vulnerabilities and has paid $127,618 total across 864 resolved reports.

**Key constraint:** All testing MUST occur on our own self-hosted Nextcloud instances. No automated scanning or DoS attacks against Nextcloud-operated infrastructure. Every finding must be manually reproduced with screenshot evidence.

---

## 2. Program Intelligence

### 2.1 Reward Structure

| Severity | Definition | Max Reward |
|----------|-----------|-----------|
| **Critical** | Remote code execution as non-admin user (RCE) | $10,000 |
| **High** | Access to complete user data of any other user (Auth Bypass) | $4,000 |
| **Medium** | Limited user data disclosure or single-user session access (XSS with CSP bypass) | $1,500 |
| **Low** | Very limited data disclosure or high user interaction required | $500 |

### 2.2 Program Statistics (as of April 2026)

- **Average bounty:** $150 | **Top range:** $750 - $5,000
- **Reports received (90 days):** 928 | **Reports resolved:** 864
- **Response efficiency:** 100%
- **Last report resolved:** 16 hours ago

### 2.3 Eligible Versions

| Version | Name | Current | EOL |
|---------|------|---------|-----|
| **33** | Hub 26 Winter | 33.0.2 | 2027-02 |
| **32** | Hub 25 Autumn | 32.0.8 | 2026-09 |

**Upcoming:** Version 34 (Hub 26 Spring) — Beta 1: April 28, Final: June 9, 2026

---

## 3. Rules of Engagement (RoE)

### 3.1 Mandatory Requirements

1. Every reported vulnerability MUST be reproduced on our own instance with screenshot proof
2. Reports MUST specify the Nextcloud Server version and App version tested
3. All findings MUST be manually validated — automated tool output alone is rejected
4. PII, secrets, keys, and credentials MUST be redacted in all report materials
5. No disclosure before Nextcloud publishes a patch

### 3.2 Prohibited Activities

1. **No DoS attacks** against any Nextcloud infrastructure
2. **No automated scanning** against Nextcloud-operated servers
3. **No user data extraction** from Nextcloud infrastructure
4. **No leaking report contents** to SaaS, AI services, search engines, or translation tools
5. **No third-party AppStore apps** — only Nextcloud GmbH-supported apps are in scope

### 3.3 AI/LLM Policy

- If LLMs are used, usage MUST be disclosed in the report
- Only locally-running LLM services may be used (no cloud AI)
- All reproduction steps must be manually verified
- AI-generated reports without manual review = Spam (-10 reputation) + possible suspension

---

## 4. Scope Analysis

### 4.1 Asset Categories (94 Total In-Scope Assets)

| Category | Count | Examples |
|----------|-------|---------|
| **Server Core** | 1 | nextcloud/server |
| **Official Apps** | ~75 | calendar, contacts, mail, talk, deck, files_sharing, encryption, etc. |
| **Mobile Clients** | 4 | Android, iOS (latest store versions only) |
| **Desktop Clients** | 3 | Windows, macOS, Linux (latest versions only) |
| **Supporting Libraries** | ~11 | nextcloud/android-library, nextcloud/ios-sdk, etc. |

### 4.2 High-Value Targets (Ranked by Reward Potential)

**Tier 1 — Critical ($10,000 RCE potential):**
- `nextcloud/server` — Core PHP application, WebDAV/OCS/DAV APIs
- `nextcloud/files_antivirus` — ClamAV integration (command injection surface)
- `nextcloud/files_external` — External storage mounts (SSRF, path traversal)
- `nextcloud/user_ldap` — LDAP authentication (injection, bypass)
- `nextcloud/encryption` / `nextcloud/end_to_end_encryption` — Crypto implementation flaws

**Tier 2 — High ($4,000 Auth Bypass potential):**
- `nextcloud/files_sharing` — Share link access control, public shares
- `nextcloud/twofactor_totp` / `nextcloud/twofactor_webauthn` — 2FA bypass
- `nextcloud/user_saml` — SAML SSO authentication bypass
- `nextcloud/spreed` (Talk) — Video/chat with WebRTC, signaling server
- `nextcloud/mail` — Email client (SSRF via IMAP/SMTP, XSS in rendered emails)

**Tier 3 — Medium ($1,500 XSS/data leak potential):**
- `nextcloud/text` — Collaborative editor (stored XSS, markdown injection)
- `nextcloud/richdocuments` — Collabora integration (document rendering XSS)
- `nextcloud/calendar` / `nextcloud/contacts` — CalDAV/CardDAV injection
- `nextcloud/notifications` — Notification content injection
- `nextcloud/activity` — Activity log data leakage

### 4.3 Attack Surface Map

```
┌─────────────────────────────────────────────────────────────┐
│                    NEXTCLOUD SERVER                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ WebDAV   │  │ OCS API  │  │ DAV API  │  │ REST API │   │
│  │ /remote. │  │ /ocs/v2/ │  │ /remote. │  │ /api/v1/ │   │
│  │ php/dav  │  │ cloud/   │  │ php/dav  │  │          │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│  ┌────┴──────────────┴──────────────┴──────────────┴────┐   │
│  │              PHP Application Layer                    │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐   │   │
│  │  │ Files   │ │ Sharing │ │ Auth    │ │ Apps     │   │   │
│  │  │ Engine  │ │ Engine  │ │ Engine  │ │ Framework│   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └──────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
│       │              │              │              │         │
│  ┌────┴──────────────┴──────────────┴──────────────┴────┐   │
│  │              Data Layer                               │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐   │   │
│  │  │ MySQL/  │ │ Redis/  │ │ S3/Local│ │ LDAP/    │   │   │
│  │  │ Postgres│ │ Memcache│ │ Storage │ │ SAML/SSO │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └──────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              External Integrations                    │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐   │   │
│  │  │Collabora│ │ TURN/   │ │ ClamAV  │ │ External │   │   │
│  │  │ Online  │ │ STUN    │ │ Scanner │ │ Storage  │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └──────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Desktop      │  │ Android      │  │ iOS          │
│ Client       │  │ Client       │  │ Client       │
│ (C++/Qt)     │  │ (Kotlin/Java)│  │ (Swift)      │
└──────────────┘  └──────────────┘  └──────────────┘
```

---

## 5. Test Environment Architecture

### 5.1 Infrastructure Requirements

All testing MUST be performed on self-hosted infrastructure. The following Docker-based environment provides full coverage:

**Primary Lab: Nextcloud 33.0.2 (Latest Stable)**
```yaml
# docker-compose.nextcloud-lab.yml
services:
  nextcloud-33:
    image: nextcloud:33.0.2-apache
    ports: ["8443:443", "8080:80"]
    volumes:
      - nc33_data:/var/www/html
      - nc33_custom_apps:/var/www/html/custom_apps
    environment:
      - MYSQL_HOST=db-33
      - MYSQL_DATABASE=nextcloud33
      - MYSQL_USER=nextcloud
      - MYSQL_PASSWORD=${NC_DB_PASS}
      - NEXTCLOUD_ADMIN_USER=admin
      - NEXTCLOUD_ADMIN_PASSWORD=${NC_ADMIN_PASS}
      - NEXTCLOUD_TRUSTED_DOMAINS=nc33.lab.local
    depends_on: [db-33, redis-33]

  db-33:
    image: mariadb:10.11
    environment:
      - MYSQL_ROOT_PASSWORD=${NC_DB_ROOT_PASS}
      - MYSQL_DATABASE=nextcloud33
      - MYSQL_USER=nextcloud
      - MYSQL_PASSWORD=${NC_DB_PASS}
    volumes: [db33_data:/var/lib/mysql]

  redis-33:
    image: redis:7-alpine
    volumes: [redis33_data:/data]

  # Collabora for document editing tests
  collabora:
    image: collabora/code:latest
    environment:
      - domain=nc33.lab.local
      - extra_params=--o:ssl.enable=false
    ports: ["9980:9980"]

  # ClamAV for antivirus integration tests
  clamav:
    image: clamav/clamav:latest
    ports: ["3310:3310"]
    volumes: [clamav_data:/var/lib/clamav]

  # TURN server for Talk/WebRTC tests
  coturn:
    image: coturn/coturn:latest
    ports: ["3478:3478/udp", "3478:3478/tcp"]

  # OpenLDAP for LDAP auth tests
  openldap:
    image: osixia/openldap:1.5.0
    environment:
      - LDAP_ORGANISATION=TestOrg
      - LDAP_DOMAIN=lab.local
      - LDAP_ADMIN_PASSWORD=${LDAP_ADMIN_PASS}
    ports: ["389:389"]
```

**Secondary Lab: Nextcloud 32.0.8 (Previous Stable)**
```yaml
  nextcloud-32:
    image: nextcloud:32.0.8-apache
    ports: ["9443:443", "9080:80"]
    # Same pattern as above with separate DB
```

### 5.2 Required Supporting Services

| Service | Purpose | Docker Image |
|---------|---------|-------------|
| **MariaDB 10.11** | Primary database | `mariadb:10.11` |
| **Redis 7** | Session/cache backend | `redis:7-alpine` |
| **Collabora CODE** | Document editing (richdocuments) | `collabora/code:latest` |
| **ClamAV** | Antivirus scanning (files_antivirus) | `clamav/clamav:latest` |
| **OpenLDAP** | LDAP authentication (user_ldap) | `osixia/openldap:1.5.0` |
| **Coturn** | TURN/STUN for Talk (spreed) | `coturn/coturn:latest` |
| **MinIO** | S3-compatible external storage | `minio/minio:latest` |
| **Mailhog** | Email testing (mail app) | `mailhog/mailhog:latest` |
| **Keycloak** | SAML/SSO testing (user_saml) | `quay.io/keycloak/keycloak:latest` |

### 5.3 Test User Matrix

| User | Role | Purpose |
|------|------|---------|
| `admin` | Administrator | Admin-level testing, app management |
| `user1` | Regular user | Standard user operations, file sharing |
| `user2` | Regular user | Cross-user access control testing |
| `user3` | Regular user | Group-based permission testing |
| `ldapuser1` | LDAP user | LDAP authentication testing |
| `shareuser` | Regular user | Share link and federated sharing tests |
| `encuser` | Regular user | E2E encryption testing |

### 5.4 Apps to Install for Testing

All Nextcloud GmbH-supported apps that are in the H1 scope:

```bash
# Core apps (install via occ)
php occ app:install calendar
php occ app:install contacts
php occ app:install deck
php occ app:install mail
php occ app:install spreed          # Talk
php occ app:install text
php occ app:install richdocuments   # Collabora integration
php occ app:install files_external
php occ app:install files_antivirus
php occ app:install encryption
php occ app:install end_to_end_encryption
php occ app:install user_ldap
php occ app:install user_saml
php occ app:install twofactor_totp
php occ app:install twofactor_webauthn
php occ app:install notifications
php occ app:install activity
php occ app:install files_sharing   # Usually pre-installed
php occ app:install groupfolders
php occ app:install circles
php occ app:install photos
php occ app:install maps
php occ app:install forms
php occ app:install polls
php occ app:install collectives
php occ app:install news
php occ app:install notes
php occ app:install bookmarks
php occ app:install tasks
php occ app:install passwords
```

---

## 6. Open Source Tooling Arsenal

### 6.1 Source Code Analysis (SAST)

| Tool | Purpose | Target |
|------|---------|--------|
| **Semgrep** | PHP SAST with OWASP rules (`semgrep --config p/php --config p/owasp-top-ten`) | Server PHP code, app PHP code |
| **PHPStan** | PHP static analysis (type safety, dead code) | All PHP repos |
| **Psalm** | PHP taint analysis (tracks user input to dangerous sinks) | Server core, apps |
| **PHPCS-Security-Audit** | PHP security-focused code sniffer | All PHP repos |
| **Snyk CLI** | Dependency vulnerability scanning | Composer, npm, Gradle, CocoaPods |
| **Trivy** | Container image vulnerability scanning | Docker images |
| **Grype** | SBOM-based vulnerability scanning | All dependencies |

### 6.2 Dynamic Application Security Testing (DAST)

| Tool | Purpose | Target |
|------|---------|--------|
| **OWASP ZAP** | Web app scanner, proxy, fuzzer (against our instance only) | WebDAV, OCS, DAV, REST APIs |
| **Nuclei** | Template-based vulnerability scanner | Known CVE patterns, misconfigs |
| **ffuf** | Web fuzzer (directory, parameter, vhost) | API endpoints, hidden routes |
| **Burp Suite Community** | Manual proxy/repeater for request manipulation | All HTTP traffic |
| **mitmproxy** | Transparent proxy for mobile/desktop client traffic | Client-server communication |
| **sqlmap** | SQL injection testing | OCS/REST API parameters |

### 6.3 WebDAV/CalDAV/CardDAV Testing

| Tool | Purpose | Target |
|------|---------|--------|
| **cadaver** | WebDAV CLI client for manual testing | `/remote.php/dav/` |
| **litmus** | WebDAV compliance test suite | WebDAV protocol compliance |
| **curl** | Raw HTTP/WebDAV request crafting | All DAV endpoints |
| **davtest** | WebDAV upload/execute testing | File upload restrictions |

### 6.4 API Testing & Fuzzing

| Tool | Purpose | Target |
|------|---------|--------|
| **Postman/Hoppscotch** | API collection management and testing | OCS, REST, DAV APIs |
| **RESTler** | Stateful REST API fuzzer (Microsoft) | OCS API v2 |
| **Atheris** | Python-based coverage-guided fuzzer | Custom fuzz harnesses |
| **radamsa** | General-purpose mutation fuzzer | File format fuzzing (CalDAV/CardDAV) |

### 6.5 Mobile Application Testing

| Tool | Purpose | Target |
|------|---------|--------|
| **MobSF** | Automated mobile app analysis (SAST + DAST) | Android APK, iOS IPA |
| **Frida** | Dynamic instrumentation framework | Runtime hooking, SSL pinning bypass |
| **objection** | Runtime mobile exploration (built on Frida) | Android/iOS runtime analysis |
| **jadx** | Android APK decompiler | Android client source review |
| **Hopper/Ghidra** | Binary analysis for desktop/iOS | Desktop clients, iOS binary |
| **apktool** | APK decompilation and repackaging | Android client modification |

### 6.6 Desktop Client Testing

| Tool | Purpose | Target |
|------|---------|--------|
| **Ghidra** | Binary reverse engineering | Desktop client binaries (C++/Qt) |
| **Wireshark** | Network traffic analysis | Client-server sync protocol |
| **Process Monitor** | Windows file/registry/process monitoring | Windows desktop client |
| **strace/ltrace** | Linux system call tracing | Linux desktop client |

### 6.7 Authentication & Crypto Testing

| Tool | Purpose | Target |
|------|---------|--------|
| **Hashcat/John** | Password hash analysis | Password storage review |
| **jwt_tool** | JWT token manipulation | Session tokens, API tokens |
| **testssl.sh** | TLS configuration analysis | HTTPS endpoints |
| **CryptoLyzer** | Cryptographic protocol analysis | E2E encryption implementation |

### 6.8 Reconnaissance & Enumeration

| Tool | Purpose | Target |
|------|---------|--------|
| **Nextcloud Security Scan** | Official Nextcloud security scanner | `scan.nextcloud.com` (allowed) |
| **nmap** | Port/service enumeration (our instance only) | Lab environment |
| **nikto** | Web server misconfiguration scanner | Lab environment |
| **wpscan-style enumeration** | User/app enumeration via OCS | Lab environment |

### 6.9 Exploit Development

| Tool | Purpose | Target |
|------|---------|--------|
| **Metasploit** | Exploit framework and payload generation | PoC development |
| **pwntools** | Python exploit development library | Custom exploit scripts |
| **CyberChef** | Data encoding/decoding/analysis | Payload crafting |
| **xsstrike** | XSS detection and bypass | CSP bypass research |

---

## 7. Engagement Phases

### Phase 1: Reconnaissance & Setup (Week 1)

**Objective:** Stand up test environment, clone all 94 in-scope repos, establish baseline.

| Task | Tool | Deliverable |
|------|------|-------------|
| Deploy Nextcloud 33.0.2 + 32.0.8 Docker labs | Docker Compose | Running instances |
| Install all in-scope apps | `occ` CLI | Fully configured test env |
| Clone all 94 GitHub repos | `git clone` | Local source tree |
| Create test user matrix | Nextcloud admin | 7+ test accounts |
| Run Nextcloud Security Scan | scan.nextcloud.com | Baseline security grade |
| Map all API endpoints | ZAP spider + manual | API endpoint inventory |
| Run Trivy/Grype on Docker images | Trivy, Grype | Dependency vuln report |
| Run Snyk on all repos | Snyk CLI | Dependency vuln report |

### Phase 2: Source Code Review (Weeks 2-3)

**Objective:** Identify vulnerabilities through static analysis and manual code review.

| Task | Tool | Focus Area |
|------|------|-----------|
| Run Semgrep OWASP + PHP rules on all repos | Semgrep | SQL injection, XSS, SSRF, path traversal |
| Run Psalm taint analysis on server core | Psalm | User input → dangerous sink flows |
| Manual review: authentication flows | Code review | Session management, token validation, 2FA bypass |
| Manual review: file operations | Code review | Path traversal, symlink attacks, zip slip |
| Manual review: sharing engine | Code review | IDOR, access control bypass, permission escalation |
| Manual review: WebDAV implementation | Code review | XML injection, XXE, PROPFIND abuse |
| Manual review: OCS API endpoints | Code review | Mass assignment, parameter injection |
| Manual review: encryption implementation | Code review | Key management, IV reuse, padding oracle |
| Review recent security advisories for patterns | GitHub advisories | Regression testing, variant analysis |

**Priority repos for manual review:**
1. `nextcloud/server` (core — files, sharing, auth, WebDAV)
2. `nextcloud/spreed` (Talk — WebRTC signaling, chat)
3. `nextcloud/mail` (email rendering, SSRF)
4. `nextcloud/files_external` (external storage, SSRF)
5. `nextcloud/richdocuments` (Collabora bridge)

### Phase 3: Dynamic Testing (Weeks 3-5)

**Objective:** Discover runtime vulnerabilities through active testing against our lab.

| Test Category | Tools | Targets |
|--------------|-------|---------|
| **Authentication bypass** | Burp Suite, ZAP, curl | Login, 2FA, SAML, LDAP, app passwords |
| **Authorization (IDOR)** | Burp Intruder, ffuf | File IDs, share tokens, user IDs, calendar/contact IDs |
| **SQL injection** | sqlmap, manual | OCS search, DAV REPORT, app-specific queries |
| **XSS (stored/reflected)** | XSStrike, Burp, manual | File names, comments, chat messages, calendar events, contact fields |
| **SSRF** | manual, Burp Collaborator | External storage, mail (IMAP/SMTP), avatar URLs, link previews |
| **Path traversal** | ffuf, manual | File download, WebDAV MOVE/COPY, zip extraction |
| **XXE** | manual, Burp | WebDAV PROPFIND/PROPPATCH, CalDAV/CardDAV XML |
| **CSRF** | Burp, manual | State-changing operations, admin functions |
| **File upload abuse** | manual | SVG XSS, polyglot files, .htaccess upload, PHP in images |
| **WebDAV protocol abuse** | cadaver, litmus, curl | LOCK/UNLOCK, PROPFIND depth, COPY/MOVE cross-user |
| **API fuzzing** | RESTler, ffuf, radamsa | OCS v2 endpoints, DAV endpoints |
| **Race conditions** | Burp Turbo Intruder | Share creation/deletion, file locking, quota enforcement |

### Phase 4: Mobile & Desktop Client Testing (Week 5-6)

**Objective:** Test client applications for local and network vulnerabilities.

| Test Category | Tools | Targets |
|--------------|-------|---------|
| **Android SAST** | MobSF, jadx | APK decompilation, hardcoded secrets, insecure storage |
| **Android DAST** | Frida, objection | SSL pinning bypass, runtime manipulation |
| **iOS SAST** | MobSF, Hopper | IPA analysis, keychain storage review |
| **iOS DAST** | Frida, objection | Runtime hooking, data protection class audit |
| **Desktop binary analysis** | Ghidra | Memory corruption, unsafe deserialization |
| **Client-server protocol** | mitmproxy, Wireshark | Sync protocol manipulation, downgrade attacks |
| **Deep link / URL scheme** | manual | Custom URL scheme hijacking, intent injection |

### Phase 5: Advanced Testing (Week 6-7)

**Objective:** Target complex vulnerability classes and chain findings.

| Test Category | Tools | Targets |
|--------------|-------|---------|
| **Variant analysis** | Semgrep custom rules | Find variants of past CVEs in new code |
| **Chained exploits** | manual | Combine low-severity findings into high-impact chains |
| **E2E encryption audit** | CryptoLyzer, manual | Key exchange, metadata leakage, implementation flaws |
| **Federation attacks** | manual, 2nd instance | Federated sharing protocol manipulation |
| **Upgrade path testing** | Docker | Vulnerabilities during version upgrade process |
| **App interaction bugs** | manual | Cross-app data leakage, conflicting permissions |

### Phase 6: Reporting & Submission (Week 7-8)

**Objective:** Document findings, create PoCs, submit to HackerOne.

| Task | Tool | Deliverable |
|------|------|-------------|
| Write detailed reproduction steps | Markdown | Step-by-step with screenshots |
| Create PoC scripts | Python/PHP | Automated reproduction |
| Verify on both NC 33 and NC 32 | Lab instances | Version-specific impact notes |
| Redact all PII and secrets | Manual review | Clean report materials |
| Submit via HackerOne | H1 platform | Individual reports per finding |
| Track response and provide clarification | H1 platform | Ongoing communication |

---

## 8. Vulnerability Pattern Playbook

Based on analysis of Nextcloud's historical security advisories, these are the most productive vulnerability classes:

### 8.1 High-Yield Patterns

**1. Access Control Bypass in Sharing**
- Test: Create shares with various permission levels, attempt to exceed permissions via direct API calls
- Focus: `files_sharing`, `groupfolders`, `circles`
- Historical: Multiple IDOR and permission bypass CVEs

**2. Server-Side Request Forgery (SSRF)**
- Test: External storage URLs, mail server connections, avatar/preview URLs, link previews in Talk
- Focus: `files_external`, `mail`, `spreed`, `server` core
- Historical: SSRF via external storage and mail app

**3. Stored XSS with CSP Bypass**
- Test: File names, comments, chat messages, calendar event descriptions, contact vCard fields
- Focus: All apps that render user content
- Historical: Multiple stored XSS in various apps, CSP bypass techniques

**4. Path Traversal / Directory Traversal**
- Test: WebDAV MOVE/COPY operations, zip file extraction, file download paths
- Focus: `server` core file operations, `files_external`
- Historical: Path traversal in file operations (recent Windfall CVE)

**5. SQL Injection**
- Test: Search queries, DAV REPORT filters, app-specific database queries
- Focus: OCS API search, CalDAV/CardDAV queries
- Historical: SQL injection in search and filtering

**6. XML External Entity (XXE)**
- Test: WebDAV PROPFIND/PROPPATCH, CalDAV/CardDAV XML bodies, SVG uploads
- Focus: All XML-processing endpoints
- Historical: XXE in DAV operations

### 8.2 Emerging Patterns

**7. Race Conditions**
- Test: Concurrent share creation/deletion, simultaneous file operations, quota enforcement
- Focus: Any state-changing operation without proper locking

**8. Deserialization**
- Test: Session data, cache entries, inter-app communication
- Focus: PHP `unserialize()` usage in server core

**9. WebSocket/WebRTC Attacks**
- Test: Talk signaling server, real-time collaboration
- Focus: `spreed`, `text` (collaborative editing)

---

## 9. AC3 Integration Plan

### 9.1 Engagement Record

Create a new engagement in AC3 with:
- **Target:** nextcloud.com (program reference)
- **Type:** Bug Bounty
- **Platform:** HackerOne
- **Status:** Active
- **Scope:** 94 assets (imported from H1 CSV)

### 9.2 DI Scans to Run

| Scan Target | Purpose |
|-------------|---------|
| `nextcloud.com` | Full DI scan — org profile, threat actors, affiliated domains |
| `github.com/nextcloud` | GitHub org reconnaissance |
| Key developer domains | Developer OSINT for social engineering context |

### 9.3 Threat Catalog Integration

- Import Nextcloud-specific threat actors from incident search
- Map known CVEs to MITRE ATT&CK TTPs
- Build Caldera adversary profiles based on historical attack patterns

### 9.4 Scan Configurations

Pre-configure AC3 scan templates for:
1. **Nextcloud Server Passive Recon** — DNS, CT logs, subdomain enumeration
2. **Nextcloud Source Code Audit** — Semgrep rules, dependency scanning
3. **Nextcloud API Security** — OCS/DAV endpoint testing checklist
4. **Nextcloud Client Security** — Mobile/desktop app analysis checklist

---

## 10. Test Environment Build Script

```bash
#!/bin/bash
# AC3 Nextcloud Bug Bounty Lab Setup
# Run on a dedicated test server (recommended: 8GB RAM, 4 CPU, 100GB SSD)

set -e

echo "=== AC3 Nextcloud Bug Bounty Lab Setup ==="

# 1. Create project directory
mkdir -p ~/nc-bounty-lab && cd ~/nc-bounty-lab

# 2. Clone all in-scope repos
echo "[*] Cloning in-scope repositories..."
REPOS=(
  "server" "android" "ios" "desktop"
  "calendar" "contacts" "deck" "mail" "spreed"
  "text" "richdocuments" "files_external" "files_antivirus"
  "encryption" "end_to_end_encryption" "user_ldap" "user_saml"
  "twofactor_totp" "twofactor_webauthn" "notifications" "activity"
  "files_sharing" "groupfolders" "circles" "photos" "maps"
  "forms" "polls" "collectives" "news" "notes" "bookmarks"
  "tasks" "passwords" "viewer" "files_pdfviewer"
  "files_rightclick" "files_videoplayer" "firstrunwizard"
  "logreader" "nextcloud_announcements" "password_policy"
  "privacy" "recommendations" "related_resources"
  "serverinfo" "sharebymail" "support" "survey_client"
  "suspicious_login" "theming" "updatenotification"
  "weather_status" "files_trashbin" "files_versions"
  "files_downloadlimit" "files_lock" "files_reminders"
  "files_accesscontrol" "files_automatedtagging"
  "files_retention" "lookup_server_connector"
  "user_status" "dashboard" "federation"
  "oauth2" "provisioning_api" "settings"
  "workflowengine" "flow" "integration_discourse"
  "integration_github" "integration_gitlab" "integration_google"
  "integration_mastodon" "integration_openproject"
  "integration_reddit" "integration_twitter"
)

for repo in "${REPOS[@]}"; do
  if [ ! -d "$repo" ]; then
    git clone --depth 1 "https://github.com/nextcloud/${repo}.git" 2>/dev/null || echo "  [!] Could not clone: $repo"
  fi
done

# 3. Install security tools
echo "[*] Installing security tools..."
# Semgrep
pip3 install semgrep

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ffuf
go install github.com/ffuf/ffuf/v2@latest

# sqlmap
pip3 install sqlmap

# MobSF
docker pull opensecurity/mobile-security-framework-mobsf:latest

# OWASP ZAP
docker pull ghcr.io/zaproxy/zaproxy:stable

# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Frida
pip3 install frida-tools

# jwt_tool
pip3 install jwt_tool

# testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git tools/testssl

# xsstrike
git clone https://github.com/s0md3v/XSStrike.git tools/xsstrike

# davtest
apt-get install -y davtest

# cadaver
apt-get install -y cadaver

echo "[*] Setup complete! Start the lab with: docker compose up -d"
```

---

## 11. Report Template

Every HackerOne submission must follow this structure:

```markdown
## Summary
[One sentence describing the vulnerability]

## Nextcloud Version
- Server: 33.0.2
- App: [app_name] v[version]
- Tested on: Self-hosted Docker instance

## Vulnerability Type
[e.g., IDOR, Stored XSS, SSRF, Path Traversal]

## Steps to Reproduce
1. Log in as user1
2. Navigate to [specific URL]
3. [Specific action with exact parameters]
4. Observe [specific outcome]

## Impact
[What an attacker can achieve — data access, privilege escalation, etc.]

## Proof of Concept
[Screenshots showing each step]
[Curl commands or scripts for reproduction]

## Suggested Fix
[Optional but appreciated — specific code change recommendation]
```

---

## 12. Success Metrics

| Metric | Target |
|--------|--------|
| Valid reports submitted | 10+ |
| Critical/High findings | 2+ |
| Total bounty earned | $5,000+ |
| Reports accepted (not N/A or Informative) | >70% |
| Average response time from Nextcloud | <48 hours |

---

## 13. Timeline

| Week | Phase | Focus |
|------|-------|-------|
| 1 | Setup | Deploy labs, clone repos, install tools |
| 2-3 | SAST | Source code review, static analysis |
| 3-5 | DAST | Dynamic testing against lab instances |
| 5-6 | Clients | Mobile and desktop client testing |
| 6-7 | Advanced | Variant analysis, exploit chaining |
| 7-8 | Reporting | Document findings, submit to H1 |
| Ongoing | Monitoring | Track new releases, re-test on updates |
