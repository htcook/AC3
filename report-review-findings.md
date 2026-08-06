# DI Report Review Findings — risk.lexisnexis.com

## Page 1 — Cover
- Title: "Domain Intelligence Report"
- Subtitle: "risk.lexisnexis.com" (raw domain name, looks messy)
- Overall Risk Assessment: 28/100 LOW (green)
- Total Assets Discovered: 871, Confirmed Findings: 111, Data Sources: 18, Scan Duration: 166.3s
- Scan Date: 4/7/2026, Scan Mode: standard, Sector: Technology, Client Type: enterprise

## Page 2 — Table of Contents
- 12 sections, looks fine

## Page 3 — Executive Summary
**ISSUES FOUND:**
1. **Starts with raw domain name** — "risk.lexisnexis.com presents a LOW risk posture (28/100)..." — unprofessional, should start with organizational context
2. **Dense wall of text** — single paragraph with all metrics crammed in, hard to parse
3. **Risk Score 28/100 LOW but 72 CISA KEV matches and 54 public exploits** — this is contradictory. 72 CISA KEV matches should significantly elevate the risk score
4. **Peak Asset Risk is 45 (MEDIUM)** — but with critical vulns present, this seems too low
5. **"No probable findings were used to form conclusions on risk"** — this is good disclaimer but doesn't explain why critical vulns don't affect the score
6. Organization Profile shows "Organization: risk.lexisnexis.com" — should show "LexisNexis Risk Solutions" (the actual org name from the web crawl)
7. Business Intelligence section is good — correctly identifies LexisNexis Risk Solutions

## Pages 4-8 — Attack Surface Inventory
- Asset Distribution: 827 Web Applications (95.3%), 41 Services (4.7%) — looks correct
- Risk Distribution: 3 MEDIUM (0.3%), 865 LOW (99.7%) — **NOTE: No HIGH or CRITICAL assets listed despite critical vulns existing**
- Discovered Subdomains table: Hostname, IP, Type, Risk, Band, Hosting, Technologies
- Many assets show "—" for IP, Hosting, Technologies — this is expected for cert-discovered subdomains
- Top 3 MEDIUM risk: risk.lexisnexis.com (45), preview.risk.lexisnexis.com (41), contractorservices.risk.lex... (41)
- Hundreds of LOW risk assets at score 9 with no IP/hosting/tech data — these are cert-discovered subdomains

## KEY ISSUES IDENTIFIED SO FAR:
1. Risk score doesn't properly weight CISA KEV matches (72!) and public exploits (54)
2. Executive summary is unprofessional — starts with domain, single dense paragraph
3. Organization name should be "LexisNexis Risk Solutions" not "risk.lexisnexis.com"
4. No HIGH or CRITICAL risk band in asset distribution despite critical vulns
5. Need to check vulnerability section (pages 26+) for the critical severity vulns

## Page 24 — Domain Health & Blacklist Status
- Overall Domain Health: B (77) — looks correct
- DNS, Email Security, Blacklist tables all look good
- Listed on 1 blacklist: cbl.anti-spam.org.cn (MEDIUM severity) with false positive analysis
- DNS Security: Zone Transfer Blocked, Open Recursion Disabled — good

## Page 25 — SSL Certificate Health
- 15 discovered certificates, all show "Invalid Date" for Expires — **ISSUE: All certificates show "Invalid Date"**
- This could be a parsing issue in the report generator

## Page 26 — Breach & Credential Exposure
- **CRITICAL ISSUE: Shows counts but NO actual credential pairs**
  - Total Exposures: 428, Unique Emails: 421, Breach Sources: 12
  - Passwords Exposed: 34, Hashed Passwords: 4, Credential Pairs: 34
- Breach Sources listed (12): DemandScience, emunicipio.com.br (Cit0day), MGM Grand Hotels, Apollo, MyFitnessPal, Collections, Exploit.in, Adobe, Nitro PDF, EPA.gov, Under Armour, Covve
- **MISSING: Actual email:password pairs table — user wants to see the credentials**
- **MISSING: Which breach each credential came from**
- Dark Web: No dark web mentions detected

## Page 26 (bottom) — Vulnerability & Technology Landscape
- Technology Stack table looks correct
- 43 Confirmed Vulnerabilities

## Page 27 — Top 20 Critical Findings
**CRITICAL SEVERITY VULNS (all marked KEV):**
1. CVE-2021-42013 — Apache HTTP Server Path Traversal [RANSOMWARE] — Sev: Critical, Ver: 10.0
2. CVE-2021-41773 — Apache HTTP Server Path Traversal [RANSOMWARE] — Sev: Critical, Ver: 10.0
3. CVE-2021-42321 — Microsoft Exchange Server RCE [RANSOMWARE] — Sev: Critical
4. CVE-2017-11357 — Telerik UI AJAX Insecure Direct Object Reference — Sev: Critical, CVSS: 9.8
5. CVE-2019-18935 — Progress Telerik UI AJAX Deserialization — Sev: Critical
6. CVE-2024-38475 — Apache HTTP Server Improper Escaping — Sev: Critical
7. CVE-2019-0211 — Apache HTTP Server Privilege Escalation — Sev: Critical

## Page 28 — More Critical + High Findings
8. CVE-2017-11317 — Telerik UI AJAX Unrestricted File Upload — Sev: Critical, KEV
9. CVE-2017-9248 — Telerik UI AJAX Cryptographic Weakness — Sev: Critical, KEV

**HIGH SEVERITY VULNS (Shodan-detected, all on wcostarslms-pr.risk.lexisnexis.com):**
- CVE-2025-62401, CVE-2025-67847, CVE-2025-62397, CVE-2025-62396, CVE-2025-62393, CVE-2025-62400, CVE-2025-62399, CVE-2025-62398, CVE-2025-67848
- All detected on Microsoft IIS httpd 10.0 (69.84.186.46:443)
- All have "Public exploit available"

## KEY SCORING ISSUE:
**9 Critical severity CVEs (many with RANSOMWARE tag and KEV listing) + 9+ High severity CVEs = Risk score should NOT be 28/LOW**
The risk score is clearly not properly weighting:
1. Critical severity vulnerabilities (should add massive penalty)
2. CISA KEV matches (72 total — these are ACTIVELY EXPLOITED)
3. Public exploit availability (54 matched)
4. RANSOMWARE-tagged vulnerabilities (3 CVEs)

## Page 29 — More High + Additional Confirmed Findings
- CVE-2025-67849, CVE-2007-3205 — both High on wcostarslms-pr.risk.lexisnexis.com
- Additional Confirmed Findings table (23 CVEs):
  - High severity: CVE-2024-3566, CVE-2026-26046, CVE-2026-26047, CVE-2026-26045, CVE-2013-2220, CVE-2025-67855, CVE-2025-67857, CVE-2025-67856, CVE-2025-67851, CVE-2025-67850, CVE-2025-67853, CVE-2025-67852, CVE-2007-6538, CVE-2025-62394, CVE-2010-4208, CVE-2025-62395, CVE-2010-4207
  - Medium severity: CVE-2019-16278, CVE-2026-20963, CVE-2008-0015, CVE-2024-43468, CVE-2026-21513, CVE-2026-21525
  - **ISSUE: Medium CVEs show KEV=Yes and Assets=31 — this seems wrong. 31 assets affected by a single medium CVE?**
- 57 Potential Findings mentioned (product family matches, need verification)

## Page 30 — Provider-Managed Infrastructure + Exploit Availability
- Provider-Managed: outlook.com and cloudflare.com excluded (Microsoft 365) — correct
- **MAJOR TABLE ISSUE: Public Exploit Availability table**
  - 54 public exploits listed BUT:
  - Source: ALL show "Unknown"
  - Module/ID: ALL show "N/A"
  - Technology: ALL show "N/A"
  - Remote Access: ALL show "No"
  - Only Severity numbers vary (10, 9, 8, 5)
  - **This table is useless — no actual exploit data, just severity numbers**
  - The header says "12 Metasploit modules, 25 ExploitDB entries, 17 Caldera abilities" but the table doesn't show any of this

## Page 31 — Compliance & Container Exposure + Cross-Module Intelligence
- Compliance Score: 75%, Benchmark: CIS + DISA STIG + NIST 800-53
- 16 checks: 12 passed, 4 failed
- Failed checks: CSP (medium), DNSSEC (medium), CAA DNS Records (low), Secure Cookie Attributes (medium)
- Cross-Module: 4/4 enrichment modules completed, 0 correlations, 0 new findings
- Infrastructure Insights: Cloud (Cloudflare), WAF/CDN on 3 assets

## Page 32 — Prioritized Recommendations + Attack Chains
- P1-P4 recommendations — looks good and actionable
- 3 Attack Chains identified:
  1. Apache HTTP Server Path Traversal to RCE
  2. Telerik UI AJAX Deserialization to RCE
  3. Microsoft Exchange Server RCE (ransomware vector)
- **These attack chains confirm CRITICAL risk but score is still 28/LOW**

## Page 33 — Appendix: Data Sources & Methodology
- 18 data sources queried, top producers: Shodan (911), Censys (293), Dehashed (270)
- Several connectors errored: reverse_whois, github_recon, greynoise, virustotal, hibp, whoisxml, leakix, fullhunt, netlas, hunter, passivetotal, intelx_search, hudson_rock, leakcheck
- Many show "Skipped: No API key configured"
- **ISSUE: Error connectors with 0 observations still listed — could be cleaned up**

## COMPLETE LIST OF ISSUES TO FIX:

### Critical Issues:
1. **Risk Score 28/LOW despite 9 Critical CVEs, 72 CISA KEV matches, 3 RANSOMWARE-tagged vulns** — scoring doesn't weight critical vulns
2. **Breach section shows counts but NO actual credential pairs (email:password)** — user explicitly wants these
3. **No breach source per credential** — user wants to know which breach each credential came from
4. **Exploit Availability table is completely empty** — all Source=Unknown, Module=N/A, Technology=N/A

### Formatting Issues:
5. **Executive Summary starts with raw domain name** — unprofessional, should use NIST-style format
6. **Executive Summary is a dense single paragraph** — needs structured sections
7. **Organization name shows "risk.lexisnexis.com" instead of "LexisNexis Risk Solutions"**

### Data Issues:
8. **SSL Certificate Expires column shows "Invalid Date" for all 15 certs**
9. **Medium CVEs showing 31 affected assets seems inflated** (CVE-2026-20963 etc.)
10. **No HIGH or CRITICAL risk band in Asset Distribution** despite critical vulns existing
11. **Appendix shows error connectors with 0 observations** — could filter or flag better
