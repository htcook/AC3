# Broken Crystals Pentest Review — Engagement #1800033

**Date:** April 12, 2026  
**Target:** brokencrystals.lab.aceofcloud.io (159.223.152.190)  
**Engagement:** Broken Crystals Full Pipeline v2  
**Mode:** strict_passive → standard (auto-escalated)  
**Duration:** 80 minutes  
**Status:** completed

---

## Executive Summary

The engagement completed its full pipeline but produced **underwhelming exploitation results** despite finding 97 verified vulnerabilities (3 critical, 8 high). The exploitation phase attempted only 2 exploits — both failed — and opened zero sessions. Several systemic issues in the vuln-to-exploit pipeline prevented the platform from capitalizing on confirmed, exploitable findings.

---

## §1 — Vulnerability Results Audit

### What Worked

| Scanner | Findings | Notes |
|---------|----------|-------|
| Nuclei | 15 | Found the critical .env exposure (CVE-2017-16894), config.json, .git, .svn |
| ZAP | 20 (deduplicated to engagement_findings) | SQL injection on :8443, Vulnerable JS Library, CSP issues |
| Nikto | 48 | Mostly informational headers/banners, 1 low finding |
| Gobuster | 4 | Found /experiments/configurations (401) |
| RustScan | 5 | 7 open ports discovered: 22, 80, 443, 1337, 4000, 8090, 8443 |
| httpx | 5 | Service fingerprinting |
| Burp | **0** | Completed scan, 0 issues imported (see Issue #1) |

### What's Missing

**Broken Crystals is a deliberately vulnerable Node.js/Express application** with well-documented vulnerabilities including XSS (reflected + stored), IDOR, JWT manipulation, OS command injection, XML external entity (XXE), SSRF, path traversal, and more. The scan pipeline missed most of these because:

1. **ZAP scanned :8443 (Nextcloud) not the actual Broken Crystals app on :80 or :1337.** The SQL injection findings are all against `oc_sessionPassphrase` on the Nextcloud instance at port 8443 — not the Broken Crystals application. These are likely false positives (Nextcloud returns 500 on malformed cookies, not actual SQL injection).

2. **The Broken Crystals app runs on port 1337** (the Node.js API) with a frontend on port 80 (nginx reverse proxy). The nuclei scans targeted port 80 and found .env/.git/.svn exposure, but the ZAP active scan never crawled the actual application endpoints (`/api/`, `/api/products`, `/api/auth`, etc.).

3. **No authenticated scanning was performed** (`auth_configured: 0` on all ZAP scans). Broken Crystals has an auth system — without credentials, the scanner can't reach authenticated-only endpoints where many vulns live.

---

## §2 — Exploitation Results Audit

### Exploit Attempt #1: EDB-52338 (Ingress-NGINX RCE)

| Stage | Result |
|-------|--------|
| MSF Direct | "No output" — module check did not confirm vulnerability |
| Nuclei Fallback | Tags `cve,rce,critical` — no matches |
| LLM Fallback | Generated Python exploit (2769 chars, popsShell=true) |
| Quality Score | 70/100 (warn) |
| Pipeline Result | **FAILED** |
| Error | `Cannot read properties of undefined (reading 'length')` |
| Root Cause | **Wrong CVE.** EDB-52338 is an Ingress-NGINX controller RCE — this target runs Apache/nginx as a reverse proxy, not Ingress-NGINX. The exploit selection was a false match. |

### Exploit Attempt #2: CVE-2017-16894 (.env exposure)

| Stage | Result |
|-------|--------|
| Nuclei Re-Verification | "No matching vulnerabilities" (contradicts the original finding) |
| Confidence | Reduced by 10 |
| Retry | Skipped — "No strategy adjustments available" |
| Root Cause | **Not an exploitable CVE in the traditional sense.** CVE-2017-16894 is an information disclosure (exposed .env file). The pipeline tried to "exploit" it as if it were an RCE, but the correct action would be to **read the .env contents** and use the leaked credentials/secrets for lateral movement. The pipeline doesn't have a "credential harvesting" exploit strategy. |

### Why Zero Sessions

The pipeline's exploit selection algorithm matched against CVEs in the nuclei findings, but:

1. **Only 1 CVE was present** (CVE-2017-16894) — the rest had `cve: N/A`
2. The Ingress-NGINX exploit was a **false match** from the exploit intelligence catalog
3. The pipeline has no strategy for **chaining information disclosure → credential theft → auth bypass**
4. The `exhaustiveExploit: true` flag was set, meaning the pipeline tried everything it could — but "everything" was limited to 2 candidates

---

## §3 — Specific Issues Found

### Issue #1: Burp Suite Returned 0 Issues

**Observation:** Burp Professional scan completed (scan_id: 42, progress: 100%) in ~16 seconds against `https://brokencrystals.lab.aceofcloud.io` but found 0 issues and imported 0.

**Probable Cause:** A 16-second Burp scan is suspiciously fast for a full crawl+audit. This suggests either:
- The scan was blocked by the reverse proxy / WAF (ModSecurity detected with 30% confidence)
- The scan target resolved to the nginx landing page only, not the actual application
- The Burp scan configuration was minimal (no crawl depth, no active scan)

**Recommendation:** Verify Burp is targeting the correct port/path. Consider adding `http://brokencrystals.lab.aceofcloud.io:1337` as a target URL. Check if the scan used authentication.

### Issue #2: ZAP Scanned the Wrong Application

**Observation:** ZAP's high-severity findings (SQL Injection) are all against port 8443, which is a **Nextcloud** instance (identified by `oc_sessionPassphrase` cookie, `/apps/theming/` paths, Nextcloud JS frameworks). The actual Broken Crystals app was not actively scanned.

**Evidence:**
- Target profile fingerprint: `jsFrameworks: ["Nextcloud"]`, `serverHeader: "Apache/2.4.62 (Debian)"`
- SQL injection attack vector: `param: oc_sessionPassphrase, attack: ;` — this is a Nextcloud session cookie
- All SQL injection URLs are on `:8443/apps/theming/*` and `:8443/core/*`

**Impact:** The real Broken Crystals vulnerabilities (XSS, IDOR, JWT bypass, command injection, XXE, SSRF) were never tested by ZAP's active scanner.

**Recommendation:** The pipeline should identify the primary application per port and prioritize scanning the target application (port 80/1337) over co-hosted services (Nextcloud on 8443).

### Issue #3: Nuclei Found Real Vulns But Pipeline Couldn't Exploit Them

**Observation:** Nuclei correctly identified:
- Exposed `.env` file (CVE-2017-16894) — **CRITICAL**
- Exposed `config.json` — **CRITICAL**
- `.git/config` exposure — **MEDIUM**
- `.svn/wc.db` exposure — **MEDIUM**

These are all **information disclosure** vulnerabilities that should feed into a credential harvesting / lateral movement phase, not a direct exploitation phase.

**Recommendation:** Add an "information harvesting" exploit strategy that:
1. Downloads the exposed .env file and extracts credentials
2. Downloads .git/config and attempts `git clone` for source code access
3. Downloads config.json and extracts API keys, database URIs
4. Feeds harvested credentials into the credential testing phase

### Issue #4: Missing Vulnerability Classes for Broken Crystals

**Expected vulnerabilities not found:**

| Vuln Class | Expected | Found | Gap |
|-----------|----------|-------|-----|
| XSS (Reflected) | Yes — `/api/products?q=<script>` | No | ZAP didn't crawl API |
| XSS (Stored) | Yes — product reviews | No | No auth scanning |
| IDOR | Yes — `/api/users/:id` | No | No auth scanning |
| JWT Manipulation | Yes — weak secret, algorithm confusion | No | No auth scanning |
| OS Command Injection | Yes — `/api/spawn` | No | ZAP didn't crawl API |
| XXE | Yes — XML upload endpoint | No | ZAP didn't crawl API |
| SSRF | Yes — `/api/render?url=` | No | ZAP didn't crawl API |
| Path Traversal | Yes — file download endpoint | No | ZAP didn't crawl API |
| SQL Injection | Yes — `/api/products` | No (found FP on Nextcloud) | ZAP scanned wrong app |
| Open Redirect | Yes — login redirect | No | ZAP didn't crawl API |

### Issue #5: ScanForge Produced Zero Findings

**Observation:** The `_scanforgeResult` shows 37 templates executed against 1 target with 0 findings. This suggests the ScanForge templates didn't match the Broken Crystals attack surface.

### Issue #6: No Domain Intel Scan

**Observation:** No domain_intel_scans record exists for engagement #1800033. The `passiveDiscovery` data shows empty results for breach exposure, certificates, subdomains, and technologies. This is expected for a lab domain but means the pipeline had no OSINT context to work with.

### Issue #7: Coverage Scores Are Low

**Observation:** Final coverage scores:
- Recon: 46/100
- Exploit: 45/100
- Evasion: 90/100
- Cognitive: 49/100
- Cloud: 0/100
- Supply Chain: 0/100

The exploit score of 45/100 reflects the failed exploitation attempts. The recon score of 46/100 reflects the incomplete application crawling.

---

## §4 — Root Cause Summary

The fundamental issue is a **target identification and routing problem**. The scan server hosts multiple applications on different ports:

| Port | Service | Application |
|------|---------|-------------|
| 22 | SSH | OpenSSH |
| 80 | HTTP | Nginx reverse proxy → Broken Crystals frontend |
| 443 | HTTPS | Nginx reverse proxy → Broken Crystals frontend |
| 1337 | HTTP | Broken Crystals Node.js API (the actual vulnerable app) |
| 4000 | HTTP | Unknown service |
| 8090 | HTTP | Unknown service |
| 8443 | HTTPS | Nextcloud instance |

The pipeline correctly discovered all 7 ports but then:
1. Nuclei scanned port 80 (correct — found .env/.git/.svn via the reverse proxy)
2. ZAP scanned ports 80, 443, and **8443** — spending most effort on Nextcloud
3. ZAP **never scanned port 1337** (the actual API with all the vulns)
4. Burp scanned only HTTPS (443) and found nothing
5. The exploit phase only had nuclei findings (info disclosure) to work with

---

## §5 — Recommendations

### Immediate Fixes

1. **Add port 1337 to ZAP scan targets.** The pipeline should scan all HTTP(S) ports discovered by RustScan, not just 80/443/8443.

2. **Implement application fingerprinting before ZAP scanning.** Detect that :8443 is Nextcloud (not the target app) and deprioritize it, or at least flag findings as "co-hosted service" rather than "target application."

3. **Add credential harvesting exploit strategy.** When nuclei finds exposed .env/config files, the pipeline should download and parse them before moving to exploitation.

4. **Enable authenticated ZAP scanning.** Broken Crystals has default credentials — the pipeline should attempt to discover and use them.

### Pipeline Improvements

5. **Improve exploit matching.** EDB-52338 (Ingress-NGINX RCE) should never have been matched to an Apache/nginx reverse proxy. The exploit selector needs to validate that the target technology stack matches the exploit prerequisites.

6. **Add API endpoint discovery.** Use katana/gospider with JavaScript rendering to discover API endpoints, then feed them to ZAP for active scanning.

7. **Fix the `Cannot read properties of undefined (reading 'length')` error** in the exploit execution pipeline — this is a code bug that caused the first exploit attempt to crash.

8. **Increase Burp scan timeout / verify Burp connectivity.** A 16-second scan that finds 0 issues suggests the scan didn't actually crawl the application.

---

## §6 — Data Integrity Notes

- **Duplicate findings:** Several nuclei findings appear twice (with and without `[Nuclei]` prefix) — the dedup layer should normalize these
- **ZAP finding duplication:** ZAP findings appear at both their original severity AND as `info` duplicates (20 findings = 10 unique + 10 info copies)
- **Port field is NULL** on all engagement_findings — the `port` column is not being populated from the scan results
- **OWASP categories are empty** on all findings — the OWASP mapping is not running
- **MITRE techniques are empty** on all findings — the MITRE mapping is not running

---

*Report generated from engagement_ops_snapshots, engagement_findings, exploitation_attempts, scan_results, web_app_scans, web_app_findings, and burp_scan_history tables.*
