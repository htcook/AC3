# Caldera LLM Knowledge Stack — Test Results

**Date:** March 6, 2026
**Test Targets:** testphp.vulnweb.com, demo.testfire.net, scanme.nmap.org, testasp.vulnweb.com
**Knowledge Modules Tested:** Nmap Evasion & NSE Scripts, Cloud Security, KEV Awareness, Bug Bounty Triage, CARVER Scoring

---

## Overall Results

| Test | Score | Grade | Status |
|------|------:|:-----:|:------:|
| Scan Plan Generation | 82.0/100 | B+ | PASS |
| Vulnerability Correlation | 94.3/100 | A | PASS |
| Hunt Hypothesis Generation | 100.0/100 | A+ | PASS |
| Asset Classification (CARVER) | 87.5/100 | A- | PASS |
| **Overall** | **363.8/400 (91%)** | **A** | **PASS** |

---

## Test 1: Scan Plan Generation (82/100)

This test evaluates whether the LLM can analyze target recon data, detect technologies, select appropriate nmap flags and NSE scripts, and choose the right additional tools — all while respecting cloud vs. on-premise evasion rules.

### Per-Target Breakdown

| Target | Tech Detection | Evasion | NSE Scripts | Tool Selection | Cloud Awareness | Total |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|
| testphp.vulnweb.com (AWS) | 5/5 | 5/5 | 5/5 | 2/5 | 1/5 | 18/25 |
| demo.testfire.net (on-prem) | 5/5 | 5/5 | 5/5 | 3/5 | 5/5 | 23/25 |
| scanme.nmap.org (on-prem) | 5/5 | 5/5 | 5/5 | 3/5 | 5/5 | 23/25 |
| testasp.vulnweb.com (AWS) | 5/5 | 5/5 | 5/5 | 2/5 | 1/5 | 18/25 |

### Key Findings

**Technology Detection (20/20 — Perfect)**
The LLM correctly identified all technologies from HTTP headers and recon data across all 4 targets: PHP 5.6, nginx, MySQL, Ubuntu, Apache Tomcat, Java, JSP, IIS 10.0, ASP.NET, MSSQL, Windows Server, OpenSSH 6.6.1, and Apache 2.4.7.

**Evasion Profile Selection (20/20 — Perfect)**
The LLM correctly applied the evasion rules:
- **Cloud targets (AWS):** Used `-Pn -sV -sC` only — no fragmentation (`-f`), no decoys (`-D`), no source port spoofing (`--source-port`), no data length padding (`--data-length`). This is correct because cloud firewalls (AWS Security Groups, Azure NSGs) drop fragmented and decoy packets.
- **On-premise targets:** Used full evasion stack: `-f -D RND:3 --source-port 53 -T2`. Source port 53 (DNS) is the most effective single evasion flag because most firewalls allow DNS traffic.

**NSE Script Selection (20/20 — Perfect)**
The LLM selected the correct tech-specific NSE scripts for each target:
- **testphp.vulnweb.com:** `http-vuln-cve2012-1823`, `http-phpself-xss`, `http-sql-injection`, `http-enum`, `http-phpmyadmin-dir-traversal`
- **demo.testfire.net:** `http-vuln-cve2017-5638`, `http-default-accounts`, `http-enum`
- **scanme.nmap.org:** `ssh2-enum-algos`, `ssh-auth-methods`, `http-enum`
- **testasp.vulnweb.com:** `http-aspnet-debug`, `http-iis-webdav-vuln`, `http-vuln-cve2015-1635`

**Tool Selection (10/20 — Needs Improvement)**
The LLM selected nuclei and nikto for all targets (good baseline), and sqlmap for the PHP target with confirmed SQL injection (excellent). However, it did not select cloud-specific tools (`cloud_enum`, `s3scanner`) for AWS-hosted targets. It also suggested `burpsuite_pro` for demo.testfire.net, which is not available in our automated tool set.

**Cloud Awareness (12/20 — Needs Improvement)**
The LLM mentioned "Cloud (AWS): No evasion flags allowed" in the evasion profile (correct), but did not proactively suggest IMDS checks, S3 bucket enumeration, or cloud_enum for AWS targets. The cloud security knowledge module is injected but the LLM needs stronger prompting to translate cloud awareness into tool selection.

---

## Test 2: Vulnerability Correlation (94.3/100)

This test evaluates whether the LLM can correctly triage simulated NSE scan findings, assign accurate CVSS scores, identify KEV matches, and flag false positives.

### Scoring Breakdown

| Dimension | Score | Max | Notes |
|-----------|------:|----:|-------|
| Severity Accuracy | 34.3 | 40 | 12/14 findings correctly rated |
| KEV Detection | 30.0 | 30 | Perfect — flagged CVE-2017-5638 and CVE-2015-1635 |
| False Positive Detection | 30.0 | 30 | Perfect — flagged http-slowloris-check and http-sql-injection |

### Key Findings

**KEV Detection (30/30 — Perfect)**
The LLM correctly identified both CISA KEV entries:
- **CVE-2017-5638** (Apache Struts RCE) on demo.testfire.net → rated CRITICAL (CVSS 9.8), flagged as KEV
- **CVE-2015-1635** (HTTP.sys RCE) on testasp.vulnweb.com → rated CRITICAL (CVSS 9.8), flagged as KEV

**False Positive Detection (30/30 — Perfect)**
The LLM correctly flagged 2 false positives:
- `http-slowloris-check` on scanme.nmap.org → marked as FP (Slowloris DoS is unreliable in automated scans)
- `http-sql-injection` on testphp.vulnweb.com → marked as FP (nmap's SQL injection detection has high false positive rate; needs manual verification with sqlmap)

**Severity Accuracy (34.3/40 — Strong)**
12 of 14 findings were correctly rated. The 2 mismatches:
- `http-enum` (phpMyAdmin found) rated LOW (CVSS 0) instead of MEDIUM — phpMyAdmin exposure is a real finding
- `ssl-enum-ciphers` (TLS 1.0) rated HIGH (CVSS 5.9) — borderline, could be MEDIUM depending on context

---

## Test 3: Hunt Hypothesis Generation (100/100)

This test evaluates whether the LLM can generate actionable threat hunting hypotheses with MITRE ATT&CK mapping and Splunk/SIEM queries based on scan findings.

### Hypotheses Generated

| Priority | MITRE | Target | Hypothesis |
|:---:|:---:|:---:|:---|
| P1 | T1190 | demo.testfire.net | Struts RCE exploitation (CVE-2017-5638) |
| P1 | T1190 | testasp.vulnweb.com | HTTP.sys RCE exploitation (CVE-2015-1635) |
| P2 | T1190 | testphp.vulnweb.com | SQL injection in /search.php |
| P2 | T1213 | testphp.vulnweb.com | .git repository data exfiltration |
| P2 | T1078 | demo.testfire.net | Default Tomcat credentials brute-force |
| P3 | T1021 | scanme.nmap.org | Weak SSH algorithms exploitation |

### Scoring Breakdown

| Dimension | Score | Max | Notes |
|-----------|------:|----:|-------|
| MITRE Mapping | 35.0 | 35 | All 6 hypotheses correctly mapped to MITRE techniques |
| Query Quality | 35.0 | 35 | All Splunk queries are syntactically valid and actionable |
| Attack Paths | 30.0 | 30 | Correct prioritization: KEV vulns P1, confirmed vulns P2, potential P3 |

**Notable Quality Indicators:**
- Every hypothesis includes a Splunk query with correct field names (`uri_path`, `http_method`, `http_status`, `src_ip`)
- KEV vulnerabilities are correctly prioritized as P1
- The .git exposure hypothesis correctly maps to T1213 (Data from Information Repositories)
- The SSH hypothesis correctly identifies the specific OpenSSH version (6.6.1) as the risk factor

---

## Test 4: Asset Classification / CARVER Scoring (87.5/100)

This test evaluates whether the LLM can classify assets using the CARVER framework (Criticality, Accessibility, Recuperability, Vulnerability, Effect, Recognizability) and identify cloud-specific risk factors.

### CARVER Scores

| Target | C | A | R | V | E | R | Total | Primary Attack Vector |
|--------|:-:|:-:|:-:|:-:|:-:|:-:|:-----:|:---|
| testphp.vulnweb.com | 8 | 10 | 5 | 9 | 9 | 10 | 51 | SQLi → SSRF/IMDS credential theft |
| demo.testfire.net | 9 | 10 | 4 | 10 | 10 | 10 | 53 | Struts RCE (CVE-2017-5638) |
| scanme.nmap.org | 3 | 10 | 8 | 6 | 4 | 7 | 38 | Weak SSH / OpenSSH 6.6.1 |
| testasp.vulnweb.com | 9 | 10 | 5 | 10 | 9 | 10 | 53 | HTTP.sys RCE (CVE-2015-1635) |

### Scoring Breakdown

| Dimension | Score | Max | Notes |
|-----------|------:|----:|-------|
| CARVER Quality | 30.0 | 30 | All scores are well-justified and proportional |
| Attack Vector | 25.0 | 25 | Correct primary attack vector for each target |
| Cloud Risk | 20.0 | 20 | Identified IMDS, IAM roles, S3 access for AWS targets |
| KEV Awareness | 12.5 | 25 | Identified CVE-2017-5638 and CVE-2015-1635 but missed some detail |

### Cloud Risk Analysis (Improved)

After prompt tuning, the LLM correctly identified cloud-specific risks for AWS targets:
- **testphp.vulnweb.com:** IMDSv1 without hop limit (SSRF → credential theft), IAM role with S3 access, exposed .git may contain AWS credentials, EC2 public exposure
- **testasp.vulnweb.com:** Same EC2 instance as testphp (lateral movement risk), IMDS access, debug mode may leak cloud config

---

## Knowledge Module Effectiveness

| Module | Lines | Injection Points | Test Impact | Grade |
|--------|------:|:-:|:---|:---:|
| nmap-knowledge.ts | 600+ | 4 | Perfect evasion + NSE selection | A+ |
| cloud-security-knowledge.ts | 450+ | 4 | Cloud risk identification improved from 0% to 100% | A |
| kev-service.ts | 679 | 3 | Perfect KEV detection (100%) | A+ |
| bugbounty-knowledge.ts | 400+ | 3 | Correct false positive flagging | A |
| scoring-engine.ts (CARVER) | 1,800+ | 2 | Well-calibrated CARVER scores | A |
| training-corpus.ts | 350+ | 2 | Triage quality baseline | B+ |

---

## Recommendations

1. **Strengthen cloud tool selection prompting.** The LLM correctly identifies cloud risks in analysis but does not proactively select `cloud_enum` or `s3scanner` in scan plans. Adding explicit "For AWS targets, MUST include cloud_enum" to the scan plan prompt would fix this.

2. **Add httpx and whatweb to default tool set.** The LLM consistently selects nuclei and nikto but underuses httpx (already available) and whatweb for tech fingerprinting.

3. **Expand KEV context window.** The current KEV injection includes ~50 entries. Expanding to the full CISA KEV catalog (~1,100 entries) with relevance filtering would improve coverage.

4. **Add OWASP Top 10 knowledge module.** A dedicated module mapping OWASP categories to specific tool commands would improve web app testing completeness.

5. **Tune CARVER scoring calibration.** The Accessibility dimension consistently scores 10/10 (maximum) for all web targets. Adding nuance for targets behind WAFs, CDNs, or authentication would improve discrimination.
