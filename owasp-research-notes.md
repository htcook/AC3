# OWASP Top 10:2025 Research Notes

## Full Category List
1. A01:2025 - Broken Access Control (40 CWEs, 1.8M occurrences, 32K CVEs)
2. A02:2025 - Security Misconfiguration
3. A03:2025 - Software Supply Chain Failures (NEW)
4. A04:2025 - Cryptographic Failures
5. A05:2025 - Injection
6. A06:2025 - Insecure Design
7. A07:2025 - Authentication Failures
8. A08:2025 - Software or Data Integrity Failures
9. A09:2025 - Security Logging and Alerting Failures
10. A10:2025 - Mishandling of Exceptional Conditions (NEW)

## Key Changes from 2021 to 2025
- A03 is NEW: Software Supply Chain Failures (was not in 2021)
- A10 is NEW: Mishandling of Exceptional Conditions (was not in 2021)
- "Vulnerable and Outdated Components" merged into Supply Chain
- "Server-Side Request Forgery" merged into Broken Access Control

## A01: Broken Access Control
- Key CWEs: CWE-200, CWE-201, CWE-918 (SSRF), CWE-352 (CSRF), CWE-22 (Path Traversal)
- Testing tools: nikto (forced browsing), nuclei (IDOR/SSRF templates), nmap http-enum, burp
- NSE scripts: http-enum, http-methods, http-auth-finder
- Nuclei tags: idor, ssrf, lfi, rfi, traversal, cors, redirect

## A02: Security Misconfiguration
- Key CWEs: CWE-16, CWE-611 (XXE), CWE-1004, CWE-1032
- Testing tools: nikto, nmap, nuclei, testssl.sh
- NSE scripts: http-security-headers, http-default-accounts, http-config-backup, ssl-enum-ciphers
- Nuclei tags: misconfig, exposure, default-login, debug, backup

## A03: Software Supply Chain Failures (NEW in 2025)
- Key CWEs: CWE-1104 (Use of Unmaintained Third-Party Components)
- Testing tools: npm audit, snyk, retire.js, nuclei
- NSE scripts: N/A (not network-scannable)
- Nuclei tags: cve, outdated, component

## A04: Cryptographic Failures
- Key CWEs: CWE-259, CWE-327, CWE-328, CWE-330, CWE-331
- Testing tools: testssl.sh, nmap ssl scripts, sslyze
- NSE scripts: ssl-enum-ciphers, ssl-cert, ssl-dh-params, ssl-heartbleed, ssl-poodle, ssl-ccs-injection
- Nuclei tags: ssl, tls, weak-crypto, heartbleed

## A05: Injection
- Key CWEs: CWE-79 (XSS), CWE-89 (SQLi), CWE-78 (OS Command), CWE-94 (Code Injection)
- Testing tools: sqlmap, nuclei, nikto, commix, XSStrike
- NSE scripts: http-sql-injection, http-stored-xss, http-dombased-xss, http-phpself-xss
- Nuclei tags: sqli, xss, ssti, rce, injection, lfi, rfi

## A06: Insecure Design
- Key CWEs: CWE-209, CWE-256, CWE-501, CWE-522
- Testing tools: Manual review, threat modeling, nuclei
- NSE scripts: http-default-accounts, http-auth-finder
- Nuclei tags: exposure, default-login, info-disclosure

## A07: Authentication Failures
- Key CWEs: CWE-287, CWE-384, CWE-613, CWE-640
- Testing tools: hydra, medusa, nmap brute scripts, nuclei
- NSE scripts: http-brute, http-form-brute, ssh-brute, ftp-brute, http-auth-finder
- Nuclei tags: auth-bypass, default-login, brute-force, token

## A08: Software or Data Integrity Failures
- Key CWEs: CWE-502 (Deserialization), CWE-829
- Testing tools: nuclei, ysoserial, custom scripts
- NSE scripts: N/A (application-level)
- Nuclei tags: deserialization, rce, java

## A09: Security Logging and Alerting Failures
- Key CWEs: CWE-117, CWE-223, CWE-532, CWE-778
- Testing tools: Manual review, log analysis
- NSE scripts: N/A (not network-scannable)
- Nuclei tags: log, exposure, debug

## A10: Mishandling of Exceptional Conditions (NEW in 2025)
- Key CWEs: CWE-252, CWE-280, CWE-391, CWE-754, CWE-755
- Testing tools: fuzzing, error-based testing, nuclei
- NSE scripts: http-errors (custom)
- Nuclei tags: error, stacktrace, debug, info-disclosure


## Tool-to-Category Mapping (from pentesting guides)

### Comprehensive Tool Mapping per OWASP Category:

| OWASP Category | Primary Tools | Nmap NSE Scripts | Nuclei Tags | Other Tools |
|---|---|---|---|---|
| A01: Broken Access Control | Burp (AuthMatrix, Authorize), nuclei | http-enum, http-methods, http-auth-finder | idor, ssrf, lfi, rfi, traversal, cors, redirect, auth-bypass | ffuf, gobuster, feroxbuster |
| A02: Security Misconfiguration | nikto, nmap, nuclei, testssl | http-security-headers, http-default-accounts, http-config-backup, ssl-enum-ciphers, http-server-header | misconfig, exposure, default-login, debug, backup, config | skipfish |
| A03: Supply Chain Failures | npm audit, snyk, retire.js | N/A | cve, outdated, component, wordpress, joomla, drupal | wpscan, searchsploit |
| A04: Cryptographic Failures | testssl.sh, sslyze, nmap | ssl-enum-ciphers, ssl-cert, ssl-dh-params, ssl-heartbleed, ssl-poodle, ssl-ccs-injection | ssl, tls, weak-crypto, heartbleed, poodle | sslscan |
| A05: Injection | sqlmap, nuclei, commix | http-sql-injection, http-stored-xss, http-dombased-xss, http-phpself-xss | sqli, xss, ssti, rce, injection, lfi, rfi, xxe, command-injection | XSStrike, tplmap |
| A06: Insecure Design | Manual review, threat modeling | http-default-accounts, http-auth-finder | exposure, default-login, info-disclosure | N/A |
| A07: Authentication Failures | hydra, medusa, nmap brute | http-brute, http-form-brute, ssh-brute, ftp-brute, http-auth-finder | auth-bypass, default-login, brute-force, token, session | john, hashcat |
| A08: Data Integrity Failures | nuclei, ysoserial | N/A | deserialization, rce, java, upload | N/A |
| A09: Logging Failures | Manual review | N/A | log, exposure, debug | ELK, Splunk |
| A10: Exception Handling | fuzzing, nuclei | N/A | error, stacktrace, debug, info-disclosure | wfuzz, ffuf |
