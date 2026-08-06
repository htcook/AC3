# Broken Crystals Scan Review — 2026-04-12

## Engagement: Broken Crystals Full Pipeline v2 (ID: 1800033)
- **Status**: Active
- **Type**: Pentest
- **Scan Mode**: strict_passive
- **Target**: brokencrystals.lab.aceofcloud.io (159.223.152.190)
- **Started**: 2026-04-12 15:35 EDT

## Discovery Phase (RustScan)
7 open ports discovered:
| Port | Service |
|------|---------|
| 22   | SSH     |
| 80   | HTTP    |
| 443  | HTTPS   |
| 1337 | Unknown |
| 4000 | Unknown |
| 8090 | HTTP    |
| 8443 | HTTPS   |

## Technology Fingerprinting (httpx)
- Nginx 1.18.0 (Ubuntu)
- Bootstrap
- HSTS enabled
- TLS CN: scan.aceofcloud.io (expires 2026-06-10)
- Port 443: 404 Not Found (likely reverse proxy misconfiguration)

## Vulnerability Findings

### Critical (1)
1. **Exposed JSON Configuration Files** — `/config.json`
   - Detects exposed config files containing API keys, AWS credentials, database configs
   - Tool: Nuclei

### High (4)
2. **Laravel .env File Disclosure** — `/.env`
   - Contains database credentials and tokens
   - Tool: Nuclei
3. **Codeigniter .env File Discovery** — `/.env`
   - Same endpoint, different template match
   - Tool: Nuclei
4. **Generic Env File Disclosure** — `/.env`
   - Same endpoint, generic template
   - Tool: Nuclei
5. **Laravel <5.5.21 Information Disclosure** — `/.env`
   - CVE-related, externally usable passwords
   - Tool: Nuclei

### Low (1)
6. **SSL Certificate Info** — Subject: CN=159.223.152.190, O=AC3 Test Lab, C=US
   - Self-signed or test certificate
   - Tool: Nikto

### Info (17)
- Missing httponly flag on cookies (ocupcgl28q0h, oc_sessionPassphrase)
- PHP 8.2.29 detected via x-powered-by header
- Security headers present: X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, Referrer-Policy, X-Robots-Tag
- X-Permitted-Cross-Domain-Policies: none

## Scan Performance Issues
- **Nuclei timeouts**: Scans on ports 8443 and 8090 timed out at 300s
- **httpx timeout**: Discovery scan timed out at 180s
- **naabu timeout**: Port scan timed out at 180s
- **ZAP**: Returned 0 findings (likely configuration issue)
- **Katana**: Returned 0 findings
- **Gobuster**: Returned 0 findings (10s duration — may need longer timeout)

## Observations
1. **Deduplication needed**: The .env file was flagged 4 times by different Nuclei templates — these should be deduplicated into a single finding with corroboration from multiple templates
2. **Missing engagement_findings**: 0 findings were promoted to engagement_findings despite scan_results having 5 nuclei + 18 nikto findings — the finding promotion pipeline may not be running
3. **Port coverage gaps**: Nuclei only found vulns on port 80; ports 1337, 4000, 8090, 8443 need deeper scanning
4. **ZAP not producing findings**: ZAP scan returned 0 findings — may need active scanning mode or AJAX spider
5. **Known BC vulns not found**: Broken Crystals is known for SQL Injection, XSS, SSRF, SSTI, XXE, JWT Bypass, LDAP Injection, OS Command Injection — none of these were detected yet
6. **Scan mode limitation**: Running in strict_passive mode limits active vulnerability testing

## Recommendations
1. Switch to `active` scan mode to enable deeper vulnerability testing
2. Fix the finding promotion pipeline to move scan_results findings into engagement_findings
3. Implement finding deduplication for the same endpoint across templates
4. Configure ZAP with AJAX spider and active scan policies
5. Increase timeout for nuclei scans on non-standard ports
6. Add targeted scans for known BC vulnerabilities (SQLi, XSS, SSRF, etc.)
