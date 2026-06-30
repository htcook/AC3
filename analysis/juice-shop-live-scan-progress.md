# Juice Shop Live Scan Progress

## Session: lab-1774410387850-a84e9b81
## Target: https://scan.aceofcloud.io/lab/juice-shop/
## Profile: Deep (+ ZAP full scan)

### Scan Log (as of ~3:50 AM)
- 3:46:27 — Phase 1: Reconnaissance — Probing target
- 3:46:29 — httpx Complete — Detected 1 port
- 3:46:32 — Header Probe Complete — Found 0 header issues
- 3:46:32 — Phase 2: Enumeration — Running nmap service detection
- 3:48:15 — nmap Complete — Found 17 open ports
- 3:48:16 — Phase 3: Vulnerability Detection — Running nuclei, nikto, and gobuster scans
- 3:48:16 — Nuclei Pass 1/3 — DAST active testing (XSS, SQLi, LFI, SSRF, SSTI)
- 3:48:16 — Nuclei Pass 1 Done — +0 findings (0s)
- 3:48:16 — Nuclei Pass 2/3 — Tech-specific checks (hsts, nginx:1.18.0, ubuntu)
- 3:48:16 — Nuclei Pass 2 Done — +0 findings (0s)
- 3:48:16 — Nuclei Pass 3/3 — Exposure & panel checks

### Stats
- 1 Host, 17 Ports, 0 Vulns Found, 6 Tools Run
- LLM Analysis: Not started yet

### Notes
- Nuclei Pass 1 (DAST) found 0 findings — this is concerning, may indicate the target URL is behind a proxy
- The scan is hitting scan.aceofcloud.io/lab/juice-shop/ not demo.owasp-juice.shop directly
- Need to check if the proxy is interfering with active scanning
