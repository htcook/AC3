# ZAP Juice Shop Scan Diagnosis — Complete Root Cause Analysis

## Summary of Issues

### Issue 1: ZAP Active Scan 400 Bad Request (2 of 3 scans failed)
- **http://juiceshop.lab.aceofcloud.io** → ERROR: 400 Bad Request at /JSON/ascan/action/scan/
- **http://juiceshop.lab.aceofcloud.io:4000** → ERROR: 400 Bad Request at /JSON/ascan/action/scan/
- **https://juiceshop.lab.aceofcloud.io** → Completed but only 4 info-level alerts

The scanPolicyName fix was applied (line 1565 comment says "Do NOT pass scanPolicyName") and the code
at lines 1569 and 1665 correctly omits it. However, the 400 error is still happening for HTTP scans.

**Root cause**: The 400 error from ZAP's `/JSON/ascan/action/scan/` endpoint typically means the target URL
is not in ZAP's context (wasn't spidered) or the URL is unreachable from ZAP's perspective. Since the
spider only found 2-3 URLs, ZAP may not have a valid site tree to scan.

### Issue 2: ZAP Spider Found Almost No URLs (2-4 instead of 100+)
- Nmap scanned IP 159.223.152.190 and found ports 22, 80, 443, 4000
- ZAP targets were constructed as:
  - http://juiceshop.lab.aceofcloud.io (port 80)
  - https://juiceshop.lab.aceofcloud.io (port 443)
  - http://juiceshop.lab.aceofcloud.io:4000

**Root cause**: The hostname `juiceshop.lab.aceofcloud.io` likely does NOT resolve in DNS.
The Juice Shop is hosted at `https://scan.aceofcloud.io/lab/juice-shop/` (path-based routing
behind nginx reverse proxy). The subdomain is a logical name used in our system but not a real
DNS record. When ZAP tries to spider `http://juiceshop.lab.aceofcloud.io`, it either:
1. Gets a DNS resolution failure
2. Gets the nginx default page (not Juice Shop)
3. Gets redirected somewhere unexpected

Port 4000 is the raw Node.js Express port — it may work if accessed directly via IP, but
using the hostname `juiceshop.lab.aceofcloud.io` won't resolve.

### Issue 3: SQLMap Import Error (FIXED in current build)
Error: "The requested module '../deterministic-scanner-analysis' does not provide an export named 'analyzeSqlmapFindingsDeterministic'"
This was a stale build issue. The current dist/_server.js (built Mar 24 22:48) contains the function.
The error occurred on a previous deployment. This is now fixed.

## Fix Plan

### Fix 1: Training Lab URL Mapping
For training labs hosted on the scan server, we need to map the logical hostname to the actual
reverse proxy URL. The mapping should be:
- `juiceshop.lab.aceofcloud.io` → `https://scan.aceofcloud.io/lab/juice-shop/`
- `dvwa.lab.aceofcloud.io` → `https://scan.aceofcloud.io/lab/dvwa/`
- etc.

This mapping should be applied in the ZAP target URL construction (line 4535 of engagement-orchestrator.ts).

### Fix 2: ZAP Active Scan Error Handling
When the ZAP active scan returns 400, we should:
1. Log the actual ZAP error response body for debugging
2. Try alternative scan approaches (e.g., scan the IP directly)

### Fix 3: SQLMap URL Construction
SQLMap should also use the correct reverse proxy URL for training labs.
