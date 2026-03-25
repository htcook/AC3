# ZAP Network Investigation Results (Mar 25, 2026)

## Key Findings

### ZAP Deployment
- ZAP v2.17.0 running as a Java daemon process (NOT Docker)
- Listening on port 8080 on the scan server (159.223.152.190)
- Config: `-daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true`
- ZAP_BASE_URL in env: `http://159.223.152.190:8090` (goes through nginx reverse proxy)
- ZAP actual port: 8080 (direct)

### Critical Discovery: ZAP API Proxy Routing Issue
- ZAP_BASE_URL = `http://159.223.152.190:8090` — this is the NGINX reverse proxy port
- ZAP actual port = 8080 (direct)
- When our code uses `HttpProxyAgent(ZAP_BASE_URL)`, it routes through nginx:8090 → ZAP:8080
- But when ZAP tries to access URLs, it uses its OWN network context (the host)

### ZAP accessUrl Results
| URL | Status | Notes |
|-----|--------|-------|
| http://127.0.0.1:3001/ | 500 Internal Error | ZAP can't reach localhost:3001! |
| http://juiceshop.lab.aceofcloud.io/ | 500 Internal Error | ZAP can't reach via hostname either |
| http://juiceshop.lab.aceofcloud.io:3001/ | 500 Internal Error | Same |
| http://127.0.0.1:3001/rest/products/search?q=test | 500 Internal Error | Same |
| https://scan.aceofcloud.io/lab/juice-shop/ | **200 OK** | **Works! Returns actual Juice Shop HTML** |
| http://dvwa.lab.aceofcloud.io:8083/ | 500 Internal Error | DVWA also fails via hostname! |
| http://127.0.0.1:8083/ | 500 Internal Error | DVWA also fails via localhost! |

### Root Cause Analysis
ZAP is running as user 1000 (non-root) and listening on 0.0.0.0:8080. When ZAP tries to 
access `http://127.0.0.1:3001/`, it gets a 500 Internal Error. This means:

1. ZAP cannot access ANY localhost URLs on the scan server
2. ZAP cannot resolve lab hostnames (127.0.0.1 via /etc/hosts)
3. The ONLY URL that works is `https://scan.aceofcloud.io/lab/juice-shop/` (external HTTPS)

This is likely because:
- ZAP is running in a chroot/namespace/container-like environment
- OR ZAP's Java process has network restrictions
- OR the nginx proxy between our code and ZAP is interfering

### ZAP Site Tree (existing sites from previous scans)
- http://demo.testfire.net (Altoro Mutual - external, works)
- https://scan.aceofcloud.io (reverse proxy - works)
- http://dvbank.lab.aceofcloud.io:* (various ports - these were from httpx, not ZAP direct access)
- http://altoro.lab.aceofcloud.io:* (same)

### Juice Shop Deployment
- NOT running in Docker (docker ps returns empty)
- Running directly on host at port 3001
- Nginx proxies /lab/juice-shop/ → http://127.0.0.1:3001/
- /etc/hosts maps juiceshop.lab.aceofcloud.io → 127.0.0.1

## Conclusion
The ONLY way ZAP can scan the Juice Shop is through the HTTPS reverse proxy URL:
`https://scan.aceofcloud.io/lab/juice-shop/`

This is already what our URL resolver does. The 0-alerts issue is NOT a connectivity problem — 
ZAP CAN reach the Juice Shop through the reverse proxy. The issue is that:
1. The active scan is too slow through the proxy (46% in 25 minutes)
2. The reverse proxy may be interfering with ZAP's attack payloads
3. ZAP needs more time and possibly tuned scan policies for proxy-based scanning
