# ZAP Fix Plan v3 — Reverse Proxy URL Resolution

## Root Cause (Confirmed via Live Testing)

ZAP runs in a Docker container on the scan server (159.223.152.190:8090).
The hostname `juiceshop.lab.aceofcloud.io` does NOT resolve from ZAP's container.

### Test Results:
| URL | ZAP accessUrl Status | Result |
|-----|---------------------|--------|
| `http://juiceshop.lab.aceofcloud.io/` | 500 | DNS resolution failure |
| `http://159.223.152.190/` | 200 | 301 redirect to nginx |
| `http://159.223.152.190:3000/` | Timeout | Port firewalled |
| `https://scan.aceofcloud.io/lab/juice-shop/` | **200** | **Juice Shop HTML** |

## Fix: Training Lab ZAP URL Resolver

For training labs hosted on the scan server, the orchestrator must:
1. Map the logical hostname to the reverse proxy URL
2. Use `https://scan.aceofcloud.io/lab/{slug}/` as the ZAP target URL
3. Also rewrite seed URLs and injectable endpoint URLs to use the reverse proxy

### Mapping:
- `juiceshop.lab.aceofcloud.io` → `https://scan.aceofcloud.io/lab/juice-shop/`
- `dvwa.lab.aceofcloud.io` → check if accessible via similar path
- Other labs: use the logical hostname (external labs like demo.testfire.net resolve normally)

### Code Changes:
1. Add `TRAINING_LAB_ZAP_URL_MAP` in engagement-orchestrator.ts
2. Before ZAP scan: resolve the target URL through the map
3. Before SQLMap/XSStrike: resolve the target URL through the map
4. Seed URLs must also use the resolved base URL
