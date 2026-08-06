# ZAP Juice Shop Scan Diagnosis v2 — Final Root Cause

## Key Evidence

### httpx Results (from scan server)
- `http://juiceshop.lab.aceofcloud.io:80` → **200 "OWASP Juice Shop"** (content-length: 75002)
- `https://juiceshop.lab.aceofcloud.io:443` → **404 "404 Not Found"** (content-length: 162)
- `http://juiceshop.lab.aceofcloud.io:4000` → **404 "Error"** (content-length: 139)
- `http://juiceshop.lab.aceofcloud.io:8080` → **404 "HTTP Status 404"** (content-length: 683)

The hostname DOES resolve on the scan server (it's in /etc/hosts). Port 80 serves the Juice Shop.
Port 443 returns 404 (nginx doesn't have the right server_name for HTTPS).
Port 4000 returns 404 (Express is running but not serving Juice Shop there).

### ZAP Scan Results
1. **http://juiceshop.lab.aceofcloud.io** (port 80) → ERROR: 400 Bad Request on active scan start
   - Spider found 2 URLs, AJAX spider found 3 URLs
   - Active scan FAILED with 400 error
   
2. **https://juiceshop.lab.aceofcloud.io** (port 443) → Completed but only 4 info alerts
   - Spider found 4 URLs (all 404 pages)
   - Active scan completed on 404 pages → nothing to find
   
3. **http://juiceshop.lab.aceofcloud.io:4000** → ERROR: 400 Bad Request on active scan start
   - Spider found 3 URLs (all 404 pages)
   - Active scan FAILED with 400 error

### Comparison: Altoro Mutual (working lab)
- `http://altoro.lab.aceofcloud.io` (port 80) → Completed, 978 total alerts
- `http://altoro.lab.aceofcloud.io:8081` → Completed, 246 total alerts (4 high, 91 medium)
- `http://altoro.lab.aceofcloud.io:8083` → Timed out at 35% active scan progress, 257 URLs found
- `http://altoro.lab.aceofcloud.io:8084` → Timed out at 36% active scan progress, 464 URLs found

## Root Causes

### Issue 1: ZAP 400 Bad Request on Active Scan Start
The 400 error from `/JSON/ascan/action/scan/` means ZAP cannot start an active scan on the target.
This happens when:
- The URL is not in ZAP's site tree (spider didn't discover it properly)
- The spider found too few URLs (2-3) and ZAP's context is essentially empty

The spider only found 2-3 URLs because:
- Port 80 serves Juice Shop but ZAP's spider may be getting redirected
- The Juice Shop is an Angular SPA — the traditional spider can't crawl it effectively
- The AJAX spider should handle SPAs but only found 3 URLs, suggesting connectivity issues

### Issue 2: HTTPS target returns 404
The nginx on the scan server doesn't have a proper HTTPS virtual host for `juiceshop.lab.aceofcloud.io`.
It falls through to the default server block which returns 404.

### Issue 3: Port 4000 returns 404
Port 4000 is likely another service (not Juice Shop). Nmap detected it as "Node.js Express" but
it's not the Juice Shop instance.

## Fix Plan

### Fix 1: For training labs, only scan the port that actually serves the app
Instead of scanning all HTTP ports, detect which port returns a 200 response and only scan that one.
For Juice Shop, that's port 80 (HTTP).

### Fix 2: Fix the ZAP 400 error on active scan start
The 400 error happens because ZAP's spider found too few URLs. For SPA targets like Juice Shop:
1. Force AJAX spider mode (not traditional spider)
2. Increase spider timeout
3. Add seed URLs for known Juice Shop endpoints

### Fix 3: Add Juice Shop-specific injectable endpoints for SQLMap
Instead of generic `/search?q=`, use known Juice Shop endpoints:
- `/rest/products/search?q=` (SQL injection vulnerable)
- `/rest/user/login` (POST with email/password)
- `/api/Products?q=` (SQL injection vulnerable)

### Fix 4: Increase ZAP scan timeout for training labs
The 5-minute timeout is too short for a full active scan of a complex SPA.
Increase to 10-15 minutes for training labs.
