# Juice Shop Live Scan Analysis

## Scan Results
- Session: lab-1774410387850-a84e9b81
- Profile: Deep (+ ZAP full scan)
- Target: https://scan.aceofcloud.io/lab/juice-shop/
- Tools Run: 6 (httpx, nmap, nuclei x3, nikto, gobuster)
- Vulns Found: 0
- Ports Found: 17

## Key Issue: ZAP and SQLMap NOT triggered
The "Deep" scan profile should include ZAP full scan and SQLMap, but only 6 tools ran.
The Juice Shop application IS accessible through the reverse proxy (confirmed via browser).

## Root Cause Investigation
Need to check:
1. Why ZAP was not triggered — the webApps filter requires assets with web ports
2. Why SQLMap was not triggered — requires injectable parameters detected
3. Whether the asset was classified as web_app type
4. Whether the nmap scan detected HTTP services on the correct ports
