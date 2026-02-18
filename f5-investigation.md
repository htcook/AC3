# F5 BIG-IP False Positive Investigation

## Root Cause Analysis

### How F5 BIG-IP gets matched

1. **KEV service mapping (kev-service.ts line 145)**: The nginx entry maps to vendors `["nginx", "f5"]` — because F5 acquired NGINX Inc. in 2019, the mapping includes "f5" as a vendor. This means ANY asset with "nginx" technology will also match ALL F5 KEV entries.

2. **Fuzzy matching (kev-service.ts lines 336-362)**: The fuzzy matcher does `kevVendor.includes(techLower)` — if an asset has technology "nginx", and a KEV entry has vendor "F5" with product "BIG-IP", the vendor match on "f5" (from the nginx mapping) pulls in all F5 BIG-IP CVEs.

3. **Banner detection (dns-banner-verify.ts line 80)**: The pattern `/Server:.*\bF5\b/i` could match any Server header containing "F5" as a word boundary — but this is unlikely to trigger on AWS infrastructure.

### Does AWS use F5 BIG-IP?

No. AWS does NOT use F5 BIG-IP in their native infrastructure:
- AWS ELB (Elastic Load Balancer) is AWS's own technology, not F5
- AWS CloudFront is AWS's own CDN, not F5
- F5 BIG-IP VE is available as a marketplace product that customers can CHOOSE to deploy
- AWS native services do NOT set BIGipServer cookies or F5 Server headers

### Why AceofCloud sees F5 findings

The root cause is the KEV service's `TECH_TO_KEV_PATTERNS` mapping:
```
"nginx": { vendors: ["nginx", "f5"], products: ["nginx"] }
```

Since AceofCloud runs nginx (confirmed via banner detection), the KEV matcher maps nginx → vendor "f5" → matches ALL F5 KEV entries including BIG-IP CVEs. This is a **product-family false positive** — nginx and BIG-IP are both F5 products but completely different technologies.

### Fix

Remove "f5" from the nginx vendor mapping. F5 BIG-IP should only match when "F5 BIG-IP", "BIG-IP", or "BigIP" is explicitly detected as a technology.
