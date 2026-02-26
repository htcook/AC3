# ProjectDiscovery Cloud Platform (PDCP) API Notes

## Base URL
`https://api.projectdiscovery.io`

## Auth
Header: `X-Api-Key: <api-key>`

## Asset Discovery (subfinder equivalent)
- POST /v1/asset/enumerate — Create Enumeration
  - body.root_domains: string[] — domains to enumerate
  - body.steps: enum[] — dns_resolve, dns_bruteforce, dns_permute, port_scan, http_probe, http_screenshot, endpoint_crawling, dns_passive, tls_scan, uncover_assets, dns_scraping
  - body.enumeration_ports: string — port list
  - body.name: string — enumeration name
  - Response: { id, truncated-scan-targets, is-public, bulk_ids, failed_domains }
- GET /v1/asset/enumerate — Get Enumeration List
- GET /v1/asset/enumerate/{id} — Get Enumeration (results)
- POST /v1/asset/enumerate/{id}/rescan — Rescan
- GET /v1/asset/enumerate/{id}/export — Export results
- GET /v1/domain/associated — Get Associated Domains

## Scans (nuclei equivalent)
- POST /v1/scans — Create Scan (nuclei templates)
  - body.targets: string[]
  - body.templates: string[]
  - body.recommended: boolean
  - body.all: boolean
  - Response: { message, id, truncated-scan-targets }
- GET /v1/scans — Get Scan List
- GET /v1/scans/{id} — Get Scan results
- POST /v1/scans/{id}/stop — Stop Scan
- POST /v1/scans/{id}/rescan — Rescan

## Key Integration Points
- subfinder = Create Enumeration with steps: [dns_passive, dns_resolve, dns_scraping]
- httpx = Create Enumeration with steps: [http_probe, http_screenshot]
- naabu = Create Enumeration with steps: [port_scan] + enumeration_ports
- All three can be combined in a single enumeration request

## For our dashboard integration:
Since these are CLI tools (not cloud API), we'll build service wrappers that:
1. Accept the same parameters as the CLI tools
2. Use the PDCP Cloud API if PDCP_API_KEY is set
3. Fall back to simulated/mock results for demo mode
4. Store results in our scan_observations table via the normalizer
