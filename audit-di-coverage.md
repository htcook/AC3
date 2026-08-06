# DI Scan Template & Results UI Audit — Apr 24, 2026

## Summary of Today's Changes

### New Backend Connectors Added Today
1. **Tier 1 (6 connectors):** URLhaus, MalwareBazaar, SEC EDGAR, OSV.dev, Team Cymru, CISA Advisories
2. **Tier 2 (7 connectors):** Feodo Tracker, SSLBL, GitHub Security Advisories, Certspotter, Companies House, OpenCorporates, HC3

### New Backend Modules Added Today
- Evidence multiplier mapping config
- Unified OSINT rate limiter with token bucket + 429 backoff
- ToS compliance registry with attribution tracking
- NIST 800-53 control mapper (25 signal types, 18 CWE IDs)
- FedRAMP Impact Level on engagements
- FedRAMP remediation timeline badges
- FedRAMP SAR report template
- Infrastructure inference module (15 service categories)
- JARM TLS fingerprint integration
- JARM historical tracking + community signature feeds
- Breach timeline visualization
- Credential spray status indicator

### Existing Backend Connectors (pre-today): ~63 connectors
### Total Backend Connectors: 76

## Audit Results

### 1. DomainIntel.tsx — SCAN_METHODS (Scan Creation Page)
**Status:** 21 methods listed (these are pipeline stages, not individual connectors)
**Assessment:** This is intentionally a high-level view of the pipeline stages, not a 1:1 connector list. The SCAN_METHODS describe pipeline phases (passive collection, DNS verification, banner grabbing, KEV matching, etc.). This is fine — users don't need to see 76 individual connectors here.

**Missing pipeline stages that could be added:**
- Infrastructure Inference (new today)
- JARM TLS Fingerprinting (new today)
- NIST 800-53 Control Mapping (new today)
- Breach Timeline Analysis (new today)
- Credential Harvesting (new today)

### 2. getConnectorCatalog (OSINT Sources Tab Backend)
**Status:** 42 connectors listed in the hardcoded catalog
**Gap:** Missing 13 connectors added in recent sessions:
- domain-health (DNSBL/SMTP/DNS health)
- alienvault-otx (threat intel exchange)
- google-safe-browsing (malware/phishing detection)
- phishtank (phishing URL database)
- darkweb-crossref (underground intel DB)
- dehashed-whois (WHOIS + subdomain scan)
- anubis, hackertarget, rapiddns, dnsrepo, sitedossier (free subdomain enum)
- favicon-hash (infrastructure discovery)
- jarm-fingerprint (TLS fingerprinting)
- dns-zone-transfer (AXFR attempt)
- wayback-diff (historical content analysis)
- container-discovery (Docker/K8s)
- github-recon (enhanced GitHub recon)
- cloud-bucket-recon (enhanced cloud bucket)
- **Tier 1:** urlhaus, malwarebazaar, sec-edgar, osv-dev, team-cymru, cisa-advisories
- **Tier 2:** feodo-tracker, sslbl, github-advisories, certspotter, companies-house, opencorporates, hc3

### 3. DomainIntelResults.tsx — Scan Results UI
**Status:** Comprehensive with many tabs
**Tabs present:** overview, assets, subdomains, inventory, ports, adversaries, campaigns, threat-model, vulns, breaches, incidents, affiliated-domains, coverage, methods, osint-sources, infra-map, spider, findings, corroboration, email-security, accuracy, changes, tech-vulns, takeover, cve-actors, takeover-poc, credentials, enrichment, analysis, web-crawl, entity-profile, vendor-alerts

**Today's features present in UI:**
- [x] OSINT Risk Signals with NIST control badges (just added)
- [x] Breach timeline visualization (Breaches tab)
- [x] Credential spray status indicator (Breaches tab)
- [x] Infrastructure Map tab (infra-map)
- [x] JARM fingerprint section (in InfrastructureMapTab)
- [x] FedRAMP remediation badges (in Ac3Reports.tsx)

## Gaps to Fix

### Priority 1: Update getConnectorCatalog with all missing connectors
Add the ~34 missing connectors to the hardcoded catalog in domain-intel-core.ts

### Priority 2: Add new pipeline stages to SCAN_METHODS in DomainIntel.tsx
Add entries for: Infrastructure Inference, JARM Fingerprinting, NIST Control Mapping, Breach Analysis, Credential Harvesting
