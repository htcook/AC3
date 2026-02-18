# Domain Intelligence Pipeline — Gap Analysis & Enhancement Roadmap

**Prepared for:** AceofCloud / Spicy TIP Platform  
**Date:** February 18, 2026  
**Author:** Manus AI

---

## Executive Summary

This document provides a comprehensive audit of the Caldera Dashboard's domain intelligence pipeline, identifies gaps in discovery scanning, enumeration scanning, and vulnerability validation, and presents a prioritized enhancement roadmap. The analysis covers the current 9-stage pipeline architecture, benchmarks it against industry-standard External Attack Surface Management (EASM) practices, and evaluates passive and API-based vulnerability validation services that can supplement Shodan to approach real vulnerability scanning fidelity — without active probing. The document concludes with an architecture proposal for integrating third-party vulnerability scanner uploads and API-based scan platforms.

---

## 1. Current Pipeline Architecture

The domain intelligence pipeline currently executes the following stages in sequence:

| Stage | Name | Function | Data Sources |
|-------|------|----------|-------------|
| 0 | FP Learning Context | Loads analyst false-positive feedback to calibrate LLM analysis | Internal DB |
| 0.5 | Passive Reconnaissance | Runs 9 connectors in parallel to discover assets | crt.sh, Shodan, Wayback, Censys, URLScan, RDAP, RIPEstat, SecurityTrails, Dehashed |
| 1 | Asset Discovery | LLM-driven asset enumeration using passive recon context | LLM + passive data |
| 1.5 | DNS & Banner Verification | Resolves hostnames, extracts Server/X-Powered-By headers | Active DNS, HTTP headers |
| 1.7 | Shodan Banner Enrichment | Populates technologyVersions from Shodan banner data | Shodan observations |
| 2–3 | Asset Analysis | CARVER+SHOCK scoring, BIA, hybrid risk computation | LLM + passive signals |
| 3.5 | CISA KEV Enrichment | Matches technologies against Known Exploited Vulnerabilities | CISA KEV catalog |
| 3.6 | Vuln Feed Enrichment | Matches technologies against NVD, ExploitDB, and other feeds | NVD, ExploitDB, abuse.ch |
| 3.7 | Shodan CVE Verification | Upgrades probable findings to confirmed using Shodan vulns | Shodan vuln detection |
| 3.8 | Exploit Matching | Maps CVEs to Metasploit modules, ExploitDB, Caldera abilities | Metasploit DB, ExploitDB |
| 4 | Campaign Recommendations | LLM-designed red team campaigns targeting top-risk assets | LLM + all prior data |
| 5 | Executive Summary | LLM-generated executive and threat model summaries | LLM + all prior data |

### 1.1 Current Passive Connectors

The passive reconnaissance stage uses 9 connectors, each producing typed `AssetObservation` objects:

| Connector | Asset Types Discovered | Requires API Key | Data Provided |
|-----------|----------------------|-------------------|---------------|
| **crt.sh** | Subdomains, certificates | No | Certificate Transparency logs, SAN entries |
| **Shodan** | IPs, services, banners | Yes | Open ports, product/version, CPE, CVEs, OS |
| **Wayback Machine** | Historical URLs | No | Archived URLs, admin paths, API endpoints |
| **Censys** | IPs, certificates, services | Yes | TLS certificates, service banners, protocols |
| **URLScan** | URLs, technologies | Yes | Page screenshots, DOM analysis, tech detection |
| **RDAP** | Domain registration | No | Registrar, nameservers, registration dates |
| **RIPEstat** | ASN, IP prefixes | No | BGP routing, IP allocation, abuse contacts |
| **SecurityTrails** | Subdomains, DNS history | Yes | Historical DNS records, subdomain enumeration |
| **Dehashed** | Breach records | Yes | Leaked credentials, email addresses, breach sources |

### 1.2 Signal Classifier Rules

The signal classifier applies 12 heuristic rules to observations, detecting: exposed admin interfaces, open database ports, expired TLS certificates, staging/dev environments, API endpoints, sensitive data in URLs, weak SPF records, vulnerable software versions, historical admin paths, credential exposure, high-volume breach exposure, and open remote access ports.

### 1.3 Corroboration Tier System

The pipeline uses a three-tier evidence model for posture findings:

| Tier | Meaning | Severity Cap | Scoring Impact |
|------|---------|-------------|----------------|
| **Confirmed** | Version-matched CVE or Shodan-verified vulnerability | 10/10 | Full weight in hybrid risk |
| **Probable** | Real CVE matched to product family, version unconfirmed | 6/10 | 60% weight in vuln risk |
| **Potential** | LLM-inferred weakness without CVE evidence | NOT RATED | Excluded from risk scoring |

---

## 2. Gap Analysis — Discovery Scanning

Discovery scanning is the process of identifying all assets (subdomains, IPs, services, cloud resources) belonging to a target organization. The current pipeline has strong coverage but several notable gaps.

### 2.1 What We Have

The current discovery stage is solid for a passive-first platform. Certificate Transparency via crt.sh provides excellent subdomain coverage. Shodan and Censys provide service-level discovery with banner data. SecurityTrails adds historical DNS intelligence. Dehashed provides breach-derived subdomain discovery. The Wayback Machine reveals historical attack surface.

### 2.2 What We're Missing

**Passive DNS Aggregation.** The pipeline lacks dedicated passive DNS (pDNS) data sources beyond SecurityTrails. Services like **Farsight DNSDB** (now part of DomainTools), **CircL Passive DNS**, and **VirusTotal passive DNS** maintain massive databases of historical DNS resolutions observed by sensor networks worldwide. These reveal subdomains that never appeared in CT logs or active scans — internal-facing subdomains that leaked into public DNS, temporary infrastructure used during incidents, and CDN/cloud migrations that left dangling records [1] [2].

**Autonomous System (AS) Correlation.** While RIPEstat provides basic ASN data, the pipeline does not perform AS-level correlation to discover all IP ranges owned by the target organization. A comprehensive approach would resolve the target's known IPs to ASNs, then enumerate all prefixes announced by those ASNs, and finally reverse-DNS all IPs in those prefixes to find additional hostnames. Services like **BGPView**, **Hurricane Electric BGP Toolkit**, and **IPinfo.io** provide APIs for this [3].

**Cloud Asset Discovery.** The pipeline has no specific detection for cloud-hosted assets. Modern organizations host significant infrastructure on AWS, Azure, and GCP. Techniques for cloud discovery include: enumerating S3 bucket names derived from the domain (e.g., `aceofcloud-backups.s3.amazonaws.com`), checking Azure blob storage (`aceofcloud.blob.core.windows.net`), detecting cloud provider IP ranges in resolved addresses, and identifying cloud-specific HTTP headers (e.g., `x-amz-request-id`, `x-ms-request-id`) [4].

**WHOIS/Registrant Correlation.** RDAP provides registration data for the primary domain, but the pipeline does not perform reverse WHOIS lookups to find other domains registered by the same organization, registrant email, or organization name. Services like **WhoisXML API**, **DomainTools**, and **SecurityTrails** offer reverse WHOIS APIs that can uncover shadow IT domains, acquired company domains, and forgotten project domains [5].

**GitHub/Code Repository Leakage.** Developer repositories frequently leak internal hostnames, API endpoints, credentials, and infrastructure details. The pipeline should search GitHub, GitLab, and Bitbucket for code referencing the target domain. Tools like **truffleHog** and **GitDorker** automate this, and the GitHub Search API can be queried directly [6].

**Technology Fingerprinting Depth.** The current banner verification extracts Server/X-Powered-By headers and matches against ~30 technology patterns. This misses JavaScript framework detection (React, Angular, Vue versions from page source), CMS detection (WordPress plugin enumeration, Drupal module detection), WAF detection (Cloudflare, Akamai, AWS WAF behavioral signatures), and SaaS/third-party service detection (analytics, CDN, payment processors). Services like **Wappalyzer** (now part of BuiltWith) and **WhatRuns** provide comprehensive technology fingerprinting via API [7].

### 2.3 Discovery Gap Summary

| Gap | Severity | Current Coverage | Recommended Addition |
|-----|----------|-----------------|---------------------|
| Passive DNS aggregation | High | SecurityTrails only | Farsight DNSDB, VirusTotal pDNS, CircL |
| AS-level correlation | Medium | Basic RIPEstat | BGPView API, full prefix enumeration |
| Cloud asset discovery | High | None | S3/Azure/GCP bucket enumeration, cloud header detection |
| Reverse WHOIS | Medium | None | WhoisXML API, DomainTools reverse lookup |
| Code repository leakage | Medium | None | GitHub Search API, GitLab API |
| Deep technology fingerprinting | Medium | ~30 header patterns | Wappalyzer API, WhatRuns API |
| IPv6 enumeration | Low | Minimal | Censys IPv6, DNS AAAA brute-force |
| SPF/DMARC/DKIM analysis | Low | Basic SPF check only | Full email security posture analysis |

---

## 3. Gap Analysis — Enumeration Scanning

Enumeration scanning goes deeper than discovery — it identifies specific services, versions, configurations, and potential entry points on discovered assets. This is where the pipeline transitions from "what exists" to "what's running and how is it configured."

### 3.1 What We Have

The pipeline performs HTTP banner grabbing (Server, X-Powered-By, X-Generator headers), DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT), Shodan service banner analysis (product, version, CPE, CVEs), and Censys certificate and service data. The signal classifier detects exposed admin panels, open database ports, and staging environments.

### 3.2 What We're Missing

**Port and Service Enumeration Depth.** Shodan and Censys scan common ports but may miss non-standard ports. The pipeline currently relies entirely on what Shodan has already scanned. Adding **BinaryEdge** would provide an independent port/service scan dataset with different scanning schedules and port coverage. BinaryEdge scans over 3,500 ports compared to Shodan's default ~1,500, and provides structured vulnerability data including CVE mappings, JARM fingerprints, and SSH key analysis [8].

**TLS/SSL Configuration Analysis.** Beyond certificate validity, the pipeline does not assess TLS configuration quality: cipher suite strength, protocol versions supported (TLS 1.0/1.1 still enabled), certificate chain issues, HSTS deployment, and certificate pinning. The **SSL Labs API** (Qualys) provides free, detailed TLS grading that maps directly to security findings. **Censys** also provides TLS configuration data that could be extracted more thoroughly from existing observations [9].

**Web Application Enumeration.** The pipeline does not perform directory/path enumeration, robots.txt/sitemap.xml parsing, or common endpoint discovery (/.well-known/, /wp-admin/, /.env, /.git/). While the Wayback Machine provides historical URLs, active enumeration of common paths would reveal currently exposed sensitive endpoints. This could be done passively by checking URLScan.io results more thoroughly or by adding **CommonCrawl** data [10].

**DNS Zone Transfer and DNSSEC Analysis.** The pipeline checks basic DNS records but does not attempt zone transfers (AXFR), analyze DNSSEC deployment, or detect DNS misconfigurations like dangling CNAMEs (subdomain takeover vectors). Adding **DNSRecon**-style checks and **can-i-take-over-xyz** pattern matching would catch subdomain takeover vulnerabilities [11].

**Email Infrastructure Enumeration.** Beyond basic MX record discovery, the pipeline should enumerate: SMTP banner versions, SPF/DKIM/DMARC policy strength and alignment, email gateway products (Proofpoint, Mimecast, Microsoft Defender), and open relay testing. This is critical for phishing campaign design — the Campaigns tab already generates GoPhish templates but lacks intelligence about the target's email defenses [12].

**API Endpoint Discovery.** The pipeline detects API endpoints via URL patterns but does not attempt to discover OpenAPI/Swagger specifications, GraphQL introspection endpoints, or common API versioning patterns. Many organizations expose `/api/docs`, `/swagger.json`, `/graphql` with introspection enabled, or `/.well-known/openapi` — all of which reveal the full API attack surface [13].

### 3.3 Enumeration Gap Summary

| Gap | Severity | Impact on Pipeline | Recommended Addition |
|-----|----------|-------------------|---------------------|
| Extended port coverage | High | Missing non-standard services | BinaryEdge connector (3,500+ ports) |
| TLS configuration grading | Medium | No cipher/protocol assessment | SSL Labs API integration |
| Web path enumeration | Medium | Missing exposed sensitive files | CommonCrawl, enhanced URLScan parsing |
| Subdomain takeover detection | High | Missing dangling CNAME vulns | can-i-take-over-xyz pattern matching |
| Email defense enumeration | Medium | Phishing campaigns lack defense intel | SMTP banner, SPF/DKIM/DMARC deep analysis |
| API specification discovery | Medium | Missing full API attack surface | OpenAPI/Swagger/GraphQL endpoint probing |
| JARM/JA3 fingerprinting | Low | No TLS client/server fingerprinting | JARM hash computation, JA3 matching |

---

## 4. Vulnerability Validation — Beyond Shodan

Shodan currently serves as the primary vulnerability validation source, providing CVE detection from banner analysis and CPE matching. While powerful, Shodan has limitations: it scans on its own schedule (not on-demand), covers a subset of ports, and its CVE detection is based on version matching rather than actual exploit verification. To approach real vulnerability scanning fidelity, the platform should layer multiple passive and API-based validation sources.

### 4.1 Tier 1 — Passive Vulnerability Intelligence (No Active Scanning)

These services provide vulnerability data derived from internet-wide scanning that has already been performed. They require no active probing of the target.

**Shodan InternetDB + CVEDB APIs.** Shodan offers two lightweight APIs beyond the main search API. The **InternetDB API** (`internetdb.shodan.io/{ip}`) provides free, instant lookups of open ports, CVEs, CPEs, hostnames, and tags for any IP — no API key required, no rate limits. The **CVEDB API** (`cvedb.shodan.io`) provides fast CVE lookups by CVE-ID or CPE2.3 string, returning affected products, CVSS scores, and references. These should be integrated as a fast-path enrichment layer that runs before the full Shodan API queries [14].

**BinaryEdge.** BinaryEdge maintains an independent internet-wide scanning platform that provides vulnerability data through a structured API. Key advantages over Shodan: broader port coverage (3,500+), JARM TLS fingerprinting, SSH key analysis, torrent activity monitoring, and a different scanning schedule that may catch services Shodan missed. The API returns CVE matches, CPE strings, and detailed service metadata. BinaryEdge also provides a **dataleaks** endpoint for credential exposure data, complementing Dehashed [8].

**Censys (Enhanced Integration).** The current Censys connector extracts certificates and basic service data, but Censys provides significantly more vulnerability-relevant information: detailed TLS configuration, HTTP response bodies, JARM fingerprints, and software version detection. The Censys Search 2.0 API supports structured queries like `services.software.product = "Apache" AND services.software.version < "2.4.50"` that can directly identify vulnerable versions. The pipeline should extract and cross-reference this data more thoroughly [15].

**GreyNoise.** GreyNoise provides a unique perspective: it monitors which IPs are actively scanning or being scanned on the internet. For vulnerability validation, GreyNoise can tell you whether a target IP is being actively targeted by exploit scanners (indicating attackers believe it's vulnerable), whether the target IP itself is scanning others (indicating compromise), and which CVEs are being mass-exploited right now. The **GreyNoise RIOT** dataset identifies known-benign scanners, while the **NOISE** dataset identifies malicious scanners. This contextual intelligence adds a "threat pressure" dimension to vulnerability findings [16].

**Criminal IP.** Criminal IP is a newer internet scanning platform that provides vulnerability detection, phishing site detection, and malicious IP identification through its API. It offers a "Domain Search" feature that returns technology stacks, open ports, CVEs, and security scores. Its advantage is a focus on criminal infrastructure detection — identifying whether target assets appear in phishing campaigns, C2 infrastructure, or malware distribution networks [17].

### 4.2 Tier 2 — API-Based Active Scanning Platforms

These services perform on-demand active scanning through their APIs. They provide the closest approximation to traditional vulnerability scanning without requiring the operator to run their own scanner.

**ProjectDiscovery Cloud Platform (PDCP).** ProjectDiscovery, the creators of Nuclei, offer a cloud-based scanning platform with an API. Nuclei's template library contains over 9,000 vulnerability detection templates maintained by the security community. PDCP can run these templates against target assets on-demand, detecting real vulnerabilities through actual HTTP requests, not just version matching. This is the single most impactful addition for closing the gap between passive intelligence and real vulnerability scanning. The API supports: asset discovery (subfinder, httpx), vulnerability scanning (nuclei templates), and results export in structured JSON [18].

**Detectify.** Detectify is an EASM platform that performs continuous external scanning using a crowdsourced vulnerability research model. Their API supports on-demand scans, asset monitoring, and finding export. Detectify's scanner goes beyond version matching — it sends actual exploit payloads (safely) to detect vulnerabilities like XSS, SQLi, SSRF, and misconfigurations. Their "Crowdsource" program means new vulnerability checks are added within days of disclosure [19].

**Intruder.** Intruder provides cloud-based vulnerability scanning with an API that supports scan initiation, result retrieval, and continuous monitoring. It combines network scanning (open ports, services) with web application scanning (OWASP Top 10) and cloud configuration checks. The API is straightforward for integration and supports webhook notifications for new findings [20].

**Qualys External Scanning.** Qualys offers an API for external vulnerability scanning that can be triggered programmatically. The Qualys VMDR (Vulnerability Management, Detection, and Response) API supports launching scans, retrieving results, and managing scan schedules. Qualys has the largest vulnerability detection signature database in the industry (200,000+), making it the gold standard for comprehensive vulnerability assessment [21].

**Tenable.io.** Tenable's cloud platform provides API access to Nessus-powered scanning. The API supports scan creation, launch, and result export in multiple formats. Tenable's advantage is its plugin library (180,000+ checks) and its integration with the Tenable Vulnerability Priority Rating (VPR) system, which uses machine learning to predict which vulnerabilities are most likely to be exploited [22].

### 4.3 Tier 3 — User-Uploaded Scan Results

For true validated vulnerability data, the platform should accept uploads from scanners that operators have run themselves. This is the highest-fidelity data source because it represents actual scan results from the target environment.

**Supported Upload Formats:**

| Format | Source Scanner | File Extension | Structure |
|--------|---------------|---------------|-----------|
| Nessus XML | Tenable Nessus | `.nessus` | XML with ReportHost/ReportItem elements |
| Qualys XML | Qualys VMDR | `.xml` | XML with HOST/VULN elements |
| OpenVAS XML | Greenbone/OpenVAS | `.xml` | XML with result/nvt elements |
| Nuclei JSON | ProjectDiscovery Nuclei | `.json`, `.jsonl` | JSON lines with template-id, matched-at, severity |
| SARIF | Multiple (Snyk, Semgrep, etc.) | `.sarif` | OASIS standard JSON for static analysis results |
| CSV/Generic | Any scanner | `.csv` | Columns: IP, Port, CVE, Severity, Description |
| Burp XML | PortSwigger Burp Suite | `.xml` | XML with issue elements |
| Nmap XML | Nmap | `.xml` | XML with host/port/script elements |

**Upload Integration Architecture:**

The upload system should normalize all formats into the existing `PostureFinding` schema, automatically setting `corroborationTier: "confirmed"` and `evidenceBasis: "scan_upload"` since these represent validated findings. The evidence chain should record the source scanner, scan date, and original finding ID for traceability.

```
User Upload → Format Detection → Parser (per format) → Normalized PostureFinding[]
  → CVE Enrichment (NVD/KEV lookup) → Exploit Matching → Merge with Scan Results
```

### 4.4 Validation Source Comparison Matrix

| Source | Type | CVE Detection | Version Matching | Exploit Verification | Cost | API Complexity | Priority |
|--------|------|--------------|-----------------|---------------------|------|---------------|----------|
| **Shodan** (current) | Passive | Banner-based | CPE matching | No | $59/mo | Low | Already integrated |
| **Shodan InternetDB** | Passive | Pre-computed | Pre-computed | No | Free | Trivial | **P0 — Immediate** |
| **BinaryEdge** | Passive | Banner-based | CPE matching | No | $40/mo | Low | **P1 — High** |
| **Censys (enhanced)** | Passive | Version-based | Software detection | No | Free tier available | Medium | **P1 — High** |
| **GreyNoise** | Passive | Threat context | N/A | Exploit traffic detection | Free community tier | Low | **P1 — High** |
| **VirusTotal** | Passive | Domain reputation | N/A | Malware detection | Free tier (500/day) | Low | **P2 — Medium** |
| **Criminal IP** | Passive | Banner-based | Service detection | No | Free tier available | Low | **P2 — Medium** |
| **PDCP/Nuclei Cloud** | Active API | Template-based | Actual probing | Yes (safe payloads) | Free tier (100 scans) | Medium | **P1 — High** |
| **Detectify** | Active API | Crowdsourced | Actual probing | Yes | Enterprise pricing | Medium | **P2 — Medium** |
| **Qualys** | Active API | Signature-based | Actual probing | Yes | Enterprise pricing | High | **P3 — Future** |
| **Tenable.io** | Active API | Plugin-based | Actual probing | Yes | Enterprise pricing | High | **P3 — Future** |
| **Scan Uploads** | User-provided | Scanner-dependent | Scanner-dependent | Yes (validated) | Free | Medium (parsing) | **P1 — High** |

---

## 5. Enhancement Roadmap

### Phase 1 — Immediate (Next Sprint)

These enhancements require minimal new infrastructure and provide the highest return on investment.

**1a. Shodan InternetDB Fast-Path Enrichment.** Add a pre-enrichment step that queries `internetdb.shodan.io/{ip}` for every resolved IP before the full Shodan API call. This is free, has no rate limits, and provides instant CVE/port/CPE data. Implementation: ~50 lines of code in a new `shodan-internetdb.ts` connector.

**1b. BinaryEdge Connector.** Add BinaryEdge as a 10th passive connector. The API provides host search, dataleaks, and torrent monitoring. This immediately doubles the passive vulnerability validation coverage by providing an independent scanning dataset. Implementation: new `binaryedge.ts` connector following the existing `PassiveConnector` interface.

**1c. GreyNoise Threat Context.** Add GreyNoise lookups for all resolved IPs. Tag assets that are being actively targeted by exploit scanners with a "UNDER ACTIVE ATTACK" signal. Tag assets that are scanning others with a "POTENTIALLY COMPROMISED" signal. Implementation: new `greynoise.ts` connector.

**1d. Enhanced Censys Data Extraction.** The existing Censys connector should extract TLS configuration details, HTTP response metadata, and software version data more thoroughly. This is a code enhancement to the existing connector, not a new integration.

### Phase 2 — Near-Term (1–2 Sprints)

**2a. Scan Upload System.** Build the upload endpoint and parsers for Nessus XML, Nuclei JSON, Nmap XML, and generic CSV. This is the fastest path to "true validated weakness exposures" because operators can run their own Nessus/Nuclei scans and import the results. The uploaded findings merge into the existing PostureFinding pipeline with `corroborationTier: "confirmed"`.

**2b. ProjectDiscovery Cloud Integration.** Integrate PDCP's API to run Nuclei templates against discovered assets on-demand. This provides actual exploit verification (not just version matching) through safe payload delivery. The "Scan with Nuclei" button would appear on the Domain Intel results page.

**2c. Subdomain Takeover Detection.** Add CNAME dangling detection using the `can-i-take-over-xyz` fingerprint database. Check all CNAME records against known takeover-vulnerable services (GitHub Pages, Heroku, AWS S3, Azure, etc.). These are high-severity, easily exploitable findings.

**2d. Cloud Asset Discovery.** Add S3/Azure/GCP bucket enumeration derived from the target domain name. Check for common patterns like `{domain}-backup`, `{domain}-dev`, `{domain}-staging` across cloud storage services.

### Phase 3 — Medium-Term (3–4 Sprints)

**3a. Passive DNS Aggregation.** Integrate Farsight DNSDB or VirusTotal passive DNS to discover subdomains invisible to CT logs. This significantly expands the discovery surface for organizations with large internal DNS footprints.

**3b. Deep Technology Fingerprinting.** Integrate Wappalyzer API for comprehensive technology detection including JavaScript frameworks, CMS plugins, WAF products, and analytics services. This improves CVE matching accuracy by identifying more technologies.

**3c. Email Defense Intelligence.** Add SMTP banner analysis, SPF/DKIM/DMARC policy grading, and email gateway detection. Feed this intelligence into the phishing campaign design stage so GoPhish templates account for the target's email defenses.

**3d. Enterprise Scanner API Integration.** Build integration modules for Qualys VMDR API and Tenable.io API, allowing operators to trigger scans from the dashboard and import results automatically. This requires the operator to have their own Qualys/Tenable subscription.

### Phase 4 — Long-Term (5+ Sprints)

**4a. Continuous Monitoring Mode.** Transform the pipeline from on-demand scanning to continuous monitoring. Assets discovered in previous scans are re-checked on a schedule. New subdomains, changed services, and new CVEs trigger alerts.

**4b. STIX/TAXII Export.** Export all findings, threat actor matches, and campaign recommendations in STIX 2.1 format for integration with enterprise SIEM/SOAR platforms.

**4c. Reverse WHOIS and Corporate Hierarchy.** Discover all domains owned by the target organization through registrant correlation, then automatically expand the scan scope to include subsidiary and acquired company domains.

---

## 6. Proposed Architecture for Scan Upload & API Scanner Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOMAIN INTEL PIPELINE                         │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Passive  │  │ Active   │  │ API-Based│  │  User    │       │
│  │ Recon    │  │ Verify   │  │ Scanners │  │ Uploads  │       │
│  │ (9+3     │  │ (DNS +   │  │ (Nuclei  │  │ (Nessus  │       │
│  │ connectors)│ │ Banner)  │  │ Qualys   │  │ Nmap     │       │
│  │          │  │          │  │ Tenable) │  │ Burp     │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │              │             │
│       ▼              ▼              ▼              ▼             │
│  ┌──────────────────────────────────────────────────────┐       │
│  │           UNIFIED FINDING NORMALIZER                  │       │
│  │  AssetObservation → PostureFinding → CorroborationTier│      │
│  │                                                       │       │
│  │  Sources:          Tier Assignment:                    │       │
│  │  - passive_recon → potential/probable                  │       │
│  │  - banner_verify → probable                           │       │
│  │  - shodan_vuln   → confirmed                          │       │
│  │  - binaryedge    → probable/confirmed                 │       │
│  │  - nuclei_scan   → confirmed                          │       │
│  │  - nessus_upload → confirmed                          │       │
│  │  - qualys_api    → confirmed                          │       │
│  └──────────────────────┬────────────────────────────────┘       │
│                         │                                        │
│                         ▼                                        │
│  ┌──────────────────────────────────────────────────────┐       │
│  │           EVIDENCE CORRELATION ENGINE                  │       │
│  │  Cross-reference findings across sources:              │       │
│  │  - Same CVE from 2+ sources → boost confidence         │       │
│  │  - Shodan + BinaryEdge agree → confirmed               │       │
│  │  - Nuclei exploit success → confirmed + exploitable    │       │
│  │  - Nessus upload + passive match → highest confidence  │       │
│  └──────────────────────┬────────────────────────────────┘       │
│                         │                                        │
│                         ▼                                        │
│  ┌──────────────────────────────────────────────────────┐       │
│  │     EXPLOIT MATCHING → CAMPAIGN DESIGN → REPORTING    │       │
│  └──────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### 6.1 Evidence Correlation Engine

The most impactful architectural enhancement is an **Evidence Correlation Engine** that cross-references findings across multiple sources. When the same CVE is detected by both Shodan and BinaryEdge, confidence should increase. When a Nuclei template successfully exploits a vulnerability that was flagged as "probable" by passive scanning, it should be upgraded to "confirmed + exploitable." When a user uploads Nessus results that match passive findings, the combined evidence should produce the highest confidence tier.

The correlation engine would assign a **composite confidence score** based on:

| Evidence Combination | Composite Confidence | Tier |
|---------------------|---------------------|------|
| Single passive source, no version | 0.3–0.5 | Potential |
| Single passive source, version matched | 0.6–0.7 | Probable |
| Two passive sources agree, version matched | 0.8–0.85 | Confirmed |
| Passive + active scanner (Nuclei/Detectify) | 0.9–0.95 | Confirmed |
| Passive + user upload (Nessus/Qualys) | 0.95–0.99 | Confirmed |
| Active scanner exploit success | 0.95+ | Confirmed + Exploitable |

### 6.2 Upload System Schema

The scan upload system should store metadata about each upload and link findings back to the source:

```sql
CREATE TABLE scan_uploads (
  id INT PRIMARY KEY AUTO_INCREMENT,
  engagement_id INT NOT NULL,
  scanner_type ENUM('nessus', 'qualys', 'openvas', 'nuclei', 'nmap', 'burp', 'sarif', 'csv'),
  filename VARCHAR(255),
  upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  scan_date TIMESTAMP,
  findings_count INT DEFAULT 0,
  critical_count INT DEFAULT 0,
  high_count INT DEFAULT 0,
  status ENUM('processing', 'complete', 'error') DEFAULT 'processing',
  uploaded_by VARCHAR(255),
  s3_key VARCHAR(512),
  FOREIGN KEY (engagement_id) REFERENCES domain_intel_scans(id)
);

CREATE TABLE upload_findings (
  id INT PRIMARY KEY AUTO_INCREMENT,
  upload_id INT NOT NULL,
  original_finding_id VARCHAR(255),
  cve_id VARCHAR(20),
  host VARCHAR(255),
  port INT,
  severity DECIMAL(3,1),
  title TEXT,
  description TEXT,
  solution TEXT,
  evidence TEXT,
  corroboration_tier ENUM('confirmed') DEFAULT 'confirmed',
  merged_with_finding_id VARCHAR(255),
  FOREIGN KEY (upload_id) REFERENCES scan_uploads(id)
);
```

---

## 7. Priority Implementation Matrix

| Priority | Enhancement | Effort | Impact | Dependencies |
|----------|------------|--------|--------|-------------|
| **P0** | Shodan InternetDB fast-path | 2 hours | High | None |
| **P1** | BinaryEdge connector | 1 day | High | API key ($40/mo) |
| **P1** | GreyNoise connector | 1 day | High | Free community API |
| **P1** | Scan upload system (Nessus + Nuclei) | 3 days | Very High | S3 storage, parsers |
| **P1** | PDCP/Nuclei Cloud integration | 2 days | Very High | PDCP API key |
| **P1** | Subdomain takeover detection | 1 day | High | None |
| **P2** | Enhanced Censys extraction | 4 hours | Medium | Existing API key |
| **P2** | Cloud asset discovery | 1 day | Medium | None |
| **P2** | Criminal IP connector | 1 day | Medium | Free tier API |
| **P2** | VirusTotal domain analysis | 4 hours | Medium | Free tier API |
| **P2** | SSL Labs TLS grading | 4 hours | Medium | Free API |
| **P3** | Qualys/Tenable API integration | 3 days | High | Enterprise subscription |
| **P3** | Passive DNS (Farsight DNSDB) | 1 day | Medium | Enterprise subscription |
| **P3** | Wappalyzer tech fingerprinting | 1 day | Medium | API key |
| **P3** | Email defense intelligence | 2 days | Medium | None |
| **P4** | Evidence Correlation Engine | 3 days | Very High | Multiple sources integrated |
| **P4** | Continuous monitoring mode | 5 days | Very High | Scheduler, DB changes |
| **P4** | STIX/TAXII export | 2 days | Medium | None |

---

## 8. Conclusion

The current domain intelligence pipeline is architecturally sound — the 9-connector passive recon, 3-tier corroboration system, and Shodan-based CVE verification provide a strong foundation. The primary gaps are in **discovery breadth** (passive DNS, cloud assets, reverse WHOIS), **enumeration depth** (extended port coverage, TLS grading, subdomain takeover), and **vulnerability validation fidelity** (only Shodan currently provides CVE confirmation).

The highest-impact enhancements are: (1) adding BinaryEdge and GreyNoise as independent passive validation sources to corroborate Shodan findings, (2) integrating ProjectDiscovery's Nuclei Cloud for actual exploit verification, and (3) building the scan upload system so operators can import Nessus/Qualys/Nuclei results as ground-truth validated findings. Together, these three additions would transform the platform from "passive intelligence with Shodan verification" to "multi-source validated vulnerability assessment with active scanning capability" — approaching the fidelity of dedicated vulnerability management platforms while maintaining the platform's passive-first, API-driven architecture.

---

## References

[1] Farsight Security DNSDB — https://www.farsightsecurity.com/solutions/dnsdb/  
[2] CircL Passive DNS — https://www.circl.lu/services/passive-dns/  
[3] BGPView API — https://bgpview.docs.apiary.io/  
[4] AWS S3 Bucket Enumeration — https://github.com/nahamsec/lazys3  
[5] WhoisXML API Reverse WHOIS — https://whoisxmlapi.com/reverse-whois-api  
[6] GitHub Code Search API — https://docs.github.com/en/rest/search/search  
[7] Wappalyzer API — https://www.wappalyzer.com/docs/api/  
[8] BinaryEdge API Documentation — https://docs.binaryedge.io/  
[9] SSL Labs API — https://www.ssllabs.com/projects/ssllabs-apis/  
[10] CommonCrawl — https://commoncrawl.org/  
[11] Can I Take Over XYZ — https://github.com/EdOverflow/can-i-take-over-xyz  
[12] MX Toolbox API — https://mxtoolbox.com/  
[13] OWASP API Security Top 10 — https://owasp.org/API-Security/  
[14] Shodan InternetDB API — https://internetdb.shodan.io/  
[15] Censys Search 2.0 API — https://search.censys.io/api  
[16] GreyNoise API — https://docs.greynoise.io/  
[17] Criminal IP API — https://www.criminalip.io/developer  
[18] ProjectDiscovery Cloud — https://cloud.projectdiscovery.io/  
[19] Detectify API — https://developer.detectify.com/  
[20] Intruder API — https://developers.intruder.io/  
[21] Qualys VMDR API — https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf  
[22] Tenable.io API — https://developer.tenable.com/reference/  
