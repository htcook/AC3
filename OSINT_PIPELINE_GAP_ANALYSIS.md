# OSINT Pipeline Gap Analysis — Caldera Dashboard

**Author:** Manus AI | **Date:** March 17, 2026 | **Version:** 1.0

---

## 1. Executive Summary

The Caldera Dashboard currently operates a robust passive reconnaissance pipeline with **30+ connectors** spanning DNS, certificate transparency, breach databases, cloud asset enumeration, and threat intelligence feeds. However, a gap analysis reveals three critical blind spots that limit the platform's ability to generate accurate Business Impact Analyses (BIA), contextualize risk scores, and operationalize engagement planning:

1. **Darkweb depth is shallow** — the platform ingests IOC feeds (abuse.ch, ransomware.live, HIBP) but does not actively search for domain-specific stealer logs, paste site leaks, or underground forum mentions tied to the target organization.

2. **Company and product intelligence is incomplete** — the `org-enrichment.ts` module scrapes the target's website and uses LLM inference, but does not pull structured firmographic data from business data brokers (LinkedIn, Yahoo Finance, SEC EDGAR) or technology profiling APIs (BuiltWith/Wappalyzer-style detection).

3. **Regulatory framework detection is heuristic-only** — the LLM guesses applicable frameworks from website content, but does not cross-reference industry classification codes (SIC/NAICS), SEC filings, privacy policy language, or data-type indicators to produce a validated regulatory profile.

4. **Breach credentials are not operationalized** — DeHashed returns leaked email/password pairs, but these are stored only as OSINT observations. They are never populated into the engagement's credential attack lists for use against login forms during red team operations.

This report details each gap, maps the data sources available to close it, and provides an implementation plan.

---

## 2. Current Pipeline Inventory

### 2.1 Passive Reconnaissance Connectors (30 active)

The following table summarizes every connector currently registered in `server/lib/passive/index.ts`:

| Connector | Category | API Key Required | Data Provided |
|---|---|---|---|
| Shodan InternetDB | Infrastructure | No | Ports, CVEs, hostnames (fast path) |
| crt.sh | Certificates | No | Certificate transparency logs, subdomains |
| Shodan | Infrastructure | Yes | Open ports, services, banners, vulns, OS |
| Wayback Machine | Historical | No | Historical URLs, archived pages |
| Censys | Infrastructure | Yes | Services, TLS certs, autonomous systems |
| URLScan | Web Analysis | Yes | Screenshots, DOM, requests, technologies |
| RDAP | Registration | No | Domain registration data |
| RIPEstat | Network | No | ASN, IP prefix, routing data |
| SecurityTrails | DNS/WHOIS | Yes | Subdomains, DNS history, WHOIS, associated domains |
| DeHashed | Breaches | Yes | Leaked emails, passwords, IPs, breach databases |
| Coalition Control | ASM | No | Attack surface management (replaced BinaryEdge) |
| GreyNoise | Threat Pressure | No | IP noise/threat classification |
| Email Security | Email | No | SPF, DKIM, DMARC posture analysis |
| HTTP Security | Web | No | Security headers, WAF detection |
| Cloud Assets | Cloud | No | S3/Azure/GCP bucket enumeration |
| Container Discovery | Infrastructure | No | Docker/K8s/registry exposure |
| DNS Deep | DNS | No | Comprehensive DNS record analysis |
| GitHub Leaks | Code Exposure | Yes | Secret/credential leaks in public repos |
| GitHub Recon | Code Exposure | Yes | Org discovery, repo enum, CI/CD, dorks |
| Cloud Bucket Recon | Cloud | No | Cloud storage misconfiguration |
| VirusTotal | Reputation | Yes | File/URL/domain reputation, malware |
| HIBP | Breaches | No | Breach exposure catalog |
| WhoisXML | WHOIS/DNS | Yes | WHOIS records, DNS, subdomain enum |
| LeakIX | Data Leaks | No | Exposed services, data leaks |
| FullHunt | ASM | Yes | Attack surface discovery |
| Netlas | Infrastructure | Yes | Internet-wide scanning, DNS history |
| Hunter.io | Email/Org | Yes | Email discovery, org intelligence |
| Social Media | Social | No | GitHub org/user presence |
| AbuseIPDB | IP Reputation | Yes | IP abuse scoring |
| PassiveTotal | DNS/SSL | Yes | Passive DNS, SSL history, host attributes |

### 2.2 Darkweb Intelligence Feeds (13 built-in)

The `darkweb-osint-service.ts` module provides IOC-level feed ingestion:

| Feed | Provider | Type | Update Interval |
|---|---|---|---|
| URLhaus | abuse.ch | Malicious URLs | 6h |
| ThreatFox | abuse.ch | Campaign IOCs | 6h |
| Feodo Tracker | abuse.ch | Botnet C2 IPs | 6h |
| MalwareBazaar | abuse.ch | Malware samples | 12h |
| SSL Blacklist | abuse.ch | Malicious SSL certs | Daily |
| Ransomware Victims | ransomware.live | Victim reports | 6h |
| Ransomware Groups | ransomware.live | Group profiles | Daily |
| AlienVault OTX | AlienVault | Community IOCs | 6h |
| OpenPhish | OpenPhish | Phishing URLs | 6h |
| Tor Exit Nodes | TorProject | Exit node IPs | Daily |
| Blocklist.de | blocklist.de | Attack IPs | Daily |
| Spamhaus DROP | Spamhaus | Hijacked IP ranges | Daily |
| HIBP Breaches | HIBP | Breach catalog | Daily |

### 2.3 Organization Enrichment (org-enrichment.ts)

The current `OrgProfile` data model captures:

| Field | Current Source | Quality |
|---|---|---|
| Company Name | Website scrape + LLM inference | Medium — depends on website quality |
| Industry / Sector | LLM inference from website content | Medium — no SIC/NAICS validation |
| Description | LLM summary of scraped content | Good |
| Products & Services | LLM extraction from headings/paragraphs | Medium — misses B2B/internal products |
| Technologies | HTTP headers + HTML pattern matching | Good for frontend, weak for backend |
| Employee Count | LLM estimate | Low — no authoritative source |
| Locations | LLM extraction | Low — often incomplete |
| Financials | LLM inference | Very Low — no market data source |
| Regulatory Context | LLM guess from website mentions | Low — no cross-referencing |
| Social Media Links | HTML link extraction | Medium |

### 2.4 BIA Scoring Integration

The scoring engine (`server/lib/industry-baseline-scoring.ts`) uses:

- **AUTO_BIA_RULES** — 6 signal-to-asset mappings (MX Record, SSO, Payment, Admin, Database, Git)
- **SIGNAL_PATTERNS** — 12 regex patterns for hostname/service matching
- **FIPS 199 categorization** — industry-tier defaults for C/I/A levels
- **CARVER+Shock scoring** — 7-factor target analysis
- **LLM-based BIA generation** — uses `buildLLMPromptForBIA()` with org profile + Shodan + DNS data

**Critical gap:** The LLM prompt for BIA currently receives org profile data, Shodan data, and DNS data — but **no darkweb context, no breach history, no stealer log exposure, and no validated regulatory framework**. This means the LLM cannot factor in real-world compromise evidence when scoring business impact.

---

## 3. Identified Gaps

### Gap 1: Darkweb Intelligence — Shallow Depth, No Domain-Specific Search

**Current state:** The platform ingests generic IOC feeds (abuse.ch, ransomware.live) and has a HIBP connector for breach catalog lookups. DeHashed searches for leaked credentials by domain.

**What's missing:**

| Capability | Status | Impact |
|---|---|---|
| Stealer log search by domain | Missing | Cannot detect if employee credentials are actively sold in infostealer marketplaces |
| Paste site monitoring (Pastebin, Ghostbin, etc.) | Missing | Cannot detect leaked configs, API keys, or internal documents |
| Underground forum mention search | Missing | Cannot detect if the target org is being discussed as a potential victim |
| Ransomware leak site domain matching | Partial | ransomware.live ingests victims but does not match against engagement target domains |
| Telegram channel monitoring | Missing | Cannot detect credential dumps or breach announcements on Telegram |
| Dark web marketplace listing search | Missing | Cannot detect if access to the target is being sold (RDP, VPN, webshell) |

**Recommended data sources to add:**

1. **Intelligence X (IntelX)** — Search engine for darkweb, paste sites, leaked databases. API provides domain/email search across Tor, I2P, and paste sites. Returns leaked documents, credentials, and forum posts.

2. **Hudson Rock** — Stealer log intelligence platform. API searches for compromised credentials from infostealer infections by domain. Returns stolen cookies, saved passwords, and session tokens.

3. **LeakCheck** — Credential leak search API. Searches across 15B+ leaked records by domain/email. Returns breach source, password (hashed or plain), and breach date.

4. **Ransomware.live victim matching** — Already ingested but not cross-referenced against engagement target domains. Need to add domain-matching logic.

5. **Abuse.ch domain-specific IOC correlation** — Already ingested but not filtered by target domain. Need to add target-domain correlation to surface relevant IOCs.

### Gap 2: Company & Product Intelligence — No Structured Business Data

**Current state:** The `org-enrichment.ts` module scrapes the target's homepage and uses LLM inference to extract company information. This works for companies with informative websites but fails for B2B companies, subsidiaries, or organizations with minimal web presence.

**What's missing:**

| Data Point | Current Source | Gap | BIA/Scoring Impact |
|---|---|---|---|
| Official company name & legal entity | Website scrape | No authoritative source | Affects WHOIS correlation and subsidiary mapping |
| Industry classification (SIC/NAICS) | LLM guess | No validated code | Cannot apply correct industry risk modifiers |
| Employee count | LLM estimate | No authoritative data | Affects org size tier and BIA scale |
| Revenue / market cap | None | Completely missing | Cannot estimate financial impact of breach |
| Headquarters & office locations | LLM extraction | Often incomplete | Affects jurisdiction and regulatory mapping |
| Executive team / key personnel | None | Completely missing | Cannot assess social engineering targets |
| Technology stack (full) | HTML pattern matching | Only detects frontend tech | Misses backend, database, cloud provider |
| Subsidiaries & parent company | None | Completely missing | Cannot map full attack surface |
| Funding stage / investors | None | Completely missing | Affects target value assessment |
| Business description (authoritative) | LLM summary | Depends on website quality | Core input to BIA mission function mapping |

**Recommended data sources to add:**

1. **LinkedIn Company API** (via Manus Data API `LinkedIn/get_company_details`) — Returns company name, industry, employee count, specialties, description, headquarters, website, Crunchbase URL. Already available as a built-in Data API.

2. **Yahoo Finance Stock Profile** (via Manus Data API `YahooFinance/get_stock_profile`) — For publicly traded companies: sector, industry, employee count, market cap, revenue, business summary, executive team, address. Already available as a built-in Data API.

3. **SEC EDGAR API** (free, no key required) — SIC code, filing history, company CIK lookup by domain/name. Provides authoritative industry classification for US public companies.

4. **BuiltWith-style technology detection** — Extend the existing HTML pattern matching in `org-enrichment.ts` with deeper analysis: meta generators, script src patterns, cookie names, DNS TXT records (e.g., `_amazonses`, `google-site-verification`), and Wappalyzer-compatible fingerprinting.

5. **Crunchbase** (via LinkedIn Crunchbase URL) — Funding rounds, investors, acquisitions, founding date. Can be scraped from the Crunchbase URL returned by LinkedIn API.

### Gap 3: Regulatory Framework Detection — No Systematic Inference

**Current state:** The LLM prompt in `buildLLMPromptForOrgProfile()` asks the LLM to guess applicable frameworks from website content. This produces inconsistent results and misses frameworks that are not explicitly mentioned on the website.

**What's missing:**

| Detection Method | Status | Frameworks Detected |
|---|---|---|
| Industry-to-framework mapping (SIC/NAICS) | Missing | HIPAA, GLBA, NERC CIP, FISMA, FERPA |
| Data type inference from products/services | Partial (LLM guess) | PCI-DSS, HIPAA, GDPR, CCPA |
| Geographic jurisdiction mapping | Missing | GDPR, CCPA, PIPEDA, LGPD, state privacy laws |
| SEC filing / public company detection | Missing | SOX, SEC reporting requirements |
| Government contract indicators | Missing | CMMC, FedRAMP, ITAR, DFARS |
| Privacy policy language analysis | Missing | GDPR, CCPA, COPPA indicators |
| Website compliance badge detection | Missing | SOC 2, ISO 27001, PCI-DSS, HITRUST |

**Recommended approach — LLM-powered regulatory inference engine:**

Build a deterministic rule engine combined with LLM analysis that takes the enriched company profile (industry code, data types, locations, products, SEC status) and produces a validated regulatory profile. The engine should:

1. **Map SIC/NAICS codes to mandatory frameworks** — e.g., SIC 8000-8099 (Healthcare) triggers HIPAA; SIC 6000-6199 (Banking) triggers GLBA/SOX.

2. **Detect data types from product descriptions** — e.g., "patient portal" implies PHI (HIPAA); "payment processing" implies cardholder data (PCI-DSS).

3. **Map geographic presence to jurisdiction** — e.g., EU operations trigger GDPR; California presence triggers CCPA.

4. **Detect government contract indicators** — e.g., ".gov" email domains, GSA schedule mentions, CAGE/DUNS numbers imply CMMC/FedRAMP.

5. **Analyze privacy policy and terms of service** — scrape and LLM-analyze for explicit framework mentions, data processing disclosures, and DPA references.

6. **Detect compliance badges/certifications** — scan website for SOC 2, ISO 27001, HITRUST, FedRAMP logos and text mentions.

### Gap 4: Breach Credentials Not Operationalized

**Current state:** DeHashed returns leaked email/password pairs as OSINT observations with `assetType: "breach"`. These are displayed in the domain intel dashboard but never flow into the engagement's credential attack infrastructure.

**What's needed:**

1. **Extract username/password pairs from DeHashed observations** — parse the `evidence` field for email addresses and associated passwords (plaintext or hashed).

2. **Create a new `engagementBreachedCredentials` table** (or extend `credentialFindings`) — store domain, email, password, breach source, breach date, hash type, and engagement linkage.

3. **Auto-populate credential attack wordlists** — when a domain intel scan completes for an engagement, automatically extract all breached credentials and add them to the engagement's credential attack configuration.

4. **Surface in the UI** — show a "Breached Credentials" tab in the engagement view with the count of leaked accounts, breach sources, and a button to launch credential stuffing/spraying attacks using the discovered credentials.

---

## 4. Data Flow Architecture — Current vs. Proposed

### Current Flow

```
Target Domain → Passive Connectors (30) → Observations → Signal Classifier → Scoring Engine
                                                                                    ↓
Target Domain → Website Scrape → LLM Org Profile → BIA Prompt → LLM BIA → CARVER/Shock Scores
                                                                                    ↓
IOC Feeds (13) → Darkweb Events DB → Dashboard Display (no domain correlation)
```

### Proposed Flow

```
Target Domain → Passive Connectors (30) → Observations → Signal Classifier ──┐
                                                                               ↓
Target Domain → Website Scrape ──────────────────────────────────────────────→ │
Target Domain → LinkedIn API ────→ Firmographics ────────────────────────────→ │
Target Domain → Yahoo Finance ───→ Financial Data ───────────────────────────→ │
Target Domain → SEC EDGAR ───────→ SIC Code + Filings ──────────────────────→ │
Target Domain → Deep Tech Detection → Full Tech Stack ──────────────────────→ │
                                                                               ↓
                                                              LLM Org Profile (enriched)
                                                                               ↓
Target Domain → IntelX API ──────→ Paste/Darkweb Mentions ──────────────────→ │
Target Domain → Hudson Rock ─────→ Stealer Log Exposure ────────────────────→ │
Target Domain → LeakCheck ───────→ Credential Leaks ────────────────────────→ │
Target Domain → DeHashed ────────→ Breach Records ──→ Engagement Cred Lists  │
Target Domain → Ransomware.live ─→ Victim Matching ─────────────────────────→ │
                                                                               ↓
                                                    Regulatory Framework Inference Engine
                                                    (SIC→Framework + Data Type + Jurisdiction + LLM)
                                                                               ↓
                                                         Enriched BIA Prompt → LLM BIA
                                                         (org + darkweb + regulatory + breach context)
                                                                               ↓
                                                              CARVER/Shock/CVSS Hybrid Scores
                                                              (with breach exposure multiplier)
```

---

## 5. Implementation Plan

### Phase 1: New Passive Connectors (Darkweb + Company Intel)

| Connector | File | Priority | API Key Env Var | Estimated LOC |
|---|---|---|---|---|
| Intelligence X (IntelX) | `server/lib/passive/intelx.ts` | High | `INTELX_API_KEY` | ~180 |
| Hudson Rock Stealer Logs | `server/lib/passive/hudson-rock.ts` | High | `HUDSONROCK_API_KEY` | ~150 |
| LeakCheck Credentials | `server/lib/passive/leakcheck.ts` | Medium | `LEAKCHECK_API_KEY` | ~140 |
| LinkedIn Company Intel | `server/lib/passive/linkedin-company.ts` | High | Built-in Data API | ~160 |
| Yahoo Finance Profile | `server/lib/passive/yahoo-finance.ts` | Medium | Built-in Data API | ~140 |
| SEC EDGAR Lookup | `server/lib/passive/sec-edgar.ts` | Medium | None (free) | ~180 |
| Deep Tech Fingerprinting | `server/lib/passive/tech-fingerprint.ts` | Medium | None | ~200 |

### Phase 2: Regulatory Framework Inference Engine

| Component | File | Description |
|---|---|---|
| SIC/NAICS-to-Framework Map | `server/lib/regulatory-framework-engine.ts` | Deterministic mapping of industry codes to mandatory frameworks |
| Data Type Detector | Same file | Pattern matching on product/service descriptions for PHI, PII, PCI, etc. |
| Jurisdiction Mapper | Same file | Geographic location to applicable privacy/security regulations |
| Compliance Badge Scanner | Same file | Website scrape for SOC 2, ISO 27001, HITRUST, FedRAMP mentions |
| LLM Regulatory Analyzer | Same file | LLM prompt combining all signals for validated regulatory profile |

### Phase 3: Credential Auto-Population

| Component | File | Description |
|---|---|---|
| Schema: `engagementBreachedCredentials` | `drizzle/schema.ts` | New table for breach-sourced credentials linked to engagements |
| DeHashed → Credential Extractor | `server/lib/credential-harvester.ts` | Parse DeHashed observations into username/password pairs |
| Auto-populate on scan complete | `server/routers/domain-intel-core.ts` | After scan, extract credentials and insert into engagement |
| UI: Breached Credentials Tab | `client/src/pages/EngagementCredentials.tsx` | Display and manage breached credentials for engagement |

### Phase 4: Enriched BIA Prompt

| Component | File | Description |
|---|---|---|
| Extended LLM prompt | `server/lib/org-enrichment.ts` | Add darkweb context, regulatory profile, breach history to BIA prompt |
| Breach exposure multiplier | `server/lib/industry-baseline-scoring.ts` | New AUTO_BIA_RULES for breach exposure signals |
| Darkweb risk signals | `server/lib/passive/signal-classifier.ts` | New signal rules for stealer logs, paste mentions, forum chatter |

---

## 6. LLM Integration Strategy

The key architectural decision is that **the LLM should receive the full organizational context alongside technical scan data**. Currently, the LLM prompt for BIA generation includes:

- Company name, industry, sector, description
- Products, services, technologies
- Employee count, regulatory frameworks (guessed)
- Open ports, services, vulnerabilities (from Shodan)
- DNS records (MX, SPF, DMARC)

**After implementation, the LLM prompt will additionally include:**

- **Validated industry classification** (SIC/NAICS code + description)
- **Authoritative employee count and revenue** (from LinkedIn/Yahoo Finance)
- **Full technology stack** (frontend + backend + infrastructure + security tools)
- **Breach history** — number of breaches, total records exposed, credentials at risk, most recent breach date
- **Stealer log exposure** — whether employee credentials appear in active infostealer marketplaces
- **Darkweb mentions** — paste site leaks, forum discussions, marketplace listings
- **Ransomware victim status** — whether the org has been listed on ransomware leak sites
- **Validated regulatory profile** — confirmed frameworks with evidence sources (not just LLM guesses)
- **Executive team** — key personnel for social engineering target assessment
- **Subsidiaries and parent company** — for full attack surface context

This transforms the LLM from a technical vulnerability assessor into a **mission-aware threat analyst** that understands the business behind the infrastructure.

---

## 7. Priority Matrix

| Item | Business Value | Implementation Effort | Priority |
|---|---|---|---|
| LinkedIn Company Intel connector | Very High | Low (built-in API) | P0 |
| Regulatory Framework Inference Engine | Very High | Medium | P0 |
| DeHashed → Engagement Credential Auto-Population | Very High | Low | P0 |
| Intelligence X darkweb search | High | Medium | P1 |
| Yahoo Finance connector | High | Low (built-in API) | P1 |
| SEC EDGAR SIC code lookup | High | Low (free API) | P1 |
| Deep Tech Fingerprinting | Medium | Medium | P1 |
| Hudson Rock stealer log search | High | Medium | P2 |
| LeakCheck credential search | Medium | Medium | P2 |
| Enriched BIA LLM prompt | Very High | Low (prompt engineering) | P0 |
| Breach exposure scoring multiplier | High | Low | P1 |
| Ransomware victim domain matching | Medium | Low | P2 |

---

## 8. References

- [Intelligence X API Documentation](https://help.intelx.io/api/search/)
- [Hudson Rock API Documentation](https://docs.hudsonrock.com/)
- [SEC EDGAR API Documentation](https://www.sec.gov/search-filings/edgar-application-programming-interfaces)
- [Manus Data API — LinkedIn/get_company_details](internal)
- [Manus Data API — YahooFinance/get_stock_profile](internal)
- [NIST SP 800-30 — Risk Assessment Guide](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
- [FIPS 199 — Standards for Security Categorization](https://csrc.nist.gov/publications/detail/fips/199/final)
