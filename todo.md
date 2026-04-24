# Project TODO

### Claude Response Remediation (Apr 23)
- [x] Implement dual-approval for full_exploitation tier in safety-engine.ts
- [x] Add second approver resolver to engagement-orchestrator.ts approval gates
- [x] Implement exploit quarantine queue in exploit-knowledge-store.ts
- [x] Add human review gate before LLM-generated exploits enter searchable index
- [x] Add elevated graduation bar for exploit-category procedures
- [x] Write vitest tests for dual-approval, quarantine queue, and elevated graduation bar (26 tests passing)
- [x] Generate revised comprehensive spec document with corrected language
- [x] Include explicit exploit lifecycle documentation in spec
- [x] Include adversarial threat model section in spec
- [x] Correct FIPS claim to specify CMVP inheritance
- [x] Revise framework alignment language ("architected consistently with")
- [x] Checkpoint and push to GitHub

### Claude Follow-Up Feedback (Apr 23, Round 2)
- [x] Persist quarantine queue to database (not in-memory)
- [x] Persist approved exploit catalog entries to database
- [x] Add catalog snapshot binding for exploit-selection events (engagement evidence chain)
- [x] Fix graduation bar phrasing: "reduces tolerated failure rate from 3% to 1%"
- [x] Clarify that graduated exploit callers still feed quarantine queue (graduation != quarantine bypass)
- [x] Expand adversarial threat model: add cross-tenant data leakage and graduation pipeline attack surface
- [x] Add specific test cases, pass/fail criteria, and residual risk to each threat
- [x] Verify CMVP certificate #4282 against active CMVP list (FIPS 140-2, Active, Sunset 9/21/2026)
- [x] Soften conclusion: "strengthened by remediations, remains to be independently assessed"
- [x] Acknowledge Wassenaar review could affect customer eligibility, not just paperwork
- [x] Regenerate revised spec document v3 with all corrections
- [x] Write vitest tests for persistence changes (46 total tests passing)
- [x] Checkpoint and push to GitHub (Round 2)

### Claude Follow-Up Feedback (Apr 23, Round 3)
- [x] Implement EVIDENCE_HMAC_KEY separation from JWT_SECRET in evidence-integrity.ts
- [x] Add dedicated evidence key lifecycle management (rotation without breaking historical chains)
- [x] Expand graduation threat model: adversarial target responses crafted to maximize apparent success
- [x] Expand graduation threat model: statistical drift detection on graduation scores (slow poisoning)
- [x] Add cross-customer consent: reviewer checklist for customer-data scrubbing at quarantine approval
- [x] Add cross-customer consent: ROE schema clause for shared catalog contribution consent
- [x] Characterize test suite beyond count: unit vs integration, adversarial vs happy-path
- [x] Disclose which 3 OWASP LLM Top 10 categories are pending in §10.3
- [x] Add separation-of-duties note for admin roles in §8.3
- [x] Fix CMMC row in §7 to reference NIST SP 800-171 control equivalents
- [x] Add Level 1 validation caveat implication for federal procurement in §7.1
- [x] Change §12 to "internally strengthened" language
- [x] Write vitest tests for HMAC key separation (68 total tests passing)
- [x] Generate v4 spec document with all corrections
- [x] Checkpoint and push to GitHub (Round 3)
- [x] Generate dedicated Graduation Engine deep-dive response document for Claude

### Claude Follow-Up Feedback (Apr 23, Round 4)
- [x] Implement two-person sign-off for graduation promotion events (LLM caller → deterministic, model tier advancement)
- [x] Add drift detection operational gating: auto-block graduation when detectors fire + alert operators
- [x] Log graduation promotion events to evidence integrity chain (tamper-evident records)
- [x] Create OWASP LLM08 (Excessive Agency) preliminary test suite (13 cases)
- [x] Create OWASP LLM09 (Overreliance) preliminary test suite (13 cases)
- [x] Set specific migration deadline for reviewer checklist (2026-07-01)
- [x] Document downstream actions for each drift detector (block/hold/audit)
- [x] Write vitest tests for Round 4 changes (92 total tests passing)
- [x] Generate v5 spec document with all corrections
- [x] Generate Graduation Engine deep-dive v3
- [x] Checkpoint and push to GitHub (Round 4)

### Hybrid Scoring System Deep Dive (Apr 23)
- [x] Research CARVER scoring implementation end-to-end
- [x] Research CVSS scoring implementation and integration
- [x] Research BIA data capture and scoring
- [x] Trace hybrid scoring integration (CARVER + CVSS + BIA)
- [x] Research scoring data sources, enrichment pipelines, and persistence
- [x] Write comprehensive hybrid scoring deep-dive document for Claude
- [x] Checkpoint and push to GitHub

### Claude Round 5 Feedback — Hybrid Scoring Deep Dive (Apr 23)
- [x] Add practitioner provenance (20-year CARVER background) to document
- [x] Rewrite §16: replace patent claims with trade-secret/copyright/IP protection framing
- [x] Address inter-rater reliability: add anchored rubrics with concrete example assets per score level
- [x] Implement inter-rater reliability test harness (10 assets, 2 operators, agreement measurement)
- [x] Address one-way ratchet: add correlated-input damping mechanism for Criticality
- [x] Address double-counting: recognize when CVSS Env + FIPS 199 + Tier + Sector push same dimension
- [x] Clarify Layer 9 LLM propagation: document whether deltas re-run pipeline or bypass it
- [x] Name Layer 8 additive-vs-multiplicative as deliberate design choice with rationale
- [x] Add downstream responses to distribution monitoring flags (not just observational)
- [x] Name deterministic-baseline + bounded-LLM-delta as consistent platform philosophy
- [x] Write vitest tests for correlated-input damping and distribution monitoring responses (17 tests passing)
- [x] Generate v2 Hybrid Scoring Deep Dive document with all corrections (1,252 lines)
- [x] Checkpoint and push to GitHub (Round 5)

### AC3 Platform Deep Dive Document (Apr 23)
- [x] Survey all server/lib modules and catalog capabilities
- [x] Survey all client pages and UI features
- [x] Survey engagement/campaign/DI features
- [x] Write comprehensive AC3 Platform Deep Dive document (987 lines, 20 sections)
- [x] Checkpoint and push to GitHub (Platform Deep Dive)

### Claude Round 6 — Final Consistency Cleanup (Apr 23)
- [x] Reconcile safety level terminology: pick canonical set, cross-reference in other doc
- [x] Correct FIPS 140-2 to FIPS 140-3 across all documents and add sunset/context notes
- [x] Add dated disclaimer to competitive comparison table §20.1 ("as of April 2026")
- [x] Replace approximate module counts ("45+", "90+", "80+") with exact numbers from codebase
- [x] Reconcile scope enforcement language (tRPC procedure level vs transport-layer middleware)
- [x] Add LLM prompt versioning note to §18 (model evolution requires calibration testing)
- [x] Checkpoint and push to GitHub (Round 6)
- [x] Write intelligence agency product guide document (710 lines, 18 sections)

### IC Product Guide Revision — Company-Centric Framing (Apr 23)
- [x] Research AceofCloud company profile, certifications, and team depth
- [x] Reframe product guide from individual to company-centric (AceofCloud as org, Harrison Cook as architect/creator)
- [x] Emphasize company certifications and collective experience
- [x] Checkpoint and push to GitHub

### Role Correction — Harrison Cook (Apr 23)
- [x] Correct role from 'founder' to 'Director of Security Engineering and Offensive Operations' in IC Product Guide
- [x] Correct role in Platform Deep Dive
- [x] Correct role in Hybrid Scoring Deep Dive v2
- [x] Checkpoint and push

### HACS SIN Response Template (Apr 23)
- [x] Research GSA HACS SIN subcategories and evaluation criteria
- [x] Write HACS SIN response template mapping AC3 capabilities to each subcategory (525 lines, 14 sections)
- [x] Checkpoint and push to GitHub
- [x] Tone down military intelligence experience references in IC Product Guide only

### DI Scan Vulnerability Inflation Bug Fix (Apr 24)
- [x] Audit DI scan pipeline: trace tech detection → CVE association → vuln classification → UI display
- [x] Identify where probable/potential CVEs are being counted as "Confirmed Vulns"
- [x] Fix backend: tightened tier classification — vendor-only matches without version → potential
- [x] Fix frontend: default to Confirmed-only view, three-tier filter, filtered summary stats
- [x] Add clear visual distinction: tier breakdown bar, info banner, tier-accurate labels
- [x] Write tests for the fix (18 tests passing)
- [x] Checkpoint and push

### Backend Services Inference Module (Apr 24)
- [x] Audit existing signal sources (DNS, SPF, MX, headers, cloud-assets, builtwith, etc.)
- [x] Design InfrastructureMap interface and inference engine
- [x] Implement infrastructure-inference.ts module (15 service categories, vendor dependency analysis, tech lifecycle, supply chain risks)
- [x] Add inferInfrastructure tRPC procedure to caldera-proxy.ts
- [x] Add Infrastructure Map sub-tab to DomainIntelResults.tsx (lazy-loaded InfrastructureMapTab component)
- [x] Write tests (38 tests passing across 14 test groups)

### Confidence Explanation Tooltips (Apr 24)
- [x] Add TooltipProvider and Tooltip components to VulnIntelSection.tsx
- [x] Add confidence explanation tooltips to corroboration tier badges (confirmed/probable/potential)
- [x] Add confidence explanation tooltips to KEV CONFIRMED/POTENTIAL badges
- [x] Tooltips explain match specificity (product vs vendor-only, version-confirmed vs unconfirmed)

### JARM Fingerprint Integration (Apr 24)
- [x] Research JARM fingerprint patterns for major CDN/cloud/server/C2 providers (Salesforce JARM, Censys, community threat intel)
- [x] Add JARM known-fingerprint database: 20+ full-hash signatures + 8 prefix patterns covering C2 (Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Merlin), CDN (Cloudflare, CloudFront, Akamai, Fastly, Imperva, Sucuri), Cloud (Google Cloud, Azure), Server (nginx, Apache, IIS, LiteSpeed)
- [x] Integrate JARM signals from 3 data sources: jarm_fingerprint connector, BinaryEdge (evidence + tags), httpx jarmHash evidence
- [x] Implement confidence boosting: CDN/cloud/server confidence +0.08-0.10 when JARM corroborates other signals
- [x] Implement C2 framework detection with critical supply chain risk alerts
- [x] Add cert issuer corroboration for CDN identification
- [x] Add JarmAnalysis type and JARM TLS Fingerprint Analysis section to InfrastructureMapTab UI
- [x] Write tests: 66 tests passing (28 new JARM-specific tests across 10 test groups)
- [x] Push to GitHub

### JARM Historical Tracking (Apr 24)
- [x] Design jarm_scan_history and jarm_feed_sources and jarm_community_signatures DB tables (MySQL schema + drizzle)
- [x] Implement jarm-history.ts: processAndStoreJarmHistory, getJarmTimeline, getJarmHistoryByScan, getRecentJarmAlerts
- [x] Implement change detection with severity classification: c2_appearance (critical), c2_disappearance (high), provider_change (medium), server_change (medium), new_fingerprint (low), hash_drift (info)
- [x] Add 4 tRPC procedures: getJarmTimeline, getJarmHistoryByScan, getRecentJarmAlerts, storeJarmHistory
- [x] Add JARM History Timeline collapsible UI section with summary stats, change alerts, and records table

### Community JARM Signature Feed Integration (Apr 24)
- [x] Design jarm_community_signatures table with signatureId/jarmHash/provider/matchType/confidence/feedSource/tags fields
- [x] Implement jarm-community-feeds.ts with CSV and JSON feed parsers, C2 tool name inference, and key-value format support
- [x] Add 3 default feed sources: Salesforce JARM Known Hashes, C2 JARM IOC, TLS Fingerprint Database
- [x] Implement feed lifecycle: initializeDefaultFeeds, refreshFeed, refreshAllFeeds, toggleFeedSource, deleteFeedSource, getFeedStats
- [x] Add 9 tRPC procedures for feed management: getJarmFeedSources, getJarmFeedStats, getCommunitySignatures, initializeJarmFeeds, refreshJarmFeed, refreshAllJarmFeeds, addJarmFeedSource, toggleJarmFeed, deleteJarmFeed
- [x] Add Community JARM Signature Feeds collapsible UI section with stats, action buttons, and feed source cards with enable/disable/refresh/delete controls
- [x] Write 24 tests across 8 test groups (JARM history change classification, processAndStoreJarmHistory, getJarmTimeline, getRecentJarmAlerts, feed parsers, initializeDefaultFeeds, getFeedStats, CSV edge cases)
- [x] All 90 JARM-related tests passing (66 infrastructure-inference + 24 history/feeds)
- [x] Push to GitHub

### Bug Fix: OSINT Risk Signals Raw JSON (Apr 24)
- [x] Fix OSINT Risk Signals cards rendering raw JSON objects instead of formatted human-readable content
- [x] Fix Asset Risk Heatmap to include all discovered assets (sortedAssets and riskDist now use allAssets = DB assets + subdomain assets)
- [x] Fix entity profile LLM showing wrong org name: added third-party title filter (Outlook, Sign in, Microsoft, etc.), WHOIS org extraction from passiveRecon pipeline data, domain-derived name as Signal 7 fallback, and third-party name filtering in candidate resolution
- [x] Push fixes to GitHub

### Bug Fix: OSINT Risk Signals Still Raw JSON + Entity Name Wrong (Apr 24)
- [x] Verified OSINT Risk Signals fix works correctly on dev server (carmax.com scan renders properly with severity badges, confidence %, rationale text)
- [x] Confirmed deployed site needs redeployment to pick up latest code (scan 2070001/2070002 only exist on production DB)
- [x] Expanded entity resolver third-party name filter from 18 to 65+ entries (added GitHub, GitLab, Atlassian, Salesforce, security vendors, cloud providers, HR platforms, generic page titles)
- [x] Push fixes to GitHub

### Wire JARM History into DI Scan Pipeline (Apr 24)
- [x] Found DI scan pipeline completion hooks in domain-intel-core.ts (scan-only path line 675, full engagement path line 794)
- [x] Created jarm-pipeline-hook.ts: extracts JARM observations via inferInfrastructure, stores via processAndStoreJarmHistory, emits system notification for critical C2 detections
- [x] Wired into both scan-only and full engagement completion paths as fire-and-forget setImmediate hooks
- [x] Write tests: 7 tests passing (importability, empty observations, no-JARM data, observation mapping, asset mapping, integration points)
- [x] Push to GitHub for DigitalOcean deployment

### Credential Display & Engagement Passthrough (Apr 24)
- [x] Display credential details (breach source, email, username, hash type) in OSINT Risk Signal cards
- [x] Pass credentials through to credential testing when starting an engagement
- [x] Fix Breaches tab badge count to show breach source count (not total exposure records)
- [x] Clarify first stat card label from "Exposures" to "Breach Records" to avoid confusion with breach count

### Credential Testing Button & Executive Summary Stats (Apr 24)
- [x] Add "Send to Credential Testing" button on individual breach signal cards for manual one-click credential spray initiation
- [x] Aggregate credential stats into executive summary (e.g., "14 credentials with plaintext passwords across 3 breach sources")

### Credential Spray Status & PDF Report (Apr 24)
- [x] Add credential spray status indicator on Breaches tab showing tested vs pending credentials
- [x] Add Credential Exposure section to PDF report export with breach stats

### Breach Timeline Visualization (Apr 24)
- [x] Add breach timeline visualization to Breaches tab showing when each breach source was first detected chronologically
- [x] Push to GitHub

### Tier 1 OSINT Connector Gaps (Apr 24)
- [x] Build abuse.ch URLhaus connector (malicious URL hosting detection)
- [x] Build abuse.ch MalwareBazaar connector (malware distribution association)
- [x] Build SEC EDGAR connector (10-K filings for BIA financial impact)
- [x] Build OSV.dev connector (supply chain vulns for npm/PyPI/Go)
- [x] Build Team Cymru connector (authoritative IP-to-ASN mapping)
- [x] Build CISA Advisories connector (real-time vulnerability advisories)
- [x] Register all 6 new connectors in index.ts and passive-guard.ts
- [x] Write tests for all new connectors (38 tests passing)
- [x] Implement evidence multiplier mapping config (confirmed/corroborated/unverified tiers per connector)
- [x] Implement unified OSINT rate limiter with circuit breaker pattern
- [x] Implement ToS compliance registry for all connectors

### Rate Limiter Integration & Compliance Attribution (Apr 24)
- [x] Wire rateLimitedFetch into existing connectors (20 connectors wired)
- [x] Add compliance attribution footer to generated reports using generateComplianceSummary()

### Tier 2 OSINT Connector Gaps (Apr 24)
- [x] Build Feodo Tracker connector (C2 botnet tracking)
- [x] Build SSL Blacklist connector (malicious SSL certificate detection)
- [x] Build GitHub Security Advisories connector (GHSA vulnerability data)
- [x] Build Certspotter connector (CT log monitoring)
- [x] Build Companies House connector (UK company registry data)
- [x] Build OpenCorporates connector (global corporate registry)
- [x] Build HC3 connector (Health Sector Cybersecurity Coordination Center)
- [x] Register all Tier 2 connectors in index.ts and passive-guard.ts
- [x] Write tests for all Tier 2 connectors (19 tests passing)
- [x] Push to GitHub

### FedRAMP Quick Wins (Apr 24)
- [x] Add NIST 800-53 control references to existing risk signals (nistControl field on each signal)
- [x] Add FedRAMP Impact Level field to engagement creation (Low/Moderate/High dropdown)
- [x] Add FedRAMP remediation timelines to findings (auto-calculate 30/90/180-day deadlines)
- [x] Add FedRAMP report template option (reformat existing report sections with SAR-aligned headings)
- [x] Push to GitHub
- [x] Wire NIST control references into OSINT Risk Signal cards on frontend

### DI Scan Template & Results UI Audit (Apr 24)
- [x] Update getConnectorCatalog with all missing connectors (34 connectors missing from OSINT Sources tab)
- [x] Add new pipeline stage entries to SCAN_METHODS in DomainIntel.tsx (Infrastructure Inference, JARM, NIST Mapping, Breach Analysis, Credential Harvesting)

### Claude Passive/Active Tool Classification Feedback (Apr 24)
- [x] Add missing passive OSINT tools to connector catalog (subfinder, chaos-client, amass, assetfinder, findomain, gau, waybackurls, FOFA, ZoomEye, whoisfreaks, OpenPhish, EPSS, theHarvester)
- [x] Update scan policy engine with accurate tool-to-tier classification mapping
- [x] Add active-tier tool definitions (httpx, dnsx, naabu, gowitness, ffuf, katana, nuclei, nmap)
- [x] Update DI pipeline documentation with hypothesis-vs-confirmed finding distinction
- [x] Update SCAN_METHODS UI with passive/active classification labels
- [x] Add scan mode classification to connector catalog entries

### Exploit Pipeline Audit (Apr 24)
- [x] Read and catalog all exploit pipeline modules (24 modules, ~15,000 LOC)
- [x] Compile architecture summary document (9 architectural layers)
- [x] Build tRPC endpoint for LLM-powered pipeline audit report generation
- [x] Build Pipeline Audit page with safety/legal framework banner, recommendations, priority matrix, module inventory
- [x] Add safety guardrails & legal compliance framework section (ROE Guard, Safety Engine, Audit Trail, Risk Tier Classification)
- [x] Write tests for pipeline audit feature (21 tests passing)
- [x] All 111 tests passing across 3 test suites
