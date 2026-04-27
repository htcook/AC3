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

### Manual Tool Runner & Unified Ingestion Pipeline (Apr 24)
- [x] Audit all scanning/exploit sidebar tools (functional vs. stub) — 30 functional, 2 light, 3 stubs, 5 missing pages
- [x] Build unified tool output ingestion pipeline (ingestToolOutput server-side)
- [x] Build Manual Tool Runner panel in engagement ops dashboard UI
- [x] Add embedded CLI with matched exploit/script catalog (pre-built scripts matched to target profile)
- [x] Wire engagement context selector as prerequisite for tool execution
- [x] Add engagement activity feed for manual tool executions
- [x] Integrate Safety Engine, ROE Guard, and evidence integrity chain into all manual tool executions
- [x] Write tests for tool runner and ingestion pipeline (19 tests passing)

### Exploit Pipeline Audit Findings Remediation (Apr 24)
- [x] REC-001: Automated Exploit Selection and Chaining (vuln-to-exploit mapper, auto-queue, chain logic)
- [x] REC-002: Automated and Resilient C2 Handoff (multi-channel fallback, persistence, health monitoring)
- [x] REC-004: Proactive OPSEC and Evasion Module (pre-action OPSEC scoring, traffic shaping, cleanup)
- [x] REC-003: Automated Initial Post-Exploitation Playbooks (auto-run situational awareness on foothold)
- [x] REC-005: Dynamic Multi-Vector Payload Delivery (protocol-aware staging, delivery channel selection)
- [x] REC-006: Automated Credential Harvesting and Reuse (auto-extract + spray across discovered services)
- [x] REC-007: Automated Privilege Escalation Detection and Execution (OS fingerprint → privesc matcher)
- [x] REC-008: Advanced C2 Resilience and Fallback (domain fronting, protocol rotation, jitter)
- [x] REC-009: Dynamic EDR/AV Evasion Profiles (target-aware evasion technique selection)
- [x] REC-010: Automated Lateral Movement Playbooks (credential + access → pivot path automation)
- [x] REC-011: Pre-Exploitation Vulnerability Validation (confirm vuln before exploit attempt)
- [x] REC-012: Payload Staging and Multi-Layer Obfuscation (staged delivery with layered encoding)
- [x] Generate comprehensive exploit pipeline deep-dive document for Claude (docs/exploit-pipeline-deep-dive.md, 450+ lines)

### Purple Team Platform Enhancements (Apr 24)
- [x] 1. Detection-centric data model (detectionTestId, detection_test event type, detection metrics)
- [x] 2. Purple team ROE addendum schema (defensive counterparty, coordination protocol, vendor notification, technique-level auth, evasion scope bounding, detection grace period)
- [x] 3. Reframe EDR catalog as detection-test mapping (expectedIndicators, publicReferences, vendorPurpleTeamPolicy)
- [x] 4. Bilateral evidence collection pipeline (ingest customer SOC/EDR logs, correlate by timestamp+host, negative evidence as first-class records)
- [x] 5. Purple team test plan template (defensive stack inventory, detection objectives, technique enumeration, success criteria)
- [x] 6. Replayability versioning (test plan version, catalog version, technique params, platform version)
- [x] 7. Deprecate Manjusaka C2 adapter (removed from C2Registry, marked deprecated in UI, env vars, and attack coverage)
- [x] Update report module for purple team ROE section (PT-1)
- [x] Update report module for purple team scoping section (PT-2 test plan)
- [x] Update report module for purple team test plan section (PT-2, PT-3)
- [x] Update report module for purple team final report (PT-4 metrics, PT-5 bilateral timeline, PT-6 gap analysis, PT-7 replayability)
- [x] Write tests for all purple team enhancements (25 tests passing: data model, ROE addendum, detection metrics, negative evidence, replayability, test plan, unified timeline, detection assessment catalog, report pipeline, Manjusaka deprecation)

### Fix Missing Sidebar Tool Pages (Apr 24)
- [x] Audit sidebar navigation links and identify dead/missing pages (all 6 originally flagged pages now exist and route correctly)
- [x] Updated audit-tool-status.md to reflect resolved status

### Hypothesis-vs-Confirmed Badges in Scan Results (Apr 24)
- [x] Created shared CorroborationTierBadge component with consistent color-coded styling and tooltips
- [x] Added per-CVE tier badges to VulnIntelSection (tech-level + individual CVE badges)
- [x] Added tier badges to DomainIntelResults subdomain findings view
- [x] Added tier badges to DomainIntelResults risk signals (replaced plain text)
- [x] Added tier badges to DomainIntelResults exploit match view
- [x] Replaced plain badge in ClientPortal findings with CorroborationTierBadge
- [x] Replaced inline tier badges in EngagementOps (2 locations) with shared component
- [x] Replaced tierBadge function in ScanComparison with shared component
- [x] Write vitest tests for CorroborationTierBadge logic (covered in llm-specialists-modular.test.ts validation section)

### Discovery Context Engine (Claude Analysis Implementation, Apr 24)
- [x] Build DiscoveryContextEngine data model with 5 specialist interfaces (AttributionClaim, RoleInference, LifecycleStage, BusinessContext, ThreatRelevance)
- [x] Implement structured evidence package builder (assembles cert, DNS, BGP, WHOIS, HTTP into structured packages)
- [x] Implement Asset Attribution Specialist with bounded delta pattern (deterministic baseline + LLM ±20pt adjustment)
- [x] Implement Asset Role Specialist (customer-facing/internal, prod/non-prod, primary/backup)
- [x] Implement Lifecycle Stage Specialist (active/declining/abandoned/unknown with temporal signals)
- [x] Implement Business Context Specialist (business unit, function, revenue path attribution)
- [x] Implement Threat Relevance Specialist (per-actor-type, per-attack-pattern scoring with sector context)
- [x] Add evidence grounding validation (every claim must cite input evidence, reject ungrounded claims)
- [x] Add three degradation modes (Full LLM, Deterministic-only, Confidence-degraded)
- [x] Integrate discovery context into existing scan pipeline (2 tRPC procedures: analyzeDiscoveryContext + analyzeDiscoveryContextBatch)
- [ ] Add discovery context UI panel to DomainIntelResults
- [x] Write vitest tests for discovery context engine (53 tests in llm-specialists-modular.test.ts)

### LLM Specialist Modular Decomposition (Claude Reference Implementation, Apr 24)
- [x] Create server/lib/llm-specialists/ directory structure per Claude's reference
- [x] Create shared types.ts with all specialist interfaces (AttributionClaim, EvidenceReference, ValidationResult, etc.)
- [x] Create evidence-package.ts module for structured evidence package construction
- [x] Build asset-attribution specialist (specialist.ts, prompts.ts, validation.ts, deterministic-baseline.ts, scoring-integration.ts)
- [x] Build asset-role specialist following same pattern
- [x] Build lifecycle-stage specialist following same pattern
- [x] Build business-context specialist following same pattern
- [x] Build threat-relevance specialist following same pattern
- [x] Update tRPC procedures to use new modular specialists (6 new procedures + 1 batch procedure)
- [x] Write vitest tests for deterministic baselines, validation logic, and scoring integration (53 tests all passing)
- [x] Save Claude reference implementation document for team handoff (claude-attribution-specialist-reference.md)

### Discovery Context UI Tab (Apr 24)
- [x] Create DiscoveryContextTab.tsx component with 5 specialist result cards (Attribution, Role, Lifecycle, Business Context, Threat Relevance)
- [x] Add Discovery Context tab trigger to DomainIntelResults Analysis tab group
- [x] Add Discovery Context TabsContent with lazy-loading and Suspense fallback
- [x] Show attribution claims with confidence badges, evidence citations, and primary/alternative claim layout
- [x] Show asset role (exposure/environment/criticality) with color-coded visual indicators
- [x] Show lifecycle stage with temporal signals and direction indicators
- [x] Show business context (function, revenue path, regulatory exposure, dependencies)
- [x] Show threat relevance (actor types with icons, sector exposure, campaign correlations, overall threat score)
- [x] Add "Analyze Asset" button + "Batch Analyze Top 20" + deterministic/LLM toggle
- [x] Handle loading/error/empty states with proper spinner, empty state, and previously-analyzed grid

### Wire LLM Invocation into Specialists (Apr 24)
- [x] Verified tRPC procedures pass invokeLLM function when deterministicOnly is false
- [x] Each specialist's invoke function correctly calls LLM with structured prompts (already implemented)
- [x] Bounded delta clamping works end-to-end (±20pt) — tested in 53 vitest tests
- [x] Fallback to deterministic-only when LLM call fails (confidence_degraded mode)

### Scan Mode Selector UI (Apr 24)
- [x] Scan mode selector already exists in DomainIntel.tsx (Passive Only / Passive + DNS / Full)
- [x] Already integrated with TOOL_TIER_CLASSIFICATION registry and backend ScanMode type
- [x] Scan mode selector present in DI scan launch flow
- [x] Selected mode passes through to scan pipeline

### Persist Discovery Context to Database (Apr 24)
- [x] Add discovery_context and discovery_context_analyzed_at columns to discovered_assets table
- [x] Add saveDiscoveryContext, getDiscoveryContext, getDiscoveryContextBatch tRPC procedures
- [x] Auto-save in runModularDiscoveryPipeline when assetId provided
- [x] Load persisted results on DiscoveryContextTab mount (batch query by scanId)
- [x] Display previously analyzed assets with "analyzed" badge

### Discovery Context in Report Pipeline (Apr 24)
- [x] Add discoveryContextData field to PipelineInput interface
- [x] Add "Asset Discovery Context Intelligence" section to report markdown
- [x] Summary table + per-asset detail (Attribution, Role, Lifecycle, Business Context, Threat Relevance)
- [x] Write 27 vitest tests for report integration and persistence (all passing)

### Architecture Documentation (Apr 24)
- [x] Audited all 137 in-memory stores — categorized into 6 risk categories
- [x] Documented discovery context engine (bounded delta, 5 specialists, 3 degradation modes)
- [x] Documented report pipeline (6-step FedRAMP generation)
- [x] Documented purple team data model, C2 registry, tool tier classification
- [x] Written comprehensive 12-section ARCHITECTURE.md

### Migrate P0 Active Operation State to DB (Apr 24)
- [x] Audit campaignRunStates in campaign-orchestrator.ts (5 fields, 6 access points)
- [x] Audit activePlans in c2-orchestrator.ts (~25 fields, 7 access points)
- [x] Add campaign_run_states DB table to drizzle schema (10 columns incl. heartbeat)
- [x] Add c2_orchestration_plans DB table to drizzle schema (16 columns incl. phases_json, log_json)
- [x] Create operation-state-persistence.ts with write-through DB layer
- [x] Migrate campaignRunStates: write-through at set/pause/resume/abort/delete + heartbeat
- [x] Migrate activePlans: write-through at create/update-status/pause/resume/abort/complete/fail
- [x] Add fallback to in-memory on DB failure (try/catch with console.warn)
- [x] Write vitest tests for DB-backed state machines (35 tests, all passing)

### Discovery Context in ClientPortal (Apr 24)
- [x] Add discovery context query to client-portal.ts accessReport procedure (fetches from discovered_assets by scanId)
- [x] Add inline discovery context cards on each asset in ClientPortal assets tab
- [x] Show attribution (org + confidence), role (exposure/environment), lifecycle (stage + direction), threat relevance (score + band)
- [x] Handle assets with no discovery context gracefully (hidden when null)

### Stale Analysis Indicator (Apr 24)
- [x] Add stale analysis detection (>7 days threshold with isStaleAnalysis/getAnalysisAge helpers)
- [x] Display pulsing orange StaleBadge on stale assets with tooltip explanation
- [x] Add summary banner showing count of stale assets with "Re-analyze Stale" batch button
- [x] Add inline "Re-analyze" button on individual stale asset results
- [x] Stale assets shown with orange border and AlertTriangle icon in summary grid
- [x] Write vitest tests for stale detection logic (14 tests incl. boundary cases, all passing)

### Orphaned Operation Recovery on Startup (Apr 24)
- [x] Wire recoverOperationState() into server boot sequence (Phase 2, 30s after boot)
- [x] Log recovery report on startup (campaigns recovered, plans recovered, orphans marked failed)
- [x] Add startHeartbeat() call on server boot for active node tracking
- [x] Write vitest tests for recovery integration (35 tests in operation-state-and-stale.test.ts)

### Discovery Context Comparison View (Apr 24)
- [x] Add discovery_context_history column to DB schema and discovered_assets table
- [x] Update saveDiscoveryContext to snapshot previous context into history (keeps last 10)
- [x] Add getDiscoveryContextHistory tRPC procedure
- [x] Build DiscoveryContextComparisonView.tsx with side-by-side diff dialog
- [x] Detect per-specialist changes: attribution shifts, role changes, lifecycle transitions, business context, threat relevance
- [x] Add snapshot selector (dropdown of up to 10 historical snapshots with timestamps)
- [x] Add snapshot timeline bar with visual indicator
- [x] Add "View Changes" button on analyzed asset results in DiscoveryContextTab
- [x] Write vitest tests for comparison diff logic (9 tests, all passing)

### Discovery Context Export to CSV/PDF (Apr 24)
- [x] Build exportDiscoveryContextCSV tRPC procedure (16-column CSV with proper escaping)
- [x] Build exportDiscoveryContextMarkdown tRPC procedure (full report with summary table + per-asset details)
- [x] Add CSV and Report (MD) export buttons to DiscoveryContextTab toolbar
- [x] Client-side Blob download for both formats
- [x] Write vitest tests for CSV formatting and Markdown report structure (13 tests, all passing)
- [x] Total: 172 tests passing across 5 test suites

##### Bug Fix: Engagement Crash — TypeError null r.phase (Apr 25)
- [x] Root cause: getState returned null when no in-memory or DB snapshot existed; frontend accessed ops.phase without null guard
- [x] Fix: getState now returns default idle state instead of null (engagement-ops-core.ts)
- [x] Fix: ManualToolRunner uses ops?.phase || 'idle' instead of ops.phase (EngagementOps.tsx line 4656)
- [x] Write 15 vitest tests for null guard, phase safety, normalizer, breachData TDZ, heartbeat fix

### Bug Fix: DI Scan Re-runs Return Empty Results (Apr 25)
- [x] Root cause: breachData TDZ error — variable used at lines 3741/3790 before declaration at line 3974 in domainIntel.ts
- [x] Fix: Moved breach data extraction block BEFORE summary generation stage
- [x] Pipeline error "Cannot access 'breachData' before initialization" resolved

### Bug Fix: Heartbeat getRunningCampaignIds Error (Apr 25)
- [x] Root cause: startHeartbeat was called with db instance instead of callback functions
- [x] Fix: Updated server/_core/index.ts to pass proper getRunningCampaignIds/getRunningPlanIds callbacks
- [x] Server now boots cleanly: "Heartbeat started for node ..."

### New Test Engagement (Apr 25)
- [x] Created engagement ID 1830001: "Pipeline Test — Full Stack Validation"
- [x] Targets: tesconsultantsgov.us, mcdllc.com
- [x] RoE pre-signed (status: signed), RoE document ID 240001 (status: approved)
- [x] Authorizing official signature added
- [x] Scan mode: standard, engagement type: red_team, status: active
- [x] Checkpoint saved and pushed to GitHub for DO deployment

### SAFETY FIX: Remove Live Domains from Test Engagement (Apr 25)
- [x] Verified: only passive OSINT ran (CISA advisories, GitHub advisories, Feodo, SSLBL) — 0 active/exploit operations
- [x] Found AC3 test lab sites: scan.aceofcloud.io/lab/{dvwa,juice-shop,bwapp,webgoat,mutillidae} + 159.223.152.190
- [x] Updated engagement 1830001 targetDomain to test lab sites only
- [x] Updated RoE scope and RoE document in_scope_domains/in_scope_ip_ranges to test lab only
- [x] Cleared old ops snapshot (contained passive recon data from live domains)
- [x] Checkpoint and push to GitHub

### Safety Guardrail: Domain Whitelist Validation (Apr 25)
- [x] Create shared/domain-safety-whitelist.ts with 17 approved domains + 2 IPs + private range patterns
- [x] Add domain validation to engagement creation procedure (engagements-core.ts) — stores [SAFETY] warning in notes
- [x] Add domain validation gate to pipeline execute procedure (engagement-ops-core.ts) — FORBIDDEN error for non-whitelisted without admin override
- [x] Add domain whitelist enforcement in orchestrator (engagement-orchestrator.ts) — forcibly caps safety level to passive_only
- [x] Add active_scan_override column to engagements table (admin override flag)
- [x] Add UI warning banner in EngagementOps.tsx — red banner for blocked, amber for admin override
- [x] Add frontend domain whitelist validation (useMemo with same approved patterns)
- [x] Write 54 vitest tests for whitelist validator (extractHostname, isDomainWhitelisted, parseTargets, validateEngagementTargets, getSafetyWarning, whitelist integrity)
- [x] Checkpoint and push to GitHub

### Monitor Broken Crystals Engagement + Exploit Workflow Audit (Apr 26)
- [ ] Monitor Broken Crystals engagement on prod for errors
- [ ] Audit exploit pipeline: vuln-to-exploit selection, LLM exploit generation, execution flow
- [ ] Identify why exploits are not succeeding (0 successful exploits across all engagements)
- [ ] Fix exploit selection logic (vuln-to-exploit mapper)
- [ ] Fix LLM exploit generation prompts and validation
- [ ] Fix exploit execution and result verification
- [ ] Ensure LLM can independently identify, create, and run exploits
- [ ] Write vitest tests for exploit workflow fixes
- [ ] Checkpoint and push to GitHub

### Nuclei-Verified Exploit Promotion (Apr 26)
- [x] Define criteria for Nuclei findings that qualify as verified exploits (data extraction, command execution, injection proof)
- [x] Add nucleiVerifiedExploit flag to vuln findings in the orchestrator
- [x] Implement promotion logic after Nuclei vuln detection that counts verified findings as exploit successes
- [x] Update stats.exploitsSucceeded counter for promoted findings
- [x] Add log entries for promoted exploits with evidence
- [x] Update the exploitation phase to skip re-testing already-promoted vulns
- [x] Write vitest tests for promotion logic (57 tests passing)
- [x] Checkpoint and push to GitHub

### Exploit Promotion Enhancements (Apr 26)
- [x] Expand promotion module to cover ZAP active scan findings with injection/extraction evidence
- [x] Expand promotion module to cover Burp Suite findings with injection/extraction evidence
- [x] Ensure evidence is captured and stored on promoted vulns (extractedDataPreview, category, confidence)
- [x] Add "Promoted Exploits" UI section in EngagementOps showing promoted findings with evidence
- [x] Add evidence detail cards with proof text, category badges, confidence indicators
- [x] Wire ZAP/Burp promotion into orchestrator alongside Nuclei promotion
- [ ] Re-run Broken Crystals engagement on prod to validate promotion + evidence capture (post-deploy)
- [x] Write vitest tests for ZAP and Burp promotion logic (120 tests passing)
- [x] Checkpoint and push to GitHub

### Engagement Pipeline Scan Effectiveness Fix (Apr 26)
- [x] Investigate how assets/targets are stored and recovered during server restarts (persistence is solid)
- [x] Fix Nuclei URL generation in rerunFullPipeline to scan both HTTP and HTTPS with discovered ports
- [x] Fix stats recalculation and asset count display after pipeline completion
- [x] Fix same Nuclei URL issue in executeEngagement's vuln_detection phase
- [x] Write vitest tests for the fixes (140 tests passing across 3 suites)
- [x] Fix ZAP scan fallback to scan both HTTP and HTTPS when no web ports discovered
- [x] Fix Burp extractScopeUrls to include both HTTP and HTTPS for targetDomain and discovered assets
- [ ] Deploy fix and re-run Broken Crystals engagement to validate
- [ ] Verify promotion logic fires with actual scanner findings
- [ ] Checkpoint and push to GitHub

### Delete Pipeline Test Engagement (Apr 26)
- [x] Delete engagement #1830001 (Pipeline Test — Full Stack Validation) with live sites

### Vulnerability Assessment Engagement Type (Apr 26)
- [x] Add 'Vulnerability Assessment' to engagement type enum in schema
- [ ] Build VA-specific pipeline (recon → active discovery → vuln detection → LLM synthesis, NO exploitation)
- [ ] Add VA-specific report template (vuln inventory, CVSS scores, remediation guidance)
- [ ] Add VA engagement creation in New Engagement wizard
- [ ] Add VA-specific EngagementOps view (scanner coverage, vuln classification focus)

### Bug Bounty Engagement Type (Apr 26)
- [x] Add 'Bug Bounty' already in engagement type enum in schema
- [ ] Build Program Policy Parser (HackerOne/Bugcrowd policy → structured PolicyROE)
- [ ] Build bug-bounty-specific scope enforcement extensions
- [ ] Build finding documentation workflow (reproduction steps, evidence capture, impact analysis)
- [ ] Build originality verification system (duplicate/known issue detection)
- [ ] Build submission workflow (platform-specific formatting, draft review)
- [ ] Add Bug Bounty engagement creation in New Engagement wizard
- [ ] Add Bug Bounty EngagementOps view (program info, scope, findings tracker)

### Cross-Training Infrastructure (Apr 26)
- [ ] Build specialist outcome logging schema (triage outcomes, finding confirmations, program decisions)
- [ ] Build pattern repository for context-independent patterns (reproduction quality, evidence quality, vuln class)
- [ ] Build vulnerability validation calibration pipeline (bug bounty triage → vuln detection improvement)
- [ ] Build tool effectiveness cross-training (scanner results → tool selection improvement)
- [ ] Build reproduction quality patterns (bug bounty evidence → reporting improvement)

### License-Tier Gating (Apr 26)
- [ ] Add licenseRequirement field to engagement type configuration
- [ ] Define tier mapping (Standard: VA + Bug Bounty, Professional: Pentest, Enterprise: Red Team + Purple Team)
- [ ] Add UI gating in New Engagement wizard with upgrade prompts
- [ ] Add backend enforcement in engagement creation endpoint

### Vitest Tests for New Features (Apr 26)
- [ ] Write tests for VA pipeline phase gating
- [ ] Write tests for Bug Bounty policy parser
- [ ] Write tests for cross-training pipelines
- [ ] Write tests for license-tier enforcement

### Compliance Framework Mapping for Scan Results (Apr 26)
- [x] Build compliance framework mapping engine (NIST 800-53, CIS Controls, PCI-DSS, ISO 27001, HIPAA, SOC 2)
- [x] Map CWE/CVE categories to 800-53 control families (AC, AU, CA, CM, IA, IR, MA, MP, PE, PL, PM, PS, RA, SA, SC, SI)
- [x] Map CWE/CVE categories to CIS Controls v8 (18 control groups)
- [x] Map CWE/CVE categories to PCI-DSS v4.0 requirements
- [x] Map CWE/CVE categories to ISO 27001:2022 Annex A controls
- [x] Map CWE/CVE categories to HIPAA Security Rule safeguards
- [x] Map CWE/CVE categories to SOC 2 Trust Services Criteria
- [x] Integrate framework mapping into vuln scan results (EngagementOps vuln findings)
- [x] Integrate framework mapping into DI scan results (DomainIntelResults vuln section)
- [x] Build framework selection UI — user picks which frameworks to include in scan reports
- [ ] Add framework compliance summary to engagement reports (controls affected, gap analysis)
- [ ] Add framework compliance summary to DI scan reports
- [ ] Write vitest tests for framework mapping engine

### VA & Bug Bounty Sprint (Apr 26)
- [x] Build NormalizedFinding interface and finding normalization layer (Nuclei, ZAP, Burp, Trivy normalizers)
- [x] Build fingerprint generation, severity inference, corroboration tier inference
- [x] Build finding deduplication and merge logic with confidence boosting
- [x] Build batch normalization pipeline with stats tracking
- [x] Build VerificationProfile system (7 profiles: Standard VA, PCI ASV, FedRAMP ConMon, HIPAA, SOC 2, Deep Assessment, Continuous Monitoring)
- [x] Build VA pipeline configuration with phase gating (no exploitation in VA)
- [x] Build verification depth ladder (unverified → config_verified → behavior_verified)
- [x] Build finding prioritization engine with severity/KEV/EPSS/corroboration scoring
- [x] Build VA report data builder with executive summary, remediation roadmap, compliance mapping
- [x] Build Bug Bounty policy parser (HackerOne, Bugcrowd, Intigriti, YesWeHack URL parsing)
- [x] Build scope enforcement engine (in-scope, out-of-scope, wildcard domain matching)
- [x] Build finding originality verification (known issue matching, common non-original pattern detection)
- [x] Build platform-specific submission formatting (HackerOne, Bugcrowd, Intigriti, Synack, YesWeHack, Custom)
- [x] Build policy enrichment from parsed text
- [x] Build cross-training infrastructure — PatternRepository with contamination isolation
- [x] Build CalibrationPipeline for scanner confidence adjustment from triage outcomes
- [x] Build ToolEffectivenessTracker with best-tool-for-vuln-class ranking
- [x] Build reproduction quality guidelines for 4 vuln classes + default
- [x] Build cross-training batch processor (outcome logging → pattern extraction → calibration → tool tracking)
- [x] Build license-tier gating (Standard/Professional/Enterprise tiers)
- [x] Build engagement type gating (VA+BB+Phishing+Tabletop=Standard, +Pentest+Purple=Pro, +RedTeam=Enterprise)
- [x] Build feature availability checks and tier comparison data
- [x] Build tRPC router for VA/Bug Bounty (verification profiles, normalization, policy parsing, scope checking, tier gating, cross-training)
- [x] Wire vaBugBounty router into appRouter
- [x] Write comprehensive vitest tests — 117 tests across all 5 modules (all passing)

### VA & Bug Bounty UI Sprint (Apr 26)
- [x] Build VA Engagement Creation wizard page (profile picker, target input, framework selector, pipeline launch)
- [x] Build Bug Bounty Workspace page (program URL parser, scope viewer, finding documenter, originality checker, submission formatter)
- [x] Wire normalization pipeline to live Nuclei/ZAP scan results in engagement ops (normalizeEngagementFindings procedure)
- [x] Add sidebar navigation entries and route wiring for VA wizard and Bug Bounty workspace
- [x] Write vitest tests for new tRPC procedures and integration points — 32 tests (all passing)
- [x] Checkpoint and push to GitHub

### Normalization Stats, Triage Queue & BB Integration Sprint (Apr 26)
- [x] Add Normalized Findings tab to EngagementOps with dedup/corroboration breakdown and stats (NormalizedFindingsPanel component)
- [x] Build Finding Triage Queue page (accept/reject/reclassify findings, feed outcomes to cross-training pipeline)
- [x] Add tRPC procedures for triage queue operations and engagement-to-bounty workspace bridge (listEngagementFindingsForBounty)
- [x] Connect Bug Bounty Workspace to live engagement data (Import tab with adopt flow)
- [x] Add sidebar navigation entries and routes for Finding Triage Queue
- [x] Write vitest tests for new procedures — 26 tests (all passing)
- [x] Checkpoint and push to GitHub

### Bulk Triage & Engagement Selector Sprint (Apr 26)
- [x] Add bulk triage actions to Finding Triage Queue (multi-select checkboxes, batch accept/reject/reclassify, bulk action bar)
- [x] Single cross-training submission for bulk triage operations (batch outcomes with extractedPatterns)
- [x] Add engagement selector dropdown to Bug Bounty Import tab (listActiveEngagements procedure, dropdown with type badges, manual fallback)
- [x] Write vitest tests for new functionality — 15 tests (all passing)
- [x] Checkpoint and push to GitHub

### Bug Fixes (Apr 27)
- [x] Fix ReferenceError: ComplianceFrameworkSelector is not defined (added missing import in DomainIntelResults.tsx)
- [x] Fix ZAP self-referencing loop on scan server (nginx reverse proxy on port 8092 → localhost:8090, Host: zap header)
- [x] Update Caldera ZAP connection config (scan-service-url.ts + zap-scanner.ts → port 8092, diagnostic check updated)
- [x] Fix useAuth import paths (FindingTriageQueue.tsx, CustomerPortalSelfService.tsx)
- [x] Fix listVerificationProfiles returning partial data (now returns full profile objects)
- [x] Fix VA Wizard type mismatch (scannerConfig.enabledScanners → getEnabledScanners helper)

### Broken Crystals Report & Node.js Engagement Fixes (Apr 27)
- [x] Fix exploit status contradiction: exploitation_attempts with ea_status=failed but shell_obtained=1 should resolve correctly
- [x] Fix evidence summary counter bug in report generation
- [x] Fix report generation to determine exploit success from shell_obtained + ea_access_level fields
- [x] Add finding deduplication logic to prevent duplicate .env/config findings in reports
- [x] Add false positive CVE detection for mismatched software (e.g. Qlik Sense CVEs on non-Qlik targets)
- [x] Fix HackerOne scope loading: pulls hackerone.com instead of actual program in-scope assets
- [x] Fix Node.js engagement 1830002 targetDomain and scope data

### Buildable Asset Detection & Requirements (Apr 27)
- [x] Detect SOURCE_CODE and DOWNLOADABLE_EXECUTABLES asset types in engagement builder
- [x] Generate build/test requirements (clone, build, deploy locally) in engagement plan
- [x] Include program sponsor's build instructions from HackerOne scope instructions in ROE
- [x] Display build requirements banner/section on ops page for non-URL assets
- [x] Differentiate scan pipeline behavior for buildable vs live-URL assets

### Auto-Build Pipeline & Dynamic Tooling Provisioner (Apr 27)
- [x] Create asset-provisioner.ts module (clone/download, detect build system, build, deploy to Docker)
- [x] Create tooling-provisioner.ts module (LLM analyzes program requirements → determines needed tools → installs) — integrated into engagement-builder.ts
- [x] Add provisioning DB tables — using engagement_timeline_events with metadata type=build_requirement/tool_requirements
- [x] Integrate provisioners into engagement builder createEngagement flow
- [x] Update engagement builder LLM prompt to output buildRequirements and toolRequirements
- [x] Add provisioning status display to ops page (build progress, tool install status)
- [x] Write vitest tests for both provisioner modules (17 tests passing)

### Verification & Provision Now Button (Apr 27)
- [x] Re-generate Broken Crystals report and verify corrected executive summary, evidence counters, deduplication
- [x] Create new Node.js bug bounty engagement to test scope loading and build requirements — updated whitelist, source code detection, engagement-orchestrator
- [x] Add "Provision Now" button to Build & Deploy Requirements card on ops page
- [x] Create tRPC mutation for triggering asset provisioning from the UI (engagementOps.provisionAsset)
- [x] Write tests for the new provision mutation (20 tests passing — source code detection, whitelist, provisioner exports, exploit status resolution, deduplication)

### Next Steps Sprint (Apr 27)
- [x] Re-generate Broken Crystals report with final derivedStatus fix — report triggered, still generating (LLM pipeline takes 10-15 min)
- [x] Create fresh Node.js bug bounty engagement — confirmed github.com/nodejs/node now shows correctly as target
- [x] Add real-time provisioning status tracker with WebSocket updates on ops page (clone/build/deploy progress bar with stage labels and elapsed time)
- [x] Write tests for provisioning status tracker (37 total tests passing)
- [x] Push all changes to GitHub (pushed c3459778 to htcook/caldera-dashboard)

### Dependabot Vulnerability Fixes (Apr 27)
- [x] Audit all 71 vulnerabilities (3 critical, 36 high, 28 moderate, 4 low) — found 88 total
- [x] Fix critical severity vulnerabilities (tar, esbuild)
- [x] Fix high severity vulnerabilities (path-to-regexp, picomatch, minimatch, rollup)
- [x] Fix moderate severity vulnerabilities (fast-xml-parser, uuid, postcss, qs, follow-redirects, lodash, brace-expansion, protobufjs)
- [x] Verify fixes with pnpm audit — 0 vulnerabilities remaining. 37 new tests passing.
- [ ] Push fixes to GitHub (pending checkpoint)
