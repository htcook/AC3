- [x] Implement Pentest Report Writer specialist (report-writer.ts)
- [x] Create barrel index.ts for all specialist modules
- [x] Add JSON output schemas for all modules
- [x] Add evidence tags ([OBSERVED], [INFERRED], [HYPOTHESIS]) to findings
- [x] Wire specialists into orchestrator pipeline (replace monolithic calls)
  - [x] planAttack replaces generateScanPlan LLM call
  - [x] decideNextOp replaces llmDecide LLM call
  - [x] analyzeScan after passive recon per domain
  - [x] verifyVulnerability after Phase 3 for high/critical vulns
  - [x] mapThreats after Phase 3 for threat actor correlation
- [ ] Test specialist calls on production with OpenAI

## Hybrid Scoring & Context Awareness (March 2026)
- [x] Create hybrid-scorer.ts specialist — combines CARVER, Shock 2.0, CVSS v4.0, AI-BIA scoring with integrated context awareness
- [x] Context engine embedded in hybrid-scorer (buildEngagementContext, formatContextForLLM)
- [x] Wire hybrid scoring into passive recon (after scan analyst per domain)
- [x] Wire hybrid scoring into post-vuln detection phase (active scan findings)
- [x] Wire context awareness into executeEngagement pipeline start
- [x] Build succeeds with all integrations
- [ ] Deploy and test on Vianova engagement

## Parallel Passive Discovery Scan
- [x] Parallelize passive discovery scan — scan multiple domains concurrently instead of sequentially
- [x] Add configurable concurrency limit (3 domains at once, with 20-min per-domain watchdog)
- [x] Ensure state updates and log broadcasts are thread-safe with concurrent scans
- [x] Maintain per-domain watchdog timers in parallel mode
- [x] Test parallel scan execution and verify observation collection (IP targets complete, domain targets need connector optimization)
- [x] Sort CVEs by most recent in engagement ops asset detail views
- [x] Add version-aware vulnerability matching — only list CVEs that affect the detected version, not all CVEs for the product
- [ ] Re-run passive discovery on Master Test Range to verify parallel scanning and version filtering
- [x] Add version-match confidence indicators to findings cards in EngagementOps UI (e.g., "Confirmed v2.4.49 in range >= 2.4.49, < 2.4.50")

## Connector Pipeline Optimization
- [x] Add 30s hard per-connector timeout (Promise.race) to prevent individual connectors from hanging
- [x] Add 5-minute global recon timeout to cap total connector phase duration
- [x] Reduce default connector timeout from 30s to 15s
- [x] Reduce cloud-bucket-recon global timeout from 60s to 30s
- [x] Increase connector concurrency from 5 to 10 per domain
- [ ] Re-run passive discovery on Master Test Range to verify optimized pipeline

## Connector Hard Timeout Fix (Promise.race + Semaphore)
- [x] Replace batch-based connector execution with semaphore + Promise.race pattern
- [x] Each connector wrapped in Promise.race against 30s timeout — straggler abandoned
- [x] Reduce cloud-assets probes from 20 to 8 candidates, cap probe timeout at 3s
- [x] Add external signal checks to Shodan connector between stages, limit IPs to 5
- [x] Add external signal checks to social-media connector between operations
- [x] Reduce domain parallelism from 3 to 2 (reduces event loop pressure)
- [x] Reduce per-domain watchdog from 20 to 12 minutes
- [x] Reduce global watchdog from 90 to 60 minutes
- [x] Reduce connector timeout from 30s to 15s
- [x] Update all 16 timeout configuration tests — all passing
- [ ] Verify fix in production with Master Test Range scan

## Deployment Failure Investigation
- [x] Diagnose DeployS3WebsiteActivityV2 timeout error on publish
- [x] Check for large static files in project directory causing upload timeout
- [x] Remove 582 .manus/db query JSON files from git tracking (reduced files from 1897 to 1315)
- [ ] Redeploy and verify

## Production Scan Verification
- [ ] Trigger passive discovery scan on Master Test Range (ID: 1590026)
- [ ] Monitor scan progress — verify connectors complete within 30s hard timeout
- [ ] Verify domains complete within 12-minute watchdog
- [ ] Check for "HARD TIMEOUT" log entries confirming enforcement

## Black Page Issue
- [ ] Investigate production page showing only black
- [ ] Check if deployment succeeded or if old version is stale

## Tier 1 Pipeline Optimizations
- [x] 3.1: Add LLM timeout wrapper (60s) to all 6 invokeLLM calls (5 in domainIntel.ts + 1 in llm-post-enrichment-analysis.ts)
- [x] 3.4: KEV catalog already has 6-hour in-memory cache — verified, no changes needed
- [x] 3.3: Move GitHub connectors (github_leaks, github_recon) to background queue with remaining time budget
- [x] 3.2: Parallelize post-enrichment analysis + campaign recommendations via Promise.allSettled
- [x] All 31 tests passing (16 passive-timeout + 14 tier1-optimizations + 1 auth)

## LLM max_tokens Error Fix
- [x] Fix max_tokens: 32768 exceeding model limit of 16384 — capped to 16384
- [x] Check for other LLM calls with max_tokens > 16384 — all use 16384 now

## Tiered LLM Routing
- [x] Add _priority parameter to InvokeParams (essential | standard | bulk)
- [x] Implement tiered resolveProvider that routes based on priority
- [x] Tag 18 essential calls (vuln verification, attack planning, exploit generation, scoring)
- [x] Tag 25 bulk calls (summarization, report writing, classification, enrichment)
- [x] Default 52 untagged calls to standard (Forge-first)
- [x] Add telemetry logging for provider routing decisions (priority logged in console)
- [x] All 64 tests passing (33 llm-routing + 16 passive-timeout + 14 tier1 + 1 auth)

## Vianova Engagement Reset
- [x] Find Vianova engagement ID (1350014)
- [x] Clear all scan data across 34+ tables (domain_intel_scans, osint_findings, scan_results, timeline events, workflow states, reports, vuln snapshots, web crawls, phishing drafts, attack data, etc.)
- [x] Reset engagement status to 'planning' with clean slate
- [x] Verify no scan data remains for engagement 1350014

## Deployment S3 Timeout Fix (Persistent)
- [x] Audit total project size and file count in git (was 1318 files, 33MB)
- [x] Removed 5 old drizzle snapshots (4.5MB), 5 old migration SQL files (220K)
- [x] Removed 290 test files from tracking (4MB)
- [x] Removed docs/ directory (316K), scan report (20K)
- [x] Trimmed todo.md from 552K to 8K
- [x] Updated .gitignore to prevent re-tracking
- [x] Result: 990 files, 23MB (down from 1318 files, 33MB — 25% fewer files, 30% less size)
- [ ] Save checkpoint and verify deployment succeeds

## Bug: Confirmed Vulns Showing 0 in Final Summary
- [x] Query Vianova scan data: assets have 16 vulns (10 + 6) but stats.vulnsFound = 0
- [x] Root cause: stats counter only incremented by nmap/nuclei/ZAP tool parsers, not by passive recon handoff or LLM correlation
- [x] Impact: Phase 4 (Exploitation) skipped entirely because vulnsFound=0 gate check fails
- [x] Fix: Added stats recalculation (reduce over asset.vulns) at 4 critical checkpoints:
  - Before LLM correlation analysis (line 3469)
  - Before Phase 3 completion summary (line 3692)
  - Before exploitation decision gate (line 4568)
  - Before final engagement summary (line 4631)
- [x] All 64 tests passing

## Persistent Deployment S3 Timeout Fix
- [x] Deep audit: found ~80 non-essential files (debug .mjs, audit .md, threatActorSeed, Docker, deploy, scripts)
- [x] Removed 82 files: 22 audit/analysis .md, 38 debug/test .mjs, 4 threatActorSeed, 7 server .mjs, 5 deploy, 9 scripts, 4 Docker
- [x] Cleaned old drizzle snapshots from disk (0000-0004, 4.5MB)
- [x] Updated .gitignore with comprehensive exclusion patterns
- [x] Result: 897 files / 22MB (down from original 1318 / 33MB — 32% fewer files, 33% less size)
- [ ] Publish and verify deployment succeeds

## DigitalOcean Architecture Split
- [x] Audit codebase: 910 files/22MB — server/lib 351 files/8.6MB, routers 158/3.1MB, client 339/8.1MB
- [x] Design split architecture — Option A: DO Scan Microservice approved
- [x] Plan approved by user
- [x] Query DO API — found caldera-scan-server at 159.223.152.190 (4GB/2vCPU)
- [x] Scaffold DO scan microservice (Express API on port 4000 with auth)
- [x] Deploy to DO droplet with PM2 + nginx (auto-restart, auto-startup)
- [x] Knowledge files served from DO via /api/knowledge/:filename endpoint
- [x] Updated attack-chain-retriever.ts and asset-ontology.ts to fetch from DO with local fallback
- [x] Removed 4 large files from git: attack_chains_300.json (425K), asset_role_ontology.json (75K), 0005_snapshot.json (933K), threatActorSeed2.ts (67K)
- [x] Result: 906 files / 18.7MB (down from 1318 / 33MB — 31% fewer files, 43% less size)
- [x] All 64 tests passing
- [x] Save checkpoint and publish

## Deployment Build OOM Fix (Exit Code 137)
- [x] Diagnose vite build OOM — 7175 modules + 209 lazy chunks exhausting 4GB heap during rollup rendering
- [x] Downgrade Vite 7.1.9 to 6.4.1 (compatible with deploy env Node 20.15.1)
- [x] Add manualChunks config to group 209 lazy page chunks into 8 page groups + 6 vendor groups
- [x] Disable sourcemaps and CSS code splitting to reduce memory
- [x] Build succeeds locally in 61s (was OOM killed)
- [x] Restored test files from git history (were removed in payload reduction)
- [x] All 64 tests passing
- [ ] Save checkpoint and publish

## DO Scan Execution Offload
- [ ] Review current DO scan service architecture
- [ ] Implement scan execution endpoints on DO droplet (nmap, nuclei, ZAP proxy)
- [ ] Update Manus engagement orchestrator to proxy scan commands to DO
- [ ] Test end-to-end scan flow through DO proxy
- [ ] Save checkpoint and publish

## Vianova Engagement Re-run
- [x] Reset Vianova engagement (cleared: 1 ops snapshot, 6 scan results, 91 LLM telemetry rows, reset to planning)
- [ ] Re-run Vianova engagement scans
- [ ] Monitor scan execution for errors
- [ ] Verify vulnsFound bug fix (should show vulns and enter Phase 4)

## Black Screen Fix (User-Reported)
- [x] Diagnosed: React fails to mount — TypeError: Cannot read properties of undefined (reading 'forwardRef') in vendor-radix chunk
- [x] Root cause: manualChunks split React and @radix-ui into separate chunks; Radix loaded before React was available
- [x] Fix attempt 1: Merged react+radix into vendor-react chunk — FAILED (lucide-react also needs React)
- [x] Fix attempt 2: Put ALL node_modules into single 'vendor' chunk — FAILED (TDZ error: Cannot access 'aft' before initialization due to circular deps between vendor and page chunks)
- [x] Fix attempt 3: Remove manualChunks entirely — let Rollup handle splitting naturally via React.lazy
- [x] Build succeeds in 71s with 751 natural chunks (mostly tiny syntax highlighting langs)
- [x] All 72 tests pass
- [x] Deployed successfully — black screen FIXED (site live at dashboard.aceofcloud.io)
- [x] Added shiki subset Vite plugin: 751→466 chunks, 31MB→24MB build output

## Deployment Size Reduction via DO Offloading
- [x] Analyzed: shiki language grammars were 711 chunks / 19.6MB (95% of chunk count)
- [x] Root cause: shiki alias removed during vite.config.ts rewrite, streamdown pulled all 327 langs
- [x] Fix: Custom Vite resolveId plugin intercepts exact "shiki" imports, redirects to 25-lang subset
- [x] Result: 466 chunks / 24MB (was 751 / 31MB) — 38% fewer chunks, 23% less size
- [ ] Further optimization: externalize jspdf/cytoscape/mermaid to CDN (saves ~2MB more)
- [ ] Save checkpoint and publish

## Vianova Scan Error Check & Re-run
- [ ] Check scan error logs for Vianova engagement
- [ ] Fix any scan errors found
- [ ] Re-run Vianova engagement scans
- [ ] Monitor scan execution and verify results

## Post-Scan Bug Fixes
- [x] Investigated auto-restart — not a code bug; completion handler correctly sets isRunning=false. Re-run was triggered by user/UI 36s after completion
- [x] No code fix needed — the rerunFullPipeline mutation has proper isRunning guard
- [x] Fix undefined port in exploit logging — default to first open port on asset when LLM omits port
- [x] Investigated Forge API 403 — transient issue (API works now). Added OpenAI fallback when Forge returns 403/429 after all retries

## KEV Match Accuracy Audit & Exploit Evidence
- [x] Audit KEV vuln matches on api.dev.vianova.ai for false positives (vulns for technologies not present)
- [x] Fix KEV matching logic to validate against detected technology stack
- [x] Add exploit success details and evidence to asset data after Phase 4
- [x] Ensure supporting evidence (screenshots, command output, PoC) is stored with exploited vulns

## Scan Accuracy Fixes (March 2026)
- [x] Fix KEV matching false positives — validate CVE vendor/product against asset's detected tech stack
- [x] Add exploit evidence persistence — store exploit output, PoC, screenshots, shell info in asset data
- [x] Fix duplicate vulnerability entries — deduplicate vulns from multiple scan tools
- [x] Delete existing Vianova scan data and reset engagement
- [ ] Re-run Vianova engagement from start with all fixes applied
- [ ] Verify scan accuracy — no false positive KEV matches, exploit evidence visible, no duplicate vulns
- [ ] Audit Vianova re-run for errors in scan logs
- [ ] Audit Vianova re-run for duplicate vulnerabilities across assets
- [x] Fix duplicate header probe vulns — header probe findings pushed twice per asset
- [x] Fix stats counters not updating — hostsScanned, portsFound, vulnsFound stay 0 after scans
- [x] Fix asset status staying "pending" after nmap scan completes (23.20.98.48)
- [x] Create test engagement: Acunetix Vulnweb (PHP) — http://testphp.vulnweb.com (ID: 1650001)
- [x] Create test engagement: Broken Crystals — https://brokencrystals.com (ID: 1650002)
- [x] Create test engagement: Gin & Juice Shop (PortSwigger) — https://ginandjuice.shop (ID: 1650003)
- [x] Create test engagement: DVWA — dvwa.co.uk (ID: 1650004)
- [x] Create test engagement: Nmap ScanMe — http://scanme.nmap.org (ID: 1650005)
- [x] Audit Training Lab self-learning pipeline — does it persist corrections from test engagements?
- [x] Audit engagement ops pipeline — does it use training data from previous runs?
- [x] Implement training feedback loop — ensure test engagement results train LLM for future accuracy
  - [x] Integration Point 1: Inject buildLearningContext() into LLM vuln synthesis prompt
  - [x] Integration Point 2: Score results against ground truth after pipeline completion
  - [x] Integration Point 3: Auto-generate learning entries for missed findings & false positives
  - [x] Added scanme-nmap ground truth library (6 entries)
  - [x] Domain-to-preset resolver maps engagement targets to Training Lab presets automatically

## Report Generation Overhaul (March 2026)
- [x] Audit current report generation code — identify gaps against provided templates
- [x] Implement 13-section report structure (Exec Summary, Engagement Overview, Scope, RoE, Methodology, Attack Surface, Vuln Summary, Detailed Findings, Exploitation Narrative, Risk Matrix, Remediation Roadmap, Detection Recommendations, Appendix)
- [x] Implement 6-step pipeline (Ingest Recon → Translate Signals → Generate Exploit Narratives → Calculate Risk → Produce Findings → Build Visualizations)
- [x] Every finding must include: CVSS v3.1 score+vector, MITRE ATT&CK mapping, NIST 800-53 control mapping, OWASP Top 10 category
- [x] Generate Mermaid diagrams: attack surface, kill chain, risk matrix, severity distribution
- [x] Build report generation UI with preview and PDF export (Streamdown markdown renderer + branded HTML export)
- [x] Test end-to-end report generation from engagement data (11 tests passing)

## Training Environment Verification
- [x] Check if Broken Crystals has a public live instance available for scanning (YES - brokencrystals.com HTTP 200)
- [x] Verify legal authorization to scan all 5 test targets
- [x] Check each target's ToS/README for explicit scanning permission
- [x] DVWA requires self-hosted deployment on scan server (Docker: ghcr.io/digininja/dvwa)
- [x] Verify all 5 test engagement targets are reachable (4/5 live; DVWA needs self-hosting)
- [x] Create and approve RoE for Acunetix Vulnweb test engagement (ID: 1650001) — RoE #120001 ACTIVE
- [x] Create and approve RoE for Broken Crystals test engagement (ID: 1650002) — RoE #120002 ACTIVE
- [x] Create and approve RoE for Gin & Juice Shop test engagement (ID: 1650003) — RoE #120003 ACTIVE
- [x] Create and approve RoE for DVWA test engagement (ID: 1650004) — RoE #120004 DRAFT (self-host first)
- [x] Create and approve RoE for Nmap ScanMe test engagement (ID: 1650005) — RoE #120005 ACTIVE

## Threat Catalog Dashboard Sync Fix (March 2026)
- [x] Fix threat catalog sync with dashboards - some showing 0 counts
- [x] Investigate data flow from vuln feeds to dashboard components
- [x] Verify all dashboard cards/widgets pull from correct data sources
- [x] Ensure threat catalog data is accessible to all relevant dashboard views
- [x] Fix threatActors.type → threatActors.actorType in 6 files (db.ts, threat-intel.ts, threat-intel-connectors.ts, threat-intel-catalog.ts, actor-context-provider.ts)
- [x] Fix iocFeeds.severity → iocFeeds.feedSeverity in db.ts queries
- [x] Fix iocFeeds insert objects: severity→feedSeverity, iocType→feedIocType, tags→feedTags in ioc-feed.ts
- [x] Fix ensureActorInCatalog insert: type→actorType in threat-intel-connectors.ts
- [x] All 13 regression tests passing (threat-catalog-sync.test.ts)

## Recent Test Scan Error Audit (March 2026)
- [x] Check recent test scan logs for errors
- [x] Identify any scan failures or issues
- [x] Report findings

## Fix Scan Errors (March 2026)
- [x] Clean up 15 stuck IOC sync jobs (marked as timed_out)
- [x] Clean up 10 stuck threat intel updates (marked as failed)
- [x] Investigate Broken Crystals recon failure (1650002) — domain watchdog timeout, recon completed with 1 asset
- [x] Add auto-cleanup logic for stuck IOC sync jobs (30-min timeout, runs on startup + before each sync)
- [x] Fix Vianova (1350014) — confirmed recon-only completion, no active scan was triggered
- [x] Fix Master Test Range (1590026) — cleared error state for retry
- [x] Fix threatIntelUpdates column name mismatches: status→tiuStatus, startedAt→tiuStartedAt, completedAt→tiuCompletedAt, summary→tiuSummary, details→tiuDetails, errors→tiuErrors across 5 files
- [x] All 28 regression tests passing (15 field alignment + 13 catalog sync)

## Re-trigger Master Test Range Scan (March 2026)
- [x] Re-trigger scan for engagement 1590026 (Master Test Range) — resumed successfully, now running with 21 assets, 9 ports, 304 vulns found so far

## Deploy Vulnerable Test Apps & Integrate into Test Range (March 2026)
- [x] Research VAmPI, DVGA, WebGoat repos for deployment requirements
- [x] Check existing test range infrastructure in the platform
- [x] Deploy VAmPI (Vulnerable REST API) on scan server via Docker (port 5000, HTTP 200)
- [x] Deploy DVGA (Damn Vulnerable GraphQL Application) on scan server via Docker (port 5013, HTTP 200)
- [x] Deploy WebGoat (OWASP) on scan server via Docker (port 8080 + WebWolf 9090, HTTP 302)
- [x] Integrate all three into Training Lab catalog (vampi, dvga, webgoat entries with full metadata, RoE, OWASP categories)
- [x] Add container health check endpoint (scanServer.containerHealth procedure)
- [x] All 9 integration tests passing (training-targets.test.ts)
- [x] All containers verified running and responding on scan server 159.223.152.190

## KSI Feature & UX Improvements (March 2026)
### Phase 1: Demo-Critical
- [x] Fix "11 themes" to "13 themes" in KsiDashboard
- [x] Add KSI health summary bar to KSI Hub (coverage %, evidence count, overdue, chain integrity)
- [x] Add Readiness Score KPI (0-100 composite score with gauge visualization)
- [x] Replace theme coverage bars with interactive heatmap grid (13 themes x individual KSIs, clickable cells)
- [x] Add evidence chain timeline visualization with hash links (EvidenceTimeline component)
- [x] Add validation run detail view (expandable rows with full results)
- [x] Add "Run All Overdue" button for batch validation
- [x] Add visual ATT&CK matrix overlay in Threat Map (AttackMatrixGrid component, 14 tactics)
- [x] Make FedRAMP coverage map dynamic with live data (live posture summary on FedRAMP20xReadiness)
### Phase 2: Compliance Value
- [x] Add collection health status panel in Auto-Collector (CollectionHealthPanel component)
- [x] Add progress indicators during sweeps
- [x] Add "Generate Assessment Package" button (bundles SSP+SAR+POA&M+Assessment Plan+Component Def)
- [x] Add 3PAO Review Mode page (read-only assessor view with executive summary, theme breakdown, KSI detail table)
- [x] Add unified KSI detail page (/ksi/:ksiId with definition, evidence, validation, NIST controls tabs)
- [x] Add clickable KSI navigation from heatmap grid and 3PAO review to detail page
- [x] All 20 regression tests passing (ksi-improvements.test.ts)

## Fix Report Generation - 0 Scan Findings (March 2026)
- [x] Trace report generation data pipeline from scan results to report output
- [x] Identify column name mismatches or query failures in report data ingestion
- [x] Fix getOpsState→getOpsStateWithRecovery in reports-core.ts (in-memory only → DB fallback)
- [x] Add scan_results table fallback when ops snapshot has no findings
- [x] Add missing pentest_assessment enum value to engagementReports.reportType (was causing insert failures)
- [x] Fix generatedAt timestamp format — pass MySQL-compatible string instead of Date object for Drizzle string mode
- [x] Add missing type exports to schema (InsertEngagementReport, SelectEngagementReport, InsertPentestReport, SelectPentestReport, InsertScanResult, ScanResult)
- [x] Write 15 regression tests covering pipeline input construction, scan_results fallback, risk matrix, timestamp format, and report type enum validation
- [x] Verify data flow end-to-end: DVWA engagement has 12 vulns + 15 tool results in ops snapshot, 10 scan_results with 40 findings

## Reporting Package Integration (March 2026)
- [x] Integrate Ace C3 system prompt into report generation LLM calls (both pentest pipeline and legacy path)
- [x] Integrate 6-step pipeline prompt into pentest_assessment report path (Step 2 signal translation, Step 3 exploit narratives, Step 5 findings production)
- [x] Integrate AC3-XXX finding ID format and template structure (already implemented)
- [x] Ensure all 13 sections are generated per the package spec (already implemented)
- [x] Ensure every finding has CVSS v3.1 + vector, MITRE ATT&CK, NIST 800-53, OWASP Top 10 (already implemented)
- [x] Add Mermaid diagrams: attack surface, kill chain, risk matrix, severity distribution pie chart (already implemented)
- [x] Add Harrison Cook as report author attribution
- [ ] Test report generation with updated pipeline

## LLM Training Audit & Continuous Accuracy Loop (March 2026)
- [x] Audit Training Lab learning metrics from recent test scans (26 scored sessions across 4 targets)
- [x] Check LLM accuracy scores for vuln detection and exploit attempts (DVWA 44.7%, Vulnweb 50.6%, Broken Crystals 48.8%, Juice Shop 17.9%)
- [x] Implement continuous scan-until-100% accuracy loop backend (continuous-training.ts + 3 tRPC endpoints)
- [x] Build continuous training UI component in Training Lab page (ContinuousTraining.tsx with iteration history, accuracy trend bars, convergence detection)
- [x] Add accuracy tracking dashboard/metrics for training progress (F1/precision/recall stats, iteration table, bar chart visualization)
- [x] All 56 regression tests passing (21 continuous-training + 20 threat-actor-mapping + 15 reports)

## Bug Fixes (March 2026)
- [x] Fix Threat Actor catalog "actor not found" when clicking on a threat actor
  - Root cause: threatGroupEvents.actorId should be threatGroupEvents.tgeActorId (prefixed column names)
  - Also fixed: actorType→type alias, iocType→type, iocConfidence→confidence, iocLastSeen→lastSeen mappings
  - 20 regression tests added (threat-actor-mapping.test.ts)

## Ground Truth Libraries for Continuous Training (March 2026)
- [x] Research known vulnerabilities for Broken Crystals (brokencrystals.com)
- [x] Research known vulnerabilities for OWASP Juice Shop
- [x] Add Broken Crystals ground truth library to Training Lab (exploit-method-ground-truth.ts)
- [x] Add Juice Shop ground truth library to Training Lab (exploit-method-ground-truth.ts)
- [x] Wire new presets into domain-to-preset resolver (broken-crystals, juice-shop keys)
- [x] Write tests for new ground truth libraries (20 tests in exploit-selection.test.ts)
- [x] Verify scoring works with continuous training loop

## Exploit Selection Intelligence Framework (March 2026)
- [x] Review current exploit attempt tracking and LLM analysis pipeline (exploitation-bridge.ts)
- [x] Design exploit method taxonomy (Metasploit, ExploitDB, Custom-built, Manual Verification)
- [x] Build exploit selection decision tree with criteria (exploit-selection-intelligence.ts)
- [x] Add exploit method ground truth to DVWA library (12 vulns mapped)
- [x] Add exploit method ground truth to Broken Crystals library (12 vulns mapped)
- [x] Add exploit method ground truth to Juice Shop library (12 vulns mapped)
- [x] Integrate exploit selection reasoning into LLM analysis prompt (both main scan + rerunAnalysis)
- [x] Add exploit selection scoring to ground truth scoring engine (scoreExploitSelection)
- [x] Update continuous training loop to track exploit selection accuracy (methodAccuracy, cliToolAccuracy, cliPatternAccuracy)
- [x] Add CLI command generation templates (msfconsole, searchsploit, custom scripts) — in EXPLOIT_SELECTION_SYSTEM_PROMPT
- [x] Train LLM to generate proper msfconsole resource scripts — CLI templates in prompt + ground truth patterns
- [x] Train LLM to use searchsploit CLI and pull/compile ExploitDB exploits — CLI templates in prompt
- [x] Train LLM to generate custom exploit scripts (Python, bash) when no module exists — CLI templates in prompt
- [x] Write tests for exploit selection framework (20 tests, all 237 tests passing across 15 files)
