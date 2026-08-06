# AC3 Caldera Dashboard — Architecture Reference

**Author:** Harrison Cook — Ace of Cloud LLC  
**Last Updated:** April 24, 2026  
**Classification:** INTERNAL — Engineering Reference

---

## 1. System Overview

The AC3 (Cyber Campaign Command) Caldera Dashboard is a full-stack offensive security operations platform built on React 19 + Tailwind 4 (client), Express 4 + tRPC 11 (server), and TiDB/MySQL (persistence). The platform orchestrates the complete penetration testing lifecycle — from passive reconnaissance through active exploitation, purple team exercises, and automated FedRAMP-compliant report generation.

The codebase comprises approximately **788,669 lines of TypeScript** across **1,402 source files**, organized into three primary layers:

| Layer | Files | LOC | Description |
|---|---|---|---|
| `server/lib/` | 676 | 404,383 | Core business logic, engines, and integrations |
| `server/routers/` | 221 | 115,995 | tRPC procedure definitions (API surface) |
| `client/src/` | 497 | 268,291 | React UI components, pages, and hooks |
| `drizzle/schema.ts` | 1 | ~12,000 | 351 database tables |

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React 19 Client                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │ DI Scans │ │ Exploits │ │ Purple   │ │ Reports    │ │
│  │ & Recon  │ │ & C2     │ │ Team     │ │ & Client   │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘ │
│       └─────────────┴────────────┴─────────────┘        │
│                     tRPC Hooks                           │
└─────────────────────┬───────────────────────────────────┘
                      │ /api/trpc (Superjson)
┌─────────────────────▼───────────────────────────────────┐
│                  Express 4 Server                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │              221 tRPC Routers                     │   │
│  │  (publicProcedure / protectedProcedure / admin)   │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                                │
│  ┌──────────────────────▼───────────────────────────┐   │
│  │           676 Server Library Modules              │   │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────────────┐   │   │
│  │  │Engines  │ │Integra-  │ │LLM Specialists   │   │   │
│  │  │& Scans  │ │tions     │ │& AI Governance   │   │   │
│  │  └─────────┘ └──────────┘ └──────────────────┘   │   │
│  └──────────────────────────────────────────────────┘   │
│                         │                                │
│  ┌──────────────────────▼───────────────────────────┐   │
│  │  TiDB/MySQL (351 tables) │ S3 Storage │ LLM API  │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Server Library Subsystems

The `server/lib/` directory contains 6 subdirectories and ~670 top-level modules organized by domain:

### 3.1 Subdirectories

| Directory | Purpose |
|---|---|
| `integration-registry/` | Auto-discovery engine for third-party API integrations, classification, and wiring proposals |
| `knowledge/` | Static knowledge bases (post-exploit credential knowledge, MITRE mappings, tool catalogs) |
| `llm-specialists/` | Modular LLM specialist framework — 5 decomposed specialists for discovery context analysis |
| `passive/` | Passive reconnaissance modules (ToS compliance, passive-only scan tools) |
| `scanners/` | Active scanner integrations (Nmap, Nuclei, ZAP, Burp, custom scanners) |
| `vendors/` | Vendor-specific API adapters (Shodan, Censys, SecurityTrails, etc.) |

### 3.2 Core Engine Modules

The platform's intelligence is concentrated in several key engine modules:

| Module | Purpose | Key Exports |
|---|---|---|
| `pentest-report-pipeline.ts` | 6-step automated FedRAMP report generation | `runPentestReportPipeline()` |
| `discovery-context-engine.ts` | Monolithic discovery context analysis (5 specialists) | `analyzeDiscoveryContext()` |
| `correlation-engine.ts` | Multi-source finding correlation and deduplication | `CorrelationEngine` singleton |
| `domain-intel-advanced.ts` | Advanced domain intelligence with tech-vuln matching | `matchTechnologiesAgainstAllFeeds()` |
| `scan-policy-engine.ts` | Scan mode classification and tool tier management | `TOOL_TIER_CLASSIFICATION` |
| `purple-team-model.ts` | Purple team data model (ROE, test plans, detection tests) | All purple team interfaces |
| `campaign-orchestrator.ts` | Multi-phase campaign state machine | `campaignRunStates` |
| `c2-orchestrator.ts` | C2 framework orchestration (Caldera, Sliver, Havoc, etc.) | `activePlans` |
| `attack-coverage.ts` | MITRE ATT&CK coverage analysis with C2 registry | `C2Registry`, `getC2Registry()` |
| `adaptive-scan-strategy.ts` | Dynamic scan strategy with graduation scoring | `graduationStore` |
| `ai-governance.ts` | AI model registry, approval queues, audit trails | `modelRegistry`, `approvalQueue` |

---

## 4. In-Memory State Architecture

The platform uses **137 module-level in-memory stores** (Maps, Sets, singletons) across the server layer. These fall into 5 categories, each with distinct persistence and lifecycle characteristics.

### 4.1 Category Taxonomy

| Category | Count | Persistence | Lifecycle | Risk Level |
|---|---|---|---|---|
| **Static Catalogs** | ~25 | Immutable after init | Process lifetime | None — read-only reference data |
| **TTL Caches** | ~35 | Ephemeral (5min–24hr) | Auto-evict on TTL expiry | Low — cache miss triggers re-fetch |
| **Active Operation State** | ~20 | Volatile | Tied to operation lifecycle | **High** — lost on restart |
| **Performance Trackers** | ~30 | Volatile | Accumulates over time | Medium — degrades optimization |
| **Singleton Engines** | ~15 | Volatile | Lazy-initialized | Medium — re-initialized on restart |
| **Domain Stores** | ~12 | Volatile | Tied to domain analysis | Medium — re-analyzable |

### 4.2 Static Catalogs (No Persistence Risk)

These are compile-time or boot-time constants that never change at runtime:

| Store | Module | Type | Description |
|---|---|---|---|
| `TOOL_TIER_CLASSIFICATION` | `scan-policy-engine.ts` | `Record` | Scan tool aggressiveness tiers (passive/standard/active) |
| `EDR_EVASION_CATALOG` | `evasion-scorecard.ts` | `Array` | 30+ EDR evasion technique entries |
| `ATTACK_TECHNIQUE_CATALOG` | `evasion-scorecard.ts` | `Array` | MITRE ATT&CK technique metadata |
| `KALI_TOOLS_CATALOG` | `ttp-ingest.ts` | `Array` | Kali Linux tool-to-TTP mappings |
| `CISA_KEV_CVES` | `domain-intel-advanced.ts` | `Set` | Known Exploited Vulnerabilities CVE IDs |
| `HIGH_VALUE_SIDS` | `bloodhound-parser.ts` | `Set` | Active Directory high-value SIDs |
| `BUILT_IN_PROFILES` | `c2-traffic-profiles.ts` | `Array` | Default C2 malleable profiles |
| `BUILT_IN_FEEDS` | `darkweb-osint-service.ts` | `Array` | Default dark web OSINT feed configurations |
| `BUILT_IN_BLUEPRINTS` | `infra-deploy-automation.ts` | `Array` | Infrastructure deployment templates |
| `EXPLOIT_CLASSIFICATION_SCHEMA` | `exploit-verification-engine.ts` | `Object` | Exploit classification taxonomy |

### 4.3 TTL Caches (Self-Healing)

These caches have explicit TTL expiration and automatically refresh on miss:

| Store | Module | TTL | Key Type | Description |
|---|---|---|---|---|
| `sectorInsightsCache` | `adaptive-scan-strategy.ts` | 5 min | sector string | Industry-specific scan insights |
| `responseCache` | `api-helpers.ts` | varies | URL string | HTTP response cache for external APIs |
| `epssCache` | `epss-service.ts` | varies | CVE ID | FIRST EPSS probability scores |
| `cpeCache` | `dynamic-cpe-matcher.ts` | 24 hr | tech string | CPE dictionary match results |
| `kevIndex` | `cisa-kev-product-map.ts` | 24 hr | CVE ID | CISA KEV product mapping index |
| `promptCache` | `llm-reliability.ts` | 5 min | prompt hash | LLM response cache for identical prompts |
| `scoreCache` | `adjustment-effectiveness-tracker.ts` | varies | finding ID | Adjustment effectiveness scores |
| `installCache` | `exploit-dependency-manager.ts` | varies | tool name | Exploit tool installation status |
| `discoveryCache` | `integration-registry/registry.ts` | varies | API URL | Integration discovery results |
| `_cache` | `knowledge/knowledge-loader.ts` | varies | knowledge key | Static knowledge base entries |

### 4.4 Active Operation State (HIGH RISK — Volatile)

These stores track in-flight operations and are **lost on process restart**. This is the primary architectural concern for production deployments on Cloud Run (which shuts down instances when idle).

| Store | Module | Key Type | Description | Impact of Loss |
|---|---|---|---|---|
| `activePlans` | `c2-orchestrator.ts` | plan ID | Active C2 orchestration plans | Orphaned C2 sessions |
| `activeExecutions` | `caldera-graph-executor.ts` | execution ID | Running attack graph executions | Incomplete attack chains |
| `activeBurpScans` | `burp-auto-scan.ts` | scan ID | Running Burp Suite scans | Lost scan progress |
| `activeScanStore` | `ai-security-validation.ts` | scan ID | AI security validation scans | Lost validation state |
| `campaignRunStates` | `campaign-orchestrator.ts` | campaign ID | Multi-phase campaign state machines | Incomplete campaigns |
| `chainRuns` | `discovery-chain-orchestrator.ts` | chain ID | Discovery chain orchestration runs | Incomplete discovery |
| `pollers` | `caldera-c2-callback-poller.ts` | engagement ID | Active C2 callback pollers | Missed callbacks |
| `activeLoops` | `continuous-training.ts` | loop ID | Active ML training loops | Interrupted training |
| `activeScans` | `scan-concurrency.ts` | array | Currently running scans | Orphaned scan processes |
| `disclosureDocs` | `client-ip-disclosure.ts` | engagement ID | IP disclosure documents | Lost disclosure state |
| `approvalGates` | `client-ip-disclosure.ts` | engagement ID | IP disclosure approval gates | Blocked workflows |

> **Architectural Note:** Active operation state is the most critical gap in the current architecture. For production resilience, these stores should be migrated to database-backed state machines with heartbeat-based recovery. The `campaignRunStates` and `activePlans` stores are the highest priority candidates because they represent long-running multi-step operations that cannot be easily re-derived.

### 4.5 Performance Trackers (Degraded Optimization)

These accumulate performance data over time to optimize future operations:

| Store | Module | Description | Impact of Loss |
|---|---|---|---|
| `graduationStore` | `adaptive-scan-strategy.ts` | Passive-to-active graduation scores | Reverts to default thresholds |
| `connectorPerfStore` | `adaptive-scan-strategy.ts` | Connector reliability metrics | Loses connector preference |
| `performanceStore` | `c2-actor-feedback-loop.ts` | Actor technique performance history | Loses technique optimization |
| `modulePerformanceCache` | `exploit-feedback-loop.ts` | Exploit module success rates | Loses exploit prioritization |
| `feedbackLogCache` | `exploit-feedback-loop.ts` | Exploit feedback log entries | Loses feedback history |
| `exploitHistoryCache` | `exploit-preflight.ts` | Per-target exploit attempt history | May retry failed exploits |
| `callCounts` | `api-resilience.ts` | API call success/failure counts | Resets circuit breaker stats |
| `circuits` | `api-resilience.ts` | Circuit breaker states | All circuits reset to closed |
| `profiles` | `domain-reputation-engine.ts` | Domain reputation profiles | Re-analyzed on next scan |
| `toolDetectionCache` | `external-credential-tools.ts` | Detected credential tools | Re-detected on next use |

### 4.6 Singleton Engines

These are lazy-initialized singleton instances that maintain internal state:

| Store | Module | Description |
|---|---|---|
| `engineInstance` | `correlation-engine.ts` | Finding correlation engine with loaded rules |
| `engineInstance` | `alert-rules-engine.ts` | Alert rules evaluation engine |
| `workerRegistry` | `job-queue.ts` | Background job worker registration |
| `modelRegistry` | `ai-governance.ts` | Registered AI model configurations |
| `approvalQueue` | `ai-governance.ts` | Pending human approval requests |
| `pinStore` | `cert-pinning.ts` | Certificate pinning configurations |
| `freshBurpData` | `campaign-advisor.ts` | Latest Burp scan results for advisory |

---

## 5. Discovery Context Engine Architecture

The Discovery Context Engine is the newest major subsystem, implementing a 5-specialist decomposed LLM analysis pipeline for asset-level intelligence enrichment.

### 5.1 Architecture Pattern: Bounded Delta

Each specialist follows a consistent pattern:

```
Raw Evidence → Deterministic Baseline → LLM Refinement (±20pt) → Validation → Output
                    (always runs)         (optional, bounded)    (grounding check)
```

The bounded delta pattern ensures that LLM responses can only adjust deterministic scores by ±20 points, preventing hallucination-driven score inflation. If the LLM response fails evidence grounding validation, the system falls back to the deterministic baseline with a `confidence_degraded` mode flag.

### 5.2 Specialist Decomposition

| Specialist | Module | Deterministic Signals | LLM Enhancement |
|---|---|---|---|
| **Asset Attribution** | `llm-specialists/asset-attribution/` | WHOIS registrant, cert org, DNS patterns, reverse DNS | Subsidiary inference, hosting provider attribution |
| **Asset Role** | `llm-specialists/asset-role/` | Port signatures, technology stack, hostname patterns | Nuanced role classification beyond pattern matching |
| **Lifecycle Stage** | `llm-specialists/lifecycle-stage/` | Cert expiry, DNS freshness, technology age | Temporal trend interpretation |
| **Business Context** | `llm-specialists/business-context/` | Technology-to-function mapping, regulatory keywords | Revenue path and dependency inference |
| **Threat Relevance** | `llm-specialists/threat-relevance/` | Exposed service scoring, sector-specific threat data | Actor-type relevance and campaign correlation |

### 5.3 Evidence Package Structure

All specialists consume a structured evidence package assembled from raw discovery data:

```
EvidencePackage
├── certEvidence: { issuer, subject, san[], validFrom, validTo, selfSigned }
├── dnsEvidence: { aRecords[], cnameChain[], mxRecords[], txtRecords[], nsRecords[] }
├── bgpEvidence: { asn, asnOrg, prefixes[], peerCount }
├── whoisEvidence: { registrantOrg, registrarName, creationDate, expirationDate, nameServers[] }
├── httpEvidence: { statusCode, server, poweredBy, technologies[], headers }
└── businessIntelEvidence: { industry, companyName, subsidiaries[], products[] }
```

### 5.4 Degradation Modes

| Mode | Trigger | Behavior |
|---|---|---|
| `full_llm` | LLM available, response validates | Deterministic baseline + bounded LLM delta |
| `deterministic_only` | LLM not requested or unavailable | Pure rule-based analysis |
| `confidence_degraded` | LLM response fails validation | Deterministic baseline with reduced confidence scores |

### 5.5 Persistence

Discovery context results are persisted to the `discoveredAssets` table via two JSON columns:

- `discoveryContext` — Full analysis output (all 5 specialists)
- `discoveryContextAnalyzedAt` — Timestamp of last analysis

The UI tab loads persisted results on mount and auto-saves new analysis results when the pipeline completes.

---

## 6. Report Pipeline Architecture

The pentest report pipeline (`pentest-report-pipeline.ts`) generates FedRAMP-compliant Markdown reports through a 6-step process:

| Step | Function | Description |
|---|---|---|
| 1 | `ingestReconData()` | Normalizes raw asset, vuln, tool, and exploit data |
| 2 | `translateSignals()` | Maps findings to CVE, CVSS, MITRE ATT&CK, NIST, OWASP (LLM-assisted) |
| 3 | `generateExploitNarratives()` | Produces human-readable exploit narratives (LLM-assisted) |
| 4 | `calculateRisk()` | Computes likelihood × impact risk matrix |
| 5 | `produceFindings()` | Structures findings into enriched finding cards |
| 6 | `buildVisualizations()` | Generates Mermaid diagrams for attack paths |

### 6.1 Report Sections

The generated report includes the following sections:

1. Executive Summary
2. Scope of Target System (FedRAMP 6.1)
3. Attack Vectors Assessed (FedRAMP 6.2)
4. Timeline for Assessment Activity (FedRAMP 6.3)
5. Methodology and Tools
6. Actual Tests Performed and Results (FedRAMP 6.4)
7. Findings and Evidence (FedRAMP 6.5)
8. Access Paths (FedRAMP 6.6)
9. Risk Matrix
10. Remediation Roadmap
11. OSINT Intelligence Summary
12. Caldera Operations Evidence
13. Exploitation Evidence
14. Manual Findings
15. Purple Team Sections (PT-1 through PT-7, conditional)
16. **Asset Discovery Context Intelligence** (new, conditional)
17. Credential Exposure Summary

---

## 7. Purple Team Data Model

The purple team subsystem (`purple-team-model.ts`) provides structured data types for bilateral red/blue team exercises:

| Component | Interface | Description |
|---|---|---|
| ROE Addendum | `PurpleTeamROEAddendum` | EDR vendor notification, evasion scope bounding, exercise windows |
| Test Plan | `PurpleTeamTestPlan` | Defensive stack inventory, test cases, success criteria |
| Detection Tests | `DetectionTest` | Per-TTP detection test results with bilateral evidence |
| Bilateral Evidence | `BilateralEvidenceRecord` | Red team action + blue team detection paired records |
| Unified Timeline | `UnifiedTimeline` | Merged chronological timeline of red/blue events |
| Negative Evidence | `NegativeEvidence` | Structured absence-of-detection records |
| Detection Metrics | `DetectionMetrics` | Aggregate detection rates, MTTD, coverage gaps |

---

## 8. Database Schema Overview

The platform uses 351 MySQL/TiDB tables organized by domain. Key table groups include:

| Domain | Table Count | Key Tables |
|---|---|---|
| Engagement Management | ~15 | `engagements`, `engagementAssets`, `engagementFindings` |
| Asset Discovery | ~10 | `discoveredAssets`, `discoveredSubdomains`, `discoveredCertificates` |
| Vulnerability Intel | ~20 | `vulnerabilities`, `vulnMatches`, `exploitAttempts` |
| C2 Operations | ~15 | `c2Implants`, `c2Listeners`, `c2Operations` |
| Campaign Management | ~10 | `campaigns`, `campaignPhases`, `campaignTargets` |
| Purple Team | ~8 | `purpleTeamExercises`, `detectionTests`, `bilateralEvidence` |
| OSINT | ~15 | `osintFindings`, `darkwebListings`, `breachCredentials` |
| Reports | ~8 | `ac3Reports`, `ac3ReportFindings`, `ac3ReportArtifacts` |
| User & Auth | ~5 | `user`, `activeSessions`, `activityLogs` |
| AI Governance | ~8 | `aiModelAuditLog`, `aiApprovalRequests` |

---

## 9. Authentication and Authorization

The platform uses Manus OAuth with role-based access control:

| Role | Access Level | Description |
|---|---|---|
| `owner` | Full | Platform owner — all operations |
| `admin` | Administrative | User management, engagement creation, report generation |
| `user` | Standard | View engagements, run scans, view reports |

Authentication flows through `server/_core/context.ts`, which extracts the session cookie and injects `ctx.user` into all tRPC procedures. Protected procedures use `protectedProcedure`, and admin-only operations use a middleware guard checking `ctx.user.role`.

---

## 10. External Integration Points

The platform integrates with numerous external services:

| Category | Services |
|---|---|
| **Reconnaissance** | Shodan, Censys, SecurityTrails, URLScan, crt.sh |
| **Vulnerability Intel** | NVD, CISA KEV, EPSS, Exploit-DB, abuse.ch |
| **Breach Data** | DeHashed, Have I Been Pwned (via API) |
| **C2 Frameworks** | Caldera, Sliver, Havoc, Mythic, Cobalt Strike |
| **Scanning** | Nmap, Nuclei, ZAP, Burp Suite, Nikto |
| **AI/LLM** | OpenAI API (via Manus built-in proxy) |
| **Storage** | S3-compatible (DigitalOcean Spaces) |
| **Phishing** | GoPhish |
| **Cloud** | DigitalOcean (infrastructure deployment) |

---

## 11. Deployment Considerations

### 11.1 Cloud Run Limitations

The platform deploys on Cloud Run, which has important implications for the in-memory architecture:

1. **Instance shutdown on idle** — All volatile state (§4.4) is lost when the instance scales to zero.
2. **No persistent filesystem** — File-based caches are not viable.
3. **Cold start latency** — Singleton engines (§4.6) must re-initialize on each cold start.

### 11.2 Recommended Mitigations

For production hardening, the following in-memory stores should be migrated to database-backed persistence:

| Priority | Store | Current Module | Recommended Migration |
|---|---|---|---|
| **P0** | `campaignRunStates` | `campaign-orchestrator.ts` | DB state machine with heartbeat recovery |
| **P0** | `activePlans` | `c2-orchestrator.ts` | DB-backed plan state with checkpoint/resume |
| **P1** | `activeExecutions` | `caldera-graph-executor.ts` | DB execution log with replay capability |
| **P1** | `pollers` | `caldera-c2-callback-poller.ts` | DB-backed poller registration |
| **P2** | `graduationStore` | `adaptive-scan-strategy.ts` | DB table for graduation scores |
| **P2** | `performanceStore` | `c2-actor-feedback-loop.ts` | DB table for technique performance |

### 11.3 Scheduled Tasks

Periodic data updates (NVD refresh, CISA KEV sync, EPSS updates) must not use `setInterval` or `node-cron` due to Cloud Run's idle shutdown behavior. Instead, these are implemented via the Manus scheduled task system, which POSTs to `/api/scheduled/<name>` endpoints.

---

## 12. Testing Strategy

The platform uses Vitest for unit testing. Current test coverage:

| Test Suite | Tests | Description |
|---|---|---|
| `purple-team-enhancements.test.ts` | 25 | Purple team data model, ROE, detection metrics, report pipeline |
| `llm-specialists-modular.test.ts` | 53 | All 5 LLM specialists, evidence packages, validation, scoring |
| `auth.logout.test.ts` | 1 | Authentication logout flow |

Tests are run with `pnpm test` or `npx vitest run <file>`.

---

*This document is maintained alongside the codebase and should be updated when new subsystems are added or architectural patterns change.*
