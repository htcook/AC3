# ScanForge Technical Architecture Analysis

**Prepared for:** Claude (Architecture Review)
**Author:** Harrison Cook — AceofCloud
**Date:** May 2026
**Codebase:** `server/scanforge/` — 23,663 lines across 38 modules

---

## 1. Executive Overview

ScanForge is the vulnerability scanning subsystem of the AC3 (Ace Cloud Cyber Command) platform. It replaces the previous approach of SSH-invoking individual tools (Nuclei, ZAP, SQLMap) on a remote scan server with a unified, intelligent scanning engine that runs in-process alongside the engagement orchestrator.

ScanForge's distinguishing characteristic is its **intelligence-driven architecture**: rather than running a static set of checks against every target, it uses LLM-powered context classification to understand *what* it is scanning, selects optimal detection strategies accordingly, and continuously improves its detection templates through a self-learning feedback loop.

The system occupies a critical position in the AC3 pipeline:

```
DI Scan Pipeline (domainIntel.ts)
        │
        ▼
Engagement Orchestrator (engagement-orchestrator.ts)
        │
        ├── Phase 6: Vulnerability Scanning ──▶ ScanForge (in-process)
        │                                         ├── Template Engine (37 templates)
        │                                         ├── Protocol Scanners (24 scanners)
        │                                         ├── Proof Engine (6 strategies)
        │                                         └── Ember Bridge (internal network)
        │
        ├── Phase 7: Exploitation
        └── Phase 8: Post-Exploitation
```

ScanForge is invoked during Phase 6 of the engagement orchestrator via the `engagement-integration.ts` module, which provides a lightweight in-process bridge. It also feeds findings into the hybrid scoring engine for prioritization and into the auto-report generator for deliverable creation.

---

## 2. Architecture Overview

### 2.1 Module Inventory

| Module | Lines | Role |
|--------|-------|------|
| `intelligence/dedup-coverage.ts` | 1,323 | Finding deduplication, normalization, FN coverage gap detection |
| `intelligence/context-engine.ts` | 1,117 | LLM-powered asset classification, adaptive scan planning, finding correlation |
| `intelligence/fp-fn-prevention.ts` | 1,109 | Multi-layer confidence scoring, corroboration, proof validation |
| `engine/ember-bridge.ts` | 937 | Internal network scanning via deployed Ember agents |
| `engine/deep-research-agent.ts` | 859 | 30+ TI feed monitoring, LLM template generation |
| `engine/engagement-integration.ts` | 814 | Engagement orchestrator bridge (in-process scan execution) |
| `engine/exploit-reasoning-prompts.ts` | 801 | 8 specialized LLM prompts for reasoning pipeline |
| `engine/proof-engine.ts` | 747 | Proof-based verification (6 exploitation strategies) |
| `protocols/registry.ts` | 710 | Protocol scanner registry (24 scanners) |
| `protocols/cloud-scanners.ts` | 676 | AWS IMDS, CloudStorage, K8s, Docker, etcd, ContainerRegistry |
| `engine/template-engine.ts` | 637 | YAML template loading, execution, matcher evaluation |
| `engine/scan-orchestrator.ts` | 762 | 5-phase scan lifecycle coordinator |
| `intelligence/ti-engine.ts` | 582 | CISA KEV, EPSS, MITRE ATT&CK, DFIR artifacts, threat actor profiles |
| `engine/auth-scanner.ts` | 566 | Authenticated DAST (form login, OAuth, API key, mTLS) |
| `engine/accuracy-tracker.ts` | 516 | TP/FP/FN verdict tracking, rolling metrics per template |
| `engine/auto-promoter.ts` | 514 | Template lifecycle: draft → candidate → promoted → production |
| `engine/knowledge-base.ts` | 509 | Cross-template state sharing (OpenVAS-inspired KB) |
| `engine/llm-prompts.ts` | 509 | 8 structured LLM prompts (triage, enrichment, mapping, etc.) |
| `queue/scan-queue.ts` | 495 | In-memory priority queue with configurable concurrency |
| `protocols/ics-scanners.ts` | 459 | Modbus, DNP3, BACnet, EtherNet/IP, OPC-UA |
| `engine/detection-plugins.ts` | 442 | YAML-based safe detection plugin system |
| `api/router.ts` | 442 | RESTful API + WebSocket for scan lifecycle |
| `engine/hybrid-scoring.ts` | 420 | CVSS + KEV + EPSS + context → normalized 0–100 priority |
| `engine/snmp-handler.ts` | 408 | SNMP v1/v2c/v3 scanning |
| `engine/confidence-tuner.ts` | 387 | Self-tuning confidence thresholds from historical data |
| `engine/smb-handler.ts` | 371 | SMB share/user enumeration, vuln detection |
| `engine/reassessment-agent.ts` | 336 | Post-engagement LLM comparison (ScanForge vs Nuclei/ZAP) |
| `engine/cvss-engine.ts` | 320 | CVSS v3.1 + v4.0 base/temporal/environmental scoring |
| `engine/oob-server.ts` | 308 | Out-of-band callback server for blind vuln detection |
| `protocols/iot-scanners.ts` | 297 | MQTT, CoAP, UPnP |
| `bridge/ac3-bridge.ts` | 251 | ScanForge ↔ Engagement Orchestrator data translation |
| `engine/dynamic-attack-mapper.ts` | 240 | MITRE ATT&CK kill chain coverage analysis |
| `engine/exploit-reasoning-narratives.ts` | 228 | Reasoning chain tracking for report transparency |
| `types/index.ts` | 627 | Core type definitions (scan lifecycle, findings, templates) |

**Total:** 23,663 lines (excluding test files: 2,877 lines across 4 test files)

### 2.2 Five-Phase Scan Lifecycle

The `ScanOrchestrator` coordinates every scan job through five sequential phases, each with configurable timeouts and concurrency limits:

| Phase | Timeout | Concurrency | Purpose |
|-------|---------|-------------|---------|
| **Recon** | 120s | 5 | Port scanning, service detection, technology fingerprinting |
| **Enumeration** | 180s | 3 | Directory brute-force, subdomain enumeration |
| **Detection** | 600s | 5 | Template execution, protocol scanning, vulnerability checks |
| **Verification** | 120s | 3 | Re-test findings for false positive reduction |
| **Reporting** | 30s | 1 | Aggregate results, compute risk scores, generate summary |

Between Phase 1 (Recon) and Phase 2 (Enumeration), the orchestrator performs **LLM context classification** — it sends recon data to the context engine, which classifies the target's environment (cloud/IoT/ICS/container/traditional) and selects optimal scanners for subsequent phases. This classification is refined after recon data is available (Phase 1.5).

### 2.3 Data Flow

```
Target Input
    │
    ▼
[Phase 0: Context Classification] ──▶ AssetClassification
    │                                    (environment, technologies,
    │                                     compliance frameworks)
    ▼
[Phase 1: Recon] ──▶ Open ports, services, banners
    │
    ▼
[Phase 1.5: Context Refinement] ──▶ Refined classification with recon data
    │
    ▼
[Phase 2: Enumeration] ──▶ Directories, subdomains, endpoints
    │
    ▼
[Phase 3: Detection] ──▶ Raw findings (templates + protocol scanners)
    │                         │
    │                         ▼
    │                    [FP/FN Prevention Engine]
    │                         │
    │                         ▼
    │                    [Proof Engine] ──▶ Verified findings
    │
    ▼
[Phase 4: Verification] ──▶ Re-tested findings, confidence adjusted
    │
    ▼
[Phase 5: Reporting] ──▶ Deduplicated, scored, enriched findings
                              │
                              ▼
                         [Hybrid Scoring] ──▶ Priority 0–100
                              │
                              ▼
                         [Dedup + Normalization]
                              │
                              ▼
                         [Coverage Gap Detection]
```

---

## 3. Template Engine

### 3.1 Template Structure

ScanForge uses a declarative template system inspired by Nuclei. Templates are JSON files stored in `server/scanforge/templates/definitions/` and define:

- **Target protocol and request** (HTTP method, path, headers, body)
- **Matchers** (response conditions that indicate vulnerability)
- **Metadata** (severity, CVEs, CWEs, remediation guidance)

Currently **37 static templates** are deployed, organized by category:

| Category | Count | Examples |
|----------|-------|---------|
| DNS Security | 11 | Dangling CNAME, DNSSEC misconfig, zone transfer, tunneling, typosquat |
| HTTP Vulnerabilities | 5 | CVE-specific, exposure, misconfig, security headers, tech detection |
| OWASP Top 10 | 14 | SQLi, XSS, SSRF, SSTI, XXE, LFI, IDOR, CMDi, CSRF, deserialization |
| Infrastructure | 4 | Default credentials, cloud misconfig, TLS misconfig |
| Default Credentials | 2 | Service-level and HTTP-level default credential checks |

### 3.2 Template Lifecycle (Auto-Promoter)

The Deep Research Agent generates new templates from TI feeds. These enter a **four-stage promotion pipeline**:

```
draft → candidate → promoted → production
```

Two rule sets govern promotion:

| Rule | DEFAULT_PROMOTION_RULES | FAST_TRACK_RULES |
|------|------------------------|-------------------|
| Min Engagements | 3 | 1 |
| Min Precision | 0.80 | 0.95 |
| Min Recall | 0.60 | 0.80 |
| Min F1 Score | 0.70 | 0.85 |
| Max FP Rate | 0.15 | 0.05 |
| Min Effectiveness | 65 | 80 |
| Min LLM Confidence | 0.60 | 0.85 |
| Min Total Scans | 5 | 3 |

The **FAST_TRACK_RULES** allow high-confidence templates (LLM confidence ≥ 0.85, precision ≥ 0.95) to reach production after just 1 engagement and 3 scans, enabling rapid response to emerging threats.

### 3.3 Self-Improvement Loop

```
Engagement completes
        │
        ▼
[Accuracy Tracker] ──▶ Log all ScanForge findings with verdict (TP/FP/FN)
        │
        ▼
[Reassessment Agent] ──▶ LLM compares ScanForge vs Nuclei/ZAP/SQLMap results
        │                    - Identifies false negatives (what was missed)
        │                    - Identifies false positives (what was wrong)
        │                    - Generates template improvement recommendations
        │
        ▼
[Confidence Tuner] ──▶ Adjusts per-template confidence thresholds
        │                - High FP rate → raise threshold (harder to trigger)
        │                - High TP rate → boost confidence (trusted more)
        │
        ▼
[Auto-Promoter] ──▶ Evaluate templates against promotion rules
                      - Promote if thresholds met
                      - Reject if FP rate too high
                      - Defer if insufficient data
```

---

## 4. Deep Research Agent

### 4.1 Feed Architecture

The Deep Research Agent monitors **30+ threat intelligence feeds** organized into 7 categories:

| Category | Feeds | Purpose |
|----------|-------|---------|
| CVE/Exploit | NVD, CISA KEV, ExploitDB | Detect newly weaponized vulnerabilities |
| Reconnaissance | Shodan, Censys, SecurityTrails, URLScan | Detect exposed services |
| Threat Actor | Spicy TIP, OTX, MalwareBazaar | Detect actor-specific TTPs |
| Breach/Darkweb | DeHashed, HIBP, Daily Dark Web, IntelX, Hudson Rock, Leak Check | Detect credential exposure |
| Bug Bounty | HackerOne hacktivity | Detect real-world exploit patterns |
| Abuse | AbuseIPDB, abuse.ch, Tor exit nodes, Blocklist.de, Spamhaus, OpenPhish | Detect malicious infrastructure |
| Knowledge Base | OWASP, MITRE ATT&CK | Map findings to frameworks |

Each feed adapter normalizes data into a `ResearchInput` structure:

```typescript
interface ResearchInput {
  feedSource: FeedSource;      // Which feed provided this data
  researchType: ResearchType;  // cve_analysis, exploit_research, trend_analysis, etc.
  subject: string;             // CVE ID, domain, IP, threat actor, CWE
  data: Record<string, any>;   // Raw feed data
  urgency: "critical" | "high" | "medium" | "low";
}
```

### 4.2 Template Generation Pipeline

When the Deep Research Agent identifies actionable intelligence:

1. **Feed adapter** fetches and normalizes data into `ResearchInput`
2. **LLM analysis** determines if a new detection template is warranted
3. **Template generation** — LLM produces structured template definition:
   - HTTP requests (method, path, headers, body)
   - Matchers (response conditions)
   - Metadata (CVE, CWE, CVSS, references)
4. **Draft insertion** — template saved to `scanforge_generated_templates` table with status "draft"
5. **Validation** — template enters the auto-promoter pipeline

### 4.3 Research Types

The agent supports 11 research types, each with specialized LLM prompts:

- `cve_analysis` — Analyze a new CVE for exploitability and detection feasibility
- `exploit_research` — Research exploit techniques for a known vulnerability
- `trend_analysis` — Identify emerging attack patterns across feeds
- `gap_analysis` — Find detection gaps in current template coverage
- `ttp_mapping` — Map threat actor TTPs to detection templates
- `zero_day_monitoring` — Monitor for critical items with no patch
- `bug_bounty_pattern` — Extract detection patterns from disclosed bug bounty reports
- `credential_exposure` — Generate checks for leaked credentials
- `malware_analysis` — Analyze malware indicators for detection
- `threat_actor_ttp` — Generate templates targeting specific actor TTPs
- `service_exposure` — Detect exposed services from Shodan/Censys data

---

## 5. Protocol Scanner Registry

### 5.1 Scanner Inventory

The protocol registry manages **24 scanners** across 4 environment categories:

| Category | Scanners | Default Ports |
|----------|----------|---------------|
| **Traditional** | MySQL, PostgreSQL, Redis, MongoDB, SMB, LDAP, RDP, VNC, AMQP, Telnet | 3306, 5432, 6379, 27017, 445/139, 389/636, 3389, 5900/5901, 5672/15672, 23 |
| **Web/Network** | HTTP Security, TLS, DNS | 80/443/8080/8443, 443, 53 |
| **Cloud** | AWS IMDS, CloudStorage, Kubernetes API, Docker API, etcd, ContainerRegistry | 169.254.169.254, various, 6443/8443, 2375/2376, 2379/2380, 5000 |
| **IoT** | MQTT, CoAP, UPnP | 1883/8883, 5683/5684, 1900 |
| **ICS/SCADA** | Modbus, DNP3, BACnet, EtherNet/IP, OPC-UA | 502, 20000, 47808, 44818, 4840 |

### 5.2 Scanner Architecture

Scanners implement the `ProtocolScanner` interface:

```typescript
interface ProtocolScanner {
  name: string;
  protocol: string;
  defaultPorts: number[];
  environments?: AssetEnvironment[];
  scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]>;
  probe(host: string, port: number): Promise<boolean>;
}
```

Two implementation patterns exist:

1. **ToolWrappedScanner** — Wraps existing tools (naabu scripts) as protocol scanners. Used for traditional services (MySQL, PostgreSQL, Redis, etc.). Executes via `scan-server-executor.ts` on the remote scan server.

2. **Native Scanners** — Full TypeScript implementations for cloud/IoT/ICS protocols. These run in-process and handle protocol-specific handshakes directly (e.g., Modbus function code reads, BACnet Who-Is broadcasts, MQTT CONNECT packets).

### 5.3 Environment-Aware Routing

The registry supports environment-based scanner selection:

```typescript
// Get only scanners relevant to a cloud environment
const cloudScanners = registry.getByEnvironment("cloud");
// → [AWSIMDSScanner, CloudStorageScanner, KubernetesAPIScanner, ...]

// Get scanners for a specific port
const port502Scanners = registry.getByPort(502);
// → [ModbusScanner]
```

This integrates with the context engine's asset classification — once a target is classified as "ics_ot", only ICS-relevant scanners are invoked, avoiding false positives from running web-focused checks against PLCs.

---

## 6. Intelligence Engines

### 6.1 Threat Intelligence Engine (`ti-engine.ts`)

Operates in two modes:

**Pre-scan mode:** Selects and prioritizes templates based on target context. If the TI engine knows a threat actor targeting the client's industry commonly exploits specific CVEs, those templates are prioritized.

**Post-scan mode:** Enriches findings with TI data for risk scoring. Adds KEV status, EPSS probability, known ransomware campaign associations, and threat actor attribution.

Key data structures:

- **KEV entries** — CVE ID, vendor, product, date added, due date, ransomware campaign use
- **EPSS entries** — CVE, probability (0–1), percentile
- **Threat actor profiles** — name, aliases, target industries/regions, common techniques, common CVEs, tools
- **DFIR artifacts** — persistence mechanisms, lateral movement indicators, exfiltration patterns, each mapped to ATT&CK techniques and scan checks

### 6.2 Context Engine (`context-engine.ts`)

The LLM-powered "brain" of ScanForge. Six capabilities:

1. **Asset Classification** — Identify target environment (cloud/IoT/ICS/container/traditional) with confidence scoring. Falls back to heuristic classification if LLM unavailable.

2. **Adaptive Scan Planning** — Select optimal scanners and templates based on classification. A target classified as "ics_ot" gets Modbus/DNP3/BACnet scanners; a "cloud" target gets AWS IMDS/K8s checks.

3. **Finding Correlation** — Chain individual findings into attack paths. E.g., "exposed admin panel + default credentials + internal network access = full compromise path."

4. **Enriched Narratives** — Generate human-readable finding descriptions that explain business impact, not just technical details.

5. **Compliance Mapping** — Map findings to applicable frameworks (NIST 800-53, FedRAMP, PCI-DSS, HIPAA, IEC 62443, NERC CIP, CIS Benchmarks, DISA STIG).

6. **Risk Contextualization** — Adjust risk scores based on environment. A critical finding on a segmented test server scores lower than the same finding on an internet-facing production database.

### 6.3 FP/FN Prevention Engine (`fp-fn-prevention.ts`)

A six-layer validation system:

| Layer | Purpose | Mechanism |
|-------|---------|-----------|
| **Signal Collection** | Gather evidence from multiple sources | 14 signal types (version_match, banner_match, exploit_proof, etc.) |
| **Confidence Scoring** | Multi-factor confidence calculation | Weighted sum of signal confidences |
| **Corroboration** | Cross-validate across scanners/signals | Multiple scanners finding same issue → confidence boost |
| **Proof Validation** | Safe exploitation to confirm exploitability | 6 proof strategies (reflection, behavioral, OOB, time-based, error-based, computation) |
| **Contextual Filtering** | Environment-aware suppression rules | E.g., suppress "missing HSTS" on internal-only services |
| **Adaptive Thresholds** | Learn from operator feedback | Historical TP/FP patterns adjust future thresholds |

Configuration supports three suppression profiles:

- **Conservative** — Fewer FPs, more FNs (high-confidence reporting only)
- **Balanced** — Default (minReportingConfidence: 60, confirmedThreshold: 80)
- **Aggressive** — More FPs, fewer FNs (report everything above minimal threshold)

### 6.4 Deduplication & Coverage Gap Detection (`dedup-coverage.ts`)

Three integrated subsystems in the largest intelligence module (1,323 lines):

1. **Deduplication Engine** — Fingerprint-based matching using multi-factor fingerprints (target + port + CVE/CWE + title hash). Merges duplicates while preserving highest-confidence evidence.

2. **Normalization Layer** — Unifies severity, CVE/CWE mappings, MITRE ATT&CK technique IDs, and compliance references. Resolves severity disagreements between scanners using confidence-weighted voting.

3. **FN Coverage Gap Detector** — Compares executed templates/scanners against expected coverage matrix for the target's asset environment, protocol profile, and compliance requirements. Identifies missing checks and recommends additional scans.

---

## 7. Hybrid Scoring Engine

### 7.1 Formula

```
hybrid_priority_score =
  ((technical_severity × exposure_modifier) +
   (technical_severity × attack_path_modifier × 0.5) +
   (mission_impact_score × 0.8))

Normalized to 0–100 for UI display.
```

### 7.2 Input Factors

| Factor | Source | Range |
|--------|--------|-------|
| CVSS Base Score | NVD / CVSS Engine | 0–10 |
| KEV Listed | CISA KEV catalog | boolean |
| EPSS Probability | FIRST EPSS API | 0–1 |
| Exposure Level | Context Engine | external (1.4×), internal (1.1×), segmented (0.9×), unknown (1.0×) |
| Asset Criticality | Context Engine | 0–10 |
| Business Role | Context Engine | string → mission impact inference |
| Attack Path Categories | Dynamic Attack Mapper | 13 ATT&CK categories |
| Compensating Controls | Engagement context | 0–1 (higher = more mitigated) |
| Data Sensitivity | Context Engine | 0–10 |
| Operational Criticality | Context Engine | 0–10 |
| Finding State | Proof Engine | verified/probable/suspected/informational/not_affected |
| Exploitability Confidence | FP/FN Engine | 0–1 |

### 7.3 EPSS Severity Boost Bands

| EPSS Threshold | Boost |
|---------------|-------|
| ≥ 0.70 | +1.0 to technical severity |
| ≥ 0.40 | +0.75 |
| ≥ 0.20 | +0.50 |
| ≥ 0.05 | +0.25 |
| < 0.05 | +0.0 |

### 7.4 Output

```typescript
interface HybridScoringResult {
  hybridPriorityScore: number;     // 0–100
  severityBand: SeverityBand;      // critical/high/medium/low/informational
  technicalSeverity: number;       // 0–10
  exposureModifier: number;
  missionImpactScore: number;      // 0–10
  attackPathModifier: number;
  exploitabilityConfidence: number; // 0–1
  attackPathValue: string;
  rationale: string;               // Human-readable explanation
  breakdown: {                     // Component transparency
    baseComponent: number;
    exposureComponent: number;
    attackPathComponent: number;
    missionComponent: number;
    stateAdjustment: number;
    controlsMitigation: number;
  };
}
```

---

## 8. Proof-Based Verification Engine

### 8.1 Proof Strategies

| Strategy | Mechanism | Use Case |
|----------|-----------|----------|
| **Reflection** | Inject unique canary, verify it appears in response | XSS, SSTI, header injection |
| **Behavioral** | Compare responses with/without payload to detect state change | Auth bypass, IDOR |
| **OOB (Out-of-Band)** | Trigger DNS/HTTP callback to dedicated OOB server | Blind SQLi, blind SSRF, blind XXE, blind CMDi |
| **Time-Based** | Measure response time delta with time-delay payloads | Blind SQLi (SLEEP), blind CMDi |
| **Error-Based** | Trigger distinctive error messages confirming vuln class | SQLi error messages, stack traces |
| **Computation** | Inject math expression, verify computed result in response | SSTI ({{7*7}}=49), expression injection |

### 8.2 Proof Output

Each proof attempt produces a cryptographic audit trail:

```typescript
interface ProofResult {
  findingId: string;
  status: "confirmed" | "likely" | "unconfirmed" | "safe_unexploitable" | "error";
  strategy: ProofStrategy;
  confidenceAdjustment: number;  // Added to finding confidence
  canary?: string;               // The unique token used
  proofRequest?: string;         // Request that produced proof
  proofResponse?: string;        // Response excerpt showing proof
  proofHash: string;             // SHA-256 of full proof chain
  verifiedAt: number;
  durationMs: number;
}
```

### 8.3 OOB Server

A dedicated callback server (`oob-server.ts`) handles blind vulnerability detection:

- Registers unique canary tokens per proof attempt
- Listens for HTTP callbacks on a dedicated Express route
- Correlates callbacks to findings via canary token
- Supports DNS-based OOB via subdomain canary matching
- Covers: blind SQLi, blind SSRF, blind XXE, blind CMDi, blind SSTI

---

## 9. Ember Bridge (Internal Network Scanning)

### 9.1 Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  ScanForge   │────▶│ Ember Bridge │────▶│ Ember Agent  │
│  Orchestrator│     │              │     │ (Internal)   │
└──────────────┘     └──────────────┘     └──────────────┘
       │                    │                     │
       │  scan request      │  task dispatch      │  execute scan
       │                    │                     │  from inside
       │                    │                     │  the network
       │                    │◀────────────────────│
       │                    │  beacon results     │
       │◀───────────────────│                     │
       │  normalized        │                     │
       │  findings          │                     │
```

### 9.2 Supported Internal Scan Types

- Port scanning (internal network ranges)
- Service fingerprinting (banner grabbing)
- Web application scanning (internal web apps)
- Credential testing (internal services)
- Network vulnerability detection (CVE checks)
- SMB/LDAP/DNS enumeration
- Certificate analysis (internal CAs)
- Configuration auditing (via agent access)

The bridge translates ScanForge templates into Ember tasks and normalizes Ember intelligence back into ScanForge findings, enabling the same detection logic to work against both external and internal targets.

---

## 10. Supporting Subsystems

### 10.1 Knowledge Base (OpenVAS-Inspired)

An in-memory key-value store per scan session that enables cross-template state sharing:

- **Hierarchical keys:** `host/port/service/finding`
- **Template dependencies:** Templates declare what KB keys they require and produce
- **Auto-population:** Discovery and service detection results populate the KB automatically
- **Persistence:** KB state saved to DB for post-engagement analysis

This allows one template's discoveries to feed into another's checks — e.g., a service detection template populates `ports/443/service=https`, which triggers HTTPS-specific vulnerability templates.

### 10.2 Service Detector

Native service fingerprinting inspired by OpenVAS `nasl_builtin_find_service.c`:

- Banner grabbing on all open ports
- Protocol-specific probes (HTTP, FTP, SMTP, POP3, IMAP, SSH, etc.)
- SSL/TLS service detection and certificate extraction
- Version extraction from banners using regex patterns
- Technology stack fingerprinting for web services
- Populates KB with service information for downstream templates

### 10.3 Authenticated DAST Scanner

Session-aware vulnerability scanning supporting 7 authentication strategies:

- Form-based login (POST credentials)
- Bearer token (API key or JWT)
- Cookie injection (pre-authenticated session)
- OAuth2 client credentials flow
- Basic HTTP authentication
- API key (header/query)
- Certificate-based (mTLS)

Features automatic session expiry detection and re-authentication, enabling scanning of authenticated pages invisible to unauthenticated scans.

### 10.4 Dynamic Attack Mapper

Maps discovered vulnerabilities to the MITRE ATT&CK kill chain (14 tactics, TA0043–TA0040). Provides:

- Kill chain phase coverage analysis
- Gap identification (phases with no techniques exercised)
- Attack path visualization data for reports
- Contextual prompts for the LLM based on current coverage

### 10.5 Exploit Reasoning Narratives

Tracks the reasoning chain behind every exploit decision for report transparency:

- Why a vulnerability was selected for exploitation
- What exploit method was chosen and why
- What tools/dependencies were required
- Expected vs actual outcome
- How the result feeds into the next decision

### 10.6 CVSS Engine

Full implementation of CVSS v3.1 and v4.0 scoring:

- Base score calculation from vector components
- Temporal and environmental modifiers
- Vector string parsing and generation
- Severity classification (None/Low/Medium/High/Critical)
- Auto-scoring from vulnerability characteristics when CVSS vector unavailable

### 10.7 LLM Prompt Pack

Eight specialized prompts for the ScanForge reasoning pipeline:

1. **Triage** — Finding state classification (verified/probable/suspected/informational)
2. **Enrichment** — Analyst-ready summaries with business context
3. **Attack Mapping** — MITRE ATT&CK technique alignment
4. **FedRAMP Alignment** — NIST 800-53 Rev. 5 control mapping
5. **False Positive Review** — FP likelihood assessment
6. **Remediation Planner** — Actionable fix guidance with priority
7. **Report Writer** — Professional assessment prose
8. **Executive Summary** — Leadership-ready overview

All prompts return structured JSON schemas for deterministic, parseable output.

---

## 11. Integration Points

### 11.1 Engagement Integration (`engagement-integration.ts`)

The primary integration path — runs ScanForge in-process during Phase 6:

- No queue, no Redis, no IPC overhead
- Uses template engine directly for HTTP/TCP detection
- Routes internal targets through Ember agents via the bridge
- Logs findings alongside Nuclei/ZAP for side-by-side comparison
- Feeds results into accuracy tracker for self-improvement
- Respects engagement scope (ROE) and checkpoint tracking

### 11.2 AC3 Bridge (`ac3-bridge.ts`)

Data translation layer between ScanForge and the engagement orchestrator:

- Translates ScanForge findings to AC3 engagement data format
- Maps ScanForge severity bands to AC3 severity levels
- Forwards WebSocket events to the engagement ops WebSocket
- Supports dual-write migration path (ScanForge alongside existing scanners)

### 11.3 Migration Path

The AC3 bridge defines a three-phase migration:

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | **Current** | ScanForge runs alongside existing scanners (dual-write) |
| Phase 2 | Planned | ScanForge becomes primary, SSH fallback for unsupported tools |
| Phase 3 | Planned | Full ScanForge, SSH executor deprecated |

---

## 12. Architecture Observations & Questions for Claude

### 12.1 Strengths

1. **Intelligence-driven scanning** — The LLM context classification is genuinely differentiated. Most scanners run the same checks regardless of target; ScanForge adapts its approach based on understanding.

2. **Self-improvement loop** — The accuracy tracker → reassessment agent → confidence tuner → auto-promoter pipeline creates genuine machine learning without requiring labeled training data. Each engagement improves detection quality.

3. **Proof-based verification** — Six proof strategies with cryptographic audit trails provide evidence-grade findings, not just pattern matches.

4. **Multi-environment coverage** — Cloud/IoT/ICS/container scanners with environment-aware routing is rare in a single platform.

5. **Deduplication + coverage gap detection** — The FN coverage gap detector is particularly valuable — it identifies what *wasn't* checked, not just what was found.

### 12.2 Potential Concerns

1. **In-memory queue** — The scan queue is in-memory with no persistence. If the process crashes mid-scan, all queued jobs are lost. The code acknowledges this ("For future scaling, this can be swapped for BullMQ with Redis") but for production reliability this may need attention sooner.

2. **LLM dependency for core scanning** — If the LLM is unavailable, the context engine falls back to heuristics, but the deep research agent, reassessment agent, and enrichment pipelines all hard-depend on LLM availability. A sustained LLM outage degrades the self-improvement loop.

3. **Template engine YAML parser** — The template engine uses a custom "simple YAML parser" rather than a proper YAML library. The comment says "For production, swap this with the `yaml` npm package." This could cause template parsing failures for complex templates.

4. **Ember bridge coupling** — The Ember bridge assumes Ember agents are deployed and reachable. If no agents are available, internal network scanning silently fails. Error handling and fallback behavior should be explicit.

5. **OOB server in shared Express app** — The OOB callback server runs on the same Express instance as the main application. In production, blind vulnerability detection requires a dedicated domain with wildcard DNS. The current architecture may not support this without infrastructure changes.

6. **Concurrency limits are static** — Phase concurrency (e.g., detection: 5 concurrent) is hardcoded. For large engagements with many targets, this could be a bottleneck. Dynamic concurrency based on available resources would be more efficient.

7. **No circuit breaker for external feeds** — The deep research agent monitors 30+ feeds. If multiple feeds are down or rate-limited simultaneously, the agent could spend its entire cycle on timeouts rather than processing available data.

### 12.3 Questions for Claude's Review

1. **Template generation quality control** — The FAST_TRACK_RULES allow production promotion after just 1 engagement and 3 scans. Is this sufficient validation for a template that will run against real client infrastructure? What additional safeguards would you recommend?

2. **Scoring formula weighting** — The hybrid scoring formula weights mission_impact at 0.8× and attack_path at 0.5×. Are these weights appropriate? Should they be configurable per engagement type (e.g., compliance assessment vs penetration test)?

3. **Context engine cache invalidation** — The classification cache has no TTL. If a target's infrastructure changes between scans, stale classifications could cause incorrect scanner selection. What cache invalidation strategy would you recommend?

4. **FP/FN prevention threshold tuning** — The adaptive threshold system learns from operator feedback, but there's no mechanism to prevent threshold drift over time (e.g., if an operator consistently marks findings as FP, thresholds could rise until real vulnerabilities are suppressed). Should there be bounds or decay?

5. **Dedup fingerprint collision** — The dedup engine uses target + port + CVE/CWE + title hash. Could this merge genuinely distinct findings that happen to share these attributes (e.g., same CVE on different endpoints of the same host)?

6. **Proof engine safety** — The proof engine performs "safe, non-destructive" exploitation. How should we define and enforce safety boundaries? Should there be a ROE gate before proof attempts, similar to the credential testing gate in the DI pipeline?

7. **Knowledge base memory pressure** — The KB is in-memory per scan session. For large engagements with thousands of findings, could this cause memory pressure? Should there be a size limit or LRU eviction?

8. **Migration path timing** — The AC3 bridge defines a 3-phase migration from SSH-based scanning to full ScanForge. What criteria should gate each phase transition? How do we validate that ScanForge achieves parity with the existing scanner stack before deprecating SSH execution?

---

## 13. Test Coverage

Current test files:

| File | Tests | Coverage |
|------|-------|----------|
| `scanforge.test.ts` | Core engine tests | Template execution, scoring, queue |
| `fp-fn-prevention.test.ts` | FP/FN engine | Confidence scoring, corroboration, proof validation |
| `context-engine.test.ts` | Context engine | Asset classification, scan planning, correlation |
| `dedup-coverage.test.ts` | Dedup + coverage | Fingerprinting, normalization, gap detection |
| `scanforge-engines.test.ts` | Engine integration | Orchestrator, protocol scanners, accuracy tracker |

---

## 14. Relationship to DI Pipeline & Engagement Orchestrator

### 14.1 DI Pipeline Integration

The DI scan pipeline (`domainIntel.ts`) feeds ScanForge in two ways:

1. **Passive intelligence** — DI stages 3.5–3.6 (KEV + Vuln Feeds) provide vulnerability context that ScanForge uses for template prioritization
2. **Active scanning** — When `scanMode === 'active'`, the engagement orchestrator invokes ScanForge during Phase 6 with targets discovered during DI stages 1–4

### 14.2 Engagement Orchestrator Integration

ScanForge is invoked during Phase 6 (Vulnerability Scanning) of the engagement orchestrator. The orchestrator provides:

- Target list (from Phase 5 enumeration)
- Scope constraints (ROE)
- Discovered credentials (from Phase 5 credential testing)
- Technology fingerprints (from Phase 4 DI enrichment)

ScanForge returns:

- Prioritized findings (via hybrid scoring)
- Attack path mappings (via dynamic attack mapper)
- Proof evidence (via proof engine)
- Coverage gap analysis (via dedup-coverage)

These feed into Phase 7 (Exploitation) for exploit selection and Phase 8 (Post-Exploitation) for lateral movement planning.

---

## 15. Summary Statistics

| Metric | Value |
|--------|-------|
| Total lines of code | 23,663 |
| Number of modules | 38 |
| Static templates | 37 |
| Protocol scanners | 24 |
| TI feed sources | 30+ |
| Proof strategies | 6 |
| LLM prompt specializations | 8 |
| Compliance frameworks supported | 10 |
| Authentication strategies | 7 |
| MITRE ATT&CK tactics mapped | 14 |
| Test files | 5 (2,877 lines) |
| Scan phases | 5 |
| Template lifecycle stages | 4 |
| Environment classifications | 7 |
| Confidence signal types | 14 |

---

*End of analysis. Ready for Claude's architectural review and recommendations.*
