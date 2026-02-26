# Attack Emulation Enhancement — Integration Analysis

**Author:** Manus AI  
**Date:** February 26, 2026  
**Scope:** Integration of the Attack Emulation Enhancement document into the Caldera Admin Dashboard threat actor data ingest, enhancement, and emulation pipeline

---

## 1. Executive Summary

The Attack Emulation Enhancement document proposes five interconnected modules designed to transform DFIR-derived ATT&CK mappings into structured, graph-driven adversary emulation plans with validation hooks, safety gating, and telemetry scoring. After a comprehensive audit of the existing Caldera Admin Dashboard codebase — spanning 40+ service files, 80+ database tables, and the full SSIL specification — this analysis concludes that **substantial infrastructure already exists** to support four of the five proposed modules. The platform's existing Attack Sequence Learner, TTP Knowledge Base, Hybrid Scoring Engine, Evasion Orchestrator, and SSIL Scan Policy Engine collectively cover approximately 60–70% of the proposed functionality. The primary net-new construction required is the **Ability Graph Engine** (DAG model with preconditions, exit criteria, and conditional edges) and the **Telemetry Validation outcome scoring layer**.

The integration strategy below maps each proposed module to existing platform components, quantifies coverage gaps, and recommends a phased build approach that maximizes reuse while delivering the document's full vision.

---

## 2. Module-by-Module Integration Map

### 2.1 Module 1: DFIR-to-TTP Extraction Layer

The document calls for a structured pipeline that extracts actor objective, initial access vector, execution chain, privilege escalation path, lateral movement, persistence mechanisms, collection targets, exfiltration methods, observables, and environmental assumptions from DFIR reports into normalized TTP packages.

**Existing Platform Coverage:**

| Component | Location | Current Capability |
|---|---|---|
| Attack Sequence Learner | `server/lib/attack-sequence-learner.ts` | LLM-powered pipeline that processes ingested incident reports to extract structured attack sequences (ordered phases with techniques, tools, commands, duration), identify threat actors and behavioral patterns, map exploits to real-world usage context, and generate Caldera adversary emulation profiles |
| Incident Reports Table | `drizzle/schema.ts` → `incidentReports` | Stores DFIR source data with `attackSequence`, `ttpsExtracted`, `iocsExtracted`, `actorsIdentified`, `malwareIdentified`, `cvesMentioned`, `attackNarrative`, `emulationGuidance`, `exploitContext`, and `incidentType` classification |
| Attack Sequence Templates | `drizzle/schema.ts` → `attackSequenceTemplates` | Persists ordered phases with techniques, tools, commands, Caldera ability mappings, evasion intelligence, `avgDwellTime`, `successRate`, and `detectionDifficulty` scoring |
| TTP Knowledge Base | `drizzle/schema.ts` → `ttpKnowledge` | Deep per-technique understanding with `executionMethods`, `toolsUsed`, `iocPatterns`, `artifacts`, `detectionRules`, `eventLogSources`, `calderaAbilities`, `prerequisiteTechniques`, `followUpTechniques`, `defensiveGaps`, and red/blue team value scoring |
| TTP Ingest Pipeline | `server/lib/ttp-ingest.ts` | Ingests MITRE ATT&CK STIX bundles, Atomic Red Team tests, LOLBAS binaries, Metasploit modules, and Kali tools catalog into the knowledge base |

The existing `attack-sequence-learner.ts` already performs the core DFIR-to-TTP extraction described in the document. The `extractAttackSequence()` function uses the LLM to parse incident reports into ordered phases with techniques, tools, commands, duration, and narrative. The `attackSequenceTemplates` table stores the output in the exact structure the document describes — ordered phases, actor mapping, Caldera abilities, evasion techniques, and dwell time. The `processReport()` function orchestrates the full pipeline: extraction, template generation, exploit enrichment, actor cross-referencing, and TTP knowledge updates.

**Gap Analysis — Two Missing Pieces:**

The first gap is **Environmental Assumptions Extraction**. The current pipeline captures what the attacker did but not what the target environment looked like. The document calls for structured extraction of OS version, domain topology, security tooling deployed, network segmentation posture, and cloud provider configuration. This data is currently buried in the free-text `attackNarrative` field rather than being structured.

The second gap is **SSIL Observation Normalization**. DFIR-extracted IOCs and artifacts are stored in the `iocsExtracted` JSON column but are not wired into the SSIL observation normalizer. This means DFIR-derived intelligence does not auto-populate the unified observations table, cannot trigger alerting rules, and is not correlated with live scan findings.

**Integration Recommendation:**

Extend the existing `attack-sequence-learner.ts` with two additions rather than building a new module. First, add an `environmentalAssumptions` structured field to `ExtractedAttackSequence` that captures `{ os: string[], domainType: string, cloudProvider?: string, securityStack: string[], networkSegmentation: string, identityProvider?: string }`. Update the LLM extraction prompt to populate this field. This data feeds directly into the Ability Graph Builder's preconditions (Module 3). Second, build a new `adaptDfirResults()` adapter in the observation normalizer that transforms `iocsExtracted` and `artifacts` from incident reports into `NormalizedObservation` records. Wire this into the `processReport()` pipeline so DFIR intelligence auto-populates the unified observations table and triggers the alerting rules engine when a DFIR-extracted IOC matches a live scan finding.

---

### 2.2 Module 2: Evidence-Anchored ATT&CK Mapper

The document calls for attaching evidence references, observables, confidence scores, environmental constraints, and expected telemetry signals to each ATT&CK technique, creating a rich evidence layer that supports both emulation planning and detection validation.

**Existing Platform Coverage:**

| Component | Location | Current Capability |
|---|---|---|
| TTP Knowledge Base | `ttpKnowledge` table | Stores `confidence` (0–100), `iocPatterns` (typed observables with confidence and volatility), `artifacts` (categorized with location and persistence), `detectionRules` (Sigma/YARA/Suricata with false positive rates), `eventLogSources` (source + event ID + description) per technique |
| TTP Engine | `server/lib/ttp-engine.ts` | `researchTechnique()` and `enrichTechnique()` use LLM to populate evidence fields; `generateDetectionRules()` creates detection rules per technique in multiple formats |
| Attack Coverage Router | `server/routers/attack-coverage.ts` | Provides ATT&CK heatmap visualization, technique detail queries, and coverage gap analysis across the matrix |
| KSI Evidence Chains | `ksiEvidenceChains` table | Stores evidence chains linking findings to compliance controls with confidence scoring and evidence type classification |

The `ttpKnowledge` table already contains most of the fields the document describes. Each technique has typed IOC patterns with confidence and volatility scoring, categorized artifacts with persistence indicators, detection rules in multiple formats with false positive rates, and event log source mappings. The TTP Engine's enrichment pipeline uses the LLM to populate these fields from multiple intelligence sources.

**Gap Analysis — Two Structured Fields Missing:**

The first gap is **Environmental Constraints**. The table lacks a structured field for expressing "this technique requires Windows Active Directory with LDAP enabled" or "requires cloud IAM with federated identity." Currently this information is scattered across the free-text `description` and `executionMethods` fields, making it impossible to programmatically evaluate whether a technique is applicable to a given target environment.

The second gap is **Expected Telemetry Signals**. While `eventLogSources` captures which log sources are relevant and `detectionRules` captures detection logic, there is no structured mapping of "if this technique executes successfully, these specific telemetry events should fire with these field values." This structured mapping is essential for the Telemetry Validation Engine (Module 4) to classify outcomes as Prevented, Detected, Missed, or Telemetry Gap.

**Integration Recommendation:**

Add two new JSON columns to the `ttpKnowledge` table. The `environmentalConstraints` column should be structured as `{ os: string[], domainRequired: boolean, cloudProvider?: string, requiredServices: string[], securityTooling: string[], networkAccess: string[] }`. The `expectedTelemetry` column should be structured as `{ logSource: string, eventId: string, field: string, expectedValue: string, telemetryType: "prevention" | "detection" | "visibility", description: string }[]`. Extend the `enrichTechnique()` function in `ttp-engine.ts` to populate these fields during LLM enrichment passes. This is a low-effort change that creates high-value downstream data for Modules 3 and 4.

---

### 2.3 Module 3: Ability Graph Builder (DAG Model)

The document calls for converting ATT&CK techniques into modular abilities with Preconditions, Inputs, Action, Exit Criteria, Validation Signals, and Safety Constraints, organized as a Directed Acyclic Graph with typed edges supporting dependency, conditional, fallback, and parallel relationships.

**Existing Platform Coverage:**

| Component | Location | Current Capability |
|---|---|---|
| AI Attack Planner | `server/lib/ai-attack-planner.ts` | Hybrid graph + LLM planning with `TechniqueNode` graph, topological ordering, `prerequisites` per step, detection risk scoring — **closest existing analog to a DAG** |
| Chain Builder | `server/lib/chain-builder.ts` | Maps 60+ MITRE techniques to Caldera tactics, builds operation chains with ordered abilities, uses LLM to select optimal abilities based on target context |
| Campaign Abilities | `campaignAbilities` table | Stores abilities with `technique`, `tactic`, `executionOrder`, `status`, `calderaAbilityId` — but as a flat ordered list, not a graph |
| Campaign Archetypes | `campaignArchetypes` table | Stores `prerequisites`, `killChainPhases`, `defaultAbilities` with step ordering, `complexity` rating |
| Emulation Playbooks | `emulationPlaybooks` table | Stores `phases` with ordered abilities, Caldera adversary mapping, execution status |
| Caldera Sync | `server/lib/caldera-sync.ts` | Syncs 495+ adversaries with 1,940+ abilities from the Caldera C2 server, maintaining ability metadata including `executors`, `requirements`, and `platforms` |

**Gap Analysis — This Is the Largest Gap:**

The `ai-attack-planner.ts` has a technique-level graph with prerequisites and topological ordering, which is the closest existing structure to the proposed DAG. However, it operates at the technique level (abstract planning) rather than the ability level (executable actions). The current system lacks five critical capabilities.

First, there is no **formal DAG data structure** with typed edges. The current graph uses implicit ordering via topological sort, but edges are not typed (dependency vs. conditional vs. fallback). Second, there is no **structured Precondition/Exit Criteria schema**. The `prerequisites` field on `AttackStep` is a string array containing natural language descriptions, not machine-evaluable conditions. Third, there is no **Validation Signal linkage** between ability execution and expected telemetry outcomes. Fourth, there is no **per-ability safety tier assignment**. The SSIL scan policy engine gates scanners at the tool level, but there is no mechanism to assign safety constraints to individual emulation abilities. Fifth, there is no **conditional branching logic**. The current chain is strictly linear — "if credential dump succeeds, proceed to lateral movement; if blocked, try kerberoasting" cannot be expressed.

**Integration Recommendation — Net-New Module:**

Build a new `server/lib/ability-graph-engine.ts` module with the following architecture:

The **Ability Node schema** should include `id`, `techniqueId`, `name`, `action` (high-level description), `preconditions` (typed array with `{ field, operator, value, description }`), `inputs` (typed array with `{ name, type, source, required }`), `exitCriteria` (typed array with `{ field, operator, value, outcomeOnFail }`), `validationSignals` (linked to `expectedTelemetry` from Module 2), `safetyTier` (1, 2, or 3 mapping to SSIL profiles), `safetyConstraints` (string array), `calderaAbilityId` (optional link to Caldera), `estimatedDwellTime` (milliseconds), and `jitterRange` (min/max tuple).

The **DAG Edge schema** should include `from`, `to`, `type` (one of "dependency", "conditional", "fallback", "parallel"), and an optional `condition` expression (e.g., `exit_criteria.credential_obtained === true`).

The module should provide graph operations including `buildGraphFromTemplate()` (converts an `attackSequenceTemplate` into a DAG), `topologicalSort()`, `findCriticalPath()`, `evaluatePreconditions()` (checks whether a node's preconditions are met given current execution state), and `getNextExecutableNodes()` (returns all nodes whose dependencies are satisfied).

Integration points with existing systems include reading technique data from `ttpKnowledge` to auto-populate preconditions and validation signals, reading Caldera abilities from `caldera-sync.ts` to map graph nodes to executable abilities, reading safety policy from `scan-policy-engine.ts` to enforce tier gating, and writing execution results to `playbookExecutions` for tracking.

Two new database tables are required: `ability_graph_nodes` and `ability_graph_edges`, linked to `emulationPlaybooks` or `attackSequenceTemplates` as the parent container.

---

### 2.4 Module 4: Telemetry Validation Engine

The document calls for attaching expected log sources and detection logic to each ability, scoring execution outcomes as Prevented, Detected, Missed, or Telemetry Gap, and integrating results into the hybrid CARVER+SHOCK × CVSS × BIA scoring framework.

**Existing Platform Coverage:**

| Component | Location | Current Capability |
|---|---|---|
| Validation Engine | `server/lib/validation-engine.ts` | Validates findings with modes `check_only`, `auxiliary_scan`, `safe_exploit`; produces `ValidationResult` with status, evidence, and confidence scoring |
| Scoring Engine | `server/lib/scoring-engine.ts` | Full CARVER+SHOCK scoring with `CarverScores`, `ShockScores`, `CvssV4Metrics`; produces composite `ScoringResult` |
| BIA Report Generator | `server/lib/bia-report-generator.ts` | Generates NIST IR 8286D Business Impact Analysis reports with mission function mapping |
| SSIL Hybrid Scoring | `docs/ssil/scoring/hybrid-scoring.yaml` | Defines `final_score = (cvss * 0.4 + carver * 0.4 + bia * 0.2) * confidence` formula with per-signal-type CARVER component mappings |
| SSIL Risk Cards | `server/lib/observation-normalizer.ts` | Generates risk cards with CVSS, CARVER, and BIA component scores from normalized observations |
| TTP Knowledge | `ttpKnowledge` table | Stores `detectionRules` (Sigma/YARA/Suricata) and `eventLogSources` per technique |
| Alert Rules Engine | `server/lib/alert-rules-engine.ts` | Evaluates threshold-based alerting rules against observations and triggers owner notifications |

The scoring infrastructure is mature. The CARVER+SHOCK scoring engine, CVSS v4 metrics, BIA report generator, and hybrid scoring formula are all production-ready. The validation engine already supports three validation modes with evidence collection. The gap is specifically the **telemetry outcome classification** layer.

**Gap Analysis — Outcome Classification and Scoring Integration:**

The platform can validate whether a vulnerability exists (validation engine) and score its risk (scoring engine), but it cannot classify the outcome of an emulation ability execution against the detection stack. The four-outcome model proposed in the document — Prevented, Detected, Missed, Telemetry Gap — requires a new classification function that compares expected telemetry signals (from Module 2's `expectedTelemetry` field) against actual telemetry received during or after ability execution.

| Outcome | Definition | Scoring Impact |
|---|---|---|
| **Prevented** | Security control blocked the technique before execution completed | Decreases risk score — control is effective |
| **Detected** | Technique executed successfully but generated an alert in the detection stack | Moderate risk — detection works but prevention failed |
| **Missed** | Technique executed with no alert generated despite expected telemetry being available | Increases risk score — detection gap |
| **Telemetry Gap** | Expected log source is not configured or not forwarding events | Highest risk increase — blind spot in visibility |

**Integration Recommendation:**

Extend the existing `validation-engine.ts` with a new `TelemetryOutcome` type and `scoreTelemetryOutcome()` function that takes ability execution results plus expected telemetry signals and classifies the outcome. Add a `telemetry_validation_results` table that stores per-ability outcomes linked to playbook executions, including the expected signal, actual signal (if any), outcome classification, and timestamp.

Wire telemetry outcomes into the SSIL risk card generation. A "Missed" outcome on a critical technique should increase the risk card's CARVER vulnerability component, while "Prevented" should decrease it. A "Telemetry Gap" should increase the CARVER accessibility component (the attacker can operate undetected). This feeds directly into the existing `generateRiskCards()` function in `observation-normalizer.ts` and the hybrid scoring formula.

Build a **Telemetry Coverage Dashboard** showing per-technique detection coverage across the ATT&CK matrix, colored by outcome: green for Prevented, yellow for Detected, red for Missed, and gray for Telemetry Gap. This reuses the existing `attack-coverage.ts` router's heatmap infrastructure with a new data source.

---

### 2.5 Module 5: Adaptive Orchestration Controller

The document calls for conditional branching, retry logic, dwell-time modeling, jitter, and operator behavior profiles derived from DFIR analysis to create realistic adversary emulation that mirrors real-world attacker behavior.

**Existing Platform Coverage:**

| Component | Location | Current Capability |
|---|---|---|
| Evasion Orchestrator | `server/lib/evasion-orchestrator.ts` | Progressive evasion escalation with retry logic, block signal detection (HTTP 403/429/503, WAF pages, CAPTCHA, EDR quarantine, AMSI blocks), and escalation ladder across scanning, C2, and exploit domains |
| C2 Traffic Profiles | `server/lib/c2-traffic-profiles.ts` | Traffic pattern modeling for C2 communications with protocol rotation |
| SIEM Mutation Engine | `server/lib/siem-mutation-engine.ts` | Generates payload mutations for evasion testing |
| Payload Transform Pipeline | `server/lib/payload-transform-pipeline.ts` | Builds evasion transform pipelines with technique chaining |
| Attack Sequence Templates | `attackSequenceTemplates` table | Stores `avgDwellTime` and `evasionTechniques` per template derived from DFIR analysis |
| Chain Builder | `server/lib/chain-builder.ts` | Builds Caldera operation chains with ordered abilities |

The evasion orchestrator already implements sophisticated retry logic and escalation. When an attempt is blocked, it automatically steps through increasingly aggressive evasion techniques until bypass succeeds, then records findings. The three-domain model (scanning, C2, exploit) provides comprehensive coverage.

**Gap Analysis — Four Missing Capabilities:**

The gaps are conditional branching based on ability outcomes (handled by Module 3's DAG), dwell-time modeling with DFIR-derived timing profiles, jitter randomization to simulate human operator behavior, and operator behavior profiles that capture different actors' operational tempos (APT29's patient multi-month campaigns vs. FIN7's rapid smash-and-grab operations).

**Integration Recommendation:**

This module is naturally served by the Ability Graph Builder (Module 3). The DAG model's conditional edges handle branching, and the `AbilityNode.estimatedDwellTime` and `jitterRange` fields handle timing. Build an **`AdaptiveOrchestrationController`** class in `server/lib/adaptive-orchestration.ts` that walks the DAG, evaluating preconditions at each node, applying dwell-time delays with jitter between nodes, following conditional and fallback edges based on exit criteria evaluation, logging execution telemetry for the Telemetry Validation Engine, and enforcing safety tier gating via the SSIL Scan Policy Engine.

Add an **Operator Behavior Profiles** table that stores per-actor timing profiles extracted from DFIR analysis: `{ actorId, avgDwellTimeMs, jitterPercent, workingHoursUTC, preferredTools, operationalTempo: "patient" | "moderate" | "rapid", sessionDurationMs, reconToExploitRatio }`. When an emulation plan is linked to a specific threat actor, the orchestration controller loads the actor's behavior profile and applies it to the DAG walk.

---

## 3. Emulation Safety Tiers — Mapping to Existing SSIL

The document defines three safety tiers that map directly to the existing SSIL Scan Policy Engine profiles:

| Document Tier | SSIL Profile | Allowed Behavior | Current Status |
|---|---|---|---|
| Tier 1: Safe Simulation | `strict_passive` | Metadata-only reasoning, no active probing, configuration checks only, DNS/WHOIS/certificate transparency queries | Fully implemented in `scan-policy-engine.ts` with SP-01 through SP-05 controls |
| Tier 2: Controlled Emulation | `balanced` | Active-low and active-standard scanning, rate-limited (max 50 req/s), approved scanners only, no exploit execution | Fully implemented with rate limiting and scanner allowlists |
| Tier 3: Full Scope | `aggressive_internal` | All scan modes including active-aggressive, exploit validation, payload delivery, requires explicit engagement authorization | Implemented but lacks authorization gate |

The integration recommendation is to extend the `ScanPolicyEngine.canExecute()` method to accept an `emulationTier` parameter that maps to the corresponding profile. Add a `requiresAuthorization` flag for Tier 3 that checks engagement authorization status before allowing execution. This is a low-effort change since the profile infrastructure and enforcement logic already exist.

---

## 4. Enrichment of Other Platform Features

The proposed modules create data flows that enrich several existing platform features beyond the emulation pipeline itself.

**Threat Actor Profiles.** DFIR-extracted actor behavior — dwell time, tool preferences, operational tempo, working hours — enriches the `threatActors` table with behavioral profiles. These profiles improve campaign archetype recommendations by matching actor behavior patterns to archetype templates. When a user selects APT29 for an emulation, the system can auto-populate realistic timing, tool selection, and operational patterns derived from actual DFIR analysis of APT29 incidents.

**OSINT Correlation.** DFIR-derived IOCs and observables, once wired into the SSIL observation normalizer via the `adaptDfirResults()` adapter, enable cross-correlation between DFIR intelligence and live scan findings. When a subfinder enumeration discovers a subdomain that matches a DFIR-extracted C2 domain, or when an httpx probe detects a technology stack that matches a known threat actor's target preferences, the alerting rules engine triggers a notification. This closes the loop between historical threat intelligence and real-time reconnaissance.

**Risk Scoring.** Telemetry validation outcomes (Prevented, Detected, Missed, Telemetry Gap) feed empirical evidence into the hybrid CARVER+CVSS+BIA scoring framework. Currently, risk cards are generated from theoretical vulnerability data. With telemetry validation, risk scores reflect actual defensive posture — a critical vulnerability that is reliably prevented by existing controls receives a lower operational risk score than one that consistently goes undetected.

**Detection Engineering.** Telemetry validation results identify detection gaps that feed into the `defensiveGaps` field in `ttpKnowledge`, creating a feedback loop between emulation and detection improvement. When a technique consistently produces "Missed" outcomes, the system can auto-generate detection rule recommendations using the existing `generateDetectionRules()` function in `ttp-engine.ts`.

**Campaign Design.** The Ability Graph Engine's DAG structure improves the campaign archetype system by replacing flat ability lists with graph-based execution plans that support conditional logic. Campaign archetypes can express "if initial phishing succeeds, proceed to macro execution; if blocked by email gateway, fall back to watering hole" — something the current linear `defaultAbilities` array cannot represent.

---

## 5. Recommended Build Phases

The following phased approach maximizes reuse of existing infrastructure while delivering incremental value at each stage.

| Phase | Module | Primary Work | Effort Estimate | Dependencies |
|---|---|---|---|---|
| 1 | Extend DFIR-to-TTP Extraction | Add `environmentalAssumptions` to extraction pipeline; build `adaptDfirResults()` SSIL adapter | Low (2–3 days) | Existing `attack-sequence-learner.ts` |
| 2 | Extend Evidence-Anchored ATT&CK Mapper | Add `environmentalConstraints` and `expectedTelemetry` columns to `ttpKnowledge`; extend `enrichTechnique()` | Low (2–3 days) | Existing `ttp-engine.ts` |
| 3 | Build Ability Graph Engine | New DAG model, `ability_graph_nodes` and `ability_graph_edges` tables, graph operations, LLM-assisted ability decomposition | High (7–10 days) | Phases 1 and 2 for input data |
| 4 | Build Telemetry Validation Engine | Outcome scoring function, `telemetry_validation_results` table, integration with hybrid scoring | Medium (4–5 days) | Phase 3 for ability execution data |
| 5 | Build Adaptive Orchestration Controller | DAG walker, dwell-time modeling, jitter, operator behavior profiles table | Medium (4–5 days) | Phase 3 for DAG structure |
| 6 | Safety Tier Integration | Extend `ScanPolicyEngine` with `emulationTier` parameter, add authorization gate for Tier 3 | Low (1–2 days) | Phase 5 for enforcement points |
| 7 | UI: Ability Graph Visualizer, Telemetry Coverage Matrix, Orchestration Monitor | Three new dashboard pages with interactive graph visualization, ATT&CK heatmap overlay, and real-time execution monitor | Medium (5–7 days) | All backend modules |

**Total estimated effort: 25–35 days of focused development.**

---

## 6. SSIL Directory Structure Additions

The document recommends organizing SSIL artifacts into `/schema`, `/policies`, `/scoring`, and `/llm` directories. The existing SSIL structure already follows this pattern. The following additions are recommended:

```
docs/ssil/
├── schema/
│   ├── scan_observation.schema.json      ← existing
│   ├── signal.schema.json                ← existing
│   ├── risk_card.schema.json             ← existing
│   ├── ability_node.schema.json          ← NEW: Ability Graph node schema
│   ├── ability_edge.schema.json          ← NEW: DAG edge schema
│   └── telemetry_outcome.schema.json     ← NEW: Validation outcome schema
├── policies/
│   ├── scan-modes.yaml                   ← existing
│   ├── escalation-rules.yaml             ← existing
│   ├── strict-passive-profile.yaml       ← existing
│   └── emulation-safety-tiers.yaml       ← NEW: Tier 1/2/3 definitions
├── scoring/
│   ├── hybrid-scoring.yaml               ← existing
│   └── telemetry-outcome-scoring.yaml    ← NEW: Outcome → score impact weights
└── llm/
    └── prompts/
        ├── system.md                     ← existing
        ├── analyst.md                    ← existing
        ├── dfir_extraction.md            ← NEW: Environmental assumptions extraction
        ├── ability_decomposition.md      ← NEW: Technique → ability graph decomposition
        └── telemetry_mapping.md          ← NEW: Expected telemetry signal generation
```

---

## 7. Summary

The Caldera Admin Dashboard is well-positioned for this integration. The DFIR-to-TTP extraction pipeline, ATT&CK knowledge base, hybrid scoring engine, evasion orchestrator, and SSIL policy framework provide a strong foundation that covers the majority of the proposed functionality. The primary net-new construction is the **Ability Graph Engine** — a DAG model with typed edges, structured preconditions, exit criteria, and conditional branching — and the **Telemetry Validation outcome scoring layer** that classifies emulation results against the detection stack. Everything else extends existing modules with additional structured fields and wiring.

The integration also creates valuable feedback loops: DFIR intelligence enriches live scanning via the observation normalizer, telemetry validation outcomes improve risk scoring with empirical evidence, and detection gaps identified during emulation feed back into the TTP knowledge base for detection rule generation. These loops transform the platform from a collection of independent tools into a closed-loop threat emulation and validation system.
