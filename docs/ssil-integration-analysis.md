# SSIL Bundle Integration Analysis for Ace C3

**Author:** Harrison Cook (AceofCloud)  
**Date:** February 26, 2026  
**Bundle Analyzed:** `ssil_manus_bundle.zip` — Service Scanner Integration Layer v1 (dated 2026-02-25)

---

## Executive Summary

The SSIL (Service Scanner Integration Layer) bundle is a well-architected specification for **policy-governed, normalized scan orchestration** with LLM-assisted risk reasoning. It was **not previously analyzed** for integration into the Ace C3 platform. After reading all 21 files in the bundle and mapping them against the platform's existing 188-table codebase, the conclusion is clear: **SSIL fills three critical gaps that Ace C3 currently lacks** — scan governance policies, observation normalization, and hybrid risk scoring — while the platform already has the scanner infrastructure, LLM integration, and database backbone to absorb SSIL rapidly.

This document provides a file-by-file analysis, a feature-gap matrix, and a prioritized integration roadmap.

---

## 1. What the SSIL Bundle Contains

The bundle is organized into six functional layers, each with a distinct purpose in the scan-to-risk pipeline.

| Layer | Files | Purpose |
|-------|-------|---------|
| **Policies** | `scan-modes.yaml`, `escalation-rules.yaml`, `strict-passive-profile.yaml` | Govern what scanners can do, when they can escalate from passive to active, and what controls enforce strict passive mode |
| **Schemas** | `scan_observation.schema.json`, `signal.schema.json`, `risk_card.schema.json` | JSON Schema definitions for normalized scan outputs, derived intelligence signals, and explainable risk cards |
| **Adapters** | `adapter-contract.yaml`, `nuclei-adapter.yaml`, `zgrab2-adapter.yaml` | Interface contracts that define how scanner tools emit normalized observations |
| **Scoring** | `hybrid-scoring.yaml` | Weights and formulas for fusing CVSS (0.40), CARVER+SHOCK (0.40), and BIA (0.20) into a single 0-10 risk score |
| **LLM Prompts** | `system.md`, `analyst.md`, `risk_card.md`, `caldera_hooks.md`, `guardrails.md` | A curated prompt pack for LLM reasoning over normalized scan data — with explicit guardrails against exploit generation |
| **Examples** | `assets.yaml`, `scan_observations.json`, `signals.json` | Sample data showing the full pipeline from asset intake through observation to signal derivation |

The key design principle is stated in the README:

> Raw scanner output is not stored; only normalized observations and signals are stored. This helps with determinism, explainability, and license hygiene.

This is a significant architectural decision that aligns with FIPS 140-3 evidence handling (store hashes, not raw payloads) and addresses the license concerns around redistributing output from GPL-licensed scanners like Nmap.

---

## 2. Feature-Gap Matrix: SSIL vs. Ace C3

The following table maps each SSIL capability against what already exists in the Ace C3 platform, identifies the gap, and rates the integration effort.

| SSIL Capability | Ace C3 Current State | Gap | Effort |
|----------------|---------------------|-----|--------|
| **Scan Mode Profiles** (strict_passive, balanced, aggressive_internal) | Web app scanning has `passive`/`active` enum; nuclei scanner has `rateLimit` param; no unified policy engine | **No centralized scan governance** — each scanner has its own ad-hoc mode handling | Medium |
| **Escalation Rules** (passive → active gating based on signal confidence) | No automatic escalation; operators manually choose scan mode per scan | **No automated escalation logic** — operators must manually decide when to escalate | Medium |
| **Strict Passive Profile** (SP-01 through SP-05 controls) | No formal passive mode compliance profile; no HTTP method blocking, no header redaction | **No compliance-auditable passive mode** — critical for FedRAMP/CMMC environments | Medium |
| **Scan Observation Schema** (normalized output format) | Each scanner stores findings in its own table format (`vulnScanFindings`, `webAppFindings`, `protocolFindings`, `configScanResults`) | **No unified observation format** — 6+ different finding schemas with no cross-scanner normalization | High |
| **Signal Schema** (derived intelligence from observations) | Risk trending captures snapshots; accuracy engine has corroboration; no formal signal abstraction | **No signal layer** — observations go directly to findings without an intermediate intelligence derivation step | High |
| **Risk Card Schema** (explainable composite risk) | `riskScore` field exists on several tables; risk trending page shows trends; no CARVER/BIA fusion | **No hybrid risk scoring** — current scores are single-dimensional (CVSS or ad-hoc), not multi-factor | High |
| **Hybrid Scoring** (CVSS × CARVER+SHOCK × BIA with confidence weighting) | `cvssScore` and `riskScore` fields exist; no CARVER mapping, no BIA scoring | **No CARVER+SHOCK or BIA integration** — the scoring/hybrid-scoring.yaml is entirely new capability | Medium |
| **Adapter Contract** (standardized scanner plugin interface) | Nuclei scanner, ZAP scanner, and vuln scanner parsers exist but each has a bespoke integration | **No plugin contract** — adding a new scanner requires writing a full router + parser from scratch | Medium |
| **Nuclei Adapter** (curated template tags, allowlist/blocklist) | `nuclei-scanner.ts` (193 lines) has template execution but no tag allowlist/blocklist governance | **No template governance** — operators can run any nuclei template without policy restrictions | Low |
| **zgrab2 Adapter** | No zgrab2 integration exists | **Complete gap** — zgrab2 for banner/TLS/protocol metadata collection is not available | Medium |
| **LLM Analyst Prompt** (structured findings/risks/next-steps output) | `invokeLLM` used in 5 routers (attack planner, detection rules, exploit arsenal, phishing ops, report generation) | **Partially covered** — LLM is used for specific tasks but not for general scan analysis reasoning | Low |
| **LLM Risk Card Prompt** (generate explainable risk cards from signals) | No risk card generation | **Complete gap** — no LLM-generated explainable risk cards | Low |
| **LLM Caldera Hooks** (safe emulation objectives from signals) | AI attack planner exists but generates from manual input, not from scan signals | **Partial gap** — the bridge from scan signals to CALDERA planning hooks does not exist | Low |
| **LLM Guardrails** (no exploit payloads, defensive focus) | No formal LLM guardrails in the platform | **Complete gap** — LLM calls have no safety guardrails preventing exploit generation | Low |
| **Evidence Fingerprinting** (store hashes, not raw payloads) | FIPS crypto service exists; evidence chain of custody table exists; but raw findings are stored as text | **Partial gap** — the infrastructure exists but findings store raw evidence text, not fingerprints | Medium |

---

## 3. Integration Opportunities — Prioritized

### Tier 1: High-Value, Moderate Effort (Implement First)

**3.1 Unified Scan Governance Engine**

The platform currently has 5+ scanners (nuclei, ZAP, web app scanner, vuln scanner, domain intel), each with its own mode handling. SSIL's `scan-modes.yaml` and `escalation-rules.yaml` provide a centralized policy engine that would:

- Replace per-scanner mode enums with a single `ScanPolicy` that all scanners consult before executing
- Add automatic passive → active escalation when signal confidence exceeds thresholds (e.g., `esc-001`: admin surface discovered at confidence ≥ 0.85 triggers nuclei safe templates)
- Enforce strict passive mode for FedRAMP/CMMC engagements with auditable controls (SP-01 through SP-05)

**Implementation approach:** Create a `server/lib/ssil/scan-policy-engine.ts` service that loads the YAML policies, exposes a `canExecute(scanner, mode, asset)` function, and is called by every scanner router before execution. Store the active policy profile per engagement in the `engagements` table.

**3.2 Observation Normalization Layer**

This is the highest-impact integration. Currently, scan results are scattered across 6+ tables with incompatible schemas:

- `vulnScanFindings` — Nessus/Qualys imports
- `webAppFindings` — ZAP/web app scan results
- `protocolFindings` — protocol-level findings
- `configScanResults` — configuration audit results
- `discoveredAssets` — domain intel discoveries
- `osintFindings` — OSINT reconnaissance results

SSIL's `scan_observation.schema.json` provides a single normalized format that captures asset, scanner, observation type, severity, confidence, evidence (with fingerprints), and metadata. Implementing this would:

- Create a single `scan_observations` table matching the SSIL schema
- Add adapter functions in each existing scanner router that transform native findings into normalized observations
- Enable cross-scanner correlation (e.g., "this nuclei finding and this ZAP finding both affect the same asset")
- Support the signal derivation layer that feeds into risk scoring

**Implementation approach:** Create a `server/lib/ssil/observation-normalizer.ts` with per-scanner adapter functions. Add a `scan_observations` table. Each scanner router calls the normalizer after generating findings, storing both the native finding (for backward compatibility) and the normalized observation.

**3.3 Hybrid Risk Scoring (CARVER+SHOCK × CVSS × BIA)**

The platform currently has single-dimensional risk scores (`riskScore` as a number, `cvssScore` from vulnerability imports). SSIL's hybrid scoring model fuses three dimensions:

- **CVSS (40%)** — technical severity from vulnerability scanners
- **CARVER+SHOCK (40%)** — operational impact assessment (criticality, accessibility, recoverability, vulnerability, effect, shock value)
- **BIA (20%)** — business impact analysis (mission criticality of the affected asset)

The scoring formula `final_score = (cvss × 0.40 + carver × 0.40 + bia × 0.20) × confidence` produces a 0-10 score that is explainable — each component is visible in the risk card.

**Implementation approach:** Create a `server/lib/ssil/hybrid-risk-scorer.ts` that implements the formula from `hybrid-scoring.yaml`, with the CARVER mapping table for common signal categories (auth_surface, tls_hygiene, dns_takeover). Add a `risk_cards` table matching `risk_card.schema.json`. Wire the scorer into the signal derivation pipeline so risk cards are generated automatically.

### Tier 2: Medium-Value, Low Effort (Quick Wins)

**3.4 LLM Guardrails and Prompt Pack**

The platform already uses `invokeLLM` in 5+ routers but has no safety guardrails. SSIL's `guardrails.md` provides explicit rules:

- Never produce exploit payloads, attack strings, or instructions to compromise systems
- Focus on remediation, validation, monitoring, configuration hardening
- Do not store or repeat sensitive data (tokens, cookies, credentials)
- Use hashes/fingerprints if referencing evidence

**Implementation approach:** Create a `server/lib/ssil/llm-guardrails.ts` that wraps `invokeLLM` with the guardrails system prompt prepended. Replace direct `invokeLLM` calls in scanner-related routers with the guarded version. Store the SSIL prompt pack (`analyst.md`, `risk_card.md`, `caldera_hooks.md`) as configurable templates.

**3.5 Caldera Planning Hooks from Scan Signals**

The platform has an AI attack planner that generates CALDERA operations from manual input. SSIL's `caldera_hooks.md` prompt generates safe, high-level CALDERA planning hooks directly from scan signals — bridging the gap between reconnaissance and adversary emulation.

**Implementation approach:** Add a `generateCalderaHooks` procedure to the agent manager router that takes signal IDs as input, loads the corresponding signals, passes them through the `caldera_hooks.md` prompt via `invokeLLM`, and returns suggested objectives and abilities. This creates an automated recon → emulation pipeline.

**3.6 Nuclei Template Governance**

The existing `nuclei-scanner.ts` (193 lines) executes nuclei templates but has no tag allowlist/blocklist. SSIL's `nuclei-adapter.yaml` defines:

- Default allow tags: `misconfig`, `headers`, `tls`, `exposures`
- Default block tags: `rce`, `ssrf`, `sqli`, `cmdi`, `deserialization`, `bruteforce`

**Implementation approach:** Add allowlist/blocklist fields to the nuclei scan input schema. Validate template tags against the active scan policy profile before execution. This is a 30-line change to the existing router.

### Tier 3: Strategic, Higher Effort (Future Roadmap)

**3.7 Signal Derivation Engine**

The signal layer sits between raw observations and risk cards. It transforms observations into intelligence signals with categories (vulnerability, exposure, weak_signal, intel, hygiene, misconfiguration), confidence scores, and rationale. This enables:

- Automated triage: signals above confidence 0.85 trigger escalation rules
- Cross-observation correlation: multiple observations can produce a single signal
- LLM-assisted reasoning: the analyst prompt generates findings summaries from signal sets

**Implementation approach:** Create a `server/lib/ssil/signal-engine.ts` with rule-based signal derivation (observation type → signal category mapping) plus optional LLM enrichment for complex cases. Add a `signals` table. Wire the engine to run after each scan completes.

**3.8 Scanner Adapter Plugin System**

Currently, adding a new scanner requires writing a full router, parser, and database table. SSIL's adapter contract defines a standardized interface: inputs (asset, policy, mode, allowlist, blocklist) → outputs (normalized observation, metrics). Implementing this would:

- Create a plugin registry where adapters register their capabilities
- Allow new scanners to be added by implementing the adapter contract without touching the core codebase
- Enable the zgrab2 adapter (currently a complete gap) as the first plugin

**Implementation approach:** Create a `server/lib/ssil/adapter-registry.ts` with a `ScannerAdapter` interface matching the SSIL contract. Refactor the nuclei and ZAP integrations as adapters. Add zgrab2 as a new adapter.

---

## 4. Architecture: How SSIL Fits Into Ace C3

The following diagram shows how the SSIL layers integrate into the existing platform architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Ace C3 Platform                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐       │
│  │ Nuclei       │   │ ZAP          │   │ zgrab2 (NEW) │       │
│  │ Scanner      │   │ Scanner      │   │ Adapter      │       │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘       │
│         │                  │                   │                │
│         ▼                  ▼                   ▼                │
│  ┌─────────────────────────────────────────────────────┐       │
│  │          SSIL Scan Policy Engine (NEW)               │       │
│  │  • scan-modes.yaml (passive/balanced/aggressive)     │       │
│  │  • escalation-rules.yaml (auto passive→active)       │       │
│  │  • strict-passive-profile.yaml (FedRAMP controls)    │       │
│  └──────────────────────┬──────────────────────────────┘       │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────┐       │
│  │       SSIL Observation Normalizer (NEW)              │       │
│  │  • scan_observation.schema.json validation           │       │
│  │  • Per-scanner adapter transforms                    │       │
│  │  • Evidence fingerprinting (hashes, not raw)         │       │
│  └──────────────────────┬──────────────────────────────┘       │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────┐       │
│  │          SSIL Signal Engine (NEW)                    │       │
│  │  • Observation → Signal derivation                   │       │
│  │  • Confidence scoring                                │       │
│  │  • Cross-observation correlation                     │       │
│  └──────────────────────┬──────────────────────────────┘       │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────┐       │
│  │       SSIL Hybrid Risk Scorer (NEW)                  │       │
│  │  • CVSS (0.40) × CARVER+SHOCK (0.40) × BIA (0.20)  │       │
│  │  • Confidence-weighted final score                   │       │
│  │  • Explainable risk cards                            │       │
│  └──────────────────────┬──────────────────────────────┘       │
│                         ▼                                       │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐       │
│  │ LLM Analyst  │   │ LLM Risk     │   │ LLM Caldera  │       │
│  │ Reasoning    │   │ Card Gen     │   │ Hooks Gen    │       │
│  │ (guardrails) │   │ (guardrails) │   │ (guardrails) │       │
│  └──────────────┘   └──────────────┘   └──────────────┘       │
│                                                                 │
│  ┌─────────────────────────────────────────────────────┐       │
│  │              Existing Ace C3 Infrastructure           │       │
│  │  • 188 DB tables  • FIPS 140-3 crypto  • mTLS       │       │
│  │  • Multi-C2 agents  • RBAC  • Error boundary         │       │
│  └─────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. FIPS 140-3 Alignment

The SSIL bundle's design principles align well with the platform's existing FIPS 140-3 implementation:

| SSIL Principle | FIPS 140-3 Alignment |
|---------------|---------------------|
| Store only hashes/fingerprints, not raw responses | Matches FIPS evidence handling — store encrypted metadata, not plaintext payloads |
| Redact Authorization, Cookie, Set-Cookie headers | Aligns with FIPS key material protection — never store credentials in scan evidence |
| Confidence-weighted scoring with explainable components | Supports CMMC audit requirements — every risk score can be decomposed into its inputs |
| Policy-governed scan modes with attestation statement | Directly supports FedRAMP continuous monitoring — the strict passive attestation is audit-ready |

The `strict-passive-profile.yaml` attestation statement is particularly valuable:

> When Strict Passive Mode is enabled, the system enforces technical controls that prevent active exploitation, payload injection, and authentication attacks. Evidence retention is limited to metadata and hashes to reduce data sensitivity.

This can be included verbatim in FedRAMP SSP documentation as a technical control description.

---

## 6. Competitive Advantage

Integrating SSIL would give Ace C3 capabilities that no single competing platform currently offers in combination:

- **Pentera** has automated scanning but no policy-governed passive mode or CARVER scoring
- **Cobalt Strike** has adversary emulation but no scan normalization or LLM reasoning
- **Rapid7 InsightVM** has vulnerability management but no CALDERA integration or hybrid risk scoring
- **Tenable.io** has CVSS scoring but no CARVER+SHOCK operational impact fusion

The combination of **FIPS 140-3 crypto + policy-governed scanning + hybrid risk scoring + LLM-assisted analysis + CALDERA emulation hooks** positions Ace C3 as the only platform that covers the full defensive-to-offensive spectrum with compliance built in.

---

## 7. Recommended Implementation Order

| Phase | Deliverable | Estimated Effort | Dependencies |
|-------|------------|-----------------|--------------|
| 1 | Scan Policy Engine + Strict Passive Profile | 2-3 days | None |
| 2 | Observation Normalizer + `scan_observations` table | 3-4 days | Phase 1 |
| 3 | LLM Guardrails + Prompt Pack integration | 1 day | None |
| 4 | Nuclei Template Governance (allowlist/blocklist) | 0.5 day | Phase 1 |
| 5 | Hybrid Risk Scorer + `risk_cards` table | 2-3 days | Phase 2 |
| 6 | Signal Derivation Engine + `signals` table | 3-4 days | Phase 2 |
| 7 | Caldera Planning Hooks from Signals | 1-2 days | Phase 6 |
| 8 | Scanner Adapter Plugin System + zgrab2 | 3-4 days | Phase 2 |

**Total estimated effort:** 16-22 days for full integration, with Phases 1-4 deliverable in the first week as a meaningful milestone.

---

## 8. Files to Preserve

The SSIL bundle should be stored in the project at `docs/ssil/` for reference during implementation. The YAML policies and JSON schemas are the source of truth for the integration — they should be loaded at runtime, not hard-coded.

```
docs/ssil/
├── policies/
│   ├── scan-modes.yaml
│   ├── escalation-rules.yaml
│   └── strict-passive-profile.yaml
├── schema/
│   ├── scan_observation.schema.json
│   ├── signal.schema.json
│   └── risk_card.schema.json
├── scoring/
│   └── hybrid-scoring.yaml
├── adapters/
│   ├── adapter-contract.yaml
│   ├── nuclei-adapter.yaml
│   └── zgrab2-adapter.yaml
└── llm/
    └── prompts/
        ├── system.md
        ├── analyst.md
        ├── risk_card.md
        ├── caldera_hooks.md
        └── guardrails.md
```
