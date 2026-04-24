# AC3 Hybrid Scoring System — Deep Dive

**Document Version:** v1  
**Date:** April 23, 2026  
**Scope:** End-to-end architecture of the CARVER+SHOCK/CVSS/BIA hybrid risk scoring pipeline  
**Audience:** External safety reviewer (Claude)  
**Source Files:** `scoring-engine.ts` (1,650 lines), `auto-industry-carver.ts` (1,210 lines), `hybrid-scorer.ts` (522 lines), `entity-resolver.ts` (576 lines), `scoring-hardening.ts` (530 lines), `temporal-decay.ts` (290 lines)

---

## 1. Executive Summary

The AC3 Hybrid Scoring System is a multi-layered risk quantification engine that fuses three historically separate methodologies — military targeting analysis (CARVER), vulnerability severity scoring (CVSS v4.0), and business impact analysis (BIA) — into a single, explainable risk score for every digital asset in scope.

The system's central thesis is that **no single scoring methodology captures the full risk picture**:

- **CVSS** tells you how severe a vulnerability is in isolation, but says nothing about whether the affected asset matters to the organization's mission.
- **CARVER** tells you how valuable a target is from an adversary's perspective, but was designed for physical military targets and lacks native integration with vulnerability databases.
- **BIA** tells you the financial and operational impact of asset loss, but provides no mechanism for assessing attack likelihood or exploitability.

AC3 bridges these gaps through a 12-layer pipeline that begins with automated sector detection and ends with an `ExplainableRiskCard` — a structured output that provides not just a score, but the complete reasoning chain behind it.

### 1.1 What Makes This Novel

The hybrid scoring system introduces several capabilities that, to our knowledge, do not exist in any commercial or open-source vulnerability management platform:

1. **CARVER Digital Translation Tables** — The first systematic translation of the U.S. Army's CARVER targeting methodology (FM 34-36, 1990) from physical military targets to digital assets, with 1-10 scale criteria for each of six CARVER factors plus the SHOCK extension.

2. **CVSS v4.0 → CARVER Feed-Through** — A bidirectional mapping that translates CVSS v4.0 vector components (AV, AC, AT, PR, UI, VC/VI/VA, SC/SI/SA, E, CR/IR/AR, R, S, AU, V) into CARVER and SHOCK dimension adjustments, applied as floors (never lowering existing scores).

3. **Sector-Aware Scoring with NAICS Auto-Mapping** — Automated detection of organizational sector from domain TLDs, keywords, and asset signals, with NAICS code inference and per-sector CARVER+SHOCK baseline presets that reflect the actual threat landscape for each industry.

4. **LLM Augmentation with Graceful Degradation** — A deterministic scoring baseline that operates without any AI dependency, augmented by an LLM layer that provides bounded delta adjustments (-3 to +3 per dimension) with structured evidence tags. If the LLM is unavailable, the system returns the deterministic baseline with zero deltas — it never fails to produce a score.

5. **"Innocent Until Proven Guilty" Likelihood Model** — Unlike CVSS-only approaches where every vulnerability immediately inflates the risk score, AC3's likelihood computation keeps assets at low risk (≤15%) until confirmed vulnerability evidence arrives. This prevents the "everything is critical" problem that plagues traditional vulnerability management.

6. **Evidence-Quality Weighting** — The fusion formula applies an evidence multiplier (confirmed=1.0, corroborated=0.85, unverified=0.3) that mathematically penalizes scores based on unverified findings, preventing LLM hallucinations or unconfirmed scan results from driving remediation priorities.

7. **Dynamic Re-Scoring Triggers** — Five discovery-phase triggers (KEV match, dark web exposure, threat actor TTP match, attack chain match, bug bounty correlation) that automatically elevate scores when new intelligence arrives, with per-trigger CARVER/SHOCK adjustments and likelihood boosts.

8. **Anti-Gaming Hardening** — A hardened scoring wrapper that sanitizes all inputs, catches NaN/undefined at every computation stage, detects suspicious score distributions, and falls back to pure deterministic scoring if the main pipeline fails.

9. **Temporal Decay** — A five-factor temporal model (exploit maturity, patch negligence, KEV urgency, validation staleness, finding age) that adjusts scores over time with a 0.5x-2.0x multiplier, ensuring that stale findings lose confidence while unpatched known-exploited vulnerabilities escalate.

### 1.2 Pipeline Overview

The complete scoring pipeline processes an asset through 12 layers:

| Layer | Name | Source File | Purpose |
|-------|------|-------------|---------|
| 1 | Sector Detection & NAICS Mapping | `auto-industry-carver.ts` | Detect organizational sector from signals |
| 2 | CARVER+SHOCK Sector Presets | `auto-industry-carver.ts` | Apply per-sector baseline scores |
| 3 | CVSS v4.0 Feed-Through | `scoring-engine.ts` | Map CVSS metrics to CARVER/SHOCK adjustments |
| 4 | FIPS 199 Integration | `scoring-engine.ts` | Map CIA categorization to scoring adjustments |
| 5 | Criticality Tier System | `scoring-engine.ts` | Apply NIST SP 800-34 tier floors |
| 6 | LLM Asset Classification | `scoring-engine.ts` | Batch-classify assets with calibration rules |
| 7 | Core Hybrid Risk Computation | `scoring-engine.ts` | Compute `hybridRiskScore` from impact × likelihood |
| 8 | Fusion Formula | `auto-industry-carver.ts` | Compute `hybridFusionScore` with EPSS/KEV/evidence |
| 9 | LLM Augmentation | `hybrid-scorer.ts` | Apply bounded LLM delta adjustments |
| 10 | BIA Financial Impact | `entity-resolver.ts` | Calculate dollar-value financial exposure |
| 11 | Dynamic Re-Scoring Triggers | `scoring-engine.ts` | Elevate scores on new intelligence |
| 12 | Hardening & Temporal Decay | `scoring-hardening.ts`, `temporal-decay.ts` | Anti-gaming + time-based adjustments |

The final output is an `ExplainableRiskCard` containing the asset's sector, NAICS code, regulatory profile, composite scores, priority tier, top risk drivers, threat likelihood by category, recommended actions, and Caldera operation prioritization.

---

## 2. Layer 1 — Sector Detection & NAICS Mapping

### 2.1 Purpose

Before any scoring can occur, the system must determine what kind of organization owns the target assets. A payment gateway at a bank faces a fundamentally different threat landscape than the same technology stack at a SaaS startup. Sector detection is the foundation that makes all downstream scoring context-aware.

### 2.2 Industry Detection Rules

The `INDUSTRY_DETECTION_RULES` constant in `auto-industry-carver.ts` defines pattern-matching rules for seven sectors:

| Sector | TLD Patterns | Keyword Patterns | Asset Signal Patterns |
|--------|-------------|-----------------|----------------------|
| `banking_financial_services` | `.bank`, financial TLDs | "banking", "payment", "SWIFT", "ACH" | Payment gateways, trading platforms |
| `healthcare_providers` | `.health` | "hospital", "patient", "EHR", "HIPAA" | Medical devices, patient portals |
| `pharmaceuticals_biotech` | — | "pharma", "clinical trial", "FDA", "GxP" | LIMS, CTMS systems |
| `defense_aerospace` | `.mil` | "defense", "classified", "ITAR", "CMMC" | Classified networks, weapons systems |
| `electric_gas_utilities` | — | "SCADA", "grid", "NERC", "OT" | ICS/SCADA, grid operations |
| `federal_government` | `.gov` | "federal", "FISMA", "FedRAMP", "PIV" | PIV infrastructure, mission systems |
| `saas_tech` | `.io`, `.app`, `.dev` | "SaaS", "API", "cloud", "platform" | CI/CD, production APIs |

Each rule produces a confidence score (0-1) based on how many signals matched. The highest-confidence sector wins.

### 2.3 NAICS Auto-Mapping

Once a sector is detected, the system infers the most likely NAICS (North American Industry Classification System) code through a multi-stage process:

1. **TLD evidence** — Domain TLDs like `.bank`, `.gov`, `.mil` provide high-confidence sector signals
2. **Keyword evidence** — Content keywords and asset names are matched against sector-specific vocabularies
3. **Asset signal evidence** — Technology stack signals (e.g., "SCADA", "EHR", "SWIFT") provide strong sector indicators
4. **Candidate ranking** — Multiple NAICS candidates are scored and ranked, with the highest-scoring candidate selected as `primaryNaics`

The output is a `NaicsInferenceResult` with confidence banding:

```typescript
interface NaicsInferenceResult {
  primaryNaics: string;        // e.g., "522110" (Commercial Banking)
  primaryLabel: string;        // e.g., "Commercial Banking"
  candidates: NaicsCandidate[];
  confidence: number;          // 0-1
  confidenceBand: "high" | "medium" | "low" | "insufficient";
  evidence: {
    tlds: string[];
    keywords: string[];
    assetSignals: string[];
    sources: string[];
  };
}
```

### 2.4 Regulatory Framework Inference

Each sector maps to a set of regulatory frameworks that affect scoring:

| Sector | Regulatory Frameworks |
|--------|----------------------|
| Banking/Financial | GLBA, SOX, FFIEC |
| Defense/Aerospace | CMMC, ITAR, DFARS |
| Electric/Gas Utilities | NERC CIP |
| Healthcare | HIPAA, HITECH |
| Federal Government | FISMA, FedRAMP |
| Pharmaceuticals | GxP, FDA |

These frameworks drive the regulatory overlay adjustments applied in Layer 2.

---

## 3. Layer 2 — CARVER+SHOCK Sector Presets

### 3.1 The CARVER Framework

CARVER is a military target analysis methodology developed by the U.S. Army (FM 34-36, *Special Operations Forces Intelligence and Electronic Warfare Operations*, 1990). The acronym stands for:

- **C**riticality — How important is the target to the overall system?
- **A**ccessibility — Can the attacker reach the target?
- **R**ecuperability — How long to replace, repair, or bypass?
- **V**ulnerability — Does the attacker have means to exploit?
- **E**ffect — What are the broader organizational impacts?
- **R**ecognizability — How easily can the target be identified?

AC3 extends CARVER with a seventh dimension — **SHOCK** — adapted from the Department of Homeland Security's consequence assessment methodology. SHOCK captures the broader impact dimensions that CARVER's military focus does not address:

- **S**cope — Blast radius (how many users/systems affected)
- **H**andling — Response complexity (incident response difficulty)
- **O**perational Impact — Business disruption severity
- **C**ascading Effects — Dependency chain propagation
- **K**nowledge — Exploitation expertise required (inverted: higher = easier to exploit)

### 3.2 Per-Sector Baseline Presets

Each sector has a pre-calibrated CARVER+SHOCK baseline that reflects the typical risk profile for organizations in that industry:

| Sector | C | A | R | V | E | Rec | Shock |
|--------|---|---|---|---|---|-----|-------|
| Banking/Financial | 9 | 7 | 5 | 6 | 9 | 8 | 8 |
| Healthcare | 8 | 7 | 6 | 7 | 8 | 7 | 8 |
| Pharma/Biotech | 8 | 5 | 4 | 6 | 8 | 6 | 7 |
| Defense/Aerospace | 9 | 6 | 3 | 6 | 9 | 8 | 9 |
| Electric/Gas Utilities | 10 | 5 | 2 | 5 | 10 | 7 | 9 |
| Federal Government | 9 | 5 | 4 | 5 | 9 | 7 | 8 |
| SaaS/Tech | 7 | 8 | 6 | 7 | 7 | 8 | 7 |

The rationale behind these presets:

- **Electric/Gas Utilities** receive the highest Criticality (10) and Effect (10) because compromise of grid operations can cause physical harm and cascading infrastructure failure. Their low Recuperability (2) reflects the resilience of modern grid systems with redundant controls.
- **Defense/Aerospace** receives the highest Shock (9) because compromise of classified systems has national security implications. Low Recuperability (3) reflects the difficulty of rebuilding classified networks.
- **SaaS/Tech** has the highest Accessibility (8) because cloud-native architectures are inherently internet-facing, but lower Criticality (7) because individual SaaS assets rarely represent single points of failure.

### 3.3 Regulatory Overlays

After the sector baseline is established, regulatory overlays adjust specific dimensions:

```typescript
const REGULATORY_OVERLAYS: Record<string, RegulatoryOverlay> = {
  fedramp:  { shock: 1, effect: 1, criticality: 1 },
  cmmc:     { criticality: 1, shock: 1, recuperability: -1 },
  nerc_cip: { criticality: 2, effect: 2, recuperability: -1 },
  glba:     { criticality: 1, effect: 1 },
  hipaa:    { criticality: 1, vulnerability: 1 },
  fisma:    { criticality: 1, effect: 1, shock: 1 },
  itar:     { criticality: 2, shock: 1, recognizability: 1 },
  dfars:    { criticality: 1, shock: 1 },
  sox:      { effect: 1 },
  ffiec:    { criticality: 1, vulnerability: 1 },
  hitech:   { vulnerability: 1, effect: 1 },
  gxp:      { criticality: 1, recuperability: -1 },
  fda:      { criticality: 1, effect: 1 },
};
```

Overlays are additive. A defense contractor subject to both CMMC and ITAR would receive: Criticality +3, Shock +2, Recuperability -2, Recognizability +1. The negative Recuperability adjustments for CMMC, NERC CIP, and GxP reflect the fact that these regulatory environments mandate redundancy and recovery capabilities, making assets harder to permanently destroy.

### 3.4 Auto-BIA Asset Priority Lists

Each sector also defines a prioritized list of crown jewel assets — the systems that matter most to that specific industry:

| Sector | Crown Jewels (Top 5) |
|--------|---------------------|
| Banking | SWIFT/Wire Transfer, Core Banking Platform, Online Banking Portal, Mobile Banking API, Payment Processing Gateway |
| Healthcare | EHR System, Patient Data Store, Billing Systems, Email |
| Defense | Classified Network, Engineering Systems, Program Data, Email |
| Utilities | OT Control Systems, SCADA, Grid Operations, Corporate IT |
| Federal Gov | Mission Systems, Classified Network, PIV Infrastructure, Email |
| SaaS/Tech | Production API, Customer Data Store, CI/CD Pipeline, Admin Portal |

These lists inform the LLM asset classification layer (Layer 6) and help calibrate which assets should receive elevated criticality scores.

### 3.5 Threat Actor Likelihood by Sector

Each sector has a pre-calibrated threat actor likelihood profile based on industry threat intelligence:

| Threat Category | Banking | Healthcare | Defense | Utilities | SaaS |
|----------------|---------|------------|---------|-----------|------|
| Ransomware/eCrime | 0.85 | 0.90 | 0.45 | — | — |
| Financial Fraud/BEC | 0.90 | — | — | — | — |
| APT/State Espionage | 0.60 | 0.40 | 0.95 | — | — |
| DDoS/Extortion | 0.55 | 0.35 | — | — | — |
| Insider Threat | 0.45 | 0.50 | 0.60 | — | — |
| Credential Stuffing | 0.80 | — | — | — | — |
| API Abuse | 0.75 | — | — | — | — |
| Supply Chain | 0.50 | — | 0.65 | — | — |
| Web App Exploitation | 0.85 | — | — | — | — |
| Account Takeover | 0.90 | — | — | — | — |
| Data Extortion | — | 0.80 | — | — | — |

These probabilities feed into the `ExplainableRiskCard` output and inform the LLM augmentation layer's threat landscape context.

---

## 4. Layer 3 — CVSS v4.0 Feed-Through

### 4.1 Purpose

CVSS (Common Vulnerability Scoring System) v4.0 is the industry standard for rating vulnerability severity. Rather than treating CVSS as a competing score, AC3 feeds CVSS metrics through a translation layer that maps each CVSS component to the most semantically appropriate CARVER or SHOCK dimension.

### 4.2 Vector Parsing

The `parseCvssV4Vector()` function in `scoring-engine.ts` parses CVSS v4.0 vector strings (e.g., `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`) into a structured `CvssV4Parsed` object containing all base, threat, environmental, and supplemental metrics.

### 4.3 CVSS → CARVER/SHOCK Mapping

The `cvssV4ToCarverAdjustments()` function implements the following translation:

| CVSS v4.0 Metric | Maps To | Translation Logic |
|-------------------|---------|-------------------|
| **AV** (Attack Vector) | CARVER: Accessibility | N(etwork)→9, A(djacent)→7, L(ocal)→4, P(hysical)→2 |
| **AC** (Attack Complexity) × **AT** (Attack Requirements) | CARVER: Vulnerability | AC: L→8, H→4; multiplied by AT: N→1.0, P→0.7 |
| **PR** (Privileges Required) + **UI** (User Interaction) | CARVER: Accessibility (modifier) | PR: N→0, L→-1, H→-3; UI: N→0, P→-1, A→-2 |
| **VC/VI/VA** (Vulnerable System Impact) | CARVER: Effect | Max of C/I/A impacts: N→0, L→3, H→8 |
| **SC/SI/SA** (Subsequent System Impact) | SHOCK: Cascading Effects, Scope | Max of subsequent impacts +1; Scope = 0.8× |
| **E** (Exploit Maturity) | CARVER: Vulnerability boost + Recognizability | A(ctive)→+2/Rec=8, P(oC)→+1/Rec=6, U(nproven)→+0 |
| **CR/IR/AR** (Environmental Requirements) | CARVER: Criticality | H→9, M→6, L→3 (max of three) |
| **R** (Recovery) | CARVER: Recuperability | I(rrecoverable)→10, U(ser-assisted)→7, A(utomatic)→3 |
| **S** (Safety) | SHOCK: Operational Impact | P(resent)→9 |
| **AU** (Automatable) | CARVER: Accessibility + Recognizability | Y(es)→+1 to both |
| **V** (Value Density) | SHOCK: Scope | C(oncentrated)→+2 |

All adjustments are applied as **floors** — they can only raise a dimension's score, never lower it. This design ensures that CVSS data enriches the CARVER baseline without contradicting sector-specific intelligence.

### 4.4 Design Decision: Floors, Not Overrides

The floor-based application is a deliberate architectural choice. Consider a healthcare EHR system with a CARVER Criticality baseline of 8 (from the healthcare sector preset). If a CVSS vector's environmental requirements suggest Criticality of 6, the floor mechanism preserves the higher sector-informed value. Conversely, if the CVSS vector indicates Criticality of 9 (e.g., due to high availability requirements), the score is raised.

This asymmetry reflects the principle that **sector context should not be overridden by generic vulnerability metrics**, but vulnerability-specific intelligence should be able to elevate risk when warranted.

---

## 5. Layer 4 — FIPS 199 Integration

### 5.1 Purpose

FIPS 199 (*Standards for Security Categorization of Federal Information and Information Systems*) defines three security objectives — Confidentiality, Integrity, and Availability — each rated as Low, Moderate, or High. While originally designed for federal systems, the CIA triad categorization applies to any organization's asset classification.

### 5.2 Mapping Logic

The `fips199ToCarverAdjustments()` function maps FIPS 199 categories to CARVER/SHOCK adjustments:

```typescript
function fips199ToCarverAdjustments(category: Fips199Category): {
  carverAdjustments: Partial<CarverScores>;
  shockAdjustments: Partial<ShockScores>;
  missionMultiplier: number;
}
```

| FIPS 199 Level | Numeric Value | Mission Multiplier |
|----------------|---------------|-------------------|
| Low | 2 | 0.9× |
| Moderate | 5 | 1.3× |
| High | 9 | 1.8× |

The mapping logic:

- **Criticality** ← Maximum of all three CIA levels (the overall security categorization)
- **Effect** ← Average of Confidentiality and Integrity (data-centric impact)
- **Recuperability** ← Availability level (≥7→8, ≥4→5, else→3)
- **SHOCK Scope** ← Confidentiality level (≥7→8, ≥4→5, else→2)
- **SHOCK Operational Impact** ← Availability level (same thresholds)
- **SHOCK Handling** ← Integrity level (≥7→7, ≥4→5, else→3)
- **Mission Multiplier** ← Based on highest categorization level

The mission multiplier is particularly important: a FIPS 199 High system receives a 1.8× multiplier that amplifies the final mission impact score, ensuring that the most sensitive systems receive proportionally higher risk scores regardless of their individual CARVER dimension values.

---

## 6. Layer 5 — Criticality Tier System

### 6.1 Purpose

The criticality tier system provides a coarse-grained classification aligned with NIST SP 800-34 (*Contingency Planning Guide for Federal Information Systems*) and Business Continuity Planning (BCP) best practices. It establishes minimum CARVER/SHOCK score floors based on an asset's Recovery Time Objective (RTO).

### 6.2 Tier Definitions

| Tier | Name | RTO | Mission Multiplier | Description |
|------|------|-----|-------------------|-------------|
| 1 | Mission Critical | < 1 hour | 2.0× | Immediate operational impact. Loss causes complete mission failure. No acceptable workaround exists. |
| 2 | Business Critical | 1-24 hours | 1.6× | Significant impact within hours. Core business functions degraded. Manual workarounds possible but costly. |
| 3 | Business Important | 1-7 days | 1.3× | Moderate impact within days. Supporting functions affected. Workarounds available. |
| 4 | Administrative | > 7 days | 0.9× | Minimal operational impact. Administrative or convenience functions. Extended outage tolerable. |
| 5 | Non-Essential | N/A | 0.6× | No operational impact. Test environments, deprecated systems, or non-production assets. |

### 6.3 Score Floors

Each tier enforces minimum CARVER and SHOCK scores:

| Tier | CARVER Floors | SHOCK Floors |
|------|--------------|-------------|
| 1 | Criticality=9, Effect=8, Recuperability=9 | OperationalImpact=9, CascadingEffects=8, Scope=8 |
| 2 | Criticality=7, Effect=7, Recuperability=7 | OperationalImpact=7, CascadingEffects=6, Scope=6 |
| 3 | Criticality=5, Effect=5, Recuperability=5 | OperationalImpact=5, CascadingEffects=4, Scope=4 |
| 4 | Criticality=3, Effect=3 | OperationalImpact=3 |
| 5 | Criticality=1, Effect=1 | OperationalImpact=1 |

The `applyCriticalityTierFloors()` function applies these as floors using `Math.max()`, ensuring that a Tier 1 asset can never have a Criticality score below 9, regardless of what other layers computed.

### 6.4 Interaction with Other Layers

The criticality tier system interacts with FIPS 199 through the mission multiplier. Both layers produce mission multipliers, and the system takes the maximum:

```typescript
missionMult = Math.max(missionMult, tierResult.missionMultiplier);
```

This means a Tier 1 asset with FIPS 199 High categorization receives a 2.0× multiplier (from the tier), not a 1.8× (from FIPS 199), because the tier's assessment is more severe.

---

## 7. Layer 6 — LLM Asset Classification

### 7.1 Purpose

Layers 1-5 operate on structured data (sector detection rules, CVSS vectors, FIPS categories, tier assignments). Layer 6 introduces LLM-based reasoning to classify assets that cannot be adequately categorized by pattern matching alone.

### 7.2 Classification Taxonomy

The LLM classifies each asset across multiple dimensions:

| Dimension | Values | Purpose |
|-----------|--------|---------|
| `deviceType` | server, workstation, network_appliance, iot_device, database_server, identity_provider, mail_server, dns_server, cdn_node, api_gateway, payment_processor, ci_cd_server, ... | Physical/logical device category |
| `platformType` | web_application, data_store, authentication, email, infrastructure, content_delivery, api_service, financial_service, development_tools, network_security, ... | Platform/service category |
| `missionFunction` | command_control, revenue_generation, customer_data, intellectual_property, operational_continuity, compliance, external_communication, authentication, data_processing, supply_chain | Business mission alignment |
| `businessImpactLevel` | mission_critical, business_essential, operational, administrative | Impact tier |
| `fips199Category` | {confidentiality, integrity, availability}: low/moderate/high | Security categorization |
| `criticalityTier` | 1-5 | RTO-based tier |
| `missionDependencies` | upstreamAssets, downstreamAssets, sharedServices | Dependency graph |
| `carverAdjustments` | Per-dimension 0-10 scores | LLM-inferred CARVER scores |
| `shockAdjustments` | Per-dimension 0-10 scores | LLM-inferred SHOCK scores |

### 7.3 Calibration Rules

The LLM prompt includes explicit calibration rules to prevent over-classification:

> - Only 5-10% of assets should be `mission_critical` / Tier 1
> - Consider the organization's sector when assessing impact
> - CDNs, static sites, and marketing pages are almost always administrative / Tier 4-5
> - Domain controllers, SSO, and payment gateways are almost always Tier 1
> - APIs and databases are typically Tier 2 unless storing critical data

These rules address the known tendency of LLMs to over-estimate importance. Without calibration, LLMs typically classify 30-50% of assets as "critical," which defeats the purpose of prioritization.

### 7.4 Deterministic Fallback

If the LLM is unavailable or returns invalid output, the `deterministicAssetClassification()` function in `scoring-hardening.ts` provides a rule-based fallback using regex pattern matching on hostnames, asset types, and technology stacks:

```typescript
// Authentication / SSO → Tier 1
if (allSignals.some(s => /auth|sso|login|ldap|keycloak|okta|adfs|saml|oauth/.test(s))) {
  deviceType = "identity_provider";
  businessImpactLevel = "mission_critical";
  criticalityTier = 1;
}
// CDN / Static → Tier 4
if (allSignals.some(s => /\bcdn\b|cloudfront|akamai|fastly|\bstatic\b/.test(s))) {
  deviceType = "cdn_node";
  businessImpactLevel = "administrative";
  criticalityTier = 4;
}
```

The deterministic fallback has a fixed confidence of 0.4 (vs. LLM classification confidence of 0.5-0.95), ensuring that the system always produces a classification but clearly signals when it is operating in degraded mode.

### 7.5 Mission Function Baselines

Each mission function has pre-defined CARVER/SHOCK baselines and mission multipliers:

| Mission Function | Key CARVER Floors | Mission Multiplier | Rationale |
|-----------------|-------------------|-------------------|-----------|
| Authentication | C=9, A=7, E=9, R=8 | 1.9× | "The master key — compromise grants access to all downstream systems" |
| Command & Control | C=9, E=8, R=7 | 1.8× | "The nerve center — compromise enables adversary control" |
| Customer Data | C=8, E=7, R=8 | 1.7× | "Regulatory and reputational risk — breach triggers mandatory disclosure" |
| Revenue Generation | C=8, E=8, Rec=7 | 1.6× | "Directly impacts financial viability — downtime has immediate P&L consequences" |
| Intellectual Property | C=7, E=9, R=9 | 1.5× | "Irreplaceable competitive advantage — exfiltration causes permanent damage" |
| Supply Chain | C=7, A=6, V=7 | 1.5× | "Bridges trust boundaries — enables island-hopping attacks" |
| Operational Continuity | C=7, E=7, R=6 | 1.4× | "Keeps the lights on — disruption cascades through dependent processes" |
| Compliance | C=6, E=7, Rec=5 | 1.3× | "Regulatory risk — failure triggers audit findings and fines" |
| External Communication | C=6, A=8, Rec=8 | 1.2× | "Prime targets for impersonation and phishing" |
| Data Processing | C=6, E=6, V=5 | 1.2× | "Transforms raw data into actionable intelligence" |

---

## 8. Layer 7 — Core Hybrid Risk Computation

### 8.1 The Central Formula

The `computeHybridRisk()` function in `scoring-engine.ts` is the mathematical core of the scoring system. It takes a `ScoringInput` (CARVER scores, SHOCK scores, exposure, confidence, optional CVSS/FIPS/tier data) and a `ScoringProfile` (weights and thresholds) and produces a `ScoringResult`.

The computation proceeds in five stages:

**Stage 1 — Composite Scores:**

```
carverComposite = Σ(carver[i] × weight[i]) / Σ(weight[i])    for i ∈ {C, A, R, V, E, Rec}
shockComposite  = Σ(shock[j] × weight[j]) / Σ(weight[j])     for j ∈ {S, H, O, C, K}
```

These are weighted averages on a 0-10 scale.

**Stage 2 — Mission Impact:**

```
carverNorm = carverWeight / (carverWeight + shockWeight)
shockNorm  = shockWeight / (carverWeight + shockWeight)
missionImpact = clamp((carverComposite × carverNorm + shockComposite × shockNorm) × missionMultiplier, 0, 10)
```

**Stage 3 — Impact Normalization:**

```
impact = clamp(missionImpact / 10, 0, 1)
```

**Stage 4 — Likelihood Computation (the "Innocent Until Proven Guilty" model):**

```
IF confirmedVulnScore > 0:
    likelihoodBase = confirmedVulnScore / 100
    likelihoodBase += (exposure - 0.5) × 0.2
    likelihoodBase += (recognizability/10 - 0.5) × 0.1
ELSE:
    // No confirmed vulnerability — asset stays GREEN
    likelihoodBase = clamp(exposure × 0.1 + recognizability/10 × 0.05, 0, 0.15)

// Port-based likelihood boost (from open port analysis)
likelihoodBase += portLikelihoodBoost

// Confidence dampening
confidenceDampening = 0.55 + (confidence × 0.45)
likelihood = clamp(likelihoodBase × confidenceDampening, 0, 1)
```

**Stage 5 — Final Score:**

```
hybridRiskScore = round(√(impact × likelihood) × 100)
```

The geometric mean (square root of impact × likelihood) is used instead of arithmetic mean because it produces more conservative scores — an asset must have both high impact AND high likelihood to receive a high score. An asset with impact=1.0 and likelihood=0.01 scores only 10, not 50.

### 8.2 Risk Banding

The `hybridRiskScore` (0-100) is mapped to risk bands using configurable thresholds:

| Band | Default Threshold | Meaning |
|------|------------------|---------|
| Critical | ≥ 85 | Immediate remediation required |
| High | ≥ 65 | Remediation within current sprint |
| Medium | ≥ 40 | Remediation within current quarter |
| Low | < 40 | Accept or schedule for future remediation |

### 8.3 The "Innocent Until Proven Guilty" Design

This is one of the most important architectural decisions in the scoring system. When `confirmedVulnScore` is undefined or zero, the likelihood is capped at 15% regardless of other factors. This means:

- An internet-facing web server with no confirmed vulnerabilities scores low (green)
- The same server with a confirmed RCE vulnerability immediately scores high (red)
- CVSS estimates from LLM analysis are "advisory only" and do NOT inflate the score

This design prevents the "alert fatigue" problem where traditional vulnerability scanners flag thousands of assets as high-risk based on theoretical vulnerabilities. In AC3, assets stay green until corroborated evidence arrives.

### 8.4 Scoring Profiles

The system ships with six pre-configured scoring profiles that adjust weights and thresholds for different use cases:

| Profile | CARVER Weight | SHOCK Weight | CVSS Weight | Key Emphasis |
|---------|--------------|-------------|-------------|-------------|
| Default | 0.40 | 0.30 | 0.30 | Balanced |
| Critical Infrastructure | 0.30 | 0.50 | 0.20 | SHOCK (cascading effects, operational impact) |
| Financial Services | 0.45 | 0.20 | 0.35 | CARVER (accessibility) + CVSS |
| Healthcare | 0.35 | 0.40 | 0.25 | SHOCK (operational impact) + CARVER (recuperability) |
| Government/DoD | 0.50 | 0.25 | 0.25 | CARVER (traditional military methodology) |
| Red Team/Offensive | 0.50 | 0.15 | 0.35 | CARVER (accessibility, vulnerability) |
| MSSP/Managed | 0.35 | 0.35 | 0.30 | Balanced with scope emphasis |

Each profile also adjusts individual CARVER and SHOCK dimension weights. For example, the Red Team profile sets Accessibility weight to 3.0 (vs. default 1.5) and Vulnerability weight to 2.5 (vs. default 1.5), because offensive operators prioritize the easiest attack paths.

### 8.5 Factor Contribution Analysis

Every scoring result includes a `factorContributions` array that breaks down each CARVER and SHOCK dimension's contribution to the final score:

```typescript
interface FactorContribution {
  factor: string;        // e.g., "Criticality"
  category: "CARVER" | "Shock";
  rawScore: number;      // 0-10
  weight: number;        // From profile
  weightedScore: number; // rawScore × weight
}
```

This enables the `ExplainableRiskCard` to show exactly which factors drove the score, supporting the "explainable AI" requirement.

---

## 9. Layer 8 — Fusion Formula

### 9.1 Purpose

While Layer 7 computes the core `hybridRiskScore` from CARVER/SHOCK composites and likelihood, Layer 8 provides an alternative scoring path — the `hybridFusionScore` — that directly fuses CARVER composites with CVSS base/exploitability scores and real-time threat intelligence (EPSS, KEV).

### 9.2 The Formula

The `computeHybridFusionScore()` function in `auto-industry-carver.ts`:

```
hybrid = (carverComposite × sectorMultiplier) + (cvssBase × 0.6) + (cvssExploitability × 0.4)
```

Where:
- `carverComposite` = weighted average of the 7 CARVER+SHOCK dimensions from the sector preset
- `sectorMultiplier` = sector-specific scaling factor (e.g., 1.2 for defense, 1.0 for SaaS)
- `cvssBase` = CVSS v4.0 base score (0-10)
- `cvssExploitability` = CVSS exploitability sub-score (0-10)

### 9.3 EPSS Boost

If the EPSS (Exploit Prediction Scoring System) probability exceeds 0.5 (50% chance of exploitation in the next 30 days):

```
hybrid += epssScore × 1.5
```

An EPSS score of 0.8 adds 1.2 points to the fusion score. This boost is only applied above the 0.5 threshold to avoid noise from low-probability predictions.

### 9.4 KEV Boost

If the vulnerability is listed in CISA's Known Exploited Vulnerabilities catalog:

```
hybrid += 2.0
```

This is a flat boost that reflects the empirical reality that KEV-listed vulnerabilities are under active exploitation. The 2.0-point boost is significant enough to push borderline P1 vulnerabilities into P0 territory.

### 9.5 Evidence Multiplier

The final score is scaled by evidence quality:

```
IF evidenceMultiplier < 1.0:
    hybrid = hybrid × evidenceMultiplier
```

| Evidence Level | Multiplier | Meaning |
|---------------|-----------|---------|
| Confirmed | 1.0 | Vulnerability verified by exploitation or reliable scanner |
| Corroborated | 0.85 | Multiple independent sources agree |
| Unverified | 0.30 | Single source, LLM inference, or unconfirmed report |

An unverified finding with a raw fusion score of 12.0 is reduced to 3.6 after the evidence multiplier — dropping it from P0 to P3. This is the primary mechanism for preventing LLM hallucinations from driving remediation priorities.

### 9.6 Priority Tiers

The fusion score maps to priority tiers:

| Tier | Threshold | Meaning |
|------|-----------|---------|
| P0 | ≥ 12.0 | Immediate action — active exploitation, critical asset |
| P1 | ≥ 9.0 | Urgent — high severity, high-value target |
| P2 | ≥ 6.0 | Standard — moderate risk, scheduled remediation |
| P3 | < 6.0 | Low — accept or defer |

### 9.7 Relationship Between Layer 7 and Layer 8

The two scoring paths serve different purposes:

| Aspect | Layer 7 (`hybridRiskScore`) | Layer 8 (`hybridFusionScore`) |
|--------|---------------------------|------------------------------|
| Scale | 0-100 | 0-~20 |
| Likelihood model | "Innocent until proven guilty" | Implicit via CVSS + EPSS |
| Evidence weighting | Via confidence dampening | Via explicit evidence multiplier |
| Primary use | Risk dashboard, risk banding | Priority triage, Caldera operation planning |
| Sector awareness | Via CARVER/SHOCK composites | Via sector multiplier |

Both scores appear in the `ExplainableRiskCard`. Layer 7 is used for the risk dashboard and trend analysis. Layer 8 is used for operational prioritization and Caldera red team operation planning.

---

## 10. Layer 9 — LLM Augmentation

### 10.1 Architecture

The `scoreHybrid()` function in `hybrid-scorer.ts` implements a "deterministic baseline + LLM delta" architecture. The LLM does not compute scores from scratch — it reviews the deterministic baseline and provides bounded adjustments.

### 10.2 The HYBRID_SCORER_ROLE Prompt

The LLM receives a system prompt that defines five augmentation types:

> 1. **Business Context Inference**: What role does this asset likely play in the organization? Does the hostname, technology stack, or content suggest it's a crown jewel, support system, or peripheral asset?
>
> 2. **Attack Surface Reality Check**: Do the observed ports, services, and configurations suggest the asset is more or less accessible/vulnerable than the sector baseline assumes?
>
> 3. **OSINT Signal Fusion**: Do certificate transparency logs, DNS records, WHOIS data, or other OSINT signals reveal information that changes the risk picture?
>
> 4. **Dark Web / Threat Intel Fusion**: If DWX or threat intel data is provided, factor in whether credentials, mentions, or indicators related to this asset appear in underground sources.
>
> 5. **Exploitability Assessment**: Based on the specific services and versions observed, how realistic is exploitation? Consider WAF presence, cloud provider protections, and known mitigations.

### 10.3 Bounded Delta Adjustments

For each CARVER+SHOCK dimension, the LLM provides:

```typescript
{
  delta: number,        // -3 to +3 (0 = agree with baseline)
  justification: string // One-sentence evidence-tagged justification
}
```

The delta range of -3 to +3 is enforced by the JSON schema. The prompt explicitly instructs:

> Keep adjustments conservative. Most dimensions should be 0 (agree with baseline). Only adjust when scan data provides clear evidence.

### 10.4 Structured Output

The LLM returns a structured JSON response:

```typescript
interface HybridScorerOutput {
  adjustments: {
    criticality:    { delta: number; justification: string };
    accessibility:  { delta: number; justification: string };
    recuperability: { delta: number; justification: string };
    vulnerability:  { delta: number; justification: string };
    effect:         { delta: number; justification: string };
    recognizability:{ delta: number; justification: string };
    shock:          { delta: number; justification: string };
  };
  businessContextInference: string;
  attackSurfaceAssessment: string;
  exploitabilityAssessment: string;
  overallRiskNarrative: string;
  adjustedHybridScore: number;
  adjustedPriorityTier: PriorityTier;
  confidence: "high" | "medium" | "low";
  evidenceTags: string[];
}
```

### 10.5 Graceful Degradation

If the LLM call fails (timeout, rate limit, invalid response), the system returns the deterministic baseline with all deltas set to 0:

```typescript
// On LLM failure: return baseline with zero adjustments
return {
  adjustments: {
    criticality: { delta: 0, justification: "LLM unavailable — baseline preserved" },
    // ... all dimensions delta: 0
  },
  businessContextInference: "LLM augmentation unavailable",
  overallRiskNarrative: "Deterministic baseline only",
  adjustedHybridScore: baselineCard.scores.hybrid,
  adjustedPriorityTier: baselineCard.scores.priorityTier,
  confidence: "low",
  evidenceTags: ["fallback"],
};
```

This ensures the scoring pipeline never fails to produce a result. The `confidence: "low"` and `evidenceTags: ["fallback"]` signals allow downstream consumers to know the score was not LLM-augmented.

### 10.6 Engagement Context

Every LLM call receives rich engagement context built by `buildEngagementContext()`:

```typescript
interface EngagementContext {
  engagementType: string;
  clientName?: string;
  industry?: string;
  scope?: string;
  targetCount: number;
  inferredSector: CarverSector;
  sectorConfidence: number;
  regulatoryProfile: string[];
  complianceFrameworks: string[];
  threatLandscape: Array<{ category: string; likelihood: number }>;
  crownJewels: string[];
  rulesOfEngagement?: string;
}
```

This context ensures the LLM understands the organizational environment when making adjustments. A web server at a defense contractor should be assessed differently than the same server at a marketing agency.

---

## 11. Layer 10 — BIA Financial Impact

### 11.1 Purpose

While Layers 1-9 produce technical risk scores, Layer 10 translates those scores into dollar-value financial impact estimates that executives and board members can understand.

### 11.2 The `calculateFinancialImpact()` Function

Located in `entity-resolver.ts`, this function takes an `EntityProfile` (containing estimated revenue, valuation, employee count, industry, and public company status) and produces:

```typescript
{
  maxSingleIncidentLoss: number;
  estimatedDailyRevenueLoss: number;
  regulatoryFineExposure: number;
  reputationalDamageEstimate: number;
  totalMaxExposure: number;
  impactTier: "catastrophic" | "severe" | "significant" | "moderate" | "minimal";
  rationale: string;
}
```

### 11.3 Industry-Adjusted Incident Loss Rates

The maximum single-incident loss is calculated as a percentage of annual revenue, with rates calibrated to industry-specific data from the Ponemon Institute / IBM Cost of a Data Breach reports:

| Industry | Incident Loss Rate | Basis |
|----------|-------------------|-------|
| Healthcare | 5.0% | Highest per-record breach cost ($10.93M avg, 2023 IBM report) |
| Financial Services | 4.0% | Second-highest breach cost ($5.90M avg) + regulatory fines |
| Technology | 3.5% | High breach cost ($4.66M avg) + IP loss multiplier |
| Government | 2.0% | Lower direct financial impact but high operational cost |
| Default (all others) | 3.0% | Global average breach cost as percentage of revenue |

### 11.4 Financial Impact Components

| Component | Calculation | Rationale |
|-----------|-------------|-----------|
| `maxSingleIncidentLoss` | `revenue × incidentLossRate` | Direct breach cost (forensics, notification, remediation, legal) |
| `estimatedDailyRevenueLoss` | `revenue / 365` | Revenue lost per day of outage |
| `regulatoryFineExposure` | `revenue × 0.04` | GDPR maximum (4% of global revenue); HIPAA up to $1.5M per violation |
| `reputationalDamageEstimate` | `(valuation or revenue×3) × 0.02` | 1-5% of market cap; conservative 2% estimate |
| `totalMaxExposure` | Sum of above + 7 days downtime | Worst-case scenario: breach + week-long outage |

### 11.5 Impact Tiers

| Tier | Threshold | Typical Organization |
|------|-----------|---------------------|
| Catastrophic | > $100M | Fortune 500, large financial institutions |
| Severe | > $10M | Mid-market enterprises, regional banks |
| Significant | > $1M | SMBs with meaningful revenue |
| Moderate | > $100K | Small businesses |
| Minimal | ≤ $100K | Micro-businesses, non-profits |

### 11.6 Integration with Scoring Pipeline

The BIA financial impact feeds into the `ExplainableRiskCard` and the BIA report generator (`bia-report-generator.ts`). It does not directly modify the hybrid risk score — instead, it provides a parallel financial dimension that helps prioritize remediation by business impact rather than technical severity alone.

---

## 12. Layer 11 — Dynamic Re-Scoring Triggers

### 12.1 Purpose

Static scoring captures a point-in-time assessment. Dynamic re-scoring triggers allow the system to automatically elevate risk scores when new threat intelligence arrives during an engagement.

### 12.2 Discovery Phase Triggers

Five triggers are defined in `DISCOVERY_PHASE_TRIGGERS`:

| Trigger | Description | Likelihood Boost | Key CARVER Adjustments |
|---------|-------------|-----------------|----------------------|
| `kev_match` | Vulnerability matches CISA KEV catalog | 0.30 (0.45 if ransomware) | V=10, Rec=8; if ransomware: C=9, E=9 |
| `darkweb_exposure` | Credentials/data found on dark web | 0.25 | A=9, V=8, Rec=9 |
| `threat_actor_ttp_match` | Asset matches known threat actor TTPs | 0.10-0.20 | V=5-7 (based on sophistication) |
| `attack_chain_match` | Vulnerabilities match known attack chain | 0.05-0.25 | V=5-9, E=6-8 (based on feasibility) |
| `bug_bounty_correlation` | Pattern matches bug bounty findings | 0.10-0.30 | V=5-9, A=7 (based on bounty tier) |

### 12.3 Floor-Based Application

All trigger adjustments are applied as floors:

```typescript
for (const [key, val] of Object.entries(carverAdj)) {
  adjustedCarver[k] = Math.max(adjustedCarver[k], val as number);
}
```

This ensures triggers can only elevate risk, never reduce it. A KEV match sets Vulnerability to 10 — the maximum — because active exploitation is the strongest possible evidence of exploitability.

### 12.4 Re-Scoring Events

Each trigger application generates a `RescoringEvent`:

```typescript
interface RescoringEvent {
  trigger: RescoringTrigger;
  assetId: string;
  previousScore: number;
  newScore: number;
  previousBand: string;
  newBand: string;
  delta: number;
  changeDescription: string;
  factorChanges: Array<{ factor: string; previous: number; new: number }>;
  timestamp: number;
}
```

A re-scoring event is considered "significant" if:
- The risk band changed (e.g., medium → high)
- The absolute score delta is ≥ 15 points
- The asset moved into the critical band

Significant changes trigger alerts and may require re-prioritization of remediation efforts.

---

## 13. Layer 12 — Hardening & Temporal Decay

### 13.1 Anti-Gaming Hardening

The `computeHybridRiskHardened()` function in `scoring-hardening.ts` wraps the core scoring engine with defensive measures:

**Input Sanitization:**
- All CARVER scores clamped to [0, 10]
- All SHOCK scores clamped to [0, 10]
- NaN/undefined/null values replaced with defaults
- Division-by-zero guards on profile weights

**Output Validation:**
- Checks for NaN/Infinity in `hybridRiskScore`
- Falls back to pure deterministic scoring if validation fails
- Generates audit trail of all corrections

**Distribution Monitoring:**
- Flags if > 30% of assets score critical (possible over-inflation)
- Flags if 0% score critical or high (possible under-scoring)
- Flags if > 50% of assets used fallback scoring (LLM classification may be failing)

The `HardenedScoringResult` extends the base `ScoringResult` with:

```typescript
interface HardenedScoringResult extends ScoringResult {
  usedFallback: boolean;
  validationWarnings: string[];
  sanitizationLog: string[];
}
```

### 13.2 Temporal Decay

The temporal decay module in `temporal-decay.ts` adjusts vulnerability scores based on five time-sensitive factors:

| Factor | Weight | Multiplier Range | Logic |
|--------|--------|-----------------|-------|
| Exploit Maturity | 0.25 | 0.8x - 1.5x | Older CVEs with public exploits = higher maturity |
| Patch Negligence | 0.25 | 1.0x - 1.5x | Patch available but not applied = negligence penalty |
| KEV Urgency | 0.20 | 1.0x - 1.5x | Recently added to KEV = maximum urgency |
| Validation Staleness | 0.15 | 0.7x - 1.1x | Stale validations lose confidence |
| Finding Age | 0.15 | 1.0x - 1.2x | New findings prioritized; old unresolved = escalation |

**Temporal Score Output:**

```typescript
interface TemporalScore {
  baseScore: number;
  temporalMultiplier: number;     // 0.5 - 2.0
  adjustedScore: number;          // baseScore × multiplier, capped at 10
  adjustedSeverity: string;
  factors: TemporalFactorBreakdown[];
  urgencyLevel: "immediate" | "urgent" | "elevated" | "standard" | "deferred";
  rationale: string;
  decayWarnings: string[];
}
```

**Urgency Levels:**

| Level | Criteria |
|-------|---------|
| Immediate | Score ≥ 9.0 AND KEV-listed |
| Urgent | Score ≥ 9.0 OR (score ≥ 7.0 AND KEV-listed) |
| Elevated | Score ≥ 7.0 OR 2+ decay warnings |
| Standard | Score ≥ 4.0 |
| Deferred | Score < 4.0 |

**Key Temporal Behaviors:**

- A vulnerability with a patch available for 14+ days receives a negligence penalty (up to 1.5×)
- A KEV entry added within the last 30 days receives maximum urgency boost (1.5×)
- A finding that has never been validated receives a confidence reduction (0.8×)
- A finding validated within the last 30 days receives a confidence boost (1.1×)
- Long-standing unresolved findings (90+ days) receive an escalation boost (1.15×)

---

## 14. The ExplainableRiskCard — Final Output

### 14.1 Structure

The `buildExplainableRiskCard()` function in `auto-industry-carver.ts` assembles the final output by orchestrating Layers 1-8:

```typescript
interface ExplainableRiskCard {
  assetId: string;
  assetLabel: string;
  sector: CarverSector;
  naics: string;
  regulatoryProfile: RegulatoryFramework[];
  scores: {
    carverShock: number;       // Composite (0-10)
    cvss: {
      base: number;            // 0-10
      exploitability: number;  // 0-10
    };
    hybrid: number;            // Fusion score
    priorityTier: PriorityTier;
  };
  topDrivers: RiskCardDriver[];
  threatLikelihood: Partial<Record<ThreatCategory, number>>;
  recommendedActions: string[];
  calderaPriority: CalderaPriority;
  confidence: number;
}
```

### 14.2 Caldera Operation Prioritization

The `calderaPriority` field maps the risk assessment to concrete Caldera red team operations:

```typescript
interface CalderaPriority {
  operationTier: string;              // e.g., "full_exploitation"
  operationProfile: string;           // e.g., "APT29 emulation"
  objectives: string[];               // e.g., ["Validate RCE", "Test lateral movement"]
  recommendedAdversaries: string[];   // e.g., ["APT29", "FIN7"]
  recommendedAbilitySets: string[];   // e.g., ["credential_harvesting", "data_exfiltration"]
  notes: string[];
}
```

This closes the loop from risk assessment to automated penetration testing — the scoring system does not just identify risk, it prescribes the specific offensive operations needed to validate and remediate that risk.

---

## 15. Data Capture Inventory

### 15.1 Input Data Sources

The following data sources feed into the scoring pipeline:

| Data Source | Layer(s) | Required? | Source |
|-------------|---------|-----------|--------|
| Domain name / hostname | 1, 6, 9 | Yes | Scan discovery |
| TLD | 1 | No | Parsed from domain |
| Keywords from page content | 1, 6 | No | Web crawling |
| Asset type / technology stack | 6, 12 | No | Technology fingerprinting |
| CVSS v4.0 vector string | 3, 7 | No | NVD, vulnerability scanners |
| CVSS base score | 8 | No | NVD, vulnerability scanners |
| CVSS exploitability sub-score | 8 | No | NVD, vulnerability scanners |
| EPSS probability | 8 | No | FIRST EPSS API |
| CISA KEV listing | 8, 11, 12 | No | CISA KEV catalog |
| FIPS 199 categorization | 4 | No | Manual or LLM-inferred |
| Criticality tier | 5 | No | Manual or LLM-inferred |
| Confirmed vulnerability score | 7 | No | Validated scan findings |
| Exposure level (0-1) | 7 | Yes | Network analysis |
| Confidence level (0-1) | 7 | Yes | Scan confidence |
| Port scan results | 7, 9 | No | Port scanning |
| Entity revenue / valuation | 10 | No | Entity resolution |
| Entity employee count | 10 | No | Entity resolution |
| Entity industry | 10 | No | Entity resolution |
| Dark web intelligence | 9, 11 | No | DWX feeds |
| OSINT findings | 9 | No | OSINT collection |
| Certificate data | 9 | No | Certificate transparency |
| DNS records | 9 | No | DNS enumeration |
| WHOIS data | 9 | No | WHOIS lookup |
| HTTP headers | 9 | No | Web crawling |
| CVE publication date | 12 | No | NVD |
| Patch availability date | 12 | No | Vendor advisories |
| Exploit publication date | 12 | No | ExploitDB, GitHub |
| Last validation timestamp | 12 | No | Internal scan records |

### 15.2 Output Data

| Output | Type | Consumer |
|--------|------|----------|
| `ExplainableRiskCard` | Structured JSON | Risk dashboard, reports, Caldera operations |
| `ScoringResult` | Structured JSON | Internal scoring pipeline |
| `HardenedScoringResult` | Structured JSON | Audit trail, debugging |
| `TemporalScore` | Structured JSON | Time-based risk trending |
| `FinancialImpact` | Structured JSON | BIA reports, executive dashboards |
| `RescoringEvent` | Structured JSON | Alert system, audit trail |
| `ScoringValidationReport` | Structured JSON | Quality assurance, monitoring |

---

## 16. Patentability Analysis

### 16.1 Novel Contributions

The AC3 Hybrid Scoring System introduces several elements that, individually and in combination, represent novel contributions to the field of automated vulnerability risk assessment:

**16.1.1 CARVER Digital Translation (Novel)**

The translation of the U.S. Army's CARVER targeting methodology from physical military targets to digital assets is, to our knowledge, unprecedented in commercial vulnerability management software. While CARVER has been used in physical security assessments and some government cyber assessments, no existing product provides:

- Systematic 1-10 scale criteria for each CARVER factor in a digital context
- Side-by-side original military criteria and digital equivalents
- Sub-factor decomposition for each dimension
- The SHOCK extension adapted for cyber operational disruption

**16.1.2 CVSS → CARVER Bidirectional Mapping (Novel)**

No existing system maps CVSS v4.0 vector components to CARVER dimensions. This mapping enables organizations to leverage their existing CVSS data within a richer targeting-based framework without requiring manual re-assessment.

**16.1.3 Multi-Framework Fusion with Evidence Weighting (Novel)**

The combination of:
- Military targeting methodology (CARVER)
- Vulnerability severity scoring (CVSS v4.0)
- Threat intelligence (EPSS, KEV)
- Business impact analysis (BIA with industry-adjusted loss rates)
- LLM augmentation with bounded deltas
- Evidence quality weighting

...in a single scoring pipeline with explainable output is not available in any existing product. Commercial tools typically use CVSS alone, or CVSS + EPSS, but do not incorporate military targeting methodology or sector-aware business impact analysis.

**16.1.4 "Innocent Until Proven Guilty" Likelihood Model (Novel)**

The design decision to cap likelihood at 15% without confirmed vulnerability evidence is a departure from standard vulnerability management practice. Most tools assign risk based on CVSS severity alone, leading to alert fatigue. AC3's approach requires corroborated evidence before elevating risk, which is a fundamentally different philosophy.

**16.1.5 Sector-Aware Scoring with Automatic NAICS Inference (Novel)**

The automatic detection of organizational sector from domain signals, with NAICS code inference and per-sector CARVER+SHOCK presets, threat actor likelihood profiles, and regulatory overlay adjustments, represents a novel approach to contextualizing vulnerability risk.

### 16.2 Prior Art Comparison

| Capability | AC3 | Tenable.io | Qualys VMDR | Rapid7 InsightVM | CVSS Alone |
|-----------|-----|-----------|------------|-----------------|-----------|
| CARVER targeting | Yes (6 factors + SHOCK) | No | No | No | No |
| CVSS v4.0 integration | Yes (feed-through) | Yes (native) | Yes (native) | Yes (native) | Yes |
| EPSS integration | Yes | Yes | Yes | Yes | No |
| KEV integration | Yes | Yes | Yes | Yes | No |
| Sector-aware scoring | Yes (7 sectors, auto-detect) | No | No | No | No |
| NAICS auto-mapping | Yes | No | No | No | No |
| BIA financial impact | Yes (industry-adjusted) | No | No | No | No |
| LLM augmentation | Yes (bounded deltas) | No | No | No | No |
| Evidence weighting | Yes (confirmed/corroborated/unverified) | No | No | No | No |
| "Innocent until proven" | Yes | No | No | No | No |
| Temporal decay | Yes (5-factor) | Limited | Limited | Limited | No |
| Explainable risk cards | Yes | Limited | Limited | Limited | No |
| Caldera operation mapping | Yes | No | No | No | No |

### 16.3 Potential Patent Claims

Based on the analysis above, the following claims could be considered for patent protection:

1. **A method for scoring digital asset risk** by translating military CARVER targeting factors to digital asset criteria and fusing the resulting scores with CVSS vulnerability severity, EPSS exploitation probability, and business impact analysis through a multi-layer pipeline that produces an explainable risk score.

2. **A system for automatic sector detection and NAICS inference** from domain signals, with per-sector baseline risk profiles and regulatory overlay adjustments that contextualize vulnerability risk scoring.

3. **A method for LLM-augmented risk scoring** where a deterministic baseline score is computed independently of any AI system, and an LLM provides bounded delta adjustments (-3 to +3) with structured evidence tags, with graceful degradation to the deterministic baseline when the LLM is unavailable.

4. **A likelihood computation method** that maintains assets at low risk (≤15%) until confirmed vulnerability evidence arrives, preventing alert fatigue while ensuring rapid escalation when corroborated evidence is obtained.

5. **A temporal decay scoring system** that adjusts vulnerability severity based on five time-sensitive factors (exploit maturity, patch negligence, KEV urgency, validation staleness, finding age) with configurable weights and a bounded multiplier range.

---

## 17. Known Limitations and Honest Gaps

### 17.1 Sector Detection Accuracy

The rule-based sector detection in Layer 1 relies on pattern matching against TLDs, keywords, and asset signals. Organizations with ambiguous digital footprints (e.g., a healthcare company using `.com` with no medical keywords) may be misclassified. The confidence score mitigates this, but the system has no mechanism for user correction of misclassified sectors within the automated pipeline.

### 17.2 CARVER Subjectivity

The CARVER digital translation tables represent expert judgment, not empirical measurement. The mapping of "Replacement/repair requires 1 month+" to "Custom-built system, no backups, no documentation — months to rebuild" is a reasonable analogy, but different security professionals might draw the boundaries differently. The tables have not been validated through formal inter-rater reliability studies.

### 17.3 LLM Augmentation Consistency

While the bounded delta range (-3 to +3) limits the LLM's influence, different LLM models or even different invocations of the same model may produce different adjustments for identical inputs. The system does not currently track LLM adjustment consistency across invocations or flag high-variance dimensions.

### 17.4 Financial Impact Precision

The BIA financial impact calculations use industry-average loss rates from published research (Ponemon/IBM). These averages may not reflect the specific financial exposure of any individual organization. The system does not account for cyber insurance coverage, existing security controls, or organization-specific financial structures.

### 17.5 Temporal Decay Calibration

The temporal decay weights and thresholds are based on security industry best practices but have not been empirically validated against actual breach data. The 14-day patch negligence grace period, for example, is a policy decision that may be too lenient for critical infrastructure or too aggressive for resource-constrained organizations.

---

## 18. Conclusion

The AC3 Hybrid Scoring System represents a comprehensive approach to vulnerability risk quantification that goes beyond any single methodology. By fusing military targeting analysis (CARVER+SHOCK), vulnerability severity (CVSS v4.0), threat intelligence (EPSS, KEV), business impact analysis (BIA), and LLM augmentation into a 12-layer pipeline, it produces risk scores that are simultaneously:

- **Technically precise** — grounded in CVSS v4.0 metrics and confirmed vulnerability data
- **Operationally relevant** — contextualized by sector, regulatory environment, and mission criticality
- **Financially meaningful** — translated to dollar-value impact estimates
- **Explainable** — every score includes the complete reasoning chain via `ExplainableRiskCard`
- **Resilient** — graceful degradation at every layer ensures the system always produces a score

The "innocent until proven guilty" likelihood model, evidence-quality weighting, and anti-gaming hardening collectively address the alert fatigue and score inflation problems that plague traditional vulnerability management. The temporal decay module ensures scores remain current as the threat landscape evolves.

The system's novel combination of military targeting methodology, multi-framework fusion, and LLM augmentation with bounded deltas represents a meaningful advancement in automated vulnerability risk assessment.

---

## Appendix A — Source File Index

| File | Lines | Primary Responsibility |
|------|-------|----------------------|
| `server/lib/scoring-engine.ts` | 1,650 | Core scoring engine, CARVER/SHOCK types, CVSS v4.0 parser, FIPS 199 mapping, criticality tiers, digital translation tables, `computeHybridRisk()`, LLM asset classification, dynamic re-scoring triggers |
| `server/lib/auto-industry-carver.ts` | 1,210 | Sector detection, NAICS mapping, CARVER+SHOCK presets, regulatory overlays, `computeHybridFusionScore()`, `buildExplainableRiskCard()`, threat actor likelihood, Caldera operation prioritization |
| `server/lib/llm-specialists/hybrid-scorer.ts` | 522 | LLM augmentation layer, `scoreHybrid()`, engagement context builder, HYBRID_SCORER_ROLE prompt |
| `server/lib/entity-resolver.ts` | 576 | Entity resolution, `calculateFinancialImpact()`, industry-adjusted loss rates |
| `server/lib/scoring-hardening.ts` | 530 | Anti-gaming hardening, `computeHybridRiskHardened()`, deterministic fallback, distribution monitoring |
| `server/lib/temporal-decay.ts` | 290 | Temporal decay scoring, 5-factor model, urgency levels |

## Appendix B — Glossary

| Term | Definition |
|------|-----------|
| **CARVER** | Criticality, Accessibility, Recuperability, Vulnerability, Effect, Recognizability — U.S. Army targeting methodology (FM 34-36) |
| **SHOCK** | Scope, Handling, Operational Impact, Cascading Effects, Knowledge — DHS-adapted consequence assessment extension |
| **CVSS** | Common Vulnerability Scoring System — industry standard for vulnerability severity (v4.0) |
| **EPSS** | Exploit Prediction Scoring System — probability of exploitation in next 30 days |
| **KEV** | Known Exploited Vulnerabilities — CISA catalog of actively exploited vulnerabilities |
| **FIPS 199** | Standards for Security Categorization of Federal Information and Information Systems |
| **NIST SP 800-34** | Contingency Planning Guide for Federal Information Systems |
| **NAICS** | North American Industry Classification System |
| **BIA** | Business Impact Analysis |
| **RTO** | Recovery Time Objective — maximum acceptable downtime |
| **ExplainableRiskCard** | AC3's structured output containing scores, drivers, and recommended actions |
| **Fusion Score** | The `hybridFusionScore` computed by Layer 8 (CARVER × sector + CVSS + EPSS/KEV) |
| **Hybrid Risk Score** | The `hybridRiskScore` computed by Layer 7 (√(impact × likelihood) × 100) |
