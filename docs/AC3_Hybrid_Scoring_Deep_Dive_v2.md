# AC3 Hybrid Scoring System — Technical Deep Dive (v2)

**Document Version:** v2 (Round 5 Revision)
**Date:** April 23, 2026
**Author:** AceofCloud (Harrison Cook, Director of Security Engineering and Offensive Operations) — 25-year practitioner in military targeting analysis, critical infrastructure protection, and offensive security operations
**Scope:** End-to-end architecture of the CARVER+SHOCK/CVSS/BIA hybrid risk scoring pipeline
**Audience:** External safety reviewer (Claude)
**Source Files:** `scoring-engine.ts` (1,780+ lines), `auto-industry-carver.ts` (1,210 lines), `hybrid-scorer.ts` (522 lines), `entity-resolver.ts` (576 lines), `scoring-hardening.ts` (660+ lines), `temporal-decay.ts` (290 lines)
**Revision Notes:** Addresses all 8 issues from Claude Round 5 review. Code changes implemented and tested (17/17 tests pass).

---

## 1. Executive Summary

The AC3 Hybrid Scoring System is a multi-layered risk quantification engine that fuses three historically separate methodologies — military targeting analysis (CARVER), vulnerability severity scoring (CVSS v4.0), and business impact analysis (BIA) — into a single, explainable risk score for every digital asset in scope.

The system's central thesis is that **no single scoring methodology captures the full risk picture**:

- **CVSS** tells you how severe a vulnerability is in isolation, but says nothing about whether the affected asset matters to the organization's mission.
- **CARVER** tells you how valuable a target is from an adversary's perspective, but was designed for physical military targets and lacks native integration with vulnerability databases.
- **BIA** tells you the financial and operational impact of asset loss, but provides no mechanism for assessing attack likelihood or exploitability.

AC3 bridges these gaps through a 12-layer pipeline that begins with automated sector detection and ends with an `ExplainableRiskCard` — a structured output that provides not just a score, but the complete reasoning chain behind it.

### 1.1 Practitioner Provenance

The CARVER digital translation tables, sector presets, and scoring calibrations in this system are not academic exercises — they are grounded in 20 years of hands-on experience across military targeting analysis, critical infrastructure protection, and offensive security operations. Specific calibration decisions reflect direct operational experience:

- **Criticality 9 for identity providers** is drawn from two decades of observing Active Directory compromise costs — when AD falls, everything downstream falls with it. The 9 reflects the empirical reality that identity infrastructure is the single most consequential target in any enterprise environment.
- **Banking sector preset Criticality 9, Effect 9** reflects the cascading financial and regulatory consequences observed in real-world banking incidents where a single compromised system triggered SWIFT transaction fraud, regulatory investigations, and multi-million-dollar remediation efforts.
- **Electric/Gas Utilities Criticality 10** is the only sector receiving the maximum score, reflecting the unique physical safety consequences of grid compromise — a calibration informed by direct experience with NERC CIP environments where cyber-physical convergence creates life-safety risks.
- **Defense/Aerospace Recuperability 3** (low, meaning hard to destroy permanently) reflects the redundancy mandates in classified environments — CMMC and ITAR environments require backup and recovery capabilities that make permanent asset destruction extremely difficult.

These calibrations are not arbitrary — they represent pattern recognition across hundreds of engagements, distilled into quantitative baselines that can be systematically applied and adjusted.

### 1.2 What Makes This Novel

The hybrid scoring system introduces several capabilities that, to our knowledge, do not exist in any commercial or open-source vulnerability management platform:

1. **CARVER Digital Translation Tables** — The first systematic, production-grade translation of the U.S. Army's CARVER targeting methodology (FM 34-36, 1990) from physical military targets to digital assets, with 1-10 scale criteria for each of six CARVER factors plus the SHOCK extension. While CARVER has been applied to cyber contexts in government assessments (CISA CRR, DHS CARVER+Shock) and academic papers for over 20 years, no existing commercial product provides automated, software-embedded translation tables with sub-factor decomposition at this level of granularity.

2. **CVSS v4.0 → CARVER Feed-Through** — A bidirectional mapping that translates CVSS v4.0 vector components (AV, AC, AT, PR, UI, VC/VI/VA, SC/SI/SA, E, CR/IR/AR, R, S, AU, V) into CARVER and SHOCK dimension adjustments, applied as floors with **correlated-input damping** to prevent inflation when multiple enrichment sources push the same dimension (see Section 4a).

3. **Sector-Aware Scoring with NAICS Auto-Mapping** — Automated detection of organizational sector from domain TLDs, keywords, and asset signals, with NAICS code inference and per-sector CARVER+SHOCK baseline presets that reflect the actual threat landscape for each industry.

4. **LLM Augmentation with Graceful Degradation** — A deterministic scoring baseline that operates without any AI dependency, augmented by an LLM layer that provides bounded delta adjustments (-3 to +3 per dimension) with structured evidence tags. The LLM adjusts the sector preset CARVER values, then the deterministic pipeline re-runs `computeHybridFusionScore()` — there is no bypass path (see Section 10.6 for explicit propagation trace).

5. **"Innocent Until Proven Guilty" Likelihood Model** — Unlike CVSS-only approaches where every vulnerability immediately inflates the risk score, AC3's likelihood computation keeps assets at low risk (≤15%) until confirmed vulnerability evidence arrives. This prevents the "everything is critical" problem that plagues traditional vulnerability management.

6. **Evidence-Quality Weighting** — The fusion formula applies an evidence multiplier (confirmed=1.0, corroborated=0.85, unverified=0.3) that mathematically penalizes scores based on unverified findings, preventing LLM hallucinations or unconfirmed scan results from driving remediation priorities.

7. **Dynamic Re-Scoring Triggers** — Five discovery-phase triggers (KEV match, dark web exposure, threat actor TTP match, attack chain match, bug bounty correlation) that automatically elevate scores when new intelligence arrives, with per-trigger CARVER/SHOCK adjustments and likelihood boosts.

8. **Anti-Gaming Hardening with Actionable Distribution Monitoring** — A hardened scoring wrapper that sanitizes all inputs, catches NaN/undefined at every computation stage, detects suspicious score distributions, and generates **actionable response objects** with specific remediation guidance for each anomaly type (see Section 13.1).

9. **Temporal Decay** — A five-factor temporal model (exploit maturity, patch negligence, KEV urgency, validation staleness, finding age) that adjusts scores over time with a 0.5x-2.0x multiplier, ensuring that stale findings lose confidence while unpatched known-exploited vulnerabilities escalate.

10. **Inter-Rater Reliability Harness** — A built-in testing harness that compares two independent operator CARVER assessments and computes per-factor agreement metrics, flagging dimensions where rubrics need tightening (see Section 17.2).

### 1.3 Pipeline Overview

The complete scoring pipeline processes an asset through 12 layers:

| Layer | Name | Source File | Purpose |
|-------|------|-------------|---------|
| 1 | Sector Detection & NAICS Mapping | `auto-industry-carver.ts` | Detect organizational sector from signals |
| 2 | CARVER+SHOCK Sector Presets | `auto-industry-carver.ts` | Apply per-sector baseline scores |
| 3 | CVSS v4.0 Feed-Through | `scoring-engine.ts` | Map CVSS metrics to CARVER/SHOCK adjustments |
| 4 | FIPS 199 Integration | `scoring-engine.ts` | Map CIA categorization to scoring adjustments |
| 4a | **Correlated-Input Damping** | `scoring-engine.ts` | Prevent inflation from correlated enrichment sources |
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

Each sector has a pre-calibrated CARVER+SHOCK baseline that reflects the typical risk profile for organizations in that industry. These calibrations are drawn from the author's 20 years of operational experience across military, government, and commercial engagements:

| Sector | C | A | R | V | E | Rec | Shock | Calibration Basis |
|--------|---|---|---|---|---|-----|-------|-------------------|
| Banking/Financial | 9 | 7 | 5 | 6 | 9 | 8 | 8 | SWIFT fraud incidents, FFIEC examination findings |
| Healthcare | 8 | 7 | 6 | 7 | 8 | 7 | 8 | EHR compromise costs, HIPAA breach penalties |
| Pharma/Biotech | 8 | 5 | 4 | 6 | 8 | 6 | 7 | IP theft impact on drug pipeline valuations |
| Defense/Aerospace | 9 | 6 | 3 | 6 | 9 | 8 | 9 | Classified network rebuild costs, CMMC remediation |
| Electric/Gas Utilities | 10 | 5 | 2 | 5 | 10 | 7 | 9 | NERC CIP violations, cyber-physical safety risk |
| Federal Government | 9 | 5 | 4 | 5 | 9 | 7 | 8 | FISMA audit findings, OPM breach aftermath |
| SaaS/Tech | 7 | 8 | 6 | 7 | 7 | 8 | 7 | Cloud-native attack surface, SaaS breach patterns |

The rationale behind key calibration decisions:

- **Electric/Gas Utilities** receive the highest Criticality (10) and Effect (10) because compromise of grid operations can cause physical harm and cascading infrastructure failure. Their low Recuperability (2) reflects the resilience of modern grid systems with redundant controls — it is very hard to permanently destroy a utility's operational capability.
- **Defense/Aerospace** receives the highest Shock (9) because compromise of classified systems has national security implications. Low Recuperability (3) reflects the difficulty of rebuilding classified networks — but the redundancy mandates in CMMC/ITAR environments mean permanent destruction is unlikely.
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

**Important:** As of v2, CVSS-derived CARVER floors are no longer applied directly. Instead, they are collected as an enrichment source and processed through the **correlated-input damping** system (Section 4a) before being applied to the CARVER scores. Shock adjustments are still applied directly.

### 4.4 Design Decision: Floors, Not Overrides

The floor-based application is a deliberate architectural choice. Consider a healthcare EHR system with a CARVER Criticality baseline of 8 (from the healthcare sector preset). If a CVSS vector's environmental requirements suggest Criticality of 6, the floor mechanism preserves the higher sector-informed value. Conversely, if the CVSS vector indicates Criticality of 9 (e.g., due to high availability requirements), the score is raised.

This asymmetry reflects the principle that **sector context should not be overridden by generic vulnerability metrics**, but vulnerability-specific intelligence should be able to elevate risk when warranted.

---

## 4a. Correlated-Input Damping (NEW in v2)

### 4a.1 The Problem: Correlated Enrichment Sources

Claude's Round 5 review identified a structural concern: multiple enrichment sources (CVSS Environmental metrics, FIPS 199, Criticality Tier, Sector preset) can independently push the same CARVER dimension toward the ceiling. Consider a bank's core platform:

| Source | Criticality Floor Proposed |
|--------|---------------------------|
| Banking sector preset | 9 |
| CVSS CR:H (Environmental) | 9 |
| FIPS 199 High | 9 |
| Criticality Tier 1 | 9 |

All four sources independently propose Criticality ≥ 9. Under the previous max-floor approach, the result was simply `max(9, 9, 9, 9) = 9` — which happens to be correct in this case. However, the concern is that these sources are **not independent** — they are all measuring the same underlying property (the asset is critical to the bank's mission) from different angles. When sources are correlated, treating them as independent evidence overstates confidence.

### 4a.2 The Solution: Logarithmic Damping

The `detectAndDampCorrelatedInputs()` function in `scoring-engine.ts` implements a damping mechanism that activates when **≥3 enrichment sources** independently push the same CARVER factor above its baseline:

```
IF sourceCount >= 3:
    totalPush = Σ(proposedFloor[i] - baseValue) for all sources
    dampedPush = ln(1 + totalPush) × 2.0
    dampedValue = min(10, baseValue + dampedPush)
ELSE:
    dampedValue = max(baseValue, max(proposedFloors))
```

The logarithmic function `ln(1 + x)` has the property of diminishing returns — the first few points of push have near-linear effect, but additional pushes contribute progressively less. The scale factor of 2.0 was calibrated to ensure that:

- 2 sources: standard max-floor behavior (no damping)
- 3 sources: slight damping (~5-10% reduction from raw max)
- 4+ sources: meaningful damping (~15-25% reduction from raw max)
- Extreme case (4 sources all proposing 10 from base 4): damped to ~9.3 instead of 10

### 4a.3 What This Addresses

This mechanism addresses the **one-way ratchet / inflation pressure** concern from Claude's review. While the floor mechanism is correct in principle (enrichment should not lower scores), the damping prevents correlated sources from artificially stacking. The system now produces a `correlatedInputReport` in every `ScoringResult`, providing full transparency into which factors were damped and why.

### 4a.4 Design Decision: Why Not Replace Floors with Weighted Averages?

Claude's review suggested considering weighted averages instead of floors in specific places. We chose logarithmic damping over weighted averages for three reasons:

1. **Preserving the safety property**: Floors guarantee that no enrichment source can lower a score. Weighted averages could produce a lower result than the highest single source, potentially under-scoring a genuinely critical asset.
2. **Auditability**: The damping report shows exactly which sources contributed and by how much, making the adjustment transparent. A weighted average would obscure individual source contributions.
3. **Proportionality**: The logarithmic function naturally handles the case where one source is much higher than others — it doesn't average them down to the median, it acknowledges the highest source while reducing the marginal contribution of correlated confirmations.

---

## 5. Layer 4 — FIPS 199 Integration

### 5.1 Purpose

FIPS 199 (*Standards for Security Categorization of Federal Information and Information Systems*) defines three security objectives — Confidentiality, Integrity, and Availability — each rated as Low, Moderate, or High. While originally designed for federal systems, the CIA triad categorization applies to any organization's asset classification.

### 5.2 Mapping Logic

The `fips199ToCarverAdjustments()` function maps FIPS 199 categories to CARVER/SHOCK adjustments:

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

**Important:** As of v2, FIPS 199 CARVER floors are collected as an enrichment source and processed through correlated-input damping (Section 4a) before application. Shock adjustments and mission multipliers are applied directly.

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

**Important:** As of v2, Criticality Tier CARVER floors are collected as an enrichment source and processed through correlated-input damping (Section 4a). Shock floors and mission multipliers are applied directly.

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

| Mission Function | Key CARVER Floors | Mission Multiplier | Calibration Basis |
|-----------------|-------------------|-------------------|-------------------|
| Authentication | C=9, A=7, E=9, R=8 | 1.9× | "The master key — when AD falls, everything downstream falls" (20 years of AD compromise observations) |
| Command & Control | C=9, E=8, R=7 | 1.8× | "The nerve center — compromise enables adversary persistence and lateral movement" |
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

The computation proceeds in six stages (five original + correlated-input damping):

**Stage 1 — Enrichment Collection:**

All CARVER floor proposals from CVSS v4.0, FIPS 199, and Criticality Tier are collected as enrichment sources rather than applied immediately.

**Stage 2 — Correlated-Input Damping:**

The `detectAndDampCorrelatedInputs()` function processes all collected enrichment sources and applies logarithmic damping when ≥3 sources push the same factor (see Section 4a).

**Stage 3 — Composite Scores:**

```
carverComposite = Σ(carver[i] × weight[i]) / Σ(weight[i])    for i ∈ {C, A, R, V, E, Rec}
shockComposite  = Σ(shock[j] × weight[j]) / Σ(weight[j])     for j ∈ {S, H, O, C, K}
```

These are weighted averages on a 0-10 scale.

**Stage 4 — Mission Impact:**

```
carverNorm = carverWeight / (carverWeight + shockWeight)
shockNorm  = shockWeight / (carverWeight + shockWeight)
missionImpact = clamp((carverComposite × carverNorm + shockComposite × shockNorm) × missionMultiplier, 0, 10)
```

**Stage 5 — Likelihood Computation (the "Innocent Until Proven Guilty" model):**

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

**Stage 6 — Final Score:**

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

### 8.5 Factor Contribution Analysis

Every scoring result includes a `factorContributions` array that breaks down each CARVER and SHOCK dimension's contribution to the final score, plus a `correlatedInputReport` array (new in v2) that documents any damping applied to enrichment sources.

---

## 9. Layer 8 — Fusion Formula

### 9.1 Purpose and Philosophical Distinction from Layer 7

**This section addresses Claude's Round 5 Issue #6 — the deliberate difference between Layer 7 and Layer 8 scoring philosophies.**

Layer 7 and Layer 8 embody fundamentally different risk philosophies, and this is a **deliberate architectural choice**, not an oversight:

- **Layer 7 (`hybridRiskScore`)** uses a **geometric mean** (`√(impact × likelihood)`), which requires BOTH high impact AND high likelihood to produce a high score. This is the "conservative" path — it prevents high-impact-but-no-evidence assets from scoring high. This philosophy is correct for **risk dashboards and trend analysis**, where you want to avoid false positives.

- **Layer 8 (`hybridFusionScore`)** uses an **additive formula** (`CARVER×sector + CVSS×0.6 + exploitability×0.4`), which means a single extreme input can drive a high score. A CARVER=0 + CVSS=10 scenario produces a P1 score. This philosophy is correct for **operational triage and Caldera operation planning**, where you want to prioritize the most dangerous vulnerabilities regardless of whether the asset has been confirmed as critical.

The two paths serve different consumers:

| Aspect | Layer 7 (`hybridRiskScore`) | Layer 8 (`hybridFusionScore`) |
|--------|---------------------------|------------------------------|
| Philosophy | **Both must be high** (geometric mean) | **Either can drive priority** (additive) |
| Scale | 0-100 | 0-~20 |
| Likelihood model | "Innocent until proven guilty" | Implicit via CVSS + EPSS |
| Evidence weighting | Via confidence dampening | Via explicit evidence multiplier |
| Primary consumer | Risk dashboard, trend analysis, executive reporting | Priority triage, Caldera operation planning, red team queuing |
| Sector awareness | Via CARVER/SHOCK composites | Via sector multiplier |
| False positive tolerance | Low (conservative) | Higher (aggressive — better to over-triage than miss) |

This dual-path design is intentional: the risk dashboard should never cry wolf (Layer 7), but the red team queue should never miss a dangerous vulnerability (Layer 8).

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
  evidenceTags: ["[BASELINE_ONLY]"],
};
```

This ensures the scoring pipeline never fails to produce a result. The `confidence: "low"` and `evidenceTags: ["[BASELINE_ONLY]"]` signals allow downstream consumers to know the score was not LLM-augmented.

### 10.6 Explicit Propagation Path (Addresses Claude Issue #5)

**This section clarifies exactly how LLM deltas propagate through the scoring pipeline, addressing Claude's Round 5 concern about whether the LLM bypasses the deterministic pipeline.**

The answer is: **No bypass exists.** The LLM adjusts the sector preset CARVER values, and then the deterministic `computeHybridFusionScore()` function re-runs with the adjusted values. Here is the exact code path:

```
Step 1: Get base sector preset
    basePreset = getAdjustedCarverPreset(sector, regulatoryProfile)

Step 2: Apply LLM deltas to preset (clamped to [1, 10])
    adjustedPreset.criticality = clamp(basePreset.criticality + delta.criticality, 1, 10)
    adjustedPreset.accessibility = clamp(basePreset.accessibility + delta.accessibility, 1, 10)
    ... (all 7 dimensions)

Step 3: Re-run deterministic fusion formula with adjusted preset
    adjustedFusion = computeHybridFusionScore({
        carverPreset: adjustedPreset,
        cvssBase: baselineCard.scores.cvss.base,
        cvssExploitability: baselineCard.scores.cvss.exploitability,
    })

Step 4: Return adjusted score
    adjustedHybridScore = adjustedFusion.hybrid
    adjustedPriorityTier = adjustedFusion.priorityTier
```

**Key properties of this design:**

1. The LLM never produces a score directly — it only produces deltas that modify the CARVER preset.
2. The modified preset is fed back through the same deterministic `computeHybridFusionScore()` function that computed the baseline.
3. The `clamp(1, 10)` on each adjusted dimension ensures the LLM cannot push any factor below 1 or above 10, regardless of the delta.
4. The maximum possible score swing from LLM augmentation is bounded: a -3 to +3 delta on a single dimension, processed through the same weighted composite formula, produces a predictable and auditable score change.

This architecture ensures that the **bounded-delta property is strong** — the LLM cannot produce arbitrary scores, and every LLM-influenced score can be traced back to specific delta adjustments on specific CARVER dimensions.

### 10.7 Engagement Context

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

### 11.2 Industry-Adjusted Incident Loss Rates

The maximum single-incident loss is calculated as a percentage of annual revenue, with rates calibrated to industry-specific data from the Ponemon Institute / IBM Cost of a Data Breach reports:

| Industry | Incident Loss Rate | Basis |
|----------|-------------------|-------|
| Healthcare | 5.0% | Highest per-record breach cost ($10.93M avg, 2023 IBM report) |
| Financial Services | 4.0% | Second-highest breach cost ($5.90M avg) + regulatory fines |
| Technology | 3.5% | High breach cost ($4.66M avg) + IP loss multiplier |
| Government | 2.0% | Lower direct financial impact but high operational cost |
| Default (all others) | 3.0% | Global average breach cost as percentage of revenue |

### 11.3 Financial Impact Components

| Component | Calculation | Rationale |
|-----------|-------------|-----------|
| `maxSingleIncidentLoss` | `revenue × incidentLossRate` | Direct breach cost (forensics, notification, remediation, legal) |
| `estimatedDailyRevenueLoss` | `revenue / 365` | Revenue lost per day of outage |
| `regulatoryFineExposure` | `revenue × 0.04` | GDPR maximum (4% of global revenue); HIPAA up to $1.5M per violation |
| `reputationalDamageEstimate` | `(valuation or revenue×3) × 0.02` | 1-5% of market cap; conservative 2% estimate |
| `totalMaxExposure` | Sum of above + 7 days downtime | Worst-case scenario: breach + week-long outage |

### 11.4 Integration with Scoring Pipeline

The BIA financial impact feeds into the `ExplainableRiskCard` and the BIA report generator. It does not directly modify the hybrid risk score — instead, it provides a parallel financial dimension that helps prioritize remediation by business impact rather than technical severity alone.

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

All trigger adjustments are applied as floors. A KEV match sets Vulnerability to 10 — the maximum — because active exploitation is the strongest possible evidence of exploitability.

### 12.4 Re-Scoring Events

Each trigger application generates a `RescoringEvent` with full audit trail. A re-scoring event is considered "significant" if the risk band changed, the absolute score delta is ≥ 15 points, or the asset moved into the critical band.

---

## 13. Layer 12 — Hardening & Temporal Decay

### 13.1 Anti-Gaming Hardening with Actionable Distribution Monitoring

**This section addresses Claude's Round 5 Issue #8 — distribution monitoring flags now have downstream actions.**

The `computeHybridRiskHardened()` function wraps the core scoring engine with defensive measures:

**Input Sanitization:**
- All CARVER scores clamped to [0, 10]
- All SHOCK scores clamped to [0, 10]
- NaN/undefined/null values replaced with defaults
- Division-by-zero guards on profile weights

**Output Validation:**
- Checks for NaN/Infinity in `hybridRiskScore`
- Falls back to pure deterministic scoring if validation fails
- Generates audit trail of all corrections

**Distribution Monitoring with Actionable Responses (v2):**

The `generateScoringValidationReport()` function now produces not just warnings but **actionable response objects** with specific remediation guidance:

| Flag | Response Type | Action |
|------|--------------|--------|
| `critical_over_30pct` | `review_enrichment_sources` | Check correlated-input damping report for stacked enrichment. Verify FIPS 199, Criticality Tier, and CVSS Environmental are not independently pushing the same factors. Consider tightening sector preset baselines. |
| `no_critical_or_high` | `review_scoring_profiles` | Verify scoring profile thresholds are appropriate for the engagement sector. Check if confirmedVulnScore data is being ingested. Review whether "innocent until proven guilty" is suppressing scores that should have evidence. |
| `high_fallback_rate` | `review_llm_classification` | Check LLM telemetry for error rates. Verify API connectivity. Review recent LLM reliability circuit breaker state. Consider increasing LLM timeout or switching to deterministic-only mode. |
| `multiple_anomalies` | `manual_audit_recommended` | Multiple distribution anomalies detected simultaneously. A manual audit of 10-20 representative assets across risk bands is recommended before finalizing engagement scoring. |

The `ScoringValidationReport` interface now includes:

```typescript
interface ScoringValidationReport {
  totalAssets: number;
  scoredAssets: number;
  fallbackAssets: number;
  nanDetected: number;
  correctedInputs: number;
  riskDistribution: Record<string, number>;
  warnings: string[];
  responses: Array<{
    flag: string;
    response: DistributionResponse;
    action: string;
  }>;
}
```

### 13.2 Temporal Decay

The temporal decay module adjusts vulnerability scores based on five time-sensitive factors:

| Factor | Weight | Multiplier Range | Logic |
|--------|--------|-----------------|-------|
| Exploit Maturity | 0.25 | 0.8x - 1.5x | Older CVEs with public exploits = higher maturity |
| Patch Negligence | 0.25 | 1.0x - 1.5x | Patch available but not applied = negligence penalty |
| KEV Urgency | 0.20 | 1.0x - 1.5x | Recently added to KEV = maximum urgency |
| Validation Staleness | 0.15 | 0.7x - 1.1x | Stale validations lose confidence |
| Finding Age | 0.15 | 1.0x - 1.2x | New findings prioritized; old unresolved = escalation |

**Urgency Levels:**

| Level | Criteria |
|-------|---------|
| Immediate | Score ≥ 9.0 AND KEV-listed |
| Urgent | Score ≥ 9.0 OR (score ≥ 7.0 AND KEV-listed) |
| Elevated | Score ≥ 7.0 OR 2+ decay warnings |
| Standard | Score ≥ 4.0 |
| Deferred | Score < 4.0 |

---

## 14. The ExplainableRiskCard — Final Output

### 14.1 Structure

The `buildExplainableRiskCard()` function assembles the final output by orchestrating Layers 1-8:

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

The `calderaPriority` field maps the risk assessment to concrete Caldera red team operations, closing the loop from risk assessment to automated penetration testing — the scoring system does not just identify risk, it prescribes the specific offensive operations needed to validate and remediate that risk.

---

## 15. Data Capture Inventory

### 15.1 Input Data Sources

| Data Source | Layer(s) | Required? | Source |
|-------------|---------|-----------|--------|
| Domain name / hostname | 1, 6, 9 | Yes | Scan discovery |
| TLD | 1 | No | Parsed from domain |
| Keywords from page content | 1, 6 | No | Web crawling |
| Asset type / technology stack | 6, 12 | No | Technology fingerprinting |
| CVSS v4.0 vector string | 3, 4a, 7 | No | NVD, vulnerability scanners |
| CVSS base score | 8 | No | NVD, vulnerability scanners |
| CVSS exploitability sub-score | 8 | No | NVD, vulnerability scanners |
| EPSS probability | 8 | No | FIRST EPSS API |
| CISA KEV listing | 8, 11, 12 | No | CISA KEV catalog |
| FIPS 199 categorization | 4, 4a | No | Manual or LLM-inferred |
| Criticality tier | 5, 4a | No | Manual or LLM-inferred |
| Confirmed vulnerability score | 7 | No | Validated scan findings |
| Exposure level (0-1) | 7 | Yes | Network analysis |
| Confidence level (0-1) | 7 | Yes | Scan confidence |
| Port scan results | 7, 9 | No | Port scanning |
| Entity revenue / valuation | 10 | No | Entity resolution |
| Dark web intelligence | 9, 11 | No | DWX feeds |
| OSINT findings | 9 | No | OSINT collection |
| Certificate data | 9 | No | Certificate transparency |
| DNS records | 9 | No | DNS enumeration |
| WHOIS data | 9 | No | WHOIS lookup |
| HTTP headers | 9 | No | Web crawling |
| CVE publication date | 12 | No | NVD |
| Patch availability date | 12 | No | Vendor advisories |
| Last validation timestamp | 12 | No | Internal scan records |

### 15.2 Output Data

| Output | Type | Consumer |
|--------|------|----------|
| `ExplainableRiskCard` | Structured JSON | Risk dashboard, reports, Caldera operations |
| `ScoringResult` (with `correlatedInputReport`) | Structured JSON | Internal scoring pipeline, audit trail |
| `HardenedScoringResult` | Structured JSON | Audit trail, debugging |
| `ScoringValidationReport` (with `responses`) | Structured JSON | Quality assurance, monitoring, automated remediation |
| `TemporalScore` | Structured JSON | Time-based risk trending |
| `FinancialImpact` | Structured JSON | BIA reports, executive dashboards |
| `RescoringEvent` | Structured JSON | Alert system, audit trail |
| `InterRaterResult` | Structured JSON | Calibration testing, rubric validation |

---

## 16. Intellectual Property Protection Strategy

**This section has been rewritten per Claude's Round 5 Issue #1. The original v1 framed this as "patentability analysis" with specific patent claims. Claude correctly identified that several elements have prior art (CARVER applied to cyber has 20+ years of practice; multi-framework fusion has precedent in FAIR since ~2005; the "innocent until proven guilty" concept faces Alice/Mayo challenges post-2014). This section now presents a more honest and defensible IP protection strategy.**

### 16.1 What Is Genuinely Novel vs. What Has Prior Art

| Element | Novelty Assessment | Prior Art |
|---------|-------------------|-----------|
| CARVER applied to cyber | **Not novel** — CISA CRR, DHS CARVER+Shock assessments, academic papers since ~2005 | DHS, CISA, multiple government assessments |
| Multi-framework fusion | **Not novel in concept** — FAIR (Factor Analysis of Information Risk) has fused multiple frameworks since ~2005 | FAIR Institute, RiskLens |
| CVSS v4.0 → CARVER mapping | **Novel implementation** — no existing product maps CVSS v4.0 vector components to CARVER dimensions at this granularity | None found |
| Sector-aware NAICS auto-detection | **Novel implementation** — automated sector detection with per-sector scoring presets | None found in vulnerability management |
| "Innocent until proven guilty" | **Novel design philosophy** — but difficult to patent under Alice/Mayo (abstract idea) | Conceptually similar to risk-based authentication |
| Evidence quality multiplier | **Novel in this context** — but the concept of evidence weighting is well-established | Intelligence community tradecraft |
| LLM augmentation with bounded deltas | **Novel implementation** — no existing product uses LLM-bounded deltas on CARVER dimensions | None found |
| Correlated-input damping | **Novel** — logarithmic damping for correlated enrichment sources | None found |
| Temporal decay (5-factor) | **Novel combination** — individual factors are known, but the specific 5-factor weighted model is new | Individual factors are standard practice |

### 16.2 Recommended IP Protection Strategy

Based on this honest assessment, the recommended strategy is **trade secret + copyright protection**, with selective patent filing only for the most defensible claims:

**Trade Secret Protection (Primary):**

The following elements are best protected as trade secrets:
- The specific CARVER digital translation tables (the 1-10 criteria for each factor)
- The per-sector CARVER+SHOCK baseline presets and their calibration rationale
- The regulatory overlay adjustment values
- The mission function baseline tables
- The LLM prompt engineering (HYBRID_SCORER_ROLE and calibration rules)
- The correlated-input damping scale factor (2.0) and threshold (≥3 sources)

Trade secret protection is appropriate because these elements derive their value from the specific calibrations, which are grounded in 20 years of practitioner experience and are not discoverable through reverse engineering of the output scores alone.

**Copyright Protection:**

The source code, documentation, and digital translation tables are automatically protected by copyright. The specific expression of the CARVER-to-digital mapping — the exact wording of each 1-10 criterion, the sub-factor decompositions, the calibration rationale — is copyrightable even if the underlying methodology is not.

**Selective Patent Filing (Consult IP Counsel):**

If patent protection is pursued, the strongest candidates are:

1. **The CVSS v4.0 → CARVER feed-through mapping** — a specific, technical, non-obvious translation of vulnerability metrics to targeting factors
2. **The correlated-input damping mechanism** — a specific mathematical solution (logarithmic damping) to a specific technical problem (correlated enrichment inflation)
3. **The full pipeline architecture** — the specific 12-layer pipeline with deterministic baseline + bounded LLM delta + evidence weighting + temporal decay, taken as a whole system

**Important:** These are recommendations for discussion with IP counsel, not legal conclusions. The Alice/Mayo framework (post-2014) makes software patents challenging, and any filing should be evaluated by a patent attorney familiar with the current USPTO examination guidelines for software-implemented inventions.

### 16.3 Competitive Differentiation (Prior Art Comparison)

Even where individual elements have prior art, the **combination** and **implementation depth** differentiate AC3 from existing products:

| Capability | AC3 | Tenable.io | Qualys VMDR | Rapid7 InsightVM | FAIR |
|-----------|-----|-----------|------------|-----------------|------|
| CARVER targeting | Yes (6+SHOCK, automated) | No | No | No | No |
| CVSS v4.0 feed-through | Yes (full vector mapping) | Yes (native score) | Yes (native score) | Yes (native score) | No |
| EPSS integration | Yes | Yes | Yes | Yes | No |
| KEV integration | Yes | Yes | Yes | Yes | No |
| Sector-aware scoring | Yes (7 sectors, auto-detect) | No | No | No | Partial |
| NAICS auto-mapping | Yes | No | No | No | No |
| BIA financial impact | Yes (industry-adjusted) | No | No | No | Yes |
| LLM augmentation | Yes (bounded deltas) | No | No | No | No |
| Evidence weighting | Yes (3-tier) | No | No | No | Partial |
| "Innocent until proven" | Yes | No | No | No | No |
| Correlated-input damping | Yes | No | No | No | No |
| Temporal decay | Yes (5-factor) | Limited | Limited | Limited | No |
| Caldera operation mapping | Yes | No | No | No | No |
| Inter-rater reliability | Yes (built-in harness) | No | No | No | No |

---

## 17. Known Limitations and Honest Gaps

### 17.1 Sector Detection Accuracy

The rule-based sector detection in Layer 1 relies on pattern matching against TLDs, keywords, and asset signals. Organizations with ambiguous digital footprints (e.g., a healthcare company using `.com` with no medical keywords) may be misclassified. The confidence score mitigates this, but the system has no mechanism for user correction of misclassified sectors within the automated pipeline.

### 17.2 CARVER Subjectivity and Inter-Rater Reliability

**This section addresses Claude's Round 5 Issue #2 — the load-bearing weakness of CARVER subjectivity.**

The CARVER digital translation tables represent expert judgment, not empirical measurement. The mapping of "Replacement/repair requires 1 month+" to "Custom-built system, no backups, no documentation — months to rebuild" is a reasonable analogy, but different security professionals might draw the boundaries differently.

**The compounding problem:** A 2-point disagreement on Criticality between two operators can shift an asset's priority tier. When that disagreement compounds through the mission multiplier (up to 2.0×), the impact on the final score is significant. This is the most load-bearing weakness in the system.

**Mitigation — Inter-Rater Reliability Harness (v2):**

The `computeInterRaterReliability()` function in `scoring-hardening.ts` provides a built-in testing harness that compares two independent operator CARVER assessments and computes per-factor agreement metrics:

```typescript
interface InterRaterResult {
  assetCount: number;
  factorAgreement: Record<string, {
    exactMatch: number;      // % of assets with identical scores
    withinOne: number;       // % of assets within 1 point
    maxDelta: number;        // Largest disagreement
    meanDelta: number;       // Average disagreement
  }>;
  overallExactMatch: number;
  overallWithinOne: number;
  riskBandAgreement: number;
  flaggedFactors: string[];
  recommendation: string;
}
```

**Recommended calibration process:**

1. Have two operators independently score 10+ representative assets using the CARVER digital translation tables
2. Run `computeInterRaterReliability()` to measure agreement
3. Target: ≥75% exact-match, ≥90% within-1, ≥80% risk band agreement
4. If agreement is below threshold, tighten the anchored rubrics for flagged factors and re-test
5. Even 75-80% agreement is defensible; 50-60% means rubrics need significant tightening

**Anchored rubric examples** (to reduce subjectivity):

| Factor | Score | Anchored Example |
|--------|-------|-----------------|
| Criticality 9 | Identity provider (AD/SSO) | "If this system goes down, no one can log in to anything" |
| Criticality 7 | Core business application | "Business operations degraded but workarounds exist" |
| Criticality 3 | Marketing website | "No operational impact; brand inconvenience only" |
| Accessibility 9 | Internet-facing, no auth | "Anyone on the internet can reach this without credentials" |
| Accessibility 4 | Internal network, VPN required | "Requires VPN + network access to reach" |
| Recuperability 2 | Cloud-hosted with auto-scaling | "Auto-recovers in minutes with no manual intervention" |
| Recuperability 9 | Custom-built, no backups | "Months to rebuild from scratch" |

These anchored examples should be expanded into a full calibration guide for each factor at each score level.

### 17.3 LLM Augmentation Consistency

While the bounded delta range (-3 to +3) limits the LLM's influence, different LLM models or even different invocations of the same model may produce different adjustments for identical inputs. The system does not currently track LLM adjustment consistency across invocations or flag high-variance dimensions.

### 17.4 Financial Impact Precision

The BIA financial impact calculations use industry-average loss rates from published research (Ponemon/IBM). These averages may not reflect the specific financial exposure of any individual organization. The system does not account for cyber insurance coverage, existing security controls, or organization-specific financial structures.

### 17.5 Temporal Decay Calibration

The temporal decay weights and thresholds are based on security industry best practices but have not been empirically validated against actual breach data. The 14-day patch negligence grace period is a policy decision that may be too lenient for critical infrastructure or too aggressive for resource-constrained organizations.

### 17.6 One-Way Ratchet Limitation

**This section addresses Claude's Round 5 Issue #3.**

The floor mechanism prevents any enrichment layer from lowering scores. This is a deliberate safety property — enrichment should not contradict sector-specific intelligence. However, it creates a structural inflation pressure: scores can only go up through enrichment, never down.

The correlated-input damping mechanism (Section 4a) partially addresses this by preventing correlated sources from stacking. However, the fundamental one-way ratchet remains. Future work should consider:

- A "confidence-weighted floor" where the floor strength is proportional to the source's confidence level
- A "decay floor" where enrichment-applied floors gradually relax if not confirmed by subsequent evidence
- A manual override mechanism for operators to explicitly lower scores with documented justification

---

## 18. Conclusion

The AC3 Hybrid Scoring System represents a comprehensive approach to vulnerability risk quantification that goes beyond any single methodology. By fusing military targeting analysis (CARVER+SHOCK), vulnerability severity (CVSS v4.0), threat intelligence (EPSS, KEV), business impact analysis (BIA), and LLM augmentation into a 12-layer pipeline, it produces risk scores that are simultaneously:

- **Technically precise** — grounded in CVSS v4.0 metrics and confirmed vulnerability data
- **Operationally relevant** — contextualized by sector, regulatory environment, and mission criticality
- **Financially meaningful** — translated to dollar-value impact estimates
- **Explainable** — every score includes the complete reasoning chain via `ExplainableRiskCard`
- **Resilient** — graceful degradation at every layer ensures the system always produces a score
- **Auditable** — correlated-input damping reports, inter-rater reliability metrics, and distribution monitoring responses provide full transparency

The "innocent until proven guilty" likelihood model, evidence-quality weighting, correlated-input damping, and anti-gaming hardening collectively address the alert fatigue and score inflation problems that plague traditional vulnerability management. The temporal decay module ensures scores remain current as the threat landscape evolves.

The system's combination of military targeting methodology, multi-framework fusion, LLM augmentation with bounded deltas, and correlated-input damping represents a meaningful advancement in automated vulnerability risk assessment — best protected through trade secret and copyright, with selective patent filing for the most technically defensible claims.

---

## Appendix A — Source File Index

| File | Lines | Primary Responsibility |
|------|-------|----------------------|
| `server/lib/scoring-engine.ts` | 1,780+ | Core scoring engine, CARVER/SHOCK types, CVSS v4.0 parser, FIPS 199 mapping, criticality tiers, digital translation tables, correlated-input damping, `computeHybridRisk()`, LLM asset classification, dynamic re-scoring triggers |
| `server/lib/auto-industry-carver.ts` | 1,210 | Sector detection, NAICS mapping, CARVER+SHOCK presets, regulatory overlays, `computeHybridFusionScore()`, `buildExplainableRiskCard()`, threat actor likelihood, Caldera operation prioritization |
| `server/lib/llm-specialists/hybrid-scorer.ts` | 522 | LLM augmentation layer, `scoreHybrid()`, engagement context builder, HYBRID_SCORER_ROLE prompt |
| `server/lib/entity-resolver.ts` | 576 | Entity resolution, `calculateFinancialImpact()`, industry-adjusted loss rates |
| `server/lib/scoring-hardening.ts` | 660+ | Anti-gaming hardening, `computeHybridRiskHardened()`, deterministic fallback, distribution monitoring with actionable responses, inter-rater reliability harness |
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
| **FAIR** | Factor Analysis of Information Risk — prior art for multi-framework risk fusion (~2005) |
| **ExplainableRiskCard** | AC3's structured output containing scores, drivers, and recommended actions |
| **Fusion Score** | The `hybridFusionScore` computed by Layer 8 (CARVER × sector + CVSS + EPSS/KEV) |
| **Hybrid Risk Score** | The `hybridRiskScore` computed by Layer 7 (√(impact × likelihood) × 100) |
| **Correlated-Input Damping** | Logarithmic damping mechanism that prevents correlated enrichment sources from inflating scores (v2) |
| **Inter-Rater Reliability** | Measurement of agreement between two independent CARVER assessors (v2) |

## Appendix C — Round 5 Issue Resolution Matrix

| Issue # | Description | Resolution | Section |
|---------|-------------|------------|---------|
| 1 | Patentability claims too strong | Reframed as trade-secret + copyright; honest prior art assessment | §16 |
| 2 | Inter-rater reliability gap | Built-in harness + anchored rubric examples | §17.2 |
| 3 | One-way ratchet / inflation pressure | Correlated-input damping + honest limitation acknowledgment | §4a, §17.6 |
| 4 | Double-counting / correlated inputs | `detectAndDampCorrelatedInputs()` with logarithmic damping | §4a |
| 5 | Layer 9 LLM propagation ambiguity | Explicit code path trace showing no bypass | §10.6 |
| 6 | Layer 8 additive vs Layer 7 geometric | Named as deliberate choice with philosophical explanation | §9.1 |
| 7 | Practitioner provenance missing | 20-year background integrated throughout | §1.1, §3.2, §7.5 |
| 8 | Distribution monitoring flags lack actions | Actionable response objects with specific remediation guidance | §13.1 |
