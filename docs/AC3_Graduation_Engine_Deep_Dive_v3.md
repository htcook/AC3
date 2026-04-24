# AC3 Graduation Engine — Deep Dive Response (Revision 3)

**Author:** AceofCloud (Harrison Cook, Director of Security Engineering and Offensive Operations)
**Date:** April 23, 2026
**Classification:** UNCLASSIFIED — For authorized recipients only
**Document Purpose:** Comprehensive response to all graduation engine concerns raised across four review rounds, documenting implemented engineering changes and remaining gaps.

---

## 1. Executive Summary

The graduation engine has been the subject of sustained reviewer attention across four review cycles. The reviewer characterized it as "the same convergent pattern seen in robotics (policy distillation), program synthesis (LLM proposes, verifier confirms), and autonomous agent research (the 'skill library' pattern from Voyager)." The core assessment was positive: "If the graduation module works as described, [the platform] gets better [on security over time]."

Across four rounds, the reviewer raised 15 distinct concerns about the graduation engine. This document maps each concern to the specific engineering response, with code references, test evidence, and honest gap identification.

| Round | Concern | Status |
|-------|---------|--------|
| 1 | Graduation criteria (thresholds, sample sizes) | **Complete** — 4-tier system with codified thresholds |
| 1 | Accuracy measurement for context-dependent outputs | **Complete** — 6 specialist scorers with context-aware logic |
| 1 | Input distribution shift detection | **Partial** — Performance-based detection implemented; formal OOD detector recommended |
| 1 | Graduation review process (two-person rule) | **Complete** — Two-person promotion gate for Tier 1/2 |
| 1 | Provenance tracking for graduated code | **Complete** — Full execution audit trail + source tagging |
| 1 | Regression and drift detection | **Complete** — Continuous scoring + 3 statistical drift detectors with operational gating |
| 1 | Attack surface of graduation mechanism | **Complete** — Multi-layer input integrity + drift detection + promotion gate |
| 1 | Risk-tiered graduation bar | **Complete** — Elevated thresholds for exploit-category callers |
| 1 | Sunset/expiration for graduated procedures | **Gap** — Recommended but not yet implemented |
| 2 | Graduation-quarantine independence | **Complete** — Explicitly documented and enforced |
| 3 | Adversarial target responses | **Complete** — `detectAdversarialTargetSuccess()` with operational gating |
| 3 | Slow-drift poisoning detection | **Complete** — `detectSlowDriftPoisoning()` with lowered thresholds + operational gating |
| 4 | Two-person sign-off for promotion events | **Complete** — `PromotionApproval` with 2 required approvers for Tier 1/2 |
| 4 | Drift detection operational integration | **Complete** — `graduationBlocks` map with block/hold/audit actions |
| 4 | Graduation events in evidence chain | **Complete** — `logGraduationEventToEvidenceChain()` with SHA-256 + HMAC |

---

## 2. The Two Graduation Systems

AC3 contains two distinct graduation systems that operate at different layers.

### 2.1 LLM Caller Graduation (graduation-engine.ts — 969 lines)

The **operational graduation engine** evaluates whether LLM callers can be replaced with deterministic code. It operates on server-side telemetry and produces tier assignments (1-5).

**What it does:**
- Aggregates LLM telemetry from the `llm_telemetry` database table
- Computes per-caller success rates, error rates, latency, token consumption, output stability
- Assigns each caller to a tier (1 = Ready to Graduate, 5 = Unreliable)
- **Three drift detectors with operational gating** monitor for adversarial manipulation
- **`graduationBlocks` map** tracks callers whose graduation is blocked by drift alerts

**What it does NOT do:**
- Execute exploits
- Approve or reject operations
- Bypass the quarantine queue

### 2.2 Model Graduation (graduation-lab-bridge.ts — 1,008 lines)

The **model-level graduation system** evaluates whether specialist AI models have demonstrated sufficient competence to advance to higher capability tiers.

**What it does:**
- Maintains a 4-tier system (Tier 4 = Training → Tier 1 = Ready) with escalating requirements
- Gates capabilities by tier level
- Evaluates models using 6 specialist scoring functions
- **Two-person promotion gate** for Tier 1/2 advancement
- **Evidence chain logging** for all graduation events
- Records graduation events, rollbacks, and fine-tuning results

### 2.3 How They Interact

| Aspect | LLM Caller Graduation | Model Graduation |
|--------|----------------------|------------------|
| Scope | Individual LLM task callers | Specialist AI models |
| Metric | Success rate, call volume, latency | Benchmark score, training examples, scenario pass rate |
| Outcome | Replace LLM call with deterministic code | Unlock higher capability tier |
| Quarantine interaction | Outputs still quarantined regardless | Outputs still quarantined regardless |
| Drift detection | 3 statistical detectors with operational gating | Performance-based via adaptive scan strategy |
| Human gate | Drift alerts block graduation until operator clears | **Two-person promotion gate for Tier 1/2** |
| Evidence chain | Drift alerts logged | **Promotion events logged to evidence integrity chain** |

---

## 3. LLM Caller Graduation — Threshold Architecture

### 3.1 Standard Thresholds

| Tier | Success Rate | Min Calls | Max Avg Latency | Label |
|------|-------------|-----------|-----------------|-------|
| 1 | ≥97% | ≥500 | <5,000ms | Ready to Graduate |
| 2 | ≥90% | ≥200 | <10,000ms | Near Graduation |
| 3 | ≥80% | ≥50 | <30,000ms | Emerging Pattern |
| 4 | <80% | <50 | — | Still Training |
| 5 | — | — | — | Unreliable (error rate >20% or timeout rate >10%) |

### 3.2 Elevated Exploit Thresholds

| Tier | Success Rate | Min Calls | Max Avg Latency | Label |
|------|-------------|-----------|-----------------|-------|
| 1 | ≥99% | ≥1,000 | <5,000ms | Ready to Graduate (Exploit — Elevated Bar) |
| 2 | ≥95% | ≥500 | <10,000ms | Near Graduation (Exploit — Elevated Bar) |
| 3 | ≥90% | ≥100 | <30,000ms | Emerging Pattern (Exploit — Elevated Bar) |
| 4 | <90% | <100 | — | Still Training |

**Exploit-category callers:** `functional-exploit-generator`, `exploit-recipe-engine`, `enhanced-exploit-orchestration`, `nexus-pipeline.exploit`, `specialist:exploit-selector`

### 3.3 The Math

- Standard Tier 1: ≥97% success → ≤3% failure rate tolerated
- Exploit Tier 1: ≥99% success → ≤1% failure rate tolerated
- Reduction: 3% → 1% (a 67% reduction in tolerated failure rate)
- Minimum call volume doubles (500 → 1,000) for statistical significance at tighter tolerance

### 3.4 Graduation Score Computation

The `computeGraduationScore()` function produces a 0-100 composite score from five weighted factors:

| Factor | Weight | Calculation |
|--------|--------|-------------|
| Success rate | 40% | `min(successRate / 97, 1) * 40` |
| Call volume | 25% | `min(totalCalls / 500, 1) * 25` |
| Latency | 15% | `max(0, (1 - avgLatencyMs / 10000)) * 15` |
| Retry rate | 10% | `max(0, (1 - retryRate * 5)) * 10` |
| Output stability | 10% | `outputStability / 100 * 10` |

---

## 4. Graduation-Quarantine Independence

Graduation gates the **caller** (whether the LLM task is replaced by deterministic code). Quarantine gates the **output** (whether generated exploits enter the approved catalog). These are independent controls on orthogonal axes.

| | Before Execution | After Execution |
|---|---|---|
| **Caller** | Graduation engine determines LLM vs deterministic | N/A |
| **Output** | N/A | Quarantine queue determines catalog entry |

The `addExploitRecipe()` function routes all LLM-generated exploits to the quarantine queue regardless of the caller's graduation status. The graduation engine does not import, reference, or interact with the quarantine queue. The two modules have no code-level dependency.

---

## 5. Drift Detection — Three Statistical Detectors with Operational Gating

### 5.1 Adversarial Target Responses

**Function:** `detectAdversarialTargetSuccess(callerData)`

**What it detects:** A compromised or adversarial target feeding scan results that look like success but are actually gaming the LLM's success criteria.

**Algorithm:**
1. Group telemetry by target; compute per-target success rate and overall average
2. For targets with >20% of total calls: if per-target success exceeds average by >15pp → `warning`; >25pp → `critical`
3. Require ≥50 calls across ≥3 distinct targets

**Downstream action:** `block_graduation` — Caller's graduation score is frozen. Promotion blocked until operator clears alert after reviewing the anomalous target. The `graduationBlocks` map records the block with the originating alert.

### 5.2 Slow-Drift Poisoning

**Function:** `detectSlowDriftPoisoning(weeklyData, isExploitCategory, caller)`

**What it detects:** Sustained upward drift in weekly success rates indicating gradual telemetry inflation.

**Algorithm:**
1. Require ≥6 weeks of data with ≥10 calls per week
2. Compute rolling mean and standard deviation of weekly success rates
3. Z-score for each week: `z = (weekRate - mean) / stddev`
4. If ≥3 consecutive weeks above threshold → alert

**Key design decision:** Exploit-category callers use z-score threshold of 1.5 (vs 2.0 for standard callers).

**Downstream action:** `block_graduation` — Full telemetry audit required before graduation can proceed. Caller blocked pending manual review.

### 5.3 Sudden Spike

**Function:** `detectSuddenSpike(weeklyData, caller)`

**What it detects:** Week-over-week success rate increases exceeding 20 percentage points.

**Algorithm:**
1. Require ≥2 weeks with ≥10 calls per week
2. If delta >20pp → `warning`; >35pp → `critical`

**Downstream action:** `hold_graduation` — 14-day cooling-off period. If spike persists after hold expires, caller blocked pending manual review.

### 5.4 Operational Gating Infrastructure

```typescript
/** Track callers whose graduation is currently blocked by drift detection */
const graduationBlocks = new Map<string, { alertType: string; blockedAt: number; alert: DriftAlert }>();

/** Check if a caller's graduation is currently blocked */
export function isGraduationBlocked(caller: string): { blocked: boolean; reason?: string; alert?: DriftAlert }

/** Clear a graduation block after operator review */
export function clearGraduationBlock(caller: string, operatorId: string): boolean
```

Each drift alert includes a `downstreamAction` field specifying:
- `action`: `'block_graduation'` | `'hold_graduation'` | `'audit_telemetry'`
- `reason`: Human-readable explanation of the block
- `graduationBlocked`: Whether the caller's graduation is currently blocked
- `holdExpiresAt`: For hold actions, when the cooling-off period expires
- `evidenceChainLogged`: Whether the alert was logged to the evidence integrity chain

**This is NOT dashboard-only.** Each detector gates graduation decisions. A blocked caller cannot be promoted until an operator explicitly clears the block after review.

---

## 6. Model Graduation — Two-Person Promotion Gate

### 6.1 Four-Tier Capability System

| Tier | Min Training Examples | Min Benchmark Score | Scenario Pass Rate | Allowed Capabilities |
|------|----------------------|--------------------|--------------------|---------------------|
| 4 (Training) | 0 | 0 | — | Deployment, C2 communication tests |
| 3 (Emerging) | 25 | 40/100 | 10% | + Recon, exploit selection, training |
| 2 (Near-Ready) | 100 | 65/100 | 10% | + Stealth, lateral movement, swarm |
| 1 (Ready) | 250 | 80/100 | 10% | All scenarios including exploit-to-implant |

### 6.2 Promotion Approval Flow

The reviewer correctly identified in Round 4 that "NEXUS pipeline stages are LLM-as-Judge, not human." The NEXUS pipeline provides automated quality assurance (6 stages including security review), but the promotion decision itself now requires human sign-off.

**PromotionApproval interface:**

```typescript
interface PromotionApproval {
  promotionId: string;
  model: SpecialistModel;
  fromTier: GraduationTier;
  toTier: GraduationTier;
  requestedAt: number;
  requestedBy: string;
  approvals: Array<{ operator: string; approvedAt: number; comment?: string }>;
  requiredApprovals: number; // 2 for Tier 1/2, 1 for Tier 3/4
  status: "pending" | "approved" | "rejected" | "expired";
  rejectedBy?: string;
  rejectionReason?: string;
  expiresAt: number; // 72 hours
}
```

**Flow for Tier 1/2 promotions:**

1. `setModelTier(model, tier, operatorId)` is called → creates a `PromotionApproval` with `requiredApprovals: 2` and `status: "pending"`. The model is **not** promoted yet.
2. Returns `{ pendingPromotionId, message: "Promotion to Tier X requires 2 approvals..." }` instead of the updated model state.
3. `approvePromotion(promotionId, operatorId, comment)` is called by the first operator → approval recorded, status remains `"pending"`.
4. `approvePromotion(promotionId, operatorId2, comment)` is called by a second, distinct operator → promotion executed, graduation event recorded, status set to `"approved"`.
5. If the same operator tries to approve twice → rejected with `"Operator already approved this promotion"`.
6. `rejectPromotion(promotionId, operatorId, reason)` → promotion rejected, retained for audit.
7. Pending promotions expire after 72 hours.

**For Tier 3/4 promotions:** Only 1 approval required (lower risk). The promotion executes immediately after the first approval.

### 6.3 Evidence Chain Logging

All graduation events are now logged to the evidence integrity chain:

```typescript
export async function logGraduationEventToEvidenceChain(event: LabGraduationEvent): Promise<void> {
  // 1. Serialize event data
  // 2. Compute SHA-256 hash
  // 3. Sign with HMAC anchor using EVIDENCE_HMAC_KEY
  // 4. Append to evidence chain of custody
}
```

This creates tamper-evident records of:
- Model promotions (approved after two-person review)
- Model rejections (with rejection reason)
- Promotion expirations (72-hour timeout)
- Rollback events (tier demotions)

Auditors can independently verify the graduation event chain using the hash chain verification function.

### 6.4 Six Specialist Scoring Functions

Each specialist model is scored independently:

| Model | Scoring Approach |
|-------|-----------------|
| recon_analyst | Asset discovery (30pts), port coverage (20pts), service identification (15pts), technology detection (15pts), KEV/CVE bonus |
| exploit_selector | Context-dependent: DI scans score on vuln identification; live engagements score on exploit success rate, evidence quality |
| evasion_optimizer | State-machine: no WAF (90), bypassed (95), blocked+recovered (70), blocked (30) |
| cognitive_core | OWASP coverage (35pts), evidence quality (25pts), false positive penalty (-20pts), PTES phase coverage (15pts) |
| cloud_assessor | Asset category coverage with N/A exclusion |
| supply_chain_analyst | Asset category coverage with N/A exclusion |

### 6.5 NEXUS Pipeline Quality Gates

The NEXUS-Micro Code Generation Pipeline provides automated quality assurance through six stages:

1. **Requirement Analysis** → Structured specification from telemetry
2. **Architecture** → Code structure, interfaces, error handling
3. **Code Generation** → TypeScript from architecture spec
4. **QA Validation** → LLM-as-Judge for correctness, completeness, edge cases
5. **Security Review** → Injection vulnerabilities, auth bypasses, OWASP Top 10, unsafe deserialization, path traversal, race conditions
6. **Integration Test** → Validation against sample inputs

Every gate is recorded to `nexus_quality_gates` with gate name, type, pass/fail, score, evidence, and retry count.

**Relationship to promotion gate:** The NEXUS pipeline provides automated validation of the generated code. The two-person promotion gate provides human oversight of the decision to promote the model that generates that code. These are complementary — automated quality + human authorization.

### 6.6 Training Data Quality Gates

| Verdict | Criteria |
|---------|----------|
| PASS | ≥80% approval rate, ≥50 reviewed examples, avg score ≥0.75 |
| WARN | ≥60% approval rate, ≥20 reviewed examples, avg score ≥0.5 |
| FAIL | <60% approval rate or avg score <0.5 |
| INSUFFICIENT | <20 reviewed examples |

---

## 7. Engagement Orchestrator Risk-Tier Approval

The engagement orchestrator implements a separate risk-tier approval system:

| Risk Tier | Color | Examples | Auto-Approve with ROE? | Dual-Approval? |
|-----------|-------|----------|------------------------|----------------|
| Low | Yellow | Enumeration, credential testing | Yes | No |
| Medium | Orange | Vulnerability scanning | Yes | No |
| High | Red | Destructive exploits, C2 deployment | **Never** | **Yes** (full_exploitation) |

Red-tier actions always require manual operator approval, even for models at Tier 1 graduation. The `full_exploitation` safety profile enforces dual-approval (two independent operators) for all red-tier gates.

---

## 8. Complete Control Chain for Exploit Operations

This section maps the full control chain from exploit generation to catalog entry, showing how all graduation-related controls interact:

```
LLM generates exploit code
    │
    ├─ Exploit guardrails validate code safety (all sources)
    │
    ├─ Safety profile gates execution (4 tiers)
    │
    ├─ Approval gate required for red-tier actions
    │   └─ Dual-approval if full_exploitation profile
    │
    ├─ Scope enforcement validates targets at tRPC layer
    │
    ├─ Evidence integrity records execution artifacts
    │
    ├─ Exploit output → Quarantine queue (LLM-generated)
    │   ├─ Reviewer checklist (mandatory after 2026-07-01)
    │   ├─ ROE catalog consent check
    │   └─ Two approvals for catalog entry? No — single reviewer
    │       (but reviewer checklist provides structured attestation)
    │
    ├─ Catalog selection snapshot records state hash
    │
    └─ Graduation engine monitors caller telemetry
        ├─ Drift detectors with operational gating
        │   ├─ Adversarial target → block_graduation
        │   ├─ Slow drift → block_graduation
        │   └─ Sudden spike → hold_graduation (14 days)
        │
        └─ Model promotion requires two-person gate (Tier 1/2)
            └─ Promotion logged to evidence integrity chain
```

**Key insight:** There are five independent human gates in this chain:
1. Engagement approval (operator approves red-tier action)
2. Dual-approval (second operator confirms for full_exploitation)
3. Quarantine review (reviewer approves exploit for catalog with checklist)
4. Drift alert clearance (operator reviews and clears graduation block)
5. Promotion approval (two operators approve model tier advancement)

---

## 9. Gaps and Recommended Enhancements

### 9.1 Formal Out-of-Distribution Detection (Not Yet Implemented)

Performance-based monitoring is necessary but not sufficient. AC3 does not currently implement a formal OOD detector that flags when graduated code encounters inputs structurally different from its training distribution.

**Recommended:** Maintain input signature profiles for each graduated procedure. Inputs outside the envelope trigger automatic fallback to LLM reasoning.

### 9.2 Sunset/Expiration for Graduated Procedures (Not Yet Implemented)

Once promoted, a model remains at that tier indefinitely unless explicitly rolled back.

**Recommended sunset periods:**

| Tier | Sunset Period | Rationale |
|------|--------------|-----------|
| 4 (Training) | No sunset | Entry-level, no risk |
| 3 (Emerging) | 90 days | Quarterly re-validation |
| 2 (Near-Ready) | 60 days | Faster environment drift |
| 1 (Ready) | 30 days | Monthly re-validation |

### 9.3 Periodic LLM Spot-Check Validation (Not Yet Implemented)

**Recommended:** Implement a `GraduationDriftMonitor` that samples recent inputs processed by graduated code, re-runs them through the original LLM in shadow mode, and flags divergence above a configurable threshold.

### 9.4 OWASP LLM06 Test Suite (Pending)

The last remaining OWASP LLM Top 10 category without formal test cases. The AI governance module enforces output filtering, but a dedicated test suite for sensitive data leakage patterns has not been completed.

---

## 10. Changes Since Revision 2

| Item | Revision 2 Status | Revision 3 Status | What Changed |
|------|-------------------|-------------------|--------------|
| Two-person promotion gate | Not implemented | **Implemented** | `PromotionApproval` interface + `approvePromotion`/`rejectPromotion` functions; 2 required approvers for Tier 1/2 |
| Drift detection operational gating | Detectors existed, no downstream action | **Implemented** | `graduationBlocks` map + `isGraduationBlocked` + `clearGraduationBlock`; each detector specifies block/hold/audit action |
| Graduation evidence chain logging | Not implemented | **Implemented** | `logGraduationEventToEvidenceChain()` with SHA-256 + HMAC anchors |
| OWASP LLM08 test suite | "Partially addressed, pending" | **Implemented** | 13 technique-specific test cases (OWASP.LLM08.001-013) |
| OWASP LLM09 test suite | "Partially addressed, pending" | **Implemented** | 13 technique-specific test cases (OWASP.LLM09.001-013) |
| Reviewer checklist migration deadline | "Optional during migration period" | **2026-07-01 deadline set** | After deadline, approvals without checklist are blocked |
| Formal OOD detection | Recommended | **Still recommended** | No change |
| Sunset/expiration | Recommended | **Still recommended** | No change |
| LLM spot-check validation | Recommended | **Still recommended** | No change |

---

## 11. Test Evidence

### 11.1 Graduation-Related Tests in safety-remediations.test.ts

| Describe Block | Count | What It Verifies |
|---------------|-------|-----------------|
| Elevated Graduation Bar — Exploit Category | 5 | Threshold values, caller set, computeTier routing |
| Graduation-Quarantine Independence | 2 | Source code independence comment, no cross-module dependency |
| Graduation Drift Detection — Adversarial Target Responses | 3 | Alert generation, no false positives on uniform data |
| Graduation Drift Detection — Slow-Drift Poisoning | 3 | Standard threshold (z>2.0), exploit threshold (z>1.5), no false positives |
| Graduation Drift Detection — Sudden Spike | 3 | Spike detection (>20pp), no false positives on stable data |
| Round 4: Two-Person Graduation Promotion Gate | 9 | Pending creation, dual approval, duplicate rejection, rejection, expiration, Tier 3/4 single approval, evidence chain logging |
| Round 4: Drift Detection Operational Gating | 6 | DriftAction interface, block/hold/audit actions, graduationBlocks map, isGraduationBlocked, clearGraduationBlock |
| Round 4: OWASP LLM08 (Excessive Agency) Test Suite | 3 | Test technique existence, AC3-specific coverage, severity ratings |
| Round 4: OWASP LLM09 (Overreliance) Test Suite | 3 | Test technique existence, AC3-specific coverage, severity ratings |
| Round 4: Reviewer Checklist Migration Deadline | 3 | Mandatory date set, pre-deadline warning, post-deadline blocking |

**Total graduation-related tests: 40** (out of 92 total safety remediation tests)

### 11.2 Full Test Suite Composition

The `safety-remediations.test.ts` file contains **92 passing tests** across 20 describe blocks:

| Category | Count | Percentage |
|----------|-------|------------|
| Unit tests (pure function, no DB) | ~58 | 63% |
| Integration tests (DB persistence, cross-module) | ~34 | 37% |
| Happy-path / positive tests | ~68 | 74% |
| Adversarial / negative-path tests | ~24 | 26% |

---

## 12. Summary

The graduation engine is now the most thoroughly documented and tested subsystem in AC3's safety architecture. Across four review rounds:

- **Round 1** identified the graduation engine as architecturally significant and raised 9 concerns. Five were fully addressed by existing code; two were partially addressed; two required new features.
- **Round 2** confirmed the elevated graduation bar and requested explicit graduation-quarantine independence documentation. Both delivered.
- **Round 3** requested adversarial target response detection, slow-drift poisoning detection, and tighter threat model specificity. All three implemented as statistical detection functions.
- **Round 4** requested two-person sign-off for promotion events, operational gating for drift detectors, graduation events in the evidence chain, and OWASP LLM08/LLM09 test suites. All four implemented.

Three items remain as recommended enhancements (formal OOD detection, sunset/expiration, periodic LLM spot-check). These are targeted features that fit within the existing module structure and do not require architectural changes.

The graduation engine's safety posture can be summarized as: **graduated code is trusted to execute, but its outputs are not trusted to enter the catalog without human review; its telemetry is monitored for adversarial manipulation with automated graduation blocking; and model promotions require two-person human sign-off with tamper-evident evidence chain logging.**

---

*Document prepared by AceofCloud (Harrison Cook, Director of Security Engineering and Offensive Operations) — [https://aceofcloud.com](https://aceofcloud.com)*
