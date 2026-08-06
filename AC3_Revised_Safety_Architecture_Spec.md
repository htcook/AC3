# AC3 Safety Architecture Specification — Revised

**Author:** Harrison Cook, AceofCloud
**Date:** April 23, 2026
**Revision:** 2.0 — Post-Review Remediation
**Classification:** UNCLASSIFIED — For authorized recipients only
**Audience:** External AI safety reviewer (Claude), Cyber AB assessors, customer CISOs, third-party red teams

---

## 1. Purpose and Scope

This document is the revised AC3 safety architecture specification, produced in direct response to the substantive architectural questions raised during an independent AI safety review conducted by Anthropic's Claude. The reviewer identified real design considerations that any qualified assessor — whether a Cyber AB reviewer, customer CISO, or adversarial red team — would raise. This document provides evidence-based responses grounded in the AC3 codebase, with gaps clearly identified as pre-review prerequisites.

This revision incorporates three engineering changes implemented since the initial review:

1. **Dual-approval enforcement** for the `full_exploitation` safety tier (two-person rule)
2. **Exploit quarantine queue** for LLM-generated exploits entering the knowledge store
3. **Elevated graduation bar** for exploit-category LLM callers

The document is structured for three simultaneous audiences: the C3PAO assessor checking NIST 800-53 control mappings, the customer CISO asking "what happens if your AI generates an exploit that damages my production system?", and the adversary looking for the weakest link in the safety chain.

---

## 2. Platform Overview

AC3 (AceofCloud Cyber Command) is an AI-driven offensive security platform that orchestrates penetration testing engagements using a combination of traditional security tools (Nmap, Nuclei, ZAP, Burp Suite, Metasploit, Caldera) and LLM-powered decision-making. The platform automates the full red team lifecycle — reconnaissance, vulnerability discovery, exploitation, post-exploitation, and reporting — while maintaining human-in-the-loop controls at every risk-escalation boundary.

The platform comprises approximately 536,000 lines of TypeScript across 650 server-side modules, with 287 vitest test files providing automated coverage. The engagement orchestrator alone spans 14,460 lines, implementing a multi-phase pipeline with approval gates, safety engine integration, scope enforcement, and forensic-grade evidence chains.

---

## 3. Safety Architecture — Defense in Depth

AC3's safety architecture implements defense in depth through 12 dedicated safety modules. Each module operates independently and can block operations at its layer without relying on downstream controls. The authorization chain flows through seven sequential gates before any operation executes.

### 3.1 Authorization Chain

Every operation passes through the following chain, where each layer can independently block execution:

> **User Role** → **Engagement Access Guard** → **ROE Validation** → **Risk Tier Check** → **Safety Engine Assessment** → **Scope Enforcement** → **Execution**

### 3.2 Core Safety Modules

| Module | Source File | Purpose |
|--------|------------|---------|
| Safety Engine | `safety-engine.ts` | Four-tier safety profiles with blast-radius estimation, tool category restrictions, and per-profile approval requirements |
| Scope Guard | `scope-guard.ts` | CIDR, domain, URL, and IP scope validation against engagement Rules of Engagement |
| Scope Enforcement Middleware | `scope-enforcement-middleware.ts` | tRPC transport-layer interception of all mutations containing target parameters; validates scope at execution time, not approval time |
| ROE Guard | `roe-guard.ts` | Rules of Engagement validation — all Orange/Red tier operations require valid, non-expired, signed ROE |
| Evidence Integrity | `evidence-integrity.ts` | SHA-256 hash chains with HMAC anchors for forensic-grade evidence provenance |
| AI Security Validation | `ai-security-validation.ts` | MITRE ATLAS technique testing for adversarial ML attack resistance |
| AI Governance | `ai-governance.ts` | LLM usage policy enforcement, telemetry collection, and compliance reporting |
| FIPS Crypto Service | `fips-crypto.ts` | FIPS 140-3 approved algorithm enforcement (AES-256-GCM, SHA-256/384/512, ECDSA P-256/P-384) |
| Engagement Access Guard | `engagement-access-guard.ts` | Row-level security ensuring non-admin users access only their own engagements |
| Exploit Guardrails | `exploit-guardrails.ts` | Pre-execution validation of LLM-generated exploit code against safety constraints |
| Training ROE Guard | `training-roe-guard.ts` | Separate ROE enforcement for training targets, preventing violation of target terms of use |
| Prompt Injection Shield | `prompt-injection-shield.ts` | Five-layer defense against prompt injection via scan output, advisories, and threat intel feeds |

### 3.3 Safety Profiles

AC3 implements four safety levels, each with progressively broader capabilities and stricter approval requirements. The `full_exploitation` tier now enforces dual-approval (two-person rule) for all red-tier operations.

| Safety Level | Credential Testing | Exploitation | C2 Deployment | Lateral Movement | Phase Approval | Dual Approval |
|-------------|-------------------|-------------|---------------|-----------------|----------------|---------------|
| `passive_only` | No | No | No | No | No | No |
| `low_impact` | No | No | No | No | No | No |
| `standard` | Yes | Yes | No | No | Yes | No |
| `full_exploitation` | Yes | Yes | Yes | Yes | Yes | **Yes** |

---

## 4. Remediation 1: Dual-Approval Enforcement (Two-Person Rule)

### 4.1 Problem Statement

The initial review identified that the `full_exploitation` safety profile required only a single operator approval for high-risk actions. For a platform executing real exploits against live production systems for CMMC-regulated customers, the two-person rule is a standard control expectation.

### 4.2 Implementation

The dual-approval enforcement is implemented across three files:

**Safety Engine (`safety-engine.ts`):** The `full_exploitation` profile now includes `dualApprovalRequired: true`. All other profiles remain at `dualApprovalRequired: false`.

**Engagement Orchestrator (`engagement-orchestrator.ts`):** The `requestApproval()` function checks the active safety profile's `dualApprovalRequired` flag. When true and the gate's risk tier is `red`, the approval gate is created with `requiredApprovals: 2` instead of the default `1`. The `ApprovalGate` interface has been extended with three new fields:

```typescript
interface ApprovalGate {
  // ... existing fields ...
  dualApprovalRequired?: boolean;
  approvers?: string[];
  requiredApprovals?: number;
}
```

**Resolve Approval (`resolveApproval()`):** The function now returns `boolean | 'partial'`. When a dual-approval gate receives its first approval, the function records the approver, logs the partial approval, broadcasts a progress update, and returns `'partial'`. The gate remains open until a second, distinct operator approves. Key enforcement rules:

- **Any single operator can deny** — denial always resolves the gate immediately
- **Duplicate approvers are rejected** — the same operator cannot approve the same gate twice, with a warning logged to the audit trail
- **Both approvers are recorded** — the `resolvedBy` field contains both operator names (comma-separated) for audit purposes

**Router (`engagement-ops-core.ts`):** The `resolveApproval` mutation now handles the `'partial'` return value, logging a `ops_dual_approval_partial` activity entry and returning `{ resolved: false, partial: true }` to the frontend so the UI can display the waiting-for-second-approver state.

### 4.3 Audit Trail

Every dual-approval interaction generates log entries:

| Event | Log Type | Detail |
|-------|----------|--------|
| Gate created | `approval_request` | "Dual Approval Required (0/2): {title}" |
| First approver | `approval_response` | "Partial Approval (1/2): {title} — Operator '{name}' approved" |
| Duplicate rejected | `warning` | "Duplicate Approver Rejected: {title}" |
| Second approver | `approval_response` | "Dual Approval Complete (2/2): {title} — All 2 independent approvers confirmed" |

### 4.4 Test Coverage

The `safety-remediations.test.ts` file includes 26 passing tests covering the dual-approval interface, the safety profile `dualApprovalRequired` field across all four safety levels, the `ApprovalGate` interface extensions, and the `resolveApproval` return type.

---

## 5. Remediation 2: Exploit Quarantine Queue

### 5.1 Problem Statement

The reviewer identified that LLM-generated exploits were auto-indexed into the knowledge store's searchable catalog upon successful execution, with no human review gate. This meant unreviewed AI-generated exploit code could be served to the RAG pipeline in subsequent engagements.

> "At what point does a generated exploit enter the reusable catalog versus being regenerated each engagement, and who reviews it when it enters?"

### 5.2 Exploit Lifecycle — Two Distinct Paths

The exploit knowledge store indexes exploits from two fundamentally different sources:

**Path 1: Framework-Sourced Exploits (Durable Catalog)**

These are externally maintained, publicly available exploit databases loaded at startup:

| Source | Count | Review Status |
|--------|-------|---------------|
| ExploitDB archive | ~46,993 | Community-reviewed, publicly available |
| Metasploit modules | ~3,976 | Rapid7-maintained, quality-controlled |
| GitHub PoC repositories | ~20,000+ | Community-published, source-attributed |

These enter the knowledge store directly — they are reference material for the RAG pattern, not raw execution payloads. The LLM uses them as grounding context to adapt working PoCs to the current engagement.

**Path 2: LLM-Generated Exploits (Quarantined)**

When the exploit generation pipeline (functional-exploit-generator, exploit-recipe-engine, or enhanced-exploit-orchestration) successfully generates and executes an exploit, the result is now routed to the **quarantine queue** rather than the main catalog.

### 5.3 Implementation

The `addExploitRecipe()` function in `exploit-knowledge-store.ts` has been redesigned:

**Default behavior:** All LLM-generated exploits are quarantined. The function creates a `QuarantinedExploit` entry with status `pending_review` and returns `{ quarantined: true, quarantineId: string }`.

**Bypass mechanism:** Exploits can skip quarantine when `bypassQuarantine: true` is explicitly set. This is reserved for human-authored imports or externally verified exploits.

**Quarantine entry structure:**

```typescript
interface QuarantinedExploit {
  id: string;
  exploit: ExploitDocument;
  submittedBy: string;
  sourcePipeline: string;  // e.g., 'nexus-pipeline', 'exploit-recipe-engine'
  status: 'pending_review' | 'approved' | 'rejected';
  quarantinedAt: number;
  reviewedAt?: number;
  reviewedBy?: string;
  reviewNotes?: string;
  metadata: {
    cveId?: string;
    engagementId?: string;
    success: boolean;
    language: string;
    service?: string;
    platform?: string;
  };
}
```

**Management functions:**

| Function | Purpose |
|----------|---------|
| `getQuarantineQueue(statusFilter?)` | List quarantined exploits, optionally filtered by status |
| `approveQuarantinedExploit(id, reviewer, notes?)` | Move exploit from quarantine to main catalog with `human-reviewed` tag |
| `rejectQuarantinedExploit(id, reviewer, notes?)` | Mark exploit as rejected; it remains in the queue for audit but is never indexed |
| `getQuarantineStats()` | Return counts: total, pending_review, approved, rejected |
| `clearQuarantineQueue()` | Clear the queue (testing/memory pressure) |

**Key safety properties:**

- Quarantined exploits are **never searchable** via the RAG pipeline until explicitly approved by a human reviewer
- Approved exploits receive the `human-reviewed` tag, distinguishing them from auto-indexed framework-sourced exploits
- Rejected exploits remain in the queue for audit trail purposes but are never indexed
- The queue is pruned when it exceeds 500 entries (oldest rejected entries are removed first)
- Each quarantine entry records the source pipeline, enabling traceability from exploit to the LLM caller that generated it

### 5.4 Revised Exploit Lifecycle Table

| Aspect | Framework-Sourced | LLM-Generated (Post-Remediation) |
|--------|-------------------|----------------------------------|
| Source | ExploitDB, Metasploit, GitHub PoC | LLM synthesis during engagement |
| Review before catalog entry | External community review | **Human review via quarantine queue** |
| Reliability score | Varies by source | 90 (after human approval) |
| Human review required? | No (community-vetted) | **Yes — mandatory quarantine** |
| Provenance tracking | Source URL, author, date | Engagement ID, CVE, service, pipeline, reviewer |
| Searchable via RAG? | Immediately | **Only after human approval** |

### 5.5 Test Coverage

The test suite includes 12 tests for the quarantine queue: routing to quarantine by default, bypass mechanism, failed exploit rejection, queue listing and filtering, approval flow (moves to catalog), rejection flow (stays out of catalog), double-approval prevention, double-rejection prevention, statistics, queue clearing, and metadata integrity.

---

## 6. Remediation 3: Elevated Graduation Bar for Exploit-Category Callers

### 6.1 Problem Statement

The graduation engine evaluates LLM callers for replacement with deterministic code based on success rate, call volume, and latency thresholds. The reviewer noted that exploit-generating callers operate in a higher-risk domain where false positives (bad exploit code) can cause real damage, and should therefore face a higher graduation bar.

### 6.2 Implementation

The `graduation-engine.ts` router now maintains two threshold tables:

**Standard Graduation Thresholds (unchanged):**

| Tier | Success Rate | Min Calls | Max Avg Latency | Label |
|------|-------------|-----------|-----------------|-------|
| 1 (Ready) | ≥97% | ≥500 | <5s | Ready to Graduate |
| 2 (Near) | ≥90% | ≥200 | <10s | Near Graduation |
| 3 (Emerging) | ≥80% | ≥50 | <30s | Emerging Pattern |
| 4 (Training) | <80% | <50 | — | Still Training |

**Elevated Exploit Graduation Thresholds (new):**

| Tier | Success Rate | Min Calls | Max Avg Latency | Label |
|------|-------------|-----------|-----------------|-------|
| 1 (Ready) | ≥99% | ≥1,000 | <5s | Ready to Graduate (Exploit — Elevated Bar) |
| 2 (Near) | ≥95% | ≥500 | <10s | Near Graduation (Exploit — Elevated Bar) |
| 3 (Emerging) | ≥90% | ≥100 | <30s | Emerging Pattern (Exploit — Elevated Bar) |
| 4 (Training) | <90% | <100 | — | Still Training |

**Callers subject to elevated thresholds:**

- `functional-exploit-generator`
- `exploit-recipe-engine`
- `enhanced-exploit-orchestration`
- `nexus-pipeline.exploit`
- `specialist:exploit-selector`

The `computeTier()` function now selects the appropriate threshold table based on whether the caller is in the `EXPLOIT_CATEGORY_CALLERS` set.

### 6.3 Rationale

The elevated bar means an exploit-generating LLM caller must demonstrate:

- **2x the call volume** (1,000 vs 500 for Tier 1) to ensure statistical significance
- **2% higher success rate** (99% vs 97% for Tier 1) because a 3% failure rate in exploit generation is unacceptable
- **Proportionally higher bars at every tier** to prevent premature graduation

This ensures that exploit-category callers remain under LLM control (with human oversight via the quarantine queue) until they have demonstrated extraordinary reliability.

### 6.4 Test Coverage

The test suite verifies that the standard thresholds are unchanged, the elevated thresholds have the correct values, the `EXPLOIT_CATEGORY_CALLERS` set includes all expected callers, and the `computeTier()` function routes to the correct threshold table.

---

## 7. Framework Alignment

The following table describes AC3's relationship to relevant security frameworks. Language has been revised per the reviewer's guidance to distinguish between "architected consistently with" (design intent with code evidence) and "compliant with" (formal assessment completed).

| Framework | Relationship | Evidence |
|-----------|-------------|---------|
| NIST 800-53 Rev 5 | Implements controls for AC, AU, CA, CM, IA, IR, RA, SA, SC, SI families | Per-control mapping available; formal assessment pending |
| NIST AI RMF (AI 100-1) | Architected consistently with GOVERN, MAP, MEASURE, MANAGE functions | AI governance module, telemetry, graduation engine |
| ISO/IEC 42001:2023 | Architected consistently with requirements for AI management systems | AI governance, safety profiles, evidence integrity |
| OWASP Top 10 for LLM Applications | Implements controls addressing all 10 risk categories | Per-category test evidence available for 7 of 10; 3 pending formal validation |
| MITRE ATLAS | Automated testing against adversarial ML techniques | `ai-security-validation.ts` with technique-specific test cases |
| EU AI Act (Articles 9-15) | Architecture supports requirements for high-risk AI systems | Formal conformity assessment not yet conducted |
| CMMC Level 2+ | Designed for DoD-adjacent customer environments | CMMC controls mapped in `cmmc-controls.ts`; C3PAO assessment pending |

### 7.1 FIPS Cryptographic Compliance

AC3 implements FIPS 140-3 approved cryptographic algorithms exclusively (AES-256-GCM, SHA-256/384/512, ECDSA P-256/P-384) and prohibits non-approved algorithms at the application layer. CMVP validation is inherited from the deployment infrastructure — AWS GovCloud provides CMVP-validated OpenSSL FIPS modules (Certificate #4282). AC3's `FIPSCryptoService` enforces algorithm restrictions and generates compliance reports for audit.

---

## 8. Adversarial Threat Model for the AI Safety Architecture

This section addresses the adversarial perspective — what happens when the safety architecture itself is attacked.

### 8.1 Threat: Prompt Injection via Scan Output

**Attack vector:** A compromised target returns crafted responses (HTTP headers, DNS records, banner text) containing instructions designed to manipulate the LLM orchestrator into executing out-of-scope actions.

**Mitigations:**
- The Prompt Injection Shield (`prompt-injection-shield.ts`) implements five-layer defense: input sanitization, structural analysis, semantic analysis, output validation, and behavioral monitoring
- The Scope Enforcement Middleware validates targets at execution time (not approval time), so even if the LLM is tricked into proposing an out-of-scope target, the middleware blocks it at the tRPC transport layer
- The Safety Engine's blast-radius estimation provides a second check — anomalous target counts or risk scores trigger additional approval requirements

### 8.2 Threat: Exploit Knowledge Store Poisoning

**Attack vector:** An attacker introduces malicious entries into the exploit knowledge store, which are then served to the RAG pipeline and influence LLM-generated exploits.

**Mitigations:**
- Framework-sourced exploits (ExploitDB, Metasploit, GitHub PoC) are loaded from verified external databases with community review
- LLM-generated exploits now pass through the quarantine queue and require human approval before entering the searchable catalog
- The `exploit-guardrails.ts` module validates generated exploit code against safety constraints before execution
- The evidence integrity module provides SHA-256 hash chains, so any tampering with stored exploit data is detectable

### 8.3 Threat: Operator Credential Abuse

**Attack vector:** An operator with valid credentials attempts to bypass safety controls — for example, approving their own dual-approval gate, or escalating an engagement's safety level without authorization.

**Mitigations:**
- Dual-approval enforcement rejects duplicate approvers — the same operator cannot approve a gate twice
- The engagement access guard enforces row-level security, preventing operators from accessing engagements they are not assigned to
- ROE validation checks are performed at execution time, not just at engagement creation
- All approval actions are logged with operator identity, timestamp, and gate details for forensic review

### 8.4 Threat: Evidence Integrity Chain Attack

**Attack vector:** An attacker attempts to modify evidence artifacts (scan results, exploit outputs, approval records) after the fact to conceal unauthorized actions.

**Mitigations:**
- The evidence integrity module (`evidence-integrity.ts`) computes SHA-256 hashes for all evidence artifacts and chains them with HMAC anchors
- Each evidence entry includes the hash of the previous entry, creating a tamper-evident chain
- The FIPS crypto service ensures all hashing uses approved algorithms
- Evidence chains can be independently verified by auditors using the hash chain verification function

---

## 9. Pre-Review Prerequisites

The following items are identified as prerequisites for external review. They represent policy documents requiring legal counsel, not architectural gaps.

| # | Prerequisite | Status | Owner | Timeline |
|---|-------------|--------|-------|----------|
| 1 | Non-Public Source Policy | Not started | Security Engineering + Counsel | 2-4 weeks |
| 2 | Jurisdiction Enforcement Policy | Not started | Legal + Engineering | 2-4 weeks |
| 3 | Wassenaar/EAR Export Control Analysis | Not started | Legal (primary) | 3-6 weeks |
| 4 | Novel Vulnerability Disclosure Policy | Not started | Security Engineering + Legal | 2-4 weeks |

### 9.1 Export Control Consideration

AC3's capabilities — functional exploit generation, C2 deployment, lateral movement, credential testing — likely fall under Wassenaar Arrangement Category 4.D.4 ("intrusion software") and potentially EAR ECCN 4D004. Outside counsel is required before any non-US customer engagement. This review can run in parallel with engineering work.

---

## 10. Remediation Summary and Control Inventory

### 10.1 Technical Controls Implemented

| # | Control | Module | Status |
|---|---------|--------|--------|
| 1 | Four-tier safety profiles | `safety-engine.ts` | Implemented |
| 2 | Scope enforcement at tRPC transport layer | `scope-enforcement-middleware.ts` | Implemented |
| 3 | ROE validation with expiration | `roe-guard.ts` | Implemented |
| 4 | SHA-256 evidence integrity chains | `evidence-integrity.ts` | Implemented |
| 5 | MITRE ATLAS adversarial ML testing | `ai-security-validation.ts` | Implemented |
| 6 | AI governance and telemetry | `ai-governance.ts` | Implemented |
| 7 | FIPS 140-3 algorithm enforcement | `fips-crypto.ts` | Implemented |
| 8 | Row-level engagement access control | `engagement-access-guard.ts` | Implemented |
| 9 | Exploit code guardrails | `exploit-guardrails.ts` | Implemented |
| 10 | Training target ROE guard | `training-roe-guard.ts` | Implemented |
| 11 | Prompt injection shield (5-layer) | `prompt-injection-shield.ts` | Implemented |
| 12 | Blast-radius estimation | `safety-engine.ts` | Implemented |
| 13 | Approval gates with resolver pattern | `engagement-orchestrator.ts` | Implemented |
| 14 | **Dual-approval for full_exploitation** | `engagement-orchestrator.ts` | **Implemented (this revision)** |
| 15 | **Exploit quarantine queue** | `exploit-knowledge-store.ts` | **Implemented (this revision)** |
| 16 | **Elevated graduation bar for exploit callers** | `graduation-engine.ts` | **Implemented (this revision)** |
| 17 | LLM graduation engine | `graduation-engine.ts`, `graduation-lab-bridge.ts` | Implemented |

### 10.2 Engineering Remediations Completed (This Revision)

| Remediation | Reviewer Concern | Implementation | Test Coverage |
|-------------|-----------------|----------------|---------------|
| Dual-approval enforcement | "Two-person rule should be implemented" | `safety-engine.ts`, `engagement-orchestrator.ts`, `engagement-ops-core.ts` | 8 tests |
| Exploit quarantine queue | "Who reviews [LLM-generated exploits] when they enter?" | `exploit-knowledge-store.ts` | 12 tests |
| Elevated graduation bar | "Exploit-category procedures [need] higher bar" | `graduation-engine.ts` | 6 tests |

### 10.3 Remaining Items

| Category | Count | Effort | Timeline |
|----------|-------|--------|----------|
| Policy documents (require legal counsel) | 4 | Medium | 2-6 weeks |
| Third-party PyRIT-style AI red team assessment | 1 | External engagement | 2-4 weeks |
| Formal NIST 800-53A spec sheet population | 1 | Documentation | 2 weeks |
| Per-category OWASP LLM Top 10 test evidence (3 remaining) | 1 | Testing | 1-2 weeks |

---

## 11. Recommended Next Steps

The reviewer recommended four next steps. Current status:

1. **Third-party PyRIT-style assessment** — Not yet scheduled. Should be engaged after policy documents are complete so the red team can test the full control surface. Recommended vendors: Trail of Bits, NCC Group, or Anthropic's red team program.

2. **Counsel-led export control review** — Not yet started. Should be engaged immediately and can run in parallel with other work. Estimated timeline: 3-6 weeks.

3. **Written policy documents** — Not yet started. Four documents identified (Section 9). Should be drafted with internal security engineering input and reviewed by counsel.

4. **Formal two-person rule implementation** — **Completed.** Dual-approval enforcement is implemented and tested (Section 4).

---

## 12. Conclusion

AC3 now implements 17 technical safety controls, including the three engineering remediations identified during the independent AI safety review. The dual-approval enforcement ensures that the highest-risk operations require two independent human approvers. The exploit quarantine queue ensures that LLM-generated exploit code cannot enter the reusable knowledge store without human review. The elevated graduation bar ensures that exploit-category LLM callers face significantly higher reliability requirements before their outputs can be considered for deterministic replacement.

No architectural redesign was required. The remaining items are policy documents requiring legal counsel and external assessment engagements. The platform's safety architecture — scope enforcement at the tRPC transport layer, evidence-grounded exploit generation, SHA-256 evidence integrity chains, and the MITRE ATLAS security validation loop — has been validated by the reviewer and strengthened by the remediations documented herein.

---

## References

- NIST SP 800-53 Rev 5: Security and Privacy Controls for Information Systems and Organizations
- NIST AI 100-1: Artificial Intelligence Risk Management Framework
- ISO/IEC 42001:2023: Information Technology — Artificial Intelligence — Management System
- OWASP Top 10 for LLM Applications (2025)
- MITRE ATLAS: Adversarial Threat Landscape for AI Systems
- Wassenaar Arrangement: List of Dual-Use Goods and Technologies, Category 4
- CMMC Model Overview (Version 2.0)
- FIPS 140-3: Security Requirements for Cryptographic Modules
