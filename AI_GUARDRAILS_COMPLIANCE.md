# Ace C3 Platform — AI/LLM Guardrails & Compliance Documentation

**Document Classification:** CONTROLLED — Distribution Limited to Authorized Personnel  
**Version:** 1.0  
**Date:** March 15, 2026  
**Prepared by:** Ace of Cloud Engineering  
**Applicable Frameworks:** NIST AI RMF 1.0, NIST AI 600-1, OMB M-24-10, DoD RAI Principles, EO 14110, MITRE ATLAS, CMMC AI, FedRAMP AI

---

## 1. Executive Summary

The Ace C3 (Cyber Command & Control) platform integrates large language models (LLMs) and artificial intelligence throughout its offensive security pipeline — from vulnerability synthesis and exploit generation to campaign advisory and risk scoring. Recognizing that AI-augmented cybersecurity tools present unique risks including confabulation, prompt injection, uncontrolled autonomous action, and dual-use concerns, the platform implements a comprehensive, code-enforced AI governance framework.

This document maps every U.S. government AI compliance requirement to its specific implementation within the Ace C3 codebase. Each control is traceable to a source file, function, and test case. The platform's AI governance is not a policy document — it is an executable, auditable, and continuously monitored enforcement layer.

---

## 2. Regulatory Landscape

The following table summarizes the applicable U.S. government AI regulations and their relevance to the Ace C3 platform.

| Framework | Authority | Key Requirements | Platform Relevance |
|---|---|---|---|
| **NIST AI RMF 1.0** [1] | NIST (Jan 2023) | Govern, Map, Measure, Manage lifecycle | Core governance structure for all AI components |
| **NIST AI 600-1** [2] | NIST (Jul 2024) | GenAI-specific risks: confabulation, CBRN, cybersecurity, data privacy | Directly applicable — platform uses GenAI for exploit generation |
| **OMB M-24-10** [3] | OMB (Mar 2024) | Minimum practices for federal AI: impact assessment, testing, monitoring, human oversight | Required for any federal procurement |
| **DoD RAI Principles** [4] | DoD (Feb 2020) | Responsible, Equitable, Traceable, Reliable, Governable | Required for DoD/IC customer engagements |
| **EO 14110** [5] | White House (Oct 2023) | Red teaming, dual-use testing, safety standards | Establishes baseline for AI safety in national security |
| **MITRE ATLAS** [6] | MITRE (ongoing) | Adversarial ML threat matrix | Informs defensive posture of AI components |
| **CMMC 2.0** [7] | DoD (Dec 2024) | CUI protection, supply chain security | AI components handling CUI must comply |
| **FedRAMP** [8] | GSA/OMB | Cloud service authorization | Platform deployment authorization pathway |

---

## 3. AI Governance Architecture

The platform's AI governance is implemented as a unified module (`server/lib/ai-governance.ts`) that consolidates previously scattered controls into a single enforceable system. The architecture follows the NIST AI RMF lifecycle.

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI GOVERNANCE MODULE                          │
│                  server/lib/ai-governance.ts                     │
├─────────────┬──────────────┬──────────────┬─────────────────────┤
│   Model     │   Input      │   Output     │   Human-in-the-     │
│   Registry  │   Validation │   Validation │   Loop Queue        │
├─────────────┼──────────────┼──────────────┼─────────────────────┤
│   Audit     │   Bias       │   Compliance │   Incident          │
│   Trail     │   Assessment │   Attestation│   Management        │
├─────────────┴──────────────┴──────────────┴─────────────────────┤
│              EXISTING ENFORCEMENT POINTS                         │
├─────────────┬──────────────┬──────────────┬─────────────────────┤
│ LLM         │ SSIL         │ AI Decision  │ AI Security         │
│ Guardrails  │ Guardrails   │ Audit        │ Validation          │
│ (llm-       │ (ssil-       │ (ai-decision │ (ai-security-       │
│ guardrails  │ guardrails   │ -audit.ts)   │ validation.ts)      │
│ .ts)        │ .ts)         │              │                     │
└─────────────┴──────────────┴──────────────┴─────────────────────┘
```

### 3.2 Module Inventory

The following table lists every AI/LLM module in the platform with its purpose and governance controls.

| Module | File | Purpose | Governance Controls |
|---|---|---|---|
| **AI Governance (Unified)** | `server/lib/ai-governance.ts` | Consolidated governance: registry, validation, audit, compliance | All 8 frameworks, 28 vitest tests |
| **LLM Guardrails** | `server/lib/llm-guardrails.ts` | Prompt injection defense, output sanitization, scope enforcement | Input/output filtering, rate limiting |
| **SSIL Guardrails** | `server/lib/ssil-guardrails.ts` | Security-specific AI safety for the SSIL pipeline | Vuln validation, false positive detection |
| **AI Decision Audit** | `server/lib/ai-decision-audit.ts` | Decision logging and traceability for all AI actions | Immutable audit trail, decision replay |
| **AI Security Validation** | `server/lib/ai-security-validation.ts` | Validates AI-generated security findings | Cross-reference, confidence scoring |
| **Functional Exploit Generator** | `server/lib/functional-exploit-generator.ts` | LLM-generated exploit code | Code sandboxing, RoE enforcement, human approval gates |
| **Vuln Synthesis** | `server/routers/engagement-ops-core.ts` | LLM-synthesized vulnerability findings | Ground truth validation, precision config |
| **Campaign Advisor** | `server/routers/operatorCockpit.ts` | LLM-powered tactical recommendations | Scope constraints, engagement-bound context |
| **LLM Specialists** | `server/lib/llm-specialists/` | Domain-specific LLM agents | Core policy enforcement, role isolation |
| **Continuous Training** | `server/lib/continuous-training.ts` | Model performance tracking and improvement | Feedback loops, accuracy metrics |

---

## 4. NIST AI RMF 1.0 Compliance Mapping

The NIST AI Risk Management Framework defines four core functions: Govern, Map, Measure, and Manage. The following sections map each subcategory to its implementation.

### 4.1 GOVERN — Establish AI Governance Policies

| Control ID | Requirement | Implementation | Code Reference |
|---|---|---|---|
| **GV-1.1** | Legal and regulatory requirements documented | `ComplianceFramework` enum covers all 8 applicable frameworks; `generateComplianceAttestation()` produces per-framework attestations | `ai-governance.ts` |
| **GV-1.2** | Trustworthy AI characteristics integrated | Model registry tracks `riskClassification`, `humanOversightLevel`, `approvedUseCases`, `prohibitedUseCases` per model | `ai-governance.ts:registerModel()` |
| **GV-1.3** | Processes for risk management established | `reportIncident()` → `updateIncident()` lifecycle with P1-P4 severity, root cause analysis, and remediation tracking | `ai-governance.ts:reportIncident()` |
| **GV-2.1** | Roles and responsibilities defined | `HumanOversightLevel` enum: `none`, `monitoring`, `approval_required`, `human_in_the_loop`, `full_manual` — each model specifies required oversight | `ai-governance.ts` |
| **GV-2.2** | Personnel are trained and aware | Platform includes Training Lab (`server/routers/engagement-automation.ts`) and Learning Dashboard for operator AI safety training | `engagement-automation.ts` |
| **GV-3.1** | Decision-making is documented | Every AI decision logged via `logGovernanceAudit()` with action, category, model, latency, violations, compliance frameworks, and control IDs | `ai-governance.ts:logGovernanceAudit()` |
| **GV-3.2** | Feedback mechanisms exist | `continuous-training.ts` implements feedback loops; `assessBias()` enables periodic output analysis | `continuous-training.ts`, `ai-governance.ts` |
| **GV-4.1** | Organizational practices are in place | AI Governance Dashboard (`server/routers/ai-governance.ts`) provides real-time visibility into model registry, guardrail stats, audit stats, approval queue, incidents, and compliance overview | `routers/ai-governance.ts` |

### 4.2 MAP — Contextualize AI Risks

| Control ID | Requirement | Implementation | Code Reference |
|---|---|---|---|
| **MAP-1.1** | Intended purpose documented | Each registered model has `approvedUseCases` and `prohibitedUseCases` arrays; scope enforcement in `validateInput()` blocks off-topic queries | `ai-governance.ts:validateInput()` |
| **MAP-1.2** | Interdependencies mapped | `LLM_SPECIALISTS` in `core-policy.ts` defines role isolation between specialist agents; engagement context binds AI actions to specific targets | `llm-specialists/core-policy.ts` |
| **MAP-2.1** | Intended benefits documented | Model registry `capabilities` field enumerates what each model can do; `limitations` field documents known weaknesses | `ai-governance.ts:ModelRegistryEntry` |
| **MAP-2.2** | Potential harms identified | `riskClassification` (minimal/low/moderate/high/critical) and `knownBiases` fields per model; `confabulationRisk` assessed on every output | `ai-governance.ts` |
| **MAP-3.1** | Benefits and costs characterized | Audit trail tracks `latencyMs` per AI decision; `guardrailStats` tracks block rate and sanitization rate for cost/benefit analysis | `ai-governance.ts:getAuditStats()` |

### 4.3 MEASURE — Assess AI Risks

| Control ID | Requirement | Implementation | Code Reference |
|---|---|---|---|
| **MS-1.1** | Approaches for measurement identified | `assessBias()` performs output analysis across geographic, technological, severity, temporal, and false positive dimensions | `ai-governance.ts:assessBias()` |
| **MS-2.1** | AI evaluated for trustworthy characteristics | `generateComplianceAttestation()` produces per-framework attestation with control-level pass/fail, code references, and evidence | `ai-governance.ts:generateComplianceAttestation()` |
| **MS-2.2** | Evaluations involve internal and external expertise | Compliance attestations include `attestedBy` field and `validUntil` expiration requiring periodic re-evaluation | `ai-governance.ts` |
| **MS-2.3** | AI system performance monitored | `getGovernanceDashboard()` provides real-time metrics: total checks, block rate, avg latency, violation breakdown, confabulation rate | `ai-governance.ts:getGovernanceDashboard()` |
| **MS-3.1** | Risks and impacts monitored | Incident management with `reportIncident()` tracks affected models, affected engagements, severity, timeline, root cause, and remediation | `ai-governance.ts:reportIncident()` |

### 4.4 MANAGE — Manage AI Risks

| Control ID | Requirement | Implementation | Code Reference |
|---|---|---|---|
| **MG-1.1** | Risk treatment plans in place | `requestHumanApproval()` gates high-risk AI actions; tiered approval levels (green/amber/red) in engagement pipeline | `ai-governance.ts`, `engagement-orchestrator.ts` |
| **MG-2.1** | Risks are responded to | `updateIncident()` supports status progression: detected → investigating → mitigating → resolved → closed | `ai-governance.ts:updateIncident()` |
| **MG-2.2** | Mechanisms to supersede or deactivate | `deregisterModel()` removes models from active registry; `prohibitedUseCases` blocks specific use cases per model | `ai-governance.ts:deregisterModel()` |
| **MG-3.1** | Pre-deployment testing conducted | `validateInput()` and `validateOutput()` run on every LLM interaction; `ai-security-validation.ts` validates generated exploits before execution | `ai-governance.ts`, `ai-security-validation.ts` |
| **MG-3.2** | Post-deployment monitoring | `logGovernanceAudit()` creates immutable audit trail; `continuous-training.ts` tracks model accuracy over time | `ai-governance.ts`, `continuous-training.ts` |

---

## 5. NIST AI 600-1 (GenAI Profile) Compliance

NIST AI 600-1 identifies 12 GenAI-specific risks. The following table maps each to its mitigation.

| Risk Category | NIST AI 600-1 Reference | Platform Mitigation | Code Reference |
|---|---|---|---|
| **Confabulation** | GAI.1 | `confabulationRisk` assessed on every output (none/low/medium/high); cross-referenced against CVE databases and ground truth | `ai-governance.ts:validateOutput()`, `ai-security-validation.ts` |
| **CBRN Information** | GAI.2 | `validateOutput()` detects and blocks biological/chemical/radiological/nuclear weapon content via forbidden content patterns | `ai-governance.ts:validateOutput()` |
| **Data Privacy** | GAI.3 | `validateOutput()` detects PII (SSN, credit cards) as `data_leakage` violations; output sanitization strips sensitive data | `ai-governance.ts:validateOutput()` |
| **Environmental** | GAI.6 | Audit trail tracks `latencyMs` per call enabling resource usage monitoring; model registry documents compute requirements | `ai-governance.ts:logGovernanceAudit()` |
| **Cybersecurity** | GAI.7 | `validateInput()` detects prompt injection and jailbreak attempts; `llm-guardrails.ts` enforces scope constraints | `ai-governance.ts:validateInput()`, `llm-guardrails.ts` |
| **Intellectual Property** | GAI.8 | Model registry `trainingDataSources` documents data provenance; output validation flags potential IP violations | `ai-governance.ts:ModelRegistryEntry` |
| **Obscene Content** | GAI.9 | `validateOutput()` forbidden content filter blocks obscene/harmful content generation | `ai-governance.ts:validateOutput()` |
| **Value Chain** | GAI.10 | Model registry tracks `provider`, `deploymentType`, `modelVersion` for supply chain visibility | `ai-governance.ts:ModelRegistryEntry` |
| **Information Integrity** | GAI.11 | `confabulationRisk` scoring; `ai-security-validation.ts` cross-validates AI findings against known vulnerability databases | `ai-security-validation.ts` |
| **Information Security** | GAI.12 | Input/output validation pipeline; audit trail for forensic analysis; incident management for security events | `ai-governance.ts` |
| **Human-AI Configuration** | GAI.4 | `HumanOversightLevel` per model; `requestHumanApproval()` for high-risk actions; tiered approval gates | `ai-governance.ts` |
| **Homogenization** | GAI.5 | `assessBias()` detects technological and geographic bias in model outputs; diversity metrics tracked | `ai-governance.ts:assessBias()` |

---

## 6. OMB M-24-10 Minimum Practices

OMB Memorandum M-24-10 establishes minimum practices for federal agency AI use. Section 5(c) defines nine mandatory requirements.

| OMB Requirement | Section | Implementation | Code Reference |
|---|---|---|---|
| **AI Impact Assessment** | 5(c)(i) | `generateComplianceAttestation()` produces framework-specific impact assessments with control-level evaluation | `ai-governance.ts` |
| **Real-World Testing** | 5(c)(ii) | Training Lab mode enables controlled testing against known-vulnerable targets (demo.testfire.net, DVWA); ground truth validation measures accuracy | `engagement-automation.ts`, `engagement-ops-core.ts` |
| **Independent Evaluation** | 5(c)(iii) | `assessBias()` provides independent output analysis; compliance attestations include `attestedBy` field for third-party review | `ai-governance.ts:assessBias()` |
| **Ongoing Monitoring** | 5(c)(iv) | `getGovernanceDashboard()` provides real-time monitoring; `continuous-training.ts` tracks model drift; audit trail enables forensic review | `ai-governance.ts`, `continuous-training.ts` |
| **Human Oversight** | 5(c)(v) | `HumanOversightLevel` enforced per model; `requestHumanApproval()` gates critical actions; Rules of Engagement (RoE) require human sign-off before active scanning | `ai-governance.ts`, `engagement-orchestrator.ts` |
| **Transparency** | 5(c)(vi) | AI Governance Dashboard exposes all metrics; audit trail is queryable; model registry documents capabilities and limitations | `routers/ai-governance.ts` |
| **Notice to Public** | 5(c)(vii) | Platform clearly labels AI-generated content (exploit code, vuln synthesis, campaign recommendations) in the UI | Client-side rendering |
| **Equity and Fairness** | 5(c)(viii) | `assessBias()` evaluates geographic, technological, severity, temporal, and false positive bias dimensions | `ai-governance.ts:assessBias()` |
| **Data Governance** | 5(c)(ix) | Model registry `trainingDataSources` documents data provenance; `hashContent()` enables data lineage tracking | `ai-governance.ts` |

---

## 7. DoD Responsible AI (RAI) Principles

The Department of Defense adopted five ethical principles for AI in February 2020. The following table maps each principle to its enforcement.

| Principle | Description | Implementation | Code Reference |
|---|---|---|---|
| **Responsible** | Personnel exercise appropriate judgment and care | `HumanOversightLevel` enforced per model; tiered approval gates (green/amber/red) require human judgment for escalating risk levels; RoE sign-off required before active operations | `ai-governance.ts`, `engagement-orchestrator.ts` |
| **Equitable** | Steps taken to minimize unintended bias | `assessBias()` evaluates 5 bias dimensions; model registry `knownBiases` field; compliance attestation tracks equity controls | `ai-governance.ts:assessBias()` |
| **Traceable** | Transparent and auditable AI operations | `logGovernanceAudit()` creates immutable audit trail with action, model, latency, violations, compliance frameworks; `ai-decision-audit.ts` logs every AI decision with full context | `ai-governance.ts`, `ai-decision-audit.ts` |
| **Reliable** | AI has explicit, well-defined uses | Model registry `approvedUseCases` and `prohibitedUseCases`; `validateInput()` scope enforcement; ground truth validation for accuracy measurement | `ai-governance.ts`, `engagement-ops-core.ts` |
| **Governable** | Ability to detect and avoid unintended consequences | `validateOutput()` blocks harmful content; `requestHumanApproval()` gates high-risk actions; `deregisterModel()` can disable models; incident management with P1-P4 severity | `ai-governance.ts` |

---

## 8. Executive Order 14110 Compliance

EO 14110 (October 2023) establishes requirements for safe, secure, and trustworthy AI development and use.

| EO Requirement | Section | Implementation | Code Reference |
|---|---|---|---|
| **Red Teaming** | Sec. 4.2 | Training Lab enables red team testing of AI components against known-vulnerable targets; ground truth validation measures AI accuracy | `engagement-automation.ts` |
| **Dual-Use Testing** | Sec. 4.2 | `validateOutput()` blocks CBRN content; `prohibitedUseCases` per model prevents dual-use applications | `ai-governance.ts:validateOutput()` |
| **Safety Standards** | Sec. 4.1 | Unified AI governance module enforces safety across all AI components; 28 vitest tests validate safety controls | `ai-governance.ts`, `ai-governance.test.ts` |
| **Reporting Requirements** | Sec. 4.5 | `reportIncident()` creates structured incident reports; `generateComplianceAttestation()` produces compliance reports | `ai-governance.ts` |
| **AI Workforce** | Sec. 5 | Training Dashboard and Learning modules provide AI safety training for operators | `pages/TrainingDashboard.tsx` |

---

## 9. Guardrail Enforcement Details

### 9.1 Input Validation (Prompt Injection Defense)

Every user input that reaches an LLM passes through `validateInput()` which applies the following checks:

1. **Prompt Injection Detection** — Pattern matching against known injection vectors ("ignore all previous instructions", "system prompt override", "you are now", etc.)
2. **Jailbreak Detection** — Identifies DAN mode, developer mode, and other jailbreak patterns
3. **Scope Enforcement** — Ensures queries are within the security/offensive operations domain
4. **Context Binding** — Validates that AI actions are bound to an authorized engagement with signed RoE

**Test Coverage:** 5 vitest tests validate prompt injection, jailbreak, scope, and valid query handling.

### 9.2 Output Validation (Content Safety)

Every LLM output passes through `validateOutput()` which applies:

1. **Forbidden Content Filter** — Blocks biological/chemical/nuclear weapon instructions, mass casualty content
2. **Data Leakage Detection** — Identifies SSN patterns, credit card numbers, and other PII
3. **Confabulation Risk Assessment** — Rates output confabulation risk as none/low/medium/high
4. **Output Sanitization** — Strips or redacts detected violations from the output

**Test Coverage:** 4 vitest tests validate PII detection, harmful content blocking, valid output allowance, and confabulation assessment.

### 9.3 Human-in-the-Loop Controls

The platform implements a multi-tier human oversight system:

| Tier | Risk Level | Approval Required | Auto-Approve in Training Lab |
|---|---|---|---|
| **Green** | Low | No — automated | Yes |
| **Amber** | Medium | Operator notification | Yes |
| **Red** | High/Critical | Explicit human approval via `requestHumanApproval()` | Yes |
| **RoE Gate** | All active scanning | Human-signed Rules of Engagement | Auto-signed for lab targets |

The `requestHumanApproval()` function creates a time-limited approval request with:
- Unique request ID for traceability
- Risk level classification
- Required approval level
- Expiration timer (default: 1 hour)
- Compliance justification
- Full context for the approver

**Test Coverage:** 2 vitest tests validate approval and denial workflows.

### 9.4 Audit Trail

Every AI decision is logged with the following fields:

| Field | Description |
|---|---|
| `id` | Unique event identifier |
| `timestamp` | UTC timestamp |
| `action` | What the AI did |
| `category` | Classification (input_validation, output_validation, exploit_generation, etc.) |
| `inputHash` | SHA-256 hash of the input (for privacy-preserving audit) |
| `modelId` | Which model was used |
| `modelVersion` | Model version for reproducibility |
| `latencyMs` | Processing time |
| `guardrailActions` | What guardrails were triggered (allowed, blocked, sanitized, warned) |
| `violations` | Detailed violation records |
| `complianceFrameworks` | Which frameworks this event relates to |
| `controlIds` | Specific control IDs satisfied |
| `result` | Outcome (success, blocked, error) |

**Test Coverage:** 3 vitest tests validate logging, querying, and content hashing.

### 9.5 Model Registry

Every AI model used in the platform is registered with:

- **Identity:** modelId, modelName, modelVersion, provider
- **Classification:** modelType (llm/classifier/embedding/vision), deploymentType (api/local/hybrid)
- **Capabilities and Limitations:** Enumerated lists
- **Risk Profile:** riskClassification (minimal → critical), humanOversightLevel
- **Use Case Boundaries:** approvedUseCases, prohibitedUseCases
- **Data Provenance:** trainingDataSources, knownBiases
- **Compliance Status:** Per-framework compliance (compliant/partial/non_compliant/not_assessed)

**Test Coverage:** 2 vitest tests validate registration and deregistration.

---

## 10. Compliance Attestation Engine

The `generateComplianceAttestation()` function produces machine-readable attestation reports for any of the 8 supported frameworks. Each attestation includes:

- **Framework identification** and version
- **Overall compliance status** (compliant/partial/non_compliant)
- **Control-level results** with status, implementation description, code reference, evidence, and last tested date
- **Evidence collection** linking to specific code files and test results
- **Validity period** with expiration requiring re-evaluation
- **Attested by** field for accountability

The attestation engine is accessible via the AI Governance Dashboard in the platform UI and via the `aiGovernance.getAttestation` tRPC endpoint.

**Test Coverage:** 6 vitest tests validate attestation generation across all frameworks, including DoD RAI principle coverage and code reference inclusion.

---

## 11. Incident Management

The platform implements a structured AI incident management process:

1. **Detection** — `reportIncident()` creates a new incident with severity (P1-P4), affected models, affected engagements
2. **Investigation** — `updateIncident()` progresses status to investigating, adds root cause analysis
3. **Mitigation** — Status updated to mitigating, remediation steps documented
4. **Resolution** — Incident resolved with lessons learned
5. **Closure** — Final review and closure

**Test Coverage:** 3 vitest tests validate incident reporting, status updates, and severity filtering.

---

## 12. Test Coverage Summary

| Test File | Tests | Coverage Area |
|---|---|---|
| `server/ai-governance.test.ts` | 28 | Unified governance: registry, input/output validation, approval queue, audit trail, bias assessment, compliance attestation, incident management, dashboard |
| `server/packet-analysis.test.ts` | 45 | PCAP parser, Scapy crafter, probe templates |
| `server/packet-enhancements.test.ts` | 14 | PCAP replay, network topology |
| **Total** | 87 | All AI governance and packet analysis modules |

---

## 13. Continuous Improvement

The AI governance framework is designed for continuous improvement through:

1. **Periodic Attestation** — Compliance attestations have a `validUntil` expiration requiring re-evaluation
2. **Bias Monitoring** — `assessBias()` can be run on demand or scheduled to detect drift
3. **Incident Learning** — Each resolved incident feeds back into guardrail rules
4. **Model Performance Tracking** — `continuous-training.ts` tracks accuracy metrics over time
5. **Ground Truth Validation** — Training Lab engagements against known-vulnerable targets measure AI accuracy (F1 score, precision, recall)

---

## References

[1]: https://www.nist.gov/itl/ai-risk-management-framework "NIST AI Risk Management Framework (AI RMF 1.0), January 2023"
[2]: https://airc.nist.gov/Docs/1 "NIST AI 600-1: Artificial Intelligence Risk Management Framework: Generative AI Profile, July 2024"
[3]: https://www.whitehouse.gov/wp-content/uploads/2024/03/M-24-10-Advancing-Governance-Innovation-and-Risk-Management-for-Agency-Use-of-Artificial-Intelligence.pdf "OMB Memorandum M-24-10: Advancing Governance, Innovation, and Risk Management for Agency Use of Artificial Intelligence, March 2024"
[4]: https://www.defense.gov/News/Releases/Release/Article/2091996/dod-adopts-ethical-principles-for-artificial-intelligence/ "DoD Adopts Ethical Principles for Artificial Intelligence, February 2020"
[5]: https://www.whitehouse.gov/briefing-room/presidential-actions/2023/10/30/executive-order-on-the-safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence/ "Executive Order 14110: Safe, Secure, and Trustworthy Development and Use of Artificial Intelligence, October 2023"
[6]: https://atlas.mitre.org/ "MITRE ATLAS: Adversarial Threat Landscape for AI Systems"
[7]: https://www.acq.osd.mil/cmmc/ "Cybersecurity Maturity Model Certification (CMMC) 2.0"
[8]: https://www.fedramp.gov/ "Federal Risk and Authorization Management Program (FedRAMP)"
