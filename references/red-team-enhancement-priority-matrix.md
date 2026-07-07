# AC3 Red Team Enhancement — Revised Priority Matrix

## Revision of "AC3 Red Team Enhancement Recommendations" (Manus, 2025-07-02)

**Date:** 2026-07-02
**Basis:** AC3 Red Team Artifact Spec v0.1; Manus gap analysis; conformance review against FedRAMP CA-8(2) / Pen Test Guidance Appendix D, CISA RTA model, NIST SP 800-115 / 800-53r5.

## What changed and why

The Manus structure is sound — the gap inventory is accurate and the post-phase artifact-emission architecture is the right call. This revision does one thing: **it re-sequences the work so the compliance guardrails and the human-attestation anchor land before the generators that depend on them.** Two principles drive the re-cut:

1. **Structural conformance ≠ compliance.** A schema-valid RTTR does not satisfy CA-8(2). Compliance is conferred by a credentialed 3PAO validating/attesting and an AO accepting. The attestation binding is therefore load-bearing infrastructure, not a P3 portal.
2. **Guardrails must exist before the data they guard.** Evidence masking, critical-finding notification, and the detection-data source have to be designed before the RTTR generator writes findings — otherwise the generator creates the exposures the guidance requires you to prevent.

Net effect: several items Manus placed in P2/P3 move to P1 as **decisions or write-time gates**; the heavy generators (RTTR, scoring, OSCAL) stay in P2 but are explicitly ordered by dependency; UI polish and continuous re-validation stay in P3.

---

## Revised priority tiers

**P1 — Foundation + compliance guardrails.** Everything the generators depend on: the artifact store (with attestation binding), the phase and vector mapping, the RTTP emitter, and the four guardrails that must be in place before any finding is written (masking, notification, cadence, detection-data decision).

**P2 — Generators + scoring.** RTTR generator, detection/purple-team scoring, scored Navigator layer, OSCAL emitter — in strict dependency order.

**P3 — Attestation UI + continuous.** The 3PAO portal *UI* (the binding is P1), continuous re-validation, deconfliction integration, evidence certificates.

---

## Revised action matrix

Columns extend Manus's format with **Depends on** and **Compliance-critical** (a "yes" means a FedRAMP/CISA requirement fails without it, not merely a nice-to-have). Effort estimates corrected where Manus was optimistic.

### Priority 1 — Implement now

| # | Action | File(s) | Effort | Depends on | Compliance-critical |
| --- | --- | --- | --- | --- | --- |
| 1 | `engagementArtifacts` table **with attestation binding** — approval bound to authenticated 3PAO identity + `credential_ref` + content hash captured at approval; `status` transitions gated, not free-text | `drizzle/schema.ts`, router guard | 3 h | — | **Yes** |
| 2 | `attack-phase-mapping.ts` — P1–P7 → ATT&CK tactic map; tag each pipeline step with `phase_id` | new file | 2 h | — | Yes |
| 3 | `attack_vectors_covered` field **with N/A state** — states: `covered` / `not_applicable`(+justification) / `deviated`(+AO ref); completion gate honors N/A | `drizzle/schema.ts`, UI | 2 h | 2 | Yes |
| 4 | RTTP JSON emitter **+ CSP threat-intel input path** — extend `generateFedRAMP`; wire threat-actor matching → `objectives.threat_model` seeded from CSP intel (Appendix D requires this input) | `server/routers/test-plan-generator.ts`, `server/lib/test-plan-generator.ts` | 4 h | 1 | Yes |
| 5 | Deviation tracking — explicit `deviations[]` objects with AO approval refs in scope/ROE | router + UI | 4 h | 1, 3 | Yes |
| 6 | **Evidence-masking gate (write-time)** — mask PII/credentials *before* persistence; block unmasked writes to artifact `content` | `server/lib/evidence-guard.ts` (new), write path | 5 h | 1 | **Yes** |
| 7 | **Critical-finding notification hook** — mid-engagement out-of-band notify CIO/CISO/ISSO/AO on critical high-impact; route through existing safety-architecture escalation path | engagement orchestrator | 4 h | — | **Yes** |
| 8 | **Timing/cadence metadata + validation** — initial ≤6 mo pre-SAR; annual ≤12 mo; store + reminder/validation | `drizzle/schema.ts`, validation | 2 h | 1 | Yes |
| 9 | **Detection-data ingestion — architecture decision** — decide the source for defender-side outcomes (SOC/EDR/SIEM ingest vs. collaborative-phase manual capture). Decision + interface only; no computation yet | design doc + interface stub | 4 h | — | Yes (enables P2) |
| 10 | `attack-navigator.ts` — **binary** executed / not-executed layer first (scoring deferred to P2) | new file | 3 h | 2 | No |
| 11 | **Log-preservation mode flag** — "assessment transparency" vs "operational stealth"; default transparency for FedRAMP/CISA engagements | orchestrator config | 2 h | — | Yes |

### Priority 2 — Implement next (dependency-ordered)

| # | Action | File(s) | Effort | Depends on | Compliance-critical |
| --- | --- | --- | --- | --- | --- |
| 12 | Detection scoring fields + computation — `detection_outcome` enum, `time_to_detect`, `detection_source`; rollups (detection/prevention coverage, MTTD by tactic, behavior-vs-IOC ratio, log-sufficiency) | `drizzle/schema.ts`, `server/lib/detection-scoring.ts` | 8 h | **9** (data source) | No* |
| 13 | Purple-team mode — two-phase (no-notice emulation → collaborative SOC sessions) | `client/src/pages/`, orchestrator | 8 h | 12 | No* |
| 14 | `rttr-generator.ts` — timeline→findings from telemetry; ATT&CK mapping, access-path chains, risk (CVSS+operator), control-effectiveness, detection metrics, lessons-learned vs CISA deficiency set, defense-in-depth | new file | 12–16 h | 2, 3, 6, 12 | Yes |
| 15 | Scored Navigator layer — upgrade #10 with per-technique score/color from detection outcomes | `server/lib/attack-navigator.ts` | 3 h | 12 | No |
| 16 | `oscal-emitter.ts` — RTTP→assessment-plan, RTTR→assessment-results (findings/observations/risks); **behind a swappable adapter**; iterate against FedRAMP validators | new file | **3–5 days** | 14 | No† |

\* Not individually compliance-critical, but collectively these are the entire "CISA-grade / exceeds" claim. Without #9's data source, #12 collapses to `unknown` and the differentiator evaporates.
† No published FedRAMP OSCAL profile for red team / pen test artifacts exists yet; this is an anticipatory bet, hence the adapter.

### Priority 3 — Attestation UI + continuous

| # | Action | File(s) | Effort | Depends on | Compliance-critical |
| --- | --- | --- | --- | --- | --- |
| 17 | 3PAO validation portal (UI) — read-only artifact review + attestation signing surface (the *binding* already exists from #1) | `client/src/pages/` | 8 h | 1, 14 | No |
| 18 | Continuous re-validation (20x KSI model) — scheduled re-validation + delta/remediation reports | orchestrator | — | 14, 16 | No |
| 19 | Deconfliction channel integration — real-time logging; SOC channel (Slack/Teams/PagerDuty); auto-pause on deconfliction | integration | — | 13 | No |
| 20 | Evidence-handling certificates — masking/destruction attestation certs (masking itself shipped in #6) | reporting | — | 6, 14 | No |

---

## Dependency ordering (the critical path)

```
#1 artifact store + attestation binding
     ├─> #4 RTTP emitter ──────────────┐
     ├─> #5 deviation tracking          │
     ├─> #6 evidence-masking gate ──────┤
     └─> #8 cadence metadata            │
#2 phase mapping ──> #3 vector tracking ┤
#9 detection-data DECISION ─────────────┤
                                        v
                              #12 detection scoring
                                        │
                              #14 RTTR generator  <── (also needs #2,#3,#6)
                                        │
                              #16 OSCAL emitter (adapter)
                                        │
                              #17 3PAO portal UI / #18 continuous
```

The two hard gates: **nothing writes a finding until #6 (masking) exists**, and **#12 is inert until #9 (data source) is decided**. Everything else is comparatively mechanical.

---

## Corrections to specific Manus items

1. **Attestation is not P3.** Manus placed the 3PAO portal and attestation workflow at the bottom. The *portal UI* can stay in P3, but the *attestation binding* (authenticated identity, credential ref, content hash at approval) is P1 infrastructure — see #1. A `status='approved'` reachable via a free-text `approvedBy` varchar is a governance hole; harden it.

2. **Detection scoring is gated on a data source AC3 doesn't natively have.** An offensive platform sees its own actions, not the blue team's alerts. The `prevented|detected_and_alerted|detected_no_alert|missed` outcomes require defender telemetry or collaborative-phase capture. Promote the *ingestion decision* (#9) to P1; keep the *computation* (#12) in P2 behind it.

3. **OSCAL at 6 hours is optimistic by roughly an order of magnitude,** and there is no published FedRAMP OSCAL profile for these artifacts yet. Build behind an adapter (#16), sequence *after* the RTTR schema stabilizes, and budget days–weeks of validator iteration.

4. **Evidence masking is a write-time guardrail, not a P3 workflow.** The moment the RTTR generator writes evidence into a `json` column, unmasked screenshots and captured phishing creds land in the DB. Mask before persistence (#6).

5. **The critical-finding notification clause is a runtime behavior, not a report field.** "As soon as discovered" implies mid-engagement out-of-band notification (#7) — hook it into the existing safety-architecture escalation path rather than reinventing it.

6. **The six-vector completion gate over-flags.** V5 (mobile) and V6 (client-side) are conditionally applicable; "not applicable, with justification" must be a first-class state distinct from "deviated," or you manufacture spurious High findings (#3).

7. **Log preservation fights the platform's likely default.** The CISA transparency model deliberately does not clean up logs; an offensive tool usually minimizes footprint. Make it an explicit mode flag defaulting to transparency for these engagements (#11).

8. **Navigator scoring depends on detection outcomes.** Ship a binary executed/not-executed layer in P1 (#10), upgrade to scored/colored in P2 once #12 exists (#15) — so the later change doesn't read as a regression.

---

## Positioning language

Revise the competitive-positioning claim from **"the only platform that auto-generates FedRAMP CA-8(2) *compliant* artifacts"** to **"…CA-8(2) *conformant, attestation-ready* artifacts."** Structural conformance is real and defensible; "compliant" overclaims, because compliance is conferred by 3PAO attestation + AO acceptance — not by the platform. This is also the stronger claim: the external human attestation *is* the moat and the "external proof," so naming the attestation layer explicitly reinforces the positioning rather than papering over it. Given the C3PAO standing behind this, precision here is worth more than the marginal punch of the word "compliant."

---

## The quality risk to watch

The revised P1+P2 effort still measures "emits an artifact matching the schema." The gap between that and "emits an RTTR a 3PAO will attest to and an AO won't bounce" lives in content quality — access-path narratives that actually chain, risk justifications that hold up, lessons-learned that map to real CISA-pattern deficiencies. At AC3's build velocity the failure mode is fast production of structurally-valid, compliance-shallow artifacts. Recommend one human-in-the-loop review pass on the first live RTTR before the attestation binding is exercised in anger.
