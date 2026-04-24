# Project TODO

### Claude Response Remediation (Apr 23)
- [x] Implement dual-approval for full_exploitation tier in safety-engine.ts
- [x] Add second approver resolver to engagement-orchestrator.ts approval gates
- [x] Implement exploit quarantine queue in exploit-knowledge-store.ts
- [x] Add human review gate before LLM-generated exploits enter searchable index
- [x] Add elevated graduation bar for exploit-category procedures
- [x] Write vitest tests for dual-approval, quarantine queue, and elevated graduation bar (26 tests passing)
- [x] Generate revised comprehensive spec document with corrected language
- [x] Include explicit exploit lifecycle documentation in spec
- [x] Include adversarial threat model section in spec
- [x] Correct FIPS claim to specify CMVP inheritance
- [x] Revise framework alignment language ("architected consistently with")
- [x] Checkpoint and push to GitHub

### Claude Follow-Up Feedback (Apr 23, Round 2)
- [x] Persist quarantine queue to database (not in-memory)
- [x] Persist approved exploit catalog entries to database
- [x] Add catalog snapshot binding for exploit-selection events (engagement evidence chain)
- [x] Fix graduation bar phrasing: "reduces tolerated failure rate from 3% to 1%"
- [x] Clarify that graduated exploit callers still feed quarantine queue (graduation != quarantine bypass)
- [x] Expand adversarial threat model: add cross-tenant data leakage and graduation pipeline attack surface
- [x] Add specific test cases, pass/fail criteria, and residual risk to each threat
- [x] Verify CMVP certificate #4282 against active CMVP list (FIPS 140-2, Active, Sunset 9/21/2026)
- [x] Soften conclusion: "strengthened by remediations, remains to be independently assessed"
- [x] Acknowledge Wassenaar review could affect customer eligibility, not just paperwork
- [x] Regenerate revised spec document v3 with all corrections
- [x] Write vitest tests for persistence changes (46 total tests passing)
- [x] Checkpoint and push to GitHub (Round 2)

### Claude Follow-Up Feedback (Apr 23, Round 3)
- [x] Implement EVIDENCE_HMAC_KEY separation from JWT_SECRET in evidence-integrity.ts
- [x] Add dedicated evidence key lifecycle management (rotation without breaking historical chains)
- [x] Expand graduation threat model: adversarial target responses crafted to maximize apparent success
- [x] Expand graduation threat model: statistical drift detection on graduation scores (slow poisoning)
- [x] Add cross-customer consent: reviewer checklist for customer-data scrubbing at quarantine approval
- [x] Add cross-customer consent: ROE schema clause for shared catalog contribution consent
- [x] Characterize test suite beyond count: unit vs integration, adversarial vs happy-path
- [x] Disclose which 3 OWASP LLM Top 10 categories are pending in §10.3
- [x] Add separation-of-duties note for admin roles in §8.3
- [x] Fix CMMC row in §7 to reference NIST SP 800-171 control equivalents
- [x] Add Level 1 validation caveat implication for federal procurement in §7.1
- [x] Change §12 to "internally strengthened" language
- [x] Write vitest tests for HMAC key separation (68 total tests passing)
- [x] Generate v4 spec document with all corrections
- [x] Checkpoint and push to GitHub (Round 3)
- [x] Generate dedicated Graduation Engine deep-dive response document for Claude

### Claude Follow-Up Feedback (Apr 23, Round 4)
- [x] Implement two-person sign-off for graduation promotion events (LLM caller → deterministic, model tier advancement)
- [x] Add drift detection operational gating: auto-block graduation when detectors fire + alert operators
- [x] Log graduation promotion events to evidence integrity chain (tamper-evident records)
- [x] Create OWASP LLM08 (Excessive Agency) preliminary test suite (13 cases)
- [x] Create OWASP LLM09 (Overreliance) preliminary test suite (13 cases)
- [x] Set specific migration deadline for reviewer checklist (2026-07-01)
- [x] Document downstream actions for each drift detector (block/hold/audit)
- [x] Write vitest tests for Round 4 changes (92 total tests passing)
- [x] Generate v5 spec document with all corrections
- [x] Generate Graduation Engine deep-dive v3
- [x] Checkpoint and push to GitHub (Round 4)

### Hybrid Scoring System Deep Dive (Apr 23)
- [x] Research CARVER scoring implementation end-to-end
- [x] Research CVSS scoring implementation and integration
- [x] Research BIA data capture and scoring
- [x] Trace hybrid scoring integration (CARVER + CVSS + BIA)
- [x] Research scoring data sources, enrichment pipelines, and persistence
- [x] Write comprehensive hybrid scoring deep-dive document for Claude
- [ ] Checkpoint and push to GitHub
