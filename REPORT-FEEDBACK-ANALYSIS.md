# Report Quality Feedback Analysis

**Source:** Claude review of criticalsec.com DI Report + BrokenCrystals Pentest Report  
**Date:** 2026-05-06  
**Analyst:** Harrison Cook — AceofCloud

---

## Executive Summary

The feedback identifies **27 distinct issues** across both reports. These collapse into **7 systemic root causes** rather than isolated bugs. Fixing the root causes eliminates entire classes of defects simultaneously.

| Priority | Root Cause | Issues Affected | Fix Complexity |
|----------|-----------|-----------------|----------------|
| P0 | Exploit result classification logic | 4 issues | Medium |
| P0 | Vendor-asset attribution in discovery | 3 issues | Medium |
| P0 | Tool execution failure detection | 3 issues | Low |
| P1 | Count reconciliation (single source of truth) | 5 issues | Medium |
| P1 | LLM-generated content quarantine | 4 issues | Medium |
| P2 | DNSBL false-positive detection | 2 issues | Low |
| P2 | Template/rendering bugs | 6 issues | Low-Medium |

---

## Root Cause 1: Exploit Result Classification (P0 — Credibility Killer)

### Symptoms
- E-2, E-3, E-4, E-5 marked `SUCCEEDED` but PoC output says `EXPLOIT_FAILED`
- Access level = `none`, shell = `No`, but status = `SUCCEEDED`
- All exploit attempts returned `{"error":"Invalid or missing X-Scan-Key"}` (HTTP 401)

### Root Cause
The success/failure classifier checks whether the HTTP request returned a response (status code exists) rather than whether the exploit achieved its objective. The classification logic in the exploit pipeline evaluates:
```
response received? → SUCCEEDED
```
Instead of:
```
access_level != "none" AND proof does not contain "FAILED" → SUCCEEDED
```

### Code Location
- `server/lib/enhanced-exploit-orchestration.ts` — result classification after exploit execution
- `server/lib/engagement-phase-exploitation.ts` — summary aggregation

### Fix
Add multi-field validation before marking an exploit as SUCCEEDED:
1. `access_level` must be != "none"
2. `proof` text must NOT contain "EXPLOIT_FAILED", "FAILED", "error", "401", "403"
3. If `X-Scan-Key` error detected → mark as `BLOCKED_AUTH` (new status)
4. Add schema validation: refuse to emit report if `status=SUCCEEDED + access_level=none`

---

## Root Cause 2: Vendor-Asset Attribution (P0 — Credibility Killer)

### Symptoms
- `google.com` and `googlemail.com` appear in customer's attack surface
- MX target hostnames treated as discovered subdomains
- Google's sign-in page listed as customer's "Login Form Discovered"
- Mail Server F-grade assigned to vendor-managed infrastructure

### Root Cause
The asset discovery pipeline treats MX/NS/CNAME target hostnames as customer-owned assets. The existing `MANAGED_HOST_PATTERNS` taxonomy (Sprint 7 backlog item) isn't applied early enough in the pipeline — assets get graded before vendor classification removes them.

### Code Location
- `server/domainIntel.ts` — asset discovery and classification
- `server/lib/export-di-report.ts` — grading sections that include vendor assets
- Asset discovery modules that resolve MX/NS records

### Fix
1. Apply vendor-domain allowlist BEFORE grading (not after)
2. Expand `MANAGED_HOST_PATTERNS` to include: `google.com`, `googlemail.com`, `*.google.com`, `*.googleapis.com`, `*.gstatic.com`, `outlook.com`, `*.outlook.com`, `*.office365.com`
3. When a vendor-managed asset is detected, exclude it from:
   - Web Security Analysis grades
   - Login Form Discovery
   - Attack Surface Inventory (move to separate "Supply Chain Context" section)
4. Mail Server grade: if mail is vendor-managed, label as "Vendor Infrastructure (informational, not scored)"

---

## Root Cause 3: Tool Execution Failure Detection (P0 — Silent Failures)

### Symptoms
- testssl: exit code 127 (command not found)
- zap: ran 0.1 seconds, exit -1
- katana: ran 11ms, exit -1
- nerva, paramspider, naabu, httpx: all returned -1
- Engagement marked "completed" despite catastrophic tool failures
- `X-Scan-Key` placeholder not replaced → all exploits blocked

### Root Cause
The engagement completion logic doesn't gate on tool execution success rate. A phase can "complete" even if 90% of tools failed. The pre-engagement health check (Sprint 5) validates SSH connectivity but doesn't validate individual tool availability or credential configuration.

### Code Location
- `server/lib/engagement-orchestrator.ts` — phase completion logic
- `server/lib/scan-server-executor.ts` — tool execution result handling
- `server/lib/scan-server-inventory.ts` — tool inventory (already built but not gating)

### Fix
1. Add **minimum tool success threshold** per phase (e.g., ≥50% of planned tools must succeed)
2. If threshold not met → mark phase as `DEGRADED` (not `completed`)
3. Add `X-Scan-Key` validation to pre-engagement health check
4. Report must disclose tool failure rate in Appendix (already partially done in Appendix D)
5. If engagement has >50% tool failures, add prominent "DEGRADED ENGAGEMENT" banner to cover page

---

## Root Cause 4: Count Reconciliation (P1 — Professional Quality)

### Symptoms
- Cover: "13 discovered assets" vs. Attack Surface table: 8 assets
- Cover: "Confirmed Findings: 17" vs. Exec Summary: "25 findings (17 confirmed, 8 potential)" vs. Web Security: "48 security findings"
- KEV: Exec summary says "6 CISA KEV matches" vs. Vuln section says "8 findings matched"
- Pentest: Asset summary says "23 vulns" but report has 5 findings
- "10 Total Open Ports" but only 3 rows shown

### Root Cause
Counts are computed independently in each section from different filtered views of the same data. No single source of truth exists. The cover page, exec summary, body sections, and appendices each apply their own filters and arrive at different numbers.

### Code Location
- `server/lib/export-di-report.ts` — multiple independent count computations (lines 814, 1200, 6149)
- Pentest report renderer — similar pattern

### Fix
1. Compute ALL counts ONCE at report-build time in a `ReportMetrics` object
2. Inject `ReportMetrics` into every section (cover, exec summary, body, appendix)
3. Add a **post-generation count reconciliation linter** that:
   - Extracts all numeric claims from rendered text
   - Compares against actual table row counts
   - Flags mismatches as build errors (not warnings)
4. For KEV: only count matches where product AND version are confirmed (not "potential")

---

## Root Cause 5: LLM-Generated Content Quarantine (P1 — Credibility)

### Symptoms
- "Operational Security Gaps" section contains OWASP categories without evidence (passive scan)
- AC3-017 and AC3-018 have "Tool: LLM Inference Engine" as their only source
- LLM-inferred findings included in findings count and Risk Matrix
- "Very High Likelihood" assigned to low-confidence LLM inferences
- Stale "LOW risk rating" sentence in exec summary (template residual)
- "Confidence in overall LOW risk rating" when actual rating is MEDIUM

### Root Cause
LLM-generated content is not distinguished from evidence-based findings in the data model. The `finding` schema doesn't have a `source_type` field that separates scanner evidence from LLM inference. Additionally, LLM prompt templates contain example values that sometimes persist into output.

### Code Location
- `server/lib/engagement-orchestrator.ts` — LLM scan plan generation
- `server/lib/export-di-report.ts` — Cross-Module Intelligence section
- Pentest report renderer — findings aggregation
- LLM prompt templates for exec summary generation

### Fix
1. Add `source_type: "scanner" | "llm_inference" | "manual"` to finding schema
2. LLM-inferred findings:
   - Excluded from main findings count
   - Excluded from Risk Matrix
   - Rendered in separate "Hypotheses for Investigation" section
   - Different visual treatment (dashed border, italic, "INFERRED" badge)
3. Risk Matrix: Likelihood must factor in confidence level (low confidence → max "Medium" likelihood)
4. Add post-generation linter: if narrative text contains a risk rating word that doesn't match computed rating → build error
5. Validate all prompt-template variables are non-default before emission

---

## Root Cause 6: DNSBL False-Positive Detection (P2)

### Symptoms
- URIBL TXT record says "Query Refused" but report treats it as a listing
- False positive propagates into "2 actionable DNSBL listings" count
- Existing False Positive Analysis section missed the obvious "Query Refused" indicator

### Root Cause
The DNSBL checker doesn't parse TXT record content for query-state errors. It treats any non-empty response as a positive listing.

### Code Location
- `server/lib/vuln-feeds.ts` or DNSBL checking module
- `server/domainIntel.ts` — DNSBL result processing

### Fix
Add a DNSBL response validator that checks for:
- "refused" / "rate" / "blocked" in TXT content
- Links to provider's refused/abuse page (e.g., `uribl.com/refused`)
- Known error response patterns per provider
If detected → classify as `query_error` (not `listed`) and exclude from actionable count.

---

## Root Cause 7: Template/Rendering Bugs (P2)

### Symptoms
- `[object Object], [object Object]` in Risk Signals column (JS serialization bug)
- Suricata rules truncated mid-string
- Sigma rules are generic templates, not findings-specific
- "exploitation narrative could not be generated due to a processing error" left in report
- "Findings have not been manually verified" vs. "All findings validated through manual testing" (contradiction)
- CLOSED ports listed with open-port recommendations (column mapping bug)
- "10 Total Open Ports" header but only 3 rows shown

### Code Location
- Pentest report renderer — `JSON.stringify` missing or `.toString()` on object arrays
- `server/lib/export-di-report.ts` — Suricata rule string truncation (PDF column width)
- Sigma rule generator — template-based, not findings-aware
- Port table renderer — state field mapping

### Fix
1. `[object Object]` → Add `JSON.stringify()` or proper field extraction for Risk Signals
2. Suricata truncation → Use `overflow: 'linebreak'` or move to code block with smaller font
3. Sigma rules → Either generate findings-specific rules or omit for non-applicable findings
4. Processing error messages → Catch and replace with professional fallback text
5. Manual verification contradiction → Use single `verification_status` field, render consistently
6. Port state mapping → Verify column alignment in table renderer
7. "10 ports / 3 rows" → Add "showing top N of M" or render all rows

---

## Pentest-Specific Issues (Additional)

| Issue | Category | Fix |
|-------|----------|-----|
| C2 section shows paused operation with 0 agents | Template logic | Skip C2 section if `agents === 0` |
| ROE fields all N/A | Template logic | For real engagements: require ROE upload; for labs: label as "Training Exercise — ROE N/A" |
| "raw" and "none" listed as tools | Data cleanup | Filter tool list to exclude non-tool entries |
| "sqlmap-blind" listed separately from sqlmap | Data cleanup | Consolidate tool variants |
| Tool appendix shows tools that never executed | Rendering logic | Only list tools that produced output or ran >1s |

---

## DI-Specific Issues (Additional)

| Issue | Category | Fix |
|-------|----------|-----|
| Compliance section conflates CIS + STIG + NIST 800-53 | Framework logic | Split scores by framework OR rename to "External Hygiene Checks (limited subset)" |
| Domain registration "N/A" but asserts locks missing | Logic error | If RDAP data unavailable → "Could not confirm" (not "missing") |
| Data source transparency weak | Reporting | Disclose which intelligence categories had degraded coverage in exec summary |
| 28 sources queried but 14 skipped (no API keys) | Reporting | Show "14/28 sources active" with list of unavailable sources |

---

## Implementation Priority Order

### Phase 1 — Immediate (Credibility Fixes)
1. Exploit result classification validation (Root Cause 1)
2. Vendor-asset exclusion before grading (Root Cause 2)
3. Tool failure gating + degraded engagement banner (Root Cause 3)

### Phase 2 — Next Sprint (Professional Quality)
4. Single-source-of-truth count reconciliation (Root Cause 4)
5. LLM content quarantine + source_type field (Root Cause 5)
6. Post-generation validation linter (combines RC4 + RC5 + RC6)

### Phase 3 — Polish
7. DNSBL false-positive detection (Root Cause 6)
8. Template/rendering bug fixes (Root Cause 7)
9. Pentest-specific template logic fixes

---

## Proposed Report Validation Linter

A final-stage validation pass that runs after report generation but before PDF emission:

```
CHECKS:
├── count_reconciliation     → compare claimed counts vs actual table rows
├── rating_consistency       → verify rating words match computed scores
├── exploit_status_validate  → refuse SUCCEEDED + access_level=none
├── vendor_asset_exclusion   → flag vendor domains in customer grade sections
├── dnsbl_response_validate  → detect "refused"/"rate" in TXT records
├── llm_content_quarantine   → verify source_type=llm_inference not in main findings
├── object_serialization     → detect "[object Object]" in rendered text
├── template_residual        → detect placeholder/example values in output
├── tool_failure_threshold   → flag if >50% tools failed
└── section_contradiction    → detect opposing claims (verified vs not verified)
```

Each check returns PASS/WARN/FAIL. FAIL blocks report emission. WARN adds a "Quality Advisory" note to the report cover.
