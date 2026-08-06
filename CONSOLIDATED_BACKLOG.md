# AC3 Platform — Consolidated Prioritized Backlog

**Source:** All diagnosed issues from Claude conversations, analysis documents, error dashboard, and code audit.
**Date:** May 5, 2026
**Scope:** Bugs, architectural debt, integration gaps, and pipeline failures — not feature proposals.

---

## Tier 0 — Active Bugs (Broken in Production)

These are confirmed broken behaviors observed on the live platform.

| # | Issue | Source | Impact |
|---|-------|--------|--------|
| T0-1 | **Exploit pipeline produces 0 successful exploits** — vuln-to-exploit selection, LLM generation, and execution all fail. Broken Crystals engagement confirmed 0 exploits landed. | broken-crystals-review.md | Engagement pipeline cannot prove vulnerabilities are exploitable |
| T0-2 | **React boundary crash: "Spread syntax requires ...iterable"** — 43 occurrences, latest Mar 25. Active in production. | error-dashboard-findings.md | Users hit white screen crash |
| T0-3 | **React boundary crash: "Cannot access 'T' before initialization"** — 5 occurrences, latest Mar 26. Circular import or hoisting. | error-dashboard-findings.md | Users hit white screen crash |
| T0-4 | **React boundary crash: "undefined is not an object (evaluating 'a.includes')"** — 13 occurrences. Null safety. | error-dashboard-findings.md | Users hit white screen crash |
| T0-5 | **DI Report PDF: Prioritized Recommendations page is completely blank** — the most actionable section renders nothing. | notes-catalyic-review.md, notes-pdf-review.md | Customers receive a report with an empty recommendations page |
| T0-6 | **DI Report PDF: Exploit table is ALL "Unknown/N/A"** — 180 rows of useless data with no source, module, or technology. | notes-catalyic-review.md | Report credibility undermined |
| T0-7 | **DI Report PDF: Confirmed Findings count mismatch** — cover/appendix say 0, exec summary says 39. `_confirmedVulnFindings` uses strict CVE filter while BLUF uses observation corroboration. | notes-pdf-review.md | Contradictory data in the same report |
| T0-8 | **Registration Risk false positives** — Transfer lock and Delete lock show "not set" when they ARE set. Root cause: status string comparison fails because RDAP returns "client transfer prohibited" (with spaces) but code checks for "clienttransferprohibited" (no spaces). | notes-reg-risk-bugs.md | False risk findings in customer reports |
| T0-9 | **Conditional hook call: "Rendered more hooks than during previous render"** — 2 occurrences, latest Mar 25. | error-dashboard-findings.md | Intermittent React crash |
| T0-10 | **ZAP scanned wrong application** — ZAP targeted port 8443 (Nextcloud) instead of the actual target app. Pipeline doesn't scan all discovered HTTP ports. | broken-crystals-review.md | Scanner misses the actual target |

---

## Tier 1 — Architectural Debt (Limits Platform Capability)

These are structural issues that prevent major subsystems from functioning as designed.

| # | Issue | Source | Impact |
|---|-------|--------|--------|
| T1-1 | **ScanForge NOT wired into engagement pipeline** — exists as standalone REST API but engagement orchestrator still uses Nuclei + ZAP + Hydra directly via SSH. | research-scanforge-improvements.md | All ScanForge intelligence (context engine, TI enrichment, FP/FN prevention, dedup) is unused in real engagements |
| T1-2 | **Discovery Context Engine orphaned from DI pipeline** — 1785 lines, 5 LLM specialists built but only exposed as manual tRPC endpoints. DI pipeline uses simpler monolithic `analyzeAssets()` LLM call instead. | Context audit (this session) | Sophisticated asset attribution, lifecycle, business context, and threat relevance analysis never runs automatically |
| T1-3 | **Actor Context Provider only consumed by C2 phase** — 1475 lines, 11 data sources, but engagement orchestrator scan planning uses only the simpler `buildThreatActorLearningContext()`. | Context audit (this session) | Scan planning and exploitation phases lack full threat actor intelligence |
| T1-4 | **Engagement orchestrator is 8573 lines in one file** — monolithic, untestable, impossible to debug individual phases. | Code audit | Any change risks breaking unrelated phases; no unit testing possible |
| T1-5 | **No Knowledge Base (KB) system** — OpenVAS uses Redis-backed KB for cross-test state sharing. ScanForge has template-level state only. | research-openvas-gaps.md | Templates cannot share discovered state (e.g., service fingerprints informing vuln checks) |
| T1-6 | **No SMB/CIFS or SNMP protocol handlers** — critical for internal network scanning (AD environments, IoT/OT). | research-openvas-gaps.md | Cannot scan Windows file shares, AD services, or SNMP devices |
| T1-7 | **Attack path analysis is catalog-only** — 13 patterns defined but not dynamically evaluated against real enumeration data. | CLOUD_SCANNING_GAP_ANALYSIS.md | Cloud attack paths are theoretical, not validated against actual infrastructure |
| T1-8 | **Connector catalog missing 34 connectors** — `getConnectorCatalog` hardcoded list is stale, missing recent additions. | audit-di-coverage.md | OSINT Sources tab shows incomplete picture to users |
| T1-9 | **AC3 Report: No engagement timeline events** — report pipeline can't access ops snapshot data. | AC3_REPORT_GAP_ANALYSIS.md | Reports lack temporal narrative of what happened during engagement |
| T1-10 | **Breach credentials not operationalized** — DeHashed finds breaches but doesn't populate credential attack lists. | OSINT_AUDIT_FINDINGS.md | Discovered credentials never feed into exploitation phase |

---

## Tier 2 — Report Quality Issues (Customer-Facing)

These degrade the quality of deliverables customers receive.

| # | Issue | Source | Impact |
|---|-------|--------|--------|
| T2-1 | **CVE section takes 5 pages with repetitive affected asset lists** — same 10 assets listed per CVE when they share an IP. Needs grouping by IP/service. | notes-catalyic-review.md | Report bloat, unprofessional appearance |
| T2-2 | **Recommendations text truncated with "..."** — the most actionable section is cut off. | notes-catalyic-review.md | Customers can't read full remediation guidance |
| T2-3 | **CVSS shows "N/A" for all CVEs** — not pulling from NVD data. | notes-catalyic-review.md | Missing industry-standard severity metric |
| T2-4 | **Phishing Difficulty wording contradictory** — "DIFFICULT (HIGH RISK)" is confusing. Is it difficult to phish (good) or high risk of phishing (bad)? | notes-pdf-review.md | Customers misinterpret risk |
| T2-5 | **Double footer on cover page** — overlapping CONFIDENTIAL lines. | notes-pdf-review.md, notes-catalyic-review.md | Unprofessional appearance |
| T2-6 | **Empty pages waste space** — Breach (p8), Dark Web (p9) are nearly blank when no data. Should combine or skip. | notes-pdf-review.md | Report feels padded |
| T2-7 | **Mission function values show underscores** — "public_facing_services" instead of "Public Facing Services". | notes-catalyic-review.md | Unprofessional appearance |
| T2-8 | **Compliance table text truncation** — category and remediation columns cut off. | notes-pdf-review.md | Customers can't read compliance details |
| T2-9 | **Technology deduplication** — "Express" and "Express.js" listed separately. | notes-pdf-review.md | Noisy, inflated tech stack |
| T2-10 | **AC3 Report: ATT&CK technique IDs not auto-extracted per finding** | AC3_REPORT_GAP_ANALYSIS.md | Reports lack MITRE mapping |

---

## Tier 3 — Integration Gaps (Subsystems Not Connected)

These represent built capabilities that aren't wired together.

| # | Issue | Source | Impact |
|---|-------|--------|--------|
| T3-1 | **No OOB detection mechanism** — blind SSRF, blind XSS, blind SQLi cannot be detected. No Interactsh or callback server integrated. | research-scanforge-improvements.md | Entire class of blind vulnerabilities missed |
| T3-2 | **No authenticated scanning** — ScanForge has no cookie/token injection for authenticated scans. | research-scanforge-improvements.md | Post-auth attack surface invisible |
| T3-3 | **No API spec import** — cannot parse OpenAPI/Swagger/Postman for endpoint discovery. | research-scanforge-improvements.md | API testing requires manual endpoint entry |
| T3-4 | **Darkweb intel is generic IOC ingestion** — no domain-specific darkweb searches. Missing IntelX, Hudson Rock, LeakCheck. | OSINT_AUDIT_FINDINGS.md | No targeted darkweb intelligence per customer |
| T3-5 | **No scheduled/recurring cloud scans** — all cloud scans are manual one-shot. No drift detection. | CLOUD_SCANNING_GAP_ANALYSIS.md | Cloud security posture not monitored over time |
| T3-6 | **Cross-module enrichment not linked** — Prowler findings not correlated with Trivy container vulns or resource enum data. | CLOUD_SCANNING_GAP_ANALYSIS.md | Cloud findings are siloed |
| T3-7 | **No Kubernetes cluster scanning** — Trivy supports `trivy k8s` but not wired. | CLOUD_SCANNING_GAP_ANALYSIS.md | K8s clusters not assessed |
| T3-8 | **Test Lab not in sidebar** — 6 routes, full backend router, but inaccessible from navigation. | review-findings.md | Feature exists but users can't find it |
| T3-9 | **No manual IOC/finding entry** — cannot add custom indicators or manual findings to an engagement. | OSINT_AUDIT_FINDINGS.md | Operators can't supplement automated findings |
| T3-10 | **No company intel override** — cannot manually correct/supplement LLM-inferred org profile. | OSINT_AUDIT_FINDINGS.md | Incorrect org classification can't be fixed |

---

## Tier 4 — Pipeline Gaps (Missing Scan Capabilities)

| # | Issue | Source | Impact |
|---|-------|--------|--------|
| T4-1 | **ZAP doesn't scan all discovered HTTP ports** — only targets 80/443/8443, misses custom ports found by RustScan. | broken-crystals-review.md | Web apps on non-standard ports missed |
| T4-2 | **Burp Suite returns 0 issues** — 16-second scan suggests it didn't actually crawl the application. | broken-crystals-review.md | Burp integration may be non-functional |
| T4-3 | **ScanForge produced 0 findings** — 37 templates executed, 0 matches. Templates don't match real attack surfaces. | broken-crystals-review.md | ScanForge template library ineffective |
| T4-4 | **No service detection engine** — no native service fingerprinting (relies entirely on nmap). | research-openvas-gaps.md | Limited protocol identification |
| T4-5 | **No local security checks** — cannot compare installed packages against known vulnerable versions (requires agent). | research-openvas-gaps.md | Package-level vulns invisible without agent |
| T4-6 | **GCP resource enumeration is partial** — missing Cloud Functions, Cloud SQL, Audit Logs. | CLOUD_SCANNING_GAP_ANALYSIS.md | Incomplete GCP coverage |

---

## Recommended Work Order

Based on customer impact, effort, and dependency chains:

**Sprint 1 (Immediate — fixes broken production behavior):**
1. T0-2, T0-3, T0-4, T0-9 — Fix React boundary crashes (investigate spread/iterable, circular import, null safety, conditional hooks)
2. T0-5 — Fix blank Prioritized Recommendations page in DI report
3. T0-6 — Filter out Unknown/N/A exploit rows from report
4. T0-7 — Align Confirmed Findings count between cover and exec summary
5. T0-8 — Fix RDAP status string comparison (strip spaces before matching)

**Sprint 2 (Report quality — customer deliverables):**
6. T2-1 — Group CVEs by IP/service to compact the section
7. T2-2 — Remove text truncation in recommendations
8. T2-3 — Pull CVSS from NVD data
9. T2-5, T2-6, T2-7, T2-8, T2-9 — Layout/formatting fixes (batch)
10. T2-4 — Fix phishing difficulty wording

**Sprint 3 (Exploit pipeline — core engagement value):**
11. T0-1 — Fix exploit pipeline end-to-end (vuln selection → LLM generation → execution → verification)
12. T0-10 — Fix ZAP port targeting (scan all discovered HTTP ports)
13. T4-1 — Same as T0-10 (ZAP port coverage)
14. T4-2 — Investigate Burp connectivity/timeout

**Sprint 4 (Architecture — unlock subsystem value):**
15. T1-1 — Wire ScanForge into engagement pipeline as parallel phase
16. T1-2 — Wire Discovery Context Engine into DI pipeline
17. T1-3 — Wire Actor Context Provider into engagement orchestrator scan planning
18. T1-4 — Extract engagement orchestrator phases into separate modules

**Sprint 5 (Integration gaps — complete the platform):**
19. T1-8 — Update connector catalog with all 34 missing entries
20. T3-1 — Integrate Interactsh for OOB detection
21. T3-8 — Add Test Lab to sidebar navigation
22. T1-10 — Wire DeHashed breach credentials into credential attack lists

---

## Items Added Per Claude's Review (May 5)

The following diagnosed issues were identified in previous Claude conversations but missing from the initial backlog:

| # | Issue | Tier | Sprint |
|---|-------|------|--------|
| T2-11 | **CARVER feedback loop ordering bug** — Stage 3.99 uses pre-feedback scores; Stage 3.995 adjusts CARVER based on attack paths computed with stale scores. Scoring inconsistency in customer reports. | Tier 2 | Sprint 2 |
| T1-11 | **ScanForge YAML parser swap** — Uses custom parser; needs swap to `yaml` npm package for production reliability. | Tier 1 | Sprint 4 |
| T1-12 | **FAST_TRACK_RULES too aggressive** — 1 engagement / 3 scans threshold promotes templates to production too quickly. | Tier 1 | Sprint 4 |
| T1-13 | **Proof engine safety profile undefined** — No explicit operational definition of what "safe" proof attempts mean against customer infrastructure. Must be defined before proof attempts run in production. | Tier 1 | Sprint 4 |
| T1-14 | **Dedup fingerprint over-merging web findings** — Findings that share target + port + CVE but differ in endpoint get incorrectly merged. | Tier 1 | Sprint 4 |
| T1-15 | **Confidence framework reconciliation** — Corroboration multipliers and CARVER confidence run as separate unreconciled systems. | Tier 1 | Sprint 4+ |

**Claude's sprint ordering adjustment (adopted):**
- T0-1 (exploit pipeline) investigation moved to Sprint 1 (diagnosis only); fix remains Sprint 3
- T1-4 (orchestrator decomposition) stays Sprint 4 but noted that Sprint 3 exploit work inside the 8573-line monolith will be harder

---

## Items NOT Included

The following were intentionally excluded from this backlog:

- **Context engine architecture** — solid design, just needs wiring (covered as T1-2, T1-3)
- **New feature proposals** — no Polymarket feeds, no STIX/TAXII servers, no white-labeling
- **AWS migration** — blocked by IAM role creation (external dependency)
- **DNS security checks** — already tracked in todo.md with 20+ items, not a diagnosed bug
- **VA/Bug Bounty engagement types** — feature work, not debt
- **License tier enforcement** — business decision, not technical debt
