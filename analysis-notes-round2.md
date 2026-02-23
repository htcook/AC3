# Round 2 Competitive Analysis - Working Notes

## Previous Analysis Gaps Identified (from ace-c3-platform-analysis.md)

### P0 Gaps (Critical)
1. Cross-Source Corroboration Engine - reduce FP by 30-40%
2. Dynamic CVE-to-Product Matching - eliminate stale mappings
3. Closed-Loop Remediation Verification - match Horizon3 1-Click Verify

### P1 Gaps
4. Compensating Control Awareness - contextual scoring
5. Exploit Confidence Pre-Flight Checks - reduce wasted attempts
6. Active Verification Probes (Nuclei integration)

### P2 Gaps
7. Temporal Decay Scoring
8. Attack Chain Validation - prove chained impact
9. Exploit Module Feedback Loop

### P3 Gaps
10. LLM-Powered Rule Generation (replace hardcoded templates)
11. Rule Validation Against Evidence

### Competitive Gaps from competitive-analysis.md
- BAS: Cymulate, Picus, SafeBreach, AttackIQ
- Auto Pentest: Pentera ($100M+ ARR), Horizon3 NodeZero
- Vuln Scanners: Nessus, Qualys, Rapid7
- C2: Cobalt Strike, Sliver, Brute Ratel
- EASM: CyCognito, Censys, BitSight

### Module Accuracy Ratings (previous)
- 18/20 modules rated "Good"
- 2/20 rated "Moderate" (KEV Service, Rule Generator)
- 0/20 rated "Excellent"

## Features Added Since Last Analysis (need to inventory from todo.md)
- ROE Upload UI + compliance workflow
- ROE Warning Banners on offensive pages
- Compliance & Authorization section in reports
- Offensive audit log system
- ROE guardrails (roe-guard.ts)
- Purple Team module
- Emulation Playbooks
- Validation Engine enhancements
- Domain Intel gap analysis improvements
- Evidence capture improvements
- Cross-source corroboration (need to verify)
- Dynamic CVE matching (need to verify)
