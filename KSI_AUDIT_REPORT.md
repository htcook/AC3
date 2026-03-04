# ACE C3 — Key Security Indicators (KSI) Comprehensive Audit Report

**Date:** March 3, 2026  
**Scope:** Full audit of all 58 FedRAMP KSIs across 11 themes  
**Platform:** ACE C3 Caldera Dashboard  

---

## Executive Summary

The ACE C3 platform implements a comprehensive KSI framework with 58 FedRAMP Key Security Indicators organized across 11 compliance themes. The architecture includes evidence collection (manual + automated), SHA-256 hash-chained evidence integrity, validation scheduling, threat-to-KSI mapping (MITRE ATT&CK), and auto-collection from 17 source modules. However, the audit reveals significant gaps between the framework's design and its operational state: **only 8 of 58 KSIs have any evidence**, the NIST SP 800-53 control mappings table is empty, 72 validation runs are stuck in "running" status, and evidence is heavily skewed toward threat-intel data (96% of all evidence items).

---

## 1. Architecture Inventory

### 1.1 Database Tables

| Table | Rows | Purpose | Status |
|-------|------|---------|--------|
| `ksi_definitions` | 58 | KSI catalog (all 58 FedRAMP KSIs) | **Fully seeded** |
| `ksi_evidence` | 15,411 | Evidence items with SHA-256 hash chaining | **Heavily skewed** — 96% threat-intel |
| `ksi_evidence_chains` | 144 | Named evidence chains per KSI | **Active** — all valid |
| `ksi_control_mappings` | **0** | NIST SP 800-53 control mappings | **EMPTY — Critical gap** |
| `ksi_validation_runs` | 288 | Validation execution records | **72 stuck in "running"** |
| `ksi_validation_schedules` | 58 | Per-KSI validation schedules | **51 enabled, 7 disabled** |

### 1.2 Server-Side Modules

| Module | File | Capabilities |
|--------|------|-------------|
| Evidence Chain Router | `ksi-evidence-chain.ts` | Collect evidence, create chains, verify integrity, seed catalog |
| Auto-Collector Router | `ksi-auto-collector.ts` | 17 source-to-KSI mappings, individual + sweep collection |
| Validation Scheduler | `ksi-validation-scheduler.ts` | Schedule init, start/complete validation, overdue tracking |
| Threat Map Router | `ksi-threat-map.ts` | MITRE ATT&CK technique-to-KSI mapping, threat actor coverage |
| Scheduled Collection | `ksi-scheduled-collection.ts` | Cadence-based auto-collection with live scanner dispatch |
| Continuous Monitoring | `ksi-continuous-monitoring.ts` | Compliance scoring, drift detection, alert generation |
| Live Scanner API | `live-scanner-api.ts` | Caldera, GoPhish, ZAP, Shodan, SecurityTrails, URLScan, abuse.ch |

### 1.3 Frontend Pages

| Page | Route | Features |
|------|-------|----------|
| KSI Dashboard | `/ksi-dashboard` | Overview stats, validation runs, evidence stats, alerts |
| Evidence Chain | `/ksi-evidence-chain` | Evidence list, chain management, integrity verification |
| Validation Scheduler | `/ksi-validation` | Schedule management, run history, overdue alerts |
| Auto-Collector | `/ksi-auto-collector` | Source mappings, individual/sweep collection, stats |
| Threat Map | `/ksi-threat-map` | MITRE ATT&CK coverage matrix, threat group mappings |

---

## 2. KSI Coverage Analysis

### 2.1 Coverage by Theme

| Theme | Code | Total KSIs | Direct | Supporting | Planned | Evidence? |
|-------|------|-----------|--------|------------|---------|-----------|
| Authorization by FedRAMP | AFR | 8 | 3 | 4 | 0 | **None** |
| Change Management | CMT | 4 | 2 | 2 | 0 | **None** |
| Cloud Native Architecture | CNA | 8 | 4 | 4 | 0 | **None** |
| Cybersecurity Education | CED | 4 | 1 | 3 | 0 | **None** |
| Identity & Access Mgmt | IAM | 8 | 6 | 2 | 0 | **2 KSIs** (216 items) |
| Incident Response | INR | 7 | 5 | 0 | 0 | **4 KSIs** (15,051 items) |
| Monitoring, Logging, Auditing | MLA | 5 | 3 | 1 | 0 | **2 KSIs** (144 items) |
| Policy & Inventory | PIY | 5 | 2 | 1 | 2 | **None** |
| Recovery Planning | RPL | 4 | 0 | 0 | 4 | **None** |
| Service Configuration | SVC | 8 | 5 | 2 | 1 | **None** |
| Supply Chain Risk | SCR | 2 | 1 | 1 | 0 | **None** |
| **Totals** | | **58** | **31** | **20** | **7** | **8 KSIs** |

### 2.2 Evidence Distribution

| KSI ID | Title | Evidence Count | Source |
|--------|-------|---------------|--------|
| KSI-INR-TIF | Threat Intelligence Feeds | 3,792 | threat-intel |
| KSI-INR-TIU | Threat Intelligence Usage | 3,792 | threat-intel |
| KSI-INR-IOC | Indicators of Compromise | 3,778 | threat-intel + osint |
| KSI-INR-IRP | IR Procedures | 3,689 | threat-intel |
| KSI-IAM-AAM | Account Lifecycle Mgmt | 144 | IAM Lifecycle Manager |
| KSI-IAM-MFA | MFA Enforcement | 72 | MFA Compliance Checker |
| KSI-MLA-OSM | SIEM Centralized Logging | 72 | SIEM Integration |
| KSI-MLA-LET | Log Event Types | 72 | Log Policy Manager |
| **50 KSIs** | **(no evidence)** | **0** | — |

### 2.3 Coverage Status Summary

- **Direct coverage (31 KSIs):** Platform claims direct measurement capability. Only 8 have evidence.
- **Supporting coverage (20 KSIs):** Platform provides supporting data. Zero have evidence.
- **Planned (7 KSIs):** Not yet implemented. All in RPL (4), PIY (2), SVC (1) themes.

---

## 3. Compliance Framework Mapping

### 3.1 FedRAMP Rev 5 Alignment

The 58 KSIs are directly derived from the FedRAMP Key Security Indicators framework. The platform's `KSI_CATALOG` in `ksi-evidence-chain.ts` maps each KSI to:
- Theme code and name
- Validation type (machine/human/mixed/tbd)
- Frequency (Continuous/Persistent/Ongoing/etc.)
- Coverage status
- ACE C3 module responsible

**Gap:** The `ksi_control_mappings` table (NIST SP 800-53 control-to-KSI mapping) is **completely empty**. The `sp800_53_controls` JSON field in `ksi_definitions` is also null for all records. This means there is no traceable link between KSIs and the underlying NIST controls they satisfy.

### 3.2 NIST SP 800-53 Rev 5 Mapping

The `KSI_TTP_CATALOG` in `ksi-threat-map.ts` maps KSIs to MITRE ATT&CK techniques, but the NIST SP 800-53 control mapping is absent from the database. The schema supports it (`sp800_53_controls` field, `ksi_control_mappings` table) but no data has been seeded.

**Required mapping (not yet populated):**

| KSI Theme | NIST 800-53 Control Families |
|-----------|------------------------------|
| AFR | CA (Assessment), RA (Risk Assessment), SA (System Acquisition) |
| CMT | CM (Configuration Management), SA (System Acquisition) |
| CNA | SC (System & Communications), AC (Access Control) |
| CED | AT (Awareness & Training), PM (Program Management) |
| IAM | IA (Identification & Authentication), AC (Access Control) |
| INR | IR (Incident Response), SI (System & Information Integrity) |
| MLA | AU (Audit & Accountability), SI (System & Information Integrity) |
| PIY | PM (Program Management), PL (Planning), CM (Configuration Management) |
| RPL | CP (Contingency Planning) |
| SVC | CM (Configuration Management), RA (Risk Assessment), SI (System & Information Integrity) |
| SCR | SR (Supply Chain Risk Management), SA (System Acquisition) |

### 3.3 MITRE ATT&CK Coverage

The `KSI_TTP_CATALOG` maps KSIs to specific ATT&CK techniques across 14 tactics. The threat map router provides:
- Technique-to-KSI coverage matrix
- Threat group-to-KSI mappings via threat actor catalog
- Exploit coverage summary
- Per-KSI threat reports

**Strength:** This is one of the most complete parts of the KSI module. The threat catalog cross-reference (`crossRefThreatCatalog`) actively links live scanner evidence to known threat actors.

### 3.4 SOC 2 Type II Alignment

| SOC 2 Trust Service Criteria | Relevant KSI Themes | Coverage |
|------------------------------|---------------------|----------|
| CC6 (Logical & Physical Access) | IAM | Partial — 2 of 8 KSIs have evidence |
| CC7 (System Operations) | MLA, SVC | Partial — 2 of 13 KSIs have evidence |
| CC8 (Change Management) | CMT | **None** — 0 of 4 KSIs have evidence |
| CC9 (Risk Mitigation) | SCR, INR | Partial — 4 INR KSIs have threat-intel |
| A1 (Availability) | CNA, RPL | **None** — 0 of 12 KSIs have evidence |
| C1 (Confidentiality) | CNA (encryption) | **None** |
| PI1 (Processing Integrity) | SVC | **None** |

### 3.5 ISO 27001:2022 Alignment

| ISO 27001 Annex A Domain | Relevant KSI Themes | Coverage |
|--------------------------|---------------------|----------|
| A.5 Organizational Controls | PIY, AFR | **None** |
| A.6 People Controls | CED | **None** |
| A.7 Physical Controls | — | Not in scope |
| A.8 Technological Controls | IAM, MLA, CNA, SVC, SCR, CMT, INR | Partial — 8 of 42 KSIs |

---

## 4. Critical Gaps Identified

### Gap 1: NIST SP 800-53 Control Mappings Not Seeded (CRITICAL)

**Impact:** Cannot demonstrate traceability between KSIs and NIST controls for FedRAMP authorization.  
**Current State:** `ksi_control_mappings` table has 0 rows. `sp800_53_controls` field in definitions is null.  
**Fix:** Seed the control mappings table with the standard KSI-to-control relationships.

### Gap 2: 50 of 58 KSIs Have Zero Evidence (HIGH)

**Impact:** 86% of KSIs show no compliance evidence. The dashboard will show near-zero compliance scores.  
**Current State:** Only 8 KSIs have evidence, and 4 of those are exclusively from threat-intel actor records.  
**Root Cause:** Auto-collection only runs when manually triggered. The "Full Collection Sweep" pulls from DB tables that may be empty for many source modules.  
**Fix:** (a) Seed initial evidence for KSIs that can be machine-validated from existing platform data, (b) implement scheduled auto-collection cron job.

### Gap 3: 72 Validation Runs Stuck in "running" Status (HIGH)

**Impact:** Validation dashboard shows inaccurate pass/fail rates. Stuck runs block re-validation.  
**Current State:** 72 of 288 runs have status "running" with no completion timestamp.  
**Fix:** Add a cleanup mechanism to mark stale "running" runs as "error" after a timeout period. Add a manual "cancel" button.

### Gap 4: Evidence Heavily Skewed to Threat-Intel (MEDIUM)

**Impact:** 96% of evidence (14,758 of 15,411) comes from threat actor records mapped to INR KSIs. This creates a misleading picture of compliance coverage.  
**Current State:** Each threat actor creates 4 evidence items (one per INR KSI), inflating counts.  
**Fix:** (a) Deduplicate — one evidence item per unique threat actor per KSI, (b) rebalance collection to prioritize under-represented KSIs.

### Gap 5: No Continuous Monitoring Cron Job (MEDIUM)

**Impact:** The `ksi-continuous-monitoring.ts` module defines scoring, drift detection, and alert generation, but there is no scheduled job that runs it.  
**Current State:** Module exists as pure library code. Never invoked automatically.  
**Fix:** Wire the continuous monitoring into the server's scheduled task system.

### Gap 6: Validation Runs Don't Actually Validate (MEDIUM)

**Impact:** "Start Validation" creates a run record but doesn't execute any real validation logic. Completion is manual.  
**Current State:** `startValidation` inserts a "running" record. `completeValidation` manually sets pass/fail. No automated checks.  
**Fix:** Implement actual validation logic for machine-type KSIs (check evidence freshness, count, hash integrity).

### Gap 7: Missing KSIs in Source Mapping (LOW)

**Impact:** Some KSIs referenced in `SOURCE_KSI_MAP` don't exist in the 58-KSI catalog.  
**Affected:** `KSI-SVC-VSR`, `KSI-SVC-VRM`, `KSI-SDE-SST`, `KSI-CNA-HCI`, `KSI-CNA-NSD`, `KSI-MLA-ALE`, `KSI-IAM-PRA`, `KSI-SCR-SAT`, `KSI-SCR-PEN`, `KSI-SCR-APT`, `KSI-PPM-PPR`, `KSI-PPM-PPI`  
**Fix:** Reconcile the source mapping KSI IDs with the actual catalog. Either add missing KSIs to the catalog or correct the mappings.

---

## 5. What's Working Well

1. **SHA-256 Hash Chaining:** Evidence integrity is properly implemented with hash chaining. Each evidence item references the previous hash, creating a tamper-evident chain.

2. **MITRE ATT&CK Threat Mapping:** The `KSI_TTP_CATALOG` provides detailed technique-to-KSI mappings across all 14 ATT&CK tactics. The threat actor cross-reference is functional.

3. **Live Scanner Integration:** Real API clients for Caldera, GoPhish, ZAP, Shodan, SecurityTrails, URLScan, and abuse.ch are properly implemented with graceful fallback.

4. **Auto-Collection Architecture:** The 17 source-to-KSI mappings are well-designed. Each source module maps to specific KSIs with appropriate evidence types.

5. **Validation Scheduling:** All 58 KSIs have validation schedules with appropriate frequencies based on their type (Continuous=24h, Persistent=72h, Ongoing=168h, etc.).

6. **Continuous Monitoring Library:** The scoring algorithm, drift detection, and alert generation logic is well-implemented (just not wired up).

---

## 6. Recommended Improvements (Priority Order)

### P0 — Critical (Block FedRAMP readiness)

1. **Seed NIST SP 800-53 Control Mappings** — Populate `ksi_control_mappings` with standard control-to-KSI relationships for all 58 KSIs.
2. **Fix Stuck Validation Runs** — Clean up 72 "running" runs. Add timeout/cancel mechanism.
3. **Reconcile KSI IDs** — Fix mismatched KSI IDs between `SOURCE_KSI_MAP` and `KSI_CATALOG`.

### P1 — High (Required for meaningful compliance reporting)

4. **Implement Machine Validation Logic** — For the 31 machine-type KSIs, implement automated validation that checks evidence freshness, count, and hash integrity.
5. **Wire Continuous Monitoring** — Connect the monitoring library to a scheduled job that runs compliance scoring and generates alerts.
6. **Broaden Evidence Collection** — Trigger auto-collection across all source modules, not just threat-intel. Prioritize IAM, MLA, CNA, and SVC themes.

### P2 — Medium (Improve accuracy and usability)

7. **Deduplicate Threat-Intel Evidence** — One evidence item per unique threat actor per KSI instead of bulk duplication.
8. **Add Evidence Expiration** — Implement the `expiresAt` field logic so stale evidence is flagged.
9. **Add Manual Evidence Upload** — Allow users to upload policy documents, attestations, and training records for human-validated KSIs.

### P3 — Low (Nice to have)

10. **OSCAL Export Integration** — Wire KSI evidence into the OSCAL export engine for automated SSP/SAR generation.
11. **Compliance Dashboard** — Add a unified compliance score dashboard showing all frameworks (FedRAMP, SOC 2, ISO 27001) with drill-down.
12. **Evidence Chain Visualization** — Add a visual timeline/graph of evidence chains per KSI.

---

## 7. Implementation Roadmap

| Phase | Items | Effort | Impact |
|-------|-------|--------|--------|
| **Immediate** | Fix stuck runs, reconcile KSI IDs | 1-2 hours | Unblocks dashboard accuracy |
| **Week 1** | Seed NIST mappings, implement machine validation | 4-6 hours | Enables compliance reporting |
| **Week 2** | Wire continuous monitoring, broaden collection | 4-6 hours | Automated compliance tracking |
| **Week 3** | Dedup evidence, add expiration, manual upload | 4-6 hours | Improves data quality |
| **Week 4** | OSCAL integration, compliance dashboard | 6-8 hours | Full compliance automation |

---

## Appendix A: KSI-to-Source Module Mapping

| Source Module | KSI IDs | Evidence Type | Data Source |
|---------------|---------|---------------|-------------|
| vuln-scanner | KSI-SVC-VSR, KSI-SVC-VRM, KSI-AFR-PVA | scan_result | vulnScanFindings table |
| web-app-scanning | KSI-SVC-VSR, KSI-SVC-VRM, KSI-SDE-SST | scan_result | webAppFindings table |
| nuclei-scanner | KSI-SVC-VSR, KSI-CNA-HCI, KSI-SDE-SST | scan_result | (no dedicated collector) |
| osint-recon | KSI-INR-TIF, KSI-INR-TIU, KSI-INR-IOC | api_response | osintFindings table |
| phishing-ops | KSI-SCR-SAT, KSI-SCR-PEN | test_result | phishingDrafts table |
| siem-connectors | KSI-MLA-LET, KSI-MLA-OSM, KSI-MLA-ALE | log_entry | (no dedicated collector) |
| edr-validation | KSI-MLA-OSM, KSI-MLA-ALE, KSI-SVC-VSR | test_result | edrTestResults table |
| ngfw-validation | KSI-CNA-NSD, KSI-MLA-ALE | test_result | ngfwValidationTests table |
| ad-attack-sim | KSI-IAM-MFA, KSI-IAM-AAM, KSI-IAM-PRA | test_result | adAttackSimulations table |
| cloud-misconfigs | KSI-CNA-HCI, KSI-CNA-EDE, KSI-CNA-NSD | configuration_check | cloudMisconfigurations table |
| threat-intel | KSI-INR-TIF, KSI-INR-TIU, KSI-INR-IOC, KSI-INR-IRP | api_response | threatActors table |
| unified-pipeline | KSI-SCR-PEN, KSI-SCR-APT | test_result | (no dedicated collector) |
| atomic-red-team | KSI-SCR-APT, KSI-SCR-PEN, KSI-MLA-ALE | test_result | atomicTestExecutions table |
| exploit-arsenal | KSI-SCR-PEN, KSI-SVC-VSR, KSI-SCR-APT | test_result | (no dedicated collector) |
| darkweb-intel | KSI-INR-TIF, KSI-INR-IOC | api_response | (no dedicated collector) |
| credential-alerts | KSI-IAM-AAM, KSI-IAM-MFA, KSI-INR-IOC | incident_report | (no dedicated collector) |
| compliance-mapper | KSI-PPM-PPR, KSI-PPM-PPI, KSI-AFR-ADS | document | (no dedicated collector) |

## Appendix B: Mismatched KSI IDs

The following KSI IDs appear in `SOURCE_KSI_MAP` but do NOT exist in the 58-KSI `KSI_CATALOG`:

| Referenced KSI ID | Used In | Likely Correct KSI |
|-------------------|---------|---------------------|
| KSI-SVC-VSR | vuln-scanner, web-app, edr, exploit | KSI-SVC-VRI (Vulnerability Risk Identification) |
| KSI-SVC-VRM | vuln-scanner, web-app | KSI-SVC-VCM (Vulnerability/Config Management) |
| KSI-SDE-SST | web-app, nuclei | Not in catalog — consider adding or mapping to KSI-PIY-RSD |
| KSI-CNA-HCI | nuclei, cloud | Not in catalog — consider mapping to KSI-CNA-MAS |
| KSI-CNA-NSD | ngfw, cloud | Not in catalog — consider mapping to KSI-CNA-RNT |
| KSI-MLA-ALE | siem, edr, ngfw, atomic | Not in catalog — consider mapping to KSI-MLA-RVL |
| KSI-IAM-PRA | ad-attack-sim | Not in catalog — consider mapping to KSI-IAM-ELP |
| KSI-SCR-SAT | phishing | Not in catalog — consider adding (Security Awareness Testing) |
| KSI-SCR-PEN | phishing, unified, atomic | Not in catalog — consider adding (Penetration Testing) |
| KSI-SCR-APT | unified, atomic, exploit | Not in catalog — consider adding (APT Simulation) |
| KSI-PPM-PPR | compliance-mapper | Not in catalog — consider adding (Policy & Procedure Review) |
| KSI-PPM-PPI | compliance-mapper | Not in catalog — consider adding (Policy & Procedure Implementation) |

---

*End of Audit Report*
