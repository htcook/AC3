# Ace C3 Platform Deep-Dive Audit: Strengths, Gaps, and Remediation Roadmap

**Author:** Harrison Cook, AceofCloud  
**Date:** March 1, 2026  
**Classification:** UNCLASSIFIED — For Internal Use Only  
**Scope:** Full codebase audit of the Caldera Dashboard (Ace C3 Command Center) mapped against the evaluation framework for AI-driven penetration testing and red team platforms, with emphasis on FedRAMP 20x, NIST SP 800-53/800-115, FIPS 140-3, and MITRE ATT&CK alignment.

---

## Executive Summary

This review audits the Ace C3 platform codebase against the acceptance criteria outlined in the external evaluation document, which assessed Ace C3 based solely on public marketing claims. This internal audit validates those claims against actual implementation. The platform is substantial — **217 database tables, 107 backend routers, 195 frontend pages, 135,000+ lines of server-side library code, and 5,077 automated test cases** — representing a genuinely comprehensive offensive security orchestration layer.

The audit identifies **23 confirmed strengths** where the platform meets or exceeds the evaluation criteria, and **14 gaps** ranging from missing modules to areas where implementation exists but lacks the depth required for federal assessment credibility. Each gap includes a concrete remediation recommendation with priority and estimated effort.

---

## 1. Platform Scale and Architecture Overview

The Ace C3 platform is architected as a full-stack TypeScript application (React 19 + Express 4 + tRPC 11) with a MySQL/TiDB database layer managed through Drizzle ORM. The following table summarizes the platform's scale by domain.

| Domain | Metric | Count |
|---|---|---|
| Database schema | Tables | 217 |
| Backend API | Router files | 107 |
| Backend API | Total tRPC procedures (estimated) | ~1,200+ |
| Server libraries | Lib modules | 180+ |
| Server libraries | Total lines of code | 135,245 |
| Frontend | Page components | 195 |
| Frontend | Total lines of code | 109,817 |
| Testing | Test files | 145+ |
| Testing | Individual test cases | 5,077 |
| Authentication | Roles supported | 8 (admin, operator, analyst, team_lead, client, executive, observer, user) |
| Compliance | FIPS modules | 5 (crypto, TLS, compliance, audit scheduler, global TLS) |

The platform is organized into eight primary navigation domains: **Command Center** (mission operations, risk analysis), **Attack Surface** (discovery, scanning, attack paths), **Emulation & Testing** (agents, defense validation), **Exploit Ops** (phishing, exploit tooling, C2/post-exploit), **Intelligence** (threat intel, credentials, export), **Key Security Indicators** (KSI dashboard, compliance), **Reports & Knowledge** (reports, evidence, training), and **Platform** (administration, integrations, tenants).

---

## 2. Strengths: Where the Platform Meets or Exceeds Evaluation Criteria

### 2.1 Discovery and Reconnaissance Automation

The evaluation document noted that Ace C3 claims a four-stage discovery pipeline (Amass → Nmap → service fingerprinting → Nuclei) with configurable stages, timeouts, and parallel execution.

**Audit finding: CONFIRMED and deeply implemented.** The platform contains a dedicated `discovery-chain-orchestrator.ts` (1,109 lines), `discovery-engine.ts` (1,206 lines), `nmap-orchestrator.ts` (701 lines), `service-fingerprinter.ts` (2,161 lines — the single largest lib module), and `projectdiscovery.ts` (738 lines) for Subfinder/Httpx/Naabu integration. The `org-domain-discovery.ts` (932 lines) and `org-enrichment.ts` (1,049 lines) modules provide organizational-level asset enumeration. A passive reconnaissance layer with **33 distinct connector modules** (Shodan, Censys, VirusTotal, SecurityTrails, GreyNoise, BinaryEdge, CRT.sh, RDAP, Wayback, GitHub Leaks, DeHashed, HIBP, and more) provides comprehensive OSINT coverage without active scanning.

The `scope-guard.ts` (913 lines) and `scope-enforcement-middleware.ts` (351 lines) enforce target boundaries at the orchestrator layer, consistent with the "unified scope guard" claim.

### 2.2 Web and API DAST

**Audit finding: CONFIRMED.** The `web-app-scanning.ts` router (1,110 lines, 57 procedures) is one of the largest routers in the platform. The ZAP integration layer is particularly deep: `zap-scanner.ts` (1,700 lines), `zap-proxy-orchestrator.ts` (1,212 lines), `zap-attack-playbooks.ts` (1,351 lines), and `zap-report-generator.ts` (1,326 lines) — totaling over 5,500 lines dedicated to DAST orchestration. The `api-security.ts` router (288 lines) handles OpenAPI/GraphQL/SOAP spec-driven testing. The `scan-policy-engine.ts` (713 lines) manages AI-tuned scan policies.

### 2.3 Exploit Execution and Adversary Emulation

**Audit finding: CONFIRMED with significant depth.** The platform integrates both Metasploit and CALDERA as exploit/emulation backends. The Metasploit layer includes `msf-client.ts` (776 lines), `msf-provisioner.ts` (338 lines), `msf-sessions.ts` router (450 lines), and `exploitation-bridge.ts` (499 lines). The CALDERA integration includes campaign management tables (`campaigns`, `campaignAgents`, `campaignAbilities`), the `campaign-advisor.ts` library, and `campaign-archetypes.ts` router with pre-loaded engagement templates.

The `emulation-playbooks.ts` router manages ATT&CK-mapped playbook execution, and the `atomic-red-team.ts` router provides Atomic Red Team test execution. The `attack-vector-engine.ts` (1,001 lines, 16 procedures) orchestrates multi-vector attack chains. The `exploit-arsenal.ts` router (458 lines, 13 procedures) manages the unified exploit catalog.

### 2.4 Scope Enforcement

The evaluation document emphasized that scope enforcement is "the platform's primary safety control" and must be technically hard to bypass.

**Audit finding: STRONG implementation.** The scope enforcement system spans three layers:

1. **Scope Guard** (`scope-guard.ts`, 913 lines): Core enforcement logic with domain/IP/CIDR validation, wildcard matching, and exclusion lists.
2. **Scope Enforcement Middleware** (`scope-enforcement-middleware.ts`, 351 lines): Server-side middleware that intercepts requests before they reach scanning/exploitation modules.
3. **ROE Guard** (`roe-guard.ts`, 204 lines): Rules of Engagement enforcement that gates active operations behind approved ROE documents.

The ROE system itself is substantial: `roe-builder.ts` router (751 lines, 27 procedures), `roe-audit.ts` router (224 lines, 7 procedures), `roe-pdf-generator.ts` (835 lines), and database tables for `roeDocuments`, `roeVersions`, `roeSignatures`, and `roePersonnel`. The ROE builder includes support for physical, wireless, and social engineering scoping — consistent with FedRAMP ROE/Test Plan template requirements.

### 2.5 Evidence Chain and Capture

**Audit finding: CONFIRMED.** The `evidence-capture.ts` (491 lines) library handles artifact collection with S3 storage. The `evidenceItems` and `evidenceChainOfCustody` database tables provide tamper-evident evidence tracking. The `evidence.ts` router (261 lines, 10 procedures) exposes CRUD operations. The `ksi-evidence-chain.ts` router (483 lines, 13 procedures) links evidence to KSI validation runs. Session recordings (`sessionRecordings`, `recordingChunks` tables) capture live exploitation sessions.

### 2.6 OSCAL and STIX Export

**Audit finding: CONFIRMED.** The `oscal-export.ts` router (452 lines, 6 procedures) generates OSCAL-formatted packages. The `stix-generator.ts` (709 lines) and `stix-export.ts` router (442 lines) produce STIX 2.1 bundles. Both are backed by dedicated frontend pages (`OscalExport.tsx`, `StixExport.tsx`).

### 2.7 FIPS 140-3 Compliance

**Audit finding: STRONG implementation across 5 dedicated modules totaling 2,058 lines.** The `fips-crypto.ts` (410 lines) provides AES-256-GCM encryption, SHA-256/384/512 hashing, HMAC-SHA256, PBKDF2 key derivation, and CSPRNG token generation — all using Node.js `crypto` module (which delegates to OpenSSL's FIPS-validated implementations). The `fips-tls.ts` (283 lines) enforces TLS 1.2+ minimum with approved cipher suites. The `fips-compliance.ts` (953 lines) provides compliance status reporting and gap analysis. The `fips-audit-scheduler.ts` (365 lines) runs periodic compliance checks.

### 2.8 Phishing and Social Engineering

**Audit finding: CONFIRMED with exceptional depth.** The phishing subsystem is one of the platform's deepest domains: `phishing-ops.ts` router (1,349 lines, 21 procedures), `phishing-exploits.ts` library (1,330 lines), `crawl-phish-generator.ts` (1,070 lines), `typosquat.ts` (586 lines), `dns-automation.ts` (213 lines), and `redirector-manager.ts` (747 lines). GoPhish integration is present with a dedicated router and guide page. The `phishingDrafts`, `typosquatDomains`, and `infoOpsCampaigns` tables support the full campaign lifecycle. The `landing-page-builder.tsx` page enables custom phishing landing page creation.

### 2.9 Threat Intelligence Enrichment

**Audit finding: CONFIRMED.** The threat intelligence layer includes `threat-intel.ts` router (452 lines, 14 procedures), `threat-enrichment-engine.ts` router, `threat-actor-crawler.ts` (1,341 lines), `threat-intel-catalog.ts` (1,038 lines), `threat-intel-connectors.ts` (858 lines), and `threat-intel-ingest.ts` (758 lines). The `cross-module-enrichment.ts` (729 lines) correlates findings across modules. The `kev-service.ts` (679 lines) integrates CISA KEV data. The `ransomware-intel.ts` (451 lines) tracks ransomware groups and affiliates. Darkweb intelligence spans 6 modules totaling over 3,000 lines.

### 2.10 SIEM/EDR Evasion Engine

**Audit finding: CONFIRMED with the deepest implementation of any subsystem.** The evasion engine totals **5,179 lines** across 6 modules: `evasion-orchestrator.ts` (1,186 lines), `evasion-playbook.ts` (744 lines), `evasion-scorecard.ts` (803 lines), `evasion-validation.ts` (944 lines), `evasion-integrations.ts` (557 lines), and the `evasion-engine.ts` router (945 lines, 32 procedures). The `siem-mutation-engine.ts` (1,342 lines) handles rule mutation. The `payload-transform-pipeline.ts` (966 lines) manages payload transformation. This is complemented by the `waf-ngfw-detection.ts` (1,565 lines) for WAF/NGFW bypass testing.

### 2.11 Detection Rule Generation and Purple Team

**Audit finding: CONFIRMED.** The `rule-generator.ts` (980 lines) produces Sigma, YARA, Suricata, SPL, and KQL detection rules. The `rule-validator.ts` (890 lines) validates rule effectiveness. The `purple-team.ts` router (291 lines, 10 procedures) orchestrates detection gap analysis. The `detection-tests.ts` table tracks detection coverage. Vendor-specific SIEM/EDR clients exist for **Splunk, Microsoft Sentinel, Microsoft Defender, CrowdStrike, SentinelOne, Cortex XDR, and XSOAR** — enabling real-time detection validation against production security stacks.

### 2.12 Role-Based Access Control and Multi-Tenancy

**Audit finding: CONFIRMED.** Eight distinct roles with role-based dashboards, role-specialized AI chat personas, and role-gated procedures. The `tenants.ts` router (136 lines) and `tenantMemberships` table provide multi-tenant isolation. The SAML 2.0 integration (`saml-auth.ts`, 492 lines; `saml-service.ts`, 520 lines) supports enterprise SSO with Okta, Azure AD, PingFederate, Google Workspace, and OneLogin. Session management (`session-management.ts`, 377 lines) includes device fingerprinting and geo-IP tracking.

### 2.13 Additional Confirmed Strengths

| Capability | Implementation Evidence |
|---|---|
| Active Directory attack paths | 4 routers (845 lines total), BloodHound import, AD simulation |
| ICS/OT security testing | 4 modules (2,786 lines): device discovery, exploit catalog, OT protocol analyzer |
| Container security | `container-registry.ts` (423 lines), container image scanning |
| CI/CD pipeline security | `cicd-pipeline.ts` (108 lines), pipeline scanning |
| Credential attack engine | `credential-attack-engine.ts` (1,219 lines), OEM default creds (418 lines) |
| C2 framework integration | Sliver C2 (241 lines), Metasploit sessions (450 lines), mTLS certs (565 lines) |
| Post-exploitation | `post-exploit-playbooks.ts`, lateral movement engine (605 lines), privilege escalation (771 lines) |
| Scoring and risk | `scoring-engine.ts` (1,637 lines), CARVER risk cards, temporal decay (384 lines) |
| LLM guardrails | `llm-guardrails.ts` (504 lines), `llm-resilience.ts` (402 lines) |
| Webhook/SOAR integration | Webhooks (deliveries + endpoints), SOAR connectors (140 lines) |

---

## 3. Gaps: Where the Platform Falls Short of Evaluation Criteria

### Gap 1: Wireless Penetration Testing — ABSENT

**Evaluation requirement:** FedRAMP ROE planning explicitly includes wireless penetration testing as a mandatory consideration. The evaluation document notes this as a known limitation.

**Audit finding:** No dedicated wireless testing module exists. The `roe-builder.ts` references wireless as a scoping option (for ROE documentation purposes), but there are no backend modules for 802.11 frame capture, WPA/WPA2 cracking, Bluetooth/BLE assessment, or RF signal analysis. This is structurally expected — wireless testing requires physical hardware and proximity — but it means the platform cannot claim full FedRAMP attack vector coverage without external tooling.

**Remediation:** Create a `wireless-assessment.ts` module that integrates with remote wireless testing agents (e.g., WiFi Pineapple API, Kismet REST API) for organizations that deploy hardware probes. At minimum, add a wireless assessment checklist and evidence capture workflow to the ROE builder so wireless findings from external tools can be imported and correlated. **Priority: Medium. Effort: 2-3 weeks.**

### Gap 2: Physical Penetration Testing — ABSENT

**Evaluation requirement:** FedRAMP ROE planning includes physical penetration testing. The evaluation document acknowledges this as a structural limitation of any SaaS platform.

**Audit finding:** Similar to wireless, the `roe-builder.ts` and `scope-guard.ts` reference physical testing as a scoping category, but no modules exist for badge cloning, lock assessment, tailgating documentation, or physical security evidence capture workflows.

**Remediation:** Build a `physical-assessment.ts` module with structured evidence capture templates (photo upload, GPS coordinates, timestamp verification, chain-of-custody for physical artifacts). Integrate with the evidence vault and report generator. This turns the platform into the evidence management layer for physical tests even if the testing itself is manual. **Priority: Medium. Effort: 1-2 weeks.**

### Gap 3: Mobile Application Testing — THIN

**Evaluation requirement:** FedRAMP mandatory attack vectors include "mobile-app-to-target." The evaluation document flags this as requiring different tooling and lab setups.

**Audit finding:** The `payload-generator.ts` router references mobile payloads, and the `roe-builder.ts` includes mobile in scoping. The `exploit-ingestion.ts` references APK analysis. However, there is no dedicated mobile DAST module (no MobSF integration, no Frida orchestration, no iOS/Android-specific scanning pipeline). The `container-registry-service.ts` mentions mobile apps but only for container image scanning.

**Remediation:** Build a `mobile-security.ts` router and `mobile-dast.ts` library that integrates with MobSF (Mobile Security Framework) for automated APK/IPA analysis, and provides Frida script orchestration for runtime instrumentation. Add mobile-specific evidence capture (screenshot, logcat, network trace). **Priority: High. Effort: 3-4 weeks.**

### Gap 4: Tenant Isolation Depth — SHALLOW

**Evaluation requirement:** The evaluation document demands clarity on "tenancy isolation (single-tenant vs multi-tenant)" and asks whether customer artifacts are isolated.

**Audit finding:** The `tenants.ts` router is only 136 lines with basic CRUD. The `tenantMemberships` table exists, but there is no evidence of row-level security enforcement across all 217 tables. Most routers filter by `userId` or `engagementId` but do not enforce tenant-scoped queries at the middleware level. The `scope-enforcement-middleware.ts` handles target scope but not data tenancy scope.

**Remediation:** Implement a `tenant-isolation-middleware.ts` that injects `tenantId` into every database query context (similar to how `ctx.user` is injected). Add a `tenantId` foreign key to all engagement-related tables. Create a tenant isolation test suite that verifies cross-tenant data leakage is impossible. **Priority: Critical for federal deployments. Effort: 4-6 weeks.**

### Gap 5: Evidence Integrity Verification — INCOMPLETE

**Evaluation requirement:** The evaluation document states that evidence handling must include "traceability" and "integrity" — not just screenshots. FedRAMP expects evidence that can be independently verified.

**Audit finding:** The `evidenceChainOfCustody` table tracks custody transfers, and `evidence-capture.ts` stores artifacts in S3. However, there is no cryptographic integrity verification — no SHA-256 hashes of evidence files at capture time, no hash-chain or Merkle tree for tamper detection, and no digital signature on evidence packages. The FIPS crypto module has the primitives (SHA-256, HMAC) but they are not wired into the evidence pipeline.

**Remediation:** Extend `evidence-capture.ts` to compute SHA-256 hashes at capture time and store them in the `evidenceItems` table. Add a `verifyIntegrity` procedure that re-hashes stored artifacts and compares. Implement HMAC-signed evidence manifests for export packages. Wire the FIPS crypto module's `hash()` function into the evidence pipeline. **Priority: High. Effort: 1-2 weeks.**

### Gap 6: OSCAL Export Depth — SURFACE-LEVEL

**Evaluation requirement:** The evaluation document demands "sample exports mapped to the relevant OSCAL models (not just JSON output)" with "traceability from each exported assertion to underlying evidence artifacts" and "regeneration-on-demand capability."

**Audit finding:** The `oscal-export.ts` router has 452 lines and 6 procedures, which is relatively thin for a compliance export system that must produce valid OSCAL System Security Plan (SSP), Security Assessment Plan (SAP), Security Assessment Report (SAR), and Plan of Action and Milestones (POA&M) artifacts. There is no evidence of OSCAL schema validation against NIST's published JSON schemas, no automated linking of OSCAL assertions to evidence items, and no regeneration-on-demand workflow.

**Remediation:** Expand the OSCAL export module to produce all four OSCAL model types. Add JSON Schema validation against NIST's official OSCAL schemas. Create a `oscal-evidence-linker.ts` that automatically maps KSI validation results and evidence items to OSCAL assessment result entries. Add a "regenerate package" endpoint that rebuilds the full OSCAL package from current platform state. **Priority: High for FedRAMP 20x. Effort: 3-4 weeks.**

### Gap 7: AI Decision Audit Trail — INCOMPLETE

**Evaluation requirement:** The evaluation document demands "visibility into which AI profile or model version acted," "the exact inputs the model used," "the resulting configuration deltas," and "a human override path."

**Audit finding:** The `llm-guardrails.ts` (504 lines) provides input sanitization and output validation. The `llm-resilience.ts` (402 lines) handles retry logic and fallback. However, there is no dedicated AI decision audit log that records: (a) which LLM model version was used, (b) the full prompt/input sent to the model, (c) the raw model response, (d) what configuration changes the AI recommended, and (e) whether a human approved or overrode the recommendation. The `activityLogs` table captures user actions but not AI actions.

**Remediation:** Create an `ai_decision_log` table with columns for `modelVersion`, `inputPromptHash`, `rawResponse`, `configDelta`, `humanOverride`, `approvedBy`, and `timestamp`. Wire all LLM invocations (scan policy tuning, triage, detection rule generation, template creation) through a logging middleware. Add an "AI Decisions" audit page for admins. **Priority: High for federal trust. Effort: 2-3 weeks.**

### Gap 8: Deterministic Scan Replay — ABSENT

**Evaluation requirement:** The evaluation document demands "deterministic replay of scans and exploit validations (or at minimum, traceable configuration snapshots)."

**Audit finding:** The platform captures scan results and configurations, but there is no mechanism to replay a scan with identical parameters to verify reproducibility. The `scan-scheduler.ts` (456 lines) handles scheduling but not replay. The `scanPolicies` table stores configurations but does not snapshot the full execution environment (tool versions, module versions, target state).

**Remediation:** Build a `scan-replay.ts` module that snapshots the complete scan configuration (tool versions, scan policy, target list, scope rules, ROE constraints) at execution time and stores it as an immutable record. Add a "replay scan" action that re-executes with the identical configuration. Include a diff view comparing original and replay results. **Priority: Medium. Effort: 2-3 weeks.**

### Gap 9: Prompt Injection Hardening — PARTIAL

**Evaluation requirement:** The evaluation document explicitly flags prompt injection as "structurally relevant" for an offensive platform where "untrusted input is everywhere" — OSINT feeds, scan outputs, imported specs, and threat intel feeds.

**Audit finding:** The `llm-guardrails.ts` (504 lines) exists and provides input sanitization. However, there is no evidence of adversarial input testing against the LLM layer. The platform processes attacker-controlled data (scan responses, OSINT scrapes, imported OpenAPI specs) and feeds it to LLM-powered triage and analysis — creating a real prompt injection attack surface. The guardrails module needs to be validated against known prompt injection techniques.

**Remediation:** Create a `prompt-injection-test-suite.ts` with known prompt injection payloads (OWASP LLM Top 10 patterns). Add input sanitization specifically for data flowing from scan results and OSINT feeds into LLM prompts. Implement output validation that detects when LLM responses contain unexpected tool calls or scope-violating recommendations. Add a "canary" system that detects when the LLM's behavior deviates from expected patterns. **Priority: High. Effort: 2-3 weeks.**

### Gap 10: Report Narrative Quality — THIN

**Evaluation requirement:** FedRAMP reporting expects "a complete test narrative that ties evidence to the ROE-approved scope and timeline" and "defensible access path articulation that explains chained weaknesses."

**Audit finding:** The `report-generator.ts` (734 lines), `report-export.ts` (368 lines), `pdf-report-generator.ts` (363 lines), and `report-templates.ts` router exist. The `attackPaths` table and `attack-path-discovery.ts` router track chained attack paths. However, the report generation appears to produce structured data exports rather than narrative-quality assessment reports. There is no evidence of LLM-powered narrative generation that ties together the attack path, evidence, ROE compliance, and timeline into a coherent story that a federal assessor would accept.

**Remediation:** Build an `assessment-narrative-generator.ts` that uses the LLM to produce professional assessment narratives from structured data. The generator should: (a) pull the ROE document and verify all testing stayed within scope, (b) construct attack path narratives with evidence links, (c) produce executive summaries with risk quantification, and (d) generate finding-level narratives with reproduction steps. Add NIST SP 800-115 report template compliance. **Priority: High. Effort: 3-4 weeks.**

### Gap 11: Corroboration Engine Depth — THIN

**Evaluation requirement:** The evaluation document demands "transparent proof of why an issue is confirmed" and "reproducible validation steps."

**Audit finding:** The `corroboration-engine.ts` router is only 117 lines with 5 procedures, and the `corroborationResults` table exists. However, for a platform that claims "confirmed-only vulnerability counting," the corroboration system is surprisingly thin. There is no evidence of multi-source validation (e.g., confirming a vulnerability found by Nuclei is also exploitable via Metasploit, and matches a KEV entry).

**Remediation:** Expand the corroboration engine to implement a three-tier confirmation model: (1) tool-level confirmation (scanner reports it), (2) cross-tool confirmation (second tool validates), (3) exploitation confirmation (exploit succeeds). Link corroboration results to evidence items and KEV entries. Add a "confidence score" that reflects the corroboration depth. **Priority: Medium. Effort: 2-3 weeks.**

### Gap 12: KSI Validation Scheduling and Continuous Monitoring — PARTIAL

**Evaluation requirement:** FedRAMP 20x emphasizes "continuous/automated validation" and expects "validation cycles (machine and non-machine)" to be documented.

**Audit finding:** The `ksi-auto-collector.ts` (773 lines, 19 procedures) and `ksi-validation-scheduler.ts` (91 lines, 6 procedures) exist, but the scheduler is thin relative to the auto-collector. The `validationSchedules` table exists but the scheduling logic lacks cron-based continuous validation, drift detection, and automated alerting when KSI scores degrade.

**Remediation:** Expand the KSI validation scheduler to support cron-based continuous validation runs. Add drift detection that compares current KSI scores against baseline. Implement automated alerting (via the existing notification system) when KSI coverage drops below thresholds. Add a "continuous monitoring dashboard" that shows KSI validation trends over time. **Priority: High for FedRAMP 20x. Effort: 2-3 weeks.**

### Gap 13: Data Retention and Deletion Semantics — ABSENT

**Evaluation requirement:** The evaluation document demands clarity on "retention and deletion semantics" and "whether customer artifacts are used to train models."

**Audit finding:** No data retention policy module exists. There is no automated data lifecycle management (retention periods, automated deletion, legal hold). The S3 storage layer stores evidence indefinitely. There is no documented guarantee that customer data is not used for model training (though the platform uses external LLM APIs, not self-hosted models).

**Remediation:** Build a `data-lifecycle.ts` module with configurable retention policies per data type (evidence: 7 years for federal, scan results: configurable, chat history: configurable). Add automated purge jobs. Create a data retention policy page in the admin UI. Document the LLM data handling policy (no customer data used for training) in both the UI and exportable compliance documentation. **Priority: High for federal/healthcare/banking. Effort: 2-3 weeks.**

### Gap 14: SOAR Connector Depth — THIN

**Evaluation requirement:** Enterprise security operations expect bidirectional integration with SOAR platforms for automated response workflows.

**Audit finding:** The `soar-connectors.ts` router is only 140 lines. The vendor integration layer includes XSOAR client (in `server/lib/vendors/xsoar.ts`) but the SOAR integration lacks bidirectional playbook triggering, automated ticket creation, and response action feedback loops. The webhook system (`webhookEndpoints`, `webhookDeliveries`) provides outbound notification but not structured SOAR orchestration.

**Remediation:** Expand SOAR connectors to support bidirectional integration with Cortex XSOAR, Splunk SOAR, and ServiceNow SecOps. Add automated incident ticket creation from confirmed findings. Implement response action feedback (e.g., "firewall rule deployed" → update finding status). **Priority: Medium. Effort: 3-4 weeks.**

---

## 4. Gap Priority Matrix

| # | Gap | Severity | Federal Impact | Effort | Priority |
|---|---|---|---|---|---|
| 4 | Tenant isolation depth | Critical | Blocks multi-tenant federal deployment | 4-6 weeks | **P0** |
| 5 | Evidence integrity verification | High | Undermines evidence credibility | 1-2 weeks | **P1** |
| 6 | OSCAL export depth | High | Blocks FedRAMP 20x package submission | 3-4 weeks | **P1** |
| 7 | AI decision audit trail | High | Blocks AI trust for federal assessors | 2-3 weeks | **P1** |
| 3 | Mobile application testing | High | Missing mandatory FedRAMP attack vector | 3-4 weeks | **P1** |
| 9 | Prompt injection hardening | High | Active security risk to platform | 2-3 weeks | **P1** |
| 10 | Report narrative quality | High | Affects assessment deliverable acceptance | 3-4 weeks | **P2** |
| 12 | KSI continuous monitoring | High | Required for FedRAMP 20x continuous auth | 2-3 weeks | **P2** |
| 13 | Data retention/deletion | High | Required for federal/healthcare compliance | 2-3 weeks | **P2** |
| 11 | Corroboration engine depth | Medium | Affects "confirmed-only" credibility | 2-3 weeks | **P2** |
| 8 | Deterministic scan replay | Medium | Affects reproducibility claims | 2-3 weeks | **P3** |
| 1 | Wireless testing | Medium | Structural SaaS limitation (documented) | 2-3 weeks | **P3** |
| 2 | Physical testing | Medium | Structural SaaS limitation (documented) | 1-2 weeks | **P3** |
| 14 | SOAR connector depth | Medium | Affects enterprise integration story | 3-4 weeks | **P3** |

---

## 5. Comparison: External Evaluation Claims vs. Internal Audit Reality

The following table maps each major claim from the external evaluation document to the actual codebase finding.

| Evaluation Claim | Claimed? | Implemented? | Depth Assessment |
|---|---|---|---|
| Four-stage discovery pipeline | Yes | Yes | **Deep** — 6,000+ lines across 5 modules |
| Unified scope guard | Yes | Yes | **Strong** — 1,264 lines, middleware-enforced |
| OWASP Top 10 DAST | Yes | Yes | **Deep** — 5,500+ lines ZAP integration |
| API spec-driven testing | Yes | Yes | **Moderate** — 288 lines dedicated router |
| Exploit library (thousands) | Yes | Yes | **Deep** — Metasploit + CALDERA + Atomic Red Team |
| ATT&CK-mapped validation | Yes | Yes | **Strong** — TTP engine, playbooks, detection tests |
| Autonomous validation engine | Yes | Yes | **Moderate** — validation engine exists but corroboration thin |
| Proof-of-exploit artifacts | Yes | Yes | **Moderate** — evidence capture exists but lacks integrity hashing |
| Social engineering campaigns | Yes | Yes | **Deep** — 4,000+ lines phishing subsystem |
| Typosquatting/DNS automation | Yes | Yes | **Strong** — 586 + 213 lines |
| Threat intel enrichment | Yes | Yes | **Deep** — 6,000+ lines across 8 modules |
| KEV catalog integration | Yes | Yes | **Strong** — 679 lines dedicated KEV service |
| FedRAMP 20x KSI mapping | Yes | Yes | **Strong** — 5 KSI routers, auto-collector |
| OSCAL export | Yes | Yes | **Shallow** — needs schema validation and evidence linking |
| Detection rule generation | Yes | Yes | **Deep** — 2,466 lines, multi-format (Sigma/YARA/SPL/KQL) |
| SIEM/EDR evasion engine | Yes | Yes | **Deep** — 5,179 lines, the deepest subsystem |
| Purple team loop | Yes | Yes | **Moderate** — 291 lines router, vendor clients exist |
| FIPS 140-3 compliance | Yes | Yes | **Strong** — 2,058 lines across 5 modules |
| Multi-tenancy | Yes | Partial | **Shallow** — CRUD exists but no row-level enforcement |
| Wireless testing | No | No | **Absent** — structural limitation acknowledged |
| Physical testing | No | No | **Absent** — structural limitation acknowledged |
| Mobile testing | Partial | Thin | **Thin** — references exist but no dedicated module |

---

## 6. Recommended Implementation Sequence

Based on the gap analysis, the following 90-day remediation roadmap is recommended:

**Weeks 1-2 (Quick Wins):**
- Evidence integrity verification (Gap 5) — wire FIPS crypto hashing into evidence pipeline
- Data retention policy module (Gap 13) — configurable retention with automated purge

**Weeks 3-6 (Federal Blockers):**
- Tenant isolation middleware (Gap 4) — row-level security across all tables
- AI decision audit trail (Gap 7) — logging middleware for all LLM invocations
- OSCAL export expansion (Gap 6) — full OSCAL model support with schema validation

**Weeks 7-10 (Attack Vector Coverage):**
- Mobile application testing (Gap 3) — MobSF integration and mobile DAST
- Prompt injection hardening (Gap 9) — adversarial testing suite for LLM layer
- KSI continuous monitoring (Gap 12) — cron-based validation with drift detection

**Weeks 11-14 (Assessment Quality):**
- Report narrative generator (Gap 10) — LLM-powered assessment narratives
- Corroboration engine expansion (Gap 11) — multi-source confirmation model
- Deterministic scan replay (Gap 8) — configuration snapshotting and replay
- SOAR connector expansion (Gap 14) — bidirectional XSOAR/Splunk SOAR integration
- Wireless/physical evidence workflows (Gaps 1-2) — import and correlation for external tools

---

## 7. Conclusion

The Ace C3 platform is a genuinely substantial offensive security orchestration system. The codebase audit confirms that the vast majority of public marketing claims are backed by real implementation — in many cases with significantly more depth than the external evaluation could assess from public materials alone. The platform's strongest areas are discovery automation (33 passive connectors), DAST (5,500+ lines of ZAP integration), evasion engineering (5,179 lines), phishing operations (4,000+ lines), and FIPS 140-3 compliance (2,058 lines).

The 14 identified gaps are addressable within a 90-day sprint cycle. The most critical gap — tenant isolation — is a prerequisite for any multi-tenant federal deployment and should be prioritized immediately. The evidence integrity, OSCAL depth, and AI audit trail gaps are the next tier, as they directly affect the platform's credibility for FedRAMP 20x assessment packages.

The platform's honest limitations (wireless, physical, and mobile testing) are structural to any SaaS-based offensive platform and should be documented transparently in ROE scoping rather than treated as deficiencies. The recommended approach is to build evidence import workflows for these modalities so the platform serves as the unified evidence management and reporting layer even when external tools are required for specific test types.

---

*This audit was conducted against the Caldera Dashboard codebase at checkpoint version `4f09336c`. All line counts and module inventories reflect the platform state as of March 1, 2026.*
