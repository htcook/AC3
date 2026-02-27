# Sidebar Menu Audit — Current State

## Summary
- **7 top-level groups**, **20 sub-sections**, **125 total nav items**
- Several items are misplaced or duplicated across groups
- Some groups are overloaded (Operations has 6 sub-sections, 48+ items)
- Some groups are too thin (Knowledge Base has 1 sub-section, 8 items)

## Current Structure

### 1. OPERATIONS (Swords) — 6 sub-sections
- **Core Operations** (5): Dashboard, Mission Workflows, Engagement Mgr, ROE Builder, Kill Chain
- **Agent Management** (3): Agents, Agent Manager, Campaign Exec
- **Detection & Validation** (13): Rule Validator, Coverage Matrix, Emulation Playbooks, Ability Graph, Graph Compare, Purple Team, Evasion Engine, EDR Validation, Agentless BAS, NGFW Validation, Email Security, Remediation Verify, AI Security (ATLAS)
- **SIEM & Connectors** (2): SIEM Connectors, SIEM Feedback Loop
- **Attack Paths & AD** (10): Attack Paths, Cloud Attack Paths, Cloud Credentials, Credential Alerts, AD Attack Sim, AD Domain Connector, Attack Path Graph, Forest Mapper, AD Graph Import, Auto-Rotation, Path Discovery
- **Scoring & Analysis** (11): Risk Scoring, Risk Trending, Continuous Validation, AI Attack Planner, Corroboration Engine, NVD CVE Matcher, Compensating Controls, Pre-Flight Checks, Active Verification, Unified Pipeline, ATT&CK Coverage

### 2. KEY SECURITY INDICATORS (BadgeCheck) — 2 sub-sections
- **Indicators & Evidence** (5): Indicators Dashboard, Evidence Chain, Auto-Collection, Threat Map, Config Baseline
- **Automation & Export** (6): Validation Scheduler, OSCAL Export, Attack Vectors, Scheduled Collection, Engagement Automation, Threat Enrichment

### 3. PHISHING & EXPLOITS (Zap) — 3 sub-sections
- **Campaign Management** (5): Phishing Ops, Launch Wizard, Page Builder, Template Gen, Auto Pipeline
- **Exploit Tools** (7): Exploit Catalog, Validation Engine, Payload Generator, API Security, Web App Scanner, ATT&CK Tests, Template Scanner
- **C2 & Sessions** (6): C2 Servers, SSH Keys, Live Sessions, Recordings, Post-Exploit, File Transfers

### 4. INTELLIGENCE (Search) — 2 sub-sections
- **Threat Intelligence** (5): Vuln Intel, Threat Intel Hub, Threat Catalog, Darkweb Intel, IOC Feed
- **Reconnaissance** (10): Discovery Chain, Domain Intel, Scan History, Web Crawler, Actor Intel Crawler, Scan Scheduler, Scan Compare, Bug Bounty Hub, STIX/TAXII Export, Training Pipeline

### 5. KNOWLEDGE BASE (GraduationCap) — 1 sub-section
- **Reference Library** (8): Archetypes, Abilities, TTP Knowledge, Compliance, Compliance Mapper, Infrastructure, Infra Wiki, Live Infrastructure

### 6. REPORTS & GUIDES (BarChart3) — 1 sub-section
- **Reports & Templates** (7): Engagement Report, Report Generator, Auto-BIA Report, Phishing Ops Guide, Emulation Guide, Template Library, Report Templates

### 7. ADMIN (Settings) — 5 sub-sections
- **Team & Access** (4): Team, Tenants, Activity, Audit Log
- **Infrastructure** (5): Evidence Locker, Webhooks, Vuln Scanner, CI/CD Pipeline, SOAR Connectors
- **Compliance & Security** (1): FIPS Compliance
- **SSIL Integration** (6): SSIL Dashboard, Scan Policies, LLM Guardrails, Observations, Alert Rules, Correlation
- **ProjectDiscovery** (3): Subfinder, HTTPX, Naabu

## Issues Identified

### Misplaced Items
1. **STIX/TAXII Export** in Reconnaissance → should be in Reports or KSI Automation
2. **Training Pipeline** in Reconnaissance → should be in Knowledge Base or Admin
3. **Engagement Automation** in KSI Automation → should be in Operations Core
4. **Threat Enrichment** in KSI Automation → should be in Intelligence
5. **Attack Vectors** in KSI Automation → should be in Scoring & Analysis or Operations
6. **Auto Pipeline** (engagement-pipeline) in Phishing Campaigns → should be in Operations
7. **Vuln Scanner** in Admin Infrastructure → should be in Phishing & Exploits or Operations
8. **Evidence Locker** in Admin Infrastructure → should be in KSI or Reports
9. **SIEM Connectors/Feedback** in Operations → should be in Admin or Intelligence
10. **Email Security** in Detection & Validation → should be in Phishing or separate
11. **Compensating Controls** in Scoring → better in KSI or Compliance
12. **Config Baseline** in KSI → better in Admin Compliance
13. **FIPS Compliance** alone in Admin Compliance → merge with Compliance in Knowledge Base
14. **Live Infrastructure** in Knowledge Base → should be in Admin Infrastructure
15. **Infra Wiki** and **Infrastructure** in Knowledge Base → redundant, merge

### Clutter Issues
1. **Operations** has 48+ items across 6 sub-sections — too large, needs splitting
2. **Detection & Validation** has 13 items — should split into Detection vs Validation
3. **Attack Paths & AD** has 11 items — too many, some are redundant (3 "attack path" variants)
4. **Scoring & Analysis** mixes scoring, validation, and planning — should separate
5. **Reports** has duplicate items: Template Library + Report Templates
6. **Knowledge Base** mixes reference docs with live infrastructure
7. **C2 & Sessions** is under Phishing but C2 is broader than phishing

### Proposed Reorganization (7 groups → 8 groups, better balanced)
1. **COMMAND CENTER** — Dashboard, Workflows, Engagements, ROE, Kill Chain, Campaign Exec
2. **ATTACK SURFACE** — Domain Intel, Discovery Chain, Scan History, Web Crawler, Scan Scheduler, Scan Compare, Bug Bounty, Subfinder/HTTPX/Naabu
3. **EMULATION & TESTING** — Agents, Agent Manager, Emulation Playbooks, Ability Graph, Graph Compare, Purple Team, Evasion Engine, ATT&CK Tests, Atomic Red Team
4. **VALIDATION & DEFENSE** — EDR Validation, NGFW Validation, Agentless BAS, AI Security, Rule Validator, Coverage Matrix, Email Security, Remediation Verify, Continuous Validation, Active Verification
5. **EXPLOIT OPS** — Phishing Ops, Launch Wizard, Page Builder, Template Gen, Exploit Catalog, Payload Generator, API Security, Web App Scanner, Template Scanner, C2 Servers, SSH Keys, Live Sessions, Post-Exploit, File Transfers, Recordings
6. **RISK & SCORING** — Risk Scoring, Risk Trending, Corroboration Engine, NVD CVE Matcher, Unified Pipeline, ATT&CK Coverage, AI Attack Planner, Pre-Flight Checks, Compensating Controls, KSI Dashboard, Evidence Chain, Auto-Collection, Threat Map, Attack Vectors, Validation Scheduler
7. **INTELLIGENCE** — Threat Intel Hub, Vuln Intel, Threat Catalog, Darkweb Intel, IOC Feed, Actor Intel Crawler, Threat Enrichment, STIX/TAXII Export, Attack Paths, Cloud Attack Paths, AD Attack Sim, AD Domain Connector, Attack Path Graph, Forest Mapper, AD Graph Import, Path Discovery
8. **PLATFORM** — Team, Tenants, Activity, Audit Log, Webhooks, SOAR Connectors, SIEM Connectors, SIEM Feedback, SSIL Dashboard, Scan Policies, LLM Guardrails, Observations, Alert Rules, Correlation, CI/CD Pipeline, OSCAL Export, Compliance, Compliance Mapper, FIPS Compliance, Config Baseline, Evidence Locker, Engagement Automation, Scheduled Collection, Reports, Templates, Guides, Training Pipeline, Infra Wiki, Live Infrastructure
