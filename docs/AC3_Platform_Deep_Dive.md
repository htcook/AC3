# AC3 Platform Deep Dive — Architecture, Capabilities, and Safety Posture

**Author:** Harrison Cook — AceofCloud
**Version:** 1.0 — April 2026
**Classification:** UNCLASSIFIED — Business Confidential
**Codebase Metrics:** 633 server modules | 319 client pages | 352 database tables | 666,579 lines of TypeScript

---

## Table of Contents

1. Provenance and Calibration Authority
2. Platform Identity and Market Position
3. Intended Customers and Use Cases
4. Architecture Overview
5. Command Center — Mission Operations and Risk Analysis
6. Attack Surface Management — Discovery, Scanning, and Attack Paths
7. Emulation and Testing — Agents, Defense Validation, Ember C2, and Test Lab
8. Exploit Operations — Phishing, Exploit Tooling, and Post-Exploitation
9. Threat Intelligence — The Intelligence Backbone (Deep Section)
10. Key Security Indicators and Compliance
11. Reports, Knowledge, and Continuous Learning
12. Platform Administration and Multi-Tenancy
13. The Hybrid Risk Scoring System — CARVER+SHOCK/CVSS/BIA Fusion
14. Engagement and Campaign Orchestration
15. Safety Architecture — Seven Layers of Guardrails
16. AI Governance and LLM Reliability
17. Code vs. Judgment — The Two Kinds of Intellectual Property
18. Continuity and the Bus Factor
19. Philosophical Spine — Where the Design Comes From
20. Competitive Landscape and Differentiation

---

## 1. Provenance and Calibration Authority

AC3 was not designed by committee, extracted from a requirements document, or assembled by a product team iterating on market research. It was built in four months by a single practitioner — Harrison Cook — drawing on twenty-five years of operational experience that spans physical security, anthropological fieldwork, tiger-team penetration testing, and enterprise cybersecurity architecture. That provenance is not biographical decoration. It is the calibration source for every scoring threshold, every sector anchor, every ROE parsing priority, and every graduation drift sensitivity in the platform.

The arc matters because it explains what AC3 encodes. Harrison began as an archaeologist and anthropologist — disciplines that train the practitioner to read material culture backwards, to infer what a society valued from what it built, fortified, buried, and hid. That training transferred directly into physical penetration testing, where the same operation runs in reverse: inferring what is worth attacking from what has been built to protect it. Two decades of walking buildings, networks, and critical infrastructure — observing what actual operators guard and why — produced a set of internalized anchors that no textbook could replicate and no training dataset could approximate.

The four-month build was not a sprint from zero. It was the compression of twenty-five years of preparation into a platform that codifies practitioner judgment at a density that typically requires teams of dozens working over years. The 666,579 lines of TypeScript, the 633 server modules, the 352 database tables — these are the material expression of knowledge that existed in Harrison's operational instincts long before it existed in code. When a CISO or procurement team asks "why should I trust the judgment encoded in this platform?", the answer is the provenance: the person who calibrated these systems has been doing the underlying operation — reading what organizations value, what they fear, and what they fail to protect — for a quarter century.

---

## 2. Platform Identity and Market Position

**AC3** (AceofCloud Cybersecurity Command Center) is a unified offensive security and threat intelligence platform that combines adversary emulation, vulnerability management, risk scoring, threat intelligence, and compliance automation into a single operational environment. It is not a point solution. It is not a scanner with a dashboard bolted on. It is a full-spectrum platform that covers the entire offensive security lifecycle — from passive reconnaissance through exploitation, post-exploitation, evidence collection, and executive reporting — with AI-augmented decision-making at every stage.

The platform occupies a market position that no single competitor currently fills. Existing tools address fragments of the offensive security workflow: Pentera and NodeZero handle automated penetration testing; Tenable and Qualys handle vulnerability management; Recorded Future and Mandiant handle threat intelligence; PlexTrac and AttackForge handle pentest management. AC3 unifies all of these capabilities into a single platform with a shared data model, shared scoring engine, and shared AI reasoning layer. The closest architectural comparison is to a military C2 (Command and Control) system adapted for cybersecurity operations — hence the name.

The platform is built as a multi-tenant SaaS application with white-label support, three license tiers (Starter, Professional, Enterprise), and MSSP analytics for managed security service providers. It is cloud-native, deployed on managed infrastructure, and designed for both single-operator use and team-based engagement management.

---

## 3. Intended Customers and Use Cases

AC3 serves four primary customer segments, each with distinct operational requirements and value propositions.

| Customer Segment | Primary Use Cases | Key Platform Modules |
|---|---|---|
| **MSSPs and Consultancies** | Multi-client engagement management, white-label reporting, campaign orchestration, tenant-isolated operations | Engagement Manager, Campaign Orchestrator, White-Label, Tenant Isolation, MSSP Analytics, Report Generator |
| **Enterprise Security Teams** | Continuous validation, attack surface management, compliance automation, risk trending, executive dashboards | Domain Intel, ScanForge, KSI Dashboard, Compliance Mapper, Risk Center, Executive View |
| **Red Team Operators** | Adversary emulation, C2 operations, exploit development, evasion testing, purple team exercises | Caldera Integration, Ember C2, Evasion Engine, Exploit Catalog, Purple Team, OPSEC Dashboard |
| **Government and Defense** | NIST/FedRAMP compliance, CISA KEV tracking, FIPS 140-2 crypto, HACS-compliant threat hunting, OSCAL export | FIPS Compliance, FedRAMP Controls, Hunt Ops, OSCAL Export, STIX Generator, AI Governance |

**Starter Tier** provides domain intelligence, threat catalog, vulnerability scanning, report generation, incident search, and affiliated domain discovery. This tier serves small consultancies and individual practitioners who need a professional-grade reconnaissance and reporting platform.

**Professional Tier** adds adversary emulation, phishing operations, zero-day tracking, compliance frameworks, training feedback, bug bounty intelligence, and a client portal. This tier serves mid-market MSSPs and enterprise security teams that need offensive testing capabilities alongside compliance automation.

**Enterprise Tier** unlocks the full platform: campaign orchestration, AI security validation, Ember C2 agents, CI/CD pipeline integration, and full red team operations. This tier serves large MSSPs, government contractors, and enterprise red teams that need the complete offensive security lifecycle in a single platform.

---

## 4. Architecture Overview

AC3 is built on a modern TypeScript stack with clear separation between the client application, the server-side business logic, and the data persistence layer.

**Frontend:** React 19 with Tailwind CSS 4, shadcn/ui component library, and tRPC client bindings. The UI is organized into 319 page-level components across eight navigation groups, with a responsive sidebar layout that adapts to mobile screens. The design language uses a dark theme with accent colors for operational hierarchy — red for critical findings, amber for warnings, emerald for healthy states.

**Backend:** Express 4 with tRPC 11 for type-safe RPC, Drizzle ORM for database access, and a modular library architecture where each capability is implemented as an independent TypeScript module under `server/lib/`. The 633 server modules total 388,030 lines of code and cover everything from passive OSINT connectors to LLM-powered exploit reasoning engines.

**Database:** MySQL/TiDB with 352 tables managed through Drizzle schema migrations. The schema covers engagement management, vulnerability findings, threat actor catalogs, IOC feeds, evidence chains, compliance mappings, scoring histories, and multi-tenant isolation.

**AI Layer:** 13 LLM specialist modules provide domain-specific reasoning for attack planning, vulnerability verification, scan analysis, report writing, threat mapping, exploit selection, evasion tactics, CARVER scoring, and operational decision-making. All LLM calls are governed by a unified AI governance pipeline that enforces input/output filtering, prompt injection defense, decision audit trails, circuit breakers, rate limiting, and NIST AI RMF compliance.

**External Integrations:** The platform integrates with MITRE Caldera for adversary emulation, Metasploit for exploitation, Sliver and Empire for C2 operations, GoPhish for phishing campaigns, ZAP and Burp Suite for web application testing, Nuclei for vulnerability scanning, and a dedicated scan server running Nmap, Subfinder, Httpx, and Naabu for network discovery. Vendor integrations include Splunk, CrowdStrike, SentinelOne, Microsoft Defender, Cortex XDR, Microsoft Sentinel, and Palo Alto XSOAR.

**Storage:** S3-compatible object storage for evidence files, screenshots, scan results, and generated reports. All file bytes are stored in S3; the database stores metadata, URLs, and access control information.

The eight navigation groups that organize the platform's capabilities are:

| Group | Domain | Module Count (approx.) |
|---|---|---|
| **Command Center** | Mission operations, risk analysis, engagement management | 45+ |
| **Attack Surface** | Discovery, scanning, enumeration, attack paths | 90+ |
| **Emulation & Testing** | Agents, playbooks, defense validation, Ember C2, test lab | 80+ |
| **Exploit Ops** | Phishing, exploit tooling, C2, post-exploitation | 85+ |
| **Intelligence** | Threat intel, darkweb, IOC feeds, actor tracking | 75+ |
| **Key Security Indicators** | KSI dashboard, compliance, evidence chains | 25+ |
| **Reports & Knowledge** | Report generation, knowledge bases, LLM learning | 55+ |
| **Platform** | Administration, integrations, SSIL, infrastructure | 50+ |

---

## 5. Command Center — Mission Operations and Risk Analysis

The Command Center is the operational nerve center of AC3. It provides two primary views — an **Executive View** for CISOs and management stakeholders, and an **Operator View** for red team practitioners — along with mission workflow management, engagement lifecycle control, and the hybrid risk scoring system.

### 5.1 Executive View

The Executive View presents a high-level operational picture designed for non-technical stakeholders. It surfaces aggregate risk scores, trending vulnerability counts, compliance posture summaries, and engagement status across all active operations. The dashboard uses the hybrid CARVER+SHOCK/CVSS/BIA scoring system (detailed in Section 13) to present risk in business-impact terms rather than raw technical severity.

### 5.2 Operator View

The Operator View is the primary workspace for red team operators. It provides real-time visibility into active engagements, agent status, scan progress, finding counts, and exploitation results. The view is designed for operational tempo — operators can launch scans, review findings, trigger exploits, and collect evidence without leaving the dashboard.

### 5.3 Key Security Indicators (KSI)

The KSI Dashboard implements a continuous monitoring framework aligned with FedRAMP and NIST SP 800-137. It tracks quantitative security metrics — patch currency, vulnerability density, mean time to remediate, scan coverage percentage, and compliance control pass rates — and presents them as live indicators with trend lines and threshold alerts. The **KSI Auto Collector** automatically gathers evidence from scan results, engagement findings, and compliance checks to maintain an always-current security posture picture.

### 5.4 Mission Workflows and Engagement Management

AC3 manages offensive security operations through a structured engagement lifecycle:

| Phase | Description | Key Modules |
|---|---|---|
| **Scoping** | ROE definition, scope validation, target enumeration | ROE Builder, Scope Guard |
| **Reconnaissance** | Passive and active discovery, OSINT collection | Discovery Chain, Domain Intel, ScanForge |
| **Vulnerability Assessment** | Multi-tool scanning, finding correlation, risk scoring | Nuclei, ZAP, Burp, CARVER+SHOCK Scoring |
| **Exploitation** | Validated exploitation, evidence collection | Exploitation Bridge, Metasploit, Ember C2 |
| **Post-Exploitation** | Lateral movement, privilege escalation, data exfiltration simulation | Lateral Movement Engine, PrivEsc Engine, Exfil Simulation |
| **Reporting** | Automated report generation, evidence packaging | Report Generator, PDF Export, STIX/OSCAL |

The **Engagement Orchestrator** is the LLM-driven autonomous execution engine that can run an entire engagement pipeline with a single operator click. It progresses through nine phases — from passive OSINT through active scanning, vulnerability assessment, exploitation, and reporting — pausing only for operator approval on high-risk actions. Every action is gated by ROE scope enforcement and logged to an immutable audit trail.

### 5.5 Risk Center and AI Attack Planner

The **Risk Center** provides the primary interface to the hybrid scoring system, displaying CARVER+SHOCK composite scores, CVSS severity distributions, BIA impact assessments, and temporal decay adjustments for every finding in an engagement. The **AI Attack Planner** uses LLM reasoning to generate prioritized attack plans based on the scored findings, recommending exploitation sequences that maximize impact while respecting ROE constraints and safety guardrails.

### 5.6 Campaign Archetypes and Automation

The **Campaign Archetypes** module provides pre-built campaign templates for common offensive scenarios — external penetration test, internal network assessment, web application assessment, social engineering campaign, red team exercise, and purple team validation. Each archetype defines the phases, tools, success criteria, and reporting requirements for its scenario type. The **Engagement Automation Hub** allows operators to chain these archetypes into multi-phase campaigns with conditional branching, failure handling, and timeout enforcement.

---

## 6. Attack Surface Management — Discovery, Scanning, and Attack Paths

The Attack Surface group provides the reconnaissance and vulnerability assessment capabilities that feed every downstream operation in the platform. It is organized into three subsections: Discovery and Recon, Scanning and Enumeration, and Attack Paths.

### 6.1 Discovery Chain

The **Discovery Chain** is AC3's automated reconnaissance pipeline that orchestrates 70+ passive OSINT connectors in a structured sequence. Starting from a single domain, IP address, or organization name, the chain progressively discovers subdomains, resolves DNS records, fingerprints technologies, identifies cloud assets, checks certificate transparency logs, queries WHOIS records, and cross-references findings against threat intelligence feeds.

The passive connector library includes integrations with:

| Category | Connectors |
|---|---|
| **DNS and Subdomain** | crt.sh, RapidDNS, DNSRepo, SecurityTrails, Anubis, DNS Deep, Zone Transfer Detection |
| **IP and Network** | Shodan, Censys, BinaryEdge, GreyNoise, BGPView, RIPEStat, IP-API, Netlas |
| **Web and Technology** | BuiltWith, Wayback Machine, CommonCrawl, URLScan, Favicon Hash, JARM Fingerprint |
| **Credential and Breach** | Have I Been Pwned, DeHashed, LeakCheck, LeakIX, Hudson Rock |
| **Threat Intel** | VirusTotal, ThreatFox, ThreatMiner, AlienVault OTX, PhishTank, Google SafeBrowsing |
| **Cloud and Container** | Cloud Bucket Recon, Cloud Asset Discovery, Container Discovery |
| **Social and OSINT** | LinkedIn Company Intel, GitHub Recon, GitHub Leaks, Social Media |
| **Dark Web** | IntelX Search, DarkWeb CrossRef, Ransomware.live |

Each connector implements a standardized interface with rate limiting, error handling, and result normalization. The **Corroboration Engine** cross-references findings across multiple sources to assign confidence levels — a subdomain confirmed by three independent sources receives higher confidence than one found by a single connector.

### 6.2 Domain Intelligence Pipeline

The **Domain Intel** module is the deep-dive reconnaissance capability that goes beyond subdomain enumeration. For each discovered asset, it performs technology fingerprinting, HTTP security header analysis, TLS certificate inspection, email security assessment (SPF/DKIM/DMARC), domain health scoring, and typosquatting detection. The pipeline feeds directly into the CARVER scoring system — assets with weak security postures receive higher Accessibility scores, while assets running critical services receive higher Criticality scores.

The **DI Threat Enrichment** and **DI Threat Matching** modules automatically correlate discovered assets against the threat intelligence catalog, flagging any asset that matches known IOCs, has been mentioned in darkweb forums, or runs software with active CVEs in the CISA KEV catalog.

### 6.3 ScanForge — Multi-Tool Scanning Engine

**ScanForge** is AC3's intelligent scanning orchestration layer that coordinates multiple scanning tools — Nuclei, Nmap, ZAP, Burp Suite, and 18 specialized DAST scanners — into a unified scanning pipeline. Rather than running each tool independently and manually correlating results, ScanForge analyzes the target's technology stack and selects the optimal scanner combination, sequences scans to avoid redundancy, deduplicates findings across scanners using CVE-based and signature-based matching, feeds all results into the CARVER+SHOCK scoring engine for unified risk assessment, and applies the **ScanForge Reasoning** LLM specialist to generate narrative analysis of scan results.

The specialized DAST scanner library includes:

| Scanner | Target |
|---|---|
| SQLMap | SQL injection |
| XSStrike | Cross-site scripting |
| Commix | Command injection |
| Tplmap | Template injection |
| Nikto | Web server misconfiguration |
| Wapiti | Web application vulnerabilities |
| Arachni | Comprehensive web scanning |
| SSH Audit | SSH configuration |
| TLS Deep Scanner | Certificate and cipher analysis |
| DNS Audit | DNS configuration |
| SMTP Audit | Mail server security |
| SNMP Audit | SNMP community strings |
| FTP Audit | FTP configuration |
| RDP Audit | Remote desktop security |
| HTTP Header Audit | Security header analysis |
| Service Audit Pipeline | Multi-protocol service enumeration |

### 6.4 Attack Path Discovery and Visualization

The **Attack Path** modules map the relationships between discovered vulnerabilities, network topology, and potential exploitation chains to identify the most likely paths an attacker would follow from initial access to objective completion.

**Network Attack Paths** provide traditional network-layer path analysis using discovered hosts, open ports, vulnerability findings, and credential relationships to map lateral movement opportunities.

**Cloud Attack Paths** provide cloud-specific path analysis that maps IAM privilege escalation chains, cross-account trust relationships, storage bucket misconfigurations, and serverless function vulnerabilities across AWS, Azure, and GCP environments. The **Cloud Security Validation** and **Cloud Workload Testing** modules provide active validation of discovered cloud attack paths.

**Active Directory Attack Paths** provide AD-specific path analysis using BloodHound-compatible data imports, AD domain connector integration, and the Forest Mapper for multi-domain environments. The **AD Attack Path Graph** provides interactive visualization of Kerberoasting paths, delegation abuse chains, ACL exploitation routes, and Group Policy Object attack vectors.

The **Attack Vector Engine** combines all path types into a unified attack graph, scoring each path by feasibility, impact, and detection risk.


---

## 7. Emulation and Testing — Agents, Defense Validation, Ember C2, and Test Lab

The Emulation and Testing group provides the adversary simulation capabilities that transform vulnerability findings into validated exploitation evidence. This is where AC3 transitions from "what could be attacked" to "what we proved can be attacked" — the distinction that separates a vulnerability scanner from a penetration testing platform.

### 7.1 Agents and Adversary Emulation

AC3 integrates natively with **MITRE Caldera** for adversary emulation, providing a bridge between the platform's vulnerability findings and Caldera's ability-based execution framework. The integration includes:

**Caldera Sync** maintains bidirectional synchronization between AC3's asset inventory and Caldera's agent registry. When AC3 discovers a new host, it can automatically register it as a Caldera target. When a Caldera operation produces results, they flow back into AC3's finding database and scoring engine.

**Emulation Playbooks** are pre-built adversary profiles mapped to MITRE ATT&CK techniques. Each playbook defines a sequence of abilities (atomic actions) that simulate a specific threat actor's TTPs. The platform includes playbooks for APT29, APT3, FIN7, and other well-documented threat groups, with the ability to create custom playbooks from the TTP Knowledge Base.

**Ability Graph** provides a visual representation of the ATT&CK technique coverage across all available abilities, showing which techniques have been tested, which have been validated, and which remain uncovered.

**Atomic Red Team** integration provides access to the Atomic Red Team test library for individual ATT&CK technique validation, allowing operators to run specific technique tests without building full adversary profiles.

### 7.2 Defense Validation

The defense validation subsection answers the question that every red team engagement ultimately exists to answer: "Are the defenses working?"

**Purple Team** provides a collaborative interface where red team operators and blue team defenders can jointly execute attack simulations, observe detection results in real-time, and document coverage gaps. The module tracks which ATT&CK techniques were detected, which were missed, and which generated alerts but were not investigated.

**EDR Validation** tests endpoint detection and response products against a catalog of safe attack simulations mapped to ATT&CK techniques. The module generates an effectiveness scorecard showing detection rates, response times, and false positive rates for each EDR product under test.

**Detection Coverage Matrix** provides a heat map of ATT&CK technique coverage across all deployed detection technologies — SIEM rules, EDR signatures, network detection rules, and custom Sigma rules. The matrix identifies blind spots where no detection exists for a given technique.

**NGFW Validation** tests next-generation firewall configurations against known evasion techniques, protocol abuse patterns, and application-layer attacks.

**AI Security Validation** implements a MITRE ATLAS-aligned test suite for validating customer AI and LLM deployments against prompt injection, model extraction, adversarial evasion, data poisoning, and AI supply chain attacks. This module treats customer AI systems as targets to validate — distinct from the AI governance module that protects AC3's own internal LLM calls.

**Sigma Rules** engine generates, manages, and deploys Sigma detection rules based on engagement findings. When a red team operation successfully executes a technique that was not detected, the platform can automatically generate a Sigma rule to close the detection gap.

**Remediation Verification** provides automated re-testing of previously discovered vulnerabilities after remediation has been applied, confirming that fixes are effective and have not introduced new issues.

### 7.3 Ember C2 Agent

**Ember** is AC3's proprietary lightweight C2 agent, designed for internal penetration testing and red team operations. Unlike traditional agents that follow rigid playbooks, Ember combines five architectural pillars that represent significant novel engineering:

**Cognitive Core** — An LLM-powered autonomous decision engine that plans, adapts, and reasons about the target environment in real-time. The Cognitive Engine analyzes the local environment, selects appropriate actions, and adjusts its approach based on observed defenses — without requiring operator intervention for routine decisions.

**Polymorphic Protocol Engine** — Adaptive multi-channel C2 communication with automatic failover, traffic mimicry, and protocol mutation on detection. Ember can communicate over HTTP/S, DNS, WebSocket, and custom protocols, switching channels automatically when one is blocked.

**Modular Capability System** — A plugin architecture where capabilities (reconnaissance, exploitation, persistence, exfiltration) are loaded on-demand from the C2 server. This keeps the initial implant footprint minimal and allows capabilities to be added or removed during an operation.

**Memory Stealth Architecture** — Page-level encryption where only active code pages are ever in plaintext, inspired by advanced memory evasion techniques. This makes memory forensics significantly more difficult.

**Swarm Intelligence** — Multi-agent coordination with shared intelligence, distributed task execution, and collective evasion. Multiple Ember agents can coordinate their actions, share discovered information, and distribute tasks across the swarm.

The Ember fleet is managed through the **Ember Fleet** dashboard, with dedicated interfaces for deployment, task management, payload generation, swarm control, and intelligence aggregation.

### 7.4 Test Lab

The **Test Lab** provides isolated environments for safe testing, training, and capability validation. It includes:

**Environment Management** — Provisioning and lifecycle management of isolated test environments with configurable network topologies, operating systems, and vulnerable applications.

**Scenario Library** — Pre-built attack scenarios for training and capability validation, ranging from basic exploitation exercises to complex multi-stage campaigns.

**Implant Testing** — Dedicated environment for testing Ember implants and other C2 agents against various endpoint protection configurations.

**LLM Training** — Environment for training and evaluating the platform's LLM specialists against known-good test cases, measuring precision, recall, and F1 scores for vulnerability detection and exploit selection.

**Graduation** — The quality gate that determines when an LLM specialist or exploit technique has demonstrated sufficient reliability to be promoted from the test lab to production use. The graduation system tracks performance metrics over time and enforces minimum thresholds before promotion.

---

## 8. Exploit Operations — Phishing, Exploit Tooling, and Post-Exploitation

The Exploit Ops group provides the active exploitation capabilities that transform validated vulnerabilities into demonstrated impact. This section of the platform is the most heavily gated by safety guardrails — every action requires ROE validation, scope checking, and safety level authorization.

### 8.1 Phishing Campaigns

AC3 integrates with **GoPhish** for phishing campaign management, extending the base GoPhish capabilities with AI-powered content generation and reconnaissance-driven targeting.

**Phishing Ops** provides the campaign management interface — target group creation, email template selection, sending schedule configuration, and real-time tracking of opens, clicks, and credential submissions.

**Phishing Assets** (Landing Page Builder) provides a visual editor for creating phishing landing pages, with AI-assisted content generation that can clone legitimate login pages and adapt them for social engineering scenarios.

**Crawl-Phish Generator** automatically generates phishing content based on web crawler results — analyzing the target organization's public web presence to create contextually appropriate social engineering materials.

### 8.2 Exploit Tooling

The exploit tooling subsection provides a comprehensive exploitation framework that goes far beyond running Metasploit modules.

**Exploit Catalog** is the master registry of all available exploits across all sources — Metasploit modules, ExploitDB entries, Nuclei templates, custom exploits, and the platform's own functional exploit generator. Each catalog entry includes CVE mapping, reliability rating, target requirements, and safety classification.

**Exploit Knowledge Store** maintains a knowledge base of exploitation techniques, methodologies, and lessons learned from previous engagements. This knowledge feeds into the LLM's exploit selection reasoning.

**Exploit Reasoning Engine** uses LLM analysis to select the optimal exploit for a given vulnerability, considering factors like target environment, available access, detection risk, and reliability. The reasoning is transparent — the engine produces a narrative explanation of why it selected a particular exploit and what alternatives were considered.

**Exploit Chain Planner** identifies multi-step exploitation paths where individual vulnerabilities that are not independently exploitable can be chained together for greater impact. The planner uses the Attack Path Graph to identify viable chains and the Exploit Reasoning Engine to validate feasibility.

**Exploitation Bridge** is the unified execution layer that abstracts the differences between exploitation frameworks. Whether an exploit runs through Metasploit, a custom Python script, or a Nuclei template, the bridge provides a consistent interface for execution, evidence collection, and result reporting.

**API Security Testing** provides specialized testing for REST and GraphQL APIs, including authentication bypass, authorization testing, injection attacks, and business logic flaws.

**Credential Attacks** provides automated credential testing capabilities — password spraying, credential stuffing, Kerberoasting, AS-REP roasting, and default credential checking against the OEM Default Credentials database.

**Privilege Escalation Engine** automates the discovery and exploitation of local privilege escalation vectors on compromised hosts, covering kernel exploits, SUID/SGID binaries, misconfigured services, and token manipulation.

**Lateral Movement Engine** automates post-exploitation lateral movement using discovered credentials, pass-the-hash, pass-the-ticket, WMI execution, PSExec, and SSH pivoting.

**Data Exfiltration Simulation** demonstrates data exfiltration risk by simulating the extraction of sensitive data through various channels — HTTP/S, DNS tunneling, ICMP, and cloud storage — while measuring detection rates.

### 8.3 C2 and Post-Exploitation

**C2 Hub** provides a unified command and control interface that manages sessions across multiple C2 frameworks — Metasploit, Sliver, Empire, and Ember — from a single dashboard.

**C2 Knowledge Base** maintains tactical knowledge about C2 techniques, evasion methods, and infrastructure management best practices.

**Evasion Engine** provides a comprehensive evasion toolkit that includes EDR evasion techniques, payload encoding, traffic obfuscation, and detection avoidance strategies. The **Evasion Orchestrator** coordinates multi-technique evasion chains, while the **Evasion Scorecard** tracks the effectiveness of evasion techniques against specific security products.

**Session Recordings** captures and replays terminal sessions from exploitation and post-exploitation activities, providing tamper-evident evidence for engagement reports.

---

## 9. Threat Intelligence — The Intelligence Backbone

Threat intelligence is not a bolt-on feature in AC3. It is the connective tissue that runs through every other capability in the platform. Every scan result is enriched against threat intelligence. Every vulnerability finding is correlated with known exploitation activity. Every engagement plan is informed by current threat actor TTPs. The intelligence subsystem is what transforms AC3 from a collection of security tools into an intelligence-driven operations platform.

### 9.1 Architecture of the Intelligence Layer

The threat intelligence architecture is organized in four tiers:

**Tier 1 — Feed Ingestion** comprises the automated connectors that pull raw intelligence from external sources. The platform ingests data from 15+ feed sources on automated schedules, normalizing heterogeneous data formats into a unified internal schema.

**Tier 2 — Enrichment and Correlation** applies LLM-powered analysis to raw intelligence, extracting structured indicators, mapping to ATT&CK techniques, correlating across sources, and assigning confidence levels.

**Tier 3 — Catalog and Knowledge** maintains the persistent intelligence stores — the threat actor catalog, the IOC database, the vulnerability intelligence corpus, and the darkweb event archive.

**Tier 4 — Operational Integration** pushes intelligence into every operational module — scoring engines, exploit selectors, scan prioritizers, and engagement planners — ensuring that every decision is informed by current intelligence.

### 9.2 Threat Intelligence Hub

The **Threat Intel Hub** is the central dashboard for all intelligence operations. It provides a unified view of current threat landscape activity, trending vulnerabilities, active threat campaigns, and intelligence feed health. The hub aggregates data from all intelligence sources and presents it through multiple analytical lenses — by threat actor, by vulnerability, by sector, by geography, and by time.

### 9.3 Feed Ingestion — Sources and Connectors

AC3 ingests threat intelligence from a diverse set of authoritative sources:

| Source | Data Type | Update Frequency |
|---|---|---|
| **CISA KEV** | Known exploited vulnerabilities | Daily |
| **NVD/CVE** | Vulnerability details, CVSS scores | Continuous |
| **Google Project Zero** | Zero-day vulnerability tracking | Daily |
| **abuse.ch URLhaus** | Malicious URLs | Daily |
| **abuse.ch ThreatFox** | IOCs from malware campaigns | Daily |
| **AlienVault OTX** | Threat pulses, IOCs | Continuous |
| **MISP CIRCL OSINT** | Collaborative incident data | Daily |
| **The DFIR Report** | Real intrusion case write-ups | RSS |
| **CISA Advisories** | Government security alerts | RSS |
| **Unit 42 (Palo Alto)** | Vendor threat research | RSS |
| **The Hacker News** | Cyber attack coverage | RSS |
| **Dark Reading** | Breach analysis | RSS |
| **CyberScoop** | Policy and critical infrastructure | RSS |
| **Cybersecurity Dive** | Industry analysis | RSS |
| **HHS OCR Breach Portal** | Healthcare breaches | CSV |
| **SpicyThreatIntel API** | Darkweb intelligence, ransomware stats | API |
| **DailyDarkWeb RSS** | Underground forum monitoring | RSS |

The **IOC Feed Auto-Sync** service runs as a scheduled background task (daily at 06:00 UTC) to fetch IOCs from CISA KEV, abuse.ch URLhaus, and abuse.ch ThreatFox, storing results in the IOC database and logging sync history.

The **Threat Intel RSS** aggregator monitors 7+ security news feeds for new advisories, breach announcements, and threat research, using LLM extraction to parse unstructured articles into structured intelligence records.

### 9.4 Vulnerability Intelligence

The **Vuln Intel** module provides deep vulnerability analysis that goes beyond what NVD provides:

**NVD CVE Matcher** correlates discovered assets against the full NVD database, matching by CPE (Common Platform Enumeration), product name, and version number. The matcher handles version range logic, vendor aliases, and product name variations that cause false negatives in simpler matching systems.

**CISA KEV Catalog** integration provides real-time tracking of the Known Exploited Vulnerabilities catalog, with automatic alerting when a vulnerability affecting a client's assets is added to KEV. The **KEV Refresh Scheduler** ensures the local KEV cache is always current.

**Zero-Day Tracker** monitors the Google Project Zero "0day In the Wild" dataset and integrates it with CISA KEV data for a unified zero-day view. The **Zero-Day Pipeline** processes new zero-day disclosures through LLM analysis to assess potential impact on monitored assets.

**CVE Enrichment Service** augments raw CVE data with exploit availability (from ExploitDB and Metasploit), patch status, vendor advisory links, and EPSS (Exploit Prediction Scoring System) probability scores. This enrichment feeds directly into the hybrid scoring engine's likelihood calculations.

### 9.5 Threat Actor Intelligence

The threat actor intelligence subsystem is one of AC3's most distinctive capabilities. Rather than maintaining a static database of known threat groups, the platform operates a continuous intelligence cycle that discovers, tracks, enriches, and operationalizes threat actor information.

**Threat Actor Catalog** is the master registry of all known threat actors — APT groups, ransomware gangs, cybercrime syndicates, hacktivists, access brokers, and influence operators. Each catalog entry includes aliases, attributed nation-state, known TTPs mapped to ATT&CK, target sectors, historical campaigns, and associated IOCs. The catalog is not static; it is continuously updated by the crawler and enrichment systems.

**Threat Actor Crawler** is the autonomous intelligence collection engine that continuously enriches the catalog by crawling OSINT sources, news feeds, security research, government advisories, and social media for new TTPs, IOCs, campaign details, and activity timelines. The crawler uses LLM extraction to parse unstructured text into structured actor intelligence, and the **Threat Actor Matcher** automatically maps new articles to existing catalog entries or flags potential new groups for analyst review.

**Threat Actor Discovery** identifies previously unknown threat groups from patterns in IOC data, darkweb forum activity, and incident reports. When the system detects a cluster of activity that does not match any known group, it creates a provisional catalog entry and begins targeted enrichment.

**Threat Group Browser** provides an interactive interface for exploring the full threat actor catalog, with filtering by nation-state, type (APT, ransomware, hacktivist), target sector, activity level, and ATT&CK technique coverage.

**Threat Group Knowledge** maintains deep-dive intelligence profiles for priority threat groups, including detailed campaign timelines, infrastructure analysis, and TTP evolution tracking.

### 9.6 Dark Web Intelligence

The dark web intelligence subsystem monitors underground forums, marketplaces, and paste sites for intelligence relevant to monitored organizations and the broader threat landscape.

**DarkWeb Intel Service** provides higher-order analysis functions including ransomware actor synchronization, affiliate tracking, victim monitoring, sector-based enrichment, cross-source correlation, and trend analysis.

**DarkWeb Feeds** aggregates data from multiple underground sources, normalizing the heterogeneous data formats into a unified event schema. The **DarkWeb Feed Scheduler** manages automated collection cycles.

**DarkWeb IOC Enrichment** cross-references darkweb indicators against the platform's asset inventory, flagging any discovered credentials, leaked data, or mentioned organizations that match monitored clients.

**DarkWeb OSINT Service** provides targeted intelligence collection for specific organizations, searching underground sources for mentions of the organization's domains, email addresses, employee names, and proprietary data.

**Ransomware Intel** tracks ransomware group activity including victim announcements, ransom demands, data leak timelines, and affiliate relationships. The **Ransomware Groups** dashboard provides a real-time view of active ransomware operations across all tracked groups.

**SpicyThreatIntel Bridge** provides a server-to-server API connector to the SpicyThreatIntel platform for darkweb intelligence data, including ransomware victim statistics, ThreatFox IOCs, activity ratings, global threat actors, CISA KEV data, and OTX pulses.

### 9.7 Conflict Theater — Geopolitical Intelligence

The **Conflict Theater** module provides geopolitical context for cyber operations by tracking five major conflict zones and their associated cyber threat activity:

| Conflict Zone | Key Actors | Cyber Dimensions |
|---|---|---|
| **Russia-Ukraine War** | Russian APTs, Ukrainian hacktivists, Belarusian proxies | State-sponsored espionage, destructive malware, influence operations, hacktivist DDoS |
| **Israel-Hamas/Iran** | IRGC-linked APTs, Palestinian hacktivists, Hezbollah cyber units | Critical infrastructure targeting, hacktivist campaigns, influence operations |
| **China-Taiwan Tensions** | Chinese state-sponsored groups, pre-positioning operations | Espionage, supply chain compromise, pre-conflict infrastructure mapping |
| **North Korea Cyber Ops** | Lazarus Group, Kimsuky, APT38 | Financial theft, cryptocurrency heists, sanctions evasion, espionage |
| **Iran-US/Gulf Tensions** | IRGC cyber units, proxy groups | Infrastructure targeting, Gulf state espionage, Western interest attacks |

For each conflict zone, the module tracks associated threat actors, recent cyber operations, IOC activity, and geopolitical developments that may signal escalation in cyber operations. This intelligence feeds into the sector-aware scoring system — organizations in sectors targeted by active conflict-zone actors receive elevated threat scores.

### 9.8 Threat Enrichment and Context Engine

The **Threat Enrichment** module applies LLM-powered analysis to raw intelligence data, producing structured enrichment that includes ATT&CK technique mapping, confidence scoring, relevance assessment, and operational recommendations.

The **Context Engine** is the intelligence fusion layer that combines data from all intelligence sources — vulnerability feeds, threat actor tracking, darkweb monitoring, and geopolitical analysis — into a unified threat context for each monitored organization. When an operator opens an engagement, the Context Engine provides a pre-built intelligence briefing that includes relevant threat actors, active campaigns targeting the client's sector, recently exploited vulnerabilities in the client's technology stack, and any darkweb mentions of the client's assets.

### 9.9 IOC Management and Cross-Reference

The **IOC Feed** provides a searchable database of all ingested indicators of compromise — IP addresses, domains, URLs, file hashes, email addresses, and Bitcoin wallets — with source attribution, confidence levels, and temporal metadata.

The **IOC Cross-Reference** engine automatically correlates IOCs across multiple sources, identifying overlapping indicators that may represent the same campaign or actor. The **IOC-TTP Reverse Engineer** module attempts to infer the likely ATT&CK techniques used in an attack based on the observed IOC patterns.

### 9.10 Intelligence Integration with Operations

The intelligence layer's operational value comes from its deep integration with every other platform capability:

**Scoring Integration** — The hybrid CARVER+SHOCK scoring engine consumes threat intelligence to adjust likelihood scores. A vulnerability with an active exploit in the wild (confirmed via KEV or ThreatFox) receives a higher likelihood score than one with only a theoretical proof-of-concept.

**Scan Prioritization** — ScanForge uses threat intelligence to prioritize scanning targets. Assets running software with recently disclosed zero-days or active KEV entries are scanned first.

**Exploit Selection** — The Exploit Reasoning Engine considers threat intelligence when selecting exploits. If a specific threat actor is known to target the client's sector using a particular technique, the engine prioritizes testing that technique.

**Engagement Planning** — The AI Attack Planner incorporates threat intelligence into engagement plans, recommending attack paths that simulate the TTPs of threat actors most likely to target the client.

**Report Enrichment** — Generated reports include threat intelligence context, explaining not just what vulnerabilities were found but which threat actors are known to exploit them and what the potential business impact would be.

---

## 10. Key Security Indicators and Compliance

The Key Security Indicators (KSI) and Compliance group provides the measurement and governance capabilities that translate offensive security findings into compliance evidence and executive-level metrics.

### 10.1 KSI Dashboard

The KSI Dashboard tracks quantitative security metrics aligned with FedRAMP continuous monitoring requirements and NIST SP 800-137. Key indicators include vulnerability scan coverage, mean time to remediate, patch currency ratios, compliance control pass rates, and security incident response times. Each indicator includes trend visualization, threshold alerting, and drill-down to supporting evidence.

### 10.2 KSI Auto Collector and Evidence Chain

The **KSI Auto Collector** automatically gathers evidence artifacts from scan results, engagement findings, compliance checks, and remediation verifications. Each artifact is cryptographically hashed and linked into a tamper-evident **Evidence Chain** using SHA-256 hash chaining — creating a blockchain-like integrity trail that proves evidence has not been modified after collection.

The **KSI Threat Map** provides a geographic visualization of threat activity relevant to monitored assets, overlaying threat intelligence data on a map interface.

### 10.3 Compliance Center

The **Compliance Center** provides framework-aware compliance tracking for multiple regulatory standards:

| Framework | Coverage |
|---|---|
| **NIST SP 800-53** | Full control catalog with automated evidence mapping |
| **NIST CSF** | Function/Category/Subcategory mapping |
| **FedRAMP** | Baseline controls with POA&M tracking |
| **CMMC** | Level 1-3 practice assessment |
| **PCI DSS** | Requirement mapping for payment environments |
| **HIPAA** | Security Rule safeguard tracking |
| **SOC 2** | Trust Services Criteria mapping |
| **ISO 27001** | Annex A control mapping |

The **Compliance Mapper** automatically maps engagement findings to compliance control failures, generating pre-populated POA&M (Plan of Action and Milestones) entries. The **Compensating Controls** module tracks alternative controls implemented when primary controls cannot be met.

**Control Testing** provides automated testing of compliance controls using the platform's scanning and emulation capabilities — for example, testing access control effectiveness by attempting unauthorized access, or testing encryption requirements by analyzing TLS configurations.

### 10.4 Data Export and Interoperability

The platform supports multiple export formats for interoperability with external systems:

**STIX Generator** produces STIX 2.1 bundles containing threat intelligence, IOCs, and threat actor profiles for sharing with ISACs and partner organizations.

**OSCAL Export** generates NIST OSCAL (Open Security Controls Assessment Language) documents for automated compliance reporting to federal agencies.

**Pentest Export** provides engagement results in multiple formats — PDF reports, CSV findings, JSON data exports — for integration with client GRC (Governance, Risk, and Compliance) platforms.


---

## 11. Reports, Knowledge, and Continuous Learning

The Reports and Knowledge group provides the output layer that transforms raw operational data into actionable deliverables and the learning layer that makes the platform smarter over time.

### 11.1 Report Generator

The **Report Generator** produces professional-grade penetration test reports, vulnerability assessment reports, and executive summaries from engagement data. Reports are generated using LLM-powered narrative writing combined with structured data from the engagement database, producing documents that read like they were written by a senior consultant rather than assembled by a template engine.

Report types include:

| Report Type | Audience | Content |
|---|---|---|
| **Executive Summary** | CISOs, Board | Business risk overview, key findings, strategic recommendations |
| **Technical Report** | Security teams | Detailed findings, reproduction steps, evidence, remediation guidance |
| **Vulnerability Assessment** | IT operations | Prioritized vulnerability list with patch recommendations |
| **Compliance Report** | Auditors | Framework-mapped findings with control gap analysis |
| **Purple Team Report** | SOC teams | Detection coverage analysis, gap identification, rule recommendations |
| **Campaign Summary** | Management | Multi-engagement trend analysis, ROI metrics |

The **Report Wizard** provides a guided interface for customizing report content, selecting findings, adjusting severity ratings, and adding analyst commentary before generation. The **Report Templates** system supports custom branding, formatting, and content structure for white-label deployments.

### 11.2 Knowledge Bases

AC3 maintains multiple specialized knowledge bases that support both human operators and LLM reasoning:

**Pentest Knowledge Base** contains 300+ attack chains from real-world penetration testing engagements, organized by target type, technique, and complexity. This knowledge feeds the AI Attack Planner and the Engagement Orchestrator.

**Exploit Knowledge Store** maintains exploitation methodology, technique documentation, and lessons learned from previous exploit attempts. This knowledge feeds the Exploit Reasoning Engine.

**TTP Knowledge Base** provides comprehensive documentation of ATT&CK techniques with practical implementation guidance, detection indicators, and defensive recommendations.

**ScanForge Knowledge** contains scanner-specific knowledge — optimal configurations, false positive patterns, and result interpretation guidance — that feeds the ScanForge Reasoning LLM specialist.

**Remediation Knowledge Base** provides detailed remediation guidance for common vulnerability classes, including code-level fixes, configuration changes, and architectural recommendations.

### 11.3 Continuous Learning and Self-Improvement

The platform includes a sophisticated continuous learning architecture that improves its capabilities over time:

**LLM Self-Learning Engine** (SSIL — Self-Supervised Intelligence Loop) monitors the outcomes of LLM-assisted decisions and uses the results to improve future performance. When an LLM-recommended exploit succeeds, the decision context is recorded as a positive training signal. When a recommendation fails, the failure context is analyzed and stored as a negative signal. Over time, the system builds a corpus of engagement-specific knowledge that supplements the base LLM's training.

**Continuous Training** provides a framework for evaluating and improving LLM specialist performance through automated test suites, A/B testing of prompt variations, and performance regression detection.

**Training Feedback** captures operator corrections to LLM outputs — when an operator overrides an LLM recommendation, the correction is logged with context and used to improve future recommendations.

**Graduation System** manages the promotion of LLM capabilities from experimental to production status. A new LLM specialist or prompt variation must demonstrate consistent performance above minimum thresholds across a test suite before being promoted. The **Graduation Drift Detector** monitors production performance and triggers re-evaluation if accuracy drops below the graduation threshold.

### 11.4 Breach Intelligence and Incident Search

The **Breach Events** module tracks publicly disclosed data breaches, correlating breach details with the platform's asset inventory to identify potential exposure. The **Incident Search** capability provides a searchable archive of security incidents, breach notifications, and regulatory actions, allowing operators to research an organization's security history during engagement planning.

---

## 12. Platform Administration and Multi-Tenancy

The Platform group provides the administrative, integration, and infrastructure capabilities that support AC3's operation as a multi-tenant SaaS platform.

### 12.1 White-Label and Multi-Tenancy

The **White-Label** module provides comprehensive branding customization — logos, color schemes, email templates, report headers, and domain names — allowing MSSPs to deploy AC3 under their own brand. All branding is configured through environment variables prefixed with `WL_`, requiring no code changes.

The **Tenant Isolation** module enforces strict data separation between tenants at the database level. Every query is automatically scoped to the current tenant's data partition, preventing cross-tenant data leakage. The isolation is enforced at the ORM layer, making it impossible for application code to accidentally access another tenant's data.

### 12.2 License Tier Management

The platform implements three license tiers with feature gating:

| Tier | Feature Modules | Target Customer |
|---|---|---|
| **Starter** | Domain Intel, Threat Catalog, Vuln Scanner, Reports, Incident Search, Affiliated Domains | Solo practitioners, small consultancies |
| **Professional** | + Adversary Emulation, Phishing Ops, Zero-Day Tracker, Compliance, Training, Bounty Intel, Client Portal | Mid-market MSSPs, enterprise security teams |
| **Enterprise** | + Campaign Orchestrator, AI Security Validation, Ember Agents, CI/CD Pipeline, Red Team Ops | Large MSSPs, government contractors, enterprise red teams |

Feature access is enforced at the tRPC procedure level — attempting to call a procedure for a feature not included in the current license tier returns a structured error with upgrade guidance.

### 12.3 MSSP Analytics

The **MSSP Analytics** module provides multi-client portfolio analytics for managed security service providers. It aggregates risk scores, vulnerability trends, compliance postures, and engagement metrics across all managed clients, providing a portfolio-level view of security posture with drill-down to individual client details.

### 12.4 Client Portal

The **Client Portal** provides a read-only interface for MSSP clients to view their engagement results, risk scores, compliance status, and remediation progress without requiring access to the full operator platform. The portal supports custom branding per client and role-based access control for client team members.

### 12.5 Vendor Integrations

AC3 integrates with major security vendor platforms through a unified **Vendor Bridge** architecture:

| Vendor | Integration Type | Capabilities |
|---|---|---|
| **Splunk** | SIEM | Log forwarding, alert correlation, dashboard integration |
| **CrowdStrike** | EDR | Agent status, detection data, response actions |
| **SentinelOne** | EDR | Threat data, agent management, response |
| **Microsoft Defender** | EDR/XDR | Alert ingestion, device status, response |
| **Cortex XDR** | XDR | Incident data, agent management |
| **Microsoft Sentinel** | SIEM/SOAR | Alert correlation, playbook triggering |
| **Palo Alto XSOAR** | SOAR | Incident creation, playbook execution |

Each vendor integration implements a common `BaseClient` interface, allowing the platform to interact with all vendors through a unified API. The **SOAR Expansion** module extends the vendor bridge with automated response playbooks that can be triggered by engagement findings or threat intelligence alerts.

### 12.6 CI/CD Integration

The **CI/CD Pipeline** module integrates security testing into software development workflows. It provides GitHub Actions integration for automated scanning on pull requests, scheduled vulnerability assessments, and security gate enforcement. The **CI/CD Baseline Scheduler** manages recurring scan schedules, and the **CI/CD Schedule Conflict** resolver prevents overlapping scans from consuming excessive resources.

### 12.7 Infrastructure Management

The **Scan Server** module manages the dedicated scanning infrastructure — provisioning, health monitoring, and task distribution for the remote scan server that runs Nmap, Subfinder, Httpx, and Naabu. The **Infrastructure Hardening** module monitors the security posture of the platform's own infrastructure, applying the same security standards to the platform that it enforces on client environments.

---

## 13. The Hybrid Risk Scoring System — CARVER+SHOCK/CVSS/BIA Fusion

The hybrid scoring system is AC3's most technically distinctive capability and the strongest candidate for intellectual property protection. A comprehensive technical deep dive is provided in the companion document **AC3 Hybrid Scoring System Deep Dive v2**, but this section provides an architectural summary.

### 13.1 The Problem Being Solved

Traditional vulnerability management relies on CVSS scores as the primary risk metric. CVSS is a technical severity rating — it measures how bad a vulnerability is in isolation. It does not measure how much damage exploitation would cause to a specific organization, in a specific sector, with specific business processes at risk. A CVSS 9.8 vulnerability on a development server that processes no real data is less urgent than a CVSS 6.5 vulnerability on the authentication gateway for a hospital's electronic health records system. CVSS cannot express this distinction. AC3's hybrid scoring system can.

### 13.2 The Three-Pillar Architecture

The scoring system fuses three independent assessment frameworks:

**CARVER+SHOCK** (50% weight) is a military target analysis methodology adapted for cybersecurity. CARVER scores assets on seven factors — Criticality, Accessibility, Recuperability, Vulnerability, Effect, and Recognizability — while SHOCK scores the downstream consequences — Systemic impact, Health/safety risk, Operational disruption, Cascading failures, and Known precedent. The CARVER+SHOCK composite provides the "mission impact" dimension that CVSS lacks.

**CVSS** (30% weight) provides the technical severity baseline. AC3 supports CVSS v3.1 and v4.0, with automatic parsing of CVSS vectors and a novel feed-through mechanism that maps CVSS v4.0 metric groups to CARVER factor adjustments.

**BIA** (20% weight) provides the business impact dimension. The Auto-BIA module dynamically infers business impact from asset signals — MX records suggest email infrastructure, SSO endpoints suggest identity systems, payment processing indicators suggest financial systems — and assigns impact tiers without requiring manual business impact assessments.

### 13.3 The Fusion Formula

The core fusion formula is:

```
HybridScore = (CARVER_composite / 70 * W_carver) + (CVSS / 10 * W_cvss) + (BIA * W_bia)
```

where `W_carver = 0.50`, `W_cvss = 0.30`, `W_bia = 0.20` by default, adjustable per engagement profile. The result is a normalized 0-1 score that is then classified into severity tiers (Critical, High, Medium, Low, Informational) using sector-aware thresholds.

### 13.4 Sector-Aware Calibration

The scoring system includes pre-built sector profiles for six industry verticals — Healthcare, Financial Services, Government, Critical Infrastructure, Technology, and Retail/E-commerce — each with calibrated CARVER factor weights, SHOCK multiplier ranges, regulatory overlay adjustments, and severity tier thresholds. These sector profiles encode practitioner judgment about what matters most in each industry context. The Healthcare profile, for example, amplifies Health/safety risk and Recuperability factors because patient safety and system recovery time are disproportionately important in healthcare environments. These calibrations were not derived from a textbook; they were calibrated based on observed behavior across two decades of engagements in these specific sectors.

### 13.5 Production Hardening

The scoring engine includes multiple hardening layers: input validation and NaN protection, correlated-input damping (logarithmic damping when multiple enrichment sources push the same CARVER factor), deterministic fallback scoring when LLM classification fails, scoring audit trails, distribution monitoring with actionable response objects, and an inter-rater reliability harness for comparing independent operator assessments.

### 13.6 Temporal Decay

The **Temporal Decay** module adjusts severity scores based on time-sensitive factors — age of the finding, time since CVE publication, time since last validation, KEV listing recency, and patch availability window. A vulnerability that has been known for six months with a patch available but not applied receives a higher temporal multiplier than a freshly disclosed vulnerability with no patch yet available.

---

## 14. Engagement and Campaign Orchestration

The engagement and campaign orchestration capabilities are what transform AC3 from a collection of security tools into an operational platform. They provide the workflow management, automation, and coordination that allow a single operator to execute complex multi-phase security assessments.

### 14.1 Engagement Orchestrator

The **Engagement Orchestrator** is the LLM-driven autonomous execution engine. Given a target scope and engagement parameters, it can execute a complete penetration testing workflow — from passive reconnaissance through active scanning, vulnerability assessment, exploitation, and reporting — with minimal operator intervention.

The orchestrator progresses through nine phases:

| Phase | Actions | Operator Approval Required |
|---|---|---|
| 1. Passive OSINT | Domain intel, subdomain enumeration, technology fingerprinting | No |
| 2. Active Discovery | Port scanning, service enumeration, version detection | No |
| 3. Vulnerability Assessment | Multi-tool scanning, finding correlation | No |
| 4. Risk Scoring | CARVER+SHOCK/CVSS/BIA hybrid scoring | No |
| 5. Attack Planning | AI-generated exploitation plan | Yes — plan review |
| 6. Exploitation | Validated exploitation of approved targets | Yes — per-exploit approval |
| 7. Post-Exploitation | Lateral movement, privilege escalation | Yes — per-action approval |
| 8. Evidence Collection | Screenshot capture, session recording, data sampling | No |
| 9. Report Generation | Automated report writing and evidence packaging | No |

The key safety property is that phases 1-4 and 8-9 run autonomously, while phases 5-7 require explicit operator approval for each high-risk action. This design allows the orchestrator to handle the labor-intensive but low-risk phases automatically while ensuring human judgment governs all exploitation decisions.

### 14.2 Campaign Orchestrator

The **Campaign Orchestrator** manages multi-engagement campaigns — coordinating multiple concurrent engagements, tracking cross-engagement findings, and producing campaign-level analytics. This is the module that enables MSSPs to manage portfolios of client engagements from a single operational view.

Campaign features include:

**Campaign Templates** — Pre-built campaign structures for common scenarios (quarterly vulnerability assessment, annual penetration test, continuous monitoring program).

**Phase Gating** — Configurable approval gates between campaign phases, ensuring that findings from one phase are reviewed before the next phase begins.

**Resource Scheduling** — Operator assignment and workload balancing across concurrent engagements.

**Campaign Analytics** — Cross-engagement trend analysis, finding correlation, and portfolio-level risk metrics.

### 14.3 ROE Builder and Scope Guard

The **ROE Builder** provides a structured interface for defining Rules of Engagement — target scope, authorized techniques, time windows, escalation procedures, and emergency contacts. The ROE is stored as a machine-readable document that the **Scope Guard** enforces at runtime.

The **Scope Guard** is a real-time enforcement engine that validates every operator and automated action against the current ROE before execution. If an action targets an asset outside the authorized scope, uses a technique not authorized in the ROE, or occurs outside the authorized time window, the Scope Guard blocks the action and logs the attempted violation. This enforcement is not advisory — it is a hard gate that cannot be bypassed without modifying the ROE.

### 14.4 OPSEC Risk Engine

The **OPSEC Risk Engine** provides LLM-driven detection simulation for every operator action. Before an action is executed, the engine scores its detection risk by simulating how EDR, SIEM, and NDR products would detect the action. High-risk actions are flagged with safer alternatives. The engine tracks cumulative OPSEC exposure across the engagement and detects "burn" indicators — signals that the operator has likely been detected by the target's defenses.

The **OPSEC Monitor** provides infrastructure-level security monitoring — SSH key management, firewall rule validation, service hardening checks, and centralized logging for the platform's own operational infrastructure.

### 14.5 Hunt Operations

The **Hunt Engine** implements DHS/GSA HACS-compliant threat hunting workflows aligned with the CISA methodology (PREPARE, EXECUTE, ACT) and the Sqrrl/PEAK hypothesis-driven framework. Hunt operations are informed by the platform's threat intelligence, using current threat actor TTPs and IOCs to generate hunting hypotheses. The hunt engine draws on a knowledge base of 300+ attack chains from real-world engagements to identify patterns that may indicate compromise.


---

## 15. Safety Architecture — Seven Layers of Guardrails

Safety is not an afterthought in AC3. It is a structural property of the architecture — seven independent layers of guardrails that enforce operational boundaries at every level of the platform. The safety architecture reflects a core design philosophy: an offensive security platform that can cause harm if misused must be built with the same engineering discipline applied to safety-critical systems in aviation, medicine, and nuclear operations.

### 15.1 Layer 1 — ROE Scope Enforcement

Every action in the platform — whether initiated by a human operator or an automated system — is validated against the current Rules of Engagement before execution. The Scope Guard maintains a runtime representation of the authorized scope (target IP ranges, domain names, authorized techniques, time windows) and performs real-time validation. Out-of-scope actions are blocked, not warned. The enforcement is implemented at the tRPC procedure level, making it impossible for any client-side code to bypass the check.

### 15.2 Layer 2 — Safety Level Classification

Every exploit, technique, and automated action in the platform is classified into one of four safety levels:

| Level | Description | Authorization |
|---|---|---|
| **Safe** | Read-only operations, passive reconnaissance | Automatic |
| **Cautious** | Active scanning, non-destructive probing | Automatic with logging |
| **Aggressive** | Exploitation, credential attacks, privilege escalation | Requires operator approval |
| **Dangerous** | Destructive operations, data modification, denial of service | Requires explicit operator confirmation with impact acknowledgment |

The safety level classification is enforced by the **Exploit Guardrails** module, which gates every exploitation action based on its safety classification and the engagement's authorized safety level.

### 15.3 Layer 3 — LLM Output Filtering

All LLM outputs that influence operational decisions — exploit selection, attack planning, evasion recommendations — pass through the **LLM Guardrails** module before being acted upon. The guardrails enforce:

**Input Filtering** — Prompt injection detection and sanitization for all user-provided content that enters LLM prompts.

**Output Validation** — Structured output parsing with schema validation, ensuring LLM responses conform to expected formats and value ranges.

**Decision Bounds** — Hard limits on LLM-recommended actions. The LLM cannot recommend actions above the engagement's authorized safety level, cannot recommend targets outside the authorized scope, and cannot recommend techniques not included in the engagement's authorized technique set.

**Hallucination Detection** — Cross-validation of LLM-generated technical claims against the platform's knowledge bases. If the LLM claims a CVE exists that is not in the NVD database, or recommends an exploit module that does not exist in the exploit catalog, the claim is flagged.

### 15.4 Layer 4 — Evidence Integrity

The **Evidence Integrity** module ensures that all evidence collected during engagements is tamper-evident. Every evidence artifact — screenshots, session recordings, scan results, exploitation logs — is cryptographically hashed at collection time and linked into a hash chain. Any modification to evidence after collection would break the chain, making tampering detectable. This is not just a security feature; it is a legal requirement for evidence that may be used in compliance audits, incident response, or legal proceedings.

### 15.5 Layer 5 — AI Governance Pipeline

The **AI Governance** module implements a comprehensive governance framework for all AI-assisted decisions in the platform, aligned with the NIST AI Risk Management Framework (AI RMF). The governance pipeline includes:

**Decision Audit Trail** — Every AI-assisted decision is logged with full context: the input data, the prompt, the model response, the parsed decision, and the action taken. This trail is immutable and available for post-engagement review.

**Circuit Breakers** — Automatic disengagement of AI-assisted automation when error rates exceed configurable thresholds. If the LLM begins producing invalid outputs (parsing failures, out-of-bounds values, hallucinated references), the circuit breaker trips and the system falls back to deterministic processing.

**Rate Limiting** — Configurable rate limits on AI-assisted actions to prevent runaway automation. The limits are set per engagement, per action type, and per time window.

**Bias Detection** — Monitoring for systematic bias in AI-assisted scoring and decision-making. The distribution monitoring system (detailed in the Hybrid Scoring Deep Dive) detects when scoring distributions deviate from expected patterns, which may indicate bias in the LLM's reasoning.

**Human-in-the-Loop Enforcement** — Configurable policies that require human approval for AI-assisted decisions above specified risk thresholds. The default policy requires human approval for all exploitation decisions, all scope changes, and all actions classified as Aggressive or Dangerous.

### 15.6 Layer 6 — Scoring Hardening

The **Scoring Hardening** layer protects the integrity of the hybrid risk scoring system through input validation, NaN protection, division-by-zero guards, deterministic fallback scoring, correlated-input damping, distribution monitoring, and inter-rater reliability testing. This layer ensures that the scoring system produces reliable, defensible results even when fed adversarial, malformed, or edge-case inputs. The full technical details are documented in the Hybrid Scoring Deep Dive v2.

### 15.7 Layer 7 — Operational Guardrails

The operational guardrails enforce platform-level safety policies:

**Tenant Isolation** — Strict data separation between tenants, enforced at the ORM layer.

**Session Management** — Secure session handling with JWT-based authentication, CSRF protection, and session expiration.

**Audit Logging** — Comprehensive logging of all operator actions, automated actions, and system events. Logs are append-only and cannot be modified or deleted by operators.

**Infrastructure Hardening** — The platform's own infrastructure is monitored and hardened using the same standards applied to client environments.

**FIPS 140-2 Compliance** — Cryptographic operations use FIPS-validated algorithms when operating in government environments.

---

## 16. AI Governance and LLM Reliability

AC3 employs 13 LLM specialist modules, each trained (via system prompts and knowledge injection) for a specific operational domain. The AI governance architecture ensures that these specialists operate reliably, transparently, and within defined boundaries.

### 16.1 LLM Specialist Modules

| Specialist | Domain | Key Functions |
|---|---|---|
| **Attack Planner** | Engagement planning | Generate prioritized attack plans from scored findings |
| **Vulnerability Verifier** | Finding validation | Assess vulnerability validity and exploitability |
| **Scan Analyzer** | Scan results | Interpret multi-tool scan results, identify patterns |
| **Report Writer** | Documentation | Generate professional narrative from engagement data |
| **Threat Mapper** | Intelligence | Map findings to ATT&CK techniques and threat actors |
| **Exploit Selector** | Exploitation | Choose optimal exploit for target/vulnerability pair |
| **Evasion Advisor** | Stealth | Recommend evasion techniques for detection avoidance |
| **CARVER Scorer** | Risk assessment | Apply CARVER+SHOCK scoring with sector awareness |
| **ScanForge Reasoner** | Scan orchestration | Select scanner combinations and interpret results |
| **Hunt Hypothesis Generator** | Threat hunting | Generate hunting hypotheses from threat intelligence |
| **Remediation Advisor** | Defense | Generate remediation guidance for findings |
| **Engagement Orchestrator** | Automation | Drive autonomous engagement execution |
| **OPSEC Analyst** | Detection risk | Score detection risk and recommend safer alternatives |

### 16.2 Reliability Architecture

The LLM reliability architecture includes multiple mechanisms to ensure consistent, trustworthy AI behavior:

**Structured Output Enforcement** — All LLM calls that produce operational decisions use JSON schema-constrained outputs, ensuring responses conform to expected data structures. Free-text generation is reserved for narrative content (reports, summaries) where structural constraints are unnecessary.

**Deterministic Fallback** — Every LLM-assisted operation has a deterministic fallback path. If the LLM is unavailable, returns an unparseable response, or produces values outside expected ranges, the system falls back to rule-based processing. The fallback produces conservative results — it will never score a vulnerability higher than the deterministic baseline, ensuring that LLM failures result in under-scoring rather than over-scoring.

**Throttle and Rate Control** — The **LLM Throttle** module manages API rate limits, request queuing, and cost control across all LLM specialists. It implements priority queuing (exploitation decisions take priority over report generation), request deduplication, and configurable spending limits.

**Performance Monitoring** — The **LLM Performance Monitor** tracks response times, error rates, parsing success rates, and output quality metrics for each specialist. Degradation triggers automatic alerts and, if sustained, circuit breaker activation.

**Prompt Versioning** — All system prompts are versioned and tracked. Changes to prompts require graduation testing before deployment, ensuring that prompt modifications do not degrade specialist performance.

---

## 17. Code vs. Judgment — The Two Kinds of Intellectual Property

AC3 contains two fundamentally different kinds of intellectual property, and the distinction matters for defensibility, customer trust, and continuity planning.

### 17.1 Architecture — The Rebuildable Layer

The first kind is **architecture**: the system design, the module structure, the data flow patterns, the API contracts, and the integration protocols. This is sophisticated engineering — 633 modules, 352 database tables, 13 LLM specialists — but it is, in principle, rebuildable. A sufficiently capable engineering team, given the specification, could reconstruct the architecture. The architecture is defensible through trade secret protection and, where applicable, software patents, but it is not the platform's deepest moat.

### 17.2 Calibration — The Irreproducible Layer

The second kind is **calibration**: the scoring thresholds, the sector anchors, the CARVER digital translation tables, the ROE parsing priorities, the graduation drift sensitivities, the safety level classifications, and the LLM system prompts that encode operational judgment. This calibration could not be reproduced by an engineering team working from a specification, because it was not derived from a specification. It was derived from twenty-five years of operational experience — walking buildings, penetrating networks, observing what organizations actually guard and why, and internalizing the patterns that distinguish a critical asset from a merely expensive one.

When the deep dive describes a particular threshold — for example, the CARVER Criticality anchor that maps "single point of failure for revenue-generating service" to a score of 9 — it is worth understanding that this anchor was not selected from a menu of options. It was calibrated based on observed behavior across hundreds of engagements where the practitioner saw what happened when that specific type of asset was compromised. The threshold encodes a judgment that took decades to develop.

This distinction matters for three audiences:

**For customers:** The calibration is what makes AC3's risk scores trustworthy. A competitor could build a similar architecture, but without the operational experience to calibrate it, the scores would be arbitrary rather than grounded.

**For investors:** The calibration is the deepest moat. It cannot be reverse-engineered from the software alone, because the relationship between the code and the judgment that produced it is not recoverable from the code.

**For continuity planning:** The calibration is what must be preserved if the platform is to survive its creator. This is addressed in the next section.

---

## 18. Continuity and the Bus Factor

A solo-built platform at AC3's capability level will raise the bus factor question in every serious procurement conversation, and the right move is to address it openly rather than being surprised by it.

### 18.1 What Survives the Builder

The platform's continuity posture rests on three pillars:

**Code as Documentation** — The 666,579 lines of TypeScript are themselves the most detailed documentation of the platform's architecture. The modular structure — each capability in its own file with JSDoc headers explaining purpose, inputs, outputs, and dependencies — means that a competent TypeScript engineer can understand any module in isolation. The code is the specification.

**Calibration Documentation** — The scoring thresholds, sector anchors, and translation tables are documented in the codebase with inline comments explaining the operational rationale for each value. The companion documents (Hybrid Scoring Deep Dive, this Platform Deep Dive) provide the higher-level reasoning that connects individual calibration decisions to the operational experience that produced them. These documents are the handoff protocol for the calibration judgment.

**Test Suites as Behavioral Contracts** — The vitest test suites define the expected behavior of every critical system. Even if the rationale for a particular threshold is lost, the test suite preserves the behavioral contract — "given these inputs, the system must produce these outputs." A future maintainer can modify the implementation while preserving the behavior.

### 18.2 What Requires the Builder

Honest assessment requires acknowledging what cannot be fully documented:

**Novel Calibration** — When AC3 encounters a new industry vertical, a new threat landscape, or a new class of vulnerability, the initial calibration of scoring parameters requires the same kind of operational judgment that produced the existing calibrations. This judgment can be partially encoded in the LLM specialists' system prompts, but the prompts themselves were written by someone with the operational experience to know what matters.

**Architectural Evolution** — The platform's architecture reflects a coherent design philosophy. Extending it in ways that maintain that coherence requires understanding the philosophy, not just the code. The documents produced in this series are an attempt to make that philosophy explicit and transferable.

### 18.3 Mitigation Strategy

The practical mitigation for the bus factor is a three-part strategy:

First, **documentation density** — the platform is documented at a level that exceeds industry norms for a solo-built system. The code comments, the JSDoc headers, the test suites, and the companion documents collectively provide a handoff package that a senior security engineer could use to maintain and extend the platform.

Second, **LLM-assisted continuity** — the platform's own LLM specialists encode significant operational knowledge in their system prompts. A future maintainer who does not have Harrison's operational experience can still benefit from the judgment encoded in those prompts, because the LLM will continue to apply the calibrated reasoning even if the person operating it does not fully understand the calibration.

Third, **graduated onboarding** — the platform's modular architecture allows a new maintainer to take ownership incrementally, starting with the modules they understand best and gradually expanding to the more judgment-intensive components. The test suites provide a safety net throughout this process.

---

## 19. Philosophical Spine — Where the Design Comes From

The design decisions in AC3 are not arbitrary, and they are not derived from the security literature alone. They come from a specific intellectual lineage that is worth naming once, carefully, because it makes the architecture feel inevitable rather than accidental.

### 19.1 Archaeological Restraint — Don't Interpret Past the Evidence

The "innocent until proven guilty" likelihood model — where every vulnerability starts at baseline likelihood and evidence must push the score upward — comes from archaeological discipline. In archaeology, you do not interpret past the evidence. You do not assume a potsherd is ceremonial because it would make a better story. You describe what you found, note the context, and let the evidence speak. AC3's scoring system applies the same restraint: a vulnerability is not critical because it could theoretically be exploited. It is critical only when the evidence — active exploitation in the wild, KEV listing, functional exploit availability, threat actor targeting — pushes it there.

This restraint has a practical consequence that matters enormously in production: it prevents score inflation. Most vulnerability management tools suffer from "everything is critical" syndrome because their scoring models lack the discipline to say "we don't have enough evidence to call this critical yet." AC3's model has that discipline because it was designed by someone trained in a field where premature interpretation is a professional failure.

### 19.2 Anthropological Humility — The Field Site Is Not What You Expected

The sector-aware baselines read like cultural ethnography more than like threat modeling. Each industry is treated as a distinct cultural context with its own threat landscape, crown jewels, regulatory overlays, and attacker motivations. This is the anthropologist's instinct: do not impose a universal framework on a field site. Figure out what this particular group values, what they guard, what they fear, and calibrate your analysis to their context.

Most security tools do the opposite — they assume the customer fits the framework and treat deviations as noise. AC3 treats each sector as a field site with its own ethnology. The Healthcare profile amplifies patient safety factors not because a textbook says healthcare cares about patient safety, but because two decades of working in healthcare environments revealed that patient safety is the factor that actually drives remediation urgency in that sector. The Financial Services profile amplifies regulatory and systemic risk factors because those are the factors that actually drive remediation urgency in financial institutions. These are ethnographic observations, not theoretical assumptions.

### 19.3 Tiger-Team Patience — Don't Move Until You Can Move Decisively

The engagement orchestrator's nine-phase progression — with autonomous execution of low-risk phases and mandatory human approval for exploitation — reflects the tiger-team operator's discipline of patience. In physical penetration testing, the operator who rushes to exploit the first vulnerability they find is the operator who gets caught. The skilled operator observes, maps, scores, plans, and then moves decisively when the conditions are right.

AC3 encodes this patience structurally. The platform does not rush to exploitation. It spends phases 1-4 building a comprehensive picture of the target environment, scoring every finding against the hybrid model, and generating an optimized attack plan before any exploitation occurs. This is not caution for caution's sake — it is the operational discipline that produces better results with lower detection risk.

### 19.4 The Convergence

These three intellectual traditions — archaeological restraint, anthropological humility, and tiger-team patience — converge in AC3's design philosophy. The platform is conservative where conservatism protects accuracy (scoring), adaptive where adaptation improves relevance (sector awareness), and decisive where decisiveness maximizes impact (exploitation). This convergence is not something that could have been designed by committee or derived from a requirements document. It is the product of a specific intellectual history applied to a specific operational domain over a specific period of intense, focused work.

---

## 20. Competitive Landscape and Differentiation

AC3 operates in a market populated by well-funded competitors, each addressing a subset of the offensive security workflow. The platform's differentiation lies not in any single capability but in the integration of capabilities that competitors sell as separate products, unified by a scoring system that no competitor has replicated.

### 20.1 Competitive Comparison

| Capability | AC3 | Pentera | Tenable | Recorded Future | PlexTrac |
|---|---|---|---|---|---|
| Automated Penetration Testing | Yes | Yes | No | No | No |
| Vulnerability Management | Yes | Limited | Yes | No | No |
| Threat Intelligence | Yes (75+ modules) | No | Limited | Yes | No |
| Pentest Management | Yes | No | No | No | Yes |
| Adversary Emulation (MITRE) | Yes (Caldera) | Limited | No | No | No |
| Hybrid Risk Scoring | Yes (CARVER+SHOCK/CVSS/BIA) | No | CVSS only | No | No |
| Phishing Campaigns | Yes (GoPhish) | No | No | No | No |
| C2 Operations | Yes (Ember, Sliver, Empire) | No | No | No | No |
| Compliance Automation | Yes (8 frameworks) | No | Limited | No | No |
| AI Security Validation | Yes (MITRE ATLAS) | No | No | No | No |
| White-Label / Multi-Tenant | Yes | No | No | No | Yes |
| Darkweb Intelligence | Yes | No | No | Yes | No |
| Geopolitical Context | Yes (5 conflict zones) | No | No | Yes | No |

### 20.2 The Integration Advantage

The deepest competitive advantage is not any single row in the table above — it is the fact that all rows exist in a single platform with a shared data model. When AC3 discovers a vulnerability through ScanForge, that finding is automatically scored by the hybrid engine, enriched with threat intelligence, correlated with darkweb activity, mapped to compliance controls, and available for exploitation through the engagement orchestrator. In a competitor's environment, achieving the same workflow requires integrating 4-6 separate products, each with its own data model, its own API, and its own scoring system.

### 20.3 The Scoring Advantage

No competitor has a scoring system that fuses military target analysis (CARVER+SHOCK), technical severity (CVSS), and business impact (BIA) into a single risk score with sector-aware calibration, temporal decay, LLM augmentation, and production hardening. This is the capability that is most defensible as intellectual property and most difficult for competitors to replicate, because the calibration requires operational experience that cannot be acquired through engineering effort alone.

---

## Appendix A — Module Inventory Summary

| Category | Module Count | Lines of Code |
|---|---|---|
| Server Library (`server/lib/`) | 633 | 388,030 |
| Client Pages (`client/src/pages/`) | 319 | 278,549 |
| Database Schema (`drizzle/schema.ts`) | 352 tables | ~18,000 |
| LLM Specialists (`server/lib/llm-specialists/`) | 13 | ~15,000 |
| Vendor Integrations (`server/lib/vendors/`) | 10 | ~8,000 |
| Test Suites (`server/*.test.ts`) | 25+ | ~12,000 |
| **Total** | **1,000+** | **666,579** |

## Appendix B — External Integration Summary

| Integration | Protocol | Purpose |
|---|---|---|
| MITRE Caldera | REST API | Adversary emulation, agent management |
| Metasploit | RPC | Exploitation framework |
| Sliver | gRPC | C2 operations |
| Empire | REST API | C2 operations |
| GoPhish | REST API | Phishing campaigns |
| ZAP | REST API | Web application scanning |
| Burp Suite | REST API | Web application scanning |
| Nuclei | CLI | Vulnerability scanning |
| Nmap | CLI (scan server) | Network discovery |
| Shodan | REST API | Internet-wide scanning data |
| Censys | REST API | Certificate and host data |
| VirusTotal | REST API | Malware and URL analysis |
| NVD | REST API | Vulnerability database |
| CISA KEV | JSON feed | Known exploited vulnerabilities |
| abuse.ch | REST API | Malware IOCs |
| AlienVault OTX | REST API | Threat intelligence pulses |
| SpicyThreatIntel | tRPC API | Darkweb intelligence |
| Splunk | REST API | SIEM integration |
| CrowdStrike | REST API | EDR integration |
| SentinelOne | REST API | EDR integration |
| Microsoft Defender | REST API | EDR/XDR integration |
| Cortex XDR | REST API | XDR integration |
| Microsoft Sentinel | REST API | SIEM/SOAR integration |
| Palo Alto XSOAR | REST API | SOAR integration |

---

*This document was prepared by Harrison Cook — AceofCloud. It describes the AC3 platform as implemented in the current codebase (April 2026). For the detailed technical treatment of the hybrid scoring system, see the companion document: AC3 Hybrid Scoring System Deep Dive v2.*
