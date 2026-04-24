# AC3 Product Guide for Intelligence Community Customers

**Classification: UNCLASSIFIED**
**Distribution: Approved for public release**
**Document Version: 1.0 — April 2026**
**Prepared by: AceofCloud — [https://aceofcloud.com](https://aceofcloud.com)**
**Contact: info@aceofcloud.com | 703-488-8889 | Sterling, Virginia**

---

## Table of Contents

1. Executive Summary
2. Platform Overview for IC Stakeholders
3. Compliance and Authorization Posture
4. Deployment Models and Network Classification
5. Threat Intelligence Capabilities
6. Offensive Cyber Operations Support
7. Adversary Emulation and Red Team Operations
8. Hunt Operations and Incident Response
9. Intelligence Preparation of the Operational Environment
10. Vulnerability Equities Process Support
11. All-Source Cyber Intelligence Analysis
12. Geopolitical and Conflict Theater Intelligence
13. AI Governance and Trustworthy AI
14. Safety Architecture for Sensitive Operations
15. Interoperability and Intelligence Sharing
16. Licensing and Procurement
17. Frequently Asked Questions
18. References

---

## 1. Executive Summary

AC3 (AceofCloud Cybersecurity Command) is an integrated offensive security, threat intelligence, and risk analysis platform developed by **AceofCloud**, a NIST-focused cybersecurity and compliance firm headquartered in Sterling, Virginia. AceofCloud is an **Authorized C3PAO** (CMMC Third-Party Assessment Organization), **Registered Provider Organization (RPO)**, and **accredited SCF 3PAO**, with a team of certified CMMC Assessors (CCA), CMMC Professionals (CCP), and offensive security practitioners whose collective experience spans DoD, federal civilian agencies, the Intelligence Community, and critical infrastructure sectors. The platform is designed to serve the operational requirements of the United States Intelligence Community (IC), Department of Defense (DoD) cyber organizations, and federal agencies with national security missions.

AC3 was architected by Harrison Cook, AceofCloud's founder, whose 25 years of experience spanning military intelligence, penetration testing, red team operations, and critical infrastructure security informed every design decision — from the CARVER+SHOCK scoring methodology (adapted from its military origins for digital asset risk analysis) to the seven-layer safety architecture that enforces two-person integrity for high-risk operations. The platform consolidates capabilities that the IC currently procures from multiple vendors — adversary emulation, vulnerability assessment, threat intelligence aggregation, risk scoring, hunt operations, and compliance reporting — into a single, unified operational environment.

AceofCloud's organizational depth extends beyond platform development. The firm's active practice in **CMMC assessments, FedRAMP/GovRAMP advisory, penetration testing (red and purple team), vCISO services, and data governance** means that AC3 is not built by developers imagining what practitioners need — it is built by practitioners who conduct assessments, advise federal agencies on compliance, and perform offensive operations against real targets under real Rules of Engagement. This practitioner-first design philosophy is visible throughout the platform: the ROE scope enforcement system reflects the legal constraints that real engagements face, the evidence integrity chains reflect the evidentiary standards that real oversight processes demand, and the hybrid risk scoring system reflects the mission-impact language that real intelligence consumers understand.

AC3 is not a point solution. It is a platform that spans six GSA HACS subcategories — High Value Asset Assessments, Risk and Vulnerability Assessments, Cyber Hunt, Incident Response, Penetration Testing, and Incident Handling and Event Management — within a single operational environment. For IC customers, this means fewer procurement actions, fewer integration challenges, and a unified evidence chain across all assessment activities.

---

## 2. Platform Overview for IC Stakeholders

AC3 comprises 633 server-side modules, 319 client-facing pages, 352 database tables, and 13 LLM specialist modules, organized into eight operational domains. The platform's architecture is designed around the principle that offensive security operations, threat intelligence analysis, and risk management are not separate disciplines — they are phases of a continuous intelligence cycle that should share data, context, and scoring.

### 2.1 Operational Domains

| Domain | IC Relevance | Key Capabilities |
|---|---|---|
| **Command Center** | Mission planning, risk analysis, executive briefing | Engagement lifecycle management, hybrid risk scoring, executive dashboards, mission workflow |
| **Attack Surface** | Asset discovery, vulnerability assessment, attack path analysis | 64 passive OSINT connectors, multi-tool scanning orchestration, attack graph generation |
| **Emulation & Testing** | Adversary emulation, defense validation, purple team | CALDERA integration, Ember C2, MITRE ATT&CK mapping, detection engineering |
| **Exploit Operations** | Penetration testing, C2 operations, post-exploitation | Exploit catalog, phishing operations, evasion engine, credential testing |
| **Intelligence** | Threat intelligence, actor tracking, darkweb monitoring | Threat intel hub, IOC feeds, STIX generation, actor profiling, zero-day tracking |
| **Key Security Indicators** | Compliance, evidence integrity, audit readiness | KSI dashboard, compliance mapping, evidence hash chains, OSCAL export |
| **Reports & Knowledge** | Intelligence products, knowledge management, LLM learning | Report generation, knowledge bases, self-supervised learning, training feedback |
| **Platform** | Administration, integrations, multi-tenancy | White-label, tenant isolation, MSSP management, integration registry |

### 2.2 Architecture for IC Operations

The platform is built on a modern, containerizable architecture that supports multiple deployment models:

**Application Layer:** React 19 frontend with TypeScript, providing a responsive operational interface accessible from standard government workstations. The interface is designed for extended operational use, with dark-mode defaults, keyboard navigation, and information density appropriate for analyst workflows.

**API Layer:** tRPC-based API with end-to-end type safety, ensuring that every data exchange between client and server is validated at compile time. All API traffic routes through `/api/trpc`, making it straightforward to integrate with existing network security appliances and proxy architectures.

**Data Layer:** MySQL/TiDB database with 352 tables covering the full operational data model — engagements, findings, evidence, threat intelligence, scoring history, and audit logs. S3-compatible object storage for evidence files, screenshots, and generated reports.

**AI Layer:** 13 LLM specialist modules, each with domain-specific system prompts and knowledge injection, governed by a comprehensive AI governance pipeline with circuit breakers, rate limiting, and human-in-the-loop enforcement.

**Cryptographic Layer:** FIPS 140-3 compliant cryptographic operations via the `FIPSCryptoService`, enforcing AES-256 symmetric encryption, ECDSA P-256/P-384 asymmetric operations, and SHA-256/384/512 hashing with application-layer minimum key length enforcement.

### 2.3 AceofCloud Organizational Credentials

AC3 is developed and supported by AceofCloud, a firm whose organizational credentials directly inform the platform's design and provide assurance to IC customers that the platform is backed by demonstrated assessment and compliance expertise.

| Credential | Description | IC Relevance |
|---|---|---|
| **Cyber AB Authorized C3PAO** | Authorized by the Cyber AB to conduct CMMC Level 2 certification assessments for the Defense Industrial Base | Demonstrates organizational competence in assessing security controls against NIST SP 800-171 — the same control framework that underpins AC3's compliance modules |
| **CMMC-AB Registered Provider Organization (RPO)** | Authorized to provide CMMC readiness advisory services to organizations seeking certification | Validates the firm's advisory capability and understanding of the assessment process from both sides |
| **Accredited SCF 3PAO** | Accredited Third-Party Assessment Organization under the Secure Controls Framework | Extends assessment authority beyond CMMC to the broader SCF control catalog, which maps across 200+ frameworks |
| **Certified CMMC Assessors (CCA)** | Team members hold individual CCA certifications from the Cyber AB | Ensures that the people building AC3's compliance modules have personally conducted the assessments those modules support |
| **CMMC Professionals (CCP)** | Team members hold CCP certifications demonstrating CMMC ecosystem expertise | Provides depth beyond individual assessors — the organization maintains a bench of qualified professionals |

AceofCloud's active service lines — **C3PAO assessments, FedRAMP/GovRAMP advisory (Moderate through High, IL4/IL5), red and purple team penetration testing mapped to MITRE ATT&CK, tiered vCISO programs, and data governance consulting (GDPR, CPRA, HIPAA, NIST Privacy Framework)** — mean that the firm's practitioners encounter the operational realities that AC3 is designed to address. When the platform's ROE scope enforcement system validates an action against the engagement's Rules of Engagement, that validation logic was designed by practitioners who have written and operated under real ROE. When the evidence integrity system generates tamper-evident hash chains, those chains were designed by assessors who know what Inspector General investigators and congressional oversight staff actually examine.

This practitioner-to-platform feedback loop is a structural advantage that pure software development firms cannot replicate. AceofCloud does not build tools for practitioners — AceofCloud practitioners build their own tools, and AC3 is the result.

---

## 3. Compliance and Authorization Posture

### 3.1 Current Compliance Alignment

AC3's architecture is designed to be consistent with the following frameworks. The table below distinguishes between architectural alignment (the platform is built to support the framework's requirements) and formal certification (an independent audit has verified compliance).

| Framework | Status | Notes |
|---|---|---|
| **FIPS 140-3** | Architecturally compliant | `FIPSCryptoService` enforces FIPS 140-3 approved algorithms; AES-256, ECDSA P-256/P-384, SHA-256/384/512 |
| **NIST SP 800-53 Rev 5** | Architecturally aligned | Controls implemented across safety architecture; no formal audit |
| **NIST SP 800-171 Rev 2** | Architecturally aligned | CUI protection controls implemented; relevant for CMMC Level 2 |
| **NIST AI RMF (AI 100-1)** | Architecturally aligned | AI governance pipeline implements MAP, MEASURE, MANAGE functions |
| **CNSSI 1253** | Architecturally compatible | Security categorization methodology supported; overlay selection requires customer input |
| **CMMC Level 2** | Architecturally aligned | 110 practices from NIST SP 800-171 addressed in platform design |
| **OWASP Top 10 for LLM** | 9/10 categories addressed | LLM01-LLM07, LLM08 (Excessive Agency), LLM09 (Overreliance) covered |
| **MITRE ATLAS** | Architecturally aligned | Adversarial AI threat model informed by ATLAS taxonomy |
| **Wassenaar Arrangement** | Assessed | Category 4 (Computers) and Category 5 Part 2 (Information Security) evaluated for export control implications |

### 3.2 Path to Authorization

For IC customers requiring formal authorization, the following path is recommended:

**FedRAMP High** — The platform's architecture supports the 421 controls required for FedRAMP High authorization. AceofCloud's active FedRAMP/GovRAMP advisory practice — supporting cloud service providers through FedRAMP Moderate, High, and IL4/IL5 authorizations — means the firm has direct experience with the authorization process and the evidence packages that 3PAOs and the JAB expect. The primary gap is the formal audit process itself, not architectural deficiencies. A FedRAMP High authorization would enable deployment on NIPRNet and support procurement by civilian IC agencies.

**DoD IL4/IL5** — For DoD components requiring Impact Level 4 (CUI) or Impact Level 5 (CUI + national security information), the platform can be deployed on DoD-authorized cloud infrastructure (AWS GovCloud, Azure Government) with the appropriate security controls overlay. IL5 authorization would enable use by DoD intelligence components for processing national security information.

**ICD 503 / RMF for IC** — For IC elements requiring authorization under ICD 503, the platform's security controls map to the CNSSI 1253 categorization methodology. The platform supports the continuous monitoring requirements of the IC RMF through its comprehensive audit logging, evidence integrity chains, and automated compliance reporting. AceofCloud's team includes practitioners with direct experience in IC authorization processes, ensuring that the platform's compliance documentation and evidence packages align with the expectations of IC Designated Authorizing Officials (DAO).

### 3.3 Cryptographic Compliance

The platform's `FIPSCryptoService` provides defense-in-depth for cryptographic operations:

| Requirement | Implementation |
|---|---|
| Symmetric Encryption | AES-256 (minimum key length enforced at application layer) |
| Asymmetric Encryption | ECDSA P-256/P-384 |
| Hash Functions | SHA-256, SHA-384, SHA-512 |
| Key Derivation | HKDF, PBKDF2 |
| Evidence Integrity | HMAC-SHA256 hash chains with dedicated EVIDENCE_HMAC_KEY |
| Key Rotation | Supported with configurable rotation schedules |

The application-layer key length enforcement operates independently of the underlying FIPS module, providing a second line of defense against key generation weaknesses. This approach meets the cryptographic requirements for CMMC Level 2 and is defensible for most IC procurement conversations. Customers with Level 3+ physical security assurance requirements should be informed of the validation scope.

---

## 4. Deployment Models and Network Classification

### 4.1 Supported Deployment Models

AC3's containerized architecture supports multiple deployment models appropriate for different classification levels and operational requirements.

| Deployment Model | Classification | Network | Description |
|---|---|---|---|
| **Cloud SaaS** | Unclassified (CUI-capable) | NIPRNet / Internet | Standard deployment on commercial or GovCloud infrastructure; suitable for unclassified assessments and CUI processing with appropriate controls |
| **GovCloud Dedicated** | CUI / IL4-IL5 | AWS GovCloud / Azure Gov | Dedicated tenant deployment on FedRAMP High authorized infrastructure; suitable for DoD and IC components processing national security information |
| **On-Premises** | Up to SECRET | SIPRNet / Isolated | Containerized deployment on customer-managed infrastructure; supports air-gapped operation with no external dependencies |
| **Air-Gapped SCIF** | Up to TS/SCI | JWICS / Isolated | Fully air-gapped deployment with pre-loaded threat intelligence, exploit catalogs, and LLM models; no network connectivity required |

### 4.2 Air-Gapped Deployment Considerations

For classified network deployments, the platform supports operation without internet connectivity. The following capabilities are affected:

**Fully Functional in Air-Gapped Mode:** All scoring engines, engagement management, evidence collection, report generation, compliance mapping, and the core exploitation/emulation workflow operate without external connectivity. The CARVER+SHOCK/CVSS/BIA hybrid scoring system is entirely deterministic and requires no external API calls.

**Degraded but Functional:** Threat intelligence feeds (CISA KEV, NVD, abuse.ch, AlienVault OTX) require periodic manual import via cross-domain solution or sneakernet update. The platform supports bulk import of STIX 2.1 bundles for offline threat intelligence updates.

**Requires Adaptation:** LLM specialist modules require either a locally hosted model (the platform supports configurable LLM endpoints) or pre-computed analysis packages. The platform's deterministic fallback scoring ensures that all critical scoring functions operate without LLM availability.

### 4.3 Cross-Domain Considerations

For organizations operating across multiple classification levels, AC3's STIX 2.1 export capability enables structured intelligence sharing through NSA-approved Cross-Domain Solutions (CDS). The platform's evidence integrity hash chains provide tamper-evident provenance that survives cross-domain transfer, allowing findings from classified assessments to be sanitized and shared at lower classification levels with verifiable integrity.

---

## 5. Threat Intelligence Capabilities

The Intelligence domain is AC3's most IC-relevant capability set. The platform aggregates, correlates, and operationalizes threat intelligence from 83 server-side modules spanning open-source feeds, commercial integrations, darkweb monitoring, and LLM-assisted analysis.

### 5.1 Threat Intelligence Hub

The **Threat Intel Hub** serves as the central aggregation point for all threat intelligence in the platform. It normalizes data from multiple sources into a unified threat model aligned with STIX 2.1 data objects:

| STIX Object Type | AC3 Implementation | Sources |
|---|---|---|
| **Threat Actor** | Actor profiling with TTP mapping, motivation analysis, targeting patterns | MITRE ATT&CK, open-source reporting, darkweb monitoring, LLM-assisted analysis |
| **Campaign** | Campaign tracking with temporal analysis, infrastructure mapping, victimology | IOC feeds, darkweb monitoring, news aggregation, LLM correlation |
| **Indicator** | IOC management with confidence scoring, aging, and cross-reference validation | CISA KEV, abuse.ch, AlienVault OTX, ThreatFox, VirusTotal, Shodan, Censys |
| **Vulnerability** | CVE tracking with EPSS scoring, exploit availability, active exploitation status | NVD, CISA KEV, Exploit-DB, Vulners, zero-day monitoring |
| **Attack Pattern** | MITRE ATT&CK technique mapping with detection coverage analysis | ATT&CK framework, adversary emulation plans, detection engineering |
| **Malware** | Malware family tracking with behavioral analysis and YARA rule generation | abuse.ch, ThreatFox, darkweb monitoring, LLM-assisted analysis |
| **Infrastructure** | C2 infrastructure tracking, domain analysis, IP reputation | Shodan, Censys, SecurityTrails, passive DNS, certificate transparency |

### 5.2 Intelligence Feed Integration

The platform integrates with the following intelligence sources, organized by classification level:

**Unclassified / Open Source:**

| Feed | Data Type | Update Frequency |
|---|---|---|
| CISA Known Exploited Vulnerabilities (KEV) | Actively exploited CVEs | Daily |
| NVD (National Vulnerability Database) | CVE details, CVSS scores, CPE matching | Continuous |
| EPSS (Exploit Prediction Scoring System) | Exploitation probability scores | Daily |
| abuse.ch (ThreatFox, URLhaus, MalwareBazaar) | IOCs, malware samples, C2 URLs | Continuous |
| AlienVault OTX | Threat pulses, IOCs, community intelligence | Continuous |
| Shodan | Internet-facing asset intelligence | On-demand |
| Censys | Certificate transparency, host enumeration | On-demand |
| SecurityTrails | DNS history, WHOIS, domain intelligence | On-demand |
| Exploit-DB | Public exploit code, proof-of-concept | Daily |
| Vulners | Vulnerability aggregation, exploit matching | Continuous |
| GreyNoise | Internet background noise, mass scanning detection | On-demand |
| URLScan | Website analysis, phishing detection | On-demand |

**Customer-Provided / Classified:**

The platform's STIX 2.1 import capability supports ingestion of classified threat intelligence from IC-internal sources (e.g., SIGINT-derived indicators, HUMINT-derived requirements, NSA Cybersecurity Advisories) via manual import or cross-domain solution. Imported intelligence is automatically correlated with the platform's existing threat model and integrated into scoring calculations.

### 5.3 Darkweb Intelligence

The **Darkweb Monitor** provides continuous surveillance of darkweb marketplaces, forums, and paste sites for intelligence relevant to the customer's operational environment:

**Credential Monitoring** — Detection of leaked credentials, session tokens, and authentication material associated with target organizations or personnel of interest.

**Threat Actor Activity** — Tracking of threat actor communications, tool advertisements, and operational planning discussions on darkweb forums.

**Data Breach Detection** — Identification of organizational data (documents, databases, source code) appearing on darkweb marketplaces or paste sites.

**Infrastructure Sales** — Monitoring of compromised infrastructure (botnets, proxy networks, VPN credentials) being sold on darkweb markets, with correlation to known threat actor infrastructure.

For IC customers, darkweb intelligence provides early warning of adversary operations targeting IC equities, and supports counterintelligence analysis by identifying compromised credentials or infrastructure associated with IC personnel or systems.

### 5.4 Zero-Day Monitoring

The **Zero-Day Tracker** provides continuous monitoring for zero-day vulnerabilities through multiple detection channels:

**Vendor Advisory Monitoring** — Real-time tracking of vendor security advisories from major software vendors (Microsoft, Apple, Google, Cisco, Fortinet, Palo Alto Networks, etc.) with automated classification of zero-day vs. n-day vulnerabilities.

**Exploit Market Monitoring** — Surveillance of public and semi-public exploit markets for zero-day exploit advertisements, with automated correlation to known vulnerability classes and affected products.

**Anomaly Detection** — LLM-assisted analysis of vulnerability disclosure patterns to identify potential zero-day exploitation before formal disclosure, based on indicators such as unusual patching urgency, out-of-cycle advisories, and threat actor behavioral changes.

For IC customers involved in the Vulnerabilities Equities Process (VEP), the zero-day tracker provides the technical context needed to assess the intelligence value, third-party discovery probability, and critical infrastructure impact of newly discovered vulnerabilities.

---

## 6. Offensive Cyber Operations Support

AC3 provides capabilities that support the full spectrum of authorized offensive cyber operations, from vulnerability assessment through exploitation and post-exploitation. All offensive capabilities are governed by the platform's seven-layer safety architecture, ensuring that operations remain within authorized scope and comply with applicable legal authorities.

### 6.1 Capability Mapping to IC Mission Areas

| IC Mission Area | AC3 Capabilities | Safety Controls |
|---|---|---|
| **Computer Network Exploitation (CNE)** | Vulnerability assessment, exploit selection, credential testing, post-exploitation, data collection | ROE scope enforcement, safety level classification, evidence integrity |
| **Computer Network Attack (CNA)** | Exploit delivery, payload generation, evasion techniques, denial-of-service assessment | Dual-approval for `full_exploitation`, operator confirmation with impact acknowledgment |
| **Computer Network Defense (CND)** | Detection engineering, purple team exercises, defense validation, EDR evasion testing | Automatic safety level for defensive operations |
| **Vulnerability Assessment** | 64 passive connectors, multi-tool scanning, web application testing, API security testing | Automatic with logging for `low_impact` operations |
| **Penetration Testing** | Full-lifecycle penetration testing with PTES/OSSTMM methodology alignment | Operator approval for exploitation, evidence chain for all findings |

### 6.2 Exploit Catalog and Selection

The platform maintains a curated exploit catalog with automated selection based on target environment characteristics. The exploit selection engine considers:

**Vulnerability-Exploit Matching** — Automated correlation of discovered vulnerabilities with available exploits, including public exploits (Exploit-DB, Metasploit), custom exploits, and LLM-generated exploit concepts.

**Reliability Scoring** — Each exploit is scored for reliability based on historical success rates, target environment compatibility, and detection risk. The scoring system uses the same CARVER-derived methodology applied to vulnerability scoring, ensuring consistency across the assessment lifecycle.

**Safety Classification** — Every exploit is classified into one of four safety levels (`passive_only`, `low_impact`, `standard`, `full_exploitation`), with the classification enforced by the Exploit Guardrails module before any exploitation attempt.

**OPSEC Risk Assessment** — Before execution, each exploit is assessed for detection risk using the OPSEC Risk Engine, which simulates how EDR, SIEM, and NDR products would detect the exploitation attempt. High-risk exploits are flagged with safer alternatives.

### 6.3 Command and Control (C2)

The platform provides two C2 capabilities:

**CALDERA Integration** — Direct integration with MITRE's CALDERA adversary emulation platform, providing access to CALDERA's agent framework, ability execution, and ATT&CK-mapped operations. This integration enables IC red teams to execute adversary emulation plans using the same framework used by MITRE's own Center for Threat-Informed Defense.

**Ember C2** — AC3's native C2 framework, designed for operations requiring capabilities beyond CALDERA's scope. Ember provides encrypted communications, modular implant architecture, and operational security features designed for environments where detection avoidance is a primary requirement.

Both C2 capabilities are governed by the platform's safety architecture, with all C2 communications logged, all agent actions validated against the ROE, and all post-exploitation activities subject to the same safety level classification as direct exploitation.

---

## 7. Adversary Emulation and Red Team Operations

### 7.1 MITRE ATT&CK Integration

AC3's adversary emulation capabilities are built on the MITRE ATT&CK framework, providing IC red teams with the ability to execute realistic adversary emulation plans that replicate the tactics, techniques, and procedures (TTPs) of specific threat actors.

**ATT&CK Coverage:** The platform maps all offensive capabilities to ATT&CK techniques, providing coverage analysis that shows which techniques the platform can emulate and which require manual execution. This coverage map is essential for IC red teams that must demonstrate specific adversary emulation capabilities to satisfy DoDI 8585.01 requirements.

**Adversary Profiles:** The platform maintains adversary profiles for major threat actors, including nation-state APT groups (APT28, APT29, APT41, Lazarus Group, etc.), cybercriminal organizations, and hacktivist groups. Each profile includes the actor's known TTPs mapped to ATT&CK, preferred tools and infrastructure, targeting patterns, and operational tempo.

**Emulation Plan Generation:** The platform can generate adversary emulation plans from threat actor profiles, producing step-by-step operational plans that replicate a specific actor's methodology. These plans are compatible with MITRE's Adversary Emulation Plan format and can be executed through the CALDERA integration or manually by operators.

### 7.2 DoD Cyber Red Team (DCRT) Support

For DoD Cyber Red Teams operating under DoDI 8585.01, AC3 provides:

**Mission Planning** — Structured engagement planning with ROE definition, scope authorization, and mission objective mapping. The engagement workflow aligns with the DCRT mission lifecycle: planning, coordination, execution, and reporting.

**Deconfliction Support** — The platform's engagement management system supports the deconfliction requirements of DoDI 8585.01, tracking authorized time windows, target systems, and techniques to prevent interference with other cyber operations.

**Reporting Standards** — Automated report generation that produces findings in formats compatible with DoD reporting requirements, including CVSS scoring, MITRE ATT&CK mapping, and mission impact assessment using the CARVER+SHOCK methodology.

**Skills Validation** — The platform's graduation system, which promotes LLM specialists through capability tiers based on demonstrated performance, provides a model for the skills validation requirements of DoDI 8585.01. The graduation criteria — accuracy thresholds, safety compliance, and inter-rater reliability — can be adapted to validate human operator proficiency.

### 7.3 Purple Team and Defense Validation

For IC organizations conducting purple team exercises — where red team and blue team collaborate to improve detection and response capabilities — AC3 provides:

**Detection Engineering** — The platform generates detection signatures (SIGMA rules, YARA rules, Snort/Suricata rules) for every technique executed during an engagement. These signatures are mapped to ATT&CK techniques and can be imported directly into the customer's SIEM/EDR infrastructure.

**Defense Validation** — Automated testing of detection coverage by executing ATT&CK techniques and measuring whether the customer's security stack detects, alerts on, and responds to each technique. The results are presented as an ATT&CK coverage heatmap showing detection gaps.

**EDR Evasion Testing** — The Evasion Engine tests the customer's EDR products against known evasion techniques, identifying gaps in endpoint protection that adversaries could exploit. This capability is particularly relevant for IC organizations that must validate their endpoint security against nation-state adversary capabilities.

---

## 8. Hunt Operations and Incident Response

### 8.1 HACS-Compliant Hunt Operations

AC3's Hunt Engine implements threat hunting workflows aligned with the DHS/GSA HACS Cyber Hunt subcategory requirements and the CISA hunt methodology (PREPARE, EXECUTE, ACT). The hunt engine also incorporates the Sqrrl/PEAK hypothesis-driven hunting framework, providing IC hunt teams with a structured methodology for proactive threat detection.

**PREPARE Phase:** The hunt engine generates hunting hypotheses based on the platform's threat intelligence, using current threat actor TTPs, IOCs, and vulnerability data to identify the most likely attack vectors for the customer's environment. Hypotheses are prioritized using the hybrid risk scoring system, ensuring that hunt efforts focus on the highest-risk scenarios.

**EXECUTE Phase:** The platform provides hunt operators with tools for data collection, analysis, and correlation across multiple data sources. The hunt engine draws on a knowledge base of 300+ attack chains from real-world engagements to identify patterns that may indicate compromise. LLM-assisted analysis helps operators identify subtle indicators that might be missed by signature-based detection.

**ACT Phase:** When hunting identifies potential compromise, the platform transitions to incident response mode, providing evidence collection, containment recommendations, and automated reporting. All evidence collected during hunt operations is cryptographically hashed and linked into the platform's evidence integrity chain, ensuring that findings are admissible in legal and congressional proceedings.

### 8.2 Incident Response Integration

For IC organizations with incident response responsibilities, AC3 provides:

**Evidence Collection and Preservation** — Automated evidence collection with HMAC-SHA256 hash chains, ensuring tamper-evident provenance for all evidence artifacts. The evidence integrity system uses a dedicated EVIDENCE_HMAC_KEY with rotation support, meeting the evidentiary standards required for IC Inspector General investigations and congressional oversight.

**Timeline Reconstruction** — Automated reconstruction of attack timelines from collected evidence, with ATT&CK technique mapping for each observed action. The timeline provides both technical detail for analysts and executive-level summaries for leadership briefings.

**Attribution Support** — The platform's threat intelligence correlation engine assists with attribution by matching observed TTPs, infrastructure, and malware to known threat actor profiles. Attribution confidence is scored using a structured methodology that distinguishes between technical indicators (high confidence) and behavioral patterns (moderate confidence).


---

## 9. Intelligence Preparation of the Operational Environment

### 9.1 JIPOE Support for Cyber Domain

Joint Intelligence Preparation of the Operational Environment (JIPOE) is the four-step analytical process that IC and military intelligence organizations use to understand the operational environment. AC3 provides direct support for each JIPOE step as applied to the cyber domain:

| JIPOE Step | Traditional Focus | AC3 Cyber Domain Support |
|---|---|---|
| **Step 1: Define the Operational Environment** | Geographic, political, military boundaries | Attack surface enumeration, network topology mapping, asset discovery across 64 passive connectors, infrastructure dependency analysis |
| **Step 2: Describe Environmental Effects** | Terrain, weather, civil considerations | Network architecture analysis, security control mapping, detection capability assessment, communication pathway analysis |
| **Step 3: Evaluate the Adversary** | Order of battle, doctrine, capabilities | Threat actor profiling, TTP mapping to ATT&CK, adversary infrastructure tracking, capability assessment, historical campaign analysis |
| **Step 4: Determine Adversary COAs** | Most likely and most dangerous courses of action | Attack path analysis, adversary emulation planning, vulnerability-to-TTP correlation, mission impact scoring |

### 9.2 Conflict Theater Intelligence

The platform's **Conflict Theater** module provides geopolitical context for cyber operations by tracking active and emerging conflicts and their cyber dimensions. The module covers major geopolitical theaters including:

**Active Theaters:** Russia-Ukraine, Israel-Hamas, China-Taiwan tensions, North Korea, Iran, and associated cyber operations by state-sponsored threat actors operating in each theater.

**Cyber Dimensions Tracked:** State-sponsored APT activity, hacktivist operations, critical infrastructure targeting, disinformation campaigns, supply chain compromise attempts, and sanctions evasion through cyber means.

**Intelligence Products:** The conflict theater module generates intelligence summaries that correlate geopolitical events with observed cyber activity, providing IC analysts with the context needed to assess whether observed network activity is related to broader geopolitical operations.

For IC customers, the conflict theater module provides the geopolitical context layer that is often missing from purely technical threat intelligence platforms. By correlating technical indicators with geopolitical events, the platform helps analysts distinguish between opportunistic cybercrime and state-directed operations.

### 9.3 Attack Surface Intelligence

The platform's attack surface intelligence capabilities directly support JIPOE Step 1 by providing comprehensive enumeration of the target operational environment:

**Passive Reconnaissance** — 64 passive OSINT connectors that enumerate internet-facing assets without generating network traffic detectable by the target. Sources include Shodan, Censys, SecurityTrails, certificate transparency logs, passive DNS, WHOIS history, and social media intelligence.

**Active Reconnaissance** — Multi-tool scanning orchestration through the ScanForge module, which coordinates Nmap, Nuclei, ZAP, Burp Suite, and custom scanners to provide comprehensive vulnerability assessment. Active scanning is governed by the ROE scope enforcement system, ensuring that scanning remains within authorized boundaries.

**Attack Path Analysis** — The Attack Graph Generator constructs attack paths from discovered vulnerabilities, showing how an adversary could chain multiple vulnerabilities to achieve specific objectives. Attack paths are scored using the hybrid risk scoring system, providing mission-impact context for each potential attack chain.

---

## 10. Vulnerability Equities Process Support

### 10.1 VEP Context

The Vulnerabilities Equities Process (VEP) is the mechanism by which the U.S. government decides whether to disclose a newly discovered vulnerability to the vendor for patching or retain it for intelligence or offensive use. The VEP Equities Review Board (ERB) evaluates each vulnerability against criteria including intelligence value, third-party discovery probability, critical infrastructure impact, and defensive mitigation availability.

AC3's hybrid scoring system provides quantitative support for VEP analysis by translating vulnerability characteristics into the mission-impact dimensions that the ERB evaluates.

### 10.2 CARVER+SHOCK Scoring for VEP Analysis

The platform's CARVER+SHOCK scoring methodology maps directly to VEP evaluation criteria:

| VEP Criterion | CARVER+SHOCK Dimension | Scoring Approach |
|---|---|---|
| **Intelligence Value** | Criticality + Accessibility | How critical is the target system to the adversary's operations, and how accessible is the vulnerability for exploitation? |
| **Third-Party Discovery Probability** | Recognizability | How likely is it that other parties (researchers, adversaries) will independently discover the vulnerability? |
| **Critical Infrastructure Impact** | Effect + Shock | What is the operational and cascading impact if the vulnerability is exploited against critical infrastructure? |
| **Defensive Mitigation Availability** | Recuperability | How quickly can the affected system recover from exploitation, and are alternative mitigations available? |
| **Exploitation Sophistication** | Vulnerability (inverted) | How difficult is it to develop a reliable exploit for the vulnerability? |

### 10.3 Quantitative VEP Support

For IC customers involved in VEP deliberations, the platform provides:

**Impact Scoring** — The hybrid risk scoring system quantifies the impact of vulnerability exploitation across multiple dimensions (operational, financial, reputational, safety), providing the ERB with structured impact data rather than subjective assessments.

**Sector-Specific Analysis** — The platform's 18 sector presets (including Defense Industrial Base, Government Facilities, Energy, Communications, and Information Technology) provide sector-specific impact analysis that reflects the different consequences of exploitation across critical infrastructure sectors.

**Temporal Analysis** — The temporal decay module models how vulnerability risk changes over time, accounting for factors such as patch availability, exploit maturity, and active exploitation status. This temporal analysis supports VEP decisions about the urgency of disclosure.

**Explainable Risk Cards** — The ExplainableRiskCard output provides a structured, auditable explanation of how the risk score was calculated, including all contributing factors, data sources, and confidence levels. This transparency is essential for VEP deliberations, where decision-makers need to understand the basis for risk assessments.

---

## 11. All-Source Cyber Intelligence Analysis

### 11.1 Intelligence Fusion Architecture

AC3's intelligence fusion architecture is designed to support the all-source analysis methodology used by IC analysts. The platform aggregates intelligence from multiple collection disciplines and correlates it into unified threat assessments:

**OSINT Integration** — 64 passive connectors providing open-source intelligence from internet scanning services, vulnerability databases, threat intelligence feeds, social media, and darkweb monitoring.

**SIGINT-Derived Indicators** — The platform's STIX 2.1 import capability supports ingestion of indicators derived from signals intelligence, allowing IC analysts to correlate SIGINT-derived indicators with OSINT data within the platform's unified threat model.

**HUMINT-Derived Requirements** — Intelligence requirements derived from human intelligence sources can be imported as structured collection requirements, driving the platform's automated collection and analysis priorities.

**TECHINT Integration** — Technical intelligence from malware analysis, reverse engineering, and forensic examination can be imported and correlated with the platform's vulnerability and threat actor databases.

### 11.2 Analytic Tradecraft Support

The platform supports IC analytic tradecraft standards (ICD 203) through several mechanisms:

**Source Reliability Assessment** — Every intelligence source in the platform is assigned a reliability rating based on historical accuracy, timeliness, and corroboration. The reliability rating is propagated through the scoring system, ensuring that risk assessments reflect the quality of underlying intelligence.

**Confidence Levels** — All platform assessments include explicit confidence levels (High, Moderate, Low) with supporting rationale. The confidence methodology distinguishes between assessments based on multiple corroborating sources (high confidence) and those based on single-source or analytical inference (lower confidence).

**Alternative Analysis** — The platform's LLM specialist modules are designed to challenge initial assessments by generating alternative hypotheses. The inter-rater reliability harness, which compares independent operator assessments, provides a structured mechanism for identifying analytical disagreements.

**Audit Trail** — Every analytical judgment in the platform is linked to its supporting evidence through the evidence integrity chain, providing the traceability required by ICD 203 for intelligence products.

### 11.3 Intelligence Products

The platform generates intelligence products in formats familiar to IC analysts:

| Product Type | Description | IC Equivalent |
|---|---|---|
| **Threat Assessment** | Comprehensive assessment of threat actors targeting the customer's environment | Intelligence Assessment (IA) |
| **Vulnerability Brief** | Prioritized vulnerability report with mission impact scoring | Intelligence Information Report (IIR) |
| **Campaign Analysis** | Detailed analysis of observed adversary campaigns with TTP mapping | Intelligence Memorandum |
| **Risk Dashboard** | Real-time risk visualization with trend analysis and alerting | Current Intelligence Brief |
| **Engagement Report** | Full assessment report with findings, evidence, and remediation guidance | Assessment Report |
| **STIX Bundle** | Machine-readable threat intelligence in STIX 2.1 format | Structured Intelligence Product |

---

## 12. Geopolitical and Conflict Theater Intelligence

### 12.1 Geopolitical Context Layer

The platform's Conflict Theater module provides the geopolitical context layer that distinguishes AC3 from purely technical threat intelligence platforms. For IC customers, this capability bridges the gap between technical cyber indicators and the strategic intelligence context that drives IC analysis.

**Active Conflict Monitoring** — The platform tracks active geopolitical conflicts and their cyber dimensions, correlating observed cyber activity with geopolitical events. This correlation helps IC analysts distinguish between state-directed operations, proxy operations, and opportunistic cybercrime occurring in the context of geopolitical tensions.

**Threat Actor Geopolitical Alignment** — Each threat actor profile in the platform includes geopolitical alignment data, linking the actor to state sponsors, geopolitical objectives, and historical targeting patterns. This alignment data supports attribution analysis and helps analysts assess the strategic intent behind observed operations.

**Sanctions and Export Control Monitoring** — The platform tracks sanctions regimes and export control restrictions relevant to cyber operations, helping IC customers ensure that their operations comply with applicable legal authorities and that their analysis accounts for the impact of sanctions on adversary capabilities.

### 12.2 Regional Cyber Threat Profiles

The platform maintains regional cyber threat profiles that aggregate threat actor activity, vulnerability exploitation patterns, and infrastructure characteristics by geographic region. These profiles support IC analysts who need to assess the cyber threat landscape for specific regions as part of broader intelligence assessments.

---

## 13. AI Governance and Trustworthy AI

### 13.1 AI Governance Architecture

AC3 employs 13 LLM specialist modules across the platform, each governed by a comprehensive AI governance pipeline that implements the principles of the NIST AI Risk Management Framework (AI 100-1). For IC customers, the AI governance architecture addresses the unique concerns of deploying AI in national security contexts.

**Deterministic Baseline + Bounded LLM Delta** — This is the platform's foundational AI design principle. Every AI-augmented function has a deterministic baseline that operates without LLM involvement. The LLM can adjust the baseline within bounded limits (typically 10-15% of the total score range), but cannot override the deterministic calculation. If the LLM is unavailable, degraded, or compromised, the platform continues to operate on deterministic baselines alone.

This design principle directly addresses the IC's concern about AI reliability in operational contexts. A scoring system that depends entirely on LLM availability is not suitable for operations on classified networks where LLM connectivity may be intermittent or unavailable. AC3's deterministic fallback ensures operational continuity regardless of AI availability.

### 13.2 LLM Safety Controls

| Control | Implementation | IC Relevance |
|---|---|---|
| **Circuit Breakers** | Automatic LLM disengagement when error rates exceed thresholds | Prevents cascading failures in operational scoring |
| **Rate Limiting** | Per-procedure and per-user rate limits on LLM invocations | Prevents resource exhaustion and cost overruns |
| **Output Validation** | JSON schema validation on all LLM outputs with type checking | Prevents malformed data from entering scoring pipeline |
| **Delta Clamping** | LLM adjustments clamped to bounded ranges (e.g., -2 to +2 per CARVER factor) | Prevents LLM from producing extreme scores |
| **Prompt Injection Defense** | Input sanitization, system prompt isolation, output filtering | Addresses OWASP LLM01 (Prompt Injection) |
| **Human-in-the-Loop** | Mandatory human approval for safety-critical decisions | Addresses OWASP LLM08 (Excessive Agency) |
| **Confidence Scoring** | LLM outputs include self-assessed confidence with calibration tracking | Addresses OWASP LLM09 (Overreliance) |
| **Audit Logging** | All LLM invocations logged with input, output, and metadata | Supports IC oversight and accountability requirements |

### 13.3 OWASP Top 10 for LLM Coverage

The platform addresses 9 of 10 OWASP Top 10 for LLM Applications categories:

| OWASP Category | Status | Implementation |
|---|---|---|
| LLM01: Prompt Injection | Addressed | Input sanitization, system prompt isolation, output validation |
| LLM02: Insecure Output Handling | Addressed | JSON schema validation, type checking, output filtering |
| LLM03: Training Data Poisoning | Addressed | Self-supervised learning with human review gates |
| LLM04: Model Denial of Service | Addressed | Rate limiting, circuit breakers, timeout enforcement |
| LLM05: Supply Chain Vulnerabilities | Addressed | Configurable LLM endpoints, no embedded model weights |
| LLM06: Sensitive Information Disclosure | Addressed | Output filtering, PII detection, classification marking |
| LLM07: Insecure Plugin Design | Addressed | Tool validation, scope enforcement, capability restrictions |
| LLM08: Excessive Agency | Addressed | Human-in-the-loop for safety-critical decisions, bounded deltas |
| LLM09: Overreliance | Addressed | Deterministic baselines, confidence scoring, calibration tracking |
| LLM10: Model Theft | Not directly applicable | Platform uses API-based LLM access, no local model weights to steal |

### 13.4 Graduation System for AI Trust

The platform's **Self-Supervised Incremental Learning (SSIL)** system provides a structured methodology for building trust in AI capabilities over time. LLM specialist modules are promoted through capability tiers based on demonstrated performance:

| Tier | Capabilities | Requirements |
|---|---|---|
| **Tier 0: Quarantine** | No autonomous operation; all outputs require human review | Initial state for all new LLM specialists |
| **Tier 1: Assisted** | Can provide recommendations; human must approve before execution | Demonstrated accuracy above baseline on calibration dataset |
| **Tier 2: Supervised** | Can execute low-risk operations with post-hoc review | Sustained accuracy, safety compliance, and inter-rater reliability |
| **Tier 3: Autonomous** | Can execute within bounded scope without per-action approval | Extended track record, drift detection passing, dual-approval for promotion |

For IC customers, the graduation system provides a transparent, auditable methodology for managing AI trust that aligns with the IC's risk-averse approach to AI deployment. The system ensures that AI capabilities are never trusted beyond their demonstrated reliability, and that any degradation in performance triggers automatic demotion to a lower trust tier.

---

## 14. Safety Architecture for Sensitive Operations

### 14.1 Seven-Layer Safety Architecture

AC3's safety architecture is designed for environments where operational errors have consequences beyond the technical domain — legal liability, diplomatic incidents, congressional scrutiny, and mission compromise. The seven-layer architecture provides defense-in-depth for all offensive operations:

| Layer | Function | IC Relevance |
|---|---|---|
| **Layer 1: ROE Scope Enforcement** | Validates every action against the engagement's Rules of Engagement | Ensures operations remain within legal authorities |
| **Layer 2: Safety Level Classification** | Classifies every action into one of four safety levels | Provides graduated approval requirements |
| **Layer 3: Operator Confirmation** | Requires human confirmation for actions above `low_impact` | Prevents autonomous execution of high-risk actions |
| **Layer 4: Dual-Approval** | Requires two independent approvers for `full_exploitation` actions | Implements two-person integrity for the most dangerous operations |
| **Layer 5: Evidence Integrity** | Cryptographic hash chains for all evidence and actions | Ensures findings withstand legal and oversight scrutiny |
| **Layer 6: Exploit Guardrails** | Pre-execution validation of exploit safety and scope compliance | Prevents out-of-scope exploitation |
| **Layer 7: OPSEC Risk Assessment** | Assesses detection risk before execution | Protects operational security of IC operations |

### 14.2 Safety Levels

All offensive actions in the platform are classified into one of four safety levels, each with escalating approval requirements:

| Safety Level | Examples | Approval Required |
|---|---|---|
| **passive_only** | OSINT collection, passive scanning, intelligence analysis | Automatic with logging |
| **low_impact** | Port scanning, service enumeration, banner grabbing | Operator approval |
| **standard** | Vulnerability exploitation, credential testing, web application attacks | Operator approval + impact acknowledgment |
| **full_exploitation** | Privilege escalation, lateral movement, data exfiltration, C2 deployment | Dual-approval (two independent operators) |

### 14.3 Evidence Integrity for IC Oversight

The platform's evidence integrity system is designed to meet the evidentiary standards required for IC Inspector General investigations, congressional oversight, and legal proceedings:

**HMAC-SHA256 Hash Chains** — Every evidence artifact is hashed using HMAC-SHA256 with a dedicated EVIDENCE_HMAC_KEY. Each hash includes the previous hash in the chain, creating a tamper-evident linked list that detects any modification or deletion of evidence.

**Key Separation** — The EVIDENCE_HMAC_KEY is separate from the platform's general-purpose JWT_SECRET, preventing compromise of one key from affecting the other. Key rotation is supported with configurable schedules.

**Provenance Tracking** — Every evidence artifact includes metadata recording who collected it, when, how, and under what authorization. This provenance data is included in the hash chain, ensuring that metadata tampering is also detectable.

**Export Formats** — Evidence can be exported in formats suitable for IC oversight processes, including structured JSON with hash verification, PDF reports with embedded integrity checksums, and STIX 2.1 bundles for intelligence sharing.


---

## 15. Interoperability and Intelligence Sharing

### 15.1 Standards Compliance

AC3 implements the following interoperability standards to ensure seamless integration with IC intelligence sharing infrastructure:

| Standard | Version | Implementation | IC Use Case |
|---|---|---|---|
| **STIX** | 2.1 | Full STIX 2.1 bundle generation and import | Intelligence sharing across IC elements via CTIIC |
| **TAXII** | 2.1 | TAXII client for feed consumption; export-ready for TAXII servers | Automated threat intelligence exchange |
| **OSCAL** | 1.0 | OSCAL-formatted compliance documentation export | Automated compliance reporting for ICD 503 / RMF |
| **MITRE ATT&CK** | v14+ | Full technique mapping for all offensive capabilities | Common adversary TTP taxonomy across IC |
| **CVSS** | v3.1 / v4.0 | Dual-version scoring with v4.0 feed-through to CARVER | Vulnerability severity communication |
| **EPSS** | Current | Daily EPSS score integration for exploitation probability | Prioritization of vulnerability remediation |
| **SIGMA** | Current | Detection rule generation in SIGMA format | Cross-platform detection engineering |
| **YARA** | Current | YARA rule generation for malware detection | Malware identification and hunting |
| **Snort/Suricata** | Current | Network detection rule generation | Network-level threat detection |

### 15.2 SIEM and SOAR Integration

The platform integrates with enterprise security infrastructure through its SIEM/SOAR integration modules:

**SIEM Integration** — Bidirectional integration with major SIEM platforms (Splunk, Elastic, Microsoft Sentinel, IBM QRadar) for log ingestion, alert correlation, and finding export. The integration supports both push (sending findings to SIEM) and pull (querying SIEM for contextual data during assessments).

**SOAR Integration** — Integration with SOAR platforms (Palo Alto XSOAR, Splunk SOAR, IBM Resilient) for automated response orchestration. Assessment findings can trigger SOAR playbooks for automated containment, notification, and remediation workflows.

**Ticketing Integration** — Integration with IT service management platforms (ServiceNow, Jira) for finding tracking and remediation workflow management.

### 15.3 Cross-Domain Intelligence Sharing

For IC organizations operating across multiple classification levels, AC3 provides structured intelligence sharing capabilities:

**STIX 2.1 Export** — All threat intelligence, findings, and assessments can be exported as STIX 2.1 bundles, providing a standardized format for cross-domain transfer through NSA-approved Cross-Domain Solutions.

**Classification Marking** — The platform supports classification marking of intelligence products, ensuring that exported data includes appropriate classification and handling caveats.

**Sanitization Support** — The platform provides tools for sanitizing classified findings for release at lower classification levels, including automated redaction of sensitive sources and methods while preserving the analytical value of the intelligence.

**TLP Marking** — All intelligence products support Traffic Light Protocol (TLP) marking (TLP:RED, TLP:AMBER+STRICT, TLP:AMBER, TLP:GREEN, TLP:CLEAR) for controlled sharing with external partners.

---

## 16. Licensing and Procurement

### 16.1 AceofCloud as Prime Contractor

AC3 is delivered and supported by AceofCloud, which serves as the prime contractor for all platform engagements. AceofCloud's organizational certifications — Authorized C3PAO, RPO, and accredited SCF 3PAO — provide IC customers with assurance that the firm meets the organizational maturity and security posture requirements expected of vendors operating in the national security space. The firm's team of certified CMMC Assessors (CCA) and CMMC Professionals (CCP) provides the bench depth required for sustained IC engagements, including on-site support, classified deployment assistance, and ongoing platform customization.

### 16.2 Procurement Vehicles

AC3 is designed to be procurable through the following federal procurement mechanisms:

| Vehicle | Applicability | Notes |
|---|---|---|
| **GSA MAS / HACS SIN (54151HACS)** | All federal agencies | Covers all six HACS subcategories: HVA Assessment, RVA, Cyber Hunt, Incident Response, Penetration Testing, IHEM |
| **Direct Award** | IC elements with specialized requirements | For classified deployments or customized configurations |
| **BPA/BOA** | Agencies with recurring assessment needs | Blanket Purchase Agreements for ongoing platform access |
| **IDIQ** | Large-scale, multi-year engagements | Indefinite Delivery/Indefinite Quantity for enterprise deployments |

### 16.3 Licensing Tiers

The platform offers tiered licensing appropriate for different organizational scales and mission requirements:

| Tier | Target Customer | Key Capabilities |
|---|---|---|
| **Professional** | Small teams, single-mission focus | Core scoring, vulnerability assessment, basic threat intelligence, engagement management |
| **Enterprise** | Large organizations, multi-team operations | Full platform capabilities, multi-tenant support, advanced threat intelligence, SIEM/SOAR integration |
| **Government** | Federal agencies, DoD components | Enterprise capabilities + FedRAMP alignment, FIPS 140-3 enforcement, evidence integrity chains, compliance reporting |
| **Intelligence** | IC elements, national security missions | Government capabilities + air-gapped deployment support, classified network compatibility, VEP analysis tools, cross-domain export |
| **MSSP** | Managed security service providers serving government | White-label deployment, multi-tenant isolation, client portal, automated reporting |

### 16.4 HACS Subcategory Mapping

The following table maps AC3 capabilities to GSA HACS subcategories, demonstrating how a single platform procurement satisfies requirements that traditionally require multiple vendor contracts:

| HACS Subcategory | AC3 Capabilities | Traditional Vendor Count |
|---|---|---|
| **High Value Asset Assessment** | Hybrid risk scoring (CARVER+SHOCK/CVSS/BIA), mission impact analysis, sector-specific assessment, executive risk dashboards | 1-2 vendors |
| **Risk and Vulnerability Assessment** | 64 passive connectors, multi-tool scanning (Nmap, Nuclei, ZAP, Burp), web app testing, API security, wireless assessment, OS security assessment | 2-3 vendors |
| **Cyber Hunt** | Hunt engine with HACS-compliant workflows, hypothesis-driven hunting, IOC correlation, behavioral analysis, LLM-assisted anomaly detection | 1-2 vendors |
| **Incident Response** | Evidence collection with hash chains, timeline reconstruction, attribution support, containment recommendations, automated reporting | 1-2 vendors |
| **Penetration Testing** | Full-lifecycle penetration testing, exploit catalog, C2 operations, post-exploitation, MITRE ATT&CK mapping, adversary emulation | 1-2 vendors |
| **IHEM** | SIEM integration, SOAR integration, detection engineering, alert correlation, compliance reporting | 1-2 vendors |

**Procurement Efficiency:** A single AC3 procurement replaces 7-13 separate vendor contracts, reducing procurement overhead, integration complexity, and the number of Authority to Operate (ATO) packages that must be maintained.

---

## 17. Frequently Asked Questions

**Q: Can AC3 operate on classified networks?**

A: Yes. The platform's containerized architecture supports deployment on SIPRNet (SECRET) and JWICS (TS/SCI) networks. Air-gapped deployment requires pre-loaded threat intelligence and either a locally hosted LLM or pre-computed analysis packages. The deterministic scoring engine operates without any external dependencies.

**Q: How does AC3 handle the VEP?**

A: The platform's CARVER+SHOCK scoring methodology provides quantitative support for VEP analysis by mapping vulnerability characteristics to the mission-impact dimensions evaluated by the Equities Review Board. The ExplainableRiskCard output provides the structured, auditable impact assessment that VEP deliberations require. The platform does not make VEP decisions — it provides the analytical foundation for human decision-makers.

**Q: What is the platform's FedRAMP status?**

A: AC3 is architecturally aligned with FedRAMP High requirements (421 controls). Formal FedRAMP authorization has not yet been obtained. The platform can be deployed on FedRAMP-authorized infrastructure (AWS GovCloud, Azure Government) as a customer-managed application while the formal authorization process is underway.

**Q: How does the AI governance address IC concerns about AI reliability?**

A: The platform's "Deterministic Baseline + Bounded LLM Delta" design principle ensures that all critical functions operate without AI involvement. LLM modules can adjust scores within bounded limits (typically 10-15%), but the deterministic baseline always provides a valid result. If LLM services are unavailable — as they may be on air-gapped networks — the platform continues to operate on deterministic scoring alone.

**Q: Can the platform integrate with existing IC threat intelligence infrastructure?**

A: Yes. The platform supports STIX 2.1 import and export, TAXII 2.1 feed consumption, and integration with major SIEM/SOAR platforms. Classified threat intelligence can be imported via STIX bundles through cross-domain solutions. The platform's threat model automatically correlates imported intelligence with existing data.

**Q: How does the platform handle multi-classification environments?**

A: The platform supports deployment at multiple classification levels simultaneously, with STIX 2.1 export enabling structured intelligence sharing through NSA-approved Cross-Domain Solutions. Classification marking and sanitization tools support downgrading findings for release at lower classification levels.

**Q: What training is required for IC analysts?**

A: The platform is designed for practitioners with existing offensive security and threat intelligence experience. IC analysts familiar with MITRE ATT&CK, STIX/TAXII, and standard vulnerability assessment methodologies can be productive within days. The platform's LLM-assisted analysis provides contextual guidance that helps less experienced operators make informed decisions, while the graduation system ensures that AI recommendations are calibrated to the operator's demonstrated proficiency. AceofCloud provides onboarding support, training packages, and ongoing technical assistance as part of all Government and Intelligence tier engagements.

**Q: What organizational certifications does the vendor hold?**

A: AceofCloud is a Cyber AB Authorized C3PAO, CMMC-AB Registered Provider Organization (RPO), and accredited SCF Third-Party Assessment Organization (3PAO). The firm's team includes certified CMMC Assessors (CCA) and CMMC Professionals (CCP). AceofCloud maintains active service lines in CMMC assessment, FedRAMP/GovRAMP advisory, penetration testing, vCISO services, and data governance — ensuring that the platform is continuously informed by real-world assessment and compliance experience.

**Q: What is the vendor's capacity for sustained IC engagements?**

A: AceofCloud maintains a team of 11-50 professionals with expertise spanning offensive security, compliance assessment, cloud architecture, and AI governance. The firm's organizational structure supports concurrent engagements across multiple classification levels and geographic locations. For large-scale IC deployments, AceofCloud can augment its team with vetted subcontractors holding appropriate clearances.

**Q: How does the platform support congressional oversight?**

A: Every action taken in the platform is logged with cryptographic integrity (HMAC-SHA256 hash chains), operator attribution, timestamp, and authorization reference. Evidence chains are tamper-evident and exportable in formats suitable for Inspector General investigations and congressional briefings. The ExplainableRiskCard output provides human-readable explanations of all scoring decisions, ensuring that non-technical oversight bodies can understand the basis for risk assessments.

---

## 18. References

| Reference | Description |
|---|---|
| DoDI 8585.01 (January 2024) | DoD Cyber Red Teams — governance, scope, authorities, and reporting requirements for DoD Cyber Red Teams |
| ICD 503 | Intelligence Community Information Technology Systems Security Risk Management — IC-specific RMF implementation |
| ICD 203 | Analytic Standards — standards for IC analytic tradecraft, including sourcing, confidence, and alternative analysis |
| CNSSI 1253 | Security Categorization and Control Selection for National Security Systems |
| NIST SP 800-53 Rev 5 | Security and Privacy Controls for Information Systems and Organizations |
| NIST SP 800-171 Rev 2 | Protecting Controlled Unclassified Information in Nonfederal Systems |
| NIST SP 800-115 | Technical Guide to Information Security Testing and Assessment |
| NIST AI 100-1 | AI Risk Management Framework |
| FIPS 140-3 | Security Requirements for Cryptographic Modules |
| FIPS 199 | Standards for Security Categorization of Federal Information and Information Systems |
| MITRE ATT&CK | Adversary Tactics, Techniques, and Common Knowledge framework |
| MITRE ATLAS | Adversarial Threat Landscape for AI Systems |
| OWASP Top 10 for LLM (2025) | Top 10 security risks for Large Language Model applications |
| STIX 2.1 | Structured Threat Information eXpression — standard for representing cyber threat intelligence |
| TAXII 2.1 | Trusted Automated eXchange of Indicator Information — transport protocol for CTI sharing |
| OSCAL 1.0 | Open Security Controls Assessment Language — machine-readable compliance documentation |
| GSA HACS SIN (54151HACS) | Highly Adaptive Cybersecurity Services — federal procurement vehicle for cybersecurity services |
| DoD CC SRG | DoD Cloud Computing Security Requirements Guide — Impact Levels IL2-IL6 |
| IC ITE Strategy 2022-2027 | Intelligence Community Information Technology Enterprise Strategy |
| PPD-41 | Presidential Policy Directive on United States Cyber Incident Coordination |
| VEP Charter (2017) | Vulnerabilities Equities Policy and Process for the United States Government |
| Wassenaar Arrangement | Export control regime for dual-use technologies including cybersecurity tools |

---

**Document Control**

| Field | Value |
|---|---|
| Document ID | AC3-IC-PG-001 |
| Version | 1.0 |
| Date | April 2026 |
| Author | AceofCloud (Harrison Cook, Architect/Creator) |
| Classification | UNCLASSIFIED |
| Distribution | Approved for public release |
| Review Cycle | Quarterly |

---

*This document is approved for public release and does not contain classified information. All capabilities described are based on the platform's unclassified architecture. Classified deployment configurations, specific IC customer implementations, and operational details are addressed in separate, appropriately classified documents.*
