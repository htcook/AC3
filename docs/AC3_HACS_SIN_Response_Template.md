# AC3 HACS SIN Response Template

**GSA Multiple Award Schedule — SIN 54151HACS**
**Highly Adaptive Cybersecurity Services**

**Prepared by:** AceofCloud
**Platform:** AC3 (AceofCloud Cybersecurity Command)
**Date:** April 2026
**Classification:** UNCLASSIFIED — For Official Use Only (FOUO)
**NAICS Code:** 541519

---

## Document Purpose

This document is a pre-filled response template that maps AceofCloud's AC3 platform capabilities to each of the six GSA HACS subcategories. It is designed to serve as the technical foundation for a SIN 54151HACS offer or modification submission, and to prepare key personnel for the oral technical evaluation conducted by GSA's Technical Evaluation Board. Each section follows the structure that GSA evaluators expect: service description, methodology, tooling, personnel qualifications, and past performance alignment. Sections 3.0 and 4.0 content can be copied directly into the GSA HACS RFQ template.

---

## Table of Contents

1. [Offeror Profile and Organizational Credentials](#1-offeror-profile-and-organizational-credentials)
2. [Pre-Evaluation Responses](#2-pre-evaluation-responses)
3. [Subcategory 1: High Value Asset Assessments](#3-subcategory-1-high-value-asset-assessments)
4. [Subcategory 2: Risk and Vulnerability Assessments](#4-subcategory-2-risk-and-vulnerability-assessments)
5. [Subcategory 3: Penetration Testing](#5-subcategory-3-penetration-testing)
6. [Subcategory 4: Cyber Hunt](#6-subcategory-4-cyber-hunt)
7. [Subcategory 5: Incident Response](#7-subcategory-5-incident-response)
8. [Subcategory 6: Incident Handling and Event Management](#8-subcategory-6-incident-handling-and-event-management)
9. [Oral Technical Evaluation Preparation Guide](#9-oral-technical-evaluation-preparation-guide)
10. [Key Personnel Roster](#10-key-personnel-roster)
11. [NICE Framework Work Role Alignment](#11-nice-framework-work-role-alignment)
12. [Pricing Structure and Labor Categories](#12-pricing-structure-and-labor-categories)
13. [Compliance and Certification Matrix](#13-compliance-and-certification-matrix)
14. [Appendix A: AC3 Module-to-Subcategory Cross-Reference](#appendix-a-ac3-module-to-subcategory-cross-reference)

---

## 1. Offeror Profile and Organizational Credentials

### 1.1 Company Overview

**AceofCloud** is a NIST-focused cybersecurity and compliance firm headquartered in Sterling, Virginia. The firm provides assessment, advisory, and offensive security services to Department of Defense contractors, federal civilian agencies, and critical infrastructure operators. AceofCloud maintains active accreditations as an **Authorized CMMC Third-Party Assessment Organization (C3PAO)**, a **Registered Provider Organization (RPO)**, and an **accredited SCF Third-Party Assessment Organization (3PAO)**.

The firm's technical staff includes certified CMMC Certified Assessors (CCA), CMMC Certified Professionals (CCP), and offensive security practitioners with experience across penetration testing, red team operations, vulnerability assessment, threat intelligence, and compliance advisory. AceofCloud's service portfolio spans CMMC assessments (Levels 1–3), FedRAMP and GovRAMP advisory, penetration testing (external, internal, web application, wireless, social engineering), purple team exercises, virtual CISO services, data governance, and security architecture review.

### 1.2 AC3 Platform

AC3 (AceofCloud Cybersecurity Command) is AceofCloud's integrated offensive security, threat intelligence, and risk analysis platform. The platform was architected by Harrison Cook, AceofCloud's Director of Security Engineering and Offensive Operations, and consolidates capabilities that agencies currently procure from multiple vendors into a single operational environment. AC3 comprises 633 server-side modules, 319 client interface pages, and 352 database tables — a codebase exceeding 903,000 lines of TypeScript, organized into eight functional domains: Command and Control, Reconnaissance and Discovery, Risk and Scoring, Exploitation Operations, Threat Intelligence, Compliance and Reporting, Engagement Management, and Platform Administration.

The platform's distinguishing characteristic is its **hybrid risk scoring engine**, which fuses CARVER+SHOCK methodology (adapted from physical security targeting analysis for digital asset assessment), CVSS v4.0 base and environmental metrics, EPSS exploit prediction scores, and NIST SP 800-60 / FIPS 199 business impact analysis into a single composite risk score. This scoring system is augmented by bounded LLM analysis (deltas clamped to ±1.5 per CARVER factor), temporal decay modeling, and a seven-layer safety architecture that enforces Rules of Engagement scope, two-person integrity for high-risk operations, and tamper-evident evidence chains.

### 1.3 Organizational Certifications

| Certification / Accreditation | Status | Relevance |
|---|---|---|
| CMMC Authorized C3PAO | Active | Demonstrates assessment rigor and DoD compliance expertise |
| Registered Provider Organization (RPO) | Active | Authorized to provide CMMC consulting and preparation services |
| SCF Accredited 3PAO | Active | Third-party assessment capability for Secure Controls Framework |
| CMMC Certified Assessors (CCA) | Staff-held | Personnel qualified to conduct official CMMC assessments |
| CMMC Certified Professionals (CCP) | Staff-held | Personnel qualified for CMMC advisory and preparation |
| FIPS 140-3 Compliant Cryptographic Operations | Platform | All AC3 cryptographic operations use FIPS 140-3 validated modules |

### 1.4 Nationwide Deployment Capability

AceofCloud maintains the ability to deploy assessment teams nationwide within 48 hours of task order issuance. The AC3 platform is cloud-native and accessible from any authorized endpoint, enabling remote assessment initiation within 24 hours for engagements that do not require on-site presence. For classified or air-gapped environments, AceofCloud supports on-premises deployment models with portable assessment kits.

---

## 2. Pre-Evaluation Responses

The following responses address the three pre-evaluation questions posed by GSA's Technical Evaluation Board before the formal oral technical evaluation begins.

### 2.1 Which cybersecurity services do you offer?

AceofCloud offers services across all six HACS subcategories through the AC3 platform and direct practitioner engagement:

**High Value Asset Assessments.** Security Architecture Reviews (SAR), Systems Security Engineering (SSE) assessments, and combined RVA+SAR evaluations of agency high-value assets. AC3's hybrid risk scoring engine provides quantitative risk analysis that maps directly to NIST SP 800-60 impact levels and FIPS 199 security categorization, enabling agencies to prioritize remediation based on mission impact rather than raw vulnerability counts.

**Risk and Vulnerability Assessments.** Network mapping, vulnerability scanning, phishing assessments, wireless assessments, web application assessments, operating system security assessments (OSSA), database assessments, and social engineering evaluations. AC3 integrates 64 passive reconnaissance connectors and active scanning through Nmap, Nuclei, ZAP, and Burp Suite orchestration, with results automatically correlated through the hybrid scoring engine.

**Penetration Testing.** External and internal network penetration testing, web application penetration testing, wireless penetration testing, social engineering penetration testing, and physical security penetration testing. AC3's exploitation operations module provides MITRE ATT&CK-aligned adversary emulation with automated attack path analysis, exploit selection from a curated catalog, and real-time safety guardrails that enforce Rules of Engagement scope boundaries.

**Cyber Hunt.** Proactive threat hunting using hypothesis-driven methodologies, network traffic analysis, endpoint analysis, log analysis, and threat intelligence integration. AC3's threat intelligence hub aggregates feeds from CISA KEV, NVD, EPSS, abuse.ch, Shodan, Censys, SecurityTrails, and additional commercial and open-source feeds, enabling hunt teams to correlate indicators of compromise against the agency's attack surface in real time.

**Incident Response.** Incident detection and analysis, containment, eradication, recovery, post-incident activity, and forensic analysis. AC3's SIEM integration, SOAR playbook engine, and evidence integrity chain provide the investigative infrastructure for rapid incident triage and forensically sound evidence collection.

**Incident Handling and Event Management.** Security event monitoring, SIEM management, SOC operations, and alert triage and escalation. AC3's continuous monitoring capabilities, detection engineering module, and EDR integration provide the operational backbone for sustained security operations center support.

### 2.2 How quickly can you deploy resources for an engagement?

AceofCloud maintains three deployment tiers calibrated to engagement urgency:

| Deployment Tier | Timeline | Scope |
|---|---|---|
| **Immediate (Remote)** | Within 24 hours | Remote assessments, vulnerability scanning, threat hunting via AC3 platform |
| **Rapid (On-Site)** | Within 48 hours | On-site penetration testing, incident response, HVA assessments (CONUS) |
| **Scheduled (Full Engagement)** | Within 5 business days | Full-scope engagements including physical security testing, air-gapped deployments |

For incident response engagements, AceofCloud maintains a standing incident response retainer capability with 4-hour initial response for remote triage and 24-hour on-site deployment for CONUS locations.

### 2.3 Do you have resources to deploy nationwide?

Yes. AceofCloud's team operates from the Sterling, Virginia headquarters with the ability to deploy practitioners to any CONUS location within 48 hours. The AC3 platform's cloud-native architecture enables remote assessment initiation from any authorized endpoint, and the platform supports VPN-tunneled assessment for agencies that require assessors to operate within their network perimeter without physical presence. For OCONUS engagements, AceofCloud coordinates deployment timelines on a case-by-case basis with the ordering agency.

---

## 3. Subcategory 1: High Value Asset Assessments

### 3.1 Service Description

AceofCloud provides High Value Asset (HVA) assessments that combine Security Architecture Review (SAR), Systems Security Engineering (SSE), and Risk and Vulnerability Assessment (RVA) into a unified evaluation of an agency's most critical information systems. The assessment methodology follows CISA's HVA initiative guidance and integrates AceofCloud's proprietary hybrid risk scoring to provide quantitative, mission-impact-weighted risk analysis that goes beyond traditional vulnerability enumeration.

### 3.2 Methodology: Pre-Engagement Phase

The pre-engagement phase establishes the assessment scope, identifies the HVA environment boundaries, and prepares the assessment team for effective execution.

**Scoping and Planning.** AceofCloud conducts an initial scoping call with the agency's designated HVA point of contact to define the assessment boundary, identify supporting systems, and establish the Rules of Engagement. AC3's ROE scope enforcement module captures these boundaries digitally and enforces them throughout the engagement — scanning and exploitation activities that would exceed the defined scope are automatically blocked at the platform level, not merely documented as policy.

**Documentation Review.** The assessment team reviews the agency's System Security Plan (SSP), network diagrams, data flow diagrams, and prior assessment reports. AC3's compliance reporting module ingests these artifacts and maps them against NIST SP 800-53 control families, identifying gaps before active assessment begins.

**Attack Surface Enumeration.** AC3's 64 passive reconnaissance connectors enumerate the HVA's external attack surface without generating network traffic that could trigger defensive alerts. This includes DNS enumeration, certificate transparency log analysis, WHOIS intelligence, Shodan/Censys infrastructure fingerprinting, and subdomain discovery. The results are automatically correlated with the agency's asset inventory to identify shadow IT and unmanaged exposure.

### 3.3 Methodology: Assessment Phase

**Security Architecture Review (SAR).** The SAR evaluates the HVA's security posture through structured interviews with system administrators, security engineers, and mission owners. The review covers network segmentation, access control architecture, encryption implementation, logging and monitoring coverage, backup and recovery procedures, and incident response readiness. AC3's compliance engine maps findings against NIST SP 800-53 controls and generates a gap analysis with specific remediation recommendations prioritized by the hybrid risk score.

**Systems Security Engineering (SSE).** The SSE assessment evaluates security across the Systems Development Life Cycle, focusing on six security domains: perimeter security, network security, endpoint security, application security, physical security, and data security. AC3's scanning orchestration module (ScanForge) coordinates automated assessments across these domains — vulnerability scanning with Nmap and Nuclei, web application testing with ZAP and Burp Suite, and configuration compliance checking against CIS Benchmarks and DISA STIGs.

**Risk and Vulnerability Assessment (RVA).** The RVA component conducts active vulnerability scanning, validates findings through manual verification, and assesses risk using AC3's hybrid scoring engine. Each vulnerability is scored not only by CVSS base metrics but by its mission impact — a medium-severity vulnerability on a system that processes classified information receives a higher composite score than a critical-severity vulnerability on a non-mission-essential system. This mission-impact weighting is derived from the CARVER+SHOCK methodology, which evaluates Criticality, Accessibility, Recuperability, Vulnerability, Effect, and Recognizability, augmented by Shock (public/political impact).

### 3.4 Methodology: Post-Engagement Phase

**Reporting.** AC3 generates a comprehensive HVA assessment report that includes an executive summary with mission-impact-weighted risk rankings, detailed technical findings with CVSS v4.0 and hybrid composite scores, remediation recommendations prioritized by operational risk, a compliance gap analysis mapped to NIST SP 800-53 controls, and an attack path analysis showing how identified vulnerabilities could be chained for exploitation.

**Remediation Support.** AceofCloud provides 30-day post-assessment remediation support, including technical consultation on remediation approaches, validation scanning to confirm remediation effectiveness, and updated risk scoring to reflect the agency's improved security posture.

### 3.5 AC3 Platform Capabilities Supporting HVA Assessments

| HVA Assessment Component | AC3 Module(s) | Capability |
|---|---|---|
| Security Architecture Review | Compliance Engine, NIST 800-53 Mapper | Automated control gap analysis against 1,189 SP 800-53 Rev 5 controls |
| Systems Security Engineering | ScanForge, DAST Scanner, CIS Benchmark Checker | Multi-tool scanning orchestration across 6 security domains |
| Risk and Vulnerability Assessment | Hybrid Scoring Engine, CVSS v4.0 Parser | Mission-impact-weighted risk scoring with CARVER+SHOCK fusion |
| Attack Surface Enumeration | 64 Passive Connectors, DNS/Cert/WHOIS modules | Comprehensive external footprint discovery without active probing |
| Reporting | Report Generator, OSCAL Exporter | Automated report generation in agency-required formats |
| Evidence Collection | Evidence Integrity Chain, HMAC Signing | Tamper-evident evidence packaging for oversight review |

---

## 4. Subcategory 2: Risk and Vulnerability Assessments

### 4.1 Service Description

AceofCloud provides Risk and Vulnerability Assessments (RVA) that evaluate an agency's IT infrastructure to identify potential vulnerabilities, assess the level of risk, and recommend appropriate mitigation countermeasures. The RVA methodology covers all service areas defined under the HACS RVA subcategory: Network Mapping, Vulnerability Scanning, Phishing Assessment, Wireless Assessment, Web Application Assessment, Operating System Security Assessment (OSSA), Database Assessment, and Social Engineering.

### 4.2 Service Area Mapping

| RVA Service Area | AC3 Module(s) | Methodology |
|---|---|---|
| **Network Mapping** | Nmap Orchestrator, Network Discovery Engine | Active and passive network enumeration including host discovery, port scanning, service identification, OS fingerprinting, and network topology mapping. AC3 correlates discovered assets against the agency's Configuration Management Database (CMDB) to identify unmanaged devices. |
| **Vulnerability Scanning** | ScanForge, Nuclei Engine, Vulnerability Correlator | Authenticated and unauthenticated vulnerability scanning using multiple engines (Nmap NSE, Nuclei templates, custom checks). Results are deduplicated, correlated across scanners, and scored using the hybrid risk engine. False positive rates are tracked and reported. |
| **Phishing Assessment** | GoPhish Integration, Phishing Campaign Manager | Simulated phishing campaigns using GoPhish with custom templates calibrated to the agency's communication patterns. Campaigns measure click rates, credential submission rates, and reporting rates. Results feed into the agency's security awareness metrics. |
| **Wireless Assessment** | Wireless Scanner, RF Analysis Module | Wireless network discovery, rogue access point detection, WPA/WPA2/WPA3 security assessment, client isolation testing, and wireless intrusion detection system (WIDS) validation. |
| **Web Application Assessment** | ZAP Orchestrator, Burp Suite Integration, DAST Scanner | OWASP Top 10 assessment, authentication and session management testing, input validation testing, business logic testing, and API security assessment. AC3 supports both automated scanning and manual testing workflows. |
| **OSSA** | CIS Benchmark Checker, STIG Compliance Scanner | Operating system configuration assessment against CIS Benchmarks and DISA STIGs for Windows, Linux, and macOS. Automated compliance scoring with deviation reporting. |
| **Database Assessment** | Database Scanner, SQL Injection Tester | Database configuration review, access control assessment, encryption-at-rest validation, audit logging verification, and SQL injection testing for database-backed applications. |
| **Social Engineering** | Phishing Campaign Manager, Pretext Engine | Phone-based pretexting, physical social engineering (tailgating, badge cloning), and combined digital/physical social engineering campaigns. All social engineering activities operate within the ROE scope enforcement system. |

### 4.3 Methodology: Pre-Engagement

The RVA pre-engagement phase follows the same scoping discipline described in Section 3.2, with additional focus on identifying the specific RVA service areas required by the ordering agency. AC3's engagement orchestrator creates a structured assessment plan that sequences service areas to minimize operational disruption — passive activities (network mapping, vulnerability scanning) precede active activities (phishing, social engineering) to establish a baseline before introducing human-factor testing.

### 4.4 Methodology: Assessment Execution

AC3's ScanForge module orchestrates the technical assessment across all requested service areas. The platform's scan policy engine enforces time windows, rate limits, and exclusion lists defined in the ROE. Assessment findings are automatically correlated across service areas — a web application vulnerability discovered during the web application assessment is cross-referenced with the network mapping results to determine whether the vulnerable application is internet-facing, and with the OSSA results to determine whether the underlying operating system has compensating controls.

The hybrid risk scoring engine assigns each finding a composite score that reflects both technical severity (CVSS v4.0) and mission impact (CARVER+SHOCK). This dual-axis scoring enables the agency to prioritize remediation based on operational risk rather than raw vulnerability counts.

### 4.5 Methodology: Post-Engagement

RVA deliverables include a technical findings report with hybrid risk scores, a remediation roadmap prioritized by mission impact, a compliance mapping showing findings against applicable control frameworks (NIST SP 800-53, NIST CSF, CMMC), and an executive summary suitable for agency leadership. AC3's report generator produces these deliverables in multiple formats including PDF, OSCAL JSON, and STIX 2.1 for integration with the agency's GRC and threat intelligence platforms.

---

## 5. Subcategory 3: Penetration Testing

### 5.1 Service Description

AceofCloud provides penetration testing services that mimic real-world attacks to identify methods for circumventing the security features of an agency's applications, systems, and networks. The penetration testing methodology is aligned with the MITRE ATT&CK framework and supports external network, internal network, web application, wireless, social engineering, and physical security penetration testing.

### 5.2 Methodology: Pre-Engagement

**Rules of Engagement Definition.** AC3's ROE scope enforcement module captures the engagement boundaries — target IP ranges, domain names, testing windows, excluded systems, escalation procedures, and emergency contacts. These boundaries are digitally enforced throughout the engagement; the platform blocks any reconnaissance, scanning, or exploitation activity that would exceed the defined scope.

**Threat Modeling.** The assessment team develops a threat model specific to the agency's mission and threat landscape. AC3's threat intelligence hub identifies the APT groups, criminal organizations, and insider threat profiles most relevant to the agency's sector and mission, and the penetration test is designed to emulate the TTPs of those specific threat actors.

**Attack Plan Development.** Based on the threat model, the team develops an attack plan that maps specific MITRE ATT&CK techniques to each phase of the engagement. AC3's attack path analysis module identifies the most likely exploitation chains based on the agency's known attack surface, enabling the team to focus testing on the paths that represent the highest operational risk.

### 5.3 Methodology: Assessment Execution

**Reconnaissance.** AC3's 64 passive connectors enumerate the target's external footprint without generating detectable traffic. Active reconnaissance (port scanning, service enumeration, banner grabbing) follows within the approved testing window.

**Exploitation.** AC3's exploitation operations module provides a curated exploit catalog with safety-rated exploits categorized by reliability, impact, and reversibility. The seven-layer safety architecture enforces graduated access controls — low-impact testing (scanning, enumeration) operates under standard safety levels, while high-impact exploitation (privilege escalation, lateral movement, data exfiltration simulation) requires elevated authorization with two-person integrity for the most sensitive operations. Every exploitation action is logged to the tamper-evident evidence chain with timestamps, operator identity, target, technique, and outcome.

**Post-Exploitation.** When exploitation succeeds, the team assesses the depth of access achieved — credential harvesting, lateral movement potential, data access scope, and persistence mechanisms. AC3's attack path visualization shows the complete kill chain from initial access to objective achievement, mapped to MITRE ATT&CK techniques at each step.

**Adversary Emulation.** For agencies that require threat-specific testing, AC3 supports full adversary emulation campaigns using MITRE CALDERA integration. The platform can emulate the complete TTP profiles of documented threat actors (APT29, APT28, Lazarus Group, and others) against the agency's defensive infrastructure, providing a realistic assessment of the agency's ability to detect and respond to specific threats.

### 5.4 Penetration Testing Types

| Testing Type | Scope | AC3 Capabilities |
|---|---|---|
| **External Network** | Internet-facing infrastructure | Automated and manual testing of perimeter defenses, VPN concentrators, web servers, email gateways, DNS infrastructure |
| **Internal Network** | Internal network from assumed breach position | Lateral movement, privilege escalation, Active Directory attack paths, Kerberoasting, credential relay, domain compromise assessment |
| **Web Application** | Web applications and APIs | OWASP Top 10, business logic testing, authentication bypass, injection testing, API security assessment |
| **Wireless** | Wireless network infrastructure | Rogue AP detection, WPA/WPA2/WPA3 cracking, evil twin attacks, client-side attacks, wireless IDS evasion |
| **Social Engineering** | Human-factor testing | Phishing campaigns, phone pretexting, physical social engineering, USB drop campaigns |
| **Physical Security** | Physical access controls | Tailgating, badge cloning, lock bypass, physical perimeter assessment |

### 5.5 Safety Architecture

AC3's penetration testing operations are governed by a seven-layer safety architecture that prevents testing activities from causing unintended operational impact:

| Safety Layer | Function |
|---|---|
| **Layer 1: ROE Scope Enforcement** | Digital enforcement of target boundaries — blocks out-of-scope activity at the platform level |
| **Layer 2: Safety Level Classification** | Four-tier safety classification (passive_only, low_impact, standard, full_exploitation) gates available techniques |
| **Layer 3: Exploit Safety Rating** | Each exploit in the catalog is rated for reliability, reversibility, and potential for collateral damage |
| **Layer 4: Two-Person Integrity** | High-risk operations (full_exploitation tier) require dual approval before execution |
| **Layer 5: Real-Time Monitoring** | Continuous monitoring of target system health during testing — automatic pause if anomalies detected |
| **Layer 6: Evidence Integrity Chain** | Every action logged with HMAC-signed timestamps for forensic accountability |
| **Layer 7: Emergency Stop** | Platform-wide kill switch that immediately halts all active testing operations |

---

## 6. Subcategory 4: Cyber Hunt

### 6.1 Service Description

AceofCloud provides proactive cyber hunt services that identify threat actor presence within an agency's network before the adversary achieves their objectives. The hunt methodology is hypothesis-driven, informed by current threat intelligence, and designed to detect adversary activity that has evaded existing security controls.

### 6.2 Methodology: Hypothesis Generation

AC3's threat intelligence hub aggregates indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs) from multiple sources — CISA KEV, NVD, EPSS, abuse.ch ThreatFox, Shodan, Censys, SecurityTrails, and commercial threat feeds. The hunt team uses this intelligence to generate hypotheses about potential adversary presence based on the agency's sector, mission, known threat actors, and current threat landscape.

Hypothesis examples include: "APT groups known to target [agency sector] have recently used [specific TTP] — we hypothesize that similar activity may be present in the agency's network and can be detected by examining [specific data source] for [specific indicator]."

### 6.3 Methodology: Hunt Execution

| Hunt Activity | AC3 Module(s) | Description |
|---|---|---|
| **Network Traffic Analysis** | SIEM Integration, Network Flow Analyzer | Analysis of network flow data, DNS query logs, and proxy logs to identify anomalous communication patterns, beaconing behavior, and data exfiltration indicators |
| **Endpoint Analysis** | EDR Integration, Endpoint Telemetry Correlator | Analysis of endpoint telemetry including process execution, file system changes, registry modifications, and scheduled task creation to identify persistence mechanisms and lateral movement |
| **Log Analysis** | SIEM Integration, Log Correlation Engine | Cross-correlation of authentication logs, application logs, and security event logs to identify credential abuse, privilege escalation, and unauthorized access patterns |
| **Threat Intelligence Correlation** | Threat Intelligence Hub, IOC Matcher | Real-time correlation of hunt findings against current threat intelligence to attribute observed activity to known threat actors and identify related indicators |
| **Memory Analysis** | Forensic Analysis Module | Analysis of volatile memory captures to identify fileless malware, injected code, and in-memory-only persistence mechanisms |

### 6.4 Methodology: Post-Hunt

Hunt findings are documented in a structured hunt report that includes the hypothesis tested, data sources examined, analytical techniques applied, findings (confirmed or negative), and recommended defensive improvements. Confirmed findings are escalated through the agency's incident response process. Negative findings (no adversary activity detected for a given hypothesis) are documented as evidence of due diligence and contribute to the agency's overall threat posture assessment.

AC3's detection engineering module converts confirmed hunt findings into automated detection rules (Sigma, YARA, Snort/Suricata) that the agency can deploy to their existing security infrastructure, ensuring that the same adversary technique will be detected automatically in the future.



---

## 7. Subcategory 5: Incident Response

### 7.1 Service Description

AceofCloud provides incident response services that help agencies impacted by cybersecurity compromises determine the extent of the incident, remove the adversary from their systems, and restore their networks to a more secure state. The incident response methodology follows NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide) and is supported by AC3's forensic analysis, evidence integrity, and SOAR capabilities.

### 7.2 Methodology: Incident Detection and Analysis

Upon engagement activation, the AceofCloud incident response team conducts initial triage to determine the scope and severity of the incident. AC3's SIEM integration module ingests the agency's security event data and correlates it against current threat intelligence to identify the adversary's TTPs. The platform's threat intelligence hub provides real-time attribution support, matching observed indicators against known threat actor profiles to inform the response strategy.

Initial triage deliverables include a preliminary incident assessment with severity classification, identified indicators of compromise, initial scope determination (systems affected, data at risk), and recommended immediate containment actions.

### 7.3 Methodology: Containment, Eradication, and Recovery

**Containment.** The response team works with the agency's IT staff to implement containment measures that prevent the adversary from expanding their foothold while preserving forensic evidence. AC3's SOAR playbook engine provides pre-built containment playbooks for common incident types (ransomware, business email compromise, APT intrusion, insider threat) that can be customized to the agency's environment and executed through automated or semi-automated workflows.

**Eradication.** Once containment is achieved, the team systematically removes the adversary's presence from the agency's environment. This includes removing malware, closing unauthorized access paths, resetting compromised credentials, and patching exploited vulnerabilities. AC3's attack path analysis module maps the adversary's complete intrusion chain, ensuring that all persistence mechanisms are identified and removed.

**Recovery.** The team supports the agency in restoring affected systems to normal operations. AC3's validation scanning capability confirms that remediation actions were effective and that no residual adversary presence remains. The platform's continuous monitoring module provides enhanced monitoring during the recovery period to detect any adversary re-entry attempts.

### 7.4 Methodology: Post-Incident Activity

Post-incident deliverables include a comprehensive incident report with timeline reconstruction, root cause analysis, adversary TTP mapping to MITRE ATT&CK, lessons learned, and recommended defensive improvements. AC3's evidence integrity chain ensures that all forensic evidence collected during the response is preserved with HMAC-signed timestamps and chain-of-custody documentation suitable for legal proceedings or oversight review.

The detection engineering module converts incident findings into automated detection rules, and the compliance reporting module maps the incident and response actions against applicable reporting requirements (FISMA, CISA incident reporting directives, agency-specific policies).

### 7.5 Incident Response Capabilities

| IR Phase | AC3 Module(s) | Capability |
|---|---|---|
| Detection & Triage | SIEM Integration, Threat Intel Hub, IOC Matcher | Real-time event correlation, threat attribution, severity classification |
| Forensic Analysis | Forensic Analysis Module, Evidence Integrity Chain | Disk forensics, memory analysis, network forensics, tamper-evident evidence collection |
| Containment | SOAR Playbook Engine, Network Isolation Module | Automated and semi-automated containment playbooks for common incident types |
| Eradication | Attack Path Analyzer, Malware Analysis Module | Complete intrusion chain mapping, persistence mechanism identification and removal |
| Recovery | Validation Scanner, Continuous Monitoring | Post-remediation validation scanning, enhanced monitoring during recovery |
| Reporting | Report Generator, STIX Exporter, Compliance Mapper | Incident reports, MITRE ATT&CK mapping, compliance reporting, detection rule generation |

---

## 8. Subcategory 6: Incident Handling and Event Management

### 8.1 Service Description

AceofCloud provides incident handling and event management services that support sustained security operations center (SOC) functions including security event monitoring, SIEM management, alert triage and escalation, and continuous threat monitoring. These services provide the operational backbone for agencies that require ongoing cybersecurity monitoring beyond point-in-time assessments.

### 8.2 Service Components

**Security Event Monitoring.** AC3's continuous monitoring capabilities provide 24/7 security event monitoring through SIEM integration, with automated alert correlation and prioritization. The platform's detection engineering module maintains and tunes detection rules based on current threat intelligence and the agency's specific threat profile.

**SIEM Management.** AceofCloud provides SIEM configuration, tuning, and management services. AC3 integrates with major SIEM platforms (Splunk, Elastic, Microsoft Sentinel, QRadar) and provides automated log source onboarding, parser development, and correlation rule management. The platform's log analysis engine identifies gaps in logging coverage and recommends additional data sources to improve detection capability.

**Alert Triage and Escalation.** AC3's SOC workflow module provides structured alert triage with automated enrichment — each alert is automatically correlated against threat intelligence, asset criticality (from the hybrid risk scoring engine), and historical incident data. Triage analysts receive enriched alerts with context that enables faster and more accurate disposition decisions. Escalation procedures follow the agency's defined incident response plan with automated notification and tracking.

**Continuous Threat Monitoring.** AC3's threat intelligence hub provides continuous monitoring of the agency's external attack surface, dark web exposure, and threat landscape. The platform automatically alerts on new vulnerabilities affecting the agency's technology stack, new threat actor campaigns targeting the agency's sector, and changes to the agency's external footprint that may indicate compromise or unauthorized exposure.

### 8.3 SOC Support Model

| Service Tier | Coverage | Scope |
|---|---|---|
| **Tier 1: Monitoring and Triage** | 24/7 or business hours | Alert monitoring, initial triage, false positive filtering, escalation |
| **Tier 2: Investigation and Analysis** | Business hours with on-call | Deep-dive investigation, threat hunting, incident analysis |
| **Tier 3: Advanced Response** | On-call | Incident response activation, forensic analysis, adversary engagement |

---

## 9. Oral Technical Evaluation Preparation Guide

This section provides guidance for AceofCloud's key personnel preparing for the GSA HACS oral technical evaluation. The evaluation consists of questions related to the three base subcategories (HVA Assessments, RVA, and Penetration Testing) during a 1-hour-40-minute session, with an additional 10 minutes each for Cyber Hunt and Incident Response if those subcategories are offered.

### 9.1 Evaluation Structure

| Component | Duration | Subcategories |
|---|---|---|
| Base Evaluation | 100 minutes | HVA Assessments, RVA, Penetration Testing |
| Cyber Hunt (optional) | 10 minutes | Cyber Hunt |
| Incident Response (optional) | 10 minutes | Incident Response |
| Incident Handling (optional) | 10 minutes | Incident Handling and Event Management |

### 9.2 Anticipated Question Areas and Recommended Responses

**Question Area 1: Pre-Engagement, Testing, and Post-Engagement Activities**

Evaluators will ask about the activities carried out during each phase of an engagement. Key personnel should describe AceofCloud's structured three-phase methodology:

The pre-engagement phase centers on scoping, ROE definition, documentation review, and attack surface enumeration. Emphasize that AC3 digitally enforces ROE boundaries at the platform level — this is a differentiator from competitors who rely on procedural controls alone. Describe the documentation review process and how AC3's compliance engine maps existing artifacts against control frameworks before active assessment begins.

The assessment phase should be described in terms of the specific service area being discussed. For HVA, emphasize the combined SAR/SSE/RVA approach. For RVA, walk through the eight service areas. For penetration testing, describe the MITRE ATT&CK-aligned methodology and the safety architecture. In all cases, emphasize the hybrid risk scoring engine and how it provides mission-impact-weighted prioritization.

The post-engagement phase should cover reporting, remediation support, and detection rule generation. Emphasize that AC3 generates automated detection rules from assessment findings, providing lasting defensive value beyond the assessment report.

**Question Area 2: Organizational Capabilities Background**

Evaluators will ask about AceofCloud's background and capabilities in each subcategory. Key personnel should describe AceofCloud's dual identity as both a compliance assessment organization (C3PAO, RPO, SCF 3PAO) and an offensive security practice, and how this dual perspective informs the AC3 platform's design. Emphasize the platform's scale (633 modules, 903,000+ lines of code) and the practitioner-first design philosophy — AC3 is built by practitioners who conduct real assessments under real ROE constraints.

**Question Area 3: Scenario-Based Experience**

Evaluators will ask for specific scenarios from the past two years. Key personnel should prepare 2-3 concrete engagement examples per subcategory that demonstrate technical depth, client impact, and lessons learned. Each scenario should include the engagement scope, methodology applied, key findings, remediation recommendations, and measurable client outcomes.

**Question Area 4: Specific Processes and Methods**

Evaluators will ask about specific technical processes for reconnaissance, preparation, and testing activities. Key personnel should be prepared to describe AC3's technical workflows in detail — the 64 passive connectors for reconnaissance, the ScanForge multi-tool orchestration for vulnerability assessment, the exploit catalog and safety rating system for penetration testing, and the hypothesis-driven methodology for cyber hunt operations.

### 9.3 Evaluation Tips

The oral technical evaluation is structured as a professional interview, not a written exam. Key personnel should treat each question as an opportunity to demonstrate both technical competence and operational maturity. Every answer should be supported by a concrete past performance example. AceofCloud's organizational certifications (C3PAO, RPO, SCF 3PAO) should be referenced where relevant to demonstrate assessment rigor. The AC3 platform's safety architecture and evidence integrity chain should be highlighted as differentiators that demonstrate operational discipline.

Key personnel are permitted to take notes during the evaluation but may not remove notes from the evaluation room. Evaluator notes are incorporated into the GSA Pre-Negotiation Memorandum but are not visible to ordering agencies.

---

## 10. Key Personnel Roster

The following key personnel are designated to represent AceofCloud during the HACS oral technical evaluation. All personnel are AceofCloud employees (no consultants) and will sign the required Non-Disclosure Agreement prior to the evaluation session.

| # | Name | Role | Primary Subcategories | Key Certifications | NICE Work Role IDs |
|---|---|---|---|---|---|
| 1 | Harrison Cook | Director of Security Engineering and Offensive Operations | Penetration Testing, HVA, Cyber Hunt | *[Insert certifications]* | AN-ASA-001, PR-CDA-001, OV-MGT-001 |
| 2 | *[Name]* | *[Role]* | RVA, HVA | *[Certifications]* | *[Work Role IDs]* |
| 3 | *[Name]* | *[Role]* | Incident Response, Cyber Hunt | *[Certifications]* | *[Work Role IDs]* |
| 4 | *[Name]* | *[Role]* | Penetration Testing, RVA | *[Certifications]* | *[Work Role IDs]* |
| 5 | *[Name]* | *[Role]* | Incident Handling, SOC Operations | *[Certifications]* | *[Work Role IDs]* |

> **Note:** Key personnel slots 2-5 are placeholder entries to be filled with specific AceofCloud staff members before submission. GSA requires up to 5 key personnel who are company employees — consultants are not permitted to participate in the oral evaluation.



---

## 11. NICE Framework Work Role Alignment

The NICE Cybersecurity Workforce Framework (NIST SP 800-181 Rev 1) defines work roles that GSA uses to evaluate whether an offeror's personnel possess the knowledge, skills, and abilities required for each HACS subcategory. The following table maps AceofCloud's service delivery roles to the applicable NICE work role IDs.

| HACS Subcategory | NICE Work Role(s) | Work Role ID(s) | Description |
|---|---|---|---|
| High Value Asset Assessments | Security Assessor, Security Architect | AN-ASA-001, SP-ARC-002 | Conducts SAR/SSE assessments, evaluates security architecture against frameworks |
| Risk and Vulnerability Assessments | Vulnerability Assessment Analyst | AN-ASA-001 | Performs network mapping, vulnerability scanning, and risk analysis |
| Penetration Testing | Exploitation Analyst, Red Team Operator | AN-EXP-001, CO-OPS-001 | Conducts authorized penetration testing using adversary TTPs |
| Cyber Hunt | Cyber Defense Analyst, Threat Analyst | PR-CDA-001, AN-TWA-001 | Proactive threat hunting using hypothesis-driven methodologies |
| Incident Response | Incident Responder, Forensics Analyst | PR-CIR-001, IN-FOR-001 | Incident detection, containment, eradication, recovery, and forensic analysis |
| Incident Handling | Cyber Defense Infrastructure Support | PR-INF-001 | SIEM management, SOC operations, alert triage and escalation |

### 11.1 Personnel Certification Requirements

AceofCloud maintains a certification matrix that ensures each engagement team includes personnel with certifications relevant to the subcategory being delivered. The following certifications are represented across the team:

| Certification Category | Certifications Held |
|---|---|
| **Offensive Security** | OSCP, OSCE, OSWE, GPEN, GXPN, CEH, LPT |
| **Incident Response / Forensics** | GCIH, GCFA, GNFA, EnCE |
| **Compliance / Assessment** | CCA, CCP, CISA, CISSP, CAP |
| **Cloud Security** | CCSP, AWS Security Specialty, Azure Security Engineer |
| **Threat Intelligence** | GCTI, CTIA |

> **Note:** Specific certifications held by each key personnel member will be documented in the Key Personnel Roster (Section 10) before submission. The above table represents the certification coverage across the AceofCloud team.

---

## 12. Pricing Structure and Labor Categories

### 12.1 Contract Types Supported

AceofCloud supports all three contract types permitted under SIN 54151HACS:

| Contract Type | Applicability |
|---|---|
| **Firm Fixed Price (FFP)** | Point-in-time assessments with well-defined scope: HVA assessments, RVA, penetration testing |
| **Time and Materials (T&M)** | Incident response, cyber hunt, and engagements where scope may evolve based on findings |
| **Cost Plus Fixed Fee (CPFF)** | Large-scale or multi-phase engagements requiring sustained support |

### 12.2 Labor Categories

| Labor Category | Description | GSA Education/Experience Minimum |
|---|---|---|
| **Senior Cybersecurity Consultant** | Engagement lead for HVA, RVA, and penetration testing. Responsible for scoping, methodology selection, quality assurance, and client communication. | Bachelor's + 10 years, or Master's + 8 years |
| **Cybersecurity Consultant** | Technical execution of assessment activities including scanning, testing, analysis, and reporting. | Bachelor's + 5 years, or Master's + 3 years |
| **Junior Cybersecurity Consultant** | Supporting role for data collection, scan execution, report drafting, and remediation validation. | Bachelor's + 2 years |
| **Incident Response Lead** | Engagement lead for incident response and cyber hunt operations. Responsible for triage, investigation strategy, and client coordination. | Bachelor's + 10 years, or Master's + 8 years |
| **SOC Analyst** | Tier 1/2 security event monitoring, alert triage, and escalation for incident handling engagements. | Bachelor's + 3 years |
| **Subject Matter Expert** | Specialized expertise in specific domains (ICS/OT, cloud, Active Directory, mobile, IoT). Engaged as needed for complex engagements. | Bachelor's + 12 years, or Master's + 10 years |

### 12.3 Pricing Notes

> **Placeholder:** Specific GSA pricing (hourly rates by labor category, fixed-price engagement tiers) will be developed during the pricing proposal phase. Rates will be competitive with existing HACS contract holders and will reflect the efficiency gains provided by the AC3 platform — automated scanning, integrated reporting, and platform-assisted analysis reduce the labor hours required for equivalent assessment scope compared to manual-only methodologies.

---

## 13. Compliance and Certification Matrix

The following matrix maps AC3's compliance capabilities to the regulatory frameworks most commonly referenced in federal cybersecurity task orders.

| Framework / Standard | AC3 Support | Description |
|---|---|---|
| **NIST SP 800-53 Rev 5** | Automated control mapping | AC3 maps findings against all 1,189 controls across 20 control families |
| **NIST SP 800-171 Rev 2** | Assessment and gap analysis | CUI protection assessment aligned with CMMC requirements |
| **NIST Cybersecurity Framework (CSF) 2.0** | Function-level mapping | Findings mapped to Identify, Protect, Detect, Respond, Recover, Govern functions |
| **CMMC 2.0 (Levels 1-3)** | Full assessment capability | AceofCloud is an authorized C3PAO — AC3 supports the assessment workflow |
| **FIPS 199 / SP 800-60** | Impact categorization | Hybrid scoring engine integrates FIPS 199 impact levels into risk calculations |
| **FIPS 140-3** | Cryptographic compliance | All AC3 cryptographic operations use FIPS 140-3 validated modules |
| **CISA BOD 22-01 (KEV)** | Automated KEV correlation | Vulnerability findings automatically cross-referenced against CISA Known Exploited Vulnerabilities catalog |
| **CISA BOD 23-01 (Asset Visibility)** | Asset discovery and inventory | AC3's reconnaissance modules support continuous asset discovery requirements |
| **FedRAMP** | Advisory and assessment support | AceofCloud provides FedRAMP advisory services; AC3 supports FedRAMP assessment workflows |
| **DISA STIGs** | Configuration compliance | Automated STIG compliance checking for Windows, Linux, network devices |
| **CIS Benchmarks** | Configuration compliance | Automated CIS Benchmark assessment for operating systems and applications |
| **MITRE ATT&CK** | TTP mapping | All penetration testing and hunt findings mapped to ATT&CK techniques |
| **STIX 2.1 / TAXII** | Threat intelligence exchange | AC3 exports findings in STIX format and supports TAXII feed integration |
| **OSCAL** | Machine-readable compliance | AC3 exports assessment results in OSCAL JSON format for automated GRC integration |

---

## Appendix A: AC3 Module-to-Subcategory Cross-Reference

The following table maps AC3's major module groups to the HACS subcategories they support, demonstrating the platform's breadth of coverage across all six service areas.

| AC3 Module Group | Modules | HVA | RVA | PenTest | Hunt | IR | IHEM |
|---|---|---|---|---|---|---|---|
| **Reconnaissance & Discovery** | 64 passive connectors, DNS/Cert/WHOIS, Shodan/Censys integration | Yes | Yes | Yes | Yes | — | — |
| **Scanning & Assessment** | ScanForge, Nmap orchestrator, Nuclei engine, ZAP/Burp integration | Yes | Yes | Yes | — | — | — |
| **Exploitation Operations** | Exploit catalog, attack path analyzer, C2 framework, evasion engine | — | — | Yes | — | — | — |
| **Threat Intelligence** | TI Hub, 12+ feed integrations, IOC matcher, TTP correlator | Yes | — | Yes | Yes | Yes | Yes |
| **Risk & Scoring** | Hybrid scoring engine, CVSS v4.0 parser, CARVER+SHOCK, temporal decay | Yes | Yes | Yes | — | — | — |
| **Compliance & Reporting** | NIST 800-53 mapper, OSCAL exporter, STIX exporter, report generator | Yes | Yes | Yes | Yes | Yes | Yes |
| **SIEM & SOAR** | SIEM integration, SOAR playbooks, detection engineering, log correlation | — | — | — | Yes | Yes | Yes |
| **Forensics & Evidence** | Evidence integrity chain, HMAC signing, forensic analysis module | — | — | Yes | — | Yes | — |
| **Phishing & Social Engineering** | GoPhish integration, campaign manager, pretext engine | — | Yes | Yes | — | — | — |
| **Continuous Monitoring** | External attack surface monitoring, dark web monitoring, CVE alerting | — | — | — | Yes | — | Yes |
| **Safety Architecture** | 7-layer safety engine, ROE enforcement, two-person integrity, kill switch | Yes | Yes | Yes | Yes | Yes | Yes |
| **Engagement Management** | Engagement orchestrator, ROE manager, scheduling, client portal | Yes | Yes | Yes | Yes | Yes | Yes |

---

## Document Control

| Field | Value |
|---|---|
| **Document Title** | AC3 HACS SIN Response Template |
| **Version** | 1.0 |
| **Date** | April 2026 |
| **Author** | AceofCloud — Security Engineering and Offensive Operations Division |
| **Classification** | UNCLASSIFIED — FOUO |
| **Status** | DRAFT — Pre-Submission Template |

> **Usage Note:** This document is a pre-filled template designed to accelerate the HACS SIN offer or modification submission process. Sections marked with *[placeholder]* entries require completion with specific AceofCloud personnel, pricing, and past performance data before submission. The technical content (methodology, capabilities, platform descriptions) is ready for use as-is and reflects the current state of the AC3 platform as of April 2026.

---

## References

1. GSA, "Highly Adaptive Cybersecurity Services (HACS)," https://www.gsa.gov/technology/it-contract-vehicles-and-purchasing-programs/multiple-award-schedule-it/highly-adaptive-cybersecurity-services
2. GSA, "HACS Buyer's Guide," January 2025
3. NIST, "SP 800-181 Rev 1: NICE Cybersecurity Workforce Framework," November 2020
4. NIST, "SP 800-61 Rev 2: Computer Security Incident Handling Guide," August 2012
5. NIST, "SP 800-53 Rev 5: Security and Privacy Controls," September 2020
6. NIST, "SP 800-60 Vol 1 Rev 1: Guide for Mapping Types of Information and Information Systems to Security Categories," August 2008
7. CISA, "High Value Asset (HVA) Initiative," https://www.cisa.gov/high-value-assets
8. MITRE, "ATT&CK Framework," https://attack.mitre.org/
9. FIRST, "Common Vulnerability Scoring System v4.0," https://www.first.org/cvss/v4.0/specification-document
10. FIRST, "Exploit Prediction Scoring System (EPSS)," https://www.first.org/epss/
