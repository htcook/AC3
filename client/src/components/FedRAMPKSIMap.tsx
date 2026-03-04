import { useState } from "react";
import {
  Shield, Building2, ChevronRight, CheckCircle2,
  Layers, Lock, Eye, Server, Users, BookOpen, RefreshCw,
  FileText, Radar, Target, Zap, Brain, ShieldCheck, BarChart3,
  Fingerprint, Clock, ArrowRight, AlertTriangle, Info,
  Package, Code2, ScrollText, KeyRound
} from "lucide-react";

// ─── KSI Theme Data ─────────────────────────────────────────────────

type KSIEntry = {
  id: string;
  name: string;
  status: "direct" | "supporting" | "planned";
  aceModules: string[];
  cspDetail: string;
  agencyDetail: string;
};

type KSITheme = {
  id: string;
  name: string;
  abbrev: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  totalKSIs: number;
  directCoverage: number;
  supportingCoverage: number;
  description: string;
  cspValue: string;
  agencyValue: string;
  ksis: KSIEntry[];
};

// ─── Honest KSI Data — Grounded in real platform capabilities ──────
// Coverage levels:
//   DIRECT = platform actively performs the function and generates evidence
//   SUPPORTING = platform provides telemetry/testing that validates the control
//   PLANNED = module exists but relies on mock data or is not yet wired

const KSI_THEMES: KSITheme[] = [
  {
    id: "afr",
    name: "Authorization by FedRAMP",
    abbrev: "AFR",
    icon: Shield,
    color: "text-indigo-400",
    totalKSIs: 8,
    directCoverage: 3,
    supportingCoverage: 4,
    description: "FedRAMP authorization lifecycle — compliance monitoring, assessment scope, vulnerability assessment, security configuration guides, and data sharing.",
    cspValue: "ACE C3 provides continuous compliance monitoring through the KSI Dashboard with automated validation scheduling, OSCAL-formatted evidence export for machine-readable data sharing, and full penetration testing across all 6 mandatory attack vectors to satisfy periodic vulnerability assessment requirements.",
    agencyValue: "Agencies can review CSP-submitted OSCAL exports, KSI evidence chains, and assessment reports to verify continuous compliance posture. Periodic vulnerability assessment results and NIST control mapping evidence are available for passive monitoring without initiating any active testing.",
    ksis: [
      {
        id: "KSI-AFR-ADS", name: "Authorization Data Sharing", status: "supporting",
        aceModules: ["OSCAL Export", "STIX Export", "Evidence Chain"],
        cspDetail: "OSCAL Export produces machine-readable compliance evidence packages. STIX Export provides threat intelligence in standardized format. Evidence Chain maintains tamper-resistant audit trails with SHA-256 integrity hashing.",
        agencyDetail: "Review CSP-submitted OSCAL packages and STIX feeds for machine-readable compliance and threat data. Evidence Chain integrity hashes allow independent verification of evidence authenticity."
      },
      {
        id: "KSI-AFR-CCM", name: "Continuous Compliance Monitoring", status: "direct",
        aceModules: ["KSI Dashboard", "Validation Scheduler", "Auto-Collectors"],
        cspDetail: "KSI Dashboard tracks 70 Key Security Indicators with NIST SP 800-53 control mappings. Validation Scheduler automates assessment cadence at configurable frequencies (3-day, 7-day, monthly). Auto-Collectors gather evidence from live API integrations.",
        agencyDetail: "Monitor CSP compliance posture through KSI Dashboard evidence showing validation frequency, coverage percentages, and control mapping completeness. Track assessment cadence compliance passively."
      },
      {
        id: "KSI-AFR-FSI", name: "FedRAMP Security Inbox", status: "planned",
        aceModules: ["Notification System"],
        cspDetail: "Platform notification system exists but a dedicated FedRAMP communication channel for agency-CSP correspondence is planned for future development.",
        agencyDetail: "Planned capability for structured FedRAMP communication between agencies and CSPs through the platform."
      },
      {
        id: "KSI-AFR-ICP", name: "Initial Compliance Posture", status: "supporting",
        aceModules: ["KSI Evidence Chain", "NIST Control Mappings"],
        cspDetail: "KSI Evidence Chain documents initial security posture with 142 NIST SP 800-53 control mappings across all 70 KSIs. Evidence is stored with integrity verification for audit readiness.",
        agencyDetail: "Review CSP-submitted initial compliance posture documentation through KSI Evidence Chain exports with NIST control mapping traceability."
      },
      {
        id: "KSI-AFR-MAS", name: "Minimum Assessment Scope", status: "direct",
        aceModules: ["RoE Builder", "Engagement Pipeline", "Scope Guard"],
        cspDetail: "RoE Builder defines and enforces assessment scope with version-controlled rules of engagement. Engagement Pipeline orchestrates multi-phase assessments (passive → active → exploitation → reporting). Scope Guard prevents out-of-scope testing.",
        agencyDetail: "Review CSP-submitted RoE documentation and scope definitions. Engagement Pipeline evidence shows assessment coverage across all defined scope boundaries."
      },
      {
        id: "KSI-AFR-PVA", name: "Periodic Vulnerability Assessment", status: "direct",
        aceModules: ["ZAP DAST", "Nuclei Scanner", "Vuln Scanner Import", "Engagement Pipeline"],
        cspDetail: "ZAP DAST performs active web application testing. Nuclei Scanner executes template-based vulnerability scanning on remote scan servers. Vuln Scanner Import normalizes Nessus/Qualys/Burp reports. Engagement Pipeline orchestrates periodic assessment cycles.",
        agencyDetail: "Review CSP-submitted vulnerability assessment results from DAST, Nuclei, and imported scanner reports. Track assessment frequency and remediation SLA compliance passively."
      },
      {
        id: "KSI-AFR-SCG", name: "Secure Configuration Guide", status: "supporting",
        aceModules: ["Config Baseline Engine", "SCAP Compliance Scanner"],
        cspDetail: "Config Baseline Engine tracks security configurations against approved baselines. SCAP Compliance Scanner checks CIS benchmarks. These inform SCG development but don't auto-generate configuration guides.",
        agencyDetail: "Review CSP-submitted configuration baseline reports and CIS benchmark compliance data to verify alignment with secure configuration standards."
      },
      {
        id: "KSI-AFR-SCN", name: "Significant Change Notification", status: "supporting",
        aceModules: ["Audit Log", "Evidence Chain", "Config Baseline Engine"],
        cspDetail: "Audit Log records all security-relevant changes with timestamps and user attribution. Config Baseline Engine detects drift from approved configurations. Evidence Chain provides tamper-resistant change records.",
        agencyDetail: "Review CSP-submitted Audit Log exports and Config Baseline drift reports to identify significant changes. Evidence Chain records provide tamper-resistant proof of change management."
      },
    ],
  },
  {
    id: "cmt",
    name: "Change Management",
    abbrev: "CMT",
    icon: RefreshCw,
    color: "text-amber-400",
    totalKSIs: 5,
    directCoverage: 2,
    supportingCoverage: 3,
    description: "Log and monitor modifications, validate changes through deployment, review change management procedures, and governance.",
    cspValue: "Audit Log records all security-relevant changes with timestamps and user attribution. Validation Scheduler triggers post-change security validation. Agentless BAS tests detection coverage after changes to verify security controls still function.",
    agencyValue: "Agencies passively review CSP-submitted Audit Log exports and Validation Scheduler evidence showing security controls are re-validated after changes. Config Baseline drift reports demonstrate change management practices.",
    ksis: [
      {
        id: "KSI-CMT-LMC", name: "Log and Monitor Modifications", status: "direct",
        aceModules: ["Audit Log", "Evidence Chain"],
        cspDetail: "Audit Log records all security-relevant changes with timestamps, user attribution, and change details. Evidence Chain provides tamper-resistant storage of modification records with SHA-256 integrity hashing.",
        agencyDetail: "Review CSP-submitted Audit Log exports showing complete modification history with timestamps and attribution. Evidence Chain integrity records provide tamper-resistant proof of change logging."
      },
      {
        id: "KSI-CMT-RMV", name: "Redeployment of Version-Controlled Resources", status: "supporting",
        aceModules: ["Config Baseline Engine", "Audit Log"],
        cspDetail: "Config Baseline Engine tracks deployment configurations and detects drift from approved baselines. Audit Log records deployment events. The platform does not manage IaC directly.",
        agencyDetail: "Review CSP-submitted Config Baseline reports showing deployment configuration compliance and drift history."
      },
      {
        id: "KSI-CMT-RVP", name: "Review Change Management Procedures", status: "supporting",
        aceModules: ["Evidence Chain", "RoE Builder"],
        cspDetail: "Evidence Chain stores procedure documentation with version history. RoE Builder maintains version-controlled rules of engagement. LLM analysis can review procedures for completeness.",
        agencyDetail: "Review CSP-submitted change management procedure documentation through Evidence Chain exports with version history tracking."
      },
      {
        id: "KSI-CMT-VTD", name: "Validate Changes Throughout Deployment", status: "direct",
        aceModules: ["Validation Scheduler", "Agentless BAS", "ATT&CK Validation Tests"],
        cspDetail: "Validation Scheduler triggers post-deployment security validation at configurable cadences. Agentless BAS tests detection coverage without deploying agents. ATT&CK Validation Tests confirm security controls function after deployment.",
        agencyDetail: "Review CSP-submitted Validation Scheduler evidence showing security controls are re-validated after deployments. Agentless BAS results before and after changes demonstrate deployment validation practices."
      },
      {
        id: "KSI-CMT-CMG", name: "Change Management Governance", status: "supporting",
        aceModules: ["RoE Builder", "Audit Log", "Scope Guard"],
        cspDetail: "RoE Builder maintains version-controlled governance documentation. Audit Log provides complete change audit trail. Scope Guard enforces operational boundaries. The platform supports governance documentation but doesn't enforce CM policy.",
        agencyDetail: "Review CSP-submitted governance documentation, audit trails, and scope enforcement evidence to verify change management governance practices."
      },
    ],
  },
  {
    id: "cna",
    name: "Cloud Native Architecture",
    abbrev: "CNA",
    icon: Server,
    color: "text-cyan-400",
    totalKSIs: 10,
    directCoverage: 3,
    supportingCoverage: 5,
    description: "Minimal attack surface, secure-by-design architecture, encryption enforcement, network controls, cloud infrastructure hardening, and availability.",
    cspValue: "Domain Intel and service fingerprinting continuously discover the external attack surface. DigitalOcean infrastructure auditing validates cloud configurations. ZAP DAST validates TLS/encryption. NGFW validation tests network segmentation and firewall rules.",
    agencyValue: "Agencies passively monitor CSP external attack surface through ingested Domain Intel reports and independent passive enumeration. CSP-submitted DAST, NGFW validation, and cloud infrastructure audit results are available for review.",
    ksis: [
      {
        id: "KSI-CNA-DFP", name: "Define Functionality and Privileges", status: "direct",
        aceModules: ["Cloud Attack Paths", "AD Attack Simulation"],
        cspDetail: "Cloud Attack Paths maps permission chains across cloud environments to identify over-privileged roles and unnecessary functionality. AD Attack Simulation tests whether privilege boundaries are enforced by attempting escalation.",
        agencyDetail: "Review CSP-submitted Cloud Attack Paths reports revealing whether environments follow least-functionality principles. AD Attack Simulation results show whether privilege boundaries contain lateral movement."
      },
      {
        id: "KSI-CNA-EDE", name: "Encrypt Data at Rest and In Transit (FIPS)", status: "supporting",
        aceModules: ["ZAP DAST", "Email Security Analyzer"],
        cspDetail: "ZAP DAST validates TLS configurations, cipher suites, and certificate validity across all endpoints. Email Security Analyzer tests SPF, DKIM, and DMARC configurations. The platform tests encryption but doesn't implement it.",
        agencyDetail: "Review CSP-submitted DAST TLS test results showing cipher suite strength, certificate validity, and protocol versions. Email Security Analyzer reports verify email authentication compliance."
      },
      {
        id: "KSI-CNA-MAS", name: "Minimal Attack Surface", status: "direct",
        aceModules: ["Domain Intel", "Service Fingerprinting", "Shodan", "Censys"],
        cspDetail: "Domain Intel discovers all external-facing assets, subdomains, and services using Shodan, Censys, SecurityTrails, and URLScan. Service Fingerprinting identifies exposed services, technologies, and versions across the attack surface.",
        agencyDetail: "Review CSP-submitted Domain Intel reports and independently verify external attack surface through passive discovery — subdomains, open ports, exposed services. Track attack surface size over time."
      },
      {
        id: "KSI-CNA-OFA", name: "Optimize for High Availability", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track HA configurations. Active availability testing and failover validation is planned for future development.",
        agencyDetail: "Planned capability to passively review CSP-submitted high availability configuration reports and failover test results."
      },
      {
        id: "KSI-CNA-RNT", name: "Restrict Network Traffic", status: "supporting",
        aceModules: ["DigitalOcean Firewall Validation", "NGFW Validation"],
        cspDetail: "DigitalOcean Firewall Validation audits cloud firewall rules and port exposure. NGFW Validation tests next-generation firewall rules and network boundaries to verify traffic restriction effectiveness.",
        agencyDetail: "Review CSP-submitted firewall validation results showing whether network traffic restrictions are properly configured and enforced."
      },
      {
        id: "KSI-CNA-RVP", name: "Review DoS Protection Effectiveness", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track DoS protection configurations (WAF rules, rate limiting). Active DoS testing is out of scope for offensive security platforms.",
        agencyDetail: "Planned capability to passively review CSP-submitted DoS protection configuration reports."
      },
      {
        id: "KSI-CNA-SBD", name: "Secure By Design Architecture", status: "supporting",
        aceModules: ["Cloud Attack Paths", "SCAP Compliance Scanner"],
        cspDetail: "Cloud Attack Paths identifies architectural security weaknesses through permission chain analysis. SCAP Compliance Scanner checks CIS benchmarks for infrastructure security posture.",
        agencyDetail: "Review CSP-submitted Cloud Attack Paths analysis and SCAP compliance reports to assess architectural security posture."
      },
      {
        id: "KSI-CNA-ULN", name: "Use Logical Networking Controls", status: "supporting",
        aceModules: ["NGFW Validation", "DigitalOcean Firewall Auditing"],
        cspDetail: "NGFW Validation tests firewall rules and network segmentation. DigitalOcean Firewall Auditing validates cloud-native networking controls and security group configurations.",
        agencyDetail: "Review CSP-submitted NGFW validation and firewall audit results to verify logical networking controls are properly configured."
      },
      {
        id: "KSI-CNA-HCI", name: "Harden Cloud Infrastructure", status: "direct",
        aceModules: ["DigitalOcean Infrastructure Audit", "Cloud Misconfiguration Detection"],
        cspDetail: "DigitalOcean Infrastructure Audit checks droplets, firewalls, load balancers, and databases for misconfigurations. Cloud Misconfiguration Detection via live KSI collectors identifies hardening gaps.",
        agencyDetail: "Review CSP-submitted cloud infrastructure audit results showing hardening compliance across compute, network, and database resources."
      },
      {
        id: "KSI-CNA-NSD", name: "Network Segmentation & Defense", status: "supporting",
        aceModules: ["NGFW Validation", "Service Fingerprinting"],
        cspDetail: "NGFW Validation tests network segmentation boundaries. Service Fingerprinting identifies services that may cross segmentation boundaries. The platform tests segmentation but doesn't implement it.",
        agencyDetail: "Review CSP-submitted NGFW validation results and service discovery data to verify network segmentation effectiveness."
      },
    ],
  },
  {
    id: "ced",
    name: "Cybersecurity Education",
    abbrev: "CED",
    icon: BookOpen,
    color: "text-teal-400",
    totalKSIs: 4,
    directCoverage: 1,
    supportingCoverage: 2,
    description: "Security awareness training effectiveness, developer training, incident response training, and high-risk role training.",
    cspValue: "Phishing Ops runs realistic social engineering campaigns with 17 exploit techniques to measure security awareness. Purple Team exercises provide hands-on incident response training. AD Attack Simulation targets privileged users for high-risk role training.",
    agencyValue: "Agencies passively review CSP-submitted phishing simulation results showing employee click rates and improvement trends. Purple Team exercise reports demonstrate IR training effectiveness.",
    ksis: [
      {
        id: "KSI-CED-RGT", name: "General Employee Training Effectiveness", status: "direct",
        aceModules: ["Phishing Ops", "Campaign Wizard", "Template Generator"],
        cspDetail: "Phishing Ops executes realistic phishing campaigns with 17 exploit techniques including AiTM, BITB, device code phishing, and HTML smuggling. Campaign Wizard configures targeted awareness exercises. Results measure click rates, credential capture rates, and improvement trends.",
        agencyDetail: "Review CSP-submitted phishing simulation results showing click rates, credential capture rates, and reporting rates. Track improvement trends over successive campaigns to verify training effectiveness."
      },
      {
        id: "KSI-CED-RRT", name: "IR/DR Staff Training Effectiveness", status: "supporting",
        aceModules: ["Red Team Ops", "Purple Team", "SIEM Feedback Loop"],
        cspDetail: "Red Team Ops provides realistic attack scenarios for IR team training. Purple Team exercises enable collaborative attack-defense training. SIEM Feedback Loop validates whether IR procedures detect real attacks during exercises.",
        agencyDetail: "Review CSP-submitted Purple Team exercise reports showing IR team performance — detection times, containment actions, and communication effectiveness during simulated incidents."
      },
      {
        id: "KSI-CED-RST", name: "High-Risk Role Training Effectiveness", status: "supporting",
        aceModules: ["AD Attack Simulation", "Phishing Ops"],
        cspDetail: "AD Attack Simulation targets privileged accounts with techniques like Kerberoasting and Pass-the-Hash. Phishing Ops can target high-risk roles specifically with tailored social engineering campaigns.",
        agencyDetail: "Review CSP-submitted privileged user testing results and targeted phishing campaign reports to assess high-risk role security awareness."
      },
      {
        id: "KSI-CED-DET", name: "Developer/Engineering Training Effectiveness", status: "planned",
        aceModules: ["ZAP DAST"],
        cspDetail: "DAST findings can inform developer security training priorities by identifying common vulnerability classes. Dedicated developer training tracking is planned.",
        agencyDetail: "Planned capability to review CSP-submitted vulnerability trend analysis showing whether common vulnerability classes decrease over time."
      },
    ],
  },
  {
    id: "iam",
    name: "Identity & Access Management",
    abbrev: "IAM",
    icon: Fingerprint,
    color: "text-blue-400",
    totalKSIs: 8,
    directCoverage: 4,
    supportingCoverage: 4,
    description: "Phishing-resistant MFA, privileged access management, least privilege enforcement, account lifecycle, JIT authorization, and service authentication.",
    cspValue: "ACE C3 tests MFA resilience through real phishing campaigns with 17 MFA bypass techniques. AD Attack Simulation validates privileged access controls. Cloud Attack Paths identifies excessive permissions. Credential attack engine tests password policies.",
    agencyValue: "Agencies review CSP-submitted MFA bypass test results, AD Attack Simulation reports, and Cloud Attack Paths analysis to verify identity and access management controls. All review is passive.",
    ksis: [
      {
        id: "KSI-IAM-MFA", name: "Phishing-Resistant MFA Enforcement", status: "direct",
        aceModules: ["Phishing Ops", "Campaign Wizard"],
        cspDetail: "Phishing Ops executes real MFA bypass attacks including AiTM proxy, BITB, device code phishing, and HTML smuggling — 17 techniques total. Results prove whether MFA implementation resists actual attack techniques.",
        agencyDetail: "Review CSP-submitted MFA bypass test results showing which attack techniques succeeded or failed. Campaign reports include click rates, credential capture attempts, and MFA bypass success rates."
      },
      {
        id: "KSI-IAM-APM", name: "Authentication Policy Management", status: "direct",
        aceModules: ["Phishing Ops", "Credential Attack Engine"],
        cspDetail: "Phishing Ops tests MFA bypass and credential harvesting. Credential Attack Engine tests password policies, lockout thresholds, and authentication mechanisms. Results validate authentication policy effectiveness.",
        agencyDetail: "Review CSP-submitted authentication testing results showing password policy strength, lockout behavior, and MFA resilience."
      },
      {
        id: "KSI-IAM-ELP", name: "Enforce Least Privilege", status: "direct",
        aceModules: ["Cloud Attack Paths", "AD Attack Simulation", "Privilege Escalation Engine"],
        cspDetail: "Cloud Attack Paths maps permission chains to identify over-privileged roles. AD Attack Simulation tests privilege escalation paths. Privilege Escalation Engine automates discovery of escalation vectors.",
        agencyDetail: "Review CSP-submitted Cloud Attack Paths reports and privilege escalation test results to verify least privilege enforcement."
      },
      {
        id: "KSI-IAM-PRA", name: "Privileged Access Reviews & Auditing", status: "direct",
        aceModules: ["AD Domain Connector", "Cloud Attack Paths", "Audit Log"],
        cspDetail: "AD Domain Connector enumerates domain structure, group memberships, and privileged accounts. Cloud Attack Paths identifies excessive cloud permissions. Audit Log records all privileged access events.",
        agencyDetail: "Review CSP-submitted privileged access review reports showing account enumeration, group membership analysis, and permission chain mapping."
      },
      {
        id: "KSI-IAM-AAM", name: "Automated Account Lifecycle Management", status: "supporting",
        aceModules: ["AD Domain Connector", "Audit Log"],
        cspDetail: "AD Domain Connector enumerates accounts, group memberships, and last-login timestamps to identify stale or orphaned accounts. Audit Log tracks account provisioning events. The platform identifies lifecycle issues but doesn't manage accounts directly.",
        agencyDetail: "Review CSP-submitted AD Domain Connector reports showing stale accounts, group membership sprawl, and orphaned service accounts."
      },
      {
        id: "KSI-IAM-JIT", name: "Just-In-Time Authorization", status: "supporting",
        aceModules: ["Cloud Attack Paths"],
        cspDetail: "Cloud Attack Paths can identify persistent privileged access that should be JIT by mapping always-on admin permissions. The platform identifies JIT gaps but doesn't implement JIT controls.",
        agencyDetail: "Review CSP-submitted Cloud Attack Paths reports to identify persistent privileged access that should be converted to JIT."
      },
      {
        id: "KSI-IAM-SNU", name: "Secure Non-User Authentication", status: "supporting",
        aceModules: ["Service Fingerprinting", "API Security Testing"],
        cspDetail: "Service Fingerprinting identifies exposed service accounts and API endpoints. API Security Testing validates service-to-service authentication mechanisms. The platform tests but doesn't implement service authentication.",
        agencyDetail: "Review CSP-submitted service discovery and API security testing results to verify non-user authentication security."
      },
      {
        id: "KSI-IAM-SUS", name: "Suspend Suspicious Privileged Accounts", status: "supporting",
        aceModules: ["AD Attack Simulation", "Session Alerter"],
        cspDetail: "AD Attack Simulation identifies compromisable privileged accounts. Session Alerter detects suspicious activity patterns during red team exercises. The platform identifies suspicious accounts but doesn't suspend them.",
        agencyDetail: "Review CSP-submitted attack simulation results and session alert data to verify suspicious account detection and response capabilities."
      },
    ],
  },
  {
    id: "inr",
    name: "Incident Response",
    abbrev: "INR",
    icon: AlertTriangle,
    color: "text-red-400",
    totalKSIs: 7,
    directCoverage: 5,
    supportingCoverage: 2,
    description: "After-action reports, IR procedure review, incident pattern analysis, threat intelligence feeds, IOC management, and IR planning.",
    cspValue: "Report Generator produces post-engagement reports with MITRE heatmaps. Purple Team exercises test IR procedures. abuse.ch, Shodan, SecurityTrails, and DeHashed provide real threat intelligence feeds. IOC Feed manages indicators with automated enrichment.",
    agencyValue: "Agencies review CSP-submitted post-engagement reports, Purple Team exercise results, and threat intelligence integration evidence to verify incident response capabilities.",
    ksis: [
      {
        id: "KSI-INR-AAR", name: "After-Action Reports and Lessons Learned", status: "direct",
        aceModules: ["Report Generator", "Evidence Chain", "MITRE Heatmaps"],
        cspDetail: "Report Generator produces AI-powered post-engagement reports with findings, recommendations, and MITRE ATT&CK heatmaps. Evidence Chain links all findings to proof artifacts. Reports include executive summaries and technical details.",
        agencyDetail: "Review CSP-submitted post-engagement reports with embedded evidence links, MITRE ATT&CK coverage heatmaps, and remediation recommendations."
      },
      {
        id: "KSI-INR-RIR", name: "Review IR Procedures Effectiveness", status: "direct",
        aceModules: ["Purple Team", "SIEM Feedback Loop", "Detection Rule Generator"],
        cspDetail: "Purple Team exercises test whether IR procedures detect and respond to real attacks. SIEM Feedback Loop validates whether SIEM rules fire during red team exercises. Detection Rule Generator creates rules from executed TTPs to improve detection.",
        agencyDetail: "Review CSP-submitted Purple Team exercise results showing IR procedure effectiveness — detection rates, response times, and SIEM alert coverage."
      },
      {
        id: "KSI-INR-RPI", name: "Review Past Incidents for Patterns", status: "supporting",
        aceModules: ["Threat Intel Connectors", "Threat Actor Crawler", "Ransomware Intel"],
        cspDetail: "Threat Intel Connectors aggregate incident data from multiple sources. Threat Actor Crawler identifies relevant threat actor patterns. Ransomware Intel tracks ransomware group activity and TTPs.",
        agencyDetail: "Review CSP-submitted threat intelligence analysis showing incident pattern identification and threat actor tracking."
      },
      {
        id: "KSI-INR-IRP", name: "Incident Response Planning", status: "supporting",
        aceModules: ["Red Team Ops", "RoE Builder", "Emulation Playbooks"],
        cspDetail: "Red Team Ops provides realistic attack scenarios for IR planning. RoE Builder documents IR scope and rules of engagement. Emulation Playbooks define repeatable attack scenarios for IR exercises.",
        agencyDetail: "Review CSP-submitted Red Team exercise scope documentation and emulation playbook evidence to verify IR planning maturity."
      },
      {
        id: "KSI-INR-TIF", name: "Threat Intelligence Feeds", status: "direct",
        aceModules: ["abuse.ch (URLhaus/ThreatFox)", "Shodan", "SecurityTrails", "DeHashed"],
        cspDetail: "abuse.ch provides URLhaus malware URL feeds and ThreatFox IOC feeds. Shodan provides internet-wide scanning data. SecurityTrails provides DNS and domain intelligence. DeHashed provides credential breach data. All are real API integrations.",
        agencyDetail: "Review CSP-submitted threat intelligence feed integration evidence showing active consumption of URLhaus, ThreatFox, Shodan, SecurityTrails, and breach data feeds."
      },
      {
        id: "KSI-INR-TIU", name: "Threat Intelligence Utilization", status: "direct",
        aceModules: ["Threat Actor Matcher", "Threat Enrichment Engine", "IOC Feed"],
        cspDetail: "Threat Actor Matcher correlates discovered vulnerabilities with known threat actor TTPs. Threat Enrichment Engine adds context to raw indicators. IOC Feed integrates indicators into operational workflows.",
        agencyDetail: "Review CSP-submitted threat intelligence utilization evidence showing how threat data informs security operations and testing priorities."
      },
      {
        id: "KSI-INR-IOC", name: "Indicator of Compromise Management", status: "direct",
        aceModules: ["IOC Feed", "Darkweb Intel", "Threat Intel Ingest"],
        cspDetail: "IOC Feed manages indicators with automated enrichment from abuse.ch and other sources. Darkweb Intel monitors dark web sources for relevant IOCs. Threat Intel Ingest normalizes and stores indicators for operational use.",
        agencyDetail: "Review CSP-submitted IOC management evidence showing indicator collection, enrichment, and operational integration."
      },
    ],
  },
  {
    id: "mla",
    name: "Monitoring, Logging & Auditing",
    abbrev: "MLA",
    icon: Eye,
    color: "text-violet-400",
    totalKSIs: 6,
    directCoverage: 4,
    supportingCoverage: 2,
    description: "Centralized SIEM operation, event type catalogs, configuration evaluation, log access controls, log review, and alert engineering.",
    cspValue: "SIEM Connectors integrate with SIEM platforms to validate detection coverage. Detection Rule Generator auto-creates Sigma/YARA/Suricata rules from executed TTPs. SIEM Feedback Loop validates whether rules fire during red team exercises. SIEM Mutation Engine tests alert quality.",
    agencyValue: "Agencies review CSP-submitted SIEM detection coverage reports, detection rule output, and ATT&CK Coverage Matrix results showing monitoring effectiveness.",
    ksis: [
      {
        id: "KSI-MLA-OSM", name: "Operate SIEM for Centralized Logging", status: "direct",
        aceModules: ["SIEM Connectors", "SIEM Feedback Loop"],
        cspDetail: "SIEM Connectors integration tests connectivity and event forwarding to centralized SIEM platforms. SIEM Feedback Loop validates whether the SIEM actually processes and alerts on security events during red team exercises.",
        agencyDetail: "Review CSP-submitted SIEM Connector configuration and feedback loop results showing centralized logging is operational and detecting real attacks."
      },
      {
        id: "KSI-MLA-LET", name: "Log Event Types Catalog", status: "direct",
        aceModules: ["SIEM Connectors", "Detection Rule Generator"],
        cspDetail: "SIEM Connectors define event types for platform activities. Detection Rule Generator produces Sigma/YARA/Suricata rules covering specific event types from executed TTPs, creating a comprehensive event catalog.",
        agencyDetail: "Review CSP-submitted Detection Rule Generator output showing event type coverage and SIEM Connector event mappings."
      },
      {
        id: "KSI-MLA-EVC", name: "Evaluate and Test Configuration", status: "direct",
        aceModules: ["Config Baseline Engine", "SCAP Compliance Scanner"],
        cspDetail: "Config Baseline Engine defines and monitors security configuration baselines. SCAP Compliance Scanner checks CIS benchmarks for infrastructure security posture. Results identify configuration drift and non-compliance.",
        agencyDetail: "Review CSP-submitted configuration evaluation results showing baseline compliance rates, drift history, and CIS benchmark scores."
      },
      {
        id: "KSI-MLA-ALE", name: "Alert Engineering & Response", status: "direct",
        aceModules: ["Detection Rule Generator", "SIEM Mutation Engine", "Sigma Rule Engine"],
        cspDetail: "Detection Rule Generator creates Sigma/YARA/Suricata rules from executed TTPs. SIEM Mutation Engine tests alert quality by mutating attack patterns. Sigma Rule Engine validates and optimizes detection rules.",
        agencyDetail: "Review CSP-submitted detection rule output and alert quality testing results showing alert engineering maturity."
      },
      {
        id: "KSI-MLA-ALA", name: "Access Controls for Log Data", status: "supporting",
        aceModules: ["Evidence Chain", "Config Baseline Engine"],
        cspDetail: "Evidence Chain provides tamper-resistant log storage with SHA-256 integrity verification. Config Baseline Engine can track log access control configurations. The platform verifies log integrity but doesn't implement access controls.",
        agencyDetail: "Review CSP-submitted Evidence Chain integrity records and log access control configuration reports."
      },
      {
        id: "KSI-MLA-RVL", name: "Review and Audit Logs", status: "supporting",
        aceModules: ["ATT&CK Coverage Matrix", "SIEM Feedback Loop"],
        cspDetail: "ATT&CK Coverage Matrix measures detection coverage against MITRE techniques, revealing which logs are being reviewed effectively. SIEM Feedback Loop validates log review processes during exercises.",
        agencyDetail: "Review CSP-submitted ATT&CK Coverage Matrix showing detection percentages and SIEM Feedback Loop results demonstrating log review effectiveness."
      },
    ],
  },
  {
    id: "piy",
    name: "Policy & Inventory",
    abbrev: "PIY",
    icon: FileText,
    color: "text-emerald-400",
    totalKSIs: 5,
    directCoverage: 1,
    supportingCoverage: 3,
    description: "Real-time asset inventories, security investment review, SDLC security review, vulnerability disclosure programs, and executive support.",
    cspValue: "Domain Intel, service fingerprinting, and web crawler generate real-time asset inventories. Risk trending and scoring engine provide ROI metrics. Bug bounty intelligence integrates HackerOne program data.",
    agencyValue: "Agencies review CSP-submitted asset inventory data, risk trending reports, and vulnerability disclosure program evidence.",
    ksis: [
      {
        id: "KSI-PIY-GIV", name: "Generate Real-Time Inventories", status: "direct",
        aceModules: ["Domain Intel", "Service Fingerprinting", "Web Crawler"],
        cspDetail: "Domain Intel discovers all external-facing assets using Shodan, Censys, SecurityTrails, and URLScan. Service Fingerprinting identifies exposed services, technologies, and versions. Web Crawler maps application structure and content.",
        agencyDetail: "Review CSP-submitted asset inventory data and independently verify through passive discovery — subdomains, open ports, exposed services, technology stacks."
      },
      {
        id: "KSI-PIY-RIS", name: "Review Security Investment Effectiveness", status: "supporting",
        aceModules: ["Risk Trending", "Scoring Engine", "Temporal Decay"],
        cspDetail: "Risk Trending tracks historical risk trajectory. Scoring Engine (CARVER+Shock/CVSS) quantifies security posture. Temporal Decay models score degradation over time. These provide ROI metrics but don't evaluate investment decisions.",
        agencyDetail: "Review CSP-submitted risk trending data and scoring metrics to assess security investment effectiveness over time."
      },
      {
        id: "KSI-PIY-RSD", name: "Review SDLC Security (CISA Secure By Design)", status: "supporting",
        aceModules: ["ZAP DAST", "API Security Testing", "Nuclei Scanner"],
        cspDetail: "ZAP DAST and API Security Testing validate SDLC security outputs by testing deployed applications. Nuclei Scanner checks for known vulnerabilities. Results inform SDLC security but don't audit the SDLC process itself.",
        agencyDetail: "Review CSP-submitted DAST and API security testing results to assess whether SDLC produces secure outputs."
      },
      {
        id: "KSI-PIY-RVD", name: "Review Vulnerability Disclosure Program", status: "supporting",
        aceModules: ["Bug Bounty Intelligence (HackerOne)"],
        cspDetail: "Bug Bounty Intelligence integrates HackerOne API to provide vulnerability disclosure program data — program activity, submission trends, and resolution metrics.",
        agencyDetail: "Review CSP-submitted vulnerability disclosure program data showing program activity and resolution metrics."
      },
      {
        id: "KSI-PIY-RES", name: "Review Executive Support for Security", status: "planned",
        aceModules: [],
        cspDetail: "Organizational governance requirement — outside the scope of an offensive security platform. Executive support review requires organizational processes.",
        agencyDetail: "Organizational governance requirement that must be assessed through CSP organizational documentation, not through security testing tools."
      },
    ],
  },
  {
    id: "rpl",
    name: "Recovery Planning",
    abbrev: "RPL",
    icon: RefreshCw,
    color: "text-orange-400",
    totalKSIs: 4,
    directCoverage: 0,
    supportingCoverage: 1,
    description: "Recovery plan alignment, RTO/RPO objectives, recovery capability testing, and disaster recovery planning.",
    cspValue: "Config Baseline Engine can track recovery configurations against objectives. Dedicated recovery validation testing with automated failover exercises is planned for future development.",
    agencyValue: "Agencies can review CSP-submitted configuration reports showing recovery configuration compliance. Active recovery testing capabilities are planned.",
    ksis: [
      {
        id: "KSI-RPL-ARP", name: "Align Recovery Plans with Objectives", status: "supporting",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine tracks whether recovery configurations align with stated objectives. The platform can verify configuration alignment but doesn't create recovery plans.",
        agencyDetail: "Review CSP-submitted Config Baseline reports verifying recovery configurations align with stated objectives."
      },
      {
        id: "KSI-RPL-ABO", name: "Recovery Planning Alignment", status: "planned",
        aceModules: [],
        cspDetail: "No active recovery planning capability. Recovery planning is an organizational process outside the scope of an offensive security platform.",
        agencyDetail: "Recovery planning alignment must be assessed through CSP organizational documentation."
      },
      {
        id: "KSI-RPL-RRO", name: "Review RTO and RPO Objectives", status: "planned",
        aceModules: [],
        cspDetail: "No RTO/RPO measurement capability. Recovery time and point objectives require infrastructure-level testing outside the platform's scope.",
        agencyDetail: "RTO/RPO review must be assessed through CSP recovery test documentation and infrastructure monitoring."
      },
      {
        id: "KSI-RPL-TRC", name: "Test Recovery Capabilities", status: "planned",
        aceModules: [],
        cspDetail: "No automated failover or recovery testing capability. Recovery capability testing requires infrastructure-level access outside the platform's scope.",
        agencyDetail: "Recovery capability testing must be assessed through CSP failover test documentation and disaster recovery exercise results."
      },
    ],
  },
  {
    id: "svc",
    name: "Service Configuration",
    abbrev: "SVC",
    icon: Lock,
    color: "text-pink-400",
    totalKSIs: 9,
    directCoverage: 6,
    supportingCoverage: 2,
    description: "Attack surface management, vulnerability scanning, configuration management, endpoint security, remediation management, and service transparency.",
    cspValue: "Domain Intel + Shodan + Censys provide continuous attack surface management. ZAP DAST + Nuclei + vuln scanner imports produce real scanning results. NVD/KEV integration + remediation verification provide full vulnerability lifecycle management.",
    agencyValue: "Agencies review CSP-submitted attack surface discovery data, vulnerability scanning results, and remediation tracking evidence to verify service configuration security.",
    ksis: [
      {
        id: "KSI-SVC-ASM", name: "Attack Surface Management", status: "direct",
        aceModules: ["Domain Intel", "Shodan", "Censys", "Service Fingerprinting"],
        cspDetail: "Domain Intel discovers all external-facing assets using Shodan, Censys, SecurityTrails, and URLScan. Service Fingerprinting identifies exposed services and technologies. Continuous discovery tracks attack surface changes over time.",
        agencyDetail: "Review CSP-submitted attack surface discovery data and independently verify through passive enumeration."
      },
      {
        id: "KSI-SVC-VSR", name: "Vulnerability Scanning Results", status: "direct",
        aceModules: ["ZAP DAST", "Nuclei Scanner", "Vuln Scanner Import"],
        cspDetail: "ZAP DAST performs active web application vulnerability scanning. Nuclei Scanner executes template-based scanning on remote scan servers via SSH. Vuln Scanner Import normalizes Nessus/Qualys/Burp reports into a unified format.",
        agencyDetail: "Review CSP-submitted vulnerability scanning results from DAST, Nuclei, and imported scanner reports."
      },
      {
        id: "KSI-SVC-VRI", name: "Vulnerability Risk Identification", status: "direct",
        aceModules: ["Scoring Engine (CARVER+Shock/CVSS)", "Temporal Decay", "Risk Trending"],
        cspDetail: "Scoring Engine combines CARVER+Shock methodology with CVSS for vulnerability prioritization. Temporal Decay models score degradation over time. Risk Trending tracks historical risk trajectory for trend analysis.",
        agencyDetail: "Review CSP-submitted vulnerability risk scoring and trending data to verify risk identification and prioritization practices."
      },
      {
        id: "KSI-SVC-VCM", name: "Vulnerability/Configuration Management", status: "direct",
        aceModules: ["Vuln Feeds (NVD/KEV)", "Vuln Scanner Import", "Remediation Verification"],
        cspDetail: "Vuln Feeds aggregate NVD and CISA KEV data for continuous vulnerability intelligence. Vuln Scanner Import normalizes multi-vendor scan results. Remediation Verification tracks and validates fix implementation.",
        agencyDetail: "Review CSP-submitted vulnerability management evidence showing NVD/KEV integration, scan normalization, and remediation tracking."
      },
      {
        id: "KSI-SVC-VRM", name: "Vulnerability Remediation Management", status: "direct",
        aceModules: ["Remediation Verification", "Risk Trending"],
        cspDetail: "Remediation Verification tracks remediation progress and validates fixes through re-scanning. Risk Trending shows whether remediation efforts reduce overall risk over time.",
        agencyDetail: "Review CSP-submitted remediation tracking evidence showing fix implementation rates, re-scan results, and risk reduction trends."
      },
      {
        id: "KSI-SVC-EIS", name: "Endpoint/Infrastructure Security", status: "direct",
        aceModules: ["Nuclei Scanner", "Vuln Scanner", "DigitalOcean Infrastructure Audit"],
        cspDetail: "Nuclei Scanner tests endpoint security with template-based scanning. Vuln Scanner Import processes endpoint scan results. DigitalOcean Infrastructure Audit validates cloud endpoint configurations.",
        agencyDetail: "Review CSP-submitted endpoint scanning results and infrastructure audit data to verify endpoint security posture."
      },
      {
        id: "KSI-SVC-ACM", name: "Automated Configuration Management", status: "supporting",
        aceModules: ["Config Baseline Engine", "SCAP Compliance Scanner"],
        cspDetail: "Config Baseline Engine tracks configurations against approved baselines and detects drift. SCAP Compliance Scanner checks CIS benchmarks. The platform monitors configurations but doesn't manage them directly.",
        agencyDetail: "Review CSP-submitted configuration baseline compliance reports and CIS benchmark scores."
      },
      {
        id: "KSI-SVC-PRR", name: "Post-Change Residual Review", status: "supporting",
        aceModules: ["Validation Scheduler"],
        cspDetail: "Validation Scheduler can trigger post-change re-validation to identify residual risks after changes. The platform tests for residual issues but doesn't manage the change process.",
        agencyDetail: "Review CSP-submitted post-change validation results showing whether security controls function correctly after changes."
      },
      {
        id: "KSI-SVC-SNT", name: "Service Notification/Transparency", status: "planned",
        aceModules: [],
        cspDetail: "No dedicated service notification capability. Service transparency requires organizational communication processes outside the platform's scope.",
        agencyDetail: "Service notification and transparency must be assessed through CSP organizational communication documentation."
      },
    ],
  },
  {
    id: "scr",
    name: "Supply Chain Risk",
    abbrev: "SCR",
    icon: Package,
    color: "text-lime-400",
    totalKSIs: 5,
    directCoverage: 4,
    supportingCoverage: 1,
    description: "Penetration testing, APT simulation, security awareness testing, third-party vulnerability monitoring, and supply chain risk mitigation.",
    cspValue: "Full penetration testing pipeline across all 6 FedRAMP attack vectors. Caldera C2 + MITRE ATT&CK technique execution for APT simulation. Phishing Ops for security awareness testing. NVD/KEV integration for third-party vulnerability monitoring.",
    agencyValue: "Agencies review CSP-submitted penetration test reports, APT simulation results, phishing campaign data, and third-party vulnerability monitoring evidence.",
    ksis: [
      {
        id: "KSI-SCR-PEN", name: "Penetration Testing", status: "direct",
        aceModules: ["Engagement Pipeline", "Exploit Arsenal", "ZAP DAST", "Nuclei Scanner"],
        cspDetail: "Engagement Pipeline orchestrates multi-phase penetration tests (recon → vuln assessment → exploitation → reporting). Exploit Arsenal provides 16,000+ Metasploit modules. ZAP DAST and Nuclei Scanner perform automated vulnerability discovery.",
        agencyDetail: "Review CSP-submitted penetration test reports with evidence artifacts, MITRE ATT&CK heatmaps, and remediation recommendations."
      },
      {
        id: "KSI-SCR-APT", name: "Advanced Persistent Threat Simulation", status: "direct",
        aceModules: ["Caldera C2", "Emulation Playbooks", "Threat Actor Matcher"],
        cspDetail: "Caldera C2 provides full adversary emulation with MITRE ATT&CK technique execution. Emulation Playbooks define repeatable APT scenarios. Threat Actor Matcher correlates findings with known threat actor TTPs.",
        agencyDetail: "Review CSP-submitted APT simulation results showing MITRE ATT&CK technique coverage, detection rates, and threat actor TTP correlation."
      },
      {
        id: "KSI-SCR-SAT", name: "Security Awareness Testing", status: "direct",
        aceModules: ["Phishing Ops", "Campaign Wizard", "GoPhish"],
        cspDetail: "Phishing Ops executes realistic social engineering campaigns via GoPhish integration. Campaign Wizard configures multi-step campaigns. Results measure click rates, credential capture, and improvement trends.",
        agencyDetail: "Review CSP-submitted phishing campaign results showing employee security awareness metrics and improvement trends."
      },
      {
        id: "KSI-SCR-MON", name: "Monitor Third-Party Software Vulnerabilities", status: "direct",
        aceModules: ["Vuln Feeds (NVD/KEV)", "Container Registry Scanner"],
        cspDetail: "Vuln Feeds aggregate NVD and CISA KEV data for continuous third-party vulnerability monitoring. Container Registry Scanner checks container images for known vulnerabilities in dependencies.",
        agencyDetail: "Review CSP-submitted third-party vulnerability monitoring evidence showing NVD/KEV integration and container image scanning results."
      },
      {
        id: "KSI-SCR-MIT", name: "Mitigate Supply Chain Risks", status: "supporting",
        aceModules: ["Container Registry Scanner", "Nuclei Scanner"],
        cspDetail: "Container Registry Scanner identifies vulnerable dependencies in container images. Nuclei Scanner tests for known supply chain vulnerabilities. The platform identifies risks but doesn't implement supply chain controls.",
        agencyDetail: "Review CSP-submitted container scanning and dependency analysis results to verify supply chain risk identification."
      },
    ],
  },
  {
    id: "sde",
    name: "Secure Development",
    abbrev: "SDE",
    icon: Code2,
    color: "text-sky-400",
    totalKSIs: 2,
    directCoverage: 1,
    supportingCoverage: 1,
    description: "Secure software testing and secure development practices validation.",
    cspValue: "ZAP DAST + API Security Testing + Nuclei Scanner perform automated security testing of developed software. DAST findings inform secure development but don't enforce SDLC processes.",
    agencyValue: "Agencies review CSP-submitted software security testing results to assess whether development practices produce secure outputs.",
    ksis: [
      {
        id: "KSI-SDE-SST", name: "Secure Software Testing", status: "direct",
        aceModules: ["ZAP DAST", "API Security Testing", "Nuclei Scanner"],
        cspDetail: "ZAP DAST performs active web application security testing. API Security Testing validates API security (authentication, authorization, injection). Nuclei Scanner executes template-based security checks. All produce real vulnerability data.",
        agencyDetail: "Review CSP-submitted software security testing results from DAST, API testing, and Nuclei scanning."
      },
      {
        id: "KSI-SDE-SDP", name: "Secure Development Practices", status: "supporting",
        aceModules: ["ZAP DAST", "Vuln Analysis Agents"],
        cspDetail: "DAST findings and Vuln Analysis Agents inform secure development priorities by identifying common vulnerability classes. The platform tests outputs but doesn't audit SDLC processes directly.",
        agencyDetail: "Review CSP-submitted vulnerability trend analysis to assess whether secure development practices reduce common vulnerability classes over time."
      },
    ],
  },
  {
    id: "ppm",
    name: "Policy & Procedure Management",
    abbrev: "PPM",
    icon: ScrollText,
    color: "text-stone-400",
    totalKSIs: 2,
    directCoverage: 0,
    supportingCoverage: 2,
    description: "Policy and procedure review and implementation verification.",
    cspValue: "RoE Builder + Evidence Chain store and version policy documents. Scope Enforcement Middleware + Scan Policy Engine enforce operational policies within the platform. The platform supports policy documentation but doesn't manage organizational policies.",
    agencyValue: "Agencies review CSP-submitted policy documentation and operational enforcement evidence.",
    ksis: [
      {
        id: "KSI-PPM-PPR", name: "Policy & Procedure Review", status: "supporting",
        aceModules: ["RoE Builder", "Evidence Chain"],
        cspDetail: "RoE Builder maintains version-controlled rules of engagement and policy documents. Evidence Chain stores policy documentation with integrity verification. LLM analysis can review policies for completeness.",
        agencyDetail: "Review CSP-submitted policy documentation through RoE Builder version history and Evidence Chain exports."
      },
      {
        id: "KSI-PPM-PPI", name: "Policy & Procedure Implementation", status: "supporting",
        aceModules: ["Scope Enforcement Middleware", "Scan Policy Engine"],
        cspDetail: "Scope Enforcement Middleware enforces operational boundaries during testing. Scan Policy Engine defines and enforces scan policies. These demonstrate policy implementation within the platform's operational scope.",
        agencyDetail: "Review CSP-submitted operational policy enforcement evidence showing scope enforcement and scan policy compliance."
      },
    ],
  },
];

// ─── Summary Stats ──────────────────────────────────────────────────

const TOTAL_KSIS = KSI_THEMES.reduce((sum, t) => sum + t.totalKSIs, 0);
const DIRECT = KSI_THEMES.reduce((sum, t) => sum + t.directCoverage, 0);
const SUPPORTING = KSI_THEMES.reduce((sum, t) => sum + t.supportingCoverage, 0);
const PLANNED = TOTAL_KSIS - DIRECT - SUPPORTING;
const COVERAGE_PCT = Math.round(((DIRECT + SUPPORTING) / TOTAL_KSIS) * 100);

// ─── Component ──────────────────────────────────────────────────────

export default function FedRAMPKSIMap() {
  const [activeView, setActiveView] = useState<"csp" | "agency">("csp");
  const [expandedTheme, setExpandedTheme] = useState<string | null>(null);

  return (
    <section id="fedramp-20x" className="py-20">
      <div className="container">
        {/* Header */}
        <div className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-display text-xs tracking-[0.3em] text-primary">COMPLIANCE ENABLEMENT</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-display mb-4">FEDRAMP 20x KSI MAP</h2>
          <p className="text-lg text-muted-foreground max-w-3xl">
            How ACE C3 maps to {TOTAL_KSIS} FedRAMP 20x Key Security Indicators across {KSI_THEMES.length} compliance themes — 
            providing direct automated validation for {DIRECT} KSIs and supporting evidence for {SUPPORTING} more, grounded in real penetration testing, adversary emulation, and continuous security monitoring capabilities.
          </p>
        </div>

        {/* Coverage Summary Bar */}
        <div className="mb-10 p-6 border-2 border-primary/30 bg-primary/5">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div>
              <div className="font-display text-5xl text-primary mb-1">{COVERAGE_PCT}%</div>
              <div className="text-sm text-muted-foreground">KSI COVERAGE</div>
            </div>
            <div className="flex-1 max-w-xl w-full">
              <div className="h-4 bg-card border border-border overflow-hidden flex">
                <div
                  className="h-full bg-primary transition-all duration-1000"
                  style={{ width: `${(DIRECT / TOTAL_KSIS) * 100}%` }}
                />
                <div
                  className="h-full bg-primary/40 transition-all duration-1000"
                  style={{ width: `${(SUPPORTING / TOTAL_KSIS) * 100}%` }}
                />
              </div>
              <div className="flex items-center gap-6 mt-3 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-primary" />
                  <span className="text-muted-foreground">{DIRECT} Direct ({Math.round((DIRECT / TOTAL_KSIS) * 100)}%)</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-primary/40" />
                  <span className="text-muted-foreground">{SUPPORTING} Supporting ({Math.round((SUPPORTING / TOTAL_KSIS) * 100)}%)</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-muted border border-border" />
                  <span className="text-muted-foreground">{PLANNED} Planned</span>
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="font-display text-2xl">{TOTAL_KSIS}</div>
              <div className="text-xs text-muted-foreground">TOTAL KSIs</div>
            </div>
          </div>
        </div>

        {/* CSP / Agency Toggle */}
        <div className="flex items-center gap-2 mb-8">
          <button
            onClick={() => setActiveView("csp")}
            className={`flex items-center gap-2 px-5 py-3 font-display text-sm tracking-wider border-2 transition-all ${
              activeView === "csp"
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:border-primary/50 hover:text-foreground"
            }`}
          >
            <Building2 className="w-4 h-4" />
            FOR CLOUD SERVICE PROVIDERS
          </button>
          <button
            onClick={() => setActiveView("agency")}
            className={`flex items-center gap-2 px-5 py-3 font-display text-sm tracking-wider border-2 transition-all ${
              activeView === "agency"
                ? "border-primary bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:border-primary/50 hover:text-foreground"
            }`}
          >
            <Layers className="w-4 h-4" />
            FOR FEDERAL AGENCIES
          </button>
        </div>

        {/* View Description */}
        <div className="mb-8 p-4 border border-border/50 bg-card/30">
          {activeView === "csp" ? (
            <div>
              <p className="text-sm text-muted-foreground leading-relaxed mb-3">
                <span className="text-primary font-display tracking-wider">CSP VIEW</span> — ACE C3 supports cloud service providers in preparing for and maintaining FedRAMP 20x authorization by providing automated security validation, evidence generation, penetration testing across all 6 mandatory attack vectors, and OSCAL-formatted export for submission. ACE C3 does not grant authorization — it equips CSPs with the tools, evidence, and continuous validation needed to satisfy FedRAMP requirements.
              </p>
              <p className="text-xs text-muted-foreground/70 leading-relaxed">
                Each KSI shows the specific ACE C3 modules that provide coverage, what they actually do, and whether coverage is direct (the module performs the KSI function and generates evidence), supporting (the module contributes telemetry or partial coverage), or planned (capability is on the roadmap).
              </p>
            </div>
          ) : (
            <div>
              <p className="text-sm text-muted-foreground leading-relaxed mb-3">
                <span className="text-primary font-display tracking-wider">AGENCY VIEW</span> — ACE C3 provides federal agencies with a passive monitoring and oversight capability for evaluating CSP security posture. Agencies do not run, trigger, or conduct their own penetration tests through the platform. Instead, agencies can monitor CSP status through passive discovery, ingest CSP-submitted assessment evidence, and track remediation status across all KSI themes.
              </p>
              <div className="mt-3 p-3 bg-primary/5 border border-primary/20">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                  <div className="text-xs text-muted-foreground leading-relaxed">
                    <span className="text-primary font-display tracking-wider">AGENCY MONITORING MODEL</span> — Agencies consume evidence produced by CSPs using ACE C3 — they do not initiate scans or active tests. Each KSI below describes what CSP-submitted evidence agencies can review and how passive monitoring supports continuous oversight.
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* KSI Theme Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {KSI_THEMES.map((theme) => {
            const isExpanded = expandedTheme === theme.id;
            const coveragePct = Math.round(((theme.directCoverage + theme.supportingCoverage) / theme.totalKSIs) * 100);

            return (
              <div
                key={theme.id}
                className={`border-2 transition-all cursor-pointer ${
                  isExpanded
                    ? "border-primary bg-primary/5 md:col-span-2 lg:col-span-3"
                    : "border-border hover:border-primary/50 bg-card/30"
                }`}
                onClick={() => setExpandedTheme(isExpanded ? null : theme.id)}
              >
                {/* Theme Header */}
                <div className="p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <theme.icon className={`w-5 h-5 ${theme.color}`} />
                      <div>
                        <span className="font-display text-[10px] tracking-[0.2em] text-muted-foreground">{theme.abbrev}</span>
                        <h3 className="font-display text-sm tracking-wider leading-tight">{theme.name}</h3>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0 ml-3">
                      <div className={`font-display text-xl ${coveragePct === 100 ? 'text-emerald-400' : coveragePct >= 75 ? 'text-primary' : coveragePct >= 50 ? 'text-amber-400' : 'text-muted-foreground'}`}>
                        {coveragePct}%
                      </div>
                      <div className="text-[10px] text-muted-foreground">{theme.totalKSIs} KSIs</div>
                    </div>
                  </div>

                  {/* Mini coverage bar */}
                  <div className="h-1.5 bg-card border border-border/50 overflow-hidden flex mb-3">
                    <div className="h-full bg-primary" style={{ width: `${(theme.directCoverage / theme.totalKSIs) * 100}%` }} />
                    <div className="h-full bg-primary/40" style={{ width: `${(theme.supportingCoverage / theme.totalKSIs) * 100}%` }} />
                  </div>

                  <p className="text-xs text-muted-foreground leading-relaxed">{theme.description}</p>

                  {!isExpanded && (
                    <div className="flex items-center gap-1 mt-3 text-xs text-primary font-display tracking-wider">
                      VIEW DETAILS <ChevronRight className="w-3 h-3" />
                    </div>
                  )}
                </div>

                {/* Expanded Detail */}
                {isExpanded && (
                  <div className="border-t border-border/50 p-5">
                    {/* Value Proposition */}
                    <div className="mb-6 p-4 bg-card/50 border border-border/30">
                      <div className="flex items-center gap-2 mb-2">
                        {activeView === "csp" ? (
                          <Building2 className="w-4 h-4 text-primary" />
                        ) : (
                          <Layers className="w-4 h-4 text-primary" />
                        )}
                        <span className="font-display text-xs tracking-wider text-primary">
                          {activeView === "csp" ? "HOW ACE C3 HELPS CSPs" : "HOW ACE C3 HELPS AGENCIES"}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        {activeView === "csp" ? theme.cspValue : theme.agencyValue}
                      </p>
                    </div>

                    {/* Individual KSIs */}
                    <div className="space-y-3">
                      <div className="font-display text-xs tracking-[0.2em] text-muted-foreground mb-3">
                        INDIVIDUAL KEY SECURITY INDICATORS
                      </div>
                      {theme.ksis.map((ksi) => (
                        <div
                          key={ksi.id}
                          className="p-4 bg-card/30 border border-border/20"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="flex items-start gap-3 mb-2">
                            <div className="flex-shrink-0 mt-0.5">
                              {ksi.status === "direct" ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                              ) : ksi.status === "supporting" ? (
                                <CheckCircle2 className="w-4 h-4 text-primary/60" />
                              ) : (
                                <Clock className="w-4 h-4 text-amber-400/60" />
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-display text-xs tracking-wider">{ksi.name}</span>
                                <span className={`text-[9px] px-1.5 py-0.5 font-display tracking-wider ${
                                  ksi.status === "direct"
                                    ? "bg-emerald-400/10 text-emerald-400 border border-emerald-400/20"
                                    : ksi.status === "supporting"
                                    ? "bg-primary/10 text-primary border border-primary/20"
                                    : "bg-amber-400/10 text-amber-400 border border-amber-400/20"
                                }`}>
                                  {ksi.status === "direct" ? "DIRECT" : ksi.status === "supporting" ? "SUPPORTING" : "PLANNED"}
                                </span>
                              </div>
                              {/* Module tags */}
                              <div className="flex flex-wrap gap-1.5 mb-2">
                                {ksi.aceModules.map((mod) => (
                                  <span key={mod} className="text-[10px] text-muted-foreground bg-background/50 border border-border/30 px-1.5 py-0.5">
                                    {mod}
                                  </span>
                                ))}
                              </div>
                              {/* Detailed description based on view */}
                              <p className="text-xs text-muted-foreground/80 leading-relaxed">
                                {activeView === "csp" ? ksi.cspDetail : ksi.agencyDetail}
                              </p>
                            </div>
                            <span className="text-[9px] text-muted-foreground font-mono flex-shrink-0">{ksi.id}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Bottom CTA */}
        <div className="mt-10 p-6 border-2 border-border bg-card/30 flex flex-col md:flex-row items-center justify-between gap-6">
          <div>
            <h3 className="font-display text-xl tracking-wider mb-2">
              {activeView === "csp"
                ? "READY TO ACHIEVE FEDRAMP 20x AUTHORIZATION?"
                : "READY TO EVALUATE YOUR CSP PORTFOLIO?"}
            </h3>
            <p className="text-sm text-muted-foreground">
              {activeView === "csp"
                ? `ACE C3 covers ${COVERAGE_PCT}% of all ${TOTAL_KSIS} KSIs today — ${DIRECT} with direct automated validation and ${SUPPORTING} with supporting evidence. Real penetration testing, adversary emulation, and OSCAL export for FedRAMP submission.`
                : `ACE C3 provides evidence-based CSP evaluation across ${DIRECT + SUPPORTING} of ${TOTAL_KSIS} KSIs — with real penetration test evidence, detection coverage metrics, and configuration compliance data instead of self-attestation.`}
            </p>
          </div>
          <a href="mailto:info@aceofcloud.com" className="flex-shrink-0">
            <button className="flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-white font-display text-sm tracking-wider transition-colors">
              CONTACT US <ArrowRight className="w-4 h-4" />
            </button>
          </a>
        </div>

        {/* Compliance References */}
        <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-2 text-[10px] text-muted-foreground/60 font-display tracking-wider">
          <span>ALIGNED TO:</span>
          <span>NIST SP 800-53 Rev 5</span>
          <span>•</span>
          <span>NIST SP 800-115</span>
          <span>•</span>
          <span>FEDRAMP 20x FRAMEWORK</span>
          <span>•</span>
          <span>NIST OSCAL</span>
          <span>•</span>
          <span>CISA KEV CATALOG</span>
          <span>•</span>
          <span>MITRE ATT&CK v15</span>
        </div>
      </div>
    </section>
  );
}
