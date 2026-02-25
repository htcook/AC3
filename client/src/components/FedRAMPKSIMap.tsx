import { useState } from "react";
import {
  Shield, Building2, ChevronRight, CheckCircle2,
  Layers, Lock, Eye, Server, Users, BookOpen, RefreshCw,
  FileText, Radar, Target, Zap, Brain, ShieldCheck, BarChart3,
  Fingerprint, Clock, ArrowRight, AlertTriangle, Info
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

// ─── Honest KSI Data — Only references modules that actually exist ──

const KSI_THEMES: KSITheme[] = [
  {
    id: "vdr",
    name: "Vulnerability Detection & Response",
    abbrev: "VDR",
    icon: Target,
    color: "text-red-400",
    totalKSIs: 3,
    directCoverage: 3,
    supportingCoverage: 0,
    description: "Continuous vulnerability scanning, remediation within SLA, and annual penetration testing across all 6 FedRAMP attack vectors.",
    cspValue: "ACE C3 executes real penetration tests across all 6 mandatory attack vectors — external, internal, web app, API, mobile, and social engineering — with evidence capture proving exploitability. DAST scanning, exploit validation, and vulnerability intelligence feeds provide continuous detection.",
    agencyValue: "Agencies can passively monitor CSP vulnerability posture through ingested scan reports, passive domain discovery, and enumeration data. CSP-submitted penetration test evidence, DAST scan results, and vulnerability remediation timelines are available for review. Agencies track remediation SLA compliance without initiating any active testing.",
    ksis: [
      {
        id: "KSI-VDR-001", name: "Vulnerability Detection & Response", status: "direct",
        aceModules: ["Domain Intel", "Vuln Intel", "Validation Engine", "DAST Scanner"],
        cspDetail: "Domain Intel discovers external attack surface. Vuln Intel aggregates KEV, NVD, and ExploitDB feeds. DAST Scanner performs active web application testing. Validation Engine confirms exploitability with proof artifacts.",
        agencyDetail: "Review CSP-submitted vulnerability scan results from Domain Intel and DAST Scanner. Passive discovery and enumeration independently verify external attack surface. Track remediation SLA compliance through Evidence Chain timestamps without initiating any active scans."
      },
      {
        id: "KSI-VDR-002", name: "Penetration Testing", status: "direct",
        aceModules: ["Exploit Arsenal", "Red Team Ops", "Phishing Ops", "DAST Scanner", "Post-Engagement Report"],
        cspDetail: "Exploit Arsenal provides 16,000+ modules for real exploitation. Red Team Ops orchestrates adversary emulation with Caldera. Phishing Ops tests human defenses with 17 techniques. Post-Engagement Report generates evidence-backed deliverables.",
        agencyDetail: "Agencies ingest CSP-submitted Post-Engagement Reports with evidence artifacts proving each finding. Reports include MITRE ATT&CK heatmaps showing which techniques were tested, exploit proof screenshots, and remediation recommendations with severity ratings. Agencies review — not execute — these assessments."
      },
      {
        id: "KSI-VDR-003", name: "Persistent Validation & Assessment", status: "direct",
        aceModules: ["Validation Scheduler", "Agentless BAS", "ATT&CK Validation Tests"],
        cspDetail: "Validation Scheduler runs assessments at configurable cadences (3-day, 7-day, monthly). Agentless BAS tests detection coverage without deploying agents. ATT&CK Validation Tests execute 1,400+ atomic tests mapped to MITRE techniques.",
        agencyDetail: "Monitor CSP continuous validation cadence through submitted assessment evidence. Agentless BAS results show detection coverage percentages. ATT&CK Validation test results demonstrate which techniques the CSP can detect and which remain blind spots. Agencies track assessment frequency and remediation progress passively."
      },
    ],
  },
  {
    id: "pva",
    name: "Persistent Validation & Assessment",
    abbrev: "PVA",
    icon: ShieldCheck,
    color: "text-emerald-400",
    totalKSIs: 4,
    directCoverage: 1,
    supportingCoverage: 2,
    description: "Machine-based validation at 3-day/7-day cadence, authorization data sharing via trust centers, and ongoing assessment reports.",
    cspValue: "ACE C3 generates OSCAL-formatted evidence packages from validation results and produces ongoing assessment reports with evidence artifacts. Validation Scheduler automates assessment cadence at FedRAMP-mandated frequencies.",
    agencyValue: "Agencies ingest OSCAL exports submitted by CSPs using ACE C3 to verify assessment data in machine-readable format. Evidence Chain provides tamper-resistant audit trails of all validation activities. Agencies passively monitor CSP assessment cadence, completeness, and remediation status without conducting any active testing.",
    ksis: [
      {
        id: "KSI-PVA-001", name: "Authorization Data Sharing", status: "supporting",
        aceModules: ["OSCAL Export", "Evidence Chain"],
        cspDetail: "OSCAL Export generates machine-readable SSP, SAR, and POA&M documents from platform data. Evidence Chain maintains tamper-resistant records of all assessment activities with S3-stored artifacts.",
        agencyDetail: "Ingest OSCAL-formatted authorization packages submitted by CSPs. Evidence Chain records provide an immutable audit trail of when assessments were performed, what was tested, and what evidence was captured. Agencies review submitted data — no active testing is initiated."
      },
      {
        id: "KSI-PVA-002", name: "Ongoing Assessment Reports", status: "direct",
        aceModules: ["Post-Engagement Report", "Evidence Chain", "Report Generator"],
        cspDetail: "Post-Engagement Report generates branded assessment deliverables with MITRE heatmaps and evidence links. Report Generator produces executive summaries with validation coverage metrics. Evidence Chain links all findings to proof artifacts.",
        agencyDetail: "Review CSP-submitted ongoing assessment reports with embedded evidence links. Reports include validation coverage percentages, MITRE ATT&CK technique coverage, and links to proof artifacts stored in Evidence Chain. Agencies monitor report cadence and remediation progress."
      },
      {
        id: "KSI-PVA-003", name: "Significant Change Notification", status: "supporting",
        aceModules: ["Config Baseline Engine", "Audit Log"],
        cspDetail: "Config Baseline Engine detects drift from approved configurations. Audit Log records all security-relevant changes with timestamps and user attribution for change documentation.",
        agencyDetail: "Review CSP-submitted configuration change history through Audit Log exports. Config Baseline drift reports show what changed from the approved baseline, enabling agencies to assess whether changes require re-assessment — all through passive monitoring."
      },
      {
        id: "KSI-PVA-004", name: "Feedback Mechanism", status: "planned",
        aceModules: ["Evidence Chain"],
        cspDetail: "Evidence Chain can store agency feedback artifacts, but a dedicated feedback portal for agency-CSP communication is planned for future development.",
        agencyDetail: "A structured feedback mechanism for agencies to communicate findings and concerns to CSPs is planned. Currently, CSP-submitted assessment evidence can be reviewed through Evidence Chain exports."
      },
    ],
  },
  {
    id: "iam",
    name: "Identity & Access Management",
    abbrev: "IAM",
    icon: Fingerprint,
    color: "text-blue-400",
    totalKSIs: 7,
    directCoverage: 2,
    supportingCoverage: 2,
    description: "Phishing-resistant MFA, privileged access management, least privilege enforcement, and account lifecycle controls.",
    cspValue: "ACE C3 tests MFA resilience through real phishing campaigns with MFA bypass techniques (AiTM, BITB, device code). AD Attack Simulation validates privileged access controls. Cloud Attack Paths identifies excessive permissions.",
    agencyValue: "Agencies can review CSP-submitted MFA bypass test results to verify phishing resistance. AD Attack Simulation reports submitted by CSPs show whether privileged access controls withstand real attack techniques. Cloud Attack Paths analysis reveals excessive permission chains. All review is passive — agencies do not initiate these tests.",
    ksis: [
      {
        id: "KSI-IAM-001", name: "Phishing-Resistant MFA", status: "direct",
        aceModules: ["Phishing Ops", "Campaign Wizard"],
        cspDetail: "Phishing Ops executes real MFA bypass attacks including AiTM proxy, BITB, device code phishing, and HTML smuggling. Campaign Wizard configures targeted MFA resilience tests. Results prove whether MFA implementation resists actual attack techniques.",
        agencyDetail: "Review CSP-submitted MFA bypass test results showing which attack techniques succeeded or failed. Phishing campaign reports include click rates, credential capture attempts, and MFA bypass success rates. Agencies monitor these results passively to verify MFA resilience."
      },
      {
        id: "KSI-IAM-002", name: "Privileged Access Management", status: "direct",
        aceModules: ["AD Attack Simulation", "AD Domain Connector"],
        cspDetail: "AD Attack Simulation tests privileged access controls with techniques like Kerberoasting, DCSync, Golden Ticket, and Pass-the-Hash. AD Domain Connector enumerates domain structure to identify privileged account exposure.",
        agencyDetail: "Review CSP-submitted AD Attack Simulation results showing whether privileged access controls resist real attack techniques. Reports detail which privilege escalation paths exist and whether PAM controls effectively contain lateral movement. Agencies monitor remediation status."
      },
      {
        id: "KSI-IAM-003", name: "Account Lifecycle", status: "supporting",
        aceModules: ["AD Domain Connector", "Audit Log"],
        cspDetail: "AD Domain Connector enumerates accounts, group memberships, and last-login timestamps to identify stale or orphaned accounts. Audit Log tracks account provisioning and deprovisioning events.",
        agencyDetail: "Review CSP-submitted AD Domain Connector reports showing stale accounts, group membership sprawl, and orphaned service accounts. Audit Log exports demonstrate account lifecycle management practices. Agencies passively enumerate and monitor account hygiene."
      },
      {
        id: "KSI-IAM-004", name: "Least Privilege", status: "supporting",
        aceModules: ["Cloud Attack Paths", "AD Attack Simulation"],
        cspDetail: "Cloud Attack Paths maps permission chains across AWS, Azure, and GCP to identify over-privileged roles. AD Attack Simulation tests whether least privilege is enforced by attempting privilege escalation.",
        agencyDetail: "Review CSP-submitted Cloud Attack Paths reports revealing excessive permission chains. AD Attack Simulation results show whether privilege escalation is possible, indicating least privilege enforcement gaps. Agencies track remediation of identified gaps."
      },
      {
        id: "KSI-IAM-005", name: "Just-in-Time Access", status: "planned",
        aceModules: ["Cloud Attack Paths"],
        cspDetail: "Cloud Attack Paths can identify persistent privileged access that should be JIT. Dedicated JIT access validation is planned.",
        agencyDetail: "Planned capability to passively verify CSP JIT access implementations through review of submitted privilege elevation audit logs and time-bound access control configurations."
      },
      {
        id: "KSI-IAM-006", name: "Single Sign-On", status: "planned",
        aceModules: ["AD Domain Connector"],
        cspDetail: "AD Domain Connector can enumerate SSO configurations. Dedicated SSO security testing is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted SSO configuration reports including federation trust configurations and token security assessments."
      },
      {
        id: "KSI-IAM-007", name: "Network Access Control", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track network access control configurations. Dedicated NAC validation testing is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted network access control configurations through baseline comparison and segmentation audit reports."
      },
    ],
  },
  {
    id: "cmt",
    name: "Change Management",
    abbrev: "CMT",
    icon: RefreshCw,
    color: "text-amber-400",
    totalKSIs: 4,
    directCoverage: 2,
    supportingCoverage: 2,
    description: "Automated configuration management, configuration databases, documented changes, and deployment validation.",
    cspValue: "Config Baseline Engine tracks configuration drift from approved baselines. Validation Scheduler validates security controls after changes. Audit Log and RoE Builder maintain complete change documentation with version history.",
    agencyValue: "Agencies passively review CSP-submitted Config Baseline drift reports to verify approved configurations are maintained. Audit Log exports demonstrate change documentation practices. Validation Scheduler evidence shows whether security controls are re-validated after changes. No active testing is initiated by agencies.",
    ksis: [
      {
        id: "KSI-CMT-001", name: "Automate Configuration Management", status: "supporting",
        aceModules: ["Config Baseline Engine", "Validation Scheduler"],
        cspDetail: "Config Baseline Engine defines and monitors security configuration baselines. Validation Scheduler triggers automated re-validation after configuration changes are detected.",
        agencyDetail: "Review CSP-submitted Config Baseline reports showing configuration compliance rates and drift history. Validation Scheduler evidence demonstrates automated re-assessment after changes. Agencies monitor compliance passively."
      },
      {
        id: "KSI-CMT-002", name: "Configuration Database", status: "supporting",
        aceModules: ["Config Baseline Engine", "Domain Intel"],
        cspDetail: "Config Baseline Engine maintains a database of approved configurations and current state. Domain Intel provides asset inventory data that feeds configuration tracking.",
        agencyDetail: "Review CSP-submitted Config Baseline exports showing configuration inventory and compliance status. Passive enumeration via Domain Intel independently verifies whether all assets are tracked in the configuration database."
      },
      {
        id: "KSI-CMT-003", name: "Document Changes", status: "direct",
        aceModules: ["Audit Log", "RoE Builder", "Evidence Chain"],
        cspDetail: "Audit Log records all security-relevant changes with timestamps and user attribution. RoE Builder maintains version-controlled rules of engagement documentation. Evidence Chain provides tamper-resistant change records.",
        agencyDetail: "Review CSP-submitted Audit Log exports showing complete change history with timestamps and attribution. RoE Builder version history demonstrates documentation practices. Evidence Chain records provide tamper-resistant proof of change management. Agencies monitor change cadence passively."
      },
      {
        id: "KSI-CMT-004", name: "Validate Through Deployment", status: "direct",
        aceModules: ["Validation Scheduler", "Agentless BAS", "ATT&CK Validation Tests"],
        cspDetail: "Validation Scheduler triggers post-deployment security validation. Agentless BAS tests detection coverage after changes. ATT&CK Validation Tests confirm security controls still function after deployment.",
        agencyDetail: "Review CSP-submitted Validation Scheduler evidence showing security controls are re-validated after deployments. Agentless BAS and ATT&CK test results before and after changes demonstrate deployment validation practices. Agencies track remediation status passively."
      },
    ],
  },
  {
    id: "cna",
    name: "Cloud Native Architecture",
    abbrev: "CNA",
    icon: Server,
    color: "text-cyan-400",
    totalKSIs: 8,
    directCoverage: 2,
    supportingCoverage: 3,
    description: "Minimal attack surface, logical network segmentation, DoS protection, high availability, resilience, and container security.",
    cspValue: "Domain Intel and DAST Scanner continuously discover and test the external attack surface. Cloud Attack Paths identifies excessive privileges and misconfigurations. Nuclei Scanner tests container and infrastructure security with template-based scanning.",
    agencyValue: "Agencies passively monitor CSP external attack surface through ingested Domain Intel reports and independent passive enumeration. CSP-submitted DAST Scanner results and Cloud Attack Paths analysis are available for review. Agencies do not initiate scans — they monitor submitted evidence and track remediation of identified issues.",
    ksis: [
      {
        id: "KSI-CNA-001", name: "Minimal Attack Surface", status: "direct",
        aceModules: ["Domain Intel", "DAST Scanner", "Vuln Scanner"],
        cspDetail: "Domain Intel discovers all external-facing assets, subdomains, and services. DAST Scanner tests web applications for vulnerabilities. Vuln Scanner identifies exposed services and known vulnerabilities across the attack surface.",
        agencyDetail: "Review CSP-submitted Domain Intel reports and independently verify external attack surface through passive discovery and enumeration — subdomains, open ports, exposed services. Track attack surface size over time to verify reduction efforts. No active scanning is initiated by agencies."
      },
      {
        id: "KSI-CNA-002", name: "Define Functionality/Privileges", status: "direct",
        aceModules: ["Cloud Attack Paths", "AD Attack Simulation"],
        cspDetail: "Cloud Attack Paths maps permission chains to identify over-privileged roles and unnecessary functionality. AD Attack Simulation tests whether privilege boundaries are enforced.",
        agencyDetail: "Review CSP-submitted Cloud Attack Paths reports revealing whether environments follow least-functionality principles. AD Attack Simulation results show whether privilege boundaries contain lateral movement. Agencies track remediation of over-privileged roles."
      },
      {
        id: "KSI-CNA-003", name: "Logical Network Segmentation", status: "supporting",
        aceModules: ["Config Baseline Engine", "NGFW Validation"],
        cspDetail: "Config Baseline Engine tracks network segmentation configurations. NGFW Validation tests firewall rules and network boundaries to verify segmentation effectiveness.",
        agencyDetail: "Review CSP-submitted NGFW Validation results showing whether network segmentation rules are properly configured. Config Baseline reports track segmentation configuration compliance. Agencies monitor passively."
      },
      {
        id: "KSI-CNA-004", name: "Container/Image Security", status: "supporting",
        aceModules: ["Nuclei Scanner", "Config Baseline Engine"],
        cspDetail: "Nuclei Scanner runs container security templates against container registries and running containers. Config Baseline Engine tracks container configuration compliance.",
        agencyDetail: "Review CSP-submitted Nuclei Scanner container security results showing image vulnerabilities and misconfigurations. Config Baseline reports demonstrate container hardening compliance. Agencies track remediation status."
      },
      {
        id: "KSI-CNA-005", name: "DoS Protection", status: "supporting",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine tracks DoS protection configurations (WAF rules, rate limiting, CDN settings). Active DoS testing is out of scope for offensive security platforms.",
        agencyDetail: "Review CSP-submitted Config Baseline reports showing DoS protection configuration compliance — WAF rules, rate limiting, and CDN configurations. Agencies monitor passively."
      },
      {
        id: "KSI-CNA-006", name: "High Availability", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track HA configurations. Dedicated availability testing and failover validation is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted high availability configuration reports and failover test results."
      },
      {
        id: "KSI-CNA-007", name: "Resilience", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track resilience configurations. Dedicated resilience testing is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted resilience test results and recovery validation exercise reports."
      },
      {
        id: "KSI-CNA-008", name: "Secure Software Management", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track software management configurations. Dedicated SBOM analysis and software supply chain testing is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted SBOM analysis reports and dependency vulnerability tracking data."
      },
    ],
  },
  {
    id: "mla",
    name: "Monitoring, Logging & Alerting",
    abbrev: "MLA",
    icon: Eye,
    color: "text-violet-400",
    totalKSIs: 5,
    directCoverage: 3,
    supportingCoverage: 1,
    description: "Centralized logging, event type catalogs, tamper-resistant logs, log archival, and security monitoring.",
    cspValue: "SIEM Connectors integrate with your SIEM to validate detection coverage. Detection Rule Generator auto-creates Sigma/YARA/Suricata rules from executed TTPs. ATT&CK Coverage Matrix measures detection gaps against real attack techniques.",
    agencyValue: "Agencies passively review CSP-submitted SIEM detection coverage reports showing which attack techniques the CSP can detect. Detection Rule Generator output demonstrates detection engineering maturity. ATT&CK Coverage Matrix reveals monitoring blind spots. Agencies do not initiate detection tests — they ingest and monitor submitted evidence.",
    ksis: [
      {
        id: "KSI-MLA-001", name: "Centralized Logging", status: "direct",
        aceModules: ["SIEM Connectors", "Evidence Chain"],
        cspDetail: "SIEM Connectors push security events to centralized SIEM platforms. Evidence Chain maintains its own centralized, tamper-resistant log of all platform activities and findings.",
        agencyDetail: "Review CSP-submitted SIEM Connector configuration reports showing centralized logging integration. Evidence Chain exports demonstrate comprehensive logging of all security assessment activities. Agencies monitor passively."
      },
      {
        id: "KSI-MLA-002", name: "Event Type Catalog", status: "direct",
        aceModules: ["SIEM Connectors", "Detection Rule Generator"],
        cspDetail: "SIEM Connectors define event types for all platform activities. Detection Rule Generator produces detection rules covering specific event types from executed TTPs, creating a comprehensive event catalog.",
        agencyDetail: "Review CSP-submitted Detection Rule Generator output showing event type coverage. SIEM Connector event mappings demonstrate which security events are captured and forwarded. Agencies track detection maturity passively."
      },
      {
        id: "KSI-MLA-003", name: "Security Monitoring", status: "direct",
        aceModules: ["SIEM Connectors", "ATT&CK Coverage Matrix", "SIEM Feedback Loop"],
        cspDetail: "ATT&CK Coverage Matrix measures detection coverage against executed techniques. SIEM Feedback Loop validates whether SIEM rules actually fire during red team exercises. SIEM Connectors ensure monitoring data flows to centralized platforms.",
        agencyDetail: "Review CSP-submitted ATT&CK Coverage Matrix showing detection percentages across MITRE techniques. SIEM Feedback Loop results prove whether monitoring actually detects real attacks. Agencies monitor detection coverage trends and remediation of blind spots passively."
      },
      {
        id: "KSI-MLA-004", name: "Tamper-Resistant Logging", status: "supporting",
        aceModules: ["Evidence Chain", "Config Baseline Engine"],
        cspDetail: "Evidence Chain stores assessment artifacts in S3 with integrity verification. Config Baseline Engine can track log integrity configurations.",
        agencyDetail: "Review CSP-submitted Evidence Chain integrity records showing tamper-resistant storage of assessment artifacts. Config Baseline reports demonstrate log protection configuration compliance. Agencies verify log integrity passively."
      },
      {
        id: "KSI-MLA-005", name: "Log Archival", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track log retention configurations. Dedicated log archival validation is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted log retention configuration reports and archival practice documentation."
      },
    ],
  },
  {
    id: "svc",
    name: "Service Configuration & Vaulting",
    abbrev: "SVC",
    icon: Lock,
    color: "text-pink-400",
    totalKSIs: 7,
    directCoverage: 2,
    supportingCoverage: 1,
    description: "Encryption at rest and in transit, data handling restrictions, key management, API security, and secure configuration guides.",
    cspValue: "DAST Scanner and API Security Testing validate TLS configurations and API security. Email Security Analyzer tests email encryption and authentication (SPF, DKIM, DMARC). Config Baseline Engine tracks encryption and key management configurations.",
    agencyValue: "Agencies passively review CSP-submitted DAST Scanner TLS test results and API Security Testing reports to verify encryption implementations. Email Security Analyzer results show email authentication compliance. Config Baseline reports demonstrate encryption configuration standards. Agencies do not initiate scans.",
    ksis: [
      {
        id: "KSI-SVC-001", name: "API Security", status: "direct",
        aceModules: ["DAST Scanner", "API Security Testing"],
        cspDetail: "DAST Scanner tests web APIs with OpenAPI/GraphQL/SOAP spec import for comprehensive coverage. API Security Testing performs targeted API vulnerability assessment including authentication bypass, injection, and authorization testing.",
        agencyDetail: "Review CSP-submitted DAST Scanner API test results showing vulnerability findings across APIs. API Security Testing reports demonstrate whether APIs enforce proper authentication, authorization, and input validation. Agencies track remediation status passively."
      },
      {
        id: "KSI-SVC-002", name: "Encryption in Transit", status: "direct",
        aceModules: ["DAST Scanner", "Email Security Analyzer"],
        cspDetail: "DAST Scanner validates TLS configurations, cipher suites, and certificate validity across all endpoints. Email Security Analyzer tests SPF, DKIM, and DMARC configurations for email encryption in transit.",
        agencyDetail: "Review CSP-submitted DAST Scanner TLS test results showing cipher suite strength, certificate validity, and protocol versions. Email Security Analyzer reports verify email authentication compliance. Agencies monitor passively."
      },
      {
        id: "KSI-SVC-003", name: "Encryption at Rest", status: "supporting",
        aceModules: ["Config Baseline Engine", "Cloud Attack Paths"],
        cspDetail: "Config Baseline Engine tracks encryption-at-rest configurations. Cloud Attack Paths can identify unencrypted storage resources through permission chain analysis.",
        agencyDetail: "Review CSP-submitted Config Baseline reports showing encryption-at-rest configuration compliance across storage services. Agencies monitor passively."
      },
      {
        id: "KSI-SVC-004", name: "Key Management", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track key management configurations. Dedicated key rotation and lifecycle validation is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted key management configuration reports including rotation schedules and lifecycle management."
      },
      {
        id: "KSI-SVC-005", name: "Secure Configuration Guide", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine maintains approved configurations that can serve as the basis for secure configuration guides. Automated SCG generation is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted secure configuration guides and verify alignment with approved baselines."
      },
      {
        id: "KSI-SVC-006", name: "Data Handling Restrictions", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track data handling configurations. Dedicated data classification and handling validation is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted data handling configuration reports and data flow documentation."
      },
      {
        id: "KSI-SVC-007", name: "Third-Party Access", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track third-party access configurations. Dedicated third-party access validation is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted third-party access configuration reports and access path audit documentation."
      },
    ],
  },
  {
    id: "rpl",
    name: "Resilience, Planning & Logistics",
    abbrev: "RPL",
    icon: RefreshCw,
    color: "text-orange-400",
    totalKSIs: 4,
    directCoverage: 0,
    supportingCoverage: 2,
    description: "Backup alignment, recovery validation testing, RTO/RPO objectives, and disaster recovery planning.",
    cspValue: "BIA Report generates business impact analysis documentation. Config Baseline Engine tracks backup and recovery configurations. Dedicated recovery validation testing with automated failover exercises is planned.",
    agencyValue: "Agencies passively review CSP-submitted BIA Report outputs showing business impact analysis. Config Baseline reports demonstrate backup configuration compliance. Agencies monitor recovery posture and remediation status without initiating any active tests.",
    ksis: [
      {
        id: "KSI-RPL-001", name: "Recovery Validation Testing", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track recovery configurations. Automated recovery validation testing with failover exercises and RTO/RPO measurement is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted recovery validation test results and actual RTO/RPO measurements against stated targets."
      },
      {
        id: "KSI-RPL-002", name: "RTO/RPO Objectives", status: "supporting",
        aceModules: ["BIA Report", "Config Baseline Engine"],
        cspDetail: "BIA Report documents RTO/RPO objectives based on business impact analysis. Config Baseline Engine tracks whether recovery configurations align with stated objectives.",
        agencyDetail: "Review CSP-submitted BIA Report outputs showing RTO/RPO objectives and their business justification. Config Baseline reports verify recovery configurations align with stated targets. Agencies monitor compliance passively."
      },
      {
        id: "KSI-RPL-003", name: "Backup Alignment", status: "supporting",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine tracks backup configurations and schedules to verify alignment with recovery objectives.",
        agencyDetail: "Review CSP-submitted Config Baseline reports showing backup configuration compliance and alignment with stated recovery objectives. Agencies monitor passively."
      },
      {
        id: "KSI-RPL-004", name: "Disaster Recovery Plan", status: "planned",
        aceModules: ["Config Baseline Engine"],
        cspDetail: "Config Baseline Engine can track DR configurations. Automated DR plan validation and tabletop exercise support is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted disaster recovery plan documentation and tabletop exercise results."
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
    supportingCoverage: 1,
    description: "Security awareness training, developer training, incident response training, and privileged user training.",
    cspValue: "Phishing Ops runs realistic social engineering campaigns with 17 exploit techniques to measure security awareness. Campaign Wizard configures targeted training exercises. Purple Team exercises provide hands-on incident response training.",
    agencyValue: "Agencies passively review CSP-submitted phishing simulation results showing employee click rates, credential capture rates, and improvement trends over time. Purple Team exercise reports demonstrate incident response training effectiveness. Agencies monitor training program maturity without initiating any exercises.",
    ksis: [
      {
        id: "KSI-CED-001", name: "Security Awareness Training", status: "direct",
        aceModules: ["Phishing Ops", "Campaign Wizard", "Template Generator"],
        cspDetail: "Phishing Ops executes realistic phishing campaigns with 17 exploit techniques including AiTM, BITB, and HTML smuggling. Campaign Wizard configures targeted awareness exercises. Template Generator creates customized phishing templates for training scenarios.",
        agencyDetail: "Review CSP-submitted phishing simulation results showing click rates, credential capture rates, and reporting rates. Track improvement trends over successive campaigns to verify training effectiveness. Agencies monitor passively."
      },
      {
        id: "KSI-CED-002", name: "Incident Response Training", status: "supporting",
        aceModules: ["Red Team Ops", "Purple Team"],
        cspDetail: "Red Team Ops provides realistic attack scenarios for IR team training. Purple Team exercises enable collaborative attack-defense training with real-time feedback on detection and response.",
        agencyDetail: "Review CSP-submitted Purple Team exercise reports showing incident response team performance — detection times, containment actions, and communication effectiveness during simulated incidents. Agencies do not participate in or trigger exercises."
      },
      {
        id: "KSI-CED-003", name: "Developer Training", status: "planned",
        aceModules: ["DAST Scanner"],
        cspDetail: "DAST Scanner findings can inform developer security training priorities. Dedicated developer training content and tracking is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted developer training program reports and vulnerability trend analysis showing whether common vulnerability classes decrease over time."
      },
      {
        id: "KSI-CED-004", name: "Privileged User Training", status: "planned",
        aceModules: ["AD Attack Simulation"],
        cspDetail: "AD Attack Simulation results can inform privileged user training priorities. Dedicated privileged user training tracking is planned.",
        agencyDetail: "Planned capability to passively review CSP-submitted privileged user training reports and social engineering exercise results."
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
            How ACE C3 maps to all {TOTAL_KSIS} FedRAMP Key Security Indicators across 9 compliance themes — 
            supporting cloud service providers in preparing for authorization and providing federal agencies with passive monitoring to evaluate CSP security posture through submitted evidence.
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
                <span className="text-primary font-display tracking-wider">CSP VIEW</span> — ACE C3 supports cloud service providers in preparing for and maintaining FedRAMP authorization by providing automated security validation, evidence generation, penetration testing across all 6 mandatory attack vectors, and OSCAL-formatted export for submission. ACE C3 does not grant or enable authorization itself — it equips CSPs with the tools, evidence, and continuous validation needed to satisfy FedRAMP requirements.
              </p>
              <p className="text-xs text-muted-foreground/70 leading-relaxed">
                Each KSI shows the specific ACE C3 modules that provide coverage, what they actually do, and whether coverage is direct (the module performs the KSI function), supporting (the module contributes evidence or partial coverage), or planned (capability is on the roadmap).
              </p>
            </div>
          ) : (
            <div>
              <p className="text-sm text-muted-foreground leading-relaxed mb-3">
                <span className="text-primary font-display tracking-wider">AGENCY VIEW</span> — ACE C3 provides federal agencies with a passive monitoring and oversight capability for evaluating CSP security posture. Agencies do not run, trigger, or conduct their own penetration tests or active testing through the platform. Instead, agencies can monitor CSP status through passive discovery and enumeration, ingest CSP-submitted scan reports and assessment evidence, and track remediation status across all KSI themes.
              </p>
              <div className="mt-3 p-3 bg-primary/5 border border-primary/20">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                  <div className="text-xs text-muted-foreground leading-relaxed">
                    <span className="text-primary font-display tracking-wider">AGENCY MONITORING MODEL</span> — Agencies consume evidence produced by CSPs using ACE C3 — they do not initiate scans or active tests. Each KSI below describes what CSP-submitted evidence agencies can review, how passive discovery and enumeration supports independent verification, and how remediation tracking enables continuous monitoring decisions.
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
                ? `ACE C3 covers ${COVERAGE_PCT}% of all ${TOTAL_KSIS} KSIs today — ${DIRECT} with direct coverage and ${SUPPORTING} with supporting evidence. Automated validation, evidence generation, and OSCAL export for FedRAMP submission.`
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
