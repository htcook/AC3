// Compliance Framework Mappings — Maps security findings to NIST CSF, CIS Controls v8, ISO 27001:2022
// Used by the Compliance Frameworks page and engagement report compliance tabs

export interface FrameworkControl {
  id: string;
  name: string;
  description: string;
  category: string;
  findingTypes: string[]; // maps to types of findings that test this control
  severity: "critical" | "high" | "medium" | "low";
}

export interface FrameworkCategory {
  id: string;
  name: string;
  description: string;
  color: string;
  controls: FrameworkControl[];
}

// ─── NIST CSF 2.0 ─────────────────────────────────────────────────────────────

export const NIST_CSF_CATEGORIES: FrameworkCategory[] = [
  {
    id: "GV",
    name: "GOVERN",
    description: "Establish and monitor cybersecurity risk management strategy, expectations, and policy",
    color: "purple",
    controls: [
      { id: "GV.OC-01", name: "Organizational Context", description: "The organizational mission is understood and informs cybersecurity risk management", category: "GV", findingTypes: ["policy_gap", "governance"], severity: "medium" },
      { id: "GV.RM-01", name: "Risk Management Strategy", description: "Risk management objectives are established and expressed as risk tolerance statements", category: "GV", findingTypes: ["risk_assessment", "governance"], severity: "medium" },
      { id: "GV.SC-01", name: "Supply Chain Risk", description: "Cyber supply chain risk management program is established", category: "GV", findingTypes: ["supply_chain", "third_party"], severity: "high" },
    ],
  },
  {
    id: "ID",
    name: "IDENTIFY",
    description: "Understand the organization's cybersecurity risk to systems, assets, data, and capabilities",
    color: "blue",
    controls: [
      { id: "ID.AM-01", name: "Asset Management", description: "Inventories of hardware, software, services, and data are maintained", category: "ID", findingTypes: ["asset_discovery", "shadow_it", "unmanaged_asset"], severity: "high" },
      { id: "ID.AM-02", name: "Software Inventory", description: "Software platforms and applications are inventoried", category: "ID", findingTypes: ["software_inventory", "outdated_software"], severity: "medium" },
      { id: "ID.RA-01", name: "Vulnerability Identification", description: "Vulnerabilities in assets are identified, validated, and recorded", category: "ID", findingTypes: ["vulnerability", "cve", "missing_patch"], severity: "critical" },
      { id: "ID.RA-02", name: "Threat Intelligence", description: "Cyber threat intelligence is received from information sharing forums and sources", category: "ID", findingTypes: ["threat_intel", "ioc_match"], severity: "high" },
      { id: "ID.RA-05", name: "Risk Assessment", description: "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk", category: "ID", findingTypes: ["risk_assessment", "attack_surface"], severity: "high" },
    ],
  },
  {
    id: "PR",
    name: "PROTECT",
    description: "Develop and implement appropriate safeguards to ensure delivery of services",
    color: "green",
    controls: [
      { id: "PR.AA-01", name: "Identity Management", description: "Identities and credentials for authorized users, services, and hardware are managed", category: "PR", findingTypes: ["weak_credentials", "credential_exposure", "password_policy"], severity: "critical" },
      { id: "PR.AA-03", name: "Access Control", description: "Access permissions and authorizations are managed, incorporating least privilege and separation of duties", category: "PR", findingTypes: ["excessive_permissions", "privilege_escalation", "access_control"], severity: "critical" },
      { id: "PR.AA-05", name: "Multi-Factor Authentication", description: "MFA is implemented for access to sensitive resources", category: "PR", findingTypes: ["missing_mfa", "authentication_bypass"], severity: "critical" },
      { id: "PR.AT-01", name: "Security Awareness Training", description: "Personnel are provided awareness and training so they can perform cybersecurity-related duties", category: "PR", findingTypes: ["phishing_susceptibility", "social_engineering", "click_rate"], severity: "high" },
      { id: "PR.DS-01", name: "Data Protection", description: "Data-at-rest is protected", category: "PR", findingTypes: ["data_exposure", "unencrypted_data", "sensitive_data"], severity: "critical" },
      { id: "PR.DS-02", name: "Data-in-Transit", description: "Data-in-transit is protected", category: "PR", findingTypes: ["ssl_tls_issue", "cleartext_protocol", "certificate_issue"], severity: "high" },
      { id: "PR.PS-01", name: "Configuration Management", description: "Configuration management practices are established and applied", category: "PR", findingTypes: ["misconfiguration", "default_config", "hardening_gap"], severity: "high" },
      { id: "PR.IR-01", name: "Network Security", description: "Networks and environments are protected from unauthorized logical access", category: "PR", findingTypes: ["open_port", "network_exposure", "firewall_gap"], severity: "high" },
    ],
  },
  {
    id: "DE",
    name: "DETECT",
    description: "Develop and implement appropriate activities to identify the occurrence of a cybersecurity event",
    color: "yellow",
    controls: [
      { id: "DE.CM-01", name: "Continuous Monitoring", description: "Networks and network services are monitored to find potentially adverse events", category: "DE", findingTypes: ["detection_gap", "monitoring_blind_spot", "log_gap"], severity: "high" },
      { id: "DE.CM-06", name: "External Service Monitoring", description: "External service provider activity and services are monitored", category: "DE", findingTypes: ["third_party_risk", "external_service"], severity: "medium" },
      { id: "DE.AE-02", name: "Anomaly Detection", description: "Potentially adverse events are analyzed to better understand associated activities", category: "DE", findingTypes: ["anomaly", "behavioral_detection", "evasion"], severity: "high" },
      { id: "DE.AE-06", name: "Incident Correlation", description: "Information on adverse events is correlated from multiple sources", category: "DE", findingTypes: ["siem_gap", "correlation_failure", "alert_fatigue"], severity: "medium" },
    ],
  },
  {
    id: "RS",
    name: "RESPOND",
    description: "Develop and implement appropriate activities to take action regarding a detected cybersecurity event",
    color: "orange",
    controls: [
      { id: "RS.MA-01", name: "Incident Management", description: "Incidents are managed from detection through resolution", category: "RS", findingTypes: ["incident_response", "response_time", "containment"], severity: "high" },
      { id: "RS.AN-03", name: "Incident Analysis", description: "Analysis is performed to determine what has taken place during an incident", category: "RS", findingTypes: ["forensic_gap", "investigation"], severity: "medium" },
      { id: "RS.MI-01", name: "Incident Mitigation", description: "Incidents are contained and mitigated", category: "RS", findingTypes: ["lateral_movement", "persistence", "c2_communication"], severity: "critical" },
    ],
  },
  {
    id: "RC",
    name: "RECOVER",
    description: "Develop and implement appropriate activities to maintain plans for resilience and restore capabilities",
    color: "cyan",
    controls: [
      { id: "RC.RP-01", name: "Recovery Planning", description: "Recovery plan is executed during or after a cybersecurity incident", category: "RC", findingTypes: ["recovery_gap", "backup_failure", "disaster_recovery"], severity: "high" },
      { id: "RC.CO-03", name: "Recovery Communication", description: "Recovery activities and progress are communicated to stakeholders", category: "RC", findingTypes: ["communication_gap"], severity: "low" },
    ],
  },
];

// ─── CIS Controls v8 ──────────────────────────────────────────────────────────

export const CIS_CONTROLS: FrameworkCategory[] = [
  {
    id: "IG1",
    name: "IMPLEMENTATION GROUP 1 — Basic Hygiene",
    description: "Essential cyber hygiene — the minimum standard of information security for all enterprises",
    color: "emerald",
    controls: [
      { id: "CIS-1", name: "Inventory & Control of Enterprise Assets", description: "Actively manage all enterprise assets connected to the infrastructure", category: "IG1", findingTypes: ["asset_discovery", "unmanaged_asset", "shadow_it"], severity: "high" },
      { id: "CIS-2", name: "Inventory & Control of Software Assets", description: "Actively manage all software on the network", category: "IG1", findingTypes: ["software_inventory", "unauthorized_software", "outdated_software"], severity: "high" },
      { id: "CIS-3", name: "Data Protection", description: "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data", category: "IG1", findingTypes: ["data_exposure", "sensitive_data", "unencrypted_data"], severity: "critical" },
      { id: "CIS-4", name: "Secure Configuration", description: "Establish and maintain secure configurations for enterprise assets and software", category: "IG1", findingTypes: ["misconfiguration", "default_config", "hardening_gap"], severity: "high" },
      { id: "CIS-5", name: "Account Management", description: "Use processes and tools to assign and manage authorization to credentials for user accounts", category: "IG1", findingTypes: ["weak_credentials", "credential_exposure", "password_policy", "excessive_permissions"], severity: "critical" },
      { id: "CIS-6", name: "Access Control Management", description: "Use processes and tools to create, assign, manage, and revoke access credentials and privileges", category: "IG1", findingTypes: ["access_control", "privilege_escalation", "missing_mfa"], severity: "critical" },
      { id: "CIS-7", name: "Continuous Vulnerability Management", description: "Develop a plan to continuously assess and track vulnerabilities on all enterprise assets", category: "IG1", findingTypes: ["vulnerability", "cve", "missing_patch", "outdated_software"], severity: "critical" },
      { id: "CIS-14", name: "Security Awareness & Skills Training", description: "Establish and maintain a security awareness program", category: "IG1", findingTypes: ["phishing_susceptibility", "social_engineering", "click_rate"], severity: "high" },
    ],
  },
  {
    id: "IG2",
    name: "IMPLEMENTATION GROUP 2 — Foundational",
    description: "For enterprises managing IT infrastructure of varying complexity with sensitive data",
    color: "blue",
    controls: [
      { id: "CIS-8", name: "Audit Log Management", description: "Collect, alert, review, and retain audit logs of events", category: "IG2", findingTypes: ["log_gap", "monitoring_blind_spot", "audit_failure"], severity: "high" },
      { id: "CIS-9", name: "Email & Web Browser Protections", description: "Improve protections and detections of threats from email and web vectors", category: "IG2", findingTypes: ["email_security", "spf_dkim_dmarc", "web_filter_bypass"], severity: "high" },
      { id: "CIS-10", name: "Malware Defenses", description: "Prevent or control the installation, spread, and execution of malicious applications", category: "IG2", findingTypes: ["malware_detection", "av_bypass", "evasion"], severity: "critical" },
      { id: "CIS-11", name: "Data Recovery", description: "Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets", category: "IG2", findingTypes: ["backup_failure", "recovery_gap", "disaster_recovery"], severity: "high" },
      { id: "CIS-12", name: "Network Infrastructure Management", description: "Establish and maintain the management and security of network infrastructure", category: "IG2", findingTypes: ["network_exposure", "open_port", "firewall_gap", "dns_issue"], severity: "high" },
      { id: "CIS-13", name: "Network Monitoring & Defense", description: "Operate processes and tooling to establish and maintain comprehensive network monitoring", category: "IG2", findingTypes: ["detection_gap", "siem_gap", "correlation_failure"], severity: "high" },
      { id: "CIS-15", name: "Service Provider Management", description: "Develop a process to evaluate service providers who hold sensitive data", category: "IG2", findingTypes: ["third_party_risk", "supply_chain", "external_service"], severity: "medium" },
      { id: "CIS-16", name: "Application Software Security", description: "Manage the security life cycle of in-house developed, hosted, or acquired software", category: "IG2", findingTypes: ["application_vulnerability", "code_injection", "xss", "sqli"], severity: "critical" },
    ],
  },
  {
    id: "IG3",
    name: "IMPLEMENTATION GROUP 3 — Organizational",
    description: "For enterprises with security experts specializing in different facets of cybersecurity",
    color: "purple",
    controls: [
      { id: "CIS-17", name: "Incident Response Management", description: "Establish a program to develop and maintain an incident response capability", category: "IG3", findingTypes: ["incident_response", "response_time", "containment", "forensic_gap"], severity: "high" },
      { id: "CIS-18", name: "Penetration Testing", description: "Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses", category: "IG3", findingTypes: ["penetration_test", "exploitation", "lateral_movement", "persistence"], severity: "critical" },
    ],
  },
];

// ─── ISO 27001:2022 ───────────────────────────────────────────────────────────

export const ISO_27001_CATEGORIES: FrameworkCategory[] = [
  {
    id: "A5",
    name: "A.5 — Organizational Controls",
    description: "Policies, roles, responsibilities, and management direction for information security",
    color: "indigo",
    controls: [
      { id: "A.5.1", name: "Policies for Information Security", description: "Information security policy and topic-specific policies shall be defined and approved", category: "A5", findingTypes: ["policy_gap", "governance"], severity: "medium" },
      { id: "A.5.7", name: "Threat Intelligence", description: "Information relating to information security threats shall be collected and analyzed", category: "A5", findingTypes: ["threat_intel", "ioc_match", "threat_actor"], severity: "high" },
      { id: "A.5.23", name: "Cloud Services Security", description: "Processes for acquisition, use, management, and exit from cloud services shall be established", category: "A5", findingTypes: ["cloud_misconfiguration", "cloud_exposure"], severity: "high" },
      { id: "A.5.30", name: "ICT Readiness for Business Continuity", description: "ICT readiness shall be planned, implemented, maintained, and tested", category: "A5", findingTypes: ["disaster_recovery", "backup_failure", "recovery_gap"], severity: "high" },
    ],
  },
  {
    id: "A6",
    name: "A.6 — People Controls",
    description: "Human resource security, awareness, and training",
    color: "pink",
    controls: [
      { id: "A.6.3", name: "Information Security Awareness & Training", description: "Personnel shall receive appropriate security awareness education and training", category: "A6", findingTypes: ["phishing_susceptibility", "social_engineering", "click_rate"], severity: "high" },
      { id: "A.6.8", name: "Information Security Event Reporting", description: "Personnel shall report observed or suspected information security events", category: "A6", findingTypes: ["reporting_gap", "incident_response"], severity: "medium" },
    ],
  },
  {
    id: "A7",
    name: "A.7 — Physical Controls",
    description: "Physical security perimeters, entry controls, and environmental threats",
    color: "amber",
    controls: [
      { id: "A.7.4", name: "Physical Security Monitoring", description: "Premises shall be continuously monitored for unauthorized physical access", category: "A7", findingTypes: ["physical_access", "badge_cloning"], severity: "medium" },
    ],
  },
  {
    id: "A8",
    name: "A.8 — Technological Controls",
    description: "Technical security controls for systems, networks, and applications",
    color: "cyan",
    controls: [
      { id: "A.8.1", name: "User Endpoint Devices", description: "Information stored on, processed by, or accessible via user endpoint devices shall be protected", category: "A8", findingTypes: ["endpoint_security", "device_compromise"], severity: "high" },
      { id: "A.8.2", name: "Privileged Access Rights", description: "The allocation and use of privileged access rights shall be restricted and managed", category: "A8", findingTypes: ["privilege_escalation", "excessive_permissions", "admin_access"], severity: "critical" },
      { id: "A.8.3", name: "Information Access Restriction", description: "Access to information and other associated assets shall be restricted", category: "A8", findingTypes: ["access_control", "data_exposure", "authorization_bypass"], severity: "critical" },
      { id: "A.8.5", name: "Secure Authentication", description: "Secure authentication technologies and procedures shall be established", category: "A8", findingTypes: ["weak_credentials", "missing_mfa", "authentication_bypass", "credential_exposure"], severity: "critical" },
      { id: "A.8.7", name: "Protection Against Malware", description: "Protection against malware shall be implemented", category: "A8", findingTypes: ["malware_detection", "av_bypass", "evasion"], severity: "critical" },
      { id: "A.8.8", name: "Management of Technical Vulnerabilities", description: "Information about technical vulnerabilities shall be obtained and appropriate measures taken", category: "A8", findingTypes: ["vulnerability", "cve", "missing_patch", "outdated_software"], severity: "critical" },
      { id: "A.8.9", name: "Configuration Management", description: "Configurations, including security configurations, of hardware, software, services, and networks shall be established", category: "A8", findingTypes: ["misconfiguration", "default_config", "hardening_gap"], severity: "high" },
      { id: "A.8.15", name: "Logging", description: "Logs that record activities, exceptions, faults, and other relevant events shall be produced and stored", category: "A8", findingTypes: ["log_gap", "monitoring_blind_spot", "audit_failure"], severity: "high" },
      { id: "A.8.16", name: "Monitoring Activities", description: "Networks, systems, and applications shall be monitored for anomalous behavior", category: "A8", findingTypes: ["detection_gap", "siem_gap", "behavioral_detection"], severity: "high" },
      { id: "A.8.20", name: "Network Security", description: "Networks and network devices shall be secured, managed, and controlled", category: "A8", findingTypes: ["network_exposure", "open_port", "firewall_gap"], severity: "high" },
      { id: "A.8.24", name: "Use of Cryptography", description: "Rules for the effective use of cryptography shall be defined and implemented", category: "A8", findingTypes: ["ssl_tls_issue", "weak_encryption", "certificate_issue", "cleartext_protocol"], severity: "high" },
      { id: "A.8.25", name: "Secure Development Life Cycle", description: "Rules for the secure development of software and systems shall be established", category: "A8", findingTypes: ["application_vulnerability", "code_injection", "xss", "sqli"], severity: "critical" },
      { id: "A.8.28", name: "Secure Coding", description: "Secure coding principles shall be applied to software development", category: "A8", findingTypes: ["code_injection", "xss", "sqli", "application_vulnerability"], severity: "critical" },
    ],
  },
];

// ─── Finding Type Classifier ──────────────────────────────────────────────────
// Maps common security finding descriptions to finding types used in framework mappings

export const FINDING_TYPE_KEYWORDS: Record<string, string[]> = {
  vulnerability: ["cve", "vulnerability", "vulnerable", "exploit", "exploitable"],
  cve: ["cve-", "CVE-"],
  missing_patch: ["patch", "update", "outdated", "end of life", "eol", "unsupported"],
  outdated_software: ["outdated", "deprecated", "legacy", "end of life"],
  weak_credentials: ["weak password", "default password", "credential", "brute force", "password spray"],
  credential_exposure: ["credential", "leaked", "exposed", "breach", "dehashed", "password dump"],
  missing_mfa: ["mfa", "multi-factor", "two-factor", "2fa", "no mfa"],
  phishing_susceptibility: ["phishing", "click rate", "credential harvest", "social engineering"],
  social_engineering: ["social engineering", "pretexting", "vishing", "smishing"],
  ssl_tls_issue: ["ssl", "tls", "certificate", "https", "cleartext"],
  misconfiguration: ["misconfigur", "default config", "hardening", "security header"],
  open_port: ["open port", "exposed port", "unnecessary service", "port scan"],
  network_exposure: ["exposed", "internet-facing", "public access", "network exposure"],
  data_exposure: ["data leak", "sensitive data", "pii", "exposed data", "information disclosure"],
  detection_gap: ["detection", "undetected", "blind spot", "no alert", "evasion"],
  lateral_movement: ["lateral movement", "pivot", "internal spread"],
  privilege_escalation: ["privilege escalation", "privesc", "admin access", "root access"],
  access_control: ["access control", "authorization", "rbac", "permission"],
  email_security: ["spf", "dkim", "dmarc", "email security", "mail"],
  dns_issue: ["dns", "subdomain", "zone transfer", "dangling"],
  asset_discovery: ["asset", "subdomain", "host discovery", "enumeration"],
  incident_response: ["incident response", "ir plan", "response time"],
};

// ─── Compliance Score Calculator ──────────────────────────────────────────────

export interface ComplianceScore {
  framework: string;
  totalControls: number;
  testedControls: number;
  passedControls: number;
  failedControls: number;
  notTestedControls: number;
  score: number; // 0-100
  grade: "A" | "B" | "C" | "D" | "F";
  status: "compliant" | "partial" | "at_risk" | "non_compliant";
}

export function calculateComplianceGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function calculateComplianceStatus(score: number): "compliant" | "partial" | "at_risk" | "non_compliant" {
  if (score >= 85) return "compliant";
  if (score >= 70) return "partial";
  if (score >= 50) return "at_risk";
  return "non_compliant";
}

export function classifyFindingTypes(findingDescription: string): string[] {
  const desc = findingDescription.toLowerCase();
  const matched: string[] = [];
  for (const [type, keywords] of Object.entries(FINDING_TYPE_KEYWORDS)) {
    if (keywords.some(kw => desc.includes(kw.toLowerCase()))) {
      matched.push(type);
    }
  }
  return matched.length > 0 ? matched : ["general"];
}

export function mapFindingsToControls(
  findingTypes: string[],
  framework: "nist_csf" | "cis_controls" | "iso_27001"
): FrameworkControl[] {
  const categories = framework === "nist_csf"
    ? NIST_CSF_CATEGORIES
    : framework === "cis_controls"
    ? CIS_CONTROLS
    : ISO_27001_CATEGORIES;

  const matched: FrameworkControl[] = [];
  for (const cat of categories) {
    for (const ctrl of cat.controls) {
      if (ctrl.findingTypes.some(ft => findingTypes.includes(ft))) {
        matched.push(ctrl);
      }
    }
  }
  return matched;
}
