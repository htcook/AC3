/**
 * Compliance Evidence Auto-Mapper
 *
 * Automatically maps engagement scan findings, tool results, and vulnerability
 * data to compliance framework controls (SOC 2, FedRAMP, CMMC, ISO 27001,
 * HIPAA, PCI DSS, NIST CSF) to generate real evidence artifacts.
 *
 * This module:
 *   1. Takes engagement state (assets, vulns, tool results, ZAP findings)
 *   2. Maps each finding to relevant compliance controls across all frameworks
 *   3. Generates evidence records with timestamps, tool provenance, and severity
 *   4. Produces a compliance posture summary showing which controls have evidence
 *   5. Identifies gaps where no evidence exists for required controls
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ComplianceEvidence {
  id: string;
  controlId: string;
  framework: string;
  controlTitle: string;
  evidenceType: "scan_result" | "vuln_finding" | "tool_output" | "config_check" | "credential_test" | "zap_finding" | "owasp_coverage";
  source: string;        // tool name (nmap, nuclei, hydra, zap, nikto, etc.)
  asset: string;         // hostname or IP
  title: string;         // finding title
  description: string;   // evidence description
  severity: string;
  timestamp: number;
  rawSnippet?: string;   // truncated raw output for proof
  status: "pass" | "fail" | "partial" | "informational";
  engagementId: number;
}

export interface ControlPosture {
  controlId: string;
  framework: string;
  controlTitle: string;
  family: string;
  evidenceCount: number;
  passCount: number;
  failCount: number;
  partialCount: number;
  overallStatus: "compliant" | "non_compliant" | "partial" | "no_evidence";
  lastEvidenceTimestamp: number | null;
}

export interface CompliancePostureSummary {
  framework: string;
  totalControls: number;
  compliant: number;
  nonCompliant: number;
  partial: number;
  noEvidence: number;
  complianceScore: number; // 0-100
  controls: ControlPosture[];
  generatedAt: number;
  engagementId: number;
}

export interface EvidenceMapperResult {
  evidence: ComplianceEvidence[];
  summaries: CompliancePostureSummary[];
  totalEvidenceItems: number;
  frameworksCovered: string[];
  gapCount: number;
}

// ─── Control Mapping Rules ──────────────────────────────────────────────────
// Maps tool types and finding categories to compliance controls across frameworks.
// Each rule matches findings by tool, severity pattern, or title pattern and maps
// them to specific controls in each framework.

interface MappingRule {
  id: string;
  name: string;
  matchTool?: string[];                 // match by tool name
  matchTitlePattern?: RegExp;           // match by finding title
  matchSeverityMin?: string;            // minimum severity to match
  matchCategory?: string[];             // match by category
  controls: {
    framework: string;
    controlId: string;
    controlTitle: string;
    family: string;
    evidenceType: ComplianceEvidence["evidenceType"];
    statusLogic: "pass_if_no_finding" | "fail_if_finding" | "informational" | "pass_if_finding";
  }[];
}

const MAPPING_RULES: MappingRule[] = [
  // ─── Network Scanning (nmap) ───
  {
    id: "nmap-port-scan",
    name: "Network Port Discovery",
    matchTool: ["nmap"],
    controls: [
      { framework: "SOC2", controlId: "CC6.1", controlTitle: "Logical and Physical Access Controls", family: "Common Criteria", evidenceType: "scan_result", statusLogic: "informational" },
      { framework: "SOC2", controlId: "CC6.6", controlTitle: "Logical Access Security Measures", family: "Common Criteria", evidenceType: "scan_result", statusLogic: "informational" },
      { framework: "FedRAMP", controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", evidenceType: "scan_result", statusLogic: "informational" },
      { framework: "FedRAMP", controlId: "SC-7", controlTitle: "Boundary Protection", family: "System and Communications Protection", evidenceType: "scan_result", statusLogic: "informational" },
      { framework: "CMMC", controlId: "SC.L2-3.13.1", controlTitle: "Boundary Protection", family: "System and Communications Protection", evidenceType: "scan_result", statusLogic: "informational" },
      { framework: "ISO27001", controlId: "A.13.1.1", controlTitle: "Network Controls", family: "Communications Security", evidenceType: "scan_result", statusLogic: "informational" },
      { framework: "PCI_DSS", controlId: "11.2", controlTitle: "Network Vulnerability Scans", family: "Regular Testing", evidenceType: "scan_result", statusLogic: "pass_if_finding" },
      { framework: "NIST_CSF", controlId: "DE.CM-1", controlTitle: "Network Monitoring", family: "Detect", evidenceType: "scan_result", statusLogic: "pass_if_finding" },
    ],
  },
  // ─── Vulnerability Scanning (nuclei) ───
  {
    id: "nuclei-vuln-scan",
    name: "Vulnerability Detection",
    matchTool: ["nuclei"],
    controls: [
      { framework: "SOC2", controlId: "CC7.1", controlTitle: "Detection and Monitoring", family: "Common Criteria", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
      { framework: "SOC2", controlId: "CC8.1", controlTitle: "Change Management", family: "Common Criteria", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "RA-5", controlTitle: "Vulnerability Monitoring and Scanning", family: "Risk Assessment", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
      { framework: "FedRAMP", controlId: "SI-2", controlTitle: "Flaw Remediation", family: "System and Information Integrity", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "CMMC", controlId: "RA.L2-3.11.2", controlTitle: "Vulnerability Scan", family: "Risk Assessment", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
      { framework: "CMMC", controlId: "SI.L2-3.14.1", controlTitle: "Flaw Remediation", family: "System and Information Integrity", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "ISO27001", controlId: "A.12.6.1", controlTitle: "Management of Technical Vulnerabilities", family: "Operations Security", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
      { framework: "PCI_DSS", controlId: "6.1", controlTitle: "Identify Security Vulnerabilities", family: "Secure Systems", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
      { framework: "PCI_DSS", controlId: "11.2", controlTitle: "Network Vulnerability Scans", family: "Regular Testing", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
      { framework: "HIPAA", controlId: "164.308(a)(1)(ii)(A)", controlTitle: "Risk Analysis", family: "Administrative Safeguards", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
      { framework: "NIST_CSF", controlId: "ID.RA-1", controlTitle: "Asset Vulnerabilities Identified", family: "Identify", evidenceType: "vuln_finding", statusLogic: "pass_if_finding" },
    ],
  },
  // ─── Web Application Scanning (ZAP) ───
  {
    id: "zap-web-scan",
    name: "Web Application Security Testing",
    matchTool: ["zap", "owasp-zap"],
    controls: [
      { framework: "SOC2", controlId: "CC6.1", controlTitle: "Logical and Physical Access Controls", family: "Common Criteria", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
      { framework: "SOC2", controlId: "CC7.1", controlTitle: "Detection and Monitoring", family: "Common Criteria", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
      { framework: "FedRAMP", controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
      { framework: "FedRAMP", controlId: "RA-5", controlTitle: "Vulnerability Monitoring and Scanning", family: "Risk Assessment", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
      { framework: "CMMC", controlId: "RA.L2-3.11.2", controlTitle: "Vulnerability Scan", family: "Risk Assessment", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
      { framework: "ISO27001", controlId: "A.14.2.8", controlTitle: "System Security Testing", family: "System Acquisition", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
      { framework: "PCI_DSS", controlId: "6.6", controlTitle: "Web Application Security", family: "Secure Systems", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
      { framework: "NIST_CSF", controlId: "PR.IP-12", controlTitle: "Vulnerability Management Plan", family: "Protect", evidenceType: "zap_finding", statusLogic: "pass_if_finding" },
    ],
  },
  // ─── Credential Testing (Hydra) ───
  {
    id: "hydra-cred-test",
    name: "Credential Strength Testing",
    matchTool: ["hydra"],
    controls: [
      { framework: "SOC2", controlId: "CC6.1", controlTitle: "Logical and Physical Access Controls", family: "Common Criteria", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "SOC2", controlId: "CC6.2", controlTitle: "Prior to Issuing System Credentials", family: "Common Criteria", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "IA-5", controlTitle: "Authenticator Management", family: "Identification and Authentication", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "AC-7", controlTitle: "Unsuccessful Logon Attempts", family: "Access Control", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "CMMC", controlId: "IA.L2-3.5.7", controlTitle: "Password Complexity", family: "Identification and Authentication", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "ISO27001", controlId: "A.9.4.3", controlTitle: "Password Management System", family: "Access Control", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "PCI_DSS", controlId: "8.2.3", controlTitle: "Password Complexity Requirements", family: "Access Management", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "HIPAA", controlId: "164.312(d)", controlTitle: "Person or Entity Authentication", family: "Technical Safeguards", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
      { framework: "NIST_CSF", controlId: "PR.AC-1", controlTitle: "Identities and Credentials Managed", family: "Protect", evidenceType: "credential_test", statusLogic: "fail_if_finding" },
    ],
  },
  // ─── SSL/TLS Findings ───
  {
    id: "ssl-tls-findings",
    name: "Encryption and Transport Security",
    matchTitlePattern: /ssl|tls|certificate|cipher|https|hsts/i,
    controls: [
      { framework: "SOC2", controlId: "CC6.7", controlTitle: "Restriction of Data Transmission", family: "Common Criteria", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity", family: "System and Communications Protection", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "SC-13", controlTitle: "Cryptographic Protection", family: "System and Communications Protection", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "CMMC", controlId: "SC.L2-3.13.8", controlTitle: "Data in Transit", family: "System and Communications Protection", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "ISO27001", controlId: "A.10.1.1", controlTitle: "Policy on Use of Cryptographic Controls", family: "Cryptography", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "PCI_DSS", controlId: "4.1", controlTitle: "Strong Cryptography for Transmission", family: "Encryption", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "HIPAA", controlId: "164.312(e)(1)", controlTitle: "Transmission Security", family: "Technical Safeguards", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "NIST_CSF", controlId: "PR.DS-2", controlTitle: "Data-in-Transit Protected", family: "Protect", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
    ],
  },
  // ─── Injection Vulnerabilities (SQLi, XSS, Command Injection) ───
  {
    id: "injection-vulns",
    name: "Injection Vulnerability Detection",
    matchTitlePattern: /injection|sqli|xss|cross.?site|command.?inject|rce|remote.?code/i,
    controls: [
      { framework: "SOC2", controlId: "CC6.1", controlTitle: "Logical and Physical Access Controls", family: "Common Criteria", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "CMMC", controlId: "SI.L2-3.14.1", controlTitle: "Flaw Remediation", family: "System and Information Integrity", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "ISO27001", controlId: "A.14.2.5", controlTitle: "Secure System Engineering Principles", family: "System Acquisition", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "PCI_DSS", controlId: "6.5.1", controlTitle: "Injection Flaws", family: "Secure Systems", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "NIST_CSF", controlId: "PR.IP-12", controlTitle: "Vulnerability Management Plan", family: "Protect", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
    ],
  },
  // ─── Authentication / Access Control Findings ───
  {
    id: "auth-access-findings",
    name: "Authentication and Access Control Issues",
    matchTitlePattern: /auth|login|session|token|cookie|access.?control|privilege|escalat|bypass|brute/i,
    controls: [
      { framework: "SOC2", controlId: "CC6.1", controlTitle: "Logical and Physical Access Controls", family: "Common Criteria", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "SOC2", controlId: "CC6.3", controlTitle: "Role-Based Access", family: "Common Criteria", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "AC-2", controlTitle: "Account Management", family: "Access Control", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "IA-2", controlTitle: "Identification and Authentication", family: "Identification and Authentication", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "CMMC", controlId: "AC.L2-3.1.1", controlTitle: "Authorized Access Control", family: "Access Control", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "ISO27001", controlId: "A.9.2.1", controlTitle: "User Registration and De-registration", family: "Access Control", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "PCI_DSS", controlId: "8.1", controlTitle: "Unique User Identification", family: "Access Management", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "HIPAA", controlId: "164.312(d)", controlTitle: "Person or Entity Authentication", family: "Technical Safeguards", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "NIST_CSF", controlId: "PR.AC-7", controlTitle: "Authentication Mechanisms", family: "Protect", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
    ],
  },
  // ─── Information Disclosure ───
  {
    id: "info-disclosure",
    name: "Information Disclosure Detection",
    matchTitlePattern: /disclosure|exposed|leak|sensitive|directory.?list|backup|debug|stack.?trace|error.?message|server.?header/i,
    controls: [
      { framework: "SOC2", controlId: "CC6.7", controlTitle: "Restriction of Data Transmission", family: "Common Criteria", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "SC-28", controlTitle: "Protection of Information at Rest", family: "System and Communications Protection", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "CMMC", controlId: "SC.L2-3.13.16", controlTitle: "Data at Rest", family: "System and Communications Protection", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "ISO27001", controlId: "A.18.1.4", controlTitle: "Privacy and Protection of PII", family: "Compliance", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "PCI_DSS", controlId: "3.4", controlTitle: "Render PAN Unreadable", family: "Data Protection", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "HIPAA", controlId: "164.312(a)(2)(iv)", controlTitle: "Encryption and Decryption", family: "Technical Safeguards", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
      { framework: "NIST_CSF", controlId: "PR.DS-1", controlTitle: "Data-at-Rest Protected", family: "Protect", evidenceType: "vuln_finding", statusLogic: "fail_if_finding" },
    ],
  },
  // ─── Exploitation Results ───
  {
    id: "exploitation-results",
    name: "Penetration Test Exploitation Evidence",
    matchTool: ["metasploit", "exploit", "manual-exploit"],
    controls: [
      { framework: "SOC2", controlId: "CC4.1", controlTitle: "COSO Principle 16 - Monitoring Activities", family: "Common Criteria", evidenceType: "tool_output", statusLogic: "pass_if_finding" },
      { framework: "FedRAMP", controlId: "CA-8", controlTitle: "Penetration Testing", family: "Assessment, Authorization, and Monitoring", evidenceType: "tool_output", statusLogic: "pass_if_finding" },
      { framework: "CMMC", controlId: "CA.L2-3.12.1", controlTitle: "Security Control Assessment", family: "Assessment, Authorization, and Monitoring", evidenceType: "tool_output", statusLogic: "pass_if_finding" },
      { framework: "ISO27001", controlId: "A.18.2.3", controlTitle: "Technical Compliance Review", family: "Compliance", evidenceType: "tool_output", statusLogic: "pass_if_finding" },
      { framework: "PCI_DSS", controlId: "11.3", controlTitle: "Penetration Testing", family: "Regular Testing", evidenceType: "tool_output", statusLogic: "pass_if_finding" },
      { framework: "NIST_CSF", controlId: "DE.DP-4", controlTitle: "Detection Process Improvement", family: "Detect", evidenceType: "tool_output", statusLogic: "pass_if_finding" },
    ],
  },
  // ─── Configuration / Hardening ───
  {
    id: "config-hardening",
    name: "Configuration and Hardening Checks",
    matchTitlePattern: /misconfigur|default|hardening|security.?header|cors|csp|x-frame|clickjack|open.?redirect/i,
    controls: [
      { framework: "SOC2", controlId: "CC6.6", controlTitle: "Logical Access Security Measures", family: "Common Criteria", evidenceType: "config_check", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "CM-6", controlTitle: "Configuration Settings", family: "Configuration Management", evidenceType: "config_check", statusLogic: "fail_if_finding" },
      { framework: "FedRAMP", controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", evidenceType: "config_check", statusLogic: "fail_if_finding" },
      { framework: "CMMC", controlId: "CM.L2-3.4.2", controlTitle: "Security Configuration Enforcement", family: "Configuration Management", evidenceType: "config_check", statusLogic: "fail_if_finding" },
      { framework: "ISO27001", controlId: "A.14.1.1", controlTitle: "Information Security Requirements Analysis", family: "System Acquisition", evidenceType: "config_check", statusLogic: "fail_if_finding" },
      { framework: "PCI_DSS", controlId: "2.2", controlTitle: "Configuration Standards", family: "Secure Configuration", evidenceType: "config_check", statusLogic: "fail_if_finding" },
      { framework: "NIST_CSF", controlId: "PR.IP-1", controlTitle: "Baseline Configuration", family: "Protect", evidenceType: "config_check", statusLogic: "fail_if_finding" },
    ],
  },
  // ─── Nikto / Server Scanning ───
  {
    id: "nikto-server-scan",
    name: "Web Server Security Scanning",
    matchTool: ["nikto"],
    controls: [
      { framework: "SOC2", controlId: "CC7.1", controlTitle: "Detection and Monitoring", family: "Common Criteria", evidenceType: "scan_result", statusLogic: "pass_if_finding" },
      { framework: "FedRAMP", controlId: "RA-5", controlTitle: "Vulnerability Monitoring and Scanning", family: "Risk Assessment", evidenceType: "scan_result", statusLogic: "pass_if_finding" },
      { framework: "PCI_DSS", controlId: "11.2", controlTitle: "Network Vulnerability Scans", family: "Regular Testing", evidenceType: "scan_result", statusLogic: "pass_if_finding" },
      { framework: "NIST_CSF", controlId: "DE.CM-8", controlTitle: "Vulnerability Scans Performed", family: "Detect", evidenceType: "scan_result", statusLogic: "pass_if_finding" },
    ],
  },
];

// ─── All known controls per framework (for gap analysis) ───
const FRAMEWORK_CONTROLS: Record<string, { controlId: string; title: string; family: string }[]> = {
  SOC2: [
    { controlId: "CC1.1", title: "COSO Principle 1 - Integrity and Ethics", family: "Control Environment" },
    { controlId: "CC2.1", title: "COSO Principle 13 - Quality Information", family: "Communication and Information" },
    { controlId: "CC3.1", title: "COSO Principle 6 - Risk Assessment", family: "Risk Assessment" },
    { controlId: "CC4.1", title: "COSO Principle 16 - Monitoring Activities", family: "Monitoring Activities" },
    { controlId: "CC5.1", title: "COSO Principle 10 - Control Activities", family: "Control Activities" },
    { controlId: "CC6.1", title: "Logical and Physical Access Controls", family: "Logical and Physical Access" },
    { controlId: "CC6.2", title: "Prior to Issuing System Credentials", family: "Logical and Physical Access" },
    { controlId: "CC6.3", title: "Role-Based Access", family: "Logical and Physical Access" },
    { controlId: "CC6.6", title: "Logical Access Security Measures", family: "Logical and Physical Access" },
    { controlId: "CC6.7", title: "Restriction of Data Transmission", family: "Logical and Physical Access" },
    { controlId: "CC7.1", title: "Detection and Monitoring", family: "System Operations" },
    { controlId: "CC7.2", title: "Anomaly Detection and Response", family: "System Operations" },
    { controlId: "CC8.1", title: "Change Management", family: "Change Management" },
    { controlId: "CC9.1", title: "Risk Mitigation", family: "Risk Mitigation" },
  ],
  FedRAMP: [
    { controlId: "AC-2", title: "Account Management", family: "Access Control" },
    { controlId: "AC-7", title: "Unsuccessful Logon Attempts", family: "Access Control" },
    { controlId: "AU-2", title: "Event Logging", family: "Audit and Accountability" },
    { controlId: "CA-8", title: "Penetration Testing", family: "Assessment, Authorization, and Monitoring" },
    { controlId: "CM-6", title: "Configuration Settings", family: "Configuration Management" },
    { controlId: "CM-7", title: "Least Functionality", family: "Configuration Management" },
    { controlId: "IA-2", title: "Identification and Authentication", family: "Identification and Authentication" },
    { controlId: "IA-5", title: "Authenticator Management", family: "Identification and Authentication" },
    { controlId: "IR-4", title: "Incident Handling", family: "Incident Response" },
    { controlId: "RA-5", title: "Vulnerability Monitoring and Scanning", family: "Risk Assessment" },
    { controlId: "SA-11", title: "Developer Testing and Evaluation", family: "System and Services Acquisition" },
    { controlId: "SC-7", title: "Boundary Protection", family: "System and Communications Protection" },
    { controlId: "SC-8", title: "Transmission Confidentiality and Integrity", family: "System and Communications Protection" },
    { controlId: "SC-13", title: "Cryptographic Protection", family: "System and Communications Protection" },
    { controlId: "SC-28", title: "Protection of Information at Rest", family: "System and Communications Protection" },
    { controlId: "SI-2", title: "Flaw Remediation", family: "System and Information Integrity" },
    { controlId: "SI-10", title: "Information Input Validation", family: "System and Information Integrity" },
  ],
  CMMC: [
    { controlId: "AC.L2-3.1.1", title: "Authorized Access Control", family: "Access Control" },
    { controlId: "CA.L2-3.12.1", title: "Security Control Assessment", family: "Assessment, Authorization, and Monitoring" },
    { controlId: "CM.L2-3.4.2", title: "Security Configuration Enforcement", family: "Configuration Management" },
    { controlId: "IA.L2-3.5.7", title: "Password Complexity", family: "Identification and Authentication" },
    { controlId: "RA.L2-3.11.2", title: "Vulnerability Scan", family: "Risk Assessment" },
    { controlId: "SC.L2-3.13.1", title: "Boundary Protection", family: "System and Communications Protection" },
    { controlId: "SC.L2-3.13.8", title: "Data in Transit", family: "System and Communications Protection" },
    { controlId: "SC.L2-3.13.16", title: "Data at Rest", family: "System and Communications Protection" },
    { controlId: "SI.L2-3.14.1", title: "Flaw Remediation", family: "System and Information Integrity" },
  ],
  ISO27001: [
    { controlId: "A.9.2.1", title: "User Registration and De-registration", family: "Access Control" },
    { controlId: "A.9.4.3", title: "Password Management System", family: "Access Control" },
    { controlId: "A.10.1.1", title: "Policy on Use of Cryptographic Controls", family: "Cryptography" },
    { controlId: "A.12.6.1", title: "Management of Technical Vulnerabilities", family: "Operations Security" },
    { controlId: "A.13.1.1", title: "Network Controls", family: "Communications Security" },
    { controlId: "A.14.1.1", title: "Information Security Requirements Analysis", family: "System Acquisition" },
    { controlId: "A.14.2.5", title: "Secure System Engineering Principles", family: "System Acquisition" },
    { controlId: "A.14.2.8", title: "System Security Testing", family: "System Acquisition" },
    { controlId: "A.18.1.4", title: "Privacy and Protection of PII", family: "Compliance" },
    { controlId: "A.18.2.3", title: "Technical Compliance Review", family: "Compliance" },
  ],
  PCI_DSS: [
    { controlId: "2.2", title: "Configuration Standards", family: "Secure Configuration" },
    { controlId: "3.4", title: "Render PAN Unreadable", family: "Data Protection" },
    { controlId: "4.1", title: "Strong Cryptography for Transmission", family: "Encryption" },
    { controlId: "6.1", title: "Identify Security Vulnerabilities", family: "Secure Systems" },
    { controlId: "6.5.1", title: "Injection Flaws", family: "Secure Systems" },
    { controlId: "6.6", title: "Web Application Security", family: "Secure Systems" },
    { controlId: "8.1", title: "Unique User Identification", family: "Access Management" },
    { controlId: "8.2.3", title: "Password Complexity Requirements", family: "Access Management" },
    { controlId: "11.2", title: "Network Vulnerability Scans", family: "Regular Testing" },
    { controlId: "11.3", title: "Penetration Testing", family: "Regular Testing" },
  ],
  HIPAA: [
    { controlId: "164.308(a)(1)(ii)(A)", title: "Risk Analysis", family: "Administrative Safeguards" },
    { controlId: "164.312(a)(2)(iv)", title: "Encryption and Decryption", family: "Technical Safeguards" },
    { controlId: "164.312(d)", title: "Person or Entity Authentication", family: "Technical Safeguards" },
    { controlId: "164.312(e)(1)", title: "Transmission Security", family: "Technical Safeguards" },
  ],
  NIST_CSF: [
    { controlId: "ID.RA-1", title: "Asset Vulnerabilities Identified", family: "Identify" },
    { controlId: "PR.AC-1", title: "Identities and Credentials Managed", family: "Protect" },
    { controlId: "PR.AC-7", title: "Authentication Mechanisms", family: "Protect" },
    { controlId: "PR.DS-1", title: "Data-at-Rest Protected", family: "Protect" },
    { controlId: "PR.DS-2", title: "Data-in-Transit Protected", family: "Protect" },
    { controlId: "PR.IP-1", title: "Baseline Configuration", family: "Protect" },
    { controlId: "PR.IP-12", title: "Vulnerability Management Plan", family: "Protect" },
    { controlId: "DE.CM-1", title: "Network Monitoring", family: "Detect" },
    { controlId: "DE.CM-8", title: "Vulnerability Scans Performed", family: "Detect" },
    { controlId: "DE.DP-4", title: "Detection Process Improvement", family: "Detect" },
  ],
};

// ─── Core Mapper ────────────────────────────────────────────────────────────

let evidenceCounter = 0;

function makeEvidenceId(): string {
  return `EVD-${Date.now()}-${++evidenceCounter}`;
}

interface FindingInput {
  tool: string;
  asset: string;
  title: string;
  description?: string;
  severity: string;
  rawSnippet?: string;
  timestamp?: number;
}

function matchFindingToRules(finding: FindingInput): MappingRule[] {
  const matched: MappingRule[] = [];
  for (const rule of MAPPING_RULES) {
    // Match by tool
    if (rule.matchTool && rule.matchTool.some(t => finding.tool.toLowerCase().includes(t))) {
      matched.push(rule);
      continue;
    }
    // Match by title pattern
    if (rule.matchTitlePattern && rule.matchTitlePattern.test(finding.title)) {
      matched.push(rule);
      continue;
    }
  }
  return matched;
}

function determineStatus(
  statusLogic: MappingRule["controls"][0]["statusLogic"],
  hasFinding: boolean,
  severity?: string
): ComplianceEvidence["status"] {
  switch (statusLogic) {
    case "pass_if_finding":
      return hasFinding ? "pass" : "informational";
    case "fail_if_finding":
      if (!hasFinding) return "pass";
      if (severity === "critical" || severity === "high") return "fail";
      if (severity === "medium") return "partial";
      return "informational";
    case "pass_if_no_finding":
      return hasFinding ? "fail" : "pass";
    case "informational":
    default:
      return "informational";
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────

export interface EngagementStateForMapping {
  engagementId: number;
  assets: {
    hostname: string;
    ip?: string;
    vulns: { title: string; severity: string; description?: string; tool?: string; cve?: string; rawOutput?: string }[];
    ports: { port: number; service?: string; protocol?: string }[];
    toolResults: { tool: string; command?: string; exitCode?: number; findingCount: number; outputPreview?: string; findings: { title: string; severity: string }[] }[];
    zapFindings: { alert: string; risk: string; description?: string; url?: string; evidence?: string }[];
  }[];
}

/**
 * Map all findings from an engagement to compliance controls and generate evidence.
 */
export function mapEngagementToCompliance(state: EngagementStateForMapping): EvidenceMapperResult {
  const evidence: ComplianceEvidence[] = [];
  const now = Date.now();

  for (const asset of state.assets) {
    // Map tool results
    for (const tr of asset.toolResults) {
      const finding: FindingInput = {
        tool: tr.tool,
        asset: asset.hostname,
        title: `${tr.tool} scan (${tr.findingCount} findings)`,
        severity: tr.findingCount > 0 ? "medium" : "info",
        rawSnippet: tr.outputPreview?.slice(0, 500),
        timestamp: now,
      };
      const rules = matchFindingToRules(finding);
      for (const rule of rules) {
        for (const ctrl of rule.controls) {
          evidence.push({
            id: makeEvidenceId(),
            controlId: ctrl.controlId,
            framework: ctrl.framework,
            controlTitle: ctrl.controlTitle,
            evidenceType: ctrl.evidenceType,
            source: tr.tool,
            asset: asset.hostname,
            title: finding.title,
            description: `${rule.name}: ${tr.tool} scan completed on ${asset.hostname} with ${tr.findingCount} findings.${tr.command ? ` Command: ${tr.command.slice(0, 200)}` : ""}`,
            severity: finding.severity,
            timestamp: now,
            rawSnippet: finding.rawSnippet,
            status: determineStatus(ctrl.statusLogic, tr.findingCount > 0, finding.severity),
            engagementId: state.engagementId,
          });
        }
      }

      // Also map individual findings from tool results
      for (const f of tr.findings) {
        const subFinding: FindingInput = {
          tool: tr.tool,
          asset: asset.hostname,
          title: f.title,
          severity: f.severity,
          timestamp: now,
        };
        const subRules = matchFindingToRules(subFinding);
        for (const rule of subRules) {
          for (const ctrl of rule.controls) {
            evidence.push({
              id: makeEvidenceId(),
              controlId: ctrl.controlId,
              framework: ctrl.framework,
              controlTitle: ctrl.controlTitle,
              evidenceType: ctrl.evidenceType,
              source: tr.tool,
              asset: asset.hostname,
              title: f.title,
              description: `${rule.name}: ${f.title} (${f.severity}) found by ${tr.tool} on ${asset.hostname}`,
              severity: f.severity,
              timestamp: now,
              status: determineStatus(ctrl.statusLogic, true, f.severity),
              engagementId: state.engagementId,
            });
          }
        }
      }
    }

    // Map vulnerabilities
    for (const vuln of asset.vulns) {
      const finding: FindingInput = {
        tool: vuln.tool || "nuclei",
        asset: asset.hostname,
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity,
        rawSnippet: vuln.rawOutput?.slice(0, 500),
        timestamp: now,
      };
      const rules = matchFindingToRules(finding);
      for (const rule of rules) {
        for (const ctrl of rule.controls) {
          evidence.push({
            id: makeEvidenceId(),
            controlId: ctrl.controlId,
            framework: ctrl.framework,
            controlTitle: ctrl.controlTitle,
            evidenceType: ctrl.evidenceType,
            source: vuln.tool || "nuclei",
            asset: asset.hostname,
            title: vuln.title,
            description: `${rule.name}: ${vuln.title} (${vuln.severity})${vuln.cve ? ` [${vuln.cve}]` : ""} on ${asset.hostname}`,
            severity: vuln.severity,
            timestamp: now,
            rawSnippet: finding.rawSnippet,
            status: determineStatus(ctrl.statusLogic, true, vuln.severity),
            engagementId: state.engagementId,
          });
        }
      }
    }

    // Map ZAP findings
    for (const zap of asset.zapFindings) {
      const finding: FindingInput = {
        tool: "zap",
        asset: asset.hostname,
        title: zap.alert,
        description: zap.description,
        severity: zap.risk,
        rawSnippet: zap.evidence?.slice(0, 500),
        timestamp: now,
      };
      const rules = matchFindingToRules(finding);
      for (const rule of rules) {
        for (const ctrl of rule.controls) {
          evidence.push({
            id: makeEvidenceId(),
            controlId: ctrl.controlId,
            framework: ctrl.framework,
            controlTitle: ctrl.controlTitle,
            evidenceType: ctrl.evidenceType,
            source: "zap",
            asset: asset.hostname,
            title: zap.alert,
            description: `${rule.name}: ${zap.alert} (${zap.risk}) found by ZAP on ${asset.hostname}${zap.url ? ` at ${zap.url}` : ""}`,
            severity: zap.risk,
            timestamp: now,
            rawSnippet: finding.rawSnippet,
            status: determineStatus(ctrl.statusLogic, true, zap.risk),
            engagementId: state.engagementId,
          });
        }
      }
    }
  }

  // Build posture summaries per framework
  const summaries: CompliancePostureSummary[] = [];
  for (const [framework, controls] of Object.entries(FRAMEWORK_CONTROLS)) {
    const controlPostures: ControlPosture[] = controls.map(ctrl => {
      const ctrlEvidence = evidence.filter(e => e.framework === framework && e.controlId === ctrl.controlId);
      const passCount = ctrlEvidence.filter(e => e.status === "pass").length;
      const failCount = ctrlEvidence.filter(e => e.status === "fail").length;
      const partialCount = ctrlEvidence.filter(e => e.status === "partial").length;

      let overallStatus: ControlPosture["overallStatus"] = "no_evidence";
      if (ctrlEvidence.length > 0) {
        if (failCount > 0) overallStatus = "non_compliant";
        else if (partialCount > 0) overallStatus = "partial";
        else if (passCount > 0) overallStatus = "compliant";
        else overallStatus = "partial"; // informational only
      }

      return {
        controlId: ctrl.controlId,
        framework,
        controlTitle: ctrl.title,
        family: ctrl.family,
        evidenceCount: ctrlEvidence.length,
        passCount,
        failCount,
        partialCount,
        overallStatus,
        lastEvidenceTimestamp: ctrlEvidence.length > 0 ? Math.max(...ctrlEvidence.map(e => e.timestamp)) : null,
      };
    });

    const compliant = controlPostures.filter(c => c.overallStatus === "compliant").length;
    const nonCompliant = controlPostures.filter(c => c.overallStatus === "non_compliant").length;
    const partial = controlPostures.filter(c => c.overallStatus === "partial").length;
    const noEvidence = controlPostures.filter(c => c.overallStatus === "no_evidence").length;
    const total = controlPostures.length;
    const score = total > 0 ? Math.round(((compliant + partial * 0.5) / total) * 100) : 0;

    summaries.push({
      framework,
      totalControls: total,
      compliant,
      nonCompliant,
      partial,
      noEvidence,
      complianceScore: score,
      controls: controlPostures,
      generatedAt: Date.now(),
      engagementId: state.engagementId,
    });
  }

  return {
    evidence,
    summaries,
    totalEvidenceItems: evidence.length,
    frameworksCovered: summaries.map(s => s.framework),
    gapCount: summaries.reduce((sum, s) => sum + s.noEvidence, 0),
  };
}

/**
 * Get the list of all supported frameworks and their control counts.
 */
export function getSupportedFrameworks(): { framework: string; controlCount: number }[] {
  return Object.entries(FRAMEWORK_CONTROLS).map(([framework, controls]) => ({
    framework,
    controlCount: controls.length,
  }));
}

/**
 * Get the mapping rules for documentation/transparency.
 */
export function getMappingRules(): { id: string; name: string; controlCount: number; frameworks: string[] }[] {
  return MAPPING_RULES.map(r => ({
    id: r.id,
    name: r.name,
    controlCount: r.controls.length,
    frameworks: [...new Set(r.controls.map(c => c.framework))],
  }));
}
