/**
 * Compliance Mapping Module
 * Maps CI/CD scan findings to compliance frameworks (SOC 2, PCI-DSS, NIST 800-53).
 * Generates compliance gap reports per pipeline.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type ComplianceFramework = "soc2" | "pci_dss" | "nist_800_53";

export interface ComplianceControl {
  id: string;
  framework: ComplianceFramework;
  title: string;
  description: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  automatable: boolean;
}

export interface ComplianceMapping {
  controlId: string;
  framework: ComplianceFramework;
  findingPatterns: string[]; // Nuclei template IDs or tag patterns
  cweIds: number[];
  keywords: string[];
}

export interface ComplianceResult {
  control: ComplianceControl;
  status: "pass" | "fail" | "partial" | "not_tested";
  matchedFindings: Array<{
    findingId: string;
    name: string;
    severity: string;
    cve?: string;
  }>;
  evidence: string;
  remediationPriority: number; // 1-10
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  frameworkName: string;
  generatedAt: string;
  pipelineId: number;
  pipelineName: string;
  runId: number;
  summary: {
    totalControls: number;
    passed: number;
    failed: number;
    partial: number;
    notTested: number;
    complianceScore: number; // 0-100
    riskLevel: "critical" | "high" | "medium" | "low";
  };
  categories: Array<{
    name: string;
    controls: ComplianceResult[];
    categoryScore: number;
  }>;
  topGaps: ComplianceResult[];
  recommendations: string[];
}

// ─── Framework Definitions ──────────────────────────────────────────────────

const SOC2_CONTROLS: ComplianceControl[] = [
  // CC6 - Logical and Physical Access Controls
  { id: "CC6.1", framework: "soc2", title: "Logical Access Security", description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets.", category: "Logical & Physical Access", severity: "critical", automatable: true },
  { id: "CC6.2", framework: "soc2", title: "User Authentication", description: "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.", category: "Logical & Physical Access", severity: "high", automatable: true },
  { id: "CC6.3", framework: "soc2", title: "Role-Based Access", description: "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles.", category: "Logical & Physical Access", severity: "high", automatable: true },
  { id: "CC6.6", framework: "soc2", title: "System Boundary Protection", description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.", category: "Logical & Physical Access", severity: "critical", automatable: true },
  { id: "CC6.7", framework: "soc2", title: "Data Transmission Security", description: "The entity restricts the transmission, movement, and removal of information to authorized internal and external users.", category: "Logical & Physical Access", severity: "high", automatable: true },
  { id: "CC6.8", framework: "soc2", title: "Unauthorized Software Prevention", description: "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.", category: "Logical & Physical Access", severity: "high", automatable: true },
  // CC7 - System Operations
  { id: "CC7.1", framework: "soc2", title: "Vulnerability Management", description: "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in vulnerabilities.", category: "System Operations", severity: "critical", automatable: true },
  { id: "CC7.2", framework: "soc2", title: "Anomaly Detection", description: "The entity monitors system components and the operation of those components for anomalies.", category: "System Operations", severity: "high", automatable: true },
  { id: "CC7.3", framework: "soc2", title: "Security Event Evaluation", description: "The entity evaluates security events to determine whether they could or have resulted in a failure.", category: "System Operations", severity: "medium", automatable: false },
  { id: "CC7.4", framework: "soc2", title: "Incident Response", description: "The entity responds to identified security incidents by executing a defined incident response program.", category: "System Operations", severity: "high", automatable: false },
  // CC8 - Change Management
  { id: "CC8.1", framework: "soc2", title: "Change Management Process", description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes.", category: "Change Management", severity: "medium", automatable: true },
  // CC9 - Risk Mitigation
  { id: "CC9.1", framework: "soc2", title: "Risk Mitigation", description: "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.", category: "Risk Mitigation", severity: "medium", automatable: false },
];

const PCI_DSS_CONTROLS: ComplianceControl[] = [
  // Requirement 1 - Network Security
  { id: "PCI-1.1", framework: "pci_dss", title: "Network Security Controls", description: "Install and maintain network security controls.", category: "Network Security", severity: "critical", automatable: true },
  { id: "PCI-1.2", framework: "pci_dss", title: "Network Segmentation", description: "Network security controls are configured and maintained.", category: "Network Security", severity: "high", automatable: true },
  // Requirement 2 - Secure Configuration
  { id: "PCI-2.1", framework: "pci_dss", title: "Secure Configuration Standards", description: "Apply secure configurations to all system components.", category: "Secure Configuration", severity: "high", automatable: true },
  { id: "PCI-2.2", framework: "pci_dss", title: "Default Credentials", description: "Vendor-supplied defaults are changed before installing a system on the network.", category: "Secure Configuration", severity: "critical", automatable: true },
  // Requirement 3 - Data Protection
  { id: "PCI-3.1", framework: "pci_dss", title: "Data Retention", description: "Stored account data is kept to a minimum.", category: "Data Protection", severity: "high", automatable: false },
  { id: "PCI-3.4", framework: "pci_dss", title: "Data Encryption at Rest", description: "PAN is secured with strong cryptography wherever it is stored.", category: "Data Protection", severity: "critical", automatable: true },
  // Requirement 4 - Encryption in Transit
  { id: "PCI-4.1", framework: "pci_dss", title: "Encryption in Transit", description: "Strong cryptography is used during transmission of cardholder data over open, public networks.", category: "Encryption", severity: "critical", automatable: true },
  { id: "PCI-4.2", framework: "pci_dss", title: "Secure Messaging", description: "PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies.", category: "Encryption", severity: "high", automatable: true },
  // Requirement 5 - Malware Protection
  { id: "PCI-5.1", framework: "pci_dss", title: "Anti-Malware", description: "Processes and automated mechanisms to detect and protect against malware.", category: "Malware Protection", severity: "high", automatable: true },
  // Requirement 6 - Secure Development
  { id: "PCI-6.1", framework: "pci_dss", title: "Secure Development Lifecycle", description: "Bespoke and custom software is developed securely.", category: "Secure Development", severity: "high", automatable: true },
  { id: "PCI-6.2", framework: "pci_dss", title: "Vulnerability Management", description: "Bespoke and custom software is developed securely with vulnerability identification.", category: "Secure Development", severity: "critical", automatable: true },
  { id: "PCI-6.3", framework: "pci_dss", title: "Security Vulnerabilities Identified", description: "Security vulnerabilities are identified and addressed.", category: "Secure Development", severity: "critical", automatable: true },
  { id: "PCI-6.4", framework: "pci_dss", title: "Web Application Security", description: "Public-facing web applications are protected against attacks.", category: "Secure Development", severity: "critical", automatable: true },
  // Requirement 8 - Authentication
  { id: "PCI-8.1", framework: "pci_dss", title: "User Identification", description: "Processes and mechanisms for identifying users and authenticating access.", category: "Authentication", severity: "high", automatable: true },
  { id: "PCI-8.3", framework: "pci_dss", title: "Strong Authentication", description: "Strong authentication for users and administrators is established and managed.", category: "Authentication", severity: "critical", automatable: true },
  // Requirement 11 - Testing
  { id: "PCI-11.3", framework: "pci_dss", title: "Penetration Testing", description: "External and internal penetration testing is regularly performed.", category: "Security Testing", severity: "critical", automatable: true },
  { id: "PCI-11.4", framework: "pci_dss", title: "Intrusion Detection", description: "External and internal intrusion detection and/or prevention techniques are used.", category: "Security Testing", severity: "high", automatable: true },
];

const NIST_800_53_CONTROLS: ComplianceControl[] = [
  // AC - Access Control
  { id: "AC-2", framework: "nist_800_53", title: "Account Management", description: "Manage system accounts, group memberships, privileges, and associated authorizations.", category: "Access Control", severity: "high", automatable: true },
  { id: "AC-3", framework: "nist_800_53", title: "Access Enforcement", description: "Enforce approved authorizations for logical access to information and system resources.", category: "Access Control", severity: "critical", automatable: true },
  { id: "AC-6", framework: "nist_800_53", title: "Least Privilege", description: "Employ the principle of least privilege, allowing only authorized accesses.", category: "Access Control", severity: "high", automatable: true },
  { id: "AC-7", framework: "nist_800_53", title: "Unsuccessful Logon Attempts", description: "Enforce a limit of consecutive invalid logon attempts by a user.", category: "Access Control", severity: "medium", automatable: true },
  { id: "AC-17", framework: "nist_800_53", title: "Remote Access", description: "Establish and document usage restrictions and implementation guidance for each type of remote access.", category: "Access Control", severity: "high", automatable: true },
  // AU - Audit
  { id: "AU-2", framework: "nist_800_53", title: "Event Logging", description: "Identify the types of events that the system is capable of logging.", category: "Audit & Accountability", severity: "medium", automatable: true },
  { id: "AU-6", framework: "nist_800_53", title: "Audit Record Review", description: "Review and analyze system audit records for indications of inappropriate or unusual activity.", category: "Audit & Accountability", severity: "medium", automatable: false },
  // CA - Assessment
  { id: "CA-2", framework: "nist_800_53", title: "Control Assessments", description: "Assess the security and privacy controls to determine effectiveness.", category: "Assessment", severity: "high", automatable: true },
  { id: "CA-7", framework: "nist_800_53", title: "Continuous Monitoring", description: "Develop a system-level continuous monitoring strategy and implement continuous monitoring.", category: "Assessment", severity: "high", automatable: true },
  // CM - Configuration Management
  { id: "CM-2", framework: "nist_800_53", title: "Baseline Configuration", description: "Develop, document, and maintain a current baseline configuration of the system.", category: "Configuration Management", severity: "medium", automatable: true },
  { id: "CM-6", framework: "nist_800_53", title: "Configuration Settings", description: "Establish and document configuration settings for components employed within the system.", category: "Configuration Management", severity: "high", automatable: true },
  { id: "CM-7", framework: "nist_800_53", title: "Least Functionality", description: "Configure the system to provide only mission-essential capabilities.", category: "Configuration Management", severity: "medium", automatable: true },
  // IA - Identification & Authentication
  { id: "IA-2", framework: "nist_800_53", title: "User Identification & Authentication", description: "Uniquely identify and authenticate organizational users.", category: "Identification & Authentication", severity: "critical", automatable: true },
  { id: "IA-5", framework: "nist_800_53", title: "Authenticator Management", description: "Manage system authenticators by verifying identity before distributing credentials.", category: "Identification & Authentication", severity: "high", automatable: true },
  // RA - Risk Assessment
  { id: "RA-5", framework: "nist_800_53", title: "Vulnerability Monitoring & Scanning", description: "Monitor and scan for vulnerabilities in the system and hosted applications.", category: "Risk Assessment", severity: "critical", automatable: true },
  { id: "RA-7", framework: "nist_800_53", title: "Risk Response", description: "Respond to findings from security and privacy assessments, monitoring, and audits.", category: "Risk Assessment", severity: "high", automatable: false },
  // SC - System & Communications Protection
  { id: "SC-7", framework: "nist_800_53", title: "Boundary Protection", description: "Monitor and control communications at external managed interfaces.", category: "System & Communications", severity: "critical", automatable: true },
  { id: "SC-8", framework: "nist_800_53", title: "Transmission Confidentiality", description: "Protect the confidentiality and integrity of transmitted information.", category: "System & Communications", severity: "high", automatable: true },
  { id: "SC-12", framework: "nist_800_53", title: "Cryptographic Key Management", description: "Establish and manage cryptographic keys when cryptography is employed.", category: "System & Communications", severity: "high", automatable: true },
  { id: "SC-13", framework: "nist_800_53", title: "Cryptographic Protection", description: "Determine the cryptographic uses and implement the required types of cryptography.", category: "System & Communications", severity: "high", automatable: true },
  // SI - System & Information Integrity
  { id: "SI-2", framework: "nist_800_53", title: "Flaw Remediation", description: "Identify, report, and correct system flaws.", category: "System Integrity", severity: "critical", automatable: true },
  { id: "SI-3", framework: "nist_800_53", title: "Malicious Code Protection", description: "Implement malicious code protection mechanisms at system entry and exit points.", category: "System Integrity", severity: "high", automatable: true },
  { id: "SI-4", framework: "nist_800_53", title: "System Monitoring", description: "Monitor the system to detect attacks and indicators of potential attacks.", category: "System Integrity", severity: "high", automatable: true },
  { id: "SI-5", framework: "nist_800_53", title: "Security Alerts & Advisories", description: "Receive system security alerts, advisories, and directives from external organizations.", category: "System Integrity", severity: "medium", automatable: true },
  { id: "SI-10", framework: "nist_800_53", title: "Information Input Validation", description: "Check the validity of information inputs.", category: "System Integrity", severity: "high", automatable: true },
];

// ─── Finding-to-Control Mapping Rules ───────────────────────────────────────

interface MappingRule {
  controlIds: string[];
  tags: string[];
  cweIds: number[];
  keywords: string[];
  severityMin?: string;
}

const MAPPING_RULES: MappingRule[] = [
  // SSL/TLS issues → encryption controls
  { controlIds: ["CC6.7", "PCI-4.1", "SC-8", "SC-13"], tags: ["ssl", "tls", "https", "certificate"], cweIds: [295, 319, 326, 327], keywords: ["ssl", "tls", "certificate", "https", "encryption", "cipher"] },
  // Authentication issues
  { controlIds: ["CC6.1", "CC6.2", "PCI-8.1", "PCI-8.3", "IA-2", "IA-5", "AC-7"], tags: ["auth", "login", "credential", "password", "brute-force"], cweIds: [287, 306, 307, 521, 522, 798], keywords: ["authentication", "login", "credential", "password", "brute", "default-login"] },
  // Access control issues
  { controlIds: ["CC6.3", "PCI-2.2", "AC-3", "AC-6"], tags: ["misconfig", "exposure", "unauth", "default-login"], cweIds: [284, 285, 862, 863], keywords: ["unauthorized", "access control", "permission", "privilege", "default"] },
  // XSS/Injection → input validation + web app security
  { controlIds: ["PCI-6.4", "SI-10"], tags: ["xss", "injection", "sqli", "rce", "lfi", "rfi", "ssrf", "ssti"], cweIds: [79, 89, 94, 78, 77, 918, 22, 98], keywords: ["injection", "xss", "cross-site", "sql injection", "command injection", "ssrf", "template injection"] },
  // Vulnerability scanning → vuln management controls
  { controlIds: ["CC7.1", "PCI-6.2", "PCI-6.3", "PCI-11.3", "RA-5", "SI-2"], tags: ["cve", "vulnerability", "outdated", "eol"], cweIds: [], keywords: ["cve-", "vulnerability", "outdated", "end-of-life", "patch", "update"] },
  // Information disclosure
  { controlIds: ["CC6.6", "PCI-3.1", "SC-7"], tags: ["exposure", "disclosure", "leak", "listing"], cweIds: [200, 209, 497, 538], keywords: ["disclosure", "exposed", "leak", "directory listing", "information exposure", "sensitive data"] },
  // Malware/malicious code
  { controlIds: ["CC6.8", "PCI-5.1", "SI-3"], tags: ["malware", "backdoor", "webshell"], cweIds: [506, 507, 912], keywords: ["malware", "backdoor", "webshell", "trojan", "malicious"] },
  // Configuration issues
  { controlIds: ["CC8.1", "PCI-2.1", "CM-2", "CM-6", "CM-7"], tags: ["misconfig", "misconfiguration", "config", "header"], cweIds: [16, 1188], keywords: ["misconfiguration", "security header", "cors", "csp", "hsts", "x-frame", "configuration"] },
  // Monitoring and logging
  { controlIds: ["CC7.2", "CC7.3", "PCI-11.4", "AU-2", "SI-4"], tags: ["monitoring", "logging", "detection"], cweIds: [778, 223], keywords: ["monitoring", "logging", "detection", "audit", "intrusion"] },
  // Cryptographic issues
  { controlIds: ["PCI-3.4", "SC-12", "SC-13"], tags: ["crypto", "encryption", "hash"], cweIds: [326, 327, 328, 330, 916], keywords: ["weak cipher", "weak hash", "md5", "sha1", "des", "rc4", "cryptographic"] },
  // Remote access
  { controlIds: ["AC-17"], tags: ["ssh", "rdp", "vpn", "remote"], cweIds: [], keywords: ["ssh", "rdp", "remote access", "vpn", "telnet"] },
];

// ─── Compliance Assessment ──────────────────────────────────────────────────

function getControlsForFramework(framework: ComplianceFramework): ComplianceControl[] {
  switch (framework) {
    case "soc2": return SOC2_CONTROLS;
    case "pci_dss": return PCI_DSS_CONTROLS;
    case "nist_800_53": return NIST_800_53_CONTROLS;
  }
}

function getFrameworkName(framework: ComplianceFramework): string {
  switch (framework) {
    case "soc2": return "SOC 2 Type II";
    case "pci_dss": return "PCI DSS v4.0";
    case "nist_800_53": return "NIST SP 800-53 Rev. 5";
  }
}

/**
 * Assess a single control against scan findings
 */
function assessControl(control: ComplianceControl, findings: any[]): ComplianceResult {
  // Find mapping rules for this control
  const applicableRules = MAPPING_RULES.filter(rule => rule.controlIds.includes(control.id));

  if (applicableRules.length === 0) {
    return {
      control,
      status: "not_tested",
      matchedFindings: [],
      evidence: "No automated mapping rules available for this control. Manual assessment required.",
      remediationPriority: 5,
    };
  }

  // Collect all matching findings
  const matchedFindings: ComplianceResult["matchedFindings"] = [];

  for (const finding of findings) {
    const findingTags = (finding.tags || finding.info?.tags || []).map((t: string) => t.toLowerCase());
    const findingName = (finding.name || finding.info?.name || "").toLowerCase();
    const findingDesc = (finding.description || finding.info?.description || "").toLowerCase();
    const findingCwes = (finding.cwe || finding.info?.cwe || []).map((c: any) => typeof c === "number" ? c : parseInt(String(c).replace(/\D/g, "")));
    const findingSeverity = (finding.severity || finding.info?.severity || "").toLowerCase();
    const fullText = `${findingName} ${findingDesc} ${findingTags.join(" ")}`;

    let matched = false;
    for (const rule of applicableRules) {
      // Check tag matches
      if (rule.tags.some(t => findingTags.some((ft: string) => ft.includes(t)))) { matched = true; break; }
      // Check CWE matches
      if (rule.cweIds.some(cwe => findingCwes.includes(cwe))) { matched = true; break; }
      // Check keyword matches
      if (rule.keywords.some(kw => fullText.includes(kw.toLowerCase()))) { matched = true; break; }
    }

    if (matched) {
      matchedFindings.push({
        findingId: finding.id || finding.templateId || finding.info?.id || "unknown",
        name: finding.name || finding.info?.name || "Unknown Finding",
        severity: findingSeverity || "medium",
        cve: finding.cve?.id || finding.cveId || undefined,
      });
    }
  }

  // Determine status
  let status: ComplianceResult["status"];
  let evidence: string;
  let remediationPriority: number;

  if (matchedFindings.length === 0) {
    if (control.automatable) {
      status = "pass";
      evidence = `No findings matched this control. Automated scan did not detect violations.`;
      remediationPriority = 0;
    } else {
      status = "not_tested";
      evidence = `This control requires manual assessment. No automated findings available.`;
      remediationPriority = 5;
    }
  } else {
    const hasCritical = matchedFindings.some(f => f.severity === "critical");
    const hasHigh = matchedFindings.some(f => f.severity === "high");

    if (hasCritical || hasHigh) {
      status = "fail";
      evidence = `${matchedFindings.length} finding(s) detected: ${hasCritical ? "critical" : "high"} severity issues require immediate remediation.`;
      remediationPriority = hasCritical ? 10 : 8;
    } else {
      status = "partial";
      evidence = `${matchedFindings.length} finding(s) detected: medium/low severity issues suggest partial compliance.`;
      remediationPriority = 5;
    }
  }

  return { control, status, matchedFindings, evidence, remediationPriority };
}

// ─── Report Generation ──────────────────────────────────────────────────────

/**
 * Generate a compliance report for a specific framework against CI/CD scan findings
 */
export function generateComplianceReport(params: {
  framework: ComplianceFramework;
  pipelineId: number;
  pipelineName: string;
  runId: number;
  findings: any[];
}): ComplianceReport {
  const { framework, pipelineId, pipelineName, runId, findings } = params;
  const controls = getControlsForFramework(framework);

  // Assess each control
  const results = controls.map(control => assessControl(control, findings));

  // Group by category
  const categoryMap = new Map<string, ComplianceResult[]>();
  for (const result of results) {
    const cat = result.control.category;
    if (!categoryMap.has(cat)) categoryMap.set(cat, []);
    categoryMap.get(cat)!.push(result);
  }

  const categories = Array.from(categoryMap.entries()).map(([name, controls]) => {
    const passed = controls.filter(c => c.status === "pass").length;
    const total = controls.filter(c => c.status !== "not_tested").length;
    return {
      name,
      controls,
      categoryScore: total > 0 ? Math.round((passed / total) * 100) : 0,
    };
  });

  // Summary
  const passed = results.filter(r => r.status === "pass").length;
  const failed = results.filter(r => r.status === "fail").length;
  const partial = results.filter(r => r.status === "partial").length;
  const notTested = results.filter(r => r.status === "not_tested").length;
  const testable = results.length - notTested;
  const complianceScore = testable > 0 ? Math.round((passed / testable) * 100) : 0;

  let riskLevel: ComplianceReport["summary"]["riskLevel"];
  if (complianceScore >= 90) riskLevel = "low";
  else if (complianceScore >= 70) riskLevel = "medium";
  else if (complianceScore >= 50) riskLevel = "high";
  else riskLevel = "critical";

  // Top gaps (failed controls sorted by remediation priority)
  const topGaps = results
    .filter(r => r.status === "fail" || r.status === "partial")
    .sort((a, b) => b.remediationPriority - a.remediationPriority)
    .slice(0, 10);

  // Generate recommendations
  const recommendations = generateRecommendations(topGaps, framework);

  return {
    framework,
    frameworkName: getFrameworkName(framework),
    generatedAt: new Date().toISOString(),
    pipelineId,
    pipelineName,
    runId,
    summary: { totalControls: results.length, passed, failed, partial, notTested, complianceScore, riskLevel },
    categories,
    topGaps,
    recommendations,
  };
}

function generateRecommendations(gaps: ComplianceResult[], framework: ComplianceFramework): string[] {
  const recs: string[] = [];

  const criticalGaps = gaps.filter(g => g.control.severity === "critical");
  const highGaps = gaps.filter(g => g.control.severity === "high");

  if (criticalGaps.length > 0) {
    recs.push(`Address ${criticalGaps.length} critical control failure(s) immediately: ${criticalGaps.map(g => g.control.id).join(", ")}.`);
  }

  if (highGaps.length > 0) {
    recs.push(`Remediate ${highGaps.length} high-severity gap(s) within 30 days: ${highGaps.map(g => g.control.id).join(", ")}.`);
  }

  // Framework-specific recommendations
  switch (framework) {
    case "soc2":
      if (gaps.some(g => g.control.id.startsWith("CC7"))) {
        recs.push("Strengthen vulnerability management processes (CC7.x). Implement continuous scanning with automated remediation tracking.");
      }
      if (gaps.some(g => g.control.id.startsWith("CC6"))) {
        recs.push("Review logical access controls (CC6.x). Ensure encryption in transit, role-based access, and boundary protection are properly configured.");
      }
      break;
    case "pci_dss":
      if (gaps.some(g => ["PCI-6.2", "PCI-6.3", "PCI-6.4"].includes(g.control.id))) {
        recs.push("Prioritize secure development practices (Req 6). Implement WAF, code review, and vulnerability scanning in the SDLC.");
      }
      if (gaps.some(g => ["PCI-4.1", "PCI-3.4"].includes(g.control.id))) {
        recs.push("Ensure all cardholder data is encrypted at rest and in transit (Req 3-4). Review TLS configurations and key management.");
      }
      break;
    case "nist_800_53":
      if (gaps.some(g => g.control.id.startsWith("RA-"))) {
        recs.push("Enhance risk assessment processes (RA family). Implement continuous vulnerability monitoring and formal risk response procedures.");
      }
      if (gaps.some(g => g.control.id.startsWith("SI-"))) {
        recs.push("Strengthen system integrity controls (SI family). Deploy flaw remediation tracking, malicious code protection, and input validation.");
      }
      break;
  }

  if (recs.length === 0) {
    recs.push("No critical gaps detected. Continue monitoring and maintain current security posture.");
  }

  return recs;
}

// ─── Multi-Framework Comparison ─────────────────────────────────────────────

export interface CrossFrameworkSummary {
  frameworks: Array<{
    framework: ComplianceFramework;
    name: string;
    score: number;
    riskLevel: string;
    failed: number;
    total: number;
  }>;
  sharedGaps: Array<{
    findingName: string;
    severity: string;
    affectedFrameworks: string[];
    controlIds: string[];
  }>;
  overallRiskLevel: string;
}

/**
 * Generate a cross-framework comparison from multiple compliance reports
 */
export function generateCrossFrameworkSummary(reports: ComplianceReport[]): CrossFrameworkSummary {
  const frameworks = reports.map(r => ({
    framework: r.framework,
    name: r.frameworkName,
    score: r.summary.complianceScore,
    riskLevel: r.summary.riskLevel,
    failed: r.summary.failed,
    total: r.summary.totalControls,
  }));

  // Find findings that affect multiple frameworks
  const findingFrameworkMap = new Map<string, { severity: string; frameworks: Set<string>; controlIds: Set<string> }>();

  for (const report of reports) {
    for (const gap of report.topGaps) {
      for (const finding of gap.matchedFindings) {
        const key = finding.findingId;
        if (!findingFrameworkMap.has(key)) {
          findingFrameworkMap.set(key, {
            severity: finding.severity,
            frameworks: new Set(),
            controlIds: new Set(),
          });
        }
        const entry = findingFrameworkMap.get(key)!;
        entry.frameworks.add(report.frameworkName);
        entry.controlIds.add(gap.control.id);
      }
    }
  }

  const sharedGaps = Array.from(findingFrameworkMap.entries())
    .filter(([_, v]) => v.frameworks.size > 1)
    .map(([name, v]) => ({
      findingName: name,
      severity: v.severity,
      affectedFrameworks: Array.from(v.frameworks),
      controlIds: Array.from(v.controlIds),
    }))
    .sort((a, b) => {
      const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
    });

  const avgScore = frameworks.reduce((sum, f) => sum + f.score, 0) / frameworks.length;
  let overallRiskLevel: string;
  if (avgScore >= 90) overallRiskLevel = "low";
  else if (avgScore >= 70) overallRiskLevel = "medium";
  else if (avgScore >= 50) overallRiskLevel = "high";
  else overallRiskLevel = "critical";

  return { frameworks, sharedGaps, overallRiskLevel };
}

/**
 * Get all available frameworks with metadata
 */
export function getAvailableFrameworks(): Array<{ id: ComplianceFramework; name: string; controlCount: number; description: string }> {
  return [
    { id: "soc2", name: "SOC 2 Type II", controlCount: SOC2_CONTROLS.length, description: "Service Organization Control 2 — Trust Services Criteria for security, availability, processing integrity, confidentiality, and privacy." },
    { id: "pci_dss", name: "PCI DSS v4.0", controlCount: PCI_DSS_CONTROLS.length, description: "Payment Card Industry Data Security Standard — Requirements for organizations handling cardholder data." },
    { id: "nist_800_53", name: "NIST SP 800-53 Rev. 5", controlCount: NIST_800_53_CONTROLS.length, description: "Security and Privacy Controls for Information Systems and Organizations — Comprehensive federal security framework." },
  ];
}
