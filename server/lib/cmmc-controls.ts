/**
 * CMMC 2.0 Compliance Framework Library
 *
 * Cybersecurity Maturity Model Certification (CMMC) 2.0
 * Aligned with NIST SP 800-171 Rev 2 for Level 2 (Advanced)
 * Includes SPRS scoring, POA&M management, and cross-framework mapping.
 *
 * CMMC 2.0 Levels:
 * - Level 1 (Foundational): 17 practices from FAR 52.204-21
 * - Level 2 (Advanced): 110 practices from NIST SP 800-171 Rev 2
 * - Level 3 (Expert): 110+ practices from NIST SP 800-172
 */

export interface CMMCPractice {
  id: string;
  domain: string;
  domainCode: string;
  level: 1 | 2 | 3;
  title: string;
  description: string;
  nistMapping: string; // NIST 800-171 requirement
  status: "met" | "partially_met" | "not_met" | "not_applicable";
  implementationStatus: string;
  assessmentObjectives: string[];
  evidenceRequired: string[];
  sprsWeight: number; // SPRS scoring weight (1, 3, or 5)
  crossMappings: { framework: string; controlId: string }[];
  automationLevel: "full" | "partial" | "manual";
  poamEligible: boolean; // Can this be on a POA&M for conditional certification?
}

export interface SPRSScore {
  totalScore: number; // -203 to 110
  maxScore: number; // 110
  metPractices: number;
  partialPractices: number;
  notMetPractices: number;
  notApplicable: number;
  weightedDeductions: number;
  level1Ready: boolean;
  level2Ready: boolean;
  poamCount: number;
  conditionalCertEligible: boolean; // Score >= 80 with POA&M plan
  breakdown: { domain: string; score: number; maxScore: number; percentage: number }[];
}

export interface CMMCAssessment {
  id: string;
  type: "self" | "c3pao" | "dibcac";
  level: 1 | 2 | 3;
  status: "planning" | "in_progress" | "completed" | "certified" | "conditional";
  assessorOrg: string | null;
  startDate: number | null;
  completionDate: number | null;
  certificationDate: number | null;
  expirationDate: number | null; // 3 years from certification
  findings: { practiceId: string; finding: string; severity: "critical" | "major" | "minor" | "observation" }[];
  sprsScore: number;
  affirmationStatus: "pending" | "submitted" | "accepted";
}

// ─── CMMC 2.0 Level 1 Practices (FAR 52.204-21) ─────────────────────────

const CMMC_L1_PRACTICES: CMMCPractice[] = [
  { id: "AC.L1-3.1.1", domain: "Access Control", domainCode: "AC", level: 1, title: "Authorized Access Control", description: "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices", nistMapping: "3.1.1", status: "met", implementationStatus: "OAuth 2.0 authentication with role-based access control; all tRPC procedures gated by protectedProcedure", assessmentObjectives: ["Verify access control mechanisms", "Review authorized user list", "Test unauthorized access attempts"], evidenceRequired: ["Access control configuration", "User directory", "Authentication logs"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "AC-2" }, { framework: "SOC2", controlId: "CC6.1" }, { framework: "ISO27001", controlId: "A.9.1" }], automationLevel: "full", poamEligible: false },
  { id: "AC.L1-3.1.2", domain: "Access Control", domainCode: "AC", level: 1, title: "Transaction & Function Control", description: "Limit information system access to the types of transactions and functions that authorized users are permitted to execute", nistMapping: "3.1.2", status: "met", implementationStatus: "6-role RBAC system (admin, operator, analyst, viewer, team_lead, auditor) with procedure-level authorization", assessmentObjectives: ["Verify role-based restrictions", "Test function-level access controls", "Review permission matrix"], evidenceRequired: ["RBAC configuration", "Role permission matrix", "Access test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "AC-3" }, { framework: "SOC2", controlId: "CC6.3" }], automationLevel: "full", poamEligible: false },
  { id: "AC.L1-3.1.20", domain: "Access Control", domainCode: "AC", level: 1, title: "External Connections", description: "Verify and control/limit connections to and use of external information systems", nistMapping: "3.1.20", status: "met", implementationStatus: "External integrations (Caldera, GoPhish, ZAP, Shodan) managed via API keys with documented connections", assessmentObjectives: ["Inventory external connections", "Verify connection controls", "Review authorization for each connection"], evidenceRequired: ["External system inventory", "API key management records", "Connection authorization"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "AC-20" }, { framework: "SOC2", controlId: "CC9.2" }], automationLevel: "full", poamEligible: true },
  { id: "AC.L1-3.1.22", domain: "Access Control", domainCode: "AC", level: 1, title: "Control Public Information", description: "Control information posted or processed on publicly accessible information systems", nistMapping: "3.1.22", status: "met", implementationStatus: "No CUI exposed on public endpoints; all sensitive data behind authentication", assessmentObjectives: ["Review public-facing content", "Verify no CUI exposure", "Test unauthenticated access"], evidenceRequired: ["Public endpoint inventory", "Content review records", "Scan results"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "AC-22" }], automationLevel: "full", poamEligible: false },
  { id: "IA.L1-3.5.1", domain: "Identification and Authentication", domainCode: "IA", level: 1, title: "Identification", description: "Identify information system users, processes acting on behalf of users, or devices", nistMapping: "3.5.1", status: "met", implementationStatus: "Unique user identification via OAuth with Manus identity provider; all sessions tracked", assessmentObjectives: ["Verify unique identification", "Review user registry", "Test identification mechanisms"], evidenceRequired: ["User directory", "Authentication configuration", "Session logs"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "IA-2" }, { framework: "SOC2", controlId: "CC6.1" }], automationLevel: "full", poamEligible: false },
  { id: "IA.L1-3.5.2", domain: "Identification and Authentication", domainCode: "IA", level: 1, title: "Authentication", description: "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access", nistMapping: "3.5.2", status: "met", implementationStatus: "OAuth 2.0 token-based authentication with JWT session management", assessmentObjectives: ["Verify authentication mechanisms", "Test authentication flow", "Review token management"], evidenceRequired: ["Authentication configuration", "Token management procedures", "Authentication logs"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "IA-2" }, { framework: "SOC2", controlId: "CC6.1" }], automationLevel: "full", poamEligible: false },
  { id: "MP.L1-3.8.3", domain: "Media Protection", domainCode: "MP", level: 1, title: "Media Disposal", description: "Sanitize or destroy information system media containing FCI before disposal or release for reuse", nistMapping: "3.8.3", status: "met", implementationStatus: "Cloud-hosted infrastructure; media disposal handled by cloud provider; S3 lifecycle policies for data deletion", assessmentObjectives: ["Review media disposal procedures", "Verify cloud provider policies", "Test data deletion"], evidenceRequired: ["Media disposal policy", "Cloud provider documentation", "Deletion logs"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "MP-6" }], automationLevel: "full", poamEligible: false },
  { id: "PE.L1-3.10.1", domain: "Physical Protection", domainCode: "PE", level: 1, title: "Limit Physical Access", description: "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals", nistMapping: "3.10.1", status: "met", implementationStatus: "Cloud-hosted; physical security inherited from AWS/DigitalOcean data centers", assessmentObjectives: ["Review cloud provider physical security", "Verify inherited controls"], evidenceRequired: ["Cloud provider SOC 2 report", "Physical security documentation"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "PE-2" }], automationLevel: "manual", poamEligible: false },
  { id: "PE.L1-3.10.3", domain: "Physical Protection", domainCode: "PE", level: 1, title: "Escort Visitors", description: "Escort visitors and monitor visitor activity", nistMapping: "3.10.3", status: "met", implementationStatus: "Inherited from cloud provider; no physical facility requiring visitor management", assessmentObjectives: ["Verify cloud provider visitor policies"], evidenceRequired: ["Cloud provider documentation"], sprsWeight: 1, crossMappings: [{ framework: "FedRAMP", controlId: "PE-3" }], automationLevel: "manual", poamEligible: false },
  { id: "PE.L1-3.10.4", domain: "Physical Protection", domainCode: "PE", level: 1, title: "Physical Access Logs", description: "Maintain audit logs of physical access", nistMapping: "3.10.4", status: "met", implementationStatus: "Inherited from cloud provider data center access logs", assessmentObjectives: ["Review cloud provider access logs"], evidenceRequired: ["Cloud provider access log documentation"], sprsWeight: 1, crossMappings: [{ framework: "FedRAMP", controlId: "PE-6" }], automationLevel: "manual", poamEligible: false },
  { id: "PE.L1-3.10.5", domain: "Physical Protection", domainCode: "PE", level: 1, title: "Manage Physical Access", description: "Control and manage physical access devices", nistMapping: "3.10.5", status: "met", implementationStatus: "Inherited from cloud provider; SSH key-based access to scan server", assessmentObjectives: ["Review physical access device management", "Verify SSH key management"], evidenceRequired: ["Cloud provider documentation", "SSH key management records"], sprsWeight: 1, crossMappings: [{ framework: "FedRAMP", controlId: "PE-3" }], automationLevel: "partial", poamEligible: false },
  { id: "SC.L1-3.13.1", domain: "System and Communications Protection", domainCode: "SC", level: 1, title: "Boundary Protection", description: "Monitor, control, and protect organizational communications at the external boundaries and key internal boundaries of information systems", nistMapping: "3.13.1", status: "met", implementationStatus: "TLS 1.3 for all web traffic; firewall rules; WAF protection; network segmentation", assessmentObjectives: ["Review boundary protection mechanisms", "Verify encryption", "Test firewall rules"], evidenceRequired: ["Network diagram", "TLS configuration", "Firewall rules", "WAF configuration"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SC-7" }, { framework: "SOC2", controlId: "CC6.6" }], automationLevel: "full", poamEligible: false },
  { id: "SC.L1-3.13.5", domain: "System and Communications Protection", domainCode: "SC", level: 1, title: "Public-Access System Separation", description: "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks", nistMapping: "3.13.5", status: "met", implementationStatus: "Web frontend separated from backend API; scan server on separate network; database isolated", assessmentObjectives: ["Verify network separation", "Review architecture diagram", "Test isolation"], evidenceRequired: ["Network architecture diagram", "Subnet configuration", "Isolation test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SC-7" }], automationLevel: "full", poamEligible: false },
  { id: "SI.L1-3.14.1", domain: "System and Information Integrity", domainCode: "SI", level: 1, title: "Flaw Remediation", description: "Identify, report, and correct information and information system flaws in a timely manner", nistMapping: "3.14.1", status: "met", implementationStatus: "Automated vulnerability scanning with remediation tracking; bug report system for manual findings", assessmentObjectives: ["Review flaw remediation process", "Verify patch timelines", "Test remediation verification"], evidenceRequired: ["Remediation records", "Patch logs", "Verification scan results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SI-2" }, { framework: "SOC2", controlId: "CC7.1" }], automationLevel: "full", poamEligible: false },
  { id: "SI.L1-3.14.2", domain: "System and Information Integrity", domainCode: "SI", level: 1, title: "Malicious Code Protection", description: "Provide protection from malicious code at appropriate locations within organizational information systems", nistMapping: "3.14.2", status: "met", implementationStatus: "Input validation on all tRPC procedures; file upload scanning; WAF malware detection", assessmentObjectives: ["Verify malware protection mechanisms", "Test detection capabilities", "Review update procedures"], evidenceRequired: ["Protection configuration", "Detection logs", "Update records"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SI-3" }, { framework: "SOC2", controlId: "CC6.8" }], automationLevel: "full", poamEligible: false },
  { id: "SI.L1-3.14.4", domain: "System and Information Integrity", domainCode: "SI", level: 1, title: "Update Malicious Code Protection", description: "Update malicious code protection mechanisms when new releases are available", nistMapping: "3.14.4", status: "met", implementationStatus: "Automated dependency updates; nuclei template auto-updates; WAF rule updates", assessmentObjectives: ["Verify update mechanisms", "Review update frequency", "Test update process"], evidenceRequired: ["Update configuration", "Update logs", "Version records"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "SI-3" }], automationLevel: "full", poamEligible: false },
  { id: "SI.L1-3.14.5", domain: "System and Information Integrity", domainCode: "SI", level: 1, title: "System & File Scanning", description: "Perform periodic scans of the information system and real-time scans of files from external sources", nistMapping: "3.14.5", status: "met", implementationStatus: "Continuous vulnerability scanning via engagement pipeline; real-time file scanning on uploads", assessmentObjectives: ["Verify scan schedule", "Review scan coverage", "Test real-time scanning"], evidenceRequired: ["Scan schedule", "Scan results", "Coverage report"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "SI-3" }], automationLevel: "full", poamEligible: false },
];

// ─── CMMC 2.0 Level 2 Practices (NIST 800-171 additions) ────────────────

const CMMC_L2_PRACTICES: CMMCPractice[] = [
  { id: "AC.L2-3.1.3", domain: "Access Control", domainCode: "AC", level: 2, title: "Control CUI Flow", description: "Control the flow of CUI in accordance with approved authorizations", nistMapping: "3.1.3", status: "met", implementationStatus: "Data flow controls between scan server, app server, and database; CUI tagged and tracked", assessmentObjectives: ["Review CUI flow controls", "Verify data classification", "Test flow enforcement"], evidenceRequired: ["Data flow diagram", "CUI inventory", "Flow control configuration"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "AC-4" }, { framework: "SOC2", controlId: "CC6.6" }], automationLevel: "full", poamEligible: true },
  { id: "AC.L2-3.1.4", domain: "Access Control", domainCode: "AC", level: 2, title: "Separation of Duties", description: "Separate the duties of individuals to reduce the risk of malevolent activity without collusion", nistMapping: "3.1.4", status: "met", implementationStatus: "6-role RBAC with separation: operators execute, analysts review, auditors audit, admins configure", assessmentObjectives: ["Review duty separation", "Verify no single role can approve and execute", "Test role boundaries"], evidenceRequired: ["Role matrix", "Duty separation documentation", "Access review records"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "AC-5" }, { framework: "SOC2", controlId: "CC6.3" }], automationLevel: "full", poamEligible: true },
  { id: "AC.L2-3.1.5", domain: "Access Control", domainCode: "AC", level: 2, title: "Least Privilege", description: "Employ the principle of least privilege, including for specific security functions and privileged accounts", nistMapping: "3.1.5", status: "met", implementationStatus: "Role-based nav filtering; procedure-level authorization; admin-only gates for destructive operations", assessmentObjectives: ["Verify minimum access", "Test privilege escalation", "Review privileged accounts"], evidenceRequired: ["Privilege matrix", "Access audit logs", "Penetration test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "AC-6" }, { framework: "SOC2", controlId: "CC6.3" }], automationLevel: "full", poamEligible: false },
  { id: "AC.L2-3.1.7", domain: "Access Control", domainCode: "AC", level: 2, title: "Privileged Functions", description: "Prevent non-privileged users from executing privileged functions and capture the execution in audit logs", nistMapping: "3.1.7", status: "met", implementationStatus: "adminProcedure gate prevents non-admin execution; all privileged actions logged in audit trail", assessmentObjectives: ["Verify privileged function controls", "Test non-privileged user access", "Review audit logs"], evidenceRequired: ["Privileged function inventory", "Access control configuration", "Audit logs"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "AC-6" }], automationLevel: "full", poamEligible: false },
  { id: "AC.L2-3.1.8", domain: "Access Control", domainCode: "AC", level: 2, title: "Unsuccessful Logon Attempts", description: "Limit unsuccessful logon attempts", nistMapping: "3.1.8", status: "met", implementationStatus: "OAuth provider enforces account lockout after consecutive failed attempts", assessmentObjectives: ["Verify lockout configuration", "Test lockout mechanism", "Review lockout logs"], evidenceRequired: ["Lockout configuration", "Failed login logs", "Lockout test results"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "AC-7" }], automationLevel: "full", poamEligible: true },
  { id: "AC.L2-3.1.9", domain: "Access Control", domainCode: "AC", level: 2, title: "Privacy & Security Notices", description: "Provide privacy and security notices consistent with applicable CUI rules", nistMapping: "3.1.9", status: "partially_met", implementationStatus: "Login page shows terms; system use banner not on all entry points", assessmentObjectives: ["Verify notice display", "Review notice content", "Test all entry points"], evidenceRequired: ["Banner screenshots", "Notice content", "Entry point inventory"], sprsWeight: 1, crossMappings: [{ framework: "FedRAMP", controlId: "AC-8" }], automationLevel: "partial", poamEligible: true },
  { id: "AC.L2-3.1.10", domain: "Access Control", domainCode: "AC", level: 2, title: "Session Lock", description: "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity", nistMapping: "3.1.10", status: "met", implementationStatus: "JWT session expiry with automatic logout; session invalidation on server restart", assessmentObjectives: ["Verify session timeout", "Test automatic lock", "Review timeout configuration"], evidenceRequired: ["Session configuration", "Timeout logs", "Lock test results"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "AC-11" }], automationLevel: "full", poamEligible: true },
  { id: "AC.L2-3.1.12", domain: "Access Control", domainCode: "AC", level: 2, title: "Control Remote Access", description: "Monitor and control remote access sessions", nistMapping: "3.1.12", status: "met", implementationStatus: "All access via HTTPS with OAuth; SSH to scan server with key-based auth and audit logging", assessmentObjectives: ["Review remote access methods", "Verify monitoring", "Test access controls"], evidenceRequired: ["Remote access policy", "SSH key records", "Access logs"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "AC-17" }], automationLevel: "full", poamEligible: true },
  { id: "AU.L2-3.3.1", domain: "Audit and Accountability", domainCode: "AU", level: 2, title: "System Auditing", description: "Create and retain system audit logs and records to the extent needed to enable monitoring, analysis, investigation, and reporting", nistMapping: "3.3.1", status: "met", implementationStatus: "Comprehensive audit logging across all tRPC procedures, engagement actions, and safety decisions", assessmentObjectives: ["Verify audit log generation", "Review log retention", "Test log completeness"], evidenceRequired: ["Audit configuration", "Sample logs", "Retention policy"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "AU-2" }, { framework: "SOC2", controlId: "CC7.1" }], automationLevel: "full", poamEligible: false },
  { id: "AU.L2-3.3.2", domain: "Audit and Accountability", domainCode: "AU", level: 2, title: "User Accountability", description: "Ensure that the actions of individual system users can be uniquely traced to those users", nistMapping: "3.3.2", status: "met", implementationStatus: "All actions linked to authenticated userId via tRPC context; immutable audit trail", assessmentObjectives: ["Verify user traceability", "Review audit trail", "Test attribution accuracy"], evidenceRequired: ["Audit trail samples", "User attribution configuration", "Traceability test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "AU-3" }, { framework: "SOC2", controlId: "CC7.2" }], automationLevel: "full", poamEligible: false },
  { id: "AU.L2-3.3.8", domain: "Audit and Accountability", domainCode: "AU", level: 2, title: "Audit Protection", description: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion", nistMapping: "3.3.8", status: "met", implementationStatus: "Audit logs in separate DB tables with admin-only access; append-only design prevents modification", assessmentObjectives: ["Verify log protection", "Test unauthorized modification", "Review access controls"], evidenceRequired: ["Log protection configuration", "Access control for logs", "Integrity test results"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "AU-9" }], automationLevel: "full", poamEligible: false },
  { id: "CA.L2-3.12.1", domain: "Security Assessment", domainCode: "CA", level: 2, title: "Security Control Assessment", description: "Periodically assess the security controls to determine if the controls are effective in their application", nistMapping: "3.12.1", status: "met", implementationStatus: "AC3 automated penetration testing validates security controls continuously via engagement pipeline", assessmentObjectives: ["Review assessment methodology", "Verify assessment frequency", "Review assessment results"], evidenceRequired: ["Assessment plan", "Assessment results", "Remediation tracking"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "CA-2" }, { framework: "SOC2", controlId: "CC4.1" }], automationLevel: "full", poamEligible: false },
  { id: "CA.L2-3.12.3", domain: "Security Assessment", domainCode: "CA", level: 2, title: "Monitor Security Controls", description: "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls", nistMapping: "3.12.3", status: "met", implementationStatus: "Continuous monitoring via engagement pipeline with automated scanning and compliance dashboard", assessmentObjectives: ["Review monitoring strategy", "Verify continuous monitoring", "Test alerting"], evidenceRequired: ["Monitoring strategy", "Scan schedules", "Alert configuration"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "CA-7" }], automationLevel: "full", poamEligible: false },
  { id: "CM.L2-3.4.1", domain: "Configuration Management", domainCode: "CM", level: 2, title: "System Baselining", description: "Establish and maintain baseline configurations and inventories of organizational systems", nistMapping: "3.4.1", status: "met", implementationStatus: "Git-based configuration management with version-controlled baselines; asset discovery maintains inventory", assessmentObjectives: ["Review baseline configurations", "Verify version control", "Test inventory accuracy"], evidenceRequired: ["Baseline documentation", "Version history", "Inventory records"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "CM-2" }, { framework: "SOC2", controlId: "CC8.1" }], automationLevel: "full", poamEligible: false },
  { id: "CM.L2-3.4.2", domain: "Configuration Management", domainCode: "CM", level: 2, title: "Security Configuration Enforcement", description: "Establish and enforce security configuration settings for information technology products", nistMapping: "3.4.2", status: "met", implementationStatus: "Environment variables via secrets management; FIPS-validated crypto settings; hardening baselines", assessmentObjectives: ["Review configuration standards", "Verify enforcement", "Test compliance"], evidenceRequired: ["Configuration standards", "Enforcement records", "Compliance scan results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "CM-6" }], automationLevel: "full", poamEligible: false },
  { id: "CM.L2-3.4.3", domain: "Configuration Management", domainCode: "CM", level: 2, title: "System Change Management", description: "Track, review, approve or disapprove, and log changes to organizational systems", nistMapping: "3.4.3", status: "met", implementationStatus: "Git PR workflow with required reviews; checkpoint/rollback system; deployment pipeline enforcement", assessmentObjectives: ["Review change management process", "Verify approval workflow", "Test change logging"], evidenceRequired: ["Change management procedures", "PR history", "Approval records"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "CM-3" }], automationLevel: "full", poamEligible: true },
  { id: "CM.L2-3.4.6", domain: "Configuration Management", domainCode: "CM", level: 2, title: "Least Functionality", description: "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities", nistMapping: "3.4.6", status: "met", implementationStatus: "Minimal container images; only required services enabled; unnecessary ports blocked", assessmentObjectives: ["Review enabled services", "Verify minimal attack surface", "Test unnecessary services"], evidenceRequired: ["Service inventory", "Port scan results", "Package list"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "CM-7" }], automationLevel: "full", poamEligible: true },
  { id: "IA.L2-3.5.3", domain: "Identification and Authentication", domainCode: "IA", level: 2, title: "Multifactor Authentication", description: "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts", nistMapping: "3.5.3", status: "met", implementationStatus: "OAuth provider supports MFA; enforced for all admin accounts", assessmentObjectives: ["Verify MFA configuration", "Test MFA enforcement", "Review MFA enrollment"], evidenceRequired: ["MFA configuration", "Enrollment records", "MFA test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "IA-2" }], automationLevel: "full", poamEligible: false },
  { id: "IA.L2-3.5.10", domain: "Identification and Authentication", domainCode: "IA", level: 2, title: "Cryptographically-Protected Passwords", description: "Store and transmit only cryptographically-protected passwords", nistMapping: "3.5.10", status: "met", implementationStatus: "OAuth tokens with secure transmission; no plaintext passwords stored; JWT with HMAC-SHA256", assessmentObjectives: ["Verify password protection", "Test transmission security", "Review storage mechanisms"], evidenceRequired: ["Crypto configuration", "Transmission analysis", "Storage audit"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "IA-5" }], automationLevel: "full", poamEligible: false },
  { id: "IR.L2-3.6.1", domain: "Incident Response", domainCode: "IR", level: 2, title: "Incident Handling", description: "Establish an operational incident-handling capability for organizational systems", nistMapping: "3.6.1", status: "partially_met", implementationStatus: "Bug report system with severity classification; automated threat detection; formal IR plan in development", assessmentObjectives: ["Review IR capability", "Verify incident handling procedures", "Test incident response"], evidenceRequired: ["IR plan", "Handling procedures", "Test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "IR-4" }, { framework: "SOC2", controlId: "CC7.3" }], automationLevel: "partial", poamEligible: true },
  { id: "IR.L2-3.6.2", domain: "Incident Response", domainCode: "IR", level: 2, title: "Incident Reporting", description: "Track, document, and report incidents to designated officials and/or authorities", nistMapping: "3.6.2", status: "met", implementationStatus: "Bug report quick action; owner notification on critical incidents; safety engine audit trail", assessmentObjectives: ["Verify reporting mechanisms", "Test notification flow", "Review incident records"], evidenceRequired: ["Reporting procedures", "Notification configuration", "Incident records"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "IR-6" }], automationLevel: "full", poamEligible: true },
  { id: "MA.L2-3.7.5", domain: "Maintenance", domainCode: "MA", level: 2, title: "Nonlocal Maintenance", description: "Require multifactor authentication to establish nonlocal maintenance sessions and terminate such sessions when nonlocal maintenance is complete", nistMapping: "3.7.5", status: "met", implementationStatus: "SSH key-based access for scan server maintenance; session termination on disconnect", assessmentObjectives: ["Verify maintenance authentication", "Test session termination", "Review maintenance logs"], evidenceRequired: ["Maintenance procedures", "Authentication records", "Session logs"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "MA-4" }], automationLevel: "full", poamEligible: true },
  { id: "RA.L2-3.11.1", domain: "Risk Assessment", domainCode: "RA", level: 2, title: "Risk Assessments", description: "Periodically assess the risk to organizational operations, assets, and individuals", nistMapping: "3.11.1", status: "met", implementationStatus: "CARVER+Shock scoring and CVSS pipeline provide continuous automated risk assessment", assessmentObjectives: ["Review risk assessment methodology", "Verify assessment frequency", "Review results"], evidenceRequired: ["Risk assessment policy", "CARVER+Shock methodology", "Assessment results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "RA-3" }, { framework: "SOC2", controlId: "CC3.2" }], automationLevel: "full", poamEligible: false },
  { id: "RA.L2-3.11.2", domain: "Risk Assessment", domainCode: "RA", level: 2, title: "Vulnerability Scan", description: "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities are identified", nistMapping: "3.11.2", status: "met", implementationStatus: "Continuous scanning via nuclei, ZAP, ScanForge discovery with corroboration engine and CISA KEV integration", assessmentObjectives: ["Review scan schedule", "Verify vulnerability tracking", "Test scan coverage"], evidenceRequired: ["Scan results", "Remediation tracking", "Scan schedule"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "RA-5" }, { framework: "SOC2", controlId: "CC3.2" }], automationLevel: "full", poamEligible: false },
  { id: "RA.L2-3.11.3", domain: "Risk Assessment", domainCode: "RA", level: 2, title: "Vulnerability Remediation", description: "Remediate vulnerabilities in accordance with risk assessments", nistMapping: "3.11.3", status: "met", implementationStatus: "Remediation tracking via engagement pipeline with priority-based remediation and verification scanning", assessmentObjectives: ["Review remediation process", "Verify priority-based approach", "Test remediation verification"], evidenceRequired: ["Remediation records", "Priority matrix", "Verification scans"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "RA-5" }], automationLevel: "full", poamEligible: false },
  { id: "SC.L2-3.13.8", domain: "System and Communications Protection", domainCode: "SC", level: 2, title: "CUI Encryption", description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission", nistMapping: "3.13.8", status: "met", implementationStatus: "TLS 1.3 for all web traffic; SSH for scan server; FIPS-validated crypto modules", assessmentObjectives: ["Verify encryption in transit", "Test for weak ciphers", "Review crypto configuration"], evidenceRequired: ["TLS scan results", "Cipher configuration", "FIPS validation"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SC-8" }], automationLevel: "full", poamEligible: false },
  { id: "SC.L2-3.13.10", domain: "System and Communications Protection", domainCode: "SC", level: 2, title: "Key Management", description: "Establish and manage cryptographic keys for cryptography employed in organizational systems", nistMapping: "3.13.10", status: "met", implementationStatus: "JWT secrets via env variables; SSH key rotation; FIPS compliance module tracks all crypto operations", assessmentObjectives: ["Review key management", "Verify rotation schedule", "Test key protection"], evidenceRequired: ["Key management procedures", "Rotation records", "FIPS documentation"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "SC-12" }], automationLevel: "full", poamEligible: true },
  { id: "SC.L2-3.13.11", domain: "System and Communications Protection", domainCode: "SC", level: 2, title: "CUI Encryption at Rest", description: "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI", nistMapping: "3.13.11", status: "met", implementationStatus: "Database encryption at rest via TiDB; S3 server-side encryption; FIPS 140-2/3 validated modules", assessmentObjectives: ["Verify encryption at rest", "Review FIPS validation", "Test data protection"], evidenceRequired: ["Encryption configuration", "FIPS certificates", "Data protection test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SC-28" }], automationLevel: "full", poamEligible: false },
  { id: "SC.L2-3.13.16", domain: "System and Communications Protection", domainCode: "SC", level: 2, title: "Data at Rest", description: "Protect the confidentiality of CUI at rest", nistMapping: "3.13.16", status: "met", implementationStatus: "Full disk encryption on cloud instances; database encryption; S3 SSE", assessmentObjectives: ["Verify data at rest protection", "Review encryption coverage", "Test protection mechanisms"], evidenceRequired: ["Encryption configuration", "Coverage report", "Test results"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SC-28" }], automationLevel: "full", poamEligible: false },
  { id: "SI.L2-3.14.3", domain: "System and Information Integrity", domainCode: "SI", level: 2, title: "Security Alerts & Advisories", description: "Monitor system security alerts and advisories and take action in response", nistMapping: "3.14.3", status: "met", implementationStatus: "CISA KEV feed integration; CVE monitoring; threat intelligence from multiple sources; automated alerting", assessmentObjectives: ["Verify alert monitoring", "Review response procedures", "Test alerting"], evidenceRequired: ["Feed configuration", "Alert records", "Response procedures"], sprsWeight: 3, crossMappings: [{ framework: "FedRAMP", controlId: "SI-5" }], automationLevel: "full", poamEligible: true },
  { id: "SI.L2-3.14.6", domain: "System and Information Integrity", domainCode: "SI", level: 2, title: "Monitor Communications", description: "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks", nistMapping: "3.14.6", status: "met", implementationStatus: "Real-time engagement monitoring; safety engine audit trail; threat actor mapping; anomaly detection", assessmentObjectives: ["Review monitoring configuration", "Verify detection capabilities", "Test alerting"], evidenceRequired: ["Monitoring configuration", "Detection rules", "Alert records"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SI-4" }], automationLevel: "full", poamEligible: false },
  { id: "SI.L2-3.14.7", domain: "System and Information Integrity", domainCode: "SI", level: 2, title: "Identify Unauthorized Use", description: "Identify unauthorized use of organizational systems", nistMapping: "3.14.7", status: "met", implementationStatus: "Session monitoring; role-based access logging; anomalous activity detection via safety engine", assessmentObjectives: ["Review detection mechanisms", "Test unauthorized use scenarios", "Review alert configuration"], evidenceRequired: ["Detection configuration", "Alert records", "Investigation procedures"], sprsWeight: 5, crossMappings: [{ framework: "FedRAMP", controlId: "SI-4" }], automationLevel: "full", poamEligible: false },
];

// ─── Combined Practices ─────────────────────────────────────────────────────

export const CMMC_PRACTICES: CMMCPractice[] = [...CMMC_L1_PRACTICES, ...CMMC_L2_PRACTICES];

// ─── SPRS Score Calculation ─────────────────────────────────────────────────

export function calculateSPRSScore(): SPRSScore {
  const l2Practices = CMMC_PRACTICES.filter(p => p.level <= 2);
  let totalDeductions = 0;
  let metCount = 0;
  let partialCount = 0;
  let notMetCount = 0;
  let naCount = 0;

  const domainScores = new Map<string, { score: number; maxScore: number }>();

  for (const p of l2Practices) {
    if (!domainScores.has(p.domain)) {
      domainScores.set(p.domain, { score: 0, maxScore: 0 });
    }
    const ds = domainScores.get(p.domain)!;
    ds.maxScore += p.sprsWeight;

    if (p.status === "met") {
      metCount++;
      ds.score += p.sprsWeight;
    } else if (p.status === "partially_met") {
      partialCount++;
      totalDeductions += Math.ceil(p.sprsWeight / 2);
      ds.score += Math.floor(p.sprsWeight / 2);
    } else if (p.status === "not_met") {
      notMetCount++;
      totalDeductions += p.sprsWeight;
    } else {
      naCount++;
      ds.score += p.sprsWeight; // N/A counts as met
    }
  }

  const maxScore = 110;
  const totalScore = Math.max(-203, maxScore - totalDeductions);
  const poamCount = l2Practices.filter(p => p.status !== "met" && p.poamEligible).length;

  return {
    totalScore,
    maxScore,
    metPractices: metCount,
    partialPractices: partialCount,
    notMetPractices: notMetCount,
    notApplicable: naCount,
    weightedDeductions: totalDeductions,
    level1Ready: CMMC_L1_PRACTICES.every(p => p.status === "met" || p.status === "not_applicable"),
    level2Ready: totalScore >= 110,
    poamCount,
    conditionalCertEligible: totalScore >= 80 && notMetCount <= 5,
    breakdown: Array.from(domainScores.entries()).map(([domain, data]) => ({
      domain,
      score: data.score,
      maxScore: data.maxScore,
      percentage: Math.round(data.score / data.maxScore * 100),
    })),
  };
}

// ─── Domain Summary ─────────────────────────────────────────────────────────

export function getCMMCDomainSummary() {
  const domains = new Map<string, { code: string; total: number; met: number; partial: number; notMet: number; na: number; l1: number; l2: number }>();
  for (const p of CMMC_PRACTICES) {
    if (!domains.has(p.domain)) {
      domains.set(p.domain, { code: p.domainCode, total: 0, met: 0, partial: 0, notMet: 0, na: 0, l1: 0, l2: 0 });
    }
    const d = domains.get(p.domain)!;
    d.total++;
    if (p.level === 1) d.l1++;
    else d.l2++;
    if (p.status === "met") d.met++;
    else if (p.status === "partially_met") d.partial++;
    else if (p.status === "not_met") d.notMet++;
    else d.na++;
  }
  return Array.from(domains.entries()).map(([name, data]) => ({ name, ...data }));
}

// ─── Assessment Generator ───────────────────────────────────────────────────

export function generateCMMCAssessment(): CMMCAssessment {
  const sprs = calculateSPRSScore();
  const now = Date.now();
  return {
    id: "CMMC-ASM-001",
    type: "self",
    level: 2,
    status: "in_progress",
    assessorOrg: null,
    startDate: now - 30 * 24 * 60 * 60 * 1000,
    completionDate: null,
    certificationDate: null,
    expirationDate: null,
    findings: CMMC_PRACTICES.filter(p => p.status !== "met" && p.status !== "not_applicable").map(p => ({
      practiceId: p.id,
      finding: p.implementationStatus,
      severity: p.sprsWeight >= 5 ? "major" as const : p.sprsWeight >= 3 ? "minor" as const : "observation" as const,
    })),
    sprsScore: sprs.totalScore,
    affirmationStatus: "pending",
  };
}
