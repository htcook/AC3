/**
 * Compliance Framework Mapping Engine
 * Maps penetration testing findings to SOC 2, ISO 27001, NIST CSF, PCI DSS,
 * FedRAMP, DoD STIG, and CMMC 2.0 controls.
 */

export interface ComplianceControlDef {
  controlId: string;
  controlName: string;
  category: string;
  subcategory?: string;
  description: string;
  testProcedures: string[];
}

// ── SOC 2 Type II Trust Service Criteria ────────────────────────────────
export const SOC2_CONTROLS: ComplianceControlDef[] = [
  { controlId: "CC1.1", controlName: "COSO Principle 1: Integrity and Ethical Values", category: "Control Environment", description: "The entity demonstrates a commitment to integrity and ethical values", testProcedures: ["Review code of conduct", "Interview management about tone at the top"] },
  { controlId: "CC2.1", controlName: "Information and Communication", category: "Communication", description: "The entity obtains or generates and uses relevant, quality information", testProcedures: ["Review information classification policy", "Test data flow documentation"] },
  { controlId: "CC3.1", controlName: "Risk Assessment", category: "Risk Assessment", description: "The entity specifies objectives with sufficient clarity to enable identification and assessment of risks", testProcedures: ["Review risk assessment methodology", "Verify risk register completeness"] },
  { controlId: "CC5.1", controlName: "Control Activities: Logical Access", category: "Logical Access", description: "The entity selects and develops control activities that contribute to the mitigation of risks", testProcedures: ["Test access control policies", "Verify MFA enforcement", "Review privileged access management"] },
  { controlId: "CC5.2", controlName: "Control Activities: Technology Controls", category: "Technology Controls", description: "The entity deploys control activities through policies and technology", testProcedures: ["Test firewall rules", "Verify encryption standards", "Review patch management"] },
  { controlId: "CC6.1", controlName: "Logical and Physical Access Controls", category: "Access Control", description: "The entity implements logical access security software, infrastructure, and architectures", testProcedures: ["Penetration test network segmentation", "Test authentication mechanisms", "Verify authorization controls"] },
  { controlId: "CC6.2", controlName: "User Registration and Authorization", category: "Access Control", description: "Prior to issuing system credentials, the entity registers and authorizes new users", testProcedures: ["Review user provisioning process", "Test account creation workflow", "Verify access approval records"] },
  { controlId: "CC6.3", controlName: "Role-Based Access", category: "Access Control", description: "The entity authorizes, modifies, or removes access based on roles", testProcedures: ["Test RBAC implementation", "Verify separation of duties", "Review access recertification"] },
  { controlId: "CC6.6", controlName: "System Boundaries and Threat Management", category: "System Operations", description: "The entity implements controls to prevent or detect and act upon unauthorized access", testProcedures: ["Test IDS/IPS effectiveness", "Verify WAF configuration", "Penetration test external boundaries"] },
  { controlId: "CC6.7", controlName: "Data Transmission Security", category: "Data Protection", description: "The entity restricts the transmission of data to authorized channels", testProcedures: ["Test TLS configuration", "Verify certificate management", "Test data loss prevention"] },
  { controlId: "CC6.8", controlName: "Malware Prevention", category: "System Operations", description: "The entity implements controls to prevent or detect and act upon the introduction of malware", testProcedures: ["Test EDR effectiveness", "Verify email security controls", "Test endpoint protection"] },
  { controlId: "CC7.1", controlName: "Monitoring Infrastructure", category: "Monitoring", description: "The entity uses detection and monitoring procedures to identify changes to configurations", testProcedures: ["Test SIEM alerting", "Verify log collection coverage", "Test change detection mechanisms"] },
  { controlId: "CC7.2", controlName: "Anomaly Detection", category: "Monitoring", description: "The entity monitors system components and the operation of those components for anomalies", testProcedures: ["Test anomaly detection rules", "Verify baseline monitoring", "Test alert escalation"] },
  { controlId: "CC7.3", controlName: "Incident Response", category: "Incident Response", description: "The entity evaluates security events to determine whether they constitute incidents", testProcedures: ["Test incident classification", "Verify IR playbooks", "Conduct tabletop exercise"] },
  { controlId: "CC8.1", controlName: "Change Management", category: "Change Management", description: "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes", testProcedures: ["Review change management process", "Test change approval workflow", "Verify rollback procedures"] },
  { controlId: "CC9.1", controlName: "Risk Mitigation", category: "Risk Mitigation", description: "The entity identifies, selects, and develops risk mitigation activities", testProcedures: ["Review risk treatment plans", "Verify control implementation", "Test compensating controls"] },
];

// ── ISO 27001:2022 Annex A Controls ─────────────────────────────────────
export const ISO27001_CONTROLS: ComplianceControlDef[] = [
  { controlId: "A.5.1", controlName: "Policies for Information Security", category: "Organizational", description: "Information security policy and topic-specific policies shall be defined and approved", testProcedures: ["Review policy documentation", "Verify policy approval and communication"] },
  { controlId: "A.5.7", controlName: "Threat Intelligence", category: "Organizational", description: "Information relating to information security threats shall be collected and analyzed", testProcedures: ["Review threat intelligence feeds", "Verify threat analysis process", "Test threat indicator integration"] },
  { controlId: "A.5.23", controlName: "Information Security for Cloud Services", category: "Organizational", description: "Processes for acquisition, use, management and exit from cloud services shall be established", testProcedures: ["Review cloud security policy", "Test cloud access controls", "Verify cloud configuration"] },
  { controlId: "A.6.1", controlName: "Screening", category: "People", description: "Background verification checks on all candidates shall be carried out", testProcedures: ["Review screening process", "Verify background check records"] },
  { controlId: "A.7.1", controlName: "Physical Security Perimeters", category: "Physical", description: "Security perimeters shall be defined and used to protect areas containing information", testProcedures: ["Physical security assessment", "Test access control systems"] },
  { controlId: "A.8.1", controlName: "User Endpoint Devices", category: "Technological", description: "Information stored on, processed by or accessible via user endpoint devices shall be protected", testProcedures: ["Test endpoint security controls", "Verify device encryption", "Test MDM effectiveness"] },
  { controlId: "A.8.3", controlName: "Information Access Restriction", category: "Technological", description: "Access to information and other associated assets shall be restricted", testProcedures: ["Test access control mechanisms", "Verify least privilege", "Test data classification enforcement"] },
  { controlId: "A.8.5", controlName: "Secure Authentication", category: "Technological", description: "Secure authentication technologies and procedures shall be established", testProcedures: ["Test authentication mechanisms", "Verify MFA implementation", "Test password policies"] },
  { controlId: "A.8.8", controlName: "Management of Technical Vulnerabilities", category: "Technological", description: "Information about technical vulnerabilities shall be obtained and appropriate measures taken", testProcedures: ["Review vulnerability management process", "Test patch management", "Verify vulnerability scanning"] },
  { controlId: "A.8.9", controlName: "Configuration Management", category: "Technological", description: "Configurations, including security configurations, shall be established and managed", testProcedures: ["Review hardening standards", "Test configuration baselines", "Verify configuration monitoring"] },
  { controlId: "A.8.12", controlName: "Data Leakage Prevention", category: "Technological", description: "Data leakage prevention measures shall be applied", testProcedures: ["Test DLP controls", "Verify data classification", "Test exfiltration prevention"] },
  { controlId: "A.8.15", controlName: "Logging", category: "Technological", description: "Logs that record activities, exceptions, faults and other relevant events shall be produced", testProcedures: ["Verify log collection", "Test log integrity", "Review log retention"] },
  { controlId: "A.8.16", controlName: "Monitoring Activities", category: "Technological", description: "Networks, systems and applications shall be monitored for anomalous behavior", testProcedures: ["Test monitoring coverage", "Verify alert thresholds", "Test detection capabilities"] },
  { controlId: "A.8.20", controlName: "Networks Security", category: "Technological", description: "Networks and network devices shall be secured, managed and controlled", testProcedures: ["Test network segmentation", "Verify firewall rules", "Test network access controls"] },
  { controlId: "A.8.24", controlName: "Use of Cryptography", category: "Technological", description: "Rules for the effective use of cryptography shall be defined and implemented", testProcedures: ["Test encryption implementation", "Verify key management", "Test TLS configuration"] },
  { controlId: "A.8.25", controlName: "Secure Development Life Cycle", category: "Technological", description: "Rules for the secure development of software and systems shall be established", testProcedures: ["Review SDLC process", "Test code review practices", "Verify security testing in CI/CD"] },
  { controlId: "A.8.28", controlName: "Secure Coding", category: "Technological", description: "Secure coding principles shall be applied to software development", testProcedures: ["Review coding standards", "Test for OWASP Top 10", "Verify SAST/DAST integration"] },
];

// ── NIST CSF 2.0 Categories ─────────────────────────────────────────────
export const NIST_CSF_CONTROLS: ComplianceControlDef[] = [
  { controlId: "GV.OC-01", controlName: "Organizational Context", category: "Govern", description: "The organizational mission is understood and informs cybersecurity risk management", testProcedures: ["Review mission alignment", "Verify risk appetite documentation"] },
  { controlId: "GV.RM-01", controlName: "Risk Management Strategy", category: "Govern", description: "Risk management objectives are established and expressed as risk tolerance statements", testProcedures: ["Review risk management framework", "Verify risk tolerance statements"] },
  { controlId: "ID.AM-01", controlName: "Asset Management", category: "Identify", subcategory: "Asset Management", description: "Inventories of hardware, software, services, and data are maintained", testProcedures: ["Review asset inventory", "Verify discovery scanning", "Test CMDB accuracy"] },
  { controlId: "ID.RA-01", controlName: "Risk Assessment", category: "Identify", subcategory: "Risk Assessment", description: "Vulnerabilities in assets are identified, validated, and recorded", testProcedures: ["Review vulnerability scanning", "Verify penetration testing", "Test risk scoring"] },
  { controlId: "PR.AA-01", controlName: "Identity Management and Access Control", category: "Protect", subcategory: "Access Control", description: "Identities and credentials for authorized users, services, and hardware are managed", testProcedures: ["Test identity lifecycle", "Verify credential management", "Test access provisioning"] },
  { controlId: "PR.AA-03", controlName: "Authentication", category: "Protect", subcategory: "Access Control", description: "Users, services, and hardware are authenticated", testProcedures: ["Test MFA implementation", "Verify authentication strength", "Test SSO security"] },
  { controlId: "PR.DS-01", controlName: "Data Security", category: "Protect", subcategory: "Data Security", description: "The confidentiality, integrity, and availability of data-at-rest are protected", testProcedures: ["Test encryption at rest", "Verify data classification", "Test backup integrity"] },
  { controlId: "PR.DS-02", controlName: "Data-in-Transit Protection", category: "Protect", subcategory: "Data Security", description: "The confidentiality, integrity, and availability of data-in-transit are protected", testProcedures: ["Test TLS configuration", "Verify certificate management", "Test VPN security"] },
  { controlId: "PR.PS-01", controlName: "Platform Security", category: "Protect", subcategory: "Platform Security", description: "The hardware, software, and services of physical and virtual platforms are managed", testProcedures: ["Test hardening baselines", "Verify patch management", "Test configuration management"] },
  { controlId: "DE.CM-01", controlName: "Continuous Monitoring", category: "Detect", subcategory: "Monitoring", description: "Networks and network services are monitored to find potentially adverse events", testProcedures: ["Test network monitoring", "Verify IDS/IPS effectiveness", "Test log analysis"] },
  { controlId: "DE.AE-02", controlName: "Adverse Event Analysis", category: "Detect", subcategory: "Analysis", description: "Potentially adverse events are analyzed to better understand associated activities", testProcedures: ["Test SIEM correlation rules", "Verify threat hunting", "Test alert triage"] },
  { controlId: "RS.MA-01", controlName: "Incident Management", category: "Respond", subcategory: "Management", description: "The incident response plan is executed in coordination with relevant third parties", testProcedures: ["Test IR plan execution", "Verify communication procedures", "Conduct tabletop exercise"] },
  { controlId: "RC.RP-01", controlName: "Recovery Planning", category: "Recover", subcategory: "Planning", description: "The recovery portion of the incident response plan is executed", testProcedures: ["Test recovery procedures", "Verify backup restoration", "Test business continuity"] },
];

// ── PCI DSS 4.0 Requirements ────────────────────────────────────────────
export const PCI_DSS_CONTROLS: ComplianceControlDef[] = [
  { controlId: "1.2.1", controlName: "Network Security Controls", category: "Requirement 1", description: "Network security controls (NSCs) are configured and maintained", testProcedures: ["Test firewall rules", "Verify network segmentation", "Test ACL effectiveness"] },
  { controlId: "2.2.1", controlName: "System Hardening Standards", category: "Requirement 2", description: "System configuration standards are developed, implemented, and maintained", testProcedures: ["Test hardening baselines", "Verify CIS benchmark compliance", "Test default credential removal"] },
  { controlId: "3.5.1", controlName: "PAN Protection", category: "Requirement 3", description: "Primary account number (PAN) is secured wherever it is stored", testProcedures: ["Test PAN encryption", "Verify tokenization", "Test data masking"] },
  { controlId: "4.2.1", controlName: "Strong Cryptography for Transmission", category: "Requirement 4", description: "Strong cryptography is used during transmission of PAN", testProcedures: ["Test TLS configuration", "Verify cipher suites", "Test certificate validation"] },
  { controlId: "5.2.1", controlName: "Anti-Malware Solution", category: "Requirement 5", description: "An anti-malware solution is deployed on all systems", testProcedures: ["Test EDR/AV effectiveness", "Verify signature updates", "Test malware detection"] },
  { controlId: "6.2.4", controlName: "Software Development Security", category: "Requirement 6", description: "Software engineering techniques or other methods are defined and in use", testProcedures: ["Review SDLC", "Test for OWASP Top 10", "Verify code review process"] },
  { controlId: "6.4.1", controlName: "Web Application Protection", category: "Requirement 6", description: "Public-facing web applications are protected against attacks", testProcedures: ["Test WAF effectiveness", "Verify web app scanning", "Test API security"] },
  { controlId: "7.2.1", controlName: "Access Control System", category: "Requirement 7", description: "An access control system is in place that restricts access based on need to know", testProcedures: ["Test RBAC implementation", "Verify least privilege", "Test access reviews"] },
  { controlId: "8.3.1", controlName: "Strong Authentication", category: "Requirement 8", description: "All user access to system components is authenticated", testProcedures: ["Test MFA implementation", "Verify password policies", "Test account lockout"] },
  { controlId: "10.2.1", controlName: "Audit Logging", category: "Requirement 10", description: "Audit logs are enabled and active for all system components", testProcedures: ["Verify log collection", "Test log integrity", "Review log retention"] },
  { controlId: "11.3.1", controlName: "Vulnerability Scanning", category: "Requirement 11", description: "Internal vulnerability scans are performed at least quarterly", testProcedures: ["Review scan schedules", "Verify remediation tracking", "Test scan coverage"] },
  { controlId: "11.4.1", controlName: "Penetration Testing", category: "Requirement 11", description: "External and internal penetration testing is regularly performed", testProcedures: ["Review pentest scope", "Verify methodology", "Test finding remediation"] },
  { controlId: "12.10.1", controlName: "Incident Response Plan", category: "Requirement 12", description: "An incident response plan exists and is ready to be activated", testProcedures: ["Review IR plan", "Test notification procedures", "Conduct IR exercise"] },
];

// ── FedRAMP Rev 5 Controls (based on NIST SP 800-53 Rev 5) ──────────────
export const FEDRAMP_CONTROLS: ComplianceControlDef[] = [
  // Access Control (AC)
  { controlId: "AC-1", controlName: "Policy and Procedures", category: "Access Control", description: "Develop, document, and disseminate access control policy and procedures", testProcedures: ["Review AC policy documentation", "Verify policy review cadence", "Test policy dissemination"] },
  { controlId: "AC-2", controlName: "Account Management", category: "Access Control", description: "Define and manage information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts", testProcedures: ["Review account provisioning process", "Test account lifecycle management", "Verify periodic access reviews"] },
  { controlId: "AC-3", controlName: "Access Enforcement", category: "Access Control", description: "Enforce approved authorizations for logical access to information and system resources", testProcedures: ["Test access control enforcement", "Verify RBAC implementation", "Test unauthorized access attempts"] },
  { controlId: "AC-4", controlName: "Information Flow Enforcement", category: "Access Control", description: "Enforce approved authorizations for controlling the flow of information within the system and between systems", testProcedures: ["Test network segmentation", "Verify data flow controls", "Test cross-boundary enforcement"] },
  { controlId: "AC-6", controlName: "Least Privilege", category: "Access Control", description: "Employ the principle of least privilege, allowing only authorized accesses necessary for organizational missions", testProcedures: ["Review privilege assignments", "Test least privilege enforcement", "Verify privilege escalation controls"] },
  { controlId: "AC-7", controlName: "Unsuccessful Logon Attempts", category: "Access Control", description: "Enforce a limit of consecutive invalid logon attempts and automatically lock the account", testProcedures: ["Test account lockout thresholds", "Verify lockout duration", "Test lockout notification"] },
  { controlId: "AC-17", controlName: "Remote Access", category: "Access Control", description: "Establish and document usage restrictions, configuration requirements, and implementation guidance for remote access", testProcedures: ["Test VPN configuration", "Verify remote access MFA", "Test remote session controls"] },
  // Audit and Accountability (AU)
  { controlId: "AU-2", controlName: "Event Logging", category: "Audit and Accountability", description: "Identify the types of events that the system is capable of logging in support of the audit function", testProcedures: ["Review audit event types", "Verify log completeness", "Test audit generation"] },
  { controlId: "AU-3", controlName: "Content of Audit Records", category: "Audit and Accountability", description: "Ensure audit records contain information that establishes what, when, where, source, outcome, and identity", testProcedures: ["Review audit record content", "Verify timestamp accuracy", "Test record completeness"] },
  { controlId: "AU-6", controlName: "Audit Record Review, Analysis, and Reporting", category: "Audit and Accountability", description: "Review and analyze system audit records for indications of inappropriate or unusual activity", testProcedures: ["Test SIEM integration", "Verify alert rules", "Test audit review process"] },
  { controlId: "AU-12", controlName: "Audit Record Generation", category: "Audit and Accountability", description: "Provide audit record generation capability for the event types the system is capable of auditing", testProcedures: ["Test audit generation across components", "Verify centralized collection", "Test audit integrity"] },
  // Configuration Management (CM)
  { controlId: "CM-2", controlName: "Baseline Configuration", category: "Configuration Management", description: "Develop, document, and maintain a current baseline configuration of the system", testProcedures: ["Review baseline documentation", "Test configuration compliance", "Verify baseline updates"] },
  { controlId: "CM-6", controlName: "Configuration Settings", category: "Configuration Management", description: "Establish and document configuration settings for components using security configuration checklists", testProcedures: ["Test hardening compliance", "Verify CIS/STIG benchmarks", "Test configuration monitoring"] },
  { controlId: "CM-7", controlName: "Least Functionality", category: "Configuration Management", description: "Configure the system to provide only mission-essential capabilities and restrict the use of unnecessary functions, ports, protocols, and services", testProcedures: ["Test service minimization", "Verify port restrictions", "Test unnecessary function removal"] },
  // Identification and Authentication (IA)
  { controlId: "IA-2", controlName: "Identification and Authentication (Organizational Users)", category: "Identification and Authentication", description: "Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users", testProcedures: ["Test user identification", "Verify MFA enforcement", "Test authentication mechanisms"] },
  { controlId: "IA-5", controlName: "Authenticator Management", category: "Identification and Authentication", description: "Manage system authenticators by verifying identity, establishing initial content, and ensuring administrative procedures are in place", testProcedures: ["Test password policies", "Verify credential rotation", "Test authenticator protection"] },
  // Incident Response (IR)
  { controlId: "IR-4", controlName: "Incident Handling", category: "Incident Response", description: "Implement an incident handling capability for incidents that includes preparation, detection, analysis, containment, eradication, and recovery", testProcedures: ["Test IR procedures", "Verify containment capabilities", "Conduct tabletop exercise"] },
  { controlId: "IR-6", controlName: "Incident Reporting", category: "Incident Response", description: "Require personnel to report suspected incidents to the organizational incident response capability within defined time periods", testProcedures: ["Test reporting procedures", "Verify reporting timelines", "Test FedRAMP-specific reporting (US-CERT)"] },
  // Risk Assessment (RA)
  { controlId: "RA-5", controlName: "Vulnerability Monitoring and Scanning", category: "Risk Assessment", description: "Monitor and scan for vulnerabilities in the system and hosted applications", testProcedures: ["Test vulnerability scanning", "Verify scan frequency", "Test remediation tracking"] },
  // System and Communications Protection (SC)
  { controlId: "SC-7", controlName: "Boundary Protection", category: "System and Communications Protection", description: "Monitor and control communications at the external managed interfaces and at key internal managed interfaces", testProcedures: ["Test boundary devices", "Verify DMZ configuration", "Test egress filtering"] },
  { controlId: "SC-8", controlName: "Transmission Confidentiality and Integrity", category: "System and Communications Protection", description: "Protect the confidentiality and integrity of transmitted information", testProcedures: ["Test TLS configuration", "Verify FIPS 140-2 compliance", "Test data-in-transit encryption"] },
  { controlId: "SC-12", controlName: "Cryptographic Key Establishment and Management", category: "System and Communications Protection", description: "Establish and manage cryptographic keys using NIST-approved key management technology and processes", testProcedures: ["Test key management procedures", "Verify FIPS-approved algorithms", "Test key rotation"] },
  { controlId: "SC-13", controlName: "Cryptographic Protection", category: "System and Communications Protection", description: "Implement FIPS-validated or NSA-approved cryptography", testProcedures: ["Verify FIPS 140-2/3 validation", "Test algorithm compliance", "Audit crypto implementations"] },
  { controlId: "SC-28", controlName: "Protection of Information at Rest", category: "System and Communications Protection", description: "Protect the confidentiality and integrity of information at rest", testProcedures: ["Test encryption at rest", "Verify key management", "Test data classification enforcement"] },
  // System and Information Integrity (SI)
  { controlId: "SI-2", controlName: "Flaw Remediation", category: "System and Information Integrity", description: "Identify, report, and correct system flaws in a timely manner", testProcedures: ["Test patch management", "Verify remediation SLAs (30/90/180 days)", "Test emergency patching"] },
  { controlId: "SI-3", controlName: "Malicious Code Protection", category: "System and Information Integrity", description: "Implement malicious code protection mechanisms at system entry and exit points", testProcedures: ["Test AV/EDR effectiveness", "Verify signature updates", "Test malware detection rates"] },
  { controlId: "SI-4", controlName: "System Monitoring", category: "System and Information Integrity", description: "Monitor the system to detect attacks, indicators of potential attacks, and unauthorized connections", testProcedures: ["Test IDS/IPS effectiveness", "Verify monitoring coverage", "Test alert response"] },
];

// ── DoD STIG Controls (Defense Information Systems Agency) ──────────────
export const DOD_STIG_CONTROLS: ComplianceControlDef[] = [
  // CAT I (Critical)
  { controlId: "V-254239", controlName: "OS Must Be Vendor Supported", category: "CAT I - Critical", description: "The operating system must be a vendor-supported release with security patches available", testProcedures: ["Verify OS version is vendor-supported", "Check end-of-life dates", "Verify patch availability"] },
  { controlId: "V-254240", controlName: "FIPS 140-2 Compliant Encryption", category: "CAT I - Critical", description: "The system must implement FIPS 140-2/3 validated cryptographic modules", testProcedures: ["Verify FIPS mode enabled", "Test crypto module validation", "Audit algorithm usage"] },
  { controlId: "V-254241", controlName: "No Unencrypted Remote Access", category: "CAT I - Critical", description: "All remote access sessions must be encrypted using FIPS-approved cryptography", testProcedures: ["Test SSH/TLS configuration", "Verify no Telnet/FTP", "Test remote access encryption"] },
  { controlId: "V-254242", controlName: "Disable Root SSH Login", category: "CAT I - Critical", description: "The system must not allow direct root login via SSH", testProcedures: ["Test SSH root login", "Verify PermitRootLogin setting", "Test su/sudo requirements"] },
  { controlId: "V-254243", controlName: "Password Complexity Requirements", category: "CAT I - Critical", description: "Passwords must meet DoD complexity requirements (15+ characters, uppercase, lowercase, numbers, special)", testProcedures: ["Test password policy enforcement", "Verify complexity rules", "Test minimum length"] },
  { controlId: "V-254244", controlName: "Disable Unused Services", category: "CAT I - Critical", description: "All unnecessary services, ports, and protocols must be disabled", testProcedures: ["Port scan for unnecessary services", "Verify service minimization", "Test disabled protocol enforcement"] },
  { controlId: "V-254245", controlName: "PKI-Based Authentication for Privileged Access", category: "CAT I - Critical", description: "Privileged access must require PKI-based multi-factor authentication (CAC/PIV)", testProcedures: ["Test CAC/PIV authentication", "Verify PKI certificate validation", "Test MFA enforcement for admins"] },
  // CAT II (High)
  { controlId: "V-254260", controlName: "Audit Log Protection", category: "CAT II - High", description: "Audit logs must be protected from unauthorized access, modification, and deletion", testProcedures: ["Test log file permissions", "Verify log integrity monitoring", "Test log forwarding to SIEM"] },
  { controlId: "V-254261", controlName: "Session Timeout", category: "CAT II - High", description: "Sessions must be terminated after 15 minutes of inactivity", testProcedures: ["Test session timeout enforcement", "Verify timeout configuration", "Test re-authentication requirement"] },
  { controlId: "V-254262", controlName: "Failed Login Attempt Lockout", category: "CAT II - High", description: "Accounts must be locked after 3 consecutive failed login attempts", testProcedures: ["Test account lockout threshold", "Verify lockout duration (15 min)", "Test administrator notification"] },
  { controlId: "V-254263", controlName: "Audit Record Content", category: "CAT II - High", description: "Audit records must contain sufficient information to establish what events occurred, when, where, and by whom", testProcedures: ["Review audit record fields", "Verify timestamp synchronization", "Test user attribution"] },
  { controlId: "V-254264", controlName: "System Patch Currency", category: "CAT II - High", description: "Security-relevant patches must be applied within the IAVM timeline (critical: 21 days, important: 30 days)", testProcedures: ["Verify patch compliance", "Test IAVM tracking", "Review patch deployment timeline"] },
  { controlId: "V-254265", controlName: "Antivirus/EDR Deployment", category: "CAT II - High", description: "Host-based intrusion detection/prevention and antivirus must be deployed on all endpoints", testProcedures: ["Verify EDR deployment coverage", "Test signature currency", "Verify real-time protection"] },
  { controlId: "V-254266", controlName: "Network Segmentation", category: "CAT II - High", description: "Networks must be segmented based on data classification and mission requirements", testProcedures: ["Test network segmentation", "Verify VLAN configuration", "Test cross-segment access controls"] },
  { controlId: "V-254267", controlName: "TLS 1.2 Minimum", category: "CAT II - High", description: "All web services must use TLS 1.2 or higher with FIPS-approved cipher suites", testProcedures: ["Test TLS version enforcement", "Verify cipher suite configuration", "Test protocol downgrade prevention"] },
  { controlId: "V-254268", controlName: "Backup and Recovery", category: "CAT II - High", description: "System backups must be performed regularly and tested for recoverability", testProcedures: ["Verify backup schedule", "Test backup restoration", "Verify offsite backup storage"] },
  // CAT III (Medium)
  { controlId: "V-254280", controlName: "Login Banner Display", category: "CAT III - Medium", description: "The system must display the DoD-approved login banner before granting access", testProcedures: ["Verify banner text matches DoD standard", "Test banner display on all access points", "Verify banner acknowledgment"] },
  { controlId: "V-254281", controlName: "Password History", category: "CAT III - Medium", description: "The system must prohibit password reuse for a minimum of 24 generations", testProcedures: ["Test password history enforcement", "Verify 24-generation minimum", "Test reuse prevention"] },
  { controlId: "V-254282", controlName: "Automatic Screen Lock", category: "CAT III - Medium", description: "The system must initiate a screen lock after 15 minutes of inactivity", testProcedures: ["Test screen lock timer", "Verify lock configuration", "Test re-authentication on unlock"] },
  { controlId: "V-254283", controlName: "USB Storage Restrictions", category: "CAT III - Medium", description: "Removable media must be restricted and controlled", testProcedures: ["Test USB policy enforcement", "Verify device control software", "Test unauthorized media detection"] },
];

// ── CMMC 2.0 (Cybersecurity Maturity Model Certification) ───────────────
export const CMMC_CONTROLS: ComplianceControlDef[] = [
  // Level 1 - Foundational (17 practices from FAR 52.204-21)
  { controlId: "AC.L1-3.1.1", controlName: "Authorized Access Control", category: "Level 1 - Access Control", description: "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices", testProcedures: ["Test access control enforcement", "Verify user authorization", "Test process-level access controls"] },
  { controlId: "AC.L1-3.1.2", controlName: "Transaction & Function Control", category: "Level 1 - Access Control", description: "Limit information system access to the types of transactions and functions that authorized users are permitted to execute", testProcedures: ["Test function-level authorization", "Verify transaction controls", "Test role-based restrictions"] },
  { controlId: "AC.L1-3.1.20", controlName: "External Connections", category: "Level 1 - Access Control", description: "Verify and control/limit connections to and use of external information systems", testProcedures: ["Test external connection controls", "Verify approved connections list", "Test unauthorized connection blocking"] },
  { controlId: "AC.L1-3.1.22", controlName: "Public Information Control", category: "Level 1 - Access Control", description: "Control information posted or processed on publicly accessible information systems", testProcedures: ["Review public-facing content", "Test content approval process", "Verify CUI is not publicly exposed"] },
  { controlId: "IA.L1-3.5.1", controlName: "Identification", category: "Level 1 - Identification & Authentication", description: "Identify information system users, processes acting on behalf of users, or devices", testProcedures: ["Test user identification", "Verify unique identifiers", "Test device identification"] },
  { controlId: "IA.L1-3.5.2", controlName: "Authentication", category: "Level 1 - Identification & Authentication", description: "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access", testProcedures: ["Test authentication mechanisms", "Verify credential validation", "Test multi-factor where required"] },
  { controlId: "MP.L1-3.8.3", controlName: "Media Disposal", category: "Level 1 - Media Protection", description: "Sanitize or destroy information system media containing Federal Contract Information before disposal or release for reuse", testProcedures: ["Test media sanitization procedures", "Verify destruction records", "Test sanitization effectiveness"] },
  { controlId: "PE.L1-3.10.1", controlName: "Physical Access Limitation", category: "Level 1 - Physical Protection", description: "Limit physical access to organizational information systems, equipment, and operating environments to authorized individuals", testProcedures: ["Test physical access controls", "Verify badge/key management", "Test visitor procedures"] },
  { controlId: "PE.L1-3.10.3", controlName: "Visitor Escort", category: "Level 1 - Physical Protection", description: "Escort visitors and monitor visitor activity", testProcedures: ["Test visitor escort procedures", "Verify visitor logs", "Test monitoring capabilities"] },
  { controlId: "SC.L1-3.13.1", controlName: "Boundary Protection", category: "Level 1 - System & Communications", description: "Monitor, control, and protect organizational communications at the external boundaries and key internal boundaries", testProcedures: ["Test boundary devices", "Verify monitoring coverage", "Test protection mechanisms"] },
  { controlId: "SC.L1-3.13.5", controlName: "Public-Access System Separation", category: "Level 1 - System & Communications", description: "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks", testProcedures: ["Test DMZ segmentation", "Verify logical separation", "Test cross-zone access"] },
  { controlId: "SI.L1-3.14.1", controlName: "Flaw Remediation", category: "Level 1 - System & Information Integrity", description: "Identify, report, and correct information and information system flaws in a timely manner", testProcedures: ["Test vulnerability management", "Verify patch timelines", "Test flaw reporting"] },
  { controlId: "SI.L1-3.14.2", controlName: "Malicious Code Protection", category: "Level 1 - System & Information Integrity", description: "Provide protection from malicious code at appropriate locations within organizational information systems", testProcedures: ["Test AV/EDR deployment", "Verify signature updates", "Test detection effectiveness"] },
  { controlId: "SI.L1-3.14.4", controlName: "Update Malicious Code Protection", category: "Level 1 - System & Information Integrity", description: "Update malicious code protection mechanisms when new releases are available", testProcedures: ["Verify auto-update configuration", "Test update frequency", "Verify update validation"] },
  { controlId: "SI.L1-3.14.5", controlName: "System & File Scanning", category: "Level 1 - System & Information Integrity", description: "Perform periodic scans of the information system and real-time scans of files from external sources", testProcedures: ["Test scheduled scan configuration", "Verify real-time scanning", "Test scan coverage"] },
  // Level 2 - Advanced (110 practices from NIST SP 800-171 Rev 2)
  { controlId: "AC.L2-3.1.3", controlName: "CUI Flow Enforcement", category: "Level 2 - Access Control", description: "Control the flow of CUI in accordance with approved authorizations", testProcedures: ["Test CUI data flow controls", "Verify DLP for CUI", "Test cross-boundary CUI transfers"] },
  { controlId: "AC.L2-3.1.4", controlName: "Separation of Duties", category: "Level 2 - Access Control", description: "Separate the duties of individuals to reduce the risk of malevolent activity without collusion", testProcedures: ["Test separation of duties", "Verify role conflicts", "Test dual-control requirements"] },
  { controlId: "AC.L2-3.1.5", controlName: "Least Privilege", category: "Level 2 - Access Control", description: "Employ the principle of least privilege, including for specific security functions and privileged accounts", testProcedures: ["Test least privilege enforcement", "Verify privileged account restrictions", "Test privilege escalation controls"] },
  { controlId: "AC.L2-3.1.7", controlName: "Privileged Function Control", category: "Level 2 - Access Control", description: "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs", testProcedures: ["Test privilege enforcement", "Verify audit logging of privileged actions", "Test unauthorized privilege attempts"] },
  { controlId: "AC.L2-3.1.12", controlName: "Remote Access Control", category: "Level 2 - Access Control", description: "Monitor and control remote access sessions", testProcedures: ["Test remote access monitoring", "Verify session controls", "Test VPN MFA enforcement"] },
  { controlId: "AU.L2-3.3.1", controlName: "System Auditing", category: "Level 2 - Audit & Accountability", description: "Create and retain system audit logs and records to the extent needed to enable monitoring, analysis, investigation, and reporting", testProcedures: ["Test audit log generation", "Verify retention periods", "Test log completeness"] },
  { controlId: "AU.L2-3.3.2", controlName: "User Accountability", category: "Level 2 - Audit & Accountability", description: "Ensure that the actions of individual system users can be uniquely traced to those users", testProcedures: ["Test user attribution", "Verify unique identification in logs", "Test non-repudiation"] },
  { controlId: "AT.L2-3.2.1", controlName: "Security Awareness Training", category: "Level 2 - Awareness & Training", description: "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks", testProcedures: ["Verify training completion records", "Test training content relevance", "Verify annual refresher training"] },
  { controlId: "CM.L2-3.4.1", controlName: "System Baselining", category: "Level 2 - Configuration Management", description: "Establish and maintain baseline configurations and inventories of organizational systems", testProcedures: ["Review baseline documentation", "Test configuration compliance", "Verify inventory accuracy"] },
  { controlId: "IR.L2-3.6.1", controlName: "Incident Handling", category: "Level 2 - Incident Response", description: "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities", testProcedures: ["Test IR plan execution", "Verify IR team readiness", "Conduct tabletop exercise"] },
  { controlId: "IR.L2-3.6.2", controlName: "Incident Reporting", category: "Level 2 - Incident Response", description: "Track, document, and report incidents to designated officials and/or authorities", testProcedures: ["Test incident reporting procedures", "Verify DIBCAC reporting (72 hours)", "Test documentation completeness"] },
  { controlId: "RA.L2-3.11.1", controlName: "Risk Assessment", category: "Level 2 - Risk Assessment", description: "Periodically assess the risk to organizational operations, organizational assets, and individuals", testProcedures: ["Review risk assessment methodology", "Verify assessment frequency", "Test risk scoring accuracy"] },
  { controlId: "RA.L2-3.11.2", controlName: "Vulnerability Scanning", category: "Level 2 - Risk Assessment", description: "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities are identified", testProcedures: ["Test vulnerability scanning", "Verify scan frequency", "Test remediation tracking"] },
  { controlId: "SC.L2-3.13.8", controlName: "CUI Encryption in Transit", category: "Level 2 - System & Communications", description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission", testProcedures: ["Test encryption of CUI in transit", "Verify FIPS-validated crypto", "Test protocol configuration"] },
  { controlId: "SC.L2-3.13.11", controlName: "CUI Encryption at Rest", category: "Level 2 - System & Communications", description: "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI", testProcedures: ["Test CUI encryption at rest", "Verify FIPS 140-2 validation", "Test key management"] },
  { controlId: "SC.L2-3.13.15", controlName: "Communications Authenticity", category: "Level 2 - System & Communications", description: "Protect the authenticity of communications sessions", testProcedures: ["Test session authentication", "Verify certificate validation", "Test replay protection"] },
  // Level 3 - Expert (24 additional practices from NIST SP 800-172)
  { controlId: "AC.L3-3.1.2e", controlName: "Dual Authorization", category: "Level 3 - Access Control", description: "Employ dual authorization to execute critical or sensitive system and organizational operations", testProcedures: ["Test dual-authorization enforcement", "Verify critical operation controls", "Test bypass prevention"] },
  { controlId: "IR.L3-3.6.1e", controlName: "Security Operations Center", category: "Level 3 - Incident Response", description: "Establish and maintain a security operations center capability", testProcedures: ["Verify SOC staffing and coverage", "Test SOC monitoring capabilities", "Verify 24/7 coverage"] },
  { controlId: "RA.L3-3.11.1e", controlName: "Threat Hunting", category: "Level 3 - Risk Assessment", description: "Employ threat hunting techniques to search for indicators of compromise and advanced persistent threats", testProcedures: ["Test threat hunting procedures", "Verify hunting tool capabilities", "Test IOC detection"] },
  { controlId: "SI.L3-3.14.3e", controlName: "Advanced Threat Protection", category: "Level 3 - System & Information Integrity", description: "Employ advanced automated tools and techniques to respond to and contain cyber incidents", testProcedures: ["Test automated response capabilities", "Verify SOAR integration", "Test containment automation"] },
];

export const ALL_FRAMEWORKS = {
  soc2: { name: "SOC 2 Type II", version: "2022", controls: SOC2_CONTROLS },
  iso27001: { name: "ISO 27001:2022", version: "2022", controls: ISO27001_CONTROLS },
  nist_csf: { name: "NIST CSF 2.0", version: "2.0", controls: NIST_CSF_CONTROLS },
  pci_dss: { name: "PCI DSS 4.0", version: "4.0", controls: PCI_DSS_CONTROLS },
  fedramp: { name: "FedRAMP Rev 5", version: "Rev 5", controls: FEDRAMP_CONTROLS },
  dod_stig: { name: "DoD STIG", version: "2024", controls: DOD_STIG_CONTROLS },
  cmmc: { name: "CMMC 2.0", version: "2.0", controls: CMMC_CONTROLS },
};

/**
 * Auto-map pentest findings to compliance controls
 */
export function autoMapFindings(
  frameworkType: keyof typeof ALL_FRAMEWORKS,
  findings: Array<{ type: string; severity: string; category: string }>
): Array<{ controlId: string; status: "covered" | "gap" | "partial"; findingCount: number }> {
  const framework = ALL_FRAMEWORKS[frameworkType];
  return framework.controls.map(control => {
    const relatedFindings = findings.filter(f => {
      const cat = f.category.toLowerCase();
      const cname = control.controlName.toLowerCase();
      const cdesc = control.description.toLowerCase();
      return cat.includes("access") && (cname.includes("access") || cdesc.includes("access")) ||
             cat.includes("network") && (cname.includes("network") || cdesc.includes("network")) ||
             cat.includes("crypto") && (cname.includes("crypto") || cdesc.includes("crypto")) ||
             cat.includes("auth") && (cname.includes("auth") || cdesc.includes("auth")) ||
             cat.includes("monitor") && (cname.includes("monitor") || cdesc.includes("monitor"));
    });
    return {
      controlId: control.controlId,
      status: relatedFindings.length > 0 ? "covered" as const : "gap" as const,
      findingCount: relatedFindings.length,
    };
  });
}

/**
 * Generate compliance score for a framework
 */
export function calculateComplianceScore(mappings: Array<{ status: string }>) {
  const total = mappings.length;
  if (total === 0) return { score: 0, covered: 0, gap: 0, partial: 0, na: 0 };
  const covered = mappings.filter(m => m.status === "covered").length;
  const gap = mappings.filter(m => m.status === "gap").length;
  const partial = mappings.filter(m => m.status === "partial").length;
  const na = mappings.filter(m => m.status === "not_applicable").length;
  const compensating = mappings.filter(m => m.status === "compensating").length;
  const applicable = total - na;
  const score = applicable > 0 ? ((covered + compensating + partial * 0.5) / applicable) * 100 : 100;
  return { score: Math.round(score * 10) / 10, covered, gap, partial, na, compensating, total };
}
