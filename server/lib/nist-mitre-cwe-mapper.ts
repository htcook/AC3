/**
 * Centralized NIST 800-53 / MITRE ATT&CK / CWE / CVE Mapping Engine
 *
 * This module provides a single source of truth for mapping between:
 *   - CWE IDs → NIST 800-53 Rev 5 controls
 *   - CWE IDs → MITRE ATT&CK techniques
 *   - MITRE ATT&CK techniques → NIST 800-53 controls
 *   - CVE → CWE (via pattern matching on CVE descriptions)
 *   - Finding severity/category → NIST control families
 *
 * Used by: context-engine, compliance-mapper, dedup-coverage-bridge, zap-scanner, UI components
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface NistControl {
  controlId: string;
  controlTitle: string;
  family: string;
  familyCode: string;
  /** NIST 800-53 Rev 5 baseline: low / moderate / high */
  baseline: "low" | "moderate" | "high";
}

export interface MitreTechnique {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  /** Sub-technique parent, if applicable */
  parentId?: string;
}

export interface CweEntry {
  cweId: string;
  cweName: string;
  category: string;
}

export interface FindingEnrichment {
  cwes: CweEntry[];
  nistControls: NistControl[];
  mitreTechniques: MitreTechnique[];
  /** Severity-adjusted NIST priority: P1 (critical) through P4 (informational) */
  nistPriority: "P1" | "P2" | "P3" | "P4";
}

// ─── NIST 800-53 Control Families ───────────────────────────────────────────

export const NIST_CONTROL_FAMILIES: Record<string, string> = {
  AC: "Access Control",
  AT: "Awareness and Training",
  AU: "Audit and Accountability",
  CA: "Assessment, Authorization, and Monitoring",
  CM: "Configuration Management",
  CP: "Contingency Planning",
  IA: "Identification and Authentication",
  IR: "Incident Response",
  MA: "Maintenance",
  MP: "Media Protection",
  PE: "Physical and Environmental Protection",
  PL: "Planning",
  PM: "Program Management",
  PS: "Personnel Security",
  PT: "PII Processing and Transparency",
  RA: "Risk Assessment",
  SA: "System and Services Acquisition",
  SC: "System and Communications Protection",
  SI: "System and Information Integrity",
  SR: "Supply Chain Risk Management",
};

// ─── CWE → NIST 800-53 Rev 5 Control Mapping ───────────────────────────────
// Comprehensive mapping of OWASP Top 10 / Top 25 CWEs to NIST controls

export const CWE_TO_NIST: Record<string, NistControl[]> = {
  // ── Injection Vulnerabilities ──
  "CWE-89": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SI-16", controlTitle: "Memory Protection", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
  ],
  "CWE-78": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", familyCode: "CM", baseline: "low" },
    { controlId: "AC-6", controlTitle: "Least Privilege", family: "Access Control", familyCode: "AC", baseline: "moderate" },
  ],
  "CWE-77": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", familyCode: "CM", baseline: "low" },
  ],
  "CWE-90": [ // LDAP Injection
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "IA-2", controlTitle: "Identification and Authentication (Organizational Users)", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
  ],
  "CWE-917": [ // Expression Language Injection
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
  ],
  "CWE-1336": [ // SSTI
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
  ],

  // ── Cross-Site Scripting (XSS) ──
  "CWE-79": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SI-15", controlTitle: "Information Output Filtering", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SC-18", controlTitle: "Mobile Code", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-80": [ // Basic XSS
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SI-15", controlTitle: "Information Output Filtering", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],

  // ── Authentication & Session Management ──
  "CWE-287": [
    { controlId: "IA-2", controlTitle: "Identification and Authentication (Organizational Users)", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
    { controlId: "IA-8", controlTitle: "Identification and Authentication (Non-Organizational Users)", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
  ],
  "CWE-306": [
    { controlId: "IA-2", controlTitle: "Identification and Authentication (Organizational Users)", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
    { controlId: "AC-3", controlTitle: "Access Enforcement", family: "Access Control", familyCode: "AC", baseline: "low" },
  ],
  "CWE-384": [ // Session Fixation
    { controlId: "SC-23", controlTitle: "Session Authenticity", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "IA-2", controlTitle: "Identification and Authentication (Organizational Users)", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
  ],
  "CWE-613": [ // Insufficient Session Expiration
    { controlId: "AC-12", controlTitle: "Session Termination", family: "Access Control", familyCode: "AC", baseline: "moderate" },
    { controlId: "SC-23", controlTitle: "Session Authenticity", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-521": [ // Weak Password Requirements
    { controlId: "IA-5", controlTitle: "Authenticator Management", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
  ],
  "CWE-798": [ // Hard-coded Credentials
    { controlId: "IA-5", controlTitle: "Authenticator Management", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
    { controlId: "SC-12", controlTitle: "Cryptographic Key Establishment and Management", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-307": [ // Brute Force
    { controlId: "AC-7", controlTitle: "Unsuccessful Logon Attempts", family: "Access Control", familyCode: "AC", baseline: "low" },
    { controlId: "IA-5", controlTitle: "Authenticator Management", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
  ],
  "CWE-330": [ // Weak Random
    { controlId: "SC-13", controlTitle: "Cryptographic Protection", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-539": [ // Persistent Cookies with Sensitive Data
    { controlId: "SC-23", controlTitle: "Session Authenticity", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "AC-12", controlTitle: "Session Termination", family: "Access Control", familyCode: "AC", baseline: "moderate" },
  ],

  // ── Access Control ──
  "CWE-284": [
    { controlId: "AC-3", controlTitle: "Access Enforcement", family: "Access Control", familyCode: "AC", baseline: "low" },
    { controlId: "AC-6", controlTitle: "Least Privilege", family: "Access Control", familyCode: "AC", baseline: "moderate" },
  ],
  "CWE-639": [ // IDOR
    { controlId: "AC-3", controlTitle: "Access Enforcement", family: "Access Control", familyCode: "AC", baseline: "low" },
    { controlId: "AC-4", controlTitle: "Information Flow Enforcement", family: "Access Control", familyCode: "AC", baseline: "moderate" },
  ],
  "CWE-732": [ // Incorrect Permission Assignment
    { controlId: "AC-6", controlTitle: "Least Privilege", family: "Access Control", familyCode: "AC", baseline: "moderate" },
    { controlId: "AC-3", controlTitle: "Access Enforcement", family: "Access Control", familyCode: "AC", baseline: "low" },
  ],
  "CWE-250": [ // Execution with Unnecessary Privileges
    { controlId: "AC-6", controlTitle: "Least Privilege", family: "Access Control", familyCode: "AC", baseline: "moderate" },
    { controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", familyCode: "CM", baseline: "low" },
  ],
  "CWE-863": [ // Incorrect Authorization
    { controlId: "AC-3", controlTitle: "Access Enforcement", family: "Access Control", familyCode: "AC", baseline: "low" },
  ],
  "CWE-862": [ // Missing Authorization
    { controlId: "AC-3", controlTitle: "Access Enforcement", family: "Access Control", familyCode: "AC", baseline: "low" },
    { controlId: "AC-6", controlTitle: "Least Privilege", family: "Access Control", familyCode: "AC", baseline: "moderate" },
  ],

  // ── Cryptography ──
  "CWE-327": [
    { controlId: "SC-13", controlTitle: "Cryptographic Protection", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "SC-12", controlTitle: "Cryptographic Key Establishment and Management", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-328": [ // Weak Hash
    { controlId: "SC-13", controlTitle: "Cryptographic Protection", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-295": [ // Improper Certificate Validation
    { controlId: "SC-12", controlTitle: "Cryptographic Key Establishment and Management", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "SC-17", controlTitle: "Public Key Infrastructure Certificates", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-319": [ // Cleartext Transmission
    { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "SC-23", controlTitle: "Session Authenticity", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],
  "CWE-311": [ // Missing Encryption
    { controlId: "SC-8", controlTitle: "Transmission Confidentiality and Integrity", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "SC-28", controlTitle: "Protection of Information at Rest", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],

  // ── Information Disclosure ──
  "CWE-200": [
    { controlId: "SC-28", controlTitle: "Protection of Information at Rest", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "SI-11", controlTitle: "Error Handling", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],
  "CWE-209": [ // Error Message Information Leak
    { controlId: "SI-11", controlTitle: "Error Handling", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],
  "CWE-532": [ // Log File Information Leak
    { controlId: "AU-9", controlTitle: "Protection of Audit Information", family: "Audit and Accountability", familyCode: "AU", baseline: "low" },
    { controlId: "SI-11", controlTitle: "Error Handling", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],

  // ── Path Traversal / File Inclusion ──
  "CWE-22": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "AC-3", controlTitle: "Access Enforcement", family: "Access Control", familyCode: "AC", baseline: "low" },
  ],
  "CWE-98": [ // PHP File Inclusion
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", familyCode: "CM", baseline: "low" },
  ],

  // ── SSRF ──
  "CWE-918": [
    { controlId: "SC-7", controlTitle: "Boundary Protection", family: "System and Communications Protection", familyCode: "SC", baseline: "low" },
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "AC-4", controlTitle: "Information Flow Enforcement", family: "Access Control", familyCode: "AC", baseline: "moderate" },
  ],

  // ── XXE ──
  "CWE-611": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "CM-6", controlTitle: "Configuration Settings", family: "Configuration Management", familyCode: "CM", baseline: "low" },
  ],

  // ── CSRF ──
  "CWE-352": [
    { controlId: "SC-23", controlTitle: "Session Authenticity", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],

  // ── Deserialization ──
  "CWE-502": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
  ],

  // ── File Upload ──
  "CWE-434": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", familyCode: "CM", baseline: "low" },
    { controlId: "SC-18", controlTitle: "Mobile Code", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
  ],

  // ── CORS / Headers ──
  "CWE-942": [
    { controlId: "SC-7", controlTitle: "Boundary Protection", family: "System and Communications Protection", familyCode: "SC", baseline: "low" },
    { controlId: "AC-4", controlTitle: "Information Flow Enforcement", family: "Access Control", familyCode: "AC", baseline: "moderate" },
  ],
  "CWE-693": [ // Protection Mechanism Failure (CSP bypass)
    { controlId: "SC-18", controlTitle: "Mobile Code", family: "System and Communications Protection", familyCode: "SC", baseline: "moderate" },
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],

  // ── Open Redirect ──
  "CWE-601": [
    { controlId: "SI-10", controlTitle: "Information Input Validation", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],

  // ── Security Misconfiguration ──
  "CWE-16": [ // Configuration
    { controlId: "CM-6", controlTitle: "Configuration Settings", family: "Configuration Management", familyCode: "CM", baseline: "low" },
    { controlId: "CM-2", controlTitle: "Baseline Configuration", family: "Configuration Management", familyCode: "CM", baseline: "low" },
  ],
  "CWE-1188": [ // Insecure Default Initialization
    { controlId: "CM-6", controlTitle: "Configuration Settings", family: "Configuration Management", familyCode: "CM", baseline: "low" },
    { controlId: "CM-7", controlTitle: "Least Functionality", family: "Configuration Management", familyCode: "CM", baseline: "low" },
  ],

  // ── Buffer Overflow / Memory Safety ──
  "CWE-120": [
    { controlId: "SI-16", controlTitle: "Memory Protection", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
  ],
  "CWE-787": [ // Out-of-bounds Write
    { controlId: "SI-16", controlTitle: "Memory Protection", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
  ],
  "CWE-125": [ // Out-of-bounds Read
    { controlId: "SI-16", controlTitle: "Memory Protection", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],
  "CWE-416": [ // Use After Free
    { controlId: "SI-16", controlTitle: "Memory Protection", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
  ],

  // ── Race Conditions ──
  "CWE-362": [
    { controlId: "SA-11", controlTitle: "Developer Testing and Evaluation", family: "System and Services Acquisition", familyCode: "SA", baseline: "moderate" },
    { controlId: "SI-16", controlTitle: "Memory Protection", family: "System and Information Integrity", familyCode: "SI", baseline: "moderate" },
  ],

  // ── DNS / Network ──
  "CWE-350": [ // Reliance on Reverse DNS
    { controlId: "SC-7", controlTitle: "Boundary Protection", family: "System and Communications Protection", familyCode: "SC", baseline: "low" },
    { controlId: "IA-2", controlTitle: "Identification and Authentication (Organizational Users)", family: "Identification and Authentication", familyCode: "IA", baseline: "low" },
  ],

  // ── Logging / Monitoring Gaps ──
  "CWE-778": [ // Insufficient Logging
    { controlId: "AU-2", controlTitle: "Event Logging", family: "Audit and Accountability", familyCode: "AU", baseline: "low" },
    { controlId: "AU-3", controlTitle: "Content of Audit Records", family: "Audit and Accountability", familyCode: "AU", baseline: "low" },
    { controlId: "SI-4", controlTitle: "System Monitoring", family: "System and Information Integrity", familyCode: "SI", baseline: "low" },
  ],

  // ── Supply Chain / Dependencies ──
  "CWE-1104": [ // Use of Unmaintained Third-Party Components
    { controlId: "SA-12", controlTitle: "Supply Chain Protection", family: "System and Services Acquisition", familyCode: "SA", baseline: "high" },
    { controlId: "SR-3", controlTitle: "Supply Chain Controls and Processes", family: "Supply Chain Risk Management", familyCode: "SR", baseline: "moderate" },
    { controlId: "SI-2", controlTitle: "Flaw Remediation", family: "System and Information Integrity", familyCode: "SI", baseline: "low" },
  ],
};

// ─── CWE → MITRE ATT&CK Technique Mapping ──────────────────────────────────
// Maps CWE weaknesses to the ATT&CK techniques that exploit them

export const CWE_TO_MITRE: Record<string, MitreTechnique[]> = {
  // ── Injection → Initial Access / Execution ──
  "CWE-89": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  ],
  "CWE-564": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  ],
  "CWE-78": [
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  ],
  "CWE-77": [
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  ],
  "CWE-90": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  ],
  "CWE-917": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  ],
  "CWE-1336": [
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  ],

  // ── XSS → Client-Side Attacks ──
  "CWE-79": [
    { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
    { techniqueId: "T1059.007", techniqueName: "JavaScript", tactic: "Execution", parentId: "T1059" },
  ],
  "CWE-80": [
    { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
  ],

  // ── Authentication / Credential ──
  "CWE-287": [
    { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
    { techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" },
  ],
  "CWE-306": [
    { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  ],
  "CWE-384": [
    { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
    { techniqueId: "T1539", techniqueName: "Steal Web Session Cookie", tactic: "Credential Access" },
  ],
  "CWE-613": [
    { techniqueId: "T1539", techniqueName: "Steal Web Session Cookie", tactic: "Credential Access" },
  ],
  "CWE-521": [
    { techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" },
  ],
  "CWE-798": [
    { techniqueId: "T1552.001", techniqueName: "Credentials In Files", tactic: "Credential Access", parentId: "T1552" },
    { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
  ],
  "CWE-307": [
    { techniqueId: "T1110", techniqueName: "Brute Force", tactic: "Credential Access" },
  ],

  // ── Access Control ──
  "CWE-284": [
    { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  ],
  "CWE-639": [
    { techniqueId: "T1530", techniqueName: "Data from Cloud Storage Object", tactic: "Collection" },
  ],
  "CWE-732": [
    { techniqueId: "T1222", techniqueName: "File and Directory Permissions Modification", tactic: "Defense Evasion" },
  ],
  "CWE-250": [
    { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  ],
  "CWE-862": [
    { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  ],
  "CWE-863": [
    { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  ],

  // ── Cryptography ──
  "CWE-327": [
    { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
    { techniqueId: "T1040", techniqueName: "Network Sniffing", tactic: "Credential Access" },
  ],
  "CWE-328": [
    { techniqueId: "T1110.002", techniqueName: "Password Cracking", tactic: "Credential Access", parentId: "T1110" },
  ],
  "CWE-295": [
    { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
  ],
  "CWE-319": [
    { techniqueId: "T1040", techniqueName: "Network Sniffing", tactic: "Credential Access" },
    { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
  ],
  "CWE-311": [
    { techniqueId: "T1040", techniqueName: "Network Sniffing", tactic: "Credential Access" },
  ],

  // ── Information Disclosure ──
  "CWE-200": [
    { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
    { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
  ],
  "CWE-209": [
    { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
  ],
  "CWE-532": [
    { techniqueId: "T1552.001", techniqueName: "Credentials In Files", tactic: "Credential Access", parentId: "T1552" },
  ],

  // ── Path Traversal / File Inclusion ──
  "CWE-22": [
    { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
    { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
  ],
  "CWE-98": [
    { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  ],

  // ── SSRF ──
  "CWE-918": [
    { techniqueId: "T1090", techniqueName: "Proxy", tactic: "Command and Control" },
    { techniqueId: "T1552.005", techniqueName: "Cloud Instance Metadata API", tactic: "Credential Access", parentId: "T1552" },
  ],

  // ── XXE ──
  "CWE-611": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
  ],

  // ── CSRF ──
  "CWE-352": [
    { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
  ],

  // ── Deserialization ──
  "CWE-502": [
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
  ],

  // ── File Upload ──
  "CWE-434": [
    { techniqueId: "T1105", techniqueName: "Ingress Tool Transfer", tactic: "Command and Control" },
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
  ],

  // ── CORS ──
  "CWE-942": [
    { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
  ],

  // ── Open Redirect ──
  "CWE-601": [
    { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
    { techniqueId: "T1566.002", techniqueName: "Spearphishing Link", tactic: "Initial Access", parentId: "T1566" },
  ],

  // ── Buffer Overflow / Memory ──
  "CWE-120": [
    { techniqueId: "T1203", techniqueName: "Exploitation for Client Execution", tactic: "Execution" },
    { techniqueId: "T1068", techniqueName: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  ],
  "CWE-787": [
    { techniqueId: "T1203", techniqueName: "Exploitation for Client Execution", tactic: "Execution" },
    { techniqueId: "T1068", techniqueName: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  ],
  "CWE-125": [
    { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
  ],
  "CWE-416": [
    { techniqueId: "T1203", techniqueName: "Exploitation for Client Execution", tactic: "Execution" },
    { techniqueId: "T1068", techniqueName: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  ],

  // ── Logging Gaps ──
  "CWE-778": [
    { techniqueId: "T1562.002", techniqueName: "Disable Windows Event Logging", tactic: "Defense Evasion", parentId: "T1562" },
    { techniqueId: "T1070", techniqueName: "Indicator Removal", tactic: "Defense Evasion" },
  ],

  // ── Supply Chain ──
  "CWE-1104": [
    { techniqueId: "T1195.002", techniqueName: "Compromise Software Supply Chain", tactic: "Initial Access", parentId: "T1195" },
  ],
};

// ─── MITRE ATT&CK → NIST 800-53 Control Mapping ────────────────────────────
// Maps ATT&CK techniques to the NIST controls that mitigate them

export const MITRE_TO_NIST: Record<string, string[]> = {
  // Initial Access
  "T1190": ["SI-10", "SC-7", "SI-2", "RA-5", "SA-11"],
  "T1189": ["SC-18", "SI-10", "SC-7", "SI-3"],
  "T1566": ["AT-2", "SI-3", "SI-8", "SC-7"],
  "T1566.001": ["AT-2", "SI-3", "SI-8"],
  "T1566.002": ["AT-2", "SI-3", "SC-7"],
  "T1195": ["SA-12", "SR-3", "SR-4", "SI-7"],
  "T1195.002": ["SA-12", "SR-3", "SI-7", "CM-7"],

  // Execution
  "T1059": ["CM-7", "SI-10", "AC-6", "SI-16"],
  "T1059.001": ["CM-7", "SI-10", "AC-6"], // PowerShell
  "T1059.003": ["CM-7", "SI-10", "AC-6"], // Windows Command Shell
  "T1059.007": ["SC-18", "SI-10"],        // JavaScript
  "T1203": ["SI-2", "SI-16", "SA-11", "SC-18"],
  "T1204": ["AT-2", "SI-3", "SC-18"],
  "T1204.001": ["AT-2", "SI-3"],          // Malicious Link
  "T1204.002": ["AT-2", "SI-3"],          // Malicious File

  // Persistence
  "T1078": ["AC-2", "AC-6", "IA-2", "IA-5", "AU-6"],
  "T1098": ["AC-2", "AC-6", "AU-2"],
  "T1136": ["AC-2", "AC-6", "AU-2"],

  // Privilege Escalation
  "T1068": ["SI-2", "SI-16", "AC-6", "SA-11"],
  "T1548": ["AC-6", "CM-7", "AC-3"],
  "T1611": ["CM-7", "AC-6", "SC-7"], // Container Escape

  // Defense Evasion
  "T1070": ["AU-9", "AU-6", "SI-4"],
  "T1562": ["AU-9", "SI-4", "AC-6"],
  "T1562.002": ["AU-2", "AU-9", "SI-4"],
  "T1036": ["SI-4", "SI-7", "CM-7"],
  "T1222": ["AC-3", "AC-6", "AU-2"],
  "T1027": ["SI-3", "SI-4"],

  // Credential Access
  "T1110": ["AC-7", "IA-5", "IA-2", "AU-2"],
  "T1110.002": ["IA-5", "SC-13"],
  "T1539": ["SC-23", "AC-12", "IA-2"],
  "T1552": ["IA-5", "SC-28", "AC-6"],
  "T1552.001": ["IA-5", "CM-6", "AC-6"],
  "T1552.005": ["SC-7", "CM-6", "AC-6"],
  "T1040": ["SC-8", "SC-13", "AC-4"],
  "T1557": ["SC-8", "SC-12", "SC-23"],

  // Discovery
  "T1083": ["AC-3", "AC-6", "SI-4"],
  "T1082": ["CM-7", "AC-6", "SI-4"],
  "T1046": ["SC-7", "SI-4", "CM-7"],

  // Collection
  "T1005": ["AC-3", "AC-6", "SC-28"],
  "T1530": ["AC-3", "AC-6", "SC-28"],
  "T1185": ["SC-23", "SI-10", "AC-12"],

  // Command and Control
  "T1090": ["SC-7", "SI-4", "AC-4"],
  "T1105": ["SC-7", "SI-3", "SI-4"],
  "T1071": ["SC-7", "SI-4", "AC-4"],
  "T1071.001": ["SC-7", "SI-4"],

  // Exfiltration
  "T1041": ["SC-7", "SI-4", "AC-4"],
  "T1567": ["SC-7", "SI-4", "AC-4"],

  // Impact
  "T1486": ["CP-9", "CP-10", "SI-3", "SI-4"],
  "T1499": ["SC-5", "SC-7", "SI-4"],
  "T1498": ["SC-5", "SC-7"],
};

// ─── Common CWE Definitions ────────────────────────────────────────────────

export const CWE_DEFINITIONS: Record<string, CweEntry> = {
  "CWE-79": { cweId: "CWE-79", cweName: "Improper Neutralization of Input During Web Page Generation (XSS)", category: "Injection" },
  "CWE-80": { cweId: "CWE-80", cweName: "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", category: "Injection" },
  "CWE-89": { cweId: "CWE-89", cweName: "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", category: "Injection" },
  "CWE-564": { cweId: "CWE-564", cweName: "SQL Injection: Hibernate", category: "Injection" },
  "CWE-78": { cweId: "CWE-78", cweName: "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)", category: "Injection" },
  "CWE-77": { cweId: "CWE-77", cweName: "Improper Neutralization of Special Elements used in a Command (Command Injection)", category: "Injection" },
  "CWE-90": { cweId: "CWE-90", cweName: "Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)", category: "Injection" },
  "CWE-917": { cweId: "CWE-917", cweName: "Improper Neutralization of Special Elements used in an Expression Language Statement", category: "Injection" },
  "CWE-1336": { cweId: "CWE-1336", cweName: "Improper Neutralization of Special Elements Used in a Template Engine", category: "Injection" },
  "CWE-287": { cweId: "CWE-287", cweName: "Improper Authentication", category: "Authentication" },
  "CWE-306": { cweId: "CWE-306", cweName: "Missing Authentication for Critical Function", category: "Authentication" },
  "CWE-384": { cweId: "CWE-384", cweName: "Session Fixation", category: "Session Management" },
  "CWE-613": { cweId: "CWE-613", cweName: "Insufficient Session Expiration", category: "Session Management" },
  "CWE-521": { cweId: "CWE-521", cweName: "Weak Password Requirements", category: "Authentication" },
  "CWE-798": { cweId: "CWE-798", cweName: "Use of Hard-coded Credentials", category: "Credential Management" },
  "CWE-307": { cweId: "CWE-307", cweName: "Improper Restriction of Excessive Authentication Attempts", category: "Authentication" },
  "CWE-330": { cweId: "CWE-330", cweName: "Use of Insufficiently Random Values", category: "Cryptography" },
  "CWE-284": { cweId: "CWE-284", cweName: "Improper Access Control", category: "Access Control" },
  "CWE-639": { cweId: "CWE-639", cweName: "Authorization Bypass Through User-Controlled Key (IDOR)", category: "Access Control" },
  "CWE-732": { cweId: "CWE-732", cweName: "Incorrect Permission Assignment for Critical Resource", category: "Access Control" },
  "CWE-250": { cweId: "CWE-250", cweName: "Execution with Unnecessary Privileges", category: "Access Control" },
  "CWE-862": { cweId: "CWE-862", cweName: "Missing Authorization", category: "Access Control" },
  "CWE-863": { cweId: "CWE-863", cweName: "Incorrect Authorization", category: "Access Control" },
  "CWE-327": { cweId: "CWE-327", cweName: "Use of a Broken or Risky Cryptographic Algorithm", category: "Cryptography" },
  "CWE-328": { cweId: "CWE-328", cweName: "Use of Weak Hash", category: "Cryptography" },
  "CWE-295": { cweId: "CWE-295", cweName: "Improper Certificate Validation", category: "Cryptography" },
  "CWE-319": { cweId: "CWE-319", cweName: "Cleartext Transmission of Sensitive Information", category: "Cryptography" },
  "CWE-311": { cweId: "CWE-311", cweName: "Missing Encryption of Sensitive Data", category: "Cryptography" },
  "CWE-200": { cweId: "CWE-200", cweName: "Exposure of Sensitive Information to an Unauthorized Actor", category: "Information Disclosure" },
  "CWE-209": { cweId: "CWE-209", cweName: "Generation of Error Message Containing Sensitive Information", category: "Information Disclosure" },
  "CWE-532": { cweId: "CWE-532", cweName: "Insertion of Sensitive Information into Log File", category: "Information Disclosure" },
  "CWE-22": { cweId: "CWE-22", cweName: "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", category: "File System" },
  "CWE-98": { cweId: "CWE-98", cweName: "Improper Control of Filename for Include/Require Statement in PHP Program", category: "File System" },
  "CWE-918": { cweId: "CWE-918", cweName: "Server-Side Request Forgery (SSRF)", category: "Network" },
  "CWE-611": { cweId: "CWE-611", cweName: "Improper Restriction of XML External Entity Reference (XXE)", category: "Injection" },
  "CWE-352": { cweId: "CWE-352", cweName: "Cross-Site Request Forgery (CSRF)", category: "Session Management" },
  "CWE-502": { cweId: "CWE-502", cweName: "Deserialization of Untrusted Data", category: "Injection" },
  "CWE-434": { cweId: "CWE-434", cweName: "Unrestricted Upload of File with Dangerous Type", category: "File System" },
  "CWE-942": { cweId: "CWE-942", cweName: "Permissive Cross-domain Policy with Untrusted Domains", category: "Network" },
  "CWE-693": { cweId: "CWE-693", cweName: "Protection Mechanism Failure", category: "Security Misconfiguration" },
  "CWE-601": { cweId: "CWE-601", cweName: "URL Redirection to Untrusted Site (Open Redirect)", category: "Network" },
  "CWE-16": { cweId: "CWE-16", cweName: "Configuration", category: "Security Misconfiguration" },
  "CWE-1188": { cweId: "CWE-1188", cweName: "Insecure Default Initialization of Resource", category: "Security Misconfiguration" },
  "CWE-120": { cweId: "CWE-120", cweName: "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)", category: "Memory Safety" },
  "CWE-787": { cweId: "CWE-787", cweName: "Out-of-bounds Write", category: "Memory Safety" },
  "CWE-125": { cweId: "CWE-125", cweName: "Out-of-bounds Read", category: "Memory Safety" },
  "CWE-416": { cweId: "CWE-416", cweName: "Use After Free", category: "Memory Safety" },
  "CWE-362": { cweId: "CWE-362", cweName: "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)", category: "Concurrency" },
  "CWE-778": { cweId: "CWE-778", cweName: "Insufficient Logging", category: "Logging" },
  "CWE-1104": { cweId: "CWE-1104", cweName: "Use of Unmaintained Third Party Components", category: "Supply Chain" },
  "CWE-539": { cweId: "CWE-539", cweName: "Use of Persistent Cookies Containing Sensitive Information", category: "Session Management" },
  "CWE-350": { cweId: "CWE-350", cweName: "Reliance on Reverse DNS Resolution for a Security-Critical Action", category: "Network" },
};

// ─── Enrichment Functions ───────────────────────────────────────────────────

/**
 * Enrich a finding with NIST 800-53 controls, MITRE ATT&CK techniques, and CWE details
 * based on its CWE IDs, MITRE technique IDs, and severity.
 */
export function enrichFinding(input: {
  cwes?: string[];
  techniqueIds?: string[];
  severity?: string;
  title?: string;
  category?: string;
}): FindingEnrichment {
  const cwes: CweEntry[] = [];
  const nistControlMap = new Map<string, NistControl>();
  const mitreMap = new Map<string, MitreTechnique>();

  // 1. Resolve CWE details and map to NIST + MITRE
  for (const cweId of input.cwes || []) {
    const normalized = cweId.startsWith("CWE-") ? cweId : `CWE-${cweId}`;
    const def = CWE_DEFINITIONS[normalized];
    if (def) cwes.push(def);
    else cwes.push({ cweId: normalized, cweName: normalized, category: "Unknown" });

    // CWE → NIST
    const nistMappings = CWE_TO_NIST[normalized];
    if (nistMappings) {
      for (const ctrl of nistMappings) {
        nistControlMap.set(ctrl.controlId, ctrl);
      }
    }

    // CWE → MITRE
    const mitreMappings = CWE_TO_MITRE[normalized];
    if (mitreMappings) {
      for (const tech of mitreMappings) {
        mitreMap.set(tech.techniqueId, tech);
      }
    }
  }

  // 2. Resolve MITRE technique IDs → additional NIST controls
  for (const techId of input.techniqueIds || []) {
    const nistIds = MITRE_TO_NIST[techId];
    if (nistIds) {
      for (const ctrlId of nistIds) {
        if (!nistControlMap.has(ctrlId)) {
          const familyCode = ctrlId.split("-")[0];
          nistControlMap.set(ctrlId, {
            controlId: ctrlId,
            controlTitle: `${NIST_CONTROL_FAMILIES[familyCode] || familyCode} (${ctrlId})`,
            family: NIST_CONTROL_FAMILIES[familyCode] || familyCode,
            familyCode,
            baseline: "moderate",
          });
        }
      }
    }
  }

  // 3. If no CWE/technique data, infer from title/category
  if (nistControlMap.size === 0 && mitreMap.size === 0) {
    const inferredMappings = inferFromTitleCategory(input.title, input.category);
    for (const ctrl of inferredMappings.nist) nistControlMap.set(ctrl.controlId, ctrl);
    for (const tech of inferredMappings.mitre) mitreMap.set(tech.techniqueId, tech);
  }

  // 4. Determine NIST priority from severity
  const nistPriority = severityToNistPriority(input.severity);

  return {
    cwes,
    nistControls: Array.from(nistControlMap.values()),
    mitreTechniques: Array.from(mitreMap.values()),
    nistPriority,
  };
}

/**
 * Get NIST 800-53 controls for a specific CWE
 */
export function getNistControlsForCwe(cweId: string): NistControl[] {
  const normalized = cweId.startsWith("CWE-") ? cweId : `CWE-${cweId}`;
  return CWE_TO_NIST[normalized] || [];
}

/**
 * Get MITRE ATT&CK techniques for a specific CWE
 */
export function getMitreTechniquesForCwe(cweId: string): MitreTechnique[] {
  const normalized = cweId.startsWith("CWE-") ? cweId : `CWE-${cweId}`;
  return CWE_TO_MITRE[normalized] || [];
}

/**
 * Get NIST 800-53 controls that mitigate a specific MITRE technique
 */
export function getNistControlsForMitre(techniqueId: string): string[] {
  return MITRE_TO_NIST[techniqueId] || [];
}

/**
 * Get CWE definition by ID
 */
export function getCweDefinition(cweId: string): CweEntry | null {
  const normalized = cweId.startsWith("CWE-") ? cweId : `CWE-${cweId}`;
  return CWE_DEFINITIONS[normalized] || null;
}

/**
 * Map a finding severity to NIST priority level
 */
export function severityToNistPriority(severity?: string): "P1" | "P2" | "P3" | "P4" {
  switch (severity?.toLowerCase()) {
    case "critical": return "P1";
    case "high": return "P2";
    case "medium":
    case "moderate": return "P3";
    case "low":
    case "informational":
    case "info":
    default: return "P4";
  }
}

/**
 * Get all NIST control families with their descriptions
 */
export function getNistControlFamilies(): Record<string, string> {
  return { ...NIST_CONTROL_FAMILIES };
}

/**
 * Get the unique set of NIST control families impacted by a set of findings
 */
export function getImpactedNistFamilies(
  findings: Array<{ cwes?: string[]; techniqueIds?: string[] }>
): Array<{ familyCode: string; familyName: string; controlCount: number }> {
  const familyMap = new Map<string, Set<string>>();

  for (const finding of findings) {
    const enrichment = enrichFinding(finding);
    for (const ctrl of enrichment.nistControls) {
      if (!familyMap.has(ctrl.familyCode)) {
        familyMap.set(ctrl.familyCode, new Set());
      }
      familyMap.get(ctrl.familyCode)!.add(ctrl.controlId);
    }
  }

  return Array.from(familyMap.entries())
    .map(([code, controls]) => ({
      familyCode: code,
      familyName: NIST_CONTROL_FAMILIES[code] || code,
      controlCount: controls.size,
    }))
    .sort((a, b) => b.controlCount - a.controlCount);
}

/**
 * Generate a compliance gap summary for a set of findings against a NIST baseline
 */
export function generateNistGapSummary(
  findings: Array<{ cwes?: string[]; techniqueIds?: string[]; severity?: string }>,
  baseline: "low" | "moderate" | "high" = "moderate"
): {
  totalControlsImpacted: number;
  byFamily: Array<{ familyCode: string; familyName: string; controls: string[]; highestPriority: string }>;
  criticalGaps: NistControl[];
  coverageScore: number;
} {
  const allControls = new Map<string, { control: NistControl; highestSeverity: string }>();

  for (const finding of findings) {
    const enrichment = enrichFinding(finding);
    for (const ctrl of enrichment.nistControls) {
      const existing = allControls.get(ctrl.controlId);
      if (!existing || compareSeverity(finding.severity, existing.highestSeverity) > 0) {
        allControls.set(ctrl.controlId, { control: ctrl, highestSeverity: finding.severity || "low" });
      }
    }
  }

  // Group by family
  const byFamily = new Map<string, { controls: Set<string>; highestSeverity: string }>();
  for (const [, { control, highestSeverity }] of allControls) {
    const existing = byFamily.get(control.familyCode);
    if (!existing) {
      byFamily.set(control.familyCode, { controls: new Set([control.controlId]), highestSeverity });
    } else {
      existing.controls.add(control.controlId);
      if (compareSeverity(highestSeverity, existing.highestSeverity) > 0) {
        existing.highestSeverity = highestSeverity;
      }
    }
  }

  // Critical gaps: controls at the requested baseline that have critical/high findings
  const criticalGaps = Array.from(allControls.values())
    .filter(({ control, highestSeverity }) => {
      const baselineOrder = { low: 0, moderate: 1, high: 2 };
      return baselineOrder[control.baseline] <= baselineOrder[baseline] &&
        (highestSeverity === "critical" || highestSeverity === "high");
    })
    .map(({ control }) => control);

  // Total NIST 800-53 controls at moderate baseline: ~325
  const totalBaselineControls = baseline === "low" ? 125 : baseline === "moderate" ? 325 : 421;
  const coverageScore = Math.round((allControls.size / totalBaselineControls) * 100 * 10) / 10;

  return {
    totalControlsImpacted: allControls.size,
    byFamily: Array.from(byFamily.entries())
      .map(([code, { controls, highestSeverity }]) => ({
        familyCode: code,
        familyName: NIST_CONTROL_FAMILIES[code] || code,
        controls: Array.from(controls),
        highestPriority: severityToNistPriority(highestSeverity),
      }))
      .sort((a, b) => a.highestPriority.localeCompare(b.highestPriority)),
    criticalGaps,
    coverageScore,
  };
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

function compareSeverity(a?: string, b?: string): number {
  const order: Record<string, number> = { critical: 4, high: 3, medium: 2, moderate: 2, low: 1, informational: 0, info: 0 };
  return (order[a?.toLowerCase() || ""] || 0) - (order[b?.toLowerCase() || ""] || 0);
}

function inferFromTitleCategory(
  title?: string,
  category?: string
): { nist: NistControl[]; mitre: MitreTechnique[] } {
  const text = `${title || ""} ${category || ""}`.toLowerCase();
  const nist: NistControl[] = [];
  const mitre: MitreTechnique[] = [];

  // Keyword-based inference when no CWE/technique data is available
  const patterns: Array<{
    keywords: string[];
    nistIds: string[];
    mitreIds: string[];
  }> = [
    {
      keywords: ["sql injection", "sqli", "blind sql"],
      nistIds: ["SI-10", "SA-11"],
      mitreIds: ["T1190"],
    },
    {
      keywords: ["xss", "cross-site scripting", "cross site scripting"],
      nistIds: ["SI-10", "SI-15", "SC-18"],
      mitreIds: ["T1189"],
    },
    {
      keywords: ["command injection", "os command", "rce", "remote code execution"],
      nistIds: ["SI-10", "CM-7", "AC-6"],
      mitreIds: ["T1059"],
    },
    {
      keywords: ["authentication", "login", "credential", "password", "brute force"],
      nistIds: ["IA-2", "IA-5", "AC-7"],
      mitreIds: ["T1110", "T1078"],
    },
    {
      keywords: ["authorization", "access control", "privilege", "idor"],
      nistIds: ["AC-3", "AC-6"],
      mitreIds: ["T1548"],
    },
    {
      keywords: ["encryption", "tls", "ssl", "crypto", "certificate"],
      nistIds: ["SC-8", "SC-12", "SC-13"],
      mitreIds: ["T1557"],
    },
    {
      keywords: ["ssrf", "server-side request forgery"],
      nistIds: ["SC-7", "SI-10", "AC-4"],
      mitreIds: ["T1090"],
    },
    {
      keywords: ["xxe", "xml external entity"],
      nistIds: ["SI-10", "CM-6"],
      mitreIds: ["T1190"],
    },
    {
      keywords: ["csrf", "cross-site request forgery"],
      nistIds: ["SC-23", "SI-10"],
      mitreIds: ["T1185"],
    },
    {
      keywords: ["path traversal", "directory traversal", "file inclusion", "lfi", "rfi"],
      nistIds: ["SI-10", "AC-3"],
      mitreIds: ["T1005"],
    },
    {
      keywords: ["information disclosure", "information leak", "sensitive data"],
      nistIds: ["SC-28", "SI-11"],
      mitreIds: ["T1552"],
    },
    {
      keywords: ["configuration", "misconfiguration", "hardening", "default"],
      nistIds: ["CM-6", "CM-2", "CM-7"],
      mitreIds: [],
    },
    {
      keywords: ["deserialization", "insecure deserialization"],
      nistIds: ["SI-10", "SA-11"],
      mitreIds: ["T1059"],
    },
    {
      keywords: ["file upload", "unrestricted upload"],
      nistIds: ["SI-10", "CM-7"],
      mitreIds: ["T1105"],
    },
    {
      keywords: ["cors", "cross-origin"],
      nistIds: ["SC-7", "AC-4"],
      mitreIds: ["T1557"],
    },
    {
      keywords: ["open redirect"],
      nistIds: ["SI-10"],
      mitreIds: ["T1189"],
    },
    {
      keywords: ["buffer overflow", "memory corruption", "heap", "stack"],
      nistIds: ["SI-16", "SA-11"],
      mitreIds: ["T1203"],
    },
    {
      keywords: ["logging", "monitoring", "audit"],
      nistIds: ["AU-2", "AU-3", "SI-4"],
      mitreIds: ["T1562"],
    },
    {
      keywords: ["supply chain", "dependency", "third party", "component"],
      nistIds: ["SA-12", "SR-3", "SI-2"],
      mitreIds: ["T1195"],
    },
    {
      keywords: ["phishing", "social engineering"],
      nistIds: ["AT-2", "SI-3", "SI-8"],
      mitreIds: ["T1566"],
    },
    {
      keywords: ["dns", "domain", "subdomain takeover"],
      nistIds: ["SC-7", "SC-20"],
      mitreIds: ["T1584"],
    },
    {
      keywords: ["container", "docker", "kubernetes", "k8s"],
      nistIds: ["CM-7", "AC-6", "SC-7"],
      mitreIds: ["T1611"],
    },
    {
      keywords: ["cloud", "aws", "azure", "gcp", "s3", "iam"],
      nistIds: ["AC-3", "AC-6", "SC-7"],
      mitreIds: ["T1530"],
    },
    {
      keywords: ["modbus", "dnp3", "bacnet", "ics", "scada", "ot ", "plc"],
      nistIds: ["SC-7", "AC-3", "SI-4"],
      mitreIds: ["T1190"],
    },
  ];

  // Use word-boundary matching to prevent substring false positives
  // (e.g., "force" matching "rce" in command injection)
  const matchesKeyword = (text: string, kw: string) => {
    // Multi-word keywords: use exact substring match (they're specific enough)
    if (kw.includes(" ")) return text.includes(kw);
    // Single-word keywords: use word boundary regex
    return new RegExp(`\\b${kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(text);
  };

  for (const pattern of patterns) {
    if (pattern.keywords.some(kw => matchesKeyword(text, kw))) {
      for (const ctrlId of pattern.nistIds) {
        const familyCode = ctrlId.split("-")[0];
        nist.push({
          controlId: ctrlId,
          controlTitle: `${NIST_CONTROL_FAMILIES[familyCode] || familyCode} (${ctrlId})`,
          family: NIST_CONTROL_FAMILIES[familyCode] || familyCode,
          familyCode,
          baseline: "moderate",
        });
      }
      for (const techId of pattern.mitreIds) {
        const existing = Object.values(CWE_TO_MITRE).flat().find(t => t.techniqueId === techId);
        if (existing) {
          mitre.push(existing);
        } else {
          mitre.push({ techniqueId: techId, techniqueName: techId, tactic: "Unknown" });
        }
      }
      break; // Use first match
    }
  }

  return { nist, mitre };
}
