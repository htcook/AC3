/**
 * NIST 800-53 Control Mapper
 * 
 * Maps risk signal types, CWE IDs, and finding categories to specific
 * NIST 800-53 Rev5 controls for FedRAMP-aligned reporting.
 */

// ─── Control Family Definitions ────────────────────────────────────

export interface NistControl {
  controlId: string;        // e.g., "IA-5"
  controlName: string;      // e.g., "Authenticator Management"
  family: string;           // e.g., "Identification and Authentication"
  familyCode: string;       // e.g., "IA"
  fedrampBaseline: "low" | "moderate" | "high" | "all";
  description: string;
}

const NIST_CONTROLS: Record<string, NistControl> = {
  "AC-2": {
    controlId: "AC-2", controlName: "Account Management",
    family: "Access Control", familyCode: "AC",
    fedrampBaseline: "low",
    description: "Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
  },
  "AC-3": {
    controlId: "AC-3", controlName: "Access Enforcement",
    family: "Access Control", familyCode: "AC",
    fedrampBaseline: "low",
    description: "Enforce approved authorizations for logical access to information and system resources.",
  },
  "AC-4": {
    controlId: "AC-4", controlName: "Information Flow Enforcement",
    family: "Access Control", familyCode: "AC",
    fedrampBaseline: "moderate",
    description: "Enforce approved authorizations for controlling the flow of information within the system and between systems.",
  },
  "AC-17": {
    controlId: "AC-17", controlName: "Remote Access",
    family: "Access Control", familyCode: "AC",
    fedrampBaseline: "low",
    description: "Establish and document usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed.",
  },
  "AU-6": {
    controlId: "AU-6", controlName: "Audit Record Review, Analysis, and Reporting",
    family: "Audit and Accountability", familyCode: "AU",
    fedrampBaseline: "low",
    description: "Review and analyze system audit records for indications of inappropriate or unusual activity.",
  },
  "CA-8": {
    controlId: "CA-8", controlName: "Penetration Testing",
    family: "Assessment, Authorization, and Monitoring", familyCode: "CA",
    fedrampBaseline: "moderate",
    description: "Conduct penetration testing on the system or system components.",
  },
  "CM-6": {
    controlId: "CM-6", controlName: "Configuration Settings",
    family: "Configuration Management", familyCode: "CM",
    fedrampBaseline: "low",
    description: "Establish and document configuration settings for components employed within the system.",
  },
  "CM-7": {
    controlId: "CM-7", controlName: "Least Functionality",
    family: "Configuration Management", familyCode: "CM",
    fedrampBaseline: "low",
    description: "Configure the system to provide only mission-essential capabilities.",
  },
  "CM-8": {
    controlId: "CM-8", controlName: "System Component Inventory",
    family: "Configuration Management", familyCode: "CM",
    fedrampBaseline: "low",
    description: "Develop and document an inventory of system components.",
  },
  "IA-2": {
    controlId: "IA-2", controlName: "Identification and Authentication (Organizational Users)",
    family: "Identification and Authentication", familyCode: "IA",
    fedrampBaseline: "low",
    description: "Uniquely identify and authenticate organizational users.",
  },
  "IA-5": {
    controlId: "IA-5", controlName: "Authenticator Management",
    family: "Identification and Authentication", familyCode: "IA",
    fedrampBaseline: "low",
    description: "Manage system authenticators by verifying identity, initial content, establishing administrative procedures, and protecting authenticators.",
  },
  "IR-4": {
    controlId: "IR-4", controlName: "Incident Handling",
    family: "Incident Response", familyCode: "IR",
    fedrampBaseline: "low",
    description: "Implement an incident handling capability for incidents that includes preparation, detection and analysis, containment, eradication, and recovery.",
  },
  "IR-6": {
    controlId: "IR-6", controlName: "Incident Reporting",
    family: "Incident Response", familyCode: "IR",
    fedrampBaseline: "low",
    description: "Require personnel to report suspected incidents to the organizational incident response capability.",
  },
  "RA-5": {
    controlId: "RA-5", controlName: "Vulnerability Monitoring and Scanning",
    family: "Risk Assessment", familyCode: "RA",
    fedrampBaseline: "low",
    description: "Monitor and scan for vulnerabilities in the system and hosted applications.",
  },
  "SA-11": {
    controlId: "SA-11", controlName: "Developer Testing and Evaluation",
    family: "System and Services Acquisition", familyCode: "SA",
    fedrampBaseline: "moderate",
    description: "Require the developer to create and implement a security and privacy assessment plan.",
  },
  "SA-12": {
    controlId: "SA-12", controlName: "Supply Chain Risk Management",
    family: "System and Services Acquisition", familyCode: "SA",
    fedrampBaseline: "moderate",
    description: "Protect against supply chain threats by employing security safeguards.",
  },
  "SC-5": {
    controlId: "SC-5", controlName: "Denial-of-Service Protection",
    family: "System and Communications Protection", familyCode: "SC",
    fedrampBaseline: "low",
    description: "Protect against or limit the effects of denial-of-service attacks.",
  },
  "SC-7": {
    controlId: "SC-7", controlName: "Boundary Protection",
    family: "System and Communications Protection", familyCode: "SC",
    fedrampBaseline: "low",
    description: "Monitor and control communications at the external managed interfaces to the system and at key internal managed interfaces.",
  },
  "SC-8": {
    controlId: "SC-8", controlName: "Transmission Confidentiality and Integrity",
    family: "System and Communications Protection", familyCode: "SC",
    fedrampBaseline: "moderate",
    description: "Protect the confidentiality and integrity of transmitted information.",
  },
  "SC-12": {
    controlId: "SC-12", controlName: "Cryptographic Key Establishment and Management",
    family: "System and Communications Protection", familyCode: "SC",
    fedrampBaseline: "low",
    description: "Establish and manage cryptographic keys when cryptography is employed within the system.",
  },
  "SC-13": {
    controlId: "SC-13", controlName: "Cryptographic Protection",
    family: "System and Communications Protection", familyCode: "SC",
    fedrampBaseline: "low",
    description: "Implement FIPS-validated or NSA-approved cryptography.",
  },
  "SC-17": {
    controlId: "SC-17", controlName: "Public Key Infrastructure Certificates",
    family: "System and Communications Protection", familyCode: "SC",
    fedrampBaseline: "moderate",
    description: "Issue public key certificates under an appropriate certificate policy or obtain public key certificates from an approved service provider.",
  },
  "SC-28": {
    controlId: "SC-28", controlName: "Protection of Information at Rest",
    family: "System and Communications Protection", familyCode: "SC",
    fedrampBaseline: "moderate",
    description: "Protect the confidentiality and integrity of information at rest.",
  },
  "SI-2": {
    controlId: "SI-2", controlName: "Flaw Remediation",
    family: "System and Information Integrity", familyCode: "SI",
    fedrampBaseline: "low",
    description: "Identify, report, and correct system flaws.",
  },
  "SI-3": {
    controlId: "SI-3", controlName: "Malicious Code Protection",
    family: "System and Information Integrity", familyCode: "SI",
    fedrampBaseline: "low",
    description: "Implement malicious code protection mechanisms at system entry and exit points.",
  },
  "SI-4": {
    controlId: "SI-4", controlName: "System Monitoring",
    family: "System and Information Integrity", familyCode: "SI",
    fedrampBaseline: "low",
    description: "Monitor the system to detect attacks, indicators of potential attacks, and unauthorized connections.",
  },
  "SI-5": {
    controlId: "SI-5", controlName: "Security Alerts, Advisories, and Directives",
    family: "System and Information Integrity", familyCode: "SI",
    fedrampBaseline: "low",
    description: "Receive system security alerts, advisories, and directives from external organizations on an ongoing basis.",
  },
  "SI-10": {
    controlId: "SI-10", controlName: "Information Input Validation",
    family: "System and Information Integrity", familyCode: "SI",
    fedrampBaseline: "moderate",
    description: "Check the validity of information inputs.",
  },
};

// ─── Signal Type → NIST Control Mapping ────────────────────────────

const SIGNAL_TO_NIST: Record<string, string[]> = {
  // Access control & authentication
  "admin_panel_exposed":     ["AC-3", "AC-17", "CM-7"],
  "open_remote_access":      ["AC-17", "SC-7"],
  "credential_exposure":     ["IA-5", "IR-6"],
  "high_volume_breach":      ["IA-5", "IR-4", "IR-6"],
  "api_key_leak":            ["IA-5", "SC-28"],
  "sensitive_data_url":      ["IA-5", "SC-28"],

  // Configuration & inventory
  "open_db_port":            ["SC-7", "CM-7"],
  "staging_env_exposed":     ["CM-8", "CM-7"],
  "shadow_it_service":       ["CM-8", "CM-7"],
  "cloud_storage_exposed":   ["SC-28", "AC-3"],

  // Certificates & encryption
  "expired_cert":            ["SC-17", "SC-12"],
  "cert_anomaly":            ["SC-17", "SC-13"],
  "missing_spf":             ["SC-8", "SI-4"],
  "missing_dmarc":           ["SC-8", "SI-4"],

  // Vulnerability management
  "known_vuln_software":     ["SI-2", "RA-5"],
  "binaryedge_cve":          ["SI-2", "RA-5"],
  "internetdb_cve":          ["SI-2", "RA-5"],
  "greynoise_cve_exploit":   ["SI-2", "RA-5", "SI-5"],

  // Threat detection
  "greynoise_malicious":     ["SI-4", "IR-4"],
  "greynoise_noise":         ["SI-4"],

  // Subdomain & DNS
  "subdomain_takeover":      ["CM-8", "SC-7"],
  "breach_subdomain":        ["CM-8"],

  // Historical
  "historical_admin_path":   ["CM-8", "AC-3"],
  "api_endpoint_exposed":    ["AC-3", "SC-7"],
};

// ─── CWE → NIST Control Mapping ───────────────────────────────────

const CWE_TO_NIST: Record<number, string[]> = {
  // Injection
  79:  ["SI-10"],          // XSS
  89:  ["SI-10"],          // SQL Injection
  94:  ["SI-10"],          // Code Injection
  78:  ["SI-10"],          // OS Command Injection
  77:  ["SI-10"],          // Command Injection
  917: ["SI-10"],          // Expression Language Injection

  // Authentication & Access
  287: ["IA-2", "IA-5"],   // Improper Authentication
  306: ["IA-2"],            // Missing Authentication for Critical Function
  798: ["IA-5"],            // Use of Hard-coded Credentials
  521: ["IA-5"],            // Weak Password Requirements
  307: ["AC-2", "IA-5"],    // Improper Restriction of Excessive Authentication Attempts
  384: ["IA-2"],            // Session Fixation

  // Authorization
  862: ["AC-3"],            // Missing Authorization
  863: ["AC-3"],            // Incorrect Authorization
  639: ["AC-3"],            // Authorization Bypass Through User-Controlled Key (IDOR)

  // SSRF & Request Forgery
  918: ["SC-7"],            // SSRF
  352: ["SI-10"],           // CSRF

  // File & Path
  22:  ["AC-3"],            // Path Traversal
  434: ["SI-10"],           // Unrestricted Upload of File with Dangerous Type

  // Cryptographic
  327: ["SC-13"],           // Use of a Broken or Risky Cryptographic Algorithm
  328: ["SC-13"],           // Use of Weak Hash
  311: ["SC-28"],           // Missing Encryption of Sensitive Data
  319: ["SC-8"],            // Cleartext Transmission of Sensitive Information

  // Information Disclosure
  200: ["SC-28"],           // Exposure of Sensitive Information
  209: ["SI-4"],            // Generation of Error Message Containing Sensitive Information
  532: ["AU-6"],            // Insertion of Sensitive Information into Log File

  // Configuration
  16:  ["CM-6"],            // Configuration
  1188: ["CM-6"],           // Insecure Default Initialization of Resource

  // Deserialization
  502: ["SI-10"],           // Deserialization of Untrusted Data

  // XXE
  611: ["SI-10"],           // Improper Restriction of XML External Entity Reference

  // Supply Chain
  1104: ["SA-12"],          // Use of Unmaintained Third Party Components
};

// ─── FedRAMP Remediation Timelines ─────────────────────────────────

export interface FedrampTimeline {
  severity: string;
  remediationDays: number;
  label: string;
}

const FEDRAMP_TIMELINES: Record<string, FedrampTimeline> = {
  critical: { severity: "critical", remediationDays: 30, label: "30 days (Critical)" },
  high:     { severity: "high",     remediationDays: 30, label: "30 days (High)" },
  medium:   { severity: "medium",   remediationDays: 90, label: "90 days (Moderate)" },
  low:      { severity: "low",      remediationDays: 180, label: "180 days (Low)" },
  info:     { severity: "info",     remediationDays: 365, label: "365 days (Informational)" },
};

// ─── Public API ────────────────────────────────────────────────────

/**
 * Get NIST 800-53 controls for a risk signal type
 */
export function getNistControlsForSignal(signalType: string): NistControl[] {
  const controlIds = SIGNAL_TO_NIST[signalType] || [];
  return controlIds
    .map(id => NIST_CONTROLS[id])
    .filter((c): c is NistControl => c !== undefined);
}

/**
 * Get NIST 800-53 controls for a CWE ID
 */
export function getNistControlsForCwe(cweId: number): NistControl[] {
  const controlIds = CWE_TO_NIST[cweId] || [];
  return controlIds
    .map(id => NIST_CONTROLS[id])
    .filter((c): c is NistControl => c !== undefined);
}

/**
 * Get the primary NIST control ID for a signal type (first mapped control)
 */
export function getPrimaryNistControl(signalType: string): string | null {
  const controlIds = SIGNAL_TO_NIST[signalType];
  return controlIds?.[0] || null;
}

/**
 * Get FedRAMP remediation timeline for a severity level
 */
export function getFedrampTimeline(severity: string): FedrampTimeline {
  return FEDRAMP_TIMELINES[severity.toLowerCase()] || FEDRAMP_TIMELINES.info;
}

/**
 * Calculate the FedRAMP remediation deadline from a finding date
 */
export function calculateFedrampDeadline(findingDate: Date, severity: string): Date {
  const timeline = getFedrampTimeline(severity);
  const deadline = new Date(findingDate);
  deadline.setDate(deadline.getDate() + timeline.remediationDays);
  return deadline;
}

/**
 * Get all NIST controls referenced across a set of signal types
 * Returns a deduplicated, sorted list with hit counts
 */
export function aggregateNistControls(signalTypes: string[]): Array<NistControl & { hitCount: number }> {
  const controlCounts = new Map<string, number>();

  for (const signalType of signalTypes) {
    const controlIds = SIGNAL_TO_NIST[signalType] || [];
    for (const id of controlIds) {
      controlCounts.set(id, (controlCounts.get(id) || 0) + 1);
    }
  }

  return Array.from(controlCounts.entries())
    .map(([id, count]) => {
      const control = NIST_CONTROLS[id];
      if (!control) return null;
      return { ...control, hitCount: count };
    })
    .filter((c): c is NistControl & { hitCount: number } => c !== null)
    .sort((a, b) => b.hitCount - a.hitCount);
}

/**
 * Generate a NIST 800-53 control assessment summary for a set of findings
 */
export function generateControlAssessmentSummary(
  signalTypes: string[]
): string {
  const controls = aggregateNistControls(signalTypes);
  if (controls.length === 0) return "";

  const lines: string[] = [
    "### NIST 800-53 Control Assessment Summary",
    "",
    "| Control | Name | Family | Findings | FedRAMP Baseline |",
    "|---------|------|--------|----------|-----------------|",
  ];

  for (const c of controls) {
    lines.push(
      `| ${c.controlId} | ${c.controlName} | ${c.family} | ${c.hitCount} | ${c.fedrampBaseline} |`
    );
  }

  // Add family summary
  const familyCounts = new Map<string, number>();
  for (const c of controls) {
    familyCounts.set(c.family, (familyCounts.get(c.family) || 0) + c.hitCount);
  }

  lines.push("");
  lines.push("**Control Family Distribution:**");
  for (const [family, count] of Array.from(familyCounts.entries()).sort((a, b) => b[1] - a[1])) {
    lines.push(`- ${family}: ${count} finding(s)`);
  }

  return lines.join("\n");
}

/**
 * Get a lookup of all available NIST controls
 */
export function getAllNistControls(): Record<string, NistControl> {
  return { ...NIST_CONTROLS };
}

/**
 * Get all signal-to-NIST mappings
 */
export function getSignalToNistMappings(): Record<string, string[]> {
  return { ...SIGNAL_TO_NIST };
}
