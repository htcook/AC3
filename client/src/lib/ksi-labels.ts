/**
 * KSI Abbreviation Lookup — maps KSI theme codes and KSI IDs to human-readable labels.
 *
 * Usage:
 *   import { getThemeLabel, getKsiLabel, formatKsiId } from "@/lib/ksi-labels";
 *   getThemeLabel("AFR")        → "Authorization by FedRAMP"
 *   getKsiLabel("KSI-AFR-ADS")  → "Authorization Data Sharing"
 *   formatKsiId("KSI-AFR-ADS")  → "KSI-AFR-ADS — Authorization Data Sharing"
 */

/** Theme code → full theme name */
export const THEME_LABELS: Record<string, string> = {
  AFR: "Authorization by FedRAMP",
  CMT: "Change Management",
  CNA: "Cloud Native Architecture",
  CED: "Cybersecurity Education",
  IAM: "Identity and Access Management",
  INR: "Incident Response",
  MLA: "Monitoring, Logging, and Auditing",
  PIY: "Policy and Inventory",
  RPL: "Recovery Planning",
  SVC: "Service Configuration",
  SCR: "Supply Chain Risk",
  SDE: "Secure Development",
  PPM: "Policy & Procedure Management",
};

/** KSI ID → short title */
export const KSI_TITLES: Record<string, string> = {
  // AFR — Authorization by FedRAMP
  "KSI-AFR-ADS": "Authorization Data Sharing",
  "KSI-AFR-CCM": "Continuous Compliance Monitoring",
  "KSI-AFR-FSI": "FedRAMP Security Inbox",
  "KSI-AFR-ICP": "Initial Compliance Posture",
  "KSI-AFR-MAS": "Minimum Assessment Scope",
  "KSI-AFR-PVA": "Periodic Vulnerability Assessment",
  "KSI-AFR-SCG": "Secure Configuration Guide",
  "KSI-AFR-SCN": "Significant Change Notifications",

  // CMT — Change Management
  "KSI-CMT-LMC": "Log and Monitor Modifications",
  "KSI-CMT-RMV": "Redeployment of Version-Controlled Immutable Resources",
  "KSI-CMT-RVP": "Review Change Management Procedures",
  "KSI-CMT-VTD": "Validate Changes Throughout Deployment",
  "KSI-CMT-CMG": "Change Management Governance",

  // CNA — Cloud Native Architecture
  "KSI-CNA-DFP": "Define Functionality and Privileges",
  "KSI-CNA-EDE": "Encrypt Data at Rest and In Transit (FIPS)",
  "KSI-CNA-MAS": "Minimal Attack Surface",
  "KSI-CNA-OFA": "Optimize for High Availability",
  "KSI-CNA-RNT": "Restrict Network Traffic",
  "KSI-CNA-RVP": "Review DoS Protection Effectiveness",
  "KSI-CNA-SBD": "Secure By Design Architecture",
  "KSI-CNA-ULN": "Use Logical Networking Controls",
  "KSI-CNA-HCI": "Harden Cloud Infrastructure",
  "KSI-CNA-NSD": "Network Segmentation & Defense",

  // CED — Cybersecurity Education
  "KSI-CED-DET": "Developer/Engineering Training Effectiveness",
  "KSI-CED-RGT": "General Employee Training Effectiveness",
  "KSI-CED-RRT": "IR/DR Staff Training Effectiveness",
  "KSI-CED-RST": "High-Risk Role Training Effectiveness",

  // IAM — Identity and Access Management
  "KSI-IAM-AAM": "Automated Account Lifecycle Management",
  "KSI-IAM-APM": "Authentication Policy Management",
  "KSI-IAM-ELP": "Enforce Least Privilege",
  "KSI-IAM-JIT": "Just-In-Time Authorization",
  "KSI-IAM-MFA": "Phishing-Resistant MFA Enforcement",
  "KSI-IAM-SNU": "Secure Non-User Authentication",
  "KSI-IAM-SUS": "Suspend Suspicious Privileged Accounts",
  "KSI-IAM-PRA": "Privileged Access Reviews & Auditing",

  // INR — Incident Response
  "KSI-INR-AAR": "After-Action Reports and Lessons Learned",
  "KSI-INR-RIR": "Review IR Procedures Effectiveness",
  "KSI-INR-RPI": "Review Past Incidents for Patterns",
  "KSI-INR-IRP": "Incident Response Planning",
  "KSI-INR-TIF": "Threat Intelligence Feeds",
  "KSI-INR-TIU": "Threat Intelligence Utilization",
  "KSI-INR-IOC": "Indicator of Compromise Management",

  // MLA — Monitoring, Logging, and Auditing
  "KSI-MLA-ALA": "Access Controls for Log Data",
  "KSI-MLA-EVC": "Evaluate and Test Configuration",
  "KSI-MLA-LET": "Log Event Types Catalog",
  "KSI-MLA-OSM": "Operate SIEM for Centralized Logging",
  "KSI-MLA-RVL": "Review and Audit Logs",
  "KSI-MLA-ALE": "Alert Engineering & Response",

  // PIY — Policy and Inventory
  "KSI-PIY-GIV": "Generate Real-Time Inventories",
  "KSI-PIY-RES": "Review Executive Support for Security",
  "KSI-PIY-RIS": "Review Security Investment Effectiveness",
  "KSI-PIY-RSD": "Review SDLC Security (CISA Secure By Design)",
  "KSI-PIY-RVD": "Review Vulnerability Disclosure Program",

  // RPL — Recovery Planning
  "KSI-RPL-ABO": "Recovery Planning Alignment",
  "KSI-RPL-ARP": "Align Recovery Plans with Objectives",
  "KSI-RPL-RRO": "Review RTO and RPO Objectives",
  "KSI-RPL-TRC": "Test Recovery Capabilities",

  // SVC — Service Configuration
  "KSI-SVC-ACM": "Automated Configuration Management",
  "KSI-SVC-ASM": "Attack Surface Management",
  "KSI-SVC-EIS": "Endpoint/Infrastructure Security",
  "KSI-SVC-PRR": "Post-Change Residual Review",
  "KSI-SVC-SNT": "Service Notification/Transparency",
  "KSI-SVC-VCM": "Vulnerability/Configuration Management",
  "KSI-SVC-VRI": "Vulnerability Risk Identification",
  "KSI-SVC-VSR": "Vulnerability Scanning Results",
  "KSI-SVC-VRM": "Vulnerability Remediation Management",

  // SCR — Supply Chain Risk
  "KSI-SCR-MIT": "Mitigate Supply Chain Risks",
  "KSI-SCR-MON": "Monitor Third-Party Software Vulnerabilities",
  "KSI-SCR-SAT": "Security Awareness Testing",
  "KSI-SCR-PEN": "Penetration Testing",
  "KSI-SCR-APT": "Advanced Persistent Threat Simulation",

  // SDE — Secure Development
  "KSI-SDE-SST": "Secure Software Testing",
  "KSI-SDE-SDP": "Secure Development Practices",

  // PPM — Policy & Procedure Management
  "KSI-PPM-PPR": "Policy & Procedure Review",
  "KSI-PPM-PPI": "Policy & Procedure Implementation",
};

/** Get the full theme name for a theme code */
export function getThemeLabel(themeCode: string): string {
  return THEME_LABELS[themeCode] || themeCode;
}

/** Get the title for a KSI ID */
export function getKsiLabel(ksiId: string): string {
  return KSI_TITLES[ksiId] || ksiId;
}

/** Extract the theme code from a KSI ID (e.g., "KSI-AFR-ADS" → "AFR") */
export function getThemeFromKsiId(ksiId: string): string {
  const parts = ksiId.split("-");
  return parts.length >= 2 ? parts[1] : "";
}

/** Format a KSI ID with its full title: "KSI-AFR-ADS — Authorization Data Sharing" */
export function formatKsiId(ksiId: string): string {
  const title = KSI_TITLES[ksiId];
  return title ? `${ksiId} — ${title}` : ksiId;
}

/** Format a KSI ID with theme context: "Authorization Data Sharing (AFR: Authorization by FedRAMP)" */
export function formatKsiWithTheme(ksiId: string): string {
  const title = KSI_TITLES[ksiId];
  const themeCode = getThemeFromKsiId(ksiId);
  const themeName = THEME_LABELS[themeCode];
  if (!title) return ksiId;
  return `${title} (${themeCode}: ${themeName || themeCode})`;
}
