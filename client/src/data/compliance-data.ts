// Compliance Framework Data - From mega-redteam-bundle
// Government Template Library + Government Red Team Expansion Pack

export interface ComplianceControl {
  family: string;
  moderate: string;
  high: string;
}

export const FEDRAMP_CONTROLS: ComplianceControl[] = [
  { family: "Access Control (AC)", moderate: "Required", high: "Enhanced monitoring" },
  { family: "Incident Response (IR)", moderate: "IR-4 baseline", high: "IR-4 + enhanced reporting" },
  { family: "Audit & Accountability (AU)", moderate: "AU baseline", high: "Expanded log retention" },
  { family: "System & Comms Protection (SC)", moderate: "SC baseline", high: "SC with additional encryption" },
  { family: "Continuous Monitoring (CA)", moderate: "CA-7", high: "CA-7 with higher frequency review" },
];

export const FEDRAMP_REQUIREMENTS = {
  authorization: [
    "Written ATO boundary confirmation",
    "Explicit phishing authorization from Authorizing Official (AO)",
    "Scope clearly defined (systems, personnel, timeframe)",
  ],
  dataHandling: [
    "No storage of federal credentials without written authorization",
    "Encrypt all stored identifiers",
    "Retention aligned to SSP documentation",
    "Secure destruction at engagement end",
  ],
  infraIsolation: [
    "Separate cloud project per engagement",
    "No infrastructure reuse across agencies",
    "Logging enabled and exportable",
  ],
  auditReporting: [
    "Provide control-mapped report",
    "Map findings to NIST 800-53 controls",
    "Provide ATT&CK technique mapping",
  ],
  postEngagement: [
    "Destroy infrastructure",
    "Revoke domains and certificates",
    "Archive encrypted reports",
    "Provide compliance attestation summary",
  ],
};

export interface CMMCLevel {
  level: string;
  name: string;
  description: string;
  requirements: string[];
  controlFamilies: string[];
}

export const CMMC_LEVELS: CMMCLevel[] = [
  {
    level: "Level 1",
    name: "Foundational",
    description: "Basic cyber hygiene practices for protecting Federal Contract Information (FCI).",
    requirements: [
      "Basic phishing awareness measurement",
      "Access control validation",
    ],
    controlFamilies: ["AC", "IA"],
  },
  {
    level: "Level 2",
    name: "Advanced",
    description: "Alignment with NIST SP 800-171 for protecting Controlled Unclassified Information (CUI).",
    requirements: [
      "Alignment with NIST SP 800-171",
      "Logging of simulated credential events",
      "MFA validation testing",
    ],
    controlFamilies: ["AC", "IA", "IR", "AU"],
  },
  {
    level: "Level 3",
    name: "Expert (Future)",
    description: "Advanced/progressive security practices for protecting CUI against APTs.",
    requirements: [
      "Advanced APT emulation",
      "Continuous monitoring validation",
      "Incident response maturity testing",
    ],
    controlFamilies: ["AC", "IA", "IR", "AU", "SC", "CA"],
  },
];

export const CMMC_REPORT_MAPPING = [
  "AC (Access Control)",
  "IA (Identification & Authentication)",
  "IR (Incident Response)",
  "AU (Audit & Accountability)",
];

export interface ImpersonationRule {
  theme: string;
  allowed: "Yes" | "No";
  requiresApproval: "Yes" | "No";
  prohibited: "Yes" | "No";
  notes?: string;
}

export const IMPERSONATION_MATRIX: ImpersonationRule[] = [
  { theme: "Generic IT Notice", allowed: "Yes", requiresApproval: "No", prohibited: "No", notes: "Safe for all engagement types" },
  { theme: "Base-wide Policy Update", allowed: "Yes", requiresApproval: "Yes", prohibited: "No", notes: "Requires CISO sign-off" },
  { theme: "Security Clearance Notice", allowed: "No", requiresApproval: "Yes", prohibited: "No", notes: "High sensitivity — legal review required" },
  { theme: "Operational Orders", allowed: "No", requiresApproval: "No", prohibited: "Yes", notes: "Never impersonate operational tasking" },
  { theme: "Classified Reference", allowed: "No", requiresApproval: "No", prohibited: "Yes", notes: "Never reference classified programs" },
  { theme: "Procurement Invoice", allowed: "Yes", requiresApproval: "Yes", prohibited: "No", notes: "Financial approval required" },
];

export const IMPERSONATION_CONTROLS = [
  "No impersonation of classified programs",
  "No operational tasking language",
  "No political themes",
  "Legal + CISO sign-off for High realism",
  "Record all impersonation themes used",
  "Store approval documentation",
];

export const SUPPORTED_INDUSTRIES = ["Enterprise", "Finance", "Healthcare", "Government"];

export const GOPHISH_POLICY_TEMPLATE = {
  subject: "Policy Review Required",
  body: `Dear {{.FirstName}},

An updated internal policy requires acknowledgment.

Please review the document below:

[Review Document]

Thank you,
Administrative Services`,
  category: "Governance",
  riskLevel: "Low",
  notes: "Neutral template suitable for all industries. Requires approval workflow before deployment.",
};

// Terraform Infrastructure Architecture
export interface InfraComponent {
  name: string;
  role: string;
  size: string;
  access: string;
  description: string;
}

export const ENGAGEMENT_INFRA: InfraComponent[] = [
  {
    name: "Bastion",
    role: "Jump Host",
    size: "s-1vcpu-1gb",
    access: "SSH from red team CIDRs only",
    description: "Entry point for all operator access. SSH-only from approved red team IP ranges. All other droplets accessible only through bastion.",
  },
  {
    name: "App Server",
    role: "C2 / Caldera / GoPhish",
    size: "s-2vcpu-2gb",
    access: "HTTPS 443 (configurable CIDRs), SSH from bastion only",
    description: "Hosts Caldera C2 server and GoPhish phishing platform. HTTPS exposed for campaign delivery, SSH restricted to bastion private IP.",
  },
  {
    name: "Mail Server",
    role: "SMTP Relay",
    size: "s-1vcpu-1gb",
    access: "SSH from bastion only, no inbound SMTP",
    description: "Outbound-only mail relay for phishing campaigns. No inbound SMTP to prevent abuse. All access through bastion.",
  },
  {
    name: "Log Sink",
    role: "Centralized Logging",
    size: "s-1vcpu-1gb",
    access: "SSH from bastion, syslog 6514 from VPC",
    description: "Centralized log collection with attached storage volume. Receives syslog from all VPC nodes. 50GB default storage.",
  },
];

export const INFRA_REQUIREMENTS = {
  terraform: ">= 1.5",
  provider: "DigitalOcean (doctl authenticated)",
  tools: ["jq"],
  variables: [
    { name: "do_token", description: "DigitalOcean API token", sensitive: true },
    { name: "engagement_id", description: "Unique engagement identifier (e.g., clientx-2026q1)", sensitive: false },
    { name: "region", description: "DO region (default: nyc3)", sensitive: false },
    { name: "ssh_key_fingerprints", description: "SSH keys uploaded to DigitalOcean", sensitive: false },
    { name: "redteam_admin_cidrs", description: "CIDRs allowed to SSH to bastion", sensitive: false },
    { name: "app_https_cidrs", description: "CIDRs allowed to reach app on 443", sensitive: false },
  ],
};
