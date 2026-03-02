/**
 * Engagement Templates — Pre-configured profiles for common engagement types.
 *
 * Each template pre-fills the engagement creation form with:
 * - Engagement type, description, notes
 * - Default RoE text (purpose, testing windows, restrictions)
 * - Scan configuration (nmap profiles, nuclei templates, ZAP policy)
 * - Phase settings (which phases to enable, auto-advance rules)
 * - Scope type guidance (domains, IPs, subnets, cloud)
 */

export interface ScanConfig {
  nmapProfile: string;
  nmapFlags: string;
  nucleiTemplates: string[];
  nucleiSeverity: string[];
  zapPolicy: string;
  zapStrength: "low" | "medium" | "high" | "insane";
  zapThreshold: "low" | "medium" | "high";
  wafEvasion: boolean;
  throttleMs: number;
}

export interface PhaseConfig {
  recon: boolean;
  enumeration: boolean;
  vulnDetection: boolean;
  exploitation: boolean;
  postExploit: boolean;
  reporting: boolean;
  autoAdvance: boolean;
  requireApprovalForExploits: boolean;
  requireApprovalForC2: boolean;
}

export interface RoeDefaults {
  purpose: string;
  testingDays: string[];
  testTimezone: string;
  testingHoursStart: string;
  testingHoursEnd: string;
  restrictions: string[];
  allowedTechniques: string[];
  prohibitedTechniques: string[];
  emergencyContact: string;
  deconflictionProcess: string;
}

export interface EngagementTemplate {
  id: string;
  name: string;
  shortName: string;
  description: string;
  icon: string;
  category: "pentest" | "red_team" | "phishing" | "purple_team" | "tabletop";
  engagementType: "pentest" | "red_team" | "phishing" | "purple_team" | "tabletop";
  defaultDescription: string;
  defaultNotes: string;
  scopeGuidance: string;
  scanConfig: ScanConfig;
  phaseConfig: PhaseConfig;
  roeDefaults: RoeDefaults;
  estimatedDuration: string;
  teamSize: string;
  difficulty: "beginner" | "intermediate" | "advanced" | "expert";
  tags: string[];
}

export const ENGAGEMENT_TEMPLATES: EngagementTemplate[] = [
  // ─── 1. External Web Application Pentest ─────────────────────────────────
  {
    id: "ext-webapp-pentest",
    name: "External Web Application Pentest",
    shortName: "Web App Pentest",
    description: "Systematic testing of external-facing web applications for OWASP Top 10, authentication flaws, injection vulnerabilities, and sensitive data exposure. Focuses on demonstrating unauthorized access to data or privileged functions.",
    icon: "globe",
    category: "pentest",
    engagementType: "pentest",
    defaultDescription: "External web application penetration test targeting customer-facing web applications. Testing will cover OWASP Top 10 vulnerabilities, authentication/authorization flaws, business logic errors, and sensitive data exposure. Goal: demonstrate unauthorized access to data or privileged functions on each in-scope asset.",
    defaultNotes: "Pre-engagement checklist:\n- Confirm all target URLs/domains\n- Verify test accounts provided (if authenticated testing)\n- Confirm WAF whitelisting or test from approved IPs\n- Establish emergency contact and deconfliction process\n- Review any excluded endpoints or functionality",
    scopeGuidance: "Enter the target domain(s) for the web application(s). Include subdomains if they host separate applications. For API-only targets, include the API base URL domain.",
    scanConfig: {
      nmapProfile: "web-focused",
      nmapFlags: "-sV -sC --script=http-enum,http-headers,http-methods,http-title,ssl-enum-ciphers -p 80,443,8080,8443,3000,5000,8000,9443",
      nucleiTemplates: ["cves", "vulnerabilities", "exposures", "misconfiguration", "technologies", "default-logins"],
      nucleiSeverity: ["critical", "high", "medium"],
      zapPolicy: "Default Policy",
      zapStrength: "medium",
      zapThreshold: "medium",
      wafEvasion: true,
      throttleMs: 200,
    },
    phaseConfig: {
      recon: true,
      enumeration: true,
      vulnDetection: true,
      exploitation: true,
      postExploit: false,
      reporting: true,
      autoAdvance: false,
      requireApprovalForExploits: true,
      requireApprovalForC2: true,
    },
    roeDefaults: {
      purpose: "Identify and demonstrate exploitable vulnerabilities in external-facing web applications. Testing will attempt to gain unauthorized access to data, privileged functions, and backend systems through the web application layer.",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      testTimezone: "America/New_York",
      testingHoursStart: "09:00",
      testingHoursEnd: "17:00",
      restrictions: [
        "No denial-of-service testing",
        "No destructive testing against production data",
        "No social engineering of customer employees",
        "Testing limited to identified web application endpoints",
      ],
      allowedTechniques: [
        "OWASP Top 10 testing",
        "Authentication and session management testing",
        "Authorization bypass attempts",
        "SQL injection, XSS, SSRF, XXE testing",
        "Business logic testing",
        "API security testing",
        "File upload testing",
        "Sensitive data exposure checks",
      ],
      prohibitedTechniques: [
        "Physical access attempts",
        "Social engineering",
        "Wireless network attacks",
        "DoS/DDoS attacks",
      ],
      emergencyContact: "",
      deconflictionProcess: "Contact engagement lead immediately if production impact is suspected. Cease testing and notify customer POC within 15 minutes of any unintended service disruption.",
    },
    estimatedDuration: "1-2 weeks",
    teamSize: "1-2 operators",
    difficulty: "intermediate",
    tags: ["web", "owasp", "application", "external", "api"],
  },

  // ─── 2. Internal Network Penetration Test ────────────────────────────────
  {
    id: "internal-network-pentest",
    name: "Internal Network Penetration Test",
    shortName: "Internal Pentest",
    description: "Simulates an insider threat or compromised endpoint scenario. Tests internal network segmentation, Active Directory security, privilege escalation paths, and lateral movement opportunities.",
    icon: "network",
    category: "pentest",
    engagementType: "pentest",
    defaultDescription: "Internal network penetration test simulating an insider threat or compromised workstation. Testing will cover network segmentation, Active Directory attacks, privilege escalation, credential harvesting, and lateral movement. Goal: demonstrate the blast radius from an initial internal foothold.",
    defaultNotes: "Pre-engagement checklist:\n- Confirm VPN/jump box access credentials\n- Verify test subnet ranges and excluded hosts\n- Confirm domain controller IPs (for AD testing)\n- Identify critical systems to avoid (SCADA, medical devices, etc.)\n- Establish out-of-band communication channel",
    scopeGuidance: "Enter the target IP ranges (CIDR notation) for internal network segments. Exclude any critical infrastructure IPs that should not be tested.",
    scanConfig: {
      nmapProfile: "internal-comprehensive",
      nmapFlags: "-sV -sC -O --script=smb-enum-shares,smb-vuln-ms17-010,ldap-rootdse,ms-sql-info -p- --min-rate=1000",
      nucleiTemplates: ["cves", "vulnerabilities", "network", "default-logins", "misconfiguration"],
      nucleiSeverity: ["critical", "high", "medium", "low"],
      zapPolicy: "Default Policy",
      zapStrength: "high",
      zapThreshold: "low",
      wafEvasion: false,
      throttleMs: 50,
    },
    phaseConfig: {
      recon: true,
      enumeration: true,
      vulnDetection: true,
      exploitation: true,
      postExploit: true,
      reporting: true,
      autoAdvance: false,
      requireApprovalForExploits: true,
      requireApprovalForC2: false,
    },
    roeDefaults: {
      purpose: "Assess internal network security posture by simulating an attacker with initial network access. Identify privilege escalation paths, lateral movement opportunities, and demonstrate the potential impact of a compromised internal endpoint.",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      testTimezone: "America/New_York",
      testingHoursStart: "08:00",
      testingHoursEnd: "18:00",
      restrictions: [
        "No testing of SCADA/ICS systems",
        "No modification of Active Directory Group Policy",
        "No deletion of production data",
        "Avoid systems listed in exclusion list",
      ],
      allowedTechniques: [
        "Network scanning and enumeration",
        "Active Directory enumeration and attacks",
        "Credential harvesting (LLMNR/NBT-NS poisoning, Kerberoasting)",
        "Privilege escalation (local and domain)",
        "Lateral movement (PsExec, WMI, WinRM, RDP)",
        "Pass-the-hash / Pass-the-ticket",
        "SMB relay attacks",
        "Internal web application testing",
      ],
      prohibitedTechniques: [
        "Physical access attempts",
        "Modification of GPOs or domain admin accounts",
        "Data exfiltration of real PII/PHI",
        "DoS attacks against domain controllers",
      ],
      emergencyContact: "",
      deconflictionProcess: "If domain admin is achieved, pause and notify team lead before proceeding. Contact customer SOC if any alerts are triggered that could cause incident response activation.",
    },
    estimatedDuration: "2-3 weeks",
    teamSize: "2-3 operators",
    difficulty: "advanced",
    tags: ["internal", "network", "active-directory", "lateral-movement", "privilege-escalation"],
  },

  // ─── 3. Full-Scope Red Team ──────────────────────────────────────────────
  {
    id: "full-scope-red-team",
    name: "Full-Scope Red Team Exercise",
    shortName: "Red Team",
    description: "Adversary simulation focused on finding the easiest path to initial access, deploying a C2 agent, establishing persistence, and pivoting into internal networks. Tests detection and response capabilities.",
    icon: "skull",
    category: "red_team",
    engagementType: "red_team",
    defaultDescription: "Full-scope red team exercise simulating a real-world adversary. Objective: gain initial access through the weakest entry point, deploy C2 agent, establish callback, and pivot laterally into internal networks and systems. Focus on stealth, evasion, and achieving objectives — not exhaustive coverage.",
    defaultNotes: "Pre-engagement checklist:\n- Confirm C2 infrastructure is staged (Caldera/Sliver)\n- Prepare phishing pretexts and domains\n- Stage payload delivery mechanisms\n- Confirm deconfliction with customer SOC/Blue Team\n- Establish safe words and emergency stop procedures\n- Review TTPs to emulate (if threat-informed)",
    scopeGuidance: "Enter all external-facing domains and IP ranges. For red team, the scope is typically broader — include any internet-facing assets the adversary could target.",
    scanConfig: {
      nmapProfile: "stealth",
      nmapFlags: "-sS -sV --version-intensity=2 -T2 --randomize-hosts -p 21,22,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,8080,8443",
      nucleiTemplates: ["cves", "vulnerabilities", "exposures", "default-logins"],
      nucleiSeverity: ["critical", "high"],
      zapPolicy: "Default Policy",
      zapStrength: "low",
      zapThreshold: "high",
      wafEvasion: true,
      throttleMs: 500,
    },
    phaseConfig: {
      recon: true,
      enumeration: true,
      vulnDetection: true,
      exploitation: true,
      postExploit: true,
      reporting: true,
      autoAdvance: true,
      requireApprovalForExploits: true,
      requireApprovalForC2: true,
    },
    roeDefaults: {
      purpose: "Simulate a real-world adversary to test the organization's detection and response capabilities. The red team will attempt to gain initial access, establish persistence, and achieve defined objectives while evading detection.",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"],
      testTimezone: "America/New_York",
      testingHoursStart: "00:00",
      testingHoursEnd: "23:59",
      restrictions: [
        "No destructive actions against production systems",
        "No exfiltration of real customer PII/PHI/PCI data",
        "Physical access limited to unlocked/public areas only",
        "No attacks against third-party systems not in scope",
      ],
      allowedTechniques: [
        "OSINT and social media reconnaissance",
        "Phishing and social engineering (with approved pretexts)",
        "External vulnerability exploitation",
        "C2 agent deployment and callback",
        "Lateral movement and pivoting",
        "Privilege escalation",
        "Persistence mechanisms",
        "Data staging and simulated exfiltration",
        "Credential harvesting",
        "Evasion techniques (AV/EDR bypass)",
      ],
      prohibitedTechniques: [
        "Destruction of production data",
        "Attacks against out-of-scope third parties",
        "Physical break-in (unless explicitly authorized)",
        "Real data exfiltration (use canary/test data)",
      ],
      emergencyContact: "",
      deconflictionProcess: "Use designated safe word to immediately halt operations. Red team lead contacts customer CISO directly for deconfliction. All actions logged in real-time to offensive audit trail.",
    },
    estimatedDuration: "3-4 weeks",
    teamSize: "3-5 operators",
    difficulty: "expert",
    tags: ["red-team", "adversary-simulation", "c2", "lateral-movement", "evasion"],
  },

  // ─── 4. Phishing & Social Engineering ────────────────────────────────────
  {
    id: "phishing-social-engineering",
    name: "Phishing & Social Engineering Campaign",
    shortName: "Phishing",
    description: "Targeted phishing campaign to test employee security awareness. Includes pretext development, landing page creation, credential harvesting, and payload delivery with detailed metrics.",
    icon: "fish",
    category: "phishing",
    engagementType: "phishing",
    defaultDescription: "Phishing and social engineering campaign to assess employee security awareness and email security controls. Campaign will include targeted spear-phishing emails, credential harvesting landing pages, and optional payload delivery. Metrics tracked: open rate, click rate, credential submission rate, report rate.",
    defaultNotes: "Pre-engagement checklist:\n- Confirm phishing domain is registered and aged\n- Set up GoPhish campaign infrastructure\n- Prepare email templates and landing pages\n- Confirm target employee list (HR-approved)\n- Verify SPF/DKIM/DMARC for phishing domain\n- Stage credential harvesting infrastructure\n- Coordinate with customer IT to whitelist if needed",
    scopeGuidance: "Enter the target organization's primary domain. The phishing domain should be entered in the Phishing Domain field. Target employee email addresses will be loaded separately in the campaign wizard.",
    scanConfig: {
      nmapProfile: "minimal",
      nmapFlags: "-sV -p 25,80,443,587,993 --script=smtp-enum-users,smtp-open-relay",
      nucleiTemplates: ["technologies", "exposures"],
      nucleiSeverity: ["critical", "high"],
      zapPolicy: "Default Policy",
      zapStrength: "low",
      zapThreshold: "high",
      wafEvasion: false,
      throttleMs: 1000,
    },
    phaseConfig: {
      recon: true,
      enumeration: false,
      vulnDetection: false,
      exploitation: false,
      postExploit: false,
      reporting: true,
      autoAdvance: false,
      requireApprovalForExploits: false,
      requireApprovalForC2: false,
    },
    roeDefaults: {
      purpose: "Assess organizational resilience to phishing and social engineering attacks. Test email security controls, employee awareness, and incident reporting procedures through controlled phishing simulations.",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      testTimezone: "America/New_York",
      testingHoursStart: "08:00",
      testingHoursEnd: "17:00",
      restrictions: [
        "No targeting of C-suite executives (unless explicitly approved)",
        "No use of fear-based or threatening pretexts",
        "No collection of actual passwords (use credential landing pages with immediate redirect)",
        "Campaign limited to approved employee list",
      ],
      allowedTechniques: [
        "Spear-phishing emails with crafted pretexts",
        "Credential harvesting landing pages",
        "Link-based payload delivery (benign tracking payloads only)",
        "Vishing (voice phishing) if approved",
        "Pretext development using OSINT",
        "Email spoofing assessment",
      ],
      prohibitedTechniques: [
        "Actual malware delivery",
        "Targeting personal email accounts",
        "Physical social engineering",
        "Attacks against email infrastructure",
      ],
      emergencyContact: "",
      deconflictionProcess: "If a targeted employee reports the phishing attempt to IT/SOC, coordinate with customer POC to handle appropriately without revealing the engagement to other employees.",
    },
    estimatedDuration: "1-2 weeks",
    teamSize: "1-2 operators",
    difficulty: "beginner",
    tags: ["phishing", "social-engineering", "awareness", "email", "gophish"],
  },

  // ─── 5. Cloud Infrastructure Assessment ──────────────────────────────────
  {
    id: "cloud-infra-assessment",
    name: "Cloud Infrastructure Assessment",
    shortName: "Cloud Pentest",
    description: "Security assessment of cloud infrastructure (AWS, Azure, GCP). Tests IAM policies, storage bucket permissions, network security groups, serverless functions, and cloud-native attack paths.",
    icon: "cloud",
    category: "pentest",
    engagementType: "pentest",
    defaultDescription: "Cloud infrastructure security assessment targeting AWS/Azure/GCP environments. Testing will cover IAM policy misconfigurations, storage bucket permissions, network security groups, serverless function vulnerabilities, and cloud-native privilege escalation paths. Goal: identify paths to unauthorized data access or administrative control.",
    defaultNotes: "Pre-engagement checklist:\n- Confirm cloud provider and account/subscription IDs\n- Verify read-only IAM credentials provided for assessment\n- Confirm regions in scope\n- Identify critical workloads and data classifications\n- Review shared responsibility model boundaries\n- Confirm if testing includes serverless/container workloads",
    scopeGuidance: "Enter the primary domain associated with the cloud infrastructure. Include any cloud-hosted application domains. IP ranges may include cloud-hosted public IPs or load balancer addresses.",
    scanConfig: {
      nmapProfile: "cloud-external",
      nmapFlags: "-sV -sC --script=http-headers,ssl-enum-ciphers -p 80,443,8080,8443,22,3389,5432,3306,6379,27017,9200",
      nucleiTemplates: ["cves", "vulnerabilities", "exposures", "misconfiguration", "technologies", "cloud"],
      nucleiSeverity: ["critical", "high", "medium"],
      zapPolicy: "Default Policy",
      zapStrength: "medium",
      zapThreshold: "medium",
      wafEvasion: true,
      throttleMs: 300,
    },
    phaseConfig: {
      recon: true,
      enumeration: true,
      vulnDetection: true,
      exploitation: true,
      postExploit: true,
      reporting: true,
      autoAdvance: false,
      requireApprovalForExploits: true,
      requireApprovalForC2: true,
    },
    roeDefaults: {
      purpose: "Assess the security posture of cloud infrastructure by identifying misconfigurations, excessive permissions, and exploitable vulnerabilities. Demonstrate potential impact of cloud-native attack paths including privilege escalation and cross-account access.",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      testTimezone: "America/New_York",
      testingHoursStart: "09:00",
      testingHoursEnd: "17:00",
      restrictions: [
        "No modification of IAM policies or security groups",
        "No deletion of cloud resources or data",
        "Testing limited to approved accounts/subscriptions",
        "No testing of production databases with live customer data",
      ],
      allowedTechniques: [
        "Cloud configuration review (IAM, S3/Blob, VPC/VNet)",
        "Metadata service exploitation (IMDS)",
        "Storage bucket enumeration and access testing",
        "Serverless function analysis",
        "Container escape testing (in isolated environments)",
        "Cross-account trust exploitation",
        "Cloud-native privilege escalation",
      ],
      prohibitedTechniques: [
        "Resource deletion or modification",
        "Crypto-mining or resource abuse",
        "Cross-tenant attacks",
        "Attacks against cloud provider infrastructure",
      ],
      emergencyContact: "",
      deconflictionProcess: "If cloud provider alerts or guardrails are triggered, pause testing and notify customer cloud team immediately. Document all API calls for forensic review.",
    },
    estimatedDuration: "2-3 weeks",
    teamSize: "2-3 operators",
    difficulty: "advanced",
    tags: ["cloud", "aws", "azure", "gcp", "iam", "infrastructure"],
  },

  // ─── 6. Purple Team Exercise ─────────────────────────────────────────────
  {
    id: "purple-team-exercise",
    name: "Purple Team Exercise",
    shortName: "Purple Team",
    description: "Collaborative exercise between red and blue teams. Executes specific ATT&CK techniques while blue team monitors detection coverage. Focuses on improving detection engineering and response procedures.",
    icon: "shield",
    category: "purple_team",
    engagementType: "purple_team",
    defaultDescription: "Purple team exercise combining offensive technique execution with defensive detection validation. Red team will execute specific MITRE ATT&CK techniques while blue team monitors SIEM, EDR, and network detection coverage. Goal: identify detection gaps and improve security monitoring.",
    defaultNotes: "Pre-engagement checklist:\n- Coordinate with SOC/Blue Team on schedule\n- Prepare ATT&CK technique execution matrix\n- Confirm SIEM and EDR access for blue team\n- Set up shared communication channel (Slack/Teams)\n- Prepare detection gap tracking spreadsheet\n- Review current detection rules and coverage",
    scopeGuidance: "Enter the target domain and IP ranges for the environment being tested. Purple team exercises typically cover both internal and external assets.",
    scanConfig: {
      nmapProfile: "standard",
      nmapFlags: "-sV -sC -O -p- --min-rate=500",
      nucleiTemplates: ["cves", "vulnerabilities", "misconfiguration", "technologies"],
      nucleiSeverity: ["critical", "high", "medium", "low"],
      zapPolicy: "Default Policy",
      zapStrength: "medium",
      zapThreshold: "medium",
      wafEvasion: false,
      throttleMs: 100,
    },
    phaseConfig: {
      recon: true,
      enumeration: true,
      vulnDetection: true,
      exploitation: true,
      postExploit: true,
      reporting: true,
      autoAdvance: false,
      requireApprovalForExploits: false,
      requireApprovalForC2: false,
    },
    roeDefaults: {
      purpose: "Collaborative purple team exercise to validate detection coverage across the MITRE ATT&CK framework. Red team executes techniques while blue team validates detection, triage, and response capabilities. Joint goal: improve organizational security posture.",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      testTimezone: "America/New_York",
      testingHoursStart: "09:00",
      testingHoursEnd: "17:00",
      restrictions: [
        "All techniques must be announced to blue team before execution",
        "No unannounced testing outside scheduled windows",
        "Production systems testing requires explicit approval per technique",
      ],
      allowedTechniques: [
        "All MITRE ATT&CK techniques as agreed in the technique matrix",
        "Atomic Red Team test execution",
        "Caldera adversary emulation",
        "Custom detection validation scripts",
        "Log source validation",
      ],
      prohibitedTechniques: [
        "Unannounced techniques not in the agreed matrix",
        "Destructive techniques without explicit approval",
        "Testing outside the scheduled purple team windows",
      ],
      emergencyContact: "",
      deconflictionProcess: "Real-time coordination via shared channel. Red team announces each technique before execution. Blue team confirms detection or gap. All results logged in shared tracking matrix.",
    },
    estimatedDuration: "1-2 weeks",
    teamSize: "2-4 operators + blue team",
    difficulty: "intermediate",
    tags: ["purple-team", "detection", "att&ck", "blue-team", "siem", "edr"],
  },

  // ─── 7. Tabletop Exercise ────────────────────────────────────────────────
  {
    id: "tabletop-exercise",
    name: "Tabletop Exercise",
    shortName: "Tabletop",
    description: "Discussion-based exercise simulating a cybersecurity incident. Tests incident response procedures, communication plans, and decision-making without live technical testing.",
    icon: "clipboard",
    category: "tabletop",
    engagementType: "tabletop",
    defaultDescription: "Tabletop exercise simulating a cybersecurity incident scenario. Participants will walk through incident response procedures, communication plans, and decision-making processes. No live technical testing — this is a discussion-based exercise focused on organizational preparedness.",
    defaultNotes: "Pre-engagement checklist:\n- Develop incident scenario and injects\n- Confirm participant list and roles\n- Reserve conference room / video call\n- Prepare facilitator guide and timeline\n- Review customer's existing IR plan\n- Prepare evaluation criteria and scoring rubric",
    scopeGuidance: "Enter the organization's primary domain for reference. Tabletop exercises don't require technical scope — the scenario will define the simulated incident scope.",
    scanConfig: {
      nmapProfile: "none",
      nmapFlags: "",
      nucleiTemplates: [],
      nucleiSeverity: [],
      zapPolicy: "Default Policy",
      zapStrength: "low",
      zapThreshold: "high",
      wafEvasion: false,
      throttleMs: 0,
    },
    phaseConfig: {
      recon: false,
      enumeration: false,
      vulnDetection: false,
      exploitation: false,
      postExploit: false,
      reporting: true,
      autoAdvance: false,
      requireApprovalForExploits: false,
      requireApprovalForC2: false,
    },
    roeDefaults: {
      purpose: "Conduct a tabletop exercise to evaluate the organization's incident response capabilities, communication procedures, and decision-making processes through a simulated cybersecurity incident scenario.",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      testTimezone: "America/New_York",
      testingHoursStart: "09:00",
      testingHoursEnd: "12:00",
      restrictions: [
        "No live technical testing",
        "Discussion-based only",
        "Scenario details confidential to facilitators until exercise start",
      ],
      allowedTechniques: [
        "Scenario presentation and discussion",
        "Inject delivery and response evaluation",
        "Communication plan testing",
        "Decision-making assessment",
      ],
      prohibitedTechniques: [
        "Any live technical testing",
        "Network scanning or exploitation",
        "Social engineering of participants",
      ],
      emergencyContact: "",
      deconflictionProcess: "N/A — tabletop exercises do not involve live testing. Facilitator manages exercise flow and timing.",
    },
    estimatedDuration: "2-4 hours",
    teamSize: "1-2 facilitators",
    difficulty: "beginner",
    tags: ["tabletop", "incident-response", "discussion", "preparedness"],
  },
];

/**
 * Get a template by ID
 */
export function getTemplateById(id: string): EngagementTemplate | undefined {
  return ENGAGEMENT_TEMPLATES.find(t => t.id === id);
}

/**
 * Get templates filtered by category
 */
export function getTemplatesByCategory(category: string): EngagementTemplate[] {
  return ENGAGEMENT_TEMPLATES.filter(t => t.category === category);
}
