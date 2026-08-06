/**
 * ROE Engagement Type Templates
 * 
 * Defines 5 engagement types with calibrated scope boundaries, guardrails,
 * liability protections, and compliance mappings. Each template pre-populates
 * type-appropriate defaults and validation rules.
 * 
 * Types:
 * 1. Vulnerability Scanning — lightest touch, automated tools only
 * 2. Penetration Testing — NIST SP 800-115 aligned, controlled exploitation
 * 3. Red/Purple Teaming — full adversary emulation with safety controls
 * 4. CI/CD Integration — automated pipeline testing with guardrails
 * 5. Phishing — social engineering campaigns with HR/legal coordination
 */

// ─── Types ─────────────────────────────────────────────────────────────────────

export type EngagementType =
  | "vulnerability_scanning"
  | "penetration_testing"
  | "red_purple_team"
  | "cicd_integration"
  | "phishing";

export interface RoeGuardrail {
  id: string;
  label: string;
  description: string;
  defaultEnabled: boolean;
  severity: "critical" | "high" | "medium" | "low";
  enforced: boolean; // If true, customer cannot disable this guardrail
}

export interface RoeLiabilityClause {
  id: string;
  title: string;
  defaultText: string;
  required: boolean;
  complianceRef?: string[];
}

export interface RoeFieldDefault {
  field: string;
  value: any;
  locked?: boolean; // If true, customer cannot change this default
  helpText?: string;
}

export interface RoeComplianceMapping {
  framework: string;
  controls: string[];
  required: boolean;
  description: string;
}

export interface RoeEngagementTemplate {
  type: EngagementType;
  label: string;
  shortDescription: string;
  longDescription: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  estimatedDuration: string;
  icon: string;
  
  // Scope design
  scopeFields: string[];
  requiredScopeFields: string[];
  hiddenScopeFields: string[];
  
  // Guardrails
  guardrails: RoeGuardrail[];
  
  // Field defaults
  fieldDefaults: RoeFieldDefault[];
  
  // Liability
  liabilityClauses: RoeLiabilityClause[];
  insuranceMinimums: {
    errorsAndOmissions: string;
    cyberLiability: string;
    generalLiability: string;
  };
  liabilityCapDefault: string;
  
  // Compliance
  complianceMappings: RoeComplianceMapping[];
  
  // Wizard steps (which sections to show/hide)
  wizardSections: string[];
  
  // Customer-facing help
  customerGuide: {
    whatToExpect: string;
    commonQuestions: { q: string; a: string }[];
    estimatedPrepTime: string;
  };
}

// ─── Shared Liability Clauses ──────────────────────────────────────────────────

const SHARED_LIABILITY_CLAUSES: RoeLiabilityClause[] = [
  {
    id: "hold_harmless",
    title: "Hold Harmless Agreement",
    defaultText: "The Customer agrees to hold harmless and indemnify the Testing Firm, its officers, directors, employees, and agents from and against any and all claims, damages, losses, costs, and expenses (including reasonable attorney fees) arising out of or related to the authorized security testing activities described in this Rules of Engagement document, provided such activities are conducted within the agreed scope and in accordance with the terms herein.",
    required: true,
    complianceRef: ["NIST SP 800-115 §7.1"],
  },
  {
    id: "indemnification",
    title: "Mutual Indemnification",
    defaultText: "Each party shall indemnify, defend, and hold harmless the other party from and against any third-party claims, damages, or expenses arising from: (a) the indemnifying party's breach of this agreement, (b) the indemnifying party's negligence or willful misconduct, or (c) the indemnifying party's violation of applicable law. The Testing Firm's indemnification obligation extends to damages caused by testing activities that exceed the authorized scope.",
    required: true,
  },
  {
    id: "data_breach_notification",
    title: "Data Breach Notification",
    defaultText: "In the event that the Testing Firm discovers or causes a data breach during authorized testing activities, the Testing Firm shall notify the Customer's designated security contact within 24 hours of discovery. The Testing Firm shall cooperate fully with the Customer's incident response procedures and provide all relevant evidence and documentation. The Testing Firm shall not be liable for pre-existing vulnerabilities discovered during testing.",
    required: true,
    complianceRef: ["CISA BOD 22-01", "NIST SP 800-61"],
  },
  {
    id: "data_destruction",
    title: "Data Destruction Certification",
    defaultText: "Upon completion of the engagement and expiration of the evidence retention period, the Testing Firm shall securely destroy all Customer data, evidence, credentials, and access tokens using NIST SP 800-88 compliant methods. The Testing Firm shall provide a signed Certificate of Destruction within 5 business days of data destruction. Failure to destroy data within the agreed timeframe constitutes a material breach.",
    required: true,
    complianceRef: ["NIST SP 800-88", "FedRAMP ROE §4.3"],
  },
  {
    id: "force_majeure",
    title: "Force Majeure",
    defaultText: "Neither party shall be liable for any failure or delay in performing its obligations under this agreement due to circumstances beyond its reasonable control, including but not limited to: acts of God, natural disasters, war, terrorism, government actions, power failures, internet outages, or pandemic-related restrictions. The affected party shall notify the other party promptly and resume performance as soon as reasonably practicable.",
    required: false,
  },
  {
    id: "dispute_resolution",
    title: "Dispute Resolution",
    defaultText: "Any dispute arising out of or relating to this agreement shall first be submitted to good-faith negotiation between the parties' designated representatives for a period of 30 days. If unresolved, the dispute shall be submitted to binding arbitration administered by the American Arbitration Association under its Commercial Arbitration Rules. The arbitration shall be conducted in the jurisdiction specified in the Governing Law section. Each party shall bear its own costs, and the arbitrator's fees shall be shared equally.",
    required: true,
  },
];

const SHARED_NDA_CLAUSE: RoeLiabilityClause = {
  id: "nda_confidentiality",
  title: "Confidentiality & Non-Disclosure",
  defaultText: "Both parties agree to maintain strict confidentiality of all information exchanged during the engagement, including but not limited to: vulnerability findings, system architecture details, credentials, network diagrams, and business processes. Neither party shall disclose such information to any third party without prior written consent, except as required by law or regulation. This obligation survives termination of the engagement for a period of 3 years.",
  required: true,
  complianceRef: ["NIST SP 800-115 §7.1"],
};

// ─── Template: Vulnerability Scanning ──────────────────────────────────────────

const VULNERABILITY_SCANNING: RoeEngagementTemplate = {
  type: "vulnerability_scanning",
  label: "Vulnerability Scanning",
  shortDescription: "Automated scanning to identify known vulnerabilities without exploitation",
  longDescription: "A non-intrusive assessment using automated scanning tools to identify known vulnerabilities, misconfigurations, and missing patches across your network and applications. No exploitation is attempted — this is the safest form of security testing and is often the starting point for organizations new to security assessments.",
  riskLevel: "low",
  estimatedDuration: "1–5 days",
  icon: "Search",
  
  scopeFields: [
    "inScopeIpRanges", "outOfScopeIpRanges", "inScopeDomains", "outOfScopeDomains",
    "inScopeApplications", "cloudEnvironments",
  ],
  requiredScopeFields: ["inScopeIpRanges", "inScopeDomains"],
  hiddenScopeFields: [
    "physicalLocations", "wirelessNetworks", "socialEngineeringPretexts",
  ],
  
  guardrails: [
    { id: "vs_no_exploit", label: "No Exploitation", description: "Scanning only — no vulnerabilities will be exploited or validated through active exploitation", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "vs_no_dos", label: "No Denial of Service", description: "Scans will not include DoS testing or high-volume requests that could impact availability", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "vs_rate_limit", label: "Rate Limiting", description: "Scan requests will be throttled to prevent network saturation (default: 100 requests/second)", defaultEnabled: true, severity: "high", enforced: false },
    { id: "vs_no_cred_harvest", label: "No Credential Harvesting", description: "No attempt to capture, guess, or brute-force credentials", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "vs_no_lateral", label: "No Lateral Movement", description: "Scanning is limited to the defined IP ranges — no pivoting to adjacent networks", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "vs_safe_checks", label: "Safe Checks Only", description: "Only non-destructive vulnerability checks will be used — no exploit payloads", defaultEnabled: true, severity: "high", enforced: true },
    { id: "vs_business_hours", label: "Business Hours Awareness", description: "Intensive scans will be scheduled outside peak business hours to minimize impact", defaultEnabled: true, severity: "medium", enforced: false },
    { id: "vs_auto_pause", label: "Auto-Pause on Error", description: "Scanning will automatically pause if error rates exceed 5% on any target", defaultEnabled: true, severity: "high", enforced: false },
  ],
  
  fieldDefaults: [
    { field: "dosTestingAllowed", value: 0, locked: true, helpText: "DoS testing is never included in vulnerability scanning" },
    { field: "physicalTestingAllowed", value: 0, locked: true },
    { field: "socialEngineeringAllowed", value: 0, locked: true },
    { field: "pivotingAllowed", value: 0, locked: true },
    { field: "exfiltrationAllowed", value: 0, locked: true },
    { field: "persistenceAllowed", value: 0, locked: true },
    { field: "fileModificationAllowed", value: 0, locked: true },
    { field: "fileInstallationAllowed", value: 0, locked: true },
    { field: "credentialedTesting", value: 0, helpText: "Authenticated scanning provides deeper results but requires test credentials" },
    { field: "evidenceRetentionDays", value: 30, helpText: "Scan results are retained for 30 days by default" },
    { field: "communicationFrequency", value: "as-needed" },
    { field: "reportFrequency", value: "final_only" },
  ],
  
  liabilityClauses: [
    ...SHARED_LIABILITY_CLAUSES,
    SHARED_NDA_CLAUSE,
    {
      id: "vs_limited_liability",
      title: "Limited Liability — Vulnerability Scanning",
      defaultText: "The Testing Firm's total aggregate liability for all claims arising from vulnerability scanning activities shall not exceed the total fees paid for the scanning engagement. The Testing Firm shall not be liable for: (a) pre-existing vulnerabilities or security weaknesses, (b) service degradation caused by the Customer's infrastructure limitations, or (c) any indirect, incidental, or consequential damages. The Customer acknowledges that vulnerability scanning may cause minor, temporary performance impacts on scanned systems.",
      required: true,
    },
  ],
  insuranceMinimums: {
    errorsAndOmissions: "$1,000,000",
    cyberLiability: "$1,000,000",
    generalLiability: "$1,000,000",
  },
  liabilityCapDefault: "1x contract value",
  
  complianceMappings: [
    { framework: "NIST SP 800-115", controls: ["§4.1 Network Scanning", "§4.2 Vulnerability Scanning"], required: false, description: "NIST technical guide for information security testing" },
    { framework: "PCI DSS 4.0", controls: ["11.3.1 Internal Vulnerability Scans", "11.3.2 External Vulnerability Scans"], required: false, description: "Quarterly vulnerability scanning for cardholder data environments" },
    { framework: "CISA BOD 22-01", controls: ["KEV Catalog Cross-Reference"], required: false, description: "Known Exploited Vulnerabilities must be checked" },
    { framework: "SOC 2", controls: ["CC7.1 Vulnerability Management"], required: false, description: "Regular vulnerability scanning as part of system monitoring" },
  ],
  
  wizardSections: ["engagement_type", "scope", "exclusions", "schedule", "communication", "data_handling", "authorization", "compliance", "review"],
  
  customerGuide: {
    whatToExpect: "We'll run automated scanners against your systems to find known vulnerabilities — like checking all the locks on your doors. Nothing gets 'broken into,' we just identify what's weak. You'll get a prioritized report showing what to fix first. Most scans complete in 1–3 days.",
    commonQuestions: [
      { q: "Will this break anything?", a: "Vulnerability scanning is non-intrusive. In rare cases, very old or fragile systems may experience minor slowdowns during scanning. We use 'safe checks' mode and rate limiting to minimize any impact." },
      { q: "Do I need to give you credentials?", a: "Not required, but recommended. Authenticated scans find 40–60% more vulnerabilities because they can check software versions and configurations that aren't visible from the outside." },
      { q: "How is this different from a penetration test?", a: "Vulnerability scanning identifies potential weaknesses. Penetration testing goes further by actually trying to exploit those weaknesses to prove they're real. Scanning is the first step — many organizations start here." },
      { q: "What tools will you use?", a: "Industry-standard scanners like Nessus, Qualys, OpenVAS, or Nuclei. We'll document exactly which tools are used in the final report." },
    ],
    estimatedPrepTime: "30 minutes",
  },
};

// ─── Template: Penetration Testing ─────────────────────────────────────────────

const PENETRATION_TESTING: RoeEngagementTemplate = {
  type: "penetration_testing",
  label: "Penetration Testing",
  shortDescription: "Controlled exploitation to validate vulnerabilities and assess real-world impact",
  longDescription: "A hands-on assessment where our security professionals actively attempt to exploit vulnerabilities in your systems, simulating how a real attacker would operate. This goes beyond scanning by proving which vulnerabilities are actually exploitable and what damage they could cause. Testing follows NIST SP 800-115 methodology with strict boundaries.",
  riskLevel: "medium",
  estimatedDuration: "1–4 weeks",
  icon: "Shield",
  
  scopeFields: [
    "inScopeIpRanges", "outOfScopeIpRanges", "inScopeDomains", "outOfScopeDomains",
    "inScopeApplications", "cloudEnvironments", "wirelessNetworks",
  ],
  requiredScopeFields: ["inScopeIpRanges", "inScopeDomains", "inScopeApplications"],
  hiddenScopeFields: ["socialEngineeringPretexts"],
  
  guardrails: [
    { id: "pt_no_dos", label: "No Denial of Service", description: "No intentional service disruption — testing stops immediately if availability is impacted", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "pt_no_data_exfil", label: "No Data Exfiltration", description: "Proof-of-access only — no actual customer data will be extracted or stored", defaultEnabled: true, severity: "critical", enforced: false },
    { id: "pt_no_persistence", label: "No Persistent Access", description: "All backdoors, shells, and implants will be removed immediately after each test session", defaultEnabled: true, severity: "high", enforced: false },
    { id: "pt_screenshot_evidence", label: "Screenshot Evidence Only", description: "Exploitation proof captured via screenshots — no full data dumps", defaultEnabled: true, severity: "high", enforced: false },
    { id: "pt_technique_whitelist", label: "Technique Whitelist", description: "Only pre-approved exploitation techniques will be used — no zero-days or destructive exploits", defaultEnabled: true, severity: "high", enforced: false },
    { id: "pt_production_safeguard", label: "Production Safeguard", description: "Testing automatically halts if a production system shows signs of instability", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "pt_credential_scope", label: "Credential Scope Lock", description: "Provided credentials will only be used on systems explicitly listed in scope", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "pt_cleanup_required", label: "Mandatory Cleanup", description: "All test artifacts, accounts, and modifications will be removed within 24 hours of test completion", defaultEnabled: true, severity: "high", enforced: true },
    { id: "pt_critical_notify", label: "Critical Finding Notification", description: "Critical/high-severity findings reported to customer within 4 hours of discovery", defaultEnabled: true, severity: "high", enforced: true },
  ],
  
  fieldDefaults: [
    { field: "dosTestingAllowed", value: 0, helpText: "DoS testing can be enabled separately with additional safeguards" },
    { field: "physicalTestingAllowed", value: 0, helpText: "Physical access testing is typically part of Red Team engagements" },
    { field: "socialEngineeringAllowed", value: 0, helpText: "Social engineering is handled through dedicated Phishing engagements" },
    { field: "pivotingAllowed", value: 1, helpText: "Lateral movement within scope helps identify network segmentation weaknesses" },
    { field: "exfiltrationAllowed", value: 0, helpText: "Proof-of-access screenshots are used instead of actual data exfiltration" },
    { field: "persistenceAllowed", value: 0, helpText: "Persistent access is not maintained between test sessions" },
    { field: "fileModificationAllowed", value: 0, helpText: "System files will not be modified during testing" },
    { field: "fileInstallationAllowed", value: 1, helpText: "Temporary testing tools may be installed and removed after each session" },
    { field: "credentialedTesting", value: 1, helpText: "Authenticated testing is recommended for comprehensive coverage" },
    { field: "evidenceRetentionDays", value: 90, helpText: "Evidence retained for 90 days to support remediation verification" },
    { field: "communicationFrequency", value: "daily" },
    { field: "reportFrequency", value: "weekly" },
  ],
  
  liabilityClauses: [
    ...SHARED_LIABILITY_CLAUSES,
    SHARED_NDA_CLAUSE,
    {
      id: "pt_liability",
      title: "Limitation of Liability — Penetration Testing",
      defaultText: "The Testing Firm's total aggregate liability for all claims arising from penetration testing activities shall not exceed two times (2x) the total fees paid for the engagement. The Testing Firm shall not be liable for: (a) pre-existing vulnerabilities, security weaknesses, or misconfigurations, (b) damages resulting from the Customer's failure to implement recommended remediation, (c) service disruptions caused by the Customer's infrastructure responding to authorized testing activities, (d) any indirect, incidental, special, or consequential damages, or (e) lost profits, data loss, or business interruption except where caused by the Testing Firm's gross negligence or willful misconduct. The Customer acknowledges that penetration testing inherently carries risk of minor service disruptions and agrees to maintain current backups of all in-scope systems.",
      required: true,
      complianceRef: ["NIST SP 800-115 §7.1"],
    },
    {
      id: "pt_third_party",
      title: "Third-Party System Disclaimer",
      defaultText: "The Testing Firm shall not test any systems, services, or infrastructure owned or operated by third parties (including cloud service providers, SaaS vendors, and managed service providers) unless the Customer provides written authorization from the third-party owner. The Customer shall indemnify the Testing Firm against any claims from third parties whose systems are inadvertently affected by authorized testing activities within the agreed scope.",
      required: true,
    },
  ],
  insuranceMinimums: {
    errorsAndOmissions: "$2,000,000",
    cyberLiability: "$2,000,000",
    generalLiability: "$1,000,000",
  },
  liabilityCapDefault: "2x contract value",
  
  complianceMappings: [
    { framework: "NIST SP 800-115", controls: ["§5.1 Target Identification", "§5.2 Technique Selection", "§5.3 Execution", "§5.4 Analysis"], required: true, description: "Primary methodology standard for penetration testing" },
    { framework: "FedRAMP", controls: ["Pen Test Guidance §3", "6 Attack Vectors", "SAR Appendix F"], required: false, description: "FedRAMP requires annual penetration testing with specific attack vectors" },
    { framework: "PCI DSS 4.0", controls: ["11.4 Penetration Testing", "11.4.1 Methodology", "11.4.3 Segmentation Testing"], required: false, description: "Annual penetration testing for cardholder data environments" },
    { framework: "CISA BOD 22-01", controls: ["KEV Catalog", "Remediation SLAs"], required: false, description: "Known Exploited Vulnerabilities must be tested and remediated" },
    { framework: "SOC 2", controls: ["CC7.1", "CC7.2 Monitoring", "CC8.1 Change Management"], required: false, description: "Penetration testing as part of system monitoring controls" },
    { framework: "HIPAA", controls: ["§164.308(a)(8) Evaluation"], required: false, description: "Technical evaluation of security controls for ePHI systems" },
  ],
  
  wizardSections: ["engagement_type", "scope", "exclusions", "schedule", "boundaries", "communication", "credentials", "data_handling", "authorization", "compliance", "reporting", "review"],
  
  customerGuide: {
    whatToExpect: "Our testers will actively try to break into your systems — like hiring a professional lockpick to test your security. We'll attempt to exploit real vulnerabilities to show you exactly what an attacker could do. You'll get a detailed report with proof of each finding and step-by-step remediation guidance. We communicate daily and alert you immediately on critical findings.",
    commonQuestions: [
      { q: "Could this damage our systems?", a: "We use careful, controlled techniques and avoid anything destructive. We maintain backups awareness and have emergency halt procedures. In 99%+ of engagements, there is zero service impact. We'll agree on specific guardrails before testing begins." },
      { q: "What's the difference between black box and white box?", a: "Black box means we start with no insider knowledge (like a real external attacker). White box means you share architecture docs, source code, and credentials (more thorough, finds more issues). Grey box is a middle ground. We recommend grey box for the best value." },
      { q: "Do we need to tell our IT team?", a: "Yes — your IT team should know testing is happening so they don't block our testers or trigger unnecessary incident responses. We'll coordinate timing and provide our source IP addresses." },
      { q: "What happens if you find something critical?", a: "We notify your designated security contact within 4 hours of discovering any critical vulnerability. We'll provide enough detail for your team to begin remediation immediately, even before the final report." },
      { q: "How long does remediation verification take?", a: "We include one round of free retesting within 90 days. We'll verify that your fixes actually resolved the vulnerabilities we found." },
    ],
    estimatedPrepTime: "1–2 hours",
  },
};

// ─── Template: Red/Purple Teaming ──────────────────────────────────────────────

const RED_PURPLE_TEAM: RoeEngagementTemplate = {
  type: "red_purple_team",
  label: "Red / Purple Teaming",
  shortDescription: "Full adversary emulation testing your detection and response capabilities",
  longDescription: "An advanced assessment that simulates real-world adversary behavior across your entire attack surface — network, applications, people, and physical security. Red teaming tests your defenses without your blue team's knowledge. Purple teaming adds collaborative exercises where our red team works alongside your defenders to improve detection and response. This is the most comprehensive form of security testing.",
  riskLevel: "high",
  estimatedDuration: "2–8 weeks",
  icon: "Swords",
  
  scopeFields: [
    "inScopeIpRanges", "outOfScopeIpRanges", "inScopeDomains", "outOfScopeDomains",
    "inScopeApplications", "cloudEnvironments", "wirelessNetworks",
    "physicalLocations", "socialEngineeringPretexts",
  ],
  requiredScopeFields: ["inScopeIpRanges", "inScopeDomains"],
  hiddenScopeFields: [],
  
  guardrails: [
    { id: "rt_deconfliction", label: "Deconfliction Protocol", description: "Unique deconfliction codes provided to trusted agents to distinguish red team activity from real attacks", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "rt_white_cell", label: "White Cell Coordination", description: "A neutral 'white cell' coordinator manages communication between red team and organizational leadership", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "rt_kill_switch", label: "Emergency Kill Switch", description: "Immediate halt capability — any authorized person can stop all red team activity with a single phone call", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "rt_safety_zones", label: "Safety Zones", description: "Designated critical systems (life safety, medical, financial processing) are permanently off-limits", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "rt_no_destructive", label: "No Destructive Actions", description: "No data deletion, ransomware simulation, or actions that could cause permanent damage", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "rt_graduated_escalation", label: "Graduated Escalation", description: "Techniques escalate gradually from passive recon to active exploitation, with approval gates at each level", defaultEnabled: true, severity: "high", enforced: false },
    { id: "rt_daily_checkin", label: "Daily Status Check-in", description: "Red team lead checks in with white cell daily to confirm operational status and any concerns", defaultEnabled: true, severity: "high", enforced: true },
    { id: "rt_evidence_chain", label: "Evidence Chain of Custody", description: "All evidence is timestamped, hashed, and maintained with forensic chain of custody", defaultEnabled: true, severity: "high", enforced: true },
    { id: "rt_physical_limits", label: "Physical Access Limits", description: "Physical testing limited to approved locations — no breaking locks, no forced entry, no trespassing beyond designated areas", defaultEnabled: true, severity: "high", enforced: false },
    { id: "rt_se_boundaries", label: "Social Engineering Boundaries", description: "No targeting of executives' families, no threats, no impersonation of law enforcement or emergency services", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "rt_data_handling", label: "Sensitive Data Protocol", description: "If PII, PHI, or classified data is encountered, testing stops in that area and the white cell is notified immediately", defaultEnabled: true, severity: "critical", enforced: true },
  ],
  
  fieldDefaults: [
    { field: "dosTestingAllowed", value: 0, helpText: "DoS testing requires separate approval and additional safeguards" },
    { field: "physicalTestingAllowed", value: 1, helpText: "Physical access testing is a core component of red team engagements" },
    { field: "socialEngineeringAllowed", value: 1, helpText: "Social engineering tests your human security layer — phishing, pretexting, tailgating" },
    { field: "pivotingAllowed", value: 1, helpText: "Lateral movement simulates how real adversaries expand their foothold" },
    { field: "exfiltrationAllowed", value: 1, helpText: "Controlled data exfiltration tests your DLP and monitoring capabilities" },
    { field: "persistenceAllowed", value: 1, helpText: "Persistence testing validates whether your team can detect and remove implants" },
    { field: "fileModificationAllowed", value: 0, helpText: "System files will not be modified unless specifically approved" },
    { field: "fileInstallationAllowed", value: 1, helpText: "Red team tools and implants will be installed and tracked for removal" },
    { field: "credentialedTesting", value: 1 },
    { field: "evidenceRetentionDays", value: 180, helpText: "Extended retention for comprehensive post-engagement analysis" },
    { field: "communicationFrequency", value: "daily" },
    { field: "reportFrequency", value: "weekly" },
    { field: "wirelessTestingAllowed", value: 1 },
  ],
  
  liabilityClauses: [
    ...SHARED_LIABILITY_CLAUSES,
    SHARED_NDA_CLAUSE,
    {
      id: "rt_liability",
      title: "Limitation of Liability — Red/Purple Team",
      defaultText: "The Testing Firm's total aggregate liability for all claims arising from red team and purple team activities shall not exceed three times (3x) the total fees paid for the engagement. Given the advanced and inherently higher-risk nature of adversary emulation, the Customer specifically acknowledges and accepts that: (a) red team activities may cause temporary service disruptions as a necessary part of testing detection and response capabilities, (b) social engineering activities may cause temporary employee concern or confusion, (c) physical access testing may trigger security alarms or responses, (d) persistence testing involves temporary installation of benign implants that will be fully removed. The Testing Firm shall not be liable for: (i) the Customer's failure to detect red team activities (this is a test outcome, not a damage), (ii) employee disciplinary actions taken based on social engineering test results, (iii) any indirect, incidental, special, or consequential damages, or (iv) damages exceeding the liability cap. The Customer shall maintain comprehensive cyber insurance and current system backups throughout the engagement.",
      required: true,
    },
    {
      id: "rt_physical_liability",
      title: "Physical Testing Liability",
      defaultText: "Physical access testing will be conducted only at locations explicitly listed in the scope. The Testing Firm shall carry valid identification and the signed ROE at all times during physical testing. The Customer shall provide a 24/7 emergency contact who can verify the Testing Firm's authorization if challenged by security personnel or law enforcement. The Customer shall indemnify the Testing Firm against any claims arising from authorized physical testing activities, including but not limited to: security guard responses, law enforcement interactions, and employee complaints. The Testing Firm shall not be liable for damages to physical security controls (locks, doors, barriers) that are tested with the Customer's explicit written approval.",
      required: false,
    },
    {
      id: "rt_se_liability",
      title: "Social Engineering Liability",
      defaultText: "Social engineering activities will be conducted only against personnel within the approved target scope. The Testing Firm shall not: (a) use threats, intimidation, or coercion, (b) impersonate law enforcement, emergency services, or government officials, (c) target employees' personal accounts or family members, or (d) create pretexts involving illegal activity. The Customer acknowledges that social engineering testing may temporarily cause employee stress or concern and agrees not to hold the Testing Firm liable for reasonable emotional responses to authorized social engineering activities. The Customer is solely responsible for any employment actions taken based on test results.",
      required: false,
    },
    {
      id: "rt_emergency_stop",
      title: "Emergency Stop Provisions",
      defaultText: "Either party may invoke an emergency stop at any time by contacting the designated emergency number. Upon invocation: (a) all red team activities cease immediately, (b) the red team lead confirms cessation within 15 minutes, (c) a preliminary incident report is provided within 4 hours, (d) the white cell convenes within 24 hours to assess whether testing can resume. If the emergency stop was triggered by a real security incident unrelated to testing, the Testing Firm shall cooperate fully with the Customer's incident response. The Testing Firm shall not be liable for any damages that occur between the emergency stop invocation and confirmation of cessation (maximum 15-minute window).",
      required: true,
    },
  ],
  insuranceMinimums: {
    errorsAndOmissions: "$5,000,000",
    cyberLiability: "$5,000,000",
    generalLiability: "$2,000,000",
  },
  liabilityCapDefault: "3x contract value",
  
  complianceMappings: [
    { framework: "NIST SP 800-115", controls: ["§5 Penetration Testing", "§6 Social Engineering", "§7 Planning"], required: true, description: "Full methodology coverage including social engineering" },
    { framework: "NIST SP 800-53", controls: ["CA-8 Penetration Testing", "CA-8(1) Independent Agent", "CA-8(2) Red Team Exercises"], required: false, description: "Red team exercises as a security assessment control" },
    { framework: "FedRAMP", controls: ["All 6 Attack Vectors", "SAR Appendix F", "PoA&M Integration"], required: false, description: "Comprehensive FedRAMP penetration testing with all attack vectors" },
    { framework: "MITRE ATT&CK", controls: ["Full Kill Chain Coverage"], required: false, description: "Adversary emulation mapped to MITRE ATT&CK framework" },
    { framework: "TIBER-EU", controls: ["Threat Intelligence", "Red Team Test", "Purple Team Replay"], required: false, description: "European framework for threat intelligence-based ethical red teaming" },
  ],
  
  wizardSections: ["engagement_type", "scope", "exclusions", "schedule", "boundaries", "communication", "credentials", "data_handling", "authorization", "compliance", "reporting", "review"],
  
  customerGuide: {
    whatToExpect: "This is the most realistic security test available. Our team will simulate a real adversary — using the same techniques that nation-states and criminal groups use — to test whether your organization can detect and respond to a sophisticated attack. We'll coordinate through a 'white cell' (a neutral party, usually your CISO or security director) who knows about the test but doesn't tip off the defenders. After the exercise, we'll conduct a collaborative debrief where our red team walks your blue team through exactly what happened.",
    commonQuestions: [
      { q: "What if our security team calls the police?", a: "This is why we have deconfliction protocols. Your white cell coordinator has our team's identities and deconfliction codes. If law enforcement is contacted, the white cell can immediately verify our authorization. We also carry signed copies of the ROE at all times." },
      { q: "Will you actually break into our building?", a: "Physical testing is optional and always pre-approved. We test things like tailgating, badge cloning, and social engineering at reception — never forced entry or property damage. We'll agree on exact boundaries before any physical testing." },
      { q: "What about our employees — will they be targeted?", a: "Social engineering targets are agreed upon in advance. We never use threats, target families, or create pretexts involving illegal activity. After the engagement, we recommend awareness training rather than disciplinary action." },
      { q: "How is this different from a penetration test?", a: "A pentest finds vulnerabilities in your technology. A red team tests your entire security program — people, processes, and technology — against a realistic adversary scenario. Purple teaming adds the collaborative element where we help your defenders improve in real-time." },
    ],
    estimatedPrepTime: "3–5 hours",
  },
};

// ─── Template: CI/CD Integration ───────────────────────────────────────────────

const CICD_INTEGRATION: RoeEngagementTemplate = {
  type: "cicd_integration",
  label: "CI/CD Pipeline Integration",
  shortDescription: "Automated security testing embedded in your development pipeline",
  longDescription: "Continuous security testing integrated directly into your CI/CD pipeline. Every commit, pull request, or release automatically triggers security scans — SAST, DAST, SCA, container scanning, and IaC analysis. This shifts security left by catching vulnerabilities before they reach production. The ROE defines what scans run, when they run, and what happens when they find issues.",
  riskLevel: "low",
  estimatedDuration: "Ongoing (setup: 1–3 days)",
  icon: "GitBranch",
  
  scopeFields: [
    "inScopeDomains", "inScopeApplications", "cloudEnvironments",
  ],
  requiredScopeFields: ["inScopeApplications"],
  hiddenScopeFields: [
    "inScopeIpRanges", "outOfScopeIpRanges", "wirelessNetworks",
    "physicalLocations", "socialEngineeringPretexts",
  ],
  
  guardrails: [
    { id: "ci_scan_timeout", label: "Scan Duration Limit", description: "Each scan must complete within the configured timeout (default: 30 minutes) to avoid blocking deployments", defaultEnabled: true, severity: "high", enforced: true },
    { id: "ci_no_production", label: "No Production Testing", description: "CI/CD scans only run against staging/dev environments and code artifacts — never against production", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ci_no_exploit", label: "No Active Exploitation", description: "Scans identify vulnerabilities but do not attempt exploitation in the pipeline", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ci_rollback_trigger", label: "Rollback Triggers", description: "Critical findings automatically trigger deployment rollback or blocking based on configured policy", defaultEnabled: true, severity: "high", enforced: false },
    { id: "ci_secret_detection", label: "Secret Detection", description: "Automatically detect and block commits containing API keys, passwords, or other secrets", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ci_dependency_check", label: "Dependency Vulnerability Check", description: "Block dependencies with known critical vulnerabilities from being added", defaultEnabled: true, severity: "high", enforced: false },
    { id: "ci_excluded_paths", label: "Path Exclusions", description: "Certain file paths (test fixtures, vendor code, generated files) are excluded from scanning", defaultEnabled: true, severity: "low", enforced: false },
    { id: "ci_rate_limit", label: "Scan Rate Limiting", description: "Maximum number of concurrent scans to prevent resource exhaustion in the CI environment", defaultEnabled: true, severity: "medium", enforced: false },
  ],
  
  fieldDefaults: [
    { field: "dosTestingAllowed", value: 0, locked: true },
    { field: "physicalTestingAllowed", value: 0, locked: true },
    { field: "socialEngineeringAllowed", value: 0, locked: true },
    { field: "pivotingAllowed", value: 0, locked: true },
    { field: "exfiltrationAllowed", value: 0, locked: true },
    { field: "persistenceAllowed", value: 0, locked: true },
    { field: "fileModificationAllowed", value: 0, locked: true },
    { field: "fileInstallationAllowed", value: 0, locked: true },
    { field: "credentialedTesting", value: 0, locked: true },
    { field: "evidenceRetentionDays", value: 365, helpText: "CI/CD scan results retained for 1 year for trend analysis" },
    { field: "communicationFrequency", value: "as-needed" },
    { field: "reportFrequency", value: "weekly" },
    { field: "cicdFailureAction", value: "warn_only", helpText: "Start with 'warn only' to baseline your findings, then escalate to 'block deploy' once false positives are tuned" },
    { field: "cicdMaxScanDuration", value: 30, helpText: "30-minute timeout prevents scans from blocking your pipeline" },
  ],
  
  liabilityClauses: [
    ...SHARED_LIABILITY_CLAUSES,
    SHARED_NDA_CLAUSE,
    {
      id: "ci_liability",
      title: "Limitation of Liability — CI/CD Integration",
      defaultText: "The Testing Firm's total aggregate liability for all claims arising from CI/CD pipeline integration shall not exceed the annual subscription fees paid for the service. The Testing Firm shall not be liable for: (a) deployment delays caused by scan findings or scan timeouts, (b) false positive findings that block deployments when the Customer has configured 'block deploy' failure action, (c) vulnerabilities that exist in code not covered by the configured scan types, (d) any indirect, incidental, special, or consequential damages including lost revenue from delayed deployments. The Customer acknowledges that automated scanning may produce false positives and is responsible for configuring appropriate failure actions and exclusion rules.",
      required: true,
    },
    {
      id: "ci_source_code",
      title: "Source Code Handling",
      defaultText: "The Testing Firm's scanning tools will process the Customer's source code solely for the purpose of security analysis. Source code is processed in-memory and is not stored, copied, or transmitted outside the Customer's CI/CD environment except for: (a) vulnerability findings and code snippets necessary for remediation guidance, (b) dependency manifests for SCA analysis. The Testing Firm shall not reverse-engineer, decompile, or use the Customer's source code for any purpose other than security testing.",
      required: true,
    },
  ],
  insuranceMinimums: {
    errorsAndOmissions: "$1,000,000",
    cyberLiability: "$1,000,000",
    generalLiability: "$1,000,000",
  },
  liabilityCapDefault: "1x annual subscription",
  
  complianceMappings: [
    { framework: "NIST SP 800-218 (SSDF)", controls: ["PW.7 Code Review", "PW.8 Testing", "RV.1 Vulnerability Identification"], required: false, description: "Secure Software Development Framework — shift-left security" },
    { framework: "SOC 2", controls: ["CC7.1 Vulnerability Management", "CC8.1 Change Management"], required: false, description: "Continuous security testing as part of change management" },
    { framework: "PCI DSS 4.0", controls: ["6.3 Security Vulnerabilities", "6.5 Change Management"], required: false, description: "Automated security testing in development lifecycle" },
    { framework: "FedRAMP", controls: ["SA-11 Developer Testing", "SI-10 Input Validation"], required: false, description: "Automated security testing as part of system development" },
  ],
  
  wizardSections: ["engagement_type", "scope", "exclusions", "schedule", "communication", "data_handling", "authorization", "compliance", "review"],
  
  customerGuide: {
    whatToExpect: "We'll integrate security scanning directly into your development pipeline — every time your developers push code, our tools automatically check for vulnerabilities, exposed secrets, and risky dependencies. Think of it as spell-check for security. Setup takes 1–3 days, and after that it runs automatically. You'll get a dashboard showing trends over time.",
    commonQuestions: [
      { q: "Will this slow down our deployments?", a: "Most scans complete in 5–15 minutes. We set a 30-minute timeout by default so scans never block your pipeline indefinitely. You can start with 'warn only' mode so findings don't block deployments while you tune the system." },
      { q: "What if it finds too many false positives?", a: "We start with conservative rules and tune over time. You can exclude specific paths, suppress known false positives, and adjust severity thresholds. Most teams reach a stable baseline within 2–4 weeks." },
      { q: "Does it see our source code?", a: "Scans run inside your CI/CD environment. We only receive vulnerability findings and small code snippets for remediation guidance — never your full source code. Source code handling is covered in the ROE." },
      { q: "Which scan types should we start with?", a: "We recommend starting with SAST (static analysis), SCA (dependency checking), and secret detection. These catch the most common issues with the fewest false positives. Add DAST and container scanning once you're comfortable." },
    ],
    estimatedPrepTime: "15 minutes",
  },
};

// ─── Template: Phishing ────────────────────────────────────────────────────────

const PHISHING: RoeEngagementTemplate = {
  type: "phishing",
  label: "Phishing Engagement",
  shortDescription: "Social engineering campaigns testing employee security awareness",
  longDescription: "A controlled social engineering assessment that sends realistic phishing emails, SMS messages (smishing), or voice calls (vishing) to your employees to measure security awareness and identify training gaps. Campaigns are carefully designed with approved pretexts, target lists, and strict boundaries to test your human security layer without causing harm.",
  riskLevel: "medium",
  estimatedDuration: "2–6 weeks",
  icon: "Mail",
  
  scopeFields: [
    "inScopeDomains",
  ],
  requiredScopeFields: ["inScopeDomains"],
  hiddenScopeFields: [
    "inScopeIpRanges", "outOfScopeIpRanges", "inScopeApplications",
    "cloudEnvironments", "wirelessNetworks", "physicalLocations",
  ],
  
  guardrails: [
    { id: "ph_approved_pretexts", label: "Approved Pretexts Only", description: "Only pre-approved phishing scenarios will be used — no improvisation during the campaign", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ph_no_threats", label: "No Threats or Coercion", description: "Phishing emails will never contain threats, intimidation, or language that could cause severe distress", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ph_no_law_enforcement", label: "No Law Enforcement Impersonation", description: "Pretexts will never impersonate law enforcement, government agencies, or emergency services", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ph_no_personal", label: "No Personal Account Targeting", description: "Only corporate email addresses and phone numbers will be targeted — never personal accounts", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ph_credential_limits", label: "Credential Handling Limits", description: "Captured credentials are hashed immediately and never used to access actual systems unless explicitly authorized", defaultEnabled: true, severity: "critical", enforced: true },
    { id: "ph_landing_safe", label: "Safe Landing Pages", description: "Phishing landing pages display an educational message after credential capture — no malware, no persistent tracking", defaultEnabled: true, severity: "high", enforced: true },
    { id: "ph_opt_out", label: "Employee Opt-Out", description: "Employees who report the phishing email are removed from subsequent waves (configurable)", defaultEnabled: true, severity: "medium", enforced: false },
    { id: "ph_volume_limit", label: "Daily Volume Limit", description: "Maximum emails per day to prevent email system overload and reduce detection by email security tools", defaultEnabled: true, severity: "high", enforced: false },
    { id: "ph_hr_coordination", label: "HR Coordination Required", description: "HR department must be notified before campaign launch and involved in post-campaign communications", defaultEnabled: true, severity: "high", enforced: true },
    { id: "ph_no_discipline", label: "No Disciplinary Recommendation", description: "Results are used for training, not punishment — the Testing Firm will not recommend disciplinary action", defaultEnabled: true, severity: "high", enforced: true },
    { id: "ph_payload_limits", label: "Payload Restrictions", description: "Attachments are benign tracking files only — no actual malware, macros with harmful payloads, or exploit code", defaultEnabled: true, severity: "critical", enforced: true },
  ],
  
  fieldDefaults: [
    { field: "dosTestingAllowed", value: 0, locked: true },
    { field: "physicalTestingAllowed", value: 0, helpText: "Physical social engineering (tailgating, USB drops) can be added as an option" },
    { field: "socialEngineeringAllowed", value: 1, locked: true, helpText: "Social engineering is the core of phishing engagements" },
    { field: "pivotingAllowed", value: 0, locked: true },
    { field: "exfiltrationAllowed", value: 0, locked: true },
    { field: "persistenceAllowed", value: 0, locked: true },
    { field: "fileModificationAllowed", value: 0, locked: true },
    { field: "fileInstallationAllowed", value: 0, locked: true },
    { field: "credentialedTesting", value: 0, locked: true },
    { field: "evidenceRetentionDays", value: 90, helpText: "Campaign results retained for 90 days for trend analysis" },
    { field: "communicationFrequency", value: "weekly" },
    { field: "reportFrequency", value: "final_only" },
    { field: "phishingCredentialHarvesting", value: "capture_only", helpText: "Credentials are captured and hashed for reporting but never used to access systems" },
    { field: "phishingPayloadType", value: "link_only", helpText: "Start with link-only phishing — attachments can be added in later campaigns" },
    { field: "phishingMaxEmailsPerDay", value: 50, helpText: "50 emails/day prevents triggering email security rate limits" },
    { field: "phishingCampaignDurationDays", value: 14, helpText: "Two-week campaigns provide enough data for meaningful statistics" },
    { field: "phishingOptOutHandling", value: "remove_from_campaign" },
    { field: "phishingEmployeeNotificationPost", value: "after_campaign", helpText: "Employees are informed after the campaign ends, with training resources" },
    { field: "phishingTrainingRequired", value: 1, helpText: "We recommend mandatory awareness training for all employees after the campaign" },
    { field: "phishingBrandImpersonation", value: "internal_only", helpText: "Internal-only means we impersonate your company's IT department, HR, etc. — not external brands" },
  ],
  
  liabilityClauses: [
    ...SHARED_LIABILITY_CLAUSES,
    SHARED_NDA_CLAUSE,
    {
      id: "ph_liability",
      title: "Limitation of Liability — Phishing Engagement",
      defaultText: "The Testing Firm's total aggregate liability for all claims arising from phishing engagement activities shall not exceed two times (2x) the total fees paid for the engagement. The Testing Firm shall not be liable for: (a) employee emotional distress resulting from authorized phishing simulations conducted within the approved pretexts, (b) employment actions taken by the Customer based on phishing test results (the Testing Firm explicitly recommends against disciplinary action), (c) email deliverability issues caused by the Customer's email security controls, (d) any indirect, incidental, special, or consequential damages. The Customer acknowledges that phishing simulations are designed to be realistic and may temporarily cause employee concern, and agrees that this is a necessary aspect of effective security awareness testing.",
      required: true,
    },
    {
      id: "ph_employee_privacy",
      title: "Employee Privacy Protection",
      defaultText: "The Testing Firm shall handle all employee data (names, email addresses, phone numbers, response data) in accordance with applicable privacy laws and the Customer's privacy policy. Individual employee results shall be reported only in aggregate to the Customer's designated security contact and HR representative. The Testing Firm shall not: (a) share individual employee results with the employee's direct manager unless explicitly authorized, (b) retain employee personal data beyond the evidence retention period, (c) use employee data for any purpose other than the phishing assessment. The Customer is responsible for ensuring that phishing testing is permitted under applicable employment agreements, union contracts, and local labor laws.",
      required: true,
    },
    {
      id: "ph_union_coordination",
      title: "Union & Labor Law Compliance",
      defaultText: "If the Customer's workforce includes unionized employees, the Customer shall: (a) review applicable collective bargaining agreements for restrictions on monitoring or testing, (b) notify union representatives if required by the agreement, (c) ensure phishing testing complies with local labor laws regarding employee monitoring and testing. The Testing Firm shall not be liable for the Customer's failure to comply with labor agreements or local employment laws. The Customer shall indemnify the Testing Firm against any claims from employees, unions, or labor boards arising from authorized phishing activities.",
      required: false,
    },
    {
      id: "ph_brand_protection",
      title: "Brand Impersonation Limits",
      defaultText: "When impersonating external brands (if authorized), the Testing Firm shall: (a) use only brands explicitly listed in the approved brands list, (b) not register domains that could be confused with the actual brand's domains, (c) include clear 'this was a test' messaging on all landing pages, (d) destroy all brand-impersonation materials within 7 days of campaign completion. The Customer warrants that they have obtained any necessary permissions for external brand impersonation and shall indemnify the Testing Firm against trademark or brand-related claims.",
      required: false,
    },
  ],
  insuranceMinimums: {
    errorsAndOmissions: "$2,000,000",
    cyberLiability: "$2,000,000",
    generalLiability: "$1,000,000",
  },
  liabilityCapDefault: "2x contract value",
  
  complianceMappings: [
    { framework: "NIST SP 800-115", controls: ["§6 Social Engineering Testing"], required: false, description: "Social engineering testing methodology" },
    { framework: "NIST SP 800-50", controls: ["Security Awareness Training"], required: false, description: "Building an IT security awareness and training program" },
    { framework: "PCI DSS 4.0", controls: ["12.6 Security Awareness Program"], required: false, description: "Security awareness training for cardholder data environments" },
    { framework: "SOC 2", controls: ["CC1.4 Security Awareness"], required: false, description: "Security awareness as part of control environment" },
    { framework: "HIPAA", controls: ["§164.308(a)(5) Security Awareness Training"], required: false, description: "Security awareness training for healthcare organizations" },
    { framework: "CISA", controls: ["Phishing Assessment Services"], required: false, description: "CISA offers free phishing assessments for critical infrastructure" },
  ],
  
  wizardSections: ["engagement_type", "scope", "exclusions", "schedule", "boundaries", "communication", "data_handling", "authorization", "compliance", "reporting", "review"],
  
  customerGuide: {
    whatToExpect: "We'll send realistic phishing emails to your employees to measure how many click links, enter credentials, or report the email. This isn't about catching people doing something wrong — it's about identifying where your organization needs better training. After the campaign, we provide aggregate statistics and recommend targeted training. Most campaigns run for 2 weeks with multiple 'waves' of different phishing scenarios.",
    commonQuestions: [
      { q: "Will employees get in trouble?", a: "We strongly recommend against using results for disciplinary action. Phishing tests are most effective when employees feel safe reporting — punishment creates a culture of hiding mistakes. Results should drive training, not consequences." },
      { q: "What kind of emails will you send?", a: "We'll agree on specific pretexts (scenarios) before the campaign. Common examples: password reset requests, IT system notifications, package delivery alerts, or HR policy updates. You approve every pretext before we send anything." },
      { q: "Do we need to tell HR?", a: "Yes — HR must be notified before the campaign. They need to know so they can handle any employee concerns and participate in post-campaign communications. We also recommend checking union agreements if applicable." },
      { q: "What about our email security tools?", a: "We'll coordinate with your IT team to ensure our test emails aren't blocked by spam filters. This usually means whitelisting our sending domain. We'll also measure how many emails your security tools catch — that's valuable data too." },
      { q: "Can we include text messages and phone calls?", a: "Yes — smishing (SMS phishing) and vishing (voice phishing) can be added as options. Each requires separate approval and has its own guardrails. Most organizations start with email-only and expand later." },
    ],
    estimatedPrepTime: "1–2 hours",
  },
};

// ─── Template Registry ─────────────────────────────────────────────────────────

export const ROE_TEMPLATES: Record<EngagementType, RoeEngagementTemplate> = {
  vulnerability_scanning: VULNERABILITY_SCANNING,
  penetration_testing: PENETRATION_TESTING,
  red_purple_team: RED_PURPLE_TEAM,
  cicd_integration: CICD_INTEGRATION,
  phishing: PHISHING,
};

export const ENGAGEMENT_TYPE_LIST = Object.values(ROE_TEMPLATES).map(t => ({
  type: t.type,
  label: t.label,
  shortDescription: t.shortDescription,
  riskLevel: t.riskLevel,
  estimatedDuration: t.estimatedDuration,
  icon: t.icon,
}));

/**
 * Get the template for a specific engagement type.
 */
export function getEngagementTemplate(type: EngagementType): RoeEngagementTemplate {
  const template = ROE_TEMPLATES[type];
  if (!template) {
    throw new Error(`Unknown engagement type: ${type}`);
  }
  return template;
}

/**
 * Get field defaults for a specific engagement type.
 * Returns a flat object suitable for merging into an ROE document.
 */
export function getFieldDefaults(type: EngagementType): Record<string, any> {
  const template = getEngagementTemplate(type);
  const defaults: Record<string, any> = {};
  for (const fd of template.fieldDefaults) {
    defaults[fd.field] = fd.value;
  }
  defaults.roeEngagementType = type;
  return defaults;
}

/**
 * Get locked fields for a specific engagement type.
 * These fields cannot be changed by the customer.
 */
export function getLockedFields(type: EngagementType): string[] {
  const template = getEngagementTemplate(type);
  return template.fieldDefaults
    .filter(fd => fd.locked)
    .map(fd => fd.field);
}

/**
 * Get enforced guardrails for a specific engagement type.
 * These guardrails cannot be disabled by the customer.
 */
export function getEnforcedGuardrails(type: EngagementType): RoeGuardrail[] {
  const template = getEngagementTemplate(type);
  return template.guardrails.filter(g => g.enforced);
}

/**
 * Validate that an ROE document respects the guardrails for its engagement type.
 * Returns a list of violations.
 */
export function validateGuardrails(
  type: EngagementType,
  roeData: Record<string, any>
): { guardrailId: string; label: string; violation: string }[] {
  const template = getEngagementTemplate(type);
  const violations: { guardrailId: string; label: string; violation: string }[] = [];
  
  // Check locked field defaults
  for (const fd of template.fieldDefaults) {
    if (fd.locked && roeData[fd.field] !== undefined && roeData[fd.field] !== fd.value) {
      violations.push({
        guardrailId: `locked_${fd.field}`,
        label: `Locked Field: ${fd.field}`,
        violation: `Field "${fd.field}" is locked to ${fd.value} for ${template.label} engagements but was set to ${roeData[fd.field]}`,
      });
    }
  }
  
  // Type-specific guardrail checks
  if (type === "vulnerability_scanning") {
    if (roeData.dosTestingAllowed) violations.push({ guardrailId: "vs_no_dos", label: "No Denial of Service", violation: "DoS testing is not permitted for vulnerability scanning" });
    if (roeData.pivotingAllowed) violations.push({ guardrailId: "vs_no_lateral", label: "No Lateral Movement", violation: "Lateral movement is not permitted for vulnerability scanning" });
    if (roeData.exfiltrationAllowed) violations.push({ guardrailId: "vs_no_exploit", label: "No Exploitation", violation: "Data exfiltration is not permitted for vulnerability scanning" });
    if (roeData.persistenceAllowed) violations.push({ guardrailId: "vs_no_exploit", label: "No Exploitation", violation: "Persistence is not permitted for vulnerability scanning" });
  }
  
  if (type === "cicd_integration") {
    if (roeData.dosTestingAllowed) violations.push({ guardrailId: "ci_no_production", label: "No Production Testing", violation: "DoS testing is not permitted for CI/CD integration" });
    if (roeData.pivotingAllowed) violations.push({ guardrailId: "ci_no_exploit", label: "No Active Exploitation", violation: "Lateral movement is not permitted for CI/CD integration" });
  }
  
  if (type === "phishing") {
    if (roeData.pivotingAllowed) violations.push({ guardrailId: "ph_no_lateral", label: "No Lateral Movement", violation: "Lateral movement is not permitted for phishing engagements" });
    if (roeData.exfiltrationAllowed) violations.push({ guardrailId: "ph_no_exfil", label: "No Data Exfiltration", violation: "Data exfiltration is not permitted for phishing engagements" });
    if (!roeData.phishingHrNotified && roeData.status !== "draft") violations.push({ guardrailId: "ph_hr_coordination", label: "HR Coordination Required", violation: "HR must be notified before a phishing campaign can be approved" });
  }
  
  return violations;
}

/**
 * Get the complete liability package for an engagement type.
 */
export function getLiabilityPackage(type: EngagementType): {
  clauses: RoeLiabilityClause[];
  insuranceMinimums: { errorsAndOmissions: string; cyberLiability: string; generalLiability: string };
  liabilityCapDefault: string;
  riskLevel: string;
} {
  const template = getEngagementTemplate(type);
  return {
    clauses: template.liabilityClauses,
    insuranceMinimums: template.insuranceMinimums,
    liabilityCapDefault: template.liabilityCapDefault,
    riskLevel: template.riskLevel,
  };
}
