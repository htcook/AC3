// APT Scenario Library - Data from mega-redteam-bundle
// Government Red Team Expansion Pack

export interface TechniqueEntry {
  id: string;
  name: string;
  tactic: string;
  score: number;
  description: string;
}

export interface CalderaProfile {
  id: string;
  name: string;
  atomicOrdering: string[];
}

export interface APTScenario {
  id: string;
  name: string;
  alias: string;
  origin: string;
  description: string;
  objective: string;
  color: string;
  borderColor: string;
  techniques: TechniqueEntry[];
  calderaProfile?: CalderaProfile;
  stixCampaignId?: string;
}

export const APT_SCENARIOS: APTScenario[] = [
  {
    id: "apt29",
    name: "APT29",
    alias: "Cozy Bear / The Dukes",
    origin: "Russia (SVR)",
    description: "APT29 is a sophisticated threat group attributed to Russian intelligence services. Known for long-dwell credential access operations targeting government networks, diplomatic institutions, and policy think tanks.",
    objective: "Credential Access & Dwell — Establish persistent access through valid credentials, move laterally, and exfiltrate sensitive data while maintaining stealth.",
    color: "text-red-500",
    borderColor: "border-red-500/30",
    techniques: [
      { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", score: 3, description: "Targeted phishing emails with malicious links to credential harvesting pages or exploit kits." },
      { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion / Persistence", score: 3, description: "Use of compromised legitimate credentials to maintain access and blend with normal traffic." },
      { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", score: 3, description: "Extraction of credentials from OS memory, registry, or domain controllers (LSASS, SAM, NTDS)." },
      { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", score: 3, description: "Use of legitimate remote services (RDP, SSH, SMB) to move between systems." },
      { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", score: 3, description: "Data exfiltration using the existing command and control communication channel." },
    ],
    calderaProfile: {
      id: "gov-apt29-001",
      name: "Government APT29 Simulation",
      atomicOrdering: ["phish_link_click", "valid_account_sim", "credential_dump_sim", "lateral_movement_sim", "exfil_sim"],
    },
    stixCampaignId: "campaign--apt29-sim",
  },
  {
    id: "apt28",
    name: "APT28",
    alias: "Fancy Bear / Sofacy",
    origin: "Russia (GRU)",
    description: "APT28 is a threat group attributed to Russia's GRU military intelligence. Known for rapid exploitation campaigns targeting government, military, and media organizations with zero-day exploits and aggressive lateral movement.",
    objective: "Rapid Exploitation — Quickly exploit vulnerabilities, establish foothold, and evade defenses before detection.",
    color: "text-orange-500",
    borderColor: "border-orange-500/30",
    techniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", score: 3, description: "Weaponized document attachments exploiting Office vulnerabilities or macros." },
      { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation", score: 3, description: "Exploitation of software vulnerabilities (including zero-days) to gain elevated privileges." },
      { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion", score: 3, description: "Disabling or modifying security tools, logging, and monitoring to avoid detection." },
    ],
    calderaProfile: undefined,
    stixCampaignId: undefined,
  },
  {
    id: "sandworm",
    name: "Sandworm",
    alias: "Voodoo Bear / IRIDIUM",
    origin: "Russia (GRU Unit 74455)",
    description: "Sandworm is a destructive threat group attributed to Russia's GRU Unit 74455. Responsible for NotPetya, Olympic Destroyer, and attacks on Ukrainian infrastructure. Focuses on destructive operations and critical infrastructure disruption.",
    objective: "Destructive Modeling — Simulate ransomware/wiper deployment to test organizational resilience against destructive attacks.",
    color: "text-purple-500",
    borderColor: "border-purple-500/30",
    techniques: [
      { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", score: 3, description: "Phishing campaigns with links to exploit kits or credential harvesting infrastructure." },
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", score: 3, description: "Encryption of data on target systems to simulate ransomware/wiper impact scenarios." },
    ],
    calderaProfile: {
      id: "gov-sandworm-001",
      name: "Government Sandworm Simulation",
      atomicOrdering: ["phish_link_click", "privilege_escalation_sim", "encryption_marker_sim"],
    },
    stixCampaignId: undefined,
  },
  {
    id: "apt41",
    name: "APT41-style",
    alias: "Double Dragon / Winnti",
    origin: "China (Hybrid State/Criminal)",
    description: "APT41-style operations represent a hybrid threat model combining state-sponsored espionage with financially motivated cybercrime. Targets span government, healthcare, telecom, and technology sectors across multiple countries.",
    objective: "Hybrid Espionage & Data Theft — Combine espionage tradecraft with data theft for both intelligence and financial gain.",
    color: "text-yellow-500",
    borderColor: "border-yellow-500/30",
    techniques: [
      { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", score: 3, description: "Targeted phishing with links to watering holes or credential harvesting pages." },
      { id: "T1005", name: "Data from Local System", tactic: "Collection", score: 3, description: "Collection of sensitive data from local file systems, databases, and application stores." },
      { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", score: 3, description: "Exfiltration of collected data through the command and control infrastructure." },
    ],
    calderaProfile: undefined,
    stixCampaignId: undefined,
  },
];

// ATT&CK Navigator layer data for heatmap rendering
export const NAVIGATOR_LAYERS = {
  apt29: {
    version: "4.3",
    name: "APT29 Government Simulation",
    domain: "enterprise-attack",
    techniques: [
      { techniqueID: "T1566.002", score: 3 },
      { techniqueID: "T1078", score: 3 },
      { techniqueID: "T1003", score: 3 },
      { techniqueID: "T1021", score: 3 },
      { techniqueID: "T1041", score: 3 },
    ],
  },
  apt28: {
    version: "4.3",
    name: "APT28 Government Simulation",
    domain: "enterprise-attack",
    techniques: [
      { techniqueID: "T1566.001", score: 3 },
      { techniqueID: "T1068", score: 3 },
      { techniqueID: "T1562", score: 3 },
    ],
  },
  sandworm: {
    version: "4.3",
    name: "Sandworm Government Simulation",
    domain: "enterprise-attack",
    techniques: [
      { techniqueID: "T1566.002", score: 3 },
      { techniqueID: "T1486", score: 3 },
    ],
  },
  apt41: {
    version: "4.3",
    name: "APT41-style Government Simulation",
    domain: "enterprise-attack",
    techniques: [
      { techniqueID: "T1566.002", score: 3 },
      { techniqueID: "T1005", score: 3 },
      { techniqueID: "T1041", score: 3 },
    ],
  },
};

// STIX 2.1 Bundle objects
export const STIX_BUNDLE = {
  type: "bundle" as const,
  id: "bundle--gov-redteam-001",
  objects: [
    {
      type: "identity",
      id: "identity--gov-client",
      name: "Government Client (Red Team Engagement)",
      identityClass: "organization",
    },
    {
      type: "campaign",
      id: "campaign--apt29-sim",
      name: "APT29 Government Simulation Campaign",
      description: "Simulated credential access and stealth persistence modeling.",
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--T1566-002",
      name: "Spearphishing Link",
      externalReferences: [{ sourceName: "mitre-attack", externalId: "T1566.002" }],
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--T1486",
      name: "Data Encrypted for Impact",
      externalReferences: [{ sourceName: "mitre-attack", externalId: "T1486" }],
    },
  ],
};
