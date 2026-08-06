/**
 * Automated Attack Chain Synthesis Engine
 * 
 * Composes novel multi-step attack chains from:
 * - Utility attack playbook fragments
 * - Actor Genome tradecraft fingerprints
 * - Client environment asset inventory
 * - Discovered vulnerabilities
 * 
 * Produces environment-aware, feasibility-scored kill chains that go beyond
 * replaying known playbooks — it synthesizes NEW chains tailored to specific targets.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ClientEnvironment {
  engagementId: string;
  clientName: string;
  discoveredAssets: DiscoveredAsset[];
  discoveredVulnerabilities: DiscoveredVulnerability[];
  networkTopology: NetworkSegment[];
  securityControls: SecurityControl[];
}

export interface DiscoveredAsset {
  id: string;
  type: "plc" | "hmi" | "scada" | "web_app" | "network_device" | "cloud_service" | "endpoint" | "ad_server" | "iot_device" | "database" | "api_gateway";
  vendor?: string;
  model?: string;
  firmware?: string;
  os?: string;
  ip?: string;
  ports?: number[];
  protocols?: string[];
  segment: string;
  exposureLevel: "internet_facing" | "dmz" | "internal" | "air_gapped";
}

export interface DiscoveredVulnerability {
  id: string;
  cve?: string;
  assetId: string;
  type: "rce" | "auth_bypass" | "privilege_escalation" | "info_disclosure" | "dos" | "injection" | "misconfig" | "default_creds" | "firmware_vuln";
  severity: "critical" | "high" | "medium" | "low";
  exploitAvailable: boolean;
  exploitId?: string;
  validated: boolean;
}

export interface NetworkSegment {
  id: string;
  name: string;
  cidr: string;
  type: "corporate" | "dmz" | "ot_level3" | "ot_level2" | "ot_level1" | "ot_level0" | "cloud" | "remote";
  connectedTo: string[]; // segment IDs
  firewallRules?: string[];
}

export interface SecurityControl {
  type: "firewall" | "ids" | "edr" | "waf" | "nac" | "dlp" | "siem" | "mfa" | "segmentation" | "air_gap";
  vendor?: string;
  coverage: string[]; // segment IDs covered
  bypassDifficulty: "trivial" | "moderate" | "hard" | "very_hard";
}

export interface AttackChainStep {
  stepNumber: number;
  phase: "reconnaissance" | "initial_access" | "execution" | "persistence" | "privilege_escalation" | "defense_evasion" | "credential_access" | "discovery" | "lateral_movement" | "collection" | "command_and_control" | "exfiltration" | "impact";
  technique: string;
  techniqueId: string; // MITRE ATT&CK ID
  targetAsset: string;
  targetSegment: string;
  prerequisiteSteps: number[];
  exploitRequired?: string; // CVE or exploit ID
  tooling: string[];
  description: string;
  expectedOutcome: string;
  detectionRisk: "low" | "medium" | "high" | "very_high";
  securityControlsToEvade: string[];
  alternativeApproaches: string[];
  estimatedDurationMinutes: number;
  rawEvidenceExpected: RawEvidenceSpec[];
}

export interface RawEvidenceSpec {
  type: "pcap" | "screenshot" | "log_entry" | "memory_dump" | "file_artifact" | "api_response" | "register_snapshot" | "config_dump" | "credential" | "token" | "certificate" | "binary" | "network_flow";
  description: string;
  captureMethod: string;
  storageRequirement: "immediate" | "on_success" | "always";
  retentionDays: number;
  forensicValue: "critical" | "high" | "medium" | "low";
}

export interface SynthesizedChain {
  id: string;
  title: string;
  description: string;
  engagementId: string;
  clientName: string;
  synthesizedAt: number;
  
  // Chain composition
  steps: AttackChainStep[];
  totalSteps: number;
  estimatedDurationHours: number;
  
  // Scoring
  feasibilityScore: number; // 0-100: how likely this chain succeeds given discovered vulns
  noveltyScore: number; // 0-100: how different from known playbooks
  completenessScore: number; // 0-100: kill chain phase coverage
  impactScore: number; // 0-100: potential damage if chain succeeds
  compositeScore: number; // weighted combination
  
  // Provenance
  sourcePlaybooks: string[]; // which playbooks contributed fragments
  sourceActors: string[]; // which actor tradecraft patterns were used
  sourceTechniques: string[]; // MITRE ATT&CK IDs used
  
  // Metadata
  targetObjective: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  requiredExploits: string[];
  requiredTools: string[];
  securityControlsChallenged: string[];
  
  // Evidence collection plan
  evidenceCollectionPlan: EvidenceCollectionPlan;
}

export interface EvidenceCollectionPlan {
  totalEvidencePoints: number;
  criticalEvidence: RawEvidenceSpec[];
  perStepEvidence: Record<number, RawEvidenceSpec[]>;
  storageEstimateMB: number;
  chainOfCustodyRequired: boolean;
}

// ─── Kill Chain Phase Definitions ────────────────────────────────────────────

const KILL_CHAIN_PHASES = [
  "reconnaissance",
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
] as const;

// ─── Technique Library (subset for chain synthesis) ──────────────────────────

interface TechniqueTemplate {
  id: string;
  name: string;
  phase: typeof KILL_CHAIN_PHASES[number];
  applicableTo: DiscoveredAsset["type"][];
  prerequisitePhases: (typeof KILL_CHAIN_PHASES[number])[];
  tooling: string[];
  detectionRisk: "low" | "medium" | "high" | "very_high";
  estimatedMinutes: number;
  evidenceGenerated: RawEvidenceSpec[];
}

const TECHNIQUE_LIBRARY: TechniqueTemplate[] = [
  // ─── Initial Access ─────────────────────────────────────────────────────────
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    phase: "initial_access",
    applicableTo: ["web_app", "api_gateway", "scada", "hmi"],
    prerequisitePhases: ["reconnaissance"],
    tooling: ["custom_exploit", "metasploit", "nuclei"],
    detectionRisk: "medium",
    estimatedMinutes: 30,
    evidenceGenerated: [
      { type: "pcap", description: "Network capture of exploitation traffic", captureMethod: "tcpdump on attack interface", storageRequirement: "always", retentionDays: 90, forensicValue: "critical" },
      { type: "screenshot", description: "Successful exploitation confirmation", captureMethod: "automated screenshot", storageRequirement: "on_success", retentionDays: 365, forensicValue: "high" },
      { type: "log_entry", description: "Target application logs showing exploitation", captureMethod: "log forwarding or post-access retrieval", storageRequirement: "on_success", retentionDays: 90, forensicValue: "high" },
    ],
  },
  {
    id: "T1078",
    name: "Valid Accounts (Default Credentials)",
    phase: "initial_access",
    applicableTo: ["plc", "hmi", "scada", "network_device", "iot_device"],
    prerequisitePhases: ["reconnaissance"],
    tooling: ["hydra", "custom_scripts", "medusa"],
    detectionRisk: "low",
    estimatedMinutes: 15,
    evidenceGenerated: [
      { type: "credential", description: "Default credentials confirmed valid", captureMethod: "authentication attempt logging", storageRequirement: "on_success", retentionDays: 365, forensicValue: "critical" },
      { type: "screenshot", description: "Authenticated session screenshot", captureMethod: "automated screenshot", storageRequirement: "on_success", retentionDays: 365, forensicValue: "high" },
      { type: "pcap", description: "Authentication protocol capture", captureMethod: "tcpdump", storageRequirement: "always", retentionDays: 90, forensicValue: "medium" },
    ],
  },
  {
    id: "T1133",
    name: "External Remote Services",
    phase: "initial_access",
    applicableTo: ["endpoint", "ad_server", "network_device", "cloud_service"],
    prerequisitePhases: ["reconnaissance"],
    tooling: ["ssh", "rdp_client", "vpn_tools"],
    detectionRisk: "low",
    estimatedMinutes: 20,
    evidenceGenerated: [
      { type: "log_entry", description: "Remote service authentication log", captureMethod: "session logging", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
      { type: "network_flow", description: "Connection metadata and session duration", captureMethod: "netflow capture", storageRequirement: "always", retentionDays: 30, forensicValue: "medium" },
    ],
  },
  // ─── Execution ──────────────────────────────────────────────────────────────
  {
    id: "T0821",
    name: "Modify Controller Tasking (PLC Logic Upload)",
    phase: "execution",
    applicableTo: ["plc"],
    prerequisitePhases: ["initial_access"],
    tooling: ["codesys", "rslogix", "step7", "custom_modbus"],
    detectionRisk: "medium",
    estimatedMinutes: 45,
    evidenceGenerated: [
      { type: "register_snapshot", description: "PLC register state before and after modification", captureMethod: "Modbus read holding registers", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
      { type: "file_artifact", description: "Original and modified ladder logic files", captureMethod: "PLC program upload/download", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
      { type: "pcap", description: "Industrial protocol traffic during modification", captureMethod: "span port capture", storageRequirement: "always", retentionDays: 90, forensicValue: "critical" },
    ],
  },
  {
    id: "T1059.001",
    name: "PowerShell Execution",
    phase: "execution",
    applicableTo: ["endpoint", "ad_server"],
    prerequisitePhases: ["initial_access"],
    tooling: ["powershell", "powershell_empire", "covenant"],
    detectionRisk: "high",
    estimatedMinutes: 10,
    evidenceGenerated: [
      { type: "log_entry", description: "PowerShell script block logging output", captureMethod: "Windows Event Log 4104", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
      { type: "memory_dump", description: "Process memory at time of execution", captureMethod: "procdump or volatility", storageRequirement: "on_success", retentionDays: 30, forensicValue: "medium" },
    ],
  },
  // ─── Persistence ────────────────────────────────────────────────────────────
  {
    id: "T1053.005",
    name: "Scheduled Task/Job",
    phase: "persistence",
    applicableTo: ["endpoint", "ad_server"],
    prerequisitePhases: ["execution"],
    tooling: ["schtasks", "at", "cron"],
    detectionRisk: "medium",
    estimatedMinutes: 15,
    evidenceGenerated: [
      { type: "config_dump", description: "Scheduled task XML configuration", captureMethod: "schtasks /query /xml", storageRequirement: "on_success", retentionDays: 90, forensicValue: "high" },
      { type: "log_entry", description: "Task creation event log", captureMethod: "Windows Event Log 4698", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
    ],
  },
  {
    id: "T0889",
    name: "Modify Program (Firmware Persistence)",
    phase: "persistence",
    applicableTo: ["plc", "iot_device"],
    prerequisitePhases: ["execution"],
    tooling: ["custom_firmware_tools", "binwalk", "flashrom"],
    detectionRisk: "low",
    estimatedMinutes: 60,
    evidenceGenerated: [
      { type: "binary", description: "Original and modified firmware images", captureMethod: "firmware dump before/after", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
      { type: "file_artifact", description: "Firmware diff showing modifications", captureMethod: "bindiff analysis", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
    ],
  },
  // ─── Privilege Escalation ───────────────────────────────────────────────────
  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    phase: "privilege_escalation",
    applicableTo: ["endpoint", "ad_server", "cloud_service"],
    prerequisitePhases: ["execution"],
    tooling: ["custom_exploit", "metasploit", "potato_family"],
    detectionRisk: "high",
    estimatedMinutes: 30,
    evidenceGenerated: [
      { type: "screenshot", description: "Elevated privilege confirmation (whoami)", captureMethod: "command output capture", storageRequirement: "on_success", retentionDays: 365, forensicValue: "critical" },
      { type: "log_entry", description: "Privilege escalation event trail", captureMethod: "security event log", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
    ],
  },
  {
    id: "T1078.002",
    name: "Domain Account Compromise",
    phase: "privilege_escalation",
    applicableTo: ["ad_server", "endpoint"],
    prerequisitePhases: ["credential_access"],
    tooling: ["mimikatz", "rubeus", "impacket"],
    detectionRisk: "high",
    estimatedMinutes: 20,
    evidenceGenerated: [
      { type: "credential", description: "Compromised domain credentials or hashes", captureMethod: "credential extraction tool output", storageRequirement: "on_success", retentionDays: 365, forensicValue: "critical" },
      { type: "token", description: "Kerberos TGT or service ticket", captureMethod: "ticket extraction", storageRequirement: "on_success", retentionDays: 30, forensicValue: "high" },
    ],
  },
  // ─── Defense Evasion ────────────────────────────────────────────────────────
  {
    id: "T1562.001",
    name: "Disable or Modify Security Tools",
    phase: "defense_evasion",
    applicableTo: ["endpoint", "ad_server"],
    prerequisitePhases: ["privilege_escalation"],
    tooling: ["custom_scripts", "service_manipulation"],
    detectionRisk: "very_high",
    estimatedMinutes: 15,
    evidenceGenerated: [
      { type: "log_entry", description: "Security tool state change evidence", captureMethod: "service status before/after", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
      { type: "screenshot", description: "Disabled security tool confirmation", captureMethod: "automated screenshot", storageRequirement: "on_success", retentionDays: 90, forensicValue: "medium" },
    ],
  },
  // ─── Credential Access ──────────────────────────────────────────────────────
  {
    id: "T1003.001",
    name: "LSASS Memory Dump",
    phase: "credential_access",
    applicableTo: ["endpoint", "ad_server"],
    prerequisitePhases: ["privilege_escalation"],
    tooling: ["mimikatz", "procdump", "comsvcs.dll"],
    detectionRisk: "very_high",
    estimatedMinutes: 10,
    evidenceGenerated: [
      { type: "memory_dump", description: "LSASS process memory dump", captureMethod: "procdump -ma lsass.exe", storageRequirement: "on_success", retentionDays: 7, forensicValue: "critical" },
      { type: "credential", description: "Extracted credentials from memory", captureMethod: "mimikatz sekurlsa::logonpasswords", storageRequirement: "on_success", retentionDays: 365, forensicValue: "critical" },
    ],
  },
  {
    id: "T1552.001",
    name: "Credentials in Files",
    phase: "credential_access",
    applicableTo: ["endpoint", "web_app", "cloud_service", "database"],
    prerequisitePhases: ["execution", "discovery"],
    tooling: ["grep", "trufflehog", "custom_scripts"],
    detectionRisk: "low",
    estimatedMinutes: 20,
    evidenceGenerated: [
      { type: "file_artifact", description: "Files containing credentials", captureMethod: "file copy with path metadata", storageRequirement: "on_success", retentionDays: 365, forensicValue: "high" },
      { type: "credential", description: "Extracted credentials with context", captureMethod: "automated extraction", storageRequirement: "on_success", retentionDays: 365, forensicValue: "critical" },
    ],
  },
  // ─── Lateral Movement ───────────────────────────────────────────────────────
  {
    id: "T1021.002",
    name: "SMB/Windows Admin Shares",
    phase: "lateral_movement",
    applicableTo: ["endpoint", "ad_server"],
    prerequisitePhases: ["credential_access"],
    tooling: ["psexec", "smbclient", "impacket"],
    detectionRisk: "medium",
    estimatedMinutes: 15,
    evidenceGenerated: [
      { type: "network_flow", description: "SMB session metadata and file transfers", captureMethod: "netflow + pcap", storageRequirement: "always", retentionDays: 30, forensicValue: "high" },
      { type: "log_entry", description: "Logon event on target system", captureMethod: "Windows Event Log 4624", storageRequirement: "on_success", retentionDays: 90, forensicValue: "high" },
    ],
  },
  {
    id: "T1053.005-lateral",
    name: "Scheduled Task Lateral Movement (atexec)",
    phase: "lateral_movement",
    applicableTo: ["endpoint", "ad_server"],
    prerequisitePhases: ["credential_access"],
    tooling: ["impacket-atexec", "atexec.py"],
    detectionRisk: "medium",
    estimatedMinutes: 10,
    evidenceGenerated: [
      { type: "log_entry", description: "Task Scheduler create/delete events (4698/4699)", captureMethod: "Windows Event Log 4698+4699", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
      { type: "network_flow", description: "ATSVC named pipe binding over SMB (port 445)", captureMethod: "pcap on port 445", storageRequirement: "always", retentionDays: 30, forensicValue: "high" },
      { type: "file_artifact", description: "Temp output file on ADMIN$ share", captureMethod: "SMB file audit (Event 5145)", storageRequirement: "on_success", retentionDays: 30, forensicValue: "medium" },
    ],
  },
  {
    id: "T0886",
    name: "Remote Services (OT Lateral Movement)",
    phase: "lateral_movement",
    applicableTo: ["plc", "hmi", "scada"],
    prerequisitePhases: ["credential_access", "discovery"],
    tooling: ["engineering_workstation", "modbus_client", "ethernet_ip_tools"],
    detectionRisk: "low",
    estimatedMinutes: 25,
    evidenceGenerated: [
      { type: "pcap", description: "OT protocol lateral movement traffic", captureMethod: "span port on OT switch", storageRequirement: "always", retentionDays: 90, forensicValue: "critical" },
      { type: "register_snapshot", description: "Target PLC state upon initial access", captureMethod: "Modbus function code 3/4 read", storageRequirement: "always", retentionDays: 365, forensicValue: "high" },
    ],
  },
  // ─── Collection ─────────────────────────────────────────────────────────────
  {
    id: "T1005",
    name: "Data from Local System",
    phase: "collection",
    applicableTo: ["endpoint", "ad_server", "database", "web_app"],
    prerequisitePhases: ["lateral_movement"],
    tooling: ["custom_scripts", "7zip", "robocopy"],
    detectionRisk: "medium",
    estimatedMinutes: 30,
    evidenceGenerated: [
      { type: "file_artifact", description: "Collected sensitive files with metadata", captureMethod: "staged collection with hashing", storageRequirement: "on_success", retentionDays: 30, forensicValue: "high" },
      { type: "log_entry", description: "File access audit trail", captureMethod: "Windows Event Log 4663", storageRequirement: "always", retentionDays: 90, forensicValue: "medium" },
    ],
  },
  // ─── Command & Control ──────────────────────────────────────────────────────
  {
    id: "T1071.001",
    name: "Web Protocols (HTTPS C2)",
    phase: "command_and_control",
    applicableTo: ["endpoint", "ad_server", "web_app"],
    prerequisitePhases: ["execution"],
    tooling: ["cobalt_strike", "sliver", "mythic", "covenant"],
    detectionRisk: "medium",
    estimatedMinutes: 20,
    evidenceGenerated: [
      { type: "pcap", description: "C2 beacon traffic capture", captureMethod: "tcpdump with TLS metadata", storageRequirement: "always", retentionDays: 30, forensicValue: "high" },
      { type: "network_flow", description: "C2 communication pattern and timing", captureMethod: "netflow analysis", storageRequirement: "always", retentionDays: 30, forensicValue: "medium" },
      { type: "certificate", description: "C2 server TLS certificate", captureMethod: "openssl s_client capture", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
    ],
  },
  // ─── Impact ─────────────────────────────────────────────────────────────────
  {
    id: "T0831",
    name: "Manipulation of Control (Process Disruption)",
    phase: "impact",
    applicableTo: ["plc", "hmi", "scada"],
    prerequisitePhases: ["execution", "lateral_movement"],
    tooling: ["custom_modbus", "engineering_software", "custom_scripts"],
    detectionRisk: "high",
    estimatedMinutes: 30,
    evidenceGenerated: [
      { type: "register_snapshot", description: "PLC register state showing manipulated values", captureMethod: "Modbus read before/during/after", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
      { type: "screenshot", description: "HMI showing abnormal process state", captureMethod: "HMI screenshot capture", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
      { type: "pcap", description: "Full packet capture during manipulation", captureMethod: "span port capture", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
      { type: "log_entry", description: "SCADA alarm logs triggered by manipulation", captureMethod: "SCADA historian export", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
    ],
  },
  {
    id: "T1486",
    name: "Data Encrypted for Impact (Ransomware)",
    phase: "impact",
    applicableTo: ["endpoint", "ad_server", "database"],
    prerequisitePhases: ["privilege_escalation", "lateral_movement"],
    tooling: ["custom_ransomware_sim", "encryption_tools"],
    detectionRisk: "very_high",
    estimatedMinutes: 15,
    evidenceGenerated: [
      { type: "file_artifact", description: "Encrypted file samples with ransom note", captureMethod: "file system snapshot", storageRequirement: "always", retentionDays: 365, forensicValue: "critical" },
      { type: "log_entry", description: "Mass file modification events", captureMethod: "file integrity monitoring", storageRequirement: "always", retentionDays: 90, forensicValue: "high" },
    ],
  },
];

// ─── Chain Synthesis Engine ──────────────────────────────────────────────────

export interface SynthesisOptions {
  targetObjective: "data_exfiltration" | "process_disruption" | "ransomware" | "espionage" | "sabotage" | "credential_harvest" | "supply_chain_compromise";
  maxSteps?: number;
  preferredActorStyle?: string; // actor ID to emulate
  avoidDetection?: boolean; // prioritize stealth
  includeAlternatives?: boolean;
  evidenceComprehensiveness?: "minimal" | "standard" | "forensic_grade";
}

/**
 * Synthesize a novel attack chain for a specific client environment
 */
export function synthesizeAttackChain(
  environment: ClientEnvironment,
  options: SynthesisOptions
): SynthesizedChain {
  const startTime = Date.now();
  const maxSteps = options.maxSteps || 12;
  const evidenceLevel = options.evidenceComprehensiveness || "standard";
  
  // Step 1: Identify viable initial access vectors
  const initialAccessVectors = findInitialAccessVectors(environment);
  
  // Step 2: Map lateral movement paths through network topology
  const movementPaths = mapLateralMovementPaths(environment);
  
  // Step 3: Identify high-value targets for the objective
  const highValueTargets = identifyHighValueTargets(environment, options.targetObjective);
  
  // Step 4: Compose the chain from entry to objective
  const steps = composeChain(
    initialAccessVectors,
    movementPaths,
    highValueTargets,
    environment,
    options,
    maxSteps
  );
  
  // Step 5: Score the chain
  const feasibilityScore = computeFeasibility(steps, environment);
  const noveltyScore = computeNovelty(steps);
  const completenessScore = computeCompleteness(steps);
  const impactScore = computeImpact(steps, options.targetObjective);
  
  // Step 6: Build evidence collection plan
  const evidenceCollectionPlan = buildEvidenceCollectionPlan(steps, evidenceLevel);
  
  // Step 7: Compute composite score
  const compositeScore = Math.round(
    feasibilityScore * 0.35 +
    noveltyScore * 0.15 +
    completenessScore * 0.25 +
    impactScore * 0.25
  );
  
  const chain: SynthesizedChain = {
    id: `chain_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    title: generateChainTitle(steps, options.targetObjective),
    description: generateChainDescription(steps, environment, options),
    engagementId: environment.engagementId,
    clientName: environment.clientName,
    synthesizedAt: startTime,
    steps,
    totalSteps: steps.length,
    estimatedDurationHours: steps.reduce((sum, s) => sum + s.estimatedDurationMinutes, 0) / 60,
    feasibilityScore,
    noveltyScore,
    completenessScore,
    impactScore,
    compositeScore,
    sourcePlaybooks: identifySourcePlaybooks(steps),
    sourceActors: options.preferredActorStyle ? [options.preferredActorStyle] : identifySourceActors(steps),
    sourceTechniques: steps.map(s => s.techniqueId),
    targetObjective: options.targetObjective,
    riskLevel: compositeScore >= 80 ? "critical" : compositeScore >= 60 ? "high" : compositeScore >= 40 ? "medium" : "low",
    requiredExploits: steps.filter(s => s.exploitRequired).map(s => s.exploitRequired!),
    requiredTools: [...new Set(steps.flatMap(s => s.tooling))],
    securityControlsChallenged: [...new Set(steps.flatMap(s => s.securityControlsToEvade))],
    evidenceCollectionPlan,
  };
  
  return chain;
}

/**
 * Generate multiple chain variants for comparison
 */
export function synthesizeChainVariants(
  environment: ClientEnvironment,
  options: SynthesisOptions,
  variantCount: number = 3
): SynthesizedChain[] {
  const variants: SynthesizedChain[] = [];
  
  // Variant 1: Stealth-optimized
  variants.push(synthesizeAttackChain(environment, { ...options, avoidDetection: true }));
  
  // Variant 2: Speed-optimized (fewer steps)
  variants.push(synthesizeAttackChain(environment, { ...options, maxSteps: 6 }));
  
  // Variant 3: Maximum impact
  if (variantCount >= 3) {
    variants.push(synthesizeAttackChain(environment, { ...options, maxSteps: 15, avoidDetection: false }));
  }
  
  return variants.sort((a, b) => b.compositeScore - a.compositeScore);
}

// ─── Internal Functions ──────────────────────────────────────────────────────

function findInitialAccessVectors(env: ClientEnvironment): TechniqueTemplate[] {
  const internetFacing = env.discoveredAssets.filter(a => a.exposureLevel === "internet_facing" || a.exposureLevel === "dmz");
  const vulnsOnExposed = env.discoveredVulnerabilities.filter(v => {
    const asset = internetFacing.find(a => a.id === v.assetId);
    return asset && (v.type === "rce" || v.type === "auth_bypass" || v.type === "default_creds");
  });
  
  const applicableTechniques = TECHNIQUE_LIBRARY.filter(t => {
    if (t.phase !== "initial_access") return false;
    return internetFacing.some(a => t.applicableTo.includes(a.type));
  });
  
  // Prioritize techniques that have matching vulnerabilities
  return applicableTechniques.sort((a, b) => {
    const aHasVuln = vulnsOnExposed.some(v => {
      const asset = internetFacing.find(x => x.id === v.assetId);
      return asset && a.applicableTo.includes(asset.type);
    });
    const bHasVuln = vulnsOnExposed.some(v => {
      const asset = internetFacing.find(x => x.id === v.assetId);
      return asset && b.applicableTo.includes(asset.type);
    });
    if (aHasVuln && !bHasVuln) return -1;
    if (!aHasVuln && bHasVuln) return 1;
    return 0;
  });
}

function mapLateralMovementPaths(env: ClientEnvironment): Map<string, string[]> {
  const paths = new Map<string, string[]>();
  
  for (const segment of env.networkTopology) {
    const reachable: string[] = [];
    const visited = new Set<string>();
    const queue = [segment.id];
    
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);
      reachable.push(current);
      
      const seg = env.networkTopology.find(s => s.id === current);
      if (seg) {
        for (const connected of seg.connectedTo) {
          if (!visited.has(connected)) queue.push(connected);
        }
      }
    }
    
    paths.set(segment.id, reachable);
  }
  
  return paths;
}

function identifyHighValueTargets(env: ClientEnvironment, objective: string): DiscoveredAsset[] {
  switch (objective) {
    case "process_disruption":
    case "sabotage":
      return env.discoveredAssets.filter(a => ["plc", "hmi", "scada"].includes(a.type));
    case "data_exfiltration":
    case "espionage":
      return env.discoveredAssets.filter(a => ["database", "ad_server", "cloud_service", "endpoint"].includes(a.type));
    case "ransomware":
      return env.discoveredAssets.filter(a => ["ad_server", "endpoint", "database"].includes(a.type));
    case "credential_harvest":
      return env.discoveredAssets.filter(a => ["ad_server", "endpoint", "cloud_service"].includes(a.type));
    case "supply_chain_compromise":
      return env.discoveredAssets.filter(a => ["web_app", "api_gateway", "cloud_service"].includes(a.type));
    default:
      return env.discoveredAssets;
  }
}

function composeChain(
  initialAccess: TechniqueTemplate[],
  movementPaths: Map<string, string[]>,
  targets: DiscoveredAsset[],
  env: ClientEnvironment,
  options: SynthesisOptions,
  maxSteps: number
): AttackChainStep[] {
  const steps: AttackChainStep[] = [];
  let stepNumber = 1;
  
  // Select best initial access
  const entryTechnique = initialAccess[0] || TECHNIQUE_LIBRARY.find(t => t.phase === "initial_access")!;
  const entryAsset = env.discoveredAssets.find(a => 
    (a.exposureLevel === "internet_facing" || a.exposureLevel === "dmz") &&
    entryTechnique.applicableTo.includes(a.type)
  ) || env.discoveredAssets[0];
  
  // Step 1: Initial Access
  steps.push(createStep(stepNumber++, entryTechnique, entryAsset, env, []));
  
  // Step 2: Execution
  const execTechniques = TECHNIQUE_LIBRARY.filter(t => 
    t.phase === "execution" && t.applicableTo.includes(entryAsset.type)
  );
  if (execTechniques.length > 0 && stepNumber <= maxSteps) {
    steps.push(createStep(stepNumber++, execTechniques[0], entryAsset, env, [1]));
  }
  
  // Step 3: Persistence (if stealth mode)
  if (options.avoidDetection !== false && stepNumber <= maxSteps) {
    const persistTechniques = TECHNIQUE_LIBRARY.filter(t => 
      t.phase === "persistence" && t.applicableTo.includes(entryAsset.type)
    );
    if (persistTechniques.length > 0) {
      steps.push(createStep(stepNumber++, persistTechniques[0], entryAsset, env, [stepNumber - 2]));
    }
  }
  
  // Step 4: Privilege Escalation
  if (stepNumber <= maxSteps) {
    const privescTechniques = TECHNIQUE_LIBRARY.filter(t => 
      t.phase === "privilege_escalation" && t.applicableTo.includes(entryAsset.type)
    );
    if (privescTechniques.length > 0) {
      steps.push(createStep(stepNumber++, privescTechniques[0], entryAsset, env, [stepNumber - 2]));
    }
  }
  
  // Step 5: Credential Access
  if (stepNumber <= maxSteps) {
    const credTechniques = TECHNIQUE_LIBRARY.filter(t => 
      t.phase === "credential_access" && t.applicableTo.includes(entryAsset.type)
    );
    if (credTechniques.length > 0) {
      steps.push(createStep(stepNumber++, credTechniques[0], entryAsset, env, [stepNumber - 2]));
    }
  }
  
  // Step 6+: Lateral Movement to target
  // EDR-aware selection: prefer atexec (T1053.005-lateral) over psexec/SMB (T1021.002)
  // when EDR is present, as atexec has a lower detection profile — it uses the Task Scheduler
  // service (ATSVC) which generates less telemetry than service creation (psexec) or WMI.
  if (targets.length > 0 && stepNumber <= maxSteps) {
    const target = targets[0];
    const latMoveTechniques = TECHNIQUE_LIBRARY.filter(t => 
      t.phase === "lateral_movement" && t.applicableTo.includes(target.type)
    );
    if (latMoveTechniques.length > 0) {
      const hasEDR = env.securityControls.some(c => c.type === "edr");
      const hasSIEM = env.securityControls.some(c => c.type === "siem");
      const hasIDS = env.securityControls.some(c => c.type === "ids");
      
      // Scoring: rank lateral movement techniques based on environment controls
      const scored = latMoveTechniques.map(t => {
        let score = 0;
        // atexec preferred when EDR is present (lower process-creation footprint)
        if (t.id === "T1053.005-lateral") {
          if (hasEDR) score += 30; // strong preference when EDR monitors service creation
          if (hasSIEM) score += 10; // fewer log artifacts than psexec
          score += 5; // slight baseline preference for speed (10 min vs 15 min)
        }
        // SMB/Admin Shares (psexec) penalized when EDR present
        if (t.id === "T1021.002") {
          if (hasEDR) score -= 20; // psexec service creation is heavily signatured
          if (!hasEDR && !hasSIEM) score += 15; // preferred in unmonitored environments
        }
        // OT lateral movement preferred for OT targets regardless of controls
        if (t.id === "T0886") {
          score += 10; // OT-specific, always relevant for OT targets
        }
        // General penalty for high detection risk in monitored environments
        if (t.detectionRisk === "high" && (hasEDR || hasIDS)) score -= 15;
        if (t.detectionRisk === "low" && (hasEDR || hasIDS)) score += 10;
        
        return { technique: t, score };
      });
      
      // Sort by score descending, pick highest
      scored.sort((a, b) => b.score - a.score);
      const selectedTechnique = scored[0].technique;
      
      steps.push(createStep(stepNumber++, selectedTechnique, target, env, [stepNumber - 2]));
    }
  }
  
  // Step 7: Defense Evasion (if needed)
  if (options.avoidDetection && stepNumber <= maxSteps) {
    const evasionTechniques = TECHNIQUE_LIBRARY.filter(t => t.phase === "defense_evasion");
    if (evasionTechniques.length > 0) {
      const evasionTarget = env.discoveredAssets.find(a => 
        evasionTechniques[0].applicableTo.includes(a.type)
      ) || entryAsset;
      steps.push(createStep(stepNumber++, evasionTechniques[0], evasionTarget, env, [stepNumber - 2]));
    }
  }
  
  // Step 8: C2 establishment
  if (stepNumber <= maxSteps) {
    const c2Techniques = TECHNIQUE_LIBRARY.filter(t => t.phase === "command_and_control");
    if (c2Techniques.length > 0) {
      const c2Target = env.discoveredAssets.find(a => 
        c2Techniques[0].applicableTo.includes(a.type)
      ) || entryAsset;
      steps.push(createStep(stepNumber++, c2Techniques[0], c2Target, env, [2]));
    }
  }
  
  // Final Step: Impact/Objective
  if (stepNumber <= maxSteps) {
    const impactTechniques = TECHNIQUE_LIBRARY.filter(t => {
      if (t.phase !== "impact") return false;
      if (options.targetObjective === "process_disruption" || options.targetObjective === "sabotage") {
        return t.id === "T0831";
      }
      if (options.targetObjective === "ransomware") {
        return t.id === "T1486";
      }
      return true;
    });
    if (impactTechniques.length > 0) {
      const impactTarget = targets[0] || entryAsset;
      steps.push(createStep(stepNumber++, impactTechniques[0], impactTarget, env, [stepNumber - 2]));
    }
  }
  
  return steps;
}

function createStep(
  stepNumber: number,
  technique: TechniqueTemplate,
  targetAsset: DiscoveredAsset,
  env: ClientEnvironment,
  prerequisites: number[]
): AttackChainStep {
  const controlsToEvade = env.securityControls
    .filter(c => c.coverage.includes(targetAsset.segment))
    .map(c => `${c.type}${c.vendor ? ` (${c.vendor})` : ""}`);
  
  const matchingVuln = env.discoveredVulnerabilities.find(v => v.assetId === targetAsset.id);
  
  return {
    stepNumber,
    phase: technique.phase,
    technique: technique.name,
    techniqueId: technique.id,
    targetAsset: targetAsset.id,
    targetSegment: targetAsset.segment,
    prerequisiteSteps: prerequisites,
    exploitRequired: matchingVuln?.cve || matchingVuln?.exploitId,
    tooling: technique.tooling,
    description: `Execute ${technique.name} against ${targetAsset.type} (${targetAsset.vendor || "unknown"}) in ${targetAsset.segment} segment`,
    expectedOutcome: `Successful ${technique.phase} on ${targetAsset.id}`,
    detectionRisk: technique.detectionRisk,
    securityControlsToEvade: controlsToEvade,
    alternativeApproaches: TECHNIQUE_LIBRARY
      .filter(t => t.phase === technique.phase && t.id !== technique.id && t.applicableTo.includes(targetAsset.type))
      .slice(0, 2)
      .map(t => t.name),
    estimatedDurationMinutes: technique.estimatedMinutes,
    rawEvidenceExpected: technique.evidenceGenerated,
  };
}

function buildEvidenceCollectionPlan(steps: AttackChainStep[], level: string): EvidenceCollectionPlan {
  const perStepEvidence: Record<number, RawEvidenceSpec[]> = {};
  let criticalEvidence: RawEvidenceSpec[] = [];
  let totalPoints = 0;
  let storageMB = 0;
  
  for (const step of steps) {
    let evidence = step.rawEvidenceExpected;
    
    // Filter based on comprehensiveness level
    if (level === "minimal") {
      evidence = evidence.filter(e => e.forensicValue === "critical");
    } else if (level === "standard") {
      evidence = evidence.filter(e => e.forensicValue === "critical" || e.forensicValue === "high");
    }
    // "forensic_grade" keeps all evidence
    
    perStepEvidence[step.stepNumber] = evidence;
    totalPoints += evidence.length;
    
    // Estimate storage
    for (const e of evidence) {
      switch (e.type) {
        case "pcap": storageMB += 50; break;
        case "memory_dump": storageMB += 200; break;
        case "binary": storageMB += 100; break;
        case "screenshot": storageMB += 2; break;
        case "log_entry": storageMB += 1; break;
        case "config_dump": storageMB += 1; break;
        case "register_snapshot": storageMB += 0.5; break;
        case "credential": storageMB += 0.1; break;
        case "token": storageMB += 0.1; break;
        case "certificate": storageMB += 0.1; break;
        case "file_artifact": storageMB += 10; break;
        case "network_flow": storageMB += 5; break;
        case "api_response": storageMB += 1; break;
      }
    }
    
    criticalEvidence.push(...evidence.filter(e => e.forensicValue === "critical"));
  }
  
  return {
    totalEvidencePoints: totalPoints,
    criticalEvidence,
    perStepEvidence,
    storageEstimateMB: Math.round(storageMB),
    chainOfCustodyRequired: level === "forensic_grade",
  };
}

// ─── Scoring Functions ───────────────────────────────────────────────────────

function computeFeasibility(steps: AttackChainStep[], env: ClientEnvironment): number {
  let score = 100;
  
  for (const step of steps) {
    // Deduct for missing exploits
    if (step.exploitRequired) {
      const vuln = env.discoveredVulnerabilities.find(v => v.cve === step.exploitRequired || v.exploitId === step.exploitRequired);
      if (!vuln?.exploitAvailable) score -= 15;
      if (!vuln?.validated) score -= 5;
    }
    
    // Deduct for security controls
    score -= step.securityControlsToEvade.length * 5;
    
    // Deduct for high detection risk
    if (step.detectionRisk === "very_high") score -= 10;
    else if (step.detectionRisk === "high") score -= 5;
  }
  
  return Math.max(0, Math.min(100, score));
}

function computeNovelty(steps: AttackChainStep[]): number {
  // Score based on technique diversity and non-standard combinations
  const uniquePhases = new Set(steps.map(s => s.phase)).size;
  const uniqueTechniques = new Set(steps.map(s => s.techniqueId)).size;
  const phaseRatio = uniquePhases / KILL_CHAIN_PHASES.length;
  const techniqueRatio = Math.min(1, uniqueTechniques / 8);
  
  // Bonus for cross-domain techniques (IT + OT)
  const hasIT = steps.some(s => ["T1059.001", "T1003.001", "T1021.002"].includes(s.techniqueId));
  const hasOT = steps.some(s => ["T0821", "T0831", "T0886", "T0889"].includes(s.techniqueId));
  const crossDomainBonus = (hasIT && hasOT) ? 20 : 0;
  
  return Math.min(100, Math.round((phaseRatio * 40) + (techniqueRatio * 40) + crossDomainBonus));
}

function computeCompleteness(steps: AttackChainStep[]): number {
  const coveredPhases = new Set(steps.map(s => s.phase));
  const criticalPhases = ["initial_access", "execution", "privilege_escalation", "lateral_movement", "impact"];
  const criticalCoverage = criticalPhases.filter(p => coveredPhases.has(p as any)).length / criticalPhases.length;
  const totalCoverage = coveredPhases.size / KILL_CHAIN_PHASES.length;
  
  return Math.round(criticalCoverage * 70 + totalCoverage * 30);
}

function computeImpact(steps: AttackChainStep[], objective: string): number {
  const hasImpactStep = steps.some(s => s.phase === "impact");
  const hasPrivEsc = steps.some(s => s.phase === "privilege_escalation");
  const hasLatMove = steps.some(s => s.phase === "lateral_movement");
  
  let score = 30; // base
  if (hasImpactStep) score += 40;
  if (hasPrivEsc) score += 15;
  if (hasLatMove) score += 15;
  
  // Bonus for OT impact objectives
  if ((objective === "process_disruption" || objective === "sabotage") && 
      steps.some(s => s.techniqueId === "T0831")) {
    score += 10;
  }
  
  return Math.min(100, score);
}

function generateChainTitle(steps: AttackChainStep[], objective: string): string {
  const entryMethod = steps[0]?.technique || "Unknown Entry";
  const targetType = steps[steps.length - 1]?.targetAsset || "Unknown Target";
  const objectiveLabel = objective.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());
  return `${objectiveLabel} via ${entryMethod} → ${targetType}`;
}

function generateChainDescription(steps: AttackChainStep[], env: ClientEnvironment, options: SynthesisOptions): string {
  return `Synthesized ${steps.length}-step attack chain targeting ${env.clientName} infrastructure. ` +
    `Objective: ${options.targetObjective.replace(/_/g, " ")}. ` +
    `Entry via ${steps[0]?.technique || "unknown"}, ` +
    `traversing ${new Set(steps.map(s => s.targetSegment)).size} network segments, ` +
    `with ${steps.filter(s => s.detectionRisk === "low").length}/${steps.length} steps at low detection risk.`;
}

function identifySourcePlaybooks(steps: AttackChainStep[]): string[] {
  const playbooks: string[] = [];
  const hasOT = steps.some(s => ["T0821", "T0831", "T0886", "T0889"].includes(s.techniqueId));
  const hasRansomware = steps.some(s => s.techniqueId === "T1486");
  const hasCredDump = steps.some(s => s.techniqueId === "T1003.001");
  
  if (hasOT) playbooks.push("cyberav3ngers_water_treatment", "sandworm_electric_grid");
  if (hasRansomware) playbooks.push("ransomware_double_extortion");
  if (hasCredDump) playbooks.push("apt29_credential_harvest");
  if (steps.some(s => s.techniqueId === "T1133")) playbooks.push("volt_typhoon_lotl");
  
  return playbooks.length > 0 ? playbooks : ["custom_synthesis"];
}

function identifySourceActors(steps: AttackChainStep[]): string[] {
  const actors: string[] = [];
  const hasOT = steps.some(s => ["T0821", "T0831"].includes(s.techniqueId));
  const hasLOTL = steps.some(s => s.techniqueId === "T1133");
  const hasSafety = steps.some(s => s.techniqueId === "T0889");
  
  if (hasOT) actors.push("cyberav3ngers");
  if (hasLOTL) actors.push("volt_typhoon");
  if (hasSafety) actors.push("xenotime");
  if (steps.some(s => s.techniqueId === "T1486")) actors.push("sandworm");
  
  return actors.length > 0 ? actors : ["novel_composition"];
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export function getAvailableTechniques(): TechniqueTemplate[] {
  return TECHNIQUE_LIBRARY;
}

export function getTechniquesByPhase(phase: string): TechniqueTemplate[] {
  return TECHNIQUE_LIBRARY.filter(t => t.phase === phase);
}

export function getKillChainPhases(): readonly string[] {
  return KILL_CHAIN_PHASES;
}
