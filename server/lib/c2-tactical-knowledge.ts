/**
 * C2 Tactical Knowledge Base
 *
 * Comprehensive operational knowledge for all C2 frameworks, enabling:
 * 1. Intelligent C2 framework selection based on engagement context
 * 2. Threat actor TTP → C2 module mapping for adversary emulation
 * 3. Post-exploitation playbook generation when shells/agents land
 * 4. Automated adversary profile generation from TTP catalogs
 * 5. C2 chaining strategies for multi-framework operations
 * 6. OPSEC-aware technique selection per framework
 *
 * Data flow:
 *   Threat Actor TTPs → TTP-to-C2 Mapper → C2 Module Selection
 *   Shell/Agent Callback → Post-Exploitation Selector → C2 Task Dispatch
 *   New Threat Intel → Profile Completeness Check → Auto-Generate Adversary Profile
 *
 * Author: Harrison Cook — AceofCloud
 */

import type { C2FrameworkType, C2Agent, C2Module, IC2Adapter } from "./c2-abstraction";
import { getDb } from "../db";
import { threatActors, ttpKnowledge } from "../../drizzle/schema";
import { eq, sql, inArray, and, isNotNull, desc, gte } from "drizzle-orm";

// ─── C2 Framework Tactical Profiles ─────────────────────────────────────────

export interface C2FrameworkProfile {
  framework: C2FrameworkType;
  displayName: string;
  description: string;
  /** Primary use cases in engagement lifecycle */
  primaryUseCases: string[];
  /** MITRE ATT&CK tactics this framework excels at */
  strongTactics: string[];
  /** Supported platforms */
  platforms: ("windows" | "linux" | "macos")[];
  /** Communication protocols supported */
  protocols: string[];
  /** Evasion capabilities */
  evasionCapabilities: EvasionCapability[];
  /** OPSEC profile */
  opsecProfile: OpsecProfile;
  /** When to prefer this framework over others */
  preferWhen: string[];
  /** When to avoid this framework */
  avoidWhen: string[];
  /** Typical engagement phases where this framework shines */
  bestPhases: EngagementPhase[];
  /** Known tools/modules mapped to MITRE techniques */
  techniqueModuleMap: Record<string, string[]>;
  /** Post-exploitation capabilities */
  postExploitCapabilities: PostExploitCapability[];
}

export interface EvasionCapability {
  technique: string;
  description: string;
  effectiveness: "high" | "medium" | "low";
  bypassesDefenses: string[];
}

export interface OpsecProfile {
  networkNoise: "minimal" | "low" | "moderate" | "high";
  diskArtifacts: "none" | "minimal" | "moderate" | "heavy";
  memoryFootprint: "tiny" | "small" | "moderate" | "large";
  defaultSleepJitter: string;
  antiForensics: string[];
  detectionDifficulty: "very-hard" | "hard" | "moderate" | "easy";
}

export type EngagementPhase =
  | "reconnaissance"
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection_exfiltration"
  | "impact";

export interface PostExploitCapability {
  name: string;
  description: string;
  phase: EngagementPhase;
  techniqueIds: string[];
  requiredPrivilege: "user" | "admin" | "system";
  platforms: string[];
  moduleId?: string;
}

// ─── Framework Profiles ─────────────────────────────────────────────────────

const FRAMEWORK_PROFILES: Record<C2FrameworkType, C2FrameworkProfile> = {
  caldera: {
    framework: "caldera",
    displayName: "MITRE Caldera",
    description: "MITRE's adversary emulation platform with automated attack planning, ability chaining, and agent-based execution. Best for structured adversary emulation and purple team exercises.",
    primaryUseCases: ["Adversary emulation", "Purple team exercises", "Automated TTP execution", "Detection validation"],
    strongTactics: ["execution", "discovery", "persistence", "privilege-escalation", "lateral-movement", "collection", "defense-evasion"],
    platforms: ["windows", "linux", "macos"],
    protocols: ["HTTP", "HTTPS", "TCP", "UDP", "DNS-over-HTTPS"],
    evasionCapabilities: [
      { technique: "Obfuscated agent comms", description: "Sandcat/Manx agents use encrypted HTTP with jitter", effectiveness: "medium", bypassesDefenses: ["basic-IDS", "signature-NIDS"] },
      { technique: "Living-off-the-land", description: "Abilities use native OS tools (PowerShell, cmd, bash)", effectiveness: "high", bypassesDefenses: ["application-whitelisting-partial", "AV-signatures"] },
      { technique: "Agent rotation", description: "Switch between Sandcat, Manx, and Ragdoll agents", effectiveness: "medium", bypassesDefenses: ["agent-signature-detection"] },
    ],
    opsecProfile: {
      networkNoise: "moderate",
      diskArtifacts: "minimal",
      memoryFootprint: "small",
      defaultSleepJitter: "60s/25%",
      antiForensics: ["In-memory execution", "Cleanup operations post-ability"],
      detectionDifficulty: "moderate",
    },
    preferWhen: [
      "Running structured adversary emulation plans",
      "Need automated kill chain execution with decision logic",
      "Purple team exercises requiring detection validation",
      "Emulating specific threat actors with known TTP sequences",
    ],
    avoidWhen: [
      "Need maximum stealth for assumed-breach scenarios",
      "Target has mature EDR that signatures Sandcat",
      "Need long-term persistent access (better: Cobalt Strike/Sliver)",
    ],
    bestPhases: ["execution", "discovery", "persistence", "privilege_escalation", "lateral_movement"],
    techniqueModuleMap: {
      "T1059.001": ["PowerShell execution abilities"],
      "T1059.003": ["Windows Command Shell abilities"],
      "T1059.004": ["Unix Shell abilities"],
      "T1053.005": ["Scheduled Task abilities"],
      "T1003.001": ["LSASS Memory dump abilities"],
      "T1087.001": ["Local Account Discovery abilities"],
      "T1082": ["System Information Discovery abilities"],
      "T1083": ["File and Directory Discovery abilities"],
      "T1057": ["Process Discovery abilities"],
      "T1021.002": ["SMB/Windows Admin Shares abilities"],
    },
    postExploitCapabilities: [
      { name: "System Enumeration", description: "Comprehensive host and network discovery using native tools", phase: "discovery", techniqueIds: ["T1082", "T1083", "T1057", "T1087", "T1016"], requiredPrivilege: "user", platforms: ["windows", "linux", "macos"] },
      { name: "Credential Harvesting", description: "Extract credentials from memory, files, and registries", phase: "credential_access", techniqueIds: ["T1003.001", "T1003.002", "T1552.001"], requiredPrivilege: "admin", platforms: ["windows"] },
      { name: "Persistence Installation", description: "Establish persistence via scheduled tasks, services, or registry", phase: "persistence", techniqueIds: ["T1053.005", "T1543.003", "T1547.001"], requiredPrivilege: "admin", platforms: ["windows", "linux"] },
      { name: "Privilege Escalation", description: "Escalate from user to admin/system using known techniques", phase: "privilege_escalation", techniqueIds: ["T1055", "T1134", "T1548.002"], requiredPrivilege: "user", platforms: ["windows", "linux"] },
      { name: "Lateral Movement", description: "Move to adjacent hosts via SMB, WMI, or SSH", phase: "lateral_movement", techniqueIds: ["T1021.002", "T1021.004", "T1047"], requiredPrivilege: "admin", platforms: ["windows", "linux"] },
    ],
  },

  metasploit: {
    framework: "metasploit",
    displayName: "Metasploit Framework",
    description: "The industry-standard exploitation framework with the largest public exploit database. Best for vulnerability validation, exploit development, and initial access.",
    primaryUseCases: ["Exploit development", "Vulnerability validation", "Initial access", "Payload generation", "Post-exploitation modules"],
    strongTactics: ["initial-access", "execution", "privilege-escalation", "credential-access", "lateral-movement"],
    platforms: ["windows", "linux", "macos"],
    protocols: ["HTTP", "HTTPS", "TCP", "DNS", "SMB", "SSH"],
    evasionCapabilities: [
      { technique: "Payload encoding", description: "Shikata Ga Nai and other polymorphic encoders", effectiveness: "low", bypassesDefenses: ["basic-AV"] },
      { technique: "Meterpreter in-memory", description: "Reflective DLL injection, no disk artifacts", effectiveness: "medium", bypassesDefenses: ["disk-scanning-AV", "file-integrity-monitoring"] },
      { technique: "Stageless payloads", description: "Single-stage payloads reduce network signatures", effectiveness: "medium", bypassesDefenses: ["staged-payload-detection"] },
      { technique: "HTTPS reverse shell", description: "Encrypted C2 channel blends with web traffic", effectiveness: "medium", bypassesDefenses: ["basic-IDS", "unencrypted-traffic-inspection"] },
    ],
    opsecProfile: {
      networkNoise: "moderate",
      diskArtifacts: "minimal",
      memoryFootprint: "moderate",
      defaultSleepJitter: "5s/0%",
      antiForensics: ["In-memory Meterpreter", "Timestomping module", "Event log clearing"],
      detectionDifficulty: "moderate",
    },
    preferWhen: [
      "Need to validate specific CVE exploits",
      "Initial access phase — largest exploit database",
      "Generating custom payloads for specific targets",
      "Need post-exploitation modules for Windows environments",
      "Pivoting through networks with autoroute",
    ],
    avoidWhen: [
      "Target has mature EDR (Meterpreter is heavily signatured)",
      "Need long-term stealth (noisy default config)",
      "Adversary emulation requiring specific actor TTPs (better: Caldera)",
    ],
    bestPhases: ["initial_access", "execution", "privilege_escalation", "credential_access", "lateral_movement"],
    techniqueModuleMap: {
      "T1190": ["exploit/multi/http/*", "exploit/windows/http/*"],
      "T1059.001": ["post/windows/manage/powershell/*"],
      "T1003.001": ["post/windows/gather/hashdump", "post/windows/gather/smart_hashdump"],
      "T1055": ["post/windows/manage/migrate"],
      "T1548.002": ["exploit/windows/local/bypassuac*"],
      "T1021.002": ["exploit/windows/smb/psexec"],
      "T1047": ["exploit/windows/local/wmi*"],
      "T1110": ["auxiliary/scanner/ssh/ssh_login", "auxiliary/scanner/smb/smb_login"],
    },
    postExploitCapabilities: [
      { name: "Hashdump", description: "Dump password hashes from SAM/NTDS", phase: "credential_access", techniqueIds: ["T1003.001", "T1003.002", "T1003.003"], requiredPrivilege: "system", platforms: ["windows"] },
      { name: "Mimikatz Integration", description: "Load Mimikatz for credential extraction (kerberos, wdigest, SAM)", phase: "credential_access", techniqueIds: ["T1003.001", "T1558.003"], requiredPrivilege: "system", platforms: ["windows"] },
      { name: "Token Impersonation", description: "Steal and impersonate tokens for privilege escalation", phase: "privilege_escalation", techniqueIds: ["T1134.001"], requiredPrivilege: "admin", platforms: ["windows"] },
      { name: "Autoroute Pivoting", description: "Route traffic through compromised host to reach internal networks", phase: "lateral_movement", techniqueIds: ["T1090"], requiredPrivilege: "user", platforms: ["windows", "linux"] },
      { name: "Screenshot/Keylog", description: "Capture screenshots and keystrokes for intelligence gathering", phase: "collection_exfiltration", techniqueIds: ["T1113", "T1056.001"], requiredPrivilege: "user", platforms: ["windows", "linux", "macos"] },
    ],
  },

  sliver: {
    framework: "sliver",
    displayName: "Sliver C2",
    description: "Modern, open-source C2 framework by BishopFox with strong evasion, mTLS/WireGuard transport, and cross-platform implants. Best for stealth operations and assumed-breach scenarios.",
    primaryUseCases: ["Stealth operations", "Assumed-breach testing", "Long-term persistence", "Cross-platform implants", "Evasion-focused red team"],
    strongTactics: ["command-and-control", "defense-evasion", "persistence", "execution", "lateral-movement"],
    platforms: ["windows", "linux", "macos"],
    protocols: ["mTLS", "WireGuard", "HTTPS", "DNS", "TCP", "Named Pipes"],
    evasionCapabilities: [
      { technique: "Compile-time obfuscation", description: "Each implant is uniquely compiled with randomized symbols", effectiveness: "high", bypassesDefenses: ["signature-AV", "YARA-rules", "static-analysis"] },
      { technique: "mTLS/WireGuard transport", description: "Encrypted tunnels that don't look like typical C2 traffic", effectiveness: "high", bypassesDefenses: ["network-IDS", "SSL-inspection-partial", "traffic-analysis"] },
      { technique: "Process injection", description: "Migrate into legitimate processes", effectiveness: "high", bypassesDefenses: ["process-monitoring-partial", "application-whitelisting"] },
      { technique: "DNS C2", description: "Exfiltrate data and receive commands over DNS queries", effectiveness: "high", bypassesDefenses: ["HTTP-proxy-inspection", "firewall-egress-filtering"] },
    ],
    opsecProfile: {
      networkNoise: "minimal",
      diskArtifacts: "none",
      memoryFootprint: "small",
      defaultSleepJitter: "60s/30%",
      antiForensics: ["In-memory only", "No disk writes", "Encrypted comms", "Randomized beacon intervals"],
      detectionDifficulty: "very-hard",
    },
    preferWhen: [
      "Need maximum stealth and evasion",
      "Assumed-breach scenario requiring long-term access",
      "Target has mature EDR/NDR (Sliver evades better than MSF/CS)",
      "Cross-platform targets (Linux servers + Windows workstations)",
      "Need encrypted C2 channels (mTLS/WireGuard)",
    ],
    avoidWhen: [
      "Need large exploit library (better: Metasploit)",
      "Structured adversary emulation with ability chaining (better: Caldera)",
      "Need GUI-based team collaboration (better: Cobalt Strike)",
    ],
    bestPhases: ["persistence", "defense_evasion", "lateral_movement", "collection_exfiltration"],
    techniqueModuleMap: {
      "T1055": ["process-inject", "migrate"],
      "T1059.001": ["powershell", "execute-shellcode"],
      "T1059.004": ["shell", "execute"],
      "T1021.002": ["psexec", "sharphound"],
      "T1003.001": ["mimikatz", "sharp-dump"],
      "T1571": ["pivots", "portfwd"],
      "T1572": ["wg-portfwd", "named-pipe"],
    },
    postExploitCapabilities: [
      { name: "Process Injection", description: "Inject into legitimate processes for stealth persistence", phase: "defense_evasion", techniqueIds: ["T1055", "T1055.001"], requiredPrivilege: "admin", platforms: ["windows", "linux"] },
      { name: "Credential Extraction", description: "Dump credentials via Mimikatz or SharpDump extensions", phase: "credential_access", techniqueIds: ["T1003.001", "T1003.002"], requiredPrivilege: "system", platforms: ["windows"] },
      { name: "Network Pivoting", description: "WireGuard and SOCKS5 pivoting through compromised hosts", phase: "lateral_movement", techniqueIds: ["T1090", "T1572"], requiredPrivilege: "user", platforms: ["windows", "linux", "macos"] },
      { name: "Port Forwarding", description: "Forward ports through implant for accessing internal services", phase: "lateral_movement", techniqueIds: ["T1090.001"], requiredPrivilege: "user", platforms: ["windows", "linux", "macos"] },
      { name: "Screenshot & Keylog", description: "Capture visual and keyboard intelligence", phase: "collection_exfiltration", techniqueIds: ["T1113", "T1056.001"], requiredPrivilege: "user", platforms: ["windows", "linux", "macos"] },
    ],
  },

  empire: {
    framework: "empire",
    displayName: "PowerShell Empire / Starkiller",
    description: "BC Security's PowerShell/Python post-exploitation framework with extensive module library. Best for Windows-heavy environments, Active Directory attacks, and credential harvesting.",
    primaryUseCases: ["Active Directory attacks", "PowerShell post-exploitation", "Credential harvesting", "Windows domain escalation", "Lateral movement in AD environments"],
    strongTactics: ["credential-access", "privilege-escalation", "lateral-movement", "execution", "persistence", "discovery"],
    platforms: ["windows", "linux", "macos"],
    protocols: ["HTTP", "HTTPS", "Dropbox", "OneDrive"],
    evasionCapabilities: [
      { technique: "AMSI bypass", description: "Built-in AMSI bypass for PowerShell execution", effectiveness: "medium", bypassesDefenses: ["AMSI", "PowerShell-logging-partial"] },
      { technique: "Obfuscated stagers", description: "Multiple stager formats with obfuscation", effectiveness: "medium", bypassesDefenses: ["basic-AV", "email-gateway-partial"] },
      { technique: "Malleable C2 profiles", description: "Customize HTTP traffic to mimic legitimate services", effectiveness: "medium", bypassesDefenses: ["traffic-pattern-analysis"] },
      { technique: "Python agents", description: "Python-based agents for Linux/macOS bypass AV focused on PE files", effectiveness: "high", bypassesDefenses: ["Windows-focused-AV", "PE-scanning"] },
    ],
    opsecProfile: {
      networkNoise: "low",
      diskArtifacts: "minimal",
      memoryFootprint: "moderate",
      defaultSleepJitter: "5s/20%",
      antiForensics: ["In-memory PowerShell execution", "Script block logging bypass attempts", "Encrypted comms"],
      detectionDifficulty: "moderate",
    },
    preferWhen: [
      "Windows Active Directory environment",
      "Need extensive PowerShell post-exploitation modules",
      "Credential harvesting and Kerberos attacks (Kerberoasting, Golden Ticket)",
      "Need Mimikatz, BloodHound, Rubeus integration",
      "Lateral movement via WMI, DCOM, PSRemoting, SMB",
    ],
    avoidWhen: [
      "Target has PowerShell Constrained Language Mode enforced",
      "Target has mature PowerShell logging and AMSI (Empire is well-known)",
      "Linux-only environment (better: Sliver)",
      "Need exploit delivery (better: Metasploit)",
    ],
    bestPhases: ["credential_access", "privilege_escalation", "lateral_movement", "persistence", "discovery"],
    techniqueModuleMap: {
      "T1003.001": ["credentials/mimikatz/logonpasswords", "credentials/mimikatz/sam"],
      "T1558.003": ["credentials/mimikatz/kerberoast", "credentials/rubeus"],
      "T1558.001": ["credentials/mimikatz/golden_ticket"],
      "T1087.002": ["situational_awareness/network/powerview/get_user", "situational_awareness/network/bloodhound3"],
      "T1021.006": ["lateral_movement/invoke_psremoting"],
      "T1021.003": ["lateral_movement/invoke_dcom"],
      "T1047": ["lateral_movement/invoke_wmi"],
      "T1021.002": ["lateral_movement/invoke_psexec", "lateral_movement/invoke_smbexec"],
      "T1053.005": ["persistence/elevated/schtasks"],
      "T1543.003": ["persistence/elevated/new_service"],
      "T1547.001": ["persistence/userland/registry"],
    },
    postExploitCapabilities: [
      { name: "Mimikatz Suite", description: "Full Mimikatz integration — logonpasswords, SAM, DCSync, Golden/Silver tickets", phase: "credential_access", techniqueIds: ["T1003.001", "T1003.002", "T1003.006", "T1558.001", "T1558.003"], requiredPrivilege: "system", platforms: ["windows"] },
      { name: "BloodHound Collection", description: "Run SharpHound/BloodHound for AD attack path mapping", phase: "discovery", techniqueIds: ["T1087.002", "T1069.002", "T1482"], requiredPrivilege: "user", platforms: ["windows"] },
      { name: "Kerberos Attacks", description: "Kerberoasting, AS-REP roasting, ticket forging via Rubeus", phase: "credential_access", techniqueIds: ["T1558.003", "T1558.004", "T1558.001"], requiredPrivilege: "user", platforms: ["windows"] },
      { name: "AD Lateral Movement", description: "PSExec, WMI, DCOM, PSRemoting for domain-wide movement", phase: "lateral_movement", techniqueIds: ["T1021.002", "T1021.003", "T1021.006", "T1047"], requiredPrivilege: "admin", platforms: ["windows"] },
      { name: "Domain Persistence", description: "Golden Ticket, Skeleton Key, DCSync for domain persistence", phase: "persistence", techniqueIds: ["T1558.001", "T1556.001", "T1003.006"], requiredPrivilege: "system", platforms: ["windows"] },
    ],
  },

  cobaltstrike: {
    framework: "cobaltstrike",
    displayName: "Cobalt Strike",
    description: "Commercial adversary simulation platform with Beacon implants, Malleable C2, and team collaboration. The gold standard for professional red team operations.",
    primaryUseCases: ["Professional red team operations", "Long-term stealth access", "Team-based operations", "Malleable C2 for evasion", "Advanced lateral movement"],
    strongTactics: ["command-and-control", "defense-evasion", "lateral-movement", "credential-access", "execution", "persistence"],
    platforms: ["windows", "linux"],
    protocols: ["HTTP", "HTTPS", "DNS", "SMB Named Pipes", "TCP"],
    evasionCapabilities: [
      { technique: "Malleable C2 profiles", description: "Fully customizable HTTP/S traffic profiles mimicking legitimate services (Amazon, Google, etc.)", effectiveness: "high", bypassesDefenses: ["traffic-analysis", "network-IDS", "SSL-inspection-partial"] },
      { technique: "Sleep mask", description: "Encrypt Beacon in memory during sleep to evade memory scanners", effectiveness: "high", bypassesDefenses: ["memory-scanning", "EDR-memory-analysis"] },
      { technique: "User-defined reflective loader", description: "Custom PE loader to bypass EDR hooks", effectiveness: "high", bypassesDefenses: ["EDR-hooks", "NTDLL-unhooking-detection"] },
      { technique: "BOF (Beacon Object Files)", description: "Execute position-independent C code in Beacon's memory without spawning processes", effectiveness: "high", bypassesDefenses: ["process-creation-monitoring", "command-line-logging"] },
      { technique: "SMB Beacon chaining", description: "Chain Beacons over named pipes for internal-only C2", effectiveness: "high", bypassesDefenses: ["egress-filtering", "network-segmentation-partial"] },
    ],
    opsecProfile: {
      networkNoise: "minimal",
      diskArtifacts: "none",
      memoryFootprint: "small",
      defaultSleepJitter: "60s/37%",
      antiForensics: ["Sleep mask encryption", "In-memory only", "BOF execution", "Timestomping", "Event log clearing"],
      detectionDifficulty: "very-hard",
    },
    preferWhen: [
      "Professional red team engagement requiring maximum stealth",
      "Long-term persistent access (weeks/months)",
      "Team-based operations with multiple operators",
      "Need advanced evasion (Malleable C2, sleep mask, BOFs)",
      "Windows-heavy enterprise environment",
      "Need SMB Beacon chaining for internal pivoting",
    ],
    avoidWhen: [
      "Budget-constrained (commercial license required)",
      "Need open-source tooling for transparency",
      "Linux-heavy environment (limited Linux Beacon)",
      "Adversary emulation requiring automated TTP sequencing (better: Caldera)",
    ],
    bestPhases: ["initial_access", "persistence", "defense_evasion", "credential_access", "lateral_movement", "collection_exfiltration"],
    techniqueModuleMap: {
      "T1059.001": ["powershell", "powerpick"],
      "T1059.003": ["shell", "run"],
      "T1055": ["inject", "shinject", "dllinject"],
      "T1003.001": ["mimikatz logonpasswords", "mimikatz sekurlsa::logonpasswords"],
      "T1558.003": ["execute-assembly Rubeus kerberoast"],
      "T1021.002": ["psexec", "psexec_psh"],
      "T1021.006": ["winrm"],
      "T1047": ["wmi"],
      "T1090": ["socks", "rportfwd"],
      "T1071.001": ["Malleable C2 HTTP profiles"],
    },
    postExploitCapabilities: [
      { name: "Beacon Object Files", description: "Execute custom C code in-process without spawning child processes", phase: "execution", techniqueIds: ["T1106"], requiredPrivilege: "user", platforms: ["windows"] },
      { name: "Mimikatz Integration", description: "Built-in Mimikatz for credential extraction, DCSync, ticket forging", phase: "credential_access", techniqueIds: ["T1003.001", "T1003.006", "T1558.001"], requiredPrivilege: "system", platforms: ["windows"] },
      { name: "SMB Beacon Chaining", description: "Chain Beacons over named pipes for stealthy internal C2", phase: "lateral_movement", techniqueIds: ["T1021.002", "T1570"], requiredPrivilege: "admin", platforms: ["windows"] },
      { name: "SOCKS Proxy", description: "SOCKS4a proxy through Beacon for tunneling tools", phase: "lateral_movement", techniqueIds: ["T1090"], requiredPrivilege: "user", platforms: ["windows", "linux"] },
      { name: "Execute-Assembly", description: "Run .NET assemblies in-memory without touching disk", phase: "execution", techniqueIds: ["T1059"], requiredPrivilege: "user", platforms: ["windows"] },
    ],
  },

  manjusaka: {
    framework: "manjusaka",
    displayName: "Manjusaka C2",
    description: "Rust-based C2 framework with cross-platform implants. Lightweight, fast, and less signatured than mainstream C2 frameworks. Good for operations where common tools are detected.",
    primaryUseCases: ["Alternative C2 when mainstream tools are detected", "Cross-platform operations", "Lightweight implant deployment", "Operations requiring novel tooling"],
    strongTactics: ["command-and-control", "execution", "persistence", "defense-evasion"],
    platforms: ["windows", "linux"],
    protocols: ["HTTP", "HTTPS", "TCP", "WebSocket"],
    evasionCapabilities: [
      { technique: "Rust-compiled implants", description: "Rust binaries are less commonly signatured by AV/EDR", effectiveness: "high", bypassesDefenses: ["signature-AV", "YARA-rules", "behavioral-analysis-partial"] },
      { technique: "Novel framework", description: "Less well-known = fewer detection rules in commercial products", effectiveness: "high", bypassesDefenses: ["EDR-behavioral-rules", "threat-intel-IOC-matching"] },
      { technique: "Small footprint", description: "Minimal implant size reduces detection surface", effectiveness: "medium", bypassesDefenses: ["anomaly-detection-partial"] },
    ],
    opsecProfile: {
      networkNoise: "low",
      diskArtifacts: "minimal",
      memoryFootprint: "tiny",
      defaultSleepJitter: "30s/20%",
      antiForensics: ["Rust memory safety", "Minimal disk writes", "Encrypted comms"],
      detectionDifficulty: "hard",
    },
    preferWhen: [
      "Common C2 frameworks (CS, MSF, Empire) are being detected",
      "Need a lightweight, fast implant",
      "Want to diversify C2 infrastructure to avoid single-framework detection",
      "Cross-platform target (Windows + Linux)",
    ],
    avoidWhen: [
      "Need extensive post-exploitation module library (better: Empire/MSF)",
      "Need team collaboration features (better: Cobalt Strike)",
      "Need structured adversary emulation (better: Caldera)",
    ],
    bestPhases: ["initial_access", "execution", "persistence", "defense_evasion"],
    techniqueModuleMap: {
      "T1059": ["cmd", "shell"],
      "T1105": ["upload", "download"],
      "T1082": ["sysinfo"],
      "T1057": ["ps"],
      "T1083": ["ls", "find"],
    },
    postExploitCapabilities: [
      { name: "Command Execution", description: "Execute system commands via cmd/shell", phase: "execution", techniqueIds: ["T1059.003", "T1059.004"], requiredPrivilege: "user", platforms: ["windows", "linux"] },
      { name: "File Operations", description: "Upload/download files for staging and exfiltration", phase: "collection_exfiltration", techniqueIds: ["T1105", "T1041"], requiredPrivilege: "user", platforms: ["windows", "linux"] },
      { name: "System Enumeration", description: "Gather system info, processes, and file listings", phase: "discovery", techniqueIds: ["T1082", "T1057", "T1083"], requiredPrivilege: "user", platforms: ["windows", "linux"] },
    ],
  },
};

// ─── C2 Selection Engine ────────────────────────────────────────────────────

export interface C2SelectionContext {
  targetPlatform: "windows" | "linux" | "macos" | "mixed";
  engagementPhase: EngagementPhase;
  targetDefenses: string[];
  stealthRequired: "maximum" | "high" | "moderate" | "low";
  hasActiveDirectory: boolean;
  threatActorToEmulate?: string;
  availableFrameworks: C2FrameworkType[];
  currentShellPrivilege?: "user" | "admin" | "system";
}

export interface C2Recommendation {
  primary: C2FrameworkType;
  secondary?: C2FrameworkType;
  reasoning: string;
  suggestedModules: string[];
  opsecWarnings: string[];
  chainStrategy?: C2ChainStrategy;
}

export interface C2ChainStrategy {
  description: string;
  stages: {
    phase: EngagementPhase;
    framework: C2FrameworkType;
    purpose: string;
    handoffTrigger: string;
  }[];
}

/**
 * Select the optimal C2 framework(s) for a given engagement context.
 * This is the deterministic advisor that feeds into the LLM system prompt.
 */
export function selectC2Framework(context: C2SelectionContext): C2Recommendation {
  const scores: Record<C2FrameworkType, number> = {
    caldera: 0, metasploit: 0, sliver: 0, empire: 0, cobaltstrike: 0, manjusaka: 0,
  };

  for (const fw of context.availableFrameworks) {
    const profile = FRAMEWORK_PROFILES[fw];
    if (!profile) continue;

    // Platform match
    if (context.targetPlatform === "mixed" || profile.platforms.includes(context.targetPlatform as any)) {
      scores[fw] += 10;
    }

    // Phase match
    if (profile.bestPhases.includes(context.engagementPhase)) {
      scores[fw] += 20;
    }

    // Stealth match
    const stealthScores: Record<string, Record<string, number>> = {
      maximum: { "very-hard": 30, hard: 15, moderate: 0, easy: -20 },
      high: { "very-hard": 25, hard: 20, moderate: 5, easy: -10 },
      moderate: { "very-hard": 10, hard: 15, moderate: 20, easy: 10 },
      low: { "very-hard": 5, hard: 10, moderate: 15, easy: 20 },
    };
    scores[fw] += stealthScores[context.stealthRequired]?.[profile.opsecProfile.detectionDifficulty] ?? 0;

    // Active Directory bonus for Empire
    if (context.hasActiveDirectory && fw === "empire") scores[fw] += 25;
    if (context.hasActiveDirectory && fw === "cobaltstrike") scores[fw] += 15;

    // Defense evasion — check if framework can bypass target defenses
    for (const defense of context.targetDefenses) {
      for (const evasion of profile.evasionCapabilities) {
        if (evasion.bypassesDefenses.some(d => d.toLowerCase().includes(defense.toLowerCase()))) {
          scores[fw] += 10;
        }
      }
    }

    // Novelty bonus for less-known frameworks when stealth is critical
    if (context.stealthRequired === "maximum" && (fw === "sliver" || fw === "manjusaka")) {
      scores[fw] += 10;
    }
  }

  // Sort by score
  const sorted = context.availableFrameworks
    .filter(fw => scores[fw] > 0)
    .sort((a, b) => scores[b] - scores[a]);

  const primary = sorted[0] || "caldera";
  const secondary = sorted[1];
  const primaryProfile = FRAMEWORK_PROFILES[primary];

  // Build reasoning
  const reasoning = buildSelectionReasoning(primary, secondary, context, scores);

  // Suggest modules based on phase
  const suggestedModules = primaryProfile.postExploitCapabilities
    .filter(cap => cap.phase === context.engagementPhase)
    .filter(cap => {
      if (!context.currentShellPrivilege) return true;
      const privOrder = { user: 0, admin: 1, system: 2 };
      return privOrder[context.currentShellPrivilege] >= privOrder[cap.requiredPrivilege];
    })
    .map(cap => `${cap.name}: ${cap.description}`);

  // OPSEC warnings
  const opsecWarnings = primaryProfile.avoidWhen
    .filter(warning => {
      if (warning.includes("EDR") && context.targetDefenses.some(d => d.toLowerCase().includes("edr"))) return true;
      if (warning.includes("PowerShell") && context.targetDefenses.some(d => d.toLowerCase().includes("powershell"))) return true;
      return false;
    });

  // Build chain strategy for multi-phase operations
  const chainStrategy = buildChainStrategy(context, sorted);

  return { primary, secondary, reasoning, suggestedModules, opsecWarnings, chainStrategy };
}

function buildSelectionReasoning(
  primary: C2FrameworkType,
  secondary: C2FrameworkType | undefined,
  context: C2SelectionContext,
  scores: Record<C2FrameworkType, number>,
): string {
  const profile = FRAMEWORK_PROFILES[primary];
  let reasoning = `Selected ${profile.displayName} (score: ${scores[primary]}) for ${context.engagementPhase} phase. `;
  reasoning += `${profile.description.split(".")[0]}. `;

  if (context.stealthRequired === "maximum" || context.stealthRequired === "high") {
    reasoning += `OPSEC: ${profile.opsecProfile.detectionDifficulty} detection difficulty, ${profile.opsecProfile.networkNoise} network noise. `;
  }

  if (secondary) {
    const secProfile = FRAMEWORK_PROFILES[secondary];
    reasoning += `Fallback: ${secProfile.displayName} (score: ${scores[secondary]}) if primary is detected.`;
  }

  return reasoning;
}

function buildChainStrategy(
  context: C2SelectionContext,
  rankedFrameworks: C2FrameworkType[],
): C2ChainStrategy | undefined {
  if (rankedFrameworks.length < 2) return undefined;

  // Standard kill chain C2 rotation strategy
  const stages: C2ChainStrategy["stages"] = [];

  // Phase 1: Initial access — use the framework with best exploit support
  const initialAccessFw = rankedFrameworks.find(fw =>
    FRAMEWORK_PROFILES[fw].bestPhases.includes("initial_access"),
  ) || rankedFrameworks[0];
  stages.push({
    phase: "initial_access",
    framework: initialAccessFw,
    purpose: `${FRAMEWORK_PROFILES[initialAccessFw].displayName} for initial foothold — ${FRAMEWORK_PROFILES[initialAccessFw].primaryUseCases[0]}`,
    handoffTrigger: "Shell/agent callback received",
  });

  // Phase 2: Post-exploitation — switch to stealthier framework
  const postExploitFw = rankedFrameworks.find(fw =>
    ["sliver", "cobaltstrike"].includes(fw) && fw !== initialAccessFw,
  ) || rankedFrameworks[0];
  stages.push({
    phase: "persistence",
    framework: postExploitFw,
    purpose: `Switch to ${FRAMEWORK_PROFILES[postExploitFw].displayName} for stealth — ${FRAMEWORK_PROFILES[postExploitFw].opsecProfile.detectionDifficulty} detection difficulty`,
    handoffTrigger: "Persistence established, initial access agent terminated",
  });

  // Phase 3: AD attacks — use Empire if available and AD present
  if (context.hasActiveDirectory && rankedFrameworks.includes("empire")) {
    stages.push({
      phase: "credential_access",
      framework: "empire",
      purpose: "Empire for AD credential harvesting — Mimikatz, BloodHound, Kerberoasting",
      handoffTrigger: "Domain credentials obtained or domain controller reached",
    });
  }

  // Phase 4: Lateral movement — use the framework with best pivoting
  const lateralFw = rankedFrameworks.find(fw =>
    FRAMEWORK_PROFILES[fw].bestPhases.includes("lateral_movement"),
  ) || rankedFrameworks[0];
  if (lateralFw !== postExploitFw) {
    stages.push({
      phase: "lateral_movement",
      framework: lateralFw,
      purpose: `${FRAMEWORK_PROFILES[lateralFw].displayName} for network pivoting`,
      handoffTrigger: "High-value target reached or objective completed",
    });
  }

  return {
    description: `Multi-framework chain: ${stages.map(s => `${s.framework}(${s.phase})`).join(" → ")}`,
    stages,
  };
}

// ─── Threat Actor TTP → C2 Module Mapper ────────────────────────────────────

export interface ActorC2Mapping {
  actorName: string;
  actorId: string;
  totalTTPs: number;
  mappedToC2: number;
  coveragePercent: number;
  frameworkBreakdown: Record<C2FrameworkType, {
    moduleCount: number;
    techniques: string[];
  }>;
  recommendedPrimaryC2: C2FrameworkType;
  emulationPlan: EmulationPlanStep[];
}

export interface EmulationPlanStep {
  order: number;
  phase: EngagementPhase;
  techniqueId: string;
  techniqueName: string;
  framework: C2FrameworkType;
  modules: string[];
  description: string;
}

/**
 * Map a threat actor's TTPs to specific C2 framework modules.
 * Uses the threat actor's technique list and the framework profiles
 * to build a complete emulation plan.
 */
export async function mapActorTTPs(actorId: string): Promise<ActorC2Mapping | null> {
  const db = await getDb();
  if (!db) return null;

  // Get the actor and their techniques
  const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (!actor) return null;

  const techniques: Array<{ id: string; name: string; tactic: string }> =
    typeof actor.techniques === "string" ? JSON.parse(actor.techniques) : (actor.techniques as any[] || []);

  if (techniques.length === 0) return null;

  // Map each technique to C2 modules
  const frameworkBreakdown: ActorC2Mapping["frameworkBreakdown"] = {
    caldera: { moduleCount: 0, techniques: [] },
    metasploit: { moduleCount: 0, techniques: [] },
    sliver: { moduleCount: 0, techniques: [] },
    empire: { moduleCount: 0, techniques: [] },
    cobaltstrike: { moduleCount: 0, techniques: [] },
    manjusaka: { moduleCount: 0, techniques: [] },
  };

  let mappedCount = 0;
  const emulationPlan: EmulationPlanStep[] = [];

  for (const tech of techniques) {
    let mapped = false;

    for (const [fwName, profile] of Object.entries(FRAMEWORK_PROFILES)) {
      const fw = fwName as C2FrameworkType;
      // Check if this technique has modules in this framework
      const baseId = tech.id.split(".")[0]; // T1059.001 → T1059
      const modules = profile.techniqueModuleMap[tech.id] || profile.techniqueModuleMap[baseId] || [];

      if (modules.length > 0) {
        frameworkBreakdown[fw].moduleCount += modules.length;
        frameworkBreakdown[fw].techniques.push(tech.id);
        mapped = true;
      }
    }

    if (mapped) mappedCount++;

    // Build emulation plan step
    const phase = tacticToPhase(tech.tactic);
    const bestFw = selectBestFrameworkForTechnique(tech.id, tech.tactic);
    const modules = FRAMEWORK_PROFILES[bestFw]?.techniqueModuleMap[tech.id]
      || FRAMEWORK_PROFILES[bestFw]?.techniqueModuleMap[tech.id.split(".")[0]]
      || [];

    emulationPlan.push({
      order: emulationPlan.length + 1,
      phase,
      techniqueId: tech.id,
      techniqueName: tech.name,
      framework: bestFw,
      modules,
      description: `Execute ${tech.name} (${tech.id}) via ${FRAMEWORK_PROFILES[bestFw].displayName}`,
    });
  }

  // Sort emulation plan by kill chain order
  const phaseOrder: Record<EngagementPhase, number> = {
    reconnaissance: 0, initial_access: 1, execution: 2, persistence: 3,
    privilege_escalation: 4, defense_evasion: 5, credential_access: 6,
    discovery: 7, lateral_movement: 8, collection_exfiltration: 9, impact: 10,
  };
  emulationPlan.sort((a, b) => phaseOrder[a.phase] - phaseOrder[b.phase]);
  emulationPlan.forEach((step, i) => step.order = i + 1);

  // Determine recommended primary C2
  const fwScores = Object.entries(frameworkBreakdown)
    .map(([fw, data]) => ({ fw: fw as C2FrameworkType, score: data.moduleCount }))
    .sort((a, b) => b.score - a.score);

  return {
    actorName: actor.name,
    actorId: actor.actorId!,
    totalTTPs: techniques.length,
    mappedToC2: mappedCount,
    coveragePercent: Math.round((mappedCount / techniques.length) * 100),
    frameworkBreakdown,
    recommendedPrimaryC2: fwScores[0]?.fw || "caldera",
    emulationPlan,
  };
}

function tacticToPhase(tactic: string): EngagementPhase {
  const mapping: Record<string, EngagementPhase> = {
    "reconnaissance": "reconnaissance",
    "resource-development": "reconnaissance",
    "initial-access": "initial_access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege_escalation",
    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",
    "discovery": "discovery",
    "lateral-movement": "lateral_movement",
    "collection": "collection_exfiltration",
    "exfiltration": "collection_exfiltration",
    "command-and-control": "execution",
    "impact": "impact",
    // Handle capitalized versions from some data sources
    "Initial Access": "initial_access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege_escalation",
    "Defense Evasion": "defense_evasion",
    "Credential Access": "credential_access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral_movement",
    "Collection": "collection_exfiltration",
    "Exfiltration": "collection_exfiltration",
    "Command and Control": "execution",
    "Impact": "impact",
  };
  return mapping[tactic] || "execution";
}

function selectBestFrameworkForTechnique(techniqueId: string, tactic: string): C2FrameworkType {
  // Score each framework for this specific technique
  let bestFw: C2FrameworkType = "caldera";
  let bestScore = 0;

  for (const [fwName, profile] of Object.entries(FRAMEWORK_PROFILES)) {
    const fw = fwName as C2FrameworkType;
    let score = 0;
    const baseId = techniqueId.split(".")[0];

    if (profile.techniqueModuleMap[techniqueId]) score += 20;
    else if (profile.techniqueModuleMap[baseId]) score += 10;

    const phase = tacticToPhase(tactic);
    if (profile.bestPhases.includes(phase)) score += 5;

    if (score > bestScore) {
      bestScore = score;
      bestFw = fw;
    }
  }

  return bestFw;
}

// ─── Adversary Profile Auto-Generator ───────────────────────────────────────

export interface ProfileCompletenessScore {
  actorName: string;
  actorId: string;
  totalTTPs: number;
  totalAbilities: number;
  tacticsRepresented: number;
  totalTactics: number;
  killChainCoverage: number; // 0-100
  hasCalderaProfile: boolean;
  profileQuality: "excellent" | "good" | "fair" | "insufficient";
  missingPhases: string[];
  readyForAutoGeneration: boolean;
  score: number; // 0-100
}

/**
 * Score how complete an actor's profile is and whether it's ready
 * for automatic Caldera adversary profile generation.
 */
export async function scoreProfileCompleteness(actorId: string): Promise<ProfileCompletenessScore | null> {
  const db = await getDb();
  if (!db) return null;

  const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (!actor) return null;

  const techniques: Array<{ id: string; name: string; tactic: string }> =
    typeof actor.techniques === "string" ? JSON.parse(actor.techniques) : (actor.techniques as any[] || []);

  // Count abilities from threat_actor_abilities table
  const [abilityCount] = await db.execute(
    sql`SELECT COUNT(*) as cnt FROM threat_actor_abilities WHERE actorId = ${actorId}`,
  );
  const totalAbilities = (abilityCount as any)[0]?.cnt ?? 0;

  // Calculate tactic coverage
  const allTactics = [
    "reconnaissance", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "exfiltration",
    "command-and-control", "impact",
  ];
  const representedTactics = new Set(
    techniques.map(t => t.tactic?.toLowerCase()).filter(Boolean),
  );
  const tacticsRepresented = representedTactics.size;
  const killChainCoverage = Math.round((tacticsRepresented / allTactics.length) * 100);

  // Missing phases
  const missingPhases = allTactics.filter(t => !representedTactics.has(t));

  // Has existing profile?
  const hasCalderaProfile = !!actor.calderaProfile && actor.calderaProfile !== "null";

  // Composite score
  let score = 0;
  score += Math.min(30, techniques.length * 1.5); // Up to 30 points for TTPs (20+ = max)
  score += Math.min(30, totalAbilities * 0.5);      // Up to 30 points for abilities (60+ = max)
  score += killChainCoverage * 0.3;                  // Up to 30 points for kill chain coverage
  score += tacticsRepresented >= 5 ? 10 : 0;         // 10 bonus for 5+ tactics
  score = Math.min(100, Math.round(score));

  // Quality assessment
  let profileQuality: ProfileCompletenessScore["profileQuality"];
  if (score >= 80) profileQuality = "excellent";
  else if (score >= 60) profileQuality = "good";
  else if (score >= 40) profileQuality = "fair";
  else profileQuality = "insufficient";

  // Ready for auto-generation: 15+ TTPs, 10+ abilities, 3+ tactics
  const readyForAutoGeneration = techniques.length >= 15 && totalAbilities >= 10 && tacticsRepresented >= 3;

  return {
    actorName: actor.name,
    actorId: actorId,
    totalTTPs: techniques.length,
    totalAbilities,
    tacticsRepresented,
    totalTactics: allTactics.length,
    killChainCoverage,
    hasCalderaProfile,
    profileQuality,
    missingPhases,
    readyForAutoGeneration,
    score,
  };
}

/**
 * Auto-generate a Caldera adversary profile from an actor's abilities.
 * Orders abilities by kill chain phase for realistic emulation.
 */
export async function generateAdversaryProfile(actorId: string): Promise<{
  adversaryId: string;
  name: string;
  description: string;
  atomicOrdering: string[];
  abilityCount: number;
  killChainPhases: string[];
} | null> {
  const db = await getDb();
  if (!db) return null;

  const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (!actor) return null;

  // Get all abilities for this actor
  const abilities = await db.execute(
    sql`SELECT abilityId, name, tactic, techniqueId, platforms
        FROM threat_actor_abilities
        WHERE actorId = ${actorId}
        ORDER BY tactic, techniqueId`,
  );
  const abilityRows = abilities[0] as any[];

  if (!abilityRows || abilityRows.length === 0) return null;

  // Order abilities by kill chain phase
  const tacticOrder: Record<string, number> = {
    "reconnaissance": 0, "resource-development": 1,
    "initial-access": 2, "execution": 3,
    "persistence": 4, "privilege-escalation": 5,
    "defense-evasion": 6, "credential-access": 7,
    "discovery": 8, "lateral-movement": 9,
    "collection": 10, "command-and-control": 11,
    "exfiltration": 12, "impact": 13,
  };

  const sortedAbilities = abilityRows.sort((a: any, b: any) => {
    const orderA = tacticOrder[a.tactic?.toLowerCase()] ?? 99;
    const orderB = tacticOrder[b.tactic?.toLowerCase()] ?? 99;
    return orderA - orderB;
  });

  const atomicOrdering = sortedAbilities.map((a: any) => a.abilityId);
  const killChainPhases = [...new Set(sortedAbilities.map((a: any) => a.tactic).filter(Boolean))];

  const adversaryId = `auto-${actorId}-${Date.now().toString(36)}`;
  const profile = {
    adversaryId,
    name: `${actor.name} Emulation Profile`,
    description: `Auto-generated adversary emulation profile for ${actor.name}. Covers ${killChainPhases.length} kill chain phases with ${atomicOrdering.length} abilities. Generated from threat actor TTP catalog and ability mappings.`,
    atomicOrdering,
    abilityCount: atomicOrdering.length,
    killChainPhases,
  };

  // Update the actor's calderaProfile in the database
  await db.update(threatActors)
    .set({ calderaProfile: JSON.stringify(profile) })
    .where(eq(threatActors.actorId, actorId));

  return profile;
}

// ─── Post-Exploitation Playbook Generator ───────────────────────────────────

export interface PostExploitPlaybook {
  shellType: "user" | "admin" | "system" | "root";
  targetPlatform: "windows" | "linux" | "macos";
  engagementObjectives: string[];
  steps: PostExploitStep[];
  estimatedDuration: string;
  opsecGuidelines: string[];
}

export interface PostExploitStep {
  order: number;
  phase: EngagementPhase;
  action: string;
  description: string;
  framework: C2FrameworkType;
  modules: string[];
  techniqueIds: string[];
  requiredPrivilege: "user" | "admin" | "system";
  expectedOutput: string;
  nextStepTrigger: string;
}

/**
 * Generate a post-exploitation playbook when a shell/agent lands.
 * Selects the right C2 modules based on OS, privilege level, and objectives.
 */
export function generatePostExploitPlaybook(params: {
  shellPrivilege: "user" | "admin" | "system" | "root";
  targetPlatform: "windows" | "linux" | "macos";
  objectives: string[];
  availableFrameworks: C2FrameworkType[];
  hasActiveDirectory: boolean;
  targetDefenses: string[];
  threatActorToEmulate?: string;
}): PostExploitPlaybook {
  const steps: PostExploitStep[] = [];
  const privLevel = params.shellPrivilege === "root" ? "system" : params.shellPrivilege;
  let stepOrder = 1;

  // ── Step 1: Situational Awareness (always first) ──
  const discoveryFw = selectBestForPhase("discovery", params.availableFrameworks, params.targetPlatform);
  steps.push({
    order: stepOrder++,
    phase: "discovery",
    action: "System Enumeration",
    description: "Gather hostname, OS version, network interfaces, running processes, logged-in users, and installed software",
    framework: discoveryFw,
    modules: getModulesForPhase(discoveryFw, "discovery", params.targetPlatform),
    techniqueIds: ["T1082", "T1016", "T1057", "T1087.001", "T1083"],
    requiredPrivilege: "user",
    expectedOutput: "System profile, network topology hints, user accounts, running services",
    nextStepTrigger: "Enumeration complete — assess privilege level",
  });

  // ── Step 2: Privilege Escalation (if not already admin/system) ──
  if (privLevel === "user") {
    const privescFw = selectBestForPhase("privilege_escalation", params.availableFrameworks, params.targetPlatform);
    steps.push({
      order: stepOrder++,
      phase: "privilege_escalation",
      action: "Privilege Escalation",
      description: params.targetPlatform === "windows"
        ? "Attempt UAC bypass, token impersonation, or local exploit for SYSTEM"
        : "Attempt sudo misconfiguration, SUID binary abuse, or kernel exploit for root",
      framework: privescFw,
      modules: getModulesForPhase(privescFw, "privilege_escalation", params.targetPlatform),
      techniqueIds: params.targetPlatform === "windows"
        ? ["T1548.002", "T1134.001", "T1068"]
        : ["T1548.003", "T1068"],
      requiredPrivilege: "user",
      expectedOutput: "Elevated shell (admin/SYSTEM/root)",
      nextStepTrigger: "Elevated privileges obtained — proceed to credential harvesting",
    });
  }

  // ── Step 3: Credential Harvesting ──
  const credFw = selectBestForPhase("credential_access", params.availableFrameworks, params.targetPlatform);
  steps.push({
    order: stepOrder++,
    phase: "credential_access",
    action: "Credential Harvesting",
    description: params.targetPlatform === "windows"
      ? "Dump LSASS memory, SAM database, cached credentials, and browser passwords"
      : "Extract /etc/shadow, SSH keys, bash history, and application credentials",
    framework: credFw,
    modules: getModulesForPhase(credFw, "credential_access", params.targetPlatform),
    techniqueIds: params.targetPlatform === "windows"
      ? ["T1003.001", "T1003.002", "T1552.001", "T1555.003"]
      : ["T1003.008", "T1552.004", "T1552.001"],
    requiredPrivilege: "admin",
    expectedOutput: "Password hashes, plaintext credentials, SSH keys, tokens",
    nextStepTrigger: "Credentials obtained — assess lateral movement opportunities",
  });

  // ── Step 3b: AD-specific attacks (if Windows + AD) ──
  if (params.hasActiveDirectory !== undefined && params.hasActiveDirectory && params.targetPlatform === "windows") {
    const adFw = params.availableFrameworks.includes("empire") ? "empire" : credFw;
    steps.push({
      order: stepOrder++,
      phase: "credential_access",
      action: "Active Directory Attacks",
      description: "Run BloodHound for attack path mapping, Kerberoasting for service account hashes, and DCSync if domain admin",
      framework: adFw,
      modules: ["BloodHound/SharpHound", "Rubeus kerberoast", "Mimikatz DCSync"],
      techniqueIds: ["T1087.002", "T1069.002", "T1482", "T1558.003", "T1003.006"],
      requiredPrivilege: "user",
      expectedOutput: "AD attack paths, service account hashes, domain topology",
      nextStepTrigger: "Domain credentials or attack paths identified — plan lateral movement",
    });
  }

  // ── Step 4: Persistence ──
  const persistFw = selectBestForPhase("persistence", params.availableFrameworks, params.targetPlatform);
  steps.push({
    order: stepOrder++,
    phase: "persistence",
    action: "Establish Persistence",
    description: params.targetPlatform === "windows"
      ? "Install persistence via scheduled task, registry run key, or service"
      : "Install persistence via cron job, systemd service, or SSH authorized_keys",
    framework: persistFw,
    modules: getModulesForPhase(persistFw, "persistence", params.targetPlatform),
    techniqueIds: params.targetPlatform === "windows"
      ? ["T1053.005", "T1547.001", "T1543.003"]
      : ["T1053.003", "T1543.002", "T1098.004"],
    requiredPrivilege: "admin",
    expectedOutput: "Persistent access mechanism installed and verified",
    nextStepTrigger: "Persistence confirmed — safe to proceed with lateral movement",
  });

  // ── Step 5: Lateral Movement ──
  const lateralFw = selectBestForPhase("lateral_movement", params.availableFrameworks, params.targetPlatform);
  steps.push({
    order: stepOrder++,
    phase: "lateral_movement",
    action: "Lateral Movement",
    description: params.targetPlatform === "windows"
      ? "Move to adjacent hosts via PSExec, WMI, DCOM, or PSRemoting using harvested credentials"
      : "Move to adjacent hosts via SSH with harvested keys or credentials",
    framework: lateralFw,
    modules: getModulesForPhase(lateralFw, "lateral_movement", params.targetPlatform),
    techniqueIds: params.targetPlatform === "windows"
      ? ["T1021.002", "T1047", "T1021.003", "T1021.006"]
      : ["T1021.004", "T1021.002"],
    requiredPrivilege: "admin",
    expectedOutput: "Shell/agent on additional hosts, expanded network access",
    nextStepTrigger: "Additional hosts compromised — assess objective proximity",
  });

  // ── Step 6: Collection & Exfiltration (if objective includes data) ──
  if (params.objectives.some(o =>
    o.toLowerCase().includes("data") || o.toLowerCase().includes("exfil") ||
    o.toLowerCase().includes("collect") || o.toLowerCase().includes("proof"),
  )) {
    steps.push({
      order: stepOrder++,
      phase: "collection_exfiltration",
      action: "Data Collection & Staging",
      description: "Identify and stage target data for exfiltration proof",
      framework: lateralFw,
      modules: ["File search", "Archive creation", "Data staging"],
      techniqueIds: ["T1005", "T1560.001", "T1074.001"],
      requiredPrivilege: "user",
      expectedOutput: "Target data identified, staged, and ready for exfiltration proof",
      nextStepTrigger: "Data staged — document findings for report",
    });
  }

  // OPSEC guidelines
  const opsecGuidelines = [
    "Use LOLBins (Living-off-the-Land Binaries) where possible to blend with normal activity",
    "Maintain sleep/jitter intervals between actions to avoid behavioral detection",
    "Clean up artifacts after each step (remove dropped files, clear event logs if authorized)",
    "Monitor for defensive responses (account lockouts, AV alerts) and pause if detected",
    `Current OPSEC posture: ${FRAMEWORK_PROFILES[discoveryFw].opsecProfile.detectionDifficulty} detection difficulty`,
  ];

  if (params.targetDefenses && params.targetDefenses.length > 0) {
    opsecGuidelines.push(`Known defenses: ${params.targetDefenses.join(", ")} — adjust techniques accordingly`);
  }

  // Estimate duration
  const estimatedDuration = steps.length <= 4 ? "2-4 hours" : steps.length <= 6 ? "4-8 hours" : "1-2 days";

  return {
    shellType: params.shellPrivilege,
    targetPlatform: params.targetPlatform,
    engagementObjectives: params.objectives,
    steps,
    estimatedDuration,
    opsecGuidelines,
  };
}

function selectBestForPhase(
  phase: EngagementPhase,
  available: C2FrameworkType[],
  platform: string,
): C2FrameworkType {
  let best: C2FrameworkType = available[0] || "caldera";
  let bestScore = 0;

  for (const fw of available) {
    const profile = FRAMEWORK_PROFILES[fw];
    if (!profile) continue;
    let score = 0;
    if (profile.bestPhases.includes(phase)) score += 10;
    if (profile.platforms.includes(platform as any)) score += 5;
    // Bonus for specific phase-framework combos
    if (phase === "credential_access" && fw === "empire") score += 15;
    if (phase === "credential_access" && fw === "cobaltstrike") score += 10;
    if (phase === "initial_access" && fw === "metasploit") score += 15;
    if (phase === "persistence" && fw === "sliver") score += 10;
    if (phase === "defense_evasion" && fw === "cobaltstrike") score += 15;
    if (phase === "lateral_movement" && fw === "empire") score += 10;

    if (score > bestScore) {
      bestScore = score;
      best = fw;
    }
  }
  return best;
}

function getModulesForPhase(fw: C2FrameworkType, phase: EngagementPhase, platform: string): string[] {
  const profile = FRAMEWORK_PROFILES[fw];
  if (!profile) return [];
  return profile.postExploitCapabilities
    .filter(cap => cap.phase === phase && cap.platforms.includes(platform))
    .map(cap => cap.name);
}

// ─── LLM System Prompt Context Builder ──────────────────────────────────────

/**
 * Build the C2 tactical context that gets injected into LLM system prompts
 * for the operator cockpit and engagement workflow engine.
 */
export function buildC2SystemPromptContext(params: {
  activeAgents: C2Agent[];
  engagementPhase: EngagementPhase;
  targetPlatform: string;
  availableFrameworks: C2FrameworkType[];
  threatActorToEmulate?: string;
}): string {
  const recommendation = selectC2Framework({
    targetPlatform: params.targetPlatform as any,
    engagementPhase: params.engagementPhase,
    targetDefenses: [],
    stealthRequired: "high",
    hasActiveDirectory: params.targetPlatform === "windows",
    threatActorToEmulate: params.threatActorToEmulate,
    availableFrameworks: params.availableFrameworks,
  });

  const activeByFw: Record<string, number> = {};
  for (const agent of params.activeAgents) {
    activeByFw[agent.framework] = (activeByFw[agent.framework] || 0) + 1;
  }

  let context = `\n## C2 Framework Intelligence\n`;
  context += `Current Phase: ${params.engagementPhase}\n`;
  context += `Recommended C2: ${FRAMEWORK_PROFILES[recommendation.primary].displayName}\n`;
  context += `Reasoning: ${recommendation.reasoning}\n`;

  if (recommendation.chainStrategy) {
    context += `\nC2 Chain Strategy: ${recommendation.chainStrategy.description}\n`;
    for (const stage of recommendation.chainStrategy.stages) {
      context += `  - ${stage.phase}: ${FRAMEWORK_PROFILES[stage.framework].displayName} — ${stage.purpose}\n`;
    }
  }

  context += `\nActive Agents: ${params.activeAgents.length} total\n`;
  for (const [fw, count] of Object.entries(activeByFw)) {
    const profile = FRAMEWORK_PROFILES[fw as C2FrameworkType];
    if (profile) context += `  - ${profile.displayName}: ${count} agents\n`;
  }

  if (recommendation.suggestedModules.length > 0) {
    context += `\nSuggested Modules for ${params.engagementPhase}:\n`;
    for (const mod of recommendation.suggestedModules) {
      context += `  - ${mod}\n`;
    }
  }

  if (recommendation.opsecWarnings.length > 0) {
    context += `\nOPSEC Warnings:\n`;
    for (const warning of recommendation.opsecWarnings) {
      context += `  ⚠ ${warning}\n`;
    }
  }

  if (params.threatActorToEmulate) {
    context += `\nEmulating: ${params.threatActorToEmulate} — use their known TTPs and tooling patterns.\n`;
  }

  return context;
}

// ─── Exports ────────────────────────────────────────────────────────────────

export { FRAMEWORK_PROFILES };
export type { C2FrameworkProfile as FrameworkProfile };
