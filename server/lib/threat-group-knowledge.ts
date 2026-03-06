/**
 * Threat Group Knowledge Module
 * 
 * Maps APT, ransomware, cybercrime, and hacktivist groups to their preferred
 * TTPs, tools, target sectors, and defensive recommendations. Provides
 * structured context for LLM-powered hunt hypothesis generation, scan plan
 * optimization, and threat-informed defense prioritization.
 * 
 * Sources: MITRE ATT&CK, SOCRadar, Arctic Wolf, Bitsight, CISA advisories
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export type ThreatGroupType = "apt" | "ransomware" | "cybercrime" | "hacktivist";
export type ThreatLevel = "critical" | "high" | "medium" | "low";

export interface ThreatGroupTTP {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  description: string;
  /** How commonly this group uses this TTP: primary, secondary, occasional */
  frequency: "primary" | "secondary" | "occasional";
}

export interface ThreatGroupTool {
  name: string;
  category: "malware" | "rat" | "c2" | "exploit" | "credential" | "lateral" | "exfiltration" | "persistence" | "recon" | "living-off-the-land";
  description: string;
}

export interface DefenseRecommendation {
  priority: "critical" | "high" | "medium";
  category: "detection" | "prevention" | "monitoring" | "hardening";
  recommendation: string;
  siemQuery?: string;
  mitreTechniques: string[];
}

export interface ThreatGroupKnowledge {
  id: string;
  name: string;
  aliases: string[];
  type: ThreatGroupType;
  origin: string;
  threatLevel: ThreatLevel;
  active: boolean;
  description: string;
  motivation: string;
  targetSectors: string[];
  targetRegions: string[];
  ttps: ThreatGroupTTP[];
  tools: ThreatGroupTool[];
  initialAccessMethods: string[];
  defenseRecommendations: DefenseRecommendation[];
  /** Detection signatures / YARA / Sigma rule hints */
  detectionHints: string[];
  /** Known CVEs exploited by this group */
  exploitedCVEs: string[];
  /** MITRE ATT&CK Group ID (e.g., G0016) */
  mitreGroupId?: string;
}

export interface SectorThreatProfile {
  sector: string;
  topGroups: string[];
  commonTTPs: string[];
  priorityDefenses: string[];
}

// ─── APT Groups ─────────────────────────────────────────────────────────────

const APT_GROUPS: ThreatGroupKnowledge[] = [
  {
    id: "apt29",
    name: "APT29 / Cozy Bear",
    aliases: ["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard", "YTTRIUM"],
    type: "apt",
    origin: "Russia (SVR)",
    threatLevel: "critical",
    active: true,
    description: "Russian SVR-affiliated group known for sophisticated supply chain attacks, cloud exploitation, and long-term espionage operations against government and technology targets.",
    motivation: "Espionage, intelligence collection",
    targetSectors: ["government", "technology", "think-tanks", "healthcare", "energy", "defense"],
    targetRegions: ["USA", "Europe", "NATO countries", "Ukraine"],
    ttps: [
      { techniqueId: "T1195.002", techniqueName: "Supply Chain Compromise: Compromise Software Supply Chain", tactic: "initial-access", description: "SolarWinds Orion compromise", frequency: "primary" },
      { techniqueId: "T1078.004", techniqueName: "Valid Accounts: Cloud Accounts", tactic: "initial-access", description: "Device code authentication abuse, OAuth token theft", frequency: "primary" },
      { techniqueId: "T1566.002", techniqueName: "Phishing: Spearphishing Link", tactic: "initial-access", description: "Watering hole campaigns with targeted links", frequency: "primary" },
      { techniqueId: "T1098", techniqueName: "Account Manipulation", tactic: "persistence", description: "Federated trust manipulation, SAML token forging (Golden SAML)", frequency: "primary" },
      { techniqueId: "T1550.001", techniqueName: "Use Alternate Authentication Material: Application Access Token", tactic: "defense-evasion", description: "OAuth token abuse for persistent access", frequency: "primary" },
      { techniqueId: "T1071.001", techniqueName: "Application Layer Protocol: Web Protocols", tactic: "command-and-control", description: "HTTPS-based C2 blending with legitimate traffic", frequency: "secondary" },
      { techniqueId: "T1567.002", techniqueName: "Exfiltration Over Web Service: Exfiltration to Cloud Storage", tactic: "exfiltration", description: "Data exfiltration via cloud services", frequency: "secondary" },
      { techniqueId: "T1059.001", techniqueName: "Command and Scripting Interpreter: PowerShell", tactic: "execution", description: "PowerShell for payload execution and recon", frequency: "secondary" },
      { techniqueId: "T1087.004", techniqueName: "Account Discovery: Cloud Account", tactic: "discovery", description: "Enumerating cloud accounts and permissions", frequency: "secondary" },
      { techniqueId: "T1114.002", techniqueName: "Email Collection: Remote Email Collection", tactic: "collection", description: "Accessing email via Graph API or EWS", frequency: "primary" },
    ],
    tools: [
      { name: "SUNBURST", category: "malware", description: "SolarWinds backdoor for initial access and C2" },
      { name: "TEARDROP", category: "malware", description: "Memory-only dropper for Cobalt Strike" },
      { name: "Cobalt Strike", category: "c2", description: "Commercial C2 framework for post-exploitation" },
      { name: "EnvyScout", category: "malware", description: "HTML smuggling tool for initial payload delivery" },
      { name: "FoggyWeb", category: "malware", description: "AD FS backdoor for token theft" },
      { name: "MagicWeb", category: "malware", description: "AD FS DLL replacement for authentication bypass" },
    ],
    initialAccessMethods: ["Supply chain compromise", "Spearphishing", "Device code phishing", "Watering hole attacks", "Credential stuffing against cloud services"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor Azure AD sign-in logs for device code authentication flows from unusual locations", siemQuery: "index=azure sourcetype=azure:aad:signin properties.authenticationProtocol=deviceCode | stats count by properties.userPrincipalName, properties.ipAddress", mitreTechniques: ["T1078.004"] },
      { priority: "critical", category: "detection", recommendation: "Alert on new federation trust configurations in Azure AD/Entra ID", siemQuery: "index=azure sourcetype=azure:aad:audit operationName=\"Set federation settings on domain\" | table _time, initiatedBy.user.userPrincipalName, targetResources{}.displayName", mitreTechniques: ["T1098"] },
      { priority: "critical", category: "prevention", recommendation: "Enforce conditional access policies requiring managed devices and MFA for all cloud access", mitreTechniques: ["T1078.004", "T1550.001"] },
      { priority: "high", category: "monitoring", recommendation: "Monitor for anomalous Graph API access patterns, especially bulk email reads", siemQuery: "index=o365 sourcetype=o365:management:activity Operation=MailItemsAccessed | stats count by UserId, ClientIPAddress | where count > 1000", mitreTechniques: ["T1114.002"] },
      { priority: "high", category: "hardening", recommendation: "Implement SAML token lifetime policies and certificate rotation for AD FS", mitreTechniques: ["T1098"] },
    ],
    detectionHints: [
      "YARA: rule SUNBURST { strings: $api = \"OrionImprovementBusinessLayer\" }",
      "Sigma: title: Device Code Phishing Detection; logsource: product: azure; detection: authProtocol: deviceCode",
      "Monitor for anomalous OAuth application consent grants",
      "Alert on SAML token signing certificate changes",
    ],
    exploitedCVEs: ["CVE-2020-14882", "CVE-2021-21972", "CVE-2021-26855", "CVE-2023-42793"],
    mitreGroupId: "G0016",
  },
  {
    id: "volt_typhoon",
    name: "Volt Typhoon",
    aliases: ["VANGUARD PANDA", "Bronze Silhouette", "DEV-0391", "Insidious Taurus"],
    type: "apt",
    origin: "China (PLA/MSS)",
    threatLevel: "critical",
    active: true,
    description: "Chinese state-sponsored group targeting US critical infrastructure using living-off-the-land techniques to pre-position for potential disruptive attacks.",
    motivation: "Pre-positioning for disruption, espionage",
    targetSectors: ["critical-infrastructure", "telecommunications", "energy", "water", "transportation", "government"],
    targetRegions: ["USA", "Guam", "Pacific Islands"],
    ttps: [
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Exploitation of Fortinet, Zoho, Citrix, and SOHO routers", frequency: "primary" },
      { techniqueId: "T1133", techniqueName: "External Remote Services", tactic: "initial-access", description: "VPN and remote access exploitation", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "Living-off-the-land PowerShell usage", frequency: "primary" },
      { techniqueId: "T1218", techniqueName: "System Binary Proxy Execution", tactic: "defense-evasion", description: "Using wmic, certutil, ntdsutil for evasion", frequency: "primary" },
      { techniqueId: "T1003.003", techniqueName: "OS Credential Dumping: NTDS", tactic: "credential-access", description: "ntdsutil for Active Directory credential extraction", frequency: "primary" },
      { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "persistence", description: "Using compromised credentials for long-term access", frequency: "primary" },
      { techniqueId: "T1090.001", techniqueName: "Proxy: Internal Proxy", tactic: "command-and-control", description: "SOHO router botnets for C2 proxying", frequency: "primary" },
      { techniqueId: "T1046", techniqueName: "Network Service Discovery", tactic: "discovery", description: "Internal network scanning via native tools", frequency: "secondary" },
      { techniqueId: "T1021.002", techniqueName: "Remote Services: SMB/Windows Admin Shares", tactic: "lateral-movement", description: "Lateral movement via SMB", frequency: "secondary" },
    ],
    tools: [
      { name: "wmic.exe", category: "living-off-the-land", description: "WMI command-line for remote execution" },
      { name: "ntdsutil.exe", category: "credential", description: "AD database extraction tool" },
      { name: "certutil.exe", category: "living-off-the-land", description: "Certificate utility for file download/encoding" },
      { name: "netsh.exe", category: "living-off-the-land", description: "Network configuration and port forwarding" },
      { name: "PowerShell", category: "living-off-the-land", description: "Script execution and recon" },
      { name: "Impacket", category: "lateral", description: "Python tools for SMB/WMI lateral movement" },
      { name: "FRP (Fast Reverse Proxy)", category: "c2", description: "Open-source reverse proxy for tunneling" },
    ],
    initialAccessMethods: ["Exploitation of edge devices (Fortinet, Citrix, SOHO routers)", "VPN credential compromise", "Zero-day exploitation"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor for living-off-the-land binary usage: wmic, certutil, ntdsutil, netsh in unusual contexts", siemQuery: "index=windows sourcetype=WinEventLog:Sysmon EventCode=1 (Image=\"*\\\\wmic.exe\" OR Image=\"*\\\\certutil.exe\" OR Image=\"*\\\\ntdsutil.exe\") | stats count by Image, CommandLine, User, Computer", mitreTechniques: ["T1218", "T1003.003"] },
      { priority: "critical", category: "hardening", recommendation: "Patch all edge devices (Fortinet, Citrix, SOHO routers) immediately and implement network segmentation", mitreTechniques: ["T1190", "T1133"] },
      { priority: "critical", category: "detection", recommendation: "Alert on NTDS.dit access or volume shadow copy creation targeting system state", siemQuery: "index=windows sourcetype=WinEventLog:Security EventCode=4663 ObjectName=\"*ntds.dit*\" OR (EventCode=1 CommandLine=\"*vssadmin*\" CommandLine=\"*ntds*\")", mitreTechniques: ["T1003.003"] },
      { priority: "high", category: "monitoring", recommendation: "Monitor SOHO router traffic for unusual outbound connections that may indicate botnet C2", mitreTechniques: ["T1090.001"] },
      { priority: "high", category: "prevention", recommendation: "Implement application allowlisting to prevent unauthorized LOLBin execution", mitreTechniques: ["T1218"] },
    ],
    detectionHints: [
      "Sigma: title: Volt Typhoon LOLBin Chain; logsource: product: windows, service: sysmon; detection: certutil AND (encode OR decode OR urlcache)",
      "Monitor for ntdsutil.exe creating IFM snapshots",
      "Alert on PowerShell commands with encoded payloads from service accounts",
      "Track SOHO router firmware versions and patch status",
    ],
    exploitedCVEs: ["CVE-2021-40539", "CVE-2021-27860", "CVE-2023-27997", "CVE-2024-21887", "CVE-2023-46805"],
    mitreGroupId: "G1017",
  },
  {
    id: "apt41",
    name: "APT41 / Double Dragon",
    aliases: ["Double Dragon", "Winnti", "Barium", "Wicked Panda", "BRASS TYPHOON"],
    type: "apt",
    origin: "China",
    threatLevel: "critical",
    active: true,
    description: "Dual-mission Chinese group conducting both state-sponsored espionage and financially motivated cybercrime, known for supply chain attacks and sophisticated custom malware.",
    motivation: "Espionage + financial gain",
    targetSectors: ["technology", "healthcare", "gaming", "telecommunications", "education", "manufacturing"],
    targetRegions: ["USA", "Europe", "Asia-Pacific", "Global"],
    ttps: [
      { techniqueId: "T1195.002", techniqueName: "Supply Chain Compromise", tactic: "initial-access", description: "Compromising software update mechanisms (CCleaner, ASUS)", frequency: "primary" },
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Web application exploitation, SQL injection", frequency: "primary" },
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Targeted phishing with weaponized documents", frequency: "secondary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for payload execution", frequency: "primary" },
      { techniqueId: "T1055", techniqueName: "Process Injection", tactic: "defense-evasion", description: "DLL injection and process hollowing", frequency: "primary" },
      { techniqueId: "T1003", techniqueName: "OS Credential Dumping", tactic: "credential-access", description: "Mimikatz and custom credential harvesters", frequency: "primary" },
      { techniqueId: "T1021.001", techniqueName: "Remote Desktop Protocol", tactic: "lateral-movement", description: "RDP for lateral movement", frequency: "secondary" },
      { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control", description: "HTTPS C2 with custom protocols", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "Ransomware deployment for financial gain", frequency: "occasional" },
    ],
    tools: [
      { name: "ShadowPad", category: "malware", description: "Modular backdoor platform shared among Chinese APTs" },
      { name: "Winnti", category: "malware", description: "Custom backdoor for long-term persistence" },
      { name: "PlugX", category: "rat", description: "Remote access trojan with DLL sideloading" },
      { name: "Cobalt Strike", category: "c2", description: "Commercial C2 framework" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction tool" },
      { name: "China Chopper", category: "malware", description: "Web shell for web server persistence" },
      { name: "Deadeye", category: "malware", description: "Custom downloader for payload delivery" },
    ],
    initialAccessMethods: ["Supply chain compromise", "Spearphishing", "Web application exploitation", "SQL injection", "Zero-day exploitation"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor for DLL sideloading patterns associated with PlugX and ShadowPad", siemQuery: "index=windows sourcetype=WinEventLog:Sysmon EventCode=7 (ImageLoaded=\"*\\\\log.dll\" OR ImageLoaded=\"*\\\\http_dll.dll\") NOT (Image=\"*\\\\system32\\\\*\")", mitreTechniques: ["T1055", "T1574.002"] },
      { priority: "critical", category: "prevention", recommendation: "Verify software supply chain integrity with code signing validation and SBOMs", mitreTechniques: ["T1195.002"] },
      { priority: "high", category: "detection", recommendation: "Alert on China Chopper web shell indicators (eval/base64 in HTTP POST bodies)", siemQuery: "index=web sourcetype=access_combined method=POST | regex _raw=\"(eval|base64_decode|cmd\\.exe|/bin/sh)\" | stats count by src_ip, uri_path", mitreTechniques: ["T1505.003"] },
      { priority: "high", category: "monitoring", recommendation: "Monitor for unusual process injection patterns, especially into legitimate system processes", mitreTechniques: ["T1055"] },
    ],
    detectionHints: [
      "YARA: rule ShadowPad { strings: $config = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 } }",
      "Monitor for DLL sideloading in non-standard directories",
      "Alert on web shells in IIS/Apache directories",
      "Track SQL injection attempts against public-facing applications",
    ],
    exploitedCVEs: ["CVE-2019-3396", "CVE-2020-10189", "CVE-2021-44228", "CVE-2021-26855", "CVE-2023-22515"],
    mitreGroupId: "G0096",
  },
  {
    id: "lazarus",
    name: "Lazarus Group",
    aliases: ["APT38", "Hidden Cobra", "Zinc", "Diamond Sleet", "Labyrinth Chollima"],
    type: "apt",
    origin: "North Korea (RGB)",
    threatLevel: "critical",
    active: true,
    description: "North Korean state-sponsored group conducting espionage, financial theft (cryptocurrency), and destructive attacks. Known for sophisticated social engineering and supply chain attacks.",
    motivation: "Financial theft, espionage, disruption",
    targetSectors: ["cryptocurrency", "financial", "defense", "aerospace", "technology", "media"],
    targetRegions: ["USA", "South Korea", "Japan", "Global"],
    ttps: [
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Fake job offers with weaponized documents (Operation Dream Job)", frequency: "primary" },
      { techniqueId: "T1566.002", techniqueName: "Spearphishing Link", tactic: "initial-access", description: "Social engineering via LinkedIn/GitHub", frequency: "primary" },
      { techniqueId: "T1195.002", techniqueName: "Supply Chain Compromise", tactic: "initial-access", description: "npm/PyPI package poisoning, 3CX compromise", frequency: "primary" },
      { techniqueId: "T1059.007", techniqueName: "JavaScript", tactic: "execution", description: "Node.js and Electron app exploitation", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for payload delivery", frequency: "secondary" },
      { techniqueId: "T1055", techniqueName: "Process Injection", tactic: "defense-evasion", description: "Custom injection techniques", frequency: "secondary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "WannaCry and targeted ransomware", frequency: "occasional" },
      { techniqueId: "T1485", techniqueName: "Data Destruction", tactic: "impact", description: "Disk wipers (Sony Pictures attack)", frequency: "occasional" },
      { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control", description: "HTTPS C2 with custom encryption", frequency: "primary" },
      { techniqueId: "T1496", techniqueName: "Resource Hijacking", tactic: "impact", description: "Cryptocurrency mining on compromised systems", frequency: "secondary" },
    ],
    tools: [
      { name: "BLINDINGCAN", category: "rat", description: "Full-featured RAT with C2 capabilities" },
      { name: "AppleJeus", category: "malware", description: "Trojanized cryptocurrency trading applications" },
      { name: "HOPLIGHT", category: "malware", description: "Proxy-based backdoor for tunneling" },
      { name: "DTrack", category: "rat", description: "Modular RAT for espionage operations" },
      { name: "Mimikatz", category: "credential", description: "Credential dumping" },
      { name: "Custom cryptocurrency stealers", category: "malware", description: "Browser extension and wallet targeting malware" },
    ],
    initialAccessMethods: ["Fake job offers via LinkedIn", "Supply chain compromise (npm, 3CX)", "Trojanized cryptocurrency apps", "Spearphishing with weaponized docs"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor for trojanized npm/PyPI packages and unusual Node.js process spawning", siemQuery: "index=endpoint sourcetype=sysmon EventCode=1 (Image=\"*node.exe\" OR Image=\"*npm*\") (CommandLine=\"*eval*\" OR CommandLine=\"*child_process*\" OR CommandLine=\"*net.Socket*\")", mitreTechniques: ["T1195.002", "T1059.007"] },
      { priority: "critical", category: "prevention", recommendation: "Implement cryptocurrency wallet security: hardware wallets, transaction signing verification, browser extension auditing", mitreTechniques: ["T1566.001"] },
      { priority: "high", category: "detection", recommendation: "Alert on LinkedIn/social media-sourced executables and documents", siemQuery: "index=endpoint sourcetype=sysmon EventCode=1 (CommandLine=\"*LinkedIn*\" OR CommandLine=\"*job*offer*\") (Image=\"*.exe\" OR Image=\"*.scr\")", mitreTechniques: ["T1566.001", "T1566.002"] },
      { priority: "high", category: "monitoring", recommendation: "Monitor for unusual outbound connections from cryptocurrency-related applications", mitreTechniques: ["T1071.001"] },
    ],
    detectionHints: [
      "YARA: rule AppleJeus { strings: $s1 = \"CryptoCurrencyTrader\" $s2 = \"celasllc.com\" }",
      "Monitor npm audit for known malicious packages",
      "Alert on Electron apps spawning cmd.exe or PowerShell",
      "Track cryptocurrency wallet file access patterns",
    ],
    exploitedCVEs: ["CVE-2017-0144", "CVE-2021-44228", "CVE-2022-47966", "CVE-2023-42793"],
    mitreGroupId: "G0032",
  },
  {
    id: "sandworm",
    name: "Sandworm",
    aliases: ["APT44", "Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Telebots"],
    type: "apt",
    origin: "Russia (GRU Unit 74455)",
    threatLevel: "critical",
    active: true,
    description: "Russian GRU unit responsible for the most destructive cyberattacks in history including NotPetya, BlackEnergy power grid attacks, and Olympic Destroyer. Specializes in ICS/SCADA targeting.",
    motivation: "Disruption, sabotage, espionage",
    targetSectors: ["energy", "critical-infrastructure", "government", "media", "transportation", "financial"],
    targetRegions: ["Ukraine", "Europe", "USA", "Global"],
    ttps: [
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Exploitation of web servers and edge devices", frequency: "primary" },
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Weaponized documents targeting energy sector", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for payload execution", frequency: "primary" },
      { techniqueId: "T1485", techniqueName: "Data Destruction", tactic: "impact", description: "Wiper malware (CaddyWiper, ZeroLot, HermeticWiper)", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "NotPetya pseudo-ransomware for destruction", frequency: "primary" },
      { techniqueId: "T1495", techniqueName: "Firmware Corruption", tactic: "impact", description: "ICS/SCADA firmware attacks on power grid", frequency: "primary" },
      { techniqueId: "T1003", techniqueName: "OS Credential Dumping", tactic: "credential-access", description: "Mimikatz and custom credential harvesters", frequency: "secondary" },
      { techniqueId: "T1021.002", techniqueName: "SMB/Windows Admin Shares", tactic: "lateral-movement", description: "WMI and SMB for lateral movement", frequency: "secondary" },
    ],
    tools: [
      { name: "BlackEnergy", category: "malware", description: "ICS-targeting malware for power grid attacks" },
      { name: "Industroyer/CrashOverride", category: "malware", description: "ICS protocol exploitation (IEC 104, IEC 61850)" },
      { name: "NotPetya", category: "malware", description: "Destructive wiper disguised as ransomware" },
      { name: "CaddyWiper", category: "malware", description: "Data destruction wiper" },
      { name: "HermeticWiper", category: "malware", description: "MBR/partition destruction" },
      { name: "Olympic Destroyer", category: "malware", description: "False-flag destructive malware" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction" },
    ],
    initialAccessMethods: ["Spearphishing", "Web application exploitation", "Supply chain compromise", "VPN exploitation"],
    defenseRecommendations: [
      { priority: "critical", category: "prevention", recommendation: "Segment ICS/SCADA networks from IT networks with unidirectional gateways", mitreTechniques: ["T1495"] },
      { priority: "critical", category: "detection", recommendation: "Monitor for wiper indicators: MBR overwrites, mass file deletion, volume shadow copy deletion", siemQuery: "index=windows (EventCode=1 CommandLine=\"*vssadmin*delete*shadows*\") OR (EventCode=4663 ObjectName=\"*\\\\PhysicalDrive0*\") | stats count by Computer, User, CommandLine", mitreTechniques: ["T1485", "T1490"] },
      { priority: "critical", category: "hardening", recommendation: "Implement offline backups with air-gapped storage for critical systems", mitreTechniques: ["T1485", "T1486"] },
      { priority: "high", category: "detection", recommendation: "Alert on ICS protocol anomalies (IEC 104, Modbus, DNP3)", mitreTechniques: ["T1495"] },
    ],
    detectionHints: [
      "YARA: rule Industroyer2 { strings: $s1 = \"IEC-104\" $s2 = \"ASDU\" }",
      "Monitor for mass file operations (>1000 files/minute) on critical servers",
      "Alert on MBR/VBR write operations",
      "Track ICS protocol traffic for anomalous commands",
    ],
    exploitedCVEs: ["CVE-2017-0144", "CVE-2017-0145", "CVE-2021-40444", "CVE-2023-38831"],
    mitreGroupId: "G0034",
  },
  {
    id: "apt28",
    name: "APT28 / Fancy Bear",
    aliases: ["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "Forest Blizzard", "STRONTIUM"],
    type: "apt",
    origin: "Russia (GRU Unit 26165)",
    threatLevel: "critical",
    active: true,
    description: "Russian GRU military intelligence unit conducting espionage, influence operations, and hack-and-leak campaigns against government, military, and political targets.",
    motivation: "Espionage, influence operations",
    targetSectors: ["government", "military", "defense", "media", "political-organizations", "sports"],
    targetRegions: ["USA", "Europe", "NATO countries", "Ukraine", "Georgia"],
    ttps: [
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Weaponized Office documents with macros", frequency: "primary" },
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Exploitation of email servers (Exchange, Zimbra)", frequency: "primary" },
      { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "initial-access", description: "Credential harvesting via fake login pages", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for execution and recon", frequency: "primary" },
      { techniqueId: "T1003.001", techniqueName: "LSASS Memory", tactic: "credential-access", description: "Mimikatz for LSASS credential extraction", frequency: "primary" },
      { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control", description: "HTTPS C2 with legitimate service impersonation", frequency: "primary" },
      { techniqueId: "T1567", techniqueName: "Exfiltration Over Web Service", tactic: "exfiltration", description: "Data exfiltration via cloud services and email", frequency: "secondary" },
      { techniqueId: "T1583.001", techniqueName: "Acquire Infrastructure: Domains", tactic: "resource-development", description: "Typosquatting domains for credential harvesting", frequency: "primary" },
    ],
    tools: [
      { name: "XAgent/Sofacy", category: "rat", description: "Cross-platform RAT (Windows, Linux, iOS)" },
      { name: "Zebrocy", category: "malware", description: "Multi-language downloader (Delphi, Go, C#)" },
      { name: "GoDownloader", category: "malware", description: "Go-based downloader for second-stage payloads" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction" },
      { name: "Responder", category: "credential", description: "LLMNR/NBT-NS poisoning for credential capture" },
      { name: "Cobalt Strike", category: "c2", description: "Commercial C2 framework" },
    ],
    initialAccessMethods: ["Spearphishing with weaponized documents", "Credential harvesting via fake login portals", "Zero-day exploitation", "VPN/email server exploitation"],
    defenseRecommendations: [
      { priority: "critical", category: "prevention", recommendation: "Implement FIDO2/hardware security keys for all privileged accounts to prevent credential phishing", mitreTechniques: ["T1078", "T1566.001"] },
      { priority: "critical", category: "detection", recommendation: "Monitor for typosquatting domains impersonating your organization's login portals", siemQuery: "index=dns sourcetype=dns query=\"*\" | eval similarity=mvfind(query, \"yourdomain\") | where similarity > 0.8", mitreTechniques: ["T1583.001"] },
      { priority: "high", category: "detection", recommendation: "Alert on Responder/LLMNR poisoning activity on the network", siemQuery: "index=network sourcetype=bro_dns query_type=LLMNR | stats count by src_ip, query | where count > 50", mitreTechniques: ["T1557.001"] },
    ],
    detectionHints: [
      "Sigma: title: XAgent C2 Communication; logsource: product: windows, service: sysmon; detection: dns query containing known XAgent C2 patterns",
      "Monitor for Office documents with VBA macros from external senders",
      "Alert on LLMNR/NBT-NS traffic in environments where it should be disabled",
    ],
    exploitedCVEs: ["CVE-2017-0262", "CVE-2017-0263", "CVE-2023-23397", "CVE-2023-38831"],
    mitreGroupId: "G0007",
  },
  {
    id: "salt_typhoon",
    name: "Salt Typhoon",
    aliases: ["GhostEmperor", "FamousSparrow", "Earth Estries", "UNC2286"],
    type: "apt",
    origin: "China (MSS)",
    threatLevel: "critical",
    active: true,
    description: "Chinese state-sponsored group that compromised major US telecommunications providers (AT&T, Verizon, T-Mobile) in 2024, accessing lawful intercept systems and call metadata.",
    motivation: "Espionage, signals intelligence",
    targetSectors: ["telecommunications", "ISP", "government", "technology"],
    targetRegions: ["USA", "Southeast Asia", "Europe"],
    ttps: [
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Exploitation of telecom infrastructure (Cisco IOS XE, Barracuda ESG)", frequency: "primary" },
      { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "persistence", description: "Compromised admin credentials for telecom infrastructure", frequency: "primary" },
      { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "credential-access", description: "Intercepting lawful intercept systems", frequency: "primary" },
      { techniqueId: "T1040", techniqueName: "Network Sniffing", tactic: "credential-access", description: "Passive interception of network traffic", frequency: "primary" },
      { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "collection", description: "Call detail records and metadata collection", frequency: "primary" },
      { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control", description: "Encrypted C2 channels", frequency: "secondary" },
    ],
    tools: [
      { name: "GhostEmperor rootkit", category: "malware", description: "Kernel-level rootkit for persistence" },
      { name: "Demodex", category: "malware", description: "Windows kernel rootkit" },
      { name: "Custom telecom implants", category: "malware", description: "Purpose-built for telecom infrastructure" },
    ],
    initialAccessMethods: ["Telecom infrastructure exploitation", "Edge device zero-days", "Compromised admin credentials"],
    defenseRecommendations: [
      { priority: "critical", category: "hardening", recommendation: "Implement end-to-end encryption for all communications; do not rely on carrier-level encryption", mitreTechniques: ["T1557", "T1040"] },
      { priority: "critical", category: "detection", recommendation: "Monitor telecom infrastructure for unauthorized access to lawful intercept systems", mitreTechniques: ["T1557"] },
      { priority: "high", category: "hardening", recommendation: "Patch Cisco IOS XE, Barracuda ESG, and all edge networking equipment immediately", mitreTechniques: ["T1190"] },
    ],
    detectionHints: [
      "Monitor for unauthorized access to CALEA/lawful intercept systems",
      "Alert on kernel driver installations on telecom infrastructure",
      "Track admin account usage patterns on network equipment",
    ],
    exploitedCVEs: ["CVE-2023-20198", "CVE-2023-20273", "CVE-2023-2868"],
    mitreGroupId: "G1045",
  },
  {
    id: "apt34",
    name: "APT34 / OilRig",
    aliases: ["OilRig", "Helix Kitten", "Hazel Sandstorm", "EUROPIUM", "Crambus"],
    type: "apt",
    origin: "Iran (MOIS)",
    threatLevel: "high",
    active: true,
    description: "Iranian intelligence group targeting Middle Eastern governments, energy, and financial sectors using custom backdoors and DNS-based exfiltration.",
    motivation: "Espionage, regional intelligence",
    targetSectors: ["government", "energy", "financial", "telecommunications", "chemical"],
    targetRegions: ["Middle East", "USA", "Europe"],
    ttps: [
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Weaponized Office documents with macros", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell-based backdoors and downloaders", frequency: "primary" },
      { techniqueId: "T1071.004", techniqueName: "DNS", tactic: "command-and-control", description: "DNS tunneling for C2 and exfiltration", frequency: "primary" },
      { techniqueId: "T1048.003", techniqueName: "Exfiltration Over Unencrypted Non-C2 Protocol", tactic: "exfiltration", description: "DNS and email-based exfiltration", frequency: "primary" },
      { techniqueId: "T1505.003", techniqueName: "Web Shell", tactic: "persistence", description: "Web shells on compromised servers", frequency: "secondary" },
      { techniqueId: "T1003", techniqueName: "OS Credential Dumping", tactic: "credential-access", description: "Mimikatz and custom credential tools", frequency: "secondary" },
    ],
    tools: [
      { name: "POWBAT", category: "rat", description: "PowerShell-based backdoor" },
      { name: "BONDUPDATER", category: "malware", description: "DNS-based C2 backdoor" },
      { name: "Karkoff", category: "malware", description: "Lightweight backdoor using Exchange for C2" },
      { name: "SideTwist", category: "malware", description: "Custom backdoor with HTTP C2" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction" },
    ],
    initialAccessMethods: ["Spearphishing", "Web application exploitation", "Credential harvesting"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor DNS traffic for tunneling indicators: high query volume, long subdomain labels, TXT record abuse", siemQuery: "index=dns sourcetype=dns | eval label_len=len(mvindex(split(query,\".\"),0)) | where label_len > 40 | stats count by src_ip, query", mitreTechniques: ["T1071.004", "T1048.003"] },
      { priority: "high", category: "prevention", recommendation: "Block DNS over HTTPS (DoH) and enforce DNS through monitored resolvers", mitreTechniques: ["T1071.004"] },
    ],
    detectionHints: [
      "Monitor for unusually long DNS subdomain labels (>40 chars)",
      "Alert on high-volume TXT record queries to single domains",
      "Track PowerShell execution with encoded commands from Office processes",
    ],
    exploitedCVEs: ["CVE-2017-11882", "CVE-2019-0604", "CVE-2021-26855"],
    mitreGroupId: "G0049",
  },
  {
    id: "mustang_panda",
    name: "Mustang Panda",
    aliases: ["TA416", "RedDelta", "Bronze President", "Earth Preta", "Stately Taurus"],
    type: "apt",
    origin: "China",
    threatLevel: "high",
    active: true,
    description: "Chinese espionage group targeting government and NGO organizations, known for PlugX malware and sophisticated social engineering with geopolitical lures.",
    motivation: "Espionage",
    targetSectors: ["government", "NGO", "think-tanks", "telecommunications", "education"],
    targetRegions: ["Southeast Asia", "Europe", "USA", "Mongolia", "Myanmar"],
    ttps: [
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Geopolitical-themed lure documents", frequency: "primary" },
      { techniqueId: "T1574.002", techniqueName: "DLL Side-Loading", tactic: "defense-evasion", description: "PlugX delivery via DLL sideloading", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for payload staging", frequency: "secondary" },
      { techniqueId: "T1547.001", techniqueName: "Registry Run Keys", tactic: "persistence", description: "Registry-based persistence", frequency: "primary" },
      { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control", description: "HTTPS C2 with custom PlugX protocol", frequency: "primary" },
      { techniqueId: "T1560.001", techniqueName: "Archive via Utility", tactic: "collection", description: "RAR archiving of collected data", frequency: "secondary" },
    ],
    tools: [
      { name: "PlugX", category: "rat", description: "Modular RAT with DLL sideloading" },
      { name: "Poison Ivy", category: "rat", description: "Legacy RAT still in active use" },
      { name: "Cobalt Strike", category: "c2", description: "Commercial C2 framework" },
      { name: "TONESHELL", category: "malware", description: "Custom backdoor" },
    ],
    initialAccessMethods: ["Spearphishing with geopolitical lures", "USB-based delivery", "Watering hole attacks"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor for DLL sideloading patterns: legitimate executables loading unsigned DLLs from unusual paths", siemQuery: "index=windows sourcetype=WinEventLog:Sysmon EventCode=7 Signed=false | where NOT match(ImageLoaded, \"system32|syswow64|program files\")", mitreTechniques: ["T1574.002"] },
      { priority: "high", category: "prevention", recommendation: "Disable USB autorun and implement USB device control policies", mitreTechniques: ["T1091"] },
    ],
    detectionHints: [
      "YARA: rule PlugX_Loader { strings: $mz = { 4D 5A } $config = { 58 58 58 58 58 58 58 58 } }",
      "Monitor for legitimate executables (e.g., Adobe, Google) loading DLLs from temp/user directories",
    ],
    exploitedCVEs: ["CVE-2017-0199", "CVE-2017-11882", "CVE-2022-30190"],
    mitreGroupId: "G0129",
  },
  {
    id: "apt36",
    name: "APT36 / Transparent Tribe",
    aliases: ["Transparent Tribe", "ProjectM", "Mythic Leopard", "Earth Karkaddan"],
    type: "apt",
    origin: "Pakistan (ISI-linked)",
    threatLevel: "high",
    active: true,
    description: "Pakistani state-linked group primarily targeting Indian military and government with custom RATs, fake document lures, and Linux-targeting capabilities.",
    motivation: "Espionage, military intelligence",
    targetSectors: ["military", "government", "defense", "education"],
    targetRegions: ["India", "Afghanistan", "South Asia"],
    ttps: [
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Fake PDF documents with embedded payloads", frequency: "primary" },
      { techniqueId: "T1204.002", techniqueName: "User Execution: Malicious File", tactic: "execution", description: ".desktop file abuse on Linux targets", frequency: "primary" },
      { techniqueId: "T1059.004", techniqueName: "Unix Shell", tactic: "execution", description: "Bash payloads for Linux targets", frequency: "primary" },
      { techniqueId: "T1071.004", techniqueName: "DNS", tactic: "command-and-control", description: "DNS and UDP-based C2", frequency: "primary" },
      { techniqueId: "T1053.003", techniqueName: "Cron", tactic: "persistence", description: "Cron-based persistence on Linux", frequency: "secondary" },
      { techniqueId: "T1543.002", techniqueName: "Systemd Service", tactic: "persistence", description: "Systemd service persistence", frequency: "secondary" },
    ],
    tools: [
      { name: "CrimsonRAT", category: "rat", description: ".NET-based RAT for Windows" },
      { name: "ObliqueRAT", category: "rat", description: "C/C++ RAT with anti-analysis" },
      { name: "Poseidon", category: "rat", description: "Linux-targeting RAT" },
      { name: "Custom Android spyware", category: "malware", description: "Mobile surveillance tools" },
    ],
    initialAccessMethods: ["Spearphishing with fake government documents", "Watering hole attacks", "Trojanized mobile apps"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor for .desktop file creation in unusual locations on Linux systems", siemQuery: "index=linux sourcetype=auditd type=CREATE name=\"*.desktop\" | where NOT match(name, \"/usr/share/applications\")", mitreTechniques: ["T1204.002"] },
      { priority: "high", category: "detection", recommendation: "Alert on new cron jobs and systemd services created by non-root users", mitreTechniques: ["T1053.003", "T1543.002"] },
    ],
    detectionHints: [
      "YARA: rule CrimsonRAT { strings: $s1 = \"JEYZZ\" $s2 = \"getinfo\" }",
      "Monitor for DNS queries with encoded payloads in subdomain labels",
    ],
    exploitedCVEs: ["CVE-2017-0199", "CVE-2017-11882"],
    mitreGroupId: "G0134",
  },
];

// ─── Ransomware Groups ──────────────────────────────────────────────────────

const RANSOMWARE_GROUPS: ThreatGroupKnowledge[] = [
  {
    id: "lockbit",
    name: "LockBit 3.0",
    aliases: ["LockBit Black", "LockBit Green"],
    type: "ransomware",
    origin: "Russia-linked (RaaS)",
    threatLevel: "critical",
    active: true,
    description: "Most prolific ransomware-as-a-service operation with automated encryption, StealBit exfiltration, and a large affiliate network. Despite law enforcement disruptions, continues to operate.",
    motivation: "Financial extortion",
    targetSectors: ["healthcare", "manufacturing", "financial", "government", "education", "technology"],
    targetRegions: ["Global"],
    ttps: [
      { techniqueId: "T1133", techniqueName: "External Remote Services", tactic: "initial-access", description: "RDP/VPN brute-force and credential purchase from IABs", frequency: "primary" },
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Exploitation of known CVEs in VPNs and web apps", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for payload deployment and lateral movement", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "AES+RSA encryption with configurable exclusions", frequency: "primary" },
      { techniqueId: "T1490", techniqueName: "Inhibit System Recovery", tactic: "impact", description: "Shadow copy deletion, BCDEdit modification", frequency: "primary" },
      { techniqueId: "T1567.002", techniqueName: "Exfiltration to Cloud Storage", tactic: "exfiltration", description: "StealBit tool for automated data exfiltration", frequency: "primary" },
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "defense-evasion", description: "EDR/AV termination before encryption", frequency: "primary" },
      { techniqueId: "T1003", techniqueName: "OS Credential Dumping", tactic: "credential-access", description: "Mimikatz for credential harvesting", frequency: "secondary" },
      { techniqueId: "T1021.001", techniqueName: "Remote Desktop Protocol", tactic: "lateral-movement", description: "RDP for lateral movement", frequency: "secondary" },
    ],
    tools: [
      { name: "LockBit 3.0 encryptor", category: "malware", description: "Configurable ransomware with anti-analysis" },
      { name: "StealBit", category: "exfiltration", description: "Automated data exfiltration tool" },
      { name: "Cobalt Strike", category: "c2", description: "C2 framework for post-exploitation" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction" },
      { name: "PsExec", category: "lateral", description: "Remote execution for deployment" },
      { name: "AnyDesk/TeamViewer", category: "c2", description: "RMM tools for persistent access" },
    ],
    initialAccessMethods: ["RDP brute-force", "VPN exploitation", "Initial access broker purchases", "Phishing"],
    defenseRecommendations: [
      { priority: "critical", category: "prevention", recommendation: "Enforce MFA on all remote access (RDP, VPN, email) and disable RDP on internet-facing systems", mitreTechniques: ["T1133", "T1021.001"] },
      { priority: "critical", category: "detection", recommendation: "Monitor for shadow copy deletion and BCDEdit modifications", siemQuery: "index=windows sourcetype=WinEventLog:Sysmon EventCode=1 (CommandLine=\"*vssadmin*delete*\" OR CommandLine=\"*bcdedit*recoveryenabled*no*\" OR CommandLine=\"*wbadmin*delete*\")", mitreTechniques: ["T1490"] },
      { priority: "critical", category: "detection", recommendation: "Alert on EDR/AV service termination or tampering", siemQuery: "index=windows sourcetype=WinEventLog:System EventCode=7036 (param1=\"Windows Defender*\" OR param1=\"CrowdStrike*\" OR param1=\"Carbon Black*\") param2=\"stopped\"", mitreTechniques: ["T1562.001"] },
      { priority: "high", category: "hardening", recommendation: "Implement immutable backups with offline/air-gapped copies tested monthly", mitreTechniques: ["T1486", "T1490"] },
    ],
    detectionHints: [
      "Monitor for rapid file rename operations (>.lockbit extension)",
      "Alert on StealBit network signatures (high-volume outbound to Tor)",
      "Track PsExec deployment across multiple hosts simultaneously",
    ],
    exploitedCVEs: ["CVE-2021-22986", "CVE-2023-0669", "CVE-2023-4966", "CVE-2024-1709"],
  },
  {
    id: "blackcat",
    name: "ALPHV / BlackCat",
    aliases: ["BlackCat", "Noberus", "UNC4466"],
    type: "ransomware",
    origin: "Russia-linked (RaaS, ex-DarkSide/BlackMatter)",
    threatLevel: "critical",
    active: true,
    description: "Rust-based cross-platform ransomware with triple extortion (encrypt + leak + DDoS). Known for targeting healthcare and critical infrastructure with sophisticated access techniques.",
    motivation: "Financial extortion",
    targetSectors: ["healthcare", "financial", "critical-infrastructure", "legal", "technology"],
    targetRegions: ["USA", "Europe", "Global"],
    ttps: [
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Exploitation of Exchange, VPN, and web applications", frequency: "primary" },
      { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "initial-access", description: "Purchased credentials from IABs", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "Rust-based cross-platform encryption (Windows, Linux, ESXi)", frequency: "primary" },
      { techniqueId: "T1567", techniqueName: "Exfiltration Over Web Service", tactic: "exfiltration", description: "Data exfiltration before encryption for double extortion", frequency: "primary" },
      { techniqueId: "T1498", techniqueName: "Network Denial of Service", tactic: "impact", description: "DDoS threats as third extortion vector", frequency: "secondary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for lateral movement and payload execution", frequency: "primary" },
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "defense-evasion", description: "EDR bypass and safe mode boot for encryption", frequency: "primary" },
    ],
    tools: [
      { name: "BlackCat/ALPHV encryptor", category: "malware", description: "Rust-based cross-platform ransomware" },
      { name: "ExMatter", category: "exfiltration", description: "Custom data exfiltration tool" },
      { name: "Cobalt Strike", category: "c2", description: "C2 framework" },
      { name: "Brute Ratel", category: "c2", description: "Advanced C2 framework with EDR evasion" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction" },
      { name: "Impacket", category: "lateral", description: "Python tools for lateral movement" },
    ],
    initialAccessMethods: ["Credential purchase from IABs", "Exchange exploitation", "VPN exploitation", "Social engineering"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor for Rust-based executables and safe mode boot modifications", siemQuery: "index=windows sourcetype=WinEventLog:Sysmon EventCode=1 (CommandLine=\"*bcdedit*safeboot*\" OR CommandLine=\"*-safe-mode*\")", mitreTechniques: ["T1562.001"] },
      { priority: "critical", category: "prevention", recommendation: "Implement ESXi hardening: disable SSH, enforce lockdown mode, patch promptly", mitreTechniques: ["T1486"] },
      { priority: "high", category: "detection", recommendation: "Alert on ExMatter data staging indicators (large archive creation before exfiltration)", mitreTechniques: ["T1567"] },
    ],
    detectionHints: [
      "Monitor for .alphv/.blackcat file extensions",
      "Alert on safe mode boot configuration changes",
      "Track ESXi VM encryption operations",
    ],
    exploitedCVEs: ["CVE-2021-26855", "CVE-2021-31207", "CVE-2023-22515", "CVE-2023-46747"],
  },
  {
    id: "clop",
    name: "Cl0p",
    aliases: ["TA505", "FIN11", "Lace Tempest", "DEV-0950"],
    type: "ransomware",
    origin: "Russia-linked",
    threatLevel: "critical",
    active: true,
    description: "Ransomware group specializing in mass exploitation of file transfer vulnerabilities (MOVEit, GoAnywhere, Accellion) for large-scale data theft without traditional encryption.",
    motivation: "Financial extortion, mass data theft",
    targetSectors: ["financial", "government", "healthcare", "education", "technology"],
    targetRegions: ["USA", "Europe", "Global"],
    ttps: [
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "Zero-day exploitation of file transfer appliances (MOVEit, GoAnywhere)", frequency: "primary" },
      { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "collection", description: "Mass data collection from file transfer servers", frequency: "primary" },
      { techniqueId: "T1567", techniqueName: "Exfiltration Over Web Service", tactic: "exfiltration", description: "Automated data exfiltration at scale", frequency: "primary" },
      { techniqueId: "T1505.003", techniqueName: "Web Shell", tactic: "persistence", description: "Web shells on compromised file transfer servers", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "Traditional encryption (less common in recent campaigns)", frequency: "occasional" },
    ],
    tools: [
      { name: "DEWMODE", category: "malware", description: "Web shell for Accellion FTA exploitation" },
      { name: "LEMURLOOT", category: "malware", description: "Web shell for MOVEit exploitation" },
      { name: "FlawedAmmyy", category: "rat", description: "RAT for persistent access" },
      { name: "Truebot", category: "malware", description: "Downloader for initial access" },
      { name: "Cobalt Strike", category: "c2", description: "C2 framework" },
    ],
    initialAccessMethods: ["Zero-day exploitation of file transfer appliances", "Phishing", "Truebot distribution"],
    defenseRecommendations: [
      { priority: "critical", category: "hardening", recommendation: "Inventory and patch all file transfer appliances (MOVEit, GoAnywhere, Accellion, Citrix ShareFile) immediately", mitreTechniques: ["T1190"] },
      { priority: "critical", category: "detection", recommendation: "Monitor file transfer servers for web shell indicators and unusual file access patterns", siemQuery: "index=web sourcetype=access_combined uri_path=\"/human2.aspx\" OR uri_path=\"/guestaccess.aspx\" OR uri_path=\"*moveit*\" method=POST | stats count by src_ip, uri_path", mitreTechniques: ["T1505.003"] },
      { priority: "high", category: "prevention", recommendation: "Implement network segmentation isolating file transfer servers from internal networks", mitreTechniques: ["T1005"] },
    ],
    detectionHints: [
      "Monitor for LEMURLOOT web shell indicators on MOVEit servers",
      "Alert on mass file downloads from file transfer appliances",
      "Track zero-day advisories for managed file transfer products",
    ],
    exploitedCVEs: ["CVE-2023-34362", "CVE-2023-0669", "CVE-2021-27101", "CVE-2021-27104", "CVE-2024-50623"],
  },
  {
    id: "akira",
    name: "Akira",
    aliases: [],
    type: "ransomware",
    origin: "Unknown (possible Conti successor)",
    threatLevel: "high",
    active: true,
    description: "Rapidly growing ransomware group targeting SMBs and enterprises, known for exploiting Cisco VPN vulnerabilities and deploying Linux ESXi variants.",
    motivation: "Financial extortion",
    targetSectors: ["manufacturing", "technology", "healthcare", "education", "professional-services"],
    targetRegions: ["USA", "Europe", "Australia"],
    ttps: [
      { techniqueId: "T1133", techniqueName: "External Remote Services", tactic: "initial-access", description: "Cisco ASA/FTD VPN exploitation without MFA", frequency: "primary" },
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", description: "VMware Horizon, Cisco VPN vulnerabilities", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "Cross-platform encryption (Windows + Linux ESXi)", frequency: "primary" },
      { techniqueId: "T1567", techniqueName: "Exfiltration Over Web Service", tactic: "exfiltration", description: "Data exfiltration before encryption", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for payload execution", frequency: "secondary" },
      { techniqueId: "T1021.001", techniqueName: "Remote Desktop Protocol", tactic: "lateral-movement", description: "RDP for lateral movement", frequency: "secondary" },
    ],
    tools: [
      { name: "Akira encryptor", category: "malware", description: "C++ ransomware with Linux variant" },
      { name: "Megazord", category: "malware", description: "Rust-based variant of Akira" },
      { name: "Cobalt Strike", category: "c2", description: "C2 framework" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction" },
      { name: "AnyDesk", category: "c2", description: "RMM tool for persistence" },
    ],
    initialAccessMethods: ["Cisco VPN exploitation (no MFA)", "VMware Horizon exploitation", "Credential purchase"],
    defenseRecommendations: [
      { priority: "critical", category: "prevention", recommendation: "Enable MFA on all Cisco ASA/FTD VPN connections and patch to latest firmware", mitreTechniques: ["T1133"] },
      { priority: "critical", category: "detection", recommendation: "Monitor for Cisco VPN authentication anomalies and brute-force attempts", siemQuery: "index=network sourcetype=cisco:asa \"authentication rejected\" OR \"Login denied\" | stats count by src_ip | where count > 10", mitreTechniques: ["T1133"] },
      { priority: "high", category: "hardening", recommendation: "Harden ESXi hosts: disable SSH, enable lockdown mode, restrict management network", mitreTechniques: ["T1486"] },
    ],
    detectionHints: [
      "Monitor for .akira file extensions",
      "Alert on Cisco VPN logins from unusual geolocations",
      "Track AnyDesk/RMM tool installations",
    ],
    exploitedCVEs: ["CVE-2023-20269", "CVE-2020-3259", "CVE-2023-20198"],
  },
  {
    id: "black_basta",
    name: "Black Basta",
    aliases: ["Storm-1811"],
    type: "ransomware",
    origin: "Russia-linked (ex-Conti members)",
    threatLevel: "high",
    active: true,
    description: "Ransomware group with Conti lineage, known for QakBot distribution, vishing campaigns, and rapid encryption deployment targeting large enterprises.",
    motivation: "Financial extortion",
    targetSectors: ["manufacturing", "construction", "financial", "healthcare", "technology"],
    targetRegions: ["USA", "Europe", "Global"],
    ttps: [
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "QakBot/Pikabot distribution via email", frequency: "primary" },
      { techniqueId: "T1566.004", techniqueName: "Spearphishing Voice", tactic: "initial-access", description: "Vishing campaigns impersonating IT support", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "Rapid encryption with ChaCha20 + RSA-4096", frequency: "primary" },
      { techniqueId: "T1490", techniqueName: "Inhibit System Recovery", tactic: "impact", description: "Shadow copy deletion", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for lateral movement", frequency: "primary" },
      { techniqueId: "T1219", techniqueName: "Remote Access Software", tactic: "command-and-control", description: "AnyDesk, Quick Assist for remote access", frequency: "primary" },
    ],
    tools: [
      { name: "Black Basta encryptor", category: "malware", description: "ChaCha20+RSA ransomware" },
      { name: "QakBot", category: "malware", description: "Banking trojan used as initial access loader" },
      { name: "Cobalt Strike", category: "c2", description: "C2 framework" },
      { name: "SystemBC", category: "c2", description: "Proxy bot for C2 tunneling" },
      { name: "Mimikatz", category: "credential", description: "Credential extraction" },
    ],
    initialAccessMethods: ["QakBot/Pikabot phishing", "Vishing (IT support impersonation)", "Credential purchase"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor for vishing indicators: Quick Assist/AnyDesk installations initiated by phone calls", siemQuery: "index=windows sourcetype=WinEventLog:Sysmon EventCode=1 (Image=\"*QuickAssist*\" OR Image=\"*AnyDesk*\") | stats count by Computer, User", mitreTechniques: ["T1219", "T1566.004"] },
      { priority: "critical", category: "prevention", recommendation: "Implement email filtering for QakBot/Pikabot distribution patterns (password-protected ZIPs, OneNote attachments)", mitreTechniques: ["T1566.001"] },
      { priority: "high", category: "detection", recommendation: "Alert on SystemBC proxy connections to known C2 infrastructure", mitreTechniques: ["T1090"] },
    ],
    detectionHints: [
      "Monitor for .basta file extensions",
      "Alert on QakBot DLL execution via regsvr32",
      "Track Quick Assist usage outside IT support hours",
    ],
    exploitedCVEs: ["CVE-2024-1709", "CVE-2024-26169", "CVE-2023-27350"],
  },
];

// ─── Cybercrime Groups ──────────────────────────────────────────────────────

const CYBERCRIME_GROUPS: ThreatGroupKnowledge[] = [
  {
    id: "scattered_spider",
    name: "Scattered Spider",
    aliases: ["UNC3944", "Roasted 0ktapus", "Star Fraud", "Octo Tempest"],
    type: "cybercrime",
    origin: "USA/UK (English-speaking)",
    threatLevel: "critical",
    active: true,
    description: "Young English-speaking cybercrime group known for sophisticated social engineering, SIM swapping, and MFA fatigue attacks targeting large enterprises including MGM and Caesars.",
    motivation: "Financial gain, data theft",
    targetSectors: ["hospitality", "gaming", "telecommunications", "technology", "financial"],
    targetRegions: ["USA", "Global"],
    ttps: [
      { techniqueId: "T1566.004", techniqueName: "Spearphishing Voice", tactic: "initial-access", description: "Vishing IT help desks for credential resets", frequency: "primary" },
      { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "initial-access", description: "SIM swapping for MFA bypass", frequency: "primary" },
      { techniqueId: "T1621", techniqueName: "Multi-Factor Authentication Request Generation", tactic: "credential-access", description: "MFA fatigue/push bombing", frequency: "primary" },
      { techniqueId: "T1199", techniqueName: "Trusted Relationship", tactic: "initial-access", description: "Compromising identity providers (Okta)", frequency: "primary" },
      { techniqueId: "T1078.004", techniqueName: "Cloud Accounts", tactic: "persistence", description: "Creating persistent cloud admin accounts", frequency: "primary" },
      { techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", tactic: "impact", description: "ALPHV/BlackCat ransomware deployment", frequency: "secondary" },
    ],
    tools: [
      { name: "Social engineering", category: "recon", description: "Vishing, SIM swapping, MFA fatigue" },
      { name: "ALPHV/BlackCat", category: "malware", description: "Ransomware affiliate" },
      { name: "Okta exploitation", category: "exploit", description: "Identity provider compromise" },
      { name: "Azure AD manipulation", category: "persistence", description: "Cloud identity persistence" },
    ],
    initialAccessMethods: ["Vishing IT help desks", "SIM swapping", "MFA fatigue attacks", "Phishing for Okta credentials"],
    defenseRecommendations: [
      { priority: "critical", category: "prevention", recommendation: "Implement phishing-resistant MFA (FIDO2) and eliminate SMS-based authentication", mitreTechniques: ["T1621", "T1078"] },
      { priority: "critical", category: "prevention", recommendation: "Establish verbal verification procedures for IT help desk credential resets", mitreTechniques: ["T1566.004"] },
      { priority: "critical", category: "detection", recommendation: "Monitor for MFA fatigue: multiple push notifications in short timeframes", siemQuery: "index=okta sourcetype=OktaIM2:log eventType=system.push.send_factor_verify_push | stats count by actor.alternateId | where count > 5", mitreTechniques: ["T1621"] },
      { priority: "high", category: "detection", recommendation: "Alert on new admin account creation in Azure AD/Okta", mitreTechniques: ["T1078.004"] },
    ],
    detectionHints: [
      "Monitor for SIM swap indicators: sudden MFA method changes",
      "Alert on multiple failed MFA attempts followed by success",
      "Track Okta admin console access from unusual locations",
    ],
    exploitedCVEs: ["CVE-2023-20269"],
  },
  {
    id: "fin7",
    name: "FIN7 / Carbanak",
    aliases: ["Carbanak", "Carbon Spider", "Sangria Tempest", "ELBRUS"],
    type: "cybercrime",
    origin: "Russia/Ukraine",
    threatLevel: "high",
    active: true,
    description: "Sophisticated financially motivated group targeting retail, hospitality, and financial sectors with custom malware, social engineering, and point-of-sale attacks.",
    motivation: "Financial theft",
    targetSectors: ["retail", "hospitality", "financial", "restaurant"],
    targetRegions: ["USA", "Europe", "Global"],
    ttps: [
      { techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access", description: "Weaponized documents mimicking business communications", frequency: "primary" },
      { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution", description: "PowerShell for payload execution and persistence", frequency: "primary" },
      { techniqueId: "T1055", techniqueName: "Process Injection", tactic: "defense-evasion", description: "In-memory execution and injection", frequency: "primary" },
      { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "collection", description: "POS RAM scraping for payment card data", frequency: "primary" },
      { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control", description: "HTTPS C2 with custom protocols", frequency: "primary" },
    ],
    tools: [
      { name: "Carbanak", category: "malware", description: "Custom banking malware" },
      { name: "GRIFFON", category: "malware", description: "JavaScript backdoor" },
      { name: "BOOSTWRITE", category: "malware", description: "DLL loader with signed certificates" },
      { name: "Cobalt Strike", category: "c2", description: "C2 framework" },
      { name: "Pillowmint", category: "malware", description: "POS malware for card data theft" },
    ],
    initialAccessMethods: ["Spearphishing with business-themed lures", "Fake company websites for malware delivery", "USB-based attacks"],
    defenseRecommendations: [
      { priority: "critical", category: "detection", recommendation: "Monitor POS systems for RAM scraping indicators and unusual process behavior", siemQuery: "index=endpoint sourcetype=sysmon EventCode=10 TargetImage=\"*pos*\" OR TargetImage=\"*payment*\" | stats count by SourceImage, TargetImage", mitreTechniques: ["T1005"] },
      { priority: "high", category: "prevention", recommendation: "Implement application allowlisting on POS systems and network segmentation for payment networks", mitreTechniques: ["T1005", "T1055"] },
    ],
    detectionHints: [
      "Monitor for Carbanak C2 beacon patterns",
      "Alert on PowerShell execution from Office processes",
      "Track POS system process creation anomalies",
    ],
    exploitedCVEs: ["CVE-2017-0199", "CVE-2017-11882"],
    mitreGroupId: "G0046",
  },
];

// ─── All Groups Combined ────────────────────────────────────────────────────

const ALL_GROUPS: ThreatGroupKnowledge[] = [
  ...APT_GROUPS,
  ...RANSOMWARE_GROUPS,
  ...CYBERCRIME_GROUPS,
];

// ─── Sector Threat Profiles ─────────────────────────────────────────────────

const SECTOR_PROFILES: SectorThreatProfile[] = [
  {
    sector: "healthcare",
    topGroups: ["lockbit", "blackcat", "lazarus", "apt41"],
    commonTTPs: ["T1190", "T1133", "T1486", "T1567", "T1078"],
    priorityDefenses: ["Patch file transfer appliances", "MFA on all remote access", "Immutable backups", "Network segmentation for medical devices", "PHI data loss prevention"],
  },
  {
    sector: "financial",
    topGroups: ["lazarus", "fin7", "apt34", "lockbit", "clop"],
    commonTTPs: ["T1566.001", "T1190", "T1005", "T1486", "T1567"],
    priorityDefenses: ["SWIFT network isolation", "POS system hardening", "Anti-phishing training", "Transaction monitoring", "Cryptocurrency wallet security"],
  },
  {
    sector: "government",
    topGroups: ["apt29", "apt28", "volt_typhoon", "sandworm", "salt_typhoon"],
    commonTTPs: ["T1566.001", "T1078.004", "T1190", "T1098", "T1003"],
    priorityDefenses: ["FIDO2 MFA", "Cloud identity monitoring", "Edge device patching", "Supply chain verification", "Classified network segmentation"],
  },
  {
    sector: "energy",
    topGroups: ["sandworm", "volt_typhoon", "apt34", "lockbit"],
    commonTTPs: ["T1190", "T1495", "T1485", "T1078", "T1071.004"],
    priorityDefenses: ["ICS/SCADA network segmentation", "OT monitoring", "Unidirectional gateways", "Edge device hardening", "Incident response plans for destructive attacks"],
  },
  {
    sector: "telecommunications",
    topGroups: ["salt_typhoon", "volt_typhoon", "apt41", "mustang_panda"],
    commonTTPs: ["T1190", "T1557", "T1040", "T1078", "T1005"],
    priorityDefenses: ["End-to-end encryption", "Lawful intercept system monitoring", "Network equipment patching", "Admin account auditing", "Kernel integrity monitoring"],
  },
  {
    sector: "technology",
    topGroups: ["apt29", "apt41", "lazarus", "scattered_spider", "lockbit"],
    commonTTPs: ["T1195.002", "T1566.001", "T1078.004", "T1059.007", "T1621"],
    priorityDefenses: ["Supply chain security (SBOM)", "Source code repository protection", "CI/CD pipeline hardening", "FIDO2 MFA", "npm/PyPI dependency auditing"],
  },
  {
    sector: "manufacturing",
    topGroups: ["lockbit", "black_basta", "akira", "apt41", "volt_typhoon"],
    commonTTPs: ["T1133", "T1190", "T1486", "T1059.001", "T1021.001"],
    priorityDefenses: ["OT/IT segmentation", "VPN MFA enforcement", "Backup testing", "RDP restriction", "Patch management for legacy systems"],
  },
  {
    sector: "education",
    topGroups: ["lockbit", "clop", "akira", "apt36"],
    commonTTPs: ["T1190", "T1133", "T1486", "T1566.001"],
    priorityDefenses: ["MFA for all accounts", "File transfer appliance patching", "Student data protection", "Email filtering", "Endpoint detection"],
  },
];

// ─── Context Builders for LLM Injection ─────────────────────────────────────

/**
 * Get threat group context for hunt hypothesis generation.
 * Returns a structured prompt section with group TTPs, tools, and detection recommendations.
 */
export function getThreatGroupHuntContext(options?: {
  groupIds?: string[];
  sector?: string;
  maxGroups?: number;
}): string {
  const maxGroups = options?.maxGroups ?? 5;
  let groups: ThreatGroupKnowledge[];

  if (options?.groupIds?.length) {
    groups = ALL_GROUPS.filter(g => options.groupIds!.includes(g.id));
  } else if (options?.sector) {
    const profile = SECTOR_PROFILES.find(p => p.sector === options.sector);
    if (profile) {
      groups = ALL_GROUPS.filter(g => profile.topGroups.includes(g.id));
    } else {
      groups = ALL_GROUPS.filter(g => g.threatLevel === "critical").slice(0, maxGroups);
    }
  } else {
    groups = ALL_GROUPS.filter(g => g.active && g.threatLevel === "critical").slice(0, maxGroups);
  }

  if (groups.length === 0) return "";

  let context = `\n=== THREAT GROUP INTELLIGENCE ===\n`;
  context += `Active threat groups relevant to this hunt (${groups.length} groups):\n\n`;

  for (const g of groups.slice(0, maxGroups)) {
    context += `## ${g.name} [${g.type.toUpperCase()}] — Threat Level: ${g.threatLevel.toUpperCase()}\n`;
    context += `Origin: ${g.origin} | Motivation: ${g.motivation}\n`;
    context += `Target Sectors: ${g.targetSectors.join(", ")}\n`;
    context += `Primary TTPs:\n`;
    for (const ttp of g.ttps.filter(t => t.frequency === "primary").slice(0, 5)) {
      context += `  - ${ttp.techniqueId} (${ttp.techniqueName}): ${ttp.description}\n`;
    }
    context += `Tools: ${g.tools.map(t => t.name).join(", ")}\n`;
    context += `Initial Access: ${g.initialAccessMethods.join(", ")}\n`;
    if (g.exploitedCVEs.length > 0) {
      context += `Known Exploited CVEs: ${g.exploitedCVEs.join(", ")}\n`;
    }
    context += `Detection Recommendations:\n`;
    for (const rec of g.defenseRecommendations.filter(r => r.category === "detection").slice(0, 2)) {
      context += `  - [${rec.priority.toUpperCase()}] ${rec.recommendation}\n`;
      if (rec.siemQuery) {
        context += `    SIEM Query: ${rec.siemQuery}\n`;
      }
    }
    context += `\n`;
  }

  context += `INSTRUCTIONS: Generate hypotheses that specifically target the TTPs and tools used by these threat groups. Include SIEM queries that detect the specific indicators listed above. Reference threat group names in hypothesis descriptions.\n`;

  return context;
}

/**
 * Get threat group context for scan plan generation.
 * Focuses on initial access methods and exploited CVEs.
 */
export function getThreatGroupScanContext(options?: {
  sector?: string;
  technologies?: string[];
}): string {
  let groups: ThreatGroupKnowledge[];

  if (options?.sector) {
    const profile = SECTOR_PROFILES.find(p => p.sector === options.sector);
    groups = profile
      ? ALL_GROUPS.filter(g => profile.topGroups.includes(g.id))
      : ALL_GROUPS.filter(g => g.threatLevel === "critical").slice(0, 5);
  } else {
    groups = ALL_GROUPS.filter(g => g.active && g.threatLevel === "critical").slice(0, 5);
  }

  if (groups.length === 0) return "";

  let context = `\n=== THREAT-INFORMED SCANNING PRIORITIES ===\n`;
  context += `Based on active threat groups targeting this sector:\n\n`;

  // Aggregate exploited CVEs
  const allCVEs = new Set<string>();
  const initialAccessMethods = new Set<string>();
  for (const g of groups) {
    g.exploitedCVEs.forEach(c => allCVEs.add(c));
    g.initialAccessMethods.forEach(m => initialAccessMethods.add(m));
  }

  context += `PRIORITY CVEs TO CHECK (exploited by active threat groups):\n`;
  context += `${[...allCVEs].join(", ")}\n\n`;

  context += `INITIAL ACCESS METHODS TO TEST:\n`;
  for (const method of initialAccessMethods) {
    context += `  - ${method}\n`;
  }

  context += `\nTHREAT GROUP TOOL SIGNATURES TO DETECT:\n`;
  const toolSet = new Set<string>();
  for (const g of groups) {
    for (const tool of g.tools) {
      if (!toolSet.has(tool.name)) {
        toolSet.add(tool.name);
        context += `  - ${tool.name} (${tool.category}): ${tool.description}\n`;
      }
    }
  }

  context += `\nINSTRUCTIONS: Prioritize scanning for the CVEs and initial access methods listed above. Include nuclei templates for the listed CVEs. Test for indicators of the tools listed above.\n`;

  return context;
}

/**
 * Get threat group context for vulnerability correlation.
 * Maps findings to threat group exploitation patterns.
 */
export function getThreatGroupVulnContext(technologies?: string[]): string {
  let context = `\n=== THREAT GROUP VULNERABILITY CORRELATION ===\n`;
  context += `When correlating vulnerabilities, consider these active threat group exploitation patterns:\n\n`;

  // Build CVE-to-group mapping
  const cveToGroups: Record<string, string[]> = {};
  for (const g of ALL_GROUPS) {
    for (const cve of g.exploitedCVEs) {
      if (!cveToGroups[cve]) cveToGroups[cve] = [];
      cveToGroups[cve].push(g.name);
    }
  }

  context += `CVEs ACTIVELY EXPLOITED BY THREAT GROUPS:\n`;
  for (const [cve, groups] of Object.entries(cveToGroups).slice(0, 30)) {
    context += `  ${cve}: ${groups.join(", ")}\n`;
  }

  context += `\nSEVERITY BOOST RULES:\n`;
  context += `  - If a finding matches a CVE exploited by a CRITICAL threat group → boost severity to CRITICAL\n`;
  context += `  - If a finding matches a CVE exploited by multiple groups → boost severity by one level\n`;
  context += `  - If a finding matches a ransomware group's initial access method → flag as RANSOMWARE RISK\n`;
  context += `  - If a finding matches an APT group's persistence technique → flag as APT RISK\n`;

  return context;
}

/**
 * Get sector-specific threat profile for asset classification.
 */
export function getSectorThreatContext(sector: string): string {
  const profile = SECTOR_PROFILES.find(p => p.sector === sector);
  if (!profile) return "";

  const groups = ALL_GROUPS.filter(g => profile.topGroups.includes(g.id));

  let context = `\n=== SECTOR THREAT PROFILE: ${sector.toUpperCase()} ===\n`;
  context += `Top threat groups targeting this sector:\n`;
  for (const g of groups) {
    context += `  - ${g.name} (${g.type}, ${g.threatLevel}): ${g.motivation}\n`;
  }
  context += `Common TTPs: ${profile.commonTTPs.join(", ")}\n`;
  context += `Priority Defenses: ${profile.priorityDefenses.join("; ")}\n`;

  return context;
}

// ─── Lookup Functions ───────────────────────────────────────────────────────

export function getGroupById(id: string): ThreatGroupKnowledge | undefined {
  return ALL_GROUPS.find(g => g.id === id);
}

export function getGroupByName(name: string): ThreatGroupKnowledge | undefined {
  const lower = name.toLowerCase();
  return ALL_GROUPS.find(g =>
    g.name.toLowerCase().includes(lower) ||
    g.aliases.some(a => a.toLowerCase().includes(lower))
  );
}

export function getGroupsByType(type: ThreatGroupType): ThreatGroupKnowledge[] {
  return ALL_GROUPS.filter(g => g.type === type);
}

export function getGroupsBySector(sector: string): ThreatGroupKnowledge[] {
  const profile = SECTOR_PROFILES.find(p => p.sector === sector);
  if (!profile) return [];
  return ALL_GROUPS.filter(g => profile.topGroups.includes(g.id));
}

export function getGroupsByTechnique(techniqueId: string): ThreatGroupKnowledge[] {
  return ALL_GROUPS.filter(g =>
    g.ttps.some(t => t.techniqueId === techniqueId)
  );
}

export function getGroupsByCVE(cve: string): ThreatGroupKnowledge[] {
  return ALL_GROUPS.filter(g => g.exploitedCVEs.includes(cve));
}

export function getAllGroups(): ThreatGroupKnowledge[] {
  return [...ALL_GROUPS];
}

export function getSectorProfiles(): SectorThreatProfile[] {
  return [...SECTOR_PROFILES];
}

/**
 * Get a summary of all threat groups for dashboard display.
 */
export function getThreatGroupSummary(): {
  totalGroups: number;
  byType: Record<ThreatGroupType, number>;
  byThreatLevel: Record<ThreatLevel, number>;
  totalTTPs: number;
  totalCVEs: number;
  totalTools: number;
  activeGroups: number;
} {
  const byType: Record<string, number> = { apt: 0, ransomware: 0, cybercrime: 0, hacktivist: 0 };
  const byThreatLevel: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const allCVEs = new Set<string>();
  const allTools = new Set<string>();
  let totalTTPs = 0;

  for (const g of ALL_GROUPS) {
    byType[g.type] = (byType[g.type] || 0) + 1;
    byThreatLevel[g.threatLevel] = (byThreatLevel[g.threatLevel] || 0) + 1;
    totalTTPs += g.ttps.length;
    g.exploitedCVEs.forEach(c => allCVEs.add(c));
    g.tools.forEach(t => allTools.add(t.name));
  }

  return {
    totalGroups: ALL_GROUPS.length,
    byType: byType as Record<ThreatGroupType, number>,
    byThreatLevel: byThreatLevel as Record<ThreatLevel, number>,
    totalTTPs,
    totalCVEs: allCVEs.size,
    totalTools: allTools.size,
    activeGroups: ALL_GROUPS.filter(g => g.active).length,
  };
}
