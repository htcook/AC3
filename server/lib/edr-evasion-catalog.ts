/**
 * EDR Evasion Threat Intel Cross-Reference Catalog
 * ═══════════════════════════════════════════════════════════════════
 * Maps real-world EDR evasion techniques used by known threat groups
 * to specific security products. This catalog is used by:
 *
 *   1. Interception Fingerprinting Engine — enriches findings with
 *      known bypass techniques per vendor
 *   2. Ember Interception Knowledge — selects evasion modules
 *   3. LLM Interception-Evasion Specialist — contextualizes recommendations
 *   4. Attack Planner — factors defense evasion into attack chains
 *   5. Threat Mapper — correlates detected defenses with threat group TTPs
 *
 * Sources: MITRE ATT&CK, public red team research, vendor advisories,
 *          threat intelligence reports, and documented APT campaigns.
 */

// ─── Types ──────────────────────────────────────────────────────────

export interface EvasionTechniqueEntry {
  /** Unique ID */
  id: string;
  /** Human-readable name */
  name: string;
  /** MITRE ATT&CK technique ID(s) */
  mitreIds: string[];
  /** Description of the technique */
  description: string;
  /** Which products this technique bypasses */
  bypassesProducts: string[];
  /** Threat groups known to use this technique */
  usedByGroups: string[];
  /** Reliability rating */
  reliability: "proven" | "likely" | "experimental" | "patched";
  /** Risk of detection when using this technique */
  detectionRisk: "low" | "medium" | "high";
  /** Platform applicability */
  platforms: ("windows" | "linux" | "macos")[];
  /** Requires elevated privileges? */
  requiresAdmin: boolean;
  /** Implementation notes */
  implementation: string;
  /** Known patches or mitigations */
  mitigations: string[];
  /** Last verified date (YYYY-MM-DD) */
  lastVerified: string;
  /** Category */
  category: "memory" | "process" | "network" | "credential" | "persistence" | "discovery" | "lateral" | "collection" | "exfiltration";
}

// ─── Catalog ────────────────────────────────────────────────────────

export const EDR_EVASION_CATALOG: EvasionTechniqueEntry[] = [
  // ═══ MEMORY TECHNIQUES ═══
  {
    id: "mem-001",
    name: "Direct Syscall Invocation (SysWhispers)",
    mitreIds: ["T1106"],
    description: "Bypass userland API hooks by calling NT syscalls directly, avoiding EDR inline hooks on ntdll.dll functions.",
    bypassesProducts: ["CrowdStrike Falcon", "SentinelOne Singularity", "Microsoft Defender for Endpoint", "Carbon Black", "Cortex XDR", "Elastic Endpoint Security", "Cybereason", "Sophos Intercept X"],
    usedByGroups: ["APT29", "APT41", "FIN7", "Lazarus Group", "Turla"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Use SysWhispers3 or HellsGate to resolve syscall numbers dynamically. Avoid static syscall stubs that can be signature-matched.",
    mitigations: ["Kernel-level ETW tracing", "Kernel callback monitoring", "Hardware breakpoint detection"],
    lastVerified: "2025-12-01",
    category: "memory",
  },
  {
    id: "mem-002",
    name: "Sleep Obfuscation (Ekko/Foliage)",
    mitreIds: ["T1027.013"],
    description: "Encrypt beacon memory during sleep intervals using ROP chains or APC-based techniques to avoid memory scanning.",
    bypassesProducts: ["CrowdStrike Falcon", "SentinelOne Singularity", "Microsoft Defender for Endpoint", "Elastic Endpoint Security"],
    usedByGroups: ["APT29", "FIN7"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Use Ekko (timer-based) or Foliage (APC-based) sleep obfuscation. Encrypt heap and stack during sleep. Re-encrypt on wake.",
    mitigations: ["Thread stack walking during sleep", "Timer queue monitoring", "APC dispatch monitoring"],
    lastVerified: "2025-11-15",
    category: "memory",
  },
  {
    id: "mem-003",
    name: "Module Stomping / DLL Hollowing",
    mitreIds: ["T1055.001"],
    description: "Load a legitimate DLL, then overwrite its .text section with shellcode. Appears as a legitimate module in memory.",
    bypassesProducts: ["CrowdStrike Falcon", "Carbon Black", "Symantec Endpoint Protection", "ESET Endpoint Security", "Kaspersky Endpoint Security"],
    usedByGroups: ["APT32", "Lazarus Group", "APT41"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Map a sacrificial DLL (e.g., amsi.dll, dbghelp.dll), change page protections, write shellcode to .text section.",
    mitigations: ["Module integrity verification", "Private page detection in mapped images", "Code integrity guard (CIG)"],
    lastVerified: "2025-10-20",
    category: "memory",
  },
  {
    id: "mem-004",
    name: "Hardware Breakpoint Hooking",
    mitreIds: ["T1106"],
    description: "Use hardware debug registers (DR0-DR3) to set breakpoints on hooked functions, intercept execution before EDR hooks.",
    bypassesProducts: ["CrowdStrike Falcon", "SentinelOne Singularity", "Cortex XDR"],
    usedByGroups: ["APT29"],
    reliability: "likely",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Set hardware breakpoints via SetThreadContext on NtAllocateVirtualMemory, NtWriteVirtualMemory, etc. Use VEH to handle exceptions.",
    mitigations: ["Debug register monitoring", "GetThreadContext monitoring"],
    lastVerified: "2025-09-15",
    category: "memory",
  },
  {
    id: "mem-005",
    name: "Phantom DLL Hollowing",
    mitreIds: ["T1055.001"],
    description: "Create a section from a transacted file, map it into the target process, then rollback the transaction. The DLL appears legitimate but contains shellcode.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne Singularity", "Carbon Black"],
    usedByGroups: ["Lazarus Group"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Use NtCreateTransaction, NtCreateFile (transacted), write shellcode, NtCreateSection, NtMapViewOfSection, NtRollbackTransaction.",
    mitigations: ["Transaction monitoring", "Section object auditing"],
    lastVerified: "2025-08-01",
    category: "memory",
  },

  // ═══ PROCESS TECHNIQUES ═══
  {
    id: "proc-001",
    name: "PPID Spoofing",
    mitreIds: ["T1134.004"],
    description: "Create processes with a spoofed parent PID to break process tree analysis used by EDR behavioral detection.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne Singularity", "Carbon Black", "Cybereason"],
    usedByGroups: ["APT29", "APT41", "FIN7", "Cobalt Group"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Use PROC_THREAD_ATTRIBUTE_PARENT_PROCESS with UpdateProcThreadAttribute. Spoof parent to explorer.exe or svchost.exe.",
    mitigations: ["ETW process creation events with real parent", "Kernel callback PsSetCreateProcessNotifyRoutine"],
    lastVerified: "2025-12-01",
    category: "process",
  },
  {
    id: "proc-002",
    name: "Process Ghosting",
    mitreIds: ["T1055"],
    description: "Create a process from a file that is deleted before the image section is created. The process runs but the file no longer exists on disk.",
    bypassesProducts: ["Microsoft Defender for Endpoint", "Symantec Endpoint Protection", "ESET Endpoint Security", "Trend Micro Apex One"],
    usedByGroups: ["APT32"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Create file, set delete disposition, write payload, create section, delete file, create process from section.",
    mitigations: ["PsSetCreateProcessNotifyRoutineEx2", "Minifilter pre-create callbacks"],
    lastVerified: "2025-07-15",
    category: "process",
  },
  {
    id: "proc-003",
    name: "Process Doppelganging",
    mitreIds: ["T1055.013"],
    description: "Use NTFS transactions to create a process from a transacted file that is never committed to disk.",
    bypassesProducts: ["Symantec Endpoint Protection", "ESET Endpoint Security", "Kaspersky Endpoint Security", "Trend Micro Apex One"],
    usedByGroups: ["SynAck ransomware"],
    reliability: "likely",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "NtCreateTransaction, create transacted file, write payload, NtCreateSection, NtRollbackTransaction, NtCreateProcessEx.",
    mitigations: ["Minifilter IRP_MJ_CREATE monitoring", "Transaction rollback monitoring"],
    lastVerified: "2025-06-01",
    category: "process",
  },
  {
    id: "proc-004",
    name: "Thread Execution Hijacking",
    mitreIds: ["T1055.003"],
    description: "Suspend a thread in a legitimate process, modify its context to point to shellcode, then resume it.",
    bypassesProducts: ["Carbon Black", "Symantec Endpoint Protection", "ESET Endpoint Security"],
    usedByGroups: ["APT28", "Turla", "Lazarus Group"],
    reliability: "proven",
    detectionRisk: "high",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "OpenThread, SuspendThread, VirtualAllocEx, WriteProcessMemory, SetThreadContext (RIP → shellcode), ResumeThread.",
    mitigations: ["SetThreadContext monitoring", "Cross-process memory write detection"],
    lastVerified: "2025-11-01",
    category: "process",
  },

  // ═══ NETWORK TECHNIQUES ═══
  {
    id: "net-001",
    name: "Domain Fronting",
    mitreIds: ["T1090.004"],
    description: "Use a legitimate CDN domain in the TLS SNI while routing traffic to a C2 server via the Host header.",
    bypassesProducts: ["Palo Alto NGFW", "Fortinet FortiGate", "Cisco Firepower", "Check Point NGFW", "Zscaler"],
    usedByGroups: ["APT29", "APT32", "Turla", "Lazarus Group"],
    reliability: "likely",
    detectionRisk: "low",
    platforms: ["windows", "linux", "macos"],
    requiresAdmin: false,
    implementation: "Configure C2 to use Azure CDN or CloudFront. Set SNI to legitimate domain, Host header to C2 domain.",
    mitigations: ["CDN providers blocking domain fronting", "TLS inspection comparing SNI vs Host", "JA3/JA3S fingerprinting"],
    lastVerified: "2025-10-01",
    category: "network",
  },
  {
    id: "net-002",
    name: "DNS-over-HTTPS C2",
    mitreIds: ["T1071.004"],
    description: "Tunnel C2 traffic through DNS-over-HTTPS requests to legitimate resolvers (Cloudflare, Google).",
    bypassesProducts: ["Palo Alto NGFW", "Fortinet FortiGate", "Snort/Suricata", "Zscaler"],
    usedByGroups: ["APT34", "Godlua"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows", "linux", "macos"],
    requiresAdmin: false,
    implementation: "Use cloudflare-dns.com/dns-query or dns.google/resolve with TXT records for data exfiltration.",
    mitigations: ["DoH endpoint blocking", "DNS query volume analysis", "Encrypted DNS policy enforcement"],
    lastVerified: "2025-11-01",
    category: "network",
  },
  {
    id: "net-003",
    name: "Malleable C2 Profiles (Traffic Mimicry)",
    mitreIds: ["T1071.001"],
    description: "Configure C2 traffic to mimic legitimate application traffic (Slack, Teams, Google APIs) to evade network signatures.",
    bypassesProducts: ["Snort/Suricata", "Cisco Firepower", "Palo Alto NGFW", "Darktrace"],
    usedByGroups: ["APT29", "FIN7", "APT41", "Cobalt Group"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows", "linux", "macos"],
    requiresAdmin: false,
    implementation: "Use Cobalt Strike malleable C2 profiles or custom HTTP headers/URIs that match legitimate traffic patterns.",
    mitigations: ["JA3/JA3S fingerprinting", "Behavioral analysis of traffic patterns", "Certificate transparency monitoring"],
    lastVerified: "2025-12-01",
    category: "network",
  },
  {
    id: "net-004",
    name: "Named Pipe C2 (SMB)",
    mitreIds: ["T1071.002"],
    description: "Use SMB named pipes for C2 communication within a network, blending with legitimate Windows file sharing traffic.",
    bypassesProducts: ["Palo Alto NGFW", "Fortinet FortiGate", "Zscaler"],
    usedByGroups: ["APT29", "FIN7", "Turla"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Create named pipe server on compromised host, connect from beacon via SMB. Use custom pipe names that blend with legitimate pipes.",
    mitigations: ["Named pipe creation monitoring (Sysmon Event 17/18)", "SMB traffic analysis"],
    lastVerified: "2025-09-01",
    category: "network",
  },

  // ═══ CREDENTIAL ACCESS TECHNIQUES ═══
  {
    id: "cred-001",
    name: "LSASS Memory Dump via MiniDumpWriteDump Alternative",
    mitreIds: ["T1003.001"],
    description: "Dump LSASS memory using alternatives to MiniDumpWriteDump (which is heavily monitored) — e.g., NanoDump, HandleDuplicator.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne Singularity"],
    usedByGroups: ["APT29", "APT28", "FIN7", "Lazarus Group"],
    reliability: "proven",
    detectionRisk: "high",
    platforms: ["windows"],
    requiresAdmin: true,
    implementation: "Use NanoDump (direct syscalls + MalSecLogon), or duplicate LSASS handle from another process, or use ProcDump with -accepteula.",
    mitigations: ["PPL protection on LSASS", "Credential Guard", "LSASS handle access monitoring"],
    lastVerified: "2025-12-01",
    category: "credential",
  },
  {
    id: "cred-002",
    name: "DCSync via DRS Replication",
    mitreIds: ["T1003.006"],
    description: "Use Directory Replication Service (DRS) protocol to replicate password hashes from a domain controller without touching LSASS.",
    bypassesProducts: ["CrowdStrike Falcon", "SentinelOne Singularity", "Carbon Black"],
    usedByGroups: ["APT29", "APT28", "FIN7", "Wizard Spider"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: true,
    implementation: "Requires Replicating Directory Changes (All) privilege. Use Mimikatz lsadump::dcsync or Impacket secretsdump.py.",
    mitigations: ["Monitor DRS replication from non-DC sources", "Restrict replication privileges", "Azure AD Connect monitoring"],
    lastVerified: "2025-11-15",
    category: "credential",
  },
  {
    id: "cred-003",
    name: "Kerberoasting with AES Encryption",
    mitreIds: ["T1558.003"],
    description: "Request Kerberos service tickets with AES encryption (instead of RC4) to avoid detection rules that look for RC4 downgrade.",
    bypassesProducts: ["Microsoft Defender for Endpoint", "CrowdStrike Falcon"],
    usedByGroups: ["FIN7", "Wizard Spider", "APT29"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Use Rubeus kerberoast /aes or Impacket GetUserSPNs.py with -dc-ip and AES encryption.",
    mitigations: ["Monitor TGS requests for service accounts", "Managed Service Accounts (gMSA)", "Long/complex service account passwords"],
    lastVerified: "2025-10-01",
    category: "credential",
  },

  // ═══ PERSISTENCE TECHNIQUES ═══
  {
    id: "persist-001",
    name: "COM Object Hijacking",
    mitreIds: ["T1546.015"],
    description: "Hijack COM object registry entries to load a malicious DLL when legitimate applications instantiate the COM object.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne Singularity", "Carbon Black"],
    usedByGroups: ["APT29", "APT28", "Turla", "Cobalt Group"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Find frequently-used COM CLSIDs, create HKCU\\Software\\Classes\\CLSID\\{CLSID}\\InprocServer32 pointing to malicious DLL.",
    mitigations: ["COM object creation monitoring", "Registry key monitoring for CLSID changes"],
    lastVerified: "2025-12-01",
    category: "persistence",
  },
  {
    id: "persist-002",
    name: "DLL Search Order Hijacking",
    mitreIds: ["T1574.001"],
    description: "Place a malicious DLL in a directory that is searched before the legitimate DLL location.",
    bypassesProducts: ["Symantec Endpoint Protection", "ESET Endpoint Security", "Trend Micro Apex One", "Kaspersky Endpoint Security"],
    usedByGroups: ["APT41", "Lazarus Group", "APT32", "Mustang Panda"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Identify vulnerable applications that load DLLs without full paths. Place malicious DLL in application directory or PATH directory.",
    mitigations: ["SafeDllSearchMode", "DLL signature verification", "Application whitelisting"],
    lastVerified: "2025-11-01",
    category: "persistence",
  },
  {
    id: "persist-003",
    name: "WMI Event Subscription",
    mitreIds: ["T1546.003"],
    description: "Create WMI event subscriptions that execute payloads on system events (logon, timer, process creation).",
    bypassesProducts: ["Carbon Black", "Symantec Endpoint Protection", "ESET Endpoint Security"],
    usedByGroups: ["APT29", "APT28", "Turla", "Leviathan"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: true,
    implementation: "Create __EventFilter, CommandLineEventConsumer, and __FilterToConsumerBinding in root\\subscription namespace.",
    mitigations: ["WMI event subscription monitoring (Sysmon Event 19/20/21)", "WMI namespace ACL hardening"],
    lastVerified: "2025-10-15",
    category: "persistence",
  },

  // ═══ DISCOVERY TECHNIQUES ═══
  {
    id: "disc-001",
    name: "BOF-based Discovery (Beacon Object Files)",
    mitreIds: ["T1057", "T1082", "T1016"],
    description: "Use Beacon Object Files for discovery to avoid spawning child processes that trigger EDR behavioral alerts.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne Singularity", "Carbon Black", "Cortex XDR"],
    usedByGroups: ["APT29", "FIN7"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Compile discovery commands as BOFs (C object files). Execute in-process without spawning cmd.exe/powershell.exe.",
    mitigations: ["In-process memory scanning", "API call sequence monitoring"],
    lastVerified: "2025-12-01",
    category: "discovery",
  },
  {
    id: "disc-002",
    name: "LDAP-based AD Enumeration",
    mitreIds: ["T1087.002"],
    description: "Use LDAP queries instead of net.exe commands for Active Directory enumeration to avoid command-line monitoring.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "Carbon Black"],
    usedByGroups: ["APT29", "APT28", "FIN7", "Wizard Spider"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Use SharpView, ADSearch, or direct LDAP queries via System.DirectoryServices. Avoid net.exe, nltest.exe, dsquery.exe.",
    mitigations: ["LDAP query auditing", "Tiered administration model", "Honeypot accounts"],
    lastVerified: "2025-11-01",
    category: "discovery",
  },

  // ═══ LATERAL MOVEMENT TECHNIQUES ═══
  {
    id: "lat-001",
    name: "DCOM Lateral Movement",
    mitreIds: ["T1021.003"],
    description: "Use DCOM (Distributed COM) objects for lateral movement instead of PSExec/WMI which are heavily monitored.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "Carbon Black"],
    usedByGroups: ["APT29", "Cobalt Group"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: true,
    implementation: "Use MMC20.Application, ShellWindows, or ShellBrowserWindow DCOM objects to execute commands on remote hosts.",
    mitigations: ["DCOM usage monitoring", "Network segmentation", "Windows Firewall rules for DCOM"],
    lastVerified: "2025-10-01",
    category: "lateral",
  },
  {
    id: "lat-002",
    name: "SSH Tunneling for Lateral Movement",
    mitreIds: ["T1021.004"],
    description: "Use SSH tunnels for lateral movement in mixed Windows/Linux environments, bypassing Windows-focused monitoring.",
    bypassesProducts: ["CrowdStrike Falcon", "SentinelOne Singularity", "Carbon Black"],
    usedByGroups: ["APT41", "Lazarus Group", "APT32"],
    reliability: "proven",
    detectionRisk: "low",
    platforms: ["windows", "linux", "macos"],
    requiresAdmin: false,
    implementation: "Use built-in OpenSSH client (Windows 10+) or plink.exe for SSH tunneling. Forward ports for RDP, SMB, or HTTP access.",
    mitigations: ["SSH connection monitoring", "Outbound SSH blocking", "Network segmentation"],
    lastVerified: "2025-11-15",
    category: "lateral",
  },

  // ═══ AMSI/ETW BYPASS TECHNIQUES ═══
  {
    id: "av-001",
    name: "AMSI Patch (AmsiScanBuffer)",
    mitreIds: ["T1562.001"],
    description: "Patch the AmsiScanBuffer function in amsi.dll to return AMSI_RESULT_CLEAN for all scans.",
    bypassesProducts: ["Microsoft Defender for Endpoint", "Symantec Endpoint Protection", "ESET Endpoint Security", "Kaspersky Endpoint Security"],
    usedByGroups: ["APT29", "FIN7", "Cobalt Group", "Wizard Spider"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Use VirtualProtect to make AmsiScanBuffer writable, patch first bytes to return E_INVALIDARG. Or use hardware breakpoints.",
    mitigations: ["AMSI integrity monitoring", "ETW AmsiPatch detection", "Script block logging"],
    lastVerified: "2025-12-01",
    category: "memory",
  },
  {
    id: "av-002",
    name: "ETW Patching (EtwEventWrite)",
    mitreIds: ["T1562.001"],
    description: "Patch EtwEventWrite in ntdll.dll to prevent ETW events from being generated, blinding EDR telemetry.",
    bypassesProducts: ["CrowdStrike Falcon", "Microsoft Defender for Endpoint", "SentinelOne Singularity", "Elastic Endpoint Security"],
    usedByGroups: ["APT29", "FIN7"],
    reliability: "proven",
    detectionRisk: "medium",
    platforms: ["windows"],
    requiresAdmin: false,
    implementation: "Patch EtwEventWrite to return immediately (ret/xor eax,eax;ret). Also consider patching NtTraceEvent for kernel-level ETW.",
    mitigations: ["Kernel ETW provider monitoring", "Integrity verification of ntdll.dll", "Threat intelligence-based detection"],
    lastVerified: "2025-11-01",
    category: "memory",
  },
];

// ─── Lookup Functions ───────────────────────────────────────────────

/**
 * Get all evasion techniques that bypass a specific product.
 */
export function getEvasionTechniquesForProduct(productName: string): EvasionTechniqueEntry[] {
  const normalized = productName.toLowerCase();
  return EDR_EVASION_CATALOG.filter(t =>
    t.bypassesProducts.some(p => p.toLowerCase().includes(normalized)) &&
    t.reliability !== "patched"
  );
}

/**
 * Get all evasion techniques used by a specific threat group.
 */
export function getEvasionTechniquesForGroup(groupName: string): EvasionTechniqueEntry[] {
  const normalized = groupName.toLowerCase();
  return EDR_EVASION_CATALOG.filter(t =>
    t.usedByGroups.some(g => g.toLowerCase().includes(normalized))
  );
}

/**
 * Get evasion techniques for a specific category.
 */
export function getEvasionTechniquesByCategory(category: EvasionTechniqueEntry["category"]): EvasionTechniqueEntry[] {
  return EDR_EVASION_CATALOG.filter(t => t.category === category && t.reliability !== "patched");
}

/**
 * Get evasion techniques by MITRE ATT&CK ID.
 */
export function getEvasionTechniquesByMitre(mitreId: string): EvasionTechniqueEntry[] {
  return EDR_EVASION_CATALOG.filter(t => t.mitreIds.includes(mitreId));
}

/**
 * Cross-reference: given a list of detected products, return the optimal evasion strategy.
 * Prioritizes techniques that bypass the most detected products.
 */
export function crossReferenceEvasionStrategy(detectedProducts: string[]): {
  techniques: Array<EvasionTechniqueEntry & { coversProducts: string[]; coverageScore: number }>;
  uncoveredProducts: string[];
  overallCoverage: number;
} {
  const normalizedProducts = detectedProducts.map(p => p.toLowerCase());
  const coveredProducts = new Set<string>();
  const scoredTechniques = EDR_EVASION_CATALOG
    .filter(t => t.reliability !== "patched")
    .map(t => {
      const coversProducts = t.bypassesProducts.filter(bp =>
        normalizedProducts.some(np => bp.toLowerCase().includes(np) || np.includes(bp.toLowerCase()))
      );
      return {
        ...t,
        coversProducts,
        coverageScore: coversProducts.length / Math.max(detectedProducts.length, 1),
      };
    })
    .filter(t => t.coversProducts.length > 0)
    .sort((a, b) => b.coverageScore - a.coverageScore || a.detectionRisk.localeCompare(b.detectionRisk));

  for (const t of scoredTechniques) {
    for (const p of t.coversProducts) {
      coveredProducts.add(p.toLowerCase());
    }
  }

  const uncoveredProducts = detectedProducts.filter(p =>
    !coveredProducts.has(p.toLowerCase()) &&
    !Array.from(coveredProducts).some(cp => cp.includes(p.toLowerCase()) || p.toLowerCase().includes(cp))
  );

  return {
    techniques: scoredTechniques,
    uncoveredProducts,
    overallCoverage: coveredProducts.size / Math.max(detectedProducts.length, 1),
  };
}

/**
 * Get a compact summary suitable for LLM context injection.
 */
export function getEvasionCatalogSummaryForLLM(detectedProducts: string[]): string {
  const xref = crossReferenceEvasionStrategy(detectedProducts);
  const topTechniques = xref.techniques.slice(0, 15);

  const lines = [
    `## EDR Evasion Cross-Reference (${detectedProducts.length} products detected)`,
    `Overall coverage: ${(xref.overallCoverage * 100).toFixed(0)}%`,
    xref.uncoveredProducts.length > 0 ? `Uncovered: ${xref.uncoveredProducts.join(", ")}` : "",
    "",
    "### Top Evasion Techniques:",
  ];

  for (const t of topTechniques) {
    lines.push(`• ${t.name} [${t.mitreIds.join(",")}] — ${t.reliability} reliability, ${t.detectionRisk} detection risk`);
    lines.push(`  Bypasses: ${t.coversProducts.join(", ")}`);
    lines.push(`  Used by: ${t.usedByGroups.slice(0, 3).join(", ")}`);
    lines.push(`  Implementation: ${t.implementation.slice(0, 120)}...`);
  }

  return lines.filter(Boolean).join("\n");
}
