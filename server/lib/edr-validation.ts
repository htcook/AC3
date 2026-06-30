/**
 * EDR Effectiveness Validation Engine
 * Tests EDR products against a catalog of safe attack simulations
 * mapped to MITRE ATT&CK techniques.
 */

export interface EDRTestDefinition {
  id: string;
  testName: string;
  category: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  description: string;
  binaryType: string;
  expectedBehavior: string;
  riskLevel: "safe" | "low" | "medium" | "high";
}

// ── Built-in EDR Test Catalog ───────────────────────────────────────────
export const EDR_TEST_CATALOG: EDRTestDefinition[] = [
  // Process Injection
  { id: "edr-pi-01", testName: "Classic DLL Injection", category: "process_injection", mitreTechniqueId: "T1055.001", mitreTechniqueName: "DLL Injection", description: "Injects a benign DLL into a target process using CreateRemoteThread", binaryType: "safe_injection", expectedBehavior: "EDR should alert on cross-process DLL injection", riskLevel: "safe" },
  { id: "edr-pi-02", testName: "Process Hollowing", category: "process_injection", mitreTechniqueId: "T1055.012", mitreTechniqueName: "Process Hollowing", description: "Creates a suspended process and replaces its memory with benign payload", binaryType: "safe_injection", expectedBehavior: "EDR should detect process hollowing via memory manipulation", riskLevel: "safe" },
  { id: "edr-pi-03", testName: "APC Queue Injection", category: "process_injection", mitreTechniqueId: "T1055.004", mitreTechniqueName: "Asynchronous Procedure Call", description: "Queues an APC to a thread in a target process", binaryType: "safe_injection", expectedBehavior: "EDR should detect APC-based code injection", riskLevel: "safe" },

  // Credential Access
  { id: "edr-ca-01", testName: "LSASS Memory Dump (MiniDump)", category: "credential_access", mitreTechniqueId: "T1003.001", mitreTechniqueName: "LSASS Memory", description: "Attempts to dump LSASS process memory using MiniDumpWriteDump", binaryType: "safe_mimikatz", expectedBehavior: "EDR should block LSASS access and alert", riskLevel: "safe" },
  { id: "edr-ca-02", testName: "SAM Registry Hive Extraction", category: "credential_access", mitreTechniqueId: "T1003.002", mitreTechniqueName: "Security Account Manager", description: "Attempts to extract SAM, SYSTEM, and SECURITY registry hives", binaryType: "safe_dump", expectedBehavior: "EDR should detect registry hive extraction attempts", riskLevel: "safe" },
  { id: "edr-ca-03", testName: "Credential Manager Vault Access", category: "credential_access", mitreTechniqueId: "T1555.004", mitreTechniqueName: "Windows Credential Manager", description: "Attempts to read credentials from Windows Credential Manager", binaryType: "safe_dump", expectedBehavior: "EDR should detect credential vault access", riskLevel: "safe" },

  // Defense Evasion
  { id: "edr-de-01", testName: "AMSI Bypass Attempt", category: "defense_evasion", mitreTechniqueId: "T1562.001", mitreTechniqueName: "Disable or Modify Tools", description: "Attempts to patch AmsiScanBuffer to bypass AMSI scanning", binaryType: "custom", expectedBehavior: "EDR should detect AMSI tampering", riskLevel: "safe" },
  { id: "edr-de-02", testName: "ETW Patching", category: "defense_evasion", mitreTechniqueId: "T1562.006", mitreTechniqueName: "Indicator Blocking", description: "Attempts to patch ETW providers to blind logging", binaryType: "custom", expectedBehavior: "EDR should detect ETW provider manipulation", riskLevel: "safe" },
  { id: "edr-de-03", testName: "Timestomping", category: "defense_evasion", mitreTechniqueId: "T1070.006", mitreTechniqueName: "Timestomp", description: "Modifies file timestamps to blend with legitimate files", binaryType: "custom", expectedBehavior: "EDR should detect timestamp manipulation", riskLevel: "safe" },

  // Lateral Movement
  { id: "edr-lm-01", testName: "PsExec-style Remote Execution", category: "lateral_movement", mitreTechniqueId: "T1569.002", mitreTechniqueName: "Service Execution", description: "Creates and starts a remote service for command execution", binaryType: "safe_lateral", expectedBehavior: "EDR should detect remote service creation and execution", riskLevel: "low" },
  { id: "edr-lm-02", testName: "WMI Remote Process Creation", category: "lateral_movement", mitreTechniqueId: "T1047", mitreTechniqueName: "Windows Management Instrumentation", description: "Uses WMI to create a process on a remote system", binaryType: "safe_lateral", expectedBehavior: "EDR should detect WMI-based remote execution", riskLevel: "low" },
  { id: "edr-lm-03", testName: "SMB Lateral Movement", category: "lateral_movement", mitreTechniqueId: "T1021.002", mitreTechniqueName: "Remote Services: SMB/Windows Admin Shares", description: "Copies and executes payload via SMB admin shares", binaryType: "safe_lateral", expectedBehavior: "EDR should detect file copy and execution via admin shares", riskLevel: "low" },

  // Persistence
  { id: "edr-pe-01", testName: "Registry Run Key Persistence", category: "persistence", mitreTechniqueId: "T1547.001", mitreTechniqueName: "Registry Run Keys / Startup Folder", description: "Adds a registry run key for persistence", binaryType: "safe_persist", expectedBehavior: "EDR should detect new run key entries", riskLevel: "safe" },
  { id: "edr-pe-02", testName: "Scheduled Task Persistence", category: "persistence", mitreTechniqueId: "T1053.005", mitreTechniqueName: "Scheduled Task", description: "Creates a scheduled task for persistence", binaryType: "safe_persist", expectedBehavior: "EDR should detect suspicious scheduled task creation", riskLevel: "safe" },
  { id: "edr-pe-03", testName: "WMI Event Subscription", category: "persistence", mitreTechniqueId: "T1546.003", mitreTechniqueName: "WMI Event Subscription", description: "Creates a WMI event subscription for persistence", binaryType: "safe_persist", expectedBehavior: "EDR should detect WMI event subscription creation", riskLevel: "safe" },

  // Privilege Escalation
  { id: "edr-priv-01", testName: "Named Pipe Impersonation", category: "privilege_escalation", mitreTechniqueId: "T1134.001", mitreTechniqueName: "Token Impersonation/Theft", description: "Creates a named pipe to impersonate connecting clients", binaryType: "custom", expectedBehavior: "EDR should detect named pipe impersonation", riskLevel: "safe" },
  { id: "edr-priv-02", testName: "UAC Bypass via fodhelper", category: "privilege_escalation", mitreTechniqueId: "T1548.002", mitreTechniqueName: "Bypass User Account Control", description: "Bypasses UAC using fodhelper.exe registry manipulation", binaryType: "custom", expectedBehavior: "EDR should detect UAC bypass attempts", riskLevel: "safe" },

  // Command & Control
  { id: "edr-c2-01", testName: "DNS Tunneling", category: "command_and_control", mitreTechniqueId: "T1071.004", mitreTechniqueName: "Application Layer Protocol: DNS", description: "Encodes data in DNS queries for C2 communication", binaryType: "safe_c2", expectedBehavior: "EDR should detect anomalous DNS query patterns", riskLevel: "safe" },
  { id: "edr-c2-02", testName: "HTTP C2 Beacon", category: "command_and_control", mitreTechniqueId: "T1071.001", mitreTechniqueName: "Application Layer Protocol: Web Protocols", description: "Simulates periodic HTTP beacon to C2 server", binaryType: "safe_c2", expectedBehavior: "EDR should detect beaconing behavior", riskLevel: "safe" },

  // Exfiltration
  { id: "edr-exfil-01", testName: "Data Staging and Compression", category: "exfiltration", mitreTechniqueId: "T1560.001", mitreTechniqueName: "Archive Collected Data: Archive via Utility", description: "Stages and compresses files for exfiltration", binaryType: "safe_exfil", expectedBehavior: "EDR should detect bulk file staging and compression", riskLevel: "safe" },
  { id: "edr-exfil-02", testName: "Exfiltration Over HTTPS", category: "exfiltration", mitreTechniqueId: "T1048.002", mitreTechniqueName: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", description: "Exfiltrates staged data over HTTPS to external endpoint", binaryType: "safe_exfil", expectedBehavior: "EDR should detect large data transfers to unusual destinations", riskLevel: "safe" },

  // Execution
  { id: "edr-exec-01", testName: "PowerShell Encoded Command", category: "execution", mitreTechniqueId: "T1059.001", mitreTechniqueName: "PowerShell", description: "Executes base64-encoded PowerShell commands", binaryType: "custom", expectedBehavior: "EDR should detect encoded PowerShell execution", riskLevel: "safe" },
  { id: "edr-exec-02", testName: "MSHTA Script Execution", category: "execution", mitreTechniqueId: "T1218.005", mitreTechniqueName: "Mshta", description: "Uses mshta.exe to execute inline script", binaryType: "custom", expectedBehavior: "EDR should detect mshta-based script execution", riskLevel: "safe" },

  // Discovery
  { id: "edr-disc-01", testName: "BloodHound-style AD Enumeration", category: "discovery", mitreTechniqueId: "T1087.002", mitreTechniqueName: "Account Discovery: Domain Account", description: "Performs LDAP queries to enumerate domain objects similar to BloodHound/SharpHound", binaryType: "custom", expectedBehavior: "EDR should detect bulk LDAP enumeration", riskLevel: "safe" },

  // Collection
  { id: "edr-coll-01", testName: "Screen Capture", category: "collection", mitreTechniqueId: "T1113", mitreTechniqueName: "Screen Capture", description: "Captures screenshots of the desktop", binaryType: "custom", expectedBehavior: "EDR should detect automated screen capture", riskLevel: "safe" },

  // Impact
  { id: "edr-imp-01", testName: "Volume Shadow Copy Deletion", category: "impact", mitreTechniqueId: "T1490", mitreTechniqueName: "Inhibit System Recovery", description: "Attempts to delete volume shadow copies (simulated, non-destructive)", binaryType: "custom", expectedBehavior: "EDR should block and alert on shadow copy deletion", riskLevel: "safe" },
];

// ── Known EDR Products ──────────────────────────────────────────────────
export const KNOWN_EDR_PRODUCTS = [
  { vendor: "CrowdStrike", product: "Falcon", deploymentType: "endpoint" as const },
  { vendor: "Microsoft", product: "Defender for Endpoint", deploymentType: "endpoint" as const },
  { vendor: "SentinelOne", product: "Singularity", deploymentType: "endpoint" as const },
  { vendor: "Palo Alto Networks", product: "Cortex XDR", deploymentType: "hybrid" as const },
  { vendor: "Carbon Black", product: "VMware Carbon Black Cloud", deploymentType: "endpoint" as const },
  { vendor: "Trend Micro", product: "Vision One", deploymentType: "hybrid" as const },
  { vendor: "Sophos", product: "Intercept X", deploymentType: "endpoint" as const },
  { vendor: "Elastic", product: "Elastic Security", deploymentType: "hybrid" as const },
  { vendor: "Cybereason", product: "Defense Platform", deploymentType: "endpoint" as const },
  { vendor: "Trellix", product: "Endpoint Security", deploymentType: "endpoint" as const },
  { vendor: "Fortinet", product: "FortiEDR", deploymentType: "endpoint" as const },
  { vendor: "Bitdefender", product: "GravityZone", deploymentType: "endpoint" as const },
];

/**
 * Calculate EDR coverage score for a set of test results
 */
export function calculateEDRCoverage(results: Array<{ detectionResult: string | null; category: string }>) {
  const total = results.length;
  if (total === 0) return { overallScore: 0, byCategory: {} };

  const detected = results.filter(r => r.detectionResult === "detected" || r.detectionResult === "blocked").length;
  const partial = results.filter(r => r.detectionResult === "partial" || r.detectionResult === "delayed").length;
  const missed = results.filter(r => r.detectionResult === "missed").length;

  const overallScore = ((detected + partial * 0.5) / total) * 100;

  // Group by category
  const byCategory: Record<string, { total: number; detected: number; missed: number; score: number }> = {};
  for (const r of results) {
    if (!byCategory[r.category]) byCategory[r.category] = { total: 0, detected: 0, missed: 0, score: 0 };
    byCategory[r.category].total++;
    if (r.detectionResult === "detected" || r.detectionResult === "blocked") byCategory[r.category].detected++;
    if (r.detectionResult === "missed") byCategory[r.category].missed++;
  }
  for (const cat of Object.keys(byCategory)) {
    byCategory[cat].score = (byCategory[cat].detected / byCategory[cat].total) * 100;
  }

  return { overallScore: Math.round(overallScore * 10) / 10, detected, partial, missed, total, byCategory };
}

/**
 * Generate EDR effectiveness report summary
 */
export function generateEDRSummary(productName: string, vendor: string, coverage: ReturnType<typeof calculateEDRCoverage>) {
  const grade = coverage.overallScore >= 90 ? "A" : coverage.overallScore >= 80 ? "B" : coverage.overallScore >= 70 ? "C" : coverage.overallScore >= 60 ? "D" : "F";
  
  const weakCategories = Object.entries(coverage.byCategory)
    .filter(([_, v]) => v.score < 70)
    .map(([cat, v]) => ({ category: cat, score: v.score, missed: v.missed }))
    .sort((a, b) => a.score - b.score);

  return {
    productName,
    vendor,
    grade,
    overallScore: coverage.overallScore,
    totalTests: coverage.total,
    detected: coverage.detected,
    missed: coverage.missed,
    weakCategories,
    recommendation: grade === "A" || grade === "B" 
      ? "EDR coverage is strong. Focus on the few missed detections for improvement."
      : grade === "C"
      ? "EDR coverage has notable gaps. Prioritize tuning detection rules for weak categories."
      : "EDR coverage is insufficient. Consider supplementing with additional security controls or evaluating alternative products.",
  };
}
