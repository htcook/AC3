/**
 * SIEM Correlation & Blue Team Wins Module
 * 
 * Generates structured SIEM-correlatable data for every action taken during
 * a red team engagement, and captures "Blue Team Wins" — successful detections
 * and blocks by the client's security controls.
 * 
 * Purpose: Enable the client's SOC to correlate red team actions with their
 * SIEM events, validate detection capabilities, and identify coverage gaps.
 */

// ─── SIEM Correlation Types ──────────────────────────────────────────────────

export interface SiemCorrelationEntry {
  /** Unique action ID for cross-referencing */
  actionId: string;
  /** UTC timestamp when the action started */
  timestampStart: number;
  /** UTC timestamp when the action completed */
  timestampEnd: number;
  /** Source IP address used for this action */
  sourceIp: string;
  /** Source port (if known) */
  sourcePort: number | null;
  /** Destination IP address */
  destIp: string;
  /** Destination port */
  destPort: number;
  /** Protocol used (TCP, UDP, HTTP, HTTPS, SSH, etc.) */
  protocol: string;
  /** Target operating system (if identified) */
  targetOs: string | null;
  /** Target platform/framework (e.g., Apache 2.4, nginx 1.18, Node.js 18) */
  targetPlatform: string | null;
  /** Target service and version (e.g., OpenSSH 8.9p1, MySQL 8.0) */
  targetServiceVersion: string | null;
  /** MITRE ATT&CK technique ID (e.g., T1190, T1059.001) */
  mitreAttackId: string;
  /** MITRE ATT&CK tactic (e.g., Initial Access, Execution, Persistence) */
  mitreTactic: string;
  /** MITRE ATT&CK technique name (e.g., Exploit Public-Facing Application) */
  mitreTechniqueName: string;
  /** Tool used for this action */
  toolUsed: string;
  /** Command or request signature (for detection rule writing) */
  commandSignature: string;
  /** Expected SIEM log sources that should have recorded this action */
  expectedLogSources: SiemLogSource[];
  /** Whether the action was successful */
  actionSuccessful: boolean;
  /** Whether the action was detected by client controls */
  wasDetected: boolean;
  /** Detection details (if detected) */
  detectionDetails: DetectionDetail | null;
  /** Phase of the engagement */
  engagementPhase: string;
  /** Human-readable description of the action */
  description: string;
}

export type SiemLogSource =
  | "firewall"
  | "ids_ips"
  | "waf"
  | "edr"
  | "siem_rule"
  | "proxy_log"
  | "dns_log"
  | "auth_log"
  | "web_server_log"
  | "application_log"
  | "endpoint_log"
  | "email_gateway"
  | "network_flow";

export interface DetectionDetail {
  /** Which control detected the action */
  controlType: string;
  /** Name of the specific control/rule */
  controlName: string;
  /** Action taken by the control */
  actionTaken: "blocked" | "alerted" | "logged" | "rate_limited" | "challenged";
  /** Response time in milliseconds (from action to detection) */
  responseTimeMs: number | null;
}

// ─── Blue Team Win Types ─────────────────────────────────────────────────────

export type EffectivenessRating =
  | "blocked_completely"
  | "detected_and_blocked"
  | "detected_not_blocked"
  | "delayed_response"
  | "partial_block"
  | "logged_only";

export type ControlType =
  | "waf"
  | "ids_ips"
  | "edr"
  | "siem_rule"
  | "soc_analyst"
  | "firewall"
  | "rate_limiter"
  | "auth_lockout"
  | "network_segmentation"
  | "application_control"
  | "email_filter"
  | "dns_filter";

export interface BlueTeamWin {
  /** Unique win ID */
  id: string;
  /** UTC timestamp of the detection/block */
  timestamp: number;
  /** Source IP that was detected/blocked */
  sourceIp: string;
  /** Destination IP/host */
  destIp: string;
  /** Destination port */
  destPort: number;
  /** Protocol */
  protocol: string;
  /** MITRE ATT&CK technique that was detected */
  mitreAttackId: string;
  /** MITRE tactic */
  mitreTactic: string;
  /** MITRE technique name */
  mitreTechniqueName: string;
  /** Type of security control that detected/blocked */
  controlType: ControlType;
  /** Specific control name (e.g., "Cloudflare WAF Rule #12345") */
  controlName: string;
  /** Action taken by the control */
  actionTaken: "blocked" | "alerted" | "logged" | "rate_limited" | "challenged" | "quarantined";
  /** Response time from action to detection (ms) */
  responseTimeMs: number | null;
  /** Effectiveness rating */
  effectivenessRating: EffectivenessRating;
  /** Tool that triggered the detection */
  toolUsed: string;
  /** Engagement phase when detection occurred */
  engagementPhase: string;
  /** Human-readable description */
  description: string;
  /** Recommendation for the client */
  recommendation: string;
}

// ─── Detection Coverage Matrix ───────────────────────────────────────────────

export interface DetectionCoverageEntry {
  mitreAttackId: string;
  mitreTactic: string;
  mitreTechniqueName: string;
  attempted: boolean;
  detected: boolean;
  blocked: boolean;
  controlsInvolved: string[];
  gapAssessment: "covered" | "partial" | "gap";
  recommendation: string;
}

export interface DetectionCoverageMatrix {
  totalTechniquesAttempted: number;
  totalDetected: number;
  totalBlocked: number;
  totalGaps: number;
  coveragePercentage: number;
  blockPercentage: number;
  entries: DetectionCoverageEntry[];
}

// ─── In-Memory Registry ──────────────────────────────────────────────────────

const engagementCorrelations = new Map<number, SiemCorrelationEntry[]>();
const engagementBlueTeamWins = new Map<number, BlueTeamWin[]>();

// ─── SIEM Correlation Entry Creation ─────────────────────────────────────────

/**
 * Record a SIEM-correlatable action for an engagement.
 */
export function recordSiemAction(
  engagementId: number,
  entry: Omit<SiemCorrelationEntry, "actionId">,
): SiemCorrelationEntry {
  const actionId = `act-${engagementId}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const fullEntry: SiemCorrelationEntry = { ...entry, actionId };

  if (!engagementCorrelations.has(engagementId)) {
    engagementCorrelations.set(engagementId, []);
  }
  engagementCorrelations.get(engagementId)!.push(fullEntry);

  return fullEntry;
}

/**
 * Record a Blue Team Win for an engagement.
 */
export function recordBlueTeamWin(
  engagementId: number,
  win: Omit<BlueTeamWin, "id">,
): BlueTeamWin {
  const id = `btw-${engagementId}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const fullWin: BlueTeamWin = { ...win, id };

  if (!engagementBlueTeamWins.has(engagementId)) {
    engagementBlueTeamWins.set(engagementId, []);
  }
  engagementBlueTeamWins.get(engagementId)!.push(fullWin);

  return fullWin;
}

// ─── Auto-Detection from Pipeline Events ─────────────────────────────────────

/**
 * Analyze a scan/exploit response and auto-generate Blue Team Win if detection found.
 */
export function analyzeForBlueTeamWin(
  engagementId: number,
  context: {
    sourceIp: string;
    destIp: string;
    destPort: number;
    protocol: string;
    mitreAttackId: string;
    mitreTactic: string;
    mitreTechniqueName: string;
    toolUsed: string;
    engagementPhase: string;
    responseStatusCode?: number;
    responseBody?: string;
    errorMessage?: string;
    responseTimeMs?: number;
  },
): BlueTeamWin | null {
  // WAF Block Detection
  if (context.responseStatusCode === 403 &&
      context.responseBody?.match(/blocked|denied|firewall|waf|cloudflare|akamai|imperva|f5|barracuda/i)) {
    const wafName = detectWafName(context.responseBody);
    return recordBlueTeamWin(engagementId, {
      timestamp: Date.now(),
      sourceIp: context.sourceIp,
      destIp: context.destIp,
      destPort: context.destPort,
      protocol: context.protocol,
      mitreAttackId: context.mitreAttackId,
      mitreTactic: context.mitreTactic,
      mitreTechniqueName: context.mitreTechniqueName,
      controlType: "waf",
      controlName: wafName,
      actionTaken: "blocked",
      responseTimeMs: context.responseTimeMs || null,
      effectivenessRating: "blocked_completely",
      toolUsed: context.toolUsed,
      engagementPhase: context.engagementPhase,
      description: `WAF (${wafName}) blocked ${context.toolUsed} request targeting ${context.destIp}:${context.destPort}`,
      recommendation: `WAF rule effective against ${context.mitreTechniqueName}. Consider extending similar rules to other endpoints.`,
    });
  }

  // Rate Limiting Detection
  if (context.responseStatusCode === 429) {
    return recordBlueTeamWin(engagementId, {
      timestamp: Date.now(),
      sourceIp: context.sourceIp,
      destIp: context.destIp,
      destPort: context.destPort,
      protocol: context.protocol,
      mitreAttackId: context.mitreAttackId,
      mitreTactic: context.mitreTactic,
      mitreTechniqueName: context.mitreTechniqueName,
      controlType: "rate_limiter",
      controlName: "Rate Limiter",
      actionTaken: "rate_limited",
      responseTimeMs: context.responseTimeMs || null,
      effectivenessRating: "partial_block",
      toolUsed: context.toolUsed,
      engagementPhase: context.engagementPhase,
      description: `Rate limiter throttled ${context.toolUsed} scanning against ${context.destIp}:${context.destPort}`,
      recommendation: `Rate limiting is working but may not fully prevent determined attackers. Consider combining with IP reputation blocking.`,
    });
  }

  // Connection Reset / IP Block
  if (context.errorMessage?.match(/ECONNRESET|ECONNREFUSED|EHOSTUNREACH/)) {
    return recordBlueTeamWin(engagementId, {
      timestamp: Date.now(),
      sourceIp: context.sourceIp,
      destIp: context.destIp,
      destPort: context.destPort,
      protocol: context.protocol,
      mitreAttackId: context.mitreAttackId,
      mitreTactic: context.mitreTactic,
      mitreTechniqueName: context.mitreTechniqueName,
      controlType: "firewall",
      controlName: "Network Firewall / IDS",
      actionTaken: "blocked",
      responseTimeMs: context.responseTimeMs || null,
      effectivenessRating: "blocked_completely",
      toolUsed: context.toolUsed,
      engagementPhase: context.engagementPhase,
      description: `Firewall/IDS blocked connection from ${context.sourceIp} to ${context.destIp}:${context.destPort} (${context.errorMessage})`,
      recommendation: `Network-level blocking is effective. Ensure similar rules cover all in-scope assets.`,
    });
  }

  // CAPTCHA / Challenge
  if (context.responseBody?.match(/captcha|challenge|verify.*human|recaptcha|hcaptcha/i)) {
    return recordBlueTeamWin(engagementId, {
      timestamp: Date.now(),
      sourceIp: context.sourceIp,
      destIp: context.destIp,
      destPort: context.destPort,
      protocol: context.protocol,
      mitreAttackId: context.mitreAttackId,
      mitreTactic: context.mitreTactic,
      mitreTechniqueName: context.mitreTechniqueName,
      controlType: "application_control",
      controlName: "CAPTCHA Challenge",
      actionTaken: "challenged",
      responseTimeMs: context.responseTimeMs || null,
      effectivenessRating: "detected_and_blocked",
      toolUsed: context.toolUsed,
      engagementPhase: context.engagementPhase,
      description: `Application challenge (CAPTCHA) triggered by ${context.toolUsed} activity against ${context.destIp}`,
      recommendation: `CAPTCHA challenge effectively disrupted automated scanning. Consider adding progressive challenges for repeated suspicious requests.`,
    });
  }

  // Auth Lockout
  if (context.responseStatusCode === 423 ||
      context.responseBody?.match(/locked|lockout|too many.*attempts|account.*disabled/i)) {
    return recordBlueTeamWin(engagementId, {
      timestamp: Date.now(),
      sourceIp: context.sourceIp,
      destIp: context.destIp,
      destPort: context.destPort,
      protocol: context.protocol,
      mitreAttackId: context.mitreAttackId,
      mitreTactic: context.mitreTactic,
      mitreTechniqueName: context.mitreTechniqueName,
      controlType: "auth_lockout",
      controlName: "Account Lockout Policy",
      actionTaken: "blocked",
      responseTimeMs: context.responseTimeMs || null,
      effectivenessRating: "blocked_completely",
      toolUsed: context.toolUsed,
      engagementPhase: context.engagementPhase,
      description: `Account lockout triggered by brute-force attempt from ${context.sourceIp} against ${context.destIp}`,
      recommendation: `Account lockout policy is effective. Ensure lockout thresholds are consistent across all authentication endpoints.`,
    });
  }

  return null;
}

function detectWafName(body: string): string {
  if (body.match(/cloudflare/i)) return "Cloudflare WAF";
  if (body.match(/akamai/i)) return "Akamai Kona WAF";
  if (body.match(/imperva|incapsula/i)) return "Imperva WAF";
  if (body.match(/f5|big-?ip/i)) return "F5 BIG-IP ASM";
  if (body.match(/barracuda/i)) return "Barracuda WAF";
  if (body.match(/aws.*waf|awswaf/i)) return "AWS WAF";
  if (body.match(/azure.*front|afd/i)) return "Azure Front Door WAF";
  if (body.match(/modsecurity|mod_security/i)) return "ModSecurity WAF";
  if (body.match(/sucuri/i)) return "Sucuri WAF";
  return "Unknown WAF";
}

// ─── Detection Coverage Matrix Generation ────────────────────────────────────

/**
 * Generate a detection coverage matrix from all SIEM correlation entries.
 */
export function generateDetectionCoverageMatrix(engagementId: number): DetectionCoverageMatrix {
  const correlations = engagementCorrelations.get(engagementId) || [];
  const blueWins = engagementBlueTeamWins.get(engagementId) || [];

  // Group by MITRE technique
  const techniqueMap = new Map<string, {
    id: string;
    tactic: string;
    name: string;
    attempted: boolean;
    detected: boolean;
    blocked: boolean;
    controls: Set<string>;
  }>();

  for (const entry of correlations) {
    const key = entry.mitreAttackId;
    if (!techniqueMap.has(key)) {
      techniqueMap.set(key, {
        id: entry.mitreAttackId,
        tactic: entry.mitreTactic,
        name: entry.mitreTechniqueName,
        attempted: true,
        detected: entry.wasDetected,
        blocked: false,
        controls: new Set(),
      });
    }
    const t = techniqueMap.get(key)!;
    if (entry.wasDetected) {
      t.detected = true;
      if (entry.detectionDetails) {
        t.controls.add(entry.detectionDetails.controlName);
      }
    }
  }

  // Merge blue team wins
  for (const win of blueWins) {
    const key = win.mitreAttackId;
    if (!techniqueMap.has(key)) {
      techniqueMap.set(key, {
        id: win.mitreAttackId,
        tactic: win.mitreTactic,
        name: win.mitreTechniqueName,
        attempted: true,
        detected: true,
        blocked: win.actionTaken === "blocked",
        controls: new Set([win.controlName]),
      });
    } else {
      const t = techniqueMap.get(key)!;
      t.detected = true;
      if (win.actionTaken === "blocked") t.blocked = true;
      t.controls.add(win.controlName);
    }
  }

  const entries: DetectionCoverageEntry[] = Array.from(techniqueMap.values()).map(t => ({
    mitreAttackId: t.id,
    mitreTactic: t.tactic,
    mitreTechniqueName: t.name,
    attempted: t.attempted,
    detected: t.detected,
    blocked: t.blocked,
    controlsInvolved: Array.from(t.controls),
    gapAssessment: t.blocked ? "covered" : t.detected ? "partial" : "gap",
    recommendation: t.blocked
      ? `Detection and blocking effective for ${t.name}. Maintain current controls.`
      : t.detected
        ? `${t.name} was detected but not blocked. Add blocking rules to ${Array.from(t.controls).join(", ")} or deploy additional controls.`
        : `${t.name} was NOT detected. This is a detection gap. Implement SIEM rules, IDS signatures, or EDR policies to detect this technique.`,
  }));

  const totalAttempted = entries.length;
  const totalDetected = entries.filter(e => e.detected).length;
  const totalBlocked = entries.filter(e => e.blocked).length;
  const totalGaps = entries.filter(e => e.gapAssessment === "gap").length;

  return {
    totalTechniquesAttempted: totalAttempted,
    totalDetected,
    totalBlocked,
    totalGaps,
    coveragePercentage: totalAttempted > 0 ? Math.round((totalDetected / totalAttempted) * 100) : 0,
    blockPercentage: totalAttempted > 0 ? Math.round((totalBlocked / totalAttempted) * 100) : 0,
    entries,
  };
}

// ─── Expected Log Source Mapping ─────────────────────────────────────────────

/**
 * Map a MITRE ATT&CK technique to expected SIEM log sources.
 */
export function getExpectedLogSources(mitreAttackId: string, protocol: string): SiemLogSource[] {
  const sources: SiemLogSource[] = [];

  // Network-level actions
  if (["TCP", "UDP", "ICMP"].includes(protocol.toUpperCase())) {
    sources.push("firewall", "network_flow");
  }

  // Web-based actions
  if (["HTTP", "HTTPS"].includes(protocol.toUpperCase())) {
    sources.push("waf", "web_server_log", "proxy_log");
  }

  // Technique-specific log sources
  const techniqueLogMap: Record<string, SiemLogSource[]> = {
    // Reconnaissance
    "T1595": ["firewall", "waf", "ids_ips", "network_flow"],
    "T1595.001": ["firewall", "ids_ips", "network_flow"],
    "T1595.002": ["waf", "web_server_log", "ids_ips"],
    // Initial Access
    "T1190": ["waf", "web_server_log", "application_log", "ids_ips"],
    "T1133": ["auth_log", "firewall", "endpoint_log"],
    "T1078": ["auth_log", "siem_rule", "endpoint_log"],
    // Execution
    "T1059": ["endpoint_log", "edr", "siem_rule"],
    "T1059.001": ["endpoint_log", "edr", "siem_rule"],
    "T1059.003": ["endpoint_log", "edr", "siem_rule"],
    "T1059.004": ["endpoint_log", "edr", "siem_rule"],
    // Persistence
    "T1136": ["auth_log", "siem_rule", "endpoint_log"],
    "T1098": ["auth_log", "siem_rule"],
    "T1053": ["endpoint_log", "edr", "siem_rule"],
    // Privilege Escalation
    "T1068": ["endpoint_log", "edr", "siem_rule"],
    "T1548": ["endpoint_log", "edr", "auth_log"],
    // Defense Evasion
    "T1070": ["siem_rule", "endpoint_log", "edr"],
    "T1562": ["siem_rule", "edr", "endpoint_log"],
    // Credential Access
    "T1110": ["auth_log", "siem_rule", "ids_ips"],
    "T1110.001": ["auth_log", "siem_rule"],
    "T1110.003": ["auth_log", "siem_rule"],
    "T1003": ["endpoint_log", "edr", "siem_rule"],
    // Discovery
    "T1046": ["firewall", "ids_ips", "network_flow"],
    "T1018": ["dns_log", "network_flow"],
    // Lateral Movement
    "T1021": ["auth_log", "firewall", "endpoint_log"],
    "T1021.001": ["auth_log", "endpoint_log", "network_flow"],
    "T1021.004": ["auth_log", "endpoint_log"],
    // Collection
    "T1005": ["endpoint_log", "edr"],
    // Command and Control
    "T1071": ["proxy_log", "dns_log", "firewall", "ids_ips"],
    "T1071.001": ["proxy_log", "waf", "ids_ips"],
    "T1105": ["proxy_log", "firewall", "edr"],
    // Exfiltration
    "T1041": ["proxy_log", "firewall", "network_flow", "ids_ips"],
    "T1048": ["dns_log", "firewall", "network_flow"],
    // Impact
    "T1486": ["endpoint_log", "edr", "siem_rule"],
    "T1489": ["endpoint_log", "edr", "siem_rule"],
  };

  const techniqueSources = techniqueLogMap[mitreAttackId];
  if (techniqueSources) {
    for (const s of techniqueSources) {
      if (!sources.includes(s)) sources.push(s);
    }
  }

  // Always include SIEM as a meta-source
  if (!sources.includes("siem_rule")) sources.push("siem_rule");

  return sources;
}

// ─── MITRE ATT&CK Mapping Helpers ────────────────────────────────────────────

export interface MitreMapping {
  id: string;
  tactic: string;
  technique: string;
}

/**
 * Map common pentest tools/actions to MITRE ATT&CK techniques.
 */
export function mapToolToMitre(tool: string, action: string): MitreMapping {
  const mappings: Record<string, MitreMapping> = {
    "nmap:port_scan": { id: "T1046", tactic: "Discovery", technique: "Network Service Discovery" },
    "nmap:os_detection": { id: "T1082", tactic: "Discovery", technique: "System Information Discovery" },
    "nuclei:vuln_scan": { id: "T1595.002", tactic: "Reconnaissance", technique: "Active Scanning: Vulnerability Scanning" },
    "zap:active_scan": { id: "T1595.002", tactic: "Reconnaissance", technique: "Active Scanning: Vulnerability Scanning" },
    "zap:spider": { id: "T1595.002", tactic: "Reconnaissance", technique: "Active Scanning: Vulnerability Scanning" },
    "httpx:fingerprint": { id: "T1595.002", tactic: "Reconnaissance", technique: "Active Scanning: Vulnerability Scanning" },
    "ssh:brute_force": { id: "T1110.001", tactic: "Credential Access", technique: "Brute Force: Password Guessing" },
    "ssh:credential_spray": { id: "T1110.003", tactic: "Credential Access", technique: "Brute Force: Password Spraying" },
    "ssh:login": { id: "T1021.004", tactic: "Lateral Movement", technique: "Remote Services: SSH" },
    "exploit:sqli": { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
    "exploit:xss": { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
    "exploit:rce": { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
    "exploit:lfi": { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
    "exploit:rfi": { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
    "exploit:command_injection": { id: "T1059", tactic: "Execution", technique: "Command and Scripting Interpreter" },
    "caldera:agent_deploy": { id: "T1105", tactic: "Command and Control", technique: "Ingress Tool Transfer" },
    "caldera:c2_callback": { id: "T1071.001", tactic: "Command and Control", technique: "Application Layer Protocol: Web Protocols" },
    "caldera:credential_dump": { id: "T1003", tactic: "Credential Access", technique: "OS Credential Dumping" },
    "caldera:privilege_escalation": { id: "T1068", tactic: "Privilege Escalation", technique: "Exploitation for Privilege Escalation" },
    "caldera:persistence": { id: "T1053", tactic: "Persistence", technique: "Scheduled Task/Job" },
    "caldera:lateral_movement": { id: "T1021", tactic: "Lateral Movement", technique: "Remote Services" },
    "caldera:data_collection": { id: "T1005", tactic: "Collection", technique: "Data from Local System" },
    "caldera:exfiltration": { id: "T1041", tactic: "Exfiltration", technique: "Exfiltration Over C2 Channel" },
    "osint:domain_intel": { id: "T1596", tactic: "Reconnaissance", technique: "Search Open Technical Databases" },
    "osint:whois": { id: "T1596.002", tactic: "Reconnaissance", technique: "Search Open Technical Databases: WHOIS" },
    "osint:dns_enum": { id: "T1018", tactic: "Discovery", technique: "Remote System Discovery" },
    "gobuster:dir_brute": { id: "T1595.003", tactic: "Reconnaissance", technique: "Active Scanning: Wordlist Scanning" },
  };

  const key = `${tool}:${action}`;
  return mappings[key] || {
    id: "T1595",
    tactic: "Reconnaissance",
    technique: "Active Scanning",
  };
}

// ─── Report Section Generators ───────────────────────────────────────────────

/**
 * Generate the SIEM Correlation Table section for the report.
 */
export function generateSiemCorrelationSection(engagementId: number): string {
  const correlations = engagementCorrelations.get(engagementId) || [];
  if (correlations.length === 0) return "";

  let md = `## SIEM Correlation Log\n\n`;
  md += `The following table provides a chronological log of all red team actions with SIEM-correlatable metadata. `;
  md += `Use this data to validate your SIEM detection rules and identify coverage gaps.\n\n`;

  md += `| Timestamp (UTC) | Source IP | Dest IP:Port | Protocol | MITRE ATT&CK | Tool | Action | Detected? | Expected Log Sources |\n`;
  md += `|---|---|---|---|---|---|---|---|---|\n`;

  for (const entry of correlations.sort((a, b) => a.timestampStart - b.timestampStart)) {
    const ts = new Date(entry.timestampStart).toISOString().replace("T", " ").slice(0, 19);
    const detected = entry.wasDetected ? "YES" : "NO";
    const logSources = entry.expectedLogSources.join(", ");
    md += `| ${ts} | ${entry.sourceIp} | ${entry.destIp}:${entry.destPort} | ${entry.protocol} | ${entry.mitreAttackId} (${entry.mitreTactic}) | ${entry.toolUsed} | ${entry.description.slice(0, 50)} | ${detected} | ${logSources} |\n`;
  }
  md += `\n`;

  // Command signatures for detection rule writing
  md += `### Tool Command Signatures\n\n`;
  md += `The following command signatures can be used to write detection rules in your SIEM:\n\n`;

  const uniqueSignatures = new Map<string, string>();
  for (const entry of correlations) {
    if (entry.commandSignature && !uniqueSignatures.has(entry.commandSignature)) {
      uniqueSignatures.set(entry.commandSignature, entry.toolUsed);
    }
  }

  for (const [sig, tool] of uniqueSignatures) {
    md += `**${tool}:**\n\`\`\`\n${sig}\n\`\`\`\n\n`;
  }

  return md;
}

/**
 * Generate the Blue Team Wins section for the report.
 */
export function generateBlueTeamWinsSection(engagementId: number): string {
  const wins = engagementBlueTeamWins.get(engagementId) || [];
  if (wins.length === 0) {
    let md = `## Blue Team Wins — Positive Detection Findings\n\n`;
    md += `No successful detections or blocks were recorded during this engagement. `;
    md += `This indicates significant gaps in the organization's detection capabilities.\n\n`;
    return md;
  }

  let md = `## Blue Team Wins — Positive Detection Findings\n\n`;
  md += `The following table documents successful detections and blocks by the organization's security controls. `;
  md += `These represent positive findings that validate existing security investments.\n\n`;

  md += `| Timestamp (UTC) | Source IP | Target | Control | Action | MITRE ATT&CK | Effectiveness | Response Time |\n`;
  md += `|---|---|---|---|---|---|---|---|\n`;

  for (const win of wins.sort((a, b) => a.timestamp - b.timestamp)) {
    const ts = new Date(win.timestamp).toISOString().replace("T", " ").slice(0, 19);
    const responseTime = win.responseTimeMs ? `${win.responseTimeMs}ms` : "N/A";
    md += `| ${ts} | ${win.sourceIp} | ${win.destIp}:${win.destPort} | ${win.controlName} | ${win.actionTaken} | ${win.mitreAttackId} | ${win.effectivenessRating} | ${responseTime} |\n`;
  }
  md += `\n`;

  // Detailed findings
  md += `### Detailed Detection Findings\n\n`;
  for (let i = 0; i < wins.length; i++) {
    const win = wins[i];
    md += `**${i + 1}. ${win.controlName} — ${win.actionTaken.toUpperCase()}**\n\n`;
    md += `| Field | Value |\n|---|---|\n`;
    md += `| Timestamp | ${new Date(win.timestamp).toISOString()} |\n`;
    md += `| Source IP | ${win.sourceIp} |\n`;
    md += `| Target | ${win.destIp}:${win.destPort} (${win.protocol}) |\n`;
    md += `| MITRE ATT&CK | ${win.mitreAttackId} — ${win.mitreTechniqueName} (${win.mitreTactic}) |\n`;
    md += `| Control Type | ${win.controlType} |\n`;
    md += `| Tool Detected | ${win.toolUsed} |\n`;
    md += `| Effectiveness | ${win.effectivenessRating} |\n`;
    md += `| Response Time | ${win.responseTimeMs ? `${win.responseTimeMs}ms` : "N/A"} |\n\n`;
    md += `> ${win.description}\n\n`;
    md += `**Recommendation:** ${win.recommendation}\n\n`;
  }

  return md;
}

/**
 * Generate the Detection Coverage Matrix section for the report.
 */
export function generateDetectionCoverageSection(engagementId: number): string {
  const matrix = generateDetectionCoverageMatrix(engagementId);

  let md = `## Detection Coverage Matrix\n\n`;
  md += `This matrix maps all MITRE ATT&CK techniques attempted during the engagement against the organization's detection and blocking capabilities.\n\n`;

  md += `### Summary\n\n`;
  md += `| Metric | Value |\n|---|---|\n`;
  md += `| Techniques Attempted | ${matrix.totalTechniquesAttempted} |\n`;
  md += `| Techniques Detected | ${matrix.totalDetected} |\n`;
  md += `| Techniques Blocked | ${matrix.totalBlocked} |\n`;
  md += `| Detection Gaps | ${matrix.totalGaps} |\n`;
  md += `| Detection Coverage | ${matrix.coveragePercentage}% |\n`;
  md += `| Block Coverage | ${matrix.blockPercentage}% |\n\n`;

  md += `### Technique-Level Coverage\n\n`;
  md += `| MITRE ID | Tactic | Technique | Detected | Blocked | Controls | Assessment |\n`;
  md += `|---|---|---|---|---|---|---|\n`;

  for (const entry of matrix.entries) {
    const detected = entry.detected ? "YES" : "NO";
    const blocked = entry.blocked ? "YES" : "NO";
    const controls = entry.controlsInvolved.join(", ") || "None";
    const assessment = entry.gapAssessment === "covered" ? "COVERED" :
                       entry.gapAssessment === "partial" ? "PARTIAL" : "**GAP**";
    md += `| ${entry.mitreAttackId} | ${entry.mitreTactic} | ${entry.mitreTechniqueName} | ${detected} | ${blocked} | ${controls} | ${assessment} |\n`;
  }
  md += `\n`;

  // Gap recommendations
  const gaps = matrix.entries.filter(e => e.gapAssessment === "gap");
  if (gaps.length > 0) {
    md += `### Detection Gap Recommendations\n\n`;
    for (const gap of gaps) {
      md += `- **${gap.mitreAttackId} (${gap.mitreTechniqueName}):** ${gap.recommendation}\n`;
    }
    md += `\n`;
  }

  return md;
}

// ─── Getters ─────────────────────────────────────────────────────────────────

export function getSiemCorrelations(engagementId: number): SiemCorrelationEntry[] {
  return engagementCorrelations.get(engagementId) || [];
}

export function getBlueTeamWins(engagementId: number): BlueTeamWin[] {
  return engagementBlueTeamWins.get(engagementId) || [];
}
