/**
 * PLC Integrity Monitoring Engine
 * 
 * Monitors programmable logic controllers for indicators of compromise
 * based on documented CyberAv3ngers/IRGC-CEC TTPs from CISA AA26-097A.
 * 
 * Detection Model:
 * - Credential manipulation (password changes, username changes)
 * - IP address redirection (controller IP modified to lock out operators)
 * - Project file tampering (ladder logic modifications, AOI manipulation)
 * - Safety logic disablement (shutdown/alarm systems disabled)
 * - HMI/SCADA display manipulation (false readings to operators)
 * - Unauthorized engineering software connections
 * 
 * Supported PLC Families:
 * - Rockwell Automation MicroLogix 1100/1400
 * - Rockwell Automation CompactLogix/ControlLogix
 * - Schneider Electric Modicon M340 (BMX P34)
 * - Siemens S7-1200/S7-1500
 * 
 * Author: Harrison Cook / AC3 Platform
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export type PlcVendor = "rockwell" | "schneider" | "siemens" | "unitronics" | "other";
export type PlcProtocol = "ethernet_ip" | "modbus" | "s7comm" | "pcom" | "opc_ua";
export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";
export type MonitorStatus = "healthy" | "degraded" | "compromised" | "offline" | "unknown";

export interface PlcDevice {
  id: string;
  name: string;
  vendor: PlcVendor;
  model: string;
  firmwareVersion: string;
  ipAddress: string;
  protocol: PlcProtocol;
  port: number;
  facilityName: string;
  facilityType: "water_treatment" | "wastewater" | "pump_station" | "lift_station" | "water_tower" | "power_substation" | "gas_distribution" | "other";
  sector: "water" | "energy" | "government" | "manufacturing" | "other";
  connectionType: "ethernet" | "cellular" | "serial" | "vpn" | "direct_internet";
  isInternetExposed: boolean;
  lastKnownGoodHash: string; // SHA-256 of project file
  lastCheckin: Date;
  status: MonitorStatus;
  engagementId?: number; // Linked client engagement
}

export interface IntegrityBaseline {
  deviceId: string;
  capturedAt: Date;
  projectFileHash: string;
  ladderLogicHash: string;
  aoiHashes: Record<string, string>; // AOI name → hash
  ipConfig: {
    address: string;
    subnet: string;
    gateway: string;
    dns: string[];
  };
  credentials: {
    passwordSet: boolean;
    passwordHash: string; // Not the actual password, just a verification hash
    lastChanged: Date;
  };
  safetyLogic: {
    shutdownEnabled: boolean;
    alarmSystemEnabled: boolean;
    safetyInterlocks: string[];
  };
  runMode: "run" | "program" | "remote" | "test";
  firmwareVersion: string;
  moduleInventory: string[]; // List of installed modules
}

export interface IntegrityAlert {
  id: string;
  deviceId: string;
  deviceName: string;
  facilityName: string;
  alertType: IntegrityAlertType;
  severity: AlertSeverity;
  timestamp: Date;
  description: string;
  technicalDetails: string;
  mitreAttackId: string;
  mitreAttackTechnique: string;
  threatActorAssociation: string;
  cisaAdvisory?: string;
  recommendedActions: string[];
  rawEvidence: Record<string, any>;
  acknowledged: boolean;
  resolvedAt?: Date;
}

export type IntegrityAlertType =
  | "credential_change"       // Password/username modified (CyberAv3ngers primary TTP)
  | "ip_redirect"             // IP address changed to lock out operators
  | "project_file_tampered"   // Ladder logic or project file modified
  | "aoi_manipulation"        // Add-On Instructions modified (safety logic disabled)
  | "safety_logic_disabled"   // Shutdown/alarm systems disabled
  | "hmi_display_manipulation" // False data on operator displays
  | "unauthorized_connection" // Engineering software connection from unknown source
  | "firmware_change"         // Firmware modified without authorization
  | "run_mode_change"         // Device switched from RUN to PROGRAM mode
  | "communication_loss"      // Device went offline unexpectedly
  | "internet_exposure"       // Device detected as internet-accessible
  | "cellular_modem_compromise" // Cellular gateway compromised
  | "project_file_exfiltration" // Project file downloaded to external system
  | "protocol_anomaly";       // Unusual protocol traffic patterns

// ─── MITRE ATT&CK for ICS Mapping ──────────────────────────────────────────────

const MITRE_ICS_MAPPING: Record<IntegrityAlertType, { id: string; technique: string; tactic: string }> = {
  credential_change: { id: "T0859", technique: "Valid Accounts", tactic: "Persistence" },
  ip_redirect: { id: "T0836", technique: "Modify Parameter", tactic: "Impair Process Control" },
  project_file_tampered: { id: "T0839", technique: "Module Firmware", tactic: "Persistence" },
  aoi_manipulation: { id: "T0821", technique: "Modify Controller Tasking", tactic: "Execution" },
  safety_logic_disabled: { id: "T0880", technique: "Loss of Safety", tactic: "Impact" },
  hmi_display_manipulation: { id: "T0832", technique: "Manipulation of View", tactic: "Impact" },
  unauthorized_connection: { id: "T0886", technique: "Remote Services", tactic: "Lateral Movement" },
  firmware_change: { id: "T0839", technique: "Module Firmware", tactic: "Persistence" },
  run_mode_change: { id: "T0858", technique: "Change Operating Mode", tactic: "Evasion" },
  communication_loss: { id: "T0826", technique: "Loss of Availability", tactic: "Impact" },
  internet_exposure: { id: "T0883", technique: "Internet Accessible Device", tactic: "Initial Access" },
  cellular_modem_compromise: { id: "T0886", technique: "Remote Services", tactic: "Initial Access" },
  project_file_exfiltration: { id: "T0882", technique: "Theft of Operational Information", tactic: "Collection" },
  protocol_anomaly: { id: "T0869", technique: "Standard Application Layer Protocol", tactic: "Command and Control" },
};

// ─── Threat Actor TTP Signatures ────────────────────────────────────────────────

interface ThreatActorSignature {
  name: string;
  aliases: string[];
  sponsor: string;
  ttps: IntegrityAlertType[];
  targetedVendors: PlcVendor[];
  targetedSectors: string[];
  cisaAdvisories: string[];
  confidence: "high" | "moderate" | "low";
}

const THREAT_ACTOR_SIGNATURES: ThreatActorSignature[] = [
  {
    name: "CyberAv3ngers",
    aliases: ["Storm-0784", "Bauxite", "Hydro Kitten", "UNC5691", "G1027"],
    sponsor: "IRGC Cyber-Electronic Command (IRGC-CEC)",
    ttps: [
      "credential_change",
      "ip_redirect",
      "project_file_tampered",
      "aoi_manipulation",
      "safety_logic_disabled",
      "hmi_display_manipulation",
      "unauthorized_connection",
      "project_file_exfiltration",
      "internet_exposure",
    ],
    targetedVendors: ["rockwell", "schneider", "siemens", "unitronics"],
    targetedSectors: ["water", "energy", "government"],
    cisaAdvisories: ["AA26-097A", "AA23-335A"],
    confidence: "high",
  },
  {
    name: "Handala",
    aliases: ["Void Manticore"],
    sponsor: "MOIS (Ministry of Intelligence and Security)",
    ttps: [
      "credential_change",
      "communication_loss",
      "hmi_display_manipulation",
    ],
    targetedVendors: ["rockwell", "schneider"],
    targetedSectors: ["water", "energy"],
    cisaAdvisories: [],
    confidence: "moderate",
  },
  {
    name: "Sandworm",
    aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard"],
    sponsor: "GRU Unit 74455 (Russia)",
    ttps: [
      "project_file_tampered",
      "safety_logic_disabled",
      "firmware_change",
      "communication_loss",
    ],
    targetedVendors: ["siemens", "schneider"],
    targetedSectors: ["energy", "water", "government"],
    cisaAdvisories: ["AA22-110A"],
    confidence: "high",
  },
  {
    name: "CHERNOVITE",
    aliases: ["COSMICENERGY"],
    sponsor: "Russia (assessed)",
    ttps: [
      "project_file_tampered",
      "safety_logic_disabled",
      "unauthorized_connection",
      "protocol_anomaly",
    ],
    targetedVendors: ["schneider", "siemens"],
    targetedSectors: ["energy"],
    cisaAdvisories: [],
    confidence: "moderate",
  },
  {
    name: "XENOTIME",
    aliases: ["TEMP.Veles"],
    sponsor: "Russia (CNIIHM)",
    ttps: [
      "safety_logic_disabled",
      "firmware_change",
      "project_file_tampered",
      "protocol_anomaly",
    ],
    targetedVendors: ["schneider"],
    targetedSectors: ["energy"],
    cisaAdvisories: ["MAR-17-352-01"],
    confidence: "high",
  },
];

// ─── Known Vulnerable Ports ─────────────────────────────────────────────────────

const VULNERABLE_PORTS: Record<PlcProtocol, number[]> = {
  ethernet_ip: [44818, 2222],
  modbus: [502],
  s7comm: [102],
  pcom: [20256],
  opc_ua: [4840],
};

// ─── In-Memory State ────────────────────────────────────────────────────────────

let monitoredDevices: PlcDevice[] = [];
let baselines: Map<string, IntegrityBaseline> = new Map();
let alerts: IntegrityAlert[] = [];
let monitoringActive = false;

// ─── Core Engine Functions ──────────────────────────────────────────────────────

/**
 * Initialize the PLC integrity monitoring engine
 */
export function initializeMonitor(devices: PlcDevice[]): { success: boolean; devicesRegistered: number; exposedDevices: number } {
  monitoredDevices = devices;
  monitoringActive = true;

  const exposedDevices = devices.filter(d => d.isInternetExposed).length;

  // Generate alerts for any internet-exposed devices
  for (const device of devices) {
    if (device.isInternetExposed) {
      generateAlert(device, "internet_exposure", "critical",
        `PLC ${device.name} at ${device.facilityName} is directly exposed to the internet on ${device.connectionType} connection`,
        `Device ${device.model} (${device.vendor}) accessible on port ${device.port} via ${device.connectionType}. ` +
        `This matches the attack surface exploited by CyberAv3ngers in the July 2026 Minnesota water attacks.`,
        { port: device.port, connectionType: device.connectionType, ipAddress: device.ipAddress }
      );
    }
  }

  return { success: true, devicesRegistered: devices.length, exposedDevices };
}

/**
 * Capture an integrity baseline for a device
 */
export function captureBaseline(deviceId: string, baseline: IntegrityBaseline): { success: boolean } {
  baselines.set(deviceId, baseline);
  return { success: true };
}

/**
 * Check a device against its baseline — detect tampering
 */
export function checkIntegrity(deviceId: string, currentState: Partial<IntegrityBaseline>): IntegrityAlert[] {
  const device = monitoredDevices.find(d => d.id === deviceId);
  const baseline = baselines.get(deviceId);
  if (!device || !baseline) return [];

  const newAlerts: IntegrityAlert[] = [];

  // Check for credential changes (CyberAv3ngers primary TTP)
  if (currentState.credentials && currentState.credentials.passwordHash !== baseline.credentials.passwordHash) {
    newAlerts.push(generateAlert(device, "credential_change", "critical",
      `Password changed on PLC ${device.name} without authorization`,
      `Credential hash mismatch detected. Previous: ${baseline.credentials.passwordHash.substring(0, 8)}... ` +
      `Current: ${currentState.credentials.passwordHash.substring(0, 8)}... ` +
      `This is the PRIMARY TTP used by CyberAv3ngers in the July 2026 water utility attacks (FBI PSA 260730).`,
      { previousHash: baseline.credentials.passwordHash, currentHash: currentState.credentials.passwordHash }
    ));
  }

  // Check for IP address redirection
  if (currentState.ipConfig && currentState.ipConfig.address !== baseline.ipConfig.address) {
    newAlerts.push(generateAlert(device, "ip_redirect", "critical",
      `IP address changed on PLC ${device.name} — operator lockout likely`,
      `Device IP changed from ${baseline.ipConfig.address} to ${currentState.ipConfig.address}. ` +
      `This causes loss of monitoring and control. Matches CyberAv3ngers TTP documented in CISA AA26-097A: ` +
      `"actors changed the IP addresses and passwords, resulting in a loss of monitoring and control functionality."`,
      { previousIp: baseline.ipConfig.address, currentIp: currentState.ipConfig.address }
    ));
  }

  // Check for project file tampering
  if (currentState.projectFileHash && currentState.projectFileHash !== baseline.projectFileHash) {
    newAlerts.push(generateAlert(device, "project_file_tampered", "critical",
      `Project file modified on PLC ${device.name}`,
      `Project file hash mismatch. Previous: ${baseline.projectFileHash.substring(0, 16)}... ` +
      `Current: ${currentState.projectFileHash.substring(0, 16)}... ` +
      `FBI PSA reports "at least one organization reported modified PLC project files after noticing ladder logic discrepancies across several sites."`,
      { previousHash: baseline.projectFileHash, currentHash: currentState.projectFileHash }
    ));
  }

  // Check for AOI manipulation (safety logic tampering)
  if (currentState.aoiHashes) {
    for (const [aoiName, hash] of Object.entries(currentState.aoiHashes)) {
      if (baseline.aoiHashes[aoiName] && baseline.aoiHashes[aoiName] !== hash) {
        newAlerts.push(generateAlert(device, "aoi_manipulation", "critical",
          `Add-On Instruction "${aoiName}" modified on PLC ${device.name}`,
          `AOI "${aoiName}" hash changed from ${baseline.aoiHashes[aoiName].substring(0, 8)}... to ${hash.substring(0, 8)}... ` +
          `CISA AA26-097A July 22 update: "a malicious project file retained normal downstream ladder logic while inserting modified AOIs ` +
          `that disabled safety shutdown and alarm systems."`,
          { aoiName, previousHash: baseline.aoiHashes[aoiName], currentHash: hash }
        ));
      }
    }
  }

  // Check for safety logic disablement
  if (currentState.safetyLogic) {
    if (baseline.safetyLogic.shutdownEnabled && !currentState.safetyLogic.shutdownEnabled) {
      newAlerts.push(generateAlert(device, "safety_logic_disabled", "critical",
        `Safety shutdown DISABLED on PLC ${device.name} — IMMEDIATE PHYSICAL DANGER`,
        `Safety shutdown logic has been disabled. This allows equipment to operate in unsafe conditions. ` +
        `CISA AA26-097A: "actors also manipulated data on HMI and SCADA displays, allowing equipment to operate in unsafe conditions without alerting operators."`,
        { previousState: "enabled", currentState: "disabled" }
      ));
    }
    if (baseline.safetyLogic.alarmSystemEnabled && !currentState.safetyLogic.alarmSystemEnabled) {
      newAlerts.push(generateAlert(device, "safety_logic_disabled", "critical",
        `Alarm system DISABLED on PLC ${device.name}`,
        `Alarm system has been silenced. Operators will not be notified of unsafe conditions. ` +
        `This matches the documented Phase 4 CyberAv3ngers capability: deliberate safety-logic manipulation.`,
        { previousState: "enabled", currentState: "disabled" }
      ));
    }
  }

  // Check for run mode changes
  if (currentState.runMode && currentState.runMode !== baseline.runMode) {
    const severity: AlertSeverity = currentState.runMode === "program" ? "high" : "medium";
    newAlerts.push(generateAlert(device, "run_mode_change", severity,
      `PLC ${device.name} switched from ${baseline.runMode.toUpperCase()} to ${currentState.runMode.toUpperCase()} mode`,
      `Mode change detected. When in PROGRAM mode, unauthorized changes to logic can be downloaded. ` +
      `FBI recommends: "Place physical and software key switches into the run position to block unauthorized changes."`,
      { previousMode: baseline.runMode, currentMode: currentState.runMode }
    ));
  }

  return newAlerts;
}

/**
 * Detect unauthorized engineering software connections
 */
export function detectUnauthorizedConnection(
  deviceId: string,
  sourceIp: string,
  sourcePort: number,
  softwareName: string,
  authorizedIps: string[]
): IntegrityAlert | null {
  const device = monitoredDevices.find(d => d.id === deviceId);
  if (!device) return null;

  if (!authorizedIps.includes(sourceIp)) {
    return generateAlert(device, "unauthorized_connection", "critical",
      `Unauthorized engineering software connection to PLC ${device.name} from ${sourceIp}`,
      `Connection from ${sourceIp}:${sourcePort} using ${softwareName}. Not in authorized IP list. ` +
      `CISA AA26-097A: "actors connected to internet-facing PLCs from foreign hosting providers using the same manufacturer ` +
      `engineering software (Studio 5000 Logix Designer) that legitimate operators use."`,
      { sourceIp, sourcePort, software: softwareName, authorizedIps }
    );
  }
  return null;
}

/**
 * Correlate alerts with known threat actor TTPs
 */
export function correlateWithThreatActors(deviceAlerts: IntegrityAlert[]): {
  primarySuspect: string;
  confidence: string;
  matchedTtps: string[];
  cisaAdvisories: string[];
  allMatches: { actor: string; score: number; matchedTtps: string[] }[];
} {
  const alertTypes = new Set(deviceAlerts.map(a => a.alertType));
  const device = monitoredDevices.find(d => d.id === deviceAlerts[0]?.deviceId);

  const matches = THREAT_ACTOR_SIGNATURES.map(actor => {
    let score = 0;
    const matchedTtps: string[] = [];

    // TTP match scoring
    for (const ttp of actor.ttps) {
      if (alertTypes.has(ttp)) {
        score += 10;
        matchedTtps.push(ttp);
      }
    }

    // Vendor match bonus
    if (device && actor.targetedVendors.includes(device.vendor)) {
      score += 5;
    }

    // Sector match bonus
    if (device && actor.targetedSectors.includes(device.sector)) {
      score += 5;
    }

    // Credential + IP redirect combo is CyberAv3ngers signature
    if (alertTypes.has("credential_change") && alertTypes.has("ip_redirect")) {
      if (actor.name === "CyberAv3ngers") score += 20;
    }

    // Safety logic + AOI manipulation is advanced CyberAv3ngers
    if (alertTypes.has("safety_logic_disabled") && alertTypes.has("aoi_manipulation")) {
      if (actor.name === "CyberAv3ngers") score += 15;
      if (actor.name === "XENOTIME") score += 10;
    }

    return { actor: actor.name, score, matchedTtps, cisaAdvisories: actor.cisaAdvisories };
  }).sort((a, b) => b.score - a.score);

  const primary = matches[0];
  const confidenceLevel = primary.score >= 30 ? "high" :
    primary.score >= 20 ? "moderate-high" :
    primary.score >= 10 ? "moderate" : "low";

  return {
    primarySuspect: primary.actor,
    confidence: confidenceLevel,
    matchedTtps: primary.matchedTtps,
    cisaAdvisories: primary.cisaAdvisories,
    allMatches: matches.filter(m => m.score > 0),
  };
}

// ─── Alert Generation ───────────────────────────────────────────────────────────

function generateAlert(
  device: PlcDevice,
  alertType: IntegrityAlertType,
  severity: AlertSeverity,
  description: string,
  technicalDetails: string,
  evidence: Record<string, any>
): IntegrityAlert {
  const mitreMapping = MITRE_ICS_MAPPING[alertType];
  const actorMatch = THREAT_ACTOR_SIGNATURES.find(a => a.ttps.includes(alertType));

  const alert: IntegrityAlert = {
    id: `PLC-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
    deviceId: device.id,
    deviceName: device.name,
    facilityName: device.facilityName,
    alertType,
    severity,
    timestamp: new Date(),
    description,
    technicalDetails,
    mitreAttackId: mitreMapping.id,
    mitreAttackTechnique: `${mitreMapping.technique} (${mitreMapping.tactic})`,
    threatActorAssociation: actorMatch ? `${actorMatch.name} (${actorMatch.sponsor})` : "Unknown",
    cisaAdvisory: actorMatch?.cisaAdvisories[0],
    recommendedActions: getRecommendedActions(alertType),
    rawEvidence: evidence,
    acknowledged: false,
  };

  alerts.push(alert);
  return alert;
}

function getRecommendedActions(alertType: IntegrityAlertType): string[] {
  const baseActions = [
    "Isolate affected device from network immediately",
    "Report to CISA (contact@cisa.dhs.gov) and FBI IC3 (ic3.gov)",
    "Switch to manual operations for affected processes",
  ];

  const specificActions: Record<IntegrityAlertType, string[]> = {
    credential_change: [
      "Power off unit and remove 1747-BA battery to clear memory (MicroLogix)",
      "Restore from known-good offline backup (.RSS file)",
      "Verify backup does not contain malicious logic before deployment",
      "Change to RUN mode via LCD keypad after restoration",
      "Review all connected devices for lateral movement",
    ],
    ip_redirect: [
      "Use LCD panel to reset IP configuration (MicroLogix 1400)",
      "Verify no other devices on network have been similarly modified",
      "Check cellular modem configurations for unauthorized changes",
      "Implement ACL to restrict communications to authorized devices only",
    ],
    project_file_tampered: [
      "Compare running program against known-good logic using vendor integrity tools",
      "Check Add-On Instructions (AOIs) for unauthorized modifications",
      "Verify I/O configurations are valid",
      "Do NOT restore backup without first verifying it is clean",
    ],
    aoi_manipulation: [
      "IMMEDIATELY verify safety shutdown and alarm systems are functional",
      "Compare AOI code against documented baseline",
      "Check if safety interlocks are still active",
      "Consider physical inspection of controlled equipment",
    ],
    safety_logic_disabled: [
      "EMERGENCY: Manually verify physical process is in safe state",
      "Activate physical safety mechanisms (manual shutoffs, pressure relief)",
      "Do not trust HMI/SCADA displays — verify with physical instruments",
      "Engage process safety team immediately",
    ],
    hmi_display_manipulation: [
      "Do NOT trust displayed values — verify with physical instrumentation",
      "Check for discrepancies between HMI values and field measurements",
      "Review historian data for anomalies",
      "Verify all alarm thresholds are intact",
    ],
    unauthorized_connection: [
      "Block source IP immediately at firewall/ACL",
      "Determine if project files were downloaded or modified",
      "Check for connections from hosting providers or VPN services",
      "Review all recent engineering software sessions",
    ],
    firmware_change: [
      "Compare firmware version against known-good baseline",
      "Check for unauthorized modules or capabilities",
      "Contact vendor PSIRT for analysis",
    ],
    run_mode_change: [
      "Return device to RUN mode immediately",
      "Verify no logic changes were made while in PROGRAM mode",
      "Set hardware key switch to RUN position",
    ],
    communication_loss: [
      "Verify physical connectivity and power",
      "Check cellular modem status and configuration",
      "Determine if loss is due to IP change or password lockout",
      "Prepare for manual operations",
    ],
    internet_exposure: [
      "IMMEDIATELY disconnect PLC from direct internet access",
      "Place behind VPN/firewall with strict ACL",
      "Audit all cellular modem connections",
      "Implement private APN or ZTNA for remote access",
    ],
    cellular_modem_compromise: [
      "Disconnect cellular modem from PLC",
      "Check modem firmware and configuration for changes",
      "Implement private APN with strong authentication",
      "Enable modem logging and review for suspicious activity",
    ],
    project_file_exfiltration: [
      "Assume attacker has full knowledge of control logic",
      "Change all credentials on affected and connected devices",
      "Review for subsequent logic modifications",
      "Consider redesigning safety-critical logic",
    ],
    protocol_anomaly: [
      "Capture network traffic for forensic analysis",
      "Compare against baseline communication patterns",
      "Check for scanning activity on OT protocol ports (44818, 502, 102)",
      "Review firewall logs for unusual source IPs",
    ],
  };

  return [...baseActions, ...(specificActions[alertType] || [])];
}

// ─── Query Functions ────────────────────────────────────────────────────────────

export function getMonitoringStatus(): {
  active: boolean;
  totalDevices: number;
  devicesByStatus: Record<MonitorStatus, number>;
  devicesByVendor: Record<PlcVendor, number>;
  devicesBySector: Record<string, number>;
  internetExposed: number;
  cellularConnected: number;
  alertCounts: Record<AlertSeverity, number>;
  recentAlerts: IntegrityAlert[];
} {
  const devicesByStatus: Record<MonitorStatus, number> = { healthy: 0, degraded: 0, compromised: 0, offline: 0, unknown: 0 };
  const devicesByVendor: Record<PlcVendor, number> = { rockwell: 0, schneider: 0, siemens: 0, unitronics: 0, other: 0 };
  const devicesBySector: Record<string, number> = {};
  let internetExposed = 0;
  let cellularConnected = 0;

  for (const device of monitoredDevices) {
    devicesByStatus[device.status]++;
    devicesByVendor[device.vendor]++;
    devicesBySector[device.sector] = (devicesBySector[device.sector] || 0) + 1;
    if (device.isInternetExposed) internetExposed++;
    if (device.connectionType === "cellular") cellularConnected++;
  }

  const alertCounts: Record<AlertSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const alert of alerts) {
    alertCounts[alert.severity]++;
  }

  return {
    active: monitoringActive,
    totalDevices: monitoredDevices.length,
    devicesByStatus,
    devicesByVendor,
    devicesBySector,
    internetExposed,
    cellularConnected,
    alertCounts,
    recentAlerts: alerts.slice(-20).reverse(),
  };
}

export function getAlerts(filters?: {
  severity?: AlertSeverity;
  alertType?: IntegrityAlertType;
  deviceId?: string;
  acknowledged?: boolean;
  limit?: number;
}): IntegrityAlert[] {
  let filtered = [...alerts];

  if (filters?.severity) filtered = filtered.filter(a => a.severity === filters.severity);
  if (filters?.alertType) filtered = filtered.filter(a => a.alertType === filters.alertType);
  if (filters?.deviceId) filtered = filtered.filter(a => a.deviceId === filters.deviceId);
  if (filters?.acknowledged !== undefined) filtered = filtered.filter(a => a.acknowledged === filters.acknowledged);

  filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

  if (filters?.limit) filtered = filtered.slice(0, filters.limit);

  return filtered;
}

export function getDevices(): PlcDevice[] {
  return monitoredDevices;
}

export function getDeviceById(id: string): PlcDevice | undefined {
  return monitoredDevices.find(d => d.id === id);
}

export function getBaselineForDevice(deviceId: string): IntegrityBaseline | undefined {
  return baselines.get(deviceId);
}

export function acknowledgeAlert(alertId: string): boolean {
  const alert = alerts.find(a => a.id === alertId);
  if (alert) {
    alert.acknowledged = true;
    return true;
  }
  return false;
}

export function resolveAlert(alertId: string): boolean {
  const alert = alerts.find(a => a.id === alertId);
  if (alert) {
    alert.acknowledged = true;
    alert.resolvedAt = new Date();
    return true;
  }
  return false;
}

/**
 * Get vulnerability assessment for the monitored fleet
 */
export function getFleetVulnerabilityAssessment(): {
  overallRisk: "critical" | "high" | "medium" | "low";
  riskFactors: { factor: string; severity: AlertSeverity; count: number; recommendation: string }[];
  cisaComplianceGaps: string[];
  exposureScore: number; // 0-100, higher = more exposed
} {
  const riskFactors: { factor: string; severity: AlertSeverity; count: number; recommendation: string }[] = [];

  const internetExposed = monitoredDevices.filter(d => d.isInternetExposed);
  if (internetExposed.length > 0) {
    riskFactors.push({
      factor: "Internet-exposed PLCs",
      severity: "critical",
      count: internetExposed.length,
      recommendation: "Immediately disconnect from internet. Use VPN/gateway for remote access (CISA July 30, 2026 Alert)",
    });
  }

  const cellularDevices = monitoredDevices.filter(d => d.connectionType === "cellular");
  if (cellularDevices.length > 0) {
    riskFactors.push({
      factor: "Cellular-connected PLCs (potential undocumented exposure)",
      severity: "high",
      count: cellularDevices.length,
      recommendation: "Audit all cellular modems. Implement private APN, ZTNA, or site-to-site VPN. Enable modem logging.",
    });
  }

  const rockwellMicrologix = monitoredDevices.filter(d =>
    d.vendor === "rockwell" && (d.model.includes("MicroLogix") || d.model.includes("1100") || d.model.includes("1400"))
  );
  if (rockwellMicrologix.length > 0) {
    riskFactors.push({
      factor: "Rockwell MicroLogix 1100/1400 (actively targeted by CyberAv3ngers)",
      severity: "critical",
      count: rockwellMicrologix.length,
      recommendation: "Apply Rockwell SD1790 guidance. Set RUN mode. Apply firmware FRN 21.002+ on Series B. Enable Enhanced Password Security.",
    });
  }

  const noBaseline = monitoredDevices.filter(d => !baselines.has(d.id));
  if (noBaseline.length > 0) {
    riskFactors.push({
      factor: "Devices without integrity baseline",
      severity: "high",
      count: noBaseline.length,
      recommendation: "Capture project file hash, credential state, and safety logic baseline for all devices immediately.",
    });
  }

  const cisaComplianceGaps: string[] = [];
  if (internetExposed.length > 0) cisaComplianceGaps.push("PLCs directly exposed to internet (violates CISA AA26-097A guidance)");
  if (noBaseline.length > 0) cisaComplianceGaps.push("No integrity baseline for comparison (cannot detect project file tampering)");
  if (cellularDevices.length > 0) cisaComplianceGaps.push("Cellular connections may bypass network security controls");

  const exposureScore = Math.min(100, Math.round(
    (internetExposed.length / Math.max(monitoredDevices.length, 1)) * 50 +
    (cellularDevices.length / Math.max(monitoredDevices.length, 1)) * 30 +
    (noBaseline.length / Math.max(monitoredDevices.length, 1)) * 20
  ));

  const overallRisk: "critical" | "high" | "medium" | "low" =
    exposureScore >= 50 ? "critical" :
    exposureScore >= 30 ? "high" :
    exposureScore >= 15 ? "medium" : "low";

  return { overallRisk, riskFactors, cisaComplianceGaps, exposureScore };
}

/**
 * Simulate the CyberAv3ngers attack pattern for red team exercises
 * Returns the expected detection sequence
 */
export function simulateAttackPattern(pattern: "credential_lockout" | "safety_logic_tamper" | "full_chain"): {
  steps: { step: number; action: string; expectedAlert: IntegrityAlertType; mitreId: string }[];
  description: string;
  reference: string;
} {
  const patterns = {
    credential_lockout: {
      description: "CyberAv3ngers Phase 4 - Credential Manipulation and Operator Lockout (Minnesota July 2026)",
      reference: "FBI PSA 260730, CISA Alert July 30 2026",
      steps: [
        { step: 1, action: "Scan for internet-exposed MicroLogix PLCs on port 44818", expectedAlert: "internet_exposure" as IntegrityAlertType, mitreId: "T0883" },
        { step: 2, action: "Connect to PLC using default/weak credentials", expectedAlert: "unauthorized_connection" as IntegrityAlertType, mitreId: "T0886" },
        { step: 3, action: "Change device IP address", expectedAlert: "ip_redirect" as IntegrityAlertType, mitreId: "T0836" },
        { step: 4, action: "Set new password to lock out operators", expectedAlert: "credential_change" as IntegrityAlertType, mitreId: "T0859" },
        { step: 5, action: "Operator loses view and control", expectedAlert: "communication_loss" as IntegrityAlertType, mitreId: "T0826" },
      ],
    },
    safety_logic_tamper: {
      description: "CyberAv3ngers Phase 4 - Safety Logic Manipulation (CISA AA26-097A July 22 Update)",
      reference: "CISA Advisory AA26-097A (July 22, 2026 update)",
      steps: [
        { step: 1, action: "Connect using vendor engineering software from foreign hosting", expectedAlert: "unauthorized_connection" as IntegrityAlertType, mitreId: "T0886" },
        { step: 2, action: "Download PLC project file", expectedAlert: "project_file_exfiltration" as IntegrityAlertType, mitreId: "T0882" },
        { step: 3, action: "Modify Add-On Instructions to disable safety shutdown", expectedAlert: "aoi_manipulation" as IntegrityAlertType, mitreId: "T0821" },
        { step: 4, action: "Upload modified project file retaining normal ladder logic", expectedAlert: "project_file_tampered" as IntegrityAlertType, mitreId: "T0839" },
        { step: 5, action: "Manipulate HMI/SCADA displays to hide unsafe conditions", expectedAlert: "hmi_display_manipulation" as IntegrityAlertType, mitreId: "T0832" },
        { step: 6, action: "Safety systems fail to trigger during unsafe operation", expectedAlert: "safety_logic_disabled" as IntegrityAlertType, mitreId: "T0880" },
      ],
    },
    full_chain: {
      description: "Full CyberAv3ngers Kill Chain - Combined Credential + Safety Logic Attack",
      reference: "CISA AA26-097A + FBI PSA 260730 combined",
      steps: [
        { step: 1, action: "Internet reconnaissance for exposed PLCs (Shodan/Censys)", expectedAlert: "internet_exposure" as IntegrityAlertType, mitreId: "T0883" },
        { step: 2, action: "Connect via cellular modem path", expectedAlert: "cellular_modem_compromise" as IntegrityAlertType, mitreId: "T0886" },
        { step: 3, action: "Authenticate with default/compromised credentials", expectedAlert: "unauthorized_connection" as IntegrityAlertType, mitreId: "T0886" },
        { step: 4, action: "Switch PLC to PROGRAM mode", expectedAlert: "run_mode_change" as IntegrityAlertType, mitreId: "T0858" },
        { step: 5, action: "Exfiltrate project file to attacker infrastructure", expectedAlert: "project_file_exfiltration" as IntegrityAlertType, mitreId: "T0882" },
        { step: 6, action: "Modify AOIs to disable safety logic", expectedAlert: "aoi_manipulation" as IntegrityAlertType, mitreId: "T0821" },
        { step: 7, action: "Upload modified project file", expectedAlert: "project_file_tampered" as IntegrityAlertType, mitreId: "T0839" },
        { step: 8, action: "Manipulate operator displays", expectedAlert: "hmi_display_manipulation" as IntegrityAlertType, mitreId: "T0832" },
        { step: 9, action: "Change IP and password to lock out operators", expectedAlert: "ip_redirect" as IntegrityAlertType, mitreId: "T0836" },
        { step: 10, action: "Operators lose all visibility; unsafe conditions develop", expectedAlert: "safety_logic_disabled" as IntegrityAlertType, mitreId: "T0880" },
      ],
    },
  };

  return patterns[pattern];
}
