/**
 * Vendor Data Bridge
 * 
 * Connects vendor integrations (CrowdStrike, SentinelOne, Defender, Splunk, XSOAR)
 * to the platform's EDR Validation and SIEM Feedback modules.
 * 
 * EDR Bridge: Pulls live detection/alert data from EDR vendors and maps them
 * to the EDR test catalog format for automated validation scoring.
 * 
 * SIEM Bridge: Pulls notable events / search results from Splunk and XSOAR
 * incidents into the SIEM Feedback detection results format.
 */

import type { BaseVendorClient } from "./base-client";
import { getClientForIntegration } from "./index";
import { getDb } from "../../db";
import { vendorIntegrations, vendorCachedData } from "../../../drizzle/schema";
import { eq, and, gte, desc, like } from "drizzle-orm";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EDRDetectionMapping {
  vendorDetectionId: string;
  vendorName: string;
  hostname: string;
  ipAddress?: string;
  techniqueId?: string;       // MITRE ATT&CK technique
  techniqueName?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  detectionResult: "detected" | "missed" | "partial" | "delayed" | "blocked";
  detectionTimeMs?: number;
  alertTitle: string;
  alertSeverity: string;
  responseAction?: string;
  rawData: any;
  detectedAt: Date;
}

export interface SIEMEventMapping {
  vendorEventId: string;
  vendorName: string;
  techniqueId?: string;
  techniqueName?: string;
  alertsFound: number;
  detectionResult: "detected" | "missed" | "partial" | "error";
  alertDetails: any[];
  queryUsed?: string;
  latencyMs?: number;
  executedAt: Date;
}

export interface BridgeSyncResult {
  vendor: string;
  module: "edr" | "siem";
  recordsMapped: number;
  recordsSkipped: number;
  errors: string[];
  durationMs: number;
}

// ─── MITRE ATT&CK Mapping Helpers ───────────────────────────────────────────

/** Common keyword-to-technique mappings for vendor alert titles */
const TECHNIQUE_KEYWORDS: Record<string, { id: string; name: string }> = {
  "credential dump": { id: "T1003", name: "OS Credential Dumping" },
  "credential access": { id: "T1003", name: "OS Credential Dumping" },
  "lsass": { id: "T1003.001", name: "LSASS Memory" },
  "mimikatz": { id: "T1003.001", name: "LSASS Memory" },
  "pass the hash": { id: "T1550.002", name: "Pass the Hash" },
  "pass the ticket": { id: "T1550.003", name: "Pass the Ticket" },
  "kerberoast": { id: "T1558.003", name: "Kerberoasting" },
  "golden ticket": { id: "T1558.001", name: "Golden Ticket" },
  "dcsync": { id: "T1003.006", name: "DCSync" },
  "lateral movement": { id: "T1021", name: "Remote Services" },
  "psexec": { id: "T1021.002", name: "SMB/Windows Admin Shares" },
  "wmi": { id: "T1047", name: "Windows Management Instrumentation" },
  "powershell": { id: "T1059.001", name: "PowerShell" },
  "command line": { id: "T1059", name: "Command and Scripting Interpreter" },
  "persistence": { id: "T1547", name: "Boot or Logon Autostart Execution" },
  "registry": { id: "T1547.001", name: "Registry Run Keys" },
  "scheduled task": { id: "T1053.005", name: "Scheduled Task" },
  "service creation": { id: "T1543.003", name: "Windows Service" },
  "dll injection": { id: "T1055.001", name: "Dynamic-link Library Injection" },
  "process injection": { id: "T1055", name: "Process Injection" },
  "process hollowing": { id: "T1055.012", name: "Process Hollowing" },
  "ransomware": { id: "T1486", name: "Data Encrypted for Impact" },
  "exfiltration": { id: "T1041", name: "Exfiltration Over C2 Channel" },
  "dns tunnel": { id: "T1071.004", name: "DNS" },
  "phishing": { id: "T1566", name: "Phishing" },
  "spearphishing": { id: "T1566.001", name: "Spearphishing Attachment" },
  "macro": { id: "T1204.002", name: "Malicious File" },
  "exploit": { id: "T1203", name: "Exploitation for Client Execution" },
  "privilege escalation": { id: "T1068", name: "Exploitation for Privilege Escalation" },
  "uac bypass": { id: "T1548.002", name: "Bypass User Account Control" },
  "defense evasion": { id: "T1562", name: "Impair Defenses" },
  "disable av": { id: "T1562.001", name: "Disable or Modify Tools" },
  "obfuscation": { id: "T1027", name: "Obfuscated Files or Information" },
  "c2": { id: "T1071", name: "Application Layer Protocol" },
  "beacon": { id: "T1071.001", name: "Web Protocols" },
  "cobalt strike": { id: "T1071.001", name: "Web Protocols" },
  "discovery": { id: "T1082", name: "System Information Discovery" },
  "reconnaissance": { id: "T1595", name: "Active Scanning" },
  "brute force": { id: "T1110", name: "Brute Force" },
  "password spray": { id: "T1110.003", name: "Password Spraying" },
};

function inferTechnique(alertTitle: string, tags?: string[]): { id: string; name: string } | null {
  const searchText = (alertTitle + " " + (tags || []).join(" ")).toLowerCase();
  
  for (const [keyword, technique] of Object.entries(TECHNIQUE_KEYWORDS)) {
    if (searchText.includes(keyword)) {
      return technique;
    }
  }
  return null;
}

function normalizeSeverity(severity: string): "critical" | "high" | "medium" | "low" | "info" {
  const s = severity.toLowerCase();
  if (s.includes("critical") || s === "5") return "critical";
  if (s.includes("high") || s === "4") return "high";
  if (s.includes("medium") || s.includes("moderate") || s === "3") return "medium";
  if (s.includes("low") || s === "2") return "low";
  return "info";
}

function mapDetectionResult(status: string, responseAction?: string): "detected" | "blocked" | "partial" | "delayed" {
  const s = status.toLowerCase();
  if (s.includes("block") || s.includes("quarantine") || s.includes("kill") || s.includes("remediat")) return "blocked";
  if (s.includes("partial") || s.includes("alert_only")) return "partial";
  if (responseAction?.toLowerCase().includes("block") || responseAction?.toLowerCase().includes("kill")) return "blocked";
  return "detected";
}

// ─── CrowdStrike EDR Bridge ─────────────────────────────────────────────────

async function mapCrowdStrikeDetections(client: BaseVendorClient): Promise<EDRDetectionMapping[]> {
  const results: EDRDetectionMapping[] = [];
  
  // Query detections
  const detectionsResult = await client.query("detections", {
    limit: 100,
    filters: { status: "new,in_progress" },
  });
  
  if (!detectionsResult.success || !detectionsResult.data) return results;
  
  for (const detection of (detectionsResult.data as any[]).slice(0, 100)) {
    const technique = inferTechnique(
      detection.behaviors?.[0]?.tactic || detection.behaviors?.[0]?.technique || "",
      detection.behaviors?.map((b: any) => b.technique_id).filter(Boolean)
    );
    
    const behavior = detection.behaviors?.[0] || {};
    
    results.push({
      vendorDetectionId: detection.detection_id || detection.id || `cs-${Date.now()}`,
      vendorName: "crowdstrike",
      hostname: behavior.hostname || detection.device?.hostname || "unknown",
      ipAddress: detection.device?.local_ip || detection.device?.external_ip,
      techniqueId: behavior.technique_id || technique?.id,
      techniqueName: behavior.technique || technique?.name,
      severity: normalizeSeverity(detection.max_severity_displayname || behavior.severity || "medium"),
      detectionResult: mapDetectionResult(detection.status || "detected", behavior.pattern_disposition_details?.kill_process ? "kill" : undefined),
      detectionTimeMs: undefined,
      alertTitle: behavior.description || behavior.scenario || detection.detection_id || "CrowdStrike Detection",
      alertSeverity: detection.max_severity_displayname || "Medium",
      responseAction: behavior.pattern_disposition_details ? JSON.stringify(behavior.pattern_disposition_details) : undefined,
      rawData: detection,
      detectedAt: new Date(detection.created_timestamp || behavior.timestamp || Date.now()),
    });
  }
  
  return results;
}

// ─── SentinelOne EDR Bridge ─────────────────────────────────────────────────

async function mapSentinelOneThreats(client: BaseVendorClient): Promise<EDRDetectionMapping[]> {
  const results: EDRDetectionMapping[] = [];
  
  const threatsResult = await client.query("threats", {
    limit: 100,
    filters: { resolved: "false" },
  });
  
  if (!threatsResult.success || !threatsResult.data) return results;
  
  for (const threat of (threatsResult.data as any[]).slice(0, 100)) {
    const technique = inferTechnique(
      threat.threatName || threat.classification || "",
      threat.indicators?.map((i: any) => i.title).filter(Boolean)
    );
    
    const agentInfo = threat.agentRealtimeInfo || threat.agentDetectionInfo || {};
    
    results.push({
      vendorDetectionId: threat.id || `s1-${Date.now()}`,
      vendorName: "sentinelone",
      hostname: agentInfo.agentComputerName || agentInfo.name || "unknown",
      ipAddress: agentInfo.agentIpV4 || agentInfo.externalIp,
      techniqueId: threat.mitigationStatus?.mitreTechniqueId || technique?.id,
      techniqueName: technique?.name,
      severity: normalizeSeverity(threat.confidenceLevel || threat.threatInfo?.confidenceLevel || "medium"),
      detectionResult: mapDetectionResult(
        threat.mitigationStatus?.status || "detected",
        threat.mitigationStatus?.action
      ),
      detectionTimeMs: undefined,
      alertTitle: threat.threatName || threat.threatInfo?.threatName || "SentinelOne Threat",
      alertSeverity: threat.confidenceLevel || "Medium",
      responseAction: threat.mitigationStatus?.action,
      rawData: threat,
      detectedAt: new Date(threat.createdAt || threat.threatInfo?.createdAt || Date.now()),
    });
  }
  
  return results;
}

// ─── Microsoft Defender EDR Bridge ──────────────────────────────────────────

async function mapDefenderAlerts(client: BaseVendorClient): Promise<EDRDetectionMapping[]> {
  const results: EDRDetectionMapping[] = [];
  
  const alertsResult = await client.query("alerts", {
    limit: 100,
    filters: { status: "New,InProgress" },
  });
  
  if (!alertsResult.success || !alertsResult.data) return results;
  
  for (const alert of (alertsResult.data as any[]).slice(0, 100)) {
    const technique = inferTechnique(
      alert.title || alert.category || "",
      alert.mitreTechniques || []
    );
    
    // Defender alerts often include MITRE technique IDs directly
    const mitreId = alert.mitreTechniques?.[0] || technique?.id;
    
    results.push({
      vendorDetectionId: alert.id || alert.alertId || `mde-${Date.now()}`,
      vendorName: "defender",
      hostname: alert.computerDnsName || alert.machineId || "unknown",
      ipAddress: undefined,
      techniqueId: mitreId,
      techniqueName: technique?.name || alert.category,
      severity: normalizeSeverity(alert.severity || "medium"),
      detectionResult: mapDetectionResult(
        alert.status || "detected",
        alert.assignedTo ? "assigned" : undefined
      ),
      detectionTimeMs: undefined,
      alertTitle: alert.title || "Microsoft Defender Alert",
      alertSeverity: alert.severity || "Medium",
      responseAction: alert.classification || undefined,
      rawData: alert,
      detectedAt: new Date(alert.alertCreationTime || alert.creationTime || Date.now()),
    });
  }
  
  return results;
}

// ─── Splunk SIEM Bridge ─────────────────────────────────────────────────────

async function mapSplunkEvents(client: BaseVendorClient): Promise<SIEMEventMapping[]> {
  const results: SIEMEventMapping[] = [];
  
  // Query notable events from Splunk ES
  const eventsResult = await client.query("notable_events", {
    limit: 100,
  });
  
  if (!eventsResult.success || !eventsResult.data) return results;
  
  for (const event of (eventsResult.data as any[]).slice(0, 100)) {
    const technique = inferTechnique(
      event.rule_name || event.search_name || event.rule_title || "",
      event.annotations?.mitre_attack || []
    );
    
    results.push({
      vendorEventId: event.event_id || event.sid || `splunk-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      vendorName: "splunk",
      techniqueId: event.annotations?.mitre_attack?.[0] || technique?.id,
      techniqueName: technique?.name,
      alertsFound: 1,
      detectionResult: event.status === "closed" ? "detected" : event.urgency === "critical" ? "detected" : "partial",
      alertDetails: [{
        title: event.rule_name || event.search_name || "Splunk Notable Event",
        severity: event.urgency || event.severity || "medium",
        source: event.source || "Splunk ES",
        time: event._time || event.time,
        raw: event,
      }],
      queryUsed: event.search_name || event.savedsearch_name,
      latencyMs: undefined,
      executedAt: new Date(event._time || event.time || Date.now()),
    });
  }
  
  return results;
}

// ─── XSOAR SIEM/SOAR Bridge ────────────────────────────────────────────────

async function mapXSOARIncidents(client: BaseVendorClient): Promise<SIEMEventMapping[]> {
  const results: SIEMEventMapping[] = [];
  
  const incidentsResult = await client.query("incidents", {
    limit: 100,
    filters: { status: "active" },
  });
  
  if (!incidentsResult.success || !incidentsResult.data) return results;
  
  for (const incident of (incidentsResult.data as any[]).slice(0, 100)) {
    const technique = inferTechnique(
      incident.name || incident.type || "",
      incident.labels?.map((l: any) => l.value).filter(Boolean)
    );
    
    results.push({
      vendorEventId: incident.id || `xsoar-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      vendorName: "xsoar",
      techniqueId: technique?.id,
      techniqueName: technique?.name,
      alertsFound: incident.linkedIncidents?.length || 1,
      detectionResult: incident.status === "done" ? "detected" : "partial",
      alertDetails: [{
        title: incident.name || "XSOAR Incident",
        severity: incident.severity?.toString() || "medium",
        type: incident.type,
        owner: incident.owner,
        playbook: incident.playbookId,
        raw: incident,
      }],
      queryUsed: incident.playbookId ? `Playbook: ${incident.playbookId}` : undefined,
      latencyMs: undefined,
      executedAt: new Date(incident.created || Date.now()),
    });
  }
  
  return results;
}

// ─── Public Bridge Functions ────────────────────────────────────────────────

/**
 * Pull EDR detections from a vendor and map them to the EDR Validation format.
 * Supports: crowdstrike, sentinelone, defender
 */
export async function bridgeEDRDetections(integrationId: number): Promise<BridgeSyncResult> {
  const start = Date.now();
  const errors: string[] = [];
  let recordsMapped = 0;
  let recordsSkipped = 0;
  let vendorName = "unknown";
  
  try {
    const client = await getClientForIntegration(integrationId);
    if (!client) {
      return { vendor: vendorName, module: "edr", recordsMapped: 0, recordsSkipped: 0, errors: ["Client not found"], durationMs: Date.now() - start };
    }
    
    // Get vendor info
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
    const [integration] = await db.select().from(vendorIntegrations).where(eq(vendorIntegrations.id, integrationId));
    vendorName = integration?.vendor || "unknown";
    
    let detections: EDRDetectionMapping[] = [];
    
    switch (vendorName) {
      case "crowdstrike":
        detections = await mapCrowdStrikeDetections(client);
        break;
      case "sentinelone":
        detections = await mapSentinelOneThreats(client);
        break;
      case "defender":
        detections = await mapDefenderAlerts(client);
        break;
      default:
        errors.push(`Vendor ${vendorName} is not an EDR — skipping EDR bridge`);
        return { vendor: vendorName, module: "edr", recordsMapped: 0, recordsSkipped: 0, errors, durationMs: Date.now() - start };
    }
    
    // Store mapped detections in vendor_cached_data for EDR validation to consume
    // vendorCachedData already imported at top level
    
    for (const detection of detections) {
      try {
        await db.insert(vendorCachedData).values({
          integrationId,
          dataType: "edr_detection",
          externalId: detection.vendorDetectionId,
          title: detection.alertTitle,
          severity: detection.severity,
          hostname: detection.hostname,
          ipAddress: detection.ipAddress || null,
          rawData: JSON.stringify({
            ...detection,
            _bridgeModule: "edr",
            _mappedAt: new Date().toISOString(),
          }),
          detectedAt: detection.detectedAt,
        });
        recordsMapped++;
      } catch (err: any) {
        if (err.code === "ER_DUP_ENTRY" || err.message?.includes("Duplicate")) {
          recordsSkipped++;
        } else {
          errors.push(`Failed to store detection ${detection.vendorDetectionId}: ${err.message}`);
        }
      }
    }
  } catch (err: any) {
    errors.push(`Bridge error: ${err.message}`);
  }
  
  return { vendor: vendorName, module: "edr", recordsMapped, recordsSkipped, errors, durationMs: Date.now() - start };
}

/**
 * Pull SIEM events from a vendor and map them to the SIEM Feedback format.
 * Supports: splunk, xsoar
 */
export async function bridgeSIEMEvents(integrationId: number): Promise<BridgeSyncResult> {
  const start = Date.now();
  const errors: string[] = [];
  let recordsMapped = 0;
  let recordsSkipped = 0;
  let vendorName = "unknown";
  
  try {
    const client = await getClientForIntegration(integrationId);
    if (!client) {
      return { vendor: vendorName, module: "siem", recordsMapped: 0, recordsSkipped: 0, errors: ["Client not found"], durationMs: Date.now() - start };
    }
    
    const db = await getDb();
    if (!db) throw new Error("Database unavailable");
    const [integration] = await db.select().from(vendorIntegrations).where(eq(vendorIntegrations.id, integrationId));
    vendorName = integration?.vendor || "unknown";
    
    let events: SIEMEventMapping[] = [];
    
    switch (vendorName) {
      case "splunk":
        events = await mapSplunkEvents(client);
        break;
      case "xsoar":
        events = await mapXSOARIncidents(client);
        break;
      default:
        errors.push(`Vendor ${vendorName} is not a SIEM/SOAR — skipping SIEM bridge`);
        return { vendor: vendorName, module: "siem", recordsMapped: 0, recordsSkipped: 0, errors, durationMs: Date.now() - start };
    }
    
    // Store mapped events in vendor_cached_data for SIEM feedback to consume
    // vendorCachedData already imported at top level
    
    for (const event of events) {
      try {
        await db.insert(vendorCachedData).values({
          integrationId,
          dataType: "siem_event",
          externalId: event.vendorEventId,
          title: event.alertDetails?.[0]?.title || "SIEM Event",
          severity: normalizeSeverity(event.alertDetails?.[0]?.severity || "medium"),
          hostname: null,
          ipAddress: null,
          rawData: JSON.stringify({
            ...event,
            _bridgeModule: "siem",
            _mappedAt: new Date().toISOString(),
          }),
          detectedAt: event.executedAt,
        });
        recordsMapped++;
      } catch (err: any) {
        if (err.code === "ER_DUP_ENTRY" || err.message?.includes("Duplicate")) {
          recordsSkipped++;
        } else {
          errors.push(`Failed to store event ${event.vendorEventId}: ${err.message}`);
        }
      }
    }
  } catch (err: any) {
    errors.push(`Bridge error: ${err.message}`);
  }
  
  return { vendor: vendorName, module: "siem", recordsMapped, recordsSkipped, errors, durationMs: Date.now() - start };
}

/**
 * Auto-detect vendor type and bridge to the appropriate module.
 */
export async function autoBridge(integrationId: number): Promise<BridgeSyncResult> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  
  const [integration] = await db.select().from(vendorIntegrations).where(eq(vendorIntegrations.id, integrationId));
  if (!integration) throw new Error(`Integration ${integrationId} not found`);
  
  const edrVendors = ["crowdstrike", "sentinelone", "defender"];
  const siemVendors = ["splunk", "xsoar"];
  
  if (edrVendors.includes(integration.vendor)) {
    return bridgeEDRDetections(integrationId);
  } else if (siemVendors.includes(integration.vendor)) {
    return bridgeSIEMEvents(integrationId);
  } else {
    return {
      vendor: integration.vendor,
      module: "edr",
      recordsMapped: 0,
      recordsSkipped: 0,
      errors: [`Unknown vendor type: ${integration.vendor}`],
      durationMs: 0,
    };
  }
}

/**
 * Bridge all enabled integrations to their respective modules.
 */
export async function bridgeAll(): Promise<BridgeSyncResult[]> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  
  const integrations = await db.select()
    .from(vendorIntegrations)
    .where(eq(vendorIntegrations.enabled, true));
  
  const results: BridgeSyncResult[] = [];
  
  for (const integration of integrations) {
    try {
      const result = await autoBridge(integration.id);
      results.push(result);
    } catch (err: any) {
      results.push({
        vendor: integration.vendor,
        module: "edr",
        recordsMapped: 0,
        recordsSkipped: 0,
        errors: [err.message],
        durationMs: 0,
      });
    }
  }
  
  return results;
}

/**
 * Get EDR detections from vendor cache for use in EDR Validation module.
 * Returns data in the format expected by the EDR test results recorder.
 */
export async function getEDRDetectionsForValidation(options?: {
  vendor?: string;
  hostname?: string;
  techniqueId?: string;
  since?: Date;
  limit?: number;
}): Promise<EDRDetectionMapping[]> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  
  const conditions: any[] = [eq(vendorCachedData.dataType, "edr_detection")];
  
  if (options?.hostname) {
    conditions.push(like(vendorCachedData.hostname, `%${options.hostname}%`));
  }
  if (options?.since) {
    conditions.push(gte(vendorCachedData.detectedAt, options.since));
  }
  
  const rows = await db.select()
    .from(vendorCachedData)
    .innerJoin(vendorIntegrations, eq(vendorCachedData.integrationId, vendorIntegrations.id))
    .where(and(...conditions))
    .orderBy(desc(vendorCachedData.detectedAt))
    .limit(options?.limit || 200);
  
  return rows
    .map((row: any) => {
      try {
        const raw = typeof row.vendor_cached_data.rawData === "string"
          ? JSON.parse(row.vendor_cached_data.rawData)
          : row.vendor_cached_data.rawData;
        return raw as EDRDetectionMapping;
      } catch {
        return null;
      }
    })
    .filter((d): d is EDRDetectionMapping => d !== null)
    .filter((d) => {
      if (options?.vendor && d.vendorName !== options.vendor) return false;
      if (options?.techniqueId && d.techniqueId !== options.techniqueId) return false;
      return true;
    });
}

/**
 * Get SIEM events from vendor cache for use in SIEM Feedback module.
 */
export async function getSIEMEventsForFeedback(options?: {
  vendor?: string;
  techniqueId?: string;
  since?: Date;
  limit?: number;
}): Promise<SIEMEventMapping[]> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  
  const conditions: any[] = [eq(vendorCachedData.dataType, "siem_event")];
  
  if (options?.since) {
    conditions.push(gte(vendorCachedData.detectedAt, options.since));
  }
  
  const rows = await db.select()
    .from(vendorCachedData)
    .innerJoin(vendorIntegrations, eq(vendorCachedData.integrationId, vendorIntegrations.id))
    .where(and(...conditions))
    .orderBy(desc(vendorCachedData.detectedAt))
    .limit(options?.limit || 200);
  
  return rows
    .map((row: any) => {
      try {
        const raw = typeof row.vendor_cached_data.rawData === "string"
          ? JSON.parse(row.vendor_cached_data.rawData)
          : row.vendor_cached_data.rawData;
        return raw as SIEMEventMapping;
      } catch {
        return null;
      }
    })
    .filter((d): d is SIEMEventMapping => d !== null)
    .filter((d) => {
      if (options?.vendor && d.vendorName !== options.vendor) return false;
      if (options?.techniqueId && d.techniqueId !== options.techniqueId) return false;
      return true;
    });
}
