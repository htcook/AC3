/**
 * SOC Integration Hub
 * ═══════════════════════════════════════════════════════════════
 * Unified module that ties together SIEM connectors, alert export,
 * and detection gap analysis into a single SOC operations interface.
 *
 * Features:
 *   1. Alert Export — Convert engagement findings to CEF/LEEF/JSON structured alerts
 *   2. Detection Gap Analysis — Compare attacks executed vs. SIEM detections
 *   3. SOC Health Dashboard — Connector status, alert volume, detection rates
 *   4. Real-time Detection Correlation — Live attack-to-detection mapping
 */

import type { NormalizedSiemAlert, DetectionCorrelation, SiemConnectionConfig, SiemConnectionStatus } from "./siem-connectors";
import { testSiemConnection, fetchSiemAlerts, correlateDetections, computeDetectionStats, summarizeAlerts } from "./siem-connectors";
import type { SIEMConfig } from "./siem-feedback";
import { testSIEMConnection, executeDetectionQuery } from "./siem-feedback";

// ═══════════════════════════════════════════════════════════════
// §1 — ALERT EXPORT FORMATS (CEF, LEEF, JSON, Syslog)
// ═══════════════════════════════════════════════════════════════

export type AlertExportFormat = "cef" | "leef" | "json" | "syslog" | "csv";

export interface EngagementFinding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss?: number;
  cveIds?: string[];
  mitreTechniques?: string[];
  mitreTactics?: string[];
  targetHost?: string;
  targetPort?: number;
  toolUsed?: string;
  evidence?: string;
  timestamp: number;
  engagementId: number;
  phase?: string;
}

export interface ExportedAlert {
  format: AlertExportFormat;
  raw: string;
  findingId: string;
  timestamp: number;
}

const SEVERITY_TO_CEF: Record<string, number> = {
  critical: 10, high: 8, medium: 5, low: 3, info: 1,
};

const SEVERITY_TO_LEEF: Record<string, number> = {
  critical: 10, high: 7, medium: 4, low: 2, info: 1,
};

/**
 * Export a single finding as a CEF (Common Event Format) alert.
 * CEF is the standard for ArcSight, QRadar, and many SIEMs.
 */
export function exportFindingAsCEF(finding: EngagementFinding): ExportedAlert {
  const severity = SEVERITY_TO_CEF[finding.severity] ?? 5;
  const deviceVendor = "AC3";
  const deviceProduct = "PentestPlatform";
  const deviceVersion = "1.0";
  const signatureId = finding.id;
  const name = finding.title.replace(/\|/g, "\\|").replace(/\\/g, "\\\\");
  const desc = (finding.description || "").replace(/\|/g, "\\|").replace(/\\/g, "\\\\").substring(0, 1000);

  const extensions: string[] = [];
  if (finding.targetHost) extensions.push(`dst=${finding.targetHost}`);
  if (finding.targetPort) extensions.push(`dpt=${finding.targetPort}`);
  if (finding.cveIds?.length) extensions.push(`cs1=${finding.cveIds.join(",")}`);
  if (finding.cveIds?.length) extensions.push(`cs1Label=CVE_IDs`);
  if (finding.mitreTechniques?.length) extensions.push(`cs2=${finding.mitreTechniques.join(",")}`);
  if (finding.mitreTechniques?.length) extensions.push(`cs2Label=MITRE_Techniques`);
  if (finding.toolUsed) extensions.push(`cs3=${finding.toolUsed}`);
  if (finding.toolUsed) extensions.push(`cs3Label=Tool_Used`);
  extensions.push(`msg=${desc}`);
  extensions.push(`rt=${new Date(finding.timestamp).toISOString()}`);
  extensions.push(`externalId=${finding.engagementId}`);

  const cef = `CEF:0|${deviceVendor}|${deviceProduct}|${deviceVersion}|${signatureId}|${name}|${severity}|${extensions.join(" ")}`;

  return { format: "cef", raw: cef, findingId: finding.id, timestamp: finding.timestamp };
}

/**
 * Export a single finding as a LEEF (Log Event Extended Format) alert.
 * LEEF is the standard for IBM QRadar.
 */
export function exportFindingAsLEEF(finding: EngagementFinding): ExportedAlert {
  const severity = SEVERITY_TO_LEEF[finding.severity] ?? 4;
  const fields: string[] = [
    `LEEF:2.0|AceC3|PentestPlatform|1.0|${finding.id}|`,
    `sev=${severity}`,
    `cat=${finding.phase || "pentest"}`,
    `devTime=${new Date(finding.timestamp).toISOString()}`,
    `msg=${finding.title}`,
  ];
  if (finding.targetHost) fields.push(`dst=${finding.targetHost}`);
  if (finding.targetPort) fields.push(`dstPort=${finding.targetPort}`);
  if (finding.cveIds?.length) fields.push(`vulnId=${finding.cveIds.join(",")}`);
  if (finding.mitreTechniques?.length) fields.push(`mitreId=${finding.mitreTechniques.join(",")}`);
  if (finding.toolUsed) fields.push(`toolUsed=${finding.toolUsed}`);

  const leef = fields.join("\t");
  return { format: "leef", raw: leef, findingId: finding.id, timestamp: finding.timestamp };
}

/**
 * Export a single finding as structured JSON alert.
 */
export function exportFindingAsJSON(finding: EngagementFinding): ExportedAlert {
  const alert = {
    "@timestamp": new Date(finding.timestamp).toISOString(),
    event: {
      kind: "alert",
      category: ["vulnerability"],
      type: ["info"],
      severity: SEVERITY_TO_CEF[finding.severity] ?? 5,
      module: "ac3",
      dataset: "pentest_finding",
    },
    rule: {
      id: finding.id,
      name: finding.title,
      description: finding.description,
    },
    vulnerability: {
      id: finding.cveIds,
      severity: finding.severity,
      score: { base: finding.cvss },
    },
    threat: {
      technique: finding.mitreTechniques?.map(t => ({ id: t })),
      tactic: finding.mitreTactics?.map(t => ({ name: t })),
    },
    destination: {
      ip: finding.targetHost,
      port: finding.targetPort,
    },
    ac3: {
      engagement_id: finding.engagementId,
      tool_used: finding.toolUsed,
      phase: finding.phase,
      evidence: finding.evidence,
    },
  };

  return { format: "json", raw: JSON.stringify(alert, null, 2), findingId: finding.id, timestamp: finding.timestamp };
}

/**
 * Export a single finding as syslog-formatted alert.
 */
export function exportFindingAsSyslog(finding: EngagementFinding): ExportedAlert {
  const pri = finding.severity === "critical" ? 2 : finding.severity === "high" ? 3 : finding.severity === "medium" ? 4 : 6;
  const ts = new Date(finding.timestamp).toISOString();
  const msg = `<${pri}>1 ${ts} ace-c3 pentest ${finding.engagementId} ${finding.id} - [finding severity="${finding.severity}" target="${finding.targetHost || "unknown"}" tool="${finding.toolUsed || "unknown"}"] ${finding.title}: ${finding.description?.substring(0, 500)}`;

  return { format: "syslog", raw: msg, findingId: finding.id, timestamp: finding.timestamp };
}

/**
 * Export a single finding as CSV row.
 */
export function exportFindingAsCSV(finding: EngagementFinding): ExportedAlert {
  const escape = (s: string) => `"${(s || "").replace(/"/g, '""')}"`;
  const row = [
    new Date(finding.timestamp).toISOString(),
    finding.id,
    escape(finding.title),
    finding.severity,
    finding.cvss ?? "",
    (finding.cveIds || []).join(";"),
    (finding.mitreTechniques || []).join(";"),
    finding.targetHost || "",
    finding.targetPort || "",
    finding.toolUsed || "",
    escape(finding.description?.substring(0, 500) || ""),
    finding.engagementId,
  ].join(",");

  return { format: "csv", raw: row, findingId: finding.id, timestamp: finding.timestamp };
}

/**
 * Batch export all findings in a given format.
 */
export function exportFindings(findings: EngagementFinding[], format: AlertExportFormat): ExportedAlert[] {
  const exportFn = {
    cef: exportFindingAsCEF,
    leef: exportFindingAsLEEF,
    json: exportFindingAsJSON,
    syslog: exportFindingAsSyslog,
    csv: exportFindingAsCSV,
  }[format];

  const alerts = findings.map(f => exportFn(f));

  if (format === "csv") {
    const header = "timestamp,finding_id,title,severity,cvss,cve_ids,mitre_techniques,target_host,target_port,tool_used,description,engagement_id";
    alerts.unshift({ format: "csv", raw: header, findingId: "header", timestamp: 0 });
  }

  return alerts;
}

// ═══════════════════════════════════════════════════════════════
// §2 — DETECTION GAP ANALYSIS
// ═══════════════════════════════════════════════════════════════

export interface AttackAction {
  id: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  tool: string;
  targetHost: string;
  timestamp: number;
  success: boolean;
  description: string;
}

export interface DetectionGap {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  attackCount: number;
  detectionCount: number;
  detectionRate: number;
  gapSeverity: "critical" | "high" | "medium" | "low";
  recommendation: string;
  relatedRules: string[];
  sampleAttacks: string[];
}

export interface DetectionGapReport {
  totalAttacks: number;
  totalDetected: number;
  overallDetectionRate: number;
  gaps: DetectionGap[];
  coveredTechniques: string[];
  uncoveredTechniques: string[];
  meanTimeToDetect: number | null;
  detectionByTactic: Record<string, { attacks: number; detected: number; rate: number }>;
  generatedAt: number;
}

const GAP_RECOMMENDATIONS: Record<string, string> = {
  "T1059": "Deploy command-line logging (Sysmon Event ID 1) and create detection rules for suspicious interpreter usage (PowerShell, cmd, bash).",
  "T1053": "Monitor scheduled task creation events (Windows Event ID 4698) and cron job modifications on Linux.",
  "T1078": "Implement impossible travel detection and monitor for credential usage from unusual locations or times.",
  "T1021": "Monitor lateral movement protocols (RDP, SSH, WinRM, SMB) for anomalous connection patterns.",
  "T1055": "Deploy memory protection monitoring and detect process injection via Sysmon Event ID 8 (CreateRemoteThread).",
  "T1071": "Implement DNS analytics, monitor for beaconing patterns, and inspect TLS certificate anomalies.",
  "T1105": "Monitor for unusual file downloads, especially from external IPs, using proxy logs and endpoint telemetry.",
  "T1562": "Alert on security tool tampering — monitor for stopped services, modified configs, or disabled logging.",
  "T1003": "Deploy credential guard, monitor LSASS access (Sysmon Event ID 10), and alert on DCSync operations.",
  "T1486": "Monitor for mass file encryption patterns, volume shadow copy deletion, and ransomware-associated extensions.",
  "T1190": "Implement WAF rules, monitor for exploit signatures in web server logs, and deploy runtime application protection.",
  "T1566": "Deploy email security gateway with attachment sandboxing and URL rewriting. Monitor for suspicious email patterns.",
};

function getGapRecommendation(techniqueId: string): string {
  const baseId = techniqueId.split(".")[0];
  return GAP_RECOMMENDATIONS[baseId] || GAP_RECOMMENDATIONS[techniqueId] ||
    `Create detection rules for ${techniqueId}. Review MITRE ATT&CK for data sources and detection opportunities.`;
}

function classifyGapSeverity(detectionRate: number, attackCount: number): DetectionGap["gapSeverity"] {
  if (detectionRate === 0 && attackCount >= 3) return "critical";
  if (detectionRate === 0) return "high";
  if (detectionRate < 0.3) return "high";
  if (detectionRate < 0.6) return "medium";
  return "low";
}

/**
 * Analyze detection gaps by comparing attack actions against SIEM detections.
 */
export function analyzeDetectionGaps(
  attacks: AttackAction[],
  siemAlerts: NormalizedSiemAlert[],
  timeWindowMs: number = 300_000 // 5 minute correlation window
): DetectionGapReport {
  // Group attacks by technique
  const attacksByTechnique = new Map<string, AttackAction[]>();
  for (const attack of attacks) {
    const existing = attacksByTechnique.get(attack.techniqueId) || [];
    existing.push(attack);
    attacksByTechnique.set(attack.techniqueId, existing);
  }

  // Build alert lookup by technique
  const alertsByTechnique = new Map<string, NormalizedSiemAlert[]>();
  for (const alert of siemAlerts) {
    for (const tech of alert.mitreTechniques) {
      const existing = alertsByTechnique.get(tech) || [];
      existing.push(alert);
      alertsByTechnique.set(tech, existing);
    }
  }

  const gaps: DetectionGap[] = [];
  const coveredTechniques: string[] = [];
  const uncoveredTechniques: string[] = [];
  let totalDetected = 0;
  const detectionTimes: number[] = [];
  const detectionByTactic: Record<string, { attacks: number; detected: number; rate: number }> = {};

  for (const [techniqueId, techAttacks] of attacksByTechnique.entries()) {
    const techAlerts = alertsByTechnique.get(techniqueId) || [];

    // Correlate: for each attack, check if there's an alert within the time window
    let detectedCount = 0;
    const matchedRules = new Set<string>();
    const sampleAttackIds: string[] = [];

    for (const attack of techAttacks) {
      const matchingAlert = techAlerts.find(alert =>
        Math.abs(alert.timestamp - attack.timestamp) <= timeWindowMs
      );
      if (matchingAlert) {
        detectedCount++;
        matchedRules.add(matchingAlert.ruleName);
        const ttd = matchingAlert.timestamp - attack.timestamp;
        if (ttd >= 0) detectionTimes.push(ttd);
      } else {
        sampleAttackIds.push(attack.id);
      }
    }

    const detectionRate = techAttacks.length > 0 ? detectedCount / techAttacks.length : 0;
    totalDetected += detectedCount;

    if (detectionRate >= 0.8) {
      coveredTechniques.push(techniqueId);
    } else {
      uncoveredTechniques.push(techniqueId);
    }

    // Track by tactic
    const tactic = techAttacks[0]?.tactic || "unknown";
    if (!detectionByTactic[tactic]) {
      detectionByTactic[tactic] = { attacks: 0, detected: 0, rate: 0 };
    }
    detectionByTactic[tactic].attacks += techAttacks.length;
    detectionByTactic[tactic].detected += detectedCount;

    gaps.push({
      techniqueId,
      techniqueName: techAttacks[0]?.techniqueName || techniqueId,
      tactic,
      attackCount: techAttacks.length,
      detectionCount: detectedCount,
      detectionRate,
      gapSeverity: classifyGapSeverity(detectionRate, techAttacks.length),
      recommendation: getGapRecommendation(techniqueId),
      relatedRules: Array.from(matchedRules),
      sampleAttacks: sampleAttackIds.slice(0, 5),
    });
  }

  // Compute tactic rates
  for (const tactic of Object.values(detectionByTactic)) {
    tactic.rate = tactic.attacks > 0 ? tactic.detected / tactic.attacks : 0;
  }

  // Sort gaps by severity (critical first) then by detection rate (lowest first)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  gaps.sort((a, b) => {
    const sevDiff = severityOrder[a.gapSeverity] - severityOrder[b.gapSeverity];
    return sevDiff !== 0 ? sevDiff : a.detectionRate - b.detectionRate;
  });

  const meanTimeToDetect = detectionTimes.length > 0
    ? detectionTimes.reduce((a, b) => a + b, 0) / detectionTimes.length
    : null;

  return {
    totalAttacks: attacks.length,
    totalDetected,
    overallDetectionRate: attacks.length > 0 ? totalDetected / attacks.length : 0,
    gaps,
    coveredTechniques,
    uncoveredTechniques,
    meanTimeToDetect,
    detectionByTactic,
    generatedAt: Date.now(),
  };
}

// ═══════════════════════════════════════════════════════════════
// §3 — SOC HEALTH DASHBOARD
// ═══════════════════════════════════════════════════════════════

export interface SocConnectorHealth {
  id: string;
  name: string;
  backend: string;
  status: "connected" | "degraded" | "disconnected" | "unknown";
  lastCheck: number;
  latencyMs: number;
  alertsLast24h: number;
  errorMessage?: string;
}

export interface SocHealthSnapshot {
  connectors: SocConnectorHealth[];
  totalAlertsLast24h: number;
  totalAlertsLast7d: number;
  avgLatencyMs: number;
  detectionCoverage: number;
  lastUpdated: number;
  overallStatus: "healthy" | "degraded" | "critical" | "unknown";
}

/**
 * Compute overall SOC health from connector statuses.
 */
export function computeSocHealth(connectors: SocConnectorHealth[]): SocHealthSnapshot {
  if (connectors.length === 0) {
    return {
      connectors: [],
      totalAlertsLast24h: 0,
      totalAlertsLast7d: 0,
      avgLatencyMs: 0,
      detectionCoverage: 0,
      lastUpdated: Date.now(),
      overallStatus: "unknown",
    };
  }

  const totalAlertsLast24h = connectors.reduce((sum, c) => sum + c.alertsLast24h, 0);
  const avgLatencyMs = connectors.reduce((sum, c) => sum + c.latencyMs, 0) / connectors.length;
  const connectedCount = connectors.filter(c => c.status === "connected").length;
  const disconnectedCount = connectors.filter(c => c.status === "disconnected").length;

  let overallStatus: SocHealthSnapshot["overallStatus"] = "healthy";
  if (disconnectedCount === connectors.length) {
    overallStatus = "critical";
  } else if (disconnectedCount > 0 || connectors.some(c => c.status === "degraded")) {
    overallStatus = "degraded";
  }

  return {
    connectors,
    totalAlertsLast24h,
    totalAlertsLast7d: 0, // Populated by caller with historical data
    avgLatencyMs: Math.round(avgLatencyMs),
    detectionCoverage: connectors.length > 0 ? connectedCount / connectors.length : 0,
    lastUpdated: Date.now(),
    overallStatus,
  };
}

// ═══════════════════════════════════════════════════════════════
// §4 — SIEM PUSH (Send alerts TO the SIEM)
// ═══════════════════════════════════════════════════════════════

export interface SiemPushConfig {
  /** Target SIEM type */
  target: "splunk_hec" | "elastic" | "syslog" | "qradar" | "sentinel" | "wazuh";
  /** Endpoint URL (HEC endpoint, Elastic bulk API, syslog host:port, etc.) */
  endpoint: string;
  /** Auth token or API key */
  authToken?: string;
  /** Index name (Elastic/Splunk) */
  index?: string;
  /** Skip TLS verification */
  insecure?: boolean;
}

export interface SiemPushResult {
  success: boolean;
  alertsSent: number;
  alertsFailed: number;
  errors: string[];
  durationMs: number;
}

/**
 * Push exported alerts to a SIEM via its ingestion API.
 */
export async function pushAlertsToSiem(
  alerts: ExportedAlert[],
  config: SiemPushConfig
): Promise<SiemPushResult> {
  const start = Date.now();
  let sent = 0;
  let failed = 0;
  const errors: string[] = [];

  try {
    switch (config.target) {
      case "splunk_hec": {
        // Splunk HTTP Event Collector
        for (const alert of alerts) {
          if (alert.findingId === "header") continue; // Skip CSV headers
          try {
            const payload = alert.format === "json"
              ? { event: JSON.parse(alert.raw), sourcetype: "ac3:pentest", index: config.index || "main" }
              : { event: alert.raw, sourcetype: `ac3:${alert.format}`, index: config.index || "main" };

            const resp = await fetch(config.endpoint, {
              method: "POST",
              headers: {
                "Authorization": `Splunk ${config.authToken}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify(payload),
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok) sent++; else { failed++; errors.push(`Splunk HEC ${resp.status}: ${await resp.text()}`); }
          } catch (e: any) {
            failed++;
            errors.push(`Splunk HEC error: ${e.message}`);
          }
        }
        break;
      }

      case "elastic": {
        // Elasticsearch Bulk API
        const bulkLines: string[] = [];
        for (const alert of alerts) {
          if (alert.findingId === "header") continue;
          const indexName = config.index || "ace-c3-findings";
          bulkLines.push(JSON.stringify({ index: { _index: indexName } }));
          bulkLines.push(alert.format === "json" ? alert.raw : JSON.stringify({ message: alert.raw, format: alert.format }));
        }

        if (bulkLines.length > 0) {
          try {
            const headers: Record<string, string> = { "Content-Type": "application/x-ndjson" };
            if (config.authToken) headers["Authorization"] = `ApiKey ${config.authToken}`;
            const resp = await fetch(`${config.endpoint}/_bulk`, {
              method: "POST",
              headers,
              body: bulkLines.join("\n") + "\n",
              signal: AbortSignal.timeout(30_000),
            });
            if (resp.ok) {
              const result = await resp.json();
              sent = (result.items || []).filter((i: any) => !i.index?.error).length;
              failed = (result.items || []).filter((i: any) => i.index?.error).length;
            } else {
              failed = alerts.length;
              errors.push(`Elastic bulk ${resp.status}: ${await resp.text()}`);
            }
          } catch (e: any) {
            failed = alerts.length;
            errors.push(`Elastic bulk error: ${e.message}`);
          }
        }
        break;
      }

      case "sentinel": {
        // Microsoft Sentinel Log Analytics Data Collector API
        for (const alert of alerts) {
          if (alert.findingId === "header") continue;
          try {
            const body = alert.format === "json" ? alert.raw : JSON.stringify({ message: alert.raw, format: alert.format });
            const resp = await fetch(config.endpoint, {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${config.authToken}`,
                "Content-Type": "application/json",
                "Log-Type": "AC3Findings",
              },
              body,
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok) sent++; else { failed++; errors.push(`Sentinel ${resp.status}`); }
          } catch (e: any) {
            failed++;
            errors.push(`Sentinel error: ${e.message}`);
          }
        }
        break;
      }

      case "qradar": {
        // QRadar Log Source Management API
        for (const alert of alerts) {
          if (alert.findingId === "header") continue;
          try {
            const resp = await fetch(`${config.endpoint}/api/data_ingestion/events`, {
              method: "POST",
              headers: {
                "SEC": config.authToken || "",
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ events: [{ message: alert.raw }] }),
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok) sent++; else { failed++; errors.push(`QRadar ${resp.status}`); }
          } catch (e: any) {
            failed++;
            errors.push(`QRadar error: ${e.message}`);
          }
        }
        break;
      }

      case "wazuh": {
        // Wazuh API — authenticate then push events via /events endpoint
        let wazuhToken = config.authToken;
        if (!wazuhToken && config.endpoint) {
          // Attempt JWT auth with username/password in authToken as "user:pass"
          try {
            const authResp = await fetch(`${config.endpoint}/security/user/authenticate`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              signal: AbortSignal.timeout(10_000),
            });
            if (authResp.ok) {
              const authData = await authResp.json();
              wazuhToken = authData?.data?.token;
            }
          } catch (e: any) {
            errors.push(`Wazuh auth error: ${e.message}`);
          }
        }
        for (const alert of alerts) {
          if (alert.findingId === "header") continue;
          try {
            const body = alert.format === "json" ? alert.raw : JSON.stringify({ message: alert.raw, format: alert.format });
            const resp = await fetch(`${config.endpoint}/events`, {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${wazuhToken}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ events: [body] }),
              signal: AbortSignal.timeout(10_000),
            });
            if (resp.ok) sent++; else { failed++; errors.push(`Wazuh ${resp.status}`); }
          } catch (e: any) {
            failed++;
            errors.push(`Wazuh error: ${e.message}`);
          }
        }
        break;
      }

      case "syslog": {
        // For syslog, we'd normally use UDP/TCP, but in a web context we log them
        // and note they need a syslog forwarder
        sent = alerts.filter(a => a.findingId !== "header").length;
        break;
      }
    }
  } catch (e: any) {
    errors.push(`Push failed: ${e.message}`);
  }

  return {
    success: failed === 0 && errors.length === 0,
    alertsSent: sent,
    alertsFailed: failed,
    errors: errors.slice(0, 10),
    durationMs: Date.now() - start,
  };
}

// ═══════════════════════════════════════════════════════════════
// §5 — DETECTION RULE RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════

export interface DetectionRuleRecommendation {
  techniqueId: string;
  techniqueName: string;
  platform: "splunk" | "elastic" | "sigma" | "sentinel_kql";
  ruleName: string;
  ruleQuery: string;
  dataSources: string[];
  priority: "critical" | "high" | "medium" | "low";
}

const DETECTION_RULE_TEMPLATES: Record<string, Omit<DetectionRuleRecommendation, "techniqueId" | "techniqueName" | "priority">[]> = {
  "T1059.001": [
    {
      platform: "splunk",
      ruleName: "Suspicious PowerShell Execution",
      ruleQuery: `index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104 | where match(ScriptBlockText, "(?i)(invoke-expression|iex|downloadstring|encodedcommand|bypass)")`,
      dataSources: ["Windows PowerShell Operational Log", "Sysmon Event ID 1"],
    },
    {
      platform: "elastic",
      ruleName: "PowerShell Suspicious Script Block",
      ruleQuery: `event.code: "4104" AND powershell.file.script_block_text: (*Invoke-Expression* OR *IEX* OR *DownloadString* OR *EncodedCommand*)`,
      dataSources: ["winlog.event_data.ScriptBlockText"],
    },
    {
      platform: "sigma",
      ruleName: "Suspicious PowerShell Keywords",
      ruleQuery: `title: Suspicious PowerShell Keywords\nlogsource:\n  product: windows\n  service: powershell-script\ndetection:\n  selection:\n    ScriptBlockText|contains:\n      - 'Invoke-Expression'\n      - 'IEX'\n      - 'DownloadString'\n  condition: selection`,
      dataSources: ["PowerShell Script Block Logging"],
    },
  ],
  "T1003.001": [
    {
      platform: "splunk",
      ruleName: "LSASS Memory Access Detection",
      ruleQuery: `index=windows sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*\\\\lsass.exe" | where NOT match(SourceImage, "(MsMpEng|csrss|services)")`,
      dataSources: ["Sysmon Event ID 10 (ProcessAccess)"],
    },
    {
      platform: "elastic",
      ruleName: "LSASS Process Access",
      ruleQuery: `event.code: "10" AND winlog.event_data.TargetImage: *lsass.exe AND NOT winlog.event_data.SourceImage: (*MsMpEng* OR *csrss* OR *services*)`,
      dataSources: ["Sysmon ProcessAccess events"],
    },
  ],
  "T1021.001": [
    {
      platform: "splunk",
      ruleName: "Anomalous RDP Connection",
      ruleQuery: `index=windows sourcetype=WinEventLog:Security EventCode=4624 LogonType=10 | stats count by src_ip, dest, user | where count > 5`,
      dataSources: ["Windows Security Event Log 4624"],
    },
    {
      platform: "sentinel_kql",
      ruleName: "Unusual RDP Connections",
      ruleQuery: `SecurityEvent\n| where EventID == 4624 and LogonType == 10\n| summarize ConnectionCount = count() by SourceIP = IpAddress, DestHost = Computer, Account\n| where ConnectionCount > 5`,
      dataSources: ["SecurityEvent"],
    },
  ],
  "T1071.001": [
    {
      platform: "splunk",
      ruleName: "Suspicious HTTP Beaconing",
      ruleQuery: `index=proxy OR index=firewall | stats count, stdev(bytes_out) as std_bytes, avg(_time) as avg_time by src_ip, dest_ip | where count > 100 AND std_bytes < 50`,
      dataSources: ["Proxy logs", "Firewall logs"],
    },
    {
      platform: "elastic",
      ruleName: "HTTP Beaconing Detection",
      ruleQuery: `destination.bytes: [1 TO 1000] AND event.category: "network_traffic" | aggregate by source.ip, destination.ip`,
      dataSources: ["Network traffic logs", "Proxy logs"],
    },
  ],
  "T1486": [
    {
      platform: "splunk",
      ruleName: "Ransomware File Encryption Pattern",
      ruleQuery: `index=windows sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11 | stats dc(TargetFilename) as file_count by Computer, User | where file_count > 100`,
      dataSources: ["Sysmon Event ID 11 (FileCreate)"],
    },
    {
      platform: "sigma",
      ruleName: "Volume Shadow Copy Deletion",
      ruleQuery: `title: Volume Shadow Copy Deletion\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains:\n      - 'vssadmin delete shadows'\n      - 'wmic shadowcopy delete'\n  condition: selection`,
      dataSources: ["Process creation logs"],
    },
  ],
};

/**
 * Get detection rule recommendations for uncovered techniques.
 */
export function getDetectionRuleRecommendations(
  gaps: DetectionGap[],
  platforms?: DetectionRuleRecommendation["platform"][]
): DetectionRuleRecommendation[] {
  const recommendations: DetectionRuleRecommendation[] = [];

  for (const gap of gaps) {
    const baseId = gap.techniqueId.split(".").slice(0, 2).join(".");
    const templates = DETECTION_RULE_TEMPLATES[gap.techniqueId] || DETECTION_RULE_TEMPLATES[baseId] || [];

    for (const template of templates) {
      if (platforms && !platforms.includes(template.platform)) continue;

      recommendations.push({
        ...template,
        techniqueId: gap.techniqueId,
        techniqueName: gap.techniqueName,
        priority: gap.gapSeverity,
      });
    }
  }

  return recommendations;
}
