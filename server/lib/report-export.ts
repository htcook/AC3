/**
 * Report Export Engine
 * Generates CSV and structured JSON exports for pentest report artifacts.
 * Covers: credential attack findings, engagement timeline, OPSEC events,
 * exploitation attempts, privilege escalation findings, and lateral movement paths.
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface ExportOptions {
  format: "csv" | "json";
  engagementId?: string;
  dateFrom?: number;
  dateTo?: number;
  includeRawOutput?: boolean;
}

export interface CredentialFinding {
  id: string;
  timestamp: number;
  tool: string;
  protocol: string;
  target: string;
  port: number;
  username: string;
  password: string;
  status: string;
  validated: boolean;
}

export interface TimelineEvent {
  id: string;
  timestamp: number;
  engagementId: string;
  phase: string;
  category: string;
  action: string;
  description: string;
  severity: string;
  opsecScore?: number;
}

export interface OpsecEvent {
  id: string;
  timestamp: number;
  engagementId: string;
  action: string;
  riskScore: number;
  detectionTech: string;
  mitigations: string;
  burnIndicator: boolean;
}

export interface ExploitAttempt {
  id: string;
  timestamp: number;
  cve: string;
  target: string;
  tool: string;
  technique: string;
  success: boolean;
  evidence: string;
  opsecRisk: number;
}

export interface PrivescFinding {
  id: string;
  timestamp: number;
  os: string;
  technique: string;
  vector: string;
  severity: string;
  exploitability: string;
  description: string;
}

export interface LateralMovePath {
  id: string;
  timestamp: number;
  sourceHost: string;
  targetHost: string;
  technique: string;
  protocol: string;
  credentials: string;
  success: boolean;
}

// ─── CSV Generation ─────────────────────────────────────────────────────────────

function escapeCSV(value: unknown): string {
  if (value === null || value === undefined) return "";
  const str = String(value);
  if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function arrayToCSV<T extends Record<string, unknown>>(data: T[], columns: { key: keyof T; header: string }[]): string {
  const header = columns.map((c) => escapeCSV(c.header)).join(",");
  const rows = data.map((row) => columns.map((c) => escapeCSV(row[c.key])).join(","));
  return [header, ...rows].join("\n");
}

// ─── Export Functions ───────────────────────────────────────────────────────────

export function exportCredentialFindings(findings: CredentialFinding[], options: ExportOptions): string {
  const filtered = filterByDate(findings, options);

  if (options.format === "json") {
    return JSON.stringify({ type: "credential_findings", exportedAt: Date.now(), count: filtered.length, data: filtered }, null, 2);
  }

  return arrayToCSV(filtered, [
    { key: "id", header: "ID" },
    { key: "timestamp", header: "Timestamp" },
    { key: "tool", header: "Tool" },
    { key: "protocol", header: "Protocol" },
    { key: "target", header: "Target" },
    { key: "port", header: "Port" },
    { key: "username", header: "Username" },
    { key: "password", header: "Password" },
    { key: "status", header: "Status" },
    { key: "validated", header: "Validated" },
  ]);
}

export function exportTimelineEvents(events: TimelineEvent[], options: ExportOptions): string {
  let filtered = filterByDate(events, options);
  if (options.engagementId) {
    filtered = filtered.filter((e) => e.engagementId === options.engagementId);
  }

  if (options.format === "json") {
    return JSON.stringify({ type: "timeline_events", exportedAt: Date.now(), count: filtered.length, data: filtered }, null, 2);
  }

  return arrayToCSV(filtered, [
    { key: "id", header: "ID" },
    { key: "timestamp", header: "Timestamp" },
    { key: "engagementId", header: "Engagement ID" },
    { key: "phase", header: "Phase" },
    { key: "category", header: "Category" },
    { key: "action", header: "Action" },
    { key: "description", header: "Description" },
    { key: "severity", header: "Severity" },
    { key: "opsecScore", header: "OPSEC Score" },
  ]);
}

export function exportOpsecEvents(events: OpsecEvent[], options: ExportOptions): string {
  let filtered = filterByDate(events, options);
  if (options.engagementId) {
    filtered = filtered.filter((e) => e.engagementId === options.engagementId);
  }

  if (options.format === "json") {
    return JSON.stringify({ type: "opsec_events", exportedAt: Date.now(), count: filtered.length, data: filtered }, null, 2);
  }

  return arrayToCSV(filtered, [
    { key: "id", header: "ID" },
    { key: "timestamp", header: "Timestamp" },
    { key: "engagementId", header: "Engagement ID" },
    { key: "action", header: "Action" },
    { key: "riskScore", header: "Risk Score" },
    { key: "detectionTech", header: "Detection Technology" },
    { key: "mitigations", header: "Mitigations" },
    { key: "burnIndicator", header: "Burn Indicator" },
  ]);
}

export function exportExploitAttempts(attempts: ExploitAttempt[], options: ExportOptions): string {
  const filtered = filterByDate(attempts, options);

  if (options.format === "json") {
    return JSON.stringify({ type: "exploitation_attempts", exportedAt: Date.now(), count: filtered.length, data: filtered }, null, 2);
  }

  return arrayToCSV(filtered, [
    { key: "id", header: "ID" },
    { key: "timestamp", header: "Timestamp" },
    { key: "cve", header: "CVE" },
    { key: "target", header: "Target" },
    { key: "tool", header: "Tool" },
    { key: "technique", header: "Technique" },
    { key: "success", header: "Success" },
    { key: "evidence", header: "Evidence" },
    { key: "opsecRisk", header: "OPSEC Risk" },
  ]);
}

export function exportPrivescFindings(findings: PrivescFinding[], options: ExportOptions): string {
  const filtered = filterByDate(findings, options);

  if (options.format === "json") {
    return JSON.stringify({ type: "privesc_findings", exportedAt: Date.now(), count: filtered.length, data: filtered }, null, 2);
  }

  return arrayToCSV(filtered, [
    { key: "id", header: "ID" },
    { key: "timestamp", header: "Timestamp" },
    { key: "os", header: "OS" },
    { key: "technique", header: "Technique" },
    { key: "vector", header: "Vector" },
    { key: "severity", header: "Severity" },
    { key: "exploitability", header: "Exploitability" },
    { key: "description", header: "Description" },
  ]);
}

export function exportLateralMovePaths(paths: LateralMovePath[], options: ExportOptions): string {
  const filtered = filterByDate(paths, options);

  if (options.format === "json") {
    return JSON.stringify({ type: "lateral_movement_paths", exportedAt: Date.now(), count: filtered.length, data: filtered }, null, 2);
  }

  return arrayToCSV(filtered, [
    { key: "id", header: "ID" },
    { key: "timestamp", header: "Timestamp" },
    { key: "sourceHost", header: "Source Host" },
    { key: "targetHost", header: "Target Host" },
    { key: "technique", header: "Technique" },
    { key: "protocol", header: "Protocol" },
    { key: "credentials", header: "Credentials" },
    { key: "success", header: "Success" },
  ]);
}

// ─── Executive Summary Generator ────────────────────────────────────────────────

export interface ExecutiveSummary {
  generatedAt: number;
  engagementId?: string;
  totalCredentialsFound: number;
  validatedCredentials: number;
  totalExploitAttempts: number;
  successfulExploits: number;
  totalPrivescVectors: number;
  criticalPrivesc: number;
  totalLateralPaths: number;
  successfulLateral: number;
  averageOpsecScore: number;
  burnIndicators: number;
  timelineEventCount: number;
  toolBreakdown: Record<string, number>;
  protocolBreakdown: Record<string, number>;
  severityBreakdown: Record<string, number>;
}

export function generateExecutiveSummary(data: {
  credentials: CredentialFinding[];
  exploits: ExploitAttempt[];
  privesc: PrivescFinding[];
  lateral: LateralMovePath[];
  opsec: OpsecEvent[];
  timeline: TimelineEvent[];
  engagementId?: string;
}): ExecutiveSummary {
  const toolBreakdown: Record<string, number> = {};
  const protocolBreakdown: Record<string, number> = {};
  const severityBreakdown: Record<string, number> = {};

  data.credentials.forEach((c) => {
    toolBreakdown[c.tool] = (toolBreakdown[c.tool] || 0) + 1;
    protocolBreakdown[c.protocol] = (protocolBreakdown[c.protocol] || 0) + 1;
  });

  data.privesc.forEach((p) => {
    severityBreakdown[p.severity] = (severityBreakdown[p.severity] || 0) + 1;
  });

  const opsecScores = data.opsec.map((o) => o.riskScore).filter((s) => s > 0);
  const avgOpsec = opsecScores.length > 0 ? opsecScores.reduce((a, b) => a + b, 0) / opsecScores.length : 0;

  return {
    generatedAt: Date.now(),
    engagementId: data.engagementId,
    totalCredentialsFound: data.credentials.length,
    validatedCredentials: data.credentials.filter((c) => c.validated).length,
    totalExploitAttempts: data.exploits.length,
    successfulExploits: data.exploits.filter((e) => e.success).length,
    totalPrivescVectors: data.privesc.length,
    criticalPrivesc: data.privesc.filter((p) => p.severity === "critical").length,
    totalLateralPaths: data.lateral.length,
    successfulLateral: data.lateral.filter((l) => l.success).length,
    averageOpsecScore: Math.round(avgOpsec * 100) / 100,
    burnIndicators: data.opsec.filter((o) => o.burnIndicator).length,
    timelineEventCount: data.timeline.length,
    toolBreakdown,
    protocolBreakdown,
    severityBreakdown,
  };
}

export function exportExecutiveSummary(summary: ExecutiveSummary, format: "csv" | "json"): string {
  if (format === "json") {
    return JSON.stringify({ type: "executive_summary", ...summary }, null, 2);
  }

  const rows = [
    ["Metric", "Value"],
    ["Generated At", new Date(summary.generatedAt).toISOString()],
    ["Engagement ID", summary.engagementId || "All"],
    ["Total Credentials Found", String(summary.totalCredentialsFound)],
    ["Validated Credentials", String(summary.validatedCredentials)],
    ["Total Exploit Attempts", String(summary.totalExploitAttempts)],
    ["Successful Exploits", String(summary.successfulExploits)],
    ["Total Privesc Vectors", String(summary.totalPrivescVectors)],
    ["Critical Privesc", String(summary.criticalPrivesc)],
    ["Total Lateral Paths", String(summary.totalLateralPaths)],
    ["Successful Lateral", String(summary.successfulLateral)],
    ["Average OPSEC Score", String(summary.averageOpsecScore)],
    ["Burn Indicators", String(summary.burnIndicators)],
    ["Timeline Events", String(summary.timelineEventCount)],
    ["", ""],
    ["Tool Breakdown", ""],
    ...Object.entries(summary.toolBreakdown).map(([k, v]) => [k, String(v)]),
    ["", ""],
    ["Protocol Breakdown", ""],
    ...Object.entries(summary.protocolBreakdown).map(([k, v]) => [k, String(v)]),
    ["", ""],
    ["Severity Breakdown", ""],
    ...Object.entries(summary.severityBreakdown).map(([k, v]) => [k, String(v)]),
  ];

  return rows.map((r) => r.map(escapeCSV).join(",")).join("\n");
}

// ─── Full Engagement Export (all data combined) ─────────────────────────────────

export function exportFullEngagement(
  data: {
    credentials: CredentialFinding[];
    exploits: ExploitAttempt[];
    privesc: PrivescFinding[];
    lateral: LateralMovePath[];
    opsec: OpsecEvent[];
    timeline: TimelineEvent[];
  },
  options: ExportOptions
): Record<string, string> {
  const summary = generateExecutiveSummary(data);

  return {
    "executive_summary": exportExecutiveSummary(summary, options.format),
    "credential_findings": exportCredentialFindings(data.credentials, options),
    "timeline_events": exportTimelineEvents(data.timeline, options),
    "opsec_events": exportOpsecEvents(data.opsec, options),
    "exploitation_attempts": exportExploitAttempts(data.exploits, options),
    "privesc_findings": exportPrivescFindings(data.privesc, options),
    "lateral_movement_paths": exportLateralMovePaths(data.lateral, options),
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

function filterByDate<T extends { timestamp: number }>(items: T[], options: ExportOptions): T[] {
  let result = items;
  if (options.dateFrom) {
    result = result.filter((i) => i.timestamp >= options.dateFrom!);
  }
  if (options.dateTo) {
    result = result.filter((i) => i.timestamp <= options.dateTo!);
  }
  return result;
}
