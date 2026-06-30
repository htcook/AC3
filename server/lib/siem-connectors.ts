/**
 * SIEM Connectors — Wazuh + Elastic Alert Ingestion
 * ──────────────────────────────────────────────────
 * Provides a unified interface for pulling alerts from Wazuh and
 * Elasticsearch/Elastic SIEM. Normalizes alerts into a common schema
 * that feeds directly into the Evasion Scorecard for live detection
 * correlation during campaigns.
 *
 * Supported backends:
 *   - Wazuh Manager REST API (v4.x)
 *   - Elasticsearch / Elastic SIEM (v7.x / v8.x)
 *
 * The normalized alert format maps each alert to MITRE ATT&CK
 * technique IDs so the Evasion Scorecard can compute real-time
 * detection coverage.
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export type SiemBackend = "wazuh" | "elastic";

export interface SiemConnectionConfig {
  backend: SiemBackend;
  /** Base URL (e.g., https://wazuh.example.com:55000 or https://elastic.example.com:9200) */
  baseUrl: string;
  /** Username for basic auth */
  username?: string;
  /** Password for basic auth */
  password?: string;
  /** API key (Elastic) or JWT token (Wazuh) */
  apiKey?: string;
  /** Skip TLS verification (for self-signed certs) */
  insecure?: boolean;
  /** Connection timeout in ms */
  timeout?: number;
  /** Wazuh-specific: index prefix for alerts */
  wazuhAlertIndex?: string;
  /** Elastic-specific: index pattern for SIEM alerts */
  elasticIndex?: string;
  /** Elastic-specific: use Elastic Security detection rules index */
  useSecurityDetections?: boolean;
}

/** Normalized SIEM alert — common format for both backends */
export interface NormalizedSiemAlert {
  /** Unique alert ID */
  alertId: string;
  /** Source backend */
  backend: SiemBackend;
  /** Alert timestamp */
  timestamp: number;
  /** Alert severity (1-15 for Wazuh, mapped to low/medium/high/critical) */
  severity: "low" | "medium" | "high" | "critical";
  /** Numeric severity (0-100) */
  severityScore: number;
  /** Alert title / rule name */
  title: string;
  /** Alert description */
  description: string;
  /** MITRE ATT&CK technique IDs (if mapped) */
  mitreTechniques: string[];
  /** MITRE ATT&CK tactic names */
  mitreTactics: string[];
  /** Detection rule ID */
  ruleId: string;
  /** Detection rule name */
  ruleName: string;
  /** Agent / host that generated the alert */
  agentName: string;
  /** Agent IP */
  agentIp?: string;
  /** Raw source data (backend-specific) */
  rawData: Record<string, any>;
  /** Process name (if available) */
  processName?: string;
  /** Command line (if available) */
  commandLine?: string;
  /** File path (if available) */
  filePath?: string;
  /** User name (if available) */
  userName?: string;
}

export interface SiemAlertQuery {
  /** Time range start (Unix ms) */
  from?: number;
  /** Time range end (Unix ms) */
  to?: number;
  /** Filter by MITRE technique IDs */
  techniques?: string[];
  /** Filter by severity */
  minSeverity?: "low" | "medium" | "high" | "critical";
  /** Filter by agent name */
  agentName?: string;
  /** Free-text search */
  query?: string;
  /** Max results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

export interface SiemAlertResult {
  alerts: NormalizedSiemAlert[];
  total: number;
  backend: SiemBackend;
  queryDurationMs: number;
  errors: string[];
}

export interface SiemConnectionStatus {
  connected: boolean;
  backend: SiemBackend;
  version?: string;
  clusterName?: string;
  alertCount?: number;
  error?: string;
  latencyMs: number;
}

/** Detection correlation result — maps campaign techniques to SIEM detections */
export interface DetectionCorrelation {
  /** Campaign technique ID */
  techniqueId: string;
  /** Whether this technique was detected by the SIEM */
  detected: boolean;
  /** Number of alerts matching this technique */
  alertCount: number;
  /** Highest severity alert for this technique */
  maxSeverity: "low" | "medium" | "high" | "critical" | "none";
  /** Detection rule names that fired */
  detectionRules: string[];
  /** Sample alert IDs */
  sampleAlertIds: string[];
  /** Time to first detection (ms from campaign start, if available) */
  timeToDetection?: number;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — WAZUH CONNECTOR
// ═══════════════════════════════════════════════════════════════════════

const WAZUH_SEVERITY_MAP: Record<number, NormalizedSiemAlert["severity"]> = {
  0: "low", 1: "low", 2: "low", 3: "low", 4: "low",
  5: "medium", 6: "medium", 7: "medium", 8: "medium", 9: "medium",
  10: "high", 11: "high", 12: "high",
  13: "critical", 14: "critical", 15: "critical",
};

function mapWazuhSeverityScore(level: number): number {
  return Math.min(100, Math.round((level / 15) * 100));
}

async function wazuhAuthenticate(config: SiemConnectionConfig): Promise<string> {
  const { baseUrl, username = "wazuh-wui", password = "" } = config;
  const url = `${baseUrl}/security/user/authenticate`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
    },
    signal: AbortSignal.timeout(config.timeout ?? 10000),
  });

  if (!response.ok) {
    throw new Error(`Wazuh auth failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  return data?.data?.token || "";
}

function normalizeWazuhAlert(raw: any): NormalizedSiemAlert {
  const rule = raw.rule || {};
  const agent = raw.agent || {};
  const data = raw.data || {};
  const mitre = rule.mitre || {};

  // Extract MITRE technique IDs
  const techniques: string[] = [];
  if (mitre.id && Array.isArray(mitre.id)) {
    techniques.push(...mitre.id);
  } else if (mitre.technique && Array.isArray(mitre.technique)) {
    // Some Wazuh versions use technique names instead of IDs
    techniques.push(...mitre.technique);
  }

  const tactics: string[] = [];
  if (mitre.tactic && Array.isArray(mitre.tactic)) {
    tactics.push(...mitre.tactic);
  }

  const level = parseInt(rule.level || "0", 10);

  return {
    alertId: raw.id || `wazuh-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    backend: "wazuh",
    timestamp: raw.timestamp ? new Date(raw.timestamp).getTime() : Date.now(),
    severity: WAZUH_SEVERITY_MAP[level] || "low",
    severityScore: mapWazuhSeverityScore(level),
    title: rule.description || "Wazuh Alert",
    description: raw.full_log || rule.description || "",
    mitreTechniques: techniques,
    mitreTactics: tactics,
    ruleId: String(rule.id || ""),
    ruleName: rule.description || "",
    agentName: agent.name || "unknown",
    agentIp: agent.ip,
    rawData: raw,
    processName: data.win?.eventdata?.image || data.process?.name,
    commandLine: data.win?.eventdata?.commandLine || data.process?.command_line,
    filePath: data.win?.eventdata?.targetFilename || data.file?.path,
    userName: data.win?.eventdata?.user || data.user?.name,
  };
}

async function fetchWazuhAlerts(
  config: SiemConnectionConfig,
  query: SiemAlertQuery
): Promise<SiemAlertResult> {
  const start = Date.now();
  const errors: string[] = [];

  try {
    // Authenticate
    const token = await wazuhAuthenticate(config);

    // Build query parameters
    const params = new URLSearchParams();
    params.set("limit", String(query.limit || 50));
    params.set("offset", String(query.offset || 0));
    params.set("sort", "-timestamp");

    if (query.query) {
      params.set("q", query.query);
    }

    // Severity filter
    if (query.minSeverity) {
      const minLevel = query.minSeverity === "critical" ? 13 : query.minSeverity === "high" ? 10 : query.minSeverity === "medium" ? 5 : 1;
      params.set("q", `${params.get("q") || ""};rule.level>=${minLevel}`.replace(/^;/, ""));
    }

    // Agent filter
    if (query.agentName) {
      params.set("q", `${params.get("q") || ""};agent.name=${query.agentName}`.replace(/^;/, ""));
    }

    const url = `${config.baseUrl}/alerts?${params.toString()}`;
    const response = await fetch(url, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(config.timeout ?? 15000),
    });

    if (!response.ok) {
      throw new Error(`Wazuh alerts fetch failed: ${response.status}`);
    }

    const data = await response.json();
    const items = data?.data?.affected_items || [];
    const total = data?.data?.total_affected_items || 0;

    let alerts = items.map(normalizeWazuhAlert);

    // Post-filter by technique
    if (query.techniques && query.techniques.length > 0) {
      const techSet = new Set(query.techniques);
      alerts = alerts.filter((a: NormalizedSiemAlert) =>
        a.mitreTechniques.some(t => techSet.has(t))
      );
    }

    // Post-filter by time range
    if (query.from) {
      alerts = alerts.filter((a: NormalizedSiemAlert) => a.timestamp >= query.from!);
    }
    if (query.to) {
      alerts = alerts.filter((a: NormalizedSiemAlert) => a.timestamp <= query.to!);
    }

    return {
      alerts,
      total,
      backend: "wazuh",
      queryDurationMs: Date.now() - start,
      errors,
    };
  } catch (err: any) {
    errors.push(`Wazuh error: ${err.message}`);
    return {
      alerts: [],
      total: 0,
      backend: "wazuh",
      queryDurationMs: Date.now() - start,
      errors,
    };
  }
}

async function testWazuhConnection(config: SiemConnectionConfig): Promise<SiemConnectionStatus> {
  const start = Date.now();
  try {
    const token = await wazuhAuthenticate(config);

    // Get cluster info
    const response = await fetch(`${config.baseUrl}/cluster/status`, {
      headers: { "Authorization": `Bearer ${token}` },
      signal: AbortSignal.timeout(config.timeout ?? 10000),
    });

    if (!response.ok) {
      throw new Error(`Status check failed: ${response.status}`);
    }

    const data = await response.json();

    // Get alert count
    const alertResponse = await fetch(`${config.baseUrl}/alerts?limit=1`, {
      headers: { "Authorization": `Bearer ${token}` },
      signal: AbortSignal.timeout(config.timeout ?? 10000),
    });
    const alertData = alertResponse.ok ? await alertResponse.json() : null;

    return {
      connected: true,
      backend: "wazuh",
      version: data?.data?.api_version || "unknown",
      clusterName: data?.data?.enabled === "yes" ? "cluster" : "standalone",
      alertCount: alertData?.data?.total_affected_items,
      latencyMs: Date.now() - start,
    };
  } catch (err: any) {
    return {
      connected: false,
      backend: "wazuh",
      error: err.message,
      latencyMs: Date.now() - start,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — ELASTIC SIEM CONNECTOR
// ═══════════════════════════════════════════════════════════════════════

function normalizeElasticAlert(hit: any): NormalizedSiemAlert {
  const source = hit._source || {};
  const rule = source.rule || source.signal?.rule || {};
  const threat = source.threat || {};
  const process = source.process || {};
  const host = source.host || source.agent || {};
  const user = source.user || {};
  const file = source.file || {};

  // Extract MITRE technique IDs
  const techniques: string[] = [];
  const tactics: string[] = [];

  if (threat.technique) {
    const techArray = Array.isArray(threat.technique) ? threat.technique : [threat.technique];
    for (const t of techArray) {
      if (t.id) techniques.push(t.id);
      if (t.subtechnique) {
        for (const st of Array.isArray(t.subtechnique) ? t.subtechnique : [t.subtechnique]) {
          if (st.id) techniques.push(st.id);
        }
      }
    }
  }
  if (threat.tactic) {
    const tacticArray = Array.isArray(threat.tactic) ? threat.tactic : [threat.tactic];
    for (const t of tacticArray) {
      if (t.name) tactics.push(t.name);
    }
  }

  // Also check signal.rule.threat (Elastic Security format)
  const signalThreat = source.signal?.rule?.threat || [];
  for (const st of Array.isArray(signalThreat) ? signalThreat : [signalThreat]) {
    if (st.technique) {
      for (const t of Array.isArray(st.technique) ? st.technique : [st.technique]) {
        if (t.id && !techniques.includes(t.id)) techniques.push(t.id);
      }
    }
    if (st.tactic?.name && !tactics.includes(st.tactic.name)) {
      tactics.push(st.tactic.name);
    }
  }

  // Map severity
  const severityStr = (rule.severity || source.event?.severity || "low").toString().toLowerCase();
  const severity: NormalizedSiemAlert["severity"] =
    severityStr === "critical" || severityStr === "4" ? "critical" :
    severityStr === "high" || severityStr === "3" ? "high" :
    severityStr === "medium" || severityStr === "2" ? "medium" : "low";

  const severityScore =
    severity === "critical" ? 90 :
    severity === "high" ? 70 :
    severity === "medium" ? 50 : 25;

  return {
    alertId: hit._id || `elastic-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    backend: "elastic",
    timestamp: source["@timestamp"] ? new Date(source["@timestamp"]).getTime() : Date.now(),
    severity,
    severityScore,
    title: rule.name || source.message || "Elastic Alert",
    description: rule.description || source.message || "",
    mitreTechniques: techniques,
    mitreTactics: tactics,
    ruleId: rule.id || rule.rule_id || "",
    ruleName: rule.name || "",
    agentName: host.name || host.hostname || "unknown",
    agentIp: host.ip?.[0] || host.ip || undefined,
    rawData: source,
    processName: process.name || process.executable,
    commandLine: process.command_line || process.args?.join(" "),
    filePath: file.path || file.name,
    userName: user.name || user.id,
  };
}

function buildElasticQuery(query: SiemAlertQuery, config: SiemConnectionConfig): any {
  const must: any[] = [];
  const filter: any[] = [];

  // Time range
  if (query.from || query.to) {
    const range: any = {};
    if (query.from) range.gte = query.from;
    if (query.to) range.lte = query.to;
    range.format = "epoch_millis";
    filter.push({ range: { "@timestamp": range } });
  }

  // MITRE technique filter
  if (query.techniques && query.techniques.length > 0) {
    filter.push({
      bool: {
        should: [
          { terms: { "threat.technique.id": query.techniques } },
          { terms: { "signal.rule.threat.technique.id": query.techniques } },
        ],
        minimum_should_match: 1,
      },
    });
  }

  // Severity filter
  if (query.minSeverity) {
    const severities: string[] = [];
    if (query.minSeverity === "low") severities.push("low", "medium", "high", "critical");
    else if (query.minSeverity === "medium") severities.push("medium", "high", "critical");
    else if (query.minSeverity === "high") severities.push("high", "critical");
    else severities.push("critical");
    filter.push({ terms: { "rule.severity": severities } });
  }

  // Agent name filter
  if (query.agentName) {
    filter.push({
      bool: {
        should: [
          { match: { "host.name": query.agentName } },
          { match: { "agent.name": query.agentName } },
        ],
        minimum_should_match: 1,
      },
    });
  }

  // Free-text search
  if (query.query) {
    must.push({ query_string: { query: query.query } });
  }

  return {
    size: query.limit || 50,
    from: query.offset || 0,
    sort: [{ "@timestamp": { order: "desc" } }],
    query: {
      bool: {
        must: must.length > 0 ? must : [{ match_all: {} }],
        filter,
      },
    },
  };
}

async function fetchElasticAlerts(
  config: SiemConnectionConfig,
  query: SiemAlertQuery
): Promise<SiemAlertResult> {
  const start = Date.now();
  const errors: string[] = [];

  try {
    const index = config.useSecurityDetections
      ? ".siem-signals-*"
      : config.elasticIndex || "wazuh-alerts-*,.siem-signals-*,logs-*";

    const esQuery = buildElasticQuery(query, config);
    const url = `${config.baseUrl}/${index}/_search`;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (config.apiKey) {
      headers["Authorization"] = `ApiKey ${config.apiKey}`;
    } else if (config.username && config.password) {
      headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(esQuery),
      signal: AbortSignal.timeout(config.timeout ?? 15000),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Elasticsearch query failed: ${response.status} — ${errText.slice(0, 200)}`);
    }

    const data = await response.json();
    const hits = data?.hits?.hits || [];
    const total = typeof data?.hits?.total === "object" ? data.hits.total.value : data?.hits?.total || 0;

    const alerts = hits.map(normalizeElasticAlert);

    return {
      alerts,
      total,
      backend: "elastic",
      queryDurationMs: Date.now() - start,
      errors,
    };
  } catch (err: any) {
    errors.push(`Elasticsearch error: ${err.message}`);
    return {
      alerts: [],
      total: 0,
      backend: "elastic",
      queryDurationMs: Date.now() - start,
      errors,
    };
  }
}

async function testElasticConnection(config: SiemConnectionConfig): Promise<SiemConnectionStatus> {
  const start = Date.now();
  try {
    const headers: Record<string, string> = {};
    if (config.apiKey) {
      headers["Authorization"] = `ApiKey ${config.apiKey}`;
    } else if (config.username && config.password) {
      headers["Authorization"] = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
    }

    const response = await fetch(config.baseUrl, {
      headers,
      signal: AbortSignal.timeout(config.timeout ?? 10000),
    });

    if (!response.ok) {
      throw new Error(`Connection failed: ${response.status}`);
    }

    const data = await response.json();

    // Count alerts
    const index = config.elasticIndex || "wazuh-alerts-*,.siem-signals-*";
    const countResponse = await fetch(`${config.baseUrl}/${index}/_count`, {
      headers,
      signal: AbortSignal.timeout(config.timeout ?? 10000),
    });
    const countData = countResponse.ok ? await countResponse.json() : null;

    return {
      connected: true,
      backend: "elastic",
      version: data?.version?.number || "unknown",
      clusterName: data?.cluster_name || "unknown",
      alertCount: countData?.count,
      latencyMs: Date.now() - start,
    };
  } catch (err: any) {
    return {
      connected: false,
      backend: "elastic",
      error: err.message,
      latencyMs: Date.now() - start,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — UNIFIED INTERFACE
// ═══════════════════════════════════════════════════════════════════════

/** Test connectivity to a SIEM backend */
export async function testSiemConnection(config: SiemConnectionConfig): Promise<SiemConnectionStatus> {
  if (config.backend === "wazuh") {
    return testWazuhConnection(config);
  }
  return testElasticConnection(config);
}

/** Fetch alerts from a SIEM backend */
export async function fetchSiemAlerts(
  config: SiemConnectionConfig,
  query: SiemAlertQuery = {}
): Promise<SiemAlertResult> {
  if (config.backend === "wazuh") {
    return fetchWazuhAlerts(config, query);
  }
  return fetchElasticAlerts(config, query);
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — DETECTION CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Correlate campaign techniques with SIEM alerts to determine which
 * techniques were detected in real-time.
 *
 * This is the bridge between the Evasion Scorecard and live SIEM data.
 */
export function correlateDetections(
  campaignTechniques: string[],
  alerts: NormalizedSiemAlert[],
  campaignStartTime?: number
): DetectionCorrelation[] {
  // Build a lookup: technique → alerts
  const techAlertMap = new Map<string, NormalizedSiemAlert[]>();
  for (const alert of alerts) {
    for (const tech of alert.mitreTechniques) {
      const normalized = tech.toUpperCase();
      if (!techAlertMap.has(normalized)) {
        techAlertMap.set(normalized, []);
      }
      techAlertMap.get(normalized)!.push(alert);
    }
  }

  const SEVERITY_ORDER: Record<string, number> = {
    critical: 4, high: 3, medium: 2, low: 1, none: 0,
  };

  return campaignTechniques.map(techId => {
    const normalized = techId.toUpperCase();
    const matchingAlerts = techAlertMap.get(normalized) || [];
    const detected = matchingAlerts.length > 0;

    // Find max severity
    let maxSeverity: NormalizedSiemAlert["severity"] | "none" = "none";
    for (const alert of matchingAlerts) {
      if (SEVERITY_ORDER[alert.severity] > SEVERITY_ORDER[maxSeverity]) {
        maxSeverity = alert.severity;
      }
    }

    // Unique detection rules
    const detectionRules = Array.from(new Set(matchingAlerts.map(a => a.ruleName).filter(Boolean)));

    // Sample alert IDs (max 5)
    const sampleAlertIds = matchingAlerts.slice(0, 5).map(a => a.alertId);

    // Time to first detection
    let timeToDetection: number | undefined;
    if (campaignStartTime && matchingAlerts.length > 0) {
      const earliest = Math.min(...matchingAlerts.map(a => a.timestamp));
      timeToDetection = earliest - campaignStartTime;
      if (timeToDetection < 0) timeToDetection = 0;
    }

    return {
      techniqueId: techId,
      detected,
      alertCount: matchingAlerts.length,
      maxSeverity: maxSeverity as any,
      detectionRules,
      sampleAlertIds,
      timeToDetection,
    };
  });
}

/**
 * Compute detection coverage statistics from correlation results.
 */
export function computeDetectionStats(correlations: DetectionCorrelation[]) {
  const total = correlations.length;
  const detected = correlations.filter(c => c.detected).length;
  const undetected = total - detected;
  const coveragePercent = total > 0 ? Math.round((detected / total) * 100) : 0;

  // Average time to detection (for detected techniques)
  const detectedWithTime = correlations.filter(c => c.detected && c.timeToDetection !== undefined);
  const avgTimeToDetection = detectedWithTime.length > 0
    ? Math.round(detectedWithTime.reduce((s, c) => s + (c.timeToDetection || 0), 0) / detectedWithTime.length)
    : undefined;

  // Severity distribution
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  for (const c of correlations) {
    bySeverity[c.maxSeverity as keyof typeof bySeverity]++;
  }

  // Undetected techniques (gaps)
  const gaps = correlations
    .filter(c => !c.detected)
    .map(c => c.techniqueId);

  return {
    totalTechniques: total,
    detectedTechniques: detected,
    undetectedTechniques: undetected,
    coveragePercent,
    avgTimeToDetectionMs: avgTimeToDetection,
    bySeverity,
    detectionGaps: gaps,
  };
}

/**
 * Generate a SIEM alert summary suitable for display in the UI.
 */
export function summarizeAlerts(alerts: NormalizedSiemAlert[]) {
  const byBackend: Record<string, number> = {};
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byTechnique: Record<string, number> = {};
  const byRule: Record<string, number> = {};
  const byAgent: Record<string, number> = {};

  for (const alert of alerts) {
    byBackend[alert.backend] = (byBackend[alert.backend] || 0) + 1;
    bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
    for (const tech of alert.mitreTechniques) {
      byTechnique[tech] = (byTechnique[tech] || 0) + 1;
    }
    if (alert.ruleName) {
      byRule[alert.ruleName] = (byRule[alert.ruleName] || 0) + 1;
    }
    byAgent[alert.agentName] = (byAgent[alert.agentName] || 0) + 1;
  }

  // Top rules by count
  const topRules = Object.entries(byRule)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name, count }));

  // Top techniques by count
  const topTechniques = Object.entries(byTechnique)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([id, count]) => ({ id, count }));

  return {
    totalAlerts: alerts.length,
    byBackend,
    bySeverity,
    topRules,
    topTechniques,
    byAgent,
    timeRange: alerts.length > 0
      ? {
          earliest: Math.min(...alerts.map(a => a.timestamp)),
          latest: Math.max(...alerts.map(a => a.timestamp)),
        }
      : undefined,
  };
}
