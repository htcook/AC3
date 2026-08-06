/**
 * SIEM Query Engine
 * 
 * Executes search queries against SIEM platforms and normalizes results
 * into a common alert format for detection gap analysis.
 * 
 * Supported providers:
 * - Splunk: SPL queries via REST API (/services/search/jobs)
 * - Elastic: KQL/Lucene via _search API
 * - Sentinel: KQL via Azure Log Analytics API
 * - QRadar: AQL via /api/ariel/searches
 * - Custom/Wazuh: Generic REST query
 */

import type { NormalizedSiemAlert } from "./siem-connectors";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

export type SiemProvider = "splunk" | "elastic" | "sentinel" | "qradar" | "custom";

export interface SiemQueryConfig {
  provider: SiemProvider;
  baseUrl: string;
  apiKey?: string;
  query: string;
  /** Time range in hours to search (default: 24) */
  timeRangeHours?: number;
  /** Max results to return (default: 100) */
  maxResults?: number;
}

export interface SiemQueryResult {
  success: boolean;
  provider: SiemProvider;
  query: string;
  alerts: NormalizedSiemAlert[];
  totalResults: number;
  durationMs: number;
  error?: string;
  rawResponse?: any;
}

export interface QueryTemplate {
  id: string;
  name: string;
  provider: SiemProvider;
  query: string;
  description: string;
  /** Placeholders like {{technique_id}}, {{time_range}}, {{host}} */
  variables: string[];
}

// ═══════════════════════════════════════════════════════════
// Default Query Templates
// ═══════════════════════════════════════════════════════════

export const DEFAULT_QUERY_TEMPLATES: QueryTemplate[] = [
  // Splunk SPL Templates
  {
    id: "splunk-mitre-technique",
    name: "MITRE Technique Alerts",
    provider: "splunk",
    query: 'index=* sourcetype=*security* mitre_technique_id="{{technique_id}}" earliest=-{{time_range}}h | table _time, source, severity, mitre_technique_id, mitre_tactic, description, src_ip, dest_ip, process_name | head {{max_results}}',
    description: "Search for alerts matching a specific MITRE ATT&CK technique ID",
    variables: ["technique_id", "time_range", "max_results"],
  },
  {
    id: "splunk-high-severity",
    name: "High Severity Alerts",
    provider: "splunk",
    query: 'index=* sourcetype=*security* (severity="critical" OR severity="high") earliest=-{{time_range}}h | table _time, source, severity, description, src_ip, dest_ip, rule_name | head {{max_results}}',
    description: "Search for critical and high severity security alerts",
    variables: ["time_range", "max_results"],
  },
  {
    id: "splunk-host-activity",
    name: "Host Security Activity",
    provider: "splunk",
    query: 'index=* sourcetype=*security* (src_ip="{{host}}" OR dest_ip="{{host}}") earliest=-{{time_range}}h | table _time, source, severity, description, src_ip, dest_ip, action | head {{max_results}}',
    description: "Search for all security events involving a specific host",
    variables: ["host", "time_range", "max_results"],
  },

  // Elastic KQL Templates
  {
    id: "elastic-mitre-technique",
    name: "MITRE Technique Alerts",
    provider: "elastic",
    query: '{"query":{"bool":{"must":[{"match":{"threat.technique.id":"{{technique_id}}"}},{"range":{"@timestamp":{"gte":"now-{{time_range}}h"}}}]}},"size":{{max_results}},"sort":[{"@timestamp":"desc"}]}',
    description: "Search for alerts matching a specific MITRE ATT&CK technique ID",
    variables: ["technique_id", "time_range", "max_results"],
  },
  {
    id: "elastic-high-severity",
    name: "High Severity Alerts",
    provider: "elastic",
    query: '{"query":{"bool":{"must":[{"terms":{"event.severity":[3,4]}},{"range":{"@timestamp":{"gte":"now-{{time_range}}h"}}}]}},"size":{{max_results}},"sort":[{"@timestamp":"desc"}]}',
    description: "Search for high and critical severity alerts",
    variables: ["time_range", "max_results"],
  },
  {
    id: "elastic-host-activity",
    name: "Host Security Activity",
    provider: "elastic",
    query: '{"query":{"bool":{"must":[{"multi_match":{"query":"{{host}}","fields":["source.ip","destination.ip","host.ip"]}},{"range":{"@timestamp":{"gte":"now-{{time_range}}h"}}}]}},"size":{{max_results}},"sort":[{"@timestamp":"desc"}]}',
    description: "Search for all security events involving a specific host",
    variables: ["host", "time_range", "max_results"],
  },

  // Sentinel KQL Templates
  {
    id: "sentinel-mitre-technique",
    name: "MITRE Technique Alerts",
    provider: "sentinel",
    query: 'SecurityAlert | where TimeGenerated > ago({{time_range}}h) | where Tactics has "{{technique_id}}" or ExtendedProperties has "{{technique_id}}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Entities | take {{max_results}}',
    description: "Search for alerts matching a specific MITRE ATT&CK technique ID",
    variables: ["technique_id", "time_range", "max_results"],
  },
  {
    id: "sentinel-high-severity",
    name: "High Severity Alerts",
    provider: "sentinel",
    query: 'SecurityAlert | where TimeGenerated > ago({{time_range}}h) | where AlertSeverity in ("High", "Critical") | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Entities | take {{max_results}}',
    description: "Search for high and critical severity alerts",
    variables: ["time_range", "max_results"],
  },

  // QRadar AQL Templates
  {
    id: "qradar-mitre-technique",
    name: "MITRE Technique Alerts",
    provider: "qradar",
    query: "SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') as start_time, LOGSOURCENAME(logsourceid) as log_source, categoryname(category) as category, severity, RULENAME(creeventlist) as rule_name, sourceip, destinationip FROM events WHERE INOFFENSE({{technique_id}}) LAST {{time_range}} HOURS LIMIT {{max_results}}",
    description: "Search for offenses matching a specific technique",
    variables: ["technique_id", "time_range", "max_results"],
  },
  {
    id: "qradar-high-severity",
    name: "High Severity Offenses",
    provider: "qradar",
    query: "SELECT DATEFORMAT(starttime,'YYYY-MM-dd HH:mm:ss') as start_time, LOGSOURCENAME(logsourceid) as log_source, severity, RULENAME(creeventlist) as rule_name, sourceip, destinationip FROM events WHERE severity >= 7 LAST {{time_range}} HOURS LIMIT {{max_results}}",
    description: "Search for high severity events and offenses",
    variables: ["time_range", "max_results"],
  },

  // Custom / Wazuh Templates
  {
    id: "custom-wazuh-alerts",
    name: "Wazuh Security Alerts",
    provider: "custom",
    query: '{"query":{"bool":{"must":[{"range":{"timestamp":{"gte":"now-{{time_range}}h"}}},{"term":{"rule.mitre.id":"{{technique_id}}"}}]}},"size":{{max_results}}}',
    description: "Search Wazuh alerts by MITRE technique ID",
    variables: ["technique_id", "time_range", "max_results"],
  },
];

// ═══════════════════════════════════════════════════════════
// Query Variable Substitution
// ═══════════════════════════════════════════════════════════

export function substituteQueryVariables(
  query: string,
  variables: Record<string, string>,
): string {
  let result = query;
  for (const [key, value] of Object.entries(variables)) {
    result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, "g"), value);
  }
  return result;
}

export function extractQueryVariables(query: string): string[] {
  const matches = query.match(/\{\{(\w+)\}\}/g);
  if (!matches) return [];
  return [...new Set(matches.map(m => m.replace(/\{\{|\}\}/g, "")))];
}

// ═══════════════════════════════════════════════════════════
// Provider-Specific Query Execution
// ═══════════════════════════════════════════════════════════

async function querySplunk(config: SiemQueryConfig): Promise<SiemQueryResult> {
  const start = Date.now();
  const maxResults = config.maxResults || 100;

  try {
    // 1. Create a search job
    const jobResp = await fetch(`${config.baseUrl}/services/search/jobs`, {
      method: "POST",
      headers: {
        "Authorization": `Splunk ${config.apiKey}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        search: config.query.startsWith("search ") ? config.query : `search ${config.query}`,
        output_mode: "json",
        exec_mode: "oneshot",
        count: String(maxResults),
      }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!jobResp.ok) {
      const errText = await jobResp.text().catch(() => "");
      return {
        success: false,
        provider: "splunk",
        query: config.query,
        alerts: [],
        totalResults: 0,
        durationMs: Date.now() - start,
        error: `Splunk API error (HTTP ${jobResp.status}): ${errText.slice(0, 200)}`,
      };
    }

    const data = await jobResp.json();
    const results = data.results || [];

    // Normalize Splunk results to NormalizedSiemAlert
    const alerts: NormalizedSiemAlert[] = results.map((r: any, i: number) => ({
      alertId: r.sid || `splunk-${Date.now()}-${i}`,
      backend: "splunk" as const,
      timestamp: r._time ? new Date(r._time).getTime() : Date.now(),
      severity: normalizeSeverity(r.severity || r.urgency || "medium"),
      severityScore: severityToScore(r.severity || r.urgency || "medium"),
      title: r.search_name || r.rule_name || r.source || "Splunk Alert",
      description: r.description || r._raw?.slice(0, 500) || "",
      mitreTechniques: extractMitreTechniques(r),
      mitreTactics: extractMitreTactics(r),
      ruleId: r.rule_id || r.search_name || "",
      ruleName: r.rule_name || r.search_name || "",
      agentName: r.host || r.src || "",
      agentIp: r.src_ip || r.sourceip || undefined,
      rawData: r,
      processName: r.process_name || r.process || undefined,
    }));

    return {
      success: true,
      provider: "splunk",
      query: config.query,
      alerts,
      totalResults: data.results?.length || 0,
      durationMs: Date.now() - start,
    };
  } catch (e: any) {
    return {
      success: false,
      provider: "splunk",
      query: config.query,
      alerts: [],
      totalResults: 0,
      durationMs: Date.now() - start,
      error: `Splunk query error: ${e.message}`,
    };
  }
}

async function queryElastic(config: SiemQueryConfig): Promise<SiemQueryResult> {
  const start = Date.now();

  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (config.apiKey) headers["Authorization"] = `ApiKey ${config.apiKey}`;

    // Determine the search index
    const searchUrl = `${config.baseUrl}/.siem-signals-*,security-*,logs-*/_search`;

    const resp = await fetch(searchUrl, {
      method: "POST",
      headers,
      body: config.query, // Already a JSON query body
      signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      return {
        success: false,
        provider: "elastic",
        query: config.query,
        alerts: [],
        totalResults: 0,
        durationMs: Date.now() - start,
        error: `Elasticsearch error (HTTP ${resp.status}): ${errText.slice(0, 200)}`,
      };
    }

    const data = await resp.json();
    const hits = data.hits?.hits || [];

    const alerts: NormalizedSiemAlert[] = hits.map((hit: any, i: number) => {
      const src = hit._source || {};
      return {
        alertId: hit._id || `elastic-${Date.now()}-${i}`,
        backend: "elastic" as const,
        timestamp: src["@timestamp"] ? new Date(src["@timestamp"]).getTime() : Date.now(),
        severity: normalizeSeverity(src.event?.severity?.toString() || src.signal?.rule?.severity || "medium"),
        severityScore: typeof src.event?.severity === "number" ? src.event.severity * 25 : 50,
        title: src.signal?.rule?.name || src.rule?.name || src.message || "Elastic Alert",
        description: src.signal?.rule?.description || src.message || "",
        mitreTechniques: src.threat?.technique?.id ? [src.threat.technique.id] : (src.signal?.rule?.threat?.map((t: any) => t.technique?.[0]?.id).filter(Boolean) || []),
        mitreTactics: src.threat?.tactic?.name ? [src.threat.tactic.name] : [],
        ruleId: src.signal?.rule?.id || src.rule?.id || "",
        ruleName: src.signal?.rule?.name || src.rule?.name || "",
        agentName: src.agent?.name || src.host?.name || "",
        agentIp: src.source?.ip || src.host?.ip?.[0] || undefined,
        rawData: src,
        processName: src.process?.name || undefined,
      };
    });

    return {
      success: true,
      provider: "elastic",
      query: config.query,
      alerts,
      totalResults: data.hits?.total?.value || hits.length,
      durationMs: Date.now() - start,
    };
  } catch (e: any) {
    return {
      success: false,
      provider: "elastic",
      query: config.query,
      alerts: [],
      totalResults: 0,
      durationMs: Date.now() - start,
      error: `Elasticsearch query error: ${e.message}`,
    };
  }
}

async function querySentinel(config: SiemQueryConfig): Promise<SiemQueryResult> {
  const start = Date.now();

  try {
    // Azure Log Analytics query API
    const resp = await fetch(`${config.baseUrl}/query`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${config.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: config.query,
        timespan: `PT${config.timeRangeHours || 24}H`,
      }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      return {
        success: false,
        provider: "sentinel",
        query: config.query,
        alerts: [],
        totalResults: 0,
        durationMs: Date.now() - start,
        error: `Sentinel API error (HTTP ${resp.status}): ${errText.slice(0, 200)}`,
      };
    }

    const data = await resp.json();
    const tables = data.tables || [];
    const rows = tables[0]?.rows || [];
    const columns = tables[0]?.columns?.map((c: any) => c.name) || [];

    const alerts: NormalizedSiemAlert[] = rows.map((row: any[], i: number) => {
      const obj: Record<string, any> = {};
      columns.forEach((col: string, idx: number) => { obj[col] = row[idx]; });
      return {
        alertId: obj.SystemAlertId || `sentinel-${Date.now()}-${i}`,
        backend: "sentinel" as const,
        timestamp: obj.TimeGenerated ? new Date(obj.TimeGenerated).getTime() : Date.now(),
        severity: normalizeSeverity(obj.AlertSeverity || "medium"),
        severityScore: severityToScore(obj.AlertSeverity || "medium"),
        title: obj.AlertName || obj.DisplayName || "Sentinel Alert",
        description: obj.Description || "",
        mitreTechniques: obj.Tactics ? extractTechniquesFromString(obj.Tactics) : [],
        mitreTactics: obj.Tactics ? obj.Tactics.split(",").map((t: string) => t.trim()) : [],
        ruleId: obj.AlertType || "",
        ruleName: obj.AlertName || "",
        agentName: obj.CompromisedEntity || "",
        rawData: obj,
      };
    });

    return {
      success: true,
      provider: "sentinel",
      query: config.query,
      alerts,
      totalResults: rows.length,
      durationMs: Date.now() - start,
    };
  } catch (e: any) {
    return {
      success: false,
      provider: "sentinel",
      query: config.query,
      alerts: [],
      totalResults: 0,
      durationMs: Date.now() - start,
      error: `Sentinel query error: ${e.message}`,
    };
  }
}

async function queryQRadar(config: SiemQueryConfig): Promise<SiemQueryResult> {
  const start = Date.now();

  try {
    // 1. Create an AQL search
    const searchResp = await fetch(`${config.baseUrl}/api/ariel/searches`, {
      method: "POST",
      headers: {
        "SEC": config.apiKey || "",
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({ query_expression: config.query }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!searchResp.ok) {
      const errText = await searchResp.text().catch(() => "");
      return {
        success: false,
        provider: "qradar",
        query: config.query,
        alerts: [],
        totalResults: 0,
        durationMs: Date.now() - start,
        error: `QRadar API error (HTTP ${searchResp.status}): ${errText.slice(0, 200)}`,
      };
    }

    const searchData = await searchResp.json();
    const searchId = searchData.search_id;

    // 2. Poll for results (up to 20 seconds)
    let results: any[] = [];
    let completed = false;
    for (let i = 0; i < 10 && !completed; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const statusResp = await fetch(`${config.baseUrl}/api/ariel/searches/${searchId}`, {
        headers: { "SEC": config.apiKey || "", "Accept": "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
      if (statusResp.ok) {
        const statusData = await statusResp.json();
        if (statusData.status === "COMPLETED") {
          // Fetch results
          const resultsResp = await fetch(`${config.baseUrl}/api/ariel/searches/${searchId}/results`, {
            headers: { "SEC": config.apiKey || "", "Accept": "application/json" },
            signal: AbortSignal.timeout(10_000),
          });
          if (resultsResp.ok) {
            const resultsData = await resultsResp.json();
            results = resultsData.events || resultsData.flows || [];
          }
          completed = true;
        } else if (statusData.status === "ERROR") {
          return {
            success: false, provider: "qradar", query: config.query,
            alerts: [], totalResults: 0, durationMs: Date.now() - start,
            error: `QRadar search error: ${statusData.error_messages?.join(", ") || "Unknown"}`,
          };
        }
      }
    }

    const alerts: NormalizedSiemAlert[] = results.map((r: any, i: number) => ({
      alertId: r.qid?.toString() || `qradar-${Date.now()}-${i}`,
      backend: "qradar" as const,
      timestamp: r.starttime || r.start_time || Date.now(),
      severity: normalizeSeverity(r.severity?.toString() || "medium"),
      severityScore: typeof r.severity === "number" ? r.severity * 10 : 50,
      title: r.rule_name || r.category || "QRadar Event",
      description: r.log_source || "",
      mitreTechniques: [],
      mitreTactics: [],
      ruleId: r.creeventlist?.toString() || "",
      ruleName: r.rule_name || "",
      agentName: r.log_source || "",
      agentIp: r.sourceip || undefined,
      rawData: r,
    }));

    return {
      success: true,
      provider: "qradar",
      query: config.query,
      alerts,
      totalResults: results.length,
      durationMs: Date.now() - start,
    };
  } catch (e: any) {
    return {
      success: false,
      provider: "qradar",
      query: config.query,
      alerts: [],
      totalResults: 0,
      durationMs: Date.now() - start,
      error: `QRadar query error: ${e.message}`,
    };
  }
}

async function queryCustom(config: SiemQueryConfig): Promise<SiemQueryResult> {
  const start = Date.now();

  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (config.apiKey) headers["Authorization"] = `Bearer ${config.apiKey}`;

    // Try POST with query body first (Wazuh / generic)
    const resp = await fetch(`${config.baseUrl}`, {
      method: "POST",
      headers,
      body: config.query,
      signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => "");
      return {
        success: false,
        provider: "custom",
        query: config.query,
        alerts: [],
        totalResults: 0,
        durationMs: Date.now() - start,
        error: `Custom SIEM error (HTTP ${resp.status}): ${errText.slice(0, 200)}`,
      };
    }

    const data = await resp.json();

    // Try to normalize common response shapes
    const rawAlerts = data.data?.affected_items || data.hits?.hits || data.results || data.alerts || data.events || [];

    const alerts: NormalizedSiemAlert[] = rawAlerts.map((r: any, i: number) => {
      const src = r._source || r;
      return {
        alertId: r._id || src.id || `custom-${Date.now()}-${i}`,
        backend: "wazuh" as const,
        timestamp: src.timestamp ? new Date(src.timestamp).getTime() : Date.now(),
        severity: normalizeSeverity(src.rule?.level?.toString() || src.severity || "medium"),
        severityScore: typeof src.rule?.level === "number" ? src.rule.level * 7 : 50,
        title: src.rule?.description || src.title || "Custom Alert",
        description: src.full_log || src.description || "",
        mitreTechniques: src.rule?.mitre?.id || [],
        mitreTactics: src.rule?.mitre?.tactic || [],
        ruleId: src.rule?.id?.toString() || "",
        ruleName: src.rule?.description || "",
        agentName: src.agent?.name || "",
        agentIp: src.agent?.ip || undefined,
        rawData: src,
        processName: src.data?.process?.name || undefined,
      };
    });

    return {
      success: true,
      provider: "custom",
      query: config.query,
      alerts,
      totalResults: rawAlerts.length,
      durationMs: Date.now() - start,
    };
  } catch (e: any) {
    return {
      success: false,
      provider: "custom",
      query: config.query,
      alerts: [],
      totalResults: 0,
      durationMs: Date.now() - start,
      error: `Custom SIEM query error: ${e.message}`,
    };
  }
}

// ═══════════════════════════════════════════════════════════
// Main Query Dispatcher
// ═══════════════════════════════════════════════════════════

export async function executeSiemQuery(config: SiemQueryConfig): Promise<SiemQueryResult> {
  switch (config.provider) {
    case "splunk": return querySplunk(config);
    case "elastic": return queryElastic(config);
    case "sentinel": return querySentinel(config);
    case "qradar": return queryQRadar(config);
    case "custom": return queryCustom(config);
    default:
      return {
        success: false,
        provider: config.provider,
        query: config.query,
        alerts: [],
        totalResults: 0,
        durationMs: 0,
        error: `Unsupported provider: ${config.provider}`,
      };
  }
}

/**
 * Get default query templates for a specific provider
 */
export function getDefaultTemplates(provider?: SiemProvider): QueryTemplate[] {
  if (!provider) return DEFAULT_QUERY_TEMPLATES;
  return DEFAULT_QUERY_TEMPLATES.filter(t => t.provider === provider);
}

/**
 * Get the query language name for a provider
 */
export function getQueryLanguage(provider: SiemProvider): string {
  switch (provider) {
    case "splunk": return "SPL (Search Processing Language)";
    case "elastic": return "Elasticsearch Query DSL (JSON)";
    case "sentinel": return "KQL (Kusto Query Language)";
    case "qradar": return "AQL (Ariel Query Language)";
    case "custom": return "JSON Query Body";
  }
}

/**
 * Get a syntax hint for each provider
 */
export function getQuerySyntaxHint(provider: SiemProvider): string {
  switch (provider) {
    case "splunk":
      return 'SPL: index=* sourcetype=*security* severity="critical" earliest=-24h | table _time, source, severity, description | head 100';
    case "elastic":
      return '{"query":{"bool":{"must":[{"match":{"event.category":"threat"}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}},"size":100}';
    case "sentinel":
      return 'SecurityAlert | where TimeGenerated > ago(24h) | where AlertSeverity in ("High","Critical") | project TimeGenerated, AlertName, AlertSeverity | take 100';
    case "qradar":
      return "SELECT starttime, sourceip, destinationip, severity, RULENAME(creeventlist) FROM events WHERE severity >= 7 LAST 24 HOURS LIMIT 100";
    case "custom":
      return '{"query":{"bool":{"must":[{"range":{"timestamp":{"gte":"now-24h"}}}]}},"size":100}';
  }
}

// ═══════════════════════════════════════════════════════════
// Normalization Helpers
// ═══════════════════════════════════════════════════════════

function normalizeSeverity(raw: string): "low" | "medium" | "high" | "critical" {
  const lower = raw.toLowerCase().trim();
  if (lower === "critical" || lower === "4" || lower === "very-high" || lower === "very high") return "critical";
  if (lower === "high" || lower === "3") return "high";
  if (lower === "medium" || lower === "2" || lower === "moderate") return "medium";
  return "low";
}

function severityToScore(sev: string): number {
  switch (normalizeSeverity(sev)) {
    case "critical": return 90;
    case "high": return 70;
    case "medium": return 50;
    case "low": return 25;
  }
}

function extractMitreTechniques(obj: any): string[] {
  const techniques: string[] = [];
  if (obj.mitre_technique_id) techniques.push(obj.mitre_technique_id);
  if (obj.mitre_technique) techniques.push(obj.mitre_technique);
  if (obj["threat.technique.id"]) techniques.push(obj["threat.technique.id"]);
  // Check for T-pattern in any string field
  for (const val of Object.values(obj)) {
    if (typeof val === "string") {
      const matches = val.match(/T\d{4}(?:\.\d{3})?/g);
      if (matches) techniques.push(...matches);
    }
  }
  return [...new Set(techniques)];
}

function extractMitreTactics(obj: any): string[] {
  const tactics: string[] = [];
  if (obj.mitre_tactic) tactics.push(obj.mitre_tactic);
  if (obj.tactic) tactics.push(obj.tactic);
  return [...new Set(tactics)];
}

function extractTechniquesFromString(str: string): string[] {
  const matches = str.match(/T\d{4}(?:\.\d{3})?/g);
  return matches ? [...new Set(matches)] : [];
}
