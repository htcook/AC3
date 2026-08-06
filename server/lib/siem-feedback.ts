/**
 * SIEM Detection Feedback Loop
 * Queries SIEM platforms (Splunk, Elastic, Sentinel, QRadar) after technique
 * execution to verify whether the attack was detected, missed, or partially detected.
 */

export interface SIEMConfig {
  provider: "splunk" | "elastic" | "sentinel" | "qradar" | "custom";
  baseUrl: string;
  apiKey: string;
  queryTemplate?: string;
}

export interface DetectionQuery {
  techniqueId: string;
  techniqueName?: string;
  executedAt: Date;
  queryWindowSec?: number;
}

export interface DetectionResult {
  detected: boolean;
  alertsFound: number;
  result: "detected" | "missed" | "partial" | "error";
  alerts: any[];
  queryUsed: string;
  latencyMs: number;
  error?: string;
}

// Default SIEM query templates per provider
const DEFAULT_QUERY_TEMPLATES: Record<string, string> = {
  splunk: `search index=* sourcetype=* (mitre_technique_id="{{techniqueId}}" OR technique="{{techniqueName}}") earliest="{{startTime}}" latest="{{endTime}}" | head 100`,
  elastic: JSON.stringify({
    query: {
      bool: {
        must: [
          { bool: { should: [
            { match: { "threat.technique.id": "{{techniqueId}}" } },
            { match: { "rule.name": "{{techniqueName}}" } },
            { match: { "signal.rule.threat.technique.id": "{{techniqueId}}" } }
          ]}},
          { range: { "@timestamp": { gte: "{{startTime}}", lte: "{{endTime}}" } } }
        ]
      }
    },
    size: 100
  }),
  sentinel: `SecurityAlert | where TimeGenerated between (datetime({{startTime}}) .. datetime({{endTime}})) | where Tactics has "{{techniqueName}}" or ExtendedProperties has "{{techniqueId}}" | take 100`,
  qradar: `SELECT * FROM events WHERE LOGSOURCETYPENAME(logsourcetypeid) ILIKE '%{{techniqueName}}%' AND starttime >= {{startTimeEpoch}} AND endtime <= {{endTimeEpoch}} LIMIT 100`,
};

function interpolateQuery(template: string, params: Record<string, string>): string {
  let result = template;
  for (const [key, value] of Object.entries(params)) {
    result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, "g"), value);
  }
  return result;
}

export async function querySplunk(config: SIEMConfig, query: string): Promise<{ alerts: any[]; latencyMs: number }> {
  const start = Date.now();
  const searchUrl = `${config.baseUrl}/services/search/jobs`;
  
  // Create search job
  const createResp = await fetch(searchUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ search: query, output_mode: "json", exec_mode: "oneshot" }),
  });

  if (!createResp.ok) {
    throw new Error(`Splunk query failed: ${createResp.status} ${await createResp.text()}`);
  }

  const data = await createResp.json();
  const alerts = data?.results || data?.rows || [];
  return { alerts, latencyMs: Date.now() - start };
}

export async function queryElastic(config: SIEMConfig, query: string): Promise<{ alerts: any[]; latencyMs: number }> {
  const start = Date.now();
  const searchUrl = `${config.baseUrl}/_search`;

  const resp = await fetch(searchUrl, {
    method: "POST",
    headers: {
      Authorization: `ApiKey ${config.apiKey}`,
      "Content-Type": "application/json",
    },
    body: query,
  });

  if (!resp.ok) {
    throw new Error(`Elastic query failed: ${resp.status} ${await resp.text()}`);
  }

  const data = await resp.json();
  const alerts = data?.hits?.hits?.map((h: any) => h._source) || [];
  return { alerts, latencyMs: Date.now() - start };
}

export async function querySentinel(config: SIEMConfig, query: string): Promise<{ alerts: any[]; latencyMs: number }> {
  const start = Date.now();
  const queryUrl = `${config.baseUrl}/api/query`;

  const resp = await fetch(queryUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, timespan: "PT1H" }),
  });

  if (!resp.ok) {
    throw new Error(`Sentinel query failed: ${resp.status} ${await resp.text()}`);
  }

  const data = await resp.json();
  const alerts = data?.tables?.[0]?.rows || [];
  return { alerts, latencyMs: Date.now() - start };
}

export async function queryQRadar(config: SIEMConfig, query: string): Promise<{ alerts: any[]; latencyMs: number }> {
  const start = Date.now();
  const searchUrl = `${config.baseUrl}/api/ariel/searches`;

  const createResp = await fetch(searchUrl, {
    method: "POST",
    headers: {
      SEC: config.apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query_expression: query }),
  });

  if (!createResp.ok) {
    throw new Error(`QRadar query failed: ${createResp.status} ${await createResp.text()}`);
  }

  const searchData = await createResp.json();
  const searchId = searchData.search_id;

  // Poll for results (simplified — real implementation would poll status)
  await new Promise((r) => setTimeout(r, 2000));

  const resultsResp = await fetch(`${searchUrl}/${searchId}/results`, {
    headers: { SEC: config.apiKey },
  });

  const results = await resultsResp.json();
  const alerts = results?.events || results?.flows || [];
  return { alerts, latencyMs: Date.now() - start };
}

export async function executeDetectionQuery(
  config: SIEMConfig,
  detection: DetectionQuery
): Promise<DetectionResult> {
  const windowSec = detection.queryWindowSec || 300;
  const startTime = new Date(detection.executedAt.getTime() - 60000); // 1 min before
  const endTime = new Date(detection.executedAt.getTime() + windowSec * 1000);

  const template = config.queryTemplate || DEFAULT_QUERY_TEMPLATES[config.provider] || "";
  const queryParams: Record<string, string> = {
    techniqueId: detection.techniqueId,
    techniqueName: detection.techniqueName || detection.techniqueId,
    startTime: startTime.toISOString(),
    endTime: endTime.toISOString(),
    startTimeEpoch: String(Math.floor(startTime.getTime() / 1000)),
    endTimeEpoch: String(Math.floor(endTime.getTime() / 1000)),
  };

  const queryUsed = interpolateQuery(template, queryParams);

  try {
    let result: { alerts: any[]; latencyMs: number };

    switch (config.provider) {
      case "splunk":
        result = await querySplunk(config, queryUsed);
        break;
      case "elastic":
        result = await queryElastic(config, queryUsed);
        break;
      case "sentinel":
        result = await querySentinel(config, queryUsed);
        break;
      case "qradar":
        result = await queryQRadar(config, queryUsed);
        break;
      default:
        // Custom provider — attempt generic REST query
        result = await queryElastic(config, queryUsed);
    }

    const alertCount = result.alerts.length;
    let detectionResult: "detected" | "missed" | "partial";
    if (alertCount === 0) {
      detectionResult = "missed";
    } else if (alertCount >= 1) {
      detectionResult = "detected";
    } else {
      detectionResult = "partial";
    }

    return {
      detected: alertCount > 0,
      alertsFound: alertCount,
      result: detectionResult,
      alerts: result.alerts.slice(0, 20), // Cap stored alerts
      queryUsed,
      latencyMs: result.latencyMs,
    };
  } catch (err: any) {
    return {
      detected: false,
      alertsFound: 0,
      result: "error",
      alerts: [],
      queryUsed,
      latencyMs: 0,
      error: err.message || String(err),
    };
  }
}

export async function testSIEMConnection(config: SIEMConfig): Promise<{ success: boolean; message: string; latencyMs: number }> {
  const start = Date.now();
  try {
    switch (config.provider) {
      case "splunk": {
        const resp = await fetch(`${config.baseUrl}/services/server/info?output_mode=json`, {
          headers: { Authorization: `Bearer ${config.apiKey}` },
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "Splunk connection successful", latencyMs: Date.now() - start };
      }
      case "elastic": {
        const resp = await fetch(`${config.baseUrl}/_cluster/health`, {
          headers: { Authorization: `ApiKey ${config.apiKey}` },
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "Elasticsearch connection successful", latencyMs: Date.now() - start };
      }
      case "sentinel": {
        const resp = await fetch(`${config.baseUrl}/api/query`, {
          method: "POST",
          headers: { Authorization: `Bearer ${config.apiKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({ query: "SecurityAlert | take 1", timespan: "PT1M" }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "Sentinel connection successful", latencyMs: Date.now() - start };
      }
      case "qradar": {
        const resp = await fetch(`${config.baseUrl}/api/system/about`, {
          headers: { SEC: config.apiKey },
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "QRadar connection successful", latencyMs: Date.now() - start };
      }
      default:
        return { success: false, message: `Unknown provider: ${config.provider}`, latencyMs: Date.now() - start };
    }
  } catch (err: any) {
    return { success: false, message: err.message || String(err), latencyMs: Date.now() - start };
  }
}
