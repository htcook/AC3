import "./chunk-KFQGP6VL.js";

// server/lib/siem-feedback.ts
var DEFAULT_QUERY_TEMPLATES = {
  splunk: `search index=* sourcetype=* (mitre_technique_id="{{techniqueId}}" OR technique="{{techniqueName}}") earliest="{{startTime}}" latest="{{endTime}}" | head 100`,
  elastic: JSON.stringify({
    query: {
      bool: {
        must: [
          { bool: { should: [
            { match: { "threat.technique.id": "{{techniqueId}}" } },
            { match: { "rule.name": "{{techniqueName}}" } },
            { match: { "signal.rule.threat.technique.id": "{{techniqueId}}" } }
          ] } },
          { range: { "@timestamp": { gte: "{{startTime}}", lte: "{{endTime}}" } } }
        ]
      }
    },
    size: 100
  }),
  sentinel: `SecurityAlert | where TimeGenerated between (datetime({{startTime}}) .. datetime({{endTime}})) | where Tactics has "{{techniqueName}}" or ExtendedProperties has "{{techniqueId}}" | take 100`,
  qradar: `SELECT * FROM events WHERE LOGSOURCETYPENAME(logsourcetypeid) ILIKE '%{{techniqueName}}%' AND starttime >= {{startTimeEpoch}} AND endtime <= {{endTimeEpoch}} LIMIT 100`
};
function interpolateQuery(template, params) {
  let result = template;
  for (const [key, value] of Object.entries(params)) {
    result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, "g"), value);
  }
  return result;
}
async function querySplunk(config, query) {
  const start = Date.now();
  const searchUrl = `${config.baseUrl}/services/search/jobs`;
  const createResp = await fetch(searchUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({ search: query, output_mode: "json", exec_mode: "oneshot" })
  });
  if (!createResp.ok) {
    throw new Error(`Splunk query failed: ${createResp.status} ${await createResp.text()}`);
  }
  const data = await createResp.json();
  const alerts = data?.results || data?.rows || [];
  return { alerts, latencyMs: Date.now() - start };
}
async function queryElastic(config, query) {
  const start = Date.now();
  const searchUrl = `${config.baseUrl}/_search`;
  const resp = await fetch(searchUrl, {
    method: "POST",
    headers: {
      Authorization: `ApiKey ${config.apiKey}`,
      "Content-Type": "application/json"
    },
    body: query
  });
  if (!resp.ok) {
    throw new Error(`Elastic query failed: ${resp.status} ${await resp.text()}`);
  }
  const data = await resp.json();
  const alerts = data?.hits?.hits?.map((h) => h._source) || [];
  return { alerts, latencyMs: Date.now() - start };
}
async function querySentinel(config, query) {
  const start = Date.now();
  const queryUrl = `${config.baseUrl}/api/query`;
  const resp = await fetch(queryUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, timespan: "PT1H" })
  });
  if (!resp.ok) {
    throw new Error(`Sentinel query failed: ${resp.status} ${await resp.text()}`);
  }
  const data = await resp.json();
  const alerts = data?.tables?.[0]?.rows || [];
  return { alerts, latencyMs: Date.now() - start };
}
async function queryQRadar(config, query) {
  const start = Date.now();
  const searchUrl = `${config.baseUrl}/api/ariel/searches`;
  const createResp = await fetch(searchUrl, {
    method: "POST",
    headers: {
      SEC: config.apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query_expression: query })
  });
  if (!createResp.ok) {
    throw new Error(`QRadar query failed: ${createResp.status} ${await createResp.text()}`);
  }
  const searchData = await createResp.json();
  const searchId = searchData.search_id;
  await new Promise((r) => setTimeout(r, 2e3));
  const resultsResp = await fetch(`${searchUrl}/${searchId}/results`, {
    headers: { SEC: config.apiKey }
  });
  const results = await resultsResp.json();
  const alerts = results?.events || results?.flows || [];
  return { alerts, latencyMs: Date.now() - start };
}
async function executeDetectionQuery(config, detection) {
  const windowSec = detection.queryWindowSec || 300;
  const startTime = new Date(detection.executedAt.getTime() - 6e4);
  const endTime = new Date(detection.executedAt.getTime() + windowSec * 1e3);
  const template = config.queryTemplate || DEFAULT_QUERY_TEMPLATES[config.provider] || "";
  const queryParams = {
    techniqueId: detection.techniqueId,
    techniqueName: detection.techniqueName || detection.techniqueId,
    startTime: startTime.toISOString(),
    endTime: endTime.toISOString(),
    startTimeEpoch: String(Math.floor(startTime.getTime() / 1e3)),
    endTimeEpoch: String(Math.floor(endTime.getTime() / 1e3))
  };
  const queryUsed = interpolateQuery(template, queryParams);
  try {
    let result;
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
        result = await queryElastic(config, queryUsed);
    }
    const alertCount = result.alerts.length;
    let detectionResult;
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
      alerts: result.alerts.slice(0, 20),
      // Cap stored alerts
      queryUsed,
      latencyMs: result.latencyMs
    };
  } catch (err) {
    return {
      detected: false,
      alertsFound: 0,
      result: "error",
      alerts: [],
      queryUsed,
      latencyMs: 0,
      error: err.message || String(err)
    };
  }
}
async function testSIEMConnection(config) {
  const start = Date.now();
  try {
    switch (config.provider) {
      case "splunk": {
        const resp = await fetch(`${config.baseUrl}/services/server/info?output_mode=json`, {
          headers: { Authorization: `Bearer ${config.apiKey}` }
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "Splunk connection successful", latencyMs: Date.now() - start };
      }
      case "elastic": {
        const resp = await fetch(`${config.baseUrl}/_cluster/health`, {
          headers: { Authorization: `ApiKey ${config.apiKey}` }
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "Elasticsearch connection successful", latencyMs: Date.now() - start };
      }
      case "sentinel": {
        const resp = await fetch(`${config.baseUrl}/api/query`, {
          method: "POST",
          headers: { Authorization: `Bearer ${config.apiKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({ query: "SecurityAlert | take 1", timespan: "PT1M" })
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "Sentinel connection successful", latencyMs: Date.now() - start };
      }
      case "qradar": {
        const resp = await fetch(`${config.baseUrl}/api/system/about`, {
          headers: { SEC: config.apiKey }
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return { success: true, message: "QRadar connection successful", latencyMs: Date.now() - start };
      }
      default:
        return { success: false, message: `Unknown provider: ${config.provider}`, latencyMs: Date.now() - start };
    }
  } catch (err) {
    return { success: false, message: err.message || String(err), latencyMs: Date.now() - start };
  }
}
export {
  executeDetectionQuery,
  queryElastic,
  queryQRadar,
  querySentinel,
  querySplunk,
  testSIEMConnection
};
