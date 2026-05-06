import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/integration-registry/pipeline-bridge.ts
async function getActiveSourcesForStage(stage) {
  try {
    const { getActiveCustomerIntegrationsByStage } = await import("./db-UCRYETLI.js");
    return getActiveCustomerIntegrationsByStage(stage);
  } catch (err) {
    console.error(`[PipelineBridge] Failed to fetch active sources for stage ${stage}: ${err.message}`);
    return [];
  }
}
async function executeIntegrationCall(integration, context) {
  const startTime = Date.now();
  const integrationId = integration.integrationId;
  const displayName = integration.displayName;
  const category = integration.category;
  try {
    const endpointConfig = integration.endpointConfig || {};
    const authConfig = integration.authConfig || {};
    const credentials = integration.credentials || {};
    const baseUrl = integration.endpointBaseUrl || endpointConfig.baseUrl || "";
    if (!baseUrl) {
      return {
        integrationId,
        displayName,
        category,
        stage: context.phase,
        status: "skipped",
        durationMs: Date.now() - startTime,
        recordsReturned: 0,
        data: [],
        error: "No base URL configured"
      };
    }
    const url = buildRequestUrl(baseUrl, context);
    const headers = {
      "Accept": "application/json",
      "User-Agent": "AceC3-PipelineBridge/1.0"
    };
    const authMethod = integration.authMethod || authConfig.method || "none";
    const apiKey = credentials.apiKey || credentials.api_key || "";
    switch (authMethod) {
      case "api_key":
        const headerName = authConfig.headerName || "X-API-Key";
        if (apiKey) headers[headerName] = apiKey;
        break;
      case "bearer_token":
        if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
        break;
      case "basic_auth":
        const username = credentials.username || "";
        const password = credentials.password || "";
        if (username) headers["Authorization"] = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
        break;
      case "custom_header":
        if (authConfig.customHeaders) {
          Object.assign(headers, authConfig.customHeaders);
        }
        break;
    }
    const timeout = endpointConfig.timeout || 3e4;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    let response;
    try {
      response = await fetch(url, {
        method: "GET",
        headers,
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }
    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      return {
        integrationId,
        displayName,
        category,
        stage: context.phase,
        status: response.status === 429 ? "partial" : "failed",
        durationMs: Date.now() - startTime,
        recordsReturned: 0,
        data: [],
        error: `HTTP ${response.status}: ${errorText.slice(0, 200)}`
      };
    }
    const data = await response.json().catch(() => ({}));
    const records = normalizeResponseData(data, category);
    return {
      integrationId,
      displayName,
      category,
      stage: context.phase,
      status: "success",
      durationMs: Date.now() - startTime,
      recordsReturned: records.length,
      data: records
    };
  } catch (err) {
    const isTimeout = err.name === "AbortError";
    return {
      integrationId,
      displayName,
      category,
      stage: context.phase,
      status: isTimeout ? "timeout" : "failed",
      durationMs: Date.now() - startTime,
      recordsReturned: 0,
      data: [],
      error: err.message
    };
  }
}
async function executeCustomerIntegrationsForStage(context) {
  const activeIntegrations = await getActiveSourcesForStage(context.phase);
  if (activeIntegrations.length === 0) {
    return [];
  }
  console.log(`[PipelineBridge] Executing ${activeIntegrations.length} customer integration(s) for stage: ${context.phase}`);
  const results = await Promise.allSettled(
    activeIntegrations.map((integ) => executeIntegrationCall(integ, context))
  );
  const processedResults = [];
  for (const result of results) {
    if (result.status === "fulfilled") {
      processedResults.push(result.value);
    } else {
      processedResults.push({
        integrationId: "unknown",
        displayName: "Unknown",
        category: "custom",
        stage: context.phase,
        status: "failed",
        durationMs: 0,
        recordsReturned: 0,
        data: [],
        error: result.reason?.message || "Unknown error"
      });
    }
  }
  recordExecutionLogs(processedResults, context.engagementId).catch((err) => {
    console.error(`[PipelineBridge] Failed to record execution logs: ${err.message}`);
  });
  updateIntegrationStats(processedResults).catch((err) => {
    console.error(`[PipelineBridge] Failed to update integration stats: ${err.message}`);
  });
  const successCount = processedResults.filter((r) => r.status === "success").length;
  const failCount = processedResults.filter((r) => r.status === "failed" || r.status === "timeout").length;
  const totalRecords = processedResults.reduce((sum, r) => sum + r.recordsReturned, 0);
  console.log(`[PipelineBridge] Stage ${context.phase} complete: ${successCount} success, ${failCount} failed, ${totalRecords} records`);
  return processedResults;
}
function buildRequestUrl(baseUrl, context) {
  let url = baseUrl;
  url = url.replace(/\{domain\}/g, encodeURIComponent(context.targetDomain));
  url = url.replace(/\{target\}/g, encodeURIComponent(context.targetDomain));
  if (context.targetIps?.[0]) {
    url = url.replace(/\{ip\}/g, encodeURIComponent(context.targetIps[0]));
  }
  if (url === baseUrl && !url.includes("?")) {
    const separator = url.includes("?") ? "&" : "?";
    url = `${url}${separator}q=${encodeURIComponent(context.targetDomain)}`;
  }
  return url;
}
function normalizeResponseData(data, category) {
  if (Array.isArray(data)) return data;
  if (data?.results && Array.isArray(data.results)) return data.results;
  if (data?.data && Array.isArray(data.data)) return data.data;
  if (data?.items && Array.isArray(data.items)) return data.items;
  if (data?.records && Array.isArray(data.records)) return data.records;
  if (data?.hits?.hits && Array.isArray(data.hits.hits)) return data.hits.hits;
  if (data && typeof data === "object" && Object.keys(data).length > 0) return [data];
  return [];
}
async function recordExecutionLogs(results, engagementId) {
  const { createExecutionLog } = await import("./db-UCRYETLI.js");
  for (const result of results) {
    await createExecutionLog({
      integrationId: result.integrationId,
      engagementId,
      pipelineStage: result.stage,
      executionStatus: result.status,
      durationMs: result.durationMs,
      recordsReturned: result.recordsReturned,
      errorMessage: result.error || null,
      executedAt: Date.now()
    });
  }
}
async function updateIntegrationStats(results) {
  const { updateCustomerIntegration, getCustomerIntegrationByIntegrationId } = await import("./db-UCRYETLI.js");
  for (const result of results) {
    if (result.integrationId === "unknown") continue;
    try {
      const existing = await getCustomerIntegrationByIntegrationId(result.integrationId);
      if (!existing) continue;
      const totalCalls = (existing.totalCalls || 0) + 1;
      const totalErrors = (existing.totalErrors || 0) + (result.status === "failed" || result.status === "timeout" ? 1 : 0);
      const prevAvg = existing.avgLatencyMs || result.durationMs;
      const avgLatencyMs = Math.round((prevAvg * (totalCalls - 1) + result.durationMs) / totalCalls);
      await updateCustomerIntegration(result.integrationId, {
        totalCalls,
        totalErrors,
        avgLatencyMs,
        ...result.error ? { lastError: result.error } : {},
        ...result.status === "failed" || result.status === "timeout" ? { lastHealthStatus: "degraded" } : { lastHealthStatus: "healthy" }
      });
    } catch {
    }
  }
}
function mergeIntegrationResultsIntoObservations(results, existingObservations) {
  const newObservations = [];
  for (const result of results) {
    if (result.status !== "success" || result.data.length === 0) continue;
    for (const record of result.data) {
      newObservations.push({
        source: `customer:${result.integrationId}`,
        sourceDisplayName: result.displayName,
        category: result.category,
        pipelineStage: result.stage,
        timestamp: Date.now(),
        data: record,
        // Attempt to extract common fields for dedup
        hostname: record.hostname || record.domain || record.host || null,
        ip: record.ip || record.ip_address || record.address || null,
        port: record.port || null,
        assetType: inferAssetType(record),
        confidence: 0.7,
        // Customer integrations get slightly lower default confidence
        tags: [`source:${result.integrationId}`, `category:${result.category}`]
      });
    }
  }
  const existingKeys = new Set(
    existingObservations.map((o) => `${o.hostname || ""}:${o.ip || ""}:${o.port || ""}`).filter((k) => k !== "::")
  );
  const deduped = newObservations.filter((o) => {
    const key = `${o.hostname || ""}:${o.ip || ""}:${o.port || ""}`;
    if (key === "::" || !existingKeys.has(key)) {
      existingKeys.add(key);
      return true;
    }
    return false;
  });
  return [...existingObservations, ...deduped];
}
function inferAssetType(record) {
  if (record.cve || record.vulnerability || record.vuln_id) return "vulnerability";
  if (record.port || record.service) return "service";
  if (record.subdomain || record.hostname || record.domain) return "subdomain";
  if (record.ip || record.ip_address) return "ip";
  if (record.email || record.credential) return "credential";
  if (record.url || record.endpoint) return "url";
  return "unknown";
}
var init_pipeline_bridge = __esm({
  "server/lib/integration-registry/pipeline-bridge.ts"() {
  }
});

export {
  getActiveSourcesForStage,
  executeCustomerIntegrationsForStage,
  mergeIntegrationResultsIntoObservations,
  init_pipeline_bridge
};
