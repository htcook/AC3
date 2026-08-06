/**
 * Pipeline Integration Bridge
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * Connects approved/active customer integrations into the live engagement
 * orchestrator pipeline. Each pipeline phase calls `getActiveSourcesForStage()`
 * to discover which customer-added integrations should execute alongside
 * built-in connectors.
 * 
 * The bridge handles:
 *   - Fetching active integrations for a given pipeline stage from DB
 *   - Executing each integration's API call with proper auth/headers
 *   - Normalizing results into the standard pipeline data format
 *   - Recording execution logs for audit and health tracking
 *   - Respecting rate limits and timeouts per integration
 *   - Graceful degradation: integration failures don't block the pipeline
 */

import type { IntegrationCategory, PipelineStage } from "./types";

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface PipelineIntegrationResult {
  integrationId: string;
  displayName: string;
  category: IntegrationCategory;
  stage: PipelineStage;
  status: "success" | "partial" | "failed" | "timeout" | "skipped";
  durationMs: number;
  recordsReturned: number;
  data: any[];
  error?: string;
}

export interface PipelineExecutionContext {
  engagementId: number;
  targetDomain: string;
  targetIps?: string[];
  assets?: Array<{ hostname: string; ip?: string; assetType?: string }>;
  phase: PipelineStage;
  /** Additional context from previous phases */
  previousResults?: Record<string, any>;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — FETCH ACTIVE INTEGRATIONS FOR A STAGE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Get all active customer integrations that should execute for a given pipeline stage.
 * Returns integration definitions with their credentials.
 */
export async function getActiveSourcesForStage(stage: PipelineStage): Promise<any[]> {
  try {
    const { getActiveCustomerIntegrationsByStage } = await import("../../db");
    return getActiveCustomerIntegrationsByStage(stage);
  } catch (err: any) {
    console.error(`[PipelineBridge] Failed to fetch active sources for stage ${stage}: ${err.message}`);
    return [];
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — EXECUTE INTEGRATION API CALL
// ═══════════════════════════════════════════════════════════════════════

/**
 * Execute a single customer integration's API call for a pipeline stage.
 * Handles auth injection, timeout, rate limiting, and error handling.
 */
async function executeIntegrationCall(
  integration: any,
  context: PipelineExecutionContext,
): Promise<PipelineIntegrationResult> {
  const startTime = Date.now();
  const integrationId = integration.integrationId;
  const displayName = integration.displayName;
  const category = integration.category as IntegrationCategory;

  try {
    const endpointConfig = integration.endpointConfig || {};
    const authConfig = integration.authConfig || {};
    const credentials = integration.credentials || {};
    const baseUrl = integration.endpointBaseUrl || endpointConfig.baseUrl || "";

    if (!baseUrl) {
      return {
        integrationId, displayName, category, stage: context.phase,
        status: "skipped", durationMs: Date.now() - startTime,
        recordsReturned: 0, data: [],
        error: "No base URL configured",
      };
    }

    // Build request URL with target context
    const url = buildRequestUrl(baseUrl, context);

    // Build headers with auth injection
    const headers: Record<string, string> = {
      "Accept": "application/json",
      "User-Agent": "AceC3-PipelineBridge/1.0",
    };

    // Inject authentication
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

    // Execute with timeout
    const timeout = endpointConfig.timeout || 30_000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    let response: Response;
    try {
      response = await fetch(url, {
        method: "GET",
        headers,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      return {
        integrationId, displayName, category, stage: context.phase,
        status: response.status === 429 ? "partial" : "failed",
        durationMs: Date.now() - startTime,
        recordsReturned: 0, data: [],
        error: `HTTP ${response.status}: ${errorText.slice(0, 200)}`,
      };
    }

    const data = await response.json().catch(() => ({}));
    const records = normalizeResponseData(data, category);

    return {
      integrationId, displayName, category, stage: context.phase,
      status: "success",
      durationMs: Date.now() - startTime,
      recordsReturned: records.length,
      data: records,
    };

  } catch (err: any) {
    const isTimeout = err.name === "AbortError";
    return {
      integrationId, displayName, category, stage: context.phase,
      status: isTimeout ? "timeout" : "failed",
      durationMs: Date.now() - startTime,
      recordsReturned: 0, data: [],
      error: err.message,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — EXECUTE ALL INTEGRATIONS FOR A PIPELINE STAGE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Execute all active customer integrations for a given pipeline stage.
 * Runs integrations in parallel with individual timeouts.
 * Records execution logs for audit.
 * Returns aggregated results — failures are logged but don't block the pipeline.
 */
export async function executeCustomerIntegrationsForStage(
  context: PipelineExecutionContext,
): Promise<PipelineIntegrationResult[]> {
  const activeIntegrations = await getActiveSourcesForStage(context.phase);

  if (activeIntegrations.length === 0) {
    return [];
  }

  console.log(`[PipelineBridge] Executing ${activeIntegrations.length} customer integration(s) for stage: ${context.phase}`);

  // Execute all integrations in parallel
  const results = await Promise.allSettled(
    activeIntegrations.map(integ => executeIntegrationCall(integ, context))
  );

  const processedResults: PipelineIntegrationResult[] = [];

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
        error: result.reason?.message || "Unknown error",
      });
    }
  }

  // Record execution logs (fire and forget)
  recordExecutionLogs(processedResults, context.engagementId).catch(err => {
    console.error(`[PipelineBridge] Failed to record execution logs: ${err.message}`);
  });

  // Update integration health stats (fire and forget)
  updateIntegrationStats(processedResults).catch(err => {
    console.error(`[PipelineBridge] Failed to update integration stats: ${err.message}`);
  });

  const successCount = processedResults.filter(r => r.status === "success").length;
  const failCount = processedResults.filter(r => r.status === "failed" || r.status === "timeout").length;
  const totalRecords = processedResults.reduce((sum, r) => sum + r.recordsReturned, 0);

  console.log(`[PipelineBridge] Stage ${context.phase} complete: ${successCount} success, ${failCount} failed, ${totalRecords} records`);

  return processedResults;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — HELPERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build the request URL by injecting target context into the base URL.
 * Supports common patterns: {domain}, {ip}, {target}
 */
function buildRequestUrl(baseUrl: string, context: PipelineExecutionContext): string {
  let url = baseUrl;
  url = url.replace(/\{domain\}/g, encodeURIComponent(context.targetDomain));
  url = url.replace(/\{target\}/g, encodeURIComponent(context.targetDomain));
  if (context.targetIps?.[0]) {
    url = url.replace(/\{ip\}/g, encodeURIComponent(context.targetIps[0]));
  }

  // If URL doesn't contain any template variables, append domain as query param
  if (url === baseUrl && !url.includes("?")) {
    const separator = url.includes("?") ? "&" : "?";
    url = `${url}${separator}q=${encodeURIComponent(context.targetDomain)}`;
  }

  return url;
}

/**
 * Normalize API response data into a standard array format.
 * Different categories return different data shapes — normalize them.
 */
function normalizeResponseData(data: any, category: IntegrationCategory): any[] {
  if (Array.isArray(data)) return data;
  if (data?.results && Array.isArray(data.results)) return data.results;
  if (data?.data && Array.isArray(data.data)) return data.data;
  if (data?.items && Array.isArray(data.items)) return data.items;
  if (data?.records && Array.isArray(data.records)) return data.records;
  if (data?.hits?.hits && Array.isArray(data.hits.hits)) return data.hits.hits;
  // Single object response — wrap in array
  if (data && typeof data === "object" && Object.keys(data).length > 0) return [data];
  return [];
}

/**
 * Record execution logs to the DB for audit trail.
 */
async function recordExecutionLogs(
  results: PipelineIntegrationResult[],
  engagementId: number,
): Promise<void> {
  const { createExecutionLog } = await import("../../db");
  for (const result of results) {
    await createExecutionLog({
      integrationId: result.integrationId,
      engagementId,
      pipelineStage: result.stage,
      executionStatus: result.status,
      durationMs: result.durationMs,
      recordsReturned: result.recordsReturned,
      errorMessage: result.error || null,
      executedAt: Date.now(),
    });
  }
}

/**
 * Update integration health stats in the DB.
 */
async function updateIntegrationStats(results: PipelineIntegrationResult[]): Promise<void> {
  const { updateCustomerIntegration, getCustomerIntegrationByIntegrationId } = await import("../../db");
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
        ...(result.error ? { lastError: result.error } : {}),
        ...(result.status === "failed" || result.status === "timeout"
          ? { lastHealthStatus: "degraded" as any }
          : { lastHealthStatus: "healthy" as any }),
      });
    } catch { /* non-fatal */ }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — MERGE CUSTOMER RESULTS INTO PIPELINE DATA
// ═══════════════════════════════════════════════════════════════════════

/**
 * Merge customer integration results into the standard pipeline observations.
 * Called by the engagement orchestrator after each phase to enrich the data.
 */
export function mergeIntegrationResultsIntoObservations(
  results: PipelineIntegrationResult[],
  existingObservations: any[],
): any[] {
  const newObservations: any[] = [];

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
        confidence: 0.7, // Customer integrations get slightly lower default confidence
        tags: [`source:${result.integrationId}`, `category:${result.category}`],
      });
    }
  }

  // Deduplicate against existing observations
  const existingKeys = new Set(
    existingObservations.map(o => `${o.hostname || ""}:${o.ip || ""}:${o.port || ""}`).filter(k => k !== "::")
  );

  const deduped = newObservations.filter(o => {
    const key = `${o.hostname || ""}:${o.ip || ""}:${o.port || ""}`;
    if (key === "::" || !existingKeys.has(key)) {
      existingKeys.add(key);
      return true;
    }
    return false;
  });

  return [...existingObservations, ...deduped];
}

/**
 * Infer asset type from a data record.
 */
function inferAssetType(record: any): string {
  if (record.cve || record.vulnerability || record.vuln_id) return "vulnerability";
  if (record.port || record.service) return "service";
  if (record.subdomain || record.hostname || record.domain) return "subdomain";
  if (record.ip || record.ip_address) return "ip";
  if (record.email || record.credential) return "credential";
  if (record.url || record.endpoint) return "url";
  return "unknown";
}
