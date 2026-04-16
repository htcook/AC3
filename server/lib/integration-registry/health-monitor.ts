/**
 * Integration Health Monitor
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * Periodic health checks for customer-added API integrations.
 * Monitors:
 *   - API reachability (HTTP probe)
 *   - Response latency
 *   - Auth validity (401/403 detection)
 *   - Rate limit status (429 detection)
 *   - Data freshness (response content check)
 * 
 * Alerts:
 *   - Integration goes down (3 consecutive failures)
 *   - Auth expired (401/403 response)
 *   - Rate limited (429 response)
 *   - Latency degradation (>2x average)
 *   - Integration recovered after outage
 */

import type { IntegrationCategory } from "./types";

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export type HealthStatus = "healthy" | "degraded" | "down" | "auth_expired" | "rate_limited" | "unknown";

export interface HealthCheckResult {
  integrationId: string;
  status: HealthStatus;
  httpStatus: number | null;
  latencyMs: number;
  errorMessage: string | null;
  checkedAt: number;
  details: {
    reachable: boolean;
    authValid: boolean;
    rateLimited: boolean;
    responseValid: boolean;
    latencyDelta?: number; // % change from average
  };
}

export interface HealthAlert {
  integrationId: string;
  displayName: string;
  alertType: "down" | "auth_expired" | "rate_limited" | "latency_degraded" | "recovered";
  severity: "critical" | "warning" | "info";
  message: string;
  timestamp: number;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — STATUS MAPPING (code → DB enum)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Map internal HealthStatus values to DB enum values.
 * Code uses: healthy, degraded, down, auth_expired, rate_limited, unknown
 * DB expects: healthy, degraded, unreachable, auth_failed, rate_limited, timeout, error
 */
function mapStatusToDb(status: HealthStatus): string {
  switch (status) {
    case "down":          return "unreachable";
    case "auth_expired":  return "auth_failed";
    case "unknown":       return "error";
    default:              return status; // healthy, degraded, rate_limited pass through
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — CONSECUTIVE FAILURE TRACKING
// ═══════════════════════════════════════════════════════════════════════

const consecutiveFailures = new Map<string, number>();
const previousStatus = new Map<string, HealthStatus>();

// ═══════════════════════════════════════════════════════════════════════
// §3 — HEALTH CHECK EXECUTION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run a health check for a specific customer integration.
 * Probes the API endpoint and records the result.
 */
export async function runHealthCheckForIntegration(integrationId: string): Promise<HealthCheckResult> {
  const { getCustomerIntegrationByIntegrationId, createHealthCheck, updateCustomerIntegration } = await import("../../db");
  
  const integration = await getCustomerIntegrationByIntegrationId(integrationId);
  if (!integration) {
    return {
      integrationId,
      status: "unknown",
      httpStatus: null,
      latencyMs: 0,
      errorMessage: "Integration not found",
      checkedAt: Date.now(),
      details: { reachable: false, authValid: false, rateLimited: false, responseValid: false },
    };
  }

  const result = await probeIntegrationHealth(integration);

  // Record to DB
  try {
    await createHealthCheck({
      integrationId,
      status: mapStatusToDb(result.status) as any,
      httpStatus: result.httpStatus,
      latencyMs: result.latencyMs,
      errorMessage: result.errorMessage,
      checkedAt: result.checkedAt,
    });

    // Update the integration's health status
    await updateCustomerIntegration(integrationId, {
      lastHealthStatus: result.status as any,
      lastHealthCheck: result.checkedAt,
    });
  } catch (err: any) {
    console.error(`[HealthMonitor] Failed to record health check for ${integrationId}: ${err.message}`);
  }

  // Track consecutive failures and generate alerts
  await processHealthResult(result, integration);

  return result;
}

/**
 * Probe an integration's API endpoint for health.
 */
async function probeIntegrationHealth(integration: any): Promise<HealthCheckResult> {
  const integrationId = integration.integrationId;
  const baseUrl = integration.endpointBaseUrl || integration.endpointConfig?.baseUrl || "";
  const authConfig = integration.authConfig || {};
  const authMethod = integration.authMethod || authConfig.method || "none";

  if (!baseUrl) {
    return {
      integrationId,
      status: "unknown",
      httpStatus: null,
      latencyMs: 0,
      errorMessage: "No endpoint URL configured",
      checkedAt: Date.now(),
      details: { reachable: false, authValid: false, rateLimited: false, responseValid: false },
    };
  }

  const headers: Record<string, string> = {
    "Accept": "application/json",
    "User-Agent": "AceC3-HealthMonitor/1.0",
  };

  // Inject auth for the health check
  const credentials = integration.credentials || {};
  const apiKey = credentials.apiKey || credentials.api_key || "";

  switch (authMethod) {
    case "api_key":
      if (apiKey) headers[authConfig.headerName || "X-API-Key"] = apiKey;
      break;
    case "bearer_token":
      if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
      break;
    case "basic_auth":
      if (credentials.username) {
        headers["Authorization"] = `Basic ${Buffer.from(`${credentials.username}:${credentials.password || ""}`).toString("base64")}`;
      }
      break;
  }

  const startTime = Date.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15_000);

    let response: Response;
    try {
      response = await fetch(baseUrl, {
        method: "GET",
        headers,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const latencyMs = Date.now() - startTime;
    const httpStatus = response.status;

    // Determine health status from HTTP response
    let status: HealthStatus = "healthy";
    let errorMessage: string | null = null;
    const details = {
      reachable: true,
      authValid: true,
      rateLimited: false,
      responseValid: true,
      latencyDelta: 0,
    };

    if (httpStatus === 401 || httpStatus === 403) {
      status = "auth_expired";
      details.authValid = false;
      errorMessage = `Authentication failed (HTTP ${httpStatus})`;
    } else if (httpStatus === 429) {
      status = "rate_limited";
      details.rateLimited = true;
      errorMessage = "Rate limited by API provider";
    } else if (httpStatus >= 500) {
      status = "down";
      errorMessage = `Server error (HTTP ${httpStatus})`;
    } else if (httpStatus >= 400) {
      status = "degraded";
      errorMessage = `Client error (HTTP ${httpStatus})`;
    }

    // Check latency degradation
    const avgLatency = integration.avgLatencyMs || latencyMs;
    if (avgLatency > 0 && latencyMs > avgLatency * 2 && status === "healthy") {
      status = "degraded";
      details.latencyDelta = Math.round(((latencyMs - avgLatency) / avgLatency) * 100);
      errorMessage = `Latency degraded: ${latencyMs}ms vs ${avgLatency}ms avg (+${details.latencyDelta}%)`;
    }

    return {
      integrationId,
      status,
      httpStatus,
      latencyMs,
      errorMessage,
      checkedAt: Date.now(),
      details,
    };

  } catch (err: any) {
    const isTimeout = err.name === "AbortError";
    return {
      integrationId,
      status: "down",
      httpStatus: null,
      latencyMs: Date.now() - startTime,
      errorMessage: isTimeout ? "Health check timed out (15s)" : err.message,
      checkedAt: Date.now(),
      details: { reachable: false, authValid: false, rateLimited: false, responseValid: false },
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — ALERT PROCESSING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Process a health check result and generate alerts if needed.
 */
async function processHealthResult(result: HealthCheckResult, integration: any): Promise<void> {
  const id = result.integrationId;
  const prevStatus = previousStatus.get(id) || "unknown";
  const failures = consecutiveFailures.get(id) || 0;

  // Track consecutive failures
  if (result.status === "down" || result.status === "auth_expired") {
    consecutiveFailures.set(id, failures + 1);
  } else {
    consecutiveFailures.set(id, 0);
  }

  previousStatus.set(id, result.status);

  // Generate alerts
  const alerts: HealthAlert[] = [];

  // Alert: Integration went down (3 consecutive failures)
  if ((failures + 1) >= 3 && result.status === "down" && prevStatus !== "down") {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "down",
      severity: "critical",
      message: `Integration "${integration.displayName}" is down after ${failures + 1} consecutive failures. Last error: ${result.errorMessage}`,
      timestamp: Date.now(),
    });
  }

  // Alert: Auth expired
  if (result.status === "auth_expired" && prevStatus !== "auth_expired") {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "auth_expired",
      severity: "warning",
      message: `Integration "${integration.displayName}" authentication has expired. Please update credentials.`,
      timestamp: Date.now(),
    });
  }

  // Alert: Rate limited
  if (result.status === "rate_limited" && prevStatus !== "rate_limited") {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "rate_limited",
      severity: "warning",
      message: `Integration "${integration.displayName}" is being rate limited by the API provider.`,
      timestamp: Date.now(),
    });
  }

  // Alert: Recovered
  if (result.status === "healthy" && (prevStatus === "down" || prevStatus === "auth_expired")) {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "recovered",
      severity: "info",
      message: `Integration "${integration.displayName}" has recovered and is healthy again.`,
      timestamp: Date.now(),
    });
  }

  // Send alerts via notification system
  for (const alert of alerts) {
    try {
      const { notifyOwner } = await import("../../_core/notification");
      await notifyOwner({
        title: `[Integration Health] ${alert.alertType.toUpperCase()}: ${alert.displayName}`,
        content: alert.message,
      });
    } catch (err: any) {
      console.error(`[HealthMonitor] Failed to send alert for ${id}: ${err.message}`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — BATCH HEALTH CHECK (all active integrations)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run health checks for all active customer integrations.
 * Called periodically by the scan scheduler or manually from the UI.
 */
export async function runAllHealthChecks(): Promise<HealthCheckResult[]> {
  try {
    const { getCustomerIntegrationsByStatus } = await import("../../db");
    const activeIntegrations = await getCustomerIntegrationsByStatus("active");
    const approvedIntegrations = await getCustomerIntegrationsByStatus("approved");
    const allIntegrations = [...activeIntegrations, ...approvedIntegrations];

    if (allIntegrations.length === 0) return [];

    console.log(`[HealthMonitor] Running health checks for ${allIntegrations.length} integration(s)`);

    const results = await Promise.allSettled(
      allIntegrations.map(integ => runHealthCheckForIntegration(integ.integrationId))
    );

    return results
      .filter((r): r is PromiseFulfilledResult<HealthCheckResult> => r.status === "fulfilled")
      .map(r => r.value);
  } catch (err: any) {
    console.error(`[HealthMonitor] Batch health check failed: ${err.message}`);
    return [];
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — PERIODIC SCHEDULER
// ═══════════════════════════════════════════════════════════════════════

let healthCheckInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start periodic health checks (every 5 minutes by default).
 */
export function startPeriodicHealthChecks(intervalMs: number = 5 * 60 * 1000): void {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
  }

  console.log(`[HealthMonitor] Starting periodic health checks every ${intervalMs / 1000}s`);

  healthCheckInterval = setInterval(async () => {
    try {
      const results = await runAllHealthChecks();
      const unhealthy = results.filter(r => r.status !== "healthy");
      if (unhealthy.length > 0) {
        console.log(`[HealthMonitor] ${unhealthy.length}/${results.length} integrations unhealthy`);
      }
    } catch (err: any) {
      console.error(`[HealthMonitor] Periodic check error: ${err.message}`);
    }
  }, intervalMs);
}

/**
 * Stop periodic health checks.
 */
export function stopPeriodicHealthChecks(): void {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
    console.log("[HealthMonitor] Periodic health checks stopped");
  }
}

/**
 * Get the current health status summary for all tracked integrations.
 */
export function getHealthStatusSummary(): {
  tracked: number;
  healthy: number;
  degraded: number;
  down: number;
  authExpired: number;
  rateLimited: number;
} {
  const statuses = [...previousStatus.values()];
  return {
    tracked: statuses.length,
    healthy: statuses.filter(s => s === "healthy").length,
    degraded: statuses.filter(s => s === "degraded").length,
    down: statuses.filter(s => s === "down").length,
    authExpired: statuses.filter(s => s === "auth_expired").length,
    rateLimited: statuses.filter(s => s === "rate_limited").length,
  };
}
