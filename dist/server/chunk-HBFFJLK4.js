// server/lib/integration-registry/health-monitor.ts
function mapStatusToDb(status) {
  switch (status) {
    case "down":
      return "unreachable";
    case "auth_expired":
      return "auth_failed";
    case "unknown":
      return "error";
    default:
      return status;
  }
}
function mapStatusToIntegrationDb(status) {
  switch (status) {
    case "down":
      return "unreachable";
    case "auth_expired":
      return "auth_failed";
    case "rate_limited":
      return "degraded";
    // closest match in narrower enum
    case "unknown":
      return "unknown";
    // keep as unknown (not 'error')
    default:
      return status;
  }
}
var consecutiveFailures = /* @__PURE__ */ new Map();
var previousStatus = /* @__PURE__ */ new Map();
async function runHealthCheckForIntegration(integrationId) {
  const { getCustomerIntegrationByIntegrationId, createHealthCheck, updateCustomerIntegration } = await import("./db-EEYUM2OC.js");
  const integration = await getCustomerIntegrationByIntegrationId(integrationId);
  if (!integration) {
    return {
      integrationId,
      status: "unknown",
      httpStatus: null,
      latencyMs: 0,
      errorMessage: "Integration not found",
      checkedAt: Date.now(),
      details: { reachable: false, authValid: false, rateLimited: false, responseValid: false }
    };
  }
  const result = await probeIntegrationHealth(integration);
  try {
    await createHealthCheck({
      integrationId,
      status: mapStatusToDb(result.status),
      httpStatus: result.httpStatus,
      latencyMs: result.latencyMs,
      errorMessage: result.errorMessage,
      checkedAt: result.checkedAt
    });
    await updateCustomerIntegration(integrationId, {
      lastHealthStatus: mapStatusToIntegrationDb(result.status),
      lastHealthCheck: result.checkedAt
    });
  } catch (err) {
    console.error(`[HealthMonitor] Failed to record health check for ${integrationId}: ${err.message}`);
  }
  await processHealthResult(result, integration);
  return result;
}
async function probeIntegrationHealth(integration) {
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
      details: { reachable: false, authValid: false, rateLimited: false, responseValid: false }
    };
  }
  const headers = {
    "Accept": "application/json",
    "User-Agent": "AceC3-HealthMonitor/1.0"
  };
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
    const timeoutId = setTimeout(() => controller.abort(), 15e3);
    let response;
    try {
      response = await fetch(baseUrl, {
        method: "GET",
        headers,
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeoutId);
    }
    const latencyMs = Date.now() - startTime;
    const httpStatus = response.status;
    let status = "healthy";
    let errorMessage = null;
    const details = {
      reachable: true,
      authValid: true,
      rateLimited: false,
      responseValid: true,
      latencyDelta: 0
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
    const avgLatency = integration.avgLatencyMs || latencyMs;
    if (avgLatency > 0 && latencyMs > avgLatency * 2 && status === "healthy") {
      status = "degraded";
      details.latencyDelta = Math.round((latencyMs - avgLatency) / avgLatency * 100);
      errorMessage = `Latency degraded: ${latencyMs}ms vs ${avgLatency}ms avg (+${details.latencyDelta}%)`;
    }
    return {
      integrationId,
      status,
      httpStatus,
      latencyMs,
      errorMessage,
      checkedAt: Date.now(),
      details
    };
  } catch (err) {
    const isTimeout = err.name === "AbortError";
    return {
      integrationId,
      status: "down",
      httpStatus: null,
      latencyMs: Date.now() - startTime,
      errorMessage: isTimeout ? "Health check timed out (15s)" : err.message,
      checkedAt: Date.now(),
      details: { reachable: false, authValid: false, rateLimited: false, responseValid: false }
    };
  }
}
async function processHealthResult(result, integration) {
  const id = result.integrationId;
  const prevStatus = previousStatus.get(id) || "unknown";
  const failures = consecutiveFailures.get(id) || 0;
  if (result.status === "down" || result.status === "auth_expired") {
    consecutiveFailures.set(id, failures + 1);
  } else {
    consecutiveFailures.set(id, 0);
  }
  previousStatus.set(id, result.status);
  const alerts = [];
  if (failures + 1 >= 3 && result.status === "down" && prevStatus !== "down") {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "down",
      severity: "critical",
      message: `Integration "${integration.displayName}" is down after ${failures + 1} consecutive failures. Last error: ${result.errorMessage}`,
      timestamp: Date.now()
    });
  }
  if (result.status === "auth_expired" && prevStatus !== "auth_expired") {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "auth_expired",
      severity: "warning",
      message: `Integration "${integration.displayName}" authentication has expired. Please update credentials.`,
      timestamp: Date.now()
    });
  }
  if (result.status === "rate_limited" && prevStatus !== "rate_limited") {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "rate_limited",
      severity: "warning",
      message: `Integration "${integration.displayName}" is being rate limited by the API provider.`,
      timestamp: Date.now()
    });
  }
  if (result.status === "healthy" && (prevStatus === "down" || prevStatus === "auth_expired")) {
    alerts.push({
      integrationId: id,
      displayName: integration.displayName || id,
      alertType: "recovered",
      severity: "info",
      message: `Integration "${integration.displayName}" has recovered and is healthy again.`,
      timestamp: Date.now()
    });
  }
  for (const alert of alerts) {
    try {
      const { notifyOwner } = await import("./notification-4RFY3TAD.js");
      await notifyOwner({
        title: `[Integration Health] ${alert.alertType.toUpperCase()}: ${alert.displayName}`,
        content: alert.message
      });
    } catch (err) {
      console.error(`[HealthMonitor] Failed to send alert for ${id}: ${err.message}`);
    }
  }
}
async function runAllHealthChecks() {
  try {
    const { getCustomerIntegrationsByStatus } = await import("./db-EEYUM2OC.js");
    const activeIntegrations = await getCustomerIntegrationsByStatus("active");
    const approvedIntegrations = await getCustomerIntegrationsByStatus("approved");
    const allIntegrations = [...activeIntegrations, ...approvedIntegrations];
    if (allIntegrations.length === 0) return [];
    console.log(`[HealthMonitor] Running health checks for ${allIntegrations.length} integration(s)`);
    const results = await Promise.allSettled(
      allIntegrations.map((integ) => runHealthCheckForIntegration(integ.integrationId))
    );
    return results.filter((r) => r.status === "fulfilled").map((r) => r.value);
  } catch (err) {
    console.error(`[HealthMonitor] Batch health check failed: ${err.message}`);
    return [];
  }
}
var healthCheckInterval = null;
function startPeriodicHealthChecks(intervalMs = 5 * 60 * 1e3) {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
  }
  console.log(`[HealthMonitor] Starting periodic health checks every ${intervalMs / 1e3}s`);
  healthCheckInterval = setInterval(async () => {
    try {
      const results = await runAllHealthChecks();
      const unhealthy = results.filter((r) => r.status !== "healthy");
      if (unhealthy.length > 0) {
        console.log(`[HealthMonitor] ${unhealthy.length}/${results.length} integrations unhealthy`);
      }
    } catch (err) {
      console.error(`[HealthMonitor] Periodic check error: ${err.message}`);
    }
  }, intervalMs);
}
function stopPeriodicHealthChecks() {
  if (healthCheckInterval) {
    clearInterval(healthCheckInterval);
    healthCheckInterval = null;
    console.log("[HealthMonitor] Periodic health checks stopped");
  }
}
function getHealthStatusSummary() {
  const statuses = [...previousStatus.values()];
  return {
    tracked: statuses.length,
    healthy: statuses.filter((s) => s === "healthy").length,
    degraded: statuses.filter((s) => s === "degraded").length,
    down: statuses.filter((s) => s === "down").length,
    authExpired: statuses.filter((s) => s === "auth_expired").length,
    rateLimited: statuses.filter((s) => s === "rate_limited").length
  };
}

export {
  runHealthCheckForIntegration,
  runAllHealthChecks,
  startPeriodicHealthChecks,
  stopPeriodicHealthChecks,
  getHealthStatusSummary
};
