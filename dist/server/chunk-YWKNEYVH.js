import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/api-resilience.ts
function classifyError(err, service) {
  const timestamp = Date.now();
  const message = err?.message || String(err);
  const statusCode = err?.status || err?.statusCode || err?.response?.status;
  if (statusCode === 401 || statusCode === 403 || message.includes("401") || message.includes("Unauthorized") || message.includes("Forbidden")) {
    return { category: "auth_failure", message, statusCode, retryable: false, service, timestamp };
  }
  if (statusCode === 429 || message.includes("429") || message.includes("rate limit") || message.includes("Too Many Requests")) {
    return { category: "rate_limited", message, statusCode, retryable: true, service, timestamp };
  }
  if (message.includes("timeout") || message.includes("ETIMEDOUT") || message.includes("AbortError") || message.includes("aborted") || message.includes("timed out") || err?.name === "AbortError" || err?.name === "TimeoutError") {
    return { category: "timeout", message, statusCode: void 0, retryable: true, service, timestamp };
  }
  if (message.includes("ECONNREFUSED") || message.includes("ENOTFOUND") || message.includes("ENETUNREACH") || message.includes("fetch failed") || message.includes("network")) {
    return { category: "network_error", message, statusCode: void 0, retryable: true, service, timestamp };
  }
  if (message.includes("not configured") || message.includes("API key not") || message.includes("missing key")) {
    return { category: "not_configured", message, statusCode: void 0, retryable: false, service, timestamp };
  }
  if (message.includes("JSON") || message.includes("parse") || message.includes("Unexpected token")) {
    return { category: "parse_error", message, statusCode, retryable: false, service, timestamp };
  }
  if (statusCode && statusCode >= 500) {
    return { category: "api_error", message, statusCode, retryable: true, service, timestamp };
  }
  return { category: "unknown", message, statusCode, retryable: true, service, timestamp };
}
function getCircuit(service) {
  if (!circuits.has(service)) {
    circuits.set(service, {
      state: "closed",
      failures: 0,
      lastFailureAt: 0,
      lastSuccessAt: 0,
      halfOpenAttempts: 0,
      recentErrors: []
    });
  }
  return circuits.get(service);
}
function recordSuccess(service) {
  const circuit = getCircuit(service);
  circuit.state = "closed";
  circuit.failures = 0;
  circuit.halfOpenAttempts = 0;
  circuit.lastSuccessAt = Date.now();
}
function recordFailure(service, error, config = DEFAULT_CB_CONFIG) {
  const circuit = getCircuit(service);
  circuit.failures++;
  circuit.lastFailureAt = Date.now();
  circuit.recentErrors.push(error);
  if (circuit.recentErrors.length > 10) {
    circuit.recentErrors = circuit.recentErrors.slice(-10);
  }
  if (error.category === "auth_failure" || error.category === "not_configured") {
    circuit.state = "open";
    circuit.failures = config.failureThreshold;
  } else if (circuit.failures >= config.failureThreshold) {
    circuit.state = "open";
  }
}
function shouldAllowRequest(service, config = DEFAULT_CB_CONFIG) {
  const circuit = getCircuit(service);
  if (circuit.state === "closed") {
    return { allowed: true };
  }
  if (circuit.state === "open") {
    const elapsed = Date.now() - circuit.lastFailureAt;
    if (elapsed >= config.resetTimeoutMs) {
      circuit.state = "half_open";
      circuit.halfOpenAttempts = 0;
      return { allowed: true, reason: "half_open_probe" };
    }
    const remainingMs = config.resetTimeoutMs - elapsed;
    return { allowed: false, reason: `Circuit open for ${service} \u2014 ${Math.ceil(remainingMs / 1e3)}s until retry` };
  }
  if (circuit.halfOpenAttempts < config.halfOpenMaxAttempts) {
    circuit.halfOpenAttempts++;
    return { allowed: true, reason: "half_open_probe" };
  }
  return { allowed: false, reason: `Circuit half-open limit reached for ${service}` };
}
async function resilientCall(fn, options) {
  const { service, timeoutMs = 15e3, circuitBreakerConfig = DEFAULT_CB_CONFIG, retries = 0, retryDelayMs = 1e3 } = options;
  const circuit = getCircuit(service);
  const check = shouldAllowRequest(service, circuitBreakerConfig);
  if (!check.allowed) {
    return {
      success: false,
      error: { category: "circuit_open", message: check.reason || "Circuit breaker open", retryable: false, service, timestamp: Date.now() },
      durationMs: 0,
      circuitState: circuit.state,
      attempt: 0
    };
  }
  let lastError;
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    const start = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const data = await Promise.race([
        fn(controller.signal),
        new Promise((_, reject) => {
          const t = setTimeout(() => {
            controller.abort();
            reject(new Error(`Request to ${service} timed out after ${timeoutMs}ms`));
          }, timeoutMs);
          controller._raceTimer = t;
        })
      ]);
      clearTimeout(timer);
      if (controller._raceTimer) clearTimeout(controller._raceTimer);
      recordSuccess(service);
      return {
        success: true,
        data,
        durationMs: Date.now() - start,
        circuitState: getCircuit(service).state,
        attempt
      };
    } catch (err) {
      clearTimeout(timer);
      lastError = classifyError(err, service);
      recordFailure(service, lastError, circuitBreakerConfig);
      if (!lastError.retryable || attempt > retries) {
        return {
          success: false,
          error: lastError,
          durationMs: Date.now() - start,
          circuitState: getCircuit(service).state,
          attempt
        };
      }
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs * attempt));
    }
  }
  return {
    success: false,
    error: lastError || { category: "unknown", message: "Exhausted retries", retryable: false, service, timestamp: Date.now() },
    durationMs: 0,
    circuitState: getCircuit(service).state,
    attempt: retries + 1
  };
}
function trackCall(service, success) {
  if (!callCounts.has(service)) {
    callCounts.set(service, { total: 0, successes: 0 });
  }
  const counts = callCounts.get(service);
  counts.total++;
  if (success) counts.successes++;
}
function getServiceHealth(service) {
  const circuit = getCircuit(service);
  const counts = callCounts.get(service);
  let status = "unknown";
  if (circuit.state === "open") {
    status = "down";
  } else if (circuit.state === "half_open") {
    status = "degraded";
  } else if (circuit.failures > 0) {
    status = "degraded";
  } else if (circuit.lastSuccessAt > 0) {
    status = "healthy";
  }
  const hasAuthFailure = circuit.recentErrors.some((e) => e.category === "auth_failure" || e.category === "not_configured");
  if (hasAuthFailure && circuit.lastSuccessAt === 0) {
    status = "not_configured";
  }
  const uptime = counts && counts.total > 0 ? `${(counts.successes / counts.total * 100).toFixed(1)}%` : "N/A";
  return {
    service,
    status,
    circuitState: circuit.state,
    lastSuccessAt: circuit.lastSuccessAt || null,
    lastFailureAt: circuit.lastFailureAt || null,
    recentFailures: circuit.failures,
    recentErrors: circuit.recentErrors.slice(-5),
    uptime
  };
}
function getAllServiceHealth() {
  return TRACKED_SERVICES.map((s) => getServiceHealth(s));
}
function getHealthSummary() {
  const health = getAllServiceHealth();
  const healthy = health.filter((h) => h.status === "healthy").length;
  const degraded = health.filter((h) => h.status === "degraded").length;
  const down = health.filter((h) => h.status === "down").length;
  const notConfigured = health.filter((h) => h.status === "not_configured").length;
  const unknown = health.filter((h) => h.status === "unknown").length;
  let overallStatus = "healthy";
  if (down > 3 || degraded > 5) overallStatus = "critical";
  else if (down > 0 || degraded > 2) overallStatus = "degraded";
  return {
    totalServices: health.length,
    healthy,
    degraded,
    down,
    notConfigured,
    unknown,
    overallStatus
  };
}
async function runStageWithFallback(stageName, fn, fallback, options) {
  const start = Date.now();
  const timeoutMs = options?.timeoutMs || 6e4;
  try {
    const result = await Promise.race([
      fn(),
      new Promise(
        (_, reject) => setTimeout(() => reject(new Error(`Stage ${stageName} timed out after ${timeoutMs}ms`)), timeoutMs)
      )
    ]);
    return {
      stageName,
      success: true,
      data: result,
      durationMs: Date.now() - start,
      skipped: false
    };
  } catch (err) {
    const classified = classifyError(err, stageName);
    console.error(`[Pipeline] Stage "${stageName}" failed (${classified.category}): ${classified.message}`);
    return {
      stageName,
      success: false,
      data: fallback,
      error: classified.message,
      errorCategory: classified.category,
      durationMs: Date.now() - start,
      skipped: false
    };
  }
}
function isRetryableError(err) {
  const message = err?.message || String(err);
  const statusCode = err?.status || err?.statusCode || err?.response?.status;
  if (statusCode === 429 || message.includes("429") || message.includes("rate limit") || message.includes("Too Many Requests")) {
    return true;
  }
  if (statusCode && statusCode >= 500 && statusCode < 600) {
    return true;
  }
  if (message.includes("timeout") || message.includes("ETIMEDOUT") || message.includes("AbortError") || message.includes("timed out") || err?.name === "AbortError") {
    return true;
  }
  if (message.includes("ECONNREFUSED") || message.includes("ENOTFOUND") || message.includes("ENETUNREACH") || message.includes("fetch failed")) {
    return true;
  }
  if (statusCode === 403 || message.includes("403") || message.includes("Forbidden")) {
    return true;
  }
  if (message.includes("Empty LLM response")) {
    return true;
  }
  return false;
}
async function retryWithBackoff(fn, config) {
  const { maxRetries, baseDelayMs, maxDelayMs = 3e4, retryableCheck = isRetryableError } = config;
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (attempt >= maxRetries || !retryableCheck(err)) {
        throw err;
      }
      const exponentialDelay = baseDelayMs * Math.pow(2, attempt);
      const jitter = Math.random() * (baseDelayMs / 2);
      const delay = Math.min(exponentialDelay + jitter, maxDelayMs);
      console.log(
        `[Retry] Attempt ${attempt + 1}/${maxRetries} failed (${err?.message?.slice(0, 100)}). Retrying in ${Math.round(delay)}ms...`
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}
function resetAllCircuits() {
  circuits.clear();
  callCounts.clear();
}
function resetCircuit(service) {
  circuits.delete(service);
  callCounts.delete(service);
}
var DEFAULT_CB_CONFIG, circuits, TRACKED_SERVICES, callCounts;
var init_api_resilience = __esm({
  "server/lib/api-resilience.ts"() {
    DEFAULT_CB_CONFIG = {
      failureThreshold: 3,
      resetTimeoutMs: 6e4,
      // 1 minute cooldown
      halfOpenMaxAttempts: 1
    };
    circuits = /* @__PURE__ */ new Map();
    TRACKED_SERVICES = [
      "shodan",
      "censys",
      "securitytrails",
      "urlscan",
      "dehashed",
      "binaryedge",
      "greynoise",
      "virustotal",
      "hibp",
      "whoisxml",
      "leakix",
      "fullhunt",
      "netlas",
      "hunter",
      "abuseipdb",
      "passivetotal",
      "crtsh",
      "wayback",
      "rdap",
      "ripestat",
      "shodan-internetdb",
      "email-security",
      "http-security",
      "cloud-assets",
      "dns-deep",
      "github-leaks",
      "social-media",
      "hackerone",
      "caldera",
      "gophish",
      "zap"
    ];
    callCounts = /* @__PURE__ */ new Map();
  }
});

export {
  classifyError,
  recordSuccess,
  recordFailure,
  shouldAllowRequest,
  resilientCall,
  trackCall,
  getServiceHealth,
  getAllServiceHealth,
  getHealthSummary,
  runStageWithFallback,
  isRetryableError,
  retryWithBackoff,
  resetAllCircuits,
  resetCircuit,
  init_api_resilience
};
