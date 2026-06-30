/**
 * API Resilience Layer — Circuit Breaker, Error Classification, Timeout Enforcement
 * 
 * Provides production-grade error handling for all external API integrations:
 * - Circuit breaker pattern to avoid hammering failing APIs
 * - Error categorization (auth, rate-limit, timeout, network, API error)
 * - Per-call timeout enforcement with AbortController
 * - Health status tracking for all external services
 * - Graceful degradation reporting for the UI
 */

// ─── Error Classification ────────────────────────────────────────────

export type ErrorCategory = 
  | "auth_failure"       // 401/403 — credentials invalid or expired
  | "rate_limited"       // 429 — rate limit exceeded
  | "timeout"            // Request timed out
  | "network_error"      // DNS failure, connection refused, etc.
  | "api_error"          // 5xx or unexpected API response
  | "parse_error"        // Response couldn't be parsed
  | "not_configured"     // API key not set
  | "circuit_open"       // Circuit breaker is open, call skipped
  | "unknown";           // Unclassified error

export interface ClassifiedError {
  category: ErrorCategory;
  message: string;
  statusCode?: number;
  retryable: boolean;
  service: string;
  timestamp: number;
}

export function classifyError(err: any, service: string): ClassifiedError {
  const timestamp = Date.now();
  const message = err?.message || String(err);
  
  // Check for HTTP status codes
  const statusCode = err?.status || err?.statusCode || err?.response?.status;
  
  if (statusCode === 401 || statusCode === 403 || message.includes("401") || message.includes("Unauthorized") || message.includes("Forbidden")) {
    return { category: "auth_failure", message, statusCode, retryable: false, service, timestamp };
  }
  
  if (statusCode === 429 || message.includes("429") || message.includes("rate limit") || message.includes("Too Many Requests")) {
    return { category: "rate_limited", message, statusCode, retryable: true, service, timestamp };
  }
  
  if (message.includes("timeout") || message.includes("ETIMEDOUT") || message.includes("AbortError") || message.includes("aborted") || message.includes("timed out") || err?.name === "AbortError" || err?.name === "TimeoutError") {
    return { category: "timeout", message, statusCode: undefined, retryable: true, service, timestamp };
  }
  
  if (message.includes("ECONNREFUSED") || message.includes("ENOTFOUND") || message.includes("ENETUNREACH") || message.includes("fetch failed") || message.includes("network")) {
    return { category: "network_error", message, statusCode: undefined, retryable: true, service, timestamp };
  }
  
  if (message.includes("not configured") || message.includes("API key not") || message.includes("missing key")) {
    return { category: "not_configured", message, statusCode: undefined, retryable: false, service, timestamp };
  }
  
  if (message.includes("JSON") || message.includes("parse") || message.includes("Unexpected token")) {
    return { category: "parse_error", message, statusCode, retryable: false, service, timestamp };
  }
  
  if (statusCode && statusCode >= 500) {
    return { category: "api_error", message, statusCode, retryable: true, service, timestamp };
  }
  
  return { category: "unknown", message, statusCode, retryable: true, service, timestamp };
}


// ─── Circuit Breaker ─────────────────────────────────────────────────

export interface CircuitBreakerConfig {
  failureThreshold: number;     // Number of failures before opening circuit
  resetTimeoutMs: number;       // Time to wait before half-opening
  halfOpenMaxAttempts: number;  // Max attempts in half-open state
}

const DEFAULT_CB_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 3,
  resetTimeoutMs: 60_000,       // 1 minute cooldown
  halfOpenMaxAttempts: 1,
};

type CircuitState = "closed" | "open" | "half_open";

interface CircuitBreakerState {
  state: CircuitState;
  failures: number;
  lastFailureAt: number;
  lastSuccessAt: number;
  halfOpenAttempts: number;
  recentErrors: ClassifiedError[];
}

// In-memory circuit breaker state per service
const circuits = new Map<string, CircuitBreakerState>();

function getCircuit(service: string): CircuitBreakerState {
  if (!circuits.has(service)) {
    circuits.set(service, {
      state: "closed",
      failures: 0,
      lastFailureAt: 0,
      lastSuccessAt: 0,
      halfOpenAttempts: 0,
      recentErrors: [],
    });
  }
  return circuits.get(service)!;
}

export function recordSuccess(service: string): void {
  const circuit = getCircuit(service);
  circuit.state = "closed";
  circuit.failures = 0;
  circuit.halfOpenAttempts = 0;
  circuit.lastSuccessAt = Date.now();
}

export function recordFailure(service: string, error: ClassifiedError, config: CircuitBreakerConfig = DEFAULT_CB_CONFIG): void {
  const circuit = getCircuit(service);
  circuit.failures++;
  circuit.lastFailureAt = Date.now();
  circuit.recentErrors.push(error);
  
  // Keep only last 10 errors
  if (circuit.recentErrors.length > 10) {
    circuit.recentErrors = circuit.recentErrors.slice(-10);
  }
  
  // Auth failures (401/403) open circuit immediately — retrying with same bad creds is pointless
  if (error.category === 'auth_failure' || error.category === 'not_configured') {
    circuit.state = 'open';
    circuit.failures = config.failureThreshold; // Ensure it stays open
  } else if (circuit.failures >= config.failureThreshold) {
    circuit.state = 'open';
  }
}

export function shouldAllowRequest(service: string, config: CircuitBreakerConfig = DEFAULT_CB_CONFIG): { allowed: boolean; reason?: string } {
  const circuit = getCircuit(service);
  
  if (circuit.state === "closed") {
    return { allowed: true };
  }
  
  if (circuit.state === "open") {
    const elapsed = Date.now() - circuit.lastFailureAt;
    if (elapsed >= config.resetTimeoutMs) {
      // Transition to half-open
      circuit.state = "half_open";
      circuit.halfOpenAttempts = 0;
      return { allowed: true, reason: "half_open_probe" };
    }
    const remainingMs = config.resetTimeoutMs - elapsed;
    return { allowed: false, reason: `Circuit open for ${service} — ${Math.ceil(remainingMs / 1000)}s until retry` };
  }
  
  // half_open
  if (circuit.halfOpenAttempts < config.halfOpenMaxAttempts) {
    circuit.halfOpenAttempts++;
    return { allowed: true, reason: "half_open_probe" };
  }
  
  return { allowed: false, reason: `Circuit half-open limit reached for ${service}` };
}


// ─── Resilient API Call Wrapper ──────────────────────────────────────

export interface ResilientCallOptions {
  service: string;
  timeoutMs?: number;
  circuitBreakerConfig?: CircuitBreakerConfig;
  retries?: number;
  retryDelayMs?: number;
}

export interface ResilientCallResult<T> {
  success: boolean;
  data?: T;
  error?: ClassifiedError;
  durationMs: number;
  circuitState: CircuitState;
  attempt: number;
}

/**
 * Execute an API call with circuit breaker, timeout, and retry logic.
 * Returns a structured result instead of throwing.
 */
export async function resilientCall<T>(
  fn: (signal?: AbortSignal) => Promise<T>,
  options: ResilientCallOptions
): Promise<ResilientCallResult<T>> {
  const { service, timeoutMs = 15000, circuitBreakerConfig = DEFAULT_CB_CONFIG, retries = 0, retryDelayMs = 1000 } = options;
  const circuit = getCircuit(service);
  
  // Check circuit breaker
  const check = shouldAllowRequest(service, circuitBreakerConfig);
  if (!check.allowed) {
    return {
      success: false,
      error: { category: "circuit_open", message: check.reason || "Circuit breaker open", retryable: false, service, timestamp: Date.now() },
      durationMs: 0,
      circuitState: circuit.state,
      attempt: 0,
    };
  }
  
  let lastError: ClassifiedError | undefined;
  
  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    const start = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    
    try {
      const data = await Promise.race([
        fn(controller.signal),
        new Promise<never>((_, reject) => {
          const t = setTimeout(() => {
            controller.abort();
            reject(new Error(`Request to ${service} timed out after ${timeoutMs}ms`));
          }, timeoutMs);
          // Store ref so we can clear it
          (controller as any)._raceTimer = t;
        }),
      ]);
      clearTimeout(timer);
      if ((controller as any)._raceTimer) clearTimeout((controller as any)._raceTimer);
      recordSuccess(service);
      
      return {
        success: true,
        data,
        durationMs: Date.now() - start,
        circuitState: getCircuit(service).state,
        attempt,
      };
    } catch (err: any) {
      clearTimeout(timer);
      lastError = classifyError(err, service);
      recordFailure(service, lastError, circuitBreakerConfig);
      
      // Don't retry non-retryable errors
      if (!lastError.retryable || attempt > retries) {
        return {
          success: false,
          error: lastError,
          durationMs: Date.now() - start,
          circuitState: getCircuit(service).state,
          attempt,
        };
      }
      
      // Wait before retry with exponential backoff
      await new Promise(resolve => setTimeout(resolve, retryDelayMs * attempt));
    }
  }
  
  // Should not reach here, but just in case
  return {
    success: false,
    error: lastError || { category: "unknown", message: "Exhausted retries", retryable: false, service, timestamp: Date.now() },
    durationMs: 0,
    circuitState: getCircuit(service).state,
    attempt: retries + 1,
  };
}


// ─── Service Health Dashboard ────────────────────────────────────────

export interface ServiceHealth {
  service: string;
  status: "healthy" | "degraded" | "down" | "not_configured" | "unknown";
  circuitState: CircuitState;
  lastSuccessAt: number | null;
  lastFailureAt: number | null;
  recentFailures: number;
  recentErrors: ClassifiedError[];
  uptime: string;   // e.g., "99.2%" or "N/A"
}

const TRACKED_SERVICES = [
  "shodan", "censys", "securitytrails", "urlscan", "dehashed",
  "binaryedge", "greynoise", "virustotal", "hibp", "whoisxml",
  "leakix", "fullhunt", "netlas", "hunter", "abuseipdb",
  "passivetotal", "crtsh", "wayback", "rdap", "ripestat",
  "shodan-internetdb", "email-security", "http-security",
  "cloud-assets", "dns-deep", "github-leaks", "social-media",
  "hackerone", "caldera", "gophish", "zap",
] as const;

// Track call counts for uptime calculation
const callCounts = new Map<string, { total: number; successes: number }>();

export function trackCall(service: string, success: boolean): void {
  if (!callCounts.has(service)) {
    callCounts.set(service, { total: 0, successes: 0 });
  }
  const counts = callCounts.get(service)!;
  counts.total++;
  if (success) counts.successes++;
}

export function getServiceHealth(service: string): ServiceHealth {
  const circuit = getCircuit(service);
  const counts = callCounts.get(service);
  
  let status: ServiceHealth["status"] = "unknown";
  if (circuit.state === "open") {
    status = "down";
  } else if (circuit.state === "half_open") {
    status = "degraded";
  } else if (circuit.failures > 0) {
    status = "degraded";
  } else if (circuit.lastSuccessAt > 0) {
    status = "healthy";
  }
  
  // Check for auth failures — mark as not_configured
  const hasAuthFailure = circuit.recentErrors.some(e => e.category === "auth_failure" || e.category === "not_configured");
  if (hasAuthFailure && circuit.lastSuccessAt === 0) {
    status = "not_configured";
  }
  
  const uptime = counts && counts.total > 0
    ? `${((counts.successes / counts.total) * 100).toFixed(1)}%`
    : "N/A";
  
  return {
    service,
    status,
    circuitState: circuit.state,
    lastSuccessAt: circuit.lastSuccessAt || null,
    lastFailureAt: circuit.lastFailureAt || null,
    recentFailures: circuit.failures,
    recentErrors: circuit.recentErrors.slice(-5),
    uptime,
  };
}

export function getAllServiceHealth(): ServiceHealth[] {
  return TRACKED_SERVICES.map(s => getServiceHealth(s));
}

export function getHealthSummary(): {
  totalServices: number;
  healthy: number;
  degraded: number;
  down: number;
  notConfigured: number;
  unknown: number;
  overallStatus: "healthy" | "degraded" | "critical";
} {
  const health = getAllServiceHealth();
  const healthy = health.filter(h => h.status === "healthy").length;
  const degraded = health.filter(h => h.status === "degraded").length;
  const down = health.filter(h => h.status === "down").length;
  const notConfigured = health.filter(h => h.status === "not_configured").length;
  const unknown = health.filter(h => h.status === "unknown").length;
  
  let overallStatus: "healthy" | "degraded" | "critical" = "healthy";
  if (down > 3 || degraded > 5) overallStatus = "critical";
  else if (down > 0 || degraded > 2) overallStatus = "degraded";
  
  return {
    totalServices: health.length,
    healthy,
    degraded,
    down,
    notConfigured,
    unknown,
    overallStatus,
  };
}


// ─── Pipeline Stage Wrapper ──────────────────────────────────────────

export interface StageResult<T> {
  stageName: string;
  success: boolean;
  data?: T;
  error?: string;
  errorCategory?: ErrorCategory;
  durationMs: number;
  skipped: boolean;
  skipReason?: string;
}

/**
 * Wrap a pipeline stage with error handling and timing.
 * On failure, returns a default value instead of throwing.
 */
export async function runStageWithFallback<T>(
  stageName: string,
  fn: () => Promise<T>,
  fallback: T,
  options?: { timeoutMs?: number }
): Promise<StageResult<T>> {
  const start = Date.now();
  const timeoutMs = options?.timeoutMs || 60000;
  
  try {
    const result = await Promise.race([
      fn(),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error(`Stage ${stageName} timed out after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
    
    return {
      stageName,
      success: true,
      data: result,
      durationMs: Date.now() - start,
      skipped: false,
    };
  } catch (err: any) {
    const classified = classifyError(err, stageName);
    console.error(`[Pipeline] Stage "${stageName}" failed (${classified.category}): ${classified.message}`);
    
    return {
      stageName,
      success: false,
      data: fallback,
      error: classified.message,
      errorCategory: classified.category,
      durationMs: Date.now() - start,
      skipped: false,
    };
  }
}


// ─── Retry with Exponential Backoff ───────────────────────────────────

export interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs?: number;
  retryableCheck?: (err: any) => boolean;
}

/**
 * Check if an error is retryable (rate limit, timeout, network, 5xx).
 * Used as default retryableCheck for retryWithBackoff.
 */
export function isRetryableError(err: any): boolean {
  const message = err?.message || String(err);
  const statusCode = err?.status || err?.statusCode || err?.response?.status;

  // Rate limit (429)
  if (statusCode === 429 || message.includes("429") || message.includes("rate limit") || message.includes("Too Many Requests")) {
    return true;
  }
  // Server errors (5xx)
  if (statusCode && statusCode >= 500 && statusCode < 600) {
    return true;
  }
  // Timeouts
  if (message.includes("timeout") || message.includes("ETIMEDOUT") || message.includes("AbortError") || message.includes("timed out") || err?.name === "AbortError") {
    return true;
  }
  // Network errors
  if (message.includes("ECONNREFUSED") || message.includes("ENOTFOUND") || message.includes("ENETUNREACH") || message.includes("fetch failed")) {
    return true;
  }
  // 403 can be transient (rate limit without proper 429 header)
  if (statusCode === 403 || message.includes("403") || message.includes("Forbidden")) {
    return true;
  }
  // Empty LLM response (transient)
  if (message.includes("Empty LLM response")) {
    return true;
  }
  return false;
}

/**
 * Retry an async function with exponential backoff + jitter.
 * Throws the last error if all retries are exhausted.
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  config: RetryConfig
): Promise<T> {
  const { maxRetries, baseDelayMs, maxDelayMs = 30000, retryableCheck = isRetryableError } = config;
  let lastError: any;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err: any) {
      lastError = err;

      if (attempt >= maxRetries || !retryableCheck(err)) {
        throw err;
      }

      // Exponential backoff with jitter: delay = base * 2^attempt + random(0, base/2)
      const exponentialDelay = baseDelayMs * Math.pow(2, attempt);
      const jitter = Math.random() * (baseDelayMs / 2);
      const delay = Math.min(exponentialDelay + jitter, maxDelayMs);

      console.log(
        `[Retry] Attempt ${attempt + 1}/${maxRetries} failed (${err?.message?.slice(0, 100)}). Retrying in ${Math.round(delay)}ms...`
      );
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}


// ─── Reset (for testing) ────────────────────────────────────────────

export function resetAllCircuits(): void {
  circuits.clear();
  callCounts.clear();
}

export function resetCircuit(service: string): void {
  circuits.delete(service);
  callCounts.delete(service);
}
