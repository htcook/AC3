/**
 * LLM Reliability Hardening Module
 * ═══════════════════════════════════════════════════════════════
 * Adds production-grade reliability patterns on top of the existing
 * invokeLLM retry/backoff logic:
 *
 *   1. Circuit Breaker — Prevents cascading failures by short-circuiting
 *      calls when the LLM API is consistently failing
 *   2. Prompt Cache — Deduplicates identical LLM calls within a TTL window
 *      to reduce latency and cost
 *   3. Health Dashboard — Aggregates telemetry into real-time health metrics
 *      for the LLM subsystem
 *   4. Fallback Chain — Provides graceful degradation with cached/static
 *      responses when the LLM is unavailable
 */

import { invokeLLM, type InvokeParams, type InvokeResult } from "../_core/llm";

// ═══════════════════════════════════════════════════════════════
// §1 — CIRCUIT BREAKER
// ═══════════════════════════════════════════════════════════════

export type CircuitState = "closed" | "open" | "half_open";

export interface CircuitBreakerConfig {
  /** Number of consecutive failures to trip the breaker (default: 5) */
  failureThreshold: number;
  /** Time in ms before attempting recovery (default: 60000 = 1 min) */
  recoveryTimeout: number;
  /** Number of successful calls in half-open to close the breaker (default: 2) */
  successThreshold: number;
  /** Rolling window in ms for failure counting (default: 300000 = 5 min) */
  rollingWindowMs: number;
}

const DEFAULT_CIRCUIT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  recoveryTimeout: 60_000,
  successThreshold: 2,
  rollingWindowMs: 300_000,
};

interface CircuitBreakerState {
  state: CircuitState;
  failures: number[];
  consecutiveSuccesses: number;
  lastFailureTime: number;
  lastStateChange: number;
  totalTrips: number;
  totalCallsBlocked: number;
}

const circuitState: CircuitBreakerState = {
  state: "closed",
  failures: [],
  consecutiveSuccesses: 0,
  lastFailureTime: 0,
  lastStateChange: Date.now(),
  totalTrips: 0,
  totalCallsBlocked: 0,
};

let circuitConfig = { ...DEFAULT_CIRCUIT_CONFIG };

export function configureCircuitBreaker(config: Partial<CircuitBreakerConfig>): void {
  circuitConfig = { ...circuitConfig, ...config };
}

export function getCircuitState(): CircuitState {
  pruneOldFailures();

  if (circuitState.state === "open") {
    const elapsed = Date.now() - circuitState.lastFailureTime;
    if (elapsed >= circuitConfig.recoveryTimeout) {
      circuitState.state = "half_open";
      circuitState.consecutiveSuccesses = 0;
      circuitState.lastStateChange = Date.now();
    }
  }

  return circuitState.state;
}

export function getCircuitBreakerStats(): {
  state: CircuitState;
  recentFailures: number;
  totalTrips: number;
  totalCallsBlocked: number;
  lastFailureTime: number;
  lastStateChange: number;
  config: CircuitBreakerConfig;
} {
  pruneOldFailures();
  return {
    state: getCircuitState(),
    recentFailures: circuitState.failures.length,
    totalTrips: circuitState.totalTrips,
    totalCallsBlocked: circuitState.totalCallsBlocked,
    lastFailureTime: circuitState.lastFailureTime,
    lastStateChange: circuitState.lastStateChange,
    config: { ...circuitConfig },
  };
}

function pruneOldFailures(): void {
  const cutoff = Date.now() - circuitConfig.rollingWindowMs;
  circuitState.failures = circuitState.failures.filter(t => t > cutoff);
}

function recordCircuitFailure(): void {
  circuitState.failures.push(Date.now());
  circuitState.lastFailureTime = Date.now();
  circuitState.consecutiveSuccesses = 0;
  pruneOldFailures();

  if (circuitState.state === "half_open") {
    // Any failure in half-open trips back to open
    circuitState.state = "open";
    circuitState.totalTrips++;
    circuitState.lastStateChange = Date.now();
  } else if (circuitState.state === "closed" && circuitState.failures.length >= circuitConfig.failureThreshold) {
    circuitState.state = "open";
    circuitState.totalTrips++;
    circuitState.lastStateChange = Date.now();
  }
}

function recordCircuitSuccess(): void {
  if (circuitState.state === "half_open") {
    circuitState.consecutiveSuccesses++;
    if (circuitState.consecutiveSuccesses >= circuitConfig.successThreshold) {
      circuitState.state = "closed";
      circuitState.failures = [];
      circuitState.lastStateChange = Date.now();
    }
  }
}

/** Reset the circuit breaker (for testing or manual recovery) */
export function resetCircuitBreaker(): void {
  circuitState.state = "closed";
  circuitState.failures = [];
  circuitState.consecutiveSuccesses = 0;
  circuitState.lastFailureTime = 0;
  circuitState.lastStateChange = Date.now();
  // Don't reset totalTrips/totalCallsBlocked — those are lifetime metrics
}

// ═══════════════════════════════════════════════════════════════
// §2 — PROMPT CACHE
// ═══════════════════════════════════════════════════════════════

interface CacheEntry {
  result: InvokeResult;
  createdAt: number;
  hits: number;
}

const promptCache = new Map<string, CacheEntry>();
const DEFAULT_CACHE_TTL_MS = 300_000; // 5 minutes
const MAX_CACHE_SIZE = 100;

let cacheTtlMs = DEFAULT_CACHE_TTL_MS;
let cacheEnabled = true;

export function configureCaching(options: { ttlMs?: number; enabled?: boolean; maxSize?: number }): void {
  if (options.ttlMs !== undefined) cacheTtlMs = options.ttlMs;
  if (options.enabled !== undefined) cacheEnabled = options.enabled;
}

/**
 * Generate a deterministic cache key from the LLM params.
 * Only caches based on messages content and response format — ignores telemetry fields.
 */
function generateCacheKey(params: InvokeParams): string {
  const keyObj = {
    messages: params.messages.map(m => ({ role: m.role, content: m.content })),
    tools: params.tools,
    toolChoice: params.toolChoice || params.tool_choice,
    responseFormat: params.responseFormat || params.response_format,
    outputSchema: params.outputSchema || params.output_schema,
  };
  // Simple hash — not cryptographic, just for deduplication
  const str = JSON.stringify(keyObj);
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return `llm_cache_${hash}`;
}

function getCachedResult(key: string): InvokeResult | null {
  if (!cacheEnabled) return null;

  const entry = promptCache.get(key);
  if (!entry) return null;

  if (Date.now() - entry.createdAt > cacheTtlMs) {
    promptCache.delete(key);
    return null;
  }

  entry.hits++;
  return entry.result;
}

function setCachedResult(key: string, result: InvokeResult): void {
  if (!cacheEnabled) return;

  // Evict oldest entries if cache is full
  if (promptCache.size >= MAX_CACHE_SIZE) {
    let oldestKey = "";
    let oldestTime = Infinity;
    for (const [k, v] of promptCache) {
      if (v.createdAt < oldestTime) {
        oldestTime = v.createdAt;
        oldestKey = k;
      }
    }
    if (oldestKey) promptCache.delete(oldestKey);
  }

  promptCache.set(key, { result, createdAt: Date.now(), hits: 0 });
}

export function getCacheStats(): {
  size: number;
  maxSize: number;
  ttlMs: number;
  enabled: boolean;
  totalHits: number;
  entries: Array<{ key: string; age: number; hits: number }>;
} {
  let totalHits = 0;
  const entries: Array<{ key: string; age: number; hits: number }> = [];

  for (const [key, entry] of promptCache) {
    totalHits += entry.hits;
    entries.push({ key, age: Date.now() - entry.createdAt, hits: entry.hits });
  }

  return { size: promptCache.size, maxSize: MAX_CACHE_SIZE, ttlMs: cacheTtlMs, enabled: cacheEnabled, totalHits, entries };
}

export function clearPromptCache(): void {
  promptCache.clear();
}

// ═══════════════════════════════════════════════════════════════
// §3 — FALLBACK CHAIN
// ═══════════════════════════════════════════════════════════════

export interface FallbackResponse {
  source: "live" | "cache" | "static_fallback";
  result: InvokeResult;
  degraded: boolean;
  circuitState: CircuitState;
  latencyMs: number;
  fromCache: boolean;
}

/**
 * Static fallback responses for critical operations when LLM is unavailable.
 * These provide safe defaults so the system doesn't completely fail.
 */
const STATIC_FALLBACKS: Record<string, string> = {
  "scan_plan": JSON.stringify({
    phases: [
      { name: "reconnaissance", tools: ["nmap", "httpx"], priority: 1 },
      { name: "vulnerability_scan", tools: ["nuclei", "nikto"], priority: 2 },
      { name: "web_scan", tools: ["zap"], priority: 3 },
    ],
    strategy: "sequential_safe",
    note: "Static fallback plan — LLM was unavailable. Running standard sequential scan."
  }),
  "vuln_analysis": JSON.stringify({
    findings: [],
    summary: "LLM analysis unavailable — raw scan results displayed without AI correlation.",
    confidence: 0,
    note: "Static fallback — review raw findings manually."
  }),
  "hunt_hypothesis": JSON.stringify({
    hypotheses: [
      { title: "Standard Lateral Movement Check", description: "Look for unusual RDP/SSH connections between internal hosts", priority: "high" },
      { title: "Credential Access Indicators", description: "Check for LSASS access, Mimikatz signatures, or credential dumping tools", priority: "high" },
      { title: "Persistence Mechanisms", description: "Review scheduled tasks, services, and registry run keys for unauthorized entries", priority: "medium" },
    ],
    note: "Static fallback hypotheses — LLM was unavailable."
  }),
};

function getStaticFallback(caller?: string): InvokeResult | null {
  let fallbackContent: string | null = null;

  if (caller) {
    for (const [key, content] of Object.entries(STATIC_FALLBACKS)) {
      if (caller.toLowerCase().includes(key)) {
        fallbackContent = content;
        break;
      }
    }
  }

  if (!fallbackContent) return null;

  return {
    id: `fallback-${Date.now()}`,
    created: Math.floor(Date.now() / 1000),
    model: "static-fallback",
    choices: [{
      index: 0,
      message: { role: "assistant", content: fallbackContent },
      finish_reason: "stop",
    }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
}

// ═══════════════════════════════════════════════════════════════
// §4 — RESILIENT INVOKE (combines all patterns)
// ═══════════════════════════════════════════════════════════════

/**
 * Resilient LLM invocation that wraps invokeLLM with:
 *   1. Circuit breaker check
 *   2. Prompt cache lookup
 *   3. Live call with fallback chain
 *
 * Use this instead of invokeLLM directly for non-critical paths.
 * Critical paths (engagement orchestrator) should continue using
 * invokeLLM directly with their own error handling.
 */
export async function resilientInvokeLLM(
  params: InvokeParams,
  options?: {
    /** Skip cache for this call */
    skipCache?: boolean;
    /** Allow static fallback if everything fails */
    allowStaticFallback?: boolean;
  }
): Promise<FallbackResponse> {
  const start = Date.now();
  const cacheKey = generateCacheKey(params);
  const currentState = getCircuitState();

  // 1. Check cache first (even if circuit is open)
  if (!options?.skipCache) {
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return {
        source: "cache",
        result: cached,
        degraded: false,
        circuitState: currentState,
        latencyMs: Date.now() - start,
        fromCache: true,
      };
    }
  }

  // 2. Check circuit breaker
  if (currentState === "open") {
    circuitState.totalCallsBlocked++;

    // Try static fallback
    if (options?.allowStaticFallback) {
      const fallback = getStaticFallback(params._caller);
      if (fallback) {
        return {
          source: "static_fallback",
          result: fallback,
          degraded: true,
          circuitState: currentState,
          latencyMs: Date.now() - start,
          fromCache: false,
        };
      }
    }

    throw new Error(`LLM circuit breaker is OPEN — ${circuitState.failures.length} failures in the last ${circuitConfig.rollingWindowMs / 1000}s. Recovery in ${Math.max(0, circuitConfig.recoveryTimeout - (Date.now() - circuitState.lastFailureTime))}ms.`);
  }

  // 3. Make the live call
  try {
    const result = await invokeLLM(params);
    recordCircuitSuccess();

    // Cache the result
    if (!options?.skipCache) {
      setCachedResult(cacheKey, result);
    }

    return {
      source: "live",
      result,
      degraded: false,
      circuitState: getCircuitState(),
      latencyMs: Date.now() - start,
      fromCache: false,
    };
  } catch (err: any) {
    recordCircuitFailure();

    // Try static fallback
    if (options?.allowStaticFallback) {
      const fallback = getStaticFallback(params._caller);
      if (fallback) {
        return {
          source: "static_fallback",
          result: fallback,
          degraded: true,
          circuitState: getCircuitState(),
          latencyMs: Date.now() - start,
          fromCache: false,
        };
      }
    }

    throw err;
  }
}

// ═══════════════════════════════════════════════════════════════
// §5 — HEALTH DASHBOARD
// ═══════════════════════════════════════════════════════════════

export interface LLMHealthMetrics {
  status: "healthy" | "degraded" | "unhealthy";
  circuitBreaker: ReturnType<typeof getCircuitBreakerStats>;
  cache: ReturnType<typeof getCacheStats>;
  recentPerformance: {
    avgLatencyMs: number;
    p95LatencyMs: number;
    successRate: number;
    totalCalls: number;
    errorRate: number;
    timeoutRate: number;
  };
  uptime: {
    since: number;
    durationMs: number;
  };
  recommendations: string[];
}

const startTime = Date.now();

// Rolling window for performance tracking
const performanceWindow: Array<{
  timestamp: number;
  latencyMs: number;
  success: boolean;
  timeout: boolean;
}> = [];
const PERFORMANCE_WINDOW_MS = 600_000; // 10 minutes

export function recordPerformanceSample(latencyMs: number, success: boolean, timeout: boolean = false): void {
  performanceWindow.push({ timestamp: Date.now(), latencyMs, success, timeout });

  // Prune old entries
  const cutoff = Date.now() - PERFORMANCE_WINDOW_MS;
  while (performanceWindow.length > 0 && performanceWindow[0].timestamp < cutoff) {
    performanceWindow.shift();
  }
}

export function getLLMHealthMetrics(): LLMHealthMetrics {
  const circuitBreaker = getCircuitBreakerStats();
  const cache = getCacheStats();

  // Compute performance metrics
  const cutoff = Date.now() - PERFORMANCE_WINDOW_MS;
  const recentSamples = performanceWindow.filter(s => s.timestamp > cutoff);

  const totalCalls = recentSamples.length;
  const successCount = recentSamples.filter(s => s.success).length;
  const timeoutCount = recentSamples.filter(s => s.timeout).length;
  const errorCount = totalCalls - successCount;

  const latencies = recentSamples.map(s => s.latencyMs).sort((a, b) => a - b);
  const avgLatencyMs = totalCalls > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / totalCalls) : 0;
  const p95LatencyMs = totalCalls > 0 ? latencies[Math.floor(totalCalls * 0.95)] || latencies[latencies.length - 1] : 0;

  const successRate = totalCalls > 0 ? successCount / totalCalls : 1;
  const errorRate = totalCalls > 0 ? errorCount / totalCalls : 0;
  const timeoutRate = totalCalls > 0 ? timeoutCount / totalCalls : 0;

  // Determine overall health status
  let status: LLMHealthMetrics["status"] = "healthy";
  if (circuitBreaker.state === "open") {
    status = "unhealthy";
  } else if (circuitBreaker.state === "half_open" || errorRate > 0.2 || avgLatencyMs > 30_000) {
    status = "degraded";
  }

  // Generate recommendations
  const recommendations: string[] = [];
  if (circuitBreaker.state === "open") {
    recommendations.push("Circuit breaker is OPEN — LLM API is experiencing sustained failures. Check API key validity and service status.");
  }
  if (errorRate > 0.3) {
    recommendations.push(`High error rate (${(errorRate * 100).toFixed(1)}%) — consider increasing retry count or backoff intervals.`);
  }
  if (timeoutRate > 0.2) {
    recommendations.push(`High timeout rate (${(timeoutRate * 100).toFixed(1)}%) — consider increasing timeout threshold or simplifying prompts.`);
  }
  if (avgLatencyMs > 20_000) {
    recommendations.push(`High average latency (${(avgLatencyMs / 1000).toFixed(1)}s) — consider enabling prompt caching or reducing prompt complexity.`);
  }
  if (cache.size === 0 && totalCalls > 10) {
    recommendations.push("Prompt cache is empty despite active usage — consider enabling caching for repeated queries.");
  }
  if (circuitBreaker.totalTrips > 5) {
    recommendations.push(`Circuit breaker has tripped ${circuitBreaker.totalTrips} times — investigate recurring LLM API instability.`);
  }
  if (recommendations.length === 0) {
    recommendations.push("All systems nominal. LLM subsystem is operating within expected parameters.");
  }

  return {
    status,
    circuitBreaker,
    cache,
    recentPerformance: {
      avgLatencyMs,
      p95LatencyMs,
      successRate,
      totalCalls,
      errorRate,
      timeoutRate,
    },
    uptime: {
      since: startTime,
      durationMs: Date.now() - startTime,
    },
    recommendations,
  };
}

/**
 * Quick health check — returns true if LLM is available for calls.
 */
export function isLLMAvailable(): boolean {
  return getCircuitState() !== "open";
}
