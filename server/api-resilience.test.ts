/**
 * Tests for the API Resilience Layer — Circuit Breaker, Error Classification, Timeout Enforcement
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  classifyError,
  resilientCall,
  getServiceHealth,
  getAllServiceHealth,
  getHealthSummary,
  resetAllCircuits,
  resetCircuit,
  trackCall,
  runStageWithFallback,
  type ClassifiedError,
  type ErrorCategory,
} from "./lib/api-resilience";

describe("Error Classification", () => {
  it("classifies 401 as auth_failure", () => {
    const err = { message: "HTTP 401 Unauthorized", status: 401 };
    const classified = classifyError(err, "shodan");
    expect(classified.category).toBe("auth_failure");
    expect(classified.retryable).toBe(false);
    expect(classified.service).toBe("shodan");
  });

  it("classifies 429 as rate_limited", () => {
    const err = { message: "Too Many Requests", status: 429 };
    const classified = classifyError(err, "censys");
    expect(classified.category).toBe("rate_limited");
    expect(classified.retryable).toBe(true);
  });

  it("classifies timeout errors", () => {
    const err = { message: "Request timeout after 15000ms" };
    const classified = classifyError(err, "urlscan");
    expect(classified.category).toBe("timeout");
    expect(classified.retryable).toBe(true);
  });

  it("classifies network errors", () => {
    const err = { message: "ECONNREFUSED 127.0.0.1:443" };
    const classified = classifyError(err, "securitytrails");
    expect(classified.category).toBe("network_error");
    expect(classified.retryable).toBe(true);
  });

  it("classifies not_configured errors", () => {
    const err = { message: "API key not configured for Shodan" };
    const classified = classifyError(err, "shodan");
    expect(classified.category).toBe("not_configured");
    expect(classified.retryable).toBe(false);
  });

  it("classifies parse errors", () => {
    const err = { message: "Unexpected token < in JSON at position 0" };
    const classified = classifyError(err, "virustotal");
    expect(classified.category).toBe("parse_error");
    expect(classified.retryable).toBe(false);
  });

  it("classifies 500 as api_error", () => {
    const err = { message: "Internal Server Error", status: 500 };
    const classified = classifyError(err, "dehashed");
    expect(classified.category).toBe("api_error");
    expect(classified.retryable).toBe(true);
  });

  it("classifies unknown errors", () => {
    const err = { message: "Something weird happened" };
    const classified = classifyError(err, "test");
    expect(classified.category).toBe("unknown");
    expect(classified.retryable).toBe(true);
  });
});

describe("Circuit Breaker", () => {
  beforeEach(() => {
    resetAllCircuits();
  });

  it("allows requests when circuit is closed", async () => {
    const result = await resilientCall(
      async () => "success",
      { service: "test-service-closed" }
    );
    expect(result.success).toBe(true);
    expect(result.data).toBe("success");
    expect(result.circuitState).toBe("closed");
  });

  it("opens circuit after threshold failures", async () => {
    const service = "test-service-open";
    
    // Fail 3 times (default threshold)
    for (let i = 0; i < 3; i++) {
      await resilientCall(
        async () => { throw new Error("API error"); },
        { service }
      );
    }
    
    // 4th call should be blocked by circuit breaker
    const result = await resilientCall(
      async () => "should not reach",
      { service }
    );
    expect(result.success).toBe(false);
    expect(result.error?.category).toBe("circuit_open");
    expect(result.circuitState).toBe("open");
  });

  it("transitions to half-open after reset timeout", async () => {
    const service = "test-service-halfopen";
    
    // Fail 3 times with very short reset timeout
    for (let i = 0; i < 3; i++) {
      await resilientCall(
        async () => { throw new Error("API error"); },
        { service, circuitBreakerConfig: { failureThreshold: 3, resetTimeoutMs: 50, halfOpenMaxAttempts: 1 } }
      );
    }
    
    // Wait for reset timeout
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Should allow one probe request
    const result = await resilientCall(
      async () => "recovered",
      { service, circuitBreakerConfig: { failureThreshold: 3, resetTimeoutMs: 50, halfOpenMaxAttempts: 1 } }
    );
    expect(result.success).toBe(true);
    expect(result.data).toBe("recovered");
    expect(result.circuitState).toBe("closed");
  });

  it("handles timeout enforcement", async () => {
    const result = await resilientCall(
      async () => {
        await new Promise(resolve => setTimeout(resolve, 5000));
        return "too late";
      },
      { service: "test-timeout", timeoutMs: 100 }
    );
    expect(result.success).toBe(false);
    expect(result.error?.category).toBe("timeout");
    expect(result.durationMs).toBeLessThan(1000);
  });

  it("retries on retryable errors", async () => {
    let attempts = 0;
    const result = await resilientCall(
      async () => {
        attempts++;
        if (attempts < 3) throw new Error("ECONNREFUSED");
        return "success on retry";
      },
      { service: "test-retry", retries: 2, retryDelayMs: 50 }
    );
    expect(result.success).toBe(true);
    expect(result.data).toBe("success on retry");
    expect(result.attempt).toBe(3);
  });

  it("does not retry non-retryable errors", async () => {
    let attempts = 0;
    const result = await resilientCall(
      async () => {
        attempts++;
        throw Object.assign(new Error("Unauthorized"), { status: 401 });
      },
      { service: "test-no-retry", retries: 2, retryDelayMs: 50 }
    );
    expect(result.success).toBe(false);
    expect(result.error?.category).toBe("auth_failure");
    expect(attempts).toBe(1);
  });
});

describe("Service Health Dashboard", () => {
  beforeEach(() => {
    resetAllCircuits();
  });

  it("reports unknown status for new services", () => {
    const health = getServiceHealth("brand-new-service");
    expect(health.status).toBe("unknown");
    expect(health.circuitState).toBe("closed");
    expect(health.lastSuccessAt).toBeNull();
  });

  it("reports healthy after successful calls", async () => {
    await resilientCall(async () => "ok", { service: "healthy-svc" });
    const health = getServiceHealth("healthy-svc");
    expect(health.status).toBe("healthy");
    expect(health.lastSuccessAt).toBeGreaterThan(0);
  });

  it("reports degraded after some failures", async () => {
    await resilientCall(async () => "ok", { service: "degraded-svc" });
    await resilientCall(async () => { throw new Error("fail"); }, { service: "degraded-svc" });
    const health = getServiceHealth("degraded-svc");
    expect(health.status).toBe("degraded");
    expect(health.recentFailures).toBe(1);
  });

  it("reports down when circuit is open", async () => {
    for (let i = 0; i < 3; i++) {
      await resilientCall(async () => { throw new Error("fail"); }, { service: "down-svc" });
    }
    const health = getServiceHealth("down-svc");
    expect(health.status).toBe("down");
    expect(health.circuitState).toBe("open");
  });

  it("returns health summary for all tracked services", () => {
    const summary = getHealthSummary();
    expect(summary.totalServices).toBeGreaterThan(0);
    expect(summary).toHaveProperty("healthy");
    expect(summary).toHaveProperty("degraded");
    expect(summary).toHaveProperty("down");
    expect(summary).toHaveProperty("overallStatus");
  });

  it("tracks call counts for uptime calculation", () => {
    trackCall("uptime-test", true);
    trackCall("uptime-test", true);
    trackCall("uptime-test", false);
    const health = getServiceHealth("uptime-test");
    expect(health.uptime).toBe("66.7%");
  });
});

describe("Pipeline Stage Wrapper", () => {
  it("returns data on success", async () => {
    const result = await runStageWithFallback(
      "test-stage",
      async () => ({ count: 42 }),
      { count: 0 }
    );
    expect(result.success).toBe(true);
    expect(result.data).toEqual({ count: 42 });
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(result.skipped).toBe(false);
  });

  it("returns fallback on failure", async () => {
    const result = await runStageWithFallback(
      "failing-stage",
      async () => { throw new Error("Stage exploded"); },
      { count: -1 }
    );
    expect(result.success).toBe(false);
    expect(result.data).toEqual({ count: -1 });
    expect(result.error).toContain("Stage exploded");
    expect(result.errorCategory).toBe("unknown");
  });

  it("enforces stage timeout", async () => {
    const result = await runStageWithFallback(
      "slow-stage",
      async () => {
        await new Promise(resolve => setTimeout(resolve, 5000));
        return { count: 999 };
      },
      { count: 0 },
      { timeoutMs: 100 }
    );
    expect(result.success).toBe(false);
    expect(result.data).toEqual({ count: 0 });
    expect(result.error).toContain("timed out");
    expect(result.errorCategory).toBe("timeout");
  });
});
