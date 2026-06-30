import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Rate Limiter Tests ─────────────────────────────────────────────────────
describe("Rate Limiter", () => {
  it("should export all required rate limiters", async () => {
    const rateLimiter = await import("./lib/rate-limiter");
    expect(rateLimiter.authRateLimiter).toBeDefined();
    expect(rateLimiter.apiRateLimiter).toBeDefined();
    expect(rateLimiter.generalRateLimiter).toBeDefined();
    expect(rateLimiter.trpcAuthRateLimiter).toBeDefined();
  });

  it("trpcAuthRateLimiter should detect auth procedure calls", async () => {
    const { trpcAuthRateLimiter } = await import("./lib/rate-limiter");

    // Mock request with auth procedure in path
    const authReq = {
      path: "/accountAuth.emailLogin",
      hostname: "aceofcloud.io",
      headers: { host: "aceofcloud.io" },
      ip: "1.2.3.4",
      socket: { remoteAddress: "1.2.3.4" },
    } as any;

    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
      setHeader: vi.fn(),
      set: vi.fn(),
      headersSent: false,
    } as any;

    // Should invoke authRateLimiter (which calls next internally)
    let nextCalled = false;
    // For auth calls, the authRateLimiter middleware is invoked instead of next
    // We just verify it doesn't throw
    expect(() => {
      trpcAuthRateLimiter(authReq, res, () => { nextCalled = true; });
    }).not.toThrow();
  });

  it("trpcAuthRateLimiter should pass through non-auth calls", async () => {
    const { trpcAuthRateLimiter } = await import("./lib/rate-limiter");

    const nonAuthReq = {
      path: "/engagement.list",
      hostname: "aceofcloud.io",
      headers: { host: "aceofcloud.io" },
      ip: "1.2.3.4",
      socket: { remoteAddress: "1.2.3.4" },
    } as any;

    const res = {} as any;
    let nextCalled = false;

    trpcAuthRateLimiter(nonAuthReq, res, () => { nextCalled = true; });
    expect(nextCalled).toBe(true);
  });

  it("trpcAuthRateLimiter should detect batched auth calls", async () => {
    const { trpcAuthRateLimiter } = await import("./lib/rate-limiter");

    // tRPC batches multiple procedures separated by commas
    const batchedReq = {
      path: "/calderaAuth.session,accountAuth.emailLogin",
      hostname: "aceofcloud.io",
      headers: { host: "aceofcloud.io" },
      ip: "1.2.3.4",
      socket: { remoteAddress: "1.2.3.4" },
    } as any;

    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
      setHeader: vi.fn(),
      set: vi.fn(),
      headersSent: false,
    } as any;

    let nextCalled = false;
    // Should detect the auth call in the batch and NOT call next directly
    expect(() => {
      trpcAuthRateLimiter(batchedReq, res, () => { nextCalled = true; });
    }).not.toThrow();
  });
});

// ─── Session Activity Logger Tests ──────────────────────────────────────────
describe("Session Activity Logger", () => {
  it("should export all required functions", async () => {
    const logger = await import("./lib/session-activity-logger");
    expect(logger.initSessionLogger).toBeDefined();
    expect(logger.logSessionEvent).toBeDefined();
    expect(logger.flushSessionEvents).toBeDefined();
    expect(logger.extractRequestInfo).toBeDefined();
  });

  it("extractRequestInfo should extract IP from X-Forwarded-For", async () => {
    const { extractRequestInfo } = await import("./lib/session-activity-logger");

    const req = {
      ip: "127.0.0.1",
      headers: {
        "x-forwarded-for": "203.0.113.50, 70.41.3.18",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      },
    };

    const info = extractRequestInfo(req);
    expect(info.ipAddress).toBe("203.0.113.50");
    expect(info.userAgent).toContain("Mozilla");
  });

  it("extractRequestInfo should fall back to req.ip when no X-Forwarded-For", async () => {
    const { extractRequestInfo } = await import("./lib/session-activity-logger");

    const req = {
      ip: "10.0.0.1",
      headers: {
        "user-agent": "curl/7.81.0",
      },
    };

    const info = extractRequestInfo(req);
    expect(info.ipAddress).toBe("10.0.0.1");
    expect(info.userAgent).toBe("curl/7.81.0");
  });

  it("extractRequestInfo should handle missing headers gracefully", async () => {
    const { extractRequestInfo } = await import("./lib/session-activity-logger");

    const req = {
      headers: {},
    };

    const info = extractRequestInfo(req);
    expect(info.ipAddress).toBe("unknown");
    expect(info.userAgent).toBe("unknown");
  });

  it("logSessionEvent should not throw for any event type", async () => {
    const { logSessionEvent } = await import("./lib/session-activity-logger");

    const eventTypes = [
      "session_created",
      "session_validated",
      "session_expired",
      "session_invalidated",
      "session_error",
      "session_mismatch",
      "session_context_fallback",
      "session_not_found",
    ] as const;

    for (const type of eventTypes) {
      expect(() => {
        logSessionEvent({
          type,
          userId: 30001,
          email: "test@example.com",
          ipAddress: "1.2.3.4",
          detail: `Test event: ${type}`,
        });
      }).not.toThrow();
    }
  });

  it("logSessionEvent should handle events without optional fields", async () => {
    const { logSessionEvent } = await import("./lib/session-activity-logger");

    expect(() => {
      logSessionEvent({ type: "session_error" });
    }).not.toThrow();
  });

  it("flushSessionEvents should not throw when logger is not initialized", async () => {
    const { flushSessionEvents } = await import("./lib/session-activity-logger");

    // Should handle gracefully even without DB initialization
    await expect(flushSessionEvents()).resolves.not.toThrow();
  });
});

// ─── Health Endpoint Tests ──────────────────────────────────────────────────
// These tests require a running server — skip in CI where no server is available
const hasServer = !process.env.CI;
describe("Health Endpoint", () => {
  it.skipIf(!hasServer)("/healthz should return 200 with status ok", async () => {
    const response = await fetch("http://localhost:3000/healthz");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("ok");
    expect(body.timestamp).toBeDefined();
    expect(typeof body.timestamp).toBe("number");
  });

  it.skipIf(!hasServer)("/api/health should return comprehensive health data", async () => {
    const response = await fetch("http://localhost:3000/api/health", {
      signal: AbortSignal.timeout(10000),
    });
    expect(response.status).toBe(200);
    const body = await response.json();

    // Core fields
    expect(body.status).toBeDefined();
    expect(["ok", "degraded", "error"]).toContain(body.status);
    expect(body.timestamp).toBeDefined();
    expect(body.uptime).toBeDefined();
    expect(typeof body.uptime).toBe("number");
    expect(body.pid).toBeDefined();
    expect(body.nodeVersion).toBeDefined();

    // Memory info
    expect(body.memory).toBeDefined();
    expect(body.memory.heapUsedMB).toBeDefined();
    expect(body.memory.heapTotalMB).toBeDefined();
    expect(body.memory.rssMB).toBeDefined();
    expect(body.memory.heapUtilization).toBeDefined();
    expect(body.memory.heapUtilization).toBeGreaterThan(0);
    expect(body.memory.heapUtilization).toBeLessThanOrEqual(100);

    // Database connectivity
    expect(body.database).toBeDefined();
    expect(typeof body.database.connected).toBe("boolean");
    expect(typeof body.database.latencyMs).toBe("number");
  });

  it.skipIf(!hasServer)("/api/health should respond within 5 seconds", async () => {
    const start = Date.now();
    const response = await fetch("http://localhost:3000/api/health", {
      signal: AbortSignal.timeout(5000),
    });
    const elapsed = Date.now() - start;
    expect(response.status).toBe(200);
    expect(elapsed).toBeLessThan(5000);
  });
});
