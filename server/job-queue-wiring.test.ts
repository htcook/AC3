/**
 * Tests for:
 * 1. Job Queue Bridge (engagement-orchestrator wiring)
 * 2. WebSocket review queue events
 * 3. Redis DO Provisioner
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Job Queue Bridge Tests ─────────────────────────────────────────────────

describe("Job Queue Bridge", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("should export executeToolViaQueue function", async () => {
    const mod = await import("./lib/job-queue-bridge");
    expect(typeof mod.executeToolViaQueue).toBe("function");
  });

  it("should export executeRawCommandViaQueue function", async () => {
    const mod = await import("./lib/job-queue-bridge");
    expect(typeof mod.executeRawCommandViaQueue).toBe("function");
  });

  it("should fall back to SSH when no workers available", async () => {
    const mod = await import("./lib/job-queue-bridge");
    // With no Redis/workers configured, should fall back to direct SSH
    const result = await mod.executeToolViaQueue(
      { tool: "nmap", args: "--top-ports 10 127.0.0.1", timeoutSeconds: 30 },
      { engagementId: 1, roeScope: ["127.0.0.1"] }
    );
    // Should return a ToolExecResult-compatible object (even if SSH fails due to no server)
    expect(result).toHaveProperty("stdout");
    expect(result).toHaveProperty("stderr");
    expect(result).toHaveProperty("exitCode");
  });

  it("should enforce RoE scope in dispatch context", async () => {
    const mod = await import("./lib/job-queue-bridge");
    const context = { engagementId: 42, roeScope: ["example.com", "10.0.0.1"] };
    // The function should accept and pass through RoE scope
    expect(() =>
      mod.executeToolViaQueue(
        { tool: "httpx", args: "-json", timeoutSeconds: 60 },
        context
      )
    ).not.toThrow();
  });

  it("should handle raw command execution via queue", async () => {
    const mod = await import("./lib/job-queue-bridge");
    const result = await mod.executeRawCommandViaQueue(
      "echo hello 2>&1",
      30,
      { engagementId: 1 }
    );
    expect(result).toHaveProperty("stdout");
    expect(result).toHaveProperty("exitCode");
  });
});

// ─── Engagement Orchestrator Wiring Tests ───────────────────────────────────

describe("Engagement Orchestrator Job Queue Wiring", () => {
  it("should import job-queue-bridge in engagement-orchestrator", async () => {
    // Verify the import exists in the orchestrator file
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    expect(content).toContain("executeToolViaQueue");
    expect(content).toContain("executeRawCommandViaQueue");
    expect(content).toContain('from "./job-queue-bridge"');
  });

  it("should replace all direct executeTool imports with bridge calls", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Count remaining direct executeTool imports from scan-server-executor
    // There should be NO direct `const { executeTool } = await import("./scan-server-executor")`
    // Only suggestToolCommands and getScanServerConfigForNmap should remain
    const directImports = content.match(
      /const\s*\{\s*executeTool[^}]*\}\s*=\s*await\s+import\s*\(\s*["']\.\/scan-server-executor["']\s*\)/g
    );
    expect(directImports).toBeNull();
  });

  it("should use executeToolViaQueue for nmap execution", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    // The nmap execution should now go through the bridge
    expect(content).toContain("executeToolViaQueue(config, { engagementId: state.engagementId, roeScope");
  });

  it("should use executeRawCommandViaQueue for httpx pipe commands", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    expect(content).toContain("executeRawCommandViaQueue(cmd.command");
  });

  it("should build RoE scope from state for each phase", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    // Each phase should extract RoE scope from state
    const roeScopeExtractions = content.match(
      /\[\.\.\.?\(state\.roeScopeGuard\?\.authorizedDomains/g
    );
    // Should have at least 4 (Phase A, Phase B, Nuclei, Credential testing)
    expect(roeScopeExtractions?.length).toBeGreaterThanOrEqual(4);
  });

  it("should retain suggestToolCommands imports for LLM tool suggestion", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    // suggestToolCommands should still be imported from scan-server-executor
    expect(content).toContain("suggestToolCommands");
  });
});

// ─── WebSocket Review Queue Events Tests ────────────────────────────────────

describe("WebSocket Review Queue Events", () => {
  it("should export review queue emit functions", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitReviewItemCreated).toBe("function");
    expect(typeof mod.emitReviewItemApproved).toBe("function");
    expect(typeof mod.emitReviewItemRejected).toBe("function");
    expect(typeof mod.emitReviewItemDeferred).toBe("function");
    expect(typeof mod.emitReviewBulkApproved).toBe("function");
  });

  it("should export job queue emit functions", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitJobEnqueued).toBe("function");
    expect(typeof mod.emitJobDispatched).toBe("function");
    expect(typeof mod.emitJobCompleted).toBe("function");
    expect(typeof mod.emitJobFailed).toBe("function");
    expect(typeof mod.emitJobWorkerEvent).toBe("function");
  });

  it("should include review queue event types in WsEventType", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/ws-event-hub.ts", "utf-8");
    expect(content).toContain('"review:item_created"');
    expect(content).toContain('"review:item_approved"');
    expect(content).toContain('"review:item_rejected"');
    expect(content).toContain('"review:item_deferred"');
    expect(content).toContain('"review:bulk_approved"');
  });

  it("should include job queue event types in WsEventType", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/ws-event-hub.ts", "utf-8");
    expect(content).toContain('"job:enqueued"');
    expect(content).toContain('"job:dispatched"');
    expect(content).toContain('"job:completed"');
    expect(content).toContain('"job:failed"');
    expect(content).toContain('"job:worker_registered"');
    expect(content).toContain('"job:worker_lost"');
  });

  it("should call emit functions in review-queue router", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/review-queue.ts", "utf-8");
    expect(content).toContain("emitReviewItemCreated");
    expect(content).toContain("emitReviewItemApproved");
    expect(content).toContain("emitReviewItemRejected");
    expect(content).toContain("emitReviewItemDeferred");
    expect(content).toContain("emitReviewBulkApproved");
  });
});

// ─── Frontend WebSocket Hook Tests ──────────────────────────────────────────

describe("Frontend WebSocket Hooks", () => {
  it("should include review queue events in frontend WsEventType", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/hooks/useWebSocket.ts", "utf-8");
    expect(content).toContain('"review:item_created"');
    expect(content).toContain('"review:item_approved"');
    expect(content).toContain('"job:enqueued"');
    expect(content).toContain('"job:completed"');
  });

  it("should export useReviewQueueEvents hook", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/hooks/useWebSocket.ts", "utf-8");
    expect(content).toContain("export function useReviewQueueEvents");
  });

  it("should export useJobQueueEvents hook", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/hooks/useWebSocket.ts", "utf-8");
    expect(content).toContain("export function useJobQueueEvents");
  });

  it("should add review queue events to TOAST_EVENT_TYPES", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/hooks/useWebSocket.ts", "utf-8");
    expect(content).toContain('"review:item_created"');
    expect(content).toContain('"job:failed"');
    expect(content).toContain('"job:worker_lost"');
  });

  it("should add toast handlers for review queue events", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/hooks/useWebSocket.ts", "utf-8");
    expect(content).toContain('case "review:item_created"');
    expect(content).toContain('case "job:completed"');
    expect(content).toContain('case "job:failed"');
  });

  it("should wire WS events into ReviewQueue page", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/pages/ReviewQueue.tsx", "utf-8");
    expect(content).toContain("useReviewQueueEvents");
    expect(content).toContain("utils.reviewQueue.list.invalidate()");
  });

  it("should wire WS events into JobQueueDashboard page", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/pages/JobQueueDashboard.tsx", "utf-8");
    expect(content).toContain("useJobQueueEvents");
    expect(content).toContain("utils.jobQueue.stats.invalidate()");
  });
});

// ─── Redis DO Provisioner Tests ─────────────────────────────────────────────

describe("Redis DO Provisioner", () => {
  it("should export provisioning functions", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    expect(typeof mod.provisionRedisCluster).toBe("function");
    expect(typeof mod.getRedisCluster).toBe("function");
    expect(typeof mod.getRedisClusterStatus).toBe("function");
    expect(typeof mod.destroyRedisCluster).toBe("function");
    expect(typeof mod.ensureFipsVpc).toBe("function");
  });

  it("should export firewall management functions", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    expect(typeof mod.configureRedisFirewall).toBe("function");
    expect(typeof mod.getRedisFirewallRules).toBe("function");
    expect(typeof mod.lockdownRedisAccess).toBe("function");
  });

  it("should export health check function", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    expect(typeof mod.checkRedisHealth).toBe("function");
  });

  it("should export connection info builder", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    expect(typeof mod.buildRedisUrl).toBe("function");
    expect(typeof mod.getRedisClientConfig).toBe("function");
  });

  it("should build correct Redis URL from connection info", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    const connInfo = {
      host: "public.redis.example.com",
      port: 25061,
      password: "test-password",
      tls: true,
      uri: "rediss://default:test-password@public.redis.example.com:25061",
      privateHost: "private.redis.example.com",
      privateUri: "rediss://default:test-password@private.redis.example.com:25061",
      tlsOptions: {
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ciphers: "TLS_AES_256_GCM_SHA384",
      },
    };
    const url = mod.buildRedisUrl(connInfo);
    // Should prefer private URI
    expect(url).toBe("rediss://default:test-password@private.redis.example.com:25061");
  });

  it("should build fallback Redis URL when no private URI", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    const connInfo = {
      host: "public.redis.example.com",
      port: 25061,
      password: "test-password",
      tls: true,
      uri: "",
      privateHost: "private.redis.example.com",
      privateUri: "",
      tlsOptions: {
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ciphers: "TLS_AES_256_GCM_SHA384",
      },
    };
    const url = mod.buildRedisUrl(connInfo);
    expect(url).toContain("rediss://");
    expect(url).toContain("private.redis.example.com");
    expect(url).toContain("25061");
  });

  it("should generate FIPS-compliant TLS client config", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    const connInfo = {
      host: "redis.example.com",
      port: 25061,
      password: "pass",
      tls: true,
      uri: "rediss://default:pass@redis.example.com:25061",
      privateHost: "private.redis.example.com",
      privateUri: "rediss://default:pass@private.redis.example.com:25061",
      tlsOptions: {
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ciphers: "TLS_AES_256_GCM_SHA384",
      },
    };
    const config = mod.getRedisClientConfig(connInfo);
    expect(config.socket.tls).toBe(true);
    expect(config.socket.rejectUnauthorized).toBe(true);
    expect(config.socket.minVersion).toBe("TLSv1.2");
    expect(config.socket.ciphers).toContain("AES_256_GCM");
    expect(config.socket.connectTimeout).toBeGreaterThan(0);
    expect(config.socket.keepAlive).toBeGreaterThan(0);
  });

  it("should export full provisioning workflow", async () => {
    const mod = await import("./lib/redis-do-provisioner");
    expect(typeof mod.provisionAndSecureRedis).toBe("function");
  });
});
