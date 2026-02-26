/**
 * Agent Heartbeat & Watchdog Service Tests
 *
 * Tests heartbeat processing, state transitions, and watchdog sweep logic.
 * The mocks must match the import paths as resolved from the *source* file
 * (server/lib/agent-heartbeat.ts), which uses:
 *   - "../db" → server/db
 *   - "../../drizzle/schema" → drizzle/schema
 *   - "./fips-crypto" → server/lib/fips-crypto
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Shared mock state ──────────────────────────────────────────────────

let mockAgentRows: any[];
let mockUpdatedSets: Record<string, any>;
let mockInsertedRows: any[];

// ─── Mock drizzle-orm (must come before any imports that use it) ────────

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((field, value) => ({ _type: "eq", field, value })),
  and: vi.fn((...args: any[]) => ({ _type: "and", args })),
  sql: Object.assign(vi.fn(), { raw: vi.fn() }),
  lte: vi.fn((a, b) => ({ _type: "lte", a, b })),
  inArray: vi.fn((field, values) => ({ _type: "inArray", field, values })),
}));

// ─── Mock drizzle schema ────────────────────────────────────────────────

vi.mock("../../drizzle/schema", () => ({
  agentDeployments: {
    id: "agent_deployments.id",
    status: "agent_deployments.status",
    lastHeartbeat: "agent_deployments.lastHeartbeat",
    watchdogSeconds: "agent_deployments.watchdogSeconds",
    deployedAt: "agent_deployments.deployedAt",
  },
  agentAuditLog: {
    agentId: "agent_audit_log.agentId",
    recordHash: "agent_audit_log.recordHash",
  },
}));

// ─── Mock FIPS crypto ───────────────────────────────────────────────────

vi.mock("./lib/fips-crypto", () => ({
  getFIPSCrypto: () => ({
    hmac: (data: string) => ({ mac: "mock-hmac-" + Date.now() }),
  }),
}));

// ─── Mock DB ────────────────────────────────────────────────────────────
// The source imports `getDb` from `../db` (relative to server/lib/).
// vi.mock resolves relative to the *test* file (server/), so we use `./db`.

vi.mock("./db", () => ({
  getDb: vi.fn(async () => {
    // Build a chainable mock that captures calls
    const makeSelectChain = () => ({
      from: () => ({
        where: (condition: any) => {
          // Watchdog sweep: inArray query
          if (condition?._type === "inArray") {
            return Promise.resolve(
              mockAgentRows.filter((a) =>
                condition.values?.includes?.(a.status) ?? ["active", "paused"].includes(a.status)
              )
            );
          }
          // Single agent lookup by eq
          if (condition?._type === "eq") {
            const matches = mockAgentRows.filter((a) => a.id === condition.value);
            // Return array directly (for .select().from().where() without .limit())
            return Object.assign(Promise.resolve(matches), {
              orderBy: () => ({
                limit: () => Promise.resolve([]),
              }),
              limit: () => Promise.resolve(matches),
            });
          }
          return Object.assign(Promise.resolve([]), {
            orderBy: () => ({
              limit: () => Promise.resolve([]),
            }),
            limit: () => Promise.resolve([]),
          });
        },
      }),
    });

    return {
      select: () => makeSelectChain(),
      insert: () => ({
        values: (row: any) => {
          mockInsertedRows.push(row);
          return Promise.resolve(undefined);
        },
      }),
      update: () => ({
        set: (data: any) => ({
          where: (condition: any) => {
            const id = condition?.value ?? "unknown";
            mockUpdatedSets[id] = { ...mockUpdatedSets[id], ...data };
            return Promise.resolve(undefined);
          },
        }),
      }),
    };
  }),
}));

// ─── Import SUT ─────────────────────────────────────────────────────────

import {
  processHeartbeat,
  runWatchdogSweep,
  type HeartbeatPayload,
} from "./lib/agent-heartbeat";

// ─── Tests ──────────────────────────────────────────────────────────────

describe("Agent Heartbeat Service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAgentRows = [];
    mockUpdatedSets = {};
    mockInsertedRows = [];
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ─── Heartbeat Processing ──────────────────────────────────────────

  describe("processHeartbeat", () => {
    it("should reject heartbeat for non-existent agent", async () => {
      const result = await processHeartbeat({ agentId: "nonexistent" });

      expect(result.accepted).toBe(false);
      expect(result.message).toContain("Agent not found");
    });

    it("should accept heartbeat and transition approved → active", async () => {
      mockAgentRows = [{
        id: "agent-1",
        status: "approved",
        lastHeartbeat: null,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({
        agentId: "agent-1",
        platform: "linux",
        hostname: "target-host",
      });

      expect(result.accepted).toBe(true);
      expect(result.previousStatus).toBe("approved");
      expect(result.newStatus).toBe("active");
      expect(result.message).toContain("First beacon");
    });

    it("should accept heartbeat and transition deploying → active", async () => {
      mockAgentRows = [{
        id: "agent-2",
        status: "deploying",
        lastHeartbeat: null,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({ agentId: "agent-2" });

      expect(result.accepted).toBe(true);
      expect(result.previousStatus).toBe("deploying");
      expect(result.newStatus).toBe("active");
    });

    it("should accept heartbeat and transition lost → active (reconnection)", async () => {
      mockAgentRows = [{
        id: "agent-3",
        status: "lost",
        lastHeartbeat: Date.now() - 3600_000,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({ agentId: "agent-3" });

      expect(result.accepted).toBe(true);
      expect(result.previousStatus).toBe("lost");
      expect(result.newStatus).toBe("active");
      expect(result.message).toContain("reconnected");
    });

    it("should accept heartbeat for active agent (normal heartbeat)", async () => {
      mockAgentRows = [{
        id: "agent-4",
        status: "active",
        lastHeartbeat: Date.now() - 30_000,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({ agentId: "agent-4" });

      expect(result.accepted).toBe(true);
      expect(result.previousStatus).toBe("active");
      expect(result.newStatus).toBe("active");
      expect(result.message).toBe("Heartbeat accepted");
    });

    it("should reject heartbeat from terminated agent", async () => {
      mockAgentRows = [{
        id: "agent-5",
        status: "terminated",
        lastHeartbeat: Date.now() - 60_000,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({ agentId: "agent-5" });

      expect(result.accepted).toBe(false);
      expect(result.message).toContain("terminal state");
    });

    it("should reject heartbeat from completed agent", async () => {
      mockAgentRows = [{
        id: "agent-6",
        status: "completed",
        lastHeartbeat: Date.now() - 60_000,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({ agentId: "agent-6" });

      expect(result.accepted).toBe(false);
      expect(result.message).toContain("terminal state");
    });

    it("should reject heartbeat from failed agent", async () => {
      mockAgentRows = [{
        id: "agent-7",
        status: "failed",
        lastHeartbeat: null,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({ agentId: "agent-7" });

      expect(result.accepted).toBe(false);
      expect(result.message).toContain("terminal state");
    });

    it("should accept heartbeat for paused agent without changing status", async () => {
      mockAgentRows = [{
        id: "agent-8",
        status: "paused",
        lastHeartbeat: Date.now() - 30_000,
        watchdogSeconds: 14400,
      }];

      const result = await processHeartbeat({ agentId: "agent-8" });

      expect(result.accepted).toBe(true);
      expect(result.previousStatus).toBe("paused");
    });

    it("should update system info from payload", async () => {
      mockAgentRows = [{
        id: "agent-9",
        status: "active",
        lastHeartbeat: Date.now() - 30_000,
        watchdogSeconds: 14400,
      }];

      const payload: HeartbeatPayload = {
        agentId: "agent-9",
        platform: "windows",
        architecture: "x64",
        username: "SYSTEM",
        privilege: "elevated",
        pid: 1234,
        hostname: "WIN-TARGET",
        internalIp: "192.168.1.100",
        ipAddress: "203.0.113.50",
        userAgent: "Sandcat/5.0",
      };

      const result = await processHeartbeat(payload);

      expect(result.accepted).toBe(true);
      const update = mockUpdatedSets["agent-9"];
      expect(update).toBeDefined();
      expect(update.agentPlatform).toBe("windows");
      expect(update.agentArchitecture).toBe("x64");
      expect(update.agentUsername).toBe("SYSTEM");
      expect(update.agentPrivilege).toBe("elevated");
      expect(update.agentPid).toBe(1234);
      expect(update.targetHostname).toBe("WIN-TARGET");
      expect(update.targetIp).toBe("192.168.1.100");
    });

    it("should create audit log entry for heartbeat", async () => {
      mockAgentRows = [{
        id: "agent-10",
        status: "active",
        lastHeartbeat: Date.now() - 30_000,
        watchdogSeconds: 14400,
      }];

      await processHeartbeat({ agentId: "agent-10" });

      const heartbeatLogs = mockInsertedRows.filter((r) => r.eventType === "heartbeat");
      expect(heartbeatLogs.length).toBeGreaterThan(0);
      expect(heartbeatLogs[0].agentId).toBe("agent-10");
    });

    it("should create reconnected audit log for lost → active", async () => {
      mockAgentRows = [{
        id: "agent-11",
        status: "lost",
        lastHeartbeat: Date.now() - 3600_000,
        watchdogSeconds: 14400,
      }];

      await processHeartbeat({ agentId: "agent-11" });

      const reconnectLogs = mockInsertedRows.filter((r) => r.eventType === "reconnected");
      expect(reconnectLogs.length).toBeGreaterThan(0);
      expect(reconnectLogs[0].agentId).toBe("agent-11");
    });
  });

  // ─── Watchdog Sweep ────────────────────────────────────────────────

  describe("runWatchdogSweep", () => {
    it("should return empty results when no active agents exist", async () => {
      const result = await runWatchdogSweep();

      expect(result.scannedAgents).toBe(0);
      expect(result.markedLost).toBe(0);
      expect(result.lostAgentIds).toHaveLength(0);
    });

    it("should not mark agents as lost when heartbeats are recent", async () => {
      mockAgentRows = [
        {
          id: "agent-healthy-1",
          status: "active",
          lastHeartbeat: Date.now() - 30_000,
          watchdogSeconds: 14400,
          deployedAt: Date.now() - 86400_000,
        },
        {
          id: "agent-healthy-2",
          status: "active",
          lastHeartbeat: Date.now() - 60_000,
          watchdogSeconds: 3600,
          deployedAt: Date.now() - 86400_000,
        },
      ];

      const result = await runWatchdogSweep();

      expect(result.scannedAgents).toBe(2);
      expect(result.markedLost).toBe(0);
    });

    it("should mark agents as lost when heartbeat exceeds watchdog threshold", async () => {
      const now = Date.now();
      mockAgentRows = [{
        id: "agent-stale-1",
        status: "active",
        lastHeartbeat: now - 20_000_000,
        watchdogSeconds: 14400,
        deployedAt: now - 86400_000,
      }];

      const result = await runWatchdogSweep();

      expect(result.scannedAgents).toBe(1);
      expect(result.markedLost).toBe(1);
      expect(result.lostAgentIds).toContain("agent-stale-1");
    });

    it("should use deployedAt when lastHeartbeat is null", async () => {
      const now = Date.now();
      mockAgentRows = [{
        id: "agent-no-hb",
        status: "active",
        lastHeartbeat: null,
        watchdogSeconds: 3600,
        deployedAt: now - 7200_000,
      }];

      const result = await runWatchdogSweep();

      expect(result.markedLost).toBe(1);
      expect(result.lostAgentIds).toContain("agent-no-hb");
    });

    it("should handle mixed healthy and stale agents", async () => {
      const now = Date.now();
      mockAgentRows = [
        {
          id: "agent-ok",
          status: "active",
          lastHeartbeat: now - 30_000,
          watchdogSeconds: 14400,
          deployedAt: now - 86400_000,
        },
        {
          id: "agent-stale",
          status: "active",
          lastHeartbeat: now - 50_000_000,
          watchdogSeconds: 14400,
          deployedAt: now - 86400_000,
        },
        {
          id: "agent-paused-stale",
          status: "paused",
          lastHeartbeat: now - 100_000_000,
          watchdogSeconds: 14400,
          deployedAt: now - 172800_000,
        },
      ];

      const result = await runWatchdogSweep();

      expect(result.scannedAgents).toBe(3);
      expect(result.markedLost).toBe(2);
      expect(result.lostAgentIds).toContain("agent-stale");
      expect(result.lostAgentIds).toContain("agent-paused-stale");
      expect(result.lostAgentIds).not.toContain("agent-ok");
    });

    it("should create lost audit log entries for stale agents", async () => {
      const now = Date.now();
      mockAgentRows = [{
        id: "agent-going-lost",
        status: "active",
        lastHeartbeat: now - 20_000_000,
        watchdogSeconds: 14400,
        deployedAt: now - 86400_000,
      }];

      await runWatchdogSweep();

      const lostLogs = mockInsertedRows.filter((r) => r.eventType === "lost");
      expect(lostLogs.length).toBeGreaterThan(0);
      expect(lostLogs[0].agentId).toBe("agent-going-lost");
    });
  });
});
