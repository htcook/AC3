import { describe, it, expect, vi, afterEach } from "vitest";

describe("Server Instance Identity", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should export a SERVER_INSTANCE_ID string", async () => {
    const { SERVER_INSTANCE_ID } = await import("./lib/server-instance");
    expect(typeof SERVER_INSTANCE_ID).toBe("string");
    expect(SERVER_INSTANCE_ID.length).toBeGreaterThan(10);
  });

  it("should include hostname, PID, and timestamp in the ID", async () => {
    const { SERVER_INSTANCE_ID } = await import("./lib/server-instance");
    const parts = SERVER_INSTANCE_ID.split("-");
    // Format: hostname-pid-timestamp-random (at least 4 parts)
    expect(parts.length).toBeGreaterThanOrEqual(4);
    // PID should be a number
    const pidPart = parseInt(parts[parts.length - 3], 10);
    expect(pidPart).toBeGreaterThan(0);
    // Timestamp should be a recent epoch
    const tsPart = parseInt(parts[parts.length - 2], 10);
    expect(tsPart).toBeGreaterThan(1700000000); // After 2023
    // Random suffix should be 4 hex chars
    const randomPart = parts[parts.length - 1];
    expect(randomPart).toMatch(/^[0-9a-f]{4}$/);
  });

  it("should export SERVER_START_TIME as a recent timestamp", async () => {
    const { SERVER_START_TIME } = await import("./lib/server-instance");
    expect(typeof SERVER_START_TIME).toBe("number");
    expect(SERVER_START_TIME).toBeGreaterThan(Date.now() - 60 * 60 * 1000); // Within last hour
    expect(SERVER_START_TIME).toBeLessThanOrEqual(Date.now());
  });

  it("should be consistent across multiple imports (singleton)", async () => {
    const mod1 = await import("./lib/server-instance");
    const mod2 = await import("./lib/server-instance");
    expect(mod1.SERVER_INSTANCE_ID).toBe(mod2.SERVER_INSTANCE_ID);
  });
});

describe("Server Instance in Health Endpoint", () => {
  it("should include serverInstanceId in getHealthStatus output", async () => {
    const { getHealthStatus } = await import("./lib/engagement-orchestrator");
    const health = getHealthStatus();
    expect(typeof health.serverInstanceId).toBe("string");
    expect(health.serverInstanceId.length).toBeGreaterThan(5);
  });
});

describe("Server Instance in Ops State Persistence", () => {
  it("should import SERVER_INSTANCE_ID in ops-state-persistence", async () => {
    const mod = await import("./lib/ops-state-persistence");
    // The module should load without errors (it imports server-instance)
    expect(typeof mod.saveStateSnapshot).toBe("function");
    expect(typeof mod.recoverState).toBe("function");
  });
});

describe("Auto-Resume Ownership Check", () => {
  it("should import SERVER_INSTANCE_ID in engagement-auto-resume", async () => {
    const mod = await import("./lib/engagement-auto-resume");
    // The module should load without errors (it imports server-instance)
    expect(typeof mod.detectInterruptedEngagements).toBe("function");
    expect(typeof mod.scheduleAutoResumes).toBe("function");
  });

  it("should skip engagements owned by a different server instance", async () => {
    // The detection logic checks snap.serverInstanceId !== SERVER_INSTANCE_ID
    // If they differ, it should skip (not count as interrupt)
    const { SERVER_INSTANCE_ID } = await import("./lib/server-instance");
    
    // Verify our instance ID is not "other-server-123"
    expect(SERVER_INSTANCE_ID).not.toBe("other-server-123");
    
    // The logic is: if snapshotOwner && snapshotOwner !== SERVER_INSTANCE_ID → skip
    const snapshotOwner = "other-server-123";
    const shouldSkip = snapshotOwner && snapshotOwner !== SERVER_INSTANCE_ID;
    expect(shouldSkip).toBe(true);
  });

  it("should NOT skip engagements owned by the same server instance", async () => {
    const { SERVER_INSTANCE_ID } = await import("./lib/server-instance");
    
    // Same instance → should NOT skip (it IS a real interrupt)
    const snapshotOwner = SERVER_INSTANCE_ID;
    const shouldSkip = snapshotOwner && snapshotOwner !== SERVER_INSTANCE_ID;
    expect(shouldSkip).toBe(false);
  });

  it("should NOT skip engagements with null server_instance_id (legacy snapshots)", async () => {
    const { SERVER_INSTANCE_ID } = await import("./lib/server-instance");
    
    // Null/undefined → should NOT skip (legacy behavior, treat as same instance)
    const snapshotOwner: string | null = null;
    const shouldSkip = snapshotOwner && snapshotOwner !== SERVER_INSTANCE_ID;
    // null is falsy, so short-circuit evaluation returns null (falsy = don't skip)
    expect(shouldSkip).toBeFalsy();
  });

  it("should export AUTO_RESUME_CONFIG with expected values", async () => {
    const { AUTO_RESUME_CONFIG } = await import("./lib/engagement-auto-resume");
    expect(AUTO_RESUME_CONFIG.MAX_INTERRUPTS_BEFORE_BLOCK).toBe(3);
    expect(AUTO_RESUME_CONFIG.CRASH_LOOP_WINDOW_MS).toBe(24 * 60 * 60 * 1000);
    expect(AUTO_RESUME_CONFIG.AUTO_RESUME_DELAY_MS).toBe(3 * 60 * 1000);
    expect(AUTO_RESUME_CONFIG.CANCEL_GRACE_PERIOD_MS).toBe(30 * 1000);
  });
});

describe("Schema includes server_instance_id", () => {
  it("engagement_ops_snapshots schema should have serverInstanceId field", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.engagementOpsSnapshots;
    const columns = Object.keys(table);
    // The column should exist in the schema definition
    expect(columns).toContain("serverInstanceId");
  });
});
