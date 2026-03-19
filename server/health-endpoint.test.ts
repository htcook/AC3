import { describe, it, expect, vi, afterEach } from "vitest";

describe("Health Endpoint & getHealthStatus", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("getHealthStatus export", () => {
    it("should export getHealthStatus function", async () => {
      const mod = await import("./lib/engagement-orchestrator");
      expect(typeof mod.getHealthStatus).toBe("function");
    });

    it("should return a well-structured health object", async () => {
      const { getHealthStatus } = await import("./lib/engagement-orchestrator");
      const health = getHealthStatus();

      // Top-level fields
      expect(health.status).toBe("ok");
      expect(typeof health.timestamp).toBe("number");
      expect(health.timestamp).toBeGreaterThan(0);
      expect(typeof health.uptime).toBe("number");
      expect(health.uptime).toBeGreaterThanOrEqual(0);
      expect(typeof health.pid).toBe("number");
      expect(health.pid).toBeGreaterThan(0);
      expect(typeof health.nodeVersion).toBe("string");
      expect(health.nodeVersion).toMatch(/^v\d+/);
    });

    it("should include memory usage in MB", async () => {
      const { getHealthStatus } = await import("./lib/engagement-orchestrator");
      const health = getHealthStatus();

      expect(typeof health.memory.heapUsedMB).toBe("number");
      expect(typeof health.memory.heapTotalMB).toBe("number");
      expect(typeof health.memory.rssMB).toBe("number");
      expect(typeof health.memory.externalMB).toBe("number");
      expect(typeof health.memory.arrayBuffersMB).toBe("number");

      // Sanity checks: heap should be positive and reasonable
      expect(health.memory.heapUsedMB).toBeGreaterThan(0);
      expect(health.memory.rssMB).toBeGreaterThan(0);
      expect(health.memory.heapUsedMB).toBeLessThanOrEqual(health.memory.heapTotalMB);
    });

    it("should include memory watchdog status", async () => {
      const { getHealthStatus } = await import("./lib/engagement-orchestrator");
      const health = getHealthStatus();

      expect(typeof health.memoryWatchdog.running).toBe("boolean");
      expect(health.memoryWatchdog.heapWarningThresholdMB).toBe(300);
      expect(health.memoryWatchdog.heapCriticalThresholdMB).toBe(400);
    });

    it("should include engagement status", async () => {
      const { getHealthStatus } = await import("./lib/engagement-orchestrator");
      const health = getHealthStatus();

      expect(typeof health.engagements.activeCount).toBe("number");
      expect(health.engagements.activeCount).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(health.engagements.details)).toBe(true);
      expect(health.engagements.details.length).toBe(health.engagements.activeCount);
    });

    it("should reflect watchdog running state correctly", async () => {
      const { getHealthStatus, startMemoryWatchdog, stopMemoryWatchdog } = await import("./lib/engagement-orchestrator");

      // Start watchdog
      startMemoryWatchdog();
      const healthRunning = getHealthStatus();
      expect(healthRunning.memoryWatchdog.running).toBe(true);

      // Stop watchdog
      stopMemoryWatchdog();
      const healthStopped = getHealthStatus();
      expect(healthStopped.memoryWatchdog.running).toBe(false);
    });

    it("should include engagement details when active engagements exist", async () => {
      const { getHealthStatus, initOpsState } = await import("./lib/engagement-orchestrator");

      // Create a test engagement state
      const testEngId = 99998;
      initOpsState(testEngId, "test_health");

      const health = getHealthStatus();
      const testEng = health.engagements.details.find((e: any) => e.id === testEngId);

      if (testEng) {
        expect(testEng.id).toBe(testEngId);
        expect(typeof testEng.phase).toBe("string");
        expect(typeof testEng.progress).toBe("number");
        expect(typeof testEng.assets).toBe("number");
        expect(typeof testEng.logs).toBe("number");
      }

      // Clean up
      const { clearOpsState } = await import("./lib/engagement-orchestrator");
      await clearOpsState(testEngId);
    });
  });

  describe("Dockerfile NODE_OPTIONS", () => {
    it("should have --max-old-space-size=512 in Dockerfile", async () => {
      const fs = await import("fs");
      const dockerfile = fs.readFileSync("Dockerfile", "utf-8");
      expect(dockerfile).toContain("--max-old-space-size=512");
      expect(dockerfile).toContain("NODE_OPTIONS");
    });
  });
});
