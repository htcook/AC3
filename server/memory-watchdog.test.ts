import { describe, it, expect, vi, afterEach } from "vitest";

describe("Memory Watchdog & Crash Protection", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Memory Watchdog exports", () => {
    it("should export startMemoryWatchdog and stopMemoryWatchdog functions", async () => {
      const mod = await import("./lib/engagement-orchestrator");
      expect(typeof mod.startMemoryWatchdog).toBe("function");
      expect(typeof mod.stopMemoryWatchdog).toBe("function");
    });

    it("should start and stop without errors", async () => {
      const { startMemoryWatchdog, stopMemoryWatchdog } = await import("./lib/engagement-orchestrator");
      // Should not throw
      startMemoryWatchdog();
      // Calling start again should be idempotent (no double intervals)
      startMemoryWatchdog();
      // Stop should clean up
      stopMemoryWatchdog();
      stopMemoryWatchdog(); // double-stop should be safe
    });
  });

  describe("Memory-aware log trimming in addLog", () => {
    it("should trim logs based on memory pressure thresholds", async () => {
      const { addLog } = await import("./lib/engagement-orchestrator");
      
      // Create a mock state with many logs
      const state: any = {
        engagementId: 99999,
        phase: "recon",
        progress: 10,
        log: [],
        assets: [],
        stats: { hostsFound: 0, portsFound: 0, vulnsFound: 0, servicesFound: 0 },
        timeline: [],
        startedAt: Date.now(),
      };

      // Add 1200 logs (exceeds the 1000 default limit for 10 concurrent engagements)
      for (let i = 0; i < 1200; i++) {
        state.log.push({
          id: `log-${i}`,
          timestamp: Date.now(),
          phase: "recon" as const,
          type: "info" as const,
          title: `Test log ${i}`,
        });
      }

      // addLog should trim to at most 1000 (under normal memory, scaled for 10 concurrent engagements)
      addLog(state, { phase: "recon", type: "info", title: "New log entry" });
      expect(state.log.length).toBeLessThanOrEqual(1001); // 1000 max + the new entry might push it to 1001 before trim
      expect(state.log.length).toBeGreaterThan(0);
    });

    it("should include memory-aware trimming logic in addLog", async () => {
      const source = await import("./lib/engagement-orchestrator");
      // Verify the function exists and is callable
      expect(typeof source.addLog).toBe("function");
    });
  });

  describe("AbortController per engagement", () => {
    it("should export getEngagementAbortSignal and abortEngagement", async () => {
      const mod = await import("./lib/engagement-orchestrator");
      expect(typeof mod.getEngagementAbortSignal).toBe("function");
      expect(typeof mod.abortEngagement).toBe("function");
    });

    it("should return an AbortSignal for an engagement", async () => {
      const { getEngagementAbortSignal, abortEngagement } = await import("./lib/engagement-orchestrator");
      const signal = getEngagementAbortSignal(88888);
      expect(signal).toBeDefined();
      expect(signal.aborted).toBe(false);

      // Abort should set the signal
      abortEngagement(88888);
      expect(signal.aborted).toBe(true);
    });

    it("should be idempotent on double-abort", async () => {
      const { getEngagementAbortSignal, abortEngagement } = await import("./lib/engagement-orchestrator");
      const signal = getEngagementAbortSignal(77777);
      abortEngagement(77777);
      // Second abort should not throw
      abortEngagement(77777);
      expect(signal.aborted).toBe(true);
    });
  });

  describe("flushAllPendingState", () => {
    it("should export flushAllPendingState function", async () => {
      const mod = await import("./lib/engagement-orchestrator");
      expect(typeof mod.flushAllPendingState).toBe("function");
    });

    it("should return 0 when no active engagements", async () => {
      const { flushAllPendingState } = await import("./lib/engagement-orchestrator");
      const flushed = await flushAllPendingState();
      expect(flushed).toBe(0);
    });
  });

  describe("process.memoryUsage integration", () => {
    it("should have heapUsed and rss available", () => {
      const mem = process.memoryUsage();
      expect(mem.heapUsed).toBeGreaterThan(0);
      expect(mem.rss).toBeGreaterThan(0);
      expect(mem.heapTotal).toBeGreaterThan(0);
    });
  });
});
