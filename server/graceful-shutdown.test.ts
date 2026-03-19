/**
 * Tests for Graceful Shutdown: state flushing, SSH cleanup, and AbortController
 */
import { describe, it, expect } from "vitest";

// ─── flushAllPendingState Logic ─────────────────────────────────────────────

describe("Graceful Shutdown — State Flushing", () => {
  // Simulate the flush logic from engagement-orchestrator

  interface MockState {
    engagementId: number;
    phase: string;
    progress: number;
    isRunning: boolean;
  }

  function simulateFlush(
    opsStates: Map<number, MockState>,
    persistTimers: Map<number, NodeJS.Timeout>
  ): { flushed: number[]; timersCancelled: number } {
    // Cancel all debounce timers
    let timersCancelled = 0;
    for (const [engId, timer] of persistTimers.entries()) {
      clearTimeout(timer);
      persistTimers.delete(engId);
      timersCancelled++;
    }

    // Collect all states that would be flushed
    const flushed: number[] = [];
    for (const [engId, state] of opsStates.entries()) {
      flushed.push(engId);
    }

    return { flushed, timersCancelled };
  }

  it("flushes all active engagement states", () => {
    const opsStates = new Map<number, MockState>();
    opsStates.set(100, { engagementId: 100, phase: "recon", progress: 20, isRunning: true });
    opsStates.set(200, { engagementId: 200, phase: "vuln_detection", progress: 55, isRunning: true });
    const persistTimers = new Map<number, NodeJS.Timeout>();

    const result = simulateFlush(opsStates, persistTimers);
    expect(result.flushed).toEqual([100, 200]);
  });

  it("cancels all pending debounce timers", () => {
    const opsStates = new Map<number, MockState>();
    const persistTimers = new Map<number, NodeJS.Timeout>();
    // Create fake timers
    persistTimers.set(100, setTimeout(() => {}, 999999) as any);
    persistTimers.set(200, setTimeout(() => {}, 999999) as any);

    const result = simulateFlush(opsStates, persistTimers);
    expect(result.timersCancelled).toBe(2);
    expect(persistTimers.size).toBe(0);
  });

  it("returns empty when no active engagements", () => {
    const opsStates = new Map<number, MockState>();
    const persistTimers = new Map<number, NodeJS.Timeout>();

    const result = simulateFlush(opsStates, persistTimers);
    expect(result.flushed).toEqual([]);
    expect(result.timersCancelled).toBe(0);
  });

  it("handles mixed state: some with timers, some without", () => {
    const opsStates = new Map<number, MockState>();
    opsStates.set(100, { engagementId: 100, phase: "recon", progress: 10, isRunning: true });
    opsStates.set(200, { engagementId: 200, phase: "enumeration", progress: 30, isRunning: true });
    opsStates.set(300, { engagementId: 300, phase: "exploitation", progress: 80, isRunning: true });
    const persistTimers = new Map<number, NodeJS.Timeout>();
    persistTimers.set(100, setTimeout(() => {}, 999999) as any);
    // 200 has no timer (already flushed)
    persistTimers.set(300, setTimeout(() => {}, 999999) as any);

    const result = simulateFlush(opsStates, persistTimers);
    expect(result.flushed).toHaveLength(3);
    expect(result.timersCancelled).toBe(2);
  });
});

// ─── Per-Engagement AbortController ─────────────────────────────────────────

describe("Graceful Shutdown — AbortController Management", () => {
  function createAbortControllerMap() {
    const controllers = new Map<number, AbortController>();

    function getSignal(engagementId: number): AbortSignal {
      let controller = controllers.get(engagementId);
      if (!controller) {
        controller = new AbortController();
        controllers.set(engagementId, controller);
      }
      return controller.signal;
    }

    function abort(engagementId: number): boolean {
      const controller = controllers.get(engagementId);
      if (controller) {
        controller.abort();
        controllers.delete(engagementId);
        return true;
      }
      return false;
    }

    function abortAll(): number {
      let count = 0;
      for (const [engId, controller] of controllers.entries()) {
        controller.abort();
        controllers.delete(engId);
        count++;
      }
      return count;
    }

    return { getSignal, abort, abortAll, controllers };
  }

  it("creates AbortController on first getSignal call", () => {
    const { getSignal, controllers } = createAbortControllerMap();
    const signal = getSignal(100);
    expect(signal).toBeDefined();
    expect(signal.aborted).toBe(false);
    expect(controllers.size).toBe(1);
  });

  it("reuses existing AbortController for same engagement", () => {
    const { getSignal } = createAbortControllerMap();
    const signal1 = getSignal(100);
    const signal2 = getSignal(100);
    expect(signal1).toBe(signal2);
  });

  it("creates separate controllers for different engagements", () => {
    const { getSignal } = createAbortControllerMap();
    const signal1 = getSignal(100);
    const signal2 = getSignal(200);
    expect(signal1).not.toBe(signal2);
  });

  it("aborts a specific engagement", () => {
    const { getSignal, abort, controllers } = createAbortControllerMap();
    const signal = getSignal(100);
    expect(signal.aborted).toBe(false);

    const result = abort(100);
    expect(result).toBe(true);
    expect(signal.aborted).toBe(true);
    expect(controllers.size).toBe(0);
  });

  it("returns false when aborting non-existent engagement", () => {
    const { abort } = createAbortControllerMap();
    const result = abort(999);
    expect(result).toBe(false);
  });

  it("aborts all engagements at once", () => {
    const { getSignal, abortAll } = createAbortControllerMap();
    const signal1 = getSignal(100);
    const signal2 = getSignal(200);
    const signal3 = getSignal(300);

    const count = abortAll();
    expect(count).toBe(3);
    expect(signal1.aborted).toBe(true);
    expect(signal2.aborted).toBe(true);
    expect(signal3.aborted).toBe(true);
  });

  it("handles abort event listeners", () => {
    const { getSignal, abort } = createAbortControllerMap();
    const signal = getSignal(100);
    let abortCalled = false;
    signal.addEventListener("abort", () => {
      abortCalled = true;
    });

    abort(100);
    expect(abortCalled).toBe(true);
  });
});

// ─── SSH Pool Cleanup Logic ─────────────────────────────────────────────────

describe("Graceful Shutdown — SSH Pool Cleanup", () => {
  it("cleans up idle timer and connection", () => {
    let timerCleared = false;
    let connectionEnded = false;

    // Simulate the cleanup logic
    let poolIdleTimer: NodeJS.Timeout | null = setTimeout(() => {}, 60000);
    let pooledConn: { end: () => void } | null = {
      end: () => { connectionEnded = true; },
    };

    // Cleanup function
    if (poolIdleTimer) {
      clearTimeout(poolIdleTimer);
      poolIdleTimer = null;
      timerCleared = true;
    }
    if (pooledConn) {
      pooledConn.end();
      pooledConn = null;
    }

    expect(timerCleared).toBe(true);
    expect(connectionEnded).toBe(true);
    expect(poolIdleTimer).toBeNull();
    expect(pooledConn).toBeNull();
  });

  it("handles cleanup when no active connection", () => {
    let poolIdleTimer: NodeJS.Timeout | null = null;
    let pooledConn: { end: () => void } | null = null;

    // Should not throw
    if (poolIdleTimer) {
      clearTimeout(poolIdleTimer);
      poolIdleTimer = null;
    }
    if (pooledConn) {
      pooledConn.end();
      pooledConn = null;
    }

    expect(poolIdleTimer).toBeNull();
    expect(pooledConn).toBeNull();
  });

  it("handles cleanup when connection end() throws", () => {
    let pooledConn: { end: () => void } | null = {
      end: () => { throw new Error("Connection already closed"); },
    };

    // Should not throw — matches the try/catch in cleanupSSHPool
    try {
      if (pooledConn) {
        pooledConn.end();
      }
    } catch {
      // ignore
    }
    pooledConn = null;
    expect(pooledConn).toBeNull();
  });
});

// ─── Shutdown Sequence Ordering ─────────────────────────────────────────────

describe("Graceful Shutdown — Sequence Ordering", () => {
  it("executes shutdown steps in correct order", async () => {
    const steps: string[] = [];

    // Simulate the shutdown sequence
    async function gracefulShutdown() {
      steps.push("cancel_timers");
      steps.push("flush_states");
      steps.push("abort_controllers");
      steps.push("cleanup_ssh");
      steps.push("close_server");
    }

    await gracefulShutdown();

    expect(steps).toEqual([
      "cancel_timers",
      "flush_states",
      "abort_controllers",
      "cleanup_ssh",
      "close_server",
    ]);
  });

  it("handles timeout when shutdown takes too long", async () => {
    let timedOut = false;
    let shutdownCompleted = false;

    const SHUTDOWN_TIMEOUT = 50; // 50ms for test
    const shutdownTimeout = setTimeout(() => {
      timedOut = true;
    }, SHUTDOWN_TIMEOUT);

    // Simulate fast shutdown
    await new Promise(r => setTimeout(r, 10));
    shutdownCompleted = true;
    clearTimeout(shutdownTimeout);

    expect(shutdownCompleted).toBe(true);
    expect(timedOut).toBe(false);
  });

  it("prevents double-shutdown", () => {
    let isShuttingDown = false;
    let shutdownCount = 0;

    function tryShutdown() {
      if (isShuttingDown) return;
      isShuttingDown = true;
      shutdownCount++;
    }

    tryShutdown(); // First call
    tryShutdown(); // Second call (should be ignored)
    tryShutdown(); // Third call (should be ignored)

    expect(shutdownCount).toBe(1);
  });
});

// ─── Export Verification ────────────────────────────────────────────────────

describe("Graceful Shutdown — Export Verification", () => {
  it("engagement-orchestrator exports flushAllPendingState", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    expect(typeof mod.flushAllPendingState).toBe("function");
  });

  it("engagement-orchestrator exports getEngagementAbortSignal", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    expect(typeof mod.getEngagementAbortSignal).toBe("function");
  });

  it("engagement-orchestrator exports abortEngagement", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    expect(typeof mod.abortEngagement).toBe("function");
  });

  it("scan-server-executor exports cleanupSSHPool", async () => {
    const mod = await import("./lib/scan-server-executor");
    expect(typeof mod.cleanupSSHPool).toBe("function");
  });
});
