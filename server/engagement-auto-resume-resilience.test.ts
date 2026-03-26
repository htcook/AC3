/**
 * Engagement Pipeline Resilience — Unit Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for:
 *   P1: Graceful shutdown timeout (15s)
 *   P2: Auto-resume with crash-loop guard
 *     - Interrupt counter tracking
 *     - Crash-loop detection (3+ interrupts in 24h window)
 *     - Crash-loop window reset (interrupts outside 24h)
 *     - Auto-resume eligibility (flag + canResume + no crash-loop)
 *     - Cancellation of scheduled auto-resumes
 *     - Interrupt counter reset
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── P1: Graceful Shutdown Timeout ─────────────────────────────────────────

describe("P1: Graceful Shutdown Timeout", () => {
  it("should use 15-second timeout instead of 5-second", async () => {
    // Read the index.ts file and verify the timeout value
    const fs = await import("fs");
    const path = await import("path");
    const indexPath = path.resolve(__dirname, "_core/index.ts");
    const content = fs.readFileSync(indexPath, "utf-8");

    // Verify the 15s timeout is set
    expect(content).toContain("Timeout after 15s, forcing exit");
    expect(content).toContain("}, 15000);");

    // Verify the old 5s timeout is NOT present
    expect(content).not.toContain("Timeout after 5s, forcing exit");
    expect(content).not.toContain("}, 5000);");
  });
});

// ─── P2: Crash-Loop Guard Logic ────────────────────────────────────────────

/** Constants matching the auto-resume module */
const MAX_INTERRUPTS_BEFORE_BLOCK = 10;
const CRASH_LOOP_WINDOW_MS = 24 * 60 * 60 * 1000;

interface SnapshotRecord {
  engagementId: number;
  isRunning: boolean;
  interruptCount: number;
  lastInterruptedAt: string | null;
  stateJson: any;
  phase: string;
  updatedAt: string;
}

interface EngagementRecord {
  id: number;
  autoResumeOnRestart: number;
}

/**
 * Simulate the crash-loop guard decision logic (extracted from engagement-auto-resume.ts).
 * Returns { shouldAutoResume, crashLoopBlocked, newInterruptCount }.
 */
function evaluateCrashLoopGuard(
  snapshot: SnapshotRecord,
  engagement: EngagementRecord,
): {
  shouldAutoResume: boolean;
  crashLoopBlocked: boolean;
  newInterruptCount: number;
  canResume: boolean;
} {
  const newInterruptCount = (snapshot.interruptCount || 0) + 1;

  // Parse state to determine canResume
  const state = typeof snapshot.stateJson === "string"
    ? JSON.parse(snapshot.stateJson)
    : snapshot.stateJson;
  const assetsCount = state?.assets?.length || 0;
  const phase = state?.phase || "unknown";
  const PHASE_ORDER = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"];
  const canResume = assetsCount > 0 && PHASE_ORDER.includes(phase);

  const autoResumeEnabled = engagement.autoResumeOnRestart === 1;

  // Crash-loop guard
  let crashLoopBlocked = false;
  if (newInterruptCount >= MAX_INTERRUPTS_BEFORE_BLOCK) {
    const lastInterruptedAt = snapshot.lastInterruptedAt
      ? new Date(snapshot.lastInterruptedAt).getTime()
      : 0;
    const windowStart = Date.now() - CRASH_LOOP_WINDOW_MS;
    if (lastInterruptedAt > windowStart) {
      crashLoopBlocked = true;
    }
    // If outside window, counter would be reset to 1 (handled by caller)
  }

  const shouldAutoResume = canResume && autoResumeEnabled && !crashLoopBlocked;

  return { shouldAutoResume, crashLoopBlocked, newInterruptCount, canResume };
}

describe("P2: Crash-Loop Guard", () => {
  const baseState = {
    phase: "vuln_detection",
    progress: 45,
    assets: [{ hostname: "test.lab" }, { hostname: "api.lab" }],
    stats: { vulnsFound: 50, portsFound: 20 },
  };

  const baseSnapshot: SnapshotRecord = {
    engagementId: 1,
    isRunning: true,
    interruptCount: 0,
    lastInterruptedAt: null,
    stateJson: baseState,
    phase: "vuln_detection",
    updatedAt: new Date().toISOString(),
  };

  const autoResumeEngagement: EngagementRecord = { id: 1, autoResumeOnRestart: 1 };
  const noAutoResumeEngagement: EngagementRecord = { id: 1, autoResumeOnRestart: 0 };

  it("should allow auto-resume on first interrupt when flag is enabled", () => {
    const result = evaluateCrashLoopGuard(baseSnapshot, autoResumeEngagement);
    expect(result.shouldAutoResume).toBe(true);
    expect(result.crashLoopBlocked).toBe(false);
    expect(result.newInterruptCount).toBe(1);
    expect(result.canResume).toBe(true);
  });

  it("should NOT auto-resume when flag is disabled", () => {
    const result = evaluateCrashLoopGuard(baseSnapshot, noAutoResumeEngagement);
    expect(result.shouldAutoResume).toBe(false);
    expect(result.crashLoopBlocked).toBe(false);
    expect(result.canResume).toBe(true);
  });

  it("should allow auto-resume on second interrupt (below threshold)", () => {
    const snap = { ...baseSnapshot, interruptCount: 1, lastInterruptedAt: new Date().toISOString() };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    expect(result.shouldAutoResume).toBe(true);
    expect(result.crashLoopBlocked).toBe(false);
    expect(result.newInterruptCount).toBe(2);
  });

  it("should BLOCK auto-resume on 10th interrupt within 24h window (crash-loop)", () => {
    const recentTime = new Date(Date.now() - 60 * 60 * 1000).toISOString(); // 1 hour ago
    const snap = { ...baseSnapshot, interruptCount: 9, lastInterruptedAt: recentTime };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    expect(result.shouldAutoResume).toBe(false);
    expect(result.crashLoopBlocked).toBe(true);
    expect(result.newInterruptCount).toBe(10);
  });

  it("should BLOCK auto-resume on 11th interrupt within 24h window", () => {
    const recentTime = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(); // 2 hours ago
    const snap = { ...baseSnapshot, interruptCount: 10, lastInterruptedAt: recentTime };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    expect(result.shouldAutoResume).toBe(false);
    expect(result.crashLoopBlocked).toBe(true);
    expect(result.newInterruptCount).toBe(11);
  });

  it("should NOT block when interrupts are outside the 24h window", () => {
    const oldTime = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(); // 25 hours ago
    const snap = { ...baseSnapshot, interruptCount: 5, lastInterruptedAt: oldTime };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    // Outside window — the counter would be reset to 1 by the caller
    expect(result.crashLoopBlocked).toBe(false);
    expect(result.shouldAutoResume).toBe(true);
  });

  it("should NOT auto-resume when no assets exist (canResume=false)", () => {
    const emptyState = { ...baseState, assets: [] };
    const snap = { ...baseSnapshot, stateJson: emptyState };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    expect(result.canResume).toBe(false);
    expect(result.shouldAutoResume).toBe(false);
  });

  it("should NOT auto-resume when phase is unknown/completed", () => {
    const completedState = { ...baseState, phase: "completed" };
    const snap = { ...baseSnapshot, stateJson: completedState };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    expect(result.canResume).toBe(false);
    expect(result.shouldAutoResume).toBe(false);
  });

  it("should handle null lastInterruptedAt gracefully (no crash-loop)", () => {
    const snap = { ...baseSnapshot, interruptCount: 5, lastInterruptedAt: null };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    // null timestamp means epoch 0, which is outside any 24h window
    expect(result.crashLoopBlocked).toBe(false);
    expect(result.shouldAutoResume).toBe(true);
  });

  it("should handle string stateJson (JSON parse)", () => {
    const snap = { ...baseSnapshot, stateJson: JSON.stringify(baseState) };
    const result = evaluateCrashLoopGuard(snap, autoResumeEngagement);
    expect(result.canResume).toBe(true);
    expect(result.shouldAutoResume).toBe(true);
  });
});

// ─── P2: Auto-Resume Scheduling & Cancellation ────────────────────────────

describe("P2: Auto-Resume Scheduling", () => {
  it("should export cancel and reset functions", async () => {
    const mod = await import("./lib/engagement-auto-resume");
    expect(typeof mod.cancelAutoResume).toBe("function");
    expect(typeof mod.cancelAllAutoResumes).toBe("function");
    expect(typeof mod.resetInterruptCounter).toBe("function");
    expect(typeof mod.getDetectedInterruptions).toBe("function");
    expect(typeof mod.clearDetectedInterruptions).toBe("function");
    expect(typeof mod.scheduleAutoResumes).toBe("function");
  });

  it("should export configuration constants", async () => {
    const mod = await import("./lib/engagement-auto-resume");
    expect(mod.AUTO_RESUME_CONFIG.MAX_INTERRUPTS_BEFORE_BLOCK).toBe(10);
    expect(mod.AUTO_RESUME_CONFIG.CRASH_LOOP_WINDOW_MS).toBe(24 * 60 * 60 * 1000);
    expect(mod.AUTO_RESUME_CONFIG.AUTO_RESUME_DELAY_MS).toBe(30 * 1000);
    expect(mod.AUTO_RESUME_CONFIG.CANCEL_GRACE_PERIOD_MS).toBe(30 * 1000);
  });

  it("cancelAutoResume should return false when no timer exists", async () => {
    const mod = await import("./lib/engagement-auto-resume");
    const result = mod.cancelAutoResume(99999);
    expect(result).toBe(false);
  });

  it("getDetectedInterruptions should return empty array initially", async () => {
    const mod = await import("./lib/engagement-auto-resume");
    // Clear any state from other tests
    mod.clearDetectedInterruptions();
    const result = mod.getDetectedInterruptions();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(0);
  });
});

// ─── P2: Schema Validation ─────────────────────────────────────────────────

describe("P2: Schema Fields", () => {
  it("engagements table should have autoResumeOnRestart field", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.engagements.autoResumeOnRestart).toBeDefined();
  });

  it("engagementOpsSnapshots should have interruptCount and lastInterruptedAt fields", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.engagementOpsSnapshots.interruptCount).toBeDefined();
    expect(schema.engagementOpsSnapshots.lastInterruptedAt).toBeDefined();
  });
});

// ─── P2: Interrupt Counter Edge Cases ──────────────────────────────────────

describe("P2: Interrupt Counter Edge Cases", () => {
  it("should correctly calculate boundary: exactly 10 interrupts at exactly 24h ago", () => {
    // Exactly at the boundary — 24h ago should be outside the window (>= not >)
    const exactBoundary = new Date(Date.now() - CRASH_LOOP_WINDOW_MS).toISOString();
    const snap: SnapshotRecord = {
      engagementId: 1,
      isRunning: true,
      interruptCount: 9,
      lastInterruptedAt: exactBoundary,
      stateJson: {
        phase: "enumeration",
        assets: [{ hostname: "a.lab" }],
        stats: {},
      },
      phase: "enumeration",
      updatedAt: new Date().toISOString(),
    };
    const eng: EngagementRecord = { id: 1, autoResumeOnRestart: 1 };
    const result = evaluateCrashLoopGuard(snap, eng);
    // At exactly the boundary, lastInterruptedAt equals windowStart, so NOT > windowStart
    expect(result.crashLoopBlocked).toBe(false);
  });

  it("should block at 1ms inside the 24h window", () => {
    const justInside = new Date(Date.now() - CRASH_LOOP_WINDOW_MS + 1).toISOString();
    const snap: SnapshotRecord = {
      engagementId: 1,
      isRunning: true,
      interruptCount: 9,
      lastInterruptedAt: justInside,
      stateJson: {
        phase: "enumeration",
        assets: [{ hostname: "a.lab" }],
        stats: {},
      },
      phase: "enumeration",
      updatedAt: new Date().toISOString(),
    };
    const eng: EngagementRecord = { id: 1, autoResumeOnRestart: 1 };
    const result = evaluateCrashLoopGuard(snap, eng);
    expect(result.crashLoopBlocked).toBe(true);
  });

  it("should handle all valid pipeline phases for canResume", () => {
    const validPhases = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"];
    for (const phase of validPhases) {
      const snap: SnapshotRecord = {
        engagementId: 1,
        isRunning: true,
        interruptCount: 0,
        lastInterruptedAt: null,
        stateJson: { phase, assets: [{ hostname: "test.lab" }], stats: {} },
        phase,
        updatedAt: new Date().toISOString(),
      };
      const eng: EngagementRecord = { id: 1, autoResumeOnRestart: 1 };
      const result = evaluateCrashLoopGuard(snap, eng);
      expect(result.canResume).toBe(true);
    }
  });

  it("should reject invalid phases for canResume", () => {
    const invalidPhases = ["idle", "completed", "error", "unknown", "paused"];
    for (const phase of invalidPhases) {
      const snap: SnapshotRecord = {
        engagementId: 1,
        isRunning: true,
        interruptCount: 0,
        lastInterruptedAt: null,
        stateJson: { phase, assets: [{ hostname: "test.lab" }], stats: {} },
        phase,
        updatedAt: new Date().toISOString(),
      };
      const eng: EngagementRecord = { id: 1, autoResumeOnRestart: 1 };
      const result = evaluateCrashLoopGuard(snap, eng);
      expect(result.canResume).toBe(false);
    }
  });
});
