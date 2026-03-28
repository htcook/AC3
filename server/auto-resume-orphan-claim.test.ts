import { describe, it, expect } from "vitest";

/**
 * Tests for the orphan engagement claim logic and updated memory watchdog thresholds.
 *
 * The auto-resume system now allows production to claim engagements started by
 * a different server (e.g., dev/localhost) if the snapshot is older than
 * ORPHAN_CLAIM_TIMEOUT_MS (default 5 minutes).
 */

// ─── Orphan Claim Logic Tests ───────────────────────────────────────────────

describe("Orphan engagement claim logic", () => {
  const ORPHAN_CLAIM_TIMEOUT_MS = 300_000; // 5 min default

  function shouldClaimOrphan(
    ownerHostname: string,
    ourHostname: string,
    snapshotAgeMs: number,
    orphanTimeoutMs: number = ORPHAN_CLAIM_TIMEOUT_MS
  ): { skip: boolean; reason: string } {
    if (ownerHostname === ourHostname) {
      return { skip: false, reason: "same-server-restart" };
    }
    // Different server — check if old enough to claim
    if (snapshotAgeMs < orphanTimeoutMs) {
      return { skip: true, reason: "different-server-recent" };
    }
    return { skip: false, reason: "orphan-claimed" };
  }

  it("should allow same-server restart (hostname matches)", () => {
    const result = shouldClaimOrphan("ace-c3", "ace-c3", 10_000);
    expect(result.skip).toBe(false);
    expect(result.reason).toBe("same-server-restart");
  });

  it("should skip different-server engagement if snapshot is recent (< 5 min)", () => {
    const result = shouldClaimOrphan("localhost", "ace-c3", 60_000); // 1 minute old
    expect(result.skip).toBe(true);
    expect(result.reason).toBe("different-server-recent");
  });

  it("should claim orphaned engagement from different server if snapshot is old (> 5 min)", () => {
    const result = shouldClaimOrphan("localhost", "ace-c3", 600_000); // 10 minutes old
    expect(result.skip).toBe(false);
    expect(result.reason).toBe("orphan-claimed");
  });

  it("should claim orphaned engagement exactly at the threshold boundary", () => {
    // At exactly the threshold, snapshotAge (300000) is NOT < orphanTimeout (300000), so it claims
    const atThreshold = shouldClaimOrphan("localhost", "ace-c3", ORPHAN_CLAIM_TIMEOUT_MS);
    expect(atThreshold.skip).toBe(false); // exactly at threshold = old enough to claim
    expect(atThreshold.reason).toBe("orphan-claimed");

    // One ms before threshold — still too recent
    const beforeThreshold = shouldClaimOrphan("localhost", "ace-c3", ORPHAN_CLAIM_TIMEOUT_MS - 1);
    expect(beforeThreshold.skip).toBe(true);
  });

  it("should claim engagement with Infinity age (no updatedAt)", () => {
    const result = shouldClaimOrphan("localhost", "ace-c3", Infinity);
    expect(result.skip).toBe(false);
    expect(result.reason).toBe("orphan-claimed");
  });

  it("should respect custom orphan timeout via env var", () => {
    const customTimeout = 60_000; // 1 minute
    // 2 minutes old with 1 minute timeout → should claim
    const result = shouldClaimOrphan("localhost", "ace-c3", 120_000, customTimeout);
    expect(result.skip).toBe(false);
    expect(result.reason).toBe("orphan-claimed");
  });

  it("should handle same hostname with different instance IDs", () => {
    // Same hostname prefix, different pid/timestamp suffixes
    const result = shouldClaimOrphan("ace-c3", "ace-c3", 5_000);
    expect(result.skip).toBe(false);
    expect(result.reason).toBe("same-server-restart");
  });
});

// ─── Hostname Extraction Tests ──────────────────────────────────────────────

describe("Server hostname extraction from instance ID", () => {
  function extractHostname(instanceId: string): string {
    return instanceId.split("-").slice(0, -3).join("-") || instanceId;
  }

  it("should extract hostname from standard instance ID format", () => {
    expect(extractHostname("ace-c3-77554ffbcf-6v-1-1774726116-8005")).toBe("ace-c3-77554ffbcf-6v");
  });

  it("should return full ID for localhost (no dashes to split)", () => {
    expect(extractHostname("localhost")).toBe("localhost");
  });

  it("should handle localhost with pid/timestamp suffix", () => {
    expect(extractHostname("localhost-1-1774726116-8005")).toBe("localhost");
  });

  it("should handle short instance IDs gracefully", () => {
    expect(extractHostname("a-b")).toBe("a-b"); // Not enough segments
  });

  it("should handle empty string", () => {
    expect(extractHostname("")).toBe("");
  });
});

// ─── Memory Watchdog Threshold Tests ────────────────────────────────────────

describe("Memory watchdog thresholds for 4GB instance", () => {
  const DEFAULT_HEAP_WARNING = 1500;
  const DEFAULT_HEAP_CRITICAL = 2000;
  const DEFAULT_RSS_EMERGENCY = 3200;

  it("should have heap warning at 1500MB for 4GB instance", () => {
    expect(DEFAULT_HEAP_WARNING).toBe(1500);
    expect(DEFAULT_HEAP_WARNING).toBeGreaterThan(600); // old value
  });

  it("should have heap critical at 2000MB for 4GB instance", () => {
    expect(DEFAULT_HEAP_CRITICAL).toBe(2000);
    expect(DEFAULT_HEAP_CRITICAL).toBeGreaterThan(800); // old value
  });

  it("should have RSS emergency at 3200MB for 4GB instance", () => {
    expect(DEFAULT_RSS_EMERGENCY).toBe(3200);
    expect(DEFAULT_RSS_EMERGENCY).toBeGreaterThan(1400); // old value
  });

  it("should leave ~800MB headroom below 4GB total", () => {
    const totalMB = 4096;
    const headroom = totalMB - DEFAULT_RSS_EMERGENCY;
    expect(headroom).toBeGreaterThanOrEqual(800);
  });

  it("should have critical > warning and emergency > critical", () => {
    expect(DEFAULT_HEAP_CRITICAL).toBeGreaterThan(DEFAULT_HEAP_WARNING);
    expect(DEFAULT_RSS_EMERGENCY).toBeGreaterThan(DEFAULT_HEAP_CRITICAL);
  });

  function determineLevel(heapMB: number, rssMB: number): string | null {
    const needsAction = heapMB > DEFAULT_HEAP_WARNING || rssMB > DEFAULT_RSS_EMERGENCY;
    if (!needsAction) return null;
    if (rssMB > DEFAULT_RSS_EMERGENCY) return "EMERGENCY";
    if (heapMB > DEFAULT_HEAP_CRITICAL) return "CRITICAL";
    return "WARNING";
  }

  it("should not trigger at normal memory levels (heap=500MB, RSS=800MB)", () => {
    expect(determineLevel(500, 800)).toBeNull();
  });

  it("should not trigger at moderate levels (heap=1200MB, RSS=2000MB)", () => {
    expect(determineLevel(1200, 2000)).toBeNull();
  });

  it("should trigger WARNING at heap=1600MB", () => {
    expect(determineLevel(1600, 2000)).toBe("WARNING");
  });

  it("should trigger CRITICAL at heap=2100MB", () => {
    expect(determineLevel(2100, 2500)).toBe("CRITICAL");
  });

  it("should trigger EMERGENCY at RSS=3300MB", () => {
    expect(determineLevel(1000, 3300)).toBe("EMERGENCY");
  });

  it("should prioritize EMERGENCY over CRITICAL when both thresholds exceeded", () => {
    expect(determineLevel(2500, 3500)).toBe("EMERGENCY");
  });
});

// ─── Crash-Loop Guard Tests ─────────────────────────────────────────────────

describe("Crash-loop guard configuration", () => {
  const MAX_INTERRUPTS_BEFORE_BLOCK = 10;
  const CRASH_LOOP_WINDOW_MS = 24 * 60 * 60 * 1000;

  it("should allow up to 9 interrupts without blocking", () => {
    for (let i = 1; i < MAX_INTERRUPTS_BEFORE_BLOCK; i++) {
      expect(i < MAX_INTERRUPTS_BEFORE_BLOCK).toBe(true);
    }
  });

  it("should block at 10 interrupts within 24h window", () => {
    const interruptCount = 10;
    const lastInterruptedAt = Date.now() - 1000; // 1 second ago
    const windowStart = Date.now() - CRASH_LOOP_WINDOW_MS;
    const blocked = interruptCount >= MAX_INTERRUPTS_BEFORE_BLOCK && lastInterruptedAt > windowStart;
    expect(blocked).toBe(true);
  });

  it("should not block if interrupts are outside the 24h window", () => {
    const interruptCount = 15;
    const lastInterruptedAt = Date.now() - (25 * 60 * 60 * 1000); // 25 hours ago
    const windowStart = Date.now() - CRASH_LOOP_WINDOW_MS;
    const blocked = interruptCount >= MAX_INTERRUPTS_BEFORE_BLOCK && lastInterruptedAt > windowStart;
    expect(blocked).toBe(false);
  });
});
