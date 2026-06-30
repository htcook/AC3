/**
 * Tests for Campaign Advisor ↔ Burp Completion Integration
 * and Phase Stall Force-Abort mechanism
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  AdvisorContext,
  injectBurpCompletionContext,
  gatherEngagementContextWithBurp,
  buildContextSummary,
  freshBurpData,
} from "./lib/campaign-advisor";

// ─── Campaign Advisor Burp Integration ───────────────────────────────────────


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("Campaign Advisor ↔ Burp Completion Integration", () => {
  beforeEach(() => {
    // Clear the in-memory cache before each test
    freshBurpData.clear();
  });

  describe("injectBurpCompletionContext", () => {
    it("stores Burp data in the fresh cache keyed by engagement ID", () => {
      injectBurpCompletionContext(42, {
        scanId: "scan-abc",
        status: "completed",
        targetUrls: ["https://example.com"],
        issueCount: 15,
        importedCount: 12,
        completedAt: Date.now(),
        edition: "professional",
      });

      expect(freshBurpData.has("42")).toBe(true);
      const data = freshBurpData.get("42");
      expect(data?.scanId).toBe("scan-abc");
      expect(data?.issueCount).toBe(15);
      expect(data?.importedCount).toBe(12);
      expect(data?.edition).toBe("professional");
    });

    it("accepts string engagement IDs", () => {
      injectBurpCompletionContext("99", {
        scanId: "scan-xyz",
        status: "completed",
        targetUrls: [],
        issueCount: 0,
        importedCount: 0,
        completedAt: null,
        edition: "enterprise",
      });

      expect(freshBurpData.has("99")).toBe(true);
    });

    it("overwrites previous data for the same engagement", () => {
      injectBurpCompletionContext(42, {
        scanId: "scan-1",
        status: "completed",
        targetUrls: [],
        issueCount: 5,
        importedCount: 3,
        completedAt: null,
        edition: "professional",
      });

      injectBurpCompletionContext(42, {
        scanId: "scan-2",
        status: "completed",
        targetUrls: ["https://new.com"],
        issueCount: 20,
        importedCount: 18,
        completedAt: Date.now(),
        edition: "enterprise",
      });

      const data = freshBurpData.get("42");
      expect(data?.scanId).toBe("scan-2");
      expect(data?.issueCount).toBe(20);
    });
  });

  describe("gatherEngagementContextWithBurp", () => {
    it("merges fresh Burp data into context when available", async () => {
      injectBurpCompletionContext("7", {
        scanId: "scan-merge",
        status: "completed",
        targetUrls: ["https://target.com"],
        issueCount: 8,
        importedCount: 6,
        completedAt: Date.now(),
        edition: "professional",
      });

      const ctx = await gatherEngagementContextWithBurp("7");
      expect(ctx.burpScanResults).toBeDefined();
      expect(ctx.burpScanResults?.scanId).toBe("scan-merge");
      expect(ctx.burpDataFresh).toBe(true);
    });

    it("returns context without Burp data when no fresh data exists", async () => {
      const ctx = await gatherEngagementContextWithBurp("999");
      // burpScanResults may be undefined or from DB (which is likely empty in test)
      expect(ctx.burpDataFresh).toBeUndefined();
    });

    it("returns context when no engagement ID is provided", async () => {
      const ctx = await gatherEngagementContextWithBurp(undefined);
      expect(ctx).toBeDefined();
      expect(ctx.burpDataFresh).toBeUndefined();
    });
  });

  describe("buildContextSummary with Burp data", () => {
    it("includes Burp scan results in the context summary", () => {
      const ctx: AdvisorContext = {
        engagementId: "42",
        currentPhase: "exploitation",
        burpScanResults: {
          scanId: "scan-summary",
          status: "completed",
          targetUrls: ["https://example.com", "https://api.example.com"],
          issueCount: 25,
          importedCount: 20,
          completedAt: Date.now(),
          edition: "professional",
          severityBreakdown: { critical: 3, high: 7, medium: 10, low: 5 },
          escalatedCount: 5,
          priorityFlaggedCount: 3,
        },
        burpDataFresh: true,
      };

      const summary = buildContextSummary(ctx);
      expect(summary).toContain("Burp Suite Scan Results");
      expect(summary).toContain("Issues Found: 25");
      expect(summary).toContain("Imported: 20");
      expect(summary).toContain("critical: 3");
      expect(summary).toContain("Cross-Tool Escalations: 5");
      expect(summary).toContain("Priority Exploitation Targets: 3");
      expect(summary).toContain("FRESH BURP DATA");
    });

    it("omits Burp section when no Burp data is present", () => {
      const ctx: AdvisorContext = {
        engagementId: "42",
        currentPhase: "recon",
      };

      const summary = buildContextSummary(ctx);
      expect(summary).not.toContain("Burp Suite Scan Results");
    });

    it("omits FRESH BURP DATA marker when burpDataFresh is false", () => {
      const ctx: AdvisorContext = {
        engagementId: "42",
        burpScanResults: {
          scanId: "scan-old",
          status: "completed",
          targetUrls: [],
          issueCount: 5,
          importedCount: 5,
          completedAt: Date.now() - 3600_000,
          edition: "professional",
        },
        burpDataFresh: false,
      };

      const summary = buildContextSummary(ctx);
      expect(summary).toContain("Burp Suite Scan Results");
      expect(summary).not.toContain("FRESH BURP DATA");
    });

    it("handles Burp data with zero issues gracefully", () => {
      const ctx: AdvisorContext = {
        engagementId: "42",
        burpScanResults: {
          scanId: null,
          status: "completed",
          targetUrls: [],
          issueCount: 0,
          importedCount: 0,
          completedAt: null,
          edition: "enterprise",
        },
      };

      const summary = buildContextSummary(ctx);
      expect(summary).toContain("Issues Found: 0");
      expect(summary).toContain("Imported: 0");
      expect(summary).not.toContain("Cross-Tool Escalations");
      expect(summary).not.toContain("Priority Exploitation");
    });
  });

  describe("AdvisorContext type contract", () => {
    it("burpScanResults includes all expected fields", () => {
      const ctx: AdvisorContext = {
        burpScanResults: {
          scanId: "test",
          status: "completed",
          targetUrls: ["https://t.com"],
          issueCount: 10,
          importedCount: 8,
          completedAt: Date.now(),
          edition: "professional",
          severityBreakdown: { high: 5, medium: 5 },
          escalatedCount: 2,
          priorityFlaggedCount: 1,
        },
        burpDataFresh: true,
      };

      expect(ctx.burpScanResults).toBeDefined();
      expect(typeof ctx.burpScanResults!.scanId).toBe("string");
      expect(typeof ctx.burpScanResults!.issueCount).toBe("number");
      expect(typeof ctx.burpScanResults!.importedCount).toBe("number");
      expect(typeof ctx.burpDataFresh).toBe("boolean");
    });
  });
});

// ─── Phase Stall Force-Abort ─────────────────────────────────────────────────

describe("Phase Stall Force-Abort Mechanism", () => {
  it("orchestrator exports abortEngagement and getEngagementAbortSignal", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    expect(typeof mod.abortEngagement).toBe("function");
    expect(typeof mod.getEngagementAbortSignal).toBe("function");
  });

  it("abortEngagement cancels the AbortController signal", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    // Create a signal first
    const signal = mod.getEngagementAbortSignal(99999);
    expect(signal.aborted).toBe(false);

    // Abort it
    mod.abortEngagement(99999);
    expect(signal.aborted).toBe(true);
  });

  it("getEngagementAbortSignal creates a fresh controller if none exists", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    const signal1 = mod.getEngagementAbortSignal(88888);
    expect(signal1.aborted).toBe(false);

    // Clean up
    mod.abortEngagement(88888);
  });

  it("abortEngagement is safe to call on non-existent engagement", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    // Should not throw
    expect(() => mod.abortEngagement(77777)).not.toThrow();
  });

  it("fresh controller works after abort (pipeline can continue)", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    const engId = 66666;

    // Create and abort
    const signal1 = mod.getEngagementAbortSignal(engId);
    mod.abortEngagement(engId);
    expect(signal1.aborted).toBe(true);

    // Get a fresh signal — should be a new, non-aborted controller
    const signal2 = mod.getEngagementAbortSignal(engId);
    expect(signal2.aborted).toBe(false);
    expect(signal2).not.toBe(signal1);

    // Clean up
    mod.abortEngagement(engId);
  });
});

// ─── Heartbeat Stall Detection Constants ─────────────────────────────────────

describe("Heartbeat Stall Detection Architecture", () => {
  it("orchestrator source contains stall detection with force-abort logic", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // Verify the stall detection constants exist
    expect(source).toContain("STALL_WARNING_MS");
    expect(source).toContain("STALL_FORCE_MS");
    expect(source).toContain("MAX_STALL_COUNT");

    // Verify force-abort mechanism
    expect(source).toContain("Phase Force-Abort");
    expect(source).toContain("abortEngagement(state.engagementId)");
    expect(source).toContain("freshController");

    // Verify consecutive stall tracking
    expect(source).toContain("consecutiveStalls");
    expect(source).toContain("lastStallPhase");
  });

  it("stall detection uses broadcastOpsUpdate for real-time UI feedback", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // The heartbeat section should broadcast updates on stall detection
    const heartbeatSection = source.slice(
      source.indexOf("PHASE ACTIVITY HEARTBEAT"),
      source.indexOf("PERIODIC FORCED PERSISTENCE")
    );

    expect(heartbeatSection).toContain("broadcastOpsUpdate");
    expect(heartbeatSection).toContain("log_update");
  });

  it("stall counter resets when phase changes", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // Verify the logic that resets stall counter on phase change
    expect(source).toContain("lastStallPhase === state.phase");
    expect(source).toContain("consecutiveStalls = 1");
  });
});
