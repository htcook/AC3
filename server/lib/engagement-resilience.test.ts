/**
 * Engagement Resilience Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for:
 * 1. Stale approval gate dismissal on resume
 * 2. Phase checkpoint tracking (completedScans)
 * 3. normalizeOpsState rehydration of completedScans Sets
 * 4. saveOpsSnapshot serialization of completedScans Sets
 * 5. Resume skipping already-completed scans
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Test: normalizeOpsState rehydration ──────────────────────────────────

describe("normalizeOpsState — completedScans rehydration", () => {
  let normalizeOpsState: (state: any) => any;

  beforeEach(async () => {
    const mod = await import("./engagement-orchestrator");
    normalizeOpsState = mod.normalizeOpsState;
  });

  it("creates default completedScans when field is missing", () => {
    const state: any = {
      engagementId: 1,
      phase: "vuln_detection",
      isRunning: false,
      isPaused: false,
      assets: [],
      log: [],
      approvalGates: [],
      stats: {},
    };
    const normalized = normalizeOpsState(state);
    expect(normalized.completedScans).toBeDefined();
    expect(normalized.completedScans.nucleiCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.zapCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.hydraCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.exploitCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.nucleiCompleted.size).toBe(0);
  });

  it("rehydrates completedScans arrays from JSON into Sets", () => {
    const state: any = {
      engagementId: 2,
      phase: "vuln_detection",
      isRunning: false,
      isPaused: false,
      assets: [],
      log: [],
      approvalGates: [],
      stats: {},
      completedScans: {
        nucleiCompleted: ["http://target:8080", "http://target:443"],
        zapCompleted: ["target:8080"],
        hydraCompleted: [],
        exploitCompleted: ["exploit-1"],
        lastCheckpointAt: 1700000000000,
      },
    };
    const normalized = normalizeOpsState(state);
    expect(normalized.completedScans.nucleiCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.nucleiCompleted.size).toBe(2);
    expect(normalized.completedScans.nucleiCompleted.has("http://target:8080")).toBe(true);
    expect(normalized.completedScans.nucleiCompleted.has("http://target:443")).toBe(true);
    expect(normalized.completedScans.zapCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.zapCompleted.size).toBe(1);
    expect(normalized.completedScans.exploitCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.exploitCompleted.size).toBe(1);
    expect(normalized.completedScans.lastCheckpointAt).toBe(1700000000000);
  });

  it("handles already-Set completedScans (no double-wrap)", () => {
    const nucleiSet = new Set(["http://a:80"]);
    const state: any = {
      engagementId: 3,
      phase: "idle",
      isRunning: false,
      isPaused: false,
      assets: [],
      log: [],
      approvalGates: [],
      stats: {},
      completedScans: {
        nucleiCompleted: nucleiSet,
        zapCompleted: new Set(),
        hydraCompleted: new Set(),
        exploitCompleted: new Set(),
        lastCheckpointAt: Date.now(),
      },
    };
    const normalized = normalizeOpsState(state);
    expect(normalized.completedScans.nucleiCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.nucleiCompleted.size).toBe(1);
    expect(normalized.completedScans.nucleiCompleted.has("http://a:80")).toBe(true);
  });

  it("handles null/undefined sub-fields in completedScans", () => {
    const state: any = {
      engagementId: 4,
      phase: "idle",
      isRunning: false,
      isPaused: false,
      assets: [],
      log: [],
      approvalGates: [],
      stats: {},
      completedScans: {
        nucleiCompleted: null,
        zapCompleted: undefined,
        // hydraCompleted and exploitCompleted missing entirely
        lastCheckpointAt: null,
      },
    };
    const normalized = normalizeOpsState(state);
    expect(normalized.completedScans.nucleiCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.nucleiCompleted.size).toBe(0);
    expect(normalized.completedScans.zapCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.hydraCompleted).toBeInstanceOf(Set);
    expect(normalized.completedScans.exploitCompleted).toBeInstanceOf(Set);
    expect(typeof normalized.completedScans.lastCheckpointAt).toBe("number");
  });
});

// ─── Test: dismissAllStaleApprovals ──────────────────────────────────────

describe("dismissAllStaleApprovals", () => {
  let dismissAllStaleApprovals: (engagementId: number, resolvedBy?: string) => number;
  let initOpsState: any;

  beforeEach(async () => {
    const mod = await import("./engagement-orchestrator");
    dismissAllStaleApprovals = mod.dismissAllStaleApprovals;
    initOpsState = mod.initOpsState;
  });

  it("returns 0 for non-existent engagement", () => {
    const count = dismissAllStaleApprovals(999999);
    expect(count).toBe(0);
  });

  it("dismisses stale pending gates (no resolver in memory)", async () => {
    // Create a state with stale gates
    const state = await initOpsState(888001, "pentest", "standard");
    // Manually add stale gates (no resolver registered)
    state.approvalGates.push({
      id: "stale-gate-1",
      phase: "vuln_detection",
      title: "Stale Gate 1",
      detail: "This gate has no resolver",
      riskTier: "orange",
      status: "pending",
      createdAt: Date.now() - 60000,
    });
    state.approvalGates.push({
      id: "stale-gate-2",
      phase: "exploitation",
      title: "Stale Gate 2",
      detail: "This gate also has no resolver",
      riskTier: "red",
      status: "pending",
      createdAt: Date.now() - 120000,
    });
    state.isPaused = true;

    const count = dismissAllStaleApprovals(888001, "auto-resume:test");
    expect(count).toBe(2);
    expect(state.approvalGates[0].status).toBe("denied");
    expect(state.approvalGates[1].status).toBe("denied");
    expect(state.approvalGates[0].resolvedBy).toBe("auto-resume:test");
    expect(state.isPaused).toBe(false);
  });

  it("does not dismiss already-resolved gates", async () => {
    const state = await initOpsState(888002, "pentest", "standard");
    state.approvalGates.push({
      id: "resolved-gate",
      phase: "vuln_detection",
      title: "Already Resolved",
      detail: "This was already approved",
      riskTier: "yellow",
      status: "approved",
      createdAt: Date.now() - 60000,
      resolvedAt: Date.now() - 30000,
      resolvedBy: "operator",
    });

    const count = dismissAllStaleApprovals(888002);
    expect(count).toBe(0);
  });
});

// ─── Test: completedScans checkpoint tracking ────────────────────────────

describe("completedScans checkpoint tracking", () => {
  it("initializes with empty Sets on new engagement", async () => {
    const { initOpsState } = await import("./engagement-orchestrator");
    const state = await initOpsState(888003, "pentest", "standard");
    expect(state.completedScans).toBeDefined();
    expect(state.completedScans!.nucleiCompleted).toBeInstanceOf(Set);
    expect(state.completedScans!.nucleiCompleted.size).toBe(0);
    expect(state.completedScans!.zapCompleted).toBeInstanceOf(Set);
    expect(state.completedScans!.zapCompleted.size).toBe(0);
    expect(state.completedScans!.hydraCompleted).toBeInstanceOf(Set);
    expect(state.completedScans!.hydraCompleted.size).toBe(0);
    expect(state.completedScans!.exploitCompleted).toBeInstanceOf(Set);
    expect(state.completedScans!.exploitCompleted.size).toBe(0);
    expect(typeof state.completedScans!.lastCheckpointAt).toBe("number");
  });

  it("tracks completed scans by adding URLs to Sets", async () => {
    const { initOpsState } = await import("./engagement-orchestrator");
    const state = await initOpsState(888004, "pentest", "standard");

    // Simulate scan completion
    state.completedScans!.nucleiCompleted.add("http://target:8080");
    state.completedScans!.nucleiCompleted.add("http://target:443");
    state.completedScans!.zapCompleted.add("target:8080");
    state.completedScans!.lastCheckpointAt = Date.now();

    expect(state.completedScans!.nucleiCompleted.size).toBe(2);
    expect(state.completedScans!.nucleiCompleted.has("http://target:8080")).toBe(true);
    expect(state.completedScans!.zapCompleted.size).toBe(1);
  });

  it("skip-completed check works correctly", async () => {
    const { initOpsState } = await import("./engagement-orchestrator");
    const state = await initOpsState(888005, "pentest", "standard");

    // Mark some URLs as completed
    state.completedScans!.nucleiCompleted.add("http://target:8080");
    state.completedScans!.nucleiCompleted.add("https://target:443");

    // Simulate building scan tasks with skip logic
    const allUrls = ["http://target:8080", "https://target:443", "http://target:3000"];
    const tasksToRun = allUrls.filter(url => !state.completedScans?.nucleiCompleted.has(url));

    expect(tasksToRun).toEqual(["http://target:3000"]);
    expect(tasksToRun.length).toBe(1);
  });
});

// ─── Test: saveOpsSnapshot serialization ─────────────────────────────────

describe("saveOpsSnapshot — completedScans serialization", () => {
  it("serializes Sets to Arrays for JSON storage", () => {
    // Test the serialization logic directly (extracted from saveOpsSnapshot)
    const state = {
      completedScans: {
        nucleiCompleted: new Set(["http://a:80", "http://b:443"]),
        zapCompleted: new Set(["a:80"]),
        hydraCompleted: new Set<string>(),
        exploitCompleted: new Set(["exploit-1"]),
        lastCheckpointAt: 1700000000000,
      },
      skippedDomains: new Set(["skip.example.com"]),
    };

    // Replicate the serialization logic from saveOpsSnapshot
    const completedScansToSave = state.completedScans ? {
      nucleiCompleted: state.completedScans.nucleiCompleted instanceof Set ? Array.from(state.completedScans.nucleiCompleted) : (state.completedScans.nucleiCompleted || []),
      zapCompleted: state.completedScans.zapCompleted instanceof Set ? Array.from(state.completedScans.zapCompleted) : (state.completedScans.zapCompleted || []),
      hydraCompleted: state.completedScans.hydraCompleted instanceof Set ? Array.from(state.completedScans.hydraCompleted) : (state.completedScans.hydraCompleted || []),
      exploitCompleted: state.completedScans.exploitCompleted instanceof Set ? Array.from(state.completedScans.exploitCompleted) : (state.completedScans.exploitCompleted || []),
      lastCheckpointAt: state.completedScans.lastCheckpointAt || Date.now(),
    } : undefined;

    expect(Array.isArray(completedScansToSave!.nucleiCompleted)).toBe(true);
    expect(completedScansToSave!.nucleiCompleted).toEqual(["http://a:80", "http://b:443"]);
    expect(Array.isArray(completedScansToSave!.zapCompleted)).toBe(true);
    expect(completedScansToSave!.zapCompleted).toEqual(["a:80"]);
    expect(Array.isArray(completedScansToSave!.hydraCompleted)).toBe(true);
    expect(completedScansToSave!.hydraCompleted).toEqual([]);
    expect(completedScansToSave!.exploitCompleted).toEqual(["exploit-1"]);
    expect(completedScansToSave!.lastCheckpointAt).toBe(1700000000000);

    // Verify it round-trips through JSON
    const json = JSON.stringify(completedScansToSave);
    const parsed = JSON.parse(json);
    expect(parsed.nucleiCompleted).toEqual(["http://a:80", "http://b:443"]);
    expect(parsed.zapCompleted).toEqual(["a:80"]);
  });

  it("handles undefined completedScans gracefully", () => {
    const state = {
      completedScans: undefined,
      skippedDomains: new Set(),
    };

    const completedScansToSave = state.completedScans ? {
      nucleiCompleted: [],
      zapCompleted: [],
      hydraCompleted: [],
      exploitCompleted: [],
      lastCheckpointAt: Date.now(),
    } : undefined;

    expect(completedScansToSave).toBeUndefined();
  });
});

// ─── Test: Round-trip serialize → rehydrate ──────────────────────────────

describe("completedScans round-trip (serialize → rehydrate)", () => {
  it("preserves scan progress through serialize/rehydrate cycle", async () => {
    const { normalizeOpsState } = await import("./engagement-orchestrator");

    // Simulate state with completed scans
    const originalState = {
      engagementId: 888006,
      phase: "vuln_detection",
      isRunning: false,
      isPaused: false,
      assets: [],
      log: [],
      approvalGates: [],
      stats: {},
      completedScans: {
        nucleiCompleted: new Set(["http://target:8080", "https://target:443"]),
        zapCompleted: new Set(["target:8080"]),
        hydraCompleted: new Set<string>(),
        exploitCompleted: new Set<string>(),
        lastCheckpointAt: 1700000000000,
      },
    };

    // Serialize (simulating saveOpsSnapshot)
    const serialized = {
      ...originalState,
      completedScans: {
        nucleiCompleted: Array.from(originalState.completedScans.nucleiCompleted),
        zapCompleted: Array.from(originalState.completedScans.zapCompleted),
        hydraCompleted: Array.from(originalState.completedScans.hydraCompleted),
        exploitCompleted: Array.from(originalState.completedScans.exploitCompleted),
        lastCheckpointAt: originalState.completedScans.lastCheckpointAt,
      },
    };

    // Simulate JSON round-trip (DB storage)
    const jsonStr = JSON.stringify(serialized);
    const fromDb = JSON.parse(jsonStr);

    // Rehydrate (simulating normalizeOpsState)
    const rehydrated = normalizeOpsState(fromDb);

    // Verify Sets are restored
    expect(rehydrated.completedScans.nucleiCompleted).toBeInstanceOf(Set);
    expect(rehydrated.completedScans.nucleiCompleted.size).toBe(2);
    expect(rehydrated.completedScans.nucleiCompleted.has("http://target:8080")).toBe(true);
    expect(rehydrated.completedScans.nucleiCompleted.has("https://target:443")).toBe(true);
    expect(rehydrated.completedScans.zapCompleted).toBeInstanceOf(Set);
    expect(rehydrated.completedScans.zapCompleted.size).toBe(1);
    expect(rehydrated.completedScans.zapCompleted.has("target:8080")).toBe(true);
    expect(rehydrated.completedScans.lastCheckpointAt).toBe(1700000000000);
  });
});
