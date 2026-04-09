import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for the stats reset logic in rerunFullPipeline.
 * We test the reset logic in isolation by simulating what the handler does
 * to the in-memory ops state before launching the pipeline.
 */

// Simulate the default stats shape from initOpsState
function makeDefaultStats() {
  return {
    hostsScanned: 0, portsFound: 0, vulnsFound: 0,
    exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
    zapScansRun: 0, wafDetections: 0,
  };
}

// Simulate a "dirty" ops state with accumulated stats from a previous run
function makeDirtyOpsState(engagementId: number) {
  return {
    engagementId,
    engagementType: "bug_bounty",
    phase: "complete" as const,
    progress: 100,
    isRunning: false,
    isPaused: false,
    assets: [
      { hostname: "example.com", ports: [80, 443, 8443], vulns: [{ id: "v1", tool: "nuclei" }] },
      { hostname: "api.example.com", ports: [443], vulns: [] },
    ],
    log: [
      { phase: "recon", type: "info", title: "Scan started", detail: "...", ts: Date.now() },
      { phase: "recon", type: "info", title: "Scan complete", detail: "...", ts: Date.now() },
      { phase: "vuln_detection", type: "info", title: "ZAP scan", detail: "...", ts: Date.now() },
    ],
    approvalGates: [{ id: "g1", phase: "exploitation", status: "approved" }],
    skippedDomains: new Set(["skip.example.com"]),
    completedScans: {
      nucleiCompleted: new Set(["example.com", "api.example.com"]),
      zapCompleted: new Set(["example.com"]),
      hydraCompleted: new Set(),
      exploitCompleted: new Set(["example.com:443"]),
      lastCheckpointAt: Date.now() - 60000,
    },
    exhaustiveExploit: true,
    stats: {
      hostsScanned: 2, portsFound: 4, vulnsFound: 7,
      exploitsAttempted: 3, exploitsSucceeded: 1, sessionsOpened: 1,
      zapScansRun: 1, wafDetections: 2,
    },
    activeScanPlan: { phases: ["A", "B"], targets: 5 },
    feedbackLoop: { iterations: 2, lastRun: Date.now() },
    severityEscalation: { escalated: 3, total: 7 },
    crossToolPipeline: { correlated: 2, coverage: 0.8 },
    roeScopeGuard: {
      authorizedDomains: ["example.com"],
      authorizedIps: ["1.2.3.4"],
      roeStatus: "signed",
    },
  };
}

// Replicate the exact reset logic from the rerunFullPipeline handler
function applyStatsReset(state: any) {
  state.stats = {
    hostsScanned: 0, portsFound: 0, vulnsFound: 0,
    exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
    zapScansRun: 0, wafDetections: 0,
  };
  state.assets = [];
  state.log = [];
  state.approvalGates = [];
  state.progress = 0;
  state.phase = "idle";
  state.error = undefined;
  state.skippedDomains = new Set();
  state.completedScans = {
    nucleiCompleted: new Set(),
    zapCompleted: new Set(),
    hydraCompleted: new Set(),
    exploitCompleted: new Set(),
    lastCheckpointAt: Date.now(),
  };
  state.activeScanPlan = undefined;
  state.feedbackLoop = undefined;
  state.severityEscalation = undefined;
  state.crossToolPipeline = undefined;
}

// Replicate the selective reset logic from the updated rerunFullPipeline handler
function applySelectiveReset(state: any, rs: { recon: boolean; scanning: boolean; analysis: boolean; exploitation: boolean; logs: boolean }) {
  const resetAll = rs.recon && rs.scanning && rs.analysis && rs.exploitation && rs.logs;

  // Always reset progress/phase/error for a fresh run
  state.progress = 0;
  state.phase = "idle";
  state.error = undefined;

  if (rs.recon) {
    state.assets = [];
    state.skippedDomains = new Set();
    state.stats.hostsScanned = 0;
    state.stats.portsFound = 0;
    state.stats.wafDetections = 0;
  }

  if (rs.scanning) {
    state.stats.vulnsFound = 0;
    state.stats.zapScansRun = 0;
    state.completedScans = {
      nucleiCompleted: new Set(),
      zapCompleted: new Set(),
      hydraCompleted: new Set(),
      exploitCompleted: rs.exploitation ? new Set() : state.completedScans?.exploitCompleted || new Set(),
      lastCheckpointAt: Date.now(),
    };
    state.activeScanPlan = undefined;
    state.crossToolPipeline = undefined;
  }

  if (rs.analysis) {
    state.feedbackLoop = undefined;
    state.severityEscalation = undefined;
    if (!rs.recon && Array.isArray(state.assets)) {
      for (const asset of state.assets) {
        if (Array.isArray(asset.vulns)) {
          asset.vulns = asset.vulns.filter((v: any) => v.tool !== 'llm-synthesis');
        }
      }
    }
  }

  if (rs.exploitation) {
    state.stats.exploitsAttempted = 0;
    state.stats.exploitsSucceeded = 0;
    state.stats.sessionsOpened = 0;
    if (state.completedScans) {
      state.completedScans.exploitCompleted = new Set();
    }
  }

  if (rs.logs) {
    state.log = [];
    state.approvalGates = [];
  }

  if (resetAll) {
    state.stats = {
      hostsScanned: 0, portsFound: 0, vulnsFound: 0,
      exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
      zapScansRun: 0, wafDetections: 0,
    };
  }
}

describe("rerunFullPipeline stats reset", () => {
  it("should reset all numeric stats to zero", () => {
    const state = makeDirtyOpsState(1);
    expect(state.stats.hostsScanned).toBe(2);
    expect(state.stats.vulnsFound).toBe(7);
    expect(state.stats.exploitsSucceeded).toBe(1);

    applyStatsReset(state);

    expect(state.stats).toEqual(makeDefaultStats());
    expect(state.stats.hostsScanned).toBe(0);
    expect(state.stats.portsFound).toBe(0);
    expect(state.stats.vulnsFound).toBe(0);
    expect(state.stats.exploitsAttempted).toBe(0);
    expect(state.stats.exploitsSucceeded).toBe(0);
    expect(state.stats.sessionsOpened).toBe(0);
    expect(state.stats.zapScansRun).toBe(0);
    expect(state.stats.wafDetections).toBe(0);
  });

  it("should clear all discovered assets", () => {
    const state = makeDirtyOpsState(1);
    expect(state.assets.length).toBe(2);

    applyStatsReset(state);

    expect(state.assets).toEqual([]);
    expect(state.assets.length).toBe(0);
  });

  it("should clear all log entries", () => {
    const state = makeDirtyOpsState(1);
    expect(state.log.length).toBe(3);

    applyStatsReset(state);

    expect(state.log).toEqual([]);
  });

  it("should clear approval gates", () => {
    const state = makeDirtyOpsState(1);
    expect(state.approvalGates.length).toBe(1);

    applyStatsReset(state);

    expect(state.approvalGates).toEqual([]);
  });

  it("should reset progress to 0 and phase to idle", () => {
    const state = makeDirtyOpsState(1);
    expect(state.progress).toBe(100);
    expect(state.phase).toBe("complete");

    applyStatsReset(state);

    expect(state.progress).toBe(0);
    expect(state.phase).toBe("idle");
  });

  it("should clear skipped domains", () => {
    const state = makeDirtyOpsState(1);
    expect(state.skippedDomains.size).toBe(1);

    applyStatsReset(state);

    expect(state.skippedDomains.size).toBe(0);
  });

  it("should reset all completed scan trackers", () => {
    const state = makeDirtyOpsState(1);
    expect(state.completedScans.nucleiCompleted.size).toBe(2);
    expect(state.completedScans.zapCompleted.size).toBe(1);
    expect(state.completedScans.exploitCompleted.size).toBe(1);

    applyStatsReset(state);

    expect(state.completedScans.nucleiCompleted.size).toBe(0);
    expect(state.completedScans.zapCompleted.size).toBe(0);
    expect(state.completedScans.hydraCompleted.size).toBe(0);
    expect(state.completedScans.exploitCompleted.size).toBe(0);
    expect(typeof state.completedScans.lastCheckpointAt).toBe("number");
  });

  it("should clear cached pipeline state (scan plan, feedback, escalation, cross-tool)", () => {
    const state = makeDirtyOpsState(1);
    expect(state.activeScanPlan).toBeDefined();
    expect(state.feedbackLoop).toBeDefined();
    expect(state.severityEscalation).toBeDefined();
    expect(state.crossToolPipeline).toBeDefined();

    applyStatsReset(state);

    expect(state.activeScanPlan).toBeUndefined();
    expect(state.feedbackLoop).toBeUndefined();
    expect(state.severityEscalation).toBeUndefined();
    expect(state.crossToolPipeline).toBeUndefined();
  });

  it("should preserve engagementId and engagementType", () => {
    const state = makeDirtyOpsState(42);
    applyStatsReset(state);

    expect(state.engagementId).toBe(42);
    expect(state.engagementType).toBe("bug_bounty");
  });

  it("should preserve roeScopeGuard (refreshed separately in the pipeline)", () => {
    const state = makeDirtyOpsState(1);
    applyStatsReset(state);

    // RoE scope guard is NOT reset here — it's refreshed separately from engagement data
    expect(state.roeScopeGuard).toBeDefined();
    expect(state.roeScopeGuard.authorizedDomains).toContain("example.com");
  });

  it("should produce a state where all tab counts would show 0", () => {
    const state = makeDirtyOpsState(1);
    applyStatsReset(state);

    // Operations tab counts
    expect(state.log.length).toBe(0);  // Live Feed count
    expect(state.assets.length).toBe(0);  // Assets count

    // Stats card values
    expect(state.stats.hostsScanned).toBe(0);
    expect(state.stats.portsFound).toBe(0);
    expect(state.stats.vulnsFound).toBe(0);
    expect(state.stats.exploitsAttempted).toBe(0);
    expect(state.stats.exploitsSucceeded).toBe(0);
  });

  // ═══ PARTIAL RESET TESTS ═══

  it("should only reset recon data when only recon scope is checked", () => {
    const state = makeDirtyOpsState(1);
    applySelectiveReset(state, { recon: true, scanning: false, analysis: false, exploitation: false, logs: false });

    // Recon data cleared
    expect(state.assets).toEqual([]);
    expect(state.stats.hostsScanned).toBe(0);
    expect(state.stats.portsFound).toBe(0);
    expect(state.stats.wafDetections).toBe(0);

    // Scanning data preserved
    expect(state.stats.vulnsFound).toBe(7);
    expect(state.stats.zapScansRun).toBe(1);

    // Exploitation data preserved
    expect(state.stats.exploitsAttempted).toBe(3);
    expect(state.stats.exploitsSucceeded).toBe(1);
    expect(state.stats.sessionsOpened).toBe(1);

    // Logs preserved
    expect(state.log.length).toBe(3);
    expect(state.approvalGates.length).toBe(1);
  });

  it("should only reset scanning data when only scanning scope is checked", () => {
    const state = makeDirtyOpsState(1);
    applySelectiveReset(state, { recon: false, scanning: true, analysis: false, exploitation: false, logs: false });

    // Recon data preserved
    expect(state.assets.length).toBe(2);
    expect(state.stats.hostsScanned).toBe(2);

    // Scanning data cleared
    expect(state.stats.vulnsFound).toBe(0);
    expect(state.stats.zapScansRun).toBe(0);
    expect(state.completedScans.nucleiCompleted.size).toBe(0);
    expect(state.completedScans.zapCompleted.size).toBe(0);
    expect(state.activeScanPlan).toBeUndefined();
    expect(state.crossToolPipeline).toBeUndefined();

    // Exploitation preserved (exploitCompleted stays because exploitation scope is off)
    expect(state.stats.exploitsAttempted).toBe(3);
    expect(state.completedScans.exploitCompleted.size).toBe(1);
  });

  it("should only reset exploitation data when only exploitation scope is checked", () => {
    const state = makeDirtyOpsState(1);
    applySelectiveReset(state, { recon: false, scanning: false, analysis: false, exploitation: true, logs: false });

    // Recon + scanning preserved
    expect(state.assets.length).toBe(2);
    expect(state.stats.vulnsFound).toBe(7);

    // Exploitation cleared
    expect(state.stats.exploitsAttempted).toBe(0);
    expect(state.stats.exploitsSucceeded).toBe(0);
    expect(state.stats.sessionsOpened).toBe(0);
    expect(state.completedScans.exploitCompleted.size).toBe(0);
  });

  it("should only reset logs when only logs scope is checked", () => {
    const state = makeDirtyOpsState(1);
    applySelectiveReset(state, { recon: false, scanning: false, analysis: false, exploitation: false, logs: true });

    // All data preserved
    expect(state.assets.length).toBe(2);
    expect(state.stats.vulnsFound).toBe(7);
    expect(state.stats.exploitsAttempted).toBe(3);

    // Logs cleared
    expect(state.log).toEqual([]);
    expect(state.approvalGates).toEqual([]);
  });

  it("should only reset analysis data when only analysis scope is checked", () => {
    const state = makeDirtyOpsState(1);
    applySelectiveReset(state, { recon: false, scanning: false, analysis: true, exploitation: false, logs: false });

    // Analysis cleared
    expect(state.feedbackLoop).toBeUndefined();
    expect(state.severityEscalation).toBeUndefined();

    // Recon preserved
    expect(state.assets.length).toBe(2);
    // Scanning preserved
    expect(state.stats.vulnsFound).toBe(7);
  });

  it("should reset nothing when all scopes are unchecked", () => {
    const state = makeDirtyOpsState(1);
    applySelectiveReset(state, { recon: false, scanning: false, analysis: false, exploitation: false, logs: false });

    // Progress/phase/error always reset
    expect(state.progress).toBe(0);
    expect(state.phase).toBe("idle");

    // But all data preserved
    expect(state.assets.length).toBe(2);
    expect(state.stats.vulnsFound).toBe(7);
    expect(state.stats.exploitsAttempted).toBe(3);
    expect(state.log.length).toBe(3);
    expect(state.feedbackLoop).toBeDefined();
  });

  it("should reset everything when all scopes are checked (same as full reset)", () => {
    const state = makeDirtyOpsState(1);
    applySelectiveReset(state, { recon: true, scanning: true, analysis: true, exploitation: true, logs: true });

    expect(state.stats).toEqual(makeDefaultStats());
    expect(state.assets).toEqual([]);
    expect(state.log).toEqual([]);
    expect(state.approvalGates).toEqual([]);
    expect(state.activeScanPlan).toBeUndefined();
    expect(state.feedbackLoop).toBeUndefined();
    expect(state.severityEscalation).toBeUndefined();
    expect(state.crossToolPipeline).toBeUndefined();
  });

  it("should strip LLM-synthesized vulns from assets when analysis is reset but recon is kept", () => {
    const state = makeDirtyOpsState(1);
    // Add an LLM-synthesized vuln to an asset
    state.assets[0].vulns.push({ id: 'v2', tool: 'llm-synthesis' } as any);
    expect(state.assets[0].vulns.length).toBe(2);

    applySelectiveReset(state, { recon: false, scanning: false, analysis: true, exploitation: false, logs: false });

    // Assets preserved but LLM vulns stripped
    expect(state.assets.length).toBe(2);
    expect(state.assets[0].vulns.length).toBe(1);
    expect(state.assets[0].vulns[0].tool).toBe('nuclei');
  });

  it("should handle already-clean state without errors", () => {
    const state = {
      engagementId: 1,
      engagementType: "pentest",
      phase: "idle",
      progress: 0,
      isRunning: false,
      isPaused: false,
      assets: [],
      log: [],
      approvalGates: [],
      skippedDomains: new Set(),
      completedScans: {
        nucleiCompleted: new Set(),
        zapCompleted: new Set(),
        hydraCompleted: new Set(),
        exploitCompleted: new Set(),
        lastCheckpointAt: Date.now(),
      },
      stats: makeDefaultStats(),
    };

    // Should not throw
    expect(() => applyStatsReset(state)).not.toThrow();
    expect(state.stats).toEqual(makeDefaultStats());
    expect(state.assets).toEqual([]);
  });
});
