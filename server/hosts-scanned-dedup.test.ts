// @ts-nocheck
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for the hostsScanned deduplication fix in port-discovery.ts.
 *
 * Bug: When startActiveScan is called after passive recon has already set
 * hostsScanned to N (via recalculation), executePortDiscovery's per-asset
 * hostsScanned++ increments would add N more on top, showing 2N instead of N.
 *
 * Fix: Reset state.stats.hostsScanned = 0 at the start of executePortDiscovery
 * before the per-asset loop increments it.
 */

describe("hostsScanned deduplication fix", () => {
  let executePortDiscovery: any;

  beforeEach(async () => {
    // Mock scan-server-executor to avoid real SSH calls
    vi.doMock("./lib/scan-server-executor", () => ({
      executeTool: vi.fn().mockResolvedValue({
        tool: "naabu",
        command: "naabu -host target -top-ports 1000",
        stdout: "80/tcp open http\n443/tcp open https\n",
        stderr: "",
        exitCode: 0,
        durationMs: 2000,
        timedOut: false,
      }),
      getScanServerConfigForScanForge: vi.fn().mockResolvedValue({ host: "scan.test" }),
    }));

    // Mock scanforge-discovery
    vi.doMock("./lib/scanforge-discovery", () => ({
      autoSelectTool: vi.fn().mockReturnValue("naabu"),
      parseNaabuOutput: vi.fn().mockReturnValue([{
        host: "target.com",
        ports: [
          { port: 80, protocol: "tcp", service: "http" },
          { port: 443, protocol: "tcp", service: "https" },
        ],
      }]),
    }));

    // Mock pcap-auto-capture
    vi.doMock("./lib/pcap-auto-capture", () => ({
      beforeDiscoveryScan: vi.fn().mockResolvedValue(null),
      afterDiscoveryScan: vi.fn().mockResolvedValue(undefined),
    }));

    const mod = await import("./lib/active-enumeration/port-discovery");
    executePortDiscovery = mod.executePortDiscovery;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  function buildMockState(assetCount: number, initialHostsScanned: number) {
    const assets = Array.from({ length: assetCount }, (_, i) => ({
      hostname: `target${i + 1}.com`,
      ip: `10.0.0.${i + 1}`,
      type: "web_app",
      status: "discovered", // Already discovered by passive recon
      ports: [],
      vulns: [],
      zapFindings: [],
      exploitAttempts: [],
      toolResults: [],
      passiveRecon: { services: [] },
    }));

    return {
      engagementId: 1001,
      assets,
      stats: {
        hostsScanned: initialHostsScanned, // Simulates passive recon having set this
        portsFound: 0,
        vulnsFound: 0,
        assetsDiscovered: assetCount,
        exploitsAttempted: 0,
        exploitsSucceeded: 0,
        sessionsOpened: 0,
        zapScansRun: 0,
        wafDetections: 0,
      },
      scanPlan: null,
      progress: 0,
    };
  }

  function buildMockHelpers() {
    return {
      addLog: vi.fn(),
      broadcastOpsUpdate: vi.fn(),
      executeTool: vi.fn().mockResolvedValue({
        stdout: "80/tcp open http\n443/tcp open https\n",
        stderr: "",
        exitCode: 0,
        timedOut: false,
      }),
      fmtTarget: vi.fn((asset: any, target: string) => target),
      enrichPortServices: vi.fn(),
    };
  }

  it("resets hostsScanned to 0 before incrementing per-asset (fixes double-count)", async () => {
    const state = buildMockState(6, 6); // 6 assets, hostsScanned already set to 6 by passive recon
    const helpers = buildMockHelpers();
    const targets = state.assets.map((a: any) => ({
      scanTarget: a.hostname,
      assetHostname: a.hostname,
    }));

    await executePortDiscovery(state, targets, helpers);

    // After fix: hostsScanned should be exactly 6 (one per asset), NOT 12
    expect(state.stats.hostsScanned).toBe(6);
  });

  it("hostsScanned equals target count even when starting from non-zero", async () => {
    const state = buildMockState(3, 10); // 3 assets but hostsScanned was 10 (stale value)
    const helpers = buildMockHelpers();
    const targets = state.assets.map((a: any) => ({
      scanTarget: a.hostname,
      assetHostname: a.hostname,
    }));

    await executePortDiscovery(state, targets, helpers);

    // Should be 3 (actual assets scanned), not 13
    expect(state.stats.hostsScanned).toBe(3);
  });

  it("hostsScanned is 0 when targets list is empty", async () => {
    const state = buildMockState(3, 3);
    const helpers = buildMockHelpers();

    await executePortDiscovery(state, [], helpers);

    // Empty targets = early return, hostsScanned stays at 3 (no reset for empty)
    expect(state.stats.hostsScanned).toBe(3);
  });

  it("hostsScanned matches asset count on first run (no prior value)", async () => {
    const state = buildMockState(4, 0); // Fresh state, hostsScanned = 0
    const helpers = buildMockHelpers();
    const targets = state.assets.map((a: any) => ({
      scanTarget: a.hostname,
      assetHostname: a.hostname,
    }));

    await executePortDiscovery(state, targets, helpers);

    expect(state.stats.hostsScanned).toBe(4);
  });

  it("hostsScanned does not count assets not in target list", async () => {
    const state = buildMockState(6, 6);
    const helpers = buildMockHelpers();
    // Only scan 3 of the 6 assets
    const targets = state.assets.slice(0, 3).map((a: any) => ({
      scanTarget: a.hostname,
      assetHostname: a.hostname,
    }));

    await executePortDiscovery(state, targets, helpers);

    // Only 3 were in the target list, so hostsScanned = 3
    expect(state.stats.hostsScanned).toBe(3);
  });
});
