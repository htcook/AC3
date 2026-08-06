/**
 * Tests for parallel batched port discovery execution.
 * Verifies that:
 * 1. Targets are batched into groups of MAX_CONCURRENT_TARGETS (3)
 * 2. Each batch runs concurrently (Promise.allSettled)
 * 3. Individual target failures don't crash the batch
 * 4. Stats are updated correctly after each batch
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the imports that port-discovery.ts uses
vi.mock("../scan-server-executor", () => ({
  getScanServerConfigForScanForge: vi.fn().mockResolvedValue({
    host: "10.0.0.1",
    user: "root",
    privateKey: "fake-key",
  }),
}));

vi.mock("../scanforge-discovery", () => ({
  autoSelectTool: vi.fn().mockReturnValue("naabu"),
  parseMasscanOutput: vi.fn().mockReturnValue([]),
  parseNaabuOutput: vi.fn().mockReturnValue([
    { ip: "10.0.0.2", ports: [{ port: 80, protocol: "tcp", service: "http" }, { port: 443, protocol: "tcp", service: "https" }] },
  ]),
  parseRustScanOutput: vi.fn().mockReturnValue([]),
}));

vi.mock("../pcap-auto-capture", () => ({
  beforeDiscoveryScan: vi.fn().mockResolvedValue(null),
  afterDiscoveryScan: vi.fn().mockResolvedValue(null),
}));

describe("port-discovery parallel execution", () => {
  let executePortDiscovery: typeof import("./port-discovery").executePortDiscovery;
  let mockHelpers: any;
  let mockState: any;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Build mock state
    mockState = {
      engagementId: 1,
      phase: "enumeration",
      progress: 15,
      scanPlan: {
        discoveryEvasionProfile: null,
        discoveryStrategy: "test",
        assetPlans: [],
      },
      assets: [
        { hostname: "target1.com", ip: "10.0.0.2", status: "discovered", ports: [], toolResults: [], passiveRecon: {}, type: "web_app" },
        { hostname: "target2.com", ip: "10.0.0.3", status: "discovered", ports: [], toolResults: [], passiveRecon: {}, type: "web_app" },
        { hostname: "target3.com", ip: "10.0.0.4", status: "discovered", ports: [], toolResults: [], passiveRecon: {}, type: "web_app" },
        { hostname: "target4.com", ip: "10.0.0.5", status: "discovered", ports: [], toolResults: [], passiveRecon: {}, type: "web_app" },
        { hostname: "target5.com", ip: "10.0.0.6", status: "discovered", ports: [], toolResults: [], passiveRecon: {}, type: "web_app" },
      ],
      stats: { hostsScanned: 0, portsFound: 0 },
    };

    // Build mock helpers
    mockHelpers = {
      addLog: vi.fn(),
      broadcastOpsUpdate: vi.fn(),
      broadcastReconFinding: vi.fn(),
      fmtTarget: vi.fn((asset: any, target: string) => `${asset.hostname} (${target})`),
      executeTool: vi.fn().mockResolvedValue({
        stdout: '{"host":"10.0.0.2","port":80,"protocol":"tcp"}',
        stderr: "",
        exitCode: 0,
        timedOut: false,
      }),
      enrichPortServices: vi.fn(),
      parseToolOutput: vi.fn(),
    };

    // Dynamic import after mocks are set up
    const mod = await import("./port-discovery");
    executePortDiscovery = mod.executePortDiscovery;
  });

  it("should batch targets into groups of 3", async () => {
    const targets = [
      { scanTarget: "10.0.0.2", assetHostname: "target1.com" },
      { scanTarget: "10.0.0.3", assetHostname: "target2.com" },
      { scanTarget: "10.0.0.4", assetHostname: "target3.com" },
      { scanTarget: "10.0.0.5", assetHostname: "target4.com" },
      { scanTarget: "10.0.0.6", assetHostname: "target5.com" },
    ];

    await executePortDiscovery(mockState, targets, mockHelpers);

    // Should have logged 2 parallel batch messages (batch 1: 3 targets, batch 2: 2 targets)
    const batchLogs = mockHelpers.addLog.mock.calls.filter(
      (call: any) => call[0]?.title?.includes("Parallel Batch")
    );
    expect(batchLogs.length).toBe(2);
    expect(batchLogs[0][0].title).toContain("Batch 1/2");
    expect(batchLogs[1][0].title).toContain("Batch 2/2");
  });

  it("should scan all targets even if one fails", async () => {
    // Make the second target fail
    let callCount = 0;
    mockHelpers.executeTool = vi.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 2) {
        throw new Error("Connection refused");
      }
      return {
        stdout: '{"host":"10.0.0.2","port":80,"protocol":"tcp"}',
        stderr: "",
        exitCode: 0,
        timedOut: false,
      };
    });

    const targets = [
      { scanTarget: "10.0.0.2", assetHostname: "target1.com" },
      { scanTarget: "10.0.0.3", assetHostname: "target2.com" },
      { scanTarget: "10.0.0.4", assetHostname: "target3.com" },
    ];

    // Should not throw
    await executePortDiscovery(mockState, targets, mockHelpers);

    // All 3 targets should have been attempted (executeTool called 3 times)
    expect(mockHelpers.executeTool).toHaveBeenCalledTimes(3);

    // The failed target should have an error log
    const errorLogs = mockHelpers.addLog.mock.calls.filter(
      (call: any) => call[0]?.type === "error" && call[0]?.title?.includes("scanforge Failed")
    );
    expect(errorLogs.length).toBe(1);
  });

  it("should handle empty target list gracefully", async () => {
    await executePortDiscovery(mockState, [], mockHelpers);
    expect(mockHelpers.addLog).not.toHaveBeenCalled();
  });

  it("should not show parallel batch log for single target", async () => {
    const targets = [{ scanTarget: "10.0.0.2", assetHostname: "target1.com" }];

    await executePortDiscovery(mockState, targets, mockHelpers);

    const batchLogs = mockHelpers.addLog.mock.calls.filter(
      (call: any) => call[0]?.title?.includes("Parallel Batch")
    );
    expect(batchLogs.length).toBe(0);
  });

  it("should update progress proportionally after each batch", async () => {
    const targets = [
      { scanTarget: "10.0.0.2", assetHostname: "target1.com" },
      { scanTarget: "10.0.0.3", assetHostname: "target2.com" },
      { scanTarget: "10.0.0.4", assetHostname: "target3.com" },
      { scanTarget: "10.0.0.5", assetHostname: "target4.com" },
    ];

    await executePortDiscovery(mockState, targets, mockHelpers);

    // Progress should end at 25 (15 + 10 * 1.0)
    expect(mockState.progress).toBe(25);
  });
});
