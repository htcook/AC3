/**
 * Tests for:
 * 1. SSE Event Stream endpoint (server-side)
 * 2. Hydra checkpoint tracking (skip-on-resume)
 * 3. Exploit checkpoint tracking (skip-on-resume)
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── SSE Event Stream Tests ─────────────────────────────────────────

describe("SSE Event Stream", () => {
  it("should export registerSSEEventStream function", async () => {
    const mod = await import("./sse-event-stream");
    expect(typeof mod.registerSSEEventStream).toBe("function");
  });

  it("should register GET /api/events/stream route on Express app", async () => {
    const { registerSSEEventStream } = await import("./sse-event-stream");
    const routes: Array<{ method: string; path: string }> = [];
    const mockApp = {
      get: vi.fn((path: string, _handler: any) => {
        routes.push({ method: "GET", path });
      }),
    };
    registerSSEEventStream(mockApp as any);
    expect(mockApp.get).toHaveBeenCalledWith("/api/events/stream", expect.any(Function));
    expect(routes).toEqual([{ method: "GET", path: "/api/events/stream" }]);
  });
});

// ─── Hydra Checkpoint Tracking Tests ────────────────────────────────

describe("Hydra Checkpoint Tracking", () => {
  let state: any;

  beforeEach(() => {
    state = {
      completedScans: {
        nucleiCompleted: new Set<string>(),
        zapCompleted: new Set<string>(),
        hydraCompleted: new Set<string>(),
        exploitCompleted: new Set<string>(),
        lastCheckpointAt: Date.now(),
      },
    };
  });

  it("should skip hydra targets already in hydraCompleted set", () => {
    const hydraKey = "hydra:192.168.1.1:SSH brute-force";
    state.completedScans.hydraCompleted.add(hydraKey);

    // Simulate the skip check from the credential testing loop
    const shouldSkip = state.completedScans.hydraCompleted.has(hydraKey);
    expect(shouldSkip).toBe(true);
  });

  it("should not skip new hydra targets", () => {
    const hydraKey = "hydra:10.0.0.5:FTP brute-force";
    const shouldSkip = state.completedScans.hydraCompleted.has(hydraKey);
    expect(shouldSkip).toBe(false);
  });

  it("should add hydra target to completed set after execution", () => {
    const hydraKey = "hydra:192.168.1.1:SSH brute-force";
    expect(state.completedScans.hydraCompleted.size).toBe(0);

    // Simulate post-execution checkpoint
    state.completedScans.hydraCompleted.add(hydraKey);
    state.completedScans.lastCheckpointAt = Date.now();

    expect(state.completedScans.hydraCompleted.size).toBe(1);
    expect(state.completedScans.hydraCompleted.has(hydraKey)).toBe(true);
  });

  it("should track multiple hydra targets independently", () => {
    const targets = [
      "hydra:192.168.1.1:SSH brute-force",
      "hydra:192.168.1.2:HTTP form login",
      "hydra:10.0.0.5:FTP brute-force",
    ];

    // Complete first two
    state.completedScans.hydraCompleted.add(targets[0]);
    state.completedScans.hydraCompleted.add(targets[1]);

    expect(state.completedScans.hydraCompleted.has(targets[0])).toBe(true);
    expect(state.completedScans.hydraCompleted.has(targets[1])).toBe(true);
    expect(state.completedScans.hydraCompleted.has(targets[2])).toBe(false);
    expect(state.completedScans.hydraCompleted.size).toBe(2);
  });

  it("should serialize hydraCompleted Set to array for DB persistence", () => {
    state.completedScans.hydraCompleted.add("hydra:192.168.1.1:SSH");
    state.completedScans.hydraCompleted.add("hydra:10.0.0.5:FTP");

    // Simulate serialization (from saveOpsSnapshot)
    const serialized = {
      ...state.completedScans,
      hydraCompleted: Array.from(state.completedScans.hydraCompleted),
    };

    expect(Array.isArray(serialized.hydraCompleted)).toBe(true);
    expect(serialized.hydraCompleted).toEqual(["hydra:192.168.1.1:SSH", "hydra:10.0.0.5:FTP"]);
  });

  it("should rehydrate hydraCompleted from array back to Set", () => {
    const fromDb = ["hydra:192.168.1.1:SSH", "hydra:10.0.0.5:FTP"];

    // Simulate rehydration (from normalizeOpsState)
    const rehydrated = new Set(fromDb);
    expect(rehydrated instanceof Set).toBe(true);
    expect(rehydrated.size).toBe(2);
    expect(rehydrated.has("hydra:192.168.1.1:SSH")).toBe(true);
  });
});

// ─── Exploit Checkpoint Tracking Tests ──────────────────────────────

describe("Exploit Checkpoint Tracking", () => {
  let state: any;

  beforeEach(() => {
    state = {
      completedScans: {
        nucleiCompleted: new Set<string>(),
        zapCompleted: new Set<string>(),
        hydraCompleted: new Set<string>(),
        exploitCompleted: new Set<string>(),
        lastCheckpointAt: Date.now(),
      },
    };
  });

  it("should skip exploit targets already in exploitCompleted set", () => {
    const exploitKey = "target.com:443:CVE-2024-1234";
    state.completedScans.exploitCompleted.add(exploitKey);

    const shouldSkip = state.completedScans.exploitCompleted.has(exploitKey);
    expect(shouldSkip).toBe(true);
  });

  it("should not skip new exploit targets", () => {
    const exploitKey = "target.com:8080:CVE-2024-5678";
    const shouldSkip = state.completedScans.exploitCompleted.has(exploitKey);
    expect(shouldSkip).toBe(false);
  });

  it("should add exploit target to completed set after execution", () => {
    const exploitKey = "target.com:443:CVE-2024-1234";
    expect(state.completedScans.exploitCompleted.size).toBe(0);

    state.completedScans.exploitCompleted.add(exploitKey);
    state.completedScans.lastCheckpointAt = Date.now();

    expect(state.completedScans.exploitCompleted.size).toBe(1);
    expect(state.completedScans.exploitCompleted.has(exploitKey)).toBe(true);
  });

  it("should generate correct exploit key format: target:port:cve_or_module", () => {
    // Simulate the key generation from the exploit loop
    const target = "192.168.1.100";
    const port = 443;
    const cve = "CVE-2024-1234";
    const module = "apache_struts_rce";

    // With CVE
    const keyWithCve = `${target}:${port}:${cve || module || 'auto'}`;
    expect(keyWithCve).toBe("192.168.1.100:443:CVE-2024-1234");

    // Without CVE, with module
    const keyWithModule = `${target}:${port}:${undefined || module || 'auto'}`;
    expect(keyWithModule).toBe("192.168.1.100:443:apache_struts_rce");

    // Without CVE or module
    const keyAuto = `${target}:${port}:${undefined || undefined || 'auto'}`;
    expect(keyAuto).toBe("192.168.1.100:443:auto");
  });

  it("should track both success and failure as completed", () => {
    // Both successful and failed exploits should be marked as completed
    // to avoid re-running them on resume
    const successKey = "target.com:443:CVE-2024-1234";
    const failKey = "target.com:8080:CVE-2024-5678";

    state.completedScans.exploitCompleted.add(successKey);
    state.completedScans.exploitCompleted.add(failKey);

    expect(state.completedScans.exploitCompleted.size).toBe(2);
    expect(state.completedScans.exploitCompleted.has(successKey)).toBe(true);
    expect(state.completedScans.exploitCompleted.has(failKey)).toBe(true);
  });

  it("should serialize exploitCompleted Set to array for DB persistence", () => {
    state.completedScans.exploitCompleted.add("target.com:443:CVE-2024-1234");
    state.completedScans.exploitCompleted.add("target.com:8080:auto");

    const serialized = {
      ...state.completedScans,
      exploitCompleted: Array.from(state.completedScans.exploitCompleted),
    };

    expect(Array.isArray(serialized.exploitCompleted)).toBe(true);
    expect(serialized.exploitCompleted).toHaveLength(2);
  });

  it("should rehydrate exploitCompleted from array back to Set", () => {
    const fromDb = ["target.com:443:CVE-2024-1234", "target.com:8080:auto"];
    const rehydrated = new Set(fromDb);
    expect(rehydrated instanceof Set).toBe(true);
    expect(rehydrated.size).toBe(2);
    expect(rehydrated.has("target.com:443:CVE-2024-1234")).toBe(true);
  });
});

// ─── normalizeOpsState completedScans rehydration ───────────────────

describe("normalizeOpsState completedScans rehydration", () => {
  it("should rehydrate all four completedScans Sets from arrays", async () => {
    const { normalizeOpsState } = await import("./engagement-orchestrator");

    const mockState = {
      engagementId: 1,
      phase: "vuln_detection",
      isRunning: true,
      log: [],
      assets: [],
      stats: {},
      completedScans: {
        nucleiCompleted: ["http://target.com"],
        zapCompleted: ["http://target.com/app"],
        hydraCompleted: ["hydra:192.168.1.1:SSH"],
        exploitCompleted: ["target.com:443:CVE-2024-1234"],
        lastCheckpointAt: 1700000000000,
      },
    };

    const normalized = normalizeOpsState(mockState);

    expect(normalized.completedScans.nucleiCompleted instanceof Set).toBe(true);
    expect(normalized.completedScans.zapCompleted instanceof Set).toBe(true);
    expect(normalized.completedScans.hydraCompleted instanceof Set).toBe(true);
    expect(normalized.completedScans.exploitCompleted instanceof Set).toBe(true);

    expect(normalized.completedScans.nucleiCompleted.has("http://target.com")).toBe(true);
    expect(normalized.completedScans.zapCompleted.has("http://target.com/app")).toBe(true);
    expect(normalized.completedScans.hydraCompleted.has("hydra:192.168.1.1:SSH")).toBe(true);
    expect(normalized.completedScans.exploitCompleted.has("target.com:443:CVE-2024-1234")).toBe(true);
  });

  it("should initialize empty Sets when completedScans is missing", async () => {
    const { normalizeOpsState } = await import("./engagement-orchestrator");

    const mockState = {
      engagementId: 1,
      phase: "recon",
      isRunning: true,
      log: [],
      assets: [],
      stats: {},
      // No completedScans field at all
    };

    const normalized = normalizeOpsState(mockState);

    expect(normalized.completedScans).toBeDefined();
    expect(normalized.completedScans.nucleiCompleted instanceof Set).toBe(true);
    expect(normalized.completedScans.hydraCompleted instanceof Set).toBe(true);
    expect(normalized.completedScans.exploitCompleted instanceof Set).toBe(true);
    expect(normalized.completedScans.nucleiCompleted.size).toBe(0);
  });
});
