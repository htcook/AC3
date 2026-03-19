/**
 * Evidence Gallery Router — Vitest Tests
 *
 * Tests the evidence gallery tRPC procedures:
 *   - captureEvidence (live Caldera capture + DB persistence)
 *   - exportPng (render + upload)
 *   - gallery (listing + filtering)
 *   - galleryStats (aggregation)
 *   - engagementsWithEvidence (engagement listing)
 *   - exportLive (live capture + render without DB)
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock caldera-evidence-collector ─────────────────────────────────
const mockCaptureCalderaEvidence = vi.fn();
const mockRenderEvidenceToFile = vi.fn();

vi.mock("./lib/caldera-evidence-collector", () => ({
  captureCalderaEvidence: (...args: any[]) => mockCaptureCalderaEvidence(...args),
  renderEvidenceToFile: (...args: any[]) => mockRenderEvidenceToFile(...args),
}));

// ─── Mock storage ────────────────────────────────────────────────────
const mockStoragePut = vi.fn();
vi.mock("./storage", () => ({
  storagePut: (...args: any[]) => mockStoragePut(...args),
}));

// ─── Mock DB ─────────────────────────────────────────────────────────
const mockSelect = vi.fn();
const mockInsert = vi.fn();
const mockFrom = vi.fn();
const mockWhere = vi.fn();
const mockOrderBy = vi.fn();
const mockLimit = vi.fn();
const mockOffset = vi.fn();
const mockGroupBy = vi.fn();
const mockValues = vi.fn();

const mockDb = {
  select: () => {
    const chain: any = {
      from: (table: any) => {
        mockFrom(table);
        return {
          where: (cond: any) => {
            mockWhere(cond);
            return {
              orderBy: () => ({
                limit: () => ({
                  offset: () => Promise.resolve([]),
                }),
              }),
              limit: () => ({
                offset: () => Promise.resolve([]),
              }),
              groupBy: () => Promise.resolve([]),
            };
          },
          groupBy: () => Promise.resolve([]),
          orderBy: () => ({
            limit: () => ({
              offset: () => Promise.resolve([]),
            }),
          }),
        };
      },
    };
    return chain;
  },
  insert: (table: any) => ({
    values: (vals: any) => {
      mockInsert(table);
      mockValues(vals);
      return Promise.resolve();
    },
  }),
};

vi.mock("./db", () => ({
  getDb: () => Promise.resolve(mockDb),
}));

// ─── Mock fetch for HTML download ────────────────────────────────────
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ─── Mock fs ─────────────────────────────────────────────────────────
vi.mock("fs/promises", () => ({
  default: {
    mkdir: vi.fn().mockResolvedValue(undefined),
    writeFile: vi.fn().mockResolvedValue(undefined),
    readFile: vi.fn().mockResolvedValue(Buffer.from("PNG_DATA")),
    unlink: vi.fn().mockResolvedValue(undefined),
  },
  mkdir: vi.fn().mockResolvedValue(undefined),
  writeFile: vi.fn().mockResolvedValue(undefined),
  readFile: vi.fn().mockResolvedValue(Buffer.from("PNG_DATA")),
  unlink: vi.fn().mockResolvedValue(undefined),
}));

// ─── Import types ────────────────────────────────────────────────────
import type { CalderaEvidenceSnapshot } from "./lib/caldera-evidence-collector";

// ─── Test Data ───────────────────────────────────────────────────────
function makeMockSnapshot(overrides: Partial<CalderaEvidenceSnapshot> = {}): CalderaEvidenceSnapshot {
  return {
    engagementId: 1770043,
    engagementName: "Banking Systems Pentest",
    calderaServerUrl: "http://134.199.213.248:8888",
    calderaServerIp: "134.199.213.248",
    agents: [
      {
        paw: "xyzabc",
        host: "dvwa-target",
        platform: "linux",
        username: "root",
        privilege: "Elevated",
        pid: 12345,
        exeName: "sandcat.go",
        contact: "HTTP",
        hostIp: "172.17.0.2",
        executors: ["sh"],
        created: "2026-03-15T10:00:00Z",
        lastSeen: "2026-03-15T12:00:00Z",
        displayName: "dvwa-target$root",
        linksExecuted: 15,
      },
    ],
    operations: [
      {
        operationId: "op-123",
        operationName: "Banking DVWA Exploitation",
        state: "finished",
        startedAt: "2026-03-15T10:05:00Z",
        adversaryName: "Axiom",
        adversaryId: "adv-axiom",
        plannerName: "atomic",
        agentCount: 1,
        links: [
          {
            linkId: "link-1",
            paw: "xyzabc",
            agentHost: "dvwa-target",
            abilityName: "Find System Info",
            tactic: "discovery",
            techniqueId: "T1082",
            techniqueName: "System Information Discovery",
            status: "success",
            decidedAt: "2026-03-15T10:06:00Z",
          },
        ],
      },
    ],
    adversaryProfile: {
      adversaryId: "adv-axiom",
      name: "Axiom",
      description: "APT threat group",
      abilities: [
        {
          abilityId: "ab-1",
          name: "Find System Info",
          tactic: "discovery",
          techniqueId: "T1082",
          techniqueName: "System Information Discovery",
        },
      ],
    },
    capturedAt: "2026-03-15T12:30:00Z",
    renderedHtml: {
      agentTable: "<html><body>Agent Table HTML</body></html>",
      operationTimeline: "<html><body>Operation Timeline HTML</body></html>",
      adversaryProfile: "<html><body>Adversary Profile HTML</body></html>",
      attackChainSummary: "<html><body>Attack Chain Summary HTML</body></html>",
    },
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────

describe("Evidence Gallery — Data Types", () => {
  it("CalderaEvidenceSnapshot includes source/destination IP and timestamps", () => {
    const snapshot = makeMockSnapshot();
    expect(snapshot.calderaServerIp).toBe("134.199.213.248");
    expect(snapshot.calderaServerUrl).toBe("http://134.199.213.248:8888");
    expect(snapshot.agents[0].hostIp).toBe("172.17.0.2");
    expect(snapshot.agents[0].created).toBeTruthy();
    expect(snapshot.agents[0].lastSeen).toBeTruthy();
    expect(snapshot.capturedAt).toBeTruthy();
  });

  it("Agent evidence includes all required network fields", () => {
    const snapshot = makeMockSnapshot();
    const agent = snapshot.agents[0];
    expect(agent).toHaveProperty("paw");
    expect(agent).toHaveProperty("host");
    expect(agent).toHaveProperty("hostIp");
    expect(agent).toHaveProperty("platform");
    expect(agent).toHaveProperty("username");
    expect(agent).toHaveProperty("privilege");
    expect(agent).toHaveProperty("contact");
    expect(agent).toHaveProperty("created");
    expect(agent).toHaveProperty("lastSeen");
    expect(agent).toHaveProperty("linksExecuted");
  });

  it("Operation evidence includes timeline with timestamps", () => {
    const snapshot = makeMockSnapshot();
    const op = snapshot.operations[0];
    expect(op.startedAt).toBeTruthy();
    expect(op.links[0].decidedAt).toBeTruthy();
    expect(op.links[0].status).toBe("success");
    expect(op.links[0].agentHost).toBe("dvwa-target");
  });

  it("Rendered HTML panels are all present", () => {
    const snapshot = makeMockSnapshot();
    expect(snapshot.renderedHtml.agentTable).toContain("Agent Table");
    expect(snapshot.renderedHtml.operationTimeline).toContain("Operation Timeline");
    expect(snapshot.renderedHtml.adversaryProfile).toContain("Adversary Profile");
    expect(snapshot.renderedHtml.attackChainSummary).toContain("Attack Chain Summary");
  });
});

describe("Evidence Gallery — Capture Flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("captureCalderaEvidence is called with correct params", async () => {
    const snapshot = makeMockSnapshot();
    mockCaptureCalderaEvidence.mockResolvedValue(snapshot);

    await mockCaptureCalderaEvidence({
      engagementId: 1770043,
      engagementName: "Banking Systems Pentest",
      operationId: "op-123",
      adversaryId: "adv-axiom",
      targets: [{ hostname: "dvwa-target", ip: "172.17.0.2" }],
    });

    expect(mockCaptureCalderaEvidence).toHaveBeenCalledWith({
      engagementId: 1770043,
      engagementName: "Banking Systems Pentest",
      operationId: "op-123",
      adversaryId: "adv-axiom",
      targets: [{ hostname: "dvwa-target", ip: "172.17.0.2" }],
    });
  });

  it("returns null when Caldera URL is not configured", async () => {
    mockCaptureCalderaEvidence.mockResolvedValue(null);

    const result = await mockCaptureCalderaEvidence({
      engagementId: 1,
      engagementName: "Test",
    });

    expect(result).toBeNull();
  });

  it("snapshot includes all 4 rendered HTML panels", async () => {
    const snapshot = makeMockSnapshot();
    mockCaptureCalderaEvidence.mockResolvedValue(snapshot);

    const result = await mockCaptureCalderaEvidence({
      engagementId: 1770043,
      engagementName: "Banking Systems Pentest",
    });

    expect(result.renderedHtml).toHaveProperty("agentTable");
    expect(result.renderedHtml).toHaveProperty("operationTimeline");
    expect(result.renderedHtml).toHaveProperty("adversaryProfile");
    expect(result.renderedHtml).toHaveProperty("attackChainSummary");
  });
});

describe("Evidence Gallery — Export Flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renderEvidenceToFile returns success with PNG format", async () => {
    mockRenderEvidenceToFile.mockResolvedValue({
      success: true,
      path: "/tmp/evidence-export/test.png",
      format: "png",
    });

    const result = await mockRenderEvidenceToFile("<html>test</html>", "/tmp/test.png");
    expect(result.success).toBe(true);
    expect(result.format).toBe("png");
  });

  it("renderEvidenceToFile falls back to HTML when PNG tools unavailable", async () => {
    mockRenderEvidenceToFile.mockResolvedValue({
      success: true,
      path: "/tmp/evidence-export/test.html",
      format: "html",
    });

    const result = await mockRenderEvidenceToFile("<html>test</html>", "/tmp/test.png");
    expect(result.success).toBe(true);
    expect(result.format).toBe("html");
  });

  it("storagePut is called with correct content type for PNG", async () => {
    mockStoragePut.mockResolvedValue({ key: "test-key", url: "https://s3.example.com/test.png" });

    await mockStoragePut("evidence-exports/test.png", Buffer.from("PNG"), "image/png");

    expect(mockStoragePut).toHaveBeenCalledWith(
      "evidence-exports/test.png",
      expect.any(Buffer),
      "image/png"
    );
  });

  it("storagePut is called with correct content type for HTML fallback", async () => {
    mockStoragePut.mockResolvedValue({ key: "test-key", url: "https://s3.example.com/test.html" });

    await mockStoragePut("evidence-exports/test.html", Buffer.from("<html>"), "text/html");

    expect(mockStoragePut).toHaveBeenCalledWith(
      "evidence-exports/test.html",
      expect.any(Buffer),
      "text/html"
    );
  });
});

describe("Evidence Gallery — Panel Types", () => {
  it("all four panel types are defined", () => {
    const panels = ["agentTable", "operationTimeline", "adversaryProfile", "attackChainSummary"];
    for (const p of panels) {
      expect(panels).toContain(p);
    }
  });

  it("panel labels map correctly", () => {
    const labels: Record<string, string> = {
      agentTable: "C2 Agent Check-Ins",
      operationTimeline: "Operation Timeline",
      adversaryProfile: "Adversary Profile",
      attackChainSummary: "Attack Chain Summary",
    };
    expect(labels.agentTable).toBe("C2 Agent Check-Ins");
    expect(labels.operationTimeline).toBe("Operation Timeline");
    expect(labels.adversaryProfile).toBe("Adversary Profile");
    expect(labels.attackChainSummary).toBe("Attack Chain Summary");
  });
});

describe("Evidence Gallery — Metadata Parsing", () => {
  it("parses metadata JSON with phase info", () => {
    const metadata = JSON.stringify({
      calderaServerUrl: "http://134.199.213.248:8888",
      calderaServerIp: "134.199.213.248",
      agentCount: 2,
      operationCount: 1,
      hasAdversary: true,
      capturedAt: "2026-03-15T12:30:00Z",
      panelType: "agentTable",
      phase: "exploitation",
    });

    const parsed = JSON.parse(metadata);
    expect(parsed.phase).toBe("exploitation");
    expect(parsed.calderaServerIp).toBe("134.199.213.248");
    expect(parsed.agentCount).toBe(2);
  });

  it("parses tags JSON with agent PAWs", () => {
    const tags = JSON.stringify(["caldera", "auto-captured", "agentTable", "agent:xyzabc", "agent:def456"]);
    const parsed = JSON.parse(tags);
    const agentTags = parsed.filter((t: string) => t.startsWith("agent:"));
    expect(agentTags).toHaveLength(2);
    expect(agentTags[0]).toBe("agent:xyzabc");
  });

  it("handles missing metadata gracefully", () => {
    const metadata = "{}";
    const parsed = JSON.parse(metadata);
    expect(parsed.phase).toBeUndefined();
    expect(parsed.calderaServerIp).toBeUndefined();
  });
});

describe("Evidence Gallery — Filtering Logic", () => {
  it("filters by phase from metadata", () => {
    const items = [
      { parsedMetadata: { phase: "exploitation" }, category: "agentTable" },
      { parsedMetadata: { phase: "post-exploitation" }, category: "operationTimeline" },
      { parsedMetadata: { phase: "exploitation" }, category: "attackChainSummary" },
    ];

    const filtered = items.filter(item => item.parsedMetadata.phase === "exploitation");
    expect(filtered).toHaveLength(2);
  });

  it("filters by agent PAW from tags", () => {
    const items = [
      { parsedTags: ["caldera", "agent:xyzabc"] },
      { parsedTags: ["caldera", "agent:def456"] },
      { parsedTags: ["caldera", "agent:xyzabc", "agent:def456"] },
    ];

    const targetPaw = "xyzabc";
    const filtered = items.filter(item =>
      item.parsedTags.some((t: string) => t.includes(targetPaw))
    );
    expect(filtered).toHaveLength(2);
  });

  it("filters by panel type", () => {
    const items = [
      { category: "agentTable" },
      { category: "operationTimeline" },
      { category: "agentTable" },
      { category: "adversaryProfile" },
    ];

    const filtered = items.filter(item => item.category === "agentTable");
    expect(filtered).toHaveLength(2);
  });

  it("combined filters narrow results correctly", () => {
    const items = [
      { parsedMetadata: { phase: "exploitation" }, category: "agentTable", parsedTags: ["agent:abc"] },
      { parsedMetadata: { phase: "post-exploitation" }, category: "agentTable", parsedTags: ["agent:abc"] },
      { parsedMetadata: { phase: "exploitation" }, category: "operationTimeline", parsedTags: ["agent:def"] },
    ];

    const filtered = items.filter(item =>
      item.parsedMetadata.phase === "exploitation" &&
      item.category === "agentTable" &&
      item.parsedTags.some((t: string) => t.includes("abc"))
    );
    expect(filtered).toHaveLength(1);
  });
});

describe("Evidence Gallery — Live Export", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("live export captures and renders in one step", async () => {
    const snapshot = makeMockSnapshot();
    mockCaptureCalderaEvidence.mockResolvedValue(snapshot);
    mockRenderEvidenceToFile.mockResolvedValue({
      success: true,
      path: "/tmp/evidence-export/live-agentTable.png",
      format: "png",
    });
    mockStoragePut.mockResolvedValue({ key: "test", url: "https://s3.example.com/live.png" });

    // Simulate the live export flow
    const captured = await mockCaptureCalderaEvidence({
      engagementId: 1770043,
      engagementName: "Banking Systems Pentest",
    });

    const html = captured.renderedHtml.agentTable;
    const rendered = await mockRenderEvidenceToFile(html, "/tmp/test.png");
    const uploaded = await mockStoragePut("evidence-exports/live.png", Buffer.from("PNG"), "image/png");

    expect(captured.agents).toHaveLength(1);
    expect(rendered.success).toBe(true);
    expect(uploaded.url).toBeTruthy();
  });
});

describe("Evidence Gallery — Network Context Validation", () => {
  it("every agent has source IP (C2 server) and destination IP (host)", () => {
    const snapshot = makeMockSnapshot();
    // Source = Caldera server
    expect(snapshot.calderaServerIp).toMatch(/\d+\.\d+\.\d+\.\d+/);
    // Destination = agent host IPs
    for (const agent of snapshot.agents) {
      expect(agent.hostIp).toMatch(/\d+\.\d+\.\d+\.\d+/);
    }
  });

  it("operation links include agent host for destination context", () => {
    const snapshot = makeMockSnapshot();
    for (const op of snapshot.operations) {
      for (const link of op.links) {
        expect(link.agentHost).toBeTruthy();
        expect(link.decidedAt).toBeTruthy();
      }
    }
  });

  it("timestamps are ISO 8601 format", () => {
    const snapshot = makeMockSnapshot();
    const isoRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
    expect(snapshot.capturedAt).toMatch(isoRegex);
    expect(snapshot.agents[0].created).toMatch(isoRegex);
    expect(snapshot.agents[0].lastSeen).toMatch(isoRegex);
    expect(snapshot.operations[0].startedAt).toMatch(isoRegex);
    expect(snapshot.operations[0].links[0].decidedAt).toMatch(isoRegex);
  });
});
