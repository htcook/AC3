import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createProtectedContext(): { ctx: TrpcContext } {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-user",
    email: "test@example.com",
    name: "Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };
  const ctx: TrpcContext = {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
  return { ctx };
}

// ─── Unified Pipeline Router ──────────────────────────────────────────────────

describe("unifiedPipeline", () => {
  it("returns pipeline stage definitions", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const stages = await caller.unifiedPipeline.getStages();
    expect(stages).toBeDefined();
    expect(Array.isArray(stages)).toBe(true);
    expect(stages.length).toBeGreaterThan(0);
    expect(stages[0]).toHaveProperty("phase");
    expect(stages[0]).toHaveProperty("tools");
    expect(stages[0]).toHaveProperty("toolDetails");
  });

  it("returns tool-to-phase matrix", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const matrix = await caller.unifiedPipeline.getToolMatrix();
    expect(matrix).toBeDefined();
    expect(Array.isArray(matrix)).toBe(true);
    expect(matrix.length).toBeGreaterThan(0);
    expect(matrix[0]).toHaveProperty("tool");
    expect(matrix[0]).toHaveProperty("phases");
  });

  it("starts a pipeline run and returns runId", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.unifiedPipeline.startRun({
      domain: "example.com",
      targetUrls: ["https://example.com"],
      targetIps: ["93.184.216.34"],
    });
    expect(result).toHaveProperty("runId");
    expect(result).toHaveProperty("status", "pending");
    expect(result.target.domain).toBe("example.com");
  });

  it("lists pipeline runs", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    // Start a run first
    await caller.unifiedPipeline.startRun({ domain: "test.com" });
    const runs = await caller.unifiedPipeline.listRuns();
    expect(Array.isArray(runs)).toBe(true);
    expect(runs.length).toBeGreaterThan(0);
    expect(runs[0]).toHaveProperty("id");
    expect(runs[0]).toHaveProperty("domain");
    expect(runs[0]).toHaveProperty("status");
  });

  it("submits findings to a pipeline run", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const { runId } = await caller.unifiedPipeline.startRun({ domain: "vuln.test" });
    const result = await caller.unifiedPipeline.submitFindings({
      runId,
      phase: "recon",
      tool: "passive_osint",
      findings: [
        { type: "subdomain", title: "sub.vuln.test", host: "sub.vuln.test", severity: "info" },
        { type: "port", title: "Port 443 open", host: "vuln.test", port: 443, severity: "info" },
      ],
    });
    expect(result.findingsAdded).toBe(2);
    expect(result.totalFindings).toBe(2);
  });

  it("completes a phase and returns correlation data", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const { runId } = await caller.unifiedPipeline.startRun({ domain: "phase.test" });
    await caller.unifiedPipeline.submitFindings({
      runId,
      phase: "recon",
      tool: "passive_osint",
      findings: [{ title: "DNS record", host: "phase.test", severity: "info" }],
    });
    const result = await caller.unifiedPipeline.completePhase({ runId, phase: "recon" });
    expect(result.phase).toBe("recon");
    expect(result.status).toBe("completed");
    expect(result).toHaveProperty("findingsInPhase");
    expect(result).toHaveProperty("nextPhase");
  });

  it("cancels a running pipeline", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const { runId } = await caller.unifiedPipeline.startRun({ domain: "cancel.test" });
    const result = await caller.unifiedPipeline.cancelRun({ runId });
    expect(result.status).toBe("cancelled");
  });

  it("returns discovery coverage data", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const coverage = await caller.unifiedPipeline.getDiscoveryCoverage();
    expect(coverage).toBeDefined();
  });

  it("returns corroboration weights", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const weights = await caller.unifiedPipeline.getCorroborationWeights();
    expect(weights).toBeDefined();
  });
});

// ─── Sliver C2 Router ─────────────────────────────────────────────────────────

describe("sliverC2", () => {
  it("returns C2 stats", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const stats = await caller.sliverC2.getStats();
    expect(stats).toHaveProperty("totalImplants");
    expect(stats).toHaveProperty("activeSessions");
    expect(stats).toHaveProperty("activeListeners");
    expect(stats).toHaveProperty("byTransport");
    expect(stats).toHaveProperty("byOs");
  });

  it("generates an implant", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const implant = await caller.sliverC2.generateImplant({
      name: "test-beacon",
      os: "windows",
      arch: "amd64",
      transport: "mtls",
      host: "c2.test.com",
      port: 443,
      obfuscation: true,
    });
    expect(implant).toHaveProperty("id");
    expect(implant.name).toBe("test-beacon");
    expect(implant.os).toBe("windows");
    expect(implant.transport).toBe("mtls");
    expect(implant).toHaveProperty("sha256");
  });

  it("lists implants after generation", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.sliverC2.listImplants();
    expect(result).toHaveProperty("total");
    expect(result).toHaveProperty("implants");
    expect(result.total).toBeGreaterThan(0);
  });

  it("starts and stops a listener", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const listener = await caller.sliverC2.startListener({
      transport: "https",
      host: "0.0.0.0",
      port: 8443,
    });
    expect(listener).toHaveProperty("id");
    expect(listener.status).toBe("active");

    const stopResult = await caller.sliverC2.stopListener({ id: listener.id });
    expect(stopResult.success).toBe(true);
  });

  it("lists listeners", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const listeners = await caller.sliverC2.listListeners();
    expect(Array.isArray(listeners)).toBe(true);
  });
});

// ─── Nuclei Scanner Router ────────────────────────────────────────────────────

describe("nucleiScanner", () => {
  it("returns template categories", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const categories = await caller.nucleiScanner.listTemplateCategories();
    expect(Array.isArray(categories)).toBe(true);
    expect(categories.length).toBeGreaterThan(0);
    expect(categories[0]).toHaveProperty("category");
    expect(categories[0]).toHaveProperty("templateCount");
  });

  it("starts a scan", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.nucleiScanner.startScan({
      targets: ["https://example.com"],
      rateLimit: 100,
      concurrency: 10,
    });
    expect(result).toHaveProperty("scanId");
    expect(result.status).toBe("running");
  });

  it("lists scans", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.nucleiScanner.listScans();
    expect(result).toHaveProperty("total");
    expect(result).toHaveProperty("scans");
  });

  it("returns scanner stats", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const stats = await caller.nucleiScanner.getStats();
    expect(stats).toHaveProperty("totalScans");
    expect(stats).toHaveProperty("totalTemplates");
    expect(stats).toHaveProperty("bySeverity");
    expect(stats.totalTemplates).toBeGreaterThan(0);
  });

  it("submits findings to a scan", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const { scanId } = await caller.nucleiScanner.startScan({ targets: ["test.com"] });
    const result = await caller.nucleiScanner.submitFindings({
      scanId,
      findings: [
        { templateId: "CVE-2021-44228", name: "Log4Shell", severity: "critical", host: "test.com" },
      ],
    });
    expect(result.added).toBe(1);
    expect(result.total).toBe(1);
  });

  it("completes a scan", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const { scanId } = await caller.nucleiScanner.startScan({ targets: ["complete.test"] });
    const result = await caller.nucleiScanner.completeScan({ scanId });
    expect(result.status).toBe("completed");
  });
});

// ─── ATT&CK Coverage Router ──────────────────────────────────────────────────

describe("attackCoverage", () => {
  it("returns the coverage heatmap", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const heatmap = await caller.attackCoverage.getHeatmap();
    expect(heatmap).toHaveProperty("tactics");
    expect(heatmap).toHaveProperty("tools");
    expect(heatmap).toHaveProperty("summary");
    expect(heatmap.tactics.length).toBe(14); // 14 ATT&CK Enterprise tactics
    expect(heatmap.summary.totalTactics).toBe(14);
    expect(heatmap.tools.length).toBe(7); // 7 integrated tools
  });

  it("returns coverage for a specific tool", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const coverage = await caller.attackCoverage.getToolCoverage({ tool: "caldera" });
    expect(coverage.tool).toBe("caldera");
    expect(coverage).toHaveProperty("tacticDetails");
    expect(coverage.techniqueCount).toBeGreaterThan(0);
  });

  it("returns coverage gaps", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const gaps = await caller.attackCoverage.getCoverageGaps();
    expect(Array.isArray(gaps)).toBe(true);
    // Each gap should have a recommendation
    for (const gap of gaps) {
      expect(gap).toHaveProperty("tacticId");
      expect(gap).toHaveProperty("recommendation");
      expect(gap.gap).toBe(true);
    }
  });

  it("returns tactic list", async () => {
    const { ctx } = createProtectedContext();
    const caller = appRouter.createCaller(ctx);
    const tactics = await caller.attackCoverage.getTactics();
    expect(tactics.length).toBe(14);
    expect(tactics[0]).toHaveProperty("id");
    expect(tactics[0]).toHaveProperty("name");
    expect(tactics[0]).toHaveProperty("shortName");
  });
});
