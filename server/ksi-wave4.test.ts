/**
 * Wave 4 Tests: Live Scanner Integration, Engagement Automation, Threat Catalog Cross-Ref
 */
import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;
function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-wave4-user",
    email: "wave4-test@acec3.com",
    name: "Wave4 Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };
  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: () => {} } as TrpcContext["res"],
  };
}
function createAnonContext(): TrpcContext {
  return {
    user: null,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: () => {} } as TrpcContext["res"],
  };
}
const caller = appRouter.createCaller(createAuthContext());
const anonCaller = appRouter.createCaller(createAnonContext());

// ─── Live Scanner Integration (via Auto-Collector) ──────────────────────────
describe("Live Scanner Integration", () => {
  it("should list available scanner source mappings", async () => {
    const result = await caller.ksiAutoCollector.getSourceMappings();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    const source = result[0];
    expect(source).toHaveProperty("sourceModule");
    expect(source).toHaveProperty("ksiIds");
    expect(source).toHaveProperty("evidenceType");
  });

  it("should get auto-collector collection stats", async () => {
    const result = await caller.ksiAutoCollector.getCollectionStats();
    expect(result).toBeDefined();
    expect(result).toHaveProperty("totalEvidence");
    expect(result).toHaveProperty("autoCollected");
    expect(result).toHaveProperty("sourceMappingCount");
    expect(typeof result.totalEvidence).toBe("number");
  });

  it("should cross-reference evidence with threat catalog", async () => {
    const result = await caller.ksiAutoCollector.crossRefEvidence({ techniqueIds: ["T1059", "T1190"] });
    expect(result).toBeDefined();
    expect(result).toHaveProperty("threatActors");
    expect(result).toHaveProperty("ttpKnowledge");
    expect(Array.isArray(result.threatActors)).toBe(true);
    expect(Array.isArray(result.ttpKnowledge)).toBe(true);
  });

  it("should require auth for cross-ref evidence", async () => {
    await expect(anonCaller.ksiAutoCollector.crossRefEvidence({ techniqueIds: ["T1059"] }))
      .rejects.toThrow();
  });
});

// ─── Scheduled Collection ───────────────────────────────────────────────────
describe("Scheduled Collection", () => {
  it("should list schedules", async () => {
    const result = await caller.ksiScheduledCollection.listSchedules();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
  });

  it("should get job history", async () => {
    const result = await caller.ksiScheduledCollection.getJobHistory({ limit: 10 });
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
  });

  it("should run a collection job", async () => {
    const result = await caller.ksiScheduledCollection.runCollection({ sourceType: "vuln_scanner" });
    expect(result).toBeDefined();
    expect(result).toHaveProperty("jobId");
    expect(result).toHaveProperty("status");
    expect(result).toHaveProperty("evidenceCollected");
    expect(typeof result.evidenceCollected).toBe("number");
  });

  it("should initialize default schedules", async () => {
    const result = await caller.ksiScheduledCollection.initializeSchedules();
    expect(result).toBeDefined();
    expect(result).toHaveProperty("created");
    expect(result).toHaveProperty("total");
    expect(typeof result.created).toBe("number");
    expect(typeof result.total).toBe("number");
  });
});

// ─── Engagement Automation ──────────────────────────────────────────────────
describe("Engagement Automation", () => {
  it("should get available templates", async () => {
    const result = await caller.engagementAutomation.getTemplates();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    const template = result[0];
    expect(template).toHaveProperty("templateId");
    expect(template).toHaveProperty("name");
    expect(template).toHaveProperty("description");
    expect(template).toHaveProperty("type");
    expect(template).toHaveProperty("killChainPhases");
    expect(Array.isArray(template.killChainPhases)).toBe(true);
    expect(template).toHaveProperty("recommendedTechniques");
  });

  it("should have all 6 engagement templates", async () => {
    const result = await caller.engagementAutomation.getTemplates();
    const templateIds = result.map((t: any) => t.templateId);
    expect(templateIds).toContain("full_pentest");
    expect(templateIds).toContain("red_team");
    expect(templateIds).toContain("phishing_assessment");
    expect(templateIds).toContain("web_app_test");
    expect(templateIds).toContain("cloud_assessment");
    expect(templateIds).toContain("apt_emulation");
  });

  it("should get dashboard stats", async () => {
    const result = await caller.engagementAutomation.getDashboardStats();
    expect(result).toBeDefined();
    expect(result).toHaveProperty("totalEngagements");
    expect(result).toHaveProperty("totalPipelines");
    expect(result).toHaveProperty("totalPlaybooks");
    expect(result).toHaveProperty("totalVectors");
    expect(result).toHaveProperty("pipelinesByStatus");
    expect(result).toHaveProperty("vectorsByStatus");
    expect(result).toHaveProperty("recentEngagements");
    expect(result).toHaveProperty("templates");
    expect(typeof result.totalEngagements).toBe("number");
  });

  it("should list automated engagements", async () => {
    const result = await caller.engagementAutomation.listAutomatedEngagements({ limit: 10 });
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
  });

  it("should require auth for creating engagement from vectors", async () => {
    await expect(anonCaller.engagementAutomation.createFromVectors({
      templateId: "full_pentest",
      name: "Test Engagement",
      customerName: "Test Corp",
      vectorIds: ["fake-id"],
    })).rejects.toThrow();
  });

  it("should require auth for creating engagement from playbook", async () => {
    await expect(anonCaller.engagementAutomation.createFromPlaybook({
      playbookId: "fake-id",
      customerName: "Test Corp",
    })).rejects.toThrow();
  });
});

// ─── Live Scanner API Layer ─────────────────────────────────────────────────
describe("Live Scanner API Layer", () => {
  it("should export scanner health check functions", async () => {
    const mod = await import("./lib/live-scanner-api");
    expect(mod).toHaveProperty("checkCalderaHealth");
    expect(mod).toHaveProperty("checkGophishHealth");
    expect(mod).toHaveProperty("checkZapHealth");
    expect(mod).toHaveProperty("checkShodanHealth");
    expect(mod).toHaveProperty("checkAbusechHealth");
    expect(mod).toHaveProperty("checkAllScannerHealth");
    expect(typeof mod.checkCalderaHealth).toBe("function");
    expect(typeof mod.checkAllScannerHealth).toBe("function");
  });

  it("should export evidence collection functions", async () => {
    const mod = await import("./lib/live-scanner-api");
    expect(mod).toHaveProperty("collectCalderaEvidence");
    expect(mod).toHaveProperty("collectGophishEvidence");
    expect(mod).toHaveProperty("collectZapEvidence");
    expect(mod).toHaveProperty("collectAllLiveEvidence");
    expect(typeof mod.collectCalderaEvidence).toBe("function");
  });

  it("should export threat catalog cross-reference functions", async () => {
    const mod = await import("./lib/live-scanner-api");
    expect(mod).toHaveProperty("crossRefThreatCatalog");
    expect(mod).toHaveProperty("crossRefTtpKnowledge");
    expect(typeof mod.crossRefThreatCatalog).toBe("function");
    expect(typeof mod.crossRefTtpKnowledge).toBe("function");
  });

  it("should cross-reference techniques with threat catalog via db", async () => {
    const mod = await import("./lib/live-scanner-api");
    const { getDb } = await import("./db");
    const dbConn = await getDb();
    const result = await mod.crossRefThreatCatalog(["T1059", "T1190"], dbConn);
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    // Each result should have actorId, actorName, matchedTechniques, threatLevel
    if (result.length > 0) {
      expect(result[0]).toHaveProperty("actorId");
      expect(result[0]).toHaveProperty("actorName");
      expect(result[0]).toHaveProperty("matchedTechniques");
      expect(result[0]).toHaveProperty("threatLevel");
    }
  });
});

// ─── Config Baseline - Azure/GCP Rules ──────────────────────────────────────
describe("Config Baseline - Expanded CIS Rules", () => {
  it("should have rules for all 4 platforms", async () => {
    const result = await caller.configBaseline.getRuleCatalog();
    expect(result).toBeDefined();
    expect(result).toHaveProperty("rules");
    expect(result).toHaveProperty("platforms");
    expect(result.platforms).toContain("aws");
    expect(result.platforms).toContain("azure");
    expect(result.platforms).toContain("gcp");
    expect(result.platforms).toContain("kubernetes");
  });

  it("should have significantly more rules than original 31", async () => {
    const result = await caller.configBaseline.getRuleCatalog();
    expect(result.totalRules).toBeGreaterThan(60);
  });

  it("should filter rules by platform - azure", async () => {
    const result = await caller.configBaseline.getRuleCatalog({ platform: "azure" });
    expect(result.rules.length).toBeGreaterThan(10);
    expect(result.rules.every((r: any) => r.platform === "azure")).toBe(true);
  });

  it("should filter rules by platform - gcp", async () => {
    const result = await caller.configBaseline.getRuleCatalog({ platform: "gcp" });
    expect(result.rules.length).toBeGreaterThan(10);
    expect(result.rules.every((r: any) => r.platform === "gcp")).toBe(true);
  });
});
