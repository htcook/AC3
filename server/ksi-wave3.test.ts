import { describe, expect, it, beforeAll } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

// ─── Test Context Helper ───────────────────────────────────────────────────────
type AuthenticatedUser = NonNullable<TrpcContext["user"]>;
function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-wave3-user",
    email: "wave3-test@acec3.com",
    name: "Wave3 Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };
  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

const caller = appRouter.createCaller(createAuthContext());

// ─── Attack Vector Engine Tests ────────────────────────────────────────────────
describe("Attack Vector Engine", () => {
  it("should return kill chain phases", async () => {
    const phases = await caller.attackVectorEngine.getKillChainPhases();
    expect(Array.isArray(phases)).toBe(true);
    expect(phases.length).toBeGreaterThan(0);
    // Each phase has id, name, order, preExploit
    const phase = phases[0];
    expect(phase).toHaveProperty("id");
    expect(phase).toHaveProperty("name");
    expect(phase).toHaveProperty("order");
    expect(phase).toHaveProperty("preExploit");
  });

  it("should return dashboard stats", async () => {
    const stats = await caller.attackVectorEngine.getDashboardStats();
    expect(stats).toHaveProperty("vectors");
    expect(stats).toHaveProperty("playbooks");
    expect(stats).toHaveProperty("executions");
    expect(stats).toHaveProperty("calderaAbilityCount");
    expect(stats).toHaveProperty("msfModuleCount");
    expect(stats).toHaveProperty("killChainPhases");
    expect(typeof stats.calderaAbilityCount).toBe("number");
    expect(typeof stats.msfModuleCount).toBe("number");
  });

  it("should list vectors (empty initially)", async () => {
    const vectors = await caller.attackVectorEngine.listVectors({ limit: 10 });
    expect(Array.isArray(vectors)).toBe(true);
  });

  it("should list playbooks", async () => {
    const playbooks = await caller.attackVectorEngine.listPlaybooks({});
    expect(Array.isArray(playbooks)).toBe(true);
  });

  it("should identify vectors from sources", async () => {
    const result = await caller.attackVectorEngine.identifyVectors({});
    expect(result).toHaveProperty("totalIdentified");
    expect(typeof result.totalIdentified).toBe("number");
  });

  it("should get Caldera abilities mapping", async () => {
    const abilities = await caller.attackVectorEngine.getCalderaAbilities({ techniqueIds: ["T1190", "T1110"] });
    expect(Array.isArray(abilities)).toBe(true);
    expect(abilities.length).toBeGreaterThan(0);
    expect(abilities[0]).toHaveProperty("techniqueId");
  });

  it("should get MSF modules mapping", async () => {
    const modules = await caller.attackVectorEngine.getMsfModules({ techniqueIds: ["T1190", "T1110"] });
    expect(Array.isArray(modules)).toBe(true);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules[0]).toHaveProperty("techniqueId");
  });
});

// ─── Scheduled Collection Tests ────────────────────────────────────────────────
describe("Scheduled Auto-Collection", () => {
  it("should initialize schedules", async () => {
    const result = await caller.ksiScheduledCollection.initializeSchedules();
    expect(result).toHaveProperty("created");
    expect(result).toHaveProperty("total");
    expect(result.total).toBe(11); // 11 source types
    expect(typeof result.created).toBe("number");
  });

  it("should list schedules after initialization", async () => {
    const schedules = await caller.ksiScheduledCollection.listSchedules();
    expect(Array.isArray(schedules)).toBe(true);
    expect(schedules.length).toBeGreaterThan(0);
    // Each schedule should have key fields
    const schedule = schedules[0];
    expect(schedule).toHaveProperty("sourceType");
    expect(schedule).toHaveProperty("displayName");
    expect(schedule).toHaveProperty("enabled");
    expect(schedule).toHaveProperty("cadence");
  });

  it("should update a schedule cadence", async () => {
    const schedules = await caller.ksiScheduledCollection.listSchedules();
    if (schedules.length > 0) {
      const result = await caller.ksiScheduledCollection.updateSchedule({
        scheduleId: schedules[0].id,
        cadence: "hourly",
      });
      expect(result.success).toBe(true);

      // Verify the update
      const updated = await caller.ksiScheduledCollection.listSchedules();
      const target = updated.find((s: any) => s.id === schedules[0].id);
      expect(target?.cadence).toBe("hourly");
    }
  });

  it("should toggle a schedule enabled/disabled", async () => {
    const schedules = await caller.ksiScheduledCollection.listSchedules();
    if (schedules.length > 0) {
      const result = await caller.ksiScheduledCollection.updateSchedule({
        scheduleId: schedules[0].id,
        enabled: false,
      });
      expect(result.success).toBe(true);

      // Re-enable
      await caller.ksiScheduledCollection.updateSchedule({
        scheduleId: schedules[0].id,
        enabled: true,
      });
    }
  });

  it("should run a manual collection", async () => {
    const result = await caller.ksiScheduledCollection.runCollection({
      sourceType: "vuln_scanner",
    });
    expect(result).toHaveProperty("jobId");
    expect(result).toHaveProperty("evidenceCollected");
    expect(result).toHaveProperty("status");
    expect(result.status).toBe("completed");
    expect(typeof result.evidenceCollected).toBe("number");
  });

  it("should return job history after a run", async () => {
    const history = await caller.ksiScheduledCollection.getJobHistory({ limit: 10 });
    expect(Array.isArray(history)).toBe(true);
    expect(history.length).toBeGreaterThan(0);
    const job = history[0];
    expect(job).toHaveProperty("sourceType");
    expect(job).toHaveProperty("status");
    expect(job).toHaveProperty("startedAt");
  });

  it("should run due collections", async () => {
    const result = await caller.ksiScheduledCollection.runDueCollections();
    expect(result).toHaveProperty("schedulesRun");
    expect(result).toHaveProperty("totalEvidence");
    expect(result).toHaveProperty("dueCount");
    expect(typeof result.schedulesRun).toBe("number");
  });

  it("should return dashboard stats", async () => {
    const stats = await caller.ksiScheduledCollection.getDashboardStats();
    expect(stats).toHaveProperty("totalSchedules");
    expect(stats).toHaveProperty("enabledCount");
    expect(stats).toHaveProperty("dueCount");
    expect(stats).toHaveProperty("failedCount");
    expect(stats).toHaveProperty("totalEvidence");
    expect(stats).toHaveProperty("totalRuns");
    expect(stats).toHaveProperty("recentJobs");
    expect(stats).toHaveProperty("sourceDefinitions");
    expect(stats.sourceDefinitions.length).toBe(11);
  });
});

// ─── CIS Benchmark Expansion Tests ─────────────────────────────────────────────
describe("CIS Benchmark Expansion (Azure/GCP)", () => {
  it("should have rules for all 4 platforms", async () => {
    const catalog = await caller.configBaseline.getRuleCatalog();
    expect(catalog).toHaveProperty("rules");
    expect(catalog).toHaveProperty("platforms");
    expect(catalog.platforms).toContain("aws");
    expect(catalog.platforms).toContain("azure");
    expect(catalog.platforms).toContain("gcp");
    expect(catalog.platforms).toContain("kubernetes");
  });

  it("should have significantly expanded rule count (80+)", async () => {
    const catalog = await caller.configBaseline.getRuleCatalog();
    expect(catalog.totalRules).toBeGreaterThanOrEqual(80);
  });

  it("should have Azure CIS v2.1 rules", async () => {
    const catalog = await caller.configBaseline.getRuleCatalog();
    const azureRules = catalog.rules.filter((r: any) => r.platform === "azure");
    expect(azureRules.length).toBeGreaterThanOrEqual(20);
    // Check for specific Azure benchmarks
    const benchmarks = [...new Set(azureRules.map((r: any) => r.benchmark))];
    expect(benchmarks.some((b: string) => b.includes("Azure"))).toBe(true);
  });

  it("should have GCP CIS v2.0 rules", async () => {
    const catalog = await caller.configBaseline.getRuleCatalog();
    const gcpRules = catalog.rules.filter((r: any) => r.platform === "gcp");
    expect(gcpRules.length).toBeGreaterThanOrEqual(15);
  });

  it("should have Kubernetes CIS rules", async () => {
    const catalog = await caller.configBaseline.getRuleCatalog();
    const k8sRules = catalog.rules.filter((r: any) => r.platform === "kubernetes");
    expect(k8sRules.length).toBeGreaterThanOrEqual(8);
  });
});
