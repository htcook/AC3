import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";

function makeMockCtx(user: any = null) {
  return {
    user,
    setCookie: () => {},
    getCookie: () => undefined,
    deleteCookie: () => {},
    req: { headers: {} } as any,
    res: { setHeader: () => {}, getHeader: () => undefined } as any,
  };
}

const authedCtx = makeMockCtx({
  id: 1,
  openId: "test-user",
  name: "Test User",
  role: "admin",
});

describe("scoring router", () => {
  it("returns preset templates", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const presets = await caller.scoring.getPresets();
    expect(presets).toBeDefined();
    expect(Array.isArray(presets)).toBe(true);
    expect(presets.length).toBeGreaterThan(0);
    // Each preset should have key, name, description, profile
    const first = presets[0];
    expect(first).toHaveProperty("key");
    expect(first).toHaveProperty("name");
    expect(first).toHaveProperty("profile");
    expect(first.profile).toHaveProperty("carverWeights");
    expect(first.profile).toHaveProperty("shockWeights");
    expect(first.profile).toHaveProperty("carverWeight");
    expect(first.profile).toHaveProperty("shockWeight");
    expect(first.profile).toHaveProperty("cvssWeight");
  });

  it("creates a scoring profile", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const result = await caller.scoring.createProfile({
      name: "Test Healthcare Profile",
      description: "Test profile for healthcare assessment",
      wCriticality: 3.0,
      wAccessibility: 1.0,
      wRecuperability: 2.5,
      wVulnerability: 1.5,
      wEffect: 2.0,
      wRecognizability: 0.5,
      wScope: 2.0,
      wHandling: 1.5,
      wOperationalImpact: 3.0,
      wCascadingEffects: 2.0,
      wKnowledge: 1.0,
      carverWeight: 0.35,
      shockWeight: 0.35,
      cvssWeight: 0.30,
      criticalThreshold: 80,
      highThreshold: 60,
      mediumThreshold: 35,
    });
    expect(result).toHaveProperty("id");
    expect(typeof result.id).toBe("number");
  });

  it("lists scoring profiles", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const profiles = await caller.scoring.listProfiles();
    expect(Array.isArray(profiles)).toBe(true);
    // Should include the profile we just created
    expect(profiles.length).toBeGreaterThan(0);
    const found = profiles.find((p: any) => p.name === "Test Healthcare Profile");
    expect(found).toBeDefined();
  });

  it("simulates a score", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const result = await caller.scoring.simulateScore({
      carver: {
        criticality: 8,
        accessibility: 6,
        recuperability: 4,
        vulnerability: 7,
        effect: 9,
        recognizability: 3,
      },
      shock: {
        scope: 7,
        handling: 5,
        operationalImpact: 8,
        cascadingEffects: 6,
        knowledge: 4,
      },
      cvssEstimate: 7.5,
      exposure: 0.7,
      confidence: 0.8,
      confirmedVulnScore: 65,
    });
    expect(result).toHaveProperty("hybridRiskScore");
    expect(result).toHaveProperty("riskBand");
    expect(result).toHaveProperty("carverComposite");
    expect(result).toHaveProperty("shockComposite");
    expect(result).toHaveProperty("impactScore");
    expect(result).toHaveProperty("likelihoodScore");
    expect(result).toHaveProperty("factorContributions");
    expect(typeof result.hybridRiskScore).toBe("number");
    expect(result.hybridRiskScore).toBeGreaterThan(0);
    expect(result.hybridRiskScore).toBeLessThanOrEqual(100);
    expect(["critical", "high", "medium", "low"]).toContain(result.riskBand);
    expect(Array.isArray(result.factorContributions)).toBe(true);
    expect(result.factorContributions.length).toBe(11); // 6 CARVER + 5 Shock
  });

  it("simulates with a custom profile", async () => {
    const caller = appRouter.createCaller(authedCtx);
    // First get profiles
    const profiles = await caller.scoring.listProfiles();
    const profile = profiles.find((p: any) => p.name === "Test Healthcare Profile");
    expect(profile).toBeDefined();

    const result = await caller.scoring.simulateScore({
      carver: {
        criticality: 9,
        accessibility: 3,
        recuperability: 2,
        vulnerability: 8,
        effect: 9,
        recognizability: 2,
      },
      shock: {
        scope: 8,
        handling: 3,
        operationalImpact: 9,
        cascadingEffects: 7,
        knowledge: 3,
      },
      cvssEstimate: 9.0,
      exposure: 0.9,
      confidence: 0.95,
      confirmedVulnScore: 85,
      profileId: profile!.id,
    });
    expect(result.hybridRiskScore).toBeGreaterThan(50);
    expect(["critical", "high"]).toContain(result.riskBand);
  });

  it("lists scored scans", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const scans = await caller.scoring.listScoredScans();
    expect(Array.isArray(scans)).toBe(true);
    // May be empty if no scans exist, but should not error
  });

  it("returns audit log (may be empty)", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const log = await caller.scoring.getAuditLog({ limit: 10 });
    expect(Array.isArray(log)).toBe(true);
  });

  it("deletes a scoring profile", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const profiles = await caller.scoring.listProfiles();
    const profile = profiles.find((p: any) => p.name === "Test Healthcare Profile");
    expect(profile).toBeDefined();
    const result = await caller.scoring.deleteProfile({ id: profile!.id });
    expect(result).toHaveProperty("success", true);
    // Verify deletion
    const after = await caller.scoring.listProfiles();
    const gone = after.find((p: any) => p.name === "Test Healthcare Profile");
    expect(gone).toBeUndefined();
  });

  it("validates scoring math: high impact + high likelihood = critical", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const result = await caller.scoring.simulateScore({
      carver: {
        criticality: 10,
        accessibility: 10,
        recuperability: 10,
        vulnerability: 10,
        effect: 10,
        recognizability: 10,
      },
      shock: {
        scope: 10,
        handling: 10,
        operationalImpact: 10,
        cascadingEffects: 10,
        knowledge: 10,
      },
      cvssEstimate: 10,
      exposure: 1.0,
      confidence: 1.0,
      confirmedVulnScore: 100,
    });
    expect(result.riskBand).toBe("critical");
    expect(result.hybridRiskScore).toBeGreaterThanOrEqual(85);
  });

  it("validates scoring math: low impact + low likelihood = low", async () => {
    const caller = appRouter.createCaller(authedCtx);
    const result = await caller.scoring.simulateScore({
      carver: {
        criticality: 1,
        accessibility: 1,
        recuperability: 1,
        vulnerability: 1,
        effect: 1,
        recognizability: 1,
      },
      shock: {
        scope: 1,
        handling: 1,
        operationalImpact: 1,
        cascadingEffects: 1,
        knowledge: 1,
      },
      cvssEstimate: 1,
      exposure: 0.1,
      confidence: 0.3,
      confirmedVulnScore: 0,
    });
    expect(result.riskBand).toBe("low");
    expect(result.hybridRiskScore).toBeLessThan(40);
  });
});
