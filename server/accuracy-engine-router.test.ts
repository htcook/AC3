import { describe, it, expect, vi } from "vitest";

/**
 * Tests for the accuracy-engine tRPC router.
 * These verify that the router module exports correctly and that
 * each sub-router is properly structured with the expected endpoints.
 */

describe("Accuracy Engine Router Structure", () => {
  it("should export accuracyEngineRouter with all 11 sub-routers", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    expect(accuracyEngineRouter).toBeDefined();
    expect(accuracyEngineRouter._def).toBeDefined();

    // Check that the router has procedures defined
    const routerDef = accuracyEngineRouter._def;
    expect(routerDef.record).toBeDefined();

    const subRouterNames = Object.keys(routerDef.record);
    expect(subRouterNames).toContain("corroboration");
    expect(subRouterNames).toContain("cveMatcher");
    expect(subRouterNames).toContain("remediation");
    expect(subRouterNames).toContain("controls");
    expect(subRouterNames).toContain("preFlight");
    expect(subRouterNames).toContain("probes");
    expect(subRouterNames).toContain("temporal");
    expect(subRouterNames).toContain("attackChains");
    expect(subRouterNames).toContain("feedback");
    expect(subRouterNames).toContain("ruleGen");
    expect(subRouterNames).toContain("ruleEvidence");
    expect(subRouterNames.length).toBe(11);
  });
});

// Helper to get endpoint names from a sub-router
// tRPC 11 merged routers expose endpoints as own properties (not under _def.record)
function getEndpoints(subRouter: any): string[] {
  if (!subRouter) return [];
  // tRPC 11 merged router: endpoints are direct own properties
  const ownKeys = Object.getOwnPropertyNames(subRouter).filter(k => !k.startsWith("_"));
  if (ownKeys.length > 0) return ownKeys;
  // Fallback: _def.record for standalone routers
  if (subRouter._def?.record) return Object.keys(subRouter._def.record);
  return [];
}

describe("Sub-Router: corroboration", () => {
  it("should have analyze and sourceReliability endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.corroboration;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("analyze");
    expect(endpoints).toContain("sourceReliability");
  });
});

describe("Sub-Router: cveMatcher", () => {
  it("should have match, batchMatch, and scanMatch endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.cveMatcher;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("match");
    expect(endpoints).toContain("batchMatch");
    expect(endpoints).toContain("scanMatch");
  });
});

describe("Sub-Router: remediation", () => {
  it("should have core CRUD and verification endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.remediation;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("create");
    expect(endpoints).toContain("markRemediated");
    expect(endpoints).toContain("summary");
    expect(endpoints).toContain("overdue");
    expect(endpoints).toContain("needsVerification");
  });
});

describe("Sub-Router: controls", () => {
  it("should have detect and assessScan endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.controls;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("detect");
    expect(endpoints).toContain("assessScan");
  });
});

describe("Sub-Router: preFlight", () => {
  it("should have check, batchCheck, and successRate endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.preFlight;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("check");
    expect(endpoints).toContain("batchCheck");
    expect(endpoints).toContain("successRate");
  });
});

describe("Sub-Router: probes", () => {
  it("should have listTemplates and runScan endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.probes;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("listTemplates");
    expect(endpoints).toContain("runScan");
  });
});

describe("Sub-Router: temporal", () => {
  it("should have score and scanScores endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.temporal;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("score");
    expect(endpoints).toContain("scanScores");
  });
});

describe("Sub-Router: attackChains", () => {
  it("should have analyze endpoint", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.attackChains;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("analyze");
  });
});

describe("Sub-Router: feedback", () => {
  it("should have record, modulePerformance, rankModules, summary, needsAttention, and improvementPrompt endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.feedback;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("record");
    expect(endpoints).toContain("modulePerformance");
    expect(endpoints).toContain("rankModules");
    expect(endpoints).toContain("summary");
    expect(endpoints).toContain("needsAttention");
    expect(endpoints).toContain("improvementPrompt");
  });
});

describe("Sub-Router: ruleGen", () => {
  it("should have generate and validate endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.ruleGen;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("generate");
    expect(endpoints).toContain("validate");
  });
});

describe("Sub-Router: ruleEvidence", () => {
  it("should have validateSingle and batchValidate endpoints", async () => {
    const { accuracyEngineRouter } = await import("./routers/accuracy-engine");
    const sub = accuracyEngineRouter._def.record.ruleEvidence;
    expect(sub).toBeDefined();
    const endpoints = getEndpoints(sub);
    expect(endpoints).toContain("validate");
    expect(endpoints).toContain("batchValidate");
  });
});

describe("Main Router Integration", () => {
  it("should have accuracyEngine registered in the main appRouter", async () => {
    const { appRouter } = await import("./routers");
    expect(appRouter).toBeDefined();
    const topLevelKeys = Object.keys(appRouter._def.record);
    expect(topLevelKeys).toContain("accuracyEngine");
  });
});
