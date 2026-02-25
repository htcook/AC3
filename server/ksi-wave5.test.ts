/**
 * Wave 5 Tests: Threat Intelligence Enrichment Engine, Live Scanner Integration, Engagement Automation
 */
import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-wave5-user",
    email: "wave5-test@acec3.com",
    name: "Wave5 Test User",
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

const authCaller = appRouter.createCaller(createAuthContext());
const anonCaller = appRouter.createCaller(createAnonContext());

// ─── Threat Enrichment Engine ──────────────────────────────────────────────────

describe("Threat Enrichment Engine", () => {
  it("getDashboardStats returns threat intelligence statistics", async () => {
    const stats = await authCaller.threatEnrichment.getDashboardStats();
    expect(stats).toHaveProperty("totalActors");
    expect(stats).toHaveProperty("totalIocs");
    expect(stats).toHaveProperty("totalTtps");
    expect(stats).toHaveProperty("totalKsis");
    expect(stats).toHaveProperty("totalEvidence");
    expect(stats).toHaveProperty("totalVectors");
    expect(typeof stats.totalActors).toBe("number");
    expect(typeof stats.totalKsis).toBe("number");
  });

  it("getCoverageMatrix returns KSI theme coverage with threat data", async () => {
    const matrix = await authCaller.threatEnrichment.getCoverageMatrix();
    expect(matrix).toHaveProperty("matrix");
    expect(matrix).toHaveProperty("overallCoverage");
    expect(matrix).toHaveProperty("totalActors");
    expect(Array.isArray(matrix.matrix)).toBe(true);
    if (matrix.matrix.length > 0) {
      expect(matrix.matrix[0]).toHaveProperty("theme");
      expect(matrix.matrix[0]).toHaveProperty("themeFullName");
      expect(matrix.matrix[0]).toHaveProperty("coverageLevel");
      expect(matrix.matrix[0]).toHaveProperty("actorCoverage");
      expect(matrix.matrix[0]).toHaveProperty("techniqueCount");
    }
  });

  it("enrichKsi returns threat intelligence for a specific KSI", async () => {
    const result = await authCaller.threatEnrichment.enrichKsi({ ksiId: "KSI-SVC-VSR" });
    expect(result).toHaveProperty("ksiId", "KSI-SVC-VSR");
    expect(result).toHaveProperty("riskScore");
    expect(result).toHaveProperty("threatActors");
    expect(typeof result.riskScore).toBe("number");
    expect(result.riskScore).toBeGreaterThanOrEqual(0);
    expect(result.riskScore).toBeLessThanOrEqual(100);
    expect(Array.isArray(result.threatActors)).toBe(true);
  });

  it("enrichAllKsis returns bulk enrichment results for all KSIs", async () => {
    const result = await authCaller.threatEnrichment.enrichAllKsis();
    expect(result).toHaveProperty("totalKsis");
    expect(result).toHaveProperty("highRiskKsis");
    expect(result).toHaveProperty("mediumRiskKsis");
    expect(result).toHaveProperty("lowRiskKsis");
    expect(result).toHaveProperty("results");
    expect(Array.isArray(result.results)).toBe(true);
    expect(result.totalKsis).toBeGreaterThan(0);
    if (result.results.length > 0) {
      expect(result.results[0]).toHaveProperty("ksiId");
      expect(result.results[0]).toHaveProperty("riskScore");
      expect(result.results[0]).toHaveProperty("actorCount");
    }
  });

  it("getActorKsiImpact returns KSI impact analysis for a threat actor", async () => {
    // Use a non-existent actor to test the null path
    const result = await authCaller.threatEnrichment.getActorKsiImpact({ actorId: "nonexistent-actor" });
    expect(result).toHaveProperty("actor");
    expect(result).toHaveProperty("impactedKsis");
    expect(result).toHaveProperty("totalImpact");
    expect(result.actor).toBeNull();
    expect(result.totalImpact).toBe(0);
  });

  it("getTechniqueKsiCoverage returns KSI coverage for a MITRE technique", async () => {
    const result = await authCaller.threatEnrichment.getTechniqueKsiCoverage({ techniqueId: "T1190" });
    expect(result).toHaveProperty("techniqueId", "T1190");
    expect(result).toHaveProperty("coveredByKsis");
    expect(result).toHaveProperty("usedByActors");
    expect(Array.isArray(result.coveredByKsis)).toBe(true);
    expect(Array.isArray(result.usedByActors)).toBe(true);
  });

  it("getIocFeedForModule returns IOCs relevant to a specific module", async () => {
    const result = await authCaller.threatEnrichment.getIocFeedForModule({ module: "ksi", limit: 10 });
    expect(result).toHaveProperty("iocs");
    expect(result).toHaveProperty("totalIocs");
    expect(Array.isArray(result.iocs)).toBe(true);
  });

  it("feedValidationPriorities updates validation schedules based on threat data", async () => {
    const result = await authCaller.threatEnrichment.feedValidationPriorities();
    expect(result).toHaveProperty("totalSchedules");
    expect(result).toHaveProperty("criticalCount");
    expect(result).toHaveProperty("highCount");
    expect(result).toHaveProperty("elevatedCount");
    expect(result).toHaveProperty("normalCount");
    expect(result).toHaveProperty("priorityUpdates");
    expect(Array.isArray(result.priorityUpdates)).toBe(true);
    expect(typeof result.totalSchedules).toBe("number");
  });

  it("feedAttackVectorEnrichment enriches attack vectors with threat intelligence", async () => {
    const result = await authCaller.threatEnrichment.feedAttackVectorEnrichment();
    expect(result).toHaveProperty("totalVectors");
    expect(result).toHaveProperty("enrichedVectors");
    expect(result).toHaveProperty("enrichedAt");
    expect(typeof result.totalVectors).toBe("number");
  });

  it("feedConfigBaselinePriorities updates config baseline priorities", async () => {
    const result = await authCaller.threatEnrichment.feedConfigBaselinePriorities();
    expect(result).toHaveProperty("priorities");
    expect(result).toHaveProperty("enrichedAt");
    expect(Array.isArray(result.priorities)).toBe(true);
  });

  it("runFullEnrichmentCycle executes the complete enrichment pipeline", async () => {
    const result = await authCaller.threatEnrichment.runFullEnrichmentCycle();
    expect(result).toHaveProperty("duration");
    expect(result).toHaveProperty("threatDataSummary");
    expect(result).toHaveProperty("ksiEnrichment");
    expect(result).toHaveProperty("validationPriorities");
    expect(result).toHaveProperty("attackVectorEnrichment");
    expect(result).toHaveProperty("configBaselinePriorities");
    expect(result.threatDataSummary).toHaveProperty("actors");
    expect(result.threatDataSummary).toHaveProperty("ttps");
    expect(typeof result.duration).toBe("number");
  });

  it("rejects unauthenticated access to getDashboardStats", async () => {
    await expect(anonCaller.threatEnrichment.getDashboardStats()).rejects.toThrow();
  });

  it("rejects unauthenticated access to enrichAllKsis", async () => {
    await expect(anonCaller.threatEnrichment.enrichAllKsis()).rejects.toThrow();
  });

  it("rejects unauthenticated access to runFullEnrichmentCycle", async () => {
    await expect(anonCaller.threatEnrichment.runFullEnrichmentCycle()).rejects.toThrow();
  });
});

// ─── Live Scanner Integration ──────────────────────────────────────────────────

describe("Live Scanner Integration (via Auto-Collector)", () => {
  it("getCollectionStats returns source mapping statistics", async () => {
    const stats = await authCaller.ksiAutoCollector.getCollectionStats();
    expect(stats).toHaveProperty("totalEvidence");
    expect(stats).toHaveProperty("autoCollected");
    expect(stats).toHaveProperty("bySource");
    expect(stats).toHaveProperty("sourceMappingCount");
    expect(typeof stats.totalEvidence).toBe("number");
  });

  it("getSourceMappings returns scanner-to-KSI mappings", async () => {
    const mappings = await authCaller.ksiAutoCollector.getSourceMappings();
    expect(Array.isArray(mappings)).toBe(true);
    if (mappings.length > 0) {
      expect(mappings[0]).toHaveProperty("sourceModule");
      expect(mappings[0]).toHaveProperty("ksiIds");
    }
  });

  it("crossRefEvidence returns threat catalog cross-references", async () => {
    const result = await authCaller.ksiAutoCollector.crossRefEvidence({
      techniqueIds: ["T1190", "T1566"],
    });
    expect(result).toHaveProperty("threatActors");
    expect(result).toHaveProperty("ttpKnowledge");
    expect(result).toHaveProperty("totalTechniques");
    expect(Array.isArray(result.threatActors)).toBe(true);
  });
});

// ─── Engagement Automation ─────────────────────────────────────────────────────

describe("Engagement Automation", () => {
  it("getDashboardStats returns engagement automation statistics", async () => {
    const stats = await authCaller.engagementAutomation.getDashboardStats();
    expect(stats).toHaveProperty("totalVectors");
    expect(stats).toHaveProperty("totalPlaybooks");
    expect(stats).toHaveProperty("totalEngagements");
    expect(typeof stats.totalVectors).toBe("number");
    expect(typeof stats.totalPlaybooks).toBe("number");
  });

  it("getTemplates returns engagement templates", async () => {
    const result = await authCaller.engagementAutomation.getTemplates();
    expect(Array.isArray(result)).toBe(true);
    if (result.length > 0) {
      expect(result[0]).toHaveProperty("templateId");
      expect(result[0]).toHaveProperty("name");
      expect(result[0]).toHaveProperty("killChainPhases");
    }
  });

  it("listAutomatedEngagements returns automated engagements", async () => {
    const result = await authCaller.engagementAutomation.listAutomatedEngagements({ limit: 20 });
    expect(Array.isArray(result)).toBe(true);
  });

  it("rejects unauthenticated access to getDashboardStats", async () => {
    await expect(anonCaller.engagementAutomation.getDashboardStats()).rejects.toThrow();
  });
});
