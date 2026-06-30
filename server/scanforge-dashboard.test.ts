import { describe, it, expect, vi } from "vitest";

/**
 * Tests for:
 * 1. ScanForge Dashboard tRPC procedures (health metrics, template effectiveness, etc.)
 * 2. TI connector column name fixes (actorType, tge* prefixes, ioc* prefixes)
 * 3. Error dashboard resolution
 */

// ── ScanForge Engine Imports ──────────────────────────────────────────────
const importAccuracyTracker = () => import("./scanforge/engine/accuracy-tracker");
const importConfidenceTuner = () => import("./scanforge/engine/confidence-tuner");
const importDeepResearch = () => import("./scanforge/engine/deep-research-agent");


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("ScanForge Dashboard — Engine Functions", () => {
  describe("Accuracy Tracker exports", () => {
    it("should export getTemplateEffectiveness function", async () => {
      const mod = await importAccuracyTracker();
      expect(typeof mod.getTemplateEffectiveness).toBe("function");
    });

    it("should export getEngagementReports function", async () => {
      const mod = await importAccuracyTracker();
      expect(typeof mod.getEngagementReports).toBe("function");
    });

    it("should export getEngagementFindings function", async () => {
      const mod = await importAccuracyTracker();
      expect(typeof mod.getEngagementFindings).toBe("function");
    });

    it("should export logFinding function", async () => {
      const mod = await importAccuracyTracker();
      expect(typeof mod.logFinding).toBe("function");
    });

    it("should export updateTemplateMetrics function", async () => {
      const mod = await importAccuracyTracker();
      expect(typeof mod.updateTemplateMetrics).toBe("function");
    });

    it("should export generateEngagementReport function", async () => {
      const mod = await importAccuracyTracker();
      expect(typeof mod.generateEngagementReport).toBe("function");
    });
  });

  describe("Confidence Tuner exports", () => {
    it("should export getScanForgeHealthMetrics function", async () => {
      const mod = await importConfidenceTuner();
      expect(typeof mod.getScanForgeHealthMetrics).toBe("function");
    });

    it("should export getTuningHistory function", async () => {
      const mod = await importConfidenceTuner();
      expect(typeof mod.getTuningHistory).toBe("function");
    });

    it("should export runConfidenceTuning function", async () => {
      const mod = await importConfidenceTuner();
      expect(typeof mod.runConfidenceTuning).toBe("function");
    });

    it("should export getTemplateConfidence function", async () => {
      const mod = await importConfidenceTuner();
      expect(typeof mod.getTemplateConfidence).toBe("function");
    });
  });

  describe("Deep Research Agent exports", () => {
    it("should export getDraftTemplates function", async () => {
      const mod = await importDeepResearch();
      expect(typeof mod.getDraftTemplates).toBe("function");
    });

    it("should export getResearchLog function", async () => {
      const mod = await importDeepResearch();
      expect(typeof mod.getResearchLog).toBe("function");
    });

    it("should export promoteTemplate function", async () => {
      const mod = await importDeepResearch();
      expect(typeof mod.promoteTemplate).toBe("function");
    });

    it("should export runResearchCycle function", async () => {
      const mod = await importDeepResearch();
      expect(typeof mod.runResearchCycle).toBe("function");
    });
  });
});

// ── TI Connector Column Name Fixes ─────────────────────────────────────────
describe("TI Connector Column Name Fixes", () => {
  describe("threatActors schema uses actorType not type", () => {
    it("should have actorType column in schema", async () => {
      const { threatActors } = await import("../drizzle/schema");
      expect(threatActors.actorType).toBeDefined();
      // Ensure the old 'type' property doesn't exist as a column
      expect((threatActors as any).type).toBeUndefined();
    });
  });

  describe("threatGroupEvents schema uses tge-prefixed columns", () => {
    it("should have tgeActorId column in schema", async () => {
      const { threatGroupEvents } = await import("../drizzle/schema");
      expect(threatGroupEvents.tgeActorId).toBeDefined();
    });

    it("should have tgeTitle column in schema", async () => {
      const { threatGroupEvents } = await import("../drizzle/schema");
      expect(threatGroupEvents.tgeTitle).toBeDefined();
    });

    it("should have tgeDescription column in schema", async () => {
      const { threatGroupEvents } = await import("../drizzle/schema");
      expect(threatGroupEvents.tgeDescription).toBeDefined();
    });

    it("should have tgeSeverity column in schema", async () => {
      const { threatGroupEvents } = await import("../drizzle/schema");
      expect(threatGroupEvents.tgeSeverity).toBeDefined();
    });

    it("should have tgeSource column in schema", async () => {
      const { threatGroupEvents } = await import("../drizzle/schema");
      expect(threatGroupEvents.tgeSource).toBeDefined();
    });

    it("should have tgeSourceUrl column in schema", async () => {
      const { threatGroupEvents } = await import("../drizzle/schema");
      expect(threatGroupEvents.tgeSourceUrl).toBeDefined();
    });

    it("should have tgeConfidence column in schema", async () => {
      const { threatGroupEvents } = await import("../drizzle/schema");
      expect(threatGroupEvents.tgeConfidence).toBeDefined();
    });
  });

  describe("threatActorIocs schema uses ioc-prefixed columns", () => {
    it("should have iocType column in schema", async () => {
      const { threatActorIocs } = await import("../drizzle/schema");
      expect(threatActorIocs.iocType).toBeDefined();
    });

    it("should have iocConfidence column in schema", async () => {
      const { threatActorIocs } = await import("../drizzle/schema");
      expect(threatActorIocs.iocConfidence).toBeDefined();
    });

    it("should have iocFirstSeen column in schema", async () => {
      const { threatActorIocs } = await import("../drizzle/schema");
      expect(threatActorIocs.iocFirstSeen).toBeDefined();
    });
  });

  describe("TI connector files use correct column names", () => {
    it("threat-intel-connectors.ts should not reference threatActors.type", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("server/lib/threat-intel-connectors.ts", "utf-8");
      // Should use actorType, not bare 'type:' in insert contexts
      const insertBlocks = content.match(/\.insert\(threatActors\)[\s\S]*?\.values\(\{[\s\S]*?\}\)/g) || [];
      for (const block of insertBlocks) {
        expect(block).toContain("actorType");
        // 'type:' alone should not appear in threatActors insert blocks
        const typeMatches = block.match(/\btype\s*:/g) || [];
        const actorTypeMatches = block.match(/\bactorType\s*:/g) || [];
        expect(actorTypeMatches.length).toBeGreaterThanOrEqual(typeMatches.length);
      }
    });

    it("dailydarkweb-feed.ts should use actorType not type for threatActors", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("server/lib/dailydarkweb-feed.ts", "utf-8");
      // Check that FULCRUMSEC_ACTOR and DAILYDARKWEB_ACTORS use actorType
      expect(content).toContain("actorType:");
    });

    it("ransomware-intel.ts should use actorType not type for threatActors", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("server/lib/ransomware-intel.ts", "utf-8");
      expect(content).toContain("actorType:");
    });
  });
});

// ── ScanForge Schema Tables ─────────────────────────────────────────────────
describe("ScanForge Schema Tables", () => {
  it("should export scanforgeFindingLog table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.scanforgeFindingLog).toBeDefined();
    expect(schema.scanforgeFindingLog.engagementId).toBeDefined();
    expect(schema.scanforgeFindingLog.templateId).toBeDefined();
    expect(schema.scanforgeFindingLog.verdict).toBeDefined();
    expect(schema.scanforgeFindingLog.confidence).toBeDefined();
  });

  it("should export scanforgeTemplateMetrics table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.scanforgeTemplateMetrics).toBeDefined();
    expect(schema.scanforgeTemplateMetrics.templateId).toBeDefined();
    expect(schema.scanforgeTemplateMetrics.precision).toBeDefined();
    expect(schema.scanforgeTemplateMetrics.recall).toBeDefined();
    expect(schema.scanforgeTemplateMetrics.f1Score).toBeDefined();
    expect(schema.scanforgeTemplateMetrics.effectivenessScore).toBeDefined();
  });

  it("should export scanforgeEngagementReport table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.scanforgeEngagementReport).toBeDefined();
    expect(schema.scanforgeEngagementReport.scanforgeFindings).toBeDefined();
    expect(schema.scanforgeEngagementReport.nucleiFindings).toBeDefined();
    expect(schema.scanforgeEngagementReport.scanforgePrecision).toBeDefined();
    expect(schema.scanforgeEngagementReport.scanforgeF1).toBeDefined();
  });

  it("should export scanforgeGeneratedTemplates table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.scanforgeGeneratedTemplates).toBeDefined();
    expect(schema.scanforgeGeneratedTemplates.templateId).toBeDefined();
    expect(schema.scanforgeGeneratedTemplates.status).toBeDefined();
    expect(schema.scanforgeGeneratedTemplates.generationSource).toBeDefined();
    expect(schema.scanforgeGeneratedTemplates.generationConfidence).toBeDefined();
  });

  it("should export scanforgeResearchLog table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.scanforgeResearchLog).toBeDefined();
    expect(schema.scanforgeResearchLog.feedSource).toBeDefined();
    expect(schema.scanforgeResearchLog.researchSubject).toBeDefined();
    expect(schema.scanforgeResearchLog.researchType).toBeDefined();
    expect(schema.scanforgeResearchLog.actionable).toBeDefined();
  });
});
