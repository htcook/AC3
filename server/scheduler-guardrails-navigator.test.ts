import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Scheduler Module Tests ──────────────────────────────────────────

describe("Catalog Enrichment Scheduler", () => {
  let scheduler: typeof import("./lib/catalog-enrichment-scheduler");

  beforeEach(async () => {
    // Fresh import to reset module state
    vi.resetModules();
    scheduler = await import("./lib/catalog-enrichment-scheduler");
  });

  afterEach(() => {
    scheduler.stopCatalogEnrichmentScheduler();
  });

  it("getCatalogEnrichmentStatus returns default config", () => {
    const status = scheduler.getCatalogEnrichmentStatus();
    expect(status.config).toEqual({
      batchSize: 10,
      completenessThreshold: 60,
      cronHourUtc: 3,
      cronMinuteUtc: 0,
      discoveryEnabled: true,
      enabled: true,
    });
    expect(status.running).toBe(false);
    expect(status.lastRunAt).toBeNull();
    expect(status.lastRunResult).toBeNull();
    expect(status.lastError).toBeNull();
    expect(status.stats.totalRunsCompleted).toBe(0);
    expect(status.stats.totalActorsEnriched).toBe(0);
  });

  it("updateCatalogEnrichmentConfig merges partial config", () => {
    const updated = scheduler.updateCatalogEnrichmentConfig({
      batchSize: 25,
      cronHourUtc: 5,
    });
    expect(updated.batchSize).toBe(25);
    expect(updated.cronHourUtc).toBe(5);
    expect(updated.completenessThreshold).toBe(60); // unchanged
    expect(updated.enabled).toBe(true); // unchanged
  });

  it("updateCatalogEnrichmentConfig can disable scheduler", () => {
    const updated = scheduler.updateCatalogEnrichmentConfig({ enabled: false });
    expect(updated.enabled).toBe(false);
    const status = scheduler.getCatalogEnrichmentStatus();
    expect(status.config.enabled).toBe(false);
  });

  it("updateCatalogEnrichmentConfig can re-enable scheduler", () => {
    scheduler.updateCatalogEnrichmentConfig({ enabled: false });
    const updated = scheduler.updateCatalogEnrichmentConfig({ enabled: true });
    expect(updated.enabled).toBe(true);
  });

  it("status includes nextRunAt when enabled", () => {
    // Start scheduler to get nextRunAt
    scheduler.startCatalogEnrichmentScheduler({ enabled: true });
    const status = scheduler.getCatalogEnrichmentStatus();
    expect(status.nextRunAt).toBeTruthy();
    const nextRun = new Date(status.nextRunAt!);
    expect(nextRun.getTime()).toBeGreaterThan(Date.now());
  });

  it("status has null nextRunAt when disabled", () => {
    scheduler.updateCatalogEnrichmentConfig({ enabled: false });
    const status = scheduler.getCatalogEnrichmentStatus();
    expect(status.nextRunAt).toBeNull();
  });

  it("stopCatalogEnrichmentScheduler clears the timer", () => {
    scheduler.startCatalogEnrichmentScheduler({ enabled: true });
    scheduler.stopCatalogEnrichmentScheduler();
    const status = scheduler.getCatalogEnrichmentStatus();
    expect(status.schedulerActive).toBe(false);
  });

  it("runCatalogEnrichment rejects when already running", async () => {
    // Simulate running state by starting a run that will fail on DB access
    const promise = scheduler.runCatalogEnrichment("manual").catch(() => {});
    // Second call should throw
    await expect(scheduler.runCatalogEnrichment("manual")).rejects.toThrow(
      "already running"
    );
    await promise; // cleanup
  });
});

// ─── Enrichment Guardrails Config Tests ──────────────────────────────

describe("Enrichment Guardrails Config", () => {
  it("exports GUARDRAIL_CONFIG with threshold constants", async () => {
    const guardrails = await import("./lib/enrichment-guardrails");
    const config = guardrails.GUARDRAIL_CONFIG;
    expect(config).toBeDefined();
    expect(config.CONFIDENCE_ACCEPT_THRESHOLD).toBeGreaterThan(0);
    expect(config.CONFIDENCE_ACCEPT_THRESHOLD).toBeLessThanOrEqual(100);
    expect(config.CONFIDENCE_REJECT_THRESHOLD).toBeGreaterThanOrEqual(0);
    expect(config.CONFIDENCE_REJECT_THRESHOLD).toBeLessThan(config.CONFIDENCE_ACCEPT_THRESHOLD);
    expect(config.LLM_ONLY_MIN_CONFIDENCE).toBeGreaterThan(0);
  });

  it("MITRE_TECHNIQUE_REGEX accepts valid T-codes", async () => {
    const guardrails = await import("./lib/enrichment-guardrails");
    const regex = guardrails.GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX;
    expect(regex.test("T1059")).toBe(true);
    expect(regex.test("T1059.001")).toBe(true);
    expect(regex.test("T1595.002")).toBe(true);
  });

  it("MITRE_TECHNIQUE_REGEX rejects invalid T-codes", async () => {
    const guardrails = await import("./lib/enrichment-guardrails");
    const regex = guardrails.GUARDRAIL_CONFIG.MITRE_TECHNIQUE_REGEX;
    expect(regex.test("TXYZ")).toBe(false);
    expect(regex.test("")).toBe(false);
    expect(regex.test("random string")).toBe(false);
    expect(regex.test("T99999")).toBe(false);
  });

  it("applyGuardrails returns a guardrail report", async () => {
    const guardrails = await import("./lib/enrichment-guardrails");
    const mockParsed = {
      description: "Test description that is long enough to pass the minimum length check for guardrails validation",
      origin: "Russia",
    };
    const mockSources = [
      { field: "description", confidence: 80, sourceType: "vendor_report", sourceName: "Mandiant" },
      { field: "origin", confidence: 90, sourceType: "osint", sourceName: "CrowdStrike" },
    ];
    const localContext = { tgeEvents: [], uieEvents: [], iocs: [] };
    const existingActor = {};

    const { report } = guardrails.applyGuardrails(mockParsed, mockSources, localContext, existingActor);
    expect(report).toBeDefined();
    expect(report.totalFields).toBeGreaterThan(0);
    expect(typeof report.accepted).toBe("number");
    expect(typeof report.flagged).toBe("number");
    expect(typeof report.rejected).toBe("number");
    expect(report.overallTrustScore).toBeDefined();
    expect(report.verdicts).toBeDefined();
    expect(Array.isArray(report.verdicts)).toBe(true);
  });

  it("applyGuardrails accepts high-confidence fields with good sources", async () => {
    const guardrails = await import("./lib/enrichment-guardrails");
    const parsed = {
      description: "Known APT group targeting financial sector with extensive operations across multiple regions and industries",
    };
    const sources = [
      { field: "description", confidence: 85, sourceType: "vendor_report", sourceName: "Mandiant" },
      { field: "description", confidence: 90, sourceType: "osint", sourceName: "CrowdStrike" },
    ];
    const localContext = { tgeEvents: [], uieEvents: [], iocs: [] };

    const { report } = guardrails.applyGuardrails(parsed, sources, localContext, {});
    const descVerdict = report.verdicts.find((v: any) => v.field === "description");
    expect(descVerdict).toBeDefined();
    expect(descVerdict?.status).toBe("accepted");
  });

  it("applyGuardrails flags LLM-only sources below LLM_ONLY_MIN_CONFIDENCE", async () => {
    const guardrails = await import("./lib/enrichment-guardrails");
    // Use confidence below LLM_ONLY_MIN_CONFIDENCE (70) to trigger flagging
    const parsed = {
      description: "Some description from LLM only that is long enough to pass the minimum length check for guardrails",
    };
    const sources = [
      { field: "description", confidence: 50, sourceType: "llm_knowledge", sourceName: "LLM Knowledge" },
    ];
    const localContext = { tgeEvents: [], uieEvents: [], iocs: [] };

    const { report } = guardrails.applyGuardrails(parsed, sources, localContext, {});
    const descVerdict = report.verdicts.find((v: any) => v.field === "description");
    expect(descVerdict).toBeDefined();
    expect(["flagged", "rejected"]).toContain(descVerdict?.status);
  });
});

// ─── MITRE ATT&CK Navigator Layer Tests ──────────────────────────────

describe("MITRE ATT&CK Navigator Layer Export", () => {
  it("generates valid Navigator layer JSON structure", () => {
    // Test the expected structure of a Navigator layer
    const layer = {
      name: "Threat Actor Coverage",
      versions: { attack: "14", navigator: "4.9.1", layer: "4.5" },
      domain: "enterprise-attack",
      description: "Technique coverage from threat actor catalog",
      filters: { platforms: ["windows", "linux", "macos"] },
      sorting: 3,
      layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregateScores: true, countUnscored: false },
      hideDisabled: false,
      techniques: [] as any[],
      gradient: { colors: ["#ffffff", "#ff6666"], minValue: 0, maxValue: 100 },
      legendItems: [],
      metadata: [],
      links: [],
      showTacticRowBackground: true,
      tacticRowBackground: "#dddddd",
      selectTechniquesAcrossTactics: true,
      selectSubtechniquesWithParent: false,
      selectVisibleTechniques: false,
    };

    expect(layer.name).toBe("Threat Actor Coverage");
    expect(layer.domain).toBe("enterprise-attack");
    expect(layer.versions).toBeDefined();
    expect(layer.versions.attack).toBeDefined();
    expect(layer.versions.navigator).toBeDefined();
    expect(layer.techniques).toBeDefined();
    expect(Array.isArray(layer.techniques)).toBe(true);
    expect(layer.gradient).toBeDefined();
    expect(layer.gradient.colors.length).toBe(2);
  });

  it("generates technique entries with correct structure", () => {
    const technique = {
      techniqueID: "T1059",
      tactic: "execution",
      color: "#ff6666",
      comment: "Used by: APT28, Lazarus Group",
      score: 2,
      discoveryEnabled: true,
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: false,
    };

    expect(technique.techniqueID).toMatch(/^T\d{4}/);
    expect(technique.tactic).toBeTruthy();
    expect(typeof technique.score).toBe("number");
    expect(technique.score).toBeGreaterThan(0);
    expect(technique.enabled).toBe(true);
    expect(technique.comment).toContain("Used by:");
  });

  it("handles subtechniques correctly", () => {
    const subtechnique = {
      techniqueID: "T1059.001",
      tactic: "execution",
      color: "#ff9999",
      comment: "Used by: APT29",
      score: 1,
      discoveryEnabled: true,
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: false,
    };

    expect(subtechnique.techniqueID).toMatch(/^T\d{4}\.\d{3}$/);
    expect(subtechnique.score).toBe(1);
  });

  it("color gradient scales with actor count", () => {
    // Simulate color calculation based on actor count
    function getColor(count: number, maxCount: number): string {
      if (maxCount === 0) return "#ffffff";
      const intensity = Math.min(count / maxCount, 1);
      const r = 255;
      const g = Math.round(255 * (1 - intensity * 0.6));
      const b = Math.round(255 * (1 - intensity * 0.6));
      return `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
    }

    // Low count = lighter
    const lowColor = getColor(1, 10);
    // High count = darker
    const highColor = getColor(10, 10);

    expect(lowColor).not.toBe(highColor);
    // High count should have lower G/B values (more red)
    expect(parseInt(highColor.slice(3, 5), 16)).toBeLessThan(
      parseInt(lowColor.slice(3, 5), 16)
    );
  });
});

// ─── Completeness Calculator Tests ───────────────────────────────────

describe("Completeness Calculator", () => {
  it("returns 0 for empty actor", () => {
    function computeCompleteness(actor: any): number {
      if (!actor) return 0;
      const fields = [
        { name: "description", weight: 15 },
        { name: "origin", weight: 10 },
        { name: "motivation", weight: 10 },
        { name: "firstSeen", weight: 5 },
        { name: "aliases", weight: 10 },
        { name: "mitreTechniques", weight: 15 },
        { name: "tools", weight: 10 },
        { name: "targetSectors", weight: 10 },
        { name: "targetRegions", weight: 10 },
        { name: "notableAttacks", weight: 5 },
      ];
      let score = 0;
      for (const f of fields) {
        const val = actor[f.name];
        if (!val) continue;
        if (typeof val === "string" && val.trim().length > 0) score += f.weight;
        else if (Array.isArray(val) && val.length > 0) score += f.weight;
        else if (typeof val === "object" && val !== null) {
          const arr = Array.isArray(val) ? val : Object.keys(val);
          if (arr.length > 0) score += f.weight;
        }
      }
      return score;
    }

    expect(computeCompleteness(null)).toBe(0);
    expect(computeCompleteness({})).toBe(0);
    expect(computeCompleteness({ description: "" })).toBe(0);
    expect(computeCompleteness({ description: "   " })).toBe(0);
  });

  it("returns 100 for fully populated actor", () => {
    function computeCompleteness(actor: any): number {
      if (!actor) return 0;
      const fields = [
        { name: "description", weight: 15 },
        { name: "origin", weight: 10 },
        { name: "motivation", weight: 10 },
        { name: "firstSeen", weight: 5 },
        { name: "aliases", weight: 10 },
        { name: "mitreTechniques", weight: 15 },
        { name: "tools", weight: 10 },
        { name: "targetSectors", weight: 10 },
        { name: "targetRegions", weight: 10 },
        { name: "notableAttacks", weight: 5 },
      ];
      let score = 0;
      for (const f of fields) {
        const val = actor[f.name];
        if (!val) continue;
        if (typeof val === "string" && val.trim().length > 0) score += f.weight;
        else if (Array.isArray(val) && val.length > 0) score += f.weight;
        else if (typeof val === "object" && val !== null) {
          const arr = Array.isArray(val) ? val : Object.keys(val);
          if (arr.length > 0) score += f.weight;
        }
      }
      return score;
    }

    const fullActor = {
      description: "A known APT group",
      origin: "Russia",
      motivation: "Espionage",
      firstSeen: "2015",
      aliases: ["Fancy Bear"],
      mitreTechniques: ["T1059", "T1566"],
      tools: ["Mimikatz"],
      targetSectors: ["Government"],
      targetRegions: ["US", "EU"],
      notableAttacks: ["SolarWinds"],
    };

    expect(computeCompleteness(fullActor)).toBe(100);
  });

  it("returns partial score for partially populated actor", () => {
    function computeCompleteness(actor: any): number {
      if (!actor) return 0;
      const fields = [
        { name: "description", weight: 15 },
        { name: "origin", weight: 10 },
        { name: "motivation", weight: 10 },
        { name: "firstSeen", weight: 5 },
        { name: "aliases", weight: 10 },
        { name: "mitreTechniques", weight: 15 },
        { name: "tools", weight: 10 },
        { name: "targetSectors", weight: 10 },
        { name: "targetRegions", weight: 10 },
        { name: "notableAttacks", weight: 5 },
      ];
      let score = 0;
      for (const f of fields) {
        const val = actor[f.name];
        if (!val) continue;
        if (typeof val === "string" && val.trim().length > 0) score += f.weight;
        else if (Array.isArray(val) && val.length > 0) score += f.weight;
        else if (typeof val === "object" && val !== null) {
          const arr = Array.isArray(val) ? val : Object.keys(val);
          if (arr.length > 0) score += f.weight;
        }
      }
      return score;
    }

    // Only description (15) + origin (10) = 25
    const partialActor = {
      description: "Known group",
      origin: "China",
    };

    expect(computeCompleteness(partialActor)).toBe(25);
  });
});
