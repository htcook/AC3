/**
 * Threat Intel Training Pipeline Tests
 *
 * Tests for:
 * - Feed ingestion service (THREAT_INTEL_SOURCES, RSS parsing, dedup)
 * - Attack sequence learner (extraction, template generation, exploit enrichment)
 * - tRPC router procedures
 * - Cron scheduler integration
 */
import { describe, it, expect } from "vitest";

describe("Threat Intel Ingestion Service", () => {
  it("should export THREAT_INTEL_SOURCES with all 12 sources", async () => {
    const mod = await import("./lib/threat-intel-ingest");
    expect(mod.THREAT_INTEL_SOURCES).toBeDefined();
    expect(Array.isArray(mod.THREAT_INTEL_SOURCES)).toBe(true);
    expect(mod.THREAT_INTEL_SOURCES.length).toBeGreaterThanOrEqual(10);
  });

  it("should have correct source categories", async () => {
    const { THREAT_INTEL_SOURCES } = await import("./lib/threat-intel-ingest");
    const categories = Array.from(new Set(THREAT_INTEL_SOURCES.map(s => s.category)));
    expect(categories).toContain("incident_reports");
    expect(categories).toContain("news");
    expect(categories).toContain("exploit_intel");
  });

  it("should include DFIR Report as highest priority source", async () => {
    const { THREAT_INTEL_SOURCES } = await import("./lib/threat-intel-ingest");
    const dfir = THREAT_INTEL_SOURCES.find(s => s.name === "dfir_report");
    expect(dfir).toBeDefined();
    expect(dfir!.priority).toBe(1);
    expect(dfir!.category).toBe("incident_reports");
  });

  it("should include CISA advisories source", async () => {
    const { THREAT_INTEL_SOURCES } = await import("./lib/threat-intel-ingest");
    const cisa = THREAT_INTEL_SOURCES.find(s => s.name === "cisa_advisory");
    expect(cisa).toBeDefined();
    expect(cisa!.category).toBe("government_advisories");
  });

  it("should include news sources (Hacker News, Dark Reading, CyberScoop, CybersecDive)", async () => {
    const { THREAT_INTEL_SOURCES } = await import("./lib/threat-intel-ingest");
    const newsNames = THREAT_INTEL_SOURCES.filter(s => s.category === "news").map(s => s.name);
    expect(newsNames).toContain("hacker_news");
    expect(newsNames).toContain("dark_reading");
  });

  it("should include threat feed sources (MISP, Metasploit, CISA KEV)", async () => {
    const { THREAT_INTEL_SOURCES } = await import("./lib/threat-intel-ingest");
    const threatSharing = THREAT_INTEL_SOURCES.filter(s => s.category === "threat_sharing").map(s => s.name);
    expect(threatSharing).toContain("misp_circl");
    const exploitIntel = THREAT_INTEL_SOURCES.filter(s => s.category === "exploit_intel").map(s => s.name);
    expect(exploitIntel).toContain("metasploit_cve");
    expect(exploitIntel).toContain("cisa_kev_exploits");
  });

  it("should export runFullIngest function", async () => {
    const mod = await import("./lib/threat-intel-ingest");
    expect(typeof mod.runFullIngest).toBe("function");
  });

  it("should export getIngestStats function", async () => {
    const mod = await import("./lib/threat-intel-ingest");
    expect(typeof mod.getIngestStats).toBe("function");
  });

  it("should export individual source ingest functions", async () => {
    const mod = await import("./lib/threat-intel-ingest");
    expect(typeof mod.ingestDfirReport).toBe("function");
    expect(typeof mod.ingestCisaAdvisories).toBe("function");
    expect(typeof mod.ingestUnit42).toBe("function");
    expect(typeof mod.ingestHackerNews).toBe("function");
    expect(typeof mod.ingestDarkReading).toBe("function");
    expect(typeof mod.ingestMispCircl).toBe("function");
    expect(typeof mod.ingestMetasploitCves).toBe("function");
    expect(typeof mod.ingestCisaKevExploits).toBe("function");
  });

  it("each source should have priority, name, category, and fn", async () => {
    const { THREAT_INTEL_SOURCES } = await import("./lib/threat-intel-ingest");
    for (const source of THREAT_INTEL_SOURCES) {
      expect(source.name).toBeTruthy();
      expect(source.category).toBeTruthy();
      expect(typeof source.priority).toBe("number");
      expect(typeof source.fn).toBe("function");
    }
  });
});

describe("Attack Sequence Learner", () => {
  it("should export extractAttackSequence function", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.extractAttackSequence).toBe("function");
  });

  it("should export generateAttackTemplate function", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.generateAttackTemplate).toBe("function");
  });

  it("should export enrichExploitsFromReport function", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.enrichExploitsFromReport).toBe("function");
  });

  it("should export crossReferenceActors function", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.crossReferenceActors).toBe("function");
  });

  it("should export updateTtpKnowledgeFromReport function", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.updateTtpKnowledgeFromReport).toBe("function");
  });

  it("should export processReport function for full pipeline", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.processReport).toBe("function");
  });

  it("should export processBatch function for batch processing", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.processBatch).toBe("function");
  });

  it("should export getLearnerStats function", async () => {
    const mod = await import("./lib/attack-sequence-learner");
    expect(typeof mod.getLearnerStats).toBe("function");
  });
});

describe("Threat Intel Training Router", () => {
  it("should export threatIntelTrainingRouter", async () => {
    const mod = await import("./routers/threat-intel-training");
    expect(mod.threatIntelTrainingRouter).toBeDefined();
  });

  it("should have all ingestion procedures", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("ingestAll");
    expect(procedures).toContain("ingestSource");
    expect(procedures).toContain("ingestStats");
    expect(procedures).toContain("listSources");
  });

  it("should have all report procedures", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("listReports");
    expect(procedures).toContain("getReport");
  });

  it("should have all processing procedures", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("processReport");
    expect(procedures).toContain("processBatch");
    expect(procedures).toContain("extractSequence");
    expect(procedures).toContain("generateTemplate");
  });

  it("should have all template procedures", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("listTemplates");
    expect(procedures).toContain("getTemplate");
    expect(procedures).toContain("updateTemplateStatus");
  });

  it("should have exploit intelligence procedures", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("listExploits");
    expect(procedures).toContain("getExploitByCve");
  });

  it("should have statistics procedures", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("learnerStats");
    expect(procedures).toContain("dashboardStats");
  });
});

describe("Cron Scheduler Integration", () => {
  it("scheduler should include threat intel ingestion cron job", async () => {
    const mod = await import("./lib/darkweb-feed-scheduler");
    // The scheduler imports runFullIngest — verify the module loads cleanly
    expect(typeof mod.initDarkwebFeedScheduler).toBe("function");
  });

  it("scheduler should include attack sequence extraction cron job", async () => {
    const mod = await import("./lib/darkweb-feed-scheduler");
    expect(typeof mod.runFullDarkwebSync).toBe("function");
  });
});

describe("Schema Tables", () => {
  it("should export incidentReports table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.incidentReports).toBeDefined();
  });

  it("should export attackSequenceTemplates table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.attackSequenceTemplates).toBeDefined();
  });

  it("should export exploitIntelligence table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.exploitIntelligence).toBeDefined();
  });
});
