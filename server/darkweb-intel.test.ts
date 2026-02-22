import { describe, expect, it, vi, beforeEach } from "vitest";

// ─── Darkweb IOC Enrichment Tests ────────────────────────────────────────

describe("darkweb-ioc-enrichment", () => {
  it("enrichIocWithDarkweb returns correct structure for IP", async () => {
    const { enrichIocWithDarkweb } = await import("./lib/darkweb-ioc-enrichment");
    const result = await enrichIocWithDarkweb("8.8.8.8", "ip");

    expect(result).toHaveProperty("ioc", "8.8.8.8");
    expect(result).toHaveProperty("iocType", "ip");
    expect(result).toHaveProperty("darkwebHits");
    expect(result).toHaveProperty("riskElevation");
    expect(result).toHaveProperty("summary");
    expect(result).toHaveProperty("enrichedAt");
    expect(Array.isArray(result.darkwebHits)).toBe(true);
    expect(typeof result.riskElevation).toBe("number");
    expect(result.riskElevation).toBeGreaterThanOrEqual(0);
    expect(result.riskElevation).toBeLessThanOrEqual(100);
  });

  it("enrichIocWithDarkweb returns correct structure for domain", async () => {
    const { enrichIocWithDarkweb } = await import("./lib/darkweb-ioc-enrichment");
    const result = await enrichIocWithDarkweb("example.com", "domain");

    expect(result.ioc).toBe("example.com");
    expect(result.iocType).toBe("domain");
    expect(Array.isArray(result.darkwebHits)).toBe(true);
    expect(typeof result.summary).toBe("string");
    expect(result.summary.length).toBeGreaterThan(0);
  });

  it("enrichIocWithDarkweb returns correct structure for email", async () => {
    const { enrichIocWithDarkweb } = await import("./lib/darkweb-ioc-enrichment");
    const result = await enrichIocWithDarkweb("test@example.com", "email");

    expect(result.ioc).toBe("test@example.com");
    expect(result.iocType).toBe("email");
    expect(Array.isArray(result.darkwebHits)).toBe(true);
  });

  it("enrichIocWithDarkweb returns correct structure for hash", async () => {
    const { enrichIocWithDarkweb } = await import("./lib/darkweb-ioc-enrichment");
    const result = await enrichIocWithDarkweb("d41d8cd98f00b204e9800998ecf8427e", "hash");

    expect(result.ioc).toBe("d41d8cd98f00b204e9800998ecf8427e");
    expect(result.iocType).toBe("hash");
    expect(Array.isArray(result.darkwebHits)).toBe(true);
  });

  it("enrichIocWithDarkweb returns correct structure for CVE", async () => {
    const { enrichIocWithDarkweb } = await import("./lib/darkweb-ioc-enrichment");
    const result = await enrichIocWithDarkweb("CVE-2024-1234", "cve");

    expect(result.ioc).toBe("CVE-2024-1234");
    expect(result.iocType).toBe("cve");
    expect(Array.isArray(result.darkwebHits)).toBe(true);
  });

  it("enrichIocBatchWithDarkweb processes multiple IOCs", async () => {
    const { enrichIocBatchWithDarkweb } = await import("./lib/darkweb-ioc-enrichment");
    const iocs = [
      { value: "8.8.8.8", type: "ip" as const },
      { value: "example.com", type: "domain" as const },
      { value: "CVE-2024-1234", type: "cve" as const },
    ];
    const results = await enrichIocBatchWithDarkweb(iocs);

    expect(Array.isArray(results)).toBe(true);
    expect(results.length).toBe(3);
    expect(results[0].ioc).toBe("8.8.8.8");
    expect(results[1].ioc).toBe("example.com");
    expect(results[2].ioc).toBe("CVE-2024-1234");
  });

  it("postSyncDarkwebEnrichment returns enrichment stats", async () => {
    const { postSyncDarkwebEnrichment } = await import("./lib/darkweb-ioc-enrichment");
    const result = await postSyncDarkwebEnrichment([
      { value: "1.2.3.4", type: "ip" },
      { value: "evil.com", type: "domain" },
    ]);

    expect(result).toHaveProperty("enriched");
    expect(result).toHaveProperty("totalHits");
    expect(typeof result.enriched).toBe("number");
    expect(typeof result.totalHits).toBe("number");
  });

  it("darkwebHit objects have correct severity values", async () => {
    const { enrichIocWithDarkweb } = await import("./lib/darkweb-ioc-enrichment");
    const result = await enrichIocWithDarkweb("192.168.1.1", "ip");

    for (const hit of result.darkwebHits) {
      expect(["critical", "high", "medium", "low"]).toContain(hit.severity);
      expect(["exact", "partial", "related"]).toContain(hit.matchType);
      expect(typeof hit.source).toBe("string");
      expect(typeof hit.category).toBe("string");
      expect(typeof hit.description).toBe("string");
      expect(typeof hit.confidence).toBe("number");
      expect(hit.confidence).toBeGreaterThanOrEqual(0);
      expect(hit.confidence).toBeLessThanOrEqual(100);
    }
  });
});

// ─── Darkweb OSINT Service Tests ─────────────────────────────────────────

describe("darkweb-osint-service", () => {
  it("exports runDarkwebFeedSync function", async () => {
    const mod = await import("./lib/darkweb-osint-service");
    expect(typeof mod.runDarkwebFeedSync).toBe("function");
  });

  it("exports isDarkwebSyncRunning function", async () => {
    const mod = await import("./lib/darkweb-osint-service");
    expect(typeof mod.isDarkwebSyncRunning).toBe("function");
    expect(mod.isDarkwebSyncRunning()).toBe(false);
  });

  it("exports all expected feed fetch functions", async () => {
    const mod = await import("./lib/darkweb-osint-service");
    // Check that all feed fetchers are exported
    expect(typeof mod.fetchFeodoTracker).toBe("function");
    expect(typeof mod.fetchMalwareBazaar).toBe("function");
    expect(typeof mod.fetchSSLBlacklist).toBe("function");
    expect(typeof mod.fetchRansomwareLiveVictims).toBe("function");
    expect(typeof mod.fetchRansomwareLiveGroups).toBe("function");
    expect(typeof mod.fetchAlienVaultOTX).toBe("function");
    expect(typeof mod.fetchOpenPhish).toBe("function");
    expect(typeof mod.fetchTorExitNodes).toBe("function");
    expect(typeof mod.fetchBlocklistDe).toBe("function");
    expect(typeof mod.fetchSpamhausDrop).toBe("function");
    expect(typeof mod.fetchHIBPBreaches).toBe("function");
  });

  it("getFeedHealthSummary returns feed status data", async () => {
    const mod = await import("./lib/darkweb-osint-service");
    const health = await mod.getFeedHealthSummary();
    expect(health).toBeDefined();
    expect(typeof health).toBe("object");
  });
});

// ─── Darkweb MySQL Service Tests ─────────────────────────────────────────

describe("darkweb-mysql-service", () => {
  it("exports all CRUD query functions", async () => {
    const mod = await import("./lib/darkweb-mysql-service");

    expect(typeof mod.getUndergroundEvents).toBe("function");
    expect(typeof mod.getNetworkEvents).toBe("function");
    expect(typeof mod.getCredentialExposures).toBe("function");
    expect(typeof mod.getIabActivities).toBe("function");
    expect(typeof mod.getEnrichedRecords).toBe("function");
    expect(typeof mod.getRansomwareAffiliates).toBe("function");
    expect(typeof mod.getDarkwebDashboardStats).toBe("function");
  });

  it("getUndergroundEvents returns array", async () => {
    const mod = await import("./lib/darkweb-mysql-service");
    const result = await mod.getUndergroundEvents({});
    expect(result).toHaveProperty("events");
    expect(Array.isArray(result.events)).toBe(true);
  });

  it("getNetworkEvents returns array", async () => {
    const mod = await import("./lib/darkweb-mysql-service");
    const result = await mod.getNetworkEvents({});
    expect(result).toHaveProperty("events");
    expect(Array.isArray(result.events)).toBe(true);
  });

  it("getCredentialExposures returns array", async () => {
    const mod = await import("./lib/darkweb-mysql-service");
    const result = await mod.getCredentialExposures({});
    expect(result).toHaveProperty("exposures");
    expect(Array.isArray(result.exposures)).toBe(true);
  });

  it("getIabActivities returns array", async () => {
    const mod = await import("./lib/darkweb-mysql-service");
    const result = await mod.getIabActivities({});
    expect(result).toHaveProperty("activities");
    expect(Array.isArray(result.activities)).toBe(true);
  });

  it("getDarkwebDashboardStats returns stats object", async () => {
    const mod = await import("./lib/darkweb-mysql-service");
    const stats = await mod.getDarkwebDashboardStats();

    expect(stats).toHaveProperty("undergroundEvents");
    expect(stats).toHaveProperty("networkEvents");
    expect(stats).toHaveProperty("credentialExposures");
    expect(typeof stats.undergroundEvents).toBe("object");
  });
});

// ─── Darkweb Intel Service Tests ─────────────────────────────────────────

describe("darkweb-intel-service", () => {
  it("exports syncRansomwareActors function", async () => {
    const mod = await import("./lib/darkweb-intel-service");
    expect(typeof mod.syncRansomwareActors).toBe("function");
  });

  it("exports getSectorThreatProfiles function", async () => {
    const mod = await import("./lib/darkweb-intel-service");
    expect(typeof mod.getSectorThreatProfiles).toBe("function");
  });

  it("getSectorThreatProfiles returns array of profiles", async () => {
    const mod = await import("./lib/darkweb-intel-service");
    const profiles = await mod.getSectorThreatProfiles();
    expect(Array.isArray(profiles)).toBe(true);
  });
});

// ─── Darkweb Enrichment Service Tests ────────────────────────────────────

describe("darkweb-enrichment-service", () => {
  it("exports enrichEvent function", async () => {
    const mod = await import("./lib/darkweb-enrichment-service");
    expect(typeof mod.enrichEvent).toBe("function");
  });

  it("exports enrichBatch function", async () => {
    const mod = await import("./lib/darkweb-enrichment-service");
    expect(typeof mod.enrichBatch).toBe("function");
  });
});

// ─── tRPC Router Tests ───────────────────────────────────────────────────

describe("darkweb-intel tRPC router", () => {
  it("router has all expected procedures", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");

    // Check the router has the expected procedure keys
    const procedureKeys = Object.keys(darkwebIntelRouter._def.procedures);

    expect(procedureKeys).toContain("listEvents");
    expect(procedureKeys).toContain("listNetworkEvents");
    expect(procedureKeys).toContain("listCredentialExposures");
    expect(procedureKeys).toContain("listIabActivity");
    expect(procedureKeys).toContain("listEnrichedRecords");
    expect(procedureKeys).toContain("listAffiliates");
    expect(procedureKeys).toContain("syncActors");
    expect(procedureKeys).toContain("enrichEvent");
    expect(procedureKeys).toContain("enrichBatch");
    expect(procedureKeys).toContain("feedHealth");
    expect(procedureKeys).toContain("syncAllFeeds");
    expect(procedureKeys).toContain("sectorProfiles");
    expect(procedureKeys).toContain("trends");
    expect(procedureKeys).toContain("correlateActor");
    expect(procedureKeys).toContain("enrichIoc");
    expect(procedureKeys).toContain("enrichIocBatch");
    expect(procedureKeys).toContain("dashboardStats");
  });
});
