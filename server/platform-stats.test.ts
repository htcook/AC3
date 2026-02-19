import { describe, it, expect, vi } from "vitest";

// ─── Unit tests for the platformStats.getHomepageStats endpoint ───────

describe("platformStats.getHomepageStats", () => {
  it("getCatalogStats returns structured stats from the exploit catalog", async () => {
    const { getCatalogStats } = await import("./lib/exploit-catalog");
    const stats = await getCatalogStats();

    expect(stats).toHaveProperty("total");
    expect(stats).toHaveProperty("byTier");
    expect(stats).toHaveProperty("bySource");
    expect(stats).toHaveProperty("byCategory");
    expect(stats).toHaveProperty("calderaSynced");
    expect(stats).toHaveProperty("withStagers");

    // Tier breakdown
    expect(stats.byTier).toHaveProperty("initial_access");
    expect(stats.byTier).toHaveProperty("post_access");
    expect(typeof stats.byTier.initial_access).toBe("number");
    expect(typeof stats.byTier.post_access).toBe("number");

    // Total should equal sum of tiers
    expect(stats.total).toBe(stats.byTier.initial_access + stats.byTier.post_access);
  });

  it("catalog has been populated with entries from the enrichment pipeline", async () => {
    const { getCatalogStats } = await import("./lib/exploit-catalog");
    const stats = await getCatalogStats();

    // After running the enrichment pipeline, we should have entries
    expect(stats.total).toBeGreaterThan(0);

    // Should have entries from multiple sources
    expect(stats.bySource).toHaveProperty("metasploit");
    expect(stats.bySource).toHaveProperty("caldera_stockpile");
    expect(stats.bySource).toHaveProperty("phishing_library");

    // Metasploit should have the most entries
    expect(stats.bySource["metasploit"]).toBeGreaterThan(2000);

    // Caldera stockpile should have ~1900 entries
    expect(stats.bySource["caldera_stockpile"]).toBeGreaterThan(1500);

    // Phishing library should have 17 entries
    expect(stats.bySource["phishing_library"]).toBe(17);
  });

  it("getThreatActorCount returns a positive number", async () => {
    const { getThreatActorCount } = await import("./db");
    const count = await getThreatActorCount();

    expect(typeof count).toBe("number");
    expect(count).toBeGreaterThan(0);
    // We verified 1,694 threat actors in the DB
    expect(count).toBeGreaterThanOrEqual(1600);
  });

  it("catalog byTier has both initial_access and post_access entries", async () => {
    const { getCatalogStats } = await import("./lib/exploit-catalog");
    const stats = await getCatalogStats();

    // Metasploit and phishing are initial_access
    expect(stats.byTier.initial_access).toBeGreaterThan(0);

    // Caldera stockpile abilities are mostly post_access
    expect(stats.byTier.post_access).toBeGreaterThan(0);
  });

  it("catalog byCategory has expected categories", async () => {
    const { getCatalogStats } = await import("./lib/exploit-catalog");
    const stats = await getCatalogStats();

    // Should have common categories from the enrichment
    const categories = Object.keys(stats.byCategory);
    expect(categories.length).toBeGreaterThan(3);

    // RCE category should exist (from Metasploit remote exploits)
    expect(stats.byCategory).toHaveProperty("rce");
    expect(stats.byCategory["rce"]).toBeGreaterThan(0);
  });

  it("searchCatalog returns paginated results", async () => {
    const { searchCatalog } = await import("./lib/exploit-catalog");
    const result = await searchCatalog({ limit: 10, offset: 0 });

    expect(result).toHaveProperty("items");
    expect(result).toHaveProperty("total");
    expect(Array.isArray(result.items)).toBe(true);
    expect(result.items.length).toBeLessThanOrEqual(10);
    expect(result.total).toBeGreaterThan(0);

    // Each item should have required fields
    const item = result.items[0];
    expect(item).toHaveProperty("catalogId");
    expect(item).toHaveProperty("name");
    expect(item).toHaveProperty("tier");
    expect(item).toHaveProperty("source");
  });

  it("searchCatalog filters by tier correctly", async () => {
    const { searchCatalog } = await import("./lib/exploit-catalog");

    const initialAccess = await searchCatalog({ tier: "initial_access", limit: 5 });
    const postAccess = await searchCatalog({ tier: "post_access", limit: 5 });

    // All initial_access results should have that tier
    for (const item of initialAccess.items) {
      expect(item.tier).toBe("initial_access");
    }

    // All post_access results should have that tier
    for (const item of postAccess.items) {
      expect(item.tier).toBe("post_access");
    }
  });

  it("searchCatalog filters by source correctly", async () => {
    const { searchCatalog } = await import("./lib/exploit-catalog");

    const msf = await searchCatalog({ source: "metasploit", limit: 5 });
    for (const item of msf.items) {
      expect(item.source).toBe("metasploit");
    }

    const caldera = await searchCatalog({ source: "caldera_stockpile", limit: 5 });
    for (const item of caldera.items) {
      expect(item.source).toBe("caldera_stockpile");
    }
  });

  it("getCatalogEntry returns a single entry by ID", async () => {
    const { searchCatalog, getCatalogEntry } = await import("./lib/exploit-catalog");

    // Get a known entry
    const results = await searchCatalog({ limit: 1 });
    expect(results.items.length).toBe(1);

    const entry = await getCatalogEntry(results.items[0].catalogId);
    expect(entry).not.toBeNull();
    expect(entry!.catalogId).toBe(results.items[0].catalogId);
  });

  it("getCatalogEntry returns null for non-existent ID", async () => {
    const { getCatalogEntry } = await import("./lib/exploit-catalog");
    const entry = await getCatalogEntry("nonexistent:fake-id-12345");
    expect(entry).toBeNull();
  });
});
