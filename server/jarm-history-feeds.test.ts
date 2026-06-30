import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Test the change classification logic (pure function) ──────────────────
// We test classifyChange indirectly through processAndStoreJarmHistory
// and test the feed parsers directly

// ─── JARM History: classifyChange via processAndStoreJarmHistory ────────────

describe("JARM History Module", () => {
  describe("classifyChange logic", () => {
    // We can test the classification by importing matchJarmFingerprint
    // and simulating the logic
    it("should classify C2 appearance as critical", async () => {
      const { matchJarmFingerprint } = await import("./lib/infrastructure-inference");

      // Cobalt Strike JARM hash
      const c2Hash = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1";
      const normalHash = "00000000000000000000000000000000000000000000000000000000000000";

      const c2Match = matchJarmFingerprint(c2Hash);
      const normalMatch = matchJarmFingerprint(normalHash);

      expect(c2Match).not.toBeNull();
      expect(c2Match!.matchType).toBe("c2");
      expect(c2Match!.provider).toContain("Cobalt Strike");
      expect(normalMatch).toBeNull();
    });

    it("should classify Google Cloud prefix pattern", async () => {
      const { matchJarmFingerprint } = await import("./lib/infrastructure-inference");

      const gcpHash = "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4";
      const match = matchJarmFingerprint(gcpHash);

      expect(match).not.toBeNull();
      expect(match!.matchType).toBe("cloud");
      expect(match!.provider).toContain("Google Cloud");
    });

    it("should return null for unknown hashes", async () => {
      const { matchJarmFingerprint } = await import("./lib/infrastructure-inference");

      const unknownHash = "aaabbbccc111222333444555666777888999000aaabbbccc111222333444555";
      const match = matchJarmFingerprint(unknownHash);

      expect(match).toBeNull();
    });
  });

  describe("processAndStoreJarmHistory", () => {
    let mockDb: any;
    let mockSchema: any;

    beforeEach(() => {
      // Create mock database and schema
      mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        orderBy: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
        insert: vi.fn().mockReturnThis(),
        values: vi.fn().mockResolvedValue(undefined),
      };

      mockSchema = {
        jarmScanHistory: {
          domain: "domain",
          scanId: "scanId",
          scannedAt: "scannedAt",
          changeDetected: "changeDetected",
        },
      };
    });

    it("should return empty results for no matches", async () => {
      const { processAndStoreJarmHistory } = await import("./lib/jarm-history");

      const result = await processAndStoreJarmHistory(
        mockDb,
        mockSchema,
        1,
        "example.com",
        [],
        Date.now(),
      );

      expect(result.records).toHaveLength(0);
      expect(result.alerts).toHaveLength(0);
    });

    it("should process a single JARM match without previous history", async () => {
      const { processAndStoreJarmHistory } = await import("./lib/jarm-history");

      const jarmMatches = [
        {
          hash: "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4",
          matchedProvider: "Cloudflare",
          matchType: "cdn" as const,
          confidence: 0.9,
          source: "jarm_fingerprint",
          port: 443,
        },
      ];

      const result = await processAndStoreJarmHistory(
        mockDb,
        mockSchema,
        1,
        "example.com",
        jarmMatches,
        Date.now(),
      );

      expect(result.records).toHaveLength(1);
      expect(result.records[0].jarmHash).toBe(jarmMatches[0].hash);
      expect(result.records[0].matchedProvider).toBe("Cloudflare");
      expect(result.records[0].changeDetected).toBe(false);
      expect(result.alerts).toHaveLength(0);
    });

    it("should detect change when previous hash exists and differs", async () => {
      const { processAndStoreJarmHistory } = await import("./lib/jarm-history");

      // Mock previous records
      const previousHash = "00000000000000000000000000000000000000000000000000000000000000";
      const currentHash = "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4";

      mockDb.limit = vi.fn().mockResolvedValue([
        {
          host: "example.com",
          port: 443,
          jarmHash: previousHash,
          matchedProvider: null,
          matchType: null,
        },
      ]);

      const jarmMatches = [
        {
          hash: currentHash,
          matchedProvider: "Cloudflare",
          matchType: "cdn" as const,
          confidence: 0.9,
          source: "jarm_fingerprint",
          port: 443,
        },
      ];

      const result = await processAndStoreJarmHistory(
        mockDb,
        mockSchema,
        2,
        "example.com",
        jarmMatches,
        Date.now(),
      );

      expect(result.records).toHaveLength(1);
      expect(result.records[0].changeDetected).toBe(true);
      expect(result.records[0].previousHash).toBe(previousHash);
      expect(result.alerts).toHaveLength(1);
      expect(result.alerts[0].changeType).toBe("new_fingerprint");
    });

    it("should flag C2 appearance as critical alert", async () => {
      const { processAndStoreJarmHistory } = await import("./lib/jarm-history");

      const normalHash = "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4";
      const c2Hash = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1";

      mockDb.limit = vi.fn().mockResolvedValue([
        {
          host: "example.com",
          port: 443,
          jarmHash: normalHash,
          matchedProvider: "Cloudflare",
          matchType: "cdn",
        },
      ]);

      const jarmMatches = [
        {
          hash: c2Hash,
          matchedProvider: "Cobalt Strike",
          matchType: "c2" as const,
          confidence: 0.95,
          source: "jarm_fingerprint",
          port: 443,
        },
      ];

      const result = await processAndStoreJarmHistory(
        mockDb,
        mockSchema,
        2,
        "example.com",
        jarmMatches,
        Date.now(),
      );

      expect(result.records).toHaveLength(1);
      expect(result.records[0].changeDetected).toBe(true);
      expect(result.alerts).toHaveLength(1);
      expect(result.alerts[0].severity).toBe("critical");
      expect(result.alerts[0].changeType).toBe("c2_appearance");
      expect(result.alerts[0].description).toContain("CRITICAL");
    });
  });

  describe("getJarmTimeline", () => {
    it("should return empty timeline for domain with no history", async () => {
      const { getJarmTimeline } = await import("./lib/jarm-history");

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        orderBy: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
      };
      const mockSchema = { jarmScanHistory: { domain: "domain", scannedAt: "scannedAt" } };

      const timeline = await getJarmTimeline(mockDb, mockSchema, "example.com");

      expect(timeline.domain).toBe("example.com");
      expect(timeline.totalRecords).toBe(0);
      expect(timeline.uniqueHosts).toBe(0);
      expect(timeline.changesDetected).toBe(0);
      expect(timeline.criticalAlerts).toBe(0);
      expect(timeline.records).toHaveLength(0);
      expect(timeline.alerts).toHaveLength(0);
    });

    it("should reconstruct alerts from change records", async () => {
      const { getJarmTimeline } = await import("./lib/jarm-history");

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        orderBy: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([
          {
            id: 1,
            scanId: 2,
            domain: "example.com",
            host: "example.com",
            port: 443,
            jarmHash: "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
            matchedProvider: "Cobalt Strike",
            matchType: "c2",
            matchConfidence: 0.95,
            source: "jarm_fingerprint",
            certIssuer: null,
            certSubject: null,
            protocol: null,
            previousHash: "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4",
            changeDetected: 1,
            changeType: "c2_appearance",
            changeSeverity: "critical",
            scannedAt: Date.now(),
          },
        ]),
      };
      const mockSchema = { jarmScanHistory: { domain: "domain", scannedAt: "scannedAt" } };

      const timeline = await getJarmTimeline(mockDb, mockSchema, "example.com");

      expect(timeline.totalRecords).toBe(1);
      expect(timeline.changesDetected).toBe(1);
      expect(timeline.criticalAlerts).toBe(1);
      expect(timeline.alerts).toHaveLength(1);
      expect(timeline.alerts[0].changeType).toBe("c2_appearance");
      expect(timeline.alerts[0].severity).toBe("critical");
    });
  });

  describe("getRecentJarmAlerts", () => {
    it("should return alerts from change records", async () => {
      const { getRecentJarmAlerts } = await import("./lib/jarm-history");

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        orderBy: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([
          {
            host: "example.com",
            port: 443,
            jarmHash: "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
            previousHash: "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4",
            matchedProvider: "Cobalt Strike",
            changeType: "c2_appearance",
            changeSeverity: "critical",
            scannedAt: Date.now(),
          },
        ]),
      };
      const mockSchema = { jarmScanHistory: { changeDetected: "changeDetected", scannedAt: "scannedAt" } };

      const alerts = await getRecentJarmAlerts(mockDb, mockSchema, 10);

      expect(alerts).toHaveLength(1);
      expect(alerts[0].severity).toBe("critical");
      expect(alerts[0].changeType).toBe("c2_appearance");
    });
  });
});

// ─── JARM Community Feeds Module ───────────────────────────────────────────

describe("JARM Community Feeds Module", () => {
  describe("DEFAULT_FEED_SOURCES", () => {
    it("should have at least 3 default feed sources", async () => {
      const { DEFAULT_FEED_SOURCES } = await import("./lib/jarm-community-feeds");

      expect(DEFAULT_FEED_SOURCES.length).toBeGreaterThanOrEqual(3);
    });

    it("should have valid feed source structure", async () => {
      const { DEFAULT_FEED_SOURCES } = await import("./lib/jarm-community-feeds");

      for (const feed of DEFAULT_FEED_SOURCES) {
        expect(feed.feedId).toBeTruthy();
        expect(feed.name).toBeTruthy();
        expect(["github_csv", "github_json", "censys_dataset", "custom_api"]).toContain(feed.feedType);
        expect(feed.url).toMatch(/^https?:\/\//);
        expect(feed.refreshIntervalHours).toBeGreaterThan(0);
      }
    });

    it("should include C2 JARM IOC feed", async () => {
      const { DEFAULT_FEED_SOURCES } = await import("./lib/jarm-community-feeds");

      const c2Feed = DEFAULT_FEED_SOURCES.find((f) => f.feedId === "c2-jarm-ioc");
      expect(c2Feed).toBeDefined();
      expect(c2Feed!.feedType).toBe("github_csv");
      expect(c2Feed!.refreshIntervalHours).toBe(24);
    });

    it("should include Salesforce JARM feed", async () => {
      const { DEFAULT_FEED_SOURCES } = await import("./lib/jarm-community-feeds");

      const sfFeed = DEFAULT_FEED_SOURCES.find((f) => f.feedId === "salesforce-jarm");
      expect(sfFeed).toBeDefined();
      expect(sfFeed!.feedType).toBe("github_json");
    });
  });

  describe("Feed Parsers (via refreshFeed)", () => {
    // Test CSV parsing logic indirectly through the module's internal parsers
    // We can test the parseFeedContent function by mocking fetch in refreshFeed

    it("should parse CSV feed content with C2 tools", async () => {
      // We test the CSV parser by importing and calling it indirectly
      // The parser is internal, so we test through refreshFeed with mocked fetch
      const { refreshFeed } = await import("./lib/jarm-community-feeds");

      const csvContent = `"Tool","JARM","Type"
"Cobalt Strike","07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1","c2"
"Metasploit","07d14d16d21d21d00042d41d00041de5fb3038b65b1e7bf1c56d236e6d8a96","c2"
"nginx","29d29d15d29d29d21c29d29d29d29de9f58a1aa7c1378650c4736a2e8e3e04","server"`;

      // Mock fetch globally
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(csvContent),
      });

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
        insert: vi.fn().mockReturnThis(),
        values: vi.fn().mockResolvedValue(undefined),
        update: vi.fn().mockReturnThis(),
        set: vi.fn().mockReturnThis(),
      };
      // Add where to the update chain
      mockDb.update = vi.fn().mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue(undefined),
        }),
      });

      const mockSchema = {
        jarmCommunitySignatures: { signatureId: "signatureId" },
        jarmFeedSources: { feedId: "feedId", totalSignatures: "totalSignatures" },
      };

      const feed = {
        id: 1,
        feedId: "test-csv",
        name: "Test CSV Feed",
        feedType: "github_csv" as const,
        url: "https://example.com/jarm.csv",
        description: null,
        enabled: true,
        autoRefresh: true,
        refreshIntervalHours: 24,
        lastRefreshAt: null,
        lastRefreshStatus: null,
        lastRefreshError: null,
        totalSignatures: 0,
        lastSignatureCount: null,
      };

      const result = await refreshFeed(mockDb, mockSchema, feed);

      expect(result.success).toBe(true);
      expect(result.signaturesTotal).toBe(3);
      expect(result.signaturesAdded).toBe(3);
      expect(result.error).toBeNull();

      // Restore fetch
      globalThis.fetch = originalFetch;
    });

    it("should parse JSON feed content", async () => {
      const { refreshFeed } = await import("./lib/jarm-community-feeds");

      const jsonContent = JSON.stringify([
        { jarm: "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4", name: "Cloudflare", type: "cdn" },
        { jarm: "29d29d15d29d29d21c29d29d29d29de9f58a1aa7c1378650c4736a2e8e3e04", name: "nginx", type: "server" },
      ]);

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(jsonContent),
      });

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
        insert: vi.fn().mockReturnThis(),
        values: vi.fn().mockResolvedValue(undefined),
        update: vi.fn().mockReturnValue({
          set: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue(undefined),
          }),
        }),
      };

      const mockSchema = {
        jarmCommunitySignatures: { signatureId: "signatureId" },
        jarmFeedSources: { feedId: "feedId", totalSignatures: "totalSignatures" },
      };

      const feed = {
        id: 1,
        feedId: "test-json",
        name: "Test JSON Feed",
        feedType: "github_json" as const,
        url: "https://example.com/jarm.json",
        description: null,
        enabled: true,
        autoRefresh: true,
        refreshIntervalHours: 24,
        lastRefreshAt: null,
        lastRefreshStatus: null,
        lastRefreshError: null,
        totalSignatures: 0,
        lastSignatureCount: null,
      };

      const result = await refreshFeed(mockDb, mockSchema, feed);

      expect(result.success).toBe(true);
      expect(result.signaturesTotal).toBe(2);
      expect(result.signaturesAdded).toBe(2);

      globalThis.fetch = originalFetch;
    });

    it("should handle fetch errors gracefully", async () => {
      const { refreshFeed } = await import("./lib/jarm-community-feeds");

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      const mockDb = {
        update: vi.fn().mockReturnValue({
          set: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue(undefined),
          }),
        }),
      };

      const mockSchema = {
        jarmFeedSources: { feedId: "feedId" },
      };

      const feed = {
        id: 1,
        feedId: "test-error",
        name: "Test Error Feed",
        feedType: "github_json" as const,
        url: "https://example.com/nonexistent.json",
        description: null,
        enabled: true,
        autoRefresh: true,
        refreshIntervalHours: 24,
        lastRefreshAt: null,
        lastRefreshStatus: null,
        lastRefreshError: null,
        totalSignatures: 0,
        lastSignatureCount: null,
      };

      const result = await refreshFeed(mockDb, mockSchema, feed);

      expect(result.success).toBe(false);
      expect(result.error).toContain("404");

      globalThis.fetch = originalFetch;
    });

    it("should update existing signatures instead of duplicating", async () => {
      const { refreshFeed } = await import("./lib/jarm-community-feeds");

      const jsonContent = JSON.stringify([
        { jarm: "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4", name: "Cloudflare", type: "cdn" },
      ]);

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(jsonContent),
      });

      // Mock that signature already exists
      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([{ signatureId: "test:hash:Cloudflare" }]),
        update: vi.fn().mockReturnValue({
          set: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue(undefined),
          }),
        }),
      };

      const mockSchema = {
        jarmCommunitySignatures: { signatureId: "signatureId" },
        jarmFeedSources: { feedId: "feedId", totalSignatures: "totalSignatures" },
      };

      const feed = {
        id: 1,
        feedId: "test-update",
        name: "Test Update Feed",
        feedType: "github_json" as const,
        url: "https://example.com/jarm.json",
        description: null,
        enabled: true,
        autoRefresh: true,
        refreshIntervalHours: 24,
        lastRefreshAt: null,
        lastRefreshStatus: null,
        lastRefreshError: null,
        totalSignatures: 0,
        lastSignatureCount: null,
      };

      const result = await refreshFeed(mockDb, mockSchema, feed);

      expect(result.success).toBe(true);
      expect(result.signaturesUpdated).toBe(1);
      expect(result.signaturesAdded).toBe(0);

      globalThis.fetch = originalFetch;
    });
  });

  describe("initializeDefaultFeeds", () => {
    it("should add default feeds when none exist", async () => {
      const { initializeDefaultFeeds, DEFAULT_FEED_SOURCES } = await import("./lib/jarm-community-feeds");

      const insertValues: any[] = [];
      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
        insert: vi.fn().mockReturnThis(),
        values: vi.fn().mockImplementation((v: any) => {
          insertValues.push(v);
          return Promise.resolve(undefined);
        }),
      };

      const mockSchema = {
        jarmFeedSources: { feedId: "feedId" },
      };

      const added = await initializeDefaultFeeds(mockDb, mockSchema);

      expect(added).toBe(DEFAULT_FEED_SOURCES.length);
      expect(insertValues).toHaveLength(DEFAULT_FEED_SOURCES.length);
    });

    it("should skip feeds that already exist", async () => {
      const { initializeDefaultFeeds } = await import("./lib/jarm-community-feeds");

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([{ feedId: "existing" }]),
        insert: vi.fn().mockReturnThis(),
        values: vi.fn().mockResolvedValue(undefined),
      };

      const mockSchema = {
        jarmFeedSources: { feedId: "feedId" },
      };

      const added = await initializeDefaultFeeds(mockDb, mockSchema);

      expect(added).toBe(0);
    });
  });

  describe("getFeedStats", () => {
    it("should compute correct statistics", async () => {
      const { getFeedStats } = await import("./lib/jarm-community-feeds");

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockImplementation((table: any) => {
          if (table === "feeds") {
            return {
              select: vi.fn().mockReturnThis(),
              from: vi.fn().mockReturnThis(),
              where: vi.fn().mockReturnThis(),
            };
          }
          return mockDb;
        }),
        where: vi.fn().mockReturnThis(),
      };

      // First call returns feeds, second returns signatures
      let callCount = 0;
      mockDb.select = vi.fn().mockReturnValue({
        from: vi.fn().mockImplementation(() => {
          callCount++;
          if (callCount === 1) {
            // Feeds
            return Promise.resolve([
              { enabled: 1, lastRefreshAt: 1000 },
              { enabled: 1, lastRefreshAt: 2000 },
              { enabled: 0, lastRefreshAt: null },
            ]);
          } else {
            // Signatures
            return {
              where: vi.fn().mockResolvedValue([
                { matchType: "c2" },
                { matchType: "c2" },
                { matchType: "cdn" },
                { matchType: "server" },
              ]),
            };
          }
        }),
      });

      const mockSchema = {
        jarmFeedSources: "feeds",
        jarmCommunitySignatures: { enabled: "enabled" },
      };

      const stats = await getFeedStats(mockDb, mockSchema);

      expect(stats.totalFeeds).toBe(3);
      expect(stats.enabledFeeds).toBe(2);
      expect(stats.totalSignatures).toBe(4);
      expect(stats.c2Signatures).toBe(2);
      expect(stats.lastRefresh).toBe(2000);
    });
  });

  describe("CSV parser edge cases", () => {
    it("should infer C2 from known tool names in provider field", async () => {
      const { refreshFeed } = await import("./lib/jarm-community-feeds");

      const csvContent = `Name,Hash,Category
Cobalt Strike 4.5,07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1,malware
Sliver C2,07d14d16d21d21d00042d41d00041de5fb3038b65b1e7bf1c56d236e6d8a96,tool
PoshC2 Framework,29d29d15d29d29d21c29d29d29d29de9f58a1aa7c1378650c4736a2e8e3e04,unknown`;

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(csvContent),
      });

      const insertedValues: any[] = [];
      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
        insert: vi.fn().mockReturnThis(),
        values: vi.fn().mockImplementation((v: any) => {
          insertedValues.push(v);
          return Promise.resolve(undefined);
        }),
        update: vi.fn().mockReturnValue({
          set: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue(undefined),
          }),
        }),
      };

      const mockSchema = {
        jarmCommunitySignatures: { signatureId: "signatureId" },
        jarmFeedSources: { feedId: "feedId", totalSignatures: "totalSignatures" },
      };

      const feed = {
        id: 1,
        feedId: "test-c2-infer",
        name: "Test C2 Inference",
        feedType: "github_csv" as const,
        url: "https://example.com/c2.csv",
        description: null,
        enabled: true,
        autoRefresh: true,
        refreshIntervalHours: 24,
        lastRefreshAt: null,
        lastRefreshStatus: null,
        lastRefreshError: null,
        totalSignatures: 0,
        lastSignatureCount: null,
      };

      const result = await refreshFeed(mockDb, mockSchema, feed);

      expect(result.success).toBe(true);
      expect(result.signaturesTotal).toBe(3);

      // All three should be classified as C2 based on name inference
      const c2Values = insertedValues.filter((v) => v.matchType === "c2");
      expect(c2Values.length).toBe(3);

      globalThis.fetch = originalFetch;
    });

    it("should handle empty CSV gracefully", async () => {
      const { refreshFeed } = await import("./lib/jarm-community-feeds");

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve("Header1,Header2\n"),
      });

      const mockDb = {
        update: vi.fn().mockReturnValue({
          set: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue(undefined),
          }),
        }),
      };

      const mockSchema = {
        jarmFeedSources: { feedId: "feedId" },
      };

      const feed = {
        id: 1,
        feedId: "test-empty",
        name: "Empty Feed",
        feedType: "github_csv" as const,
        url: "https://example.com/empty.csv",
        description: null,
        enabled: true,
        autoRefresh: true,
        refreshIntervalHours: 24,
        lastRefreshAt: null,
        lastRefreshStatus: null,
        lastRefreshError: null,
        totalSignatures: 0,
        lastSignatureCount: null,
      };

      const result = await refreshFeed(mockDb, mockSchema, feed);

      expect(result.success).toBe(false);
      expect(result.error).toContain("No valid signatures");

      globalThis.fetch = originalFetch;
    });

    it("should handle JSON object format (key-value pairs)", async () => {
      const { refreshFeed } = await import("./lib/jarm-community-feeds");

      const jsonContent = JSON.stringify({
        "27d40d40d29d40d1dc42d43d00041d4689ee210f1f09e32bdd9c2e77eb5ba4": "Cloudflare",
        "29d29d15d29d29d21c29d29d29d29de9f58a1aa7c1378650c4736a2e8e3e04": "nginx",
      });

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(jsonContent),
      });

      const mockDb = {
        select: vi.fn().mockReturnThis(),
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
        insert: vi.fn().mockReturnThis(),
        values: vi.fn().mockResolvedValue(undefined),
        update: vi.fn().mockReturnValue({
          set: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue(undefined),
          }),
        }),
      };

      const mockSchema = {
        jarmCommunitySignatures: { signatureId: "signatureId" },
        jarmFeedSources: { feedId: "feedId", totalSignatures: "totalSignatures" },
      };

      const feed = {
        id: 1,
        feedId: "test-kv",
        name: "Test KV Feed",
        feedType: "github_json" as const,
        url: "https://example.com/kv.json",
        description: null,
        enabled: true,
        autoRefresh: true,
        refreshIntervalHours: 24,
        lastRefreshAt: null,
        lastRefreshStatus: null,
        lastRefreshError: null,
        totalSignatures: 0,
        lastSignatureCount: null,
      };

      const result = await refreshFeed(mockDb, mockSchema, feed);

      expect(result.success).toBe(true);
      expect(result.signaturesTotal).toBe(2);

      globalThis.fetch = originalFetch;
    });
  });
});
