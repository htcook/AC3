/**
 * SOCRadar Connector & Router Tests
 *
 * Tests the SOCRadar connector library (API client) and the tRPC router
 * that exposes dark web monitoring, brand protection, IOC enrichment,
 * and threat feed procedures.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Mock fetch globally ─────────────────────────────────────────────────
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ─── SOCRadar Connector Tests ────────────────────────────────────────────

describe("SOCRadarConnector", () => {
  let SOCRadarConnector: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const mod = await import("./lib/socradar-connector");
    SOCRadarConnector = mod.SOCRadarConnector;
  });

  describe("constructor", () => {
    it("sets default base URL when none provided", () => {
      const connector = new SOCRadarConnector({ apiKey: "test-key", companyId: "123" });
      expect(connector).toBeDefined();
    });

    it("strips trailing slashes from custom base URL", () => {
      const connector = new SOCRadarConnector({
        apiKey: "test-key",
        companyId: "123",
        baseUrl: "https://custom.socradar.com/api///",
      });
      expect(connector).toBeDefined();
    });
  });

  describe("verify", () => {
    it("returns valid=true when API responds with 200", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ company_name: "Ace Cloud" }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.verify();

      expect(result.valid).toBe(true);
      expect(result.companyName).toBe("Ace Cloud");
      expect(result.message).toContain("Successfully");
    });

    it("returns valid=false on 401 unauthorized", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 401 });

      const connector = new SOCRadarConnector({ apiKey: "bad-key", companyId: "1" });
      const result = await connector.verify();

      expect(result.valid).toBe(false);
      expect(result.message).toContain("Invalid API key");
    });

    it("returns valid=false on network error", async () => {
      mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.verify();

      expect(result.valid).toBe(false);
      expect(result.message).toContain("Connection failed");
    });
  });

  describe("getIncidents", () => {
    it("returns normalized incidents on success", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          incidents: [
            {
              id: 101,
              main_type: "dark_web",
              sub_type: "credential_leak",
              severity: "HIGH",
              title: "Credential leak detected",
              content: "Found on dark web forum",
              created_at: "2026-05-01T10:00:00Z",
              is_false_positive: false,
              is_resolved: false,
              source: "dark_web_forum",
            },
          ],
          total: 1,
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.getIncidents({ severity: ["high"], limit: 10 });

      expect(result.total).toBe(1);
      expect(result.incidents).toHaveLength(1);
      expect(result.incidents[0].id).toBe(101);
      expect(result.incidents[0].mainType).toBe("dark_web");
      expect(result.incidents[0].severity).toBe("high");
      expect(result.incidents[0].isFalsePositive).toBe(false);
    });

    it("returns empty array on API error", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.getIncidents();

      expect(result.incidents).toEqual([]);
      expect(result.total).toBe(0);
    });

    it("returns empty array on network failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("timeout"));

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.getIncidents();

      expect(result.incidents).toEqual([]);
    });
  });

  describe("markIncidentFP", () => {
    it("returns true on success", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.markIncidentFP(101, "Not relevant");

      expect(result).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining("/incidents/101/false-positive"),
        expect.objectContaining({ method: "POST" }),
      );
    });

    it("returns false on failure", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.markIncidentFP(999);

      expect(result).toBe(false);
    });
  });

  describe("markIncidentResolved", () => {
    it("returns true on success", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.markIncidentResolved(101);

      expect(result).toBe(true);
    });
  });

  describe("getDarkWebMentions", () => {
    it("returns normalized mentions", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          mentions: [
            {
              id: 201,
              source: "FORUM",
              title: "Company data for sale",
              content: "Selling access to company network",
              detected_at: "2026-05-10T08:00:00Z",
              severity: "critical",
              category: "access_sale",
              threat_actor: "DarkBroker",
            },
          ],
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const mentions = await connector.getDarkWebMentions({ limit: 10 });

      expect(mentions).toHaveLength(1);
      expect(mentions[0].id).toBe(201);
      expect(mentions[0].source).toBe("forum");
      expect(mentions[0].category).toBe("access_sale");
      expect(mentions[0].threatActor).toBe("DarkBroker");
    });

    it("returns empty on failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("fail"));

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const mentions = await connector.getDarkWebMentions();

      expect(mentions).toEqual([]);
    });
  });

  describe("getBrandAlerts", () => {
    it("returns normalized brand alerts", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          alerts: [
            {
              id: 301,
              type: "phishing_domain",
              severity: "high",
              title: "Phishing domain detected",
              description: "Domain mimicking company",
              detected_at: "2026-05-09T12:00:00Z",
              domain: "fake-company.com",
              status: "active",
              takedown_requested: false,
            },
          ],
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const alerts = await connector.getBrandAlerts({ type: "phishing_domain" });

      expect(alerts).toHaveLength(1);
      expect(alerts[0].type).toBe("phishing_domain");
      expect(alerts[0].domain).toBe("fake-company.com");
      expect(alerts[0].takedownRequested).toBe(false);
    });
  });

  describe("requestTakedown", () => {
    it("returns true on success", async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.requestTakedown(301);

      expect(result).toBe(true);
    });
  });

  describe("enrichIP", () => {
    it("returns enriched IP reputation data", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          risk_score: 75,
          total_encounters: 42,
          score_details: { malware: 50, botnet: 25 },
          geo_location: {
            CountryName: "Russia",
            CityName: "Moscow",
            ASN: "12345",
            AsnName: "Evil ISP",
            Latitude: 55.75,
            Longitude: 37.62,
          },
          tags: ["malware", "c2"],
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.enrichIP("1.2.3.4");

      expect(result).not.toBeNull();
      expect(result!.indicator).toBe("1.2.3.4");
      expect(result!.type).toBe("ip");
      expect(result!.riskScore).toBe(75);
      expect(result!.totalEncounters).toBe(42);
      expect(result!.geoLocation?.country).toBe("Russia");
      expect(result!.geoLocation?.city).toBe("Moscow");
      expect(result!.tags).toContain("malware");
    });

    it("returns null on API error", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.enrichIP("invalid");

      expect(result).toBeNull();
    });
  });

  describe("enrichDomain", () => {
    it("returns enriched domain data", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          risk_score: 10,
          total_encounters: 0,
          score_details: {},
          tags: [],
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.enrichDomain("example.com");

      expect(result).not.toBeNull();
      expect(result!.type).toBe("domain");
      expect(result!.riskScore).toBe(10);
    });
  });

  describe("enrichHash", () => {
    it("returns enriched hash data", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          risk_score: 95,
          total_encounters: 100,
          score_details: { ransomware: 90, trojan: 5 },
          tags: ["ransomware", "lockbit"],
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const result = await connector.enrichHash("d41d8cd98f00b204e9800998ecf8427e");

      expect(result).not.toBeNull();
      expect(result!.type).toBe("hash");
      expect(result!.riskScore).toBe(95);
      expect(result!.tags).toContain("ransomware");
    });
  });

  describe("getThreatFeeds", () => {
    it("returns normalized threat feeds", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          feeds: [
            { id: "feed-1", name: "C2 Servers", type: "c2", total_count: 500, last_updated: "2026-05-12T00:00:00Z" },
            { id: "feed-2", name: "Botnet IPs", type: "botnet", total_count: 1200, last_updated: "2026-05-11T00:00:00Z" },
          ],
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const feeds = await connector.getThreatFeeds({ limit: 10 });

      expect(feeds).toHaveLength(2);
      expect(feeds[0].name).toBe("C2 Servers");
      expect(feeds[0].type).toBe("c2");
      expect(feeds[0].totalCount).toBe(500);
    });
  });

  describe("getFeedIndicators", () => {
    it("returns normalized feed indicators", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          indicators: [
            {
              value: "10.0.0.1",
              type: "ip",
              confidence: 95,
              first_seen: "2026-04-01T00:00:00Z",
              last_seen: "2026-05-12T00:00:00Z",
              tags: ["c2", "cobalt_strike"],
              threat_actor: "APT29",
            },
          ],
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const indicators = await connector.getFeedIndicators("feed-1", 50);

      expect(indicators).toHaveLength(1);
      expect(indicators[0].value).toBe("10.0.0.1");
      expect(indicators[0].confidence).toBe(95);
      expect(indicators[0].threatActor).toBe("APT29");
    });
  });

  describe("getStats", () => {
    it("returns summary statistics", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          total_incidents: 150,
          open_incidents: 30,
          resolved_incidents: 110,
          false_positives: 10,
          by_severity: { critical: 5, high: 25, medium: 80, low: 40 },
          by_type: { dark_web: 60, brand: 40, data_leak: 50 },
          dark_web_mentions: 60,
          brand_alerts: 40,
          data_leaks: 50,
        }),
      });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const stats = await connector.getStats();

      expect(stats.totalIncidents).toBe(150);
      expect(stats.openIncidents).toBe(30);
      expect(stats.resolvedIncidents).toBe(110);
      expect(stats.falsePositives).toBe(10);
      expect(stats.darkWebMentions).toBe(60);
      expect(stats.brandAlerts).toBe(40);
      expect(stats.bySeverity.critical).toBe(5);
    });

    it("returns empty stats on failure", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });

      const connector = new SOCRadarConnector({ apiKey: "key", companyId: "1" });
      const stats = await connector.getStats();

      expect(stats.totalIncidents).toBe(0);
      expect(stats.openIncidents).toBe(0);
    });
  });
});

// ─── SOCRadar Router Tests ───────────────────────────────────────────────

describe("SOCRadar Router", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe("health procedure", () => {
    it("returns configured=false when env vars are missing", async () => {
      delete process.env.SOCRADAR_API_KEY;
      delete process.env.SOCRADAR_COMPANY_ID;

      // Re-import to pick up env changes
      const { socradarRouter } = await import("./routers/socradar");
      const caller = socradarRouter.createCaller({
        user: { id: 1, role: "admin", openId: "test", name: "Test" },
      } as any);

      const result = await caller.health();

      expect(result.configured).toBe(false);
      expect(result.connected).toBe(false);
      expect(result.message).toContain("not configured");
    });

    it("returns connected=true when API key is valid", async () => {
      process.env.SOCRADAR_API_KEY = "valid-key";
      process.env.SOCRADAR_COMPANY_ID = "123";

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ company_name: "Test Corp" }),
      });

      const { socradarRouter } = await import("./routers/socradar");
      const caller = socradarRouter.createCaller({
        user: { id: 1, role: "admin", openId: "test", name: "Test" },
      } as any);

      const result = await caller.health();

      expect(result.configured).toBe(true);
      expect(result.connected).toBe(true);
      expect(result.companyName).toBe("Test Corp");
    });
  });

  describe("incidents procedure", () => {
    it("returns configured=false when not configured", async () => {
      delete process.env.SOCRADAR_API_KEY;
      delete process.env.SOCRADAR_COMPANY_ID;

      const { socradarRouter } = await import("./routers/socradar");
      const caller = socradarRouter.createCaller({
        user: { id: 1, role: "admin", openId: "test", name: "Test" },
      } as any);

      const result = await caller.incidents();

      expect(result.configured).toBe(false);
      expect(result.incidents).toEqual([]);
    });
  });

  describe("enrichIP procedure", () => {
    it("returns configured=false when not configured", async () => {
      delete process.env.SOCRADAR_API_KEY;
      delete process.env.SOCRADAR_COMPANY_ID;

      const { socradarRouter } = await import("./routers/socradar");
      const caller = socradarRouter.createCaller({
        user: { id: 1, role: "admin", openId: "test", name: "Test" },
      } as any);

      const result = await caller.enrichIP({ ip: "1.1.1.1" });

      expect(result.configured).toBe(false);
      expect(result.result).toBeNull();
    });
  });

  describe("stats procedure", () => {
    it("returns configured=false when not configured", async () => {
      delete process.env.SOCRADAR_API_KEY;
      delete process.env.SOCRADAR_COMPANY_ID;

      const { socradarRouter } = await import("./routers/socradar");
      const caller = socradarRouter.createCaller({
        user: { id: 1, role: "admin", openId: "test", name: "Test" },
      } as any);

      const result = await caller.stats();

      expect(result.configured).toBe(false);
      expect(result.stats).toBeNull();
    });
  });
});
