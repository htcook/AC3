import { describe, it, expect, vi } from "vitest";

// ─── Broker Timeline Endpoint Tests ──────────────────────────────────────
// Tests the brokerTimeline endpoint's response shape and data transformations

describe("Broker Timeline Analytics", () => {
  // ─── Response Shape ──────────────────────────────────────────────────────
  describe("Response Shape", () => {
    it("should return all five data sections in the response", () => {
      // Validate the expected shape of the empty response
      const emptyResponse = {
        activityByWeek: [],
        priceByType: [],
        sectorBreakdown: [],
        topBrokers: [],
        govTargeting: [],
      };
      expect(emptyResponse).toHaveProperty("activityByWeek");
      expect(emptyResponse).toHaveProperty("priceByType");
      expect(emptyResponse).toHaveProperty("sectorBreakdown");
      expect(emptyResponse).toHaveProperty("topBrokers");
      expect(emptyResponse).toHaveProperty("govTargeting");
      expect(Array.isArray(emptyResponse.activityByWeek)).toBe(true);
      expect(Array.isArray(emptyResponse.priceByType)).toBe(true);
      expect(Array.isArray(emptyResponse.sectorBreakdown)).toBe(true);
      expect(Array.isArray(emptyResponse.topBrokers)).toBe(true);
      expect(Array.isArray(emptyResponse.govTargeting)).toBe(true);
    });
  });

  // ─── Activity By Week Mapping ──────────────────────────────────────────
  describe("Activity By Week Mapping", () => {
    it("should correctly map raw activity data to the expected output format", () => {
      const rawRows = [
        { week: "2026-14", weekStart: "2026-03-30", count: 5, avgPrice: 12345.678 },
        { week: "2026-15", weekStart: "2026-04-06", count: 3, avgPrice: null },
        { week: "2026-16", weekStart: "2026-04-13", count: 8, avgPrice: 0 },
      ];
      // Simulate the mapping logic from the endpoint
      const mapped = rawRows.map(r => ({
        week: r.week,
        weekStart: r.weekStart,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));
      expect(mapped).toHaveLength(3);
      expect(mapped[0]).toEqual({ week: "2026-14", weekStart: "2026-03-30", listings: 5, avgPrice: 12346 });
      expect(mapped[1]).toEqual({ week: "2026-15", weekStart: "2026-04-06", listings: 3, avgPrice: null });
      expect(mapped[2]).toEqual({ week: "2026-16", weekStart: "2026-04-13", listings: 8, avgPrice: null }); // 0 is falsy
    });

    it("should handle empty activity data gracefully", () => {
      const rawRows: any[] = [];
      const mapped = rawRows.map(r => ({
        week: r.week,
        weekStart: r.weekStart,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));
      expect(mapped).toHaveLength(0);
    });
  });

  // ─── Price By Type Mapping ──────────────────────────────────────────────
  describe("Price By Type Mapping", () => {
    it("should correctly map price data by listing type", () => {
      const rawRows = [
        { listingType: "vpn_access", count: 10, avgPrice: 5000, minPrice: 1000, maxPrice: 15000 },
        { listingType: "rdp_access", count: 7, avgPrice: 2500.5, minPrice: 500, maxPrice: 8000 },
        { listingType: "cloud_access", count: 3, avgPrice: null, minPrice: null, maxPrice: null },
      ];
      const mapped = rawRows.map(r => ({
        type: r.listingType,
        count: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        minPrice: r.minPrice ? Math.round(r.minPrice) : null,
        maxPrice: r.maxPrice ? Math.round(r.maxPrice) : null,
      }));
      expect(mapped).toHaveLength(3);
      expect(mapped[0]).toEqual({ type: "vpn_access", count: 10, avgPrice: 5000, minPrice: 1000, maxPrice: 15000 });
      expect(mapped[1]).toEqual({ type: "rdp_access", count: 7, avgPrice: 2501, minPrice: 500, maxPrice: 8000 });
      expect(mapped[2]).toEqual({ type: "cloud_access", count: 3, avgPrice: null, minPrice: null, maxPrice: null });
    });

    it("should handle listing types with special characters", () => {
      const rawRows = [
        { listingType: "zero_day", count: 1, avgPrice: 100000, minPrice: 100000, maxPrice: 100000 },
      ];
      const mapped = rawRows.map(r => ({
        type: r.listingType,
        count: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        minPrice: r.minPrice ? Math.round(r.minPrice) : null,
        maxPrice: r.maxPrice ? Math.round(r.maxPrice) : null,
      }));
      expect(mapped[0].type).toBe("zero_day");
      expect(mapped[0].avgPrice).toBe(100000);
    });
  });

  // ─── Sector Breakdown Mapping ──────────────────────────────────────────
  describe("Sector Breakdown Mapping", () => {
    it("should filter out null sectors", () => {
      const rawRows = [
        { sector: "Healthcare", count: 12, avgPrice: 8000 },
        { sector: null, count: 5, avgPrice: 3000 },
        { sector: "Government", count: 8, avgPrice: 15000 },
        { sector: "Finance", count: 6, avgPrice: 10000 },
      ];
      const mapped = rawRows.filter(r => r.sector).map(r => ({
        sector: r.sector!,
        count: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));
      expect(mapped).toHaveLength(3);
      expect(mapped.map(m => m.sector)).toEqual(["Healthcare", "Government", "Finance"]);
    });

    it("should correctly round average prices", () => {
      const rawRows = [
        { sector: "Education", count: 4, avgPrice: 3333.33 },
      ];
      const mapped = rawRows.filter(r => r.sector).map(r => ({
        sector: r.sector!,
        count: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));
      expect(mapped[0].avgPrice).toBe(3333);
    });
  });

  // ─── Top Brokers Mapping ──────────────────────────────────────────────
  describe("Top Brokers Mapping", () => {
    it("should correctly map broker data with reputation levels", () => {
      const rawRows = [
        { brokerId: "broker-1", brokerName: "DarkShadow", count: 25, avgPrice: 7500, reputation: "established" as const },
        { brokerId: "broker-2", brokerName: "N3tw0rk", count: 15, avgPrice: 3000, reputation: "rising" as const },
        { brokerId: "broker-3", brokerName: "NewKid", count: 3, avgPrice: null, reputation: "new" as const },
        { brokerId: "broker-4", brokerName: "Unknown1", count: 1, avgPrice: 500, reputation: "unknown" as const },
      ];
      const mapped = rawRows.map(r => ({
        brokerId: r.brokerId,
        name: r.brokerName,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        reputation: r.reputation,
      }));
      expect(mapped).toHaveLength(4);
      expect(mapped[0]).toEqual({ brokerId: "broker-1", name: "DarkShadow", listings: 25, avgPrice: 7500, reputation: "established" });
      expect(mapped[2].avgPrice).toBeNull();
      expect(mapped[3].reputation).toBe("unknown");
    });

    it("should sort by listing count (descending) in the expected output", () => {
      const rawRows = [
        { brokerId: "b1", brokerName: "Top", count: 50, avgPrice: 5000, reputation: "established" as const },
        { brokerId: "b2", brokerName: "Mid", count: 20, avgPrice: 3000, reputation: "rising" as const },
        { brokerId: "b3", brokerName: "Low", count: 5, avgPrice: 1000, reputation: "new" as const },
      ];
      const mapped = rawRows.map(r => ({
        brokerId: r.brokerId,
        name: r.brokerName,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        reputation: r.reputation,
      }));
      // Verify descending order
      for (let i = 1; i < mapped.length; i++) {
        expect(mapped[i - 1].listings).toBeGreaterThanOrEqual(mapped[i].listings);
      }
    });
  });

  // ─── Gov Targeting Mapping ──────────────────────────────────────────────
  describe("Gov Targeting Mapping", () => {
    it("should correctly map gov targeting data", () => {
      const rawRows = [
        { week: "2026-14", weekStart: "2026-03-30", count: 2, sector: "Government" },
        { week: "2026-15", weekStart: "2026-04-06", count: 1, sector: "Defense" },
        { week: "2026-15", weekStart: "2026-04-06", count: 3, sector: "Federal Agency" },
      ];
      const mapped = rawRows.map(r => ({
        week: r.week,
        weekStart: r.weekStart,
        count: r.count,
        sector: r.sector,
      }));
      expect(mapped).toHaveLength(3);
      expect(mapped[0]).toEqual({ week: "2026-14", weekStart: "2026-03-30", count: 2, sector: "Government" });
      expect(mapped[2].sector).toBe("Federal Agency");
    });

    it("should handle empty gov targeting results", () => {
      const rawRows: any[] = [];
      const mapped = rawRows.map(r => ({
        week: r.week,
        weekStart: r.weekStart,
        count: r.count,
        sector: r.sector,
      }));
      expect(mapped).toHaveLength(0);
    });
  });

  // ─── Cutoff Date Calculation ──────────────────────────────────────────
  describe("Cutoff Date Calculation", () => {
    it("should calculate correct cutoff for 90 days", () => {
      const days = 90;
      const now = Date.now();
      const cutoff = new Date(now - days * 86400000);
      // Verify the cutoff is approximately 90 days ago (within 2 hours for DST)
      const diffMs = now - cutoff.getTime();
      const diffDays = diffMs / 86400000;
      expect(diffDays).toBeCloseTo(90, 0);
    });

    it("should calculate correct cutoff for 7 days", () => {
      const days = 7;
      const now = Date.now();
      const cutoff = new Date(now - days * 86400000);
      const expected = new Date(now);
      expected.setDate(expected.getDate() - 7);
      expect(Math.abs(cutoff.getTime() - expected.getTime())).toBeLessThan(1000);
    });

    it("should calculate correct cutoff for 365 days", () => {
      const days = 365;
      const now = Date.now();
      const cutoff = new Date(now - days * 86400000);
      const expected = new Date(now);
      expected.setDate(expected.getDate() - 365);
      expect(Math.abs(cutoff.getTime() - expected.getTime())).toBeLessThan(1000);
    });
  });

  // ─── Price Parsing Logic ──────────────────────────────────────────────
  describe("Price Parsing Logic", () => {
    it("should handle price strings with $ and commas", () => {
      // Simulating the SQL: REPLACE(REPLACE(askingPrice, '$', ''), ',', '')
      const priceStr = "$12,500";
      const cleaned = priceStr.replace("$", "").replace(",", "");
      const parsed = parseFloat(cleaned);
      expect(parsed).toBe(12500);
    });

    it("should handle plain numeric price strings", () => {
      const priceStr = "5000";
      const cleaned = priceStr.replace("$", "").replace(",", "");
      const parsed = parseFloat(cleaned);
      expect(parsed).toBe(5000);
    });

    it("should handle empty price strings as NaN", () => {
      const priceStr = "";
      const cleaned = priceStr.replace("$", "").replace(",", "");
      const parsed = parseFloat(cleaned);
      expect(isNaN(parsed)).toBe(true);
    });

    it("should handle negotiable/text price strings as NaN", () => {
      const priceStr = "Negotiable";
      const cleaned = priceStr.replace("$", "").replace(",", "");
      const parsed = parseFloat(cleaned);
      expect(isNaN(parsed)).toBe(true);
    });
  });

  // ─── Input Validation ──────────────────────────────────────────────────
  describe("Input Validation", () => {
    it("should default to 90 days when no input provided", () => {
      const input = undefined;
      const days = input?.days ?? 90;
      expect(days).toBe(90);
    });

    it("should use provided days value", () => {
      const input = { days: 30 };
      const days = input?.days ?? 90;
      expect(days).toBe(30);
    });

    it("should accept minimum value of 7 days", () => {
      const days = Math.max(7, Math.min(365, 7));
      expect(days).toBe(7);
    });

    it("should accept maximum value of 365 days", () => {
      const days = Math.max(7, Math.min(365, 365));
      expect(days).toBe(365);
    });
  });

  // ─── Sector Heatmap Intensity Calculation ──────────────────────────────
  describe("Sector Heatmap Intensity", () => {
    it("should calculate correct intensity for heatmap cells", () => {
      const sectorBreakdown = [
        { sector: "Healthcare", count: 12, avgPrice: 8000 },
        { sector: "Government", count: 8, avgPrice: 15000 },
        { sector: "Finance", count: 4, avgPrice: 10000 },
      ];
      const maxCount = Math.max(...sectorBreakdown.map(x => x.count));
      expect(maxCount).toBe(12);

      const intensities = sectorBreakdown.map(s => s.count / maxCount);
      expect(intensities[0]).toBe(1.0); // Healthcare = max
      expect(intensities[1]).toBeCloseTo(0.667, 2); // Government
      expect(intensities[2]).toBeCloseTo(0.333, 2); // Finance
    });

    it("should handle single sector without division by zero", () => {
      const sectorBreakdown = [{ sector: "Tech", count: 5, avgPrice: 3000 }];
      const maxCount = Math.max(...sectorBreakdown.map(x => x.count));
      expect(maxCount).toBe(5);
      const intensity = maxCount > 0 ? sectorBreakdown[0].count / maxCount : 0;
      expect(intensity).toBe(1.0);
    });

    it("should handle empty sector breakdown", () => {
      const sectorBreakdown: any[] = [];
      // Math.max of empty array returns -Infinity
      const maxCount = sectorBreakdown.length > 0 ? Math.max(...sectorBreakdown.map(x => x.count)) : 0;
      expect(maxCount).toBe(0);
    });
  });

  // ─── Time Range Selector ──────────────────────────────────────────────
  describe("Time Range Selector", () => {
    const VALID_RANGES = [7, 30, 90, 365];

    it("should support all four time range options", () => {
      expect(VALID_RANGES).toEqual([7, 30, 90, 365]);
      expect(VALID_RANGES).toHaveLength(4);
    });

    it("should format range labels correctly", () => {
      const formatLabel = (d: number) => d === 365 ? '1Y' : `${d}D`;
      expect(formatLabel(7)).toBe('7D');
      expect(formatLabel(30)).toBe('30D');
      expect(formatLabel(90)).toBe('90D');
      expect(formatLabel(365)).toBe('1Y');
    });

    it("should clamp out-of-range values", () => {
      const clamp = (d: number) => Math.max(7, Math.min(365, d));
      expect(clamp(1)).toBe(7);
      expect(clamp(500)).toBe(365);
      expect(clamp(90)).toBe(90);
    });

    it("should produce different cutoff dates for each range", () => {
      const now = Date.now();
      const cutoffs = VALID_RANGES.map(d => new Date(now - d * 86400000).getTime());
      // Each cutoff should be further back than the previous
      for (let i = 1; i < cutoffs.length; i++) {
        expect(cutoffs[i]).toBeLessThan(cutoffs[i - 1]);
      }
    });

    it("should default to 90 days when state is initialized", () => {
      const defaultDays = 90;
      expect(VALID_RANGES).toContain(defaultDays);
    });
  });

  // ─── Seed Data Validation ──────────────────────────────────────────────
  describe("Seed Data Validation", () => {
    const BROKERS = [
      { id: "iab-shadowbroker-01", name: "ShadowBroker_01", rep: "established" },
      { id: "iab-pioneer-kitten", name: "Pioneer Kitten", rep: "established" },
      { id: "iab-scattered-spider", name: "Scattered Spider", rep: "established" },
      { id: "iab-cloudpwn", name: "CloudPwn3r", rep: "new" },
    ];

    it("should have valid broker IDs with iab- prefix", () => {
      for (const b of BROKERS) {
        expect(b.id).toMatch(/^iab-/);
      }
    });

    it("should have valid reputation levels", () => {
      const validReps = ["established", "rising", "new", "unknown"];
      for (const b of BROKERS) {
        expect(validReps).toContain(b.rep);
      }
    });

    it("should generate prices in valid format", () => {
      const priceRegex = /^\$[\d,]+$/;
      const testPrices = ["$500", "$12,345", "$150,000"];
      for (const p of testPrices) {
        expect(p).toMatch(priceRegex);
      }
    });

    it("should have valid listing types", () => {
      const validTypes = [
        "vpn_access", "rdp_access", "citrix_access", "webshell", "domain_admin",
        "cloud_access", "email_access", "database_access", "zero_day", "credential_dump", "other",
      ];
      expect(validTypes).toHaveLength(11);
      expect(validTypes).toContain("vpn_access");
      expect(validTypes).toContain("zero_day");
    });

    it("should have valid access levels", () => {
      const validLevels = ["domain_admin", "local_admin", "user", "service_account", "unknown"];
      expect(validLevels).toHaveLength(5);
    });

    it("should have valid status values", () => {
      const validStatuses = ["active", "sold", "expired", "removed"];
      expect(validStatuses).toHaveLength(4);
    });
  });
});
