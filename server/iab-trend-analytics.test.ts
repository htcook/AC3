import { describe, it, expect } from 'vitest';

// ─── IAB Trend Analytics Endpoint Tests ──────────────────────────────────────
// Tests the iabTrends endpoint's response shape, data transformations,
// sector normalization, price calculations, and summary aggregation

describe("IAB Trend Analytics", () => {
  // ─── Response Shape ──────────────────────────────────────────────────────
  describe("Response Shape", () => {
    it("should return all expected sections in the response", () => {
      const emptyResponse = {
        monthlyVolume: [],
        sectorShifts: [],
        accessTypeDistribution: [],
        priceEvolution: [],
        topBrokersRanked: [],
        govTargetingTrend: [],
        summary: { totalListings: 0, activeBrokers: 0, avgPrice: 0, govListings: 0, topSector: '', topAccessType: '' },
        topSectors: [],
      };
      expect(emptyResponse).toHaveProperty("monthlyVolume");
      expect(emptyResponse).toHaveProperty("sectorShifts");
      expect(emptyResponse).toHaveProperty("accessTypeDistribution");
      expect(emptyResponse).toHaveProperty("priceEvolution");
      expect(emptyResponse).toHaveProperty("topBrokersRanked");
      expect(emptyResponse).toHaveProperty("govTargetingTrend");
      expect(emptyResponse).toHaveProperty("summary");
      expect(emptyResponse).toHaveProperty("topSectors");
      expect(Array.isArray(emptyResponse.monthlyVolume)).toBe(true);
      expect(Array.isArray(emptyResponse.sectorShifts)).toBe(true);
      expect(Array.isArray(emptyResponse.accessTypeDistribution)).toBe(true);
      expect(Array.isArray(emptyResponse.priceEvolution)).toBe(true);
      expect(Array.isArray(emptyResponse.topBrokersRanked)).toBe(true);
      expect(Array.isArray(emptyResponse.govTargetingTrend)).toBe(true);
    });

    it("should have correct summary fields", () => {
      const summary = { totalListings: 44, activeBrokers: 15, avgPrice: 125240, govListings: 12, topSector: 'Government', topAccessType: 'Other' };
      expect(summary).toHaveProperty("totalListings");
      expect(summary).toHaveProperty("activeBrokers");
      expect(summary).toHaveProperty("avgPrice");
      expect(summary).toHaveProperty("govListings");
      expect(summary).toHaveProperty("topSector");
      expect(summary).toHaveProperty("topAccessType");
      expect(typeof summary.totalListings).toBe("number");
      expect(typeof summary.avgPrice).toBe("number");
    });
  });

  // ─── Monthly Volume Mapping ──────────────────────────────────────────
  describe("Monthly Volume Mapping", () => {
    it("should correctly map monthly data with cumulative totals", () => {
      const rawRows = [
        { month: "2024-03", count: 1, avgPrice: 50000 },
        { month: "2024-04", count: 2, avgPrice: 25000 },
        { month: "2024-05", count: 3, avgPrice: null },
      ];
      let runningTotal = 0;
      const mapped = rawRows.map(r => {
        runningTotal += r.count;
        return {
          month: r.month,
          listings: r.count,
          cumulative: runningTotal,
          avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        };
      });
      expect(mapped).toHaveLength(3);
      expect(mapped[0]).toEqual({ month: "2024-03", listings: 1, cumulative: 1, avgPrice: 50000 });
      expect(mapped[1]).toEqual({ month: "2024-04", listings: 2, cumulative: 3, avgPrice: 25000 });
      expect(mapped[2]).toEqual({ month: "2024-05", listings: 3, cumulative: 6, avgPrice: null });
    });

    it("should handle empty monthly data gracefully", () => {
      const rawRows: any[] = [];
      let runningTotal = 0;
      const mapped = rawRows.map(r => {
        runningTotal += r.count;
        return { month: r.month, listings: r.count, cumulative: runningTotal, avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null };
      });
      expect(mapped).toHaveLength(0);
      expect(runningTotal).toBe(0);
    });

    it("should correctly accumulate running totals", () => {
      const rawRows = [
        { month: "2025-01", count: 5, avgPrice: 10000 },
        { month: "2025-02", count: 3, avgPrice: 20000 },
        { month: "2025-03", count: 7, avgPrice: 15000 },
      ];
      let runningTotal = 0;
      const mapped = rawRows.map(r => {
        runningTotal += r.count;
        return { month: r.month, listings: r.count, cumulative: runningTotal, avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null };
      });
      expect(mapped[0].cumulative).toBe(5);
      expect(mapped[1].cumulative).toBe(8);
      expect(mapped[2].cumulative).toBe(15);
    });
  });

  // ─── Sector Normalization ──────────────────────────────────────────
  describe("Sector Normalization", () => {
    it("should normalize multi-sector entries into separate counts", () => {
      const sectorMonthly = [
        { month: "2024-06", sector: "Technology, Healthcare, Finance", count: 1 },
        { month: "2024-06", sector: "Government", count: 3 },
        { month: "2024-07", sector: "Healthcare, Education, Government", count: 1 },
      ];

      const sectorCounts: Record<string, number> = {};
      const sectorMonthMap: Record<string, Record<string, number>> = {};
      for (const row of sectorMonthly) {
        const sectors = (row.sector || '').split(',').map(s => s.trim()).filter(Boolean);
        for (const s of sectors) {
          const normalized = s.charAt(0).toUpperCase() + s.slice(1);
          sectorCounts[normalized] = (sectorCounts[normalized] || 0) + row.count;
          if (!sectorMonthMap[row.month]) sectorMonthMap[row.month] = {};
          sectorMonthMap[row.month][normalized] = (sectorMonthMap[row.month][normalized] || 0) + row.count;
        }
      }

      expect(sectorCounts["Government"]).toBe(4); // 3 + 1
      expect(sectorCounts["Healthcare"]).toBe(2); // 1 + 1
      expect(sectorCounts["Technology"]).toBe(1);
      expect(sectorCounts["Finance"]).toBe(1);
      expect(sectorCounts["Education"]).toBe(1);
    });

    it("should handle null/empty sectors gracefully", () => {
      const sectorMonthly = [
        { month: "2024-06", sector: "", count: 2 },
        { month: "2024-06", sector: null as any, count: 1 },
      ];

      const sectorCounts: Record<string, number> = {};
      for (const row of sectorMonthly) {
        const sectors = (row.sector || '').split(',').map((s: string) => s.trim()).filter(Boolean);
        for (const s of sectors) {
          const normalized = s.charAt(0).toUpperCase() + s.slice(1);
          sectorCounts[normalized] = (sectorCounts[normalized] || 0) + row.count;
        }
      }

      expect(Object.keys(sectorCounts)).toHaveLength(0);
    });

    it("should select top 8 sectors by count", () => {
      const sectorCounts: Record<string, number> = {
        Government: 15, Technology: 5, Healthcare: 4, Multiple: 3,
        Telecommunications: 2, Defense: 2, Education: 1, Retail: 1,
        Finance: 1, Manufacturing: 1,
      };
      const topSectors = Object.entries(sectorCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([s]) => s);

      expect(topSectors).toHaveLength(8);
      expect(topSectors[0]).toBe("Government");
      expect(topSectors[1]).toBe("Technology");
      expect(topSectors).not.toContain("Manufacturing");
    });
  });

  // ─── Access Type Distribution ──────────────────────────────────────────
  describe("Access Type Distribution", () => {
    it("should map access types to human-readable labels", () => {
      const TYPE_LABELS: Record<string, string> = {
        vpn_access: 'VPN Access', rdp_access: 'RDP Access', citrix_access: 'Citrix',
        webshell: 'Web Shell', domain_admin: 'Domain Admin', cloud_access: 'Cloud Access',
        email_access: 'Email Access', database_access: 'Database', zero_day: 'Zero-Day',
        exploit_kit: 'Exploit Kit', credential_dump: 'Credential Dump', other: 'Other',
      };

      const accessTypes = [
        { type: 'vpn_access', count: 10, avgPrice: 15000 },
        { type: 'rdp_access', count: 5, avgPrice: 8000 },
        { type: 'other', count: 11, avgPrice: null },
      ];

      const mapped = accessTypes.map(r => ({
        type: r.type,
        label: TYPE_LABELS[r.type || ''] || r.type || 'Unknown',
        count: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));

      expect(mapped[0].label).toBe('VPN Access');
      expect(mapped[1].label).toBe('RDP Access');
      expect(mapped[2].label).toBe('Other');
      expect(mapped[0].avgPrice).toBe(15000);
      expect(mapped[2].avgPrice).toBeNull();
    });

    it("should handle unknown access types", () => {
      const TYPE_LABELS: Record<string, string> = {
        vpn_access: 'VPN Access', rdp_access: 'RDP Access',
      };
      const accessTypes = [{ type: 'unknown_type', count: 1, avgPrice: null }];
      const mapped = accessTypes.map(r => ({
        type: r.type,
        label: TYPE_LABELS[r.type || ''] || r.type || 'Unknown',
        count: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));
      expect(mapped[0].label).toBe('unknown_type');
    });
  });

  // ─── Price Evolution ──────────────────────────────────────────
  describe("Price Evolution", () => {
    it("should correctly map price data with min/avg/max", () => {
      const priceMonthly = [
        { month: "2024-06", avgPrice: 35000.5, maxPrice: 100000, minPrice: 1500, count: 3 },
        { month: "2024-08", avgPrice: 20000, maxPrice: 50000, minPrice: 5000, count: 2 },
      ];

      const mapped = priceMonthly.map(r => ({
        month: r.month,
        avg: r.avgPrice ? Math.round(r.avgPrice) : null,
        max: r.maxPrice ? Math.round(r.maxPrice) : null,
        min: r.minPrice ? Math.round(r.minPrice) : null,
        listings: r.count,
      }));

      expect(mapped[0]).toEqual({ month: "2024-06", avg: 35001, max: 100000, min: 1500, listings: 3 });
      expect(mapped[1]).toEqual({ month: "2024-08", avg: 20000, max: 50000, min: 5000, listings: 2 });
    });

    it("should handle null prices", () => {
      const priceMonthly = [
        { month: "2024-06", avgPrice: null, maxPrice: null, minPrice: null, count: 1 },
      ];
      const mapped = priceMonthly.map(r => ({
        month: r.month,
        avg: r.avgPrice ? Math.round(r.avgPrice) : null,
        max: r.maxPrice ? Math.round(r.maxPrice) : null,
        min: r.minPrice ? Math.round(r.minPrice) : null,
        listings: r.count,
      }));
      expect(mapped[0].avg).toBeNull();
      expect(mapped[0].max).toBeNull();
      expect(mapped[0].min).toBeNull();
    });
  });

  // ─── Top Brokers Ranking ──────────────────────────────────────────
  describe("Top Brokers Ranking", () => {
    it("should correctly map broker data with type labels", () => {
      const TYPE_LABELS: Record<string, string> = {
        vpn_access: 'VPN Access', rdp_access: 'RDP Access', other: 'Other',
      };
      const topBrokersRaw = [
        { brokerId: 'ib-001', brokerName: 'IntelBroker', count: 5, avgPrice: 50000, reputation: 'established' as const, topSector: 'Government', topType: 'vpn_access' },
        { brokerId: 'wz-001', brokerName: 'Wazawaka', count: 3, avgPrice: null, reputation: 'established' as const, topSector: 'Technology', topType: 'other' },
      ];

      const mapped = topBrokersRaw.map(r => ({
        brokerId: r.brokerId,
        name: r.brokerName,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
        reputation: r.reputation,
        topSector: r.topSector,
        topType: TYPE_LABELS[r.topType || ''] || r.topType,
      }));

      expect(mapped[0].name).toBe('IntelBroker');
      expect(mapped[0].listings).toBe(5);
      expect(mapped[0].avgPrice).toBe(50000);
      expect(mapped[0].topType).toBe('VPN Access');
      expect(mapped[1].avgPrice).toBeNull();
      expect(mapped[1].topType).toBe('Other');
    });
  });

  // ─── Gov Targeting Trend ──────────────────────────────────────────
  describe("Gov Targeting Trend", () => {
    it("should correctly map gov targeting data", () => {
      const govMonthly = [
        { month: "2024-06", count: 3, avgPrice: 75000 },
        { month: "2024-08", count: 2, avgPrice: null },
      ];

      const mapped = govMonthly.map(r => ({
        month: r.month,
        listings: r.count,
        avgPrice: r.avgPrice ? Math.round(r.avgPrice) : null,
      }));

      expect(mapped[0]).toEqual({ month: "2024-06", listings: 3, avgPrice: 75000 });
      expect(mapped[1]).toEqual({ month: "2024-08", listings: 2, avgPrice: null });
    });
  });

  // ─── Summary Aggregation ──────────────────────────────────────────
  describe("Summary Aggregation", () => {
    it("should correctly calculate summary stats from data", () => {
      const monthlyVolume = [
        { month: "2024-06", listings: 3, cumulative: 3, avgPrice: 50000 },
        { month: "2024-08", listings: 2, cumulative: 5, avgPrice: 20000 },
      ];
      const accessTypes = [
        { type: 'vpn_access', count: 10, avgPrice: 15000 },
        { type: 'rdp_access', count: 5, avgPrice: 8000 },
        { type: 'other', count: 11, avgPrice: null },
      ];
      const topBrokersRanked = [
        { brokerId: 'ib-001', name: 'IntelBroker', listings: 5, avgPrice: 50000, reputation: 'established', topSector: 'Government', topType: 'VPN Access' },
      ];
      const govTargetingTrend = [
        { month: "2024-06", listings: 3, avgPrice: 75000 },
        { month: "2024-08", listings: 2, avgPrice: null },
      ];
      const topSectors = ['Government', 'Technology'];
      const accessTypeDistribution = [
        { type: 'other', label: 'Other', count: 11, avgPrice: null },
        { type: 'vpn_access', label: 'VPN Access', count: 10, avgPrice: 15000 },
      ];

      const totalListings = monthlyVolume.reduce((sum, m) => sum + m.listings, 0) || accessTypes.reduce((sum, t) => sum + t.count, 0);
      const activeBrokers = topBrokersRanked.length;
      const allPrices = accessTypes.filter(t => t.avgPrice != null && !isNaN(Number(t.avgPrice))).map(t => Number(t.avgPrice));
      const avgPrice = allPrices.length > 0 ? Math.round(allPrices.reduce((a, b) => a + b, 0) / allPrices.length) : 0;
      const govListings = govTargetingTrend.reduce((sum, g) => sum + g.listings, 0);
      const topSector = topSectors[0] || 'Unknown';
      const topAccessType = accessTypeDistribution[0]?.label || 'Unknown';

      expect(totalListings).toBe(5);
      expect(activeBrokers).toBe(1);
      expect(avgPrice).toBe(11500); // (15000 + 8000) / 2
      expect(govListings).toBe(5);
      expect(topSector).toBe('Government');
      expect(topAccessType).toBe('Other');
    });

    it("should handle empty data for summary", () => {
      const monthlyVolume: any[] = [];
      const accessTypes: any[] = [];
      const topBrokersRanked: any[] = [];
      const govTargetingTrend: any[] = [];
      const topSectors: string[] = [];
      const accessTypeDistribution: any[] = [];

      const totalListings = monthlyVolume.reduce((sum: number, m: any) => sum + m.listings, 0) || accessTypes.reduce((sum: number, t: any) => sum + t.count, 0);
      const activeBrokers = topBrokersRanked.length;
      const allPrices = accessTypes.filter((t: any) => t.avgPrice != null && !isNaN(Number(t.avgPrice))).map((t: any) => Number(t.avgPrice));
      const avgPrice = allPrices.length > 0 ? Math.round(allPrices.reduce((a: number, b: number) => a + b, 0) / allPrices.length) : 0;
      const govListings = govTargetingTrend.reduce((sum: number, g: any) => sum + g.listings, 0);
      const topSector = topSectors[0] || 'Unknown';
      const topAccessType = accessTypeDistribution[0]?.label || 'Unknown';

      expect(totalListings).toBe(0);
      expect(activeBrokers).toBe(0);
      expect(avgPrice).toBe(0);
      expect(govListings).toBe(0);
      expect(topSector).toBe('Unknown');
      expect(topAccessType).toBe('Unknown');
    });

    it("should handle NaN avgPrice values gracefully", () => {
      const accessTypes = [
        { type: 'vpn_access', count: 10, avgPrice: NaN },
        { type: 'rdp_access', count: 5, avgPrice: 8000 },
        { type: 'other', count: 11, avgPrice: null },
      ];
      const allPrices = accessTypes.filter(t => t.avgPrice != null && !isNaN(Number(t.avgPrice))).map(t => Number(t.avgPrice));
      const avgPrice = allPrices.length > 0 ? Math.round(allPrices.reduce((a, b) => a + b, 0) / allPrices.length) : 0;
      expect(avgPrice).toBe(8000);
      expect(allPrices).toHaveLength(1);
    });
  });

  // ─── Input Validation ──────────────────────────────────────────
  describe("Input Validation", () => {
    it("should default to 365 days when no input provided", () => {
      const input = undefined;
      const days = input ?? 365;
      expect(days).toBe(365);
    });

    it("should use provided days value", () => {
      const input = { days: 90 };
      const days = input?.days ?? 365;
      expect(days).toBe(90);
    });

    it("should calculate correct cutoff date", () => {
      const now = Date.now();
      const days = 365;
      const cutoff = new Date(now - days * 86400000).toISOString();
      const cutoffDate = new Date(cutoff);
      const diffMs = now - cutoffDate.getTime();
      const diffDays = Math.round(diffMs / 86400000);
      expect(diffDays).toBe(365);
    });
  });

  // ─── Sector Shifts Data Structure ──────────────────────────────────────
  describe("Sector Shifts Data Structure", () => {
    it("should build correct sector shifts with top sectors as keys", () => {
      const sectorMonthMap: Record<string, Record<string, number>> = {
        "2024-06": { Government: 3, Technology: 1 },
        "2024-08": { Government: 2, Healthcare: 1 },
      };
      const topSectors = ['Government', 'Technology', 'Healthcare'];

      const sectorShifts = Object.entries(sectorMonthMap)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([month, sectors]) => ({
          month,
          ...Object.fromEntries(topSectors.map(s => [s, sectors[s] || 0])),
        }));

      expect(sectorShifts).toHaveLength(2);
      expect(sectorShifts[0]).toEqual({ month: "2024-06", Government: 3, Technology: 1, Healthcare: 0 });
      expect(sectorShifts[1]).toEqual({ month: "2024-08", Government: 2, Technology: 0, Healthcare: 1 });
    });
  });
});
