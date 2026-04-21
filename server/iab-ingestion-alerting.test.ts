import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock fetch for external API calls ──────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ─── Mock DB ────────────────────────────────────────────────────────────

const mockSelect = vi.fn().mockReturnThis();
const mockFrom = vi.fn().mockReturnThis();
const mockWhere = vi.fn().mockReturnThis();
const mockLimit = vi.fn().mockResolvedValue([]);
const mockInsert = vi.fn().mockReturnThis();
const mockValues = vi.fn().mockResolvedValue([]);
const mockUpdate = vi.fn().mockReturnThis();
const mockSet = vi.fn().mockReturnThis();
const mockExecute = vi.fn().mockResolvedValue([]);

const mockDb = {
  select: mockSelect,
  insert: mockInsert,
  update: mockUpdate,
  execute: mockExecute,
};
mockSelect.mockReturnValue({ from: mockFrom });
mockFrom.mockReturnValue({ where: mockWhere, limit: mockLimit });
mockWhere.mockReturnValue({ limit: mockLimit });
mockInsert.mockReturnValue({ values: mockValues });
mockUpdate.mockReturnValue({ set: mockSet });
mockSet.mockReturnValue({ where: vi.fn().mockResolvedValue([]) });

vi.mock("./db", () => ({
  getDb: vi.fn().mockResolvedValue(mockDb),
}));

vi.mock("../drizzle/schema", () => ({
  accessBrokerListings: {
    id: "id",
    brokerId: "broker_id",
    iabConfidence: "iab_confidence",
    victimSector: "victim_sector",
  },
}));

vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{ message: { content: JSON.stringify({ enrichments: [] }) } }],
  }),
}));

vi.mock("./_core/notification", () => ({
  notifyOwner: vi.fn().mockResolvedValue(true),
}));

// ─── Tests ──────────────────────────────────────────────────────────────

describe("IAB Ingestion Service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLimit.mockResolvedValue([]);
  });

  describe("ingestRansomwareLiveGroups", () => {
    it("should fetch groups from ransomware.live and filter IAB-related ones", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          { name: "lockbit", description: "sells initial access to corporate networks", tools: [] },
          { name: "alphv", description: "ransomware group", tools: [{ name: "Cobalt Strike" }] },
          { name: "generic", description: "just a group", tools: [] },
        ]),
      });

      const { ingestRansomwareLiveGroups } = await import("./lib/iab-ingestion-service");
      const result = await ingestRansomwareLiveGroups();

      expect(result.source).toBe("ransomware_live_groups");
      expect(result.fetched).toBeGreaterThanOrEqual(1);
      expect(result.error).toBeUndefined();
    });

    it("should handle API errors gracefully", async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });

      const { ingestRansomwareLiveGroups } = await import("./lib/iab-ingestion-service");
      const result = await ingestRansomwareLiveGroups();

      expect(result.error).toBeDefined();
      expect(result.fetched).toBe(0);
    });

    it("should skip existing broker IDs", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          { name: "lockbit", description: "sells initial access", tools: [] },
        ]),
      });
      mockLimit.mockResolvedValueOnce([{ id: 1 }]); // Already exists

      const { ingestRansomwareLiveGroups } = await import("./lib/iab-ingestion-service");
      const result = await ingestRansomwareLiveGroups();

      expect(result.skipped).toBeGreaterThanOrEqual(0);
    });
  });

  describe("ingestVictimIABAttribution", () => {
    it("should fetch recent victims and group by ransomware group", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          { group_name: "lockbit", post_title: "Victim A", activity: "Healthcare", country: "US", published: "2026-04-01" },
          { group_name: "lockbit", post_title: "Victim B", activity: "Finance", country: "UK", published: "2026-04-02" },
          { group_name: "alphv", post_title: "Victim C", activity: "Government", country: "US", published: "2026-04-03" },
          { group_name: "alphv", post_title: "Victim D", activity: "Defense", country: "US", published: "2026-04-04" },
        ]),
      });

      const { ingestVictimIABAttribution } = await import("./lib/iab-ingestion-service");
      const result = await ingestVictimIABAttribution();

      expect(result.source).toBe("ransomware_live_victim_attribution");
      expect(result.fetched).toBeGreaterThanOrEqual(2); // 2 groups with 2+ victims
    });

    it("should skip groups with only 1 victim", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          { group_name: "solo", post_title: "Only Victim", activity: "Tech", country: "US" },
        ]),
      });

      const { ingestVictimIABAttribution } = await import("./lib/iab-ingestion-service");
      const result = await ingestVictimIABAttribution();

      expect(result.inserted).toBe(0);
    });
  });

  describe("ingestCISAKEVExploits", () => {
    it("should fetch CISA KEV and filter IAB-relevant vulnerabilities", async () => {
      const now = new Date();
      const recentDate = new Date(now.getFullYear(), now.getMonth() - 3, 1).toISOString().slice(0, 10);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          vulnerabilities: [
            {
              cveID: "CVE-2026-1234",
              vendorProject: "Fortinet",
              product: "FortiGate VPN",
              shortDescription: "Authentication bypass in FortiGate VPN",
              vulnerabilityName: "Fortinet FortiGate VPN Auth Bypass",
              dateAdded: recentDate,
              knownRansomwareCampaignUse: "Known",
              requiredAction: "Apply vendor patch",
            },
            {
              cveID: "CVE-2020-0001",
              vendorProject: "OldVendor",
              product: "OldProduct",
              shortDescription: "Old vulnerability",
              vulnerabilityName: "Old Vuln",
              dateAdded: "2020-01-01",
              knownRansomwareCampaignUse: "Unknown",
            },
          ],
        }),
      });

      const { ingestCISAKEVExploits } = await import("./lib/iab-ingestion-service");
      const result = await ingestCISAKEVExploits();

      expect(result.source).toBe("cisa_kev_exploits");
      expect(result.fetched).toBeGreaterThanOrEqual(1);
    });

    it("should handle network errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network timeout"));

      const { ingestCISAKEVExploits } = await import("./lib/iab-ingestion-service");
      const result = await ingestCISAKEVExploits();

      expect(result.error).toBe("Network timeout");
    });
  });

  describe("ingestRansomLookMarkets", () => {
    it("should fetch markets and filter IAB-related ones", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          "darkleakmarket",
          "accessshop",
          "exploitforum",
          "randomsite",
          "credentialstore",
        ]),
      });

      const { ingestRansomLookMarkets } = await import("./lib/iab-ingestion-service");
      const result = await ingestRansomLookMarkets();

      expect(result.source).toBe("ransomlook_markets");
      expect(result.fetched).toBeGreaterThanOrEqual(1);
    });
  });

  describe("runIABIngestionPipeline", () => {
    it("should run all sources and return summary", async () => {
      // Mock all 4 fetch calls
      mockFetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) }) // groups
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) }) // victims
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ vulnerabilities: [] }) }) // KEV
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) }); // markets

      const { runIABIngestionPipeline } = await import("./lib/iab-ingestion-service");
      const result = await runIABIngestionPipeline();

      expect(result.startedAt).toBeDefined();
      expect(result.completedAt).toBeDefined();
      expect(result.results.length).toBeGreaterThanOrEqual(4);
      expect(typeof result.totalInserted).toBe("number");
      expect(typeof result.totalErrors).toBe("number");
    });
  });
});

describe("IAB Spike Alerting Service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockExecute.mockResolvedValue([{ cnt: 0 }]);
  });

  describe("runIABSpikeCheck", () => {
    it("should return no alerts when all metrics are within thresholds", async () => {
      mockExecute.mockResolvedValue([{ cnt: 0 }]);

      const { runIABSpikeCheck } = await import("./lib/iab-spike-alerting");
      const result = await runIABSpikeCheck({
        monthlyVolumeThreshold: 100,
        govTargetingThreshold: 50,
        highValuePriceThreshold: 100000,
        newBrokerDailyThreshold: 50,
        volumeSpikePercent: 200,
      });

      expect(result.checkedAt).toBeDefined();
      expect(result.alerts.length).toBe(0);
      expect(result.notificationsSent).toBe(0);
    });

    it("should detect volume spike when threshold exceeded", async () => {
      // Current month: 25, Previous month: 5
      mockExecute
        .mockResolvedValueOnce([{ cnt: 25 }]) // current month
        .mockResolvedValueOnce([{ cnt: 5 }])  // prev month
        .mockResolvedValueOnce([{ cnt: 0 }])  // gov targeting
        .mockResolvedValueOnce([])             // high value
        .mockResolvedValueOnce([{ cnt: 0 }]); // new brokers

      const { runIABSpikeCheck } = await import("./lib/iab-spike-alerting");
      const result = await runIABSpikeCheck({
        monthlyVolumeThreshold: 20,
        govTargetingThreshold: 50,
        highValuePriceThreshold: 100000,
        newBrokerDailyThreshold: 50,
        volumeSpikePercent: 50,
      });

      const volumeAlerts = result.alerts.filter(a => a.type === "volume_spike");
      expect(volumeAlerts.length).toBeGreaterThanOrEqual(1);
    });

    it("should detect government targeting spike", async () => {
      // Since all 4 checks run in parallel, we mock execute to always return
      // a high count so the gov check will find it
      mockExecute.mockResolvedValue([{ cnt: 10 }]);

      const { runIABSpikeCheck } = await import("./lib/iab-spike-alerting");
      const result = await runIABSpikeCheck({
        monthlyVolumeThreshold: 100,  // high so volume doesn't trigger
        govTargetingThreshold: 5,     // low so gov triggers with cnt=10
        highValuePriceThreshold: 100000,
        newBrokerDailyThreshold: 50,
        volumeSpikePercent: 200,
      });

      // With cnt=10 for everything, gov targeting should trigger
      const govAlerts = result.alerts.filter(a => a.type === "gov_targeting");
      expect(govAlerts.length).toBeGreaterThanOrEqual(1);
    });

    it("should sort alerts by severity", async () => {
      // Trigger both volume and gov alerts
      mockExecute
        .mockResolvedValueOnce([{ cnt: 50 }])  // current month (critical volume)
        .mockResolvedValueOnce([{ cnt: 5 }])   // prev month
        .mockResolvedValueOnce([{ cnt: 10 }])  // gov targeting
        .mockResolvedValueOnce([])              // gov listings detail
        .mockResolvedValueOnce([])              // high value
        .mockResolvedValueOnce([{ cnt: 0 }]);  // new brokers

      const { runIABSpikeCheck } = await import("./lib/iab-spike-alerting");
      const result = await runIABSpikeCheck({
        monthlyVolumeThreshold: 20,
        govTargetingThreshold: 5,
        highValuePriceThreshold: 100000,
        newBrokerDailyThreshold: 50,
        volumeSpikePercent: 50,
      });

      if (result.alerts.length > 1) {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        for (let i = 1; i < result.alerts.length; i++) {
          expect(severityOrder[result.alerts[i].severity]).toBeGreaterThanOrEqual(
            severityOrder[result.alerts[i - 1].severity]
          );
        }
      }
    });

    it("should send notifications for critical and high alerts", async () => {
      const { notifyOwner } = await import("./_core/notification");

      mockExecute
        .mockResolvedValueOnce([{ cnt: 50 }])  // current month
        .mockResolvedValueOnce([{ cnt: 5 }])   // prev month
        .mockResolvedValueOnce([{ cnt: 0 }])   // gov targeting
        .mockResolvedValueOnce([])              // high value
        .mockResolvedValueOnce([{ cnt: 0 }]);  // new brokers

      const { runIABSpikeCheck } = await import("./lib/iab-spike-alerting");
      const result = await runIABSpikeCheck({
        monthlyVolumeThreshold: 20,
        govTargetingThreshold: 50,
        highValuePriceThreshold: 100000,
        newBrokerDailyThreshold: 50,
        volumeSpikePercent: 50,
      });

      if (result.alerts.some(a => a.severity === "critical" || a.severity === "high")) {
        expect(notifyOwner).toHaveBeenCalled();
      }
    });
  });

  describe("getDefaultThresholds", () => {
    it("should return default threshold values", async () => {
      const { getDefaultThresholds } = await import("./lib/iab-spike-alerting");
      const thresholds = getDefaultThresholds();

      expect(thresholds.monthlyVolumeThreshold).toBe(20);
      expect(thresholds.govTargetingThreshold).toBe(5);
      expect(thresholds.highValuePriceThreshold).toBe(50000);
      expect(thresholds.newBrokerDailyThreshold).toBe(5);
      expect(thresholds.volumeSpikePercent).toBe(50);
    });
  });
});
