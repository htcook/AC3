import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * CISO Metrics Router Tests
 * Validates the executive metrics procedures return correct shapes
 * when the database returns data or is empty.
 */

// Mock getDb to return a controllable drizzle-like object
const mockSelect = vi.fn();
const mockFrom = vi.fn();
const mockWhere = vi.fn();
const mockGroupBy = vi.fn();
const mockOrderBy = vi.fn();
const mockLimit = vi.fn();

function chainMock(finalData: any[]) {
  const chain = {
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    groupBy: vi.fn().mockReturnThis(),
    orderBy: vi.fn().mockReturnThis(),
    limit: vi.fn().mockResolvedValue(finalData),
  };
  return chain;
}

vi.mock("./db", () => ({
  getDb: vi.fn(),
}));

// Mock schema imports to avoid DB connection
vi.mock("../drizzle/schema", () => {
  const fakeTable = new Proxy({}, {
    get: (_target, prop) => prop,
  });
  return {
    phishingDrafts: fakeTable,
    edrTestResults: fakeTable,
    c2ExecutionLog: fakeTable,
    customerIntelligenceProfiles: fakeTable,
    remediationTasks: fakeTable,
    vulnScanSnapshots: fakeTable,
    engagementFindings: fakeTable,
    engagements: fakeTable,
    complianceReports: fakeTable,
  };
});

describe("CISO Metrics Router", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("phishingSusceptibility", () => {
    it("returns empty defaults when DB is null", async () => {
      const { getDb } = await import("./db");
      (getDb as any).mockResolvedValue(null);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      // Access the procedure's resolver directly
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.phishingSusceptibility();

      expect(result.campaigns).toEqual([]);
      expect(result.summary.totalCampaigns).toBe(0);
      expect(result.summary.avgClickRate).toBe(0);
      expect(result.summary.avgReportRate).toBe(0);
      expect(result.summary.totalTargets).toBe(0);
      expect(result.summary.totalClicked).toBe(0);
      expect(result.summary.totalReported).toBe(0);
      expect(result.summary.totalCredsCaptured).toBe(0);
      expect(result.summary.trend).toBe("stable");
    });

    it("correctly calculates click rates and trends from campaign data", async () => {
      const { getDb } = await import("./db");
      const mockDb = {
        select: vi.fn().mockReturnValue({
          from: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              orderBy: vi.fn().mockReturnValue({
                limit: vi.fn().mockResolvedValue([
                  {
                    id: 1, name: "Campaign A", type: "phishing", status: "completed",
                    priority: "high", targetDomain: "test.com", targetSector: "finance",
                    stats: { total: 100, opened: 60, clicked: 30, submitted_data: 5, reported: 10 },
                    launchDate: "2026-01-01", createdAt: "2026-01-01", engagementId: 1,
                  },
                  {
                    id: 2, name: "Campaign B", type: "phishing", status: "completed",
                    priority: "medium", targetDomain: "test2.com", targetSector: "tech",
                    stats: { total: 200, opened: 80, clicked: 20, submitted_data: 2, reported: 30 },
                    launchDate: "2026-02-01", createdAt: "2026-02-01", engagementId: 2,
                  },
                ]),
              }),
            }),
          }),
        }),
      };
      (getDb as any).mockResolvedValue(mockDb);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.phishingSusceptibility();

      expect(result.campaigns.length).toBe(2);
      expect(result.summary.totalCampaigns).toBe(2);
      expect(result.summary.totalTargets).toBe(300);
      expect(result.summary.totalClicked).toBe(50);
      expect(result.summary.totalReported).toBe(40);
      expect(result.summary.totalCredsCaptured).toBe(7);
      // Campaign A: 30/100 = 30%, Campaign B: 20/200 = 10%, avg = 20%
      expect(result.summary.avgClickRate).toBe(20);
      // 40/300 = 13%
      expect(result.summary.avgReportRate).toBe(13);
      // Campaigns array should have correct metrics
      expect(result.campaigns[0].metrics.clickRate).toBe(30);
      expect(result.campaigns[1].metrics.clickRate).toBe(10);
    });
  });

  describe("detectionValidation", () => {
    it("returns empty defaults when DB is null", async () => {
      const { getDb } = await import("./db");
      (getDb as any).mockResolvedValue(null);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.detectionValidation();

      expect(result.edr.total).toBe(0);
      expect(result.edr.detectionRate).toBe(0);
      expect(result.c2.total).toBe(0);
      expect(result.c2.successRate).toBe(0);
      expect(result.controlCoverage).toBe(0);
      expect(result.recentTests).toEqual([]);
    });
  });

  describe("postureHistory", () => {
    it("returns empty defaults when DB is null", async () => {
      const { getDb } = await import("./db");
      (getDb as any).mockResolvedValue(null);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.postureHistory();

      expect(result.profiles).toEqual([]);
      expect(result.aggregatePosture.avgScore).toBe(0);
      expect(result.aggregatePosture.bestScore).toBe(0);
      expect(result.aggregatePosture.worstScore).toBe(0);
      expect(result.aggregatePosture.trend).toBe("stable");
      expect(result.topWeaknesses).toEqual([]);
      expect(result.persistentGaps).toEqual([]);
    });
  });

  describe("remediationMetrics", () => {
    it("returns empty defaults when DB is null", async () => {
      const { getDb } = await import("./db");
      (getDb as any).mockResolvedValue(null);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.remediationMetrics();

      expect(result.summary.total).toBe(0);
      expect(result.summary.open).toBe(0);
      expect(result.summary.fixed).toBe(0);
      expect(result.summary.verified).toBe(0);
      expect(result.bySeverity).toEqual([]);
      expect(result.slaCompliance.complianceRate).toBe(0);
      expect(result.mttr.avgDays).toBe(0);
      expect(result.mttr.medianDays).toBe(0);
      expect(result.recentFixed).toEqual([]);
    });
  });

  describe("vulnTrend", () => {
    it("returns empty defaults when DB is null", async () => {
      const { getDb } = await import("./db");
      (getDb as any).mockResolvedValue(null);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.vulnTrend();

      expect(result.snapshots).toEqual([]);
      expect(result.summary.totalScans).toBe(0);
      expect(result.summary.latestCritical).toBe(0);
      expect(result.summary.latestHigh).toBe(0);
      expect(result.summary.trend).toBe("stable");
    });
  });

  describe("mitreHeatmap", () => {
    it("returns empty defaults when DB is null", async () => {
      const { getDb } = await import("./db");
      (getDb as any).mockResolvedValue(null);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.mitreHeatmap();

      expect(result.tactics).toBeDefined();
      expect(result.tactics.length).toBeGreaterThan(0);
      expect(result.techniques).toEqual([]);
      expect(result.coverage.totalTechniques).toBe(0);
      expect(result.coverage.testedTechniques).toBe(0);
      expect(result.coverage.coveragePercent).toBe(0);
    });

    it("returns tactics with correct MITRE ATT&CK IDs", async () => {
      const { getDb } = await import("./db");
      (getDb as any).mockResolvedValue(null);

      const { cisoMetricsRouter } = await import("./routers/ciso-metrics");
      const caller = cisoMetricsRouter.createCaller({ user: { id: 1, role: "admin", openId: "test", name: "Test" } } as any);
      const result = await caller.mitreHeatmap();

      // All tactics should have TA-prefixed IDs
      for (const tactic of result.tactics) {
        expect(tactic.id).toMatch(/^TA\d{4}$/);
        expect(tactic.name).toBeTruthy();
        expect(tactic.shortName).toBeTruthy();
      }
    });
  });

  describe("CISO Role Access", () => {
    it("executive role enum exists in schema", async () => {
      const fs = await import("fs");
      const schema = fs.readFileSync("/home/ubuntu/caldera-dashboard/drizzle/schema.ts", "utf-8");
      expect(schema).toContain("'executive'");
    });

    it("executive role has sidebar access to command-control, compliance-reporting, ksi-fedramp, detection-validation", async () => {
      const fs = await import("fs");
      const sidebarNav = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/lib/sidebar-nav.ts", "utf-8");
      expect(sidebarNav).toContain("executive: ['command-control', 'compliance-reporting', 'ksi-fedramp', 'detection-validation']");
    });

    it("Executive Dashboard is in sidebar nav for executive role", async () => {
      const fs = await import("fs");
      const sidebarNav = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/lib/sidebar-nav.ts", "utf-8");
      expect(sidebarNav).toContain('Executive Dashboard');
      expect(sidebarNav).toContain('/executive-dashboard');
      // Should be visible to admin, executive, team_lead
      expect(sidebarNav).toMatch(/Executive Dashboard.*executive/);
    });
  });

  describe("HTTPS Enforcement", () => {
    it("server has HSTS middleware configured", async () => {
      const fs = await import("fs");
      const serverCode = fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/index.ts", "utf-8");
      expect(serverCode).toContain("Strict-Transport-Security");
      expect(serverCode).toContain("X-Forwarded-Proto");
    });

    it("ALB HTTPS setup script exists", async () => {
      const fs = await import("fs");
      const exists = fs.existsSync("/home/ubuntu/caldera-dashboard/infrastructure/setup-https-alb.sh");
      expect(exists).toBe(true);
    });

    it("security headers middleware includes anti-clickjacking and CSP", async () => {
      const fs = await import("fs");
      const headers = fs.readFileSync("/home/ubuntu/caldera-dashboard/server/lib/security-headers.ts", "utf-8");
      expect(headers).toContain("X-Frame-Options");
      expect(headers).toContain("X-Content-Type-Options");
      expect(headers).toContain("upgrade-insecure-requests");
    });
  });
});
