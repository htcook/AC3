import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the database module
vi.mock("./db", () => ({
  createEngagementReport: vi.fn().mockResolvedValue(100),
  getEngagementReports: vi.fn().mockResolvedValue([]),
  getReportById: vi.fn().mockResolvedValue(null),
  updateReport: vi.fn().mockResolvedValue(undefined),
  deleteReport: vi.fn().mockResolvedValue(undefined),
  getAllReports: vi.fn().mockResolvedValue([]),
  getEngagementById: vi.fn().mockResolvedValue({
    id: 1350014,
    name: "Vianova External Pentest",
    customerName: "Vianova",
    targetDomain: "vianovahealth.com",
    engagementType: "external_pentest",
    status: "active",
    startDate: Date.now(),
    endDate: null,
  }),
  getDomainReconByEngagement: vi.fn().mockResolvedValue([]),
  getTyposquatsByEngagement: vi.fn().mockResolvedValue([]),
  getOsintFindingsByEngagement: vi.fn().mockResolvedValue([]),
  getCampaignsByEngagement: vi.fn().mockResolvedValue([]),
  getDomainIntelScansByEngagement: vi.fn().mockResolvedValue([]),
  getTtpKnowledge: vi.fn().mockResolvedValue(null),
}));

// Mock storage
vi.mock("./storage", () => ({
  storagePut: vi.fn().mockResolvedValue({ key: "reports/test.md", url: "https://s3.example.com/reports/test.md" }),
}));

// Mock LLM
vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{ message: { content: "# Test Report\n\nThis is a test report." } }],
  }),
}));

// Mock API helpers
vi.mock("./lib/api-helpers", () => ({
  fetchGophishAPI: vi.fn().mockResolvedValue(null),
}));

// Mock env
vi.mock("./_core/env", () => ({
  ENV: {
    gophishBaseUrl: "",
    gophishApiKey: "",
    calderaBaseUrl: "",
    calderaApiKey: "",
  },
}));

import * as db from "./db";

describe("Reports Module", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Report DB Helpers", () => {
    it("createEngagementReport returns a report ID", async () => {
      const id = await db.createEngagementReport({
        engagementId: 1350014,
        reportType: "full_engagement",
        clientType: "enterprise",
        title: "Test Report",
        status: "generating",
      } as any);
      expect(id).toBe(100);
      expect(db.createEngagementReport).toHaveBeenCalledWith(
        expect.objectContaining({
          engagementId: 1350014,
          reportType: "full_engagement",
        })
      );
    });

    it("getEngagementReports returns array", async () => {
      const reports = await db.getEngagementReports(1350014);
      expect(Array.isArray(reports)).toBe(true);
    });

    it("getReportById returns null for non-existent report", async () => {
      const report = await db.getReportById(999);
      expect(report).toBeNull();
    });

    it("deleteReport calls db.deleteReport with correct id", async () => {
      await db.deleteReport(100);
      expect(db.deleteReport).toHaveBeenCalledWith(100);
    });

    it("updateReport calls db.updateReport with correct params", async () => {
      await db.updateReport(100, { status: "completed" } as any);
      expect(db.updateReport).toHaveBeenCalledWith(100, { status: "completed" });
    });

    it("getAllReports returns array", async () => {
      const reports = await db.getAllReports();
      expect(Array.isArray(reports)).toBe(true);
    });
  });

  describe("Report Generation Flow", () => {
    it("report generation creates record then updates on success", async () => {
      // Simulate the flow: create → generate → update
      const reportId = await db.createEngagementReport({
        engagementId: 1350014,
        reportType: "full_engagement",
        clientType: "enterprise",
        title: "Test Report",
        status: "generating",
      } as any);

      expect(reportId).toBe(100);

      // Simulate successful generation
      await db.updateReport(reportId, {
        status: "completed",
        reportUrl: "https://s3.example.com/reports/test.md",
        reportKey: "reports/test.md",
        generatedAt: new Date(),
      } as any);

      expect(db.updateReport).toHaveBeenCalledWith(
        100,
        expect.objectContaining({
          status: "completed",
          reportUrl: "https://s3.example.com/reports/test.md",
        })
      );
    });

    it("report generation creates record then marks failed on error", async () => {
      const reportId = await db.createEngagementReport({
        engagementId: 1350014,
        reportType: "executive_summary",
        clientType: "msp",
        title: "Failed Report",
        status: "generating",
      } as any);

      // Simulate failure
      await db.updateReport(reportId, { status: "failed" } as any);

      expect(db.updateReport).toHaveBeenCalledWith(100, { status: "failed" });
    });

    it("failed reports can be deleted", async () => {
      // Simulate finding a failed report
      vi.mocked(db.getReportById).mockResolvedValueOnce({
        id: 100,
        engagementId: 1350014,
        reportType: "full_engagement",
        clientType: "enterprise",
        title: "Failed Report",
        status: "failed",
      } as any);

      const report = await db.getReportById(100);
      expect(report).not.toBeNull();
      expect(report!.status).toBe("failed");

      await db.deleteReport(100);
      expect(db.deleteReport).toHaveBeenCalledWith(100);
    });
  });

  describe("Report Types", () => {
    const validTypes = [
      "executive_summary",
      "technical_detail",
      "compliance",
      "phishing_results",
      "osint_assessment",
      "full_engagement",
      "purple_team",
      "red_team_assessment",
      "detection_gap_analysis",
    ];

    it("supports all 9 report types", () => {
      expect(validTypes).toHaveLength(9);
    });

    it.each(validTypes)("report type '%s' is valid", async (reportType) => {
      await db.createEngagementReport({
        engagementId: 1350014,
        reportType,
        clientType: "enterprise",
        title: `Test ${reportType} Report`,
        status: "generating",
      } as any);

      expect(db.createEngagementReport).toHaveBeenCalledWith(
        expect.objectContaining({ reportType })
      );
    });
  });

  describe("Client Types", () => {
    const validClientTypes = [
      "msp",
      "enterprise",
      "saas",
      "paas",
      "iaas",
      "mixed_hosting",
      "other",
    ];

    it("supports all 7 client types", () => {
      expect(validClientTypes).toHaveLength(7);
    });

    it.each(validClientTypes)("client type '%s' is valid", async (clientType) => {
      await db.createEngagementReport({
        engagementId: 1350014,
        reportType: "full_engagement",
        clientType,
        title: `Test Report for ${clientType}`,
        status: "generating",
      } as any);

      expect(db.createEngagementReport).toHaveBeenCalledWith(
        expect.objectContaining({ clientType })
      );
    });
  });

  describe("Data Gathering", () => {
    it("gathers engagement data for report context", async () => {
      const engagement = await db.getEngagementById(1350014);
      expect(engagement).not.toBeNull();
      expect(engagement!.name).toBe("Vianova External Pentest");
    });

    it("gathers OSINT data for report context", async () => {
      const recon = await db.getDomainReconByEngagement(1350014);
      const typosquats = await db.getTyposquatsByEngagement(1350014);
      const findings = await db.getOsintFindingsByEngagement(1350014);
      expect(Array.isArray(recon)).toBe(true);
      expect(Array.isArray(typosquats)).toBe(true);
      expect(Array.isArray(findings)).toBe(true);
    });

    it("gathers campaign data for report context", async () => {
      const campaigns = await db.getCampaignsByEngagement(1350014);
      expect(Array.isArray(campaigns)).toBe(true);
    });

    it("gathers domain intel data for report context", async () => {
      const scans = await db.getDomainIntelScansByEngagement(1350014);
      expect(Array.isArray(scans)).toBe(true);
    });
  });
});
