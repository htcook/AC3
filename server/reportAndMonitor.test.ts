import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import {
  createEngagement,
  createOsintMonitor,
  getOsintMonitors,
  getOsintMonitorById,
  updateOsintMonitor,
  deleteOsintMonitor,
  bulkCreateMonitorChanges,
  getMonitorChanges,
  getUnacknowledgedChanges,
  acknowledgeChange,
  createEngagementReport,
  getEngagementReports,
  getReportById,
  updateReport,
  getAllReports,
} from "./db";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-user",
    email: "test@aceofcloud.com",
    name: "Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

// ==================== OSINT MONITOR DB TESTS ====================
describe("OSINT Monitor DB operations", () => {
  it("should create an OSINT monitor", async () => {
    const id = await createOsintMonitor({
      domain: `test-monitor-${Date.now()}.com`,
      clientType: "enterprise",
      intervalHours: 24,
      notifyOnChange: true,
      enabled: true,
      totalScans: 0,
      baselineSnapshot: { spfRecord: "v=spf1 -all", dmarcRecord: null },
      createdBy: 1,
    });
    expect(id).toBeDefined();
    expect(typeof id).toBe("number");
    expect(id).toBeGreaterThan(0);
  });

  it("should list all monitors", async () => {
    const monitors = await getOsintMonitors();
    expect(Array.isArray(monitors)).toBe(true);
    expect(monitors.length).toBeGreaterThan(0);
  });

  it("should get a monitor by ID", async () => {
    const domain = `get-test-${Date.now()}.com`;
    const id = await createOsintMonitor({
      domain,
      clientType: "msp",
      intervalHours: 12,
      notifyOnChange: false,
      enabled: true,
      totalScans: 0,
      createdBy: 1,
    });
    const monitor = await getOsintMonitorById(id);
    expect(monitor).toBeDefined();
    expect(monitor?.domain).toBe(domain);
    expect(monitor?.clientType).toBe("msp");
    expect(monitor?.intervalHours).toBe(12);
  });

  it("should update a monitor", async () => {
    const id = await createOsintMonitor({
      domain: `update-test-${Date.now()}.com`,
      clientType: "saas",
      intervalHours: 24,
      notifyOnChange: true,
      enabled: true,
      totalScans: 0,
      createdBy: 1,
    });
    await updateOsintMonitor(id, { enabled: false, intervalHours: 168 });
    const updated = await getOsintMonitorById(id);
    expect(updated?.enabled).toBe(false);
    expect(updated?.intervalHours).toBe(168);
  });

  it("should delete a monitor", async () => {
    const id = await createOsintMonitor({
      domain: `delete-test-${Date.now()}.com`,
      clientType: "iaas",
      intervalHours: 6,
      notifyOnChange: false,
      enabled: true,
      totalScans: 0,
      createdBy: 1,
    });
    await deleteOsintMonitor(id);
    const deleted = await getOsintMonitorById(id);
    expect(deleted).toBeNull();
  });
});

// ==================== MONITOR CHANGES DB TESTS ====================
describe("Monitor Changes DB operations", () => {
  it("should create and retrieve monitor changes", async () => {
    const monitorId = await createOsintMonitor({
      domain: `changes-test-${Date.now()}.com`,
      clientType: "enterprise",
      intervalHours: 24,
      notifyOnChange: true,
      enabled: true,
      totalScans: 1,
      createdBy: 1,
    });

    await bulkCreateMonitorChanges([
      {
        monitorId,
        domain: `changes-test-${Date.now()}.com`,
        changeType: "spf_changed",
        severity: "warning",
        previousValue: "v=spf1 ~all",
        currentValue: "v=spf1 -all",
        description: "SPF policy changed from soft fail to hard fail",
      },
      {
        monitorId,
        domain: `changes-test-${Date.now()}.com`,
        changeType: "dmarc_removed",
        severity: "critical",
        previousValue: "v=DMARC1; p=reject",
        currentValue: null,
        description: "DMARC record was removed",
      },
    ]);

    const changes = await getMonitorChanges(monitorId);
    expect(changes.length).toBe(2);
    expect(changes.some((c) => c.changeType === "spf_changed")).toBe(true);
    expect(changes.some((c) => c.severity === "critical")).toBe(true);
  });

  it("should retrieve unacknowledged changes", async () => {
    const unacked = await getUnacknowledgedChanges();
    expect(Array.isArray(unacked)).toBe(true);
    // All returned changes should be unacknowledged
    for (const change of unacked) {
      expect(change.acknowledged).toBe(false);
    }
  });

  it("should acknowledge a change", async () => {
    const monitorId = await createOsintMonitor({
      domain: `ack-test-${Date.now()}.com`,
      clientType: "enterprise",
      intervalHours: 24,
      notifyOnChange: true,
      enabled: true,
      totalScans: 1,
      createdBy: 1,
    });

    await bulkCreateMonitorChanges([
      {
        monitorId,
        domain: `ack-test-${Date.now()}.com`,
        changeType: "mx_changed",
        severity: "info",
        description: "MX record updated",
      },
    ]);

    const changes = await getMonitorChanges(monitorId);
    expect(changes.length).toBeGreaterThan(0);
    const changeId = changes[0].id;

    await acknowledgeChange(changeId, 1);

    const updatedChanges = await getMonitorChanges(monitorId);
    const acked = updatedChanges.find((c) => c.id === changeId);
    expect(acked?.acknowledged).toBe(true);
    expect(acked?.acknowledgedBy).toBe(1);
  });
});

// ==================== ENGAGEMENT REPORTS DB TESTS ====================
describe("Engagement Reports DB operations", () => {
  it("should create an engagement report", async () => {
    const engId = await createEngagement({
      name: "Report Test Engagement " + Date.now(),
      customerName: "Report Test Corp",
      engagementType: "phishing",
      status: "active",
    });

    const reportId = await createEngagementReport({
      engagementId: engId,
      reportType: "executive_summary",
      clientType: "enterprise",
      title: "Q1 2026 Security Assessment",
      preparedFor: "Report Test Corp",
      preparedBy: "Harrison Cook",
      status: "pending",
      brandingColor: "#dc2626",
    });

    expect(reportId).toBeDefined();
    expect(typeof reportId).toBe("number");
    expect(reportId).toBeGreaterThan(0);
  });

  it("should get report by ID", async () => {
    const engId = await createEngagement({
      name: "Report Get Test " + Date.now(),
      customerName: "Get Test Corp",
      engagementType: "red_team",
      status: "completed",
    });

    const reportId = await createEngagementReport({
      engagementId: engId,
      reportType: "technical_detail",
      clientType: "msp",
      title: "Technical Detail Report",
      preparedFor: "Get Test Corp",
      status: "pending",
    });

    const report = await getReportById(reportId);
    expect(report).toBeDefined();
    expect(report?.title).toBe("Technical Detail Report");
    expect(report?.reportType).toBe("technical_detail");
    expect(report?.clientType).toBe("msp");
  });

  it("should update a report status", async () => {
    const engId = await createEngagement({
      name: "Report Update Test " + Date.now(),
      customerName: "Update Test Corp",
      engagementType: "phishing",
      status: "active",
    });

    const reportId = await createEngagementReport({
      engagementId: engId,
      reportType: "phishing_results",
      clientType: "saas",
      title: "Phishing Results Report",
      status: "pending",
    });

    await updateReport(reportId, {
      status: "completed",
      reportUrl: "https://example.com/reports/test.pdf",
      generatedAt: new Date(),
    });

    const updated = await getReportById(reportId);
    expect(updated?.status).toBe("completed");
    expect(updated?.reportUrl).toBe("https://example.com/reports/test.pdf");
    expect(updated?.generatedAt).toBeDefined();
  });

  it("should list reports by engagement", async () => {
    const engId = await createEngagement({
      name: "Report List Test " + Date.now(),
      customerName: "List Test Corp",
      engagementType: "pentest",
      status: "active",
    });

    await createEngagementReport({
      engagementId: engId,
      reportType: "executive_summary",
      clientType: "enterprise",
      title: "Exec Summary",
      status: "completed",
    });

    await createEngagementReport({
      engagementId: engId,
      reportType: "compliance",
      clientType: "enterprise",
      title: "Compliance Report",
      status: "completed",
    });

    const reports = await getEngagementReports(engId);
    expect(reports.length).toBe(2);
    expect(reports.some((r) => r.reportType === "executive_summary")).toBe(true);
    expect(reports.some((r) => r.reportType === "compliance")).toBe(true);
  });

  it("should list all reports", async () => {
    const allReports = await getAllReports();
    expect(Array.isArray(allReports)).toBe(true);
    expect(allReports.length).toBeGreaterThan(0);
  });

  it("should support all client types", async () => {
    const clientTypes = ["msp", "enterprise", "saas", "paas", "iaas", "mixed_hosting", "other"] as const;
    const engId = await createEngagement({
      name: "Client Type Test " + Date.now(),
      customerName: "Client Type Corp",
      engagementType: "red_team",
      status: "active",
    });

    for (const clientType of clientTypes) {
      const reportId = await createEngagementReport({
        engagementId: engId,
        reportType: "full_engagement",
        clientType,
        title: `${clientType} Report`,
        status: "pending",
      });
      expect(reportId).toBeGreaterThan(0);
      const report = await getReportById(reportId);
      expect(report?.clientType).toBe(clientType);
    }
  });

  it("should support all report types", async () => {
    const reportTypes = [
      "executive_summary",
      "technical_detail",
      "compliance",
      "phishing_results",
      "osint_assessment",
      "full_engagement",
      "purple_team",
      "red_team_assessment",
      "detection_gap_analysis",
    ] as const;
    const engId = await createEngagement({
      name: "Report Type Test " + Date.now(),
      customerName: "Report Type Corp",
      engagementType: "phishing",
      status: "active",
    });

    for (const reportType of reportTypes) {
      const reportId = await createEngagementReport({
        engagementId: engId,
        reportType,
        clientType: "enterprise",
        title: `${reportType} Report`,
        status: "pending",
      });
      expect(reportId).toBeGreaterThan(0);
      const report = await getReportById(reportId);
      expect(report?.reportType).toBe(reportType);
    }
  });
});

// ==================== tRPC PROCEDURE TESTS ====================
describe("Monitor tRPC procedures", () => {
  it("monitor.list should be callable", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const monitors = await caller.monitor.list();
    expect(Array.isArray(monitors)).toBe(true);
  });

  it("monitor.alerts should return unacknowledged changes", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const alerts = await caller.monitor.alerts();
    expect(Array.isArray(alerts)).toBe(true);
  });

  it("monitor.update should update monitor settings", async () => {
    const monitorId = await createOsintMonitor({
      domain: `trpc-update-${Date.now()}.com`,
      clientType: "enterprise",
      intervalHours: 24,
      notifyOnChange: true,
      enabled: true,
      totalScans: 0,
      createdBy: 1,
    });

    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.monitor.update({
      id: monitorId,
      enabled: false,
      intervalHours: 168,
    });
    expect(result.success).toBe(true);

    const updated = await getOsintMonitorById(monitorId);
    expect(updated?.enabled).toBe(false);
    expect(updated?.intervalHours).toBe(168);
  });

  it("monitor.delete should remove a monitor", async () => {
    const monitorId = await createOsintMonitor({
      domain: `trpc-delete-${Date.now()}.com`,
      clientType: "msp",
      intervalHours: 12,
      notifyOnChange: false,
      enabled: true,
      totalScans: 0,
      createdBy: 1,
    });

    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.monitor.delete({ id: monitorId });
    expect(result.success).toBe(true);

    const deleted = await getOsintMonitorById(monitorId);
    expect(deleted).toBeNull();
  });

  it("monitor.acknowledgeChange should mark change as acknowledged", async () => {
    const monitorId = await createOsintMonitor({
      domain: `trpc-ack-${Date.now()}.com`,
      clientType: "enterprise",
      intervalHours: 24,
      notifyOnChange: true,
      enabled: true,
      totalScans: 1,
      createdBy: 1,
    });

    await bulkCreateMonitorChanges([
      {
        monitorId,
        domain: `trpc-ack-${Date.now()}.com`,
        changeType: "ns_changed",
        severity: "warning",
        description: "Nameserver changed",
      },
    ]);

    const changes = await getMonitorChanges(monitorId);
    const changeId = changes[0].id;

    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.monitor.acknowledgeChange({ id: changeId });
    expect(result.success).toBe(true);
  });
});

describe("Reports tRPC procedures", () => {
  it("reports.list should be callable", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const reports = await caller.reports.list({});
    expect(Array.isArray(reports)).toBe(true);
  });

  it("reports.list should filter by engagement", async () => {
    const engId = await createEngagement({
      name: "tRPC Report Filter " + Date.now(),
      customerName: "Filter Corp",
      engagementType: "phishing",
      status: "active",
    });

    await createEngagementReport({
      engagementId: engId,
      reportType: "executive_summary",
      clientType: "enterprise",
      title: "Filtered Report",
      status: "completed",
    });

    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const reports = await caller.reports.list({ engagementId: engId });
    expect(reports.length).toBeGreaterThan(0);
    expect(reports.every((r: any) => r.engagementId === engId)).toBe(true);
  });

  it("reports.get should return a specific report", async () => {
    const engId = await createEngagement({
      name: "tRPC Report Get " + Date.now(),
      customerName: "Get Corp",
      engagementType: "red_team",
      status: "completed",
    });

    const reportId = await createEngagementReport({
      engagementId: engId,
      reportType: "osint_assessment",
      clientType: "mixed_hosting",
      title: "OSINT Assessment",
      status: "completed",
    });

    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const report = await caller.reports.get({ id: reportId });
    expect(report).toBeDefined();
    expect(report.title).toBe("OSINT Assessment");
    expect(report.reportType).toBe("osint_assessment");
    expect(report.clientType).toBe("mixed_hosting");
  });
});
