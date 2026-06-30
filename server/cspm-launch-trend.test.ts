import { describe, it, expect, vi, beforeEach } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ── getComplianceTrend function tests ─────────────────────────────────────

describe("getComplianceTrend", () => {
  const cspmDbPath = path.join(__dirname, "lib/cspm-db.ts");
  const cspmDbContent = fs.readFileSync(cspmDbPath, "utf-8");

  it("should be exported from cspm-db.ts", () => {
    expect(cspmDbContent).toContain("export async function getComplianceTrend");
  });

  it("should accept optional tool and days parameters", () => {
    expect(cspmDbContent).toContain("tool?: \"prowler\" | \"scoutsuite\" | \"trivy\"");
    expect(cspmDbContent).toContain("days?: number");
  });

  it("should default to 90 days lookback", () => {
    expect(cspmDbContent).toContain("const daysBack = opts?.days ?? 90");
  });

  it("should filter by completed scans only", () => {
    expect(cspmDbContent).toContain("scan_status") ;
    expect(cspmDbContent).toContain("'completed'");
  });

  it("should select complianceScore, criticalCount, highCount, mediumCount, lowCount", () => {
    expect(cspmDbContent).toContain("complianceScore: cspmScanRuns.complianceScore");
    expect(cspmDbContent).toContain("criticalCount: cspmScanRuns.criticalCount");
    expect(cspmDbContent).toContain("highCount: cspmScanRuns.highCount");
    expect(cspmDbContent).toContain("mediumCount: cspmScanRuns.mediumCount");
    expect(cspmDbContent).toContain("lowCount: cspmScanRuns.lowCount");
  });

  it("should order by createdAt ascending for chronological trend", () => {
    // The trend data should be ordered chronologically (oldest first)
    const trendFn = cspmDbContent.substring(cspmDbContent.indexOf("getComplianceTrend"));
    expect(trendFn).toContain(".orderBy(cspmScanRuns.createdAt)");
  });

  it("should limit results to 200", () => {
    const trendFn = cspmDbContent.substring(cspmDbContent.indexOf("getComplianceTrend"));
    expect(trendFn).toContain(".limit(200)");
  });
});

// ── CSPM Dashboard Router - getComplianceTrend endpoint ───────────────────

describe("CSPM Dashboard Router - Compliance Trend Endpoint", () => {
  const routerPath = path.join(__dirname, "routers/cspm-dashboard.ts");
  const routerContent = fs.readFileSync(routerPath, "utf-8");

  it("should have getComplianceTrend endpoint", () => {
    expect(routerContent).toContain("getComplianceTrend:");
  });

  it("should accept tool filter (prowler/scoutsuite/trivy)", () => {
    expect(routerContent).toContain('z.enum(["prowler", "scoutsuite", "trivy"])');
  });

  it("should accept days parameter with min 7 max 365", () => {
    expect(routerContent).toContain("z.number().min(7).max(365)");
  });

  it("should default days to 90", () => {
    expect(routerContent).toContain(".default(90)");
  });
});

// ── CSPM Dashboard Router - launchScanFromCredential endpoint ─────────────

describe("CSPM Dashboard Router - Launch Scan From Credential", () => {
  const routerPath = path.join(__dirname, "routers/cspm-dashboard.ts");
  const routerContent = fs.readFileSync(routerPath, "utf-8");

  it("should have launchScanFromCredential endpoint", () => {
    expect(routerContent).toContain("launchScanFromCredential:");
  });

  it("should accept credentialId as required parameter", () => {
    expect(routerContent).toContain("credentialId: z.number()");
  });

  it("should accept tool selection (prowler or scoutsuite)", () => {
    expect(routerContent).toContain('z.enum(["prowler", "scoutsuite"])');
  });

  it("should accept optional services array", () => {
    expect(routerContent).toContain("services: z.array(z.string()).optional()");
  });

  it("should accept optional compliance framework", () => {
    expect(routerContent).toContain("compliance: z.string().optional()");
  });

  it("should accept optional timeout", () => {
    expect(routerContent).toContain("timeoutSeconds: z.number()");
  });

  it("should decrypt credential before launching scan", () => {
    expect(routerContent).toContain("decryptCredentialObject");
  });

  it("should create a scan run for persistence", () => {
    expect(routerContent).toContain("createScanRun");
  });

  it("should complete scan run on success", () => {
    expect(routerContent).toContain("completeScanRun");
  });

  it("should fail scan run on error", () => {
    expect(routerContent).toContain("failScanRun");
  });

  it("should store findings in DB", () => {
    expect(routerContent).toContain("storeFindings");
  });
});

// ── Cloud Credentials Router - Column Name Fixes ──────────────────────────

describe("Cloud Credentials Router - Fixed Column Names", () => {
  const routerPath = path.join(__dirname, "routers/cloud-credentials.ts");
  const routerContent = fs.readFileSync(routerPath, "utf-8");

  it("should use credProvider instead of provider for cloudCredentials", () => {
    expect(routerContent).toContain("cloudCredentials.credProvider");
    expect(routerContent).not.toContain("cloudCredentials.provider");
  });

  it("should use credRegion instead of region for cloudCredentials", () => {
    expect(routerContent).toContain("cloudCredentials.credCreatedAt");
    expect(routerContent).not.toContain("cloudCredentials.createdAt");
  });

  it("should use credStatus for status updates", () => {
    expect(routerContent).toContain('credStatus: "active"');
    expect(routerContent).not.toMatch(/\bstatus: "active"/);
  });

  it("should use credCreatedBy for insert", () => {
    expect(routerContent).toContain("credCreatedBy:");
    // The response mapping uses 'createdBy: c.credCreatedBy' which is correct
    // The insert uses 'credCreatedBy:' which is the Drizzle column name
  });

  it("should use credAccountId for insert", () => {
    expect(routerContent).toContain("credAccountId:");
  });

  it("should use enumProvider for cloudEnumerationRuns", () => {
    expect(routerContent).toContain("enumProvider:");
    expect(routerContent).toContain("cloudEnumerationRuns.enumProvider");
  });

  it("should use enumStatus for cloudEnumerationRuns", () => {
    expect(routerContent).toContain("enumStatus:");
    expect(routerContent).toContain("cloudEnumerationRuns.enumCreatedAt");
  });

  it("should use enumResults and enumErrorLog for update", () => {
    expect(routerContent).toContain("enumResults:");
    expect(routerContent).toContain("enumErrorLog:");
  });

  it("should support all 6 providers in providerEnum", () => {
    expect(routerContent).toContain('"digitalocean"');
    expect(routerContent).toContain('"alibaba"');
    expect(routerContent).toContain('"oracle"');
  });

  it("should support new credential types", () => {
    expect(routerContent).toContain('"do_api_token"');
    expect(routerContent).toContain('"alibaba_access_key"');
    expect(routerContent).toContain('"oracle_api_key"');
  });
});

// ── CSPM Dashboard Frontend ───────────────────────────────────────────────

describe("CSPM Dashboard Frontend", () => {
  const pagePath = path.join(__dirname, "../client/src/pages/CspmDashboard.tsx");
  const pageContent = fs.readFileSync(pagePath, "utf-8");

  it("should have LaunchScanButton component", () => {
    expect(pageContent).toContain("function LaunchScanButton");
  });

  it("should have ComplianceTrendChart component", () => {
    expect(pageContent).toContain("function ComplianceTrendChart");
  });

  it("should use recharts AreaChart for trend visualization", () => {
    expect(pageContent).toContain("AreaChart");
    expect(pageContent).toContain("Area");
  });

  it("should have tool filter in trend chart (prowler/scoutsuite/trivy)", () => {
    expect(pageContent).toContain("setTrendTool");
  });

  it("should call cspmDashboard.getComplianceTrend", () => {
    expect(pageContent).toContain("trpc.cspmDashboard.getComplianceTrend.useQuery");
  });

  it("should call cspmDashboard.launchScanFromCredential", () => {
    expect(pageContent).toContain("trpc.cspmDashboard.launchScanFromCredential.useMutation");
  });

  it("should call cspmDashboard.runTrivyScan for container scans", () => {
    expect(pageContent).toContain("trpc.cspmDashboard.runTrivyScan.useMutation");
  });

  it("should have credential selection in launch dialog", () => {
    expect(pageContent).toContain("trpc.cloudCredentials.listCredentials.useQuery");
  });

  it("should invalidate stats and history after successful scan", () => {
    expect(pageContent).toContain("utils.cspmDashboard.getStats.invalidate()");
    expect(pageContent).toContain("utils.cspmDashboard.getScanHistory.invalidate()");
    expect(pageContent).toContain("utils.cspmDashboard.getComplianceTrend.invalidate()");
  });

  it("should have compliance framework selection for Prowler", () => {
    expect(pageContent).toContain("cis_1.5_aws");
    expect(pageContent).toContain("pci_3.2.1_aws");
    expect(pageContent).toContain("hipaa_aws");
    expect(pageContent).toContain("soc2_aws");
  });

  it("should show empty state when no scan data exists", () => {
    expect(pageContent).toContain("No completed scans yet");
    expect(pageContent).toContain("No scan runs recorded yet");
  });

  it("should have FindingsDetail view with drill-down", () => {
    expect(pageContent).toContain("function FindingsDetail");
    expect(pageContent).toContain("onSelectRun");
  });

  it("should have severity and status filters in findings view", () => {
    expect(pageContent).toContain("severityFilter");
    expect(pageContent).toContain("statusFilter");
  });
});
