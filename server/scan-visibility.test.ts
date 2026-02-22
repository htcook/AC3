/**
 * Scan Visibility Tests
 *
 * Verifies that completed scans are accessible via:
 * - Sidebar navigation (SCAN HISTORY link)
 * - Domain Intel page (completed scans as hero section)
 * - Scan History page route
 */
import { describe, it, expect } from "vitest";

describe("Scan History Sidebar Navigation", () => {
  it("should have SCAN HISTORY entry in sidebar navigation", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appShellPath = path.resolve(__dirname, "../client/src/components/AppShell.tsx");
    const content = fs.readFileSync(appShellPath, "utf-8");
    expect(content).toContain("/domain-intel/history");
    expect(content).toContain("SCAN HISTORY");
  });

  it("SCAN HISTORY should appear after DOMAIN INTEL in the intelligence nav group", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appShellPath = path.resolve(__dirname, "../client/src/components/AppShell.tsx");
    const content = fs.readFileSync(appShellPath, "utf-8");
    const domainIntelIdx = content.indexOf('"/domain-intel"');
    const scanHistoryIdx = content.indexOf('"/domain-intel/history"');
    const scanCompareIdx = content.indexOf('"/scan-compare"');
    expect(domainIntelIdx).toBeGreaterThan(-1);
    expect(scanHistoryIdx).toBeGreaterThan(domainIntelIdx);
    expect(scanHistoryIdx).toBeLessThan(scanCompareIdx);
  });

  it("should import ClipboardList icon for SCAN HISTORY", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appShellPath = path.resolve(__dirname, "../client/src/components/AppShell.tsx");
    const content = fs.readFileSync(appShellPath, "utf-8");
    expect(content).toContain("ClipboardList");
  });
});

describe("Domain Intel - Completed Scans Hero Section", () => {
  it("should show completed scans section when not running", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const domainIntelPath = path.resolve(__dirname, "../client/src/pages/DomainIntel.tsx");
    const content = fs.readFileSync(domainIntelPath, "utf-8");
    // The completed scans section should be gated by !isRunning only
    expect(content).toContain("Completed Scan Reports");
    // Find the completed scans section and verify it uses !isRunning
    const completedIdx = content.indexOf("Completed Scan Reports");
    expect(completedIdx).toBeGreaterThan(-1);
    // Look backwards for the condition — should be !isRunning (wider range to catch the JSX condition)
    const sectionBefore = content.substring(Math.max(0, completedIdx - 500), completedIdx);
    expect(sectionBefore).toContain("!isRunning");
    // Should NOT have !isComplete or !isScanComplete conditions blocking it
    expect(sectionBefore).not.toContain("!isComplete && !isScanComplete");
  });

  it("should have prominent scan stats above completed scans", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const domainIntelPath = path.resolve(__dirname, "../client/src/pages/DomainIntel.tsx");
    const content = fs.readFileSync(domainIntelPath, "utf-8");
    // Should have stats cards showing total scans, avg risk, total assets
    expect(content).toContain("Completed Scans");
    expect(content).toContain("overallRiskScore");
    expect(content).toContain("totalAssets");
  });

  it("should link to scan history page from completed scans section", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const domainIntelPath = path.resolve(__dirname, "../client/src/pages/DomainIntel.tsx");
    const content = fs.readFileSync(domainIntelPath, "utf-8");
    expect(content).toContain('/domain-intel/history');
    expect(content).toContain('View All');
  });

  it("should have clickable scan cards that navigate to scan detail", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const domainIntelPath = path.resolve(__dirname, "../client/src/pages/DomainIntel.tsx");
    const content = fs.readFileSync(domainIntelPath, "utf-8");
    expect(content).toContain("/domain-intel/${");
    expect(content).toContain("navigate");
  });
});

describe("Scan History Route", () => {
  it("should have /domain-intel/history route registered in App.tsx", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appPath = path.resolve(__dirname, "../client/src/App.tsx");
    const content = fs.readFileSync(appPath, "utf-8");
    expect(content).toContain("/domain-intel/history");
    expect(content).toContain("ScanHistory");
  });

  it("ScanHistory page should exist", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(__dirname, "../client/src/pages/ScanHistory.tsx");
    expect(fs.existsSync(scanHistoryPath)).toBe(true);
  });

  it("ScanHistory should use domainIntel.listScans query", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(__dirname, "../client/src/pages/ScanHistory.tsx");
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    expect(content).toContain("domainIntel.listScans.useQuery");
  });

  it("ScanHistory should allow viewing completed and scan_complete scans", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(__dirname, "../client/src/pages/ScanHistory.tsx");
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    expect(content).toContain("completed");
    expect(content).toContain("scan_complete");
    expect(content).toContain("canView");
  });

  it("ScanHistory should navigate to domain-intel/:id for viewable scans", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(__dirname, "../client/src/pages/ScanHistory.tsx");
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    expect(content).toContain("/domain-intel/${scan.id}");
  });

  it("ScanHistory should have Highest Risk Scans grid with prominent cards", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(__dirname, "../client/src/pages/ScanHistory.tsx");
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    expect(content).toContain("Highest Risk Scans");
    expect(content).toContain("View Full Report");
  });
});

describe("listScans tRPC Procedure", () => {
  it("should have listScans procedure on domainIntel router", async () => {
    const mod = await import("./routers");
    const routerDef = (mod.appRouter as any)._def;
    const procs = routerDef.procedures || routerDef.record || {};
    expect(procs["domainIntel.listScans"]).toBeDefined();
  });

  it("listScans should be a query (not mutation)", async () => {
    const mod = await import("./routers");
    const routerDef = (mod.appRouter as any)._def;
    const procs = routerDef.procedures || routerDef.record || {};
    const proc = procs["domainIntel.listScans"] as any;
    expect(proc).toBeDefined();
    expect(proc._def?.type || proc._type).toBe("query");
  });
});
