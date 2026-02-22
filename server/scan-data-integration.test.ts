/**
 * Scan Data Integration Tests
 *
 * Verifies that the scan database has actual data and that
 * the getDomainIntelScans function returns completed scans properly.
 */
import { describe, it, expect } from "vitest";

describe("Scan Data in Database", () => {
  it("getDomainIntelScans should return scans from the database", async () => {
    const { getDomainIntelScans } = await import("./db");
    const scans = await getDomainIntelScans();
    expect(Array.isArray(scans)).toBe(true);
    expect(scans.length).toBeGreaterThan(0);
    console.log(`Total scans returned: ${scans.length}`);
  });

  it("should have completed or scan_complete scans in the database", async () => {
    const { getDomainIntelScans } = await import("./db");
    const scans = await getDomainIntelScans();
    const viewable = scans.filter(
      (s: any) => s.status === "completed" || s.status === "scan_complete"
    );
    expect(viewable.length).toBeGreaterThan(0);
    console.log(`Viewable scans (completed + scan_complete): ${viewable.length}`);
  });

  it("completed scans should have primaryDomain field populated", async () => {
    const { getDomainIntelScans } = await import("./db");
    const scans = await getDomainIntelScans();
    const viewable = scans.filter(
      (s: any) => s.status === "completed" || s.status === "scan_complete"
    );
    for (const scan of viewable.slice(0, 10)) {
      expect(scan.primaryDomain).toBeTruthy();
      console.log(`  Scan ${scan.id}: ${scan.primaryDomain} (${scan.status}) risk=${scan.overallRiskScore} assets=${scan.totalAssets}`);
    }
  });

  it("scans should be ordered by createdAt descending", async () => {
    const { getDomainIntelScans } = await import("./db");
    const scans = await getDomainIntelScans();
    if (scans.length >= 2) {
      const first = new Date(scans[0].createdAt!).getTime();
      const second = new Date(scans[1].createdAt!).getTime();
      expect(first).toBeGreaterThanOrEqual(second);
    }
  });

  it("should have scans with various statuses", async () => {
    const { getDomainIntelScans } = await import("./db");
    const scans = await getDomainIntelScans();
    const statusMap: Record<string, number> = {};
    for (const s of scans) {
      statusMap[s.status!] = (statusMap[s.status!] || 0) + 1;
    }
    console.log("Status breakdown:", statusMap);
    // Should have at least completed or scan_complete
    const hasViewable =
      (statusMap["completed"] || 0) > 0 || (statusMap["scan_complete"] || 0) > 0;
    expect(hasViewable).toBe(true);
  });

  it("getDomainIntelScanById should return a specific completed scan", async () => {
    const { getDomainIntelScans, getDomainIntelScanById } = await import("./db");
    const scans = await getDomainIntelScans();
    const completed = scans.find(
      (s: any) => s.status === "completed" || s.status === "scan_complete"
    );
    expect(completed).toBeDefined();
    if (completed) {
      const scan = await getDomainIntelScanById(completed.id);
      expect(scan).toBeDefined();
      expect(scan!.id).toBe(completed.id);
      expect(scan!.primaryDomain).toBe(completed.primaryDomain);
    }
  });
});

describe("Scan History Page UI Code", () => {
  it("should filter scans by status correctly in the UI code", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(
      __dirname,
      "../client/src/pages/ScanHistory.tsx"
    );
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    // Should have status filter options
    expect(content).toContain('"completed"');
    expect(content).toContain('"scan_complete"');
    expect(content).toContain('"pending"');
    expect(content).toContain('"failed"');
    // Should have search functionality
    expect(content).toContain("search");
    expect(content).toContain("primaryDomain");
  });

  it("should have pagination support", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(
      __dirname,
      "../client/src/pages/ScanHistory.tsx"
    );
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    expect(content).toContain("PAGE_SIZE");
    expect(content).toContain("totalPages");
    expect(content).toContain("pageData");
  });

  it("should have retry and delete actions for failed/stuck scans", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(
      __dirname,
      "../client/src/pages/ScanHistory.tsx"
    );
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    expect(content).toContain("retryScan");
    expect(content).toContain("deleteScan");
    expect(content).toContain("canRetry");
  });

  it("should have sortable columns", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const scanHistoryPath = path.resolve(
      __dirname,
      "../client/src/pages/ScanHistory.tsx"
    );
    const content = fs.readFileSync(scanHistoryPath, "utf-8");
    expect(content).toContain("toggleSort");
    expect(content).toContain("sortField");
    expect(content).toContain("sortDir");
  });
});
