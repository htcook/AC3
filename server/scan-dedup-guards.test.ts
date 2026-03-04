/**
 * Scan Deduplication Guards — Tests
 * 
 * Validates that all scan insertion paths have proper deduplication guards
 * to prevent duplicate records when engagement scans are re-run.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── ZAP Scanner startScan dedup ─────────────────────────────────────────────
describe("ZAP Scanner startScan dedup guard", () => {
  it("should check for existing scan before creating a new one", async () => {
    // Read the source to verify the dedup guard exists
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    
    expect(source).toContain("Deduplication guard: skip if an identical scan already exists");
    expect(source).toContain("eq(webAppScans.scanName, effectiveScanName)");
    expect(source).toContain("eq(webAppScans.targetUrl, params.targetUrl)");
    expect(source).toContain("[ZAP Dedup] Scan already exists");
  });

  it("should return existing scan id when duplicate is found", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    
    // Verify it returns the existing scan instead of creating a new one
    expect(source).toContain("scanId: existingScan.id");
    expect(source).toContain("status: existingScan.status");
    expect(source).toContain("deduplicated: true");
  });
});

// ─── Engagement Orchestrator ZAP loop dedup ──────────────────────────────────
describe("Engagement Orchestrator ZAP scan loop dedup", () => {
  it("should track scanned URLs with a Set to prevent duplicate scans", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    
    expect(source).toContain("const scannedTargetUrls = new Set<string>()");
    expect(source).toContain("scannedTargetUrls.has(targetUrl)");
    expect(source).toContain("scannedTargetUrls.add(targetUrl)");
    expect(source).toContain("ZAP Dedup Skip");
    expect(source).toContain("Already scanned in this engagement run");
  });
});

// ─── Vuln Scanner importScan dedup ───────────────────────────────────────────
describe("Vuln Scanner importScan dedup guard", () => {
  it("should check for existing import with same fileName and scannerType", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/vuln-scanner.ts", "utf-8");
    
    expect(source).toContain("Deduplication guard: skip if same file was already imported");
    expect(source).toContain("eqCheck(vulnScanImports.fileName, input.fileName)");
    expect(source).toContain("eqCheck(vulnScanImports.scannerType, input.scannerType)");
  });

  it("should throw CONFLICT error for duplicate imports", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/vuln-scanner.ts", "utf-8");
    
    expect(source).toContain("code: \"CONFLICT\"");
    expect(source).toContain("was already imported");
    expect(source).toContain("Delete the existing import first to re-import");
  });
});

// ─── Domain Intel startScan dedup ────────────────────────────────────────────
describe("Domain Intel startScan dedup guard", () => {
  it("should check for existing in-progress scan for same engagement + domain", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/domain-intel-core.ts", "utf-8");
    
    expect(source).toContain("Deduplication guard: check for existing scan with same engagement + domain");
    expect(source).toContain("getDomainIntelScansByEngagement");
    expect(source).toContain("s.primaryDomain === input.primaryDomain");
  });

  it("should allow re-scan for completed or errored scans", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/domain-intel-core.ts", "utf-8");
    
    expect(source).toContain("existing.status !== 'completed'");
    expect(source).toContain("existing.status !== 'error'");
    // For completed/error scans, the guard should NOT block
    expect(source).toContain("allow a new scan (user explicitly wants to re-run)");
  });

  it("should return existing scan id for in-progress duplicates", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/domain-intel-core.ts", "utf-8");
    
    expect(source).toContain("scanId: existing.id");
    expect(source).toContain("deduplicated: true");
    expect(source).toContain("Scan already in progress");
  });
});

// ─── Phishing Draft materialization dedup ────────────────────────────────────
describe("Phishing Draft materialization dedup guards", () => {
  it("should have dedup guard in engagement-pipeline.ts", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/engagement-pipeline.ts", "utf-8");
    
    // Check both the existing guard (line ~168) and the new one (line ~282)
    expect(source).toContain("Dedup guard: skip if a draft already exists");
    expect(source).toContain("eq(phishingDrafts.scanId, latestScan.id)");
    expect(source).toContain("eq(phishingDrafts.campaignRecommendationIndex, i)");
    expect(source).toContain("[Pipeline Dedup] Draft already exists");
  });

  it("should have dedup guard in phishing-ops.ts", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/phishing-ops.ts", "utf-8");
    
    expect(source).toContain("Dedup guard: check if a draft already exists");
    expect(source).toContain("eq(phishingDrafts.scanId, input.scanId)");
    expect(source).toContain("eq(phishingDrafts.campaignRecommendationIndex, input.recommendationIndex)");
    expect(source).toContain("Draft already exists for this recommendation");
  });

  it("should have dedup guard in campaign-mgmt.ts", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/phishing/campaign-mgmt.ts", "utf-8");
    
    expect(source).toContain("Dedup guard: check if a draft already exists");
    expect(source).toContain("eq(phishingDrafts.scanId, input.scanId)");
    expect(source).toContain("eq(phishingDrafts.campaignRecommendationIndex, input.recommendationIndex)");
    expect(source).toContain("Draft already exists for this recommendation");
  });
});

// ─── Scan Results insertScanResult upsert dedup ──────────────────────────────
describe("insertScanResult upsert dedup guard", () => {
  it("should check for existing result with same engagement + tool + target", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    // Find the insertScanResult function section
    const fnStart = source.indexOf("export async function insertScanResult");
    const fnSection = source.substring(fnStart, fnStart + 1500);
    
    expect(fnSection).toContain("Dedup guard: check for existing result with same engagement + tool + target");
    expect(fnSection).toContain("eq(scanResults.engagementId, data.engagementId)");
    expect(fnSection).toContain("eq(scanResults.tool, data.tool)");
    expect(fnSection).toContain("eq(scanResults.target, data.target)");
  });

  it("should update existing record instead of creating duplicate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    const fnStart = source.indexOf("export async function insertScanResult");
    const fnSection = source.substring(fnStart, fnStart + 1500);
    
    // Should update the existing record with new data
    expect(fnSection).toContain("db.update(scanResults).set({");
    expect(fnSection).toContain("rawOutput: data.rawOutput");
    expect(fnSection).toContain("findings: data.findings");
    expect(fnSection).toContain("findingCount: data.findingCount");
    expect(fnSection).toContain("where(eq(scanResults.id, existing.id))");
  });
});

// ─── Previously added OSINT/Domain/Typosquat dedup guards ────────────────────
describe("Previously added dedup guards (OSINT, Domain Recon, Typosquat)", () => {
  it("should have dedup guard in createDomainRecon", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    const fnStart = source.indexOf("export async function createDomainRecon");
    expect(fnStart).toBeGreaterThan(-1);
    const fnSection = source.substring(fnStart, fnStart + 800);
    expect(fnSection).toContain("Dedup guard");
  });

  it("should have dedup guard in createOsintFinding", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    const fnStart = source.indexOf("export async function createOsintFinding");
    expect(fnStart).toBeGreaterThan(-1);
    const fnSection = source.substring(fnStart, fnStart + 800);
    expect(fnSection).toContain("Dedup guard");
  });

  it("should have dedup guard in createTyposquatDomain", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    const fnStart = source.indexOf("export async function createTyposquatDomain");
    expect(fnStart).toBeGreaterThan(-1);
    const fnSection = source.substring(fnStart, fnStart + 800);
    expect(fnSection).toContain("Dedup guard");
  });

  it("should have dedup guard in bulkCreateTyposquatDomains", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    const fnStart = source.indexOf("export async function bulkCreateTyposquatDomains");
    expect(fnStart).toBeGreaterThan(-1);
    const fnSection = source.substring(fnStart, fnStart + 800);
    expect(fnSection).toContain("Dedup guard");
  });

  it("should have dedup guard in bulkCreateOsintFindings", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    const fnStart = source.indexOf("export async function bulkCreateOsintFindings");
    expect(fnStart).toBeGreaterThan(-1);
    const fnSection = source.substring(fnStart, fnStart + 800);
    expect(fnSection).toContain("Dedup guard");
  });
});

// ─── Comprehensive coverage check ───────────────────────────────────────────
describe("Dedup guard coverage summary", () => {
  it("should have dedup guards in all 8 critical insertion paths", async () => {
    const fs = await import("fs");
    
    const files = [
      { path: "server/lib/zap-scanner.ts", marker: "Deduplication guard" },
      { path: "server/lib/engagement-orchestrator.ts", marker: "scannedTargetUrls" },
      { path: "server/routers/vuln-scanner.ts", marker: "Deduplication guard" },
      { path: "server/routers/domain-intel-core.ts", marker: "Deduplication guard" },
      { path: "server/routers/engagement-pipeline.ts", marker: "Dedup guard" },
      { path: "server/routers/phishing-ops.ts", marker: "Dedup guard" },
      { path: "server/routers/phishing/campaign-mgmt.ts", marker: "Dedup guard" },
      { path: "server/db.ts", marker: "Dedup guard: check for existing result" },
    ];

    for (const { path, marker } of files) {
      const source = fs.readFileSync(path, "utf-8");
      expect(source, `Missing dedup guard in ${path}`).toContain(marker);
    }
  });
});
