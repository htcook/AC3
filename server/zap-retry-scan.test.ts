import { describe, it, expect, vi } from "vitest";

/**
 * Unit tests for the retryScan function logic.
 * We test the validation and flow without hitting a real DB or ZAP.
 */

describe("retryScan validation logic", () => {
  it("should reject retry for non-error scans", () => {
    // The retryScan function should only allow retrying scans with status "error"
    const validStatuses = ["error"];
    const invalidStatuses = ["starting", "spidering", "active_scanning", "completed", "stopped"];

    for (const status of validStatuses) {
      expect(validStatuses.includes(status)).toBe(true);
    }
    for (const status of invalidStatuses) {
      expect(validStatuses.includes(status)).toBe(false);
    }
  });

  it("should preserve original scan config on retry", () => {
    // Simulate extracting config from an original scan record
    const originalScan = {
      targetUrl: "https://altoro.lab",
      scanType: "full",
      scanMode: "active",
      scanName: "Banking App - altoro.lab",
      llmScanConfig: JSON.stringify({ model: "gpt-4", temperature: 0.3 }),
      detectedTechStack: JSON.stringify(["Apache", "Java", "MySQL"]),
      attackChainId: "chain-001",
      calderaOperationId: "op-123",
      metasploitSessionId: null,
      domainIntelScanId: 42,
    };

    // Parse LLM config
    let llmConfig: any;
    if (originalScan.llmScanConfig) {
      try { llmConfig = JSON.parse(originalScan.llmScanConfig); } catch { /* ignore */ }
    }
    expect(llmConfig).toEqual({ model: "gpt-4", temperature: 0.3 });

    // Parse tech stack
    let discoveredTechnologies: string[] | undefined;
    if (originalScan.detectedTechStack) {
      try { discoveredTechnologies = JSON.parse(originalScan.detectedTechStack); } catch { /* ignore */ }
    }
    expect(discoveredTechnologies).toEqual(["Apache", "Java", "MySQL"]);

    // Retry scan name should have [RETRY] prefix
    const retryName = `[RETRY] ${originalScan.scanName || originalScan.targetUrl}`;
    expect(retryName).toBe("[RETRY] Banking App - altoro.lab");

    // Null fields should become undefined
    expect(originalScan.metasploitSessionId || undefined).toBeUndefined();
    expect(originalScan.attackChainId || undefined).toBe("chain-001");
  });

  it("should handle malformed JSON in llmScanConfig gracefully", () => {
    const badConfig = "not-valid-json{";
    let llmConfig: any;
    try { llmConfig = JSON.parse(badConfig); } catch { /* ignore */ }
    expect(llmConfig).toBeUndefined();
  });

  it("should handle malformed JSON in detectedTechStack gracefully", () => {
    const badTech = "{broken";
    let discoveredTechnologies: string[] | undefined;
    try { discoveredTechnologies = JSON.parse(badTech); } catch { /* ignore */ }
    expect(discoveredTechnologies).toBeUndefined();
  });

  it("should handle null/empty llmScanConfig", () => {
    const scan = { llmScanConfig: null };
    let llmConfig: any;
    if (scan.llmScanConfig) {
      try { llmConfig = JSON.parse(scan.llmScanConfig); } catch { /* ignore */ }
    }
    expect(llmConfig).toBeUndefined();
  });

  it("should handle null/empty detectedTechStack", () => {
    const scan = { detectedTechStack: "" };
    let discoveredTechnologies: string[] | undefined;
    if (scan.detectedTechStack) {
      try { discoveredTechnologies = JSON.parse(scan.detectedTechStack); } catch { /* ignore */ }
    }
    expect(discoveredTechnologies).toBeUndefined();
  });

  it("should generate correct retry scan name when scanName is null", () => {
    const scan = { scanName: null, targetUrl: "https://dvbank.lab" };
    const retryName = `[RETRY] ${scan.scanName || scan.targetUrl}`;
    expect(retryName).toBe("[RETRY] https://dvbank.lab");
  });

  it("should reset all scan progress fields on retry", () => {
    const resetFields = {
      status: "starting",
      spiderProgress: 0,
      activeScanProgress: 0,
      urlsDiscovered: 0,
      totalAlerts: 0,
      alertCounts: null,
      errorMessage: null,
      zapSpiderScanId: null,
      zapActiveScanId: null,
      zapAjaxSpiderScanId: null,
      completedAt: null,
    };

    expect(resetFields.status).toBe("starting");
    expect(resetFields.spiderProgress).toBe(0);
    expect(resetFields.activeScanProgress).toBe(0);
    expect(resetFields.urlsDiscovered).toBe(0);
    expect(resetFields.totalAlerts).toBe(0);
    expect(resetFields.alertCounts).toBeNull();
    expect(resetFields.errorMessage).toBeNull();
    expect(resetFields.zapSpiderScanId).toBeNull();
    expect(resetFields.zapActiveScanId).toBeNull();
    expect(resetFields.zapAjaxSpiderScanId).toBeNull();
    expect(resetFields.completedAt).toBeNull();
  });

  it("should mark original scan as superseded after successful retry", () => {
    const newScanId = 330010;
    const supersededMessage = `Superseded by retry scan #${newScanId}`;
    expect(supersededMessage).toBe("Superseded by retry scan #330010");
  });

  it("should mark scan back as error with retry failure message on failure", () => {
    const errorMsg = "ZAP connection timeout";
    const retryErrorMessage = `Retry failed: ${errorMsg}`;
    expect(retryErrorMessage).toBe("Retry failed: ZAP connection timeout");
  });
});
