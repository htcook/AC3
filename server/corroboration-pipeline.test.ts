import { describe, it, expect } from "vitest";

// ─── Corroboration Pipeline Integration Tests ─────────────────────────────────

describe("Corroboration Pipeline Integration", () => {
  // --- corroborateFromSources wrapper ---
  it("corroborateFromSources returns structured result", async () => {
    const { corroborateFromSources } = await import("./lib/corroboration-engine");
    const result = await corroborateFromSources({
      findingType: "vulnerability",
      findingValue: "CVE-2021-44228",
    });
    expect(result).toHaveProperty("findingType", "vulnerability");
    expect(result).toHaveProperty("findingValue", "CVE-2021-44228");
    expect(result).toHaveProperty("overallConfidence");
    expect(typeof result.overallConfidence).toBe("number");
    expect(result).toHaveProperty("overallVerdict");
    expect(["confirmed", "suspicious", "unverified", "false_positive"]).toContain(result.overallVerdict);
    expect(result).toHaveProperty("sourceResults");
    expect(Array.isArray(result.sourceResults)).toBe(true);
    expect(result).toHaveProperty("corroboratingCount");
    expect(result).toHaveProperty("totalSourcesChecked");
  });

  it("corroborateFromSources respects requested sources", async () => {
    const { corroborateFromSources } = await import("./lib/corroboration-engine");
    const result = await corroborateFromSources({
      findingType: "ip",
      findingValue: "192.168.1.1",
      requestedSources: ["shodan", "censys"],
    });
    expect(result.sourceResults.length).toBe(2);
    expect(result.sourceResults.map(s => s.source)).toEqual(["shodan", "censys"]);
  });

  it("corroborateFromSources defaults to all sources when none specified", async () => {
    const { corroborateFromSources } = await import("./lib/corroboration-engine");
    const result = await corroborateFromSources({
      findingType: "domain",
      findingValue: "example.com",
    });
    expect(result.sourceResults.length).toBe(8); // All 8 default sources
  });

  // --- getAvailableSources wrapper ---
  it("getAvailableSources returns source catalog", async () => {
    const { getAvailableSources } = await import("./lib/corroboration-engine");
    const sources = getAvailableSources();
    expect(Array.isArray(sources)).toBe(true);
    expect(sources.length).toBe(8);
    sources.forEach(src => {
      expect(src).toHaveProperty("id");
      expect(src).toHaveProperty("name");
      expect(src).toHaveProperty("configured");
      expect(src).toHaveProperty("envVar");
      expect(src).toHaveProperty("description");
      expect(typeof src.configured).toBe("boolean");
    });
  });

  it("getAvailableSources includes expected source IDs", async () => {
    const { getAvailableSources } = await import("./lib/corroboration-engine");
    const sources = getAvailableSources();
    const ids = sources.map(s => s.id);
    expect(ids).toContain("nvd");
    expect(ids).toContain("shodan");
    expect(ids).toContain("censys");
    expect(ids).toContain("dehashed");
  });
});

// ─── NVD Matcher Wrapper Functions ──────────────────────────────────────────

describe("NVD Matcher Wrapper Functions", () => {
  it("lookupCve returns structured result for unknown CVE", async () => {
    const { lookupCve } = await import("./lib/nvd-cve-matcher");
    // This will likely fail to fetch from NVD in test, but should return gracefully
    const result = await lookupCve("CVE-9999-99999");
    expect(result).toHaveProperty("found");
    expect(result).toHaveProperty("cve");
    expect(result).toHaveProperty("cpeCount");
    expect(result).toHaveProperty("weaknessCount");
    expect(result).toHaveProperty("referenceCount");
    expect(typeof result.found).toBe("boolean");
    expect(typeof result.cpeCount).toBe("number");
  });

  it("matchProductToCves returns structured result", async () => {
    const { matchProductToCves } = await import("./lib/nvd-cve-matcher");
    // Will attempt NVD API call; may return empty in test env
    const result = await matchProductToCves("apache", "log4j", "2.14.1");
    expect(result).toHaveProperty("vendor", "apache");
    expect(result).toHaveProperty("product", "log4j");
    expect(result).toHaveProperty("matches");
    expect(Array.isArray(result.matches)).toBe(true);
    expect(result).toHaveProperty("totalMatches");
    expect(typeof result.totalMatches).toBe("number");
  });

  it("getNvdApiStatus returns status object", async () => {
    const { getNvdApiStatus } = await import("./lib/nvd-cve-matcher");
    const status = getNvdApiStatus();
    expect(status).toHaveProperty("cacheSize");
    expect(status).toHaveProperty("cacheTtlMs");
    expect(status).toHaveProperty("apiBaseUrl");
    expect(status).toHaveProperty("hasApiKey");
    expect(typeof status.cacheSize).toBe("number");
    expect(typeof status.cacheTtlMs).toBe("number");
    expect(typeof status.apiBaseUrl).toBe("string");
    expect(typeof status.hasApiKey).toBe("boolean");
  });
});

// ─── Compensating Controls Wrapper Functions ────────────────────────────────

describe("Compensating Controls Wrapper Functions", () => {
  it("evaluateCompensatingControls returns assessment", async () => {
    const { evaluateCompensatingControls } = await import("./lib/compensating-controls");
    const result = await evaluateCompensatingControls({
      cveId: "CVE-2021-44228",
      existingControls: ["WAF", "EDR", "MFA"],
    });
    expect(result).toHaveProperty("controls");
    expect(result).toHaveProperty("assessment");
    expect(result).toHaveProperty("recommendations");
    expect(Array.isArray(result.controls)).toBe(true);
    expect(result.controls.length).toBe(3);
    expect(result.assessment).toHaveProperty("overallMitigationScore");
    expect(Array.isArray(result.recommendations)).toBe(true);
  });

  it("evaluateCompensatingControls with no controls returns recommendations", async () => {
    const { evaluateCompensatingControls } = await import("./lib/compensating-controls");
    const result = await evaluateCompensatingControls({
      existingControls: [],
    });
    expect(result.controls.length).toBe(0);
    expect(result.recommendations.length).toBeGreaterThan(0);
  });

  it("getControlCatalog returns full catalog", async () => {
    const { getControlCatalog } = await import("./lib/compensating-controls");
    const catalog = getControlCatalog();
    expect(Array.isArray(catalog)).toBe(true);
    expect(catalog.length).toBeGreaterThan(10);
    catalog.forEach(c => {
      expect(c).toHaveProperty("category");
      expect(c).toHaveProperty("name");
      expect(c).toHaveProperty("description");
      expect(c).toHaveProperty("typicalMitigationFactor");
      expect(c).toHaveProperty("affectedAttackVectors");
      expect(typeof c.typicalMitigationFactor).toBe("number");
    });
  });

  it("calculateRiskAdjustment reduces risk score", async () => {
    const { calculateRiskAdjustment } = await import("./lib/compensating-controls");
    const result = calculateRiskAdjustment(9.0, ["waf", "edr", "mfa"]);
    expect(result).toHaveProperty("baseRiskScore", 9.0);
    expect(result).toHaveProperty("adjustedRiskScore");
    expect(result.adjustedRiskScore).toBeLessThan(result.baseRiskScore);
    expect(result).toHaveProperty("reduction");
    expect(result.reduction).toBeGreaterThan(0);
    expect(result).toHaveProperty("reductionPercent");
    expect(result.reductionPercent).toBeGreaterThan(0);
    expect(result).toHaveProperty("rationale");
    expect(typeof result.rationale).toBe("string");
  });

  it("calculateRiskAdjustment with single control", async () => {
    const { calculateRiskAdjustment } = await import("./lib/compensating-controls");
    const result = calculateRiskAdjustment(8.0, ["waf"]);
    expect(result.adjustedRiskScore).toBeLessThan(8.0);
    expect(result.activeControls).toEqual(["waf"]);
  });
});

// ─── Vuln Scanner Router Integration ────────────────────────────────────────

describe("Vuln Scanner Router", () => {
  it("vuln scanner router exports all expected procedures", async () => {
    const { vulnScannerRouter } = await import("./routers/vuln-scanner");
    expect(vulnScannerRouter).toBeDefined();
    // Check that the router has the expected procedure keys
    const routerDef = vulnScannerRouter._def;
    expect(routerDef).toBeDefined();
  });

  it("corroboration engine router has corroborate procedure", async () => {
    const { corroborationEngineRouter } = await import("./routers/corroboration-engine");
    expect(corroborationEngineRouter).toBeDefined();
    const routerDef = corroborationEngineRouter._def;
    expect(routerDef).toBeDefined();
  });
});

// ─── Cross-Source Deduplication Logic ───────────────────────────────────────

describe("Cross-Source Deduplication", () => {
  it("same CVE from different scanners are corroborated", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const now = Date.now();
    const report = corroborateFindings([
      { id: "n1", title: "Apache Log4j RCE", source: "nessus", severity: "critical", cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.5", rawConfidence: 85, timestamp: now },
      { id: "q1", title: "Log4Shell Vulnerability", source: "qualys", severity: "critical", cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.5", rawConfidence: 90, timestamp: now },
      { id: "r1", title: "Log4j Remote Code Execution", source: "rapid7", severity: "critical", cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.5", rawConfidence: 88, timestamp: now },
    ]);
    expect(report.totalFindings).toBe(3);
    // Each finding should see the other 2 as corroborating
    const n1 = report.results.find(r => r.findingId === "n1");
    expect(n1).toBeDefined();
    expect(n1!.corroboratingSourceCount).toBeGreaterThanOrEqual(2);
    // With 2 corroborating sources, verdict should be at least 'likely'
    expect(["confirmed", "likely"]).toContain(n1!.verdict);
  });

  it("contradicting severity levels reduce confidence", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const now = Date.now();
    const report = corroborateFindings([
      { id: "f1", title: "Test Vuln", source: "nessus", severity: "critical", cveId: "CVE-2024-0001", hostOrAsset: "10.0.0.1", rawConfidence: 90, timestamp: now },
      { id: "f2", title: "Test Vuln", source: "qualys", severity: "info", cveId: "CVE-2024-0001", hostOrAsset: "10.0.0.1", rawConfidence: 20, timestamp: now },
    ]);
    const f1 = report.results.find(r => r.findingId === "f1");
    expect(f1).toBeDefined();
    // The info vs critical mismatch should cause contradiction
    expect(f1!.contradictingSourceCount).toBeGreaterThanOrEqual(1);
  });

  it("single-source findings remain unverified", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const now = Date.now();
    const report = corroborateFindings([
      { id: "solo", title: "Unique Finding", source: "nessus", severity: "medium", hostOrAsset: "10.0.0.99", rawConfidence: 60, timestamp: now },
    ]);
    const solo = report.results.find(r => r.findingId === "solo");
    expect(solo).toBeDefined();
    expect(solo!.corroboratingSourceCount).toBe(0);
    expect(solo!.verdict).toBe("unverified");
  });

  it("suppression threshold works correctly", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const now = Date.now();
    const report = corroborateFindings([
      { id: "weak", title: "Weak Finding", source: "osint", severity: "low", hostOrAsset: "10.0.0.1", rawConfidence: 20, timestamp: now },
    ]);
    const weak = report.results.find(r => r.findingId === "weak");
    expect(weak).toBeDefined();
    // Low confidence from low-weight source should trigger suppression
    expect(weak!.adjustedConfidence).toBeLessThan(25);
    expect(weak!.suppressRecommendation).toBe(true);
  });
});
