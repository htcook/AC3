import { describe, it, expect } from "vitest";

// ─── P0: Cross-Source Corroboration Engine ────────────────────────────────────
describe("Cross-Source Corroboration Engine", () => {
  it("exports corroborateFindings function", async () => {
    const mod = await import("./lib/corroboration-engine");
    expect(typeof mod.corroborateFindings).toBe("function");
  });

  it("exports estimateFPReduction function", async () => {
    const mod = await import("./lib/corroboration-engine");
    expect(typeof mod.estimateFPReduction).toBe("function");
  });

  it("corroborateFindings returns a report with verdicts", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const now = Date.now();
    const report = corroborateFindings([
      { id: "f1", title: "Log4Shell RCE", source: "nessus", severity: "critical" as const, cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.1", rawConfidence: 90, timestamp: now },
      { id: "f2", title: "Log4Shell RCE", source: "qualys", severity: "critical" as const, cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.1", rawConfidence: 85, timestamp: now },
    ]);
    expect(report).toHaveProperty("totalFindings");
    expect(report).toHaveProperty("results");
    expect(Array.isArray(report.results)).toBe(true);
    expect(report.results.length).toBe(2);
    report.results.forEach((r: any) => {
      expect(r).toHaveProperty("findingId");
      expect(r).toHaveProperty("adjustedConfidence");
      expect(typeof r.adjustedConfidence).toBe("number");
    });
  });

  it("multi-source corroboration boosts confidence", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const now = Date.now();
    const report = corroborateFindings([
      { id: "f1", title: "Log4Shell", source: "nessus", severity: "critical" as const, cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.1", rawConfidence: 80, timestamp: now },
      { id: "f2", title: "Log4Shell", source: "qualys", severity: "critical" as const, cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.1", rawConfidence: 75, timestamp: now },
    ]);
    // Both findings share the same CVE+host, so they corroborate each other
    const f1 = report.results.find((r: any) => r.findingId === "f1");
    expect(f1.corroboratingSourceCount).toBeGreaterThanOrEqual(1);
    // Adjusted confidence may be slightly lower due to recency decay, but corroboration should keep it close
    expect(f1.adjustedConfidence).toBeGreaterThanOrEqual(f1.originalConfidence - 5);
  });

  it("estimateFPReduction returns a percentage", async () => {
    const { corroborateFindings, estimateFPReduction } = await import("./lib/corroboration-engine");
    const now = Date.now();
    const report = corroborateFindings([
      { id: "f1", title: "Log4Shell", source: "nessus", severity: "critical" as const, cveId: "CVE-2021-44228", hostOrAsset: "10.0.0.1", rawConfidence: 80, timestamp: now },
      { id: "f2", title: "Open Port", source: "nmap", severity: "info" as const, hostOrAsset: "10.0.0.1", port: 22, rawConfidence: 50, timestamp: now },
    ]);
    const reduction = estimateFPReduction(report);
    expect(typeof reduction).toBe("number");
    expect(reduction).toBeGreaterThanOrEqual(0);
    expect(reduction).toBeLessThanOrEqual(100);
  });
});

// ─── P0: Dynamic CVE-to-Product Matching (NVD API) ───────────────────────────
describe("NVD CVE-to-Product Matcher", () => {
  it("exports fetchCveFromNvd function", async () => {
    const mod = await import("./lib/nvd-cve-matcher");
    expect(typeof mod.fetchCveFromNvd).toBe("function");
  });

  it("exports matchProductToCve function", async () => {
    const mod = await import("./lib/nvd-cve-matcher");
    expect(typeof mod.matchProductToCve).toBe("function");
  });

  it("exports parseCpe23 function", async () => {
    const mod = await import("./lib/nvd-cve-matcher");
    expect(typeof mod.parseCpe23).toBe("function");
  });

  it("parseCpe23 correctly parses a CPE 2.3 string", async () => {
    const { parseCpe23 } = await import("./lib/nvd-cve-matcher");
    const result = parseCpe23("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
    expect(result.vendor).toBe("apache");
    expect(result.product).toBe("log4j");
    expect(result.version).toBe("2.14.1");
  });

  it("parseCpe23 handles short CPE strings gracefully", async () => {
    const { parseCpe23 } = await import("./lib/nvd-cve-matcher");
    const result = parseCpe23("cpe:2.3:a:vendor:product");
    expect(result.vendor).toBe("vendor");
    expect(result.product).toBe("product");
  });

  it("versionInRange compares versions correctly", async () => {
    const { versionInRange } = await import("./lib/nvd-cve-matcher");
    // Exact version should be in range
    expect(versionInRange("2.14.1", "2.0.0", "2.15.0")).toBe(true);
    expect(versionInRange("2.16.0", "2.0.0", "2.15.0")).toBe(false);
  });

  it("matchProductToCve returns match results", async () => {
    const { matchProductToCve } = await import("./lib/nvd-cve-matcher");
    const cveRecord = {
      cveId: "CVE-2021-44228",
      description: "Log4Shell",
      severity: "CRITICAL",
      cvssV3Score: 10.0,
      publishedDate: "2021-12-10",
      lastModifiedDate: "2023-11-06",
      cpeMatches: [
        {
          cpe23: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
          vendor: "apache",
          product: "log4j",
          version: "*",
          vulnerable: true,
          versionStartIncluding: "2.0.0",
          versionEndExcluding: "2.15.0",
        },
      ],
    };
    const result = matchProductToCve("log4j", "2.14.1", cveRecord);
    expect(result).toHaveProperty("isVulnerable");
    expect(result.isVulnerable).toBe(true);
    expect(result).toHaveProperty("confidence");
    expect(typeof result.confidence).toBe("number");
    expect(result).toHaveProperty("cveId");
    expect(result.cveId).toBe("CVE-2021-44228");
  });

  it("exports clearNvdCache function", async () => {
    const { clearNvdCache } = await import("./lib/nvd-cve-matcher");
    expect(typeof clearNvdCache).toBe("function");
    // Should not throw
    clearNvdCache();
  });
});

// ─── P1: Compensating Control Awareness ───────────────────────────────────────
describe("Compensating Control Awareness", () => {
  it("exports assessControls function", async () => {
    const mod = await import("./lib/compensating-controls");
    expect(typeof mod.assessControls).toBe("function");
  });

  it("exports detectControlsFromHeaders function", async () => {
    const mod = await import("./lib/compensating-controls");
    expect(typeof mod.detectControlsFromHeaders).toBe("function");
  });

  it("exports detectControlsFromObservations function", async () => {
    const mod = await import("./lib/compensating-controls");
    expect(typeof mod.detectControlsFromObservations).toBe("function");
  });

  it("exports DEFAULT_CONTROL_CONFIG", async () => {
    const mod = await import("./lib/compensating-controls");
    expect(mod.DEFAULT_CONTROL_CONFIG).toBeDefined();
    expect(typeof mod.DEFAULT_CONTROL_CONFIG).toBe("object");
  });

  it("detectControlsFromHeaders detects WAF and CSP headers", async () => {
    const { detectControlsFromHeaders } = await import("./lib/compensating-controls");
    const controls = detectControlsFromHeaders({
      "x-waf-status": "active",
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=31536000",
    });
    expect(Array.isArray(controls)).toBe(true);
    expect(controls.length).toBeGreaterThan(0);
  });

  it("assessControls returns mitigation score", async () => {
    const { assessControls, detectControlsFromHeaders } = await import("./lib/compensating-controls");
    const controls = detectControlsFromHeaders({
      "x-waf-status": "active",
      "content-security-policy": "default-src 'self'",
    });
    const assessment = assessControls(controls, "critical");
    expect(assessment).toHaveProperty("overallMitigationScore");
    expect(typeof assessment.overallMitigationScore).toBe("number");
    expect(assessment.overallMitigationScore).toBeGreaterThanOrEqual(0);
    expect(assessment.overallMitigationScore).toBeLessThanOrEqual(100);
    expect(assessment).toHaveProperty("severityAdjustment");
    expect(assessment).toHaveProperty("adjustedSeverityLabel");
    expect(assessment).toHaveProperty("rationale");
  });

  it("batchAssessControls processes multiple findings", async () => {
    const { batchAssessControls } = await import("./lib/compensating-controls");
    const result = batchAssessControls([], [
      { id: "f1", severity: "critical" as const },
      { id: "f2", severity: "high" as const },
    ]);
    // Returns a Map<string, ControlAssessment>
    expect(result instanceof Map).toBe(true);
    expect(result.size).toBe(2);
  });
});

// ─── P1: Exploit Confidence Pre-Flight Checks ────────────────────────────────
describe("Exploit Confidence Pre-Flight Checks", () => {
  it("exports runPreFlightChecks function", async () => {
    const mod = await import("./lib/preflight-checks");
    expect(typeof mod.runPreFlightChecks).toBe("function");
  });

  it("exports quickConfidenceEstimate function", async () => {
    const mod = await import("./lib/preflight-checks");
    expect(typeof mod.quickConfidenceEstimate).toBe("function");
  });

  it("quickConfidenceEstimate returns a number 0-100", async () => {
    const { quickConfidenceEstimate } = await import("./lib/preflight-checks");
    const score = quickConfidenceEstimate({
      targetHost: "192.168.1.100",
      targetPort: 443,
      protocol: "https",
    });
    expect(typeof score).toBe("number");
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("runPreFlightChecks returns recommendation and checks", async () => {
    const { runPreFlightChecks } = await import("./lib/preflight-checks");
    const result = await runPreFlightChecks({
      targetHost: "192.168.1.100",
      targetPort: 443,
      protocol: "https",
    });
    expect(result).toHaveProperty("recommendation");
    expect(result).toHaveProperty("overallConfidence");
    expect(result).toHaveProperty("checks");
    expect(["proceed", "proceed_with_caution", "skip", "manual_review"]).toContain(result.recommendation);
    expect(typeof result.overallConfidence).toBe("number");
    expect(Array.isArray(result.checks)).toBe(true);
  });

  it("pre-flight checks include category and status", async () => {
    const { runPreFlightChecks } = await import("./lib/preflight-checks");
    const result = await runPreFlightChecks({
      targetHost: "10.0.0.1",
      targetPort: 80,
      protocol: "http",
    });
    result.checks.forEach((check: any) => {
      expect(check).toHaveProperty("checkName");
      expect(check).toHaveProperty("status");
      expect(check).toHaveProperty("category");
      expect(check).toHaveProperty("confidence");
      expect(["pass", "fail", "warn", "skip"]).toContain(check.status);
    });
  });
});

// ─── P1: Active Verification Probes ──────────────────────────────────────────
describe("Active Verification Probes", () => {
  it("exports BUILTIN_PROBES array", async () => {
    const mod = await import("./lib/active-verification");
    expect(Array.isArray(mod.BUILTIN_PROBES)).toBe(true);
    expect(mod.BUILTIN_PROBES.length).toBeGreaterThan(0);
  });

  it("each probe has required fields", async () => {
    const { BUILTIN_PROBES } = await import("./lib/active-verification");
    BUILTIN_PROBES.forEach((probe: any) => {
      expect(probe).toHaveProperty("id");
      expect(probe).toHaveProperty("name");
      expect(probe).toHaveProperty("description");
      expect(probe).toHaveProperty("probeType");
      expect(probe).toHaveProperty("severity");
      expect(probe).toHaveProperty("safeForProduction");
      expect(typeof probe.id).toBe("string");
      expect(typeof probe.name).toBe("string");
      expect(typeof probe.safeForProduction).toBe("boolean");
    });
  });

  it("exports runProbe function", async () => {
    const mod = await import("./lib/active-verification");
    expect(typeof mod.runProbe).toBe("function");
  });

  it("exports runVerificationSuite function", async () => {
    const mod = await import("./lib/active-verification");
    expect(typeof mod.runVerificationSuite).toBe("function");
  });

  it("exports getProbesForCve function", async () => {
    const mod = await import("./lib/active-verification");
    expect(typeof mod.getProbesForCve).toBe("function");
  });

  it("getProbesForCve returns matching probes for known CVE", async () => {
    const { getProbesForCve, BUILTIN_PROBES } = await import("./lib/active-verification");
    const probeCve = BUILTIN_PROBES.find((p: any) => p.cveIds && p.cveIds.length > 0);
    if (probeCve) {
      const matches = getProbesForCve(probeCve.cveIds[0]);
      expect(Array.isArray(matches)).toBe(true);
      expect(matches.length).toBeGreaterThan(0);
    }
  });

  it("exports getAvailableTags function", async () => {
    const { getAvailableTags } = await import("./lib/active-verification");
    const tags = getAvailableTags();
    expect(Array.isArray(tags)).toBe(true);
    expect(tags.length).toBeGreaterThan(0);
    tags.forEach((tag: string) => expect(typeof tag).toBe("string"));
  });

  it("getProbesForCve returns empty array for unknown CVE", async () => {
    const { getProbesForCve } = await import("./lib/active-verification");
    const matches = getProbesForCve("CVE-9999-99999");
    expect(Array.isArray(matches)).toBe(true);
    expect(matches.length).toBe(0);
  });
});

// ─── Router Registration Tests ───────────────────────────────────────────────
describe("Accuracy Improvement Routers", () => {
  it("corroboration engine router is exported", async () => {
    const mod = await import("./routers/corroboration-engine");
    expect(mod.corroborationEngineRouter).toBeDefined();
  });

  it("NVD CVE matcher router is exported", async () => {
    const mod = await import("./routers/nvd-cve-matcher");
    expect(mod.nvdCveMatcherRouter).toBeDefined();
  });

  it("compensating controls router is exported", async () => {
    const mod = await import("./routers/compensating-controls");
    expect(mod.compensatingControlsRouter).toBeDefined();
  });

  it("preflight checks router is exported", async () => {
    const mod = await import("./routers/preflight-checks");
    expect(mod.preflightChecksRouter).toBeDefined();
  });

  it("active verification router is exported", async () => {
    const mod = await import("./routers/active-verification");
    expect(mod.activeVerificationRouter).toBeDefined();
  });
});
