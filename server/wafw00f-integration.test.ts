// @ts-nocheck
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for wafw00f secondary WAF fingerprinting integration
 * in the progressive evasion pipeline.
 */

describe("wafw00f integration - mergeWafDetections", () => {
  let mergeWafDetections: any;

  beforeEach(async () => {
    const mod = await import("./lib/progressive-evasion-pipeline");
    mergeWafDetections = mod.mergeWafDetections;
  });

  it("returns zero confidence when neither method detects a WAF", () => {
    const result = mergeWafDetections(
      { detected: false, vendor: null, confidence: 0, bypassTechniques: [] },
      { detected: false, wafName: null, allDetected: [] }
    );
    expect(result.combinedConfidence).toBe(0);
    expect(result.methodsAgree).toBe(true);
    expect(result.primaryVendor).toBeNull();
    expect(result.bypassTechniques).toEqual([]);
  });

  it("caps confidence when only header-based detection fires (wafw00f disagrees)", () => {
    const result = mergeWafDetections(
      { detected: true, vendor: "cloudflare", confidence: 75, bypassTechniques: ["bypass1"] },
      { detected: false, wafName: null, allDetected: [] }
    );
    expect(result.combinedConfidence).toBeLessThanOrEqual(60);
    expect(result.methodsAgree).toBe(false);
    expect(result.primaryVendor).toBe("cloudflare");
    expect(result.bypassTechniques).toContain("bypass1");
  });

  it("returns moderate confidence when only wafw00f detects (single WAF)", () => {
    const result = mergeWafDetections(
      { detected: false, vendor: null, confidence: 0, bypassTechniques: [] },
      { detected: true, wafName: "Cloudflare", allDetected: [{ name: "Cloudflare", manufacturer: "Cloudflare Inc." }] }
    );
    expect(result.combinedConfidence).toBe(60);
    expect(result.methodsAgree).toBe(false);
    expect(result.primaryVendor).toBe("cloudflare");
  });

  it("returns higher confidence when wafw00f detects multiple WAFs", () => {
    const result = mergeWafDetections(
      { detected: false, vendor: null, confidence: 0, bypassTechniques: [] },
      {
        detected: true,
        wafName: "Cloudflare",
        allDetected: [
          { name: "Cloudflare", manufacturer: "Cloudflare Inc." },
          { name: "ModSecurity", manufacturer: "Trustwave" },
        ],
      }
    );
    expect(result.combinedConfidence).toBe(80);
    expect(result.methodsAgree).toBe(false);
  });

  it("returns high confidence when both methods agree on vendor", () => {
    const result = mergeWafDetections(
      { detected: true, vendor: "cloudflare", confidence: 55, bypassTechniques: ["bypass1", "bypass2"] },
      { detected: true, wafName: "Cloudflare", allDetected: [{ name: "Cloudflare", manufacturer: "Cloudflare Inc." }] }
    );
    expect(result.combinedConfidence).toBe(85); // 55 + 30
    expect(result.methodsAgree).toBe(true);
    expect(result.primaryVendor).toBe("cloudflare");
    expect(result.bypassTechniques).toEqual(["bypass1", "bypass2"]);
  });

  it("caps combined confidence at 100 when both agree and header confidence is high", () => {
    const result = mergeWafDetections(
      { detected: true, vendor: "aws_waf", confidence: 90, bypassTechniques: [] },
      { detected: true, wafName: "AWSWAF (Amazon)", allDetected: [{ name: "AWSWAF", manufacturer: "Amazon" }] }
    );
    expect(result.combinedConfidence).toBe(100);
    expect(result.methodsAgree).toBe(true);
  });

  it("returns moderate confidence when both detect but disagree on vendor", () => {
    const result = mergeWafDetections(
      { detected: true, vendor: "cloudflare", confidence: 60, bypassTechniques: ["cf_bypass"] },
      { detected: true, wafName: "ModSecurity", allDetected: [{ name: "ModSecurity", manufacturer: "Trustwave" }] }
    );
    expect(result.combinedConfidence).toBeLessThanOrEqual(70);
    expect(result.methodsAgree).toBe(false);
    expect(result.primaryVendor).toBe("cloudflare"); // Header result takes priority
  });

  it("handles null headerResult gracefully", () => {
    const result = mergeWafDetections(
      null,
      { detected: true, wafName: "Sucuri", allDetected: [{ name: "Sucuri", manufacturer: "Sucuri Inc." }] }
    );
    expect(result.combinedConfidence).toBe(60);
    expect(result.methodsAgree).toBe(false);
    expect(result.primaryVendor).toBe("sucuri");
  });
});

describe("wafw00f integration - pipeline state management", () => {
  let initProgressiveEvasion: any;
  let getProgressiveEvasionState: any;
  let getWafFingerprintResults: any;
  let getWafFingerprintSummary: any;

  beforeEach(async () => {
    const mod = await import("./lib/progressive-evasion-pipeline");
    initProgressiveEvasion = mod.initProgressiveEvasion;
    getProgressiveEvasionState = mod.getProgressiveEvasionState;
    getWafFingerprintResults = mod.getWafFingerprintResults;
    getWafFingerprintSummary = mod.getWafFingerprintSummary;
  });

  it("initializes pipeline with empty wafFingerprintResults array", () => {
    const state = initProgressiveEvasion(9999, "red_team", "stealth", "operator1");
    expect(state.wafFingerprintResults).toEqual([]);
  });

  it("getWafFingerprintResults returns empty array for fresh pipeline", () => {
    initProgressiveEvasion(9998, "pentest", "stealth", "operator1");
    const results = getWafFingerprintResults(9998);
    expect(results).toEqual([]);
  });

  it("getWafFingerprintResults returns null for non-existent pipeline", () => {
    const results = getWafFingerprintResults(77777);
    expect(results).toBeNull();
  });

  it("getWafFingerprintSummary returns null for non-existent pipeline", () => {
    const summary = getWafFingerprintSummary(77777);
    expect(summary).toBeNull();
  });

  it("getWafFingerprintSummary returns zeroed summary for fresh pipeline", () => {
    initProgressiveEvasion(9997, "red_team", "stealth", "operator1");
    const summary = getWafFingerprintSummary(9997);
    expect(summary).not.toBeNull();
    expect(summary!.totalTargets).toBe(0);
    expect(summary!.wafDetected).toBe(0);
    expect(summary!.noWaf).toBe(0);
    expect(summary!.errors).toBe(0);
    expect(summary!.highConfidence).toBe(0);
    expect(summary!.vendors).toEqual({});
    expect(summary!.methodAgreement).toEqual({ agree: 0, disagree: 0 });
  });
});

describe("wafw00f integration - runWafw00fFingerprint", () => {
  let runWafw00fFingerprint: any;
  let initProgressiveEvasion: any;
  let getProgressiveEvasionState: any;
  let getWafFingerprintResults: any;
  let getWafFingerprintSummary: any;

  beforeEach(async () => {
    // Mock scan-server-executor
    vi.doMock("./lib/scan-server-executor", () => ({
      executeTool: vi.fn().mockResolvedValue({
        tool: "wafw00f",
        command: "wafw00f https://target.com -o - -a",
        stdout: JSON.stringify([{ firewall: "Cloudflare", manufacturer: "Cloudflare Inc." }]),
        stderr: "",
        exitCode: 0,
        durationMs: 3500,
        timedOut: false,
      }),
    }));

    // Mock enumeration-tools (already has real implementations, but mock for isolation)
    vi.doMock("./lib/enumeration-tools", () => ({
      buildWafw00fCommand: vi.fn().mockReturnValue("wafw00f https://target.com -o - -a"),
      parseWafw00fOutput: vi.fn().mockReturnValue({
        waf: "Cloudflare",
        manufacturer: "Cloudflare Inc.",
        detected: true,
        allDetected: [{ name: "Cloudflare", manufacturer: "Cloudflare Inc." }],
      }),
    }));

    const mod = await import("./lib/progressive-evasion-pipeline");
    runWafw00fFingerprint = mod.runWafw00fFingerprint;
    initProgressiveEvasion = mod.initProgressiveEvasion;
    getProgressiveEvasionState = mod.getProgressiveEvasionState;
    getWafFingerprintResults = mod.getWafFingerprintResults;
    getWafFingerprintSummary = mod.getWafFingerprintSummary;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  it("runs wafw00f and stores result in pipeline state", async () => {
    initProgressiveEvasion(8001, "red_team", "stealth", "operator1");

    const result = await runWafw00fFingerprint(
      8001,
      "https://target.com",
      { detected: true, vendor: "cloudflare", confidence: 50, bypassTechniques: ["bypass1"] },
      true
    );

    expect(result.target).toBe("https://target.com");
    expect(result.detected).toBe(true);
    expect(result.wafName).toBe("Cloudflare");
    expect(result.manufacturer).toBe("Cloudflare Inc.");
    expect(result.combinedConfidence).toBeGreaterThanOrEqual(50);
    expect(result.scannedAt).toBeGreaterThan(0);
    expect(result.scanDurationMs).toBeGreaterThanOrEqual(0);

    // Verify stored in state
    const results = getWafFingerprintResults(8001);
    expect(results).toHaveLength(1);
    expect(results![0].target).toBe("https://target.com");
  });

  it("creates a pause gate when WAF detected with high confidence", async () => {
    initProgressiveEvasion(8002, "red_team", "stealth", "operator1");

    await runWafw00fFingerprint(
      8002,
      "https://target.com",
      { detected: true, vendor: "cloudflare", confidence: 55, bypassTechniques: [] },
      true
    );

    const state = getProgressiveEvasionState(8002);
    const wafGates = state!.pauseGates.filter((g: any) => g.reason === "waf_detected");
    expect(wafGates.length).toBeGreaterThanOrEqual(1);
    expect(wafGates[0].status).toBe("pending");
    expect(wafGates[0].title).toContain("Cloudflare");
  });

  it("replaces existing result for same target on re-scan", async () => {
    initProgressiveEvasion(8003, "red_team", "stealth", "operator1");

    await runWafw00fFingerprint(8003, "https://target.com", null, true);
    await runWafw00fFingerprint(8003, "https://target.com", null, true);

    const results = getWafFingerprintResults(8003);
    expect(results).toHaveLength(1); // Not duplicated
  });

  it("handles scan server errors gracefully", async () => {
    // Override the mock to simulate failure
    vi.doMock("./lib/scan-server-executor", () => ({
      executeTool: vi.fn().mockRejectedValue(new Error("SSH connection refused")),
    }));

    // Re-import to pick up new mock
    vi.resetModules();
    const mod = await import("./lib/progressive-evasion-pipeline");
    mod.initProgressiveEvasion(8004, "red_team", "stealth", "operator1");

    const result = await mod.runWafw00fFingerprint(
      8004,
      "https://target.com",
      null,
      true
    );

    expect(result.detected).toBe(false);
    expect(result.error).toContain("SSH connection refused");
    expect(result.combinedConfidence).toBe(0);
  });
});

describe("wafw00f integration - WafFingerprintResult interface", () => {
  it("WafFingerprintResult type has all required fields", async () => {
    const mod = await import("./lib/progressive-evasion-pipeline");
    const state = mod.initProgressiveEvasion(7001, "pentest", "low", "op1");

    // Manually push a result to verify the type shape
    const mockResult: any = {
      target: "https://example.com",
      wafName: "Imperva",
      manufacturer: "Imperva Inc.",
      detected: true,
      allDetected: [{ name: "Imperva", manufacturer: "Imperva Inc." }],
      headerBasedResult: { detected: true, vendor: "incapsula", confidence: 45 },
      combinedConfidence: 75,
      methodsAgree: true,
      bypassTechniques: ["technique1"],
      scannedAt: Date.now(),
      scanDurationMs: 2000,
      rawOutput: '{"firewall": "Imperva"}',
    };
    state.wafFingerprintResults.push(mockResult);

    const results = mod.getWafFingerprintResults(7001);
    expect(results).toHaveLength(1);
    expect(results![0].target).toBe("https://example.com");
    expect(results![0].wafName).toBe("Imperva");
    expect(results![0].combinedConfidence).toBe(75);
    expect(results![0].methodsAgree).toBe(true);
  });
});

describe("wafw00f integration - getWafFingerprintSummary", () => {
  it("correctly summarizes mixed results", async () => {
    const mod = await import("./lib/progressive-evasion-pipeline");
    const state = mod.initProgressiveEvasion(7002, "red_team", "stealth", "op1");

    // Push various results
    state.wafFingerprintResults.push(
      {
        target: "https://a.com",
        wafName: "Cloudflare",
        manufacturer: "Cloudflare Inc.",
        detected: true,
        allDetected: [{ name: "Cloudflare", manufacturer: "Cloudflare Inc." }],
        headerBasedResult: { detected: true, vendor: "cloudflare", confidence: 60 },
        combinedConfidence: 90,
        methodsAgree: true,
        bypassTechniques: [],
        scannedAt: Date.now(),
        scanDurationMs: 1000,
      },
      {
        target: "https://b.com",
        wafName: "Cloudflare",
        manufacturer: "Cloudflare Inc.",
        detected: true,
        allDetected: [{ name: "Cloudflare", manufacturer: "Cloudflare Inc." }],
        headerBasedResult: { detected: false, vendor: null, confidence: 0 },
        combinedConfidence: 60,
        methodsAgree: false,
        bypassTechniques: [],
        scannedAt: Date.now(),
        scanDurationMs: 1500,
      },
      {
        target: "https://c.com",
        wafName: null,
        manufacturer: null,
        detected: false,
        allDetected: [],
        headerBasedResult: null,
        combinedConfidence: 0,
        methodsAgree: true,
        bypassTechniques: [],
        scannedAt: Date.now(),
        scanDurationMs: 800,
      },
      {
        target: "https://d.com",
        wafName: null,
        manufacturer: null,
        detected: false,
        allDetected: [],
        headerBasedResult: null,
        combinedConfidence: 0,
        methodsAgree: true,
        bypassTechniques: [],
        scannedAt: Date.now(),
        scanDurationMs: 0,
        error: "Connection timed out",
      }
    );

    const summary = mod.getWafFingerprintSummary(7002);
    expect(summary).not.toBeNull();
    expect(summary!.totalTargets).toBe(4);
    expect(summary!.wafDetected).toBe(2);
    expect(summary!.noWaf).toBe(1);
    expect(summary!.errors).toBe(1);
    expect(summary!.highConfidence).toBe(1); // Only 90% one
    expect(summary!.vendors["Cloudflare"]).toBe(2);
    expect(summary!.methodAgreement.agree).toBe(1); // Only https://a.com has headerBasedResult + agrees
    expect(summary!.methodAgreement.disagree).toBe(1); // https://b.com has headerBasedResult + disagrees
  });
});
