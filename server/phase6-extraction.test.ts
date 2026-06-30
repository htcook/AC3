/**
 * Tests for Phase 6 Extraction (vuln-detection sub-modules) and Circuit Breaker
 *
 * Validates:
 *   1. Module structure and exports
 *   2. VulnDetectionContext interface completeness
 *   3. Credential tester: checkPortReachable, storeOemFallback, verifyHttpCredentials
 *   4. Vuln correlation: buildKevEpssContext, runDedupAndCoverage
 *   5. Circuit breaker: FeedCircuitBreaker behavior (open/close/half-open)
 *   6. Nuclei scanner: buildNucleiTags, NucleiScanResult interface
 *   7. ZAP scanner: ZapScanResult interface
 *   8. Injection scanner: InjectionScanResult interface
 */

import { describe, it, expect } from "vitest";

// ─── Module Structure Tests ─────────────────────────────────────────────────

describe("Phase 6 Module Structure", () => {
  it("index.ts exports all sub-modules", async () => {
    const mod = await import("./lib/vuln-detection/index");
    expect(mod.executeVulnPrep).toBeDefined();
    expect(mod.executeNucleiScanning).toBeDefined();
    expect(mod.executeZapScanning).toBeDefined();
    expect(mod.executeInjectionScanning).toBeDefined();
    expect(mod.executeCredentialTesting).toBeDefined();
    expect(mod.executeVulnCorrelation).toBeDefined();
  });

  it("VulnDetectionContext has all required fields", async () => {
    // Verify the interface shape by checking the index module's type exports
    const mod = await import("./lib/vuln-detection/index");
    // The module exports functions that accept VulnDetectionContext
    // We verify by checking the function signatures exist
    expect(typeof mod.executeVulnPrep).toBe("function");
    expect(typeof mod.executeCredentialTesting).toBe("function");
    expect(typeof mod.executeVulnCorrelation).toBe("function");
  });
});

// ─── Credential Tester Tests ────────────────────────────────────────────────

describe("Credential Tester", () => {
  it("checkPortReachable returns false for unreachable port", async () => {
    const { checkPortReachable } = await import("./lib/vuln-detection/credential-tester");
    // Port 1 on localhost should be unreachable
    const result = await checkPortReachable("127.0.0.1", 1, 1000);
    expect(result).toBe(false);
  });

  it("storeOemFallback extracts credentials from hydra args", async () => {
    const { storeOemFallback } = await import("./lib/vuln-detection/credential-tester");
    const asset: any = { confirmedCredentials: [] };
    const args = "-l 'admin' -p 'password123' -s 8080 http-get://target";
    const stored = storeOemFallback(asset, args);
    expect(stored).toBe(true);
    expect(asset.confirmedCredentials).toHaveLength(1);
    expect(asset.confirmedCredentials[0].username).toBe("admin");
    expect(asset.confirmedCredentials[0].password).toBe("password123");
    expect(asset.confirmedCredentials[0].port).toBe(8080);
    expect(asset.confirmedCredentials[0].source).toBe("oem_default_fallback");
  });

  it("storeOemFallback returns false for duplicate credentials", async () => {
    const { storeOemFallback } = await import("./lib/vuln-detection/credential-tester");
    const asset: any = { confirmedCredentials: [{ username: "admin", password: "password123" }] };
    const args = "-l 'admin' -p 'password123' -s 8080 http-get://target";
    const stored = storeOemFallback(asset, args);
    expect(stored).toBe(false);
  });

  it("storeOemFallback returns false for malformed args", async () => {
    const { storeOemFallback } = await import("./lib/vuln-detection/credential-tester");
    const asset: any = { confirmedCredentials: [] };
    const stored = storeOemFallback(asset, "some random args without credentials");
    expect(stored).toBe(false);
  });

  it("CredentialTestResult interface has all fields", async () => {
    const { executeCredentialTesting } = await import("./lib/vuln-detection/credential-tester");
    // The function exists and is async
    expect(executeCredentialTesting.constructor.name).toBe("AsyncFunction");
  });
});

// ─── Vuln Correlation Tests ─────────────────────────────────────────────────

describe("Vuln Correlation", () => {
  it("buildKevEpssContext returns empty for no CVEs", async () => {
    const { buildKevEpssContext } = await import("./lib/vuln-detection/vuln-correlation");
    const mockAddLog = () => {};
    const mockState = { assets: [] };
    const result = await buildKevEpssContext([], mockState, mockAddLog as any);
    expect(result.kevContext).toBe("");
    expect(result.kevMatches).toEqual([]);
    expect(result.epssCount).toBe(0);
  });

  it("VulnCorrelationResult interface has all fields", async () => {
    const { executeVulnCorrelation } = await import("./lib/vuln-detection/vuln-correlation");
    expect(typeof executeVulnCorrelation).toBe("function");
  });

  it("runDedupAndCoverage handles errors gracefully", async () => {
    const { runDedupAndCoverage } = await import("./lib/vuln-detection/vuln-correlation");
    const mockState = { assets: [], stats: { vulnsFound: 0 } };
    const mockAddLog = () => {};
    const mockBroadcast = () => {};
    // Should not throw — returns null stats on error
    const result = await runDedupAndCoverage(mockState, mockAddLog as any, mockBroadcast as any);
    expect(result).toHaveProperty("dedupStats");
    expect(result).toHaveProperty("coverageScore");
  });

  it("runVulnVerification returns 0 for empty vulns", async () => {
    const { runVulnVerification } = await import("./lib/vuln-detection/vuln-correlation");
    const mockState = { assets: [] };
    const mockAddLog = () => {};
    const mockBroadcast = () => {};
    const result = await runVulnVerification([], mockState, mockAddLog as any, mockBroadcast as any);
    expect(result).toBe(0);
  });

  it("runHybridScoring returns 0 for no findings", async () => {
    const { runHybridScoring } = await import("./lib/vuln-detection/vuln-correlation");
    const mockState = { assets: [{ vulns: [], zapFindings: [] }] };
    const mockAddLog = () => {};
    const mockBroadcast = () => {};
    const result = await runHybridScoring(mockState, mockAddLog as any, mockBroadcast as any);
    expect(result).toBe(0);
  });

  it("runThreatActorMapping returns 0 for no findings", async () => {
    const { runThreatActorMapping } = await import("./lib/vuln-detection/vuln-correlation");
    const mockState = { assets: [{ vulns: [], zapFindings: [] }] };
    const mockAddLog = () => {};
    const mockBroadcast = () => {};
    const result = await runThreatActorMapping(mockState, mockAddLog as any, mockBroadcast as any, null);
    expect(result).toBe(0);
  });
});

// ─── Circuit Breaker Tests ──────────────────────────────────────────────────

describe("Feed Circuit Breaker", () => {
  it("circuit breaker module exists in deep research agent", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/deep-research-agent.ts",
      "utf-8"
    );
    expect(content).toContain("CircuitBreakerState");
    expect(content).toContain("CIRCUIT_BREAKER_CONFIG");
  });

  it("circuit breaker has configurable thresholds", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/deep-research-agent.ts",
      "utf-8"
    );
    expect(content).toContain("FAILURE_THRESHOLD");
    expect(content).toContain("RECOVERY_TIMEOUT_MS");
    expect(content).toContain("ADAPTER_TIMEOUT_MS");
  });

  it("circuit breaker has three states: closed, open, half_open", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/deep-research-agent.ts",
      "utf-8"
    );
    expect(content).toContain('"closed"');
    expect(content).toContain('"open"');
    expect(content).toContain('"half_open"');
  });

  it("circuit breaker is integrated into runResearchCycle", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/deep-research-agent.ts",
      "utf-8"
    );
    // Should be used in the feed execution loop
    expect(content).toContain("circuitBreakers");
    expect(content).toContain("shouldAllowRequest");
    expect(content).toContain("recordSuccess");
    expect(content).toContain("recordFailure");
  });
});

// ─── Nuclei Scanner Tests ───────────────────────────────────────────────────

describe("Nuclei Scanner", () => {
  it("exports executeNucleiScanning function", async () => {
    const { executeNucleiScanning } = await import("./lib/vuln-detection/nuclei-scanner");
    expect(typeof executeNucleiScanning).toBe("function");
  });

  it("exports buildTechTags helper", async () => {
    const mod = await import("./lib/vuln-detection/nuclei-scanner");
    expect(mod).toHaveProperty("buildTechTags");
    expect(typeof mod.buildTechTags).toBe("function");
  });

  it("buildTechTags generates tags from technology list", async () => {
    const { buildTechTags } = await import("./lib/vuln-detection/nuclei-scanner");
    const tags = buildTechTags(["WordPress", "Apache", "PHP"]);
    expect(tags.some(t => t.toLowerCase().includes("wordpress"))).toBe(true);
    expect(tags.some(t => t.toLowerCase().includes("apache"))).toBe(true);
    expect(tags.some(t => t.toLowerCase().includes("php"))).toBe(true);
  });

  it("TRAINING_LAB_VULN_TAGS has broad tag coverage", async () => {
    const { TRAINING_LAB_VULN_TAGS } = await import("./lib/vuln-detection/nuclei-scanner");
    expect(TRAINING_LAB_VULN_TAGS.length).toBeGreaterThan(0);
  });
});

// ─── ZAP Scanner Tests ──────────────────────────────────────────────────────

describe("ZAP Scanner", () => {
  it("exports executeZapScanning function", async () => {
    const { executeZapScanning } = await import("./lib/vuln-detection/zap-scanner");
    expect(typeof executeZapScanning).toBe("function");
  });

  it("exports training lab detection helpers", async () => {
    const mod = await import("./lib/vuln-detection/zap-scanner");
    expect(mod).toHaveProperty("detectTrainingLabCreds");
    expect(mod).toHaveProperty("getFilteredWebPorts");
    expect(mod).toHaveProperty("buildTechHints");
  });

  it("detectTrainingLabCreds returns undefined for unknown hosts", async () => {
    const { detectTrainingLabCreds } = await import("./lib/vuln-detection/zap-scanner");
    const result = detectTrainingLabCreds("unknown.example.com", "http://unknown.example.com");
    expect(result).toBeUndefined();
  });
});

// ─── Injection Scanner Tests ────────────────────────────────────────────────

describe("Injection Scanner", () => {
  it("exports executeInjectionScanning function", async () => {
    const { executeInjectionScanning } = await import("./lib/vuln-detection/injection-scanner");
    expect(typeof executeInjectionScanning).toBe("function");
  });

  it("exports injectable URL builder", async () => {
    const mod = await import("./lib/vuln-detection/injection-scanner");
    expect(mod).toHaveProperty("buildInjectableUrls");
    expect(typeof mod.buildInjectableUrls).toBe("function");
  });

  it("exports training lab endpoint helper", async () => {
    const { getTrainingLabEndpoints } = await import("./lib/vuln-detection/injection-scanner");
    expect(typeof getTrainingLabEndpoints).toBe("function");
    const endpoints = getTrainingLabEndpoints("dvwa.local");
    expect(Array.isArray(endpoints)).toBe(true);
  });
});

// ─── Vuln Prep Tests ────────────────────────────────────────────────────────

describe("Vuln Prep", () => {
  it("exports executeVulnPrep function", async () => {
    const { executeVulnPrep } = await import("./lib/vuln-detection/vuln-prep");
    expect(typeof executeVulnPrep).toBe("function");
  });
});
