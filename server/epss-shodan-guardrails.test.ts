/**
 * Tests for:
 * 1. EPSS Service — fetchEpssScores, prioritizeCveWithEpss, batchPrioritizeCves, buildEpssContextForLlm
 * 2. Shodan-KEV Cross-Validation — verifyCvesWithShodanData, extractShodanVersionEvidence
 * 3. Exploit Guardrails Dashboard Router — tRPC endpoints
 * 4. Exploit Guardrails Module — runGuardrails, detectDrift
 * 5. RDP/VoIP Knowledge Module
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── EPSS Service Tests ──────────────────────────────────────────────────────

describe("EPSS Service", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("should export fetchEpssScores function", async () => {
    const mod = await import("./lib/epss-service");
    expect(mod.fetchEpssScores).toBeDefined();
    expect(typeof mod.fetchEpssScores).toBe("function");
  });

  it("should export prioritizeCveWithEpss function", async () => {
    const mod = await import("./lib/epss-service");
    expect(mod.prioritizeCveWithEpss).toBeDefined();
    expect(typeof mod.prioritizeCveWithEpss).toBe("function");
  });

  it("should export batchPrioritizeCves function", async () => {
    const mod = await import("./lib/epss-service");
    expect(mod.batchPrioritizeCves).toBeDefined();
    expect(typeof mod.batchPrioritizeCves).toBe("function");
  });

  it("should export buildEpssContextForLlm function", async () => {
    const mod = await import("./lib/epss-service");
    expect(mod.buildEpssContextForLlm).toBeDefined();
    expect(typeof mod.buildEpssContextForLlm).toBe("function");
  });

  it("fetchEpssScores should return EpssBatchResult with empty scores for empty CVE list", async () => {
    const { fetchEpssScores } = await import("./lib/epss-service");
    const result = await fetchEpssScores([]);
    expect(result).toBeDefined();
    expect(result.scores).toEqual([]);
    expect(result.missing).toEqual([]);
    expect(result.fetchedAt).toBeGreaterThan(0);
  });

  it("fetchEpssScores should handle API errors gracefully", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("Network error"));
    try {
      const { fetchEpssScores } = await import("./lib/epss-service");
      const result = await fetchEpssScores(["CVE-2024-1234"]);
      // Should return a valid result object (not throw)
      expect(result).toBeDefined();
      expect(result.scores).toBeDefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("fetchEpssScores should parse valid FIRST.org API response", async () => {
    const originalFetch = globalThis.fetch;
    // Clear cache first
    const { clearEpssCache } = await import("./lib/epss-service");
    clearEpssCache();
    
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        status: "OK",
        "status-code": 200,
        version: "1.0",
        total: 1,
        data: [
          { cve: "CVE-2024-1234", epss: "0.85432", percentile: "0.97123", date: "2024-01-01" }
        ],
      }),
    });
    try {
      const { fetchEpssScores } = await import("./lib/epss-service");
      const result = await fetchEpssScores(["CVE-2024-1234"]);
      expect(result.scores.length).toBe(1);
      expect(result.scores[0].cve).toBe("CVE-2024-1234");
      expect(result.scores[0].epss).toBeCloseTo(0.85432, 3);
      expect(result.scores[0].percentile).toBeCloseTo(0.97123, 3);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("prioritizeCveWithEpss should return CRITICAL for KEV + high EPSS", async () => {
    const { prioritizeCveWithEpss } = await import("./lib/epss-service");
    const result = prioritizeCveWithEpss("CVE-2024-1234", 0.85, 0.97, true);
    expect(result.priorityTier).toBe("critical");
    expect(result.kevListed).toBe(true);
    expect(result.rationale).toContain("CRITICAL");
  });

  it("prioritizeCveWithEpss should return HIGH for KEV + low EPSS", async () => {
    const { prioritizeCveWithEpss } = await import("./lib/epss-service");
    const result = prioritizeCveWithEpss("CVE-2024-5678", 0.05, 0.3, true);
    expect(result.priorityTier).toBe("high");
    expect(result.kevListed).toBe(true);
  });

  it("prioritizeCveWithEpss should return HIGH for non-KEV + very high EPSS", async () => {
    const { prioritizeCveWithEpss } = await import("./lib/epss-service");
    const result = prioritizeCveWithEpss("CVE-2024-9999", 0.45, 0.98, false);
    expect(result.priorityTier).toBe("high");
    expect(result.kevListed).toBe(false);
  });

  it("prioritizeCveWithEpss should return LOW for non-KEV + low EPSS", async () => {
    const { prioritizeCveWithEpss } = await import("./lib/epss-service");
    const result = prioritizeCveWithEpss("CVE-2024-0001", 0.02, 0.1, false);
    expect(result.priorityTier).toBe("low");
  });

  it("buildEpssContextForLlm should produce readable context string", async () => {
    const { buildEpssContextForLlm } = await import("./lib/epss-service");
    const prioritizations = [
      { cve: "CVE-2024-1234", epss: 0.85, percentile: 0.97, kevListed: true, priorityTier: "critical" as const, rationale: "CRITICAL: test" },
      { cve: "CVE-2024-5678", epss: 0.02, percentile: 0.1, kevListed: false, priorityTier: "low" as const, rationale: "LOW: test" },
    ];
    const context = buildEpssContextForLlm(prioritizations);
    expect(typeof context).toBe("string");
    expect(context).toContain("CVE-2024-1234");
    expect(context.length).toBeGreaterThan(20);
  });

  it("clearEpssCache should reset the cache", async () => {
    const { clearEpssCache, getEpssCacheStats } = await import("./lib/epss-service");
    clearEpssCache();
    const stats = getEpssCacheStats();
    expect(stats.size).toBe(0);
  });
});

// ─── Shodan-KEV Cross-Validation Tests ───────────────────────────────────────

describe("Shodan-KEV Cross-Validation", () => {
  it("should export verifyCvesWithShodanData function", async () => {
    const mod = await import("./lib/shodan-verifier");
    expect(mod.verifyCvesWithShodanData).toBeDefined();
    expect(typeof mod.verifyCvesWithShodanData).toBe("function");
  });

  it("should export enrichAssetsWithShodanData function", async () => {
    const mod = await import("./lib/shodan-verifier");
    expect(mod.enrichAssetsWithShodanData).toBeDefined();
    expect(typeof mod.enrichAssetsWithShodanData).toBe("function");
  });

  it("should export isProtocolVersion utility", async () => {
    const { isProtocolVersion } = await import("./lib/shodan-verifier");
    expect(isProtocolVersion).toBeDefined();
    expect(isProtocolVersion("httpd", "1.1")).toBe(true);
    expect(isProtocolVersion("httpd", "2")).toBe(true);
    expect(isProtocolVersion("nginx", "1.18.0")).toBe(false);
    expect(isProtocolVersion("Apache", "2.4.49")).toBe(false);
  });

  it("extractShodanVersionEvidence should extract from observations", async () => {
    const { extractShodanVersionEvidence } = await import("./lib/shodan-verifier");
    const observations = [
      {
        assetId: "test-1",
        domain: "example.com",
        assetType: "ip" as const,
        source: "shodan",
        observedAt: new Date(),
        tags: [],
        evidence: {
          port: 80,
          product: "Apache httpd",
          version: "2.4.49",
          ip: "1.2.3.4",
          hostname: "example.com",
          vulns: ["CVE-2021-41773"],
        },
        attribution: { provider: "shodan", method: "banner grab" },
      },
    ];
    const evidence = extractShodanVersionEvidence(observations);
    expect(evidence.length).toBeGreaterThanOrEqual(1);
  });

  it("verifyCvesWithShodanData should return results for each analysis", async () => {
    const { verifyCvesWithShodanData } = await import("./lib/shodan-verifier");
    const analyses = [
      {
        asset: {
          assetId: "test-1",
          hostname: "example.com",
          assetType: "subdomain",
          dnsRecords: { A: ["1.2.3.4"] },
          assetClasses: [],
          tags: [],
        },
        carverScores: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
        shockScores: { surprise: 5, habituation: 5, outrage: 5, cascading: 5, kinetic: 5 },
        missionImpactScore: 50, suggestedTier: "high", hybridRiskScore: 50, riskBand: "high",
        cvssEstimate: 7.5,
        contextIndicators: { exposure: 50, recognizability: 50, confidence: 50 },
        postureFindings: [
          { id: "v1", title: "Apache Path Traversal", severity: "critical", category: "vulnerability",
            cve: "CVE-2021-41773", evidence: "Shodan", remediation: "Update", source: "shodan", corroborationTier: "confirmed" as const },
        ],
        testVectors: [], confidence: 80,
        assetCriticalityScore: 50, assetCriticalityBand: "high",
        vulnRiskScore: 50, vulnRiskBand: "high",
        impactScore: 50, likelihoodScore: 50,
        missionFunction: "web_server", essentialService: "web_hosting",
        businessImpactLevel: "significant", deviceType: "server",
        platformType: "linux_server", missionJustification: "Primary web server",
      },
    ];
    const observations = [
      {
        assetId: "obs-1", domain: "example.com", assetType: "ip" as const,
        source: "shodan", observedAt: new Date(), tags: [],
        evidence: { port: 80, product: "Apache httpd", version: "2.4.49", ip: "1.2.3.4", hostname: "example.com", vulns: ["CVE-2021-41773"] },
        attribution: { provider: "shodan", method: "banner grab" },
      },
    ];
    const result = verifyCvesWithShodanData(analyses as any, observations);
    expect(result).toBeDefined();
    expect(result.verified).toBeDefined();
    expect(Array.isArray(result.verified)).toBe(true);
    expect(typeof result.summary).toBe("string");
  });
});

// ─── Exploit Guardrails Dashboard Router Tests ───────────────────────────────

describe("Exploit Guardrails Dashboard Router", () => {
  it("should export all required endpoints", async () => {
    const { exploitGuardrailsDashboardRouter } = await import("./routers/exploit-guardrails-dashboard");
    expect(exploitGuardrailsDashboardRouter).toBeDefined();
    expect(exploitGuardrailsDashboardRouter.getGuardrailStats).toBeDefined();
    expect(exploitGuardrailsDashboardRouter.getRecentExploitViolations).toBeDefined();
    expect(exploitGuardrailsDashboardRouter.getRecentLlmViolations).toBeDefined();
    expect(exploitGuardrailsDashboardRouter.getRecentEvidenceAuditFailures).toBeDefined();
    expect(exploitGuardrailsDashboardRouter.getViolationsByEngagement).toBeDefined();
    expect(exploitGuardrailsDashboardRouter.getDriftSignalBreakdown).toBeDefined();
  });

  it("should have 6 endpoints total", async () => {
    const { exploitGuardrailsDashboardRouter } = await import("./routers/exploit-guardrails-dashboard");
    const endpointKeys = Object.keys(exploitGuardrailsDashboardRouter);
    expect(endpointKeys.length).toBe(6);
  });
});

// ─── Exploit Guardrails Module Tests ─────────────────────────────────────────

describe("Exploit Guardrails Module", () => {
  it("should export runGuardrails function", async () => {
    const mod = await import("./lib/exploit-guardrails");
    expect(mod.runGuardrails).toBeDefined();
    expect(typeof mod.runGuardrails).toBe("function");
  });

  it("should export detectDrift function", async () => {
    const mod = await import("./lib/exploit-guardrails");
    expect(mod.detectDrift).toBeDefined();
    expect(typeof mod.detectDrift).toBe("function");
  });

  it("runGuardrails should block exploit with fabricated CVE", async () => {
    const { runGuardrails } = await import("./lib/exploit-guardrails");
    const result = runGuardrails(
      {
        cveId: "CVE-2024-00000",
        targetPort: 80,
        targetHostname: "192.168.1.1",
        targetService: "http",
        confidence: 90,
        code: "#!/bin/bash\ncurl http://192.168.1.1/exploit CVE-2024-00000",
        assumedTechnologies: ["Apache"],
        reasoningChain: { context: "test" },
      },
      {
        confirmedPorts: [{ port: 80, service: "http" }],
        confirmedTechnologies: ["Apache"],
        confirmedCVEs: [],
        scopeTargets: ["192.168.1.1"],
        targetHostname: "192.168.1.1",
        reconEvidence: "Port 80 open",
      }
    );
    expect(result.passed).toBe(false);
    expect(result.blockedReasons.length).toBeGreaterThan(0);
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it("runGuardrails should pass valid exploit proposal", async () => {
    const { runGuardrails } = await import("./lib/exploit-guardrails");
    const result = runGuardrails(
      {
        cveId: "CVE-2021-41773",
        targetPort: 80,
        targetHostname: "192.168.1.1",
        targetService: "http",
        confidence: 85,
        code: "#!/bin/bash\ncurl http://192.168.1.1/cgi-bin/.%2e/%2e%2e/etc/passwd",
        assumedTechnologies: ["Apache"],
        reasoningChain: { context: "Apache 2.4.49 path traversal CVE-2021-41773" },
      },
      {
        confirmedPorts: [{ port: 80, service: "http", version: "Apache/2.4.49" }],
        confirmedTechnologies: ["Apache"],
        confirmedCVEs: ["CVE-2021-41773"],
        scopeTargets: ["192.168.1.1"],
        targetHostname: "192.168.1.1",
        reconEvidence: "Port 80 open, Apache 2.4.49",
      }
    );
    expect(result.passed).toBe(true);
    expect(result.riskScore).toBeLessThan(40);
  });

  it("runGuardrails should flag port hallucination", async () => {
    const { runGuardrails } = await import("./lib/exploit-guardrails");
    const result = runGuardrails(
      {
        cveId: "CVE-2021-41773",
        targetPort: 8443,
        targetHostname: "192.168.1.1",
        targetService: "https",
        confidence: 80,
        code: "#!/bin/bash\ncurl https://192.168.1.1:8443/exploit",
        assumedTechnologies: ["Apache"],
        reasoningChain: { context: "" },
      },
      {
        confirmedPorts: [{ port: 80, service: "http" }, { port: 443, service: "https" }],
        confirmedTechnologies: ["Apache"],
        confirmedCVEs: ["CVE-2021-41773"],
        scopeTargets: ["192.168.1.1"],
        targetHostname: "192.168.1.1",
        reconEvidence: "Ports 80, 443 open",
      }
    );
    const portCheck = result.checks.find(c => c.name.toLowerCase().includes("port"));
    expect(portCheck).toBeDefined();
    if (portCheck) {
      expect(portCheck.passed).toBe(false);
    }
  });

  it("runGuardrails should detect scope creep", async () => {
    const { runGuardrails } = await import("./lib/exploit-guardrails");
    const result = runGuardrails(
      {
        cveId: "CVE-2021-41773",
        targetPort: 80,
        targetHostname: "10.0.0.1",
        targetService: "http",
        confidence: 80,
        code: "#!/bin/bash\ncurl http://10.0.0.1/exploit",
        assumedTechnologies: ["Apache"],
        reasoningChain: { context: "" },
      },
      {
        confirmedPorts: [{ port: 80, service: "http" }],
        confirmedTechnologies: ["Apache"],
        confirmedCVEs: ["CVE-2021-41773"],
        scopeTargets: ["192.168.1.1"],
        targetHostname: "10.0.0.1",
        reconEvidence: "Port 80 open",
      }
    );
    const scopeCheck = result.checks.find(c => c.name.toLowerCase().includes("scope"));
    expect(scopeCheck).toBeDefined();
  });

  it("runGuardrails should calculate risk score for multiple violations", async () => {
    const { runGuardrails } = await import("./lib/exploit-guardrails");
    const result = runGuardrails(
      {
        cveId: "CVE-2024-00000",
        targetPort: 9999,
        targetHostname: "10.0.0.1",
        targetService: "unknown",
        confidence: 99,
        code: "#!/bin/bash\nrm -rf /",
        assumedTechnologies: ["Windows"],
        reasoningChain: { context: "" },
      },
      {
        confirmedPorts: [{ port: 80, service: "http" }],
        confirmedTechnologies: ["Apache"],
        confirmedCVEs: [],
        scopeTargets: ["192.168.1.1"],
        targetHostname: "10.0.0.1",
        reconEvidence: "",
      }
    );
    expect(result.riskScore).toBeGreaterThan(20);
    expect(result.checks.length).toBeGreaterThan(0);
  });
});

// ─── RDP/VoIP Knowledge Module Tests ─────────────────────────────────────────

describe("RDP/VoIP Knowledge Module", () => {
  it("should export RDP and VoIP knowledge", async () => {
    const mod = await import("./lib/knowledge/rdp-voip-conferencing-knowledge");
    expect(mod).toBeDefined();
    const keys = Object.keys(mod);
    expect(keys.length).toBeGreaterThan(0);
  });

  it("should contain RDP exploit knowledge", async () => {
    const mod = await import("./lib/knowledge/rdp-voip-conferencing-knowledge");
    const content = JSON.stringify(mod);
    expect(content).toContain("RDP");
  });

  it("should contain VoIP/SIP exploit knowledge", async () => {
    const mod = await import("./lib/knowledge/rdp-voip-conferencing-knowledge");
    const content = JSON.stringify(mod);
    expect(content.toLowerCase()).toContain("sip");
  });

  it("should contain BlueKeep CVE reference", async () => {
    const mod = await import("./lib/knowledge/rdp-voip-conferencing-knowledge");
    const content = JSON.stringify(mod);
    expect(content).toContain("CVE-2019-0708");
  });
});
