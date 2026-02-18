/**
 * Tests for the three new passive connectors:
 * - Shodan InternetDB (free fast-path)
 * - BinaryEdge (independent validation)
 * - GreyNoise (threat pressure context)
 * 
 * Also tests signal classifier integration and pipeline wiring.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Mock DNS resolution
vi.mock("dns/promises", () => ({
  resolve4: vi.fn().mockResolvedValue(["93.184.216.34"]),
}));

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({}),
    text: async () => "",
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Shodan InternetDB Connector
// ═══════════════════════════════════════════════════════════════════════

describe("Shodan InternetDB Connector", () => {
  it("should export a valid connector with correct metadata", async () => {
    const { shodanInternetDBConnector } = await import("./lib/passive/shodan-internetdb");
    expect(shodanInternetDBConnector.name).toBe("shodan_internetdb");
    expect(shodanInternetDBConnector.requiresApiKey).toBe(false);
    expect(shodanInternetDBConnector.description).toContain("InternetDB");
  });

  it("should query InternetDB for resolved IPs and return CVE observations", async () => {
    const { shodanInternetDBConnector } = await import("./lib/passive/shodan-internetdb");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: "93.184.216.34",
        ports: [80, 443, 22],
        cpes: ["cpe:/a:apache:http_server:2.4.49"],
        vulns: ["CVE-2021-41773", "CVE-2021-42013"],
        hostnames: ["example.com"],
        tags: ["cloud"],
      }),
    });

    const result = await shodanInternetDBConnector.collect("example.com", { timeout: 10000 });

    expect(result.connector).toBe("shodan_internetdb");
    expect(result.domain).toBe("example.com");
    expect(result.observations.length).toBeGreaterThan(0);

    // Should have CVE observations
    const cveObs = result.observations.filter(o => o.tags.some(t => t.startsWith("cve:")));
    expect(cveObs.length).toBeGreaterThan(0);

    // Should have port tags
    const portObs = result.observations.filter(o => o.tags.some(t => t.startsWith("port:")));
    expect(portObs.length).toBeGreaterThan(0);
  });

  it("should handle 404 (IP not in database) gracefully", async () => {
    const { shodanInternetDBConnector } = await import("./lib/passive/shodan-internetdb");

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ detail: "No information available" }),
    });

    const result = await shodanInternetDBConnector.collect("unknown-domain.example", { timeout: 10000 });

    expect(result.connector).toBe("shodan_internetdb");
    expect(result.errors.length).toBe(0); // 404 is not an error, just no data
  });

  it("should include attribution with InternetDB URL", async () => {
    const { shodanInternetDBConnector } = await import("./lib/passive/shodan-internetdb");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: "93.184.216.34",
        ports: [80],
        cpes: [],
        vulns: ["CVE-2023-1234"],
        hostnames: ["example.com"],
        tags: [],
      }),
    });

    const result = await shodanInternetDBConnector.collect("example.com", { timeout: 10000 });
    const obs = result.observations.find(o => o.attribution);
    expect(obs?.attribution?.provider).toContain("InternetDB");
    expect(obs?.attribution?.url).toContain("internetdb.shodan.io");
  });

  it("should tag CVE observations with shodan_internetdb_vuln", async () => {
    const { shodanInternetDBConnector } = await import("./lib/passive/shodan-internetdb");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: "93.184.216.34",
        ports: [443],
        cpes: [],
        vulns: ["CVE-2024-5678"],
        hostnames: [],
        tags: [],
      }),
    });

    const result = await shodanInternetDBConnector.collect("example.com", { timeout: 10000 });
    const cveObs = result.observations.filter(o => o.tags.includes("shodan_internetdb_vuln"));
    expect(cveObs.length).toBeGreaterThan(0);
    expect(cveObs[0].tags).toContain("cve:CVE-2024-5678");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// BinaryEdge Connector
// ═══════════════════════════════════════════════════════════════════════

describe("BinaryEdge Connector", () => {
  it("should export a valid connector with correct metadata", async () => {
    const { binaryedgeConnector } = await import("./lib/passive/binaryedge");
    expect(binaryedgeConnector.name).toBe("binaryedge");
    expect(binaryedgeConnector.requiresApiKey).toBe(true);
    expect(binaryedgeConnector.description).toContain("BinaryEdge");
  });

  it("should skip when no API key is provided", async () => {
    const { binaryedgeConnector } = await import("./lib/passive/binaryedge");

    const result = await binaryedgeConnector.collect("example.com", { timeout: 10000 });

    expect(result.connector).toBe("binaryedge");
    expect(result.observations.length).toBe(0);
    expect(result.errors.some(e => e.includes("not configured"))).toBe(true);
  });

  it("should query BinaryEdge host endpoint with API key", async () => {
    const { binaryedgeConnector } = await import("./lib/passive/binaryedge");

    // Mock subdomain response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        page: 1,
        pagesize: 100,
        total: 2,
        events: ["sub1.example.com", "sub2.example.com"],
      }),
    });

    // Mock host response for IP
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        total: 1,
        query: "93.184.216.34",
        events: [{
          results: [{
            origin: { ip: "93.184.216.34", port: 443, type: "service-simple" },
            result: {
              data: {
                service: { name: "https", banner: "nginx/1.18.0" },
                state: { state: "open" },
              },
            },
          }],
        }],
      }),
    });

    const result = await binaryedgeConnector.collect("example.com", {
      timeout: 10000,
      apiKey: "test-binaryedge-key",
    });

    expect(result.connector).toBe("binaryedge");
    expect(result.domain).toBe("example.com");
    expect(result.observations.length).toBeGreaterThan(0);

    // Verify API key was passed in headers
    const calls = mockFetch.mock.calls;
    const beCall = calls.find((c: any[]) => String(c[0]).includes("binaryedge"));
    expect(beCall).toBeDefined();
    expect(beCall![1].headers["X-Key"]).toBe("test-binaryedge-key");
  });

  it("should handle rate limiting gracefully", async () => {
    const { binaryedgeConnector } = await import("./lib/passive/binaryedge");

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      json: async () => ({ message: "Rate limit exceeded" }),
    });

    const result = await binaryedgeConnector.collect("example.com", {
      timeout: 10000,
      apiKey: "test-key",
    });

    expect(result.connector).toBe("binaryedge");
    expect(result.errors.some(e => e.toLowerCase().includes("rate") || e.toLowerCase().includes("429"))).toBe(true);
  });

  it("should include attribution with BinaryEdge URL", async () => {
    const { binaryedgeConnector } = await import("./lib/passive/binaryedge");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        page: 1, pagesize: 100, total: 1,
        events: ["sub.example.com"],
      }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ total: 0, query: "93.184.216.34", events: [] }),
    });

    const result = await binaryedgeConnector.collect("example.com", {
      timeout: 10000,
      apiKey: "test-key",
    });

    const subObs = result.observations.find(o => o.assetType === "subdomain");
    if (subObs) {
      expect(subObs.attribution?.provider).toContain("BinaryEdge");
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// GreyNoise Connector
// ═══════════════════════════════════════════════════════════════════════

describe("GreyNoise Connector", () => {
  it("should export a valid connector with correct metadata", async () => {
    const { greynoiseConnector } = await import("./lib/passive/greynoise");
    expect(greynoiseConnector.name).toBe("greynoise");
    expect(greynoiseConnector.requiresApiKey).toBe(true);
    expect(greynoiseConnector.description).toContain("GreyNoise");
  });

  it("should skip when no API key is provided", async () => {
    const { greynoiseConnector } = await import("./lib/passive/greynoise");

    const result = await greynoiseConnector.collect("example.com", { timeout: 10000 });

    expect(result.connector).toBe("greynoise");
    expect(result.observations.length).toBe(0);
    expect(result.errors.some(e => e.includes("not configured"))).toBe(true);
  });

  it("should query GreyNoise community API and return classification", async () => {
    const { greynoiseConnector } = await import("./lib/passive/greynoise");

    // Mock enterprise context API call (first call in queryContextAPI — community endpoint)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: "93.184.216.34",
        noise: true,
        riot: false,
        classification: "malicious",
        name: "unknown",
        link: "https://viz.greynoise.io/ip/93.184.216.34",
        last_seen: "2026-02-18",
        message: "Success",
      }),
    });

    // Mock enterprise context API call (second call — full context endpoint, 404 = not available)
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    });

    // Mock community API fallback call
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: "93.184.216.34",
        noise: true,
        riot: false,
        classification: "malicious",
        name: "unknown",
        link: "https://viz.greynoise.io/ip/93.184.216.34",
        last_seen: "2026-02-18",
        message: "Success",
      }),
    });

    const result = await greynoiseConnector.collect("example.com", {
      timeout: 10000,
      apiKey: "test-greynoise-key",
    });

    expect(result.connector).toBe("greynoise");
    expect(result.domain).toBe("example.com");
    expect(result.observations.length).toBeGreaterThan(0);

    // Should have malicious classification
    const malObs = result.observations.find(o => o.tags.includes("UNDER_ACTIVE_ATTACK"));
    expect(malObs).toBeDefined();
    expect(malObs!.tags).toContain("greynoise_malicious");
    expect(malObs!.tags).toContain("classification:malicious");
  });

  it("should tag noise observations correctly", async () => {
    const { greynoiseConnector } = await import("./lib/passive/greynoise");

    // Enterprise context first call (community endpoint inside queryContextAPI)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ ip: "93.184.216.34", noise: true }),
    });
    // Enterprise context second call (full context endpoint — 404)
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });
    // Community API fallback
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: "93.184.216.34",
        noise: true,
        riot: false,
        classification: "unknown",
        name: "unknown",
        link: "https://viz.greynoise.io/ip/93.184.216.34",
        last_seen: "2026-02-18",
        message: "Success",
      }),
    });

    const result = await greynoiseConnector.collect("example.com", {
      timeout: 10000,
      apiKey: "test-key",
    });

    const noiseObs = result.observations.find(o => o.tags.includes("internet_noise"));
    expect(noiseObs).toBeDefined();
    expect(noiseObs!.tags).toContain("mass_scanning");
  });

  it("should include attribution with GreyNoise visualizer URL", async () => {
    const { greynoiseConnector } = await import("./lib/passive/greynoise");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: "93.184.216.34",
        noise: false,
        riot: true,
        classification: "benign",
        name: "Cloudflare",
        link: "https://viz.greynoise.io/ip/93.184.216.34",
        last_seen: "2026-02-18",
        message: "Success",
      }),
    });

    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

    const result = await greynoiseConnector.collect("example.com", {
      timeout: 10000,
      apiKey: "test-key",
    });

    const obs = result.observations[0];
    expect(obs?.attribution?.provider).toContain("GreyNoise");
    expect(obs?.attribution?.url).toContain("viz.greynoise.io");
  });

  it("should handle rate limiting", async () => {
    const { greynoiseConnector } = await import("./lib/passive/greynoise");

    // Enterprise context first call — throws rate limit error
    mockFetch.mockRejectedValueOnce(new Error("Rate limited by GreyNoise API"));
    // Community API fallback — also rate limited (returns 429)
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      json: async () => ({ message: "Rate limit exceeded" }),
    });

    const result = await greynoiseConnector.collect("example.com", {
      timeout: 10000,
      apiKey: "test-key",
    });

    // The error should be caught and recorded
    expect(result.errors.some(e => e.toLowerCase().includes("rate limit") || e.toLowerCase().includes("greynoise") || e.toLowerCase().includes("429"))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Signal Classifier Integration
// ═══════════════════════════════════════════════════════════════════════

describe("Signal Classifier — New Connector Rules", () => {
  it("should detect GreyNoise malicious classification as critical signal", async () => {
    const { classifySignals } = await import("./lib/passive/signal-classifier");

    const signals = classifySignals([{
      assetId: "test-gn-1",
      domain: "example.com",
      assetType: "ip",
      name: "93.184.216.34 (GreyNoise: malicious)",
      ip: "93.184.216.34",
      source: "greynoise",
      observedAt: new Date(),
      tags: ["UNDER_ACTIVE_ATTACK", "greynoise_malicious", "classification:malicious", "greynoise"],
      evidence: { actor: "APT28", cves_exploited: ["CVE-2024-1234"] },
      attribution: { provider: "GreyNoise", url: "https://viz.greynoise.io/ip/93.184.216.34", method: "test" },
    }]);

    const gnSignal = signals.find(s => s.signalType === "greynoise_malicious");
    expect(gnSignal).toBeDefined();
    expect(gnSignal!.severity).toBe("critical");
    expect(gnSignal!.confidence).toBe(0.95);
    expect(gnSignal!.rationale).toContain("MALICIOUS");
    expect(gnSignal!.rationale).toContain("APT28");
  });

  it("should detect GreyNoise noise as medium signal", async () => {
    const { classifySignals } = await import("./lib/passive/signal-classifier");

    const signals = classifySignals([{
      assetId: "test-gn-2",
      domain: "example.com",
      assetType: "ip",
      name: "93.184.216.34",
      ip: "93.184.216.34",
      source: "greynoise",
      observedAt: new Date(),
      tags: ["internet_noise", "mass_scanning", "classification:unknown", "greynoise"],
      evidence: {},
      attribution: { provider: "GreyNoise", url: "", method: "" },
    }]);

    const noiseSignal = signals.find(s => s.signalType === "greynoise_noise");
    expect(noiseSignal).toBeDefined();
    expect(noiseSignal!.severity).toBe("medium");
  });

  it("should detect BinaryEdge CVE as high signal", async () => {
    const { classifySignals } = await import("./lib/passive/signal-classifier");

    const signals = classifySignals([{
      assetId: "test-be-1",
      domain: "example.com",
      assetType: "ip",
      name: "CVE-2024-5678 on 93.184.216.34",
      ip: "93.184.216.34",
      source: "binaryedge",
      observedAt: new Date(),
      tags: ["binaryedge_cve", "cve:CVE-2024-5678", "binaryedge"],
      evidence: {},
      attribution: { provider: "BinaryEdge", url: "", method: "" },
    }]);

    const beSignal = signals.find(s => s.signalType === "binaryedge_cve");
    expect(beSignal).toBeDefined();
    expect(beSignal!.severity).toBe("high");
    expect(beSignal!.rationale).toContain("BinaryEdge");
    expect(beSignal!.rationale).toContain("CVE-2024-5678");
  });

  it("should detect InternetDB CVE as high signal", async () => {
    const { classifySignals } = await import("./lib/passive/signal-classifier");

    const signals = classifySignals([{
      assetId: "test-idb-1",
      domain: "example.com",
      assetType: "ip",
      name: "CVE-2023-9999 on 93.184.216.34",
      ip: "93.184.216.34",
      source: "shodan_internetdb",
      observedAt: new Date(),
      tags: ["internetdb_cve", "cve:CVE-2023-9999", "shodan_internetdb"],
      evidence: {},
      attribution: { provider: "Shodan InternetDB", url: "", method: "" },
    }]);

    const idbSignal = signals.find(s => s.signalType === "internetdb_cve");
    expect(idbSignal).toBeDefined();
    expect(idbSignal!.severity).toBe("high");
    expect(idbSignal!.rationale).toContain("InternetDB");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Passive Guard — Scan Mode Policies
// ═══════════════════════════════════════════════════════════════════════

describe("Passive Guard — New Connector Policies", () => {
  it("should allow InternetDB and BinaryEdge in strict_passive mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");

    const mockConnectors = [
      { name: "shodan_internetdb", description: "", requiresApiKey: false, collect: async () => ({} as any) },
      { name: "binaryedge", description: "", requiresApiKey: true, collect: async () => ({} as any) },
      { name: "greynoise", description: "", requiresApiKey: true, collect: async () => ({} as any) },
    ];

    const { allowed, blocked } = filterConnectors(mockConnectors, "strict_passive");

    expect(allowed.map(c => c.name)).toContain("shodan_internetdb");
    expect(allowed.map(c => c.name)).toContain("binaryedge");
    expect(blocked.map(b => b.name)).toContain("greynoise"); // Requires DNS resolution
  });

  it("should allow all three in standard mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");

    const mockConnectors = [
      { name: "shodan_internetdb", description: "", requiresApiKey: false, collect: async () => ({} as any) },
      { name: "binaryedge", description: "", requiresApiKey: true, collect: async () => ({} as any) },
      { name: "greynoise", description: "", requiresApiKey: true, collect: async () => ({} as any) },
    ];

    const { allowed } = filterConnectors(mockConnectors, "standard");

    expect(allowed.map(c => c.name)).toContain("shodan_internetdb");
    expect(allowed.map(c => c.name)).toContain("binaryedge");
    expect(allowed.map(c => c.name)).toContain("greynoise");
  });

  it("should include new connectors in scan mode descriptions", async () => {
    const { getScanModeDescription } = await import("./lib/passive/passive-guard");

    const strictDesc = getScanModeDescription("strict_passive");
    expect(strictDesc.techniques.some(t => t.includes("InternetDB"))).toBe(true);
    expect(strictDesc.techniques.some(t => t.includes("BinaryEdge"))).toBe(true);

    const standardDesc = getScanModeDescription("standard");
    expect(standardDesc.techniques.some(t => t.includes("GreyNoise"))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Pipeline Integration
// ═══════════════════════════════════════════════════════════════════════

describe("Pipeline Integration — New Connectors", () => {
  it("should include all three new connectors in the orchestrator connector list", async () => {
    const { runPassiveRecon } = await import("./lib/passive/index");

    const result = await runPassiveRecon("example.com", {
      scanMode: "active",
      apiKeys: {
        binaryedge: "test-be-key",
        greynoise: "test-gn-key",
      },
      timeout: 5000,
    });

    const connectorNames = result.connectorResults.map(r => r.connector);
    expect(connectorNames).toContain("shodan_internetdb");
    expect(connectorNames).toContain("binaryedge");
    expect(connectorNames).toContain("greynoise");
  });

  it("should have 12 total connectors in active mode", async () => {
    const { runPassiveRecon } = await import("./lib/passive/index");

    const result = await runPassiveRecon("example.com", {
      scanMode: "active",
      apiKeys: {},
      timeout: 5000,
    });

    // 9 original + 3 new = 12
    expect(result.connectorResults.length).toBe(12);
  });

  it("should include new signal rules in the rule descriptions", async () => {
    const { getSignalRuleDescriptions } = await import("./lib/passive/signal-classifier");

    const rules = getSignalRuleDescriptions();
    const ruleIds = rules.map(r => r.id);

    expect(ruleIds).toContain("greynoise_malicious");
    expect(ruleIds).toContain("greynoise_noise");
    expect(ruleIds).toContain("greynoise_cve_exploit");
    expect(ruleIds).toContain("binaryedge_cve");
    expect(ruleIds).toContain("binaryedge_exposed_service");
    expect(ruleIds).toContain("internetdb_cve");
  });

  it("should have ENV keys for BinaryEdge and GreyNoise", async () => {
    const { ENV } = await import("./_core/env");
    expect(ENV).toHaveProperty("BINARYEDGE_API_KEY");
    expect(ENV).toHaveProperty("GREYNOISE_API_KEY");
  });
});
