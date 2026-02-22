/**
 * Dehashed Connector Tests
 * 
 * Tests for the Dehashed breach intelligence connector including:
 * - Module structure and exports
 * - Behavior when API key is missing
 * - Response parsing and observation generation
 * - Subdomain extraction from email domains
 * - IP association mapping
 * - Breach database attribution
 * - Summary observation generation
 * - Error handling (401, 429, timeout, malformed responses)
 * - Signal classifier integration for breach signals
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

describe("Dehashed Connector", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ─── Module Structure ─────────────────────────────────────────────

  it("should export dehashedConnector with correct metadata", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");
    expect(dehashedConnector).toBeDefined();
    expect(dehashedConnector.name).toBe("dehashed");
    expect(dehashedConnector.requiresApiKey).toBe(true);
    expect(dehashedConnector.description).toContain("breach");
    expect(typeof dehashedConnector.collect).toBe("function");
  });

  // ─── Missing API Key ─────────────────────────────────────────────

  it("should return empty results with error when API key is missing", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");
    const result = await dehashedConnector.collect("example.com", {});
    expect(result.connector).toBe("dehashed");
    expect(result.domain).toBe("example.com");
    expect(result.observations).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain("DEHASHED_API_KEY");
    expect(result.rateLimited).toBe(false);
  });

  // ─── Successful Response Parsing ──────────────────────────────────

  it("should parse breach entries and extract subdomains, IPs, and breach records", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        balance: 95,
        total: 5,
        entries: [
          {
            id: "1",
            email: ["user@mail.example.com"],
            ip_address: ["1.2.3.4"],
            password: ["leaked123"],
            database_name: "BreachDB_2023",
            domain: "example.com",
          },
          {
            id: "2",
            email: ["admin@internal.example.com"],
            ip_address: ["5.6.7.8"],
            hashed_password: ["abc123hash"],
            database_name: "BreachDB_2023",
            domain: "example.com",
          },
          {
            id: "3",
            email: ["dev@dev.example.com"],
            ip_address: ["1.2.3.4"], // duplicate IP
            database_name: "AnotherBreach",
            domain: "example.com",
          },
          {
            id: "4",
            email: ["user2@mail.example.com"], // duplicate subdomain
            database_name: "AnotherBreach",
            domain: "example.com",
          },
          {
            id: "5",
            email: ["test@example.com"], // root domain, not a subdomain
            database_name: "AnotherBreach",
            domain: "example.com",
          },
        ],
      }),
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "test-key" });

    expect(result.connector).toBe("dehashed");
    expect(result.domain).toBe("example.com");
    expect(result.errors).toHaveLength(0);
    expect(result.rateLimited).toBe(false);

    // Should have subdomains (mail.example.com, internal.example.com, dev.example.com)
    const subdomains = result.observations.filter(o => o.assetType === "subdomain");
    expect(subdomains.length).toBe(3);
    const subdomainNames = subdomains.map(s => s.name).sort();
    expect(subdomainNames).toEqual(["dev.example.com", "internal.example.com", "mail.example.com"]);

    // Should have unique IPs (1.2.3.4, 5.6.7.8)
    const ips = result.observations.filter(o => o.assetType === "ip");
    expect(ips.length).toBe(2);

    // Should have breach records (BreachDB_2023, AnotherBreach)
    const breaches = result.observations.filter(o => o.assetType === "breach" && !o.tags.includes("breach_summary"));
    expect(breaches.length).toBe(2);

    // Should have a summary observation
    const summaries = result.observations.filter(o => o.tags.includes("breach_summary"));
    expect(summaries.length).toBe(1);
    expect(summaries[0].evidence.total_records).toBe(5);
    expect(summaries[0].evidence.unique_breaches).toBe(2);
    expect(summaries[0].evidence.unique_subdomains_found).toBe(3);
    expect(summaries[0].evidence.api_balance).toBe(95);
  });

  // ─── Credential Exposure Detection ────────────────────────────────

  it("should flag breach databases with credential exposure", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        balance: 90,
        total: 2,
        entries: [
          {
            email: ["user@sub.example.com"],
            password: ["plaintext_password"],
            database_name: "LeakedDB",
          },
          {
            email: ["user2@sub.example.com"],
            hashed_password: ["5f4dcc3b5aa765d61d8327deb882cf99"],
            database_name: "LeakedDB",
          },
        ],
      }),
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "test-key" });

    const breachRecords = result.observations.filter(o => o.assetType === "breach" && !o.tags.includes("breach_summary"));
    expect(breachRecords.length).toBe(1);
    expect(breachRecords[0].tags).toContain("credentials_exposed");
    expect(breachRecords[0].evidence.credentials_exposed).toBe(2);
    expect(breachRecords[0].evidence.has_passwords).toBe(true);
    expect(breachRecords[0].evidence.has_hashed_passwords).toBe(true);
  });

  // ─── Attribution Fields ───────────────────────────────────────────

  it("should include proper attribution on all observations", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        balance: 90,
        total: 1,
        entries: [
          {
            email: ["user@sub.example.com"],
            ip_address: ["10.0.0.1"],
            database_name: "TestDB",
          },
        ],
      }),
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "test-key" });

    for (const obs of result.observations) {
      expect(obs.attribution).toBeDefined();
      expect(obs.attribution.provider).toContain("Dehashed");
      expect(obs.attribution.url).toBe("https://dehashed.com");
      expect(obs.source).toBe("dehashed");
    }
  });

  // ─── Error Handling: 401 Unauthorized ─────────────────────────────

  it("should handle 401 unauthorized response", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: async () => "Unauthorized",
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "bad-key" });
    expect(result.observations).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain("Dehashed");
    expect(result.rateLimited).toBe(false);
  });

  // ─── Error Handling: 429 Rate Limited ─────────────────────────────

  it("should handle 429 rate limit response", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      text: async () => "Rate limited",
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "test-key" });
    expect(result.observations).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.rateLimited).toBe(true);
  });

  // ─── Error Handling: 403 Forbidden ────────────────────────────────

  it("should handle 403 forbidden response", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      text: async () => "Forbidden",
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "expired-key" });
    expect(result.observations).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain("Dehashed");
  });

  // ─── Error Handling: Network Error ────────────────────────────────

  it("should handle network errors gracefully", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockRejectedValueOnce(new Error("Network error"));

    const result = await dehashedConnector.collect("example.com", { apiKey: "test-key" });
    expect(result.observations).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain("Dehashed error");
  });

  // ─── Empty Response ───────────────────────────────────────────────

  it("should handle empty entries gracefully", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        balance: 100,
        total: 0,
        entries: [],
      }),
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "test-key" });
    expect(result.observations).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  // ─── API Request Format ───────────────────────────────────────────

  it("should send correct API request format", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ balance: 100, total: 0, entries: [] }),
    });

    await dehashedConnector.collect("example.com", { apiKey: "my-api-key" });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe("https://api.dehashed.com/v2/search");
    expect(options.method).toBe("POST");
    expect(options.headers["Dehashed-Api-Key"]).toBe("my-api-key");
    expect(options.headers["Content-Type"]).toBe("application/json");

    const body = JSON.parse(options.body);
    expect(body.query).toBe("domain:example.com");
    expect(body.de_dupe).toBe(true);
  });

  // ─── Deduplication ────────────────────────────────────────────────

  it("should deduplicate subdomains and IPs across entries", async () => {
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        balance: 90,
        total: 4,
        entries: [
          { email: ["a@sub1.example.com"], ip_address: ["1.1.1.1"], database_name: "DB1" },
          { email: ["b@sub1.example.com"], ip_address: ["1.1.1.1"], database_name: "DB1" },
          { email: ["c@sub1.example.com"], ip_address: ["2.2.2.2"], database_name: "DB2" },
          { email: ["d@sub2.example.com"], ip_address: ["2.2.2.2"], database_name: "DB2" },
        ],
      }),
    });

    const result = await dehashedConnector.collect("example.com", { apiKey: "test-key" });

    const subdomains = result.observations.filter(o => o.assetType === "subdomain");
    const ips = result.observations.filter(o => o.assetType === "ip");
    const breaches = result.observations.filter(o => o.assetType === "breach" && !o.tags.includes("breach_summary"));

    // Only 2 unique subdomains (sub1, sub2)
    expect(subdomains.length).toBe(2);
    // Only 2 unique IPs
    expect(ips.length).toBe(2);
    // Only 2 unique breach databases
    expect(breaches.length).toBe(2);
  });
});

// ─── Signal Classifier Integration ──────────────────────────────────

describe("Dehashed Signal Classifier Integration", () => {
  it("should classify credential exposure as critical signal", async () => {
    const { classifySignals } = await import("./lib/passive/signal-classifier");
    const { AssetObservation } = await import("./lib/passive/types") as any;

    const observations = [
      {
        assetId: "test-breach-1",
        domain: "example.com",
        assetType: "breach" as const,
        name: "LeakedDB",
        source: "dehashed",
        observedAt: new Date(),
        tags: ["breach_database", "credentials_exposed", "records:50"],
        evidence: {
          database_name: "LeakedDB",
          total_records: 50,
          credentials_exposed: 25,
          has_passwords: true,
        },
        attribution: {
          provider: "Dehashed (Breach Intelligence)",
          url: "https://dehashed.com",
          method: "test",
          verifyUrl: "https://dehashed.com",
        },
      },
    ];

    const signals = classifySignals(observations);
    const credSignal = signals.find(s => s.signalType === "credential_exposure");
    expect(credSignal).toBeDefined();
    expect(credSignal!.severity).toBe("critical");
    expect(credSignal!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("should classify high-volume breach as high severity signal", async () => {
    const { classifySignals } = await import("./lib/passive/signal-classifier");

    const observations = [
      {
        assetId: "test-summary-1",
        domain: "example.com",
        assetType: "breach" as const,
        name: "example.com breach summary",
        source: "dehashed",
        observedAt: new Date(),
        tags: ["breach_summary", "total_records:500", "total_breaches:5", "credentials_at_risk"],
        evidence: {
          total_records: 500,
          unique_breaches: 5,
          unique_subdomains_found: 10,
          credentials_exposed: 200,
        },
        attribution: {
          provider: "Dehashed (Breach Intelligence)",
          url: "https://dehashed.com",
          method: "test",
          verifyUrl: "https://dehashed.com",
        },
      },
    ];

    const signals = classifySignals(observations);
    const volumeSignal = signals.find(s => s.signalType === "high_volume_breach");
    expect(volumeSignal).toBeDefined();
    expect(volumeSignal!.severity).toBe("high");
  });

  it("should classify breach-derived subdomains as info signal", async () => {
    const { classifySignals } = await import("./lib/passive/signal-classifier");

    const observations = [
      {
        assetId: "test-sub-1",
        domain: "example.com",
        assetType: "subdomain" as const,
        name: "mail.example.com",
        source: "dehashed",
        observedAt: new Date(),
        tags: ["breach_derived", "email_domain"],
        evidence: {
          discovery_method: "email_domain_extraction",
          database_name: "SomeDB",
        },
        attribution: {
          provider: "Dehashed (Breach Intelligence)",
          url: "https://dehashed.com",
          method: "test",
          verifyUrl: "https://dehashed.com",
        },
      },
    ];

    const signals = classifySignals(observations);
    const subSignal = signals.find(s => s.signalType === "breach_subdomain");
    expect(subSignal).toBeDefined();
    expect(subSignal!.severity).toBe("info");
  });
});

// ─── Passive Guard Integration ──────────────────────────────────────

describe("Dehashed Passive Guard Integration", () => {
  it("should include dehashed in strict_passive mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    const { allowed } = filterConnectors([dehashedConnector], "strict_passive");
    expect(allowed.length).toBe(1);
    expect(allowed[0].name).toBe("dehashed");
  });

  it("should include dehashed in standard mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    const { allowed } = filterConnectors([dehashedConnector], "standard");
    expect(allowed.length).toBe(1);
    expect(allowed[0].name).toBe("dehashed");
  });

  it("should include dehashed in active mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");
    const { dehashedConnector } = await import("./lib/passive/dehashed");

    const { allowed } = filterConnectors([dehashedConnector], "active");
    expect(allowed.length).toBe(1);
    expect(allowed[0].name).toBe("dehashed");
  });

  it("should include api.dehashed.com in strict_passive allowed netlocs", async () => {
    const { getDefaultPolicy } = await import("./lib/passive/passive-guard");
    const policy = getDefaultPolicy("strict_passive");
    expect(policy.allowedNetlocs.has("api.dehashed.com")).toBe(true);
  });
});

// ─── Orchestrator Integration ───────────────────────────────────────

describe("Dehashed Orchestrator Integration", () => {
  it("should include dehashed in the orchestrator connector list", async () => {
    const { runPassiveRecon } = await import("./lib/passive/index");

    // Mock all external calls
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ balance: 100, total: 0, entries: [] }),
      text: async () => "",
    });

    const result = await runPassiveRecon("example.com", {
      scanMode: "active",
      apiKeys: { dehashed: "test-key" },
      timeout: 8000,
    });

    // Dehashed should appear in connector results
    const dhResult = result.connectorResults.find(r => r.connector === "dehashed");
    expect(dhResult).toBeDefined();
    expect(dhResult!.domain).toBe("example.com");
  });

  it("should pass dehashed API key through orchestrator config", async () => {
    const { runPassiveRecon } = await import("./lib/passive/index");

    // Reset mock to clear any previous calls
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ balance: 100, total: 0, entries: [] }),
      text: async () => "",
    });

    await runPassiveRecon("example.com", {
      scanMode: "strict_passive",
      apiKeys: { dehashed: "my-dehashed-key" },
      timeout: 8000,
    });

    // Find the Dehashed API call (POST to dehashed v2 search)
    const dehashedCall = mockFetch.mock.calls.find(
      (call: any[]) => call[0] === "https://api.dehashed.com/v2/search"
    );
    expect(dehashedCall).toBeDefined();
    expect(dehashedCall![1].headers["Dehashed-Api-Key"]).toBe("my-dehashed-key");
  });
});
