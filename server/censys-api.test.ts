import { describe, it, expect } from "vitest";

describe("Censys Platform API v3 credentials and connector", () => {
  const pat = process.env.CENSYS_API_SECRET;
  const orgId = process.env.CENSYS_API_ID;

  it("should have CENSYS_API_SECRET configured", () => {
    expect(pat).toBeDefined();
    expect(pat!.length).toBeGreaterThan(10);
    expect(pat).toMatch(/^censys_/); // PAT tokens start with censys_
  });

  it("should authenticate with Censys Platform API v3", async () => {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${pat}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (orgId) headers["X-Organization-ID"] = orgId;

    const res = await fetch("https://api.platform.censys.io/v3/global/search/query", {
      method: "POST",
      headers,
      body: JSON.stringify({
        query: "host.services: (port=443 and protocol=HTTP)",
        page_size: 1,
      }),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.result).toBeDefined();
    expect(data.result.hits).toBeDefined();
    expect(data.result.hits.length).toBeGreaterThan(0);
  });

  it("should return host data in v3 format (host_v1.resource)", async () => {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${pat}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (orgId) headers["X-Organization-ID"] = orgId;

    const res = await fetch("https://api.platform.censys.io/v3/global/search/query", {
      method: "POST",
      headers,
      body: JSON.stringify({
        query: "host.dns.names: google.com",
        page_size: 1,
      }),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    const hit = data.result.hits[0];
    expect(hit.host_v1).toBeDefined();
    expect(hit.host_v1.resource).toBeDefined();
    expect(hit.host_v1.resource.ip).toBeDefined();
  });

  it("should look up a host by IP", async () => {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${pat}`,
      Accept: "application/json",
    };
    if (orgId) headers["X-Organization-ID"] = orgId;

    const res = await fetch("https://api.platform.censys.io/v3/global/asset/host/8.8.8.8", {
      headers,
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.result.resource.ip).toBe("8.8.8.8");
    expect(data.result.resource.services).toBeDefined();
    expect(data.result.resource.autonomous_system).toBeDefined();
  });

  it("should handle hyphenated domain names without 422 errors", async () => {
    // Regression test: CenQL requires quoted domain values when they contain hyphens
    // Previously: host.dns.names: dashboard-dev.example.com → 422 "Invalid character: '-'"
    // Fixed:      host.dns.names: "dashboard-dev.example.com" → 200 OK
    const headers: Record<string, string> = {
      Authorization: `Bearer ${pat}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (orgId) headers["X-Organization-ID"] = orgId;

    // Test with a hyphenated domain — this should NOT return 422
    const res = await fetch("https://api.platform.censys.io/v3/global/search/query", {
      method: "POST",
      headers,
      body: JSON.stringify({
        query: `host.dns.names: "my-test-domain.example.com"`,
        page_size: 1,
      }),
    });

    // Should be 200 (even if 0 results), NOT 422
    expect(res.status).toBe(200);
  });

  it("should verify connector quotes domains in CenQL queries", async () => {
    // Verify the connector properly quotes domains by testing with a hyphenated domain
    const { censysConnector } = await import("./lib/passive/censys");
    const result = await censysConnector.collect("dashboard-dev.vianovahealth.com", {
      apiId: orgId,
      apiSecret: pat,
      timeout: 30000,
    });

    expect(result.connector).toBe("censys");
    expect(result.domain).toBe("dashboard-dev.vianovahealth.com");
    // The key assertion: no "query error" or "Invalid character" errors
    const queryErrors = result.errors.filter(e => e.includes("query error") || e.includes("Invalid character"));
    expect(queryErrors).toHaveLength(0);
  });

  it("should run the censys connector and return observations", async () => {
    const { censysConnector } = await import("./lib/passive/censys");
    const result = await censysConnector.collect("google.com", {
      apiId: orgId,
      apiSecret: pat,
      timeout: 30000,
    });

    expect(result.connector).toBe("censys");
    expect(result.domain).toBe("google.com");
    expect(result.errors.length).toBe(0);
    expect(result.observations.length).toBeGreaterThan(0);

    // Verify observation structure
    const obs = result.observations[0];
    expect(obs.ip).toBeDefined();
    expect(obs.source).toBe("censys");
    expect(obs.assetType).toBe("ip");
    expect(obs.attribution.provider).toContain("Censys");
    expect(obs.attribution.url).toContain("platform.censys.io");
  });
});
