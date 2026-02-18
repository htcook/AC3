import { describe, it, expect } from "vitest";

describe("Shodan API Key Validation", () => {
  const apiKey = process.env.SHODAN_API_KEY;

  it("should have SHODAN_API_KEY set", () => {
    expect(apiKey).toBeDefined();
    expect(apiKey!.length).toBeGreaterThan(10);
  });

  it("should authenticate with Shodan API and return account info", async () => {
    const res = await fetch(`https://api.shodan.io/api-info?key=${apiKey}`);
    expect(res.status).toBe(200);
    const data = await res.json();
    // Should return account info with query/scan credits
    expect(data).toHaveProperty("query_credits");
    expect(data).toHaveProperty("scan_credits");
    console.log(`Shodan account: query_credits=${data.query_credits}, scan_credits=${data.scan_credits}, plan=${data.plan}`);
  });

  it("should be able to search hosts by domain", async () => {
    const res = await fetch(`https://api.shodan.io/dns/domain/google.com?key=${apiKey}`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data).toHaveProperty("domain");
    expect(data.domain).toBe("google.com");
    expect(data).toHaveProperty("subdomains");
    expect(Array.isArray(data.subdomains)).toBe(true);
    console.log(`Shodan DNS domain: ${data.subdomains?.length} subdomains found for google.com`);
  });

  it("should be able to query host details by IP", async () => {
    // Google DNS
    const res = await fetch(`https://api.shodan.io/shodan/host/8.8.8.8?key=${apiKey}`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data).toHaveProperty("ip_str");
    expect(data).toHaveProperty("ports");
    expect(data).toHaveProperty("data"); // banner data array
    expect(Array.isArray(data.ports)).toBe(true);
    console.log(`Shodan host 8.8.8.8: ports=${data.ports?.join(",")}, vulns=${data.vulns?.length || 0}`);
  });
});
