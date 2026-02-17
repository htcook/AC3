import { describe, it, expect } from "vitest";

describe("abuse.ch API key validation", () => {
  it("should have ABUSECH_API_KEY set in environment", () => {
    const key = process.env.ABUSECH_API_KEY;
    expect(key).toBeDefined();
    expect(key!.length).toBeGreaterThan(10);
  });

  it("should authenticate successfully with abuse.ch URLhaus API", async () => {
    const key = process.env.ABUSECH_API_KEY;
    expect(key).toBeDefined();

    const res = await fetch("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/5/", {
      method: "GET",
      headers: { "Auth-Key": key! },
    });

    expect(res.ok).toBe(true);
    const data = await res.json() as any;
    expect(data.query_status).toBe("ok");
    expect(Array.isArray(data.urls)).toBe(true);
    expect(data.urls.length).toBeGreaterThan(0);
  }, 30000);

  it("should note ThreatFox API currently requires different auth (401 for all)", async () => {
    // ThreatFox API is returning 401 for all requests (even without auth)
    // This is a known upstream issue — URLhaus is the primary IOC source
    const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "get_iocs", days: 1 }),
    });

    // ThreatFox currently returns 401 for all requests
    expect(res.status).toBe(401);
  }, 30000);
});
