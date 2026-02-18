import { describe, it, expect } from "vitest";

describe("Dehashed API key validation", () => {
  it("should have DEHASHED_API_KEY and DEHASHED_EMAIL set in environment", () => {
    const key = process.env.DEHASHED_API_KEY;
    const email = process.env.DEHASHED_EMAIL;
    expect(key).toBeDefined();
    expect(key!.length).toBeGreaterThan(5);
    expect(email).toBeDefined();
    expect(email).toContain("@");
  });

  it("should authenticate successfully with Dehashed API", async () => {
    const key = process.env.DEHASHED_API_KEY;
    const email = process.env.DEHASHED_EMAIL;
    expect(key).toBeDefined();
    expect(email).toBeDefined();

    const auth = Buffer.from(`${email}:${key}`).toString("base64");
    const res = await fetch(
      "https://api.dehashed.com/search?query=domain:example.com&size=1",
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Basic ${auth}`,
        },
      }
    );

    // Valid credentials should return 200 (with results) or 400 (bad query)
    // Invalid credentials return 401
    expect(res.status).not.toBe(401);
    // If 200, check the response has expected structure
    if (res.ok) {
      const data = (await res.json()) as any;
      expect(data).toHaveProperty("total");
      expect(data).toHaveProperty("entries");
    }
  }, 30000);
});
