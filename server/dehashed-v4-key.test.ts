import { describe, it, expect } from "vitest";

describe("Dehashed v4 API Key Validation", () => {
  const apiKey = process.env.DEHASHED_API_KEY;

  it("should have DEHASHED_API_KEY set", () => {
    expect(apiKey).toBeDefined();
    expect(apiKey!.length).toBeGreaterThan(10);
  });

  it("should authenticate with v2 search endpoint", async () => {
    const res = await fetch("https://api.dehashed.com/v2/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Dehashed-Api-Key": apiKey!,
      },
      body: JSON.stringify({
        query: "domain:example.com",
        page: 1,
        size: 1,
        de_dupe: true,
      }),
    });
    // Should get 200 (success) or 401/403 if key is invalid
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data).toHaveProperty("balance");
    expect(data).toHaveProperty("entries");
    expect(data).toHaveProperty("total");
  }, 15000);
});
