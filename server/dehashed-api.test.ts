import { describe, it, expect } from "vitest";

describe("Dehashed V2 API Key Validation", () => {
  it("should authenticate successfully with the V2 API key", async () => {
    const apiKey = process.env.DEHASHED_API_KEY;
    expect(apiKey).toBeTruthy();

    // Use a minimal search (size=1) to validate the key without burning credits
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

    // 200 = valid key with credits, 403 = valid key but insufficient credits
    // 401 = invalid key
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(400);

    if (res.status === 200) {
      const data = await res.json();
      // V2 API returns balance field
      expect(data).toHaveProperty("balance");
      console.log(`Dehashed API key valid. Balance: ${data.balance} credits`);
    } else if (res.status === 403) {
      const body = await res.text();
      console.log(`Dehashed API key valid but insufficient credits: ${body}`);
    } else {
      console.log(`Dehashed returned status ${res.status}`);
    }
  }, 15000);
});
