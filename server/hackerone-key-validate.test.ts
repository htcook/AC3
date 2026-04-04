import { describe, it, expect } from "vitest";

describe("HackerOne API Key Validation", () => {
  it("should authenticate successfully with the new API key", async () => {
    const apiKey = process.env.HACKERONE_API_KEY;
    expect(apiKey).toBeTruthy();

    // HackerOne uses Basic auth with username:token format
    const username = process.env.HACKERONE_API_USERNAME || 'htc0';
    console.log(`Using username: ${username}, key length: ${apiKey?.length}`);
    const authHeader = "Basic " + Buffer.from(`${username}:${apiKey}`).toString("base64");

    const res = await fetch("https://api.hackerone.com/v1/hackers/programs?page[size]=1", {
      headers: {
        Accept: "application/json",
        Authorization: authHeader,
      },
      signal: AbortSignal.timeout(15000),
    });

    console.log(`HackerOne API response status: ${res.status}`);

    // 200 = valid key with valid data
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
  });
});
