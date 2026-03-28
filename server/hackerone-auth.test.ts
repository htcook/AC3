import { describe, it, expect } from "vitest";

describe("HackerOne API credentials", () => {
  it("should have HACKERONE_API_USERNAME set", () => {
    const username = process.env.HACKERONE_API_USERNAME;
    expect(username).toBeDefined();
    expect(username!.length).toBeGreaterThan(0);
  });

  it("should have HACKERONE_API_KEY set", () => {
    const apiKey = process.env.HACKERONE_API_KEY;
    expect(apiKey).toBeDefined();
    expect(apiKey!.length).toBeGreaterThan(0);
  });

  it("should authenticate successfully against HackerOne Hacker API", async () => {
    const username = process.env.HACKERONE_API_USERNAME;
    const apiKey = process.env.HACKERONE_API_KEY;

    // Use the /v1/hackers/programs endpoint — the correct endpoint for hacker accounts
    // Note: /v1/me is for the Customer/Organization API, not the Hacker API
    const response = await fetch("https://api.hackerone.com/v1/hackers/programs", {
      headers: {
        Authorization: `Basic ${Buffer.from(`${username}:${apiKey}`).toString("base64")}`,
        Accept: "application/json",
      },
    });

    // 200 = valid credentials, 401 = invalid
    expect(response.status).not.toBe(401);
    // Accept 200 (success) or 403 (valid creds but insufficient permissions)
    expect([200, 403]).toContain(response.status);
  });
});
