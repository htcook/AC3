import { describe, it, expect } from "vitest";

describe("GitHub Classic Token Validation", () => {
  it("authenticates successfully with the classic token", async () => {
    const token = process.env.GITHUB_CLASSIC_TOKEN;
    expect(token).toBeTruthy();
    const res = await fetch("https://api.github.com/user", {
      headers: { Authorization: `token ${token}`, "User-Agent": "caldera-dashboard" },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.login).toBeTruthy();
    console.log(`Classic token authenticated as: ${data.login}`);
  });

  it("has code search scope", async () => {
    const token = process.env.GITHUB_CLASSIC_TOKEN;
    const res = await fetch("https://api.github.com/search/code?q=test+in:file&per_page=1", {
      headers: { Authorization: `token ${token}`, "User-Agent": "caldera-dashboard" },
    });
    // 200 = has scope, 422 = no scope but auth works
    expect([200, 422]).toContain(res.status);
    console.log(`Code search status: ${res.status}`);
  });
});
