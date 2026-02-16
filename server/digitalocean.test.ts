import { describe, it, expect } from "vitest";

describe("DigitalOcean Access Token", () => {
  it("should be set in environment variables", () => {
    const token = process.env.DIGITALOCEAN_ACCESS_TOKEN;
    expect(token).toBeTruthy();
    expect(token!.startsWith("dop_v1_")).toBe(true);
  });

  it("should authenticate against the DigitalOcean API", async () => {
    const token = process.env.DIGITALOCEAN_ACCESS_TOKEN;
    if (!token) throw new Error("DIGITALOCEAN_ACCESS_TOKEN not set");

    const res = await fetch("https://api.digitalocean.com/v2/account", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.account).toBeDefined();
    expect(data.account.status).toBe("active");
  });
});
