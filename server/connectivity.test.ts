import { describe, it, expect } from "vitest";

describe("API Connectivity Validation", () => {
  it("should have valid GOPHISH_API_KEY set", () => {
    const val = process.env.GOPHISH_API_KEY;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(10);
  });

  it("should have valid CALDERA_API_KEY set", () => {
    const val = process.env.CALDERA_API_KEY;
    expect(val).toBeDefined();
    expect(val!.length).toBeGreaterThan(10);
  });

  it("should resolve GoPhish URL to remote server (not localhost)", async () => {
    const { ENV } = await import("./_core/env");
    expect(ENV.gophishBaseUrl).not.toContain("127.0.0.1");
    expect(ENV.gophishBaseUrl).not.toContain("localhost");
    expect(ENV.gophishBaseUrl).toContain("137.184.7.224");
  });

  it("should resolve Caldera URL to remote server (not localhost)", async () => {
    const { ENV } = await import("./_core/env");
    expect(ENV.calderaBaseUrl).not.toContain("127.0.0.1");
    expect(ENV.calderaBaseUrl).not.toContain("localhost");
    expect(ENV.calderaBaseUrl).toContain("137.184.7.224");
  });

  it("should connect to GoPhish API and list templates", async () => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const { ENV } = await import("./_core/env");
    const response = await fetch(`${ENV.gophishBaseUrl}/api/templates/`, {
      headers: {
        Authorization: ENV.gophishApiKey,
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(10000),
    });
    expect(response.ok).toBe(true);
    const data = await response.json();
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
  });

  it("should connect to Caldera API and list agents", async () => {
    const { ENV } = await import("./_core/env");
    const response = await fetch(`${ENV.calderaBaseUrl}/api/v2/agents`, {
      headers: {
        KEY: ENV.calderaApiKey,
      },
      signal: AbortSignal.timeout(10000),
    });
    expect(response.ok).toBe(true);
    const data = await response.json();
    expect(Array.isArray(data)).toBe(true);
  });
});
