import { describe, it, expect } from "vitest";

/**
 * Validate that the GoPhish API is reachable at the configured GOPHISH_BASE_URL.
 * Uses the direct IP (137.184.7.224:3333) with TLS override for self-signed cert.
 */
describe("GoPhish API Connection", () => {
  it("should resolve GoPhish URL to direct IP", async () => {
    // Dynamic import to get the resolved ENV
    const { ENV } = await import("./_core/env");
    expect(ENV.gophishBaseUrl).toContain("137.184.7.224");
    expect(ENV.gophishApiKey).toBeTruthy();
    console.log(`GoPhish URL: ${ENV.gophishBaseUrl}`);
  });

  it("should successfully fetch templates from GoPhish API", async () => {
    const { fetchGophish } = await import("./lib/gophish-client");
    const result = await fetchGophish("/api/templates/", {
      timeoutMs: 10000,
      errorMode: "silent",
    });
    // Result should be an array (even if empty) — not null (which means connection failed)
    console.log(`GoPhish templates result: ${result === null ? "null (FAILED)" : `array with ${Array.isArray(result) ? result.length : "?"} items`}`);
    expect(result).not.toBeNull();
    expect(Array.isArray(result)).toBe(true);
  });
});
