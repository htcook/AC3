/**
 * ZAP Connectivity Validation Test
 * Verifies that ZAP_BASE_URL and SCAN_SERVER_HOST are correctly configured
 * and that ZAP is reachable at the configured endpoint.
 */
import { describe, it, expect } from "vitest";

describe("ZAP Connectivity Validation", () => {
  const zapBaseUrl = process.env.ZAP_BASE_URL || "http://137.184.211.238:8092";
  const scanServerHost = process.env.SCAN_SERVER_HOST || "137.184.211.238";

  it("should have ZAP_BASE_URL env var set to the correct legacy scan server", () => {
    expect(process.env.ZAP_BASE_URL).toBeDefined();
    expect(process.env.ZAP_BASE_URL).toContain("137.184.211.238");
    expect(process.env.ZAP_BASE_URL).toContain(":8092");
  });

  it("should have SCAN_SERVER_HOST pointing to the legacy scan server IP", () => {
    expect(process.env.SCAN_SERVER_HOST).toBeDefined();
    expect(process.env.SCAN_SERVER_HOST).toBe("137.184.211.238");
  });

  it("should successfully reach ZAP version endpoint", async () => {
    const resp = await fetch(`${zapBaseUrl}/JSON/core/view/version/`, {
      signal: AbortSignal.timeout(10_000),
    });
    expect(resp.ok).toBe(true);
    const data = await resp.json();
    expect(data.version).toBeDefined();
    expect(data.version).toMatch(/^\d+\.\d+/);
  });

  it("should resolve getActiveZapUrl to the correct URL", async () => {
    const { getActiveZapUrl } = await import("./lib/scan-service-url");
    const url = await getActiveZapUrl();
    expect(url).toContain("137.184.211.238");
    expect(url).toContain(":8092");
  });

  it("should have LEGACY_ZAP_URL using port 8092", async () => {
    const mod = await import("./lib/scan-service-url");
    expect(mod.LEGACY_ZAP_URL).toContain(":8092");
    expect(mod.LEGACY_ZAP_URL).toContain("137.184.211.238");
  });
});
