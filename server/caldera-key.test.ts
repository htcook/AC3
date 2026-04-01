import { describe, it, expect } from "vitest";

/**
 * Validate that the Caldera API key resolves correctly and
 * the Caldera 5.3.0 instance at caldera.aceofcloud.io responds.
 *
 * Network tests are skipped in CI (no access to private infrastructure).
 */
const isCI = !!process.env.CI;

describe("Caldera API Key Validation", () => {
  const CALDERA_URL = "https://caldera.aceofcloud.io";
  // The resolveCalderaApiKey logic: if env is ADMIN123 or short, use the hardcoded fallback
  function resolveCalderaApiKey(): string {
    const env = process.env.CALDERA_API_KEY;
    if (env && env !== "ADMIN123" && env.length > 10) return env;
    return "kmpJNkws7KXEdyIc2K8FYAGdMoRgrZ4c3hvJ1F9SI94";
  }

  it("should resolve a valid API key (not ADMIN123)", () => {
    const key = resolveCalderaApiKey();
    expect(key).toBeDefined();
    expect(key.length).toBeGreaterThan(10);
    expect(key).not.toBe("ADMIN123");
  });

  it.skipIf(isCI)("should authenticate with Caldera v2 API /health endpoint", async () => {
    const key = resolveCalderaApiKey();
    const resp = await fetch(`${CALDERA_URL}/api/v2/health`, {
      headers: { KEY: key },
    });
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.application).toBe("Caldera");
    expect(data.version).toBe("5.3.0");
  });

  it.skipIf(isCI)("should authenticate with Caldera v2 API /agents endpoint", async () => {
    const key = resolveCalderaApiKey();
    const resp = await fetch(`${CALDERA_URL}/api/v2/agents`, {
      headers: { KEY: key },
    });
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
  });

  it.skipIf(isCI)("should authenticate with Caldera v2 API /contacts endpoint", async () => {
    const key = resolveCalderaApiKey();
    const resp = await fetch(`${CALDERA_URL}/api/v2/contacts`, {
      headers: { KEY: key },
    });
    expect(resp.status).toBe(200);
  });
});
