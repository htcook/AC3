import { describe, it, expect } from "vitest";

/**
 * Validate that the Caldera 'red' service account password is properly
 * configured via the CALDERA_PASSWORD environment variable and can
 * authenticate with the Caldera server.
 *
 * These tests are skipped in CI where secrets are not available.
 */
describe("Caldera Password Secret Validation", () => {
  const CALDERA_URL = "https://caldera.aceofcloud.io";

  it("should have CALDERA_PASSWORD set in environment", () => {
    if (!process.env.CALDERA_PASSWORD) {
      console.log("[SKIP] CALDERA_PASSWORD not set — skipping in CI");
      return;
    }
    const pw = process.env.CALDERA_PASSWORD;
    expect(pw).toBeDefined();
    expect(pw!.length).toBeGreaterThan(0);
  });

  it("should authenticate with Caldera /enter endpoint using red account", async () => {
    if (!process.env.CALDERA_PASSWORD) {
      console.log("[SKIP] CALDERA_PASSWORD not set — skipping in CI");
      return;
    }
    const pw = process.env.CALDERA_PASSWORD;
    const resp = await fetch(`${CALDERA_URL}/enter`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "red", password: pw }),
      redirect: "manual",
    });
    // Caldera returns 200 or 302 on successful login
    expect([200, 302]).toContain(resp.status);
  });
});
