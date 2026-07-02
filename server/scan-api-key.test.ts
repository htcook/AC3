/**
 * Validates that SCAN_API_KEY is set and can authenticate with the ScanForge service.
 */
import { describe, it, expect } from "vitest";

const isCI = process.env.CI === "true" || process.env.VITEST_CI === "true";

describe("SCAN_API_KEY validation", () => {
  it.skipIf(isCI)("SCAN_API_KEY env var is set and non-empty", () => {
    const key = process.env.SCAN_API_KEY;
    expect(key).toBeTruthy();
    expect(key!.length).toBeGreaterThan(10);
  });

  it.skipIf(isCI)("SCAN_API_KEY authenticates with ScanForge service", async () => {
    const key = process.env.SCAN_API_KEY;
    if (!key) return;
    const scanUrl = process.env.SCANFORGE_URL || "https://10.0.1.203:4443";
    const resp = await fetch(`${scanUrl}/api/scan/tool`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Scan-Key": key },
      body: JSON.stringify({ tool: "naabu", args: "-version", timeoutSeconds: 10 }),
      // @ts-ignore
      signal: AbortSignal.timeout(15000),
    }).catch(() => null);
    if (!resp) { console.log("Could not reach ScanForge (network) - skipping"); return; }
    expect(resp.status).not.toBe(401);
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.exitCode).toBe(0);
  }, 20000);
});
