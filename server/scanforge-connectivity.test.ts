import { describe, it, expect } from "vitest";

/**
 * Network tests are skipped in CI (no access to private ScanForge droplet).
 */
const isCI = !!process.env.CI;

describe("ScanForge Dedicated Droplet Connectivity", () => {
  const SCANFORGE_URL = "http://137.184.71.192:4000";
  const ZAP_URL = process.env.ZAP_BASE_URL || "http://137.184.71.192:8090";

  it.skipIf(isCI)("should reach the ScanForge scan service health endpoint", async () => {
    const res = await fetch(`${SCANFORGE_URL}/health`, { signal: AbortSignal.timeout(10000) });
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(body.status).toBe("ok");
    expect(body.service).toBe("scanforge-dedicated");
    expect(body.cpus).toBeGreaterThanOrEqual(4);
  });

  it.skipIf(isCI)("should execute nuclei version check via the ScanForge API", async () => {
    const res = await fetch(`${SCANFORGE_URL}/api/scan/tool`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Scan-Key": process.env.CALDERA_API_KEY || "ADMIN123",
      },
      body: JSON.stringify({ tool: "nuclei", args: "-version", timeoutSeconds: 10 }),
      signal: AbortSignal.timeout(15000),
    });
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.result.stderr).toContain("Nuclei");
  });

  it.skipIf(isCI)("should execute a simple ScanForge discovery scan via the ScanForge API", async () => {
    const res = await fetch(`${SCANFORGE_URL}/api/scan/tool`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Scan-Key": process.env.CALDERA_API_KEY || "ADMIN123",
      },
      body: JSON.stringify({ tool: "scanforge-discovery", args: "-sn 127.0.0.1", timeoutSeconds: 10 }),
      signal: AbortSignal.timeout(15000),
    });
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.result.stdout).toContain("ScanForge");
    expect(body.result.exitCode).toBe(0);
  });

  it("should have ZAP_BASE_URL configured with port 8090", () => {
    // ZAP_BASE_URL should point to port 8090 (either old or new droplet)
    expect(ZAP_URL).toContain("8090");
  });
});
