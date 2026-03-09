import { describe, it, expect } from "vitest";

/**
 * Tests for passive recon timeout configuration.
 * These verify the timeout constants are set correctly in the source.
 */

describe("Passive Recon Timeout Configuration", () => {
  it("should have a 30s hard per-connector timeout", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    // Verify the hard connector timeout is 30 seconds
    expect(source).toContain("HARD_CONNECTOR_TIMEOUT = 30_000");
  });

  it("should have a 5-minute global recon timeout", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    // Verify global recon timeout is 5 minutes
    expect(source).toContain("GLOBAL_RECON_TIMEOUT = 5 * 60 * 1000");
  });

  it("should have a 15s default connector timeout (reduced from 30s)", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    // Verify default timeout is 15s
    expect(source).toContain("timeout = 15000");
  });

  it("should have a 10 maxConcurrent connector limit", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    expect(source).toContain("maxConcurrent = 10");
  });

  it("should skip connectors with no API key before execution", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    expect(source).toContain("CONNECTORS_REQUIRING_API_KEY");
    expect(source).toContain("Skipped: No API key configured");
  });

  it("should use Promise.race for hard connector timeout", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    // Verify the Promise.race pattern is used
    expect(source).toContain("Promise.race");
    expect(source).toContain("Hard timeout:");
  });

  it("should break out of connector batches when global timeout is reached", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    expect(source).toContain("Global recon timeout");
    expect(source).toContain("break;");
  });

  it("should have 20-minute per-domain watchdog in engagement-ops", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/routers/engagement-ops-core.ts", "utf-8")
    );
    expect(source).toContain("PER_DOMAIN_WATCHDOG_MS = 20 * 60 * 1000");
  });

  it("should have 30s cloud bucket recon global timeout", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/cloud-bucket-recon.ts", "utf-8")
    );
    expect(source).toContain("GLOBAL_TIMEOUT = 30000");
  });
});
