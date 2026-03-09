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

  it("should have a 15s default connector timeout", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    // Verify default timeout is 15s
    expect(source).toContain("timeout = 15000");
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

  it("should use semaphore-based concurrency pool", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    expect(source).toContain("runSingleConnector");
    expect(source).toContain("activeCount");
    expect(source).toContain("allConnectorPromises");
  });

  it("should check global timeout before starting each connector", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/index.ts", "utf-8")
    );
    expect(source).toContain("Global recon timeout reached");
  });

  it("should have 12-minute per-domain watchdog in engagement-ops", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/routers/engagement-ops-core.ts", "utf-8")
    );
    expect(source).toContain("PER_DOMAIN_WATCHDOG_MS = 12 * 60 * 1000");
  });

  it("should have 60-minute global watchdog in engagement-ops", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/routers/engagement-ops-core.ts", "utf-8")
    );
    expect(source).toContain("GLOBAL_WATCHDOG_MS = 60 * 60 * 1000");
  });

  it("should have parallel concurrency of 2 domains", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/routers/engagement-ops-core.ts", "utf-8")
    );
    expect(source).toContain("PARALLEL_CONCURRENCY = 2");
  });

  it("should have 30s cloud bucket recon global timeout", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/cloud-bucket-recon.ts", "utf-8")
    );
    expect(source).toContain("GLOBAL_TIMEOUT = 30000");
  });

  it("cloud-assets connector should limit to 8 candidates", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/cloud-assets.ts", "utf-8")
    );
    expect(source).toContain("candidates.slice(0, 8)");
  });

  it("cloud-assets connector should cap probe timeout at 3s", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/cloud-assets.ts", "utf-8")
    );
    expect(source).toContain("3000, 3000)");
  });

  it("shodan connector should check external signal between stages", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/shodan.ts", "utf-8")
    );
    expect(source).toContain("externalSignal?.aborted");
    expect(source).toContain("Aborted before stage 2");
  });

  it("shodan connector should limit IPs to 5", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/shodan.ts", "utf-8")
    );
    expect(source).toContain("seenIPs).slice(0, 5)");
  });

  it("social-media connector should check external signal", async () => {
    const source = await import("fs").then(fs =>
      fs.readFileSync("server/lib/passive/social-media.ts", "utf-8")
    );
    expect(source).toContain("externalSignal?.aborted");
  });
});
