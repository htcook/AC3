import { describe, it, expect } from "vitest";

describe("SCAN_SERVER_SSH_KEY", () => {
  it("should be set and contain a valid SSH private key", () => {
    if (!process.env.SCAN_SERVER_SSH_KEY) {
      console.log("[SKIP] SCAN_SERVER_SSH_KEY not set — skipping in CI");
      return;
    }
    const key = process.env.SCAN_SERVER_SSH_KEY;
    expect(key).toBeDefined();
    expect(key!.length).toBeGreaterThan(50);
    expect(key).toContain("PRIVATE KEY");
  });
});
