import { describe, it, expect, vi } from "vitest";

describe("Passive Scan Fix: broadcastOpsUpdate export", () => {
  it("broadcastOpsUpdate should be exported from engagement-orchestrator", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    expect(typeof mod.broadcastOpsUpdate).toBe("function");
  });

  it("broadcastOpsUpdate should be callable without throwing TypeError", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    // Should not throw "broadcastOpsUpdate is not a function"
    // It may throw a different error (e.g., no WebSocket clients) but NOT TypeError
    try {
      mod.broadcastOpsUpdate(999999, { type: "test" });
    } catch (e: any) {
      // It's OK if it throws for other reasons (no WS clients, etc.)
      // but it should NOT be "is not a function"
      expect(e.message).not.toContain("is not a function");
    }
  });

  it("getOpsState, initOpsState, stopEngagement should all be exported", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    expect(typeof mod.getOpsState).toBe("function");
    expect(typeof mod.initOpsState).toBe("function");
    expect(typeof mod.stopEngagement).toBe("function");
  });
});

describe("Passive Scan Fix: LLM timeout", () => {
  it("invokeLLM should use AbortController for timeout", async () => {
    // Read the source file and verify it contains AbortController
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("./_core/llm.ts", import.meta.url).pathname.replace("/_core/", "/../server/_core/"),
      "utf-8"
    );
    // The file should contain AbortController usage
    expect(source).toContain("AbortController");
    expect(source).toContain("controller.abort");
    expect(source).toContain("signal: controller.signal");
    expect(source).toContain("AbortError");
  });
});

describe("Passive Scan Fix: Watchdog improvements", () => {
  it("engagement-ops-core.ts should have per-domain watchdog", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers/engagement-ops-core.ts",
      "utf-8"
    );
    // Should have per-domain watchdog
    expect(source).toContain("PER_DOMAIN_WATCHDOG_MS");
    expect(source).toContain("domainWatchdogPromise");
    expect(source).toContain("domainWatchdogTimer");
    // Should have global watchdog
    expect(source).toContain("GLOBAL_WATCHDOG_MS");
    expect(source).toContain("globalWatchdogPromise");
    // Should check for operator stop
    expect(source).toContain("if (!state!.isRunning)");
  });
});
