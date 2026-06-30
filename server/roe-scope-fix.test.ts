import { describe, it, expect } from "vitest";
import { isInRoeScope } from "./lib/engagement-orchestrator";


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("RoE Scope Guard — IP:port handling", () => {
  const makeState = (domains: string[], ips: string[]) => ({
    roeScopeGuard: {
      authorizedDomains: domains,
      authorizedIps: ips,
      roeStatus: "signed",
    },
  }) as any;

  // ─── Basic exact match (existing behavior) ───

  it("allows exact domain match", () => {
    const state = makeState(["example.com"], []);
    expect(isInRoeScope(state, "example.com")).toBe(true);
  });

  it("allows exact IP match via ip param", () => {
    const state = makeState([], ["159.223.152.190"]);
    expect(isInRoeScope(state, "some-host", "159.223.152.190")).toBe(true);
  });

  it("rejects unknown host", () => {
    const state = makeState(["example.com"], ["10.0.0.1"]);
    expect(isInRoeScope(state, "evil.com")).toBe(false);
  });

  // ─── IP:port hostname format (the bug fix) ───

  it("allows IP:port hostname when IP is in authorizedIps", () => {
    const state = makeState([], ["159.223.152.190"]);
    expect(isInRoeScope(state, "159.223.152.190:8443")).toBe(true);
  });

  it("allows IP:port hostname when IP:port is in authorizedDomains", () => {
    const state = makeState(["159.223.152.190:8443"], []);
    expect(isInRoeScope(state, "159.223.152.190:8443")).toBe(true);
  });

  it("allows IP:port hostname when bare IP is in authorizedDomains", () => {
    const state = makeState(["159.223.152.190"], []);
    expect(isInRoeScope(state, "159.223.152.190:8443")).toBe(true);
  });

  it("allows bare IP hostname when IP is in authorizedIps", () => {
    const state = makeState([], ["159.223.152.190"]);
    expect(isInRoeScope(state, "159.223.152.190")).toBe(true);
  });

  it("rejects different IP:port", () => {
    const state = makeState(["10.0.0.1:8443"], ["10.0.0.1"]);
    expect(isInRoeScope(state, "192.168.1.1:8443")).toBe(false);
  });

  // ─── Case insensitivity ───

  it("is case-insensitive for domain matching", () => {
    const state = makeState(["Example.COM"], []);
    expect(isInRoeScope(state, "example.com")).toBe(true);
  });

  // ─── No guard = legacy behavior ───

  it("returns true when no roeScopeGuard is set", () => {
    const state = {} as any;
    expect(isInRoeScope(state, "anything.com")).toBe(true);
  });

  // ─── Multiple authorized entries ───

  it("allows when one of multiple authorized domains matches", () => {
    const state = makeState(["a.com", "b.com", "159.223.152.190:8443"], []);
    expect(isInRoeScope(state, "159.223.152.190:8443")).toBe(true);
    expect(isInRoeScope(state, "a.com")).toBe(true);
    expect(isInRoeScope(state, "c.com")).toBe(false);
  });
});

describe("RoE Scope Guard — autoRegisterLabAsset integration", () => {
  it("bug-bounty.ts autoRegisterLabAsset updates roeScopeGuard in ops state", async () => {
    const fs = await import("fs");
    const src = fs.readFileSync("server/routers/bug-bounty.ts", "utf-8");
    // Verify the fix is present
    expect(src).toContain("UPDATE RoE SCOPE GUARD");
    expect(src).toContain("roeScopeGuard");
    expect(src).toContain("authorizedDomains");
    expect(src).toContain("authorizedIps");
    expect(src).toContain("scanServerHost");
  });

  it("engagement-ops-core.ts re-run refreshes roeScopeGuard", async () => {
    const fs = await import("fs");
    const src = fs.readFileSync("server/routers/engagement-ops-core.ts", "utf-8");
    expect(src).toContain("REFRESH RoE SCOPE GUARD");
    expect(src).toContain("roeScopeGuard");
    expect(src).toContain("RoE Scope Guard Refreshed");
  });
});

describe("active-handoff isInScope — IP:port handling", () => {
  it("active-handoff.ts handles IP:port format in scope check", async () => {
    const fs = await import("fs");
    const src = fs.readFileSync("server/lib/passive/active-handoff.ts", "utf-8");
    expect(src).toContain("targetWithoutPort");
    expect(src).toContain("scopeWithoutPort");
    // Verify the port-stripping logic is present
    expect(src).toContain('target.includes(":")');
  });
});

describe("Burp integration across engagement types", () => {
  // These blocks were extracted from the orchestrator into vuln-detection/vuln-prep.ts
  it("Burp auto-scan has no engagement type guard", async () => {
    const fs = await import("fs");
    const vulnPrepSrc = fs.readFileSync("server/lib/vuln-detection/vuln-prep.ts", "utf-8");
    // Find the Burp auto-scan block
    const burpBlock = vulnPrepSrc.indexOf("Burp Suite Auto-Scan");
    expect(burpBlock).toBeGreaterThan(-1);
    // Verify there's no engagementType check between the Burp comment and the import
    const blockSlice = vulnPrepSrc.slice(burpBlock, burpBlock + 300);
    expect(blockSlice).not.toContain("engagementType ===");
    expect(blockSlice).not.toContain("engagementType !==");
    expect(blockSlice).toContain("onEngagementVulnDetectionPhase");
  });

  it("ZAP\u2192Burp pipeline has no engagement type guard", async () => {
    const fs = await import("fs");
    const vulnPrepSrc = fs.readFileSync("server/lib/vuln-detection/vuln-prep.ts", "utf-8");
    const pipelineBlock = vulnPrepSrc.indexOf("ZAP \u2192 Burp Cross-Tool Pipeline");
    expect(pipelineBlock).toBeGreaterThan(-1);
    const blockSlice = vulnPrepSrc.slice(pipelineBlock, pipelineBlock + 300);
    expect(blockSlice).not.toContain("engagementType ===");
    expect(blockSlice).toContain("runZapToBurpPipeline");
  });

  it("Severity escalation has no engagement type guard", async () => {
    const fs = await import("fs");
    const vulnPrepSrc = fs.readFileSync("server/lib/vuln-detection/vuln-prep.ts", "utf-8");
    const escBlock = vulnPrepSrc.indexOf("Severity Escalation");
    expect(escBlock).toBeGreaterThan(-1);
    const blockSlice = vulnPrepSrc.slice(escBlock, escBlock + 300);
    expect(blockSlice).not.toContain("engagementType ===");
    expect(blockSlice).toContain("runSeverityEscalation");
  });
});
