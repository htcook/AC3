import { describe, it, expect } from "vitest";
import { isInRoeScope, EngagementOpsState } from "./lib/engagement-orchestrator";

function makeState(guard?: { authorizedDomains: string[]; authorizedIps: string[]; roeStatus: string }): EngagementOpsState {
  return {
    engagementId: 1,
    engagementType: "pentest",
    phase: "recon",
    progress: 0,
    isRunning: false,
    isPaused: false,
    assets: [],
    log: [],
    approvalGates: [],
    stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
    roeScopeGuard: guard,
  };
}

describe("RoE Scope Guard", () => {
  it("allows all targets when no scope guard is set (legacy behavior)", () => {
    const state = makeState(undefined);
    expect(isInRoeScope(state, "random.example.com")).toBe(true);
    expect(isInRoeScope(state, "anything.test")).toBe(true);
  });

  it("allows exact domain matches", () => {
    const state = makeState({
      authorizedDomains: ["dashboard-dev.vianovahealth.com", "api.dev.vianova.ai"],
      authorizedIps: ["23.20.98.48"],
      roeStatus: "signed",
    });
    expect(isInRoeScope(state, "dashboard-dev.vianovahealth.com")).toBe(true);
    expect(isInRoeScope(state, "api.dev.vianova.ai")).toBe(true);
  });

  it("allows exact IP matches", () => {
    const state = makeState({
      authorizedDomains: ["dashboard-dev.vianovahealth.com"],
      authorizedIps: ["23.20.98.48"],
      roeStatus: "signed",
    });
    expect(isInRoeScope(state, "unknown-host", "23.20.98.48")).toBe(true);
  });

  it("rejects out-of-scope domains", () => {
    const state = makeState({
      authorizedDomains: ["dashboard-dev.vianovahealth.com", "api.dev.vianova.ai"],
      authorizedIps: ["23.20.98.48"],
      roeStatus: "signed",
    });
    expect(isInRoeScope(state, "www.vianovahealth.com")).toBe(false);
    expect(isInRoeScope(state, "vianovahealth.com")).toBe(false);
    expect(isInRoeScope(state, "staging.vianova.ai")).toBe(false);
    expect(isInRoeScope(state, "random-other-site.com")).toBe(false);
  });

  it("rejects out-of-scope IPs", () => {
    const state = makeState({
      authorizedDomains: ["dashboard-dev.vianovahealth.com"],
      authorizedIps: ["23.20.98.48"],
      roeStatus: "signed",
    });
    expect(isInRoeScope(state, "unknown", "10.0.0.1")).toBe(false);
    expect(isInRoeScope(state, "unknown", "23.20.98.49")).toBe(false);
  });

  it("is case-insensitive for domain matching", () => {
    const state = makeState({
      authorizedDomains: ["Dashboard-Dev.VianovaHealth.COM"],
      authorizedIps: [],
      roeStatus: "signed",
    });
    expect(isInRoeScope(state, "dashboard-dev.vianovahealth.com")).toBe(true);
    expect(isInRoeScope(state, "DASHBOARD-DEV.VIANOVAHEALTH.COM")).toBe(true);
  });

  it("trims whitespace from hostnames and IPs", () => {
    const state = makeState({
      authorizedDomains: [" dashboard-dev.vianovahealth.com "],
      authorizedIps: [" 23.20.98.48 "],
      roeStatus: "signed",
    });
    expect(isInRoeScope(state, "dashboard-dev.vianovahealth.com")).toBe(true);
    expect(isInRoeScope(state, "unknown", "23.20.98.48")).toBe(true);
  });

  it("does NOT allow subdomains of authorized domains (strict mode)", () => {
    const state = makeState({
      authorizedDomains: ["vianovahealth.com"],
      authorizedIps: [],
      roeStatus: "signed",
    });
    // Subdomains should NOT be in scope unless explicitly listed
    expect(isInRoeScope(state, "sub.vianovahealth.com")).toBe(false);
    expect(isInRoeScope(state, "dashboard-dev.vianovahealth.com")).toBe(false);
    // The exact domain IS in scope
    expect(isInRoeScope(state, "vianovahealth.com")).toBe(true);
  });
});
