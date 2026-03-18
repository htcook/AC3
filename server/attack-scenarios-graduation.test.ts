import { describe, it, expect } from "vitest";
import {
  SCAN_SERVER_TARGETS,
  DO_LAB_TEMPLATES,
} from "./lib/test-lab-infrastructure";
import {
  ALL_OFFENSIVE_AGENTS,
  matchCallerToAgent,
} from "./lib/agent-definitions";
import {
  getAllModelStates,
} from "./lib/graduation-lab-bridge";

describe("Attack Scenarios — Live Targets", () => {
  it("should export at least 5 scan server targets", () => {
    expect(Array.isArray(SCAN_SERVER_TARGETS)).toBe(true);
    expect(SCAN_SERVER_TARGETS.length).toBeGreaterThanOrEqual(5);
  });

  it("each target should have required fields (id, name, url, type)", () => {
    for (const target of SCAN_SERVER_TARGETS) {
      expect(target).toHaveProperty("id");
      expect(target).toHaveProperty("name");
      expect(target).toHaveProperty("url");
      expect(target).toHaveProperty("type");
      expect(typeof target.id).toBe("string");
      expect(typeof target.name).toBe("string");
      expect(typeof target.url).toBe("string");
      expect(target.type).toBe("scan_server");
    }
  });

  it("each target should have vulnerability metadata with severity", () => {
    for (const target of SCAN_SERVER_TARGETS) {
      expect(target).toHaveProperty("knownVulns");
      expect(Array.isArray(target.knownVulns)).toBe(true);
      expect(target.knownVulns.length).toBeGreaterThan(0);
      for (const vuln of target.knownVulns) {
        expect(vuln).toHaveProperty("type");
        expect(vuln).toHaveProperty("severity");
        expect(["critical", "high", "medium", "low"]).toContain(vuln.severity);
      }
    }
  });

  it("should include known vulnerable apps (DVWA, bWAPP, Mutillidae, Juice Shop, WebGoat)", () => {
    const names = SCAN_SERVER_TARGETS.map((t: any) => t.name.toLowerCase());
    expect(names.some((n: string) => n.includes("dvwa"))).toBe(true);
    expect(names.some((n: string) => n.includes("bwapp"))).toBe(true);
    expect(names.some((n: string) => n.includes("mutillidae"))).toBe(true);
    expect(names.some((n: string) => n.includes("juice"))).toBe(true);
    expect(names.some((n: string) => n.includes("webgoat"))).toBe(true);
  });

  it("each target should have services list with port and service name", () => {
    for (const target of SCAN_SERVER_TARGETS) {
      expect(target).toHaveProperty("services");
      expect(Array.isArray(target.services)).toBe(true);
      expect(target.services.length).toBeGreaterThan(0);
      for (const svc of target.services) {
        expect(svc).toHaveProperty("port");
        expect(svc).toHaveProperty("service");
        expect(typeof svc.port).toBe("number");
      }
    }
  });
});

describe("Attack Scenarios — DO Lab Templates", () => {
  it("should export lab templates", () => {
    expect(Array.isArray(DO_LAB_TEMPLATES)).toBe(true);
    expect(DO_LAB_TEMPLATES.length).toBeGreaterThan(0);
  });

  it("each template should have required fields (id, name, description)", () => {
    for (const template of DO_LAB_TEMPLATES) {
      expect(template).toHaveProperty("id");
      expect(template).toHaveProperty("name");
      // Templates use 'desc' not 'description'
      expect(typeof template.id).toBe("string");
      expect(typeof template.name).toBe("string");
    }
  });
});

describe("Graduation Engine — Model States", () => {
  it("getAllModelStates should return an array of specialist model states", () => {
    const states = getAllModelStates();
    expect(Array.isArray(states)).toBe(true);
    expect(states.length).toBeGreaterThan(0);
  });

  it("each model state should have required graduation fields", () => {
    const states = getAllModelStates();
    for (const state of states) {
      expect(state).toHaveProperty("model");
      expect(state).toHaveProperty("currentTier");
      expect(state).toHaveProperty("labAccessLevel");
      expect(state).toHaveProperty("scenariosCompleted");
      expect(state).toHaveProperty("averageScore");
      expect(state).toHaveProperty("trainingExamples");
      expect(typeof state.currentTier).toBe("number");
      expect(state.currentTier).toBeGreaterThanOrEqual(1);
      expect(state.currentTier).toBeLessThanOrEqual(5);
    }
  });

  it("model states should include benchmark and training data", () => {
    const states = getAllModelStates();
    for (const state of states) {
      expect(state).toHaveProperty("lastBenchmarkScore");
      expect(state).toHaveProperty("fineTuneRuns");
      expect(state).toHaveProperty("currentModelVersion");
      expect(typeof state.lastBenchmarkScore).toBe("number");
    }
  });

  it("should have at least 6 specialist models", () => {
    const states = getAllModelStates();
    expect(states.length).toBeGreaterThanOrEqual(6);
  });

  it("model states should include events history", () => {
    const states = getAllModelStates();
    for (const state of states) {
      expect(state).toHaveProperty("events");
      expect(Array.isArray(state.events)).toBe(true);
    }
  });
});

describe("Agent Definitions — 10 Specialist Agents", () => {
  it("should have exactly 10 offensive agents", () => {
    expect(ALL_OFFENSIVE_AGENTS.length).toBe(10);
  });

  it("should include all 5 original agents with offensive- prefix", () => {
    const ids = ALL_OFFENSIVE_AGENTS.map((a: any) => a.agentId);
    expect(ids).toContain("offensive-osint-analyst-v1");
    expect(ids).toContain("offensive-pentester-v1");
    expect(ids).toContain("offensive-social-engineer-v1");
    expect(ids).toContain("offensive-red-team-operator-v1");
    expect(ids).toContain("offensive-report-writer-v1");
  });

  it("should include all 5 new specialist agents with offensive- prefix", () => {
    const ids = ALL_OFFENSIVE_AGENTS.map((a: any) => a.agentId);
    expect(ids).toContain("offensive-scan-analyst-v1");
    expect(ids).toContain("offensive-exploit-selector-v1");
    expect(ids).toContain("offensive-evasion-optimizer-v1");
    expect(ids).toContain("offensive-lateral-planner-v1");
    expect(ids).toContain("offensive-persistence-engineer-v1");
  });

  it("matchCallerToAgent should match scan-related callers to scan-analyst", () => {
    // 'vulnerability' matches pentester first; use 'nmap-scan-handler' which matches scan-analyst
    const match = matchCallerToAgent("nmap-scan-handler");
    expect(match?.agentId).toBe("offensive-scan-analyst-v1");
  });

  it("matchCallerToAgent should match evasion callers to evasion-optimizer", () => {
    const match = matchCallerToAgent("evasion-check-handler");
    expect(match?.agentId).toBe("offensive-evasion-optimizer-v1");
  });

  it("matchCallerToAgent should match lateral callers to lateral-planner", () => {
    const match = matchCallerToAgent("lateral-movement-handler");
    expect(match?.agentId).toBe("offensive-lateral-planner-v1");
  });

  it("matchCallerToAgent should match persistence callers to persistence-engineer", () => {
    const match = matchCallerToAgent("persistence-install-handler");
    expect(match?.agentId).toBe("offensive-persistence-engineer-v1");
  });

  it("matchCallerToAgent should return undefined for unknown callers", () => {
    const match = matchCallerToAgent("completely-unknown-random-caller-xyz");
    expect(match).toBeUndefined();
  });

  it("each agent should have persona, mission, and core rules", () => {
    for (const agent of ALL_OFFENSIVE_AGENTS) {
      expect(agent).toHaveProperty("persona");
      expect(agent).toHaveProperty("mission");
      expect(agent).toHaveProperty("coreRules");
      expect(typeof agent.persona).toBe("string");
      expect(typeof agent.mission).toBe("string");
      expect(agent.persona.length).toBeGreaterThan(10);
      expect(agent.mission.length).toBeGreaterThan(10);
    }
  });
});
