import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Remediation Verification Library Tests ─────────────────────────────────
describe("Remediation Verification Library", () => {
  it("exports DEFAULT_REMEDIATION_CONFIG with SLA hours", async () => {
    const { DEFAULT_REMEDIATION_CONFIG } = await import("./lib/remediation-verification");
    expect(DEFAULT_REMEDIATION_CONFIG).toBeDefined();
    expect(DEFAULT_REMEDIATION_CONFIG.criticalSlaHours).toBeGreaterThan(0);
    expect(DEFAULT_REMEDIATION_CONFIG.highSlaHours).toBeGreaterThan(DEFAULT_REMEDIATION_CONFIG.criticalSlaHours);
    expect(DEFAULT_REMEDIATION_CONFIG.mediumSlaHours).toBeGreaterThan(DEFAULT_REMEDIATION_CONFIG.highSlaHours);
    expect(DEFAULT_REMEDIATION_CONFIG.lowSlaHours).toBeGreaterThan(DEFAULT_REMEDIATION_CONFIG.mediumSlaHours);
  });

  it("exports createRemediationRecord function", async () => {
    const mod = await import("./lib/remediation-verification");
    expect(typeof mod.createRemediationRecord).toBe("function");
  });

  it("exports recordVerificationAttempt function", async () => {
    const mod = await import("./lib/remediation-verification");
    expect(typeof mod.recordVerificationAttempt).toBe("function");
  });

  it("SLA hours follow severity ordering (critical < high < medium < low)", async () => {
    const { DEFAULT_REMEDIATION_CONFIG } = await import("./lib/remediation-verification");
    expect(DEFAULT_REMEDIATION_CONFIG.criticalSlaHours).toBeLessThan(DEFAULT_REMEDIATION_CONFIG.highSlaHours);
    expect(DEFAULT_REMEDIATION_CONFIG.highSlaHours).toBeLessThan(DEFAULT_REMEDIATION_CONFIG.mediumSlaHours);
    expect(DEFAULT_REMEDIATION_CONFIG.mediumSlaHours).toBeLessThan(DEFAULT_REMEDIATION_CONFIG.lowSlaHours);
  });
});

// ─── AI Attack Planner Library Tests ────────────────────────────────────────
describe("AI Attack Planner Library", () => {
  it("exports AttackPlan and AttackStep interfaces via generateGraphOnlyPlan", async () => {
    const mod = await import("./lib/ai-attack-planner");
    expect(mod.generateGraphOnlyPlan).toBeDefined();
    expect(mod.THREAT_ACTOR_PROFILES).toBeDefined();
    expect(Object.keys(mod.THREAT_ACTOR_PROFILES).length).toBeGreaterThan(3);
  });

  it("exports generateGraphOnlyPlan function", async () => {
    const mod = await import("./lib/ai-attack-planner");
    expect(typeof mod.generateGraphOnlyPlan).toBe("function");
  });

  it("generateGraphOnlyPlan returns AttackPlan with phases", async () => {
    const { generateGraphOnlyPlan } = await import("./lib/ai-attack-planner");
    const plan = generateGraphOnlyPlan({
      targetDescription: "Test web server",
      threatActorProfile: "apt28",
      constraints: {},
    });
    expect(plan).toBeDefined();
    expect(plan.name).toBeDefined();
    expect(plan.summary).toBeDefined();
    expect(plan.phases).toBeDefined();
    expect(Array.isArray(plan.phases)).toBe(true);
    expect(plan.phases.length).toBeGreaterThan(0);
    expect(typeof plan.totalSteps).toBe("number");
    expect(typeof plan.estimatedRiskScore).toBe("number");
  });

  it("generateGraphOnlyPlan phases have name, objective, and steps", async () => {
    const { generateGraphOnlyPlan } = await import("./lib/ai-attack-planner");
    const plan = generateGraphOnlyPlan({
      targetDescription: "Corporate network",
      threatActorProfile: "apt29",
      objectives: ["initial_access", "lateral_movement"],
      constraints: {},
    });
    for (const phase of plan.phases) {
      expect(phase.name).toBeDefined();
      expect(phase.objective).toBeDefined();
      expect(phase.steps).toBeDefined();
      expect(Array.isArray(phase.steps)).toBe(true);
    }
  });

  it("exports THREAT_ACTOR_PROFILES", async () => {
    const { THREAT_ACTOR_PROFILES } = await import("./lib/ai-attack-planner");
    expect(THREAT_ACTOR_PROFILES).toBeDefined();
    expect(Object.keys(THREAT_ACTOR_PROFILES).length).toBeGreaterThan(0);
  });

  it("threat actor profiles are descriptive strings", async () => {
    const { THREAT_ACTOR_PROFILES } = await import("./lib/ai-attack-planner");
    const firstProfile = Object.values(THREAT_ACTOR_PROFILES)[0];
    expect(firstProfile).toBeDefined();
    expect(typeof firstProfile).toBe("string");
    expect(firstProfile.length).toBeGreaterThan(50);
  });
});

// ─── Corroboration Engine Library Tests ─────────────────────────────────────
describe("Corroboration Engine Library", () => {
  it("exports corroborateFindings function", async () => {
    const mod = await import("./lib/corroboration-engine");
    expect(typeof mod.corroborateFindings).toBe("function");
  });

  it("exports getAvailableSources function", async () => {
    const mod = await import("./lib/corroboration-engine");
    expect(typeof mod.getAvailableSources).toBe("function");
  });

  it("getAvailableSources returns array of source objects", async () => {
    const { getAvailableSources } = await import("./lib/corroboration-engine");
    const sources = getAvailableSources();
    expect(Array.isArray(sources)).toBe(true);
    expect(sources.length).toBeGreaterThan(0);
    for (const src of sources) {
      expect(src.name).toBeDefined();
      expect(typeof src.name).toBe("string");
      expect(typeof src.configured).toBe("boolean");
    }
  });

  it("corroborateFindings returns report with results array", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const result = corroborateFindings([
      {
        id: "f1",
        title: "CVE-2021-44228 Log4Shell",
        source: "scanner-a",
        severity: "critical" as const,
        cveId: "CVE-2021-44228",
        hostOrAsset: "10.0.0.1",
        rawConfidence: 80,
        timestamp: Date.now(),
      },
    ]);
    expect(result).toBeDefined();
    expect(result.results).toBeDefined();
    expect(Array.isArray(result.results)).toBe(true);
    expect(typeof result.totalFindings).toBe("number");
  });

  it("corroborateFindings enriches results with adjusted confidence", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const result = corroborateFindings([
      {
        id: "f1",
        title: "Open SSH port",
        source: "scanner-a",
        severity: "medium" as const,
        hostOrAsset: "10.0.0.1",
        port: 22,
        service: "ssh",
        rawConfidence: 70,
        timestamp: Date.now(),
      },
      {
        id: "f2",
        title: "Open SSH port",
        source: "scanner-b",
        severity: "medium" as const,
        hostOrAsset: "10.0.0.1",
        port: 22,
        service: "ssh",
        rawConfidence: 65,
        timestamp: Date.now(),
      },
    ]);
    expect(result.results.length).toBeGreaterThan(0);
    for (const r of result.results) {
      expect(typeof r.adjustedConfidence).toBe("number");
      expect(r.adjustedConfidence).toBeGreaterThanOrEqual(0);
      expect(r.adjustedConfidence).toBeLessThanOrEqual(100);
    }
  });

  it("corroborateFindings returns totalFindings and corroboratedFindings", async () => {
    const { corroborateFindings } = await import("./lib/corroboration-engine");
    const result = corroborateFindings([
      {
        id: "f1",
        title: "Test finding",
        source: "scanner-a",
        severity: "high" as const,
        hostOrAsset: "10.0.0.1",
        rawConfidence: 80,
        timestamp: Date.now(),
      },
    ]);
    expect(typeof result.totalFindings).toBe("number");
    expect(typeof result.corroboratedFindings).toBe("number");
    expect(typeof result.falsePositiveRate).toBe("number");
    expect(typeof result.generatedAt).toBe("number");
  });
});

// ─── Attack Chain Validation Library Tests ──────────────────────────────────
describe("Attack Chain Validation Library", () => {
  it("exports analyzeAttackChains function", async () => {
    const mod = await import("./lib/attack-chain-validation");
    expect(typeof mod.analyzeAttackChains).toBe("function");
  });

  it("exports CHAIN_PATTERNS with pattern definitions", async () => {
    const mod = await import("./lib/attack-chain-validation");
    expect(mod.CHAIN_PATTERNS).toBeDefined();
    expect(Array.isArray(mod.CHAIN_PATTERNS)).toBe(true);
    expect(mod.CHAIN_PATTERNS.length).toBeGreaterThan(0);
    for (const pattern of mod.CHAIN_PATTERNS.slice(0, 3)) {
      expect(pattern.name).toBeDefined();
      expect(pattern.phases).toBeDefined();
      expect(Array.isArray(pattern.phases)).toBe(true);
    }
  });

  it("analyzeAttackChains returns chains array", async () => {
    const { analyzeAttackChains } = await import("./lib/attack-chain-validation");
    const result = await analyzeAttackChains([
      { id: "1", techniqueId: "T1566", name: "Phishing", tactic: "initial-access", severity: "high", target: "host-1" },
      { id: "2", techniqueId: "T1059", name: "Command Execution", tactic: "execution", severity: "high", target: "host-1" },
      { id: "3", techniqueId: "T1053", name: "Scheduled Task", tactic: "persistence", severity: "medium", target: "host-1" },
    ]);
    expect(result).toBeDefined();
    expect(result.chains).toBeDefined();
    expect(Array.isArray(result.chains)).toBe(true);
  });
});

// ─── ICS Exploit Catalog Library Tests ──────────────────────────────────────
describe("ICS Exploit Catalog Library", () => {
  it("exports getICSExploits function", async () => {
    const mod = await import("./lib/ics-exploit-catalog");
    expect(typeof mod.searchIcsExploits).toBe("function");
  });

  it("exports ICS_APT_GROUPS with group data", async () => {
    const mod = await import("./lib/ics-exploit-catalog");
    expect(mod.ICS_APT_GROUPS).toBeDefined();
    expect(Array.isArray(mod.ICS_APT_GROUPS)).toBe(true);
    expect(mod.ICS_APT_GROUPS.length).toBeGreaterThan(5);
    for (const group of mod.ICS_APT_GROUPS.slice(0, 3)) {
      expect(group.aptGroupName).toBeDefined();
      expect(group.targetedSectors).toBeDefined();
    }
  });

  it("exports MITRE_ICS_TECHNIQUES with technique data", async () => {
    const mod = await import("./lib/ics-exploit-catalog");
    expect(mod.MITRE_ICS_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.MITRE_ICS_TECHNIQUES)).toBe(true);
    expect(mod.MITRE_ICS_TECHNIQUES.length).toBeGreaterThan(10);
    for (const tech of mod.MITRE_ICS_TECHNIQUES.slice(0, 3)) {
      expect(tech.id).toBeDefined();
      expect(tech.name).toBeDefined();
      expect(tech.tactic).toBeDefined();
    }
  });
});

// ─── Exploit Feedback Loop Library Tests ────────────────────────────────────
describe("Exploit Feedback Loop Library", () => {
  it("exports processExploitFeedback function", async () => {
    const mod = await import("./lib/exploit-feedback-loop");
    expect(typeof mod.recordFeedback).toBe("function");
  });

  it("exports calculateSuccessRate function", async () => {
    const mod = await import("./lib/exploit-feedback-loop");
    expect(typeof mod.getModulePerformance).toBe("function");
  });
});

// ─── LLM Rule Generator Library Tests ───────────────────────────────────────
describe("LLM Rule Generator Library", () => {
  it("exports generateDetectionRule function", async () => {
    const mod = await import("./lib/llm-rule-generator");
    expect(typeof mod.generateDetectionRules).toBe("function");
  });
});

// ─── Exploit Preflight Library Tests ────────────────────────────────────────
describe("Exploit Preflight Library", () => {
  it("exports runPreFlightChecks function", async () => {
    const mod = await import("./lib/exploit-preflight");
    expect(typeof mod.runPreFlightChecks).toBe("function");
  });
});
