/**
 * Sprint 11C — Graduation Engine ↔ Telemetry Integration Tests
 *
 * Tests:
 *   1. runGraduationWithTelemetry emits correct events
 *   2. Scoring breakdown is accurate
 *   3. Knowledge gap detection for zero-score models
 *   4. Methodology bonus tracking
 *   5. computeGraduationHealth extracts metrics from events
 *   6. generateGraduationDiagnosticSection produces markdown
 *   7. Helper functions (buildGapReasoning, shouldHaveScored, getRelevantMetrics)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the graduation module
vi.mock("./lib/post-pipeline-graduation", () => ({
  runPostPipelineGraduation: vi.fn().mockResolvedValue({
    scores: {
      recon_analyst: 75,
      exploit_selector: 45,
      evasion_optimizer: 90,
      cognitive_core: 60,
      cloud_assessor: 20,
      supply_chain_analyst: 15,
    },
    passed: {
      recon_analyst: true,
      exploit_selector: true,
      evasion_optimizer: true,
      cognitive_core: true,
      cloud_assessor: true,
      supply_chain_analyst: true,
    },
    trainingExamplesCollected: 5,
    modelsScored: 6,
    summary: "6 specialist models scored (avg 50/100, 6 passed). Training examples: 5",
  }),
}));

// Mock the telemetry-integration to avoid real context registry conflicts
vi.mock("./lib/telemetry-integration", async (importOriginal) => {
  const actual = await importOriginal() as any;
  return {
    ...actual,
    getTelemetryContext: vi.fn().mockReturnValue(undefined),
  };
});

import {
  runGraduationWithTelemetry,
  computeGraduationHealth,
  generateGraduationDiagnosticSection,
  GRADUATION_THRESHOLDS,
  buildGapReasoning,
  shouldHaveScored,
  getRelevantMetrics,
} from "./lib/graduation-telemetry";

import type { PipelineMetrics } from "./lib/post-pipeline-graduation";
import type { TelemetryEvent } from "./lib/telemetry-logger";

// ─── Test Data ──────────────────────────────────────────────────────────────

function makeMetrics(overrides?: Partial<PipelineMetrics>): PipelineMetrics {
  return {
    pipelineType: "engagement",
    pipelineId: 42,
    domain: "test.example.com",
    assetsDiscovered: 5,
    subdomainsFound: 3,
    portsFound: 12,
    servicesIdentified: 8,
    technologiesDetected: 6,
    totalVulns: 10,
    confirmedVulns: 7,
    potentialVulns: 3,
    criticalVulns: 2,
    highVulns: 3,
    mediumVulns: 4,
    lowVulns: 1,
    infoVulns: 0,
    uniqueCVEs: 5,
    kevMatches: 1,
    exploitsAttempted: 4,
    exploitsSucceeded: 3,
    verifiedVulns: 7,
    nucleiVerifiedExploits: 2,
    wafDetected: false,
    wafBypassed: false,
    evasionEscalations: 0,
    scanBlocked: false,
    scanRecovered: false,
    owaspCategoriesTested: 15,
    owaspCategoriesTotal: 25,
    ptesPhasesCovered: 5,
    ptesPhasesTotal: 7,
    cloudAssetsFound: 2,
    repoExposuresFound: 1,
    platformAssetsFound: 1,
    containerAssetsFound: 0,
    storageAssetsFound: 1,
    identityAssetsFound: 0,
    networkInfraFound: 0,
    falsePositiveRate: 0.1,
    connectorSuccessRate: 0.9,
    scanDurationMs: 120000,
    successfulExploits: [
      { id: "exp-1", target: "10.0.0.5", vulnTitle: "RCE in Apache", technique: "T1190", tool: "metasploit" },
    ],
    reconObservations: [
      { source: "shodan", assetType: "host", name: "test.example.com", findings: 3 },
    ],
    ...overrides,
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("Graduation Telemetry — runGraduationWithTelemetry", () => {
  it("returns graduation result with telemetry metadata", async () => {
    const metrics = makeMetrics();
    const result = await runGraduationWithTelemetry(metrics);

    expect(result.scores).toBeDefined();
    expect(result.passed).toBeDefined();
    expect(result.telemetry).toBeDefined();
    expect(result.telemetry.modelsScored).toBe(6);
    expect(result.telemetry.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("emits scoring breakdown for all models", async () => {
    const metrics = makeMetrics();
    const result = await runGraduationWithTelemetry(metrics);

    expect(result.telemetry.scoringBreakdown).toHaveLength(6);
    const models = result.telemetry.scoringBreakdown.map((s) => s.model);
    expect(models).toContain("recon_analyst");
    expect(models).toContain("exploit_selector");
    expect(models).toContain("evasion_optimizer");
    expect(models).toContain("cognitive_core");
    expect(models).toContain("cloud_assessor");
    expect(models).toContain("supply_chain_analyst");
  });

  it("tracks models passed and failed", async () => {
    const metrics = makeMetrics();
    const result = await runGraduationWithTelemetry(metrics);

    expect(result.telemetry.modelsPassed).toBe(6);
    expect(result.telemetry.modelsFailed).toBe(0);
    expect(result.telemetry.modelsPassed + result.telemetry.modelsFailed).toBe(6);
  });

  it("records training examples collected", async () => {
    const metrics = makeMetrics();
    const result = await runGraduationWithTelemetry(metrics);

    expect(result.telemetry.trainingExamplesCollected).toBe(5);
  });

  it("emits telemetry events during graduation", async () => {
    const metrics = makeMetrics();
    const result = await runGraduationWithTelemetry(metrics);

    // Should have: phase_transition + graduation_start + run_graduation_scoring (call+response) + 6 model scores + training_data + verdict
    expect(result.telemetry.totalEvents).toBeGreaterThanOrEqual(10);
  });

  it("works with engagement ID", async () => {
    const metrics = makeMetrics();
    const result = await runGraduationWithTelemetry(metrics, 42);

    expect(result.scores).toBeDefined();
    expect(result.telemetry.durationMs).toBeGreaterThanOrEqual(0);
  });
});

describe("Graduation Telemetry — computeGraduationHealth", () => {
  function makeGradEvents(): TelemetryEvent[] {
    const base = {
      engagementId: 1,
      phase: "graduation",
      eventType: "tool_response" as const,
      success: true,
      errorClass: "none" as const,
      retryCount: 0,
      storageProvider: "local",
      createdAt: new Date().toISOString(),
    };

    return [
      { ...base, step: "score_recon_analyst", outputSummary: "recon_analyst: 75/100 (threshold: 30) → PASS", success: true },
      { ...base, step: "score_exploit_selector", outputSummary: "exploit_selector: 45/100 (threshold: 20) → PASS", success: true },
      { ...base, step: "score_evasion_optimizer", outputSummary: "evasion_optimizer: 90/100 (threshold: 50) → PASS", success: true },
      { ...base, step: "score_cognitive_core", outputSummary: "cognitive_core: 60/100 (threshold: 40) → PASS", success: true },
      { ...base, step: "score_cloud_assessor", outputSummary: "cloud_assessor: 20/100 (threshold: 10) → PASS", success: true },
      { ...base, step: "score_supply_chain_analyst", outputSummary: "supply_chain_analyst: 15/100 (threshold: 10) → PASS", success: true },
      { ...base, step: "training_data_collection", outputSummary: "Collected 5 training examples from engagement pipeline", success: true },
      { ...base, step: "graduation_verdict", eventType: "decision", inputSummary: "6/6 models passed | Avg score: 50/100", success: true },
    ];
  }

  it("computes average score from events", () => {
    const events = makeGradEvents();
    const health = computeGraduationHealth(events);

    expect(health).not.toBeNull();
    expect(health!.avgScore).toBe(Math.round((75 + 45 + 90 + 60 + 20 + 15) / 6));
  });

  it("identifies weakest and strongest models", () => {
    const events = makeGradEvents();
    const health = computeGraduationHealth(events);

    expect(health!.weakestModel).toBe("supply_chain_analyst");
    expect(health!.strongestModel).toBe("evasion_optimizer");
  });

  it("computes pass rate", () => {
    const events = makeGradEvents();
    const health = computeGraduationHealth(events);

    expect(health!.passRate).toBe(1.0); // All passed
  });

  it("detects training data quality", () => {
    const events = makeGradEvents();
    const health = computeGraduationHealth(events);

    // The function sums training examples from events - single event with "Collected 5" = 5 total
    // Threshold: >= 10 = high, >= 3 = medium, else low
    expect(health!.trainingDataQuality).toBe("medium");
  });

  it("returns null for non-graduation events", () => {
    const events: TelemetryEvent[] = [
      {
        engagementId: 1,
        phase: "recon",
        step: "nmap_scan",
        eventType: "tool_response",
        success: true,
        errorClass: "none",
        retryCount: 0,
        storageProvider: "local",
        createdAt: new Date().toISOString(),
      },
    ];

    const health = computeGraduationHealth(events);
    expect(health).toBeNull();
  });

  it("detects failing models in pass rate", () => {
    const base = {
      engagementId: 1,
      phase: "graduation",
      eventType: "tool_response" as const,
      errorClass: "none" as const,
      retryCount: 0,
      storageProvider: "local",
      createdAt: new Date().toISOString(),
    };

    const events: TelemetryEvent[] = [
      { ...base, step: "score_recon_analyst", outputSummary: "recon_analyst: 75/100 (threshold: 30) → PASS", success: true },
      { ...base, step: "score_exploit_selector", outputSummary: "exploit_selector: 10/100 (threshold: 20) → FAIL", success: false },
      { ...base, step: "score_evasion_optimizer", outputSummary: "evasion_optimizer: 30/100 (threshold: 50) → FAIL", success: false },
      { ...base, step: "score_cognitive_core", outputSummary: "cognitive_core: 60/100 (threshold: 40) → PASS", success: true },
    ];

    const health = computeGraduationHealth(events);
    expect(health!.passRate).toBe(0.5); // 2/4 passed
  });

  it("generates recommended actions for weak models", () => {
    const base = {
      engagementId: 1,
      phase: "graduation",
      eventType: "tool_response" as const,
      errorClass: "none" as const,
      retryCount: 0,
      storageProvider: "local",
      createdAt: new Date().toISOString(),
    };

    const events: TelemetryEvent[] = [
      { ...base, step: "score_recon_analyst", outputSummary: "recon_analyst: 10/100 (threshold: 30) → FAIL", success: false },
      { ...base, step: "score_exploit_selector", outputSummary: "exploit_selector: 5/100 (threshold: 20) → FAIL", success: false },
    ];

    const health = computeGraduationHealth(events);
    expect(health!.recommendedActions.length).toBeGreaterThan(0);
    expect(health!.recommendedActions.some((a) => a.includes("Focus training"))).toBe(true);
  });
});

describe("Graduation Telemetry — generateGraduationDiagnosticSection", () => {
  it("generates markdown with health metrics", () => {
    const base = {
      engagementId: 1,
      phase: "graduation",
      eventType: "tool_response" as const,
      success: true,
      errorClass: "none" as const,
      retryCount: 0,
      storageProvider: "local",
      createdAt: new Date().toISOString(),
    };

    const events: TelemetryEvent[] = [
      { ...base, step: "score_recon_analyst", outputSummary: "recon_analyst: 75/100 (threshold: 30) → PASS" },
      { ...base, step: "score_exploit_selector", outputSummary: "exploit_selector: 45/100 (threshold: 20) → PASS" },
      { ...base, step: "score_evasion_optimizer", outputSummary: "evasion_optimizer: 90/100 (threshold: 50) → PASS" },
    ];

    const markdown = generateGraduationDiagnosticSection(events);

    expect(markdown).toContain("Graduation Engine Health");
    expect(markdown).toContain("Average Score");
    expect(markdown).toContain("Pass Rate");
    expect(markdown).toContain("Weakest Model");
    expect(markdown).toContain("Strongest Model");
  });

  it("returns empty string for non-graduation events", () => {
    const events: TelemetryEvent[] = [
      {
        engagementId: 1,
        phase: "recon",
        step: "nmap",
        eventType: "tool_response",
        success: true,
        errorClass: "none",
        retryCount: 0,
        storageProvider: "local",
        createdAt: new Date().toISOString(),
      },
    ];

    const markdown = generateGraduationDiagnosticSection(events);
    expect(markdown).toBe("");
  });
});

describe("Graduation Telemetry — Helper Functions", () => {
  describe("GRADUATION_THRESHOLDS", () => {
    it("has thresholds for all 6 models", () => {
      expect(Object.keys(GRADUATION_THRESHOLDS)).toHaveLength(6);
      expect(GRADUATION_THRESHOLDS.recon_analyst).toBe(30);
      expect(GRADUATION_THRESHOLDS.exploit_selector).toBe(20);
      expect(GRADUATION_THRESHOLDS.evasion_optimizer).toBe(50);
      expect(GRADUATION_THRESHOLDS.cognitive_core).toBe(40);
      expect(GRADUATION_THRESHOLDS.cloud_assessor).toBe(10);
      expect(GRADUATION_THRESHOLDS.supply_chain_analyst).toBe(10);
    });
  });

  describe("buildGapReasoning", () => {
    it("provides reasoning for recon_analyst gaps", () => {
      const metrics = makeMetrics({ assetsDiscovered: 0, subdomainsFound: 0, portsFound: 0 });
      const reasoning = buildGapReasoning("recon_analyst", 10, 30, metrics);

      expect(reasoning).toContain("20 points below");
      expect(reasoning).toContain("Assets: 0");
      expect(reasoning).toContain("No assets discovered");
    });

    it("provides reasoning for exploit_selector gaps", () => {
      const metrics = makeMetrics({ exploitsAttempted: 0, totalVulns: 5 });
      const reasoning = buildGapReasoning("exploit_selector", 5, 20, metrics);

      expect(reasoning).toContain("15 points below");
      expect(reasoning).toContain("Vulns found but no exploits attempted");
    });

    it("provides reasoning for evasion_optimizer gaps", () => {
      const metrics = makeMetrics({ wafDetected: true, scanBlocked: true, scanRecovered: false });
      const reasoning = buildGapReasoning("evasion_optimizer", 30, 50, metrics);

      expect(reasoning).toContain("WAF: detected");
      expect(reasoning).toContain("evasion escalation failed");
    });

    it("provides reasoning for cognitive_core gaps", () => {
      const metrics = makeMetrics({ falsePositiveRate: 0.5 });
      const reasoning = buildGapReasoning("cognitive_core", 25, 40, metrics);

      expect(reasoning).toContain("FP rate: 50.0%");
      expect(reasoning).toContain("High false positive rate");
    });
  });

  describe("shouldHaveScored", () => {
    it("returns true for recon_analyst with assets", () => {
      expect(shouldHaveScored("recon_analyst", makeMetrics())).toBe(true);
    });

    it("returns false for recon_analyst with no assets", () => {
      expect(shouldHaveScored("recon_analyst", makeMetrics({
        assetsDiscovered: 0, subdomainsFound: 0, portsFound: 0,
      }))).toBe(false);
    });

    it("returns true for exploit_selector with exploits", () => {
      expect(shouldHaveScored("exploit_selector", makeMetrics())).toBe(true);
    });

    it("returns false for exploit_selector with no vulns or exploits", () => {
      expect(shouldHaveScored("exploit_selector", makeMetrics({
        exploitsAttempted: 0, totalVulns: 0,
      }))).toBe(false);
    });

    it("returns true for cloud_assessor with cloud assets", () => {
      expect(shouldHaveScored("cloud_assessor", makeMetrics())).toBe(true);
    });

    it("returns false for cloud_assessor with no cloud assets", () => {
      expect(shouldHaveScored("cloud_assessor", makeMetrics({
        cloudAssetsFound: 0, storageAssetsFound: 0,
      }))).toBe(false);
    });
  });

  describe("getRelevantMetrics", () => {
    it("returns recon metrics for recon_analyst", () => {
      const metrics = makeMetrics();
      const relevant = getRelevantMetrics("recon_analyst", metrics);

      expect(relevant).toHaveProperty("assets", 5);
      expect(relevant).toHaveProperty("subdomains", 3);
      expect(relevant).toHaveProperty("ports", 12);
    });

    it("returns exploit metrics for exploit_selector", () => {
      const metrics = makeMetrics();
      const relevant = getRelevantMetrics("exploit_selector", metrics);

      expect(relevant).toHaveProperty("attempted", 4);
      expect(relevant).toHaveProperty("succeeded", 3);
      expect(relevant).toHaveProperty("vulns", 10);
    });

    it("returns empty for unknown model", () => {
      const metrics = makeMetrics();
      const relevant = getRelevantMetrics("unknown_model", metrics);

      expect(Object.keys(relevant)).toHaveLength(0);
    });
  });
});
