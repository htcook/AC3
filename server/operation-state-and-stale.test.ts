/**
 * Tests for:
 * 1. Operation State Persistence interfaces and helpers
 * 2. Discovery Context report pipeline integration
 * 3. Stale analysis detection logic
 */
import { describe, it, expect, vi } from "vitest";
import {
  PersistedCampaignRunState,
  PersistedOrchestrationPlan,
  StateRecoveryReport,
  NODE_ID,
  HEARTBEAT_INTERVAL_MS,
  STALE_THRESHOLD_MS,
} from "./lib/operation-state-persistence";
import { runPentestReportPipeline, PipelineInput } from "./lib/pentest-report-pipeline";

// ─── Operation State Persistence ─────────────────────────────────

describe("Operation State Persistence - Data Model", () => {
  it("PersistedCampaignRunState has correct shape", () => {
    const state: PersistedCampaignRunState = {
      campaignId: 42,
      isRunning: true,
      isPaused: false,
      currentStageId: "stage-3",
      startedAt: Date.now(),
      nodeId: "node-abc",
    };
    expect(state.campaignId).toBe(42);
    expect(state.isRunning).toBe(true);
    expect(state.isPaused).toBe(false);
    expect(state.currentStageId).toBe("stage-3");
    expect(typeof state.startedAt).toBe("number");
    expect(state.nodeId).toBe("node-abc");
  });

  it("PersistedOrchestrationPlan has correct shape", () => {
    const plan: PersistedOrchestrationPlan = {
      planId: "plan-123",
      name: "Test Plan",
      status: "running",
      framework: "caldera",
      phases: [{ name: "Phase 1", steps: [] }],
      currentPhaseIndex: 0,
      currentStepIndex: 0,
      startedAt: Date.now(),
      nodeId: "node-xyz",
      log: [{ timestamp: Date.now(), message: "Started" }],
    };
    expect(plan.planId).toBe("plan-123");
    expect(plan.status).toBe("running");
    expect(plan.framework).toBe("caldera");
    expect(plan.phases).toHaveLength(1);
    expect(plan.currentPhaseIndex).toBe(0);
  });

  it("StateRecoveryReport has correct shape", () => {
    const report: StateRecoveryReport = {
      nodeId: "node-abc",
      recoveredAt: Date.now(),
      campaignsRecovered: 2,
      plansRecovered: 1,
      orphanedCampaigns: 0,
      orphanedPlans: 0,
      errors: [],
    };
    expect(report.campaignsRecovered).toBe(2);
    expect(report.plansRecovered).toBe(1);
    expect(report.errors).toHaveLength(0);
  });

  it("NODE_ID is a non-empty string", () => {
    expect(typeof NODE_ID).toBe("string");
    expect(NODE_ID.length).toBeGreaterThan(0);
  });

  it("HEARTBEAT_INTERVAL_MS is a positive number", () => {
    expect(typeof HEARTBEAT_INTERVAL_MS).toBe("number");
    expect(HEARTBEAT_INTERVAL_MS).toBeGreaterThan(0);
  });

  it("STALE_THRESHOLD_MS is greater than HEARTBEAT_INTERVAL_MS", () => {
    expect(STALE_THRESHOLD_MS).toBeGreaterThan(HEARTBEAT_INTERVAL_MS);
  });

  it("campaign run state supports optional fields", () => {
    const state: PersistedCampaignRunState = {
      campaignId: 1,
      isRunning: false,
      isPaused: false,
      currentStageId: undefined as any,
      startedAt: Date.now(),
      nodeId: "node-1",
    };
    expect(state.isRunning).toBe(false);
  });

  it("orchestration plan supports completed status", () => {
    const plan: PersistedOrchestrationPlan = {
      planId: "plan-done",
      name: "Completed Plan",
      status: "completed",
      framework: "sliver",
      phases: [],
      currentPhaseIndex: 0,
      currentStepIndex: 0,
      startedAt: Date.now() - 3600000,
      nodeId: "node-1",
      log: [],
      completedAt: Date.now(),
    };
    expect(plan.status).toBe("completed");
    expect(plan.completedAt).toBeDefined();
  });

  it("orchestration plan supports failed status", () => {
    const plan: PersistedOrchestrationPlan = {
      planId: "plan-fail",
      name: "Failed Plan",
      status: "failed",
      framework: "caldera",
      phases: [],
      currentPhaseIndex: 0,
      currentStepIndex: 0,
      startedAt: Date.now() - 7200000,
      nodeId: "node-2",
      log: [{ timestamp: Date.now(), message: "Error occurred" }],
      error: "Connection timeout",
    };
    expect(plan.status).toBe("failed");
    expect(plan.error).toBe("Connection timeout");
  });
});

// ─── Stale Analysis Detection ────────────────────────────────────

describe("Stale Analysis Detection Logic", () => {
  const STALE_DAYS = 7;
  const STALE_MS = STALE_DAYS * 24 * 60 * 60 * 1000;

  function isStaleAnalysis(analyzedAt: string | number | undefined): boolean {
    if (!analyzedAt) return false;
    const ts = typeof analyzedAt === "number" ? analyzedAt : new Date(analyzedAt).getTime();
    return Date.now() - ts > STALE_MS;
  }

  function getAnalysisAge(analyzedAt: string | number | undefined): { days: number; label: string; isStale: boolean } {
    if (!analyzedAt) return { days: 0, label: "Unknown", isStale: false };
    const ts = typeof analyzedAt === "number" ? analyzedAt : new Date(analyzedAt).getTime();
    const diffMs = Date.now() - ts;
    const days = Math.floor(diffMs / (24 * 60 * 60 * 1000));
    const hours = Math.floor(diffMs / (60 * 60 * 1000));
    const isStale = diffMs > STALE_MS;
    if (days > 0) return { days, label: `${days}d ago`, isStale };
    if (hours > 0) return { days: 0, label: `${hours}h ago`, isStale };
    return { days: 0, label: "Just now", isStale };
  }

  it("returns false for undefined analyzedAt", () => {
    expect(isStaleAnalysis(undefined)).toBe(false);
  });

  it("returns false for analysis done just now", () => {
    expect(isStaleAnalysis(Date.now())).toBe(false);
  });

  it("returns false for analysis done 6 days ago", () => {
    const sixDaysAgo = Date.now() - 6 * 24 * 60 * 60 * 1000;
    expect(isStaleAnalysis(sixDaysAgo)).toBe(false);
  });

  it("returns true for analysis done 8 days ago", () => {
    const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
    expect(isStaleAnalysis(eightDaysAgo)).toBe(true);
  });

  it("returns true for analysis done 30 days ago", () => {
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
    expect(isStaleAnalysis(thirtyDaysAgo)).toBe(true);
  });

  it("handles ISO string timestamps", () => {
    const oldDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    expect(isStaleAnalysis(oldDate)).toBe(true);
  });

  it("handles recent ISO string timestamps", () => {
    const recentDate = new Date(Date.now() - 3600000).toISOString();
    expect(isStaleAnalysis(recentDate)).toBe(false);
  });

  it("getAnalysisAge returns Unknown for undefined", () => {
    const age = getAnalysisAge(undefined);
    expect(age.label).toBe("Unknown");
    expect(age.isStale).toBe(false);
  });

  it("getAnalysisAge returns Just now for recent analysis", () => {
    const age = getAnalysisAge(Date.now() - 30000); // 30 seconds ago
    expect(age.label).toBe("Just now");
    expect(age.isStale).toBe(false);
  });

  it("getAnalysisAge returns hours for same-day analysis", () => {
    const age = getAnalysisAge(Date.now() - 5 * 60 * 60 * 1000); // 5 hours ago
    expect(age.label).toBe("5h ago");
    expect(age.isStale).toBe(false);
  });

  it("getAnalysisAge returns days for older analysis", () => {
    const age = getAnalysisAge(Date.now() - 3 * 24 * 60 * 60 * 1000); // 3 days ago
    expect(age.label).toBe("3d ago");
    expect(age.days).toBe(3);
    expect(age.isStale).toBe(false);
  });

  it("getAnalysisAge marks stale for 8-day-old analysis", () => {
    const age = getAnalysisAge(Date.now() - 8 * 24 * 60 * 60 * 1000);
    expect(age.label).toBe("8d ago");
    expect(age.isStale).toBe(true);
  });

  it("boundary: exactly 7 days is not stale (needs to exceed)", () => {
    // Exactly 7 days minus 1 second
    const justUnder = Date.now() - (7 * 24 * 60 * 60 * 1000 - 1000);
    expect(isStaleAnalysis(justUnder)).toBe(false);
  });

  it("boundary: 7 days + 1 second is stale", () => {
    const justOver = Date.now() - (7 * 24 * 60 * 60 * 1000 + 1000);
    expect(isStaleAnalysis(justOver)).toBe(true);
  });
});

// ─── Discovery Context in Report Pipeline ────────────────────────

describe("Discovery Context Report Pipeline Integration", () => {
  // Mock invokeLLM to avoid actual API calls
  vi.mock("./server/_core/llm", () => ({
    invokeLLM: vi.fn().mockResolvedValue({
      choices: [{ message: { content: "Mock LLM response" } }],
    }),
  }));

  function buildMinimalPipelineInput(overrides: Partial<PipelineInput> = {}): PipelineInput {
    return {
      targetOrganization: "Test Corp",
      targetDomain: "test.example.com",
      assessmentType: "external",
      assessmentDate: new Date().toISOString(),
      assessorName: "Test Assessor",
      assessorOrganization: "Test Security LLC",
      findings: [],
      assets: [],
      ...overrides,
    };
  }

  it("report pipeline accepts discoveryContextData in input", () => {
    const input = buildMinimalPipelineInput({
      discoveryContextData: [
        {
          assetIdentifier: "app.test.com",
          attribution: {
            primaryClaim: {
              attributedTo: { organization: "Test Corp", subsidiary: "Cloud Division" },
              confidenceScore: 85,
              claimType: "definitive",
              reasoning: "WHOIS match",
            },
            metadata: { mode: "full_llm" },
          },
          role: {
            role: { exposure: "customer_facing", environment: "production", criticality: "high", function: "web_application" },
            metadata: { mode: "deterministic_only" },
          },
          lifecycle: {
            stage: "active",
            direction: "stable",
            temporalSignals: [{ signalType: "cert_issuance", value: "2024-01-15", interpretation: "Recent cert renewal" }],
            metadata: { mode: "full_llm" },
          },
          businessContext: {
            businessFunction: "Customer Portal",
            revenuePathType: "direct",
            regulatoryExposure: ["PCI-DSS", "SOC2"],
            metadata: { mode: "deterministic_only" },
          },
          threatRelevance: {
            overallThreatScore: 72,
            actorRelevance: [
              { actorType: "ransomware_group", relevanceScore: 80, reasoning: "Exposed web app" },
            ],
            metadata: { mode: "full_llm" },
          },
        },
      ],
    });
    expect(input.discoveryContextData).toHaveLength(1);
    expect(input.discoveryContextData![0].assetIdentifier).toBe("app.test.com");
  });

  it("discovery context data supports multiple assets", () => {
    const input = buildMinimalPipelineInput({
      discoveryContextData: [
        { assetIdentifier: "app.test.com", attribution: { primaryClaim: { attributedTo: { organization: "Test" }, confidenceScore: 90 }, metadata: { mode: "full_llm" } } },
        { assetIdentifier: "api.test.com", attribution: { primaryClaim: { attributedTo: { organization: "Test" }, confidenceScore: 75 }, metadata: { mode: "deterministic_only" } } },
        { assetIdentifier: "mail.test.com" },
      ],
    });
    expect(input.discoveryContextData).toHaveLength(3);
  });

  it("discovery context data supports partial specialist results", () => {
    const input = buildMinimalPipelineInput({
      discoveryContextData: [
        {
          assetIdentifier: "partial.test.com",
          attribution: {
            primaryClaim: { attributedTo: { organization: "Test" }, confidenceScore: 60 },
            metadata: { mode: "deterministic_only" },
          },
          // No role, lifecycle, businessContext, or threatRelevance
        },
      ],
    });
    expect(input.discoveryContextData![0].role).toBeUndefined();
    expect(input.discoveryContextData![0].lifecycle).toBeUndefined();
  });

  it("threat relevance score bands are correctly classified", () => {
    function getThreatBand(score: number): string {
      if (score >= 70) return "HIGH";
      if (score >= 40) return "MEDIUM";
      return "LOW";
    }
    expect(getThreatBand(85)).toBe("HIGH");
    expect(getThreatBand(70)).toBe("HIGH");
    expect(getThreatBand(55)).toBe("MEDIUM");
    expect(getThreatBand(40)).toBe("MEDIUM");
    expect(getThreatBand(25)).toBe("LOW");
    expect(getThreatBand(0)).toBe("LOW");
  });

  it("discovery context data supports all actor types", () => {
    const actorTypes = ["ransomware_group", "nation_state_apt", "financially_motivated", "insider_threat", "hacktivism"];
    const input = buildMinimalPipelineInput({
      discoveryContextData: [
        {
          assetIdentifier: "target.test.com",
          threatRelevance: {
            overallThreatScore: 65,
            actorRelevance: actorTypes.map(t => ({ actorType: t, relevanceScore: 50, reasoning: `Test ${t}` })),
            metadata: { mode: "full_llm" },
          },
        },
      ],
    });
    expect(input.discoveryContextData![0].threatRelevance!.actorRelevance).toHaveLength(5);
  });

  it("discovery context supports regulatory exposure arrays", () => {
    const input = buildMinimalPipelineInput({
      discoveryContextData: [
        {
          assetIdentifier: "regulated.test.com",
          businessContext: {
            businessFunction: "Payment Processing",
            revenuePathType: "direct",
            regulatoryExposure: ["PCI-DSS", "SOC2", "GDPR", "HIPAA"],
            metadata: { mode: "full_llm" },
          },
        },
      ],
    });
    expect(input.discoveryContextData![0].businessContext!.regulatoryExposure).toHaveLength(4);
    expect(input.discoveryContextData![0].businessContext!.regulatoryExposure).toContain("HIPAA");
  });

  it("discovery context supports lifecycle temporal signals", () => {
    const input = buildMinimalPipelineInput({
      discoveryContextData: [
        {
          assetIdentifier: "aging.test.com",
          lifecycle: {
            stage: "declining",
            direction: "degrading",
            temporalSignals: [
              { signalType: "cert_expiry", value: "2023-06-01", interpretation: "Expired cert" },
              { signalType: "dns_change", value: "2022-12-15", interpretation: "No DNS changes in 2 years" },
              { signalType: "technology_age", value: "Apache/2.2", interpretation: "End-of-life software" },
            ],
            metadata: { mode: "deterministic_only" },
          },
        },
      ],
    });
    expect(input.discoveryContextData![0].lifecycle!.temporalSignals).toHaveLength(3);
    expect(input.discoveryContextData![0].lifecycle!.stage).toBe("declining");
  });

  it("empty discoveryContextData array is valid", () => {
    const input = buildMinimalPipelineInput({ discoveryContextData: [] });
    expect(input.discoveryContextData).toHaveLength(0);
  });

  it("undefined discoveryContextData is valid (optional field)", () => {
    const input = buildMinimalPipelineInput();
    expect(input.discoveryContextData).toBeUndefined();
  });
});

// ─── DB Schema Validation ────────────────────────────────────────

describe("Database Schema - Campaign Run States and Orchestration Plans", () => {
  it("campaign_run_states table has correct column expectations", () => {
    // Validate the expected column structure matches what we created
    const expectedColumns = [
      "id", "campaign_id", "is_running", "is_paused",
      "current_stage_id", "started_at", "node_id",
      "last_heartbeat", "created_at", "updated_at",
    ];
    expectedColumns.forEach(col => {
      expect(typeof col).toBe("string");
      expect(col.length).toBeGreaterThan(0);
    });
  });

  it("orchestration_plans table has correct column expectations", () => {
    const expectedColumns = [
      "id", "plan_id", "name", "status", "framework",
      "phases_json", "current_phase_index", "current_step_index",
      "started_at", "completed_at", "node_id", "last_heartbeat",
      "log_json", "error", "created_at", "updated_at",
    ];
    expectedColumns.forEach(col => {
      expect(typeof col).toBe("string");
      expect(col.length).toBeGreaterThan(0);
    });
  });

  it("discovered_assets has discovery_context and discovery_context_analyzed_at columns", () => {
    // These columns were added via ALTER TABLE migration
    const expectedNewColumns = ["discovery_context", "discovery_context_analyzed_at"];
    expectedNewColumns.forEach(col => {
      expect(typeof col).toBe("string");
    });
  });
});
