import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-user",
    email: "test@example.com",
    name: "Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };
  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: () => {} } as unknown as TrpcContext["res"],
  };
}

const caller = appRouter.createCaller(createAuthContext());

/* ═══════════════════════════════════════════════════════════════════════════
   SOC Integration Hub Router
   ═══════════════════════════════════════════════════════════════════════════ */
describe("SOC Integration Hub Router", () => {
  it("should return demo data with sampleFindings, sampleAttacks, sampleConnectors", async () => {
    const data = await caller.socIntegrationHub.getDemoData();
    expect(data).toBeDefined();
    // getDemoData returns { sampleFindings, sampleAttacks, sampleConnectors }
    expect(data.sampleFindings).toBeDefined();
    expect(Array.isArray(data.sampleFindings)).toBe(true);
    expect(data.sampleFindings.length).toBeGreaterThan(0);
    expect(data.sampleAttacks).toBeDefined();
    expect(Array.isArray(data.sampleAttacks)).toBe(true);
    expect(data.sampleConnectors).toBeDefined();
  });

  it("should export findings in CEF format", async () => {
    const result = await caller.socIntegrationHub.exportFindings({
      findings: [
        {
          id: "f1",
          engagementId: 1,
          title: "Test Finding",
          severity: "high",
          description: "A test finding",
          timestamp: Date.now(),
        },
      ],
      format: "cef",
    });
    expect(result).toBeDefined();
    // exportFindings returns ExportedAlert[] array
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].format).toBe("cef");
    expect(result[0].raw).toBeDefined();
  });

  it("should analyze detection gaps from attacks and SIEM alerts", async () => {
    const result = await caller.socIntegrationHub.analyzeGaps({
      attacks: [
        {
          id: "a1",
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          tool: "sqlmap",
          targetHost: "10.0.1.5",
          timestamp: Date.now() - 60000,
          success: true,
          description: "SQL injection attempt",
        },
      ],
      siemAlerts: [
        {
          alertId: "alert-1",
          backend: "splunk" as const,
          timestamp: Date.now() - 55000,
          severity: "high" as const,
          severityScore: 8,
          title: "SQL Injection Detected",
          description: "SQL injection attempt detected",
          mitreTechniques: ["T1190"],
          mitreTactics: ["initial-access"],
          ruleId: "rule-1",
          ruleName: "SQL Injection Rule",
          agentName: "agent-1",
          rawData: {},
        },
      ],
    });
    expect(result).toBeDefined();
    expect(result.gaps).toBeDefined();
    expect(Array.isArray(result.gaps)).toBe(true);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════
   Cloud Workload Testing Router
   ═══════════════════════════════════════════════════════════════════════════ */
describe("Cloud Workload Testing Router", () => {
  it("should return categories for AWS", async () => {
    const result = await caller.cloudWorkloadTesting.getCategories({ provider: "aws" });
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should return K8s security checks", async () => {
    const result = await caller.cloudWorkloadTesting.getK8sChecks();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should return serverless security checks", async () => {
    const result = await caller.cloudWorkloadTesting.getServerlessChecks();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should run a unified assessment", async () => {
    const result = await caller.cloudWorkloadTesting.runAssessment({
      provider: "aws",
      categories: ["cis_benchmark"],
    });
    expect(result).toBeDefined();
    expect(result.provider).toBe("aws");
    expect(result.results).toBeDefined();
  });

  it("should compare cloud providers", async () => {
    const result = await caller.cloudWorkloadTesting.compareProviders({
      providers: ["aws", "azure"],
    });
    expect(result).toBeDefined();
    // compareCloudProviders returns MultiCloudComparison { providers, ranking, commonGaps, ... }
    expect(result.providers).toBeDefined();
    expect(Array.isArray(result.providers)).toBe(true);
    expect(result.providers.length).toBe(2);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════
   LLM Reliability Router
   ═══════════════════════════════════════════════════════════════════════════ */
describe("LLM Reliability Router", () => {
  it("should return circuit breaker state", async () => {
    const result = await caller.llmReliability.getCircuitBreaker();
    expect(result).toBeDefined();
    expect(result.state).toBeDefined();
    expect(["closed", "open", "half-open"]).toContain(result.state);
  });

  it("should check LLM availability", async () => {
    const result = await caller.llmReliability.isAvailable();
    expect(result).toBeDefined();
    expect(typeof result.available).toBe("boolean");
  });

  it("should return cache stats", async () => {
    const result = await caller.llmReliability.getCacheStats();
    expect(result).toBeDefined();
    expect(typeof result.size).toBe("number");
  });

  it("should reset circuit breaker", async () => {
    const result = await caller.llmReliability.resetCircuitBreaker();
    expect(result).toBeDefined();
    expect(result.state).toBe("closed");
  });

  it("should clear cache (admin only)", async () => {
    // clearCache returns { success, message } from the router
    const result = await caller.llmReliability.clearCache();
    expect(result).toBeDefined();
    expect(result.success).toBe(true);
    expect(result.message).toBeDefined();
  });

  it("should return health metrics with nested structure", async () => {
    const result = await caller.llmReliability.getHealthMetrics();
    expect(result).toBeDefined();
    expect(result.status).toBeDefined();
    expect(["healthy", "degraded", "unhealthy"]).toContain(result.status);
    expect(result.recentPerformance).toBeDefined();
    expect(typeof result.recentPerformance.avgLatencyMs).toBe("number");
  });
});

/* ═══════════════════════════════════════════════════════════════════════════
   Agent Installer Router
   ═══════════════════════════════════════════════════════════════════════════ */
describe("Agent Installer Router", () => {
  it("should list supported platforms with platform field", async () => {
    const result = await caller.agentInstaller.listPlatforms();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    // getSupportedPlatforms returns { platform, name, os, arch }
    const platformIds = result.map((p: any) => p.platform);
    expect(platformIds).toContain("linux_x64");
    expect(platformIds).toContain("windows_x64");
  });

  it("should list agent profiles", async () => {
    const result = await caller.agentInstaller.listProfiles();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should return profile capabilities using profile field", async () => {
    // Router expects { profile: ... } not { profileId: ... }
    const result = await caller.agentInstaller.getProfileCapabilities({ profile: "full" });
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should generate a Linux installer with callbackHost", async () => {
    // Router expects callbackHost (not callbackUrl) and callbackPort
    const result = await caller.agentInstaller.generateInstaller({
      platform: "linux_x64",
      profile: "full",
      callbackHost: "c2.example.com",
      callbackPort: 443,
      beaconIntervalSec: 60,
    });
    expect(result).toBeDefined();
    expect(result.script).toBeDefined();
    expect(typeof result.script).toBe("string");
    expect(result.script.length).toBeGreaterThan(0);
  });
});

/* ═══════════════════════════════════════════════════════════════════════════
   MSSP Analytics Router
   ═══════════════════════════════════════════════════════════════════════════ */
describe("MSSP Analytics Router", () => {
  it("should list pricing tiers", async () => {
    const result = await caller.msspAnalytics.listPricingTiers();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should list SLA definitions", async () => {
    const result = await caller.msspAnalytics.listSLADefinitions();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should calculate risk score with correct field names", async () => {
    // Router expects flat fields: criticalVulns, highVulns, etc.
    const result = await caller.msspAnalytics.calculateRisk({
      criticalVulns: 2,
      highVulns: 5,
      mediumVulns: 10,
      lowVulns: 20,
      daysSinceLastAssessment: 30,
      owaspCoveragePercent: 75,
      agentCoverage: 0.8,
      complianceGaps: 3,
      exposedServices: 5,
      unpatched: 10,
    });
    expect(result).toBeDefined();
    expect(typeof result.score).toBe("number");
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.level).toBeDefined();
  });
});

/* ═══════════════════════════════════════════════════════════════════════════
   Data Exfiltration Simulation Router
   ═══════════════════════════════════════════════════════════════════════════ */
describe("Data Exfiltration Simulation Router", () => {
  it("should list all scenarios", async () => {
    const result = await caller.dataExfilSimulation.listScenarios();
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should filter scenarios by difficulty", async () => {
    const result = await caller.dataExfilSimulation.listScenarios({ difficulty: "basic" });
    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    result.forEach((s: any) => expect(s.difficulty).toBe("basic"));
  });

  it("should get a specific scenario", async () => {
    const all = await caller.dataExfilSimulation.listScenarios();
    const first = all[0];
    const result = await caller.dataExfilSimulation.getScenario({ scenarioId: first.id });
    expect(result).toBeDefined();
    expect(result.id).toBe(first.id);
  });

  it("should preview test data with data and description fields", async () => {
    const result = await caller.dataExfilSimulation.previewTestData({
      dataType: "pii_sample",
      sizeKb: 5,
    });
    expect(result).toBeDefined();
    // generateTestData returns { data, description }, router spreads and adds sizeBytes + preview
    expect(result.description).toBeDefined();
    expect(result.preview).toBeDefined();
    expect(typeof result.sizeBytes).toBe("number");
    expect(result.sizeBytes).toBeGreaterThan(0);
  });

  it("should run an exfiltration simulation with ExfilSimulationResult fields", async () => {
    const all = await caller.dataExfilSimulation.listScenarios();
    const scenario = all[0];
    const result = await caller.dataExfilSimulation.runSimulation({
      scenarioId: scenario.id,
      targetHost: "test.example.com",
      dataSizeKb: 10,
      durationSeconds: 10,
    });
    expect(result).toBeDefined();
    // ExfilSimulationResult has: simulationId, scenarioId, status, durationMs, etc.
    expect(result.simulationId).toBeDefined();
    expect(result.scenarioId).toBe(scenario.id);
    expect(["completed", "detected", "blocked", "partial", "failed"]).toContain(result.status);
    expect(typeof result.durationMs).toBe("number");
    expect(typeof result.dataExfiltratedKb).toBe("number");
  });

  it("should run a campaign", async () => {
    const all = await caller.dataExfilSimulation.listScenarios();
    const ids = all.slice(0, 2).map((s: any) => s.id);
    const result = await caller.dataExfilSimulation.runCampaign({
      name: "Test Campaign",
      targetHost: "test.example.com",
      scenarioIds: ids,
      dataSizeKb: 10,
      durationSeconds: 10,
    });
    expect(result).toBeDefined();
    expect(result.name).toBe("Test Campaign");
    expect(result.scenarioCount).toBe(2);
    expect(result.results).toBeDefined();
    expect(result.results.length).toBe(2);
    expect(result.overallAssessment).toBeDefined();
  });
});
