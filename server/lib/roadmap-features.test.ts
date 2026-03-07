import { describe, it, expect, beforeEach } from "vitest";

// ─── SOC Integration Hub ─────────────────────────────────────────────────────
import {
  exportFindings,
  exportFindingAsCEF,
  exportFindingAsLEEF,
  exportFindingAsJSON,
  exportFindingAsSyslog,
  exportFindingAsCSV,
  analyzeDetectionGaps,
  computeSocHealth,
  type EngagementFinding,
  type AlertExportFormat,
} from "./soc-integration-hub";

describe("SOC Integration Hub", () => {
  const sampleFindings: EngagementFinding[] = [
    {
      id: "f1",
      engagementId: 1,
      title: "SQL Injection in login form",
      description: "Blind SQL injection found in login endpoint",
      severity: "critical",
      cvss: 9.8,
      targetHost: "example.com",
      toolUsed: "nuclei",
      cveIds: ["CVE-2024-1234"],
      mitreTechniques: ["T1190"],
      timestamp: Date.now() - 86400000,
      evidence: "nuclei -t sqli -u example.com",
    },
    {
      id: "f2",
      engagementId: 1,
      title: "XSS Reflected",
      description: "Reflected XSS in search parameter",
      severity: "high",
      cvss: 7.5,
      targetHost: "example.com",
      toolUsed: "zap",
      mitreTechniques: ["T1059.007"],
      timestamp: Date.now() - 43200000,
    },
  ];

  it("should export findings in CEF format", () => {
    const alert = exportFindingAsCEF(sampleFindings[0]);
    expect(alert).toBeDefined();
    expect(alert.format).toBe("cef");
    expect(alert.raw).toBeDefined();
    expect(typeof alert.raw).toBe("string");
    expect(alert.raw.length).toBeGreaterThan(0);
  });

  it("should export findings in LEEF format", () => {
    const alert = exportFindingAsLEEF(sampleFindings[0]);
    expect(alert.format).toBe("leef");
    expect(alert.raw.length).toBeGreaterThan(0);
  });

  it("should export findings in JSON format", () => {
    const alert = exportFindingAsJSON(sampleFindings[0]);
    expect(alert.format).toBe("json");
    const parsed = JSON.parse(alert.raw);
    expect(parsed.rule.name).toBe("SQL Injection in login form");
  });

  it("should export findings in syslog format", () => {
    const alert = exportFindingAsSyslog(sampleFindings[0]);
    expect(alert.format).toBe("syslog");
    expect(alert.raw.length).toBeGreaterThan(0);
  });

  it("should export findings in CSV format", () => {
    const alert = exportFindingAsCSV(sampleFindings[0]);
    expect(alert.format).toBe("csv");
    expect(alert.raw).toContain(",");
  });

  it("should batch export all findings in a given format", () => {
    const formats: AlertExportFormat[] = ["cef", "leef", "json", "syslog", "csv"];
    for (const format of formats) {
      const exported = exportFindings(sampleFindings, format);
      expect(exported).toBeDefined();
      // CSV format adds a header row
      expect(exported.length).toBeGreaterThanOrEqual(2);
      expect(exported[0].format).toBe(format);
    }
  });

  it("should analyze detection gaps from attack actions and SIEM alerts", () => {
    const attacks = [
      { id: "a1", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access", tool: "nuclei", targetHost: "example.com", timestamp: Date.now() - 60000, success: true, description: "SQL injection" },
      { id: "a2", techniqueId: "T1059.007", techniqueName: "JavaScript", tactic: "execution", tool: "zap", targetHost: "example.com", timestamp: Date.now() - 30000, success: true, description: "XSS" },
      { id: "a3", techniqueId: "T1110", techniqueName: "Brute Force", tactic: "credential-access", tool: "hydra", targetHost: "example.com", timestamp: Date.now() - 10000, success: false, description: "Brute force" },
    ];
    const siemAlerts = [
      { alertId: "s1", backend: "wazuh" as const, timestamp: Date.now() - 55000, severity: "critical" as const, severityScore: 90, title: "SQL Injection Detected", description: "WAF alert", mitreTechniques: ["T1190"], mitreTactics: ["initial-access"], ruleId: "r1", ruleName: "SQLi Detection", agentName: "agent1", rawData: {} },
    ];
    const gaps = analyzeDetectionGaps(attacks, siemAlerts);
    expect(gaps).toBeDefined();
    expect(gaps.totalAttacks).toBe(3);
    expect(gaps.totalDetected).toBeGreaterThanOrEqual(1);
    expect(gaps.gaps).toBeDefined();
    expect(gaps.coveredTechniques).toBeDefined();
    expect(gaps.uncoveredTechniques).toBeDefined();
  });

  it("should compute SOC health from connector statuses", () => {
    const connectors = [
      { id: "splunk-1", name: "Splunk HEC", backend: "splunk", status: "connected" as const, lastCheck: Date.now(), latencyMs: 45, alertsLast24h: 150 },
      { id: "sentinel-1", name: "Azure Sentinel", backend: "sentinel", status: "degraded" as const, lastCheck: Date.now() - 120000, latencyMs: 200, alertsLast24h: 80 },
    ];
    const health = computeSocHealth(connectors);
    expect(health).toBeDefined();
    expect(health.overallStatus).toBeDefined();
    expect(health.connectors.length).toBe(2);
    expect(health.totalAlertsLast24h).toBe(230);
  });
});

// ─── LLM Reliability ─────────────────────────────────────────────────────────
import {
  configureCircuitBreaker,
  getCircuitState,
  getCircuitBreakerStats,
  resetCircuitBreaker,
  configureCaching,
  getCacheStats,
  clearPromptCache,
  getLLMHealthMetrics,
  isLLMAvailable,
  recordPerformanceSample,
} from "./llm-reliability";

describe("LLM Reliability", () => {
  beforeEach(() => {
    resetCircuitBreaker();
    clearPromptCache();
  });

  it("should start with circuit breaker in closed state", () => {
    expect(getCircuitState()).toBe("closed");
  });

  it("should return circuit breaker stats", () => {
    const stats = getCircuitBreakerStats();
    expect(stats).toBeDefined();
    expect(stats.state).toBe("closed");
    expect(stats.recentFailures).toBe(0);
    expect(stats.config).toBeDefined();
    expect(stats.config.failureThreshold).toBeGreaterThan(0);
  });

  it("should allow configuring circuit breaker", () => {
    configureCircuitBreaker({ failureThreshold: 3, recoveryTimeout: 5000 });
    const stats = getCircuitBreakerStats();
    expect(stats.config.failureThreshold).toBe(3);
    expect(stats.config.recoveryTimeout).toBe(5000);
  });

  it("should reset circuit breaker to closed state", () => {
    resetCircuitBreaker();
    expect(getCircuitState()).toBe("closed");
  });

  it("should report LLM as available when circuit is closed", () => {
    expect(isLLMAvailable()).toBe(true);
  });

  it("should return cache stats", () => {
    const stats = getCacheStats();
    expect(stats).toBeDefined();
    expect(stats.size).toBe(0);
    expect(stats.maxSize).toBeGreaterThan(0);
    expect(stats.ttlMs).toBeGreaterThan(0);
    expect(stats.enabled).toBe(true);
  });

  it("should allow configuring cache", () => {
    configureCaching({ ttlMs: 10000, enabled: false });
    const stats = getCacheStats();
    expect(stats.enabled).toBe(false);
    configureCaching({ enabled: true });
  });

  it("should clear prompt cache", () => {
    clearPromptCache();
    expect(getCacheStats().size).toBe(0);
  });

  it("should record performance samples and compute health metrics", () => {
    recordPerformanceSample(150, true, false);
    recordPerformanceSample(200, true, false);
    recordPerformanceSample(5000, false, true);

    const health = getLLMHealthMetrics();
    expect(health).toBeDefined();
    expect(health.status).toBeDefined();
    expect(["healthy", "degraded", "unhealthy"]).toContain(health.status);
    expect(health.circuitBreaker).toBeDefined();
    expect(health.cache).toBeDefined();
    expect(health.recentPerformance).toBeDefined();
    expect(health.recentPerformance.totalCalls).toBeGreaterThanOrEqual(3);
    expect(health.uptime).toBeDefined();
    expect(health.uptime.durationMs).toBeGreaterThan(0);
    expect(health.recommendations).toBeDefined();
    expect(Array.isArray(health.recommendations)).toBe(true);
  });
});

// ─── Agent Installer Generator ───────────────────────────────────────────────
import {
  generateInstaller,
  getSupportedPlatforms,
  getCapabilitiesForProfile,
  getAllProfiles,
  type AgentInstallerConfig,
} from "./agent-installer-generator";

describe("Agent Installer Generator", () => {
  it("should return supported platforms", () => {
    const platforms = getSupportedPlatforms();
    expect(platforms).toBeDefined();
    expect(Array.isArray(platforms)).toBe(true);
    expect(platforms.length).toBeGreaterThan(0);
    const linux = platforms.find(p => p.platform === "linux_x64");
    expect(linux).toBeDefined();
    expect(linux!.os).toBe("Linux");
  });

  it("should have Windows and macOS platforms", () => {
    const platforms = getSupportedPlatforms();
    expect(platforms.find(p => p.platform === "windows_x64")).toBeDefined();
    expect(platforms.find(p => p.platform === "macos_x64")).toBeDefined();
  });

  it("should return all agent profiles", () => {
    const profiles = getAllProfiles();
    expect(profiles).toBeDefined();
    expect(profiles.length).toBeGreaterThan(0);
    expect(profiles.find(p => p.profile === "full")).toBeDefined();
    expect(profiles.find(p => p.profile === "stealth")).toBeDefined();
    expect(profiles.find(p => p.profile === "recon_only")).toBeDefined();
  });

  it("should return capabilities for a profile", () => {
    const caps = getCapabilitiesForProfile("full");
    expect(caps).toBeDefined();
    expect(Array.isArray(caps)).toBe(true);
    expect(caps.length).toBeGreaterThan(0);
    expect(caps[0].id).toBeDefined();
    expect(caps[0].name).toBeDefined();
  });

  it("should have fewer capabilities for recon_only than full", () => {
    const fullCaps = getCapabilitiesForProfile("full");
    const reconCaps = getCapabilitiesForProfile("recon_only");
    expect(reconCaps.length).toBeLessThan(fullCaps.length);
  });

  it("should generate a Linux installer script", () => {
    const config: AgentInstallerConfig = {
      platform: "linux_x64",
      profile: "full",
      callbackUrl: "https://c2.example.com/api/agent",
      registrationToken: "test-token-123",
      beaconInterval: 60,
      jitterPercent: 20,
      protocol: "https",
    };
    const output = generateInstaller(config);
    expect(output).toBeDefined();
    expect(output.platform).toBe("linux_x64");
    expect(output.profile).toBe("full");
    expect(output.filename).toBeDefined();
    expect(output.script).toBeDefined();
    expect(output.script.length).toBeGreaterThan(0);
    expect(output.oneLiner).toBeDefined();
    expect(output.size).toBeGreaterThan(0);
    expect(output.checksum).toBeDefined();
  });

  it("should generate a Windows installer script", () => {
    const config: AgentInstallerConfig = {
      platform: "windows_x64",
      profile: "lightweight",
      callbackUrl: "https://c2.example.com/api/agent",
      registrationToken: "test-token-456",
      beaconInterval: 120,
      jitterPercent: 30,
      protocol: "https",
    };
    const output = generateInstaller(config);
    expect(output.platform).toBe("windows_x64");
    expect(output.script.length).toBeGreaterThan(0);
  });

  it("should generate a macOS installer script", () => {
    const config: AgentInstallerConfig = {
      platform: "macos_x64",
      profile: "stealth",
      callbackUrl: "https://c2.example.com/api/agent",
      registrationToken: "test-token-789",
      beaconInterval: 300,
      jitterPercent: 40,
      protocol: "dns",
      stealthMode: true,
    };
    const output = generateInstaller(config);
    expect(output.platform).toBe("macos_x64");
    expect(output.profile).toBe("stealth");
    expect(output.script.length).toBeGreaterThan(0);
  });

  it("should include kill date when specified", () => {
    const config: AgentInstallerConfig = {
      platform: "linux_x64",
      profile: "recon_only",
      callbackUrl: "https://c2.example.com/api/agent",
      registrationToken: "test-token-kill",
      beaconInterval: 60,
      jitterPercent: 10,
      protocol: "https",
      killDate: "2026-12-31T23:59:59Z",
    };
    const output = generateInstaller(config);
    expect(output.script).toContain("2026-12-31");
  });
});

// ─── Cloud Workload Testing ──────────────────────────────────────────────────
import {
  runUnifiedAssessment,
  compareCloudProviders,
  getAvailableCategories,
  K8S_SECURITY_CHECKS,
  SERVERLESS_SECURITY_CHECKS,
  type CloudTestConfig,
} from "./cloud-workload-testing";

describe("Cloud Workload Testing", () => {
  it("should return available categories for AWS", () => {
    const categories = getAvailableCategories("aws");
    expect(categories).toBeDefined();
    expect(Array.isArray(categories)).toBe(true);
    expect(categories.length).toBeGreaterThan(0);
    expect(categories[0].category).toBeDefined();
    expect(categories[0].checkCount).toBeGreaterThan(0);
    expect(categories[0].description).toBeDefined();
  });

  it("should return categories for all three providers", () => {
    for (const provider of ["aws", "azure", "gcp"] as const) {
      const categories = getAvailableCategories(provider);
      expect(categories.length).toBeGreaterThan(0);
    }
  });

  it("should export K8s security checks", () => {
    expect(K8S_SECURITY_CHECKS).toBeDefined();
    expect(Array.isArray(K8S_SECURITY_CHECKS)).toBe(true);
    expect(K8S_SECURITY_CHECKS.length).toBeGreaterThan(0);
    expect(K8S_SECURITY_CHECKS[0].id).toBeDefined();
    expect(K8S_SECURITY_CHECKS[0].title).toBeDefined();
  });

  it("should export serverless security checks", () => {
    expect(SERVERLESS_SECURITY_CHECKS).toBeDefined();
    expect(Array.isArray(SERVERLESS_SECURITY_CHECKS)).toBe(true);
    expect(SERVERLESS_SECURITY_CHECKS.length).toBeGreaterThan(0);
  });

  it("should run unified assessment for AWS CIS benchmarks", () => {
    const config: CloudTestConfig = {
      provider: "aws",
      categories: ["cis_benchmark"],
      simulationMode: true,
      includeRemediation: true,
    };
    const report = runUnifiedAssessment(config);
    expect(report).toBeDefined();
    expect(report.provider).toBe("aws");
    expect(report.results).toBeDefined();
    expect(report.results.length).toBeGreaterThan(0);
    expect(report.summary).toBeDefined();
    expect(report.summary.totalChecks).toBeGreaterThan(0);
    expect(report.riskScore).toBeDefined();
    expect(report.grade).toBeDefined();
    expect(["A", "B", "C", "D", "F"]).toContain(report.grade);
  });

  it("should run unified assessment with multiple categories", () => {
    const config: CloudTestConfig = {
      provider: "aws",
      categories: ["cis_benchmark", "iam_audit", "container_k8s", "serverless", "network"],
      simulationMode: true,
    };
    const report = runUnifiedAssessment(config);
    expect(report.results.length).toBeGreaterThan(5);
    expect(report.summary.byCategory).toBeDefined();
    expect(Object.keys(report.summary.byCategory).length).toBeGreaterThan(1);
  });

  it("should compare cloud providers", () => {
    const reports = [
      runUnifiedAssessment({ provider: "aws", categories: ["iam_audit"], simulationMode: true }),
      runUnifiedAssessment({ provider: "azure", categories: ["iam_audit"], simulationMode: true }),
      runUnifiedAssessment({ provider: "gcp", categories: ["iam_audit"], simulationMode: true }),
    ];
    const comparison = compareCloudProviders(reports);
    expect(comparison).toBeDefined();
    expect(comparison.providers).toBeDefined();
    expect(comparison.providers.length).toBe(3);
    expect(comparison.bestProvider).toBeDefined();
    expect(comparison.worstProvider).toBeDefined();
  });
});

// ─── MSSP Analytics ──────────────────────────────────────────────────────────
import {
  PRICING_TIERS,
  getPricingTier,
  calculateTenantCost,
  calculateRiskScore,
  getRiskLevel,
  buildCrossTenantSummary,
  SLA_DEFINITIONS,
  checkSLACompliance,
  buildExecutiveReport,
  type TenantSecurityPosture,
  type RiskFactors,
} from "./mssp-analytics";

describe("MSSP Analytics", () => {
  it("should export pricing tier definitions", () => {
    expect(PRICING_TIERS).toBeDefined();
    expect(Array.isArray(PRICING_TIERS)).toBe(true);
    expect(PRICING_TIERS.length).toBe(4);
    expect(PRICING_TIERS[0].name).toBe("Starter");
    expect(PRICING_TIERS[0].monthlyBase).toBe(499);
  });

  it("should retrieve pricing tier by ID", () => {
    const tier = getPricingTier("enterprise");
    expect(tier).toBeDefined();
    expect(tier!.name).toBe("Enterprise");
    expect(tier!.monthlyBase).toBe(4999);
  });

  it("should return undefined for unknown tier", () => {
    expect(getPricingTier("nonexistent")).toBeUndefined();
  });

  it("should calculate tenant cost with base price only", () => {
    const cost = calculateTenantCost({
      tenantId: 1,
      tenantName: "Test",
      period: "2026-03",
      scansRun: 10,
      llmCallsMade: 100,
      llmTokensUsed: 50000,
      storageUsedMb: 500,
      agentHours: 100,
      engagementsCreated: 2,
      reportsGenerated: 2,
      apiCallsMade: 500,
    }, "starter");
    expect(cost).toBe(499);
  });

  it("should calculate overage costs", () => {
    const cost = calculateTenantCost({
      tenantId: 1,
      tenantName: "Heavy User",
      period: "2026-03",
      scansRun: 100,
      llmCallsMade: 1000,
      llmTokensUsed: 500000,
      storageUsedMb: 2048,
      agentHours: 5000,
      engagementsCreated: 10,
      reportsGenerated: 10,
      apiCallsMade: 5000,
    }, "starter");
    expect(cost).toBeGreaterThan(499);
  });

  it("should calculate risk score from factors", () => {
    const highRisk: RiskFactors = {
      criticalVulns: 5,
      highVulns: 10,
      mediumVulns: 20,
      lowVulns: 50,
      daysSinceLastAssessment: null,
      owaspCoveragePercent: 20,
      agentCoverage: 0.1,
      complianceGaps: 5,
      exposedServices: 10,
      unpatched: 15,
    };
    const score = calculateRiskScore(highRisk);
    expect(score).toBeGreaterThan(50);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("should calculate low risk score for healthy factors", () => {
    const lowRisk: RiskFactors = {
      criticalVulns: 0,
      highVulns: 0,
      mediumVulns: 2,
      lowVulns: 5,
      daysSinceLastAssessment: 3,
      owaspCoveragePercent: 95,
      agentCoverage: 0.95,
      complianceGaps: 0,
      exposedServices: 1,
      unpatched: 0,
    };
    const score = calculateRiskScore(lowRisk);
    expect(score).toBeLessThan(25);
  });

  it("should map risk scores to correct levels", () => {
    expect(getRiskLevel(80)).toBe("critical");
    expect(getRiskLevel(60)).toBe("high");
    expect(getRiskLevel(30)).toBe("medium");
    expect(getRiskLevel(10)).toBe("low");
  });

  it("should build cross-tenant summary", () => {
    const tenants: TenantSecurityPosture[] = [
      {
        tenantId: 1, tenantName: "Client A", riskScore: 75, riskLevel: "critical",
        openVulnerabilities: { critical: 5, high: 10, medium: 20, low: 30 },
        lastEngagement: Date.now() - 86400000, lastScan: Date.now(), agentsDeployed: 10, agentsActive: 8,
        owaspCoverageScore: 60, complianceStatus: "at_risk", daysSinceLastAssessment: 15,
      },
      {
        tenantId: 2, tenantName: "Client B", riskScore: 25, riskLevel: "low",
        openVulnerabilities: { critical: 0, high: 2, medium: 5, low: 10 },
        lastEngagement: Date.now() - 172800000, lastScan: Date.now() - 86400000, agentsDeployed: 5, agentsActive: 5,
        owaspCoverageScore: 90, complianceStatus: "compliant", daysSinceLastAssessment: 5,
      },
    ];
    const summary = buildCrossTenantSummary(tenants);
    expect(summary).toBeDefined();
    expect(summary.totalTenants).toBe(2);
    expect(summary.avgRiskScore).toBe(50);
    expect(summary.riskDistribution.critical).toBe(1);
    expect(summary.riskDistribution.low).toBe(1);
    expect(summary.totalOpenVulns).toBe(82);
    expect(summary.tenantsNeedingAttention.length).toBe(1);
  });

  it("should export SLA definitions", () => {
    expect(SLA_DEFINITIONS).toBeDefined();
    expect(SLA_DEFINITIONS.length).toBeGreaterThan(0);
    expect(SLA_DEFINITIONS[0].type).toBeDefined();
    expect(SLA_DEFINITIONS[0].name).toBeDefined();
  });

  it("should check SLA compliance", () => {
    const slaStatuses = checkSLACompliance(
      1,
      "Client A",
      Date.now() - 10 * 86400000,
      Date.now() - 3 * 86400000,
      [{ foundAt: Date.now() - 5 * 86400000, resolvedAt: null }],
    );
    expect(slaStatuses).toBeDefined();
    expect(slaStatuses.length).toBeGreaterThan(0);
    const assessmentSla = slaStatuses.find(s => s.slaType === "assessment_frequency");
    expect(assessmentSla).toBeDefined();
    expect(assessmentSla!.met).toBe(true);
    const remediationSla = slaStatuses.find(s => s.slaType === "remediation_deadline");
    expect(remediationSla).toBeDefined();
    expect(remediationSla!.met).toBe(true);
  });

  it("should detect SLA violations", () => {
    const slaStatuses = checkSLACompliance(
      1,
      "Client B",
      Date.now() - 45 * 86400000,
      null,
      [{ foundAt: Date.now() - 20 * 86400000, resolvedAt: null }],
    );
    const assessmentSla = slaStatuses.find(s => s.slaType === "assessment_frequency");
    expect(assessmentSla!.met).toBe(false);
    const remediationSla = slaStatuses.find(s => s.slaType === "remediation_deadline");
    expect(remediationSla!.met).toBe(false);
  });

  it("should build executive report", () => {
    const tenants: TenantSecurityPosture[] = [
      {
        tenantId: 1, tenantName: "Client A", riskScore: 75, riskLevel: "critical",
        openVulnerabilities: { critical: 5, high: 10, medium: 20, low: 30 },
        lastEngagement: Date.now(), lastScan: Date.now(), agentsDeployed: 10, agentsActive: 8,
        owaspCoverageScore: 45, complianceStatus: "non_compliant", daysSinceLastAssessment: 15,
      },
    ];
    const summary = buildCrossTenantSummary(tenants);
    const slaStatuses = checkSLACompliance(1, "Client A", Date.now() - 15 * 86400000, Date.now() - 5 * 86400000, []);
    const report = buildExecutiveReport(summary, null, slaStatuses, "2026-03");
    expect(report).toBeDefined();
    expect(report.title).toContain("Ace C3");
    expect(report.period).toBe("2026-03");
    expect(report.summary).toBeDefined();
    expect(report.slaCompliance).toBeDefined();
    expect(report.slaCompliance.totalChecks).toBeGreaterThan(0);
    expect(report.recommendations).toBeDefined();
    expect(report.recommendations.length).toBeGreaterThan(0);
  });
});

// ─── Data Exfiltration Simulation ────────────────────────────────────────────
import {
  EXFIL_SCENARIOS,
  getScenario,
  getScenariosByDifficulty,
  getScenariosByChannel,
  generateTestData,
  runExfilSimulation,
  buildCampaignAssessment,
} from "./data-exfil-simulation";

describe("Data Exfiltration Simulation", () => {
  it("should export all exfiltration scenarios", () => {
    expect(EXFIL_SCENARIOS).toBeDefined();
    expect(Array.isArray(EXFIL_SCENARIOS)).toBe(true);
    expect(EXFIL_SCENARIOS.length).toBeGreaterThan(5);
  });

  it("should have MITRE ATT&CK mappings for all scenarios", () => {
    for (const scenario of EXFIL_SCENARIOS) {
      expect(scenario.mitreId).toBeDefined();
      expect(scenario.mitreId.startsWith("T")).toBe(true);
      expect(scenario.mitreName).toBeDefined();
      expect(scenario.mitreName.length).toBeGreaterThan(0);
    }
  });

  it("should have threat group associations for all scenarios", () => {
    for (const scenario of EXFIL_SCENARIOS) {
      expect(scenario.threatGroups).toBeDefined();
      expect(scenario.threatGroups.length).toBeGreaterThan(0);
    }
  });

  it("should retrieve scenario by ID", () => {
    const scenario = getScenario("dns_tunnel_basic");
    expect(scenario).toBeDefined();
    expect(scenario!.name).toContain("DNS Tunneling");
    expect(scenario!.channel).toBe("dns_tunneling");
  });

  it("should return undefined for unknown scenario", () => {
    expect(getScenario("nonexistent")).toBeUndefined();
  });

  it("should filter scenarios by difficulty", () => {
    const basic = getScenariosByDifficulty("basic");
    expect(basic.length).toBeGreaterThan(0);
    for (const s of basic) expect(s.difficulty).toBe("basic");

    const expert = getScenariosByDifficulty("expert");
    expect(expert.length).toBeGreaterThan(0);
    for (const s of expert) expect(s.difficulty).toBe("expert");
  });

  it("should filter scenarios by channel", () => {
    const dns = getScenariosByChannel("dns_tunneling");
    expect(dns.length).toBeGreaterThan(0);
    for (const s of dns) expect(s.channel).toBe("dns_tunneling");
  });

  it("should generate synthetic PII test data", () => {
    const data = generateTestData("pii_sample", 10);
    expect(data).toBeDefined();
    expect(data.data.length).toBeGreaterThan(0);
    expect(data.description).toContain("PII");
    expect(data.data).toContain("SSN");
  });

  it("should generate synthetic credit card test data", () => {
    const data = generateTestData("credit_card_sample", 5);
    expect(data.data).toContain("4111");
    expect(data.description).toContain("credit card");
  });

  it("should generate synthetic credentials test data", () => {
    const data = generateTestData("credentials_sample", 5);
    expect(data.data).toContain("@");
    expect(data.data).toContain("P@ssw0rd");
  });

  it("should generate synthetic source code test data", () => {
    const data = generateTestData("source_code_sample", 5);
    expect(data.data).toContain("function");
  });

  it("should generate synthetic database dump test data", () => {
    const data = generateTestData("database_dump_sample", 5);
    expect(data.data).toContain("INSERT INTO");
  });

  it("should run DNS tunneling simulation", async () => {
    const result = await runExfilSimulation({
      scenarioId: "dns_tunnel_basic",
      targetHost: "target.example.com",
      dataSizeKb: 10,
      durationSeconds: 5,
      encrypted: false,
      encoded: true,
      chunkSizeBytes: 64,
      chunkDelayMs: 100,
      captureTraffic: false,
    });
    expect(result).toBeDefined();
    expect(result.scenarioId).toBe("dns_tunnel_basic");
    expect(result.simulationId).toBeDefined();
    expect(["completed", "detected", "blocked", "partial", "failed"]).toContain(result.status);
    expect(result.dataAttemptedKb).toBe(10);
    expect(result.chunksSent).toBeGreaterThan(0);
    expect(result.detectionEvents).toBeDefined();
    expect(result.dlpEvents).toBeDefined();
    expect(result.networkAnomalies).toBeDefined();
    expect(result.assessment).toBeDefined();
    expect(result.assessment.overallRisk).toBeDefined();
    expect(result.assessment.recommendations).toBeDefined();
    expect(result.assessment.mitreMapping).toBeDefined();
    expect(result.assessment.mitreMapping.length).toBeGreaterThan(0);
  });

  it("should run HTTPS chunked simulation", async () => {
    const result = await runExfilSimulation({
      scenarioId: "https_chunked",
      targetHost: "c2.example.com",
      dataSizeKb: 50,
      durationSeconds: 10,
      encrypted: true,
      encoded: false,
      chunkSizeBytes: 1024,
      chunkDelayMs: 500,
      captureTraffic: false,
    });
    expect(result.scenarioId).toBe("https_chunked");
    expect(result.dataAttemptedKb).toBe(50);
  });

  it("should build campaign assessment from multiple results", async () => {
    const results = await Promise.all([
      runExfilSimulation({
        scenarioId: "dns_tunnel_basic",
        targetHost: "target.example.com",
        dataSizeKb: 10,
        durationSeconds: 5,
        encrypted: false,
        encoded: true,
        chunkSizeBytes: 64,
        chunkDelayMs: 100,
        captureTraffic: false,
      }),
      runExfilSimulation({
        scenarioId: "https_chunked",
        targetHost: "c2.example.com",
        dataSizeKb: 50,
        durationSeconds: 10,
        encrypted: true,
        encoded: false,
        chunkSizeBytes: 1024,
        chunkDelayMs: 500,
        captureTraffic: false,
      }),
    ]);
    const assessment = buildCampaignAssessment(results);
    expect(assessment).toBeDefined();
    expect(assessment.overallRisk).toBeDefined();
    expect(assessment.dlpEffectiveness).toBeDefined();
    expect(assessment.networkMonitoringScore).toBeDefined();
    expect(assessment.detectionCoverage).toBeDefined();
    expect(assessment.recommendations.length).toBeGreaterThan(0);
    expect(assessment.mitreMapping.length).toBeGreaterThan(0);
  });

  it("should return empty assessment for no results", () => {
    const assessment = buildCampaignAssessment([]);
    expect(assessment.overallRisk).toBe("low");
    expect(assessment.dlpEffectiveness).toBe(100);
    expect(assessment.recommendations).toContain("No simulations run yet.");
  });
});
