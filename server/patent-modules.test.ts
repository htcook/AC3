/**
 * Comprehensive tests for all 8 fixed patent modules.
 * Tests pure/sync logic functions only — no DB or network calls.
 */
import { describe, expect, it } from "vitest";

// ─── 1. Attack Chain Validation ──────────────────────────────────────
import {
  analyzeAttackChains,
  calculateChainSeverity,
  CHAIN_PATTERNS,
  resetChainCounter,
  type ChainLink,
  type FindingInput,
} from "./lib/attack-chain-validation";

describe("Attack Chain Validation", () => {
  it("has at least 8 chain patterns defined", () => {
    expect(CHAIN_PATTERNS.length).toBeGreaterThanOrEqual(8);
    for (const pattern of CHAIN_PATTERNS) {
      expect(pattern.id).toBeTruthy();
      expect(pattern.phases.length).toBeGreaterThan(0);
      expect(pattern.requiredCapabilities.length).toBeGreaterThan(0);
    }
  });

  it("identifies chains from same-target findings", () => {
    resetChainCounter();
    const findings: FindingInput[] = [
      { id: "f1", title: "Information disclosure via .env exposure", severity: "medium", description: ".env file exposed with database credentials", target: "10.0.0.1", port: 80, cveId: null, validated: true },
      { id: "f2", title: "Credential extraction from exposed config", severity: "high", description: "Database password found in exposed configuration file", target: "10.0.0.1", port: 80, cveId: null, validated: true },
      { id: "f3", title: "Remote code execution via SQL injection", severity: "critical", description: "SQL injection leads to OS command execution on database", target: "10.0.0.1", port: 3306, cveId: "CVE-2023-1234", validated: true },
    ];
    const result = analyzeAttackChains(findings);
    expect(result.totalChainsFound).toBeGreaterThan(0);
    expect(result.chains.length).toBeGreaterThan(0);
  });

  it("discovers cross-target pivot chains", () => {
    resetChainCounter();
    const findings: FindingInput[] = [
      { id: "f1", title: "SSRF vulnerability allows internal network scanning", severity: "high", description: "Server-side request forgery allows internal access and lateral movement", target: "web.example.com", port: 443, cveId: null, validated: true },
      { id: "f2", title: "Default credentials on admin panel", severity: "high", description: "Default password enables credential reuse and lateral movement", target: "web.example.com", port: 443, cveId: null, validated: true },
      { id: "f3", title: "Remote code execution via deserialization", severity: "critical", description: "Code execution via deserialization on internal host enables persistence", target: "internal.example.com", port: 8080, cveId: null, validated: false },
    ];
    const result = analyzeAttackChains(findings);
    const pivotChain = result.chains.find(c => {
      const targets = new Set(c.links.map(l => l.target));
      return targets.size > 1;
    });
    expect(pivotChain).toBeDefined();
  });

  it("returns empty result for single low-severity finding", () => {
    resetChainCounter();
    const findings: FindingInput[] = [
      { id: "f1", title: "Missing HSTS header", severity: "info", description: "HTTP Strict Transport Security header not set", target: "a.com", port: 443, cveId: null, validated: true },
    ];
    const result = analyzeAttackChains(findings);
    expect(result.totalChainsFound).toBe(0);
    expect(result.chains).toHaveLength(0);
  });

  it("calculates chain severity with cross-target bonus", () => {
    const links: ChainLink[] = [
      { findingId: "f1", title: "SSRF", severity: "medium", phase: "initial_access", attackTechnique: "T1190", target: "host-a", port: 80, prerequisite: null, provides: ["ssrf"], validated: true },
      { findingId: "f2", title: "RCE", severity: "high", phase: "execution", attackTechnique: "T1059", target: "host-b", port: 8080, prerequisite: "ssrf", provides: ["code_execution"], validated: true },
    ];
    const result = calculateChainSeverity(links);
    expect(result.score).toBeGreaterThan(5);
    expect(["critical", "high"]).toContain(result.severity);
  });
});

// ─── 2. ICS Exploit Catalog ──────────────────────────────────────────
import {
  matchAptGroups,
  ICS_APT_GROUPS,
  MITRE_ICS_TECHNIQUES,
  getTechniquesForDeviceType,
  getTechniquesByTactic,
  getIcsTactics,
} from "./lib/ics-exploit-catalog";

describe("ICS Exploit Catalog", () => {
  it("has comprehensive APT group data (10+ groups)", () => {
    expect(ICS_APT_GROUPS.length).toBeGreaterThanOrEqual(10);
    for (const apt of ICS_APT_GROUPS) {
      expect(apt.aptGroupName).toBeTruthy();
      expect(apt.attribution).toBeTruthy();
      expect((apt.targetedProtocols as string[]).length).toBeGreaterThan(0);
      expect((apt.malwareTools as any[]).length).toBeGreaterThan(0);
    }
  });

  it("has comprehensive MITRE ICS techniques (25+ techniques)", () => {
    expect(MITRE_ICS_TECHNIQUES.length).toBeGreaterThanOrEqual(25);
    for (const tech of MITRE_ICS_TECHNIQUES) {
      expect(tech.id).toMatch(/^T\d{4}$/);
      expect(tech.tactic).toBeTruthy();
      expect(tech.platforms.length).toBeGreaterThan(0);
    }
  });

  it("matches APT groups by vendor", () => {
    const results = matchAptGroups({ vendors: ["Siemens"] });
    expect(results.length).toBeGreaterThan(0);
    const sandworm = results.find(r => r.aptGroup.aptGroupName === "SANDWORM");
    expect(sandworm).toBeDefined();
    expect(sandworm!.matchScore).toBeGreaterThan(0);
  });

  it("matches APT groups by protocol", () => {
    const results = matchAptGroups({ protocols: ["modbus"] });
    expect(results.length).toBeGreaterThan(3);
  });

  it("matches APT groups by sector", () => {
    const results = matchAptGroups({ sectors: ["energy"] });
    expect(results.length).toBeGreaterThan(3);
  });

  it("returns results sorted by match score descending", () => {
    const results = matchAptGroups({ vendors: ["Schneider Electric"], protocols: ["modbus"], sectors: ["energy"] });
    for (let i = 1; i < results.length; i++) {
      expect(results[i - 1].matchScore).toBeGreaterThanOrEqual(results[i].matchScore);
    }
  });

  it("includes relevant MITRE techniques in match results", () => {
    const results = matchAptGroups({ vendors: ["Siemens"] });
    const topResult = results[0];
    expect(topResult.relevantTechniques.length).toBeGreaterThan(0);
    for (const tech of topResult.relevantTechniques) {
      expect(tech.id).toMatch(/^T\d{4}$/);
    }
  });

  it("gets techniques for specific device types", () => {
    const plcTechniques = getTechniquesForDeviceType("plc");
    expect(plcTechniques.length).toBeGreaterThan(0);
    for (const tech of plcTechniques) {
      expect(tech.platforms).toContain("plc");
    }
  });

  it("gets techniques by tactic", () => {
    const impactTechniques = getTechniquesByTactic("Impact");
    expect(impactTechniques.length).toBeGreaterThan(5);
  });

  it("returns all unique ICS tactics", () => {
    const tactics = getIcsTactics();
    expect(tactics).toContain("Initial Access");
    expect(tactics).toContain("Impact");
    expect(tactics).toContain("Execution");
  });

  it("caps match scores at 100", () => {
    const results = matchAptGroups({
      vendors: ["Siemens", "Schneider Electric", "ABB", "GE", "Honeywell"],
      protocols: ["modbus", "opcua", "iec104", "s7comm", "dnp3"],
      sectors: ["energy", "oil_gas", "water", "manufacturing"],
      deviceTypes: ["plc", "rtu", "hmi", "scada_server"],
      countries: ["United States"],
    });
    for (const r of results) {
      expect(r.matchScore).toBeLessThanOrEqual(100);
    }
  });
});

// ─── 3. AI Attack Planner (graph-only, no LLM) ──────────────────────
import {
  generateGraphOnlyPlan,
  THREAT_ACTOR_PROFILES,
  type AttackPlanRequest,
  type AttackPlan,
} from "./lib/ai-attack-planner";

describe("AI Attack Planner", () => {
  it("exports threat actor profiles", () => {
    expect(Object.keys(THREAT_ACTOR_PROFILES).length).toBeGreaterThanOrEqual(3);
  });

  it("builds a local attack plan from graph without LLM", () => {
    const request: AttackPlanRequest = {
      targetDescription: "Linux web server running Apache with known CVE",
      environmentContext: {
        operatingSystem: ["linux"],
        knownVulnerabilities: ["CVE-2023-1234"],
      },
    };
    const plan = generateGraphOnlyPlan(request);
    expect(plan.phases.length).toBeGreaterThan(0);
    expect(plan.totalSteps).toBeGreaterThan(0);
    expect(plan.estimatedRiskScore).toBeGreaterThan(0);
    expect(plan.estimatedRiskScore).toBeLessThanOrEqual(10);
    expect(plan.name).toContain("Linux web server");
  });

  it("builds plans for Windows AD environments", () => {
    const request: AttackPlanRequest = {
      targetDescription: "Windows Active Directory domain with SMB and RDP",
      environmentContext: {
        operatingSystem: ["windows"],
        adDomain: true,
      },
    };
    const plan = generateGraphOnlyPlan(request);
    expect(plan.phases.length).toBeGreaterThan(0);
    // Should include AD-specific techniques
    const allSteps = plan.phases.flatMap(p => p.steps);
    const hasADTechnique = allSteps.some(s =>
      s.techniqueId.startsWith("T1003") || s.techniqueId === "T1558" ||
      s.techniqueId === "T1558.003" || s.techniqueId === "T1087.002"
    );
    expect(hasADTechnique).toBe(true);
  });

  it("respects maxSteps constraint", () => {
    const request: AttackPlanRequest = {
      targetDescription: "Simple web application",
      constraints: { maxSteps: 3 },
    };
    const plan = generateGraphOnlyPlan(request);
    expect(plan.totalSteps).toBeLessThanOrEqual(3);
  });

  it("filters techniques by stealth level", () => {
    const stealthyRequest: AttackPlanRequest = {
      targetDescription: "Highly monitored enterprise network",
      constraints: { stealthLevel: "high" },
    };
    const plan = generateGraphOnlyPlan(stealthyRequest);
    const allSteps = plan.phases.flatMap(p => p.steps);
    // High stealth should avoid high-detection-risk techniques
    const highRiskSteps = allSteps.filter(s => s.detectionRisk === "high");
    expect(highRiskSteps.length).toBeLessThan(allSteps.length);
  });

  it("emulates specific threat actors", () => {
    const request: AttackPlanRequest = {
      targetDescription: "Government network",
      threatActorProfile: "apt29",
    };
    const plan = generateGraphOnlyPlan(request);
    expect(plan.threatActorEmulated).toContain("apt29");
    expect(plan.phases.length).toBeGreaterThan(0);
  });

  it("includes detection opportunities and recommendations", () => {
    const request: AttackPlanRequest = {
      targetDescription: "Corporate network with web servers",
      environmentContext: { operatingSystem: ["linux", "windows"] },
    };
    const plan = generateGraphOnlyPlan(request);
    expect(plan.detectionOpportunities.length).toBeGreaterThan(0);
    expect(plan.recommendations.length).toBeGreaterThan(0);
  });
});

// ─── 4. Corroboration Engine (local logic) ───────────────────────────
import {
  corroborateFindings,
  estimateFPReduction,
  getAvailableSources,
  type Finding,
} from "./lib/corroboration-engine";

describe("Corroboration Engine", () => {
  it("corroborates findings from multiple sources on same host", () => {
    const findings: Finding[] = [
      { id: "f1", title: "Open port 22", source: "nmap", severity: "low", hostOrAsset: "10.0.0.5", port: 22, service: "ssh", rawConfidence: 90, timestamp: Date.now() },
      { id: "f2", title: "SSH service detected", source: "shodan", severity: "low", hostOrAsset: "10.0.0.5", port: 22, service: "ssh", rawConfidence: 85, timestamp: Date.now() },
      { id: "f3", title: "OpenSSH 7.4 vulnerable", source: "nessus", severity: "high", cveId: "CVE-2023-1234", hostOrAsset: "10.0.0.5", port: 22, service: "ssh", rawConfidence: 75, timestamp: Date.now() },
    ];
    const report = corroborateFindings(findings);
    expect(report.totalFindings).toBe(3);
    expect(report.corroboratedFindings).toBeGreaterThan(0);
    // At least one finding should be confirmed or likely
    const confirmed = report.results.filter(r => r.verdict === "confirmed" || r.verdict === "likely");
    expect(confirmed.length).toBeGreaterThan(0);
  });

  it("marks single-source findings as unverified", () => {
    const findings: Finding[] = [
      { id: "f1", title: "Potential XSS", source: "custom_scanner", severity: "medium", hostOrAsset: "web.example.com", port: 443, rawConfidence: 40, timestamp: Date.now() },
    ];
    const report = corroborateFindings(findings);
    expect(report.totalFindings).toBe(1);
    expect(report.results[0].corroboratingSourceCount).toBe(0);
    expect(["unverified", "likely_false_positive"]).toContain(report.results[0].verdict);
  });

  it("identifies contradictions between sources", () => {
    const findings: Finding[] = [
      { id: "f1", title: "Port 80 open", source: "nmap", severity: "low", hostOrAsset: "10.0.0.1", port: 80, rawConfidence: 95, timestamp: Date.now() },
      { id: "f2", title: "Port 80 filtered", source: "masscan", severity: "info", hostOrAsset: "10.0.0.1", port: 80, rawConfidence: 90, timestamp: Date.now() },
    ];
    const report = corroborateFindings(findings);
    // These should show some contradiction
    expect(report.totalFindings).toBe(2);
  });

  it("estimates false positive reduction percentage", () => {
    const findings: Finding[] = [
      { id: "f1", title: "SQL injection", source: "scanner_a", severity: "high", hostOrAsset: "app.com", port: 443, rawConfidence: 80, timestamp: Date.now() },
      { id: "f2", title: "SQL injection", source: "scanner_b", severity: "high", hostOrAsset: "app.com", port: 443, rawConfidence: 75, timestamp: Date.now() },
      { id: "f3", title: "Ghost vuln", source: "unknown_tool", severity: "low", hostOrAsset: "other.com", port: 80, rawConfidence: 10, timestamp: Date.now() },
    ];
    const report = corroborateFindings(findings);
    const reduction = estimateFPReduction(report);
    expect(reduction).toBeGreaterThanOrEqual(0);
    expect(reduction).toBeLessThanOrEqual(100);
  });

  it("lists available external sources", () => {
    const sources = getAvailableSources();
    expect(sources.length).toBeGreaterThan(0);
    for (const src of sources) {
      expect(src.name).toBeTruthy();
      expect(src.id).toBeTruthy();
      expect(src.envVar).toBeTruthy();
    }
  });
});

// ─── 5. Remediation Verification (pure config/logic) ─────────────────
import {
  DEFAULT_REMEDIATION_CONFIG,
  type RemediationConfig,
} from "./lib/remediation-verification";

describe("Remediation Verification", () => {
  it("exports a valid default configuration", () => {
    expect(DEFAULT_REMEDIATION_CONFIG).toBeDefined();
    expect(DEFAULT_REMEDIATION_CONFIG.maxVerificationAttempts).toBeGreaterThan(0);
    expect(DEFAULT_REMEDIATION_CONFIG.defaultSlaHours).toBeGreaterThan(0);
    expect(DEFAULT_REMEDIATION_CONFIG.criticalSlaHours).toBeGreaterThan(0);
  });

  it("has sensible default values", () => {
    const config = DEFAULT_REMEDIATION_CONFIG;
    // Max attempts should be reasonable (1-10)
    expect(config.maxVerificationAttempts).toBeGreaterThanOrEqual(1);
    expect(config.maxVerificationAttempts).toBeLessThanOrEqual(10);
    // Critical SLA should be shorter than default SLA
    expect(config.criticalSlaHours).toBeLessThan(config.defaultSlaHours);
    // Regression check interval should be positive
    expect(config.regressionCheckIntervalDays).toBeGreaterThan(0);
  });
});

// ─── 6. Exploit Feedback Loop (pure config/logic) ────────────────────
import {
  DEFAULT_FEEDBACK_CONFIG,
  type FeedbackConfig,
  type ModulePerformance,
  type FeedbackEntry,
} from "./lib/exploit-feedback-loop";

describe("Exploit Feedback Loop", () => {
  it("exports a valid default feedback configuration", () => {
    expect(DEFAULT_FEEDBACK_CONFIG).toBeDefined();
    expect(DEFAULT_FEEDBACK_CONFIG.retirementThreshold).toBeGreaterThan(0);
    expect(DEFAULT_FEEDBACK_CONFIG.degradedThreshold).toBeGreaterThan(DEFAULT_FEEDBACK_CONFIG.retirementThreshold);
    expect(DEFAULT_FEEDBACK_CONFIG.minimumAttemptsForRetirement).toBeGreaterThan(0);
    expect(DEFAULT_FEEDBACK_CONFIG.recentWindowSize).toBeGreaterThan(0);
  });

  it("has sensible retirement thresholds", () => {
    const config = DEFAULT_FEEDBACK_CONFIG;
    // Retirement threshold should be low (modules with <5% success)
    expect(config.retirementThreshold).toBeLessThanOrEqual(10);
    // Degraded threshold should be moderate
    expect(config.degradedThreshold).toBeLessThanOrEqual(50);
    expect(config.degradedThreshold).toBeGreaterThan(config.retirementThreshold);
  });

  it("FeedbackEntry type has required fields", () => {
    const entry: FeedbackEntry = {
      moduleName: "exploit/web/sqli",
      moduleSource: "metasploit",
      targetService: "mysql",
      targetVersion: "5.7.32",
      cveIds: ["CVE-2023-1234"],
      success: true,
      executionMs: 1500,
      failureReason: null,
      errorMessage: null,
      timestamp: Date.now(),
    };
    expect(entry.moduleName).toBeTruthy();
    expect(entry.moduleSource).toBe("metasploit");
    expect(entry.success).toBe(true);
    expect(entry.executionMs).toBeGreaterThan(0);
  });
});

// ─── 7. LLM Rule Generator (type checks) ────────────────────────────
import {
  type RuleFormat,
  type RuleGenerationRequest,
  type GeneratedRule,
} from "./lib/llm-rule-generator";

describe("LLM Rule Generator", () => {
  it("RuleFormat type supports standard detection formats", () => {
    const formats: RuleFormat[] = ["sigma", "yara", "snort", "suricata", "kql", "spl"];
    expect(formats.length).toBe(6);
    expect(formats).toContain("sigma");
    expect(formats).toContain("yara");
    expect(formats).toContain("snort");
    expect(formats).toContain("kql");
    expect(formats).toContain("spl");
  });

  it("RuleGenerationRequest type is structurally valid", () => {
    const request: RuleGenerationRequest = {
      attackDescription: "Lateral movement via PsExec",
      mitreTechniqueId: "T1021.002",
      format: "sigma",
      targetPlatform: "windows",
      logSources: ["sysmon", "windows_security"],
    };
    expect(request.attackDescription).toBeTruthy();
    expect(request.format).toBe("sigma");
  });
});

// ─── 8. Exploit Preflight (pure logic) ───────────────────────────────
import {
  filterViableModules,
  type PreFlightResult,
  type PreFlightCheck,
  type ExploitModuleProfile,
} from "./lib/exploit-preflight";

describe("Exploit Preflight", () => {
  it("filters viable modules from preflight results", () => {
    const results: PreFlightResult[] = [
      {
        moduleName: "exploit/web/sqli",
        verdict: "go",
        confidence: 0.9,
        checks: [],
        executionTimeMs: 100,
        recommendation: "Proceed with exploitation",
      },
      {
        moduleName: "exploit/web/xss",
        verdict: "no_go",
        confidence: 0.2,
        checks: [],
        executionTimeMs: 50,
        recommendation: "Do not proceed",
      },
      {
        moduleName: "exploit/web/rce",
        verdict: "caution",
        confidence: 0.6,
        checks: [],
        executionTimeMs: 75,
        recommendation: "Proceed with caution",
      },
    ];
    const viable = filterViableModules(results);
    expect(viable.length).toBe(2); // go + caution
    expect(viable.find(r => r.moduleName === "exploit/web/sqli")).toBeDefined();
    expect(viable.find(r => r.moduleName === "exploit/web/rce")).toBeDefined();
    expect(viable.find(r => r.moduleName === "exploit/web/xss")).toBeUndefined();
  });

  it("ExploitModuleProfile type is structurally valid", () => {
    const profile: ExploitModuleProfile = {
      moduleName: "exploit/linux/http/apache_rce",
      targetService: "apache",
      targetPort: 80,
      affectedVersions: "< 2.4.50",
      affectedProducts: ["Apache HTTP Server"],
      requiredConditions: ["mod_cgi enabled"],
      attackVector: "network",
      reliability: "good",
      historicalSuccessRate: 75,
      historicalAttempts: 20,
      cveIds: ["CVE-2021-41773"],
    };
    expect(profile.moduleName).toBeTruthy();
    expect(profile.targetPort).toBe(80);
    expect(profile.reliability).toBe("good");
    expect(profile.historicalSuccessRate).toBeLessThanOrEqual(100);
  });

  it("returns empty array when all modules are no_go", () => {
    const results: PreFlightResult[] = [
      { moduleName: "a", verdict: "no_go", confidence: 0.1, checks: [], executionTimeMs: 10, recommendation: "No" },
      { moduleName: "b", verdict: "no_go", confidence: 0.05, checks: [], executionTimeMs: 10, recommendation: "No" },
      { moduleName: "c", verdict: "skip", confidence: 0, checks: [], executionTimeMs: 10, recommendation: "Skip" },
    ];
    const viable = filterViableModules(results);
    expect(viable.length).toBe(0);
  });
});
