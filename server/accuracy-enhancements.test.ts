/**
 * Comprehensive tests for all 11 accuracy enhancements.
 * 
 * P0: Cross-Source Corroboration, Dynamic CVE Matching, Closed-Loop Remediation
 * P1: Compensating Controls, Exploit Pre-Flight, Active Probes
 * P2: Temporal Decay, Attack Chain Validation, Exploit Feedback Loop
 * P3: LLM Rule Generation, Rule Evidence Validation
 */
import { describe, it, expect, beforeEach } from "vitest";

// ─── P0-1: Cross-Source Corroboration ──────────────────────────────

import {
  corroborateFindings,
  generateFingerprint,
  type CorroborationConfig,
  DEFAULT_CORROBORATION_CONFIG,
} from "./lib/passive/corroboration-engine";
import type { ConnectorResult, AssetObservation, RiskSignal } from "./lib/passive/types";

function makeObs(overrides: Partial<AssetObservation> & { source: string; assetType: AssetObservation["assetType"]; domain: string }): AssetObservation {
  return {
    assetId: `asset-${Math.random().toString(36).slice(2, 8)}`,
    name: "test",
    ip: "1.2.3.4",
    tags: [],
    evidence: {},
    observedAt: new Date(),
    attribution: { provider: overrides.source, method: "api" },
    ...overrides,
  };
}

function makeConnectorResult(connector: string, observations: AssetObservation[]): ConnectorResult {
  return { connector, domain: "example.com", observations, errors: [], durationMs: 100, rateLimited: false };
}

describe("P0-1: Cross-Source Corroboration Engine", () => {
  it("should boost confidence when multiple sources confirm a finding", () => {
    const obs1 = makeObs({ source: "shodan", assetType: "ip", domain: "example.com", ip: "1.2.3.4", tags: ["port:443"] });
    const obs2 = makeObs({ source: "censys", assetType: "ip", domain: "example.com", ip: "1.2.3.4", tags: ["port:443"] });
    
    const cr1 = makeConnectorResult("shodan", [obs1]);
    const cr2 = makeConnectorResult("censys", [obs2]);
    
    const result = corroborateFindings([cr1, cr2], []);
    expect(result.totalObservations).toBe(2);
    expect(result.corroboratedObservations.length).toBeGreaterThan(0);
  });
  
  it("should generate consistent fingerprints for same observation", () => {
    const obs = makeObs({ source: "shodan", assetType: "ip", domain: "example.com", ip: "10.0.0.1" });
    const fp1 = generateFingerprint(obs);
    const fp2 = generateFingerprint(obs);
    expect(fp1).toBe(fp2);
  });
  
  it("should produce stats with source agreement data", () => {
    const obs1 = makeObs({ source: "shodan", assetType: "subdomain", domain: "example.com", name: "api.example.com" });
    const obs2 = makeObs({ source: "censys", assetType: "subdomain", domain: "example.com", name: "api.example.com" });
    const obs3 = makeObs({ source: "securitytrails", assetType: "subdomain", domain: "example.com", name: "api.example.com" });
    
    const result = corroborateFindings(
      [makeConnectorResult("shodan", [obs1]), makeConnectorResult("censys", [obs2]), makeConnectorResult("securitytrails", [obs3])],
      []
    );
    
    expect(result.stats).toBeDefined();
    expect(result.stats.highConfidenceCount).toBeGreaterThan(0);
  });
});

// ─── P0-2: Dynamic CVE-to-Product Matching ─────────────────────────

import {
  buildCpeUri,
  parseCpeUri,
  matchTechnologyCves,
  getCpeMatchStats,
  clearCpeCache,
} from "./lib/dynamic-cpe-matcher";

describe("P0-2: Dynamic CVE-to-Product Matching", () => {
  beforeEach(() => {
    clearCpeCache();
  });
  
  it("should build a valid CPE URI for known technologies", () => {
    const cpe = buildCpeUri("apache", "2.4.49");
    expect(cpe).toBeTruthy();
    expect(cpe).toContain("cpe:2.3:a:");
    expect(cpe).toContain("apache");
    expect(cpe).toContain("2.4.49");
  });
  
  it("should build CPE URI with wildcard for missing version", () => {
    const cpe = buildCpeUri("nginx");
    expect(cpe).toBeTruthy();
    expect(cpe).toContain("*");
  });
  
  it("should parse a CPE URI back to components", () => {
    const cpe = buildCpeUri("apache", "2.4.49");
    if (cpe) {
      const parsed = parseCpeUri(cpe);
      expect(parsed).toBeDefined();
      expect(parsed!.vendor).toBe("apache");
      expect(parsed!.version).toBe("2.4.49");
    }
  });
  
  it("should return null for unknown technologies", () => {
    const cpe = buildCpeUri("completely_unknown_tech_xyz_12345");
    expect(cpe).toBeNull();
  });
  
  it("should return match results with CVE data", async () => {
    const result = await matchTechnologyCves("apache", "2.4.49");
    expect(result).toHaveProperty("technology");
    expect(result).toHaveProperty("cpeUri");
    expect(result).toHaveProperty("cves");
    expect(result).toHaveProperty("matchConfidence");
    expect(Array.isArray(result.cves)).toBe(true);
  });
  
  it("should track stats", () => {
    const stats = getCpeMatchStats();
    expect(stats).toHaveProperty("totalQueries");
    expect(stats).toHaveProperty("cacheHits");
    expect(stats).toHaveProperty("cacheMisses");
  });
});

// ─── P0-3: Closed-Loop Remediation Verification ───────────────────

import {
  createRemediationRecord,
  markRemediationApplied,
  getRemediationRecord,
  getRemediationSummary,
  clearRemediationRecords,
} from "./lib/remediation-verification";

describe("P0-3: Closed-Loop Remediation Verification", () => {
  beforeEach(() => {
    clearRemediationRecords();
  });
  
  it("should create a remediation record", () => {
    const record = createRemediationRecord({
      scanId: 1,
      findingId: "finding-001",
      cveId: "CVE-2014-6271",
      target: "192.168.1.100",
      port: 80,
      service: "Apache",
      validationId: "val-001",
      exploitModule: "exploit/multi/http/apache_shellshock",
      validatedAt: Date.now(),
      severity: "critical",
    });
    
    expect(record).toHaveProperty("id");
    expect(record.status).toBe("exploitable");
    expect(record.findingId).toBe("finding-001");
    expect(record.slaHours).toBeGreaterThan(0);
  });
  
  it("should mark remediation as applied", () => {
    const record = createRemediationRecord({
      scanId: 1,
      findingId: "finding-002",
      cveId: "CVE-2017-0144",
      target: "10.0.0.50",
      port: 445,
      service: "SMB",
      validationId: "val-002",
      exploitModule: "exploit/windows/smb/ms17_010_eternalblue",
      validatedAt: Date.now(),
      severity: "critical",
    });
    
    const updated = markRemediationApplied(record.id, "Applied MS17-010 patch");
    expect(updated).toBeDefined();
    // autoQueueOnRemediation defaults to true, so status goes to verification_queued
    expect(updated!.status).toBe("verification_queued");
    expect(updated!.remediationNotes).toBe("Applied MS17-010 patch");
  });
  
  it("should retrieve a record by ID", () => {
    const record = createRemediationRecord({
      scanId: 2,
      findingId: "finding-003",
      cveId: null,
      target: "10.0.0.1",
      port: 22,
      service: "SSH",
      validationId: "val-003",
      exploitModule: "test_module",
      validatedAt: Date.now(),
      severity: "high",
    });
    
    const retrieved = getRemediationRecord(record.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(record.id);
  });
  
  it("should return null for unknown IDs", () => {
    const retrieved = getRemediationRecord("nonexistent-id");
    expect(retrieved).toBeNull();
  });
  
  it("should produce a summary", () => {
    createRemediationRecord({
      scanId: 3,
      findingId: "f1",
      cveId: "CVE-2023-12345",
      target: "10.0.0.1",
      port: 80,
      service: "HTTP",
      validationId: "v1",
      exploitModule: "test",
      validatedAt: Date.now(),
      severity: "medium",
    });
    
    const summary = getRemediationSummary();
    expect(summary.totalFindings).toBeGreaterThan(0);
    expect(summary).toHaveProperty("exploitable");
    expect(summary).toHaveProperty("fixRate");
  });
});

// ─── P1-1: Compensating Control Awareness ──────────────────────────

import {
  assessControls,
  detectControlsFromHeaders,
  type DetectedControl,
} from "./lib/compensating-controls";

describe("P1-1: Compensating Control Awareness", () => {
  it("should reduce severity when WAF is detected", () => {
    const controls: DetectedControl[] = [
      {
        category: "waf",
        name: "Cloudflare WAF",
        confidence: "high",
        evidence: "cf-ray header detected",
        mitigationFactor: 0.4,
        affectedAttackVectors: ["network"],
      },
    ];
    
    const result = assessControls(controls, "critical", "network");
    expect(result.overallMitigationScore).toBeGreaterThan(0);
    expect(result.rationale).toBeTruthy();
  });
  
  it("should not reduce severity when no controls detected", () => {
    const result = assessControls([], "critical");
    expect(result.overallMitigationScore).toBe(0);
    expect(result.severityAdjustment).toBe(0);
  });
  
  it("should stack multiple control mitigations with diminishing returns", () => {
    const controls: DetectedControl[] = [
      { category: "waf", name: "AWS WAF", confidence: "high", evidence: "x-amzn-waf header", mitigationFactor: 0.4, affectedAttackVectors: ["network"] },
      { category: "csp", name: "Content-Security-Policy", confidence: "high", evidence: "CSP header present", mitigationFactor: 0.3, affectedAttackVectors: ["network"] },
    ];
    
    const result = assessControls(controls, "high", "network");
    expect(result.overallMitigationScore).toBeGreaterThan(30);
    expect(result.controlCategories.length).toBe(2);
  });
  
  it("should detect controls from HTTP headers", () => {
    const headers: Record<string, string> = {
      "cf-ray": "abc123",
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
    };
    
    const controls = detectControlsFromHeaders(headers);
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.some(c => c.category === "waf" || c.category === "cdn")).toBe(true);
  });
});

// ─── P1-2: Exploit Confidence Pre-Flight Checks ───────────────────

import {
  runPreFlightChecks,
  clearExploitHistory,
  type ExploitModuleProfile,
} from "./lib/exploit-preflight";

describe("P1-2: Exploit Confidence Pre-Flight Checks", () => {
  beforeEach(() => {
    clearExploitHistory();
  });
  
  it("should return go verdict for well-matched exploit", () => {
    const module: ExploitModuleProfile = {
      moduleName: "exploit/multi/http/apache_mod_cgi_bash_env_exec",
      targetService: "Apache",
      targetPort: 80,
      affectedVersions: "< 2.4.50",
      affectedProducts: ["Apache HTTP Server"],
      requiredConditions: [],
      attackVector: "network",
      reliability: "excellent",
      historicalSuccessRate: 85,
      historicalAttempts: 20,
      cveIds: ["CVE-2014-6271"],
    };
    
    const target = {
      host: "192.168.1.100",
      detectedVersion: "2.4.49",
      detectedServices: [{ port: 80, service: "Apache", version: "2.4.49" }],
      detectedFeatures: [],
      isExternal: true,
    };
    
    const result = runPreFlightChecks(module, target);
    expect(result).toHaveProperty("verdict");
    expect(["go", "caution"]).toContain(result.verdict);
    expect(result.checks.length).toBeGreaterThan(0);
    expect(result.overallConfidence).toBeGreaterThanOrEqual(0);
    expect(result.overallConfidence).toBeLessThanOrEqual(1);
  });
  
  it("should flag no_go when service does not match", () => {
    const module: ExploitModuleProfile = {
      moduleName: "exploit/windows/smb/ms17_010_eternalblue",
      targetService: "SMB",
      targetPort: 445,
      affectedVersions: null,
      affectedProducts: ["Windows"],
      requiredConditions: ["SMBv1 enabled"],
      attackVector: "network",
      reliability: "good",
      historicalSuccessRate: 70,
      historicalAttempts: 50,
      cveIds: ["CVE-2017-0144"],
    };
    
    const target = {
      host: "10.0.0.1",
      detectedVersion: null,
      detectedServices: [{ port: 80, service: "HTTP" }],
      detectedFeatures: [],
      isExternal: true,
    };
    
    const result = runPreFlightChecks(module, target);
    expect(result.verdict).toBe("no_go");
  });
  
  it("should include estimated success rate", () => {
    const module: ExploitModuleProfile = {
      moduleName: "test_module",
      targetService: "nginx",
      targetPort: 80,
      affectedVersions: null,
      affectedProducts: [],
      requiredConditions: [],
      attackVector: "network",
      reliability: "average",
      historicalSuccessRate: 50,
      historicalAttempts: 5,
      cveIds: [],
    };
    
    const target = {
      host: "example.com",
      detectedVersion: "1.21.0",
      detectedServices: [{ port: 80, service: "nginx", version: "1.21.0" }],
      detectedFeatures: [],
      isExternal: true,
    };
    
    const result = runPreFlightChecks(module, target);
    expect(result.estimatedSuccessRate).toBeGreaterThanOrEqual(0);
    expect(result.estimatedSuccessRate).toBeLessThanOrEqual(100);
  });
});

// ─── P1-3: Active Verification Probes ──────────────────────────────

import {
  PROBE_TEMPLATES,
  getProbesForCves,
  getProbesByTag,
  type ProbeTemplate,
} from "./lib/active-probes";

describe("P1-3: Active Verification Probes", () => {
  it("should have built-in probe templates", () => {
    expect(PROBE_TEMPLATES.length).toBeGreaterThan(0);
  });
  
  it("should retrieve probes for known CVEs", () => {
    const probes = getProbesForCves(["CVE-2021-44228"]);
    expect(probes.length).toBeGreaterThan(0);
    expect(probes[0].cveIds).toContain("CVE-2021-44228");
  });
  
  it("should retrieve probes by tag", () => {
    const probes = getProbesByTag("rce");
    expect(probes.length).toBeGreaterThan(0);
  });
  
  it("should have valid probe template structure", () => {
    for (const probe of PROBE_TEMPLATES.slice(0, 5)) {
      expect(probe).toHaveProperty("id");
      expect(probe).toHaveProperty("name");
      expect(probe).toHaveProperty("type");
      expect(probe).toHaveProperty("matchConditions");
      expect(probe.matchConditions.length).toBeGreaterThan(0);
    }
  });
  
  it("should return empty array for unknown CVEs", () => {
    const probes = getProbesForCves(["CVE-9999-99999"]);
    expect(probes).toEqual([]);
  });
});

// ─── P2-1: Temporal Decay Scoring ──────────────────────────────────

import {
  calculateTemporalScore,
  batchTemporalScores,
  type TemporalFactors,
  DEFAULT_TEMPORAL_CONFIG,
} from "./lib/temporal-decay";

describe("P2-1: Temporal Decay Scoring", () => {
  const now = Date.now();
  const DAY = 24 * 60 * 60 * 1000;
  
  it("should boost score for KEV-listed vulnerabilities", () => {
    const factors: TemporalFactors = {
      cvePublishedDate: now - 30 * DAY,
      findingFirstSeen: now - 7 * DAY,
      lastValidated: now - 2 * DAY,
      patchAvailableDate: null,
      kevAddedDate: now - 5 * DAY,
      exploitPublicDate: now - 10 * DAY,
      baseSeverity: "high",
      baseScore: 7.5,
    };
    
    const result = calculateTemporalScore(factors, DEFAULT_TEMPORAL_CONFIG, now);
    expect(result.adjustedScore).toBeGreaterThan(7.5);
    expect(result.temporalMultiplier).toBeGreaterThan(1.0);
    // KEV + high adjusted score → immediate or urgent
    expect(["immediate", "urgent"]).toContain(result.urgencyLevel);
  });
  
  it("should penalize unpatched findings with available patches", () => {
    const factors: TemporalFactors = {
      cvePublishedDate: now - 120 * DAY,
      findingFirstSeen: now - 90 * DAY,
      lastValidated: now - 5 * DAY,
      patchAvailableDate: now - 100 * DAY,
      kevAddedDate: null,
      exploitPublicDate: null,
      baseSeverity: "medium",
      baseScore: 5.0,
    };
    
    const result = calculateTemporalScore(factors, DEFAULT_TEMPORAL_CONFIG, now);
    expect(result.temporalMultiplier).toBeGreaterThan(1.0);
    expect(result.decayWarnings.length).toBeGreaterThan(0);
  });
  
  it("should reduce confidence for stale validations", () => {
    const factors: TemporalFactors = {
      cvePublishedDate: now - 365 * DAY,
      findingFirstSeen: now - 200 * DAY,
      lastValidated: now - 120 * DAY,
      patchAvailableDate: null,
      kevAddedDate: null,
      exploitPublicDate: null,
      baseSeverity: "medium",
      baseScore: 5.0,
    };
    
    const result = calculateTemporalScore(factors, DEFAULT_TEMPORAL_CONFIG, now);
    const staleFactor = result.factors.find(f => f.name === "Validation Staleness");
    expect(staleFactor).toBeDefined();
    expect(staleFactor!.multiplier).toBeLessThan(1.0);
  });
  
  it("should cap adjusted score at 10", () => {
    const factors: TemporalFactors = {
      cvePublishedDate: now - 5 * DAY,
      findingFirstSeen: now - 2 * DAY,
      lastValidated: now - 1 * DAY,
      patchAvailableDate: now - 60 * DAY,
      kevAddedDate: now - 3 * DAY,
      exploitPublicDate: now - 3 * DAY,
      baseSeverity: "critical",
      baseScore: 9.8,
    };
    
    const result = calculateTemporalScore(factors, DEFAULT_TEMPORAL_CONFIG, now);
    expect(result.adjustedScore).toBeLessThanOrEqual(10);
  });
  
  it("should batch calculate scores for multiple findings", () => {
    const findings = [
      { id: "f1", factors: { cvePublishedDate: now - 30 * DAY, findingFirstSeen: now - 10 * DAY, lastValidated: now - 2 * DAY, patchAvailableDate: null, kevAddedDate: null, exploitPublicDate: null, baseSeverity: "high" as const, baseScore: 7.5 } },
      { id: "f2", factors: { cvePublishedDate: now - 90 * DAY, findingFirstSeen: now - 60 * DAY, lastValidated: null, patchAvailableDate: now - 80 * DAY, kevAddedDate: null, exploitPublicDate: null, baseSeverity: "medium" as const, baseScore: 5.0 } },
    ];
    
    const results = batchTemporalScores(findings);
    expect(results.size).toBe(2);
    expect(results.get("f1")).toBeDefined();
    expect(results.get("f2")).toBeDefined();
  });
  
  it("should produce a rationale string", () => {
    const factors: TemporalFactors = {
      cvePublishedDate: now - 30 * DAY,
      findingFirstSeen: now - 10 * DAY,
      lastValidated: now - 5 * DAY,
      patchAvailableDate: null,
      kevAddedDate: null,
      exploitPublicDate: null,
      baseSeverity: "medium",
      baseScore: 5.0,
    };
    
    const result = calculateTemporalScore(factors, DEFAULT_TEMPORAL_CONFIG, now);
    expect(result.rationale).toBeTruthy();
    expect(typeof result.rationale).toBe("string");
  });
});

// ─── P2-2: Attack Chain Validation ─────────────────────────────────

import {
  analyzeAttackChains,
  calculateChainSeverity,
  CHAIN_PATTERNS,
  resetChainCounter,
} from "./lib/attack-chain-validation";
import type { ChainLink } from "./lib/attack-chain-validation";

describe("P2-2: Attack Chain Validation", () => {
  beforeEach(() => {
    resetChainCounter();
  });
  
  it("should identify chains from related findings on same target", () => {
    const findings = [
      { id: "f1", title: "Server-Side Request Forgery (SSRF)", severity: "medium" as const, description: "SSRF vulnerability allows internal network access", target: "app.example.com", port: 443, cveId: null, validated: true },
      { id: "f2", title: "Internal Service Discovery", severity: "low" as const, description: "Service enumeration of internal network via SSRF", target: "app.example.com", port: 443, cveId: null, validated: true },
      { id: "f3", title: "Remote Code Execution", severity: "high" as const, description: "RCE via command injection on internal service", target: "app.example.com", port: 443, cveId: null, validated: false },
    ];
    
    const result = analyzeAttackChains(findings);
    expect(result).toHaveProperty("totalChainsFound");
    expect(result).toHaveProperty("chains");
    expect(result).toHaveProperty("coverageByPhase");
  });
  
  it("should boost severity for multi-step chains", () => {
    const links: ChainLink[] = [
      { findingId: "f1", title: "Info Disclosure", severity: "low", phase: "reconnaissance", attackTechnique: "T1595", target: "example.com", port: 80, prerequisite: null, provides: ["info_disclosure"], validated: true },
      { findingId: "f2", title: "Credential Extraction", severity: "medium", phase: "credential_access", attackTechnique: "T1555", target: "example.com", port: 80, prerequisite: "info_disclosure", provides: ["credential_extraction"], validated: true },
      { findingId: "f3", title: "RCE via stolen creds", severity: "high", phase: "execution", attackTechnique: "T1059", target: "example.com", port: 80, prerequisite: "credential_extraction", provides: ["code_execution"], validated: true },
    ];
    
    const { severity, score } = calculateChainSeverity(links);
    expect(["critical", "high"]).toContain(severity);
    expect(score).toBeGreaterThan(5);
  });
  
  it("should not create chains from unrelated findings on different targets", () => {
    const findings = [
      { id: "f1", title: "Open SSH port", severity: "low" as const, description: "SSH port open", target: "server-a.com", port: 22, cveId: null, validated: false },
      { id: "f2", title: "Open HTTP port", severity: "low" as const, description: "HTTP port open", target: "server-b.com", port: 80, cveId: null, validated: false },
    ];
    
    const result = analyzeAttackChains(findings);
    // Different targets — should not form multi-step chains
    expect(result.chains.filter(c => c.links.length >= 2).length).toBe(0);
  });
  
  it("should have at least 5 known chain patterns", () => {
    expect(CHAIN_PATTERNS.length).toBeGreaterThanOrEqual(5);
  });
  
  it("should include kill chain coverage in results", () => {
    const findings = [
      { id: "f1", title: "SQL Injection", severity: "high" as const, description: "SQL injection allows credential extraction", target: "app.com", port: 443, cveId: null, validated: true },
      { id: "f2", title: "Privilege Escalation", severity: "high" as const, description: "Local privilege escalation", target: "app.com", port: 443, cveId: null, validated: true },
    ];
    
    const result = analyzeAttackChains(findings);
    expect(result.coverageByPhase).toBeDefined();
    expect(typeof result.coverageByPhase.initial_access).toBe("number");
  });
});

// ─── P2-3: Exploit Module Feedback Loop ────────────────────────────

import {
  recordFeedback,
  getModulePerformance,
  rankModulesForService,
  getFeedbackSummary,
  generateLlmFeedbackPrompt,
  clearFeedbackData,
  type FeedbackEntry,
} from "./lib/exploit-feedback-loop";

describe("P2-3: Exploit Module Feedback Loop", () => {
  beforeEach(() => {
    clearFeedbackData();
  });
  
  it("should record feedback and update module performance", () => {
    const entry: FeedbackEntry = {
      moduleName: "exploit/multi/http/apache_shellshock",
      moduleSource: "metasploit",
      targetService: "Apache",
      targetVersion: "2.4.49",
      cveIds: ["CVE-2014-6271"],
      success: true,
      executionMs: 1500,
      failureReason: null,
      errorMessage: null,
      timestamp: Date.now(),
    };
    
    const perf = recordFeedback(entry);
    expect(perf.totalAttempts).toBe(1);
    expect(perf.successes).toBe(1);
    expect(perf.successRate).toBe(100);
    expect(perf.status).toBe("new");
  });
  
  it("should track success rate over multiple attempts", () => {
    const now = Date.now();
    
    for (let i = 0; i < 10; i++) {
      recordFeedback({
        moduleName: "exploit/test_module",
        moduleSource: "exploitdb",
        targetService: "nginx",
        targetVersion: "1.21.0",
        cveIds: ["CVE-2021-12345"],
        success: i < 7,
        executionMs: 1000 + i * 100,
        failureReason: i >= 7 ? "Connection refused" : null,
        errorMessage: null,
        timestamp: now + i * 1000,
      });
    }
    
    const perf = getModulePerformance("exploit/test_module");
    expect(perf).toBeDefined();
    expect(perf!.totalAttempts).toBe(10);
    expect(perf!.successRate).toBe(70);
    expect(perf!.status).toBe("active");
  });
  
  it("should retire modules with consistently low success rates", () => {
    for (let i = 0; i < 15; i++) {
      recordFeedback({
        moduleName: "exploit/bad_module",
        moduleSource: "custom",
        targetService: "IIS",
        targetVersion: "10.0",
        cveIds: [],
        success: false,
        executionMs: 5000,
        failureReason: "Exploit failed",
        errorMessage: null,
        timestamp: Date.now() + i * 1000,
      });
    }
    
    const perf = getModulePerformance("exploit/bad_module");
    expect(perf).toBeDefined();
    expect(perf!.status).toBe("retired");
    expect(perf!.successRate).toBe(0);
  });
  
  it("should rank modules by reliability for a service", () => {
    const now = Date.now();
    
    for (let i = 0; i < 5; i++) {
      recordFeedback({
        moduleName: "exploit/good_apache",
        moduleSource: "metasploit",
        targetService: "Apache",
        targetVersion: "2.4.49",
        cveIds: ["CVE-2021-41773"],
        success: true,
        executionMs: 800,
        failureReason: null,
        errorMessage: null,
        timestamp: now + i * 1000,
      });
    }
    
    for (let i = 0; i < 5; i++) {
      recordFeedback({
        moduleName: "exploit/ok_apache",
        moduleSource: "exploitdb",
        targetService: "Apache",
        targetVersion: "2.4.49",
        cveIds: ["CVE-2021-41773"],
        success: i < 3,
        executionMs: 2000,
        failureReason: i >= 3 ? "Timeout" : null,
        errorMessage: null,
        timestamp: now + i * 1000,
      });
    }
    
    const rankings = rankModulesForService("Apache");
    expect(rankings.length).toBe(2);
    expect(rankings[0].moduleName).toBe("exploit/good_apache");
    expect(rankings[0].reliabilityScore).toBeGreaterThan(rankings[1].reliabilityScore);
  });
  
  it("should generate LLM feedback prompt for failing modules", () => {
    for (let i = 0; i < 5; i++) {
      recordFeedback({
        moduleName: "exploit/failing_module",
        moduleSource: "llm_generated",
        targetService: "nginx",
        targetVersion: "1.20.0",
        cveIds: ["CVE-2021-23017"],
        success: i === 0,
        executionMs: 3000,
        failureReason: i > 0 ? "Connection reset" : null,
        errorMessage: null,
        timestamp: Date.now() + i * 1000,
      });
    }
    
    const prompt = generateLlmFeedbackPrompt("exploit/failing_module");
    expect(prompt).toBeTruthy();
    expect(prompt).toContain("exploit/failing_module");
  });
  
  it("should produce a feedback summary", () => {
    recordFeedback({
      moduleName: "exploit/summary_test",
      moduleSource: "metasploit",
      targetService: "SSH",
      targetVersion: "8.0",
      cveIds: [],
      success: true,
      executionMs: 500,
      failureReason: null,
      errorMessage: null,
      timestamp: Date.now(),
    });
    
    const summary = getFeedbackSummary();
    expect(summary.totalModules).toBeGreaterThan(0);
    expect(summary).toHaveProperty("overallSuccessRate");
    expect(summary).toHaveProperty("topPerformers");
    expect(summary).toHaveProperty("recentTrends");
  });
});

// ─── P3-1: LLM-Powered Rule Generation ────────────────────────────

import {
  generateDetectionRules,
  getRule,
  getRulesForCve,
  getRulesByFormat,
  validateRule,
  getRuleLibrary,
  clearRuleStore,
  type RuleGenerationRequest,
  type GeneratedRule,
} from "./lib/llm-rule-generator";

describe("P3-1: LLM-Powered Rule Generation", () => {
  beforeEach(() => {
    clearRuleStore();
  });
  
  it("should generate fallback rules in multiple formats", async () => {
    const request: RuleGenerationRequest = {
      exploitModule: "exploit/multi/http/apache_shellshock",
      cveIds: ["CVE-2014-6271"],
      targetService: "Apache",
      targetPort: 80,
      attackTechnique: "T1190",
      exploitOutput: "Meterpreter session 1 opened",
      evidenceArtifacts: [],
      severity: "critical",
      requestedFormats: ["sigma", "yara", "snort"],
    };
    
    const result = await generateDetectionRules(request);
    expect(result.totalGenerated).toBe(3);
    expect(result.rules.length).toBe(3);
    expect(result.rules.map(r => r.format)).toContain("sigma");
    expect(result.rules.map(r => r.format)).toContain("yara");
    expect(result.rules.map(r => r.format)).toContain("snort");
  });
  
  it("should generate valid Sigma rule content", async () => {
    const result = await generateDetectionRules({
      exploitModule: "test_exploit",
      cveIds: ["CVE-2023-12345"],
      targetService: "nginx",
      targetPort: 443,
      attackTechnique: "T1190",
      exploitOutput: null,
      evidenceArtifacts: [],
      severity: "high",
      requestedFormats: ["sigma"],
    });
    
    const sigmaRule = result.rules[0];
    expect(sigmaRule.content).toContain("title:");
    expect(sigmaRule.content).toContain("detection:");
    expect(sigmaRule.content).toContain("level:");
  });
  
  it("should generate valid YARA rule content", async () => {
    const result = await generateDetectionRules({
      exploitModule: "test_exploit",
      cveIds: ["CVE-2023-12345"],
      targetService: "Apache",
      targetPort: 80,
      attackTechnique: "T1190",
      exploitOutput: null,
      evidenceArtifacts: [],
      severity: "high",
      requestedFormats: ["yara"],
    });
    
    const yaraRule = result.rules[0];
    expect(yaraRule.content).toContain("rule ");
    expect(yaraRule.content).toContain("meta:");
    expect(yaraRule.content).toContain("condition:");
  });
  
  it("should retrieve rules by CVE", async () => {
    await generateDetectionRules({
      exploitModule: "test",
      cveIds: ["CVE-2024-99999"],
      targetService: "test",
      targetPort: 80,
      attackTechnique: "T1190",
      exploitOutput: null,
      evidenceArtifacts: [],
      severity: "high",
      requestedFormats: ["sigma"],
    });
    
    const rules = getRulesForCve("CVE-2024-99999");
    expect(rules.length).toBe(1);
    expect(rules[0].cveIds).toContain("CVE-2024-99999");
  });
  
  it("should validate and promote rules", async () => {
    const result = await generateDetectionRules({
      exploitModule: "test",
      cveIds: ["CVE-2024-11111"],
      targetService: "test",
      targetPort: 80,
      attackTechnique: "T1190",
      exploitOutput: null,
      evidenceArtifacts: [],
      severity: "high",
      requestedFormats: ["sigma"],
    });
    
    const ruleId = result.rules[0].id;
    const validated = validateRule(ruleId, true, "Tested against evidence, all patterns matched.");
    expect(validated).toBeDefined();
    expect(validated!.validated).toBe(true);
    expect(validated!.confidence).toBe("high");
  });
  
  it("should produce a rule library summary", async () => {
    await generateDetectionRules({
      exploitModule: "test",
      cveIds: ["CVE-2024-22222"],
      targetService: "test",
      targetPort: 80,
      attackTechnique: "T1190",
      exploitOutput: null,
      evidenceArtifacts: [],
      severity: "critical",
      requestedFormats: ["sigma", "yara", "snort", "kql", "spl"],
    });
    
    const library = getRuleLibrary();
    expect(library.totalRules).toBe(5);
    expect(library.byFormat.sigma).toBe(1);
    expect(library.byFormat.yara).toBe(1);
    expect(library.byFormat.snort).toBe(1);
    expect(library.byFormat.kql).toBe(1);
    expect(library.byFormat.spl).toBe(1);
  });
});

// ─── P3-2: Rule Validation Against Evidence ────────────────────────

import {
  validateRuleAgainstEvidence,
  batchValidateRules,
  type EvidenceArtifact,
} from "./lib/rule-evidence-validator";

describe("P3-2: Rule Validation Against Evidence", () => {
  it("should detect matching patterns in evidence", () => {
    const rule: GeneratedRule = {
      id: "rule-test-1",
      format: "snort",
      name: "Detect Apache Shellshock",
      description: "Detects Shellshock exploit",
      content: 'alert tcp any any -> any 80 (msg:"Shellshock"; content:"Apache"; content:"bash"; sid:1000001;)',
      severity: "critical",
      mitreTechniques: ["T1190"],
      cveIds: ["CVE-2014-6271"],
      confidence: "medium",
      falsePositiveRisk: "medium",
      tags: ["snort", "apache"],
      generatedAt: Date.now(),
      validated: false,
      validationNotes: null,
    };
    
    const evidence: EvidenceArtifact = {
      id: "ev-1",
      type: "console_output",
      content: "Exploiting Apache 2.4.49 via bash environment variable injection. Meterpreter session opened on port 80.",
      mimeType: "text/plain",
      capturedAt: Date.now(),
      exploitModule: "exploit/multi/http/apache_shellshock",
      targetHost: "192.168.1.100",
      targetPort: 80,
    };
    
    const result = validateRuleAgainstEvidence(rule, evidence);
    expect(result.detected).toBe(true);
    expect(result.matchCount).toBeGreaterThan(0);
    expect(result.matchedPatterns.length).toBeGreaterThan(0);
  });
  
  it("should report missed patterns", () => {
    const rule: GeneratedRule = {
      id: "rule-test-2",
      format: "snort",
      name: "Detect EternalBlue",
      description: "Detects EternalBlue SMB exploit",
      content: 'alert tcp any any -> any 445 (msg:"EternalBlue"; content:"SMBv1"; content:"ms17-010"; sid:1000002;)',
      severity: "critical",
      mitreTechniques: ["T1210"],
      cveIds: ["CVE-2017-0144"],
      confidence: "medium",
      falsePositiveRisk: "medium",
      tags: ["snort", "smb"],
      generatedAt: Date.now(),
      validated: false,
      validationNotes: null,
    };
    
    const evidence: EvidenceArtifact = {
      id: "ev-2",
      type: "console_output",
      content: "HTTP request to Apache server on port 80 returned 200 OK",
      mimeType: "text/plain",
      capturedAt: Date.now(),
      exploitModule: "exploit/multi/http/apache_test",
      targetHost: "192.168.1.100",
      targetPort: 80,
    };
    
    const result = validateRuleAgainstEvidence(rule, evidence);
    expect(result.detected).toBe(false);
    expect(result.missedPatterns.length).toBeGreaterThan(0);
    expect(result.detectionConfidence).toBe("none");
  });
  
  it("should batch validate multiple rules against evidence", () => {
    const rules: GeneratedRule[] = [
      {
        id: "rule-batch-1",
        format: "sigma",
        name: "Detect Apache Exploit",
        description: "Sigma rule for Apache",
        content: `title: Detect Apache Exploit\ndetection:\n  selection:\n    dst_port: 80\n  condition: selection\nlevel: high`,
        severity: "high",
        mitreTechniques: ["T1190"],
        cveIds: ["CVE-2021-41773"],
        confidence: "medium",
        falsePositiveRisk: "medium",
        tags: [],
        generatedAt: Date.now(),
        validated: false,
        validationNotes: null,
      },
      {
        id: "rule-batch-2",
        format: "yara",
        name: "Detect Webshell",
        description: "YARA rule for webshell",
        content: `rule detect_webshell {\n  meta:\n    description = "Detect webshell"\n  strings:\n    $s1 = "eval(" ascii\n    $s2 = "system(" ascii\n  condition:\n    any of them\n}`,
        severity: "critical",
        mitreTechniques: ["T1505"],
        cveIds: [],
        confidence: "medium",
        falsePositiveRisk: "medium",
        tags: [],
        generatedAt: Date.now(),
        validated: false,
        validationNotes: null,
      },
    ];
    
    const evidence: EvidenceArtifact[] = [
      {
        id: "ev-batch-1",
        type: "console_output",
        content: "Connected to Apache on port 80. Running eval(base64_decode(...)) via system() call.",
        mimeType: "text/plain",
        capturedAt: Date.now(),
        exploitModule: "test",
        targetHost: "10.0.0.1",
        targetPort: 80,
      },
    ];
    
    const result = batchValidateRules(rules, evidence);
    expect(result.totalRules).toBe(2);
    expect(result.rulesValidated).toBe(2);
    expect(result.rulesDetected).toBeGreaterThan(0);
    expect(result.summary).toBeTruthy();
  });
  
  it("should calculate coverage percentage", () => {
    const rule: GeneratedRule = {
      id: "rule-cov-1",
      format: "sigma",
      name: "Test Coverage",
      description: "Test",
      content: `title: Test\ndetection:\n  selection:\n    dst_port: 443\n    DestinationHostname: 'example.com'\n  condition: selection\nlevel: medium`,
      severity: "medium",
      mitreTechniques: [],
      cveIds: [],
      confidence: "low",
      falsePositiveRisk: "medium",
      tags: [],
      generatedAt: Date.now(),
      validated: false,
      validationNotes: null,
    };
    
    const evidence: EvidenceArtifact = {
      id: "ev-cov-1",
      type: "console_output",
      content: "Connection to example.com:443 established. TLS handshake complete.",
      mimeType: "text/plain",
      capturedAt: Date.now(),
      exploitModule: "test",
      targetHost: "example.com",
      targetPort: 443,
    };
    
    const result = validateRuleAgainstEvidence(rule, evidence);
    expect(result.coveragePercent).toBeGreaterThanOrEqual(0);
    expect(result.coveragePercent).toBeLessThanOrEqual(100);
    expect(result.recommendations.length).toBeGreaterThan(0);
  });
});
