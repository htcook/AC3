import { describe, it, expect } from "vitest";
import {
  AWS_CIS_CHECKS,
  AZURE_CIS_CHECKS,
  GCP_CIS_CHECKS,
  ALL_CIS_CHECKS,
  getChecksByProvider,
  getChecksByDomain,
  getCheckById,
  runAssessment,
  generateComplianceSummary,
  getProviderStats,
  type CloudProvider,
  type CheckDomain,
} from "./lib/cloud-security-validation";
import {
  generateFromEmulation,
  generateForThreatActor,
  exportToSigmaYaml,
  exportToSplunkSPL,
  exportToKQL,
  exportToElasticEQL,
  exportRule,
  exportRuleSet,
  getAvailableTemplates,
  getTemplateCoverage,
  type EmulationInput,
} from "./lib/sigma-rule-engine";

// ═══════════════════════════════════════════════════════════════════════════
// CLOUD SECURITY VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("Cloud Security Validation Engine", () => {
  describe("CIS Check Catalog", () => {
    it("should have checks for all three providers", () => {
      expect(AWS_CIS_CHECKS.length).toBeGreaterThan(0);
      expect(AZURE_CIS_CHECKS.length).toBeGreaterThan(0);
      expect(GCP_CIS_CHECKS.length).toBeGreaterThan(0);
    });

    it("ALL_CIS_CHECKS should be the union of all provider checks", () => {
      expect(ALL_CIS_CHECKS.length).toBe(
        AWS_CIS_CHECKS.length + AZURE_CIS_CHECKS.length + GCP_CIS_CHECKS.length
      );
    });

    it("every check should have required fields", () => {
      for (const check of ALL_CIS_CHECKS) {
        expect(check.id).toBeTruthy();
        expect(check.title).toBeTruthy();
        expect(check.description).toBeTruthy();
        expect(check.provider).toMatch(/^(aws|azure|gcp)$/);
        expect(check.domain).toMatch(/^(iam|networking|storage|compute|logging)$/);
        expect(check.severity).toMatch(/^(critical|high|medium|low|info)$/);
        expect(check.cisBenchmark).toBeTruthy();
        expect(check.defaultResource).toBeTruthy();
        expect(Array.isArray(check.mitreTechniques)).toBe(true);
        expect(Array.isArray(check.remediationSteps)).toBe(true);
        expect(check.remediationSteps.length).toBeGreaterThan(0);
      }
    });

    it("check IDs should be unique across all providers", () => {
      const ids = ALL_CIS_CHECKS.map(c => c.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it("each provider should cover all 5 domains", () => {
      const domains: CheckDomain[] = ["iam", "networking", "storage", "compute", "logging"];
      for (const provider of ["aws", "azure", "gcp"] as CloudProvider[]) {
        const checks = getChecksByProvider(provider);
        const coveredDomains = new Set(checks.map(c => c.domain));
        for (const domain of domains) {
          expect(coveredDomains.has(domain)).toBe(true);
        }
      }
    });
  });

  describe("getChecksByProvider", () => {
    it("should return only AWS checks for aws", () => {
      const checks = getChecksByProvider("aws");
      expect(checks.length).toBe(AWS_CIS_CHECKS.length);
      expect(checks.every(c => c.provider === "aws")).toBe(true);
    });

    it("should return only Azure checks for azure", () => {
      const checks = getChecksByProvider("azure");
      expect(checks.length).toBe(AZURE_CIS_CHECKS.length);
      expect(checks.every(c => c.provider === "azure")).toBe(true);
    });

    it("should return only GCP checks for gcp", () => {
      const checks = getChecksByProvider("gcp");
      expect(checks.length).toBe(GCP_CIS_CHECKS.length);
      expect(checks.every(c => c.provider === "gcp")).toBe(true);
    });
  });

  describe("getChecksByDomain", () => {
    it("should filter by both provider and domain", () => {
      const iamChecks = getChecksByDomain("aws", "iam");
      expect(iamChecks.length).toBeGreaterThan(0);
      expect(iamChecks.every(c => c.provider === "aws" && c.domain === "iam")).toBe(true);
    });
  });

  describe("getCheckById", () => {
    it("should find a check by its ID", () => {
      const firstCheck = ALL_CIS_CHECKS[0];
      const found = getCheckById(firstCheck.id);
      expect(found).toBeDefined();
      expect(found!.id).toBe(firstCheck.id);
    });

    it("should return undefined for non-existent ID", () => {
      expect(getCheckById("nonexistent-check")).toBeUndefined();
    });
  });

  describe("runAssessment", () => {
    it("should return a valid assessment for AWS", () => {
      const assessment = runAssessment("aws", "123456789012", "Production", {});
      expect(assessment.provider).toBe("aws");
      expect(assessment.accountId).toBe("123456789012");
      expect(assessment.accountAlias).toBe("Production");
      expect(assessment.results.length).toBe(AWS_CIS_CHECKS.length);
      expect(assessment.overallScore).toBeGreaterThanOrEqual(0);
      expect(assessment.overallScore).toBeLessThanOrEqual(100);
      expect(assessment.passed + assessment.failed + assessment.notAssessed).toBe(assessment.totalChecks);
    });

    it("should filter by selected domains", () => {
      const assessment = runAssessment("aws", "123456789012", "Test", {}, ["iam"]);
      const iamCheckCount = AWS_CIS_CHECKS.filter(c => c.domain === "iam").length;
      expect(assessment.results.length).toBe(iamCheckCount);
    });

    it("should include domain scores", () => {
      const assessment = runAssessment("azure", "sub-123", "Staging", {});
      expect(assessment.domainScores).toBeDefined();
      expect(assessment.domainScores.iam).toBeDefined();
      expect(assessment.domainScores.iam.score).toBeGreaterThanOrEqual(0);
    });

    it("should work for all three providers", () => {
      for (const provider of ["aws", "azure", "gcp"] as CloudProvider[]) {
        const assessment = runAssessment(provider, "test-id", "Test", {});
        expect(assessment.provider).toBe(provider);
        expect(assessment.results.length).toBeGreaterThan(0);
      }
    });
  });

  describe("generateComplianceSummary", () => {
    it("should generate framework compliance summary", () => {
      const assessment = runAssessment("aws", "123", "Test", {});
      const summary = generateComplianceSummary(assessment);
      expect(summary.frameworks).toBeDefined();
      expect(Array.isArray(summary.frameworks)).toBe(true);
      expect(summary.frameworks.length).toBeGreaterThan(0);
      for (const fw of summary.frameworks) {
        expect(fw.name).toBeTruthy();
        expect(fw.controlsCovered).toBeGreaterThanOrEqual(0);
        expect(fw.score).toBeGreaterThanOrEqual(0);
        expect(fw.score).toBeLessThanOrEqual(100);
      }
    });
  });

  describe("getProviderStats", () => {
    it("should return stats for all three providers", () => {
      const stats = getProviderStats();
      expect(stats.providers.length).toBe(3);
      const providerNames = stats.providers.map(p => p.provider);
      expect(providerNames).toContain("aws");
      expect(providerNames).toContain("azure");
      expect(providerNames).toContain("gcp");
      for (const p of stats.providers) {
        expect(p.totalChecks).toBeGreaterThan(0);
        expect(p.domains.length).toBe(5);
        expect(p.cisBenchmarkVersion).toBeTruthy();
      }
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SIGMA RULE GENERATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("Sigma Rule Generation Engine", () => {
  describe("Template Library", () => {
    it("should have available technique templates", () => {
      const templates = getAvailableTemplates();
      expect(templates.length).toBeGreaterThan(0);
    });

    it("every template should have required fields", () => {
      const templates = getAvailableTemplates();
      for (const t of templates) {
        expect(t.techniqueId).toMatch(/^T\d{4}/);
        expect(t.techniqueName).toBeTruthy();
        expect(t.tactic).toBeTruthy();
        expect(t.logSource).toBeTruthy();
        expect(t.level).toMatch(/^(informational|low|medium|high|critical)$/);
      }
    });

    it("technique IDs should be unique", () => {
      const templates = getAvailableTemplates();
      const ids = templates.map(t => t.techniqueId);
      const unique = new Set(ids);
      expect(unique.size).toBe(ids.length);
    });
  });

  describe("getTemplateCoverage", () => {
    it("should return coverage statistics", () => {
      const coverage = getTemplateCoverage();
      expect(coverage.totalTemplates).toBeGreaterThan(0);
      expect(Object.keys(coverage.byTactic).length).toBeGreaterThan(0);
      expect(Object.keys(coverage.byLogSource).length).toBeGreaterThan(0);
      expect(coverage.tactics.length).toBeGreaterThan(0);
    });

    it("totalTemplates should match getAvailableTemplates count", () => {
      const coverage = getTemplateCoverage();
      const templates = getAvailableTemplates();
      expect(coverage.totalTemplates).toBe(templates.length);
    });
  });

  describe("generateFromEmulation", () => {
    it("should generate rules from emulation inputs", () => {
      const inputs: EmulationInput[] = [
        {
          techniqueId: "T1059.001",
          techniqueName: "PowerShell",
          tactic: "execution",
          procedure: "Invoke-Expression used to download and execute payload",
        },
      ];
      const ruleSet = generateFromEmulation(inputs);
      expect(ruleSet.id).toBeTruthy();
      expect(ruleSet.name).toContain("Emulation");
      expect(ruleSet.source).toBe("emulation");
      expect(ruleSet.totalRules).toBeGreaterThan(0);
      expect(ruleSet.rules.length).toBe(ruleSet.totalRules);
      expect(ruleSet.createdAt).toBeGreaterThan(0);
    });

    it("should generate rules even for unknown techniques (fallback)", () => {
      const inputs: EmulationInput[] = [
        {
          techniqueId: "T9999",
          techniqueName: "Unknown Technique",
          tactic: "execution",
        },
      ];
      const ruleSet = generateFromEmulation(inputs);
      expect(ruleSet.totalRules).toBeGreaterThan(0);
    });

    it("should mark detection gap rules appropriately", () => {
      const inputs: EmulationInput[] = [
        {
          techniqueId: "T1059.001",
          techniqueName: "PowerShell",
          tactic: "execution",
          detectionGap: true,
        },
      ];
      const ruleSet = generateFromEmulation(inputs);
      const gapRule = ruleSet.rules.find(r => r.description.includes("[DETECTION GAP]"));
      expect(gapRule).toBeDefined();
    });

    it("should handle multiple techniques", () => {
      const inputs: EmulationInput[] = [
        { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution" },
        { techniqueId: "T1053.005", techniqueName: "Scheduled Task", tactic: "persistence" },
        { techniqueId: "T1003.001", techniqueName: "LSASS Memory", tactic: "credential-access" },
      ];
      const ruleSet = generateFromEmulation(inputs);
      expect(ruleSet.totalRules).toBeGreaterThanOrEqual(3);
    });

    it("should populate byLevel counts correctly", () => {
      const inputs: EmulationInput[] = [
        { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution" },
        { techniqueId: "T1003.001", techniqueName: "LSASS Memory", tactic: "credential-access" },
      ];
      const ruleSet = generateFromEmulation(inputs);
      const totalByLevel = Object.values(ruleSet.byLevel).reduce((a, b) => a + b, 0);
      expect(totalByLevel).toBe(ruleSet.totalRules);
    });
  });

  describe("generateForThreatActor", () => {
    it("should generate a threat actor detection pack", () => {
      const ruleSet = generateForThreatActor("APT29", [
        { id: "T1059.001", name: "PowerShell", tactic: "execution" },
        { id: "T1053.005", name: "Scheduled Task", tactic: "persistence" },
      ]);
      expect(ruleSet.name).toContain("APT29");
      expect(ruleSet.source).toBe("threat_actor");
      expect(ruleSet.totalRules).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Rule Export Formats", () => {
    let testRule: any;

    const getTestRule = () => {
      const ruleSet = generateFromEmulation([
        { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution" },
      ]);
      return ruleSet.rules[0];
    };

    it("should export to Sigma YAML format", () => {
      testRule = getTestRule();
      const yaml = exportToSigmaYaml(testRule);
      expect(yaml).toContain("title:");
      expect(yaml).toContain("logsource:");
      expect(yaml).toContain("detection:");
      expect(yaml).toContain("level:");
    });

    it("should export to Splunk SPL format", () => {
      testRule = getTestRule();
      const spl = exportToSplunkSPL(testRule);
      expect(spl).toBeTruthy();
      expect(spl.length).toBeGreaterThan(0);
    });

    it("should export to KQL format", () => {
      testRule = getTestRule();
      const kql = exportToKQL(testRule);
      expect(kql).toBeTruthy();
      expect(kql.length).toBeGreaterThan(0);
    });

    it("should export to Elastic EQL format", () => {
      testRule = getTestRule();
      const eql = exportToElasticEQL(testRule);
      expect(eql).toBeTruthy();
      expect(eql.length).toBeGreaterThan(0);
    });

    it("exportRule should dispatch to the correct format", () => {
      testRule = getTestRule();
      const sigmaOut = exportRule(testRule, "sigma");
      const splOut = exportRule(testRule, "splunk_spl");
      const kqlOut = exportRule(testRule, "kql");
      const eqlOut = exportRule(testRule, "elastic_eql");
      expect(sigmaOut).toContain("title:");
      expect(splOut).toBeTruthy();
      expect(kqlOut).toBeTruthy();
      expect(eqlOut).toBeTruthy();
      // They should all be different
      expect(sigmaOut).not.toBe(splOut);
    });

    it("exportRuleSet should export all rules with separator", () => {
      const ruleSet = generateFromEmulation([
        { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution" },
        { techniqueId: "T1053.005", techniqueName: "Scheduled Task", tactic: "persistence" },
      ]);
      const exported = exportRuleSet(ruleSet, "sigma");
      expect(exported).toBeTruthy();
      expect(exported.length).toBeGreaterThan(100);
    });
  });

  describe("SigmaRule structure", () => {
    it("every generated rule should have required fields", () => {
      const ruleSet = generateFromEmulation([
        { techniqueId: "T1059.001", techniqueName: "PowerShell", tactic: "execution" },
        { techniqueId: "T1003.001", techniqueName: "LSASS Memory", tactic: "credential-access" },
      ]);
      for (const rule of ruleSet.rules) {
        expect(rule.id).toBeTruthy();
        expect(rule.title).toBeTruthy();
        expect(rule.description).toBeTruthy();
        expect(rule.level).toMatch(/^(informational|low|medium|high|critical)$/);
        expect(rule.status).toMatch(/^(experimental|test|stable|deprecated)$/);
        expect(rule.techniqueId).toMatch(/^T\d{4}/);
        expect(rule.tactic).toBeTruthy();
        expect(rule.logsource).toBeDefined();
        expect(rule.logsource.category).toBeTruthy();
        expect(rule.detection).toBeDefined();
        expect(rule.confidence).toBeGreaterThanOrEqual(0);
        expect(rule.confidence).toBeLessThanOrEqual(100);
        expect(Array.isArray(rule.falsepositives)).toBe(true);
        expect(rule.dataSource).toBeTruthy();
        expect(rule.generationMethod).toBeTruthy();
      }
    });
  });
});
