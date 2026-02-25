import { describe, expect, it, beforeAll } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

// ─── Test Context Helper ───────────────────────────────────────────────────────
type AuthenticatedUser = NonNullable<TrpcContext["user"]>;
function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-wave2-user",
    email: "wave2-test@acec3.com",
    name: "Wave2 Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };
  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

const caller = appRouter.createCaller(createAuthContext());

// =============================================================================
// KSI Auto-Collector Tests
// =============================================================================
describe("KSI Auto-Collector", () => {
  describe("getSourceMappings", () => {
    it("should return all source-to-KSI mappings", async () => {
      const mappings = await caller.ksiAutoCollector.getSourceMappings();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings.length).toBeGreaterThan(0);
      // Each mapping should have required fields
      for (const m of mappings) {
        expect(m.sourceModule).toBeDefined();
        expect(m.evidenceType).toBeDefined();
        expect(Array.isArray(m.ksiIds)).toBe(true);
        expect(m.ksiIds.length).toBeGreaterThan(0);
        expect(m.description).toBeDefined();
      }
    });

    it("should include vuln-scanner and web-app-scanning sources", async () => {
      const mappings = await caller.ksiAutoCollector.getSourceMappings();
      const sourceNames = mappings.map((m: any) => m.sourceModule);
      expect(sourceNames).toContain("vuln-scanner");
      expect(sourceNames).toContain("web-app-scanning");
      expect(sourceNames).toContain("osint-recon");
      expect(sourceNames).toContain("phishing-ops");
      expect(sourceNames).toContain("edr-validation");
    });
  });

  describe("getCollectionStats", () => {
    it("should return collection statistics", async () => {
      const stats = await caller.ksiAutoCollector.getCollectionStats();
      expect(typeof stats.totalEvidence).toBe("number");
      expect(typeof stats.autoCollected).toBe("number");
      expect(typeof stats.manualCollected).toBe("number");
      expect(typeof stats.sourceMappingCount).toBe("number");
      expect(Array.isArray(stats.bySource)).toBe(true);
    });
  });

  describe("collectFromVulnScanner", () => {
    it("should collect evidence from vuln scanner findings", async () => {
      const result = await caller.ksiAutoCollector.collectFromVulnScanner();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("vuln-scanner");
    });
  });

  describe("collectFromWebAppScanner", () => {
    it("should collect evidence from web app scanner", async () => {
      const result = await caller.ksiAutoCollector.collectFromWebAppScanner();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("web-app-scanning");
    });
  });

  describe("collectFromOsint", () => {
    it("should collect evidence from OSINT findings", async () => {
      const result = await caller.ksiAutoCollector.collectFromOsint();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("osint-recon");
    });
  });

  describe("collectFromPhishing", () => {
    it("should collect evidence from phishing operations", async () => {
      const result = await caller.ksiAutoCollector.collectFromPhishing();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("phishing-ops");
    });
  });

  describe("collectFromEdr", () => {
    it("should collect evidence from EDR validation", async () => {
      const result = await caller.ksiAutoCollector.collectFromEdr();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("edr-validation");
    });
  });

  describe("collectFromNgfw", () => {
    it("should collect evidence from NGFW validation", async () => {
      const result = await caller.ksiAutoCollector.collectFromNgfw();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("ngfw-validation");
    });
  });

  describe("collectFromAdAttackSim", () => {
    it("should collect evidence from AD attack simulations", async () => {
      const result = await caller.ksiAutoCollector.collectFromAdAttackSim();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("ad-attack-sim");
    });
  });

  describe("collectFromCloudMisconfigs", () => {
    it("should collect evidence from cloud misconfigurations", async () => {
      const result = await caller.ksiAutoCollector.collectFromCloudMisconfigs();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("cloud-misconfigs");
    });
  });

  describe("collectFromAtomicRedTeam", () => {
    it("should collect evidence from Atomic Red Team tests", async () => {
      const result = await caller.ksiAutoCollector.collectFromAtomicRedTeam();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("atomic-red-team");
    });
  });

  describe("collectFromThreatIntel", () => {
    it("should collect evidence from threat intel feeds", async () => {
      const result = await caller.ksiAutoCollector.collectFromThreatIntel();
      expect(typeof result.collected).toBe("number");
      expect(result.collected).toBeGreaterThanOrEqual(0);
      expect(result.source).toBe("threat-intel");
    });
  });

  describe("runFullCollection", () => {
    it("should run full collection sweep across all sources", async () => {
      const result = await caller.ksiAutoCollector.runFullCollection();
      expect(typeof result.totalCollected).toBe("number");
      expect(Array.isArray(result.results)).toBe(true);
      expect(result.results.length).toBeGreaterThan(0);
      expect(result.sweepTime).toBeDefined();
      for (const r of result.results) {
        expect(r.source).toBeDefined();
        expect(typeof r.collected).toBe("number");
      }
    });
  });
});

// =============================================================================
// KSI Threat Map Tests
// =============================================================================
describe("KSI Threat Map", () => {
  describe("getTtpMappings", () => {
    it("should return TTP mappings for all KSIs", async () => {
      const mappings = await caller.ksiThreatMap.getTtpMappings();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings.length).toBeGreaterThan(0);
      for (const m of mappings) {
        expect((m as any).ksiId).toBeDefined();
        expect(Array.isArray((m as any).techniques)).toBe(true);
        expect((m as any).techniques.length).toBeGreaterThan(0);
        expect((m as any).description).toBeDefined();
        // Each technique should have id, name, tactic
        for (const t of (m as any).techniques) {
          expect(t.id).toBeDefined();
          expect(t.name).toBeDefined();
          expect(t.tactic).toBeDefined();
        }
      }
    });

    it("should include diverse ATT&CK tactics", async () => {
      const mappings = await caller.ksiThreatMap.getTtpMappings();
      // Each mapping has a techniques array with tactic fields
      const tactics = new Set<string>();
      for (const m of mappings) {
        for (const t of (m as any).techniques || []) {
          tactics.add(t.tactic);
        }
      }
      // Should cover multiple tactics across the kill chain
      expect(tactics.size).toBeGreaterThanOrEqual(5);
    });
  });

  describe("getThreatGroupMappings", () => {
    it("should return threat group to KSI mappings", async () => {
      const groups = await caller.ksiThreatMap.getThreatGroupMappings();
      expect(Array.isArray(groups)).toBe(true);
      expect(groups.length).toBeGreaterThan(0);
      for (const g of groups) {
        expect(g.groupId).toBeDefined();
        expect(g.groupName).toBeDefined();
        expect(g.type).toBeDefined();
        expect(g.origin).toBeDefined();
        expect(Array.isArray(g.ksiIds)).toBe(true);
        expect(Array.isArray(g.primaryTechniques)).toBe(true);
      }
    });

    it("should include diverse threat group origins", async () => {
      const groups = await caller.ksiThreatMap.getThreatGroupMappings();
      const origins = Array.from(new Set(groups.map((g: any) => g.origin)));
      expect(origins.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("getThreatCoverageMatrix", () => {
    it("should return coverage matrix with summary stats", async () => {
      const coverage = await caller.ksiThreatMap.getThreatCoverageMatrix();
      expect(coverage.summary).toBeDefined();
      expect(typeof coverage.summary.totalKsisWithTtps).toBe("number");
      expect(typeof coverage.summary.totalTechniques).toBe("number");
      expect(typeof coverage.summary.totalThreatGroups).toBe("number");
      expect(Array.isArray(coverage.summary.tacticDistribution)).toBe(true);
      expect(Array.isArray(coverage.matrix)).toBe(true);
    });

    it("should have matrix entries with technique and threat group counts", async () => {
      const coverage = await caller.ksiThreatMap.getThreatCoverageMatrix();
      for (const entry of coverage.matrix) {
        expect(entry.ksiId).toBeDefined();
        expect(entry.ksiTitle).toBeDefined();
        expect(typeof entry.techniqueCount).toBe("number");
        expect(typeof entry.threatGroupCount).toBe("number");
        expect(Array.isArray(entry.techniques)).toBe(true);
        expect(Array.isArray(entry.threatGroups)).toBe(true);
      }
    });
  });

  describe("getExploitCoverageSummary", () => {
    it("should return exploit coverage summary", async () => {
      const summary = await caller.ksiThreatMap.getExploitCoverageSummary();
      expect(typeof summary.totalExploitsWithMitre).toBe("number");
      expect(typeof summary.totalAtomicTests).toBe("number");
      expect(typeof summary.ksisWithExploits).toBe("number");
      expect(typeof summary.ksisWithoutExploits).toBe("number");
      expect(Array.isArray(summary.ksiExploitCoverage)).toBe(true);
    });

    it("should have coverage entries with exploit and atomic test counts", async () => {
      const summary = await caller.ksiThreatMap.getExploitCoverageSummary();
      for (const entry of summary.ksiExploitCoverage) {
        expect(entry.ksiId).toBeDefined();
        expect(typeof entry.techniqueCount).toBe("number");
        expect(typeof entry.exploitCount).toBe("number");
        expect(typeof entry.atomicTestCount).toBe("number");
        expect(typeof entry.hasValidationTools).toBe("boolean");
      }
    });
  });

  describe("getExploitsForKsi", () => {
    it("should return exploits and atomic tests for a given KSI", async () => {
      // Use KSI-VM-SBV which is the full KSI ID format in the catalog
      const mappings = await caller.ksiThreatMap.getTtpMappings();
      const firstKsi = (mappings as any[])[0]?.ksiId;
      const result = await caller.ksiThreatMap.getExploitsForKsi({ ksiId: firstKsi });
      expect(result.ksiId).toBe(firstKsi);
      expect(Array.isArray(result.exploits)).toBe(true);
      expect(Array.isArray(result.atomicTests)).toBe(true);
      expect(typeof result.totalExploits).toBe("number");
      expect(typeof result.totalAtomicTests).toBe("number");
    });
  });

  describe("getKsiThreatReport", () => {
    it("should return a comprehensive threat report for a KSI", async () => {
      const mappings = await caller.ksiThreatMap.getTtpMappings();
      const firstKsi = (mappings as any[])[0]?.ksiId;
      const report = await caller.ksiThreatMap.getKsiThreatReport({ ksiId: firstKsi });
      expect(report.ksiId).toBe(firstKsi);
      expect(report.ksiTitle).toBeDefined();
      expect(typeof report.riskScore).toBe("number");
      expect(typeof report.exploitCount).toBe("number");
      expect(typeof report.atomicTestCount).toBe("number");
      expect(Array.isArray(report.techniques)).toBe(true);
      expect(Array.isArray(report.threatGroups)).toBe(true);
      expect(report.hasTtpMapping).toBe(true);
    });
  });
});

// =============================================================================
// Configuration Baseline Engine Tests
// =============================================================================
describe("Configuration Baseline Engine", () => {
  let testBaselineId: string;

  describe("getRuleCatalog", () => {
    it("should return the built-in CIS rule catalog", async () => {
      const result = await caller.configBaseline.getRuleCatalog();
      expect(result.rules).toBeDefined();
      expect(Array.isArray(result.rules)).toBe(true);
      expect(result.rules.length).toBeGreaterThan(0);
      expect(result.totalRules).toBeGreaterThan(0);
      expect(Array.isArray(result.platforms)).toBe(true);
      expect(Array.isArray(result.benchmarks)).toBe(true);
      for (const r of result.rules) {
        expect(r.ruleId).toBeDefined();
        expect(r.title).toBeDefined();
        expect(r.benchmark).toBeDefined();
        expect(r.severity).toBeDefined();
        expect(r.platform).toBeDefined();
      }
    });

    it("should include rules mapped to KSIs and MITRE techniques", async () => {
      const result = await caller.configBaseline.getRuleCatalog();
      const withKsi = result.rules.filter((r: any) => r.ksiIds && r.ksiIds.length > 0);
      const withMitre = result.rules.filter((r: any) => r.mitreIds && r.mitreIds.length > 0);
      expect(withKsi.length).toBeGreaterThan(0);
      expect(withMitre.length).toBeGreaterThan(0);
    });
  });

  describe("createBaseline", () => {
    it("should create a new configuration baseline", async () => {
      const result = await caller.configBaseline.createBaseline({
        name: "Test Linux Baseline",
        description: "Test baseline for vitest",
        platform: "aws",
        benchmark: "CIS",
        ruleIds: ["CIS-AWS-1.4", "CIS-AWS-1.5", "CIS-AWS-1.10"],
      });
      expect(result.baselineId).toBeDefined();
      expect(result.ruleCount).toBe(3);
      testBaselineId = result.baselineId;
    });
  });

  describe("listBaselines", () => {
    it("should list all baselines including the one just created", async () => {
      const baselines = await caller.configBaseline.listBaselines();
      expect(Array.isArray(baselines)).toBe(true);
      expect(baselines.length).toBeGreaterThan(0);
      const found = baselines.find((b: any) => b.baselineId === testBaselineId);
      expect(found).toBeDefined();
    });
  });

  describe("runScan", () => {
    it("should run a baseline scan and return results", async () => {
      const result = await caller.configBaseline.runScan({
        baselineId: testBaselineId,
        targetName: "test-server-01",
        targetType: "aws-account",
      });
      expect(result.scanId).toBeDefined();
      expect(typeof result.passed).toBe("number");
      expect(typeof result.failed).toBe("number");
      expect(typeof result.totalRules).toBe("number");
      expect(result.totalRules).toBeGreaterThan(0);
      expect(typeof result.complianceScore).toBe("number");
    });
  });

  describe("listScanResults", () => {
    it("should return scan results for a baseline after scan", async () => {
      const results = await caller.configBaseline.listScanResults({
        baselineId: testBaselineId,
      });
      expect(Array.isArray(results)).toBe(true);
      // Results should exist after the scan above
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.ruleId).toBeDefined();
        expect(["pass", "fail", "warning", "error"]).toContain(r.status);
      }
    });
  });

  describe("listDriftAlerts", () => {
    it("should return drift alerts", async () => {
      const alerts = await caller.configBaseline.listDriftAlerts({});
      expect(Array.isArray(alerts)).toBe(true);
      // May or may not have alerts depending on scan results
    });
  });

  describe("updateDriftAlert", () => {
    it("should update drift alert status if alerts exist", async () => {
      const alerts = await caller.configBaseline.listDriftAlerts({});
      if (alerts.length > 0) {
        const result = await caller.configBaseline.updateDriftAlert({
          alertId: alerts[0].alertId,
          status: "acknowledged",
        });
        expect(result.success).toBe(true);
      }
    });
  });
});
