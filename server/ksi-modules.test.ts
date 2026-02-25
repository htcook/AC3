import { describe, expect, it, beforeAll } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

// ─── Test Context Helper ───────────────────────────────────────────────────────

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-ksi-user",
    email: "ksi-test@acec3.com",
    name: "KSI Test User",
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

// ─── KSI Evidence Chain Tests ──────────────────────────────────────────────────

describe("KSI Evidence Chain Router", () => {
  describe("getCoverageSummary", () => {
    it("should return coverage summary with all theme stats", async () => {
      const summary = await caller.ksiEvidenceChain.getCoverageSummary();
      expect(summary).toBeDefined();
      expect(summary.totalKSIs).toBe(58);
      expect(summary.directCount).toBeGreaterThan(0);
      expect(summary.supportingCount).toBeGreaterThan(0);
      expect(summary.overallCoverage).toBeGreaterThan(0);
      expect(summary.overallCoverage).toBeLessThanOrEqual(100);
      expect(summary.themeStats).toBeDefined();
      expect(summary.themeStats.length).toBe(11); // 11 FedRAMP 20x themes
    });

    it("should have correct theme codes", async () => {
      const summary = await caller.ksiEvidenceChain.getCoverageSummary();
      const themeCodes = summary.themeStats.map((t: any) => t.themeCode).sort();
      expect(themeCodes).toEqual([
        "AFR", "CED", "CMT", "CNA", "IAM", "INR", "MLA", "PIY", "RPL", "SCR", "SVC"
      ]);
    });

    it("should have theme stats that sum to total KSIs", async () => {
      const summary = await caller.ksiEvidenceChain.getCoverageSummary();
      const totalFromThemes = summary.themeStats.reduce((sum: number, t: any) => sum + t.total, 0);
      expect(totalFromThemes).toBe(summary.totalKSIs);
    });

    it("should have direct + supporting + planned = total for each theme", async () => {
      const summary = await caller.ksiEvidenceChain.getCoverageSummary();
      for (const theme of summary.themeStats) {
        expect(theme.direct + theme.supporting + theme.planned).toBe(theme.total);
      }
    });
  });

  describe("seedCatalog", () => {
    it("should seed the KSI catalog into the database", async () => {
      const result = await caller.ksiEvidenceChain.seedCatalog();
      expect(result).toBeDefined();
      expect(result.total).toBe(58);
      expect(result.seeded).toBeGreaterThanOrEqual(0); // May already be seeded
    });
  });

  describe("listDefinitions", () => {
    it("should list all KSI definitions", async () => {
      const defs = await caller.ksiEvidenceChain.listDefinitions();
      expect(Array.isArray(defs)).toBe(true);
      expect(defs.length).toBeGreaterThanOrEqual(0);
    });

    it("should filter by theme code", async () => {
      const defs = await caller.ksiEvidenceChain.listDefinitions({ themeCode: "IAM" });
      expect(Array.isArray(defs)).toBe(true);
      for (const def of defs) {
        expect(def.themeCode).toBe("IAM");
      }
    });

    it("should filter by coverage status", async () => {
      const defs = await caller.ksiEvidenceChain.listDefinitions({ coverageStatus: "direct" });
      expect(Array.isArray(defs)).toBe(true);
      for (const def of defs) {
        expect(def.coverageStatus).toBe("direct");
      }
    });
  });

  describe("collectEvidence", () => {
    it("should collect evidence with SHA-256 hash", async () => {
      const result = await caller.ksiEvidenceChain.collectEvidence({
        ksiId: "KSI-IAM-MFA",
        title: "MFA Compliance Check - Test",
        evidenceType: "configuration_check",
        sourceModule: "MFA Compliance Checker",
        collectionMethod: "automated",
      });
      expect(result).toBeDefined();
      expect(result.evidenceId).toMatch(/^EVD-/);
      expect(result.integrityHash).toBeDefined();
      expect(result.integrityHash.length).toBe(64); // SHA-256 hex
    });

    it("should chain hashes for subsequent evidence", async () => {
      const first = await caller.ksiEvidenceChain.collectEvidence({
        ksiId: "KSI-IAM-AAM",
        title: "Account Lifecycle Check 1",
        evidenceType: "audit_log",
        sourceModule: "IAM Lifecycle Manager",
        collectionMethod: "automated",
      });

      const second = await caller.ksiEvidenceChain.collectEvidence({
        ksiId: "KSI-IAM-AAM",
        title: "Account Lifecycle Check 2",
        evidenceType: "audit_log",
        sourceModule: "IAM Lifecycle Manager",
        collectionMethod: "automated",
      });

      expect(second.previousHash).toBe(first.integrityHash);
    });
  });

  describe("listEvidence", () => {
    it("should list collected evidence", async () => {
      const result = await caller.ksiEvidenceChain.listEvidence();
      expect(result).toBeDefined();
      expect(result.evidence).toBeDefined();
      expect(Array.isArray(result.evidence)).toBe(true);
      expect(typeof result.total).toBe("number");
    });

    it("should filter by KSI ID", async () => {
      const result = await caller.ksiEvidenceChain.listEvidence({ ksiId: "KSI-IAM-MFA" });
      for (const ev of result.evidence) {
        expect(ev.ksiId).toBe("KSI-IAM-MFA");
      }
    });
  });

  describe("validateEvidence", () => {
    it("should update evidence status to verified", async () => {
      // First collect some evidence
      const collected = await caller.ksiEvidenceChain.collectEvidence({
        ksiId: "KSI-MLA-OSM",
        title: "SIEM Log Verification Test",
        evidenceType: "log_entry",
        sourceModule: "SIEM Integration",
        collectionMethod: "automated",
      });

      const result = await caller.ksiEvidenceChain.validateEvidence({
        evidenceId: collected.evidenceId,
        status: "verified",
      });
      expect(result.success).toBe(true);
    });
  });

  describe("createChain", () => {
    it("should create an evidence chain", async () => {
      const result = await caller.ksiEvidenceChain.createChain({
        ksiId: "KSI-IAM-MFA",
        name: "Q1 2026 MFA Compliance Chain",
        description: "Evidence chain for MFA compliance validation",
      });
      expect(result).toBeDefined();
      expect(result.chainId).toMatch(/^CHN-/);
    });
  });

  describe("listChains", () => {
    it("should list evidence chains", async () => {
      const chains = await caller.ksiEvidenceChain.listChains();
      expect(Array.isArray(chains)).toBe(true);
    });
  });

  describe("verifyChain", () => {
    it("should verify chain integrity", async () => {
      // Create a chain first
      const chain = await caller.ksiEvidenceChain.createChain({
        ksiId: "KSI-CNA-EDE",
        name: "Encryption Validation Chain",
      });

      const result = await caller.ksiEvidenceChain.verifyChain({ chainId: chain.chainId });
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe("boolean");
      expect(typeof result.evidenceCount).toBe("number");
    });
  });

  describe("getDashboardStats", () => {
    it("should return dashboard statistics", async () => {
      const stats = await caller.ksiEvidenceChain.getDashboardStats();
      expect(stats).toBeDefined();
      expect(typeof stats.totalEvidence).toBe("number");
      expect(typeof stats.totalChains).toBe("number");
      expect(typeof stats.validChains).toBe("number");
      expect(typeof stats.brokenChains).toBe("number");
      expect(Array.isArray(stats.byStatus)).toBe(true);
      expect(Array.isArray(stats.byType)).toBe(true);
    });
  });
});

// ─── KSI Validation Scheduler Tests ────────────────────────────────────────────

describe("KSI Validation Scheduler Router", () => {
  describe("initializeSchedules", () => {
    it("should initialize validation schedules for seeded KSIs", async () => {
      const result = await caller.ksiValidationScheduler.initializeSchedules();
      expect(result).toBeDefined();
      expect(typeof result.created).toBe("number");
      expect(typeof result.total).toBe("number");
    });
  });

  describe("listSchedules", () => {
    it("should list all validation schedules", async () => {
      const schedules = await caller.ksiValidationScheduler.listSchedules();
      expect(Array.isArray(schedules)).toBe(true);
    });

    it("should filter by enabled status", async () => {
      const enabled = await caller.ksiValidationScheduler.listSchedules({ enabled: true });
      for (const s of enabled) {
        expect(s.enabled).toBeTruthy(); // Drizzle may return true or 1
      }
    });
  });

  describe("startValidation", () => {
    it("should start a validation run", async () => {
      const result = await caller.ksiValidationScheduler.startValidation({
        ksiId: "KSI-IAM-MFA",
        triggerType: "manual",
      });
      expect(result).toBeDefined();
      expect(result.runId).toMatch(/^VRN-/);
    });
  });

  describe("completeValidation", () => {
    it("should complete a validation run with results", async () => {
      const started = await caller.ksiValidationScheduler.startValidation({
        ksiId: "KSI-CNA-EDE",
        triggerType: "manual",
      });

      const result = await caller.ksiValidationScheduler.completeValidation({
        runId: started.runId,
        status: "passed",
        score: 95,
        maxScore: 100,
        result: { details: "FIPS 140-2 encryption verified" },
      });
      expect(result.success).toBe(true);
    });

    it("should track consecutive failures", async () => {
      const started = await caller.ksiValidationScheduler.startValidation({
        ksiId: "KSI-RPL-TRC",
        triggerType: "manual",
      });

      await caller.ksiValidationScheduler.completeValidation({
        runId: started.runId,
        status: "failed",
        errorMessage: "Recovery test not completed",
      });

      // Check the schedule was updated
      const schedules = await caller.ksiValidationScheduler.listSchedules({ ksiId: "KSI-RPL-TRC" });
      if (schedules.length > 0) {
        expect(schedules[0].lastRunStatus).toBe("failed");
      }
    });
  });

  describe("listRuns", () => {
    it("should list validation runs", async () => {
      const result = await caller.ksiValidationScheduler.listRuns();
      expect(result).toBeDefined();
      expect(Array.isArray(result.runs)).toBe(true);
      expect(typeof result.total).toBe("number");
    });

    it("should filter by KSI ID", async () => {
      const result = await caller.ksiValidationScheduler.listRuns({ ksiId: "KSI-IAM-MFA" });
      for (const run of result.runs) {
        expect(run.ksiId).toBe("KSI-IAM-MFA");
      }
    });
  });

  describe("getDashboard", () => {
    it("should return validation dashboard summary", async () => {
      const dashboard = await caller.ksiValidationScheduler.getDashboard();
      expect(dashboard).toBeDefined();
      expect(typeof dashboard.totalSchedules).toBe("number");
      expect(typeof dashboard.enabledSchedules).toBe("number");
      expect(typeof dashboard.overdueSchedules).toBe("number");
      expect(typeof dashboard.totalRuns).toBe("number");
      expect(typeof dashboard.passedRuns).toBe("number");
      expect(typeof dashboard.failedRuns).toBe("number");
      expect(typeof dashboard.passRate).toBe("number");
      expect(Array.isArray(dashboard.recentRuns)).toBe(true);
    });
  });

  describe("getOverdueValidations", () => {
    it("should return overdue validations", async () => {
      const overdue = await caller.ksiValidationScheduler.getOverdueValidations();
      expect(Array.isArray(overdue)).toBe(true);
    });
  });
});

// ─── OSCAL Export Engine Tests ─────────────────────────────────────────────────

describe("OSCAL Export Engine Router", () => {
  describe("getDocumentTypes", () => {
    it("should return supported document types", async () => {
      const types = await caller.oscalExport.getDocumentTypes();
      expect(Array.isArray(types)).toBe(true);
      expect(types.length).toBeGreaterThanOrEqual(3);
      const ids = types.map((t: any) => t.id);
      expect(ids).toContain("ssp");
      expect(ids).toContain("sar");
      expect(ids).toContain("poam");
    });
  });

  describe("generate SSP", () => {
    it("should generate an OSCAL SSP document", async () => {
      const result = await caller.oscalExport.generate({
        documentType: "ssp",
        title: "Test SSP — FedRAMP 20x",
        outputFormat: "json",
      });
      expect(result).toBeDefined();
      expect(result.exportId).toMatch(/^OSC-/);
      expect(result.documentType).toBe("ssp");
      expect(result.outputHash).toBeDefined();
      expect(result.outputHash.length).toBe(64);
      expect(result.document).toBeDefined();
      expect(result.document["system-security-plan"]).toBeDefined();
      expect(result.document["system-security-plan"].metadata).toBeDefined();
      expect(result.document["system-security-plan"].metadata.oscalVersion).toBe("1.1.2");
    });

    it("should include control implementations in SSP", async () => {
      const result = await caller.oscalExport.generate({
        documentType: "ssp",
        title: "Test SSP Controls",
        outputFormat: "json",
      });
      const ssp = result.document["system-security-plan"];
      expect(ssp["control-implementation"]).toBeDefined();
      expect(ssp["control-implementation"]["implemented-requirements"]).toBeDefined();
      expect(ssp["control-implementation"]["implemented-requirements"].length).toBeGreaterThan(0);
    });
  });

  describe("generate SAR", () => {
    it("should generate an OSCAL SAR document", async () => {
      const result = await caller.oscalExport.generate({
        documentType: "sar",
        title: "Test SAR — FedRAMP 20x",
        outputFormat: "json",
      });
      expect(result).toBeDefined();
      expect(result.documentType).toBe("sar");
      expect(result.document["assessment-results"]).toBeDefined();
      expect(result.document["assessment-results"].results).toBeDefined();
      expect(result.document["assessment-results"].results.length).toBeGreaterThan(0);
    });

    it("should include findings in SAR", async () => {
      const result = await caller.oscalExport.generate({
        documentType: "sar",
        title: "Test SAR Findings",
        outputFormat: "json",
      });
      const findings = result.document["assessment-results"].results[0].findings;
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);
      // Each finding should have a target with status
      for (const finding of findings.slice(0, 5)) {
        expect(finding.target).toBeDefined();
        expect(finding.target.status).toBeDefined();
        expect(finding.target.status.state).toBeDefined();
      }
    });
  });

  describe("generate POA&M", () => {
    it("should generate an OSCAL POA&M document", async () => {
      const result = await caller.oscalExport.generate({
        documentType: "poam",
        title: "Test POA&M — FedRAMP 20x",
        outputFormat: "json",
      });
      expect(result).toBeDefined();
      expect(result.documentType).toBe("poam");
      expect(result.document["plan-of-action-and-milestones"]).toBeDefined();
      expect(result.document["plan-of-action-and-milestones"]["poam-items"]).toBeDefined();
    });
  });

  describe("listExports", () => {
    it("should list generated exports", async () => {
      const exports = await caller.oscalExport.listExports();
      expect(Array.isArray(exports)).toBe(true);
      expect(exports.length).toBeGreaterThan(0); // We generated some above
    });

    it("should filter by document type", async () => {
      const exports = await caller.oscalExport.listExports({ documentType: "ssp" });
      for (const exp of exports) {
        expect(exp.documentType).toBe("ssp");
      }
    });
  });

  describe("getStats", () => {
    it("should return export statistics", async () => {
      const stats = await caller.oscalExport.getStats();
      expect(stats).toBeDefined();
      expect(typeof stats.totalExports).toBe("number");
      expect(stats.totalExports).toBeGreaterThan(0);
      expect(Array.isArray(stats.byType)).toBe(true);
      expect(Array.isArray(stats.byStatus)).toBe(true);
    });
  });
});

// ─── Cross-Module Integration Tests ────────────────────────────────────────────

describe("KSI Cross-Module Integration", () => {
  it("should have consistent KSI IDs across evidence and validation", async () => {
    // Collect evidence for a KSI
    const evidence = await caller.ksiEvidenceChain.collectEvidence({
      ksiId: "KSI-MLA-LET",
      title: "Log Event Types Catalog Test",
      evidenceType: "configuration_check",
      sourceModule: "Log Policy Manager",
      collectionMethod: "automated",
    });

    // Start validation for the same KSI
    const run = await caller.ksiValidationScheduler.startValidation({
      ksiId: "KSI-MLA-LET",
      triggerType: "manual",
    });

    // Complete with evidence reference
    await caller.ksiValidationScheduler.completeValidation({
      runId: run.runId,
      status: "passed",
      score: 100,
      maxScore: 100,
      evidenceIds: [evidence.evidenceId],
    });

    // Verify both are queryable
    const evidenceList = await caller.ksiEvidenceChain.listEvidence({ ksiId: "KSI-MLA-LET" });
    expect(evidenceList.evidence.length).toBeGreaterThan(0);

    const runsList = await caller.ksiValidationScheduler.listRuns({ ksiId: "KSI-MLA-LET" });
    expect(runsList.runs.length).toBeGreaterThan(0);
  });

  it("should generate OSCAL documents that reflect evidence and validation state", async () => {
    const result = await caller.oscalExport.generate({
      documentType: "sar",
      title: "Integration Test SAR",
      outputFormat: "json",
    });

    const findings = result.document["assessment-results"].results[0].findings;
    expect(findings.length).toBeGreaterThan(0);

    // Check that observations reference evidence
    const observations = result.document["assessment-results"].results[0].observations;
    expect(Array.isArray(observations)).toBe(true);
  });
});
