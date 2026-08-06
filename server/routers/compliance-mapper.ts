import * as db from "../db";
/**
 * Compliance Framework Mapping Router
 * Manages compliance frameworks (SOC 2, ISO 27001, NIST CSF, PCI DSS, FedRAMP, DoD STIG, CMMC),
 * control mappings, gap analysis, and compliance report generation.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  ALL_FRAMEWORKS,
  autoMapFindings,
  calculateComplianceScore,
} from "../lib/compliance-mapper";
import {
  mapEngagementToCompliance,
  getSupportedFrameworks,
  getMappingRules,
  type EvidenceMapperResult,
} from "../lib/compliance-evidence-mapper";
import {
  mapVulnToFrameworks,
  generateComplianceReport,
  getAvailableFrameworks,
  inferCweFromFinding,
  type FrameworkId,
  type ComplianceReport,
  FRAMEWORK_METADATA,
} from "../lib/compliance-framework-mapping";

const frameworkTypeEnum = z.enum(["soc2", "iso27001", "nist_csf", "pci_dss", "hipaa", "cis", "fedramp", "dod_stig", "cmmc", "custom"]);

export const complianceMapperRouter = router({
  /** Get all built-in framework definitions */
  getFrameworkCatalog: protectedProcedure.query(() => {
    return Object.entries(ALL_FRAMEWORKS).map(([key, fw]) => ({
      key,
      name: fw.name,
      version: fw.version,
      controlCount: fw.controls.length,
    }));
  }),

  /** Get controls for a specific built-in framework */
  getFrameworkControls: protectedProcedure
    .input(z.object({ frameworkKey: z.string() }))
    .query(({ input }) => {
      const fw = ALL_FRAMEWORKS[input.frameworkKey as keyof typeof ALL_FRAMEWORKS];
      if (!fw) throw new TRPCError({ code: "NOT_FOUND", message: "Framework not found" });
      return { name: fw.name, version: fw.version, controls: fw.controls };
    }),

  /** Auto-map findings to a framework */
  autoMap: protectedProcedure
    .input(z.object({
      frameworkKey: z.enum(["soc2", "iso27001", "nist_csf", "pci_dss", "fedramp", "dod_stig", "cmmc"]),
      findings: z.array(z.object({
        type: z.string(),
        severity: z.string(),
        category: z.string(),
      })),
    }))
    .mutation(({ input }) => {
      const mappings = autoMapFindings(input.frameworkKey, input.findings);
      const score = calculateComplianceScore(mappings);
      return { mappings, score };
    }),

  /** List configured frameworks from database */
  listFrameworks: protectedProcedure
    .input(z.object({ activeOnly: z.boolean().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceFrameworks } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      const query = input?.activeOnly
        ? db.select().from(complianceFrameworks).where(eq(complianceFrameworks.isActive, true))
        : db.select().from(complianceFrameworks);
      return await query;
    }),

  /** Add a framework configuration to the database */
  addFramework: protectedProcedure
    .input(z.object({
      frameworkName: z.string(),
      frameworkVersion: z.string().optional(),
      frameworkType: frameworkTypeEnum,
      description: z.string().optional(),
      totalControls: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceFrameworks } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(complianceFrameworks).values({
        frameworkName: input.frameworkName,
        frameworkVersion: input.frameworkVersion ?? null,
        frameworkType: input.frameworkType,
        description: input.description ?? null,
        totalControls: input.totalControls ?? null,
      });
      return { id: result.insertId, success: true };
    }),

  /** List compliance mappings for an engagement */
  listMappings: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      controlId: z.number().optional(),
      status: z.enum(["covered", "gap", "partial", "not_applicable", "compensating"]).optional(),
    }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceMappings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and } = await import("drizzle-orm");

      const conditions = [];
      if (input.engagementId) conditions.push(eq(complianceMappings.engagementId, input.engagementId));
      if (input.controlId) conditions.push(eq(complianceMappings.controlId, input.controlId));
      if (input.status) conditions.push(eq(complianceMappings.mappingStatus, input.status));

      return conditions.length > 0
        ? await db.select().from(complianceMappings).where(and(...conditions))
        : await db.select().from(complianceMappings);
    }),

  /** Create a compliance mapping */
  createMapping: protectedProcedure
    .input(z.object({
      controlId: z.number(),
      engagementId: z.number().optional(),
      findingType: z.string().optional(),
      findingId: z.number().optional(),
      findingSource: z.enum(["vulnerability", "misconfiguration", "attack_path", "edr_test", "pentest", "manual"]),
      mappingStatus: z.enum(["covered", "gap", "partial", "not_applicable", "compensating"]),
      evidenceNotes: z.string().optional(),
      compensatingControl: z.string().optional(),
      assessedBy: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { complianceMappings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [result] = await db.insert(complianceMappings).values({
        controlId: input.controlId,
        engagementId: input.engagementId ?? null,
        findingType: input.findingType ?? null,
        findingId: input.findingId ?? null,
        findingSource: input.findingSource,
        mappingStatus: input.mappingStatus,
        evidenceNotes: input.evidenceNotes ?? null,
        compensatingControl: input.compensatingControl ?? null,
        assessedBy: input.assessedBy ?? ctx.user.name ?? null,
        assessedAt: new Date(),
      });
      return { id: result.insertId, success: true };
    }),

  /** List compliance reports */
  listReports: protectedProcedure
    .input(z.object({ engagementId: z.number().optional(), frameworkId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { complianceReports } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and, desc } = await import("drizzle-orm");

      const conditions = [];
      if (input?.engagementId) conditions.push(eq(complianceReports.engagementId, input.engagementId));
      if (input?.frameworkId) conditions.push(eq(complianceReports.frameworkId, input.frameworkId));

      return conditions.length > 0
        ? await db.select().from(complianceReports).where(and(...conditions)).orderBy(desc(complianceReports.createdAt))
        : await db.select().from(complianceReports).orderBy(desc(complianceReports.createdAt));
    }),

  /** Generate a compliance report */
  generateReport: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      frameworkId: z.number(),
      reportName: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { complianceMappings, complianceReports } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, and } = await import("drizzle-orm");

      // Get all mappings for this engagement and framework's controls
      const mappings = await db.select().from(complianceMappings)
        .where(eq(complianceMappings.engagementId, input.engagementId));

      const score = calculateComplianceScore(mappings.map(m => ({ status: m.mappingStatus })));

      const [result] = await db.insert(complianceReports).values({
        engagementId: input.engagementId,
        frameworkId: input.frameworkId,
        reportName: input.reportName,
        totalControls: score.covered + score.gap + score.partial + score.na,
        coveredControls: score.covered,
        gapControls: score.gap,
        partialControls: score.partial,
        naControls: score.na,
        overallScore: score.score,
        reportData: { mappings, score },
        generatedBy: ctx.user.name ?? ctx.user.openId,
      });
      return { id: result.insertId, score, success: true };
    }),

  /** Map an engagement's scan results to compliance evidence (manual trigger) */
  mapFromEngagement: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No ops state found for this engagement" });

      const mappingState = {
        engagementId: input.engagementId,
        assets: state.assets.map(a => ({
          hostname: a.hostname || (a as any).ip || 'unknown',
          ip: a.ip,
          vulns: (a.vulns || []).map(v => ({
            title: v.title || 'Unknown',
            severity: v.severity || 'info',
            description: (v as any).description,
            tool: (v as any).tool,
            cve: v.cve,
            rawOutput: (v as any).rawOutput,
          })),
          ports: (a.ports || []).map(p => ({
            port: p.port,
            service: p.service,
            protocol: (p as any).protocol,
          })),
          toolResults: (a.toolResults || []).map(tr => ({
            tool: tr.tool,
            command: tr.command,
            exitCode: tr.exitCode,
            findingCount: tr.findingCount,
            outputPreview: tr.outputPreview,
            findings: (tr.findings || []).map(f => ({ title: f.title, severity: f.severity })),
          })),
          zapFindings: (a.zapFindings || []).map(z => ({
            alert: z.alert,
            risk: z.risk,
            description: (z as any).description,
            url: z.url,
            evidence: (z as any).evidence,
          })),
        })),
      };
      const result = mapEngagementToCompliance(mappingState);

      // Persist to DB
      const { getDb } = await import('../db');
      const { complianceMappings } = await import('../../drizzle/schema');
      const dbConn = await getDb();
      let insertedCount = 0;
      if (dbConn && result.evidence.length > 0) {
        const batchSize = 50;
        for (let i = 0; i < result.evidence.length; i += batchSize) {
          const batch = result.evidence.slice(i, i + batchSize);
          try {
            await dbConn.insert(complianceMappings).values(
              batch.map(e => ({
                controlId: 0,
                engagementId: input.engagementId,
                findingType: e.evidenceType,
                findingSource: 'pentest' as const,
                mappingStatus: e.status === 'pass' ? 'covered' as const :
                               e.status === 'fail' ? 'gap' as const :
                               e.status === 'partial' ? 'partial' as const : 'gap' as const,
                evidenceNotes: `[Auto-mapped] ${e.framework} ${e.controlId}: ${e.description}`.slice(0, 2000),
                assessedBy: ctx.user.name ?? 'AC3 Compliance Engine',
                assessedAt: new Date(),
              }))
            );
            insertedCount += batch.length;
          } catch (batchErr: any) {
            console.error(`[ComplianceMapper] Batch insert failed:`, batchErr.message);
          }
        }
      }
      return {
        totalEvidenceItems: result.totalEvidenceItems,
        frameworksCovered: result.frameworksCovered,
        gapCount: result.gapCount,
        insertedCount,
        summaries: result.summaries.map(s => ({
          framework: s.framework,
          complianceScore: s.complianceScore,
          compliant: s.compliant,
          nonCompliant: s.nonCompliant,
          partial: s.partial,
          noEvidence: s.noEvidence,
          totalControls: s.totalControls,
        })),
      };
    }),

  /** Get engagement compliance evidence from ops state */
  getEngagementEvidence: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) return null;
      return (state as any).complianceEvidence ?? null;
    }),

  /** Get supported frameworks from the evidence mapper */
  getEvidenceMapperFrameworks: protectedProcedure.query(() => {
    return getSupportedFrameworks();
  }),

  /** Get mapping rules for transparency */
  getMappingRules: protectedProcedure.query(() => {
    return getMappingRules();
  }),

  // ─── CWE-Based Framework Mapping (Vuln Scan + DI Scan) ────────────────────

  /** Get available CWE-based compliance frameworks with metadata */
  getCweFrameworks: protectedProcedure.query(() => {
    return getAvailableFrameworks();
  }),

  /** Map engagement vuln scan results to selected compliance frameworks using CWE-based mapping */
  mapVulnScanToFrameworks: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      frameworks: z.array(z.enum(['nist_800_53', 'cis_v8', 'pci_dss_v4', 'iso_27001', 'hipaa', 'soc2'])),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found for this engagement' });

      // Collect all vulns from all assets
      const vulns: Array<{ id: string; title: string; cwe?: string; cveIds?: string[]; category?: string; severity: string }> = [];
      for (const asset of state.assets || []) {
        for (const v of asset.vulns || []) {
          vulns.push({
            id: `${asset.hostname}-${v.title}-${v.source || 'unknown'}`,
            title: v.title || 'Unknown',
            cwe: (v as any).cwe || undefined,
            cveIds: v.cve ? [v.cve] : undefined,
            category: (v as any).category || v.source || undefined,
            severity: v.severity || 'info',
          });
        }
        // Also include ZAP findings
        for (const z of asset.zapFindings || []) {
          vulns.push({
            id: `${asset.hostname}-zap-${z.alert}`,
            title: z.alert || 'Unknown',
            cwe: (z as any).cweid ? `CWE-${(z as any).cweid}` : undefined,
            category: 'DAST',
            severity: z.risk || 'info',
          });
        }
        // Include Burp findings
        for (const b of (asset as any).burpFindings || []) {
          vulns.push({
            id: `${asset.hostname}-burp-${b.name || b.title}`,
            title: b.name || b.title || 'Unknown',
            cwe: b.cwe ? `CWE-${b.cwe}` : undefined,
            category: 'DAST',
            severity: b.severity || 'info',
          });
        }
      }

      const report = generateComplianceReport(vulns, input.frameworks as FrameworkId[]);
      return report;
    }),

  /** Map DI scan posture findings to selected compliance frameworks */
  mapDiScanToFrameworks: protectedProcedure
    .input(z.object({
      domainId: z.number(),
      frameworks: z.array(z.enum(['nist_800_53', 'cis_v8', 'pci_dss_v4', 'iso_27001', 'hipaa', 'soc2'])),
    }))
    .mutation(async ({ input }) => {
      // Load DI scan results from DB
      const { getDb } = await import('../db');
      const dbConn = await getDb();
      if (!dbConn) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });

      const { diScanResults } = await import('../../drizzle/schema');
      const { eq, desc } = await import('drizzle-orm');

      // Get the latest scan result for this domain
      const [latestScan] = await dbConn.select().from(diScanResults)
        .where(eq(diScanResults.domainId, input.domainId))
        .orderBy(desc(diScanResults.createdAt))
        .limit(1);

      if (!latestScan) throw new TRPCError({ code: 'NOT_FOUND', message: 'No DI scan results found for this domain' });

      // Extract posture findings from the scan result
      const scanData = latestScan.resultData as any;
      const postureFindings = scanData?.postureFindings || scanData?.findings || [];

      const vulns = postureFindings.map((f: any, idx: number) => ({
        id: f.id || `di-${input.domainId}-${idx}`,
        title: f.title || f.name || 'Unknown',
        cwe: f.cwe || undefined,
        cveIds: f.cveIds || (f.cve ? [f.cve] : undefined),
        category: f.category || 'posture',
        severity: typeof f.severity === 'number' ? String(f.severity) : (f.severity || 'info'),
      }));

      const report = generateComplianceReport(vulns, input.frameworks as FrameworkId[]);
      return report;
    }),

  /** Map arbitrary findings (manual input) to selected frameworks */
  mapFindingsToFrameworks: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        id: z.string(),
        title: z.string(),
        cwe: z.string().optional(),
        cveIds: z.array(z.string()).optional(),
        category: z.string().optional(),
        severity: z.string(),
      })),
      frameworks: z.array(z.enum(['nist_800_53', 'cis_v8', 'pci_dss_v4', 'iso_27001', 'hipaa', 'soc2'])),
    }))
    .mutation(({ input }) => {
      const report = generateComplianceReport(input.findings, input.frameworks as FrameworkId[]);
      return report;
    }),

  /** Infer CWE from a finding's category/title (utility endpoint) */
  inferCwe: protectedProcedure
    .input(z.object({ category: z.string(), title: z.string() }))
    .query(({ input }) => {
      const cwe = inferCweFromFinding(input.category, input.title);
      return { cwe: cwe || null };
    }),

  /** Get compliance statistics */
  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { complianceFrameworks, complianceMappings, complianceReports } = await import("../../drizzle/schema");
    const { count } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

    const [fwCount] = await db.select({ count: count() }).from(complianceFrameworks);
    const [mapCount] = await db.select({ count: count() }).from(complianceMappings);
    const [rptCount] = await db.select({ count: count() }).from(complianceReports);

    return {
      totalFrameworks: fwCount.count,
      totalMappings: mapCount.count,
      totalReports: rptCount.count,
      builtInFrameworks: Object.keys(ALL_FRAMEWORKS).length,
      totalBuiltInControls: Object.values(ALL_FRAMEWORKS).reduce((sum, fw) => sum + fw.controls.length, 0),
    };
  }),
});
