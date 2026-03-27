/**
 * ScanForge tRPC Router
 * 
 * Provides frontend access to the ScanForge vulnerability scanner and DAST engine.
 * Manages scan lifecycle, template library, intelligence feeds, and results.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { randomUUID } from "crypto";
import { getScanQueue } from "../scanforge/queue/scan-queue";
import { getTemplateEngine } from "../scanforge/engine/template-engine";
import { ScanOrchestrator } from "../scanforge/engine/scan-orchestrator";
import { getProtocolRegistry } from "../scanforge/protocols/registry";
import { getIntelligenceEngine } from "../scanforge/intelligence/ti-engine";
import { getContextEngine } from "../scanforge/intelligence/context-engine";
import { getFPFNEngine } from "../scanforge/intelligence/fp-fn-prevention";
import type {
  ScanConfig,
  ScanStatus,
  ScanTarget,
  ScanRequest,
  ScanPriority,
} from "../scanforge/types";
import { getScanForgeHealthMetrics, getTuningHistory } from "../scanforge/engine/confidence-tuner";
import { getTemplateEffectiveness, getEngagementReports, getEngagementFindings } from "../scanforge/engine/accuracy-tracker";
import { getDraftTemplates, getResearchLog, promoteTemplate } from "../scanforge/engine/deep-research-agent";
import { getDbRequired } from "../db";
import { scanforgeGeneratedTemplates, scanforgeResearchLog, scanforgeEngagementReport, scanforgeFindingLog, scanforgeTemplateMetrics } from "../../drizzle/schema";
import { eq, desc, sql, count } from "drizzle-orm";

// ── Singleton Instances ──────────────────────────────────────────────────
const scanQueue = getScanQueue({ maxConcurrent: 5, maxQueueSize: 100 });
const templateEngine = getTemplateEngine();
const protocolRegistry = getProtocolRegistry();
const tiEngine = getIntelligenceEngine();
const contextEngine = getContextEngine();
const fpfnEngine = getFPFNEngine();
const orchestrator = new ScanOrchestrator(scanQueue);

// Initialize on startup
(async () => {
  try {
    await orchestrator.initialize();
    console.log(`[ScanForge] Initialized: ${templateEngine.count} templates, ${protocolRegistry.count} protocol scanners`);
  } catch (err) {
    console.error("[ScanForge] Failed to initialize:", err);
  }
})();

export const scanforgeRouter = router({
  // ── Dashboard Stats ─────────────────────────────────────────────────
  stats: protectedProcedure.query(async () => {
    const queueStats = scanQueue.getStats();
    const templates = templateEngine.getAll();
    const protocols = protocolRegistry.listAll();

    return {
      queue: queueStats,
      templates: {
        total: templates.length,
        bySeverity: {
          critical: templates.filter((t) => t.severity === "critical").length,
          high: templates.filter((t) => t.severity === "high").length,
          medium: templates.filter((t) => t.severity === "medium").length,
          low: templates.filter((t) => t.severity === "low").length,
          info: templates.filter((t) => t.severity === "info").length,
        },
      },
      protocols: {
        total: protocols.length,
        names: protocols.map((p) => p.protocol),
      },
      intelligence: {
        kevLoaded: tiEngine.getKEVCount(),
        threatActorProfiles: tiEngine.getThreatActorCount(),
      },
      contextEngine: {
        initialized: true,
      },
      fpfnEngine: {
        initialized: true,
      },
    };
  }),

  // ── Start Scan ──────────────────────────────────────────────────────
  startScan: protectedProcedure
    .input(
      z.object({
        target: z.string().min(1),
        scanType: z.enum(["full", "quick", "passive", "active", "custom", "recon"]).default("full"),
        ports: z.array(z.number()).optional(),
        protocols: z.array(z.string()).optional(),
        templateTags: z.array(z.string()).optional(),
        maxConcurrency: z.number().min(1).max(20).optional(),
        timeout: z.number().min(60).max(7200).optional(),
        intelligence: z
          .object({
            enableKEV: z.boolean().optional(),
            enableEPSS: z.boolean().optional(),
            enableThreatActorMapping: z.boolean().optional(),
            enableDFIRArtifacts: z.boolean().optional(),
            targetIndustry: z.string().optional(),
            useLLMContext: z.boolean().optional(),
          })
          .optional(),
        engagementId: z.number().optional(),
        priority: z.enum(["critical", "high", "medium", "low"]).optional(),
      })
    )
    .mutation(async ({ input }) => {
      // Build scan targets
      const targets: ScanTarget[] = [{
        host: input.target,
        type: input.target.match(/^https?:\/\//) ? "url"
          : input.target.match(/^\d+\.\d+\.\d+\.\d+/) ? "ip"
          : "domain",
        ports: input.ports,
      }];

      // Build scan request
      const request: ScanRequest = {
        id: randomUUID(),
        targets,
        type: input.scanType as any,
        priority: (input.priority || "medium") as ScanPriority,
        config: {
          maxConcurrency: input.maxConcurrency || 5,
          timeoutMs: (input.timeout || 3600) * 1000,
          templateTags: input.templateTags,
          protocols: input.protocols,
        },
        intelligence: input.intelligence ? {
          enableKEV: input.intelligence.enableKEV ?? true,
          enableEPSS: input.intelligence.enableEPSS ?? true,
          enableThreatActorMapping: input.intelligence.enableThreatActorMapping ?? true,
          enableDFIRArtifacts: input.intelligence.enableDFIRArtifacts ?? true,
          targetIndustry: input.intelligence.targetIndustry,
          useLLMContext: input.intelligence.useLLMContext ?? true,
        } : undefined,
        metadata: input.engagementId ? { engagementId: input.engagementId } : undefined,
      };

      // Enqueue the scan
      const job = scanQueue.enqueue(request);
      return { scanId: request.id, status: job.status };
    }),

  // ── Get Scan Status ─────────────────────────────────────────────────
  getScan: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ input }) => {
      const job = scanQueue.getJob(input.scanId);
      if (!job) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Scan ${input.scanId} not found`,
        });
      }
      return {
        id: job.request.id,
        status: job.status,
        type: job.request.type,
        targets: job.request.targets,
        progress: job.progress,
        phase: job.phase,
        currentScanner: job.currentScanner,
        findings: job.findings.length,
        error: job.error,
        startedAt: job.startedAt,
        completedAt: job.completedAt,
      };
    }),

  // ── List Scans ──────────────────────────────────────────────────────
  listScans: protectedProcedure
    .input(
      z.object({
        status: z.enum(["queued", "running", "completed", "failed", "cancelled", "paused"]).optional(),
        limit: z.number().min(1).max(100).default(50),
        offset: z.number().min(0).default(0),
      }).optional()
    )
    .query(async ({ input }) => {
      const opts = input || {};
      const allJobs = scanQueue.listJobs(opts.status as ScanStatus);
      const total = allJobs.length;
      const offset = opts.offset || 0;
      const limit = opts.limit || 50;
      const jobs = allJobs.slice(offset, offset + limit);

      return {
        total,
        offset,
        limit,
        scans: jobs.map((j) => ({
          id: j.request.id,
          target: j.request.targets[0]?.host || "unknown",
          scanType: j.request.type,
          status: j.status,
          progress: j.progress,
          phase: j.phase,
          findingsCount: j.findings.length,
          startedAt: j.startedAt,
          completedAt: j.completedAt,
        })),
      };
    }),

  // ── Cancel Scan ─────────────────────────────────────────────────────
  cancelScan: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .mutation(async ({ input }) => {
      const success = scanQueue.cancelJob(input.scanId);
      if (!success) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Scan ${input.scanId} not found or already completed`,
        });
      }
      return { success: true };
    }),

  // ── Get Scan Results ────────────────────────────────────────────────
  getScanResults: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ input }) => {
      const job = scanQueue.getJob(input.scanId);
      if (!job) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Scan ${input.scanId} not found`,
        });
      }
      if (job.status !== "completed") {
        return {
          status: job.status,
          findings: [],
          summary: null,
          attackPaths: null,
        };
      }
      return {
        status: job.status,
        findings: job.findings,
        summary: {
          totalFindings: job.findings.length,
          bySeverity: {
            critical: job.findings.filter(f => f.severity === "critical").length,
            high: job.findings.filter(f => f.severity === "high").length,
            medium: job.findings.filter(f => f.severity === "medium").length,
            low: job.findings.filter(f => f.severity === "low").length,
            info: job.findings.filter(f => f.severity === "info").length,
          },
          scannersRun: job.scannerResults.length,
          durationMs: (job.completedAt || Date.now()) - (job.startedAt || Date.now()),
        },
        attackPaths: job.attackPaths || null,
      };
    }),

  // ── Template Library ────────────────────────────────────────────────
  listTemplates: protectedProcedure
    .input(
      z.object({
        tag: z.string().optional(),
        severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
        protocol: z.string().optional(),
        search: z.string().optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      let templates = templateEngine.getAll();
      const opts = input || {};

      if (opts.tag) {
        templates = templates.filter((t) => t.tags?.includes(opts.tag!));
      }
      if (opts.severity) {
        templates = templates.filter((t) => t.severity === opts.severity);
      }
      if (opts.protocol) {
        templates = templates.filter((t) => t.protocol === opts.protocol);
      }
      if (opts.search) {
        const q = opts.search.toLowerCase();
        templates = templates.filter(
          (t) =>
            t.name.toLowerCase().includes(q) ||
            t.description?.toLowerCase().includes(q) ||
            t.id.toLowerCase().includes(q)
        );
      }

      return {
        total: templates.length,
        templates: templates.map((t) => ({
          id: t.id,
          name: t.name,
          description: t.description,
          severity: t.severity,
          protocol: t.protocol,
          tags: t.tags,
          author: t.author,
          references: t.references,
        })),
      };
    }),

  // ── Get Template Detail ─────────────────────────────────────────────
  getTemplate: protectedProcedure
    .input(z.object({ templateId: z.string() }))
    .query(async ({ input }) => {
      const template = templateEngine.get(input.templateId);
      if (!template) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Template ${input.templateId} not found`,
        });
      }
      return template;
    }),

  // ── Protocol Registry ───────────────────────────────────────────────
  listProtocols: protectedProcedure.query(async () => {
    const protocols = protocolRegistry.listAll();
    return {
      total: protocols.length,
      protocols: protocols.map((p) => ({
        name: p.name,
        protocol: p.protocol,
        defaultPorts: p.defaultPorts,
        environments: p.environments || ["traditional"],
      })),
    };
  }),

  // ── Intelligence Feeds ──────────────────────────────────────────────
  intelligenceStatus: protectedProcedure.query(async () => {
    return {
      kev: {
        loaded: tiEngine.getKEVCount() > 0,
        count: tiEngine.getKEVCount(),
      },
      threatActors: {
        loaded: tiEngine.getThreatActorCount() > 0,
        count: tiEngine.getThreatActorCount(),
      },
      dfirArtifacts: {
        loaded: true,
        categories: ["persistence", "lateral_movement", "exfiltration", "credential_access"],
      },
      contextEngine: {
        initialized: true,
      },
      fpfnEngine: {
        initialized: true,
      },
    };
  }),

  // ── Refresh Intelligence Feeds ──────────────────────────────────────
  refreshIntelligence: protectedProcedure.mutation(async () => {
    await tiEngine.refreshFeeds();
    return {
      success: true,
      kev: tiEngine.getKEVCount(),
      threatActors: tiEngine.getThreatActorCount(),
    };
  }),

  // ── Risk Score for a target ─────────────────────────────────────────
  calculateRisk: protectedProcedure
    .input(
      z.object({
        target: z.string(),
        industry: z.string().optional(),
        services: z.array(z.string()).optional(),
      })
    )
    .query(async ({ input }) => {
      const score = tiEngine.calculateRiskScore({
        target: input.target,
        industry: input.industry,
        services: input.services,
      });
      return { score, target: input.target };
    }),

  // ── Context Analysis ────────────────────────────────────────────────
  analyzeContext: protectedProcedure
    .input(
      z.object({
        target: z.string(),
        ports: z.array(z.number()).optional(),
        services: z.record(z.string(), z.string()).optional(),
        headers: z.record(z.string(), z.string()).optional(),
      })
    )
    .mutation(async ({ input }) => {
      const target: ScanTarget = {
        host: input.target,
        type: input.target.match(/^\d+\.\d+\.\d+\.\d+/) ? "ip" : "domain",
        ports: input.ports,
        services: input.services,
        headers: input.headers,
      };
      const analysis = await contextEngine.classifyTarget(target);
      return analysis;
    }),

  // ── FP/FN Validation ────────────────────────────────────────────────
  validateFindings: protectedProcedure
    .input(
      z.object({
        scanId: z.string(),
      })
    )
    .mutation(async ({ input }) => {
      const job = scanQueue.getJob(input.scanId);
      if (!job) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Scan ${input.scanId} not found`,
        });
      }
      const result = await fpfnEngine.validateBatch(job.findings, {
        // Build context from the scan job's target information
        environment: job.request.targets[0]?.classification?.environment,
        detectedTechnologies: job.request.targets[0]?.technologies as Record<string, string> | undefined,
      });
      return {
        original: job.findings.length,
        validated: result.validated.length,
        suppressed: result.suppressed.length,
        stats: result.stats,
        findings: result.validated.map(r => r.finding),
      };
    }),

  // ── Scan Plan Preview ───────────────────────────────────────────────
  previewScanPlan: protectedProcedure
    .input(
      z.object({
        target: z.string(),
        scanType: z.enum(["full", "quick", "passive", "active", "custom"]).default("full"),
        ports: z.array(z.number()).optional(),
        targetIndustry: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const matchingTemplates = templateEngine.getAll();
      const protocols = protocolRegistry.listAll();
      const ports = input.ports || [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];

      const scanPlan = {
        target: input.target,
        scanType: input.scanType,
        estimatedDuration: input.scanType === "quick" ? "2-5 min" : input.scanType === "passive" ? "1-3 min" : "10-30 min",
        phases: [
          {
            name: "Context Classification",
            description: "LLM-powered asset classification to determine optimal scanning strategy",
            estimatedTime: "5-15s",
          },
          {
            name: "Port Discovery",
            description: `Scan ${ports.length} ports for open services`,
            estimatedTime: "30s-2min",
          },
          {
            name: "Service Fingerprinting",
            description: `Identify services on discovered open ports using ${protocols.length} protocol scanners`,
            estimatedTime: "1-3min",
          },
          {
            name: "Vulnerability Detection",
            description: `Run ${matchingTemplates.length} detection templates against discovered services`,
            estimatedTime: "3-15min",
          },
          {
            name: "FP/FN Validation",
            description: "Multi-signal validation to eliminate false positives and detect false negatives",
            estimatedTime: "30s-2min",
          },
          {
            name: "Intelligence Enrichment",
            description: "Correlate findings with KEV, EPSS, threat actor profiles, and DFIR artifacts",
            estimatedTime: "10-30s",
          },
          {
            name: "Attack Path Correlation",
            description: "Chain findings into exploitable attack paths using LLM analysis",
            estimatedTime: "15-45s",
          },
        ],
        templateCount: matchingTemplates.length,
        protocolCount: protocols.length,
        portCount: ports.length,
      };

      return scanPlan;
    }),

  // ══════════════════════════════════════════════════════════════════════
  // DASHBOARD PROCEDURES — ScanForge Analytics & Self-Improvement Engine
  // ══════════════════════════════════════════════════════════════════════

  // ── Health Metrics (Overview) ────────────────────────────────────────
  healthMetrics: protectedProcedure.query(async () => {
    try {
      return await getScanForgeHealthMetrics();
    } catch {
      // Return empty metrics if tables don't have data yet
      return {
        totalTemplates: templateEngine.getAll().length,
        activeTemplates: 0,
        deprecatedTemplates: 0,
        avgPrecision: 0,
        avgRecall: 0,
        avgF1: 0,
        totalFindings: 0,
        truePositives: 0,
        falsePositives: 0,
        falseNegatives: 0,
        topPerformers: [],
        worstPerformers: [],
      };
    }
  }),

  // ── Template Effectiveness Rankings ─────────────────────────────────
  templateEffectiveness: protectedProcedure
    .input(z.object({ minScans: z.number().min(1).default(1) }).optional())
    .query(async ({ input }) => {
      try {
        return await getTemplateEffectiveness(input?.minScans || 1);
      } catch {
        return [];
      }
    }),

  // ── Engagement Comparison Reports ───────────────────────────────────
  engagementReports: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(20) }).optional())
    .query(async ({ input }) => {
      try {
        return await getEngagementReports(input?.limit || 20);
      } catch {
        return [];
      }
    }),

  // ── Engagement Finding Details ──────────────────────────────────────
  engagementFindingDetails: protectedProcedure
    .input(z.object({ engagementId: z.string() }))
    .query(async ({ input }) => {
      try {
        return await getEngagementFindings(input.engagementId);
      } catch {
        return [];
      }
    }),

  // ── Generated Templates (Draft/Review/Promoted) ────────────────────
  generatedTemplates: protectedProcedure
    .input(z.object({
      status: z.enum(["draft", "review", "approved", "rejected", "promoted"]).optional(),
      limit: z.number().min(1).max(200).default(50),
    }).optional())
    .query(async ({ input }) => {
      try {
        const _db = await getDbRequired();
        let query = _db.select().from(scanforgeGeneratedTemplates);
        if (input?.status) {
          query = query.where(eq(scanforgeGeneratedTemplates.status, input.status)) as any;
        }
        return await (query as any)
          .orderBy(desc(scanforgeGeneratedTemplates.createdAt))
          .limit(input?.limit || 50);
      } catch {
        return [];
      }
    }),

  // ── Promote Generated Template ─────────────────────────────────────
  promoteGeneratedTemplate: protectedProcedure
    .input(z.object({ templateId: z.string() }))
    .mutation(async ({ input }) => {
      const success = await promoteTemplate(input.templateId);
      if (!success) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: `Template ${input.templateId} not found or not in promotable state`,
        });
      }
      return { success: true };
    }),

  // ── Research Activity Log ──────────────────────────────────────────
  researchLog: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(500).default(100),
      feedSource: z.string().optional(),
      researchType: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      try {
        const _db = await getDbRequired();
        let conditions: any[] = [];
        if (input?.feedSource) {
          conditions.push(eq(scanforgeResearchLog.feedSource, input.feedSource));
        }
        if (input?.researchType) {
          conditions.push(eq(scanforgeResearchLog.researchType, input.researchType));
        }
        let query = _db.select().from(scanforgeResearchLog);
        for (const cond of conditions) {
          query = query.where(cond) as any;
        }
        return await (query as any)
          .orderBy(desc(scanforgeResearchLog.createdAt))
          .limit(input?.limit || 100);
      } catch {
        return [];
      }
    }),

  // ── Confidence Tuning History ───────────────────────────────────────
  tuningHistory: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(50) }).optional())
    .query(async ({ input }) => {
      try {
        return await getTuningHistory(input?.limit || 50);
      } catch {
        return [];
      }
    }),

  // ── Dashboard Summary (aggregated counts) ──────────────────────────
  dashboardSummary: protectedProcedure.query(async () => {
    try {
      const _db = await getDbRequired();
      const [findingCount] = await _db.select({ count: sql<number>`count(*)` }).from(scanforgeFindingLog);
      const [templateMetricCount] = await _db.select({ count: sql<number>`count(*)` }).from(scanforgeTemplateMetrics);
      const [reportCount] = await _db.select({ count: sql<number>`count(*)` }).from(scanforgeEngagementReport);
      const [generatedCount] = await _db.select({ count: sql<number>`count(*)` }).from(scanforgeGeneratedTemplates);
      const [researchCount] = await _db.select({ count: sql<number>`count(*)` }).from(scanforgeResearchLog);

      // Verdict distribution
      const verdicts = await _db.select({
        verdict: scanforgeFindingLog.verdict,
        count: sql<number>`count(*)`,
      }).from(scanforgeFindingLog).groupBy(scanforgeFindingLog.verdict);

      // Generated template status distribution
      const genStatuses = await _db.select({
        status: scanforgeGeneratedTemplates.status,
        count: sql<number>`count(*)`,
      }).from(scanforgeGeneratedTemplates).groupBy(scanforgeGeneratedTemplates.status);

      // Research type distribution
      const researchTypes = await _db.select({
        type: scanforgeResearchLog.researchType,
        count: sql<number>`count(*)`,
      }).from(scanforgeResearchLog).groupBy(scanforgeResearchLog.researchType);

      return {
        totalFindings: findingCount?.count || 0,
        totalTemplateMetrics: templateMetricCount?.count || 0,
        totalReports: reportCount?.count || 0,
        totalGeneratedTemplates: generatedCount?.count || 0,
        totalResearchEntries: researchCount?.count || 0,
        verdictDistribution: Object.fromEntries(verdicts.map(v => [v.verdict, v.count])),
        generatedTemplateStatuses: Object.fromEntries(genStatuses.map(s => [s.status, s.count])),
        researchTypeDistribution: Object.fromEntries(researchTypes.map(r => [r.type, r.count])),
        templateLibrarySize: templateEngine.getAll().length,
        protocolCount: protocolRegistry.listAll().length,
      };
    } catch {
      return {
        totalFindings: 0,
        totalTemplateMetrics: 0,
        totalReports: 0,
        totalGeneratedTemplates: 0,
        totalResearchEntries: 0,
        verdictDistribution: {},
        generatedTemplateStatuses: {},
        researchTypeDistribution: {},
        templateLibrarySize: templateEngine.getAll().length,
        protocolCount: protocolRegistry.listAll().length,
      };
    }
  }),
});
