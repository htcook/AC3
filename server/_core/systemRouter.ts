import { z } from "zod";
import { notifyOwner } from "./notification";
import { adminProcedure, publicProcedure, router } from "./trpc";

export const systemRouter = router({
  health: publicProcedure
    .input(
      z.object({
        timestamp: z.number().min(0, "timestamp cannot be negative"),
      })
    )
    .query(() => ({
      ok: true,
    })),

  // ─── Error Incident Reporting ─────────────────────────────────────────────
  reportError: publicProcedure
    .input(
      z.object({
        incidentId: z.string().nullable(),
        scope: z.string().default("global"),
        error: z.object({
          name: z.string(),
          message: z.string(),
          stack: z.string().optional(),
        }),
        componentStack: z.string().optional(),
        url: z.string(),
        userAgent: z.string(),
        timestamp: z.string(),
        viewport: z
          .object({
            width: z.number(),
            height: z.number(),
          })
          .optional(),
      })
    )
    .mutation(async ({ input }) => {
      // Log the incident server-side
      console.error(
        `[Incident ${input.incidentId}] Scope: ${input.scope} | ` +
          `Error: ${input.error.name}: ${input.error.message} | ` +
          `URL: ${input.url} | Time: ${input.timestamp}`
      );

      // Store in database if available
      try {
        const { getDb } = await import("../db");
        const db = await getDb();
        if (db) {
          const { sql } = await import("drizzle-orm");
          await db
            .execute(
              sql`
            INSERT INTO error_incidents (incidentId, scope, errorName, errorMessage, errorStack, componentStack, url, userAgent, timestamp, viewportWidth, viewportHeight, createdAt)
            VALUES (${input.incidentId}, ${input.scope}, ${input.error.name}, ${input.error.message}, ${input.error.stack ?? null}, ${input.componentStack ?? null}, ${input.url}, ${input.userAgent}, ${input.timestamp}, ${input.viewport?.width ?? null}, ${input.viewport?.height ?? null}, ${Date.now()})
          `
            )
            .catch(() => {
              // Table might not exist yet — silently skip DB storage
            });
        }
      } catch {
        // DB not available — incident is still logged to console
      }

      // Notify owner for critical errors (app-root scope = full crash)
      if (input.scope === "app-root") {
        await notifyOwner({
          title: `Critical UI Error: ${input.incidentId}`,
          content: `Scope: ${input.scope}\nError: ${input.error.name}: ${input.error.message}\nURL: ${input.url}\nTime: ${input.timestamp}`,
        }).catch(() => {});
      }

      return { received: true, incidentId: input.incidentId };
    }),

  notifyOwner: adminProcedure
    .input(
      z.object({
        title: z.string().min(1, "title is required"),
        content: z.string().min(1, "content is required"),
      })
    )
    .mutation(async ({ input }) => {
      const delivered = await notifyOwner(input);
      return {
        success: delivered,
      } as const;
    }),

  // ─── LLM Hot Path Analyzer Data ─────────────────────────────────────────────
  getLLMCacheStats: adminProcedure.query(async () => {
    try {
      const { inferenceCache, callSiteTracker } = await import("../lib/llm-inference-optimizer");
      const cacheStats = inferenceCache.getStats();
      const graduationCandidates = inferenceCache.getGraduationCandidates();
      const callSites = callSiteTracker.getTopCallers(20);
      const anomalies = callSiteTracker.detectAnomalies();
      return {
        cache: cacheStats,
        graduationCandidates,
        callSites,
        anomalies,
      };
    } catch {
      return { cache: { entries: 0, hitRate: 0, tokensSaved: 0 }, graduationCandidates: [], callSites: [], anomalies: [] };
    }
  }),

  // ─── Operational Metrics Data ───────────────────────────────────────────────
  getOperationalMetrics: adminProcedure.query(async () => {
    try {
      const { getDb } = await import("../db");
      const db = await getDb();
      if (!db) return null;
      const { sql } = await import("drizzle-orm");
      // Aggregate recent engagement metrics from llm_telemetry
      const [recentStats] = await db.execute(sql`
        SELECT 
          COUNT(DISTINCT engagementId) as engagementCount,
          SUM(tokensIn + tokensOut) as totalTokens,
          COUNT(*) as totalCalls,
          AVG(latencyMs) as avgLatency
        FROM llm_telemetry
        WHERE createdAt > ${Date.now() - 7 * 24 * 60 * 60 * 1000}
      `) as any;
      return {
        avgCostPerEngagement: (recentStats?.totalTokens || 0) * 0.000003,
        avgDurationMinutes: (recentStats?.avgLatency || 0) / 1000 / 60 * (recentStats?.totalCalls || 1),
        totalFindings: 0,
        truePositiveRate: null,
        recentEngagements: [],
        ruleEffectiveness: [],
        findingLineage: [],
      };
    } catch {
      return { avgCostPerEngagement: 0, avgDurationMinutes: 0, totalFindings: 0, truePositiveRate: null, recentEngagements: [], ruleEffectiveness: [], findingLineage: [] };
    }
  }),

  // ─── Architecture Health Data ───────────────────────────────────────────────
  getArchitectureHealth: adminProcedure.query(async () => {
    try {
      const { runQuickAudit } = await import("../lib/architectural-debt-tracker");
      // Run a quick audit with known module info
      const report = runQuickAudit(
        [
          { path: 'server/lib/engagement-orchestrator.ts', name: 'engagement-orchestrator', lineCount: 11200, exportCount: 45, importCount: 28, importedBy: ['server/routers/engagement-ops-core.ts', 'server/routers/engagement-pipeline.ts'], imports: [] },
          { path: 'client/src/pages/EngagementOps.tsx', name: 'EngagementOps', lineCount: 8500, exportCount: 1, importCount: 35, importedBy: ['client/src/App.tsx'], imports: [] },
        ],
        [], // Error sites would be populated by static analysis
        []  // Flags would be populated by env scanning
      );
      return report;
    } catch {
      return { generatedAt: Date.now(), totalItems: 0, bySeverity: {}, byCategory: {}, topPriority: [], totalMaintenanceBurden: 0, healthScore: 100 };
    }
  }),
});
