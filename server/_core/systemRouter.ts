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

  // ─── CI Error Pattern Scan ───────────────────────────────────────────────
  runErrorPatternScan: adminProcedure
    .input(z.object({
      filePaths: z.array(z.string()).optional(),
      strict: z.boolean().optional().default(false),
    }))
    .mutation(async ({ input }) => {
      try {
        const { quickScan, scanFileForCatchBlocks } = await import("../lib/ci-error-pattern-validator");
        const fs = await import('fs');
        const path = await import('path');

        // Determine files to scan
        let filePaths = input.filePaths;
        if (!filePaths || filePaths.length === 0) {
          // Default: scan all server TypeScript files (non-test, non-core)
          const serverDir = path.resolve(process.cwd(), 'server');
          const allFiles: string[] = [];
          const walkDir = (dir: string, prefix: string) => {
            try {
              const entries = fs.readdirSync(dir, { withFileTypes: true });
              for (const entry of entries) {
                if (entry.name === 'node_modules' || entry.name === '_core') continue;
                const fullPath = path.join(dir, entry.name);
                const relPath = path.join(prefix, entry.name);
                if (entry.isDirectory()) {
                  walkDir(fullPath, relPath);
                } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
                  allFiles.push(relPath);
                }
              }
            } catch { /* skip unreadable dirs */ }
          };
          walkDir(serverDir, 'server');
          filePaths = allFiles;
        }

        // Read file contents
        const fileContents = new Map<string, string>();
        for (const fp of filePaths) {
          try {
            const fullPath = path.resolve(process.cwd(), fp);
            const content = fs.readFileSync(fullPath, 'utf-8');
            fileContents.set(fp, content);
          } catch { /* skip unreadable files */ }
        }

        const result = quickScan(fileContents, input.strict);
        return result;
      } catch (err: any) {
        return {
          passed: false,
          mode: 'full' as const,
          filesScanned: 0,
          totalSites: 0,
          newIssues: [],
          existingIssues: [],
          summary: { critical: 0, high: 0, medium: 0, low: 0, swallowedErrors: 0, inconsistencies: 0, newAntiPatterns: 0 },
          report: `Error running scan: ${err.message}`,
          exitCode: 1 as const,
        };
      }
    }),

  // ─── Update Error Pattern Baseline ──────────────────────────────────────────
  updateErrorBaseline: adminProcedure
    .mutation(async () => {
      try {
        const { scanFileForCatchBlocks, generateBaseline, setBaseline } = await import("../lib/ci-error-pattern-validator");
        const fs = await import('fs');
        const path = await import('path');

        const serverDir = path.resolve(process.cwd(), 'server');
        const allFiles: string[] = [];
        const walkDir = (dir: string, prefix: string) => {
          try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
              if (entry.name === 'node_modules' || entry.name === '_core') continue;
              const fullPath = path.join(dir, entry.name);
              const relPath = path.join(prefix, entry.name);
              if (entry.isDirectory()) {
                walkDir(fullPath, relPath);
              } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
                allFiles.push(relPath);
              }
            }
          } catch { /* skip */ }
        };
        walkDir(serverDir, 'server');

        const allSites: any[] = [];
        for (const fp of allFiles) {
          try {
            const fullPath = path.resolve(process.cwd(), fp);
            const content = fs.readFileSync(fullPath, 'utf-8');
            allSites.push(...scanFileForCatchBlocks(content, fp));
          } catch { /* skip */ }
        }

        const baseline = generateBaseline(allSites, new Date().toISOString());
        setBaseline(baseline);
        return { success: true, sitesBaselined: baseline.sites.length, version: baseline.version };
      } catch (err: any) {
        return { success: false, sitesBaselined: 0, version: '', error: err.message };
      }
    }),
});
