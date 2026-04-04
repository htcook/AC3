/**
 * Engagement Results Router
 * 
 * Provides read access to persisted engagement results and findings.
 * Results are saved automatically when engagements complete.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import { engagementResults, engagementFindings } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";

async function getDb() {
  const db = await _getDb();
  return db!;
}

export const engagementResultsRouter = router({
  /** Get the persisted result summary for a specific engagement */
  getResult: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const rows = await db.select().from(engagementResults)
        .where(eq(engagementResults.engagementId, input.engagementId))
        .limit(1);
      return rows[0] || null;
    }),

  /** Get all persisted findings for a specific engagement */
  getFindings: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions = [eq(engagementFindings.engagementId, input.engagementId)];
      if (input.severity) {
        conditions.push(eq(engagementFindings.severity, input.severity));
      }
      return db.select().from(engagementFindings)
        .where(and(...conditions))
        .orderBy(desc(engagementFindings.id));
    }),

  /** List all engagement results (most recent first) */
  listResults: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(20),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const limit = input?.limit || 20;
      const offset = input?.offset || 0;
      const rows = await db.select().from(engagementResults)
        .orderBy(desc(engagementResults.createdAt))
        .limit(limit)
        .offset(offset);
      return rows;
    }),

  /** Get aggregate stats across all completed engagements */
  aggregateStats: protectedProcedure.query(async () => {
    const db = await getDb();
    const [stats] = await db.select({
      totalEngagements: sql<number>`COUNT(*)`,
      totalVulns: sql<number>`COALESCE(SUM(${engagementResults.vulnsFound}), 0)`,
      totalCritical: sql<number>`COALESCE(SUM(${engagementResults.criticalVulns}), 0)`,
      totalHigh: sql<number>`COALESCE(SUM(${engagementResults.highVulns}), 0)`,
      totalMedium: sql<number>`COALESCE(SUM(${engagementResults.mediumVulns}), 0)`,
      totalLow: sql<number>`COALESCE(SUM(${engagementResults.lowVulns}), 0)`,
      totalInfo: sql<number>`COALESCE(SUM(${engagementResults.infoVulns}), 0)`,
      totalExploitsAttempted: sql<number>`COALESCE(SUM(${engagementResults.exploitsAttempted}), 0)`,
      totalExploitsSucceeded: sql<number>`COALESCE(SUM(${engagementResults.exploitsSucceeded}), 0)`,
      avgOwaspCoverage: sql<number>`COALESCE(AVG(${engagementResults.owaspCoverageScore}), 0)`,
      avgDurationMs: sql<number>`COALESCE(AVG(${engagementResults.durationMs}), 0)`,
    }).from(engagementResults);
    return stats;
  }),
});
