import * as db from "../db";
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import {
  ksiValidationRuns,
  ksiValidationSchedules,
  ksiDefinitions,
} from "../../drizzle/schema";
import { eq, desc, and, sql, lte, gte } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

function generateId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

// ─── Default validation frequencies per KSI type ───────────────────────────────

const DEFAULT_FREQUENCIES: Record<string, number> = {
  "Continuous": 24,        // Every 24 hours
  "Persistent": 72,        // Every 3 days
  "Ongoing": 168,          // Every 7 days
  "Per Change": 0,         // Event-driven
  "When Needed": 720,      // Every 30 days
  "Real-time": 1,          // Every hour
  "Promptly": 24,          // Every 24 hours
  "TBD": 720,              // Default 30 days
};

export const ksiValidationSchedulerRouter = router({
  // ── Schedule Management ──────────────────────────────────────────────────────

  /** Initialize validation schedules for all KSIs */
  initializeSchedules: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const defs = await db.select().from(ksiDefinitions);
      let created = 0;

      for (const def of defs) {
        const existing = await db.select()
          .from(ksiValidationSchedules)
          .where(and(
            eq(ksiValidationSchedules.ksiId, def.ksiId),
            input?.engagementId ? eq(ksiValidationSchedules.engagementId, input.engagementId) : sql`1=1`
          ));

        if (existing.length === 0) {
          const freq = DEFAULT_FREQUENCIES[def.frequency || "TBD"] || 720;
          const nextRun = new Date(Date.now() + freq * 3600000);

          await db.insert(ksiValidationSchedules).values({
            scheduleId: generateId("SCH"),
            ksiId: def.ksiId,
            engagementId: input?.engagementId,
            frequencyHours: freq,
            enabled: def.coverageStatus !== "planned",
            nextRunAt: nextRun,
            createdBy: ctx.user?.id,
          });
          created++;
        }
      }
      return { created, total: defs.length };
    }),

  /** List all validation schedules */
  listSchedules: protectedProcedure
    .input(z.object({
      ksiId: z.string().optional(),
      engagementId: z.string().optional(),
      enabled: z.boolean().optional(),
      overdue: z.boolean().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input?.ksiId) conditions.push(eq(ksiValidationSchedules.ksiId, input.ksiId));
      if (input?.engagementId) conditions.push(eq(ksiValidationSchedules.engagementId, input.engagementId));
      if (input?.enabled !== undefined) conditions.push(eq(ksiValidationSchedules.enabled, input.enabled));
      if (input?.overdue) conditions.push(lte(ksiValidationSchedules.nextRunAt, new Date()));

      let query = db.select().from(ksiValidationSchedules);
      if (conditions.length > 0) {
        query = query.where(and(...conditions)) as any;
      }
      return (query as any).orderBy(ksiValidationSchedules.nextRunAt);
    }),

  /** Update a validation schedule */
  updateSchedule: protectedProcedure
    .input(z.object({
      scheduleId: z.string(),
      frequencyHours: z.number().optional(),
      enabled: z.boolean().optional(),
      alertThreshold: z.number().optional(),
      config: z.any().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const updates: any = {};
      if (input.frequencyHours !== undefined) updates.frequencyHours = input.frequencyHours;
      if (input.enabled !== undefined) updates.enabled = input.enabled;
      if (input.alertThreshold !== undefined) updates.alertThreshold = input.alertThreshold;
      if (input.config !== undefined) updates.config = input.config;

      await db.update(ksiValidationSchedules)
        .set(updates)
        .where(eq(ksiValidationSchedules.scheduleId, input.scheduleId));
      return { success: true };
    }),

  // ── Validation Runs ──────────────────────────────────────────────────────────

  /** Start a validation run for a KSI */
  startValidation: protectedProcedure
    .input(z.object({
      ksiId: z.string(),
      engagementId: z.string().optional(),
      triggerType: z.enum(["scheduled", "manual", "event_driven"]).default("manual"),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const runId = generateId("VRN");

      // Get the KSI definition to determine validation type
      const def = await db.select().from(ksiDefinitions).where(eq(ksiDefinitions.ksiId, input.ksiId));
      const validationType = def[0]?.validationType === "tbd" ? "mixed" : (def[0]?.validationType || "mixed");

      await db.insert(ksiValidationRuns).values({
        runId,
        ksiId: input.ksiId,
        engagementId: input.engagementId,
        validationType: validationType as "machine" | "human" | "mixed",
        triggerType: input.triggerType,
        status: "running",
        startedAt: new Date(),
        runBy: ctx.user?.id,
        runByName: ctx.user?.name || "System",
      });

      return { runId };
    }),

  /** Complete a validation run with results */
  completeValidation: protectedProcedure
    .input(z.object({
      runId: z.string(),
      status: z.enum(["passed", "failed", "warning", "error", "skipped"]),
      score: z.number().optional(),
      maxScore: z.number().optional(),
      result: z.any().optional(),
      evidenceIds: z.array(z.string()).optional(),
      errorMessage: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();

      // Get the run to find the KSI and update schedule
      const run = await db.select().from(ksiValidationRuns).where(eq(ksiValidationRuns.runId, input.runId));
      if (!run[0]) throw new Error("Validation run not found");

      await db.update(ksiValidationRuns)
        .set({
          status: input.status,
          score: input.score,
          maxScore: input.maxScore,
          result: input.result,
          evidenceIds: input.evidenceIds,
          errorMessage: input.errorMessage,
          completedAt: new Date(),
        })
        .where(eq(ksiValidationRuns.runId, input.runId));

      // Update the schedule with last run info
      const schedules = await db.select()
        .from(ksiValidationSchedules)
        .where(eq(ksiValidationSchedules.ksiId, run[0].ksiId));

      if (schedules[0]) {
        const freq = schedules[0].frequencyHours;
        const nextRun = new Date(Date.now() + freq * 3600000);
        const consecutiveFailures = input.status === "failed" || input.status === "error"
          ? schedules[0].consecutiveFailures + 1
          : 0;

        await db.update(ksiValidationSchedules)
          .set({
            lastRunId: input.runId,
            lastRunStatus: input.status,
            lastRunAt: new Date(),
            nextRunAt: nextRun,
            consecutiveFailures,
          })
          .where(eq(ksiValidationSchedules.scheduleId, schedules[0].scheduleId));
      }

      return { success: true };
    }),

  /** List validation runs */
  listRuns: protectedProcedure
    .input(z.object({
      ksiId: z.string().optional(),
      engagementId: z.string().optional(),
      status: z.enum(["pending", "running", "passed", "failed", "warning", "error", "skipped"]).optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input?.ksiId) conditions.push(eq(ksiValidationRuns.ksiId, input.ksiId));
      if (input?.engagementId) conditions.push(eq(ksiValidationRuns.engagementId, input.engagementId));
      if (input?.status) conditions.push(eq(ksiValidationRuns.status, input.status));

      let query = db.select().from(ksiValidationRuns);
      if (conditions.length > 0) {
        query = query.where(and(...conditions)) as any;
      }
      const results = await (query as any).orderBy(desc(ksiValidationRuns.createdAt)).limit(input?.limit || 50).offset(input?.offset || 0);

      const countResult = await db.select({ count: sql<number>`count(*)` }).from(ksiValidationRuns)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      return { runs: results, total: countResult[0]?.count || 0 };
    }),

  // ── Dashboard ────────────────────────────────────────────────────────────────

  /** Get validation dashboard summary */
  getDashboard: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();

      // Schedule stats
      const totalSchedules = await db.select({ count: sql<number>`count(*)` }).from(ksiValidationSchedules);
      const enabledSchedules = await db.select({ count: sql<number>`count(*)` }).from(ksiValidationSchedules)
        .where(eq(ksiValidationSchedules.enabled, true));
      const overdueSchedules = await db.select({ count: sql<number>`count(*)` }).from(ksiValidationSchedules)
        .where(and(
          eq(ksiValidationSchedules.enabled, true),
          lte(ksiValidationSchedules.nextRunAt, new Date())
        ));

      // Run stats
      const totalRuns = await db.select({ count: sql<number>`count(*)` }).from(ksiValidationRuns);
      const passedRuns = await db.select({ count: sql<number>`count(*)` }).from(ksiValidationRuns)
        .where(eq(ksiValidationRuns.status, "passed"));
      const failedRuns = await db.select({ count: sql<number>`count(*)` }).from(ksiValidationRuns)
        .where(eq(ksiValidationRuns.status, "failed"));

      // Recent runs
      const recentRuns = await db.select()
        .from(ksiValidationRuns)
        .orderBy(desc(ksiValidationRuns.createdAt))
        .limit(10);

      // Failing KSIs (consecutive failures >= threshold)
      const failingSchedules = await db.select()
        .from(ksiValidationSchedules)
        .where(gte(ksiValidationSchedules.consecutiveFailures, ksiValidationSchedules.alertThreshold));

      return {
        totalSchedules: totalSchedules[0]?.count || 0,
        enabledSchedules: enabledSchedules[0]?.count || 0,
        overdueSchedules: overdueSchedules[0]?.count || 0,
        totalRuns: totalRuns[0]?.count || 0,
        passedRuns: passedRuns[0]?.count || 0,
        failedRuns: failedRuns[0]?.count || 0,
        passRate: totalRuns[0]?.count ? Math.round((passedRuns[0]?.count || 0) / totalRuns[0].count * 100) : 0,
        recentRuns,
        failingKSIs: failingSchedules,
      };
    }),

  /** Get overdue validations that need attention */
  getOverdueValidations: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const overdue = await db.select()
      .from(ksiValidationSchedules)
      .where(and(
        eq(ksiValidationSchedules.enabled, true),
        lte(ksiValidationSchedules.nextRunAt, new Date())
      ))
      .orderBy(ksiValidationSchedules.nextRunAt);

    return overdue;
  }),

  /** Clean up stale "running" validation runs older than the given threshold */
  cleanupStaleRuns: protectedProcedure
    .input(z.object({ maxAgeHours: z.number().min(1).max(720).default(24) }).optional())
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const cutoff = new Date(Date.now() - (input?.maxAgeHours || 24) * 3600000);

      const staleRuns = await db.select()
        .from(ksiValidationRuns)
        .where(and(
          eq(ksiValidationRuns.status, "running"),
          lte(ksiValidationRuns.startedAt, cutoff)
        ));

      let cleaned = 0;
      for (const run of staleRuns) {
        await db.update(ksiValidationRuns)
          .set({
            status: "error",
            errorMessage: `Stale run auto-cleaned: started at ${run.startedAt?.toISOString()} and exceeded ${input?.maxAgeHours || 24}h timeout`,
            completedAt: new Date(),
          })
          .where(eq(ksiValidationRuns.runId, run.runId));
        cleaned++;
      }

      return { cleaned, cutoff: cutoff.toISOString() };
    }),

  /** Cancel a specific running validation */
  cancelValidation: protectedProcedure
    .input(z.object({ runId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const run = await db.select().from(ksiValidationRuns).where(eq(ksiValidationRuns.runId, input.runId));
      if (!run[0]) throw new Error("Validation run not found");
      if (run[0].status !== "running") throw new Error("Can only cancel running validations");

      await db.update(ksiValidationRuns)
        .set({
          status: "error",
          errorMessage: "Manually cancelled by user",
          completedAt: new Date(),
        })
        .where(eq(ksiValidationRuns.runId, input.runId));

      return { success: true };
    }),

  /** Auto-validate machine-type KSIs by checking evidence freshness and count */
  autoValidateMachineKsis: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const { ksiEvidence } = await import("../../drizzle/schema");

      // Get all machine-type KSI definitions
      const machineDefs = await db.select().from(ksiDefinitions)
        .where(eq(ksiDefinitions.validationType, "machine"));

      const results: Array<{ ksiId: string; status: string; score: number; reason: string }> = [];

      for (const def of machineDefs) {
        const runId = generateId("VRN");

        // Count total evidence for this KSI
        const evidenceCount = await db.select({ count: sql<number>`count(*)` })
          .from(ksiEvidence)
          .where(eq(ksiEvidence.ksiId, def.ksiId));
        const totalEvidence = evidenceCount[0]?.count || 0;

        // Count fresh evidence (last 30 days)
        const freshCutoff = new Date(Date.now() - 30 * 24 * 3600000);
        const freshCount = await db.select({ count: sql<number>`count(*)` })
          .from(ksiEvidence)
          .where(and(
            eq(ksiEvidence.ksiId, def.ksiId),
            gte(ksiEvidence.createdAt, freshCutoff)
          ));
        const freshEvidence = freshCount[0]?.count || 0;

        // Score calculation
        let score = 0;
        let maxScore = 100;
        let reason = "";

        // Has any evidence (30 points)
        if (totalEvidence > 0) {
          score += 30;
          reason += `Has ${totalEvidence} evidence items. `;
        } else {
          reason += "No evidence collected. ";
        }

        // Has fresh evidence (30 points)
        if (freshEvidence > 0) {
          score += 30;
          reason += `${freshEvidence} fresh (last 30d). `;
        } else if (totalEvidence > 0) {
          reason += "All evidence is stale (>30d). ";
        }

        // Evidence diversity — multiple source modules (20 points)
        if (totalEvidence > 0) {
          const sources = await db.select({ source: ksiEvidence.sourceModule })
            .from(ksiEvidence)
            .where(eq(ksiEvidence.ksiId, def.ksiId))
            .groupBy(ksiEvidence.sourceModule);
          if (sources.length >= 2) {
            score += 20;
            reason += `${sources.length} source modules. `;
          } else {
            score += 10;
            reason += `Single source module. `;
          }
        }

        // Coverage status bonus (20 points)
        if (def.coverageStatus === "direct") {
          score += 20;
        } else if (def.coverageStatus === "supporting") {
          score += 10;
        }

        const status = score >= 70 ? "passed" : score >= 40 ? "warning" : totalEvidence > 0 ? "failed" : "skipped";

        // Create the validation run
        await db.insert(ksiValidationRuns).values({
          runId,
          ksiId: def.ksiId,
          engagementId: input?.engagementId,
          validationType: "machine",
          triggerType: "scheduled",
          status,
          score,
          maxScore,
          result: { totalEvidence, freshEvidence, reason },
          startedAt: new Date(),
          completedAt: new Date(),
          runBy: ctx.user?.id,
          runByName: ctx.user?.name || "Auto-Validator",
          errorMessage: status === "skipped" ? "No evidence available for validation" : undefined,
        });

        // Update schedule
        const schedules = await db.select()
          .from(ksiValidationSchedules)
          .where(eq(ksiValidationSchedules.ksiId, def.ksiId));

        if (schedules[0]) {
          const freq = schedules[0].frequencyHours;
          const nextRun = new Date(Date.now() + freq * 3600000);
          const consecutiveFailures = status === "failed" || status === "error"
            ? schedules[0].consecutiveFailures + 1
            : 0;

          await db.update(ksiValidationSchedules)
            .set({
              lastRunId: runId,
              lastRunStatus: status,
              lastRunAt: new Date(),
              nextRunAt: nextRun,
              consecutiveFailures,
            })
            .where(eq(ksiValidationSchedules.scheduleId, schedules[0].scheduleId));
        }

        results.push({ ksiId: def.ksiId, status, score, reason: reason.trim() });
      }

      return {
        validated: results.length,
        passed: results.filter(r => r.status === "passed").length,
        warning: results.filter(r => r.status === "warning").length,
        failed: results.filter(r => r.status === "failed").length,
        skipped: results.filter(r => r.status === "skipped").length,
        results,
      };
    }),
});
