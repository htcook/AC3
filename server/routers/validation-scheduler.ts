/**
 * Validation Scheduler Router
 * ────────────────────────────
 * Manages continuous validation schedules for domain scans,
 * emulation runs, campaign retests, and detection retests.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { validationSchedules } from "../../drizzle/schema";
import { eq, desc, and, lte, sql } from "drizzle-orm";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

const SCHEDULE_TYPES = ["domain_scan", "emulation", "campaign_retest", "detection_retest"] as const;

const INTERVAL_PRESETS = [
  { label: "Every 6 hours", hours: 6 },
  { label: "Every 12 hours", hours: 12 },
  { label: "Daily", hours: 24 },
  { label: "Every 3 days", hours: 72 },
  { label: "Weekly", hours: 168 },
  { label: "Bi-weekly", hours: 336 },
  { label: "Monthly", hours: 720 },
];

export const validationSchedulerRouter = router({
  // ─── List all schedules ───
  list: protectedProcedure
    .input(z.object({
      type: z.enum(SCHEDULE_TYPES).optional(),
      enabled: z.boolean().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.type) filters.push(eq(validationSchedules.scheduleType, input.type));
      if (input?.enabled !== undefined) filters.push(eq(validationSchedules.enabled, input.enabled));

      const items = await db.select().from(validationSchedules)
        .where(filters.length > 0 ? and(...filters) : undefined)
        .orderBy(desc(validationSchedules.createdAt));

      return {
        items,
        total: items.length,
        intervalPresets: INTERVAL_PRESETS,
      };
    }),

  // ─── Create a new schedule ───
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      scheduleType: z.enum(SCHEDULE_TYPES),
      targetId: z.string().optional(),
      targetLabel: z.string().optional(),
      intervalHours: z.number().min(1).max(8760).default(168),
      cronExpression: z.string().max(100).optional(),
      config: z.record(z.string(), z.any()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const nextRunAt = new Date(Date.now() + input.intervalHours * 3600 * 1000);

      await db.insert(validationSchedules).values({
        name: input.name,
        scheduleType: input.scheduleType,
        targetId: input.targetId,
        targetLabel: input.targetLabel,
        intervalHours: input.intervalHours,
        cronExpression: input.cronExpression,
        nextRunAt,
        config: input.config || {},
        createdBy: String(ctx.user.id),
      });

      return { success: true, nextRunAt: nextRunAt.toISOString() };
    }),

  // ─── Update a schedule ───
  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().min(1).max(255).optional(),
      intervalHours: z.number().min(1).max(8760).optional(),
      cronExpression: z.string().max(100).optional(),
      enabled: z.boolean().optional(),
      config: z.record(z.string(), z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const updates: Record<string, any> = {};
      if (input.name !== undefined) updates.name = input.name;
      if (input.intervalHours !== undefined) {
        updates.intervalHours = input.intervalHours;
        updates.nextRunAt = new Date(Date.now() + input.intervalHours * 3600 * 1000);
      }
      if (input.cronExpression !== undefined) updates.cronExpression = input.cronExpression;
      if (input.enabled !== undefined) updates.enabled = input.enabled;
      if (input.config !== undefined) updates.config = input.config;

      await db.update(validationSchedules).set(updates).where(eq(validationSchedules.id, input.id));
      return { success: true };
    }),

  // ─── Delete a schedule ───
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(validationSchedules).where(eq(validationSchedules.id, input.id));
      return { success: true };
    }),

  // ─── Toggle enabled/disabled ───
  toggle: protectedProcedure
    .input(z.object({ id: z.number(), enabled: z.boolean() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.update(validationSchedules)
        .set({ enabled: input.enabled })
        .where(eq(validationSchedules.id, input.id));
      return { success: true };
    }),

  // ─── Get due schedules (for background runner) ───
  getDue: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const now = new Date();
    const items = await db.select().from(validationSchedules)
      .where(and(
        eq(validationSchedules.enabled, true),
        lte(validationSchedules.nextRunAt, now),
      ))
      .orderBy(validationSchedules.nextRunAt);

    return { items, count: items.length };
  }),

  // ─── Mark a schedule as running ───
  markRunning: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.update(validationSchedules)
        .set({ lastStatus: "running", lastRunAt: new Date() })
        .where(eq(validationSchedules.id, input.id));
      return { success: true };
    }),

  // ─── Mark a schedule as completed ───
  markCompleted: protectedProcedure
    .input(z.object({
      id: z.number(),
      status: z.enum(["success", "failed"]),
      error: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();

      // Get the schedule to calculate next run
      const [schedule] = await db.select().from(validationSchedules)
        .where(eq(validationSchedules.id, input.id));

      if (!schedule) throw new TRPCError({ code: "NOT_FOUND" });

      const nextRunAt = new Date(Date.now() + schedule.intervalHours * 3600 * 1000);

      await db.update(validationSchedules)
        .set({
          lastStatus: input.status,
          lastError: input.error || null,
          nextRunAt,
          runCount: sql`${validationSchedules.runCount} + 1`,
        })
        .where(eq(validationSchedules.id, input.id));

      return { success: true, nextRunAt: nextRunAt.toISOString() };
    }),

  // ─── Dashboard stats ───
  stats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const all = await db.select().from(validationSchedules);

    const active = all.filter(s => s.enabled);
    const byType: Record<string, number> = {};
    for (const s of all) {
      byType[s.scheduleType] = (byType[s.scheduleType] || 0) + 1;
    }

    const now = new Date();
    const overdue = active.filter(s => s.nextRunAt && s.nextRunAt < now);
    const running = all.filter(s => s.lastStatus === "running");
    const failed = all.filter(s => s.lastStatus === "failed");

    return {
      total: all.length,
      active: active.length,
      overdue: overdue.length,
      running: running.length,
      failed: failed.length,
      byType,
    };
  }),
});
