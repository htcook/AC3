/**
 * Scheduled CSPM Scans Router
 * CRUD for recurring Prowler/ScoutSuite/Trivy scan schedules.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { scheduledCspmScans } from "../../drizzle/schema";
import { eq, desc, and } from "drizzle-orm";
import {
  startCspmScheduler,
  stopCspmScheduler,
  getCspmSchedulerStatus,
  validateCronExpression,
  getNextRunTime,
} from "../lib/cspm-scan-scheduler";

export const cspmScheduledScansRouter = router({
  /** List all scheduled scans */
  list: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      activeOnly: z.boolean().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const conditions = [];
      if (input?.engagementId) conditions.push(eq(scheduledCspmScans.engagementId, input.engagementId));
      if (input?.activeOnly) conditions.push(eq(scheduledCspmScans.isActive, 1));

      const where = conditions.length > 0 ? and(...conditions) : undefined;
      return db.select().from(scheduledCspmScans).where(where).orderBy(desc(scheduledCspmScans.createdAt));
    }),

  /** Create a new scheduled scan */
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      credentialId: z.number(),
      engagementId: z.number().optional(),
      scanTool: z.enum(["prowler", "scoutsuite", "trivy"]),
      cronExpression: z.string().min(5).max(64),
      services: z.array(z.string()).optional(),
      complianceFramework: z.string().optional(),
      timeoutSeconds: z.number().min(60).max(3600).default(600),
    }))
    .mutation(async ({ input, ctx }) => {
      if (!validateCronExpression(input.cronExpression)) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Invalid cron expression" });
      }

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const now = Date.now();
      const nextRun = getNextRunTime(input.cronExpression);

      const [result] = await db.insert(scheduledCspmScans).values({
        name: input.name,
        credentialId: input.credentialId,
        engagementId: input.engagementId ?? null,
        scanTool: input.scanTool,
        cronExpression: input.cronExpression,
        isActive: 1,
        services: input.services ?? null,
        complianceFramework: input.complianceFramework ?? null,
        timeoutSeconds: input.timeoutSeconds,
        nextRunAt: nextRun,
        createdBy: ctx.user?.name || ctx.user?.openId || "unknown",
        createdAt: now,
        updatedAt: now,
      });

      return { id: (result as any).insertId, success: true };
    }),

  /** Update a scheduled scan */
  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      name: z.string().min(1).max(255).optional(),
      cronExpression: z.string().min(5).max(64).optional(),
      isActive: z.boolean().optional(),
      services: z.array(z.string()).optional(),
      complianceFramework: z.string().optional(),
      timeoutSeconds: z.number().min(60).max(3600).optional(),
    }))
    .mutation(async ({ input }) => {
      if (input.cronExpression && !validateCronExpression(input.cronExpression)) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Invalid cron expression" });
      }

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const updates: any = { updatedAt: Date.now() };
      if (input.name !== undefined) updates.name = input.name;
      if (input.cronExpression !== undefined) {
        updates.cronExpression = input.cronExpression;
        updates.nextRunAt = getNextRunTime(input.cronExpression);
      }
      if (input.isActive !== undefined) updates.isActive = input.isActive ? 1 : 0;
      if (input.services !== undefined) updates.services = input.services;
      if (input.complianceFramework !== undefined) updates.complianceFramework = input.complianceFramework;
      if (input.timeoutSeconds !== undefined) updates.timeoutSeconds = input.timeoutSeconds;

      await db.update(scheduledCspmScans).set(updates).where(eq(scheduledCspmScans.id, input.id));
      return { success: true };
    }),

  /** Delete a scheduled scan */
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      await db.delete(scheduledCspmScans).where(eq(scheduledCspmScans.id, input.id));
      return { success: true };
    }),

  /** Toggle active state */
  toggleActive: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [schedule] = await db.select().from(scheduledCspmScans).where(eq(scheduledCspmScans.id, input.id));
      if (!schedule) throw new TRPCError({ code: "NOT_FOUND", message: "Schedule not found" });

      const newActive = schedule.isActive === 1 ? 0 : 1;
      const updates: any = { isActive: newActive, updatedAt: Date.now() };
      if (newActive === 1) {
        updates.nextRunAt = getNextRunTime(schedule.cronExpression);
      }

      await db.update(scheduledCspmScans).set(updates).where(eq(scheduledCspmScans.id, input.id));
      return { isActive: newActive === 1 };
    }),

  /** Get scheduler status */
  getSchedulerStatus: protectedProcedure.query(() => {
    return getCspmSchedulerStatus();
  }),

  /** Start the scheduler */
  startScheduler: protectedProcedure.mutation(() => {
    startCspmScheduler();
    return { success: true, status: getCspmSchedulerStatus() };
  }),

  /** Stop the scheduler */
  stopScheduler: protectedProcedure.mutation(() => {
    stopCspmScheduler();
    return { success: true, status: getCspmSchedulerStatus() };
  }),

  /** Common cron presets */
  getCronPresets: protectedProcedure.query(() => {
    return [
      { label: "Every hour", value: "0 * * * *", description: "Runs at the start of every hour" },
      { label: "Every 6 hours", value: "0 */6 * * *", description: "Runs every 6 hours" },
      { label: "Every 12 hours", value: "0 */12 * * *", description: "Runs twice daily" },
      { label: "Daily at midnight", value: "0 0 * * *", description: "Runs once daily at midnight UTC" },
      { label: "Daily at 6 AM", value: "0 6 * * *", description: "Runs once daily at 6 AM UTC" },
      { label: "Weekly (Monday)", value: "0 0 * * 1", description: "Runs every Monday at midnight UTC" },
      { label: "Weekly (Friday)", value: "0 0 * * 5", description: "Runs every Friday at midnight UTC" },
      { label: "Monthly (1st)", value: "0 0 1 * *", description: "Runs on the 1st of every month" },
    ];
  }),
});
