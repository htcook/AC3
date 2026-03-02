import * as db from "../db";
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const validationSchedulerRouter = router({
  listSchedules: protectedProcedure.query(async () => {
    const { validationSchedules } = await import("../../drizzle/schema");
    const { getDbRequired } = await import("../db");
    const { sql } = await import("drizzle-orm");
    const db = await getDbRequired();
    return db.select().from(validationSchedules).orderBy(sql`${validationSchedules.createdAt} DESC`);
  }),

  createSchedule: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      scheduleType: z.enum(["domain_scan", "emulation_run", "campaign_retest", "detection_validation"]),
      targetId: z.string().optional(),
      targetLabel: z.string().optional(),
      intervalHours: z.number().int().min(1).default(168),
      cronExpression: z.string().optional(),
      config: z.record(z.string(), z.any()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { validationSchedules } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const db = await getDbRequired();

      const nextRun = new Date(Date.now() + input.intervalHours * 3600_000);

      const [result] = await db.insert(validationSchedules).values({
        name: input.name,
        scheduleType: input.scheduleType,
        targetId: input.targetId ?? null,
        targetLabel: input.targetLabel ?? null,
        intervalHours: input.intervalHours,
        cronExpression: input.cronExpression ?? null,
        enabled: true,
        nextRunAt: nextRun,
        runCount: 0,
        config: input.config ?? null,
        createdBy: String(ctx.user.id),
      });

      return { id: result.insertId };
    }),

  toggleSchedule: protectedProcedure
    .input(z.object({
      id: z.number(),
      enabled: z.boolean(),
    }))
    .mutation(async ({ input }) => {
      const { validationSchedules } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const db = await getDbRequired();

      await db.update(validationSchedules)
        .set({ enabled: input.enabled })
        .where(eq(validationSchedules.id, input.id));

      return { ok: true };
    }),

  deleteSchedule: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { validationSchedules } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const db = await getDbRequired();

      await db.delete(validationSchedules).where(eq(validationSchedules.id, input.id));
      return { ok: true };
    }),

  getSchedule: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { validationSchedules } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const db = await getDbRequired();

      const [schedule] = await db.select().from(validationSchedules)
        .where(eq(validationSchedules.id, input.id)).limit(1);
      if (!schedule) throw new TRPCError({ code: "NOT_FOUND" });
      return schedule;
    }),
});
