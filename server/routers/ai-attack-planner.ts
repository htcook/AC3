import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const aiAttackPlannerRouter = router({
  list: protectedProcedure
    .input(z.object({ status: z.enum(["generating", "completed", "ready", "executing"]).optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { aiAttackPlans } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { desc, eq } = await import("drizzle-orm");
      if (input.status) {
        return db.select().from(aiAttackPlans).where(eq(aiAttackPlans.status, input.status)).orderBy(desc(aiAttackPlans.createdAt));
      }
      return db.select().from(aiAttackPlans).orderBy(desc(aiAttackPlans.createdAt));
    }),

  generate: protectedProcedure
    .input(z.object({
      name: z.string(),
      targetDescription: z.string(),
      threatActorProfile: z.string().optional(),
      environmentContext: z.string().optional(),
      constraints: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { aiAttackPlans } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const insertResult = await db.insert(aiAttackPlans).values({
        name: input.name,
        targetDescription: input.targetDescription,
        threatActorProfile: input.threatActorProfile || null,
        environmentContext: input.environmentContext || null,
        status: "generating",
        createdBy: String(ctx.user.id),
      });

      const planId = insertResult[0].insertId;

      try {
        const { generateAttackPlan } = await import("../lib/ai-attack-planner");
        const { invokeLLM } = await import("../_core/llm");
        const plan = await generateAttackPlan(
          {
            targetDescription: input.targetDescription,
            threatActorProfile: input.threatActorProfile,
          },
          invokeLLM
        );

        const { eq } = await import("drizzle-orm");
        await db.update(aiAttackPlans).set({
          generatedPlan: JSON.stringify(plan),
          attackSteps: JSON.stringify(plan.phases),
          estimatedRiskScore: plan.estimatedRiskScore,
          status: "completed",
        }).where(eq(aiAttackPlans.id, planId));

        return { id: planId, plan };
      } catch (err: any) {
        const { eq } = await import("drizzle-orm");
        await db.update(aiAttackPlans).set({ status: "generating" }).where(eq(aiAttackPlans.id, planId));
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: err.message || "AI generation failed" });
      }
    }),

  get: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { aiAttackPlans } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const result = await db.select().from(aiAttackPlans).where(eq(aiAttackPlans.id, input.id));
      if (!result[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Attack plan not found" });
      return result[0];
    }),

  accept: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { aiAttackPlans } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.update(aiAttackPlans).set({ status: "ready", acceptedAt: new Date() }).where(eq(aiAttackPlans.id, input.id));
      return { success: true };
    }),

  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { aiAttackPlans } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.delete(aiAttackPlans).where(eq(aiAttackPlans.id, input.id));
      return { success: true };
    }),

  listThreatActorProfiles: protectedProcedure.query(async () => {
    const { THREAT_ACTOR_PROFILES } = await import("../lib/ai-attack-planner");
    return THREAT_ACTOR_PROFILES;
  }),

  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { aiAttackPlans } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { count } = await import("drizzle-orm");
    const total = await db.select({ value: count() }).from(aiAttackPlans);
    return { total: total[0].value };
  }),
});
