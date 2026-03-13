import * as db from "../db";
import { CALDERA_BASE_URL, CALDERA_API_KEY } from "../lib/api-helpers";
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
    .input(z.object({ id: z.number(), agentPaw: z.string().optional() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { aiAttackPlans } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");

      // 1. Fetch the plan
      const plans = await db.select().from(aiAttackPlans).where(eq(aiAttackPlans.id, input.id));
      if (!plans[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Attack plan not found" });
      const plan = plans[0];
      const generatedPlan = plan.generatedPlan ? JSON.parse(plan.generatedPlan as string) : null;
      if (!generatedPlan) throw new TRPCError({ code: "BAD_REQUEST", message: "Plan has no generated content" });

      // 2. Extract MITRE technique IDs from the plan phases
      const techniqueIds: string[] = [];
      for (const phase of generatedPlan.phases || []) {
        for (const step of phase.steps || []) {
          if (step.techniqueId) techniqueIds.push(step.techniqueId);
          else if (step.technique_id) techniqueIds.push(step.technique_id);
        }
      }

      // 3. Try to create a live Cyber C2 operation
      const CALDERA_BASE_URL = process.env.CALDERA_BASE_URL;
      const CALDERA_API_KEY = process.env.CALDERA_API_KEY;
      let calderaOperationId: string | null = null;
      let calderaAdversaryId: string | null = null;
      let matchedAbilities = 0;

      if (CALDERA_BASE_URL && CALDERA_API_KEY) {
        try {
          // 3a. Fetch all emulation abilities to map technique IDs
          const abilitiesRes = await fetch(`${CALDERA_BASE_URL}/api/v2/abilities`, {
            headers: { "KEY": CALDERA_API_KEY },
            signal: AbortSignal.timeout(15000),
          });
          if (abilitiesRes.ok) {
            const allAbilities: any[] = await abilitiesRes.json();
            // Map technique IDs to ability IDs (pick best ability per technique)
            const abilityIds: string[] = [];
            for (const tid of techniqueIds) {
              const matching = allAbilities.filter((a: any) => a.technique_id === tid);
              if (matching.length > 0) {
                // Prefer abilities with executors for common platforms
                const best = matching.find((a: any) =>
                  a.executors?.some((e: any) => ["sh", "psh", "cmd", "bash"].includes(e.platform))
                ) || matching[0];
                abilityIds.push(best.ability_id);
                matchedAbilities++;
              }
            }

            if (abilityIds.length > 0) {
              // 3b. Create adversary profile from matched abilities
              const adversaryPayload = {
                name: `AceC3-Plan-${plan.id}-${plan.name?.slice(0, 30) || "AutoGen"}`,
                description: `Auto-generated from AI Attack Plan #${plan.id}: ${generatedPlan.summary?.slice(0, 100) || ""}`,
                atomic_ordering: abilityIds,
              };
              const advRes = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
                method: "POST",
                headers: { "KEY": CALDERA_API_KEY, "Content-Type": "application/json" },
                body: JSON.stringify(adversaryPayload),
                signal: AbortSignal.timeout(15000),
              });
              if (advRes.ok) {
                const adversary = await advRes.json();
                calderaAdversaryId = adversary.adversary_id;

                // 3c. Create operation
                const opPayload = {
                  name: `${plan.name || "AI Plan"} - ${new Date().toISOString().slice(0, 16)}`,
                  adversary: { adversary_id: adversary.adversary_id },
                  auto_close: false,
                  state: "paused",
                  ...(input.agentPaw ? { group: "", paw: input.agentPaw } : {}),
                };
                const opRes = await fetch(`${CALDERA_BASE_URL}/api/v2/operations`, {
                  method: "POST",
                  headers: { "KEY": CALDERA_API_KEY, "Content-Type": "application/json" },
                  body: JSON.stringify(opPayload),
                  signal: AbortSignal.timeout(15000),
                });
                if (opRes.ok) {
                  const operation = await opRes.json();
                  calderaOperationId = operation.id;
                }
              }
            }
          }
        } catch (err) {
          console.error("[AttackPlanner] Caldera integration error:", err);
        }
      }

      // 4. Update plan status
      await db.update(aiAttackPlans).set({
        status: calderaOperationId ? "executing" : "ready",
        acceptedAt: new Date(),
      }).where(eq(aiAttackPlans.id, input.id));

      return {
        success: true,
        calderaOperationId,
        calderaAdversaryId,
        matchedAbilities,
        totalTechniques: techniqueIds.length,
        calderaAvailable: !!(CALDERA_BASE_URL && CALDERA_API_KEY),
        message: calderaOperationId
          ? `Operation created in Caldera with ${matchedAbilities}/${techniqueIds.length} techniques mapped to abilities. Operation is paused — start it from the Caldera UI or assign an agent.`
          : CALDERA_BASE_URL
            ? `Plan accepted. ${matchedAbilities} abilities matched but operation creation failed. Check Caldera connectivity.`
            : "Plan accepted locally. Cyber C2 not configured — set CALDERA_BASE_URL and CALDERA_API_KEY to enable live operations.",
      };
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

  exportReport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { aiAttackPlans } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const plans = await db.select().from(aiAttackPlans).where(eq(aiAttackPlans.id, input.id));
      if (!plans[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Plan not found" });
      const plan = plans[0];
      const generatedPlan = plan.generatedPlan ? JSON.parse(plan.generatedPlan as string) : {};
      const { generateAttackPlanReport } = await import("../lib/pdf-report-generator");
      const html = generateAttackPlanReport({ ...generatedPlan, name: plan.name });
      return { html, filename: `attack-plan-${plan.id}-${Date.now()}.html` };
    }),

  /** Poll live Cyber C2 operation status — returns ability execution progress */
  operationStatus: protectedProcedure
    .input(z.object({ operationId: z.string() }))
    .query(async ({ input }) => {
      const CALDERA_BASE_URL = process.env.CALDERA_BASE_URL;
      const CALDERA_API_KEY = process.env.CALDERA_API_KEY;
      if (!CALDERA_BASE_URL || !CALDERA_API_KEY) {
        return { available: false, state: "unknown" as const, progress: 0, totalAbilities: 0, completedAbilities: 0, succeededAbilities: 0, failedAbilities: 0, queuedAbilities: 0, operationName: "", startedAt: null, abilities: [] as any[], message: "Cyber C2 not configured" };
      }
      try {
        const opRes = await fetch(`${CALDERA_BASE_URL}/api/v2/operations/${input.operationId}`, {
          headers: { "KEY": CALDERA_API_KEY },
          signal: AbortSignal.timeout(10000),
        });
        if (!opRes.ok) {
          return { available: true, state: "error" as const, progress: 0, totalAbilities: 0, completedAbilities: 0, succeededAbilities: 0, failedAbilities: 0, queuedAbilities: 0, operationName: "", startedAt: null, abilities: [], message: `Caldera returned ${opRes.status}: ${opRes.statusText}` };
        }
        const operation = await opRes.json();
        const chain: any[] = operation.chain || [];
        const adversary = operation.adversary || {};
        const totalAbilities = adversary.atomic_ordering?.length || chain.length || 1;
        const completed = chain.filter((l: any) => l.status !== undefined && l.status !== -3);
        const succeeded = chain.filter((l: any) => l.status === 0);
        const failed = chain.filter((l: any) => l.status !== 0 && l.status !== -3 && l.status !== undefined);
        const queued = chain.filter((l: any) => l.status === -3 || l.status === undefined);
        const progress = totalAbilities > 0 ? Math.round((completed.length / totalAbilities) * 100) : 0;
        const abilities = chain.map((link: any) => ({
          abilityId: link.ability?.ability_id || link.ability_id || "unknown",
          abilityName: link.ability?.name || link.name || "Unknown Ability",
          techniqueId: link.ability?.technique_id || "",
          techniqueName: link.ability?.technique_name || "",
          status: link.status === 0 ? "success" : link.status === -3 ? "queued" : link.status === -2 ? "discarded" : link.status === 1 ? "failed" : link.status === 124 ? "timeout" : link.status === -1 ? "running" : "unknown",
          paw: link.paw || "",
          output: link.output ? Buffer.from(link.output, "base64").toString("utf-8").slice(0, 500) : "",
          startedAt: link.decide || null,
          finishedAt: link.finish || null,
        }));
        let state: "running" | "paused" | "finished" | "cleanup" | "error" | "unknown" = "unknown";
        if (operation.state === "running") state = "running";
        else if (operation.state === "paused") state = "paused";
        else if (operation.state === "finished" || operation.state === "cleanup") state = "finished";
        return {
          available: true, state, progress, totalAbilities, completedAbilities: completed.length, succeededAbilities: succeeded.length, failedAbilities: failed.length, queuedAbilities: queued.length, operationName: operation.name || "", startedAt: operation.start || null, abilities,
          message: state === "finished" ? `Operation complete: ${succeeded.length} succeeded, ${failed.length} failed out of ${totalAbilities} abilities.` : state === "running" ? `Running: ${completed.length}/${totalAbilities} abilities executed (${progress}%)` : state === "paused" ? `Paused: ${completed.length}/${totalAbilities} abilities executed. Start the operation to continue.` : `Status: ${operation.state || "unknown"}`,
        };
      } catch (err: any) {
        return { available: true, state: "error" as const, progress: 0, totalAbilities: 0, completedAbilities: 0, succeededAbilities: 0, failedAbilities: 0, queuedAbilities: 0, operationName: "", startedAt: null, abilities: [], message: `Failed to poll Caldera: ${err.message}` };
      }
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
