import * as db from "../db";
import { CALDERA_BASE_URL, CALDERA_API_KEY } from "../lib/api-helpers";
/**
 * Adversary Emulation Playbooks Router
 * Maps threat actor TTPs to Caldera abilities for one-click emulation operations.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}
import { emulationPlaybooks, playbookExecutions, threatActors, threatActorAbilities } from "../../drizzle/schema";
import { eq, desc, like, and, sql, inArray } from "drizzle-orm";
import crypto from "crypto";

function generateId() {
  return `pb_${crypto.randomBytes(8).toString("hex")}`;
}

export const emulationPlaybooksRouter = router({
  // ─── List playbooks ───
  list: protectedProcedure
    .input(z.object({
      search: z.string().optional(),
      status: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.search) {
        filters.push(like(emulationPlaybooks.name, `%${input.search}%`));
      }
      if (input?.status) {
        filters.push(eq(emulationPlaybooks.status, input.status));
      }
      const where = filters.length > 0 ? and(...filters) : undefined;
      const [items, countResult] = await Promise.all([
        db.select().from(emulationPlaybooks).where(where)
          .orderBy(desc(emulationPlaybooks.createdAt))
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(emulationPlaybooks).where(where),
      ]);
      return { items, total: Number(countResult[0]?.count ?? 0) };
    }),

  // ─── Get single playbook ───
  get: protectedProcedure
    .input(z.object({ playbookId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [playbook] = await db.select().from(emulationPlaybooks)
        .where(eq(emulationPlaybooks.id, Number(input.playbookId)));
      if (!playbook) throw new TRPCError({ code: "NOT_FOUND", message: "Playbook not found" });
      return { ...playbook, playbookId: String(playbook.id) };
    }),

  // ─── Generate playbook from threat actor ───
  generateFromActor: protectedProcedure
    .input(z.object({
      threatActorId: z.number(),
      name: z.string().min(1).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      // Get threat actor
      const [actor] = await db.select().from(threatActors)
        .where(eq(threatActors.id, input.threatActorId));
      if (!actor) throw new TRPCError({ code: "NOT_FOUND", message: "Threat actor not found" });

      // Get TTPs for this actor via threat_actor_abilities mapping
      const ttps = await db.select().from(threatActorAbilities)
        .where(eq(threatActorAbilities.actorId, actor.actorId));

      // Build phases from tactics
      const tacticOrder = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
      ];

      const phaseMap = new Map<string, any[]>();
      for (const ttp of ttps) {
        const tactic = (ttp.tactic || "execution").toLowerCase();
        if (!phaseMap.has(tactic)) phaseMap.set(tactic, []);
        phaseMap.get(tactic)!.push({
          techniqueId: ttp.techniqueId,
          techniqueName: ttp.techniqueName,
          description: ttp.description,
          abilityId: ttp.abilityId,
        });
      }

      const phases = tacticOrder
        .filter(t => phaseMap.has(t))
        .map((tactic, idx) => ({
          order: idx + 1,
          tactic,
          techniques: phaseMap.get(tactic) || [],
        }));

      // Collect ability IDs
      const abilityIds = ttps
        .map(t => t.abilityId)
        .filter(Boolean);

      const playbookId = generateId();
      const playbookName = input.name || `${actor.name} Emulation Playbook`;

      // Estimate difficulty based on TTP count and diversity
      const difficulty = ttps.length > 20 ? "advanced" : ttps.length > 10 ? "intermediate" : "beginner";
      const estimatedDuration = Math.max(30, ttps.length * 5); // minutes

      await db.insert(emulationPlaybooks).values({
        name: playbookName,
        description: `Adversary emulation playbook based on ${actor.name} TTPs. Contains ${ttps.length} techniques across ${phases.length} kill chain phases.`,
        actorId: actor.actorId,
        actorName: actor.name,
        phases: JSON.stringify(phases),
        tacticsUsed: JSON.stringify(tacticOrder.filter(t => phaseMap.has(t))),
        techniquesUsed: JSON.stringify(abilityIds),
        totalAbilities: abilityIds.length,
        status: "draft",
        difficulty,
        estimatedDuration,
        tags: JSON.stringify([actor.name, "auto-generated"]),
        createdBy: ctx.user.id,
      });

      const [inserted] = await db.select({ id: emulationPlaybooks.id }).from(emulationPlaybooks).where(eq(emulationPlaybooks.name, playbookName)).orderBy(desc(emulationPlaybooks.id)).limit(1);
      return { playbookId: String(inserted?.id ?? 0), name: playbookName, phases: phases.length, techniques: ttps.length };
    }),

  // ─── Create manual playbook ───
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      threatActorName: z.string().optional(),
      phases: z.any().optional(),
      abilityIds: z.array(z.string()).optional(),
      difficulty: z.string().optional(),
      estimatedDuration: z.number().optional(),
      tags: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.insert(emulationPlaybooks).values({
        name: input.name,
        description: input.description,
        actorName: input.threatActorName,
        phases: input.phases ? JSON.stringify(input.phases) : null,
        techniquesUsed: input.abilityIds ? JSON.stringify(input.abilityIds) : null,
        status: "draft",
        difficulty: input.difficulty,
        estimatedDuration: input.estimatedDuration,
        tags: input.tags ? JSON.stringify(input.tags) : null,
        createdBy: ctx.user.id,
      });
      const [inserted] = await db.select({ id: emulationPlaybooks.id }).from(emulationPlaybooks).where(eq(emulationPlaybooks.name, input.name)).orderBy(desc(emulationPlaybooks.id)).limit(1);
      return { playbookId: String(inserted?.id ?? 0) };
    }),

  // ─── Update playbook ───
  update: protectedProcedure
    .input(z.object({
      playbookId: z.string(),
      name: z.string().optional(),
      description: z.string().optional(),
      status: z.string().optional(),
      phases: z.any().optional(),
      abilityIds: z.array(z.string()).optional(),
      difficulty: z.string().optional(),
      estimatedDuration: z.number().optional(),
      tags: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const updates: any = {};
      if (input.name !== undefined) updates.name = input.name;
      if (input.description !== undefined) updates.description = input.description;
      if (input.status !== undefined) updates.status = input.status;
      if (input.phases !== undefined) updates.phases = JSON.stringify(input.phases);
      if (input.abilityIds !== undefined) updates.techniquesUsed = JSON.stringify(input.abilityIds);
      if (input.difficulty !== undefined) updates.difficulty = input.difficulty;
      if (input.estimatedDuration !== undefined) updates.estimatedDuration = input.estimatedDuration;
      if (input.tags !== undefined) updates.tags = JSON.stringify(input.tags);

      await db.update(emulationPlaybooks)
        .set(updates)
        .where(eq(emulationPlaybooks.id, Number(input.playbookId)));
      return { success: true };
    }),

  // ─── Delete playbook ───
  delete: protectedProcedure
    .input(z.object({ playbookId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(emulationPlaybooks)
        .where(eq(emulationPlaybooks.id, Number(input.playbookId)));
      return { success: true };
    }),

  // ─── Launch playbook as Caldera operation ───
  launch: protectedProcedure
    .input(z.object({
      playbookId: z.string(),
      agentPaw: z.string().optional(),
      engagementId: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ─── ROE Enforcement (RED tier) + Scope Guard ───
      const { enforceROE, getEngagementROE, logOffensiveAction } = await import("../lib/roe-guard");
      if (input.engagementId) {
        const roe = await getEngagementROE(Number(input.engagementId));
        if (roe) enforceROE(roe, 'red', `Caldera emulation playbook launch: ${input.playbookId}`);
        // Enhanced: also validate testing window and ROE expiry via scope guard
        try {
          const { checkTestingWindow, loadEngagementScope } = await import("../lib/scope-guard");
          const scope = await loadEngagementScope(Number(input.engagementId));
          if (scope) {
            const windowCheck = checkTestingWindow(scope);
            if (!windowCheck.allowed) {
              throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Emulation blocked: ${windowCheck.reason}` });
            }
          }
        } catch (e: any) {
          if (e?.code === "PRECONDITION_FAILED") throw e;
          // Non-blocking if scope guard fails to load
        }
      }

      const db = await getDbSafe();
      const [playbook] = await db.select().from(emulationPlaybooks)
        .where(eq(emulationPlaybooks.id, Number(input.playbookId)));
      if (!playbook) throw new TRPCError({ code: "NOT_FOUND", message: "Playbook not found" });

      // Log the offensive action
      logOffensiveAction({
        engagementId: input.engagementId ? Number(input.engagementId) : null,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name ?? null,
        actionType: 'caldera_operation',
        riskTier: 'red',
        target: `playbook:${playbook.name}`,
        moduleOrTool: `Caldera Emulation: ${playbook.name}`,
        resultStatus: 'success',
      }).catch(() => {});

      // Create execution record
      await db.insert(playbookExecutions).values({
        playbookId: playbook.id,
        playbookName: playbook.name,
        execStatus: "pending",
        launchedBy: ctx.user.openId,
      });

      // Try to launch via Caldera API
      const CALDERA_BASE_URL = process.env.CALDERA_BASE_URL;
      const CALDERA_API_KEY = process.env.CALDERA_API_KEY;

      if (CALDERA_BASE_URL && CALDERA_API_KEY) {
        try {
          // First create adversary profile if not exists
            const abilityIds = Array.isArray(playbook.techniquesUsed)
            ? playbook.techniquesUsed
            : JSON.parse((playbook.techniquesUsed as string) || "[]");

          const adversaryPayload = {
            name: playbook.name,
            description: playbook.description || `Auto-generated from playbook ${playbook.id}`,
            atomic_ordering: abilityIds,
          };

          const advRes = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: "POST",
            headers: {
              "KEY": CALDERA_API_KEY,
              "Content-Type": "application/json",
            },
            body: JSON.stringify(adversaryPayload),
            signal: AbortSignal.timeout(15000),
          });

          if (advRes.ok) {
            const adversary = await advRes.json();
            const opPayload = {
              name: `${playbook.name} - ${new Date().toISOString().slice(0, 16)}`,
              adversary: { adversary_id: adversary.adversary_id },
              auto_close: false,
              state: "running",
              ...(input.agentPaw ? { group: "", paw: input.agentPaw } : {}),
            };

            const opRes = await fetch(`${CALDERA_BASE_URL}/api/v2/operations`, {
              method: "POST",
              headers: {
                "KEY": CALDERA_API_KEY,
                "Content-Type": "application/json",
              },
              body: JSON.stringify(opPayload),
              signal: AbortSignal.timeout(15000),
            });

            if (opRes.ok) {
              const operation = await opRes.json();
              await db.update(emulationPlaybooks)
                .set({
                  calderaAdversaryId: adversary.adversary_id,
                  status: "active",
                })
                .where(eq(emulationPlaybooks.id, Number(input.playbookId)));

              return { operationId: operation.id, status: "running" };
            }
          }
        } catch (err) {
          console.error("[Playbook Launch] Caldera API error:", err);
        }
      }

      // If Caldera not available, mark as pending
      return { operationId: null, status: "pending" };
    }),

  // ─── List executions ───
  listExecutions: protectedProcedure
    .input(z.object({
      playbookId: z.string().optional(),
      limit: z.number().min(1).max(100).default(20),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.playbookId) {
        filters.push(eq(playbookExecutions.playbookId, Number(input.playbookId)));
      }
      const where = filters.length > 0 ? and(...filters) : undefined;
      return db.select().from(playbookExecutions)
        .where(where)
        .orderBy(desc(playbookExecutions.createdAt))
        .limit(input?.limit ?? 20);
    }),

  // ─── Stats ───
  stats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [playbookCount] = await db.select({ count: sql<number>`count(*)` }).from(emulationPlaybooks);
    const [execCount] = await db.select({ count: sql<number>`count(*)` }).from(playbookExecutions);
    const [activeCount] = await db.select({ count: sql<number>`count(*)` }).from(emulationPlaybooks)
      .where(eq(emulationPlaybooks.status, "active"));
    const [draftCount] = await db.select({ count: sql<number>`count(*)` }).from(emulationPlaybooks)
      .where(eq(emulationPlaybooks.status, "draft"));
    return {
      totalPlaybooks: Number(playbookCount?.count ?? 0),
      totalExecutions: Number(execCount?.count ?? 0),
      activePlaybooks: Number(activeCount?.count ?? 0),
      draftPlaybooks: Number(draftCount?.count ?? 0),
    };
  }),
});
