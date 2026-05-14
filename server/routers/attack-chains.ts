import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { vulnAttackChains, vulnAttackChainSteps, riskRegisterEntries } from "../../drizzle/schema";
import { eq, and, or, like, sql, desc, asc, count, inArray } from "drizzle-orm";
import { randomUUID } from "crypto";

const SEV_SCORE: Record<string, number> = { critical: 10, high: 8, moderate: 5, low: 3, informational: 1 };

function computeCompositeScore(steps: { severity: string }[]): { score: number; severity: string } {
  if (steps.length === 0) return { score: 0, severity: "informational" };
  const maxSev = Math.max(...steps.map(s => SEV_SCORE[s.severity] || 1));
  const chainBonus = Math.min(steps.length * 0.5, 3);
  let escalationBonus = 0;
  for (let i = 1; i < steps.length; i++) {
    if ((SEV_SCORE[steps[i].severity] || 1) > (SEV_SCORE[steps[i - 1].severity] || 1)) escalationBonus += 0.5;
  }
  const composite = Math.min(maxSev + chainBonus + escalationBonus, 10);
  const severity = composite >= 9 ? "critical" : composite >= 7 ? "high" : composite >= 4 ? "moderate" : composite >= 2 ? "low" : "informational";
  return { score: Math.round(composite * 10) / 10, severity };
}

async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

export const attackChainsRouter = router({
  list: protectedProcedure
    .input(z.object({
      page: z.number().min(1).default(1),
      pageSize: z.number().min(1).max(100).default(25),
      status: z.string().optional(),
      severity: z.string().optional(),
      search: z.string().optional(),
      sortBy: z.enum(["createdAt", "compositeRiskScore", "compositeSeverity", "name"]).default("compositeRiskScore"),
      sortDir: z.enum(["asc", "desc"]).default("desc"),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const { page, pageSize, status, severity, search, sortBy, sortDir } = input;
      const conditions: any[] = [];
      if (status) conditions.push(eq(vulnAttackChains.status, status as any));
      if (severity) conditions.push(eq(vulnAttackChains.compositeSeverity, severity as any));
      if (search) conditions.push(or(like(vulnAttackChains.name, `%${search}%`), like(vulnAttackChains.chainId, `%${search}%`), like(vulnAttackChains.entryPoint, `%${search}%`)));
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const sortCol = sortBy === "compositeRiskScore" ? vulnAttackChains.compositeRiskScore : sortBy === "compositeSeverity" ? vulnAttackChains.compositeSeverity : sortBy === "name" ? vulnAttackChains.name : vulnAttackChains.createdAt;
      const orderFn = sortDir === "asc" ? asc : desc;
      const [items, [{ total }]] = await Promise.all([
        db.select().from(vulnAttackChains).where(where).orderBy(orderFn(sortCol)).limit(pageSize).offset((page - 1) * pageSize),
        db.select({ total: count() }).from(vulnAttackChains).where(where),
      ]);
      const chainIds = items.map(i => i.chainId);
      let stepCounts: Record<string, number> = {};
      if (chainIds.length > 0) {
        const counts = await db.select({ chainId: vulnAttackChainSteps.chainId, count: count() }).from(vulnAttackChainSteps).where(inArray(vulnAttackChainSteps.chainId, chainIds)).groupBy(vulnAttackChainSteps.chainId);
        stepCounts = Object.fromEntries(counts.map(c => [c.chainId, c.count]));
      }
      return { items: items.map(i => ({ ...i, stepCount: stepCounts[i.chainId] || 0 })), total, page, pageSize, totalPages: Math.ceil(total / pageSize) };
    }),

  get: protectedProcedure.input(z.object({ id: z.number() })).query(async ({ input }) => {
    const db = await requireDb();
    const [chain] = await db.select().from(vulnAttackChains).where(eq(vulnAttackChains.id, input.id));
    if (!chain) throw new TRPCError({ code: "NOT_FOUND", message: "Attack chain not found" });
    const steps = await db.select().from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, chain.chainId)).orderBy(asc(vulnAttackChainSteps.stepOrder));
    const linkedPoams = await db.select().from(riskRegisterEntries).where(eq(riskRegisterEntries.attackChainId, chain.chainId));
    return { ...chain, steps, linkedPoams };
  }),

  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1), description: z.string().optional(), entryPoint: z.string().optional(), finalTarget: z.string().optional(),
      impactDescription: z.string().optional(), mitreTechniques: z.array(z.string()).optional(), killChainPhases: z.array(z.string()).optional(),
      engagementId: z.number().optional(), sourceType: z.enum(["manual", "auto_correlated", "pentest", "red_team", "ctem"]).default("manual"),
      steps: z.array(z.object({
        title: z.string().min(1), description: z.string().optional(),
        findingType: z.enum(["vulnerability", "misconfiguration", "credential", "exposure", "social_engineering", "privilege_escalation", "lateral_movement", "data_access"]).default("vulnerability"),
        severity: z.enum(["critical", "high", "moderate", "low", "informational"]).default("moderate"),
        cveId: z.string().optional(), cweId: z.string().optional(), affectedAsset: z.string().optional(),
        mitreTechnique: z.string().optional(), mitreTactic: z.string().optional(), evidence: z.string().optional(),
      })),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const chainId = `CHAIN-${randomUUID().split("-")[0].toUpperCase()}`;
      const { score, severity } = computeCompositeScore(input.steps);
      const [result] = await db.insert(vulnAttackChains).values({
        chainId, name: input.name, description: input.description || null, compositeRiskScore: score, compositeSeverity: severity as any,
        entryPoint: input.entryPoint || null, finalTarget: input.finalTarget || null, impactDescription: input.impactDescription || null,
        mitreTechniques: input.mitreTechniques || null, killChainPhases: input.killChainPhases || null,
        engagementId: input.engagementId || null, sourceType: input.sourceType, createdBy: ctx.user.id,
      });
      for (let i = 0; i < input.steps.length; i++) {
        const s = input.steps[i];
        await db.insert(vulnAttackChainSteps).values({
          chainId, stepOrder: i + 1, title: s.title, description: s.description || null, findingType: s.findingType, severity: s.severity,
          cveId: s.cveId || null, cweId: s.cweId || null, affectedAsset: s.affectedAsset || null,
          mitreTechnique: s.mitreTechnique || null, mitreTactic: s.mitreTactic || null, evidence: s.evidence || null,
        });
      }
      return { id: result.insertId, chainId, compositeRiskScore: score, compositeSeverity: severity };
    }),

  update: protectedProcedure
    .input(z.object({
      id: z.number(), name: z.string().optional(), description: z.string().optional(), entryPoint: z.string().optional(),
      finalTarget: z.string().optional(), impactDescription: z.string().optional(),
      status: z.enum(["active", "mitigated", "accepted", "investigating"]).optional(),
      mitreTechniques: z.array(z.string()).optional(), killChainPhases: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { id, ...updates } = input;
      await db.update(vulnAttackChains).set(updates as any).where(eq(vulnAttackChains.id, id));
      return { success: true };
    }),

  addStep: protectedProcedure
    .input(z.object({
      chainId: z.string(), title: z.string().min(1), description: z.string().optional(),
      findingType: z.enum(["vulnerability", "misconfiguration", "credential", "exposure", "social_engineering", "privilege_escalation", "lateral_movement", "data_access"]).default("vulnerability"),
      severity: z.enum(["critical", "high", "moderate", "low", "informational"]).default("moderate"),
      cveId: z.string().optional(), cweId: z.string().optional(), affectedAsset: z.string().optional(),
      mitreTechnique: z.string().optional(), mitreTactic: z.string().optional(), evidence: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const existing = await db.select({ stepOrder: vulnAttackChainSteps.stepOrder }).from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, input.chainId)).orderBy(desc(vulnAttackChainSteps.stepOrder)).limit(1);
      const nextOrder = (existing[0]?.stepOrder || 0) + 1;
      const { chainId, ...stepData } = input;
      await db.insert(vulnAttackChainSteps).values({ chainId, stepOrder: nextOrder, ...stepData, description: stepData.description || null, cveId: stepData.cveId || null, cweId: stepData.cweId || null, affectedAsset: stepData.affectedAsset || null, mitreTechnique: stepData.mitreTechnique || null, mitreTactic: stepData.mitreTactic || null, evidence: stepData.evidence || null });
      const allSteps = await db.select({ severity: vulnAttackChainSteps.severity }).from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, chainId));
      const { score, severity } = computeCompositeScore(allSteps);
      await db.update(vulnAttackChains).set({ compositeRiskScore: score, compositeSeverity: severity as any }).where(eq(vulnAttackChains.chainId, chainId));
      return { stepOrder: nextOrder, compositeRiskScore: score, compositeSeverity: severity };
    }),

  removeStep: protectedProcedure
    .input(z.object({ stepId: z.number(), chainId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.delete(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.id, input.stepId));
      const allSteps = await db.select({ severity: vulnAttackChainSteps.severity }).from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, input.chainId));
      const { score, severity } = computeCompositeScore(allSteps);
      await db.update(vulnAttackChains).set({ compositeRiskScore: score, compositeSeverity: severity as any }).where(eq(vulnAttackChains.chainId, input.chainId));
      return { success: true, compositeRiskScore: score, compositeSeverity: severity };
    }),

  delete: protectedProcedure
    .input(z.object({ id: z.number(), chainId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.delete(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, input.chainId));
      await db.update(riskRegisterEntries).set({ attackChainId: null }).where(eq(riskRegisterEntries.attackChainId, input.chainId));
      await db.delete(vulnAttackChains).where(eq(vulnAttackChains.id, input.id));
      return { success: true };
    }),

  linkPoam: protectedProcedure
    .input(z.object({ chainId: z.string(), poamId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.update(riskRegisterEntries).set({ attackChainId: input.chainId }).where(eq(riskRegisterEntries.id, input.poamId));
      return { success: true };
    }),

  unlinkPoam: protectedProcedure
    .input(z.object({ poamId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.update(riskRegisterEntries).set({ attackChainId: null }).where(eq(riskRegisterEntries.id, input.poamId));
      return { success: true };
    }),

  recalculateScore: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const [chain] = await db.select().from(vulnAttackChains).where(eq(vulnAttackChains.id, input.id));
      if (!chain) throw new TRPCError({ code: "NOT_FOUND" });
      const steps = await db.select().from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, chain.chainId)).orderBy(asc(vulnAttackChainSteps.stepOrder));
      const sevMap: Record<string, number> = { critical: 10, high: 8, moderate: 5, low: 3, informational: 1 };
      if (steps.length === 0) {
        await db.update(vulnAttackChains).set({ compositeRiskScore: 0, compositeSeverity: "low" }).where(eq(vulnAttackChains.id, input.id));
        return { compositeRiskScore: 0, compositeSeverity: "low" };
      }
      const maxSev = Math.max(...steps.map(s => sevMap[s.severity] || 0));
      const avgSev = steps.reduce((sum, s) => sum + (sevMap[s.severity] || 0), 0) / steps.length;
      const chainLenBonus = Math.min(steps.length * 0.3, 2);
      const composite = Math.min(10, maxSev * 0.6 + avgSev * 0.25 + chainLenBonus + 0.15);
      const compSev = composite >= 9 ? "critical" : composite >= 7 ? "high" : composite >= 4 ? "moderate" : composite >= 2 ? "low" : "informational";
      await db.update(vulnAttackChains).set({ compositeRiskScore: Math.round(composite * 10) / 10, compositeSeverity: compSev }).where(eq(vulnAttackChains.id, input.id));
      return { compositeRiskScore: Math.round(composite * 10) / 10, compositeSeverity: compSev };
    }),

  summary: protectedProcedure.query(async () => {
    const db = await requireDb();
    const allChains = await db.select().from(vulnAttackChains);
    const active = allChains.filter(c => c.status === "active");
    const bySeverity = ["critical", "high", "moderate", "low", "informational"].map(sev => ({ severity: sev, count: active.filter(c => c.compositeSeverity === sev).length }));
    const topChains = active.sort((a, b) => (b.compositeRiskScore || 0) - (a.compositeRiskScore || 0)).slice(0, 5);
    return {
      totalActive: active.length, totalMitigated: allChains.filter(c => c.status === "mitigated").length, bySeverity,
      topChains: topChains.map(c => ({ id: c.id, chainId: c.chainId, name: c.name, compositeRiskScore: c.compositeRiskScore, compositeSeverity: c.compositeSeverity, entryPoint: c.entryPoint, finalTarget: c.finalTarget })),
    };
  }),
});
