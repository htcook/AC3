/**
 * Hunt Workflow Engine Router — DHS/GSA HACS-Compliant Threat Hunting
 * ═══════════════════════════════════════════════════════════════════
 * Exposes the Prepare → Execute → Act hunt state machine via tRPC.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { huntSessions, huntHypotheses } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import {
  generateHypotheses,
  evaluateEvidence,
  generateDeliverable,
  translateSigmaToSiem,
  generateBaselineQuery,
  mapHuntToNiceKsas,
  NICE_KSAS,
  type HuntContext,
  type HuntHypothesis as HuntHypothesisType,
  type HuntFinding,
} from "../lib/hunt-engine";

async function getDbSafe() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

export const huntEngineRouter = router({
  // ─── CREATE HUNT SESSION ────────────────────────────────────────────
  createSession: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      engagementId: z.number().optional(),
      huntType: z.enum(["hypothesis_driven", "baseline", "model_assisted"]).default("hypothesis_driven"),
      siemPlatform: z.enum(["splunk", "elastic", "sentinel", "qradar", "chronicle", "other"]).default("splunk"),
      dataSources: z.array(z.string()).default([]),
      targetEnvironment: z.string().optional(),
      threatActorId: z.string().optional(),
      threatActorName: z.string().optional(),
      mitreTechniques: z.array(z.object({
        id: z.string(),
        name: z.string(),
        tactic: z.string(),
      })).optional(),
      scopeConstraints: z.any().optional(),
      priority: z.enum(["critical", "high", "medium", "low"]).default("medium"),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(huntSessions).values({
        huntName: input.name,
        huntDescription: input.description || null,
        engagementId: input.engagementId || null,
        huntPhase: "prepare",
        huntType: input.huntType,
        siemPlatform: input.siemPlatform,
        dataSources: input.dataSources,
        targetEnvironment: input.targetEnvironment || null,
        threatActorId: input.threatActorId || null,
        threatActorName: input.threatActorName || null,
        mitreTechniques: input.mitreTechniques || null,
        scopeConstraints: input.scopeConstraints || null,
        huntPriority: input.priority,
        createdById: ctx.user.id,
        createdByName: ctx.user.name || ctx.user.openId,
      });
      return { id: (result as any).insertId, phase: "prepare" };
    }),

  // ─── LIST HUNT SESSIONS ────────────────────────────────────────────
  listSessions: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      phase: z.enum(["prepare", "execute", "act", "completed", "cancelled"]).optional(),
      limit: z.number().default(20),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.engagementId) conditions.push(eq(huntSessions.engagementId, input.engagementId));
      if (input.phase) conditions.push(eq(huntSessions.huntPhase, input.phase));

      const rows = await db.select().from(huntSessions)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(huntSessions.huntCreatedAt))
        .limit(input.limit);
      return rows;
    }),

  // ─── GET HUNT SESSION DETAIL ───────────────────────────────────────
  getSession: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [session] = await db.select().from(huntSessions).where(eq(huntSessions.id, input.id));
      if (!session) return null;

      const hyps = await db.select().from(huntHypotheses)
        .where(eq(huntHypotheses.huntSessionId, input.id))
        .orderBy(huntHypotheses.hypothesisPriority);

      return { ...session, hypotheses: hyps };
    }),

  // ─── PREPARE PHASE: Generate Hypotheses ────────────────────────────
  generateHypotheses: protectedProcedure
    .input(z.object({
      sessionId: z.number(),
      orgName: z.string(),
      orgSector: z.string(),
      maxHypotheses: z.number().default(10),
      knownAssets: z.array(z.object({
        hostname: z.string(),
        ip: z.string().optional(),
        assetType: z.string(),
        technologies: z.array(z.string()).optional(),
        role: z.string().optional(),
      })).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [session] = await db.select().from(huntSessions).where(eq(huntSessions.id, input.sessionId));
      if (!session) throw new Error("Hunt session not found");
      if (session.huntPhase !== "prepare") throw new Error(`Cannot generate hypotheses in ${session.huntPhase} phase`);

      const huntCtx: HuntContext = {
        sessionId: session.id,
        orgName: input.orgName,
        orgSector: input.orgSector,
        siemPlatform: (session.siemPlatform as any) || "splunk",
        dataSources: (session.dataSources as string[]) || [],
        threatActor: session.threatActorId ? {
          id: session.threatActorId,
          name: session.threatActorName || "",
        } : undefined,
        mitreTechniques: (session.mitreTechniques as any[]) || undefined,
        scope: (session.scopeConstraints as any) || undefined,
        knownAssets: input.knownAssets,
        huntType: session.huntType as any,
        priority: session.huntPriority as any,
      };

      const hypotheses = await generateHypotheses(huntCtx, input.maxHypotheses);

      // Persist hypotheses to DB
      for (const h of hypotheses) {
        await db.insert(huntHypotheses).values({
          huntSessionId: session.id,
          hypothesisStatement: h.statement,
          hypothesisStatus: "pending",
          hypothesisConfidence: h.confidence,
          mitreTechniqueId: h.mitreTechniqueId || null,
          mitreTechniqueName: h.mitreTechniqueName || null,
          mitreTactic: h.mitreTactic || null,
          requiredDataSources: h.requiredDataSources,
          sigmaRule: h.sigmaRule || null,
          splQuery: h.splQuery || null,
          kqlQuery: h.kqlQuery || null,
          attackChainRef: h.attackChainRef || null,
          bugBountyPatternRef: h.bugBountyPatternRef || null,
          hypothesisPriority: h.priority,
        });
      }

      // Update session
      await db.update(huntSessions)
        .set({ hypothesisCount: hypotheses.length } as any)
        .where(eq(huntSessions.id, session.id));

      return { generated: hypotheses.length, hypotheses };
    }),

  // ─── EXECUTE PHASE: Advance to Execute ─────────────────────────────
  advanceToExecute: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [session] = await db.select().from(huntSessions).where(eq(huntSessions.id, input.sessionId));
      if (!session) throw new Error("Hunt session not found");
      if (session.huntPhase !== "prepare") throw new Error(`Cannot advance from ${session.huntPhase} to execute`);

      await db.update(huntSessions)
        .set({ huntPhase: "execute", startedAt: new Date() } as any)
        .where(eq(huntSessions.id, input.sessionId));

      return { phase: "execute" };
    }),

  // ─── EXECUTE PHASE: Submit Evidence for Hypothesis ─────────────────
  evaluateHypothesis: protectedProcedure
    .input(z.object({
      sessionId: z.number(),
      hypothesisId: z.number(),
      queryResults: z.array(z.any()),
      resultCount: z.number(),
      timeRange: z.string().default("last 30 days"),
      orgName: z.string(),
      orgSector: z.string(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [session] = await db.select().from(huntSessions).where(eq(huntSessions.id, input.sessionId));
      if (!session) throw new Error("Hunt session not found");
      if (session.huntPhase !== "execute") throw new Error(`Cannot evaluate in ${session.huntPhase} phase`);

      const [hypothesis] = await db.select().from(huntHypotheses).where(eq(huntHypotheses.id, input.hypothesisId));
      if (!hypothesis) throw new Error("Hypothesis not found");

      const huntCtx: HuntContext = {
        sessionId: session.id,
        orgName: input.orgName,
        orgSector: input.orgSector,
        siemPlatform: (session.siemPlatform as any) || "splunk",
        dataSources: (session.dataSources as string[]) || [],
        huntType: session.huntType as any,
        priority: session.huntPriority as any,
      };

      const hypInput: HuntHypothesisType = {
        statement: hypothesis.hypothesisStatement,
        mitreTechniqueId: hypothesis.mitreTechniqueId || "",
        mitreTechniqueName: hypothesis.mitreTechniqueName || "",
        mitreTactic: hypothesis.mitreTactic || "",
        requiredDataSources: (hypothesis.requiredDataSources as string[]) || [],
        sigmaRule: hypothesis.sigmaRule || undefined,
        splQuery: hypothesis.splQuery || undefined,
        kqlQuery: hypothesis.kqlQuery || undefined,
        confidence: hypothesis.hypothesisConfidence as any,
        priority: hypothesis.hypothesisPriority,
        reasoning: "",
      };

      const result = await evaluateEvidence(hypInput, {
        queryResults: input.queryResults,
        resultCount: input.resultCount,
        timeRange: input.timeRange,
        siemPlatform: session.siemPlatform || "splunk",
      }, huntCtx);

      // Update hypothesis in DB
      await db.update(huntHypotheses)
        .set({
          hypothesisStatus: result.status,
          hypothesisConfidence: result.confidence,
          analysisNotes: result.analysisNotes,
          evidence: input.queryResults.slice(0, 50),
          detectionRule: result.detectionRule || null,
          remediation: result.remediation || null,
          investigatedAt: new Date(),
          evaluatedAt: new Date(),
        })
        .where(eq(huntHypotheses.id, input.hypothesisId));

      // Update session counters
      if (result.status === "confirmed") {
        await db.update(huntSessions)
          .set({
            confirmedFindings: sql`confirmed_findings + ${result.findings.length}`,
            detectionRulesGenerated: result.detectionRule ? sql`detection_rules_generated + 1` : sql`detection_rules_generated`,
          })
          .where(eq(huntSessions.id, input.sessionId));
      }

      return result;
    }),

  // ─── ACT PHASE: Generate Deliverable ───────────────────────────────
  advanceToAct: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [session] = await db.select().from(huntSessions).where(eq(huntSessions.id, input.sessionId));
      if (!session) throw new Error("Hunt session not found");
      if (session.huntPhase !== "execute") throw new Error(`Cannot advance from ${session.huntPhase} to act`);

      await db.update(huntSessions)
        .set({ huntPhase: "act" } as any)
        .where(eq(huntSessions.id, input.sessionId));

      return { phase: "act" };
    }),

  generateDeliverable: protectedProcedure
    .input(z.object({
      sessionId: z.number(),
      orgName: z.string(),
      orgSector: z.string(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [session] = await db.select().from(huntSessions).where(eq(huntSessions.id, input.sessionId));
      if (!session) throw new Error("Hunt session not found");
      if (session.huntPhase !== "act") throw new Error(`Cannot generate deliverable in ${session.huntPhase} phase`);

      const hyps = await db.select().from(huntHypotheses)
        .where(eq(huntHypotheses.huntSessionId, input.sessionId));

      const huntCtx: HuntContext = {
        sessionId: session.id,
        orgName: input.orgName,
        orgSector: input.orgSector,
        siemPlatform: (session.siemPlatform as any) || "splunk",
        dataSources: (session.dataSources as string[]) || [],
        threatActor: session.threatActorId ? {
          id: session.threatActorId,
          name: session.threatActorName || "",
        } : undefined,
        huntType: session.huntType as any,
        priority: session.huntPriority as any,
      };

      // Collect all findings from confirmed hypotheses
      const findings: HuntFinding[] = [];
      for (const h of hyps.filter(h => h.hypothesisStatus === "confirmed")) {
        findings.push({
          title: `Confirmed: ${h.hypothesisStatement.slice(0, 80)}`,
          description: h.analysisNotes || h.hypothesisStatement,
          severity: h.hypothesisConfidence === "high" ? "high" : h.hypothesisConfidence === "medium" ? "medium" : "low",
          mitreTechniqueId: h.mitreTechniqueId || "",
          mitreTechniqueName: h.mitreTechniqueName || "",
          mitreTactic: h.mitreTactic || "",
          evidence: typeof h.evidence === "string" ? h.evidence : JSON.stringify(h.evidence || {}),
          affectedAssets: [],
          detectionRule: h.detectionRule || undefined,
          remediation: h.remediation || "",
          confidence: h.hypothesisConfidence as any,
        });
      }

      const deliverable = await generateDeliverable(
        huntCtx,
        hyps.map(h => ({
          statement: h.hypothesisStatement,
          mitreTechniqueId: h.mitreTechniqueId || "",
          mitreTechniqueName: h.mitreTechniqueName || "",
          mitreTactic: h.mitreTactic || "",
          requiredDataSources: (h.requiredDataSources as string[]) || [],
          confidence: h.hypothesisConfidence as any,
          priority: h.hypothesisPriority,
          reasoning: "",
          status: h.hypothesisStatus,
          analysisNotes: h.analysisNotes || undefined,
        })),
        findings
      );

      // Update session as completed
      await db.update(huntSessions)
        .set({
          huntPhase: "completed",
          completedAt: new Date(),
          findingsSummary: deliverable.executiveSummary,
        } as any)
        .where(eq(huntSessions.id, input.sessionId));

      return deliverable;
    }),

  // ─── CANCEL HUNT ───────────────────────────────────────────────────
  cancelSession: protectedProcedure
    .input(z.object({ sessionId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.update(huntSessions)
        .set({ huntPhase: "cancelled", completedAt: new Date() } as any)
        .where(eq(huntSessions.id, input.sessionId));
      return { cancelled: true };
    }),

  // ─── SIGMA TRANSLATION ─────────────────────────────────────────────
  translateSigma: protectedProcedure
    .input(z.object({
      sigmaRule: z.string(),
      targetPlatform: z.enum(["splunk", "elastic", "sentinel", "qradar", "chronicle"]),
    }))
    .mutation(async ({ input }) => {
      const translated = await translateSigmaToSiem(input.sigmaRule, input.targetPlatform);
      return { query: translated };
    }),

  // ─── BASELINE QUERY GENERATION ─────────────────────────────────────
  generateBaseline: protectedProcedure
    .input(z.object({
      dataSource: z.string(),
      siemPlatform: z.string(),
      timeWindow: z.string().default("7d"),
    }))
    .mutation(async ({ input }) => {
      return generateBaselineQuery(input.dataSource, input.siemPlatform, input.timeWindow);
    }),

  // ─── NICE KSA MAPPING ─────────────────────────────────────────────
  getNiceKsas: protectedProcedure.query(() => NICE_KSAS),

  mapActivitiesToKsas: protectedProcedure
    .input(z.object({
      activities: z.array(z.string()),
    }))
    .mutation(async ({ input }) => {
      return mapHuntToNiceKsas(input.activities);
    }),

  // ─── HUNT STATS ────────────────────────────────────────────────────
  getStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [stats] = await db.select({
      total: sql<number>`COUNT(*)`,
      active: sql<number>`SUM(CASE WHEN hunt_phase IN ('prepare', 'execute', 'act') THEN 1 ELSE 0 END)`,
      completed: sql<number>`SUM(CASE WHEN hunt_phase = 'completed' THEN 1 ELSE 0 END)`,
      totalFindings: sql<number>`SUM(confirmed_findings)`,
      totalRules: sql<number>`SUM(detection_rules_generated)`,
    }).from(huntSessions);

    return {
      totalHunts: Number(stats?.total || 0),
      activeHunts: Number(stats?.active || 0),
      completedHunts: Number(stats?.completed || 0),
      totalFindings: Number(stats?.totalFindings || 0),
      totalDetectionRules: Number(stats?.totalRules || 0),
    };
  }),
});
