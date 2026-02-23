/**
 * Purple Team / Detection Tests Router
 * Manages red/blue team collaboration with detection coverage tracking.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { detectionTests, defenseScores } from "../../drizzle/schema";
import { eq, desc, like, and, sql } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

function generateId(prefix: string) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

export const purpleTeamRouter = router({
  // ─── Detection Tests ───
  listTests: protectedProcedure
    .input(z.object({
      search: z.string().optional(),
      engagementId: z.string().optional(),
      tactic: z.string().optional(),
      detected: z.boolean().optional(),
      isGap: z.boolean().optional(),
      mitigationStatus: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.search) filters.push(like(detectionTests.techniqueName, `%${input.search}%`));
      if (input?.engagementId) filters.push(eq(detectionTests.engagementId, input.engagementId));
      if (input?.tactic) filters.push(eq(detectionTests.tactic, input.tactic));
      if (input?.detected !== undefined) filters.push(eq(detectionTests.detected, input.detected));
      if (input?.isGap !== undefined) filters.push(eq(detectionTests.isGap, input.isGap));
      if (input?.mitigationStatus) filters.push(eq(detectionTests.mitigationStatus, input.mitigationStatus));
      const where = filters.length > 0 ? and(...filters) : undefined;

      const [items, countResult] = await Promise.all([
        db.select().from(detectionTests).where(where)
          .orderBy(desc(detectionTests.createdAt))
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(detectionTests).where(where),
      ]);
      return { items, total: Number(countResult[0]?.count ?? 0) };
    }),

  // ─── Get single test ───
  getTest: protectedProcedure
    .input(z.object({ testId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [test] = await db.select().from(detectionTests)
        .where(eq(detectionTests.testId, input.testId));
      if (!test) throw new TRPCError({ code: "NOT_FOUND", message: "Detection test not found" });
      return test;
    }),

  // ─── Create detection test ───
  createTest: protectedProcedure
    .input(z.object({
      techniqueId: z.string().min(1),
      techniqueName: z.string().optional(),
      tactic: z.string().optional(),
      abilityId: z.string().optional(),
      abilityName: z.string().optional(),
      engagementId: z.string().optional(),
      executionResult: z.string().optional(),
      detected: z.boolean().optional(),
      detectionTime: z.number().optional(),
      detectionSource: z.string().optional(),
      detectionRule: z.string().optional(),
      alertSeverity: z.string().optional(),
      isGap: z.boolean().optional(),
      gapSeverity: z.string().optional(),
      recommendation: z.string().optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const testId = generateId("dt");
      await db.insert(detectionTests).values({
        testId,
        techniqueId: input.techniqueId,
        techniqueName: input.techniqueName,
        tactic: input.tactic,
        abilityId: input.abilityId,
        abilityName: input.abilityName,
        engagementId: input.engagementId,
        executionResult: input.executionResult || "pending",
        executedAt: input.executionResult && input.executionResult !== "pending" ? new Date() : undefined,
        detected: input.detected ?? false,
        detectionTime: input.detectionTime,
        detectionSource: input.detectionSource,
        detectionRule: input.detectionRule,
        alertSeverity: input.alertSeverity,
        isGap: input.isGap ?? (!input.detected && input.executionResult === "success"),
        gapSeverity: input.gapSeverity,
        mitigationStatus: "open",
        recommendation: input.recommendation,
        notes: input.notes,
      });
      return { testId };
    }),

  // ─── Update detection test ───
  updateTest: protectedProcedure
    .input(z.object({
      testId: z.string(),
      executionResult: z.string().optional(),
      detected: z.boolean().optional(),
      detectionTime: z.number().optional(),
      detectionSource: z.string().optional(),
      detectionRule: z.string().optional(),
      alertSeverity: z.string().optional(),
      isGap: z.boolean().optional(),
      gapSeverity: z.string().optional(),
      mitigationStatus: z.string().optional(),
      recommendation: z.string().optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const updates: any = {};
      if (input.executionResult !== undefined) {
        updates.executionResult = input.executionResult;
        if (input.executionResult !== "pending") updates.executedAt = new Date();
      }
      if (input.detected !== undefined) updates.detected = input.detected;
      if (input.detectionTime !== undefined) updates.detectionTime = input.detectionTime;
      if (input.detectionSource !== undefined) updates.detectionSource = input.detectionSource;
      if (input.detectionRule !== undefined) updates.detectionRule = input.detectionRule;
      if (input.alertSeverity !== undefined) updates.alertSeverity = input.alertSeverity;
      if (input.isGap !== undefined) updates.isGap = input.isGap;
      if (input.gapSeverity !== undefined) updates.gapSeverity = input.gapSeverity;
      if (input.mitigationStatus !== undefined) updates.mitigationStatus = input.mitigationStatus;
      if (input.recommendation !== undefined) updates.recommendation = input.recommendation;
      if (input.notes !== undefined) updates.notes = input.notes;

      await db.update(detectionTests).set(updates)
        .where(eq(detectionTests.testId, input.testId));
      return { success: true };
    }),

  // ─── Delete detection test ───
  deleteTest: protectedProcedure
    .input(z.object({ testId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(detectionTests).where(eq(detectionTests.testId, input.testId));
      return { success: true };
    }),

  // ─── Detection Coverage Matrix ───
  coverageMatrix: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.engagementId) filters.push(eq(detectionTests.engagementId, input.engagementId));
      const where = filters.length > 0 ? and(...filters) : undefined;

      const tests = await db.select().from(detectionTests).where(where);

      // Build coverage matrix by tactic
      const tactics = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
      ];

      const matrix = tactics.map(tactic => {
        const tacticTests = tests.filter(t => t.tactic === tactic);
        const detected = tacticTests.filter(t => t.detected);
        const gaps = tacticTests.filter(t => t.isGap);
        return {
          tactic,
          totalTests: tacticTests.length,
          detected: detected.length,
          gaps: gaps.length,
          coverage: tacticTests.length > 0
            ? Math.round((detected.length / tacticTests.length) * 100)
            : 0,
        };
      });

      const totalTests = tests.length;
      const totalDetected = tests.filter(t => t.detected).length;
      const totalGaps = tests.filter(t => t.isGap).length;

      return {
        matrix,
        summary: {
          totalTests,
          totalDetected,
          totalGaps,
          overallCoverage: totalTests > 0
            ? Math.round((totalDetected / totalTests) * 100)
            : 0,
        },
      };
    }),

  // ─── Defense Scores ───
  listScores: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(50).default(20),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [items, countResult] = await Promise.all([
        db.select().from(defenseScores)
          .orderBy(desc(defenseScores.createdAt))
          .limit(input?.limit ?? 20)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(defenseScores),
      ]);
      return { items, total: Number(countResult[0]?.count ?? 0) };
    }),

  createScore: protectedProcedure
    .input(z.object({
      organizationName: z.string().min(1),
      threatActorId: z.number().optional(),
      threatActorName: z.string().optional(),
      detectionScore: z.number().min(0).max(100).optional(),
      vulnerabilityScore: z.number().min(0).max(100).optional(),
      surfaceScore: z.number().min(0).max(100).optional(),
      responseScore: z.number().min(0).max(100).optional(),
      engagementId: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const scoreId = generateId("ds");
      const scores = [
        input.detectionScore ?? 50,
        input.vulnerabilityScore ?? 50,
        input.surfaceScore ?? 50,
        input.responseScore ?? 50,
      ];
      const overallScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);

      await db.insert(defenseScores).values({
        scoreId,
        organizationName: input.organizationName,
        threatActorId: input.threatActorId,
        threatActorName: input.threatActorName,
        overallScore,
        detectionScore: input.detectionScore ?? 50,
        vulnerabilityScore: input.vulnerabilityScore ?? 50,
        surfaceScore: input.surfaceScore ?? 50,
        responseScore: input.responseScore ?? 50,
        engagementId: input.engagementId,
        createdBy: ctx.user.openId,
      });
      return { scoreId, overallScore };
    }),

  // ─── Update Blue Team Outcome ───
  updateBlueTeamOutcome: protectedProcedure
    .input(z.object({
      testId: z.string(),
      blueTeamOutcome: z.enum(["detected", "blocked", "missed", "partial", "not_tested"]),
      blueTeamNotes: z.string().optional(),
      blueTeamAnalyst: z.string().optional(),
      detectionMethod: z.string().optional(),
      responseAction: z.string().optional(),
      timeToDetect: z.number().optional(),
      timeToRespond: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const updates: any = {
        blueTeamOutcome: input.blueTeamOutcome,
        blueTeamUpdatedAt: new Date(),
      };
      // Auto-set detected and isGap based on outcome
      if (input.blueTeamOutcome === "detected" || input.blueTeamOutcome === "blocked") {
        updates.detected = true;
        updates.isGap = false;
      } else if (input.blueTeamOutcome === "missed") {
        updates.detected = false;
        updates.isGap = true;
      } else if (input.blueTeamOutcome === "partial") {
        updates.detected = true;
        updates.isGap = true; // partial detection is still a gap
      }
      if (input.blueTeamNotes !== undefined) updates.blueTeamNotes = input.blueTeamNotes;
      if (input.blueTeamAnalyst !== undefined) updates.blueTeamAnalyst = input.blueTeamAnalyst;
      else updates.blueTeamAnalyst = ctx.user.name || ctx.user.openId;
      if (input.detectionMethod !== undefined) updates.detectionMethod = input.detectionMethod;
      if (input.responseAction !== undefined) updates.responseAction = input.responseAction;
      if (input.timeToDetect !== undefined) {
        updates.timeToDetect = input.timeToDetect;
        updates.detectionTime = input.timeToDetect;
      }
      if (input.timeToRespond !== undefined) updates.timeToRespond = input.timeToRespond;

      await db.update(detectionTests).set(updates)
        .where(eq(detectionTests.testId, input.testId));
      return { success: true };
    }),

  // ─── Detection Gap Summary ───
  detectionGapSummary: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.engagementId) filters.push(eq(detectionTests.engagementId, input.engagementId));
      const where = filters.length > 0 ? and(...filters) : undefined;

      const tests = await db.select().from(detectionTests).where(where);

      // Outcome distribution
      const outcomes = { detected: 0, blocked: 0, missed: 0, partial: 0, not_tested: 0 };
      tests.forEach(t => {
        const o = (t as any).blueTeamOutcome || "not_tested";
        if (o in outcomes) (outcomes as any)[o]++;
      });

      // Detection method breakdown
      const methodMap = new Map<string, number>();
      tests.forEach(t => {
        const m = (t as any).detectionMethod;
        if (m) methodMap.set(m, (methodMap.get(m) || 0) + 1);
      });
      const detectionMethods = Array.from(methodMap.entries())
        .map(([method, count]) => ({ method, count }))
        .sort((a, b) => b.count - a.count);

      // Average response times
      const detectedTests = tests.filter(t => (t as any).timeToDetect != null);
      const respondedTests = tests.filter(t => (t as any).timeToRespond != null);
      const avgTimeToDetect = detectedTests.length > 0
        ? Math.round(detectedTests.reduce((sum, t) => sum + ((t as any).timeToDetect || 0), 0) / detectedTests.length)
        : null;
      const avgTimeToRespond = respondedTests.length > 0
        ? Math.round(respondedTests.reduce((sum, t) => sum + ((t as any).timeToRespond || 0), 0) / respondedTests.length)
        : null;

      // Gaps by tactic
      const tactics = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
      ];
      const gapsByTactic = tactics.map(tactic => {
        const tacticTests = tests.filter(t => t.tactic === tactic);
        const missed = tacticTests.filter(t => (t as any).blueTeamOutcome === "missed");
        const partial = tacticTests.filter(t => (t as any).blueTeamOutcome === "partial");
        return {
          tactic,
          total: tacticTests.length,
          missed: missed.length,
          partial: partial.length,
          gapRate: tacticTests.length > 0
            ? Math.round(((missed.length + partial.length) / tacticTests.length) * 100)
            : 0,
        };
      }).filter(t => t.total > 0);

      // Top undetected techniques
      const missedTests = tests
        .filter(t => (t as any).blueTeamOutcome === "missed")
        .map(t => ({
          testId: t.testId,
          techniqueId: t.techniqueId,
          techniqueName: t.techniqueName,
          tactic: t.tactic,
          gapSeverity: t.gapSeverity,
        }))
        .slice(0, 20);

      return {
        outcomes,
        detectionMethods,
        avgTimeToDetect,
        avgTimeToRespond,
        gapsByTactic,
        missedTests,
        totalAssessed: tests.filter(t => (t as any).blueTeamOutcome !== "not_tested").length,
        totalTests: tests.length,
      };
    }),

  // ─── Stats ───
  stats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [testCount] = await db.select({ count: sql<number>`count(*)` }).from(detectionTests);
    const [gapCount] = await db.select({ count: sql<number>`count(*)` }).from(detectionTests)
      .where(eq(detectionTests.isGap, true));
    const [detectedCount] = await db.select({ count: sql<number>`count(*)` }).from(detectionTests)
      .where(eq(detectionTests.detected, true));
    const [scoreCount] = await db.select({ count: sql<number>`count(*)` }).from(defenseScores);

    return {
      totalTests: Number(testCount?.count ?? 0),
      totalGaps: Number(gapCount?.count ?? 0),
      totalDetected: Number(detectedCount?.count ?? 0),
      totalScores: Number(scoreCount?.count ?? 0),
      coverageRate: Number(testCount?.count ?? 0) > 0
        ? Math.round((Number(detectedCount?.count ?? 0) / Number(testCount?.count ?? 0)) * 100)
        : 0,
    };
  }),
});
