/**
 * Production-Safe Autonomous Mode Router
 *
 * tRPC procedures for the Safety Engine — configurable safety levels,
 * blast radius estimation, audit trail, and real-time safety metrics.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  SafetyEngine,
  getSafetyEngine,
  clearSafetyEngine,
  type SafetyLevel,
  type SafetyAssessment,
  type BlastRadiusEstimate,
} from "../lib/safety-engine";

const safetyLevelSchema = z.enum(["passive_only", "low_impact", "standard", "full_exploitation"]);

export const safetyEngineRouter = router({
  /** Get available safety levels with descriptions */
  getLevels: protectedProcedure.query(() => {
    return SafetyEngine.getAvailableLevels();
  }),

  /** Get detailed profile for a safety level */
  getProfileDetails: protectedProcedure
    .input(z.object({ level: safetyLevelSchema }))
    .query(({ input }) => {
      return SafetyEngine.getProfileDetails(input.level);
    }),

  /** Get or create safety engine for an engagement */
  getEngineState: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(({ input }) => {
      const engine = getSafetyEngine(input.engagementId);
      return {
        safetyLevel: engine.getSafetyLevel(),
        profile: engine.getProfile(),
        stats: engine.getStats(),
      };
    }),

  /** Set safety level for an engagement */
  setSafetyLevel: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      level: safetyLevelSchema,
    }))
    .mutation(({ input, ctx }) => {
      const engine = getSafetyEngine(input.engagementId);
      const oldLevel = engine.getSafetyLevel();
      engine.setSafetyLevel(input.level);
      console.log(`[SafetyEngine] Engagement ${input.engagementId}: ${oldLevel} → ${input.level} (by ${ctx.user.name})`);
      return {
        previousLevel: oldLevel,
        newLevel: input.level,
        profile: engine.getProfile(),
      };
    }),

  /** Assess a tool command before execution */
  assessCommand: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      tool: z.string(),
      args: z.string(),
      target: z.string(),
      phase: z.string().optional(),
    }))
    .mutation(({ input }) => {
      const engine = getSafetyEngine(input.engagementId);
      return engine.assess(input.tool, input.args, input.target, input.phase);
    }),

  /** Estimate blast radius without recording to audit log */
  estimateBlastRadius: protectedProcedure
    .input(z.object({
      tool: z.string(),
      args: z.string(),
      target: z.string(),
      level: safetyLevelSchema,
    }))
    .query(({ input }) => {
      return SafetyEngine.estimateBlastRadiusStatic(input.tool, input.args, input.target, input.level);
    }),

  /** Check if a phase can be entered at current safety level */
  canEnterPhase: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      phase: z.enum([
        "recon", "enumeration", "vuln_detection", "credential_testing",
        "exploitation", "post_exploit", "c2_deployment", "lateral_movement", "exfiltration",
      ]),
    }))
    .query(({ input }) => {
      const engine = getSafetyEngine(input.engagementId);
      return engine.canEnterPhase(input.phase);
    }),

  /** Get safety audit log for an engagement */
  getAuditLog: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      limit: z.number().min(1).max(1000).default(100),
    }))
    .query(({ input }) => {
      const engine = getSafetyEngine(input.engagementId);
      return engine.getAuditLog(input.limit);
    }),

  /** Get blocked actions for an engagement */
  getBlockedActions: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(({ input }) => {
      const engine = getSafetyEngine(input.engagementId);
      return engine.getBlockedActions();
    }),

  /** Get safety stats for an engagement */
  getStats: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(({ input }) => {
      const engine = getSafetyEngine(input.engagementId);
      return engine.getStats();
    }),

  /** Reset safety engine for an engagement */
  reset: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(({ input }) => {
      clearSafetyEngine(input.engagementId);
      return { success: true };
    }),

  /** Bulk assess multiple commands (for pre-flight checks) */
  bulkAssess: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      commands: z.array(z.object({
        tool: z.string(),
        args: z.string(),
        target: z.string(),
        phase: z.string().optional(),
      })),
    }))
    .mutation(({ input }) => {
      const engine = getSafetyEngine(input.engagementId);
      const results = input.commands.map(cmd =>
        engine.assess(cmd.tool, cmd.args, cmd.target, cmd.phase)
      );
      const allowed = results.filter(r => r.allowed).length;
      const blocked = results.filter(r => !r.allowed).length;
      const maxBlastRadius = Math.max(...results.map(r => r.blastRadius.riskScore));
      return { results, summary: { total: results.length, allowed, blocked, maxBlastRadius } };
    }),

  /** Compare safety levels side-by-side */
  compareLevels: protectedProcedure.query(() => {
    const levels = SafetyEngine.getAvailableLevels();
    return levels.map(l => ({
      ...l,
      profile: SafetyEngine.getProfileDetails(l.level),
    }));
  }),
});
