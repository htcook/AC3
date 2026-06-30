import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  scoreActionRisk,
  deterministicScoreActionRisk,
  checkBurnIndicators,
  calculateEngagementOpsecStatus,
  getDetectionTechnologies,
  getAllBurnIndicators,
  getActionRiskProfiles,
} from "../lib/opsec-risk-engine";

export const opsecRiskRouter = router({
  /** LLM-driven OPSEC risk scoring for an operator action */
  scoreAction: protectedProcedure
    .input(z.object({
      actionType: z.string(),
      actionDetails: z.string(),
      targetEnvironment: z.object({
        edr: z.string().optional(),
        siem: z.string().optional(),
        ndr: z.string().optional(),
        av: z.string().optional(),
      }).optional(),
      cumulativeExposure: z.number().optional(),
      engagementConstraints: z.object({
        maxRiskLevel: z.string().optional(),
        stealthRequired: z.boolean().optional(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      return scoreActionRisk(
        input.actionType,
        input.actionDetails,
        input.targetEnvironment,
        input.cumulativeExposure,
        input.engagementConstraints
      );
    }),

  /** Quick deterministic risk score (no LLM) */
  quickScore: protectedProcedure
    .input(z.object({
      actionType: z.string(),
      actionDetails: z.string(),
      cumulativeExposure: z.number().optional(),
    }))
    .query(({ input }) => {
      return deterministicScoreActionRisk(input.actionType, input.actionDetails, input.cumulativeExposure);
    }),

  /** Check for burn indicators based on engagement events */
  checkBurn: protectedProcedure
    .input(z.object({
      events: z.array(z.object({
        type: z.string(),
        success: z.boolean(),
        timestamp: z.number(),
        details: z.string().optional(),
      })),
    }))
    .mutation(({ input }) => checkBurnIndicators(input.events)),

  /** Calculate overall engagement OPSEC status */
  engagementStatus: protectedProcedure
    .input(z.object({
      actionHistory: z.array(z.object({
        action: z.string(),
        risk: z.number(),
        timestamp: z.number(),
        detected: z.boolean(),
      })),
    }))
    .query(({ input }) => calculateEngagementOpsecStatus(input.actionHistory)),

  /** Get all detection technologies */
  detectionTechnologies: protectedProcedure
    .input(z.object({ category: z.string().optional() }).optional())
    .query(({ input }) => getDetectionTechnologies(input?.category)),

  /** Get all burn indicators */
  burnIndicators: protectedProcedure.query(() => getAllBurnIndicators()),

  /** Get action risk profiles */
  riskProfiles: protectedProcedure.query(() => getActionRiskProfiles()),
});
