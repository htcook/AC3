import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  chatWithAdvisor,
  getQuickRecommendation,
  getDeterministicAdvice,
  gatherEngagementContext,
  gatherEngagementContextWithBurp,
} from "../lib/campaign-advisor";

export const campaignAdvisorRouter = router({
  /** Full LLM chat with the Campaign Advisor */
  chat: protectedProcedure
    .input(z.object({
      messages: z.array(z.object({
        role: z.enum(["user", "assistant", "system"]),
        content: z.string(),
      })),
      engagementId: z.string().optional(),
      context: z.object({
        currentPhase: z.string().optional(),
        compromisedHosts: z.array(z.string()).optional(),
        availableCredentials: z.array(z.string()).optional(),
        knownVulnerabilities: z.array(z.object({
          cve: z.string(),
          host: z.string(),
          cvss: z.number(),
        })).optional(),
        objectives: z.array(z.string()).optional(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      return chatWithAdvisor(input.messages, input.context as any, input.engagementId);
    }),

  /** Quick recommendation without chat history */
  quickRecommend: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
      question: z.string().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      return getQuickRecommendation(input?.engagementId, input?.question);
    }),

  /** Instant deterministic advice (no LLM, no latency) */
  instantAdvice: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
      currentPhase: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const ctx = await gatherEngagementContext(input?.engagementId);
      if (input?.currentPhase) ctx.currentPhase = input.currentPhase;
      return getDeterministicAdvice(ctx);
    }),

  /** Get current engagement context for display (includes fresh Burp data if available) */
  getContext: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .query(async ({ input }) => {
      return gatherEngagementContextWithBurp(input?.engagementId);
    }),
});
