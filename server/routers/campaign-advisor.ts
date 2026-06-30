import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  chatWithAdvisor,
  getQuickRecommendation,
  getDeterministicAdvice,
  gatherEngagementContext,
  gatherEngagementContextWithBurp,
} from "../lib/campaign-advisor";
import {
  safeChatWithAdvisor,
  processInputSafety,
  processOutputSafety,
  type SafetyMiddlewareContext,
} from "../lib/ai-safety-middleware";

/** Build safety middleware context from tRPC context */
function buildSafetyCtx(ctx: any, engagementId?: string): SafetyMiddlewareContext {
  return {
    userId: String(ctx.user?.id || "unknown"),
    userName: ctx.user?.name || undefined,
    userRole: ctx.user?.role || "operator",
    // In single-tenant mode, use the owner's openId as tenantId
    // In multi-tenant mode, this would come from the user's organization
    tenantId: ctx.user?.openId || "default-tenant",
    tenantPlan: "enterprise",
    engagementId,
    sessionId: ctx.req?.cookies?.["caldera_session"]?.slice(0, 32) || undefined,
    ipAddress: ctx.req?.ip || ctx.req?.headers?.["x-forwarded-for"] as string || undefined,
    userAgent: ctx.req?.headers?.["user-agent"] || undefined,
  };
}

export const campaignAdvisorRouter = router({
  /**
   * Full LLM chat with the Campaign Advisor — SAFETY HARDENED
   * All inputs pass through prompt injection detection, tenant boundary validation,
   * and rate limiting. All outputs pass through PII scrubbing and cross-tenant filtering.
   */
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
    .mutation(async ({ input, ctx }) => {
      const safetyCtx = buildSafetyCtx(ctx, input.engagementId);

      const result = await safeChatWithAdvisor(
        {
          messages: input.messages,
          engagementId: input.engagementId,
          context: input.context,
        },
        safetyCtx,
      );

      return {
        response: result.response,
        context: result.context,
        safety: result.safety,
      };
    }),

  /**
   * Quick recommendation without chat history — SAFETY HARDENED
   */
  quickRecommend: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
      question: z.string().optional(),
    }).optional())
    .mutation(async ({ input, ctx }) => {
      const safetyCtx = buildSafetyCtx(ctx, input?.engagementId);
      const question = input?.question || "Based on the current engagement state, what should I do next?";

      // Input safety check
      const inputCheck = processInputSafety({ userMessage: question }, safetyCtx);
      if (!inputCheck.allowed) {
        return {
          response: inputCheck.blockReason || "Request blocked by security policy.",
          context: {},
          safety: { inputBlocked: true, outputModified: false, injectionDetected: true, confidence: 0 },
        };
      }

      const result = await getQuickRecommendation(input?.engagementId, inputCheck.sanitizedInput || question);

      // Output safety check
      const outputCheck = processOutputSafety(result.response, safetyCtx);

      return {
        response: outputCheck.sanitizedOutput,
        context: result.context,
        safety: {
          inputBlocked: false,
          outputModified: outputCheck.modified,
          injectionDetected: false,
          confidence: outputCheck.confidence,
        },
      };
    }),

  /** Instant deterministic advice (no LLM, no latency) — no safety needed (deterministic) */
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
