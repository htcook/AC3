// @ts-nocheck
/**
 * Intelligence Gaps Router
 * ────────────────────────
 * First-class gap tracking with explicit "what wasn't assessed and why".
 * Provides CRUD operations, automated gap detection, and report integration.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";

const gapCategoryEnum = z.enum([
  "scope_exclusion",
  "tool_limitation",
  "time_constraint",
  "access_denied",
  "data_unavailable",
  "expertise_gap",
  "environmental_constraint",
]);

const gapStatusEnum = z.enum(["open", "acknowledged", "mitigated", "resolved", "accepted"]);

const impactEnum = z.enum(["critical", "high", "medium", "low", "unknown"]);

export const intelligenceGapsRouter = router({
  /** List gaps for an engagement, scan, or customer */
  list: protectedProcedure
    .input(
      z.object({
        engagementId: z.number().optional(),
        scanId: z.number().optional(),
        customerId: z.string().optional(),
        status: gapStatusEnum.optional(),
        category: gapCategoryEnum.optional(),
        limit: z.number().min(1).max(500).default(100),
        offset: z.number().min(0).default(0),
      })
    )
    .query(async ({ input }) => {
      const { listGaps } = await import("../lib/intelligence-gaps");
      return listGaps(input);
    }),

  /** Get gap summary statistics */
  summary: protectedProcedure
    .input(
      z.object({
        engagementId: z.number().optional(),
        scanId: z.number().optional(),
        customerId: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const { getGapSummary } = await import("../lib/intelligence-gaps");
      return getGapSummary(input);
    }),

  /** Get gap category metadata */
  categories: protectedProcedure.query(async () => {
    const { GAP_CATEGORY_META } = await import("../lib/intelligence-gaps");
    return GAP_CATEGORY_META;
  }),

  /** Create a new intelligence gap manually */
  create: protectedProcedure
    .input(
      z.object({
        engagementId: z.number().optional(),
        scanId: z.number().optional(),
        customerId: z.string().optional(),
        category: gapCategoryEnum,
        subcategory: z.string().optional(),
        title: z.string().min(1).max(512),
        description: z.string().optional(),
        reason: z.string().min(1),
        riskImplication: z.string().optional(),
        potentialImpact: impactEnum.optional(),
        recommendation: z.string().optional(),
        estimatedEffort: z.string().optional(),
        affectedAssets: z.array(z.string()).optional(),
        affectedScope: z.array(z.string()).optional(),
        tags: z.array(z.string()).optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const { createGap } = await import("../lib/intelligence-gaps");
      const id = await createGap({
        ...input,
        detectedBy: ctx.user?.name || "operator",
      });
      return { id };
    }),

  /** Resolve a gap */
  resolve: protectedProcedure
    .input(
      z.object({
        gapId: z.number(),
        resolutionNote: z.string().min(1),
        status: z.enum(["resolved", "mitigated", "accepted"]).default("resolved"),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const { resolveGap } = await import("../lib/intelligence-gaps");
      await resolveGap(input.gapId, ctx.user?.id || 0, input.resolutionNote, input.status);
      return { success: true };
    }),

  /** Update gap status */
  updateStatus: protectedProcedure
    .input(
      z.object({
        gapId: z.number(),
        status: gapStatusEnum,
      })
    )
    .mutation(async ({ input }) => {
      const { updateGapStatus } = await import("../lib/intelligence-gaps");
      await updateGapStatus(input.gapId, input.status);
      return { success: true };
    }),

  /** Auto-detect gaps from engagement/scan context */
  detect: protectedProcedure
    .input(
      z.object({
        engagementId: z.number().optional(),
        scanId: z.number().optional(),
        customerId: z.string().optional(),
        scopeDomains: z.array(z.string()).optional(),
        scopeAssets: z.array(z.string()).optional(),
        outOfScope: z.array(z.string()).optional(),
        toolsUsed: z.array(z.string()).optional(),
        scanDurationMs: z.number().optional(),
        maxDurationMs: z.number().optional(),
        assetsScanned: z.array(z.string()).optional(),
        assetsDiscovered: z.array(z.string()).optional(),
        servicesDetected: z.array(z.string()).optional(),
        errorsEncountered: z
          .array(z.object({ tool: z.string(), error: z.string(), asset: z.string().optional() }))
          .optional(),
        authFailures: z
          .array(z.object({ asset: z.string(), service: z.string(), reason: z.string() }))
          .optional(),
        persist: z.boolean().default(true),
      })
    )
    .mutation(async ({ input }) => {
      const { detectGaps, createGapsBatch } = await import("../lib/intelligence-gaps");
      const detected = detectGaps(input);
      let ids: number[] = [];
      if (input.persist && detected.length > 0) {
        ids = await createGapsBatch(detected);
      }
      return { detected, persistedIds: ids, count: detected.length };
    }),

  /** Format gaps for report inclusion */
  reportSection: protectedProcedure
    .input(
      z.object({
        engagementId: z.number().optional(),
        scanId: z.number().optional(),
      })
    )
    .query(async ({ input }) => {
      const { listGaps, formatGapsForReport } = await import("../lib/intelligence-gaps");
      const gaps = await listGaps({
        engagementId: input.engagementId,
        scanId: input.scanId,
      });
      return formatGapsForReport(gaps);
    }),
});
