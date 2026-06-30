/**
 * Adjustment Effectiveness Router
 *
 * tRPC endpoints for the adjustment effectiveness feedback loop.
 * Provides dashboard data showing which exploit adjustments work best
 * against specific defense configurations.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getEffectivenessSummary,
  getEffectivenessScore,
  getAdjustedPriorities,
} from "../lib/adjustment-effectiveness-tracker";
import type { StrategyAdjustment, FailureCategory } from "../lib/exploit-retry-engine";

export const adjustmentEffectivenessRouter = router({
  /**
   * Get full effectiveness summary for the dashboard widget.
   */
  getSummary: protectedProcedure.query(async () => {
    const summary = await getEffectivenessSummary();
    return summary;
  }),

  /**
   * Get effectiveness score for a specific (adjustmentType, failureCategory, service) tuple.
   */
  getScore: protectedProcedure
    .input(
      z.object({
        adjustmentType: z.string(),
        failureCategory: z.string(),
        service: z.string(),
      })
    )
    .query(async ({ input }) => {
      const score = await getEffectivenessScore(
        input.adjustmentType as StrategyAdjustment["type"],
        input.failureCategory as FailureCategory,
        input.service
      );
      return score;
    }),

  /**
   * Get adjusted priorities for a set of adjustments (preview what the system would choose).
   */
  previewAdjustedPriorities: protectedProcedure
    .input(
      z.object({
        adjustments: z.array(
          z.object({
            type: z.string(),
            description: z.string(),
            priority: z.number(),
          })
        ),
        failureCategory: z.string(),
        service: z.string(),
      })
    )
    .query(async ({ input }) => {
      const adjusted = await getAdjustedPriorities(
        input.adjustments as StrategyAdjustment[],
        input.failureCategory as FailureCategory,
        input.service
      );
      return adjusted.map((a) => ({
        type: a.type,
        description: a.description,
        originalPriority: a.originalPriority,
        adjustedPriority: a.adjustedPriority,
        effectiveness: {
          totalAttempts: a.effectiveness.totalAttempts,
          successes: a.effectiveness.successes,
          bayesianRate: a.effectiveness.bayesianRate,
          priorityModifier: a.effectiveness.priorityModifier,
          trend: a.effectiveness.trend,
        },
      }));
    }),
});
