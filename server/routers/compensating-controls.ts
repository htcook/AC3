import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";

export const compensatingControlsRouter = router({
  /**
   * Evaluate compensating controls for a given vulnerability/finding
   */
  evaluate: protectedProcedure
    .input(z.object({
      cveId: z.string().optional(),
      techniqueId: z.string().optional(),
      targetService: z.string().optional(),
      targetPort: z.number().optional(),
      existingControls: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { evaluateCompensatingControls } = await import("../lib/compensating-controls");
      return evaluateCompensatingControls({
        cveId: input.cveId,
        techniqueId: input.techniqueId,
        targetService: input.targetService,
        targetPort: input.targetPort,
        existingControls: input.existingControls || [],
      });
    }),

  /**
   * Get the full control catalog
   */
  getCatalog: protectedProcedure.query(async () => {
    const { getControlCatalog } = await import("../lib/compensating-controls");
    return getControlCatalog();
  }),

  /**
   * Calculate risk adjustment based on active controls
   */
  calculateRiskAdjustment: protectedProcedure
    .input(z.object({
      baseRiskScore: z.number().min(0).max(10),
      activeControlIds: z.array(z.string()).min(1),
    }))
    .mutation(async ({ input }) => {
      const { calculateRiskAdjustment } = await import("../lib/compensating-controls");
      return calculateRiskAdjustment(input.baseRiskScore, input.activeControlIds);
    }),
});
