import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";

export const preflightChecksRouter = router({
  /**
   * Run full pre-flight checks before exploit execution
   */
  run: protectedProcedure
    .input(z.object({
      targetHost: z.string().min(1),
      targetPort: z.number().optional(),
      service: z.string().optional(),
      serviceVersion: z.string().optional(),
      cveId: z.string().optional(),
      exploitModule: z.string().optional(),
      techniqueId: z.string().optional(),
      requiresAuth: z.boolean().optional(),
      authCredentials: z.object({
        username: z.string(),
        password: z.string(),
      }).optional(),
      protocol: z.enum(["tcp", "udp", "http", "https"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const { runPreFlightChecks } = await import("../lib/preflight-checks");
      return runPreFlightChecks(input);
    }),

  /**
   * Quick confidence estimate (lightweight, no network calls)
   */
  quickEstimate: protectedProcedure
    .input(z.object({
      targetHost: z.string().min(1),
      targetPort: z.number().optional(),
      service: z.string().optional(),
      serviceVersion: z.string().optional(),
      cveId: z.string().optional(),
      exploitModule: z.string().optional(),
      techniqueId: z.string().optional(),
      requiresAuth: z.boolean().optional(),
      authCredentials: z.object({
        username: z.string(),
        password: z.string(),
      }).optional(),
      protocol: z.enum(["tcp", "udp", "http", "https"]).optional(),
    }))
    .query(async ({ input }) => {
      const { quickConfidenceEstimate } = await import("../lib/preflight-checks");
      return { confidence: quickConfidenceEstimate(input) };
    }),
});
