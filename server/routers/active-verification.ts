import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";

export const activeVerificationRouter = router({
  /**
   * Run a single probe against a target
   */
  runProbe: protectedProcedure
    .input(z.object({
      probeId: z.string().min(1),
      targetHost: z.string().min(1),
      targetPort: z.number().optional().default(443),
      protocol: z.enum(["http", "https"]).optional().default("https"),
    }))
    .mutation(async ({ input }) => {
      const { runProbe, BUILTIN_PROBES } = await import("../lib/active-verification");
      const probe = BUILTIN_PROBES.find(p => p.id === input.probeId);
      if (!probe) throw new Error(`Probe "${input.probeId}" not found`);
      return runProbe(probe, input.targetHost, input.targetPort, input.protocol);
    }),

  /**
   * Run full verification suite against a target
   */
  runSuite: protectedProcedure
    .input(z.object({
      targetHost: z.string().min(1),
      targetPort: z.number().optional().default(443),
      protocol: z.enum(["http", "https"]).optional().default("https"),
      cveIds: z.array(z.string()).optional(),
      tags: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { runVerificationSuite } = await import("../lib/active-verification");
      return runVerificationSuite(
        input.targetHost,
        input.targetPort,
        input.protocol,
        { cveIds: input.cveIds, tags: input.tags }
      );
    }),

  /**
   * List all available probes
   */
  listProbes: protectedProcedure.query(async () => {
    const { BUILTIN_PROBES } = await import("../lib/active-verification");
    return BUILTIN_PROBES.map(p => ({
      id: p.id,
      name: p.name,
      description: p.description,
      cveIds: p.cveIds,
      cweIds: p.cweIds,
      probeType: p.probeType,
      severity: p.severity,
      safeForProduction: p.safeForProduction,
      tags: p.tags,
    }));
  }),

  /**
   * Get probes for a specific CVE
   */
  getProbesForCve: protectedProcedure
    .input(z.object({ cveId: z.string().min(1) }))
    .query(async ({ input }) => {
      const { getProbesForCve } = await import("../lib/active-verification");
      return getProbesForCve(input.cveId);
    }),

  /**
   * Get all available probe tags
   */
  getTags: protectedProcedure.query(async () => {
    const { getAvailableTags } = await import("../lib/active-verification");
    return getAvailableTags();
  }),
});
