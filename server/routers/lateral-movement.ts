import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  planLateralMovement,
  deterministicPlanLateralMovement,
  planPivotPath,
  getAvailableTechniques,
  getTechnique,
  LATERAL_TECHNIQUES,
} from "../lib/lateral-movement-engine";

export const lateralMovementRouter = router({
  /** LLM-driven lateral movement plan generation */
  generatePlan: protectedProcedure
    .input(z.object({
      currentHost: z.object({
        ip: z.string(),
        hostname: z.string().optional(),
        os: z.string(),
        accessLevel: z.string(),
        availableCredentials: z.array(z.object({
          type: z.string(),
          username: z.string(),
          domain: z.string().optional(),
        })).optional(),
      }),
      targetHost: z.object({
        ip: z.string(),
        hostname: z.string().optional(),
        os: z.string().optional(),
        openPorts: z.array(z.number()).optional(),
        services: z.array(z.string()).optional(),
      }),
      networkTopology: z.object({
        sameSubnet: z.boolean().optional(),
        firewallBetween: z.boolean().optional(),
        segmented: z.boolean().optional(),
      }).optional(),
      constraints: z.object({
        maxOpsecRisk: z.number().optional(),
        stealthRequired: z.boolean().optional(),
        avoidTechniques: z.array(z.string()).optional(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      const result = await planLateralMovement(input.currentHost, input.targetHost, input.networkTopology, input.constraints);
      try {
        const { recordLateralMovement } = await import("../lib/auto-persistence");
        await recordLateralMovement({
          actionName: `Lateral movement plan: ${input.currentHost.ip} → ${input.targetHost.ip}`,
          description: `LLM lateral movement plan from ${input.currentHost.ip} to ${input.targetHost.ip} (${input.targetHost.os || "unknown"} OS)`,
          source: "lateral-movement-engine",
          target: input.targetHost.ip,
          success: true,
          resultData: { sourceIp: input.currentHost.ip, targetIp: input.targetHost.ip },
        });
      } catch (e) { /* non-blocking */ }
      return result;
    }),

  /** Quick deterministic plan (no LLM) */
  quickPlan: protectedProcedure
    .input(z.object({
      currentHost: z.object({
        ip: z.string(),
        hostname: z.string().optional(),
        os: z.string(),
        accessLevel: z.string(),
        availableCredentials: z.array(z.object({
          type: z.string(),
          username: z.string(),
          domain: z.string().optional(),
        })).optional(),
      }),
      targetHost: z.object({
        ip: z.string(),
        hostname: z.string().optional(),
        os: z.string().optional(),
        openPorts: z.array(z.number()).optional(),
        services: z.array(z.string()).optional(),
      }),
      networkTopology: z.object({
        sameSubnet: z.boolean().optional(),
        firewallBetween: z.boolean().optional(),
        segmented: z.boolean().optional(),
      }).optional(),
    }))
    .query(({ input }) => {
      return deterministicPlanLateralMovement(input.currentHost, input.targetHost, input.networkTopology);
    }),

  /** LLM-driven pivot path planning through multiple hops */
  planPivot: protectedProcedure
    .input(z.object({
      sourceHost: z.string(),
      targetHost: z.string(),
      intermediateHosts: z.array(z.string()).optional(),
      constraints: z.object({
        maxOpsecRisk: z.number().optional(),
        stealthRequired: z.boolean().optional(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      const result = await planPivotPath(input.sourceHost, input.targetHost, input.intermediateHosts, input.constraints);
      try {
        const { recordLateralMovement } = await import("../lib/auto-persistence");
        await recordLateralMovement({
          actionName: `Pivot path: ${input.sourceHost} → ${input.targetHost}`,
          description: `Multi-hop pivot plan from ${input.sourceHost} to ${input.targetHost} via ${input.intermediateHosts?.length || 0} hops`,
          source: "lateral-movement-engine",
          target: input.targetHost,
          success: true,
          resultData: { hops: input.intermediateHosts?.length || 0 },
        });
      } catch (e) { /* non-blocking */ }
      return result;
    }),

  /** Get all lateral movement techniques with optional filters */
  techniques: protectedProcedure
    .input(z.object({
      targetOs: z.string().optional(),
      requiresAdmin: z.boolean().optional(),
      maxOpsecRisk: z.number().optional(),
    }).optional())
    .query(({ input }) => getAvailableTechniques(input || undefined)),

  /** Get a specific technique by ID */
  technique: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => getTechnique(input.id)),

  /** Get knowledge base stats */
  knowledgeBase: protectedProcedure.query(() => ({
    totalTechniques: LATERAL_TECHNIQUES.length,
    byOs: {
      windows: LATERAL_TECHNIQUES.filter(t => t.targetOs.includes("windows")).length,
      linux: LATERAL_TECHNIQUES.filter(t => t.targetOs.includes("linux")).length,
    },
  })),
});
