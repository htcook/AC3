import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  analyzePrivescVectors,
  deterministicAnalyzePrivesc,
  getPrivescTechniques,
  getEnumerationTools,
  getKerberosAttacks,
  getCloudPrivescTechniques,
  PRIVESC_TECHNIQUES,
  ENUMERATION_TOOLS,
} from "../lib/privesc-engine";

export const privescRouter = router({
  /** LLM-driven analysis of enumeration output to find privesc vectors */
  analyze: protectedProcedure
    .input(z.object({
      enumerationOutput: z.string(),
      currentAccess: z.string(),
      targetOs: z.string(),
      isAdEnvironment: z.boolean().optional(),
      cloudProvider: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const result = await analyzePrivescVectors(
        input.enumerationOutput,
        input.currentAccess,
        input.targetOs,
        input.isAdEnvironment,
        input.cloudProvider
      );
      try {
        const { recordPrivesc } = await import("../lib/auto-persistence");
        await recordPrivesc({
          actionName: `Privesc analysis (${input.targetOs})`,
          description: `LLM privilege escalation analysis on ${input.targetOs} from ${input.currentAccess} access`,
          source: "privesc-engine",
          success: true,
          resultData: { os: input.targetOs, currentAccess: input.currentAccess, isAD: input.isAdEnvironment },
        });
      } catch (e) { /* non-blocking */ }
      return result;
    }),

  /** Quick deterministic analysis (no LLM) */
  quickAnalyze: protectedProcedure
    .input(z.object({
      enumerationOutput: z.string(),
      currentAccess: z.string(),
      targetOs: z.string(),
      isAdEnvironment: z.boolean().optional(),
      cloudProvider: z.string().optional(),
    }))
    .query(({ input }) => {
      return deterministicAnalyzePrivesc(
        input.enumerationOutput,
        input.currentAccess,
        input.targetOs,
        input.isAdEnvironment,
        input.cloudProvider
      );
    }),

  /** Get all privesc techniques with optional filters */
  techniques: protectedProcedure
    .input(z.object({
      targetOs: z.string().optional(),
      category: z.string().optional(),
      maxOpsecRisk: z.number().optional(),
      fromAccess: z.string().optional(),
    }).optional())
    .query(({ input }) => getPrivescTechniques(input || undefined)),

  /** Get enumeration tools for a target OS */
  enumerationTools: protectedProcedure
    .input(z.object({ targetOs: z.string().optional() }).optional())
    .query(({ input }) => getEnumerationTools(input?.targetOs)),

  /** Get Kerberos-specific attack techniques */
  kerberosAttacks: protectedProcedure.query(() => getKerberosAttacks()),

  /** Get cloud-specific privesc techniques */
  cloudPrivesc: protectedProcedure
    .input(z.object({ provider: z.string().optional() }).optional())
    .query(({ input }) => getCloudPrivescTechniques(input?.provider)),

  /** Get full knowledge base stats */
  knowledgeBase: protectedProcedure.query(() => ({
    totalTechniques: PRIVESC_TECHNIQUES.length,
    totalEnumerationTools: ENUMERATION_TOOLS.length,
    byCategory: {
      kernel: PRIVESC_TECHNIQUES.filter(t => t.category === "kernel").length,
      service: PRIVESC_TECHNIQUES.filter(t => t.category === "service").length,
      credential: PRIVESC_TECHNIQUES.filter(t => t.category === "credential").length,
      misconfiguration: PRIVESC_TECHNIQUES.filter(t => t.category === "misconfiguration").length,
      lolbin: PRIVESC_TECHNIQUES.filter(t => t.category === "lolbin").length,
      kerberos: PRIVESC_TECHNIQUES.filter(t => t.category === "kerberos").length,
      token: PRIVESC_TECHNIQUES.filter(t => t.category === "token").length,
      cloud: PRIVESC_TECHNIQUES.filter(t => t.category === "cloud").length,
      container: PRIVESC_TECHNIQUES.filter(t => t.category === "container").length,
    },
    byOs: {
      windows: PRIVESC_TECHNIQUES.filter(t => t.targetOs.includes("windows")).length,
      linux: PRIVESC_TECHNIQUES.filter(t => t.targetOs.includes("linux")).length,
      cloud: PRIVESC_TECHNIQUES.filter(t => t.targetOs.some(o => o.startsWith("cloud_"))).length,
    },
  })),
});
