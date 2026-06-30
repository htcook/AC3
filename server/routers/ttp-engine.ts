import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import * as schema from "../../drizzle/schema";

export const ttpEngineRouter = router({
    // Get knowledge for a single technique
    get: protectedProcedure
      .input(z.object({ techniqueId: z.string() }))
      .query(async ({ input }) => {
        return db.getTtpKnowledge(input.techniqueId);
      }),
    // List all TTP knowledge entries
    list: protectedProcedure
      .input(z.object({
        tactic: z.string().optional(),
        search: z.string().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
      }).optional())
      .query(async ({ input }) => {
        return db.listTtpKnowledge(input || {});
      }),
    // Get stats about the knowledge base
    stats: protectedProcedure.query(async () => {
      return db.getTtpKnowledgeStats();
    }),
    // Enrich a single technique with deep LLM analysis
    enrich: protectedProcedure
      .input(z.object({
        techniqueId: z.string(),
        techniqueName: z.string(),
        tactic: z.string(),
        force: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { enrichTechnique } = await import('../lib/ttp-engine');
        return enrichTechnique(input.techniqueId, input.techniqueName, input.tactic, input.force);
      }),
    // Batch enrich multiple techniques
    batchEnrich: protectedProcedure
      .input(z.object({
        techniques: z.array(z.object({
          id: z.string(),
          name: z.string(),
          tactic: z.string(),
        })),
        force: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { batchEnrichTechniques } = await import('../lib/ttp-engine');
        return batchEnrichTechniques(input.techniques, input.force);
      }),
    // Generate detection rules for a set of techniques
    detectionRules: protectedProcedure
      .input(z.object({ techniqueIds: z.array(z.string()) }))
      .query(async ({ input }) => {
        const { generateDetectionRules } = await import('../lib/ttp-engine');
        return generateDetectionRules(input.techniqueIds);
      }),
    // Generate campaign design prompt with TTP knowledge
    campaignPrompt: protectedProcedure
      .input(z.object({
        targetSector: z.string(),
        targetTechnologies: z.array(z.string()),
        threatActors: z.array(z.object({
          name: z.string(),
          techniques: z.array(z.object({
            id: z.string(),
            name: z.string(),
            tactic: z.string(),
          })),
        })),
        riskScore: z.number(),
      }))
      .mutation(async ({ input }) => {
        const { generateCampaignDesignPrompt } = await import('../lib/ttp-engine');
        const prompt = await generateCampaignDesignPrompt(input);
        return { prompt };
      }),
    // Ingest data from GitHub repositories (ATT&CK STIX, Atomic Red Team, LOLBAS, Metasploit, Kali)
    ingest: protectedProcedure
      .input(z.object({
        skipAttack: z.boolean().optional(),
        skipAtomic: z.boolean().optional(),
        skipLolbas: z.boolean().optional(),
        skipMetasploit: z.boolean().optional(),
        maxTechniques: z.number().optional(),
      }).optional())
      .mutation(async ({ input }) => {
        const { runFullIngestion } = await import('../lib/ttp-ingest');
        return runFullIngestion(input || {});
      }),
    // Get Kali Linux tools catalog
    kaliTools: protectedProcedure
      .input(z.object({ techniqueId: z.string().optional() }).optional())
      .query(async ({ input }) => {
        const { getKaliToolsCatalog, getKaliToolsForTechnique } = await import('../lib/ttp-ingest');
        if (input?.techniqueId) {
          return getKaliToolsForTechnique(input.techniqueId);
        }
        return getKaliToolsCatalog();
      }),
  });
