/**
 * Sigma Rule Generation Router
 *
 * tRPC endpoints for generating, exporting, and managing Sigma detection
 * rules from emulation results, threat actor TTPs, and gap analysis.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  generateFromEmulation,
  generateForThreatActor,
  getAvailableTemplates,
  getTemplateCoverage,
  exportRule,
  exportRuleSet,
  type EmulationInput,
  type ExportFormat,
  type SigmaRuleSet,
} from "../lib/sigma-rule-engine";

// In-memory store for generated rule sets (would be DB-backed in production)
const ruleSetStore = new Map<string, SigmaRuleSet>();

export const sigmaRulesRouter = router({
  /** Get available technique templates and coverage stats */
  getTemplates: protectedProcedure.query(() => {
    return {
      templates: getAvailableTemplates(),
      coverage: getTemplateCoverage(),
    };
  }),

  /** Generate Sigma rules from emulation technique inputs */
  generateFromEmulation: protectedProcedure
    .input(z.object({
      techniques: z.array(z.object({
        techniqueId: z.string(),
        techniqueName: z.string(),
        tactic: z.string(),
        procedure: z.string().optional(),
        tools: z.array(z.string()).optional(),
        detectionGap: z.boolean().optional(),
        observedArtifacts: z.array(z.string()).optional(),
      })),
    }))
    .mutation(({ input }) => {
      if (input.techniques.length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "At least one technique is required" });
      }
      const ruleSet = generateFromEmulation(input.techniques as EmulationInput[]);
      ruleSetStore.set(ruleSet.id, ruleSet);
      return ruleSet;
    }),

  /** Generate Sigma rules for a specific threat actor's TTPs */
  generateForThreatActor: protectedProcedure
    .input(z.object({
      actorName: z.string().min(1),
      techniques: z.array(z.object({
        id: z.string(),
        name: z.string(),
        tactic: z.string(),
      })),
    }))
    .mutation(({ input }) => {
      if (input.techniques.length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "At least one technique is required" });
      }
      const ruleSet = generateForThreatActor(input.actorName, input.techniques);
      ruleSetStore.set(ruleSet.id, ruleSet);
      return ruleSet;
    }),

  /** Export a single rule in the specified format */
  exportRule: protectedProcedure
    .input(z.object({
      ruleSetId: z.string(),
      ruleId: z.string(),
      format: z.enum(["sigma", "splunk_spl", "kql", "elastic_eql"]),
    }))
    .query(({ input }) => {
      const ruleSet = ruleSetStore.get(input.ruleSetId);
      if (!ruleSet) throw new TRPCError({ code: "NOT_FOUND", message: "Rule set not found" });
      const rule = ruleSet.rules.find(r => r.id === input.ruleId);
      if (!rule) throw new TRPCError({ code: "NOT_FOUND", message: "Rule not found" });
      return {
        content: exportRule(rule, input.format as ExportFormat),
        format: input.format,
        filename: `${rule.techniqueId}_${input.format}.${input.format === "sigma" ? "yml" : input.format === "splunk_spl" ? "spl" : input.format === "kql" ? "kql" : "eql"}`,
      };
    }),

  /** Export an entire rule set in the specified format */
  exportRuleSet: protectedProcedure
    .input(z.object({
      ruleSetId: z.string(),
      format: z.enum(["sigma", "splunk_spl", "kql", "elastic_eql"]),
    }))
    .query(({ input }) => {
      const ruleSet = ruleSetStore.get(input.ruleSetId);
      if (!ruleSet) throw new TRPCError({ code: "NOT_FOUND", message: "Rule set not found" });
      return {
        content: exportRuleSet(ruleSet, input.format as ExportFormat),
        format: input.format,
        filename: `${ruleSet.name.replace(/\s+/g, "_")}_${input.format}.${input.format === "sigma" ? "yml" : input.format}`,
        totalRules: ruleSet.totalRules,
      };
    }),

  /** List all generated rule sets */
  listRuleSets: protectedProcedure.query(() => {
    return Array.from(ruleSetStore.values())
      .sort((a, b) => b.createdAt - a.createdAt)
      .map(rs => ({
        id: rs.id,
        name: rs.name,
        description: rs.description,
        source: rs.source,
        totalRules: rs.totalRules,
        byLevel: rs.byLevel,
        createdAt: rs.createdAt,
      }));
  }),

  /** Get a specific rule set with all rules */
  getRuleSet: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      const ruleSet = ruleSetStore.get(input.id);
      if (!ruleSet) throw new TRPCError({ code: "NOT_FOUND", message: "Rule set not found" });
      return ruleSet;
    }),

  /** Delete a rule set */
  deleteRuleSet: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      if (!ruleSetStore.has(input.id)) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Rule set not found" });
      }
      ruleSetStore.delete(input.id);
      return { success: true };
    }),
});
