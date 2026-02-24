import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";

export const corroborationEngineRouter = router({
  /**
   * Corroborate a finding across multiple intelligence sources
   */
  corroborate: protectedProcedure
    .input(z.object({
      findingType: z.enum(["vulnerability", "credential", "domain", "ip", "indicator"]),
      findingValue: z.string().min(1),
      sources: z.array(z.enum(["nvd", "shodan", "censys", "urlscan", "abuseipdb", "virustotal", "securitytrails", "dehashed"])).optional(),
      includeHistorical: z.boolean().optional().default(false),
    }))
    .mutation(async ({ input }) => {
      const { corroborateFromSources } = await import("../lib/corroboration-engine");
      const result = await corroborateFromSources({
        findingType: input.findingType,
        findingValue: input.findingValue,
        requestedSources: input.sources,
        includeHistorical: input.includeHistorical,
      });
      return result;
    }),

  /**
   * Batch corroborate multiple findings
   */
  batchCorroborate: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        findingType: z.enum(["vulnerability", "credential", "domain", "ip", "indicator"]),
        findingValue: z.string().min(1),
      })).min(1).max(50),
      sources: z.array(z.enum(["nvd", "shodan", "censys", "urlscan", "abuseipdb", "virustotal", "securitytrails", "dehashed"])).optional(),
    }))
    .mutation(async ({ input }) => {
      const { corroborateFromSources } = await import("../lib/corroboration-engine");
      const results = [];
      for (const finding of input.findings) {
        const result = await corroborateFromSources({
          findingType: finding.findingType,
          findingValue: finding.findingValue,
          requestedSources: input.sources,
          includeHistorical: false,
        });
        results.push({ ...finding, ...result });
      }
      const confirmedCount = results.filter(r => r.overallVerdict === "confirmed").length;
      const falsePositiveCount = results.filter(r => r.overallVerdict === "false_positive").length;
      return {
        total: results.length,
        confirmedCount,
        falsePositiveCount,
        suspiciousCount: results.filter(r => r.overallVerdict === "suspicious").length,
        unverifiedCount: results.filter(r => r.overallVerdict === "unverified").length,
        falsePositiveRate: results.length > 0 ? Math.round((falsePositiveCount / results.length) * 100) : 0,
        results,
      };
    }),

  /**
   * Get available corroboration sources and their status
   */
  getSources: protectedProcedure.query(async () => {
    const { getAvailableSources } = await import("../lib/corroboration-engine");
    return getAvailableSources();
  }),

  exportReport: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        findingType: z.enum(["vulnerability", "credential", "domain", "ip", "indicator"]),
        findingValue: z.string().min(1),
      })).min(1).max(50),
      sources: z.array(z.enum(["nvd", "shodan", "censys", "urlscan", "abuseipdb", "virustotal", "securitytrails", "dehashed"])).optional(),
    }))
    .mutation(async ({ input }) => {
      const { corroborateFromSources, getAvailableSources } = await import("../lib/corroboration-engine");
      const sources = getAvailableSources();
      const enabledSources = sources.filter((s: any) => s.configured);

      const results: any[] = [];
      for (const finding of input.findings) {
        const result = await corroborateFromSources({
          findingType: finding.findingType,
          findingValue: finding.findingValue,
          requestedSources: input.sources,
          includeHistorical: false,
        });
        results.push({
          host: finding.findingValue,
          title: `${finding.findingType}: ${finding.findingValue}`,
          sourcesConfirming: result.sourcesConfirming || 0,
          sourcesQueried: enabledSources.length,
          adjustedConfidence: result.adjustedConfidence,
          originalConfidence: result.originalConfidence || 0.5,
          verdict: result.overallVerdict || "unverified",
        });
      }

      const report = {
        totalFindings: input.findings.length,
        corroboratedFindings: results.filter(r => r.verdict === "confirmed").length,
        contradictions: results.filter(r => r.verdict === "false_positive").length,
        estimatedFalsePositiveReduction: results.length > 0
          ? Math.round((results.filter(r => r.verdict === "false_positive").length / results.length) * 100)
          : 0,
        sourcesQueried: enabledSources.length,
        results,
      };

      const { generateCorroborationReport } = await import("../lib/pdf-report-generator");
      const html = generateCorroborationReport(report);
      return { html, filename: `corroboration-report-${Date.now()}.html` };
    }),
});
