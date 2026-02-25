/**
 * Discovery Engine Router
 *
 * Provides tRPC endpoints for:
 * 1. Standalone discovery scans (Shodan, Censys, SecurityTrails)
 * 2. Cross-module enrichment queries
 * 3. Available source status checks
 * 4. Individual API lookups (host, cert, DNS history)
 *
 * These endpoints complement the main domain intel pipeline by providing
 * direct access to discovery capabilities for ad-hoc investigations.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const discoveryEngineRouter = router({
  // ─── Source Status ──────────────────────────────────────────────────
  getAvailableSources: protectedProcedure.query(async () => {
    const { getAvailableSources } = await import("../lib/discovery-engine");
    return getAvailableSources();
  }),

  // ─── Standalone Discovery Scan ────────────────────────────────────
  runScan: protectedProcedure
    .input(z.object({
      targets: z.array(z.object({
        domain: z.string().optional(),
        ip: z.string().optional(),
        cidr: z.string().optional(),
      })).min(1).max(10),
      scanDepth: z.enum(["quick", "standard", "deep"]).default("standard"),
      enabledSources: z.object({
        shodan: z.boolean().default(true),
        censys: z.boolean().default(true),
        securityTrails: z.boolean().default(true),
        crtsh: z.boolean().default(true),
      }).optional(),
      enrichmentModules: z.array(z.enum([
        "domain_intel", "bug_bounty", "threat_enrichment", "opsec",
      ])).default(["domain_intel", "bug_bounty", "threat_enrichment", "opsec"]),
    }))
    .mutation(async ({ input }) => {
      const { runDiscoveryPipeline } = await import("../lib/discovery-engine");

      const targets = input.targets.map(t => ({
        domain: t.domain,
        ip: t.ip,
        cidr: t.cidr,
      }));

      const result = await runDiscoveryPipeline(targets, {
        scanDepth: input.scanDepth,
        enabledSources: {
          shodan: input.enabledSources?.shodan ?? true,
          censys: input.enabledSources?.censys ?? true,
          securityTrails: input.enabledSources?.securityTrails ?? true,
          nuclei: false,
          crtsh: input.enabledSources?.crtsh ?? true,
          wayback: true,
          dnsEnum: true,
          whois: true,
        },
        enrichmentModules: input.enrichmentModules,
      });

      return result;
    }),

  // ─── Individual Lookups ───────────────────────────────────────────

  shodanHostLookup: protectedProcedure
    .input(z.object({ ip: z.string() }))
    .query(async ({ input }) => {
      const { shodanHostLookup } = await import("../lib/discovery-engine");
      const result = await shodanHostLookup(input.ip);
      if (!result) throw new TRPCError({ code: "NOT_FOUND", message: `No Shodan data for ${input.ip}` });
      return result;
    }),

  shodanDomainSearch: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(async ({ input }) => {
      const { shodanDomainSearch } = await import("../lib/discovery-engine");
      return shodanDomainSearch(input.domain);
    }),

  censysHostSearch: protectedProcedure
    .input(z.object({ query: z.string() }))
    .query(async ({ input }) => {
      const { censysHostSearch } = await import("../lib/discovery-engine");
      return censysHostSearch(input.query);
    }),

  censysCertSearch: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(async ({ input }) => {
      const { censysCertSearch } = await import("../lib/discovery-engine");
      return censysCertSearch(input.domain);
    }),

  securityTrailsSubdomains: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(async ({ input }) => {
      const { securityTrailsSubdomains } = await import("../lib/discovery-engine");
      return securityTrailsSubdomains(input.domain);
    }),

  securityTrailsDNSHistory: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(async ({ input }) => {
      const { securityTrailsDNSHistory } = await import("../lib/discovery-engine");
      return securityTrailsDNSHistory(input.domain);
    }),

  securityTrailsDomainInfo: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(async ({ input }) => {
      const { securityTrailsDomainInfo } = await import("../lib/discovery-engine");
      return securityTrailsDomainInfo(input.domain);
    }),

  securityTrailsWHOIS: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(async ({ input }) => {
      const { securityTrailsWHOIS } = await import("../lib/discovery-engine");
      return securityTrailsWHOIS(input.domain);
    }),

  // ─── Cross-Module Enrichment (standalone) ─────────────────────────

  runCrossModuleEnrichment: protectedProcedure
    .input(z.object({
      scanId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { getDbRequired } = await import("../db");
      const { domainIntelScans } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const dbConn = await getDbRequired();
      const [scan] = await dbConn.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId)).limit(1);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      const pipelineOutput = scan.pipelineOutput as any;
      if (!pipelineOutput?.assets) throw new TRPCError({ code: "BAD_REQUEST", message: "Scan has no analyzed assets" });

      const { runCrossModuleEnrichment } = await import("../lib/cross-module-enrichment");
      const result = await runCrossModuleEnrichment(
        pipelineOutput.assets,
        scan.primaryDomain,
        pipelineOutput.passiveRecon,
      );

      return result;
    }),

  // ─── Post-Enrichment Analysis (standalone) ────────────────────────

  runPostEnrichmentAnalysis: protectedProcedure
    .input(z.object({
      scanId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { getDbRequired } = await import("../db");
      const { domainIntelScans } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const dbConn = await getDbRequired();
      const [scan] = await dbConn.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId)).limit(1);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      const pipelineOutput = scan.pipelineOutput as any;
      if (!pipelineOutput?.assets) throw new TRPCError({ code: "BAD_REQUEST", message: "Scan has no analyzed assets" });

      const { runPostEnrichmentAnalysis } = await import("../lib/llm-post-enrichment-analysis");
      const result = await runPostEnrichmentAnalysis(
        pipelineOutput.assets,
        pipelineOutput.orgProfile || { primaryDomain: scan.primaryDomain, customerName: scan.primaryDomain, sector: scan.sector || "technology", clientType: scan.clientType },
        pipelineOutput.crossModuleEnrichment,
      );

      return result;
    }),

  // ─── LLM Scan Analysis ────────────────────────────────────────────

  analyzeScan: protectedProcedure
    .input(z.object({
      scanId: z.number().optional(),
      discoveryResult: z.any().optional(),
    }))
    .mutation(async ({ input }) => {
      if (input.discoveryResult) {
        const { analyzeScanWithLLM } = await import("../lib/discovery-engine");
        return analyzeScanWithLLM(input.discoveryResult);
      }

      if (input.scanId) {
        const { getDbRequired } = await import("../db");
        const { domainIntelScans } = await import("../../drizzle/schema");
        const { eq } = await import("drizzle-orm");

        const dbConn = await getDbRequired();
        const [scan] = await dbConn.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId)).limit(1);
        if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

        const pipelineOutput = scan.pipelineOutput as any;
        if (!pipelineOutput) throw new TRPCError({ code: "BAD_REQUEST", message: "Scan has no pipeline output" });

        // Build a DiscoveryResult-compatible object from pipeline output
        const { analyzeScanWithLLM } = await import("../lib/discovery-engine");
        const discoveryResult = {
          id: `scan_${scan.id}`,
          startedAt: scan.createdAt?.toISOString() || new Date().toISOString(),
          completedAt: scan.updatedAt?.toISOString() || new Date().toISOString(),
          status: "completed" as const,
          targets: [{ domain: scan.primaryDomain }],
          config: { targets: [{ domain: scan.primaryDomain }], scanDepth: "standard" as const, enabledSources: {}, scanMode: "passive" as const, enrichmentModules: [], maxConcurrency: 3, timeoutMs: 120000 },
          hosts: [],
          subdomains: [],
          dnsRecords: [],
          certificates: [],
          nucleiFindings: [],
          sourceStats: [],
          summary: {
            totalHosts: pipelineOutput.assets?.length || 0,
            totalPorts: 0,
            totalSubdomains: pipelineOutput.totalSubdomainAssets || 0,
            totalVulnerabilities: pipelineOutput.totalFindings || 0,
            totalCertificates: 0,
            criticalFindings: 0,
            highFindings: 0,
            mediumFindings: 0,
            lowFindings: 0,
            infoFindings: 0,
            uniqueServices: [],
            uniqueProducts: [],
            exposedPorts: [],
            riskScore: pipelineOutput.overallRiskScore || 0,
            riskBand: pipelineOutput.overallRiskBand || "minimal",
          },
          enrichmentResults: [],
          llmAnalysis: null,
        };

        return analyzeScanWithLLM(discoveryResult as any);
      }

      throw new TRPCError({ code: "BAD_REQUEST", message: "Provide either scanId or discoveryResult" });
    }),
});
