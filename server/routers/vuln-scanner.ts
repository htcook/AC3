import * as db from "../db";
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const vulnScannerRouter = router({
  listImports: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { vulnScanImports } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    return db.select().from(vulnScanImports).orderBy(desc(vulnScanImports.importedAt));
  }),

  importScan: protectedProcedure
    .input(z.object({ scannerType: z.enum(["nessus", "qualys", "rapid7", "openvas", "custom"]), fileContent: z.string(), fileName: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings } = await import("../../drizzle/schema");
      const { parseVulnScan } = await import("../lib/vuln-scanner-parser");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      // ── Deduplication guard: skip if same file was already imported ──
      const { eq: eqCheck, and: andCheck } = await import("drizzle-orm");
      const [existingImport] = await db.select({ id: vulnScanImports.id })
        .from(vulnScanImports)
        .where(andCheck(
          eqCheck(vulnScanImports.fileName, input.fileName),
          eqCheck(vulnScanImports.scannerType, input.scannerType)
        ))
        .limit(1);
      if (existingImport) {
        throw new TRPCError({ code: "CONFLICT", message: `Scan file "${input.fileName}" from ${input.scannerType} was already imported (import #${existingImport.id}). Delete the existing import first to re-import.` });
      }

      const result = await parseVulnScan(input.scannerType, input.fileContent);

      const importResult = await db.insert(vulnScanImports).values({
        scannerType: input.scannerType,
        fileName: input.fileName,
        totalHosts: result.totalHosts,
        totalVulns: result.totalVulns,
        criticalCount: result.criticalCount,
        highCount: result.highCount,
        mediumCount: result.mediumCount,
        lowCount: result.lowCount,
        importedBy: String(ctx.user.id),
      });

      const importId = importResult[0].insertId;

      if (result.findings.length > 0) {
        const findingsToInsert = result.findings.map((f) => ({
          importId,
          cveId: f.cveId,
          title: f.title,
          severity: f.severity,
          cvssScore: f.cvssScore,
          hostIp: f.hostIp,
          hostName: f.hostName,
          port: f.port,
          protocol: f.protocol,
          description: f.description,
          solution: f.solution,
          pluginId: f.pluginId,
          exploitAvailable: f.exploitAvailable,
        }));
        await db.insert(vulnScanFindings).values(findingsToInsert);
      }

      // --- Auto-corroboration pipeline ---
      // Fetch ALL findings across ALL imports for this host set to enable cross-source corroboration
      const { corroborateFindings, estimateFPReduction } = await import("../lib/corroboration-engine");
      const { corroborationResults } = await import("../../drizzle/schema");
      const { eq: eqOp, inArray } = await import("drizzle-orm");
      
      // Get all findings for the hosts in this import
      const importedFindings = await db.select().from(vulnScanFindings).where(eqOp(vulnScanFindings.importId, importId));
      
      // Get all other findings for the same hosts (cross-source)
      const hostIps = Array.from(new Set(importedFindings.map(f => f.hostIp).filter(Boolean))) as string[];
      let allFindings = importedFindings;
      if (hostIps.length > 0) {
        const crossSourceFindings = await db.select().from(vulnScanFindings).where(inArray(vulnScanFindings.hostIp, hostIps));
        allFindings = crossSourceFindings;
      }
      
      // Map DB findings to corroboration engine Finding interface
      const engineFindings = allFindings.map(f => ({
        id: String(f.id),
        title: f.title,
        source: input.scannerType,
        severity: f.severity as "critical" | "high" | "medium" | "low" | "info",
        cveId: f.cveId ?? undefined,
        hostOrAsset: f.hostIp || f.hostName || "unknown",
        port: f.port ?? undefined,
        service: f.protocol ?? undefined,
        rawConfidence: f.cvssScore ? Math.min(100, Math.round(f.cvssScore * 10)) : 50,
        timestamp: f.createdAt ? new Date(f.createdAt).getTime() : Date.now(),
      }));
      
      // Run corroboration
      const corroborationReport = corroborateFindings(engineFindings);
      
      // Update findings with corroboration scores and store detailed results
      for (const cr of corroborationReport.results) {
        const findingId = parseInt(cr.findingId);
        if (isNaN(findingId)) continue;
        
        // Update the finding row with corroboration data
        await db.update(vulnScanFindings)
          .set({
            corroborationScore: cr.adjustedConfidence,
            corroborationVerdict: cr.verdict,
            corroborationSources: cr.corroboratingSourceCount,
            suppressRecommended: cr.suppressRecommendation,
          })
          .where(eqOp(vulnScanFindings.id, findingId));
        
        // Store detailed corroboration result
        await db.insert(corroborationResults).values({
          importId,
          findingId,
          originalConfidence: cr.originalConfidence,
          adjustedConfidence: cr.adjustedConfidence,
          corroboratingCount: cr.corroboratingSourceCount,
          contradictingCount: cr.contradictingSourceCount,
          corroboratingSources: cr.corroboratingSources.join(","),
          contradictingSources: cr.contradictingSources.join(","),
          verdict: cr.verdict,
          reasoning: cr.reasoning,
          suppressRecommendation: cr.suppressRecommendation,
        });
      }
      
      const fpReduction = estimateFPReduction(corroborationReport);

      // ─── SSIL: Auto-ingest into observation normalizer ───
      try {
        const { ingestVulnScanImportFindings } = await import("../lib/observation-ingestor");
        const ingestion = await ingestVulnScanImportFindings(importedFindings);
        console.log(`[VulnScanner→SSIL] Ingested ${ingestion.observations} observations, ${ingestion.signals} signals, ${ingestion.riskCards} risk cards`);
      } catch (err: any) {
        console.error(`[VulnScanner→SSIL] Ingestion failed (non-fatal): ${err.message}`);
      }

      return {
        id: importId,
        totalVulns: result.totalVulns,
        totalHosts: result.totalHosts,
        corroboration: {
          totalAnalyzed: corroborationReport.totalFindings,
          corroborated: corroborationReport.corroboratedFindings,
          suppressed: corroborationReport.suppressedFindings,
          estimatedFPReduction: fpReduction,
        },
      };
    }),

  getImportDetails: protectedProcedure
    .input(z.object({ importId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const scanImport = await db.select().from(vulnScanImports).where(eq(vulnScanImports.id, input.importId));
      if (!scanImport[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Import not found" });
      const findings = await db.select().from(vulnScanFindings).where(eq(vulnScanFindings.importId, input.importId));
      return { import: scanImport[0], findings };
    }),

  listFindings: protectedProcedure
    .input(z.object({ importId: z.number().optional(), severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(), cveId: z.string().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { and, eq } = await import("drizzle-orm");
      const conditions = [];
      if (input.importId) conditions.push(eq(vulnScanFindings.importId, input.importId));
      if (input.severity) conditions.push(eq(vulnScanFindings.severity, input.severity));
      if (input.cveId) conditions.push(eq(vulnScanFindings.cveId, input.cveId));
      return db.select().from(vulnScanFindings).where(conditions.length ? and(...conditions) : undefined);
    }),

  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { vulnScanImports } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { sql } = await import("drizzle-orm");
    // FIPS / Dedup: Use COUNT DISTINCT on vulnScanFindings for accurate unique counts
    // instead of SUM across imports (which inflates counts when scans overlap)
    const { vulnScanFindings } = await import("../../drizzle/schema");
    const importCount = await db.select({
      totalImports: sql<number>`count(*)`,
    }).from(vulnScanImports);
    const dedupStats = await db.select({
      totalHosts: sql<number>`COUNT(DISTINCT ${vulnScanFindings.hostIp})`,
      totalVulns: sql<number>`COUNT(DISTINCT ${vulnScanFindings.cveId})`,
      critical: sql<number>`COUNT(DISTINCT CASE WHEN ${vulnScanFindings.severity} = 'critical' THEN ${vulnScanFindings.cveId} END)`,
      high: sql<number>`COUNT(DISTINCT CASE WHEN ${vulnScanFindings.severity} = 'high' THEN ${vulnScanFindings.cveId} END)`,
      medium: sql<number>`COUNT(DISTINCT CASE WHEN ${vulnScanFindings.severity} = 'medium' THEN ${vulnScanFindings.cveId} END)`,
      low: sql<number>`COUNT(DISTINCT CASE WHEN ${vulnScanFindings.severity} = 'low' THEN ${vulnScanFindings.cveId} END)`,
    }).from(vulnScanFindings);
    return {
      totalImports: importCount[0]?.totalImports ?? 0,
      ...(dedupStats[0] ?? { totalHosts: 0, totalVulns: 0, critical: 0, high: 0, medium: 0, low: 0 }),
    };
  }),

  deleteImport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings, corroborationResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.transaction(async (tx) => {
        await tx.delete(corroborationResults).where(eq(corroborationResults.importId, input.id));
        await tx.delete(vulnScanFindings).where(eq(vulnScanFindings.importId, input.id));
        await tx.delete(vulnScanImports).where(eq(vulnScanImports.id, input.id));
      });
      return { success: true };
    }),

  // Corroboration-specific endpoints
  getCorroborationSummary: protectedProcedure
    .input(z.object({ importId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { corroborationResults } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq, sql } = await import("drizzle-orm");
      
      const results = await db.select().from(corroborationResults).where(eq(corroborationResults.importId, input.importId));
      
      const summary = {
        totalAnalyzed: results.length,
        confirmed: results.filter(r => r.verdict === "confirmed").length,
        likely: results.filter(r => r.verdict === "likely").length,
        unverified: results.filter(r => r.verdict === "unverified").length,
        likelyFP: results.filter(r => r.verdict === "likely_false_positive").length,
        falsePositive: results.filter(r => r.verdict === "false_positive").length,
        suppressed: results.filter(r => r.suppressRecommendation).length,
        avgConfidence: results.length > 0 ? Math.round(results.reduce((sum, r) => sum + r.adjustedConfidence, 0) / results.length) : 0,
        fpReductionPercent: results.length > 0 ? Math.round((results.filter(r => r.suppressRecommendation).length / results.length) * 100) : 0,
      };
      return summary;
    }),

  getCorroborationDetails: protectedProcedure
    .input(z.object({ importId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { corroborationResults, vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      
      const results = await db.select().from(corroborationResults).where(eq(corroborationResults.importId, input.importId));
      const findings = await db.select().from(vulnScanFindings).where(eq(vulnScanFindings.importId, input.importId));
      
      // Join corroboration results with finding details
      return results.map(cr => {
        const finding = findings.find(f => f.id === cr.findingId);
        return {
          ...cr,
          findingTitle: finding?.title ?? "Unknown",
          findingCve: finding?.cveId ?? null,
          findingSeverity: finding?.severity ?? "info",
          findingHost: finding?.hostIp ?? finding?.hostName ?? "unknown",
        };
      });
    }),

  // ─── Scanner API Integration ──────────────────────────────────────

  validateScannerConnection: protectedProcedure
    .input(z.object({
      type: z.enum(["nessus", "tenable_io", "qualys", "rapid7"]),
      baseUrl: z.string(),
      apiKey: z.string().optional(),
      apiSecret: z.string().optional(),
      username: z.string().optional(),
      password: z.string().optional(),
      accessKey: z.string().optional(),
      secretKey: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { validateConnection } = await import("../lib/scanner-api-integration");
      return validateConnection(input);
    }),

  listRemoteScans: protectedProcedure
    .input(z.object({
      type: z.enum(["nessus", "tenable_io", "qualys", "rapid7"]),
      baseUrl: z.string(),
      apiKey: z.string().optional(),
      apiSecret: z.string().optional(),
      username: z.string().optional(),
      password: z.string().optional(),
      accessKey: z.string().optional(),
      secretKey: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { listRemoteScans } = await import("../lib/scanner-api-integration");
      return listRemoteScans(input);
    }),

  pullRemoteScan: protectedProcedure
    .input(z.object({
      type: z.enum(["nessus", "tenable_io", "qualys", "rapid7"]),
      baseUrl: z.string(),
      scanId: z.string(),
      apiKey: z.string().optional(),
      apiSecret: z.string().optional(),
      username: z.string().optional(),
      password: z.string().optional(),
      accessKey: z.string().optional(),
      secretKey: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { pullScanResults } = await import("../lib/scanner-api-integration");
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const result = await pullScanResults(input, input.scanId);

      const importResult = await db.insert(vulnScanImports).values({
        scannerType: input.type,
        fileName: `API Pull: ${input.type} scan #${input.scanId}`,
        totalHosts: result.totalHosts,
        totalVulns: result.totalVulns,
        criticalCount: result.criticalCount,
        highCount: result.highCount,
        mediumCount: result.mediumCount,
        lowCount: result.lowCount,
        importedBy: String(ctx.user.id),
      });

      const importId = importResult[0].insertId;

      if (result.findings.length > 0) {
        const findingsToInsert = result.findings.map((f) => ({
          importId,
          cveId: f.cveId,
          title: f.title,
          severity: f.severity,
          cvssScore: f.cvssScore,
          hostIp: f.hostIp,
          hostName: f.hostName,
          port: f.port,
          protocol: f.protocol,
          description: f.description,
          solution: f.solution,
          pluginId: f.pluginId,
          exploitAvailable: f.exploitAvailable,
        }));
        await db.insert(vulnScanFindings).values(findingsToInsert);
      }

      // Run auto-corroboration
      const { corroborateFindings, estimateFPReduction } = await import("../lib/corroboration-engine");
      const { corroborationResults } = await import("../../drizzle/schema");
      const { eq: eqOp, inArray } = await import("drizzle-orm");

      const importedFindings = await db.select().from(vulnScanFindings).where(eqOp(vulnScanFindings.importId, importId));
      const hostIps = Array.from(new Set(importedFindings.map(f => f.hostIp).filter(Boolean))) as string[];
      let allFindings = importedFindings;
      if (hostIps.length > 0) {
        allFindings = await db.select().from(vulnScanFindings).where(inArray(vulnScanFindings.hostIp, hostIps));
      }

      const engineFindings = allFindings.map(f => ({
        id: String(f.id),
        title: f.title,
        source: input.type,
        severity: f.severity as "critical" | "high" | "medium" | "low" | "info",
        cveId: f.cveId ?? undefined,
        hostOrAsset: f.hostIp || f.hostName || "unknown",
        port: f.port ?? undefined,
        service: f.protocol ?? undefined,
        rawConfidence: f.cvssScore ? Math.min(100, Math.round(f.cvssScore * 10)) : 50,
        timestamp: f.createdAt ? new Date(f.createdAt).getTime() : Date.now(),
      }));

      const corroborationReport = corroborateFindings(engineFindings);

      for (const cr of corroborationReport.results) {
        const findingId = parseInt(cr.findingId);
        if (isNaN(findingId)) continue;
        await db.update(vulnScanFindings)
          .set({
            corroborationScore: cr.adjustedConfidence,
            corroborationVerdict: cr.verdict,
            corroborationSources: cr.corroboratingSourceCount,
            suppressRecommended: cr.suppressRecommendation,
          })
          .where(eqOp(vulnScanFindings.id, findingId));
        await db.insert(corroborationResults).values({
          importId,
          findingId,
          originalConfidence: cr.originalConfidence,
          adjustedConfidence: cr.adjustedConfidence,
          corroboratingCount: cr.corroboratingSourceCount,
          contradictingCount: cr.contradictingSourceCount,
          corroboratingSources: cr.corroboratingSources.join(","),
          contradictingSources: cr.contradictingSources.join(","),
          verdict: cr.verdict,
          reasoning: cr.reasoning,
          suppressRecommendation: cr.suppressRecommendation,
        });
      }

      const fpReduction = estimateFPReduction(corroborationReport);

      return {
        id: importId,
        totalVulns: result.totalVulns,
        totalHosts: result.totalHosts,
        corroboration: {
          totalAnalyzed: corroborationReport.totalFindings,
          corroborated: corroborationReport.corroboratedFindings,
          suppressed: corroborationReport.suppressedFindings,
          estimatedFPReduction: fpReduction,
        },
      };
    }),

  // ─── SCAP Compliance Scanning ─────────────────────────────────────

  runComplianceScan: protectedProcedure
    .input(z.object({
      target: z.string(),
      categories: z.array(z.enum([
        "tls_configuration", "http_security_headers", "dns_security",
        "service_hardening", "authentication", "access_control",
        "logging_auditing", "network_security", "cryptography", "patch_management"
      ])).optional(),
      benchmarks: z.array(z.enum(["cis", "disa_stig", "nist_800_53", "fedramp", "custom"])).optional(),
      timeout: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const { runExternalComplianceScan } = await import("../lib/scap-compliance-scanner");
      return runExternalComplianceScan(input.target, {
        timeout: input.timeout,
        categories: input.categories,
        benchmarks: input.benchmarks,
      });
    }),

  importComplianceReport: protectedProcedure
    .input(z.object({
      target: z.string(),
      reportType: z.enum(["openscap_xccdf", "lynis"]),
      reportContent: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { parseOpenSCAPResults, parseLynisReport } = await import("../lib/scap-compliance-scanner");
      if (input.reportType === "openscap_xccdf") {
        return parseOpenSCAPResults(input.reportContent, input.target);
      } else {
        return parseLynisReport(input.reportContent, input.target);
      }
    }),

  getGlobalCorroborationStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { corroborationResults } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { sql } = await import("drizzle-orm");
    
    const stats = await db.select({
      totalResults: sql<number>`count(*)`,
      avgOriginal: sql<number>`COALESCE(AVG(${corroborationResults.originalConfidence}), 0)`,
      avgAdjusted: sql<number>`COALESCE(AVG(${corroborationResults.adjustedConfidence}), 0)`,
      totalSuppressed: sql<number>`SUM(CASE WHEN ${corroborationResults.suppressRecommendation} = true THEN 1 ELSE 0 END)`,
      confirmed: sql<number>`SUM(CASE WHEN ${corroborationResults.verdict} = 'confirmed' THEN 1 ELSE 0 END)`,
      likely: sql<number>`SUM(CASE WHEN ${corroborationResults.verdict} = 'likely' THEN 1 ELSE 0 END)`,
      falsePositive: sql<number>`SUM(CASE WHEN ${corroborationResults.verdict} = 'false_positive' THEN 1 ELSE 0 END)`,
    }).from(corroborationResults);
    
    const s = stats[0];
    return {
      totalFindings: s.totalResults,
      avgOriginalConfidence: Math.round(s.avgOriginal),
      avgAdjustedConfidence: Math.round(s.avgAdjusted),
      totalSuppressed: s.totalSuppressed,
      confirmedCount: s.confirmed,
      likelyCount: s.likely,
      falsePositiveCount: s.falsePositive,
      fpReductionPercent: s.totalResults > 0 ? Math.round((s.totalSuppressed / s.totalResults) * 100) : 0,
    };
  }),
});
