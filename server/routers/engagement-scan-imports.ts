/**
 * Engagement Scan Report Ingestion Router
 *
 * Allows operators to upload vulnerability scan reports from commercial scanners
 * (Nessus, Qualys, Rapid7/Nexpose, Burp Suite, OWASP ZAP, OpenVAS) during engagements.
 *
 * Features:
 * - Auto-detect scanner format from file content
 * - Parse and normalize findings into platform schema
 * - Preview parsed findings before import (with dedup indicators)
 * - Import findings into engagement ops state (vulns per asset)
 * - Feed imported data into LLM corroboration/validation pipeline
 * - Track import history per engagement
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import type { ScannerType, ParsedVulnFinding, ParsedScanResult } from "../lib/vuln-scanner-parser";
import { assertEngagementAccess } from "../lib/engagement-access-guard";

const scannerTypeEnum = z.enum(["nessus", "qualys", "rapid7", "burp", "zap", "openvas", "custom"]);

export const engagementScanImportsRouter = router({
  /**
   * Auto-detect scanner format from file content and filename.
   */
  detectFormat: protectedProcedure
    .input(z.object({
      fileContent: z.string().max(500), // Only need first 500 chars for detection
      fileName: z.string(),
    }))
    .query(({ input }) => {
      const { detectScannerType, SCANNER_LABELS } = require("../lib/vuln-scanner-parser");
      const detected = detectScannerType(input.fileContent, input.fileName) as ScannerType;
      return {
        detectedType: detected,
        label: SCANNER_LABELS[detected] || "Unknown",
        confidence: detected === "custom" ? "low" : "high",
      };
    }),

  /**
   * Parse a scan report and return a preview of findings (without importing).
   * Includes deduplication indicators against existing engagement findings.
   */
  parsePreview: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      scannerType: scannerTypeEnum,
      fileContent: z.string(),
      fileName: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { parseVulnScan, detectScannerType, SCANNER_LABELS } = await import("../lib/vuln-scanner-parser");
      const { getOpsState, getOpsStateWithRecovery } = await import("../lib/engagement-orchestrator");

      // Auto-detect if custom
      const resolvedType = input.scannerType === "custom"
        ? detectScannerType(input.fileContent, input.fileName)
        : input.scannerType;

      // Parse the scan report
      const result = parseVulnScan(resolvedType, input.fileContent, input.fileName);

      // Get current engagement state for dedup checking
      let state = getOpsState(input.engagementId);
      if (!state) {
        state = await getOpsStateWithRecovery(input.engagementId);
      }

      // Build a set of existing finding keys for dedup detection
      const existingKeys = new Set<string>();
      if (state?.assets) {
        for (const asset of state.assets) {
          for (const v of (asset.vulns || [])) {
            if (v.cve) existingKeys.add(`cve:${v.cve.toUpperCase()}`);
            existingKeys.add(`title:${v.title.toLowerCase().replace(/[^a-z0-9]/g, "")}`);
          }
        }
      }

      // Annotate each finding with dedup status
      const preview = result.findings.map((f, idx) => {
        let isDuplicate = false;
        if (f.cveId && existingKeys.has(`cve:${f.cveId.toUpperCase()}`)) isDuplicate = true;
        if (!isDuplicate && existingKeys.has(`title:${f.title.toLowerCase().replace(/[^a-z0-9]/g, "")}`)) isDuplicate = true;

        return {
          index: idx,
          title: f.title,
          severity: f.severity,
          cveId: f.cveId,
          cweId: f.cweId || null,
          cvssScore: f.cvssScore,
          hostIp: f.hostIp,
          hostName: f.hostName,
          port: f.port,
          protocol: f.protocol,
          url: f.url || null,
          exploitAvailable: f.exploitAvailable,
          isDuplicate,
          description: f.description ? f.description.substring(0, 300) : null,
          solution: f.solution ? f.solution.substring(0, 300) : null,
        };
      });

      const newCount = preview.filter(p => !p.isDuplicate).length;
      const dupCount = preview.filter(p => p.isDuplicate).length;

      return {
        scannerType: resolvedType,
        scannerLabel: SCANNER_LABELS[resolvedType as ScannerType] || resolvedType,
        totalFindings: result.totalVulns,
        totalHosts: result.totalHosts,
        criticalCount: result.criticalCount,
        highCount: result.highCount,
        mediumCount: result.mediumCount,
        lowCount: result.lowCount,
        newFindings: newCount,
        duplicateFindings: dupCount,
        findings: preview,
      };
    }),

  /**
   * Import parsed scan findings into the engagement ops state.
   * Deduplicates against existing vulns, adds new findings to matching assets,
   * and triggers LLM validation on the imported batch.
   */
  importFindings: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      scannerType: scannerTypeEnum,
      fileContent: z.string(),
      fileName: z.string(),
      /** Optional: only import findings at these indices from the parsed result */
      selectedIndices: z.array(z.number()).optional(),
      /** Whether to run LLM validation on imported findings */
      runLlmValidation: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const { parseVulnScan, detectScannerType } = await import("../lib/vuln-scanner-parser");
      const { getOpsState, getOpsStateWithRecovery, initOpsState, pushVulnDeduped, addLog, saveOpsSnapshot } = await import("../lib/engagement-orchestrator");
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();

      // Resolve scanner type
      const resolvedType = input.scannerType === "custom"
        ? detectScannerType(input.fileContent, input.fileName)
        : input.scannerType;

      // Parse the scan report
      const result = parseVulnScan(resolvedType, input.fileContent, input.fileName);

      // Filter to selected indices if provided
      let findingsToImport = result.findings;
      if (input.selectedIndices && input.selectedIndices.length > 0) {
        findingsToImport = input.selectedIndices
          .filter(i => i >= 0 && i < result.findings.length)
          .map(i => result.findings[i]);
      }

      // Get or initialize engagement ops state
      let state = getOpsState(input.engagementId);
      if (!state) {
        state = await getOpsStateWithRecovery(input.engagementId);
      }
      if (!state) {
        const { getEngagementById, getDb } = await import("../db");
        // Verify user has access to this engagement
        const dbConn = await getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const engagement = await getEngagementById(input.engagementId, ctx.user);
        if (!engagement) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });
        state = initOpsState(input.engagementId, engagement.engagementType);
      }

      // ── Persist to vuln_scan_imports / vuln_scan_findings for cross-source corroboration ──
      let importId: number | null = null;
      if (db) {
        try {
          const importResult = await db.insert(vulnScanImports).values({
            vsiScannerType: resolvedType as any,
            vsiFileName: `[eng-${input.engagementId}] ${input.fileName}`,
            vsiTotalHosts: result.totalHosts,
            vsiTotalVulns: findingsToImport.length,
            vsiCritical: findingsToImport.filter(f => f.severity === "critical").length,
            vsiHigh: findingsToImport.filter(f => f.severity === "high").length,
            vsiMedium: findingsToImport.filter(f => f.severity === "medium").length,
            vsiLow: findingsToImport.filter(f => f.severity === "low").length,
            vsiImportedBy: String(ctx.user.id),
          });
          importId = importResult[0].insertId;

          if (findingsToImport.length > 0) {
            const dbFindings = findingsToImport.map(f => ({
              vsfImportId: importId!,
              vsfTitle: f.title.substring(0, 512),
              vsfSeverity: f.severity as any,
              vsfCveId: f.cveId || null,
              vsfCvssScore: f.cvssScore,
              vsfHostIp: f.hostIp,
              vsfHostName: f.hostName,
              vsfPort: f.port,
              vsfProtocol: f.protocol,
              vsfDescription: f.description,
              vsfSolution: f.solution,
              vsfPluginId: f.pluginId,
              vsfExploitAvailable: f.exploitAvailable ? 1 : 0,
            }));
            await db.insert(vulnScanFindings).values(dbFindings);
          }
        } catch (err: any) {
          console.error(`[EngScanImport] DB persist failed (non-fatal): ${err.message}`);
        }
      }

      // ── Inject findings into engagement ops state ──
      let added = 0;
      let skipped = 0;
      let assetsMatched = 0;
      const unmatchedHosts = new Set<string>();
      const genId = () => `scan-${resolvedType}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

      for (const finding of findingsToImport) {
        const findingHost = (finding.hostIp || finding.hostName || "").toLowerCase();
        if (!findingHost) {
          skipped++;
          continue;
        }

        // Find matching asset in engagement state
        let matchedAsset = state.assets.find((a: any) => {
          const aHost = (a.hostname || "").toLowerCase();
          const aIp = (a.ip || "").toLowerCase();
          return aHost === findingHost || aIp === findingHost ||
            findingHost.includes(aHost) || aHost.includes(findingHost);
        });

        // If no match, create a new asset entry
        if (!matchedAsset) {
          matchedAsset = {
            hostname: finding.hostName || finding.hostIp || findingHost,
            ip: finding.hostIp || undefined,
            type: "unknown" as const,
            ports: [],
            vulns: [],
            zapFindings: [],
            exploitAttempts: [],
            toolResults: [],
            status: "discovered" as const,
          };
          state.assets.push(matchedAsset);
          state.stats.assetsDiscovered = (state.stats.assetsDiscovered || 0) + 1;
          unmatchedHosts.add(findingHost);
        }

        // Add port if present and not already tracked
        if (finding.port && !matchedAsset.ports.some((p: any) => p.port === finding.port)) {
          matchedAsset.ports.push({
            port: finding.port,
            protocol: finding.protocol || "tcp",
            service: finding.title.split(" ")[0] || "unknown",
            state: "open",
          });
        }

        // Deduplicated vuln push
        const wasAdded = pushVulnDeduped(matchedAsset, {
          id: genId(),
          severity: finding.severity,
          title: finding.title,
          cve: finding.cveId || undefined,
          source: resolvedType,
          cvssScore: finding.cvssScore || undefined,
          exploitAvailable: finding.exploitAvailable,
          cweId: finding.cweId || undefined,
          url: finding.url || undefined,
          evidence: finding.evidence || undefined,
          description: finding.description?.substring(0, 500) || undefined,
          solution: finding.solution?.substring(0, 500) || undefined,
        });

        if (wasAdded) {
          added++;
          if (!unmatchedHosts.has(findingHost)) assetsMatched++;
        } else {
          skipped++;
        }
      }

      // Update stats
      state.stats.vulnsFound = state.assets.reduce((sum: number, a: any) => sum + (a.vulns?.length || 0), 0);

      // Add log entry
      addLog(state, {
        phase: state.phase || "vuln_detection",
        action: `Imported ${added} findings from ${resolvedType} scan report (${input.fileName}). ${skipped} duplicates skipped.`,
        severity: "info",
        data: {
          scanner: resolvedType,
          fileName: input.fileName,
          added,
          skipped,
          total: findingsToImport.length,
          newAssets: unmatchedHosts.size,
        },
      });

      // Save snapshot
      try {
        await saveOpsSnapshot(input.engagementId, state);
      } catch (err: any) {
        console.error(`[EngScanImport] Snapshot save failed: ${err.message}`);
      }

      // ── Run corroboration engine on all engagement findings ──
      let corroborationSummary: any = null;
      try {
        const { corroborateFindings, estimateFPReduction } = await import("../lib/corroboration-engine");
        // Collect all vulns across all assets
        const allVulns = state.assets.flatMap((a: any) =>
          (a.vulns || []).map((v: any) => ({
            id: v.id || genId(),
            title: v.title,
            source: v.source || "engagement",
            severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
            cveId: v.cve || undefined,
            hostOrAsset: a.hostname || a.ip || "unknown",
            port: v.port || undefined,
            service: v.protocol || undefined,
            rawConfidence: v.cvssScore ? Math.min(100, Math.round(v.cvssScore * 10)) : 50,
            timestamp: Date.now(),
          }))
        );

        if (allVulns.length > 0) {
          const report = corroborateFindings(allVulns);
          corroborationSummary = {
            totalAnalyzed: report.totalFindings,
            corroborated: report.corroboratedFindings,
            suppressed: report.suppressedFindings,
            falsePositiveRate: report.falsePositiveRate,
            estimatedFPReduction: estimateFPReduction(report),
          };
        }
      } catch (err: any) {
        console.error(`[EngScanImport] Corroboration failed (non-fatal): ${err.message}`);
      }

      // ── LLM Validation (cross-reference scanner evidence against engagement data) ──
      let llmValidation: any = null;
      if (input.runLlmValidation && added > 0) {
        try {
          llmValidation = await runLlmFindingValidation(
            input.engagementId,
            resolvedType,
            findingsToImport.filter(f => f.severity !== "info").slice(0, 25), // Validate top 25 non-info findings
            state,
          );
        } catch (err: any) {
          console.error(`[EngScanImport] LLM validation failed (non-fatal): ${err.message}`);
        }
      }

      return {
        importId,
        scanner: resolvedType,
        fileName: input.fileName,
        totalParsed: findingsToImport.length,
        added,
        skipped,
        newAssetsCreated: unmatchedHosts.size,
        assetsMatched,
        corroboration: corroborationSummary,
        llmValidation,
      };
    }),

  /**
   * List scan report imports for an engagement.
   */
  listImports: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanImports } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) return [];

      const { like, desc } = await import("drizzle-orm");
      const prefix = `[eng-${input.engagementId}]`;
      return db.select().from(vulnScanImports)
        .where(like(vulnScanImports.vsiFileName, `${prefix}%`))
        .orderBy(desc(vulnScanImports.vsiImportedAt));
    }),

  /**
   * Run LLM validation on a specific import's findings.
   */
  runLlmValidation: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      importId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanFindings } = await import("../../drizzle/schema");
      const { getOpsState, getOpsStateWithRecovery } = await import("../lib/engagement-orchestrator");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const { eq } = await import("drizzle-orm");
      const findings = await db.select().from(vulnScanFindings)
        .where(eq(vulnScanFindings.vsfImportId, input.importId));

      if (findings.length === 0) {
        throw new TRPCError({ code: "NOT_FOUND", message: "No findings found for this import" });
      }

      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);

      // Convert DB findings to ParsedVulnFinding format
      const parsedFindings: ParsedVulnFinding[] = findings
        .filter(f => f.vsfSeverity !== "info")
        .slice(0, 25)
        .map(f => ({
          cveId: f.vsfCveId,
          title: f.vsfTitle,
          severity: f.vsfSeverity as any,
          cvssScore: f.vsfCvssScore,
          hostIp: f.vsfHostIp,
          hostName: f.vsfHostName,
          port: f.vsfPort,
          protocol: f.vsfProtocol,
          description: f.vsfDescription,
          solution: f.vsfSolution,
          pluginId: f.vsfPluginId,
          exploitAvailable: !!f.vsfExploitAvailable,
        }));

      const scannerType = "external"; // Generic source label for re-validation
      const result = await runLlmFindingValidation(
        input.engagementId,
        scannerType,
        parsedFindings,
        state,
      );

      // Update DB findings with LLM verdicts
      if (result?.validations && db) {
        for (const v of result.validations) {
          const matchingFinding = findings.find(f =>
            f.vsfTitle === v.title ||
            (f.vsfCveId && f.vsfCveId === v.cveId)
          );
          if (matchingFinding) {
            await db.update(vulnScanFindings)
              .set({
                vsfCorroborationVerdict: v.verdict,
                vsfCorroborationScore: v.confidence,
              })
              .where(eq(vulnScanFindings.id, matchingFinding.id));
          }
        }
      }

      return result;
    }),

  /**
   * Get supported scanner formats with labels.
   */
  getSupportedFormats: protectedProcedure.query(() => {
    const { SCANNER_LABELS } = require("../lib/vuln-scanner-parser");
    return Object.entries(SCANNER_LABELS).map(([key, label]) => ({
      value: key,
      label: label as string,
      formats: getScannerFileFormats(key),
    }));
  }),
});

/**
 * Returns accepted file formats for each scanner type.
 */
function getScannerFileFormats(scanner: string): string {
  switch (scanner) {
    case "nessus": return ".nessus (XML)";
    case "qualys": return ".csv";
    case "rapid7": return ".csv";
    case "burp": return ".xml";
    case "zap": return ".xml, .json";
    case "openvas": return ".xml";
    case "custom": return ".csv, .xml, .json";
    default: return "any";
  }
}

/**
 * LLM-powered finding validation.
 *
 * Sends a batch of scanner findings to the LLM along with engagement context
 * (discovered assets, existing vulns, scan phase) to get validation verdicts.
 * The LLM cross-references scanner evidence against known CVE intelligence
 * and engagement-specific data to determine finding validity.
 */
async function runLlmFindingValidation(
  engagementId: number,
  scannerType: string,
  findings: ParsedVulnFinding[],
  engagementState: any,
): Promise<{
  validations: Array<{
    title: string;
    cveId: string | null;
    verdict: "confirmed" | "likely" | "unverified" | "likely_false_positive";
    confidence: number;
    reasoning: string;
  }>;
  summary: {
    confirmed: number;
    likely: number;
    unverified: number;
    likelyFalsePositive: number;
    averageConfidence: number;
  };
}> {
  const { invokeLLM } = await import("../_core/llm");

  // Build engagement context summary for the LLM
  const assetSummary = (engagementState?.assets || []).map((a: any) => ({
    host: a.hostname || a.ip,
    type: a.type,
    ports: (a.ports || []).map((p: any) => `${p.port}/${p.protocol} (${p.service || "unknown"})`).join(", "),
    existingVulns: (a.vulns || []).length,
    status: a.status,
  }));

  const findingsBatch = findings.map(f => ({
    title: f.title,
    severity: f.severity,
    cveId: f.cveId,
    cvssScore: f.cvssScore,
    host: f.hostIp || f.hostName,
    port: f.port,
    description: f.description?.substring(0, 200),
    exploitAvailable: f.exploitAvailable,
  }));

  const response = await invokeLLM({
    _caller: "engagement-scan-imports.runLlmFindingValidation",
    messages: [
      {
        role: "system",
        content: `You are a senior penetration tester validating vulnerability scan findings.
You are given a batch of findings from a ${scannerType} scanner along with the engagement's current asset inventory.
For each finding, assess whether it is a true positive or likely false positive based on:
1. Whether the reported host/port exists in the engagement's discovered assets
2. Whether the CVE is applicable to the detected services/versions
3. Whether the finding severity aligns with the CVSS score
4. Common false positive patterns for this scanner type
5. Whether corroborating evidence exists from other engagement data

Return a JSON array of validation objects.`,
      },
      {
        role: "user",
        content: `## Engagement Assets (${assetSummary.length} discovered)
${JSON.stringify(assetSummary.slice(0, 30), null, 2)}

## Scanner Findings to Validate (${findingsBatch.length} findings from ${scannerType})
${JSON.stringify(findingsBatch, null, 2)}

For each finding, return:
- title: the finding title
- cveId: the CVE ID if present
- verdict: one of "confirmed", "likely", "unverified", "likely_false_positive"
- confidence: 0-100 integer
- reasoning: brief explanation (1-2 sentences)`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "scan_finding_validations",
        strict: true,
        schema: {
          type: "object",
          properties: {
            validations: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  title: { type: "string" },
                  cveId: { type: ["string", "null"] },
                  verdict: { type: "string", enum: ["confirmed", "likely", "unverified", "likely_false_positive"] },
                  confidence: { type: "integer" },
                  reasoning: { type: "string" },
                },
                required: ["title", "cveId", "verdict", "confidence", "reasoning"],
                additionalProperties: false,
              },
            },
          },
          required: ["validations"],
          additionalProperties: false,
        },
      },
    },
  });

  let validations: any[] = [];
  try {
    const parsed = JSON.parse(response.choices[0].message.content || "{}");
    validations = parsed.validations || [];
  } catch {
    validations = [];
  }

  // Compute summary
  const confirmed = validations.filter((v: any) => v.verdict === "confirmed").length;
  const likely = validations.filter((v: any) => v.verdict === "likely").length;
  const unverified = validations.filter((v: any) => v.verdict === "unverified").length;
  const likelyFalsePositive = validations.filter((v: any) => v.verdict === "likely_false_positive").length;
  const totalConfidence = validations.reduce((sum: number, v: any) => sum + (v.confidence || 0), 0);

  return {
    validations,
    summary: {
      confirmed,
      likely,
      unverified,
      likelyFalsePositive,
      averageConfidence: validations.length > 0 ? Math.round(totalConfidence / validations.length) : 0,
    },
  };
}
