/**
 * Compliance Exports Router
 *
 * Provides three key compliance export capabilities:
 *   1. NVD CVE-to-CWE live lookup (single + batch)
 *   2. NIST 800-53 compliance report generation (structured JSON for PDF rendering)
 *   3. MITRE ATT&CK Navigator layer JSON export
 *
 * @author Harrison Cook — AceofCloud
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { lookupCve, batchLookupCves, getCacheStats, clearCache } from "../lib/nvd-cve-lookup";
import {
  getCachedEnrichment,
  getBatchCachedEnrichments,
  runEnrichmentBatch,
  getEnrichmentStats,
  extractAllCveIds,
} from "../lib/cve-enrichment-service";
import {
  enrichFinding,
  generateNistGapSummary,
  getImpactedNistFamilies,
  getMitreForCwe,
  getNistControlsForCwe,
  NIST_CONTROL_FAMILIES,
  CWE_TO_NIST,
  CWE_TO_MITRE,
  MITRE_TO_NIST,
  type NistControl,
  type MitreTechnique,
  type CweEntry,
  type FindingEnrichment,
} from "../lib/nist-mitre-cwe-mapper";

// ─── NVD CVE Lookup Procedures ──────────────────────────────────────────────

const nvdLookupProcedures = {
  /**
   * Look up a single CVE and return its CWE mappings + CVSS data
   */
  lookupCve: protectedProcedure
    .input(z.object({
      cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i, "Invalid CVE ID format"),
      skipCache: z.boolean().optional(),
    }))
    .query(async ({ input }) => {
      const result = await lookupCve(input.cveId, { skipCache: input.skipCache });

      // Also enrich with NIST/MITRE mappings if CWEs were found
      let enrichment: FindingEnrichment | null = null;
      if (result.cwes.length > 0) {
        enrichment = enrichFinding({
          cwes: result.cwes,
          severity: cvssToSeverity(result.cvssV3Score),
        });
      }

      return {
        ...result,
        enrichment,
      };
    }),

  /**
   * Batch lookup multiple CVEs
   */
  batchLookupCves: protectedProcedure
    .input(z.object({
      cveIds: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/i)).max(50, "Maximum 50 CVEs per batch"),
      skipCache: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const results = await batchLookupCves(input.cveIds, { skipCache: input.skipCache });

      // Enrich each result
      const enrichedResults = results.map(result => {
        let enrichment: FindingEnrichment | null = null;
        if (result.cwes.length > 0) {
          enrichment = enrichFinding({
            cwes: result.cwes,
            severity: cvssToSeverity(result.cvssV3Score),
          });
        }
        return { ...result, enrichment };
      });

      return {
        results: enrichedResults,
        summary: {
          total: enrichedResults.length,
          resolved: enrichedResults.filter(r => r.cwes.length > 0).length,
          cached: enrichedResults.filter(r => r.cached).length,
          errors: enrichedResults.filter(r => r.error).length,
        },
      };
    }),

  /**
   * Get NVD cache statistics
   */
  nvdCacheStats: protectedProcedure
    .query(() => getCacheStats()),

  /**
   * Clear the NVD lookup cache
   */
  clearNvdCache: protectedProcedure
    .mutation(() => {
      clearCache();
      return { success: true };
    }),

  // ─── CVE Enrichment (DB-cached) ────────────────────────────────────────────

  /**
   * Get a single CVE's enrichment from the database cache.
   * Falls back to live NVD API if not cached.
   */
  getCveEnrichment: protectedProcedure
    .input(z.object({
      cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i, "Invalid CVE ID format"),
    }))
    .query(async ({ input }) => {
      const normalized = input.cveId.toUpperCase();

      // Try DB cache first
      const cached = await getCachedEnrichment(normalized);
      if (cached && !cached.error) {
        let enrichment: FindingEnrichment | null = null;
        if (cached.cwes.length > 0) {
          enrichment = enrichFinding({
            cwes: cached.cwes,
            severity: cvssToSeverity(cached.cvssV3Score),
          });
        }
        return { ...cached, source: "db" as const, enrichment };
      }

      // Fallback to live NVD API
      const result = await lookupCve(normalized);
      let enrichment: FindingEnrichment | null = null;
      if (result.cwes.length > 0) {
        enrichment = enrichFinding({
          cwes: result.cwes,
          severity: cvssToSeverity(result.cvssV3Score),
        });
      }
      return { ...result, source: "nvd" as const, enrichment };
    }),

  /**
   * Get batch CVE enrichments from the database cache.
   */
  getBatchCveEnrichments: protectedProcedure
    .input(z.object({
      cveIds: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/i)).max(100, "Maximum 100 CVEs per batch"),
    }))
    .query(async ({ input }) => {
      const map = await getBatchCachedEnrichments(input.cveIds);
      const results = input.cveIds.map(id => {
        const cached = map.get(id.toUpperCase());
        return cached || { cveId: id.toUpperCase(), description: null, cwes: [], cvssV3Score: null, cvssV3Vector: null, publishedDate: null, lastModifiedDate: null, references: [], enrichedAt: 0, error: "Not yet enriched" };
      });
      return {
        results,
        summary: {
          total: results.length,
          enriched: results.filter(r => r.description).length,
          pending: results.filter(r => !r.description && !r.error).length,
          errors: results.filter(r => r.error).length,
        },
      };
    }),

  /**
   * Run the CVE enrichment batch job (admin-only).
   * Extracts all CVE IDs from engagements and pre-populates the cve_enrichment table.
   */
  runCveEnrichmentBatch: protectedProcedure
    .input(z.object({
      forceRefresh: z.boolean().optional(),
      maxCves: z.number().int().positive().max(500).optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const result = await runEnrichmentBatch({
        forceRefresh: input?.forceRefresh,
        maxCves: input?.maxCves,
      });
      return result;
    }),

  /**
   * Get enrichment statistics.
   */
  cveEnrichmentStats: protectedProcedure
    .query(async () => {
      const stats = await getEnrichmentStats();
      const allCveIds = await extractAllCveIds();
      return {
        ...stats,
        totalCvesInEngagements: allCveIds.length,
        coveragePercent: allCveIds.length > 0
          ? Math.round((stats.totalEnriched / allCveIds.length) * 100)
          : 0,
      };
    }),
};

// ─── NIST 800-53 Compliance Report ─────────────────────────────────────────

const nistReportProcedures = {
  /**
   * Generate a NIST 800-53 compliance report from a set of findings.
   * Returns structured data suitable for PDF rendering on the client.
   */
  generateNistReport: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        id: z.string(),
        title: z.string(),
        severity: z.string(),
        cwes: z.array(z.string()).optional(),
        cves: z.array(z.string()).optional(),
        techniqueIds: z.array(z.string()).optional(),
        target: z.string().optional(),
        source: z.string().optional(),
      })),
      baseline: z.enum(["low", "moderate", "high"]).default("moderate"),
      organizationName: z.string().optional(),
      engagementName: z.string().optional(),
      assessmentDate: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { findings, baseline, organizationName, engagementName, assessmentDate } = input;

      // Enrich each finding
      const enrichedFindings = findings.map(f => {
        const enrichment = enrichFinding({
          cwes: f.cwes,
          techniqueIds: f.techniqueIds,
          severity: f.severity,
          title: f.title,
        });
        return {
          ...f,
          enrichment,
        };
      });

      // Generate NIST gap summary
      const gapSummary = generateNistGapSummary(
        findings.map(f => ({
          cwes: f.cwes,
          techniqueIds: f.techniqueIds,
          severity: f.severity,
          title: f.title,
        })),
        baseline
      );

      // Collect all impacted controls
      const allControls = new Map<string, { control: NistControl; findings: string[]; highestSeverity: string }>();
      for (const ef of enrichedFindings) {
        for (const ctrl of ef.enrichment.nistControls) {
          const existing = allControls.get(ctrl.controlId);
          if (existing) {
            existing.findings.push(ef.id);
            if (severityOrder(ef.severity) > severityOrder(existing.highestSeverity)) {
              existing.highestSeverity = ef.severity;
            }
          } else {
            allControls.set(ctrl.controlId, {
              control: ctrl,
              findings: [ef.id],
              highestSeverity: ef.severity,
            });
          }
        }
      }

      // Group by family
      const familyMap = new Map<string, {
        familyCode: string;
        familyName: string;
        controls: Array<{
          controlId: string;
          controlTitle: string;
          baseline: string;
          findingCount: number;
          highestSeverity: string;
          findingIds: string[];
        }>;
      }>();

      for (const [, { control, findings: fIds, highestSeverity }] of allControls) {
        if (!familyMap.has(control.familyCode)) {
          familyMap.set(control.familyCode, {
            familyCode: control.familyCode,
            familyName: control.family,
            controls: [],
          });
        }
        familyMap.get(control.familyCode)!.controls.push({
          controlId: control.controlId,
          controlTitle: control.controlTitle,
          baseline: control.baseline,
          findingCount: fIds.length,
          highestSeverity,
          findingIds: fIds,
        });
      }

      // Sort families by severity
      const families = Array.from(familyMap.values())
        .map(f => ({
          ...f,
          controls: f.controls.sort((a, b) => severityOrder(b.highestSeverity) - severityOrder(a.highestSeverity)),
        }))
        .sort((a, b) => {
          const aMax = Math.max(...a.controls.map(c => severityOrder(c.highestSeverity)));
          const bMax = Math.max(...b.controls.map(c => severityOrder(c.highestSeverity)));
          return bMax - aMax;
        });

      // Severity distribution
      const severityDist = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
      for (const f of findings) {
        const key = f.severity.toLowerCase() as keyof typeof severityDist;
        if (key in severityDist) severityDist[key]++;
      }

      // Total NIST 800-53 controls at each baseline
      const baselineControlCounts = { low: 125, moderate: 325, high: 421 };
      const totalBaselineControls = baselineControlCounts[baseline];
      const coveragePercent = Math.round((allControls.size / totalBaselineControls) * 1000) / 10;

      return {
        metadata: {
          reportTitle: "NIST 800-53 Rev 5 Compliance Assessment Report",
          organizationName: organizationName || "Organization",
          engagementName: engagementName || "Security Assessment",
          assessmentDate: assessmentDate || new Date().toISOString().split("T")[0],
          baseline,
          generatedAt: new Date().toISOString(),
          generatedBy: "AceofCloud Caldera Dashboard",
        },
        executiveSummary: {
          totalFindings: findings.length,
          severityDistribution: severityDist,
          totalNistControlsImpacted: allControls.size,
          totalBaselineControls,
          coveragePercent,
          criticalControlGaps: gapSummary.criticalGaps.map(c => ({
            controlId: c.controlId,
            controlTitle: c.controlTitle,
            family: c.family,
          })),
          nistFamiliesImpacted: families.length,
          totalNistFamilies: Object.keys(NIST_CONTROL_FAMILIES).length,
        },
        controlFamilies: families,
        findingDetails: enrichedFindings.map(ef => ({
          id: ef.id,
          title: ef.title,
          severity: ef.severity,
          target: ef.target,
          source: ef.source,
          cwes: ef.enrichment.cwes.map(c => ({ id: c.cweId, name: c.cweName })),
          nistControls: ef.enrichment.nistControls.map(c => ({
            id: c.controlId,
            title: c.controlTitle,
            family: c.family,
            baseline: c.baseline,
          })),
          mitreTechniques: ef.enrichment.mitreTechniques.map(t => ({
            id: t.techniqueId,
            name: t.techniqueName,
            tactic: t.tactic,
          })),
          nistPriority: ef.enrichment.nistPriority,
        })),
        gapAnalysis: {
          ...gapSummary,
          recommendation: generateRecommendation(gapSummary, baseline),
        },
      };
    }),
};

// ─── MITRE ATT&CK Navigator Layer Export ────────────────────────────────────

const mitreNavigatorProcedures = {
  /**
   * Generate a MITRE ATT&CK Navigator layer JSON from findings.
   * Compatible with ATT&CK Navigator v4.x (layer version 4.5).
   */
  generateAttackNavigatorLayer: protectedProcedure
    .input(z.object({
      findings: z.array(z.object({
        id: z.string(),
        title: z.string(),
        severity: z.string(),
        cwes: z.array(z.string()).optional(),
        techniqueIds: z.array(z.string()).optional(),
      })),
      layerName: z.string().optional(),
      layerDescription: z.string().optional(),
      engagementName: z.string().optional(),
      /** Color scheme: "severity" colors by highest severity, "frequency" by finding count */
      colorScheme: z.enum(["severity", "frequency"]).default("severity"),
    }))
    .mutation(({ input }) => {
      const { findings, layerName, layerDescription, engagementName, colorScheme } = input;

      // Collect all techniques with their associated findings
      const techniqueMap = new Map<string, {
        technique: MitreTechnique;
        findings: Array<{ id: string; title: string; severity: string }>;
      }>();

      for (const f of findings) {
        const enrichment = enrichFinding({
          cwes: f.cwes,
          techniqueIds: f.techniqueIds,
          severity: f.severity,
          title: f.title,
        });

        for (const tech of enrichment.mitreTechniques) {
          const existing = techniqueMap.get(tech.techniqueId);
          if (existing) {
            existing.findings.push({ id: f.id, title: f.title, severity: f.severity });
          } else {
            techniqueMap.set(tech.techniqueId, {
              technique: tech,
              findings: [{ id: f.id, title: f.title, severity: f.severity }],
            });
          }
        }
      }

      // Build Navigator layer techniques
      const techniques = Array.from(techniqueMap.entries()).map(([techId, data]) => {
        const highestSeverity = data.findings.reduce((max, f) =>
          severityOrder(f.severity) > severityOrder(max) ? f.severity : max, "informational");

        const score = colorScheme === "severity"
          ? severityToScore(highestSeverity)
          : Math.min(data.findings.length, 100);

        const color = colorScheme === "severity"
          ? severityToColor(highestSeverity)
          : frequencyToColor(data.findings.length);

        // Handle sub-techniques (e.g., T1059.001)
        const parts = techId.split(".");
        const tactic = data.technique.tactic.toLowerCase().replace(/\s+/g, "-");

        const entry: any = {
          techniqueID: parts[0],
          score,
          color,
          comment: `${data.findings.length} finding(s): ${data.findings.map(f => `${f.title} [${f.severity}]`).join("; ")}`,
          enabled: true,
          metadata: [],
          links: [],
          showSubtechniques: parts.length > 1,
        };

        if (parts.length > 1) {
          // ATT&CK Navigator expects tactic in the technique entry for sub-techniques
          entry.techniqueID = techId;
        }

        // Add tactic if available
        if (tactic && tactic !== "unknown") {
          entry.tactic = tactic;
        }

        return entry;
      });

      // Build the full Navigator layer
      const layer = {
        name: layerName || `${engagementName || "Assessment"} — ATT&CK Coverage`,
        versions: {
          attack: "16",
          navigator: "5.1.0",
          layer: "4.5",
        },
        domain: "enterprise-attack",
        description: layerDescription || `MITRE ATT&CK technique coverage from ${findings.length} security findings. Generated by AceofCloud Caldera Dashboard on ${new Date().toISOString().split("T")[0]}.`,
        filters: {
          platforms: [
            "Linux", "macOS", "Windows", "Network",
            "PRE", "Containers", "Office 365", "SaaS",
            "Google Workspace", "IaaS", "Azure AD",
          ],
        },
        sorting: 3, // Sort by score descending
        layout: {
          layout: "side",
          aggregateFunction: "average",
          showID: true,
          showName: true,
          showAggregateScores: true,
          countUnscored: false,
          expandedSubtechniques: "annotated",
        },
        hideDisabled: false,
        techniques,
        gradient: colorScheme === "severity"
          ? {
              colors: ["#a1d99b", "#fee08b", "#fdae61", "#f46d43", "#d73027"],
              minValue: 0,
              maxValue: 100,
            }
          : {
              colors: ["#c6dbef", "#6baed6", "#2171b5", "#08306b"],
              minValue: 0,
              maxValue: 10,
            },
        legendItems: colorScheme === "severity"
          ? [
              { label: "Critical", color: "#d73027" },
              { label: "High", color: "#f46d43" },
              { label: "Medium", color: "#fdae61" },
              { label: "Low", color: "#fee08b" },
              { label: "Informational", color: "#a1d99b" },
            ]
          : [
              { label: "1 finding", color: "#c6dbef" },
              { label: "2-3 findings", color: "#6baed6" },
              { label: "4-6 findings", color: "#2171b5" },
              { label: "7+ findings", color: "#08306b" },
            ],
        showTacticRowBackground: true,
        tacticRowBackground: "#dddddd",
        selectTechniquesAcrossTactics: true,
        selectSubtechniquesWithParent: false,
        selectVisibleTechniques: false,
        metadata: [
          { name: "generated_by", value: "AceofCloud Caldera Dashboard" },
          { name: "generated_at", value: new Date().toISOString() },
          { name: "total_findings", value: String(findings.length) },
          { name: "total_techniques", value: String(techniques.length) },
          { name: "engagement", value: engagementName || "N/A" },
        ],
      };

      // Summary stats
      const tacticCoverage: Record<string, number> = {};
      for (const [, data] of techniqueMap) {
        const tactic = data.technique.tactic;
        tacticCoverage[tactic] = (tacticCoverage[tactic] || 0) + 1;
      }

      return {
        layer,
        summary: {
          totalTechniques: techniqueMap.size,
          totalFindings: findings.length,
          tacticCoverage: Object.entries(tacticCoverage)
            .map(([tactic, count]) => ({ tactic, techniqueCount: count }))
            .sort((a, b) => b.techniqueCount - a.techniqueCount),
          severityBreakdown: {
            critical: Array.from(techniqueMap.values()).filter(d =>
              d.findings.some(f => f.severity.toLowerCase() === "critical")).length,
            high: Array.from(techniqueMap.values()).filter(d =>
              d.findings.some(f => f.severity.toLowerCase() === "high")).length,
            medium: Array.from(techniqueMap.values()).filter(d =>
              d.findings.some(f => f.severity.toLowerCase() === "medium")).length,
            low: Array.from(techniqueMap.values()).filter(d =>
              d.findings.some(f => f.severity.toLowerCase() === "low")).length,
          },
        },
      };
    }),
};

// ─── Helper Functions ───────────────────────────────────────────────────────

function cvssToSeverity(score?: number): string {
  if (!score) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "informational";
}

function severityOrder(severity: string): number {
  const order: Record<string, number> = {
    critical: 4, high: 3, medium: 2, moderate: 2, low: 1, informational: 0, info: 0,
  };
  return order[severity.toLowerCase()] ?? 0;
}

function severityToScore(severity: string): number {
  const scores: Record<string, number> = {
    critical: 100, high: 75, medium: 50, low: 25, informational: 10,
  };
  return scores[severity.toLowerCase()] ?? 10;
}

function severityToColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: "#d73027",
    high: "#f46d43",
    medium: "#fdae61",
    low: "#fee08b",
    informational: "#a1d99b",
  };
  return colors[severity.toLowerCase()] ?? "#a1d99b";
}

function frequencyToColor(count: number): string {
  if (count >= 7) return "#08306b";
  if (count >= 4) return "#2171b5";
  if (count >= 2) return "#6baed6";
  return "#c6dbef";
}

function generateRecommendation(
  gapSummary: { totalControlsImpacted: number; criticalGaps: NistControl[]; coverageScore: number },
  baseline: string
): string {
  const parts: string[] = [];

  if (gapSummary.criticalGaps.length > 0) {
    const families = [...new Set(gapSummary.criticalGaps.map(c => c.family))];
    parts.push(
      `Immediate attention required: ${gapSummary.criticalGaps.length} NIST 800-53 controls have critical or high-severity findings. ` +
      `Priority remediation should focus on the ${families.slice(0, 3).join(", ")} control families.`
    );
  }

  if (gapSummary.coverageScore < 30) {
    parts.push(
      `Assessment coverage is limited (${gapSummary.coverageScore}% of ${baseline} baseline controls tested). ` +
      `Consider expanding the scope to include additional control families for a more comprehensive assessment.`
    );
  } else if (gapSummary.coverageScore < 60) {
    parts.push(
      `Assessment covers ${gapSummary.coverageScore}% of ${baseline} baseline controls. ` +
      `Additional testing in underrepresented families would strengthen the compliance posture.`
    );
  } else {
    parts.push(
      `Good coverage at ${gapSummary.coverageScore}% of ${baseline} baseline controls. ` +
      `Focus remediation efforts on the identified gaps to improve overall compliance posture.`
    );
  }

  return parts.join(" ");
}

// ─── Export Router ──────────────────────────────────────────────────────────

export const complianceExportsRouter = router({
  // NVD CVE Lookup
  ...nvdLookupProcedures,
  // NIST 800-53 Report
  ...nistReportProcedures,
  // MITRE ATT&CK Navigator
  ...mitreNavigatorProcedures,
});
