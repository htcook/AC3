/**
 * ScanForge Post-Engagement Reassessment Agent
 * 
 * After an engagement completes, this LLM-powered agent:
 * 1. Compares ScanForge findings vs Nuclei/ZAP/SQLMap results
 * 2. Identifies what ScanForge missed (false negatives) and why
 * 3. Identifies false positives and recommends template adjustments
 * 4. Generates specific template improvement recommendations
 * 5. Identifies coverage gaps that need new templates
 * 6. Feeds results into the accuracy tracker for metric updates
 * 
 * This is the core self-improvement loop — every engagement makes ScanForge smarter.
 */

import { invokeLLM } from "../../_core/llm";
import {
  assessFindings,
  updateTemplateMetrics,
  generateEngagementReport,
  getEngagementFindings,
  type CrossToolMatch,
} from "./accuracy-tracker";
import { getDb } from "../../db";
import { eq, sql } from "drizzle-orm";
import {
  scanforgeEngagementReport,
  scanforgeGeneratedTemplates,
  scanforgeFindingLog,
} from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface LegacyToolFinding {
  tool: "nuclei" | "zap" | "sqlmap" | "xsstrike" | "hydra" | "manual";
  title: string;
  target: string;
  severity: string;
  cve?: string;
  evidence?: string;
  rawData?: Record<string, any>;
}

export interface TemplateImprovement {
  templateId: string;
  improvementType: "adjust_matchers" | "add_payloads" | "reduce_false_positives" | "expand_coverage" | "deprecate";
  description: string;
  suggestedChanges: Record<string, any>;
  priority: "high" | "medium" | "low";
}

export interface CoverageGap {
  vulnCategory: string;
  description: string;
  affectedTargetTypes: string[];
  suggestedTemplateSpec: Record<string, any>;
  priority: "critical" | "high" | "medium" | "low";
}

export interface ReassessmentResult {
  engagementId: string;
  summary: string;
  verdicts: { tp: number; fp: number; fn: number; assessed: number };
  templateImprovements: TemplateImprovement[];
  coverageGaps: CoverageGap[];
  scanforgeScore: { precision: number; recall: number; f1: number };
  legacyScore: { precision: number; recall: number; f1: number };
  recommendation: "scanforge_superior" | "parity" | "legacy_superior" | "insufficient_data";
}

// ─── Main Reassessment Pipeline ─────────────────────────────────────────────

/**
 * Run the full post-engagement reassessment pipeline.
 * This is the main entry point — call after all scans complete.
 */
export async function runReassessment(
  engagementId: string,
  legacyFindings: LegacyToolFinding[],
  engagementContext: {
    targetType: string; // web_app, network, api, cloud
    targetUrls: string[];
    scope: string;
  }
): Promise<ReassessmentResult> {
  console.log(`[ScanForge Reassessment] Starting for engagement ${engagementId}`);

  // Step 1: Auto-assess findings using cross-tool comparison
  const verdicts = await assessFindings(engagementId, legacyFindings, "auto-crossref");
  console.log(`[ScanForge Reassessment] Auto-assessed: ${verdicts.assessed} findings (TP=${verdicts.tp}, FP=${verdicts.fp}, FN=${verdicts.fn})`);

  // Step 2: Get all findings for LLM analysis
  const allFindings = await getEngagementFindings(engagementId);

  // Step 3: LLM deep analysis — identify template improvements and coverage gaps
  const llmAnalysis = await runLLMAnalysis(engagementId, allFindings, legacyFindings, engagementContext);

  // Step 4: Update template metrics based on verdicts
  await updateTemplateMetrics(engagementId);

  // Step 5: Generate engagement comparison report
  const nucleiCount = legacyFindings.filter(f => f.tool === "nuclei").length;
  const zapCount = legacyFindings.filter(f => f.tool === "zap").length;
  const report = await generateEngagementReport(engagementId, { nuclei: nucleiCount, zap: zapCount });

  // Step 6: Store template improvements and coverage gaps
  await storeReassessmentResults(engagementId, llmAnalysis);

  // Step 7: Determine overall recommendation
  const recommendation = determineRecommendation(report);

  const result: ReassessmentResult = {
    engagementId,
    summary: llmAnalysis.summary,
    verdicts,
    templateImprovements: llmAnalysis.templateImprovements,
    coverageGaps: llmAnalysis.coverageGaps,
    scanforgeScore: {
      precision: report.scanforgePrecision,
      recall: report.scanforgeRecall,
      f1: report.scanforgeF1,
    },
    legacyScore: {
      precision: 0, // Will be computed once we have enough data
      recall: 0,
      f1: 0,
    },
    recommendation,
  };

  console.log(`[ScanForge Reassessment] Complete: ${recommendation} | F1=${report.scanforgeF1.toFixed(3)}`);
  return result;
}

// ─── LLM Analysis ───────────────────────────────────────────────────────────

async function runLLMAnalysis(
  engagementId: string,
  scanforgeFindings: any[],
  legacyFindings: LegacyToolFinding[],
  context: { targetType: string; targetUrls: string[]; scope: string }
): Promise<{
  summary: string;
  templateImprovements: TemplateImprovement[];
  coverageGaps: CoverageGap[];
}> {
  const tpFindings = scanforgeFindings.filter(f => f.verdict === "TP");
  const fpFindings = scanforgeFindings.filter(f => f.verdict === "FP");
  const fnFindings = scanforgeFindings.filter(f => f.verdict === "FN");

  const prompt = `You are the ScanForge Reassessment Agent — an expert vulnerability scanner quality analyst.

Analyze the following engagement scan results and provide specific, actionable recommendations to improve ScanForge's detection accuracy.

## Engagement Context
- ID: ${engagementId}
- Target Type: ${context.targetType}
- Targets: ${context.targetUrls.slice(0, 10).join(", ")}
- Scope: ${context.scope}

## ScanForge Results Summary
- True Positives (confirmed): ${tpFindings.length}
- False Positives (ScanForge wrong): ${fpFindings.length}
- False Negatives (ScanForge missed): ${fnFindings.length}

## False Positives (ScanForge reported but not confirmed):
${fpFindings.slice(0, 20).map(f => `- Template: ${f.templateId} | Finding: ${f.findingTitle} | Target: ${f.target} | Confidence: ${f.confidence}`).join("\n") || "None"}

## False Negatives (found by legacy tools, missed by ScanForge):
${fnFindings.slice(0, 20).map(f => `- Finding: ${f.findingTitle} | Target: ${f.target} | Cross-tool: ${JSON.stringify(f.crossToolMatches)}`).join("\n") || "None"}

## Legacy Tool Findings (Nuclei + ZAP + SQLMap):
${legacyFindings.slice(0, 30).map(f => `- [${f.tool}] ${f.title} | ${f.target} | ${f.severity}${f.cve ? ` | ${f.cve}` : ""}`).join("\n") || "None"}

Provide your analysis as JSON with this exact schema:
{
  "summary": "2-3 sentence executive summary of ScanForge's performance",
  "templateImprovements": [
    {
      "templateId": "the template ID that needs improvement",
      "improvementType": "adjust_matchers|add_payloads|reduce_false_positives|expand_coverage|deprecate",
      "description": "specific description of what to change",
      "suggestedChanges": { "field": "value" },
      "priority": "high|medium|low"
    }
  ],
  "coverageGaps": [
    {
      "vulnCategory": "e.g., SQL Injection, SSRF, Auth Bypass",
      "description": "what ScanForge is missing and why",
      "affectedTargetTypes": ["web_app", "api"],
      "suggestedTemplateSpec": {
        "name": "suggested template name",
        "detectionMethod": "how to detect this",
        "payloads": ["example payloads"],
        "matchers": ["what to look for in response"]
      },
      "priority": "critical|high|medium|low"
    }
  ]
}`;

  try {
    const response = await invokeLLM({
      _caller: "reassessment-agent.analyzeResults",
      messages: [
        { role: "system", content: "You are a vulnerability scanner quality analyst. Always respond with valid JSON matching the requested schema. Be specific and actionable in your recommendations." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "reassessment_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              summary: { type: "string" },
              templateImprovements: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    templateId: { type: "string" },
                    improvementType: { type: "string" },
                    description: { type: "string" },
                    suggestedChanges: { type: "object", additionalProperties: true },
                    priority: { type: "string" },
                  },
                  required: ["templateId", "improvementType", "description", "suggestedChanges", "priority"],
                  additionalProperties: false,
                },
              },
              coverageGaps: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    vulnCategory: { type: "string" },
                    description: { type: "string" },
                    affectedTargetTypes: { type: "array", items: { type: "string" } },
                    suggestedTemplateSpec: { type: "object", additionalProperties: true },
                    priority: { type: "string" },
                  },
                  required: ["vulnCategory", "description", "affectedTargetTypes", "suggestedTemplateSpec", "priority"],
                  additionalProperties: false,
                },
              },
            },
            required: ["summary", "templateImprovements", "coverageGaps"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    return JSON.parse(content);
  } catch (err) {
    console.error("[ScanForge Reassessment] LLM analysis failed:", err);
    return {
      summary: "LLM analysis failed — falling back to automated cross-reference only.",
      templateImprovements: [],
      coverageGaps: [],
    };
  }
}

// ─── Result Storage ─────────────────────────────────────────────────────────

async function storeReassessmentResults(
  engagementId: string,
  analysis: { summary: string; templateImprovements: TemplateImprovement[]; coverageGaps: CoverageGap[] }
): Promise<void> {
  // Update the engagement report with LLM analysis
  const db = await getDb();
  if (!db) throw new Error('Database not available');
  await db.update(scanforgeEngagementReport)
    .set({
      reassessmentSummary: analysis.summary,
      templateImprovements: analysis.templateImprovements,
      coverageGaps: analysis.coverageGaps,
    })
    .where(eq(scanforgeEngagementReport.engagementId, engagementId));

  // Auto-generate draft templates for critical/high coverage gaps
  for (const gap of analysis.coverageGaps.filter(g => g.priority === "critical" || g.priority === "high")) {
    const templateId = `auto-${gap.vulnCategory.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`;
    const dbIns = await getDb();
    if (!dbIns) throw new Error('Database not available');
    await dbIns.insert(scanforgeGeneratedTemplates).values({
      templateId,
      name: gap.suggestedTemplateSpec?.name || `Auto: ${gap.vulnCategory}`,
      generationSource: "missed_finding",
      sourceReference: `engagement:${engagementId}`,
      templateData: gap.suggestedTemplateSpec || {},
      status: "draft",
      generationConfidence: gap.priority === "critical" ? 0.8 : 0.6,
    });
  }
}

// ─── Recommendation Logic ───────────────────────────────────────────────────

function determineRecommendation(
  report: { scanforgeF1: number; scanforgeOnly: number; legacyOnly: number; scanforgeFindings: number }
): "scanforge_superior" | "parity" | "legacy_superior" | "insufficient_data" {
  const totalFindings = report.scanforgeFindings + report.legacyOnly;
  
  if (totalFindings < 3) return "insufficient_data";
  
  if (report.scanforgeF1 >= 0.8 && report.legacyOnly <= 1) return "scanforge_superior";
  if (report.scanforgeF1 >= 0.6 && report.scanforgeOnly >= report.legacyOnly) return "parity";
  return "legacy_superior";
}

// ─── Scheduled Reassessment ─────────────────────────────────────────────────

/**
 * Run reassessment for all engagements that completed but haven't been assessed yet.
 * Call this from a scheduled job or after engagement completion.
 */
export async function runPendingReassessments(): Promise<number> {
  const db2 = await getDb();
  if (!db2) return 0;
  const pendingEngagements = await db2.select({ engagementId: scanforgeFindingLog.engagementId })
    .from(scanforgeFindingLog)
    .where(eq(scanforgeFindingLog.verdict, "PENDING"))
    .groupBy(scanforgeFindingLog.engagementId);

  console.log(`[ScanForge Reassessment] Found ${pendingEngagements.length} engagements with pending assessments`);
  
  // Note: actual reassessment requires legacy findings which must be loaded from the engagement
  // This is a placeholder for the scheduled job — the full pipeline runs via runReassessment()
  return pendingEngagements.length;
}
