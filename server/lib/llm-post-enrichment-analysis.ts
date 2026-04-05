/**
 * LLM-Powered Post-Enrichment Analysis
 *
 * Runs as Stage 3.99 in the domain intel pipeline — AFTER all enrichment
 * stages (KEV, vuln feeds, Shodan, exploit matching, port risk, email
 * security, and cross-module enrichment) but BEFORE campaign generation.
 *
 * The LLM receives the complete enriched dataset and produces:
 * 1. Attack path analysis — how an attacker would chain findings
 * 2. Blind spot identification — what the scan might have missed
 * 3. Priority recommendations — which findings to address first
 * 4. Cross-finding correlations — how findings relate to each other
 * 5. Threat actor mapping — which threat groups would target this surface
 */

import type { AssetAnalysis, OrgProfile } from "../domainIntel";
import type { CrossModuleEnrichmentResult } from "./cross-module-enrichment";
import { createAssetOwnershipFilter } from "../../shared/managed-provider-filter";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PostEnrichmentAnalysis {
  attackPaths: AttackPath[];
  blindSpots: BlindSpot[];
  prioritizedRecommendations: PrioritizedRecommendation[];
  crossFindingCorrelations: CrossFindingCorrelation[];
  threatActorMapping: ThreatActorMapping[];
  overallAssessment: string;
  confidenceStatement: string;
}

export interface AttackPath {
  id: string;
  name: string;
  description: string;
  steps: Array<{
    order: number;
    technique: string;
    mitreTactic: string;
    targetAsset: string;
    finding: string;
    difficulty: "trivial" | "easy" | "moderate" | "hard" | "expert";
  }>;
  likelihood: number; // 0-10
  impact: number; // 0-10
  overallRisk: number; // 0-100
}

export interface BlindSpot {
  area: string;
  description: string;
  suggestedAction: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface PrioritizedRecommendation {
  rank: number;
  title: string;
  description: string;
  affectedAssets: string[];
  effort: "quick_win" | "short_term" | "medium_term" | "long_term";
  impact: "critical" | "high" | "medium" | "low";
  category: string;
}

export interface CrossFindingCorrelation {
  findingIds: string[];
  relationship: string;
  combinedRisk: string;
  exploitChainPotential: boolean;
}

export interface ThreatActorMapping {
  actorName: string;
  relevance: "high" | "medium" | "low";
  matchingTechniques: string[];
  rationale: string;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export async function runPostEnrichmentAnalysis(
  analyses: AssetAnalysis[],
  org: OrgProfile,
  crossModuleData?: CrossModuleEnrichmentResult,
): Promise<PostEnrichmentAnalysis> {
  try {
    const { invokeLLM } = await import("../_core/llm");
    // LLM timeout wrapper (Tier 1 Optimization #3.1)
    const LLM_TIMEOUT_MS = 60_000;
    const invokeLLMWithTimeout = (params: any, timeoutMs = LLM_TIMEOUT_MS) => {
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`LLM timeout after ${timeoutMs}ms`)), timeoutMs)
      );
      return Promise.race([invokeLLM({ _caller: "llm-post-enrichment", ...params }), timeoutPromise]);
    };
    // Wire knowledge modules for enriched post-enrichment analysis
    const { getThreatGroupVulnContext, getSectorThreatContext } = await import("./threat-group-knowledge");
    const { buildAuthKnowledgeContext } = await import("./auth-testing-knowledge");
    const { buildKnowledgeContextForLLM } = await import("./pentest-knowledge-base");
    const { getOwaspVulnCorrelationContext } = await import("./owasp-knowledge");
    const threatCtx = getThreatGroupVulnContext();
    const sectorCtx = org.sector ? getSectorThreatContext(org.sector) : '';
    const authCtx = buildAuthKnowledgeContext();
    const pentestCtx = buildKnowledgeContextForLLM('analyst', 1500);
    const owaspCtx = getOwaspVulnCorrelationContext();

    // ── Filter out managed provider and third-party assets ──
    // Detect managed provider from email findings
    const allEmailFindings = analyses.flatMap(a => a.postureFindings.filter(f => f.category?.startsWith('Email Security')));
    const managedProviderFinding = allEmailFindings.find(f => f.id?.includes('managed-provider'));
    const mpName = managedProviderFinding
      ? (managedProviderFinding.title?.match(/Managed by (.+?)(?:\s*[\-\u2014]|$)/)?.[1] || null)
      : null;
    const ownershipFilter = createAssetOwnershipFilter({
      managedProviderName: mpName,
      primaryDomain: org.primaryDomain,
    });
    const clientAnalyses = analyses.filter(a =>
      ownershipFilter.isClientOwned({ hostname: a.asset.hostname, tags: a.asset.tags })
    );
    const excludedCount = analyses.length - clientAnalyses.length;

    // Build a concise summary of all enriched data for the LLM (client-owned only)
    const confirmedFindings = clientAnalyses.flatMap(a =>
      a.postureFindings.filter(f => f.corroborationTier === "confirmed")
    );
    const probableFindings = clientAnalyses.flatMap(a =>
      a.postureFindings.filter(f => f.corroborationTier === "probable")
    );
    const criticalAssets = clientAnalyses
      .filter(a => a.assetCriticalityBand === "critical" || a.assetCriticalityBand === "high")
      .slice(0, 10);
    const highRiskAssets = clientAnalyses
      .filter(a => a.riskBand === "critical" || a.riskBand === "high")
      .slice(0, 10);

    const prompt = `You are a senior red team operator conducting a post-enrichment analysis of a comprehensive domain intelligence scan. All data has been verified through multiple sources (Shodan, Censys, SecurityTrails, CISA KEV, NVD, ExploitDB, Metasploit).

## Target Organization
- Name: ${org.customerName}
- Primary Domain: ${org.primaryDomain}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${org.criticalFunctions?.join(", ") || "Not specified"}
- Compliance: ${org.complianceFlags?.join(", ") || "None specified"}

## Scan Summary
- Total Assets Analyzed: ${clientAnalyses.length} client-owned${excludedCount > 0 ? ` (${excludedCount} managed provider/third-party assets excluded)` : ''}
- Confirmed Findings (client-owned only): ${confirmedFindings.length}
- Probable Findings (client-owned only): ${probableFindings.length}
- Critical/High Risk Assets: ${highRiskAssets.length}
${excludedCount > 0 ? `\nNOTE: ${excludedCount} managed provider/third-party asset(s) have been excluded from this analysis. Their CVEs (e.g., Exchange, SharePoint on provider infrastructure) are NOT the client's responsibility. Do NOT reference them as client risks.` : ''}

## Critical Assets (Top 10)
${criticalAssets.map(a => `- ${a.asset.hostname} [${a.assetCriticalityBand}] — Mission: ${a.missionFunction}, Service: ${a.essentialService}, Risk: ${a.hybridRiskScore}/100 (${a.riskBand})`).join("\n")}

## Confirmed Findings (Top 15)
${confirmedFindings.slice(0, 15).map(f => `- [${f.severity}/10] ${f.title} on ${f.assetHostname} — ${f.evidenceDetail?.substring(0, 100) || ""}`).join("\n")}

## Technologies Detected
${Array.from(new Set(clientAnalyses.flatMap(a => a.asset.technologies || []))).slice(0, 30).join(", ")}

## Cross-Module Intelligence
${crossModuleData ? `
- Bug Bounty: ${crossModuleData.bugBounty.status === "success" ? `Program: ${crossModuleData.bugBounty.programName || "None"}, ${crossModuleData.bugBounty.correlations.length} correlations` : "N/A"}
- Threat Intel: ${crossModuleData.threatIntel.status === "success" ? `${crossModuleData.threatIntel.matchingThreatActors.length} matching actors, ${crossModuleData.threatIntel.riskAdjustments.length} risk adjustments` : "N/A"}
- OpSec: ${crossModuleData.opsec.status === "success" ? `${crossModuleData.opsec.defensiveGaps.length} defensive gaps` : "N/A"}
- Discovery Deep Dive: ${crossModuleData.discoveryDeepDive.status === "success" ? `${crossModuleData.discoveryDeepDive.infrastructureInsights.length} infrastructure insights, ${crossModuleData.discoveryDeepDive.certificateFindings.length} cert findings` : "N/A"}
` : "Cross-module enrichment not available"}

Analyze this data and provide:
1. Attack paths an adversary would likely use (chain findings together)
2. Blind spots the scan may have missed
3. Prioritized recommendations (ranked by impact/effort)
4. Cross-finding correlations (how findings amplify each other)
5. Threat actor mapping (which groups would target this surface)
6. Overall assessment and confidence statement

Return valid JSON matching the schema.

=== KNOWLEDGE BASE CONTEXT ===
${threatCtx.slice(0, 1000)}

${sectorCtx.slice(0, 800)}

${authCtx.slice(0, 600)}

${pentestCtx.slice(0, 1000)}

${owaspCtx.slice(0, 800)}`;

    const response = await invokeLLMWithTimeout({
      messages: [
        {
          role: "system",
          content: "You are a senior penetration tester and red team operator. Provide actionable, evidence-based security analysis. Be specific about asset names and finding IDs. Return valid JSON only.",
        },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "post_enrichment_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              attackPaths: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    id: { type: "string" },
                    name: { type: "string" },
                    description: { type: "string" },
                    steps: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          order: { type: "integer" },
                          technique: { type: "string" },
                          mitreTactic: { type: "string" },
                          targetAsset: { type: "string" },
                          finding: { type: "string" },
                          difficulty: { type: "string", enum: ["trivial", "easy", "moderate", "hard", "expert"] },
                        },
                        required: ["order", "technique", "mitreTactic", "targetAsset", "finding", "difficulty"],
                        additionalProperties: false,
                      },
                    },
                    likelihood: { type: "number" },
                    impact: { type: "number" },
                    overallRisk: { type: "number" },
                  },
                  required: ["id", "name", "description", "steps", "likelihood", "impact", "overallRisk"],
                  additionalProperties: false,
                },
              },
              blindSpots: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    area: { type: "string" },
                    description: { type: "string" },
                    suggestedAction: { type: "string" },
                    severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
                  },
                  required: ["area", "description", "suggestedAction", "severity"],
                  additionalProperties: false,
                },
              },
              prioritizedRecommendations: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    rank: { type: "integer" },
                    title: { type: "string" },
                    description: { type: "string" },
                    affectedAssets: { type: "array", items: { type: "string" } },
                    effort: { type: "string", enum: ["quick_win", "short_term", "medium_term", "long_term"] },
                    impact: { type: "string", enum: ["critical", "high", "medium", "low"] },
                    category: { type: "string" },
                  },
                  required: ["rank", "title", "description", "affectedAssets", "effort", "impact", "category"],
                  additionalProperties: false,
                },
              },
              crossFindingCorrelations: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    findingIds: { type: "array", items: { type: "string" } },
                    relationship: { type: "string" },
                    combinedRisk: { type: "string" },
                    exploitChainPotential: { type: "boolean" },
                  },
                  required: ["findingIds", "relationship", "combinedRisk", "exploitChainPotential"],
                  additionalProperties: false,
                },
              },
              threatActorMapping: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    actorName: { type: "string" },
                    relevance: { type: "string", enum: ["high", "medium", "low"] },
                    matchingTechniques: { type: "array", items: { type: "string" } },
                    rationale: { type: "string" },
                  },
                  required: ["actorName", "relevance", "matchingTechniques", "rationale"],
                  additionalProperties: false,
                },
              },
              overallAssessment: { type: "string" },
              confidenceStatement: { type: "string" },
            },
            required: [
              "attackPaths", "blindSpots", "prioritizedRecommendations",
              "crossFindingCorrelations", "threatActorMapping",
              "overallAssessment", "confidenceStatement",
            ],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices[0].message.content;
    const parsed = JSON.parse(typeof content === "string" ? content : "{}");

    console.log(
      `[PostEnrichmentAnalysis] LLM analysis complete: ${parsed.attackPaths?.length || 0} attack paths, ` +
      `${parsed.blindSpots?.length || 0} blind spots, ${parsed.prioritizedRecommendations?.length || 0} recommendations`
    );

    return parsed;
  } catch (err: any) {
    console.error(`[PostEnrichmentAnalysis] LLM analysis failed: ${err.message}`);
    return {
      attackPaths: [],
      blindSpots: [{
        area: "Analysis Unavailable",
        description: "LLM-powered post-enrichment analysis could not be completed.",
        suggestedAction: "Review findings manually and prioritize confirmed vulnerabilities.",
        severity: "low",
      }],
      prioritizedRecommendations: [{
        rank: 1,
        title: "Manual Review Required",
        description: "Automated analysis unavailable. Review confirmed and probable findings manually.",
        affectedAssets: [],
        effort: "short_term",
        impact: "high",
        category: "General",
      }],
      crossFindingCorrelations: [],
      threatActorMapping: [],
      overallAssessment: "Automated post-enrichment analysis unavailable. Manual review of scan findings recommended.",
      confidenceStatement: "Low confidence — automated analysis failed. Raw enrichment data is still available for manual review.",
    };
  }
}
