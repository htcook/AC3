/**
 * LLM-Powered Post-Enrichment Analysis
 *
 * Runs as Stage 3.99 in the domain intel pipeline — AFTER all enrichment
 * stages (KEV, vuln feeds, Shodan, exploit matching, port risk, email
 * security, and cross-module enrichment) but BEFORE campaign generation.
 *
 * DESIGN PRINCIPLE: Context-based risk analysis grounded in CONFIRMED evidence.
 * The LLM must cite specific findings, CVEs, or scan data for every claim.
 * Speculative or assumption-based risk statements are explicitly prohibited.
 *
 * The LLM receives the complete enriched dataset and produces:
 * 1. Attack path analysis — chains of CONFIRMED findings only
 * 2. Blind spot identification — gaps in scan coverage (not speculative threats)
 * 3. Priority recommendations — ranked by confirmed evidence severity
 * 4. Cross-finding correlations — how confirmed findings amplify each other
 * 5. Threat actor mapping — actors whose known TTPs match CONFIRMED findings
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

    // Compute preliminary overall risk score for tone calibration
    const clientRiskScores = clientAnalyses.map(a => a.hybridRiskScore);
    const prelimOverallRisk = clientRiskScores.length > 0
      ? Math.round(clientRiskScores.reduce((s, v) => s + v, 0) / clientRiskScores.length)
      : 0;
    const prelimRiskBand = prelimOverallRisk >= 90 ? 'critical' : prelimOverallRisk >= 70 ? 'high' : prelimOverallRisk >= 40 ? 'medium' : 'low';
    const maxAssetRisk = clientRiskScores.length > 0 ? Math.max(...clientRiskScores) : 0;
    const maxRiskBand = maxAssetRisk >= 90 ? 'critical' : maxAssetRisk >= 70 ? 'high' : maxAssetRisk >= 40 ? 'medium' : 'low';

    // Build comprehensive evidence inventory for the LLM (client-owned only)
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

    // Build detailed confirmed findings list (send ALL confirmed, not just top 15)
    const confirmedFindingsList = confirmedFindings
      .sort((a, b) => (b.severity || 0) - (a.severity || 0))
      .slice(0, 40)
      .map(f => {
        const parts = [`[Sev ${f.severity}/10]`, f.title];
        if (f.cveIds?.length) parts.push(`(${f.cveIds.join(', ')})`);
        parts.push(`on ${f.assetHostname}`);
        if (f.corroborationTier) parts.push(`[${f.corroborationTier}]`);
        if (f.evidenceDetail) parts.push(`— Evidence: ${f.evidenceDetail.substring(0, 150)}`);
        return `- ${parts.join(' ')}`;
      })
      .join("\n");

    // Build probable findings summary (abbreviated)
    const probableFindingsList = probableFindings
      .sort((a, b) => (b.severity || 0) - (a.severity || 0))
      .slice(0, 20)
      .map(f => `- [Sev ${f.severity}/10] ${f.title}${f.cveIds?.length ? ` (${f.cveIds.join(', ')})` : ''} on ${f.assetHostname} [probable]`)
      .join("\n");

    // Build exposed ports summary
    const exposedPorts = clientAnalyses
      .filter(a => (a as any).openPorts?.length > 0)
      .map(a => `- ${a.asset.hostname}: ports ${((a as any).openPorts || []).map((p: any) => typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'}` : p).join(', ')}`)
      .join("\n");

    const prompt = `You are a cybersecurity risk analyst conducting a CONTEXT-BASED risk and threat analysis. Your analysis must be STRICTLY GROUNDED in the confirmed scan evidence provided below. Do NOT speculate, assume, or infer risks that are not directly supported by the data.

## CRITICAL ANALYSIS RULES
1. **EVIDENCE-FIRST**: Every risk claim, attack path step, and recommendation MUST cite a specific confirmed finding, CVE, exposed port, or scan result from the data below. If you cannot cite evidence, do not include the claim.
2. **NO ASSUMPTIONS**: Do NOT assume vulnerabilities exist based on technology names alone. A technology being present does NOT mean it is vulnerable unless a specific CVE or misconfiguration was confirmed.
3. **CONFIRMED vs PROBABLE**: Clearly distinguish between confirmed findings (version-matched CVEs, verified misconfigurations) and probable findings (product-family matches without version confirmation). Weight confirmed findings heavily; treat probable findings as lower-confidence indicators.
4. **NO SPECULATIVE THREAT ACTORS**: Only map threat actors whose known TTPs directly match CONFIRMED findings in the scan data. Do not list threat actors based solely on the organization's sector or geography.
5. **ATTACK PATHS MUST BE EVIDENCE-BASED**: Each step in an attack path must reference a specific confirmed finding or exposed service. Do not create hypothetical attack paths based on what "could" exist.
6. **BLIND SPOTS = SCAN COVERAGE GAPS**: Blind spots should identify what the scan did NOT cover (e.g., internal network, cloud IAM, mobile apps) — NOT speculative threats.
7. **MANAGED PROVIDER EXCLUSION**: ${excludedCount > 0 ? `${excludedCount} managed provider/third-party assets were excluded. Their CVEs are the provider's responsibility, NOT the client's. Do NOT reference them.` : 'No managed provider assets detected.'}

## Target Organization
- Name: ${org.customerName}
- Primary Domain: ${org.primaryDomain}
- Sector: ${org.sector}
- Client Type: ${org.clientType}
- Critical Functions: ${org.criticalFunctions?.join(", ") || "Not specified"}
- Compliance: ${org.complianceFlags?.join(", ") || "None specified"}

## Evidence Inventory
- Total Client-Owned Assets: ${clientAnalyses.length}
- Confirmed Findings: ${confirmedFindings.length}
- Probable Findings: ${probableFindings.length}
- Critical/High Criticality Assets: ${criticalAssets.length}
- High Risk Assets: ${highRiskAssets.length}

## Overall Risk Score Context
- Overall Risk Score: ${prelimOverallRisk}/100 (${prelimRiskBand.toUpperCase()})
- Peak Asset Risk: ${maxAssetRisk}/100 (${maxRiskBand.toUpperCase()})
- Risk Band Thresholds: LOW (0-39), MEDIUM (40-69), HIGH (70-89), CRITICAL (90-100)

TONE CALIBRATION: Your overallAssessment and all severity language MUST align with the ${prelimRiskBand.toUpperCase()} overall risk rating. If overall risk is LOW, use measured language and frame findings as improvement areas, not emergencies. Do NOT use "critical", "severe", or "urgent" language when the overall risk is LOW. If peak asset risk is higher than overall, you may note specific elevated-risk assets without overriding the overall tone.

## Critical Assets
${criticalAssets.map(a => `- ${a.asset.hostname} [criticality: ${a.assetCriticalityBand}] — Mission: ${a.missionFunction}, Service: ${a.essentialService}, Risk: ${a.hybridRiskScore}/100 (${a.riskBand}), Vuln Risk: ${a.vulnRiskScore}/100 (${a.vulnRiskBand})`).join("\n") || "None identified"}

## Confirmed Findings (sorted by severity)
${confirmedFindingsList || "No confirmed findings"}

## Probable Findings (lower confidence — product-family matches)
${probableFindingsList || "No probable findings"}

## Exposed Ports
${exposedPorts || "No exposed ports detected"}

## Technologies Detected (client-owned assets only)
${Array.from(new Set(clientAnalyses.flatMap(a => a.asset.technologies || []))).slice(0, 30).join(", ") || "None detected"}

## Cross-Module Intelligence
${crossModuleData ? `
- Bug Bounty: ${crossModuleData.bugBounty.status === "success" ? `Program: ${crossModuleData.bugBounty.programName || "None"}, ${crossModuleData.bugBounty.correlations.length} correlations` : "N/A"}
- Threat Intel: ${crossModuleData.threatIntel.status === "success" ? `${crossModuleData.threatIntel.matchingThreatActors.length} matching actors, ${crossModuleData.threatIntel.riskAdjustments.length} risk adjustments` : "N/A"}
- OpSec: ${crossModuleData.opsec.status === "success" ? `${crossModuleData.opsec.defensiveGaps.length} defensive gaps` : "N/A"}
- Discovery Deep Dive: ${crossModuleData.discoveryDeepDive.status === "success" ? `${crossModuleData.discoveryDeepDive.infrastructureInsights.length} infrastructure insights, ${crossModuleData.discoveryDeepDive.certificateFindings.length} cert findings` : "N/A"}
` : "Cross-module enrichment not available"}

## Your Analysis Tasks (evidence-grounded only)
1. **Attack Paths**: Chain CONFIRMED findings into realistic attack paths. Each step MUST reference a specific finding from the data above. Do not invent steps based on assumptions.
2. **Blind Spots**: Identify gaps in scan COVERAGE (what wasn't tested), not speculative threats. Examples: "No internal network scan performed", "Cloud IAM not assessed", "No web application penetration test conducted".
3. **Prioritized Recommendations**: Rank by confirmed severity and exploitability. Each recommendation must reference specific findings.
4. **Cross-Finding Correlations**: Identify how confirmed findings on the same or related assets amplify risk when combined.
5. **Threat Actor Mapping**: ONLY include actors whose documented TTPs match specific confirmed findings. Cite which findings match which techniques.
6. **Overall Assessment**: Summarize the CONFIRMED risk posture calibrated to the ${prelimRiskBand.toUpperCase()} overall risk rating. State what is known vs. unknown. Do not inflate risk based on assumptions. Your tone MUST match the overall risk band.
7. **Confidence Statement**: Explicitly state what the analysis is confident about (based on confirmed data) and what remains uncertain.

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
          content: `You are a cybersecurity risk analyst specializing in evidence-based threat assessment. Your role is to analyze CONFIRMED scan findings and produce actionable, grounded risk analysis.

STRICT RULES:
- Every claim must cite specific evidence from the scan data
- Do NOT speculate about vulnerabilities that were not confirmed
- Do NOT assume risks based on technology names alone
- Do NOT inflate severity or likelihood without evidence
- Clearly label confidence levels: HIGH (confirmed CVE with version match), MEDIUM (probable product-family match), LOW (inferred from scan gaps)
- If the evidence is insufficient to make a claim, say so explicitly rather than guessing
- Attack paths must only use confirmed findings as steps — no hypothetical exploitation

Return valid JSON only.`,
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
