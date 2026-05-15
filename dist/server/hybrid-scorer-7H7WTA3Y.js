import {
  assembleSystemPrompt,
  init_core_policy
} from "./chunk-NO5RORCF.js";
import {
  init_llm_json_parser,
  parseLLMJson
} from "./chunk-UQ7CH3JX.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-2HOIKPO3.js";
import {
  AUTO_BIA_ASSET_PRIORITY,
  THREAT_ACTOR_LIKELIHOOD,
  buildExplainableRiskCard,
  computeHybridFusionScore,
  getAdjustedCarverPreset,
  inferSector,
  init_auto_industry_carver
} from "./chunk-JQN23ZNI.js";
import "./chunk-UAG3IV7V.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/hybrid-scorer.ts
function buildEngagementContext(input) {
  const sectorResult = inferSector({
    domain: input.domains?.[0],
    hostname: input.domains?.[0],
    keywords: input.keywords,
    assetSignals: input.assetSignals,
    pageContent: input.pageContent
  });
  const threatLikelihood = THREAT_ACTOR_LIKELIHOOD[sectorResult.sector] || {};
  const threatLandscape = Object.entries(threatLikelihood).map(([category, likelihood]) => ({ category, likelihood: likelihood || 0 })).sort((a, b) => b.likelihood - a.likelihood);
  const crownJewels = AUTO_BIA_ASSET_PRIORITY[sectorResult.sector] || [];
  return {
    engagementType: input.engagementType,
    clientName: input.clientName,
    industry: input.industry || sectorResult.sector.replace(/_/g, " "),
    scope: input.scope,
    targetCount: input.targetCount,
    inferredSector: sectorResult.sector,
    sectorConfidence: sectorResult.confidence,
    regulatoryProfile: sectorResult.regulatoryProfile,
    complianceFrameworks: sectorResult.regulatoryProfile.map((r) => r.toString()),
    threatLandscape,
    crownJewels,
    rulesOfEngagement: input.rulesOfEngagement
  };
}
function formatContextForLLM(ctx) {
  const lines = [
    `## Engagement Context`,
    `Type: ${ctx.engagementType}`,
    ctx.clientName ? `Client: ${ctx.clientName}` : null,
    `Industry: ${ctx.industry} (${ctx.inferredSector}, confidence: ${Math.round(ctx.sectorConfidence * 100)}%)`,
    ctx.scope ? `Scope: ${ctx.scope}` : null,
    `Targets: ${ctx.targetCount}`,
    ``,
    `## Regulatory & Compliance`,
    ctx.regulatoryProfile.length > 0 ? `Frameworks: ${ctx.regulatoryProfile.join(", ")}` : `No specific regulatory frameworks identified`,
    ``,
    `## Threat Landscape`,
    ...ctx.threatLandscape.slice(0, 5).map(
      (t) => `\u2022 ${t.category.replace(/_/g, " ")}: ${Math.round(t.likelihood * 100)}% likelihood`
    ),
    ``,
    `## Crown Jewels (sector-typical high-value assets)`,
    ...ctx.crownJewels.map((cj) => `\u2022 ${cj}`),
    ctx.rulesOfEngagement ? `
## Rules of Engagement
${ctx.rulesOfEngagement}` : null
  ].filter(Boolean);
  return lines.join("\n");
}
async function scoreHybrid(input) {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: HYBRID_SCORER_ROLE,
    customerContext: formatContextForLLM(input.engagementContext),
    assetContext: `Asset: ${input.assetLabel} (${input.hostname || input.domain || "unknown"})`
  });
  const scanSummary = buildScanSummary(input);
  const userMessage = `## Deterministic Baseline Scores
Asset: ${input.assetLabel}
Sector: ${input.baselineCard.sector}
CARVER+SHOCK Composite: ${input.baselineCard.scores.carverShock}/10
CVSS Base: ${input.baselineCard.scores.cvss.base}/10
Hybrid Score: ${input.baselineCard.scores.hybrid}
Priority Tier: ${input.baselineCard.scores.priorityTier}
Top Drivers: ${input.baselineCard.topDrivers.map((d) => d.driver).join(", ")}

## Observed Scan Data
${scanSummary}

${input.dwxIntel?.length ? `## Dark Web / Threat Intelligence
${input.dwxIntel.map((d) => `\u2022 [${d.source}] ${d.finding}${d.date ? ` (${d.date})` : ""}`).join("\n")}` : ""}

${input.osintFindings?.length ? `## Additional OSINT
${input.osintFindings.map((f) => `\u2022 ${f}`).join("\n")}` : ""}

Provide your CARVER+SHOCK adjustments and risk narrative in the specified JSON format.`;
  try {
    const response = await throttledLLMCall({
      _priority: "essential",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userMessage }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "hybrid_score_adjustments",
          strict: true,
          schema: {
            type: "object",
            properties: {
              adjustments: {
                type: "object",
                properties: {
                  criticality: { type: "object", properties: { delta: { type: "number" }, justification: { type: "string" } }, required: ["delta", "justification"], additionalProperties: false },
                  accessibility: { type: "object", properties: { delta: { type: "number" }, justification: { type: "string" } }, required: ["delta", "justification"], additionalProperties: false },
                  recuperability: { type: "object", properties: { delta: { type: "number" }, justification: { type: "string" } }, required: ["delta", "justification"], additionalProperties: false },
                  vulnerability: { type: "object", properties: { delta: { type: "number" }, justification: { type: "string" } }, required: ["delta", "justification"], additionalProperties: false },
                  effect: { type: "object", properties: { delta: { type: "number" }, justification: { type: "string" } }, required: ["delta", "justification"], additionalProperties: false },
                  recognizability: { type: "object", properties: { delta: { type: "number" }, justification: { type: "string" } }, required: ["delta", "justification"], additionalProperties: false },
                  shock: { type: "object", properties: { delta: { type: "number" }, justification: { type: "string" } }, required: ["delta", "justification"], additionalProperties: false }
                },
                required: ["criticality", "accessibility", "recuperability", "vulnerability", "effect", "recognizability", "shock"],
                additionalProperties: false
              },
              businessContextInference: { type: "string" },
              attackSurfaceAssessment: { type: "string" },
              exploitabilityAssessment: { type: "string" },
              overallRiskNarrative: { type: "string" },
              confidence: { type: "string", enum: ["high", "medium", "low"] },
              evidenceTags: { type: "array", items: { type: "string" } }
            },
            required: ["adjustments", "businessContextInference", "attackSurfaceAssessment", "exploitabilityAssessment", "overallRiskNarrative", "confidence", "evidenceTags"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = parseLLMJson(content, { fallback: {} }).data;
    const basePreset = getAdjustedCarverPreset(
      input.baselineCard.sector,
      input.baselineCard.regulatoryProfile
    );
    const adjustedPreset = {
      criticality: clamp(basePreset.criticality + (parsed.adjustments.criticality.delta || 0), 1, 10),
      accessibility: clamp(basePreset.accessibility + (parsed.adjustments.accessibility.delta || 0), 1, 10),
      recuperability: clamp(basePreset.recuperability + (parsed.adjustments.recuperability.delta || 0), 1, 10),
      vulnerability: clamp(basePreset.vulnerability + (parsed.adjustments.vulnerability.delta || 0), 1, 10),
      effect: clamp(basePreset.effect + (parsed.adjustments.effect.delta || 0), 1, 10),
      recognizability: clamp(basePreset.recognizability + (parsed.adjustments.recognizability.delta || 0), 1, 10),
      shock: clamp(basePreset.shock + (parsed.adjustments.shock.delta || 0), 1, 10)
    };
    const adjustedFusion = computeHybridFusionScore({
      carverPreset: adjustedPreset,
      cvssBase: input.baselineCard.scores.cvss.base,
      cvssExploitability: input.baselineCard.scores.cvss.exploitability
    });
    return {
      adjustments: parsed.adjustments,
      businessContextInference: parsed.businessContextInference,
      attackSurfaceAssessment: parsed.attackSurfaceAssessment,
      exploitabilityAssessment: parsed.exploitabilityAssessment,
      overallRiskNarrative: parsed.overallRiskNarrative,
      adjustedHybridScore: adjustedFusion.hybrid,
      adjustedPriorityTier: adjustedFusion.priorityTier,
      confidence: parsed.confidence,
      evidenceTags: parsed.evidenceTags || []
    };
  } catch (err) {
    console.error("[hybrid-scorer] LLM call failed, returning baseline:", err.message);
    return {
      adjustments: {
        criticality: { delta: 0, justification: "LLM unavailable \u2014 using baseline" },
        accessibility: { delta: 0, justification: "LLM unavailable \u2014 using baseline" },
        recuperability: { delta: 0, justification: "LLM unavailable \u2014 using baseline" },
        vulnerability: { delta: 0, justification: "LLM unavailable \u2014 using baseline" },
        effect: { delta: 0, justification: "LLM unavailable \u2014 using baseline" },
        recognizability: { delta: 0, justification: "LLM unavailable \u2014 using baseline" },
        shock: { delta: 0, justification: "LLM unavailable \u2014 using baseline" }
      },
      businessContextInference: "LLM analysis unavailable \u2014 using deterministic baseline only",
      attackSurfaceAssessment: "LLM analysis unavailable",
      exploitabilityAssessment: "LLM analysis unavailable",
      overallRiskNarrative: `Baseline hybrid score: ${input.baselineCard.scores.hybrid} (${input.baselineCard.scores.priorityTier})`,
      adjustedHybridScore: input.baselineCard.scores.hybrid,
      adjustedPriorityTier: input.baselineCard.scores.priorityTier,
      confidence: "low",
      evidenceTags: ["[BASELINE_ONLY]"]
    };
  }
}
async function scoreFullHybrid(input) {
  const baseline = buildExplainableRiskCard({
    assetId: input.assetId,
    assetLabel: input.assetLabel,
    domain: input.domain,
    hostname: input.hostname,
    keywords: input.keywords,
    assetSignals: input.assetSignals,
    pageContent: input.pageContent,
    cvssBase: input.cvssBase,
    cvssExploitability: input.cvssExploitability,
    epssScore: input.epssScore,
    isKev: input.isKev,
    fedRampLevel: input.fedRampLevel,
    overrideSector: input.overrideSector
  });
  const llmEnhanced = await scoreHybrid({
    assetId: input.assetId,
    assetLabel: input.assetLabel,
    domain: input.domain,
    hostname: input.hostname,
    baselineCard: baseline,
    scanFindings: {
      ports: input.ports,
      technologies: input.technologies,
      wafDetected: input.wafDetected,
      cloudProvider: input.cloudProvider,
      certificates: input.certificates,
      dnsRecords: input.dnsRecords,
      whoisData: input.whoisData,
      httpHeaders: input.httpHeaders,
      riskSignals: input.riskSignals
    },
    dwxIntel: input.dwxIntel,
    osintFindings: input.osintFindings,
    engagementContext: input.engagementContext
  });
  const evMult = input.evidenceMultiplier ?? 1;
  const evidenceAdjusted = evMult < 1;
  const adjustedScore = evidenceAdjusted ? Math.round(llmEnhanced.adjustedHybridScore * evMult * 100) / 100 : llmEnhanced.adjustedHybridScore;
  return {
    baseline,
    llmEnhanced,
    finalScore: adjustedScore,
    finalTier: evidenceAdjusted ? priorityTierFromScore(adjustedScore) : llmEnhanced.adjustedPriorityTier,
    evidenceAdjusted
  };
}
function buildScanSummary(input) {
  const lines = [];
  if (input.scanFindings.ports?.length) {
    lines.push(`Ports: ${input.scanFindings.ports.map(
      (p) => `${p.port}/${p.service || "?"}${p.version ? " (" + p.version + ")" : ""} [${p.state || "open"}]`
    ).join(", ")}`);
  } else {
    lines.push("Ports: No open ports detected (may indicate filtering or cloud-fronted service)");
  }
  if (input.scanFindings.technologies?.length) {
    lines.push(`Technologies: ${input.scanFindings.technologies.join(", ")}`);
  }
  if (input.scanFindings.wafDetected && input.scanFindings.wafDetected !== "none") {
    lines.push(`WAF: ${input.scanFindings.wafDetected} [OBSERVED]`);
  }
  if (input.scanFindings.cloudProvider) {
    lines.push(`Cloud: ${input.scanFindings.cloudProvider} [OBSERVED]`);
  }
  if (input.scanFindings.certificates?.length) {
    const cert = input.scanFindings.certificates[0];
    lines.push(`TLS: issuer=${cert.issuer || "?"}, valid=${cert.validFrom || "?"} to ${cert.validTo || "?"}`);
    if (cert.san?.length) {
      lines.push(`SANs: ${cert.san.slice(0, 10).join(", ")}${cert.san.length > 10 ? ` (+${cert.san.length - 10} more)` : ""}`);
    }
  }
  if (input.scanFindings.dnsRecords?.length) {
    lines.push(`DNS: ${input.scanFindings.dnsRecords.map((r) => `${r.type}=${r.value}`).join(", ")}`);
  }
  if (input.scanFindings.whoisData) {
    const w = input.scanFindings.whoisData;
    lines.push(`WHOIS: registrar=${w.registrar || "?"}, created=${w.createdDate || "?"}, expires=${w.expiryDate || "?"}`);
  }
  if (input.scanFindings.httpHeaders) {
    const secHeaders = ["x-frame-options", "content-security-policy", "strict-transport-security", "x-content-type-options"];
    const present = secHeaders.filter((h) => input.scanFindings.httpHeaders?.[h]);
    const missing = secHeaders.filter((h) => !input.scanFindings.httpHeaders?.[h]);
    if (present.length) lines.push(`Security headers present: ${present.join(", ")}`);
    if (missing.length) lines.push(`Security headers missing: ${missing.join(", ")}`);
  }
  if (input.scanFindings.riskSignals?.length) {
    lines.push(`Risk signals (${input.scanFindings.riskSignals.length}):`);
    for (const sig of input.scanFindings.riskSignals.slice(0, 10)) {
      lines.push(`  \u2022 [${sig.severity}] ${sig.rationale} (${sig.source})`);
    }
  }
  return lines.join("\n");
}
function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}
var HYBRID_SCORER_ROLE;
var init_hybrid_scorer = __esm({
  "server/lib/llm-specialists/hybrid-scorer.ts"() {
    init_llm_throttle();
    init_core_policy();
    init_auto_industry_carver();
    init_llm_json_parser();
    HYBRID_SCORER_ROLE = `You are the AC3 Hybrid Risk Scorer.

Your job is to review deterministic CARVER+SHOCK+CVSS scores for an asset and provide
LLM-enhanced adjustments based on observed scan data and engagement context.

You do NOT replace the deterministic scoring \u2014 you AUGMENT it with reasoning that
static rules cannot capture:

1. **Business Context Inference**: What role does this asset likely play in the organization?
   Does the hostname, technology stack, or content suggest it's a crown jewel, support system,
   or peripheral asset? Adjust criticality and effect accordingly.

2. **Attack Surface Reality Check**: Do the observed ports, services, and configurations
   suggest the asset is more or less accessible/vulnerable than the sector baseline assumes?
   Adjust accessibility and vulnerability accordingly.

3. **OSINT Signal Fusion**: Do certificate transparency logs, DNS records, WHOIS data,
   or other OSINT signals reveal information that changes the risk picture?
   (e.g., recently registered domain \u2192 higher suspicion, wildcard cert \u2192 broader exposure)

4. **Dark Web / Threat Intel Fusion**: If DWX or threat intel data is provided, factor in
   whether credentials, mentions, or indicators related to this asset appear in underground
   sources. This can significantly elevate shock and effect scores.

5. **Exploitability Assessment**: Based on the specific services and versions observed,
   how realistic is exploitation? Consider WAF presence, cloud provider protections,
   and known mitigations.

For each CARVER+SHOCK dimension, provide:
- Your adjustment (-3 to +3, where 0 = agree with baseline)
- A one-sentence justification tagged with evidence type

Keep adjustments conservative. Most dimensions should be 0 (agree with baseline).
Only adjust when scan data provides clear evidence.`;
  }
});
init_hybrid_scorer();
export {
  buildEngagementContext,
  formatContextForLLM,
  scoreFullHybrid,
  scoreHybrid
};
