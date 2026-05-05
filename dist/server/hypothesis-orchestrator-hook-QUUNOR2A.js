import {
  bounty_hypothesis_generator_exports,
  init_bounty_hypothesis_generator
} from "./chunk-BKUXTOLG.js";
import {
  __esm,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/hypothesis-orchestrator-hook.ts
function extractReconDataFromState(state) {
  const primaryAsset = state.assets[0];
  const targetDomain = primaryAsset?.hostname || "unknown";
  const techStack = [];
  const seenTech = /* @__PURE__ */ new Set();
  for (const asset of state.assets) {
    if (asset.passiveRecon?.technologies) {
      for (const tech of asset.passiveRecon.technologies) {
        const techLower = tech.toLowerCase();
        if (!seenTech.has(techLower)) {
          seenTech.add(techLower);
          techStack.push({
            technology: tech,
            confidence: 0.8,
            source: "wappalyzer"
          });
        }
      }
    }
    for (const port of asset.ports) {
      if (port.service && !seenTech.has(port.service.toLowerCase())) {
        seenTech.add(port.service.toLowerCase());
        techStack.push({
          technology: port.service,
          version: port.version,
          confidence: 0.9,
          source: "header"
        });
      }
    }
  }
  const openPorts = [];
  const seenPorts = /* @__PURE__ */ new Set();
  for (const asset of state.assets) {
    for (const port of asset.ports) {
      const key = `${asset.hostname}:${port.port}`;
      if (!seenPorts.has(key)) {
        seenPorts.add(key);
        openPorts.push({
          port: port.port,
          service: port.service || "unknown",
          version: port.version,
          state: port.state || "open"
        });
      }
    }
  }
  const subdomains = [...new Set(
    state.assets.map((a) => a.hostname).filter((h) => h && h !== targetDomain && h.endsWith(`.${targetDomain}`))
  )];
  const endpoints = [];
  for (const asset of state.assets) {
    if (asset.toolResults) {
      for (const tr of asset.toolResults) {
        if (tr.endpoints) {
          for (const ep of tr.endpoints) {
            endpoints.push({
              path: ep.path || ep.url || "/",
              method: ep.method || "GET",
              statusCode: ep.statusCode || 200,
              responseSize: ep.responseSize,
              contentType: ep.contentType,
              requiresAuth: ep.requiresAuth || false,
              parameters: ep.parameters
            });
          }
        }
      }
    }
  }
  const headers = {};
  for (const asset of state.assets) {
    if (asset.passiveRecon?.headers) {
      Object.assign(headers, asset.passiveRecon.headers);
    }
  }
  const configAnomalies = [];
  for (const asset of state.assets) {
    if (asset.passiveRecon?.riskSignals) {
      for (const signal of asset.passiveRecon.riskSignals) {
        const category = inferAnomalyCategory(signal.category || signal.rationale);
        if (category) {
          configAnomalies.push({
            category,
            description: signal.rationale,
            severity: signal.severity || "medium",
            evidence: signal.rationale
          });
        }
      }
    }
  }
  const passiveFindings = [];
  for (const asset of state.assets) {
    for (const vuln of asset.vulns) {
      if (vuln.source === "passive" || vuln.source === "nuclei" || vuln.source === "nikto") {
        passiveFindings.push({
          type: vuln.cve || vuln.title || "unknown",
          description: vuln.description || vuln.title || "",
          endpoint: vuln.endpoint || vuln.url,
          severity: vuln.severity || "medium"
        });
      }
    }
  }
  const wafDetected = state.assets.find((a) => a.wafDetected)?.wafDetected;
  const cdnDetected = state.assets.find((a) => a.cdnDetected)?.cdnDetected;
  return {
    targetDomain,
    programHandle: state.bbRoeConfig?.programHandle,
    techStack,
    openPorts,
    subdomains,
    endpoints,
    headers,
    wafDetected,
    cdnDetected,
    configAnomalies,
    passiveFindings
  };
}
function inferAnomalyCategory(text) {
  const lower = text.toLowerCase();
  if (lower.includes("cors")) return "cors";
  if (lower.includes("csp") || lower.includes("content-security")) return "csp";
  if (lower.includes("header") || lower.includes("x-frame") || lower.includes("hsts")) return "headers";
  if (lower.includes("tls") || lower.includes("ssl") || lower.includes("certificate")) return "tls";
  if (lower.includes("dns") || lower.includes("nameserver")) return "dns";
  if (lower.includes("api") || lower.includes("gateway") || lower.includes("rate limit")) return "api_gateway";
  if (lower.includes("auth") || lower.includes("session") || lower.includes("cookie") || lower.includes("jwt")) return "auth";
  if (lower.includes("cache") || lower.includes("cdn")) return "cache";
  return null;
}
async function runHypothesisGeneration(state) {
  if (state.assets.length === 0) {
    return {
      generated: false,
      hypothesisCount: 0,
      highConfidenceCount: 0,
      topHypotheses: [],
      reconQualityScore: 0,
      missingReconData: ["No assets discovered yet"],
      chainOpportunities: 0,
      estimatedResearchHours: 0,
      generatedAt: Date.now()
    };
  }
  let generateHypotheses;
  let generateProgramAwareHypotheses;
  try {
    const mod = (init_bounty_hypothesis_generator(), __toCommonJS(bounty_hypothesis_generator_exports));
    generateHypotheses = mod.generateHypotheses;
    generateProgramAwareHypotheses = mod.generateProgramAwareHypotheses;
  } catch {
    const mod = await import("./bounty-hypothesis-generator-ZWTEM4VT.js");
    generateHypotheses = mod.generateHypotheses;
    generateProgramAwareHypotheses = mod.generateProgramAwareHypotheses;
  }
  const reconData = extractReconDataFromState(state);
  let result;
  if (state.engagementType === "bug_bounty" && state.bbRoeConfig?.programHandle) {
    const programContext = {
      avgBounty: state.bbRoeConfig.rewardStructure?.avgBounty,
      maxBounty: state.bbRoeConfig.rewardStructure?.maxBounty,
      commonCWEs: state.bbRoeConfig.rewardStructure?.commonCWEs
    };
    result = generateProgramAwareHypotheses(reconData, programContext);
  } else {
    result = generateHypotheses(reconData);
  }
  if (!state.metadata) state.metadata = {};
  state.metadata.hypothesisResults = {
    targetDomain: result.targetDomain,
    programHandle: result.programHandle,
    summary: result.summary,
    reconQuality: result.reconQuality,
    generatedAt: result.generatedAt,
    hypotheses: result.hypotheses.map((h) => ({
      id: h.id,
      vulnClass: h.vulnClass,
      title: h.title,
      description: h.description,
      affectedEndpoint: h.affectedEndpoint,
      confidence: h.confidence,
      confidenceScore: h.confidenceScore,
      reasoning: h.reasoning,
      verificationSteps: h.verificationSteps,
      estimatedEffort: h.estimatedEffort,
      potentialSeverity: h.potentialSeverity,
      potentialBountyRange: h.potentialBountyRange,
      chainPotential: h.chainPotential,
      duplicateLikelihood: h.duplicateLikelihood,
      tags: h.tags,
      supportingEvidence: h.supportingEvidence,
      disconfirmingEvidence: h.disconfirmingEvidence,
      evidenceThatWouldChangeConfidence: h.evidenceThatWouldChangeConfidence
    }))
  };
  const highConfidence = result.hypotheses.filter((h) => h.confidence === "high");
  return {
    generated: true,
    hypothesisCount: result.hypotheses.length,
    highConfidenceCount: highConfidence.length,
    topHypotheses: result.hypotheses.slice(0, 10).map((h) => ({
      title: h.title,
      vulnClass: h.vulnClass,
      confidence: h.confidence,
      confidenceScore: h.confidenceScore,
      severity: h.potentialSeverity,
      endpoint: h.affectedEndpoint,
      estimatedEffort: h.estimatedEffort
    })),
    reconQualityScore: result.reconQuality.overallScore,
    missingReconData: result.reconQuality.missingData,
    chainOpportunities: result.summary.topChainOpportunities.length,
    estimatedResearchHours: result.summary.estimatedResearchHours,
    generatedAt: result.generatedAt
  };
}
function buildScanPriorityAdjustments(state) {
  const hypothesisResults = state.metadata?.hypothesisResults;
  if (!hypothesisResults?.hypotheses) return [];
  const adjustments = [];
  for (const h of hypothesisResults.hypotheses) {
    if (h.confidence === "high" || h.confidence === "medium" && h.potentialSeverity === "critical") {
      adjustments.push({
        endpoint: h.affectedEndpoint,
        vulnClass: h.vulnClass,
        priority: h.potentialSeverity === "critical" ? "critical" : h.confidence === "high" ? "high" : "medium",
        reason: `Hypothesis "${h.title}" (${h.confidence} confidence, ${h.potentialSeverity} severity)`
      });
    }
  }
  for (const h of hypothesisResults.hypotheses) {
    if (h.chainPotential && h.chainPotential.length > 0 && h.confidenceScore >= 0.5) {
      for (const chain of h.chainPotential) {
        if (chain.impactMultiplier >= 2) {
          adjustments.push({
            endpoint: h.affectedEndpoint,
            vulnClass: chain.toVulnClass,
            priority: "high",
            reason: `Chain opportunity: ${chain.chainDescription} (${chain.impactMultiplier}x impact)`
          });
        }
      }
    }
  }
  return adjustments;
}
function formatHypothesisLogEntry(hookResult) {
  if (!hookResult.generated) {
    return {
      title: "\u{1F9E0} Hypothesis Generator: No assets to analyze",
      detail: "Hypothesis generation skipped \u2014 no assets discovered during reconnaissance."
    };
  }
  const topLines = hookResult.topHypotheses.slice(0, 5).map(
    (h, i) => `${i + 1}. [${h.confidence.toUpperCase()}] ${h.title} \u2192 ${h.endpoint} (${h.severity}, ~${h.estimatedEffort})`
  );
  return {
    title: `\u{1F9E0} Hypothesis Generator: ${hookResult.hypothesisCount} hypotheses (${hookResult.highConfidenceCount} high-confidence)`,
    detail: [
      `Recon quality: ${hookResult.reconQualityScore}/100`,
      hookResult.missingReconData.length > 0 ? `Missing data: ${hookResult.missingReconData.slice(0, 3).join(", ")}` : "Recon data coverage: complete",
      `Chain opportunities: ${hookResult.chainOpportunities}`,
      `Estimated research: ${hookResult.estimatedResearchHours.toFixed(1)} hours`,
      "",
      "Top hypotheses:",
      ...topLines
    ].join("\n")
  };
}
var init_hypothesis_orchestrator_hook = __esm({
  "server/lib/hypothesis-orchestrator-hook.ts"() {
  }
});
init_hypothesis_orchestrator_hook();
export {
  buildScanPriorityAdjustments,
  extractReconDataFromState,
  formatHypothesisLogEntry,
  runHypothesisGeneration
};
