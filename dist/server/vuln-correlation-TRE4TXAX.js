import {
  context_engine_tracker_exports,
  init_context_engine_tracker
} from "./chunk-A5MYZ335.js";
import {
  __esm,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-detection/vuln-correlation.ts
async function buildKevEpssContext(discoveredCves, state, addLog) {
  let kevContext = "";
  let kevMatches = [];
  let epssCount = 0;
  if (discoveredCves.length === 0) return { kevContext, kevMatches, epssCount };
  try {
    const { fetchKevCatalog, matchCvesAgainstKev, calculateKevRiskBoost } = await import("./kev-service-UTFPRZA3.js");
    const kevCatalog = await fetchKevCatalog();
    kevMatches = matchCvesAgainstKev(discoveredCves, kevCatalog);
    if (kevMatches.length > 0) {
      const kevBoost = calculateKevRiskBoost(kevMatches);
      kevContext = `

\u26A0\uFE0F CISA KNOWN EXPLOITED VULNERABILITIES (KEV) ALERT:
${kevMatches.length} CVEs are on the CISA KEV catalog \u2014 ACTIVELY EXPLOITED in the wild:
${kevMatches.map((m) => `- ${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? " [RANSOMWARE VECTOR]" : ""}`).join("\n")}`;
      if (kevBoost.ransomwareExposure) kevContext += "\n\u{1F534} RANSOMWARE EXPOSURE detected.";
      addLog(state, { phase: "vuln_detection", type: "finding", title: `\u26A0\uFE0F ${kevMatches.length} CISA KEV Matches`, detail: kevBoost.summary });
    }
  } catch (e) {
    console.error("[KEV] Failed to enrich:", e.message);
  }
  try {
    const { extractShodanVersionEvidence } = await import("./shodan-verifier-KUN4FU3T.js");
    const shodanObservations = [];
    for (const asset of state.assets) {
      if (!asset.passiveRecon) continue;
      for (const svc of asset.passiveRecon.services || []) {
        if (svc.source !== "shodan") continue;
        shodanObservations.push({ source: "shodan", ip: asset.ip || "", name: asset.hostname, evidence: { port: svc.port, product: svc.product || "", version: svc.version || "" } });
      }
    }
    if (shodanObservations.length > 0) {
      const versionEvidence = extractShodanVersionEvidence(shodanObservations);
      const shodanCveSet = /* @__PURE__ */ new Set();
      for (const ev of versionEvidence) for (const cve of ev.vulns) shodanCveSet.add(cve);
      const kevCveSet = new Set(kevMatches.map((m) => m.cveID));
      let confirmed = 0, unconfirmed = 0;
      for (const cve of discoveredCves) {
        if (kevCveSet.has(cve)) {
          shodanCveSet.has(cve) ? confirmed++ : unconfirmed++;
        }
      }
      if (confirmed > 0 || unconfirmed > 0) {
        kevContext += `

\u{1F50D} SHODAN KEV CROSS-VALIDATION: ${confirmed} confirmed, ${unconfirmed} unconfirmed.`;
      }
    }
  } catch {
  }
  try {
    const { batchPrioritizeCves, buildEpssContextForLlm } = await import("./epss-service-7HFFOUBB.js");
    const kevCveSet = new Set(kevMatches.map((m) => m.cveID));
    const prioritized = await batchPrioritizeCves(discoveredCves, kevCveSet);
    if (prioritized.length > 0) {
      kevContext += buildEpssContextForLlm(prioritized);
      epssCount = prioritized.length;
      const criticalCount = prioritized.filter((p) => p.priorityTier === "critical").length;
      addLog(state, { phase: "vuln_detection", type: "finding", title: `\u{1F4CA} EPSS: ${criticalCount} critical priority CVEs`, detail: `Scored ${prioritized.length} CVEs` });
    }
  } catch {
  }
  return { kevContext, kevMatches, epssCount };
}
async function runVulnVerification(highCritVulns, state, addLog, broadcastOpsUpdate) {
  if (highCritVulns.length === 0) return 0;
  let verified = 0;
  addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F9D0} Vulnerability Verification (AI Specialist)", detail: `Verifying ${highCritVulns.length} high/critical findings...` });
  broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  try {
    const { verifyVulnerability } = await import("./vuln-verifier-3ZTRJHDG.js");
    const { evidenceGate, buildProvenance, createIntegrityEnvelope } = await import("./evidence-integrity-WKAFFQR3.js");
    for (const v of highCritVulns.slice(0, 10)) {
      try {
        const result = await verifyVulnerability({
          finding: { title: v.title, severity: v.severity, cve: v.cve, description: v.title, evidence: `Found on ${v.hostname}`, source: v.title.startsWith("[ZAP]") ? "ZAP" : "nuclei", hostname: v.hostname },
          engagement: { engagementType: state.engagementType, clientName: state.assets[0]?.hostname, targetCount: state.assets.length },
          engagementId: state.engagementId
        });
        const vulnVerifContent = JSON.stringify(result);
        const provenance = buildProvenance({ tool: "llm_analysis", command: "specialist:vuln-verifier", collectorHost: process.env.SCAN_SERVER_HOST || "ac3-platform", rawOutput: vulnVerifContent, targetHost: v.hostname, sourceIp: "127.0.0.1", destinationIp: v.hostname });
        const vulnVerifGate = evidenceGate({ content: vulnVerifContent, provenance, groundTruth: { vuln_source: `${v.title} ${v.cve || ""} ${v.severity}` }, knownAssets: state.assets.map((a) => ({ hostname: a.hostname, ip: a.ip || "", ports: a.ports.map((p) => p.port) })), knownCves: state.assets.flatMap((a) => a.vulns.filter((vl) => vl.cve).map((vl) => vl.cve)), strictness: "moderate" });
        createIntegrityEnvelope({ evidenceId: `vuln-verif-${state.engagementId}-${v.cve || v.title.slice(0, 20)}-${Date.now()}`, engagementId: String(state.engagementId), content: vulnVerifContent, provenance, performedBy: "AC3 Vuln Verifier" });
        const verdictEmoji = result.analyst_verdict.includes("True Positive") ? "\u2705" : result.analyst_verdict.includes("False Positive") ? "\u274C" : "\u2753";
        addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `${verdictEmoji} Verified: ${v.title}`, detail: `Verdict: ${result.analyst_verdict} (${result.confidence})
Exploitability: ${result.exploitability.rating}
Integrity: ${vulnVerifGate.passed ? "PASSED" : "FAILED"}` });
        verified++;
      } catch (vErr) {
        console.warn(`[VulnVerifier] Failed for ${v.title}:`, vErr.message);
      }
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e) {
    console.warn("[VulnVerifier] Specialist unavailable:", e.message);
  }
  return verified;
}
async function runScanForgeReasoning(highCritVulns, state, addLog, broadcastOpsUpdate) {
  if (highCritVulns.length === 0) return 0;
  let processed = 0;
  try {
    const { batchRunScanForgeReasoning } = await import("./scanforge-reasoning-2Y7BQPBJ.js");
    const reasoningInputs = highCritVulns.slice(0, 8).map((v) => {
      const asset = state.assets.find((a) => a.hostname === v.hostname);
      return {
        finding: { id: `vuln-${v.hostname}-${v.cve || v.title.substring(0, 30)}`, title: v.title, description: v.title, severity: v.severity, cveIds: v.cve ? [v.cve] : [], evidence: `Found on ${v.hostname}`, tool: v.title.startsWith("[ZAP]") ? "ZAP" : "nuclei", port: asset?.ports?.[0]?.port, service: asset?.ports?.[0]?.service },
        asset: { hostname: v.hostname, ip: asset?.ip, exposure: "external", businessRole: asset?.hostname || "unknown", services: asset?.ports?.map((p) => ({ port: p.port, protocol: p.protocol || "tcp", service_name: p.service, product: p.product })) },
        engagement: { type: state.engagementType, clientName: state.assets[0]?.hostname },
        skipTriage: false
      };
    });
    addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F52C} ScanForge Reasoning Pipeline", detail: `Processing ${reasoningInputs.length} findings...` });
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
    const results = await batchRunScanForgeReasoning(reasoningInputs, {
      concurrency: 2,
      onProgress: () => {
        if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
      }
    });
    for (const r of results) {
      const stateEmoji = r.triage?.state === "verified" ? "\u2705" : r.triage?.state === "probable" ? "\u{1F7E1}" : "\u{1F7E0}";
      addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `${stateEmoji} ScanForge: ${r.enrichment?.titleRefined || r.findingId}`, detail: `State: ${r.triage?.state || "unknown"} | Score: ${r.hybridScore?.hybridPriorityScore || "N/A"}/100`, data: { scanforgeReasoning: r } });
      processed++;
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e) {
    console.warn("[ScanForgeReasoning] Pipeline error:", e.message);
  }
  return processed;
}
async function runHybridScoring(state, addLog, broadcastOpsUpdate) {
  const assetsWithFindings = state.assets.filter((a) => a.vulns.length > 0 || a.zapFindings.length > 0);
  if (assetsWithFindings.length === 0) return 0;
  let scored = 0;
  try {
    const { scoreFullHybrid, buildEngagementContext } = await import("./hybrid-scorer-5U6LQ3VG.js");
    addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F3AF} Hybrid Risk Scoring (Active Findings)", detail: `Scoring ${assetsWithFindings.length} assets...` });
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
    for (const asset of assetsWithFindings) {
      if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
      try {
        const riskSignals = [
          ...asset.vulns.map((v) => ({ severity: v.severity || "medium", rationale: `${v.title}${v.cve ? " (" + v.cve + ")" : ""}`, source: v.title.startsWith("[ZAP]") ? "ZAP" : "nuclei" })),
          ...asset.zapFindings.map((z) => ({ severity: z.risk || "medium", rationale: `${z.alert}: ${z.description?.substring(0, 150) || ""}`, source: "ZAP" }))
        ];
        const hybridResult = await scoreFullHybrid({
          assetId: asset.hostname,
          assetLabel: asset.hostname,
          domain: asset.hostname,
          hostname: asset.hostname,
          ports: (asset.ports || []).map((p) => ({ port: p.port, service: p.service, version: p.version, state: p.state || "open" })),
          technologies: asset.passiveRecon?.technologies || [],
          wafDetected: asset.passiveRecon?.wafDetected,
          cloudProvider: asset.passiveRecon?.cloudProvider,
          certificates: asset.passiveRecon?.certificates || [],
          dnsRecords: asset.passiveRecon?.dnsRecords || [],
          httpHeaders: asset.passiveRecon?.httpHeaders || {},
          riskSignals,
          cvssBase: Math.max(...asset.vulns.map((v) => v.cvss || 0), 0) || void 0,
          engagementContext: state.engagementContext || buildEngagementContext({ engagementType: state.engagementType || "pentest", targetCount: state.assets?.length || 1, domains: [asset.hostname] })
        });
        asset.hybridScore = hybridResult.finalScore;
        asset.hybridTier = hybridResult.finalTier;
        addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `\u{1F3AF} ${asset.hostname} \u2014 ${hybridResult.finalScore}/10`, detail: `Tier: ${hybridResult.finalTier} | Baseline: ${hybridResult.baseline.scores.hybrid}/10` });
        scored++;
      } catch (e) {
        console.warn(`[HybridScorer] Failed for ${asset.hostname}:`, e.message);
      }
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e) {
    console.warn("[HybridScorer] Unavailable:", e.message);
  }
  return scored;
}
async function runThreatActorMapping(state, addLog, broadcastOpsUpdate, scoreEngagementThreatAttribution) {
  if (!state.assets.some((a) => a.vulns.length > 0 || a.zapFindings.length > 0)) return 0;
  let mapped = 0;
  try {
    const { mapThreats } = await import("./threat-mapper-QNQDMXIP.js");
    addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F310} Threat Actor Mapping", detail: "Correlating findings with known threat actors..." });
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
    const allFindings = state.assets.flatMap((a) => [
      ...a.vulns.map((v) => `[${v.severity}] ${v.title} on ${a.hostname}${v.cve ? " (" + v.cve + ")" : ""}`),
      ...a.zapFindings.map((z) => `[${z.risk}] ${z.alert} on ${a.hostname}`)
    ]);
    const threatResult = await mapThreats({
      findingsSummary: allFindings.join("\n"),
      assets: state.assets.map((a) => ({ hostname: a.hostname, ip: a.ip, type: a.type, technologies: a.passiveRecon?.technologies, ports: a.ports.map((p) => ({ port: p.port, service: p.service })) })),
      engagement: { engagementType: state.engagementType, clientName: state.assets[0]?.hostname, targetCount: state.assets.length },
      engagementId: state.engagementId
    });
    if (threatResult.threat_actors.length > 0) {
      mapped = threatResult.threat_actors.length;
      addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `\u{1F3AF} ${mapped} Threat Actor(s) Mapped`, detail: threatResult.threat_actors.map((ta) => `${ta.actor_name} (${ta.confidence})`).join(", "), data: { threatMapping: threatResult } });
      try {
        const ttps = threatResult.threat_actors.flatMap((ta) => (ta.associated_ttps || []).map((ttpStr) => {
          const match = ttpStr.match(/^(T\d+(?:\.\d+)?)\s*[:\-]?\s*(.*)/);
          return { techniqueId: match ? match[1] : void 0, techniqueName: match ? match[2].trim() : ttpStr };
        }));
        const cves = [...new Set(state.assets.flatMap((a) => a.vulns.filter((v) => v.cve).map((v) => v.cve)))];
        if ((ttps.length > 0 || cves.length > 0) && scoreEngagementThreatAttribution) {
          await scoreEngagementThreatAttribution({ sessionId: `eng-${state.engagementId}-${Date.now()}`, engagementId: state.engagementId, targetUrl: state.assets[0]?.hostname, ttps, cves });
        }
      } catch {
      }
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e) {
    console.warn("[ThreatMapper] Unavailable:", e.message);
  }
  return mapped;
}
async function runDedupAndCoverage(state, addLog, broadcastOpsUpdate) {
  try {
    const { runEngagementDedup, runEngagementCoverageAnalysis } = await import("./dedup-coverage-bridge-5XMXAMJQ.js");
    addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F504} Running finding deduplication", detail: `Analyzing ${state.stats.vulnsFound} findings for duplicates` });
    const dedupStats = await runEngagementDedup(state.assets);
    state.dedupStats = dedupStats;
    state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
    addLog(state, { phase: "vuln_detection", type: "info", title: `\u2702\uFE0F Dedup: ${dedupStats.duplicatesRemoved} duplicates removed`, detail: `${dedupStats.totalFindingsBeforeDedup} \u2192 ${dedupStats.totalFindingsAfterDedup}` });
    addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F4CA} Coverage gap analysis", detail: "Checking scan completeness" });
    const coverageReport = runEngagementCoverageAnalysis(state.assets);
    state.coverageReport = coverageReport;
    const emoji = coverageReport.overallScore >= 80 ? "\u{1F7E2}" : coverageReport.overallScore >= 60 ? "\u{1F7E1}" : "\u{1F534}";
    addLog(state, { phase: "vuln_detection", type: "info", title: `${emoji} Coverage: ${coverageReport.overallScore}%`, detail: `${coverageReport.totalGaps} gaps (${coverageReport.criticalGaps} critical)` });
    broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats }, dedupStats, coverageReport });
    return { dedupStats, coverageScore: coverageReport.overallScore };
  } catch (e) {
    console.error("[DedupCoverage] Error:", e.message);
    addLog(state, { phase: "vuln_detection", type: "warning", title: "\u26A0\uFE0F Dedup/coverage failed", detail: e.message?.slice(0, 200) });
    return { dedupStats: null, coverageScore: null };
  }
}
async function executeVulnCorrelation(ctx) {
  const { state, addLog, broadcastOpsUpdate, llmDecide, captureDecision, scoreEngagementThreatAttribution } = ctx;
  const result = { attackStrategy: null, kevMatches: 0, epssScored: 0, vulnsVerified: 0, scanforgeProcessed: 0, assetsScored: 0, threatActorsMapped: 0, dedupStats: null, coverageScore: null, correlatedFindings: 0, exploitStrategies: 0, verifiedFindings: 0, deduplicatedCount: 0, coverageGaps: 0 };
  const allVulns = state.assets.flatMap((a) => a.vulns);
  if (allVulns.length > 0) {
    result.correlatedFindings = allVulns.length;
    if (global.gc) global.gc();
    const discoveredCves = allVulns.map((v) => v.cve).filter(Boolean);
    const { kevContext, kevMatches, epssCount } = await buildKevEpssContext(discoveredCves, state, addLog);
    result.kevMatches = kevMatches.length;
    result.epssScored = epssCount;
    try {
      const {
        getChainsByVulnDescriptions,
        formatChainsForPrompt,
        formatOntologyForPrompt,
        getBugBountyContext,
        getTriageCorpusContext,
        buildCloudSecurityContext,
        getScanforgeVulnCorrelationContext,
        getOwaspVulnCorrelationContext,
        getThreatGroupVulnContext,
        buildOffensiveTechniquesContext,
        buildZAPKnowledgeContext,
        buildSourceSecretsContext,
        buildBurpKnowledgeContext
      } = await import("./knowledge-lazy-6AWNDT67.js");
      const { capLLMContext: _capLLMContext } = await import("./memory-manager-VARXZ63M.js");
      const vulnDescs = allVulns.map((v) => v.title + (v.cve ? ` ${v.cve}` : ""));
      const chains = getChainsByVulnDescriptions(vulnDescs, 3);
      const detectedTech = state.assets.flatMap((a) => [...a.type !== "unknown" ? [a.type] : [], ...a.ports.map((p) => p.service).filter(Boolean)]);
      const contextBlocks = [
        { label: "chains", content: formatChainsForPrompt(chains) },
        { label: "ontology", content: formatOntologyForPrompt([...new Set(detectedTech)]) },
        { label: "bugBounty", content: getBugBountyContext(vulnDescs, 3) },
        { label: "triage", content: getTriageCorpusContext(void 0, 3) },
        { label: "cloud", content: buildCloudSecurityContext(state.assets.flatMap((a) => [...a.passiveRecon?.technologies || [], ...a.vulns.map((v) => v.title)])) || "" },
        { label: "scanforge", content: getScanforgeVulnCorrelationContext() },
        { label: "owasp", content: getOwaspVulnCorrelationContext() },
        { label: "threat", content: getThreatGroupVulnContext() },
        { label: "offensive", content: buildOffensiveTechniquesContext({ phase: "vuln_detection", hasFirewall: state.assets.some((a) => a.wafDetected && a.wafDetected !== "none"), hasWAF: state.assets.some((a) => a.wafDetected && a.wafDetected !== "none") }) || "" },
        { label: "zap", content: buildZAPKnowledgeContext({ phase: "vuln_detection", technology: detectedTech[0] }) || "" },
        { label: "burp", content: buildBurpKnowledgeContext({ phase: "vuln_detection", technology: detectedTech[0], includeAttackProfiles: true, includeCollaborator: true }) },
        { label: "secrets", content: buildSourceSecretsContext({ phase: "vuln_detection", includeSecretPatterns: true, includeJSAnalysis: true }) || "" }
      ];
      const cappedContext = _capLLMContext(contextBlocks);
      try {
        const { buildContributionFromBlocks } = (init_context_engine_tracker(), __toCommonJS(context_engine_tracker_exports));
        buildContributionFromBlocks(state.engagementId, state.assets.map((a) => a.hostname).join(", "), discoveredCves.join(", "), contextBlocks, cappedContext, "exploit_deferred");
      } catch {
      }
      const _corrDecStart = Date.now();
      const correlationDecision = await llmDecide({
        phase: "vuln_detection",
        engagementType: state.engagementType,
        engagementId: state.engagementId,
        assets: state.assets,
        recentLog: state.log.slice(-20),
        question: `Vulnerability scanning complete. Findings:
${allVulns.map((v) => `- ${v.title} (${v.severity})${v.cve ? ` [${v.cve}]` : ""}`).join("\n")}${kevContext}
Correlate findings and recommend exploitation strategy.
${cappedContext}`
      });
      state.llmPlan = correlationDecision.decision;
      result.attackStrategy = correlationDecision.decision;
      result.exploitStrategies = (correlationDecision.actions || []).length || 1;
      addLog(state, { phase: "vuln_detection", type: "llm_decision", title: "Attack Strategy Determined", detail: correlationDecision.decision, data: { reasoning: correlationDecision.reasoning, actions: correlationDecision.actions } });
      captureDecision({ engagementId: state.engagementId, phase: "vuln_detection", caller: "vuln-correlation.executeVulnCorrelation", decision: correlationDecision.decision, reasoning: correlationDecision.reasoning, actions: correlationDecision.actions, contextSummary: `${state.assets.length} assets, ${allVulns.length} vulns`, latencyMs: Date.now() - _corrDecStart, knowledgeModules: ["burp_pentesting", "zap_pentesting", "owasp_testing", "cross_tool_intelligence"] }).catch(() => {
      });
    } catch (e) {
      console.error("[VulnCorrelation] LLM decision failed:", e.message);
    }
  }
  state.progress = 55;
  const highCritVulns = state.assets.flatMap((a) => a.vulns.filter((v) => v.severity === "critical" || v.severity === "high").map((v) => ({ ...v, hostname: a.hostname, assetType: a.type })));
  result.vulnsVerified = await runVulnVerification(highCritVulns, state, addLog, broadcastOpsUpdate);
  result.verifiedFindings = result.vulnsVerified;
  result.scanforgeProcessed = await runScanForgeReasoning(highCritVulns, state, addLog, broadcastOpsUpdate);
  result.assetsScored = await runHybridScoring(state, addLog, broadcastOpsUpdate);
  result.threatActorsMapped = await runThreatActorMapping(state, addLog, broadcastOpsUpdate, scoreEngagementThreatAttribution);
  state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
  state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
  const { dedupStats, coverageScore } = await runDedupAndCoverage(state, addLog, broadcastOpsUpdate);
  if (dedupStats) {
    result.dedupStats = { duplicatesRemoved: dedupStats.duplicatesRemoved, totalBefore: dedupStats.totalFindingsBeforeDedup, totalAfter: dedupStats.totalFindingsAfterDedup };
    result.deduplicatedCount = dedupStats.duplicatesRemoved;
  }
  result.coverageScore = coverageScore;
  if (state.coverageReport) result.coverageGaps = state.coverageReport.totalGaps || 0;
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "\u2705 Phase 6 Complete", detail: `${state.stats.vulnsFound} vulns (post-dedup), ${state.stats.zapScansRun || 0} ZAP scans, ${state.stats.wafDetections || 0} WAFs` });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
  return result;
}
var init_vuln_correlation = __esm({
  "server/lib/vuln-detection/vuln-correlation.ts"() {
  }
});
init_vuln_correlation();
export {
  buildKevEpssContext,
  executeVulnCorrelation,
  runDedupAndCoverage,
  runHybridScoring,
  runScanForgeReasoning,
  runThreatActorMapping,
  runVulnVerification
};
