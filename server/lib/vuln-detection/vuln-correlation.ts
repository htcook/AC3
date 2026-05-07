/**
 * Vulnerability Detection — Correlation & Specialist Pipelines
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection (lines 5967-6630).
 *
 * Responsibilities:
 *   - LLM correlation: analyze all findings and recommend exploit strategy
 *   - KEV enrichment + EPSS scoring + Shodan cross-validation
 *   - Specialist: Verify high/critical vulnerabilities
 *   - Specialist: ScanForge reasoning pipeline (triage, enrichment, ATT&CK, FedRAMP)
 *   - Specialist: Hybrid scorer for active scan findings
 *   - Specialist: Map threats to threat actors (APT correlation)
 *   - Deduplication & coverage gap analysis
 *   - Phase 6 completion summary
 */

import type { VulnDetectionContext } from "./index";

// ─── Result Types ───────────────────────────────────────────────────────────

export interface VulnCorrelationResult {
  /** LLM correlation decision (attack strategy) */
  attackStrategy: string | null;
  /** Number of KEV matches found */
  kevMatches: number;
  /** Number of EPSS-scored CVEs */
  epssScored: number;
  /** Number of vulnerabilities verified by specialist */
  vulnsVerified: number;
  /** Number of findings processed by ScanForge reasoning */
  scanforgeProcessed: number;
  /** Number of assets scored by hybrid scorer */
  assetsScored: number;
  /** Number of threat actors mapped */
  threatActorsMapped: number;
  /** Dedup stats */
  dedupStats: { duplicatesRemoved: number; totalBefore: number; totalAfter: number } | null;
  /** Coverage score (0-100) */
  coverageScore: number | null;
  /** Number of findings correlated by LLM */
  correlatedFindings: number;
  /** Number of exploit strategies recommended */
  exploitStrategies: number;
  /** Number of findings verified by specialist */
  verifiedFindings: number;
  /** Number of findings deduplicated */
  deduplicatedCount: number;
  /** Coverage gaps identified */
  coverageGaps: number;
}

// ─── KEV Enrichment ─────────────────────────────────────────────────────────

/**
 * Enrich discovered CVEs with CISA KEV catalog data and EPSS scores.
 * Returns context string for LLM consumption.
 */
export async function buildKevEpssContext(
  discoveredCves: string[],
  state: any,
  addLog: VulnDetectionContext["addLog"],
): Promise<{ kevContext: string; kevMatches: any[]; epssCount: number }> {
  let kevContext = "";
  let kevMatches: any[] = [];
  let epssCount = 0;

  if (discoveredCves.length === 0) return { kevContext, kevMatches, epssCount };

  // KEV catalog lookup
  try {
    const { fetchKevCatalog, matchCvesAgainstKev, calculateKevRiskBoost } = await import("../kev-service");
    const kevCatalog = await fetchKevCatalog();
    kevMatches = matchCvesAgainstKev(discoveredCves, kevCatalog);
    if (kevMatches.length > 0) {
      const kevBoost = calculateKevRiskBoost(kevMatches);
      kevContext = `\n\n⚠️ CISA KNOWN EXPLOITED VULNERABILITIES (KEV) ALERT:\n${kevMatches.length} CVEs are on the CISA KEV catalog — ACTIVELY EXPLOITED in the wild:\n${kevMatches.map((m: any) => `- ${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? " [RANSOMWARE VECTOR]" : ""}`).join("\n")}`;
      if (kevBoost.ransomwareExposure) kevContext += "\n🔴 RANSOMWARE EXPOSURE detected.";
      addLog(state, { phase: "vuln_detection", type: "finding", title: `⚠️ ${kevMatches.length} CISA KEV Matches`, detail: kevBoost.summary });
    }
  } catch (e: any) {
    console.error("[KEV] Failed to enrich:", e.message);
  }

  // Shodan-KEV cross-validation
  try {
    const { extractShodanVersionEvidence } = await import("../shodan-verifier");
    const shodanObservations: any[] = [];
    for (const asset of state.assets) {
      if (!asset.passiveRecon) continue;
      for (const svc of asset.passiveRecon.services || []) {
        if (svc.source !== "shodan") continue;
        shodanObservations.push({ source: "shodan", ip: asset.ip || "", name: asset.hostname, evidence: { port: svc.port, product: svc.product || "", version: svc.version || "" } });
      }
    }
    if (shodanObservations.length > 0) {
      const versionEvidence = extractShodanVersionEvidence(shodanObservations);
      const shodanCveSet = new Set<string>();
      for (const ev of versionEvidence) for (const cve of ev.vulns) shodanCveSet.add(cve);
      const kevCveSet = new Set(kevMatches.map((m: any) => m.cveID));
      let confirmed = 0, unconfirmed = 0;
      for (const cve of discoveredCves) {
        if (kevCveSet.has(cve)) { shodanCveSet.has(cve) ? confirmed++ : unconfirmed++; }
      }
      if (confirmed > 0 || unconfirmed > 0) {
        kevContext += `\n\n🔍 SHODAN KEV CROSS-VALIDATION: ${confirmed} confirmed, ${unconfirmed} unconfirmed.`;
      }
    }
  } catch { /* non-fatal */ }

  // EPSS scoring
  try {
    const { batchPrioritizeCves, buildEpssContextForLlm } = await import("../epss-service");
    const kevCveSet = new Set(kevMatches.map((m: any) => m.cveID));
    const prioritized = await batchPrioritizeCves(discoveredCves, kevCveSet);
    if (prioritized.length > 0) {
      kevContext += buildEpssContextForLlm(prioritized);
      epssCount = prioritized.length;
      const criticalCount = prioritized.filter((p: any) => p.priorityTier === "critical").length;
      addLog(state, { phase: "vuln_detection", type: "finding", title: `📊 EPSS: ${criticalCount} critical priority CVEs`, detail: `Scored ${prioritized.length} CVEs` });
    }
  } catch { /* non-fatal */ }

  return { kevContext, kevMatches, epssCount };
}

// ─── Specialist: Vulnerability Verification ─────────────────────────────────

export async function runVulnVerification(
  highCritVulns: any[],
  state: any,
  addLog: VulnDetectionContext["addLog"],
  broadcastOpsUpdate: VulnDetectionContext["broadcastOpsUpdate"],
): Promise<number> {
  if (highCritVulns.length === 0) return 0;
  let verified = 0;

  addLog(state, { phase: "vuln_detection", type: "info", title: "🧐 Vulnerability Verification (AI Specialist)", detail: `Verifying ${highCritVulns.length} high/critical findings...` });
  broadcastOpsUpdate(state.engagementId, { type: "log_update" });

  try {
    const { verifyVulnerability } = await import("../llm-specialists/vuln-verifier");
    const { evidenceGate, buildProvenance, createIntegrityEnvelope } = await import("../evidence-integrity");

    for (const v of highCritVulns.slice(0, 10)) {
      try {
        const result = await verifyVulnerability({
          finding: { title: v.title, severity: v.severity, cve: v.cve, description: v.title, evidence: `Found on ${v.hostname}`, source: v.title.startsWith("[ZAP]") ? "ZAP" : "nuclei", hostname: v.hostname },
          engagement: { engagementType: state.engagementType, clientName: state.assets[0]?.hostname, targetCount: state.assets.length },
          engagementId: state.engagementId,
        });

        const vulnVerifContent = JSON.stringify(result);
        const provenance = buildProvenance({ tool: "llm_analysis" as any, command: "specialist:vuln-verifier", collectorHost: process.env.SCAN_SERVER_HOST || "ac3-platform", rawOutput: vulnVerifContent, targetHost: v.hostname, sourceIp: "127.0.0.1", destinationIp: v.hostname });
        const vulnVerifGate = evidenceGate({ content: vulnVerifContent, provenance, groundTruth: { vuln_source: `${v.title} ${v.cve || ""} ${v.severity}` }, knownAssets: state.assets.map((a: any) => ({ hostname: a.hostname, ip: a.ip || "", ports: a.ports.map((p: any) => p.port) })), knownCves: state.assets.flatMap((a: any) => a.vulns.filter((vl: any) => vl.cve).map((vl: any) => vl.cve!)), strictness: "moderate" });
        createIntegrityEnvelope({ evidenceId: `vuln-verif-${state.engagementId}-${v.cve || v.title.slice(0, 20)}-${Date.now()}`, engagementId: String(state.engagementId), content: vulnVerifContent, provenance, performedBy: "AC3 Vuln Verifier" });

        const verdictEmoji = result.analyst_verdict.includes("True Positive") ? "✅" : result.analyst_verdict.includes("False Positive") ? "❌" : "❓";
        addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `${verdictEmoji} Verified: ${v.title}`, detail: `Verdict: ${result.analyst_verdict} (${result.confidence})\nExploitability: ${result.exploitability.rating}\nIntegrity: ${vulnVerifGate.passed ? "PASSED" : "FAILED"}` });
        verified++;
      } catch (vErr: any) {
        console.warn(`[VulnVerifier] Failed for ${v.title}:`, vErr.message);
      }
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e: any) {
    console.warn("[VulnVerifier] Specialist unavailable:", e.message);
  }
  return verified;
}

// ─── Specialist: ScanForge Reasoning ────────────────────────────────────────

export async function runScanForgeReasoning(
  highCritVulns: any[],
  state: any,
  addLog: VulnDetectionContext["addLog"],
  broadcastOpsUpdate: VulnDetectionContext["broadcastOpsUpdate"],
): Promise<number> {
  if (highCritVulns.length === 0) return 0;
  let processed = 0;

  try {
    const { batchRunScanForgeReasoning } = await import("../llm-specialists/scanforge-reasoning");
    const reasoningInputs = highCritVulns.slice(0, 8).map((v: any) => {
      const asset = state.assets.find((a: any) => a.hostname === v.hostname);
      return {
        finding: { id: `vuln-${v.hostname}-${v.cve || v.title.substring(0, 30)}`, title: v.title, description: v.title, severity: v.severity, cveIds: v.cve ? [v.cve] : [], evidence: `Found on ${v.hostname}`, tool: v.title.startsWith("[ZAP]") ? "ZAP" : "nuclei", port: asset?.ports?.[0]?.port, service: asset?.ports?.[0]?.service },
        asset: { hostname: v.hostname, ip: asset?.ip, exposure: "external" as const, businessRole: asset?.hostname || "unknown", services: asset?.ports?.map((p: any) => ({ port: p.port, protocol: p.protocol || "tcp", service_name: p.service, product: p.product })) },
        engagement: { type: state.engagementType, clientName: state.assets[0]?.hostname },
        skipTriage: false,
      };
    });

    addLog(state, { phase: "vuln_detection", type: "info", title: "🔬 ScanForge Reasoning Pipeline", detail: `Processing ${reasoningInputs.length} findings...` });
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });

    const results = await batchRunScanForgeReasoning(reasoningInputs, {
      concurrency: 2,
      onProgress: () => { if ((state as any)._heartbeatRef) (state as any)._heartbeatRef.lastActivityAt = Date.now(); },
    });

    for (const r of results) {
      const stateEmoji = r.triage?.state === "verified" ? "✅" : r.triage?.state === "probable" ? "🟡" : "🟠";
      addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `${stateEmoji} ScanForge: ${r.enrichment?.titleRefined || r.findingId}`, detail: `State: ${r.triage?.state || "unknown"} | Score: ${r.hybridScore?.hybridPriorityScore || "N/A"}/100`, data: { scanforgeReasoning: r } });
      processed++;
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e: any) {
    console.warn("[ScanForgeReasoning] Pipeline error:", e.message);
  }
  return processed;
}

// ─── Specialist: Hybrid Scorer ──────────────────────────────────────────────

export async function runHybridScoring(
  state: any,
  addLog: VulnDetectionContext["addLog"],
  broadcastOpsUpdate: VulnDetectionContext["broadcastOpsUpdate"],
): Promise<number> {
  const assetsWithFindings = state.assets.filter((a: any) => a.vulns.length > 0 || a.zapFindings.length > 0);
  if (assetsWithFindings.length === 0) return 0;
  let scored = 0;

  try {
    const { scoreFullHybrid, buildEngagementContext } = await import("../llm-specialists/hybrid-scorer");
    addLog(state, { phase: "vuln_detection", type: "info", title: "🎯 Hybrid Risk Scoring (Active Findings)", detail: `Scoring ${assetsWithFindings.length} assets...` });
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });

    for (const asset of assetsWithFindings) {
      if ((state as any)._heartbeatRef) (state as any)._heartbeatRef.lastActivityAt = Date.now();
      try {
        const riskSignals = [
          ...asset.vulns.map((v: any) => ({ severity: v.severity || "medium", rationale: `${v.title}${v.cve ? " (" + v.cve + ")" : ""}`, source: v.title.startsWith("[ZAP]") ? "ZAP" : "nuclei" })),
          ...asset.zapFindings.map((z: any) => ({ severity: z.risk || "medium", rationale: `${z.alert}: ${z.description?.substring(0, 150) || ""}`, source: "ZAP" })),
        ];
        const hybridResult = await scoreFullHybrid({
          assetId: asset.hostname, assetLabel: asset.hostname, domain: asset.hostname, hostname: asset.hostname,
          ports: (asset.ports || []).map((p: any) => ({ port: p.port, service: p.service, version: p.version, state: p.state || "open" })),
          technologies: asset.passiveRecon?.technologies || [], wafDetected: asset.passiveRecon?.wafDetected,
          cloudProvider: asset.passiveRecon?.cloudProvider, certificates: asset.passiveRecon?.certificates || [],
          dnsRecords: asset.passiveRecon?.dnsRecords || [], httpHeaders: asset.passiveRecon?.httpHeaders || {},
          riskSignals, cvssBase: Math.max(...asset.vulns.map((v: any) => v.cvss || 0), 0) || undefined,
          engagementContext: state.engagementContext || buildEngagementContext({ engagementType: state.engagementType || "pentest", targetCount: state.assets?.length || 1, domains: [asset.hostname] }),
        });
        (asset as any).hybridScore = hybridResult.finalScore;
        (asset as any).hybridTier = hybridResult.finalTier;
        addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `🎯 ${asset.hostname} — ${hybridResult.finalScore}/10`, detail: `Tier: ${hybridResult.finalTier} | Baseline: ${hybridResult.baseline.scores.hybrid}/10` });
        scored++;
      } catch (e: any) {
        console.warn(`[HybridScorer] Failed for ${asset.hostname}:`, e.message);
      }
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e: any) {
    console.warn("[HybridScorer] Unavailable:", e.message);
  }
  return scored;
}

// ─── Specialist: Threat Actor Mapping ───────────────────────────────────────

export async function runThreatActorMapping(
  state: any,
  addLog: VulnDetectionContext["addLog"],
  broadcastOpsUpdate: VulnDetectionContext["broadcastOpsUpdate"],
  scoreEngagementThreatAttribution: any,
): Promise<number> {
  if (!state.assets.some((a: any) => a.vulns.length > 0 || a.zapFindings.length > 0)) return 0;
  let mapped = 0;

  try {
    const { mapThreats } = await import("../llm-specialists/threat-mapper");
    addLog(state, { phase: "vuln_detection", type: "info", title: "🌐 Threat Actor Mapping", detail: "Correlating findings with known threat actors..." });
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });

    const allFindings = state.assets.flatMap((a: any) => [
      ...a.vulns.map((v: any) => `[${v.severity}] ${v.title} on ${a.hostname}${v.cve ? " (" + v.cve + ")" : ""}`),
      ...a.zapFindings.map((z: any) => `[${z.risk}] ${z.alert} on ${a.hostname}`),
    ]);
    const threatResult = await mapThreats({
      findingsSummary: allFindings.join("\n"),
      assets: state.assets.map((a: any) => ({ hostname: a.hostname, ip: a.ip, type: a.type, technologies: a.passiveRecon?.technologies, ports: a.ports.map((p: any) => ({ port: p.port, service: p.service })) })),
      engagement: { engagementType: state.engagementType, clientName: state.assets[0]?.hostname, targetCount: state.assets.length },
      engagementId: state.engagementId,
    });

    if (threatResult.threat_actors.length > 0) {
      mapped = threatResult.threat_actors.length;
      addLog(state, { phase: "vuln_detection", type: "llm_decision", title: `🎯 ${mapped} Threat Actor(s) Mapped`, detail: threatResult.threat_actors.map((ta: any) => `${ta.actor_name} (${ta.confidence})`).join(", "), data: { threatMapping: threatResult } });

      // Score against learning engine
      try {
        const ttps = threatResult.threat_actors.flatMap((ta: any) => (ta.associated_ttps || []).map((ttpStr: string) => {
          const match = ttpStr.match(/^(T\d+(?:\.\d+)?)\s*[:\-]?\s*(.*)/);
          return { techniqueId: match ? match[1] : undefined, techniqueName: match ? match[2].trim() : ttpStr };
        }));
        const cves = [...new Set(state.assets.flatMap((a: any) => a.vulns.filter((v: any) => v.cve).map((v: any) => v.cve!)))];
        if ((ttps.length > 0 || cves.length > 0) && scoreEngagementThreatAttribution) {
          await scoreEngagementThreatAttribution({ sessionId: `eng-${state.engagementId}-${Date.now()}`, engagementId: state.engagementId, targetUrl: state.assets[0]?.hostname, ttps, cves });
        }
      } catch { /* non-fatal */ }
    }
    broadcastOpsUpdate(state.engagementId, { type: "log_update" });
  } catch (e: any) {
    console.warn("[ThreatMapper] Unavailable:", e.message);
  }
  return mapped;
}

// ─── Deduplication & Coverage ───────────────────────────────────────────────

export async function runDedupAndCoverage(
  state: any,
  addLog: VulnDetectionContext["addLog"],
  broadcastOpsUpdate: VulnDetectionContext["broadcastOpsUpdate"],
): Promise<{ dedupStats: any; coverageScore: number | null }> {
  try {
    const { runEngagementDedup, runEngagementCoverageAnalysis } = await import("../dedup-coverage-bridge");

    addLog(state, { phase: "vuln_detection", type: "info", title: "🔄 Running finding deduplication", detail: `Analyzing ${state.stats.vulnsFound} findings for duplicates` });
    const dedupStats = await runEngagementDedup(state.assets as any);
    state.dedupStats = dedupStats;
    state.stats.vulnsFound = state.assets.reduce((sum: number, a: any) => sum + a.vulns.length, 0);
    addLog(state, { phase: "vuln_detection", type: "info", title: `✂️ Dedup: ${dedupStats.duplicatesRemoved} duplicates removed`, detail: `${dedupStats.totalFindingsBeforeDedup} → ${dedupStats.totalFindingsAfterDedup}` });

    addLog(state, { phase: "vuln_detection", type: "info", title: "📊 Coverage gap analysis", detail: "Checking scan completeness" });
    const coverageReport = runEngagementCoverageAnalysis(state.assets as any);
    state.coverageReport = coverageReport;
    const emoji = coverageReport.overallScore >= 80 ? "🟢" : coverageReport.overallScore >= 60 ? "🟡" : "🔴";
    addLog(state, { phase: "vuln_detection", type: "info", title: `${emoji} Coverage: ${coverageReport.overallScore}%`, detail: `${coverageReport.totalGaps} gaps (${coverageReport.criticalGaps} critical)` });

    broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats }, dedupStats, coverageReport } as any);
    return { dedupStats, coverageScore: coverageReport.overallScore };
  } catch (e: any) {
    console.error("[DedupCoverage] Error:", e.message);
    addLog(state, { phase: "vuln_detection", type: "warning", title: "⚠️ Dedup/coverage failed", detail: e.message?.slice(0, 200) });
    return { dedupStats: null, coverageScore: null };
  }
}

// ─── Main Correlation Pipeline ──────────────────────────────────────────────

/**
 * Execute the full vulnerability correlation and specialist pipeline.
 *
 * Pipeline:
 *   1. KEV enrichment + EPSS scoring + Shodan cross-validation
 *   2. LLM correlation decision (attack strategy)
 *   3. Specialist: Vulnerability Verification
 *   4. Specialist: ScanForge Reasoning
 *   5. Specialist: Hybrid Scorer
 *   6. Specialist: Threat Actor Mapping
 *   7. Deduplication & Coverage Gap Analysis
 *   8. Phase 6 completion summary
 */
export async function executeVulnCorrelation(ctx: VulnDetectionContext): Promise<VulnCorrelationResult> {
  const { state, addLog, broadcastOpsUpdate, llmDecide, captureDecision, scoreEngagementThreatAttribution } = ctx;

  const result: VulnCorrelationResult = { attackStrategy: null, kevMatches: 0, epssScored: 0, vulnsVerified: 0, scanforgeProcessed: 0, assetsScored: 0, threatActorsMapped: 0, dedupStats: null, coverageScore: null, correlatedFindings: 0, exploitStrategies: 0, verifiedFindings: 0, deduplicatedCount: 0, coverageGaps: 0 };

  const allVulns = state.assets.flatMap((a: any) => a.vulns);
  if (allVulns.length > 0) {
    result.correlatedFindings = allVulns.length;

    // Pre-LLM memory relief
    if (global.gc) global.gc();

    // KEV + EPSS enrichment
    const discoveredCves = allVulns.map((v: any) => v.cve).filter(Boolean) as string[];
    const { kevContext, kevMatches, epssCount } = await buildKevEpssContext(discoveredCves, state, addLog);
    result.kevMatches = kevMatches.length;
    result.epssScored = epssCount;

    // LLM correlation decision
    try {
      const {
        getChainsByVulnDescriptions, formatChainsForPrompt,
        formatOntologyForPrompt,
        getBugBountyContext, getTriageCorpusContext,
        buildCloudSecurityContext,
        getScanforgeVulnCorrelationContext, getOwaspVulnCorrelationContext, getThreatGroupVulnContext,
        buildOffensiveTechniquesContext,
        buildZAPKnowledgeContext,
        buildSourceSecretsContext,
        buildBurpKnowledgeContext,
      } = await import("../knowledge-lazy");
      const { capLLMContext: _capLLMContext } = await import("../memory-manager");

      const vulnDescs = allVulns.map((v: any) => v.title + (v.cve ? ` ${v.cve}` : ""));
      const chains = getChainsByVulnDescriptions(vulnDescs, 3);
      const detectedTech = state.assets.flatMap((a: any) => [...(a.type !== "unknown" ? [a.type] : []), ...a.ports.map((p: any) => p.service).filter(Boolean)]);

      const contextBlocks = [
        { label: "chains", content: formatChainsForPrompt(chains) },
        { label: "ontology", content: formatOntologyForPrompt([...new Set(detectedTech)]) },
        { label: "bugBounty", content: getBugBountyContext(vulnDescs, 3) },
        { label: "triage", content: getTriageCorpusContext(undefined, 3) },
        { label: "cloud", content: buildCloudSecurityContext(state.assets.flatMap((a: any) => [...(a.passiveRecon?.technologies || []), ...(a.vulns.map((v: any) => v.title))])) || "" },
        { label: "scanforge", content: getScanforgeVulnCorrelationContext() },
        { label: "owasp", content: getOwaspVulnCorrelationContext() },
        { label: "threat", content: getThreatGroupVulnContext() },
        { label: "offensive", content: buildOffensiveTechniquesContext({ phase: "vuln_detection", hasFirewall: state.assets.some((a: any) => a.wafDetected && a.wafDetected !== "none"), hasWAF: state.assets.some((a: any) => a.wafDetected && a.wafDetected !== "none") }) || "" },
        { label: "zap", content: buildZAPKnowledgeContext({ phase: "vuln_detection", technology: detectedTech[0] }) || "" },
        { label: "burp", content: buildBurpKnowledgeContext({ phase: "vuln_detection", technology: detectedTech[0], includeAttackProfiles: true, includeCollaborator: true }) },
        { label: "secrets", content: buildSourceSecretsContext({ phase: "vuln_detection", includeSecretPatterns: true, includeJSAnalysis: true }) || "" },
      ];
      const cappedContext = _capLLMContext(contextBlocks);

      // Context engine tracker
      try {
        const { buildContributionFromBlocks } = require("../context-engine-tracker");
        buildContributionFromBlocks(state.engagementId, state.assets.map((a: any) => a.hostname).join(", "), discoveredCves.join(", "), contextBlocks, cappedContext, "exploit_deferred");
      } catch { /* non-fatal */ }

      const _corrDecStart = Date.now();
      const correlationDecision = await llmDecide({
        phase: "vuln_detection", engagementType: state.engagementType, engagementId: state.engagementId,
        assets: state.assets, recentLog: state.log.slice(-20),
        question: `Vulnerability scanning complete. Findings:\n${allVulns.map((v: any) => `- ${v.title} (${v.severity})${v.cve ? ` [${v.cve}]` : ""}`).join("\n")}${kevContext}\nCorrelate findings and recommend exploitation strategy.\n${cappedContext}`,
      });

      state.llmPlan = correlationDecision.decision;
      result.attackStrategy = correlationDecision.decision;
      result.exploitStrategies = (correlationDecision.actions || []).length || 1;
      addLog(state, { phase: "vuln_detection", type: "llm_decision", title: "Attack Strategy Determined", detail: correlationDecision.decision, data: { reasoning: correlationDecision.reasoning, actions: correlationDecision.actions } });
      captureDecision({ engagementId: state.engagementId, phase: "vuln_detection", caller: "vuln-correlation.executeVulnCorrelation", decision: correlationDecision.decision, reasoning: correlationDecision.reasoning, actions: correlationDecision.actions, contextSummary: `${state.assets.length} assets, ${allVulns.length} vulns`, latencyMs: Date.now() - _corrDecStart, knowledgeModules: ["burp_pentesting", "zap_pentesting", "owasp_testing", "cross_tool_intelligence"] }).catch(() => {});
    } catch (e: any) {
      console.error("[VulnCorrelation] LLM decision failed:", e.message);
    }
  }

  state.progress = 55;

  // Specialist pipeline
  const highCritVulns = state.assets.flatMap((a: any) => a.vulns.filter((v: any) => v.severity === "critical" || v.severity === "high").map((v: any) => ({ ...v, hostname: a.hostname, assetType: a.type })));

  result.vulnsVerified = await runVulnVerification(highCritVulns, state, addLog, broadcastOpsUpdate);
  result.verifiedFindings = result.vulnsVerified;
  result.scanforgeProcessed = await runScanForgeReasoning(highCritVulns, state, addLog, broadcastOpsUpdate);
  result.assetsScored = await runHybridScoring(state, addLog, broadcastOpsUpdate);
  result.threatActorsMapped = await runThreatActorMapping(state, addLog, broadcastOpsUpdate, scoreEngagementThreatAttribution);

  // Final stats recalculation
  state.stats.vulnsFound = state.assets.reduce((sum: number, a: any) => sum + a.vulns.length, 0);
  state.stats.portsFound = state.assets.reduce((sum: number, a: any) => sum + a.ports.length, 0);

  // Dedup & coverage
  const { dedupStats, coverageScore } = await runDedupAndCoverage(state, addLog, broadcastOpsUpdate);
  if (dedupStats) {
    result.dedupStats = { duplicatesRemoved: dedupStats.duplicatesRemoved, totalBefore: dedupStats.totalFindingsBeforeDedup, totalAfter: dedupStats.totalFindingsAfterDedup };
    result.deduplicatedCount = dedupStats.duplicatesRemoved;
  }
  result.coverageScore = coverageScore;
  if (state.coverageReport) result.coverageGaps = state.coverageReport.totalGaps || 0;

  // Phase 6 complete
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "✅ Phase 6 Complete", detail: `${state.stats.vulnsFound} vulns (post-dedup), ${state.stats.zapScansRun || 0} ZAP scans, ${state.stats.wafDetections || 0} WAFs` });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });

  return result;
}
