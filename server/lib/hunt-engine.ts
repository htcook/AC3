/**
 * Hunt Workflow Engine — DHS/GSA HACS-Compliant Threat Hunting
 * ═══════════════════════════════════════════════════════════════
 * Implements the CISA Threat Hunt methodology:
 *   PREPARE → EXECUTE → ACT
 *
 * Aligned with:
 *   - NIST NICE Framework PR-CDA-001 (Cyber Defense Analysis)
 *   - NIST NICE Framework AN-TWA-001 (Threat Analysis)
 *   - GSA HACS SIN 54151HACS Cyber Hunt SOW requirements
 *   - CISA Hunt & Incident Response Team (HIRT) methodology
 *   - Sqrrl/PEAK Hypothesis-Driven Threat Hunting framework
 *
 * Knowledge Sources:
 *   - 300 attack chains (pentest training bundle)
 *   - 8-role asset ontology with technology inference rules
 *   - 13 bug bounty vulnerability classes with triage methodology
 *   - MITRE ATT&CK technique subset (50 techniques)
 *   - Threat actor TTP catalog (platform DB)
 */

import { invokeLLM } from "../_core/llm";
import {
  getChainsByOwaspCategory,
  getChainsByMitreTechnique,
  getChainsByVulnDescriptions,
  formatChainsForPrompt,
  getAvailableCategories,
  type AttackChain,
} from "./knowledge/attack-chain-retriever";
import {
  inferAssetContext,
  getArchitecturePatterns,
  formatOntologyForPrompt,
  getAssetClasses,
  lookupProduct,
} from "./knowledge/asset-ontology";
import {
  getBugBountyContext,
  getTriageSystemPrompt,
  getVulnerabilityClasses,
  getOwaspMapping,
  getTrainingExamplesForPrompt,
} from "./knowledge/bugbounty-knowledge";
import {
  getTriageCorpusContext,
  getCorpusForTool,
  getCorpusForOwasp,
  getDemoSites,
} from "./knowledge/training-corpus";
import {
  fetchKevCatalog,
  matchCvesAgainstKev,
  matchTechnologiesAgainstKev,
  getKevStats,
  type KevMatch,
} from "./kev-service";
import {
  buildCloudSecurityContext,
  buildGeneralCloudContext,
  buildCloudHuntContext,
  detectCloudProviders,
  getCloudAttackPaths,
  matchDetectionRules,
} from "./knowledge/cloud-security-knowledge";
import {
  getThreatGroupHuntContext,
  getThreatGroupScanContext,
  getThreatGroupVulnContext,
  getSectorThreatContext,
  getGroupsByTechnique,
  getGroupsByCVE,
  getGroupsBySector,
  getThreatGroupSummary,
} from "./threat-group-knowledge";
import * as scanforgeKnowledge from "./scanforge-knowledge";
import * as owaspKnowledge from "./owasp-knowledge";

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface HuntContext {
  /** Hunt session ID from DB */
  sessionId: number;
  /** Organization context */
  orgName: string;
  orgSector: string;
  /** Target SIEM platform */
  siemPlatform: "splunk" | "elastic" | "sentinel" | "qradar" | "chronicle" | "other";
  /** Available data sources (e.g., Windows Event Logs, Sysmon, DNS, Proxy, EDR) */
  dataSources: string[];
  /** Threat actor being hunted (optional) */
  threatActor?: {
    id: string;
    name: string;
    aliases?: string[];
    ttps?: string[];
    targetSectors?: string[];
    knownTools?: string[];
  };
  /** MITRE ATT&CK techniques to focus on */
  mitreTechniques?: Array<{ id: string; name: string; tactic: string }>;
  /** Scope constraints */
  scope?: {
    ipRanges?: string[];
    domains?: string[];
    timeWindow?: { start: string; end: string };
    excludedAssets?: string[];
  };
  /** Known assets from discovery */
  knownAssets?: Array<{
    hostname: string;
    ip?: string;
    assetType: string;
    technologies?: string[];
    role?: string;
  }>;
  /** Hunt type (PEAK framework) */
  huntType: "hypothesis_driven" | "baseline" | "model_assisted";
  /** Priority level */
  priority: "critical" | "high" | "medium" | "low";
}

export interface HuntHypothesis {
  /** Hypothesis statement */
  statement: string;
  /** MITRE ATT&CK technique */
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  mitreTactic: string;
  /** Required data sources to test */
  requiredDataSources: string[];
  /** Generated SIEM queries */
  sigmaRule?: string;
  splQuery?: string;
  kqlQuery?: string;
  /** Confidence level */
  confidence: "high" | "medium" | "low";
  /** Priority order */
  priority: number;
  /** Reasoning for this hypothesis */
  reasoning: string;
  /** Attack chain reference */
  attackChainRef?: string;
  /** Bug bounty pattern reference */
  bugBountyPatternRef?: string;
}

export interface HuntFinding {
  /** Finding title */
  title: string;
  /** Finding description */
  description: string;
  /** Severity */
  severity: "critical" | "high" | "medium" | "low" | "informational";
  /** MITRE ATT&CK mapping */
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  mitreTactic: string;
  /** Evidence summary */
  evidence: string;
  /** Affected assets */
  affectedAssets: string[];
  /** Recommended detection rule */
  detectionRule?: string;
  /** Remediation recommendation */
  remediation: string;
  /** Confidence */
  confidence: "high" | "medium" | "low";
}

export interface HuntDeliverable {
  /** Executive summary */
  executiveSummary: string;
  /** Hypotheses tested */
  hypothesesTested: number;
  hypothesesConfirmed: number;
  hypothesesRefuted: number;
  hypothesesInconclusive: number;
  /** Findings */
  findings: HuntFinding[];
  /** New detection rules generated */
  detectionRules: Array<{
    name: string;
    format: "sigma" | "splunk_spl" | "kql";
    content: string;
    mitreTechniqueId: string;
  }>;
  /** Recommendations */
  recommendations: string[];
  /** Data source gaps identified */
  dataSourceGaps: string[];
  /** GSA HACS compliance notes */
  hacsComplianceNotes: string[];
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — PREPARE PHASE: Hypothesis Generation
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate hunt hypotheses using LLM + training bundle knowledge.
 * This is the core of the PREPARE phase.
 */
export async function generateHypotheses(
  ctx: HuntContext,
  maxHypotheses: number = 10
): Promise<HuntHypothesis[]> {
  // Gather relevant attack chains based on context
  const attackChains: AttackChain[] = [];
  if (ctx.mitreTechniques) {
    for (const tech of ctx.mitreTechniques.slice(0, 5)) {
      attackChains.push(...getChainsByMitreTechnique(tech.id).slice(0, 3));
    }
  }
  if (ctx.threatActor?.ttps) {
    for (const ttp of ctx.threatActor.ttps.slice(0, 5)) {
      attackChains.push(...getChainsByMitreTechnique(ttp).slice(0, 2));
    }
  }
  // Deduplicate
  const uniqueChains = Array.from(new Map(attackChains.map(c => [c.id, c])).values()).slice(0, 10);

  // Get asset ontology context for known assets
  let assetOntologyContext = "";
  if (ctx.knownAssets) {
    const allTechs = ctx.knownAssets.flatMap(a => a.technologies || []);
    if (allTechs.length > 0) {
      assetOntologyContext = formatOntologyForPrompt(allTechs);
    }
    // Also infer asset context per host
    for (const asset of ctx.knownAssets.slice(0, 10)) {
      const inferred = inferAssetContext(asset.technologies || []);
      if (inferred.matchedProducts.length > 0) {
        assetOntologyContext += `\nAsset ${asset.hostname}: roles=${inferred.inferredRoles.join(",")}, classes=${inferred.assetClasses.join(",")}`;
      }
    }
  }

  // Get architecture pivot paths
  const pivotPaths = getArchitecturePatterns();

  // Get bug bounty triage context
  const triageContext = getTriageSystemPrompt();

  // ── KEV enrichment: fetch CISA KEV catalog for actively exploited CVEs ──
  let kevContext = '';
  try {
    const kevCatalog = await fetchKevCatalog();
    const kevStats = getKevStats(kevCatalog);
    // Match known asset technologies against KEV
    const assetTechs = ctx.knownAssets?.flatMap(a => a.technologies || []) || [];
    const kevTechMatches = assetTechs.length > 0 ? matchTechnologiesAgainstKev(assetTechs, kevCatalog) : [];
    const ransomwareKevs = kevTechMatches.filter(m => m.knownRansomware);
    if (kevTechMatches.length > 0 || kevStats.totalEntries > 0) {
      kevContext = `\nCISA KNOWN EXPLOITED VULNERABILITIES (KEV) INTELLIGENCE:\n- Total KEV entries: ${kevStats.totalEntries} (${kevStats.addedLast90Days} added in last 90 days)\n- Ransomware-linked: ${kevStats.ransomwareLinked}\n- Overdue by CISA deadline: ${kevStats.overdueCount}`;
      if (kevTechMatches.length > 0) {
        kevContext += `\n\n⚠️ ${kevTechMatches.length} KEV MATCHES against target technology stack:\n${kevTechMatches.slice(0, 15).map(m => `- ${m.cveID}: ${m.vulnerabilityName} (${m.vendorProject} ${m.product})${m.knownRansomware ? ' [RANSOMWARE]' : ''}`).join('\n')}`;
      }
      if (ransomwareKevs.length > 0) {
        kevContext += `\n\n🔴 RANSOMWARE EXPOSURE: ${ransomwareKevs.length} KEV entries linked to active ransomware campaigns. Generate hypotheses that detect ransomware precursor activity.`;
      }
      kevContext += `\n\nYou MUST generate at least one hypothesis targeting KEV-listed vulnerabilities. These represent confirmed real-world exploitation vectors.`;
    }
  } catch (e: any) {
    console.error('[KEV] Failed to fetch for hunt hypotheses:', e.message);
  }

  // Build the hypothesis generation prompt
  const prompt = `You are an elite threat hunter operating under CISA methodology (Prepare → Execute → Act).
Your task is to generate ${maxHypotheses} prioritized, testable hypotheses for a threat hunt.

HUNT CONTEXT:
- Organization: ${ctx.orgName} (Sector: ${ctx.orgSector})
- SIEM Platform: ${ctx.siemPlatform}
- Available Data Sources: ${ctx.dataSources.join(", ")}
- Hunt Type: ${ctx.huntType} (PEAK Framework)
- Priority: ${ctx.priority}
${ctx.threatActor ? `
THREAT ACTOR INTELLIGENCE:
- Name: ${ctx.threatActor.name}${ctx.threatActor.aliases?.length ? ` (aliases: ${ctx.threatActor.aliases.join(", ")})` : ""}
- Known TTPs: ${ctx.threatActor.ttps?.join(", ") || "unknown"}
- Target Sectors: ${ctx.threatActor.targetSectors?.join(", ") || "unknown"}
- Known Tools: ${ctx.threatActor.knownTools?.join(", ") || "unknown"}
` : ""}
${ctx.mitreTechniques?.length ? `
FOCUS TECHNIQUES:
${ctx.mitreTechniques.map(t => `- ${t.id}: ${t.name} (${t.tactic})`).join("\n")}
` : ""}
${ctx.scope ? `
SCOPE CONSTRAINTS:
- IP Ranges: ${ctx.scope.ipRanges?.join(", ") || "all"}
- Domains: ${ctx.scope.domains?.join(", ") || "all"}
- Time Window: ${ctx.scope.timeWindow ? `${ctx.scope.timeWindow.start} to ${ctx.scope.timeWindow.end}` : "last 30 days"}
` : ""}
${assetOntologyContext ? `
ASSET INTELLIGENCE (from ontology):
${assetOntologyContext}
` : ""}
${pivotPaths.length > 0 ? `
ARCHITECTURE PIVOT PATHS (how attackers move laterally):
${pivotPaths.slice(0, 5).map((p: any) => `- ${p.name}: ${p.description}`).join("\n")}
` : ""}
${uniqueChains.length > 0 ? `
RELEVANT ATTACK CHAIN EXAMPLES (from training data):
${uniqueChains.map(c => `- [${c.id}] ${c.name}: ${c.steps.map(s => s.technique).join(" → ")} | Severity: ${c.severity}`).join("\n")}
` : ""}
${triageContext ? `
BUG BOUNTY TRIAGE KNOWLEDGE:
${triageContext}
` : ""}
${kevContext}
${(() => {
  // Cloud security awareness for cloud-specific hunt hypotheses
  const techStack = ctx.scope?.domains || [];
  const cloudCtx = buildGeneralCloudContext();
  const cloudPaths = getCloudAttackPaths();
  const cloudRules = matchDetectionRules(['cloud', 'aws', 'azure', 'gcp', 's3', 'blob', 'iam']);
  const cloudPathsStr = cloudPaths.slice(0, 3).map((p: any) => `- ${p.title} (${p.steps?.flatMap((s: any) => s.mitre).join(', ') || 'N/A'}): ${p.steps?.map((s: any) => s.action).join(' → ') || p.initial_condition}`).join('\n');
  const cloudRulesStr = cloudRules.slice(0, 3).map((r: any) => `- ${r.name}: ${r.description} [confidence: ${r.confidence}]`).join('\n');
  // Inject ScanForge-based threat hunting context
  const scanforgeHuntCtx = scanforgeKnowledge.getScanforgeHuntContext();
  const owaspHuntCtx = owaspKnowledge.getOwaspHuntContext();
  // Inject threat group intelligence based on sector
  const threatGroupCtx = getThreatGroupHuntContext({ sector: ctx.orgSector });
  const sectorCtx = getSectorThreatContext(ctx.orgSector);
  return `\nCLOUD SECURITY INTELLIGENCE:\n${cloudCtx}\n${cloudPathsStr ? `\nCloud Attack Paths:\n${cloudPathsStr}` : ''}\n${cloudRulesStr ? `\nCloud Detection Rules:\n${cloudRulesStr}` : ''}\n\n${scanforgeHuntCtx}\n\n${owaspHuntCtx}\n\n${threatGroupCtx}\n${sectorCtx}\n`;
})()}
HYPOTHESIS GENERATION RULES:
1. Each hypothesis MUST be testable with the available data sources
2. Each hypothesis MUST map to a specific MITRE ATT&CK technique
3. Prioritize hypotheses by: threat actor relevance > asset criticality > technique prevalence
4. Include at least one hypothesis per kill chain phase present in the threat actor's TTPs
5. For each hypothesis, specify the exact data source fields needed
6. Generate SIEM queries in the target platform format (${ctx.siemPlatform})
7. Also generate Sigma rules for portability
8. Reference attack chain IDs where applicable for traceability
9. Consider the asset ontology pivot paths for lateral movement hypotheses
10. Flag any data source gaps that would prevent testing a high-priority hypothesis
11. Reference specific threat groups by name when generating hypotheses based on their TTPs
12. Include SIEM queries from the threat group detection recommendations when applicable
13. For sector-specific hunts, prioritize TTPs from the top threat groups targeting that sector

Return JSON:
{
  "hypotheses": [
    {
      "statement": "Hypothesis statement...",
      "mitreTechniqueId": "T1059.001",
      "mitreTechniqueName": "PowerShell",
      "mitreTactic": "execution",
      "requiredDataSources": ["Windows Event Log 4688", "Sysmon Event 1"],
      "sigmaRule": "title: ...\\nstatus: ...\\nlogsource: ...\\ndetection: ...",
      "splQuery": "index=windows sourcetype=WinEventLog:Security EventCode=4688 ...",
      "kqlQuery": "SecurityEvent | where EventID == 4688 ...",
      "confidence": "high|medium|low",
      "priority": 1,
      "reasoning": "Why this hypothesis matters...",
      "attackChainRef": "chain_id or null",
      "bugBountyPatternRef": "pattern_id or null"
    }
  ],
  "dataSourceGaps": ["List of data sources that would improve coverage but are not available"],
  "huntNarrative": "Brief narrative explaining the overall hunt strategy"
}`;

  try {
    const response = await invokeLLM({
      _caller: "hunt-engine",
      messages: [
        { role: "system", content: "You are an expert threat hunter. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
    });

    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) return [];
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);

    const parsed = JSON.parse(content);
    return (parsed.hypotheses || []).map((h: any, i: number) => ({
      statement: h.statement || "",
      mitreTechniqueId: h.mitreTechniqueId || "",
      mitreTechniqueName: h.mitreTechniqueName || "",
      mitreTactic: h.mitreTactic || "",
      requiredDataSources: h.requiredDataSources || [],
      sigmaRule: h.sigmaRule || undefined,
      splQuery: h.splQuery || undefined,
      kqlQuery: h.kqlQuery || undefined,
      confidence: h.confidence || "medium",
      priority: h.priority ?? i + 1,
      reasoning: h.reasoning || "",
      attackChainRef: h.attackChainRef || undefined,
      bugBountyPatternRef: h.bugBountyPatternRef || undefined,
    }));
  } catch (err: any) {
    console.error(`[HuntEngine] Hypothesis generation failed: ${err.message}`);
    return [];
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — EXECUTE PHASE: Evidence Analysis
// ═══════════════════════════════════════════════════════════════════════

/**
 * Analyze evidence collected from SIEM queries against a hypothesis.
 * Returns an evaluation of whether the hypothesis is confirmed, refuted, or inconclusive.
 */
export async function evaluateEvidence(
  hypothesis: HuntHypothesis,
  evidence: {
    queryResults: any[];
    resultCount: number;
    timeRange: string;
    siemPlatform: string;
  },
  ctx: HuntContext
): Promise<{
  status: "confirmed" | "refuted" | "inconclusive";
  confidence: "high" | "medium" | "low";
  analysisNotes: string;
  findings: HuntFinding[];
  suggestedFollowUp: string[];
  detectionRule?: string;
  remediation?: string;
}> {
  // Get relevant attack chains for context
  const chains = getChainsByMitreTechnique(hypothesis.mitreTechniqueId).slice(0, 3);
  const corpusContext = getTriageCorpusContext([hypothesis.mitreTechniqueId]);

  const prompt = `You are analyzing threat hunt evidence to evaluate a hypothesis.

HYPOTHESIS: ${hypothesis.statement}
MITRE TECHNIQUE: ${hypothesis.mitreTechniqueId} - ${hypothesis.mitreTechniqueName} (${hypothesis.mitreTactic})

EVIDENCE COLLECTED:
- SIEM Platform: ${evidence.siemPlatform}
- Time Range: ${evidence.timeRange}
- Result Count: ${evidence.resultCount}
- Sample Results (first 20):
${JSON.stringify(evidence.queryResults.slice(0, 20), null, 2)}

ORGANIZATION CONTEXT:
- ${ctx.orgName} (${ctx.orgSector})
- Available Data Sources: ${ctx.dataSources.join(", ")}

${chains.length > 0 ? `
ATTACK CHAIN REFERENCE:
${chains.map(c => `[${c.id}] ${c.name}: Expected indicators: ${c.steps.filter(s => s.technique === hypothesis.mitreTechniqueId).map(s => s.indicators?.join(", ")).join("; ")}`).join("\n")}
` : ""}
${corpusContext ? `
TOOL OUTPUT TRAINING CONTEXT:
${corpusContext}
` : ""}

EVALUATION CRITERIA:
1. CONFIRMED: Clear evidence of the hypothesized activity with high confidence
2. REFUTED: Evidence actively contradicts the hypothesis (not just absence of evidence)
3. INCONCLUSIVE: Insufficient evidence to confirm or refute; may need additional data sources

For CONFIRMED findings:
- Generate a production-ready detection rule (Sigma format)
- Provide specific remediation steps
- List all affected assets

For INCONCLUSIVE results:
- Suggest specific follow-up queries or data sources that could resolve the ambiguity

Return JSON:
{
  "status": "confirmed|refuted|inconclusive",
  "confidence": "high|medium|low",
  "analysisNotes": "Detailed analysis...",
  "findings": [
    {
      "title": "Finding title",
      "description": "What was found",
      "severity": "critical|high|medium|low|informational",
      "mitreTechniqueId": "${hypothesis.mitreTechniqueId}",
      "mitreTechniqueName": "${hypothesis.mitreTechniqueName}",
      "mitreTactic": "${hypothesis.mitreTactic}",
      "evidence": "Specific evidence summary",
      "affectedAssets": ["hostname1", "hostname2"],
      "detectionRule": "Sigma rule content...",
      "remediation": "Specific steps...",
      "confidence": "high|medium|low"
    }
  ],
  "suggestedFollowUp": ["Follow-up query or action..."],
  "detectionRule": "Production Sigma rule if confirmed...",
  "remediation": "Overall remediation if confirmed..."
}`;

  try {
    const response = await invokeLLM({
      _caller: "hunt-engine",
      messages: [
        { role: "system", content: "You are an expert threat hunt analyst. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
    });

    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) return { status: "inconclusive", confidence: "low", analysisNotes: "LLM returned empty response", findings: [], suggestedFollowUp: [] };
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);

    const parsed = JSON.parse(content);
    return {
      status: parsed.status || "inconclusive",
      confidence: parsed.confidence || "low",
      analysisNotes: parsed.analysisNotes || "",
      findings: (parsed.findings || []).map((f: any) => ({
        title: f.title || "",
        description: f.description || "",
        severity: f.severity || "informational",
        mitreTechniqueId: f.mitreTechniqueId || hypothesis.mitreTechniqueId,
        mitreTechniqueName: f.mitreTechniqueName || hypothesis.mitreTechniqueName,
        mitreTactic: f.mitreTactic || hypothesis.mitreTactic,
        evidence: f.evidence || "",
        affectedAssets: f.affectedAssets || [],
        detectionRule: f.detectionRule || undefined,
        remediation: f.remediation || "",
        confidence: f.confidence || "medium",
      })),
      suggestedFollowUp: parsed.suggestedFollowUp || [],
      detectionRule: parsed.detectionRule || undefined,
      remediation: parsed.remediation || undefined,
    };
  } catch (err: any) {
    console.error(`[HuntEngine] Evidence evaluation failed: ${err.message}`);
    return { status: "inconclusive", confidence: "low", analysisNotes: `Error: ${err.message}`, findings: [], suggestedFollowUp: [] };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — ACT PHASE: Deliverable Generation
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate the final hunt deliverable (GSA HACS-compliant report).
 */
export async function generateDeliverable(
  ctx: HuntContext,
  hypotheses: Array<HuntHypothesis & { status: string; analysisNotes?: string }>,
  findings: HuntFinding[]
): Promise<HuntDeliverable> {
  const confirmed = hypotheses.filter(h => h.status === "confirmed");
  const refuted = hypotheses.filter(h => h.status === "refuted");
  const inconclusive = hypotheses.filter(h => h.status === "inconclusive");

  const prompt = `Generate a GSA HACS-compliant threat hunt deliverable report.

HUNT SUMMARY:
- Organization: ${ctx.orgName} (${ctx.orgSector})
- SIEM Platform: ${ctx.siemPlatform}
- Hunt Type: ${ctx.huntType}
- Priority: ${ctx.priority}
${ctx.threatActor ? `- Threat Actor: ${ctx.threatActor.name}` : ""}

RESULTS:
- Hypotheses Tested: ${hypotheses.length}
- Confirmed: ${confirmed.length}
- Refuted: ${refuted.length}
- Inconclusive: ${inconclusive.length}
- Total Findings: ${findings.length}

CONFIRMED HYPOTHESES:
${confirmed.map(h => `- ${h.statement} (${h.mitreTechniqueId}): ${h.analysisNotes || "confirmed"}`).join("\n") || "None"}

FINDINGS:
${findings.map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description} | Assets: ${f.affectedAssets.join(", ")}`).join("\n") || "None"}

INCONCLUSIVE HYPOTHESES (data gaps):
${inconclusive.map(h => `- ${h.statement}: Missing data sources: ${h.requiredDataSources.join(", ")}`).join("\n") || "None"}

GSA HACS DELIVERABLE REQUIREMENTS:
1. Executive Summary (non-technical, suitable for CISO/executive briefing)
2. Findings with severity ratings and MITRE ATT&CK mappings
3. Detection rules for each confirmed finding (Sigma format)
4. Remediation recommendations prioritized by risk
5. Data source gap analysis with improvement recommendations
6. HACS compliance notes (methodology alignment, evidence preservation)

Return JSON:
{
  "executiveSummary": "...",
  "recommendations": ["Prioritized list..."],
  "dataSourceGaps": ["Gaps identified..."],
  "hacsComplianceNotes": ["Methodology notes..."]
}`;

  try {
    const response = await invokeLLM({
      _caller: "hunt-engine",
      messages: [
        { role: "system", content: "You are a senior threat hunt lead writing a GSA HACS-compliant deliverable. Return only valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
    });

    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) throw new Error("Empty LLM response");
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    const parsed = JSON.parse(content);

    // Collect detection rules from confirmed findings
    const detectionRules = findings
      .filter(f => f.detectionRule)
      .map(f => ({
        name: `Hunt Finding: ${f.title}`,
        format: "sigma" as const,
        content: f.detectionRule!,
        mitreTechniqueId: f.mitreTechniqueId,
      }));

    return {
      executiveSummary: parsed.executiveSummary || "",
      hypothesesTested: hypotheses.length,
      hypothesesConfirmed: confirmed.length,
      hypothesesRefuted: refuted.length,
      hypothesesInconclusive: inconclusive.length,
      findings,
      detectionRules,
      recommendations: parsed.recommendations || [],
      dataSourceGaps: parsed.dataSourceGaps || [],
      hacsComplianceNotes: parsed.hacsComplianceNotes || [],
    };
  } catch (err: any) {
    console.error(`[HuntEngine] Deliverable generation failed: ${err.message}`);
    return {
      executiveSummary: `Hunt completed with ${findings.length} findings. Deliverable generation encountered an error.`,
      hypothesesTested: hypotheses.length,
      hypothesesConfirmed: confirmed.length,
      hypothesesRefuted: refuted.length,
      hypothesesInconclusive: inconclusive.length,
      findings,
      detectionRules: [],
      recommendations: ["Review findings manually and generate detection rules"],
      dataSourceGaps: [],
      hacsComplianceNotes: ["Automated deliverable generation failed — manual review required"],
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — SIEM QUERY BUILDERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate SIEM-specific queries from a Sigma rule.
 */
export async function translateSigmaToSiem(
  sigmaRule: string,
  targetPlatform: "splunk" | "elastic" | "sentinel" | "qradar" | "chronicle"
): Promise<string> {
  const platformNames: Record<string, string> = {
    splunk: "Splunk SPL",
    elastic: "Elasticsearch Query DSL / KQL",
    sentinel: "Microsoft Sentinel KQL",
    qradar: "QRadar AQL",
    chronicle: "Google Chronicle YARA-L",
  };

  try {
    const response = await invokeLLM({
      _caller: "hunt-engine.translateSigmaToSiem",
      messages: [
        {
          role: "system",
          content: `You are a SIEM detection engineer. Convert the given Sigma rule to ${platformNames[targetPlatform]} format. Return ONLY the query, no explanations.`,
        },
        {
          role: "user",
          content: `Convert this Sigma rule to ${platformNames[targetPlatform]}:\n\n${sigmaRule}`,
        },
      ],
    });

    return response.choices?.[0]?.message?.content?.toString().trim() || "";
  } catch {
    return `/* Translation failed for ${targetPlatform} — use Sigma rule directly */`;
  }
}

/**
 * Generate a baseline query for anomaly detection on a specific data source.
 */
export async function generateBaselineQuery(
  dataSource: string,
  siemPlatform: string,
  timeWindow: string = "7d"
): Promise<{ query: string; description: string }> {
  try {
    const response = await invokeLLM({
      _caller: "hunt-engine.generateBaselineQuery",
      messages: [
        {
          role: "system",
          content: `You are a SIEM analyst. Generate a baseline statistical query for ${siemPlatform} that establishes normal behavior patterns for the given data source over ${timeWindow}. Return JSON: { "query": "...", "description": "..." }`,
        },
        {
          role: "user",
          content: `Generate a baseline query for: ${dataSource}`,
        },
      ],
      response_format: { type: "json_object" },
    });

    const content = response.choices?.[0]?.message?.content?.toString() || "{}";
    const parsed = JSON.parse(content);
    return { query: parsed.query || "", description: parsed.description || "" };
  } catch {
    return { query: "", description: "Baseline generation failed" };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — NICE FRAMEWORK KSA ALIGNMENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * NICE Framework KSAs that the hunt engine exercises.
 * Used for compliance reporting and capability gap analysis.
 */
export const NICE_KSAS = {
  /** PR-CDA-001: Cyber Defense Analysis */
  cyberDefenseAnalysis: {
    workRoleId: "PR-CDA-001",
    knowledge: [
      "K0001: Knowledge of computer networking concepts and protocols",
      "K0004: Knowledge of cybersecurity and privacy principles",
      "K0005: Knowledge of cyber threats and vulnerabilities",
      "K0007: Knowledge of authentication, authorization, and access control methods",
      "K0013: Knowledge of cyber defense and vulnerability assessment tools",
      "K0015: Knowledge of computer algorithms",
      "K0018: Knowledge of encryption algorithms",
      "K0019: Knowledge of cryptography and cryptographic key management concepts",
      "K0024: Knowledge of database systems",
      "K0033: Knowledge of host/network access control mechanisms",
      "K0046: Knowledge of intrusion detection methodologies and techniques",
      "K0049: Knowledge of IT security principles and methods",
      "K0058: Knowledge of network traffic analysis methods",
      "K0061: Knowledge of how traffic flows across the network",
      "K0104: Knowledge of Virtual Private Network (VPN) security",
      "K0106: Knowledge of what constitutes a network attack",
      "K0161: Knowledge of different classes of attacks",
      "K0162: Knowledge of cyber attackers",
      "K0177: Knowledge of cyber attack stages",
      "K0180: Knowledge of network protocols such as TCP/IP, DHCP, DNS, and directory services",
      "K0190: Knowledge of encryption methodologies",
      "K0297: Knowledge of countermeasure design for identified security risks",
      "K0300: Knowledge of network mapping and recreating network topologies",
      "K0301: Knowledge of packet-level analysis using appropriate tools",
      "K0318: Knowledge of operating system command-line tools",
      "K0332: Knowledge of network protocols such as TCP/IP, DHCP, DNS",
      "K0339: Knowledge of how to use network analysis tools to identify vulnerabilities",
    ],
    skills: [
      "S0020: Skill in developing and deploying signatures",
      "S0025: Skill in detecting host and network based intrusions via intrusion detection technologies",
      "S0027: Skill in determining how a security system should work",
      "S0036: Skill in evaluating the adequacy of security designs",
      "S0054: Skill in using incident handling methodologies",
      "S0057: Skill in using protocol analyzers",
      "S0063: Skill in collecting data from a variety of cyber defense resources",
      "S0078: Skill in recognizing and categorizing types of vulnerabilities and associated attacks",
      "S0096: Skill in reading and interpreting signatures",
      "S0147: Skill in assessing security controls based on cybersecurity principles",
      "S0167: Skill in recognizing vulnerabilities in security systems",
      "S0169: Skill in conducting trend analysis",
    ],
    abilities: [
      "A0015: Ability to conduct vulnerability scans and recognize vulnerabilities in security systems",
      "A0066: Ability to accurately and completely source all data used in intelligence, assessment and/or planning products",
      "A0123: Ability to apply cybersecurity and privacy principles to organizational requirements",
    ],
  },
  /** AN-TWA-001: Threat Analysis */
  threatAnalysis: {
    workRoleId: "AN-TWA-001",
    knowledge: [
      "K0001: Knowledge of computer networking concepts",
      "K0004: Knowledge of cybersecurity principles",
      "K0005: Knowledge of cyber threats and vulnerabilities",
      "K0108: Knowledge of concepts, terminology, and operations of a wide range of communications media",
      "K0109: Knowledge of physical computer components and architectures",
      "K0177: Knowledge of cyber attack stages",
      "K0349: Knowledge of website types, administration, functions, and content management system (CMS)",
      "K0362: Knowledge of attack methods and techniques",
      "K0392: Knowledge of common computer/network infections and methods of infection",
      "K0395: Knowledge of computer networking fundamentals",
      "K0409: Knowledge of cyber intelligence/information collection capabilities and repositories",
      "K0427: Knowledge of encryption algorithms and cyber capabilities/tools",
      "K0431: Knowledge of evolving/emerging communications technologies",
      "K0436: Knowledge of fundamental cyber operations concepts",
      "K0444: Knowledge of how Internet applications work",
      "K0471: Knowledge of Internet network addressing",
    ],
    skills: [
      "S0194: Skill in determining the effect of intelligence activities on the overall organization",
      "S0196: Skill in identifying critical target elements",
      "S0203: Skill in identifying intelligence gaps",
      "S0211: Skill in interpreting vulnerability scanner results",
      "S0218: Skill in evaluating information for reliability, validity, and relevance",
      "S0229: Skill in identifying cyber threats which may jeopardize organization and/or partner interests",
    ],
    abilities: [
      "A0013: Ability to communicate complex information, concepts, or ideas in a confident and well-organized manner",
      "A0066: Ability to accurately and completely source all data used in intelligence products",
      "A0080: Ability to use and understand complex mathematical concepts",
      "A0084: Ability to evaluate, analyze, and synthesize large quantities of data",
      "A0085: Ability to exercise judgment when policies are not well-defined",
      "A0088: Ability to understand the empty battlespace and determine key terrain, key## geography, and key key factors",
      "A0089: Ability to function in a collaborative environment",
      "A0091: Ability to identify intelligence gaps",
      "A0101: Ability to recognize and mitigate cognitive biases",
      "A0106: Ability to think critically",
    ],
  },
};

/**
 * Map hunt activities to NICE Framework KSAs for compliance reporting.
 */
export function mapHuntToNiceKsas(
  activitiesPerformed: string[]
): { exercisedKnowledge: string[]; exercisedSkills: string[]; exercisedAbilities: string[] } {
  const kMap: Record<string, string[]> = {
    "hypothesis_generation": ["K0005", "K0161", "K0162", "K0177", "K0362"],
    "siem_query_creation": ["K0058", "K0061", "K0301", "K0332", "S0020", "S0057"],
    "evidence_analysis": ["K0046", "K0106", "K0339", "S0025", "S0063", "S0078", "S0096", "S0169"],
    "detection_rule_creation": ["K0013", "K0049", "S0020", "S0025", "S0036"],
    "threat_actor_profiling": ["K0162", "K0177", "K0409", "S0196", "S0229"],
    "vulnerability_assessment": ["K0005", "K0013", "S0078", "S0167", "A0015"],
    "network_analysis": ["K0001", "K0058", "K0061", "K0180", "K0300", "S0057"],
    "incident_response": ["S0054", "S0063", "A0123"],
    "report_generation": ["A0013", "A0066", "A0084", "A0106"],
  };

  const allKsas = new Set<string>();
  for (const activity of activitiesPerformed) {
    const mapped = kMap[activity] || [];
    mapped.forEach(k => allKsas.add(k));
  }

  const allKsasList = Array.from(allKsas);
  const allCdaKsas = [
    ...NICE_KSAS.cyberDefenseAnalysis.knowledge,
    ...NICE_KSAS.cyberDefenseAnalysis.skills,
    ...NICE_KSAS.cyberDefenseAnalysis.abilities,
    ...NICE_KSAS.threatAnalysis.knowledge,
    ...NICE_KSAS.threatAnalysis.skills,
    ...NICE_KSAS.threatAnalysis.abilities,
  ];

  const exercisedKnowledge: string[] = [];
  const exercisedSkills: string[] = [];
  const exercisedAbilities: string[] = [];

  for (const ksa of allKsasList) {
    const match = allCdaKsas.find(k => k.startsWith(ksa));
    if (match) {
      if (ksa.startsWith("K")) exercisedKnowledge.push(match);
      else if (ksa.startsWith("S")) exercisedSkills.push(match);
      else if (ksa.startsWith("A")) exercisedAbilities.push(match);
    }
  }

  return { exercisedKnowledge, exercisedSkills, exercisedAbilities };
}
