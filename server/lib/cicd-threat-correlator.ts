/**
 * CI/CD Threat Intelligence Correlator
 *
 * Deterministic (non-LLM) engine that enriches CI/CD scan findings with
 * threat actor intelligence from the master threat group catalog.
 *
 * Three integration points:
 *
 * 1. **Pre-scan (Template Selection):**
 *    Use sector threat profiles to select Nuclei templates targeting CVEs
 *    that real adversaries exploit, rather than scanning generically.
 *
 * 2. **Post-scan (Finding Enrichment):**
 *    Correlate every CVE finding with getGroupsByCVE() to answer
 *    "who is exploiting this?" and apply severity boosting rules.
 *
 * 3. **Analytics (Exposure Scoring):**
 *    Compute Threat Actor Exposure Scores and Kill Chain Coverage Maps
 *    for the CI/CD dashboard.
 *
 * Sources: threat-group-knowledge.ts master catalog (401+ groups)
 */

import {
  getAllGroups,
  getGroupsByCVE,
  getGroupsByTechnique,
  getGroupsBySector,
  getSectorProfiles,
  initThreatGroups,
  type ThreatGroupKnowledge,
  type SectorThreatProfile,
} from "./threat-group-knowledge";

import type { CicdFinding } from "./aws-cicd-connector";

// ─── Output Types ──────────────────────────────────────────────────────────

export interface ThreatEnrichedFinding extends CicdFinding {
  /** Threat groups known to exploit this CVE */
  attributedGroups: AttributedGroup[];
  /** Original severity before boosting */
  originalSeverity: CicdFinding["severity"];
  /** Whether severity was boosted by threat intel */
  severityBoosted: boolean;
  /** Reason for severity boost */
  boostReason?: string;
  /** Risk tags derived from threat intel */
  riskTags: string[];
  /** Kill chain phases this finding maps to */
  killChainPhases: string[];
}

export interface AttributedGroup {
  groupId: string;
  groupName: string;
  groupType: string;
  threatLevel: string;
  origin: string;
  active: boolean;
  /** How this group relates to the finding */
  matchType: "cve_exploit" | "cwe_pattern" | "technique_overlap" | "tool_signature";
}

export interface CicdThreatContext {
  /** Summary statistics */
  summary: {
    totalFindings: number;
    enrichedFindings: number;
    severityBoostedCount: number;
    uniqueActorsMatched: number;
    actorExposureScore: number;       // 0-100
    killChainCoverage: number;        // 0-100 (% of kill chain phases covered)
    ransomwareRiskFindings: number;
    aptRiskFindings: number;
  };
  /** Per-finding enrichment */
  enrichedFindings: ThreatEnrichedFinding[];
  /** Aggregated actor exposure */
  actorExposure: ActorExposureEntry[];
  /** Kill chain coverage map */
  killChainMap: KillChainEntry[];
  /** Sector-specific threat profile used */
  sectorProfile?: {
    sector: string;
    topGroups: string[];
    commonTTPs: string[];
    priorityDefenses: string[];
  };
  /** Pre-scan template recommendations (for next run) */
  templateRecommendations: TemplateRecommendation[];
}

export interface ActorExposureEntry {
  groupId: string;
  groupName: string;
  groupType: string;
  threatLevel: string;
  origin: string;
  active: boolean;
  /** Number of findings that map to this actor */
  findingCount: number;
  /** CVEs from findings that this actor exploits */
  matchedCVEs: string[];
  /** CWEs from findings that align with this actor's TTPs */
  matchedCWEs: string[];
  /** Composite exposure score for this actor (0-100) */
  exposureScore: number;
}

export interface KillChainEntry {
  phase: string;
  /** MITRE ATT&CK tactic ID */
  tacticId: string;
  /** Number of findings mapping to this phase */
  findingCount: number;
  /** Threat groups active in this phase */
  activeGroups: string[];
  /** Whether any finding in this phase was severity-boosted */
  hasBoostedFindings: boolean;
}

export interface TemplateRecommendation {
  /** Nuclei template tag or CVE ID */
  templateId: string;
  /** Why this template is recommended */
  reason: string;
  /** Which threat groups exploit this */
  attributedGroups: string[];
  /** Priority: critical > high > medium */
  priority: "critical" | "high" | "medium";
}

// ─── CWE-to-MITRE Tactic Mapping ──────────────────────────────────────────

const CWE_TO_TACTIC: Record<string, { tactic: string; tacticId: string; techniques: string[] }> = {
  "CWE-79":  { tactic: "Initial Access",        tacticId: "TA0001", techniques: ["T1189", "T1566.002"] },
  "CWE-89":  { tactic: "Initial Access",        tacticId: "TA0001", techniques: ["T1190"] },
  "CWE-94":  { tactic: "Execution",             tacticId: "TA0002", techniques: ["T1059"] },
  "CWE-78":  { tactic: "Execution",             tacticId: "TA0002", techniques: ["T1059.004"] },
  "CWE-22":  { tactic: "Collection",            tacticId: "TA0009", techniques: ["T1005"] },
  "CWE-200": { tactic: "Discovery",             tacticId: "TA0007", techniques: ["T1082"] },
  "CWE-287": { tactic: "Credential Access",     tacticId: "TA0006", techniques: ["T1110"] },
  "CWE-306": { tactic: "Initial Access",        tacticId: "TA0001", techniques: ["T1190"] },
  "CWE-352": { tactic: "Initial Access",        tacticId: "TA0001", techniques: ["T1189"] },
  "CWE-434": { tactic: "Persistence",           tacticId: "TA0003", techniques: ["T1505.003"] },
  "CWE-502": { tactic: "Execution",             tacticId: "TA0002", techniques: ["T1203"] },
  "CWE-611": { tactic: "Collection",            tacticId: "TA0009", techniques: ["T1005"] },
  "CWE-614": { tactic: "Credential Access",     tacticId: "TA0006", techniques: ["T1539"] },
  "CWE-798": { tactic: "Credential Access",     tacticId: "TA0006", techniques: ["T1552.001"] },
  "CWE-918": { tactic: "Discovery",             tacticId: "TA0007", techniques: ["T1046"] },
  "CWE-1021":{ tactic: "Initial Access",        tacticId: "TA0001", techniques: ["T1189"] },
  "CWE-16":  { tactic: "Defense Evasion",       tacticId: "TA0005", techniques: ["T1562"] },
  "CWE-295": { tactic: "Credential Access",     tacticId: "TA0006", techniques: ["T1557"] },
  "CWE-319": { tactic: "Credential Access",     tacticId: "TA0006", techniques: ["T1040"] },
  "CWE-269": { tactic: "Privilege Escalation",  tacticId: "TA0004", techniques: ["T1068"] },
  "CWE-732": { tactic: "Privilege Escalation",  tacticId: "TA0004", techniques: ["T1068"] },
  "CWE-862": { tactic: "Privilege Escalation",  tacticId: "TA0004", techniques: ["T1068"] },
};

// All MITRE ATT&CK kill chain phases for coverage calculation
const ALL_KILL_CHAIN_PHASES = [
  { phase: "Reconnaissance",       tacticId: "TA0043" },
  { phase: "Resource Development",  tacticId: "TA0042" },
  { phase: "Initial Access",       tacticId: "TA0001" },
  { phase: "Execution",            tacticId: "TA0002" },
  { phase: "Persistence",          tacticId: "TA0003" },
  { phase: "Privilege Escalation", tacticId: "TA0004" },
  { phase: "Defense Evasion",      tacticId: "TA0005" },
  { phase: "Credential Access",    tacticId: "TA0006" },
  { phase: "Discovery",            tacticId: "TA0007" },
  { phase: "Lateral Movement",     tacticId: "TA0008" },
  { phase: "Collection",           tacticId: "TA0009" },
  { phase: "Command and Control",  tacticId: "TA0011" },
  { phase: "Exfiltration",         tacticId: "TA0010" },
  { phase: "Impact",               tacticId: "TA0040" },
];

// ─── Severity Boosting Rules ───────────────────────────────────────────────

type Severity = CicdFinding["severity"];

const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const SEVERITY_NAMES: Severity[] = ["info", "low", "medium", "high", "critical"];

function boostSeverity(current: Severity, levels: number): Severity {
  const idx = SEVERITY_ORDER[current];
  const newIdx = Math.min(idx + levels, 4);
  return SEVERITY_NAMES[newIdx];
}

// ─── Core Correlation Engine ───────────────────────────────────────────────

/**
 * Extract CVE IDs from a finding's title, description, or cweId fields.
 */
function extractCVEs(finding: CicdFinding): string[] {
  const cvePattern = /CVE-\d{4}-\d{4,}/gi;
  const sources = [finding.title, finding.description, finding.cweId || ""].join(" ");
  const matches = sources.match(cvePattern) || [];
  return [...new Set(matches.map(m => m.toUpperCase()))];
}

/**
 * Extract CWE ID from a finding (normalize to "CWE-XXX" format).
 */
function extractCWE(finding: CicdFinding): string | null {
  if (!finding.cweId) return null;
  const match = finding.cweId.match(/CWE-(\d+)/i);
  return match ? `CWE-${match[1]}` : null;
}

/**
 * Enrich a single CI/CD finding with threat intelligence.
 */
function enrichFinding(finding: CicdFinding): ThreatEnrichedFinding {
  const attributedGroups: AttributedGroup[] = [];
  const riskTags: string[] = [];
  const killChainPhases: string[] = [];
  let severityBoosted = false;
  let boostReason: string | undefined;
  let boostedSeverity = finding.severity;
  const originalSeverity = finding.severity;

  // 1. CVE-to-Actor Mapping
  const cves = extractCVEs(finding);
  for (const cve of cves) {
    const groups = getGroupsByCVE(cve);
    for (const g of groups) {
      if (!attributedGroups.find(a => a.groupId === g.id)) {
        attributedGroups.push({
          groupId: g.id,
          groupName: g.name,
          groupType: g.type,
          threatLevel: g.threatLevel,
          origin: g.origin,
          active: g.active,
          matchType: "cve_exploit",
        });
      }
    }
  }

  // 2. CWE-to-Technique Mapping
  const cwe = extractCWE(finding);
  if (cwe && CWE_TO_TACTIC[cwe]) {
    const mapping = CWE_TO_TACTIC[cwe];
    killChainPhases.push(mapping.tactic);

    // Find groups that use these techniques
    for (const techId of mapping.techniques) {
      const groups = getGroupsByTechnique(techId);
      for (const g of groups) {
        if (!attributedGroups.find(a => a.groupId === g.id)) {
          attributedGroups.push({
            groupId: g.id,
            groupName: g.name,
            groupType: g.type,
            threatLevel: g.threatLevel,
            origin: g.origin,
            active: g.active,
            matchType: "technique_overlap",
          });
        }
      }
    }
  }

  // 3. Severity Boosting Rules
  if (attributedGroups.length > 0) {
    // Rule A: CVE exploited by CRITICAL threat group → boost to CRITICAL
    const criticalActors = attributedGroups.filter(
      a => a.threatLevel === "critical" && a.matchType === "cve_exploit"
    );
    if (criticalActors.length > 0 && SEVERITY_ORDER[boostedSeverity] < SEVERITY_ORDER["critical"]) {
      boostedSeverity = "critical";
      severityBoosted = true;
      boostReason = `Exploited by critical threat group: ${criticalActors.map(a => a.groupName).join(", ")}`;
    }

    // Rule B: CVE exploited by multiple groups → boost by one level
    const cveExploiters = attributedGroups.filter(a => a.matchType === "cve_exploit");
    if (!severityBoosted && cveExploiters.length >= 2) {
      boostedSeverity = boostSeverity(boostedSeverity, 1);
      severityBoosted = boostedSeverity !== originalSeverity;
      if (severityBoosted) {
        boostReason = `Exploited by ${cveExploiters.length} threat groups: ${cveExploiters.map(a => a.groupName).join(", ")}`;
      }
    }

    // Rule C: Ransomware group's initial access method → flag RANSOMWARE RISK
    const ransomwareActors = attributedGroups.filter(a => a.groupType === "ransomware");
    if (ransomwareActors.length > 0) {
      riskTags.push("RANSOMWARE_RISK");
      if (!severityBoosted && SEVERITY_ORDER[boostedSeverity] < SEVERITY_ORDER["high"]) {
        boostedSeverity = boostSeverity(boostedSeverity, 1);
        severityBoosted = boostedSeverity !== originalSeverity;
        if (severityBoosted) {
          boostReason = `Ransomware attack vector: ${ransomwareActors.map(a => a.groupName).join(", ")}`;
        }
      }
    }

    // Rule D: APT group's persistence technique → flag APT RISK
    const aptActors = attributedGroups.filter(a => a.groupType === "apt");
    if (aptActors.length > 0) {
      riskTags.push("APT_RISK");
    }

    // Rule E: Active group → flag ACTIVE_EXPLOITATION
    const activeActors = attributedGroups.filter(a => a.active);
    if (activeActors.length > 0) {
      riskTags.push("ACTIVE_EXPLOITATION");
    }
  }

  return {
    ...finding,
    severity: boostedSeverity,
    originalSeverity,
    attributedGroups,
    severityBoosted,
    boostReason,
    riskTags,
    killChainPhases,
  };
}

// ─── Aggregate Analytics ───────────────────────────────────────────────────

/**
 * Build actor exposure table from enriched findings.
 */
function buildActorExposure(enrichedFindings: ThreatEnrichedFinding[]): ActorExposureEntry[] {
  const actorMap = new Map<string, {
    group: AttributedGroup;
    findings: Set<number>;
    cves: Set<string>;
    cwes: Set<string>;
  }>();

  enrichedFindings.forEach((f, idx) => {
    for (const ag of f.attributedGroups) {
      if (!actorMap.has(ag.groupId)) {
        actorMap.set(ag.groupId, {
          group: ag,
          findings: new Set(),
          cves: new Set(),
          cwes: new Set(),
        });
      }
      const entry = actorMap.get(ag.groupId)!;
      entry.findings.add(idx);
      extractCVEs(f).forEach(c => entry.cves.add(c));
      const cwe = extractCWE(f);
      if (cwe) entry.cwes.add(cwe);
    }
  });

  const entries: ActorExposureEntry[] = [];
  for (const [, data] of actorMap) {
    // Exposure score: weighted by finding count, CVE matches, and threat level
    const threatMultiplier = data.group.threatLevel === "critical" ? 1.5
      : data.group.threatLevel === "high" ? 1.2
      : data.group.threatLevel === "medium" ? 1.0
      : 0.7;
    const activeMultiplier = data.group.active ? 1.3 : 1.0;
    const rawScore = (data.findings.size * 10 + data.cves.size * 15) * threatMultiplier * activeMultiplier;
    const exposureScore = Math.min(100, Math.round(rawScore));

    entries.push({
      groupId: data.group.groupId,
      groupName: data.group.groupName,
      groupType: data.group.groupType,
      threatLevel: data.group.threatLevel,
      origin: data.group.origin,
      active: data.group.active,
      findingCount: data.findings.size,
      matchedCVEs: [...data.cves],
      matchedCWEs: [...data.cwes],
      exposureScore,
    });
  }

  return entries.sort((a, b) => b.exposureScore - a.exposureScore);
}

/**
 * Build kill chain coverage map from enriched findings.
 */
function buildKillChainMap(enrichedFindings: ThreatEnrichedFinding[]): KillChainEntry[] {
  const phaseMap = new Map<string, {
    tacticId: string;
    findings: number;
    groups: Set<string>;
    hasBoosted: boolean;
  }>();

  // Initialize all phases
  for (const phase of ALL_KILL_CHAIN_PHASES) {
    phaseMap.set(phase.phase, {
      tacticId: phase.tacticId,
      findings: 0,
      groups: new Set(),
      hasBoosted: false,
    });
  }

  for (const f of enrichedFindings) {
    for (const phase of f.killChainPhases) {
      const entry = phaseMap.get(phase);
      if (entry) {
        entry.findings++;
        if (f.severityBoosted) entry.hasBoosted = true;
        for (const ag of f.attributedGroups) {
          entry.groups.add(ag.groupName);
        }
      }
    }
  }

  return ALL_KILL_CHAIN_PHASES.map(p => {
    const entry = phaseMap.get(p.phase)!;
    return {
      phase: p.phase,
      tacticId: p.tacticId,
      findingCount: entry.findings,
      activeGroups: [...entry.groups],
      hasBoostedFindings: entry.hasBoosted,
    };
  });
}

/**
 * Generate template recommendations for next scan based on sector threat profile.
 */
function buildTemplateRecommendations(
  sector?: string,
  existingFindings?: ThreatEnrichedFinding[]
): TemplateRecommendation[] {
  const recommendations: TemplateRecommendation[] = [];
  const allGroups = getAllGroups();

  // Get sector-relevant groups
  let relevantGroups: ThreatGroupKnowledge[];
  if (sector) {
    relevantGroups = getGroupsBySector(sector);
    if (relevantGroups.length === 0) {
      relevantGroups = allGroups.filter(g => g.active && g.threatLevel === "critical").slice(0, 10);
    }
  } else {
    relevantGroups = allGroups.filter(g => g.active && g.threatLevel === "critical").slice(0, 10);
  }

  // Collect CVEs from relevant groups that weren't already found
  const alreadyFoundCVEs = new Set<string>();
  if (existingFindings) {
    for (const f of existingFindings) {
      extractCVEs(f).forEach(c => alreadyFoundCVEs.add(c));
    }
  }

  const cveToGroups = new Map<string, string[]>();
  for (const g of relevantGroups) {
    for (const cve of g.exploitedCVEs) {
      if (!alreadyFoundCVEs.has(cve)) {
        if (!cveToGroups.has(cve)) cveToGroups.set(cve, []);
        cveToGroups.get(cve)!.push(g.name);
      }
    }
  }

  // Sort by number of groups exploiting (more groups = higher priority)
  const sortedCVEs = [...cveToGroups.entries()].sort((a, b) => b[1].length - a[1].length);

  for (const [cve, groups] of sortedCVEs.slice(0, 20)) {
    const priority = groups.length >= 3 ? "critical" : groups.length >= 2 ? "high" : "medium";
    recommendations.push({
      templateId: cve,
      reason: `Exploited by ${groups.length} active threat group(s) targeting ${sector || "your sector"}`,
      attributedGroups: groups,
      priority,
    });
  }

  return recommendations;
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Correlate CI/CD scan findings with threat intelligence.
 * This is the main entry point called from executeCicdScan post-processing.
 *
 * @param findings - Raw CI/CD scan findings
 * @param sector - Optional sector context for targeted threat profiling
 * @returns Full threat context object to store in cicd_threat_context column
 */
export async function correlateCicdFindings(
  findings: CicdFinding[],
  sector?: string
): Promise<CicdThreatContext> {
  // Ensure threat groups are loaded
  await initThreatGroups();

  // Enrich each finding
  const enrichedFindings = findings.map(f => enrichFinding(f));

  // Build aggregated analytics
  const actorExposure = buildActorExposure(enrichedFindings);
  const killChainMap = buildKillChainMap(enrichedFindings);
  const templateRecommendations = buildTemplateRecommendations(sector, enrichedFindings);

  // Get sector profile if available
  let sectorProfile: CicdThreatContext["sectorProfile"];
  if (sector) {
    const profiles = getSectorProfiles();
    const match = profiles.find(p => p.sector === sector);
    if (match) {
      sectorProfile = {
        sector: match.sector,
        topGroups: match.topGroups,
        commonTTPs: match.commonTTPs,
        priorityDefenses: match.priorityDefenses,
      };
    }
  }

  // Compute summary statistics
  const enrichedCount = enrichedFindings.filter(f => f.attributedGroups.length > 0).length;
  const boostedCount = enrichedFindings.filter(f => f.severityBoosted).length;
  const uniqueActors = new Set(enrichedFindings.flatMap(f => f.attributedGroups.map(a => a.groupId)));
  const coveredPhases = killChainMap.filter(k => k.findingCount > 0).length;
  const killChainCoverage = Math.round((coveredPhases / ALL_KILL_CHAIN_PHASES.length) * 100);

  // Actor exposure score: average of top 5 actor exposure scores
  const topActors = actorExposure.slice(0, 5);
  const actorExposureScore = topActors.length > 0
    ? Math.round(topActors.reduce((sum, a) => sum + a.exposureScore, 0) / topActors.length)
    : 0;

  return {
    summary: {
      totalFindings: findings.length,
      enrichedFindings: enrichedCount,
      severityBoostedCount: boostedCount,
      uniqueActorsMatched: uniqueActors.size,
      actorExposureScore,
      killChainCoverage,
      ransomwareRiskFindings: enrichedFindings.filter(f => f.riskTags.includes("RANSOMWARE_RISK")).length,
      aptRiskFindings: enrichedFindings.filter(f => f.riskTags.includes("APT_RISK")).length,
    },
    enrichedFindings,
    actorExposure,
    killChainMap,
    sectorProfile,
    templateRecommendations,
  };
}

/**
 * Get pre-scan Nuclei template tags based on sector threat profile.
 * Call this before executeCicdScan to get targeted template selection.
 *
 * @param sector - Industry sector (e.g., "financial", "healthcare", "government")
 * @returns Array of CVE IDs and template tags to prioritize
 */
export async function getPreScanTemplates(sector?: string): Promise<{
  priorityCVEs: string[];
  templateTags: string[];
  targetedGroups: string[];
}> {
  await initThreatGroups();

  const allGroups = getAllGroups();
  let relevantGroups: ThreatGroupKnowledge[];

  if (sector) {
    relevantGroups = getGroupsBySector(sector);
    if (relevantGroups.length === 0) {
      relevantGroups = allGroups.filter(g => g.active && g.threatLevel === "critical").slice(0, 10);
    }
  } else {
    relevantGroups = allGroups.filter(g => g.active && g.threatLevel === "critical").slice(0, 10);
  }

  const priorityCVEs = new Set<string>();
  const templateTags = new Set<string>();
  const targetedGroups: string[] = [];

  for (const g of relevantGroups) {
    targetedGroups.push(g.name);
    g.exploitedCVEs.forEach(c => priorityCVEs.add(c));

    // Map initial access methods to Nuclei template tags
    for (const method of g.initialAccessMethods) {
      const lower = method.toLowerCase();
      if (lower.includes("phishing")) templateTags.add("phishing");
      if (lower.includes("exploit") || lower.includes("vulnerability")) templateTags.add("cves");
      if (lower.includes("brute") || lower.includes("credential")) templateTags.add("default-logins");
      if (lower.includes("supply chain")) templateTags.add("misconfiguration");
      if (lower.includes("web")) templateTags.add("vulnerabilities");
      if (lower.includes("rce") || lower.includes("remote code")) templateTags.add("rce");
      if (lower.includes("injection")) templateTags.add("sqli");
      if (lower.includes("ssrf")) templateTags.add("ssrf");
    }
  }

  return {
    priorityCVEs: [...priorityCVEs],
    templateTags: [...templateTags],
    targetedGroups,
  };
}

/**
 * Compute a quick threat exposure score for a set of findings
 * without full enrichment. Used for dashboard summary cards.
 */
export async function quickThreatScore(findings: CicdFinding[]): Promise<{
  score: number;
  actorCount: number;
  hasRansomwareRisk: boolean;
  hasAptRisk: boolean;
  topActor: string | null;
}> {
  await initThreatGroups();

  const actorSet = new Set<string>();
  let hasRansomwareRisk = false;
  let hasAptRisk = false;
  let topActorScore = 0;
  let topActor: string | null = null;

  for (const f of findings) {
    const cves = extractCVEs(f);
    for (const cve of cves) {
      const groups = getGroupsByCVE(cve);
      for (const g of groups) {
        actorSet.add(g.id);
        if (g.type === "ransomware") hasRansomwareRisk = true;
        if (g.type === "apt") hasAptRisk = true;
        const score = g.threatLevel === "critical" ? 4 : g.threatLevel === "high" ? 3 : 2;
        if (score > topActorScore) {
          topActorScore = score;
          topActor = g.name;
        }
      }
    }
  }

  // Score: base on actor count + severity weighting
  const baseScore = Math.min(100, actorSet.size * 15 + (hasRansomwareRisk ? 20 : 0) + (hasAptRisk ? 15 : 0));

  return {
    score: baseScore,
    actorCount: actorSet.size,
    hasRansomwareRisk,
    hasAptRisk,
    topActor,
  };
}
