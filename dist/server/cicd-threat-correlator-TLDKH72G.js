import {
  getAllGroups,
  getGroupsByCVE,
  getGroupsBySector,
  getGroupsByTechnique,
  getSectorProfiles,
  initThreatGroups,
  init_threat_group_knowledge
} from "./chunk-RXZBKY45.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-KFQGP6VL.js";

// server/lib/cicd-threat-correlator.ts
init_threat_group_knowledge();
var CWE_TO_TACTIC = {
  "CWE-79": { tactic: "Initial Access", tacticId: "TA0001", techniques: ["T1189", "T1566.002"] },
  "CWE-89": { tactic: "Initial Access", tacticId: "TA0001", techniques: ["T1190"] },
  "CWE-94": { tactic: "Execution", tacticId: "TA0002", techniques: ["T1059"] },
  "CWE-78": { tactic: "Execution", tacticId: "TA0002", techniques: ["T1059.004"] },
  "CWE-22": { tactic: "Collection", tacticId: "TA0009", techniques: ["T1005"] },
  "CWE-200": { tactic: "Discovery", tacticId: "TA0007", techniques: ["T1082"] },
  "CWE-287": { tactic: "Credential Access", tacticId: "TA0006", techniques: ["T1110"] },
  "CWE-306": { tactic: "Initial Access", tacticId: "TA0001", techniques: ["T1190"] },
  "CWE-352": { tactic: "Initial Access", tacticId: "TA0001", techniques: ["T1189"] },
  "CWE-434": { tactic: "Persistence", tacticId: "TA0003", techniques: ["T1505.003"] },
  "CWE-502": { tactic: "Execution", tacticId: "TA0002", techniques: ["T1203"] },
  "CWE-611": { tactic: "Collection", tacticId: "TA0009", techniques: ["T1005"] },
  "CWE-614": { tactic: "Credential Access", tacticId: "TA0006", techniques: ["T1539"] },
  "CWE-798": { tactic: "Credential Access", tacticId: "TA0006", techniques: ["T1552.001"] },
  "CWE-918": { tactic: "Discovery", tacticId: "TA0007", techniques: ["T1046"] },
  "CWE-1021": { tactic: "Initial Access", tacticId: "TA0001", techniques: ["T1189"] },
  "CWE-16": { tactic: "Defense Evasion", tacticId: "TA0005", techniques: ["T1562"] },
  "CWE-295": { tactic: "Credential Access", tacticId: "TA0006", techniques: ["T1557"] },
  "CWE-319": { tactic: "Credential Access", tacticId: "TA0006", techniques: ["T1040"] },
  "CWE-269": { tactic: "Privilege Escalation", tacticId: "TA0004", techniques: ["T1068"] },
  "CWE-732": { tactic: "Privilege Escalation", tacticId: "TA0004", techniques: ["T1068"] },
  "CWE-862": { tactic: "Privilege Escalation", tacticId: "TA0004", techniques: ["T1068"] }
};
var ALL_KILL_CHAIN_PHASES = [
  { phase: "Reconnaissance", tacticId: "TA0043" },
  { phase: "Resource Development", tacticId: "TA0042" },
  { phase: "Initial Access", tacticId: "TA0001" },
  { phase: "Execution", tacticId: "TA0002" },
  { phase: "Persistence", tacticId: "TA0003" },
  { phase: "Privilege Escalation", tacticId: "TA0004" },
  { phase: "Defense Evasion", tacticId: "TA0005" },
  { phase: "Credential Access", tacticId: "TA0006" },
  { phase: "Discovery", tacticId: "TA0007" },
  { phase: "Lateral Movement", tacticId: "TA0008" },
  { phase: "Collection", tacticId: "TA0009" },
  { phase: "Command and Control", tacticId: "TA0011" },
  { phase: "Exfiltration", tacticId: "TA0010" },
  { phase: "Impact", tacticId: "TA0040" }
];
var SEVERITY_ORDER = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};
var SEVERITY_NAMES = ["info", "low", "medium", "high", "critical"];
function boostSeverity(current, levels) {
  const idx = SEVERITY_ORDER[current];
  const newIdx = Math.min(idx + levels, 4);
  return SEVERITY_NAMES[newIdx];
}
function extractCVEs(finding) {
  const cvePattern = /CVE-\d{4}-\d{4,}/gi;
  const sources = [finding.title, finding.description, finding.cweId || ""].join(" ");
  const matches = sources.match(cvePattern) || [];
  return [...new Set(matches.map((m) => m.toUpperCase()))];
}
function extractCWE(finding) {
  if (!finding.cweId) return null;
  const match = finding.cweId.match(/CWE-(\d+)/i);
  return match ? `CWE-${match[1]}` : null;
}
function enrichFinding(finding) {
  const attributedGroups = [];
  const riskTags = [];
  const killChainPhases = [];
  let severityBoosted = false;
  let boostReason;
  let boostedSeverity = finding.severity;
  const originalSeverity = finding.severity;
  const cves = extractCVEs(finding);
  for (const cve of cves) {
    const groups = getGroupsByCVE(cve);
    for (const g of groups) {
      if (!attributedGroups.find((a) => a.groupId === g.id)) {
        attributedGroups.push({
          groupId: g.id,
          groupName: g.name,
          groupType: g.type,
          threatLevel: g.threatLevel,
          origin: g.origin,
          active: g.active,
          matchType: "cve_exploit"
        });
      }
    }
  }
  const cwe = extractCWE(finding);
  if (cwe && CWE_TO_TACTIC[cwe]) {
    const mapping = CWE_TO_TACTIC[cwe];
    killChainPhases.push(mapping.tactic);
    for (const techId of mapping.techniques) {
      const groups = getGroupsByTechnique(techId);
      for (const g of groups) {
        if (!attributedGroups.find((a) => a.groupId === g.id)) {
          attributedGroups.push({
            groupId: g.id,
            groupName: g.name,
            groupType: g.type,
            threatLevel: g.threatLevel,
            origin: g.origin,
            active: g.active,
            matchType: "technique_overlap"
          });
        }
      }
    }
  }
  if (attributedGroups.length > 0) {
    const criticalActors = attributedGroups.filter(
      (a) => a.threatLevel === "critical" && a.matchType === "cve_exploit"
    );
    if (criticalActors.length > 0 && SEVERITY_ORDER[boostedSeverity] < SEVERITY_ORDER["critical"]) {
      boostedSeverity = "critical";
      severityBoosted = true;
      boostReason = `Exploited by critical threat group: ${criticalActors.map((a) => a.groupName).join(", ")}`;
    }
    const cveExploiters = attributedGroups.filter((a) => a.matchType === "cve_exploit");
    if (!severityBoosted && cveExploiters.length >= 2) {
      boostedSeverity = boostSeverity(boostedSeverity, 1);
      severityBoosted = boostedSeverity !== originalSeverity;
      if (severityBoosted) {
        boostReason = `Exploited by ${cveExploiters.length} threat groups: ${cveExploiters.map((a) => a.groupName).join(", ")}`;
      }
    }
    const ransomwareActors = attributedGroups.filter((a) => a.groupType === "ransomware");
    if (ransomwareActors.length > 0) {
      riskTags.push("RANSOMWARE_RISK");
      if (!severityBoosted && SEVERITY_ORDER[boostedSeverity] < SEVERITY_ORDER["high"]) {
        boostedSeverity = boostSeverity(boostedSeverity, 1);
        severityBoosted = boostedSeverity !== originalSeverity;
        if (severityBoosted) {
          boostReason = `Ransomware attack vector: ${ransomwareActors.map((a) => a.groupName).join(", ")}`;
        }
      }
    }
    const aptActors = attributedGroups.filter((a) => a.groupType === "apt");
    if (aptActors.length > 0) {
      riskTags.push("APT_RISK");
    }
    const activeActors = attributedGroups.filter((a) => a.active);
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
    killChainPhases
  };
}
function buildActorExposure(enrichedFindings) {
  const actorMap = /* @__PURE__ */ new Map();
  enrichedFindings.forEach((f, idx) => {
    for (const ag of f.attributedGroups) {
      if (!actorMap.has(ag.groupId)) {
        actorMap.set(ag.groupId, {
          group: ag,
          findings: /* @__PURE__ */ new Set(),
          cves: /* @__PURE__ */ new Set(),
          cwes: /* @__PURE__ */ new Set()
        });
      }
      const entry = actorMap.get(ag.groupId);
      entry.findings.add(idx);
      extractCVEs(f).forEach((c) => entry.cves.add(c));
      const cwe = extractCWE(f);
      if (cwe) entry.cwes.add(cwe);
    }
  });
  const entries = [];
  for (const [, data] of actorMap) {
    const threatMultiplier = data.group.threatLevel === "critical" ? 1.5 : data.group.threatLevel === "high" ? 1.2 : data.group.threatLevel === "medium" ? 1 : 0.7;
    const activeMultiplier = data.group.active ? 1.3 : 1;
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
      exposureScore
    });
  }
  return entries.sort((a, b) => b.exposureScore - a.exposureScore);
}
function buildKillChainMap(enrichedFindings) {
  const phaseMap = /* @__PURE__ */ new Map();
  for (const phase of ALL_KILL_CHAIN_PHASES) {
    phaseMap.set(phase.phase, {
      tacticId: phase.tacticId,
      findings: 0,
      groups: /* @__PURE__ */ new Set(),
      hasBoosted: false
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
  return ALL_KILL_CHAIN_PHASES.map((p) => {
    const entry = phaseMap.get(p.phase);
    return {
      phase: p.phase,
      tacticId: p.tacticId,
      findingCount: entry.findings,
      activeGroups: [...entry.groups],
      hasBoostedFindings: entry.hasBoosted
    };
  });
}
function buildTemplateRecommendations(sector, existingFindings) {
  const recommendations = [];
  const allGroups = getAllGroups();
  let relevantGroups;
  if (sector) {
    relevantGroups = getGroupsBySector(sector);
    if (relevantGroups.length === 0) {
      relevantGroups = allGroups.filter((g) => g.active && g.threatLevel === "critical").slice(0, 10);
    }
  } else {
    relevantGroups = allGroups.filter((g) => g.active && g.threatLevel === "critical").slice(0, 10);
  }
  const alreadyFoundCVEs = /* @__PURE__ */ new Set();
  if (existingFindings) {
    for (const f of existingFindings) {
      extractCVEs(f).forEach((c) => alreadyFoundCVEs.add(c));
    }
  }
  const cveToGroups = /* @__PURE__ */ new Map();
  for (const g of relevantGroups) {
    for (const cve of g.exploitedCVEs) {
      if (!alreadyFoundCVEs.has(cve)) {
        if (!cveToGroups.has(cve)) cveToGroups.set(cve, []);
        cveToGroups.get(cve).push(g.name);
      }
    }
  }
  const sortedCVEs = [...cveToGroups.entries()].sort((a, b) => b[1].length - a[1].length);
  for (const [cve, groups] of sortedCVEs.slice(0, 20)) {
    const priority = groups.length >= 3 ? "critical" : groups.length >= 2 ? "high" : "medium";
    recommendations.push({
      templateId: cve,
      reason: `Exploited by ${groups.length} active threat group(s) targeting ${sector || "your sector"}`,
      attributedGroups: groups,
      priority
    });
  }
  return recommendations;
}
async function correlateCicdFindings(findings, sector) {
  await initThreatGroups();
  const enrichedFindings = findings.map((f) => enrichFinding(f));
  const actorExposure = buildActorExposure(enrichedFindings);
  const killChainMap = buildKillChainMap(enrichedFindings);
  const templateRecommendations = buildTemplateRecommendations(sector, enrichedFindings);
  let sectorProfile;
  if (sector) {
    const profiles = getSectorProfiles();
    const match = profiles.find((p) => p.sector === sector);
    if (match) {
      sectorProfile = {
        sector: match.sector,
        topGroups: match.topGroups,
        commonTTPs: match.commonTTPs,
        priorityDefenses: match.priorityDefenses
      };
    }
  }
  const enrichedCount = enrichedFindings.filter((f) => f.attributedGroups.length > 0).length;
  const boostedCount = enrichedFindings.filter((f) => f.severityBoosted).length;
  const uniqueActors = new Set(enrichedFindings.flatMap((f) => f.attributedGroups.map((a) => a.groupId)));
  const coveredPhases = killChainMap.filter((k) => k.findingCount > 0).length;
  const killChainCoverage = Math.round(coveredPhases / ALL_KILL_CHAIN_PHASES.length * 100);
  const topActors = actorExposure.slice(0, 5);
  const actorExposureScore = topActors.length > 0 ? Math.round(topActors.reduce((sum, a) => sum + a.exposureScore, 0) / topActors.length) : 0;
  return {
    summary: {
      totalFindings: findings.length,
      enrichedFindings: enrichedCount,
      severityBoostedCount: boostedCount,
      uniqueActorsMatched: uniqueActors.size,
      actorExposureScore,
      killChainCoverage,
      ransomwareRiskFindings: enrichedFindings.filter((f) => f.riskTags.includes("RANSOMWARE_RISK")).length,
      aptRiskFindings: enrichedFindings.filter((f) => f.riskTags.includes("APT_RISK")).length
    },
    enrichedFindings,
    actorExposure,
    killChainMap,
    sectorProfile,
    templateRecommendations
  };
}
async function getPreScanTemplates(sector) {
  await initThreatGroups();
  const allGroups = getAllGroups();
  let relevantGroups;
  if (sector) {
    relevantGroups = getGroupsBySector(sector);
    if (relevantGroups.length === 0) {
      relevantGroups = allGroups.filter((g) => g.active && g.threatLevel === "critical").slice(0, 10);
    }
  } else {
    relevantGroups = allGroups.filter((g) => g.active && g.threatLevel === "critical").slice(0, 10);
  }
  const priorityCVEs = /* @__PURE__ */ new Set();
  const templateTags = /* @__PURE__ */ new Set();
  const targetedGroups = [];
  for (const g of relevantGroups) {
    targetedGroups.push(g.name);
    g.exploitedCVEs.forEach((c) => priorityCVEs.add(c));
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
    targetedGroups
  };
}
async function quickThreatScore(findings) {
  await initThreatGroups();
  const actorSet = /* @__PURE__ */ new Set();
  let hasRansomwareRisk = false;
  let hasAptRisk = false;
  let topActorScore = 0;
  let topActor = null;
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
  const baseScore = Math.min(100, actorSet.size * 15 + (hasRansomwareRisk ? 20 : 0) + (hasAptRisk ? 15 : 0));
  return {
    score: baseScore,
    actorCount: actorSet.size,
    hasRansomwareRisk,
    hasAptRisk,
    topActor
  };
}
export {
  correlateCicdFindings,
  getPreScanTemplates,
  quickThreatScore
};
