import {
  init_knowledge_loader,
  loadKnowledgeData
} from "./chunk-3ZWO3NC7.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/threat-group-knowledge.ts
async function initThreatGroups() {
  if (_loaded) return;
  const data = await loadKnowledgeData("threat_groups.json", FALLBACK);
  _allGroups = [
    ...data.aptGroups || [],
    ...data.ransomwareGroups || [],
    ...data.cybercrimeGroups || []
  ];
  _sectorProfiles = data.sectorProfiles || [];
  _loaded = true;
  console.log(`[ThreatGroups] Loaded ${_allGroups.length} groups, ${_sectorProfiles.length} sector profiles`);
}
function getAllGroupsCached() {
  return _allGroups;
}
function getSectorProfilesCached() {
  return _sectorProfiles;
}
function getThreatGroupHuntContext(options) {
  const ALL_GROUPS = getAllGroupsCached();
  const maxGroups = options?.maxGroups ?? 5;
  let groups;
  if (options?.groupIds?.length) {
    groups = ALL_GROUPS.filter((g) => options.groupIds.includes(g.id));
  } else if (options?.sector) {
    const profile = getSectorProfilesCached().find((p) => p.sector === options.sector);
    if (profile) {
      groups = ALL_GROUPS.filter((g) => profile.topGroups.includes(g.id));
    } else {
      groups = ALL_GROUPS.filter((g) => g.threatLevel === "critical").slice(0, maxGroups);
    }
  } else {
    groups = ALL_GROUPS.filter((g) => g.active && g.threatLevel === "critical").slice(0, maxGroups);
  }
  if (groups.length === 0) return "";
  let context = `
=== THREAT GROUP INTELLIGENCE ===
`;
  context += `Active threat groups relevant to this hunt (${groups.length} groups):

`;
  for (const g of groups.slice(0, maxGroups)) {
    context += `## ${g.name} [${g.type.toUpperCase()}] \u2014 Threat Level: ${g.threatLevel.toUpperCase()}
`;
    context += `Origin: ${g.origin} | Motivation: ${g.motivation}
`;
    context += `Target Sectors: ${g.targetSectors.join(", ")}
`;
    context += `Primary TTPs:
`;
    for (const ttp of g.ttps.filter((t) => t.frequency === "primary").slice(0, 5)) {
      context += `  - ${ttp.techniqueId} (${ttp.techniqueName}): ${ttp.description}
`;
    }
    context += `Tools: ${g.tools.map((t) => t.name).join(", ")}
`;
    context += `Initial Access: ${g.initialAccessMethods.join(", ")}
`;
    if (g.exploitedCVEs.length > 0) {
      context += `Known Exploited CVEs: ${g.exploitedCVEs.join(", ")}
`;
    }
    context += `Detection Recommendations:
`;
    for (const rec of g.defenseRecommendations.filter((r) => r.category === "detection").slice(0, 2)) {
      context += `  - [${rec.priority.toUpperCase()}] ${rec.recommendation}
`;
      if (rec.siemQuery) {
        context += `    SIEM Query: ${rec.siemQuery}
`;
      }
    }
    context += `
`;
  }
  context += `INSTRUCTIONS: Generate hypotheses that specifically target the TTPs and tools used by these threat groups. Include SIEM queries that detect the specific indicators listed above. Reference threat group names in hypothesis descriptions.
`;
  return context;
}
function getThreatGroupScanContext(options) {
  const ALL_GROUPS = getAllGroupsCached();
  let groups;
  if (options?.sector) {
    const profile = getSectorProfilesCached().find((p) => p.sector === options.sector);
    groups = profile ? ALL_GROUPS.filter((g) => profile.topGroups.includes(g.id)) : ALL_GROUPS.filter((g) => g.threatLevel === "critical").slice(0, 5);
  } else {
    groups = ALL_GROUPS.filter((g) => g.active && g.threatLevel === "critical").slice(0, 5);
  }
  if (groups.length === 0) return "";
  let context = `
=== THREAT-INFORMED SCANNING PRIORITIES ===
`;
  context += `Based on active threat groups targeting this sector:

`;
  const allCVEs = /* @__PURE__ */ new Set();
  const initialAccessMethods = /* @__PURE__ */ new Set();
  for (const g of groups) {
    g.exploitedCVEs.forEach((c) => allCVEs.add(c));
    g.initialAccessMethods.forEach((m) => initialAccessMethods.add(m));
  }
  context += `PRIORITY CVEs TO CHECK (exploited by active threat groups):
`;
  context += `${[...allCVEs].join(", ")}

`;
  context += `INITIAL ACCESS METHODS TO TEST:
`;
  for (const method of initialAccessMethods) {
    context += `  - ${method}
`;
  }
  context += `
THREAT GROUP TOOL SIGNATURES TO DETECT:
`;
  const toolSet = /* @__PURE__ */ new Set();
  for (const g of groups) {
    for (const tool of g.tools) {
      if (!toolSet.has(tool.name)) {
        toolSet.add(tool.name);
        context += `  - ${tool.name} (${tool.category}): ${tool.description}
`;
      }
    }
  }
  context += `
INSTRUCTIONS: Prioritize scanning for the CVEs and initial access methods listed above. Include nuclei templates for the listed CVEs. Test for indicators of the tools listed above.
`;
  return context;
}
function getThreatGroupVulnContext(technologies) {
  const ALL_GROUPS = getAllGroupsCached();
  let context = `
=== THREAT GROUP VULNERABILITY CORRELATION ===
`;
  context += `When correlating vulnerabilities, consider these active threat group exploitation patterns:

`;
  const cveToGroups = {};
  for (const g of ALL_GROUPS) {
    for (const cve of g.exploitedCVEs) {
      if (!cveToGroups[cve]) cveToGroups[cve] = [];
      cveToGroups[cve].push(g.name);
    }
  }
  context += `CVEs ACTIVELY EXPLOITED BY THREAT GROUPS:
`;
  for (const [cve, groups] of Object.entries(cveToGroups).slice(0, 30)) {
    context += `  ${cve}: ${groups.join(", ")}
`;
  }
  context += `
SEVERITY BOOST RULES:
`;
  context += `  - If a finding matches a CVE exploited by a CRITICAL threat group \u2192 boost severity to CRITICAL
`;
  context += `  - If a finding matches a CVE exploited by multiple groups \u2192 boost severity by one level
`;
  context += `  - If a finding matches a ransomware group's initial access method \u2192 flag as RANSOMWARE RISK
`;
  context += `  - If a finding matches an APT group's persistence technique \u2192 flag as APT RISK
`;
  return context;
}
function getSectorThreatContext(sector) {
  const ALL_GROUPS = getAllGroupsCached();
  const profile = getSectorProfilesCached().find((p) => p.sector === sector);
  if (!profile) return "";
  const groups = ALL_GROUPS.filter((g) => profile.topGroups.includes(g.id));
  let context = `
=== SECTOR THREAT PROFILE: ${sector.toUpperCase()} ===
`;
  context += `Top threat groups targeting this sector:
`;
  for (const g of groups) {
    context += `  - ${g.name} (${g.type}, ${g.threatLevel}): ${g.motivation}
`;
  }
  context += `Common TTPs: ${profile.commonTTPs.join(", ")}
`;
  context += `Priority Defenses: ${profile.priorityDefenses.join("; ")}
`;
  return context;
}
function getGroupById(id) {
  return getAllGroupsCached().find((g) => g.id === id);
}
function getGroupByName(name) {
  const lower = name.toLowerCase();
  return getAllGroupsCached().find(
    (g) => g.name.toLowerCase().includes(lower) || g.aliases.some((a) => a.toLowerCase().includes(lower))
  );
}
function getGroupsByType(type) {
  return getAllGroupsCached().filter((g) => g.type === type);
}
function getGroupsBySector(sector) {
  const profile = getSectorProfilesCached().find((p) => p.sector === sector);
  if (!profile) return [];
  return getAllGroupsCached().filter((g) => profile.topGroups.includes(g.id));
}
function getGroupsByTechnique(techniqueId) {
  return getAllGroupsCached().filter(
    (g) => g.ttps.some((t) => t.techniqueId === techniqueId)
  );
}
function getGroupsByCVE(cve) {
  return getAllGroupsCached().filter((g) => g.exploitedCVEs.includes(cve));
}
function getAllGroups() {
  return [...getAllGroupsCached()];
}
function getSectorProfiles() {
  return [...getSectorProfilesCached()];
}
function getThreatGroupSummary() {
  const ALL_GROUPS = getAllGroupsCached();
  const byType = { apt: 0, ransomware: 0, cybercrime: 0, hacktivist: 0 };
  const byThreatLevel = { critical: 0, high: 0, medium: 0, low: 0 };
  const allCVEs = /* @__PURE__ */ new Set();
  const allTools = /* @__PURE__ */ new Set();
  let totalTTPs = 0;
  for (const g of ALL_GROUPS) {
    byType[g.type] = (byType[g.type] || 0) + 1;
    byThreatLevel[g.threatLevel] = (byThreatLevel[g.threatLevel] || 0) + 1;
    totalTTPs += g.ttps.length;
    g.exploitedCVEs.forEach((c) => allCVEs.add(c));
    g.tools.forEach((t) => allTools.add(t.name));
  }
  return {
    totalGroups: ALL_GROUPS.length,
    byType,
    byThreatLevel,
    totalTTPs,
    totalCVEs: allCVEs.size,
    totalTools: allTools.size,
    activeGroups: ALL_GROUPS.filter((g) => g.active).length
  };
}
var FALLBACK, _allGroups, _sectorProfiles, _loaded;
var init_threat_group_knowledge = __esm({
  "server/lib/threat-group-knowledge.ts"() {
    init_knowledge_loader();
    FALLBACK = {
      aptGroups: [],
      ransomwareGroups: [],
      cybercrimeGroups: [],
      sectorProfiles: []
    };
    _allGroups = [];
    _sectorProfiles = [];
    _loaded = false;
    initThreatGroups().catch((e) => console.warn("[ThreatGroups] Auto-init failed:", e.message));
  }
});

export {
  initThreatGroups,
  getThreatGroupHuntContext,
  getThreatGroupScanContext,
  getThreatGroupVulnContext,
  getSectorThreatContext,
  getGroupById,
  getGroupByName,
  getGroupsByType,
  getGroupsBySector,
  getGroupsByTechnique,
  getGroupsByCVE,
  getAllGroups,
  getSectorProfiles,
  getThreatGroupSummary,
  init_threat_group_knowledge
};
