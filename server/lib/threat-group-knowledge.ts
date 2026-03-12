/**
 * Threat Group Knowledge Module
 * 
 * Maps APT, ransomware, cybercrime, and hacktivist groups to their preferred
 * TTPs, tools, target sectors, and defensive recommendations. Provides
 * structured context for LLM-powered hunt hypothesis generation, scan plan
 * optimization, and threat-informed defense prioritization.
 * 
 * Sources: MITRE ATT&CK, SOCRadar, Arctic Wolf, Bitsight, CISA advisories
 * 
 * Data is loaded at runtime from the DO scan server's /api/knowledge/ endpoint.
 */

import { loadKnowledgeData, getCachedKnowledge } from "./knowledge/knowledge-loader";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ThreatGroupType = "apt" | "ransomware" | "cybercrime" | "hacktivist";
export type ThreatLevel = "critical" | "high" | "medium" | "low";

export interface ThreatGroupTTP {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  description: string;
  /** How commonly this group uses this TTP: primary, secondary, occasional */
  frequency: "primary" | "secondary" | "occasional";
}

export interface ThreatGroupTool {
  name: string;
  category: "malware" | "rat" | "c2" | "exploit" | "credential" | "lateral" | "exfiltration" | "persistence" | "recon" | "living-off-the-land";
  description: string;
}

export interface DefenseRecommendation {
  priority: "critical" | "high" | "medium";
  category: "detection" | "prevention" | "monitoring" | "hardening";
  recommendation: string;
  siemQuery?: string;
  mitreTechniques: string[];
}

export interface ThreatGroupKnowledge {
  id: string;
  name: string;
  aliases: string[];
  type: ThreatGroupType;
  origin: string;
  threatLevel: ThreatLevel;
  active: boolean;
  description: string;
  motivation: string;
  targetSectors: string[];
  targetRegions: string[];
  ttps: ThreatGroupTTP[];
  tools: ThreatGroupTool[];
  initialAccessMethods: string[];
  defenseRecommendations: DefenseRecommendation[];
  /** Detection signatures / YARA / Sigma rule hints */
  detectionHints: string[];
  /** Known CVEs exploited by this group */
  exploitedCVEs: string[];
  /** MITRE ATT&CK Group ID (e.g., G0016) */
  mitreGroupId?: string;
}

export interface SectorThreatProfile {
  sector: string;
  topGroups: string[];
  commonTTPs: string[];
  priorityDefenses: string[];
}

// ─── Data Loading ──────────────────────────────────────────────────────────

interface ThreatGroupsData {
  aptGroups: ThreatGroupKnowledge[];
  ransomwareGroups: ThreatGroupKnowledge[];
  cybercrimeGroups: ThreatGroupKnowledge[];
  sectorProfiles: SectorThreatProfile[];
}

const FALLBACK: ThreatGroupsData = {
  aptGroups: [],
  ransomwareGroups: [],
  cybercrimeGroups: [],
  sectorProfiles: [],
};

let _allGroups: ThreatGroupKnowledge[] = [];
let _sectorProfiles: SectorThreatProfile[] = [];
let _loaded = false;

/** Initialize threat group data from DO scan server */
export async function initThreatGroups(): Promise<void> {
  if (_loaded) return;
  const data = await loadKnowledgeData<ThreatGroupsData>("threat_groups.json", FALLBACK);
  _allGroups = [
    ...(data.aptGroups || []),
    ...(data.ransomwareGroups || []),
    ...(data.cybercrimeGroups || []),
  ];
  _sectorProfiles = data.sectorProfiles || [];
  _loaded = true;
  console.log(`[ThreatGroups] Loaded ${_allGroups.length} groups, ${_sectorProfiles.length} sector profiles`);
}

// Auto-init on first import (non-blocking)
initThreatGroups().catch(e => console.warn("[ThreatGroups] Auto-init failed:", e.message));

function getAllGroupsCached(): ThreatGroupKnowledge[] {
  return _allGroups;
}

function getSectorProfilesCached(): SectorThreatProfile[] {
  return _sectorProfiles;
}

// ─── Context Builders for LLM Injection ─────────────────────────────────────

/**
 * Get threat group context for hunt hypothesis generation.
 * Returns a structured prompt section with group TTPs, tools, and detection recommendations.
 */
export function getThreatGroupHuntContext(options?: {
  groupIds?: string[];
  sector?: string;
  maxGroups?: number;
}): string {
  const ALL_GROUPS = getAllGroupsCached();
  const maxGroups = options?.maxGroups ?? 5;
  let groups: ThreatGroupKnowledge[];

  if (options?.groupIds?.length) {
    groups = ALL_GROUPS.filter(g => options.groupIds!.includes(g.id));
  } else if (options?.sector) {
    const profile = getSectorProfilesCached().find(p => p.sector === options.sector);
    if (profile) {
      groups = ALL_GROUPS.filter(g => profile.topGroups.includes(g.id));
    } else {
      groups = ALL_GROUPS.filter(g => g.threatLevel === "critical").slice(0, maxGroups);
    }
  } else {
    groups = ALL_GROUPS.filter(g => g.active && g.threatLevel === "critical").slice(0, maxGroups);
  }

  if (groups.length === 0) return "";

  let context = `\n=== THREAT GROUP INTELLIGENCE ===\n`;
  context += `Active threat groups relevant to this hunt (${groups.length} groups):\n\n`;

  for (const g of groups.slice(0, maxGroups)) {
    context += `## ${g.name} [${g.type.toUpperCase()}] — Threat Level: ${g.threatLevel.toUpperCase()}\n`;
    context += `Origin: ${g.origin} | Motivation: ${g.motivation}\n`;
    context += `Target Sectors: ${g.targetSectors.join(", ")}\n`;
    context += `Primary TTPs:\n`;
    for (const ttp of g.ttps.filter(t => t.frequency === "primary").slice(0, 5)) {
      context += `  - ${ttp.techniqueId} (${ttp.techniqueName}): ${ttp.description}\n`;
    }
    context += `Tools: ${g.tools.map(t => t.name).join(", ")}\n`;
    context += `Initial Access: ${g.initialAccessMethods.join(", ")}\n`;
    if (g.exploitedCVEs.length > 0) {
      context += `Known Exploited CVEs: ${g.exploitedCVEs.join(", ")}\n`;
    }
    context += `Detection Recommendations:\n`;
    for (const rec of g.defenseRecommendations.filter(r => r.category === "detection").slice(0, 2)) {
      context += `  - [${rec.priority.toUpperCase()}] ${rec.recommendation}\n`;
      if (rec.siemQuery) {
        context += `    SIEM Query: ${rec.siemQuery}\n`;
      }
    }
    context += `\n`;
  }

  context += `INSTRUCTIONS: Generate hypotheses that specifically target the TTPs and tools used by these threat groups. Include SIEM queries that detect the specific indicators listed above. Reference threat group names in hypothesis descriptions.\n`;

  return context;
}

/**
 * Get threat group context for scan plan generation.
 * Focuses on initial access methods and exploited CVEs.
 */
export function getThreatGroupScanContext(options?: {
  sector?: string;
  technologies?: string[];
}): string {
  const ALL_GROUPS = getAllGroupsCached();
  let groups: ThreatGroupKnowledge[];

  if (options?.sector) {
    const profile = getSectorProfilesCached().find(p => p.sector === options.sector);
    groups = profile
      ? ALL_GROUPS.filter(g => profile.topGroups.includes(g.id))
      : ALL_GROUPS.filter(g => g.threatLevel === "critical").slice(0, 5);
  } else {
    groups = ALL_GROUPS.filter(g => g.active && g.threatLevel === "critical").slice(0, 5);
  }

  if (groups.length === 0) return "";

  let context = `\n=== THREAT-INFORMED SCANNING PRIORITIES ===\n`;
  context += `Based on active threat groups targeting this sector:\n\n`;

  // Aggregate exploited CVEs
  const allCVEs = new Set<string>();
  const initialAccessMethods = new Set<string>();
  for (const g of groups) {
    g.exploitedCVEs.forEach(c => allCVEs.add(c));
    g.initialAccessMethods.forEach(m => initialAccessMethods.add(m));
  }

  context += `PRIORITY CVEs TO CHECK (exploited by active threat groups):\n`;
  context += `${[...allCVEs].join(", ")}\n\n`;

  context += `INITIAL ACCESS METHODS TO TEST:\n`;
  for (const method of initialAccessMethods) {
    context += `  - ${method}\n`;
  }

  context += `\nTHREAT GROUP TOOL SIGNATURES TO DETECT:\n`;
  const toolSet = new Set<string>();
  for (const g of groups) {
    for (const tool of g.tools) {
      if (!toolSet.has(tool.name)) {
        toolSet.add(tool.name);
        context += `  - ${tool.name} (${tool.category}): ${tool.description}\n`;
      }
    }
  }

  context += `\nINSTRUCTIONS: Prioritize scanning for the CVEs and initial access methods listed above. Include nuclei templates for the listed CVEs. Test for indicators of the tools listed above.\n`;

  return context;
}

/**
 * Get threat group context for vulnerability correlation.
 * Maps findings to threat group exploitation patterns.
 */
export function getThreatGroupVulnContext(technologies?: string[]): string {
  const ALL_GROUPS = getAllGroupsCached();
  let context = `\n=== THREAT GROUP VULNERABILITY CORRELATION ===\n`;
  context += `When correlating vulnerabilities, consider these active threat group exploitation patterns:\n\n`;

  // Build CVE-to-group mapping
  const cveToGroups: Record<string, string[]> = {};
  for (const g of ALL_GROUPS) {
    for (const cve of g.exploitedCVEs) {
      if (!cveToGroups[cve]) cveToGroups[cve] = [];
      cveToGroups[cve].push(g.name);
    }
  }

  context += `CVEs ACTIVELY EXPLOITED BY THREAT GROUPS:\n`;
  for (const [cve, groups] of Object.entries(cveToGroups).slice(0, 30)) {
    context += `  ${cve}: ${groups.join(", ")}\n`;
  }

  context += `\nSEVERITY BOOST RULES:\n`;
  context += `  - If a finding matches a CVE exploited by a CRITICAL threat group → boost severity to CRITICAL\n`;
  context += `  - If a finding matches a CVE exploited by multiple groups → boost severity by one level\n`;
  context += `  - If a finding matches a ransomware group's initial access method → flag as RANSOMWARE RISK\n`;
  context += `  - If a finding matches an APT group's persistence technique → flag as APT RISK\n`;

  return context;
}

/**
 * Get sector-specific threat profile for asset classification.
 */
export function getSectorThreatContext(sector: string): string {
  const ALL_GROUPS = getAllGroupsCached();
  const profile = getSectorProfilesCached().find(p => p.sector === sector);
  if (!profile) return "";

  const groups = ALL_GROUPS.filter(g => profile.topGroups.includes(g.id));

  let context = `\n=== SECTOR THREAT PROFILE: ${sector.toUpperCase()} ===\n`;
  context += `Top threat groups targeting this sector:\n`;
  for (const g of groups) {
    context += `  - ${g.name} (${g.type}, ${g.threatLevel}): ${g.motivation}\n`;
  }
  context += `Common TTPs: ${profile.commonTTPs.join(", ")}\n`;
  context += `Priority Defenses: ${profile.priorityDefenses.join("; ")}\n`;

  return context;
}

// ─── Lookup Functions ───────────────────────────────────────────────────────

export function getGroupById(id: string): ThreatGroupKnowledge | undefined {
  return getAllGroupsCached().find(g => g.id === id);
}

export function getGroupByName(name: string): ThreatGroupKnowledge | undefined {
  const lower = name.toLowerCase();
  return getAllGroupsCached().find(g =>
    g.name.toLowerCase().includes(lower) ||
    g.aliases.some(a => a.toLowerCase().includes(lower))
  );
}

export function getGroupsByType(type: ThreatGroupType): ThreatGroupKnowledge[] {
  return getAllGroupsCached().filter(g => g.type === type);
}

export function getGroupsBySector(sector: string): ThreatGroupKnowledge[] {
  const profile = getSectorProfilesCached().find(p => p.sector === sector);
  if (!profile) return [];
  return getAllGroupsCached().filter(g => profile.topGroups.includes(g.id));
}

export function getGroupsByTechnique(techniqueId: string): ThreatGroupKnowledge[] {
  return getAllGroupsCached().filter(g =>
    g.ttps.some(t => t.techniqueId === techniqueId)
  );
}

export function getGroupsByCVE(cve: string): ThreatGroupKnowledge[] {
  return getAllGroupsCached().filter(g => g.exploitedCVEs.includes(cve));
}

export function getAllGroups(): ThreatGroupKnowledge[] {
  return [...getAllGroupsCached()];
}

export function getSectorProfiles(): SectorThreatProfile[] {
  return [...getSectorProfilesCached()];
}

/**
 * Get a summary of all threat groups for dashboard display.
 */
export function getThreatGroupSummary(): {
  totalGroups: number;
  byType: Record<ThreatGroupType, number>;
  byThreatLevel: Record<ThreatLevel, number>;
  totalTTPs: number;
  totalCVEs: number;
  totalTools: number;
  activeGroups: number;
} {
  const ALL_GROUPS = getAllGroupsCached();
  const byType: Record<string, number> = { apt: 0, ransomware: 0, cybercrime: 0, hacktivist: 0 };
  const byThreatLevel: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const allCVEs = new Set<string>();
  const allTools = new Set<string>();
  let totalTTPs = 0;

  for (const g of ALL_GROUPS) {
    byType[g.type] = (byType[g.type] || 0) + 1;
    byThreatLevel[g.threatLevel] = (byThreatLevel[g.threatLevel] || 0) + 1;
    totalTTPs += g.ttps.length;
    g.exploitedCVEs.forEach(c => allCVEs.add(c));
    g.tools.forEach(t => allTools.add(t.name));
  }

  return {
    totalGroups: ALL_GROUPS.length,
    byType: byType as Record<ThreatGroupType, number>,
    byThreatLevel: byThreatLevel as Record<ThreatLevel, number>,
    totalTTPs,
    totalCVEs: allCVEs.size,
    totalTools: allTools.size,
    activeGroups: ALL_GROUPS.filter(g => g.active).length,
  };
}
