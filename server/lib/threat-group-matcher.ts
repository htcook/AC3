/**
 * Threat Group Matching Engine
 * 
 * Correlates engagement findings (MITRE techniques, CVEs, tools, attack patterns)
 * against known threat group TTPs to identify which APT/cybercrime/ransomware groups
 * most closely match the observed attack surface and vulnerabilities.
 * 
 * Also correlates matched threat groups to FedRAMP-authorized SaaS providers
 * that operate in targeted sectors, giving CISOs supply chain risk visibility.
 * 
 * Sources: MITRE ATT&CK, FedRAMP Marketplace, engagement scan data
 */

import { getDb } from "../db";
import {
  scanResults,
  scanObservations,
  unifiedExploitCatalog,
  attackChainRecords,
  engagements,
  threatActors,
  threatActorAbilities,
  threatActorIocs,
  threatGroupEvents,
} from "../../drizzle/schema";
import { eq, desc, count, sql, inArray, and, isNotNull } from "drizzle-orm";
import {
  getAllGroups,
  getGroupById,
  type ThreatGroupKnowledge,
  type ThreatGroupTTP,
} from "./threat-group-knowledge";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface EngagementFingerprint {
  engagementId: number;
  techniques: string[];       // MITRE ATT&CK technique IDs (T1190, T1059, etc.)
  cves: string[];             // CVE IDs found
  tools: string[];            // Tools/services detected (e.g., "Cobalt Strike", "Mimikatz")
  tactics: string[];          // MITRE tactics observed
  targetSectors: string[];    // Sectors from engagement metadata
  targetPorts: number[];      // Open ports discovered
  services: string[];         // Services detected (Apache, Tomcat, etc.)
  attackPatterns: string[];   // Attack chain pattern names
}

export interface ThreatGroupMatch {
  group: ThreatGroupKnowledge;
  matchScore: number;         // 0-100 overall match confidence
  matchedTechniques: MatchedItem[];
  matchedCVEs: MatchedItem[];
  matchedTools: MatchedItem[];
  matchedTactics: MatchedItem[];
  sectorRelevance: number;    // 0-100 how relevant this group is to the target sector
  riskLevel: "critical" | "high" | "medium" | "low";
  matchSummary: string;
  fedrampExposure: FedRAMPExposure[];
}

export interface MatchedItem {
  id: string;
  name: string;
  source: "engagement" | "threat_group" | "both";
  confidence: number;
}

export interface FedRAMPProvider {
  name: string;
  serviceModel: "SaaS" | "PaaS" | "IaaS";
  impactLevel: "Low" | "Moderate" | "High" | "LI-SaaS";
  status: "Authorized" | "In Process" | "Ready";
  sponsoringAgency: string;
  category: string;
  sectors: string[];
  authorizationDate?: string;
  description?: string;
}

export interface FedRAMPExposure {
  provider: FedRAMPProvider;
  exposureReason: string;
  riskLevel: "critical" | "high" | "medium" | "low";
  mitigations: string[];
}

// ─── FedRAMP Marketplace Data ───────────────────────────────────────────────
// Comprehensive catalog of FedRAMP-authorized SaaS providers with sector mapping
// Source: FedRAMP Marketplace (marketplace.fedramp.gov)

const FEDRAMP_PROVIDERS: FedRAMPProvider[] = [
  // Cloud Infrastructure & Compute
  { name: "Amazon Web Services (AWS) GovCloud", serviceModel: "IaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOJ", category: "Cloud Infrastructure", sectors: ["government", "defense", "financial", "healthcare", "energy"], description: "Government-isolated cloud infrastructure" },
  { name: "Microsoft Azure Government", serviceModel: "IaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOD", category: "Cloud Infrastructure", sectors: ["government", "defense", "financial", "healthcare", "energy", "education"], description: "Government cloud with DoD IL5 authorization" },
  { name: "Google Cloud Platform (GCP)", serviceModel: "IaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "GSA", category: "Cloud Infrastructure", sectors: ["government", "technology", "financial", "healthcare"], description: "Enterprise cloud with FedRAMP High authorization" },
  { name: "Oracle Cloud Infrastructure (OCI) Government", serviceModel: "IaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOD", category: "Cloud Infrastructure", sectors: ["government", "defense", "financial"], description: "Government cloud with database focus" },
  { name: "IBM Cloud for Government", serviceModel: "IaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "GSA", category: "Cloud Infrastructure", sectors: ["government", "defense", "financial", "healthcare"], description: "Enterprise hybrid cloud" },

  // Collaboration & Productivity
  { name: "Microsoft 365 Government (GCC High)", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOD", category: "Collaboration", sectors: ["government", "defense", "financial", "healthcare", "education"], description: "Office suite with Teams, SharePoint, Exchange for government" },
  { name: "Google Workspace (Government)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Collaboration", sectors: ["government", "education", "technology"], description: "Gmail, Drive, Docs for government" },
  { name: "Slack Enterprise Grid (GovSlack)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "VA", category: "Collaboration", sectors: ["government", "technology", "financial"], description: "Enterprise messaging for government" },
  { name: "Zoom for Government", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "DHS", category: "Collaboration", sectors: ["government", "education", "healthcare"], description: "Video conferencing for government" },
  { name: "Box for Government", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "DOI", category: "Content Management", sectors: ["government", "financial", "healthcare", "legal"], description: "Cloud content management and sharing" },
  { name: "Atlassian Government Cloud", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "NASA", category: "Project Management", sectors: ["government", "technology", "defense"], description: "Jira, Confluence for government" },

  // Security & Identity
  { name: "CrowdStrike Falcon GovCloud", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "CISA", category: "Endpoint Security", sectors: ["government", "defense", "financial", "healthcare", "energy", "critical_infrastructure"], description: "Endpoint detection and response" },
  { name: "Palo Alto Networks Prisma Cloud", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Cloud Security", sectors: ["government", "defense", "financial", "technology"], description: "Cloud-native security platform" },
  { name: "Splunk Cloud (GovCloud)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "DHS", category: "SIEM", sectors: ["government", "defense", "financial", "healthcare", "energy"], description: "Security information and event management" },
  { name: "Okta for Government", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "GSA", category: "Identity", sectors: ["government", "financial", "healthcare", "education"], description: "Identity and access management" },
  { name: "Zscaler Government Cloud", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOD", category: "Network Security", sectors: ["government", "defense", "financial", "healthcare"], description: "Zero trust network access" },
  { name: "Tenable.io (FedRAMP)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "DHS", category: "Vulnerability Management", sectors: ["government", "defense", "financial", "healthcare"], description: "Vulnerability assessment and management" },
  { name: "Rapid7 InsightPlatform", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Vulnerability Management", sectors: ["government", "financial", "technology"], description: "Security analytics and automation" },
  { name: "SentinelOne Singularity (GovCloud)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "VA", category: "Endpoint Security", sectors: ["government", "defense", "healthcare"], description: "AI-powered endpoint protection" },
  { name: "Tanium Cloud", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOD", category: "Endpoint Management", sectors: ["government", "defense", "financial"], description: "Endpoint management and security" },

  // Data & Analytics
  { name: "Snowflake Government", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Data Analytics", sectors: ["government", "financial", "healthcare", "technology"], description: "Cloud data platform" },
  { name: "Databricks Government Cloud", serviceModel: "PaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "DOE", category: "Data Analytics", sectors: ["government", "financial", "healthcare", "energy", "technology"], description: "Unified analytics and AI platform" },
  { name: "Palantir Gotham/Foundry", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOD", category: "Data Analytics", sectors: ["government", "defense", "intelligence", "healthcare"], description: "Data integration and analytics for defense/intel" },
  { name: "Tableau Government Cloud", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Data Visualization", sectors: ["government", "financial", "healthcare", "education"], description: "Business intelligence and visualization" },

  // CRM & Business
  { name: "Salesforce Government Cloud", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "GSA", category: "CRM", sectors: ["government", "financial", "healthcare", "education"], description: "Customer relationship management" },
  { name: "ServiceNow Government Cloud", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DHS", category: "IT Service Management", sectors: ["government", "defense", "financial", "healthcare"], description: "IT service management and workflows" },
  { name: "SAP Government Cloud", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "ERP", sectors: ["government", "defense", "financial", "manufacturing"], description: "Enterprise resource planning" },

  // DevOps & Development
  { name: "GitHub Enterprise Cloud (Government)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "DevOps", sectors: ["government", "technology", "defense"], description: "Code hosting and CI/CD" },
  { name: "GitLab Dedicated (FedRAMP)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "DevOps", sectors: ["government", "technology", "defense"], description: "DevSecOps platform" },

  // Communications
  { name: "Twilio Government Cloud", serviceModel: "PaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Communications", sectors: ["government", "healthcare", "financial"], description: "Cloud communications APIs" },
  { name: "Adobe Experience Cloud (Government)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Digital Experience", sectors: ["government", "education", "healthcare"], description: "Digital experience and content management" },

  // AI & ML
  { name: "OpenAI (Azure Government)", serviceModel: "SaaS", impactLevel: "High", status: "Authorized", sponsoringAgency: "DOD", category: "AI/ML", sectors: ["government", "defense", "intelligence", "technology"], description: "Large language model APIs via Azure Government" },
  { name: "Anthropic (AWS GovCloud)", serviceModel: "SaaS", impactLevel: "Moderate", status: "In Process", sponsoringAgency: "GSA", category: "AI/ML", sectors: ["government", "technology", "financial"], description: "AI assistant APIs" },

  // Healthcare-specific
  { name: "Epic Cloud (FedRAMP)", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "VA", category: "Healthcare IT", sectors: ["healthcare", "government"], description: "Electronic health records" },

  // Email Security
  { name: "Proofpoint Government", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "DHS", category: "Email Security", sectors: ["government", "defense", "financial", "healthcare"], description: "Email security and threat protection" },
  { name: "Mimecast Government Cloud", serviceModel: "SaaS", impactLevel: "Moderate", status: "Authorized", sponsoringAgency: "GSA", category: "Email Security", sectors: ["government", "financial", "legal"], description: "Email security and archiving" },
];

// ─── Sector Mapping ─────────────────────────────────────────────────────────
// Maps threat group target sectors to FedRAMP provider sectors for correlation

const SECTOR_ALIASES: Record<string, string[]> = {
  "government": ["government", "public sector", "federal", "state", "local"],
  "defense": ["defense", "military", "dod", "armed forces", "aerospace"],
  "financial": ["financial", "banking", "finance", "insurance", "fintech", "cryptocurrency"],
  "healthcare": ["healthcare", "health", "pharmaceutical", "biotech", "medical"],
  "energy": ["energy", "oil", "gas", "utilities", "power", "nuclear", "renewable"],
  "technology": ["technology", "tech", "software", "it", "telecommunications", "telecom"],
  "education": ["education", "academic", "university", "research"],
  "critical_infrastructure": ["critical infrastructure", "water", "transportation", "manufacturing"],
  "intelligence": ["intelligence", "intel", "sigint"],
  "legal": ["legal", "law", "law enforcement"],
  "manufacturing": ["manufacturing", "industrial", "ics", "ot", "scada"],
  "retail": ["retail", "e-commerce", "consumer"],
  "media": ["media", "entertainment", "journalism"],
};

function normalizeSector(sector: string): string {
  const lower = sector.toLowerCase().trim();
  for (const [canonical, aliases] of Object.entries(SECTOR_ALIASES)) {
    if (aliases.some(a => lower.includes(a))) return canonical;
  }
  return lower;
}

// ─── Fingerprint Extraction ─────────────────────────────────────────────────

export async function extractEngagementFingerprint(
  engagementId: number
): Promise<EngagementFingerprint> {
  const drizzleDb = await getDb();
  const techniques: Set<string> = new Set();
  const cves: Set<string> = new Set();
  const tools: Set<string> = new Set();
  const tactics: Set<string> = new Set();
  const targetSectors: Set<string> = new Set();
  const targetPorts: Set<number> = new Set();
  const services: Set<string> = new Set();
  const attackPatterns: Set<string> = new Set();

  if (!drizzleDb) {
    return {
      engagementId,
      techniques: [], cves: [], tools: [], tactics: [],
      targetSectors: [], targetPorts: [], services: [], attackPatterns: [],
    };
  }

  // 1. Get engagement metadata for sector info
  const [eng] = await drizzleDb.select({
    sector: engagements.sector,
    clientType: engagements.clientType,
  }).from(engagements).where(eq(engagements.id, engagementId)).limit(1);

  if (eng?.sector) targetSectors.add(normalizeSector(eng.sector));
  if (eng?.clientType) targetSectors.add(normalizeSector(eng.clientType));

  // 2. Extract from exploit catalog (MITRE techniques, CVEs)
  const exploits = await drizzleDb.select({
    mitreId: unifiedExploitCatalog.exploitMitreId,
    mitreName: unifiedExploitCatalog.exploitMitreName,
    mitreTactic: unifiedExploitCatalog.exploitMitreTactic,
    cveIds: unifiedExploitCatalog.exploitCveIds,
    category: unifiedExploitCatalog.exploitCategory,
  }).from(unifiedExploitCatalog).limit(500);

  for (const e of exploits) {
    if (e.mitreId) techniques.add(e.mitreId);
    if (e.mitreTactic) tactics.add(e.mitreTactic.toLowerCase());
    if (e.cveIds && Array.isArray(e.cveIds)) {
      for (const cve of e.cveIds as string[]) cves.add(cve);
    }
    if (e.category) tools.add(e.category);
  }

  // 3. Extract from attack chain records (MITRE techniques, patterns)
  const chains = await drizzleDb.select({
    mitreTechniques: attackChainRecords.acrMitreTechniques,
    patternName: attackChainRecords.acrPatternName,
    chainType: attackChainRecords.acrChainType,
  }).from(attackChainRecords)
    .where(eq(attackChainRecords.acrScanId, engagementId))
    .limit(100);

  for (const c of chains) {
    if (c.mitreTechniques && Array.isArray(c.mitreTechniques)) {
      for (const t of c.mitreTechniques as string[]) techniques.add(t);
    }
    if (c.patternName) attackPatterns.add(c.patternName);
  }

  // 4. Extract from scan results (tools used, findings)
  const results = await drizzleDb.select({
    tool: scanResults.tool,
    findings: scanResults.findings,
    target: scanResults.target,
  }).from(scanResults)
    .where(eq(scanResults.engagementId, engagementId))
    .limit(200);

  for (const r of results) {
    if (r.tool) tools.add(r.tool);
    if (r.findings && typeof r.findings === "object") {
      const findingsArr = Array.isArray(r.findings) ? r.findings : [];
      for (const f of findingsArr) {
        if (f.port) targetPorts.add(Number(f.port));
        if (f.service) services.add(f.service);
        if (f.cve) cves.add(f.cve);
        if (f.technique) techniques.add(f.technique);
      }
    }
  }

  // 5. Extract from scan observations (CVEs, services)
  const observations = await drizzleDb.select({
    assetPort: scanObservations.assetPort,
    evidenceCve: scanObservations.evidenceCve,
    evidenceSummary: scanObservations.evidenceSummary,
    scannerName: scanObservations.scannerName,
  }).from(scanObservations).limit(500);

  for (const o of observations) {
    if (o.assetPort) targetPorts.add(o.assetPort);
    if (o.evidenceCve) cves.add(o.evidenceCve);
  }

  return {
    engagementId,
    techniques: [...techniques],
    cves: [...cves],
    tools: [...tools],
    tactics: [...tactics],
    targetSectors: [...targetSectors],
    targetPorts: [...targetPorts],
    services: [...services],
    attackPatterns: [...attackPatterns],
  };
}

// ─── Matching Engine ────────────────────────────────────────────────────────

function computeTechniqueScore(
  engTechniques: string[],
  groupTTPs: ThreatGroupTTP[]
): { score: number; matched: MatchedItem[] } {
  if (engTechniques.length === 0 || groupTTPs.length === 0) return { score: 0, matched: [] };

  const matched: MatchedItem[] = [];
  const groupTechIds = new Set(groupTTPs.map(t => t.techniqueId));

  for (const tech of engTechniques) {
    if (groupTechIds.has(tech)) {
      const ttp = groupTTPs.find(t => t.techniqueId === tech)!;
      const confidence = ttp.frequency === "primary" ? 0.95 :
                         ttp.frequency === "secondary" ? 0.75 : 0.5;
      matched.push({
        id: tech,
        name: ttp.techniqueName,
        source: "both",
        confidence,
      });
    }
  }

  // Jaccard-like similarity with frequency weighting
  const weightedMatches = matched.reduce((sum, m) => sum + m.confidence, 0);
  const maxPossible = Math.min(engTechniques.length, groupTTPs.length);
  const score = maxPossible > 0 ? Math.round((weightedMatches / maxPossible) * 100) : 0;

  return { score: Math.min(100, score), matched };
}

function computeCVEScore(
  engCVEs: string[],
  groupCVEs: string[]
): { score: number; matched: MatchedItem[] } {
  if (engCVEs.length === 0 || groupCVEs.length === 0) return { score: 0, matched: [] };

  const matched: MatchedItem[] = [];
  const groupCVESet = new Set(groupCVEs.map(c => c.toUpperCase()));

  for (const cve of engCVEs) {
    if (groupCVESet.has(cve.toUpperCase())) {
      matched.push({
        id: cve,
        name: cve,
        source: "both",
        confidence: 0.9,
      });
    }
  }

  const score = Math.min(100, Math.round((matched.length / Math.min(engCVEs.length, groupCVEs.length)) * 100));
  return { score, matched };
}

function computeToolScore(
  engTools: string[],
  groupTools: { name: string; category: string }[]
): { score: number; matched: MatchedItem[] } {
  if (engTools.length === 0 || groupTools.length === 0) return { score: 0, matched: [] };

  const matched: MatchedItem[] = [];
  const engToolsLower = engTools.map(t => t.toLowerCase());

  for (const gt of groupTools) {
    const gtLower = gt.name.toLowerCase();
    for (const et of engToolsLower) {
      if (et.includes(gtLower) || gtLower.includes(et)) {
        matched.push({
          id: gt.name,
          name: `${gt.name} (${gt.category})`,
          source: "both",
          confidence: 0.85,
        });
        break;
      }
    }
  }

  const score = Math.min(100, Math.round((matched.length / Math.min(engTools.length, groupTools.length)) * 100));
  return { score, matched };
}

function computeTacticScore(
  engTactics: string[],
  groupTTPs: ThreatGroupTTP[]
): { score: number; matched: MatchedItem[] } {
  if (engTactics.length === 0 || groupTTPs.length === 0) return { score: 0, matched: [] };

  const groupTactics = new Set(groupTTPs.map(t => t.tactic.toLowerCase()));
  const matched: MatchedItem[] = [];

  for (const tactic of engTactics) {
    if (groupTactics.has(tactic.toLowerCase())) {
      matched.push({
        id: tactic,
        name: tactic,
        source: "both",
        confidence: 0.7,
      });
    }
  }

  const score = Math.min(100, Math.round((matched.length / Math.min(engTactics.length, groupTactics.size)) * 100));
  return { score, matched };
}

function computeSectorRelevance(
  engSectors: string[],
  groupSectors: string[]
): number {
  if (engSectors.length === 0 || groupSectors.length === 0) return 50; // neutral

  const normalizedEng = engSectors.map(normalizeSector);
  const normalizedGroup = groupSectors.map(normalizeSector);

  let matches = 0;
  for (const es of normalizedEng) {
    if (normalizedGroup.includes(es)) matches++;
  }

  return matches > 0 ? Math.min(100, Math.round((matches / normalizedEng.length) * 100)) : 20;
}

function computeFedRAMPExposure(
  group: ThreatGroupKnowledge,
  engSectors: string[]
): FedRAMPExposure[] {
  const exposures: FedRAMPExposure[] = [];
  const normalizedGroupSectors = group.targetSectors.map(normalizeSector);
  const normalizedEngSectors = engSectors.map(normalizeSector);
  const relevantSectors = new Set([...normalizedGroupSectors, ...normalizedEngSectors]);

  for (const provider of FEDRAMP_PROVIDERS) {
    const providerSectors = provider.sectors.map(normalizeSector);
    const sectorOverlap = providerSectors.filter(s => relevantSectors.has(s));

    if (sectorOverlap.length === 0) continue;

    // Determine exposure reason based on threat group characteristics
    const reasons: string[] = [];
    if (group.type === "apt" && group.threatLevel === "critical") {
      reasons.push(`${group.name} is a ${group.origin}-origin APT with critical threat level targeting ${sectorOverlap.join(", ")} sector(s)`);
    }
    if (group.initialAccessMethods.some(m => m.toLowerCase().includes("supply chain"))) {
      reasons.push(`${group.name} uses supply chain attacks — ${provider.name} is a potential vector`);
    }
    if (group.initialAccessMethods.some(m => m.toLowerCase().includes("phishing") || m.toLowerCase().includes("spear"))) {
      reasons.push(`${group.name} uses spearphishing — ${provider.name} email/collaboration services may be targeted`);
    }
    if (group.tools.some(t => t.category === "c2" || t.category === "rat")) {
      reasons.push(`${group.name} deploys C2/RAT tools that could target ${provider.name} endpoints`);
    }

    if (reasons.length === 0) {
      reasons.push(`${group.name} targets ${sectorOverlap.join(", ")} sector(s) where ${provider.name} operates`);
    }

    // Risk level based on threat group level and provider impact level
    const riskLevel = group.threatLevel === "critical" && provider.impactLevel === "High" ? "critical" :
                      group.threatLevel === "critical" || group.threatLevel === "high" ? "high" :
                      provider.impactLevel === "High" ? "medium" : "low";

    // Mitigations based on provider category
    const mitigations: string[] = [];
    if (provider.category.includes("Security") || provider.category.includes("Endpoint")) {
      mitigations.push("Ensure EDR/XDR policies are tuned for this threat group's TTPs");
    }
    if (provider.category.includes("Identity")) {
      mitigations.push("Enforce MFA and conditional access policies");
      mitigations.push("Monitor for credential stuffing and password spray attacks");
    }
    if (provider.category.includes("Collaboration") || provider.category.includes("Email")) {
      mitigations.push("Enable advanced threat protection for email");
      mitigations.push("Train users on spearphishing indicators specific to this group");
    }
    if (provider.category.includes("Cloud")) {
      mitigations.push("Review cloud security posture management (CSPM) alerts");
      mitigations.push("Implement least-privilege access controls");
    }
    mitigations.push(`Review ${provider.name} FedRAMP continuous monitoring reports`);
    mitigations.push("Validate vendor incident response procedures");

    exposures.push({
      provider,
      exposureReason: reasons.join("; "),
      riskLevel,
      mitigations,
    });
  }

  // Sort by risk level
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  exposures.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

  return exposures.slice(0, 15); // Top 15 most relevant
}

export async function matchThreatGroups(
  engagementId: number,
  options?: { minScore?: number; maxResults?: number }
): Promise<{
  fingerprint: EngagementFingerprint;
  matches: ThreatGroupMatch[];
  totalGroupsAnalyzed: number;
  matchTimestamp: number;
}> {
  const minScore = options?.minScore ?? 15;
  const maxResults = options?.maxResults ?? 20;

  // 1. Extract engagement fingerprint
  const fingerprint = await extractEngagementFingerprint(engagementId);

  // 2. Get all known threat groups
  let allGroups: ThreatGroupKnowledge[];
  try {
    allGroups = getAllGroups();
  } catch {
    allGroups = [];
  }

  // 3. Also check DB threat actors
  const drizzleDb = await getDb();
  if (drizzleDb && allGroups.length === 0) {
    // Fallback: build from DB
    const dbActors = await drizzleDb.select().from(threatActors).limit(200);
    for (const actor of dbActors) {
      allGroups.push({
        id: actor.actorId,
        name: actor.name,
        aliases: (actor.aliases as string[]) || [],
        type: (actor.actorType as any) || "apt",
        origin: actor.origin || "Unknown",
        threatLevel: (actor.threatLevel as any) || "medium",
        active: true,
        description: actor.description || "",
        motivation: actor.motivation || "",
        targetSectors: (actor.targetSectors as string[]) || [],
        targetRegions: (actor.targetRegions as string[]) || [],
        ttps: ((actor.techniques as any[]) || []).map((t: any) => ({
          techniqueId: t.techniqueId || t.id || "",
          techniqueName: t.techniqueName || t.name || "",
          tactic: t.tactic || "",
          description: t.description || "",
          frequency: t.frequency || "secondary",
        })),
        tools: ((actor.tools as any[]) || []).map((t: any) => ({
          name: t.name || t,
          category: t.category || "malware",
          description: t.description || "",
        })),
        initialAccessMethods: [],
        defenseRecommendations: [],
        detectionHints: [],
        exploitedCVEs: [],
        mitreGroupId: actor.stixId || undefined,
      });
    }
  }

  // 4. Score each group against the fingerprint
  const matches: ThreatGroupMatch[] = [];

  for (const group of allGroups) {
    const techResult = computeTechniqueScore(fingerprint.techniques, group.ttps);
    const cveResult = computeCVEScore(fingerprint.cves, group.exploitedCVEs);
    const toolResult = computeToolScore(fingerprint.tools, group.tools);
    const tacticResult = computeTacticScore(fingerprint.tactics, group.ttps);
    const sectorRelevance = computeSectorRelevance(fingerprint.targetSectors, group.targetSectors);

    // Weighted composite score
    const matchScore = Math.round(
      techResult.score * 0.35 +
      cveResult.score * 0.25 +
      toolResult.score * 0.15 +
      tacticResult.score * 0.10 +
      sectorRelevance * 0.15
    );

    if (matchScore < minScore) continue;

    // Determine risk level
    const riskLevel = matchScore >= 75 ? "critical" :
                      matchScore >= 50 ? "high" :
                      matchScore >= 30 ? "medium" : "low";

    // Build match summary
    const summaryParts: string[] = [];
    if (techResult.matched.length > 0) {
      summaryParts.push(`${techResult.matched.length} shared MITRE technique(s)`);
    }
    if (cveResult.matched.length > 0) {
      summaryParts.push(`${cveResult.matched.length} shared CVE(s)`);
    }
    if (toolResult.matched.length > 0) {
      summaryParts.push(`${toolResult.matched.length} shared tool(s)`);
    }
    if (sectorRelevance >= 60) {
      summaryParts.push(`targets same sector(s)`);
    }

    const matchSummary = summaryParts.length > 0
      ? `${group.name} matches with ${summaryParts.join(", ")}. ${group.origin}-origin ${group.type.toUpperCase()} group with ${group.threatLevel} threat level.`
      : `${group.name} has partial overlap with engagement findings.`;

    // Compute FedRAMP exposure
    const fedrampExposure = computeFedRAMPExposure(group, fingerprint.targetSectors);

    matches.push({
      group,
      matchScore,
      matchedTechniques: techResult.matched,
      matchedCVEs: cveResult.matched,
      matchedTools: toolResult.matched,
      matchedTactics: tacticResult.matched,
      sectorRelevance,
      riskLevel,
      matchSummary,
      fedrampExposure,
    });
  }

  // Sort by match score descending
  matches.sort((a, b) => b.matchScore - a.matchScore);

  return {
    fingerprint,
    matches: matches.slice(0, maxResults),
    totalGroupsAnalyzed: allGroups.length,
    matchTimestamp: Date.now(),
  };
}

// ─── Threat Group Profile ───────────────────────────────────────────────────

export interface ThreatGroupProfile {
  group: ThreatGroupKnowledge;
  attackHistory: AttackHistoryEntry[];
  iocs: IOCEntry[];
  abilities: AbilityEntry[];
  fedrampExposure: FedRAMPExposure[];
  relatedGroups: { id: string; name: string; relationship: string }[];
}

export interface AttackHistoryEntry {
  id: number;
  eventType: string;
  title: string;
  description: string | null;
  severity: string | null;
  victimName: string | null;
  victimSector: string | null;
  victimCountry: string | null;
  mitreTechniques: string[] | null;
  source: string | null;
  sourceUrl: string | null;
  confidence: number | null;
  eventDate: string | null;
  discoveredAt: string | null;
}

export interface IOCEntry {
  id: number;
  iocType: string;
  value: string;
  description: string | null;
  confidence: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  source: string | null;
}

export interface AbilityEntry {
  id: number;
  abilityId: string;
  name: string;
  description: string | null;
  tactic: string;
  techniqueId: string;
  techniqueName: string | null;
  platforms: string[] | null;
}

export async function getThreatGroupProfile(
  groupId: string,
  engagementSectors?: string[]
): Promise<ThreatGroupProfile | null> {
  // 1. Get group from knowledge base
  let group: ThreatGroupKnowledge | undefined;
  try {
    group = getGroupById(groupId);
  } catch { /* fallback below */ }

  // 2. Fallback: check DB
  const drizzleDb = await getDb();
  if (!group && drizzleDb) {
    const [dbActor] = await drizzleDb.select().from(threatActors)
      .where(eq(threatActors.actorId, groupId)).limit(1);
    if (dbActor) {
      group = {
        id: dbActor.actorId,
        name: dbActor.name,
        aliases: (dbActor.aliases as string[]) || [],
        type: (dbActor.actorType as any) || "apt",
        origin: dbActor.origin || "Unknown",
        threatLevel: (dbActor.threatLevel as any) || "medium",
        active: true,
        description: dbActor.description || "",
        motivation: dbActor.motivation || "",
        targetSectors: (dbActor.targetSectors as string[]) || [],
        targetRegions: (dbActor.targetRegions as string[]) || [],
        ttps: ((dbActor.techniques as any[]) || []).map((t: any) => ({
          techniqueId: t.techniqueId || "", techniqueName: t.techniqueName || "",
          tactic: t.tactic || "", description: t.description || "", frequency: "secondary" as const,
        })),
        tools: ((dbActor.tools as any[]) || []).map((t: any) => ({
          name: t.name || t, category: t.category || "malware" as const, description: t.description || "",
        })),
        initialAccessMethods: [],
        defenseRecommendations: [],
        detectionHints: [],
        exploitedCVEs: [],
        mitreGroupId: dbActor.stixId || undefined,
      };
    }
  }

  if (!group) return null;

  // 3. Get attack history from DB
  let attackHistory: AttackHistoryEntry[] = [];
  if (drizzleDb) {
    const events = await drizzleDb.select().from(threatGroupEvents)
      .where(eq(threatGroupEvents.tgeActorId, groupId))
      .orderBy(desc(threatGroupEvents.eventDate))
      .limit(50);

    attackHistory = events.map(e => ({
      id: e.id,
      eventType: e.eventType,
      title: e.tgeTitle,
      description: e.tgeDescription,
      severity: e.tgeSeverity,
      victimName: e.tgeVictimName,
      victimSector: e.tgeVictimSector,
      victimCountry: e.tgeVictimCountry,
      mitreTechniques: e.tgeMitreTechniques as string[] | null,
      source: e.tgeSource,
      sourceUrl: e.tgeSourceUrl,
      confidence: e.tgeConfidence,
      eventDate: e.eventDate,
      discoveredAt: e.discoveredAt,
    }));
  }

  // 4. Get IOCs from DB
  let iocs: IOCEntry[] = [];
  if (drizzleDb) {
    const iocRows = await drizzleDb.select().from(threatActorIocs)
      .where(eq(threatActorIocs.actorId, groupId))
      .limit(100);

    iocs = iocRows.map(i => ({
      id: i.id,
      iocType: i.iocType,
      value: i.value,
      description: i.description,
      confidence: i.iocConfidence,
      firstSeen: i.iocFirstSeen,
      lastSeen: i.iocLastSeen,
      source: i.source,
    }));
  }

  // 5. Get abilities from DB
  let abilities: AbilityEntry[] = [];
  if (drizzleDb) {
    const abilityRows = await drizzleDb.select().from(threatActorAbilities)
      .where(eq(threatActorAbilities.actorId, groupId))
      .limit(100);

    abilities = abilityRows.map(a => ({
      id: a.id,
      abilityId: a.abilityId,
      name: a.name,
      description: a.description,
      tactic: a.tactic,
      techniqueId: a.techniqueId,
      techniqueName: a.techniqueName,
      platforms: a.platforms as string[] | null,
    }));
  }

  // 6. Compute FedRAMP exposure
  const fedrampExposure = computeFedRAMPExposure(group, engagementSectors || []);

  // 7. Find related groups (same origin, similar TTPs)
  let relatedGroups: { id: string; name: string; relationship: string }[] = [];
  try {
    const allGroups = getAllGroups();
    const groupTechIds = new Set(group.ttps.map(t => t.techniqueId));
    for (const other of allGroups) {
      if (other.id === group.id) continue;
      const otherTechIds = new Set(other.ttps.map(t => t.techniqueId));
      const overlap = [...groupTechIds].filter(t => otherTechIds.has(t)).length;
      if (other.origin === group.origin) {
        relatedGroups.push({ id: other.id, name: other.name, relationship: `Same origin (${group.origin})` });
      } else if (overlap >= 3) {
        relatedGroups.push({ id: other.id, name: other.name, relationship: `${overlap} shared TTPs` });
      }
    }
  } catch { /* no knowledge data */ }

  return {
    group,
    attackHistory,
    iocs,
    abilities,
    fedrampExposure,
    relatedGroups: relatedGroups.slice(0, 10),
  };
}

// ─── FedRAMP Provider Lookup ────────────────────────────────────────────────

export function getFedRAMPProviders(filters?: {
  sector?: string;
  impactLevel?: string;
  serviceModel?: string;
  category?: string;
}): FedRAMPProvider[] {
  let providers = [...FEDRAMP_PROVIDERS];

  if (filters?.sector) {
    const normalized = normalizeSector(filters.sector);
    providers = providers.filter(p => p.sectors.some(s => normalizeSector(s) === normalized));
  }
  if (filters?.impactLevel) {
    providers = providers.filter(p => p.impactLevel === filters.impactLevel);
  }
  if (filters?.serviceModel) {
    providers = providers.filter(p => p.serviceModel === filters.serviceModel);
  }
  if (filters?.category) {
    const cat = filters.category.toLowerCase();
    providers = providers.filter(p => p.category.toLowerCase().includes(cat));
  }

  return providers;
}

export function getFedRAMPProviderCount(): number {
  return FEDRAMP_PROVIDERS.length;
}
