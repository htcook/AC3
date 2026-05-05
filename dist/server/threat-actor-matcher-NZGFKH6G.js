import {
  init_llm,
  invokeLLM
} from "./chunk-BRIFEITD.js";
import "./chunk-RUIEEOYK.js";
import {
  init_db,
  listThreatActors
} from "./chunk-AGW4B7XR.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-YB6W7YNA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/threat-actor-matcher.ts
init_llm();
init_db();
function safeParseJsonArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}
var SECTOR_ALIASES = {
  "technology": ["tech", "it", "software", "saas", "cloud", "information technology", "ict", "computing"],
  "financial": ["finance", "banking", "fintech", "insurance", "financial services", "payments"],
  "healthcare": ["health", "medical", "pharma", "pharmaceutical", "biotech", "hospital"],
  "government": ["gov", "public sector", "federal", "military", "defense", "defence", "national security"],
  "energy": ["oil", "gas", "utilities", "power", "electricity", "renewable", "petroleum"],
  "manufacturing": ["industrial", "factory", "production", "automotive"],
  "education": ["academic", "university", "school", "research", "higher education"],
  "retail": ["ecommerce", "e-commerce", "consumer", "shopping", "merchant"],
  "telecommunications": ["telecom", "telco", "communications", "mobile", "wireless"],
  "media": ["entertainment", "news", "publishing", "broadcasting"],
  "transportation": ["logistics", "shipping", "aviation", "airline", "maritime"],
  "legal": ["law", "law firm", "legal services"],
  "hospitality": ["hotel", "travel", "tourism", "restaurant"],
  "construction": ["real estate", "property", "building"],
  "agriculture": ["farming", "food", "agribusiness"],
  "aerospace": ["space", "satellite", "defense contractor"],
  "critical infrastructure": ["water", "waste", "infrastructure"],
  "managed service provider": ["msp", "mssp", "managed services", "it services"]
};
var TECH_THREAT_MAP = {
  "microsoft": ["T1059.001", "T1053.005", "T1021.001", "T1003.001"],
  // PowerShell, Scheduled Tasks, RDP, LSASS
  "active directory": ["T1003.001", "T1558.003", "T1021.002", "T1087.002"],
  // Kerberoasting, SMB, AD enum
  "exchange": ["T1190", "T1505.003", "T1114.002"],
  // ProxyLogon/ProxyShell, Web Shell, Email Collection
  "office365": ["T1078.004", "T1114.003", "T1528"],
  // Cloud accounts, Email forwarding, Steal tokens
  "azure": ["T1078.004", "T1580", "T1538"],
  // Cloud accounts, Cloud infra discovery
  "aws": ["T1078.004", "T1580", "T1530"],
  // Cloud accounts, S3 access
  "linux": ["T1059.004", "T1053.003", "T1021.004"],
  // Bash, Cron, SSH
  "docker": ["T1610", "T1613", "T1611"],
  // Container deploy, Container discovery, Escape
  "kubernetes": ["T1610", "T1613", "T1611"],
  "wordpress": ["T1190", "T1505.003"],
  // Exploit public app, Web shell
  "apache": ["T1190", "T1505.003"],
  "nginx": ["T1190"],
  "iis": ["T1190", "T1505.003"],
  "vpn": ["T1133", "T1078"],
  // External Remote Services, Valid Accounts
  "citrix": ["T1133", "T1190"],
  "vmware": ["T1190", "T1195.002"],
  // Exploit, Supply chain
  "fortinet": ["T1190", "T1133"],
  "palo alto": ["T1190", "T1133"],
  "cisco": ["T1190", "T1133", "T1557"],
  "sql": ["T1190", "T1505.001"],
  // SQL injection, Stored procedures
  "rdp": ["T1021.001", "T1563.002"],
  // Remote Desktop, RDP Hijacking
  "smb": ["T1021.002", "T1570"]
  // SMB/Windows Admin Shares, Lateral Tool Transfer
};
var CLIENT_TYPE_WEIGHTS = {
  "msp": { "ransomware": 1.5, "apt": 1.2, "cybercrime": 1.3 },
  "enterprise": { "apt": 1.4, "ransomware": 1.3, "cybercrime": 1.1 },
  "saas": { "apt": 1.3, "cybercrime": 1.2, "hacktivist": 1.1 },
  "paas": { "apt": 1.2, "cybercrime": 1.1 },
  "iaas": { "apt": 1.3, "cybercrime": 1.2 },
  "mixed_hosting": { "ransomware": 1.3, "apt": 1.2, "cybercrime": 1.2 }
};
function normalizeSector(sector) {
  const lower = sector.toLowerCase().trim();
  for (const [canonical, aliases] of Object.entries(SECTOR_ALIASES)) {
    if (canonical === lower || aliases.includes(lower)) return canonical;
  }
  return lower;
}
function sectorMatch(actorSectors, orgSector) {
  if (!actorSectors || actorSectors.length === 0) return 0.1;
  const normalizedOrg = normalizeSector(orgSector);
  for (const s of actorSectors) {
    const normalizedActor = normalizeSector(s);
    if (normalizedActor === normalizedOrg) return 1;
    const orgAliases = SECTOR_ALIASES[normalizedOrg] || [];
    const actorAliases = SECTOR_ALIASES[normalizedActor] || [];
    if (orgAliases.includes(normalizedActor) || actorAliases.includes(normalizedOrg)) return 0.8;
  }
  for (const s of actorSectors) {
    if (s.toLowerCase().includes(normalizedOrg) || normalizedOrg.includes(s.toLowerCase())) return 0.5;
  }
  return 0;
}
function techOverlap(actorTechniques, discoveredTech) {
  if (!actorTechniques || actorTechniques.length === 0 || !discoveredTech || discoveredTech.length === 0) {
    return { score: 0, matchedTechniques: [] };
  }
  const actorTechIds = new Set(actorTechniques.map((t) => t.id));
  const relevantTechIds = /* @__PURE__ */ new Set();
  for (const tech of discoveredTech) {
    const lower = tech.toLowerCase();
    for (const [keyword, techniques] of Object.entries(TECH_THREAT_MAP)) {
      if (lower.includes(keyword)) {
        for (const t of techniques) {
          if (actorTechIds.has(t)) {
            relevantTechIds.add(t);
          }
        }
      }
    }
  }
  const matchCount = relevantTechIds.size;
  const score = Math.min(1, matchCount / 3);
  return { score, matchedTechniques: Array.from(relevantTechIds) };
}
function recencyScore(lastActive) {
  if (!lastActive) return 0.3;
  const year = parseInt(lastActive);
  if (isNaN(year)) return 0.3;
  const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
  const age = currentYear - year;
  if (age <= 0) return 1;
  if (age <= 1) return 0.9;
  if (age <= 2) return 0.7;
  if (age <= 3) return 0.5;
  if (age <= 5) return 0.3;
  return 0.1;
}
function threatLevelWeight(level) {
  switch (level) {
    case "critical":
      return 1.5;
    case "high":
      return 1.3;
    case "medium":
      return 1;
    case "low":
      return 0.7;
    default:
      return 1;
  }
}
async function matchThreatActors(params) {
  const { actors } = await listThreatActors({ limit: 500 });
  const allTech = new Set(params.discoveredTechnologies);
  for (const asset of params.discoveredAssets) {
    if (asset.technologies) {
      for (const t of asset.technologies) allTech.add(t);
    }
  }
  const techList = Array.from(allTech);
  const scored = [];
  for (const actor of actors) {
    const matchReasons = [];
    let totalScore = 0;
    let maxPossible = 0;
    const sectorScore = sectorMatch(
      safeParseJsonArray(actor.targetSectors),
      params.sector
    );
    totalScore += sectorScore * 30;
    maxPossible += 30;
    if (sectorScore >= 0.5) {
      matchReasons.push(`Targets ${params.sector} sector`);
    }
    const techniques = safeParseJsonArray(actor.techniques);
    const { score: techScore, matchedTechniques } = techOverlap(techniques, techList);
    totalScore += techScore * 25;
    maxPossible += 25;
    if (techScore > 0) {
      matchReasons.push(`${matchedTechniques.length} techniques match discovered tech stack`);
    }
    const typeWeights = CLIENT_TYPE_WEIGHTS[params.clientType] || {};
    const typeMultiplier = typeWeights[actor.type] || 1;
    const typeScore = Math.min(1, (typeMultiplier - 0.7) / 0.8);
    totalScore += typeScore * 15;
    maxPossible += 15;
    if (typeMultiplier > 1.1) {
      matchReasons.push(`${actor.type} groups frequently target ${params.clientType} organizations`);
    }
    const recency = recencyScore(actor.lastActive);
    totalScore += recency * 15;
    maxPossible += 15;
    if (recency >= 0.7) {
      matchReasons.push(`Recently active (${actor.lastActive || "ongoing"})`);
    }
    const threatWeight = threatLevelWeight(actor.threatLevel);
    const threatScore = Math.min(1, (threatWeight - 0.7) / 0.8);
    totalScore += threatScore * 10;
    maxPossible += 10;
    if (params.region) {
      const targetRegions = safeParseJsonArray(actor.targetRegions);
      const regionMatch = targetRegions.some(
        (r) => r.toLowerCase().includes(params.region.toLowerCase()) || params.region.toLowerCase().includes(r.toLowerCase())
      );
      if (regionMatch) {
        totalScore += 5;
        matchReasons.push(`Targets ${params.region} region`);
      }
    }
    maxPossible += 5;
    const finalScore = Math.round(totalScore / maxPossible * 100);
    if (finalScore >= 15) {
      const relevantTechniques = techniques.filter((t) => matchedTechniques.includes(t.id)).slice(0, 10);
      scored.push({
        actorId: actor.actorId,
        name: actor.name,
        type: actor.type,
        origin: actor.origin,
        threatLevel: actor.threatLevel,
        sophistication: actor.sophistication,
        matchScore: finalScore,
        matchReasons,
        relevantTechniques,
        recommendedActions: generateRecommendedActions(actor, params),
        confidence: Math.round(Math.min(100, finalScore * 0.8 + matchReasons.length * 5)),
        rawScore: totalScore
      });
    }
  }
  scored.sort((a, b) => b.matchScore - a.matchScore);
  const topMatches = scored.slice(0, 20).map(({ rawScore, ...rest }) => rest);
  const sectorThreats = topMatches.filter((m) => m.matchReasons.some((r) => r.includes("sector"))).map((m) => m.name);
  const techStackThreats = topMatches.filter((m) => m.matchReasons.some((r) => r.includes("tech stack"))).map((m) => m.name);
  const matchSummary = generateMatchSummary(topMatches, params);
  return {
    topMatches,
    totalCandidates: actors.length,
    matchSummary,
    sectorThreats: sectorThreats.slice(0, 10),
    techStackThreats: techStackThreats.slice(0, 10)
  };
}
function generateRecommendedActions(actor, params) {
  const actions = [];
  if (actor.type === "ransomware") {
    actions.push("Test backup/recovery procedures against ransomware TTPs");
    actions.push("Validate EDR detection for ransomware execution patterns");
  }
  if (actor.type === "apt") {
    actions.push("Simulate advanced persistent threat lateral movement");
    actions.push("Test data exfiltration detection capabilities");
  }
  if (actor.type === "cybercrime") {
    actions.push("Test phishing resilience with actor-specific templates");
    actions.push("Validate credential theft detection");
  }
  actions.push(`Deploy ${actor.name} adversary profile in Caldera for simulation`);
  actions.push(`Generate IOC-driven phishing templates based on ${actor.name} TTPs`);
  return actions.slice(0, 4);
}
function generateMatchSummary(matches, params) {
  if (matches.length === 0) return "No significant threat actor matches found for this organization profile.";
  const critical = matches.filter((m) => m.matchScore >= 70);
  const high = matches.filter((m) => m.matchScore >= 50 && m.matchScore < 70);
  const moderate = matches.filter((m) => m.matchScore >= 30 && m.matchScore < 50);
  const parts = [];
  parts.push(`Analyzed ${params.sector} organization against threat actor database.`);
  if (critical.length > 0) {
    parts.push(`${critical.length} critical-match threat actor(s): ${critical.map((m) => m.name).join(", ")}.`);
  }
  if (high.length > 0) {
    parts.push(`${high.length} high-relevance actor(s): ${high.slice(0, 5).map((m) => m.name).join(", ")}.`);
  }
  if (moderate.length > 0) {
    parts.push(`${moderate.length} moderate-relevance actor(s) also identified.`);
  }
  const topTypes = Array.from(new Set(matches.slice(0, 5).map((m) => m.type)));
  parts.push(`Primary threat categories: ${topTypes.join(", ")}.`);
  return parts.join(" ");
}
async function matchThreatActorsWithLLM(params) {
  const topActorSummary = params.topDatabaseMatches.slice(0, 15).map(
    (m) => `${m.name} (${m.type}, ${m.origin || "unknown origin"}, score: ${m.matchScore}, reasons: ${m.matchReasons.join("; ")})`
  ).join("\n");
  const assetSummary = params.discoveredAssets.slice(0, 20).map(
    (a) => `${a.hostname} (${a.assetType}, tech: ${(a.technologies || []).join(", ")}, risk: ${a.riskBand || "unknown"})`
  ).join("\n");
  const response = await invokeLLM({
    _caller: "threat-actor-matcher.matchThreatActorsWithLLM",
    messages: [
      {
        role: "system",
        content: `You are an expert cyber threat intelligence analyst. Given an organization's profile, discovered assets, and pre-scored threat actor matches, provide enhanced analysis of which threat actors are most likely to target this organization and why. Return JSON with enhanced match analysis.`
      },
      {
        role: "user",
        content: `Analyze threat actor relevance for this organization:

ORGANIZATION:
- Name: ${params.orgProfile.customerName}
- Sector: ${params.orgProfile.sector}
- Type: ${params.orgProfile.clientType}
- Critical Functions: ${params.orgProfile.criticalFunctions.join(", ")}
- Overall Risk Score: ${params.overallRiskScore}/100

DISCOVERED ASSETS (top 20):
${assetSummary}

EXECUTIVE SUMMARY:
${params.executiveSummary?.substring(0, 500) || "N/A"}

PRE-SCORED THREAT ACTOR MATCHES (top 15):
${topActorSummary}

For each of the top 10 most relevant threat actors, provide:
1. A specific rationale for why they would target THIS organization
2. A brief realistic attack scenario they might use against the discovered assets
3. Priority level (critical/high/medium/low)

Return JSON: { "enhancedMatches": [{ "actorId": "...", "name": "...", "llmRationale": "...", "attackScenario": "...", "priorityLevel": "critical|high|medium|low" }], "overallAssessment": "2-3 sentence summary" }`
      }
    ],
    response_format: { type: "json_object" }
  });
  try {
    const content = String(response.choices[0].message.content || "{}");
    let cleaned = content.trim();
    if (cleaned.startsWith("```")) {
      cleaned = cleaned.replace(/^```(?:json)?\s*\n?/, "").replace(/\n?```\s*$/, "");
    }
    const parsed = JSON.parse(cleaned);
    return {
      enhancedMatches: parsed.enhancedMatches || [],
      overallAssessment: parsed.overallAssessment || "Analysis unavailable."
    };
  } catch {
    return {
      enhancedMatches: params.topDatabaseMatches.slice(0, 10).map((m) => ({
        actorId: m.actorId,
        name: m.name,
        llmRationale: m.matchReasons.join(". "),
        attackScenario: `${m.name} could leverage known TTPs against discovered infrastructure.`,
        priorityLevel: m.matchScore >= 70 ? "critical" : m.matchScore >= 50 ? "high" : "medium"
      })),
      overallAssessment: "LLM analysis unavailable. Showing database-scored matches."
    };
  }
}
export {
  matchThreatActors,
  matchThreatActorsWithLLM
};
