/**
 * Ransomware Intelligence Service
 * 
 * LLM-powered ransomware group profiling, activity scoring,
 * and integration with the domain intel pipeline.
 * Uses the built-in LLM to generate comprehensive profiles
 * from public threat intelligence knowledge.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import { ransomwareGroups, ransomwareEvents, threatActors } from "../../drizzle/schema";
import { eq, desc } from "drizzle-orm";
import type {
  RansomwareGroupProfile,
  ActivityRating,
  DarkwebDashboardStats,
  IntelligenceEnrichment,
} from "../../shared/darkweb-types";

// ─── Known Ransomware Groups (seed list) ─────────────────────────────────
const KNOWN_RANSOMWARE_GROUPS = [
  "LockBit", "BlackCat/ALPHV", "Cl0p", "Play", "8Base", "Akira",
  "BianLian", "Medusa", "NoEscape", "Rhysida", "Hunters International",
  "BlackBasta", "Royal", "Vice Society", "Hive", "Conti", "REvil/Sodinokibi",
  "DarkSide", "BlackMatter", "Ragnar Locker", "Maze", "Ryuk",
  "Cuba", "AvosLocker", "Karakurt", "Lorenz", "Snatch",
  "INC Ransom", "Cactus", "RansomHub", "Qilin", "Fog",
  "Meow", "DragonForce", "Embargo", "Lynx", "Cicada3301",
  "Sarcoma", "Funksec", "NightSpire", "Morpheus", "Termite",
];

// ─── LLM Profile Generation ─────────────────────────────────────────────

/**
 * Generate a comprehensive ransomware group profile using LLM.
 * The LLM synthesizes from its training data (public threat intel).
 */
export async function generateRansomwareProfile(
  groupName: string
): Promise<RansomwareGroupProfile> {
  const response = await invokeLLM({ _caller: "ransomware-intel.generateRansomwareProfile", _priority: 'bulk',
    messages: [
      {
        role: "system",
        content: `You are a senior threat intelligence analyst specializing in ransomware groups. 
Generate a comprehensive profile for the requested ransomware group based on publicly available threat intelligence.
Be factual and cite specific incidents where possible. If a group is defunct, note that clearly.
For activity scores: surging groups (actively attacking) = 70-100, active = 40-69, declining = 20-39, dormant = 0-19.
For victim counts, use your best estimates based on known public reporting through early 2025.
MITRE techniques should be specific T-codes (e.g., T1566.001, T1486, T1027).`,
      },
      {
        role: "user",
        content: `Generate a comprehensive threat intelligence profile for the ransomware group: "${groupName}". Include all known aliases, TTPs, targeting patterns, notable attacks, and infrastructure details.`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "ransomware_profile",
        strict: true,
        schema: {
          type: "object",
          properties: {
            groupName: { type: "string", description: "Primary name of the group" },
            aliases: { type: "array", items: { type: "string" }, description: "Known aliases" },
            description: { type: "string", description: "2-3 paragraph overview of the group" },
            activityScore: { type: "integer", description: "0-100 activity score" },
            trend: { type: "string", enum: ["surging", "active", "declining", "dormant"], description: "Current activity trend" },
            victims7d: { type: "integer", description: "Estimated victims in last 7 days" },
            victims30d: { type: "integer", description: "Estimated victims in last 30 days" },
            totalVictims: { type: "integer", description: "Total known victims" },
            topSectors: { type: "array", items: { type: "string" }, description: "Top 5 targeted sectors" },
            topCountries: { type: "array", items: { type: "string" }, description: "Top 5 targeted countries" },
            associatedMalware: { type: "array", items: { type: "string" }, description: "Associated malware families and tools" },
            mitreTechniques: { type: "array", items: { type: "string" }, description: "MITRE ATT&CK technique IDs (T-codes)" },
            firstSeen: { type: "string", description: "First seen date or year" },
            lastActive: { type: "string", description: "Last known activity date" },
            ransomwareFamily: { type: "string", description: "Ransomware family name and version" },
            extortionModel: { type: "string", enum: ["single", "double", "triple", "unknown"], description: "Extortion model" },
            affiliateProgram: { type: "boolean", description: "Whether group runs an affiliate/RaaS program" },
            knownInfrastructure: { type: "array", items: { type: "string" }, description: "Known infrastructure (.onion sites, leak sites)" },
            notableAttacks: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  victimName: { type: "string" },
                  sector: { type: "string" },
                  country: { type: "string" },
                  date: { type: "string" },
                  impactDescription: { type: "string" },
                  ransomDemand: { type: "string" },
                },
                required: ["victimName", "sector", "country", "date", "impactDescription", "ransomDemand"],
                additionalProperties: false,
              },
              description: "Notable attacks with details",
            },
          },
          required: [
            "groupName", "aliases", "description", "activityScore", "trend",
            "victims7d", "victims30d", "totalVictims", "topSectors", "topCountries",
            "associatedMalware", "mitreTechniques", "firstSeen", "lastActive",
            "ransomwareFamily", "extortionModel", "affiliateProgram",
            "knownInfrastructure", "notableAttacks",
          ],
          additionalProperties: false,
        },
      },
    },
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") throw new Error(`LLM returned empty profile for ${groupName}`);
  return JSON.parse(content) as RansomwareGroupProfile;
}

// ─── Database Helpers ────────────────────────────────────────────────────

/**
 * Seed or refresh a ransomware group profile in the database.
 */
export async function upsertRansomwareGroup(profile: RansomwareGroupProfile) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const existing = await db
    .select()
    .from(ransomwareGroups)
    .where(eq(ransomwareGroups.groupName, profile.groupName))
    .limit(1);

  const data = {
    groupName: profile.groupName,
    aliases: profile.aliases,
    description: profile.description,
    activityScore: profile.activityScore,
    trend: profile.trend as "surging" | "active" | "declining" | "dormant",
    threatLevel: (profile.activityScore >= 70 ? "critical" : profile.activityScore >= 40 ? "high" : profile.activityScore >= 20 ? "medium" : "low") as "critical" | "high" | "medium" | "low",
    victims7d: profile.victims7d,
    victims30d: profile.victims30d,
    totalVictims: profile.totalVictims,
    topSectors: profile.topSectors,
    topCountries: profile.topCountries,
    associatedMalware: profile.associatedMalware,
    mitreTechniques: profile.mitreTechniques,
    ransomwareFamily: profile.ransomwareFamily,
    extortionModel: profile.extortionModel as "single" | "double" | "triple" | "unknown",
    affiliateProgram: profile.affiliateProgram,
    knownInfrastructure: profile.knownInfrastructure,
    notableAttacks: profile.notableAttacks,
    firstSeen: profile.firstSeen,
    lastActive: profile.lastActive,
    dataSource: "llm_enriched",
    confidence: 75,
    lastEnriched: new Date(),
  };

  if (existing.length > 0) {
    await db
      .update(ransomwareGroups)
      .set(data)
      .where(eq(ransomwareGroups.groupName, profile.groupName));
    return existing[0].id;
  } else {
    const [result] = await db.insert(ransomwareGroups).values(data);
    return result.insertId;
  }
}

/**
 * Get all ransomware groups from the database, ordered by activity score.
 */
export async function getAllRansomwareGroups() {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(ransomwareGroups)
    .orderBy(desc(ransomwareGroups.activityScore));
}

/**
 * Get a single ransomware group by name.
 */
export async function getRansomwareGroupByName(groupName: string) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db
    .select()
    .from(ransomwareGroups)
    .where(eq(ransomwareGroups.groupName, groupName))
    .limit(1);
  return rows[0] ?? null;
}

/**
 * Get dashboard statistics for darkweb intelligence.
 */
export async function getDarkwebDashboardStats(): Promise<DarkwebDashboardStats> {
  const groups = await getAllRansomwareGroups();

  const activeGroups = groups.filter((g: typeof groups[number]) => g.trend === "surging" || g.trend === "active");
  const surgingGroups = groups.filter((g: typeof groups[number]) => g.trend === "surging");
  const totalVictims30d = groups.reduce((sum: number, g: typeof groups[number]) => sum + (g.victims30d ?? 0), 0);

  // Aggregate sector targeting
  const sectorMap = new Map<string, number>();
  const countryMap = new Map<string, number>();
  for (const g of groups) {
    const sectors = (g.topSectors as string[] | null) ?? [];
    const countries = (g.topCountries as string[] | null) ?? [];
    for (const s of sectors) sectorMap.set(s, (sectorMap.get(s) ?? 0) + (g.victims30d ?? 0));
    for (const c of countries) countryMap.set(c, (countryMap.get(c) ?? 0) + (g.victims30d ?? 0));
  }

  const topSectors = Array.from(sectorMap.entries())
    .sort((a: [string, number], b: [string, number]) => b[1] - a[1])
    .slice(0, 10)
    .map(([sector, count]: [string, number]) => ({ sector, count }));

  const topCountries = Array.from(countryMap.entries())
    .sort((a: [string, number], b: [string, number]) => b[1] - a[1])
    .slice(0, 10)
    .map(([country, count]: [string, number]) => ({ country, count }));

  // Get recent events
  const db = await getDb();
  const recentEvents = db
    ? await db
        .select()
        .from(ransomwareEvents)
        .orderBy(desc(ransomwareEvents.publishedAt))
        .limit(20)
    : [];

  return {
    totalGroups: groups.length,
    activeGroups: activeGroups.length,
    surgingGroups: surgingGroups.length,
    totalVictims30d,
    totalIOCs: 0, // Will be populated from iocFeeds
    kevWithRansomware: 0,
    topSectors,
    topCountries,
    recentEvents: recentEvents.map((e: typeof recentEvents[number]) => ({
      id: e.id,
      groupName: e.groupName,
      victimName: e.victimName,
      victimUrl: e.victimUrl ?? undefined,
      country: e.country ?? "",
      sector: e.sector ?? "",
      publishedAt: e.publishedAt?.toISOString() ?? "",
      source: e.source ?? "",
      description: e.description ?? undefined,
    })),
  };
}

/**
 * Get activity ratings for all groups (sorted by activity score).
 */
export async function getActivityRatings(): Promise<ActivityRating[]> {
  const groups = await getAllRansomwareGroups();
  return groups.map((g: typeof groups[number]) => ({
    groupName: g.groupName,
    activityScore: g.activityScore ?? 0,
    trend: (g.trend ?? "active") as ActivityRating["trend"],
    victims7d: g.victims7d ?? 0,
    victims30d: g.victims30d ?? 0,
    lastAttack: g.lastActive ?? "",
    threatLevel: (g.threatLevel ?? "medium") as ActivityRating["threatLevel"],
    primarySectors: (g.topSectors as string[] | null) ?? [],
  }));
}

/**
 * Enrich domain intel results with ransomware intelligence.
 * Given a target sector and country, find relevant ransomware groups
 * and generate intelligence enrichment for the domain intel pipeline.
 */
export async function enrichWithRansomwareIntel(
  sector: string,
  country?: string,
  discoveredTechniques?: string[],
): Promise<IntelligenceEnrichment> {
  const groups = await getAllRansomwareGroups();
  if (groups.length === 0) {
    return {
      matchedGroups: [],
      matchedIOCs: [],
      kevMatches: [],
      riskElevation: "No ransomware intelligence data available. Seed the threat catalog to enable ransomware-informed risk assessment.",
    };
  }

  // Match groups by sector targeting
  const sectorLower = sector.toLowerCase();
  const matchedGroups = groups
    .filter((g: typeof groups[number]) => {
      const sectors = (g.topSectors as string[] | null) ?? [];
      return sectors.some((s: string) => s.toLowerCase().includes(sectorLower) || sectorLower.includes(s.toLowerCase()));
    })
    .sort((a: typeof groups[number], b: typeof groups[number]) => (b.activityScore ?? 0) - (a.activityScore ?? 0))
    .slice(0, 5);

  // If no sector match, fall back to top active groups
  const finalGroups = matchedGroups.length > 0 ? matchedGroups : groups.slice(0, 3);

  // Calculate technique overlap if provided
  const enrichedGroups = finalGroups.map((g: typeof groups[number]) => {
    const groupTechniques = (g.mitreTechniques as string[] | null) ?? [];
    const matchedTechniques = discoveredTechniques
      ? groupTechniques.filter((t: string) => discoveredTechniques.includes(t))
      : [];

    return {
      groupName: g.groupName,
      activityScore: g.activityScore ?? 0,
      trend: (g.trend ?? "active") as "surging" | "active" | "declining" | "dormant",
      relevance: matchedGroups.length > 0
        ? `Actively targets ${sector} sector with ${g.victims30d ?? 0} victims in last 30 days`
        : `Top active ransomware group with activity score ${g.activityScore}`,
      matchedTechniques,
      recentVictimsSameSector: g.victims30d ?? 0,
    };
  });

  // Generate risk elevation summary via LLM
  const groupSummary = enrichedGroups
    .map((g: typeof enrichedGroups[number]) => `${g.groupName} (score: ${g.activityScore}, trend: ${g.trend}, 30d victims: ${g.recentVictimsSameSector})`)
    .join("; ");

  let riskElevation = `${enrichedGroups.length} ransomware groups identified targeting the ${sector} sector.`;
  try {
    const llmResponse = await invokeLLM({ _caller: "ransomware-intel.groupTechniques", _priority: 'bulk',
      messages: [
        {
          role: "system",
          content: "You are a threat intelligence analyst. Write a concise 2-3 sentence risk assessment based on ransomware group activity relevant to the target. Be specific about which groups pose the highest risk and why.",
        },
        {
          role: "user",
          content: `Target sector: ${sector}${country ? `, Country: ${country}` : ""}. Relevant ransomware groups: ${groupSummary}`,
        },
      ],
    });
    const llmContent = llmResponse.choices?.[0]?.message?.content;
    riskElevation = (typeof llmContent === "string" ? llmContent : null) ?? riskElevation;
  } catch {
    // Fall back to static summary
  }

  return {
    matchedGroups: enrichedGroups,
    matchedIOCs: [],
    kevMatches: [],
    riskElevation,
  };
}

/**
 * Seed the ransomware group catalog with LLM-generated profiles.
 * Processes groups in batches to avoid rate limits.
 */
export async function seedRansomwareCatalog(
  onProgress?: (group: string, index: number, total: number) => void,
  groupNames?: string[],
): Promise<{ seeded: number; errors: string[] }> {
  const groups = groupNames ?? KNOWN_RANSOMWARE_GROUPS;
  const errors: string[] = [];
  let seeded = 0;

  for (let i = 0; i < groups.length; i++) {
    const groupName = groups[i];
    onProgress?.(groupName, i, groups.length);

    try {
      const profile = await generateRansomwareProfile(groupName);
      await upsertRansomwareGroup(profile);

      // Also create/update a threat actor entry for Caldera integration
      await linkToThreatActor(profile);

      seeded++;
    } catch (err: any) {
      errors.push(`${groupName}: ${err.message}`);
    }

    // Small delay between LLM calls
    if (i < groups.length - 1) {
      await new Promise(r => setTimeout(r, 500));
    }
  }

  return { seeded, errors };
}

/**
 * Link a ransomware group profile to the threat_actors table
 * for Caldera adversary integration.
 */
async function linkToThreatActor(profile: RansomwareGroupProfile) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const actorId = profile.groupName.toLowerCase().replace(/[^a-z0-9]/g, "_");

  const existing = await db
    .select()
    .from(threatActors)
    .where(eq(threatActors.actorId, actorId))
    .limit(1);

  const actorData = {
    actorId,
    name: profile.groupName,
    aliases: profile.aliases,
    type: "ransomware" as const,
    origin: "Unknown",
    description: profile.description,
    motivation: "financial",
    firstSeen: profile.firstSeen,
    lastActive: profile.lastActive,
    threatLevel: (profile.activityScore >= 70 ? "critical" : profile.activityScore >= 40 ? "high" : profile.activityScore >= 20 ? "medium" : "low") as "critical" | "high" | "medium" | "low",
    sophistication: (profile.affiliateProgram ? "advanced" : "intermediate") as "nation-state" | "advanced" | "intermediate" | "basic",
    targetSectors: profile.topSectors,
    targetRegions: profile.topCountries,
    techniques: profile.mitreTechniques.map((t: string) => ({ id: t, name: t, tactic: "unknown", score: 1 })),
    tools: profile.associatedMalware,
    malware: [profile.ransomwareFamily],
    dataSource: "llm_enriched",
    confidence: 75,
  };

  if (existing.length > 0) {
    await db.update(threatActors).set(actorData).where(eq(threatActors.actorId, actorId));
  } else {
    await db.insert(threatActors).values(actorData);
  }

  // Update the ransomware group with the caldera actor ID link
  await db
    .update(ransomwareGroups)
    .set({ calderaActorId: actorId })
    .where(eq(ransomwareGroups.groupName, profile.groupName));
}

export { KNOWN_RANSOMWARE_GROUPS };
