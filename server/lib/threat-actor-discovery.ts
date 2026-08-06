/**
 * Threat Actor Discovery Engine
 * 
 * Uses LLM intelligence to discover new threat actors not yet in the catalog.
 * Multiple seed strategies: related actors, sector gaps, recent campaigns, IOC crossref.
 * All discoveries go through hallucination guardrails and require analyst approval.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import { threatActors, threatGroupEvents, undergroundIntelEvents } from "../../drizzle/schema";
import { eq, sql, desc, notInArray, count } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────

export type DiscoverySeedStrategy =
  | "related_actors"      // Find actors related to existing ones
  | "sector_gaps"         // Find actors targeting underrepresented sectors
  | "recent_campaigns"    // Discover actors from recent campaign intelligence
  | "emerging_threats"    // Find newly emerged or rebranded groups
  | "geographic_coverage" // Fill geographic blind spots in the catalog

export interface DiscoveredActor {
  suggestedId: string;
  name: string;
  aliases: string[];
  actorType: "apt" | "cybercrime" | "ransomware" | "hacktivist" | "access_broker" | "influence_ops";
  origin: string;
  description: string;
  motivation: string;
  firstSeen: string;
  lastActive: string;
  threatLevel: "critical" | "high" | "medium" | "low";
  sophistication: "nation-state" | "advanced" | "intermediate" | "basic";
  targetSectors: string[];
  targetRegions: string[];
  techniques: Array<{ id: string; name: string; tactic: string; description: string }>;
  tools: string[];
  malware: string[];
  notableAttacks: Array<{ victimName: string; sector: string; country: string; date: string; impactDescription: string; source: string }>;
  conflicts: string[];
  sources: Array<{
    field: string;
    sourceName: string;
    sourceType: "osint" | "darkweb" | "government" | "vendor_report" | "academic" | "llm_knowledge";
    sourceUrl: string;
    confidence: number;
  }>;
  discoveryReason: string;
  confidenceScore: number;
}

export interface DiscoveryResult {
  strategy: DiscoverySeedStrategy;
  seedContext: string;
  discoveredActors: DiscoveredActor[];
  alreadyKnown: string[];
  timestamp: string;
  llmModel: string;
}

// ─── Catalog Context Builder ────────────────────────────────────────────

async function getCatalogContext(): Promise<{
  existingNames: Set<string>;
  existingAliases: Set<string>;
  existingIds: Set<string>;
  actorTypeCounts: Record<string, number>;
  sectorCoverage: Record<string, number>;
  regionCoverage: Record<string, number>;
  recentEvents: any[];
  totalActors: number;
}> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // Get all existing actor names and aliases for dedup
  const actors = await db.select({
    actorId: threatActors.actorId,
    name: threatActors.name,
    aliases: threatActors.aliases,
    actorType: threatActors.actorType,
    targetSectors: threatActors.targetSectors,
    targetRegions: threatActors.targetRegions,
  }).from(threatActors);

  const existingNames = new Set<string>();
  const existingAliases = new Set<string>();
  const existingIds = new Set<string>();
  const actorTypeCounts: Record<string, number> = {};
  const sectorCoverage: Record<string, number> = {};
  const regionCoverage: Record<string, number> = {};

  for (const a of actors) {
    existingNames.add(a.name.toLowerCase());
    existingIds.add(a.actorId.toLowerCase());
    if (a.actorType) actorTypeCounts[a.actorType] = (actorTypeCounts[a.actorType] || 0) + 1;

    const aliases = safeArr(a.aliases);
    aliases.forEach((al: string) => existingAliases.add(al.toLowerCase()));

    const sectors = safeArr(a.targetSectors);
    sectors.forEach((s: string) => { sectorCoverage[s] = (sectorCoverage[s] || 0) + 1; });

    const regions = safeArr(a.targetRegions);
    regions.forEach((r: string) => { regionCoverage[r] = (regionCoverage[r] || 0) + 1; });
  }

  // Get recent events for campaign-based discovery
  const recentEvents = await db.select({
    title: threatGroupEvents.tgeTitle,
    description: threatGroupEvents.tgeDescription,
    actorId: threatGroupEvents.tgeActorId,
    eventType: threatGroupEvents.eventType,
    eventDate: threatGroupEvents.eventDate,
    source: threatGroupEvents.tgeSource,
  })
    .from(threatGroupEvents)
    .orderBy(desc(threatGroupEvents.eventDate))
    .limit(100);

  return {
    existingNames,
    existingAliases,
    existingIds,
    actorTypeCounts,
    sectorCoverage,
    regionCoverage,
    recentEvents,
    totalActors: actors.length,
  };
}

// ─── Strategy-Specific Prompt Builders ──────────────────────────────────

function buildRelatedActorsPrompt(ctx: Awaited<ReturnType<typeof getCatalogContext>>, seedActorNames?: string[]): { system: string; user: string } {
  const sampleActors = seedActorNames?.slice(0, 10).join(", ") || 
    Array.from(ctx.existingNames).slice(0, 30).join(", ");

  const system = `You are an elite cyber threat intelligence analyst specializing in threat actor attribution, group relationships, and the cyber threat landscape. Your knowledge spans APTs, ransomware operations, cybercrime syndicates, hacktivists, access brokers, and influence operations.

CRITICAL RULES:
1. Only suggest threat actors that are REAL and documented in public threat intelligence reports
2. Every actor MUST have at least 2 verifiable sources (government advisories, vendor reports, academic research, OSINT)
3. Do NOT fabricate actors — if you're uncertain, do not include them
4. Do NOT suggest actors that are just aliases of existing groups
5. Focus on actors active in 2023-2026 that are well-documented but may be missing from a catalog
6. For each actor, provide SPECIFIC source citations (e.g., "Mandiant APT44 report, April 2024")
7. Confidence score should reflect how well-documented the actor is (90+ = extensively documented, 70-89 = well-documented, 50-69 = moderately documented, <50 = emerging/limited documentation)`;

  const user = `Our threat actor catalog currently has ${ctx.totalActors} actors. Here is a sample of actors we already track:
${sampleActors}

Actor type distribution: ${JSON.stringify(ctx.actorTypeCounts)}

TASK: Identify 5-10 well-documented threat actors that are likely MISSING from our catalog. Focus on:
1. Groups that collaborate with, share infrastructure with, or are splinter groups of the actors listed above
2. Recently emerged or rebranded groups (2024-2026) that may not have been cataloged yet
3. Groups from underrepresented categories in our catalog
4. Groups that have been the subject of recent government advisories or vendor reports

Do NOT suggest any of these existing actors or their known aliases: ${Array.from(ctx.existingNames).slice(0, 100).join(", ")}`;

  return { system, user };
}

function buildSectorGapsPrompt(ctx: Awaited<ReturnType<typeof getCatalogContext>>): { system: string; user: string } {
  const sortedSectors = Object.entries(ctx.sectorCoverage).sort((a, b) => a[1] - b[1]);
  const underrepresented = sortedSectors.slice(0, 10).map(([s, c]) => `${s} (${c} actors)`).join(", ");
  const wellCovered = sortedSectors.slice(-5).map(([s, c]) => `${s} (${c} actors)`).join(", ");

  const system = `You are an elite cyber threat intelligence analyst. Your task is to identify threat actors that target specific industry sectors that are underrepresented in a threat intelligence catalog.

CRITICAL RULES:
1. Only suggest REAL, documented threat actors with verifiable sources
2. Every actor MUST have at least 2 source citations from government advisories, vendor reports, or academic research
3. Do NOT fabricate actors or sources
4. Focus on actors known to target the specified underrepresented sectors
5. Provide specific, verifiable source citations for each actor`;

  const user = `Our catalog has ${ctx.totalActors} actors. Sector coverage analysis:

UNDERREPRESENTED sectors: ${underrepresented}
WELL-COVERED sectors: ${wellCovered}

TASK: Identify 5-10 well-documented threat actors that specifically target the underrepresented sectors listed above. These actors should be real, documented in public threat intelligence, and NOT already in our catalog.

Do NOT suggest any of these existing actors: ${Array.from(ctx.existingNames).slice(0, 100).join(", ")}`;

  return { system, user };
}

function buildEmergingThreatsPrompt(ctx: Awaited<ReturnType<typeof getCatalogContext>>): { system: string; user: string } {
  const system = `You are an elite cyber threat intelligence analyst specializing in emerging threats and newly identified threat groups. You track the latest government advisories, vendor reports, and OSINT to identify new threat actors.

CRITICAL RULES:
1. Only suggest threat actors that are REAL and have been publicly documented since 2024
2. Every actor MUST have specific, verifiable source citations
3. Focus on groups that emerged, rebranded, or were first publicly attributed in 2024-2026
4. Include groups from recent CISA advisories, FBI flash alerts, Five Eyes joint advisories, and major vendor reports
5. Do NOT fabricate actors — every suggestion must be traceable to a public report
6. Confidence score reflects documentation quality: 90+ for groups with dedicated reports, 70-89 for groups mentioned in multiple advisories`;

  const user = `Our threat actor catalog has ${ctx.totalActors} actors but may be missing recently emerged groups.

Actor type distribution: ${JSON.stringify(ctx.actorTypeCounts)}

TASK: Identify 5-10 threat actors that have emerged, been newly attributed, or rebranded since 2024. Focus on:
1. Groups featured in recent government advisories (CISA, FBI, NSA, NCSC-UK, CERT-EU)
2. Groups identified in recent vendor threat reports (Mandiant, CrowdStrike, Microsoft, Unit 42)
3. Ransomware groups that emerged or rebranded in 2024-2026
4. APT groups newly attributed by intelligence agencies
5. Cybercrime groups involved in recent high-profile incidents

Do NOT suggest any of these existing actors: ${Array.from(ctx.existingNames).slice(0, 100).join(", ")}`;

  return { system, user };
}

function buildGeographicCoveragePrompt(ctx: Awaited<ReturnType<typeof getCatalogContext>>): { system: string; user: string } {
  const sortedRegions = Object.entries(ctx.regionCoverage).sort((a, b) => a[1] - b[1]);
  const underrepresented = sortedRegions.slice(0, 10).map(([r, c]) => `${r} (${c} actors)`).join(", ");

  const system = `You are an elite cyber threat intelligence analyst with global coverage of threat actors across all regions and geopolitical contexts.

CRITICAL RULES:
1. Only suggest REAL, documented threat actors with verifiable sources
2. Every actor MUST have at least 2 source citations
3. Focus on actors originating from or targeting underrepresented geographic regions
4. Do NOT fabricate actors or sources
5. Include actors from regions with active cyber operations but limited Western reporting`;

  const user = `Our catalog has ${ctx.totalActors} actors. Geographic coverage analysis:

UNDERREPRESENTED regions: ${underrepresented}

TASK: Identify 5-10 well-documented threat actors that originate from or primarily target the underrepresented regions listed above. These should be real groups documented in public threat intelligence.

Do NOT suggest any of these existing actors: ${Array.from(ctx.existingNames).slice(0, 100).join(", ")}`;

  return { system, user };
}

function buildRecentCampaignsPrompt(ctx: Awaited<ReturnType<typeof getCatalogContext>>): { system: string; user: string } {
  const recentEventSummary = ctx.recentEvents.slice(0, 30).map(e =>
    `- [${e.eventDate || "unknown"}] ${e.title} (actor: ${e.actorId}, type: ${e.eventType})`
  ).join("\n");

  const system = `You are an elite cyber threat intelligence analyst. Your task is to identify threat actors mentioned in recent campaign intelligence, incident reports, and advisories that may not yet be in a threat intelligence catalog.

CRITICAL RULES:
1. Only suggest REAL, documented threat actors
2. Every actor MUST have specific, verifiable source citations
3. Focus on actors involved in recent campaigns or incidents (2024-2026)
4. Cross-reference with known campaign clusters, intrusion sets, and activity groups
5. Do NOT fabricate actors or sources`;

  const user = `Our catalog tracks ${ctx.totalActors} actors. Here are recent events from our intelligence feeds:

${recentEventSummary || "No recent events available."}

TASK: Based on recent cyber threat campaigns and incidents (2024-2026), identify 5-10 threat actors that may be missing from our catalog. Consider:
1. Actors mentioned in recent incident response reports
2. Groups behind recent supply chain attacks or zero-day exploitation campaigns
3. Actors identified in recent law enforcement operations
4. Groups involved in recent critical infrastructure targeting

Do NOT suggest any of these existing actors: ${Array.from(ctx.existingNames).slice(0, 100).join(", ")}`;

  return { system, user };
}

// ─── LLM Response Schema ────────────────────────────────────────────────

const discoveryResponseSchema = {
  type: "json_schema" as const,
  json_schema: {
    name: "threat_actor_discovery",
    strict: true,
    schema: {
      type: "object",
      properties: {
        discoveredActors: {
          type: "array",
          items: {
            type: "object",
            properties: {
              name: { type: "string", description: "Primary name of the threat actor" },
              aliases: { type: "array", items: { type: "string" }, description: "Known aliases" },
              actorType: { type: "string", enum: ["apt", "cybercrime", "ransomware", "hacktivist", "access_broker", "influence_ops"] },
              origin: { type: "string", description: "Country or region of origin" },
              description: { type: "string", description: "Comprehensive 2-3 paragraph description" },
              motivation: { type: "string", description: "Primary motivation" },
              firstSeen: { type: "string", description: "First seen date (YYYY or YYYY-MM)" },
              lastActive: { type: "string", description: "Last known activity (YYYY-MM)" },
              threatLevel: { type: "string", enum: ["critical", "high", "medium", "low"] },
              sophistication: { type: "string", enum: ["nation-state", "advanced", "intermediate", "basic"] },
              targetSectors: { type: "array", items: { type: "string" } },
              targetRegions: { type: "array", items: { type: "string" } },
              techniques: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    id: { type: "string" },
                    name: { type: "string" },
                    tactic: { type: "string" },
                    description: { type: "string" },
                  },
                  required: ["id", "name", "tactic", "description"],
                  additionalProperties: false,
                },
              },
              tools: { type: "array", items: { type: "string" } },
              malware: { type: "array", items: { type: "string" } },
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
                    source: { type: "string" },
                  },
                  required: ["victimName", "sector", "country", "date", "impactDescription", "source"],
                  additionalProperties: false,
                },
              },
              conflicts: { type: "array", items: { type: "string" } },
              sources: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    field: { type: "string" },
                    sourceName: { type: "string" },
                    sourceType: { type: "string", enum: ["osint", "darkweb", "government", "vendor_report", "academic", "llm_knowledge"] },
                    sourceUrl: { type: "string" },
                    confidence: { type: "integer" },
                  },
                  required: ["field", "sourceName", "sourceType", "sourceUrl", "confidence"],
                  additionalProperties: false,
                },
              },
              discoveryReason: { type: "string", description: "Why this actor should be added to the catalog" },
              confidenceScore: { type: "integer", description: "0-100 overall confidence this is a real, distinct threat actor" },
            },
            required: [
              "name", "aliases", "actorType", "origin", "description", "motivation",
              "firstSeen", "lastActive", "threatLevel", "sophistication",
              "targetSectors", "targetRegions", "techniques", "tools", "malware",
              "notableAttacks", "conflicts", "sources", "discoveryReason", "confidenceScore",
            ],
            additionalProperties: false,
          },
        },
      },
      required: ["discoveredActors"],
      additionalProperties: false,
    },
  },
};

// ─── Main Discovery Function ────────────────────────────────────────────

export async function discoverNewActors(
  strategy: DiscoverySeedStrategy,
  seedActorNames?: string[],
): Promise<DiscoveryResult> {
  const ctx = await getCatalogContext();

  // Build strategy-specific prompt
  let prompt: { system: string; user: string };
  let seedContext: string;

  switch (strategy) {
    case "related_actors":
      prompt = buildRelatedActorsPrompt(ctx, seedActorNames);
      seedContext = seedActorNames?.length
        ? `Related to: ${seedActorNames.join(", ")}`
        : `Related to catalog of ${ctx.totalActors} actors`;
      break;
    case "sector_gaps":
      prompt = buildSectorGapsPrompt(ctx);
      seedContext = `Filling sector coverage gaps`;
      break;
    case "emerging_threats":
      prompt = buildEmergingThreatsPrompt(ctx);
      seedContext = `Emerging threats 2024-2026`;
      break;
    case "geographic_coverage":
      prompt = buildGeographicCoveragePrompt(ctx);
      seedContext = `Filling geographic coverage gaps`;
      break;
    case "recent_campaigns":
      prompt = buildRecentCampaignsPrompt(ctx);
      seedContext = `From recent campaign intelligence`;
      break;
    default:
      throw new Error(`Unknown discovery strategy: ${strategy}`);
  }

  // Call LLM
  const response = await invokeLLM({
    _caller: "threat-actor-discovery.discoverNewActors",
    _priority: "essential",
    messages: [
      { role: "system", content: prompt.system },
      { role: "user", content: prompt.user },
    ],
    response_format: discoveryResponseSchema,
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") throw new Error("LLM returned empty discovery result");
  const parsed = JSON.parse(content);

  // Deduplicate against existing catalog
  const alreadyKnown: string[] = [];
  const genuinelyNew: DiscoveredActor[] = [];

  for (const actor of (parsed.discoveredActors || [])) {
    const nameLower = actor.name.toLowerCase();
    const aliasesLower = (actor.aliases || []).map((a: string) => a.toLowerCase());

    // Check if already in catalog by name, alias, or generated ID
    const isKnown =
      ctx.existingNames.has(nameLower) ||
      ctx.existingAliases.has(nameLower) ||
      aliasesLower.some((a: string) => ctx.existingNames.has(a) || ctx.existingAliases.has(a)) ||
      ctx.existingIds.has(nameLower.replace(/[^a-z0-9]/g, "-"));

    if (isKnown) {
      alreadyKnown.push(actor.name);
      continue;
    }

    // Generate a clean actor ID
    const suggestedId = actor.name
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, "")
      .replace(/\s+/g, "-")
      .substring(0, 128);

    // Validate: must have sources and reasonable confidence
    const hasVerifiableSources = (actor.sources || []).some(
      (s: any) => s.sourceType !== "llm_knowledge" && s.confidence >= 60
    );

    if (!hasVerifiableSources) {
      // Downgrade confidence if no verifiable sources
      actor.confidenceScore = Math.min(actor.confidenceScore, 40);
    }

    genuinelyNew.push({
      ...actor,
      suggestedId,
    });
  }

  return {
    strategy,
    seedContext,
    discoveredActors: genuinelyNew,
    alreadyKnown,
    timestamp: new Date().toISOString(),
    llmModel: "default",
  };
}

// ─── Commit Discovered Actor to DB ──────────────────────────────────────

export async function commitDiscoveredActor(actor: DiscoveredActor): Promise<{ actorId: string; success: boolean; error?: string }> {
  const db = await getDb();
  if (!db) return { actorId: actor.suggestedId, success: false, error: "Database not available" };

  try {
    // Check for duplicate one more time
    const existing = await db.select({ id: threatActors.id })
      .from(threatActors)
      .where(eq(threatActors.actorId, actor.suggestedId))
      .limit(1);

    if (existing.length > 0) {
      return { actorId: actor.suggestedId, success: false, error: "Actor already exists in catalog" };
    }

    // Build enrichment sources from discovery sources
    const enrichmentSources = JSON.stringify({
      sources: (actor.sources || []).map((s) => ({
        field: s.field,
        value: "",
        source: s.sourceName,
        sourceType: s.sourceType,
        sourceUrl: s.sourceUrl || undefined,
        confidence: s.confidence,
        retrievedAt: new Date().toISOString(),
      })),
      discoveryMetadata: {
        discoveryReason: actor.discoveryReason,
        confidenceScore: actor.confidenceScore,
        discoveredAt: new Date().toISOString(),
      },
    });

    await db.insert(threatActors).values({
      actorId: actor.suggestedId,
      name: actor.name,
      aliases: JSON.stringify(actor.aliases || []),
      actorType: actor.actorType,
      origin: actor.origin || null,
      description: actor.description || null,
      motivation: actor.motivation || null,
      firstSeen: actor.firstSeen || null,
      lastActive: actor.lastActive || null,
      threatLevel: actor.threatLevel || "medium",
      sophistication: actor.sophistication || "intermediate",
      targetSectors: JSON.stringify(actor.targetSectors || []),
      targetRegions: JSON.stringify(actor.targetRegions || []),
      techniques: JSON.stringify(actor.techniques || []),
      tools: JSON.stringify(actor.tools || []),
      malware: JSON.stringify(actor.malware || []),
      activityTimeline: JSON.stringify([]),
      conflicts: (actor.conflicts || []).join(", "),
      dataSource: "llm_discovery",
      confidence: Math.min(actor.confidenceScore, 85), // Cap at 85 for discovered actors
      enrichmentSources,
    });

    return { actorId: actor.suggestedId, success: true };
  } catch (err: any) {
    return { actorId: actor.suggestedId, success: false, error: err.message };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────

function safeArr(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; }
  }
  return [];
}
