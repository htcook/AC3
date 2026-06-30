/**
 * Keyword-Driven LLM Enrichment Service
 * 
 * Builds targeted keyword lists from threat actor details, gathers context
 * from local databases (underground_intel_events, threat_group_events) and
 * darkweb sources, then uses the LLM to research and discover new intelligence
 * with full source attribution.
 * 
 * Goal: Make the AC3 threat actor catalog the best in the industry.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import {
  threatActors,
  threatGroupEvents,
  undergroundIntelEvents,
  threatActorIocs,
} from "../../drizzle/schema";
import { eq, sql, desc, like, or, and } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────

export interface KeywordSet {
  primary: string[];      // Actor name + aliases
  secondary: string[];    // Tools, malware, techniques
  contextual: string[];   // Sectors, regions, campaigns
  darkweb: string[];      // Forum names, leak sites, underground handles
}

export interface SourceAttribution {
  field: string;          // Which field this data populates
  value: string;          // The data value
  source: string;         // Source name (e.g., "CISA Advisory AA25-071A")
  sourceType: "osint" | "darkweb" | "government" | "vendor_report" | "academic" | "internal_db" | "llm_knowledge";
  sourceUrl?: string;     // URL if available
  confidence: number;     // 0-100
  retrievedAt: string;    // ISO timestamp
}

export interface EnrichmentResult {
  actorId: string;
  keywordsUsed: KeywordSet;
  fieldsUpdated: string[];
  fieldsDiscovered: string[];
  sources: SourceAttribution[];
  enrichedData: {
    description?: string;
    motivation?: string;
    origin?: string;
    firstSeen?: string;
    lastActive?: string;
    aliases?: string[];
    targetSectors?: string[];
    targetRegions?: string[];
    techniques?: Array<{ id: string; name: string; tactic: string; description: string }>;
    tools?: string[];
    malware?: string[];
    notableAttacks?: Array<{ victimName: string; sector: string; country: string; date: string; impactDescription: string; source: string }>;
    activityTimeline?: Array<{ date: string; event: string; source: string }>;
    conflicts?: string[];
    threatLevel?: string;
    sophistication?: string;
    activityScore?: number;
    trend?: string;
  };
  summary: string;
  dataQualityScore: number;  // 0-100 overall quality
}

// ─── Keyword Builder ────────────────────────────────────────────────────

/**
 * Build a comprehensive keyword set from an actor's existing data.
 * These keywords drive the LLM research prompt.
 */
export function buildKeywordSet(actor: any): KeywordSet {
  const primary: string[] = [];
  const secondary: string[] = [];
  const contextual: string[] = [];
  const darkweb: string[] = [];

  // Primary: Name and aliases
  if (actor.name) primary.push(actor.name);
  if (actor.actorId && actor.actorId !== actor.name?.toLowerCase().replace(/[^a-z0-9]/g, "_")) {
    primary.push(actor.actorId);
  }
  const aliases = safeArr(actor.aliases);
  aliases.forEach((a: string) => { if (a && a.length > 1) primary.push(a); });

  // Secondary: Tools, malware, techniques
  const tools = safeArr(actor.tools);
  tools.forEach((t: string) => { if (t) secondary.push(t); });
  
  const malware = safeArr(actor.malware);
  malware.forEach((m: string) => { if (m) secondary.push(m); });
  
  const techniques = safeArr(actor.techniques);
  techniques.forEach((t: any) => {
    if (typeof t === "object" && t.id) secondary.push(t.id);
    if (typeof t === "object" && t.name) secondary.push(t.name);
  });

  // Contextual: Sectors, regions, motivation
  const sectors = safeArr(actor.targetSectors);
  sectors.forEach((s: string) => { if (s) contextual.push(s); });
  
  const regions = safeArr(actor.targetRegions);
  regions.forEach((r: string) => { if (r) contextual.push(r); });
  
  if (actor.origin && actor.origin !== "Unknown") contextual.push(actor.origin);
  if (actor.motivation) contextual.push(actor.motivation);

  // Darkweb: Forum names, underground identifiers
  const darkwebKeywords = buildDarkwebKeywords(actor);
  darkweb.push(...darkwebKeywords);

  return {
    primary: [...new Set(primary)].slice(0, 10),
    secondary: [...new Set(secondary)].slice(0, 15),
    contextual: [...new Set(contextual)].slice(0, 10),
    darkweb: [...new Set(darkweb)].slice(0, 10),
  };
}

function buildDarkwebKeywords(actor: any): string[] {
  const keywords: string[] = [];
  const name = (actor.name || "").toLowerCase();
  const desc = (actor.description || "").toLowerCase();
  
  // Known forum/darkweb associations
  const forumKeywords = [
    "RAMP", "BreachForums", "XSS", "Exploit.in", "RaidForums",
    "Dread", "AlphaBay", "Genesis Market", "Russian Market",
    "Telegram", "Tox", "Jabber", "I2P", "Tor",
  ];
  
  forumKeywords.forEach(f => {
    if (desc.includes(f.toLowerCase())) keywords.push(f);
  });

  // Ransomware-specific: leak site, DLS, negotiation
  if (actor.actorType === "ransomware") {
    keywords.push(`${actor.name} leak site`);
    keywords.push(`${actor.name} ransomware victims`);
    keywords.push(`${actor.name} DLS`);
  }

  // APT-specific: C2 infrastructure, campaigns
  if (actor.actorType === "apt") {
    keywords.push(`${actor.name} campaign`);
    keywords.push(`${actor.name} infrastructure`);
    keywords.push(`${actor.name} C2`);
  }

  // Cybercrime-specific: marketplace, carding
  if (actor.actorType === "cybercrime") {
    keywords.push(`${actor.name} operations`);
    keywords.push(`${actor.name} arrests`);
  }

  // Hacktivist-specific: operations, claims
  if (actor.actorType === "hacktivist") {
    keywords.push(`${actor.name} operations`);
    keywords.push(`${actor.name} claims`);
    keywords.push(`${actor.name} DDoS`);
  }

  return keywords;
}

// ─── Local Context Gatherer ─────────────────────────────────────────────

/**
 * Gather all local intelligence context for an actor from our databases.
 * This provides the LLM with real data to cross-reference and validate.
 */
async function gatherLocalContext(actorId: string, actorName: string, aliases: string[]): Promise<{
  tgeEvents: any[];
  uieEvents: any[];
  iocs: any[];
  summary: string;
}> {
  const db = await getDb();
  if (!db) return { tgeEvents: [], uieEvents: [], iocs: [], summary: "Database unavailable" };

  // Build name match conditions for UIE (matches by actor_name)
  const nameVariants = [actorName, ...aliases].filter(Boolean);
  
  // 1. Threat Group Events (matched by actorId)
  const tgeEvents = await db.select({
    title: threatGroupEvents.tgeTitle,
    description: threatGroupEvents.tgeDescription,
    severity: threatGroupEvents.tgeSeverity,
    victimName: threatGroupEvents.tgeVictimName,
    victimSector: threatGroupEvents.tgeVictimSector,
    victimCountry: threatGroupEvents.tgeVictimCountry,
    source: threatGroupEvents.tgeSource,
    sourceUrl: threatGroupEvents.tgeSourceUrl,
    eventDate: threatGroupEvents.eventDate,
    eventType: threatGroupEvents.eventType,
    mitreTechniques: threatGroupEvents.tgeMitreTechniques,
  })
    .from(threatGroupEvents)
    .where(eq(threatGroupEvents.tgeActorId, actorId))
    .orderBy(desc(threatGroupEvents.eventDate))
    .limit(50);

  // 2. Underground Intel Events (matched by actor name or aliases)
  let uieEvents: any[] = [];
  if (nameVariants.length > 0) {
    const nameConditions = nameVariants.map(n => 
      like(undergroundIntelEvents.uieActorName, `%${n}%`)
    );
    uieEvents = await db.select({
      title: undergroundIntelEvents.uieTitle,
      description: undergroundIntelEvents.uieDescription,
      category: undergroundIntelEvents.uieCategory,
      source: undergroundIntelEvents.uieSource,
      sourceUrl: undergroundIntelEvents.uieSourceUrl,
      severity: undergroundIntelEvents.uieSeverity,
      actorName: undergroundIntelEvents.uieActorName,
      victimName: undergroundIntelEvents.uieVictimName,
      victimSector: undergroundIntelEvents.uieVictimSector,
      victimCountry: undergroundIntelEvents.uieVictimCountry,
      eventDate: undergroundIntelEvents.uieEventDate,
      mitreTechniques: undergroundIntelEvents.uieMitreTechniques,
    })
      .from(undergroundIntelEvents)
      .where(or(...nameConditions))
      .orderBy(desc(undergroundIntelEvents.uieEventDate))
      .limit(50);
  }

  // 3. IOCs
  const iocs = await db.select()
    .from(threatActorIocs)
    .where(eq(threatActorIocs.actorId, actorId))
    .limit(100);

  const summary = `Found ${tgeEvents.length} threat group events, ${uieEvents.length} underground intel events, and ${iocs.length} IOCs for ${actorName}`;

  return { tgeEvents, uieEvents, iocs, summary };
}

// ─── Gap Analyzer ───────────────────────────────────────────────────────

/**
 * Analyze what data is missing or stale for an actor.
 */
function analyzeGaps(actor: any): { missingFields: string[]; staleFields: string[]; qualityIssues: string[] } {
  const missingFields: string[] = [];
  const staleFields: string[] = [];
  const qualityIssues: string[] = [];

  if (!actor.description || actor.description.length < 50) missingFields.push("description");
  if (!actor.motivation || actor.motivation === "unknown") missingFields.push("motivation");
  if (!actor.origin || actor.origin === "Unknown") missingFields.push("origin");
  if (!actor.firstSeen) missingFields.push("firstSeen");
  if (!actor.lastActive) missingFields.push("lastActive");
  
  const aliases = safeArr(actor.aliases);
  if (aliases.length === 0) missingFields.push("aliases");
  
  const sectors = safeArr(actor.targetSectors);
  if (sectors.length === 0) missingFields.push("targetSectors");
  
  const regions = safeArr(actor.targetRegions);
  if (regions.length === 0) missingFields.push("targetRegions");
  
  const techniques = safeArr(actor.techniques);
  if (techniques.length === 0) missingFields.push("techniques");
  else if (techniques.length < 3) qualityIssues.push("techniques (fewer than 3 mapped)");
  
  const tools = safeArr(actor.tools);
  if (tools.length === 0) missingFields.push("tools");
  
  const malware = safeArr(actor.malware);
  if (malware.length === 0) missingFields.push("malware");

  if (!actor.sophistication) missingFields.push("sophistication");
  if (!actor.threatLevel) missingFields.push("threatLevel");
  if (!actor.conflicts) missingFields.push("conflicts");

  // Check staleness
  if (actor.lastActive) {
    const lastDate = new Date(actor.lastActive);
    const daysSince = Math.floor((Date.now() - lastDate.getTime()) / (1000 * 60 * 60 * 24));
    if (daysSince > 180) staleFields.push(`lastActive (${daysSince} days old)`);
  }

  return { missingFields, staleFields, qualityIssues };
}

// ─── LLM Research Prompt Builder ────────────────────────────────────────

/**
 * Build a comprehensive research prompt that includes keywords, local context,
 * and specific instructions for darkweb source inclusion.
 */
function buildResearchPrompt(
  actor: any,
  keywords: KeywordSet,
  localContext: { tgeEvents: any[]; uieEvents: any[]; iocs: any[] },
  gaps: { missingFields: string[]; staleFields: string[]; qualityIssues: string[] },
): { system: string; user: string } {
  
  // Format local context for the prompt
  const tgeSnippets = localContext.tgeEvents.slice(0, 20).map(e => 
    `- [${e.eventDate || "unknown date"}] ${e.title} (${e.source || "unknown source"}) — ${(e.description || "").substring(0, 200)}`
  ).join("\n");

  const uieSnippets = localContext.uieEvents.slice(0, 20).map(e =>
    `- [${e.eventDate || "unknown date"}] [${e.category}] ${e.title} (source: ${e.source || "unknown"}) — ${(e.description || "").substring(0, 200)}`
  ).join("\n");

  const iocSnippets = localContext.iocs.slice(0, 20).map(i =>
    `- ${i.iocType}: ${i.iocValue} (confidence: ${i.iocConfidence})`
  ).join("\n");

  const existingData = {
    name: actor.name,
    aliases: safeArr(actor.aliases),
    type: actor.actorType,
    origin: actor.origin,
    motivation: actor.motivation,
    firstSeen: actor.firstSeen,
    lastActive: actor.lastActive,
    targetSectors: safeArr(actor.targetSectors),
    targetRegions: safeArr(actor.targetRegions),
    tools: safeArr(actor.tools),
    malware: safeArr(actor.malware),
    techniques: safeArr(actor.techniques).map((t: any) => typeof t === "object" ? `${t.id} ${t.name}` : t),
    description: actor.description ? (actor.description as string).substring(0, 500) : null,
  };

  const system = `You are an elite cyber threat intelligence analyst with deep expertise in APTs, ransomware operations, cybercrime syndicates, and hacktivist movements. You have access to intelligence from OSINT, government advisories, vendor reports, academic research, and darkweb monitoring.

Your task is to research a threat actor using the provided keywords and context, then produce a comprehensive intelligence enrichment with FULL SOURCE ATTRIBUTION for every piece of data.

CRITICAL RULES:
1. Every data point MUST include a source attribution (report name, advisory ID, vendor blog post, darkweb forum, etc.)
2. Include darkweb sources: ransomware leak sites, underground forums (RAMP, XSS, Exploit.in, BreachForums), Telegram channels, paste sites
3. Include government sources: CISA advisories, FBI flash alerts, NSA/CSS advisories, NCSC-UK, CERT-EU, Five Eyes joint advisories
4. Include vendor reports: Mandiant, CrowdStrike, Microsoft MSTIC, Unit 42, Recorded Future, Securelist, SentinelOne, Proofpoint, ESET
5. Include academic/research: MITRE ATT&CK, academic papers, conference presentations (Black Hat, DEF CON, S4)
6. Do NOT fabricate sources — if you're uncertain about a source, mark confidence as low
7. For MITRE techniques, use exact T-codes (e.g., T1566.001) and map to the correct tactic
8. Prioritize recent intelligence (2024-2026) but include historical context where relevant
9. Cross-reference multiple sources for higher confidence ratings`;

  const user = `RESEARCH TARGET: ${actor.name} (ID: ${actor.actorId})
Type: ${actor.actorType || "unknown"}

SEARCH KEYWORDS:
- Primary (actor identifiers): ${keywords.primary.join(", ")}
- Secondary (tools/malware/TTPs): ${keywords.secondary.join(", ") || "none known"}
- Contextual (sectors/regions): ${keywords.contextual.join(", ") || "none known"}
- Darkweb (forums/handles): ${keywords.darkweb.join(", ") || "none known"}

EXISTING DATA IN OUR CATALOG:
${JSON.stringify(existingData, null, 2)}

LOCAL INTELLIGENCE CONTEXT (from our databases):
${tgeSnippets ? `\nThreat Group Events (${localContext.tgeEvents.length} total):\n${tgeSnippets}` : "\nNo threat group events found."}
${uieSnippets ? `\nUnderground Intel Events (${localContext.uieEvents.length} total):\n${uieSnippets}` : "\nNo underground intel events found."}
${iocSnippets ? `\nKnown IOCs (${localContext.iocs.length} total):\n${iocSnippets}` : "\nNo IOCs found."}

DATA GAPS TO FILL:
- Missing fields: ${gaps.missingFields.join(", ") || "none"}
- Stale data: ${gaps.staleFields.join(", ") || "none"}
- Quality issues: ${gaps.qualityIssues.join(", ") || "none"}

INSTRUCTIONS:
1. Research this actor using the keywords above
2. Fill in ALL missing fields with sourced data
3. Update stale fields with the latest intelligence
4. Discover any NEW information not in our catalog (new campaigns, new TTPs, new victims, rebrands, law enforcement actions)
5. For each piece of data, provide the source name, source type, URL if available, and confidence level (0-100)
6. Include intelligence from darkweb monitoring (forum posts, leak site activity, underground marketplace listings)
7. Write a comprehensive 3-4 paragraph description if the current one is missing or thin
8. Map ALL known MITRE ATT&CK techniques with exact T-codes`;

  return { system, user };
}

// ─── Main Enrichment Function ───────────────────────────────────────────

/**
 * Run the full keyword-driven enrichment pipeline for a threat actor.
 */
export async function enrichActorWithKeywords(actorId: string): Promise<EnrichmentResult> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // 1. Load the actor
  const [actor] = await db.select().from(threatActors)
    .where(eq(threatActors.actorId, actorId))
    .limit(1);
  if (!actor) throw new Error(`Actor not found: ${actorId}`);

  // 2. Build keyword set
  const keywords = buildKeywordSet(actor);

  // 3. Analyze gaps
  const gaps = analyzeGaps(actor);

  // 4. Gather local context
  const aliases = safeArr(actor.aliases);
  const localContext = await gatherLocalContext(actorId, actor.name, aliases);

  // 5. Build research prompt
  const { system, user } = buildResearchPrompt(actor, keywords, localContext, gaps);

  // 6. Call LLM with structured output
  const response = await invokeLLM({
    _caller: "keyword-enrichment.enrichActorWithKeywords",
    _priority: "essential",  // Use high-quality model for research
    messages: [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "actor_enrichment_with_sources",
        strict: true,
        schema: {
          type: "object",
          properties: {
            description: { type: "string", description: "Comprehensive 3-4 paragraph description" },
            motivation: { type: "string", description: "Primary motivation" },
            origin: { type: "string", description: "Country/region of origin" },
            firstSeen: { type: "string", description: "First seen date (YYYY or YYYY-MM)" },
            lastActive: { type: "string", description: "Last known activity date (YYYY-MM)" },
            threatLevel: { type: "string", enum: ["critical", "high", "medium", "low"] },
            sophistication: { type: "string", enum: ["nation-state", "advanced", "intermediate", "basic"] },
            activityScore: { type: "integer", description: "0-100 activity score" },
            trend: { type: "string", enum: ["surging", "active", "declining", "dormant"] },
            aliases: { type: "array", items: { type: "string" }, description: "All known aliases" },
            targetSectors: { type: "array", items: { type: "string" }, description: "Targeted sectors" },
            targetRegions: { type: "array", items: { type: "string" }, description: "Targeted regions" },
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
            activityTimeline: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  date: { type: "string" },
                  event: { type: "string" },
                  source: { type: "string" },
                },
                required: ["date", "event", "source"],
                additionalProperties: false,
              },
            },
            conflicts: {
              type: "array",
              items: { type: "string" },
              description: "Geopolitical conflicts this actor is tied to",
            },
            sources: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  field: { type: "string", description: "Which field this source supports" },
                  value: { type: "string", description: "Summary of the data point" },
                  sourceName: { type: "string", description: "Source name (e.g., CISA Advisory AA25-071A)" },
                  sourceType: { type: "string", enum: ["osint", "darkweb", "government", "vendor_report", "academic", "llm_knowledge"] },
                  sourceUrl: { type: "string", description: "URL if available, empty string if not" },
                  confidence: { type: "integer", description: "0-100 confidence" },
                },
                required: ["field", "value", "sourceName", "sourceType", "sourceUrl", "confidence"],
                additionalProperties: false,
              },
              description: "Source attribution for each data point",
            },
            summary: { type: "string", description: "2-3 sentence summary of what was discovered" },
            dataQualityScore: { type: "integer", description: "0-100 overall data quality score" },
          },
          required: [
            "description", "motivation", "origin", "firstSeen", "lastActive",
            "threatLevel", "sophistication", "activityScore", "trend",
            "aliases", "targetSectors", "targetRegions", "techniques",
            "tools", "malware", "notableAttacks", "activityTimeline",
            "conflicts", "sources", "summary", "dataQualityScore",
          ],
          additionalProperties: false,
        },
      },
    },
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") throw new Error("LLM returned empty enrichment");
  const parsed = JSON.parse(content);

  // 7. Build source attributions
  const sources: SourceAttribution[] = (parsed.sources || []).map((s: any) => ({
    field: s.field,
    value: s.value,
    source: s.sourceName,
    sourceType: s.sourceType,
    sourceUrl: s.sourceUrl || undefined,
    confidence: s.confidence,
    retrievedAt: new Date().toISOString(),
  }));

  // Add internal DB sources
  if (localContext.tgeEvents.length > 0) {
    sources.push({
      field: "activityTimeline",
      value: `${localContext.tgeEvents.length} threat group events from internal database`,
      source: "AC3 Internal Database (threat_group_events)",
      sourceType: "internal_db",
      confidence: 95,
      retrievedAt: new Date().toISOString(),
    });
  }
  if (localContext.uieEvents.length > 0) {
    sources.push({
      field: "activityTimeline",
      value: `${localContext.uieEvents.length} underground intel events from internal database`,
      source: "AC3 Internal Database (underground_intel_events)",
      sourceType: "internal_db",
      confidence: 95,
      retrievedAt: new Date().toISOString(),
    });
  }

  // 8. HALLUCINATION GUARDRAILS — validate LLM output before writing to DB
  const { applyGuardrails } = await import("./enrichment-guardrails");
  const guardrailResult = applyGuardrails(parsed, sources, localContext, actor);
  const { sanitizedData, report: guardrailReport } = guardrailResult;

  // Log guardrail results for audit trail
  console.log(`[Guardrails] ${actorId}: trust=${guardrailReport.overallTrustScore}%, accepted=${guardrailReport.accepted}, flagged=${guardrailReport.flagged}, rejected=${guardrailReport.rejected}`);
  if (guardrailReport.warnings.length > 0) {
    console.log(`[Guardrails] ${actorId} warnings:`, guardrailReport.warnings.join("; "));
  }
  if (guardrailReport.rejectedFields.length > 0) {
    console.log(`[Guardrails] ${actorId} REJECTED fields:`, guardrailReport.rejectedFields.join(", "));
  }

  // Use sanitized data (rejected fields removed) instead of raw parsed data
  const validated = sanitizedData;

  // 8b. Determine what fields were updated vs discovered
  const fieldsUpdated: string[] = [];
  const fieldsDiscovered: string[] = [];

  const checkField = (field: string, newVal: any, oldVal: any) => {
    if (!newVal || (Array.isArray(newVal) && newVal.length === 0)) return;
    // Skip fields that were rejected by guardrails
    if (guardrailReport.rejectedFields.includes(field)) return;
    if (!oldVal || (typeof oldVal === "string" && oldVal.length < 10) || (Array.isArray(oldVal) && oldVal.length === 0)) {
      fieldsDiscovered.push(field);
    } else {
      fieldsUpdated.push(field);
    }
  };

  checkField("description", validated.description, actor.description);
  checkField("motivation", validated.motivation, actor.motivation);
  checkField("origin", validated.origin, actor.origin);
  checkField("firstSeen", validated.firstSeen, actor.firstSeen);
  checkField("aliases", validated.aliases, safeArr(actor.aliases));
  checkField("targetSectors", validated.targetSectors, safeArr(actor.targetSectors));
  checkField("targetRegions", validated.targetRegions, safeArr(actor.targetRegions));
  checkField("techniques", validated.techniques, safeArr(actor.techniques));
  checkField("tools", validated.tools, safeArr(actor.tools));
  checkField("malware", validated.malware, safeArr(actor.malware));
  checkField("notableAttacks", validated.notableAttacks, []);
  checkField("activityTimeline", validated.activityTimeline, safeArr(actor.activityTimeline));
  checkField("conflicts", validated.conflicts, actor.conflicts);

  // 9. Apply updates to database (using guardrail-validated data)
  const updates: Record<string, any> = {};

  if (validated.description && validated.description.length > 50) updates.description = validated.description;
  if (validated.motivation && validated.motivation !== "unknown") updates.motivation = validated.motivation;
  if (validated.origin && validated.origin !== "Unknown") updates.origin = validated.origin;
  if (validated.firstSeen) updates.firstSeen = validated.firstSeen;
  if (validated.threatLevel) updates.threatLevel = validated.threatLevel;
  if (validated.sophistication) updates.sophistication = validated.sophistication;

  // Merge arrays (don't overwrite, extend) — using guardrail-validated data
  if (validated.aliases?.length > 0) {
    const existing = safeArr(actor.aliases);
    const merged = [...new Set([...existing, ...validated.aliases])];
    updates.aliases = JSON.stringify(merged);
  }
  if (validated.targetSectors?.length > 0) {
    const existing = safeArr(actor.targetSectors);
    const merged = [...new Set([...existing, ...validated.targetSectors])];
    updates.targetSectors = JSON.stringify(merged);
  }
  if (validated.targetRegions?.length > 0) {
    const existing = safeArr(actor.targetRegions);
    const merged = [...new Set([...existing, ...validated.targetRegions])];
    updates.targetRegions = JSON.stringify(merged);
  }
  if (validated.techniques?.length > 0) {
    const existing = safeArr(actor.techniques);
    const existingIds = new Set(existing.map((t: any) => t.id));
    const newTechs = validated.techniques.filter((t: any) => !existingIds.has(t.id));
    if (newTechs.length > 0) {
      updates.techniques = JSON.stringify([...existing, ...newTechs]);
    }
  }
  if (validated.tools?.length > 0) {
    const existing = safeArr(actor.tools);
    const merged = [...new Set([...existing, ...validated.tools])];
    updates.tools = JSON.stringify(merged);
  }
  if (validated.malware?.length > 0) {
    const existing = safeArr(actor.malware);
    const merged = [...new Set([...existing, ...validated.malware])];
    updates.malware = JSON.stringify(merged);
  }
  if (validated.activityTimeline?.length > 0) {
    const existing = safeArr(actor.activityTimeline);
    // Deduplicate by date+event
    const existingKeys = new Set(existing.map((e: any) => `${e.date}|${e.event}`));
    const newEntries = validated.activityTimeline.filter((e: any) => !existingKeys.has(`${e.date}|${e.event}`));
    if (newEntries.length > 0) {
      updates.activityTimeline = JSON.stringify([...existing, ...newEntries]);
    }
  }
  if (validated.conflicts?.length > 0) {
    const existingConflicts = actor.conflicts ? actor.conflicts.split(",").map((c: string) => c.trim()) : [];
    const merged = [...new Set([...existingConflicts, ...validated.conflicts])].filter(Boolean);
    updates.conflicts = merged.join(", ");
  }

  // Update lastActive only if newer
  if (validated.lastActive) {
    if (!actor.lastActive || validated.lastActive > actor.lastActive) {
      updates.lastActive = validated.lastActive;
    }
  }

  // Store enrichment sources + guardrail report
  updates.enrichmentSources = JSON.stringify({
    sources,
    guardrailReport: {
      overallTrustScore: guardrailReport.overallTrustScore,
      accepted: guardrailReport.accepted,
      flagged: guardrailReport.flagged,
      rejected: guardrailReport.rejected,
      warnings: guardrailReport.warnings,
      rejectedFields: guardrailReport.rejectedFields,
      flaggedFields: guardrailReport.flaggedFields,
      verdicts: guardrailReport.verdicts,
    },
  });
  updates.dataSource = "keyword_enriched";
  // Adjust confidence based on guardrail trust score
  const guardrailAdjustedQuality = Math.round((parsed.dataQualityScore || 70) * (guardrailReport.overallTrustScore / 100));
  updates.confidence = Math.min(95, Math.max(guardrailAdjustedQuality, actor.confidence || 0));

  if (Object.keys(updates).length > 0) {
    await db.update(threatActors).set(updates).where(eq(threatActors.actorId, actorId));
  }

  return {
    actorId,
    keywordsUsed: keywords,
    fieldsUpdated,
    fieldsDiscovered,
    sources,
    enrichedData: {
      description: validated.description,
      motivation: validated.motivation,
      origin: validated.origin,
      firstSeen: validated.firstSeen,
      lastActive: validated.lastActive,
      aliases: validated.aliases,
      targetSectors: validated.targetSectors,
      targetRegions: validated.targetRegions,
      techniques: validated.techniques,
      tools: validated.tools,
      malware: validated.malware,
      notableAttacks: validated.notableAttacks,
      activityTimeline: validated.activityTimeline,
      conflicts: validated.conflicts,
      threatLevel: validated.threatLevel,
      sophistication: validated.sophistication,
      activityScore: validated.activityScore,
      trend: validated.trend,
      guardrailReport: guardrailReport,
    },
    summary: parsed.summary || `Enriched ${fieldsDiscovered.length} new fields and updated ${fieldsUpdated.length} existing fields`,
    dataQualityScore: guardrailAdjustedQuality,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────

function safeArr(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; }
  }
  return [];
}
