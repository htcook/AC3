import {
  init_llm,
  invokeLLM
} from "./chunk-AOUQ6RTC.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  init_schema,
  threatActorIocs,
  threatActors,
  threatGroupEvents,
  undergroundIntelEvents
} from "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/keyword-enrichment.ts
init_llm();
init_db();
init_schema();
import { eq, desc, like, or } from "drizzle-orm";
function buildKeywordSet(actor) {
  const primary = [];
  const secondary = [];
  const contextual = [];
  const darkweb = [];
  if (actor.name) primary.push(actor.name);
  if (actor.actorId && actor.actorId !== actor.name?.toLowerCase().replace(/[^a-z0-9]/g, "_")) {
    primary.push(actor.actorId);
  }
  const aliases = safeArr(actor.aliases);
  aliases.forEach((a) => {
    if (a && a.length > 1) primary.push(a);
  });
  const tools = safeArr(actor.tools);
  tools.forEach((t) => {
    if (t) secondary.push(t);
  });
  const malware = safeArr(actor.malware);
  malware.forEach((m) => {
    if (m) secondary.push(m);
  });
  const techniques = safeArr(actor.techniques);
  techniques.forEach((t) => {
    if (typeof t === "object" && t.id) secondary.push(t.id);
    if (typeof t === "object" && t.name) secondary.push(t.name);
  });
  const sectors = safeArr(actor.targetSectors);
  sectors.forEach((s) => {
    if (s) contextual.push(s);
  });
  const regions = safeArr(actor.targetRegions);
  regions.forEach((r) => {
    if (r) contextual.push(r);
  });
  if (actor.origin && actor.origin !== "Unknown") contextual.push(actor.origin);
  if (actor.motivation) contextual.push(actor.motivation);
  const darkwebKeywords = buildDarkwebKeywords(actor);
  darkweb.push(...darkwebKeywords);
  return {
    primary: [...new Set(primary)].slice(0, 10),
    secondary: [...new Set(secondary)].slice(0, 15),
    contextual: [...new Set(contextual)].slice(0, 10),
    darkweb: [...new Set(darkweb)].slice(0, 10)
  };
}
function buildDarkwebKeywords(actor) {
  const keywords = [];
  const name = (actor.name || "").toLowerCase();
  const desc2 = (actor.description || "").toLowerCase();
  const forumKeywords = [
    "RAMP",
    "BreachForums",
    "XSS",
    "Exploit.in",
    "RaidForums",
    "Dread",
    "AlphaBay",
    "Genesis Market",
    "Russian Market",
    "Telegram",
    "Tox",
    "Jabber",
    "I2P",
    "Tor"
  ];
  forumKeywords.forEach((f) => {
    if (desc2.includes(f.toLowerCase())) keywords.push(f);
  });
  if (actor.actorType === "ransomware") {
    keywords.push(`${actor.name} leak site`);
    keywords.push(`${actor.name} ransomware victims`);
    keywords.push(`${actor.name} DLS`);
  }
  if (actor.actorType === "apt") {
    keywords.push(`${actor.name} campaign`);
    keywords.push(`${actor.name} infrastructure`);
    keywords.push(`${actor.name} C2`);
  }
  if (actor.actorType === "cybercrime") {
    keywords.push(`${actor.name} operations`);
    keywords.push(`${actor.name} arrests`);
  }
  if (actor.actorType === "hacktivist") {
    keywords.push(`${actor.name} operations`);
    keywords.push(`${actor.name} claims`);
    keywords.push(`${actor.name} DDoS`);
  }
  return keywords;
}
async function gatherLocalContext(actorId, actorName, aliases) {
  const db = await getDb();
  if (!db) return { tgeEvents: [], uieEvents: [], iocs: [], summary: "Database unavailable" };
  const nameVariants = [actorName, ...aliases].filter(Boolean);
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
    mitreTechniques: threatGroupEvents.tgeMitreTechniques
  }).from(threatGroupEvents).where(eq(threatGroupEvents.tgeActorId, actorId)).orderBy(desc(threatGroupEvents.eventDate)).limit(50);
  let uieEvents = [];
  if (nameVariants.length > 0) {
    const nameConditions = nameVariants.map(
      (n) => like(undergroundIntelEvents.uieActorName, `%${n}%`)
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
      mitreTechniques: undergroundIntelEvents.uieMitreTechniques
    }).from(undergroundIntelEvents).where(or(...nameConditions)).orderBy(desc(undergroundIntelEvents.uieEventDate)).limit(50);
  }
  const iocs = await db.select().from(threatActorIocs).where(eq(threatActorIocs.actorId, actorId)).limit(100);
  const summary = `Found ${tgeEvents.length} threat group events, ${uieEvents.length} underground intel events, and ${iocs.length} IOCs for ${actorName}`;
  return { tgeEvents, uieEvents, iocs, summary };
}
function analyzeGaps(actor) {
  const missingFields = [];
  const staleFields = [];
  const qualityIssues = [];
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
  if (actor.lastActive) {
    const lastDate = new Date(actor.lastActive);
    const daysSince = Math.floor((Date.now() - lastDate.getTime()) / (1e3 * 60 * 60 * 24));
    if (daysSince > 180) staleFields.push(`lastActive (${daysSince} days old)`);
  }
  return { missingFields, staleFields, qualityIssues };
}
function buildResearchPrompt(actor, keywords, localContext, gaps) {
  const tgeSnippets = localContext.tgeEvents.slice(0, 20).map(
    (e) => `- [${e.eventDate || "unknown date"}] ${e.title} (${e.source || "unknown source"}) \u2014 ${(e.description || "").substring(0, 200)}`
  ).join("\n");
  const uieSnippets = localContext.uieEvents.slice(0, 20).map(
    (e) => `- [${e.eventDate || "unknown date"}] [${e.category}] ${e.title} (source: ${e.source || "unknown"}) \u2014 ${(e.description || "").substring(0, 200)}`
  ).join("\n");
  const iocSnippets = localContext.iocs.slice(0, 20).map(
    (i) => `- ${i.iocType}: ${i.iocValue} (confidence: ${i.iocConfidence})`
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
    techniques: safeArr(actor.techniques).map((t) => typeof t === "object" ? `${t.id} ${t.name}` : t),
    description: actor.description ? actor.description.substring(0, 500) : null
  };
  const system = `You are an elite cyber threat intelligence analyst with deep expertise in APTs, ransomware operations, cybercrime syndicates, and hacktivist movements. You have access to intelligence from OSINT, government advisories, vendor reports, academic research, and darkweb monitoring.

Your task is to research a threat actor using the provided keywords and context, then produce a comprehensive intelligence enrichment with FULL SOURCE ATTRIBUTION for every piece of data.

CRITICAL RULES:
1. Every data point MUST include a source attribution (report name, advisory ID, vendor blog post, darkweb forum, etc.)
2. Include darkweb sources: ransomware leak sites, underground forums (RAMP, XSS, Exploit.in, BreachForums), Telegram channels, paste sites
3. Include government sources: CISA advisories, FBI flash alerts, NSA/CSS advisories, NCSC-UK, CERT-EU, Five Eyes joint advisories
4. Include vendor reports: Mandiant, CrowdStrike, Microsoft MSTIC, Unit 42, Recorded Future, Securelist, SentinelOne, Proofpoint, ESET
5. Include academic/research: MITRE ATT&CK, academic papers, conference presentations (Black Hat, DEF CON, S4)
6. Do NOT fabricate sources \u2014 if you're uncertain about a source, mark confidence as low
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
${tgeSnippets ? `
Threat Group Events (${localContext.tgeEvents.length} total):
${tgeSnippets}` : "\nNo threat group events found."}
${uieSnippets ? `
Underground Intel Events (${localContext.uieEvents.length} total):
${uieSnippets}` : "\nNo underground intel events found."}
${iocSnippets ? `
Known IOCs (${localContext.iocs.length} total):
${iocSnippets}` : "\nNo IOCs found."}

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
async function enrichActorWithKeywords(actorId) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (!actor) throw new Error(`Actor not found: ${actorId}`);
  const keywords = buildKeywordSet(actor);
  const gaps = analyzeGaps(actor);
  const aliases = safeArr(actor.aliases);
  const localContext = await gatherLocalContext(actorId, actor.name, aliases);
  const { system, user } = buildResearchPrompt(actor, keywords, localContext, gaps);
  const response = await invokeLLM({
    _caller: "keyword-enrichment.enrichActorWithKeywords",
    _priority: "essential",
    // Use high-quality model for research
    messages: [
      { role: "system", content: system },
      { role: "user", content: user }
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
                  description: { type: "string" }
                },
                required: ["id", "name", "tactic", "description"],
                additionalProperties: false
              }
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
                  source: { type: "string" }
                },
                required: ["victimName", "sector", "country", "date", "impactDescription", "source"],
                additionalProperties: false
              }
            },
            activityTimeline: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  date: { type: "string" },
                  event: { type: "string" },
                  source: { type: "string" }
                },
                required: ["date", "event", "source"],
                additionalProperties: false
              }
            },
            conflicts: {
              type: "array",
              items: { type: "string" },
              description: "Geopolitical conflicts this actor is tied to"
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
                  confidence: { type: "integer", description: "0-100 confidence" }
                },
                required: ["field", "value", "sourceName", "sourceType", "sourceUrl", "confidence"],
                additionalProperties: false
              },
              description: "Source attribution for each data point"
            },
            summary: { type: "string", description: "2-3 sentence summary of what was discovered" },
            dataQualityScore: { type: "integer", description: "0-100 overall data quality score" }
          },
          required: [
            "description",
            "motivation",
            "origin",
            "firstSeen",
            "lastActive",
            "threatLevel",
            "sophistication",
            "activityScore",
            "trend",
            "aliases",
            "targetSectors",
            "targetRegions",
            "techniques",
            "tools",
            "malware",
            "notableAttacks",
            "activityTimeline",
            "conflicts",
            "sources",
            "summary",
            "dataQualityScore"
          ],
          additionalProperties: false
        }
      }
    }
  });
  const content = response.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") throw new Error("LLM returned empty enrichment");
  const parsed = JSON.parse(content);
  const sources = (parsed.sources || []).map((s) => ({
    field: s.field,
    value: s.value,
    source: s.sourceName,
    sourceType: s.sourceType,
    sourceUrl: s.sourceUrl || void 0,
    confidence: s.confidence,
    retrievedAt: (/* @__PURE__ */ new Date()).toISOString()
  }));
  if (localContext.tgeEvents.length > 0) {
    sources.push({
      field: "activityTimeline",
      value: `${localContext.tgeEvents.length} threat group events from internal database`,
      source: "AC3 Internal Database (threat_group_events)",
      sourceType: "internal_db",
      confidence: 95,
      retrievedAt: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  if (localContext.uieEvents.length > 0) {
    sources.push({
      field: "activityTimeline",
      value: `${localContext.uieEvents.length} underground intel events from internal database`,
      source: "AC3 Internal Database (underground_intel_events)",
      sourceType: "internal_db",
      confidence: 95,
      retrievedAt: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  const { applyGuardrails } = await import("./enrichment-guardrails-ZPHHRDW7.js");
  const guardrailResult = applyGuardrails(parsed, sources, localContext, actor);
  const { sanitizedData, report: guardrailReport } = guardrailResult;
  console.log(`[Guardrails] ${actorId}: trust=${guardrailReport.overallTrustScore}%, accepted=${guardrailReport.accepted}, flagged=${guardrailReport.flagged}, rejected=${guardrailReport.rejected}`);
  if (guardrailReport.warnings.length > 0) {
    console.log(`[Guardrails] ${actorId} warnings:`, guardrailReport.warnings.join("; "));
  }
  if (guardrailReport.rejectedFields.length > 0) {
    console.log(`[Guardrails] ${actorId} REJECTED fields:`, guardrailReport.rejectedFields.join(", "));
  }
  const validated = sanitizedData;
  const fieldsUpdated = [];
  const fieldsDiscovered = [];
  const checkField = (field, newVal, oldVal) => {
    if (!newVal || Array.isArray(newVal) && newVal.length === 0) return;
    if (guardrailReport.rejectedFields.includes(field)) return;
    if (!oldVal || typeof oldVal === "string" && oldVal.length < 10 || Array.isArray(oldVal) && oldVal.length === 0) {
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
  const updates = {};
  if (validated.description && validated.description.length > 50) updates.description = validated.description;
  if (validated.motivation && validated.motivation !== "unknown") updates.motivation = validated.motivation;
  if (validated.origin && validated.origin !== "Unknown") updates.origin = validated.origin;
  if (validated.firstSeen) updates.firstSeen = validated.firstSeen;
  if (validated.threatLevel) updates.threatLevel = validated.threatLevel;
  if (validated.sophistication) updates.sophistication = validated.sophistication;
  if (validated.aliases?.length > 0) {
    const existing = safeArr(actor.aliases);
    const merged = [.../* @__PURE__ */ new Set([...existing, ...validated.aliases])];
    updates.aliases = JSON.stringify(merged);
  }
  if (validated.targetSectors?.length > 0) {
    const existing = safeArr(actor.targetSectors);
    const merged = [.../* @__PURE__ */ new Set([...existing, ...validated.targetSectors])];
    updates.targetSectors = JSON.stringify(merged);
  }
  if (validated.targetRegions?.length > 0) {
    const existing = safeArr(actor.targetRegions);
    const merged = [.../* @__PURE__ */ new Set([...existing, ...validated.targetRegions])];
    updates.targetRegions = JSON.stringify(merged);
  }
  if (validated.techniques?.length > 0) {
    const existing = safeArr(actor.techniques);
    const existingIds = new Set(existing.map((t) => t.id));
    const newTechs = validated.techniques.filter((t) => !existingIds.has(t.id));
    if (newTechs.length > 0) {
      updates.techniques = JSON.stringify([...existing, ...newTechs]);
    }
  }
  if (validated.tools?.length > 0) {
    const existing = safeArr(actor.tools);
    const merged = [.../* @__PURE__ */ new Set([...existing, ...validated.tools])];
    updates.tools = JSON.stringify(merged);
  }
  if (validated.malware?.length > 0) {
    const existing = safeArr(actor.malware);
    const merged = [.../* @__PURE__ */ new Set([...existing, ...validated.malware])];
    updates.malware = JSON.stringify(merged);
  }
  if (validated.activityTimeline?.length > 0) {
    const existing = safeArr(actor.activityTimeline);
    const existingKeys = new Set(existing.map((e) => `${e.date}|${e.event}`));
    const newEntries = validated.activityTimeline.filter((e) => !existingKeys.has(`${e.date}|${e.event}`));
    if (newEntries.length > 0) {
      updates.activityTimeline = JSON.stringify([...existing, ...newEntries]);
    }
  }
  if (validated.conflicts?.length > 0) {
    const existingConflicts = actor.conflicts ? actor.conflicts.split(",").map((c) => c.trim()) : [];
    const merged = [.../* @__PURE__ */ new Set([...existingConflicts, ...validated.conflicts])].filter(Boolean);
    updates.conflicts = merged.join(", ");
  }
  if (validated.lastActive) {
    if (!actor.lastActive || validated.lastActive > actor.lastActive) {
      updates.lastActive = validated.lastActive;
    }
  }
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
      verdicts: guardrailReport.verdicts
    }
  });
  updates.dataSource = "keyword_enriched";
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
      guardrailReport
    },
    summary: parsed.summary || `Enriched ${fieldsDiscovered.length} new fields and updated ${fieldsUpdated.length} existing fields`,
    dataQualityScore: guardrailAdjustedQuality
  };
}
function safeArr(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    try {
      const p = JSON.parse(v);
      return Array.isArray(p) ? p : [];
    } catch {
      return [];
    }
  }
  return [];
}
export {
  buildKeywordSet,
  enrichActorWithKeywords
};
