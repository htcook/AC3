import {
  init_llm,
  invokeLLM
} from "./chunk-D3Z2XQH2.js";
import {
  getDb,
  init_db
} from "./chunk-3OPUTHKA.js";
import {
  init_schema,
  ransomwareGroups,
  threatActorIocs,
  threatActors,
  threatGroupEvents,
  threatIntelUpdates
} from "./chunk-H7DAFEQB.js";

// server/lib/threat-intel-catalog.ts
init_llm();
init_db();
init_schema();
import { eq, desc, sql, and, like, inArray } from "drizzle-orm";
var SEED_GROUPS = {
  ransomware: [
    "LockBit",
    "BlackCat/ALPHV",
    "Cl0p",
    "Play",
    "8Base",
    "Akira",
    "BianLian",
    "Medusa",
    "NoEscape",
    "Rhysida",
    "Hunters International",
    "BlackBasta",
    "Royal",
    "Vice Society",
    "Hive",
    "Conti",
    "REvil/Sodinokibi",
    "DarkSide",
    "BlackMatter",
    "Ragnar Locker",
    "Maze",
    "Ryuk",
    "Cuba",
    "AvosLocker",
    "Karakurt",
    "Lorenz",
    "Snatch",
    "INC Ransom",
    "Cactus",
    "RansomHub",
    "Qilin",
    "Fog",
    "Meow",
    "DragonForce",
    "Embargo",
    "Lynx",
    "Cicada3301",
    "Sarcoma",
    "Funksec",
    "NightSpire",
    "Morpheus",
    "Termite"
  ],
  apt: [
    "APT28/Fancy Bear",
    "APT29/Cozy Bear",
    "APT1/Comment Crew",
    "APT3/Gothic Panda",
    "APT10/Stone Panda",
    "APT33/Elfin",
    "APT34/OilRig",
    "APT35/Charming Kitten",
    "APT38/Lazarus Group",
    "APT40/Leviathan",
    "APT41/Winnti",
    "Turla/Venomous Bear",
    "Sandworm",
    "Gamaredon",
    "Kimsuky",
    "MuddyWater",
    "Volt Typhoon",
    "Salt Typhoon",
    "Flax Typhoon",
    "Mustang Panda",
    "Patchwork",
    "SideWinder",
    "OceanLotus/APT32",
    "Equation Group",
    "DarkHotel",
    "Scarab",
    "Transparent Tribe",
    "Bitter",
    "Hafnium",
    "Nobelium",
    "Star Blizzard",
    "Charming Kitten/APT35",
    "MuddyWater/Mercury"
  ],
  cybercrime: [
    "FIN7/Carbanak",
    "FIN8",
    "FIN11",
    "FIN12",
    "Scattered Spider",
    "LAPSUS$",
    "Evil Corp",
    "Wizard Spider",
    "Gold Southfield",
    "TA505",
    "TA551",
    "SilverTerrier",
    "Cobalt Group",
    "Magecart",
    "Emotet Gang",
    "QakBot Operators",
    "IcedID Operators",
    "BazarLoader Gang"
  ],
  hacktivist: [
    "Anonymous",
    "KillNet",
    "NoName057(16)",
    "IT Army of Ukraine",
    "GhostSec",
    "SiegedSec",
    "Cyber Av3ngers",
    "CyberArmyofRussia_Reborn",
    "Anonymous Sudan",
    "DragonForce Malaysia",
    "Mysterious Team Bangladesh"
  ],
  unknown: []
};
var ALIAS_DEDUP = {
  "Charming Kitten/APT35": "APT35/Charming Kitten",
  "MuddyWater/Mercury": "MuddyWater"
};
function getCanonicalName(name) {
  return ALIAS_DEDUP[name] ?? name;
}
function getAllSeedGroups() {
  const seen = /* @__PURE__ */ new Set();
  const result = [];
  for (const [type, names] of Object.entries(SEED_GROUPS)) {
    if (type === "unknown") continue;
    for (const name of names) {
      const canonical = getCanonicalName(name);
      if (!seen.has(canonical.toLowerCase())) {
        seen.add(canonical.toLowerCase());
        result.push({ name: canonical, type });
      }
    }
  }
  return result;
}
async function generateGroupProfile(groupName, groupType) {
  const typePrompts = {
    ransomware: `You are a senior threat intelligence analyst specializing in ransomware operations.
Generate a comprehensive profile for the ransomware group "${groupName}".
Include: ransomware family, extortion model (single/double/triple), RaaS affiliate program status,
victim counts, leak site infrastructure, notable attacks with ransom demands.
Activity scores: surging (70-100), active (40-69), declining (20-39), dormant (0-19).`,
    apt: `You are a senior threat intelligence analyst specializing in nation-state APT groups.
Generate a comprehensive profile for the APT group "${groupName}".
Include: sponsoring nation, strategic objectives, target sectors/regions, signature TTPs,
custom tooling, notable campaigns, infrastructure patterns, and sophistication level.
Activity scores: surging (70-100), active (40-69), declining (20-39), dormant (0-19).`,
    cybercrime: `You are a senior threat intelligence analyst specializing in cybercrime organizations.
Generate a comprehensive profile for the cybercrime group "${groupName}".
Include: financial motivation details, attack methodologies, monetization strategies,
notable heists/campaigns, law enforcement actions, infrastructure, and affiliate networks.
Activity scores: surging (70-100), active (40-69), declining (20-39), dormant (0-19).`,
    hacktivist: `You are a senior threat intelligence analyst specializing in hacktivist movements.
Generate a comprehensive profile for the hacktivist group "${groupName}".
Include: ideological motivation, geopolitical alignment, typical attack methods (DDoS, defacement, data leaks),
notable operations, communication channels, and organizational structure.
Activity scores: surging (70-100), active (40-69), declining (20-39), dormant (0-19).`,
    unknown: `You are a senior threat intelligence analyst. Generate a profile for the threat group "${groupName}".`
  };
  const response = await invokeLLM({
    _caller: "threat-intel-catalog",
    _priority: "bulk",
    messages: [
      { role: "system", content: typePrompts[groupType] },
      {
        role: "user",
        content: `Generate a comprehensive threat intelligence profile for: "${groupName}".
Include all known aliases, MITRE ATT&CK techniques (specific T-codes like T1566.001), associated tools/malware,
targeting patterns, notable attacks/campaigns, and infrastructure details.
For techniques, include the tactic category (initial-access, execution, persistence, etc.) and a brief description.`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "threat_group_profile",
        strict: true,
        schema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Primary name of the group" },
            aliases: { type: "array", items: { type: "string" }, description: "Known aliases and alternate names" },
            type: { type: "string", enum: ["apt", "cybercrime", "ransomware", "hacktivist", "unknown"] },
            origin: { type: "string", description: "Country or region of origin" },
            description: { type: "string", description: "3-4 paragraph comprehensive overview" },
            motivation: { type: "string", description: "Primary motivation (espionage, financial, disruption, ideological)" },
            firstSeen: { type: "string", description: "First seen date or year" },
            lastActive: { type: "string", description: "Last known activity date" },
            sophistication: { type: "string", enum: ["nation-state", "advanced", "intermediate", "basic"] },
            activityScore: { type: "integer", description: "0-100 composite activity score" },
            trend: { type: "string", enum: ["surging", "active", "declining", "dormant"] },
            targetSectors: { type: "array", items: { type: "string" }, description: "Top targeted sectors" },
            targetRegions: { type: "array", items: { type: "string" }, description: "Top targeted countries/regions" },
            techniques: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "string", description: "MITRE technique ID (e.g. T1566.001)" },
                  name: { type: "string", description: "Technique name" },
                  tactic: { type: "string", description: "MITRE tactic category" },
                  description: { type: "string", description: "Brief description of how this group uses this technique" }
                },
                required: ["id", "name", "tactic", "description"],
                additionalProperties: false
              },
              description: "MITRE ATT&CK techniques used by this group"
            },
            tools: { type: "array", items: { type: "string" }, description: "Tools and frameworks used" },
            malware: { type: "array", items: { type: "string" }, description: "Associated malware families" },
            knownInfrastructure: { type: "array", items: { type: "string" }, description: "Known infrastructure (C2, leak sites, etc.)" },
            notableAttacks: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  victimName: { type: "string" },
                  sector: { type: "string" },
                  country: { type: "string" },
                  date: { type: "string" },
                  impactDescription: { type: "string" }
                },
                required: ["victimName", "sector", "country", "date", "impactDescription"],
                additionalProperties: false
              }
            },
            // Ransomware-specific fields
            ransomwareFamily: { type: "string", description: "Ransomware family (ransomware groups only)" },
            extortionModel: { type: "string", enum: ["single", "double", "triple", "unknown"] },
            affiliateProgram: { type: "boolean", description: "Whether group runs RaaS affiliate program" },
            victims7d: { type: "integer", description: "Estimated victims in last 7 days" },
            victims30d: { type: "integer", description: "Estimated victims in last 30 days" },
            totalVictims: { type: "integer", description: "Total known victims" }
          },
          required: [
            "name",
            "aliases",
            "type",
            "origin",
            "description",
            "motivation",
            "firstSeen",
            "lastActive",
            "sophistication",
            "activityScore",
            "trend",
            "targetSectors",
            "targetRegions",
            "techniques",
            "tools",
            "malware",
            "knownInfrastructure",
            "notableAttacks",
            "ransomwareFamily",
            "extortionModel",
            "affiliateProgram",
            "victims7d",
            "victims30d",
            "totalVictims"
          ],
          additionalProperties: false
        }
      }
    }
  });
  const content = response.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") throw new Error(`LLM returned empty profile for ${groupName}`);
  const parsed = JSON.parse(content);
  const actorId = groupName.toLowerCase().replace(/[^a-z0-9]/g, "_");
  const threatLevel = parsed.activityScore >= 70 ? "critical" : parsed.activityScore >= 40 ? "high" : parsed.activityScore >= 20 ? "medium" : "low";
  return {
    actorId,
    name: parsed.name || groupName,
    aliases: parsed.aliases ?? [],
    type: parsed.type ?? groupType,
    origin: parsed.origin ?? "Unknown",
    description: parsed.description ?? "",
    motivation: parsed.motivation ?? "unknown",
    firstSeen: parsed.firstSeen ?? "",
    lastActive: parsed.lastActive ?? "",
    threatLevel,
    sophistication: parsed.sophistication ?? "intermediate",
    targetSectors: parsed.targetSectors ?? [],
    targetRegions: parsed.targetRegions ?? [],
    techniques: parsed.techniques ?? [],
    tools: parsed.tools ?? [],
    malware: parsed.malware ?? [],
    knownInfrastructure: parsed.knownInfrastructure ?? [],
    notableAttacks: parsed.notableAttacks ?? [],
    activityScore: parsed.activityScore ?? 0,
    trend: parsed.trend ?? "active",
    ransomwareFamily: parsed.ransomwareFamily || void 0,
    extortionModel: parsed.extortionModel || void 0,
    affiliateProgram: parsed.affiliateProgram ?? false,
    victims7d: parsed.victims7d ?? 0,
    victims30d: parsed.victims30d ?? 0,
    totalVictims: parsed.totalVictims ?? 0
  };
}
async function upsertGroupToCatalog(profile) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const existing = await db.select().from(threatActors).where(eq(threatActors.actorId, profile.actorId)).limit(1);
  const actorData = {
    actorId: profile.actorId,
    name: profile.name,
    aliases: profile.aliases,
    actorType: profile.type,
    origin: profile.origin,
    description: profile.description,
    motivation: profile.motivation,
    firstSeen: profile.firstSeen,
    lastActive: profile.lastActive,
    threatLevel: profile.threatLevel,
    sophistication: profile.sophistication,
    targetSectors: profile.targetSectors,
    targetRegions: profile.targetRegions,
    techniques: profile.techniques,
    tools: profile.tools,
    malware: profile.malware,
    dataSource: "llm_enriched",
    confidence: 80,
    activityTimeline: profile.notableAttacks.map((a) => ({
      date: a.date,
      event: `Attack on ${a.victimName}: ${a.impactDescription}`,
      source: "llm_enriched"
    }))
  };
  if (existing.length > 0) {
    await db.update(threatActors).set(actorData).where(eq(threatActors.actorId, profile.actorId));
  } else {
    await db.insert(threatActors).values(actorData);
  }
  if (profile.type === "ransomware") {
    await syncToRansomwareTable(profile);
  }
  return profile.actorId;
}
async function syncToRansomwareTable(profile) {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select().from(ransomwareGroups).where(eq(ransomwareGroups.groupName, profile.name)).limit(1);
  const rwData = {
    groupName: profile.name,
    aliases: profile.aliases,
    description: profile.description,
    activityScore: profile.activityScore,
    trend: profile.trend,
    rwThreatLevel: profile.threatLevel,
    victims7D: profile.victims7d ?? 0,
    victims30D: profile.victims30d ?? 0,
    totalVictims: profile.totalVictims ?? 0,
    topSectors: profile.targetSectors,
    topCountries: profile.targetRegions,
    associatedMalware: [...profile.malware, ...profile.tools],
    mitreTechniques: profile.techniques.map((t) => t.id),
    ransomwareFamily: profile.ransomwareFamily ?? profile.name,
    extortionModel: profile.extortionModel ?? "unknown",
    affiliateProgram: profile.affiliateProgram ?? false,
    knownInfrastructure: profile.knownInfrastructure,
    notableAttacks: profile.notableAttacks,
    rwFirstSeen: profile.firstSeen,
    rwLastActive: profile.lastActive,
    calderaActorId: profile.actorId,
    rwDataSource: "llm_enriched",
    rwConfidence: 80,
    lastEnriched: (/* @__PURE__ */ new Date()).toISOString()
  };
  if (existing.length > 0) {
    await db.update(ransomwareGroups).set(rwData).where(eq(ransomwareGroups.groupName, profile.name));
  } else {
    await db.insert(ransomwareGroups).values(rwData);
  }
}
async function recordGroupEvent(event) {
  const db = await getDb();
  if (!db) return;
  await db.insert(threatGroupEvents).values({
    tgeActorId: event.actorId,
    eventType: event.eventType,
    tgeTitle: event.title,
    tgeDescription: event.description,
    tgeSeverity: event.severity ?? "medium",
    tgeVictimName: event.victimName,
    tgeVictimSector: event.victimSector,
    tgeVictimCountry: event.victimCountry,
    tgeMitreTechniques: event.mitreTechniques,
    tgeIocs: event.iocs,
    tgeSource: event.source,
    tgeSourceUrl: event.sourceUrl,
    tgeConfidence: event.confidence ?? 75,
    eventDate: event.eventDate ?? /* @__PURE__ */ new Date()
  });
}
async function listGroups(filters) {
  const db = await getDb();
  if (!db) return { groups: [], total: 0 };
  const conditions = [];
  if (filters?.type) conditions.push(eq(threatActors.actorType, filters.type));
  if (filters?.threatLevel) conditions.push(eq(threatActors.threatLevel, filters.threatLevel));
  if (filters?.origin) conditions.push(like(threatActors.origin, `%${filters.origin}%`));
  if (filters?.search) {
    conditions.push(
      sql`(${threatActors.name} LIKE ${`%${filters.search}%`} OR JSON_SEARCH(${threatActors.aliases}, 'one', ${`%${filters.search}%`}) IS NOT NULL)`
    );
  }
  const where = conditions.length > 0 ? and(...conditions) : void 0;
  const [groups, countResult] = await Promise.all([
    db.select().from(threatActors).where(where).orderBy(desc(threatActors.confidence), desc(threatActors.updatedAt)).limit(filters?.limit ?? 200).offset(filters?.offset ?? 0),
    db.select({ count: sql`COUNT(*)` }).from(threatActors).where(where)
  ]);
  return { groups, total: countResult[0]?.count ?? 0 };
}
async function getGroupDetail(actorId) {
  const db = await getDb();
  if (!db) return null;
  const [actors, events, iocs] = await Promise.all([
    db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1),
    db.select().from(threatGroupEvents).where(eq(threatGroupEvents.tgeActorId, actorId)).orderBy(desc(threatGroupEvents.eventDate)).limit(100),
    db.select().from(threatActorIocs).where(eq(threatActorIocs.actorId, actorId)).limit(200)
  ]);
  if (actors.length === 0) return null;
  let ransomwareData = null;
  if (actors[0].actorType === "ransomware") {
    const rwRows = await db.select().from(ransomwareGroups).where(eq(ransomwareGroups.calderaActorId, actorId)).limit(1);
    ransomwareData = rwRows[0] ?? null;
  }
  return {
    actor: actors[0],
    events,
    iocs,
    ransomwareData
  };
}
async function getCatalogStats() {
  const db = await getDb();
  if (!db) return {
    totalGroups: 0,
    byType: [],
    byThreatLevel: [],
    byTrend: [],
    topOrigins: [],
    recentlyUpdated: 0
  };
  const [
    allGroups,
    typeStats,
    threatLevelStats,
    originStats,
    recentCount,
    lastSweepRows
  ] = await Promise.all([
    db.select({ count: sql`COUNT(*)` }).from(threatActors),
    db.select({
      type: threatActors.actorType,
      count: sql`COUNT(*)`
    }).from(threatActors).groupBy(threatActors.actorType),
    db.select({
      level: threatActors.threatLevel,
      count: sql`COUNT(*)`
    }).from(threatActors).groupBy(threatActors.threatLevel),
    db.select({
      origin: threatActors.origin,
      count: sql`COUNT(*)`
    }).from(threatActors).groupBy(threatActors.origin).orderBy(desc(sql`COUNT(*)`)).limit(10),
    db.select({ count: sql`COUNT(*)` }).from(threatActors).where(sql`${threatActors.updatedAt} > NOW() - INTERVAL 7 DAY`),
    db.select().from(threatIntelUpdates).orderBy(desc(threatIntelUpdates.tiuStartedAt)).limit(1)
  ]);
  const groups = await db.select({
    actorId: threatActors.actorId,
    activityTimeline: threatActors.activityTimeline
  }).from(threatActors);
  const trendMap = /* @__PURE__ */ new Map();
  for (const g of groups) {
    const timeline = g.activityTimeline ?? [];
    const recentEvents = timeline.filter((e) => {
      const d = new Date(e.date);
      return d.getTime() > Date.now() - 90 * 24 * 60 * 60 * 1e3;
    }).length;
    const trend = recentEvents >= 5 ? "surging" : recentEvents >= 2 ? "active" : recentEvents >= 1 ? "declining" : "dormant";
    trendMap.set(trend, (trendMap.get(trend) ?? 0) + 1);
  }
  return {
    totalGroups: allGroups[0]?.count ?? 0,
    byType: typeStats.map((r) => ({ type: r.type, count: r.count })),
    byThreatLevel: threatLevelStats.map((r) => ({ level: r.level ?? "medium", count: r.count })),
    byTrend: Array.from(trendMap.entries()).map(([trend, count]) => ({ trend, count })),
    topOrigins: originStats.map((r) => ({ origin: r.origin ?? "Unknown", count: r.count })),
    recentlyUpdated: recentCount[0]?.count ?? 0,
    lastSweep: lastSweepRows[0]?.startedAt?.toISOString()
  };
}
async function autoDiscoverGroup(groupName, groupType = "unknown", source = "auto_discovery") {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const actorId = groupName.toLowerCase().replace(/[^a-z0-9]/g, "_");
  const existing = await db.select({ actorId: threatActors.actorId }).from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (existing.length > 0) return actorId;
  try {
    const profile = await generateGroupProfile(groupName, groupType);
    await upsertGroupToCatalog(profile);
    await recordGroupEvent({
      actorId,
      eventType: "campaign",
      title: `Auto-discovered: ${groupName}`,
      description: `New threat group "${groupName}" discovered via ${source}. Full profile generated and added to master catalog.`,
      severity: "info",
      source
    });
    return actorId;
  } catch (err) {
    await db.insert(threatActors).values({
      actorId,
      name: groupName,
      aliases: [],
      actorType: groupType,
      origin: "Unknown",
      description: `Auto-discovered via ${source}. Full profile pending.`,
      motivation: "unknown",
      dataSource: source,
      confidence: 30
    });
    return actorId;
  }
}
async function runMonitoringSweep(onProgress, groupIds) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const [sweepRow] = await db.insert(threatIntelUpdates).values({
    sweepType: "manual",
    tiuStatus: "running",
    tiuStartedAt: /* @__PURE__ */ new Date()
  });
  const sweepId = sweepRow.insertId;
  let groups;
  if (groupIds && groupIds.length > 0) {
    groups = await db.select().from(threatActors).where(inArray(threatActors.actorId, groupIds));
  } else {
    groups = await db.select().from(threatActors).orderBy(desc(threatActors.confidence));
  }
  const result = {
    sweepId,
    groupsScanned: 0,
    updatesApplied: 0,
    newEventsFound: 0,
    newIocsFound: 0,
    newTtpsFound: 0,
    summary: "",
    details: [],
    errors: []
  };
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i];
    onProgress?.(group.name, i, groups.length);
    result.groupsScanned++;
    try {
      const updateResult = await monitorSingleGroup(group);
      if (updateResult.changes.length > 0) {
        result.updatesApplied++;
        result.newEventsFound += updateResult.newEvents;
        result.newIocsFound += updateResult.newIocs;
        result.newTtpsFound += updateResult.newTtps;
        result.details.push({ groupName: group.name, changes: updateResult.changes });
      }
    } catch (err) {
      result.errors.push(`${group.name}: ${err.message}`);
    }
    if (i < groups.length - 1) await new Promise((r) => setTimeout(r, 300));
  }
  result.summary = `Scanned ${result.groupsScanned} groups. Applied ${result.updatesApplied} updates: ${result.newEventsFound} new events, ${result.newIocsFound} new IOCs, ${result.newTtpsFound} new TTPs. ${result.errors.length} errors.`;
  await db.update(threatIntelUpdates).set({
    tiuStatus: "completed",
    groupsScanned: result.groupsScanned,
    updatesApplied: result.updatesApplied,
    newEventsFound: result.newEventsFound,
    newIocsFound: result.newIocsFound,
    newTtpsFound: result.newTtpsFound,
    tiuSummary: result.summary,
    tiuDetails: result.details,
    tiuErrors: result.errors,
    tiuCompletedAt: /* @__PURE__ */ new Date(),
    durationMs: Date.now() - (sweepRow.tiuStartedAt?.getTime?.() || Date.now())
  }).where(eq(threatIntelUpdates.id, sweepId));
  return result;
}
async function monitorSingleGroup(group) {
  const currentTechniques = group.techniques ?? [];
  const currentMalware = group.malware ?? [];
  const currentTools = group.tools ?? [];
  const response = await invokeLLM({
    _caller: "threat-intel-catalog.monitorSingleGroup",
    _priority: "bulk",
    messages: [
      {
        role: "system",
        content: `You are a threat intelligence analyst monitoring threat group activity.
Given the current profile data for a threat group, identify any recent updates, new activity,
new TTPs, new IOCs, or significant events that should be recorded.
Focus on activity from 2024-2025. Be specific and factual.`
      },
      {
        role: "user",
        content: `Monitor threat group "${group.name}" (type: ${group.type}).
Current last active: ${group.lastActive ?? "unknown"}
Current techniques: ${currentTechniques.map((t) => t.id || t).join(", ")}
Current malware: ${currentMalware.join(", ")}
Current tools: ${currentTools.join(", ")}

Identify any recent updates needed: new attacks, new TTPs, new IOCs, infrastructure changes, law enforcement actions, or group status changes.`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "group_monitoring_update",
        strict: true,
        schema: {
          type: "object",
          properties: {
            hasUpdates: { type: "boolean", description: "Whether any updates were found" },
            newLastActive: { type: "string", description: "Updated last active date if changed" },
            newTrend: { type: "string", enum: ["surging", "active", "declining", "dormant", "unchanged"] },
            newEvents: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  eventType: { type: "string", enum: ["attack", "campaign", "infrastructure_change", "malware_update", "law_enforcement", "ttp_evolution", "new_tool", "zero_day"] },
                  title: { type: "string" },
                  description: { type: "string" },
                  severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
                  date: { type: "string" },
                  victimName: { type: "string" },
                  victimSector: { type: "string" },
                  victimCountry: { type: "string" }
                },
                required: ["eventType", "title", "description", "severity", "date", "victimName", "victimSector", "victimCountry"],
                additionalProperties: false
              }
            },
            newTechniques: {
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
            newIocs: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["ip", "domain", "url", "hash", "email"] },
                  value: { type: "string" },
                  description: { type: "string" }
                },
                required: ["type", "value", "description"],
                additionalProperties: false
              }
            },
            newMalware: { type: "array", items: { type: "string" } },
            newTools: { type: "array", items: { type: "string" } }
          },
          required: ["hasUpdates", "newLastActive", "newTrend", "newEvents", "newTechniques", "newIocs", "newMalware", "newTools"],
          additionalProperties: false
        }
      }
    }
  });
  const content = response.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") return { changes: [], newEvents: 0, newIocs: 0, newTtps: 0 };
  const update = JSON.parse(content);
  if (!update.hasUpdates) return { changes: [], newEvents: 0, newIocs: 0, newTtps: 0 };
  const db = await getDb();
  if (!db) return { changes: [], newEvents: 0, newIocs: 0, newTtps: 0 };
  const changes = [];
  for (const evt of update.newEvents ?? []) {
    await recordGroupEvent({
      actorId: group.actorId,
      eventType: evt.eventType,
      title: evt.title,
      description: evt.description,
      severity: evt.severity,
      victimName: evt.victimName || void 0,
      victimSector: evt.victimSector || void 0,
      victimCountry: evt.victimCountry || void 0,
      source: "llm_monitoring",
      eventDate: evt.date ? new Date(evt.date) : /* @__PURE__ */ new Date()
    });
    changes.push(`New event: ${evt.title}`);
  }
  if (update.newTechniques?.length > 0) {
    const merged = [...currentTechniques, ...update.newTechniques];
    const uniqueById = Array.from(new Map(merged.map((t) => [t.id, t])).values());
    await db.update(threatActors).set({ techniques: uniqueById }).where(eq(threatActors.actorId, group.actorId));
    changes.push(`${update.newTechniques.length} new TTPs added`);
  }
  for (const ioc of update.newIocs ?? []) {
    await db.insert(threatActorIocs).values({
      actorId: group.actorId,
      iocType: ioc.type,
      value: ioc.value,
      description: ioc.description,
      source: "llm_monitoring",
      iocConfidence: "medium"
    });
    changes.push(`New IOC: ${ioc.type}=${ioc.value}`);
  }
  const newMalware = update.newMalware ?? [];
  const newTools = update.newTools ?? [];
  if (newMalware.length > 0 || newTools.length > 0) {
    const mergedMalware = Array.from(/* @__PURE__ */ new Set([...currentMalware, ...newMalware]));
    const mergedTools = Array.from(/* @__PURE__ */ new Set([...currentTools, ...newTools]));
    await db.update(threatActors).set({
      malware: mergedMalware,
      tools: mergedTools
    }).where(eq(threatActors.actorId, group.actorId));
    if (newMalware.length > 0) changes.push(`${newMalware.length} new malware families`);
    if (newTools.length > 0) changes.push(`${newTools.length} new tools`);
  }
  if (update.newLastActive && update.newLastActive !== "unchanged") {
    await db.update(threatActors).set({ lastActive: update.newLastActive }).where(eq(threatActors.actorId, group.actorId));
  }
  return {
    changes,
    newEvents: update.newEvents?.length ?? 0,
    newIocs: update.newIocs?.length ?? 0,
    newTtps: update.newTechniques?.length ?? 0
  };
}
async function seedMasterCatalog(onProgress, types) {
  const allGroups = getAllSeedGroups();
  const filtered = types ? allGroups.filter((g) => types.includes(g.type)) : allGroups;
  const errors = [];
  let seeded = 0;
  const byType = {};
  for (let i = 0; i < filtered.length; i++) {
    const { name, type } = filtered[i];
    onProgress?.(name, i, filtered.length, type);
    try {
      const profile = await generateGroupProfile(name, type);
      await upsertGroupToCatalog(profile);
      for (const attack of profile.notableAttacks.slice(0, 3)) {
        await recordGroupEvent({
          actorId: profile.actorId,
          eventType: "attack",
          title: `Attack on ${attack.victimName}`,
          description: attack.impactDescription,
          severity: "high",
          victimName: attack.victimName,
          victimSector: attack.sector,
          victimCountry: attack.country,
          source: "llm_enriched",
          eventDate: attack.date ? new Date(attack.date) : void 0
        });
      }
      seeded++;
      byType[type] = (byType[type] ?? 0) + 1;
    } catch (err) {
      errors.push(`${name} (${type}): ${err.message}`);
    }
    if (i < filtered.length - 1) await new Promise((r) => setTimeout(r, 400));
  }
  return { seeded, errors, byType };
}
async function seedGroupsByType(type, onProgress) {
  const groups = SEED_GROUPS[type] ?? [];
  const errors = [];
  let seeded = 0;
  for (let i = 0; i < groups.length; i++) {
    const name = getCanonicalName(groups[i]);
    onProgress?.(name, i, groups.length);
    try {
      const profile = await generateGroupProfile(name, type);
      await upsertGroupToCatalog(profile);
      for (const attack of profile.notableAttacks.slice(0, 3)) {
        await recordGroupEvent({
          actorId: profile.actorId,
          eventType: "attack",
          title: `Attack on ${attack.victimName}`,
          description: attack.impactDescription,
          severity: "high",
          victimName: attack.victimName,
          victimSector: attack.sector,
          victimCountry: attack.country,
          source: "llm_enriched",
          eventDate: attack.date ? new Date(attack.date) : void 0
        });
      }
      seeded++;
    } catch (err) {
      errors.push(`${name}: ${err.message}`);
    }
    if (i < groups.length - 1) await new Promise((r) => setTimeout(r, 400));
  }
  return { seeded, errors };
}
async function ensureActorExists(actorId, meta) {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select({ id: threatActors.id }).from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (existing.length > 0) return;
  await db.insert(threatActors).values({
    actorId,
    name: meta?.name || actorId,
    actorType: meta?.actorType || "unknown",
    threatLevel: meta?.threatLevel || "medium",
    dataSource: meta?.source || "auto_discovered",
    confidence: 60,
    lastActive: (/* @__PURE__ */ new Date()).toISOString().slice(0, 10)
  });
}

export {
  SEED_GROUPS,
  getAllSeedGroups,
  generateGroupProfile,
  upsertGroupToCatalog,
  recordGroupEvent,
  listGroups,
  getGroupDetail,
  getCatalogStats,
  autoDiscoverGroup,
  runMonitoringSweep,
  seedMasterCatalog,
  seedGroupsByType,
  ensureActorExists
};
