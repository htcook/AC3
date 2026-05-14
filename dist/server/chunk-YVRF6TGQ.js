import {
  init_llm,
  invokeLLM
} from "./chunk-RL7LHL4I.js";
import {
  getDb,
  init_db
} from "./chunk-B7OU3XQL.js";
import {
  attackSequenceTemplates,
  credentialExposures,
  darkwebEnrichedRecords,
  exploitIntelligence,
  incidentReports,
  init_schema,
  networkEvents,
  ransomwareAffiliates,
  threatActors,
  ttpKnowledge,
  undergroundIntelEvents
} from "./chunk-TYPEU32S.js";

// server/lib/darkweb-enrichment-service.ts
init_llm();
init_db();
init_schema();
import { eq, desc, sql } from "drizzle-orm";
async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function enrichEvent(eventId) {
  const db = await requireDb();
  const [event] = await db.select().from(undergroundIntelEvents).where(eq(undergroundIntelEvents.id, eventId)).limit(1);
  if (!event) return null;
  const startTime = Date.now();
  try {
    const response = await invokeLLM({
      _caller: "darkweb-enrichment-service.enrichEvent",
      _priority: "bulk",
      messages: [
        {
          role: "system",
          content: `You are a senior darkweb threat intelligence analyst. Analyze the following underground intelligence event and produce a structured enrichment report. Be specific about threat actors, TTPs, and actionable recommendations. Use MITRE ATT&CK framework for technique mapping. Risk scores: 0-30 low, 31-60 medium, 61-80 high, 81-100 critical.`
        },
        {
          role: "user",
          content: `Analyze this darkweb intelligence event:

Category: ${event.uieCategory}
Source: ${event.uieSource}
Title: ${event.uieTitle}
Description: ${event.uieDescription || "N/A"}
Actor: ${event.uieActorName || "Unknown"}
Victim: ${event.uieVictimName || "N/A"}
Sector: ${event.uieVictimSector || "N/A"}
Country: ${event.uieVictimCountry || "N/A"}
IOC Type: ${event.uieIocType || "N/A"}
IOC Value: ${event.uieIocValue || "N/A"}
Severity: ${event.uieSeverity}
Tags: ${JSON.stringify(event.uieTags || [])}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "darkweb_enrichment",
          strict: true,
          schema: {
            type: "object",
            properties: {
              summary: { type: "string", description: "2-3 sentence executive summary" },
              threatAssessment: { type: "string", description: "Detailed threat assessment paragraph" },
              riskScore: { type: "integer", description: "Risk score 0-100" },
              impactAnalysis: { type: "string", description: "Business impact analysis" },
              recommendedActions: { type: "array", items: { type: "string" }, description: "3-5 recommended defensive actions" },
              relatedActors: { type: "array", items: { type: "string" }, description: "Related threat actors" },
              relatedCves: { type: "array", items: { type: "string" }, description: "Related CVEs" },
              mitreTactics: { type: "array", items: { type: "string" }, description: "MITRE ATT&CK tactics" },
              mitreTechniques: { type: "array", items: { type: "string" }, description: "MITRE ATT&CK technique IDs" },
              affectedSectors: { type: "array", items: { type: "string" }, description: "Affected industry sectors" },
              affectedCountries: { type: "array", items: { type: "string" }, description: "Affected countries" }
            },
            required: [
              "summary",
              "threatAssessment",
              "riskScore",
              "impactAnalysis",
              "recommendedActions",
              "relatedActors",
              "relatedCves",
              "mitreTactics",
              "mitreTechniques",
              "affectedSectors",
              "affectedCountries"
            ],
            additionalProperties: false
          }
        }
      }
    });
    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) throw new Error("Empty LLM response");
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    const enrichment = JSON.parse(content);
    const processingTimeMs = Date.now() - startTime;
    const record = {
      derSourceEventId: eventId,
      derSourceTable: "underground_intel_events",
      derSummary: enrichment.summary,
      derThreatAssessment: enrichment.threatAssessment,
      derRiskScore: Math.min(100, Math.max(0, enrichment.riskScore)),
      derImpactAnalysis: enrichment.impactAnalysis,
      derRecommendedActions: enrichment.recommendedActions,
      derRelatedActors: enrichment.relatedActors,
      derRelatedCampaigns: [],
      derRelatedCves: enrichment.relatedCves,
      derRelatedIocs: [],
      derMitreTactics: enrichment.mitreTactics,
      derMitreTechniques: enrichment.mitreTechniques,
      derAffectedSectors: enrichment.affectedSectors,
      derAffectedCountries: enrichment.affectedCountries,
      derEnrichmentModel: "platform-llm",
      derEnrichmentVersion: "1.0",
      derProcessingTimeMs: processingTimeMs
    };
    await db.insert(darkwebEnrichedRecords).values(record);
    await db.update(undergroundIntelEvents).set({ uieEnriched: true, uieEnrichmentData: enrichment }).where(eq(undergroundIntelEvents.id, eventId));
    return record;
  } catch (err) {
    console.error(`[DarkwebEnrichment] Failed to enrich event #${eventId}:`, err.message);
    return null;
  }
}
async function enrichBatch(limit = 10) {
  const db = await requireDb();
  const unenriched = await db.select({ id: undergroundIntelEvents.id }).from(undergroundIntelEvents).where(eq(undergroundIntelEvents.uieEnriched, false)).orderBy(desc(undergroundIntelEvents.uieCreatedAt)).limit(limit);
  let enriched = 0;
  let failed = 0;
  for (const event of unenriched) {
    const result = await enrichEvent(event.id);
    if (result) {
      enriched++;
    } else {
      failed++;
    }
    await new Promise((r) => setTimeout(r, 1e3));
  }
  return { enriched, failed, skipped: 0 };
}
async function getEnrichmentStats() {
  const db = await requireDb();
  const [stats] = await db.select({
    total: sql`COUNT(*)`,
    enriched: sql`SUM(CASE WHEN uie_enriched = true THEN 1 ELSE 0 END)`,
    unenriched: sql`SUM(CASE WHEN uie_enriched = false THEN 1 ELSE 0 END)`
  }).from(undergroundIntelEvents);
  const [enrichedStats] = await db.select({
    totalEnriched: sql`COUNT(*)`,
    avgRiskScore: sql`AVG(der_risk_score)`,
    criticalCount: sql`SUM(CASE WHEN der_risk_score >= 81 THEN 1 ELSE 0 END)`,
    highCount: sql`SUM(CASE WHEN der_risk_score >= 61 AND der_risk_score < 81 THEN 1 ELSE 0 END)`
  }).from(darkwebEnrichedRecords);
  return {
    totalEvents: stats?.total || 0,
    enrichedEvents: stats?.enriched || 0,
    unenrichedEvents: stats?.unenriched || 0,
    enrichmentRate: stats?.total ? Math.round((stats.enriched || 0) / stats.total * 100) : 0,
    totalEnrichedRecords: enrichedStats?.totalEnriched || 0,
    avgRiskScore: Math.round(enrichedStats?.avgRiskScore || 0),
    criticalRiskCount: enrichedStats?.criticalCount || 0,
    highRiskCount: enrichedStats?.highCount || 0
  };
}

// server/lib/darkweb-intel-service.ts
init_db();
init_schema();
import { eq as eq2, desc as desc2, sql as sql2, and as and2, gte, like, or } from "drizzle-orm";
async function requireDb2() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function syncRansomwareActors() {
  const db = await requireDb2();
  const actors = await db.select({
    actorName: undergroundIntelEvents.uieActorName,
    victimCount: sql2`COUNT(*)`,
    sectors: sql2`CONCAT('["', GROUP_CONCAT(DISTINCT uie_victim_sector SEPARATOR '","'), '"]')`,
    countries: sql2`CONCAT('["', GROUP_CONCAT(DISTINCT uie_victim_country SEPARATOR '","'), '"]')`,
    firstSeen: sql2`MIN(uie_event_date)`,
    lastActive: sql2`MAX(uie_event_date)`
  }).from(undergroundIntelEvents).where(
    and2(
      eq2(undergroundIntelEvents.uieCategory, "ransomware"),
      sql2`uie_actor_name IS NOT NULL AND uie_actor_name != ''`
    )
  ).groupBy(undergroundIntelEvents.uieActorName);
  let synced = 0;
  let updated = 0;
  for (const actor of actors) {
    if (!actor.actorName) continue;
    const sectors = safeJsonParse(actor.sectors, []).filter((s) => s && s !== "null");
    const countries = safeJsonParse(actor.countries, []).filter((c) => c && c !== "null");
    const [existing] = await db.select().from(ransomwareAffiliates).where(eq2(ransomwareAffiliates.raAffiliateName, actor.actorName)).limit(1);
    if (existing) {
      await db.update(ransomwareAffiliates).set({
        raTotalVictims: actor.victimCount,
        topSectors: sectors.slice(0, 10),
        topCountries: countries.slice(0, 10),
        lastActive: actor.lastActive || void 0,
        activityScore: calculateActivityScore(actor.victimCount, actor.lastActive),
        status: "active"
      }).where(eq2(ransomwareAffiliates.id, existing.id));
      updated++;
    } else {
      await db.insert(ransomwareAffiliates).values({
        affiliateId: `rw-${actor.actorName.toLowerCase().replace(/\s+/g, "-")}`,
        affiliateName: actor.actorName,
        primaryGroup: actor.actorName,
        raTotalVictims: actor.victimCount,
        topSectors: sectors.slice(0, 10),
        topCountries: countries.slice(0, 10),
        firstSeen: actor.firstSeen || void 0,
        lastActive: actor.lastActive || void 0,
        activityScore: calculateActivityScore(actor.victimCount, actor.lastActive),
        status: "active",
        confidence: 80
      });
      synced++;
    }
  }
  console.log(`[DarkwebIntel] Actor sync: ${synced} new, ${updated} updated`);
  return { synced, updated };
}
function calculateActivityScore(victimCount, lastActive) {
  let score = Math.min(50, victimCount * 5);
  if (lastActive) {
    const daysSince = (Date.now() - new Date(lastActive).getTime()) / (1e3 * 60 * 60 * 24);
    if (daysSince < 7) score += 50;
    else if (daysSince < 30) score += 35;
    else if (daysSince < 90) score += 20;
    else score += 5;
  }
  return Math.min(100, score);
}
function safeJsonParse(val, fallback) {
  if (Array.isArray(val)) return val;
  if (typeof val === "string") {
    try {
      return JSON.parse(val);
    } catch {
      return fallback;
    }
  }
  return fallback;
}
async function getSectorThreatProfiles() {
  const db = await requireDb2();
  const sectorVictims = await db.select({
    sector: undergroundIntelEvents.uieVictimSector,
    count: sql2`COUNT(*)`,
    groups: sql2`CONCAT('["', GROUP_CONCAT(DISTINCT uie_actor_name SEPARATOR '","'), '"]')`
  }).from(undergroundIntelEvents).where(
    and2(
      eq2(undergroundIntelEvents.uieCategory, "ransomware"),
      sql2`uie_victim_sector IS NOT NULL AND uie_victim_sector != ''`
    )
  ).groupBy(undergroundIntelEvents.uieVictimSector).orderBy(sql2`COUNT(*) DESC`).limit(20);
  return sectorVictims.map((sv) => {
    const groups = safeJsonParse(sv.groups, []).filter((g) => g && g !== "null");
    const count = sv.count || 0;
    return {
      sector: sv.sector || "Unknown",
      ransomwareVictims: count,
      topGroups: groups.slice(0, 5),
      credentialExposures: 0,
      // Would need a join or separate query
      iabListings: 0,
      riskLevel: count > 50 ? "critical" : count > 20 ? "high" : count > 5 ? "medium" : "low"
    };
  });
}
async function getDarkwebTrends(days = 30) {
  const db = await requireDb2();
  const cutoff = /* @__PURE__ */ new Date();
  cutoff.setDate(cutoff.getDate() - days);
  const trends = await db.select({
    date: sql2`DATE(uie_created_at)`,
    ransomware: sql2`SUM(CASE WHEN uie_category = 'ransomware' THEN 1 ELSE 0 END)`,
    malware: sql2`SUM(CASE WHEN uie_category = 'malware' THEN 1 ELSE 0 END)`,
    phishing: sql2`SUM(CASE WHEN uie_category = 'phishing' THEN 1 ELSE 0 END)`,
    credential: sql2`SUM(CASE WHEN uie_category = 'credential' THEN 1 ELSE 0 END)`,
    total: sql2`COUNT(*)`
  }).from(undergroundIntelEvents).where(gte(undergroundIntelEvents.uieCreatedAt, cutoff)).groupBy(sql2`DATE(uie_created_at)`).orderBy(sql2`DATE(uie_created_at)`);
  const netTrends = await db.select({
    date: sql2`DATE(ne_created_at)`,
    count: sql2`COUNT(*)`
  }).from(networkEvents).where(gte(networkEvents.neCreatedAt, cutoff)).groupBy(sql2`DATE(ne_created_at)`);
  const netMap = new Map(netTrends.map((t) => [t.date, t.count]));
  return trends.map((t) => ({
    date: String(t.date),
    ransomware: t.ransomware || 0,
    malware: t.malware || 0,
    phishing: t.phishing || 0,
    credential: t.credential || 0,
    network: netMap.get(String(t.date)) || 0,
    total: (t.total || 0) + (netMap.get(String(t.date)) || 0)
  }));
}
async function correlateActor(actorName) {
  const db = await requireDb2();
  const pattern = `%${actorName}%`;
  const [rwEvents] = await db.select({ count: sql2`COUNT(*)` }).from(undergroundIntelEvents).where(like(undergroundIntelEvents.uieActorName, pattern));
  const [netEvents] = await db.select({ count: sql2`COUNT(*)` }).from(networkEvents).where(like(networkEvents.neMalwareFamily, pattern));
  const [credEvents] = await db.select({ count: sql2`COUNT(*)` }).from(credentialExposures).where(like(credentialExposures.ceActorName, pattern));
  const [enriched] = await db.select({
    count: sql2`COUNT(*)`,
    avgRisk: sql2`AVG(der_risk_score)`
  }).from(darkwebEnrichedRecords).where(sql2`JSON_CONTAINS(der_related_actors, ${JSON.stringify([actorName])})`);
  const [lastEvent] = await db.select({
    lastSeen: sql2`MAX(uie_event_date)`
  }).from(undergroundIntelEvents).where(like(undergroundIntelEvents.uieActorName, pattern));
  return {
    actor: actorName,
    ransomwareEvents: rwEvents?.count || 0,
    networkIndicators: netEvents?.count || 0,
    credentialBreaches: credEvents?.count || 0,
    enrichedRecords: enriched?.count || 0,
    avgRiskScore: Math.round(enriched?.avgRisk || 0),
    lastSeen: lastEvent?.lastSeen || null
  };
}
async function getHighPriorityEvents(limit = 20) {
  const db = await requireDb2();
  return db.select().from(undergroundIntelEvents).where(
    or(
      eq2(undergroundIntelEvents.uieSeverity, "critical"),
      eq2(undergroundIntelEvents.uieSeverity, "high")
    )
  ).orderBy(desc2(undergroundIntelEvents.uieCreatedAt)).limit(limit);
}

// server/lib/attack-sequence-learner.ts
init_llm();
init_db();
init_schema();
import { eq as eq3, and as and3, sql as sql3, inArray, desc as desc3, gt, isNotNull } from "drizzle-orm";
async function requireDb3() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
function generateTemplateId() {
  return `ast-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}
async function extractAttackSequence(reportId) {
  const db = await requireDb3();
  const [report] = await db.select().from(incidentReports).where(eq3(incidentReports.id, reportId)).limit(1);
  if (!report) return null;
  const content = report.fullContent || report.summary || "";
  if (content.length < 100) return null;
  const truncatedContent = content.slice(0, 25e3);
  const response = await invokeLLM({
    _caller: "attack-sequence-learner.analyze",
    messages: [
      {
        role: "system",
        content: `You are an elite threat intelligence analyst and red team operator. Your task is to extract a structured attack sequence from an incident report or threat advisory.

You must identify:
1. The ordered phases of the attack (following MITRE ATT&CK kill chain)
2. Specific techniques used in each phase with their MITRE IDs (e.g., T1566.001)
3. Tools, malware, and commands used
4. Threat actors involved
5. Exploits/CVEs leveraged
6. The target environment and sectors
7. A narrative summary of the attack flow
8. Lessons learned for defenders
9. How to emulate this attack in a Caldera adversary emulation exercise
10. Environmental assumptions \u2014 infer the target OS, network topology, security controls, identity provider, cloud provider, privilege levels, patch state, and monitoring gaps from the report evidence
11. Expected telemetry \u2014 for each attack phase, list the detection signals (log sources, event IDs) that SHOULD fire if monitoring is properly configured, and whether each signal is typically detectable

Be extremely specific. Use real MITRE technique IDs. If the report doesn't contain enough detail for a field, use your expert knowledge to infer the most likely techniques based on the described behavior.

Return valid JSON matching the schema exactly.`
      },
      {
        role: "user",
        content: `Analyze this incident report and extract the complete attack sequence:

Title: ${report.title}
Source: ${report.source}
Type: ${report.incidentType || "unknown"}
${report.cvesMentioned ? `Known CVEs: ${JSON.stringify(report.cvesMentioned)}` : ""}
${report.ttpsExtracted ? `Pre-extracted TTPs: ${JSON.stringify(report.ttpsExtracted)}` : ""}

Content:
${truncatedContent}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "attack_sequence_extraction",
        strict: true,
        schema: {
          type: "object",
          properties: {
            phases: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  order: { type: "integer", description: "Phase order (1-based)" },
                  tactic: { type: "string", description: "MITRE ATT&CK tactic name (lowercase with hyphens)" },
                  techniques: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        id: { type: "string", description: "MITRE technique ID e.g. T1566.001" },
                        name: { type: "string", description: "Technique name" },
                        tools: { type: "array", items: { type: "string" }, description: "Tools used" },
                        commands: { type: "array", items: { type: "string" }, description: "Example commands" },
                        description: { type: "string", description: "How this technique was used" }
                      },
                      required: ["id", "name", "tools", "commands", "description"],
                      additionalProperties: false
                    }
                  },
                  duration: { type: "string", description: "Estimated duration of this phase" },
                  description: { type: "string", description: "What happened in this phase" }
                },
                required: ["order", "tactic", "techniques", "duration", "description"],
                additionalProperties: false
              }
            },
            actors: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  aliases: { type: "array", items: { type: "string" } },
                  type: { type: "string", description: "apt, cybercrime, ransomware, hacktivist, unknown" },
                  confidence: { type: "integer", description: "0-100" }
                },
                required: ["name", "aliases", "type", "confidence"],
                additionalProperties: false
              }
            },
            malware: { type: "array", items: { type: "string" } },
            exploits: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  cve: { type: "string" },
                  exploitType: { type: "string" },
                  targetProduct: { type: "string" },
                  weaponized: { type: "boolean" }
                },
                required: ["cve", "exploitType", "targetProduct", "weaponized"],
                additionalProperties: false
              }
            },
            attackType: { type: "string", description: "ransomware, apt_espionage, data_theft, supply_chain, etc." },
            complexity: { type: "string", description: "basic, intermediate, advanced, nation-state" },
            targetEnvironment: { type: "string", description: "windows_ad, linux_cloud, hybrid, ot_ics, etc." },
            targetSectors: { type: "array", items: { type: "string" } },
            dwellTime: { type: "string", description: "Estimated total dwell time" },
            narrative: { type: "string", description: "Narrative summary of the full attack flow (2-3 paragraphs)" },
            lessonsLearned: { type: "string", description: "Key takeaways for defenders" },
            emulationGuidance: { type: "string", description: "How to emulate this attack in Cyber C2" },
            environmentalAssumptions: {
              type: "object",
              properties: {
                operatingSystem: { type: "array", items: { type: "string" }, description: "Target OS versions inferred from report" },
                networkTopology: { type: "string", description: "flat_network, segmented, air_gapped, hybrid" },
                securityControls: { type: "array", items: { type: "string" }, description: "EDR, firewall, SIEM products mentioned or inferred" },
                identityProvider: { type: "string", description: "Active Directory, Azure AD, Okta, etc." },
                cloudProvider: { type: "string", description: "AWS, Azure, GCP, on-prem, hybrid" },
                privilegeLevel: { type: "string", description: "Starting privilege: user, local_admin, domain_admin" },
                patchLevel: { type: "string", description: "current, 30_days_behind, 90_days_behind, unpatched" },
                monitoringGaps: { type: "array", items: { type: "string" }, description: "Gaps that enabled the attack" },
                assumptions: { type: "array", items: { type: "string" }, description: "Free-form assumptions from report context" }
              },
              required: ["operatingSystem", "networkTopology", "securityControls", "identityProvider", "cloudProvider", "privilegeLevel", "patchLevel", "monitoringGaps", "assumptions"],
              additionalProperties: false
            },
            expectedTelemetry: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  phase: { type: "integer", description: "Phase order number" },
                  signals: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        source: { type: "string", description: "Log source: Sysmon, Windows Security, EDR, etc." },
                        eventId: { type: "string", description: "Event ID or signal name" },
                        description: { type: "string", description: "What this signal indicates" },
                        detectable: { type: "boolean", description: "Whether typically visible with standard monitoring" },
                        confidence: { type: "string", description: "high, medium, low" }
                      },
                      required: ["source", "eventId", "description", "detectable", "confidence"],
                      additionalProperties: false
                    }
                  }
                },
                required: ["phase", "signals"],
                additionalProperties: false
              }
            }
          },
          required: [
            "phases",
            "actors",
            "malware",
            "exploits",
            "attackType",
            "complexity",
            "targetEnvironment",
            "targetSectors",
            "dwellTime",
            "narrative",
            "lessonsLearned",
            "emulationGuidance",
            "environmentalAssumptions",
            "expectedTelemetry"
          ],
          additionalProperties: false
        }
      }
    }
  });
  try {
    const content2 = response.choices?.[0]?.message?.content;
    if (!content2 || typeof content2 !== "string") return null;
    const extracted = JSON.parse(content2);
    await db.update(incidentReports).set({
      attackSequence: extracted.phases,
      ttpsExtracted: extracted.phases.flatMap(
        (p) => p.techniques.map((t) => ({ techniqueId: t.id, techniqueName: t.name, tactic: p.tactic, confidence: 85 }))
      ),
      actorsIdentified: extracted.actors,
      malwareIdentified: extracted.malware,
      exploitContext: extracted.exploits,
      targetSectors: extracted.targetSectors,
      attackNarrative: extracted.narrative,
      lessonsLearned: extracted.lessonsLearned,
      emulationGuidance: extracted.emulationGuidance,
      incidentType: extracted.attackType,
      status: "extracted"
    }).where(eq3(incidentReports.id, reportId));
    return extracted;
  } catch {
    return null;
  }
}
async function generateAttackTemplate(reportId) {
  const db = await requireDb3();
  const [report] = await db.select().from(incidentReports).where(eq3(incidentReports.id, reportId)).limit(1);
  if (!report || !report.attackSequence) return null;
  const phases = report.attackSequence;
  if (!phases || phases.length === 0) return null;
  const response = await invokeLLM({
    _caller: "attack-sequence-learner.generateAttackTemplate",
    messages: [
      {
        role: "system",
        content: `You are a Caldera adversary emulation expert. Given an attack sequence extracted from a real incident, generate:
1. A Caldera adversary profile with atomic ordering of abilities
2. Detection difficulty rating (1-10)
3. Common Sigma rules that would detect each phase
4. Evasion techniques used or recommended

You know the Caldera platform intimately \u2014 abilities, executors (psh, cmd, sh, bash), payloads, and how to chain them.
Return valid JSON.`
      },
      {
        role: "user",
        content: `Generate a Caldera emulation profile for this attack sequence:

Attack: ${report.title}
Type: ${report.incidentType}
Actors: ${JSON.stringify(report.actorsIdentified || [])}

Phases:
${JSON.stringify(phases, null, 2)}

Emulation Guidance: ${report.emulationGuidance || "N/A"}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "caldera_emulation_profile",
        strict: true,
        schema: {
          type: "object",
          properties: {
            calderaProfile: {
              type: "object",
              properties: {
                name: { type: "string" },
                description: { type: "string" },
                atomicOrdering: { type: "array", items: { type: "string" }, description: "Ordered list of technique IDs" },
                objectives: { type: "array", items: { type: "string" } }
              },
              required: ["name", "description", "atomicOrdering", "objectives"],
              additionalProperties: false
            },
            detectionDifficulty: { type: "integer", description: "1-10 scale" },
            commonDetections: { type: "array", items: { type: "string" }, description: "Sigma rule names" },
            evasionTechniques: { type: "array", items: { type: "string" }, description: "Evasion technique IDs" }
          },
          required: ["calderaProfile", "detectionDifficulty", "commonDetections", "evasionTechniques"],
          additionalProperties: false
        }
      }
    }
  });
  try {
    const content = response.choices?.[0]?.message?.content;
    if (!content || typeof content !== "string") return null;
    const profile = JSON.parse(content);
    const actors = report.actorsIdentified || [];
    const template = {
      templateId: generateTemplateId(),
      name: `${report.title} \u2014 Emulation Template`,
      description: report.attackNarrative || report.summary || void 0,
      sourceIncidentIds: [reportId],
      sourceActors: actors.map((a) => a.name),
      phases,
      totalPhases: phases.length,
      attackType: report.incidentType || void 0,
      complexity: "intermediate",
      targetEnvironment: "hybrid",
      targetSectors: report.targetSectors || void 0,
      calderaAdversaryProfile: profile.calderaProfile,
      detectionDifficulty: profile.detectionDifficulty,
      commonDetections: profile.commonDetections,
      evasionTechniques: profile.evasionTechniques,
      confidence: 80,
      status: "draft"
    };
    await db.insert(attackSequenceTemplates).values(template);
    await db.update(incidentReports).set({ irStatus: "enriched" }).where(eq3(incidentReports.id, reportId));
    return template;
  } catch {
    return null;
  }
}
async function enrichExploitsFromReport(reportId) {
  const db = await requireDb3();
  const [report] = await db.select().from(incidentReports).where(eq3(incidentReports.id, reportId)).limit(1);
  if (!report) return 0;
  const exploits = report.exploitContext || [];
  let enriched = 0;
  for (const exploit of exploits) {
    if (!exploit.cve) continue;
    const existing = await db.select({ id: exploitIntelligence.id }).from(exploitIntelligence).where(and3(
      eq3(exploitIntelligence.cveId, exploit.cve),
      eq3(exploitIntelligence.eiSource, "incident_report")
    )).limit(1);
    if (existing.length > 0) {
      await db.update(exploitIntelligence).set({
        usedInIncidents: sql3`JSON_ARRAY_APPEND(COALESCE(usedInIncidents, JSON_ARRAY()), '$', ${reportId})`,
        weaponized: exploit.weaponized || void 0
      }).where(eq3(exploitIntelligence.id, existing[0].id));
    } else {
      const actors = report.actorsIdentified || [];
      const record = {
        cveId: exploit.cve,
        exploitType: exploit.exploitType || void 0,
        targetProduct: exploit.targetProduct || void 0,
        weaponized: exploit.weaponized || false,
        usedByActors: actors.map((a) => a.name),
        usedInIncidents: [reportId],
        attackPhase: "initial_access",
        source: "incident_report",
        confidence: 75
      };
      await db.insert(exploitIntelligence).values(record);
    }
    enriched++;
  }
  return enriched;
}
async function crossReferenceActors(reportId) {
  const db = await requireDb3();
  const [report] = await db.select().from(incidentReports).where(eq3(incidentReports.id, reportId)).limit(1);
  if (!report) return 0;
  const actors = report.actorsIdentified || [];
  let linked = 0;
  for (const actor of actors) {
    if (!actor.name) continue;
    const existing = await db.select().from(threatActors).where(eq3(threatActors.name, actor.name)).limit(1);
    if (existing.length > 0) {
      const existingActor = existing[0];
      const timeline = existingActor.activityTimeline || [];
      timeline.push({
        date: report.publishedAt || (/* @__PURE__ */ new Date()).toISOString(),
        event: report.title,
        source: report.source,
        reportId
      });
      await db.update(threatActors).set({
        activityTimeline: timeline,
        lastActive: report.publishedAt || (/* @__PURE__ */ new Date()).toISOString().split("T")[0]
      }).where(eq3(threatActors.id, existingActor.id));
      linked++;
    }
  }
  return linked;
}
async function updateTtpKnowledgeFromReport(reportId) {
  const db = await requireDb3();
  const [report] = await db.select().from(incidentReports).where(eq3(incidentReports.id, reportId)).limit(1);
  if (!report) return 0;
  const ttps = report.ttpsExtracted || [];
  let updated = 0;
  for (const ttp of ttps) {
    if (!ttp.techniqueId) continue;
    const existing = await db.select().from(ttpKnowledge).where(eq3(ttpKnowledge.techniqueId, ttp.techniqueId)).limit(1);
    if (existing.length > 0) {
      const current = existing[0];
      const newConfidence = Math.min(100, (current.confidence || 50) + 2);
      await db.update(ttpKnowledge).set({ confidence: newConfidence }).where(eq3(ttpKnowledge.id, current.id));
      updated++;
    }
  }
  return updated;
}
async function processReport(reportId) {
  const db = await requireDb3();
  const [report] = await db.select().from(incidentReports).where(eq3(incidentReports.id, reportId)).limit(1);
  if (!report) throw new Error(`Report ${reportId} not found`);
  const result = {
    reportId,
    title: report.title || "",
    phasesExtracted: 0,
    actorsIdentified: 0,
    exploitsEnriched: 0,
    actorsLinked: 0,
    ttpsUpdated: 0,
    templateGenerated: false
  };
  try {
    const extracted = await extractAttackSequence(reportId);
    if (extracted) {
      result.phasesExtracted = extracted.phases.length;
      result.actorsIdentified = extracted.actors.length;
      const template = await generateAttackTemplate(reportId);
      result.templateGenerated = !!template;
      result.exploitsEnriched = await enrichExploitsFromReport(reportId);
      result.actorsLinked = await crossReferenceActors(reportId);
      result.ttpsUpdated = await updateTtpKnowledgeFromReport(reportId);
      try {
        const enriched = await bidirectionalEnrich(extracted);
        result.ttpsUpdated += enriched;
      } catch (e) {
        console.warn(`[AttackSequenceLearner] Bidirectional enrichment failed: ${e.message}`);
      }
      await db.update(incidentReports).set({ irStatus: "training_ready" }).where(eq3(incidentReports.id, reportId));
    }
  } catch (e) {
    result.error = e.message;
  }
  return result;
}
async function processBatch(limit = 5) {
  const db = await requireDb3();
  const reports = await db.select({ id: incidentReports.id, source: incidentReports.source }).from(incidentReports).where(eq3(incidentReports.irStatus, "raw")).orderBy(
    sql3`FIELD(source, 'dfir_report', 'cisa_advisory', 'unit42', 'misp_circl', 'hacker_news', 'dark_reading') DESC`,
    sql3`ir_created_at DESC`
  ).limit(limit);
  const results = [];
  for (const report of reports) {
    try {
      const result = await processReport(report.id);
      results.push(result);
    } catch (e) {
      results.push({
        reportId: report.id,
        title: "",
        phasesExtracted: 0,
        actorsIdentified: 0,
        exploitsEnriched: 0,
        actorsLinked: 0,
        ttpsUpdated: 0,
        templateGenerated: false,
        error: e.message
      });
    }
  }
  return results;
}
async function getLearnerStats() {
  const db = await requireDb3();
  const [reportCount] = await db.select({ count: sql3`COUNT(*)` }).from(incidentReports);
  const statusCounts = await db.select({
    status: incidentReports.irStatus,
    count: sql3`COUNT(*)`
  }).from(incidentReports).groupBy(incidentReports.irStatus);
  const [templateCount] = await db.select({ count: sql3`COUNT(*)` }).from(attackSequenceTemplates);
  const typeCounts = await db.select({
    type: attackSequenceTemplates.attackType,
    count: sql3`COUNT(*)`
  }).from(attackSequenceTemplates).groupBy(attackSequenceTemplates.attackType);
  const [exploitCount] = await db.select({ count: sql3`COUNT(*)` }).from(exploitIntelligence);
  const [weaponizedCount] = await db.select({ count: sql3`COUNT(*)` }).from(exploitIntelligence).where(eq3(exploitIntelligence.weaponized, true));
  const [avgPhases] = await db.select({
    avg: sql3`COALESCE(AVG(totalPhases), 0)`
  }).from(attackSequenceTemplates);
  const byStatus = {};
  for (const s of statusCounts) {
    byStatus[s.status || "unknown"] = s.count;
  }
  const templatesByType = {};
  for (const t of typeCounts) {
    templatesByType[t.type || "unknown"] = t.count;
  }
  return {
    totalReports: reportCount?.count || 0,
    byStatus,
    totalTemplates: templateCount?.count || 0,
    templatesByType,
    totalExploits: exploitCount?.count || 0,
    weaponizedExploits: weaponizedCount?.count || 0,
    avgPhasesPerTemplate: avgPhases?.avg || 0,
    topActors: [],
    // Would need a more complex query across JSON fields
    topTechniques: []
    // Would need JSON extraction query
  };
}
async function bidirectionalEnrich(extracted) {
  const db = await requireDb3();
  let updated = 0;
  const techniqueIds = /* @__PURE__ */ new Set();
  for (const phase of extracted.phases) {
    for (const tech of phase.techniques) {
      if (tech.id) techniqueIds.add(tech.id);
    }
  }
  if (techniqueIds.size === 0) return 0;
  const techArray = Array.from(techniqueIds);
  const matchingActors = await db.select({
    actorId: threatActors.actorId,
    name: threatActors.name,
    type: threatActors.actorType,
    techniques: threatActors.techniques,
    tools: threatActors.tools,
    malware: threatActors.malware,
    targetSectors: threatActors.targetSectors,
    confidence: threatActors.confidence
  }).from(threatActors).where(isNotNull(threatActors.techniques)).limit(200);
  const overlappingActors = matchingActors.filter((actor) => {
    const actorTechs = actor.techniques || [];
    return actorTechs.some((t) => techniqueIds.has(t.id));
  });
  const matchingDarkweb = await db.select().from(darkwebEnrichedRecords).where(isNotNull(darkwebEnrichedRecords.derMitreTechniques)).orderBy(desc3(darkwebEnrichedRecords.derRiskScore)).limit(100);
  const overlappingDarkweb = matchingDarkweb.filter((record) => {
    const techs = record.derMitreTechniques || [];
    return techs.some((t) => techniqueIds.has(t));
  });
  for (const techId of techArray) {
    const existing = await db.select().from(ttpKnowledge).where(eq3(ttpKnowledge.techniqueId, techId)).limit(1);
    if (existing.length === 0) continue;
    const entry = existing[0];
    const existingEnv = entry.environmentalConstraints || {};
    const existingTelemetry = entry.expectedTelemetry || {};
    const actorsForTech = overlappingActors.filter(
      (a) => (a.techniques || []).some((t) => t.id === techId)
    );
    let envUpdates = { ...existingEnv };
    let telemetryUpdates = { ...existingTelemetry };
    let confidenceBoost = 0;
    let sourceAdditions = [];
    if (actorsForTech.length > 0) {
      const catalogActors = actorsForTech.map((a) => ({
        id: a.actorId,
        name: a.name,
        type: a.type,
        confidence: a.confidence
      }));
      const existingActors = envUpdates.associatedActors || [];
      const allActors = [...existingActors, ...catalogActors];
      envUpdates.associatedActors = Array.from(
        new Map(allActors.map((a) => [a.id, a])).values()
      );
      const allTools = actorsForTech.flatMap((a) => a.tools || []);
      envUpdates.associatedTools = [.../* @__PURE__ */ new Set([...envUpdates.associatedTools || [], ...allTools])];
      const allSectors = actorsForTech.flatMap((a) => a.targetSectors || []);
      envUpdates.targetedSectors = [.../* @__PURE__ */ new Set([...envUpdates.targetedSectors || [], ...allSectors])];
      confidenceBoost += Math.min(actorsForTech.length * 2, 10);
      sourceAdditions.push("catalog");
    }
    const darkwebForTech = overlappingDarkweb.filter(
      (r) => (r.derMitreTechniques || []).includes(techId)
    );
    if (darkwebForTech.length > 0) {
      envUpdates.darkwebValidated = true;
      envUpdates.lastDarkwebSighting = darkwebForTech[0].derCreatedAt?.toISOString();
      const darkwebIocs = darkwebForTech.flatMap((r) => r.derRelatedIocs || []);
      const existingIocs = telemetryUpdates.darkwebIocs || [];
      const allIocs = [...existingIocs, ...darkwebIocs];
      telemetryUpdates.darkwebIocs = Array.from(
        new Map(allIocs.map((ioc) => [ioc.value || JSON.stringify(ioc), ioc])).values()
      ).slice(0, 50);
      const darkwebCves = darkwebForTech.flatMap((r) => r.derRelatedCves || []);
      telemetryUpdates.darkwebCves = [.../* @__PURE__ */ new Set([...telemetryUpdates.darkwebCves || [], ...darkwebCves])];
      telemetryUpdates.darkwebValidated = true;
      confidenceBoost += Math.min(darkwebForTech.length * 2, 8);
      sourceAdditions.push("darkweb");
    }
    if (extracted.environmentalAssumptions) {
      const assumptions = extracted.environmentalAssumptions;
      envUpdates.dfirAssumptions = {
        ...envUpdates.dfirAssumptions || {},
        operatingSystem: [.../* @__PURE__ */ new Set([...envUpdates.dfirAssumptions?.operatingSystem || [], ...assumptions.operatingSystem || []])],
        networkTopology: assumptions.networkTopology || envUpdates.dfirAssumptions?.networkTopology,
        securityControls: [.../* @__PURE__ */ new Set([...envUpdates.dfirAssumptions?.securityControls || [], ...assumptions.securityControls || []])],
        privilegeLevel: assumptions.privilegeLevel || envUpdates.dfirAssumptions?.privilegeLevel,
        assumptions: [.../* @__PURE__ */ new Set([...envUpdates.dfirAssumptions?.assumptions || [], ...assumptions.assumptions || []])]
      };
    }
    if (extracted.expectedTelemetry) {
      telemetryUpdates.dfirTelemetry = extracted.expectedTelemetry;
    }
    if (confidenceBoost > 0 || sourceAdditions.length > 0) {
      const newConfidence = Math.min(100, (entry.confidence || 50) + confidenceBoost);
      let newSource = entry.dataSource || "unknown";
      for (const src of sourceAdditions) {
        if (!newSource.includes(src)) {
          newSource += `+${src}`;
        }
      }
      await db.update(ttpKnowledge).set({
        environmentalConstraints: envUpdates,
        expectedTelemetry: telemetryUpdates,
        confidence: newConfidence,
        dataSource: newSource,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq3(ttpKnowledge.techniqueId, techId));
      updated++;
    }
  }
  console.log(`[AttackSequenceLearner] Bidirectional enrichment: ${updated} TTP entries updated from ${overlappingActors.length} catalog actors and ${overlappingDarkweb.length} darkweb records`);
  return updated;
}

export {
  enrichEvent,
  enrichBatch,
  getEnrichmentStats,
  syncRansomwareActors,
  getSectorThreatProfiles,
  getDarkwebTrends,
  correlateActor,
  getHighPriorityEvents,
  extractAttackSequence,
  generateAttackTemplate,
  processReport,
  processBatch,
  getLearnerStats
};
