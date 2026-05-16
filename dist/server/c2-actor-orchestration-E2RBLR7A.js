import {
  getDefaultFrameworkPriority
} from "./chunk-2H5DKMIA.js";
import "./chunk-L6AJJ3QE.js";
import "./chunk-37DT2MMI.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-NLTQ4N7G.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-CKIMRR6W.js";
import "./chunk-KDOLKO2A.js";
import {
  darkwebEnrichedRecords,
  incidentReports,
  init_schema,
  iocFeeds,
  threatActors,
  ttpKnowledge
} from "./chunk-Q4QB2XQC.js";
import "./chunk-KFQGP6VL.js";

// server/lib/actor-context-provider.ts
init_db();
init_schema();
init_llm();
import { eq, and, sql, inArray, desc, gt, like, or, isNotNull } from "drizzle-orm";
async function safe(label, fn, fallback) {
  try {
    const data = await fn();
    return { data, ok: true };
  } catch (e) {
    console.warn(`[ActorContextProvider] ${label} failed: ${e.message}`);
    return { data: fallback, ok: false };
  }
}
async function getActorContext(ctx) {
  const startTime = Date.now();
  const sourcesQueried = [];
  const sourcesSucceeded = [];
  const sourcesFailed = [];
  const track = (name, ok) => {
    sourcesQueried.push(name);
    (ok ? sourcesSucceeded : sourcesFailed).push(name);
  };
  const actorsResult = await safe("catalog-actors", () => resolveActors(ctx), []);
  track("threat-intel-catalog", actorsResult.ok);
  const actorNames = actorsResult.data.map((a) => a.name);
  const actorIds = actorsResult.data.map((a) => a.actorId);
  const techniquesResult = await safe("ttp-knowledge", () => resolveActorTechniques(actorIds, actorNames, ctx), []);
  track("ttp-knowledge-base", techniquesResult.ok);
  const iocsResult = await safe("ioc-feeds", () => resolveActorIOCs(actorNames, ctx), []);
  track("ioc-feeds", iocsResult.ok);
  const toolingResult = await safe("actor-tooling", () => resolveActorTooling(actorIds), []);
  track("actor-tooling", toolingResult.ok);
  const patternsResult = await safe("incident-reports", () => resolveBehavioralPatterns(actorNames, ctx), []);
  track("incident-reports", patternsResult.ok);
  const techniqueIds = techniquesResult.data.map((t) => t.techniqueId);
  const insightsResult = await safe("c2-learning", () => resolveExecutionInsights(techniqueIds), []);
  track("c2-learning-engine", insightsResult.ok);
  const darkwebResult = await safe("darkweb-enrichment", () => resolveDarkwebEnrichment(actorNames, ctx), { iocs: [], tools: [] });
  track("darkweb-feeds", darkwebResult.ok);
  const spicyResult = await safe("spicytip-enrichment", () => resolveSpicyTIPEnrichment(actorNames), { iocs: [], patterns: [] });
  track("spicytip-bridge", spicyResult.ok);
  let novelTechniques = [];
  if (ctx.includeNovelTechniques !== false) {
    const novelResult = await safe("ttp-learning", () => learnNewTTPs(actorNames, ctx), []);
    track("ttp-learning-pipeline", novelResult.ok);
    novelTechniques = novelResult.data;
  }
  const allIOCs = deduplicateIOCs([...iocsResult.data, ...darkwebResult.data.iocs, ...spicyResult.data.iocs]);
  const allTooling = deduplicateTooling([...toolingResult.data, ...darkwebResult.data.tools]);
  const allPatterns = [...patternsResult.data, ...spicyResult.data.patterns];
  const tunedTechniques = tuneForModule(techniquesResult.data, ctx.requestingModule, ctx.maxTechniques || 50);
  return {
    actors: actorsResult.data.slice(0, ctx.maxActors || 10),
    techniques: tunedTechniques,
    iocs: allIOCs.slice(0, 200),
    tooling: allTooling,
    behavioralPatterns: allPatterns,
    executionInsights: insightsResult.data,
    novelTechniques,
    meta: {
      sourcesQueried,
      sourcesSucceeded,
      sourcesFailed,
      totalEnrichmentTimeMs: Date.now() - startTime,
      actorCount: actorsResult.data.length,
      techniqueCount: tunedTechniques.length,
      iocCount: allIOCs.length,
      novelTechniqueCount: novelTechniques.length,
      generatedAt: (/* @__PURE__ */ new Date()).toISOString()
    }
  };
}
async function resolveActors(ctx) {
  const db = await getDb();
  if (!db) return [];
  let actors = [];
  if (ctx.actorIds && ctx.actorIds.length > 0) {
    actors = await db.select().from(threatActors).where(inArray(threatActors.actorId, ctx.actorIds)).limit(ctx.maxActors || 20);
  } else {
    const conditions = [];
    if (ctx.targetSector) {
      conditions.push(
        sql`JSON_SEARCH(${threatActors.targetSectors}, 'one', ${`%${ctx.targetSector}%`}) IS NOT NULL`
      );
    }
    if (ctx.targetRegion) {
      conditions.push(
        sql`JSON_SEARCH(${threatActors.targetRegions}, 'one', ${`%${ctx.targetRegion}%`}) IS NOT NULL`
      );
    }
    if (conditions.length > 0) {
      actors = await db.select().from(threatActors).where(or(...conditions)).orderBy(desc(threatActors.confidence)).limit(ctx.maxActors || 20);
    }
    if (actors.length === 0) {
      actors = await db.select().from(threatActors).orderBy(desc(threatActors.confidence)).limit(ctx.maxActors || 10);
    }
  }
  return actors.map((a) => ({
    actorId: a.actorId,
    name: a.name,
    aliases: a.aliases || [],
    type: a.actorType || "unknown",
    origin: a.origin || "unknown",
    threatLevel: a.threatLevel || "medium",
    sophistication: a.sophistication || "intermediate",
    motivation: a.motivation || "unknown",
    targetSectors: a.targetSectors || [],
    targetRegions: a.targetRegions || [],
    activeSince: a.activeSince || "unknown",
    lastActivity: a.lastActivity || "unknown",
    matchScore: a.confidence || 50,
    matchReasons: buildMatchReasons(a, ctx)
  }));
}
function buildMatchReasons(actor, ctx) {
  const reasons = [];
  const sectors = actor.targetSectors || [];
  const regions = actor.targetRegions || [];
  if (ctx.targetSector && sectors.some((s) => s.toLowerCase().includes(ctx.targetSector.toLowerCase()))) {
    reasons.push(`Targets ${ctx.targetSector} sector`);
  }
  if (ctx.targetRegion && regions.some((r) => r.toLowerCase().includes(ctx.targetRegion.toLowerCase()))) {
    reasons.push(`Active in ${ctx.targetRegion} region`);
  }
  if (actor.threatLevel === "critical" || actor.threatLevel === "high") {
    reasons.push(`${actor.threatLevel} threat level`);
  }
  if (!reasons.length) reasons.push("High-confidence catalog entry");
  return reasons;
}
async function resolveActorTechniques(actorIds, actorNames, ctx) {
  const db = await getDb();
  if (!db) return [];
  const allTechniques = await db.select().from(ttpKnowledge).orderBy(desc(ttpKnowledge.confidence)).limit(500);
  const actorTechniques = [];
  const nameSet = new Set(actorNames.map((n) => n.toLowerCase()));
  for (const tech of allTechniques) {
    const envConstraints = tech.environmentalConstraints || {};
    const associatedActors = envConstraints.associatedActors || [];
    const toolsUsed = tech.toolsUsed || [];
    const execMethods = tech.executionMethods || [];
    const detectionRules = tech.detectionRules || [];
    const usedByActors = associatedActors.filter((a) => actorIds.includes(a.id) || nameSet.has((a.name || "").toLowerCase())).map((a) => a.name || a.id);
    for (const tool of toolsUsed) {
      const commonActors = tool.commonActors || [];
      for (const ca of commonActors) {
        if (nameSet.has(ca.toLowerCase()) && !usedByActors.includes(ca)) {
          usedByActors.push(ca);
        }
      }
    }
    const isRequested = ctx.techniqueIds?.includes(tech.techniqueId);
    if (usedByActors.length > 0 || isRequested) {
      const detectionCoverage = { sigma: 0, yara: 0, splunk: 0, kql: 0 };
      for (const rule of detectionRules) {
        const fmt = rule.format || "";
        if (fmt === "sigma") detectionCoverage.sigma++;
        else if (fmt === "yara") detectionCoverage.yara++;
        else if (fmt.includes("splunk")) detectionCoverage.splunk++;
        else if (fmt === "kql") detectionCoverage.kql++;
      }
      actorTechniques.push({
        techniqueId: tech.techniqueId,
        techniqueName: tech.techniqueName,
        tactic: tech.tactic,
        usedBy: usedByActors.length > 0 ? usedByActors : ["requested"],
        confidence: tech.confidence || 50,
        executionReliability: -1,
        // Will be enriched by C2 learning step
        executionMethods: execMethods.slice(0, 5),
        tools: toolsUsed.map((t) => t.name).filter(Boolean).slice(0, 10),
        detectionCoverage,
        killChainPhase: tech.attackChainPosition || tech.tactic,
        prerequisites: tech.prerequisiteTechniques || [],
        followUps: tech.followUpTechniques || [],
        redTeamValue: tech.redTeamValue || 5,
        dataSource: tech.dataSource || "unknown"
      });
    }
  }
  return actorTechniques;
}
async function resolveActorIOCs(actorNames, ctx) {
  const db = await getDb();
  if (!db) return [];
  const iocs = [];
  const conditions = actorNames.slice(0, 10).map(
    (name) => like(iocFeeds.description, `%${name}%`)
  );
  if (conditions.length > 0) {
    const feedIOCs = await db.select().from(iocFeeds).where(or(...conditions)).orderBy(desc(iocFeeds.id)).limit(100);
    for (const ioc of feedIOCs) {
      if (!ioc.iocValue) continue;
      const matchedActors = actorNames.filter(
        (name) => (ioc.description || "").toLowerCase().includes(name.toLowerCase())
      );
      iocs.push({
        type: ioc.iocType || "unknown",
        value: ioc.iocValue,
        actorAttribution: matchedActors.length > 0 ? matchedActors : ["unattributed"],
        source: ioc.feedSource,
        severity: ioc.severity || "medium",
        firstSeen: ioc.dateAdded || "unknown",
        lastSeen: ioc.dateAdded || "unknown",
        context: (ioc.title || ioc.description || "").slice(0, 300)
      });
    }
  }
  const kevEntries = await db.select().from(iocFeeds).where(eq(iocFeeds.feedSource, "cisa_kev")).orderBy(desc(iocFeeds.id)).limit(50);
  for (const kev of kevEntries) {
    if (!kev.iocValue) continue;
    iocs.push({
      type: "cve",
      value: kev.iocValue,
      actorAttribution: ["CISA-tracked"],
      source: "cisa_kev",
      severity: kev.severity || "high",
      firstSeen: kev.dateAdded || "unknown",
      lastSeen: kev.dueDate || kev.dateAdded || "unknown",
      context: `${kev.title || ""} \u2014 ${kev.vendorProduct || ""}`.trim().slice(0, 300)
    });
  }
  return iocs;
}
async function resolveActorTooling(actorIds) {
  const db = await getDb();
  if (!db) return [];
  const tooling = [];
  const toolMap = /* @__PURE__ */ new Map();
  const actors = actorIds.length > 0 ? await db.select().from(threatActors).where(inArray(threatActors.actorId, actorIds)) : [];
  for (const actor of actors) {
    const tools = actor.tools || [];
    const malware = actor.malware || [];
    const techniques = actor.techniques || [];
    const techIds = techniques.map((t) => t.id || t.techniqueId).filter(Boolean);
    for (const tool of tools) {
      const existing = toolMap.get(tool.toLowerCase());
      if (existing) {
        if (!existing.usedBy.includes(actor.name)) existing.usedBy.push(actor.name);
      } else {
        toolMap.set(tool.toLowerCase(), {
          name: tool,
          type: "offensive_tool",
          usedBy: [actor.name],
          techniques: techIds.slice(0, 10),
          description: `Offensive tool used by ${actor.name}`,
          source: "threat-catalog"
        });
      }
    }
    for (const mw of malware) {
      const existing = toolMap.get(mw.toLowerCase());
      if (existing) {
        if (!existing.usedBy.includes(actor.name)) existing.usedBy.push(actor.name);
      } else {
        toolMap.set(mw.toLowerCase(), {
          name: mw,
          type: "malware",
          usedBy: [actor.name],
          techniques: techIds.slice(0, 10),
          description: `Malware associated with ${actor.name}`,
          source: "threat-catalog"
        });
      }
    }
  }
  return Array.from(toolMap.values());
}
async function resolveBehavioralPatterns(actorNames, ctx) {
  const db = await getDb();
  if (!db) return [];
  const patterns = [];
  const conditions = actorNames.slice(0, 10).map(
    (name) => sql`JSON_SEARCH(${incidentReports.actorsIdentified}, 'one', ${`%${name}%`}) IS NOT NULL`
  );
  let reports = [];
  if (conditions.length > 0) {
    reports = await db.select().from(incidentReports).where(or(...conditions)).orderBy(desc(incidentReports.id)).limit(50);
  }
  if (ctx.targetSector) {
    const sectorReports = await db.select().from(incidentReports).where(sql`JSON_SEARCH(${incidentReports.targetSectors}, 'one', ${`%${ctx.targetSector}%`}) IS NOT NULL`).orderBy(desc(incidentReports.id)).limit(20);
    reports = [...reports, ...sectorReports];
  }
  const patternMap = /* @__PURE__ */ new Map();
  for (const report of reports) {
    const sequence = report.attackSequence || [];
    const actors = report.actorsIdentified || [];
    const actorName = actors[0]?.name || "Unknown";
    const initialAccess = sequence.find(
      (s) => s.tactic?.toLowerCase().includes("initial") || s.phase?.toLowerCase().includes("initial")
    );
    if (initialAccess) {
      const key = `${actorName}-initial_access`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = initialAccess.techniques || initialAccess.technique || [];
        const techIds = Array.isArray(techniques) ? techniques.map((t) => t.techniqueId || t.id || t).filter(Boolean) : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "initial_access_preference",
          description: initialAccess.description || `${actorName} initial access pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 60,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown"
        });
      }
    }
    const persistence = sequence.find(
      (s) => s.tactic?.toLowerCase().includes("persistence") || s.phase?.toLowerCase().includes("persistence")
    );
    if (persistence) {
      const key = `${actorName}-persistence`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = persistence.techniques || persistence.technique || [];
        const techIds = Array.isArray(techniques) ? techniques.map((t) => t.techniqueId || t.id || t).filter(Boolean) : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "persistence_approach",
          description: persistence.description || `${actorName} persistence pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 55,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown"
        });
      }
    }
    const lateral = sequence.find(
      (s) => s.tactic?.toLowerCase().includes("lateral") || s.phase?.toLowerCase().includes("lateral")
    );
    if (lateral) {
      const key = `${actorName}-lateral_movement`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = lateral.techniques || lateral.technique || [];
        const techIds = Array.isArray(techniques) ? techniques.map((t) => t.techniqueId || t.id || t).filter(Boolean) : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "lateral_movement_style",
          description: lateral.description || `${actorName} lateral movement pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 55,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown"
        });
      }
    }
    const exfil = sequence.find(
      (s) => s.tactic?.toLowerCase().includes("exfil") || s.phase?.toLowerCase().includes("exfil")
    );
    if (exfil) {
      const key = `${actorName}-exfiltration`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = exfil.techniques || exfil.technique || [];
        const techIds = Array.isArray(techniques) ? techniques.map((t) => t.techniqueId || t.id || t).filter(Boolean) : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "exfil_method",
          description: exfil.description || `${actorName} exfiltration pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 50,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown"
        });
      }
    }
  }
  return Array.from(patternMap.values());
}
async function resolveExecutionInsights(techniqueIds) {
  try {
    const { getHistoryForTechnique, calculateTechniqueReliability } = await import("./c2-learning-engine-R2ARKKWU.js");
    const insights = [];
    for (const techId of techniqueIds.slice(0, 50)) {
      const history = getHistoryForTechnique(techId);
      if (history.length === 0) continue;
      const reliability = calculateTechniqueReliability(techId);
      if (!reliability) continue;
      const platformStats = /* @__PURE__ */ new Map();
      const defenseBlocks = /* @__PURE__ */ new Map();
      const defenseMisses = /* @__PURE__ */ new Map();
      const lessons = [];
      for (const record of history) {
        const platform = record.feedback.targetContext.platform;
        const stats = platformStats.get(platform) || { success: 0, total: 0 };
        stats.total++;
        if (record.outcome.success) stats.success++;
        platformStats.set(platform, stats);
        const defenses = record.feedback.targetContext.defenses || [];
        for (const def of defenses) {
          if (record.outcome.success) {
            defenseMisses.set(def, (defenseMisses.get(def) || 0) + 1);
          } else {
            defenseBlocks.set(def, (defenseBlocks.get(def) || 0) + 1);
          }
        }
        for (const lesson of record.outcome.lessonsLearned.slice(0, 2)) {
          if (!lessons.includes(lesson)) lessons.push(lesson);
        }
      }
      let bestPlatform = "unknown";
      let worstPlatform = "unknown";
      let bestRate = -1;
      let worstRate = 101;
      for (const [platform, stats] of platformStats) {
        const rate = stats.total > 0 ? stats.success / stats.total * 100 : 0;
        if (rate > bestRate) {
          bestRate = rate;
          bestPlatform = platform;
        }
        if (rate < worstRate) {
          worstRate = rate;
          worstPlatform = platform;
        }
      }
      insights.push({
        techniqueId: techId,
        framework: reliability.primaryFramework || "mixed",
        successRate: reliability.successRate,
        avgConfidenceAdjustment: reliability.avgConfidenceAdjustment,
        bestPlatform,
        worstPlatform,
        defensesThatBlock: Array.from(defenseBlocks.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([def]) => def),
        defensesThatMiss: Array.from(defenseMisses.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([def]) => def),
        lessonsLearned: lessons.slice(0, 5),
        totalExecutions: history.length
      });
    }
    return insights;
  } catch {
    return [];
  }
}
async function resolveDarkwebEnrichment(actorNames, ctx) {
  const db = await getDb();
  if (!db) return { iocs: [], tools: [] };
  const iocs = [];
  const tools = [];
  const conditions = actorNames.slice(0, 10).map(
    (name) => sql`JSON_SEARCH(${darkwebEnrichedRecords.derRelatedActors}, 'one', ${`%${name}%`}) IS NOT NULL`
  );
  if (conditions.length > 0) {
    const records = await db.select().from(darkwebEnrichedRecords).where(or(...conditions)).orderBy(desc(darkwebEnrichedRecords.derRiskScore)).limit(50);
    for (const record of records) {
      const relatedActors = record.derRelatedActors || [];
      const relatedIocs = record.derRelatedIocs || [];
      const mitreTechniques = record.derMitreTechniques || [];
      for (const ioc of relatedIocs.slice(0, 10)) {
        iocs.push({
          type: ioc.type || "unknown",
          value: ioc.value || "",
          actorAttribution: relatedActors,
          source: "darkweb",
          severity: record.derRiskScore && record.derRiskScore > 70 ? "high" : "medium",
          firstSeen: record.derCreatedAt?.toISOString() || "unknown",
          lastSeen: record.derCreatedAt?.toISOString() || "unknown",
          context: (record.derThreatAssessment || "").slice(0, 300)
        });
      }
      if (record.derThreatAssessment) {
        const toolPatterns = /(?:using|via|through|with)\s+([A-Z][a-zA-Z0-9_-]+(?:\s+[A-Z][a-zA-Z0-9_-]+)?)/g;
        let match;
        while ((match = toolPatterns.exec(record.derThreatAssessment)) !== null) {
          const toolName = match[1].trim();
          if (toolName.length > 2 && toolName.length < 40) {
            tools.push({
              name: toolName,
              type: "darkweb_observed",
              usedBy: relatedActors,
              techniques: mitreTechniques.slice(0, 5),
              description: `Observed in darkweb intelligence: ${(record.derThreatAssessment || "").slice(0, 100)}`,
              source: "darkweb-enrichment"
            });
          }
        }
      }
    }
  }
  return { iocs, tools };
}
async function resolveSpicyTIPEnrichment(actorNames) {
  const iocs = [];
  const patterns = [];
  try {
    const {
      getThreatFoxIOCs,
      getOTXPulses,
      getGlobalThreatActors,
      isBridgeConfigured
    } = await import("./spicy-tip-bridge-FEBC2AWS.js");
    if (!isBridgeConfigured()) return { iocs, patterns };
    const threatFoxData = await getThreatFoxIOCs(100);
    if (threatFoxData) {
      for (const entry of threatFoxData) {
        const entryStr = JSON.stringify(entry).toLowerCase();
        const matchedActors = actorNames.filter((name) => entryStr.includes(name.toLowerCase()));
        if (matchedActors.length > 0) {
          iocs.push({
            type: entry.ioc_type || "unknown",
            value: entry.ioc || entry.value || "",
            actorAttribution: matchedActors,
            source: "spicytip-threatfox",
            severity: entry.confidence_level > 75 ? "high" : "medium",
            firstSeen: entry.first_seen || "unknown",
            lastSeen: entry.last_seen || entry.first_seen || "unknown",
            context: entry.malware || entry.tags?.join(", ") || ""
          });
        }
      }
    }
    const otxPulses = await getOTXPulses(50);
    if (otxPulses) {
      for (const pulse of otxPulses) {
        const pulseStr = JSON.stringify(pulse).toLowerCase();
        const matchedActors = actorNames.filter((name) => pulseStr.includes(name.toLowerCase()));
        if (matchedActors.length > 0) {
          patterns.push({
            actorName: matchedActors[0],
            patternType: "threat_intelligence_pulse",
            description: pulse.name || pulse.description || "OTX pulse",
            techniques: (pulse.attack_ids || []).map((a) => a.id || a).slice(0, 5),
            confidence: 65,
            sourceReports: 1,
            lastObserved: pulse.created || "unknown"
          });
        }
      }
    }
    const globalActors = await getGlobalThreatActors(50);
    if (globalActors) {
      for (const ga of globalActors) {
        const gaName = (ga.name || "").toLowerCase();
        if (actorNames.some((n) => gaName.includes(n.toLowerCase()) || n.toLowerCase().includes(gaName))) {
          const ttps = ga.ttps || ga.techniques || [];
          if (ttps.length > 0) {
            patterns.push({
              actorName: ga.name || "Unknown",
              patternType: "spicytip_actor_profile",
              description: ga.description || `SpicyTIP profile for ${ga.name}`,
              techniques: ttps.slice(0, 10),
              confidence: 70,
              sourceReports: 1,
              lastObserved: ga.lastSeen || "unknown"
            });
          }
        }
      }
    }
  } catch {
  }
  return { iocs, patterns };
}
async function learnNewTTPs(actorNames, ctx) {
  const db = await getDb();
  if (!db) return [];
  const novelTechniques = [];
  const recentReports = await db.select().from(incidentReports).where(isNotNull(incidentReports.ttpsExtracted)).orderBy(desc(incidentReports.id)).limit(100);
  const knownTechniques = await db.select({ techniqueId: ttpKnowledge.techniqueId }).from(ttpKnowledge);
  const knownSet = new Set(knownTechniques.map((t) => t.techniqueId));
  for (const report of recentReports) {
    const ttps = report.ttpsExtracted || [];
    const actors = report.actorsIdentified || [];
    const actorNamesList = actors.map((a) => a.name).filter(Boolean);
    for (const ttp of ttps) {
      const techId = ttp.techniqueId || ttp.id;
      if (techId && !knownSet.has(techId)) {
        const tempId = `novel-report-${techId || Date.now().toString(36)}`;
        if (novelTechniques.some((n) => n.tempId === tempId)) continue;
        novelTechniques.push({
          tempId,
          closestMitreId: techId?.startsWith("T") ? techId : null,
          name: ttp.techniqueName || ttp.name || `Unknown technique ${techId}`,
          tactic: ttp.tactic || "unknown",
          discoverySource: "incident_report",
          evidence: `Found in report: "${report.title}" \u2014 ${(report.summary || "").slice(0, 200)}`,
          observedActors: actorNamesList,
          associatedTools: report.malwareIdentified || [],
          analysis: "",
          reviewed: false,
          noveltyConfidence: ttp.confidence || 50,
          discoveredAt: report.publishedAt || (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    }
    const sequence = report.attackSequence || [];
    for (const phase of sequence) {
      const techniques = phase.techniques || [];
      for (const tech of Array.isArray(techniques) ? techniques : []) {
        const techId = tech.techniqueId || tech.id;
        if (!techId || knownSet.has(techId)) continue;
        const tempId = `novel-seq-${techId || Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
        if (novelTechniques.some((n) => n.closestMitreId === techId)) continue;
        novelTechniques.push({
          tempId,
          closestMitreId: techId?.startsWith("T") ? techId : null,
          name: tech.name || tech.techniqueName || `Sequence technique ${techId}`,
          tactic: phase.tactic || phase.phase || "unknown",
          discoverySource: "incident_report",
          evidence: `Attack sequence phase "${phase.phase || phase.tactic}": ${tech.description || ""}`.slice(0, 300),
          observedActors: actorNamesList,
          associatedTools: tech.tools || [],
          analysis: "",
          reviewed: false,
          noveltyConfidence: 45,
          discoveredAt: report.publishedAt || (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    }
  }
  const darkwebRecords = await db.select().from(darkwebEnrichedRecords).where(
    and(
      isNotNull(darkwebEnrichedRecords.derMitreTechniques),
      gt(darkwebEnrichedRecords.derRiskScore, 50)
    )
  ).orderBy(desc(darkwebEnrichedRecords.derRiskScore)).limit(100);
  for (const record of darkwebRecords) {
    const techniques = record.derMitreTechniques || [];
    const relatedActors = record.derRelatedActors || [];
    for (const techId of techniques) {
      if (!techId || knownSet.has(techId)) continue;
      const tempId = `novel-darkweb-${techId}`;
      if (novelTechniques.some((n) => n.tempId === tempId)) continue;
      novelTechniques.push({
        tempId,
        closestMitreId: techId.startsWith("T") ? techId : null,
        name: `Darkweb-observed technique ${techId}`,
        tactic: record.derMitreTactics?.[0] || "unknown",
        discoverySource: "darkweb",
        evidence: `Darkweb intelligence (risk score: ${record.derRiskScore}): ${(record.derThreatAssessment || "").slice(0, 200)}`,
        observedActors: relatedActors,
        associatedTools: [],
        analysis: "",
        reviewed: false,
        noveltyConfidence: record.derRiskScore ? Math.min(80, record.derRiskScore) : 40,
        discoveredAt: record.derCreatedAt?.toISOString() || (/* @__PURE__ */ new Date()).toISOString()
      });
    }
  }
  try {
    const { getExecutionHistory } = await import("./c2-learning-engine-R2ARKKWU.js");
    const history = getExecutionHistory({ limit: 200 });
    for (const record of history || []) {
      const techId = record.feedback?.techniqueId;
      if (!techId || knownSet.has(techId)) continue;
      const tempId = `novel-c2-${techId}`;
      if (novelTechniques.some((n) => n.tempId === tempId)) continue;
      novelTechniques.push({
        tempId,
        closestMitreId: techId.startsWith("T") ? techId : null,
        name: `C2-executed technique ${techId}`,
        tactic: "execution",
        discoverySource: "c2_feedback",
        evidence: `Executed via ${record.feedback.framework} on ${record.feedback.targetContext.platform}: ${record.outcome.success ? "SUCCESS" : "FAILED"}`,
        observedActors: [],
        associatedTools: [record.feedback.framework],
        analysis: record.outcome.lessonsLearned?.join("; ") || "",
        reviewed: false,
        noveltyConfidence: record.outcome.success ? 70 : 35,
        discoveredAt: record.timestamp || (/* @__PURE__ */ new Date()).toISOString()
      });
    }
  } catch {
  }
  if (novelTechniques.length > 0) {
    try {
      const batch = novelTechniques.slice(0, 15);
      const analysisPrompt = batch.map(
        (nt, i) => `${i + 1}. ${nt.name} (${nt.tactic}) \u2014 Source: ${nt.discoverySource}
   Evidence: ${nt.evidence.slice(0, 150)}`
      ).join("\n");
      const response = await invokeLLM({
        _caller: "actor-context-provider",
        _priority: "bulk",
        messages: [
          {
            role: "system",
            content: `You are a threat intelligence analyst. For each technique below, provide a brief analysis (2-3 sentences) of:
1. Whether this is genuinely novel or a known technique with a different name
2. The closest MITRE ATT&CK technique if applicable
3. The potential impact and recommended detection approach
Return a JSON array of objects with fields: index (1-based), analysis (string), isNovel (boolean), closestMitre (string or null).`
          },
          { role: "user", content: analysisPrompt }
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "technique_analysis",
            strict: true,
            schema: {
              type: "object",
              properties: {
                techniques: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      index: { type: "integer" },
                      analysis: { type: "string" },
                      isNovel: { type: "boolean" },
                      closestMitre: { type: ["string", "null"] }
                    },
                    required: ["index", "analysis", "isNovel", "closestMitre"],
                    additionalProperties: false
                  }
                }
              },
              required: ["techniques"],
              additionalProperties: false
            }
          }
        }
      });
      const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
      const analyses = parsed.techniques || [];
      for (const a of analyses) {
        const idx = (a.index || 0) - 1;
        if (idx >= 0 && idx < batch.length) {
          batch[idx].analysis = a.analysis || "";
          if (a.closestMitre) batch[idx].closestMitreId = a.closestMitre;
          if (!a.isNovel) batch[idx].noveltyConfidence = Math.max(10, (batch[idx].noveltyConfidence || 50) - 30);
        }
      }
    } catch {
    }
  }
  return novelTechniques;
}
function tuneForModule(techniques, module, maxCount) {
  const tacticPriority = {
    "ad-attack-sim": ["credential-access", "lateral-movement", "persistence", "privilege-escalation", "defense-evasion"],
    "cloud-attack-paths": ["initial-access", "privilege-escalation", "persistence", "defense-evasion", "collection"],
    "credential-engine": ["credential-access", "initial-access", "brute-force", "persistence"],
    "zap-playbooks": ["initial-access", "execution", "reconnaissance", "resource-development"],
    "sigma-rules": ["defense-evasion", "execution", "persistence", "lateral-movement", "exfiltration"],
    "auth-assessment": ["credential-access", "initial-access", "persistence", "defense-evasion"],
    "campaign-design": ["initial-access", "execution", "persistence", "privilege-escalation", "lateral-movement", "collection", "exfiltration"],
    "discovery-chain": ["reconnaissance", "discovery", "initial-access"],
    "phishing": ["initial-access", "execution", "social-engineering"],
    "soc-dashboard": ["defense-evasion", "exfiltration", "command-and-control", "impact", "lateral-movement"]
  };
  const priorities = tacticPriority[module] || [];
  if (priorities.length === 0) {
    return techniques.slice(0, maxCount);
  }
  const scored = techniques.map((t) => {
    const tacticNorm = t.tactic.toLowerCase().replace(/\s+/g, "-");
    const priorityIndex = priorities.findIndex((p) => tacticNorm.includes(p) || p.includes(tacticNorm));
    const priorityScore = priorityIndex >= 0 ? (priorities.length - priorityIndex) * 10 : 0;
    const confidenceScore = t.confidence / 10;
    const redTeamScore = t.redTeamValue;
    return { technique: t, score: priorityScore + confidenceScore + redTeamScore };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxCount).map((s) => s.technique);
}
function deduplicateIOCs(iocs) {
  const seen = /* @__PURE__ */ new Map();
  for (const ioc of iocs) {
    const key = `${ioc.type}:${ioc.value}`;
    const existing = seen.get(key);
    if (existing) {
      for (const actor of ioc.actorAttribution) {
        if (!existing.actorAttribution.includes(actor)) {
          existing.actorAttribution.push(actor);
        }
      }
      if (severityRank(ioc.severity) > severityRank(existing.severity)) {
        existing.severity = ioc.severity;
      }
    } else {
      seen.set(key, { ...ioc });
    }
  }
  return Array.from(seen.values());
}
function deduplicateTooling(tools) {
  const seen = /* @__PURE__ */ new Map();
  for (const tool of tools) {
    const key = tool.name.toLowerCase();
    const existing = seen.get(key);
    if (existing) {
      for (const actor of tool.usedBy) {
        if (!existing.usedBy.includes(actor)) existing.usedBy.push(actor);
      }
      for (const tech of tool.techniques) {
        if (!existing.techniques.includes(tech)) existing.techniques.push(tech);
      }
    } else {
      seen.set(key, { ...tool });
    }
  }
  return Array.from(seen.values());
}
function severityRank(s) {
  const ranks = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return ranks[s] || 0;
}

// server/lib/actor-behavioral-sequence-engine.ts
init_db();
init_schema();
init_llm();
import { desc as desc2, isNotNull as isNotNull2 } from "drizzle-orm";
var sequenceStore = [];
var transitionStore = [];
function buildActorFingerprint(actorName) {
  const actorSequences = sequenceStore.filter((s) => s.actorName === actorName);
  if (actorSequences.length === 0) return null;
  const tacticFrequency = /* @__PURE__ */ new Map();
  const toolCombos = [];
  let totalSteps = 0;
  for (const seq of actorSequences) {
    const seqTools = [];
    for (const step of seq.steps) {
      totalSteps++;
      const tacticMap = tacticFrequency.get(step.tactic) || /* @__PURE__ */ new Map();
      tacticMap.set(step.techniqueId, (tacticMap.get(step.techniqueId) || 0) + 1);
      tacticFrequency.set(step.tactic, tacticMap);
      seqTools.push(...step.tools);
    }
    if (seqTools.length > 0) toolCombos.push([...new Set(seqTools)]);
  }
  const buildPreferences = (tacticKeywords) => {
    const combined = /* @__PURE__ */ new Map();
    for (const [tactic, techMap] of tacticFrequency) {
      if (tacticKeywords.some((kw) => tactic.toLowerCase().includes(kw))) {
        for (const [techId, count] of techMap) {
          const existing = combined.get(techId);
          if (existing) {
            existing.count += count;
          } else {
            combined.set(techId, { name: techId, count });
          }
        }
      }
    }
    return Array.from(combined.entries()).sort((a, b) => b[1].count - a[1].count).slice(0, 5).map(([techId, data]) => ({
      techniqueId: techId,
      name: data.name,
      frequency: data.count
    }));
  };
  const sophisticationMarkers = [];
  const avgLength = totalSteps / actorSequences.length;
  if (avgLength > 8) sophisticationMarkers.push("Long kill chains (>8 steps)");
  if (actorSequences.some((s) => s.steps.some((st) => st.tactic.toLowerCase().includes("evasion")))) {
    sophisticationMarkers.push("Defense evasion capabilities");
  }
  if (actorSequences.some((s) => s.isSignature)) {
    sophisticationMarkers.push("Unique signature sequences");
  }
  if (toolCombos.some((tc) => tc.length > 3)) {
    sophisticationMarkers.push("Multi-tool operations");
  }
  let dwellTime = "Unknown";
  if (avgLength > 10) dwellTime = "Extended (weeks to months)";
  else if (avgLength > 6) dwellTime = "Moderate (days to weeks)";
  else if (avgLength > 3) dwellTime = "Short (hours to days)";
  else dwellTime = "Rapid (minutes to hours)";
  return {
    actorName,
    actorType: actorSequences[0]?.actorType || "unknown",
    initialAccessPreferences: buildPreferences(["initial", "reconnaissance"]),
    persistencePreferences: buildPreferences(["persistence"]),
    lateralMovementPreferences: buildPreferences(["lateral"]),
    exfilPreferences: buildPreferences(["exfil", "collection", "impact"]),
    signatureToolCombos: toolCombos.slice(0, 5),
    avgKillChainLength: Math.round(avgLength * 10) / 10,
    estimatedDwellTime: dwellTime,
    sophisticationMarkers,
    sequencesAnalyzed: actorSequences.length
  };
}
async function predictAttackPaths(actorName, targetContext, maxPaths = 3) {
  const fingerprint = buildActorFingerprint(actorName);
  const actorSequences = sequenceStore.filter((s) => s.actorName === actorName);
  if (!fingerprint || actorSequences.length === 0) {
    return inferAttackPaths(actorName, targetContext, maxPaths);
  }
  const paths = [];
  const sortedSequences = [...actorSequences].sort((a, b) => b.confidence - a.confidence);
  for (const seq of sortedSequences.slice(0, maxPaths)) {
    let targetFit = 50;
    if (targetContext.sector && seq.targetEnvironment.sectors.some(
      (s) => s.toLowerCase().includes(targetContext.sector.toLowerCase())
    )) {
      targetFit += 25;
    }
    if (targetContext.platform && seq.targetEnvironment.platforms.some(
      (p) => p.toLowerCase().includes(targetContext.platform.toLowerCase())
    )) {
      targetFit += 25;
    }
    paths.push({
      actorName,
      pathName: seq.name,
      steps: seq.steps,
      overallProbability: seq.confidence / 100,
      basedOnSequences: seq.corroboratingReports,
      targetFit: Math.min(100, targetFit),
      alternativePaths: sortedSequences.length - 1
    });
  }
  if (fingerprint.initialAccessPreferences.length > 0 && paths.length < maxPaths) {
    const startTech = fingerprint.initialAccessPreferences[0];
    const generatedPath = walkTransitionGraph(startTech.techniqueId, actorName, 10);
    if (generatedPath.length >= 3) {
      paths.push({
        actorName,
        pathName: `${actorName} \u2014 Predicted Path (transition model)`,
        steps: generatedPath,
        overallProbability: generatedPath.reduce((acc, s) => acc * (s.positionConfidence / 100), 1),
        basedOnSequences: actorSequences.length,
        targetFit: 50,
        alternativePaths: paths.length
      });
    }
  }
  return paths;
}
function walkTransitionGraph(startTechId, actorName, maxSteps) {
  const steps = [];
  let currentTechId = startTechId;
  const visited = /* @__PURE__ */ new Set();
  for (let i = 0; i < maxSteps; i++) {
    visited.add(currentTechId);
    const transitions = transitionStore.filter((t) => t.fromTechniqueId === currentTechId && !visited.has(t.toTechniqueId)).sort((a, b) => {
      const aActorBonus = a.actors.includes(actorName) ? 0.3 : 0;
      const bActorBonus = b.actors.includes(actorName) ? 0.3 : 0;
      return b.probability + bActorBonus - (a.probability + aActorBonus);
    });
    if (transitions.length === 0) break;
    const bestTransition = transitions[0];
    steps.push({
      position: i,
      techniqueId: bestTransition.toTechniqueId,
      techniqueName: bestTransition.toTechniqueName,
      tactic: "predicted",
      tools: [],
      description: `Predicted step via transition model (p=${bestTransition.probability.toFixed(2)})`,
      positionConfidence: Math.round(bestTransition.probability * 100)
    });
    currentTechId = bestTransition.toTechniqueId;
  }
  return steps;
}
async function inferAttackPaths(actorName, targetContext, maxPaths) {
  try {
    const response = await invokeLLM({
      _caller: "actor-behavioral-sequence-engine.inferAttackPaths",
      messages: [
        {
          role: "system",
          content: `You are a threat intelligence analyst. Given a threat actor name and target context, predict the most likely attack paths they would use. Return a JSON object with a "paths" array, each containing: name (string), steps (array of {techniqueId, techniqueName, tactic, description}), probability (0-1).`
        },
        {
          role: "user",
          content: `Predict ${maxPaths} attack paths for "${actorName}" targeting: sector=${targetContext.sector || "unknown"}, platform=${targetContext.platform || "unknown"}, technologies=${(targetContext.technologies || []).join(", ") || "unknown"}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "attack_paths",
          strict: true,
          schema: {
            type: "object",
            properties: {
              paths: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    steps: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          techniqueId: { type: "string" },
                          techniqueName: { type: "string" },
                          tactic: { type: "string" },
                          description: { type: "string" }
                        },
                        required: ["techniqueId", "techniqueName", "tactic", "description"],
                        additionalProperties: false
                      }
                    },
                    probability: { type: "number" }
                  },
                  required: ["name", "steps", "probability"],
                  additionalProperties: false
                }
              }
            },
            required: ["paths"],
            additionalProperties: false
          }
        }
      }
    });
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return (parsed.paths || []).slice(0, maxPaths).map((p) => ({
      actorName,
      pathName: p.name,
      steps: (p.steps || []).map((s, i) => ({
        position: i,
        techniqueId: s.techniqueId,
        techniqueName: s.techniqueName,
        tactic: s.tactic,
        tools: [],
        description: s.description,
        positionConfidence: Math.round((p.probability || 0.5) * 100)
      })),
      overallProbability: p.probability || 0.5,
      basedOnSequences: 0,
      targetFit: 50,
      alternativePaths: (parsed.paths || []).length - 1
    }));
  } catch {
    return [];
  }
}
function getActorSequences(actorName) {
  return sequenceStore.filter((s) => s.actorName === actorName);
}
function getTransitionsFrom(techniqueId) {
  return transitionStore.filter((t) => t.fromTechniqueId === techniqueId).sort((a, b) => b.probability - a.probability);
}

// server/lib/c2-actor-orchestration.ts
var ACTOR_FRAMEWORK_MAP = {
  // APT groups
  "APT29": {
    primary: ["cobaltstrike", "sliver"],
    secondary: ["empire", "caldera"],
    knownTools: ["Cobalt Strike", "Brute Ratel", "Sliver", "EnvyScout", "SUNBURST"]
  },
  "APT28": {
    primary: ["empire", "metasploit"],
    secondary: ["cobaltstrike", "caldera"],
    knownTools: ["X-Agent", "Zebrocy", "Responder", "Mimikatz"]
  },
  "APT41": {
    primary: ["cobaltstrike", "metasploit"],
    secondary: ["empire", "sliver"],
    knownTools: ["Cobalt Strike", "ShadowPad", "PlugX", "China Chopper"]
  },
  "Lazarus Group": {
    primary: ["metasploit", "empire"],
    secondary: ["cobaltstrike", "caldera"],
    knownTools: ["BLINDINGCAN", "HOPLIGHT", "DTrack", "AppleJeus"]
  },
  "FIN7": {
    primary: ["cobaltstrike", "metasploit"],
    secondary: ["empire", "caldera"],
    knownTools: ["Cobalt Strike", "Carbanak", "GRIFFON", "BOOSTWRITE"]
  },
  "FIN11": {
    primary: ["cobaltstrike", "empire"],
    secondary: ["metasploit", "caldera"],
    knownTools: ["Cobalt Strike", "CLOP", "FlawedAmmyy"]
  },
  "Sandworm": {
    primary: ["metasploit", "empire"],
    secondary: ["caldera", "cobaltstrike"],
    knownTools: ["Industroyer", "NotPetya", "BlackEnergy", "CaddyWiper"]
  },
  "Turla": {
    primary: ["empire", "cobaltstrike"],
    secondary: ["metasploit", "sliver"],
    knownTools: ["Carbon", "Kazuar", "Snake", "ComRAT", "LightNeuron"]
  },
  // Ransomware groups
  "LockBit": {
    primary: ["cobaltstrike", "metasploit"],
    secondary: ["sliver", "empire"],
    knownTools: ["Cobalt Strike", "StealBit", "ProxyShell exploits"]
  },
  "BlackCat/ALPHV": {
    primary: ["cobaltstrike", "sliver"],
    secondary: ["metasploit", "empire"],
    knownTools: ["Cobalt Strike", "Brute Ratel", "Evilginx2"]
  },
  "Conti": {
    primary: ["cobaltstrike", "empire"],
    secondary: ["metasploit", "caldera"],
    knownTools: ["Cobalt Strike", "BazarLoader", "TrickBot", "Anchor"]
  },
  "REvil": {
    primary: ["metasploit", "cobaltstrike"],
    secondary: ["empire", "caldera"],
    knownTools: ["Sodinokibi", "Kaseya exploit", "Cobalt Strike"]
  }
};
var ACTOR_TYPE_PROFILES = {
  apt: {
    noiseLevel: 2,
    encryptedC2: true,
    lotlPreference: true,
    antiForensics: true,
    processInjection: true,
    filelessPreference: true,
    evasionTechniques: ["process-injection", "timestomping", "log-clearing", "dll-sideloading"]
  },
  cybercrime: {
    noiseLevel: 5,
    encryptedC2: true,
    lotlPreference: false,
    antiForensics: false,
    processInjection: false,
    filelessPreference: false,
    evasionTechniques: ["obfuscation", "packing", "anti-vm"]
  },
  ransomware: {
    noiseLevel: 7,
    encryptedC2: true,
    lotlPreference: false,
    antiForensics: true,
    processInjection: true,
    filelessPreference: false,
    evasionTechniques: ["safe-mode-boot", "service-disabling", "shadow-copy-deletion"]
  },
  hacktivist: {
    noiseLevel: 8,
    encryptedC2: false,
    lotlPreference: false,
    antiForensics: false,
    processInjection: false,
    filelessPreference: false,
    evasionTechniques: ["vpn", "tor", "proxy-chains"]
  }
};
async function buildActorOrchestrationProfile(actorName, targetContext = {}) {
  const actorCtx = await getActorContext({
    actorIds: [],
    requestingModule: "c2-orchestrator",
    targetDomain: targetContext.targetDomain,
    targetSector: targetContext.targetSector,
    targetRegion: targetContext.targetRegion,
    technologies: targetContext.technologies,
    includeNovelTechniques: true
  });
  const sequences = getActorSequences(actorName);
  const fingerprint = buildActorFingerprint(actorName);
  const predictedPaths = await predictAttackPaths(actorName, {
    sector: targetContext.targetSector,
    platform: targetContext.platform,
    technologies: targetContext.technologies
  }, 5);
  const matchedActor = actorCtx.actors.find(
    (a) => a.actorId.toLowerCase() === actorName.toLowerCase() || a.actorId.toLowerCase().includes(actorName.toLowerCase())
  );
  const actorType = matchedActor?.type || "apt";
  const frameworkPreferences = buildFrameworkPreferences(actorName, actorType, actorCtx);
  const techniqueChaining = buildTechniqueChaining(actorName, sequences, actorCtx);
  const timingProfile = buildTimingProfile(actorType, fingerprint);
  const opsecProfile = buildOpsecProfile(actorName, actorType, actorCtx);
  return {
    actorName,
    actorType,
    frameworkPreferences,
    techniqueChaining,
    timingProfile,
    opsecProfile,
    predictedPaths,
    fingerprint
  };
}
function generateFrameworkOverrides(profile) {
  const defaults = getDefaultFrameworkPriority();
  const overrides = {};
  for (const [phase, defaultPriority] of Object.entries(defaults)) {
    const actorPrefs = profile.frameworkPreferences[phase];
    if (actorPrefs && actorPrefs.length > 0) {
      const seen = new Set(actorPrefs);
      const merged = [
        ...actorPrefs,
        ...defaultPriority.filter((f) => !seen.has(f))
      ];
      overrides[phase] = merged;
    } else {
      overrides[phase] = defaultPriority;
    }
  }
  return overrides;
}
function reorderStepsForActor(steps, profile) {
  if (profile.techniqueChaining.length === 0 || steps.length <= 1) {
    return steps;
  }
  const transitionMap = /* @__PURE__ */ new Map();
  for (const chain of profile.techniqueChaining) {
    const existing = transitionMap.get(chain.fromTechnique) || [];
    existing.push({ next: chain.toTechnique, probability: chain.transitionProbability });
    transitionMap.set(chain.fromTechnique, existing);
  }
  const reordered = [];
  const remaining = new Set(steps.map((_, i) => i));
  let bestStart = 0;
  let bestStartScore = -1;
  for (let i = 0; i < steps.length; i++) {
    const tid = steps[i].techniqueId;
    if (!tid) continue;
    const transitions = transitionMap.get(tid);
    const score = transitions ? transitions.reduce((s, t) => s + t.probability, 0) : 0;
    const phaseBonus = steps[i].phase === "reconnaissance" ? 100 : steps[i].phase === "delivery" ? 80 : steps[i].phase === "exploitation" ? 60 : 0;
    if (score + phaseBonus > bestStartScore) {
      bestStartScore = score + phaseBonus;
      bestStart = i;
    }
  }
  reordered.push(steps[bestStart]);
  remaining.delete(bestStart);
  while (remaining.size > 0) {
    const currentTechnique = reordered[reordered.length - 1].techniqueId;
    let bestNext = -1;
    let bestScore = -1;
    for (const idx of remaining) {
      const candidateTechnique = steps[idx].techniqueId;
      if (!candidateTechnique || !currentTechnique) {
        const orderScore = 1e3 - steps[idx].order;
        if (orderScore > bestScore && bestNext === -1) {
          bestScore = orderScore;
          bestNext = idx;
        }
        continue;
      }
      const transitions = transitionMap.get(currentTechnique) || [];
      const match = transitions.find((t) => t.next === candidateTechnique);
      const score = match ? match.probability * 10 : 0;
      const globalTransitions = getTransitionsFrom(currentTechnique);
      const globalMatch = globalTransitions.find((t) => t.toTechniqueId === candidateTechnique);
      const globalScore = globalMatch ? globalMatch.probability * 5 : 0;
      const totalScore = score + globalScore;
      if (totalScore > bestScore) {
        bestScore = totalScore;
        bestNext = idx;
      }
    }
    if (bestNext === -1) {
      let minOrder = Infinity;
      for (const idx of remaining) {
        if (steps[idx].order < minOrder) {
          minOrder = steps[idx].order;
          bestNext = idx;
        }
      }
    }
    if (bestNext >= 0) {
      reordered.push(steps[bestNext]);
      remaining.delete(bestNext);
    } else {
      break;
    }
  }
  return reordered.map((step, i) => ({ ...step, order: i }));
}
function calculateActorDelays(steps, profile) {
  const delays = [];
  for (let i = 0; i < steps.length; i++) {
    if (i === 0) {
      delays.push(0);
      continue;
    }
    const prevTechnique = steps[i - 1].techniqueId;
    const currTechnique = steps[i].techniqueId;
    if (prevTechnique && currTechnique) {
      const chain = profile.techniqueChaining.find(
        (c) => c.fromTechnique === prevTechnique && c.toTechnique === currTechnique
      );
      if (chain && chain.recommendedDelayMs > 0) {
        delays.push(chain.recommendedDelayMs);
        continue;
      }
    }
    const prevPhase = steps[i - 1].phase;
    const currPhase = steps[i].phase;
    if (prevPhase !== currPhase) {
      delays.push(profile.timingProfile.avgDwellTimeMs);
    } else {
      const jitter = profile.timingProfile.c2JitterRange;
      delays.push(Math.floor((jitter.min + jitter.max) / 2));
    }
  }
  return delays;
}
function generateEmulationNarrative(profile, steps) {
  const lines = [];
  lines.push(`## ${profile.actorName} Emulation Plan`);
  lines.push("");
  lines.push(`**Actor Type:** ${profile.actorType.toUpperCase()}`);
  lines.push(`**OPSEC Level:** ${profile.opsecProfile.noiseLevel}/10 noise`);
  lines.push(`**C2 Profile:** ${profile.opsecProfile.encryptedC2 ? "Encrypted" : "Cleartext"}, ${profile.timingProfile.beaconSleepMs / 1e3}s beacon sleep`);
  lines.push("");
  if (profile.predictedPaths.length > 0) {
    lines.push("### Predicted Attack Paths");
    for (const path of profile.predictedPaths.slice(0, 3)) {
      lines.push(`- **${path.pathName}** (${Math.round(path.overallProbability * 100)}% probability, ${path.targetFit}% target fit)`);
      for (const step of path.steps.slice(0, 5)) {
        lines.push(`  ${step.position + 1}. ${step.techniqueName} (${step.techniqueId}) \u2014 ${step.tactic}`);
      }
    }
    lines.push("");
  }
  lines.push("### Orchestration Steps");
  const phaseGroups = /* @__PURE__ */ new Map();
  for (const step of steps) {
    const group = phaseGroups.get(step.phase) || [];
    group.push(step);
    phaseGroups.set(step.phase, group);
  }
  for (const [phase, phaseSteps] of phaseGroups) {
    lines.push(`
#### ${phase.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}`);
    for (const step of phaseSteps) {
      lines.push(`- ${step.label} (${step.techniqueId || "custom"}) \u2192 ${step.framework}`);
    }
  }
  lines.push("");
  lines.push("### Behavioral Fidelity Notes");
  if (profile.opsecProfile.lotlPreference) {
    lines.push("- Actor prefers living-off-the-land techniques \u2014 prioritize native OS tools");
  }
  if (profile.opsecProfile.filelessPreference) {
    lines.push("- Actor favors fileless execution \u2014 minimize disk artifacts");
  }
  if (profile.opsecProfile.antiForensics) {
    lines.push("- Actor performs anti-forensics \u2014 include artifact cleanup steps");
  }
  if (profile.timingProfile.businessHoursOnly) {
    lines.push("- Actor operates during business hours \u2014 schedule execution accordingly");
  }
  if (profile.opsecProfile.evasionTechniques.length > 0) {
    lines.push(`- Known evasion: ${profile.opsecProfile.evasionTechniques.join(", ")}`);
  }
  return lines.join("\n");
}
function buildFrameworkPreferences(actorName, actorType, actorCtx) {
  const defaults = getDefaultFrameworkPriority();
  const prefs = {};
  const knownMapping = ACTOR_FRAMEWORK_MAP[actorName];
  const actorTools = actorCtx.tooling.map((t) => t.name.toLowerCase());
  for (const [phase, defaultPriority] of Object.entries(defaults)) {
    const phasePriority = [...defaultPriority];
    if (knownMapping) {
      for (const fw of [...knownMapping.primary].reverse()) {
        const idx = phasePriority.indexOf(fw);
        if (idx > 0) {
          phasePriority.splice(idx, 1);
          phasePriority.unshift(fw);
        }
      }
    }
    const toolToFramework = {
      "cobalt strike": "cobaltstrike",
      "brute ratel": "cobaltstrike",
      // Similar C2 profile
      "sliver": "sliver",
      "metasploit": "metasploit",
      "meterpreter": "metasploit",
      "empire": "empire",
      "powershell empire": "empire"
    };
    for (const tool of actorTools) {
      const fw = toolToFramework[tool];
      if (fw && phasePriority.includes(fw)) {
        const idx = phasePriority.indexOf(fw);
        if (idx > 1) {
          phasePriority.splice(idx, 1);
          phasePriority.splice(1, 0, fw);
        }
      }
    }
    prefs[phase] = phasePriority;
  }
  return prefs;
}
function buildTechniqueChaining(actorName, sequences, actorCtx) {
  const chains = [];
  const seen = /* @__PURE__ */ new Set();
  for (const seq of sequences) {
    for (let i = 0; i < seq.steps.length - 1; i++) {
      const from = seq.steps[i];
      const to = seq.steps[i + 1];
      const key = `${from.techniqueId}->${to.techniqueId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const positionDelta = to.position - from.position;
      const baseDelay = positionDelta <= 1 ? 5e3 : positionDelta * 3e4;
      chains.push({
        fromTechnique: from.techniqueId,
        fromTechniqueName: from.techniqueName,
        toTechnique: to.techniqueId,
        toTechniqueName: to.techniqueName,
        transitionProbability: seq.confidence * (1 - i / seq.steps.length * 0.3),
        recommendedDelayMs: baseDelay,
        tools: [.../* @__PURE__ */ new Set([...from.tools, ...to.tools])]
      });
    }
  }
  for (const technique of actorCtx.techniques) {
    for (const followUp of technique.followUps || []) {
      const key = `${technique.techniqueId}->${followUp}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const followUpTechnique = actorCtx.techniques.find((t) => t.techniqueId === followUp);
      chains.push({
        fromTechnique: technique.techniqueId,
        fromTechniqueName: technique.techniqueName,
        toTechnique: followUp,
        toTechniqueName: followUpTechnique?.techniqueName || followUp,
        transitionProbability: technique.confidence * 0.6,
        recommendedDelayMs: 15e3,
        tools: technique.tools
      });
    }
  }
  chains.sort((a, b) => b.transitionProbability - a.transitionProbability);
  return chains;
}
function buildTimingProfile(actorType, fingerprint) {
  const baseProfiles = {
    apt: {
      avgDwellTimeMs: 36e5,
      // 1 hour between phases
      businessHoursOnly: true,
      activeHours: [{ start: 8, end: 17 }],
      c2JitterRange: { min: 3e4, max: 12e4 },
      beaconSleepMs: 6e4
    },
    cybercrime: {
      avgDwellTimeMs: 6e5,
      // 10 minutes
      businessHoursOnly: false,
      activeHours: [{ start: 0, end: 24 }],
      c2JitterRange: { min: 5e3, max: 3e4 },
      beaconSleepMs: 3e4
    },
    ransomware: {
      avgDwellTimeMs: 3e5,
      // 5 minutes — fast lateral movement
      businessHoursOnly: false,
      activeHours: [{ start: 0, end: 6 }, { start: 22, end: 24 }],
      // Off-hours
      c2JitterRange: { min: 1e3, max: 1e4 },
      beaconSleepMs: 1e4
    },
    hacktivist: {
      avgDwellTimeMs: 12e4,
      // 2 minutes — fast and loud
      businessHoursOnly: false,
      activeHours: [{ start: 0, end: 24 }],
      c2JitterRange: { min: 1e3, max: 5e3 },
      beaconSleepMs: 5e3
    }
  };
  const profile = baseProfiles[actorType] || baseProfiles.apt;
  if (fingerprint) {
    if (fingerprint.estimatedDwellTime && fingerprint.estimatedDwellTime !== "unknown") {
      const match = fingerprint.estimatedDwellTime.match(/(\d+)/);
      if (match) {
        const days = parseInt(match[1], 10);
        profile.avgDwellTimeMs = days * 864e5 / 10;
      }
    }
  }
  return profile;
}
function buildOpsecProfile(actorName, actorType, actorCtx) {
  const baseProfile = ACTOR_TYPE_PROFILES[actorType] || ACTOR_TYPE_PROFILES.apt;
  const profile = {
    noiseLevel: baseProfile.noiseLevel || 5,
    encryptedC2: baseProfile.encryptedC2 ?? true,
    lotlPreference: baseProfile.lotlPreference ?? false,
    antiForensics: baseProfile.antiForensics ?? false,
    processInjection: baseProfile.processInjection ?? false,
    filelessPreference: baseProfile.filelessPreference ?? false,
    evasionTechniques: [...baseProfile.evasionTechniques || []]
  };
  const evasionTechniques = actorCtx.techniques.filter(
    (t) => t.tactic.toLowerCase().includes("defense-evasion") || t.tactic.toLowerCase().includes("evasion")
  );
  for (const tech of evasionTechniques) {
    if (tech.techniqueId === "T1055" || tech.techniqueName.toLowerCase().includes("process injection")) {
      profile.processInjection = true;
    }
    if (tech.techniqueId === "T1059" || tech.techniqueName.toLowerCase().includes("scripting")) {
      profile.lotlPreference = true;
    }
    if (tech.techniqueId === "T1070" || tech.techniqueName.toLowerCase().includes("indicator removal")) {
      profile.antiForensics = true;
    }
    if (!profile.evasionTechniques.includes(tech.techniqueName)) {
      profile.evasionTechniques.push(tech.techniqueName);
    }
  }
  return profile;
}
var ACTOR_PHISHING_PATTERNS = {
  "APT29": {
    preferredExploitIds: ["cred-oauth-consent", "cred-device-code", "mfa-aitm-proxy", "post-email-rule"],
    preferredCategories: ["credential_harvesting", "mfa_bypass"],
    preferredTags: ["oauth", "token-theft", "microsoft365", "aitm"],
    description: "APT29 favors OAuth consent phishing and device code flows for persistent token access"
  },
  "APT28": {
    preferredExploitIds: ["cred-bitb-sso", "cred-progressive-mfa", "payload-html-smuggling"],
    preferredCategories: ["credential_harvesting", "payload_delivery"],
    preferredTags: ["sso", "credential-capture", "html-smuggling"],
    description: "APT28 uses browser-in-browser SSO phishing and HTML smuggling for payload delivery"
  },
  "FIN7": {
    preferredExploitIds: ["payload-clickfix", "payload-html-smuggling", "lp-keylogger", "post-session-hijack"],
    preferredCategories: ["payload_delivery", "landing_page_exploits"],
    preferredTags: ["social-engineering", "powershell", "keylogger", "session-hijacking"],
    description: "FIN7 uses ClickFix social engineering and invoice-themed lures with embedded payloads"
  },
  "Lazarus Group": {
    preferredExploitIds: ["payload-html-smuggling", "payload-clickfix", "lp-browser-fingerprint"],
    preferredCategories: ["payload_delivery", "landing_page_exploits"],
    preferredTags: ["html-smuggling", "social-engineering", "fingerprinting"],
    description: "Lazarus uses job-themed lures with HTML smuggling and browser fingerprinting"
  },
  "LockBit": {
    preferredExploitIds: ["cred-bitb-sso", "mfa-push-fatigue", "payload-html-smuggling"],
    preferredCategories: ["credential_harvesting", "mfa_bypass", "payload_delivery"],
    preferredTags: ["credential-capture", "push-bombing", "html-smuggling"],
    description: "LockBit affiliates use credential harvesting and MFA fatigue for initial access"
  },
  "BlackCat/ALPHV": {
    preferredExploitIds: ["mfa-aitm-proxy", "cred-bitb-sso", "post-session-hijack"],
    preferredCategories: ["mfa_bypass", "credential_harvesting"],
    preferredTags: ["aitm", "evilginx", "session-hijacking", "mfa-bypass"],
    description: "BlackCat uses AiTM proxy phishing (Evilginx) for MFA bypass and session hijacking"
  },
  "Conti": {
    preferredExploitIds: ["payload-html-smuggling", "cred-bitb-sso", "mfa-push-fatigue"],
    preferredCategories: ["payload_delivery", "credential_harvesting", "mfa_bypass"],
    preferredTags: ["html-smuggling", "credential-capture", "push-bombing"],
    description: "Conti operators use BazarLoader delivery via HTML smuggling and credential phishing"
  },
  "Turla": {
    preferredExploitIds: ["evasion-redirect-chain", "evasion-captcha-gate", "lp-browser-fingerprint", "post-email-rule"],
    preferredCategories: ["evasion", "landing_page_exploits"],
    preferredTags: ["redirect", "anti-scanner", "fingerprinting", "email-forwarding"],
    description: "Turla uses sophisticated redirect chains and anti-analysis gates for targeted delivery"
  }
};
async function getActorPhishingRecommendations(actorName, targetContext = {}) {
  const knownPattern = ACTOR_PHISHING_PATTERNS[actorName];
  if (knownPattern) {
    return {
      actorName,
      rationale: knownPattern.description,
      recommendedExploitIds: knownPattern.preferredExploitIds,
      recommendedCategories: knownPattern.preferredCategories,
      filterTags: knownPattern.preferredTags,
      confidence: 90,
      source: "known_pattern"
    };
  }
  const actorCtx = await getActorContext({
    requestingModule: "phishing-selection",
    targetDomain: targetContext.targetDomain,
    targetSector: targetContext.targetSector,
    technologies: targetContext.technologies,
    includeNovelTechniques: false
  });
  const matchedActor = actorCtx.actors.find(
    (a) => a.actorId.toLowerCase().includes(actorName.toLowerCase())
  );
  if (!matchedActor) {
    return buildGenericPhishingRecommendation(targetContext);
  }
  const techniqueToExploit = {
    "T1566": ["cred-bitb-sso", "payload-html-smuggling", "payload-clickfix"],
    "T1566.001": ["payload-html-smuggling", "payload-clickfix"],
    "T1566.002": ["evasion-redirect-chain", "payload-qr-phishing"],
    "T1528": ["cred-oauth-consent", "cred-device-code"],
    "T1556": ["cred-bitb-sso", "cred-progressive-mfa"],
    "T1556.006": ["cred-bitb-sso", "cred-progressive-mfa"],
    "T1539": ["post-session-hijack", "mfa-aitm-proxy"],
    "T1557": ["mfa-aitm-proxy"],
    "T1621": ["mfa-push-fatigue", "lp-fake-mfa-push"],
    "T1204": ["payload-clickfix", "payload-html-smuggling"],
    "T1204.002": ["payload-clickfix", "payload-html-smuggling"],
    "T1027.006": ["payload-html-smuggling"],
    "T1056.001": ["lp-keylogger"],
    "T1114": ["post-email-rule"],
    "T1114.003": ["post-email-rule"]
  };
  const exploitIds = /* @__PURE__ */ new Set();
  const categories = /* @__PURE__ */ new Set();
  const tags = /* @__PURE__ */ new Set();
  for (const technique of actorCtx.techniques) {
    const mappedExploits = techniqueToExploit[technique.techniqueId];
    if (mappedExploits) {
      mappedExploits.forEach((e) => exploitIds.add(e));
    }
    if (technique.tactic.includes("credential")) categories.add("credential_harvesting");
    if (technique.tactic.includes("initial-access")) categories.add("payload_delivery");
    if (technique.tactic.includes("defense-evasion")) categories.add("evasion");
  }
  if (targetContext.usesSSO) {
    exploitIds.add("cred-bitb-sso");
    exploitIds.add("cred-oauth-consent");
    tags.add("sso");
  }
  if (targetContext.usesMfa) {
    exploitIds.add("mfa-aitm-proxy");
    exploitIds.add("mfa-push-fatigue");
    categories.add("mfa_bypass");
    tags.add("mfa-bypass");
  }
  return {
    actorName,
    rationale: `Inferred from ${actorCtx.techniques.length} known techniques attributed to ${actorName}`,
    recommendedExploitIds: Array.from(exploitIds),
    recommendedCategories: Array.from(categories),
    filterTags: Array.from(tags),
    confidence: 65,
    source: "technique_inference"
  };
}
function getKnownActorPhishingPatterns() {
  return Object.entries(ACTOR_PHISHING_PATTERNS).map(([name, pattern]) => ({
    actorName: name,
    description: pattern.description,
    exploitCount: pattern.preferredExploitIds.length,
    categories: pattern.preferredCategories
  }));
}
function buildGenericPhishingRecommendation(targetContext) {
  const exploitIds = [];
  const categories = [];
  const tags = [];
  if (targetContext.usesSSO) {
    exploitIds.push("cred-bitb-sso", "cred-oauth-consent");
    categories.push("credential_harvesting");
    tags.push("sso");
  }
  if (targetContext.usesMfa) {
    exploitIds.push("mfa-aitm-proxy", "mfa-push-fatigue", "cred-progressive-mfa");
    categories.push("mfa_bypass");
    tags.push("mfa-bypass");
  }
  if (!targetContext.usesSSO && !targetContext.usesMfa) {
    exploitIds.push("cred-bitb-sso", "payload-clickfix", "payload-html-smuggling");
    categories.push("credential_harvesting", "payload_delivery");
  }
  return {
    actorName: "generic",
    rationale: "No specific actor pattern found \u2014 recommendations based on target environment",
    recommendedExploitIds: exploitIds,
    recommendedCategories: categories,
    filterTags: tags,
    confidence: 40,
    source: "generic"
  };
}
export {
  buildActorOrchestrationProfile,
  calculateActorDelays,
  generateEmulationNarrative,
  generateFrameworkOverrides,
  getActorPhishingRecommendations,
  getKnownActorPhishingPatterns,
  reorderStepsForActor
};
