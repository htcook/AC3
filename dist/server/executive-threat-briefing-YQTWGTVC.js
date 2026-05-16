import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  carverRiskCards,
  discoveredAssets,
  domainIntelScans,
  init_schema,
  threatActorIocs,
  threatActors,
  threatGroupEvents
} from "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/executive-threat-briefing.ts
init_db();
init_schema();
import { sql, eq, desc, gte } from "drizzle-orm";
var SECTOR_ALIASES = {
  technology: ["technology", "tech", "saas_tech", "saas", "paas", "iaas", "it", "software", "information_technology", "telecommunications"],
  financial: ["financial services", "financial", "banking", "finance", "insurance", "fintech"],
  healthcare: ["healthcare", "health", "medical", "pharmaceutical", "biotech"],
  government: ["government", "gov", "public_sector", "federal", "state", "municipal"],
  defense: ["defense", "military", "aerospace", "defence", "dod"],
  energy: ["energy", "oil_gas", "utilities", "power", "nuclear", "oil & gas"],
  manufacturing: ["manufacturing", "industrial", "automotive"],
  education: ["education", "academic", "university", "research"],
  retail: ["retail", "ecommerce", "e-commerce", "consumer"],
  transportation: ["transportation", "logistics", "shipping", "aviation"],
  critical_infrastructure: ["critical infrastructure", "water", "chemical", "telecom"],
  consulting: ["consulting", "professional_services", "legal"],
  media: ["media", "entertainment", "news"],
  nonprofit: ["non-profit", "nonprofit", "ngo"]
};
function normalizeSector(sector) {
  const lower = sector.toLowerCase().trim();
  for (const [canonical, aliases] of Object.entries(SECTOR_ALIASES)) {
    if (aliases.some((a) => lower.includes(a) || a.includes(lower))) {
      return canonical;
    }
  }
  return lower;
}
function sectorsOverlap(actorSectors, clientSector) {
  const clientNorm = normalizeSector(clientSector);
  const matched = [];
  for (const s of actorSectors) {
    if (normalizeSector(s) === clientNorm) {
      matched.push(s);
    }
  }
  return { match: matched.length > 0, matchedSectors: matched };
}
function computeRelevanceScore(factors) {
  return Math.min(100, Math.round(
    factors.sectorMatch + factors.threatLevelWeight + factors.carverAlignment + factors.recentActivity + factors.iocOverlap
  ));
}
async function computeExecutiveThreatBriefing(input) {
  const db = await getDb();
  if (!db) {
    return {
      scan: null,
      matchedActors: [],
      summary: { totalMatched: 0, criticalActors: 0, highActors: 0, topAttackVectors: [], sectorRiskLevel: "unknown", avgRelevanceScore: 0 },
      trends: { eventsByMonth: [], actorActivityTrend: [] },
      carverProfile: null,
      iocOverlap: null,
      alertsTriggered: 0,
      lastUpdated: Date.now()
    };
  }
  let scanData = null;
  let clientSector = input.sector || "";
  let clientType = "enterprise";
  let scanAssetIds = [];
  if (input.scanId) {
    const [scan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId)).limit(1);
    if (scan) {
      scanData = {
        id: scan.id,
        domain: scan.primaryDomain,
        sector: scan.sector,
        clientType: scan.clientType,
        totalAssets: scan.totalAssets || 0,
        totalFindings: scan.totalFindings || 0,
        riskScore: scan.overallRiskScore,
        riskBand: scan.overallRiskBand
      };
      clientSector = scan.sector || clientSector;
      clientType = scan.clientType || "enterprise";
      const assets = await db.select({
        id: discoveredAssets.id,
        carverScores: discoveredAssets.carverScores,
        technologies: discoveredAssets.technologies,
        hybridRiskScore: discoveredAssets.hybridRiskScore,
        riskBand: discoveredAssets.riskBand
      }).from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
      scanAssetIds = assets.map((a) => a.id);
    }
  }
  if (!scanData) {
    const [latestScan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.status, "completed")).orderBy(desc(domainIntelScans.updatedAt)).limit(1);
    if (latestScan) {
      scanData = {
        id: latestScan.id,
        domain: latestScan.primaryDomain,
        sector: latestScan.sector,
        clientType: latestScan.clientType,
        totalAssets: latestScan.totalAssets || 0,
        totalFindings: latestScan.totalFindings || 0,
        riskScore: latestScan.overallRiskScore,
        riskBand: latestScan.overallRiskBand
      };
      clientSector = latestScan.sector || clientSector;
      clientType = latestScan.clientType || "enterprise";
    }
  }
  let carverProfile = null;
  if (scanData) {
    const carverCards = await db.select().from(carverRiskCards).where(eq(carverRiskCards.domainIntelScanId, scanData.id)).limit(100);
    if (carverCards.length > 0) {
      const carverAgg = { criticality: 0, vulnerability: 0, accessibility: 0, effect: 0, recuperability: 0, recognizability: 0 };
      const priorityBreakdown = {};
      const threatLikelihoodAgg = {};
      for (const card of carverCards) {
        const scores = typeof card.carverScores === "string" ? JSON.parse(card.carverScores) : card.carverScores || {};
        carverAgg.criticality += scores.criticality || 0;
        carverAgg.vulnerability += scores.vulnerability || 0;
        carverAgg.accessibility += scores.accessibility || 0;
        carverAgg.effect += scores.effect || 0;
        carverAgg.recuperability += scores.recuperability || 0;
        carverAgg.recognizability += scores.recognizability || 0;
        const tier = card.priorityTier || "P3";
        priorityBreakdown[tier] = (priorityBreakdown[tier] || 0) + 1;
        const threats = typeof card.threatLikelihood === "string" ? JSON.parse(card.threatLikelihood) : card.threatLikelihood || {};
        for (const [threat, likelihood] of Object.entries(threats)) {
          if (!threatLikelihoodAgg[threat]) threatLikelihoodAgg[threat] = [];
          threatLikelihoodAgg[threat].push(Number(likelihood) || 0);
        }
      }
      const n = carverCards.length;
      carverProfile = {
        avgCriticality: Math.round(carverAgg.criticality / n * 100) / 100,
        avgVulnerability: Math.round(carverAgg.vulnerability / n * 100) / 100,
        avgAccessibility: Math.round(carverAgg.accessibility / n * 100) / 100,
        avgEffect: Math.round(carverAgg.effect / n * 100) / 100,
        avgRecuperability: Math.round(carverAgg.recuperability / n * 100) / 100,
        avgRecognizability: Math.round(carverAgg.recognizability / n * 100) / 100,
        priorityBreakdown,
        topThreatLikelihoods: Object.entries(threatLikelihoodAgg).map(([threat, vals]) => ({
          threat: threat.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
          likelihood: Math.round(vals.reduce((a, b) => a + b, 0) / vals.length * 100) / 100
        })).sort((a, b) => b.likelihood - a.likelihood).slice(0, 8)
      };
    }
  }
  const allActors = await db.select().from(threatActors).limit(500);
  const iocCounts = await db.select({
    actorId: threatActorIocs.actorId,
    cnt: sql`count(*)`
  }).from(threatActorIocs).groupBy(threatActorIocs.actorId);
  const iocCountMap = new Map(iocCounts.map((r) => [r.actorId, r.cnt]));
  const cutoff90d = new Date(Date.now() - 90 * 24 * 60 * 60 * 1e3).toISOString().slice(0, 19).replace("T", " ");
  const recentEvents = await db.select({
    actorId: threatGroupEvents.tgeActorId,
    title: threatGroupEvents.tgeTitle,
    severity: threatGroupEvents.tgeSeverity,
    date: threatGroupEvents.eventDate
  }).from(threatGroupEvents).where(gte(threatGroupEvents.eventDate, cutoff90d)).orderBy(desc(threatGroupEvents.eventDate)).limit(2e3);
  const actorEvents30d = /* @__PURE__ */ new Map();
  const actorEvents90d = /* @__PURE__ */ new Map();
  const cutoff30d = Date.now() - 30 * 24 * 60 * 60 * 1e3;
  const monthlyEvents = {};
  for (const evt of recentEvents) {
    const evtTime = evt.date ? new Date(evt.date).getTime() : 0;
    actorEvents90d.set(evt.actorId, (actorEvents90d.get(evt.actorId) || 0) + 1);
    if (evtTime > cutoff30d) {
      actorEvents30d.set(evt.actorId, (actorEvents30d.get(evt.actorId) || 0) + 1);
    }
    const month = evt.date ? new Date(evt.date).toISOString().slice(0, 7) : "unknown";
    if (!monthlyEvents[month]) monthlyEvents[month] = { count: 0, critical: 0, high: 0 };
    monthlyEvents[month].count++;
    if (evt.severity === "critical") monthlyEvents[month].critical++;
    if (evt.severity === "high") monthlyEvents[month].high++;
  }
  const limit = input.limit || 15;
  const scoredActors = [];
  const topThreatTypes = carverProfile?.topThreatLikelihoods.map((t) => t.threat.toLowerCase()) || [];
  for (const actor of allActors) {
    const targetSectors = safeParseArr(actor.targetSectors);
    const techniques = safeParseArr(actor.techniques);
    const tools = safeParseArr(actor.tools);
    const malware = safeParseArr(actor.malware);
    let sectorMatchScore = 0;
    let matchedSectors = [];
    if (clientSector && targetSectors.length > 0) {
      const { match, matchedSectors: ms } = sectorsOverlap(targetSectors, clientSector);
      if (match) {
        sectorMatchScore = 40;
        matchedSectors = ms;
      } else {
        const clientNorm = normalizeSector(clientSector);
        const adjacentSectors = {
          government: ["defense", "critical_infrastructure"],
          defense: ["government", "technology"],
          financial: ["technology", "consulting"],
          healthcare: ["technology", "government"],
          energy: ["critical_infrastructure", "manufacturing"],
          technology: ["financial", "defense", "healthcare"]
        };
        const adjacent = adjacentSectors[clientNorm] || [];
        for (const s of targetSectors) {
          if (adjacent.includes(normalizeSector(s))) {
            sectorMatchScore = Math.max(sectorMatchScore, 20);
            matchedSectors.push(s + " (adjacent)");
          }
        }
      }
    } else if (targetSectors.length === 0) {
      sectorMatchScore = 10;
    }
    const threatLevelMap = { critical: 20, high: 15, medium: 10, low: 5 };
    const threatLevelWeight = threatLevelMap[actor.threatLevel || "medium"] || 10;
    let carverAlignment = 0;
    if (carverProfile && topThreatTypes.length > 0) {
      const actorType = (actor.actorType || "").toLowerCase();
      const motivation = (actor.motivation || "").toLowerCase();
      for (const threatType of topThreatTypes) {
        if (threatType.includes("ransomware") && (actorType === "ransomware" || actorType === "cybercrime") || threatType.includes("apt") && actorType === "apt" || threatType.includes("espionage") && (motivation.includes("espionage") || actorType === "apt") || threatType.includes("credential") && techniques.some((t) => (t.tactic || "").includes("credential")) || threatType.includes("supply") && techniques.some((t) => (t.name || "").toLowerCase().includes("supply")) || threatType.includes("api") && techniques.some((t) => (t.name || "").toLowerCase().includes("api"))) {
          carverAlignment = Math.min(20, carverAlignment + 7);
        }
      }
      if (carverProfile.avgCriticality > 5 && (actor.threatLevel === "critical" || actor.threatLevel === "high")) {
        carverAlignment = Math.min(20, carverAlignment + 5);
      }
    }
    const events30d = actorEvents30d.get(actor.actorId) || 0;
    const events90d = actorEvents90d.get(actor.actorId) || 0;
    const recentActivity = Math.min(10, events30d * 3 + (events90d - events30d) * 1);
    const iocCount = iocCountMap.get(actor.actorId) || 0;
    const iocOverlap = Math.min(10, Math.round(iocCount / 5));
    const factors = {
      sectorMatch: sectorMatchScore,
      threatLevelWeight,
      carverAlignment,
      recentActivity,
      iocOverlap
    };
    const relevanceScore = computeRelevanceScore(factors);
    if (relevanceScore < 15) continue;
    const attackVectors = [];
    const tacticSet = /* @__PURE__ */ new Set();
    for (const t of techniques.slice(0, 20)) {
      const tactic = typeof t === "string" ? "" : t.tactic || t.killChainPhase || "";
      if (tactic && !tacticSet.has(tactic)) {
        tacticSet.add(tactic);
        attackVectors.push(tactic.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()));
      }
    }
    const recommendedActions = [];
    if (sectorMatchScore >= 30) recommendedActions.push("Prioritize detection rules for this actor's TTPs");
    if (actor.threatLevel === "critical") recommendedActions.push("Immediate threat hunt recommended");
    if (events30d > 0) recommendedActions.push("Active in last 30 days \u2014 monitor closely");
    if (iocCount > 20) recommendedActions.push("Deploy IOC blocklist (" + iocCount + " indicators)");
    if (carverAlignment > 10) recommendedActions.push("Aligns with CARVER threat profile \u2014 validate defenses");
    if (techniques.some((t) => (t.tactic || "").includes("initial-access"))) {
      recommendedActions.push("Review perimeter controls against initial access techniques");
    }
    const actorRecentEvents = recentEvents.filter((e) => e.actorId === actor.actorId).slice(0, 3).map((e) => ({ title: e.title, severity: e.severity || "medium", date: e.date }));
    scoredActors.push({
      actorId: actor.actorId,
      name: actor.name,
      actorType: actor.actorType,
      origin: actor.origin,
      threatLevel: actor.threatLevel,
      relevanceScore,
      relevanceFactors: factors,
      matchedSectors,
      topTechniques: techniques.slice(0, 5).map((t) => ({
        id: typeof t === "string" ? t : t.id || "",
        name: typeof t === "string" ? t : t.name || "",
        tactic: typeof t === "string" ? "" : t.tactic || ""
      })),
      topTools: tools.slice(0, 5).map((t) => typeof t === "string" ? t : t.name || t),
      recentEvents: actorRecentEvents,
      iocCount,
      recommendedActions,
      attackVectors: attackVectors.slice(0, 6)
    });
  }
  scoredActors.sort((a, b) => b.relevanceScore - a.relevanceScore);
  const topActors = scoredActors.slice(0, limit);
  const criticalActors = topActors.filter((a) => a.threatLevel === "critical").length;
  const highActors = topActors.filter((a) => a.threatLevel === "high").length;
  const allAttackVectors = topActors.flatMap((a) => a.attackVectors);
  const vectorCounts = /* @__PURE__ */ new Map();
  for (const v of allAttackVectors) {
    vectorCounts.set(v, (vectorCounts.get(v) || 0) + 1);
  }
  const topAttackVectors = [...vectorCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([v]) => v);
  const avgRelevance = topActors.length > 0 ? Math.round(topActors.reduce((s, a) => s + a.relevanceScore, 0) / topActors.length) : 0;
  const sectorRiskLevel = criticalActors >= 3 ? "critical" : criticalActors >= 1 || highActors >= 3 ? "high" : highActors >= 1 ? "elevated" : topActors.length > 0 ? "moderate" : "low";
  const eventsByMonth = Object.entries(monthlyEvents).filter(([m]) => m !== "unknown").sort(([a], [b]) => a.localeCompare(b)).map(([month, data]) => ({ month, ...data }));
  const actorActivityTrend = topActors.slice(0, 10).map((a) => {
    const e30 = actorEvents30d.get(a.actorId) || 0;
    const e90 = actorEvents90d.get(a.actorId) || 0;
    const e60to90 = e90 - e30;
    const trend = e30 > e60to90 * 1.5 ? "rising" : e30 < e60to90 * 0.5 ? "declining" : "stable";
    return {
      actorId: a.actorId,
      name: a.name,
      eventsLast30d: e30,
      eventsLast90d: e90,
      trend
    };
  });
  let iocOverlapResult = null;
  if (scanData) {
    try {
      const { computeIocOverlap } = await import("./ioc-overlap-detector-UQZUDQ2N.js");
      const overlap = await computeIocOverlap(scanData.id);
      if (overlap.totalMatches > 0) {
        iocOverlapResult = {
          totalMatches: overlap.totalMatches,
          compromiseIndicators: overlap.compromiseIndicators.map((m) => ({
            actorId: m.actorId,
            iocType: m.iocType,
            iocValue: m.iocValue,
            matchedAsset: m.matchedAsset,
            matchType: m.matchType,
            confidence: m.confidence
          })),
          assetExposure: overlap.assetExposure
        };
        for (const actor of topActors) {
          const actorMatches = overlap.matchesByActor.get(actor.actorId);
          if (actorMatches && actorMatches.length > 0) {
            actor.relevanceScore = Math.min(100, actor.relevanceScore + Math.min(15, actorMatches.length * 3));
            actor.relevanceFactors.iocOverlap = Math.min(10, actorMatches.length * 2);
            if (!actor.recommendedActions.some((a) => a.includes("IOC overlap"))) {
              actor.recommendedActions.unshift(`CRITICAL: ${actorMatches.length} IOC overlaps with your infrastructure`);
            }
          }
        }
        topActors.sort((a, b) => b.relevanceScore - a.relevanceScore);
      }
    } catch (err) {
      console.error("[ThreatBriefing] IOC overlap check failed:", err);
    }
  }
  let alertsTriggered = 0;
  try {
    const { checkAlertThresholds } = await import("./threat-alert-engine-FGUFPHDM.js");
    const iocOverlapActors = /* @__PURE__ */ new Set();
    if (iocOverlapResult) {
      for (const ind of iocOverlapResult.compromiseIndicators) {
        iocOverlapActors.add(ind.actorId);
      }
    }
    const risingActors = new Set(actorActivityTrend.filter((a) => a.trend === "rising").map((a) => a.actorId));
    const alertResult = await checkAlertThresholds({
      scanId: scanData?.id || null,
      matchedActors: topActors.map((a) => ({
        actorId: a.actorId,
        name: a.name,
        relevanceScore: a.relevanceScore,
        threatLevel: a.threatLevel,
        iocCount: a.iocCount,
        matchedSectors: a.matchedSectors,
        attackVectors: a.attackVectors
      })),
      iocOverlapActors,
      risingActors
    });
    alertsTriggered = alertResult.alertsFired;
  } catch (err) {
    console.error("[ThreatBriefing] Alert threshold check failed:", err);
  }
  return {
    scan: scanData,
    matchedActors: topActors,
    summary: {
      totalMatched: topActors.length,
      criticalActors,
      highActors,
      topAttackVectors,
      sectorRiskLevel,
      avgRelevanceScore: avgRelevance
    },
    trends: { eventsByMonth, actorActivityTrend },
    carverProfile,
    iocOverlap: iocOverlapResult,
    alertsTriggered,
    lastUpdated: Date.now()
  };
}
async function getRecentScansForBriefing() {
  const db = await getDb();
  if (!db) return [];
  const scans = await db.select({
    id: domainIntelScans.id,
    domain: domainIntelScans.primaryDomain,
    sector: domainIntelScans.sector,
    clientType: domainIntelScans.clientType,
    totalAssets: domainIntelScans.totalAssets,
    riskScore: domainIntelScans.overallRiskScore,
    riskBand: domainIntelScans.overallRiskBand,
    status: domainIntelScans.status,
    updatedAt: domainIntelScans.updatedAt
  }).from(domainIntelScans).where(eq(domainIntelScans.status, "completed")).orderBy(desc(domainIntelScans.updatedAt)).limit(30);
  return scans;
}
function safeParseArr(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  try {
    const parsed = typeof val === "string" ? JSON.parse(val) : val;
    if (Array.isArray(parsed)) return parsed;
    if (typeof parsed === "string") {
      const inner = JSON.parse(parsed);
      if (Array.isArray(inner)) return inner;
    }
    return [];
  } catch {
    return [];
  }
}
export {
  computeExecutiveThreatBriefing,
  getRecentScansForBriefing
};
