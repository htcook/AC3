/**
 * Actor Context Provider — Universal Threat Actor Intelligence Layer
 *
 * The central module that any offensive or defensive module can import to get
 * actor-relevant TTPs, IOCs, behavioral patterns, and enrichment for the
 * current engagement context. Aggregates data from ALL platform sources:
 *
 *  1. Threat Intel Catalog (104+ group profiles, TTPs, tools, malware)
 *  2. SpicyTIP Bridge (ransomware stats, ThreatFox IOCs, OTX pulses, CISA KEV)
 *  3. Darkweb Feeds (access brokers, info ops, underground markets)
 *  4. Darkweb IOC Enrichment (corroborated IOCs with darkweb context)
 *  5. Incident Reports (DFIR, Unit42, CISA advisories — extracted attack sequences)
 *  6. IOC Sync Feeds (URLhaus, ThreatFox, MalwareBazaar, CISA KEV)
 *  7. Ransomware Intel (LLM-enriched ransomware group profiles)
 *  8. C2 Learning Engine (execution feedback, technique reliability)
 *  9. TTP Knowledge Base (deep technique understanding, detection rules)
 * 10. Attack Sequence Learner (extracted kill chains from reports)
 * 11. Threat Actor Matcher (engagement-specific actor matching)
 *
 * Additionally, this module LEARNS new TTPs from data sources:
 *  - Extracts novel techniques from incident reports not yet in MITRE ATT&CK
 *  - Discovers new attack patterns from darkweb access broker listings
 *  - Learns technique effectiveness from C2 execution outcomes
 *  - Cross-references SpicyTIP intelligence for emerging TTPs
 *  - Flags unmapped techniques for analyst review
 *
 * Author: Harrison Cook — AceofCloud
 */

import { getDb } from "../db";
import {
  threatActors,
  ttpKnowledge,
  incidentReports,
  iocFeeds,
  darkwebEnrichedRecords,
  attackSequenceTemplates,
} from "../../drizzle/schema";
import { eq, and, sql, inArray, desc, gt, like, or, isNotNull } from "drizzle-orm";
import { invokeLLM } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────────

/** The unified actor context that any module can consume */
export interface ActorContext {
  /** Primary matched actors for this engagement */
  actors: ActorProfile[];
  /** Actor-relevant TTPs ranked by relevance to the engagement */
  techniques: ActorTechnique[];
  /** Live IOCs correlated to matched actors */
  iocs: ActorIOC[];
  /** Known tools and malware used by matched actors */
  tooling: ActorTooling[];
  /** Behavioral patterns extracted from incident reports */
  behavioralPatterns: BehavioralPattern[];
  /** C2 execution insights for matched actor techniques */
  executionInsights: ExecutionInsight[];
  /** Newly learned TTPs not yet in the standard knowledge base */
  novelTechniques: NovelTechnique[];
  /** Enrichment metadata */
  meta: {
    sourcesQueried: string[];
    sourcesSucceeded: string[];
    sourcesFailed: string[];
    totalEnrichmentTimeMs: number;
    actorCount: number;
    techniqueCount: number;
    iocCount: number;
    novelTechniqueCount: number;
    generatedAt: string;
  };
}

export interface ActorProfile {
  actorId: string;
  name: string;
  aliases: string[];
  type: string; // apt, cybercrime, ransomware, hacktivist
  origin: string;
  threatLevel: string;
  sophistication: string;
  motivation: string;
  targetSectors: string[];
  targetRegions: string[];
  activeSince: string;
  lastActivity: string;
  matchScore: number;
  matchReasons: string[];
}

export interface ActorTechnique {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  /** Which actors use this technique */
  usedBy: string[];
  /** Confidence from TTP knowledge base (0-100) */
  confidence: number;
  /** Reliability from C2 execution history (0-100, -1 if no data) */
  executionReliability: number;
  /** Specific execution methods known for this actor */
  executionMethods: any[];
  /** Tools commonly used with this technique */
  tools: string[];
  /** Detection rules available */
  detectionCoverage: { sigma: number; yara: number; splunk: number; kql: number };
  /** Position in the kill chain */
  killChainPhase: string;
  /** Techniques that typically precede this one */
  prerequisites: string[];
  /** Techniques that typically follow this one */
  followUps: string[];
  /** Red team value score (1-10) */
  redTeamValue: number;
  /** Source of this technique data */
  dataSource: string;
}

export interface ActorIOC {
  type: string; // hash, ip, domain, url, cve
  value: string;
  actorAttribution: string[];
  source: string; // cisa_kev, otx, abusech, darkweb, incident_report
  severity: string;
  firstSeen: string;
  lastSeen: string;
  context: string;
}

export interface ActorTooling {
  name: string;
  type: string; // malware, rat, loader, exploit_kit, c2_framework, credential_tool
  usedBy: string[];
  techniques: string[];
  description: string;
  source: string;
}

export interface BehavioralPattern {
  actorName: string;
  patternType: string; // initial_access_preference, lateral_movement_style, exfil_method, persistence_approach
  description: string;
  techniques: string[];
  confidence: number;
  sourceReports: number;
  lastObserved: string;
}

export interface ExecutionInsight {
  techniqueId: string;
  framework: string;
  successRate: number;
  avgConfidenceAdjustment: number;
  bestPlatform: string;
  worstPlatform: string;
  defensesThatBlock: string[];
  defensesThatMiss: string[];
  lessonsLearned: string[];
  totalExecutions: number;
}

export interface NovelTechnique {
  /** Temporary ID for unmapped techniques */
  tempId: string;
  /** Closest MITRE ATT&CK technique if any */
  closestMitreId: string | null;
  /** Descriptive name */
  name: string;
  /** Which tactic category it falls under */
  tactic: string;
  /** How it was discovered */
  discoverySource: string; // incident_report, darkweb, c2_feedback, spicytip
  /** The raw evidence that revealed this technique */
  evidence: string;
  /** Which actors have been observed using it */
  observedActors: string[];
  /** Tools/malware associated */
  associatedTools: string[];
  /** LLM-generated analysis of the technique */
  analysis: string;
  /** Whether this has been reviewed by an analyst */
  reviewed: boolean;
  /** Confidence that this is genuinely novel (0-100) */
  noveltyConfidence: number;
  /** When it was first discovered */
  discoveredAt: string;
}

// ─── Engagement Context (input from the calling module) ─────────────────

export interface EngagementContext {
  /** Target domain or organization name */
  targetDomain?: string;
  /** Target industry/sector */
  targetSector?: string;
  /** Target geography */
  targetRegion?: string;
  /** Technologies discovered on target */
  technologies?: string[];
  /** Specific actor IDs to focus on (if already matched) */
  actorIds?: string[];
  /** Specific technique IDs to focus on */
  techniqueIds?: string[];
  /** Module requesting context (for relevance tuning) */
  requestingModule: string;
  /** Maximum number of actors to return */
  maxActors?: number;
  /** Maximum number of techniques to return */
  maxTechniques?: number;
  /** Whether to include novel/unverified techniques */
  includeNovelTechniques?: boolean;
  /** Whether to run TTP learning pipeline */
  learnNewTTPs?: boolean;
}

// ─── Safe wrapper ───────────────────────────────────────────────────────

async function safe<T>(label: string, fn: () => Promise<T>, fallback: T): Promise<{ data: T; ok: boolean }> {
  try {
    const data = await fn();
    return { data, ok: true };
  } catch (e: any) {
    console.warn(`[ActorContextProvider] ${label} failed: ${e.message}`);
    return { data: fallback, ok: false };
  }
}

// ─── Core: Get Actor Context ────────────────────────────────────────────

/**
 * The main entry point. Any module calls this with an EngagementContext
 * and gets back a fully enriched ActorContext.
 */
export async function getActorContext(ctx: EngagementContext): Promise<ActorContext> {
  const startTime = Date.now();
  const sourcesQueried: string[] = [];
  const sourcesSucceeded: string[] = [];
  const sourcesFailed: string[] = [];

  const track = (name: string, ok: boolean) => {
    sourcesQueried.push(name);
    (ok ? sourcesSucceeded : sourcesFailed).push(name);
  };

  // ── Step 1: Resolve actors ──────────────────────────────────────────
  const actorsResult = await safe("catalog-actors", () => resolveActors(ctx), []);
  track("threat-intel-catalog", actorsResult.ok);

  // ── Step 2: Get actor-specific TTPs from knowledge base ─────────────
  const actorNames = actorsResult.data.map(a => a.name);
  const actorIds = actorsResult.data.map(a => a.actorId);
  const techniquesResult = await safe("ttp-knowledge", () => resolveActorTechniques(actorIds, actorNames, ctx), []);
  track("ttp-knowledge-base", techniquesResult.ok);

  // ── Step 3: Get live IOCs from all feeds ────────────────────────────
  const iocsResult = await safe("ioc-feeds", () => resolveActorIOCs(actorNames, ctx), []);
  track("ioc-feeds", iocsResult.ok);

  // ── Step 4: Get tooling from catalog ────────────────────────────────
  const toolingResult = await safe("actor-tooling", () => resolveActorTooling(actorIds), []);
  track("actor-tooling", toolingResult.ok);

  // ── Step 5: Get behavioral patterns from incident reports ───────────
  const patternsResult = await safe("incident-reports", () => resolveBehavioralPatterns(actorNames, ctx), []);
  track("incident-reports", patternsResult.ok);

  // ── Step 6: Get C2 execution insights ───────────────────────────────
  const techniqueIds = techniquesResult.data.map(t => t.techniqueId);
  const insightsResult = await safe("c2-learning", () => resolveExecutionInsights(techniqueIds), []);
  track("c2-learning-engine", insightsResult.ok);

  // ── Step 7: Darkweb enrichment ──────────────────────────────────────
  const darkwebResult = await safe("darkweb-enrichment", () => resolveDarkwebEnrichment(actorNames, ctx), { iocs: [] as ActorIOC[], tools: [] as ActorTooling[] });
  track("darkweb-feeds", darkwebResult.ok);

  // ── Step 8: SpicyTIP enrichment ─────────────────────────────────────
  const spicyResult = await safe("spicytip-enrichment", () => resolveSpicyTIPEnrichment(actorNames), { iocs: [] as ActorIOC[], patterns: [] as BehavioralPattern[] });
  track("spicytip-bridge", spicyResult.ok);

  // ── Step 9: Learn new TTPs from all sources ─────────────────────────
  let novelTechniques: NovelTechnique[] = [];
  if (ctx.includeNovelTechniques !== false) {
    const novelResult = await safe("ttp-learning", () => learnNewTTPs(actorNames, ctx), []);
    track("ttp-learning-pipeline", novelResult.ok);
    novelTechniques = novelResult.data;
  }

  // ── Merge and deduplicate ───────────────────────────────────────────
  const allIOCs = deduplicateIOCs([...iocsResult.data, ...darkwebResult.data.iocs, ...spicyResult.data.iocs]);
  const allTooling = deduplicateTooling([...toolingResult.data, ...darkwebResult.data.tools]);
  const allPatterns = [...patternsResult.data, ...spicyResult.data.patterns];

  // ── Apply module-specific relevance tuning ──────────────────────────
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
      generatedAt: new Date().toISOString(),
    },
  };
}

// ─── Step 1: Resolve Actors from Catalog ────────────────────────────────

async function resolveActors(ctx: EngagementContext): Promise<ActorProfile[]> {
  const db = await getDb();
  if (!db) return [];

  let actors: any[] = [];

  // If specific actor IDs provided, fetch those directly
  if (ctx.actorIds && ctx.actorIds.length > 0) {
    actors = await db.select().from(threatActors)
      .where(inArray(threatActors.actorId, ctx.actorIds))
      .limit(ctx.maxActors || 20);
  } else {
    // Build a relevance query based on engagement context
    const conditions: any[] = [];

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

    // Fetch actors with any matching condition, plus top-rated actors
    if (conditions.length > 0) {
      actors = await db.select().from(threatActors)
        .where(or(...conditions))
        .orderBy(desc(threatActors.confidence))
        .limit(ctx.maxActors || 20);
    }

    // If no sector/region match, get the most active/confident actors
    if (actors.length === 0) {
      actors = await db.select().from(threatActors)
        .orderBy(desc(threatActors.confidence))
        .limit(ctx.maxActors || 10);
    }
  }

  return actors.map(a => ({
    actorId: a.actorId,
    name: a.name,
    aliases: (a.aliases as string[]) || [],
    type: a.type || "unknown",
    origin: a.origin || "unknown",
    threatLevel: a.threatLevel || "medium",
    sophistication: a.sophistication || "intermediate",
    motivation: a.motivation || "unknown",
    targetSectors: (a.targetSectors as string[]) || [],
    targetRegions: (a.targetRegions as string[]) || [],
    activeSince: a.activeSince || "unknown",
    lastActivity: a.lastActivity || "unknown",
    matchScore: a.confidence || 50,
    matchReasons: buildMatchReasons(a, ctx),
  }));
}

function buildMatchReasons(actor: any, ctx: EngagementContext): string[] {
  const reasons: string[] = [];
  const sectors = (actor.targetSectors as string[]) || [];
  const regions = (actor.targetRegions as string[]) || [];

  if (ctx.targetSector && sectors.some(s => s.toLowerCase().includes(ctx.targetSector!.toLowerCase()))) {
    reasons.push(`Targets ${ctx.targetSector} sector`);
  }
  if (ctx.targetRegion && regions.some(r => r.toLowerCase().includes(ctx.targetRegion!.toLowerCase()))) {
    reasons.push(`Active in ${ctx.targetRegion} region`);
  }
  if (actor.threatLevel === "critical" || actor.threatLevel === "high") {
    reasons.push(`${actor.threatLevel} threat level`);
  }
  if (!reasons.length) reasons.push("High-confidence catalog entry");
  return reasons;
}

// ─── Step 2: Resolve Actor-Specific TTPs ────────────────────────────────

async function resolveActorTechniques(
  actorIds: string[],
  actorNames: string[],
  ctx: EngagementContext
): Promise<ActorTechnique[]> {
  const db = await getDb();
  if (!db) return [];

  // Get techniques from TTP knowledge base that are associated with these actors
  const allTechniques = await db.select().from(ttpKnowledge)
    .orderBy(desc(ttpKnowledge.confidence))
    .limit(500);

  const actorTechniques: ActorTechnique[] = [];
  const nameSet = new Set(actorNames.map(n => n.toLowerCase()));

  for (const tech of allTechniques) {
    const envConstraints = (tech.environmentalConstraints as any) || {};
    const associatedActors = (envConstraints.associatedActors as any[]) || [];
    const toolsUsed = (tech.toolsUsed as any[]) || [];
    const execMethods = (tech.executionMethods as any[]) || [];
    const detectionRules = (tech.detectionRules as any[]) || [];

    // Check if this technique is associated with any of our matched actors
    const usedByActors = associatedActors
      .filter((a: any) => actorIds.includes(a.id) || nameSet.has((a.name || "").toLowerCase()))
      .map((a: any) => a.name || a.id);

    // Also check toolsUsed.commonActors
    for (const tool of toolsUsed) {
      const commonActors = (tool.commonActors as string[]) || [];
      for (const ca of commonActors) {
        if (nameSet.has(ca.toLowerCase()) && !usedByActors.includes(ca)) {
          usedByActors.push(ca);
        }
      }
    }

    // If specific technique IDs requested, include those regardless of actor match
    const isRequested = ctx.techniqueIds?.includes(tech.techniqueId);

    if (usedByActors.length > 0 || isRequested) {
      // Count detection rules by format
      const detectionCoverage = { sigma: 0, yara: 0, splunk: 0, kql: 0 };
      for (const rule of detectionRules) {
        const fmt = (rule as any).format || "";
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
        executionReliability: -1, // Will be enriched by C2 learning step
        executionMethods: execMethods.slice(0, 5),
        tools: toolsUsed.map((t: any) => t.name).filter(Boolean).slice(0, 10),
        detectionCoverage,
        killChainPhase: tech.attackChainPosition || tech.tactic,
        prerequisites: (tech.prerequisiteTechniques as string[]) || [],
        followUps: (tech.followUpTechniques as string[]) || [],
        redTeamValue: tech.redTeamValue || 5,
        dataSource: tech.dataSource || "unknown",
      });
    }
  }

  return actorTechniques;
}

// ─── Step 3: Resolve Actor IOCs from All Feeds ──────────────────────────

async function resolveActorIOCs(actorNames: string[], ctx: EngagementContext): Promise<ActorIOC[]> {
  const db = await getDb();
  if (!db) return [];

  const iocs: ActorIOC[] = [];

  // Get IOCs from ioc_feeds that mention actor names in description
  const conditions = actorNames.slice(0, 10).map(name =>
    like(iocFeeds.description, `%${name}%`)
  );

  if (conditions.length > 0) {
    const feedIOCs = await db.select().from(iocFeeds)
      .where(or(...conditions))
      .orderBy(desc(iocFeeds.id))
      .limit(100);

    for (const ioc of feedIOCs) {
      if (!ioc.iocValue) continue;
      const matchedActors = actorNames.filter(name =>
        (ioc.description || "").toLowerCase().includes(name.toLowerCase())
      );
      iocs.push({
        type: ioc.iocType || "unknown",
        value: ioc.iocValue,
        actorAttribution: matchedActors.length > 0 ? matchedActors : ["unattributed"],
        source: ioc.feedSource,
        severity: ioc.severity || "medium",
        firstSeen: ioc.dateAdded || "unknown",
        lastSeen: ioc.dateAdded || "unknown",
        context: (ioc.title || ioc.description || "").slice(0, 300),
      });
    }
  }

  // Also get CISA KEV entries (high-value IOCs)
  const kevEntries = await db.select().from(iocFeeds)
    .where(eq(iocFeeds.feedSource, "cisa_kev"))
    .orderBy(desc(iocFeeds.id))
    .limit(50);

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
      context: `${kev.title || ""} — ${kev.vendorProduct || ""}`.trim().slice(0, 300),
    });
  }

  return iocs;
}

// ─── Step 4: Resolve Actor Tooling ──────────────────────────────────────

async function resolveActorTooling(actorIds: string[]): Promise<ActorTooling[]> {
  const db = await getDb();
  if (!db) return [];

  const tooling: ActorTooling[] = [];
  const toolMap = new Map<string, ActorTooling>();

  // Get actors with their tools and malware
  const actors = actorIds.length > 0
    ? await db.select().from(threatActors).where(inArray(threatActors.actorId, actorIds))
    : [];

  for (const actor of actors) {
    const tools = (actor.tools as string[]) || [];
    const malware = (actor.malware as string[]) || [];
    const techniques = (actor.techniques as any[]) || [];
    const techIds = techniques.map((t: any) => t.id || t.techniqueId).filter(Boolean);

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
          source: "threat-catalog",
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
          source: "threat-catalog",
        });
      }
    }
  }

  return Array.from(toolMap.values());
}

// ─── Step 5: Resolve Behavioral Patterns from Incident Reports ──────────

async function resolveBehavioralPatterns(actorNames: string[], ctx: EngagementContext): Promise<BehavioralPattern[]> {
  const db = await getDb();
  if (!db) return [];

  const patterns: BehavioralPattern[] = [];

  // Find incident reports mentioning these actors
  const conditions = actorNames.slice(0, 10).map(name =>
    sql`JSON_SEARCH(${incidentReports.actorsIdentified}, 'one', ${`%${name}%`}) IS NOT NULL`
  );

  let reports: any[] = [];
  if (conditions.length > 0) {
    reports = await db.select().from(incidentReports)
      .where(or(...conditions))
      .orderBy(desc(incidentReports.id))
      .limit(50);
  }

  // Also get reports matching the target sector
  if (ctx.targetSector) {
    const sectorReports = await db.select().from(incidentReports)
      .where(sql`JSON_SEARCH(${incidentReports.targetSectors}, 'one', ${`%${ctx.targetSector}%`}) IS NOT NULL`)
      .orderBy(desc(incidentReports.id))
      .limit(20);
    reports = [...reports, ...sectorReports];
  }

  // Extract behavioral patterns from attack sequences
  const patternMap = new Map<string, BehavioralPattern>();

  for (const report of reports) {
    const sequence = (report.attackSequence as any[]) || [];
    const actors = (report.actorsIdentified as any[]) || [];
    const actorName = actors[0]?.name || "Unknown";

    // Extract initial access preference
    const initialAccess = sequence.find((s: any) =>
      s.tactic?.toLowerCase().includes("initial") || s.phase?.toLowerCase().includes("initial")
    );
    if (initialAccess) {
      const key = `${actorName}-initial_access`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = (initialAccess.techniques || initialAccess.technique || []);
        const techIds = Array.isArray(techniques)
          ? techniques.map((t: any) => t.techniqueId || t.id || t).filter(Boolean)
          : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "initial_access_preference",
          description: initialAccess.description || `${actorName} initial access pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 60,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown",
        });
      }
    }

    // Extract persistence approach
    const persistence = sequence.find((s: any) =>
      s.tactic?.toLowerCase().includes("persistence") || s.phase?.toLowerCase().includes("persistence")
    );
    if (persistence) {
      const key = `${actorName}-persistence`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = (persistence.techniques || persistence.technique || []);
        const techIds = Array.isArray(techniques)
          ? techniques.map((t: any) => t.techniqueId || t.id || t).filter(Boolean)
          : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "persistence_approach",
          description: persistence.description || `${actorName} persistence pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 55,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown",
        });
      }
    }

    // Extract lateral movement style
    const lateral = sequence.find((s: any) =>
      s.tactic?.toLowerCase().includes("lateral") || s.phase?.toLowerCase().includes("lateral")
    );
    if (lateral) {
      const key = `${actorName}-lateral_movement`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = (lateral.techniques || lateral.technique || []);
        const techIds = Array.isArray(techniques)
          ? techniques.map((t: any) => t.techniqueId || t.id || t).filter(Boolean)
          : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "lateral_movement_style",
          description: lateral.description || `${actorName} lateral movement pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 55,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown",
        });
      }
    }

    // Extract exfiltration method
    const exfil = sequence.find((s: any) =>
      s.tactic?.toLowerCase().includes("exfil") || s.phase?.toLowerCase().includes("exfil")
    );
    if (exfil) {
      const key = `${actorName}-exfiltration`;
      const existing = patternMap.get(key);
      if (existing) {
        existing.sourceReports++;
        existing.confidence = Math.min(100, existing.confidence + 5);
      } else {
        const techniques = (exfil.techniques || exfil.technique || []);
        const techIds = Array.isArray(techniques)
          ? techniques.map((t: any) => t.techniqueId || t.id || t).filter(Boolean)
          : [techniques];
        patternMap.set(key, {
          actorName,
          patternType: "exfil_method",
          description: exfil.description || `${actorName} exfiltration pattern`,
          techniques: techIds.slice(0, 5),
          confidence: 50,
          sourceReports: 1,
          lastObserved: report.publishedAt || "unknown",
        });
      }
    }
  }

  return Array.from(patternMap.values());
}

// ─── Step 6: Resolve C2 Execution Insights ──────────────────────────────

async function resolveExecutionInsights(techniqueIds: string[]): Promise<ExecutionInsight[]> {
  // Import C2 learning engine functions dynamically to avoid circular deps
  try {
    const { getHistoryForTechnique, calculateTechniqueReliability } = await import("./c2-learning-engine");

    const insights: ExecutionInsight[] = [];

    for (const techId of techniqueIds.slice(0, 50)) {
      const history = getHistoryForTechnique(techId);
      if (history.length === 0) continue;

      const reliability = calculateTechniqueReliability(techId);
      if (!reliability) continue;

      // Analyze platform success rates
      const platformStats = new Map<string, { success: number; total: number }>();
      const defenseBlocks = new Map<string, number>();
      const defenseMisses = new Map<string, number>();
      const lessons: string[] = [];

      for (const record of history) {
        const platform = record.feedback.targetContext.platform;
        const stats = platformStats.get(platform) || { success: 0, total: 0 };
        stats.total++;
        if (record.outcome.success) stats.success++;
        platformStats.set(platform, stats);

        // Track which defenses block/miss
        const defenses = record.feedback.targetContext.defenses || [];
        for (const def of defenses) {
          if (record.outcome.success) {
            defenseMisses.set(def, (defenseMisses.get(def) || 0) + 1);
          } else {
            defenseBlocks.set(def, (defenseBlocks.get(def) || 0) + 1);
          }
        }

        // Collect lessons
        for (const lesson of record.outcome.lessonsLearned.slice(0, 2)) {
          if (!lessons.includes(lesson)) lessons.push(lesson);
        }
      }

      // Find best/worst platforms
      let bestPlatform = "unknown";
      let worstPlatform = "unknown";
      let bestRate = -1;
      let worstRate = 101;
      for (const [platform, stats] of platformStats) {
        const rate = stats.total > 0 ? (stats.success / stats.total) * 100 : 0;
        if (rate > bestRate) { bestRate = rate; bestPlatform = platform; }
        if (rate < worstRate) { worstRate = rate; worstPlatform = platform; }
      }

      insights.push({
        techniqueId: techId,
        framework: reliability.primaryFramework || "mixed",
        successRate: reliability.successRate,
        avgConfidenceAdjustment: reliability.avgConfidenceAdjustment,
        bestPlatform,
        worstPlatform,
        defensesThatBlock: Array.from(defenseBlocks.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([def]) => def),
        defensesThatMiss: Array.from(defenseMisses.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([def]) => def),
        lessonsLearned: lessons.slice(0, 5),
        totalExecutions: history.length,
      });
    }

    return insights;
  } catch {
    return [];
  }
}

// ─── Step 7: Darkweb Enrichment ─────────────────────────────────────────

async function resolveDarkwebEnrichment(
  actorNames: string[],
  ctx: EngagementContext
): Promise<{ iocs: ActorIOC[]; tools: ActorTooling[] }> {
  const db = await getDb();
  if (!db) return { iocs: [], tools: [] };

  const iocs: ActorIOC[] = [];
  const tools: ActorTooling[] = [];

  // Query darkweb enriched records related to our actors
  const conditions = actorNames.slice(0, 10).map(name =>
    sql`JSON_SEARCH(${darkwebEnrichedRecords.relatedActors}, 'one', ${`%${name}%`}) IS NOT NULL`
  );

  if (conditions.length > 0) {
    const records = await db.select().from(darkwebEnrichedRecords)
      .where(or(...conditions))
      .orderBy(desc(darkwebEnrichedRecords.riskScore))
      .limit(50);

    for (const record of records) {
      const relatedActors = (record.relatedActors as string[]) || [];
      const relatedIocs = (record.relatedIocs as any[]) || [];
      const mitreTechniques = (record.mitreTechniques as string[]) || [];

      // Extract IOCs
      for (const ioc of relatedIocs.slice(0, 10)) {
        iocs.push({
          type: ioc.type || "unknown",
          value: ioc.value || "",
          actorAttribution: relatedActors,
          source: "darkweb",
          severity: record.riskScore && record.riskScore > 70 ? "high" : "medium",
          firstSeen: record.createdAt?.toISOString() || "unknown",
          lastSeen: record.createdAt?.toISOString() || "unknown",
          context: (record.threatAssessment || "").slice(0, 300),
        });
      }

      // Extract tools mentioned in threat assessment
      if (record.threatAssessment) {
        const toolPatterns = /(?:using|via|through|with)\s+([A-Z][a-zA-Z0-9_-]+(?:\s+[A-Z][a-zA-Z0-9_-]+)?)/g;
        let match;
        while ((match = toolPatterns.exec(record.threatAssessment)) !== null) {
          const toolName = match[1]!.trim();
          if (toolName.length > 2 && toolName.length < 40) {
            tools.push({
              name: toolName,
              type: "darkweb_observed",
              usedBy: relatedActors,
              techniques: mitreTechniques.slice(0, 5),
              description: `Observed in darkweb intelligence: ${(record.threatAssessment || "").slice(0, 100)}`,
              source: "darkweb-enrichment",
            });
          }
        }
      }
    }
  }

  return { iocs, tools };
}

// ─── Step 8: SpicyTIP Enrichment ────────────────────────────────────────

async function resolveSpicyTIPEnrichment(
  actorNames: string[]
): Promise<{ iocs: ActorIOC[]; patterns: BehavioralPattern[] }> {
  const iocs: ActorIOC[] = [];
  const patterns: BehavioralPattern[] = [];

  try {
    const {
      getThreatFoxIOCs,
      getOTXPulses,
      getGlobalThreatActors,
      isBridgeConfigured,
    } = await import("./spicy-tip-bridge");

    if (!isBridgeConfigured()) return { iocs, patterns };

    // Get ThreatFox IOCs and correlate with actors
    const threatFoxData = await getThreatFoxIOCs(100);
    if (threatFoxData) {
      for (const entry of threatFoxData) {
        const entryStr = JSON.stringify(entry).toLowerCase();
        const matchedActors = actorNames.filter(name => entryStr.includes(name.toLowerCase()));
        if (matchedActors.length > 0) {
          iocs.push({
            type: (entry as any).ioc_type || "unknown",
            value: (entry as any).ioc || (entry as any).value || "",
            actorAttribution: matchedActors,
            source: "spicytip-threatfox",
            severity: (entry as any).confidence_level > 75 ? "high" : "medium",
            firstSeen: (entry as any).first_seen || "unknown",
            lastSeen: (entry as any).last_seen || (entry as any).first_seen || "unknown",
            context: (entry as any).malware || (entry as any).tags?.join(", ") || "",
          });
        }
      }
    }

    // Get OTX pulses for actor-related intelligence
    const otxPulses = await getOTXPulses(50);
    if (otxPulses) {
      for (const pulse of otxPulses) {
        const pulseStr = JSON.stringify(pulse).toLowerCase();
        const matchedActors = actorNames.filter(name => pulseStr.includes(name.toLowerCase()));
        if (matchedActors.length > 0) {
          // Extract behavioral pattern from pulse
          patterns.push({
            actorName: matchedActors[0]!,
            patternType: "threat_intelligence_pulse",
            description: (pulse as any).name || (pulse as any).description || "OTX pulse",
            techniques: ((pulse as any).attack_ids || []).map((a: any) => a.id || a).slice(0, 5),
            confidence: 65,
            sourceReports: 1,
            lastObserved: (pulse as any).created || "unknown",
          });
        }
      }
    }

    // Get global threat actors for enrichment
    const globalActors = await getGlobalThreatActors(50);
    if (globalActors) {
      for (const ga of globalActors) {
        const gaName = ((ga as any).name || "").toLowerCase();
        if (actorNames.some(n => gaName.includes(n.toLowerCase()) || n.toLowerCase().includes(gaName))) {
          const ttps = (ga as any).ttps || (ga as any).techniques || [];
          if (ttps.length > 0) {
            patterns.push({
              actorName: (ga as any).name || "Unknown",
              patternType: "spicytip_actor_profile",
              description: (ga as any).description || `SpicyTIP profile for ${(ga as any).name}`,
              techniques: ttps.slice(0, 10),
              confidence: 70,
              sourceReports: 1,
              lastObserved: (ga as any).lastSeen || "unknown",
            });
          }
        }
      }
    }
  } catch {
    // SpicyTIP bridge not available — graceful degradation
  }

  return { iocs, patterns };
}

// ─── Step 9: TTP Learning Pipeline ──────────────────────────────────────

/**
 * The TTP Learning Pipeline discovers NEW techniques from data sources
 * that aren't yet in the MITRE ATT&CK framework or our knowledge base.
 *
 * Sources:
 * 1. Incident reports — novel attack patterns in extracted sequences
 * 2. Darkweb feeds — new access broker techniques, exploit methods
 * 3. C2 execution feedback — unexpected successful techniques
 * 4. SpicyTIP intelligence — emerging threat patterns
 */
async function learnNewTTPs(actorNames: string[], ctx: EngagementContext): Promise<NovelTechnique[]> {
  const db = await getDb();
  if (!db) return [];

  const novelTechniques: NovelTechnique[] = [];

  // ── Source 1: Incident Reports — find techniques not in knowledge base ──
  const recentReports = await db.select().from(incidentReports)
    .where(isNotNull(incidentReports.ttpsExtracted))
    .orderBy(desc(incidentReports.id))
    .limit(100);

  // Get all known technique IDs
  const knownTechniques = await db.select({ techniqueId: ttpKnowledge.techniqueId })
    .from(ttpKnowledge);
  const knownSet = new Set(knownTechniques.map(t => t.techniqueId));

  for (const report of recentReports) {
    const ttps = (report.ttpsExtracted as any[]) || [];
    const actors = (report.actorsIdentified as any[]) || [];
    const actorNamesList = actors.map((a: any) => a.name).filter(Boolean);

    for (const ttp of ttps) {
      const techId = ttp.techniqueId || ttp.id;

      // Check if this technique is NOT in our knowledge base
      if (techId && !knownSet.has(techId)) {
        // This is a technique mentioned in a report but not yet in our KB
        const tempId = `novel-report-${techId || Date.now().toString(36)}`;

        // Check if we already discovered this one
        if (novelTechniques.some(n => n.tempId === tempId)) continue;

        novelTechniques.push({
          tempId,
          closestMitreId: techId?.startsWith("T") ? techId : null,
          name: ttp.techniqueName || ttp.name || `Unknown technique ${techId}`,
          tactic: ttp.tactic || "unknown",
          discoverySource: "incident_report",
          evidence: `Found in report: "${report.title}" — ${(report.summary || "").slice(0, 200)}`,
          observedActors: actorNamesList,
          associatedTools: (report.malwareIdentified as string[]) || [],
          analysis: "",
          reviewed: false,
          noveltyConfidence: ttp.confidence || 50,
          discoveredAt: report.publishedAt || new Date().toISOString(),
        });
      }
    }

    // Also check the attack sequence for non-standard phases/techniques
    const sequence = (report.attackSequence as any[]) || [];
    for (const phase of sequence) {
      const techniques = phase.techniques || [];
      for (const tech of (Array.isArray(techniques) ? techniques : [])) {
        const techId = tech.techniqueId || tech.id;
        if (!techId || knownSet.has(techId)) continue;

        const tempId = `novel-seq-${techId || Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
        if (novelTechniques.some(n => n.closestMitreId === techId)) continue;

        novelTechniques.push({
          tempId,
          closestMitreId: techId?.startsWith("T") ? techId : null,
          name: tech.name || tech.techniqueName || `Sequence technique ${techId}`,
          tactic: phase.tactic || phase.phase || "unknown",
          discoverySource: "incident_report",
          evidence: `Attack sequence phase "${phase.phase || phase.tactic}": ${tech.description || ""}`.slice(0, 300),
          observedActors: actorNamesList,
          associatedTools: (tech.tools as string[]) || [],
          analysis: "",
          reviewed: false,
          noveltyConfidence: 45,
          discoveredAt: report.publishedAt || new Date().toISOString(),
        });
      }
    }
  }

  // ── Source 2: Darkweb feeds — new access methods and exploit techniques ──
  const darkwebRecords = await db.select().from(darkwebEnrichedRecords)
    .where(
      and(
        isNotNull(darkwebEnrichedRecords.mitreTechniques),
        gt(darkwebEnrichedRecords.riskScore, 50)
      )
    )
    .orderBy(desc(darkwebEnrichedRecords.riskScore))
    .limit(100);

  for (const record of darkwebRecords) {
    const techniques = (record.mitreTechniques as string[]) || [];
    const relatedActors = (record.relatedActors as string[]) || [];

    for (const techId of techniques) {
      if (!techId || knownSet.has(techId)) continue;

      const tempId = `novel-darkweb-${techId}`;
      if (novelTechniques.some(n => n.tempId === tempId)) continue;

      novelTechniques.push({
        tempId,
        closestMitreId: techId.startsWith("T") ? techId : null,
        name: `Darkweb-observed technique ${techId}`,
        tactic: (record.mitreTactics as string[])?.[0] || "unknown",
        discoverySource: "darkweb",
        evidence: `Darkweb intelligence (risk score: ${record.riskScore}): ${(record.threatAssessment || "").slice(0, 200)}`,
        observedActors: relatedActors,
        associatedTools: [],
        analysis: "",
        reviewed: false,
        noveltyConfidence: record.riskScore ? Math.min(80, record.riskScore) : 40,
        discoveredAt: record.createdAt?.toISOString() || new Date().toISOString(),
      });
    }
  }

  // ── Source 3: C2 execution feedback — unexpected successes ──
  try {
    const { getExecutionHistory } = await import("./c2-learning-engine");
    const history = getExecutionHistory({ limit: 200 });

    for (const record of (history || [])) {
      const techId = record.feedback?.techniqueId;
      if (!techId || knownSet.has(techId)) continue;

      const tempId = `novel-c2-${techId}`;
      if (novelTechniques.some(n => n.tempId === tempId)) continue;

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
        discoveredAt: record.timestamp || new Date().toISOString(),
      });
    }
  } catch {
    // C2 learning engine not available
  }

  // ── LLM analysis of novel techniques (batch for efficiency) ──
  if (novelTechniques.length > 0) {
    try {
      const batch = novelTechniques.slice(0, 15); // Analyze top 15
      const analysisPrompt = batch.map((nt, i) =>
        `${i + 1}. ${nt.name} (${nt.tactic}) — Source: ${nt.discoverySource}\n   Evidence: ${nt.evidence.slice(0, 150)}`
      ).join("\n");

      const response = await invokeLLM({
        messages: [
          {
            role: "system",
            content: `You are a threat intelligence analyst. For each technique below, provide a brief analysis (2-3 sentences) of:
1. Whether this is genuinely novel or a known technique with a different name
2. The closest MITRE ATT&CK technique if applicable
3. The potential impact and recommended detection approach
Return a JSON array of objects with fields: index (1-based), analysis (string), isNovel (boolean), closestMitre (string or null).`,
          },
          { role: "user", content: analysisPrompt },
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
                      closestMitre: { type: ["string", "null"] },
                    },
                    required: ["index", "analysis", "isNovel", "closestMitre"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["techniques"],
              additionalProperties: false,
            },
          },
        },
      });

      const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
      const analyses = parsed.techniques || [];

      for (const a of analyses) {
        const idx = (a.index || 0) - 1;
        if (idx >= 0 && idx < batch.length) {
          batch[idx]!.analysis = a.analysis || "";
          if (a.closestMitre) batch[idx]!.closestMitreId = a.closestMitre;
          if (!a.isNovel) batch[idx]!.noveltyConfidence = Math.max(10, (batch[idx]!.noveltyConfidence || 50) - 30);
        }
      }
    } catch {
      // LLM analysis is best-effort
    }
  }

  return novelTechniques;
}

// ─── Module-Specific Relevance Tuning ───────────────────────────────────

/**
 * Tunes the technique list based on which module is requesting context.
 * Different modules care about different phases of the kill chain.
 */
function tuneForModule(
  techniques: ActorTechnique[],
  module: string,
  maxCount: number
): ActorTechnique[] {
  const tacticPriority: Record<string, string[]> = {
    "ad-attack-sim": ["credential-access", "lateral-movement", "persistence", "privilege-escalation", "defense-evasion"],
    "cloud-attack-paths": ["initial-access", "privilege-escalation", "persistence", "defense-evasion", "collection"],
    "credential-engine": ["credential-access", "initial-access", "brute-force", "persistence"],
    "zap-playbooks": ["initial-access", "execution", "reconnaissance", "resource-development"],
    "sigma-rules": ["defense-evasion", "execution", "persistence", "lateral-movement", "exfiltration"],
    "auth-assessment": ["credential-access", "initial-access", "persistence", "defense-evasion"],
    "campaign-design": ["initial-access", "execution", "persistence", "privilege-escalation", "lateral-movement", "collection", "exfiltration"],
    "discovery-chain": ["reconnaissance", "discovery", "initial-access"],
    "phishing": ["initial-access", "execution", "social-engineering"],
    "soc-dashboard": ["defense-evasion", "exfiltration", "command-and-control", "impact", "lateral-movement"],
  };

  const priorities = tacticPriority[module] || [];

  if (priorities.length === 0) {
    return techniques.slice(0, maxCount);
  }

  // Score each technique based on module relevance
  const scored = techniques.map(t => {
    const tacticNorm = t.tactic.toLowerCase().replace(/\s+/g, "-");
    const priorityIndex = priorities.findIndex(p => tacticNorm.includes(p) || p.includes(tacticNorm));
    const priorityScore = priorityIndex >= 0 ? (priorities.length - priorityIndex) * 10 : 0;
    const confidenceScore = t.confidence / 10;
    const redTeamScore = t.redTeamValue;
    return { technique: t, score: priorityScore + confidenceScore + redTeamScore };
  });

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxCount).map(s => s.technique);
}

// ─── Deduplication Helpers ──────────────────────────────────────────────

function deduplicateIOCs(iocs: ActorIOC[]): ActorIOC[] {
  const seen = new Map<string, ActorIOC>();
  for (const ioc of iocs) {
    const key = `${ioc.type}:${ioc.value}`;
    const existing = seen.get(key);
    if (existing) {
      // Merge actor attributions
      for (const actor of ioc.actorAttribution) {
        if (!existing.actorAttribution.includes(actor)) {
          existing.actorAttribution.push(actor);
        }
      }
      // Keep higher severity
      if (severityRank(ioc.severity) > severityRank(existing.severity)) {
        existing.severity = ioc.severity;
      }
    } else {
      seen.set(key, { ...ioc });
    }
  }
  return Array.from(seen.values());
}

function deduplicateTooling(tools: ActorTooling[]): ActorTooling[] {
  const seen = new Map<string, ActorTooling>();
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

function severityRank(s: string): number {
  const ranks: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return ranks[s] || 0;
}

// ─── Convenience: Module-Specific Context Getters ───────────────────────

/**
 * Get actor context optimized for AD Attack Simulation.
 * Prioritizes credential access, lateral movement, and Kerberos-related TTPs.
 */
export async function getADAttackContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "ad-attack-sim",
    maxTechniques: 30,
    includeNovelTechniques: true,
    ...engagementCtx,
  });
}

/**
 * Get actor context optimized for Cloud Attack Paths.
 * Prioritizes cloud-specific TTPs, IAM abuse, and privilege escalation.
 */
export async function getCloudAttackContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "cloud-attack-paths",
    maxTechniques: 30,
    includeNovelTechniques: true,
    ...engagementCtx,
  });
}

/**
 * Get actor context optimized for Credential Testing.
 * Prioritizes credential access techniques, default creds, and brute force patterns.
 */
export async function getCredentialAttackContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "credential-engine",
    maxTechniques: 25,
    includeNovelTechniques: false,
    ...engagementCtx,
  });
}

/**
 * Get actor context optimized for ZAP Web Application Playbooks.
 * Prioritizes web-specific TTPs, initial access, and injection techniques.
 */
export async function getZAPPlaybookContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "zap-playbooks",
    maxTechniques: 20,
    includeNovelTechniques: false,
    ...engagementCtx,
  });
}

/**
 * Get actor context optimized for Sigma Rule Generation.
 * Prioritizes techniques with high detection value and defense evasion.
 */
export async function getSigmaRuleContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "sigma-rules",
    maxTechniques: 40,
    includeNovelTechniques: true,
    ...engagementCtx,
  });
}

/**
 * Get actor context optimized for Campaign Design.
 * Returns the full kill chain with all phases represented.
 */
export async function getCampaignDesignContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "campaign-design",
    maxTechniques: 60,
    maxActors: 5,
    includeNovelTechniques: true,
    learnNewTTPs: true,
    ...engagementCtx,
  });
}

/**
 * Get actor context optimized for SOC Dashboard / WATCH ADVISOR.
 * Prioritizes detection-relevant TTPs, active IOCs, and defense evasion.
 */
export async function getSOCDashboardContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "soc-dashboard",
    maxTechniques: 40,
    maxActors: 15,
    includeNovelTechniques: true,
    ...engagementCtx,
  });
}

/**
 * Get actor context optimized for Auth Assessment.
 * Prioritizes credential access, OAuth/SAML abuse, and session hijacking.
 */
export async function getAuthAssessmentContext(engagementCtx: Partial<EngagementContext> = {}): Promise<ActorContext> {
  return getActorContext({
    requestingModule: "auth-assessment",
    maxTechniques: 20,
    includeNovelTechniques: true,
    ...engagementCtx,
  });
}

/**
 * Get a summary string suitable for injection into LLM prompts.
 * Compresses the full ActorContext into a concise intelligence briefing.
 */
export function summarizeForPrompt(context: ActorContext, maxLength = 2000): string {
  const lines: string[] = [];

  lines.push(`## Threat Actor Intelligence Briefing`);
  lines.push(`Sources: ${context.meta.sourcesSucceeded.length}/${context.meta.sourcesQueried.length} succeeded | ${context.meta.actorCount} actors | ${context.meta.techniqueCount} techniques | ${context.meta.iocCount} IOCs | ${context.meta.novelTechniqueCount} novel TTPs`);
  lines.push("");

  // Top actors
  if (context.actors.length > 0) {
    lines.push(`### Matched Threat Actors`);
    for (const actor of context.actors.slice(0, 5)) {
      lines.push(`- **${actor.name}** (${actor.type}, ${actor.origin}) — ${actor.threatLevel} threat, ${actor.sophistication} sophistication. ${actor.matchReasons.join("; ")}`);
    }
    lines.push("");
  }

  // Top techniques by tactic
  if (context.techniques.length > 0) {
    lines.push(`### Key Techniques (${context.techniques.length} total)`);
    const byTactic = new Map<string, ActorTechnique[]>();
    for (const t of context.techniques.slice(0, 20)) {
      const list = byTactic.get(t.tactic) || [];
      list.push(t);
      byTactic.set(t.tactic, list);
    }
    for (const [tactic, techs] of byTactic) {
      const techStr = techs.map(t => `${t.techniqueId} ${t.techniqueName} (${t.usedBy.join(",")})`).join("; ");
      lines.push(`- **${tactic}**: ${techStr}`);
    }
    lines.push("");
  }

  // Novel techniques
  if (context.novelTechniques.length > 0) {
    lines.push(`### Novel/Emerging Techniques (${context.novelTechniques.length})`);
    for (const nt of context.novelTechniques.slice(0, 5)) {
      lines.push(`- **${nt.name}** (${nt.tactic}) — Source: ${nt.discoverySource}, Confidence: ${nt.noveltyConfidence}%`);
      if (nt.analysis) lines.push(`  ${nt.analysis.slice(0, 150)}`);
    }
    lines.push("");
  }

  // Behavioral patterns
  if (context.behavioralPatterns.length > 0) {
    lines.push(`### Behavioral Patterns`);
    for (const bp of context.behavioralPatterns.slice(0, 5)) {
      lines.push(`- **${bp.actorName}** ${bp.patternType}: ${bp.description.slice(0, 100)} (${bp.sourceReports} reports, ${bp.confidence}% confidence)`);
    }
    lines.push("");
  }

  // Execution insights
  if (context.executionInsights.length > 0) {
    lines.push(`### C2 Execution Insights`);
    for (const ei of context.executionInsights.slice(0, 5)) {
      lines.push(`- **${ei.techniqueId}**: ${ei.successRate.toFixed(0)}% success rate (${ei.totalExecutions} runs). Best: ${ei.bestPlatform}. Blocked by: ${ei.defensesThatBlock.join(", ") || "none observed"}`);
    }
  }

  let result = lines.join("\n");
  if (result.length > maxLength) {
    result = result.slice(0, maxLength - 3) + "...";
  }
  return result;
}
