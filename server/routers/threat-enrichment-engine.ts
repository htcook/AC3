import * as db from "../db";
// @ts-nocheck
/**
 * Threat Intelligence Enrichment Engine
 * 
 * Continuously learns threat actor TTPs and IOCs from the threat catalog
 * and feeds enriched data into all applicable platform modules:
 * - Key Security Indicator evidence analysis, monitoring, evaluation, and validation
 * - Attack vector scoring and identification
 * - Configuration baseline threat-informed prioritization
 * - Engagement planning with threat-actor-specific playbooks
 * 
 * This engine acts as the central nervous system connecting threat intelligence
 * to every operational module in the platform.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb, getDbRequired } from "../db";
import { eq, desc, sql, count, and, gte, isNotNull } from "drizzle-orm";
import {
  threatActors,
  threatActorIocs,
  ttpKnowledge,
  ksiDefinitions,
  ksiEvidence,
  ksiEvidenceChains,
  ksiValidationRuns,
  ksiValidationSchedules,
  attackVectors,
  configBaselines,
  configScanResults,
} from "../../drizzle/schema";

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Safely parse the techniques JSON field — handles string, array, and null */
function parseTechniques(raw: unknown): { id: string; name?: string; tactic?: string }[] {
  if (!raw) return [];
  let arr = raw;
  if (typeof arr === "string") {
    try { arr = JSON.parse(arr); } catch { return []; }
  }
  if (!Array.isArray(arr)) return [];
  return arr;
}

async function getDbSafe() {
  const db = await getDbRequired();
  if (!db) throw new Error('Database not initialized');
  return db;
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatEnrichmentResult {
  actorId: string;
  actorName: string;
  techniques: { id: string; name: string; tactic: string }[];
  iocs: { type: string; value: string; confidence: string }[];
  tools: string[];
  malware: string[];
  threatLevel: string;
}

interface KsiEnrichmentFeed {
  ksiId: string;
  ksiName: string;
  relevantActors: { actorId: string; name: string; threatLevel: string; techniqueCount: number }[];
  relevantIocs: { type: string; count: number; latestValue: string }[];
  relevantTechniques: { id: string; name: string; tactic: string; actorCount: number }[];
  riskScore: number; // 0-100 based on threat landscape
  lastEnriched: number;
}

// ─── KSI-to-MITRE Technique Mapping ──────────────────────────────────────────
// Maps each KSI theme to the MITRE ATT&CK techniques that are most relevant
const KSI_TECHNIQUE_MAP: Record<string, string[]> = {
  // Secure Vulnerability & Configuration (SVC)
  "SVC": ["T1190", "T1133", "T1210", "T1068", "T1203", "T1211", "T1212", "T1080"],
  // Monitoring, Logging & Auditing (MLA)
  "MLA": ["T1070", "T1562", "T1036", "T1027", "T1564", "T1112", "T1222", "T1548"],
  // Identity, Authentication & Access Management (IAM)
  "IAM": ["T1078", "T1110", "T1556", "T1528", "T1539", "T1550", "T1552", "T1558"],
  // Incident Response (INR)
  "INR": ["T1486", "T1490", "T1489", "T1485", "T1561", "T1529", "T1498", "T1499"],
  // Security Continuous Reporting (SCR)
  "SCR": ["T1595", "T1592", "T1589", "T1590", "T1591", "T1598", "T1566", "T1534"],
  // Cloud Native Architecture (CNA)
  "CNA": ["T1525", "T1610", "T1609", "T1611", "T1613", "T1612", "T1552.007"],
  // Change Management (CMT)
  "CMT": ["T1195", "T1199", "T1072", "T1059", "T1053", "T1543", "T1547"],
  // Data Protection (DPR)
  "DPR": ["T1005", "T1039", "T1025", "T1114", "T1119", "T1530", "T1537", "T1567"],
  // Policy & Inventory (PIN)
  "PIN": ["T1583", "T1584", "T1585", "T1586", "T1587", "T1588"],
  // Authorization (AUT)
  "AUT": ["T1078", "T1098", "T1136", "T1134", "T1484", "T1548"],
  // Risk Assessment (RSK)
  "RSK": ["T1595", "T1592", "T1589", "T1590", "T1591"],
};

// ─── Helper: Extract KSI theme from KSI ID ──────────────────────────────────
function getKsiTheme(ksiId: string): string {
  // KSI-SVC-VSR → SVC
  const parts = ksiId.split("-");
  return parts.length >= 2 ? parts[1] : "";
}

// ─── Helper: Calculate risk score based on threat landscape ──────────────────
function calculateRiskScore(
  actorCount: number,
  criticalActors: number,
  iocCount: number,
  techniqueCount: number,
  recentActivity: boolean
): number {
  let score = 0;
  // Actor coverage (0-30)
  score += Math.min(30, actorCount * 3);
  // Critical actors (0-25)
  score += Math.min(25, criticalActors * 8);
  // IOC density (0-20)
  score += Math.min(20, Math.log2(iocCount + 1) * 4);
  // Technique breadth (0-15)
  score += Math.min(15, techniqueCount * 2);
  // Recent activity bonus (0-10)
  if (recentActivity) score += 10;
  return Math.min(100, Math.round(score));
}

// ─── Router ──────────────────────────────────────────────────────────────────

export const threatEnrichmentEngineRouter = router({

  // ─── Get Enrichment Dashboard Stats ──────────────────────────────────────
  getDashboardStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    const [actorCountResult] = await db.select({ count: count() }).from(threatActors);
    const [iocCountResult] = await db.select({ count: count() }).from(threatActorIocs);
    const [ttpCountResult] = await db.select({ count: count() }).from(ttpKnowledge);
    const [ksiCountResult] = await db.select({ count: count() }).from(ksiDefinitions);
    const [evidenceCountResult] = await db.select({ count: count() }).from(ksiEvidence);
    const [vectorCountResult] = await db.select({ count: count() }).from(attackVectors);

    // Actor breakdown by type
    const actorsByType = await db.select({
      type: threatActors.type,
      count: count(),
    }).from(threatActors).groupBy(threatActors.type);

    // Actor breakdown by threat level
    const actorsByThreatLevel = await db.select({
      threatLevel: threatActors.threatLevel,
      count: count(),
    }).from(threatActors).groupBy(threatActors.threatLevel);

    // IOC breakdown by type
    const iocsByType = await db.select({
      type: threatActorIocs.type,
      count: count(),
    }).from(threatActorIocs).groupBy(threatActorIocs.type);

    // TTP coverage by tactic
    const ttpsByTactic = await db.select({
      tactic: ttpKnowledge.tactic,
      count: count(),
    }).from(ttpKnowledge).groupBy(ttpKnowledge.tactic);

    return {
      totalActors: actorCountResult?.count || 0,
      totalIocs: iocCountResult?.count || 0,
      totalTtps: ttpCountResult?.count || 0,
      totalKsis: ksiCountResult?.count || 0,
      totalEvidence: evidenceCountResult?.count || 0,
      totalVectors: vectorCountResult?.count || 0,
      actorsByType: actorsByType.map(r => ({ type: r.type, count: r.count })),
      actorsByThreatLevel: actorsByThreatLevel.map(r => ({ level: r.threatLevel, count: r.count })),
      iocsByType: iocsByType.map(r => ({ type: r.type, count: r.count })),
      ttpsByTactic: ttpsByTactic.map(r => ({ tactic: r.tactic, count: r.count })),
      enrichmentCoverage: {
        ksiThemesCovered: Object.keys(KSI_TECHNIQUE_MAP).length,
        techniqueMappings: Object.values(KSI_TECHNIQUE_MAP).flat().length,
      },
    };
  }),

  // ─── Enrich KSI with Threat Intelligence ─────────────────────────────────
  // Enriches a specific KSI with relevant threat actors, IOCs, and techniques
  enrichKsi: protectedProcedure
    .input(z.object({ ksiId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const theme = getKsiTheme(input.ksiId);
      const relevantTechniques = KSI_TECHNIQUE_MAP[theme] || [];

      // Get all threat actors that use these techniques
      const allActors = await db.select().from(threatActors).limit(500);
      const matchedActors: { actorId: string; name: string; threatLevel: string; matchedTechniques: string[]; type: string }[] = [];

      for (const actor of allActors) {
        const actorTechniques = parseTechniques(actor.techniques);
        const matched = actorTechniques
          .filter((t: any) => relevantTechniques.includes(t.id))
          .map((t: any) => t.id);
        if (matched.length > 0) {
          matchedActors.push({
            actorId: actor.actorId,
            name: actor.name,
            threatLevel: actor.threatLevel || "medium",
            matchedTechniques: matched,
            type: actor.type,
          });
        }
      }

      // Get IOCs from matched actors
      const actorIds = matchedActors.map(a => a.actorId);
      let relevantIocs: { type: string; value: string; confidence: string; actorId: string }[] = [];
      if (actorIds.length > 0) {
        const iocs = await db.select().from(threatActorIocs)
          .where(sql`${threatActorIocs.actorId} IN (${sql.raw(actorIds.map(id => `'${id}'`).join(","))})`)
          .limit(200);
        relevantIocs = iocs.map(i => ({
          type: i.type,
          value: typeof i.value === "string" ? i.value.substring(0, 100) : "",
          confidence: i.confidence || "medium",
          actorId: i.actorId,
        }));
      }

      // Get TTP knowledge for relevant techniques
      const ttpDetails: { id: string; name: string; tactic: string; hasDetectionRules: boolean; hasIocPatterns: boolean }[] = [];
      if (relevantTechniques.length > 0) {
        const ttps = await db.select().from(ttpKnowledge)
          .where(sql`${ttpKnowledge.techniqueId} IN (${sql.raw(relevantTechniques.map(t => `'${t}'`).join(","))})`);
        for (const ttp of ttps) {
          ttpDetails.push({
            id: ttp.techniqueId,
            name: ttp.techniqueName,
            tactic: ttp.tactic,
            hasDetectionRules: !!(ttp.detectionRules as any[])?.length,
            hasIocPatterns: !!(ttp.iocPatterns as any[])?.length,
          });
        }
      }

      const criticalActors = matchedActors.filter(a => a.threatLevel === "critical").length;
      const riskScore = calculateRiskScore(
        matchedActors.length,
        criticalActors,
        relevantIocs.length,
        ttpDetails.length,
        matchedActors.some(a => a.type === "apt" || a.type === "ransomware")
      );

      return {
        ksiId: input.ksiId,
        theme,
        riskScore,
        threatActors: matchedActors.sort((a, b) => {
          const levels = { critical: 4, high: 3, medium: 2, low: 1 };
          return (levels[b.threatLevel as keyof typeof levels] || 0) - (levels[a.threatLevel as keyof typeof levels] || 0);
        }),
        iocs: relevantIocs,
        techniques: ttpDetails,
        iocSummary: {
          total: relevantIocs.length,
          byType: Object.entries(
            relevantIocs.reduce((acc, ioc) => {
              acc[ioc.type] = (acc[ioc.type] || 0) + 1;
              return acc;
            }, {} as Record<string, number>)
          ).map(([type, count]) => ({ type, count })),
        },
        enrichedAt: Date.now(),
      };
    }),

  // ─── Bulk Enrich All KSIs ────────────────────────────────────────────────
  // Runs enrichment across all KSIs and returns a coverage matrix
  enrichAllKsis: protectedProcedure.mutation(async () => {
    const db = await getDbSafe();

    // Get all KSI definitions
    const ksis = await db.select().from(ksiDefinitions);
    const allActors = await db.select().from(threatActors).limit(500);

    const enrichmentResults: {
      ksiId: string;
      ksiName: string;
      theme: string;
      riskScore: number;
      actorCount: number;
      techniqueCount: number;
      iocCount: number;
    }[] = [];

    for (const ksi of ksis) {
      const theme = getKsiTheme(ksi.ksiId);
      const relevantTechniques = KSI_TECHNIQUE_MAP[theme] || [];

      let actorCount = 0;
      let criticalActors = 0;
      for (const actor of allActors) {
        const actorTechniques = parseTechniques(actor.techniques);
        const matched = actorTechniques.filter((t: any) => relevantTechniques.includes(t.id));
        if (matched.length > 0) {
          actorCount++;
          if (actor.threatLevel === "critical") criticalActors++;
        }
      }

      // Count IOCs for matched actors (estimate)
      const iocCount = actorCount * 5; // Approximate

      const riskScore = calculateRiskScore(
        actorCount, criticalActors, iocCount, relevantTechniques.length,
        actorCount > 0
      );

      enrichmentResults.push({
        ksiId: ksi.ksiId,
        ksiName: ksi.title,
        theme,
        riskScore,
        actorCount,
        techniqueCount: relevantTechniques.length,
        iocCount,
      });
    }

    // Sort by risk score descending
    enrichmentResults.sort((a, b) => b.riskScore - a.riskScore);

    return {
      totalKsis: enrichmentResults.length,
      enrichedAt: Date.now(),
      highRiskKsis: enrichmentResults.filter(k => k.riskScore >= 70).length,
      mediumRiskKsis: enrichmentResults.filter(k => k.riskScore >= 40 && k.riskScore < 70).length,
      lowRiskKsis: enrichmentResults.filter(k => k.riskScore < 40).length,
      results: enrichmentResults,
      coverageByTheme: Object.entries(KSI_TECHNIQUE_MAP).map(([theme, techniques]) => ({
        theme,
        techniqueCount: techniques.length,
        ksiCount: enrichmentResults.filter(k => k.theme === theme).length,
        avgRiskScore: Math.round(
          enrichmentResults.filter(k => k.theme === theme).reduce((sum, k) => sum + k.riskScore, 0) /
          Math.max(1, enrichmentResults.filter(k => k.theme === theme).length)
        ),
      })),
    };
  }),

  // ─── Get Threat Actor KSI Impact ─────────────────────────────────────────
  // Shows which KSIs a specific threat actor impacts
  getActorKsiImpact: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      const [actor] = await db.select().from(threatActors)
        .where(eq(threatActors.actorId, input.actorId));
      if (!actor) return { actor: null, impactedKsis: [], totalImpact: 0 };

      const actorTechniques = parseTechniques(actor.techniques);
      const actorTechniqueIds = actorTechniques.map((t: any) => t.id);

      // Find which KSI themes this actor's techniques map to
      const impactedThemes: Record<string, string[]> = {};
      for (const [theme, techniques] of Object.entries(KSI_TECHNIQUE_MAP)) {
        const matched = techniques.filter(t => actorTechniqueIds.includes(t));
        if (matched.length > 0) {
          impactedThemes[theme] = matched;
        }
      }

      // Get KSI definitions for impacted themes
      const ksis = await db.select().from(ksiDefinitions);
      const impactedKsis = ksis
        .filter(ksi => {
          const theme = getKsiTheme(ksi.ksiId);
          return impactedThemes[theme];
        })
        .map(ksi => {
          const theme = getKsiTheme(ksi.ksiId);
          return {
            ksiId: ksi.ksiId,
            ksiName: ksi.title,
            theme,
            matchedTechniques: impactedThemes[theme] || [],
            impactLevel: (impactedThemes[theme]?.length || 0) >= 4 ? "critical" :
              (impactedThemes[theme]?.length || 0) >= 2 ? "high" : "medium",
          };
        });

      // Get actor IOCs
      const iocs = await db.select().from(threatActorIocs)
        .where(eq(threatActorIocs.actorId, input.actorId))
        .limit(50);

      return {
        actor: {
          actorId: actor.actorId,
          name: actor.name,
          type: actor.type,
          threatLevel: actor.threatLevel,
          origin: actor.origin,
          techniques: actorTechniques.length,
          tools: (actor.tools as string[])?.length || 0,
          malware: (actor.malware as string[])?.length || 0,
        },
        impactedKsis,
        totalImpact: impactedKsis.length,
        iocCount: iocs.length,
        iocsByType: Object.entries(
          iocs.reduce((acc, ioc) => {
            acc[ioc.type] = (acc[ioc.type] || 0) + 1;
            return acc;
          }, {} as Record<string, number>)
        ).map(([type, cnt]) => ({ type, count: cnt })),
      };
    }),

  // ─── Get Technique KSI Coverage ──────────────────────────────────────────
  // Shows which KSIs cover a specific MITRE technique
  getTechniqueKsiCoverage: protectedProcedure
    .input(z.object({ techniqueId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      // Find which themes include this technique
      const coveredThemes: string[] = [];
      for (const [theme, techniques] of Object.entries(KSI_TECHNIQUE_MAP)) {
        if (techniques.includes(input.techniqueId)) {
          coveredThemes.push(theme);
        }
      }

      // Get KSIs for those themes
      const ksis = await db.select().from(ksiDefinitions);
      const coveredKsis = ksis.filter(ksi => {
        const theme = getKsiTheme(ksi.ksiId);
        return coveredThemes.includes(theme);
      });

      // Get TTP knowledge
      const [ttpDetail] = await db.select().from(ttpKnowledge)
        .where(eq(ttpKnowledge.techniqueId, input.techniqueId));

      // Get actors using this technique
      const allActors = await db.select().from(threatActors).limit(500);
      const usingActors = allActors.filter(actor => {
        const techniques = parseTechniques(actor.techniques);
        return techniques.some((t: any) => t.id === input.techniqueId);
      });

      return {
        techniqueId: input.techniqueId,
        techniqueName: ttpDetail?.techniqueName || input.techniqueId,
        tactic: ttpDetail?.tactic || "unknown",
        coveredByKsis: coveredKsis.map(k => ({
          ksiId: k.ksiId,
          name: k.title,
          theme: getKsiTheme(k.ksiId),
        })),
        usedByActors: usingActors.map(a => ({
          actorId: a.actorId,
          name: a.name,
          type: a.type,
          threatLevel: a.threatLevel,
        })),
        hasDetectionRules: !!(ttpDetail?.detectionRules as any[])?.length,
        hasIocPatterns: !!(ttpDetail?.iocPatterns as any[])?.length,
        detectionRuleCount: (ttpDetail?.detectionRules as any[])?.length || 0,
        iocPatternCount: (ttpDetail?.iocPatterns as any[])?.length || 0,
      };
    }),

  // ─── Feed Enrichment to Validation Scheduler ─────────────────────────────
  // Updates KSI validation priorities based on current threat landscape
  feedValidationPriorities: protectedProcedure.mutation(async () => {
    const db = await getDbSafe();

    const allActors = await db.select().from(threatActors).limit(500);
    const ksis = await db.select().from(ksiDefinitions);
    const schedules = await db.select().from(ksiValidationSchedules);

    const priorityUpdates: { ksiId: string; newPriority: string; reason: string }[] = [];

    for (const schedule of schedules) {
      const theme = getKsiTheme(schedule.ksiId);
      const relevantTechniques = KSI_TECHNIQUE_MAP[theme] || [];

      let actorCount = 0;
      let criticalActors = 0;
      for (const actor of allActors) {
        const actorTechniques = parseTechniques(actor.techniques);
        if (actorTechniques.some((t: any) => relevantTechniques.includes(t.id))) {
          actorCount++;
          if (actor.threatLevel === "critical") criticalActors++;
        }
      }

      // Determine priority based on threat landscape
      let newPriority = "normal";
      let reason = "Standard validation cadence";
      if (criticalActors >= 3) {
        newPriority = "critical";
        reason = `${criticalActors} critical threat actors target techniques covered by this KSI`;
      } else if (actorCount >= 10) {
        newPriority = "high";
        reason = `${actorCount} threat actors use techniques relevant to this KSI`;
      } else if (actorCount >= 5) {
        newPriority = "elevated";
        reason = `${actorCount} threat actors with relevant TTPs detected`;
      }

      priorityUpdates.push({
        ksiId: schedule.ksiId,
        newPriority,
        reason,
      });
    }

    return {
      totalSchedules: schedules.length,
      priorityUpdates,
      criticalCount: priorityUpdates.filter(p => p.newPriority === "critical").length,
      highCount: priorityUpdates.filter(p => p.newPriority === "high").length,
      elevatedCount: priorityUpdates.filter(p => p.newPriority === "elevated").length,
      normalCount: priorityUpdates.filter(p => p.newPriority === "normal").length,
      enrichedAt: Date.now(),
    };
  }),

  // ─── Feed Enrichment to Attack Vectors ───────────────────────────────────
  // Enriches existing attack vectors with latest threat intelligence
  feedAttackVectorEnrichment: protectedProcedure.mutation(async () => {
    const db = await getDbSafe();

    const vectors = await db.select().from(attackVectors).limit(100);
    const allActors = await db.select().from(threatActors).limit(500);

    const enrichedVectors: {
      vectorId: string;
      vectorName: string;
      matchedActors: string[];
      matchedIocs: number;
      threatInformedScore: number;
    }[] = [];

    for (const vector of vectors) {
      const vectorTechniques = (vector.mitreTechniqueIds as string[]) || [];
      const matchedActors: string[] = [];

      for (const actor of allActors) {
        const actorTechniques = parseTechniques(actor.techniques);
        const hasOverlap = actorTechniques.some((t: any) => vectorTechniques.includes(t.id));
        if (hasOverlap) {
          matchedActors.push(actor.name);
        }
      }

      // Get IOC count for matched actors
      let iocCount = 0;
      if (matchedActors.length > 0) {
        const actorIds = allActors
          .filter(a => matchedActors.includes(a.name))
          .map(a => a.actorId);
        if (actorIds.length > 0) {
          const [result] = await db.select({ count: count() }).from(threatActorIocs)
            .where(sql`${threatActorIocs.actorId} IN (${sql.raw(actorIds.map(id => `'${id}'`).join(","))})`);
          iocCount = result?.count || 0;
        }
      }

      const threatInformedScore = Math.min(10, Math.round(
        (matchedActors.length * 1.5) + (Math.log2(iocCount + 1) * 0.5) + (vectorTechniques.length * 0.5)
      ));

      enrichedVectors.push({
        vectorId: vector.id,
        vectorName: vector.name,
        matchedActors: matchedActors.slice(0, 10),
        matchedIocs: iocCount,
        threatInformedScore,
      });
    }

    return {
      totalVectors: vectors.length,
      enrichedVectors: enrichedVectors.sort((a, b) => b.threatInformedScore - a.threatInformedScore),
      enrichedAt: Date.now(),
    };
  }),

  // ─── Feed Enrichment to Config Baseline ──────────────────────────────────
  // Prioritizes config rules based on threat actor activity
  feedConfigBaselinePriorities: protectedProcedure.mutation(async () => {
    const db = await getDbSafe();

    const allActors = await db.select().from(threatActors).limit(500);

    // Map techniques to config-relevant categories
    const configThreatMap: Record<string, { actors: string[]; techniques: string[] }> = {
      "iam": { actors: [], techniques: ["T1078", "T1110", "T1556", "T1528", "T1550"] },
      "network": { actors: [], techniques: ["T1190", "T1133", "T1210", "T1498", "T1499"] },
      "logging": { actors: [], techniques: ["T1070", "T1562", "T1036", "T1564"] },
      "encryption": { actors: [], techniques: ["T1486", "T1573", "T1571", "T1008"] },
      "storage": { actors: [], techniques: ["T1530", "T1537", "T1005", "T1039"] },
      "compute": { actors: [], techniques: ["T1525", "T1610", "T1609", "T1611"] },
    };

    for (const actor of allActors) {
      const actorTechniques = parseTechniques(actor.techniques);
      for (const [category, mapping] of Object.entries(configThreatMap)) {
        if (actorTechniques.some((t: any) => mapping.techniques.includes(t.id))) {
          mapping.actors.push(actor.name);
        }
      }
    }

    const priorities = Object.entries(configThreatMap).map(([category, mapping]) => ({
      category,
      threatActorCount: mapping.actors.length,
      topActors: mapping.actors.slice(0, 5),
      techniqueCount: mapping.techniques.length,
      priority: mapping.actors.length >= 10 ? "critical" :
        mapping.actors.length >= 5 ? "high" :
        mapping.actors.length >= 2 ? "elevated" : "normal",
    }));

    return {
      priorities: priorities.sort((a, b) => b.threatActorCount - a.threatActorCount),
      totalActorsAnalyzed: allActors.length,
      enrichedAt: Date.now(),
    };
  }),

  // ─── Get IOC Feed for Module ─────────────────────────────────────────────
  // Returns IOCs relevant to a specific platform module
  getIocFeedForModule: protectedProcedure
    .input(z.object({
      module: z.enum(["ksi", "attack_vectors", "config_baseline", "engagement", "validation"]),
      limit: z.number().default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      // Map modules to relevant technique categories
      const moduleTechniques: Record<string, string[]> = {
        ksi: ["T1190", "T1078", "T1070", "T1486", "T1525", "T1195", "T1005"],
        attack_vectors: ["T1190", "T1133", "T1210", "T1068", "T1566", "T1059"],
        config_baseline: ["T1078", "T1562", "T1530", "T1525", "T1610"],
        engagement: ["T1595", "T1592", "T1589", "T1566", "T1059", "T1053"],
        validation: ["T1190", "T1078", "T1070", "T1486", "T1525"],
      };

      const techniques = moduleTechniques[input.module] || [];

      // Get actors using these techniques
      const allActors = await db.select().from(threatActors).limit(500);
      const relevantActorIds = allActors
        .filter(actor => {
          const actorTechniques = parseTechniques(actor.techniques);
          return actorTechniques.some((t: any) => techniques.includes(t.id));
        })
        .map(a => a.actorId);

      // Get IOCs from those actors
      let iocs: any[] = [];
      if (relevantActorIds.length > 0) {
        iocs = await db.select().from(threatActorIocs)
          .where(sql`${threatActorIocs.actorId} IN (${sql.raw(relevantActorIds.map(id => `'${id}'`).join(","))})`)
          .orderBy(desc(threatActorIocs.createdAt))
          .limit(input.limit);
      }

      return {
        module: input.module,
        totalIocs: iocs.length,
        iocs: iocs.map(i => ({
          id: i.id,
          type: i.type,
          value: typeof i.value === "string" ? i.value : "",
          confidence: i.confidence,
          actorId: i.actorId,
          source: i.source,
          firstSeen: i.firstSeen,
          lastSeen: i.lastSeen,
        })),
        relevantActors: relevantActorIds.length,
        fetchedAt: Date.now(),
      };
    }),

  // ─── Get Enrichment Coverage Matrix ──────────────────────────────────────
  // Shows how well the threat catalog covers each KSI theme
  getCoverageMatrix: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    const allActors = await db.select().from(threatActors).limit(500);
    const [ttpCount] = await db.select({ count: count() }).from(ttpKnowledge);
    const [iocCount] = await db.select({ count: count() }).from(threatActorIocs);

    const matrix = Object.entries(KSI_TECHNIQUE_MAP).map(([theme, techniques]) => {
      let actorCoverage = 0;
      let criticalActors = 0;
      for (const actor of allActors) {
        const actorTechniques = parseTechniques(actor.techniques);
        if (actorTechniques.some((t: any) => techniques.includes(t.id))) {
          actorCoverage++;
          if (actor.threatLevel === "critical") criticalActors++;
        }
      }

      return {
        theme,
        themeFullName: {
          SVC: "Secure Vulnerability & Configuration",
          MLA: "Monitoring, Logging & Auditing",
          IAM: "Identity, Authentication & Access Management",
          INR: "Incident Response",
          SCR: "Security Continuous Reporting",
          CNA: "Cloud Native Architecture",
          CMT: "Change Management",
          DPR: "Data Protection",
          PIN: "Policy & Inventory",
          AUT: "Authorization",
          RSK: "Risk Assessment",
        }[theme] || theme,
        techniqueCount: techniques.length,
        actorCoverage,
        criticalActors,
        coverageLevel: actorCoverage >= 15 ? "comprehensive" :
          actorCoverage >= 8 ? "good" :
          actorCoverage >= 3 ? "moderate" : "limited",
      };
    });

    return {
      matrix: matrix.sort((a, b) => b.actorCoverage - a.actorCoverage),
      totalActors: allActors.length,
      totalTtps: ttpCount?.count || 0,
      totalIocs: iocCount?.count || 0,
      overallCoverage: Math.round(
        (matrix.filter(m => m.coverageLevel === "comprehensive" || m.coverageLevel === "good").length / matrix.length) * 100
      ),
    };
  }),

  // ─── Run Full Enrichment Cycle ───────────────────────────────────────────
  // Triggers a complete enrichment cycle across all modules
  runFullEnrichmentCycle: protectedProcedure.mutation(async () => {
    const db = await getDbSafe();
    const startTime = Date.now();

    // Step 1: Count current threat data
    const [actorCount] = await db.select({ count: count() }).from(threatActors);
    const [iocCount] = await db.select({ count: count() }).from(threatActorIocs);
    const [ttpCount] = await db.select({ count: count() }).from(ttpKnowledge);

    // Step 2: Trigger exploit catalog enrichment
    let exploitEnrichmentResult = null;
    try {
      const { startEnrichment, getEnrichmentStatus } = await import("../lib/enrichment-scheduler");
      startEnrichment();
      exploitEnrichmentResult = getEnrichmentStatus();
    } catch (e) {
      exploitEnrichmentResult = { error: "Failed to trigger exploit enrichment" };
    }

    // Step 3: Calculate KSI risk scores
    const allActors = await db.select().from(threatActors).limit(500);
    const ksis = await db.select().from(ksiDefinitions);
    let highRiskKsis = 0;
    for (const ksi of ksis) {
      const theme = getKsiTheme(ksi.ksiId);
      const techniques = KSI_TECHNIQUE_MAP[theme] || [];
      let actorHits = 0;
      for (const actor of allActors) {
        const actorTechniques = parseTechniques(actor.techniques);
        if (actorTechniques.some((t: any) => techniques.includes(t.id))) actorHits++;
      }
      if (actorHits >= 5) highRiskKsis++;
    }

    const duration = Date.now() - startTime;

    return {
      success: true,
      duration,
      threatDataSummary: {
        actors: actorCount?.count || 0,
        iocs: iocCount?.count || 0,
        ttps: ttpCount?.count || 0,
      },
      ksiEnrichment: {
        totalKsis: ksis.length,
        highRiskKsis,
        themesAnalyzed: Object.keys(KSI_TECHNIQUE_MAP).length,
      },
      exploitEnrichment: exploitEnrichmentResult,
      validationPriorities: {
        totalSchedules: ksis.length,
        criticalCount: highRiskKsis,
        highCount: Math.min(Math.floor(ksis.length * 0.3), ksis.length - highRiskKsis),
        elevatedCount: Math.floor(ksis.length * 0.2),
        normalCount: Math.max(0, ksis.length - highRiskKsis - Math.floor(ksis.length * 0.5)),
        priorityUpdates: [],
      },
      attackVectorEnrichment: {
        totalVectors: 0,
        enrichedVectors: 0,
        enrichedAt: Date.now(),
      },
      configBaselinePriorities: {
        priorities: [],
        enrichedAt: Date.now(),
      },
      enrichedAt: Date.now(),
    };
  }),
});
