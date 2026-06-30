import * as db from "../db";
/**
 * Threat Intel Training Pipeline Router
 *
 * Exposes the full ingestion → extraction → learning pipeline:
 * - Ingest from all 12+ threat intel sources
 * - Extract attack sequences from reports via LLM
 * - Generate Caldera emulation templates
 * - Enrich exploit intelligence
 * - Cross-reference threat actors
 * - Update TTP knowledge base
 * - Query templates, reports, and exploits
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  incidentReports,
  attackSequenceTemplates,
  exploitIntelligence,
} from "../../drizzle/schema";
import { eq, desc, like, sql, and, or } from "drizzle-orm";
import { getDb } from "../db";
import {
  runFullIngest,
  ingestDfirReport,
  ingestCisaAdvisories,
  ingestUnit42,
  ingestHackerNews,
  ingestDarkReading,
  ingestCyberScoop,
  ingestCybersecurityDive,
  ingestMispCircl,
  ingestDigitalSideMisp,
  ingestMetasploitCves,
  ingestCisaKevExploits,
  getIngestStats,
  THREAT_INTEL_SOURCES,
} from "../lib/threat-intel-ingest";
import {
  processReport,
  processBatch,
  extractAttackSequence,
  generateAttackTemplate,
  getLearnerStats,
} from "../lib/attack-sequence-learner";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

export const threatIntelTrainingRouter = router({
  // ─── Ingestion ──────────────────────────────────────────────────────

  /** Run full ingestion from all sources */
  ingestAll: protectedProcedure.mutation(async () => {
    return runFullIngest();
  }),

  /** Ingest from a specific source */
  ingestSource: protectedProcedure
    .input(z.object({ source: z.string() }))
    .mutation(async ({ input }) => {
      const sourceMap: Record<string, () => Promise<any>> = {
        dfir_report: ingestDfirReport,
        cisa_advisory: ingestCisaAdvisories,
        unit42: ingestUnit42,
        hacker_news: ingestHackerNews,
        dark_reading: ingestDarkReading,
        cyberscoop: ingestCyberScoop,
        cybersecurity_dive: ingestCybersecurityDive,
        misp_circl: ingestMispCircl,
        digitalside_misp: ingestDigitalSideMisp,
        metasploit_cve: ingestMetasploitCves,
        cisa_kev_exploits: ingestCisaKevExploits,
      };
      const fn = sourceMap[input.source];
      if (!fn) throw new Error(`Unknown source: ${input.source}`);
      return fn();
    }),

  /** Get ingestion statistics */
  ingestStats: protectedProcedure.query(async () => {
    return getIngestStats();
  }),

  /** List available sources */
  listSources: protectedProcedure.query(() => {
    return THREAT_INTEL_SOURCES.map(s => ({
      name: s.name,
      category: s.category,
      priority: s.priority,
    }));
  }),

  // ─── Reports ────────────────────────────────────────────────────────

  /** List incident reports with filtering */
  listReports: protectedProcedure
    .input(z.object({
      source: z.string().optional(),
      status: z.string().optional(),
      incidentType: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(100).default(25),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const conditions = [];
      if (input.source) conditions.push(eq(incidentReports.source, input.source));
      if (input.status) conditions.push(eq(incidentReports.irStatus, input.status as any));
      if (input.incidentType) conditions.push(eq(incidentReports.incidentType, input.incidentType));
      if (input.search) conditions.push(like(incidentReports.title, `%${input.search}%`));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
        .from(incidentReports)
        .where(where);

      const reports = await db.select({
        id: incidentReports.id,
        sourceId: incidentReports.sourceId,
        source: incidentReports.source,
        title: incidentReports.title,
        url: incidentReports.url,
        publishedAt: incidentReports.publishedAt,
        incidentType: incidentReports.incidentType,
        severity: incidentReports.irSeverity,
        status: incidentReports.irStatus,
        createdAt: incidentReports.irCreatedAt,
      })
        .from(incidentReports)
        .where(where)
        .orderBy(desc(incidentReports.irCreatedAt))
        .limit(input.limit)
        .offset(input.offset);

      return { reports, total: countResult?.count || 0 };
    }),

  /** Get a single report with full detail */
  getReport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, input.id)).limit(1);
      return report || null;
    }),

  // ─── Processing ─────────────────────────────────────────────────────

  /** Process a single report through the full pipeline */
  processReport: protectedProcedure
    .input(z.object({ reportId: z.number() }))
    .mutation(async ({ input }) => {
      return processReport(input.reportId);
    }),

  /** Process a batch of unprocessed reports */
  processBatch: protectedProcedure
    .input(z.object({ limit: z.number().min(1).max(20).default(5) }))
    .mutation(async ({ input }) => {
      return processBatch(input.limit);
    }),

  /** Extract attack sequence from a specific report */
  extractSequence: protectedProcedure
    .input(z.object({ reportId: z.number() }))
    .mutation(async ({ input }) => {
      return extractAttackSequence(input.reportId);
    }),

  /** Generate attack template from an extracted report */
  generateTemplate: protectedProcedure
    .input(z.object({ reportId: z.number() }))
    .mutation(async ({ input }) => {
      return generateAttackTemplate(input.reportId);
    }),

  // ─── Templates ──────────────────────────────────────────────────────

  /** List attack sequence templates */
  listTemplates: protectedProcedure
    .input(z.object({
      attackType: z.string().optional(),
      complexity: z.string().optional(),
      status: z.string().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(100).default(25),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const conditions = [];
      if (input.attackType) conditions.push(eq(attackSequenceTemplates.attackType, input.attackType));
      if (input.complexity) conditions.push(eq(attackSequenceTemplates.astComplexity, input.complexity as any));
      if (input.status) conditions.push(eq(attackSequenceTemplates.astStatus, input.status as any));
      if (input.search) conditions.push(like(attackSequenceTemplates.name, `%${input.search}%`));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
        .from(attackSequenceTemplates)
        .where(where);

      const templates = await db.select()
        .from(attackSequenceTemplates)
        .where(where)
        .orderBy(desc(attackSequenceTemplates.astCreatedAt))
        .limit(input.limit)
        .offset(input.offset);

      return { templates, total: countResult?.count || 0 };
    }),

  /** Get a single template */
  getTemplate: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const [template] = await db.select().from(attackSequenceTemplates).where(eq(attackSequenceTemplates.id, input.id)).limit(1);
      return template || null;
    }),

  /** Update template status */
  updateTemplateStatus: protectedProcedure
    .input(z.object({
      id: z.number(),
      status: z.enum(["draft", "validated", "production"]),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.update(attackSequenceTemplates)
        .set({ status: input.status })
        .where(eq(attackSequenceTemplates.id, input.id));
      return { success: true };
    }),

  // ─── Exploit Intelligence ───────────────────────────────────────────

  /** List exploit intelligence */
  listExploits: protectedProcedure
    .input(z.object({
      source: z.string().optional(),
      weaponized: z.boolean().optional(),
      cisaKev: z.boolean().optional(),
      search: z.string().optional(),
      limit: z.number().min(1).max(100).default(25),
      offset: z.number().min(0).default(0),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const conditions = [];
      if (input.source) conditions.push(eq(exploitIntelligence.eiSource, input.source));
      if (input.weaponized !== undefined) conditions.push(eq(exploitIntelligence.weaponized, input.weaponized));
      if (input.cisaKev !== undefined) conditions.push(eq(exploitIntelligence.cisaKev, input.cisaKev));
      if (input.search) conditions.push(like(exploitIntelligence.cveId, `%${input.search}%`));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
        .from(exploitIntelligence)
        .where(where);

      const exploits = await db.select()
        .from(exploitIntelligence)
        .where(where)
        .orderBy(desc(exploitIntelligence.eiCreatedAt))
        .limit(input.limit)
        .offset(input.offset);

      return { exploits, total: countResult?.count || 0 };
    }),

  /** Get exploit details for a CVE */
  getExploitByCve: protectedProcedure
    .input(z.object({ cveId: z.string() }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const exploits = await db.select()
        .from(exploitIntelligence)
        .where(eq(exploitIntelligence.cveId, input.cveId.toUpperCase()));
      return exploits;
    }),

  // ─── Similar Incidents ──────────────────────────────────────────────

  /** Find similar real-world incidents based on campaign techniques */
  findSimilarIncidents: protectedProcedure
    .input(z.object({
      techniques: z.array(z.string()).min(1), // MITRE technique IDs like ["T1566.001", "T1059.001"]
      limit: z.number().min(1).max(20).default(5),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      // Find incident reports that mention any of the given techniques
      // We search in ttpsExtracted JSON and attackSequence JSON
      const techConditions = input.techniques.map(t =>
        or(
          like(sql`CAST(${incidentReports.ttpsExtracted} AS CHAR)`, `%${t}%`),
          like(sql`CAST(${incidentReports.attackSequence} AS CHAR)`, `%${t}%`)
        )
      );

      const reports = await db.select({
        id: incidentReports.id,
        title: incidentReports.title,
        source: incidentReports.source,
        url: incidentReports.url,
        incidentType: incidentReports.incidentType,
        severity: incidentReports.irSeverity,
        publishedAt: incidentReports.publishedAt,
        ttpsExtracted: incidentReports.ttpsExtracted,
        attackSequence: incidentReports.attackSequence,
        actorsIdentified: incidentReports.actorsIdentified,
        targetSectors: incidentReports.targetSectors,
        attackNarrative: incidentReports.attackNarrative,
      })
        .from(incidentReports)
        .where(or(...techConditions))
        .orderBy(desc(incidentReports.irCreatedAt))
        .limit(input.limit * 3); // Fetch more to rank

      // Rank by number of matching techniques
      const ranked = reports.map(report => {
        const ttps: any[] = Array.isArray(report.ttpsExtracted) ? report.ttpsExtracted : [];
        const seq: any[] = Array.isArray(report.attackSequence as any) ? (report.attackSequence as any) : [];
        const allTechIds = new Set<string>();
        ttps.forEach((t: any) => { if (t.techniqueId) allTechIds.add(t.techniqueId); });
        seq.forEach((s: any) => { if (s.techniqueId) allTechIds.add(s.techniqueId); });
        const matchCount = input.techniques.filter(t => allTechIds.has(t)).length;
        const relevance = input.techniques.length > 0 ? Math.round((matchCount / input.techniques.length) * 100) : 0;
        return {
          ...report,
          matchingTechniques: matchCount,
          relevanceScore: relevance,
        };
      });

      ranked.sort((a, b) => b.matchingTechniques - a.matchingTechniques);
      return ranked.slice(0, input.limit);
    }),

  /** Find attack templates matching campaign techniques */
  findSimilarTemplates: protectedProcedure
    .input(z.object({
      techniques: z.array(z.string()).min(1),
      limit: z.number().min(1).max(10).default(5),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const techConditions = input.techniques.map(t =>
        or(
          like(sql`CAST(${attackSequenceTemplates.phases} AS CHAR)`, `%${t}%`),
          like(sql`CAST(${attackSequenceTemplates.astCalderaAbilities} AS CHAR)`, `%${t}%`)
        )
      );

      const templates = await db.select()
        .from(attackSequenceTemplates)
        .where(or(...techConditions))
        .orderBy(desc(attackSequenceTemplates.astCreatedAt))
        .limit(input.limit);

      return templates;
    }),

  // ─── Statistics ─────────────────────────────────────────────────────

  /** Get learner pipeline statistics */
  learnerStats: protectedProcedure.query(async () => {
    return getLearnerStats();
  }),

  /** Get combined dashboard stats */
  dashboardStats: protectedProcedure.query(async () => {
    const ingest = await getIngestStats();
    const learner = await getLearnerStats();
    return {
      ingestion: ingest,
      learning: learner,
    };
  }),

  /** Apply attack template abilities to an internal campaign */
  applyTemplateToCampaign: protectedProcedure
    .input(z.object({
      templateId: z.number(),
      campaignId: z.number(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const [template] = await db.select().from(attackSequenceTemplates).where(eq(attackSequenceTemplates.id, input.templateId)).limit(1);
      if (!template) throw new Error("Template not found");

      // Extract abilities from phases
      const phases: any[] = (() => {
        try {
          return typeof template.phases === "string" ? JSON.parse(template.phases as string) : (template.phases as any[]) || [];
        } catch { return []; }
      })();

      const abilities: Array<{
        campaignId: number;
        abilityId: string;
        abilityName: string;
        technique?: string;
        tactic?: string;
        description?: string;
        executionOrder: number;
      }> = [];

      let order = 0;
      for (const phase of phases) {
        const techniques = Array.isArray(phase.techniques) ? phase.techniques : [];
        for (const tech of techniques) {
          abilities.push({
            campaignId: input.campaignId,
            abilityId: tech.id || `phase-${phase.order || order}-${tech.name || 'unknown'}`,
            abilityName: tech.name || `${phase.tactic || 'unknown'} technique`,
            technique: tech.id || undefined,
            tactic: phase.tactic || undefined,
            description: tech.description || undefined,
            executionOrder: order,
          });
          order++;
        }
      }

      if (abilities.length === 0) {
        return { success: false, message: "No techniques found in template phases", abilitiesAdded: 0 };
      }

      // Import addCampaignAbilities from db
      const { addCampaignAbilities } = await import("../db");
      await addCampaignAbilities(abilities);

      return {
        success: true,
        abilitiesAdded: abilities.length,
        templateName: template.name,
        tactics: Array.from(new Set(abilities.map(a => a.tactic).filter(Boolean))),
      };
    }),
});
