/**
 * DFIR Report Library Router
 * 
 * Provides procedures for:
 * - Listing/searching DFIR reports
 * - Uploading/importing reports from various sources
 * - Scraping The DFIR Report website
 * - Fetching OTX pulses
 * - LLM-powered enrichment of parsed reports
 * - Exporting training data from reports
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { dfirReports, dfirReportIocs } from "../../drizzle/schema";
import { eq, desc, like, sql, and, inArray, count } from "drizzle-orm";
import {
  parseDfirReportHtml,
  parseCisaStix,
  parseOtxPulse,
  parseManualReport,
  autoDetectAndParse,
  type ParsedDfirReport,
  type ParsedIoc,
} from "../lib/dfir-report-parser";
import { invokeLLM } from "../_core/llm";

export const dfirLibraryRouter = router({
  // ─── List Reports ───────────────────────────────────────────────────────
  list: protectedProcedure
    .input(z.object({
      page: z.number().min(1).default(1),
      pageSize: z.number().min(1).max(100).default(20),
      source: z.enum(['dfir_report', 'cisa', 'otx', 'mandiant', 'unit42', 'recorded_future', 'manual']).optional(),
      status: z.enum(['pending', 'parsed', 'enriched', 'training_ready']).optional(),
      search: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const { page = 1, pageSize = 20, source, status, search } = input || {};
      const conditions: any[] = [];
      if (source) conditions.push(eq(dfirReports.source, source));
      if (status) conditions.push(eq(dfirReports.status, status));
      if (search) conditions.push(like(dfirReports.title, `%${search}%`));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [reports, [{ total }]] = await Promise.all([
        (await getDb()).select({
          id: dfirReports.id,
          externalId: dfirReports.externalId,
          source: dfirReports.source,
          title: dfirReports.title,
          url: dfirReports.url,
          publishedAt: dfirReports.publishedAt,
          summary: dfirReports.summary,
          threatActors: dfirReports.threatActors,
          malwareFamilies: dfirReports.malwareFamilies,
          mitreAttackTechniques: dfirReports.mitreAttackTechniques,
          killChainPhases: dfirReports.killChainPhases,
          tags: dfirReports.tags,
          status: dfirReports.status,
          createdAt: dfirReports.createdAt,
        })
          .from(dfirReports)
          .where(where)
          .orderBy(desc(dfirReports.createdAt))
          .limit(pageSize)
          .offset((page - 1) * pageSize),
        (await getDb()).select({ total: count() }).from(dfirReports).where(where),
      ]);

      return { reports, total, page, pageSize };
    }),

  // ─── Get Single Report ──────────────────────────────────────────────────
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const [report] = await (await getDb()).select().from(dfirReports).where(eq(dfirReports.id, input.id)).limit(1);
      if (!report) throw new Error("Report not found");

      const iocs = await (await getDb()).select().from(dfirReportIocs).where(eq(dfirReportIocs.reportId, input.id));

      return { ...report, iocs };
    }),

  // ─── Upload / Import Report ─────────────────────────────────────────────
  importReport: protectedProcedure
    .input(z.object({
      content: z.string(),
      fileName: z.string().optional(),
      url: z.string().optional(),
      source: z.enum(['dfir_report', 'cisa', 'otx', 'mandiant', 'unit42', 'recorded_future', 'manual']).optional(),
    }))
    .mutation(async ({ input }) => {
      let parsed: ParsedDfirReport;

      if (input.source === 'cisa') {
        parsed = parseCisaStix(JSON.parse(input.content));
      } else if (input.source === 'otx') {
        parsed = parseOtxPulse(JSON.parse(input.content));
      } else if (input.source === 'dfir_report') {
        parsed = parseDfirReportHtml(input.content, input.url || '');
      } else {
        parsed = autoDetectAndParse(input.content, input.fileName, input.url);
      }

      // Upsert report
      const [existing] = await (await getDb()).select({ id: dfirReports.id })
        .from(dfirReports)
        .where(eq(dfirReports.externalId, parsed.externalId))
        .limit(1);

      let reportId: number;
      if (existing) {
        await (await getDb()).update(dfirReports)
          .set({
            title: parsed.title,
            summary: parsed.summary,
            threatActors: parsed.threatActors,
            malwareFamilies: parsed.malwareFamilies,
            mitreAttackTechniques: parsed.mitreAttackTechniques,
            diamondModel: parsed.diamondModel,
            timeline: parsed.timeline,
            killChainPhases: parsed.killChainPhases,
            tags: parsed.tags,
            rawContent: parsed.rawContent,
            status: 'parsed',
            updatedAt: new Date().toISOString(),
          })
          .where(eq(dfirReports.id, existing.id));
        reportId = existing.id;
        // Clear old IOCs
        await (await getDb()).delete(dfirReportIocs).where(eq(dfirReportIocs.reportId, reportId));
      } else {
        const [result] = await (await getDb()).insert(dfirReports).values({
          externalId: parsed.externalId,
          source: parsed.source,
          title: parsed.title,
          url: parsed.url,
          publishedAt: parsed.publishedAt,
          summary: parsed.summary,
          threatActors: parsed.threatActors,
          malwareFamilies: parsed.malwareFamilies,
          mitreAttackTechniques: parsed.mitreAttackTechniques,
          diamondModel: parsed.diamondModel,
          timeline: parsed.timeline,
          killChainPhases: parsed.killChainPhases,
          tags: parsed.tags,
          rawContent: parsed.rawContent,
          status: 'parsed',
        });
        reportId = result.insertId;
      }

      // Insert IOCs
      if (parsed.iocs.length > 0) {
        const iocBatch = parsed.iocs.slice(0, 500).map(ioc => ({
          reportId,
          iocType: ioc.type,
          value: ioc.value,
          context: ioc.context,
        }));
        // Insert in chunks of 50
        for (let i = 0; i < iocBatch.length; i += 50) {
          await (await getDb()).insert(dfirReportIocs).values(iocBatch.slice(i, i + 50));
        }
      }

      return {
        reportId,
        title: parsed.title,
        source: parsed.source,
        techniquesFound: parsed.mitreAttackTechniques.length,
        iocsFound: parsed.iocs.length,
        threatActors: parsed.threatActors,
        malwareFamilies: parsed.malwareFamilies,
        killChainPhases: parsed.killChainPhases,
        updated: !!existing,
      };
    }),

  // ─── Scrape DFIR Report URLs ────────────────────────────────────────────
  scrapeUrl: protectedProcedure
    .input(z.object({ url: z.string().url() }))
    .mutation(async ({ input }) => {
      const response = await fetch(input.url, {
        headers: { 'User-Agent': 'Caldera-DFIR-Ingest/1.0' },
      });
      if (!response.ok) throw new Error(`Failed to fetch: ${response.status}`);
      const html = await response.text();

      const parsed = parseDfirReportHtml(html, input.url);

      // Determine source from URL
      if (input.url.includes('thedfirreport.com')) parsed.source = 'dfir_report';
      else if (input.url.includes('cisa.gov')) parsed.source = 'cisa';

      // Insert
      const [existing] = await (await getDb()).select({ id: dfirReports.id })
        .from(dfirReports)
        .where(eq(dfirReports.externalId, parsed.externalId))
        .limit(1);

      let reportId: number;
      if (existing) {
        await (await getDb()).update(dfirReports)
          .set({
            title: parsed.title,
            summary: parsed.summary,
            threatActors: parsed.threatActors,
            malwareFamilies: parsed.malwareFamilies,
            mitreAttackTechniques: parsed.mitreAttackTechniques,
            diamondModel: parsed.diamondModel,
            timeline: parsed.timeline,
            killChainPhases: parsed.killChainPhases,
            tags: parsed.tags,
            rawContent: parsed.rawContent,
            status: 'parsed',
            updatedAt: new Date().toISOString(),
          })
          .where(eq(dfirReports.id, existing.id));
        reportId = existing.id;
        await (await getDb()).delete(dfirReportIocs).where(eq(dfirReportIocs.reportId, reportId));
      } else {
        const [result] = await (await getDb()).insert(dfirReports).values({
          externalId: parsed.externalId,
          source: parsed.source,
          title: parsed.title,
          url: parsed.url,
          publishedAt: parsed.publishedAt,
          summary: parsed.summary,
          threatActors: parsed.threatActors,
          malwareFamilies: parsed.malwareFamilies,
          mitreAttackTechniques: parsed.mitreAttackTechniques,
          diamondModel: parsed.diamondModel,
          timeline: parsed.timeline,
          killChainPhases: parsed.killChainPhases,
          tags: parsed.tags,
          rawContent: parsed.rawContent,
          status: 'parsed',
        });
        reportId = result.insertId;
      }

      // Insert IOCs
      if (parsed.iocs.length > 0) {
        const iocBatch = parsed.iocs.slice(0, 500).map(ioc => ({
          reportId,
          iocType: ioc.type,
          value: ioc.value,
          context: ioc.context,
        }));
        for (let i = 0; i < iocBatch.length; i += 50) {
          await (await getDb()).insert(dfirReportIocs).values(iocBatch.slice(i, i + 50));
        }
      }

      return {
        reportId,
        title: parsed.title,
        techniquesFound: parsed.mitreAttackTechniques.length,
        iocsFound: parsed.iocs.length,
        threatActors: parsed.threatActors,
        malwareFamilies: parsed.malwareFamilies,
      };
    }),

  // ─── Batch Scrape DFIR Report Index ─────────────────────────────────────
  scrapeIndex: protectedProcedure
    .input(z.object({
      maxReports: z.number().min(1).max(50).default(10),
    }).optional())
    .mutation(async ({ input }) => {
      const maxReports = input?.maxReports || 10;

      // Fetch the DFIR Report blog index
      const response = await fetch('https://thedfirreport.com/blog/', {
        headers: { 'User-Agent': 'Caldera-DFIR-Ingest/1.0' },
      });
      if (!response.ok) throw new Error(`Failed to fetch index: ${response.status}`);
      const html = await response.text();

      // Extract report URLs
      const urlPattern = /href="(https:\/\/thedfirreport\.com\/\d{4}\/\d{2}\/\d{2}\/[^"]+)"/g;
      const urls: string[] = [];
      const seen = new Set<string>();
      for (const m of html.matchAll(urlPattern)) {
        const url = m[1].replace(/\/$/, '');
        if (!seen.has(url)) {
          seen.add(url);
          urls.push(url);
        }
        if (urls.length >= maxReports) break;
      }

      // Check which ones we already have
      const existingIds = new Set<string>();
      if (urls.length > 0) {
        const externalIds = urls.map(u => u.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-').slice(0, 120));
        const existing = await (await getDb()).select({ externalId: dfirReports.externalId })
          .from(dfirReports)
          .where(inArray(dfirReports.externalId, externalIds));
        for (const e of existing) existingIds.add(e.externalId);
      }

      // Scrape new reports
      const results: { url: string; title: string; status: string; techniquesFound?: number; iocsFound?: number }[] = [];
      for (const url of urls) {
        const externalId = url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-').slice(0, 120);
        if (existingIds.has(externalId)) {
          results.push({ url, title: '(already imported)', status: 'skipped' });
          continue;
        }

        try {
          const resp = await fetch(url, {
            headers: { 'User-Agent': 'Caldera-DFIR-Ingest/1.0' },
          });
          if (!resp.ok) {
            results.push({ url, title: '', status: `fetch_error_${resp.status}` });
            continue;
          }
          const reportHtml = await resp.text();
          const parsed = parseDfirReportHtml(reportHtml, url);

          const [result] = await (await getDb()).insert(dfirReports).values({
            externalId: parsed.externalId,
            source: 'dfir_report',
            title: parsed.title,
            url: parsed.url,
            publishedAt: parsed.publishedAt,
            summary: parsed.summary,
            threatActors: parsed.threatActors,
            malwareFamilies: parsed.malwareFamilies,
            mitreAttackTechniques: parsed.mitreAttackTechniques,
            diamondModel: parsed.diamondModel,
            timeline: parsed.timeline,
            killChainPhases: parsed.killChainPhases,
            tags: parsed.tags,
            rawContent: parsed.rawContent,
            status: 'parsed',
          });

          const reportId = result.insertId;
          if (parsed.iocs.length > 0) {
            const iocBatch = parsed.iocs.slice(0, 500).map(ioc => ({
              reportId,
              iocType: ioc.type,
              value: ioc.value,
              context: ioc.context,
            }));
            for (let i = 0; i < iocBatch.length; i += 50) {
              await (await getDb()).insert(dfirReportIocs).values(iocBatch.slice(i, i + 50));
            }
          }

          results.push({
            url,
            title: parsed.title,
            status: 'imported',
            techniquesFound: parsed.mitreAttackTechniques.length,
            iocsFound: parsed.iocs.length,
          });

          // Rate limit: 2 second delay between scrapes
          await new Promise(r => setTimeout(r, 2000));
        } catch (e: any) {
          results.push({ url, title: '', status: `error: ${e.message?.slice(0, 100)}` });
        }
      }

      return {
        totalFound: urls.length,
        imported: results.filter(r => r.status === 'imported').length,
        skipped: results.filter(r => r.status === 'skipped').length,
        failed: results.filter(r => r.status.startsWith('error') || r.status.startsWith('fetch')).length,
        results,
      };
    }),

  // ─── LLM Enrichment ────────────────────────────────────────────────────
  enrichReport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const [report] = await (await getDb()).select().from(dfirReports).where(eq(dfirReports.id, input.id)).limit(1);
      if (!report) throw new Error("Report not found");

      const contentSlice = (report.rawContent || report.summary || '').slice(0, 8000);

      const response = await invokeLLM({
        _caller: 'dfir-library.enrichReport',
        messages: [
          {
            role: 'system',
            content: `You are a cyber threat intelligence analyst. Analyze the following DFIR/threat intelligence report and extract structured intelligence data. Return a JSON object with these fields:
- summary: A concise 2-3 sentence executive summary
- threatActors: Array of threat actor names/aliases mentioned
- malwareFamilies: Array of malware families, tools, and frameworks mentioned
- mitreAttackTechniques: Array of {techniqueId, name, tactic} for all MITRE ATT&CK techniques
- killChainPhases: Array of kill chain phases covered
- tags: Array of relevant tags (ransomware type, industry, region, etc.)
- diamondModel: {adversary, capability, infrastructure, victim} if identifiable
- keyFindings: Array of 3-5 key intelligence findings
- recommendedDetections: Array of detection recommendations`,
          },
          {
            role: 'user',
            content: `Report Title: ${report.title}\nSource: ${report.source}\n\nContent:\n${contentSlice}`,
          },
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'dfir_enrichment',
            strict: true,
            schema: {
              type: 'object',
              properties: {
                summary: { type: 'string' },
                threatActors: { type: 'array', items: { type: 'string' } },
                malwareFamilies: { type: 'array', items: { type: 'string' } },
                mitreAttackTechniques: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      techniqueId: { type: 'string' },
                      name: { type: 'string' },
                      tactic: { type: 'string' },
                    },
                    required: ['techniqueId', 'name', 'tactic'],
                    additionalProperties: false,
                  },
                },
                killChainPhases: { type: 'array', items: { type: 'string' } },
                tags: { type: 'array', items: { type: 'string' } },
                diamondModel: {
                  type: 'object',
                  properties: {
                    adversary: { type: 'string' },
                    capability: { type: 'string' },
                    infrastructure: { type: 'string' },
                    victim: { type: 'string' },
                  },
                  required: ['adversary', 'capability', 'infrastructure', 'victim'],
                  additionalProperties: false,
                },
                keyFindings: { type: 'array', items: { type: 'string' } },
                recommendedDetections: { type: 'array', items: { type: 'string' } },
              },
              required: ['summary', 'threatActors', 'malwareFamilies', 'mitreAttackTechniques', 'killChainPhases', 'tags', 'diamondModel', 'keyFindings', 'recommendedDetections'],
              additionalProperties: false,
            },
          },
        },
      });

      const enriched = JSON.parse(response.choices[0].message.content || '{}');

      // Merge enriched data with existing (prefer LLM enrichment for missing fields)
      const mergedActors = [...new Set([...(report.threatActors as string[] || []), ...enriched.threatActors])];
      const mergedMalware = [...new Set([...(report.malwareFamilies as string[] || []), ...enriched.malwareFamilies])];
      const existingTechIds = new Set((report.mitreAttackTechniques as any[] || []).map((t: any) => t.techniqueId));
      const mergedTechniques = [
        ...(report.mitreAttackTechniques as any[] || []),
        ...enriched.mitreAttackTechniques.filter((t: any) => !existingTechIds.has(t.techniqueId)),
      ];
      const mergedPhases = [...new Set([...(report.killChainPhases as string[] || []), ...enriched.killChainPhases])];
      const mergedTags = [...new Set([...(report.tags as string[] || []), ...enriched.tags])];

      await (await getDb()).update(dfirReports)
        .set({
          summary: enriched.summary || report.summary,
          threatActors: mergedActors,
          malwareFamilies: mergedMalware,
          mitreAttackTechniques: mergedTechniques,
          diamondModel: enriched.diamondModel || report.diamondModel,
          killChainPhases: mergedPhases,
          tags: mergedTags,
          status: 'enriched',
          updatedAt: new Date().toISOString(),
        })
        .where(eq(dfirReports.id, input.id));

      return {
        reportId: input.id,
        enrichedFields: {
          threatActorsAdded: enriched.threatActors.length,
          malwareAdded: enriched.malwareFamilies.length,
          techniquesAdded: enriched.mitreAttackTechniques.filter((t: any) => !existingTechIds.has(t.techniqueId)).length,
          keyFindings: enriched.keyFindings,
          recommendedDetections: enriched.recommendedDetections,
        },
      };
    }),

  // ─── Export Training Data ───────────────────────────────────────────────
  exportTrainingData: protectedProcedure
    .input(z.object({
      reportIds: z.array(z.number()).optional(),
      status: z.enum(['parsed', 'enriched', 'training_ready']).optional(),
    }).optional())
    .query(async ({ input }) => {
      const conditions: any[] = [];
      if (input?.reportIds?.length) conditions.push(inArray(dfirReports.id, input.reportIds));
      if (input?.status) conditions.push(eq(dfirReports.status, input.status));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const reports = await (await getDb()).select().from(dfirReports).where(where).orderBy(desc(dfirReports.createdAt));

      // Format as training examples
      const trainingExamples = reports.map(report => ({
        id: report.id,
        title: report.title,
        source: report.source,
        messages: [
          {
            role: 'system' as const,
            content: 'You are a cyber threat intelligence analyst. Analyze the following incident report and extract structured threat intelligence.',
          },
          {
            role: 'user' as const,
            content: `Analyze this incident report:\n\nTitle: ${report.title}\n\n${(report.rawContent || report.summary || '').slice(0, 6000)}`,
          },
          {
            role: 'assistant' as const,
            content: JSON.stringify({
              threatActors: report.threatActors,
              malwareFamilies: report.malwareFamilies,
              mitreAttackTechniques: report.mitreAttackTechniques,
              killChainPhases: report.killChainPhases,
              diamondModel: report.diamondModel,
              summary: report.summary,
            }),
          },
        ],
        metadata: {
          source: report.source,
          url: report.url,
          publishedAt: report.publishedAt,
          tags: report.tags,
        },
      }));

      // Mark as training_ready
      if (reports.length > 0) {
        await (await getDb()).update(dfirReports)
          .set({ status: 'training_ready', updatedAt: new Date().toISOString() })
          .where(inArray(dfirReports.id, reports.map(r => r.id)));
      }

      return {
        totalExamples: trainingExamples.length,
        examples: trainingExamples,
      };
    }),

  // ─── Stats ──────────────────────────────────────────────────────────────
  stats: protectedProcedure.query(async () => {
    const [totalResult] = await (await getDb()).select({ total: count() }).from(dfirReports);
    const sourceBreakdown = await (await getDb()).select({
      source: dfirReports.source,
      count: count(),
    }).from(dfirReports).groupBy(dfirReports.source);

    const statusBreakdown = await (await getDb()).select({
      status: dfirReports.status,
      count: count(),
    }).from(dfirReports).groupBy(dfirReports.status);

    const [iocTotal] = await (await getDb()).select({ total: count() }).from(dfirReportIocs);

    const iocTypeBreakdown = await (await getDb()).select({
      type: dfirReportIocs.iocType,
      count: count(),
    }).from(dfirReportIocs).groupBy(dfirReportIocs.iocType);

    // Count unique techniques across all reports
    const allReports = await (await getDb()).select({ techniques: dfirReports.mitreAttackTechniques }).from(dfirReports);
    const uniqueTechniques = new Set<string>();
    for (const r of allReports) {
      for (const t of (r.techniques as any[] || [])) {
        uniqueTechniques.add(t.techniqueId);
      }
    }

    return {
      totalReports: totalResult.total,
      totalIocs: iocTotal.total,
      uniqueTechniques: uniqueTechniques.size,
      bySource: sourceBreakdown,
      byStatus: statusBreakdown,
      byIocType: iocTypeBreakdown,
    };
  }),

  // ─── Seed Library (Multi-Source) ────────────────────────────────────────
  seedLibrary: protectedProcedure
    .input(z.object({
      sources: z.array(z.enum(['dfir_report', 'cisa'])).default(['dfir_report', 'cisa']),
      maxPerSource: z.number().min(1).max(30).default(15),
    }).optional())
    .mutation(async ({ input }) => {
      const sources = input?.sources || ['dfir_report', 'cisa'];
      const maxPerSource = input?.maxPerSource || 15;
      const allResults: { source: string; url: string; title: string; status: string; techniquesFound?: number; iocsFound?: number }[] = [];

      // ── DFIR Report ──
      if (sources.includes('dfir_report')) {
        try {
          const resp = await fetch('https://thedfirreport.com/blog/', {
            headers: { 'User-Agent': 'Caldera-DFIR-Ingest/1.0' },
          });
          if (resp.ok) {
            const html = await resp.text();
            const urlPattern = /href="(https:\/\/thedfirreport\.com\/\d{4}\/\d{2}\/\d{2}\/[^"]+)"/g;
            const urls: string[] = [];
            const seen = new Set<string>();
            for (const m of html.matchAll(urlPattern)) {
              const url = m[1].replace(/\/$/, '');
              if (!seen.has(url)) { seen.add(url); urls.push(url); }
              if (urls.length >= maxPerSource) break;
            }
            for (const url of urls) {
              const externalId = url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-').slice(0, 120);
              const [existing] = await (await getDb()).select({ id: dfirReports.id }).from(dfirReports).where(eq(dfirReports.externalId, externalId)).limit(1);
              if (existing) { allResults.push({ source: 'dfir_report', url, title: '(already imported)', status: 'skipped' }); continue; }
              try {
                const r = await fetch(url, { headers: { 'User-Agent': 'Caldera-DFIR-Ingest/1.0' } });
                if (!r.ok) { allResults.push({ source: 'dfir_report', url, title: '', status: `fetch_error_${r.status}` }); continue; }
                const reportHtml = await r.text();
                const parsed = parseDfirReportHtml(reportHtml, url);
                const [result] = await (await getDb()).insert(dfirReports).values({
                  externalId: parsed.externalId, source: 'dfir_report', title: parsed.title, url: parsed.url,
                  publishedAt: parsed.publishedAt, summary: parsed.summary, threatActors: parsed.threatActors,
                  malwareFamilies: parsed.malwareFamilies, mitreAttackTechniques: parsed.mitreAttackTechniques,
                  diamondModel: parsed.diamondModel, timeline: parsed.timeline, killChainPhases: parsed.killChainPhases,
                  tags: parsed.tags, rawContent: parsed.rawContent, status: 'parsed',
                });
                if (parsed.iocs.length > 0) {
                  const iocBatch = parsed.iocs.slice(0, 500).map(ioc => ({ reportId: result.insertId, iocType: ioc.type, value: ioc.value, context: ioc.context }));
                  for (let i = 0; i < iocBatch.length; i += 50) { await (await getDb()).insert(dfirReportIocs).values(iocBatch.slice(i, i + 50)); }
                }
                allResults.push({ source: 'dfir_report', url, title: parsed.title, status: 'imported', techniquesFound: parsed.mitreAttackTechniques.length, iocsFound: parsed.iocs.length });
                await new Promise(r => setTimeout(r, 2000));
              } catch (e: any) { allResults.push({ source: 'dfir_report', url, title: '', status: `error: ${e.message?.slice(0, 100)}` }); }
            }
          }
        } catch (e: any) { allResults.push({ source: 'dfir_report', url: 'index', title: '', status: `index_error: ${e.message?.slice(0, 100)}` }); }
      }

      // ── CISA Advisories ──
      if (sources.includes('cisa')) {
        try {
          const cisaResp = await fetch('https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94', {
            headers: { 'User-Agent': 'Caldera-DFIR-Ingest/1.0' },
          });
          if (cisaResp.ok) {
            const cisaHtml = await cisaResp.text();
            const cisaPattern = /href="(\/news-events\/cybersecurity-advisories\/[^"]+)"/g;
            const cisaUrls: string[] = [];
            const cisaSeen = new Set<string>();
            for (const m of cisaHtml.matchAll(cisaPattern)) {
              const path = m[1];
              if (!cisaSeen.has(path) && !path.includes('?')) {
                cisaSeen.add(path);
                cisaUrls.push(`https://www.cisa.gov${path}`);
              }
              if (cisaUrls.length >= maxPerSource) break;
            }
            for (const url of cisaUrls) {
              const externalId = url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-').slice(0, 120);
              const [existing] = await (await getDb()).select({ id: dfirReports.id }).from(dfirReports).where(eq(dfirReports.externalId, externalId)).limit(1);
              if (existing) { allResults.push({ source: 'cisa', url, title: '(already imported)', status: 'skipped' }); continue; }
              try {
                const r = await fetch(url, { headers: { 'User-Agent': 'Caldera-DFIR-Ingest/1.0' } });
                if (!r.ok) { allResults.push({ source: 'cisa', url, title: '', status: `fetch_error_${r.status}` }); continue; }
                const advisoryHtml = await r.text();
                const titleMatch = advisoryHtml.match(/<h1[^>]*>([^<]+)<\/h1>/) || advisoryHtml.match(/<title>([^<]+)<\/title>/);
                const title = titleMatch ? titleMatch[1].trim().replace(/\s*\|.*$/, '') : url.split('/').pop() || 'CISA Advisory';
                const bodyMatch = advisoryHtml.match(/<article[^>]*>([\s\S]*?)<\/article>/) || advisoryHtml.match(/<main[^>]*>([\s\S]*?)<\/main>/);
                const bodyText = bodyMatch ? bodyMatch[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() : '';
                const parsed = parseManualReport(bodyText.slice(0, 50000), title);
                const [result] = await (await getDb()).insert(dfirReports).values({
                  externalId, source: 'cisa', title, url, summary: bodyText.slice(0, 1000),
                  threatActors: parsed.threatActors, malwareFamilies: parsed.malwareFamilies,
                  mitreAttackTechniques: parsed.mitreAttackTechniques, killChainPhases: parsed.killChainPhases,
                  tags: ['cisa', 'advisory'], rawContent: bodyText.slice(0, 50000), status: 'parsed',
                });
                if (parsed.iocs.length > 0) {
                  const iocBatch = parsed.iocs.slice(0, 500).map(ioc => ({ reportId: result.insertId, iocType: ioc.type, value: ioc.value, context: ioc.context }));
                  for (let i = 0; i < iocBatch.length; i += 50) { await (await getDb()).insert(dfirReportIocs).values(iocBatch.slice(i, i + 50)); }
                }
                allResults.push({ source: 'cisa', url, title, status: 'imported', techniquesFound: parsed.mitreAttackTechniques.length, iocsFound: parsed.iocs.length });
                await new Promise(r => setTimeout(r, 2000));
              } catch (e: any) { allResults.push({ source: 'cisa', url, title: '', status: `error: ${e.message?.slice(0, 100)}` }); }
            }
          }
        } catch (e: any) { allResults.push({ source: 'cisa', url: 'index', title: '', status: `index_error: ${e.message?.slice(0, 100)}` }); }
      }

      return {
        totalImported: allResults.filter(r => r.status === 'imported').length,
        totalSkipped: allResults.filter(r => r.status === 'skipped').length,
        totalFailed: allResults.filter(r => r.status.startsWith('error') || r.status.startsWith('fetch')).length,
        results: allResults,
      };
    }),

  // ─── Delete Report ──────────────────────────────────────────────────────
  deleteReport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      await (await getDb()).delete(dfirReportIocs).where(eq(dfirReportIocs.reportId, input.id));
      await (await getDb()).delete(dfirReports).where(eq(dfirReports.id, input.id));
      return { deleted: true };
    }),

  // ─── Search IOCs ────────────────────────────────────────────────────────
  searchIocs: protectedProcedure
    .input(z.object({
      query: z.string().min(1),
      type: z.enum(['ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email', 'cve', 'filename', 'registry_key', 'mutex']).optional(),
    }))
    .query(async ({ input }) => {
      const conditions: any[] = [like(dfirReportIocs.value, `%${input.query}%`)];
      if (input.type) conditions.push(eq(dfirReportIocs.iocType, input.type));

      const results = await (await getDb()).select({
        iocId: dfirReportIocs.id,
        iocType: dfirReportIocs.iocType,
        value: dfirReportIocs.value,
        context: dfirReportIocs.context,
        reportId: dfirReportIocs.reportId,
        reportTitle: dfirReports.title,
        reportSource: dfirReports.source,
      })
        .from(dfirReportIocs)
        .innerJoin(dfirReports, eq(dfirReportIocs.reportId, dfirReports.id))
        .where(and(...conditions))
        .limit(50);

      return results;
    }),
});
