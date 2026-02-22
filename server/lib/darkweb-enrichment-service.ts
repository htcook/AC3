/**
 * Darkweb Enrichment Service
 *
 * LLM-powered enrichment of raw darkweb intelligence events.
 * Takes underground_intel_events and produces darkweb_enriched_records
 * with threat assessments, risk scores, MITRE mappings, and recommended actions.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import {
  undergroundIntelEvents,
  darkwebEnrichedRecords,
  type InsertDarkwebEnrichedRecord,
} from "../../drizzle/schema";
import { eq, and, isNull, desc, sql } from "drizzle-orm";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── LLM Enrichment ─────────────────────────────────────────────────────

interface EnrichmentOutput {
  summary: string;
  threatAssessment: string;
  riskScore: number;
  impactAnalysis: string;
  recommendedActions: string[];
  relatedActors: string[];
  relatedCves: string[];
  mitreTactics: string[];
  mitreTechniques: string[];
  affectedSectors: string[];
  affectedCountries: string[];
}

/**
 * Enrich a single underground intel event using LLM analysis.
 */
export async function enrichEvent(eventId: number): Promise<InsertDarkwebEnrichedRecord | null> {
  const db = await requireDb();
  const [event] = await db.select().from(undergroundIntelEvents).where(eq(undergroundIntelEvents.id, eventId)).limit(1);
  if (!event) return null;

  const startTime = Date.now();

  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content: `You are a senior darkweb threat intelligence analyst. Analyze the following underground intelligence event and produce a structured enrichment report. Be specific about threat actors, TTPs, and actionable recommendations. Use MITRE ATT&CK framework for technique mapping. Risk scores: 0-30 low, 31-60 medium, 61-80 high, 81-100 critical.`,
        },
        {
          role: "user",
          content: `Analyze this darkweb intelligence event:\n\nCategory: ${event.category}\nSource: ${event.source}\nTitle: ${event.title}\nDescription: ${event.description || "N/A"}\nActor: ${event.actorName || "Unknown"}\nVictim: ${event.victimName || "N/A"}\nSector: ${event.victimSector || "N/A"}\nCountry: ${event.victimCountry || "N/A"}\nIOC Type: ${event.iocType || "N/A"}\nIOC Value: ${event.iocValue || "N/A"}\nSeverity: ${event.severity}\nTags: ${JSON.stringify(event.tags || [])}`,
        },
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
              affectedCountries: { type: "array", items: { type: "string" }, description: "Affected countries" },
            },
            required: [
              "summary", "threatAssessment", "riskScore", "impactAnalysis",
              "recommendedActions", "relatedActors", "relatedCves",
              "mitreTactics", "mitreTechniques", "affectedSectors", "affectedCountries",
            ],
            additionalProperties: false,
          },
        },
      },
    });

    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) throw new Error("Empty LLM response");
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);

    const enrichment: EnrichmentOutput = JSON.parse(content);
    const processingTimeMs = Date.now() - startTime;

    const record: InsertDarkwebEnrichedRecord = {
      sourceEventId: eventId,
      sourceTable: "underground_intel_events",
      summary: enrichment.summary,
      threatAssessment: enrichment.threatAssessment,
      riskScore: Math.min(100, Math.max(0, enrichment.riskScore)),
      impactAnalysis: enrichment.impactAnalysis,
      recommendedActions: enrichment.recommendedActions,
      relatedActors: enrichment.relatedActors,
      relatedCampaigns: [],
      relatedCves: enrichment.relatedCves,
      relatedIocs: [],
      mitreTactics: enrichment.mitreTactics,
      mitreTechniques: enrichment.mitreTechniques,
      affectedSectors: enrichment.affectedSectors,
      affectedCountries: enrichment.affectedCountries,
      enrichmentModel: "platform-llm",
      enrichmentVersion: "1.0",
      processingTimeMs,
    };

    // Insert enriched record
    await db.insert(darkwebEnrichedRecords).values(record);

    // Mark source event as enriched
    await db.update(undergroundIntelEvents)
      .set({ enriched: true, enrichmentData: enrichment })
      .where(eq(undergroundIntelEvents.id, eventId));

    return record;
  } catch (err: any) {
    console.error(`[DarkwebEnrichment] Failed to enrich event #${eventId}:`, err.message);
    return null;
  }
}

/**
 * Batch-enrich unenriched events (up to `limit` at a time).
 */
export async function enrichBatch(limit = 10): Promise<{
  enriched: number;
  failed: number;
  skipped: number;
}> {
  const db = await requireDb();
  const unenriched = await db.select({ id: undergroundIntelEvents.id })
    .from(undergroundIntelEvents)
    .where(eq(undergroundIntelEvents.enriched, false))
    .orderBy(desc(undergroundIntelEvents.createdAt))
    .limit(limit);

  let enriched = 0;
  let failed = 0;

  for (const event of unenriched) {
    const result = await enrichEvent(event.id);
    if (result) {
      enriched++;
    } else {
      failed++;
    }
    // Rate limit: 1 second between LLM calls
    await new Promise((r) => setTimeout(r, 1000));
  }

  return { enriched, failed, skipped: 0 };
}

/**
 * Get enrichment statistics.
 */
export async function getEnrichmentStats() {
  const db = await requireDb();
  const [stats] = await db.select({
    total: sql<number>`COUNT(*)`,
    enriched: sql<number>`SUM(CASE WHEN uie_enriched = true THEN 1 ELSE 0 END)`,
    unenriched: sql<number>`SUM(CASE WHEN uie_enriched = false THEN 1 ELSE 0 END)`,
  }).from(undergroundIntelEvents);

  const [enrichedStats] = await db.select({
    totalEnriched: sql<number>`COUNT(*)`,
    avgRiskScore: sql<number>`AVG(der_risk_score)`,
    criticalCount: sql<number>`SUM(CASE WHEN der_risk_score >= 81 THEN 1 ELSE 0 END)`,
    highCount: sql<number>`SUM(CASE WHEN der_risk_score >= 61 AND der_risk_score < 81 THEN 1 ELSE 0 END)`,
  }).from(darkwebEnrichedRecords);

  return {
    totalEvents: stats?.total || 0,
    enrichedEvents: stats?.enriched || 0,
    unenrichedEvents: stats?.unenriched || 0,
    enrichmentRate: stats?.total ? Math.round(((stats.enriched || 0) / stats.total) * 100) : 0,
    totalEnrichedRecords: enrichedStats?.totalEnriched || 0,
    avgRiskScore: Math.round(enrichedStats?.avgRiskScore || 0),
    criticalRiskCount: enrichedStats?.criticalCount || 0,
    highRiskCount: enrichedStats?.highCount || 0,
  };
}
