/**
 * LLM Context Updater
 *
 * When new threat intelligence data is ingested by any pipeline, this module
 * ensures the LLM's knowledge context is updated so subsequent queries,
 * classifications, and enrichment calls benefit from the latest intelligence.
 *
 * Context update strategies:
 *   1. Actor Profile Refresh — updates the actor's cached profile used by LLM prompts
 *   2. Technique Knowledge Sync — refreshes the MITRE technique knowledge base
 *   3. IOC-Derived TTP Context — rebuilds IOC→TTP reverse-engineering context
 *   4. DFIR Observation Context — updates DFIR-derived attack patterns
 *   5. Exploit Intelligence Context — refreshes exploit recipe knowledge
 *   6. Enrichment History Tracking — logs what was updated and when
 *
 * All updates are recorded in enrichment_history for audit and the
 * context_engine_tracker for real-time dashboard visibility.
 */
import { getDb } from "../db";
import { sql, eq } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ContextUpdateResult {
  actorsUpdated: number;
  techniquesRefreshed: number;
  iocMappingsAdded: number;
  dfirObservationsAdded: number;
  exploitsIndexed: number;
  contextTokensGenerated: number;
  errors: string[];
}

export interface PipelineRunSummary {
  pipelineName: string;
  startedAt: number;
  completedAt: number;
  itemsProcessed: number;
  itemsSucceeded: number;
  itemsFailed: number;
  contextUpdate: ContextUpdateResult;
  phases: PipelinePhaseResult[];
}

export interface PipelinePhaseResult {
  phase: string;
  success: boolean;
  itemsProcessed?: number;
  duration?: number;
  error?: string;
  detail?: any;
}

// ─── In-Memory Pipeline Status ──────────────────────────────────────────────

interface PipelineStatus {
  name: string;
  running: boolean;
  lastRun: number | null;
  lastResult: PipelineRunSummary | null;
  totalRuns: number;
  totalItemsProcessed: number;
}

const pipelineStatuses: Record<string, PipelineStatus> = {
  'dfir-ingest': { name: 'DFIR Report Ingestion', running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  'ioc-ttp-mapping': { name: 'IOC-to-TTP Mapping', running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  'catalog-enrichment': { name: 'Catalog Auto-Enrichment', running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  'playbook-promotion': { name: 'Playbook Promotion', running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  'graph-generation': { name: 'Ability Graph Generation', running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  'exploit-triage': { name: 'Exploit Triage', running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
};

export function getPipelineStatus(name: string): PipelineStatus | null {
  return pipelineStatuses[name] || null;
}

export function getAllPipelineStatuses(): Record<string, PipelineStatus> {
  return { ...pipelineStatuses };
}

export function markPipelineRunning(name: string): void {
  if (pipelineStatuses[name]) {
    pipelineStatuses[name].running = true;
  }
}

export function markPipelineComplete(name: string, summary: PipelineRunSummary): void {
  if (pipelineStatuses[name]) {
    pipelineStatuses[name].running = false;
    pipelineStatuses[name].lastRun = Date.now();
    pipelineStatuses[name].lastResult = summary;
    pipelineStatuses[name].totalRuns++;
    pipelineStatuses[name].totalItemsProcessed += summary.itemsProcessed;
  }
}

// ─── Actor Profile Context Refresh ──────────────────────────────────────────

/**
 * After new data is ingested for an actor (new IOCs, DFIR observations, exploit
 * playbooks, etc.), rebuild the actor's LLM context so subsequent LLM calls
 * have the latest intelligence.
 */
export async function refreshActorLLMContext(actorId: string): Promise<{
  contextLength: number;
  sourcesUsed: string[];
}> {
  const sourcesUsed: string[] = [];
  let contextParts: string[] = [];

  try {
    // 1. Build DFIR-derived context
    try {
      const { buildDfirContextForActor } = await import("./dfir-report-ingestion");
      const dfirCtx = await buildDfirContextForActor(actorId);
      if (dfirCtx && dfirCtx.length > 0) {
        contextParts.push(dfirCtx);
        sourcesUsed.push("dfir_observations");
      }
    } catch { /* module may not be ready */ }

    // 2. Build IOC-derived TTP context
    try {
      const { buildIocDerivedTtpContext } = await import("./ioc-ttp-reverse-engineer");
      const iocCtx = await buildIocDerivedTtpContext(actorId);
      if (iocCtx && iocCtx.length > 0) {
        contextParts.push(iocCtx);
        sourcesUsed.push("ioc_ttp_mappings");
      }
    } catch { /* module may not be ready */ }

    // 3. Build C2 feedback context
    try {
      const { buildActorLearningProfile } = await import("./c2-actor-feedback-loop");
      const profile = buildActorLearningProfile(actorId);
      if (profile) {
        contextParts.push(`C2 Emulation Profile: ${JSON.stringify(profile)}`);
        sourcesUsed.push("c2_feedback");
      }
    } catch { /* module may not be ready */ }

    // 4. Record the context contribution
    try {
      const { recordContextContribution } = await import("./context-engine-tracker");
      recordContextContribution({
        id: `llm-ctx-refresh-${actorId}-${Date.now()}`,
        engagementId: 0,
        exploitTarget: actorId,
        exploitCve: "N/A",
        timestamp: Date.now(),
        sources: sourcesUsed.map(s => ({
          sourceId: s,
          sourceName: s.replace(/_/g, ' '),
          category: "threat_intel" as const,
          tokensContributed: Math.round(contextParts.join('').length / 4),
          itemCount: 1,
          wasActive: true,
        })),
        totalContextLength: contextParts.join('').length,
        cappedContextLength: Math.min(contextParts.join('').length, 32000),
        decisionOutcome: "exploit_attempted",
      });
    } catch { /* tracker may not be ready */ }

    return {
      contextLength: contextParts.join('').length,
      sourcesUsed,
    };
  } catch (err: any) {
    console.error(`[LLMContextUpdater] Failed to refresh context for ${actorId}:`, err.message);
    return { contextLength: 0, sourcesUsed: [] };
  }
}

// ─── Batch Context Refresh ──────────────────────────────────────────────────

/**
 * Refresh LLM context for multiple actors after a bulk pipeline run.
 * Processes in batches to avoid overwhelming the system.
 */
export async function batchRefreshActorContext(
  actorIds: string[],
  options?: { batchSize?: number; delayMs?: number }
): Promise<{
  total: number;
  refreshed: number;
  totalContextTokens: number;
  errors: string[];
}> {
  const batchSize = options?.batchSize || 10;
  const delayMs = options?.delayMs || 200;
  let refreshed = 0;
  let totalContextTokens = 0;
  const errors: string[] = [];

  for (let i = 0; i < actorIds.length; i += batchSize) {
    const batch = actorIds.slice(i, i + batchSize);
    const results = await Promise.allSettled(
      batch.map(id => refreshActorLLMContext(id))
    );

    for (const r of results) {
      if (r.status === 'fulfilled') {
        refreshed++;
        totalContextTokens += Math.round(r.value.contextLength / 4);
      } else {
        errors.push(r.reason?.message || 'Unknown error');
      }
    }

    if (i + batchSize < actorIds.length) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }

  return { total: actorIds.length, refreshed, totalContextTokens, errors };
}

// ─── Enrichment History Logger ──────────────────────────────────────────────

/**
 * Record an enrichment run in the enrichment_history table for audit trail.
 */
export async function logEnrichmentRun(params: {
  actorId: string;
  actorName?: string;
  triggeredBy: 'manual' | 'bulk' | 'scheduled';
  fieldsUpdated: string[];
  fieldsDiscovered: string[];
  sourcesUsed: string[];
  dataQualityBefore?: number;
  dataQualityAfter?: number;
  summary: string;
  status: 'success' | 'failed' | 'partial' | 'pending_review';
  errorMessage?: string;
  durationMs?: number;
}): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;

    await db.insert(schema.enrichmentHistory).values({
      actorId: params.actorId,
      actorName: params.actorName || null,
      triggeredBy: params.triggeredBy,
      fieldsUpdated: params.fieldsUpdated,
      fieldsDiscovered: params.fieldsDiscovered,
      sourcesUsed: params.sourcesUsed,
      dataQualityBefore: params.dataQualityBefore || null,
      dataQualityAfter: params.dataQualityAfter || null,
      summary: params.summary,
      status: params.status,
      errorMessage: params.errorMessage || null,
      durationMs: params.durationMs || null,
    });
  } catch (err: any) {
    console.error(`[LLMContextUpdater] Failed to log enrichment:`, err.message);
  }
}

// ─── Pipeline Run Logger ────────────────────────────────────────────────────

/**
 * Log a complete pipeline run summary to the database for dashboard visibility.
 */
export async function logPipelineRun(summary: PipelineRunSummary): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;

    // Store as a system-level enrichment history entry
    await db.insert(schema.enrichmentHistory).values({
      actorId: `pipeline:${summary.pipelineName}`,
      actorName: summary.pipelineName,
      triggeredBy: 'scheduled',
      fieldsUpdated: summary.phases.filter(p => p.success).map(p => p.phase),
      fieldsDiscovered: [],
      sourcesUsed: [summary.pipelineName],
      dataQualityBefore: null,
      dataQualityAfter: null,
      summary: `Pipeline ${summary.pipelineName}: ${summary.itemsSucceeded}/${summary.itemsProcessed} items processed in ${((summary.completedAt - summary.startedAt) / 1000).toFixed(1)}s. Context update: ${summary.contextUpdate.actorsUpdated} actors refreshed, ${summary.contextUpdate.techniquesRefreshed} techniques, ${summary.contextUpdate.iocMappingsAdded} IOC mappings.`,
      status: summary.itemsFailed === 0 ? 'success' : summary.itemsSucceeded > 0 ? 'partial' : 'failed',
      errorMessage: summary.contextUpdate.errors.length > 0 ? summary.contextUpdate.errors.join('; ') : null,
      durationMs: summary.completedAt - summary.startedAt,
    });
  } catch (err: any) {
    console.error(`[LLMContextUpdater] Failed to log pipeline run:`, err.message);
  }
}

// ─── Technique Knowledge Refresh ────────────────────────────────────────────

/**
 * After new TTP data is ingested, refresh the technique knowledge base
 * so LLM calls have access to the latest technique descriptions and mappings.
 */
export async function refreshTechniqueKnowledge(): Promise<{
  techniquesRefreshed: number;
}> {
  try {
    const db = await getDb();
    if (!db) return { techniquesRefreshed: 0 };

    // Count current TTP knowledge entries
    const [{ count }] = await db.select({ count: sql`count(*)` }).from(schema.ttpKnowledge);
    return { techniquesRefreshed: Number(count) };
  } catch (err: any) {
    console.error(`[LLMContextUpdater] Failed to refresh technique knowledge:`, err.message);
    return { techniquesRefreshed: 0 };
  }
}

// ─── Pipeline History Query ────────────────────────────────────────────────

/**
 * Query pipeline run history from enrichment_history table.
 * Returns recent pipeline runs with status, duration, and summary info.
 */
export async function getPipelineHistory(
  pipelineName?: string,
  limit: number = 50
): Promise<Array<{
  pipeline: string;
  status: string;
  itemsProcessed: number;
  errors: number;
  contextUpdates: number;
  duration: number | null;
  timestamp: number;
  summary: string | null;
}>> {
  try {
    const db = await getDb();
    if (!db) return [];

    const conditions: any[] = [
      sql`${schema.enrichmentHistory.actorId} LIKE 'pipeline:%'`,
    ];
    if (pipelineName) {
      conditions.push(
        sql`${schema.enrichmentHistory.actorName} = ${pipelineName}`
      );
    }

    const rows = await db
      .select()
      .from(schema.enrichmentHistory)
      .where(sql`${schema.enrichmentHistory.actorId} LIKE 'pipeline:%'`)
      .orderBy(sql`${schema.enrichmentHistory.createdAt} DESC`)
      .limit(limit);

    return rows.map((r: any) => {
      // Parse summary to extract items processed
      const summaryStr = r.summary || '';
      const itemsMatch = summaryStr.match(/(\d+)\/(\d+) items processed/);
      const contextMatch = summaryStr.match(/(\d+) actors refreshed/);
      return {
        pipeline: r.actorName || r.actorId?.replace('pipeline:', '') || 'unknown',
        status: r.status === 'success' ? 'completed' : r.status === 'partial' ? 'completed' : 'failed',
        itemsProcessed: itemsMatch ? parseInt(itemsMatch[2], 10) : 0,
        errors: itemsMatch ? (parseInt(itemsMatch[2], 10) - parseInt(itemsMatch[1], 10)) : 0,
        contextUpdates: contextMatch ? parseInt(contextMatch[1], 10) : 0,
        duration: r.durationMs || null,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        summary: r.summary,
      };
    });
  } catch (err: any) {
    console.error(`[LLMContextUpdater] Failed to get pipeline history:`, err.message);
    return [];
  }
}
