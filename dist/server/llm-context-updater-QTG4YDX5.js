import {
  getDb,
  init_db
} from "./chunk-3OPUTHKA.js";
import "./chunk-NRYVRXXR.js";
import {
  enrichmentHistory,
  init_schema,
  ttpKnowledge
} from "./chunk-H7DAFEQB.js";
import "./chunk-KFQGP6VL.js";

// server/lib/llm-context-updater.ts
init_db();
init_schema();
import { sql } from "drizzle-orm";
var pipelineStatuses = {
  "dfir-ingest": { name: "DFIR Report Ingestion", running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  "ioc-ttp-mapping": { name: "IOC-to-TTP Mapping", running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  "catalog-enrichment": { name: "Catalog Auto-Enrichment", running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  "playbook-promotion": { name: "Playbook Promotion", running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  "graph-generation": { name: "Ability Graph Generation", running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 },
  "exploit-triage": { name: "Exploit Triage", running: false, lastRun: null, lastResult: null, totalRuns: 0, totalItemsProcessed: 0 }
};
function getPipelineStatus(name) {
  return pipelineStatuses[name] || null;
}
function getAllPipelineStatuses() {
  return { ...pipelineStatuses };
}
function markPipelineRunning(name) {
  if (pipelineStatuses[name]) {
    pipelineStatuses[name].running = true;
  }
}
function markPipelineComplete(name, summary) {
  if (pipelineStatuses[name]) {
    pipelineStatuses[name].running = false;
    pipelineStatuses[name].lastRun = Date.now();
    pipelineStatuses[name].lastResult = summary;
    pipelineStatuses[name].totalRuns++;
    pipelineStatuses[name].totalItemsProcessed += summary.itemsProcessed;
  }
}
async function refreshActorLLMContext(actorId) {
  const sourcesUsed = [];
  let contextParts = [];
  try {
    try {
      const { buildDfirContextForActor } = await import("./dfir-report-ingestion-XSBVRJAM.js");
      const dfirCtx = await buildDfirContextForActor(actorId);
      if (dfirCtx && dfirCtx.length > 0) {
        contextParts.push(dfirCtx);
        sourcesUsed.push("dfir_observations");
      }
    } catch {
    }
    try {
      const { buildIocDerivedTtpContext } = await import("./ioc-ttp-reverse-engineer-JGYUGNCH.js");
      const iocCtx = await buildIocDerivedTtpContext(actorId);
      if (iocCtx && iocCtx.length > 0) {
        contextParts.push(iocCtx);
        sourcesUsed.push("ioc_ttp_mappings");
      }
    } catch {
    }
    try {
      const { buildActorLearningProfile } = await import("./c2-actor-feedback-loop-32EFWHPW.js");
      const profile = buildActorLearningProfile(actorId);
      if (profile) {
        contextParts.push(`C2 Emulation Profile: ${JSON.stringify(profile)}`);
        sourcesUsed.push("c2_feedback");
      }
    } catch {
    }
    try {
      const { recordContextContribution } = await import("./context-engine-tracker-IANKSPWI.js");
      recordContextContribution({
        id: `llm-ctx-refresh-${actorId}-${Date.now()}`,
        engagementId: 0,
        exploitTarget: actorId,
        exploitCve: "N/A",
        timestamp: Date.now(),
        sources: sourcesUsed.map((s) => ({
          sourceId: s,
          sourceName: s.replace(/_/g, " "),
          category: "threat_intel",
          tokensContributed: Math.round(contextParts.join("").length / 4),
          itemCount: 1,
          wasActive: true
        })),
        totalContextLength: contextParts.join("").length,
        cappedContextLength: Math.min(contextParts.join("").length, 32e3),
        decisionOutcome: "exploit_attempted"
      });
    } catch {
    }
    return {
      contextLength: contextParts.join("").length,
      sourcesUsed
    };
  } catch (err) {
    console.error(`[LLMContextUpdater] Failed to refresh context for ${actorId}:`, err.message);
    return { contextLength: 0, sourcesUsed: [] };
  }
}
async function batchRefreshActorContext(actorIds, options) {
  const batchSize = options?.batchSize || 10;
  const delayMs = options?.delayMs || 200;
  let refreshed = 0;
  let totalContextTokens = 0;
  const errors = [];
  for (let i = 0; i < actorIds.length; i += batchSize) {
    const batch = actorIds.slice(i, i + batchSize);
    const results = await Promise.allSettled(
      batch.map((id) => refreshActorLLMContext(id))
    );
    for (const r of results) {
      if (r.status === "fulfilled") {
        refreshed++;
        totalContextTokens += Math.round(r.value.contextLength / 4);
      } else {
        errors.push(r.reason?.message || "Unknown error");
      }
    }
    if (i + batchSize < actorIds.length) {
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  return { total: actorIds.length, refreshed, totalContextTokens, errors };
}
async function logEnrichmentRun(params) {
  try {
    const db = await getDb();
    if (!db) return;
    await db.insert(enrichmentHistory).values({
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
      durationMs: params.durationMs || null
    });
  } catch (err) {
    console.error(`[LLMContextUpdater] Failed to log enrichment:`, err.message);
  }
}
async function logPipelineRun(summary) {
  try {
    const db = await getDb();
    if (!db) return;
    await db.insert(enrichmentHistory).values({
      actorId: `pipeline:${summary.pipelineName}`,
      actorName: summary.pipelineName,
      triggeredBy: "scheduled",
      fieldsUpdated: summary.phases.filter((p) => p.success).map((p) => p.phase),
      fieldsDiscovered: [],
      sourcesUsed: [summary.pipelineName],
      dataQualityBefore: null,
      dataQualityAfter: null,
      summary: `Pipeline ${summary.pipelineName}: ${summary.itemsSucceeded}/${summary.itemsProcessed} items processed in ${((summary.completedAt - summary.startedAt) / 1e3).toFixed(1)}s. Context update: ${summary.contextUpdate.actorsUpdated} actors refreshed, ${summary.contextUpdate.techniquesRefreshed} techniques, ${summary.contextUpdate.iocMappingsAdded} IOC mappings.`,
      status: summary.itemsFailed === 0 ? "success" : summary.itemsSucceeded > 0 ? "partial" : "failed",
      errorMessage: summary.contextUpdate.errors.length > 0 ? summary.contextUpdate.errors.join("; ") : null,
      durationMs: summary.completedAt - summary.startedAt
    });
  } catch (err) {
    console.error(`[LLMContextUpdater] Failed to log pipeline run:`, err.message);
  }
}
async function refreshTechniqueKnowledge() {
  try {
    const db = await getDb();
    if (!db) return { techniquesRefreshed: 0 };
    const [{ count }] = await db.select({ count: sql`count(*)` }).from(ttpKnowledge);
    return { techniquesRefreshed: Number(count) };
  } catch (err) {
    console.error(`[LLMContextUpdater] Failed to refresh technique knowledge:`, err.message);
    return { techniquesRefreshed: 0 };
  }
}
async function getPipelineHistory(pipelineName, limit = 50) {
  try {
    const db = await getDb();
    if (!db) return [];
    const conditions = [
      sql`${enrichmentHistory.actorId} LIKE 'pipeline:%'`
    ];
    if (pipelineName) {
      conditions.push(
        sql`${enrichmentHistory.actorName} = ${pipelineName}`
      );
    }
    const rows = await db.select().from(enrichmentHistory).where(sql`${enrichmentHistory.actorId} LIKE 'pipeline:%'`).orderBy(sql`${enrichmentHistory.createdAt} DESC`).limit(limit);
    return rows.map((r) => {
      const summaryStr = r.summary || "";
      const itemsMatch = summaryStr.match(/(\d+)\/(\d+) items processed/);
      const contextMatch = summaryStr.match(/(\d+) actors refreshed/);
      return {
        pipeline: r.actorName || r.actorId?.replace("pipeline:", "") || "unknown",
        status: r.status === "success" ? "completed" : r.status === "partial" ? "completed" : "failed",
        itemsProcessed: itemsMatch ? parseInt(itemsMatch[2], 10) : 0,
        errors: itemsMatch ? parseInt(itemsMatch[2], 10) - parseInt(itemsMatch[1], 10) : 0,
        contextUpdates: contextMatch ? parseInt(contextMatch[1], 10) : 0,
        duration: r.durationMs || null,
        timestamp: r.createdAt ? new Date(r.createdAt).getTime() : Date.now(),
        summary: r.summary
      };
    });
  } catch (err) {
    console.error(`[LLMContextUpdater] Failed to get pipeline history:`, err.message);
    return [];
  }
}
export {
  batchRefreshActorContext,
  getAllPipelineStatuses,
  getPipelineHistory,
  getPipelineStatus,
  logEnrichmentRun,
  logPipelineRun,
  markPipelineComplete,
  markPipelineRunning,
  refreshActorLLMContext,
  refreshTechniqueKnowledge
};
