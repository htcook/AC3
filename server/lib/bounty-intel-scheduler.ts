/**
 * Bug Bounty Intelligence Scheduler
 * 
 * Automated pipeline that continuously gathers vulnerability intelligence
 * from bug bounty data sources and feeds it into the LLM training pipeline.
 * 
 * Schedule: Every 6 hours (04:00, 10:00, 16:00, 22:00 UTC)
 * 
 * Pipeline stages:
 * 1. Sync HackerOne hacktivity (latest disclosed findings)
 * 2. Sync HackerOne programs (new/updated programs)
 * 3. Sync program scopes & weaknesses for top programs
 * 4. Extract LLM training samples from new H1 findings
 * 5. Extract training samples from recent engagement findings
 * 6. Enrich raw training samples with LLM narratives
 * 7. Generate ScanForge detection templates from new findings
 * 8. Run cross-correlation against AC3 engagement assets
 * 
 * Runs without tRPC context — uses env var credentials directly.
 * Memory-safe: Each stage runs sequentially with GC hints between stages.
 */

import cron from "node-cron";
import { getDb as _getDb } from "../db";
import {
  bugBountyFindings,
  bugBountyPrograms,
  bugBountyProgramScopes,
  bugBountyProgramWeaknesses,
  bugBountySyncLogs,
  bugBountyCorrelations,
  discoveredAssets,
  iocFeeds,
} from "../../drizzle/schema";
import { eq, desc, and, sql, inArray } from "drizzle-orm";

async function getDb() {
  const db = await _getDb();
  return db!;
}

let pipelineRunning = false;

// ─── HackerOne API Client (per-user credential support) ───
import { getH1CredentialsForUser } from './credential-service';

const H1_BASE = "https://api.hackerone.com/v1/hackers";

/** Active user ID for per-user credential resolution in scheduler context */
let _schedulerUserId: number | string | null = null;

/** Set the user context for the scheduler's HackerOne API calls */
export function setSchedulerUser(userId: number | string | null): void {
  _schedulerUserId = userId;
}

async function getH1Credentials(): Promise<{ username: string; token: string } | null> {
  // Try per-user credentials from DB first
  const creds = await getH1CredentialsForUser(_schedulerUserId);
  if (creds) {
    return { username: creds.username, token: creds.apiKey };
  }
  // Fallback to env vars
  const envKey = process.env.HACKERONE_API_KEY;
  if (!envKey) return null;
  const username = process.env.HACKERONE_API_USERNAME || envKey.split(":")[0];
  const token = envKey.includes(":") ? envKey.split(":").slice(1).join(":") : envKey;
  if (username && token) return { username, token };
  return null;
}

async function h1Fetch(path: string): Promise<any> {
  // Circuit breaker: skip if HackerOne is known-down (e.g., 401 auth failure)
  const { shouldAllowRequest, recordSuccess, recordFailure, classifyError } = await import('./api-resilience');
  const cbCheck = shouldAllowRequest('hackerone');
  if (!cbCheck.allowed) {
    throw new Error(`[HackerOne] Circuit breaker open: ${cbCheck.reason}`);
  }

  const creds = await getH1Credentials();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (creds) {
    headers.Authorization = "Basic " + Buffer.from(`${creds.username}:${creds.token}`).toString("base64");
  }
  try {
    const res = await fetch(`${H1_BASE}${path}`, { headers, signal: AbortSignal.timeout(20000) });
    if (!res.ok) {
      const err = new Error(`HackerOne API ${res.status}: ${res.statusText}`);
      (err as any).status = res.status;
      recordFailure('hackerone', classifyError(err, 'hackerone'));
      throw err;
    }
    recordSuccess('hackerone');
    return res.json();
  } catch (err: any) {
    if (!err.message?.includes('Circuit breaker')) {
      recordFailure('hackerone', classifyError(err, 'hackerone'));
    }
    throw err;
  }
}

// ─── Types ───

export interface BountyIntelSyncResult {
  trigger: "scheduled" | "manual";
  timestamp: string;
  stages: Array<{
    stage: string;
    status: "ok" | "error" | "skipped";
    count?: number;
    detail?: string;
    durationMs: number;
  }>;
  totalDurationMs: number;
}

// ─── Stage Runner ───

async function runStage(
  stages: BountyIntelSyncResult["stages"],
  name: string,
  fn: () => Promise<{ count?: number; detail?: string }>
) {
  const start = Date.now();
  try {
    const result = await fn();
    const durationMs = Date.now() - start;
    stages.push({ stage: name, status: "ok", count: result.count, detail: result.detail, durationMs });
    console.log(`  [${name}] OK in ${durationMs}ms: ${result.detail || ""}`);
  } catch (err: any) {
    const durationMs = Date.now() - start;
    stages.push({ stage: name, status: "error", detail: err.message, durationMs });
    console.error(`  [${name}] FAILED in ${durationMs}ms: ${err.message}`);
  }
}

// ─── Sync Stages (direct DB access) ───

async function syncHacktivity(): Promise<{ count: number; detail: string }> {
  const db = await getDb();
  const creds = await getH1Credentials();
  if (!creds) return { count: 0, detail: "No H1 credentials configured (set HACKERONE_API_KEY)" };

  const [logResult] = await db.insert(bugBountySyncLogs).values({
    platform: "hackerone", syncType: "hacktivity_auto", status: "running",
  });
  const logId = logResult.insertId;

  let totalSynced = 0, totalUpdated = 0;
  const queries = [
    "severity_rating:critical OR severity_rating:high",
    "severity_rating:medium",
  ];

  for (const query of queries) {
    for (let page = 1; page <= 3; page++) {
      try {
        const path = `/hacktivity?queryString=${encodeURIComponent(query)}&page[number]=${page}&page[size]=25`;
        const data = await h1Fetch(path);
        if (!data?.data?.length) break;

        for (const item of data.data) {
          const attrs = item.attributes || {};
          const reporter = item.relationships?.reporter?.data?.attributes;
          const program = item.relationships?.program?.data?.attributes;
          const aiSummary = item.relationships?.report_generated_content?.data?.attributes?.hacktivity_summary;

          const existing = await db.select().from(bugBountyFindings)
            .where(and(eq(bugBountyFindings.platform, "hackerone"), eq(bugBountyFindings.externalId, String(item.id))))
            .limit(1);

          if (existing.length === 0) {
            await db.insert(bugBountyFindings).values({
              platform: "hackerone",
              externalId: String(item.id),
              title: attrs.title || "Untitled",
              severityRating: attrs.severity_rating || null,
              cveIds: attrs.cve_ids || null,
              cweId: attrs.cwe || null,
              substate: attrs.substate || null,
              reportUrl: attrs.url || null,
              disclosedAt: attrs.disclosed_at ? new Date(attrs.disclosed_at).toISOString().slice(0, 19).replace("T", " ") : null,
              submittedAt: attrs.submitted_at ? new Date(attrs.submitted_at).toISOString().slice(0, 19).replace("T", " ") : null,
              awardedAmount: attrs.total_awarded_amount || null,
              reporterUsername: reporter?.username || null,
              reporterReputation: reporter?.reputation || null,
              programHandle: program?.handle || null,
              programName: program?.name || null,
              assetIdentifier: attrs.asset_identifier || null,
              assetType: attrs.asset_type || null,
              votes: attrs.votes || 0,
              summary: aiSummary || null,
            });
            totalSynced++;
          } else {
            const updates: Record<string, any> = {};
            if (aiSummary && !existing[0].summary) updates.summary = aiSummary;
            if (attrs.votes && attrs.votes > (existing[0].votes || 0)) updates.votes = attrs.votes;
            if (attrs.total_awarded_amount && !existing[0].awardedAmount) updates.awardedAmount = attrs.total_awarded_amount;
            if (Object.keys(updates).length > 0) {
              await db.update(bugBountyFindings).set(updates).where(eq(bugBountyFindings.id, existing[0].id));
              totalUpdated++;
            }
          }
        }
      } catch (err: any) {
        console.warn(`[BountyIntel] Hacktivity page ${page} failed for query "${query}": ${err.message}`);
        break;
      }
    }
  }

  await db.update(bugBountySyncLogs).set({
    status: "completed", itemsSynced: totalSynced, completedAt: new Date(),
  }).where(eq(bugBountySyncLogs.id, Number(logId)));

  return { count: totalSynced, detail: `${totalSynced} synced, ${totalUpdated} updated` };
}

async function syncPrograms(): Promise<{ count: number; detail: string }> {
  const db = await getDb();
  let totalSynced = 0;

  for (let page = 1; page <= 2; page++) {
    try {
      const path = `/programs?page[number]=${page}&page[size]=25`;
      const data = await h1Fetch(path);
      if (!data?.data?.length) break;

      for (const item of data.data) {
        const attrs = item.attributes || {};
        const existing = await db.select().from(bugBountyPrograms)
          .where(and(eq(bugBountyPrograms.platform, "hackerone"), eq(bugBountyPrograms.handle, attrs.handle || String(item.id))))
          .limit(1);

        if (existing.length === 0) {
          await db.insert(bugBountyPrograms).values({
            platform: "hackerone",
            handle: attrs.handle || String(item.id),
            name: attrs.name || attrs.handle || "Unknown",
            url: `https://hackerone.com/${attrs.handle}`,
            logoUrl: attrs.profile_picture || null,
            state: attrs.state || null,
            submissionState: attrs.submission_state || null,
            currency: attrs.currency || "USD",
            lastSyncedAt: new Date(),
          });
          totalSynced++;
        } else {
          await db.update(bugBountyPrograms).set({
            name: attrs.name || existing[0].name,
            state: attrs.state || existing[0].state,
            lastSyncedAt: new Date(),
          }).where(eq(bugBountyPrograms.id, existing[0].id));
          totalSynced++;
        }
      }
    } catch (err: any) {
      console.warn(`[BountyIntel] Programs page ${page} failed: ${err.message}`);
      break;
    }
  }

  return { count: totalSynced, detail: `${totalSynced} programs synced` };
}

async function syncScopesAndWeaknesses(): Promise<{ count: number; detail: string }> {
  const db = await getDb();
  let totalScopes = 0, totalWeaknesses = 0;

  // Get top 5 programs to sync scopes/weaknesses for
  const programs = await db.select({ handle: bugBountyPrograms.handle })
    .from(bugBountyPrograms)
    .where(eq(bugBountyPrograms.platform, "hackerone"))
    .orderBy(desc(bugBountyPrograms.lastSyncedAt))
    .limit(5);

  for (const prog of programs) {
    try {
      // Sync scopes
      for (let page = 1; page <= 3; page++) {
        const path = `/programs/${encodeURIComponent(prog.handle)}/structured_scopes?page[number]=${page}&page[size]=25`;
        const data = await h1Fetch(path);
        if (!data?.data?.length) break;

        for (const item of data.data) {
          const attrs = item.attributes || {};
          const existing = await db.select().from(bugBountyProgramScopes)
            .where(and(
              eq(bugBountyProgramScopes.programHandle, prog.handle),
              eq(bugBountyProgramScopes.assetIdentifier, attrs.asset_identifier || ""),
              eq(bugBountyProgramScopes.assetType, attrs.asset_type || "OTHER")
            )).limit(1);

          if (existing.length === 0) {
            await db.insert(bugBountyProgramScopes).values({
              platform: "hackerone",
              programHandle: prog.handle,
              externalId: String(item.id),
              assetType: attrs.asset_type || "OTHER",
              assetIdentifier: attrs.asset_identifier || "unknown",
              eligibleForBounty: attrs.eligible_for_bounty ? 1 : 0,
              eligibleForSubmission: attrs.eligible_for_submission !== false ? 1 : 0,
              maxSeverity: attrs.max_severity || null,
              confidentialityRequirement: attrs.confidentiality_requirement || null,
              integrityRequirement: attrs.integrity_requirement || null,
              availabilityRequirement: attrs.availability_requirement || null,
              instruction: attrs.instruction || null,
            });
            totalScopes++;
          }
        }
      }

      // Sync weaknesses
      for (let page = 1; page <= 3; page++) {
        const path = `/programs/${encodeURIComponent(prog.handle)}/weaknesses?page[number]=${page}&page[size]=25`;
        const data = await h1Fetch(path);
        if (!data?.data?.length) break;

        for (const item of data.data) {
          const attrs = item.attributes || {};
          const existing = await db.select().from(bugBountyProgramWeaknesses)
            .where(and(
              eq(bugBountyProgramWeaknesses.programHandle, prog.handle),
              eq(bugBountyProgramWeaknesses.name, attrs.name || "")
            )).limit(1);

          if (existing.length === 0) {
            await db.insert(bugBountyProgramWeaknesses).values({
              platform: "hackerone",
              programHandle: prog.handle,
              externalId: String(item.id),
              cweId: attrs.external_id || null,
              name: attrs.name || "Unknown Weakness",
              description: attrs.description || null,
            });
            totalWeaknesses++;
          }
        }
      }
    } catch (err: any) {
      console.warn(`[BountyIntel] Scope/weakness sync failed for ${prog.handle}: ${err.message}`);
    }
  }

  return { count: totalScopes + totalWeaknesses, detail: `${totalScopes} scopes, ${totalWeaknesses} weaknesses` };
}

async function runCorrelationEngine(): Promise<{ count: number; detail: string }> {
  const db = await getDb();

  // Get recent uncorrelated findings
  const findings = await db.select().from(bugBountyFindings)
    .orderBy(desc(bugBountyFindings.createdAt)).limit(200);

  const assets = await db.select().from(discoveredAssets).limit(5000);
  const cveFeeds = await db.select().from(iocFeeds)
    .where(eq(iocFeeds.feedType, "vulnerability")).limit(5000);

  let newCorrelations = 0;

  for (const finding of findings) {
    const cveIds = (finding.cveIds as string[] | null) || [];

    // CVE Match
    for (const cve of cveIds) {
      if (!cve) continue;
      for (const feed of cveFeeds) {
        if (feed.cveId && feed.cveId.toLowerCase() === cve.toLowerCase()) {
          const exists = await db.select().from(bugBountyCorrelations)
            .where(and(
              eq(bugBountyCorrelations.findingId, finding.id),
              eq(bugBountyCorrelations.correlationType, "cve_match"),
              eq(bugBountyCorrelations.matchedEntityId, feed.id)
            )).limit(1);

          if (exists.length === 0) {
            await db.insert(bugBountyCorrelations).values({
              findingId: finding.id,
              correlationType: "cve_match",
              matchedEntityType: "ioc_feed",
              matchedEntityId: feed.id,
              matchedEntityName: feed.cveId || cve,
              confidenceScore: "0.95",
              details: { matchField: "cveId", matchValue: cve, feedTitle: feed.title },
            });
            newCorrelations++;
          }
        }
      }
    }

    // Asset Match
    const assetId = finding.assetIdentifier;
    if (assetId) {
      for (const asset of assets) {
        const hostname = asset.hostname?.toLowerCase() || "";
        const findingAsset = assetId.toLowerCase();
        if (hostname && (hostname === findingAsset || hostname.endsWith("." + findingAsset) || findingAsset.endsWith("." + hostname))) {
          const exists = await db.select().from(bugBountyCorrelations)
            .where(and(
              eq(bugBountyCorrelations.findingId, finding.id),
              eq(bugBountyCorrelations.correlationType, "asset_match"),
              eq(bugBountyCorrelations.matchedEntityId, asset.id)
            )).limit(1);

          if (exists.length === 0) {
            await db.insert(bugBountyCorrelations).values({
              findingId: finding.id,
              correlationType: "asset_match",
              matchedEntityType: "discovered_asset",
              matchedEntityId: asset.id,
              matchedEntityName: asset.hostname,
              confidenceScore: hostname === findingAsset ? "0.98" : "0.75",
              details: { matchField: "hostname", matchValue: findingAsset, assetType: asset.assetType },
            });
            newCorrelations++;
          }
        }
      }
    }

    // CWE Match
    if (finding.cweId) {
      for (const asset of assets) {
        const postureFindings = (asset.postureFindings as Array<{ cwe?: string; title?: string }>) || [];
        for (const pf of postureFindings) {
          if (pf.cwe && pf.cwe === finding.cweId) {
            const exists = await db.select().from(bugBountyCorrelations)
              .where(and(
                eq(bugBountyCorrelations.findingId, finding.id),
                eq(bugBountyCorrelations.correlationType, "cwe_match"),
                eq(bugBountyCorrelations.matchedEntityId, asset.id)
              )).limit(1);

            if (exists.length === 0) {
              await db.insert(bugBountyCorrelations).values({
                findingId: finding.id,
                correlationType: "cwe_match",
                matchedEntityType: "discovered_asset",
                matchedEntityId: asset.id,
                matchedEntityName: `${asset.hostname} - ${pf.title || pf.cwe}`,
                confidenceScore: "0.70",
                details: { matchField: "cwe", matchValue: finding.cweId, postureTitle: pf.title },
              });
              newCorrelations++;
            }
          }
        }
      }
    }
  }

  const [totalCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(bugBountyCorrelations);
  return { count: newCorrelations, detail: `${newCorrelations} new correlations (${totalCount?.count || 0} total)` };
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Run the full bug bounty intelligence pipeline.
 * Each stage is independent — failures in one stage don't block others.
 */
export async function runBountyIntelPipeline(
  trigger: "scheduled" | "manual" = "manual"
): Promise<BountyIntelSyncResult> {
  if (pipelineRunning) {
    console.warn("[BountyIntel] Pipeline already running, skipping");
    return {
      trigger,
      timestamp: new Date().toISOString(),
      stages: [{ stage: "guard", status: "skipped", detail: "Pipeline already running", durationMs: 0 }],
      totalDurationMs: 0,
    };
  }

  pipelineRunning = true;
  const pipelineStart = Date.now();
  const stages: BountyIntelSyncResult["stages"] = [];

  console.log(`[BountyIntel] ═══ Starting ${trigger} pipeline at ${new Date().toISOString()} ═══`);

  try {
    // ── Stage 1: Sync HackerOne Hacktivity ──
    await runStage(stages, "h1_hacktivity", syncHacktivity);

    // ── Stage 2: Sync HackerOne Programs ──
    await runStage(stages, "h1_programs", syncPrograms);

    // ── Stage 3: Sync Scopes & Weaknesses for Top Programs ──
    await runStage(stages, "h1_scopes_weaknesses", syncScopesAndWeaknesses);

    // GC hint between API-heavy and compute-heavy stages
    if (global.gc) global.gc();

    // ── Stage 4: Extract LLM Training from H1 Findings ──
    await runStage(stages, "llm_extract_h1", async () => {
      const { extractFromHackerOneFindings } = await import("./bounty-training-engine");
      const result = await extractFromHackerOneFindings({ minBounty: 0, limit: 50 });
      return { count: result.extracted, detail: `${result.extracted} extracted, ${result.skipped} skipped` };
    });

    // ── Stage 5: Extract LLM Training from Engagement Findings ──
    await runStage(stages, "llm_extract_engagements", async () => {
      const { extractFromEngagementFindings } = await import("./bounty-training-engine");
      const result = await extractFromEngagementFindings({ limit: 50 });
      return {
        count: result.extracted,
        detail: `${result.extracted} extracted — nuclei:${result.sources.nuclei} zap:${result.sources.zap} exploit:${result.sources.exploit} report:${result.sources.report}`,
      };
    });

    // ── Stage 6: Enrich Raw Training Samples ──
    await runStage(stages, "llm_enrich", async () => {
      const { enrichTrainingSamples } = await import("./bounty-training-engine");
      const result = await enrichTrainingSamples({ limit: 10 });
      return { count: result.enriched, detail: `${result.enriched} enriched, ${result.failed} failed` };
    });

    // GC hint before template generation
    if (global.gc) global.gc();

    // ── Stage 7: Generate ScanForge Templates from H1 Findings ──
    await runStage(stages, "scanforge_templates", async () => {
      const { generateScanForgeTemplatesFromFindings } = await import("./bounty-training-engine");
      const result = await generateScanForgeTemplatesFromFindings({ limit: 10 });
      return { count: result.generated, detail: `${result.generated} generated, ${result.skipped} skipped, ${result.failed} failed` };
    });

    // ── Stage 8: Run Cross-Correlation ──
    await runStage(stages, "cross_correlation", runCorrelationEngine);

  } catch (err: any) {
    console.error("[BountyIntel] Fatal pipeline error:", err.message);
    stages.push({ stage: "fatal", status: "error", detail: err.message, durationMs: 0 });
  } finally {
    pipelineRunning = false;
    if (global.gc) global.gc();
  }

  const totalDurationMs = Date.now() - pipelineStart;
  const okCount = stages.filter(s => s.status === "ok").length;
  const errCount = stages.filter(s => s.status === "error").length;
  console.log(`[BountyIntel] ═══ Pipeline complete in ${(totalDurationMs / 1000).toFixed(1)}s: ${okCount} ok, ${errCount} errors ═══`);

  return { trigger, timestamp: new Date().toISOString(), stages, totalDurationMs };
}

// ═══════════════════════════════════════════════════════════════════════════
// SCHEDULER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Initialize the scheduled bug bounty intelligence pipeline.
 * Runs every 6 hours at 04:00, 10:00, 16:00, 22:00 UTC.
 */
export function initBountyIntelSchedule() {
  const task = cron.schedule("0 4,10,16,22 * * *", async () => {
    try {
      await runBountyIntelPipeline("scheduled");
    } catch (err) {
      console.error("[BountyIntel Cron] Scheduled pipeline failed:", err);
    }
  }, {
    timezone: "UTC",
  });

  console.log("[BountyIntel] Scheduled intelligence pipeline every 6h (04:00, 10:00, 16:00, 22:00 UTC)");

  // Deferred initial run — 10 minutes after server start to avoid startup congestion
  // Skips if an engagement is actively running to avoid memory contention
  setTimeout(async () => {
    try {
      // Check if any engagement is actively running (pipelineRunning is module-level)
      if (pipelineRunning) {
        console.log("[BountyIntel] Skipping warm-up — pipeline already running");
        return;
      }
      console.log("[BountyIntel] Running initial intelligence pipeline warm-up...");
      await runBountyIntelPipeline("manual");
    } catch (err) {
      console.warn("[BountyIntel] Initial warm-up failed (non-fatal):", err);
    }
  }, 600_000); // 10 minutes

  return task;
}
