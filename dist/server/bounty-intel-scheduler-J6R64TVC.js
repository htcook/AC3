import {
  getH1CredentialsForUser,
  init_credential_service
} from "./chunk-6IAUAYA7.js";
import {
  getDb,
  init_db
} from "./chunk-YEW6KKPA.js";
import "./chunk-NRYVRXXR.js";
import {
  bugBountyCorrelations,
  bugBountyFindings,
  bugBountyProgramScopes,
  bugBountyProgramWeaknesses,
  bugBountyPrograms,
  bugBountySyncLogs,
  discoveredAssets,
  init_schema,
  iocFeeds
} from "./chunk-EMIPCWBF.js";
import "./chunk-KFQGP6VL.js";

// server/lib/bounty-intel-scheduler.ts
init_db();
init_schema();
init_credential_service();
import cron from "node-cron";
import { eq, desc, and, sql } from "drizzle-orm";
async function getDb2() {
  const db = await getDb();
  return db;
}
var pipelineRunning = false;
var H1_BASE = "https://api.hackerone.com/v1/hackers";
var _schedulerUserId = null;
function setSchedulerUser(userId) {
  _schedulerUserId = userId;
}
async function getH1Credentials() {
  const creds = await getH1CredentialsForUser(_schedulerUserId);
  if (creds) {
    return { username: creds.username, token: creds.apiKey };
  }
  return null;
}
async function h1Fetch(path) {
  const { shouldAllowRequest, recordSuccess, recordFailure, classifyError } = await import("./api-resilience-XNEMY22M.js");
  const cbCheck = shouldAllowRequest("hackerone");
  if (!cbCheck.allowed) {
    throw new Error(`[HackerOne] Circuit breaker open: ${cbCheck.reason}`);
  }
  const creds = await getH1Credentials();
  const headers = { Accept: "application/json" };
  if (creds) {
    headers.Authorization = "Basic " + Buffer.from(`${creds.username}:${creds.token}`).toString("base64");
  }
  try {
    const res = await fetch(`${H1_BASE}${path}`, { headers, signal: AbortSignal.timeout(2e4) });
    if (!res.ok) {
      const err = new Error(`HackerOne API ${res.status}: ${res.statusText}`);
      err.status = res.status;
      recordFailure("hackerone", classifyError(err, "hackerone"));
      throw err;
    }
    recordSuccess("hackerone");
    return res.json();
  } catch (err) {
    if (!err.message?.includes("Circuit breaker")) {
      recordFailure("hackerone", classifyError(err, "hackerone"));
    }
    throw err;
  }
}
async function runStage(stages, name, fn) {
  const start = Date.now();
  try {
    const result = await fn();
    const durationMs = Date.now() - start;
    stages.push({ stage: name, status: "ok", count: result.count, detail: result.detail, durationMs });
    console.log(`  [${name}] OK in ${durationMs}ms: ${result.detail || ""}`);
  } catch (err) {
    const durationMs = Date.now() - start;
    stages.push({ stage: name, status: "error", detail: err.message, durationMs });
    console.error(`  [${name}] FAILED in ${durationMs}ms: ${err.message}`);
  }
}
async function syncHacktivity() {
  const db = await getDb2();
  const creds = await getH1Credentials();
  if (!creds) return { count: 0, detail: "No H1 credentials configured (set HACKERONE_API_KEY)" };
  const [logResult] = await db.insert(bugBountySyncLogs).values({
    platform: "hackerone",
    syncType: "hacktivity_auto",
    status: "running"
  });
  const logId = logResult.insertId;
  let totalSynced = 0, totalUpdated = 0;
  const queries = [
    "severity_rating:critical OR severity_rating:high",
    "severity_rating:medium"
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
          const existing = await db.select().from(bugBountyFindings).where(and(eq(bugBountyFindings.platform, "hackerone"), eq(bugBountyFindings.externalId, String(item.id)))).limit(1);
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
              summary: aiSummary || null
            });
            totalSynced++;
          } else {
            const updates = {};
            if (aiSummary && !existing[0].summary) updates.summary = aiSummary;
            if (attrs.votes && attrs.votes > (existing[0].votes || 0)) updates.votes = attrs.votes;
            if (attrs.total_awarded_amount && !existing[0].awardedAmount) updates.awardedAmount = attrs.total_awarded_amount;
            if (Object.keys(updates).length > 0) {
              await db.update(bugBountyFindings).set(updates).where(eq(bugBountyFindings.id, existing[0].id));
              totalUpdated++;
            }
          }
        }
      } catch (err) {
        console.warn(`[BountyIntel] Hacktivity page ${page} failed for query "${query}": ${err.message}`);
        break;
      }
    }
  }
  await db.update(bugBountySyncLogs).set({
    status: "completed",
    itemsSynced: totalSynced,
    completedAt: /* @__PURE__ */ new Date()
  }).where(eq(bugBountySyncLogs.id, Number(logId)));
  return { count: totalSynced, detail: `${totalSynced} synced, ${totalUpdated} updated` };
}
async function syncPrograms() {
  const db = await getDb2();
  let totalSynced = 0;
  for (let page = 1; page <= 2; page++) {
    try {
      const path = `/programs?page[number]=${page}&page[size]=25`;
      const data = await h1Fetch(path);
      if (!data?.data?.length) break;
      for (const item of data.data) {
        const attrs = item.attributes || {};
        const existing = await db.select().from(bugBountyPrograms).where(and(eq(bugBountyPrograms.platform, "hackerone"), eq(bugBountyPrograms.handle, attrs.handle || String(item.id)))).limit(1);
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
            lastSyncedAt: /* @__PURE__ */ new Date()
          });
          totalSynced++;
        } else {
          await db.update(bugBountyPrograms).set({
            name: attrs.name || existing[0].name,
            state: attrs.state || existing[0].state,
            lastSyncedAt: /* @__PURE__ */ new Date()
          }).where(eq(bugBountyPrograms.id, existing[0].id));
          totalSynced++;
        }
      }
    } catch (err) {
      console.warn(`[BountyIntel] Programs page ${page} failed: ${err.message}`);
      break;
    }
  }
  return { count: totalSynced, detail: `${totalSynced} programs synced` };
}
async function ensureNextcloudProgramData() {
  const db = await getDb2();
  const { NEXTCLOUD_BOUNTY_POLICY, BOUNTY_ELIGIBLE_APPS, NEXTCLOUD_VERSIONS } = await import("./nextcloud-test-lab-6KMQNIPZ.js");
  const existing = await db.select().from(bugBountyPrograms).where(and(eq(bugBountyPrograms.platform, "hackerone"), eq(bugBountyPrograms.handle, "nextcloud"))).limit(1);
  const scopeAssets = BOUNTY_ELIGIBLE_APPS.map((app) => ({
    type: "SOURCE_CODE",
    identifier: `https://github.com/${app.repo}`,
    name: app.name,
    tier: app.tier,
    description: app.description,
    eligibleForBounty: true
  }));
  for (const [key, cat] of Object.entries(NEXTCLOUD_BOUNTY_POLICY.scopeCategories)) {
    scopeAssets.push({
      type: key === "server" ? "SOURCE_CODE" : "OTHER",
      identifier: key,
      name: cat.description,
      tier: key === "server" ? 0 : 10,
      description: `${cat.description} \u2014 ${cat.eligibleVersions}`,
      eligibleForBounty: true
    });
  }
  const programData = {
    platform: "hackerone",
    handle: NEXTCLOUD_BOUNTY_POLICY.handle,
    name: NEXTCLOUD_BOUNTY_POLICY.name,
    url: NEXTCLOUD_BOUNTY_POLICY.url,
    policyUrl: NEXTCLOUD_BOUNTY_POLICY.policyUrl,
    state: "open",
    submissionState: "open",
    currency: NEXTCLOUD_BOUNTY_POLICY.currency,
    minBounty: Math.min(...NEXTCLOUD_BOUNTY_POLICY.rewards.map((r) => r.maxReward)),
    maxBounty: Math.max(...NEXTCLOUD_BOUNTY_POLICY.rewards.map((r) => r.maxReward)),
    scopeAssets: JSON.stringify({
      assets: scopeAssets,
      rewardTiers: NEXTCLOUD_BOUNTY_POLICY.rewards,
      submissionRules: NEXTCLOUD_BOUNTY_POLICY.submissionRules,
      exclusions: NEXTCLOUD_BOUNTY_POLICY.exclusions,
      penalties: NEXTCLOUD_BOUNTY_POLICY.penalties,
      validBugCriteria: NEXTCLOUD_BOUNTY_POLICY.validBugCriteria,
      disclosurePolicy: NEXTCLOUD_BOUNTY_POLICY.disclosurePolicy,
      eligibleVersions: NEXTCLOUD_VERSIONS.supported,
      versionScheduleUrl: NEXTCLOUD_BOUNTY_POLICY.versionSchedule
    }),
    lastSyncedAt: /* @__PURE__ */ new Date()
  };
  if (existing.length === 0) {
    await db.insert(bugBountyPrograms).values(programData);
    return { count: 1, detail: "Nextcloud program created with full bounty policy" };
  } else {
    await db.update(bugBountyPrograms).set({
      ...programData
    }).where(eq(bugBountyPrograms.id, existing[0].id));
    return { count: 1, detail: "Nextcloud program updated with full bounty policy" };
  }
}
async function syncScopesAndWeaknesses() {
  const db = await getDb2();
  let totalScopes = 0, totalWeaknesses = 0;
  const programs = await db.select({ handle: bugBountyPrograms.handle }).from(bugBountyPrograms).where(eq(bugBountyPrograms.platform, "hackerone")).orderBy(desc(bugBountyPrograms.lastSyncedAt)).limit(5);
  for (const prog of programs) {
    try {
      for (let page = 1; page <= 3; page++) {
        const path = `/programs/${encodeURIComponent(prog.handle)}/structured_scopes?page[number]=${page}&page[size]=25`;
        const data = await h1Fetch(path);
        if (!data?.data?.length) break;
        for (const item of data.data) {
          const attrs = item.attributes || {};
          const existing = await db.select().from(bugBountyProgramScopes).where(and(
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
              instruction: attrs.instruction || null
            });
            totalScopes++;
          }
        }
      }
      for (let page = 1; page <= 3; page++) {
        const path = `/programs/${encodeURIComponent(prog.handle)}/weaknesses?page[number]=${page}&page[size]=25`;
        const data = await h1Fetch(path);
        if (!data?.data?.length) break;
        for (const item of data.data) {
          const attrs = item.attributes || {};
          const existing = await db.select().from(bugBountyProgramWeaknesses).where(and(
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
              description: attrs.description || null
            });
            totalWeaknesses++;
          }
        }
      }
    } catch (err) {
      console.warn(`[BountyIntel] Scope/weakness sync failed for ${prog.handle}: ${err.message}`);
    }
  }
  return { count: totalScopes + totalWeaknesses, detail: `${totalScopes} scopes, ${totalWeaknesses} weaknesses` };
}
async function runCorrelationEngine() {
  const db = await getDb2();
  const findings = await db.select().from(bugBountyFindings).orderBy(desc(bugBountyFindings.createdAt)).limit(200);
  const assets = await db.select().from(discoveredAssets).limit(5e3);
  const cveFeeds = await db.select().from(iocFeeds).where(eq(iocFeeds.feedType, "vulnerability")).limit(5e3);
  let newCorrelations = 0;
  for (const finding of findings) {
    const cveIds = finding.cveIds || [];
    for (const cve of cveIds) {
      if (!cve) continue;
      for (const feed of cveFeeds) {
        if (feed.cveId && feed.cveId.toLowerCase() === cve.toLowerCase()) {
          const exists = await db.select().from(bugBountyCorrelations).where(and(
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
              details: { matchField: "cveId", matchValue: cve, feedTitle: feed.title }
            });
            newCorrelations++;
          }
        }
      }
    }
    const assetId = finding.assetIdentifier;
    if (assetId) {
      for (const asset of assets) {
        const hostname = asset.hostname?.toLowerCase() || "";
        const findingAsset = assetId.toLowerCase();
        if (hostname && (hostname === findingAsset || hostname.endsWith("." + findingAsset) || findingAsset.endsWith("." + hostname))) {
          const exists = await db.select().from(bugBountyCorrelations).where(and(
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
              details: { matchField: "hostname", matchValue: findingAsset, assetType: asset.assetType }
            });
            newCorrelations++;
          }
        }
      }
    }
    if (finding.cweId) {
      for (const asset of assets) {
        const postureFindings = asset.postureFindings || [];
        for (const pf of postureFindings) {
          if (pf.cwe && pf.cwe === finding.cweId) {
            const exists = await db.select().from(bugBountyCorrelations).where(and(
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
                details: { matchField: "cwe", matchValue: finding.cweId, postureTitle: pf.title }
              });
              newCorrelations++;
            }
          }
        }
      }
    }
  }
  const [totalCount] = await db.select({ count: sql`COUNT(*)` }).from(bugBountyCorrelations);
  return { count: newCorrelations, detail: `${newCorrelations} new correlations (${totalCount?.count || 0} total)` };
}
async function runBountyIntelPipeline(trigger = "manual") {
  if (pipelineRunning) {
    console.warn("[BountyIntel] Pipeline already running, skipping");
    return {
      trigger,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      stages: [{ stage: "guard", status: "skipped", detail: "Pipeline already running", durationMs: 0 }],
      totalDurationMs: 0
    };
  }
  pipelineRunning = true;
  const pipelineStart = Date.now();
  const stages = [];
  console.log(`[BountyIntel] \u2550\u2550\u2550 Starting ${trigger} pipeline at ${(/* @__PURE__ */ new Date()).toISOString()} \u2550\u2550\u2550`);
  try {
    await runStage(stages, "h1_hacktivity", syncHacktivity);
    await runStage(stages, "h1_programs", syncPrograms);
    await runStage(stages, "nc_program_enrich", ensureNextcloudProgramData);
    await runStage(stages, "h1_scopes_weaknesses", syncScopesAndWeaknesses);
    if (global.gc) global.gc();
    await runStage(stages, "llm_extract_h1", async () => {
      const { extractFromHackerOneFindings } = await import("./bounty-training-engine-KEPZZOZT.js");
      const result = await extractFromHackerOneFindings({ minBounty: 0, limit: 50 });
      return { count: result.extracted, detail: `${result.extracted} extracted, ${result.skipped} skipped` };
    });
    await runStage(stages, "llm_extract_engagements", async () => {
      const { extractFromEngagementFindings } = await import("./bounty-training-engine-KEPZZOZT.js");
      const result = await extractFromEngagementFindings({ limit: 50 });
      return {
        count: result.extracted,
        detail: `${result.extracted} extracted \u2014 nuclei:${result.sources.nuclei} zap:${result.sources.zap} exploit:${result.sources.exploit} report:${result.sources.report}`
      };
    });
    await runStage(stages, "llm_enrich", async () => {
      const { enrichTrainingSamples } = await import("./bounty-training-engine-KEPZZOZT.js");
      const result = await enrichTrainingSamples({ limit: 10 });
      return { count: result.enriched, detail: `${result.enriched} enriched, ${result.failed} failed` };
    });
    if (global.gc) global.gc();
    await runStage(stages, "scanforge_templates", async () => {
      const { generateScanForgeTemplatesFromFindings } = await import("./bounty-training-engine-KEPZZOZT.js");
      const result = await generateScanForgeTemplatesFromFindings({ limit: 10 });
      return { count: result.generated, detail: `${result.generated} generated, ${result.skipped} skipped, ${result.failed} failed` };
    });
    await runStage(stages, "cross_correlation", runCorrelationEngine);
  } catch (err) {
    console.error("[BountyIntel] Fatal pipeline error:", err.message);
    stages.push({ stage: "fatal", status: "error", detail: err.message, durationMs: 0 });
  } finally {
    pipelineRunning = false;
    if (global.gc) global.gc();
  }
  const totalDurationMs = Date.now() - pipelineStart;
  const okCount = stages.filter((s) => s.status === "ok").length;
  const errCount = stages.filter((s) => s.status === "error").length;
  console.log(`[BountyIntel] \u2550\u2550\u2550 Pipeline complete in ${(totalDurationMs / 1e3).toFixed(1)}s: ${okCount} ok, ${errCount} errors \u2550\u2550\u2550`);
  return { trigger, timestamp: (/* @__PURE__ */ new Date()).toISOString(), stages, totalDurationMs };
}
function initBountyIntelSchedule() {
  const task = cron.schedule("0 4,10,16,22 * * *", async () => {
    try {
      await runBountyIntelPipeline("scheduled");
    } catch (err) {
      console.error("[BountyIntel Cron] Scheduled pipeline failed:", err);
    }
  }, {
    timezone: "UTC"
  });
  console.log("[BountyIntel] Scheduled intelligence pipeline every 6h (04:00, 10:00, 16:00, 22:00 UTC)");
  setTimeout(async () => {
    try {
      if (pipelineRunning) {
        console.log("[BountyIntel] Skipping warm-up \u2014 pipeline already running");
        return;
      }
      console.log("[BountyIntel] Running initial intelligence pipeline warm-up...");
      await runBountyIntelPipeline("manual");
    } catch (err) {
      console.warn("[BountyIntel] Initial warm-up failed (non-fatal):", err);
    }
  }, 6e5);
  return task;
}
export {
  initBountyIntelSchedule,
  runBountyIntelPipeline,
  setSchedulerUser
};
