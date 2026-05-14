import {
  bulkCreateDiscoveredAssets,
  createDiscoveredAsset,
  deleteDiscoveredAssetsByScan,
  getDomainIntelScanById,
  getDomainIntelScans,
  init_db,
  updateDomainIntelScan
} from "./chunk-26A2QP6T.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-NWJ2JNWL.js";
import "./chunk-KFQGP6VL.js";

// server/lib/scan-recovery.ts
init_db();
import cron from "node-cron";
var STUCK_THRESHOLD_MS = 15 * 60 * 1e3;
var MAX_AUTO_RETRIES = 3;
var CRON_SCHEDULE = "*/5 * * * *";
var IN_PROGRESS_STATUSES = [
  "pending",
  "passive_recon",
  "discovering",
  "analyzing",
  "scoring",
  "recommending"
];
var _cronTask = null;
var _isRunning = false;
var _lastCheckAt = null;
var _totalRecoveries = 0;
var _totalFailures = 0;
var _retryCountMap = /* @__PURE__ */ new Map();
async function findStuckScans() {
  const allScans = await getDomainIntelScans();
  const now = Date.now();
  return allScans.filter((scan) => {
    if (!IN_PROGRESS_STATUSES.includes(scan.status)) return false;
    if (!scan.updatedAt) return false;
    const elapsed = now - new Date(scan.updatedAt).getTime();
    return elapsed > STUCK_THRESHOLD_MS;
  }).map((scan) => ({
    id: scan.id,
    primaryDomain: scan.primaryDomain,
    status: scan.status,
    updatedAt: new Date(scan.updatedAt),
    stuckDurationMs: now - new Date(scan.updatedAt).getTime(),
    retryCount: _retryCountMap.get(scan.id) || 0
  }));
}
async function recoverScan(scanId) {
  const currentRetries = _retryCountMap.get(scanId) || 0;
  if (currentRetries >= MAX_AUTO_RETRIES) {
    await updateDomainIntelScan(scanId, {
      status: "failed",
      pipelineOutput: {
        error: `Auto-recovery exhausted after ${MAX_AUTO_RETRIES} attempts`,
        failedAt: (/* @__PURE__ */ new Date()).toISOString(),
        autoRecoveryExhausted: true,
        totalAutoRetries: currentRetries
      }
    });
    _totalFailures++;
    console.warn(
      `[ScanRecovery] Scan ${scanId} exceeded max auto-retries (${MAX_AUTO_RETRIES}). Marked as failed.`
    );
    return {
      recovered: false,
      reason: `Max auto-retries (${MAX_AUTO_RETRIES}) exceeded \u2014 marked as failed`,
      retryCount: currentRetries
    };
  }
  const newRetryCount = currentRetries + 1;
  _retryCountMap.set(scanId, newRetryCount);
  const scan = await getDomainIntelScanById(scanId);
  if (!scan) {
    return { recovered: false, reason: "Scan not found", retryCount: newRetryCount };
  }
  try {
    await deleteDiscoveredAssetsByScan(scanId);
  } catch {
  }
  await updateDomainIntelScan(scanId, {
    status: "discovering",
    totalAssets: 0,
    totalFindings: 0,
    overallRiskScore: null,
    overallRiskBand: null,
    executiveSummary: null,
    threatModelSummary: null,
    campaignRecommendations: null,
    pipelineOutput: null
  });
  const orgProfile = scan.orgProfile;
  setImmediate(async () => {
    try {
      console.log(
        `[ScanRecovery] Auto-retrying scan ${scanId} (${scan.primaryDomain}), attempt ${newRetryCount}/${MAX_AUTO_RETRIES}`
      );
      const { runDomainIntelPipeline } = await import("./domainIntel-GFFSL3GW.js");
      const result = await runDomainIntelPipeline(
        {
          customerName: orgProfile?.customerName || scan.primaryDomain,
          primaryDomain: scan.primaryDomain,
          additionalDomains: scan.additionalDomains || [],
          sector: scan.sector || "Technology",
          clientType: scan.clientType,
          criticalFunctions: scan.criticalFunctions || [],
          complianceFlags: scan.complianceFlags || [],
          notes: scan.notes || void 0
        },
        async (stage) => {
          await updateDomainIntelScan(scanId, { status: stage }).catch(() => {
          });
        },
        { scanMode: "standard", skipEngagement: true }
      );
      const assetRecords = result.assets.map((a) => ({
        scanId,
        assetId: a.asset.assetId,
        hostname: a.asset.hostname,
        url: a.asset.url || null,
        assetType: a.asset.assetType,
        dnsRecords: a.asset.dnsRecords || null,
        dnsStatus: a.asset.dnsStatus || null,
        headers: a.asset.headers || null,
        technologies: a.asset.technologies || null,
        assetClasses: a.asset.assetClasses,
        tags: a.asset.tags,
        carverScores: a.carverScores,
        shockScores: a.shockScores,
        missionImpactScore: Math.round(a.missionImpactScore * 10),
        suggestedTier: a.suggestedTier,
        hybridRiskScore: a.hybridRiskScore,
        riskBand: a.riskBand,
        cvssEstimate: Math.round(a.cvssEstimate * 10),
        contextIndicators: a.contextIndicators,
        postureFindings: a.postureFindings,
        testVectors: a.testVectors,
        recommendedCalderaAbilities: a.testVectors.filter((v) => v.suggestedEmulation?.calderaAbilityHint).map((v) => v.suggestedEmulation),
        recommendedGophishTemplates: null,
        recommendedAttackChain: null,
        confidence: a.confidence,
        confidenceExplanation: a.contextIndicators,
        impactScore: a.impactScore || 0,
        likelihoodScore: a.likelihoodScore || 0,
        assetCriticalityScore: a.assetCriticalityScore || 0,
        assetCriticalityBand: a.assetCriticalityBand || "low",
        vulnRiskScore: a.vulnRiskScore || 0,
        vulnRiskBand: a.vulnRiskBand || "low"
      }));
      if (assetRecords.length > 0) {
        const BATCH_SIZE = 5;
        for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
          const batch = assetRecords.slice(i, i + BATCH_SIZE);
          try {
            await bulkCreateDiscoveredAssets(batch);
          } catch (batchErr) {
            console.warn(
              `[ScanRecovery] Batch insert failed, falling back to individual: ${batchErr.message}`
            );
            for (const record of batch) {
              try {
                await createDiscoveredAsset(record);
              } catch (e) {
                console.error(
                  `[ScanRecovery] Failed to insert asset ${record.hostname}: ${e.message}`
                );
              }
            }
          }
        }
      }
      const trimmedOutput = {
        orgProfile: result.orgProfile,
        overallRiskScore: result.overallRiskScore,
        overallRiskBand: result.overallRiskBand,
        totalAssets: result.totalAssets,
        totalFindings: result.totalFindings,
        executiveSummary: result.executiveSummary,
        threatModelSummary: result.threatModelSummary,
        kevEnrichment: result.kevEnrichment ? {
          riskBoost: result.kevEnrichment.riskBoost,
          ransomwareExposure: result.kevEnrichment.ransomwareExposure,
          criticalKevCount: result.kevEnrichment.criticalKevCount,
          summary: result.kevEnrichment.summary,
          chainSteps: result.kevEnrichment.chainSteps,
          matchCount: result.kevEnrichment.matches.length,
          matches: result.kevEnrichment.matches.slice(0, 50)
        } : void 0,
        breachData: result.breachData,
        exploitMatches: result.exploitMatches ? {
          totalMetasploit: result.exploitMatches.totalMetasploit,
          totalExploitDb: result.exploitMatches.totalExploitDb,
          totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
          remoteAccessCount: result.exploitMatches.remoteAccessCount,
          matchCount: result.exploitMatches.matches.length,
          matches: result.exploitMatches.matches.slice(0, 30)
        } : void 0,
        passiveRecon: result.passiveRecon ? {
          summary: result.passiveRecon.summary,
          riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
          connectorResults: result.passiveRecon.connectorResults?.map((cr) => ({
            connector: cr.connector,
            observationCount: cr.observations.length,
            durationMs: cr.durationMs,
            errors: cr.errors
          }))
        } : void 0,
        autoRecovered: true,
        autoRetryAttempt: newRetryCount,
        recoveredAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      await updateDomainIntelScan(scanId, {
        status: "scan_complete",
        totalAssets: result.totalAssets,
        totalFindings: result.totalFindings,
        overallRiskScore: result.overallRiskScore,
        overallRiskBand: result.overallRiskBand,
        executiveSummary: result.executiveSummary,
        threatModelSummary: result.threatModelSummary,
        campaignRecommendations: [],
        pipelineOutput: trimmedOutput
      });
      _totalRecoveries++;
      _retryCountMap.delete(scanId);
      console.log(
        `[ScanRecovery] Auto-recovery succeeded for scan ${scanId} (${scan.primaryDomain}): ${result.totalAssets} assets, risk=${result.overallRiskScore}`
      );
      try {
        const { emitReconComplete } = await import("./ws-event-hub-GYTLNKYI.js");
        emitReconComplete({
          scanId,
          domain: scan.primaryDomain,
          findings: result.totalFindings || 0,
          engagementId: scan.engagementId || void 0
        });
      } catch {
      }
    } catch (err) {
      console.error(
        `[ScanRecovery] Auto-recovery failed for scan ${scanId} (attempt ${newRetryCount}/${MAX_AUTO_RETRIES}):`,
        err.message
      );
      if (newRetryCount >= MAX_AUTO_RETRIES) {
        await updateDomainIntelScan(scanId, {
          status: "failed",
          pipelineOutput: {
            error: err.message,
            stack: err.stack?.substring(0, 1e3),
            failedAt: (/* @__PURE__ */ new Date()).toISOString(),
            autoRecoveryExhausted: true,
            totalAutoRetries: newRetryCount
          }
        }).catch(() => {
        });
        _totalFailures++;
      } else {
        await updateDomainIntelScan(scanId, {
          status: "passive_recon",
          pipelineOutput: {
            error: err.message,
            lastAutoRetryAt: (/* @__PURE__ */ new Date()).toISOString(),
            autoRetryAttempt: newRetryCount,
            maxRetries: MAX_AUTO_RETRIES
          }
        }).catch(() => {
        });
      }
    }
  });
  return {
    recovered: true,
    reason: `Auto-retry initiated (attempt ${newRetryCount}/${MAX_AUTO_RETRIES})`,
    retryCount: newRetryCount
  };
}
async function runRecoveryCheck() {
  if (_isRunning) {
    console.log("[ScanRecovery] Recovery check already in progress, skipping");
    return { checked: false, stuckScans: 0, recovered: 0, exhausted: 0, skipped: 0 };
  }
  _isRunning = true;
  _lastCheckAt = /* @__PURE__ */ new Date();
  try {
    const stuckScans = await findStuckScans();
    if (stuckScans.length === 0) {
      return { checked: true, stuckScans: 0, recovered: 0, exhausted: 0, skipped: 0 };
    }
    console.log(
      `[ScanRecovery] Found ${stuckScans.length} stuck scan(s): ${stuckScans.map((s) => `${s.primaryDomain} (id=${s.id}, stuck ${Math.round(s.stuckDurationMs / 6e4)}min, retries=${s.retryCount})`).join(", ")}`
    );
    let recovered = 0;
    let exhausted = 0;
    let skipped = 0;
    for (const scan of stuckScans) {
      try {
        const result = await recoverScan(scan.id);
        if (result.recovered) {
          recovered++;
        } else {
          exhausted++;
        }
      } catch (err) {
        console.error(`[ScanRecovery] Error recovering scan ${scan.id}:`, err.message);
        skipped++;
      }
      if (recovered >= 1) {
        skipped += stuckScans.length - recovered - exhausted - skipped;
        console.log(
          `[ScanRecovery] Rate-limiting: recovering 1 scan per cycle. ${skipped} remaining stuck scans will be retried in the next cycle.`
        );
        break;
      }
    }
    return { checked: true, stuckScans: stuckScans.length, recovered, exhausted, skipped };
  } catch (err) {
    console.error("[ScanRecovery] Recovery check failed:", err.message);
    return { checked: false, stuckScans: 0, recovered: 0, exhausted: 0, skipped: 0 };
  } finally {
    _isRunning = false;
  }
}
function initScanRecoverySchedule() {
  if (_cronTask) {
    console.log("[ScanRecovery] Scheduler already active");
    return;
  }
  _cronTask = cron.schedule(CRON_SCHEDULE, async () => {
    const result = await runRecoveryCheck();
    if (result.stuckScans > 0) {
      console.log(
        `[ScanRecovery] Check complete: ${result.stuckScans} stuck, ${result.recovered} recovered, ${result.exhausted} exhausted, ${result.skipped} deferred`
      );
    }
  });
  console.log("[ScanRecovery] Cron job active \u2014 checking for stuck scans every 5 minutes");
}
function stopScanRecoverySchedule() {
  if (_cronTask) {
    _cronTask.stop();
    _cronTask = null;
    console.log("[ScanRecovery] Cron job stopped");
  }
}
function getScanRecoveryStatus() {
  return {
    active: _cronTask !== null,
    lastCheckAt: _lastCheckAt?.toISOString() || null,
    isRunning: _isRunning,
    totalRecoveries: _totalRecoveries,
    totalFailures: _totalFailures,
    trackedScans: _retryCountMap.size,
    retryCountMap: Object.fromEntries(_retryCountMap),
    config: {
      stuckThresholdMinutes: STUCK_THRESHOLD_MS / 6e4,
      maxAutoRetries: MAX_AUTO_RETRIES,
      cronSchedule: CRON_SCHEDULE
    }
  };
}
var _testHelpers = {
  STUCK_THRESHOLD_MS,
  MAX_AUTO_RETRIES,
  IN_PROGRESS_STATUSES,
  getRetryCount: (scanId) => _retryCountMap.get(scanId) || 0,
  setRetryCount: (scanId, count) => _retryCountMap.set(scanId, count),
  clearRetryMap: () => _retryCountMap.clear()
};
export {
  _testHelpers,
  findStuckScans,
  getScanRecoveryStatus,
  initScanRecoverySchedule,
  recoverScan,
  runRecoveryCheck,
  stopScanRecoverySchedule
};
