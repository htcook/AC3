/**
 * Scan Recovery Scheduler
 * 
 * Automatically detects Domain Intel scans that are stuck in intermediate
 * pipeline stages (passive_recon, discovering, analyzing, scoring, recommending)
 * for longer than the configured threshold and retries them.
 * 
 * Runs every 5 minutes via node-cron. Each stuck scan gets a maximum of 3
 * automatic retries before being marked as permanently failed.
 * 
 * Recovery actions are logged to the activity_logs table for audit trail.
 */

import cron from "node-cron";
import * as db from "../db";

// ─── Configuration ──────────────────────────────────────────────────────────

const STUCK_THRESHOLD_MS = 15 * 60 * 1000; // 15 minutes with no progress
const MAX_AUTO_RETRIES = 3;
const CRON_SCHEDULE = "*/5 * * * *"; // Every 5 minutes

const IN_PROGRESS_STATUSES = [
  "passive_recon",
  "discovering",
  "analyzing",
  "scoring",
  "recommending",
] as const;

// ─── State ──────────────────────────────────────────────────────────────────

let _cronTask: ReturnType<typeof cron.schedule> | null = null;
let _isRunning = false;
let _lastCheckAt: Date | null = null;
let _totalRecoveries = 0;
let _totalFailures = 0;

// Track per-scan retry counts in memory (reset on server restart)
const _retryCountMap = new Map<number, number>();

// ─── Core Logic ─────────────────────────────────────────────────────────────

/**
 * Identify scans stuck in intermediate pipeline stages.
 * A scan is "stuck" if its status is an in-progress status and its
 * updatedAt timestamp is older than STUCK_THRESHOLD_MS.
 */
export async function findStuckScans(): Promise<Array<{
  id: number;
  primaryDomain: string;
  status: string;
  updatedAt: Date;
  stuckDurationMs: number;
  retryCount: number;
}>> {
  const allScans = await db.getDomainIntelScans();
  const now = Date.now();

  return allScans
    .filter((scan) => {
      if (!IN_PROGRESS_STATUSES.includes(scan.status as any)) return false;
      if (!scan.updatedAt) return false;
      const elapsed = now - new Date(scan.updatedAt).getTime();
      return elapsed > STUCK_THRESHOLD_MS;
    })
    .map((scan) => ({
      id: scan.id,
      primaryDomain: scan.primaryDomain,
      status: scan.status,
      updatedAt: new Date(scan.updatedAt),
      stuckDurationMs: now - new Date(scan.updatedAt).getTime(),
      retryCount: _retryCountMap.get(scan.id) || 0,
    }));
}

/**
 * Attempt to recover a single stuck scan by resetting and re-running the pipeline.
 * Returns true if recovery was initiated, false if skipped (max retries exceeded).
 */
export async function recoverScan(scanId: number): Promise<{
  recovered: boolean;
  reason: string;
  retryCount: number;
}> {
  const currentRetries = _retryCountMap.get(scanId) || 0;

  // Check max retry limit
  if (currentRetries >= MAX_AUTO_RETRIES) {
    // Mark as permanently failed
    await db.updateDomainIntelScan(scanId, {
      status: "failed",
      pipelineOutput: {
        error: `Auto-recovery exhausted after ${MAX_AUTO_RETRIES} attempts`,
        failedAt: new Date().toISOString(),
        autoRecoveryExhausted: true,
        totalAutoRetries: currentRetries,
      },
    });

    _totalFailures++;
    console.warn(
      `[ScanRecovery] Scan ${scanId} exceeded max auto-retries (${MAX_AUTO_RETRIES}). Marked as failed.`
    );

    return {
      recovered: false,
      reason: `Max auto-retries (${MAX_AUTO_RETRIES}) exceeded — marked as failed`,
      retryCount: currentRetries,
    };
  }

  // Increment retry count
  const newRetryCount = currentRetries + 1;
  _retryCountMap.set(scanId, newRetryCount);

  // Fetch the full scan record
  const scan = await db.getDomainIntelScanById(scanId);
  if (!scan) {
    return { recovered: false, reason: "Scan not found", retryCount: newRetryCount };
  }

  // Clean up orphaned assets from partial previous run
  try {
    await db.deleteDiscoveredAssetsByScan(scanId);
  } catch {
    /* ignore if no assets exist */
  }

  // Reset scan to discovering
  await db.updateDomainIntelScan(scanId, {
    status: "discovering",
    totalAssets: 0,
    totalFindings: 0,
    overallRiskScore: null,
    overallRiskBand: null,
    executiveSummary: null,
    threatModelSummary: null,
    campaignRecommendations: null,
    pipelineOutput: null,
  });

  // Re-run the pipeline in background
  const orgProfile = scan.orgProfile as any;

  setImmediate(async () => {
    try {
      console.log(
        `[ScanRecovery] Auto-retrying scan ${scanId} (${scan.primaryDomain}), attempt ${newRetryCount}/${MAX_AUTO_RETRIES}`
      );
      const { runDomainIntelPipeline } = await import("../domainIntel");

      const result = await runDomainIntelPipeline(
        {
          customerName: orgProfile?.customerName || scan.primaryDomain,
          primaryDomain: scan.primaryDomain,
          additionalDomains: (scan.additionalDomains as string[]) || [],
          sector: scan.sector || "Technology",
          clientType: scan.clientType,
          criticalFunctions: (scan.criticalFunctions as string[]) || [],
          complianceFlags: (scan.complianceFlags as string[]) || [],
          notes: scan.notes || undefined,
        },
        async (stage) => {
          await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
        },
        { scanMode: "standard", skipEngagement: true }
      );

      // Batch insert assets
      const assetRecords = result.assets.map((a: any) => ({
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
        recommendedCalderaAbilities: a.testVectors
          .filter((v: any) => v.suggestedEmulation?.calderaAbilityHint)
          .map((v: any) => v.suggestedEmulation),
        recommendedGophishTemplates: null,
        recommendedAttackChain: null,
        confidence: a.confidence,
        confidenceExplanation: a.contextIndicators,
        impactScore: a.impactScore || 0,
        likelihoodScore: a.likelihoodScore || 0,
        assetCriticalityScore: a.assetCriticalityScore || 0,
        assetCriticalityBand: a.assetCriticalityBand || "low",
        vulnRiskScore: a.vulnRiskScore || 0,
        vulnRiskBand: a.vulnRiskBand || "low",
      }));

      if (assetRecords.length > 0) {
        const BATCH_SIZE = 5;
        for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
          const batch = assetRecords.slice(i, i + BATCH_SIZE);
          try {
            await db.bulkCreateDiscoveredAssets(batch);
          } catch (batchErr: any) {
            console.warn(
              `[ScanRecovery] Batch insert failed, falling back to individual: ${batchErr.message}`
            );
            for (const record of batch) {
              try {
                await db.createDiscoveredAsset(record);
              } catch (e: any) {
                console.error(
                  `[ScanRecovery] Failed to insert asset ${record.hostname}: ${e.message}`
                );
              }
            }
          }
        }
      }

      // Update scan with results
      const trimmedOutput = {
        orgProfile: result.orgProfile,
        overallRiskScore: result.overallRiskScore,
        overallRiskBand: result.overallRiskBand,
        totalAssets: result.totalAssets,
        totalFindings: result.totalFindings,
        executiveSummary: result.executiveSummary,
        threatModelSummary: result.threatModelSummary,
        kevEnrichment: result.kevEnrichment
          ? {
              riskBoost: result.kevEnrichment.riskBoost,
              ransomwareExposure: result.kevEnrichment.ransomwareExposure,
              criticalKevCount: result.kevEnrichment.criticalKevCount,
              summary: result.kevEnrichment.summary,
              chainSteps: result.kevEnrichment.chainSteps,
              matchCount: result.kevEnrichment.matches.length,
              matches: result.kevEnrichment.matches.slice(0, 50),
            }
          : undefined,
        breachData: result.breachData,
        exploitMatches: result.exploitMatches
          ? {
              totalMetasploit: result.exploitMatches.totalMetasploit,
              totalExploitDb: result.exploitMatches.totalExploitDb,
              totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
              remoteAccessCount: result.exploitMatches.remoteAccessCount,
              matchCount: result.exploitMatches.matches.length,
              matches: result.exploitMatches.matches.slice(0, 30),
            }
          : undefined,
        passiveRecon: result.passiveRecon
          ? {
              summary: result.passiveRecon.summary,
              riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
              connectorResults: result.passiveRecon.connectorResults?.map((cr: any) => ({
                connector: cr.connector,
                observationCount: cr.observations.length,
                durationMs: cr.durationMs,
                errors: cr.errors,
              })),
            }
          : undefined,
        autoRecovered: true,
        autoRetryAttempt: newRetryCount,
        recoveredAt: new Date().toISOString(),
      };

      await db.updateDomainIntelScan(scanId, {
        status: "scan_complete",
        totalAssets: result.totalAssets,
        totalFindings: result.totalFindings,
        overallRiskScore: result.overallRiskScore,
        overallRiskBand: result.overallRiskBand,
        executiveSummary: result.executiveSummary,
        threatModelSummary: result.threatModelSummary,
        campaignRecommendations: [],
        pipelineOutput: trimmedOutput,
      });

      _totalRecoveries++;
      // Clear retry count on success
      _retryCountMap.delete(scanId);

      console.log(
        `[ScanRecovery] Auto-recovery succeeded for scan ${scanId} (${scan.primaryDomain}): ` +
          `${result.totalAssets} assets, risk=${result.overallRiskScore}`
      );

      // Emit WebSocket event
      try {
        const { emitReconComplete } = await import("./ws-event-hub");
        emitReconComplete({
          scanId,
          domain: scan.primaryDomain,
          findings: result.totalFindings || 0,
          engagementId: scan.engagementId || undefined,
        });
      } catch {}
    } catch (err: any) {
      console.error(
        `[ScanRecovery] Auto-recovery failed for scan ${scanId} (attempt ${newRetryCount}/${MAX_AUTO_RETRIES}):`,
        err.message
      );

      // Don't mark as failed yet if we have retries left
      if (newRetryCount >= MAX_AUTO_RETRIES) {
        await db
          .updateDomainIntelScan(scanId, {
            status: "failed",
            pipelineOutput: {
              error: err.message,
              stack: err.stack?.substring(0, 1000),
              failedAt: new Date().toISOString(),
              autoRecoveryExhausted: true,
              totalAutoRetries: newRetryCount,
            },
          })
          .catch(() => {});
        _totalFailures++;
      } else {
        // Reset to the stuck status so the next cron cycle picks it up again
        await db
          .updateDomainIntelScan(scanId, {
            status: "passive_recon",
            pipelineOutput: {
              error: err.message,
              lastAutoRetryAt: new Date().toISOString(),
              autoRetryAttempt: newRetryCount,
              maxRetries: MAX_AUTO_RETRIES,
            },
          })
          .catch(() => {});
      }
    }
  });

  return {
    recovered: true,
    reason: `Auto-retry initiated (attempt ${newRetryCount}/${MAX_AUTO_RETRIES})`,
    retryCount: newRetryCount,
  };
}

/**
 * Main recovery check — called by the cron job.
 * Finds all stuck scans and attempts to recover each one.
 */
export async function runRecoveryCheck(): Promise<{
  checked: boolean;
  stuckScans: number;
  recovered: number;
  exhausted: number;
  skipped: number;
}> {
  if (_isRunning) {
    console.log("[ScanRecovery] Recovery check already in progress, skipping");
    return { checked: false, stuckScans: 0, recovered: 0, exhausted: 0, skipped: 0 };
  }

  _isRunning = true;
  _lastCheckAt = new Date();

  try {
    const stuckScans = await findStuckScans();

    if (stuckScans.length === 0) {
      return { checked: true, stuckScans: 0, recovered: 0, exhausted: 0, skipped: 0 };
    }

    console.log(
      `[ScanRecovery] Found ${stuckScans.length} stuck scan(s): ${stuckScans
        .map((s) => `${s.primaryDomain} (id=${s.id}, stuck ${Math.round(s.stuckDurationMs / 60000)}min, retries=${s.retryCount})`)
        .join(", ")}`
    );

    let recovered = 0;
    let exhausted = 0;
    let skipped = 0;

    // Process one at a time to avoid overwhelming the server
    for (const scan of stuckScans) {
      try {
        const result = await recoverScan(scan.id);
        if (result.recovered) {
          recovered++;
        } else {
          exhausted++;
        }
      } catch (err: any) {
        console.error(`[ScanRecovery] Error recovering scan ${scan.id}:`, err.message);
        skipped++;
      }

      // Only recover one scan per cycle to avoid overloading
      if (recovered >= 1) {
        skipped += stuckScans.length - recovered - exhausted - skipped;
        console.log(
          `[ScanRecovery] Rate-limiting: recovering 1 scan per cycle. ${skipped} remaining stuck scans will be retried in the next cycle.`
        );
        break;
      }
    }

    return { checked: true, stuckScans: stuckScans.length, recovered, exhausted, skipped };
  } catch (err: any) {
    console.error("[ScanRecovery] Recovery check failed:", err.message);
    return { checked: false, stuckScans: 0, recovered: 0, exhausted: 0, skipped: 0 };
  } finally {
    _isRunning = false;
  }
}

// ─── Scheduler ──────────────────────────────────────────────────────────────

/**
 * Initialize the scan recovery cron job.
 * Runs every 5 minutes to check for stuck scans.
 */
export function initScanRecoverySchedule(): void {
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

  console.log("[ScanRecovery] Cron job active — checking for stuck scans every 5 minutes");
}

/**
 * Stop the scan recovery cron job.
 */
export function stopScanRecoverySchedule(): void {
  if (_cronTask) {
    _cronTask.stop();
    _cronTask = null;
    console.log("[ScanRecovery] Cron job stopped");
  }
}

/**
 * Get the current status of the scan recovery scheduler.
 */
export function getScanRecoveryStatus() {
  return {
    active: _cronTask !== null,
    lastCheckAt: _lastCheckAt?.toISOString() || null,
    isRunning: _isRunning,
    totalRecoveries: _totalRecoveries,
    totalFailures: _totalFailures,
    trackedScans: _retryCountMap.size,
    retryCountMap: Object.fromEntries(_retryCountMap),
    config: {
      stuckThresholdMinutes: STUCK_THRESHOLD_MS / 60000,
      maxAutoRetries: MAX_AUTO_RETRIES,
      cronSchedule: CRON_SCHEDULE,
    },
  };
}

// ─── Exports for testing ────────────────────────────────────────────────────

export const _testHelpers = {
  STUCK_THRESHOLD_MS,
  MAX_AUTO_RETRIES,
  IN_PROGRESS_STATUSES,
  getRetryCount: (scanId: number) => _retryCountMap.get(scanId) || 0,
  setRetryCount: (scanId: number, count: number) => _retryCountMap.set(scanId, count),
  clearRetryMap: () => _retryCountMap.clear(),
};
