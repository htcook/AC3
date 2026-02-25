// @ts-nocheck
/**
 * Automated Domain Scan Scheduler
 * 
 * Runs a cron job that checks enabled OSINT monitors and triggers
 * domain scans when their configured interval has elapsed.
 * Integrates with the existing osintMonitors table and domain intel pipeline.
 * 
 * Checks every 5 minutes for monitors that are due for scanning.
 * Respects concurrency limits to avoid overwhelming the pipeline.
 */
import cron from "node-cron";
import * as db from "../db";

// ─── Types ───────────────────────────────────────────────────────────

export interface SchedulerStatus {
  running: boolean;
  lastCheckAt: number | null;
  nextCheckAt: number | null;
  activeMonitors: number;
  totalScansTriggered: number;
  recentRuns: SchedulerRun[];
  cronExpression: string;
}

export interface SchedulerRun {
  monitorId: number;
  domain: string;
  triggeredAt: number;
  status: "running" | "completed" | "failed";
  completedAt?: number;
  error?: string;
  assetsFound?: number;
  changesDetected?: number;
  scanId?: number;
}

// ─── State ───────────────────────────────────────────────────────────

let _cronTask: ReturnType<typeof cron.schedule> | null = null;
let _lastCheckAt: number | null = null;
let _totalScansTriggered = 0;
const _recentRuns: SchedulerRun[] = [];
const MAX_RECENT_RUNS = 50;
const MAX_CONCURRENT_SCANS = 2;
let _activeScanCount = 0;
const CRON_EXPRESSION = "*/5 * * * *"; // Every 5 minutes

// ─── Core Scheduler Logic ────────────────────────────────────────────

/**
 * Check all enabled monitors and trigger scans for those whose interval has elapsed.
 */
export async function checkAndTriggerScans(): Promise<{ monitorsChecked: number; scansDue: number; scansTriggered: number }> {
  _lastCheckAt = Date.now();
  let monitorsChecked = 0;
  let scansDue = 0;
  let scansTriggered = 0;

  try {
    const monitors = await db.getEnabledMonitors();
    monitorsChecked = monitors.length;

    if (monitors.length === 0) {
      console.log("[ScanScheduler] No enabled monitors found");
      return { monitorsChecked: 0, scansDue: 0, scansTriggered: 0 };
    }

    console.log(`[ScanScheduler] Checking ${monitors.length} enabled monitor(s)...`);

    const now = Date.now();
    const dueMonitors = monitors.filter(m => {
      if (!m.lastScanAt) return true; // Never scanned — due immediately
      const intervalMs = (m.intervalHours || 24) * 60 * 60 * 1000;
      const nextDueAt = new Date(m.lastScanAt).getTime() + intervalMs;
      return now >= nextDueAt;
    });

    scansDue = dueMonitors.length;

    if (dueMonitors.length === 0) {
      console.log("[ScanScheduler] No monitors due for scanning");
      return { monitorsChecked, scansDue: 0, scansTriggered: 0 };
    }

    console.log(`[ScanScheduler] ${dueMonitors.length} monitor(s) due for scanning`);

    // Process due monitors respecting concurrency limit
    for (const monitor of dueMonitors) {
      if (_activeScanCount >= MAX_CONCURRENT_SCANS) {
        console.log(`[ScanScheduler] Concurrency limit reached (${MAX_CONCURRENT_SCANS}), deferring remaining scans`);
        break;
      }

      scansTriggered++;
      // Fire and forget — don't block the scheduler loop
      triggerScheduledScan(monitor).catch(err => {
        console.error(`[ScanScheduler] Error triggering scan for ${monitor.domain}:`, err);
      });
    }

    return { monitorsChecked, scansDue, scansTriggered };
  } catch (err) {
    console.error("[ScanScheduler] Error during check cycle:", err);
    return { monitorsChecked, scansDue, scansTriggered };
  }
}

/**
 * Trigger a scheduled scan for a specific monitor.
 */
async function triggerScheduledScan(monitor: any): Promise<void> {
  const run: SchedulerRun = {
    monitorId: monitor.id,
    domain: monitor.domain,
    triggeredAt: Date.now(),
    status: "running",
  };

  _recentRuns.unshift(run);
  if (_recentRuns.length > MAX_RECENT_RUNS) _recentRuns.pop();
  _activeScanCount++;
  _totalScansTriggered++;

  console.log(`[ScanScheduler] Starting scheduled scan for ${monitor.domain} (monitor #${monitor.id})`);

  try {
    // Create a scan record
    const scanId = await db.createDomainIntelScan({
      primaryDomain: monitor.domain,
      additionalDomains: [],
      clientType: monitor.clientType || "enterprise",
      sector: "general",
      criticalFunctions: [],
      complianceFlags: [],
      orgProfile: {
        customerName: monitor.domain,
        primaryDomain: monitor.domain,
        sector: "general",
        clientType: monitor.clientType || "enterprise",
        criticalFunctions: [],
        complianceFlags: [],
      },
      status: "discovering",
      createdBy: monitor.createdBy,
    });

    run.scanId = scanId;

    // Run the domain intel pipeline
    const { runDomainIntelPipeline } = await import("../domainIntel");
    const result = await runDomainIntelPipeline(
      {
        customerName: monitor.domain,
        primaryDomain: monitor.domain,
        sector: "general",
        clientType: monitor.clientType || "enterprise",
        criticalFunctions: [],
        complianceFlags: [],
      },
      async (stage) => {
        await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
      },
      { scanMode: "standard", skipEngagement: true }
    );

    // Store discovered assets
    if (result.assets && result.assets.length > 0) {
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
        confidence: a.confidence,
        impactScore: a.impactScore || 0,
        likelihoodScore: a.likelihoodScore || 0,
      }));

      const BATCH_SIZE = 5;
      for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
        const batch = assetRecords.slice(i, i + BATCH_SIZE);
        try {
          await db.bulkCreateDiscoveredAssets(batch);
        } catch (e: any) {
          console.warn(`[ScanScheduler] Batch insert failed, trying individual: ${e.message}`);
          for (const record of batch) {
            try { await db.createDiscoveredAsset(record); } catch { /* skip */ }
          }
        }
      }
    }

    // Run advanced analysis
    const { detectSubdomainTakeover, crossReferenceTechVulnerabilities, detectSubdomainChanges } = await import("./domain-intel-advanced");
    const storedAssets = await db.getDiscoveredAssetsByScan(scanId);

    // Build trimmed pipeline output for advanced analysis
    const trimmedOutput: any = {
      discoveredSubdomains: (() => {
        if (!result.passiveRecon?.allObservations) return [];
        const seen = new Set<string>();
        return result.passiveRecon.allObservations
          .filter((o: any) => o.assetType === "subdomain" && o.name)
          .filter((o: any) => { const k = o.name!.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; })
          .map((o: any) => ({ name: o.name!, ip: o.ip || null, source: o.source, tags: o.tags || [] }))
          .slice(0, 500);
      })(),
      discoveredPorts: (() => {
        if (!result.passiveRecon?.allObservations) return [];
        const portMap = new Map<string, any>();
        for (const obs of result.passiveRecon.allObservations) {
          if (obs.assetType !== "ip" || !obs.ip) continue;
          const evidence = obs.evidence as any;
          if (evidence?.port) {
            const key = `${obs.ip}:${evidence.port}`;
            if (!portMap.has(key)) {
              portMap.set(key, { ip: obs.ip, port: evidence.port, transport: evidence.transport || "tcp", product: evidence.product || "", version: evidence.version || "", hostname: obs.name || obs.ip, source: obs.source });
            }
          }
        }
        return Array.from(portMap.values()).slice(0, 500);
      })(),
    };

    let takeoverResult = null;
    try { takeoverResult = await detectSubdomainTakeover(storedAssets, trimmedOutput); } catch { /* non-fatal */ }

    let techVulnResult = null;
    try { techVulnResult = crossReferenceTechVulnerabilities(storedAssets, trimmedOutput); } catch { /* non-fatal */ }

    // Detect changes from previous scan
    let changesDetected = 0;
    if (monitor.baselineSnapshot) {
      try {
        const currentSnapshot = buildScanSnapshot(scanId, monitor.domain, result);
        const previousSnapshot = {
          scanId: 0,
          domain: monitor.domain,
          scanDate: new Date(monitor.lastScanAt || 0).getTime(),
          subdomains: new Map(Object.entries(monitor.baselineSnapshot.subdomains || {})),
          ports: new Map(Object.entries(monitor.baselineSnapshot.ports || {})),
          technologies: new Map(Object.entries(monitor.baselineSnapshot.technologies || {})),
        };

        const changeResult = (detectSubdomainChanges as any)(currentSnapshot, previousSnapshot);
        changesDetected = ((changeResult as any)?.changes || []).length;

        if (changesDetected > 0) {
          await db.bulkCreateMonitorChanges(
            ((changeResult as any)?.changes || []).slice(0, 50).map((c: any) => ({
              monitorId: monitor.id,
              domain: monitor.domain,
              changeType: c.changeType,
              severity: c.severity === "critical" ? "critical" : c.severity === "high" ? "warning" : "info",
              previousValue: c.previousValue || null,
              currentValue: c.currentValue || null,
              description: c.description,
            }))
          );

          // Notify owner if configured
          if (monitor.notifyOnChange) {
            try {
              const { notifyOwner } = await import("../_core/notification");
              await notifyOwner({
                title: `Scheduled Scan Alert: ${changesDetected} change(s) on ${monitor.domain}`,
                content: `Automated scan detected ${changesDetected} infrastructure change(s) on ${monitor.domain}.\n\nTop changes:\n${((changeResult as any)?.changes || []).slice(0, 5).map((c: any) => `• [${c.severity.toUpperCase()}] ${c.description}`).join("\n")}`,
              });
            } catch { /* notification non-fatal */ }
          }
        }
      } catch (e: any) {
        console.error(`[ScanScheduler] Change detection error for ${monitor.domain}:`, e.message);
      }
    }

    // Build new baseline snapshot
    const newBaseline = buildBaselineSnapshot(result);

    // Update scan record with final results
    await db.updateDomainIntelScan(scanId, {
      status: "scan_complete",
      totalAssets: result.totalAssets,
      totalFindings: result.totalFindings,
      overallRiskScore: result.overallRiskScore,
      overallRiskBand: result.overallRiskBand,
      executiveSummary: result.executiveSummary,
      pipelineOutput: {
        ...trimmedOutput,
        takeoverDetection: takeoverResult,
        techVulnerabilities: techVulnResult,
        scheduledScan: true,
        monitorId: monitor.id,
      },
    });

    // Update monitor
    await db.updateOsintMonitor(monitor.id, {
      lastScanAt: new Date(),
      totalScans: (monitor.totalScans || 0) + 1,
      totalChangesDetected: (monitor.totalChangesDetected || 0) + changesDetected,
      baselineSnapshot: newBaseline,
      ...(changesDetected > 0 ? { lastChangeDetectedAt: new Date() } : {}),
    });

    run.status = "completed";
    run.completedAt = Date.now();
    run.assetsFound = result.totalAssets || 0;
    run.changesDetected = changesDetected;

    console.log(`[ScanScheduler] Completed scan for ${monitor.domain}: ${run.assetsFound} assets, ${changesDetected} changes`);

  } catch (err: any) {
    run.status = "failed";
    run.completedAt = Date.now();
    run.error = err?.message || "Unknown error";
    console.error(`[ScanScheduler] Scan failed for ${monitor.domain}:`, err?.message);

    // Update monitor with failure info
    try {
      await db.updateOsintMonitor(monitor.id, {
        lastScanAt: new Date(),
        totalScans: (monitor.totalScans || 0) + 1,
      });
    } catch { /* non-fatal */ }
  } finally {
    _activeScanCount--;
  }
}

// ─── Helper Functions ────────────────────────────────────────────────

function buildScanSnapshot(scanId: number, domain: string, result: any) {
  const subdomains = new Map<string, any>();
  const ports = new Map<string, any>();
  const technologies = new Map<string, any>();

  if (result.passiveRecon?.allObservations) {
    for (const obs of result.passiveRecon.allObservations) {
      if (obs.assetType === "subdomain" && obs.name) {
        subdomains.set(obs.name, { ips: obs.ip ? [obs.ip] : [], source: obs.source, tags: obs.tags || [] });
      }
      if (obs.assetType === "ip" && obs.ip) {
        const evidence = obs.evidence as any;
        if (evidence?.port) {
          ports.set(`${obs.ip}:${evidence.port}`, { port: evidence.port, transport: evidence.transport || "tcp", product: evidence.product || "", version: evidence.version || "" });
        }
      }
    }
  }

  if (result.assets) {
    for (const a of result.assets) {
      if (a.asset.technologies) {
        for (const t of a.asset.technologies) {
          if (!technologies.has(t)) technologies.set(t, { hosts: [a.asset.hostname] });
          else technologies.get(t).hosts.push(a.asset.hostname);
        }
      }
    }
  }

  return { scanId, domain, scanDate: Date.now(), subdomains, ports, technologies };
}

function buildBaselineSnapshot(result: any) {
  const snapshot = buildScanSnapshot(0, "", result);
  return {
    subdomains: Object.fromEntries(snapshot.subdomains),
    ports: Object.fromEntries(snapshot.ports),
    technologies: Object.fromEntries(snapshot.technologies),
  };
}

// ─── Public API ──────────────────────────────────────────────────────

/**
 * Get the current scheduler status.
 */
export function getSchedulerStatus(): SchedulerStatus {
  return {
    running: _cronTask !== null,
    lastCheckAt: _lastCheckAt,
    nextCheckAt: _lastCheckAt ? _lastCheckAt + 5 * 60 * 1000 : null,
    activeMonitors: 0, // Will be populated by caller
    totalScansTriggered: _totalScansTriggered,
    recentRuns: [..._recentRuns],
    cronExpression: CRON_EXPRESSION,
  };
}

/**
 * Initialize the scan scheduler.
 * Checks every 5 minutes for monitors that are due for scanning.
 */
export function initScanScheduler(): void {
  if (_cronTask) {
    console.log("[ScanScheduler] Already running");
    return;
  }

  console.log("[ScanScheduler] Initializing automated scan scheduler (every 5 min)");

  _cronTask = cron.schedule(CRON_EXPRESSION, async () => {
    await checkAndTriggerScans();
  });

  // Defer first check by 3 minutes to avoid startup congestion
  setTimeout(() => {
    checkAndTriggerScans().catch(err => {
      console.error("[ScanScheduler] Initial check failed:", err);
    });
  }, 3 * 60 * 1000);
}

/**
 * Stop the scan scheduler.
 */
export function stopScanScheduler(): void {
  if (_cronTask) {
    _cronTask.stop();
    _cronTask = null;
    console.log("[ScanScheduler] Stopped");
  }
}

/**
 * Force an immediate check cycle (for manual trigger).
 */
export async function forceSchedulerCheck(): Promise<{ monitorsChecked: number; scansDue: number; scansTriggered: number }> {
  return checkAndTriggerScans();
}
