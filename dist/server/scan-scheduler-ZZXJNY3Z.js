import {
  bulkCreateDiscoveredAssets,
  bulkCreateMonitorChanges,
  createDiscoveredAsset,
  createDomainIntelScan,
  getDiscoveredAssetsByScan,
  getEnabledMonitors,
  init_db,
  updateDomainIntelScan,
  updateOsintMonitor
} from "./chunk-SI4LILOM.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-YQRYZ5JK.js";
import "./chunk-KFQGP6VL.js";

// server/lib/scan-scheduler.ts
init_db();
import cron from "node-cron";
var _cronTask = null;
var _lastCheckAt = null;
var _totalScansTriggered = 0;
var _recentRuns = [];
var MAX_RECENT_RUNS = 50;
var MAX_CONCURRENT_SCANS = 2;
var _activeScanCount = 0;
var CRON_EXPRESSION = "*/5 * * * *";
async function checkAndTriggerScans() {
  _lastCheckAt = Date.now();
  let monitorsChecked = 0;
  let scansDue = 0;
  let scansTriggered = 0;
  try {
    const allMonitors = await getEnabledMonitors();
    const isTestDomain = (domain) => /^(ack-test|trpc-ack|test-monitor|get-test|scan-test|pipeline-test)-\d{10,}\./i.test(domain) || /\d{13}\.(com|org|net)$/i.test(domain);
    const monitors = allMonitors.filter((m) => !isTestDomain(m.domain || ""));
    if (monitors.length < allMonitors.length) {
      console.log(`[ScanScheduler] Filtered out ${allMonitors.length - monitors.length} test domain monitor(s)`);
    }
    monitorsChecked = monitors.length;
    if (monitors.length === 0) {
      console.log("[ScanScheduler] No enabled monitors found");
      return { monitorsChecked: 0, scansDue: 0, scansTriggered: 0 };
    }
    console.log(`[ScanScheduler] Checking ${monitors.length} enabled monitor(s)...`);
    const now = Date.now();
    const dueMonitors = monitors.filter((m) => {
      if (!m.lastScanAt) return true;
      const intervalMs = (m.intervalHours || 24) * 60 * 60 * 1e3;
      const nextDueAt = new Date(m.lastScanAt).getTime() + intervalMs;
      return now >= nextDueAt;
    });
    scansDue = dueMonitors.length;
    if (dueMonitors.length === 0) {
      console.log("[ScanScheduler] No monitors due for scanning");
      return { monitorsChecked, scansDue: 0, scansTriggered: 0 };
    }
    console.log(`[ScanScheduler] ${dueMonitors.length} monitor(s) due for scanning`);
    for (const monitor of dueMonitors) {
      if (_activeScanCount >= MAX_CONCURRENT_SCANS) {
        console.log(`[ScanScheduler] Concurrency limit reached (${MAX_CONCURRENT_SCANS}), deferring remaining scans`);
        break;
      }
      scansTriggered++;
      triggerScheduledScan(monitor).catch((err) => {
        console.error(`[ScanScheduler] Error triggering scan for ${monitor.domain}:`, err);
      });
    }
    return { monitorsChecked, scansDue, scansTriggered };
  } catch (err) {
    console.error("[ScanScheduler] Error during check cycle:", err);
    return { monitorsChecked, scansDue, scansTriggered };
  }
}
async function triggerScheduledScan(monitor) {
  const run = {
    monitorId: monitor.id,
    domain: monitor.domain,
    triggeredAt: Date.now(),
    status: "running"
  };
  _recentRuns.unshift(run);
  if (_recentRuns.length > MAX_RECENT_RUNS) _recentRuns.pop();
  _activeScanCount++;
  _totalScansTriggered++;
  console.log(`[ScanScheduler] Starting scheduled scan for ${monitor.domain} (monitor #${monitor.id})`);
  try {
    const scanId = await createDomainIntelScan({
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
        complianceFlags: []
      },
      status: "discovering",
      createdBy: monitor.createdBy
    });
    run.scanId = scanId;
    const { runDomainIntelPipeline } = await import("./domainIntel-V7SKQSHH.js");
    const result = await runDomainIntelPipeline(
      {
        customerName: monitor.domain,
        primaryDomain: monitor.domain,
        sector: "general",
        clientType: monitor.clientType || "enterprise",
        criticalFunctions: [],
        complianceFlags: []
      },
      async (stage) => {
        await updateDomainIntelScan(scanId, { status: stage }).catch(() => {
        });
      },
      { scanMode: "standard", skipEngagement: true }
    );
    if (result.assets && result.assets.length > 0) {
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
        confidence: a.confidence,
        impactScore: a.impactScore || 0,
        likelihoodScore: a.likelihoodScore || 0
      }));
      const BATCH_SIZE = 5;
      for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
        const batch = assetRecords.slice(i, i + BATCH_SIZE);
        try {
          await bulkCreateDiscoveredAssets(batch);
        } catch (e) {
          console.warn(`[ScanScheduler] Batch insert failed, trying individual: ${e.message}`);
          for (const record of batch) {
            try {
              await createDiscoveredAsset(record);
            } catch {
            }
          }
        }
      }
    }
    const { detectSubdomainTakeover, crossReferenceTechVulnerabilities, detectSubdomainChanges } = await import("./domain-intel-advanced-DLT5IQJY.js");
    const storedAssets = await getDiscoveredAssetsByScan(scanId);
    const trimmedOutput = {
      discoveredSubdomains: (() => {
        if (!result.passiveRecon?.allObservations) return [];
        const seen = /* @__PURE__ */ new Set();
        return result.passiveRecon.allObservations.filter((o) => o.assetType === "subdomain" && o.name).filter((o) => {
          const k = o.name.toLowerCase();
          if (seen.has(k)) return false;
          seen.add(k);
          return true;
        }).map((o) => ({ name: o.name, ip: o.ip || null, source: o.source, tags: o.tags || [] })).slice(0, 500);
      })(),
      discoveredPorts: (() => {
        if (!result.passiveRecon?.allObservations) return [];
        const portMap = /* @__PURE__ */ new Map();
        for (const obs of result.passiveRecon.allObservations) {
          if (obs.assetType !== "ip" || !obs.ip) continue;
          const evidence = obs.evidence;
          if (evidence?.port) {
            const key = `${obs.ip}:${evidence.port}`;
            if (!portMap.has(key)) {
              portMap.set(key, { ip: obs.ip, port: evidence.port, transport: evidence.transport || "tcp", product: evidence.product || "", version: evidence.version || "", hostname: obs.name || obs.ip, source: obs.source });
            }
          }
        }
        return Array.from(portMap.values()).slice(0, 500);
      })()
    };
    let takeoverResult = null;
    try {
      takeoverResult = await detectSubdomainTakeover(storedAssets, trimmedOutput);
    } catch {
    }
    let techVulnResult = null;
    try {
      techVulnResult = crossReferenceTechVulnerabilities(storedAssets, trimmedOutput);
    } catch {
    }
    let changesDetected = 0;
    if (monitor.baselineSnapshot) {
      try {
        const previousScanId = 0;
        const previousScanDate = new Date(monitor.lastScanAt || 0).getTime();
        const baselineSubdomains = monitor.baselineSnapshot.subdomains || {};
        const previousAssets = Object.entries(baselineSubdomains).map(([hostname, data]) => ({
          hostname,
          dnsRecords: data.ips ? { A: data.ips } : null,
          technologies: data.technologies || [],
          postureFindings: (data.ports || []).map((p) => ({ category: "open_port", title: `Open port ${p}` }))
        }));
        const previousPipeline = {
          discoveredSubdomains: Object.entries(baselineSubdomains).map(([name, data]) => ({
            name,
            ip: data.ips?.[0] || null,
            tags: data.tags || []
          })),
          discoveredPorts: Object.entries(monitor.baselineSnapshot.ports || {}).map(([key, data]) => {
            const [ip, port] = key.split(":");
            return { ip, port: parseInt(port), hostname: ip, transport: data.transport || "tcp", product: data.product || "" };
          })
        };
        const changeResult = detectSubdomainChanges(
          scanId,
          previousScanId,
          monitor.domain,
          storedAssets,
          previousAssets,
          trimmedOutput,
          previousPipeline,
          Date.now(),
          previousScanDate
        );
        const allChanges = [...changeResult.newSubdomains, ...changeResult.removedSubdomains, ...changeResult.modifiedSubdomains];
        changesDetected = allChanges.length;
        if (changesDetected > 0) {
          await bulkCreateMonitorChanges(
            allChanges.slice(0, 50).map((c) => ({
              monitorId: monitor.id,
              domain: monitor.domain,
              changeType: c.changeType,
              severity: c.severity === "critical" ? "critical" : c.severity === "high" ? "warning" : "info",
              previousValue: c.previousValue || null,
              currentValue: c.currentValue || null,
              description: c.description
            }))
          );
          if (monitor.notifyOnChange) {
            try {
              const { notifyOwner } = await import("./notification-4RFY3TAD.js");
              await notifyOwner({
                title: `Scheduled Scan Alert: ${changesDetected} change(s) on ${monitor.domain}`,
                content: `Automated scan detected ${changesDetected} infrastructure change(s) on ${monitor.domain}.

Top changes:
${allChanges.slice(0, 5).map((c) => `[${c.severity.toUpperCase()}] ${c.description}`).join("\n")}`
              });
            } catch {
            }
          }
        }
      } catch (e) {
        console.error(`[ScanScheduler] Change detection error for ${monitor.domain}:`, e.message);
      }
    }
    const newBaseline = buildBaselineSnapshot(result);
    await updateDomainIntelScan(scanId, {
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
        monitorId: monitor.id
      }
    });
    await updateOsintMonitor(monitor.id, {
      lastScanAt: /* @__PURE__ */ new Date(),
      totalScans: (monitor.totalScans || 0) + 1,
      totalChangesDetected: (monitor.totalChangesDetected || 0) + changesDetected,
      baselineSnapshot: newBaseline,
      ...changesDetected > 0 ? { lastChangeDetectedAt: /* @__PURE__ */ new Date() } : {}
    });
    run.status = "completed";
    run.completedAt = Date.now();
    run.assetsFound = result.totalAssets || 0;
    run.changesDetected = changesDetected;
    console.log(`[ScanScheduler] Completed scan for ${monitor.domain}: ${run.assetsFound} assets, ${changesDetected} changes`);
  } catch (err) {
    run.status = "failed";
    run.completedAt = Date.now();
    run.error = err?.message || "Unknown error";
    console.error(`[ScanScheduler] Scan failed for ${monitor.domain}:`, err?.message);
    try {
      await updateOsintMonitor(monitor.id, {
        lastScanAt: /* @__PURE__ */ new Date(),
        totalScans: (monitor.totalScans || 0) + 1
      });
    } catch {
    }
  } finally {
    _activeScanCount--;
  }
}
function buildScanSnapshot(scanId, domain, result) {
  const subdomains = /* @__PURE__ */ new Map();
  const ports = /* @__PURE__ */ new Map();
  const technologies = /* @__PURE__ */ new Map();
  if (result.passiveRecon?.allObservations) {
    for (const obs of result.passiveRecon.allObservations) {
      if (obs.assetType === "subdomain" && obs.name) {
        const existing = subdomains.get(obs.name);
        if (existing) {
          if (obs.ip && !existing.ips.includes(obs.ip)) existing.ips.push(obs.ip);
        } else {
          subdomains.set(obs.name, { ips: obs.ip ? [obs.ip] : [], ports: [], services: [], technologies: [], source: obs.source, tags: obs.tags || [] });
        }
      }
      if (obs.assetType === "ip" && obs.ip) {
        const evidence = obs.evidence;
        if (evidence?.port) {
          ports.set(`${obs.ip}:${evidence.port}`, { port: evidence.port, transport: evidence.transport || "tcp", product: evidence.product || "", version: evidence.version || "" });
          const hostname = obs.name || obs.ip;
          const sub = subdomains.get(hostname);
          if (sub && !sub.ports.includes(evidence.port)) {
            sub.ports.push(evidence.port);
            if (evidence.product && !sub.services.includes(evidence.product)) sub.services.push(evidence.product);
          }
        }
      }
    }
  }
  if (Array.isArray(result.assets)) {
    for (const a of result.assets) {
      const hostname = a.asset?.hostname;
      if (a.asset?.technologies) {
        for (const t of a.asset.technologies) {
          if (!technologies.has(t)) technologies.set(t, { hosts: [hostname] });
          else technologies.get(t).hosts.push(hostname);
        }
        if (hostname) {
          const sub = subdomains.get(hostname);
          if (sub) {
            for (const t of a.asset.technologies) {
              if (!sub.technologies.includes(t)) sub.technologies.push(t);
            }
          }
        }
      }
    }
  }
  return { scanId, domain, scanDate: Date.now(), subdomains, ports, technologies };
}
function buildBaselineSnapshot(result) {
  const snapshot = buildScanSnapshot(0, "", result);
  return {
    subdomains: Object.fromEntries(snapshot.subdomains),
    ports: Object.fromEntries(snapshot.ports),
    technologies: Object.fromEntries(snapshot.technologies)
  };
}
function getSchedulerStatus() {
  return {
    running: _cronTask !== null,
    lastCheckAt: _lastCheckAt,
    nextCheckAt: _lastCheckAt ? _lastCheckAt + 5 * 60 * 1e3 : null,
    activeMonitors: 0,
    // Will be populated by caller
    totalScansTriggered: _totalScansTriggered,
    recentRuns: [..._recentRuns],
    cronExpression: CRON_EXPRESSION
  };
}
function initScanScheduler() {
  if (_cronTask) {
    console.log("[ScanScheduler] Already running");
    return;
  }
  console.log("[ScanScheduler] Initializing automated scan scheduler (every 5 min)");
  _cronTask = cron.schedule(CRON_EXPRESSION, async () => {
    await checkAndTriggerScans();
  });
  setTimeout(() => {
    checkAndTriggerScans().catch((err) => {
      console.error("[ScanScheduler] Initial check failed:", err);
    });
  }, 3 * 60 * 1e3);
  setTimeout(async () => {
    try {
      const { startPeriodicHealthChecks } = await import("./health-monitor-SU5BUIXD.js");
      startPeriodicHealthChecks(5 * 60 * 1e3);
    } catch (err) {
      console.error("[ScanScheduler] Failed to start integration health monitor:", err.message);
    }
  }, 2 * 60 * 1e3);
}
function stopScanScheduler() {
  if (_cronTask) {
    _cronTask.stop();
    _cronTask = null;
    console.log("[ScanScheduler] Stopped");
  }
  import("./health-monitor-SU5BUIXD.js").then(({ stopPeriodicHealthChecks }) => {
    stopPeriodicHealthChecks();
  }).catch(() => {
  });
}
async function forceSchedulerCheck() {
  return checkAndTriggerScans();
}
export {
  checkAndTriggerScans,
  forceSchedulerCheck,
  getSchedulerStatus,
  initScanScheduler,
  stopScanScheduler
};
