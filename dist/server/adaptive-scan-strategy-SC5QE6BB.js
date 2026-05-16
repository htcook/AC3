import "./chunk-KFQGP6VL.js";

// server/lib/adaptive-scan-strategy.ts
var CONNECTOR_CATEGORIES = {
  recon_core: ["crtsh", "shodan_internetdb", "shodan", "censys", "securitytrails", "dns_deep", "rdap", "ripestat"],
  vuln_intel: ["shodan", "censys", "virustotal", "google_safebrowsing", "phishtank"],
  cloud_assets: ["cloud_assets", "cloud_bucket_recon", "container_discovery"],
  supply_chain: ["github_leaks", "github_recon", "builtwith", "commoncrawl"],
  threat_intel: ["greynoise", "alienvault_otx", "threatfox", "threatminer", "abuseipdb", "darkweb_crossref"],
  credential_exposure: ["dehashed", "dehashed_whois", "hibp", "leakix", "leakcheck", "hudson_rock", "intelx_search"],
  email_security: ["email_security", "domain_health"],
  web_security: ["http_security", "urlscan", "wayback"],
  company_intel: ["company_intel", "hunter", "social_media", "whoisxml", "reverse_whois"],
  network_intel: ["bgpview", "ip_api", "netlas", "fullhunt", "passivetotal", "circlpdns"]
};
var CONNECTOR_TO_CATEGORIES = {};
for (const [cat, connectors] of Object.entries(CONNECTOR_CATEGORIES)) {
  for (const c of connectors) {
    if (!CONNECTOR_TO_CATEGORIES[c]) CONNECTOR_TO_CATEGORIES[c] = [];
    CONNECTOR_TO_CATEGORIES[c].push(cat);
  }
}
var graduationStore = /* @__PURE__ */ new Map();
var connectorPerfStore = /* @__PURE__ */ new Map();
var hydratedDomains = /* @__PURE__ */ new Set();
var sectorInsightsCache = /* @__PURE__ */ new Map();
var SECTOR_CACHE_TTL_MS = 5 * 60 * 1e3;
async function persistGraduationToDB(domain, scores, opts) {
  try {
    const { insertGraduationScore } = await import("./db-LSUZDHGJ.js");
    await insertGraduationScore({
      domain,
      sector: opts?.sector || null,
      scanId: opts?.scanId || null,
      engagementId: opts?.engagementId || null,
      scores,
      summary: opts?.summary || null
    });
  } catch (err) {
    console.warn(`[AdaptiveStrategy] Failed to persist graduation scores for ${domain}:`, err.message);
  }
}
async function persistConnectorPerfToDB(entries, sector) {
  try {
    const { bulkInsertConnectorPerformance } = await import("./db-LSUZDHGJ.js");
    await bulkInsertConnectorPerformance(entries.map((e) => ({ ...e, sector: sector || null })));
  } catch (err) {
    console.warn(`[AdaptiveStrategy] Failed to persist connector performance:`, err.message);
  }
}
async function hydrateFromDB(domain) {
  const key = domain.toLowerCase();
  if (hydratedDomains.has(key)) return;
  hydratedDomains.add(key);
  try {
    const { getGraduationScoresForDomain, getConnectorPerformanceForDomain } = await import("./db-LSUZDHGJ.js");
    const dbGrad = await getGraduationScoresForDomain(key, 20);
    if (dbGrad.length > 0) {
      const existing = graduationStore.get(key) || [];
      const existingScanIds = new Set(existing.map((e) => e.timestamp));
      for (const row of dbGrad) {
        const ts = new Date(row.createdAt).getTime();
        if (existingScanIds.has(ts)) continue;
        existing.push({
          scores: {
            recon_analyst: row.reconAnalyst,
            exploit_selector: row.exploitSelector,
            evasion_optimizer: row.evasionOptimizer,
            cognitive_core: row.cognitiveCore,
            cloud_assessor: row.cloudAssessor,
            supply_chain_analyst: row.supplyChainAnalyst
          },
          timestamp: ts
        });
      }
      graduationStore.set(key, existing.slice(-20));
    }
    const dbPerf = await getConnectorPerformanceForDomain(key, 500);
    if (dbPerf.length > 0) {
      const existing = connectorPerfStore.get(key) || [];
      const existingScanConnectors = new Set(existing.map((e) => `${e.scanId}:${e.connector}`));
      for (const row of dbPerf) {
        const dedupKey = `${row.scanId}:${row.connector}`;
        if (existingScanConnectors.has(dedupKey)) continue;
        existing.push({
          connector: row.connector,
          domain: row.domain,
          observations: row.observations,
          durationMs: row.durationMs,
          status: row.status,
          scanId: row.scanId,
          timestamp: new Date(row.createdAt).getTime()
        });
      }
      connectorPerfStore.set(key, existing.slice(-500));
    }
    const gradCount = graduationStore.get(key)?.length || 0;
    const perfCount = connectorPerfStore.get(key)?.length || 0;
    if (gradCount > 0 || perfCount > 0) {
      console.log(`[AdaptiveStrategy] Hydrated ${key}: ${gradCount} graduation records, ${perfCount} connector records from DB`);
    }
  } catch (err) {
    console.warn(`[AdaptiveStrategy] DB hydration failed for ${key} (non-fatal):`, err.message);
  }
}
async function loadSectorInsights(sector) {
  const cached = sectorInsightsCache.get(sector);
  if (cached && Date.now() - cached.cachedAt < SECTOR_CACHE_TTL_MS) {
    return cached.insights;
  }
  try {
    const { getAvgGraduationScoresBySector, getConnectorAvgsBySector } = await import("./db-LSUZDHGJ.js");
    const [avgScores, connectorAvgs] = await Promise.all([
      getAvgGraduationScoresBySector(sector),
      getConnectorAvgsBySector(sector)
    ]);
    if (!avgScores && connectorAvgs.length === 0) return null;
    const insights = {
      sector,
      sampleCount: avgScores?.sampleCount || 0,
      avgScores: avgScores ? {
        recon_analyst: avgScores.recon_analyst,
        exploit_selector: avgScores.exploit_selector,
        evasion_optimizer: avgScores.evasion_optimizer,
        cognitive_core: avgScores.cognitive_core,
        cloud_assessor: avgScores.cloud_assessor,
        supply_chain_analyst: avgScores.supply_chain_analyst
      } : null,
      connectorAvgs
    };
    sectorInsightsCache.set(sector, { insights, cachedAt: Date.now() });
    return insights;
  } catch (err) {
    console.warn(`[AdaptiveStrategy] Failed to load sector insights for ${sector}:`, err.message);
    return null;
  }
}
function recordGraduationScores(domain, scores, opts) {
  const key = domain.toLowerCase();
  if (!graduationStore.has(key)) graduationStore.set(key, []);
  graduationStore.get(key).push({ scores, timestamp: Date.now() });
  const entries = graduationStore.get(key);
  if (entries.length > 20) graduationStore.set(key, entries.slice(-20));
  if (opts?.sector) sectorInsightsCache.delete(opts.sector);
  persistGraduationToDB(key, scores, opts).catch(() => {
  });
}
function recordConnectorPerformance(perf, sector) {
  const key = perf.domain.toLowerCase();
  if (!connectorPerfStore.has(key)) connectorPerfStore.set(key, []);
  connectorPerfStore.get(key).push(perf);
  const entries = connectorPerfStore.get(key);
  if (entries.length > 500) connectorPerfStore.set(key, entries.slice(-500));
}
function recordConnectorResults(domain, scanId, connectorResults, sector) {
  const dbEntries = [];
  for (const cr of connectorResults) {
    const status = cr.errors.some((e) => e.includes("Hard timeout")) ? "timeout" : cr.errors.some((e) => e.includes("Skipped")) ? "skipped" : cr.errors.length > 0 && cr.observations.length === 0 ? "failed" : "completed";
    recordConnectorPerformance({
      connector: cr.connector,
      domain,
      observations: cr.observations.length,
      durationMs: cr.durationMs,
      status,
      scanId,
      timestamp: Date.now()
    }, sector);
    dbEntries.push({
      connector: cr.connector,
      domain: domain.toLowerCase(),
      scanId,
      observations: cr.observations.length,
      durationMs: cr.durationMs,
      status,
      rateLimited: cr.rateLimited
    });
  }
  if (dbEntries.length > 0) {
    persistConnectorPerfToDB(dbEntries, sector).catch(() => {
    });
  }
}
async function getDomainHistoryAsync(domain) {
  await hydrateFromDB(domain);
  return getDomainHistory(domain);
}
function getDomainHistory(domain) {
  const key = domain.toLowerCase();
  const gradEntries = graduationStore.get(key);
  const perfEntries = connectorPerfStore.get(key);
  if (!gradEntries?.length && !perfEntries?.length) return null;
  let avgScores = null;
  if (gradEntries?.length) {
    const sum = {};
    for (const entry of gradEntries) {
      for (const [model, score] of Object.entries(entry.scores)) {
        sum[model] = (sum[model] || 0) + score;
      }
    }
    avgScores = {};
    for (const [model, total] of Object.entries(sum)) {
      avgScores[model] = Math.round(total / gradEntries.length);
    }
  }
  const scanIds = new Set(perfEntries?.map((p) => p.scanId) || []);
  return {
    domain: key,
    scanCount: Math.max(scanIds.size, gradEntries?.length || 0),
    lastScanAt: Math.max(
      gradEntries?.length ? gradEntries[gradEntries.length - 1].timestamp : 0,
      perfEntries?.length ? perfEntries[perfEntries.length - 1].timestamp : 0
    ),
    avgGraduationScores: avgScores,
    connectorPerformance: perfEntries || [],
    wafDetectedCount: 0,
    wafBypassedCount: 0,
    avgScanDurationMs: perfEntries?.length ? perfEntries.reduce((s, p) => s + p.durationMs, 0) / perfEntries.length : 0
  };
}
async function computeAdaptiveStrategyAsync(domain, options) {
  await hydrateFromDB(domain);
  let sectorInsights = null;
  if (options?.sector) {
    sectorInsights = await loadSectorInsights(options.sector);
  }
  return computeAdaptiveStrategy(domain, options, sectorInsights);
}
function computeAdaptiveStrategy(domain, options, sectorInsights) {
  const history = getDomainHistory(domain);
  const rationale = [];
  let sectorLearningApplied = false;
  const effectiveScores = history?.avgGraduationScores || sectorInsights?.avgScores || null;
  if (!history?.avgGraduationScores && sectorInsights?.avgScores) {
    sectorLearningApplied = true;
    rationale.push(`Sector learning: using ${sectorInsights.sector} sector averages (${sectorInsights.sampleCount} samples) \u2014 no domain-specific history`);
  }
  const confidence = history ? Math.min(1, history.scanCount / 5) : sectorInsights ? Math.min(0.5, sectorInsights.sampleCount / 10) : 0;
  const effectiveHistory = history || (effectiveScores ? {
    domain: domain.toLowerCase(),
    scanCount: sectorInsights?.sampleCount || 0,
    lastScanAt: 0,
    avgGraduationScores: effectiveScores,
    connectorPerformance: [],
    wafDetectedCount: 0,
    wafBypassedCount: 0,
    avgScanDurationMs: 0
  } : null);
  const connectorRanking = computeConnectorRanking(domain, effectiveHistory, options, rationale, sectorInsights);
  const scanDepth = computeScanDepth(effectiveHistory, options, rationale);
  const evasionPreset = computeEvasionPreset(effectiveHistory, rationale);
  const focusAreas = computeFocusAreas(effectiveHistory, rationale);
  return {
    connectorRanking,
    scanDepth,
    evasionPreset,
    focusAreas,
    rationale,
    confidence,
    basedOn: {
      scanCount: history?.scanCount || 0,
      graduationDataAvailable: !!history?.avgGraduationScores,
      connectorHistoryCount: history?.connectorPerformance.length || 0,
      sectorLearningApplied,
      sectorSampleCount: sectorInsights?.sampleCount || 0
    }
  };
}
function computeConnectorRanking(domain, history, options, rationale, sectorInsights) {
  const key = domain.toLowerCase();
  const perfEntries = connectorPerfStore.get(key) || [];
  const byConnector = /* @__PURE__ */ new Map();
  for (const p of perfEntries) {
    if (!byConnector.has(p.connector)) byConnector.set(p.connector, []);
    byConnector.get(p.connector).push(p);
  }
  const sectorAvgMap = /* @__PURE__ */ new Map();
  if (sectorInsights?.connectorAvgs) {
    for (const ca of sectorInsights.connectorAvgs) {
      sectorAvgMap.set(ca.connector, {
        avgObs: ca.avgObservations,
        avgDur: ca.avgDurationMs,
        failRate: ca.failureRate,
        runs: ca.totalRuns
      });
    }
  }
  const allConnectors = /* @__PURE__ */ new Set();
  for (const connectors of Object.values(CONNECTOR_CATEGORIES)) {
    for (const c of connectors) allConnectors.add(c);
  }
  for (const c of byConnector.keys()) allConnectors.add(c);
  for (const c of sectorAvgMap.keys()) allConnectors.add(c);
  const rankings = [];
  for (const connector of allConnectors) {
    const entries = byConnector.get(connector) || [];
    const sectorData = sectorAvgMap.get(connector);
    let avgObs;
    let avgDur;
    let failureRate;
    let dataSource = "none";
    if (entries.length > 0) {
      avgObs = entries.reduce((s, e) => s + e.observations, 0) / entries.length;
      avgDur = entries.reduce((s, e) => s + e.durationMs, 0) / entries.length;
      const failCount = entries.filter((e) => e.status === "failed" || e.status === "timeout").length;
      failureRate = failCount / entries.length;
      dataSource = "domain";
    } else if (sectorData) {
      avgObs = sectorData.avgObs;
      avgDur = sectorData.avgDur;
      failureRate = sectorData.failRate;
      dataSource = "sector";
    } else {
      avgObs = -1;
      avgDur = -1;
      failureRate = 0;
    }
    let score = 50;
    let reason = "No history \u2014 using default priority";
    if (dataSource !== "none" && avgObs >= 0) {
      const obsBonus = Math.min(30, avgObs * 3);
      score += obsBonus;
      const failPenalty = failureRate * 30;
      score -= failPenalty;
      if (avgDur > 0) {
        const speedBonus = Math.max(0, 10 - avgDur / 5e3 * 10);
        score += speedBonus;
      }
      const sourceLabel = dataSource === "sector" ? " [sector]" : "";
      reason = `Avg ${avgObs.toFixed(1)} obs, ${(failureRate * 100).toFixed(0)}% fail rate, ${(avgDur / 1e3).toFixed(1)}s avg${sourceLabel}`;
    }
    if (history?.avgGraduationScores) {
      const categories = CONNECTOR_TO_CATEGORIES[connector] || [];
      const gs = history.avgGraduationScores;
      if (categories.includes("cloud_assets") && gs.cloud_assessor < 40) {
        score += 10;
        reason += " | Boosted: low cloud_assessor score";
      }
      if (categories.includes("supply_chain") && gs.supply_chain_analyst < 40) {
        score += 10;
        reason += " | Boosted: low supply_chain score";
      }
      if (categories.includes("recon_core") && gs.recon_analyst > 70) {
        score += 5;
        reason += " | Boosted: strong recon baseline";
      }
    }
    if (dataSource === "sector" && sectorData && sectorData.runs >= 5 && sectorData.avgObs >= 5) {
      score += 5;
      reason += ` | Sector boost: ${sectorData.runs} runs, ${sectorData.avgObs.toFixed(1)} avg obs in sector`;
    }
    score = Math.max(0, Math.min(100, Math.round(score)));
    let include = score >= 20;
    if (options?.forceInclude?.includes(connector)) {
      include = true;
      reason += " | Force-included";
    }
    if (options?.forceExclude?.includes(connector)) {
      include = false;
      reason += " | Force-excluded";
    }
    if (dataSource === "domain" && failureRate > 0.8 && entries.length >= 3 && !options?.forceInclude?.includes(connector)) {
      include = false;
      reason += " | Auto-excluded: persistent failures";
    }
    rankings.push({
      connector,
      score,
      include,
      reason,
      avgObservations: avgObs >= 0 ? Math.round(avgObs * 10) / 10 : 0,
      avgDurationMs: avgDur >= 0 ? Math.round(avgDur) : 0,
      failureRate: Math.round(failureRate * 100) / 100
    });
  }
  rankings.sort((a, b) => b.score - a.score);
  const includedCount = rankings.filter((r) => r.include).length;
  const excludedCount = rankings.filter((r) => !r.include).length;
  const sectorLabel = sectorInsights ? ` + ${sectorInsights.sampleCount} sector samples` : "";
  rationale.push(`Connector ranking: ${includedCount} included, ${excludedCount} excluded based on ${perfEntries.length} domain data points${sectorLabel}`);
  return rankings;
}
function computeScanDepth(history, options, rationale) {
  const defaults = {
    scanMode: "standard",
    maxConcurrent: 5,
    connectorTimeout: 15e3,
    enableRecursiveDiscovery: false,
    recursiveDepth: 2,
    enableBackgroundConnectors: true
  };
  if (options?.forceScanMode) {
    defaults.scanMode = options.forceScanMode;
    rationale.push(`Scan mode forced to: ${options.forceScanMode}`);
    return defaults;
  }
  if (!history?.avgGraduationScores) {
    rationale.push("Scan depth: using defaults (no graduation history)");
    return defaults;
  }
  const gs = history.avgGraduationScores;
  if (gs.recon_analyst >= 70) {
    defaults.maxConcurrent = 8;
    defaults.connectorTimeout = 2e4;
    defaults.enableRecursiveDiscovery = true;
    defaults.recursiveDepth = 3;
    rationale.push(`Scan depth: DEEP \u2014 recon_analyst score ${gs.recon_analyst} indicates strong baseline, increasing depth for diminishing-return coverage`);
  } else if (gs.recon_analyst >= 40) {
    defaults.maxConcurrent = 6;
    defaults.connectorTimeout = 15e3;
    defaults.enableRecursiveDiscovery = true;
    defaults.recursiveDepth = 2;
    rationale.push(`Scan depth: STANDARD+ \u2014 recon_analyst score ${gs.recon_analyst}, enabling recursive discovery`);
  } else {
    defaults.maxConcurrent = 10;
    defaults.connectorTimeout = 12e3;
    defaults.enableRecursiveDiscovery = false;
    rationale.push(`Scan depth: BROAD \u2014 recon_analyst score ${gs.recon_analyst} is low, maximizing connector breadth over depth`);
  }
  if (gs.cognitive_core >= 80 && history.scanCount >= 3) {
    defaults.scanMode = "active";
    rationale.push(`Scan mode: ACTIVE \u2014 cognitive_core score ${gs.cognitive_core} with ${history.scanCount} prior scans justifies active probing`);
  }
  if (history.avgScanDurationMs > 18e4) {
    defaults.maxConcurrent = Math.max(3, defaults.maxConcurrent - 2);
    rationale.push(`Concurrency reduced: avg scan duration ${(history.avgScanDurationMs / 1e3).toFixed(0)}s exceeds 3min threshold`);
  }
  return defaults;
}
function computeEvasionPreset(history, rationale) {
  const defaultPreset = {
    name: "standard",
    requestDelayMs: 0,
    randomizeOrder: false,
    rotateUserAgents: false,
    reason: "No evasion history \u2014 using standard preset"
  };
  if (!history?.avgGraduationScores) {
    rationale.push("Evasion: standard preset (no history)");
    return defaultPreset;
  }
  const evasionScore = history.avgGraduationScores.evasion_optimizer;
  const wafRate = history.scanCount > 0 ? history.wafDetectedCount / history.scanCount : 0;
  if (evasionScore >= 80) {
    rationale.push(`Evasion: NONE \u2014 evasion_optimizer score ${evasionScore} indicates clean scanning`);
    return {
      name: "none",
      requestDelayMs: 0,
      randomizeOrder: false,
      rotateUserAgents: false,
      reason: `Evasion score ${evasionScore}: no WAF issues detected`
    };
  }
  if (evasionScore >= 50 || wafRate > 0.3) {
    rationale.push(`Evasion: CAUTIOUS \u2014 evasion_optimizer score ${evasionScore}, WAF rate ${(wafRate * 100).toFixed(0)}%`);
    return {
      name: "cautious",
      requestDelayMs: 500,
      randomizeOrder: true,
      rotateUserAgents: true,
      reason: `Evasion score ${evasionScore}, WAF detected in ${(wafRate * 100).toFixed(0)}% of scans`
    };
  }
  if (evasionScore < 50) {
    rationale.push(`Evasion: AGGRESSIVE \u2014 evasion_optimizer score ${evasionScore} indicates strong target defenses`);
    return {
      name: "aggressive",
      requestDelayMs: 1e3,
      randomizeOrder: true,
      rotateUserAgents: true,
      reason: `Evasion score ${evasionScore}: target has strong WAF/defenses, maximizing evasion`
    };
  }
  return defaultPreset;
}
function computeFocusAreas(history, rationale) {
  const areas = [];
  if (!history?.avgGraduationScores) {
    rationale.push("Focus areas: none (no graduation history)");
    return areas;
  }
  const gs = history.avgGraduationScores;
  if (gs.cloud_assessor < 30) {
    areas.push({
      area: "Cloud & Container Assets",
      priority: "high",
      reason: `cloud_assessor score ${gs.cloud_assessor} \u2014 cloud infrastructure may be under-discovered`,
      relevantConnectors: CONNECTOR_CATEGORIES.cloud_assets || []
    });
  } else if (gs.cloud_assessor < 60) {
    areas.push({
      area: "Cloud & Container Assets",
      priority: "medium",
      reason: `cloud_assessor score ${gs.cloud_assessor} \u2014 moderate cloud coverage, room for improvement`,
      relevantConnectors: CONNECTOR_CATEGORIES.cloud_assets || []
    });
  }
  if (gs.supply_chain_analyst < 30) {
    areas.push({
      area: "Supply Chain & Code Exposure",
      priority: "high",
      reason: `supply_chain_analyst score ${gs.supply_chain_analyst} \u2014 code repos and dependencies under-analyzed`,
      relevantConnectors: CONNECTOR_CATEGORIES.supply_chain || []
    });
  } else if (gs.supply_chain_analyst < 60) {
    areas.push({
      area: "Supply Chain & Code Exposure",
      priority: "medium",
      reason: `supply_chain_analyst score ${gs.supply_chain_analyst} \u2014 partial supply chain coverage`,
      relevantConnectors: CONNECTOR_CATEGORIES.supply_chain || []
    });
  }
  if (gs.exploit_selector < 40) {
    areas.push({
      area: "Vulnerability Identification",
      priority: "high",
      reason: `exploit_selector score ${gs.exploit_selector} \u2014 vuln detection needs improvement`,
      relevantConnectors: CONNECTOR_CATEGORIES.vuln_intel || []
    });
  }
  if (gs.recon_analyst > 60 && gs.exploit_selector < 50) {
    areas.push({
      area: "Credential & Data Exposure",
      priority: "medium",
      reason: "Good recon but low exploit identification \u2014 credential exposure may be under-checked",
      relevantConnectors: CONNECTOR_CATEGORIES.credential_exposure || []
    });
  }
  if (gs.evasion_optimizer < 50) {
    areas.push({
      area: "WAF/Defense Evasion",
      priority: "medium",
      reason: `evasion_optimizer score ${gs.evasion_optimizer} \u2014 target defenses are blocking scans`,
      relevantConnectors: ["http_security"]
    });
  }
  if (areas.length > 0) {
    rationale.push(`Focus areas: ${areas.length} identified \u2014 ${areas.map((a) => `${a.area} (${a.priority})`).join(", ")}`);
  } else {
    rationale.push("Focus areas: none \u2014 all graduation scores are healthy");
  }
  return areas;
}
function applyConnectorStrategy(allConnectors, strategy) {
  const rankMap = new Map(strategy.connectorRanking.map((r) => [r.connector, r]));
  const included = allConnectors.filter((c) => {
    const rank = rankMap.get(c.name);
    return !rank || rank.include;
  });
  included.sort((a, b) => {
    const scoreA = rankMap.get(a.name)?.score ?? 50;
    const scoreB = rankMap.get(b.name)?.score ?? 50;
    return scoreB - scoreA;
  });
  return included;
}
function formatStrategySummary(strategy) {
  const lines = [
    `[AdaptiveStrategy] Confidence: ${(strategy.confidence * 100).toFixed(0)}% (${strategy.basedOn.scanCount} prior scans${strategy.basedOn.sectorLearningApplied ? ` + ${strategy.basedOn.sectorSampleCount} sector samples` : ""})`,
    `  Scan depth: mode=${strategy.scanDepth.scanMode}, concurrent=${strategy.scanDepth.maxConcurrent}, timeout=${strategy.scanDepth.connectorTimeout}ms`,
    `  Evasion: ${strategy.evasionPreset.name} \u2014 ${strategy.evasionPreset.reason}`,
    `  Connectors: ${strategy.connectorRanking.filter((r) => r.include).length} included, ${strategy.connectorRanking.filter((r) => !r.include).length} excluded`
  ];
  if (strategy.focusAreas.length > 0) {
    lines.push(`  Focus areas: ${strategy.focusAreas.map((a) => `${a.area} (${a.priority})`).join(", ")}`);
  }
  if (strategy.basedOn.sectorLearningApplied) {
    lines.push(`  Sector learning: applied (${strategy.basedOn.sectorSampleCount} samples)`);
  }
  for (const r of strategy.rationale) {
    lines.push(`  \u2192 ${r}`);
  }
  return lines.join("\n");
}
async function getSectorInsights(sector) {
  return loadSectorInsights(sector);
}
function _resetStores() {
  graduationStore.clear();
  connectorPerfStore.clear();
  hydratedDomains.clear();
  sectorInsightsCache.clear();
}
export {
  _resetStores,
  applyConnectorStrategy,
  computeAdaptiveStrategy,
  computeAdaptiveStrategyAsync,
  formatStrategySummary,
  getDomainHistory,
  getDomainHistoryAsync,
  getSectorInsights,
  recordConnectorPerformance,
  recordConnectorResults,
  recordGraduationScores
};
