import {
  getDb,
  init_db
} from "./chunk-5G2CDI2L.js";
import {
  exploitFeedbackRecords,
  init_schema
} from "./chunk-2ZYBVKLY.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-feedback-loop.ts
async function persistFeedback(entry) {
  const db = await getDb();
  if (!db) return;
  try {
    await db.insert(exploitFeedbackRecords).values({
      exploitModule: entry.moduleName,
      target: entry.targetService,
      port: null,
      service: entry.targetService,
      cveId: entry.cveIds[0] || null,
      success: entry.success,
      durationMs: entry.executionMs,
      errorType: entry.failureReason || null,
      errorMessage: entry.errorMessage || null,
      output: entry.targetVersion ? JSON.stringify({ version: entry.targetVersion, source: entry.moduleSource }) : null,
      osType: null,
      osVersion: entry.targetVersion || null
    });
  } catch (err) {
    console.error("[ExploitFeedback] DB persist failed:", err);
  }
}
async function loadFromDb() {
  const db = await getDb();
  if (!db) return [];
  try {
    const rows = await db.select().from(exploitFeedbackRecords).orderBy(exploitFeedbackRecords.createdAt);
    return rows.map((row) => {
      let parsed = {};
      try {
        parsed = row.output ? JSON.parse(row.output) : {};
      } catch {
      }
      return {
        moduleName: row.exploitModule,
        moduleSource: parsed.source || "custom",
        targetService: row.service || row.target,
        targetVersion: row.osVersion || parsed.version || null,
        cveIds: row.cveId ? [row.cveId] : [],
        success: row.success,
        executionMs: row.durationMs || 0,
        failureReason: row.errorType || null,
        errorMessage: row.errorMessage || null,
        timestamp: row.createdAt ? new Date(row.createdAt).getTime() : Date.now()
      };
    });
  } catch (err) {
    console.error("[ExploitFeedback] DB load failed:", err);
    return [];
  }
}
async function ensureCacheLoaded() {
  if (cacheInitialized) return;
  const entries = await loadFromDb();
  for (const entry of entries) {
    feedbackLogCache.push(entry);
    rebuildPerformance(entry);
  }
  cacheInitialized = true;
}
async function recordFeedback(entry, config = DEFAULT_FEEDBACK_CONFIG) {
  await ensureCacheLoaded();
  await persistFeedback(entry);
  feedbackLogCache.push(entry);
  return rebuildPerformance(entry, config);
}
function rebuildPerformance(entry, config = DEFAULT_FEEDBACK_CONFIG) {
  let perf = modulePerformanceCache.get(entry.moduleName);
  if (!perf) {
    perf = {
      moduleName: entry.moduleName,
      moduleSource: entry.moduleSource,
      targetService: entry.targetService,
      cveIds: [...entry.cveIds],
      status: "new",
      totalAttempts: 0,
      successes: 0,
      failures: 0,
      errors: 0,
      timeouts: 0,
      successRate: 0,
      reliabilityScore: 50,
      avgExecutionMs: 0,
      versionStats: /* @__PURE__ */ new Map(),
      firstUsed: entry.timestamp,
      lastUsed: entry.timestamp,
      lastSuccess: null,
      lastFailure: null,
      recentSuccessRate: 0,
      trend: "insufficient_data",
      topFailureReasons: [],
      recommendation: "New module \u2014 insufficient data for assessment."
    };
    modulePerformanceCache.set(entry.moduleName, perf);
  }
  perf.totalAttempts++;
  if (entry.success) {
    perf.successes++;
    perf.lastSuccess = entry.timestamp;
  } else {
    if (entry.errorMessage) perf.errors++;
    else if (entry.failureReason?.includes("timeout")) perf.timeouts++;
    else perf.failures++;
    perf.lastFailure = entry.timestamp;
  }
  perf.lastUsed = entry.timestamp;
  perf.successRate = Math.round(perf.successes / perf.totalAttempts * 100);
  perf.avgExecutionMs = Math.round(
    (perf.avgExecutionMs * (perf.totalAttempts - 1) + entry.executionMs) / perf.totalAttempts
  );
  if (entry.targetVersion) {
    const vStats = perf.versionStats.get(entry.targetVersion) || { attempts: 0, successes: 0, rate: 0 };
    vStats.attempts++;
    if (entry.success) vStats.successes++;
    vStats.rate = Math.round(vStats.successes / vStats.attempts * 100);
    perf.versionStats.set(entry.targetVersion, vStats);
  }
  const recentEntries = feedbackLogCache.filter((e) => e.moduleName === entry.moduleName).slice(-config.recentWindowSize);
  const recentSuccesses = recentEntries.filter((e) => e.success).length;
  perf.recentSuccessRate = recentEntries.length > 0 ? Math.round(recentSuccesses / recentEntries.length * 100) : 0;
  perf.trend = calculateTrend(entry.moduleName, config);
  perf.reliabilityScore = calculateReliabilityScore(entry.moduleName, config);
  perf.topFailureReasons = calculateTopFailureReasons(entry.moduleName);
  perf.status = determineModuleStatus(perf, config);
  perf.recommendation = generateRecommendation(perf, config);
  for (const cve of entry.cveIds) {
    if (!perf.cveIds.includes(cve)) perf.cveIds.push(cve);
  }
  return perf;
}
async function getModulePerformance(moduleName) {
  await ensureCacheLoaded();
  return modulePerformanceCache.get(moduleName) || null;
}
async function rankModulesForService(targetService) {
  await ensureCacheLoaded();
  const rankings = [];
  for (const perf of Array.from(modulePerformanceCache.values())) {
    if (perf.targetService.toLowerCase() !== targetService.toLowerCase()) continue;
    if (perf.status === "retired") continue;
    rankings.push({
      moduleName: perf.moduleName,
      reliabilityScore: perf.reliabilityScore,
      successRate: perf.successRate,
      recentTrend: perf.trend,
      status: perf.status,
      recommendation: perf.recommendation
    });
  }
  return rankings.sort((a, b) => b.reliabilityScore - a.reliabilityScore);
}
async function getModulesNeedingAttention(config = DEFAULT_FEEDBACK_CONFIG) {
  await ensureCacheLoaded();
  return Array.from(modulePerformanceCache.values()).filter(
    (p) => p.status === "degraded" || p.status === "needs_update" || p.trend === "degrading"
  );
}
async function getFeedbackSummary(config = DEFAULT_FEEDBACK_CONFIG) {
  await ensureCacheLoaded();
  const all = Array.from(modulePerformanceCache.values());
  const totalAttempts = all.reduce((sum, p) => sum + p.totalAttempts, 0);
  const totalSuccesses = all.reduce((sum, p) => sum + p.successes, 0);
  const sorted = [...all].sort((a, b) => b.reliabilityScore - a.reliabilityScore);
  return {
    totalModules: all.length,
    activeModules: all.filter((p) => p.status === "active").length,
    degradedModules: all.filter((p) => p.status === "degraded").length,
    retiredModules: all.filter((p) => p.status === "retired").length,
    needsUpdateModules: all.filter((p) => p.status === "needs_update").length,
    overallSuccessRate: totalAttempts > 0 ? Math.round(totalSuccesses / totalAttempts * 100) : 0,
    topPerformers: sorted.slice(0, 5).map(toRanking),
    worstPerformers: sorted.slice(-5).reverse().map(toRanking),
    recentTrends: {
      improving: all.filter((p) => p.trend === "improving").length,
      stable: all.filter((p) => p.trend === "stable").length,
      degrading: all.filter((p) => p.trend === "degrading").length
    }
  };
}
function toRanking(p) {
  return {
    moduleName: p.moduleName,
    reliabilityScore: p.reliabilityScore,
    successRate: p.successRate,
    recentTrend: p.trend,
    status: p.status,
    recommendation: p.recommendation
  };
}
async function generateLlmFeedbackPrompt(moduleName) {
  await ensureCacheLoaded();
  const perf = modulePerformanceCache.get(moduleName);
  if (!perf) return null;
  const versionBreakdown = Array.from(perf.versionStats.entries()).map(([ver, stats]) => `  - Version ${ver}: ${stats.rate}% success (${stats.attempts} attempts)`).join("\n");
  return `## Exploit Module Performance Feedback

**Module:** ${perf.moduleName}
**Source:** ${perf.moduleSource}
**Target Service:** ${perf.targetService}
**CVEs:** ${perf.cveIds.join(", ") || "N/A"}

### Performance Summary
- **Overall Success Rate:** ${perf.successRate}% (${perf.totalAttempts} attempts)
- **Recent Success Rate:** ${perf.recentSuccessRate}% (last ${DEFAULT_FEEDBACK_CONFIG.recentWindowSize})
- **Trend:** ${perf.trend}
- **Status:** ${perf.status}
- **Avg Execution Time:** ${perf.avgExecutionMs}ms

### Version-Specific Results
${versionBreakdown || "No version-specific data available."}

### Top Failure Reasons
${perf.topFailureReasons.map((r) => `- ${r.reason}: ${r.count} times (${r.percentage}%)`).join("\n") || "No failure data available."}

### Request
Please analyze the failure patterns above and generate an improved version of this exploit module that:
1. Addresses the top failure reasons
2. Improves compatibility with the failing versions
3. Adds better error handling and fallback mechanisms
4. Maintains the same CVE targeting scope

Return the improved module code with explanatory comments for each change.`;
}
function calculateTrend(moduleName, config) {
  const entries = feedbackLogCache.filter((e) => e.moduleName === moduleName);
  if (entries.length < config.recentWindowSize * 2) return "insufficient_data";
  const halfPoint = Math.floor(entries.length / 2);
  const olderHalf = entries.slice(0, halfPoint);
  const newerHalf = entries.slice(halfPoint);
  const olderRate = olderHalf.filter((e) => e.success).length / olderHalf.length;
  const newerRate = newerHalf.filter((e) => e.success).length / newerHalf.length;
  const diff = newerRate - olderRate;
  if (diff > 0.1) return "improving";
  if (diff < -0.1) return "degrading";
  return "stable";
}
function calculateReliabilityScore(moduleName, config) {
  const entries = feedbackLogCache.filter((e) => e.moduleName === moduleName);
  if (entries.length === 0) return 50;
  let weightedSum = 0;
  let weightTotal = 0;
  for (let i = 0; i < entries.length; i++) {
    const weight = Math.pow(config.recencyWeightDecay, entries.length - 1 - i);
    weightedSum += (entries[i].success ? 100 : 0) * weight;
    weightTotal += weight;
  }
  return Math.round(weightedSum / weightTotal);
}
function calculateTopFailureReasons(moduleName) {
  const failures = feedbackLogCache.filter((e) => e.moduleName === moduleName && !e.success);
  if (failures.length === 0) return [];
  const reasonCounts = /* @__PURE__ */ new Map();
  for (const f of failures) {
    const reason = f.failureReason || f.errorMessage || "Unknown";
    reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
  }
  return Array.from(reasonCounts.entries()).map(([reason, count]) => ({
    reason,
    count,
    percentage: Math.round(count / failures.length * 100)
  })).sort((a, b) => b.count - a.count).slice(0, 5);
}
function determineModuleStatus(perf, config) {
  if (perf.totalAttempts < 3) return "new";
  if (perf.totalAttempts >= config.minimumAttemptsForRetirement && perf.successRate <= config.retirementThreshold) return "retired";
  if (perf.successRate <= config.degradedThreshold) return "degraded";
  const daysSinceLastUse = (Date.now() - perf.lastUsed) / (24 * 60 * 60 * 1e3);
  if (daysSinceLastUse > 90) return "needs_update";
  if (perf.trend === "degrading" && perf.recentSuccessRate < perf.successRate * 0.5) return "needs_update";
  return "active";
}
function generateRecommendation(perf, config) {
  switch (perf.status) {
    case "new":
      return `New module with ${perf.totalAttempts} attempt(s). Needs more data for reliable assessment.`;
    case "active":
      if (perf.trend === "improving") return `Performing well (${perf.successRate}% success, improving). Continue using.`;
      if (perf.trend === "degrading") return `Success rate declining (${perf.recentSuccessRate}% recent vs ${perf.successRate}% overall). Monitor closely.`;
      return `Stable performance at ${perf.successRate}% success rate.`;
    case "degraded":
      return `Below threshold (${perf.successRate}% success). Top failure: ${perf.topFailureReasons[0]?.reason || "unknown"}. Consider LLM-assisted rewrite.`;
    case "retired":
      return `Retired due to consistently low success rate (${perf.successRate}%). ${perf.totalAttempts} attempts. Replace with alternative module.`;
    case "needs_update":
      return `Module needs update. ${perf.trend === "degrading" ? "Performance degrading." : "Not used recently."} Recommend LLM-assisted revision.`;
    default:
      return "No recommendation available.";
  }
}
function clearFeedbackData() {
  modulePerformanceCache.clear();
  feedbackLogCache.length = 0;
  cacheInitialized = false;
}
var DEFAULT_FEEDBACK_CONFIG, modulePerformanceCache, feedbackLogCache, cacheInitialized;
var init_exploit_feedback_loop = __esm({
  "server/lib/exploit-feedback-loop.ts"() {
    init_db();
    init_schema();
    DEFAULT_FEEDBACK_CONFIG = {
      retirementThreshold: 5,
      degradedThreshold: 30,
      minimumAttemptsForRetirement: 10,
      recentWindowSize: 10,
      recencyWeightDecay: 0.9
    };
    modulePerformanceCache = /* @__PURE__ */ new Map();
    feedbackLogCache = [];
    cacheInitialized = false;
  }
});

export {
  DEFAULT_FEEDBACK_CONFIG,
  recordFeedback,
  getModulePerformance,
  rankModulesForService,
  getModulesNeedingAttention,
  getFeedbackSummary,
  generateLlmFeedbackPrompt,
  clearFeedbackData,
  init_exploit_feedback_loop
};
