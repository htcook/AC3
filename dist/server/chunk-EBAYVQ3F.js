import {
  EXPLOIT_TYPE_TAXONOMY,
  buildToolRegistry,
  init_exploit_tooling_framework
} from "./chunk-225XLGHB.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/tool-manifest-sync.ts
async function runManifestSync(options) {
  if (!options?.forceRefresh && !options?.skipCache && _cachedReport) {
    if (Date.now() - _cachedReport.syncedAt < CACHE_TTL_MS) {
      return _cachedReport;
    }
  }
  const startTime = Date.now();
  const registry = buildToolRegistry();
  let scanServerReachable = false;
  let scanServerHost = null;
  try {
    const { executeTool } = await import("./scan-server-executor-YX4MKSRW.js");
    const pingResult = await executeTool({ tool: "echo", args: "manifest-sync-ping", timeoutSeconds: 10 });
    scanServerReachable = pingResult.exitCode === 0;
    scanServerHost = process.env.SCAN_SERVER_HOST || null;
  } catch {
    scanServerReachable = false;
  }
  if (!scanServerReachable) {
    const offlineReport = {
      syncedAt: Date.now(),
      scanServerReachable: false,
      scanServerHost,
      totalTools: registry.length,
      availableTools: 0,
      missingTools: registry.length,
      toolHealth: registry.map((t) => ({
        name: t.name,
        category: t.category,
        required: true,
        available: false,
        version: null,
        verifyCommand: t.verifyCommand,
        installCommand: t.installCommand,
        alternatives: t.alternatives,
        alternativeAvailable: null,
        usedBy: t.usedBy,
        lastChecked: Date.now(),
        checkDurationMs: 0,
        error: "Scan server unreachable"
      })),
      categoryReadiness: buildCategoryReadiness(registry, []),
      overallReadiness: 0,
      overallStatus: "offline",
      criticalGaps: ["Scan server is unreachable \u2014 no tools can be verified"],
      remediationPlan: [{
        priority: "critical",
        tool: "scan-server",
        reason: "Scan server is offline or not configured",
        command: "ssh root@<SCAN_SERVER_HOST> 'systemctl status scanforge'",
        estimatedTimeSeconds: 0,
        affectedCategories: []
      }],
      checkDurationMs: Date.now() - startTime
    };
    _cachedReport = offlineReport;
    return offlineReport;
  }
  const toolHealth = await checkAllTools(registry);
  const availableTools = toolHealth.filter((t) => t.available).length;
  const missingTools = toolHealth.filter((t) => !t.available).length;
  const categoryReadiness = buildCategoryReadiness(registry, toolHealth);
  const criticalGaps = [];
  for (const cat of categoryReadiness) {
    if (cat.status === "unavailable") {
      criticalGaps.push(`${cat.name}: ${cat.missingRequired.length} required tools missing (${cat.missingRequired.join(", ")})`);
    }
  }
  const remediationPlan = buildRemediationPlan(toolHealth, categoryReadiness);
  const overallReadiness = Math.round(
    categoryReadiness.reduce((sum, c) => sum + c.readinessScore, 0) / Math.max(categoryReadiness.length, 1)
  );
  let overallStatus = "healthy";
  if (overallReadiness < 30) overallStatus = "critical";
  else if (overallReadiness < 70) overallStatus = "degraded";
  const report = {
    syncedAt: Date.now(),
    scanServerReachable: true,
    scanServerHost,
    totalTools: registry.length,
    availableTools,
    missingTools,
    toolHealth,
    categoryReadiness,
    overallReadiness,
    overallStatus,
    criticalGaps,
    remediationPlan,
    checkDurationMs: Date.now() - startTime
  };
  _cachedReport = report;
  console.log(`[ManifestSync] Sync complete: ${availableTools}/${registry.length} tools available, readiness=${overallReadiness}%, status=${overallStatus}`);
  return report;
}
async function checkAllTools(registry) {
  const { executeTool } = await import("./scan-server-executor-YX4MKSRW.js");
  const results = [];
  const batchSize = 5;
  for (let i = 0; i < registry.length; i += batchSize) {
    const batch = registry.slice(i, i + batchSize);
    const batchResults = await Promise.allSettled(
      batch.map(async (tool) => {
        const checkStart = Date.now();
        try {
          const result = await executeTool({
            tool: "bash",
            args: `-c "${tool.verifyCommand}"`,
            timeoutSeconds: 15
          });
          const available = result.exitCode === 0 && !result.stdout.includes("not found") && !result.stderr.includes("not found");
          const version = available ? result.stdout.trim().split("\n")[0] || null : null;
          let alternativeAvailable = null;
          if (!available && tool.alternatives.length > 0) {
            for (const alt of tool.alternatives) {
              try {
                const altResult = await executeTool({
                  tool: "bash",
                  args: `-c "which ${alt} 2>/dev/null && echo available"`,
                  timeoutSeconds: 5
                });
                if (altResult.exitCode === 0 && altResult.stdout.includes("available")) {
                  alternativeAvailable = alt;
                  break;
                }
              } catch {
              }
            }
          }
          const requiredByCategories = EXPLOIT_TYPE_TAXONOMY.filter(
            (et) => et.tools.some((t) => t.name === tool.name && t.required)
          );
          return {
            name: tool.name,
            category: tool.category,
            required: requiredByCategories.length > 0,
            available,
            version,
            verifyCommand: tool.verifyCommand,
            installCommand: tool.installCommand,
            alternatives: tool.alternatives,
            alternativeAvailable,
            usedBy: tool.usedBy,
            lastChecked: Date.now(),
            checkDurationMs: Date.now() - checkStart,
            error: null
          };
        } catch (err) {
          return {
            name: tool.name,
            category: tool.category,
            required: true,
            available: false,
            version: null,
            verifyCommand: tool.verifyCommand,
            installCommand: tool.installCommand,
            alternatives: tool.alternatives,
            alternativeAvailable: null,
            usedBy: tool.usedBy,
            lastChecked: Date.now(),
            checkDurationMs: Date.now() - checkStart,
            error: err.message
          };
        }
      })
    );
    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        results.push(result.value);
      }
    }
  }
  return results;
}
function buildCategoryReadiness(registry, toolHealth) {
  const healthMap = new Map(toolHealth.map((t) => [t.name, t]));
  const readiness = [];
  for (const exploitType of EXPLOIT_TYPE_TAXONOMY) {
    const requiredTools = exploitType.tools.filter((t) => t.required);
    const optionalTools = exploitType.tools.filter((t) => !t.required);
    const missingRequired = [];
    const missingOptional = [];
    let availableCount = 0;
    for (const tool of exploitType.tools) {
      const health = healthMap.get(tool.name);
      if (health?.available || health?.alternativeAvailable) {
        availableCount++;
      } else if (tool.required) {
        missingRequired.push(tool.name);
      } else {
        missingOptional.push(tool.name);
      }
    }
    const totalTools = exploitType.tools.length;
    const readinessScore = totalTools > 0 ? Math.round(availableCount / totalTools * 100) : 100;
    let status = "ready";
    if (missingRequired.length > 0) {
      status = missingRequired.length === requiredTools.length ? "unavailable" : "degraded";
    } else if (readinessScore < 70) {
      status = "degraded";
    }
    const remediation = [];
    for (const missing of missingRequired) {
      const tool = exploitType.tools.find((t) => t.name === missing);
      if (tool) {
        remediation.push(`[REQUIRED] Install ${missing}: ${tool.installCommand}`);
      }
    }
    for (const missing of missingOptional) {
      const tool = exploitType.tools.find((t) => t.name === missing);
      if (tool) {
        remediation.push(`[OPTIONAL] Install ${missing}: ${tool.installCommand}`);
      }
    }
    readiness.push({
      category: exploitType.category,
      name: exploitType.name,
      totalTools,
      availableTools: availableCount,
      missingRequired,
      missingOptional,
      readinessScore,
      status,
      remediation
    });
  }
  return readiness;
}
function buildRemediationPlan(toolHealth, categoryReadiness) {
  const steps = [];
  const processedTools = /* @__PURE__ */ new Set();
  for (const cat of categoryReadiness.filter((c) => c.status === "unavailable")) {
    for (const toolName of cat.missingRequired) {
      if (processedTools.has(toolName)) continue;
      processedTools.add(toolName);
      const health = toolHealth.find((t) => t.name === toolName);
      if (!health) continue;
      const affectedCategories = categoryReadiness.filter((c) => c.missingRequired.includes(toolName)).map((c) => c.category);
      steps.push({
        priority: "critical",
        tool: toolName,
        reason: `Required by ${affectedCategories.length} unavailable exploit categories`,
        command: health.installCommand,
        estimatedTimeSeconds: 60,
        affectedCategories
      });
    }
  }
  for (const cat of categoryReadiness.filter((c) => c.status === "degraded")) {
    for (const toolName of cat.missingRequired) {
      if (processedTools.has(toolName)) continue;
      processedTools.add(toolName);
      const health = toolHealth.find((t) => t.name === toolName);
      if (!health) continue;
      const affectedCategories = categoryReadiness.filter((c) => c.missingRequired.includes(toolName)).map((c) => c.category);
      steps.push({
        priority: "high",
        tool: toolName,
        reason: `Required tool missing \u2014 ${affectedCategories.length} categories degraded`,
        command: health.installCommand,
        estimatedTimeSeconds: 60,
        affectedCategories
      });
    }
  }
  for (const cat of categoryReadiness) {
    for (const toolName of cat.missingOptional) {
      if (processedTools.has(toolName)) continue;
      processedTools.add(toolName);
      const health = toolHealth.find((t) => t.name === toolName);
      if (!health) continue;
      steps.push({
        priority: "medium",
        tool: toolName,
        reason: `Optional tool \u2014 would improve ${cat.name} readiness`,
        command: health.installCommand,
        estimatedTimeSeconds: 30,
        affectedCategories: [cat.category]
      });
    }
  }
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  steps.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);
  return steps;
}
function getCachedReport() {
  return _cachedReport;
}
async function startupHealthCheck() {
  console.log("[ManifestSync] Running startup tool health check...");
  try {
    const report = await runManifestSync({ forceRefresh: true });
    console.log(`[ManifestSync] \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550`);
    console.log(`[ManifestSync] Tool Health Report`);
    console.log(`[ManifestSync] Server: ${report.scanServerHost || "not configured"} (${report.scanServerReachable ? "online" : "OFFLINE"})`);
    console.log(`[ManifestSync] Tools: ${report.availableTools}/${report.totalTools} available`);
    console.log(`[ManifestSync] Readiness: ${report.overallReadiness}% \u2014 ${report.overallStatus.toUpperCase()}`);
    if (report.criticalGaps.length > 0) {
      console.warn(`[ManifestSync] \u26A0\uFE0F Critical gaps:`);
      for (const gap of report.criticalGaps) {
        console.warn(`[ManifestSync]   - ${gap}`);
      }
    }
    for (const cat of report.categoryReadiness) {
      if (cat.status !== "ready") {
        console.log(`[ManifestSync]   ${cat.status === "unavailable" ? "\u274C" : "\u26A0\uFE0F"} ${cat.name}: ${cat.readinessScore}% (missing: ${[...cat.missingRequired, ...cat.missingOptional].join(", ")})`);
      }
    }
    if (report.remediationPlan.length > 0) {
      console.log(`[ManifestSync] Remediation plan: ${report.remediationPlan.length} steps`);
      for (const step of report.remediationPlan.slice(0, 5)) {
        console.log(`[ManifestSync]   [${step.priority.toUpperCase()}] ${step.tool}: ${step.command}`);
      }
    }
    console.log(`[ManifestSync] \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550`);
    console.log(`[ManifestSync] Check completed in ${report.checkDurationMs}ms`);
  } catch (err) {
    console.error(`[ManifestSync] Startup health check failed:`, err.message);
  }
}
function formatManifestForPrompt() {
  if (!_cachedReport) return "";
  const lines = [
    "## SCAN SERVER TOOL AVAILABILITY (live manifest sync)",
    "",
    `Server: ${_cachedReport.scanServerHost || "unknown"} \u2014 ${_cachedReport.overallStatus.toUpperCase()} (${_cachedReport.overallReadiness}% readiness)`,
    `Available: ${_cachedReport.availableTools}/${_cachedReport.totalTools} tools`,
    ""
  ];
  const available = _cachedReport.toolHealth.filter((t) => t.available);
  if (available.length > 0) {
    lines.push("### Available Tools");
    for (const tool of available) {
      lines.push(`- ${tool.name} ${tool.version ? `(${tool.version})` : ""}`);
    }
    lines.push("");
  }
  const missing = _cachedReport.toolHealth.filter((t) => !t.available);
  if (missing.length > 0) {
    lines.push("### \u26A0\uFE0F Missing Tools (DO NOT use these in exploit code)");
    for (const tool of missing) {
      const altNote = tool.alternativeAvailable ? ` \u2192 use ${tool.alternativeAvailable} instead` : "";
      lines.push(`- ${tool.name}${altNote}`);
    }
    lines.push("");
  }
  const degradedOrUnavailable = _cachedReport.categoryReadiness.filter((c) => c.status !== "ready");
  if (degradedOrUnavailable.length > 0) {
    lines.push("### Exploit Category Limitations");
    for (const cat of degradedOrUnavailable) {
      lines.push(`- ${cat.name}: ${cat.status} (${cat.readinessScore}% ready) \u2014 missing: ${cat.missingRequired.join(", ") || "optional tools only"}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
var _cachedReport, CACHE_TTL_MS;
var init_tool_manifest_sync = __esm({
  "server/lib/tool-manifest-sync.ts"() {
    init_exploit_tooling_framework();
    _cachedReport = null;
    CACHE_TTL_MS = 5 * 60 * 1e3;
  }
});

export {
  runManifestSync,
  getCachedReport,
  startupHealthCheck,
  formatManifestForPrompt,
  init_tool_manifest_sync
};
