/**
 * Scan Server Tool Manifest Sync
 *
 * Compares the exploit-tooling-framework registry against actual tools
 * installed on the scan server. Provides:
 *
 * 1. Manifest sync engine — registry vs reality comparison
 * 2. Startup health check — runs on boot, logs gaps
 * 3. Per-category readiness assessment
 * 4. Auto-remediation suggestions with install commands
 * 5. Cached results for fast dashboard queries
 *
 * @module tool-manifest-sync
 */

import {
  buildToolRegistry,
  EXPLOIT_TYPE_TAXONOMY,
  type ToolRegistryEntry,
  type ExploitCategory,
  type ExploitTypeDefinition,
} from "./exploit-tooling-framework";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface ToolHealthStatus {
  name: string;
  category: string;
  required: boolean;
  available: boolean;
  version: string | null;
  verifyCommand: string;
  installCommand: string;
  alternatives: string[];
  alternativeAvailable: string | null;
  usedBy: ExploitCategory[];
  lastChecked: number;
  checkDurationMs: number;
  error: string | null;
}

export interface CategoryReadiness {
  category: ExploitCategory;
  name: string;
  totalTools: number;
  availableTools: number;
  missingRequired: string[];
  missingOptional: string[];
  readinessScore: number; // 0-100
  status: "ready" | "degraded" | "unavailable";
  remediation: string[];
}

export interface ManifestSyncReport {
  syncedAt: number;
  scanServerReachable: boolean;
  scanServerHost: string | null;
  totalTools: number;
  availableTools: number;
  missingTools: number;
  toolHealth: ToolHealthStatus[];
  categoryReadiness: CategoryReadiness[];
  overallReadiness: number; // 0-100
  overallStatus: "healthy" | "degraded" | "critical" | "offline";
  criticalGaps: string[];
  remediationPlan: RemediationStep[];
  checkDurationMs: number;
}

export interface RemediationStep {
  priority: "critical" | "high" | "medium" | "low";
  tool: string;
  reason: string;
  command: string;
  estimatedTimeSeconds: number;
  affectedCategories: ExploitCategory[];
}

// ─── Cache ─────────────────────────────────────────────────────────────────

let _cachedReport: ManifestSyncReport | null = null;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ─── Core Sync Engine ──────────────────────────────────────────────────────

/**
 * Run a full manifest sync — compare the exploit-tooling-framework registry
 * against actual tools installed on the scan server.
 */
export async function runManifestSync(options?: {
  forceRefresh?: boolean;
  skipCache?: boolean;
}): Promise<ManifestSyncReport> {
  // Return cached report if fresh
  if (!options?.forceRefresh && !options?.skipCache && _cachedReport) {
    if (Date.now() - _cachedReport.syncedAt < CACHE_TTL_MS) {
      return _cachedReport;
    }
  }

  const startTime = Date.now();
  const registry = buildToolRegistry();

  // Check scan server connectivity first
  let scanServerReachable = false;
  let scanServerHost: string | null = null;

  try {
    const { executeTool } = await import("./scan-server-executor");
    const pingResult = await executeTool({ tool: "echo", args: "manifest-sync-ping", timeoutSeconds: 10 });
    scanServerReachable = pingResult.exitCode === 0;

    // Get host from env
    scanServerHost = process.env.SCAN_SERVER_HOST || null;
  } catch {
    scanServerReachable = false;
  }

  if (!scanServerReachable) {
    const offlineReport: ManifestSyncReport = {
      syncedAt: Date.now(),
      scanServerReachable: false,
      scanServerHost,
      totalTools: registry.length,
      availableTools: 0,
      missingTools: registry.length,
      toolHealth: registry.map(t => ({
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
        error: "Scan server unreachable",
      })),
      categoryReadiness: buildCategoryReadiness(registry, []),
      overallReadiness: 0,
      overallStatus: "offline",
      criticalGaps: ["Scan server is unreachable — no tools can be verified"],
      remediationPlan: [{
        priority: "critical",
        tool: "scan-server",
        reason: "Scan server is offline or not configured",
        command: "ssh root@<SCAN_SERVER_HOST> 'systemctl status scanforge'",
        estimatedTimeSeconds: 0,
        affectedCategories: [],
      }],
      checkDurationMs: Date.now() - startTime,
    };
    _cachedReport = offlineReport;
    return offlineReport;
  }

  // Check each tool in the registry
  const toolHealth = await checkAllTools(registry);

  const availableTools = toolHealth.filter(t => t.available).length;
  const missingTools = toolHealth.filter(t => !t.available).length;

  // Build category readiness
  const categoryReadiness = buildCategoryReadiness(registry, toolHealth);

  // Identify critical gaps
  const criticalGaps: string[] = [];
  for (const cat of categoryReadiness) {
    if (cat.status === "unavailable") {
      criticalGaps.push(`${cat.name}: ${cat.missingRequired.length} required tools missing (${cat.missingRequired.join(", ")})`);
    }
  }

  // Build remediation plan
  const remediationPlan = buildRemediationPlan(toolHealth, categoryReadiness);

  // Calculate overall readiness
  const overallReadiness = Math.round(
    categoryReadiness.reduce((sum, c) => sum + c.readinessScore, 0) / Math.max(categoryReadiness.length, 1)
  );

  let overallStatus: ManifestSyncReport["overallStatus"] = "healthy";
  if (overallReadiness < 30) overallStatus = "critical";
  else if (overallReadiness < 70) overallStatus = "degraded";

  const report: ManifestSyncReport = {
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
    checkDurationMs: Date.now() - startTime,
  };

  _cachedReport = report;
  console.log(`[ManifestSync] Sync complete: ${availableTools}/${registry.length} tools available, readiness=${overallReadiness}%, status=${overallStatus}`);

  return report;
}

/**
 * Check all tools in the registry against the scan server.
 */
async function checkAllTools(registry: ToolRegistryEntry[]): Promise<ToolHealthStatus[]> {
  const { executeTool } = await import("./scan-server-executor");
  const results: ToolHealthStatus[] = [];

  // Batch check — run up to 5 concurrent checks
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
            timeoutSeconds: 15,
          });

          const available = result.exitCode === 0 && !result.stdout.includes("not found") && !result.stderr.includes("not found");
          const version = available ? (result.stdout.trim().split("\n")[0] || null) : null;

          // Check alternatives if primary is missing
          let alternativeAvailable: string | null = null;
          if (!available && tool.alternatives.length > 0) {
            for (const alt of tool.alternatives) {
              try {
                const altResult = await executeTool({
                  tool: "bash",
                  args: `-c "which ${alt} 2>/dev/null && echo available"`,
                  timeoutSeconds: 5,
                });
                if (altResult.exitCode === 0 && altResult.stdout.includes("available")) {
                  alternativeAvailable = alt;
                  break;
                }
              } catch { /* skip */ }
            }
          }

          // Determine if this tool is required (used by any exploit category)
          const requiredByCategories = EXPLOIT_TYPE_TAXONOMY.filter(
            et => et.tools.some(t => t.name === tool.name && t.required)
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
            error: null,
          };
        } catch (err: any) {
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
            error: err.message,
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

/**
 * Build per-category readiness assessments.
 */
function buildCategoryReadiness(
  registry: ToolRegistryEntry[],
  toolHealth: ToolHealthStatus[]
): CategoryReadiness[] {
  const healthMap = new Map(toolHealth.map(t => [t.name, t]));
  const readiness: CategoryReadiness[] = [];

  for (const exploitType of EXPLOIT_TYPE_TAXONOMY) {
    const requiredTools = exploitType.tools.filter(t => t.required);
    const optionalTools = exploitType.tools.filter(t => !t.required);

    const missingRequired: string[] = [];
    const missingOptional: string[] = [];
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
    const readinessScore = totalTools > 0
      ? Math.round((availableCount / totalTools) * 100)
      : 100;

    let status: CategoryReadiness["status"] = "ready";
    if (missingRequired.length > 0) {
      status = missingRequired.length === requiredTools.length ? "unavailable" : "degraded";
    } else if (readinessScore < 70) {
      status = "degraded";
    }

    const remediation: string[] = [];
    for (const missing of missingRequired) {
      const tool = exploitType.tools.find(t => t.name === missing);
      if (tool) {
        remediation.push(`[REQUIRED] Install ${missing}: ${tool.installCommand}`);
      }
    }
    for (const missing of missingOptional) {
      const tool = exploitType.tools.find(t => t.name === missing);
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
      remediation,
    });
  }

  return readiness;
}

/**
 * Build a prioritized remediation plan.
 */
function buildRemediationPlan(
  toolHealth: ToolHealthStatus[],
  categoryReadiness: CategoryReadiness[]
): RemediationStep[] {
  const steps: RemediationStep[] = [];
  const processedTools = new Set<string>();

  // Critical: tools needed by unavailable categories
  for (const cat of categoryReadiness.filter(c => c.status === "unavailable")) {
    for (const toolName of cat.missingRequired) {
      if (processedTools.has(toolName)) continue;
      processedTools.add(toolName);

      const health = toolHealth.find(t => t.name === toolName);
      if (!health) continue;

      const affectedCategories = categoryReadiness
        .filter(c => c.missingRequired.includes(toolName))
        .map(c => c.category);

      steps.push({
        priority: "critical",
        tool: toolName,
        reason: `Required by ${affectedCategories.length} unavailable exploit categories`,
        command: health.installCommand,
        estimatedTimeSeconds: 60,
        affectedCategories,
      });
    }
  }

  // High: tools needed by degraded categories
  for (const cat of categoryReadiness.filter(c => c.status === "degraded")) {
    for (const toolName of cat.missingRequired) {
      if (processedTools.has(toolName)) continue;
      processedTools.add(toolName);

      const health = toolHealth.find(t => t.name === toolName);
      if (!health) continue;

      const affectedCategories = categoryReadiness
        .filter(c => c.missingRequired.includes(toolName))
        .map(c => c.category);

      steps.push({
        priority: "high",
        tool: toolName,
        reason: `Required tool missing — ${affectedCategories.length} categories degraded`,
        command: health.installCommand,
        estimatedTimeSeconds: 60,
        affectedCategories,
      });
    }
  }

  // Medium: optional tools that would improve readiness
  for (const cat of categoryReadiness) {
    for (const toolName of cat.missingOptional) {
      if (processedTools.has(toolName)) continue;
      processedTools.add(toolName);

      const health = toolHealth.find(t => t.name === toolName);
      if (!health) continue;

      steps.push({
        priority: "medium",
        tool: toolName,
        reason: `Optional tool — would improve ${cat.name} readiness`,
        command: health.installCommand,
        estimatedTimeSeconds: 30,
        affectedCategories: [cat.category],
      });
    }
  }

  // Sort by priority
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  steps.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  return steps;
}

/**
 * Get the cached manifest sync report (or null if never synced).
 */
export function getCachedReport(): ManifestSyncReport | null {
  return _cachedReport;
}

/**
 * Run the startup health check — called when the server boots.
 * Logs results to console and caches the report.
 */
export async function startupHealthCheck(): Promise<void> {
  console.log("[ManifestSync] Running startup tool health check...");
  try {
    const report = await runManifestSync({ forceRefresh: true });

    console.log(`[ManifestSync] ═══════════════════════════════════════════`);
    console.log(`[ManifestSync] Tool Health Report`);
    console.log(`[ManifestSync] Server: ${report.scanServerHost || "not configured"} (${report.scanServerReachable ? "online" : "OFFLINE"})`);
    console.log(`[ManifestSync] Tools: ${report.availableTools}/${report.totalTools} available`);
    console.log(`[ManifestSync] Readiness: ${report.overallReadiness}% — ${report.overallStatus.toUpperCase()}`);

    if (report.criticalGaps.length > 0) {
      console.warn(`[ManifestSync] ⚠️ Critical gaps:`);
      for (const gap of report.criticalGaps) {
        console.warn(`[ManifestSync]   - ${gap}`);
      }
    }

    // Log category readiness
    for (const cat of report.categoryReadiness) {
      if (cat.status !== "ready") {
        console.log(`[ManifestSync]   ${cat.status === "unavailable" ? "❌" : "⚠️"} ${cat.name}: ${cat.readinessScore}% (missing: ${[...cat.missingRequired, ...cat.missingOptional].join(", ")})`);
      }
    }

    if (report.remediationPlan.length > 0) {
      console.log(`[ManifestSync] Remediation plan: ${report.remediationPlan.length} steps`);
      for (const step of report.remediationPlan.slice(0, 5)) {
        console.log(`[ManifestSync]   [${step.priority.toUpperCase()}] ${step.tool}: ${step.command}`);
      }
    }

    console.log(`[ManifestSync] ═══════════════════════════════════════════`);
    console.log(`[ManifestSync] Check completed in ${report.checkDurationMs}ms`);
  } catch (err: any) {
    console.error(`[ManifestSync] Startup health check failed:`, err.message);
  }
}

/**
 * Format the manifest sync report as a prompt section for the LLM.
 * Injected into exploit generation prompts so the LLM knows what tools are actually available.
 */
export function formatManifestForPrompt(): string {
  if (!_cachedReport) return "";

  const lines: string[] = [
    "## SCAN SERVER TOOL AVAILABILITY (live manifest sync)",
    "",
    `Server: ${_cachedReport.scanServerHost || "unknown"} — ${_cachedReport.overallStatus.toUpperCase()} (${_cachedReport.overallReadiness}% readiness)`,
    `Available: ${_cachedReport.availableTools}/${_cachedReport.totalTools} tools`,
    "",
  ];

  // List available tools
  const available = _cachedReport.toolHealth.filter(t => t.available);
  if (available.length > 0) {
    lines.push("### Available Tools");
    for (const tool of available) {
      lines.push(`- ${tool.name} ${tool.version ? `(${tool.version})` : ""}`);
    }
    lines.push("");
  }

  // List missing tools with alternatives
  const missing = _cachedReport.toolHealth.filter(t => !t.available);
  if (missing.length > 0) {
    lines.push("### ⚠️ Missing Tools (DO NOT use these in exploit code)");
    for (const tool of missing) {
      const altNote = tool.alternativeAvailable ? ` → use ${tool.alternativeAvailable} instead` : "";
      lines.push(`- ${tool.name}${altNote}`);
    }
    lines.push("");
  }

  // Category readiness summary
  const degradedOrUnavailable = _cachedReport.categoryReadiness.filter(c => c.status !== "ready");
  if (degradedOrUnavailable.length > 0) {
    lines.push("### Exploit Category Limitations");
    for (const cat of degradedOrUnavailable) {
      lines.push(`- ${cat.name}: ${cat.status} (${cat.readinessScore}% ready) — missing: ${cat.missingRequired.join(", ") || "optional tools only"}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
