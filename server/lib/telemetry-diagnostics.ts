/**
 * Post-Engagement Diagnostic Summary Generator
 *
 * Generates comprehensive diagnostic reports after each engagement run.
 * Provides:
 *   1. Event breakdown by type and phase
 *   2. Failure rate analysis by error category
 *   3. Top N slowest operations
 *   4. Knowledge gaps encountered
 *   5. Retry storms (steps that retried > 2x)
 *   6. LLM token usage and cost estimation
 *   7. Overall health score (0-100)
 *   8. Markdown diagnostic report for human review
 *
 * @module telemetry-diagnostics
 * @author Harrison Cook
 */

import type { TelemetryEvent, TelemetryContext, ErrorClass } from "./telemetry-logger";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface DiagnosticSummary {
  engagementId: number;
  reportType: "post_engagement" | "phase_complete" | "error_burst" | "manual";
  totalEvents: number;
  eventTypeBreakdown: Record<string, number>;
  failureRateByCategory: Record<string, { count: number; rate: number }>;
  slowestOperations: SlowOperation[];
  knowledgeGaps: KnowledgeGapSummary[];
  retryStorms: RetryStorm[];
  totalDurationMs: number;
  llmTokensTotal: number;
  llmCostEstimate: number;
  healthScore: number;
  diagnosticMarkdown: string;
  generatedAt: number;
}

export interface SlowOperation {
  step: string;
  phase: string;
  durationMs: number;
  targetHost?: string;
  eventType: string;
  success: boolean;
}

export interface KnowledgeGapSummary {
  topic: string;
  phase: string;
  step: string;
  severity: string;
  indicators: string[];
}

export interface RetryStorm {
  step: string;
  phase: string;
  maxRetries: number;
  totalAttempts: number;
  finalSuccess: boolean;
  errorClasses: string[];
}

// ─── Cost Estimation ────────────────────────────────────────────────────────

/** Approximate cost per 1K tokens (USD) by model family */
const TOKEN_COSTS: Record<string, { input: number; output: number }> = {
  "gpt-4": { input: 0.03, output: 0.06 },
  "gpt-4o": { input: 0.005, output: 0.015 },
  "gpt-4o-mini": { input: 0.00015, output: 0.0006 },
  "gpt-3.5": { input: 0.0005, output: 0.0015 },
  "claude-3": { input: 0.015, output: 0.075 },
  "claude-3.5": { input: 0.003, output: 0.015 },
  "gemini-2.5-flash": { input: 0.00015, output: 0.0006 },
  "gemini-2.5-pro": { input: 0.00125, output: 0.01 },
  default: { input: 0.001, output: 0.003 },
};

function estimateCost(tokensIn: number, tokensOut: number, model?: string): number {
  const modelKey = model
    ? Object.keys(TOKEN_COSTS).find((k) => model.toLowerCase().includes(k)) || "default"
    : "default";
  const costs = TOKEN_COSTS[modelKey];
  return (tokensIn / 1000) * costs.input + (tokensOut / 1000) * costs.output;
}

// ─── Health Score Calculation ───────────────────────────────────────────────

/**
 * Calculate an overall health score (0-100) for the engagement run.
 *
 * Factors:
 * - Success rate (40% weight)
 * - No knowledge gaps (20% weight)
 * - No retry storms (15% weight)
 * - No hallucinations (15% weight)
 * - Reasonable latency (10% weight)
 */
function calculateHealthScore(
  events: TelemetryEvent[],
  knowledgeGaps: KnowledgeGapSummary[],
  retryStorms: RetryStorm[],
): number {
  if (events.length === 0) return 100;

  // Success rate (40 points)
  const totalWithOutcome = events.filter((e) => e.eventType === "tool_response" || e.eventType === "llm_response");
  const successCount = totalWithOutcome.filter((e) => e.success).length;
  const successRate = totalWithOutcome.length > 0 ? successCount / totalWithOutcome.length : 1;
  const successScore = Math.round(successRate * 40);

  // Knowledge gaps (20 points)
  const gapPenalty = Math.min(knowledgeGaps.length * 5, 20);
  const gapScore = 20 - gapPenalty;

  // Retry storms (15 points)
  const stormPenalty = Math.min(retryStorms.length * 5, 15);
  const stormScore = 15 - stormPenalty;

  // Hallucinations (15 points)
  const hallucinations = events.filter((e) => e.errorClass === "llm_hallucination").length;
  const hallPenalty = Math.min(hallucinations * 5, 15);
  const hallScore = 15 - hallPenalty;

  // Latency (10 points) — penalize if avg > 10s
  const timedEvents = events.filter((e) => e.durationMs && e.durationMs > 0);
  const avgLatency = timedEvents.length > 0
    ? timedEvents.reduce((sum, e) => sum + (e.durationMs || 0), 0) / timedEvents.length
    : 0;
  const latencyScore = avgLatency > 30000 ? 0 : avgLatency > 10000 ? 5 : 10;

  return Math.max(0, Math.min(100, successScore + gapScore + stormScore + hallScore + latencyScore));
}

// ─── Diagnostic Generator ───────────────────────────────────────────────────

/**
 * Generate a full diagnostic summary from telemetry events.
 */
export function generateDiagnosticSummary(
  events: TelemetryEvent[],
  opts: {
    engagementId: number;
    reportType?: "post_engagement" | "phase_complete" | "error_burst" | "manual";
    phaseFilter?: string;
  },
): DiagnosticSummary {
  const filtered = opts.phaseFilter
    ? events.filter((e) => e.phase === opts.phaseFilter)
    : events;

  // Event type breakdown
  const eventTypeBreakdown: Record<string, number> = {};
  for (const e of filtered) {
    eventTypeBreakdown[e.eventType] = (eventTypeBreakdown[e.eventType] || 0) + 1;
  }

  // Failure rate by category
  const failuresByCategory: Record<string, number> = {};
  const failures = filtered.filter((e) => !e.success);
  for (const e of failures) {
    failuresByCategory[e.errorClass] = (failuresByCategory[e.errorClass] || 0) + 1;
  }
  const failureRateByCategory: Record<string, { count: number; rate: number }> = {};
  for (const [category, count] of Object.entries(failuresByCategory)) {
    failureRateByCategory[category] = {
      count,
      rate: filtered.length > 0 ? count / filtered.length : 0,
    };
  }

  // Top 5 slowest operations
  const slowestOperations: SlowOperation[] = filtered
    .filter((e) => e.durationMs && e.durationMs > 0)
    .sort((a, b) => (b.durationMs || 0) - (a.durationMs || 0))
    .slice(0, 5)
    .map((e) => ({
      step: e.step,
      phase: e.phase,
      durationMs: e.durationMs || 0,
      targetHost: e.targetHost,
      eventType: e.eventType,
      success: e.success,
    }));

  // Knowledge gaps
  const knowledgeGaps: KnowledgeGapSummary[] = filtered
    .filter((e) => e.errorClass === "knowledge_gap")
    .map((e) => ({
      topic: e.contextSnapshot?.topic || e.errorMessage?.substring(0, 100) || "unknown",
      phase: e.phase,
      step: e.step,
      severity: e.contextSnapshot?.severity || "medium",
      indicators: e.contextSnapshot?.indicators || [],
    }));

  // Retry storms
  const retryMap = new Map<string, { attempts: number; maxRetry: number; success: boolean; errors: Set<string> }>();
  for (const e of filtered) {
    if (e.retryCount > 0 || e.eventType === "retry") {
      const key = `${e.phase}/${e.step}`;
      const existing = retryMap.get(key) || { attempts: 0, maxRetry: 0, success: false, errors: new Set<string>() };
      existing.attempts++;
      existing.maxRetry = Math.max(existing.maxRetry, e.retryCount);
      if (e.success) existing.success = true;
      if (e.errorClass !== "none") existing.errors.add(e.errorClass);
      retryMap.set(key, existing);
    }
  }
  const retryStorms: RetryStorm[] = [];
  for (const [key, data] of retryMap.entries()) {
    if (data.maxRetry >= 2) {
      const [phase, step] = key.split("/");
      retryStorms.push({
        step,
        phase,
        maxRetries: data.maxRetry,
        totalAttempts: data.attempts,
        finalSuccess: data.success,
        errorClasses: Array.from(data.errors),
      });
    }
  }

  // LLM token usage
  let llmTokensIn = 0;
  let llmTokensOut = 0;
  let llmModel: string | undefined;
  for (const e of filtered) {
    if (e.eventType === "llm_response" && e.contextSnapshot) {
      llmTokensIn += e.contextSnapshot.tokensIn || 0;
      llmTokensOut += e.contextSnapshot.tokensOut || 0;
      llmModel = e.contextSnapshot.model || llmModel;
    }
  }
  const llmTokensTotal = llmTokensIn + llmTokensOut;
  const llmCostEstimate = estimateCost(llmTokensIn, llmTokensOut, llmModel);

  // Total duration
  const timestamps = filtered
    .map((e) => e.createdAt ? new Date(e.createdAt).getTime() : 0)
    .filter((t) => t > 0);
  const totalDurationMs = timestamps.length >= 2
    ? Math.max(...timestamps) - Math.min(...timestamps)
    : filtered.reduce((sum, e) => sum + (e.durationMs || 0), 0);

  // Health score
  const healthScore = calculateHealthScore(filtered, knowledgeGaps, retryStorms);

  // Generate markdown report
  const diagnosticMarkdown = generateMarkdownReport({
    engagementId: opts.engagementId,
    totalEvents: filtered.length,
    eventTypeBreakdown,
    failureRateByCategory,
    slowestOperations,
    knowledgeGaps,
    retryStorms,
    totalDurationMs,
    llmTokensTotal,
    llmCostEstimate,
    healthScore,
    failures: failures.length,
    successRate: filtered.length > 0 ? (filtered.length - failures.length) / filtered.length : 1,
    _events: filtered,
  });

  return {
    engagementId: opts.engagementId,
    reportType: opts.reportType || "post_engagement",
    totalEvents: filtered.length,
    eventTypeBreakdown,
    failureRateByCategory,
    slowestOperations,
    knowledgeGaps,
    retryStorms,
    totalDurationMs,
    llmTokensTotal,
    llmCostEstimate,
    healthScore,
    diagnosticMarkdown,
    generatedAt: Date.now(),
  };
}

// ─── Markdown Report ────────────────────────────────────────────────────────

function generateMarkdownReport(data: {
  engagementId: number;
  totalEvents: number;
  eventTypeBreakdown: Record<string, number>;
  failureRateByCategory: Record<string, { count: number; rate: number }>;
  slowestOperations: SlowOperation[];
  knowledgeGaps: KnowledgeGapSummary[];
  retryStorms: RetryStorm[];
  totalDurationMs: number;
  llmTokensTotal: number;
  llmCostEstimate: number;
  healthScore: number;
  failures: number;
  successRate: number;
}): string {
  const lines: string[] = [];

  lines.push(`# Engagement ${data.engagementId} — Diagnostic Report`);
  lines.push("");
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push(`**Health Score:** ${data.healthScore}/100 ${data.healthScore >= 80 ? "🟢" : data.healthScore >= 50 ? "🟡" : "🔴"}`);
  lines.push(`**Duration:** ${formatDuration(data.totalDurationMs)}`);
  lines.push(`**Total Events:** ${data.totalEvents} | **Failures:** ${data.failures} | **Success Rate:** ${(data.successRate * 100).toFixed(1)}%`);
  lines.push("");

  // Event breakdown
  lines.push("## Event Breakdown");
  lines.push("");
  lines.push("| Event Type | Count | % |");
  lines.push("|---|---|---|");
  for (const [type, count] of Object.entries(data.eventTypeBreakdown).sort((a, b) => b[1] - a[1])) {
    const pct = ((count / data.totalEvents) * 100).toFixed(1);
    lines.push(`| ${type} | ${count} | ${pct}% |`);
  }
  lines.push("");

  // Failure analysis
  if (Object.keys(data.failureRateByCategory).length > 0) {
    lines.push("## Failure Analysis");
    lines.push("");
    lines.push("| Error Class | Count | Rate |");
    lines.push("|---|---|---|");
    for (const [category, info] of Object.entries(data.failureRateByCategory).sort((a, b) => b[1].count - a[1].count)) {
      lines.push(`| ${category} | ${info.count} | ${(info.rate * 100).toFixed(1)}% |`);
    }
    lines.push("");
  }

  // Slowest operations
  if (data.slowestOperations.length > 0) {
    lines.push("## Slowest Operations");
    lines.push("");
    lines.push("| Step | Phase | Duration | Target | Status |");
    lines.push("|---|---|---|---|---|");
    for (const op of data.slowestOperations) {
      const status = op.success ? "✓" : "✗";
      lines.push(`| ${op.step} | ${op.phase} | ${formatDuration(op.durationMs)} | ${op.targetHost || "-"} | ${status} |`);
    }
    lines.push("");
  }

  // Knowledge gaps
  if (data.knowledgeGaps.length > 0) {
    lines.push("## Knowledge Gaps");
    lines.push("");
    for (const gap of data.knowledgeGaps) {
      lines.push(`- **${gap.topic}** (${gap.severity}) — Phase: ${gap.phase}, Step: ${gap.step}`);
      if (gap.indicators.length > 0) {
        lines.push(`  - Indicators: ${gap.indicators.join("; ")}`);
      }
    }
    lines.push("");
  }

  // Retry storms
  if (data.retryStorms.length > 0) {
    lines.push("## Retry Storms");
    lines.push("");
    lines.push("| Step | Phase | Max Retries | Attempts | Final | Error Classes |");
    lines.push("|---|---|---|---|---|---|");
    for (const storm of data.retryStorms) {
      const final = storm.finalSuccess ? "✓" : "✗";
      lines.push(`| ${storm.step} | ${storm.phase} | ${storm.maxRetries} | ${storm.totalAttempts} | ${final} | ${storm.errorClasses.join(", ")} |`);
    }
    lines.push("");
  }

  // LLM usage
  if (data.llmTokensTotal > 0) {
    lines.push("## LLM Usage");
    lines.push("");
    lines.push(`- **Total Tokens:** ${data.llmTokensTotal.toLocaleString()}`);
    lines.push(`- **Estimated Cost:** $${data.llmCostEstimate.toFixed(4)}`);
    lines.push("");
  }

  // Graduation engine health
  try {
    const { generateGraduationDiagnosticSection } = require("./graduation-telemetry");
    // We need the raw events to compute graduation health — pass them via a closure
    // The events are available from the context that generated this report
    if ((data as any)._events) {
      const gradSection = generateGraduationDiagnosticSection((data as any)._events);
      if (gradSection) {
        lines.push(gradSection);
      }
    }
  } catch { /* graduation-telemetry not available */ }

  // Recommendations
  lines.push("## Recommendations");
  lines.push("");
  if (data.healthScore < 50) {
    lines.push("- **CRITICAL:** Health score below 50. Review failure analysis and retry storms immediately.");
  }
  if (data.knowledgeGaps.length > 0) {
    lines.push(`- **Knowledge Gaps:** ${data.knowledgeGaps.length} gap(s) detected. Consider adding RAG sources or training data for: ${data.knowledgeGaps.map((g) => g.topic).join(", ")}`);
  }
  if (data.retryStorms.length > 0) {
    lines.push(`- **Retry Storms:** ${data.retryStorms.length} step(s) with excessive retries. Check infrastructure stability for: ${data.retryStorms.map((s) => s.step).join(", ")}`);
  }
  const timeoutFailures = data.failureRateByCategory["timeout"];
  if (timeoutFailures && timeoutFailures.count > 2) {
    lines.push(`- **Timeouts:** ${timeoutFailures.count} timeout(s) detected. Consider increasing timeout thresholds or checking network connectivity.`);
  }
  if (data.healthScore >= 80 && data.knowledgeGaps.length === 0 && data.retryStorms.length === 0) {
    lines.push("- No critical issues detected. Pipeline operating within normal parameters.");
  }
  lines.push("");

  return lines.join("\n");
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

// ─── Persistence ────────────────────────────────────────────────────────────

/**
 * Persist a diagnostic summary to the telemetry_diagnostics table.
 */
export async function persistDiagnosticSummary(summary: DiagnosticSummary): Promise<void> {
  try {
    const { db } = await import("../db");
    const { telemetryDiagnostics } = await import("../../drizzle/schema");

    await db.insert(telemetryDiagnostics).values({
      engagementId: summary.engagementId,
      reportType: summary.reportType,
      totalEvents: summary.totalEvents,
      eventTypeBreakdown: summary.eventTypeBreakdown,
      failureRateByCategory: summary.failureRateByCategory,
      slowestOperations: summary.slowestOperations,
      knowledgeGaps: summary.knowledgeGaps,
      retryStorms: summary.retryStorms,
      totalDurationMs: summary.totalDurationMs,
      llmTokensTotal: summary.llmTokensTotal,
      llmCostEstimate: summary.llmCostEstimate,
      healthScore: summary.healthScore,
      diagnosticMarkdown: summary.diagnosticMarkdown,
    } as any);
  } catch (err: any) {
    console.error("[Telemetry Diagnostics] Failed to persist summary:", err.message);
  }
}

/**
 * Generate and persist a post-engagement diagnostic from the telemetry context.
 */
export async function generateAndPersistDiagnostic(ctx: TelemetryContext): Promise<DiagnosticSummary> {
  const summary = generateDiagnosticSummary(ctx.events, {
    engagementId: ctx.engagementId,
    reportType: "post_engagement",
  });

  await persistDiagnosticSummary(summary);
  return summary;
}
