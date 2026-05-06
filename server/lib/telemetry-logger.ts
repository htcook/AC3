/**
 * Telemetry & Observability Module
 *
 * Production-grade structured telemetry for the AC3 engagement pipeline.
 * Provides:
 *   1. Structured event emission (tool calls, LLM requests, decisions, errors)
 *   2. Error classification (infrastructure, auth, timeout, knowledge_gap, etc.)
 *   3. Timing wrappers for external calls (SSH relay, Caldera API, LLM)
 *   4. TelemetryContext threading through the pipeline
 *   5. Cloud storage provider abstraction (DO Spaces + AWS S3) for full payloads
 *   6. DB persistence to engagement_telemetry table
 *
 * @module telemetry-logger
 * @author Harrison Cook
 */

import * as crypto from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export type TelemetryEventType =
  | "tool_call"
  | "tool_response"
  | "llm_request"
  | "llm_response"
  | "decision"
  | "error"
  | "retry"
  | "phase_transition"
  | "approval_request"
  | "approval_response"
  | "evidence_captured"
  | "evidence_validated";

export type ErrorClass =
  | "none"
  | "timeout"
  | "auth_failure"
  | "connection_refused"
  | "api_error"
  | "parse_failure"
  | "llm_hallucination"
  | "knowledge_gap"
  | "logic_error"
  | "evidence_integrity"
  | "infrastructure"
  | "rate_limit"
  | "unknown";

export type StorageProvider = "do_spaces" | "aws_s3" | "local" | "none";

export interface TelemetryEvent {
  id?: number;
  engagementId: number;
  phase: string;
  step: string;
  eventType: TelemetryEventType;
  inputSummary?: string;
  outputSummary?: string;
  fullPayloadRef?: string;
  durationMs?: number;
  exitCode?: number;
  success: boolean;
  errorClass: ErrorClass;
  errorMessage?: string;
  retryCount: number;
  contextSnapshot?: Record<string, any>;
  storageProvider: StorageProvider;
  correlationId?: string;
  operatorId?: string;
  targetHost?: string;
  sourceModule?: string;
  createdAt?: string;
}

export interface TelemetryContext {
  engagementId: number;
  correlationId: string;
  operatorId?: string;
  phase: string;
  sourceModule: string;
  /** Accumulated events for batch flush */
  events: TelemetryEvent[];
  /** Start time of the current phase */
  phaseStartTime: number;
  /** Storage provider config */
  storageConfig: StorageProviderConfig;
  /** Whether to persist to DB (false for unit tests) */
  persistToDb: boolean;
  /** Whether to log to console */
  consoleLog: boolean;
}

export interface StorageProviderConfig {
  provider: StorageProvider;
  /** DO Spaces config */
  doSpaces?: {
    endpoint: string;
    bucket: string;
    region: string;
    accessKey: string;
    secretKey: string;
  };
  /** AWS S3 config */
  awsS3?: {
    bucket: string;
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
  };
  /** Local filesystem path for dev/test */
  localPath?: string;
}

export interface TimingResult<T> {
  result: T;
  durationMs: number;
  success: boolean;
  error?: Error;
}

// ─── Error Classification ───────────────────────────────────────────────────

const ERROR_PATTERNS: Array<{ pattern: RegExp; errorClass: ErrorClass }> = [
  { pattern: /ETIMEDOUT|ESOCKETTIMEDOUT|timeout|timed out/i, errorClass: "timeout" },
  { pattern: /ECONNREFUSED|connection refused|connect ECONNREFUSED/i, errorClass: "connection_refused" },
  { pattern: /401|403|unauthorized|forbidden|permission denied|auth/i, errorClass: "auth_failure" },
  { pattern: /429|rate.?limit|too many requests/i, errorClass: "rate_limit" },
  { pattern: /ENOTFOUND|EHOSTUNREACH|network|dns/i, errorClass: "infrastructure" },
  { pattern: /parse|JSON|syntax|unexpected token/i, errorClass: "parse_failure" },
  { pattern: /hallucin|fabricat|not grounded/i, errorClass: "llm_hallucination" },
  { pattern: /don't have information|cannot determine|unknown|no data/i, errorClass: "knowledge_gap" },
  { pattern: /integrity|tamper|hash mismatch|chain broken/i, errorClass: "evidence_integrity" },
  { pattern: /4\d\d|5\d\d|api error|bad request|internal server/i, errorClass: "api_error" },
];

/**
 * Classify an error into a standardized category for triage.
 */
export function classifyError(error: Error | string): ErrorClass {
  const message = typeof error === "string" ? error : error.message;
  for (const { pattern, errorClass } of ERROR_PATTERNS) {
    if (pattern.test(message)) {
      return errorClass;
    }
  }
  return "unknown";
}

/**
 * Get a human-readable description of an error class.
 */
export function describeErrorClass(errorClass: ErrorClass): string {
  const descriptions: Record<ErrorClass, string> = {
    none: "No error",
    timeout: "Operation timed out (network or process)",
    auth_failure: "Authentication or authorization failure",
    connection_refused: "Target refused connection",
    api_error: "API returned an error response",
    parse_failure: "Failed to parse response (JSON, XML, etc.)",
    llm_hallucination: "LLM output failed grounding/hallucination check",
    knowledge_gap: "LLM lacks knowledge about the requested topic",
    logic_error: "Internal logic error in pipeline code",
    evidence_integrity: "Evidence chain integrity violation",
    infrastructure: "Infrastructure failure (DNS, network, host)",
    rate_limit: "Rate limited by external service",
    unknown: "Unclassified error",
  };
  return descriptions[errorClass];
}

// ─── Context Factory ────────────────────────────────────────────────────────

/**
 * Create a new TelemetryContext for an engagement phase.
 */
export function createTelemetryContext(opts: {
  engagementId: number;
  phase: string;
  sourceModule: string;
  operatorId?: string;
  storageConfig?: StorageProviderConfig;
  persistToDb?: boolean;
  consoleLog?: boolean;
}): TelemetryContext {
  return {
    engagementId: opts.engagementId,
    correlationId: crypto.randomUUID().replace(/-/g, "").substring(0, 16),
    operatorId: opts.operatorId,
    phase: opts.phase,
    sourceModule: opts.sourceModule,
    events: [],
    phaseStartTime: Date.now(),
    storageConfig: opts.storageConfig || { provider: "none" },
    persistToDb: opts.persistToDb ?? true,
    consoleLog: opts.consoleLog ?? true,
  };
}

/**
 * Fork a child context (shares correlationId but different sourceModule).
 */
export function forkContext(parent: TelemetryContext, childModule: string): TelemetryContext {
  return {
    ...parent,
    sourceModule: childModule,
    events: [], // child has its own event buffer
    phaseStartTime: Date.now(),
  };
}

// ─── Event Emission ─────────────────────────────────────────────────────────

/**
 * Emit a telemetry event. Buffers in context and optionally logs to console.
 */
export function emitEvent(ctx: TelemetryContext, event: Omit<TelemetryEvent, "engagementId" | "correlationId" | "operatorId" | "sourceModule" | "storageProvider">): TelemetryEvent {
  const fullEvent: TelemetryEvent = {
    ...event,
    engagementId: ctx.engagementId,
    correlationId: ctx.correlationId,
    operatorId: ctx.operatorId,
    sourceModule: ctx.sourceModule,
    storageProvider: ctx.storageConfig.provider,
    createdAt: new Date().toISOString(),
  };

  ctx.events.push(fullEvent);

  if (ctx.consoleLog) {
    const icon = fullEvent.success ? "✓" : "✗";
    const errorInfo = fullEvent.errorClass !== "none" ? ` [${fullEvent.errorClass}]` : "";
    const timing = fullEvent.durationMs ? ` (${fullEvent.durationMs}ms)` : "";
    console.log(
      `[Telemetry] ${icon} ${fullEvent.phase}/${fullEvent.step} ${fullEvent.eventType}${errorInfo}${timing}`
    );
  }

  return fullEvent;
}

/**
 * Emit a tool_call event with timing.
 */
export function emitToolCall(ctx: TelemetryContext, opts: {
  step: string;
  targetHost?: string;
  inputSummary: string;
  contextSnapshot?: Record<string, any>;
}): TelemetryEvent {
  return emitEvent(ctx, {
    phase: ctx.phase,
    step: opts.step,
    eventType: "tool_call",
    inputSummary: opts.inputSummary,
    targetHost: opts.targetHost,
    success: true,
    errorClass: "none",
    retryCount: 0,
    contextSnapshot: opts.contextSnapshot,
  });
}

/**
 * Emit a tool_response event.
 */
export function emitToolResponse(ctx: TelemetryContext, opts: {
  step: string;
  targetHost?: string;
  outputSummary: string;
  durationMs: number;
  exitCode?: number;
  success: boolean;
  error?: Error | string;
  retryCount?: number;
}): TelemetryEvent {
  const errorClass = opts.success ? "none" : classifyError(opts.error || "unknown error");
  return emitEvent(ctx, {
    phase: ctx.phase,
    step: opts.step,
    eventType: "tool_response",
    outputSummary: opts.outputSummary,
    durationMs: opts.durationMs,
    exitCode: opts.exitCode,
    targetHost: opts.targetHost,
    success: opts.success,
    errorClass,
    errorMessage: opts.error ? (typeof opts.error === "string" ? opts.error : opts.error.message) : undefined,
    retryCount: opts.retryCount || 0,
  });
}

/**
 * Emit an error event.
 */
export function emitError(ctx: TelemetryContext, opts: {
  step: string;
  error: Error | string;
  targetHost?: string;
  retryCount?: number;
  contextSnapshot?: Record<string, any>;
}): TelemetryEvent {
  const errorClass = classifyError(opts.error);
  const message = typeof opts.error === "string" ? opts.error : opts.error.message;
  return emitEvent(ctx, {
    phase: ctx.phase,
    step: opts.step,
    eventType: "error",
    outputSummary: message.substring(0, 2048),
    targetHost: opts.targetHost,
    success: false,
    errorClass,
    errorMessage: message,
    retryCount: opts.retryCount || 0,
    contextSnapshot: opts.contextSnapshot,
  });
}

/**
 * Emit a decision event (pipeline made a routing/strategy choice).
 */
export function emitDecision(ctx: TelemetryContext, opts: {
  step: string;
  decision: string;
  reasoning?: string;
  contextSnapshot?: Record<string, any>;
}): TelemetryEvent {
  return emitEvent(ctx, {
    phase: ctx.phase,
    step: opts.step,
    eventType: "decision",
    inputSummary: opts.decision,
    outputSummary: opts.reasoning,
    success: true,
    errorClass: "none",
    retryCount: 0,
    contextSnapshot: opts.contextSnapshot,
  });
}

/**
 * Emit a phase_transition event.
 */
export function emitPhaseTransition(ctx: TelemetryContext, opts: {
  fromPhase: string;
  toPhase: string;
  durationMs?: number;
}): TelemetryEvent {
  ctx.phase = opts.toPhase;
  return emitEvent(ctx, {
    phase: opts.toPhase,
    step: "phase_transition",
    eventType: "phase_transition",
    inputSummary: `${opts.fromPhase} → ${opts.toPhase}`,
    durationMs: opts.durationMs || (Date.now() - ctx.phaseStartTime),
    success: true,
    errorClass: "none",
    retryCount: 0,
  });
}

// ─── Timing Wrappers ────────────────────────────────────────────────────────

/**
 * Wrap an async operation with timing and automatic telemetry emission.
 * Records both the tool_call and tool_response events.
 */
export async function withTelemetry<T>(
  ctx: TelemetryContext,
  opts: {
    step: string;
    targetHost?: string;
    inputSummary: string;
    maxRetries?: number;
    retryDelayMs?: number;
  },
  fn: () => Promise<T>,
): Promise<TimingResult<T>> {
  const maxRetries = opts.maxRetries || 0;
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      emitEvent(ctx, {
        phase: ctx.phase,
        step: opts.step,
        eventType: "retry",
        inputSummary: `Retry ${attempt}/${maxRetries}`,
        targetHost: opts.targetHost,
        success: true,
        errorClass: "none",
        retryCount: attempt,
      });
      await new Promise((r) => setTimeout(r, opts.retryDelayMs || 1000));
    }

    emitToolCall(ctx, {
      step: opts.step,
      targetHost: opts.targetHost,
      inputSummary: opts.inputSummary,
    });

    const start = Date.now();
    try {
      const result = await fn();
      const durationMs = Date.now() - start;

      emitToolResponse(ctx, {
        step: opts.step,
        targetHost: opts.targetHost,
        outputSummary: summarizeResult(result),
        durationMs,
        success: true,
        retryCount: attempt,
      });

      return { result, durationMs, success: true };
    } catch (err: any) {
      const durationMs = Date.now() - start;
      lastError = err;

      emitToolResponse(ctx, {
        step: opts.step,
        targetHost: opts.targetHost,
        outputSummary: err.message?.substring(0, 2048) || "Unknown error",
        durationMs,
        success: false,
        error: err,
        retryCount: attempt,
      });

      // Don't retry on auth failures or logic errors
      const errorClass = classifyError(err);
      if (errorClass === "auth_failure" || errorClass === "logic_error") {
        break;
      }
    }
  }

  return {
    result: undefined as any,
    durationMs: 0,
    success: false,
    error: lastError,
  };
}

/**
 * Wrap a synchronous operation with timing.
 */
export function withTelemetrySync<T>(
  ctx: TelemetryContext,
  opts: { step: string; inputSummary: string },
  fn: () => T,
): TimingResult<T> {
  const start = Date.now();
  try {
    const result = fn();
    const durationMs = Date.now() - start;
    emitToolResponse(ctx, {
      step: opts.step,
      outputSummary: summarizeResult(result),
      durationMs,
      success: true,
    });
    return { result, durationMs, success: true };
  } catch (err: any) {
    const durationMs = Date.now() - start;
    emitError(ctx, { step: opts.step, error: err });
    return { result: undefined as any, durationMs, success: false, error: err };
  }
}

// ─── Flush / Persist ────────────────────────────────────────────────────────

/**
 * Flush buffered events to the database.
 * Returns the number of events persisted.
 */
export async function flushEvents(ctx: TelemetryContext): Promise<number> {
  if (!ctx.persistToDb || ctx.events.length === 0) {
    return 0;
  }

  const events = [...ctx.events];
  ctx.events = [];

  try {
    // Dynamic import to avoid circular deps at module load time
    const { db } = await import("../db");
    const { engagementTelemetry } = await import("../../drizzle/schema");

    const rows = events.map((e) => ({
      engagementId: e.engagementId,
      phase: e.phase,
      step: e.step,
      eventType: e.eventType,
      inputSummary: e.inputSummary?.substring(0, 65535) || null,
      outputSummary: e.outputSummary?.substring(0, 65535) || null,
      fullPayloadRef: e.fullPayloadRef || null,
      durationMs: e.durationMs || null,
      exitCode: e.exitCode ?? null,
      success: e.success ? 1 : 0,
      errorClass: e.errorClass,
      errorMessage: e.errorMessage?.substring(0, 65535) || null,
      retryCount: e.retryCount,
      contextSnapshot: e.contextSnapshot || null,
      storageProvider: e.storageProvider,
      correlationId: e.correlationId || null,
      operatorId: e.operatorId || null,
      targetHost: e.targetHost || null,
      sourceModule: e.sourceModule || null,
    }));

    // Batch insert in chunks of 50
    for (let i = 0; i < rows.length; i += 50) {
      const chunk = rows.slice(i, i + 50);
      await db.insert(engagementTelemetry).values(chunk as any);
    }

    return events.length;
  } catch (err: any) {
    console.error("[Telemetry] Failed to flush events to DB:", err.message);
    // Put events back so they aren't lost
    ctx.events = [...events, ...ctx.events];
    return 0;
  }
}

/**
 * Get summary statistics from the current event buffer.
 */
export function getBufferStats(ctx: TelemetryContext): {
  total: number;
  byType: Record<string, number>;
  byErrorClass: Record<string, number>;
  failureRate: number;
  avgDurationMs: number;
} {
  const total = ctx.events.length;
  const byType: Record<string, number> = {};
  const byErrorClass: Record<string, number> = {};
  let failures = 0;
  let totalDuration = 0;
  let durationCount = 0;

  for (const e of ctx.events) {
    byType[e.eventType] = (byType[e.eventType] || 0) + 1;
    if (!e.success) {
      failures++;
      byErrorClass[e.errorClass] = (byErrorClass[e.errorClass] || 0) + 1;
    }
    if (e.durationMs) {
      totalDuration += e.durationMs;
      durationCount++;
    }
  }

  return {
    total,
    byType,
    byErrorClass,
    failureRate: total > 0 ? failures / total : 0,
    avgDurationMs: durationCount > 0 ? Math.round(totalDuration / durationCount) : 0,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Truncate and summarize a result for the outputSummary field.
 */
function summarizeResult(result: any): string {
  if (result === null || result === undefined) return "null";
  if (typeof result === "string") return result.substring(0, 2048);
  if (typeof result === "number" || typeof result === "boolean") return String(result);
  try {
    const json = JSON.stringify(result);
    return json.length > 2048 ? json.substring(0, 2045) + "..." : json;
  } catch {
    return "[unserializable]";
  }
}

/**
 * Generate a deterministic hash for deduplication.
 */
export function hashPayload(payload: string): string {
  return crypto.createHash("sha256").update(payload).digest("hex").substring(0, 16);
}

/**
 * Truncate input for summary fields (keeps first N chars).
 */
export function truncateForSummary(input: string, maxLen: number = 2048): string {
  if (input.length <= maxLen) return input;
  return input.substring(0, maxLen - 3) + "...";
}
