/**
 * Telemetry Integration Layer
 *
 * Wires the telemetry system into the existing engagement pipeline.
 * Provides instrumented wrappers for:
 *   1. SSH Relay calls (scan server → target)
 *   2. Caldera API calls
 *   3. LLM invocations
 *   4. Evidence chain operations
 *   5. Phase orchestration hooks
 *
 * Usage: Import these wrappers instead of calling the raw functions directly
 * to get automatic telemetry recording.
 *
 * @module telemetry-integration
 * @author Harrison Cook
 */

import {
  type TelemetryContext,
  createTelemetryContext,
  forkContext,
  emitEvent,
  emitToolCall,
  emitToolResponse,
  emitError,
  emitDecision,
  emitPhaseTransition,
  withTelemetry,
  flushEvents,
  classifyError,
} from "./telemetry-logger";
import { createStorageClientFromEnv } from "./telemetry-storage";
import { recordLlmCall, reportKnowledgeGap } from "./telemetry-llm";
import { generateAndPersistDiagnostic } from "./telemetry-diagnostics";
import type { LlmCallOptions, LlmCallResult } from "./telemetry-llm";

// ─── Global Context Registry ────────────────────────────────────────────────

/** Active telemetry contexts by engagement ID */
const activeContexts = new Map<number, TelemetryContext>();

/**
 * Initialize telemetry for an engagement.
 * Call this at the start of engagement execution.
 */
export function initEngagementTelemetry(engagementId: number, opts?: {
  operatorId?: string;
  phase?: string;
  consoleLog?: boolean;
}): TelemetryContext {
  const { client, config } = createStorageClientFromEnv();

  const ctx = createTelemetryContext({
    engagementId,
    phase: opts?.phase || "initialization",
    sourceModule: "engagement-orchestrator",
    operatorId: opts?.operatorId,
    storageConfig: config,
    persistToDb: true,
    consoleLog: opts?.consoleLog ?? (process.env.NODE_ENV !== "test"),
  });

  activeContexts.set(engagementId, ctx);
  return ctx;
}

/**
 * Get the active telemetry context for an engagement.
 */
export function getTelemetryContext(engagementId: number): TelemetryContext | undefined {
  return activeContexts.get(engagementId);
}

/**
 * Finalize telemetry for an engagement.
 * Flushes events, generates diagnostic, and cleans up.
 */
export async function finalizeEngagementTelemetry(engagementId: number): Promise<void> {
  const ctx = activeContexts.get(engagementId);
  if (!ctx) return;

  try {
    // Flush remaining events to DB
    await flushEvents(ctx);

    // Generate and persist diagnostic summary
    await generateAndPersistDiagnostic(ctx);
  } catch (err: any) {
    console.error(`[Telemetry] Failed to finalize engagement ${engagementId}:`, err.message);
  } finally {
    activeContexts.delete(engagementId);
  }
}

// ─── SSH Relay Wrapper ──────────────────────────────────────────────────────

/**
 * Instrumented SSH relay call via scan server.
 * Wraps the raw HTTP call with telemetry recording.
 */
export async function instrumentedSshRelay(
  ctx: TelemetryContext,
  opts: {
    scanServerHost: string;
    scanServerPort?: number;
    targetIp: string;
    command: string;
    timeout?: number;
    step: string;
  },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const sshCtx = forkContext(ctx, "ssh-relay");
  const timeout = opts.timeout || 30000;

  const { result, success, error } = await withTelemetry(
    sshCtx,
    {
      step: opts.step,
      targetHost: opts.targetIp,
      inputSummary: `SSH → ${opts.targetIp}: ${opts.command.substring(0, 200)}`,
      maxRetries: 1,
      retryDelayMs: 2000,
    },
    async () => {
      const { executeTool } = await import('./scan-server-executor');
      const sshOpts = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes";
      const relayCmd = `ssh ${sshOpts} root@${opts.targetIp} '${opts.command.replace(/'/g, "'\\''")}'`;

      const data = await executeTool({
        tool: 'bash',
        args: `-c "${relayCmd.replace(/"/g, '\\"')}"`,
        target: opts.targetIp,
        timeoutSeconds: Math.ceil(timeout / 1000),
      });

      return {
        stdout: data.stdout || "",
        stderr: data.stderr || "",
        exitCode: data.exitCode ?? -1,
      };
    },
  );

  // Merge child events into parent
  ctx.events.push(...sshCtx.events);

  if (!success) {
    throw error || new Error("SSH relay failed");
  }

  return result;
}

/**
 * Instrumented SSH relay via the legacy scan API (port 4000).
 */
export async function instrumentedLegacyScanRelay(
  ctx: TelemetryContext,
  opts: {
    scanServerHost: string;
    command: string;
    timeout?: number;
    step: string;
    targetHost?: string;
  },
): Promise<{ stdout: string; stderr: string; exitCode: number; durationMs: number }> {
  const scanCtx = forkContext(ctx, "legacy-scan-api");
  const timeout = opts.timeout || 30000;

  const { result, success, error } = await withTelemetry(
    scanCtx,
    {
      step: opts.step,
      targetHost: opts.targetHost,
      inputSummary: `Scan API: ${opts.command.substring(0, 200)}`,
      maxRetries: 1,
      retryDelayMs: 3000,
    },
    async () => {
      const res = await fetch(`http://${opts.scanServerHost}:4000/api/scan/raw`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scan-Key": process.env.SCAN_API_KEY || "",
        },
        body: JSON.stringify({ command: opts.command, timeout }),
        signal: AbortSignal.timeout(timeout + 5000),
      });

      if (!res.ok) {
        throw new Error(`Scan API HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      if (!data.success) {
        throw new Error(`Scan API error: ${data.error || "unknown"}`);
      }

      return {
        stdout: data.result?.stdout || "",
        stderr: data.result?.stderr || "",
        exitCode: data.result?.exitCode ?? -1,
        durationMs: data.result?.durationMs || 0,
      };
    },
  );

  ctx.events.push(...scanCtx.events);

  if (!success) {
    throw error || new Error("Legacy scan relay failed");
  }

  return result;
}

// ─── Caldera API Wrapper ────────────────────────────────────────────────────

/**
 * Instrumented Caldera API call.
 */
export async function instrumentedCalderaApi<T = any>(
  ctx: TelemetryContext,
  opts: {
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
    path: string;
    body?: any;
    step: string;
  },
): Promise<T> {
  const calderaCtx = forkContext(ctx, "caldera-api");
  const baseUrl = process.env.CALDERA_BASE_URL || "";
  const apiKey = process.env.CALDERA_API_KEY || "";

  const { result, success, error } = await withTelemetry(
    calderaCtx,
    {
      step: opts.step,
      targetHost: new URL(baseUrl).hostname,
      inputSummary: `${opts.method} ${opts.path}${opts.body ? ` body=${JSON.stringify(opts.body).substring(0, 200)}` : ""}`,
      maxRetries: 2,
      retryDelayMs: 2000,
    },
    async () => {
      const res = await fetch(`${baseUrl}${opts.path}`, {
        method: opts.method,
        headers: {
          "Content-Type": "application/json",
          "KEY": apiKey,
        },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
        signal: AbortSignal.timeout(30000),
      });

      if (!res.ok) {
        const errText = await res.text().catch(() => "");
        throw new Error(`Caldera API ${res.status}: ${errText.substring(0, 200)}`);
      }

      return res.json() as Promise<T>;
    },
  );

  ctx.events.push(...calderaCtx.events);

  if (!success) {
    throw error || new Error("Caldera API call failed");
  }

  return result;
}

// ─── LLM Wrapper ────────────────────────────────────────────────────────────

/**
 * Instrumented LLM invocation with full quality tracking.
 */
export async function instrumentedLlmCall(
  ctx: TelemetryContext,
  opts: LlmCallOptions & {
    invokeFn: (messages: any[], options?: any) => Promise<any>;
    messages: any[];
    responseFormat?: any;
    expectedSchema?: Array<{ name: string; type: "string" | "number" | "boolean" | "array" | "object"; required?: boolean }>;
  },
): Promise<{ content: string; raw: any }> {
  const llmCtx = forkContext(ctx, "llm-invocation");
  const start = Date.now();

  emitToolCall(llmCtx, {
    step: opts.step,
    targetHost: opts.targetHost,
    inputSummary: `LLM: ${opts.prompt.substring(0, 300)}`,
  });

  try {
    const raw = await opts.invokeFn(opts.messages, {
      response_format: opts.responseFormat,
    });

    const latencyMs = Date.now() - start;
    const content = raw?.choices?.[0]?.message?.content || "";
    const tokensIn = raw?.usage?.prompt_tokens || 0;
    const tokensOut = raw?.usage?.completion_tokens || 0;
    const model = raw?.model || opts.model || "unknown";

    // Record LLM quality metrics
    const llmResult: LlmCallResult = {
      content,
      tokensIn,
      tokensOut,
      model,
      finishReason: raw?.choices?.[0]?.finish_reason,
      latencyMs,
    };

    const qualityEvent = await recordLlmCall(llmCtx, opts, llmResult, {
      expectedSchema: opts.expectedSchema,
    });

    // Check for knowledge gaps and report
    if (qualityEvent.knowledgeGap) {
      reportKnowledgeGap(llmCtx, {
        topic: qualityEvent.knowledgeGapTopic || "unknown",
        context: opts.prompt.substring(0, 500),
        severity: "medium",
        taskDescription: opts.step,
        indicators: ["LLM response indicated lack of knowledge"],
      });
    }

    ctx.events.push(...llmCtx.events);
    return { content, raw };
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    emitToolResponse(llmCtx, {
      step: opts.step,
      targetHost: opts.targetHost,
      outputSummary: err.message,
      durationMs: latencyMs,
      success: false,
      error: err,
    });

    ctx.events.push(...llmCtx.events);
    throw err;
  }
}

// ─── Phase Hooks ────────────────────────────────────────────────────────────

/**
 * Record a phase transition in the engagement pipeline.
 */
export function recordPhaseTransition(
  engagementId: number,
  fromPhase: string,
  toPhase: string,
): void {
  const ctx = activeContexts.get(engagementId);
  if (!ctx) return;

  emitPhaseTransition(ctx, { fromPhase, toPhase });
  ctx.phaseStartTime = Date.now();
}

/**
 * Record a pipeline decision (strategy choice, routing, etc.).
 */
export function recordPipelineDecision(
  engagementId: number,
  step: string,
  decision: string,
  reasoning?: string,
): void {
  const ctx = activeContexts.get(engagementId);
  if (!ctx) return;

  emitDecision(ctx, { step, decision, reasoning });
}

/**
 * Record a pipeline error with classification.
 */
export function recordPipelineError(
  engagementId: number,
  step: string,
  error: Error | string,
  targetHost?: string,
): void {
  const ctx = activeContexts.get(engagementId);
  if (!ctx) return;

  emitError(ctx, { step, error, targetHost });
}

/**
 * Flush events for an engagement (call periodically or at phase boundaries).
 */
export async function flushEngagementTelemetry(engagementId: number): Promise<number> {
  const ctx = activeContexts.get(engagementId);
  if (!ctx) return 0;

  return flushEvents(ctx);
}

// ─── Convenience: Auto-detect storage from env ──────────────────────────────

/**
 * Get a human-readable description of the configured storage backend.
 */
export function getConfiguredStorageInfo(): {
  provider: string;
  endpoint: string;
  bucket: string;
  available: boolean;
} {
  const { client, config } = createStorageClientFromEnv();
  if (!client || config.provider === "none") {
    return { provider: "none", endpoint: "-", bucket: "-", available: false };
  }

  switch (config.provider) {
    case "do_spaces":
      return {
        provider: "DigitalOcean Spaces",
        endpoint: config.doSpaces?.endpoint || "",
        bucket: config.doSpaces?.bucket || "",
        available: true,
      };
    case "aws_s3":
      return {
        provider: "AWS S3",
        endpoint: `s3.${config.awsS3?.region}.amazonaws.com`,
        bucket: config.awsS3?.bucket || "",
        available: true,
      };
    case "local":
      return {
        provider: "Local Filesystem",
        endpoint: "filesystem",
        bucket: config.localPath || "/tmp/ac3-telemetry",
        available: true,
      };
    default:
      return { provider: "none", endpoint: "-", bucket: "-", available: false };
  }
}
