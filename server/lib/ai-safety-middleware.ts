/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * AI SAFETY MIDDLEWARE — Wraps all user-facing LLM invocations with:
 *   1. Prompt injection detection (input)
 *   2. Tenant boundary validation (input)
 *   3. Rate limiting (input)
 *   4. Output sanitization (output)
 *   5. Compliance-grade audit logging (both)
 * ═══════════════════════════════════════════════════════════════════════════════
 */
import { createHash } from "crypto";
import {
  detectPromptInjection,
  sanitizeAIOutput,
  createSafeChatContext,
  buildTenantScopedSystemPrompt,
  validateTenantBoundary,
  checkRateLimit,
  logAuditEvent,
  type SafeChatContext,
} from "./ai-chat-safety";
import { getDb } from "../db";
import { aiAuditLogs } from "../../drizzle/schema";
import { TRPCError } from "@trpc/server";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SafetyMiddlewareContext {
  userId: string;
  userName?: string;
  userRole: string;
  tenantId: string;
  tenantPlan?: "free" | "pro" | "enterprise";
  engagementId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface SafetyWrappedInput {
  /** The original user message content */
  userMessage: string;
  /** Additional messages in the conversation */
  conversationHistory?: Array<{ role: string; content: string }>;
}

export interface SafetyWrappedOutput {
  /** Whether the input was allowed through */
  allowed: boolean;
  /** If blocked, the reason */
  blockReason?: string;
  /** The sanitized user input (injection patterns removed) */
  sanitizedInput?: string;
  /** The safety context for system prompt injection */
  safetyContext?: SafeChatContext;
  /** Tenant-scoped system prompt to prepend */
  tenantSystemPrompt?: string;
}

export interface OutputSafetyResult {
  /** The sanitized AI output */
  sanitizedOutput: string;
  /** Whether any modifications were made */
  modified: boolean;
  /** Safety confidence score 0-1 */
  confidence: number;
  /** Whether PII was detected and scrubbed */
  piiScrubbed: boolean;
  /** Whether cross-tenant data was detected */
  crossTenantBlocked: boolean;
}

// ─── Audit Log Persistence ───────────────────────────────────────────────────

const AUDIT_BUFFER: Array<{
  tenantId: string;
  userId: string;
  sessionId: string;
  engagementId?: string;
  action: string;
  severity: "info" | "warning" | "critical" | "alert";
  details: string;
  contentHash: string;
  injectionDetected: boolean;
  injectionPatterns?: string;
  piiDetected: boolean;
  crossTenantViolation: boolean;
  autonomyLevel?: number;
  actionBlocked: boolean;
  responseTimeMs?: number;
  modelUsed?: string;
  ipAddress?: string;
  userAgent?: string;
}> = [];

const FLUSH_THRESHOLD = 10;
const FLUSH_INTERVAL_MS = 30_000; // 30 seconds
let flushTimer: ReturnType<typeof setInterval> | null = null;

/** Start the periodic flush timer */
export function startAuditFlushTimer(): void {
  if (flushTimer) return;
  flushTimer = setInterval(() => {
    flushAuditBufferToDb().catch(err => {
      console.error("[AISafety] Audit flush error:", err.message);
    });
  }, FLUSH_INTERVAL_MS);
}

/** Flush the audit buffer to the database */
export async function flushAuditBufferToDb(): Promise<number> {
  if (AUDIT_BUFFER.length === 0) return 0;
  const entries = AUDIT_BUFFER.splice(0, AUDIT_BUFFER.length);
  try {
    const db = getDb();
    if (!db) return 0;
    // Batch insert
    await db.insert(aiAuditLogs).values(
      entries.map(e => ({
        tenantId: e.tenantId,
        userId: e.userId,
        sessionId: e.sessionId,
        engagementId: e.engagementId || null,
        action: e.action,
        severity: e.severity,
        details: e.details.slice(0, 65535), // TEXT limit
        contentHash: e.contentHash,
        injectionDetected: e.injectionDetected ? 1 : 0,
        injectionPatterns: e.injectionPatterns || null,
        piiDetected: e.piiDetected ? 1 : 0,
        crossTenantViolation: e.crossTenantViolation ? 1 : 0,
        autonomyLevel: e.autonomyLevel ?? null,
        actionBlocked: e.actionBlocked ? 1 : 0,
        responseTimeMs: e.responseTimeMs ?? null,
        modelUsed: e.modelUsed || null,
        ipAddress: e.ipAddress || null,
        userAgent: e.userAgent || null,
      }))
    );
    return entries.length;
  } catch (err: any) {
    // Re-queue on failure (with limit to prevent memory leak)
    if (AUDIT_BUFFER.length < 1000) {
      AUDIT_BUFFER.push(...entries);
    }
    console.error("[AISafety] DB flush failed:", err.message);
    return 0;
  }
}

/** Add an entry to the audit buffer and flush if threshold reached */
function bufferAuditEntry(entry: (typeof AUDIT_BUFFER)[0]): void {
  AUDIT_BUFFER.push(entry);
  // Also log to in-memory audit for the safety module
  logAuditEvent({
    timestamp: Date.now(),
    tenantId: entry.tenantId,
    userId: entry.userId,
    sessionId: entry.sessionId,
    action: entry.action,
    details: entry.details,
    severity: entry.severity,
  });
  if (AUDIT_BUFFER.length >= FLUSH_THRESHOLD) {
    flushAuditBufferToDb().catch(() => {});
  }
}

// ─── Input Safety Gate ───────────────────────────────────────────────────────

/**
 * Process user input through the safety pipeline BEFORE sending to LLM.
 * Returns either a blocked result or the sanitized input + tenant system prompt.
 */
export function processInputSafety(
  input: SafetyWrappedInput,
  ctx: SafetyMiddlewareContext,
): SafetyWrappedOutput {
  const sessionId = ctx.sessionId || `session-${ctx.userId}-${Date.now()}`;
  const contentHash = createHash("sha256")
    .update(input.userMessage)
    .digest("hex")
    .slice(0, 32);

  // 1. Create safe chat context
  const safetyContext = createSafeChatContext({
    tenantId: ctx.tenantId,
    userId: ctx.userId,
    sessionId,
    engagementId: ctx.engagementId,
    userRole: ctx.userRole as any,
    tenantPlan: ctx.tenantPlan || "pro",
  });

  // 2. Rate limit check
  const rateResult = checkRateLimit(safetyContext);
  if (!rateResult.allowed) {
    bufferAuditEntry({
      tenantId: ctx.tenantId,
      userId: ctx.userId,
      sessionId,
      engagementId: ctx.engagementId,
      action: "rate_limited",
      severity: "warning",
      details: `Rate limit exceeded. Resets at ${new Date(rateResult.resetAt).toISOString()}`,
      contentHash,
      injectionDetected: false,
      piiDetected: false,
      crossTenantViolation: false,
      actionBlocked: true,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
    return {
      allowed: false,
      blockReason: `Rate limit exceeded. Please wait ${Math.ceil((rateResult.resetAt - Date.now()) / 1000)} seconds.`,
    };
  }

  // 3. Prompt injection detection
  const injectionResult = detectPromptInjection(input.userMessage);
  if (injectionResult.shouldBlock) {
    bufferAuditEntry({
      tenantId: ctx.tenantId,
      userId: ctx.userId,
      sessionId,
      engagementId: ctx.engagementId,
      action: "injection_blocked",
      severity: "critical",
      details: `Blocked: ${injectionResult.matchedPatterns.map(p => p.name).join(", ")}`,
      contentHash,
      injectionDetected: true,
      injectionPatterns: JSON.stringify(injectionResult.matchedPatterns.map(p => p.id)),
      piiDetected: false,
      crossTenantViolation: false,
      actionBlocked: true,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
    return {
      allowed: false,
      blockReason: "Your message was blocked by our security system. Please rephrase your request.",
    };
  }

  // 4. Tenant boundary validation
  const boundaryResult = validateTenantBoundary(input.userMessage, safetyContext);
  if (!boundaryResult.valid) {
    bufferAuditEntry({
      tenantId: ctx.tenantId,
      userId: ctx.userId,
      sessionId,
      engagementId: ctx.engagementId,
      action: "tenant_boundary_violation",
      severity: "alert",
      details: `Violations: ${boundaryResult.violations.join("; ")}`,
      contentHash,
      injectionDetected: false,
      piiDetected: false,
      crossTenantViolation: true,
      actionBlocked: true,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
    return {
      allowed: false,
      blockReason: "Your request attempted to access data outside your authorized scope.",
    };
  }

  // 5. Log successful input processing
  const sanitizedInput = injectionResult.detected
    ? injectionResult.sanitizedInput
    : input.userMessage;

  if (injectionResult.detected) {
    // Detected but not blocked (low severity) — log warning
    bufferAuditEntry({
      tenantId: ctx.tenantId,
      userId: ctx.userId,
      sessionId,
      engagementId: ctx.engagementId,
      action: "injection_detected_passed",
      severity: "warning",
      details: `Low-severity patterns detected: ${injectionResult.matchedPatterns.map(p => p.name).join(", ")}`,
      contentHash,
      injectionDetected: true,
      injectionPatterns: JSON.stringify(injectionResult.matchedPatterns.map(p => p.id)),
      piiDetected: false,
      crossTenantViolation: false,
      actionBlocked: false,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
  } else {
    bufferAuditEntry({
      tenantId: ctx.tenantId,
      userId: ctx.userId,
      sessionId,
      engagementId: ctx.engagementId,
      action: "chat_input",
      severity: "info",
      details: `Input processed (${input.userMessage.length} chars)`,
      contentHash,
      injectionDetected: false,
      piiDetected: false,
      crossTenantViolation: false,
      actionBlocked: false,
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
    });
  }

  // 6. Build tenant-scoped system prompt
  const tenantSystemPrompt = buildTenantScopedSystemPrompt(safetyContext);

  return {
    allowed: true,
    sanitizedInput,
    safetyContext,
    tenantSystemPrompt,
  };
}

// ─── Output Safety Gate ──────────────────────────────────────────────────────

/**
 * Process LLM output through the safety pipeline BEFORE returning to user.
 */
export function processOutputSafety(
  output: string,
  ctx: SafetyMiddlewareContext,
): OutputSafetyResult {
  const sessionId = ctx.sessionId || `session-${ctx.userId}-${Date.now()}`;
  const startTime = Date.now();

  const result = sanitizeAIOutput(output, {
    tenantId: ctx.tenantId,
    engagementId: ctx.engagementId,
    scrubPII: true,
  });

  const modified = result.sanitizedOutput !== output;
  const responseTimeMs = Date.now() - startTime;

  // Log output processing
  bufferAuditEntry({
    tenantId: ctx.tenantId,
    userId: ctx.userId,
    sessionId,
    engagementId: ctx.engagementId,
    action: "chat_output",
    severity: result.piiDetected || result.dangerousCodeDetected ? "warning" : "info",
    details: modified
      ? `Output sanitized: PII=${result.piiDetected}, dangerous=${result.dangerousCodeDetected}, modifications=${result.modifications.length}`
      : `Output clean (${output.length} chars)`,
    contentHash: createHash("sha256").update(output).digest("hex").slice(0, 32),
    injectionDetected: false,
    piiDetected: result.piiDetected,
    crossTenantViolation: false,
    actionBlocked: false,
    responseTimeMs,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  return {
    sanitizedOutput: result.sanitizedOutput,
    modified,
    confidence: result.safetyConfidence,
    piiScrubbed: result.piiDetected,
    crossTenantBlocked: false,
  };
}

// ─── Full Pipeline Wrapper ───────────────────────────────────────────────────

/**
 * Complete safety wrapper for the campaign advisor chat.
 * Call this INSTEAD of chatWithAdvisor directly from the router.
 */
export async function safeChatWithAdvisor(
  params: {
    messages: Array<{ role: string; content: string }>;
    engagementId?: string;
    context?: any;
  },
  middlewareCtx: SafetyMiddlewareContext,
): Promise<{
  response: string;
  context: any;
  safety: {
    inputBlocked: boolean;
    outputModified: boolean;
    injectionDetected: boolean;
    confidence: number;
  };
}> {
  // Get the last user message
  const lastUserMsg = [...params.messages].reverse().find(m => m.role === "user");
  if (!lastUserMsg) {
    throw new TRPCError({ code: "BAD_REQUEST", message: "No user message found" });
  }

  // 1. Input safety gate
  const inputResult = processInputSafety(
    { userMessage: lastUserMsg.content, conversationHistory: params.messages },
    middlewareCtx,
  );

  if (!inputResult.allowed) {
    return {
      response: inputResult.blockReason || "Request blocked by security policy.",
      context: {},
      safety: {
        inputBlocked: true,
        outputModified: false,
        injectionDetected: true,
        confidence: 0,
      },
    };
  }

  // 2. Replace the user message with sanitized version
  const sanitizedMessages = params.messages.map(m => {
    if (m === lastUserMsg && inputResult.sanitizedInput) {
      return { ...m, content: inputResult.sanitizedInput };
    }
    return m;
  });

  // 3. Call the actual LLM (import dynamically to avoid circular deps)
  const { chatWithAdvisor } = await import("./campaign-advisor");
  const result = await chatWithAdvisor(
    sanitizedMessages as any,
    params.context,
    params.engagementId,
  );

  // 4. Output safety gate
  const outputResult = processOutputSafety(result.response, middlewareCtx);

  return {
    response: outputResult.sanitizedOutput,
    context: result.context,
    safety: {
      inputBlocked: false,
      outputModified: outputResult.modified,
      injectionDetected: false,
      confidence: outputResult.confidence,
    },
  };
}

// ─── Query Audit Logs ────────────────────────────────────────────────────────

export async function queryAuditLogs(params: {
  tenantId: string;
  userId?: string;
  engagementId?: string;
  action?: string;
  severity?: string;
  limit?: number;
  offset?: number;
}): Promise<{ logs: any[]; total: number }> {
  const { eq, and, desc, sql, count } = await import("drizzle-orm");
  const db = getDb();
  if (!db) return { logs: [], total: 0 };

  const conditions: any[] = [eq(aiAuditLogs.tenantId, params.tenantId)];
  if (params.userId) conditions.push(eq(aiAuditLogs.userId, params.userId));
  if (params.engagementId) conditions.push(eq(aiAuditLogs.engagementId, params.engagementId));
  if (params.action) conditions.push(eq(aiAuditLogs.action, params.action));
  if (params.severity) conditions.push(eq(aiAuditLogs.severity, params.severity as any));

  const where = conditions.length > 1 ? and(...conditions) : conditions[0];

  const [logs, [countResult]] = await Promise.all([
    db.select().from(aiAuditLogs)
      .where(where)
      .orderBy(desc(aiAuditLogs.createdAt))
      .limit(params.limit || 50)
      .offset(params.offset || 0),
    db.select({ count: count() }).from(aiAuditLogs).where(where),
  ]);

  return { logs, total: (countResult as any)?.count || 0 };
}

// Start the flush timer on module load
startAuditFlushTimer();
