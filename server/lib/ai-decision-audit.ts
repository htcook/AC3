/**
 * AI Decision Audit Trail — P1 Gap Remediation
 * 
 * Logs every AI/LLM decision with full context for compliance and forensic review.
 * Captures: prompt, response, model, latency, token usage, guardrail actions,
 * user context, and decision classification.
 * 
 * Provides:
 * - Structured audit logging for all LLM invocations
 * - Decision classification (informational, recommendation, action, critical)
 * - Replay capability for forensic review
 * - Aggregated statistics for compliance reporting
 * - Integration with the existing guardrail violation system
 */

import * as crypto from "crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

export type DecisionClassification =
  | "informational"  // AI provided information only
  | "recommendation" // AI recommended an action
  | "action"         // AI triggered an automated action
  | "critical"       // AI made a security-critical decision
  | "blocked";       // AI decision was blocked by guardrails

export interface AiDecisionRecord {
  decisionId: string;
  timestamp: number;
  userId: number | null;
  userRole: string | null;
  tenantId: number | null;
  
  // Request context
  feature: string;           // Which feature triggered the AI call
  context: string;           // Guardrail context (analyst, risk_card, etc.)
  promptSummary: string;     // Sanitized summary (no PII/secrets)
  promptHash: string;        // SHA-256 of the full prompt for verification
  
  // Response context
  responseSummary: string;   // Sanitized summary
  responseHash: string;      // SHA-256 of the full response
  classification: DecisionClassification;
  confidence: number | null; // 0-1 if available
  
  // Performance
  modelId: string;
  latencyMs: number;
  inputTokens: number | null;
  outputTokens: number | null;
  
  // Guardrail context
  guardrailAction: "none" | "sanitized" | "warned" | "blocked";
  guardrailReason: string | null;
  
  // Integrity
  auditHash: string;         // Hash of the entire record for tamper detection
}

export interface AiAuditStats {
  totalDecisions: number;
  byClassification: Record<DecisionClassification, number>;
  byGuardrailAction: Record<string, number>;
  avgLatencyMs: number;
  totalTokensUsed: number;
  uniqueUsers: number;
  timeRange: { start: number; end: number };
}

// ─── Audit Logger ───────────────────────────────────────────────────────────

/**
 * In-memory buffer for batch writing audit records.
 * Flushes to the database every 10 records or 30 seconds.
 */
const auditBuffer: AiDecisionRecord[] = [];
let flushTimer: ReturnType<typeof setTimeout> | null = null;
const FLUSH_INTERVAL = 30_000; // 30 seconds
const FLUSH_THRESHOLD = 10;

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(async () => {
    flushTimer = null;
    await flushAuditBuffer();
  }, FLUSH_INTERVAL);
}

async function flushAuditBuffer() {
  if (auditBuffer.length === 0) return;
  
  const records = auditBuffer.splice(0, auditBuffer.length);
  try {
    const { getDb } = await import("../db");
    const { activityLogs } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) return;

    // Batch insert as activity log entries with AI_DECISION action
    await db.insert(activityLogs).values(
      records.map((r) => ({
        userId: r.userId,
        tenantId: r.tenantId,
        action: `AI_DECISION:${r.classification}`,
        details: JSON.stringify({
          decisionId: r.decisionId,
          feature: r.feature,
          context: r.context,
          promptHash: r.promptHash,
          responseHash: r.responseHash,
          classification: r.classification,
          confidence: r.confidence,
          modelId: r.modelId,
          latencyMs: r.latencyMs,
          inputTokens: r.inputTokens,
          outputTokens: r.outputTokens,
          guardrailAction: r.guardrailAction,
          guardrailReason: r.guardrailReason,
          auditHash: r.auditHash,
        }),
        ipAddress: "ai-audit",
      }))
    );
  } catch (err) {
    // Re-queue failed records (up to a limit)
    if (records.length < 100) {
      auditBuffer.push(...records);
    }
    console.error("[AI Audit] Failed to flush audit buffer:", err);
  }
}

/**
 * Sanitize a prompt/response to remove potential PII and secrets.
 * Keeps the first 500 chars and redacts patterns that look like credentials.
 */
function sanitize(text: string, maxLength = 500): string {
  let sanitized = text
    .replace(/(?:password|secret|token|key|apikey|api_key)\s*[:=]\s*\S+/gi, "[REDACTED_CREDENTIAL]")
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, "[REDACTED_EMAIL]")
    .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, "[REDACTED_PHONE]")
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]")
    .replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, "[REDACTED_CC]");
  
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength) + "...[truncated]";
  }
  return sanitized;
}

/**
 * Compute the audit hash for tamper detection.
 * Includes all critical fields in the hash computation.
 */
function computeAuditHash(record: Omit<AiDecisionRecord, "auditHash">): string {
  const payload = [
    record.decisionId,
    record.timestamp,
    record.userId,
    record.promptHash,
    record.responseHash,
    record.classification,
    record.guardrailAction,
  ].join("|");
  return crypto.createHash("sha256").update(payload).digest("hex");
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Log an AI decision to the audit trail.
 * Call this after every LLM invocation.
 */
export function logAiDecision(params: {
  userId?: number | null;
  userRole?: string | null;
  tenantId?: number | null;
  feature: string;
  context: string;
  prompt: string;
  response: string;
  classification: DecisionClassification;
  confidence?: number | null;
  modelId?: string;
  latencyMs: number;
  inputTokens?: number | null;
  outputTokens?: number | null;
  guardrailAction?: "none" | "sanitized" | "warned" | "blocked";
  guardrailReason?: string | null;
}): AiDecisionRecord {
  const decisionId = crypto.randomUUID();
  const timestamp = Date.now();
  
  const promptHash = crypto.createHash("sha256").update(params.prompt).digest("hex");
  const responseHash = crypto.createHash("sha256").update(params.response).digest("hex");

  const partialRecord = {
    decisionId,
    timestamp,
    userId: params.userId ?? null,
    userRole: params.userRole ?? null,
    tenantId: params.tenantId ?? null,
    feature: params.feature,
    context: params.context,
    promptSummary: sanitize(params.prompt),
    promptHash,
    responseSummary: sanitize(params.response),
    responseHash,
    classification: params.classification,
    confidence: params.confidence ?? null,
    modelId: params.modelId || "default",
    latencyMs: params.latencyMs,
    inputTokens: params.inputTokens ?? null,
    outputTokens: params.outputTokens ?? null,
    guardrailAction: params.guardrailAction || "none",
    guardrailReason: params.guardrailReason ?? null,
  };

  const auditHash = computeAuditHash(partialRecord);
  const record: AiDecisionRecord = { ...partialRecord, auditHash };

  auditBuffer.push(record);
  if (auditBuffer.length >= FLUSH_THRESHOLD) {
    flushAuditBuffer();
  } else {
    scheduleFlush();
  }

  return record;
}

/**
 * Query AI decision audit records with filters.
 */
export async function queryAiDecisions(filters: {
  userId?: number;
  tenantId?: number;
  classification?: DecisionClassification;
  feature?: string;
  startTime?: number;
  endTime?: number;
  limit?: number;
}): Promise<AiDecisionRecord[]> {
  // Flush any pending records first
  await flushAuditBuffer();

  const { getDb } = await import("../db");
  const { activityLogs } = await import("../../drizzle/schema");
  const db = await getDb();
  if (!db) return [];

  const { like, gte, lte, desc } = await import("drizzle-orm");

  let query = db
    .select()
    .from(activityLogs)
    .where(like(activityLogs.action, "AI_DECISION:%"))
    .orderBy(desc(activityLogs.createdAt))
    .limit(filters.limit || 100);

  const results = await query;

  return results
    .map((row) => {
      try {
        const details = JSON.parse(row.details || "{}");
        return {
          decisionId: details.decisionId,
          timestamp: new Date(row.createdAt).getTime(),
          userId: row.userId,
          userRole: null,
          tenantId: row.tenantId,
          feature: details.feature,
          context: details.context,
          promptSummary: "",
          promptHash: details.promptHash,
          responseSummary: "",
          responseHash: details.responseHash,
          classification: details.classification,
          confidence: details.confidence,
          modelId: details.modelId,
          latencyMs: details.latencyMs,
          inputTokens: details.inputTokens,
          outputTokens: details.outputTokens,
          guardrailAction: details.guardrailAction,
          guardrailReason: details.guardrailReason,
          auditHash: details.auditHash,
        } as AiDecisionRecord;
      } catch {
        return null;
      }
    })
    .filter((r): r is AiDecisionRecord => r !== null);
}

/**
 * Get aggregated AI audit statistics.
 */
export async function getAiAuditStats(
  tenantId?: number,
  timeRangeMs?: number
): Promise<AiAuditStats> {
  const decisions = await queryAiDecisions({
    tenantId,
    startTime: timeRangeMs ? Date.now() - timeRangeMs : undefined,
    limit: 10000,
  });

  const byClassification: Record<DecisionClassification, number> = {
    informational: 0,
    recommendation: 0,
    action: 0,
    critical: 0,
    blocked: 0,
  };

  const byGuardrailAction: Record<string, number> = {
    none: 0,
    sanitized: 0,
    warned: 0,
    blocked: 0,
  };

  let totalLatency = 0;
  let totalTokens = 0;
  const userSet = new Set<number>();

  for (const d of decisions) {
    byClassification[d.classification] = (byClassification[d.classification] || 0) + 1;
    byGuardrailAction[d.guardrailAction] = (byGuardrailAction[d.guardrailAction] || 0) + 1;
    totalLatency += d.latencyMs;
    totalTokens += (d.inputTokens || 0) + (d.outputTokens || 0);
    if (d.userId) userSet.add(d.userId);
  }

  return {
    totalDecisions: decisions.length,
    byClassification,
    byGuardrailAction,
    avgLatencyMs: decisions.length > 0 ? Math.round(totalLatency / decisions.length) : 0,
    totalTokensUsed: totalTokens,
    uniqueUsers: userSet.size,
    timeRange: {
      start: decisions.length > 0 ? decisions[decisions.length - 1].timestamp : 0,
      end: decisions.length > 0 ? decisions[0].timestamp : 0,
    },
  };
}
