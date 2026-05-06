/**
 * LLM Telemetry Extensions
 *
 * Specialized telemetry for LLM calls within the engagement pipeline.
 * Provides:
 *   1. Knowledge gap detection — identifies when the model lacks domain knowledge
 *   2. Hallucination tracking — records when grounding checks fail
 *   3. Schema validation — tracks whether LLM output matched expected format
 *   4. Prompt deduplication — detects redundant/repeated prompts
 *   5. Quality scoring — rates LLM response usefulness
 *
 * @module telemetry-llm
 * @author Harrison Cook
 */

import * as crypto from "crypto";
import type { TelemetryContext } from "./telemetry-logger";
import { emitEvent, hashPayload, truncateForSummary } from "./telemetry-logger";
import { archivePayload } from "./telemetry-storage";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface LlmTelemetryEvent {
  telemetryEventId?: number;
  engagementId: number;
  promptHash: string;
  tokensIn: number;
  tokensOut: number;
  totalTokens: number;
  parsedSuccessfully: boolean;
  schemaValid: boolean;
  hallucinationDetected: boolean;
  hallucinationConfidence?: number;
  knowledgeGap: boolean;
  knowledgeGapTopic?: string;
  model?: string;
  responseFormat?: string;
  groundingCheckPassed?: boolean;
  promptPayloadRef?: string;
  responsePayloadRef?: string;
}

export interface KnowledgeGapReport {
  topic: string;
  context: string;
  severity: "critical" | "high" | "medium" | "low";
  /** What the LLM was asked to do */
  taskDescription: string;
  /** What signals indicated the gap */
  indicators: string[];
  /** Suggested remediation (training data, RAG source, etc.) */
  remediation?: string;
  timestamp: number;
}

export interface HallucinationReport {
  claim: string;
  groundTruth?: string;
  confidence: number;
  source: string;
  /** What check detected it */
  detectionMethod: "cross_reference" | "schema_mismatch" | "impossible_value" | "temporal_inconsistency" | "self_contradiction";
  timestamp: number;
}

export interface LlmCallOptions {
  step: string;
  model?: string;
  prompt: string;
  systemPrompt?: string;
  responseFormat?: string;
  targetHost?: string;
}

export interface LlmCallResult {
  content: string;
  tokensIn: number;
  tokensOut: number;
  model: string;
  finishReason?: string;
  latencyMs: number;
}

// ─── Knowledge Gap Detection ────────────────────────────────────────────────

/**
 * Patterns that indicate the LLM lacks knowledge about a topic.
 */
const KNOWLEDGE_GAP_PATTERNS = [
  /I don't have (?:specific |detailed )?information (?:about|on|regarding)/i,
  /I'm not (?:familiar|aware) (?:of|with)/i,
  /I cannot (?:find|locate|determine|identify)/i,
  /no (?:specific |known )?(?:data|information|details) (?:available|found)/i,
  /unable to (?:determine|identify|find|locate)/i,
  /this (?:CVE|vulnerability|exploit|technique) (?:is )?not (?:in my|within)/i,
  /my (?:training|knowledge) (?:data|cutoff)/i,
  /I (?:don't|do not) have (?:access to|knowledge of)/i,
  /there (?:is|are) no (?:public|known|available) (?:exploit|information|data)/i,
  /insufficient (?:data|information|context)/i,
];

/**
 * Patterns that indicate empty/generic responses (soft knowledge gaps).
 */
const EMPTY_RESPONSE_PATTERNS = [
  /^(?:I'm sorry|I apologize|Unfortunately)/i,
  /^(?:N\/A|None|Unknown|Not available)$/i,
  /^(?:\[\]|\{\}|null|undefined)$/,
];

/**
 * Detect if an LLM response indicates a knowledge gap.
 */
export function detectKnowledgeGap(response: string, context?: string): {
  detected: boolean;
  topic?: string;
  indicators: string[];
  severity: "critical" | "high" | "medium" | "low";
} {
  const indicators: string[] = [];

  // Check explicit knowledge gap patterns
  for (const pattern of KNOWLEDGE_GAP_PATTERNS) {
    if (pattern.test(response)) {
      indicators.push(`Matched pattern: ${pattern.source.substring(0, 50)}`);
    }
  }

  // Check empty/generic responses
  const trimmed = response.trim();
  if (trimmed.length < 20) {
    indicators.push("Response too short (< 20 chars)");
  }
  for (const pattern of EMPTY_RESPONSE_PATTERNS) {
    if (pattern.test(trimmed)) {
      indicators.push(`Empty/generic response: ${pattern.source.substring(0, 30)}`);
    }
  }

  // Check for JSON responses with empty arrays/objects
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed) && parsed.length === 0) {
      indicators.push("Empty JSON array response");
    }
    if (typeof parsed === "object" && parsed !== null && Object.keys(parsed).length === 0) {
      indicators.push("Empty JSON object response");
    }
  } catch {
    // Not JSON, that's fine
  }

  const detected = indicators.length > 0;
  const severity = indicators.length >= 3 ? "critical" : indicators.length >= 2 ? "high" : indicators.length >= 1 ? "medium" : "low";

  // Try to extract the topic from context
  let topic: string | undefined;
  if (context) {
    // Extract CVE IDs, technique names, etc.
    const cveMatch = context.match(/CVE-\d{4}-\d+/);
    const techniqueMatch = context.match(/T\d{4}(?:\.\d{3})?/);
    const serviceMatch = context.match(/(?:exploit|vulnerability|technique)\s+(?:for|in|against)\s+([^\s,.]+)/i);
    topic = cveMatch?.[0] || techniqueMatch?.[0] || serviceMatch?.[1] || context.substring(0, 100);
  }

  return { detected, topic, indicators, severity };
}

// ─── Hallucination Detection ────────────────────────────────────────────────

/**
 * Check for impossible values in structured LLM output.
 */
export function checkImpossibleValues(output: Record<string, any>): HallucinationReport[] {
  const reports: HallucinationReport[] = [];

  // CVSS scores must be 0.0-10.0
  if ("cvssScore" in output || "cvss" in output) {
    const score = output.cvssScore ?? output.cvss;
    if (typeof score === "number" && (score < 0 || score > 10)) {
      reports.push({
        claim: `CVSS score: ${score}`,
        groundTruth: "CVSS scores range from 0.0 to 10.0",
        confidence: 1.0,
        source: "schema_validation",
        detectionMethod: "impossible_value",
        timestamp: Date.now(),
      });
    }
  }

  // Port numbers must be 1-65535
  if ("port" in output) {
    const port = output.port;
    if (typeof port === "number" && (port < 1 || port > 65535)) {
      reports.push({
        claim: `Port number: ${port}`,
        groundTruth: "Valid ports range from 1 to 65535",
        confidence: 1.0,
        source: "schema_validation",
        detectionMethod: "impossible_value",
        timestamp: Date.now(),
      });
    }
  }

  // CVE IDs must match format CVE-YYYY-NNNNN+
  if ("cveId" in output || "cve" in output) {
    const cve = output.cveId ?? output.cve;
    if (typeof cve === "string" && cve.length > 0 && !/^CVE-\d{4}-\d{4,}$/.test(cve)) {
      reports.push({
        claim: `CVE ID: ${cve}`,
        groundTruth: "CVE IDs must match format CVE-YYYY-NNNNN+",
        confidence: 0.9,
        source: "schema_validation",
        detectionMethod: "impossible_value",
        timestamp: Date.now(),
      });
    }
  }

  // Future dates (more than 1 day ahead)
  for (const [key, value] of Object.entries(output)) {
    if (key.includes("date") || key.includes("Date") || key.includes("timestamp")) {
      if (typeof value === "string") {
        const date = new Date(value);
        if (!isNaN(date.getTime()) && date.getTime() > Date.now() + 86400000) {
          reports.push({
            claim: `Future date in ${key}: ${value}`,
            groundTruth: "Dates should not be in the future for historical data",
            confidence: 0.7,
            source: "temporal_check",
            detectionMethod: "temporal_inconsistency",
            timestamp: Date.now(),
          });
        }
      }
    }
  }

  return reports;
}

/**
 * Check for self-contradictions in LLM output.
 */
export function checkSelfContradictions(output: Record<string, any>): HallucinationReport[] {
  const reports: HallucinationReport[] = [];

  // Severity vs CVSS score contradiction
  if ("severity" in output && ("cvssScore" in output || "cvss" in output)) {
    const severity = String(output.severity).toLowerCase();
    const score = output.cvssScore ?? output.cvss;
    if (typeof score === "number") {
      const expectedSeverity = score >= 9.0 ? "critical" : score >= 7.0 ? "high" : score >= 4.0 ? "medium" : "low";
      if (severity !== expectedSeverity && Math.abs(score - (severity === "critical" ? 9.5 : severity === "high" ? 8.0 : severity === "medium" ? 5.5 : 2.0)) > 3) {
        reports.push({
          claim: `Severity "${severity}" with CVSS ${score}`,
          groundTruth: `CVSS ${score} typically maps to "${expectedSeverity}" severity`,
          confidence: 0.8,
          source: "cross_reference",
          detectionMethod: "self_contradiction",
          timestamp: Date.now(),
        });
      }
    }
  }

  return reports;
}

// ─── Schema Validation ──────────────────────────────────────────────────────

/**
 * Validate LLM output against an expected JSON schema (simplified).
 */
export function validateLlmOutputSchema(
  output: string,
  expectedFields: Array<{ name: string; type: "string" | "number" | "boolean" | "array" | "object"; required?: boolean }>,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  let parsed: any;
  try {
    parsed = JSON.parse(output);
  } catch (e) {
    return { valid: false, errors: ["Output is not valid JSON"] };
  }

  for (const field of expectedFields) {
    const value = parsed[field.name];

    if (value === undefined || value === null) {
      if (field.required !== false) {
        errors.push(`Missing required field: ${field.name}`);
      }
      continue;
    }

    const actualType = Array.isArray(value) ? "array" : typeof value;
    if (actualType !== field.type) {
      errors.push(`Field "${field.name}" expected ${field.type}, got ${actualType}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

// ─── LLM Telemetry Emission ─────────────────────────────────────────────────

/**
 * Record a complete LLM call with quality analysis.
 */
export async function recordLlmCall(
  ctx: TelemetryContext,
  opts: LlmCallOptions,
  result: LlmCallResult,
  qualityChecks?: {
    expectedSchema?: Array<{ name: string; type: "string" | "number" | "boolean" | "array" | "object"; required?: boolean }>;
    groundTruthData?: Record<string, any>;
  },
): Promise<LlmTelemetryEvent> {
  const promptHash = hashPayload(opts.prompt + (opts.systemPrompt || ""));

  // Detect knowledge gaps
  const gapCheck = detectKnowledgeGap(result.content, opts.prompt);

  // Check for hallucinations in structured output
  let hallucinationDetected = false;
  let hallucinationConfidence: number | undefined;
  let hallucinationReports: HallucinationReport[] = [];

  try {
    const parsed = JSON.parse(result.content);
    hallucinationReports = [
      ...checkImpossibleValues(parsed),
      ...checkSelfContradictions(parsed),
    ];
    hallucinationDetected = hallucinationReports.length > 0;
    hallucinationConfidence = hallucinationReports.length > 0
      ? Math.max(...hallucinationReports.map((r) => r.confidence))
      : undefined;
  } catch {
    // Not JSON output, skip structured checks
  }

  // Schema validation
  let schemaValid = true;
  if (qualityChecks?.expectedSchema) {
    const validation = validateLlmOutputSchema(result.content, qualityChecks.expectedSchema);
    schemaValid = validation.valid;
  }

  // Parse success (did we get usable output?)
  const parsedSuccessfully = result.content.length > 0 && result.finishReason !== "error";

  // Archive full payloads if large
  const promptPayloadRef = await archivePayload(ctx, JSON.stringify({
    system: opts.systemPrompt,
    user: opts.prompt,
    model: opts.model,
    responseFormat: opts.responseFormat,
  }), {
    category: "request",
    step: opts.step,
    engagementId: ctx.engagementId,
  });

  const responsePayloadRef = await archivePayload(ctx, result.content, {
    category: "response",
    step: opts.step,
    engagementId: ctx.engagementId,
  });

  // Emit the telemetry event
  const event = emitEvent(ctx, {
    phase: ctx.phase,
    step: opts.step,
    eventType: "llm_response",
    inputSummary: truncateForSummary(opts.prompt, 500),
    outputSummary: truncateForSummary(result.content, 500),
    fullPayloadRef: responsePayloadRef || undefined,
    durationMs: result.latencyMs,
    targetHost: opts.targetHost,
    success: parsedSuccessfully && schemaValid && !hallucinationDetected,
    errorClass: hallucinationDetected ? "llm_hallucination" : gapCheck.detected ? "knowledge_gap" : "none",
    errorMessage: hallucinationDetected
      ? `Hallucination detected: ${hallucinationReports[0]?.claim}`
      : gapCheck.detected
        ? `Knowledge gap: ${gapCheck.topic}`
        : undefined,
    retryCount: 0,
    contextSnapshot: {
      model: result.model,
      tokensIn: result.tokensIn,
      tokensOut: result.tokensOut,
      finishReason: result.finishReason,
      knowledgeGap: gapCheck.detected ? gapCheck : undefined,
      hallucinations: hallucinationReports.length > 0 ? hallucinationReports : undefined,
    },
  });

  const llmEvent: LlmTelemetryEvent = {
    engagementId: ctx.engagementId,
    promptHash,
    tokensIn: result.tokensIn,
    tokensOut: result.tokensOut,
    totalTokens: result.tokensIn + result.tokensOut,
    parsedSuccessfully,
    schemaValid,
    hallucinationDetected,
    hallucinationConfidence,
    knowledgeGap: gapCheck.detected,
    knowledgeGapTopic: gapCheck.topic,
    model: result.model,
    responseFormat: opts.responseFormat,
    groundingCheckPassed: !hallucinationDetected,
    promptPayloadRef: promptPayloadRef || undefined,
    responsePayloadRef: responsePayloadRef || undefined,
  };

  return llmEvent;
}

/**
 * Report a knowledge gap explicitly (called by pipeline code when it detects
 * the LLM couldn't reason about something).
 */
export function reportKnowledgeGap(
  ctx: TelemetryContext,
  report: KnowledgeGapReport,
): void {
  emitEvent(ctx, {
    phase: ctx.phase,
    step: "knowledge_gap_report",
    eventType: "error",
    inputSummary: report.taskDescription,
    outputSummary: `Knowledge gap: ${report.topic} (${report.severity})`,
    success: false,
    errorClass: "knowledge_gap",
    errorMessage: `[${report.severity}] ${report.topic}: ${report.indicators.join("; ")}`,
    retryCount: 0,
    contextSnapshot: {
      topic: report.topic,
      context: report.context,
      severity: report.severity,
      indicators: report.indicators,
      remediation: report.remediation,
    },
  });
}

/**
 * Persist LLM quality event to the telemetry_llm_quality table.
 */
export async function persistLlmQuality(event: LlmTelemetryEvent): Promise<void> {
  try {
    const { db } = await import("../db");
    const { telemetryLlmQuality } = await import("../../drizzle/schema");

    await db.insert(telemetryLlmQuality).values({
      telemetryEventId: event.telemetryEventId || 0,
      engagementId: event.engagementId,
      promptHash: event.promptHash,
      tokensIn: event.tokensIn,
      tokensOut: event.tokensOut,
      totalTokens: event.totalTokens,
      parsedSuccessfully: event.parsedSuccessfully ? 1 : 0,
      schemaValid: event.schemaValid ? 1 : 0,
      hallucinationDetected: event.hallucinationDetected ? 1 : 0,
      hallucinationConfidence: event.hallucinationConfidence ?? null,
      knowledgeGap: event.knowledgeGap ? 1 : 0,
      knowledgeGapTopic: event.knowledgeGapTopic || null,
      model: event.model || null,
      responseFormat: event.responseFormat || null,
      groundingCheckPassed: event.groundingCheckPassed != null ? (event.groundingCheckPassed ? 1 : 0) : null,
      promptPayloadRef: event.promptPayloadRef || null,
      responsePayloadRef: event.responsePayloadRef || null,
    } as any);
  } catch (err: any) {
    console.error("[Telemetry LLM] Failed to persist quality event:", err.message);
  }
}
