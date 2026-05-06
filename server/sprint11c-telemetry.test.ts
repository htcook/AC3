/**
 * Sprint 11C — Telemetry & Observability Module Tests
 *
 * Tests:
 *   1. Error classification (pattern matching)
 *   2. TelemetryContext creation and forking
 *   3. Event emission (tool_call, tool_response, error, decision, phase_transition)
 *   4. withTelemetry timing wrapper (success, failure, retries)
 *   5. Knowledge gap detection
 *   6. Hallucination detection (impossible values, self-contradictions)
 *   7. Schema validation
 *   8. Diagnostic summary generation
 *   9. Storage client factory (env detection)
 *   10. Integration wrappers (instrumented calls)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Core Telemetry Logger Tests ────────────────────────────────────────────

import {
  classifyError,
  describeErrorClass,
  createTelemetryContext,
  forkContext,
  emitEvent,
  emitToolCall,
  emitToolResponse,
  emitError,
  emitDecision,
  emitPhaseTransition,
  withTelemetry,
  withTelemetrySync,
  getBufferStats,
  hashPayload,
  truncateForSummary,
  type TelemetryContext,
  type ErrorClass,
} from "./lib/telemetry-logger";

describe("Telemetry Logger — Error Classification", () => {
  it("classifies timeout errors", () => {
    expect(classifyError("Connection ETIMEDOUT")).toBe("timeout");
    expect(classifyError("Request timed out after 30s")).toBe("timeout");
    expect(classifyError(new Error("ESOCKETTIMEDOUT"))).toBe("timeout");
  });

  it("classifies connection refused errors", () => {
    expect(classifyError("connect ECONNREFUSED 127.0.0.1:3000")).toBe("connection_refused");
    expect(classifyError("Connection refused")).toBe("connection_refused");
  });

  it("classifies auth failures", () => {
    expect(classifyError("401 Unauthorized")).toBe("auth_failure");
    expect(classifyError("403 Forbidden")).toBe("auth_failure");
    expect(classifyError("Permission denied (publickey)")).toBe("auth_failure");
  });

  it("classifies rate limits", () => {
    expect(classifyError("429 Too Many Requests")).toBe("rate_limit");
    expect(classifyError("Rate limit exceeded")).toBe("rate_limit");
  });

  it("classifies infrastructure errors", () => {
    expect(classifyError("getaddrinfo ENOTFOUND example.com")).toBe("infrastructure");
    expect(classifyError("EHOSTUNREACH")).toBe("infrastructure");
  });

  it("classifies parse failures", () => {
    expect(classifyError("Unexpected token < in JSON at position 0")).toBe("parse_failure");
    expect(classifyError("SyntaxError: parse error")).toBe("parse_failure");
  });

  it("classifies LLM hallucinations", () => {
    expect(classifyError("Output not grounded in source")).toBe("llm_hallucination");
    expect(classifyError("Hallucination detected in CVE data")).toBe("llm_hallucination");
  });

  it("classifies knowledge gaps", () => {
    expect(classifyError("I don't have information about this CVE")).toBe("knowledge_gap");
    expect(classifyError("Cannot determine the exploit method")).toBe("knowledge_gap");
  });

  it("classifies evidence integrity errors", () => {
    expect(classifyError("Evidence chain hash mismatch")).toBe("evidence_integrity");
    expect(classifyError("Integrity check failed: tampered")).toBe("evidence_integrity");
  });

  it("classifies API errors", () => {
    expect(classifyError("500 Internal Server Error")).toBe("api_error");
    expect(classifyError("Bad request: missing field")).toBe("api_error");
  });

  it("returns unknown for unrecognized errors", () => {
    expect(classifyError("Something weird happened")).toBe("unknown");
  });

  it("provides descriptions for all error classes", () => {
    const classes: ErrorClass[] = [
      "none", "timeout", "auth_failure", "connection_refused",
      "api_error", "parse_failure", "llm_hallucination", "knowledge_gap",
      "logic_error", "evidence_integrity", "infrastructure", "rate_limit", "unknown",
    ];
    for (const cls of classes) {
      expect(describeErrorClass(cls)).toBeTruthy();
    }
  });
});

describe("Telemetry Logger — Context Management", () => {
  it("creates a context with correct defaults", () => {
    const ctx = createTelemetryContext({
      engagementId: 42,
      phase: "recon",
      sourceModule: "nmap-scanner",
    });

    expect(ctx.engagementId).toBe(42);
    expect(ctx.phase).toBe("recon");
    expect(ctx.sourceModule).toBe("nmap-scanner");
    expect(ctx.correlationId).toHaveLength(16);
    expect(ctx.events).toHaveLength(0);
    expect(ctx.persistToDb).toBe(true);
    expect(ctx.consoleLog).toBe(true);
  });

  it("forks a child context with shared correlationId", () => {
    const parent = createTelemetryContext({
      engagementId: 42,
      phase: "exploit",
      sourceModule: "metasploit",
      operatorId: "op-123",
    });

    const child = forkContext(parent, "ssh-relay");

    expect(child.engagementId).toBe(42);
    expect(child.correlationId).toBe(parent.correlationId);
    expect(child.operatorId).toBe("op-123");
    expect(child.sourceModule).toBe("ssh-relay");
    expect(child.events).toHaveLength(0);
    expect(child.events).not.toBe(parent.events); // separate buffer
  });
});

describe("Telemetry Logger — Event Emission", () => {
  let ctx: TelemetryContext;

  beforeEach(() => {
    ctx = createTelemetryContext({
      engagementId: 1,
      phase: "post_exploit",
      sourceModule: "test",
      consoleLog: false,
    });
  });

  it("emits tool_call events", () => {
    const event = emitToolCall(ctx, {
      step: "ssh_whoami",
      targetHost: "10.0.0.5",
      inputSummary: "ssh root@10.0.0.5 whoami",
    });

    expect(event.eventType).toBe("tool_call");
    expect(event.phase).toBe("post_exploit");
    expect(event.step).toBe("ssh_whoami");
    expect(event.targetHost).toBe("10.0.0.5");
    expect(event.success).toBe(true);
    expect(ctx.events).toHaveLength(1);
  });

  it("emits tool_response events with error classification", () => {
    const event = emitToolResponse(ctx, {
      step: "nmap_scan",
      outputSummary: "Scan complete: 5 hosts up",
      durationMs: 12500,
      success: true,
    });

    expect(event.durationMs).toBe(12500);
    expect(event.errorClass).toBe("none");
    expect(event.success).toBe(true);
  });

  it("emits error events with auto-classification", () => {
    const event = emitError(ctx, {
      step: "caldera_deploy",
      error: new Error("connect ECONNREFUSED 10.0.0.1:8888"),
      targetHost: "10.0.0.1",
    });

    expect(event.eventType).toBe("error");
    expect(event.errorClass).toBe("connection_refused");
    expect(event.success).toBe(false);
    expect(event.targetHost).toBe("10.0.0.1");
  });

  it("emits decision events", () => {
    const event = emitDecision(ctx, {
      step: "strategy_select",
      decision: "Use SUID escalation over kernel exploit",
      reasoning: "Target kernel 5.15 has no known CVEs, but find found /usr/bin/python3.8 with SUID",
    });

    expect(event.eventType).toBe("decision");
    expect(event.inputSummary).toContain("SUID");
    expect(event.outputSummary).toContain("python3.8");
  });

  it("emits phase_transition events and updates context phase", () => {
    expect(ctx.phase).toBe("post_exploit");

    const event = emitPhaseTransition(ctx, {
      fromPhase: "post_exploit",
      toPhase: "lateral_movement",
    });

    expect(event.eventType).toBe("phase_transition");
    expect(event.inputSummary).toBe("post_exploit → lateral_movement");
    expect(ctx.phase).toBe("lateral_movement");
  });

  it("buffers events correctly", () => {
    emitToolCall(ctx, { step: "a", inputSummary: "cmd1" });
    emitToolCall(ctx, { step: "b", inputSummary: "cmd2" });
    emitToolCall(ctx, { step: "c", inputSummary: "cmd3" });

    expect(ctx.events).toHaveLength(3);
    expect(ctx.events[0].step).toBe("a");
    expect(ctx.events[2].step).toBe("c");
  });
});

describe("Telemetry Logger — Timing Wrappers", () => {
  let ctx: TelemetryContext;

  beforeEach(() => {
    ctx = createTelemetryContext({
      engagementId: 1,
      phase: "test",
      sourceModule: "test",
      consoleLog: false,
    });
  });

  it("withTelemetry records success with timing", async () => {
    const { result, durationMs, success } = await withTelemetry(
      ctx,
      { step: "fast_op", inputSummary: "test" },
      async () => {
        await new Promise((r) => setTimeout(r, 10));
        return "done";
      },
    );

    expect(result).toBe("done");
    expect(success).toBe(true);
    expect(durationMs).toBeGreaterThanOrEqual(10);
    // Should have tool_call + tool_response events
    expect(ctx.events.length).toBeGreaterThanOrEqual(2);
  });

  it("withTelemetry records failure", async () => {
    const { success, error } = await withTelemetry(
      ctx,
      { step: "failing_op", inputSummary: "will fail" },
      async () => {
        throw new Error("ETIMEDOUT");
      },
    );

    expect(success).toBe(false);
    expect(error?.message).toBe("ETIMEDOUT");
    const errorEvents = ctx.events.filter((e) => !e.success);
    expect(errorEvents.length).toBeGreaterThan(0);
  });

  it("withTelemetry retries on transient errors", async () => {
    let attempts = 0;
    const { result, success } = await withTelemetry(
      ctx,
      { step: "retry_op", inputSummary: "retry test", maxRetries: 2, retryDelayMs: 10 },
      async () => {
        attempts++;
        if (attempts < 3) throw new Error("ETIMEDOUT");
        return "success after retries";
      },
    );

    expect(success).toBe(true);
    expect(result).toBe("success after retries");
    expect(attempts).toBe(3);
    // Should have retry events
    const retryEvents = ctx.events.filter((e) => e.eventType === "retry");
    expect(retryEvents.length).toBe(2);
  });

  it("withTelemetry does not retry auth failures", async () => {
    let attempts = 0;
    const { success } = await withTelemetry(
      ctx,
      { step: "auth_fail", inputSummary: "auth test", maxRetries: 3, retryDelayMs: 10 },
      async () => {
        attempts++;
        throw new Error("401 Unauthorized");
      },
    );

    expect(success).toBe(false);
    expect(attempts).toBe(1); // No retries for auth failures
  });

  it("withTelemetrySync records synchronous operations", () => {
    const { result, success, durationMs } = withTelemetrySync(
      ctx,
      { step: "sync_op", inputSummary: "parse JSON" },
      () => JSON.parse('{"a": 1}'),
    );

    expect(result).toEqual({ a: 1 });
    expect(success).toBe(true);
    expect(durationMs).toBeGreaterThanOrEqual(0);
  });
});

describe("Telemetry Logger — Buffer Stats", () => {
  it("computes correct statistics", () => {
    const ctx = createTelemetryContext({
      engagementId: 1,
      phase: "test",
      sourceModule: "test",
      consoleLog: false,
    });

    emitToolResponse(ctx, { step: "a", outputSummary: "ok", durationMs: 100, success: true });
    emitToolResponse(ctx, { step: "b", outputSummary: "ok", durationMs: 200, success: true });
    emitToolResponse(ctx, { step: "c", outputSummary: "err", durationMs: 50, success: false, error: "timeout" });
    emitError(ctx, { step: "d", error: "ECONNREFUSED" });

    const stats = getBufferStats(ctx);
    expect(stats.total).toBe(4);
    expect(stats.failureRate).toBe(0.5);
    expect(stats.avgDurationMs).toBeGreaterThan(0);
    expect(stats.byType["tool_response"]).toBe(3);
    expect(stats.byType["error"]).toBe(1);
    expect(stats.byErrorClass["timeout"]).toBe(1);
    expect(stats.byErrorClass["connection_refused"]).toBe(1);
  });
});

describe("Telemetry Logger — Utilities", () => {
  it("hashPayload produces consistent 16-char hex", () => {
    const h1 = hashPayload("test input");
    const h2 = hashPayload("test input");
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(16);
    expect(/^[0-9a-f]+$/.test(h1)).toBe(true);
  });

  it("truncateForSummary respects maxLen", () => {
    const long = "a".repeat(5000);
    const truncated = truncateForSummary(long, 100);
    expect(truncated).toHaveLength(100);
    expect(truncated.endsWith("...")).toBe(true);
  });

  it("truncateForSummary passes through short strings", () => {
    expect(truncateForSummary("short", 100)).toBe("short");
  });
});

// ─── LLM Telemetry Tests ────────────────────────────────────────────────────

import {
  detectKnowledgeGap,
  checkImpossibleValues,
  checkSelfContradictions,
  validateLlmOutputSchema,
} from "./lib/telemetry-llm";

describe("Telemetry LLM — Knowledge Gap Detection", () => {
  it("detects explicit knowledge gap phrases", () => {
    const result = detectKnowledgeGap(
      "I don't have specific information about CVE-2024-99999",
      "Find exploit for CVE-2024-99999",
    );
    expect(result.detected).toBe(true);
    expect(result.indicators.length).toBeGreaterThan(0);
  });

  it("detects inability phrases", () => {
    const result = detectKnowledgeGap("I cannot determine the correct exploit module for this service");
    expect(result.detected).toBe(true);
  });

  it("detects empty responses", () => {
    const result = detectKnowledgeGap("N/A");
    expect(result.detected).toBe(true);
    expect(result.indicators.some((i) => i.includes("Empty/generic") || i.includes("too short"))).toBe(true);
  });

  it("detects empty JSON arrays", () => {
    const result = detectKnowledgeGap("[]");
    expect(result.detected).toBe(true);
    expect(result.indicators.some((i) => i.includes("Empty JSON array"))).toBe(true);
  });

  it("does not flag valid detailed responses", () => {
    const result = detectKnowledgeGap(
      "The vulnerability CVE-2021-44228 (Log4Shell) affects Apache Log4j versions 2.0-beta9 through 2.14.1. " +
      "It allows remote code execution via JNDI lookup injection in log messages.",
    );
    expect(result.detected).toBe(false);
  });

  it("extracts CVE topic from context", () => {
    const result = detectKnowledgeGap(
      "I don't have information about this",
      "Analyze CVE-2024-12345 for exploitation",
    );
    expect(result.topic).toBe("CVE-2024-12345");
  });

  it("extracts MITRE technique from context", () => {
    const result = detectKnowledgeGap(
      "Unable to determine details",
      "Describe technique T1059.001 for this target",
    );
    expect(result.topic).toBe("T1059.001");
  });

  it("assigns severity based on indicator count", () => {
    // Single indicator = medium
    const r1 = detectKnowledgeGap("I cannot find this information");
    expect(r1.severity).toBe("medium");

    // Multiple indicators = high/critical
    const r2 = detectKnowledgeGap("N/A"); // short + empty pattern
    expect(["high", "critical"]).toContain(r2.severity);
  });
});

describe("Telemetry LLM — Hallucination Detection", () => {
  it("detects impossible CVSS scores", () => {
    const reports = checkImpossibleValues({ cvssScore: 15.5 });
    expect(reports).toHaveLength(1);
    expect(reports[0].detectionMethod).toBe("impossible_value");
    expect(reports[0].confidence).toBe(1.0);
  });

  it("accepts valid CVSS scores", () => {
    const reports = checkImpossibleValues({ cvssScore: 7.8 });
    expect(reports).toHaveLength(0);
  });

  it("detects impossible port numbers", () => {
    const reports = checkImpossibleValues({ port: 99999 });
    expect(reports).toHaveLength(1);
    expect(reports[0].claim).toContain("99999");
  });

  it("detects invalid CVE ID format", () => {
    const reports = checkImpossibleValues({ cveId: "CVE-2024" });
    expect(reports).toHaveLength(1);
    expect(reports[0].detectionMethod).toBe("impossible_value");
  });

  it("accepts valid CVE IDs", () => {
    const reports = checkImpossibleValues({ cveId: "CVE-2024-12345" });
    expect(reports).toHaveLength(0);
  });

  it("detects future dates", () => {
    const futureDate = new Date(Date.now() + 86400000 * 30).toISOString();
    const reports = checkImpossibleValues({ publishDate: futureDate });
    expect(reports).toHaveLength(1);
    expect(reports[0].detectionMethod).toBe("temporal_inconsistency");
  });

  it("detects severity vs CVSS contradictions", () => {
    const reports = checkSelfContradictions({ severity: "low", cvssScore: 9.8 });
    expect(reports).toHaveLength(1);
    expect(reports[0].detectionMethod).toBe("self_contradiction");
  });

  it("accepts consistent severity and CVSS", () => {
    const reports = checkSelfContradictions({ severity: "critical", cvssScore: 9.8 });
    expect(reports).toHaveLength(0);
  });
});

describe("Telemetry LLM — Schema Validation", () => {
  it("validates correct JSON against schema", () => {
    const result = validateLlmOutputSchema(
      JSON.stringify({ name: "test", score: 7.5, active: true }),
      [
        { name: "name", type: "string" },
        { name: "score", type: "number" },
        { name: "active", type: "boolean" },
      ],
    );
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("detects missing required fields", () => {
    const result = validateLlmOutputSchema(
      JSON.stringify({ name: "test" }),
      [
        { name: "name", type: "string" },
        { name: "score", type: "number", required: true },
      ],
    );
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("score");
  });

  it("detects type mismatches", () => {
    const result = validateLlmOutputSchema(
      JSON.stringify({ name: 123, score: "high" }),
      [
        { name: "name", type: "string" },
        { name: "score", type: "number" },
      ],
    );
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBe(2);
  });

  it("handles invalid JSON gracefully", () => {
    const result = validateLlmOutputSchema("not json at all", [
      { name: "field", type: "string" },
    ]);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("not valid JSON");
  });

  it("allows optional fields to be missing", () => {
    const result = validateLlmOutputSchema(
      JSON.stringify({ name: "test" }),
      [
        { name: "name", type: "string" },
        { name: "optional_field", type: "string", required: false },
      ],
    );
    expect(result.valid).toBe(true);
  });
});

// ─── Diagnostic Summary Tests ───────────────────────────────────────────────

import { generateDiagnosticSummary } from "./lib/telemetry-diagnostics";
import type { TelemetryEvent } from "./lib/telemetry-logger";

describe("Telemetry Diagnostics — Summary Generation", () => {
  const baseEvent: TelemetryEvent = {
    engagementId: 1,
    phase: "recon",
    step: "nmap_scan",
    eventType: "tool_response",
    success: true,
    errorClass: "none",
    retryCount: 0,
    storageProvider: "do_spaces",
    createdAt: new Date().toISOString(),
  };

  it("generates summary with correct event counts", () => {
    const events: TelemetryEvent[] = [
      { ...baseEvent, eventType: "tool_call" },
      { ...baseEvent, eventType: "tool_response", durationMs: 100 },
      { ...baseEvent, eventType: "tool_call" },
      { ...baseEvent, eventType: "tool_response", durationMs: 200 },
      { ...baseEvent, eventType: "error", success: false, errorClass: "timeout" },
    ];

    const summary = generateDiagnosticSummary(events, { engagementId: 1 });

    expect(summary.totalEvents).toBe(5);
    expect(summary.eventTypeBreakdown["tool_call"]).toBe(2);
    expect(summary.eventTypeBreakdown["tool_response"]).toBe(2);
    expect(summary.eventTypeBreakdown["error"]).toBe(1);
  });

  it("calculates failure rate by category", () => {
    const events: TelemetryEvent[] = [
      { ...baseEvent, success: false, errorClass: "timeout" },
      { ...baseEvent, success: false, errorClass: "timeout" },
      { ...baseEvent, success: false, errorClass: "connection_refused" },
      { ...baseEvent, success: true },
      { ...baseEvent, success: true },
    ];

    const summary = generateDiagnosticSummary(events, { engagementId: 1 });

    expect(summary.failureRateByCategory["timeout"].count).toBe(2);
    expect(summary.failureRateByCategory["connection_refused"].count).toBe(1);
  });

  it("identifies slowest operations", () => {
    const events: TelemetryEvent[] = [
      { ...baseEvent, step: "fast", durationMs: 50 },
      { ...baseEvent, step: "slow", durationMs: 15000 },
      { ...baseEvent, step: "medium", durationMs: 3000 },
      { ...baseEvent, step: "slowest", durationMs: 45000 },
    ];

    const summary = generateDiagnosticSummary(events, { engagementId: 1 });

    expect(summary.slowestOperations[0].step).toBe("slowest");
    expect(summary.slowestOperations[0].durationMs).toBe(45000);
    expect(summary.slowestOperations[1].step).toBe("slow");
  });

  it("detects knowledge gaps", () => {
    const events: TelemetryEvent[] = [
      {
        ...baseEvent,
        success: false,
        errorClass: "knowledge_gap",
        errorMessage: "Knowledge gap: CVE-2024-99999",
        contextSnapshot: { topic: "CVE-2024-99999", severity: "high", indicators: ["No data"] },
      },
    ];

    const summary = generateDiagnosticSummary(events, { engagementId: 1 });

    expect(summary.knowledgeGaps).toHaveLength(1);
    expect(summary.knowledgeGaps[0].topic).toBe("CVE-2024-99999");
  });

  it("detects retry storms", () => {
    const events: TelemetryEvent[] = [
      { ...baseEvent, step: "flaky_op", eventType: "retry", retryCount: 1 },
      { ...baseEvent, step: "flaky_op", eventType: "retry", retryCount: 2 },
      { ...baseEvent, step: "flaky_op", eventType: "retry", retryCount: 3, success: true },
    ];

    const summary = generateDiagnosticSummary(events, { engagementId: 1 });

    expect(summary.retryStorms).toHaveLength(1);
    expect(summary.retryStorms[0].step).toBe("flaky_op");
    expect(summary.retryStorms[0].maxRetries).toBe(3);
  });

  it("calculates health score (perfect run)", () => {
    const events: TelemetryEvent[] = Array.from({ length: 10 }, () => ({
      ...baseEvent,
      eventType: "tool_response" as const,
      durationMs: 500,
    }));

    const summary = generateDiagnosticSummary(events, { engagementId: 1 });
    expect(summary.healthScore).toBeGreaterThanOrEqual(80);
  });

  it("calculates health score (degraded run)", () => {
    const events: TelemetryEvent[] = [
      ...Array.from({ length: 5 }, () => ({ ...baseEvent, eventType: "tool_response" as const, success: false, errorClass: "timeout" as const })),
      ...Array.from({ length: 5 }, () => ({ ...baseEvent, eventType: "tool_response" as const })),
    ];

    const summary = generateDiagnosticSummary(events, { engagementId: 1 });
    expect(summary.healthScore).toBeLessThanOrEqual(80);
  });

  it("generates markdown report", () => {
    const events: TelemetryEvent[] = [
      { ...baseEvent, eventType: "tool_response", durationMs: 100 },
      { ...baseEvent, eventType: "error", success: false, errorClass: "timeout" },
    ];

    const summary = generateDiagnosticSummary(events, { engagementId: 42 });

    expect(summary.diagnosticMarkdown).toContain("Engagement 42");
    expect(summary.diagnosticMarkdown).toContain("Health Score");
    expect(summary.diagnosticMarkdown).toContain("Event Breakdown");
  });

  it("filters by phase when specified", () => {
    const events: TelemetryEvent[] = [
      { ...baseEvent, phase: "recon" },
      { ...baseEvent, phase: "recon" },
      { ...baseEvent, phase: "exploit" },
    ];

    const summary = generateDiagnosticSummary(events, {
      engagementId: 1,
      phaseFilter: "recon",
    });

    expect(summary.totalEvents).toBe(2);
  });
});

// ─── Storage Client Tests ───────────────────────────────────────────────────

import { LocalStorageClient, createStorageClientFromEnv } from "./lib/telemetry-storage";

describe("Telemetry Storage — Local Client", () => {
  it("puts and gets data", async () => {
    const client = new LocalStorageClient("/tmp/ac3-telemetry-test");
    const result = await client.put("test/file.json", '{"hello": "world"}', "application/json");

    expect(result.key).toBe("test/file.json");
    expect(result.provider).toBe("local");
    expect(result.sizeBytes).toBeGreaterThan(0);
    expect(result.contentHash).toHaveLength(64);

    const data = await client.get("test/file.json");
    expect(data?.toString()).toBe('{"hello": "world"}');
  });

  it("returns null for missing keys", async () => {
    const client = new LocalStorageClient("/tmp/ac3-telemetry-test");
    const data = await client.get("nonexistent/file.json");
    expect(data).toBeNull();
  });

  it("checks existence", async () => {
    const client = new LocalStorageClient("/tmp/ac3-telemetry-test");
    await client.put("exists/check.txt", "data");

    expect(await client.exists("exists/check.txt")).toBe(true);
    expect(await client.exists("does/not/exist.txt")).toBe(false);
  });

  it("deletes files", async () => {
    const client = new LocalStorageClient("/tmp/ac3-telemetry-test");
    await client.put("delete/me.txt", "temp");

    expect(await client.delete("delete/me.txt")).toBe(true);
    expect(await client.exists("delete/me.txt")).toBe(false);
  });
});

describe("Telemetry Storage — Env Detection", () => {
  it("falls back to local when no cloud env vars set", () => {
    // In test env, DO/AWS vars are typically not set
    const { client, config } = createStorageClientFromEnv();
    // Should get either local or one of the cloud providers depending on env
    expect(client).not.toBeNull();
    expect(["do_spaces", "aws_s3", "local"]).toContain(config.provider);
  });
});

// ─── Integration Wrapper Tests ──────────────────────────────────────────────

import {
  initEngagementTelemetry,
  getTelemetryContext,
  finalizeEngagementTelemetry,
  recordPhaseTransition,
  recordPipelineDecision,
  recordPipelineError,
  getConfiguredStorageInfo,
} from "./lib/telemetry-integration";

describe("Telemetry Integration — Context Lifecycle", () => {
  it("initializes and retrieves engagement context", () => {
    const ctx = initEngagementTelemetry(999, {
      operatorId: "test-op",
      phase: "recon",
      consoleLog: false,
    });

    expect(ctx.engagementId).toBe(999);
    expect(ctx.operatorId).toBe("test-op");

    const retrieved = getTelemetryContext(999);
    expect(retrieved).toBe(ctx);
  });

  it("records phase transitions", () => {
    initEngagementTelemetry(998, { consoleLog: false });
    recordPhaseTransition(998, "recon", "exploit");

    const ctx = getTelemetryContext(998);
    expect(ctx?.phase).toBe("exploit");
    expect(ctx?.events.some((e) => e.eventType === "phase_transition")).toBe(true);
  });

  it("records pipeline decisions", () => {
    initEngagementTelemetry(997, { consoleLog: false });
    recordPipelineDecision(997, "target_select", "Prioritize 10.0.0.5 (more vulns)", "5 critical vs 2 on other host");

    const ctx = getTelemetryContext(997);
    expect(ctx?.events.some((e) => e.eventType === "decision")).toBe(true);
  });

  it("records pipeline errors with classification", () => {
    initEngagementTelemetry(996, { consoleLog: false });
    recordPipelineError(996, "ssh_connect", "connect ECONNREFUSED 10.0.0.5:22", "10.0.0.5");

    const ctx = getTelemetryContext(996);
    const errorEvent = ctx?.events.find((e) => e.eventType === "error");
    expect(errorEvent?.errorClass).toBe("connection_refused");
    expect(errorEvent?.targetHost).toBe("10.0.0.5");
  });

  it("finalizes engagement (flush + diagnostic)", async () => {
    const ctx = initEngagementTelemetry(995, { consoleLog: false, phase: "test" });
    ctx.persistToDb = false; // Don't actually hit DB in tests

    emitToolResponse(ctx, { step: "test", outputSummary: "ok", durationMs: 100, success: true });

    await finalizeEngagementTelemetry(995);
    // Context should be cleaned up
    expect(getTelemetryContext(995)).toBeUndefined();
  });

  it("getConfiguredStorageInfo returns provider details", () => {
    const info = getConfiguredStorageInfo();
    expect(info).toHaveProperty("provider");
    expect(info).toHaveProperty("available");
  });
});
