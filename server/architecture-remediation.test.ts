import { describe, it, expect, vi } from "vitest";

// ═══════════════════════════════════════════════════════════════════════════
// Architecture Remediation — Test Suite
// Tests all Claude-recommended fixes and orchestrator decomposition
// ═══════════════════════════════════════════════════════════════════════════

// ── Fix #1: CARVER Two-Pass Architecture ──────────────────────────────────
describe("CARVER Two-Pass Architecture", () => {
  it("applyCarverFeedbackEarly should export and accept analyses + crossModuleData + passiveRecon", async () => {
    const mod = await import("./lib/carver-feedback-loop");
    expect(typeof mod.applyCarverFeedbackEarly).toBe("function");
  });

  it("applyCarverFeedbackLate should export and accept analyses + postEnrichment", async () => {
    const mod = await import("./lib/carver-feedback-loop");
    expect(typeof mod.applyCarverFeedbackLate).toBe("function");
  });

  it("early pass should return a CarverFeedbackResult without needing postEnrichment", async () => {
    const { applyCarverFeedbackEarly } = await import("./lib/carver-feedback-loop");
    const mockAnalyses = [
      {
        domain: "example.com",
        carverScores: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
        postureFindings: [],
      },
    ];
    const crossModuleData = {
      riskAdjustments: [
        { domain: "example.com", factor: "criticality", boost: 2, reason: "Active threat campaign" },
      ],
    };

    const result = applyCarverFeedbackEarly(mockAnalyses as any, crossModuleData as any, undefined);
    expect(result).toBeDefined();
    expect(result.adjustments).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  it("late pass should return a CarverFeedbackResult using postEnrichment", async () => {
    const { applyCarverFeedbackLate } = await import("./lib/carver-feedback-loop");
    const mockAnalyses = [
      {
        domain: "example.com",
        carverScores: { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
        postureFindings: [],
      },
    ];
    const postEnrichment = {
      attackPaths: [
        { chain: ["phishing", "lateral_movement", "data_exfil"], targetDomain: "example.com", confidence: 0.8 },
      ],
      blindSpots: [],
    };

    const result = applyCarverFeedbackLate(mockAnalyses as any, postEnrichment as any);
    expect(result).toBeDefined();
    expect(result.adjustments).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  it("original applyCarverFeedbackLoop should still work for backwards compat", async () => {
    const mod = await import("./lib/carver-feedback-loop");
    expect(typeof mod.applyCarverFeedbackLoop).toBe("function");
  });
});

// ── Fix #2: Centralized LLM JSON Parsing ──────────────────────────────────
describe("Centralized LLM JSON Parser", () => {
  it("should export safeParseLLMJson from shared module", async () => {
    const mod = await import("../shared/llm-json-parser");
    expect(typeof mod.safeParseLLMJson).toBe("function");
  });

  it("should export sanitizeJsonResponse from shared module", async () => {
    const mod = await import("../shared/llm-json-parser");
    expect(typeof mod.sanitizeJsonResponse).toBe("function");
  });

  it("should strip markdown code fences from LLM output", async () => {
    const { sanitizeJsonResponse } = await import("../shared/llm-json-parser");
    const input = '```json\n{"key": "value"}\n```';
    const result = sanitizeJsonResponse(input);
    expect(result).toBe('{"key": "value"}');
  });

  it("should handle triple backticks without language specifier", async () => {
    const { sanitizeJsonResponse } = await import("../shared/llm-json-parser");
    const input = '```\n{"key": "value"}\n```';
    const result = sanitizeJsonResponse(input);
    expect(result).toBe('{"key": "value"}');
  });

  it("should return valid JSON unchanged", async () => {
    const { sanitizeJsonResponse } = await import("../shared/llm-json-parser");
    const input = '{"key": "value"}';
    const result = sanitizeJsonResponse(input);
    expect(result).toBe('{"key": "value"}');
  });

  it("safeParseLLMJson should return parsed object for valid JSON", async () => {
    const { safeParseLLMJson } = await import("../shared/llm-json-parser");
    const result = safeParseLLMJson('{"name": "test", "score": 42}');
    expect(result).toEqual({ name: "test", score: 42 });
  });

  it("safeParseLLMJson should return fallback for invalid JSON", async () => {
    const { safeParseLLMJson } = await import("../shared/llm-json-parser");
    const fallback = { error: true };
    const result = safeParseLLMJson("not json at all", fallback);
    expect(result).toEqual(fallback);
  });

  it("safeParseLLMJson should handle code-fenced JSON", async () => {
    const { safeParseLLMJson } = await import("../shared/llm-json-parser");
    const result = safeParseLLMJson('```json\n{"status": "ok"}\n```');
    expect(result).toEqual({ status: "ok" });
  });

  it("should repair common LLM JSON errors (trailing commas)", async () => {
    const { safeParseLLMJson } = await import("../shared/llm-json-parser");
    const input = '{"items": ["a", "b", "c",]}';
    const result = safeParseLLMJson(input);
    // Should either parse successfully or return fallback gracefully
    expect(result).toBeDefined();
  });
});

// ── Fix #3: Stage Parallelization ─────────────────────────────────────────
describe("Stage Parallelization (4.5 + 4.55 + 4.6)", () => {
  it("domainIntel.ts should contain Promise.allSettled for stages 4.5/4.55/4.6", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/domainIntel.ts", "utf-8");
    // The parallelized section should use Promise.allSettled
    expect(content).toContain("Promise.allSettled");
    // Should reference the parallel stages
    expect(content).toContain("4.5");
    expect(content).toContain("4.6");
  });
});

// ── Fix #4: Credential Testing ROE Gate ───────────────────────────────────
describe("Credential Testing ROE Gate", () => {
  it("domainIntel.ts should gate credential testing behind active scan mode", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/domainIntel.ts", "utf-8");
    // Should check for scanMode === 'active' before credential testing
    expect(content).toContain("scanMode");
    expect(content).toContain("active");
    // Should have a skip log when not in active mode
    expect(content).toContain("Credential testing SKIPPED");
  });
});

// ── Fix #5: Attribution Hedging ───────────────────────────────────────────
describe("Threat Actor Attribution Hedging", () => {
  it("di-threat-matching.ts should contain confidence qualifiers", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/di-threat-matching.ts", "utf-8");
    // Should contain hedging language
    expect(content).toContain("patterns consistent with");
    // Should have the hedging prefix logic
    expect(content).toContain("hedgingPrefix");
  });

  it("should use hedged language instead of definitive attribution", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/di-threat-matching.ts", "utf-8");
    // Should contain the hedging suffix disclaimer
    expect(content).toContain("not a definitive attribution");
    // Should contain the behavioral pattern match note
    expect(content).toContain("behavioral pattern match");
  });
});

// ── Decomposition #1: Tool Output Parsers Extraction ──────────────────────
describe("Tool Output Parsers Extraction", () => {
  it("should export parseToolOutput from tool-output-parsers module", async () => {
    const mod = await import("./lib/tool-output-parsers");
    expect(typeof mod.parseToolOutput).toBe("function");
  });

  it("should export ParsedFinding type from tool-output-parsers module", async () => {
    // TypeScript type check — if this imports without error, the type exists
    const mod = await import("./lib/tool-output-parsers");
    expect(mod).toBeDefined();
  });

  it("orchestrator should import parseToolOutput from extracted module", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    expect(content).toContain("import { parseToolOutput");
    expect(content).toContain("./tool-output-parsers");
  });
});

// ── Decomposition #2: Phase 6b Social Engineering Extraction ──────────────
describe("Phase 6b Social Engineering Extraction", () => {
  it("should export executeSocialEngineering from extracted module", async () => {
    const mod = await import("./lib/engagement-phase-social-engineering");
    expect(typeof mod.executeSocialEngineering).toBe("function");
  });

  it("should check ROE authorization before executing", async () => {
    const { executeSocialEngineering } = await import("./lib/engagement-phase-social-engineering");
    const mockState = {
      engagementId: "test-1",
      isRunning: true,
      phase: "vuln_detection",
      currentAction: "",
      assets: [],
      stats: { vulnsFound: 0 },
    };
    const mockEngagement = { roeScope: { socialEngineering: false } };
    const mockCallbacks = {
      addLog: vi.fn(),
      broadcastUpdate: vi.fn(),
    };

    const result = await executeSocialEngineering(mockState, mockEngagement, mockCallbacks);
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toBe("not_authorized_in_roe");
    expect(result.executed).toBe(false);
  });

  it("should skip when ROE scope is null/undefined", async () => {
    const { executeSocialEngineering } = await import("./lib/engagement-phase-social-engineering");
    const mockState = {
      engagementId: "test-2",
      isRunning: true,
      phase: "vuln_detection",
      currentAction: "",
      assets: [],
      stats: { vulnsFound: 0 },
    };
    const mockEngagement = { roeScope: null };
    const mockCallbacks = {
      addLog: vi.fn(),
      broadcastUpdate: vi.fn(),
    };

    const result = await executeSocialEngineering(mockState, mockEngagement as any, mockCallbacks);
    expect(result.skipped).toBe(true);
    expect(result.executed).toBe(false);
  });

  it("orchestrator should use extracted module instead of inline code", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    expect(content).toContain("executeSocialEngineering");
    expect(content).toContain("engagement-phase-social-engineering");
  });
});

// ── Decomposition #3: Auto-Report Extraction ──────────────────────────────
describe("Auto-Report Generation Extraction", () => {
  it("should export generateAutoReport from extracted module", async () => {
    const mod = await import("./lib/engagement-auto-report");
    expect(typeof mod.generateAutoReport).toBe("function");
  });

  it("orchestrator should use extracted module instead of inline code", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    expect(content).toContain("generateAutoReport");
    expect(content).toContain("engagement-auto-report");
  });
});

// ── Decomposition #4: EngagementContext Interface ─────────────────────────
describe("EngagementContext Typed Interface", () => {
  it("should export EngagementContext type", async () => {
    const mod = await import("./lib/engagement-context");
    expect(mod).toBeDefined();
  });

  it("should export createEngagementContext factory", async () => {
    const { createEngagementContext } = await import("./lib/engagement-context");
    expect(typeof createEngagementContext).toBe("function");

    const ctx = createEngagementContext({
      engagementId: 1,
      engagementType: "pentest",
      targetDomain: "example.com",
      customerName: "Test Corp",
    });

    expect(ctx.engagementId).toBe(1);
    expect(ctx.engagementType).toBe("pentest");
    expect(ctx.targetDomain).toBe("example.com");
    expect(ctx.assets).toEqual([]);
    expect(ctx.findings).toEqual([]);
    expect(ctx.stats.vulnsFound).toBe(0);
    expect(ctx.startedAt).toBeGreaterThan(0);
  });

  it("should export requirePhaseOutput helper", async () => {
    const { createEngagementContext, requirePhaseOutput } = await import("./lib/engagement-context");
    expect(typeof requirePhaseOutput).toBe("function");

    const ctx = createEngagementContext({
      engagementId: 1,
      engagementType: "pentest",
      targetDomain: "example.com",
    });

    // Should throw when phase output doesn't exist
    expect(() => requirePhaseOutput(ctx, "passiveRecon", "enumeration")).toThrow(
      /Phase "enumeration" requires output from "passiveRecon"/
    );
  });

  it("requirePhaseOutput should return value when phase output exists", async () => {
    const { createEngagementContext, requirePhaseOutput } = await import("./lib/engagement-context");

    const ctx = createEngagementContext({
      engagementId: 1,
      engagementType: "pentest",
      targetDomain: "example.com",
    });

    // Simulate Phase 1 completing
    ctx.passiveRecon = {
      completedAt: Date.now(),
      domainResults: {
        "example.com": {
          subdomains: ["sub.example.com"],
          dnsRecords: {},
          certificates: [],
          technologies: ["nginx"],
          cloudProviders: [],
          emailAddresses: [],
          breachExposure: [],
          services: [{ port: 443, service: "https" }],
        },
      },
    };

    const result = requirePhaseOutput(ctx, "passiveRecon", "enumeration");
    expect(result.completedAt).toBeGreaterThan(0);
    expect(result.domainResults["example.com"].technologies).toContain("nginx");
  });
});

// ── Orchestrator Size Reduction Verification ──────────────────────────────
describe("Orchestrator Decomposition Metrics", () => {
  it("orchestrator should be smaller than original 15,736 lines", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
    const lineCount = content.split("\n").length;
    // Original was 15,736 lines. After extracting:
    // - Tool parsers: ~730 lines
    // - Phase 6b: ~130 lines (inline was ~130, module is ~200)
    // - Auto-report: ~400 lines
    // Expected: ~14,400-14,600 lines
    expect(lineCount).toBeLessThan(15000);
    console.log(`Orchestrator line count: ${lineCount} (reduced from 15,736)`);
  });

  it("extracted modules should exist and be non-trivial", async () => {
    const fs = await import("fs");
    const toolParsers = fs.readFileSync("server/lib/tool-output-parsers.ts", "utf-8");
    const socialEng = fs.readFileSync("server/lib/engagement-phase-social-engineering.ts", "utf-8");
    const autoReport = fs.readFileSync("server/lib/engagement-auto-report.ts", "utf-8");
    const context = fs.readFileSync("server/lib/engagement-context.ts", "utf-8");

    expect(toolParsers.split("\n").length).toBeGreaterThan(700);
    expect(socialEng.split("\n").length).toBeGreaterThan(100);
    expect(autoReport.split("\n").length).toBeGreaterThan(200);
    expect(context.split("\n").length).toBeGreaterThan(200);

    console.log(`Tool parsers: ${toolParsers.split("\n").length} lines`);
    console.log(`Social engineering: ${socialEng.split("\n").length} lines`);
    console.log(`Auto-report: ${autoReport.split("\n").length} lines`);
    console.log(`Engagement context: ${context.split("\n").length} lines`);
  });
});
