/**
 * Tests for LLM Resilience Layer
 */
import { describe, it, expect, vi } from "vitest";
import {
  resilientLLMCall,
  validateAndRepairResponse,
  generateDeterministicAnalysisFallback,
  estimateTokens,
  isPromptWithinBudget,
  truncatePromptToBudget,
  getLLMHealthSummary,
  LLMExhaustedError,
} from "./lib/llm-resilience";

describe("Token Estimation", () => {
  it("estimates tokens for English text", () => {
    const text = "Hello world"; // 11 chars ≈ 3 tokens
    expect(estimateTokens(text)).toBeGreaterThan(0);
    expect(estimateTokens(text)).toBeLessThan(10);
  });

  it("checks prompt budget", () => {
    const shortPrompt = "Analyze this data";
    expect(isPromptWithinBudget(shortPrompt, 100)).toBe(true);

    const longPrompt = "x".repeat(100000);
    expect(isPromptWithinBudget(longPrompt, 100)).toBe(false);
  });

  it("truncates prompt to budget", () => {
    const longPrompt = "Section 1\n\n" + "x".repeat(100000) + "\n\nSection 2";
    const truncated = truncatePromptToBudget(longPrompt, 100);
    // Truncated should be significantly shorter than original
    expect(estimateTokens(truncated)).toBeLessThan(estimateTokens(longPrompt));
    expect(truncated.length).toBeLessThan(longPrompt.length);
    // Should be roughly within budget (allow for truncation suffix)
    expect(estimateTokens(truncated)).toBeLessThanOrEqual(200);
    expect(truncated).toContain("[Content truncated");
  });

  it("returns original prompt if within budget", () => {
    const prompt = "Short prompt";
    expect(truncatePromptToBudget(prompt, 1000)).toBe(prompt);
  });
});

describe("Resilient LLM Call", () => {
  it("returns result on first success", async () => {
    const { result, audit } = await resilientLLMCall(
      async () => ({ answer: "hello" }),
      { callerModule: "test", maxRetries: 2, timeoutMs: 5000 },
    );
    expect(result).toEqual({ answer: "hello" });
    expect(audit.success).toBe(true);
    expect(audit.attempts).toBe(1);
    expect(audit.usedFallback).toBe(false);
  });

  it("retries on failure and succeeds", async () => {
    let attempt = 0;
    const { result, audit } = await resilientLLMCall(
      async () => {
        attempt++;
        if (attempt < 3) throw new Error("temporary failure");
        return { answer: "recovered" };
      },
      { callerModule: "test", maxRetries: 3, retryBaseDelayMs: 10, timeoutMs: 5000 },
    );
    expect(result).toEqual({ answer: "recovered" });
    expect(audit.success).toBe(true);
    expect(audit.attempts).toBe(3);
  });

  it("throws LLMExhaustedError after all retries fail", async () => {
    try {
      await resilientLLMCall(
        async () => { throw new Error("persistent failure"); },
        { callerModule: "test", maxRetries: 2, retryBaseDelayMs: 10, timeoutMs: 5000 },
      );
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(LLMExhaustedError);
      const exhausted = err as LLMExhaustedError;
      expect(exhausted.audit.success).toBe(false);
      expect(exhausted.audit.attempts).toBe(3);
      expect(exhausted.audit.errors.length).toBe(3);
    }
  });

  it("stops retrying on non-retryable errors", async () => {
    try {
      await resilientLLMCall(
        async () => { throw new Error("invalid_api_key: bad key"); },
        { callerModule: "test", maxRetries: 5, retryBaseDelayMs: 10, timeoutMs: 5000 },
      );
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(LLMExhaustedError);
      const exhausted = err as LLMExhaustedError;
      // Should stop after 1 attempt (non-retryable)
      expect(exhausted.audit.attempts).toBe(1);
    }
  });

  it("enforces timeout", async () => {
    try {
      await resilientLLMCall(
        () => new Promise(resolve => setTimeout(resolve, 10000)),
        { callerModule: "test", maxRetries: 0, retryBaseDelayMs: 10, timeoutMs: 100 },
      );
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(LLMExhaustedError);
      const exhausted = err as LLMExhaustedError;
      expect(exhausted.audit.errors[0]).toContain("timed out");
    }
  });
});

describe("Response Validation", () => {
  it("accepts valid response", () => {
    const defaults = { name: "", count: 0, items: [] as string[] };
    const { result, repaired } = validateAndRepairResponse(
      { name: "test", count: 5, items: ["a", "b"] },
      defaults,
    );
    expect(result.name).toBe("test");
    expect(result.count).toBe(5);
    expect(result.items).toEqual(["a", "b"]);
    expect(repaired).toHaveLength(0);
  });

  it("fills missing fields from defaults", () => {
    const defaults = { name: "default", count: 0, items: [] as string[] };
    const { result, repaired } = validateAndRepairResponse(
      { name: "test" },
      defaults,
    );
    expect(result.name).toBe("test");
    expect(result.count).toBe(0);
    expect(result.items).toEqual([]);
    expect(repaired.length).toBeGreaterThan(0);
  });

  it("rejects type mismatches", () => {
    const defaults = { name: "", count: 0 };
    const { result, repaired } = validateAndRepairResponse(
      { name: 42, count: "not a number" },
      defaults,
    );
    expect(result.name).toBe(""); // default
    expect(result.count).toBe(0); // default
    expect(repaired.length).toBe(2);
  });

  it("handles null/undefined response", () => {
    const defaults = { name: "default", count: 0 };
    const { result, repaired } = validateAndRepairResponse(null, defaults);
    expect(result).toEqual(defaults);
    expect(repaired).toContain("Entire response was invalid, using defaults");
  });

  it("runs custom validators", () => {
    const defaults = { score: 0 };
    const { result, repaired } = validateAndRepairResponse(
      { score: 150 },
      defaults,
      { score: (val: number) => val >= 0 && val <= 100 },
    );
    expect(result.score).toBe(0); // Failed validation, used default
    expect(repaired.some(r => r.includes("failed validation"))).toBe(true);
  });
});

describe("Deterministic Analysis Fallback", () => {
  it("generates fallback with confirmed findings", () => {
    const result = generateDeterministicAnalysisFallback({
      totalAssets: 50,
      confirmedFindings: 15,
      probableFindings: 30,
      criticalAssets: 3,
      highRiskAssets: 8,
      technologies: ["Apache", "WordPress", "MySQL"],
      hasBreachData: true,
    });
    expect(result.blindSpots.length).toBeGreaterThan(0);
    expect(result.prioritizedRecommendations.length).toBeGreaterThan(0);
    expect(result.overallAssessment).toContain("50 assets");
    expect(result.overallAssessment).toContain("15 confirmed");
    expect(result.confidenceStatement).toContain("Low confidence");
    // Should have CMS recommendation due to WordPress
    expect(result.prioritizedRecommendations.some(r => r.title.includes("CMS"))).toBe(true);
  });

  it("generates fallback without breach data", () => {
    const result = generateDeterministicAnalysisFallback({
      totalAssets: 10,
      confirmedFindings: 0,
      probableFindings: 5,
      criticalAssets: 0,
      highRiskAssets: 0,
      technologies: ["Nginx"],
      hasBreachData: false,
    });
    // Should flag missing breach data as blind spot
    expect(result.blindSpots.some(b => b.area.includes("Credential"))).toBe(true);
    // Should have web server hardening recommendation
    expect(result.prioritizedRecommendations.some(r => r.title.includes("Web Server"))).toBe(true);
  });

  it("always includes monitoring recommendation", () => {
    const result = generateDeterministicAnalysisFallback({
      totalAssets: 1,
      confirmedFindings: 0,
      probableFindings: 0,
      criticalAssets: 0,
      highRiskAssets: 0,
      technologies: [],
      hasBreachData: false,
    });
    expect(result.prioritizedRecommendations.some(r => r.title.includes("Monitoring"))).toBe(true);
  });

  it("assesses elevated risk for many high-risk assets", () => {
    const result = generateDeterministicAnalysisFallback({
      totalAssets: 100,
      confirmedFindings: 25,
      probableFindings: 50,
      criticalAssets: 10,
      highRiskAssets: 15,
      technologies: [],
      hasBreachData: true,
    });
    expect(result.overallAssessment).toContain("elevated");
  });
});

describe("LLM Health Summary", () => {
  it("returns valid health summary", () => {
    const summary = getLLMHealthSummary();
    expect(summary).toHaveProperty("totalCalls");
    expect(summary).toHaveProperty("successRate");
    expect(summary).toHaveProperty("fallbackRate");
    expect(summary).toHaveProperty("avgDurationMs");
    expect(summary).toHaveProperty("recentErrors");
    expect(summary.successRate).toBeGreaterThanOrEqual(0);
    expect(summary.successRate).toBeLessThanOrEqual(1);
  });
});
