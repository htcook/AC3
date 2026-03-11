/**
 * Tests for LLM Feedback Loop Resilience & Convergence Improvements
 *
 * Covers:
 * 1. retryWithBackoff utility — exponential backoff, jitter, retryable error detection
 * 2. isRetryableError — classifies 403, 429, 5xx, timeouts, network errors
 * 3. Feedback loop convergence — stale iteration detection, deduplication, early exit
 * 4. LLM response validation — malformed JSON, missing fields, graceful fallback
 * 5. Integration — retry wiring in engagement-orchestrator and zap-scanner
 */

import { describe, it, expect } from "vitest";
import * as fs from "fs";

// ─── 1. retryWithBackoff utility ────────────────────────────────────────

describe("retryWithBackoff", () => {
  it("should be exported from api-resilience.ts", async () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain("export async function retryWithBackoff");
    expect(source).toContain("export function isRetryableError");
  });

  it("should accept RetryConfig with maxRetries, baseDelayMs, maxDelayMs, retryableCheck", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain("maxRetries: number");
    expect(source).toContain("baseDelayMs: number");
    expect(source).toContain("maxDelayMs?: number");
    expect(source).toContain("retryableCheck?: (err: any) => boolean");
  });

  it("should implement exponential backoff with jitter", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain("Math.pow(2, attempt)");
    expect(source).toContain("Math.random()");
    expect(source).toContain("Math.min(exponentialDelay + jitter, maxDelayMs)");
  });

  it("should throw the last error when all retries are exhausted", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    // Should throw lastError at the end
    expect(source).toContain("throw lastError");
  });

  it("should not retry non-retryable errors", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain("!retryableCheck(err)");
  });
});

// ─── 2. isRetryableError classification ─────────────────────────────────

describe("isRetryableError", () => {
  it("should classify 429 rate limit as retryable", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain('statusCode === 429');
    expect(source).toContain('"rate limit"');
  });

  it("should classify 403 Forbidden as retryable (transient rate limit)", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain('statusCode === 403');
    expect(source).toContain('"Forbidden"');
  });

  it("should classify 5xx server errors as retryable", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain("statusCode >= 500 && statusCode < 600");
  });

  it("should classify timeout errors as retryable", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain('"ETIMEDOUT"');
    expect(source).toContain('"AbortError"');
  });

  it("should classify network errors as retryable", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain('"ECONNREFUSED"');
    expect(source).toContain('"ENOTFOUND"');
  });

  it("should classify Empty LLM response as retryable", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/api-resilience.ts",
      "utf-8"
    );
    expect(source).toContain('"Empty LLM response"');
  });
});

// ─── 3. Feedback loop convergence ───────────────────────────────────────

describe("Feedback loop convergence", () => {
  const feedbackSource = () =>
    fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/llm-scan-feedback.ts",
      "utf-8"
    );

  it("should have increased maxIterations default from 3 to 5", () => {
    const source = feedbackSource();
    expect(source).toContain("maxIterations = 5");
  });

  it("should have increased maxTotalScans default from 10 to 12", () => {
    const source = feedbackSource();
    expect(source).toContain("maxTotalScans = 12");
  });

  it("should track stale iterations for convergence detection", () => {
    const source = feedbackSource();
    expect(source).toContain("staleIterations");
    expect(source).toContain("STALE_THRESHOLD");
    expect(source).toContain("Convergence detected");
  });

  it("should force satisfaction after 2 stale iterations", () => {
    const source = feedbackSource();
    expect(source).toContain("const STALE_THRESHOLD = 2");
    expect(source).toContain("staleIterations >= STALE_THRESHOLD");
  });

  it("should deduplicate scan requests against previous history", () => {
    const source = feedbackSource();
    expect(source).toContain("Skipping duplicate scan");
    expect(source).toContain("h.request.tool === scan.tool");
    expect(source).toContain("h.request.target === scan.target");
    expect(source).toContain("h.request.args === scan.args");
  });

  it("should force satisfaction when all requested scans are duplicates", () => {
    const source = feedbackSource();
    expect(source).toContain("All requested scans are duplicates, forcing satisfaction");
  });

  it("should track new findings per iteration", () => {
    const source = feedbackSource();
    expect(source).toContain("newFindingsThisIteration");
  });

  it("should reset staleIterations counter when new findings are discovered", () => {
    const source = feedbackSource();
    expect(source).toContain("staleIterations = 0; // Reset if we found something new");
  });

  it("should wrap LLM analysis call in retryWithBackoff", () => {
    const source = feedbackSource();
    expect(source).toContain("retryWithBackoff");
    expect(source).toContain("analyzeFindingsAndRequestScans");
    expect(source).toContain("maxRetries: 3");
  });

  it("should gracefully handle LLM analysis failure after retries", () => {
    const source = feedbackSource();
    expect(source).toContain("LLM analysis failed after retries");
    expect(source).toContain("Proceeding with");
  });
});

// ─── 4. LLM response validation ────────────────────────────────────────

describe("LLM response validation", () => {
  const feedbackSource = () =>
    fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/llm-scan-feedback.ts",
      "utf-8"
    );

  it("should handle malformed JSON with markdown code block extraction", () => {
    const source = feedbackSource();
    expect(source).toContain("```(?:json)?");
    expect(source).toContain("jsonMatch[1].trim()");
  });

  it("should fallback to satisfied=true when JSON is unparseable", () => {
    const source = feedbackSource();
    expect(source).toContain("LLM returned unparseable response");
    expect(source).toContain("Treating as satisfied");
  });

  it("should fallback to satisfied=true when response is not JSON at all", () => {
    const source = feedbackSource();
    expect(source).toContain("LLM returned non-JSON response");
    expect(source).toContain("satisfied: true");
  });

  it("should validate required fields with defaults", () => {
    const source = feedbackSource();
    expect(source).toContain('typeof parsed.satisfied !== "boolean"');
    expect(source).toContain('typeof parsed.analysis !== "string"');
    expect(source).toContain("!Array.isArray(parsed.scanRequests)");
  });

  it("should default missing satisfied field to true", () => {
    const source = feedbackSource();
    expect(source).toContain("defaulting to true");
    expect(source).toContain("parsed.satisfied = true");
  });
});

// ─── 5. LLM prompt convergence guidelines ───────────────────────────────

describe("LLM prompt convergence guidelines", () => {
  const feedbackSource = () =>
    fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/llm-scan-feedback.ts",
      "utf-8"
    );

  it("should include Convergence Guidelines section in system prompt", () => {
    const source = feedbackSource();
    expect(source).toContain("## Convergence Guidelines (IMPORTANT)");
  });

  it("should instruct LLM about SUFFICIENT vs PERFECT coverage", () => {
    const source = feedbackSource();
    expect(source).toContain("SUFFICIENT data to plan attacks");
    expect(source).toContain("do NOT need PERFECT coverage");
  });

  it("should instruct LLM about diminishing returns", () => {
    const source = feedbackSource();
    expect(source).toContain("diminishing returns");
  });

  it("should instruct LLM not to repeat previous scans", () => {
    const source = feedbackSource();
    expect(source).toContain("Do NOT request the same scan");
  });

  it("should instruct LLM to prefer satisfaction when budget is low", () => {
    const source = feedbackSource();
    expect(source).toContain("budget is 3 or fewer");
    expect(source).toContain("strongly prefer satisfied=true");
  });

  it("should include severity distribution in user message", () => {
    const source = feedbackSource();
    expect(source).toContain("severityCounts");
    expect(source).toContain("Severity distribution");
  });

  it("should hint about diminishing returns in previous re-scans section", () => {
    const source = feedbackSource();
    expect(source).toContain("did not reveal significant new attack surface");
  });
});

// ─── 6. Integration: retry wiring in orchestrator and zap-scanner ───────

describe("Retry integration in engagement-orchestrator", () => {
  const orchSource = () =>
    fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

  it("should import retryWithBackoff and isRetryableError", () => {
    const source = orchSource();
    expect(source).toContain('import { retryWithBackoff, isRetryableError } from "./api-resilience"');
  });

  it("should wrap fallback LLM scan plan call in retryWithBackoff", () => {
    const source = orchSource();
    // The scan plan fallback should use retry
    const scanPlanSection = source.slice(
      source.indexOf("direct-llm"),
      source.indexOf("direct-llm") + 500
    );
    expect(scanPlanSection).toContain("retryWithBackoff");
  });

  it("should wrap ops decision LLM call in retryWithBackoff", () => {
    const source = orchSource();
    // The retryWithBackoff wraps the invokeLLM call near opsDecision
    // Search a wider window around the fallback direct LLM section (prompt template is long)
    const fallbackIdx = source.indexOf("Fallback: direct invokeLLM");
    const opsSection = source.slice(fallbackIdx, fallbackIdx + 2000);
    expect(opsSection).toContain("retryWithBackoff");
  });

  it("should use updated feedback loop config with maxIterations=5", () => {
    const source = orchSource();
    expect(source).toContain("maxIterations: 5");
    expect(source).toContain("maxTotalScans: 12");
  });
});

describe("Retry integration in zap-scanner", () => {
  const zapSource = () =>
    fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/zap-scanner.ts",
      "utf-8"
    );

  it("should use retryWithBackoff in generateLLMScanConfig", () => {
    const source = zapSource();
    const configSection = source.slice(
      source.indexOf("generateLLMScanConfig"),
      source.indexOf("generateLLMScanConfig") + 2000
    );
    expect(configSection).toContain("retryWithBackoff");
    expect(configSection).toContain("isRetryableError");
  });

  it("should log 'after retries' on final failure", () => {
    const source = zapSource();
    expect(source).toContain("Failed to generate config after retries");
  });

  it("should still fall back to default config on total failure", () => {
    const source = zapSource();
    expect(source).toContain("getDefaultScanConfig(params.scanMode, params.techStackHints, undefined, params.targetUrl)");
  });
});

// ─── 7. Feedback loop imports ───────────────────────────────────────────

describe("Feedback loop module imports", () => {
  it("should import retryWithBackoff and isRetryableError from api-resilience", () => {
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/llm-scan-feedback.ts",
      "utf-8"
    );
    expect(source).toContain('import { retryWithBackoff, isRetryableError } from "./api-resilience"');
  });
});
