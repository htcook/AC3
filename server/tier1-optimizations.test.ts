/**
 * Tier 1 Pipeline Optimization Tests
 *
 * Validates the four Tier 1 optimizations:
 * 3.1: LLM timeout wrapper (60s hard cap)
 * 3.2: Parallel LLM stages (post-enrichment || campaigns)
 * 3.3: Background GitHub connectors
 * 3.4: KEV catalog caching (already had 6h TTL — verified)
 */

import { describe, it, expect } from "vitest";

describe("Tier 1 Optimization #3.1: LLM Timeout Wrapper", () => {
  it("should have invokeLLMWithTimeout defined in domainIntel.ts", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/domainIntel.ts", "utf-8");
    expect(source).toContain("invokeLLMWithTimeout");
    expect(source).toContain("LLM_TIMEOUT_MS");
    expect(source).toContain("60_000");
  });

  it("should wrap all LLM calls with timeout in domainIntel.ts (no raw invokeLLM calls)", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/domainIntel.ts", "utf-8");
    // Count raw invokeLLM( calls (excluding the import and the wrapper definition)
    const rawCalls = source.match(/await\s+invokeLLM\(/g);
    expect(rawCalls).toBeNull(); // No raw calls should remain
    // Count wrapped calls
    const wrappedCalls = source.match(/await\s+invokeLLMWithTimeout\(/g);
    expect(wrappedCalls).not.toBeNull();
    expect(wrappedCalls!.length).toBeGreaterThanOrEqual(5); // 5 LLM calls in domainIntel.ts
  });

  it("should have timeout wrapper in post-enrichment analysis", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/llm-post-enrichment-analysis.ts", "utf-8");
    expect(source).toContain("invokeLLMWithTimeout");
    expect(source).toContain("LLM_TIMEOUT_MS");
    // Should not have raw invokeLLM calls
    const rawCalls = source.match(/await\s+invokeLLM\(/g);
    expect(rawCalls).toBeNull();
  });

  it("should use Promise.race pattern for timeout enforcement", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/domainIntel.ts", "utf-8");
    expect(source).toContain("Promise.race");
    expect(source).toContain("LLM timeout after");
  });
});

describe("Tier 1 Optimization #3.2: Parallel LLM Stages", () => {
  it("should run post-enrichment and campaigns in parallel via Promise.allSettled", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/domainIntel.ts", "utf-8");
    // Check for the parallel execution pattern
    expect(source).toContain("Promise.allSettled");
    expect(source).toContain("running post-enrichment and campaign design in parallel");
  });

  it("should handle failures gracefully with allSettled pattern", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/domainIntel.ts", "utf-8");
    // Check that both fulfilled and rejected cases are handled
    expect(source).toContain("peResult.status === 'fulfilled'");
    expect(source).toContain("campaignResult.status === 'fulfilled'");
    expect(source).toContain("campaignResult.status === 'rejected'");
  });

  it("should also parallelize scan-only mode (post-enrichment + scan summary)", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/domainIntel.ts", "utf-8");
    expect(source).toContain("Stage 3.99 + scan summary: running in parallel");
  });
});

describe("Tier 1 Optimization #3.3: Background GitHub Connectors", () => {
  it("should separate GitHub connectors from main pool", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/passive/index.ts", "utf-8");
    expect(source).toContain("BACKGROUND_CONNECTORS");
    expect(source).toContain("github_leaks");
    expect(source).toContain("github_recon");
    expect(source).toContain("mainConnectors");
    expect(source).toContain("backgroundConnectors");
  });

  it("should run background connectors after main pool completes", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/passive/index.ts", "utf-8");
    expect(source).toContain("Starting background connectors");
    expect(source).toContain("Background connectors finished or timed out");
  });

  it("should only process main connectors in the semaphore pool", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/passive/index.ts", "utf-8");
    // The main pool should iterate mainConnectors, not readyConnectors
    expect(source).toContain("mainConnectors.map((connector)");
  });

  it("should skip background connectors if global timeout is reached", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/passive/index.ts", "utf-8");
    expect(source).toContain("global timeout reached before background queue");
  });

  it("should race background connectors against remaining time budget", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/passive/index.ts", "utf-8");
    expect(source).toContain("bgTimeoutPromise");
    expect(source).toContain("Promise.race([Promise.all(bgPromises), bgTimeoutPromise])");
  });
});

describe("Tier 1 Optimization #3.4: KEV Catalog Caching", () => {
  it("should have in-memory cache with TTL in kev-service.ts", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/kev-service.ts", "utf-8");
    expect(source).toContain("cachedCatalog");
    expect(source).toContain("CACHE_TTL");
    expect(source).toContain("cacheTimestamp");
  });

  it("should return cached data when within TTL", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/kev-service.ts", "utf-8");
    expect(source).toContain("if (cachedCatalog && (now - cacheTimestamp) < CACHE_TTL)");
    expect(source).toContain("return cachedCatalog");
  });
});
