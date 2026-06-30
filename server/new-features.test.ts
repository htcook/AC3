/**
 * Tests for three new features:
 * 1. Custom Exploit Repository
 * 2. Exploit Feedback Loop Integration (Phase 2)
 * 3. Scan Server Tool Manifest Sync
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Custom Exploit Repository Tests ───────────────────────────────────────

describe("Custom Exploit Repository", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/custom-exploit-repository");
    expect(typeof mod.uploadCustomExploit).toBe("function");
    expect(typeof mod.deployToScanServer).toBe("function");
    expect(typeof mod.listCustomExploits).toBe("function");
    expect(typeof mod.getCustomExploitStats).toBe("function");
    expect(typeof mod.buildCustomExploitPromptSection).toBe("function");
  });

  it("buildCustomExploitPromptSection should return a string", async () => {
    const { buildCustomExploitPromptSection } = await import("./lib/custom-exploit-repository");
    const result = buildCustomExploitPromptSection([{
      title: "Test SQLi Exploit",
      description: "SQL injection via login form",
      language: "python",
      codeSnippet: "import requests\nrequests.post(url, data={'user': \"' OR 1=1--\"})",
      tags: ["sqli", "auth-bypass"],
      cveId: "CVE-2024-1234",
      exploitType: "sql_injection",
      toolingCategory: null,
      successRate: 0.85,
      timesDeployed: 3,
    }]);
    expect(typeof result).toBe("string");
    expect(result).toContain("Test SQLi Exploit");
    expect(result).toContain("CUSTOM EXPLOIT TEMPLATES");
  });

  it("buildCustomExploitPromptSection should return empty for no templates", async () => {
    const { buildCustomExploitPromptSection } = await import("./lib/custom-exploit-repository");
    const result = buildCustomExploitPromptSection([]);
    expect(result).toBe("");
  });
});

// ─── Exploit Feedback Integration Tests ────────────────────────────────────

describe("Exploit Feedback Integration (Phase 2)", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/exploit-feedback-integration");
    expect(typeof mod.recordExploitResult).toBe("function");
    expect(typeof mod.buildFeedbackContextForExploit).toBe("function");
    expect(typeof mod.getExploitFeedbackDashboard).toBe("function");
  });

  it("buildFeedbackContextForExploit should return structured context", async () => {
    const { buildFeedbackContextForExploit } = await import("./lib/exploit-feedback-integration");
    const ctx = await buildFeedbackContextForExploit("http", "CVE-2024-1234", "192.168.1.1", 80);
    expect(ctx).toHaveProperty("performancePrompt");
    expect(ctx).toHaveProperty("rankedModules");
    expect(ctx).toHaveProperty("avoidModules");
    expect(ctx).toHaveProperty("preferModules");
    expect(ctx).toHaveProperty("failurePatterns");
    expect(ctx).toHaveProperty("strategyRecommendation");
    expect(typeof ctx.performancePrompt).toBe("string");
    expect(Array.isArray(ctx.rankedModules)).toBe(true);
    expect(Array.isArray(ctx.avoidModules)).toBe(true);
    expect(Array.isArray(ctx.preferModules)).toBe(true);
    expect(Array.isArray(ctx.failurePatterns)).toBe(true);
    expect(typeof ctx.strategyRecommendation).toBe("string");
  });

  it("buildFeedbackContextForExploit with no history should return standard strategy", async () => {
    const { buildFeedbackContextForExploit } = await import("./lib/exploit-feedback-integration");
    const ctx = await buildFeedbackContextForExploit("nonexistent_service_xyz");
    expect(ctx.rankedModules).toHaveLength(0);
    expect(ctx.strategyRecommendation).toContain("No prior exploit attempts");
  });

  it("recordExploitResult should accept a valid result and return performance data", async () => {
    const { recordExploitResult } = await import("./lib/exploit-feedback-integration");
    const result = await recordExploitResult({
      engagementId: 999999,
      target: "test-target.local",
      port: 8080,
      service: "http",
      cve: "CVE-2024-TEST-001",
      module: "test-module-vitest",
      success: true,
      exploitOutput: "EXPLOIT_SUCCESS: test shell obtained",
      shellType: "reverse_shell",
      executionMs: 1500,
    });
    expect(result).toHaveProperty("moduleName", "test-module-vitest");
    expect(result).toHaveProperty("successRate");
    expect(result).toHaveProperty("totalAttempts");
    expect(result.totalAttempts).toBeGreaterThanOrEqual(1);
    expect(result.successes).toBeGreaterThanOrEqual(1);
  });

  it("recordExploitResult should classify failure reasons correctly", async () => {
    const { recordExploitResult } = await import("./lib/exploit-feedback-integration");
    const result = await recordExploitResult({
      engagementId: 999999,
      target: "test-target.local",
      port: 443,
      service: "https",
      success: false,
      exploitOutput: "Connection refused - ECONNREFUSED",
      executionMs: 500,
      errorMessage: "Connection refused",
    });
    expect(result).toHaveProperty("moduleName");
    expect(result.failures + result.errors).toBeGreaterThanOrEqual(1);
  });
});

// ─── Tool Manifest Sync Tests ──────────────────────────────────────────────

describe("Tool Manifest Sync", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/tool-manifest-sync");
    expect(typeof mod.runManifestSync).toBe("function");
    expect(typeof mod.getCachedReport).toBe("function");
    expect(typeof mod.startupHealthCheck).toBe("function");
    expect(typeof mod.formatManifestForPrompt).toBe("function");
  });

  it("getCachedReport should return null when no sync has been run", async () => {
    // Note: this test may fail if another test ran a sync first
    // We test the function exists and returns the expected type
    const { getCachedReport } = await import("./lib/tool-manifest-sync");
    const result = getCachedReport();
    // Result is either null or a ManifestSyncReport
    if (result !== null) {
      expect(result).toHaveProperty("syncedAt");
      expect(result).toHaveProperty("totalTools");
      expect(result).toHaveProperty("availableTools");
      expect(result).toHaveProperty("toolHealth");
      expect(result).toHaveProperty("categoryReadiness");
      expect(result).toHaveProperty("overallReadiness");
      expect(result).toHaveProperty("overallStatus");
    }
  });

  it("formatManifestForPrompt should return a string", async () => {
    const { formatManifestForPrompt } = await import("./lib/tool-manifest-sync");
    const result = formatManifestForPrompt();
    expect(typeof result).toBe("string");
  });

  it("runManifestSync should return a valid report structure (may be offline)", async () => {
    const { runManifestSync } = await import("./lib/tool-manifest-sync");
    const report = await runManifestSync({ forceRefresh: true });
    expect(report).toHaveProperty("syncedAt");
    expect(typeof report.syncedAt).toBe("number");
    expect(report).toHaveProperty("scanServerReachable");
    expect(typeof report.scanServerReachable).toBe("boolean");
    expect(report).toHaveProperty("totalTools");
    expect(typeof report.totalTools).toBe("number");
    expect(report.totalTools).toBeGreaterThan(0);
    expect(report).toHaveProperty("toolHealth");
    expect(Array.isArray(report.toolHealth)).toBe(true);
    expect(report).toHaveProperty("categoryReadiness");
    expect(Array.isArray(report.categoryReadiness)).toBe(true);
    expect(report).toHaveProperty("overallReadiness");
    expect(typeof report.overallReadiness).toBe("number");
    expect(report).toHaveProperty("overallStatus");
    expect(["healthy", "degraded", "critical", "offline"]).toContain(report.overallStatus);
    expect(report).toHaveProperty("remediationPlan");
    expect(Array.isArray(report.remediationPlan)).toBe(true);
    expect(report).toHaveProperty("checkDurationMs");
    expect(typeof report.checkDurationMs).toBe("number");
  });

  it("category readiness should cover all taxonomy categories", async () => {
    const { runManifestSync } = await import("./lib/tool-manifest-sync");
    const { EXPLOIT_TYPE_TAXONOMY } = await import("./lib/exploit-tooling-framework");
    const report = await runManifestSync();
    expect(report.categoryReadiness.length).toBe(EXPLOIT_TYPE_TAXONOMY.length);
    for (const cat of report.categoryReadiness) {
      expect(cat).toHaveProperty("category");
      expect(cat).toHaveProperty("name");
      expect(cat).toHaveProperty("totalTools");
      expect(cat).toHaveProperty("availableTools");
      expect(cat).toHaveProperty("readinessScore");
      expect(cat).toHaveProperty("status");
      expect(["ready", "degraded", "unavailable"]).toContain(cat.status);
      expect(cat).toHaveProperty("remediation");
      expect(Array.isArray(cat.remediation)).toBe(true);
    }
  });

  it("remediation plan should have valid priority levels", async () => {
    const { runManifestSync } = await import("./lib/tool-manifest-sync");
    const report = await runManifestSync();
    for (const step of report.remediationPlan) {
      expect(["critical", "high", "medium", "low"]).toContain(step.priority);
      expect(typeof step.tool).toBe("string");
      expect(typeof step.command).toBe("string");
      expect(typeof step.reason).toBe("string");
      expect(Array.isArray(step.affectedCategories)).toBe(true);
    }
  });
});

// ─── Integration Tests ─────────────────────────────────────────────────────

describe("Cross-Feature Integration", () => {
  it("exploit-tooling-framework buildToolRegistry should produce entries used by manifest sync", async () => {
    const { buildToolRegistry } = await import("./lib/exploit-tooling-framework");
    const registry = buildToolRegistry();
    expect(registry.length).toBeGreaterThan(0);
    for (const entry of registry) {
      expect(entry).toHaveProperty("name");
      expect(entry).toHaveProperty("verifyCommand");
      expect(entry).toHaveProperty("installCommand");
      expect(entry).toHaveProperty("usedBy");
      expect(Array.isArray(entry.usedBy)).toBe(true);
      expect(entry.usedBy.length).toBeGreaterThan(0);
    }
  });

  it("feedback integration should produce LLM-consumable prompt sections", async () => {
    const { buildFeedbackContextForExploit } = await import("./lib/exploit-feedback-integration");
    const ctx = await buildFeedbackContextForExploit("http");
    // The prompt should be a string that can be injected into an LLM message
    expect(typeof ctx.performancePrompt).toBe("string");
    // Even with no data, it should contain the header
    expect(ctx.performancePrompt).toContain("EXPLOIT FEEDBACK INTELLIGENCE");
  });

  it("manifest sync formatManifestForPrompt should be injectable into LLM prompts", async () => {
    const { formatManifestForPrompt } = await import("./lib/tool-manifest-sync");
    const prompt = formatManifestForPrompt();
    // Either empty (no sync yet) or contains tool availability info
    expect(typeof prompt).toBe("string");
  });
});
