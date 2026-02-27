/**
 * AI Security Validation — Vitest Tests
 * ──────────────────────────────────────
 * Tests for MITRE ATLAS technique catalog, test payloads,
 * scan lifecycle, quick assessment, and category descriptions.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock ENV
vi.mock("./_core/env", () => ({
  ENV: {
    CS_TEAM_SERVER_URL: "https://cs.test",
    CS_API_KEY: "test-key",
    CS_API_PORT: "50050",
  },
}));

// Mock fetch for scan tests
const mockFetch = vi.fn();
global.fetch = mockFetch;

import {
  ATLAS_TECHNIQUES,
  PROMPT_INJECTION_PAYLOADS,
  MODEL_EXTRACTION_PAYLOADS,
  ADVERSARIAL_EVASION_PAYLOADS,
  DATA_POISONING_PAYLOADS,
  SUPPLY_CHAIN_PAYLOADS,
  getATLASTechniques,
  getTestPayloadsByCategory,
  getCategoryDescriptions,
  runQuickAssessment,
  startAISecurityScan,
  getScanResult,
  getAllScans,
  deleteScan,
  type AITargetConfig,
} from "./lib/ai-security-validation";

// ─── ATLAS Technique Catalog ─────────────────────────────────────────────────
describe("ATLAS Technique Catalog", () => {
  it("should have at least 20 techniques", () => {
    expect(ATLAS_TECHNIQUES.length).toBeGreaterThanOrEqual(20);
  });

  it("every technique has required fields", () => {
    for (const t of ATLAS_TECHNIQUES) {
      expect(t.id).toMatch(/^AML\.T\d{4}/);
      expect(t.name).toBeTruthy();
      expect(t.description).toBeTruthy();
      expect(t.tactic).toBeTruthy();
      expect(t.testCategory).toBeTruthy();
      expect(["critical", "high", "medium", "low", "info"]).toContain(t.severity);
    }
  });

  it("technique IDs are unique", () => {
    const ids = ATLAS_TECHNIQUES.map(t => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("getATLASTechniques returns the full catalog", () => {
    const result = getATLASTechniques();
    expect(result).toEqual(ATLAS_TECHNIQUES);
    expect(result.length).toBe(ATLAS_TECHNIQUES.length);
  });

  it("covers all expected categories", () => {
    const categories = new Set(ATLAS_TECHNIQUES.map(t => t.testCategory));
    expect(categories.has("prompt-injection")).toBe(true);
    expect(categories.has("model-extraction")).toBe(true);
    expect(categories.has("adversarial-evasion")).toBe(true);
    expect(categories.has("data-poisoning")).toBe(true);
    expect(categories.has("supply-chain")).toBe(true);
  });
});

// ─── Test Payloads ───────────────────────────────────────────────────────────
describe("Test Payloads", () => {
  it("prompt injection payloads are non-empty", () => {
    expect(PROMPT_INJECTION_PAYLOADS.length).toBeGreaterThanOrEqual(5);
  });

  it("model extraction payloads are non-empty", () => {
    expect(MODEL_EXTRACTION_PAYLOADS.length).toBeGreaterThanOrEqual(3);
  });

  it("adversarial evasion payloads are non-empty", () => {
    expect(ADVERSARIAL_EVASION_PAYLOADS.length).toBeGreaterThanOrEqual(3);
  });

  it("data poisoning payloads are non-empty", () => {
    expect(DATA_POISONING_PAYLOADS.length).toBeGreaterThanOrEqual(3);
  });

  it("supply chain payloads are non-empty", () => {
    expect(SUPPLY_CHAIN_PAYLOADS.length).toBeGreaterThanOrEqual(3);
  });

  it("every payload has required fields", () => {
    const allPayloads = [
      ...PROMPT_INJECTION_PAYLOADS,
      ...MODEL_EXTRACTION_PAYLOADS,
      ...ADVERSARIAL_EVASION_PAYLOADS,
      ...DATA_POISONING_PAYLOADS,
      ...SUPPLY_CHAIN_PAYLOADS,
    ];
    for (const p of allPayloads) {
      expect(p.id).toBeTruthy();
      expect(p.name).toBeTruthy();
      expect(p.payload).toBeTruthy();
      expect(p.techniqueId).toMatch(/^AML\.T\d{4}/);
      expect(["critical", "high", "medium", "low", "info"]).toContain(p.severity);
      expect(p.expectedBehavior).toBeTruthy();
    }
  });

  it("getTestPayloadsByCategory returns all categories", () => {
    const result = getTestPayloadsByCategory();
    expect(result["prompt-injection"].length).toBe(PROMPT_INJECTION_PAYLOADS.length);
    expect(result["model-extraction"].length).toBe(MODEL_EXTRACTION_PAYLOADS.length);
    expect(result["adversarial-evasion"].length).toBe(ADVERSARIAL_EVASION_PAYLOADS.length);
    expect(result["data-poisoning"].length).toBe(DATA_POISONING_PAYLOADS.length);
    expect(result["supply-chain"].length).toBe(SUPPLY_CHAIN_PAYLOADS.length);
  });
});

// ─── Category Descriptions ───────────────────────────────────────────────────
describe("Category Descriptions", () => {
  it("returns descriptions for all 8 categories", () => {
    const cats = getCategoryDescriptions();
    const keys = Object.keys(cats);
    expect(keys).toContain("prompt-injection");
    expect(keys).toContain("model-extraction");
    expect(keys).toContain("adversarial-evasion");
    expect(keys).toContain("data-poisoning");
    expect(keys).toContain("supply-chain");
    expect(keys).toContain("model-inversion");
    expect(keys).toContain("membership-inference");
    expect(keys).toContain("denial-of-service");
  });

  it("each category has name, description, icon, and counts", () => {
    const cats = getCategoryDescriptions();
    for (const [, cat] of Object.entries(cats)) {
      expect(cat.name).toBeTruthy();
      expect(cat.description).toBeTruthy();
      expect(cat.icon).toBeTruthy();
      expect(typeof cat.techniqueCount).toBe("number");
      expect(typeof cat.payloadCount).toBe("number");
    }
  });
});

// ─── Quick Assessment ────────────────────────────────────────────────────────
describe("Quick Assessment", () => {
  it("returns 100% for all-true answers", () => {
    const result = runQuickAssessment({
      hasInputValidation: true,
      hasOutputFiltering: true,
      hasRateLimiting: true,
      hasModelAccessControls: true,
      hasDataProvenance: true,
      hasDependencyScanning: true,
      hasPromptGuardrails: true,
      hasAuditLogging: true,
      hasAdversarialTesting: true,
      hasIncidentResponse: true,
    });
    expect(result.overall).toBe(100);
    expect(result.grade).toBe("A");
  });

  it("returns 0% for all-false answers", () => {
    const result = runQuickAssessment({
      hasInputValidation: false,
      hasOutputFiltering: false,
      hasRateLimiting: false,
      hasModelAccessControls: false,
      hasDataProvenance: false,
      hasDependencyScanning: false,
      hasPromptGuardrails: false,
      hasAuditLogging: false,
      hasAdversarialTesting: false,
      hasIncidentResponse: false,
    });
    expect(result.overall).toBe(0);
    expect(result.grade).toBe("F");
    expect(result.promptInjection).toBe(0);
    expect(result.modelExtraction).toBe(0);
    expect(result.adversarialEvasion).toBe(0);
    expect(result.dataPoisoning).toBe(0);
    expect(result.supplyChain).toBe(0);
  });

  it("returns partial score for mixed answers", () => {
    const result = runQuickAssessment({
      hasInputValidation: true,
      hasOutputFiltering: true,
      hasRateLimiting: true,
      hasModelAccessControls: false,
      hasDataProvenance: false,
      hasDependencyScanning: false,
      hasPromptGuardrails: true,
      hasAuditLogging: false,
      hasAdversarialTesting: false,
      hasIncidentResponse: false,
    });
    expect(result.overall).toBeGreaterThan(0);
    expect(result.overall).toBeLessThan(100);
    // Prompt injection should be high (3 of 3 checks true)
    expect(result.promptInjection).toBe(100);
    // Model extraction should be partial (rate limiting true, access controls false)
    expect(result.modelExtraction).toBeGreaterThan(0);
    expect(result.modelExtraction).toBeLessThan(100);
  });

  it("grade follows score thresholds", () => {
    // All true = 100 = A
    const a = runQuickAssessment({
      hasInputValidation: true, hasOutputFiltering: true, hasRateLimiting: true,
      hasModelAccessControls: true, hasDataProvenance: true, hasDependencyScanning: true,
      hasPromptGuardrails: true, hasAuditLogging: true, hasAdversarialTesting: true,
      hasIncidentResponse: true,
    });
    expect(a.grade).toBe("A");

    // All false = 0 = F
    const f = runQuickAssessment({
      hasInputValidation: false, hasOutputFiltering: false, hasRateLimiting: false,
      hasModelAccessControls: false, hasDataProvenance: false, hasDependencyScanning: false,
      hasPromptGuardrails: false, hasAuditLogging: false, hasAdversarialTesting: false,
      hasIncidentResponse: false,
    });
    expect(f.grade).toBe("F");
  });
});

// ─── Scan Lifecycle ──────────────────────────────────────────────────────────
describe("Scan Lifecycle", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    // Default mock: simulate a target endpoint that returns a response
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ choices: [{ message: { content: "I cannot help with that request." } }] }),
      text: async () => "I cannot help with that request.",
      status: 200,
    });
  });

  it("startAISecurityScan creates a scan with correct metadata", async () => {
    const target: AITargetConfig = {
      name: "Test LLM",
      type: "llm-api",
      endpoint: "https://api.test.com/v1/chat",
      enabledCategories: ["prompt-injection"],
      maxConcurrency: 1,
      timeoutMs: 5000,
    };

    const scan = await startAISecurityScan(target);
    expect(scan.scanId).toBeTruthy();
    expect(scan.targetName).toBe("Test LLM");
    expect(scan.targetType).toBe("llm-api");
    expect(scan.totalTests).toBeGreaterThan(0);
    expect(["running", "completed"]).toContain(scan.status);
  });

  it("getScanResult returns the scan by ID", async () => {
    const target: AITargetConfig = {
      name: "Lookup Test",
      type: "chat-endpoint",
      endpoint: "https://api.test.com/chat",
      enabledCategories: ["prompt-injection"],
      maxConcurrency: 1,
      timeoutMs: 5000,
    };

    const scan = await startAISecurityScan(target);
    const retrieved = getScanResult(scan.scanId);
    expect(retrieved).toBeDefined();
    expect(retrieved?.scanId).toBe(scan.scanId);
    expect(retrieved?.targetName).toBe("Lookup Test");
  });

  it("getScanResult returns undefined for non-existent ID", () => {
    const result = getScanResult("non-existent-id");
    expect(result).toBeUndefined();
  });

  it("getAllScans returns all created scans", async () => {
    const before = getAllScans().length;
    const target: AITargetConfig = {
      name: "List Test",
      type: "llm-api",
      endpoint: "https://api.test.com/v1/chat",
      enabledCategories: ["supply-chain"],
      maxConcurrency: 1,
      timeoutMs: 5000,
    };
    await startAISecurityScan(target);
    const after = getAllScans().length;
    expect(after).toBe(before + 1);
  });

  it("deleteScan removes the scan", async () => {
    const target: AITargetConfig = {
      name: "Delete Test",
      type: "llm-api",
      endpoint: "https://api.test.com/v1/chat",
      enabledCategories: ["prompt-injection"],
      maxConcurrency: 1,
      timeoutMs: 5000,
    };
    const scan = await startAISecurityScan(target);
    expect(deleteScan(scan.scanId)).toBe(true);
    expect(getScanResult(scan.scanId)).toBeUndefined();
  });

  it("deleteScan returns false for non-existent ID", () => {
    expect(deleteScan("non-existent")).toBe(false);
  });

  it("scan with multiple categories creates more tests", async () => {
    const singleCat: AITargetConfig = {
      name: "Single Cat",
      type: "llm-api",
      endpoint: "https://api.test.com/v1/chat",
      enabledCategories: ["prompt-injection"],
      maxConcurrency: 1,
      timeoutMs: 5000,
    };
    const multiCat: AITargetConfig = {
      name: "Multi Cat",
      type: "llm-api",
      endpoint: "https://api.test.com/v1/chat",
      enabledCategories: ["prompt-injection", "model-extraction", "supply-chain"],
      maxConcurrency: 1,
      timeoutMs: 5000,
    };
    const s1 = await startAISecurityScan(singleCat);
    const s2 = await startAISecurityScan(multiCat);
    expect(s2.totalTests).toBeGreaterThan(s1.totalTests);
  });

  it("scan generates posture score", async () => {
    const target: AITargetConfig = {
      name: "Score Test",
      type: "llm-api",
      endpoint: "https://api.test.com/v1/chat",
      enabledCategories: ["prompt-injection"],
      maxConcurrency: 1,
      timeoutMs: 5000,
    };
    const scan = await startAISecurityScan(target);
    // Wait a tick for async scan to progress
    await new Promise(r => setTimeout(r, 100));
    const result = getScanResult(scan.scanId);
    expect(result?.postureScore).toBeDefined();
    expect(typeof result?.postureScore.overall).toBe("number");
    expect(result?.postureScore.overall).toBeGreaterThanOrEqual(0);
    expect(result?.postureScore.overall).toBeLessThanOrEqual(100);
  });
});

// ─── Payload-Technique Mapping ───────────────────────────────────────────────
describe("Payload-Technique Mapping", () => {
  it("every payload references a valid ATLAS technique ID", () => {
    const techniqueIds = new Set(ATLAS_TECHNIQUES.map(t => t.id));
    const allPayloads = [
      ...PROMPT_INJECTION_PAYLOADS,
      ...MODEL_EXTRACTION_PAYLOADS,
      ...ADVERSARIAL_EVASION_PAYLOADS,
      ...DATA_POISONING_PAYLOADS,
      ...SUPPLY_CHAIN_PAYLOADS,
    ];
    for (const p of allPayloads) {
      expect(
        techniqueIds.has(p.techniqueId),
        `Payload ${p.id} references unknown technique ${p.techniqueId}`
      ).toBe(true);
    }
  });

  it("total payload count matches sum of all category arrays", () => {
    const byCategory = getTestPayloadsByCategory();
    const totalFromCategories = Object.values(byCategory).reduce((sum, arr) => sum + arr.length, 0);
    const totalDirect =
      PROMPT_INJECTION_PAYLOADS.length +
      MODEL_EXTRACTION_PAYLOADS.length +
      ADVERSARIAL_EVASION_PAYLOADS.length +
      DATA_POISONING_PAYLOADS.length +
      SUPPLY_CHAIN_PAYLOADS.length;
    expect(totalFromCategories).toBeGreaterThanOrEqual(totalDirect);
  });
});
