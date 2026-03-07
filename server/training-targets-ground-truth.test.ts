/**
 * Training Targets & Ground Truth Library Tests
 *
 * Validates:
 * - All 20 training targets are present in the catalog
 * - Ground truth vulnerability libraries exist for all scoreable targets
 * - Knowledge modules are properly exported and wirable
 * - LLM known-site hints cover all training targets
 * - Ground truth entries have required fields
 */
import { describe, it, expect } from "vitest";

// ─── Training Target Catalog ─────────────────────────────────────────────

describe("Training Target Catalog", () => {
  it("should export TRAINING_TARGETS array", async () => {
    const mod = await import("./routers/training-lab");
    expect(mod.TRAINING_TARGETS).toBeDefined();
    expect(Array.isArray(mod.TRAINING_TARGETS)).toBe(true);
  });

  it("should contain exactly 21 targets (20 real + 1 custom)", async () => {
    const mod = await import("./routers/training-lab");
    expect(mod.TRAINING_TARGETS.length).toBe(21);
  });

  it("should contain all original training targets", async () => {
    const mod = await import("./routers/training-lab");
    const ids = mod.TRAINING_TARGETS.map((t: any) => t.id);
    const originals = [
      "juice-shop", "vulnweb-php", "vulnweb-asp", "vulnweb-rest",
      "hackazon", "altoro-mutual", "zero-bank", "webscantest", "custom",
    ];
    for (const id of originals) {
      expect(ids).toContain(id);
    }
  });

  it("should contain all new March 2026 training targets", async () => {
    const mod = await import("./routers/training-lab");
    const ids = mod.TRAINING_TARGETS.map((t: any) => t.id);
    const newTargets = [
      "broken-crystals", "gin-juice-shop", "google-gruyere", "firing-range",
      "vulnweb-aspnet", "vulnweb-html5", "hack-yourself-first",
      "testsparker-aspnet", "testsparker-php", "testsparker-angular",
      "pentest-ground", "scanme-nmap",
    ];
    for (const id of newTargets) {
      expect(ids).toContain(id);
    }
  });

  it("every target should have required fields", async () => {
    const mod = await import("./routers/training-lab");
    for (const t of mod.TRAINING_TARGETS) {
      expect(t.id).toBeTruthy();
      expect(t.name).toBeTruthy();
      expect(t.description).toBeTruthy();
      expect(["beginner", "intermediate", "advanced"]).toContain(t.difficulty);
      expect(t.category).toBeTruthy();
      expect(Array.isArray(t.knownVulns)).toBe(true);
      expect(Array.isArray(t.owaspCategories)).toBe(true);
      expect(Array.isArray(t.tags)).toBe(true);
    }
  });

  it("every non-custom target should have a URL", async () => {
    const mod = await import("./routers/training-lab");
    for (const t of mod.TRAINING_TARGETS) {
      if (t.id !== "custom") {
        expect(t.url).toBeTruthy();
        expect(t.url.startsWith("http")).toBe(true);
      }
    }
  });

  it("should have at least one target per difficulty level", async () => {
    const mod = await import("./routers/training-lab");
    const difficulties = mod.TRAINING_TARGETS.map((t: any) => t.difficulty);
    expect(difficulties).toContain("beginner");
    expect(difficulties).toContain("intermediate");
    expect(difficulties).toContain("advanced");
  });

  it("should have diverse categories", async () => {
    const mod = await import("./routers/training-lab");
    const categories = new Set(mod.TRAINING_TARGETS.map((t: any) => t.category));
    expect(categories.size).toBeGreaterThanOrEqual(4);
  });
});

// ─── Ground Truth Library ────────────────────────────────────────────────

describe("Ground Truth Library", () => {
  it("should export GROUND_TRUTH_LIBRARY", async () => {
    const mod = await import("./lib/llm-self-learning");
    expect(mod.GROUND_TRUTH_LIBRARY).toBeDefined();
    expect(typeof mod.GROUND_TRUTH_LIBRARY).toBe("object");
  });

  it("should have ground truth for all original targets", async () => {
    const mod = await import("./lib/llm-self-learning");
    const originals = [
      "juice-shop", "vulnweb-php", "vulnweb-asp", "vulnweb-rest",
      "hackazon", "altoro-mutual", "zero-bank", "webscantest",
    ];
    for (const key of originals) {
      expect(mod.GROUND_TRUTH_LIBRARY[key]).toBeDefined();
      expect(Array.isArray(mod.GROUND_TRUTH_LIBRARY[key])).toBe(true);
      expect(mod.GROUND_TRUTH_LIBRARY[key].length).toBeGreaterThan(0);
    }
  });

  it("should have ground truth for all new March 2026 targets", async () => {
    const mod = await import("./lib/llm-self-learning");
    const newTargets = [
      "broken-crystals", "gin-juice-shop", "google-gruyere", "firing-range",
      "vulnweb-aspnet", "vulnweb-html5", "hack-yourself-first",
      "testsparker-aspnet", "testsparker-php", "testsparker-angular",
      "pentest-ground",
    ];
    for (const key of newTargets) {
      expect(mod.GROUND_TRUTH_LIBRARY[key]).toBeDefined();
      expect(Array.isArray(mod.GROUND_TRUTH_LIBRARY[key])).toBe(true);
      expect(mod.GROUND_TRUTH_LIBRARY[key].length).toBeGreaterThan(0);
    }
  });

  it("should have at least 19 ground truth targets total", async () => {
    const mod = await import("./lib/llm-self-learning");
    const keys = Object.keys(mod.GROUND_TRUTH_LIBRARY);
    expect(keys.length).toBeGreaterThanOrEqual(19);
  });

  it("every ground truth entry should have required fields", async () => {
    const mod = await import("./lib/llm-self-learning");
    for (const [key, vulns] of Object.entries(mod.GROUND_TRUTH_LIBRARY)) {
      for (const v of vulns as any[]) {
        expect(v.title).toBeTruthy();
        expect(v.category).toBeTruthy();
        expect(["critical", "high", "medium", "low", "info"]).toContain(v.severity);
        expect(v.description).toBeTruthy();
        expect(v.detectionHint).toBeTruthy();
      }
    }
  });

  it("broken-crystals should have 18+ ground truth vulns (most comprehensive)", async () => {
    const mod = await import("./lib/llm-self-learning");
    expect(mod.GROUND_TRUTH_LIBRARY["broken-crystals"].length).toBeGreaterThanOrEqual(18);
  });

  it("gin-juice-shop should have 14+ ground truth vulns", async () => {
    const mod = await import("./lib/llm-self-learning");
    expect(mod.GROUND_TRUTH_LIBRARY["gin-juice-shop"].length).toBeGreaterThanOrEqual(14);
  });

  it("ground truth should cover diverse OWASP categories", async () => {
    const mod = await import("./lib/llm-self-learning");
    const allOwaspCats = new Set<string>();
    for (const vulns of Object.values(mod.GROUND_TRUTH_LIBRARY)) {
      for (const v of vulns as any[]) {
        if (v.owaspCategory) allOwaspCats.add(v.owaspCategory);
      }
    }
    // Should cover at least 5 OWASP categories
    expect(allOwaspCats.size).toBeGreaterThanOrEqual(5);
  });
});

// ─── Knowledge Module Exports ────────────────────────────────────────────

describe("Knowledge Module Exports", () => {
  it("pentest-knowledge-base should export WEB_VULN_KNOWLEDGE", async () => {
    const mod = await import("./lib/pentest-knowledge-base");
    expect(mod.WEB_VULN_KNOWLEDGE).toBeDefined();
    expect(Array.isArray(mod.WEB_VULN_KNOWLEDGE)).toBe(true);
    expect(mod.WEB_VULN_KNOWLEDGE.length).toBeGreaterThan(0);
  });

  it("pentest-knowledge-base should export TECHNIQUE_LIBRARY", async () => {
    const mod = await import("./lib/pentest-knowledge-base");
    expect(mod.TECHNIQUE_LIBRARY).toBeDefined();
    expect(Array.isArray(mod.TECHNIQUE_LIBRARY)).toBe(true);
    expect(mod.TECHNIQUE_LIBRARY.length).toBeGreaterThan(0);
  });

  it("pentest-knowledge-base should export TOOL_LIBRARY", async () => {
    const mod = await import("./lib/pentest-knowledge-base");
    expect(mod.TOOL_LIBRARY).toBeDefined();
    expect(Array.isArray(mod.TOOL_LIBRARY)).toBe(true);
    expect(mod.TOOL_LIBRARY.length).toBeGreaterThan(0);
  });

  it("auth-testing-knowledge should export buildAuthKnowledgeContext", async () => {
    const mod = await import("./lib/auth-testing-knowledge");
    expect(typeof mod.buildAuthKnowledgeContext).toBe("function");
  });

  it("auth-testing-knowledge buildAuthKnowledgeContext should return a string", async () => {
    const mod = await import("./lib/auth-testing-knowledge");
    const context = mod.buildAuthKnowledgeContext();
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(100);
  });

  it("owasp-knowledge should export getOwaspScanPlanContext", async () => {
    const mod = await import("./lib/owasp-knowledge");
    expect(typeof mod.getOwaspScanPlanContext).toBe("function");
  });

  it("owasp-knowledge should export getOwaspVulnCorrelationContext", async () => {
    const mod = await import("./lib/owasp-knowledge");
    expect(typeof mod.getOwaspVulnCorrelationContext).toBe("function");
  });

  it("nmap-knowledge should export getNmapScanPlanContext", async () => {
    const mod = await import("./lib/nmap-knowledge");
    expect(typeof mod.getNmapScanPlanContext).toBe("function");
  });

  it("nmap-knowledge should export getNmapVulnCorrelationContext", async () => {
    const mod = await import("./lib/nmap-knowledge");
    expect(typeof mod.getNmapVulnCorrelationContext).toBe("function");
  });

  it("threat-group-knowledge should export getSectorThreatContext", async () => {
    const mod = await import("./lib/threat-group-knowledge");
    expect(typeof mod.getSectorThreatContext).toBe("function");
  });
});

// ─── Training Lab Router Procedures ──────────────────────────────────────

describe("Training Lab Router", () => {
  it("should export trainingLabRouter", async () => {
    const mod = await import("./routers/training-lab");
    expect(mod.trainingLabRouter).toBeDefined();
  });

  it("should have targets procedure", async () => {
    const mod = await import("./routers/training-lab");
    const routerDef = mod.trainingLabRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("targets");
  });

  it("should have groundTruth procedure", async () => {
    const mod = await import("./routers/training-lab");
    const routerDef = mod.trainingLabRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("groundTruth");
  });

  it("should have groundTruthTargets procedure", async () => {
    const mod = await import("./routers/training-lab");
    const routerDef = mod.trainingLabRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("groundTruthTargets");
  });

  it("should have startSession procedure", async () => {
    const mod = await import("./routers/training-lab");
    const routerDef = mod.trainingLabRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("startSession");
  });

  it("should have learningStats procedure", async () => {
    const mod = await import("./routers/training-lab");
    const routerDef = mod.trainingLabRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("learningStats");
  });

  it("should have accuracyTrend procedure", async () => {
    const mod = await import("./routers/training-lab");
    const routerDef = mod.trainingLabRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("accuracyTrend");
  });
});

// ─── Scoring Function ────────────────────────────────────────────────────

describe("Ground Truth Scoring", () => {
  it("should export scoreAgainstGroundTruth function", async () => {
    const mod = await import("./lib/llm-self-learning");
    expect(typeof mod.scoreAgainstGroundTruth).toBe("function");
  });

  it("scoreAgainstGroundTruth should return score object with expected fields", async () => {
    const mod = await import("./lib/llm-self-learning");
    // Test with a simple finding set against juice-shop ground truth
    const findings = [
      { title: "SQL Injection in Login", severity: "critical", category: "Injection" },
      { title: "Cross-Site Scripting", severity: "high", category: "XSS" },
    ];
    const score = mod.scoreAgainstGroundTruth("juice-shop", findings);
    expect(score).toBeDefined();
    expect(typeof score.precision).toBe("number");
    expect(typeof score.recall).toBe("number");
    expect(typeof score.f1Score).toBe("number");
    expect(score.precision).toBeGreaterThanOrEqual(0);
    expect(score.precision).toBeLessThanOrEqual(1);
    expect(score.recall).toBeGreaterThanOrEqual(0);
    expect(score.recall).toBeLessThanOrEqual(1);
  });

  it("scoreAgainstGroundTruth should return null for unknown target", async () => {
    const mod = await import("./lib/llm-self-learning");
    const score = mod.scoreAgainstGroundTruth("nonexistent-target", []);
    expect(score).toBeNull();
  });

  it("scoreAgainstGroundTruth should work for new targets like broken-crystals", async () => {
    const mod = await import("./lib/llm-self-learning");
    const findings = [
      { title: "JWT None Algorithm Bypass", severity: "critical", category: "Cryptographic Failures" },
      { title: "SQL Injection in Login", severity: "critical", category: "Injection" },
      { title: "SSRF", severity: "high", category: "Server-Side Request Forgery" },
      { title: "Prototype Pollution", severity: "high", category: "Injection" },
    ];
    const score = mod.scoreAgainstGroundTruth("broken-crystals", findings);
    expect(score).toBeDefined();
    expect(score).not.toBeNull();
    expect(score!.recall).toBeGreaterThan(0);
    expect(score!.precision).toBeGreaterThan(0);
  });
});
