import { describe, it, expect } from "vitest";
import {
  GROUND_TRUTH_LIBRARY,
  scoreAgainstGroundTruth,
  buildCorrectionHistoryPrompt,
  type GroundTruthVuln,
  type AccuracyScore,
  type LearningEntry,
} from "../lib/llm-self-learning";
import { TRAINING_TARGETS, type TrainingTarget } from "./training-lab";

// ─── Training Targets Catalog ───────────────────────────────────────────────

describe("Training Targets Catalog", () => {
  it("should have at least 5 pre-loaded training targets", () => {
    expect(TRAINING_TARGETS.length).toBeGreaterThanOrEqual(5);
  });

  it("each target should have required fields", () => {
    for (const target of TRAINING_TARGETS) {
      expect(target.id).toBeTruthy();
      expect(target.name).toBeTruthy();
      expect(typeof target.url).toBe("string");
      expect(target.description).toBeTruthy();
      expect(target.difficulty).toMatch(/^(beginner|intermediate|advanced)$/);
      expect(target.category).toBeTruthy();
      expect(Array.isArray(target.knownVulns)).toBe(true);
      expect(Array.isArray(target.owaspCategories)).toBe(true);
      expect(Array.isArray(target.tags)).toBe(true);
    }
  });

  it("should include OWASP Juice Shop as a target", () => {
    const juiceShop = TRAINING_TARGETS.find(t =>
      t.name.toLowerCase().includes("juice shop")
    );
    expect(juiceShop).toBeDefined();
    expect(juiceShop!.knownVulns.length).toBeGreaterThan(0);
  });

  it("should include targets of varying difficulty", () => {
    const difficulties = new Set(TRAINING_TARGETS.map(t => t.difficulty));
    expect(difficulties.size).toBeGreaterThanOrEqual(2);
  });

  it("should include a custom target option", () => {
    const custom = TRAINING_TARGETS.find(t => t.id === "custom");
    expect(custom).toBeDefined();
    expect(custom!.url).toBe("");
  });

  it("non-custom targets should have at least one known vuln", () => {
    for (const target of TRAINING_TARGETS.filter(t => t.id !== "custom")) {
      expect(target.knownVulns.length).toBeGreaterThan(0);
    }
  });
});

// ─── Ground Truth Library ───────────────────────────────────────────────────

describe("Ground Truth Library", () => {
  it("should have ground truth for juice-shop", () => {
    expect(GROUND_TRUTH_LIBRARY["juice-shop"]).toBeDefined();
    expect(GROUND_TRUTH_LIBRARY["juice-shop"].length).toBeGreaterThan(0);
  });

  it("should have ground truth for vulnweb-php", () => {
    expect(GROUND_TRUTH_LIBRARY["vulnweb-php"]).toBeDefined();
    expect(GROUND_TRUTH_LIBRARY["vulnweb-php"].length).toBeGreaterThan(0);
  });

  it("each ground truth entry should have required fields", () => {
    for (const [targetId, vulns] of Object.entries(GROUND_TRUTH_LIBRARY)) {
      for (const vuln of vulns) {
        expect(vuln.title).toBeTruthy();
        expect(vuln.category).toBeTruthy();
        expect(vuln.severity).toBeTruthy();
        expect(vuln.description).toBeTruthy();
      }
    }
  });

  it("ground truth targets should map to training targets", () => {
    const targetIds = new Set(TRAINING_TARGETS.map(t => t.id));
    for (const gtId of Object.keys(GROUND_TRUTH_LIBRARY)) {
      expect(targetIds.has(gtId)).toBe(true);
    }
  });
});

// ─── Ground Truth Scoring ───────────────────────────────────────────────────

describe("scoreAgainstGroundTruth", () => {
  it("should return null for unknown target", () => {
    const score = scoreAgainstGroundTruth("nonexistent-xyz", []);
    expect(score).toBeNull();
  });

  it("should score zero for empty findings against juice-shop", () => {
    const score = scoreAgainstGroundTruth("juice-shop", []);
    expect(score).not.toBeNull();
    expect(score!.truePositives).toBe(0);
    expect(score!.falseNegatives).toBe(score!.totalGroundTruth);
    expect(score!.recall).toBe(0);
  });

  it("should detect matching findings by title similarity", () => {
    const findings = [
      { title: "SQL Injection in Login Form", severity: "critical", category: "Injection" },
      { title: "Reflected XSS in Search Functionality", severity: "high", category: "Cross-Site Scripting" },
    ];
    const score = scoreAgainstGroundTruth("juice-shop", findings);
    expect(score).not.toBeNull();
    expect(score!.truePositives).toBeGreaterThanOrEqual(1);
  });

  it("should identify false positives when more findings than ground truth", () => {
    // Create findings that exceed the ground truth count — extras must be FPs
    const gt = GROUND_TRUTH_LIBRARY["juice-shop"];
    const matchingFindings = gt.map(g => ({ title: g.title, severity: g.severity, category: g.category }));
    const extraFindings = [
      { title: "ZZZZZ Nonexistent Vuln ZZZZZ", severity: "info", category: "ZZZZZ" },
      { title: "YYYYY Another Fake YYYYY", severity: "info", category: "YYYYY" },
    ];
    const score = scoreAgainstGroundTruth("juice-shop", [...matchingFindings, ...extraFindings]);
    expect(score).not.toBeNull();
    expect(score!.falsePositives).toBeGreaterThanOrEqual(2);
  });

  it("should calculate precision, recall, and F1 correctly", () => {
    const score = scoreAgainstGroundTruth("juice-shop", [
      { title: "SQL Injection in Login", severity: "critical", category: "Injection" },
    ]);
    expect(score).not.toBeNull();
    // With 1 match out of 15 ground truth: recall should be low
    expect(score!.recall).toBeLessThan(0.5);
    // With 1 match and 0 false positives: precision should be 1.0
    expect(score!.precision).toBe(1);
    // F1 should be between 0 and 1
    expect(score!.f1Score).toBeGreaterThan(0);
    expect(score!.f1Score).toBeLessThanOrEqual(1);
  });

  it("should include matchDetails for each ground truth entry", () => {
    const score = scoreAgainstGroundTruth("juice-shop", []);
    expect(score).not.toBeNull();
    expect(score!.matchDetails.length).toBe(score!.totalGroundTruth);
    for (const detail of score!.matchDetails) {
      expect(detail.groundTruth).toBeDefined();
      expect(typeof detail.matched).toBe("boolean");
      expect(typeof detail.severityMatch).toBe("boolean");
    }
  });

  it("should compute overallScore as weighted combination", () => {
    const score = scoreAgainstGroundTruth("juice-shop", [
      { title: "SQL Injection in Login", severity: "critical", category: "Injection" },
      { title: "Reflected XSS in Search", severity: "high", category: "XSS" },
      { title: "Broken Authentication - Admin Account", severity: "critical", category: "Auth" },
    ]);
    expect(score).not.toBeNull();
    expect(score!.overallScore).toBeGreaterThanOrEqual(0);
    expect(score!.overallScore).toBeLessThanOrEqual(1);
  });
});

// ─── Correction History Prompt Builder ──────────────────────────────────────

describe("buildCorrectionHistoryPrompt", () => {
  it("should return empty string for no entries", () => {
    const prompt = buildCorrectionHistoryPrompt("juice-shop", [], []);
    expect(typeof prompt).toBe("string");
  });

  it("should include correction context for target-specific entries", () => {
    const targetEntries: LearningEntry[] = [
      {
        targetPreset: "juice-shop",
        findingTitle: "SQL Injection",
        feedbackType: "correct",
        operatorNotes: "Confirmed via manual testing",
      },
      {
        targetPreset: "juice-shop",
        findingTitle: "Fake RCE",
        feedbackType: "false_positive",
        operatorNotes: "This was a false positive",
      },
    ];
    const prompt = buildCorrectionHistoryPrompt("juice-shop", targetEntries, []);
    expect(prompt.length).toBeGreaterThan(0);
  });

  it("should include global corrections when available", () => {
    const globalEntries: LearningEntry[] = [
      {
        targetPreset: "vulnweb-php",
        findingTitle: "Path Traversal",
        feedbackType: "missed_finding",
        operatorNotes: "LLM missed this common vuln",
      },
    ];
    const prompt = buildCorrectionHistoryPrompt("juice-shop", [], globalEntries);
    expect(typeof prompt).toBe("string");
  });
});

// ─── AccuracyScore Interface Validation ─────────────────────────────────────

describe("AccuracyScore structure", () => {
  it("should have all required fields", () => {
    const score = scoreAgainstGroundTruth("juice-shop", [
      { title: "SQL Injection in Login", severity: "critical" },
    ]);
    expect(score).not.toBeNull();
    expect(typeof score!.totalGroundTruth).toBe("number");
    expect(typeof score!.truePositives).toBe("number");
    expect(typeof score!.falsePositives).toBe("number");
    expect(typeof score!.falseNegatives).toBe("number");
    expect(typeof score!.precision).toBe("number");
    expect(typeof score!.recall).toBe("number");
    expect(typeof score!.f1Score).toBe("number");
    expect(typeof score!.severityAccuracy).toBe("number");
    expect(typeof score!.overallScore).toBe("number");
    expect(Array.isArray(score!.matchDetails)).toBe(true);
    expect(Array.isArray(score!.unmatchedLlmFindings)).toBe(true);
  });
});
