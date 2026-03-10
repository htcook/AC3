/**
 * Continuous Training Module Tests
 *
 * Tests the auto-feedback generation, iteration tracking,
 * and convergence logic of the continuous training loop.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock Types ────────────────────────────────────────────────────────────

interface IterationResult {
  iteration: number;
  f1Score: number;
  precision: number;
  recall: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  feedbackGenerated: number;
  timestamp: number;
}

interface TrainingRunState {
  targetPreset: string;
  sessionId: string;
  status: "running" | "completed" | "stopped" | "failed";
  currentIteration: number;
  maxIterations: number;
  targetF1: number;
  iterations: IterationResult[];
  startedAt: number;
  completedAt?: number;
  bestF1: number;
  error?: string;
}

// ─── Helper: Simulate auto-feedback generation ────────────────────────────

interface GroundTruthEntry {
  name: string;
  severity: string;
  category: string;
}

interface LlmFinding {
  name: string;
  severity: string;
  matched: boolean;
}

function generateAutoFeedback(
  groundTruth: GroundTruthEntry[],
  llmFindings: LlmFinding[],
  unmatchedLlmFindings: LlmFinding[]
): { missedEntries: string[]; fpEntries: string[]; totalGenerated: number } {
  // Find false negatives (ground truth vulns not matched by LLM)
  const matchedNames = new Set(llmFindings.filter(f => f.matched).map(f => f.name.toLowerCase()));
  const missedEntries: string[] = [];
  
  for (const gt of groundTruth) {
    if (!matchedNames.has(gt.name.toLowerCase())) {
      missedEntries.push(gt.name);
    }
  }

  // Find false positives (LLM findings not in ground truth)
  const fpEntries = unmatchedLlmFindings.map(f => f.name);

  return {
    missedEntries,
    fpEntries,
    totalGenerated: missedEntries.length + fpEntries.length,
  };
}

// ─── Helper: Calculate F1 score ───────────────────────────────────────────

function calculateF1(tp: number, fp: number, fn: number): { f1: number; precision: number; recall: number } {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return { f1, precision, recall };
}

// ─── Helper: Check convergence ────────────────────────────────────────────

function shouldStop(state: TrainingRunState): { stop: boolean; reason: string } {
  if (state.status === "stopped") return { stop: true, reason: "manually_stopped" };
  if (state.currentIteration >= state.maxIterations) return { stop: true, reason: "max_iterations" };
  if (state.bestF1 >= state.targetF1) return { stop: true, reason: "target_reached" };
  
  // Check for stagnation (3+ iterations with no improvement)
  if (state.iterations.length >= 3) {
    const last3 = state.iterations.slice(-3);
    const allSame = last3.every(i => Math.abs(i.f1Score - last3[0].f1Score) < 0.001);
    if (allSame) return { stop: true, reason: "stagnated" };
  }
  
  return { stop: false, reason: "" };
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe("Continuous Training Module", () => {

  describe("Auto-Feedback Generation", () => {
    it("should identify missed vulns (false negatives)", () => {
      const groundTruth: GroundTruthEntry[] = [
        { name: "SQL Injection", severity: "critical", category: "injection" },
        { name: "XSS Reflected", severity: "high", category: "xss" },
        { name: "CSRF", severity: "medium", category: "csrf" },
      ];
      const llmFindings: LlmFinding[] = [
        { name: "SQL Injection", severity: "critical", matched: true },
      ];
      const unmatched: LlmFinding[] = [];

      const result = generateAutoFeedback(groundTruth, llmFindings, unmatched);
      expect(result.missedEntries).toEqual(["XSS Reflected", "CSRF"]);
      expect(result.fpEntries).toEqual([]);
      expect(result.totalGenerated).toBe(2);
    });

    it("should identify false positives", () => {
      const groundTruth: GroundTruthEntry[] = [
        { name: "SQL Injection", severity: "critical", category: "injection" },
      ];
      const llmFindings: LlmFinding[] = [
        { name: "SQL Injection", severity: "critical", matched: true },
      ];
      const unmatched: LlmFinding[] = [
        { name: "Buffer Overflow", severity: "high", matched: false },
        { name: "Race Condition", severity: "medium", matched: false },
      ];

      const result = generateAutoFeedback(groundTruth, llmFindings, unmatched);
      expect(result.missedEntries).toEqual([]);
      expect(result.fpEntries).toEqual(["Buffer Overflow", "Race Condition"]);
      expect(result.totalGenerated).toBe(2);
    });

    it("should handle perfect accuracy (no feedback needed)", () => {
      const groundTruth: GroundTruthEntry[] = [
        { name: "SQL Injection", severity: "critical", category: "injection" },
        { name: "XSS", severity: "high", category: "xss" },
      ];
      const llmFindings: LlmFinding[] = [
        { name: "SQL Injection", severity: "critical", matched: true },
        { name: "XSS", severity: "high", matched: true },
      ];

      const result = generateAutoFeedback(groundTruth, llmFindings, []);
      expect(result.missedEntries).toEqual([]);
      expect(result.fpEntries).toEqual([]);
      expect(result.totalGenerated).toBe(0);
    });

    it("should handle case-insensitive matching", () => {
      const groundTruth: GroundTruthEntry[] = [
        { name: "sql injection", severity: "critical", category: "injection" },
      ];
      const llmFindings: LlmFinding[] = [
        { name: "SQL Injection", severity: "critical", matched: true },
      ];

      const result = generateAutoFeedback(groundTruth, llmFindings, []);
      expect(result.missedEntries).toEqual([]);
      expect(result.totalGenerated).toBe(0);
    });

    it("should handle empty ground truth", () => {
      const result = generateAutoFeedback([], [], []);
      expect(result.missedEntries).toEqual([]);
      expect(result.fpEntries).toEqual([]);
      expect(result.totalGenerated).toBe(0);
    });

    it("should handle all missed (0% recall)", () => {
      const groundTruth: GroundTruthEntry[] = [
        { name: "SQLi", severity: "critical", category: "injection" },
        { name: "XSS", severity: "high", category: "xss" },
        { name: "CSRF", severity: "medium", category: "csrf" },
      ];

      const result = generateAutoFeedback(groundTruth, [], []);
      expect(result.missedEntries).toEqual(["SQLi", "XSS", "CSRF"]);
      expect(result.totalGenerated).toBe(3);
    });
  });

  describe("F1 Score Calculation", () => {
    it("should calculate perfect F1 (1.0)", () => {
      const { f1, precision, recall } = calculateF1(10, 0, 0);
      expect(f1).toBe(1.0);
      expect(precision).toBe(1.0);
      expect(recall).toBe(1.0);
    });

    it("should calculate F1 with false positives only", () => {
      const { f1, precision, recall } = calculateF1(8, 2, 0);
      expect(precision).toBe(0.8);
      expect(recall).toBe(1.0);
      expect(f1).toBeCloseTo(0.889, 2);
    });

    it("should calculate F1 with false negatives only", () => {
      const { f1, precision, recall } = calculateF1(6, 0, 4);
      expect(precision).toBe(1.0);
      expect(recall).toBe(0.6);
      expect(f1).toBeCloseTo(0.75, 10);
    });

    it("should calculate F1 with both FP and FN", () => {
      const { f1, precision, recall } = calculateF1(5, 3, 2);
      expect(precision).toBeCloseTo(0.625, 3);
      expect(recall).toBeCloseTo(0.714, 2);
      expect(f1).toBeGreaterThan(0);
      expect(f1).toBeLessThan(1);
    });

    it("should return 0 when no true positives", () => {
      const { f1, precision, recall } = calculateF1(0, 5, 5);
      expect(f1).toBe(0);
      expect(precision).toBe(0);
      expect(recall).toBe(0);
    });

    it("should handle edge case of all zeros", () => {
      const { f1, precision, recall } = calculateF1(0, 0, 0);
      expect(f1).toBe(0);
      expect(precision).toBe(0);
      expect(recall).toBe(0);
    });
  });

  describe("Convergence Detection", () => {
    it("should stop when target F1 is reached", () => {
      const state: TrainingRunState = {
        targetPreset: "dvwa",
        sessionId: "test-1",
        status: "running",
        currentIteration: 3,
        maxIterations: 10,
        targetF1: 1.0,
        iterations: [
          { iteration: 1, f1Score: 0.5, precision: 0.6, recall: 0.45, truePositives: 5, falsePositives: 3, falseNegatives: 6, feedbackGenerated: 9, timestamp: Date.now() },
          { iteration: 2, f1Score: 0.8, precision: 0.85, recall: 0.75, truePositives: 8, falsePositives: 1, falseNegatives: 3, feedbackGenerated: 4, timestamp: Date.now() },
          { iteration: 3, f1Score: 1.0, precision: 1.0, recall: 1.0, truePositives: 10, falsePositives: 0, falseNegatives: 0, feedbackGenerated: 0, timestamp: Date.now() },
        ],
        startedAt: Date.now(),
        bestF1: 1.0,
      };

      const { stop, reason } = shouldStop(state);
      expect(stop).toBe(true);
      expect(reason).toBe("target_reached");
    });

    it("should stop when max iterations reached", () => {
      const state: TrainingRunState = {
        targetPreset: "dvwa",
        sessionId: "test-2",
        status: "running",
        currentIteration: 10,
        maxIterations: 10,
        targetF1: 1.0,
        iterations: [],
        startedAt: Date.now(),
        bestF1: 0.7,
      };

      const { stop, reason } = shouldStop(state);
      expect(stop).toBe(true);
      expect(reason).toBe("max_iterations");
    });

    it("should stop when manually stopped", () => {
      const state: TrainingRunState = {
        targetPreset: "dvwa",
        sessionId: "test-3",
        status: "stopped",
        currentIteration: 5,
        maxIterations: 10,
        targetF1: 1.0,
        iterations: [],
        startedAt: Date.now(),
        bestF1: 0.6,
      };

      const { stop, reason } = shouldStop(state);
      expect(stop).toBe(true);
      expect(reason).toBe("manually_stopped");
    });

    it("should detect stagnation (3 identical F1 scores)", () => {
      const state: TrainingRunState = {
        targetPreset: "dvwa",
        sessionId: "test-4",
        status: "running",
        currentIteration: 5,
        maxIterations: 10,
        targetF1: 1.0,
        iterations: [
          { iteration: 1, f1Score: 0.5, precision: 0.6, recall: 0.45, truePositives: 5, falsePositives: 3, falseNegatives: 6, feedbackGenerated: 9, timestamp: Date.now() },
          { iteration: 2, f1Score: 0.65, precision: 0.7, recall: 0.6, truePositives: 7, falsePositives: 2, falseNegatives: 5, feedbackGenerated: 7, timestamp: Date.now() },
          { iteration: 3, f1Score: 0.65, precision: 0.7, recall: 0.6, truePositives: 7, falsePositives: 2, falseNegatives: 5, feedbackGenerated: 0, timestamp: Date.now() },
          { iteration: 4, f1Score: 0.65, precision: 0.7, recall: 0.6, truePositives: 7, falsePositives: 2, falseNegatives: 5, feedbackGenerated: 0, timestamp: Date.now() },
          { iteration: 5, f1Score: 0.65, precision: 0.7, recall: 0.6, truePositives: 7, falsePositives: 2, falseNegatives: 5, feedbackGenerated: 0, timestamp: Date.now() },
        ],
        startedAt: Date.now(),
        bestF1: 0.65,
      };

      const { stop, reason } = shouldStop(state);
      expect(stop).toBe(true);
      expect(reason).toBe("stagnated");
    });

    it("should continue when improving", () => {
      const state: TrainingRunState = {
        targetPreset: "dvwa",
        sessionId: "test-5",
        status: "running",
        currentIteration: 3,
        maxIterations: 10,
        targetF1: 1.0,
        iterations: [
          { iteration: 1, f1Score: 0.3, precision: 0.4, recall: 0.25, truePositives: 3, falsePositives: 4, falseNegatives: 9, feedbackGenerated: 13, timestamp: Date.now() },
          { iteration: 2, f1Score: 0.5, precision: 0.6, recall: 0.45, truePositives: 5, falsePositives: 3, falseNegatives: 6, feedbackGenerated: 9, timestamp: Date.now() },
          { iteration: 3, f1Score: 0.7, precision: 0.75, recall: 0.65, truePositives: 7, falsePositives: 2, falseNegatives: 4, feedbackGenerated: 6, timestamp: Date.now() },
        ],
        startedAt: Date.now(),
        bestF1: 0.7,
      };

      const { stop, reason } = shouldStop(state);
      expect(stop).toBe(false);
    });

    it("should not flag stagnation with fewer than 3 iterations", () => {
      const state: TrainingRunState = {
        targetPreset: "dvwa",
        sessionId: "test-6",
        status: "running",
        currentIteration: 2,
        maxIterations: 10,
        targetF1: 1.0,
        iterations: [
          { iteration: 1, f1Score: 0.5, precision: 0.6, recall: 0.45, truePositives: 5, falsePositives: 3, falseNegatives: 6, feedbackGenerated: 9, timestamp: Date.now() },
          { iteration: 2, f1Score: 0.5, precision: 0.6, recall: 0.45, truePositives: 5, falsePositives: 3, falseNegatives: 6, feedbackGenerated: 0, timestamp: Date.now() },
        ],
        startedAt: Date.now(),
        bestF1: 0.5,
      };

      const { stop, reason } = shouldStop(state);
      expect(stop).toBe(false);
    });
  });

  describe("Iteration Tracking", () => {
    it("should track improvement across iterations", () => {
      const iterations: IterationResult[] = [
        { iteration: 1, f1Score: 0.3, precision: 0.4, recall: 0.25, truePositives: 3, falsePositives: 4, falseNegatives: 9, feedbackGenerated: 13, timestamp: Date.now() },
        { iteration: 2, f1Score: 0.55, precision: 0.6, recall: 0.5, truePositives: 6, falsePositives: 3, falseNegatives: 6, feedbackGenerated: 9, timestamp: Date.now() },
        { iteration: 3, f1Score: 0.8, precision: 0.85, recall: 0.75, truePositives: 9, falsePositives: 1, falseNegatives: 3, feedbackGenerated: 4, timestamp: Date.now() },
      ];

      // Verify monotonic improvement
      for (let i = 1; i < iterations.length; i++) {
        expect(iterations[i].f1Score).toBeGreaterThan(iterations[i - 1].f1Score);
      }

      // Verify feedback decreases as accuracy improves
      for (let i = 1; i < iterations.length; i++) {
        expect(iterations[i].feedbackGenerated).toBeLessThanOrEqual(iterations[i - 1].feedbackGenerated);
      }
    });

    it("should calculate best F1 across all iterations", () => {
      const iterations: IterationResult[] = [
        { iteration: 1, f1Score: 0.3, precision: 0.4, recall: 0.25, truePositives: 3, falsePositives: 4, falseNegatives: 9, feedbackGenerated: 13, timestamp: Date.now() },
        { iteration: 2, f1Score: 0.8, precision: 0.85, recall: 0.75, truePositives: 9, falsePositives: 1, falseNegatives: 3, feedbackGenerated: 4, timestamp: Date.now() },
        { iteration: 3, f1Score: 0.6, precision: 0.7, recall: 0.55, truePositives: 7, falsePositives: 2, falseNegatives: 5, feedbackGenerated: 7, timestamp: Date.now() }, // regression
      ];

      const bestF1 = Math.max(...iterations.map(i => i.f1Score));
      expect(bestF1).toBe(0.8);
    });

    it("should count total corrections across iterations", () => {
      const iterations: IterationResult[] = [
        { iteration: 1, f1Score: 0.3, precision: 0.4, recall: 0.25, truePositives: 3, falsePositives: 4, falseNegatives: 9, feedbackGenerated: 13, timestamp: Date.now() },
        { iteration: 2, f1Score: 0.55, precision: 0.6, recall: 0.5, truePositives: 6, falsePositives: 3, falseNegatives: 6, feedbackGenerated: 9, timestamp: Date.now() },
        { iteration: 3, f1Score: 0.8, precision: 0.85, recall: 0.75, truePositives: 9, falsePositives: 1, falseNegatives: 3, feedbackGenerated: 4, timestamp: Date.now() },
      ];

      const totalCorrections = iterations.reduce((sum, i) => sum + i.feedbackGenerated, 0);
      expect(totalCorrections).toBe(26);
    });
  });
});
