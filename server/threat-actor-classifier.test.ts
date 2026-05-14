import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock invokeLLM
vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn(),
}));

import { invokeLLM } from "./_core/llm";
import {
  classifyActor,
  classifyBatch,
  getProgress,
  resetProgress,
  cancelBatch,
  validateClassification,
  type ClassificationInput,
  type ClassificationResult,
} from "./lib/threat-actor-classifier";

const mockLLMResponse = (type: string, confidence: number, reasoning: string) => ({
  choices: [{
    message: {
      content: JSON.stringify({
        classifiedType: type,
        confidence,
        reasoning,
        secondaryType: "none",
        secondaryConfidence: 0,
        indicators: ["indicator1", "indicator2", "indicator3"],
      }),
    },
  }],
});

const sampleActor: ClassificationInput = {
  actorId: "actor-001",
  name: "Fancy Bear",
  description: "Russian state-sponsored cyber espionage group targeting government and military organizations",
  aliases: ["APT28", "Sofacy", "Pawn Storm", "Sednit"],
  origin: "Russia",
  motivation: "espionage",
  targetSectors: ["government", "military", "defense", "aerospace"],
  targetRegions: ["NATO", "Europe", "United States"],
  techniques: ["T1566", "T1078", "T1059", "T1071", "T1027"],
  tools: ["X-Agent", "X-Tunnel", "Komplex", "Zebrocy"],
  malware: ["Sednit", "Sofacy", "X-Agent"],
  firstSeen: "2004",
  lastActive: "2024",
  sophistication: "high",
};

const unknownActor: ClassificationInput = {
  actorId: "actor-002",
  name: "DarkSide",
  description: "Ransomware-as-a-Service operation targeting large enterprises with double extortion",
  aliases: ["DarkSide RaaS"],
  origin: "Russia",
  motivation: "financial",
  targetSectors: ["energy", "manufacturing", "healthcare"],
  targetRegions: ["United States", "Europe"],
  techniques: ["T1486", "T1490", "T1489"],
  tools: ["DarkSide Ransomware", "Cobalt Strike"],
  malware: ["DarkSide"],
  firstSeen: "2020",
  lastActive: "2021",
  sophistication: "medium",
};

describe("Threat Actor Classifier", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetProgress();
  });

  describe("classifyActor", () => {
    it("should classify an APT actor correctly", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("apt", 95, "State-sponsored espionage group with government targets and custom tooling"));

      const result = await classifyActor(sampleActor);

      expect(result.actorId).toBe("actor-001");
      expect(result.name).toBe("Fancy Bear");
      expect(result.classifiedType).toBe("apt");
      expect(result.confidence).toBe(95);
      expect(result.reasoning).toContain("State-sponsored");
      expect(result.indicators).toHaveLength(3);
    });

    it("should classify a ransomware actor correctly", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("ransomware", 92, "RaaS operation with double extortion targeting enterprises"));

      const result = await classifyActor(unknownActor);

      expect(result.classifiedType).toBe("ransomware");
      expect(result.confidence).toBe(92);
    });

    it("should handle LLM errors gracefully", async () => {
      (invokeLLM as any).mockRejectedValue(new Error("LLM timeout"));

      await expect(classifyActor(sampleActor)).rejects.toThrow("LLM timeout");
    });

    it("should handle empty LLM response", async () => {
      (invokeLLM as any).mockResolvedValue({ choices: [{ message: { content: null } }] });

      await expect(classifyActor(sampleActor)).rejects.toThrow("No response from LLM");
    });

    it("should clamp confidence to 0-100 range", async () => {
      (invokeLLM as any).mockResolvedValue({
        choices: [{
          message: {
            content: JSON.stringify({
              classifiedType: "apt",
              confidence: 150,
              reasoning: "test",
              secondaryType: "none",
              secondaryConfidence: 0,
              indicators: ["a"],
            }),
          },
        }],
      });

      const result = await classifyActor(sampleActor);
      expect(result.confidence).toBe(100);
    });

    it("should pass actor profile data to LLM prompt", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("apt", 90, "test"));

      await classifyActor(sampleActor);

      expect(invokeLLM).toHaveBeenCalledTimes(1);
      const call = (invokeLLM as any).mock.calls[0][0];
      expect(call.messages[1].content).toContain("Fancy Bear");
      expect(call.messages[1].content).toContain("Russia");
      expect(call.messages[1].content).toContain("government");
      expect(call.messages[1].content).toContain("X-Agent");
    });

    it("should include response_format for structured output", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("apt", 90, "test"));

      await classifyActor(sampleActor);

      const call = (invokeLLM as any).mock.calls[0][0];
      expect(call.response_format).toBeDefined();
      expect(call.response_format.type).toBe("json_schema");
      expect(call.response_format.json_schema.name).toBe("threat_actor_classification");
    });
  });

  describe("classifyBatch", () => {
    it("should process a batch of actors", async () => {
      (invokeLLM as any)
        .mockResolvedValueOnce(mockLLMResponse("apt", 95, "APT group"))
        .mockResolvedValueOnce(mockLLMResponse("ransomware", 92, "Ransomware group"));

      const result = await classifyBatch([sampleActor, unknownActor], { batchSize: 2, delayMs: 0 });

      expect(result.total).toBe(2);
      expect(result.processed).toBe(2);
      expect(result.succeeded).toBe(2);
      expect(result.failed).toBe(0);
      expect(result.status).toBe("completed");
      expect(result.results).toHaveLength(2);
    });

    it("should handle partial failures in batch", async () => {
      (invokeLLM as any)
        .mockResolvedValueOnce(mockLLMResponse("apt", 95, "APT group"))
        .mockRejectedValueOnce(new Error("Rate limited"));

      const result = await classifyBatch([sampleActor, unknownActor], { batchSize: 2, delayMs: 0 });

      expect(result.succeeded).toBe(1);
      expect(result.failed).toBe(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toBe("Rate limited");
    });

    it("should call onResult for high-confidence classifications", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("apt", 90, "test"));
      const onResult = vi.fn();

      await classifyBatch([sampleActor], { batchSize: 1, delayMs: 0, autoApplyThreshold: 75, onResult });

      expect(onResult).toHaveBeenCalledTimes(1);
      expect(onResult).toHaveBeenCalledWith(expect.objectContaining({ classifiedType: "apt", confidence: 90 }));
    });

    it("should NOT call onResult for low-confidence classifications", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("apt", 60, "uncertain"));
      const onResult = vi.fn();

      await classifyBatch([sampleActor], { batchSize: 1, delayMs: 0, autoApplyThreshold: 75, onResult });

      expect(onResult).not.toHaveBeenCalled();
    });

    it("should respect cancellation", async () => {
      (invokeLLM as any).mockImplementation(() => new Promise(resolve => setTimeout(() => resolve(mockLLMResponse("apt", 90, "test")), 100)));

      const batchPromise = classifyBatch(
        [sampleActor, unknownActor, sampleActor, unknownActor],
        { batchSize: 1, delayMs: 50 }
      );

      // Cancel after a short delay
      setTimeout(() => cancelBatch(), 50);

      const result = await batchPromise;
      expect(result.status).toBe("cancelled");
      expect(result.processed).toBeLessThan(4);
    });
  });

  describe("getProgress / resetProgress", () => {
    it("should return idle status initially", () => {
      const progress = getProgress();
      expect(progress.status).toBe("idle");
      expect(progress.total).toBe(0);
    });

    it("should track progress during batch", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("apt", 90, "test"));

      await classifyBatch([sampleActor], { batchSize: 1, delayMs: 0 });

      const progress = getProgress();
      expect(progress.status).toBe("completed");
      expect(progress.total).toBe(1);
      expect(progress.processed).toBe(1);
    });

    it("should reset progress correctly", async () => {
      (invokeLLM as any).mockResolvedValue(mockLLMResponse("apt", 90, "test"));
      await classifyBatch([sampleActor], { batchSize: 1, delayMs: 0 });

      resetProgress();

      const progress = getProgress();
      expect(progress.status).toBe("idle");
      expect(progress.total).toBe(0);
      expect(progress.results).toHaveLength(0);
    });
  });

  describe("validateClassification", () => {
    const validResult: ClassificationResult = {
      actorId: "actor-001",
      name: "Test Actor",
      previousType: "unknown",
      classifiedType: "apt",
      confidence: 90,
      reasoning: "This is a state-sponsored group with espionage motivation",
      secondaryType: null,
      secondaryConfidence: 0,
      indicators: ["government targets", "custom tooling", "long-term campaigns"],
    };

    it("should validate a correct classification", () => {
      const { valid, issues } = validateClassification(validResult);
      expect(valid).toBe(true);
      expect(issues).toHaveLength(0);
    });

    it("should catch invalid classification type", () => {
      const { valid, issues } = validateClassification({ ...validResult, classifiedType: "invalid" as any });
      expect(valid).toBe(false);
      expect(issues[0]).toContain("Invalid classification type");
    });

    it("should catch out-of-range confidence", () => {
      const { valid, issues } = validateClassification({ ...validResult, confidence: 150 });
      expect(valid).toBe(false);
      expect(issues[0]).toContain("Confidence out of range");
    });

    it("should catch missing reasoning", () => {
      const { valid, issues } = validateClassification({ ...validResult, reasoning: "" });
      expect(valid).toBe(false);
      expect(issues[0]).toContain("Reasoning is too short");
    });

    it("should catch matching primary and secondary types", () => {
      const { valid, issues } = validateClassification({ ...validResult, secondaryType: "apt" });
      expect(valid).toBe(false);
      expect(issues[0]).toContain("Secondary type should not match");
    });

    it("should catch empty indicators", () => {
      const { valid, issues } = validateClassification({ ...validResult, indicators: [] });
      expect(valid).toBe(false);
      expect(issues[0]).toContain("No indicators");
    });
  });
});
