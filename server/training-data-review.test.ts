/**
 * Training Data Quality Review & JSONL Export — Unit Tests
 * ═══════════════════════════════════════════════════════════════════════════
 */
import { describe, it, expect } from "vitest";
import path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ─── JSONL Export Format Tests ──────────────────────────────────────────────

function toOpenAIChatFormat(messages: any[]) {
  return {
    messages: messages.map((m: any) => ({
      role: m.role,
      content: m.content,
    })),
  };
}

function toAnthropicFormat(messages: any[]) {
  const system = messages.find((m: any) => m.role === "system")?.content || "";
  const turns = messages
    .filter((m: any) => m.role !== "system")
    .map((m: any) => ({
      role: m.role === "assistant" ? "assistant" : "user",
      content: m.content,
    }));
  return { system, messages: turns };
}

function toRawFormat(messages: any[], model: string, metadata: any) {
  return { model, messages, metadata };
}

const sampleMessages = [
  { role: "system", content: "You are a penetration testing specialist." },
  { role: "user", content: "Analyze the target for SQL injection vulnerabilities." },
  { role: "assistant", content: "I'll start by testing parameter injection on the login form using UNION-based SQLi..." },
];

describe("JSONL Export Format — OpenAI Chat", () => {
  it("should produce valid OpenAI chat format with all message roles", () => {
    const result = toOpenAIChatFormat(sampleMessages);
    expect(result).toHaveProperty("messages");
    expect(result.messages).toHaveLength(3);
    expect(result.messages[0].role).toBe("system");
    expect(result.messages[1].role).toBe("user");
    expect(result.messages[2].role).toBe("assistant");
  });

  it("should preserve message content exactly", () => {
    const result = toOpenAIChatFormat(sampleMessages);
    expect(result.messages[0].content).toBe("You are a penetration testing specialist.");
    expect(result.messages[2].content).toContain("UNION-based SQLi");
  });

  it("should produce valid JSONL line (parseable JSON)", () => {
    const result = toOpenAIChatFormat(sampleMessages);
    const jsonLine = JSON.stringify(result);
    expect(() => JSON.parse(jsonLine)).not.toThrow();
    const parsed = JSON.parse(jsonLine);
    expect(parsed.messages).toHaveLength(3);
  });

  it("should handle empty messages array", () => {
    const result = toOpenAIChatFormat([]);
    expect(result.messages).toHaveLength(0);
  });

  it("should handle single message", () => {
    const result = toOpenAIChatFormat([{ role: "user", content: "test" }]);
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0].role).toBe("user");
  });
});

describe("JSONL Export Format — Anthropic", () => {
  it("should extract system message into separate field", () => {
    const result = toAnthropicFormat(sampleMessages);
    expect(result.system).toBe("You are a penetration testing specialist.");
    expect(result.messages.every((m: any) => m.role !== "system")).toBe(true);
  });

  it("should only include user and assistant turns in messages", () => {
    const result = toAnthropicFormat(sampleMessages);
    expect(result.messages).toHaveLength(2);
    expect(result.messages[0].role).toBe("user");
    expect(result.messages[1].role).toBe("assistant");
  });

  it("should handle messages without system prompt", () => {
    const noSystem = sampleMessages.filter((m) => m.role !== "system");
    const result = toAnthropicFormat(noSystem);
    expect(result.system).toBe("");
    expect(result.messages).toHaveLength(2);
  });

  it("should produce valid JSONL line", () => {
    const result = toAnthropicFormat(sampleMessages);
    const jsonLine = JSON.stringify(result);
    const parsed = JSON.parse(jsonLine);
    expect(parsed).toHaveProperty("system");
    expect(parsed).toHaveProperty("messages");
  });
});

describe("JSONL Export Format — Raw", () => {
  it("should include model, messages, and metadata", () => {
    const metadata = { technique: "T1190", severity: "critical" };
    const result = toRawFormat(sampleMessages, "recon-specialist-v2", metadata);
    expect(result.model).toBe("recon-specialist-v2");
    expect(result.messages).toHaveLength(3);
    expect(result.metadata.technique).toBe("T1190");
  });

  it("should handle empty metadata", () => {
    const result = toRawFormat(sampleMessages, "exploit-specialist-v2", {});
    expect(result.metadata).toEqual({});
  });
});

// ─── Review Workflow Logic Tests ────────────────────────────────────────────

describe("Review Status Transitions", () => {
  const statusMap: Record<string, string> = {
    approve: "approved",
    reject: "rejected",
    flag: "flagged",
    reset: "pending_review",
  };

  it("should map approve action to approved status", () => {
    expect(statusMap["approve"]).toBe("approved");
  });

  it("should map reject action to rejected status", () => {
    expect(statusMap["reject"]).toBe("rejected");
  });

  it("should map flag action to flagged status", () => {
    expect(statusMap["flag"]).toBe("flagged");
  });

  it("should map reset action to pending_review status", () => {
    expect(statusMap["reset"]).toBe("pending_review");
  });

  it("should cover all four valid actions", () => {
    expect(Object.keys(statusMap)).toEqual(["approve", "reject", "flag", "reset"]);
  });
});

describe("Auto-Approve Threshold Logic", () => {
  const examples = [
    { id: "1", quality: "high", qualityScore: 0.95, reviewStatus: "pending_review" },
    { id: "2", quality: "high", qualityScore: 0.88, reviewStatus: "pending_review" },
    { id: "3", quality: "medium", qualityScore: 0.72, reviewStatus: "pending_review" },
    { id: "4", quality: "low", qualityScore: 0.45, reviewStatus: "pending_review" },
    { id: "5", quality: "high", qualityScore: 0.92, reviewStatus: "approved" },
  ];

  it("should filter by minimum quality score threshold", () => {
    const threshold = 0.85;
    const eligible = examples.filter(
      (e) => e.reviewStatus === "pending_review" && e.qualityScore >= threshold
    );
    expect(eligible).toHaveLength(2);
    expect(eligible.map((e) => e.id)).toEqual(["1", "2"]);
  });

  it("should only auto-approve pending_review examples", () => {
    const threshold = 0.85;
    const eligible = examples.filter(
      (e) => e.reviewStatus === "pending_review" && e.qualityScore >= threshold
    );
    expect(eligible.every((e) => e.reviewStatus === "pending_review")).toBe(true);
  });

  it("should not auto-approve already approved examples", () => {
    const threshold = 0.85;
    const eligible = examples.filter(
      (e) => e.reviewStatus === "pending_review" && e.qualityScore >= threshold
    );
    expect(eligible.find((e) => e.id === "5")).toBeUndefined();
  });

  it("should filter by quality level when specified", () => {
    const threshold = 0.5;
    const eligible = examples.filter(
      (e) =>
        e.reviewStatus === "pending_review" &&
        e.qualityScore >= threshold &&
        e.quality === "high"
    );
    expect(eligible).toHaveLength(2);
  });

  it("should return empty when threshold is too high", () => {
    const threshold = 0.99;
    const eligible = examples.filter(
      (e) => e.reviewStatus === "pending_review" && e.qualityScore >= threshold
    );
    expect(eligible).toHaveLength(0);
  });
});

// ─── Bulk Review Logic Tests ────────────────────────────────────────────────

describe("Bulk Review Chunking", () => {
  it("should chunk large arrays into groups of 50", () => {
    const ids = Array.from({ length: 123 }, (_, i) => `id-${i}`);
    const chunkSize = 50;
    const chunks: string[][] = [];
    for (let i = 0; i < ids.length; i += chunkSize) {
      chunks.push(ids.slice(i, i + chunkSize));
    }
    expect(chunks).toHaveLength(3);
    expect(chunks[0]).toHaveLength(50);
    expect(chunks[1]).toHaveLength(50);
    expect(chunks[2]).toHaveLength(23);
  });

  it("should handle exactly 50 items as single chunk", () => {
    const ids = Array.from({ length: 50 }, (_, i) => `id-${i}`);
    const chunkSize = 50;
    const chunks: string[][] = [];
    for (let i = 0; i < ids.length; i += chunkSize) {
      chunks.push(ids.slice(i, i + chunkSize));
    }
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(50);
  });

  it("should handle single item", () => {
    const ids = ["id-0"];
    const chunkSize = 50;
    const chunks: string[][] = [];
    for (let i = 0; i < ids.length; i += chunkSize) {
      chunks.push(ids.slice(i, i + chunkSize));
    }
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(1);
  });
});

// ─── Export Preview Stats Tests ─────────────────────────────────────────────

describe("Export Preview Statistics", () => {
  const mockRows = [
    { quality: "high", qualityScore: 0.95, model: "recon-specialist-v2" },
    { quality: "high", qualityScore: 0.88, model: "recon-specialist-v2" },
    { quality: "medium", qualityScore: 0.72, model: "exploit-specialist-v2" },
    { quality: "low", qualityScore: 0.45, model: "exploit-specialist-v2" },
    { quality: "high", qualityScore: 0.92, model: "c2-specialist-v2" },
  ];

  it("should compute quality breakdown correctly", () => {
    const breakdown = {
      high: mockRows.filter((r) => r.quality === "high").length,
      medium: mockRows.filter((r) => r.quality === "medium").length,
      low: mockRows.filter((r) => r.quality === "low").length,
    };
    expect(breakdown).toEqual({ high: 3, medium: 1, low: 1 });
  });

  it("should compute model distribution correctly", () => {
    const dist = Object.entries(
      mockRows.reduce(
        (acc, r) => {
          acc[r.model] = (acc[r.model] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>
      )
    ).map(([model, count]) => ({ model, count }));
    expect(dist).toContainEqual({ model: "recon-specialist-v2", count: 2 });
    expect(dist).toContainEqual({ model: "exploit-specialist-v2", count: 2 });
    expect(dist).toContainEqual({ model: "c2-specialist-v2", count: 1 });
  });

  it("should compute average quality score", () => {
    const avg =
      mockRows.reduce((sum, r) => sum + r.qualityScore, 0) / mockRows.length;
    expect(avg).toBeCloseTo(0.784, 2);
  });
});

// ─── Sidebar Navigation — Data Review & Export ──────────────────────────────

describe("Sidebar Navigation — Data Review & Export", () => {
  it("should have the training-data-review path in the LLM & AI Management group", async () => {
    // Read the sidebar-nav.ts and check for the path
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    expect(content).toContain("/training-data-review");
    expect(content).toContain("Data Review & Export");
  });

  it("should have the route registered in App.tsx", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/App.tsx"),
      "utf-8"
    );
    expect(content).toContain("training-data-review");
    expect(content).toContain("TrainingDataReview");
  });
});
