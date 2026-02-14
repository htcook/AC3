import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the DB module to avoid database calls
vi.mock("./db", () => ({
  getTtpKnowledge: vi.fn().mockResolvedValue(null),
  upsertTtpKnowledge: vi.fn().mockResolvedValue(undefined),
  listAllAbilities: vi.fn().mockResolvedValue([]),
  getTtpKnowledgeStats: vi.fn().mockResolvedValue({ total: 0, byTactic: [], withDetections: 0 }),
  listTtpKnowledge: vi.fn().mockResolvedValue({ entries: [], total: 0 }),
}));

// Mock the LLM module - path relative to where the importing module (lib/ttp-engine.ts) resolves it
vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: JSON.stringify({
          description: "Test technique description",
          executionMethods: [{ method: "Test Method", tools: ["tool1"], commands: ["cmd1"], prerequisites: [], platforms: ["windows"] }],
          toolsUsed: [{ name: "TestTool", type: "offensive", description: "A test tool", commonActors: ["APT28"] }],
          iocPatterns: [{ type: "file_hash", pattern: "abc123", description: "Test IOC", confidence: "high", volatility: "low" }],
          artifacts: [{ category: "filesystem", description: "Test artifact", location: "C:\\test", persistence: "permanent" }],
          detectionRules: [{ format: "sigma", name: "Test Rule", rule: "title: Test", description: "Test detection", falsePositiveRate: "low" }],
          eventLogSources: [{ source: "Sysmon", eventId: "1", description: "Process creation" }],
          attackChainPosition: "execution",
          prerequisiteTechniques: ["T1059"],
          followUpTechniques: ["T1055"],
          defensiveGaps: [{ gap: "No EDR", impact: "High", recommendation: "Deploy EDR" }],
          redTeamValue: 8,
          blueTeamPriority: 7,
          purpleTeamNotes: "Test notes",
        }),
      },
    }],
  }),
}));

describe("TTP Knowledge Engine", () => {
  describe("Kali Tools Catalog", () => {
    it("should return the full Kali tools catalog", async () => {
      const { getKaliToolsCatalog } = await import("./lib/ttp-ingest");
      const tools = getKaliToolsCatalog();
      expect(tools).toBeDefined();
      expect(Array.isArray(tools)).toBe(true);
      expect(tools.length).toBeGreaterThan(50); // We have 60+ tools
    });

    it("should have required fields for each tool", async () => {
      const { getKaliToolsCatalog } = await import("./lib/ttp-ingest");
      const tools = getKaliToolsCatalog();
      for (const tool of tools) {
        expect(tool).toHaveProperty("name");
        expect(tool).toHaveProperty("category");
        expect(tool).toHaveProperty("description");
        expect(tool).toHaveProperty("techniques");
        expect(Array.isArray(tool.techniques)).toBe(true);
      }
    });

    it("should filter tools by technique ID", async () => {
      const { getKaliToolsForTechnique } = await import("./lib/ttp-ingest");
      const tools = getKaliToolsForTechnique("T1046");
      expect(tools.length).toBeGreaterThan(0);
      expect(tools.every((t) => t.techniques.includes("T1046"))).toBe(true);
      // nmap should be in the results
      expect(tools.some((t) => t.name === "nmap")).toBe(true);
    });

    it("should return empty for non-existent technique", async () => {
      const { getKaliToolsForTechnique } = await import("./lib/ttp-ingest");
      const tools = getKaliToolsForTechnique("T9999.999");
      expect(tools).toEqual([]);
    });

    it("should have tools in expected categories", async () => {
      const { getKaliToolsCatalog } = await import("./lib/ttp-ingest");
      const tools = getKaliToolsCatalog();
      const categories = new Set(tools.map((t) => t.category));
      expect(categories.has("Information Gathering")).toBe(true);
      expect(categories.has("Exploitation Tools")).toBe(true);
      expect(categories.has("Password Attacks")).toBe(true);
      expect(categories.has("Post Exploitation")).toBe(true);
      expect(categories.has("Web Application Analysis")).toBe(true);
    });
  });

  describe("TTP Engine Research", () => {
    it("should generate structured TTP knowledge from LLM", { timeout: 15000 }, async () => {
      const { researchTechnique } = await import("./lib/ttp-engine");
      const result = await researchTechnique("T1059.001", "PowerShell", "execution");
      
      expect(result).toBeDefined();
      expect(result.techniqueId).toBe("T1059.001");
      expect(result.techniqueName).toBe("PowerShell");
      expect(result.tactic).toBe("execution");
      expect(result.description).toBeTruthy();
      expect(Array.isArray(result.executionMethods)).toBe(true);
      expect(Array.isArray(result.toolsUsed)).toBe(true);
      expect(Array.isArray(result.iocPatterns)).toBe(true);
      expect(Array.isArray(result.detectionRules)).toBe(true);
      expect(result.dataSource).toBe("llm-enriched");
      expect(result.confidence).toBe(75);
    });

    it("should handle malformed LLM response gracefully", { timeout: 15000 }, async () => {
      const { invokeLLM } = await import("./_core/llm");
      (invokeLLM as any).mockResolvedValueOnce({
        choices: [{ message: { content: "not valid json" } }],
      });

      const { researchTechnique } = await import("./lib/ttp-engine");
      const result = await researchTechnique("T1059", "Command and Scripting Interpreter", "execution");
      
      expect(result).toBeDefined();
      expect(result.techniqueId).toBe("T1059");
      expect(result.dataSource).toBe("llm-enriched");
      // Should have defaults when parsing fails
      expect(result.executionMethods).toEqual([]);;
    });
  });

  describe("Campaign Design Prompt", () => {
    it("should generate a campaign design prompt with TTP context", async () => {
      const { generateCampaignDesignPrompt } = await import("./lib/ttp-engine");
      const prompt = await generateCampaignDesignPrompt({
        targetSector: "Financial Services",
        targetTechnologies: ["Windows Server", "Active Directory", "Exchange"],
        threatActors: [{
          name: "APT28",
          techniques: [
            { id: "T1059.001", name: "PowerShell", tactic: "execution" },
            { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
          ],
        }],
        riskScore: 85,
      });

      expect(prompt).toBeDefined();
      expect(typeof prompt).toBe("string");
      expect(prompt).toContain("Financial Services");
      expect(prompt).toContain("APT28");
      expect(prompt).toContain("CAMPAIGN DESIGN PRINCIPLES");
    });
  });

  describe("Detection Rules Generation", () => {
    it("should return empty rules for unknown techniques", async () => {
      const { generateDetectionRules } = await import("./lib/ttp-engine");
      const rules = await generateDetectionRules(["T9999.999"]);
      expect(rules).toBeDefined();
      expect(rules.sigma).toEqual([]);
      expect(rules.splunk).toEqual([]);
      expect(rules.kql).toEqual([]);
      expect(rules.suricata).toEqual([]);
    });
  });
});

describe("IOC Sync Service", () => {
  it("should have the sync module available", async () => {
    const mod = await import("./lib/ioc-sync");
    expect(mod).toBeDefined();
    expect(typeof mod.runIocSync).toBe("function");
  });
});

describe("Threat Actor Matcher", () => {
  it("should have the matcher module available", async () => {
    const mod = await import("./lib/threat-actor-matcher");
    expect(mod).toBeDefined();
    expect(typeof mod.matchThreatActors).toBe("function");
  });
});

describe("Caldera Sync Service", () => {
  it("should have the sync module available", async () => {
    const mod = await import("./lib/caldera-sync");
    expect(mod).toBeDefined();
    expect(typeof mod.syncCalderaAdversaries).toBe("function");
  });
});
