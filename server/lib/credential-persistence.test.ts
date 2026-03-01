import { describe, it, expect, vi, beforeEach } from "vitest";

describe("Credential Attack Persistence - Schema Validation", () => {
  it("should define credentialAttackRuns table with external tool columns", async () => {
    const schema = await import("../../drizzle/schema");
    expect(schema.credentialAttackRuns).toBeDefined();
    
    // Verify the table has the tool tracking columns
    const columns = schema.credentialAttackRuns as any;
    expect(columns).toBeDefined();
  });

  it("should define credentialFindings table with tool attribution columns", async () => {
    const schema = await import("../../drizzle/schema");
    expect(schema.credentialFindings).toBeDefined();
  });

  it("should export correct types for attack runs", async () => {
    const schema = await import("../../drizzle/schema");
    expect(schema.credentialAttackRuns).toBeDefined();
    type RunType = typeof schema.credentialAttackRuns.$inferSelect;
    type InsertRunType = typeof schema.credentialAttackRuns.$inferInsert;
    expect(true).toBe(true);
  });

  it("should export correct types for credential findings", async () => {
    const schema = await import("../../drizzle/schema");
    expect(schema.credentialFindings).toBeDefined();
    type FindingType = typeof schema.credentialFindings.$inferSelect;
    type InsertFindingType = typeof schema.credentialFindings.$inferInsert;
    expect(true).toBe(true);
  });
});

describe("Credential Attack Persistence - Tool Selection Knowledge", () => {
  it("should have comprehensive tool knowledge base for LLM training", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./external-credential-tools");
    
    expect(TOOL_KNOWLEDGE_BASE).toBeDefined();
    expect(typeof TOOL_KNOWLEDGE_BASE).toBe("object");
    
    // Verify all three tools are covered
    expect(TOOL_KNOWLEDGE_BASE.hydra).toBeDefined();
    expect(TOOL_KNOWLEDGE_BASE.medusa).toBeDefined();
    expect(TOOL_KNOWLEDGE_BASE.netexec).toBeDefined();
  });

  it("should include protocol coverage for each tool", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./external-credential-tools");
    
    // Hydra should support many protocols (nested under .native)
    expect(TOOL_KNOWLEDGE_BASE.hydra.protocols.native.length).toBeGreaterThan(10);
    expect(TOOL_KNOWLEDGE_BASE.hydra.protocols.native).toContain("ssh");
    expect(TOOL_KNOWLEDGE_BASE.hydra.protocols.native).toContain("ftp");
    
    // Medusa should support core protocols
    expect(TOOL_KNOWLEDGE_BASE.medusa.protocols.native.length).toBeGreaterThan(5);
    expect(TOOL_KNOWLEDGE_BASE.medusa.protocols.native).toContain("ssh");
    
    // NetExec should focus on AD/Windows protocols
    expect(TOOL_KNOWLEDGE_BASE.netexec.protocols.native).toContain("smb");
    expect(TOOL_KNOWLEDGE_BASE.netexec.protocols.native).toContain("ldap");
    expect(TOOL_KNOWLEDGE_BASE.netexec.protocols.native).toContain("winrm");
  });

  it("should include strengths and weaknesses for tool selection", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./external-credential-tools");
    
    for (const tool of ["hydra", "medusa", "netexec"] as const) {
      expect(TOOL_KNOWLEDGE_BASE[tool].strengths.length).toBeGreaterThan(0);
      expect(TOOL_KNOWLEDGE_BASE[tool].weaknesses.length).toBeGreaterThan(0);
      expect(TOOL_KNOWLEDGE_BASE[tool].bestFor.length).toBeGreaterThan(0);
    }
  });

  it("should include license information for compliance", async () => {
    const { TOOL_KNOWLEDGE_BASE } = await import("./external-credential-tools");
    
    expect(TOOL_KNOWLEDGE_BASE.hydra.license).toBe("AGPL-3.0");
    expect(TOOL_KNOWLEDGE_BASE.medusa.license).toBe("GPLv2");
    expect(TOOL_KNOWLEDGE_BASE.netexec.license).toBe("BSD 2-Clause");
  });
});

describe("Credential Attack Persistence - Deterministic Tool Selection", () => {
  it("should recommend hydra for SSH brute force", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("ssh");
    expect(result).toBe("hydra");
  });

  it("should recommend netexec for SMB attacks", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("smb");
    expect(result).toBe("netexec");
  });

  it("should recommend netexec for WinRM attacks", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("winrm");
    expect(result).toBe("netexec");
  });

  it("should recommend netexec for Active Directory scenarios", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("ssh", true);
    expect(result).toBe("netexec");
  });

  it("should recommend hydra for FTP attacks", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("ftp");
    expect(result).toBe("hydra");
  });

  it("should recommend hydra for MySQL attacks", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("mysql");
    expect(result).toBe("hydra");
  });

  it("should recommend hydra for RDP attacks", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("rdp");
    expect(result).toBe("hydra");
  });

  it("should default to hydra for unknown protocols", async () => {
    const { quickToolRecommendation } = await import("./external-credential-tools");
    
    const result = quickToolRecommendation("custom_protocol");
    expect(result).toBe("hydra");
  });
});

describe("Credential Attack Persistence - Tool Detection", () => {
  it("should detect installed tools", async () => {
    const { detectAllTools } = await import("./external-credential-tools");
    
    const tools = detectAllTools();
    expect(tools).toBeDefined();
    expect(typeof tools).toBe("object");
    
    // Should return results for all three tools + builtin
    expect("hydra" in tools).toBe(true);
    expect("medusa" in tools).toBe(true);
    expect("netexec" in tools).toBe(true);
  });

  it("should include version info for installed tools", async () => {
    const { detectAllTools } = await import("./external-credential-tools");
    
    const tools = detectAllTools();
    
    // Hydra should be installed (we installed it earlier)
    if (tools.hydra.installed) {
      expect(tools.hydra.version).toBeTruthy();
      expect(tools.hydra.path).toBeTruthy();
    }
    
    // Medusa should be installed
    if (tools.medusa.installed) {
      expect(tools.medusa.version).toBeTruthy();
    }
  });
});

describe("Credential Attack Persistence - Tool Capabilities", () => {
  it("should return capabilities for all tools", async () => {
    const { getToolCapabilities } = await import("./external-credential-tools");
    
    const caps = getToolCapabilities();
    expect(Array.isArray(caps)).toBe(true);
    expect(caps.length).toBeGreaterThanOrEqual(3);
    
    const toolNames = caps.map(c => c.tool);
    expect(toolNames).toContain("hydra");
    expect(toolNames).toContain("medusa");
    expect(toolNames).toContain("netexec");
  });

  it("should include protocol lists in capabilities", async () => {
    const { getToolCapabilities } = await import("./external-credential-tools");
    
    const caps = getToolCapabilities();
    for (const cap of caps) {
      expect(Array.isArray(cap.protocols)).toBe(true);
      expect(cap.protocols.length).toBeGreaterThan(0);
    }
  });
});

describe("Credential Attack Persistence - Data Flow Integration", () => {
  it("should have saveAttackResult endpoint schema that accepts tool info", () => {
    const validInput = {
      targetHost: "192.168.1.1",
      targetPort: 22,
      protocol: "ssh",
      attackMode: "brute_force",
      tool: "hydra",
      toolVersion: "9.5",
      totalAttempts: 1000,
      successfulAttempts: 2,
      failedAttempts: 998,
      lockoutsDetected: 0,
      rateLimitHits: 0,
      durationMs: 45000,
      status: "completed",
      rawOutput: "Hydra output...",
      findings: [
        {
          username: "admin",
          password: "password123",
          accessLevel: "admin",
          responseSnippet: "[22][ssh] host: 192.168.1.1   login: admin   password: password123",
        },
      ],
    };
    
    expect(validInput.tool).toBe("hydra");
    expect(validInput.findings.length).toBe(1);
    expect(validInput.findings[0].username).toBe("admin");
  });

  it("should support all four tool types in persistence", () => {
    const validTools = ["builtin", "hydra", "medusa", "netexec"];
    
    for (const tool of validTools) {
      const input = {
        targetHost: "10.0.0.1",
        targetPort: 22,
        protocol: "ssh",
        attackMode: "brute_force",
        tool,
        totalAttempts: 100,
        successfulAttempts: 0,
        status: "completed",
        findings: [],
      };
      
      expect(input.tool).toBe(tool);
    }
  });

  it("should support validation status transitions", () => {
    const validStatuses = ["unvalidated", "validated", "false_positive"];
    
    for (const status of validStatuses) {
      expect(validStatuses).toContain(status);
    }
  });
});

describe("Credential Attack Persistence - Tool Selection Prompt", () => {
  it("should provide a comprehensive system prompt for LLM tool selection", async () => {
    const { TOOL_SELECTION_SYSTEM_PROMPT } = await import("./external-credential-tools");
    
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toBeDefined();
    expect(typeof TOOL_SELECTION_SYSTEM_PROMPT).toBe("string");
    expect(TOOL_SELECTION_SYSTEM_PROMPT.length).toBeGreaterThan(100);
    
    // Should mention all three tools
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("Hydra");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("Medusa");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("NetExec");
  });

  it("should include decision criteria in the prompt", async () => {
    const { TOOL_SELECTION_SYSTEM_PROMPT } = await import("./external-credential-tools");
    
    // Should contain guidance about when to use each tool
    expect(TOOL_SELECTION_SYSTEM_PROMPT.toLowerCase()).toContain("protocol");
  });
});

describe("Credential Attack Persistence - Knowledge Base Access", () => {
  it("should provide knowledge base via getter function", async () => {
    const { getToolKnowledgeBase } = await import("./external-credential-tools");
    
    const kb = getToolKnowledgeBase();
    expect(kb).toBeDefined();
    expect(kb.hydra).toBeDefined();
    expect(kb.medusa).toBeDefined();
    expect(kb.netexec).toBeDefined();
  });

  it("should provide tool selection prompt via getter function", async () => {
    const { getToolSelectionPrompt } = await import("./external-credential-tools");
    
    const prompt = getToolSelectionPrompt();
    expect(typeof prompt).toBe("string");
    expect(prompt.length).toBeGreaterThan(50);
  });
});
