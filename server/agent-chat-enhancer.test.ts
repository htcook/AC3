import { describe, it, expect } from "vitest";
import {
  buildReasoningChainPrompt,
  detectAgentDelegation,
  buildDelegationContext,
  buildConfidenceScoringPrompt,
  buildMissionGuardrails,
  getDeliverableTemplates,
  enhanceChatPrompt,
} from "./lib/agent-chat-enhancer";
import {
  ALL_OFFENSIVE_AGENTS,
  matchCallerToAgent,
  buildAgentSystemPrompt,
  getAgentByCategory,
  getAgentByCallerPrefix,
  OSINT_ANALYST_AGENT,
  PENTESTER_AGENT,
  SOCIAL_ENGINEER_AGENT,
  RED_TEAM_OPERATOR_AGENT,
  REPORT_WRITER_AGENT,
} from "./lib/agent-definitions";

// ─── Agent Definitions Tests ────────────────────────────────────────────────

describe("Agent Definitions", () => {
  it("should export exactly 10 offensive agents", () => {
    expect(ALL_OFFENSIVE_AGENTS).toHaveLength(10);
  });

  it("each agent should have required fields", () => {
    for (const agent of ALL_OFFENSIVE_AGENTS) {
      expect(agent.agentId).toBeDefined();
      expect(agent.name).toBeDefined();
      expect(agent.category).toBeDefined();
      expect(agent.persona).toBeDefined();
      expect(agent.mission).toBeDefined();
      expect(agent.coreRules).toBeDefined();
      expect(agent.status).toBe("active");
    }
  });

  it("each agent should have a unique agentId", () => {
    const ids = ALL_OFFENSIVE_AGENTS.map(a => a.agentId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("each agent should have a unique category", () => {
    const cats = ALL_OFFENSIVE_AGENTS.map(a => a.category);
    expect(new Set(cats).size).toBe(cats.length);
  });

  it("each agent should have parseable JSON fields", () => {
    for (const agent of ALL_OFFENSIVE_AGENTS) {
      const rules = JSON.parse(agent.coreRules as string);
      expect(Array.isArray(rules)).toBe(true);
      expect(rules.length).toBeGreaterThan(0);

      if (agent.workflowSteps) {
        const steps = JSON.parse(agent.workflowSteps as string);
        expect(Array.isArray(steps)).toBe(true);
        expect(steps.length).toBeGreaterThan(0);
      }

      if (agent.toolAccess) {
        const tools = JSON.parse(agent.toolAccess as string);
        expect(Array.isArray(tools)).toBe(true);
      }

      if (agent.mitreTactics) {
        const mitre = JSON.parse(agent.mitreTactics as string);
        expect(Array.isArray(mitre)).toBe(true);
      }
    }
  });

  it("getAgentByCategory should find OSINT analyst", () => {
    const agent = getAgentByCategory("osint_analyst");
    expect(agent).toBeDefined();
    expect(agent!.agentId).toBe("offensive-osint-analyst-v1");
  });

  it("getAgentByCallerPrefix should find pentester", () => {
    const agent = getAgentByCallerPrefix("specialist:pentester");
    expect(agent).toBeDefined();
    expect(agent!.agentId).toBe("offensive-pentester-v1");
  });

  it("matchCallerToAgent should match by prefix", () => {
    const agent = matchCallerToAgent("specialist:osint-analyst:domain-enum");
    expect(agent).toBeDefined();
    expect(agent!.category).toBe("osint_analyst");
  });

  it("matchCallerToAgent should fuzzy match by keyword", () => {
    const osint = matchCallerToAgent("some-recon-task");
    expect(osint).toBeDefined();
    expect(osint!.category).toBe("osint_analyst");

    const pentest = matchCallerToAgent("vuln-scanner-check");
    expect(pentest).toBeDefined();
    expect(pentest!.category).toBe("pentester");

    const social = matchCallerToAgent("phishing-campaign-setup");
    expect(social).toBeDefined();
    expect(social!.category).toBe("social_engineer");

    const redTeam = matchCallerToAgent("caldera-campaign-runner");
    expect(redTeam).toBeDefined();
    expect(redTeam!.category).toBe("red_team_operator");

    const report = matchCallerToAgent("finding-report-generator");
    expect(report).toBeDefined();
    expect(report!.category).toBe("report_writer");
  });

  it("matchCallerToAgent should return undefined for unknown caller", () => {
    const result = matchCallerToAgent("completely-unrelated-task");
    expect(result).toBeUndefined();
  });

  it("buildAgentSystemPrompt should produce a non-empty prompt", () => {
    const prompt = buildAgentSystemPrompt(OSINT_ANALYST_AGENT);
    expect(prompt.length).toBeGreaterThan(100);
    expect(prompt).toContain("Mission");
    expect(prompt).toContain("Core Rules");
    expect(prompt).toContain("Workflow");
  });

  it("buildAgentSystemPrompt should include additional context", () => {
    const prompt = buildAgentSystemPrompt(PENTESTER_AGENT, "Target: example.com");
    expect(prompt).toContain("Additional Context");
    expect(prompt).toContain("Target: example.com");
  });
});

// ─── Agent Chat Enhancer Tests ──────────────────────────────────────────────

describe("Agent Chat Enhancer", () => {
  describe("buildReasoningChainPrompt", () => {
    it("should return operator reasoning chain by default", () => {
      const prompt = buildReasoningChainPrompt("operator");
      expect(prompt).toContain("ASSESS");
      expect(prompt).toContain("PLAN");
      expect(prompt).toContain("EXECUTE");
      expect(prompt).toContain("VERIFY");
    });

    it("should return analyst reasoning chain", () => {
      const prompt = buildReasoningChainPrompt("analyst");
      expect(prompt).toContain("OBSERVE");
      expect(prompt).toContain("HYPOTHESIZE");
      expect(prompt).toContain("INVESTIGATE");
      expect(prompt).toContain("CONCLUDE");
    });

    it("should return executive reasoning chain", () => {
      const prompt = buildReasoningChainPrompt("executive");
      expect(prompt).toContain("CONTEXT");
      expect(prompt).toContain("ANALYZE");
      expect(prompt).toContain("RECOMMEND");
      expect(prompt).toContain("QUANTIFY");
    });

    it("should return SOC reasoning chain", () => {
      const prompt = buildReasoningChainPrompt("soc");
      expect(prompt).toContain("TRIAGE");
      expect(prompt).toContain("RESPOND");
      expect(prompt).toContain("DOCUMENT");
    });

    it("should fall back to operator for unknown role", () => {
      const prompt = buildReasoningChainPrompt("unknown_role");
      expect(prompt).toContain("ASSESS");
    });
  });

  describe("detectAgentDelegation", () => {
    it("should detect OSINT delegation for recon keywords", () => {
      const agent = detectAgentDelegation("Run OSINT reconnaissance on target.com", "operator");
      expect(agent).not.toBeNull();
      expect(agent!.agentId).toBe("offensive-osint-analyst-v1");
    });

    it("should detect social engineering delegation", () => {
      const agent = detectAgentDelegation("Create a phishing campaign for the engagement", "operator");
      expect(agent).not.toBeNull();
      expect(agent!.agentId).toBe("offensive-social-engineer-v1");
    });

    it("should detect red team delegation", () => {
      const agent = detectAgentDelegation("Set up a caldera campaign for adversary emulation", "operator");
      expect(agent).not.toBeNull();
      expect(agent!.agentId).toBe("offensive-red-team-operator-v1");
    });

    it("should detect pentester delegation", () => {
      const agent = detectAgentDelegation("Test for SQL injection vulnerability on the login form", "operator");
      expect(agent).not.toBeNull();
      expect(agent!.agentId).toBe("offensive-pentester-v1");
    });

    it("should detect report writer delegation", () => {
      const agent = detectAgentDelegation("Write a pentest report with executive summary", "operator");
      expect(agent).not.toBeNull();
      expect(agent!.agentId).toBe("offensive-report-writer-v1");
    });

    it("should return null for non-matching messages", () => {
      const agent = detectAgentDelegation("What is the weather today?", "operator");
      expect(agent).toBeNull();
    });
  });

  describe("buildDelegationContext", () => {
    it("should build delegation context with agent details", () => {
      const context = buildDelegationContext(OSINT_ANALYST_AGENT, "Run OSINT on target.com");
      expect(context).toContain("SPECIALIST AGENT DELEGATION");
      expect(context).toContain(OSINT_ANALYST_AGENT.name);
      expect(context).toContain("METHODOLOGY RULES");
      expect(context).toContain("AVAILABLE TOOLS");
      expect(context).toContain("MITRE ATT&CK COVERAGE");
    });
  });

  describe("buildConfidenceScoringPrompt", () => {
    it("should include confidence levels", () => {
      const prompt = buildConfidenceScoringPrompt();
      expect(prompt).toContain("HIGH");
      expect(prompt).toContain("MEDIUM");
      expect(prompt).toContain("LOW");
      expect(prompt).toContain("Confidence");
    });
  });

  describe("buildMissionGuardrails", () => {
    it("should return operator guardrails", () => {
      const guardrails = buildMissionGuardrails("operator");
      expect(guardrails).toContain("MISSION BOUNDARY ENFORCEMENT");
      expect(guardrails).toContain("SCOPE CHECK");
    });

    it("should return analyst guardrails", () => {
      const guardrails = buildMissionGuardrails("analyst");
      expect(guardrails).toContain("CLASSIFICATION");
    });

    it("should fall back to operator for unknown role", () => {
      const guardrails = buildMissionGuardrails("unknown");
      expect(guardrails).toContain("SCOPE CHECK");
    });
  });

  describe("getDeliverableTemplates", () => {
    it("should return operator templates with SITREP format", () => {
      const templates = getDeliverableTemplates("operator");
      expect(templates).toContain("SITREP");
      expect(templates).toContain("FINDING FORMAT");
      expect(templates).toContain("ATTACK PATH FORMAT");
    });

    it("should return analyst templates", () => {
      const templates = getDeliverableTemplates("analyst");
      expect(templates).toContain("THREAT ASSESSMENT");
      expect(templates).toContain("HUNT HYPOTHESIS");
    });

    it("should return empty string for unknown role", () => {
      const templates = getDeliverableTemplates("unknown");
      expect(templates).toBe("");
    });
  });

  describe("enhanceChatPrompt (master function)", () => {
    it("should return all prompt parts when all features enabled", () => {
      const result = enhanceChatPrompt("operator", "Run OSINT on target.com");
      expect(result.additionalPromptParts.length).toBeGreaterThan(0);
      // Should have reasoning + delegation + confidence + guardrails + templates
      const joined = result.additionalPromptParts.join("\n");
      expect(joined).toContain("ASSESS"); // reasoning
      expect(joined).toContain("Confidence"); // confidence
      expect(joined).toContain("MISSION BOUNDARY"); // guardrails
      expect(joined).toContain("SITREP"); // templates
    });

    it("should detect and return delegated agent", () => {
      const result = enhanceChatPrompt("operator", "Run OSINT reconnaissance on target.com");
      expect(result.delegatedAgent).not.toBeNull();
      expect(result.delegatedAgent!.agentId).toBe("offensive-osint-analyst-v1");
    });

    it("should return null delegated agent for generic messages", () => {
      const result = enhanceChatPrompt("operator", "Hello, how are you?");
      expect(result.delegatedAgent).toBeNull();
    });

    it("should respect feature flags", () => {
      const result = enhanceChatPrompt("operator", "Run OSINT on target.com", {
        enableReasoning: false,
        enableDelegation: false,
        enableConfidence: false,
        enableGuardrails: false,
        enableTemplates: false,
      });
      expect(result.additionalPromptParts).toHaveLength(0);
      expect(result.delegatedAgent).toBeNull();
    });

    it("should enable only reasoning when specified", () => {
      const result = enhanceChatPrompt("operator", "Hello", {
        enableReasoning: true,
        enableDelegation: false,
        enableConfidence: false,
        enableGuardrails: false,
        enableTemplates: false,
      });
      expect(result.additionalPromptParts).toHaveLength(1);
      expect(result.additionalPromptParts[0]).toContain("ASSESS");
    });
  });
});
