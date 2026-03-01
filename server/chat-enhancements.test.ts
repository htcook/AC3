import { describe, expect, it } from "vitest";
import { getRoleActions, actionsToLLMTools } from "./lib/role-quick-actions";
import { getRoleChatConfig } from "./lib/role-chat-prompts";
import type { CalderaRole } from "./lib/role-chat-prompts";

const ALL_ROLES: CalderaRole[] = ["operator", "executive", "analyst", "team_lead", "client", "admin"];

// ─── Quick Actions Catalog Tests ────────────────────────────────────────────

describe("Role Quick Actions", () => {
  it("every role should have at least 2 quick actions", () => {
    for (const role of ALL_ROLES) {
      const actions = getRoleActions(role);
      expect(actions.length).toBeGreaterThanOrEqual(2);
    }
  });

  it("each action should have required fields", () => {
    for (const role of ALL_ROLES) {
      const actions = getRoleActions(role);
      for (const action of actions) {
        expect(action.name).toBeTruthy();
        expect(action.displayName).toBeTruthy();
        expect(action.description).toBeTruthy();
        expect(action.icon).toBeTruthy();
        expect(typeof action.confirmRequired).toBe("boolean");
        expect(Array.isArray(action.params)).toBe(true);
      }
    }
  });

  it("action names should be unique within each role", () => {
    for (const role of ALL_ROLES) {
      const actions = getRoleActions(role);
      const names = actions.map((a) => a.name);
      expect(new Set(names).size).toBe(names.length);
    }
  });

  it("operator should have generate_payload action with confirmRequired", () => {
    const actions = getRoleActions("operator");
    const payload = actions.find((a) => a.name === "generate_payload");
    expect(payload).toBeDefined();
    expect(payload!.confirmRequired).toBe(true);
    expect(payload!.params.length).toBeGreaterThan(0);
  });

  it("admin should have purge_old_errors action with confirmRequired", () => {
    const actions = getRoleActions("admin");
    const purge = actions.find((a) => a.name === "purge_old_errors");
    expect(purge).toBeDefined();
    expect(purge!.confirmRequired).toBe(true);
  });

  it("executive should have generate_risk_summary action", () => {
    const actions = getRoleActions("executive");
    const riskSummary = actions.find((a) => a.name === "generate_risk_summary");
    expect(riskSummary).toBeDefined();
    expect(riskSummary!.confirmRequired).toBe(false);
  });

  it("analyst should have enrich_ioc action with type enum", () => {
    const actions = getRoleActions("analyst");
    const enrichIoc = actions.find((a) => a.name === "enrich_ioc");
    expect(enrichIoc).toBeDefined();
    const typeParam = enrichIoc!.params.find((p) => p.name === "type");
    expect(typeParam).toBeDefined();
    expect(typeParam!.enum).toBeDefined();
    expect(typeParam!.enum!.length).toBeGreaterThan(0);
  });

  it("team_lead should have get_pipeline_summary action", () => {
    const actions = getRoleActions("team_lead");
    const pipeline = actions.find((a) => a.name === "get_pipeline_summary");
    expect(pipeline).toBeDefined();
  });

  it("client should have get_remediation_plan action", () => {
    const actions = getRoleActions("client");
    const remediation = actions.find((a) => a.name === "get_remediation_plan");
    expect(remediation).toBeDefined();
  });

  it("unknown role should fall back to operator actions", () => {
    const actions = getRoleActions("nonexistent_role");
    const operatorActions = getRoleActions("operator");
    expect(actions.length).toBe(operatorActions.length);
    expect(actions[0].name).toBe(operatorActions[0].name);
  });
});

// ─── LLM Tool Format Conversion Tests ──────────────────────────────────────

describe("actionsToLLMTools", () => {
  it("should convert actions to OpenAI-compatible tool format", () => {
    const actions = getRoleActions("operator");
    const tools = actionsToLLMTools(actions);
    expect(tools.length).toBe(actions.length);
    for (const tool of tools) {
      expect(tool.type).toBe("function");
      expect(tool.function.name).toBeTruthy();
      expect(tool.function.description).toBeTruthy();
      expect(tool.function.parameters.type).toBe("object");
      expect(typeof tool.function.parameters.properties).toBe("object");
      expect(Array.isArray(tool.function.parameters.required)).toBe(true);
    }
  });

  it("should include enum values in tool parameters", () => {
    const actions = getRoleActions("operator");
    const tools = actionsToLLMTools(actions);
    const payloadTool = tools.find((t) => t.function.name === "generate_payload");
    expect(payloadTool).toBeDefined();
    const platformProp = payloadTool!.function.parameters.properties["platform"];
    expect(platformProp.enum).toBeDefined();
    expect(platformProp.enum).toContain("windows");
    expect(platformProp.enum).toContain("linux");
  });

  it("should mark required params correctly", () => {
    const actions = getRoleActions("admin");
    const tools = actionsToLLMTools(actions);
    const errorTool = tools.find((t) => t.function.name === "get_error_report");
    expect(errorTool).toBeDefined();
    // hours is optional, so required should be empty
    expect(errorTool!.function.parameters.required).not.toContain("hours");
  });

  it("should handle actions with no params", () => {
    const actions = getRoleActions("executive");
    const tools = actionsToLLMTools(actions);
    const riskTool = tools.find((t) => t.function.name === "generate_risk_summary");
    expect(riskTool).toBeDefined();
    expect(Object.keys(riskTool!.function.parameters.properties).length).toBe(0);
    expect(riskTool!.function.parameters.required.length).toBe(0);
  });
});

// ─── Admin Persona Switching Tests ──────────────────────────────────────────

describe("Admin Persona Switching", () => {
  it("getRoleChatConfig should return different configs for each role", () => {
    const configs = ALL_ROLES.map((r) => getRoleChatConfig(r));
    const names = configs.map((c) => c.assistantName);
    expect(new Set(names).size).toBe(ALL_ROLES.length);
  });

  it("switching persona should change the system prompt", () => {
    const operatorConfig = getRoleChatConfig("operator");
    const executiveConfig = getRoleChatConfig("executive");
    expect(operatorConfig.systemPrompt).not.toBe(executiveConfig.systemPrompt);
  });

  it("switching persona should change suggestions", () => {
    const operatorConfig = getRoleChatConfig("operator");
    const clientConfig = getRoleChatConfig("client");
    expect(operatorConfig.suggestions).not.toEqual(clientConfig.suggestions);
  });

  it("switching persona should change quick actions", () => {
    const operatorActions = getRoleActions("operator");
    const executiveActions = getRoleActions("executive");
    const operatorNames = operatorActions.map((a) => a.name).sort();
    const executiveNames = executiveActions.map((a) => a.name).sort();
    expect(operatorNames).not.toEqual(executiveNames);
  });

  it("switching persona should change context permissions", () => {
    const operatorConfig = getRoleChatConfig("operator");
    const clientConfig = getRoleChatConfig("client");
    // Operator can view creds, client cannot
    expect(operatorConfig.canViewCreds).toBe(true);
    expect(clientConfig.canViewCreds).toBe(false);
  });

  it("all personas should be valid CalderaRole values", () => {
    const validRoles = ALL_ROLES;
    for (const role of validRoles) {
      const config = getRoleChatConfig(role);
      expect(config).toBeDefined();
      expect(config.assistantName).toBeTruthy();
    }
  });
});

// ─── Chat Session Schema Validation Tests ───────────────────────────────────

describe("Chat Session Schema", () => {
  it("chatSessions and chatMessages tables should be importable", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.chatSessions).toBeDefined();
    expect(schema.chatMessages).toBeDefined();
  });

  it("chatSessions should have required columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.chatSessions;
    // Check the table has the expected column references
    expect(table.id).toBeDefined();
    expect(table.userId).toBeDefined();
    expect(table.title).toBeDefined();
    expect(table.role).toBeDefined();
    expect(table.messageCount).toBeDefined();
    expect(table.archived).toBeDefined();
    expect(table.createdAt).toBeDefined();
  });

  it("chatMessages should have required columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.chatMessages;
    expect(table.id).toBeDefined();
    expect(table.sessionId).toBeDefined();
    expect(table.role).toBeDefined();
    expect(table.content).toBeDefined();
    expect(table.toolName).toBeDefined();
    expect(table.toolResult).toBeDefined();
    expect(table.createdAt).toBeDefined();
  });
});
