import { describe, expect, it } from "vitest";
import { getRoleChatConfig, getAllRoleChatConfigs } from "./lib/role-chat-prompts";
import type { CalderaRole } from "./lib/role-chat-prompts";

describe("Role Chat Prompts", () => {
  const ALL_ROLES: CalderaRole[] = ["operator", "executive", "analyst", "team_lead", "client", "admin"];

  it("should return a config for every defined role", () => {
    for (const role of ALL_ROLES) {
      const config = getRoleChatConfig(role);
      expect(config).toBeDefined();
      expect(config.assistantName).toBeTruthy();
      expect(config.assistantSubtitle).toBeTruthy();
      expect(config.systemPrompt).toBeTruthy();
      expect(config.suggestions.length).toBeGreaterThan(0);
      expect(config.inputPlaceholder).toBeTruthy();
    }
  });

  it("should return unique assistant names for each role", () => {
    const names = ALL_ROLES.map((r) => getRoleChatConfig(r).assistantName);
    const uniqueNames = new Set(names);
    expect(uniqueNames.size).toBe(ALL_ROLES.length);
  });

  it("should return unique system prompts for each role", () => {
    const prompts = ALL_ROLES.map((r) => getRoleChatConfig(r).systemPrompt);
    const uniquePrompts = new Set(prompts);
    expect(uniquePrompts.size).toBe(ALL_ROLES.length);
  });

  it("should fall back to operator config for unknown roles", () => {
    const config = getRoleChatConfig("unknown_role");
    const operatorConfig = getRoleChatConfig("operator");
    expect(config.assistantName).toBe(operatorConfig.assistantName);
    expect(config.systemPrompt).toBe(operatorConfig.systemPrompt);
  });

  it("operator should have canViewErrors and canViewCreds enabled", () => {
    const config = getRoleChatConfig("operator");
    expect(config.canViewErrors).toBe(true);
    expect(config.canViewCreds).toBe(true);
  });

  it("executive should NOT have canViewErrors or canViewCreds", () => {
    const config = getRoleChatConfig("executive");
    expect(config.canViewErrors).toBe(false);
    expect(config.canViewCreds).toBe(false);
  });

  it("analyst should have canViewErrors but NOT canViewCreds", () => {
    const config = getRoleChatConfig("analyst");
    expect(config.canViewErrors).toBe(true);
    expect(config.canViewCreds).toBe(false);
  });

  it("client should NOT have canViewErrors or canViewCreds", () => {
    const config = getRoleChatConfig("client");
    expect(config.canViewErrors).toBe(false);
    expect(config.canViewCreds).toBe(false);
  });

  it("admin should have both canViewErrors and canViewCreds", () => {
    const config = getRoleChatConfig("admin");
    expect(config.canViewErrors).toBe(true);
    expect(config.canViewCreds).toBe(true);
  });

  it("team_lead should have canViewErrors but NOT canViewCreds", () => {
    const config = getRoleChatConfig("team_lead");
    expect(config.canViewErrors).toBe(true);
    expect(config.canViewCreds).toBe(false);
  });

  it("each role should have at least 2 context toggles", () => {
    for (const role of ALL_ROLES) {
      const config = getRoleChatConfig(role);
      expect(config.contextToggles.length).toBeGreaterThanOrEqual(2);
      for (const toggle of config.contextToggles) {
        expect(toggle.key).toBeTruthy();
        expect(toggle.label).toBeTruthy();
        expect(toggle.icon).toBeTruthy();
      }
    }
  });

  it("each role should have at least 4 suggestions", () => {
    for (const role of ALL_ROLES) {
      const config = getRoleChatConfig(role);
      expect(config.suggestions.length).toBeGreaterThanOrEqual(4);
    }
  });

  it("operator system prompt should mention MITRE ATT&CK", () => {
    const config = getRoleChatConfig("operator");
    expect(config.systemPrompt).toContain("MITRE ATT&CK");
  });

  it("executive system prompt should mention business impact", () => {
    const config = getRoleChatConfig("executive");
    expect(config.systemPrompt.toLowerCase()).toContain("business impact");
  });

  it("analyst system prompt should mention threat intelligence", () => {
    const config = getRoleChatConfig("analyst");
    expect(config.systemPrompt.toLowerCase()).toContain("threat intelligence");
  });

  it("team_lead system prompt should mention engagement", () => {
    const config = getRoleChatConfig("team_lead");
    expect(config.systemPrompt.toLowerCase()).toContain("engagement");
  });

  it("client system prompt should mention remediation", () => {
    const config = getRoleChatConfig("client");
    expect(config.systemPrompt.toLowerCase()).toContain("remediation");
  });

  it("admin system prompt should mention server administration", () => {
    const config = getRoleChatConfig("admin");
    expect(config.systemPrompt.toLowerCase()).toContain("server administration");
  });

  it("getAllRoleChatConfigs should return all 6 roles", () => {
    const all = getAllRoleChatConfigs();
    expect(Object.keys(all).length).toBe(6);
    for (const role of ALL_ROLES) {
      expect(all[role]).toBeDefined();
    }
  });

  it("operator suggestions should include offensive security topics", () => {
    const config = getRoleChatConfig("operator");
    const joined = config.suggestions.join(" ").toLowerCase();
    expect(
      joined.includes("attack") || joined.includes("exploit") || joined.includes("lateral") || joined.includes("opsec")
    ).toBe(true);
  });

  it("client suggestions should include remediation topics", () => {
    const config = getRoleChatConfig("client");
    const joined = config.suggestions.join(" ").toLowerCase();
    expect(
      joined.includes("remediat") || joined.includes("fix") || joined.includes("finding")
    ).toBe(true);
  });
});
