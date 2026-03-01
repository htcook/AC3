import { describe, it, expect } from "vitest";

// ─── SOC Role RBAC Tests ───────────────────────────────────────────────────────

// Import the RBAC functions
import {
  canAccessGroup,
  canAccessSubSection,
  canAccessRoute,
  getHomeDashboardPath,
  getRoleDisplayName,
  getRoleBadgeClass,
  ALL_ROLES,
} from "../client/src/lib/role-access";

describe("SOC Role — RBAC Group Access", () => {
  it("should have access to command, surface, emulation, intelligence, ksi, and reports groups", () => {
    const expectedGroups = ["command", "surface", "emulation", "intelligence", "ksi", "reports"];
    for (const group of expectedGroups) {
      expect(canAccessGroup("soc", group)).toBe(true);
    }
  });

  it("should NOT have access to exploits or platform groups", () => {
    expect(canAccessGroup("soc", "exploits")).toBe(false);
    expect(canAccessGroup("soc", "platform")).toBe(false);
  });
});

describe("SOC Role — RBAC Sub-section Restrictions", () => {
  it("should have access to emu-agents for threat actor emulation context", () => {
    expect(canAccessSubSection("soc", "emu-agents")).toBe(true);
  });

  it("should have access to emu-validation for defense testing", () => {
    expect(canAccessSubSection("soc", "emu-validation")).toBe(true);
  });

  it("should have access to intel-threats for threat intelligence", () => {
    expect(canAccessSubSection("soc", "intel-threats")).toBe(true);
  });

  it("should have access to intel-credentials for credential monitoring", () => {
    expect(canAccessSubSection("soc", "intel-credentials")).toBe(true);
  });

  it("should have access to cmd-ops and cmd-scoring", () => {
    expect(canAccessSubSection("soc", "cmd-ops")).toBe(true);
    expect(canAccessSubSection("soc", "cmd-scoring")).toBe(true);
  });

  it("should have access to surface discovery, tools, and paths", () => {
    expect(canAccessSubSection("soc", "surf-discovery")).toBe(true);
    expect(canAccessSubSection("soc", "surf-tools")).toBe(true);
    expect(canAccessSubSection("soc", "surf-paths")).toBe(true);
  });

  it("should NOT have access to exploit sub-sections (not in allowed groups)", () => {
    // Since exploits group is not allowed, sub-sections don't matter,
    // but verify the restriction list doesn't include exploit sub-sections
    expect(canAccessSubSection("soc", "exp-phishing")).toBe(false);
    expect(canAccessSubSection("soc", "exp-tools")).toBe(false);
    expect(canAccessSubSection("soc", "exp-c2")).toBe(false);
  });
});

describe("SOC Role — Navigation and Display", () => {
  it("should have a dedicated home dashboard path", () => {
    expect(getHomeDashboardPath("soc")).toBe("/home/soc");
  });

  it("should display as 'SOC Analyst'", () => {
    expect(getRoleDisplayName("soc")).toBe("SOC Analyst");
  });

  it("should have emerald badge colors", () => {
    const badge = getRoleBadgeClass("soc");
    expect(badge).toContain("emerald");
  });

  it("should be listed in ALL_ROLES for the role switcher", () => {
    const socRole = ALL_ROLES.find(r => r.value === "soc");
    expect(socRole).toBeDefined();
    expect(socRole!.label).toBe("SOC Analyst");
    expect(socRole!.description).toContain("Security Operations Center");
  });

  it("should have access to universal routes", () => {
    expect(canAccessRoute("soc", "/")).toBe(true);
    expect(canAccessRoute("soc", "/dashboard")).toBe(true);
  });

  it("should NOT have access to admin-only routes", () => {
    expect(canAccessRoute("soc", "/team")).toBe(false);
    expect(canAccessRoute("soc", "/audit-log")).toBe(false);
    expect(canAccessRoute("soc", "/tenants")).toBe(false);
  });
});

// ─── Analyst Role — Threat Intel & Emulation Access ────────────────────────────

describe("Analyst Role — Expanded Threat Intel & Emulation Access", () => {
  it("should now have access to emulation group", () => {
    expect(canAccessGroup("analyst", "emulation")).toBe(true);
  });

  it("should have access to emu-agents for threat actor emulation context", () => {
    expect(canAccessSubSection("analyst", "emu-agents")).toBe(true);
  });

  it("should have access to emu-validation for defense validation", () => {
    expect(canAccessSubSection("analyst", "emu-validation")).toBe(true);
  });

  it("should retain full intelligence access", () => {
    expect(canAccessGroup("analyst", "intelligence")).toBe(true);
    expect(canAccessSubSection("analyst", "intel-threats")).toBe(true);
    expect(canAccessSubSection("analyst", "intel-credentials")).toBe(true);
  });
});

// ─── Operator Role — Threat Intel Access ───────────────────────────────────────

describe("Operator Role — Threat Intel Access", () => {
  it("should have full intelligence group access", () => {
    expect(canAccessGroup("operator", "intelligence")).toBe(true);
  });

  it("should have unrestricted sub-section access (no restrictions defined)", () => {
    // Operator has no sub-section restrictions, so all sub-sections are visible
    expect(canAccessSubSection("operator", "intel-threats")).toBe(true);
    expect(canAccessSubSection("operator", "intel-credentials")).toBe(true);
    expect(canAccessSubSection("operator", "emu-agents")).toBe(true);
    expect(canAccessSubSection("operator", "emu-validation")).toBe(true);
  });
});

// ─── WATCH ADVISOR Persona Tests ───────────────────────────────────────────────

import { getRoleChatConfig, getAllRoleChatConfigs } from "./lib/role-chat-prompts";

describe("WATCH ADVISOR — SOC AI Persona", () => {
  const socConfig = getRoleChatConfig("soc");

  it("should exist in ROLE_CONFIGS", () => {
    expect(socConfig).toBeDefined();
  });

  it("should be named WATCH ADVISOR", () => {
    expect(socConfig.assistantName).toBe("WATCH ADVISOR");
  });

  it("should have SOC Operations AI subtitle", () => {
    expect(socConfig.assistantSubtitle).toBe("SOC Operations AI");
  });

  it("should have a system prompt covering core SOC expertise areas", () => {
    const prompt = socConfig.systemPrompt;
    expect(prompt).toContain("Alert triage");
    expect(prompt).toContain("Detection engineering");
    expect(prompt).toContain("Threat hunting");
    expect(prompt).toContain("Incident response");
    expect(prompt).toContain("MITRE ATT&CK");
    expect(prompt).toContain("Log analysis");
    expect(prompt).toContain("EDR/XDR");
    expect(prompt).toContain("SIEM/SOAR");
    expect(prompt).toContain("Purple team");
  });

  it("should have SOC-relevant suggestions", () => {
    expect(socConfig.suggestions.length).toBeGreaterThanOrEqual(6);
    const suggestionText = socConfig.suggestions.join(" ");
    expect(suggestionText).toContain("Triage");
    expect(suggestionText).toContain("Sigma");
    expect(suggestionText).toContain("ATT&CK");
    expect(suggestionText).toContain("hunting");
  });

  it("should have appropriate context toggles for SOC work", () => {
    const toggleKeys = socConfig.contextToggles.map(t => t.key);
    expect(toggleKeys).toContain("includeDetections");
    expect(toggleKeys).toContain("includeThreatIntel");
    expect(toggleKeys).toContain("includeAlerts");
    expect(toggleKeys).toContain("includeEdrData");
  });

  it("should allow viewing errors but not credentials", () => {
    expect(socConfig.canViewErrors).toBe(true);
    expect(socConfig.canViewCreds).toBe(false);
  });
});

// ─── All Roles Complete Coverage Check ─────────────────────────────────────────

describe("All Roles — Complete Coverage", () => {
  const allRoleKeys: string[] = [
    "operator", "team_lead", "analyst", "executive",
    "client", "admin", "user", "viewer", "soc"
  ];

  it("every role should have a display name", () => {
    for (const role of allRoleKeys) {
      expect(getRoleDisplayName(role as any)).toBeTruthy();
    }
  });

  it("every role should have a badge class", () => {
    for (const role of allRoleKeys) {
      expect(getRoleBadgeClass(role as any)).toBeTruthy();
    }
  });

  it("every role should have a home dashboard path", () => {
    for (const role of allRoleKeys) {
      const path = getHomeDashboardPath(role as any);
      expect(path).toMatch(/^\/home\//);
    }
  });

  it("roles with threat intel needs should have intelligence group access", () => {
    const threatIntelRoles = ["operator", "team_lead", "analyst", "admin", "user", "soc"];
    for (const role of threatIntelRoles) {
      expect(canAccessGroup(role as any, "intelligence")).toBe(true);
    }
  });

  it("roles with emulation needs should have emulation group access", () => {
    const emulationRoles = ["operator", "team_lead", "analyst", "admin", "user", "soc"];
    for (const role of emulationRoles) {
      expect(canAccessGroup(role as any, "emulation")).toBe(true);
    }
  });
});
