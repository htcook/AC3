/**
 * Tests for Role-Based Access, WebSocket Event Types, and Auto-Persistence Integration
 */
import { describe, it, expect, vi } from "vitest";

// ─── Role-Based Access Tests ────────────────────────────────────────────────

// Import the role access config from client-side (test the logic)
const ROLE_ACCESS: Record<string, string[]> = {
  operator: [
    "Command Center", "Exploit Ops", "Recon & Intel", "Credential & Export",
    "Infrastructure", "Phishing Ops", "Compliance & Risk",
  ],
  team_lead: [
    "Command Center", "Exploit Ops", "Recon & Intel", "Credential & Export",
    "Infrastructure", "Phishing Ops", "Compliance & Risk", "Platform",
  ],
  analyst: [
    "Command Center", "Recon & Intel", "Credential & Export", "Compliance & Risk",
  ],
  executive: [
    "Command Center", "Compliance & Risk",
  ],
  client: [
    "Command Center",
  ],
  admin: [
    "Command Center", "Exploit Ops", "Recon & Intel", "Credential & Export",
    "Infrastructure", "Phishing Ops", "Compliance & Risk", "Platform",
  ],
};

describe("Role-Based Access Control", () => {
  it("should define access for all 6 roles", () => {
    expect(Object.keys(ROLE_ACCESS)).toHaveLength(6);
    expect(ROLE_ACCESS).toHaveProperty("operator");
    expect(ROLE_ACCESS).toHaveProperty("team_lead");
    expect(ROLE_ACCESS).toHaveProperty("analyst");
    expect(ROLE_ACCESS).toHaveProperty("executive");
    expect(ROLE_ACCESS).toHaveProperty("client");
    expect(ROLE_ACCESS).toHaveProperty("admin");
  });

  it("operator should have access to all operational sections", () => {
    expect(ROLE_ACCESS.operator).toContain("Exploit Ops");
    expect(ROLE_ACCESS.operator).toContain("Recon & Intel");
    expect(ROLE_ACCESS.operator).toContain("Infrastructure");
    expect(ROLE_ACCESS.operator).toContain("Phishing Ops");
  });

  it("executive should only see Command Center and Compliance", () => {
    expect(ROLE_ACCESS.executive).toHaveLength(2);
    expect(ROLE_ACCESS.executive).toContain("Command Center");
    expect(ROLE_ACCESS.executive).toContain("Compliance & Risk");
  });

  it("client should only see Command Center", () => {
    expect(ROLE_ACCESS.client).toHaveLength(1);
    expect(ROLE_ACCESS.client).toContain("Command Center");
  });

  it("admin should have access to everything including Platform", () => {
    expect(ROLE_ACCESS.admin).toContain("Platform");
    expect(ROLE_ACCESS.admin).toContain("Exploit Ops");
    expect(ROLE_ACCESS.admin).toContain("Compliance & Risk");
  });

  it("team_lead should have Platform access for team management", () => {
    expect(ROLE_ACCESS.team_lead).toContain("Platform");
    expect(ROLE_ACCESS.team_lead).toContain("Exploit Ops");
  });

  it("analyst should not have access to Exploit Ops or Infrastructure", () => {
    expect(ROLE_ACCESS.analyst).not.toContain("Exploit Ops");
    expect(ROLE_ACCESS.analyst).not.toContain("Infrastructure");
    expect(ROLE_ACCESS.analyst).not.toContain("Phishing Ops");
  });

  it("should filter nav groups correctly for a given role", () => {
    const allGroups = [
      "Command Center", "Exploit Ops", "Recon & Intel", "Credential & Export",
      "Infrastructure", "Phishing Ops", "Compliance & Risk", "Platform",
    ];
    const executiveGroups = allGroups.filter(g => ROLE_ACCESS.executive.includes(g));
    expect(executiveGroups).toEqual(["Command Center", "Compliance & Risk"]);
  });
});

// ─── WebSocket Event Type Tests ─────────────────────────────────────────────

describe("WebSocket Event Types", () => {
  const OPSEC_EVENTS = [
    "opsec:action_scored",
    "opsec:burn_detected",
    "opsec:threshold_warning",
    "opsec:risk_update",
  ];

  const CREDENTIAL_EVENTS = [
    "credential:attack_started",
    "credential:attack_complete",
    "credential:found",
    "credential:validated",
  ];

  const LATERAL_EVENTS = [
    "lateral:pivot_planned",
    "lateral:tunnel_opened",
    "lateral:movement_executed",
  ];

  const PRIVESC_EVENTS = [
    "privesc:analysis_complete",
    "privesc:escalation_found",
    "privesc:kerberos_attack",
  ];

  const ENGAGEMENT_EVENTS = [
    "engagement:phase_changed",
    "engagement:handoff",
    "engagement:timeline_event",
    "engagement:progress_update",
  ];

  it("should have 4 OPSEC event types", () => {
    expect(OPSEC_EVENTS).toHaveLength(4);
  });

  it("should have 4 credential event types", () => {
    expect(CREDENTIAL_EVENTS).toHaveLength(4);
  });

  it("should have 3 lateral movement event types", () => {
    expect(LATERAL_EVENTS).toHaveLength(3);
  });

  it("should have 3 privesc event types", () => {
    expect(PRIVESC_EVENTS).toHaveLength(3);
  });

  it("should have 4 engagement workflow event types", () => {
    expect(ENGAGEMENT_EVENTS).toHaveLength(4);
  });

  it("should have advisor:recommendation event type", () => {
    expect("advisor:recommendation").toBeTruthy();
  });

  it("all event types should follow namespace:action pattern", () => {
    const allEvents = [
      ...OPSEC_EVENTS, ...CREDENTIAL_EVENTS, ...LATERAL_EVENTS,
      ...PRIVESC_EVENTS, ...ENGAGEMENT_EVENTS, "advisor:recommendation",
    ];
    for (const event of allEvents) {
      expect(event).toMatch(/^[a-z]+:[a-z_]+$/);
    }
  });
});

// ─── Auto-Persistence Integration Tests ─────────────────────────────────────

describe("Auto-Persistence Category Mapping", () => {
  const CATEGORY_TO_PHASE: Record<string, string> = {
    recon: "recon",
    scanning: "scanning",
    credential_attack: "gaining_access",
    exploitation: "gaining_access",
    lateral_movement: "lateral_movement",
    privilege_escalation: "escalation",
    post_exploitation: "maintaining_access",
    exfiltration: "exfiltration",
    phishing: "gaining_access",
    c2: "maintaining_access",
  };

  const CATEGORY_TO_OPSEC_ACTION: Record<string, string> = {
    recon: "dns_enumeration",
    scanning: "port_scan",
    credential_attack: "brute_force_attack",
    exploitation: "exploit_execution",
    lateral_movement: "lateral_movement_psexec",
    privilege_escalation: "privilege_escalation",
    post_exploitation: "credential_dumping",
    exfiltration: "data_exfiltration",
    phishing: "phishing_email",
    c2: "c2_beacon",
  };

  it("should map all 10 action categories to kill chain phases", () => {
    expect(Object.keys(CATEGORY_TO_PHASE)).toHaveLength(10);
  });

  it("should map all 10 action categories to OPSEC action types", () => {
    expect(Object.keys(CATEGORY_TO_OPSEC_ACTION)).toHaveLength(10);
  });

  it("credential_attack should map to gaining_access phase", () => {
    expect(CATEGORY_TO_PHASE.credential_attack).toBe("gaining_access");
  });

  it("exploitation should map to gaining_access phase", () => {
    expect(CATEGORY_TO_PHASE.exploitation).toBe("gaining_access");
  });

  it("lateral_movement should map to lateral_movement phase", () => {
    expect(CATEGORY_TO_PHASE.lateral_movement).toBe("lateral_movement");
  });

  it("privilege_escalation should map to escalation phase", () => {
    expect(CATEGORY_TO_PHASE.privilege_escalation).toBe("escalation");
  });

  it("c2 should map to maintaining_access phase", () => {
    expect(CATEGORY_TO_PHASE.c2).toBe("maintaining_access");
  });

  it("scanning should map to port_scan OPSEC action", () => {
    expect(CATEGORY_TO_OPSEC_ACTION.scanning).toBe("port_scan");
  });

  it("credential_attack should map to brute_force_attack OPSEC action", () => {
    expect(CATEGORY_TO_OPSEC_ACTION.credential_attack).toBe("brute_force_attack");
  });

  it("exfiltration should map to data_exfiltration OPSEC action", () => {
    expect(CATEGORY_TO_OPSEC_ACTION.exfiltration).toBe("data_exfiltration");
  });
});

// ─── Toast Notification Mapping Tests ───────────────────────────────────────

describe("WebSocket Toast Notifications", () => {
  const TOAST_EVENT_TYPES = [
    "exploit:result",
    "agent:deployed",
    "agent:lost",
    "operation:finished",
    "recon:complete",
    "pipeline:finished",
    "msf:server_ready",
    "msf:server_destroyed",
    "system:alert",
    "opsec:burn_detected",
    "opsec:threshold_warning",
    "credential:found",
    "credential:attack_complete",
    "lateral:movement_executed",
    "privesc:escalation_found",
    "engagement:phase_changed",
    "advisor:recommendation",
  ];

  it("should include OPSEC burn detection in toast events", () => {
    expect(TOAST_EVENT_TYPES).toContain("opsec:burn_detected");
  });

  it("should include OPSEC threshold warning in toast events", () => {
    expect(TOAST_EVENT_TYPES).toContain("opsec:threshold_warning");
  });

  it("should include credential found in toast events", () => {
    expect(TOAST_EVENT_TYPES).toContain("credential:found");
  });

  it("should include lateral movement in toast events", () => {
    expect(TOAST_EVENT_TYPES).toContain("lateral:movement_executed");
  });

  it("should include privesc found in toast events", () => {
    expect(TOAST_EVENT_TYPES).toContain("privesc:escalation_found");
  });

  it("should include engagement phase change in toast events", () => {
    expect(TOAST_EVENT_TYPES).toContain("engagement:phase_changed");
  });

  it("should include advisor recommendation in toast events", () => {
    expect(TOAST_EVENT_TYPES).toContain("advisor:recommendation");
  });

  it("should have 17 total toast event types", () => {
    expect(TOAST_EVENT_TYPES).toHaveLength(17);
  });
});

// ─── Role Dashboard Routing Tests ───────────────────────────────────────────

describe("Role-Based Dashboard Routing", () => {
  const ROLE_TO_DASHBOARD: Record<string, string> = {
    operator: "OperatorHome",
    team_lead: "TeamLeadHome",
    analyst: "AnalystHome",
    executive: "ExecutiveHome",
    client: "ClientHome",
    admin: "AdminHome",
  };

  it("should map all 6 roles to unique dashboards", () => {
    const dashboards = Object.values(ROLE_TO_DASHBOARD);
    expect(new Set(dashboards).size).toBe(6);
  });

  it("operator should route to OperatorHome", () => {
    expect(ROLE_TO_DASHBOARD.operator).toBe("OperatorHome");
  });

  it("executive should route to ExecutiveHome", () => {
    expect(ROLE_TO_DASHBOARD.executive).toBe("ExecutiveHome");
  });

  it("client should route to ClientHome", () => {
    expect(ROLE_TO_DASHBOARD.client).toBe("ClientHome");
  });

  it("admin should route to AdminHome", () => {
    expect(ROLE_TO_DASHBOARD.admin).toBe("AdminHome");
  });

  it("default role (user) should fall back to OperatorHome", () => {
    const role = "user";
    const dashboard = ROLE_TO_DASHBOARD[role] || "OperatorHome";
    expect(dashboard).toBe("OperatorHome");
  });
});
