/**
 * Campaign Orchestrator — Comprehensive Tests
 *
 * Tests cover:
 *   1. Condition evaluator: single conditions, compound conditions, edge cases
 *   2. Engine exports: all expected symbols are exported
 *   3. Router: procedure definitions and structure
 *   4. UI routes: sidebar nav entries and App.tsx route registration
 *   5. Database schema: table definitions
 *   6. WebSocket event types: campaign orchestrator events registered
 */
import { describe, it, expect } from "vitest";
import path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ═══════════════════════════════════════════════════════════════════════════
// 1. CONDITION EVALUATOR TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator — Condition Evaluator", () => {
  it("evaluateCondition handles '>' operator correctly", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "total_vulns", operator: ">", value: 5 }, { total_vulns: 10 })).toBe(true);
    expect(evaluateCondition({ field: "total_vulns", operator: ">", value: 10 }, { total_vulns: 10 })).toBe(false);
    expect(evaluateCondition({ field: "total_vulns", operator: ">", value: 15 }, { total_vulns: 10 })).toBe(false);
  });

  it("evaluateCondition handles '>=' operator correctly", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "c2_agents", operator: ">=", value: 1 }, { c2_agents: 1 })).toBe(true);
    expect(evaluateCondition({ field: "c2_agents", operator: ">=", value: 1 }, { c2_agents: 0 })).toBe(false);
    expect(evaluateCondition({ field: "c2_agents", operator: ">=", value: 0 }, { c2_agents: 0 })).toBe(true);
  });

  it("evaluateCondition handles '<' and '<=' operators", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "stages_failed", operator: "<", value: 3 }, { stages_failed: 2 })).toBe(true);
    expect(evaluateCondition({ field: "stages_failed", operator: "<", value: 2 }, { stages_failed: 2 })).toBe(false);
    expect(evaluateCondition({ field: "stages_failed", operator: "<=", value: 2 }, { stages_failed: 2 })).toBe(true);
  });

  it("evaluateCondition handles '==' operator with string coercion", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "status", operator: "==", value: "completed" }, { status: "completed" })).toBe(true);
    expect(evaluateCondition({ field: "count", operator: "==", value: "5" }, { count: 5 })).toBe(true);
    expect(evaluateCondition({ field: "status", operator: "==", value: "failed" }, { status: "completed" })).toBe(false);
  });

  it("evaluateCondition handles '!=' operator", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "status", operator: "!=", value: "failed" }, { status: "completed" })).toBe(true);
    expect(evaluateCondition({ field: "status", operator: "!=", value: "completed" }, { status: "completed" })).toBe(false);
  });

  it("evaluateCondition handles 'contains' operator for arrays and strings", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "tools", operator: "contains", value: "scanforge-discovery" }, { tools: ["scanforge-discovery", "nuclei"] })).toBe(true);
    expect(evaluateCondition({ field: "tools", operator: "contains", value: "metasploit" }, { tools: ["scanforge-discovery", "nuclei"] })).toBe(false);
    expect(evaluateCondition({ field: "name", operator: "contains", value: "recon" }, { name: "external recon" })).toBe(true);
  });

  it("evaluateCondition handles 'exists' operator", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "c2_agents", operator: "exists", value: true }, { c2_agents: 3 })).toBe(true);
    expect(evaluateCondition({ field: "c2_agents", operator: "exists", value: true }, { c2_agents: undefined })).toBe(false);
    expect(evaluateCondition({ field: "c2_agents", operator: "exists", value: true }, { c2_agents: null })).toBe(false);
    expect(evaluateCondition({ field: "c2_agents", operator: "exists", value: true }, { c2_agents: 0 })).toBe(true);
  });

  it("evaluateCondition returns false for missing fields with numeric operators", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(evaluateCondition({ field: "missing", operator: ">", value: 0 }, {})).toBe(false);
    expect(evaluateCondition({ field: "missing", operator: ">=", value: 0 }, {})).toBe(false);
  });

  it("evaluateConditions returns passed=true when no conditions", async () => {
    const { evaluateConditions } = await import("./lib/campaign-orchestrator");
    const result = evaluateConditions([], {});
    expect(result.passed).toBe(true);
    expect(result.results).toHaveLength(0);
  });

  it("evaluateConditions uses AND logic — all must pass", async () => {
    const { evaluateConditions } = await import("./lib/campaign-orchestrator");
    const conditions = [
      { field: "total_vulns", operator: ">" as const, value: 0 },
      { field: "c2_agents", operator: ">=" as const, value: 1 },
    ];

    // Both pass
    const result1 = evaluateConditions(conditions, { total_vulns: 5, c2_agents: 2 });
    expect(result1.passed).toBe(true);
    expect(result1.results).toHaveLength(2);
    expect(result1.results.every((r) => r.passed)).toBe(true);

    // One fails
    const result2 = evaluateConditions(conditions, { total_vulns: 5, c2_agents: 0 });
    expect(result2.passed).toBe(false);
    expect(result2.results[0].passed).toBe(true);
    expect(result2.results[1].passed).toBe(false);

    // Both fail
    const result3 = evaluateConditions(conditions, { total_vulns: 0, c2_agents: 0 });
    expect(result3.passed).toBe(false);
  });

  it("evaluateConditions includes actualValue in results", async () => {
    const { evaluateConditions } = await import("./lib/campaign-orchestrator");
    const result = evaluateConditions(
      [{ field: "total_vulns", operator: ">", value: 10 }],
      { total_vulns: 7 }
    );
    expect(result.results[0].actualValue).toBe(7);
    expect(result.results[0].passed).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. ENGINE EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator — Engine Exports", () => {
  it("exports all expected symbols from campaign-orchestrator", async () => {
    const mod = await import("./lib/campaign-orchestrator");
    expect(mod.evaluateCondition).toBeDefined();
    expect(mod.evaluateConditions).toBeDefined();
    expect(mod.executeCampaign).toBeDefined();
    expect(mod.pauseCampaign).toBeDefined();
    expect(mod.resumeCampaign).toBeDefined();
    expect(mod.abortCampaign).toBeDefined();
    expect(mod.getCampaignRunState).toBeDefined();
    expect(mod.getRunningCampaigns).toBeDefined();
    expect(mod.generateCampaignPlan).toBeDefined();
  });

  it("evaluateCondition is a function", async () => {
    const { evaluateCondition } = await import("./lib/campaign-orchestrator");
    expect(typeof evaluateCondition).toBe("function");
  });

  it("evaluateConditions is a function", async () => {
    const { evaluateConditions } = await import("./lib/campaign-orchestrator");
    expect(typeof evaluateConditions).toBe("function");
  });

  it("getRunningCampaigns returns an array", async () => {
    const { getRunningCampaigns } = await import("./lib/campaign-orchestrator");
    const result = getRunningCampaigns();
    expect(Array.isArray(result)).toBe(true);
  });

  it("getCampaignRunState returns null for non-existent campaign", async () => {
    const { getCampaignRunState } = await import("./lib/campaign-orchestrator");
    expect(getCampaignRunState(999999)).toBeNull();
  });

  it("pauseCampaign returns false for non-running campaign", async () => {
    const { pauseCampaign } = await import("./lib/campaign-orchestrator");
    expect(pauseCampaign(999999)).toBe(false);
  });

  it("resumeCampaign returns false for non-paused campaign", async () => {
    const { resumeCampaign } = await import("./lib/campaign-orchestrator");
    expect(resumeCampaign(999999)).toBe(false);
  });

  it("abortCampaign returns false for non-running campaign", async () => {
    const { abortCampaign } = await import("./lib/campaign-orchestrator");
    expect(abortCampaign(999999)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. ROUTER STRUCTURE
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator — Router Structure", () => {
  it("exports campaignOrchestratorRouter", async () => {
    const { campaignOrchestratorRouter } = await import("./routers/campaign-orchestrator");
    expect(campaignOrchestratorRouter).toBeDefined();
  });

  it("router has all expected procedures", async () => {
    const { campaignOrchestratorRouter } = await import("./routers/campaign-orchestrator");
    const procedures = Object.keys((campaignOrchestratorRouter as any)._def.procedures || {});
    const expected = [
      "list", "getById", "create", "update", "delete",
      "addStage", "updateStage", "removeStage", "reorderStages",
      "execute", "pause", "resume", "abort",
      "getLogs", "getStatus",
      "generatePlan", "applyPlan",
      "listEngagements",
    ];
    for (const proc of expected) {
      expect(procedures).toContain(proc);
    }
  });

  it("router is registered in the main appRouter", async () => {
    const routersFile = await import("fs").then((fs) =>
      fs.readFileSync(path.join(PROJECT_ROOT, "server/routers.ts"), "utf-8")
    );
    expect(routersFile).toContain("campaignOrchestratorRouter");
    expect(routersFile).toContain("campaignOrchestrator:");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. UI ROUTES & SIDEBAR NAV
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator — UI Integration", () => {
  it("sidebar nav includes Campaign Orchestrator entry", async () => {
    const navFile = await import("fs").then((fs) =>
      fs.readFileSync(path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"), "utf-8")
    );
    expect(navFile).toContain("Campaign Orchestrator");
    expect(navFile).toContain("/campaign-orchestrator");
  });

  it("App.tsx has lazy import and route for CampaignOrchestrator", async () => {
    const appFile = await import("fs").then((fs) =>
      fs.readFileSync(path.join(PROJECT_ROOT, "client/src/App.tsx"), "utf-8")
    );
    expect(appFile).toContain('CampaignOrchestrator');
    expect(appFile).toContain('/campaign-orchestrator');
    // Check both list and detail routes
    expect(appFile).toContain('/campaign-orchestrator/:id');
  });

  it("CampaignOrchestrator page file exists", async () => {
    const fs = await import("fs");
    expect(fs.existsSync(path.join(PROJECT_ROOT, "client/src/pages/CampaignOrchestrator.tsx"))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. DATABASE SCHEMA
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator — Database Schema", () => {
  it("exports redteamCampaigns table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.redteamCampaigns).toBeDefined();
  });

  it("exports redteamCampaignStages table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.redteamCampaignStages).toBeDefined();
  });

  it("exports redteamCampaignLogs table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.redteamCampaignLogs).toBeDefined();
  });

  it("campaign tables have expected column definitions", async () => {
    const schema = await import("../drizzle/schema");
    // Verify tables have column config objects
    const campaignCols = Object.keys((schema.redteamCampaigns as any)[Symbol.for("drizzle:Columns")] || (schema.redteamCampaigns as any)._.columns || {});
    expect(campaignCols.length).toBeGreaterThan(0);
    const stageCols = Object.keys((schema.redteamCampaignStages as any)[Symbol.for("drizzle:Columns")] || (schema.redteamCampaignStages as any)._.columns || {});
    expect(stageCols.length).toBeGreaterThan(0);
    const logCols = Object.keys((schema.redteamCampaignLogs as any)[Symbol.for("drizzle:Columns")] || (schema.redteamCampaignLogs as any)._.columns || {});
    expect(logCols.length).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. WEBSOCKET EVENT TYPES
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator — WebSocket Events", () => {
  it("ws-event-hub includes campaign orchestrator event types", async () => {
    const wsFile = await import("fs").then((fs) =>
      fs.readFileSync(path.join(PROJECT_ROOT, "server/lib/ws-event-hub.ts"), "utf-8")
    );
    expect(wsFile).toContain("campaign_orch:started");
    expect(wsFile).toContain("campaign_orch:stage_started");
    expect(wsFile).toContain("campaign_orch:stage_completed");
    expect(wsFile).toContain("campaign_orch:stage_failed");
    expect(wsFile).toContain("campaign_orch:condition_eval");
    expect(wsFile).toContain("campaign_orch:completed");
    expect(wsFile).toContain("campaign_orch:paused");
    expect(wsFile).toContain("campaign_orch:aborted");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. CAMPAIGN CLONING — Router Procedure
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator — Clone Procedure", () => {
  it("router has 'clone' procedure", async () => {
    const { campaignOrchestratorRouter } = await import("./routers/campaign-orchestrator");
    const procedures = Object.keys((campaignOrchestratorRouter as any)._def.procedures || {});
    expect(procedures).toContain("clone");
  });

  it("router has 'generateReport' procedure", async () => {
    const { campaignOrchestratorRouter } = await import("./routers/campaign-orchestrator");
    const procedures = Object.keys((campaignOrchestratorRouter as any)._def.procedures || {});
    expect(procedures).toContain("generateReport");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. CAMPAIGN-TO-REPORT PIPELINE — Schema & Mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign-to-Report Pipeline — Schema & Mapping", () => {
  it("schema exports ac3Reports and ac3ReportFindings tables", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.ac3Reports).toBeDefined();
    expect(schema.ac3ReportFindings).toBeDefined();
  });

  it("campaign orchestrator router imports ac3Reports", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/campaign-orchestrator.ts"), "utf-8");
    expect(content).toContain("ac3Reports");
    expect(content).toContain("ac3ReportFindings");
    expect(content).toContain("randomUUID");
  });

  it("generateReport procedure has ATT&CK technique mappings", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/campaign-orchestrator.ts"), "utf-8");
    expect(content).toContain("STAGE_TO_TECHNIQUE");
    expect(content).toContain("T1595"); // Active Scanning
    expect(content).toContain("T1566"); // Phishing
    expect(content).toContain("T1190"); // Exploit Public-Facing Application
    expect(content).toContain("T1041"); // Exfiltration Over C2 Channel
  });

  it("generateReport procedure has NIST control mappings", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/campaign-orchestrator.ts"), "utf-8");
    expect(content).toContain("STAGE_TO_CONTROL");
    expect(content).toContain("RA-5"); // Vulnerability Monitoring
    expect(content).toContain("AT-2"); // Literacy Training
    expect(content).toContain("SC-7"); // Boundary Protection
  });

  it("generateReport includes severity derivation logic", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/campaign-orchestrator.ts"), "utf-8");
    expect(content).toContain("deriveSeverity");
    expect(content).toContain("criticalVulns");
    expect(content).toContain("exploitsSucceeded");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 9. TEMPLATE CUSTOMIZATION — Router & UI
// ═══════════════════════════════════════════════════════════════════════════

describe("Template Customization — Router & Schema", () => {
  it("ember-templates router exports expected procedures", async () => {
    const { emberTemplatesRouter } = await import("./routers/ember-templates");
    expect(emberTemplatesRouter).toBeDefined();
    const procedures = Object.keys(emberTemplatesRouter);
    expect(procedures).toContain("listTemplates");
    expect(procedures).toContain("getTemplate");
    expect(procedures).toContain("saveTemplate");
    expect(procedures).toContain("cloneTemplate");
    expect(procedures).toContain("deleteTemplate");
  });

  it("schema exports emberCustomTemplates table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.emberCustomTemplates).toBeDefined();
  });

  it("EmberTaskTemplates component includes customize integration", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/components/EmberTaskTemplates.tsx"), "utf-8");
    expect(content).toContain("Customize");
    expect(content).toContain("listTemplates");
    expect(content).toContain("CustomizeDialog");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 10. CAMPAIGN CLONE & REPORT UI — Button Integration
// ═══════════════════════════════════════════════════════════════════════════

describe("Campaign Orchestrator UI — Clone & Report Buttons", () => {
  it("CampaignOrchestrator page includes Clone button and dialog", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CampaignOrchestrator.tsx"), "utf-8");
    expect(content).toContain("Clone");
    expect(content).toContain("cloneMut");
    expect(content).toContain("cloneOpen");
    expect(content).toContain("cloneName");
    expect(content).toContain("Clone Campaign");
  });

  it("CampaignOrchestrator page includes Generate Report button and dialog", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CampaignOrchestrator.tsx"), "utf-8");
    expect(content).toContain("Generate Report");
    expect(content).toContain("generateReportMut");
    expect(content).toContain("reportOpen");
    expect(content).toContain("ClipboardList");
    expect(content).toContain("Assessment Type");
    expect(content).toContain("red_team");
    expect(content).toContain("penetration_test");
  });
});
