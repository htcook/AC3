/**
 * Training Integration Tests
 *
 * Tests for:
 * - New findSimilarIncidents and findSimilarTemplates procedures
 * - Attack Template Picker in Campaign Wizard
 * - Similar Attacks panel in Campaign Detail
 * - Training Dashboard sidebar navigation
 */
import { describe, it, expect } from "vitest";

describe("Similar Incidents & Templates Procedures", () => {
  it("should have findSimilarIncidents procedure on threatIntelTraining router", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("findSimilarIncidents");
  });

  it("should have findSimilarTemplates procedure on threatIntelTraining router", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("findSimilarTemplates");
  });

  it("findSimilarIncidents should be a query (not mutation)", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procs = routerDef.procedures || routerDef.record || {};
    const proc = procs["findSimilarIncidents"] as any;
    expect(proc).toBeDefined();
    // tRPC queries have _type "query"
    expect(proc._def?.type || proc._type).toBe("query");
  });

  it("findSimilarTemplates should be a query (not mutation)", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procs = routerDef.procedures || routerDef.record || {};
    const proc = procs["findSimilarTemplates"] as any;
    expect(proc).toBeDefined();
    expect(proc._def?.type || proc._type).toBe("query");
  });

  it("all existing procedures should still be present after additions", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    // Original procedures
    expect(procedures).toContain("ingestAll");
    expect(procedures).toContain("ingestSource");
    expect(procedures).toContain("ingestStats");
    expect(procedures).toContain("listSources");
    expect(procedures).toContain("listReports");
    expect(procedures).toContain("getReport");
    expect(procedures).toContain("processReport");
    expect(procedures).toContain("processBatch");
    expect(procedures).toContain("extractSequence");
    expect(procedures).toContain("generateTemplate");
    expect(procedures).toContain("listTemplates");
    expect(procedures).toContain("getTemplate");
    expect(procedures).toContain("updateTemplateStatus");
    expect(procedures).toContain("listExploits");
    expect(procedures).toContain("getExploitByCve");
    expect(procedures).toContain("learnerStats");
    expect(procedures).toContain("dashboardStats");
    // New procedures
    expect(procedures).toContain("findSimilarIncidents");
    expect(procedures).toContain("findSimilarTemplates");
  });
});

describe("Schema Tables for Threat Intel Training", () => {
  it("incidentReports should have attackSequence field for TTP matching", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.incidentReports;
    // Verify the column exists by checking the table's column names
    const columns = Object.keys(table);
    expect(columns).toContain("attackSequence");
    expect(columns).toContain("ttpsExtracted");
    expect(columns).toContain("actorsIdentified");
    expect(columns).toContain("targetSectors");
    expect(columns).toContain("attackNarrative");
  });

  it("attackSequenceTemplates should have phases and calderaAbilities for matching", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.attackSequenceTemplates;
    const columns = Object.keys(table);
    expect(columns).toContain("phases");
    expect(columns).toContain("calderaAbilities");
    expect(columns).toContain("attackType");
    expect(columns).toContain("complexity");
    expect(columns).toContain("commonDetections");
  });

  it("campaignAbilities should have technique field for TTP extraction", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.campaignAbilities;
    const columns = Object.keys(table);
    expect(columns).toContain("technique");
    expect(columns).toContain("tactic");
    expect(columns).toContain("abilityName");
  });
});

describe("AppShell Navigation - Training Dashboard", () => {
  it("should include training-dashboard route in sidebar navigation", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appShellPath = path.resolve(__dirname, "../client/src/components/AppShell.tsx");
    const content = fs.readFileSync(appShellPath, "utf-8");
    expect(content).toContain("/training-dashboard");
    expect(content).toContain("TRAINING");
  });

  it("training-dashboard route should be in the reports & knowledge nav group", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appShellPath = path.resolve(__dirname, "../client/src/components/AppShell.tsx");
    const content = fs.readFileSync(appShellPath, "utf-8");
    // After sidebar reorganization, training-dashboard is in REPORTS & KNOWLEDGE group
    const reportsIdx = content.indexOf('"REPORTS & KNOWLEDGE"');
    const platformIdx = content.indexOf('"PLATFORM"');
    const trainingIdx = content.indexOf("/training-dashboard");
    expect(reportsIdx).toBeGreaterThan(-1);
    expect(platformIdx).toBeGreaterThan(-1);
    expect(trainingIdx).toBeGreaterThan(reportsIdx);
    expect(trainingIdx).toBeLessThan(platformIdx);
  });
});

describe("App.tsx Route Registration", () => {
  it("should have training-dashboard route registered", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const appPath = path.resolve(__dirname, "../client/src/App.tsx");
    const content = fs.readFileSync(appPath, "utf-8");
    expect(content).toContain("/training-dashboard");
    expect(content).toContain("TrainingDashboard");
  });
});

describe("Campaign Wizard - Attack Template Picker", () => {
  it("should include AttackTemplatePicker component in CampaignWizard", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("AttackTemplatePicker");
    expect(content).toContain("ATTACK TEMPLATE LIBRARY");
  });

  it("should query listTemplates with production status filter", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain('threatIntelTraining.listTemplates.useQuery');
    expect(content).toContain('"production"');
  });

  it("should display template phases when selected", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("ATTACK PHASES");
    expect(content).toContain("COMMON DETECTIONS");
  });

  it("should be placed in Step 1 after OSINT panel", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    const osintIdx = content.indexOf("OsintFindingsPanel");
    const templateIdx = content.indexOf("AttackTemplatePicker");
    // AttackTemplatePicker should appear after OsintFindingsPanel reference
    expect(templateIdx).toBeGreaterThan(osintIdx);
  });

  it("should import Brain icon for the template picker", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("Brain");
  });
});

describe("Campaign Detail - Similar Attacks Panel", () => {
  it("should include SimilarAttacksPanel component in CampaignDetail", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const detailPath = path.resolve(__dirname, "../client/src/pages/CampaignDetail.tsx");
    const content = fs.readFileSync(detailPath, "utf-8");
    expect(content).toContain("SimilarAttacksPanel");
    expect(content).toContain("SIMILAR REAL-WORLD ATTACKS");
  });

  it("should query findSimilarIncidents with campaign techniques", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const detailPath = path.resolve(__dirname, "../client/src/pages/CampaignDetail.tsx");
    const content = fs.readFileSync(detailPath, "utf-8");
    expect(content).toContain("threatIntelTraining.findSimilarIncidents.useQuery");
    expect(content).toContain("threatIntelTraining.findSimilarTemplates.useQuery");
  });

  it("should extract techniques from campaign abilities", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const detailPath = path.resolve(__dirname, "../client/src/pages/CampaignDetail.tsx");
    const content = fs.readFileSync(detailPath, "utf-8");
    // Should extract technique IDs from abilities
    expect(content).toContain("a.technique");
    expect(content).toContain("techniques");
  });

  it("should display relevance scores for matching incidents", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const detailPath = path.resolve(__dirname, "../client/src/pages/CampaignDetail.tsx");
    const content = fs.readFileSync(detailPath, "utf-8");
    expect(content).toContain("relevanceScore");
    expect(content).toContain("matchingTechniques");
  });

  it("should show matching attack templates section", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const detailPath = path.resolve(__dirname, "../client/src/pages/CampaignDetail.tsx");
    const content = fs.readFileSync(detailPath, "utf-8");
    expect(content).toContain("MATCHING ATTACK TEMPLATES");
    expect(content).toContain("MATCHING INCIDENT REPORTS");
  });

  it("should pass abilities prop from campaign data", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const detailPath = path.resolve(__dirname, "../client/src/pages/CampaignDetail.tsx");
    const content = fs.readFileSync(detailPath, "utf-8");
    expect(content).toContain("abilities={campaign?.abilities");
  });

  it("should handle empty techniques gracefully (return null)", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const detailPath = path.resolve(__dirname, "../client/src/pages/CampaignDetail.tsx");
    const content = fs.readFileSync(detailPath, "utf-8");
    expect(content).toContain("techniques.length === 0");
    expect(content).toContain("return null");
  });
});

describe("Apply Template to Campaign", () => {
  it("should have applyTemplateToCampaign procedure on threatIntelTraining router", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procedures = Object.keys(routerDef.procedures || routerDef.record || {});
    expect(procedures).toContain("applyTemplateToCampaign");
  });

  it("applyTemplateToCampaign should be a mutation (not query)", async () => {
    const mod = await import("./routers/threat-intel-training");
    const routerDef = mod.threatIntelTrainingRouter._def;
    const procs = routerDef.procedures || routerDef.record || {};
    const proc = procs["applyTemplateToCampaign"] as any;
    expect(proc).toBeDefined();
    expect(proc._def?.type || proc._type).toBe("mutation");
  });

  it("CampaignWizard should have selectedAttackTemplateId state", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("selectedAttackTemplateId");
    expect(content).toContain("setSelectedAttackTemplateId");
  });

  it("CampaignWizard should use applyTemplateToCampaign mutation", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("applyTemplateToCampaign.useMutation");
  });

  it("CampaignWizard should create internal campaign when template selected", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("createInternalCampaign.mutateAsync");
    expect(content).toContain("applyTemplateMutation.mutateAsync");
  });

  it("CampaignWizard should pass selectedAttackTemplateId to AttackTemplatePicker", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("selectedAttackTemplateId={selectedAttackTemplateId}");
    expect(content).toContain("onSelectTemplate={setSelectedAttackTemplateId}");
  });

  it("CampaignWizard review step should show AttackTemplateSummary when template selected", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("AttackTemplateSummary");
    expect(content).toContain("ATTACK TEMPLATE WILL BE APPLIED");
  });

  it("AttackTemplateSummary should show technique count and tactics", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("totalTechniques");
    expect(content).toContain("abilities will be auto-populated");
  });

  it("AttackTemplatePicker should accept props for controlled selection", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const wizardPath = path.resolve(__dirname, "../client/src/pages/CampaignWizard.tsx");
    const content = fs.readFileSync(wizardPath, "utf-8");
    expect(content).toContain("selectedAttackTemplateId: number | null");
    expect(content).toContain("onSelectTemplate: (id: number | null) => void");
  });
});

describe("Training Dashboard Page", () => {
  it("should exist as a page component", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const dashPath = path.resolve(__dirname, "../client/src/pages/TrainingDashboard.tsx");
    expect(fs.existsSync(dashPath)).toBe(true);
  });

  it("should use threatIntelTraining tRPC procedures", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const dashPath = path.resolve(__dirname, "../client/src/pages/TrainingDashboard.tsx");
    const content = fs.readFileSync(dashPath, "utf-8");
    expect(content).toContain("threatIntelTraining");
    expect(content).toContain("dashboardStats");
  });

  it("should have tab-based navigation (overview, reports, templates, exploits)", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const dashPath = path.resolve(__dirname, "../client/src/pages/TrainingDashboard.tsx");
    const content = fs.readFileSync(dashPath, "utf-8");
    expect(content).toContain("overview");
    expect(content).toContain("reports");
    expect(content).toContain("templates");
    expect(content).toContain("exploits");
  });

  it("should include ingestion controls", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const dashPath = path.resolve(__dirname, "../client/src/pages/TrainingDashboard.tsx");
    const content = fs.readFileSync(dashPath, "utf-8");
    expect(content).toContain("ingestAll");
  });
});
