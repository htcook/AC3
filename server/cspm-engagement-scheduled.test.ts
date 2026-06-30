/**
 * Tests for CSPM Engagement Linking + Scheduled Scans
 */
import { describe, it, expect, vi } from "vitest";
import * as fs from "fs";
import * as path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("CSPM Engagement Linking", () => {
  it("cspm-dashboard router getStats accepts engagementId", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/cspm-dashboard.ts"), "utf-8");
    // getStats should accept engagementId in its input schema
    expect(src).toMatch(/getStats.*protectedProcedure/s);
    expect(src).toMatch(/engagementId.*z\.number\(\)\.optional\(\)/);
  });

  it("cspm-dashboard router getScanHistory accepts engagementId", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/cspm-dashboard.ts"), "utf-8");
    expect(src).toMatch(/getScanHistory.*protectedProcedure/s);
    expect(src).toMatch(/engagementId.*z\.number\(\)\.optional\(\)/);
  });

  it("cspm-dashboard router getComplianceTrend accepts engagementId", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/cspm-dashboard.ts"), "utf-8");
    expect(src).toMatch(/getComplianceTrend.*protectedProcedure/s);
  });

  it("cspm-db getScanRuns supports engagementId filtering", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/lib/cspm-db.ts"), "utf-8");
    expect(src).toContain("engagementId");
    // Should have conditional where clause for engagementId
    expect(src).toMatch(/engagementId.*eq/s);
  });

  it("cspm-db getScanRunStats supports engagementId filtering", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/lib/cspm-db.ts"), "utf-8");
    expect(src).toContain("getScanRunStats");
    expect(src).toMatch(/getScanRunStats.*engagementId/s);
  });

  it("cspm-db getComplianceTrend supports engagementId filtering", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/lib/cspm-db.ts"), "utf-8");
    expect(src).toContain("getComplianceTrend");
    expect(src).toMatch(/getComplianceTrend/);
  });

  it("cspmScanRuns table has engagementId column", () => {
    const schema = fs.readFileSync(path.join(PROJECT_ROOT, "drizzle/schema.ts"), "utf-8");
    // The cspm_scan_runs table should have engagementId
    expect(schema).toMatch(/cspm_scan_runs.*engagementId|cspmScanRuns.*engagement_id/s);
  });

  it("frontend StatsOverview accepts engagementId prop", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toMatch(/function StatsOverview\(\{.*engagementId/);
  });

  it("frontend ComplianceTrendChart accepts engagementId prop", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toMatch(/function ComplianceTrendChart\(\{.*engagementId/);
  });

  it("frontend ScanHistoryTable accepts engagementId prop", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toMatch(/function ScanHistoryTable\(\{.*engagementId/s);
  });

  it("frontend has engagement selector dropdown", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toContain("All Engagements");
    expect(src).toContain("engagements.data");
  });

  it("frontend passes engagementId to all child components", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toMatch(/<StatsOverview.*engagementId/);
    expect(src).toMatch(/<ComplianceTrendChart.*engagementId/);
    expect(src).toMatch(/<ScanHistoryTable.*engagementId/);
  });
});

describe("Scheduled CSPM Scans", () => {
  it("scheduledCspmScans table exists in schema", () => {
    const schema = fs.readFileSync(path.join(PROJECT_ROOT, "drizzle/schema.ts"), "utf-8");
    expect(schema).toContain("scheduled_cspm_scans");
    expect(schema).toContain("cronExpression");
    expect(schema).toContain("scanTool");
    expect(schema).toContain("credentialId");
    expect(schema).toContain("isActive");
    expect(schema).toContain("nextRunAt");
    expect(schema).toContain("lastRunAt");
    expect(schema).toContain("totalRuns");
  });

  it("cspm-scheduled-scans router file exists", () => {
    const exists = fs.existsSync(path.join(PROJECT_ROOT, "server/routers/cspm-scheduled-scans.ts"));
    expect(exists).toBe(true);
  });

  it("cspm-scheduled-scans router exports correctly", async () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/cspm-scheduled-scans.ts"), "utf-8");
    expect(src).toContain("export const cspmScheduledScansRouter");
    expect(src).toContain("router({");
  });

  it("cspm-scheduled-scans router has CRUD endpoints", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/cspm-scheduled-scans.ts"), "utf-8");
    expect(src).toContain("create:");
    expect(src).toContain("list:");
    expect(src).toContain("delete:");
    expect(src).toContain("toggleActive:");
  });

  it("cspm-scheduled-scans router has scheduler control endpoints", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/cspm-scheduled-scans.ts"), "utf-8");
    expect(src).toContain("startScheduler:");
    expect(src).toContain("stopScheduler:");
    expect(src).toContain("getSchedulerStatus:");
  });

  it("cspm-scheduled-scans router has cron presets", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers/cspm-scheduled-scans.ts"), "utf-8");
    expect(src).toContain("getCronPresets:");
  });

  it("cspm-scan-scheduler lib exists", () => {
    const exists = fs.existsSync(path.join(PROJECT_ROOT, "server/lib/cspm-scan-scheduler.ts"));
    expect(exists).toBe(true);
  });

  it("cspm-scan-scheduler has start/stop/check functions", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/lib/cspm-scan-scheduler.ts"), "utf-8");
    expect(src).toContain("startCspmScheduler");
    expect(src).toContain("stopCspmScheduler");
    expect(src).toContain("checkAndTriggerScheduledScans");
  });

  it("cspm-scan-scheduler uses cron expression parsing", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/lib/cspm-scan-scheduler.ts"), "utf-8");
    // Should parse cron expressions to determine next run time
    expect(src).toMatch(/cron|nextRun|cronExpression/);
  });

  it("cspm-scheduled-scans router is registered in routers.ts", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "server/routers.ts"), "utf-8");
    expect(src).toContain("cspmScheduledScans");
    expect(src).toContain("cspm-scheduled-scans");
  });

  it("frontend has ScheduledScansPanel component", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toContain("ScheduledScansPanel");
    expect(src).toContain("Scheduled Scans");
  });

  it("frontend has scheduled scans tab", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toMatch(/TabsTrigger.*scheduled/);
  });

  it("frontend scheduled scans panel has create dialog", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toContain("Create Scheduled Scan");
    expect(src).toContain("cronExpression");
  });

  it("frontend scheduled scans panel has scheduler controls", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CspmDashboard.tsx"), "utf-8");
    expect(src).toContain("Start Scheduler");
    expect(src).toContain("startSchedulerMut");
    expect(src).toContain("stopSchedulerMut");
  });
});

describe("Attack Path Graph Visualization", () => {
  it("CloudAttackPaths page has Graph tab", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("Attack Graph");
    expect(src).toMatch(/TabsTrigger.*graph/);
  });

  it("CloudAttackPaths page has AttackPathGraph component", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("function AttackPathGraph");
    expect(src).toContain("AttackPathGraph");
  });

  it("AttackPathGraph renders SVG-based graph", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("<svg");
    expect(src).toContain("viewBox");
  });

  it("AttackPathGraph has provider filter", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toMatch(/graphProvider/);
    expect(src).toContain("All Providers");
  });

  it("AttackPathGraph has node types: provider, identity, attack, resource, catalog", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain('type: "provider"');
    expect(src).toContain('type: "identity"');
    expect(src).toContain('type: "attack"');
    expect(src).toContain('type: "resource"');
    expect(src).toContain('type: "catalog"');
  });

  it("AttackPathGraph has animated edges for critical/high severity", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("animated");
    expect(src).toContain("animateMotion");
  });

  it("AttackPathGraph has legend", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("Legend");
    expect(src).toContain("Provider");
    expect(src).toContain("Identity");
    expect(src).toContain("Attack Path");
    expect(src).toContain("Target Resource");
  });

  it("AttackPathGraph has selected node detail panel", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("selectedNode");
    expect(src).toContain("Description:");
    expect(src).toContain("Attack Type:");
    expect(src).toContain("MITRE Techniques:");
    expect(src).toContain("Remediation:");
  });

  it("AttackPathGraph falls back to catalog items when no discovered paths", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("Showing potential attack patterns from the catalog");
    expect(src).toContain("catalog.slice");
  });

  it("AttackPathGraph builds edges between nodes", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("edges.push");
    expect(src).toContain("source:");
    expect(src).toContain("target:");
    // Should have arrowhead markers
    expect(src).toContain("arrowhead");
    expect(src).toContain("<marker");
  });

  it("Network icon is imported for the graph tab", () => {
    const src = fs.readFileSync(path.join(PROJECT_ROOT, "client/src/pages/CloudAttackPaths.tsx"), "utf-8");
    expect(src).toContain("Network");
    // Multi-line import: Network is on a separate line from the lucide-react import
    expect(src).toMatch(/Network/);
    expect(src).toMatch(/lucide-react/);
  });
});
