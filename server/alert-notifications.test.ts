/**
 * Tests for Alert Threshold Seeding, Notification Bell, Alert Sweep,
 * and Dependabot vulnerability fixes.
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ─── Alert Threshold Seeding ─────────────────────────────────────────────────

describe("Alert Threshold Seeding", () => {
  it("seed-alert-thresholds.ts exists and exports seedDefaultAlertThresholds", () => {
    const filePath = path.join(PROJECT_ROOT, "server/lib/seed-alert-thresholds.ts");
    expect(fs.existsSync(filePath)).toBe(true);
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function seedDefaultAlertThresholds");
  });

  it("seed function queries completed domain intel scans", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/seed-alert-thresholds.ts"),
      "utf-8"
    );
    expect(content).toContain("domainIntelScans");
    expect(content).toContain("completed");
  });

  it("seed function creates global catch-all threshold", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/seed-alert-thresholds.ts"),
      "utf-8"
    );
    expect(content).toContain("Global");
    expect(content).toContain("Critical Threat Monitor");
  });

  it("seed function avoids duplicate thresholds", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/seed-alert-thresholds.ts"),
      "utf-8"
    );
    expect(content).toContain("existingScanIds");
    expect(content).toContain("skipped");
  });

  it("seed function adjusts threshold based on risk score", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/seed-alert-thresholds.ts"),
      "utf-8"
    );
    expect(content).toContain("riskScore >= 70");
    expect(content).toContain("relevanceThreshold");
  });

  it("seedAlertThresholds procedure is registered in executive-dashboard router", () => {
    const routerContent = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/executive-dashboard.ts"),
      "utf-8"
    );
    expect(routerContent).toContain("seedAlertThresholds:");
    expect(routerContent).toContain("seedDefaultAlertThresholds");
  });
});

// ─── Notification Bell ───────────────────────────────────────────────────────

describe("Notification Bell Component", () => {
  it("NotificationBell.tsx exists", () => {
    const filePath = path.join(
      PROJECT_ROOT,
      "client/src/components/NotificationBell.tsx"
    );
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("NotificationBell uses trpc.executiveDashboard.recentAlerts query", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/components/NotificationBell.tsx"),
      "utf-8"
    );
    expect(content).toContain("executiveDashboard.recentAlerts");
  });

  it("NotificationBell has dismiss functionality", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/components/NotificationBell.tsx"),
      "utf-8"
    );
    expect(content).toContain("dismissAlert");
    expect(content).toContain("dismissAllAlerts");
  });

  it("NotificationBell shows unread count badge", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/components/NotificationBell.tsx"),
      "utf-8"
    );
    expect(content).toContain("unreadCount");
    expect(content).toContain("bg-red-500");
  });

  it("NotificationBell is imported in DashboardLayout", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/components/DashboardLayout.tsx"),
      "utf-8"
    );
    expect(content).toContain("NotificationBell");
    expect(content).toContain("./NotificationBell");
  });

  it("NotificationBell is rendered in both rail and expanded sidebar modes", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/components/DashboardLayout.tsx"),
      "utf-8"
    );
    // Should appear in rail mode (collapsed)
    expect(content).toContain("<NotificationBell collapsed />");
    // Should appear in expanded mode
    expect(content).toContain("<NotificationBell />");
  });

  it("NotificationBell navigates to dashboard on alert click", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/components/NotificationBell.tsx"),
      "utf-8"
    );
    expect(content).toContain("setLocation");
    expect(content).toContain('setLocation("/")');
  });

  it("NotificationBell polls for updates every 60 seconds", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/components/NotificationBell.tsx"),
      "utf-8"
    );
    expect(content).toContain("refetchInterval");
    expect(content).toContain("60_000");
  });
});

// ─── Alert Bell tRPC Procedures ──────────────────────────────────────────────

describe("Alert Bell tRPC Procedures", () => {
  it("recentAlerts procedure exists in executive-dashboard router", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/executive-dashboard.ts"),
      "utf-8"
    );
    expect(content).toContain("recentAlerts:");
    expect(content).toContain("threatAlertHistory");
  });

  it("dismissAlert procedure exists", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/executive-dashboard.ts"),
      "utf-8"
    );
    expect(content).toContain("dismissAlert:");
    expect(content).toContain("alertId");
  });

  it("dismissAllAlerts procedure exists", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/executive-dashboard.ts"),
      "utf-8"
    );
    expect(content).toContain("dismissAllAlerts:");
  });

  it("dismissed column exists in schema", () => {
    const schema = fs.readFileSync(
      path.join(PROJECT_ROOT, "drizzle/schema.ts"),
      "utf-8"
    );
    expect(schema).toContain('dismissed');
    expect(schema).toContain('tinyint("dismissed")');
  });
});

// ─── Scheduled Alert Sweep ───────────────────────────────────────────────────

describe("Scheduled Alert Sweep", () => {
  it("alert-sweep endpoint is registered in index.ts", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/_core/index.ts"),
      "utf-8"
    );
    expect(content).toContain("/api/scheduled/alert-sweep");
  });

  it("alert-sweep endpoint imports required modules", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/_core/index.ts"),
      "utf-8"
    );
    // Find the alert-sweep section
    const sweepIdx = content.indexOf("alert-sweep");
    const sweepSection = content.slice(sweepIdx, sweepIdx + 2000);
    expect(sweepSection).toContain("computeExecutiveThreatBriefing");
    expect(sweepSection).toContain("computeIocOverlap");
    expect(sweepSection).toContain("checkAlertThresholds");
  });

  it("alert-sweep processes all completed scans", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/_core/index.ts"),
      "utf-8"
    );
    const sweepIdx = content.indexOf("alert-sweep");
    const sweepSection = content.slice(sweepIdx, sweepIdx + 2000);
    expect(sweepSection).toContain("getRecentScansForBriefing");
    expect(sweepSection).toContain("for (const scan of scans)");
  });

  it("alert-sweep detects rising actors", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/_core/index.ts"),
      "utf-8"
    );
    const sweepIdx = content.indexOf("alert-sweep");
    const sweepSection = content.slice(sweepIdx, sweepIdx + 2000);
    expect(sweepSection).toContain("risingActors");
    expect(sweepSection).toContain("momentum");
  });

  it("seed-alert-thresholds endpoint is registered", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/_core/index.ts"),
      "utf-8"
    );
    expect(content).toContain("/api/scheduled/seed-alert-thresholds");
  });
});

// ─── Dependabot Vulnerability Fixes ──────────────────────────────────────────

describe("Dependabot Vulnerability Fixes", () => {
  const pkgJson = JSON.parse(
    fs.readFileSync(path.join(PROJECT_ROOT, "package.json"), "utf-8")
  );
  const overrides = pkgJson.pnpm?.overrides || {};

  it("protobufjs is overridden to >= 8.0.2", () => {
    expect(overrides.protobufjs).toBe(">=8.0.2");
  });

  it("basic-ftp is overridden to >= 5.3.1", () => {
    expect(overrides["basic-ftp"]).toBe(">=5.3.1");
  });

  it("fast-xml-builder is overridden to >= 1.1.7", () => {
    expect(overrides["fast-xml-builder"]).toBe(">=1.1.7");
  });

  it("ip-address is overridden to >= 10.1.1", () => {
    expect(overrides["ip-address"]).toBe(">=10.1.1");
  });

  it("@protobufjs/utf8 is overridden to >= 1.1.1", () => {
    expect(overrides["@protobufjs/utf8"]).toBe(">=1.1.1");
  });

  it("mermaid is updated to >= 11.15.0", () => {
    const mermaidDep = pkgJson.dependencies?.mermaid;
    expect(mermaidDep).toBeTruthy();
    // Should be ^11.15.0 or higher
    expect(mermaidDep).toMatch(/11\.15/);
  });

  it("lockfile has protobufjs >= 8.0.2", () => {
    const lockfile = fs.readFileSync(
      path.join(PROJECT_ROOT, "pnpm-lock.yaml"),
      "utf-8"
    );
    const match = lockfile.match(/protobufjs@(\d+\.\d+\.\d+)/);
    expect(match).toBeTruthy();
    const [major, minor, patch] = match![1].split(".").map(Number);
    expect(major).toBeGreaterThanOrEqual(8);
    if (major === 8) {
      expect(minor * 100 + patch).toBeGreaterThanOrEqual(2);
    }
  });

  it("lockfile has mermaid >= 11.15.0", () => {
    const lockfile = fs.readFileSync(
      path.join(PROJECT_ROOT, "pnpm-lock.yaml"),
      "utf-8"
    );
    const match = lockfile.match(/mermaid@(\d+\.\d+\.\d+)/);
    expect(match).toBeTruthy();
    const [major, minor] = match![1].split(".").map(Number);
    expect(major).toBeGreaterThanOrEqual(11);
    if (major === 11) {
      expect(minor).toBeGreaterThanOrEqual(15);
    }
  });
});

// ─── Threat Alert Engine Integration ─────────────────────────────────────────

describe("Threat Alert Engine", () => {
  it("threat-alert-engine.ts exports checkAlertThresholds", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/threat-alert-engine.ts"),
      "utf-8"
    );
    expect(content).toContain("export async function checkAlertThresholds");
  });

  it("threat-alert-engine.ts has 24h deduplication", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/threat-alert-engine.ts"),
      "utf-8"
    );
    expect(content).toContain("24 * 60 * 60 * 1000");
    expect(content).toContain("recentAlertKeys");
  });

  it("threat-alert-engine.ts fires notifyOwner", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/threat-alert-engine.ts"),
      "utf-8"
    );
    expect(content).toContain("notifyOwner");
    expect(content).toContain("Threat Alert:");
  });

  it("threat-alert-engine.ts records alert history", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/threat-alert-engine.ts"),
      "utf-8"
    );
    expect(content).toContain("threatAlertHistory");
    expect(content).toContain("insert");
  });
});
