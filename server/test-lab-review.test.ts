/**
 * Test Lab & Bug Bounty Review Tests
 * Verifies sidebar navigation wiring and TestLabDashboard data access
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const ROOT = path.resolve(__dirname, "..");

describe("Test Lab sidebar navigation", () => {
  const appShellPath = path.join(ROOT, "client/src/components/AppShell.tsx");
  const appShellContent = fs.readFileSync(appShellPath, "utf-8");

  it("should have Test Lab Dashboard in sidebar", () => {
    expect(appShellContent).toContain('href: "/test-lab"');
    expect(appShellContent).toContain('label: "TEST LAB DASHBOARD"');
  });

  it("should have Test Lab sub-pages in sidebar", () => {
    expect(appShellContent).toContain('href: "/test-lab/environments"');
    expect(appShellContent).toContain('href: "/test-lab/scenarios"');
    expect(appShellContent).toContain('href: "/test-lab/implant"');
    expect(appShellContent).toContain('href: "/test-lab/training"');
    expect(appShellContent).toContain('href: "/test-lab/graduation"');
  });

  it("should have Ember C2 Agent section in sidebar", () => {
    expect(appShellContent).toContain('href: "/ember"');
    expect(appShellContent).toContain('href: "/ember/deploy"');
    expect(appShellContent).toContain('href: "/ember/tasks"');
    expect(appShellContent).toContain('href: "/ember/payloads"');
    expect(appShellContent).toContain('href: "/ember/swarm"');
  });

  it("should have Bug Bounty Hub in sidebar", () => {
    expect(appShellContent).toContain('href: "/bug-bounty"');
    expect(appShellContent).toContain('label: "BUG BOUNTY HUB"');
  });
});

describe("Test Lab Dashboard data access", () => {
  const dashboardPath = path.join(ROOT, "client/src/pages/TestLabDashboard.tsx");
  const dashboardContent = fs.readFileSync(dashboardPath, "utf-8");

  it("should access stats from dashboard?.stats (not dashboard directly)", () => {
    expect(dashboardContent).toContain("const stats = dashboard?.stats;");
  });

  it("should access recentScenarioRuns from dashboard", () => {
    expect(dashboardContent).toContain("const recentScenarios = dashboard?.recentScenarioRuns;");
  });

  it("should access graduationSummary from dashboard", () => {
    expect(dashboardContent).toContain("const graduationSummary = dashboard?.graduationSummary;");
  });

  it("should use stats?.scenariosRun (not totalScenarios)", () => {
    expect(dashboardContent).toContain("stats?.scenariosRun");
    expect(dashboardContent).not.toContain("stats?.totalScenarios");
  });

  it("should use stats?.implantTestsRun (not totalImplantTests)", () => {
    expect(dashboardContent).toContain("stats?.implantTestsRun");
    expect(dashboardContent).not.toContain("stats?.totalImplantTests");
  });
});

describe("Test Lab routes in App.tsx", () => {
  const appPath = path.join(ROOT, "client/src/App.tsx");
  const appContent = fs.readFileSync(appPath, "utf-8");

  it("should have all 6 Test Lab routes", () => {
    expect(appContent).toContain('path="/test-lab"');
    expect(appContent).toContain('path="/test-lab/environments"');
    expect(appContent).toContain('path="/test-lab/scenarios"');
    expect(appContent).toContain('path="/test-lab/implant"');
    expect(appContent).toContain('path="/test-lab/training"');
    expect(appContent).toContain('path="/test-lab/graduation"');
  });

  it("should have Bug Bounty route", () => {
    expect(appContent).toContain('path="/bug-bounty"');
  });

  it("should have Ember routes", () => {
    expect(appContent).toContain('path="/ember"');
    expect(appContent).toContain('path="/ember/deploy"');
    expect(appContent).toContain('path="/ember/tasks"');
  });
});

describe("Test Lab backend router", () => {
  const routersPath = path.join(ROOT, "server/routers.ts");
  const routersContent = fs.readFileSync(routersPath, "utf-8");

  it("should register testLab router", () => {
    expect(routersContent).toContain("testLab: testLabRouter");
  });

  it("should register bugBounty router", () => {
    expect(routersContent).toContain("bugBounty: bugBountyRouter");
  });
});
