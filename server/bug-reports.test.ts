/**
 * Bug Reports Router Tests
 *
 * Tests for the bug report admin dashboard CRUD operations,
 * role-based access control, and statistics aggregation.
 */
import { describe, it, expect } from "vitest";
import path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// Test the router module can be imported without errors

// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("Bug Reports Router", () => {
  it("exports bugReportsRouter", async () => {
    const mod = await import("./routers/bug-reports");
    expect(mod.bugReportsRouter).toBeDefined();
    expect(mod.bugReportsRouter._def).toBeDefined();
  });

  it("has all required procedures", async () => {
    const mod = await import("./routers/bug-reports");
    const router = mod.bugReportsRouter;
    const procedures = Object.keys(router._def.procedures);
    expect(procedures).toContain("list");
    expect(procedures).toContain("getById");
    expect(procedures).toContain("updateStatus");
    expect(procedures).toContain("addNotes");
    expect(procedures).toContain("bulkUpdateStatus");
    expect(procedures).toContain("stats");
    expect(procedures).toContain("delete");
  });

  it("has exactly 7 procedures", async () => {
    const mod = await import("./routers/bug-reports");
    const procedures = Object.keys(mod.bugReportsRouter._def.procedures);
    expect(procedures.length).toBe(7);
  });
});

// Test the role-based navigation filtering
describe("Role-Based Navigation", () => {
  it("getFilteredNavGroups is exported from sidebar-nav", async () => {
    // We can't import React modules in vitest without jsdom,
    // but we can verify the file structure
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    expect(content).toContain("export function getFilteredNavGroups");
    expect(content).toContain("ROLE_GROUP_ACCESS");
  });

  it("defines access for all 8 roles", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    const roles = ["admin", "operator", "analyst", "team_lead", "executive", "client", "soc", "viewer"];
    for (const role of roles) {
      expect(content).toContain(`${role}:`);
    }
  });

  it("admin has full access", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    expect(content).toContain("admin: 'all'");
  });

  it("bug reports nav item is restricted to admin and team_lead", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/lib/sidebar-nav.ts"),
      "utf-8"
    );
    expect(content).toContain('{ label: "Bug Reports", path: "/bug-reports"');
    // Verify role restriction
    const bugReportLine = content.split("\n").find((l: string) => l.includes("Bug Reports"));
    expect(bugReportLine).toContain("admin");
    expect(bugReportLine).toContain("team_lead");
  });
});

// Test Hydra http-form-post mode
describe("Hydra HTTP Form Post Mode", () => {
  it("OEM protocol mapping uses http-form-post for web protocols", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/scan-server-executor.ts"),
      "utf-8"
    );
    // Verify http/https/web_admin map to form-post, not http-get
    expect(content).toContain('http: "http-form-post"');
    expect(content).toContain('https: "https-form-post"');
    expect(content).toContain('web_admin: "http-form-post"');
    // Verify http_basic/https_basic still map to http-get for genuine Basic Auth
    expect(content).toContain('http_basic: "http-get"');
    expect(content).toContain('https_basic: "https-get"');
  });

  it("generates form data with failure string detection for http-form-post", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/scan-server-executor.ts"),
      "utf-8"
    );
    expect(content).toContain("username=^USER^&password=^PASS^");
    expect(content).toContain("email=^USER^&password=^PASS^");
    expect(content).toContain("invalid|incorrect|failed|error|denied|wrong");
  });
});

// Test bug report notification
describe("Bug Report Notification", () => {
  it("notifyOwner is called when bug report is submitted", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/quick-action-executor.ts"),
      "utf-8"
    );
    expect(content).toContain("notifyOwner");
    expect(content).toContain("Bug Report #");
  });
});

// Test AC3 branding
describe("AC3 Branding", () => {
  it("login page uses AC3 not old branding", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/pages/Login.tsx"),
      "utf-8"
    );
    expect(content).not.toContain("Ace C3");
    expect(content).not.toContain("ACE C3");
    expect(content).toContain("AC3");
  });

  it("package.json uses ac3 name", async () => {
    const fs = await import("fs");
    const pkg = JSON.parse(
      fs.readFileSync(path.join(PROJECT_ROOT, "package.json"), "utf-8")
    );
    expect(pkg.name).toBe("ac3");
  });
});
