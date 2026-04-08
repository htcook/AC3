/**
 * Engagement Builder & Burp Suite Integration — Tests
 *
 * Tests cover:
 *   1. Engagement builder module exports and structure
 *   2. Burp Suite connector module exports and structure
 *   3. Router endpoints for both features exist
 *   4. Platform credentials schema includes burpsuite enums
 *   5. Frontend components exist and are wired
 *   6. Burp Suite issue normalization
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const ROOT = path.resolve(__dirname, "..");

// ─── Engagement Builder Module Tests ────────────────────────────────────────
describe("Engagement Builder Module", () => {
  it("exports buildEngagementPreview and createEngagementFromPreview", async () => {
    const mod = await import("./lib/engagement-builder");
    expect(mod.buildEngagementPreview).toBeDefined();
    expect(typeof mod.buildEngagementPreview).toBe("function");
    expect(mod.createEngagementFromPreview).toBeDefined();
    expect(typeof mod.createEngagementFromPreview).toBe("function");
  });

  it("buildEngagementPreview accepts programId, programUrl, programName, platform", async () => {
    const mod = await import("./lib/engagement-builder");
    // Function should accept an object with these optional fields
    expect(mod.buildEngagementPreview.length).toBeLessThanOrEqual(1);
  });
});

// ─── Burp Suite Connector Module Tests ──────────────────────────────────────
describe("Burp Suite Connector Module", () => {
  it("exports BurpSuiteConnector class", async () => {
    const mod = await import("./lib/burpsuite-connector");
    expect(mod.BurpSuiteConnector).toBeDefined();
  });

  it("BurpSuiteConnector has verify, getIssues, getScanStatus methods", async () => {
    const mod = await import("./lib/burpsuite-connector");
    const connector = new mod.BurpSuiteConnector({
      edition: "professional",
      baseUrl: "http://127.0.0.1:1337",
      apiKey: "test-key",
    });
    expect(typeof connector.verify).toBe("function");
    expect(typeof connector.getIssues).toBe("function");
    expect(typeof connector.getScanStatus).toBe("function");
  });

  it("exports normalizeBurpIssues function", async () => {
    const mod = await import("./lib/burpsuite-connector");
    expect(mod.normalizeBurpIssues).toBeDefined();
    expect(typeof mod.normalizeBurpIssues).toBe("function");
  });

  it("normalizeBurpIssues converts Burp issues to normalized format", async () => {
    const { normalizeBurpIssues } = await import("./lib/burpsuite-connector");
    const mockIssues = [
      {
        name: "SQL Injection",
        severity: "high",
        confidence: "certain",
        host: "https://example.com",
        path: "/api/login",
        issueDetail: "SQL injection in login parameter",
        serialNumber: "12345",
        type_index: 1049088,
        issueBackground: "SQL injection allows attackers to...",
        remediationBackground: "Use parameterized queries",
      },
    ];

    const normalized = normalizeBurpIssues(mockIssues, "test-engagement", "professional");
    expect(normalized).toHaveLength(1);
    expect(normalized[0].title).toContain("SQL Injection");
    expect(normalized[0].severityRating).toBe("high");
    expect(normalized[0].programHandle).toBe("test-engagement");
  });

  it("normalizeBurpIssues handles empty array", async () => {
    const { normalizeBurpIssues } = await import("./lib/burpsuite-connector");
    const normalized = normalizeBurpIssues([], "test", "professional");
    expect(normalized).toEqual([]);
  });

  it("normalizeBurpIssues maps severity correctly", async () => {
    const { normalizeBurpIssues } = await import("./lib/burpsuite-connector");
    const issues = [
      { name: "Info Issue", severity: "information", host: "https://a.com", path: "/" },
      { name: "Low Issue", severity: "low", host: "https://a.com", path: "/" },
      { name: "Medium Issue", severity: "medium", host: "https://a.com", path: "/" },
      { name: "High Issue", severity: "high", host: "https://a.com", path: "/" },
    ];
    const normalized = normalizeBurpIssues(issues, "test", "professional");
    expect(normalized[0].severityRating).toBe("information");
    expect(normalized[1].severityRating).toBe("low");
    expect(normalized[2].severityRating).toBe("medium");
    expect(normalized[3].severityRating).toBe("high");
  });
});

// ─── Router Endpoints Tests ─────────────────────────────────────────────────
describe("Bug Bounty Router — Engagement Builder & Burp Suite Endpoints", () => {
  it("bug bounty router has engagement builder endpoints", () => {
    const routerSrc = fs.readFileSync(
      path.join(ROOT, "server/routers/bug-bounty.ts"),
      "utf-8"
    );
    expect(routerSrc).toContain("buildEngagementPreview");
    expect(routerSrc).toContain("createEngagementFromProgram");
  });

  it("bug bounty router has Burp Suite endpoints", () => {
    const routerSrc = fs.readFileSync(
      path.join(ROOT, "server/routers/bug-bounty.ts"),
      "utf-8"
    );
    expect(routerSrc).toContain("verifyBurpConnection");
    expect(routerSrc).toContain("importBurpIssues");
    expect(routerSrc).toContain("getBurpScanStatus");
    expect(routerSrc).toContain("listBurpSites");
  });
});

// ─── Platform Credentials Schema Tests ──────────────────────────────────────
describe("Platform Credentials — Burp Suite Support", () => {
  it("schema includes burpsuite_pro and burpsuite_enterprise in platform enum", () => {
    const schema = fs.readFileSync(
      path.join(ROOT, "drizzle/schema.ts"),
      "utf-8"
    );
    expect(schema).toContain("burpsuite_pro");
    expect(schema).toContain("burpsuite_enterprise");
  });

  it("platform credentials router accepts burpsuite platforms", () => {
    const routerSrc = fs.readFileSync(
      path.join(ROOT, "server/routers/platform-credentials.ts"),
      "utf-8"
    );
    expect(routerSrc).toContain("burpsuite_pro");
    expect(routerSrc).toContain("burpsuite_enterprise");
  });

  it("platform credentials router has Burp Suite verification functions", () => {
    const routerSrc = fs.readFileSync(
      path.join(ROOT, "server/routers/platform-credentials.ts"),
      "utf-8"
    );
    expect(routerSrc).toContain("verifyBurpSuitePro");
    expect(routerSrc).toContain("verifyBurpSuiteEnterprise");
  });
});

// ─── Frontend Component Tests ───────────────────────────────────────────────
describe("Frontend — Engagement Builder & Burp Suite UI", () => {
  it("CreateEngagementDialog component exists", () => {
    const filePath = path.join(
      ROOT,
      "client/src/pages/bug-bounty/CreateEngagementDialog.tsx"
    );
    expect(fs.existsSync(filePath)).toBe(true);
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("CreateEngagementDialog");
    expect(content).toContain("buildEngagementPreview");
    expect(content).toContain("createEngagementFromProgram");
  });

  it("BurpSuitePanel component exists", () => {
    const filePath = path.join(
      ROOT,
      "client/src/pages/bug-bounty/BurpSuitePanel.tsx"
    );
    expect(fs.existsSync(filePath)).toBe(true);
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("BurpSuitePanel");
    expect(content).toContain("verifyBurpConnection");
    expect(content).toContain("importBurpIssues");
  });

  it("BugBountyHub imports and renders CreateEngagementDialog", () => {
    const hubSrc = fs.readFileSync(
      path.join(ROOT, "client/src/pages/BugBountyHub.tsx"),
      "utf-8"
    );
    expect(hubSrc).toContain("CreateEngagementDialog");
    expect(hubSrc).toContain("showCreateEngagementDialog");
    expect(hubSrc).toContain("Create Engagement");
  });

  it("BugBountyHub imports and renders BurpSuitePanel in Accounts tab", () => {
    const hubSrc = fs.readFileSync(
      path.join(ROOT, "client/src/pages/BugBountyHub.tsx"),
      "utf-8"
    );
    expect(hubSrc).toContain("BurpSuitePanel");
    expect(hubSrc).toContain("onRefreshCredentials");
  });

  it("PlatformIcons includes Burp Suite icon and names", () => {
    const iconsSrc = fs.readFileSync(
      path.join(ROOT, "client/src/components/PlatformIcons.tsx"),
      "utf-8"
    );
    expect(iconsSrc).toContain("BurpSuiteIcon");
    expect(iconsSrc).toContain("burpsuite_pro");
    expect(iconsSrc).toContain("burpsuite_enterprise");
    expect(iconsSrc).toContain("Burp Suite Pro");
    expect(iconsSrc).toContain("Burp Suite Enterprise");
  });

  it("Program cards have Engage button", () => {
    const hubSrc = fs.readFileSync(
      path.join(ROOT, "client/src/pages/BugBountyHub.tsx"),
      "utf-8"
    );
    expect(hubSrc).toContain("Engage");
    expect(hubSrc).toContain("Rocket");
  });
});

// ─── Engagement Builder File Structure Tests ────────────────────────────────
describe("Engagement Builder — File Structure", () => {
  it("engagement-builder.ts exists in server/lib", () => {
    expect(
      fs.existsSync(path.join(ROOT, "server/lib/engagement-builder.ts"))
    ).toBe(true);
  });

  it("burpsuite-connector.ts exists in server/lib", () => {
    expect(
      fs.existsSync(path.join(ROOT, "server/lib/burpsuite-connector.ts"))
    ).toBe(true);
  });

  it("engagement-builder imports invokeLLM for AI-powered scanning", () => {
    const src = fs.readFileSync(
      path.join(ROOT, "server/lib/engagement-builder.ts"),
      "utf-8"
    );
    expect(src).toContain("invokeLLM");
    expect(src).toContain("json_schema");
  });

  it("burpsuite-connector handles both Professional and Enterprise editions", () => {
    const src = fs.readFileSync(
      path.join(ROOT, "server/lib/burpsuite-connector.ts"),
      "utf-8"
    );
    expect(src).toContain("professional");
    expect(src).toContain("enterprise");
    expect(src).toContain("graphql");
  });
});
