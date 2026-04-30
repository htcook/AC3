/**
 * AI Vulnerability Research Module — Tests
 *
 * Tests cover:
 *   1. Router structure: all expected procedures exist
 *   2. Schema: database table definitions for ai_vuln_research_*
 *   3. UI integration: tab registered in BugBountyHub
 *   4. System prompt construction and analysis flow
 *   5. Reports page fixes: engagement filter includes 'planning' status
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const ROOT = path.resolve(__dirname, "..");

// ─── Router Structure Tests ─────────────────────────────────────────────────

// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("AI Vuln Research Router", () => {
  it("exports aiVulnResearchRouter with all expected procedures", async () => {
    const mod = await import("./routers/ai-vuln-research");
    expect(mod.aiVulnResearchRouter).toBeDefined();
    const router = mod.aiVulnResearchRouter;
    const procedureNames = Object.keys(router);

    // Session management
    expect(procedureNames).toContain("listSessions");
    expect(procedureNames).toContain("getSession");
    expect(procedureNames).toContain("deleteSession");

    // Analysis
    expect(procedureNames).toContain("startResearch");
    expect(procedureNames).toContain("generatePoc");

    // Bug Bounty integration
    expect(procedureNames).toContain("exportToBugBounty");
    expect(procedureNames).toContain("toggleVerified");

    // GitHub integration
    expect(procedureNames).toContain("fetchGithubTree");

    // Stats
    expect(procedureNames).toContain("stats");
  });

  it("has at least 10 procedures covering full research lifecycle", async () => {
    const mod = await import("./routers/ai-vuln-research");
    const procedureNames = Object.keys(mod.aiVulnResearchRouter);
    expect(procedureNames.length).toBeGreaterThanOrEqual(10);
  });
});

// ─── Schema Tests ───────────────────────────────────────────────────────────
describe("AI Vuln Research Schema", () => {
  const schemaPath = path.join(ROOT, "drizzle", "schema.ts");
  const schemaContent = fs.readFileSync(schemaPath, "utf-8");

  it("defines aiVulnResearchSessions table", () => {
    expect(schemaContent).toContain("aiVulnResearchSessions");
    expect(schemaContent).toContain("ai_vuln_research_sessions");
  });

  it("defines aiVulnResearchFindings table", () => {
    expect(schemaContent).toContain("aiVulnResearchFindings");
    expect(schemaContent).toContain("ai_vuln_research_findings");
  });

  it("defines aiVulnResearchCodeSnippets table", () => {
    expect(schemaContent).toContain("aiVulnResearchCodeSnippets");
    expect(schemaContent).toContain("ai_vuln_research_code_snippets");
  });

  it("sessions table has required columns", () => {
    expect(schemaContent).toMatch(/varchar.*target_name/);
    expect(schemaContent).toMatch(/target_type/);
    expect(schemaContent).toMatch(/research_prompt/);
    expect(schemaContent).toMatch(/pending.*analyzing.*completed/);
  });

  it("findings table has severity and vulnerability type columns", () => {
    expect(schemaContent).toMatch(/varchar.*vuln_type/);
    expect(schemaContent).toMatch(/severity.*critical.*high.*medium.*low/);
    expect(schemaContent).toMatch(/poc_code/);
    expect(schemaContent).toMatch(/cvss_score/);
  });
});

// ─── UI Integration Tests ───────────────────────────────────────────────────
describe("Bug Bounty Hub Integration", () => {
  const hubPath = path.join(ROOT, "client", "src", "pages", "BugBountyHub.tsx");
  const hubContent = fs.readFileSync(hubPath, "utf-8");

  it("has AI Vuln Research tab trigger", () => {
    expect(hubContent).toContain('value="ai-vuln-research"');
  });

  it("imports AIVulnResearchTab component", () => {
    expect(hubContent).toContain("AIVulnResearchTab");
  });

  it("renders AIVulnResearchTab in TabsContent", () => {
    expect(hubContent).toContain("<AIVulnResearchTab");
  });
});

describe("AI Vuln Research Tab Component", () => {
  const tabPath = path.join(ROOT, "client", "src", "pages", "bug-bounty", "AIVulnResearchTab.tsx");

  it("component file exists", () => {
    expect(fs.existsSync(tabPath)).toBe(true);
  });

  it("exports AIVulnResearchTab component", () => {
    const content = fs.readFileSync(tabPath, "utf-8");
    expect(content).toContain("export function AIVulnResearchTab");
  });

  it("uses tRPC hooks for data fetching", () => {
    const content = fs.readFileSync(tabPath, "utf-8");
    expect(content).toContain("trpc.aiVulnResearch");
  });

  it("has code input area for analysis", () => {
    const content = fs.readFileSync(tabPath, "utf-8");
    expect(content).toMatch(/textarea|code.*input|sourceCode|codeInput/i);
  });
});

// ─── Router Registration Tests ──────────────────────────────────────────────
describe("Router Registration", () => {
  const routersPath = path.join(ROOT, "server", "routers.ts");
  const routersContent = fs.readFileSync(routersPath, "utf-8");

  it("imports aiVulnResearchRouter", () => {
    expect(routersContent).toContain("aiVulnResearchRouter");
  });

  it("registers aiVulnResearch in appRouter", () => {
    expect(routersContent).toContain("aiVulnResearch:");
  });
});

// ─── Reports Page Fix Tests ─────────────────────────────────────────────────
describe("Reports Page Fixes", () => {
  const reportGenPath = path.join(ROOT, "client", "src", "pages", "ReportGenerator.tsx");
  const reportContent = fs.readFileSync(reportGenPath, "utf-8");

  it("engagement filter includes planning status", () => {
    expect(reportContent).toContain("'planning'");
    // The filter should include active, completed, AND planning
    expect(reportContent).toMatch(/status\s*===\s*['"]active['"]/);
    expect(reportContent).toMatch(/status\s*===\s*['"]completed['"]/);
    expect(reportContent).toMatch(/status\s*===\s*['"]planning['"]/);
  });

  it("shows indicator for orphaned reports with no reportUrl", () => {
    expect(reportContent).toContain("!report.reportUrl");
    expect(reportContent).toContain("No Content");
  });
});

// ─── Performance Fix Tests ──────────────────────────────────────────────────
describe("Performance Fixes", () => {
  it("fetchCalderaAPI has reduced timeout (<=30s)", () => {
    const helpersPath = path.join(ROOT, "server", "lib", "api-helpers.ts");
    const content = fs.readFileSync(helpersPath, "utf-8");
    // Should have a timeout of <=15000ms, not 30000
    expect(content).not.toContain("timeout: 30000");
    // AbortSignal.timeout pattern with reasonable timeout
    expect(content).toMatch(/AbortSignal\.timeout\(\d+\)/);
  });

  it("fetchCalderaAPI does not use excessively long timeouts", () => {
    const helpersPath = path.join(ROOT, "server", "lib", "api-helpers.ts");
    const content = fs.readFileSync(helpersPath, "utf-8");
    // Should not have timeout >= 30s
    expect(content).not.toContain("timeout: 30000");
    expect(content).not.toContain("timeout: 60000");
  });

  it("rate limiter allows at least 400 requests per minute", () => {
    const rateLimiterPath = path.join(ROOT, "server", "lib", "rate-limiter.ts");
    const content = fs.readFileSync(rateLimiterPath, "utf-8");
    // Should have max >= 400 for the main API limiter (not the auth limiter)
    const allMaxMatches = [...content.matchAll(/max:\s*(\d+)/g)];
    const maxValues = allMaxMatches.map(m => parseInt(m[1]));
    // At least one limiter should allow >= 400 req/min
    expect(maxValues.some(v => v >= 400)).toBe(true);
  });
});
