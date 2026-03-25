/**
 * Tests for Unified Findings tRPC procedures
 * Validates the unifiedFindings and unifiedFindingsStats queries
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

// ─── Read the router source to validate procedure structure ─────────────────

const routerSource = readFileSync(
  join(__dirname, "routers/web-app-scanning.ts"),
  "utf-8"
);

describe("Unified Findings — tRPC Procedures", () => {
  describe("unifiedFindings procedure", () => {
    it("should be defined in the web-app-scanning router", () => {
      expect(routerSource).toContain("unifiedFindings: protectedProcedure");
    });

    it("should accept severity filter", () => {
      expect(routerSource).toContain("severity: z.string().optional()");
    });

    it("should accept tool filter", () => {
      expect(routerSource).toContain("tool: z.string().optional()");
    });

    it("should accept mitreTactic filter", () => {
      expect(routerSource).toContain("mitreTactic: z.string().optional()");
    });

    it("should accept search filter", () => {
      expect(routerSource).toContain("search: z.string().optional()");
    });

    it("should accept scanId filter", () => {
      expect(routerSource).toContain("scanId: z.number().optional()");
    });

    it("should support pagination with limit and offset", () => {
      expect(routerSource).toContain("limit: z.number().min(1).max(500).default(200)");
      expect(routerSource).toContain("offset: z.number().min(0).default(0)");
    });

    it("should filter ZAP findings by numeric zapPluginId", () => {
      expect(routerSource).toContain("REGEXP '^[0-9]+$'");
    });

    it("should filter SQLMap findings by sqlmap- prefix", () => {
      expect(routerSource).toContain("like(webAppFindings.zapPluginId, 'sqlmap-%')");
    });

    it("should filter XSStrike/Dalfox findings by prefix", () => {
      expect(routerSource).toContain("LIKE 'xsstrike-%'");
      expect(routerSource).toContain("LIKE 'dalfox-%'");
    });

    it("should join with webAppScans for scan metadata", () => {
      expect(routerSource).toContain("leftJoin(webAppScans, eq(webAppFindings.scanId, webAppScans.id))");
    });

    it("should return total count for pagination", () => {
      expect(routerSource).toContain("return { findings, total, limit: input.limit, offset: input.offset }");
    });

    it("should include MITRE ATT&CK fields in the select", () => {
      expect(routerSource).toContain("mitreAttackId: webAppFindings.mitreAttackId");
      expect(routerSource).toContain("mitreAttackName: webAppFindings.mitreAttackName");
      expect(routerSource).toContain("mitreTactic: webAppFindings.mitreTactic");
    });

    it("should include exploit availability fields", () => {
      expect(routerSource).toContain("exploitAvailable: webAppFindings.exploitAvailable");
      expect(routerSource).toContain("exploitModulePath: webAppFindings.exploitModulePath");
    });

    it("should include AI triage fields", () => {
      expect(routerSource).toContain("aiTriageVerdict: webAppFindings.aiTriageVerdict");
      expect(routerSource).toContain("aiTriageReason: webAppFindings.aiTriageReason");
      expect(routerSource).toContain("falsePositiveScore: webAppFindings.falsePositiveScore");
    });
  });

  describe("unifiedFindingsStats procedure", () => {
    it("should be defined in the web-app-scanning router", () => {
      expect(routerSource).toContain("unifiedFindingsStats: protectedProcedure.query");
    });

    it("should compute total findings count", () => {
      expect(routerSource).toContain("const [{ total }] = await db.select({ total: count() }).from(webAppFindings)");
    });

    it("should group findings by severity", () => {
      expect(routerSource).toContain("groupBy(webAppFindings.severity)");
    });

    it("should group findings by tool using CASE expression", () => {
      expect(routerSource).toContain("WHEN ${webAppFindings.zapPluginId} LIKE 'sqlmap-%' THEN 'sqlmap'");
      expect(routerSource).toContain("WHEN ${webAppFindings.zapPluginId} LIKE 'xsstrike-%' THEN 'xsstrike'");
      expect(routerSource).toContain("WHEN ${webAppFindings.zapPluginId} LIKE 'dalfox-%' THEN 'dalfox'");
      expect(routerSource).toContain("WHEN ${webAppFindings.zapPluginId} REGEXP '^[0-9]+$' THEN 'zap'");
    });

    it("should group findings by MITRE tactic", () => {
      expect(routerSource).toContain("groupBy(webAppFindings.mitreTactic)");
    });

    it("should return top 10 MITRE techniques", () => {
      expect(routerSource).toContain("groupBy(webAppFindings.mitreAttackId, webAppFindings.mitreAttackName, webAppFindings.mitreTactic)");
      // Should limit to 10
      const techniqueSection = routerSource.slice(
        routerSource.indexOf("byMitreTechnique"),
        routerSource.indexOf("byMitreTechnique") + 800
      );
      expect(techniqueSection).toContain(".limit(10)");
    });

    it("should count exploitable findings", () => {
      expect(routerSource).toContain("eq(webAppFindings.exploitAvailable, 1)");
    });

    it("should return recent scans", () => {
      expect(routerSource).toContain("recentScans");
    });

    it("should return structured stats object", () => {
      expect(routerSource).toContain("bySeverity:");
      expect(routerSource).toContain("byTool:");
      expect(routerSource).toContain("byMitreTactic:");
      expect(routerSource).toContain("byMitreTechnique");
      expect(routerSource).toContain("exploitable");
      expect(routerSource).toContain("recentScans");
    });
  });
});

// ─── Frontend Page Tests ────────────────────────────────────────────────────

const pageSource = readFileSync(
  join(__dirname, "../client/src/pages/UnifiedFindings.tsx"),
  "utf-8"
);

describe("Unified Findings — Frontend Page", () => {
  it("should have a page purpose description", () => {
    // Knowledge requirement: page must have a brief description
    expect(pageSource).toContain("All web application security findings from ZAP, SQLMap, and XSStrike/Dalfox");
  });

  it("should use trpc.webAppScanning.unifiedFindings query", () => {
    expect(pageSource).toContain("trpc.webAppScanning.unifiedFindings.useQuery");
  });

  it("should use trpc.webAppScanning.unifiedFindingsStats query", () => {
    expect(pageSource).toContain("trpc.webAppScanning.unifiedFindingsStats.useQuery");
  });

  it("should have severity filter", () => {
    expect(pageSource).toContain("All Severities");
    expect(pageSource).toContain("setSeverity");
  });

  it("should have tool filter", () => {
    expect(pageSource).toContain("All Tools");
    expect(pageSource).toContain("setTool");
  });

  it("should have MITRE tactic filter", () => {
    expect(pageSource).toContain("All Tactics");
    expect(pageSource).toContain("setMitreTactic");
  });

  it("should have search functionality", () => {
    expect(pageSource).toContain("Search findings");
    expect(pageSource).toContain("debouncedSearch");
  });

  it("should have pagination controls", () => {
    expect(pageSource).toContain("Previous");
    expect(pageSource).toContain("Next");
    expect(pageSource).toContain("setOffset");
  });

  it("should display tool distribution chart", () => {
    expect(pageSource).toContain("ToolDistribution");
    expect(pageSource).toContain("Findings by Tool");
  });

  it("should display MITRE ATT&CK heatmap", () => {
    expect(pageSource).toContain("MitreHeatmap");
    expect(pageSource).toContain("Top MITRE ATT&CK Techniques");
  });

  it("should display tactic distribution", () => {
    expect(pageSource).toContain("TacticDistribution");
    expect(pageSource).toContain("Findings by MITRE Tactic");
  });

  it("should have finding detail dialog", () => {
    expect(pageSource).toContain("FindingDetail");
    expect(pageSource).toContain("DialogContent");
  });

  it("should show exploit availability indicator", () => {
    expect(pageSource).toContain("Exploit Available");
    expect(pageSource).toContain("exploitAvailable");
  });

  it("should show Metasploit module path", () => {
    expect(pageSource).toContain("Metasploit Module");
    expect(pageSource).toContain("exploitModulePath");
  });

  it("should show AI triage information", () => {
    expect(pageSource).toContain("AI Triage");
    expect(pageSource).toContain("aiTriageVerdict");
    expect(pageSource).toContain("falsePositiveScore");
  });

  it("should infer tool from zapPluginId prefix", () => {
    expect(pageSource).toContain("function inferTool");
    expect(pageSource).toContain("sqlmap-");
    expect(pageSource).toContain("xsstrike-");
    expect(pageSource).toContain("dalfox-");
  });

  it("should have empty state messaging", () => {
    expect(pageSource).toContain("No findings found");
    expect(pageSource).toContain("Run a web application scan to populate findings");
  });

  it("should have clear filters button", () => {
    expect(pageSource).toContain("clearFilters");
    expect(pageSource).toContain("Clear (");
  });

  it("should have summary stats cards", () => {
    expect(pageSource).toContain("StatsCards");
    expect(pageSource).toContain("Total Findings");
    expect(pageSource).toContain("High Severity");
    expect(pageSource).toContain("Exploitable");
    expect(pageSource).toContain("MITRE Techniques");
  });
});

// ─── Route & Navigation Tests ───────────────────────────────────────────────

const appSource = readFileSync(
  join(__dirname, "../client/src/App.tsx"),
  "utf-8"
);

const sidebarSource = readFileSync(
  join(__dirname, "../client/src/lib/sidebar-nav.ts"),
  "utf-8"
);

describe("Unified Findings — Route & Navigation", () => {
  it("should have lazy import in App.tsx", () => {
    expect(appSource).toContain('const UnifiedFindings = lazyWithRetry(() => import("./pages/UnifiedFindings"))');
  });

  it("should have route registered at /unified-findings", () => {
    expect(appSource).toContain('<Route path="/unified-findings">');
    expect(appSource).toContain("<ProtectedRoute component={UnifiedFindings} />");
  });

  it("should be in the sidebar navigation under Scanning & Assessment", () => {
    expect(sidebarSource).toContain('{ label: "Unified Findings", path: "/unified-findings"');
  });

  it("should be the first item in the Scanning & Assessment group", () => {
    const scanningSection = sidebarSource.slice(
      sidebarSource.indexOf('"scanning"'),
      sidebarSource.indexOf('"scanning"') + 600
    );
    const unifiedIdx = scanningSection.indexOf("Unified Findings");
    const webAppIdx = scanningSection.indexOf("Web App Scanner");
    expect(unifiedIdx).toBeLessThan(webAppIdx);
    expect(unifiedIdx).toBeGreaterThan(0);
  });
});
