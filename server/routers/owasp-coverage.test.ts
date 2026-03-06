import { describe, it, expect } from "vitest";
import {
  OwaspCoverageTracker,
  renderOwaspCoverageHTML,
  generateOwaspReportSection,
} from "../lib/owasp-coverage-tracker";

describe("OWASP Coverage Router Logic", () => {
  describe("CSV export generation", () => {
    it("generates CSV from tracker data", () => {
      const tracker = new OwaspCoverageTracker();
      tracker.registerAssetTech("example.com", ["php", "mysql"]);
      tracker.addToolRun({
        tool: "zap",
        target: "example.com",
        command: "zap-full-scan.py",
        exitCode: 0,
      });
      tracker.addFinding({
        title: "SQL Injection in login form",
        severity: "high",
        tool: "zap",
        target: "example.com",
      });
      tracker.addFinding({
        title: "Cross-Site Scripting (XSS)",
        severity: "medium",
        tool: "zap",
        target: "example.com",
      });

      const coverage = tracker.getEngagementCoverage("test-1");

      // Build CSV (mirrors router logic) — uses assets[].categories
      const rows: string[] = [];
      rows.push(
        [
          "OWASP Category ID",
          "Category Name",
          "Status",
          "Score (%)",
          "Findings Count",
          "Tools Used",
        ].join(",")
      );

      // Aggregate categories across all assets
      const catMap = new Map<string, { status: string; findingsCount: number; tools: Set<string> }>();
      for (const asset of coverage.assets) {
        for (const cat of asset.categories) {
          const existing = catMap.get(cat.categoryId);
          if (!existing) {
            catMap.set(cat.categoryId, {
              status: cat.status,
              findingsCount: cat.findingsCount,
              tools: new Set(cat.toolsCovering || []),
            });
          } else {
            existing.findingsCount += cat.findingsCount;
            (cat.toolsCovering || []).forEach((t) => existing.tools.add(t));
            if (cat.status === "tested" || existing.status === "tested") existing.status = "tested";
            else if (cat.status === "partial") existing.status = "partial";
          }
        }
      }

      for (const [catId, data] of catMap) {
        rows.push(
          [
            `"${catId}"`,
            `"${catId}"`,
            `"${data.status}"`,
            "0",
            data.findingsCount,
            `"${[...data.tools].join("; ")}"`,
          ].join(",")
        );
      }

      rows.push("");
      rows.push(`Overall Score,${coverage.overallScore}%`);
      rows.push(`Grade,${coverage.overallScore >= 70 ? "A" : coverage.overallScore >= 50 ? "B" : "C"}`);

      const csv = rows.join("\n");
      expect(csv).toContain("OWASP Category ID");
      expect(csv).toContain("Overall Score");
      expect(csv.split("\n").length).toBeGreaterThan(5);
    });

    it("generates per-asset CSV breakdown", () => {
      const tracker = new OwaspCoverageTracker();
      tracker.registerAssetTech("app1.com", ["node.js"]);
      tracker.registerAssetTech("app2.com", ["php"]);
      tracker.addFinding({
        title: "Broken Access Control",
        severity: "high",
        tool: "nuclei",
        target: "app1.com",
      });
      tracker.addFinding({
        title: "SQL Injection",
        severity: "critical",
        tool: "zap",
        target: "app2.com",
      });

      const coverage = tracker.getEngagementCoverage("test-2");

      // Per-asset breakdown
      const rows: string[] = [];
      rows.push(
        ["Asset", "OWASP Category", "Status", "Score", "Findings"].join(",")
      );

      for (const asset of coverage.assets) {
        for (const cat of asset.categories) {
          rows.push(
            [
              `"${asset.hostname}"`,
              `"${cat.categoryId}: ${cat.categoryName}"`,
              `"${cat.status}"`,
              cat.findingsCount > 0 ? 100 : 0,
              cat.findingsCount,
            ].join(",")
          );
        }
      }

      const csv = rows.join("\n");
      expect(csv).toContain("app1.com");
      expect(csv).toContain("app2.com");
    });
  });

  describe("HTML export generation", () => {
    it("generates HTML report from coverage data", () => {
      const tracker = new OwaspCoverageTracker();
      tracker.registerAssetTech("target.com", ["apache", "php"]);
      tracker.addToolRun({
        tool: "nuclei",
        target: "target.com",
        command: "nuclei -u target.com",
        exitCode: 0,
      });
      tracker.addFinding({
        title: "Server-Side Request Forgery",
        severity: "high",
        tool: "nuclei",
        target: "target.com",
      });

      const coverage = tracker.getEngagementCoverage("test-3");
      const html = renderOwaspCoverageHTML(coverage);

      expect(html).toContain("OWASP");
      expect(html).toContain("target.com");
      expect(html.length).toBeGreaterThan(500);
    });

    it("generates report section data", () => {
      const tracker = new OwaspCoverageTracker();
      tracker.addFinding({
        title: "Injection vulnerability",
        severity: "critical",
        tool: "zap",
        target: "api.example.com",
      });

      const coverage = tracker.getEngagementCoverage("test-4");
      const section = generateOwaspReportSection(coverage);

      expect(section.title).toContain("OWASP");
      expect(section.content).toBeTruthy();
    });
  });

  describe("real-time coverage update data shape", () => {
    it("produces the shape expected by WebSocket broadcast", () => {
      const tracker = new OwaspCoverageTracker();
      tracker.addToolRun({
        tool: "nmap",
        target: "host1.com",
        command: "nmap -sV host1.com",
        exitCode: 0,
      });
      tracker.addFinding({
        title: "Open SSH port",
        severity: "info",
        tool: "nmap",
        target: "host1.com",
      });

      const coverage = tracker.getEngagementCoverage("rt-test");

      // Aggregate categories from all assets
      const allCategories = coverage.assets.flatMap((a) =>
        a.categories.map((c) => ({
          id: c.categoryId,
          name: c.categoryName,
          status: c.status,
          score: c.findingsCount > 0 ? 100 : 0,
          findingsCount: c.findingsCount,
        }))
      );

      // This is the shape broadcast via WebSocket
      const wsPayload = {
        type: "owasp_coverage_update",
        phase: "enumeration",
        owaspCoverage: {
          overallScore: coverage.overallScore,
          grade: coverage.overallScore >= 70 ? "A" : coverage.overallScore >= 50 ? "B" : "C",
          totalTested: coverage.totalTested,
          totalPartial: coverage.totalPartial,
          totalGaps: coverage.totalGaps,
          criticalGaps: coverage.criticalGaps.length,
          categories: allCategories,
        },
      };

      expect(wsPayload.type).toBe("owasp_coverage_update");
      expect(wsPayload.owaspCoverage.overallScore).toBeGreaterThanOrEqual(0);
      expect(wsPayload.owaspCoverage.overallScore).toBeLessThanOrEqual(100);
      expect(typeof wsPayload.owaspCoverage.grade).toBe("string");
      expect(wsPayload.owaspCoverage.categories.length).toBeGreaterThan(0);
      for (const cat of wsPayload.owaspCoverage.categories) {
        expect(cat.id).toBeTruthy();
        expect(cat.name).toBeTruthy();
        expect(["tested", "partial", "not_tested", "not_applicable"]).toContain(
          cat.status
        );
        expect(typeof cat.score).toBe("number");
        expect(typeof cat.findingsCount).toBe("number");
      }
    });
  });
});
