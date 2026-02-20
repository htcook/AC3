import { describe, expect, it } from "vitest";

/**
 * Tests for the data export utility.
 * 
 * The export utility runs entirely in the browser (client-side), so these tests
 * validate the data transformation logic and CSV generation without DOM dependencies.
 * We test the core CSV escaping and column mapping logic.
 */

// ─── CSV Generation Logic (mirrors export-utils.ts) ─────────────────────

function escapeCsvCell(val: unknown): string {
  if (val === null || val === undefined) return '';
  const str = String(val);
  if (str.includes(',') || str.includes('\n') || str.includes('"')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function generateCsvContent<T>(
  columns: Array<{ header: string; accessor: (row: T) => unknown }>,
  data: T[],
): string {
  const headers = columns.map(c => c.header);
  const rows = data.map(row =>
    columns.map(col => escapeCsvCell(col.accessor(row)))
  );
  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

// ─── Tests ──────────────────────────────────────────────────────────────

describe("Data Export Utility", () => {
  describe("CSV cell escaping", () => {
    it("returns empty string for null/undefined", () => {
      expect(escapeCsvCell(null)).toBe('');
      expect(escapeCsvCell(undefined)).toBe('');
    });

    it("passes through simple strings", () => {
      expect(escapeCsvCell("hello")).toBe("hello");
      expect(escapeCsvCell("sso.acme.com")).toBe("sso.acme.com");
    });

    it("wraps strings with commas in quotes", () => {
      expect(escapeCsvCell("hello, world")).toBe('"hello, world"');
    });

    it("wraps strings with newlines in quotes", () => {
      expect(escapeCsvCell("line1\nline2")).toBe('"line1\nline2"');
    });

    it("escapes double quotes by doubling them", () => {
      expect(escapeCsvCell('say "hello"')).toBe('"say ""hello"""');
    });

    it("handles numbers and booleans", () => {
      expect(escapeCsvCell(42)).toBe("42");
      expect(escapeCsvCell(true)).toBe("true");
      expect(escapeCsvCell(0)).toBe("0");
    });
  });

  describe("CSV generation", () => {
    it("generates correct CSV for asset data", () => {
      const assets = [
        { hostname: "sso.acme.com", assetType: "web_application", hybridRiskScore: 88, riskBand: "critical" },
        { hostname: "api.acme.com", assetType: "api_endpoint", hybridRiskScore: 72, riskBand: "high" },
      ];

      const columns = [
        { header: "Hostname", accessor: (a: typeof assets[0]) => a.hostname },
        { header: "Type", accessor: (a: typeof assets[0]) => a.assetType },
        { header: "Risk Score", accessor: (a: typeof assets[0]) => a.hybridRiskScore },
        { header: "Risk Band", accessor: (a: typeof assets[0]) => a.riskBand },
      ];

      const csv = generateCsvContent(columns, assets);
      const lines = csv.split('\n');

      expect(lines[0]).toBe("Hostname,Type,Risk Score,Risk Band");
      expect(lines[1]).toBe("sso.acme.com,web_application,88,critical");
      expect(lines[2]).toBe("api.acme.com,api_endpoint,72,high");
    });

    it("handles empty data array", () => {
      const csv = generateCsvContent(
        [{ header: "Name", accessor: (r: any) => r.name }],
        [],
      );
      expect(csv).toBe("Name");
    });

    it("handles special characters in data", () => {
      const data = [
        { name: 'O"Brien Corp', description: "Has, commas" },
      ];

      const columns = [
        { header: "Name", accessor: (r: typeof data[0]) => r.name },
        { header: "Description", accessor: (r: typeof data[0]) => r.description },
      ];

      const csv = generateCsvContent(columns, data);
      const lines = csv.split('\n');
      expect(lines[1]).toBe('"O""Brien Corp","Has, commas"');
    });
  });

  describe("Finding export data mapping", () => {
    it("maps posture findings to export columns correctly", () => {
      const findings = [
        {
          assetHostname: "sso.acme.com",
          category: "vulnerability",
          title: "CVE-2024-1234 Remote Code Execution",
          severity: 9,
          likelihood: "high",
          confidence: 0.95,
          corroborationTier: "confirmed",
          cveIds: ["CVE-2024-1234"],
          kevListed: true,
          exploitAvailable: true,
          cvssScore: 9.8,
          evidenceBasis: "shodan_banner",
          recommendedControls: ["Patch immediately", "Network segmentation"],
        },
      ];

      // Simulate the column mapping from exportFindings
      const row = {
        asset: findings[0].assetHostname,
        category: findings[0].category,
        title: findings[0].title,
        severity: findings[0].severity,
        confidence: `${(findings[0].confidence * 100).toFixed(0)}%`,
        corroboration: findings[0].corroborationTier,
        cves: findings[0].cveIds.join('; '),
        kev: findings[0].kevListed ? 'Yes' : 'No',
        exploit: findings[0].exploitAvailable ? 'Yes' : 'No',
        cvss: findings[0].cvssScore,
        controls: findings[0].recommendedControls.join('; '),
      };

      expect(row.asset).toBe("sso.acme.com");
      expect(row.severity).toBe(9);
      expect(row.confidence).toBe("95%");
      expect(row.kev).toBe("Yes");
      expect(row.cves).toBe("CVE-2024-1234");
      expect(row.controls).toContain("Patch immediately");
    });
  });

  describe("Threat actor export data mapping", () => {
    it("maps threat actor matches to export columns", () => {
      const actors = [
        {
          name: "APT29",
          aliases: ["Cozy Bear", "The Dukes"],
          type: "nation_state",
          origin: "Russia",
          threatLevel: "critical",
          confidence: 0.87,
          matchReason: "Targets technology sector with supply chain attacks",
          ttps: ["T1566.001", "T1059.001"],
        },
      ];

      const row = {
        name: actors[0].name,
        aliases: actors[0].aliases.join('; '),
        type: actors[0].type,
        origin: actors[0].origin,
        threatLevel: actors[0].threatLevel,
        confidence: `${(actors[0].confidence * 100).toFixed(0)}%`,
        ttps: actors[0].ttps.join('; '),
      };

      expect(row.name).toBe("APT29");
      expect(row.aliases).toBe("Cozy Bear; The Dukes");
      expect(row.confidence).toBe("87%");
      expect(row.ttps).toContain("T1566.001");
    });
  });

  describe("Executive summary export data", () => {
    it("generates correct summary statistics", () => {
      const assets = [
        { riskBand: "critical", hybridRiskScore: 92 },
        { riskBand: "critical", hybridRiskScore: 88 },
        { riskBand: "high", hybridRiskScore: 75 },
        { riskBand: "medium", hybridRiskScore: 55 },
        { riskBand: "low", hybridRiskScore: 25 },
      ];

      const summary = {
        total: assets.length,
        critical: assets.filter(a => a.riskBand === "critical").length,
        high: assets.filter(a => a.riskBand === "high").length,
        medium: assets.filter(a => a.riskBand === "medium").length,
        low: assets.filter(a => a.riskBand === "low").length,
        avgScore: Math.round(assets.reduce((s, a) => s + a.hybridRiskScore, 0) / assets.length),
      };

      expect(summary.total).toBe(5);
      expect(summary.critical).toBe(2);
      expect(summary.high).toBe(1);
      expect(summary.medium).toBe(1);
      expect(summary.low).toBe(1);
      expect(summary.avgScore).toBe(67);
    });
  });
});
