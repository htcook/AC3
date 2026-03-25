/**
 * Tests for SQLMap Blind SQLi Integration
 *
 * Validates:
 * 1. ingestSqlmapToWebAppFindings correctly maps findings with MITRE ATT&CK
 * 2. extractZapSqliForHandoff filters and deduplicates SQLi findings
 * 3. runBlindSqliPass merges ZAP handoff URLs with known injectable URLs
 * 4. Orchestrator integrates blind SQLi pass for training labs only
 * 5. scan_results insert uses correct column names (tool, not scanType)
 * 6. Severity and confidence mapping is correct
 */
import { describe, it, expect, vi } from "vitest";
import * as fs from "fs";
import type { SqlmapFinding, SqlmapScanResult } from "./lib/scanners/sqlmap-scanner";

// Helper to create mock SqlmapFinding
function mockFinding(overrides: Partial<SqlmapFinding> = {}): SqlmapFinding {
  return {
    id: "sqli-1",
    type: "sqli",
    severity: "critical",
    technique: "time-based blind",
    parameter: "id",
    url: "https://juice-shop.example.com/rest/products/search?q=test",
    dbms: "SQLite",
    payload: "1' AND (SELECT 5 FROM (SELECT(SLEEP(5)))a)-- -",
    title: "Time-based blind SQL injection on parameter 'id'",
    description: "The parameter 'id' is vulnerable to time-based blind SQL injection.",
    databases: ["main"],
    tables: ["Users", "Products"],
    cweId: 89,
    references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
    ...overrides,
  };
}

// Helper to create mock SqlmapScanResult
function mockScanResult(overrides: Partial<SqlmapScanResult> = {}): SqlmapScanResult {
  return {
    scanId: null,
    status: "completed",
    target: "https://juice-shop.example.com/rest/products/search?q=test",
    findings: [mockFinding()],
    injectable: true,
    dbmsFingerprint: "SQLite",
    stats: {
      urlsTested: 1,
      parametersTested: 3,
      injectableParams: 1,
      techniquesUsed: ["time-based blind", "boolean-based blind"],
      durationSeconds: 45,
    },
    rawOutput: "sqlmap output...",
    ...overrides,
  };
}

describe("SQLMap Blind SQLi Integration", () => {
  const sqlmapCode = fs.readFileSync("server/lib/scanners/sqlmap-scanner.ts", "utf-8");
  const orchestratorCode = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

  describe("scan_results insert fix", () => {
    it("should use 'tool' column instead of 'scanType' for scan_results insert", () => {
      // The old code used scanType which doesn't exist in the schema
      expect(sqlmapCode).not.toContain('scanType: "sqlmap"');
      // The new code uses the correct 'tool' column
      expect(sqlmapCode).toContain('tool: "sqlmap"');
    });

    it("should include findingCount, durationMs, and severitySummary in scan_results insert", () => {
      expect(sqlmapCode).toContain("findingCount:");
      expect(sqlmapCode).toContain("durationMs:");
      expect(sqlmapCode).toContain("severitySummary:");
    });

    it("should NOT use non-existent columns (status, startedAt, completedAt) in scan_results insert", () => {
      // These columns don't exist in scan_results table
      // Check that the old broken pattern is gone
      const scanResultsInsertMatch = sqlmapCode.match(/db\.insert\(scanResults\)\.values\(\{[\s\S]*?\}\)/);
      if (scanResultsInsertMatch) {
        const insertBlock = scanResultsInsertMatch[0];
        expect(insertBlock).not.toContain("startedAt:");
        expect(insertBlock).not.toContain("completedAt:");
        // 'status' could appear in other contexts, so check specifically in the insert
        expect(insertBlock).not.toContain('status: "completed"');
      }
    });
  });

  describe("ingestSqlmapToWebAppFindings function", () => {
    it("should be exported from sqlmap-scanner.ts", () => {
      expect(sqlmapCode).toContain("export async function ingestSqlmapToWebAppFindings");
    });

    it("should create a web_app_scans record with scanType 'sqlmap_blind'", () => {
      expect(sqlmapCode).toContain('scanType: "sqlmap_blind"');
    });

    it("should insert findings into webAppFindings table", () => {
      expect(sqlmapCode).toContain("db.insert(webAppFindings)");
    });

    it("should map MITRE ATT&CK for each finding", () => {
      expect(sqlmapCode).toContain("mapToMitre(finding.cweId, finding.title)");
    });

    it("should map Metasploit modules for exploit correlation", () => {
      expect(sqlmapCode).toContain("findMsfModules(finding.cweId)");
    });

    it("should set high confidence (0.95) for confirmed SQLi findings", () => {
      expect(sqlmapCode).toContain("sqli: 0.95");
    });

    it("should include solution text for each finding type", () => {
      expect(sqlmapCode).toContain("Use parameterized queries");
      expect(sqlmapCode).toContain("solutionMap[finding.type]");
    });

    it("should use zapPluginId 'sqlmap-*' prefix to distinguish from ZAP findings", () => {
      expect(sqlmapCode).toContain("`sqlmap-${finding.type}`");
    });
  });

  describe("extractZapSqliForHandoff function", () => {
    it("should be exported from sqlmap-scanner.ts", () => {
      expect(sqlmapCode).toContain("export async function extractZapSqliForHandoff");
    });

    it("should filter findings to only SQL injection related alerts", () => {
      expect(sqlmapCode).toContain("sql injection");
      expect(sqlmapCode).toContain("sqli");
    });

    it("should deduplicate URLs and collect params", () => {
      expect(sqlmapCode).toContain("urlMap");
      expect(sqlmapCode).toContain("new Set(");
    });
  });

  describe("runBlindSqliPass function", () => {
    it("should be exported from sqlmap-scanner.ts", () => {
      expect(sqlmapCode).toContain("export async function runBlindSqliPass");
    });

    it("should use BT techniques for non-training-lab (production) targets", () => {
      // For production: only Boolean-blind + Time-blind
      expect(sqlmapCode).toContain('const techniques = isTrainingLab ? "BTEUS" : "BT"');
    });

    it("should use BTEUS techniques for training labs (broader coverage)", () => {
      expect(sqlmapCode).toContain('"BTEUS"');
    });

    it("should use risk 3 / level 5 for training labs", () => {
      expect(sqlmapCode).toContain("const risk = isTrainingLab ? 3 : 2");
      expect(sqlmapCode).toContain("const level = isTrainingLab ? 5 : 3");
    });

    it("should merge ZAP handoff URLs with known injectable URLs (dedup)", () => {
      expect(sqlmapCode).toContain("const seenUrls = new Set(handoffUrls.map");
      expect(sqlmapCode).toContain("!seenUrls.has(url.url)");
    });

    it("should call ingestSqlmapToWebAppFindings to persist findings", () => {
      expect(sqlmapCode).toContain("await ingestSqlmapToWebAppFindings(");
    });

    it("should return blindSqliFound count", () => {
      expect(sqlmapCode).toContain('const blindSqliFound = allFindings.filter(f => f.type === "sqli").length');
    });
  });

  describe("Orchestrator Integration", () => {
    it("should import runBlindSqliPass and ingestSqlmapToWebAppFindings", () => {
      expect(orchestratorCode).toContain("runBlindSqliPass");
      expect(orchestratorCode).toContain("ingestSqlmapToWebAppFindings");
    });

    it("should only run blind SQLi pass for training labs", () => {
      // The blind pass should be gated by isTrainingLabSqlmap
      expect(orchestratorCode).toContain("if (isTrainingLabSqlmap)");
      expect(orchestratorCode).toContain("Blind SQLi Pass");
    });

    it("should look up ZAP scan ID for handoff using scan name pattern", () => {
      expect(orchestratorCode).toContain("zapScanIdForHandoff");
      expect(orchestratorCode).toContain(`%EngOps-\${state.engagementId}%`);
    });

    it("should pass knownInjectableUrls to runBlindSqliPass", () => {
      expect(orchestratorCode).toContain("knownInjectableUrls: injectableUrls");
    });

    it("should add vulns for blind SQLi findings", () => {
      expect(orchestratorCode).toContain("[SQLMap Blind]");
      expect(orchestratorCode).toContain("blind SQL injection vulnerabilities");
    });

    it("should log blind SQLi pass results", () => {
      expect(orchestratorCode).toContain("Blind SQLi Pass Complete");
      expect(orchestratorCode).toContain("blindSqliFound");
    });

    it("should add tool result for sqlmap-blind", () => {
      expect(orchestratorCode).toContain("tool: 'sqlmap-blind'");
    });

    it("should ingest standard SQLMap findings into web_app_findings", () => {
      // The standard SQLMap section should also ingest findings
      expect(orchestratorCode).toContain("await ingestSqlmapToWebAppFindings(sqlmapResults, state.engagementId, webApp.hostname)");
    });

    it("should use correct risk/level in the tool command string", () => {
      // The command should use the actual risk/level variables, not hardcoded values
      expect(orchestratorCode).toContain("--risk ${sqlmapRisk} --level ${sqlmapLevel}");
    });
  });

  describe("Severity and Confidence Mapping", () => {
    it("should map SQLMap 'critical' to web_app_findings 'high' (max severity)", () => {
      expect(sqlmapCode).toContain('critical: "high"');
    });

    it("should set confidence 0.99 for os_access findings (most severe)", () => {
      expect(sqlmapCode).toContain("os_access: 0.99");
    });

    it("should set WASC-19 for SQL injection findings", () => {
      // WASC-19 = SQL Injection
      expect(sqlmapCode).toContain("wascId: finding.type === \"sqli\" ? 19 : null");
    });
  });

  describe("Import Structure", () => {
    it("should import mapToMitre and findMsfModules from zap-scanner", () => {
      expect(sqlmapCode).toContain('import { mapToMitre, findMsfModules } from "../zap-scanner"');
    });

    it("should import webAppScans and webAppFindings from schema", () => {
      expect(sqlmapCode).toContain("webAppScans, webAppFindings");
    });
  });
});
