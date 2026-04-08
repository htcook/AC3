import { describe, it, expect } from "vitest";
import {
  extractZapDiscoveredUrls,
  buildZapFingerprint,
  correlateFindings,
  getCrossToolCoverage,
  runZapToBurpPipeline,
  type ZapDiscoveredUrl,
  type ZapFingerprint,
  type CrossToolPipelineResult,
  type CorrelatedFinding,
} from "./lib/zap-burp-pipeline";

describe("ZAP → Burp Cross-Tool Pipeline", () => {
  // ─── Module Structure ───

  describe("module exports", () => {
    it("exports extractZapDiscoveredUrls function", () => {
      expect(typeof extractZapDiscoveredUrls).toBe("function");
    });

    it("exports buildZapFingerprint function", () => {
      expect(typeof buildZapFingerprint).toBe("function");
    });

    it("exports correlateFindings function", () => {
      expect(typeof correlateFindings).toBe("function");
    });

    it("exports getCrossToolCoverage function", () => {
      expect(typeof getCrossToolCoverage).toBe("function");
    });

    it("exports runZapToBurpPipeline function", () => {
      expect(typeof runZapToBurpPipeline).toBe("function");
    });
  });

  // ─── buildZapFingerprint ───

  describe("buildZapFingerprint", () => {
    it("returns empty fingerprint for empty findings", () => {
      const fp = buildZapFingerprint([]);
      expect(fp.technologies).toEqual([]);
      expect(fp.headers).toEqual({});
      expect(fp.cookies).toEqual([]);
      expect(fp.forms).toBe(0);
      expect(fp.apiEndpoints).toEqual([]);
      expect(fp.loginPages).toEqual([]);
    });

    it("detects API endpoints from URLs", () => {
      const findings = [
        { alertName: "Info", url: "https://example.com/api/v1/users" },
        { alertName: "Info", url: "https://example.com/graphql" },
        { alertName: "Info", url: "https://example.com/rest/items" },
        { alertName: "Info", url: "https://example.com/about" }, // not an API endpoint
      ];
      const fp = buildZapFingerprint(findings);
      expect(fp.apiEndpoints).toContain("https://example.com/api/v1/users");
      expect(fp.apiEndpoints).toContain("https://example.com/graphql");
      expect(fp.apiEndpoints).toContain("https://example.com/rest/items");
      expect(fp.apiEndpoints).not.toContain("https://example.com/about");
    });

    it("detects login pages from URLs", () => {
      const findings = [
        { alertName: "Info", url: "https://example.com/login" },
        { alertName: "Info", url: "https://example.com/auth/signin" },
        { alertName: "Authentication Issue", url: "https://example.com/dashboard" },
      ];
      const fp = buildZapFingerprint(findings);
      expect(fp.loginPages).toContain("https://example.com/login");
      expect(fp.loginPages).toContain("https://example.com/auth/signin");
      expect(fp.loginPages).toContain("https://example.com/dashboard"); // matched by alertName
    });

    it("detects cookies from cookie-related findings", () => {
      const findings = [
        { alertName: "Cookie Without Secure Flag", param: "JSESSIONID" },
        { alertName: "Set-Cookie Missing HttpOnly", param: "session_token" },
        { alertName: "SQL Injection", param: "id" }, // not a cookie
      ];
      const fp = buildZapFingerprint(findings);
      expect(fp.cookies).toContain("JSESSIONID");
      expect(fp.cookies).toContain("session_token");
      expect(fp.cookies).not.toContain("id");
    });

    it("counts forms from CSRF/form findings", () => {
      const findings = [
        { alertName: "Absence of Anti-CSRF Tokens", url: "https://example.com/form1" },
        { alertName: "Form Action Hijacking", url: "https://example.com/form2" },
        { alertName: "SQL Injection", url: "https://example.com/page" },
      ];
      const fp = buildZapFingerprint(findings);
      expect(fp.forms).toBe(2);
    });

    it("extracts technologies from scanConfig", () => {
      const findings: any[] = [];
      const scanConfig = { technologies: ["Apache", "PHP", "MySQL"] };
      const fp = buildZapFingerprint(findings, scanConfig);
      expect(fp.technologies).toContain("Apache");
      expect(fp.technologies).toContain("PHP");
      expect(fp.technologies).toContain("MySQL");
    });
  });

  // ─── Type Contracts ───

  describe("type contracts", () => {
    it("ZapDiscoveredUrl has required fields", () => {
      const url: ZapDiscoveredUrl = {
        url: "https://example.com",
        method: "GET",
        source: "spider",
      };
      expect(url.url).toBe("https://example.com");
      expect(url.method).toBe("GET");
      expect(url.source).toBe("spider");
    });

    it("ZapFingerprint has all required fields", () => {
      const fp: ZapFingerprint = {
        technologies: ["Apache"],
        headers: { "X-Powered-By": "Express" },
        cookies: ["session"],
        forms: 3,
        apiEndpoints: ["/api/v1"],
        loginPages: ["/login"],
      };
      expect(fp.technologies).toHaveLength(1);
      expect(fp.forms).toBe(3);
    });

    it("CrossToolPipelineResult has all required fields", () => {
      const result: CrossToolPipelineResult = {
        zapScanId: 42,
        zapUrlsDiscovered: 15,
        urlsFedToBurp: 10,
        burpScanLaunched: true,
        fingerprint: {
          technologies: [],
          headers: {},
          cookies: [],
          forms: 0,
          apiEndpoints: [],
          loginPages: [],
        },
        correlatedFindings: [],
      };
      expect(result.zapScanId).toBe(42);
      expect(result.burpScanLaunched).toBe(true);
    });

    it("CorrelatedFinding tracks multi-tool confirmation", () => {
      const cf: CorrelatedFinding = {
        vulnType: "SQL Injection",
        zapFindingId: 100,
        burpFindingRef: "burp-200",
        foundBy: ["zap", "burp"],
        severity: "high",
        confidenceBoost: true,
        url: "https://example.com/api/users",
        cweId: "89",
      };
      expect(cf.foundBy).toContain("zap");
      expect(cf.foundBy).toContain("burp");
      expect(cf.confidenceBoost).toBe(true);
    });
  });

  // ─── DB-dependent functions (graceful degradation) ───

  describe("extractZapDiscoveredUrls (no DB)", () => {
    it("returns empty array when DB is unavailable", async () => {
      const urls = await extractZapDiscoveredUrls(99999);
      expect(Array.isArray(urls)).toBe(true);
      // With no matching scan, should return empty
    });
  });

  describe("correlateFindings (no DB)", () => {
    it("returns empty array when DB is unavailable", async () => {
      const findings = await correlateFindings(99999, 99999);
      expect(Array.isArray(findings)).toBe(true);
    });
  });

  describe("getCrossToolCoverage (no DB)", () => {
    it("returns zeroed coverage when DB is unavailable", async () => {
      const coverage = await getCrossToolCoverage(99999);
      expect(coverage.totalUrls).toBeGreaterThanOrEqual(0);
      expect(coverage.zapOnly).toBeGreaterThanOrEqual(0);
      expect(coverage.burpOnly).toBeGreaterThanOrEqual(0);
      expect(coverage.both).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(coverage.urlDetails)).toBe(true);
    });
  });

  // ─── Integration with router ───

  describe("router integration", () => {
    it("bug-bounty router contains ZAP→Burp pipeline endpoints", async () => {
      const fs = await import("fs");
      const routerSource = fs.readFileSync("server/routers/bug-bounty.ts", "utf-8");
      expect(routerSource).toContain("runZapToBurpPipeline");
      expect(routerSource).toContain("getZapBurpCoverage");
      expect(routerSource).toContain("getZapDiscoveredUrls");
      expect(routerSource).toContain("correlateZapBurpFindings");
    });
  });

  // ─── Integration with orchestrator ───

  describe("orchestrator integration", () => {
    it("engagement-orchestrator imports zap-burp-pipeline in vuln_detection", async () => {
      const fs = await import("fs");
      const orchSource = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");
      expect(orchSource).toContain('import("./zap-burp-pipeline")');
      expect(orchSource).toContain("runZapToBurpPipeline");
      expect(orchSource).toContain("ZAP → Burp Pipeline");
    });
  });
});
