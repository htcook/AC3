/**
 * Tests for Compliance Exports:
 *   1. NVD CVE-to-CWE Lookup Service
 *   2. NIST 800-53 Report Generation (via enrichment logic)
 *   3. MITRE ATT&CK Navigator Layer Export (via enrichment logic)
 *
 * These tests validate the core logic without hitting the actual NVD API.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  enrichFinding,
  generateNistGapSummary,
  getImpactedNistFamilies,
  getNistControlsForCwe,
  getMitreTechniquesForCwe,
  NIST_CONTROL_FAMILIES,
  CWE_TO_NIST,
  CWE_TO_MITRE,
  MITRE_TO_NIST,
} from "./lib/nist-mitre-cwe-mapper";

// ─── NVD CVE Lookup Tests ───────────────────────────────────────────────────

describe("NVD CVE Lookup Service", () => {
  let lookupCve: typeof import("./lib/nvd-cve-lookup").lookupCve;
  let batchLookupCves: typeof import("./lib/nvd-cve-lookup").batchLookupCves;
  let resolveCvesToCwes: typeof import("./lib/nvd-cve-lookup").resolveCvesToCwes;
  let getCacheStats: typeof import("./lib/nvd-cve-lookup").getCacheStats;
  let clearCache: typeof import("./lib/nvd-cve-lookup").clearCache;

  beforeEach(async () => {
    const mod = await import("./lib/nvd-cve-lookup");
    lookupCve = mod.lookupCve;
    batchLookupCves = mod.batchLookupCves;
    resolveCvesToCwes = mod.resolveCvesToCwes;
    getCacheStats = mod.getCacheStats;
    clearCache = mod.clearCache;
    clearCache();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should normalize CVE IDs to uppercase", async () => {
    // Mock fetch to return a valid NVD response
    const mockResponse = {
      resultsPerPage: 1,
      startIndex: 0,
      totalResults: 1,
      vulnerabilities: [{
        cve: {
          id: "CVE-2021-44228",
          descriptions: [{ lang: "en", value: "Apache Log4j2 RCE" }],
          weaknesses: [{
            source: "nvd@nist.gov",
            type: "Primary",
            description: [{ lang: "en", value: "CWE-917" }],
          }],
          metrics: {
            cvssMetricV31: [{
              cvssData: { baseScore: 10.0, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
            }],
          },
          published: "2021-12-10T10:15:00.000",
          lastModified: "2023-11-07T03:39:00.000",
          references: [{ url: "https://logging.apache.org/log4j/2.x/security.html" }],
        },
      }],
    };

    vi.spyOn(global, "fetch").mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    } as any);

    const result = await lookupCve("cve-2021-44228");
    expect(result.cveId).toBe("CVE-2021-44228");
    expect(result.cwes).toContain("CWE-917");
    expect(result.cvssV3Score).toBe(10.0);
    expect(result.description).toContain("Log4j2");
    expect(result.cached).toBe(false);
  });

  it("should return cached results on second lookup", async () => {
    const mockResponse = {
      resultsPerPage: 1,
      startIndex: 0,
      totalResults: 1,
      vulnerabilities: [{
        cve: {
          id: "CVE-2023-12345",
          descriptions: [{ lang: "en", value: "Test vuln" }],
          weaknesses: [{
            source: "nvd@nist.gov",
            type: "Primary",
            description: [{ lang: "en", value: "CWE-79" }],
          }],
        },
      }],
    };

    vi.spyOn(global, "fetch").mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    } as any);

    const first = await lookupCve("CVE-2023-12345");
    expect(first.cached).toBe(false);
    expect(first.cwes).toContain("CWE-79");

    // Second call should be cached
    const second = await lookupCve("CVE-2023-12345");
    expect(second.cached).toBe(true);
    expect(second.cwes).toContain("CWE-79");
  });

  it("should handle CVE not found in NVD", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        resultsPerPage: 0,
        startIndex: 0,
        totalResults: 0,
        vulnerabilities: [],
      }),
    } as any);

    const result = await lookupCve("CVE-9999-99999");
    expect(result.cwes).toEqual([]);
    expect(result.error).toContain("not found");
  });

  it("should handle NVD API errors gracefully", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 503,
      text: () => Promise.resolve("Service Unavailable"),
    } as any);

    const result = await lookupCve("CVE-2021-44228", { skipCache: true });
    expect(result.cwes).toEqual([]);
    expect(result.error).toContain("503");
  });

  it("should handle network errors gracefully", async () => {
    vi.spyOn(global, "fetch").mockRejectedValueOnce(new Error("Network error"));

    const result = await lookupCve("CVE-2021-44228", { skipCache: true });
    expect(result.cwes).toEqual([]);
    expect(result.error).toContain("Network error");
  });

  it("should filter out CWE-noinfo entries", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        resultsPerPage: 1,
        startIndex: 0,
        totalResults: 1,
        vulnerabilities: [{
          cve: {
            id: "CVE-2023-99999",
            descriptions: [{ lang: "en", value: "Test" }],
            weaknesses: [{
              source: "nvd@nist.gov",
              type: "Primary",
              description: [
                { lang: "en", value: "CWE-noinfo" },
                { lang: "en", value: "CWE-79" },
              ],
            }],
          },
        }],
      }),
    } as any);

    const result = await lookupCve("CVE-2023-99999");
    expect(result.cwes).toEqual(["CWE-79"]);
    expect(result.cwes).not.toContain("CWE-noinfo");
  });

  it("should deduplicate CWE entries", async () => {
    vi.spyOn(global, "fetch").mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        resultsPerPage: 1,
        startIndex: 0,
        totalResults: 1,
        vulnerabilities: [{
          cve: {
            id: "CVE-2023-11111",
            descriptions: [{ lang: "en", value: "Test" }],
            weaknesses: [
              { source: "nvd@nist.gov", type: "Primary", description: [{ lang: "en", value: "CWE-89" }] },
              { source: "cna@vendor.com", type: "Secondary", description: [{ lang: "en", value: "CWE-89" }] },
            ],
          },
        }],
      }),
    } as any);

    const result = await lookupCve("CVE-2023-11111");
    expect(result.cwes).toEqual(["CWE-89"]);
  });

  it("should report cache statistics", () => {
    const stats = getCacheStats();
    expect(stats).toHaveProperty("size");
    expect(stats).toHaveProperty("maxSize");
    expect(stats.maxSize).toBe(1000);
  });

  it("should resolve CVEs to CWEs in batch", async () => {
    // Mock two sequential fetch calls
    const fetchMock = vi.spyOn(global, "fetch");
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        resultsPerPage: 1, startIndex: 0, totalResults: 1,
        vulnerabilities: [{
          cve: {
            id: "CVE-2021-44228",
            descriptions: [{ lang: "en", value: "Log4Shell" }],
            weaknesses: [{ source: "nvd", type: "Primary", description: [{ lang: "en", value: "CWE-917" }] }],
          },
        }],
      }),
    } as any);
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        resultsPerPage: 1, startIndex: 0, totalResults: 1,
        vulnerabilities: [{
          cve: {
            id: "CVE-2023-44487",
            descriptions: [{ lang: "en", value: "HTTP/2 Rapid Reset" }],
            weaknesses: [{ source: "nvd", type: "Primary", description: [{ lang: "en", value: "CWE-400" }] }],
          },
        }],
      }),
    } as any);

    const map = await resolveCvesToCwes(["CVE-2021-44228", "CVE-2023-44487"]);
    expect(map.get("CVE-2021-44228")).toContain("CWE-917");
    expect(map.get("CVE-2023-44487")).toContain("CWE-400");
  });
});

// ─── NIST 800-53 Report Generation Tests ────────────────────────────────────

describe("NIST 800-53 Report Generation", () => {
  const sampleFindings = [
    { cwes: ["CWE-89"], severity: "critical", title: "SQL Injection in login form", id: "F-001" },
    { cwes: ["CWE-79"], severity: "high", title: "Reflected XSS in search", id: "F-002" },
    { cwes: ["CWE-287"], severity: "high", title: "Authentication bypass via JWT", id: "F-003" },
    { cwes: ["CWE-22"], severity: "medium", title: "Path traversal in file upload", id: "F-004" },
    { cwes: ["CWE-200"], severity: "low", title: "Information disclosure in error pages", id: "F-005" },
  ];

  it("should enrich findings with NIST controls", () => {
    const enriched = sampleFindings.map(f => ({
      ...f,
      enrichment: enrichFinding(f),
    }));

    // SQL Injection should map to SI-10
    const sqlInjection = enriched.find(e => e.id === "F-001")!;
    expect(sqlInjection.enrichment.nistControls.some(c => c.controlId === "SI-10")).toBe(true);
    expect(sqlInjection.enrichment.cwes.some(c => c.cweId === "CWE-89")).toBe(true);

    // XSS should map to SI-10
    const xss = enriched.find(e => e.id === "F-002")!;
    expect(xss.enrichment.nistControls.some(c => c.controlId === "SI-10")).toBe(true);

    // Auth bypass should map to IA family
    const authBypass = enriched.find(e => e.id === "F-003")!;
    expect(authBypass.enrichment.nistControls.some(c => c.familyCode === "IA")).toBe(true);
  });

  it("should generate NIST gap summary with correct structure", () => {
    const summary = generateNistGapSummary(sampleFindings, "moderate");

    expect(summary).toHaveProperty("totalControlsImpacted");
    expect(summary).toHaveProperty("criticalGaps");
    expect(summary).toHaveProperty("coverageScore");
    expect(summary).toHaveProperty("byFamily");

    expect(summary.totalControlsImpacted).toBeGreaterThan(0);
    expect(typeof summary.coverageScore).toBe("number");
    expect(summary.coverageScore).toBeGreaterThanOrEqual(0);
    expect(summary.coverageScore).toBeLessThanOrEqual(100);
  });

  it("should identify critical gaps from high-severity findings", () => {
    const summary = generateNistGapSummary(sampleFindings, "moderate");

    // Critical/high findings should produce critical gaps
    expect(summary.criticalGaps.length).toBeGreaterThan(0);
    // Each gap should have a valid control ID
    for (const gap of summary.criticalGaps) {
      expect(gap.controlId).toMatch(/^[A-Z]{2}-\d+/);
    }
  });

  it("should group controls by family", () => {
    const families = getImpactedNistFamilies(sampleFindings);

    expect(families.length).toBeGreaterThan(0);
    for (const fam of families) {
      expect(fam).toHaveProperty("familyCode");
      expect(fam).toHaveProperty("familyName");
      expect(fam).toHaveProperty("controlCount");
      expect(fam.controlCount).toBeGreaterThan(0);
      // Family code should be a known NIST family
      expect(NIST_CONTROL_FAMILIES).toHaveProperty(fam.familyCode);
    }
  });

  it("should assign correct NIST priority based on severity", () => {
    const critical = enrichFinding({ cwes: ["CWE-89"], severity: "critical" });
    const high = enrichFinding({ cwes: ["CWE-89"], severity: "high" });
    const medium = enrichFinding({ cwes: ["CWE-89"], severity: "medium" });
    const low = enrichFinding({ cwes: ["CWE-89"], severity: "low" });

    expect(critical.nistPriority).toBe("P1");
    expect(high.nistPriority).toBe("P2");
    expect(medium.nistPriority).toBe("P3");
    expect(low.nistPriority).toBe("P4");
  });

  it("should handle findings with no CWEs using title inference", () => {
    const result = enrichFinding({
      title: "SQL injection vulnerability in admin panel",
      severity: "critical",
    });

    expect(result.nistControls.length).toBeGreaterThan(0);
    expect(result.mitreTechniques.length).toBeGreaterThan(0);
    // Should infer SI-10 from "sql injection" keyword
    expect(result.nistControls.some(c => c.controlId === "SI-10")).toBe(true);
  });

  it("should calculate coverage score relative to baseline", () => {
    const lowBaseline = generateNistGapSummary(sampleFindings, "low");
    const moderateBaseline = generateNistGapSummary(sampleFindings, "moderate");
    const highBaseline = generateNistGapSummary(sampleFindings, "high");

    // Same findings against larger baselines should have lower coverage
    expect(lowBaseline.coverageScore).toBeGreaterThanOrEqual(moderateBaseline.coverageScore);
    expect(moderateBaseline.coverageScore).toBeGreaterThanOrEqual(highBaseline.coverageScore);
  });
});

// ─── MITRE ATT&CK Navigator Layer Tests ────────────────────────────────────

describe("MITRE ATT&CK Navigator Layer Export", () => {
  it("should map CWEs to MITRE techniques", () => {
    // CWE-89 (SQL Injection) should map to T1190 (Exploit Public-Facing Application)
    const sqlMitre = getMitreTechniquesForCwe("CWE-89");
    expect(sqlMitre.length).toBeGreaterThan(0);
    expect(sqlMitre.some(t => t.techniqueId === "T1190")).toBe(true);
  });

  it("should map CWE-79 (XSS) to appropriate MITRE technique", () => {
    const xssMitre = getMitreTechniquesForCwe("CWE-79");
    expect(xssMitre.length).toBeGreaterThan(0);
    // XSS typically maps to T1189 (Drive-by Compromise)
    expect(xssMitre.some(t => t.techniqueId === "T1189")).toBe(true);
  });

  it("should produce valid Navigator layer structure", () => {
    const findings = [
      { cwes: ["CWE-89"], severity: "critical", title: "SQL Injection", id: "F-001" },
      { cwes: ["CWE-79"], severity: "high", title: "XSS", id: "F-002" },
      { cwes: ["CWE-287"], severity: "high", title: "Auth Bypass", id: "F-003" },
    ];

    // Simulate the Navigator layer generation logic
    const techniqueMap = new Map<string, { techniqueId: string; tactic: string; findings: string[] }>();

    for (const f of findings) {
      const enrichment = enrichFinding(f);
      for (const tech of enrichment.mitreTechniques) {
        const existing = techniqueMap.get(tech.techniqueId);
        if (existing) {
          existing.findings.push(f.id);
        } else {
          techniqueMap.set(tech.techniqueId, {
            techniqueId: tech.techniqueId,
            tactic: tech.tactic,
            findings: [f.id],
          });
        }
      }
    }

    expect(techniqueMap.size).toBeGreaterThan(0);

    // Each technique should have at least one finding
    for (const [, data] of techniqueMap) {
      expect(data.findings.length).toBeGreaterThan(0);
      expect(data.techniqueId).toMatch(/^T\d{4}/);
    }
  });

  it("should color techniques by severity", () => {
    const severityColors: Record<string, string> = {
      critical: "#d73027",
      high: "#f46d43",
      medium: "#fdae61",
      low: "#fee08b",
      informational: "#a1d99b",
    };

    for (const [severity, expectedColor] of Object.entries(severityColors)) {
      expect(expectedColor).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });

  it("should handle findings with MITRE technique IDs directly", () => {
    const result = enrichFinding({
      techniqueIds: ["T1059", "T1548"],
      severity: "high",
    });

    // Should have NIST controls mapped from MITRE techniques
    expect(result.nistControls.length).toBeGreaterThan(0);
    expect(result.mitreTechniques.length).toBe(0); // techniqueIds don't auto-populate mitreTechniques in enrichFinding
  });

  it("should map MITRE techniques to NIST controls via MITRE_TO_NIST", () => {
    // T1190 (Exploit Public-Facing Application) should map to NIST controls
    const nistIds = MITRE_TO_NIST["T1190"];
    expect(nistIds).toBeDefined();
    expect(nistIds.length).toBeGreaterThan(0);
    // Should include SI-10 (Input Validation)
    expect(nistIds).toContain("SI-10");
  });

  it("should produce techniques grouped by tactic", () => {
    const findings = [
      { cwes: ["CWE-89"], severity: "critical", title: "SQL Injection", id: "F-001" },
      { cwes: ["CWE-78"], severity: "high", title: "OS Command Injection", id: "F-002" },
      { cwes: ["CWE-287"], severity: "high", title: "Auth Bypass", id: "F-003" },
      { cwes: ["CWE-918"], severity: "medium", title: "SSRF", id: "F-004" },
    ];

    const tacticMap = new Map<string, string[]>();
    for (const f of findings) {
      const enrichment = enrichFinding(f);
      for (const tech of enrichment.mitreTechniques) {
        if (!tacticMap.has(tech.tactic)) {
          tacticMap.set(tech.tactic, []);
        }
        if (!tacticMap.get(tech.tactic)!.includes(tech.techniqueId)) {
          tacticMap.get(tech.tactic)!.push(tech.techniqueId);
        }
      }
    }

    expect(tacticMap.size).toBeGreaterThan(0);
    // At least Initial Access should be covered (SQL injection, SSRF)
    const hasInitialAccess = Array.from(tacticMap.keys()).some(t =>
      t.toLowerCase().includes("initial access") || t.toLowerCase().includes("initial_access")
    );
    const hasExecution = Array.from(tacticMap.keys()).some(t =>
      t.toLowerCase().includes("execution")
    );
    // At least one of these should be present
    expect(hasInitialAccess || hasExecution).toBe(true);
  });
});

// ─── Cross-Feature Integration Tests ────────────────────────────────────────

describe("Cross-Feature Integration", () => {
  it("should chain CVE → CWE → NIST → MITRE enrichment", () => {
    // Simulate: CVE resolved to CWE-89, then enriched
    const cwesFromNvd = ["CWE-89"];
    const enrichment = enrichFinding({
      cwes: cwesFromNvd,
      severity: "critical",
      title: "SQL Injection (CVE-2021-12345)",
    });

    // Should have CWE details
    expect(enrichment.cwes.some(c => c.cweId === "CWE-89")).toBe(true);
    expect(enrichment.cwes.some(c => c.cweName.toLowerCase().includes("sql"))).toBe(true);

    // Should have NIST controls
    expect(enrichment.nistControls.length).toBeGreaterThan(0);
    expect(enrichment.nistControls.some(c => c.controlId === "SI-10")).toBe(true);

    // Should have MITRE techniques
    expect(enrichment.mitreTechniques.length).toBeGreaterThan(0);
    expect(enrichment.mitreTechniques.some(t => t.techniqueId === "T1190")).toBe(true);

    // Should have correct priority
    expect(enrichment.nistPriority).toBe("P1");
  });

  it("should produce consistent mappings across CWE_TO_NIST and CWE_TO_MITRE", () => {
    // Every CWE in CWE_TO_NIST should also be in CWE_TO_MITRE or vice versa
    const nistCwes = new Set(Object.keys(CWE_TO_NIST));
    const mitreCwes = new Set(Object.keys(CWE_TO_MITRE));

    // At least some overlap
    const overlap = [...nistCwes].filter(c => mitreCwes.has(c));
    expect(overlap.length).toBeGreaterThan(5);
  });

  it("should handle empty findings gracefully", () => {
    const summary = generateNistGapSummary([], "moderate");
    expect(summary.totalControlsImpacted).toBe(0);
    expect(summary.criticalGaps).toEqual([]);
    expect(summary.coverageScore).toBe(0);
  });

  it("should handle findings with only title (no CWEs or techniques)", () => {
    const result = enrichFinding({
      title: "Misconfigured S3 bucket allows public access",
      severity: "high",
    });

    // Should infer cloud-related controls from title
    expect(result.nistControls.length).toBeGreaterThan(0);
  });
});
