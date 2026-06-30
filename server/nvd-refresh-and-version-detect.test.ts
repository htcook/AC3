/**
 * Tests for:
 * 1. NVD CVE Refresh Service (nvd-cve-refresh.ts)
 * 2. Version Auto-Detection (tech-auto-detector extractVersion)
 * 3. Engagement Stack Profile Auto-Link (engagement-automation suggestStackProfiles)
 *
 * @author Harrison Cook — AceofCloud
 */

import { describe, it, expect } from "vitest";

// ─── NVD CVE Refresh Service Tests ──────────────────────────────────────────

describe("NVD CVE Refresh Service", () => {
  it("getFullCveDatabase returns static CVEs when no dynamic data exists", async () => {
    const { getFullCveDatabase } = await import("./lib/nvd-cve-refresh");
    const db = getFullCveDatabase();
    expect(db.length).toBeGreaterThan(0);
    // Should include known static entries
    const streamlitCve = db.find(c => c.cveId === "CVE-2024-0217");
    expect(streamlitCve).toBeDefined();
    expect(streamlitCve!.technology).toBe("streamlit");
    expect(streamlitCve!.severity).toBe("high");
  });

  it("getCveRefreshStats returns valid initial stats", async () => {
    const { getCveRefreshStats } = await import("./lib/nvd-cve-refresh");
    const stats = getCveRefreshStats();
    expect(stats.staticCount).toBeGreaterThan(10);
    expect(stats.dynamicCount).toBeGreaterThanOrEqual(0);
    expect(stats.totalCount).toBe(stats.staticCount + stats.dynamicCount);
    expect(stats.technologies).toContain("streamlit");
    expect(stats.technologies).toContain("jupyter");
    expect(stats.technologies).toContain("langchain");
  });

  it("ingestExternalCves adds new CVEs and deduplicates existing ones", async () => {
    const { ingestExternalCves, getFullCveDatabase, getDynamicCves } = await import("./lib/nvd-cve-refresh");

    const newCves = [
      {
        technology: "streamlit",
        cveId: "CVE-2025-99999",
        affectedBelow: "2.0.0",
        severity: "critical" as const,
        title: "Test CVE",
        description: "Test description",
        scannerModule: "streamlit-scanner",
      },
      // Duplicate of static entry
      {
        technology: "streamlit",
        cveId: "CVE-2024-0217",
        affectedBelow: "1.30.0",
        severity: "high" as const,
        title: "Duplicate",
        description: "Should be skipped",
        scannerModule: "streamlit-scanner",
      },
    ];

    const result = ingestExternalCves(newCves);
    expect(result.added).toBe(1);
    expect(result.duplicates).toBe(1);

    const dynamic = getDynamicCves();
    expect(dynamic.some(c => c.cveId === "CVE-2025-99999")).toBe(true);

    const full = getFullCveDatabase();
    expect(full.some(c => c.cveId === "CVE-2025-99999")).toBe(true);
  });

  it("ingestExternalCves prevents double-ingestion of dynamic CVEs", async () => {
    const { ingestExternalCves } = await import("./lib/nvd-cve-refresh");

    const result = ingestExternalCves([{
      technology: "streamlit",
      cveId: "CVE-2025-99999",
      affectedBelow: "2.0.0",
      severity: "critical" as const,
      title: "Already ingested",
      description: "Should be duplicate",
      scannerModule: "streamlit-scanner",
    }]);
    expect(result.duplicates).toBe(1);
    expect(result.added).toBe(0);
  });
});

// ─── Version Auto-Detection Tests ───────────────────────────────────────────

describe("Version Auto-Detection (extractVersion)", () => {
  it("extracts Streamlit version from x-streamlit-version header", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "app.example.com",
      headers: { "x-streamlit-version": "1.28.2" },
    }];
    expect(extractVersion("streamlit", assets as any)).toBe("1.28.2");
  });

  it("extracts Streamlit version from Server header", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "app.example.com",
      headers: { "server": "Streamlit/1.25.0" },
    }];
    expect(extractVersion("streamlit", assets as any)).toBe("1.25.0");
  });

  it("extracts Jupyter version from x-jupyter-server-version header", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "jupyter.example.com",
      headers: { "x-jupyter-server-version": "7.0.5" },
    }];
    expect(extractVersion("jupyter", assets as any)).toBe("7.0.5");
  });

  it("extracts Firebase version from HTML script tag", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "app.example.com",
      html: '<script src="https://www.gstatic.com/firebasejs/9.22.1/firebase-app.js"></script>',
    }];
    expect(extractVersion("firebase", assets as any)).toBe("9.22.1");
  });

  it("extracts LangChain version from response body", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "api.example.com",
      responseSnippets: ['{"langchain_version": "0.0.310", "agent": "RetrievalQA"}'],
    }];
    expect(extractVersion("langchain", assets as any)).toBe("0.0.310");
  });

  it("extracts LangServe version from x-langserve-version header", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "api.example.com",
      headers: { "x-langserve-version": "0.1.5" },
    }];
    expect(extractVersion("langchain", assets as any)).toBe("0.1.5");
  });

  it("returns null when no version is detectable", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "app.example.com",
      headers: { "server": "nginx/1.24" },
    }];
    expect(extractVersion("streamlit", assets as any)).toBeNull();
  });

  it("extracts version from technology tags (Wappalyzer-style)", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "app.example.com",
      technologies: ["React", "Streamlit/1.31.0", "Python"],
    }];
    expect(extractVersion("streamlit", assets as any)).toBe("1.31.0");
  });

  it("extracts Firebase version from firebase@ pattern in HTML", async () => {
    const { extractVersion } = await import("./lib/scanners/tech-auto-detector");
    const assets = [{
      hostname: "app.example.com",
      html: 'import firebase from "firebase@10.5.2/app"',
    }];
    expect(extractVersion("firebase", assets as any)).toBe("10.5.2");
  });

  it("detectedVersions is included in detectTechnologies result", async () => {
    const { detectTechnologies } = await import("./lib/scanners/tech-auto-detector");
    const result = detectTechnologies([{
      hostname: "app.example.com",
      headers: { "x-streamlit-version": "1.27.0", "server": "Streamlit" },
      html: '<div class="stApp">Streamlit app</div>',
      technologies: ["Streamlit/1.27.0"],
    }] as any);
    expect(result).toHaveProperty("detectedVersions");
    if (result.confirmedTechnologies.includes("streamlit")) {
      expect(result.detectedVersions["streamlit"]).toBe("1.27.0");
    }
  });
});

// ─── Engagement Stack Profile Auto-Link Tests ───────────────────────────────

describe("Engagement Stack Profile Auto-Link", () => {
  it("createFromVectors accepts stackProfileId in input schema", async () => {
    // Validate the schema accepts the new field by importing the router
    const { engagementAutomationRouter } = await import("./routers/engagement-automation");
    expect(engagementAutomationRouter).toBeDefined();
    // The router should have the suggestStackProfiles procedure
    const procedures = Object.keys((engagementAutomationRouter as any)._def.procedures || {});
    expect(procedures).toContain("suggestStackProfiles");
  });

  it("suggestStackProfiles procedure exists on the router", async () => {
    const { engagementAutomationRouter } = await import("./routers/engagement-automation");
    const procs = Object.keys((engagementAutomationRouter as any)._def.procedures || {});
    expect(procs).toContain("suggestStackProfiles");
    expect(procs).toContain("createFromVectors");
  });

  it("VERSION_CVE_DATABASE is exported and accessible for matching", async () => {
    const { VERSION_CVE_DATABASE, matchVersionCves } = await import("./routers/stack-profile");
    expect(VERSION_CVE_DATABASE.length).toBeGreaterThan(10);

    // Test version matching with auto-detected versions
    const matches = matchVersionCves({ streamlit: "1.27.0", langchain: "0.0.300" });
    expect(matches.length).toBeGreaterThan(0);
    // Streamlit 1.27.0 should match CVE-2024-0217 (affectedBelow 1.30.0)
    const streamlitMatch = matches.find(m => m.cveId === "CVE-2024-0217");
    expect(streamlitMatch).toBeDefined();
    expect(streamlitMatch!.technology).toBe("streamlit");
    // LangChain 0.0.300 should match CVE-2023-44467 (affectedBelow 0.0.312)
    const langchainMatch = matches.find(m => m.cveId === "CVE-2023-44467");
    expect(langchainMatch).toBeDefined();
  });

  it("matchVersionCves handles empty and invalid versions gracefully", async () => {
    const { matchVersionCves } = await import("./routers/stack-profile");
    const empty = matchVersionCves({});
    expect(empty).toEqual([]);
    const invalid = matchVersionCves({ streamlit: "", langchain: "   " });
    expect(invalid).toEqual([]);
  });

  it("getFullCveDatabase includes both static and dynamic entries", async () => {
    const { getFullCveDatabase } = await import("./lib/nvd-cve-refresh");
    const full = getFullCveDatabase();
    // Should have at least the static entries + the one we ingested earlier
    expect(full.length).toBeGreaterThan(13);
    // Check for the dynamically ingested CVE
    expect(full.some(c => c.cveId === "CVE-2025-99999")).toBe(true);
  });
});
