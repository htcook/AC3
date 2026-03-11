import { describe, it, expect, beforeAll } from "vitest";

/**
 * Tests for the KSI enriched data module.
 * We import the client-side module directly since it's pure data with no React dependencies.
 */

// We test the data structure by importing the raw TS file
// Since the enriched data is a client module, we test its structure here
describe("KSI Enriched Data", () => {
  // Dynamic import since it's a client module
  let mod: any;

  beforeAll(async () => {
    // Import the module - vitest can handle TS imports
    mod = await import("../client/src/lib/ksi-enriched-data");
  });

  it("exports ALL_ENRICHED_KSIS with 75 entries", () => {
    expect(mod.ALL_ENRICHED_KSIS).toBeDefined();
    expect(Array.isArray(mod.ALL_ENRICHED_KSIS)).toBe(true);
    expect(mod.ALL_ENRICHED_KSIS.length).toBe(75);
  });

  it("exports ALL_ENRICHED_THEMES with 13 entries", () => {
    expect(mod.ALL_ENRICHED_THEMES).toBeDefined();
    expect(Array.isArray(mod.ALL_ENRICHED_THEMES)).toBe(true);
    expect(mod.ALL_ENRICHED_THEMES.length).toBe(13);
  });

  it("every KSI has required fields", () => {
    for (const ksi of mod.ALL_ENRICHED_KSIS) {
      expect(ksi.id).toBeTruthy();
      expect(ksi.name).toBeTruthy();
      expect(ksi.themeCode).toBeTruthy();
      expect(["direct", "supporting", "planned"]).toContain(ksi.coverageLevel);
      expect(ksi.requirement).toBeTruthy();
      expect(ksi.howAceC3Delivers).toBeTruthy();
      expect(Array.isArray(ksi.aceModules)).toBe(true);
      // Planned KSIs may have empty aceModules and evidenceTypes
      if (ksi.coverageLevel !== "planned") {
        expect(ksi.aceModules.length).toBeGreaterThan(0);
      }
      expect(Array.isArray(ksi.evidenceTypes)).toBe(true);
      if (ksi.coverageLevel !== "planned") {
        expect(ksi.evidenceTypes.length).toBeGreaterThan(0);
      }
    }
  });

  it("every AceC3Module has name and role", () => {
    for (const ksi of mod.ALL_ENRICHED_KSIS) {
      for (const m of ksi.aceModules) {
        expect(m.name).toBeTruthy();
        expect(m.role).toBeTruthy();
      }
    }
  });

  it("every theme has required fields", () => {
    for (const theme of mod.ALL_ENRICHED_THEMES) {
      expect(theme.code).toBeTruthy();
      expect(theme.name).toBeTruthy();
      expect(theme.description).toBeTruthy();
      // howAceC3Addresses may be on the theme or not depending on structure
      // The key fields are code, name, description
      expect(typeof theme.code).toBe("string");
    }
  });

  it("getKsiEnriched returns correct KSI by ID", () => {
    const ksi = mod.getKsiEnriched("KSI-AFR-PVA");
    expect(ksi).toBeDefined();
    expect(ksi.name).toBe("Periodic Vulnerability Assessment");
    expect(ksi.themeCode).toBe("AFR");
    expect(ksi.coverageLevel).toBe("direct");
  });

  it("getKsiEnriched returns undefined for unknown ID", () => {
    const ksi = mod.getKsiEnriched("KSI-FAKE-001");
    expect(ksi).toBeUndefined();
  });

  it("getThemeEnriched returns correct theme by code", () => {
    const theme = mod.getThemeEnriched("AFR");
    expect(theme).toBeDefined();
    expect(theme.name).toBe("Authorization by FedRAMP");
  });

  it("getKsisByTheme returns all KSIs for a given theme", () => {
    const afrKsis = mod.getKsisByTheme("AFR");
    expect(afrKsis.length).toBe(8);
    for (const ksi of afrKsis) {
      expect(ksi.themeCode).toBe("AFR");
    }
  });

  it("getCoverageBadgeClass returns valid CSS classes", () => {
    expect(mod.getCoverageBadgeClass("direct")).toContain("emerald");
    expect(mod.getCoverageBadgeClass("supporting")).toContain("amber");
    expect(mod.getCoverageBadgeClass("planned")).toContain("slate");
  });

  it("KSI_STATS has correct totals", () => {
    expect(mod.KSI_STATS).toBeDefined();
    expect(mod.KSI_STATS.total).toBe(75);
    expect(mod.KSI_STATS.direct + mod.KSI_STATS.supporting + mod.KSI_STATS.planned).toBe(75);
  });

  it("all 13 theme codes are represented in KSIs", () => {
    const themeCodes = new Set(mod.ALL_ENRICHED_KSIS.map((k: any) => k.themeCode));
    expect(themeCodes.size).toBe(13);
    const expectedCodes = ["AFR", "CMT", "CNA", "CED", "IAM", "INR", "MLA", "PIY", "RPL", "SVC", "SCR", "SDE", "PPM"];
    for (const code of expectedCodes) {
      expect(themeCodes.has(code)).toBe(true);
    }
  });

  it("KSI IDs follow the expected format KSI-XXX-YYY", () => {
    for (const ksi of mod.ALL_ENRICHED_KSIS) {
      expect(ksi.id).toMatch(/^KSI-[A-Z]{3}-[A-Z]{3}$/);
    }
  });

  it("no duplicate KSI IDs exist", () => {
    const ids = mod.ALL_ENRICHED_KSIS.map((k: any) => k.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});
