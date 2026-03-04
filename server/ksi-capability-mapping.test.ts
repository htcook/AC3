import { describe, it, expect } from "vitest";

/**
 * Tests to verify KSI capability mapping accuracy.
 * Ensures the ksi-labels utility has complete and correct data
 * for all FedRAMP 20x themes and KSI definitions.
 */

import {
  getKsiLabel,
  getThemeLabel,
  getThemeFromKsiId,
  formatKsiId,
  KSI_TITLES,
  THEME_LABELS,
} from "../client/src/lib/ksi-labels";

describe("KSI Capability Mapping Accuracy", () => {
  describe("KSI Catalog Completeness", () => {
    it("should have 70+ KSI definitions in the labels utility", () => {
      const ksiCount = Object.keys(KSI_TITLES).length;
      expect(ksiCount).toBeGreaterThanOrEqual(70);
    });

    it("should have 13 theme labels matching FedRAMP 20x themes", () => {
      const themeCount = Object.keys(THEME_LABELS).length;
      expect(themeCount).toBe(13);
    });

    it("should include all 13 FedRAMP 20x theme codes", () => {
      const expectedThemes = [
        "AFR", "CMT", "CNA", "CED", "IAM",
        "INR", "MLA", "PIY", "RPL", "SVC",
        "SCR", "SDE", "PPM"
      ];
      for (const theme of expectedThemes) {
        expect(THEME_LABELS[theme]).toBeDefined();
        expect(THEME_LABELS[theme].length).toBeGreaterThan(0);
      }
    });

    it("should return proper titles for known KSI IDs", () => {
      expect(getKsiLabel("KSI-IAM-MFA")).toContain("MFA");
      expect(getKsiLabel("KSI-SVC-VCM")).toContain("Vulnerabilit");
      expect(getKsiLabel("KSI-CNA-RNT")).toContain("Network");
      expect(getKsiLabel("KSI-INR-IRP")).toContain("Incident");
    });

    it("should return proper labels for all 13 themes", () => {
      expect(getThemeLabel("AFR")).toContain("Authorization");
      expect(getThemeLabel("CMT")).toContain("Change");
      expect(getThemeLabel("CNA")).toContain("Cloud");
      expect(getThemeLabel("CED")).toContain("Education");
      expect(getThemeLabel("IAM")).toContain("Identity");
      expect(getThemeLabel("INR")).toContain("Incident");
      expect(getThemeLabel("MLA")).toContain("Monitoring");
      expect(getThemeLabel("PIY")).toContain("Policy");
      expect(getThemeLabel("RPL")).toContain("Recovery");
      expect(getThemeLabel("SVC")).toContain("Service");
      expect(getThemeLabel("SCR")).toContain("Supply Chain");
      expect(getThemeLabel("SDE")).toContain("Secure Dev");
      expect(getThemeLabel("PPM")).toContain("Policy");
    });
  });

  describe("Coverage Level Integrity", () => {
    it("should have KSIs distributed across all 13 themes", () => {
      const themeCounts: Record<string, number> = {};
      for (const ksiId of Object.keys(KSI_TITLES)) {
        const theme = getThemeFromKsiId(ksiId);
        themeCounts[theme] = (themeCounts[theme] || 0) + 1;
      }
      const expectedThemes = [
        "AFR", "CMT", "CNA", "CED", "IAM",
        "INR", "MLA", "PIY", "RPL", "SVC",
        "SCR", "SDE", "PPM"
      ];
      for (const theme of expectedThemes) {
        expect(themeCounts[theme]).toBeGreaterThanOrEqual(1);
      }
    });

    it("should not have any KSI ID without a title", () => {
      for (const [ksiId, title] of Object.entries(KSI_TITLES)) {
        expect(title).toBeTruthy();
        expect(title.length).toBeGreaterThan(3);
        // KSI IDs follow the pattern KSI-XXX-YYY
        expect(ksiId).toMatch(/^KSI-[A-Z]{2,3}-[A-Z]{2,4}$/);
      }
    });

    it("should format KSI IDs correctly", () => {
      const formatted = formatKsiId("KSI-IAM-MFA");
      expect(formatted).toContain("KSI-IAM-MFA");
      expect(formatted).toContain("—");
      expect(formatted).toContain("MFA");
    });

    it("should extract theme codes from KSI IDs", () => {
      expect(getThemeFromKsiId("KSI-IAM-MFA")).toBe("IAM");
      expect(getThemeFromKsiId("KSI-AFR-ADS")).toBe("AFR");
      expect(getThemeFromKsiId("KSI-SCR-PEN")).toBe("SCR");
    });
  });

  describe("Data Consistency", () => {
    it("every KSI should belong to a known theme", () => {
      for (const ksiId of Object.keys(KSI_TITLES)) {
        const theme = getThemeFromKsiId(ksiId);
        expect(THEME_LABELS[theme]).toBeDefined();
      }
    });

    it("should return the raw code for unknown themes", () => {
      expect(getThemeLabel("UNKNOWN")).toBe("UNKNOWN");
    });

    it("should return the raw ID for unknown KSIs", () => {
      expect(getKsiLabel("KSI-ZZZ-XXX")).toBe("KSI-ZZZ-XXX");
    });
  });
});
