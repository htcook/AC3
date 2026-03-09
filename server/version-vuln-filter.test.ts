import { describe, it, expect } from "vitest";
import { isVersionAffected, filterCvesByVersion } from "./lib/dynamic-cpe-matcher";

describe("Version-Aware Vulnerability Filtering", () => {
  describe("isVersionAffected", () => {
    it("returns true when no version range is provided (can't exclude)", () => {
      expect(isVersionAffected("2.4.49", null)).toBe(true);
    });

    it("returns true when version can't be parsed (assume affected)", () => {
      expect(isVersionAffected("unknown", ">= 1.0.0, < 3.0.0")).toBe(true);
    });

    it("returns true when version is within range (>= start, < end)", () => {
      expect(isVersionAffected("2.4.49", ">= 2.0.0, < 2.5.0")).toBe(true);
    });

    it("returns false when version is below the start of range", () => {
      expect(isVersionAffected("1.9.0", ">= 2.0.0, < 2.5.0")).toBe(false);
    });

    it("returns false when version is at or above the exclusive end", () => {
      expect(isVersionAffected("2.5.0", ">= 2.0.0, < 2.5.0")).toBe(false);
    });

    it("returns true when version equals inclusive end", () => {
      expect(isVersionAffected("2.5.0", ">= 2.0.0, <= 2.5.0")).toBe(true);
    });

    it("returns false when version is above inclusive end", () => {
      expect(isVersionAffected("2.6.0", ">= 2.0.0, <= 2.5.0")).toBe(false);
    });

    it("handles single upper bound (< only)", () => {
      expect(isVersionAffected("1.18.0", "< 1.19.0")).toBe(true);
      expect(isVersionAffected("1.19.0", "< 1.19.0")).toBe(false);
      expect(isVersionAffected("1.20.0", "< 1.19.0")).toBe(false);
    });

    it("handles single lower bound (>= only)", () => {
      expect(isVersionAffected("2.0.0", ">= 2.0.0")).toBe(true);
      expect(isVersionAffected("1.9.9", ">= 2.0.0")).toBe(false);
    });

    it("handles exact version match (= operator)", () => {
      expect(isVersionAffected("2.4.49", "= 2.4.49")).toBe(true);
      expect(isVersionAffected("2.4.50", "= 2.4.49")).toBe(false);
    });

    it("handles real-world Apache 2.4.49 CVE range", () => {
      // CVE-2021-41773 affects Apache 2.4.49 only
      expect(isVersionAffected("2.4.49", ">= 2.4.49, <= 2.4.49")).toBe(true);
      expect(isVersionAffected("2.4.48", ">= 2.4.49, <= 2.4.49")).toBe(false);
      expect(isVersionAffected("2.4.50", ">= 2.4.49, <= 2.4.49")).toBe(false);
    });

    it("handles nginx version ranges", () => {
      // e.g., nginx vuln affecting < 1.21.0
      expect(isVersionAffected("1.18.0", "< 1.21.0")).toBe(true);
      expect(isVersionAffected("1.21.0", "< 1.21.0")).toBe(false);
      expect(isVersionAffected("1.22.0", "< 1.21.0")).toBe(false);
    });
  });

  describe("filterCvesByVersion", () => {
    const mockCves = [
      {
        cveId: "CVE-2021-44228",
        description: "Log4Shell",
        cvssV3Score: 10.0,
        severity: "critical" as const,
        attackVector: "NETWORK",
        attackComplexity: "LOW",
        published: "2021-12-10",
        exploitabilityScore: 3.9,
        impactScore: 6.0,
        affectedVersionRange: ">= 2.0.0, < 2.15.0",
      },
      {
        cveId: "CVE-2021-45046",
        description: "Log4j follow-up",
        cvssV3Score: 9.0,
        severity: "critical" as const,
        attackVector: "NETWORK",
        attackComplexity: "HIGH",
        published: "2021-12-14",
        exploitabilityScore: 2.2,
        impactScore: 6.0,
        affectedVersionRange: ">= 2.0.0, < 2.16.0",
      },
      {
        cveId: "CVE-2022-99999",
        description: "Hypothetical old vuln",
        cvssV3Score: 7.5,
        severity: "high" as const,
        attackVector: "NETWORK",
        attackComplexity: "LOW",
        published: "2022-01-01",
        exploitabilityScore: 3.9,
        impactScore: 3.6,
        affectedVersionRange: ">= 1.0.0, < 1.5.0",
      },
      {
        cveId: "CVE-2023-00001",
        description: "No version range data",
        cvssV3Score: 6.0,
        severity: "medium" as const,
        attackVector: "NETWORK",
        attackComplexity: "LOW",
        published: "2023-01-01",
        exploitabilityScore: 3.9,
        impactScore: 2.5,
        affectedVersionRange: null,
      },
    ];

    it("filters out CVEs that don't affect the detected version", () => {
      // Version 2.14.1 should match Log4Shell and follow-up, but NOT the old vuln
      const filtered = filterCvesByVersion(mockCves, "2.14.1");
      expect(filtered.map(c => c.cveId)).toContain("CVE-2021-44228");
      expect(filtered.map(c => c.cveId)).toContain("CVE-2021-45046");
      expect(filtered.map(c => c.cveId)).not.toContain("CVE-2022-99999");
      // CVE with no version range should be kept
      expect(filtered.map(c => c.cveId)).toContain("CVE-2023-00001");
    });

    it("filters out Log4Shell for patched version 2.17.0", () => {
      const filtered = filterCvesByVersion(mockCves, "2.17.0");
      expect(filtered.map(c => c.cveId)).not.toContain("CVE-2021-44228");
      expect(filtered.map(c => c.cveId)).not.toContain("CVE-2021-45046");
      // No version range = kept
      expect(filtered.map(c => c.cveId)).toContain("CVE-2023-00001");
    });

    it("keeps CVEs with no version range (can't exclude)", () => {
      const filtered = filterCvesByVersion(mockCves, "99.99.99");
      // Only the one with no range should remain (all others have ranges that exclude 99.x)
      expect(filtered.map(c => c.cveId)).toContain("CVE-2023-00001");
      expect(filtered.length).toBe(1);
    });

    it("keeps all CVEs when version is within all ranges", () => {
      // Version 1.2.0 is within the old vuln range
      const filtered = filterCvesByVersion(mockCves, "1.2.0");
      expect(filtered.map(c => c.cveId)).toContain("CVE-2022-99999");
      expect(filtered.map(c => c.cveId)).toContain("CVE-2023-00001");
      // But NOT Log4Shell (requires >= 2.0.0)
      expect(filtered.map(c => c.cveId)).not.toContain("CVE-2021-44228");
    });
  });
});
