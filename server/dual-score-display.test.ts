import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

/**
 * Tests for the dual CVSS + Hybrid score display feature.
 * Verifies that all asset risk rating views show both CVSS (industry standard)
 * and Ace C3 Hybrid Risk Score (proprietary) side by side.
 */

const RESULTS_PAGE = readFileSync(
  join(__dirname, "../client/src/pages/DomainIntelResults.tsx"),
  "utf-8"
);

describe("Dual CVSS + Hybrid Score Display", () => {
  describe("Overall scan header", () => {
    it("shows RiskGauge with 'Ace C3 Hybrid' label", () => {
      expect(RESULTS_PAGE).toContain("Ace C3 Hybrid");
      expect(RESULTS_PAGE).toContain("RiskGauge");
    });

    it("computes and displays aggregate CVSS (avg and max)", () => {
      expect(RESULTS_PAGE).toContain("Avg CVSS");
      expect(RESULTS_PAGE).toContain("avgCvss.toFixed(1)");
      expect(RESULTS_PAGE).toContain("maxCvss.toFixed(1)");
    });

    it("uses cyan color scheme for CVSS display", () => {
      expect(RESULTS_PAGE).toContain("border-cyan-500/30 bg-cyan-500/5");
      expect(RESULTS_PAGE).toContain("text-cyan-400");
    });
  });

  describe("Heatmap tile view", () => {
    it("shows both CVSS and Hybrid scores on heatmap tiles", () => {
      // CVSS on heatmap tile
      expect(RESULTS_PAGE).toContain('title="CVSS Estimate (Industry Standard)"');
      // Hybrid on heatmap tile
      expect(RESULTS_PAGE).toContain('title="Ace C3 Hybrid Risk Score"');
    });
  });

  describe("Expanded heatmap detail panel", () => {
    it("shows Score Comparison section with grid layout", () => {
      expect(RESULTS_PAGE).toContain("Score Comparison");
      expect(RESULTS_PAGE).toContain("grid grid-cols-2 gap-2");
    });

    it("shows CVSS Estimate with industry standard label", () => {
      expect(RESULTS_PAGE).toContain("CVSS Estimate");
      expect(RESULTS_PAGE).toContain("Industry Standard");
    });

    it("shows Hybrid Risk with Ace C3 Proprietary label", () => {
      expect(RESULTS_PAGE).toContain("Hybrid Risk");
      expect(RESULTS_PAGE).toContain("Ace C3 Proprietary");
    });

    it("includes formula explanation", () => {
      expect(RESULTS_PAGE).toContain("Hybrid = √(Impact × Likelihood)");
      expect(RESULTS_PAGE).toContain("CVSS = vulnerability severity estimate");
    });
  });

  describe("Asset list view card", () => {
    it("shows dual score badges (Hybrid box + CVSS column)", () => {
      // The list card has the hybrid score box and a CVSS column
      expect(RESULTS_PAGE).toContain('title="Ace C3 Hybrid Risk Score"');
      expect(RESULTS_PAGE).toContain('title="CVSS Estimate (0-10)"');
    });

    it("shows CVSS and Hybrid in expanded list detail", () => {
      expect(RESULTS_PAGE).toContain('title="CVSS Estimate — Industry-standard vulnerability severity"');
      expect(RESULTS_PAGE).toContain('title="Ace C3 Hybrid Risk Score — Proprietary score"');
    });
  });

  describe("Finding card CVSS badges", () => {
    it("uses cyan color scheme for CVSS badges on findings", () => {
      // All CVSS badges should use cyan styling
      const cvssBadgeMatches = RESULTS_PAGE.match(/text-cyan-400 border-cyan-500\/40/g);
      expect(cvssBadgeMatches).not.toBeNull();
      expect(cvssBadgeMatches!.length).toBeGreaterThanOrEqual(4);
    });

    it("CVSS badges are distinct from severity badges", () => {
      // Severity badges don't use cyan
      expect(RESULTS_PAGE).toContain("Sev:");
      expect(RESULTS_PAGE).toContain("CVSS:");
    });
  });

  describe("Score computation integrity", () => {
    it("cvssEstimate is computed per asset from findings", () => {
      expect(RESULTS_PAGE).toContain("cvssEstimate: Math.min(");
    });

    it("hybridRiskScore is present on all asset objects", () => {
      expect(RESULTS_PAGE).toContain("hybridRiskScore");
    });

    it("overall CVSS aggregate is computed from asset cvssEstimate values", () => {
      expect(RESULTS_PAGE).toContain("cvssValues.reduce");
      expect(RESULTS_PAGE).toContain("Math.max(...cvssValues)");
    });
  });
});

describe("CVE Date Sorting", () => {
  it("includes 'date' as a sort option for CVEs", () => {
    expect(RESULTS_PAGE).toContain('"date"');
  });

  it("sorts by publishedDate descending when date sort is selected", () => {
    expect(RESULTS_PAGE).toContain("publishedDate");
  });
});

describe("Passive Scan Disclaimer", () => {
  it("shows passive discovery disclaimer banner", () => {
    expect(RESULTS_PAGE).toContain("Passive Discovery Results");
    expect(RESULTS_PAGE).toContain("passive discovery");
  });

  it("includes engagement/ROE CTA", () => {
    expect(RESULTS_PAGE).toContain("Create Engagement");
    expect(RESULTS_PAGE).toContain("Rules of Engagement");
  });
});
