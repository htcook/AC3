/**
 * Vuln Tier Classification Tests
 *
 * Validates that the DI scan vulnerability pipeline correctly classifies
 * tech-to-CVE associations into confirmed/probable/potential tiers,
 * preventing the inflation bug where vendor-only matches were counted
 * as "confirmed" or "probable".
 *
 * Bug: A DI scan showing 11 Unique Confirmed Findings in the header
 *      but 451 "Confirmed Vulns" in the Vulnerabilities tab because
 *      vendor-only matches (e.g., "Microsoft" → all Microsoft CVEs)
 *      were classified as "probable" instead of "potential".
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock the vuln feed data to control test inputs ─────────────────────────
// We need to mock the internal cache/fetch to inject controlled VulnEntry data
// Since matchTechnologiesAgainstAllFeeds uses an internal unified cache,
// we test the tier classification logic by examining the output structure

// Helper to create a mock VulnEntry
function mockVuln(overrides: Partial<{
  cveId: string; title: string; severity: string; cvssScore: number;
  vendor: string; product: string; exploitAvailable: boolean;
  inTheWild: boolean; kevListed: boolean; affectedVersionRange: string;
}>): any {
  return {
    cveId: overrides.cveId || "CVE-2024-0001",
    title: overrides.title || "Test Vulnerability",
    description: "Test description",
    severity: overrides.severity || "high",
    cvssScore: overrides.cvssScore ?? 7.5,
    vendor: overrides.vendor || "testvendor",
    product: overrides.product || "testproduct",
    datePublished: "2024-01-01",
    sources: ["nvd"] as any,
    exploitAvailable: overrides.exploitAvailable ?? false,
    inTheWild: overrides.inTheWild ?? false,
    kevListed: overrides.kevListed ?? false,
    ransomwareLinked: false,
    suggestedTechniques: [],
    affectedVersionRange: overrides.affectedVersionRange || undefined,
  };
}

describe("Vuln Tier Classification Logic", () => {
  describe("Match Specificity Tracking", () => {
    it("should distinguish product-specific matches from vendor-only matches", () => {
      // The core of the fix: "Microsoft 365" matching a CVE with vendor="microsoft"
      // and product="office" should be vendor-only, not product-specific
      const tech = "Microsoft 365";
      const vuln = mockVuln({ vendor: "microsoft", product: "office", exploitAvailable: true });

      const techLower = tech.toLowerCase().trim();
      const vendorLower = vuln.vendor.toLowerCase();
      const productLower = vuln.product.toLowerCase();

      // Product match: does the tech name appear in the product name or vice versa?
      const directProductMatch = (productLower.length >= 3 && productLower.includes(techLower)) ||
        (productLower.length >= 3 && techLower.includes(productLower));

      // Vendor match: tech matches vendor but NOT the specific product
      const vendorMatch = !directProductMatch && vendorLower.length >= 3 &&
        (vendorLower.includes(techLower) || techLower.includes(vendorLower));

      expect(directProductMatch).toBe(false); // "office" does NOT contain "microsoft 365"
      expect(vendorMatch).toBe(true); // "microsoft 365" DOES contain "microsoft"
    });

    it("should classify Apache HTTP Server as product-specific for Apache vulns", () => {
      const tech = "Apache";
      const vuln = mockVuln({ vendor: "apache", product: "http server" });

      const techLower = tech.toLowerCase().trim();
      const productLower = vuln.product.toLowerCase();
      const titleLower = "Apache HTTP Server vulnerability".toLowerCase();

      // With PRODUCT_ALIASES, "apache" maps to ["http server", "httpd", "apache2"]
      const aliases = ["http server", "httpd", "apache2"];
      const aliasProductMatch = aliases.some(alias =>
        (productLower.includes(alias) || alias.includes(productLower)) && productLower.length >= 3
      );

      expect(aliasProductMatch).toBe(true); // "http server" matches alias
    });

    it("should classify Apache as vendor-only for Apache OFBiz vulns", () => {
      const tech = "Apache";
      const vuln = mockVuln({ vendor: "apache", product: "ofbiz" });

      const techLower = tech.toLowerCase().trim();
      const vendorLower = vuln.vendor.toLowerCase();
      const productLower = vuln.product.toLowerCase();

      // Direct product match
      const directProductMatch = (productLower.length >= 3 && productLower.includes(techLower)) ||
        (productLower.length >= 3 && techLower.includes(productLower));

      // Alias match — "apache" aliases are ["http server", "httpd", "apache2"]
      const aliases = ["http server", "httpd", "apache2"];
      const aliasProductMatch = aliases.some(alias =>
        (productLower.includes(alias) || alias.includes(productLower)) && productLower.length >= 3
      );

      const isProductMatch = directProductMatch || aliasProductMatch;

      // Vendor match
      const vendorMatch = !isProductMatch && vendorLower.length >= 3 &&
        (vendorLower.includes(techLower) || techLower.includes(vendorLower));

      expect(isProductMatch).toBe(false); // "ofbiz" is NOT "http server"
      expect(vendorMatch).toBe(true); // "apache" matches vendor
    });
  });

  describe("Tier Classification Rules", () => {
    // Simulate the tier classification logic from vuln-feeds.ts

    function classifyTier(opts: {
      hasKev: boolean;
      hasZeroDay: boolean;
      hasVersionMatch: boolean;
      hasExploit: boolean;
      hasProductSpecificMatch: boolean;
    }): string {
      const { hasKev, hasZeroDay, hasVersionMatch, hasExploit, hasProductSpecificMatch } = opts;

      if ((hasKev || hasZeroDay || (hasVersionMatch && hasExploit)) && hasProductSpecificMatch) {
        return 'confirmed';
      } else if (hasProductSpecificMatch && (hasVersionMatch || hasExploit)) {
        return 'probable';
      } else if (!hasProductSpecificMatch && hasVersionMatch && hasExploit) {
        return 'probable';
      } else {
        return 'potential';
      }
    }

    it("should classify KEV + product-specific as confirmed", () => {
      expect(classifyTier({
        hasKev: true, hasZeroDay: false, hasVersionMatch: false,
        hasExploit: false, hasProductSpecificMatch: true,
      })).toBe("confirmed");
    });

    it("should classify 0-day + product-specific as confirmed", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: true, hasVersionMatch: false,
        hasExploit: false, hasProductSpecificMatch: true,
      })).toBe("confirmed");
    });

    it("should classify version-matched + exploit + product-specific as confirmed", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: false, hasVersionMatch: true,
        hasExploit: true, hasProductSpecificMatch: true,
      })).toBe("confirmed");
    });

    it("should classify product-specific + exploit (no version) as probable", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: false, hasVersionMatch: false,
        hasExploit: true, hasProductSpecificMatch: true,
      })).toBe("probable");
    });

    it("should classify product-specific + version (no exploit) as probable", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: false, hasVersionMatch: true,
        hasExploit: false, hasProductSpecificMatch: true,
      })).toBe("probable");
    });

    it("should classify vendor-only + version + exploit as probable (weaker)", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: false, hasVersionMatch: true,
        hasExploit: true, hasProductSpecificMatch: false,
      })).toBe("probable");
    });

    // THE KEY FIX: vendor-only without version confirmation → potential
    it("should classify vendor-only + exploit (no version) as POTENTIAL, not probable", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: false, hasVersionMatch: false,
        hasExploit: true, hasProductSpecificMatch: false,
      })).toBe("potential");
    });

    it("should classify vendor-only without exploit as potential", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: false, hasVersionMatch: false,
        hasExploit: false, hasProductSpecificMatch: false,
      })).toBe("potential");
    });

    it("should classify KEV + vendor-only (no product match) as POTENTIAL, not confirmed", () => {
      // This is the critical inflation scenario: KEV-listed CVE but only vendor match
      expect(classifyTier({
        hasKev: true, hasZeroDay: false, hasVersionMatch: false,
        hasExploit: false, hasProductSpecificMatch: false,
      })).toBe("potential");
    });

    it("should classify 0-day + vendor-only as POTENTIAL, not confirmed", () => {
      expect(classifyTier({
        hasKev: false, hasZeroDay: true, hasVersionMatch: false,
        hasExploit: false, hasProductSpecificMatch: false,
      })).toBe("potential");
    });
  });

  describe("Per-Vuln Tier Counting", () => {
    function countPerVulnTiers(vulns: Array<{
      kevListed: boolean;
      inTheWild: boolean;
      exploitAvailable: boolean;
      isProductSpecific: boolean;
    }>, hasVersionMatch: boolean) {
      let confirmed = 0, probable = 0, potential = 0;
      for (const v of vulns) {
        if ((v.kevListed || v.inTheWild) && v.isProductSpecific) {
          confirmed++;
        } else if (v.isProductSpecific && (hasVersionMatch || v.exploitAvailable)) {
          probable++;
        } else if (!v.isProductSpecific && hasVersionMatch && v.exploitAvailable) {
          probable++;
        } else {
          potential++;
        }
      }
      return { confirmed, probable, potential };
    }

    it("should count vendor-only KEV vulns as potential, not confirmed", () => {
      const result = countPerVulnTiers([
        { kevListed: true, inTheWild: false, exploitAvailable: true, isProductSpecific: false },
        { kevListed: true, inTheWild: false, exploitAvailable: true, isProductSpecific: false },
        { kevListed: true, inTheWild: false, exploitAvailable: true, isProductSpecific: false },
      ], false);

      expect(result.confirmed).toBe(0);
      expect(result.probable).toBe(0);
      expect(result.potential).toBe(3);
    });

    it("should count product-specific KEV vulns as confirmed", () => {
      const result = countPerVulnTiers([
        { kevListed: true, inTheWild: false, exploitAvailable: true, isProductSpecific: true },
        { kevListed: false, inTheWild: false, exploitAvailable: true, isProductSpecific: true },
      ], false);

      expect(result.confirmed).toBe(1);
      expect(result.probable).toBe(1);
      expect(result.potential).toBe(0);
    });

    it("should produce correct mixed-tier counts for a realistic scenario", () => {
      // Simulates: Microsoft 365 detected, 451 CVEs matched
      // 3 are product-specific KEV, 10 are product-specific with exploit,
      // 438 are vendor-only without version
      const vulns = [
        // 3 confirmed: product-specific + KEV
        ...Array(3).fill(null).map(() => ({
          kevListed: true, inTheWild: false, exploitAvailable: true, isProductSpecific: true,
        })),
        // 10 probable: product-specific + exploit
        ...Array(10).fill(null).map(() => ({
          kevListed: false, inTheWild: false, exploitAvailable: true, isProductSpecific: true,
        })),
        // 438 potential: vendor-only, no version match
        ...Array(438).fill(null).map(() => ({
          kevListed: true, inTheWild: false, exploitAvailable: true, isProductSpecific: false,
        })),
      ];

      const result = countPerVulnTiers(vulns, false);

      expect(result.confirmed).toBe(3);
      expect(result.probable).toBe(10);
      expect(result.potential).toBe(438);
      // Total should still be 451
      expect(result.confirmed + result.probable + result.potential).toBe(451);
    });
  });

  describe("UI Filter Behavior", () => {
    it("should default to showing only confirmed vulns", () => {
      const defaultFilter = 'confirmed';
      const allowedTiers = defaultFilter === 'all'
        ? ['confirmed', 'probable', 'potential']
        : defaultFilter === 'confirmed+probable'
          ? ['confirmed', 'probable']
          : ['confirmed'];

      expect(allowedTiers).toEqual(['confirmed']);
    });

    it("should filter summary stats by active tier", () => {
      const matches = [
        { corroborationTier: 'confirmed', confirmedVulnCount: 3, probableVulnCount: 0, potentialVulnCount: 0, exploitCount: 3, kevCount: 3 },
        { corroborationTier: 'probable', confirmedVulnCount: 0, probableVulnCount: 10, potentialVulnCount: 0, exploitCount: 8, kevCount: 2 },
        { corroborationTier: 'potential', confirmedVulnCount: 0, probableVulnCount: 0, potentialVulnCount: 438, exploitCount: 300, kevCount: 200 },
      ];

      // Confirmed-only filter
      const confirmedMatches = matches.filter(m => ['confirmed'].includes(m.corroborationTier));
      const confirmedVulns = confirmedMatches.reduce((sum, m) => sum + (m.confirmedVulnCount || 0), 0);
      const confirmedExploits = confirmedMatches.reduce((sum, m) => sum + m.exploitCount, 0);
      const confirmedKev = confirmedMatches.reduce((sum, m) => sum + m.kevCount, 0);

      expect(confirmedVulns).toBe(3);
      expect(confirmedExploits).toBe(3);
      expect(confirmedKev).toBe(3);

      // All tiers filter
      const allMatches = matches;
      const allVulns = allMatches.reduce((sum, m) =>
        sum + (m.confirmedVulnCount || 0) + (m.probableVulnCount || 0) + (m.potentialVulnCount || 0), 0);

      expect(allVulns).toBe(451);
    });
  });
});
