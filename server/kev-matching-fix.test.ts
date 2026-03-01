import { describe, it, expect } from "vitest";
import { matchTechnologiesAgainstKev, type KevCatalog, type KevMatch } from "./lib/kev-service";

/**
 * Tests for KEV matching false positive reduction.
 * 
 * The core problem: detecting "Microsoft IIS" on a web server was matching against
 * ALL Microsoft KEV entries (SharePoint, Windows CLFS, Office, etc.) because the
 * old code used vendorMatch || productMatch. This generated 400+ false "confirmed"
 * findings per host.
 */

// Build a minimal KEV catalog for testing
function buildTestCatalog(entries: Array<{
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName?: string;
  knownRansomware?: boolean;
}>): KevCatalog {
  return {
    title: "Test KEV Catalog",
    catalogVersion: "2025.01.01",
    dateReleased: "2025-01-01",
    count: entries.length,
    vulnerabilities: entries.map(e => ({
      cveID: e.cveID,
      vendorProject: e.vendorProject,
      product: e.product,
      vulnerabilityName: e.vulnerabilityName || `${e.product} vulnerability`,
      shortDescription: `A vulnerability in ${e.vendorProject} ${e.product}`,
      dateAdded: "2025-01-01",
      dueDate: "2025-02-01",
      requiredAction: "Apply patch",
      knownRansomwareCampaignUse: e.knownRansomware ? "Known" : "Unknown",
      notes: "",
    })),
  };
}

describe("KEV Matching - False Positive Reduction", () => {
  const catalog = buildTestCatalog([
    // IIS-specific entries (should match when detecting IIS)
    { cveID: "CVE-2023-IIS-001", vendorProject: "Microsoft", product: "Internet Information Services" },
    { cveID: "CVE-2023-IIS-002", vendorProject: "Microsoft", product: "IIS" },
    // SharePoint entries (should NOT match when detecting IIS)
    { cveID: "CVE-2023-SP-001", vendorProject: "Microsoft", product: "SharePoint Server" },
    { cveID: "CVE-2023-SP-002", vendorProject: "Microsoft", product: "SharePoint" },
    // Windows entries (should NOT match when detecting IIS)
    { cveID: "CVE-2023-WIN-001", vendorProject: "Microsoft", product: "Windows" },
    { cveID: "CVE-2023-WIN-002", vendorProject: "Microsoft", product: "Windows CLFS Driver" },
    // Office entries (should NOT match when detecting IIS)
    { cveID: "CVE-2023-OFF-001", vendorProject: "Microsoft", product: "Office" },
    { cveID: "CVE-2023-OFF-002", vendorProject: "Microsoft", product: "Outlook" },
    // Exchange entries (should NOT match when detecting IIS)
    { cveID: "CVE-2023-EX-001", vendorProject: "Microsoft", product: "Exchange Server" },
    // Apache entries
    { cveID: "CVE-2023-APACHE-001", vendorProject: "Apache", product: "HTTP Server" },
    { cveID: "CVE-2023-TOMCAT-001", vendorProject: "Apache", product: "Tomcat" },
    { cveID: "CVE-2023-LOG4J-001", vendorProject: "Apache", product: "Log4j" },
    // Nginx entries
    { cveID: "CVE-2023-NGINX-001", vendorProject: "F5", product: "NGINX" },
    // Cisco entries
    { cveID: "CVE-2023-CISCO-001", vendorProject: "Cisco", product: "IOS" },
    { cveID: "CVE-2023-CISCO-002", vendorProject: "Cisco", product: "ASA" },
  ]);

  describe("IIS detection should only match IIS KEV entries", () => {
    it("should match IIS-specific KEV entries", () => {
      const matches = matchTechnologiesAgainstKev(["Microsoft IIS"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      // Should match IIS entries
      expect(matchedCves).toContain("CVE-2023-IIS-001");
      expect(matchedCves).toContain("CVE-2023-IIS-002");
    });

    it("should NOT match SharePoint KEV entries when only IIS is detected", () => {
      const matches = matchTechnologiesAgainstKev(["Microsoft IIS"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).not.toContain("CVE-2023-SP-001");
      expect(matchedCves).not.toContain("CVE-2023-SP-002");
    });

    it("should NOT match Windows KEV entries when only IIS is detected", () => {
      const matches = matchTechnologiesAgainstKev(["Microsoft IIS"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).not.toContain("CVE-2023-WIN-001");
      expect(matchedCves).not.toContain("CVE-2023-WIN-002");
    });

    it("should NOT match Office/Outlook/Exchange KEV entries when only IIS is detected", () => {
      const matches = matchTechnologiesAgainstKev(["Microsoft IIS"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).not.toContain("CVE-2023-OFF-001");
      expect(matchedCves).not.toContain("CVE-2023-OFF-002");
      expect(matchedCves).not.toContain("CVE-2023-EX-001");
    });

    it("should produce dramatically fewer matches than before (was 400+, now should be <10)", () => {
      const matches = matchTechnologiesAgainstKev(["Microsoft IIS"], catalog);
      // With the old code, IIS would match ALL Microsoft entries (9 in our test catalog)
      // With the fix, it should only match IIS-specific entries (2)
      expect(matches.length).toBeLessThanOrEqual(3);
    });
  });

  describe("SharePoint detection should only match SharePoint KEV entries", () => {
    it("should match SharePoint entries", () => {
      const matches = matchTechnologiesAgainstKev(["SharePoint"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).toContain("CVE-2023-SP-001");
      expect(matchedCves).toContain("CVE-2023-SP-002");
    });

    it("should NOT match IIS entries when only SharePoint is detected", () => {
      const matches = matchTechnologiesAgainstKev(["SharePoint"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).not.toContain("CVE-2023-IIS-001");
    });
  });

  describe("Apache detection should match only Apache HTTP Server entries", () => {
    it("should match Apache HTTP Server entries", () => {
      const matches = matchTechnologiesAgainstKev(["Apache"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).toContain("CVE-2023-APACHE-001");
    });

    it("should NOT match Tomcat and Log4j (separate product families)", () => {
      const matches = matchTechnologiesAgainstKev(["Apache"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      // Apache maps to products: ["http server", "httpd"] only — Tomcat/Log4j are separate patterns
      expect(matchedCves).not.toContain("CVE-2023-TOMCAT-001");
      expect(matchedCves).not.toContain("CVE-2023-LOG4J-001");
    });

    it("should match Tomcat when explicitly detected", () => {
      const matches = matchTechnologiesAgainstKev(["Tomcat"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      expect(matchedCves).toContain("CVE-2023-TOMCAT-001");
    });

    it("should match Log4j when explicitly detected", () => {
      const matches = matchTechnologiesAgainstKev(["Log4j"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      expect(matchedCves).toContain("CVE-2023-LOG4J-001");
    });
  });

  describe("Nginx detection should match Nginx entries", () => {
    it("should match NGINX entries", () => {
      const matches = matchTechnologiesAgainstKev(["nginx"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).toContain("CVE-2023-NGINX-001");
    });

    it("should NOT match Cisco entries", () => {
      const matches = matchTechnologiesAgainstKev(["nginx"], catalog);
      const matchedCves = matches.map(m => m.cveID);
      
      expect(matchedCves).not.toContain("CVE-2023-CISCO-001");
      expect(matchedCves).not.toContain("CVE-2023-CISCO-002");
    });
  });

  describe("Match quality field is populated", () => {
    it("should set matchQuality on all matches", () => {
      const matches = matchTechnologiesAgainstKev(["Microsoft IIS", "nginx", "Apache"], catalog);
      
      for (const m of matches) {
        expect(m.matchQuality).toBeDefined();
        expect(["exact_product", "product_family", "vendor_only", "fuzzy"]).toContain(m.matchQuality);
      }
    });
  });

  describe("Multiple technologies should not cross-contaminate", () => {
    it("should keep IIS and SharePoint findings separate when both are detected", () => {
      const matches = matchTechnologiesAgainstKev(["Microsoft IIS", "SharePoint"], catalog);
      
      // IIS matches should reference IIS
      const iisMatches = matches.filter(m => m.matchedOn === "Microsoft IIS");
      const spMatches = matches.filter(m => m.matchedOn === "SharePoint");
      
      // IIS matches should only be IIS products
      for (const m of iisMatches) {
        const productLower = m.product.toLowerCase();
        expect(
          productLower.includes("iis") || productLower.includes("internet information")
        ).toBe(true);
      }
    });
  });
});
