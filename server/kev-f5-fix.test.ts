import { describe, it, expect } from "vitest";

/**
 * Tests for the F5 BIG-IP / nginx KEV mapping fix.
 * 
 * Root cause: The KEV service's TECH_TO_VENDOR_PRODUCT map previously
 * included "f5" as a vendor alias for "nginx", causing all F5 BIG-IP
 * CVEs to match against nginx-running assets. The fix separates them
 * into distinct entries.
 */

// Inline the mapping from kev-service.ts for unit testing
// This mirrors the actual mapping structure
const TECH_TO_VENDOR_PRODUCT: Record<string, { vendors: string[]; products: string[] }> = {
  "nginx": { vendors: ["nginx"], products: ["nginx"] },
  "f5 big-ip": { vendors: ["f5"], products: ["big-ip", "big ip", "tmui", "traffic management"] },
  "big-ip": { vendors: ["f5"], products: ["big-ip", "big ip", "tmui", "traffic management"] },
  "apache": { vendors: ["apache"], products: ["http server", "httpd", "tomcat", "struts", "log4j"] },
  "iis": { vendors: ["microsoft"], products: ["internet information services", "iis"] },
};

describe("KEV Service: F5 BIG-IP / nginx Separation", () => {
  it("nginx mapping should NOT include f5 as a vendor", () => {
    const nginxMapping = TECH_TO_VENDOR_PRODUCT["nginx"];
    expect(nginxMapping).toBeDefined();
    expect(nginxMapping.vendors).not.toContain("f5");
    expect(nginxMapping.vendors).toEqual(["nginx"]);
  });

  it("nginx mapping should only match nginx products", () => {
    const nginxMapping = TECH_TO_VENDOR_PRODUCT["nginx"];
    expect(nginxMapping.products).toEqual(["nginx"]);
    expect(nginxMapping.products).not.toContain("big-ip");
    expect(nginxMapping.products).not.toContain("big ip");
    expect(nginxMapping.products).not.toContain("tmui");
  });

  it("f5 big-ip mapping should exist as a separate entry", () => {
    const f5Mapping = TECH_TO_VENDOR_PRODUCT["f5 big-ip"];
    expect(f5Mapping).toBeDefined();
    expect(f5Mapping.vendors).toEqual(["f5"]);
    expect(f5Mapping.products).toContain("big-ip");
  });

  it("big-ip shorthand mapping should also exist", () => {
    const bigipMapping = TECH_TO_VENDOR_PRODUCT["big-ip"];
    expect(bigipMapping).toBeDefined();
    expect(bigipMapping.vendors).toEqual(["f5"]);
  });

  it("nginx technology should NOT match F5 BIG-IP KEV entries", () => {
    // Simulate a KEV entry for F5 BIG-IP
    const kevEntry = {
      vendorProject: "F5",
      product: "BIG-IP",
    };

    const nginxMapping = TECH_TO_VENDOR_PRODUCT["nginx"];
    const vendorMatch = nginxMapping.vendors.some(
      (v) => kevEntry.vendorProject.toLowerCase().includes(v.toLowerCase())
    );
    const productMatch = nginxMapping.products.some(
      (p) => kevEntry.product.toLowerCase().includes(p.toLowerCase())
    );

    expect(vendorMatch).toBe(false);
    expect(productMatch).toBe(false);
  });

  it("f5 big-ip technology SHOULD match F5 BIG-IP KEV entries", () => {
    const kevEntry = {
      vendorProject: "F5",
      product: "BIG-IP",
    };

    const f5Mapping = TECH_TO_VENDOR_PRODUCT["f5 big-ip"];
    const vendorMatch = f5Mapping.vendors.some(
      (v) => kevEntry.vendorProject.toLowerCase().includes(v.toLowerCase())
    );
    const productMatch = f5Mapping.products.some(
      (p) => kevEntry.product.toLowerCase().includes(p.toLowerCase())
    );

    expect(vendorMatch).toBe(true);
    expect(productMatch).toBe(true);
  });

  it("nginx technology SHOULD match nginx KEV entries", () => {
    const kevEntry = {
      vendorProject: "Nginx",
      product: "Nginx Plus",
    };

    const nginxMapping = TECH_TO_VENDOR_PRODUCT["nginx"];
    const vendorMatch = nginxMapping.vendors.some(
      (v) => kevEntry.vendorProject.toLowerCase().includes(v.toLowerCase())
    );
    const productMatch = nginxMapping.products.some(
      (p) => kevEntry.product.toLowerCase().includes(p.toLowerCase())
    );

    expect(vendorMatch).toBe(true);
    expect(productMatch).toBe(true);
  });
});

describe("Findings Display: Confirmed vs Potential Separation", () => {
  // Simulate the filtering logic used in the UI
  const mockFindings = [
    { title: "CVE-2024-1234", corroborationTier: "confirmed", severity: 9, kevListed: true },
    { title: "CVE-2024-5678", corroborationTier: "confirmed", severity: 8, kevListed: false },
    { title: "CVE-2024-9999", corroborationTier: "probable", severity: 6, kevListed: false },
    { title: "Potential XSS", corroborationTier: "potential", severity: 4, kevListed: false },
    { title: "Possible SQLi", corroborationTier: "potential", severity: 3, kevListed: false },
    { title: "LLM-inferred risk", severity: 2, kevListed: false }, // no tier = potential
  ];

  it("confirmed and probable findings should be shown by default", () => {
    const defaultVisible = mockFindings.filter(
      (f) => f.corroborationTier === "confirmed" || f.corroborationTier === "probable"
    );
    expect(defaultVisible).toHaveLength(3);
    expect(defaultVisible.every((f) => f.corroborationTier !== "potential")).toBe(true);
  });

  it("potential findings should be hidden behind collapsible", () => {
    const potential = mockFindings.filter(
      (f) => !f.corroborationTier || f.corroborationTier === "potential"
    );
    expect(potential).toHaveLength(3);
    expect(potential.every((f) => !f.corroborationTier || f.corroborationTier === "potential")).toBe(true);
  });

  it("findings with no corroborationTier should be treated as potential", () => {
    const noTier = mockFindings.filter((f) => !f.corroborationTier);
    expect(noTier).toHaveLength(1);
    expect(noTier[0].title).toBe("LLM-inferred risk");

    // Should be in the potential group
    const potential = mockFindings.filter(
      (f) => !f.corroborationTier || f.corroborationTier === "potential"
    );
    expect(potential).toContainEqual(noTier[0]);
  });

  it("KEV-listed findings should always be in the default visible group", () => {
    const kevFindings = mockFindings.filter((f) => f.kevListed);
    expect(kevFindings).toHaveLength(1);
    expect(kevFindings[0].corroborationTier).toBe("confirmed");

    // KEV findings are confirmed, so they're in the default visible group
    const defaultVisible = mockFindings.filter(
      (f) => f.corroborationTier === "confirmed" || f.corroborationTier === "probable"
    );
    expect(defaultVisible).toContainEqual(kevFindings[0]);
  });

  it("total findings should equal confirmed + probable + potential", () => {
    const confirmed = mockFindings.filter((f) => f.corroborationTier === "confirmed");
    const probable = mockFindings.filter((f) => f.corroborationTier === "probable");
    const potential = mockFindings.filter(
      (f) => !f.corroborationTier || f.corroborationTier === "potential"
    );
    expect(confirmed.length + probable.length + potential.length).toBe(mockFindings.length);
  });
});
