import { describe, it, expect } from "vitest";
import { calculateKevRiskBoost } from "./lib/kev-service";

describe("KEV Risk Boost — Confirmed-Only Policy", () => {
  it("should return zero boost when all matches are potential (no version confirmation)", () => {
    const potentialMatches = [
      {
        cveID: "CVE-2024-1234",
        vendorProject: "Microsoft",
        product: "Exchange",
        vulnerabilityName: "Exchange RCE",
        matchedOn: "Microsoft",
        severityBoost: 8,
        knownRansomware: false,
        matchQuality: "product_family" as const,
        dueDate: "2024-06-01",
        requiredAction: "Patch Exchange",
      },
      {
        cveID: "CVE-2024-5678",
        vendorProject: "Apache",
        product: "HTTP Server",
        vulnerabilityName: "Apache RCE",
        matchedOn: "Apache",
        severityBoost: 7,
        knownRansomware: false,
        matchQuality: "vendor_only" as const,
        dueDate: "2024-07-01",
        requiredAction: "Patch Apache",
      },
    ];

    const result = calculateKevRiskBoost(potentialMatches as any);
    expect(result.riskBoost).toBe(0);
    expect(result.confirmedCount).toBe(0);
    expect(result.potentialCount).toBe(2);
    expect(result.summary).toContain("no risk boost applied");
    expect(result.summary).toContain("advisory only");
  });

  it("should apply boost only for confirmed (exact_product) matches", () => {
    const mixedMatches = [
      {
        cveID: "CVE-2024-1234",
        vendorProject: "Microsoft",
        product: "Exchange",
        vulnerabilityName: "Exchange RCE",
        matchedOn: "Exchange",
        severityBoost: 8,
        knownRansomware: false,
        matchQuality: "exact_product" as const,
        dueDate: "2024-06-01",
        requiredAction: "Patch Exchange",
      },
      {
        cveID: "CVE-2024-5678",
        vendorProject: "Apache",
        product: "HTTP Server",
        vulnerabilityName: "Apache RCE",
        matchedOn: "Apache",
        severityBoost: 7,
        knownRansomware: false,
        matchQuality: "product_family" as const,
        dueDate: "2024-07-01",
        requiredAction: "Patch Apache",
      },
    ];

    const result = calculateKevRiskBoost(mixedMatches as any);
    // Only the confirmed match (severityBoost=8) should contribute
    expect(result.riskBoost).toBe(8);
    expect(result.confirmedCount).toBe(1);
    expect(result.potentialCount).toBe(1);
    expect(result.summary).toContain("confirmed matches only");
  });

  it("should cap boost at 20 even with many confirmed matches", () => {
    const manyConfirmed = Array.from({ length: 5 }, (_, i) => ({
      cveID: `CVE-2024-${1000 + i}`,
      vendorProject: "Microsoft",
      product: "Exchange",
      vulnerabilityName: `Exchange Vuln ${i}`,
      matchedOn: "Exchange",
      severityBoost: 10,
      knownRansomware: false,
      matchQuality: "exact_product" as const,
      dueDate: "2024-06-01",
      requiredAction: "Patch Exchange",
    }));

    const result = calculateKevRiskBoost(manyConfirmed as any);
    expect(result.riskBoost).toBeLessThanOrEqual(20);
    expect(result.confirmedCount).toBe(5);
  });

  it("should return zero boost for empty matches", () => {
    const result = calculateKevRiskBoost([]);
    expect(result.riskBoost).toBe(0);
    expect(result.confirmedCount).toBe(0);
    expect(result.potentialCount).toBe(0);
    expect(result.summary).toBe("No CISA KEV matches found.");
  });

  it("should detect ransomware exposure from non-fuzzy matches", () => {
    const ransomwareMatches = [
      {
        cveID: "CVE-2024-9999",
        vendorProject: "Microsoft",
        product: "Exchange",
        vulnerabilityName: "Exchange Ransomware Vector",
        matchedOn: "Exchange",
        severityBoost: 10,
        knownRansomware: true,
        matchQuality: "exact_product" as const,
        dueDate: "2024-06-01",
        requiredAction: "Patch immediately",
      },
    ];

    const result = calculateKevRiskBoost(ransomwareMatches as any);
    expect(result.ransomwareExposure).toBe(true);
    expect(result.riskBoost).toBe(10);
    expect(result.summary).toContain("ransomware");
  });

  it("should NOT count fuzzy ransomware matches as ransomware exposure", () => {
    const fuzzyRansomware = [
      {
        cveID: "CVE-2024-8888",
        vendorProject: "SomeVendor",
        product: "SomeProduct",
        vulnerabilityName: "Some Vuln",
        matchedOn: "some",
        severityBoost: 5,
        knownRansomware: true,
        matchQuality: "fuzzy" as const,
        dueDate: "2024-06-01",
        requiredAction: "Investigate",
      },
    ];

    const result = calculateKevRiskBoost(fuzzyRansomware as any);
    expect(result.ransomwareExposure).toBe(false);
    expect(result.riskBoost).toBe(0); // fuzzy = not exact_product = potential = no boost
  });
});
