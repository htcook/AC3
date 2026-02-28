import { describe, expect, it } from "vitest";

describe("entity-resolver", () => {
  it("exports expected functions", async () => {
    const mod = await import("./lib/entity-resolver");
    expect(typeof mod.resolveEntity).toBe("function");
    expect(typeof mod.enrichEntityFinancials).toBe("function");
    expect(typeof mod.resolveAndEnrichEntity).toBe("function");
    expect(typeof mod.calculateFinancialImpact).toBe("function");
  });

  it("resolveEntity identifies org from page title", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "acmecorp.com",
      pageTitle: "Acme Corporation - Enterprise Solutions",
      metaDescription: "Acme Corporation provides enterprise software solutions",
      externalLinks: [],
    });

    expect(result.orgName).toBeDefined();
    expect(result.orgName.length).toBeGreaterThan(0);
    expect(result.confidence).toBeGreaterThan(0);
    expect(result.identificationMethod).toBeDefined();
  });

  it("resolveEntity identifies org from copyright text", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "example.com",
      pageTitle: "Welcome",
      html: `<footer>&copy; 2025 TechStart Industries. All rights reserved.</footer>`,
      externalLinks: [],
    });

    expect(result.orgName).toBe("TechStart Industries");
    expect(result.confidence).toBeGreaterThanOrEqual(90);
    expect(result.evidence.some(e => e.source === "html_copyright")).toBe(true);
  });

  it("resolveEntity filters out hosting providers from WHOIS", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "mysite.com",
      pageTitle: "My Company - Home",
      whoisOrg: "GoDaddy.com, LLC",
      externalLinks: [],
    });

    expect(result.whoisIsHostingProvider).toBe(true);
    // Should NOT use GoDaddy as the org name
    expect(result.orgName.toLowerCase()).not.toContain("godaddy");
  });

  it("resolveEntity filters out Cloudflare from WHOIS", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "mysite.com",
      pageTitle: "Real Company Inc - Dashboard",
      whoisOrg: "Cloudflare Inc",
      externalLinks: [],
    });

    expect(result.whoisIsHostingProvider).toBe(true);
    expect(result.orgName.toLowerCase()).not.toContain("cloudflare");
  });

  it("resolveEntity filters out AWS from SSL cert", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "app.startup.io",
      pageTitle: "Startup.io - Build Faster",
      tlsInfo: { subject: "CN=app.startup.io, O=Amazon Web Services", issuer: "Amazon" },
      externalLinks: [],
    });

    // Should NOT use Amazon as the org name
    expect(result.orgName.toLowerCase()).not.toContain("amazon");
  });

  it("resolveEntity boosts confidence when multiple signals agree", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "acme.com",
      pageTitle: "Acme Corp - Home",
      html: `<footer>&copy; 2025 Acme Corp. All rights reserved.</footer>`,
      metaDescription: "Acme Corp is a leading provider of widgets",
      externalLinks: ["https://www.linkedin.com/company/acme-corp/"],
    });

    // Multiple signals should boost confidence
    expect(result.confidence).toBeGreaterThan(90);
    expect(result.identificationMethod).toContain("multi_signal");
  });

  it("resolveEntity extracts social profiles", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "example.com",
      pageTitle: "Example Corp",
      externalLinks: [
        "https://www.linkedin.com/company/example-corp/",
        "https://twitter.com/examplecorp",
        "https://github.com/examplecorp",
      ],
    });

    expect(result.socialProfiles.length).toBeGreaterThanOrEqual(2);
    expect(result.socialProfiles.some(p => p.platform === "LinkedIn")).toBe(true);
    expect(result.socialProfiles.some(p => p.platform === "X/Twitter")).toBe(true);
  });

  it("resolveEntity falls back to domain when no signals", async () => {
    const { resolveEntity } = await import("./lib/entity-resolver");

    const result = resolveEntity({
      domain: "mysterious-site.com",
    });

    expect(result.orgName).toBe("mysterious-site.com");
    expect(result.confidence).toBe(0);
    expect(result.identificationMethod).toBe("domain_fallback");
  });

  it("calculateFinancialImpact returns valid impact tiers", async () => {
    const { calculateFinancialImpact } = await import("./lib/entity-resolver");

    // Large company
    const largeResult = calculateFinancialImpact({
      orgName: "Big Corp",
      confidence: 90,
      identificationMethod: "copyright",
      evidence: [],
      industry: "Technology",
      subSector: "SaaS",
      companySize: "enterprise",
      estimatedRevenue: 5_000_000_000, // $5B
      revenueConfidence: "verified",
      revenueSource: "SEC filings",
      estimatedValuation: 20_000_000_000, // $20B
      valuationConfidence: "verified",
      valuationSource: "Market cap",
      estimatedEmployees: 15000,
      isPublicCompany: true,
      stockTicker: "BIGC",
      headquarters: "San Francisco, CA",
      foundedYear: 2005,
      keyProducts: ["Cloud Platform"],
      socialProfiles: [],
      whoisOrg: null,
      sslCertOrg: null,
      whoisIsHostingProvider: false,
    });

    expect(largeResult.impactTier).toBe("catastrophic");
    expect(largeResult.totalMaxExposure).toBeGreaterThan(100_000_000);
    expect(largeResult.estimatedDailyRevenueLoss).toBeGreaterThan(0);

    // Small company
    const smallResult = calculateFinancialImpact({
      orgName: "Small Startup",
      confidence: 70,
      identificationMethod: "title",
      evidence: [],
      industry: "Technology",
      subSector: null,
      companySize: "startup",
      estimatedRevenue: 500_000, // $500K
      revenueConfidence: "estimated",
      revenueSource: null,
      estimatedValuation: 2_000_000,
      valuationConfidence: "estimated",
      valuationSource: null,
      estimatedEmployees: 10,
      isPublicCompany: false,
      stockTicker: null,
      headquarters: null,
      foundedYear: null,
      keyProducts: [],
      socialProfiles: [],
      whoisOrg: null,
      sslCertOrg: null,
      whoisIsHostingProvider: false,
    });

    expect(["moderate", "minimal"]).toContain(smallResult.impactTier);
    expect(smallResult.totalMaxExposure).toBeLessThan(1_000_000);
  });
});
