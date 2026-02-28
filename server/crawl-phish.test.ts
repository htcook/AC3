import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

// ─── Helper: create an unauthenticated (public) context ──────────
function createPublicContext(): TrpcContext {
  return {
    user: null,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

// ═══════════════════════════════════════════════════════════════════
//  PUBLIC THREAT ACTOR FEED TESTS
// ═══════════════════════════════════════════════════════════════════
describe("platformStats.recentThreatActors", () => {
  it("returns threat actors without authentication", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    const result = await caller.platformStats.recentThreatActors({ limit: 5 });

    expect(result).toBeDefined();
    expect(result.actors).toBeDefined();
    expect(Array.isArray(result.actors)).toBe(true);
    expect(typeof result.total).toBe("number");
    expect(result.total).toBeGreaterThan(0);
  });

  it("limits results to requested count", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    const result = await caller.platformStats.recentThreatActors({ limit: 3 });

    expect(result.actors.length).toBeLessThanOrEqual(3);
  });

  it("does not expose sensitive fields (calderaProfile, stixId, internal id)", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    const result = await caller.platformStats.recentThreatActors({ limit: 1 });

    if (result.actors.length > 0) {
      const actor = result.actors[0] as Record<string, unknown>;
      // These fields should NOT be in the public response
      expect(actor).not.toHaveProperty("calderaProfile");
      expect(actor).not.toHaveProperty("stixId");
      expect(actor).not.toHaveProperty("id");
      expect(actor).not.toHaveProperty("dataSource");
      expect(actor).not.toHaveProperty("confidence");
      // These fields SHOULD be present
      expect(actor).toHaveProperty("actorId");
      expect(actor).toHaveProperty("name");
      expect(actor).toHaveProperty("type");
    }
  });
});

describe("platformStats.publicActorDetail", () => {
  it("returns actor detail without authentication", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    const list = await caller.platformStats.recentThreatActors({ limit: 1 });
    if (list.actors.length === 0) return;

    const actorId = list.actors[0].actorId;
    const detail = await caller.platformStats.publicActorDetail({ actorId });

    expect(detail).toBeDefined();
    expect(detail.actorId).toBe(actorId);
    expect(detail.name).toBeDefined();
    expect(detail.type).toBeDefined();
  });

  it("does not expose sensitive fields in detail view", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    const list = await caller.platformStats.recentThreatActors({ limit: 1 });
    if (list.actors.length === 0) return;

    const detail = await caller.platformStats.publicActorDetail({
      actorId: list.actors[0].actorId,
    }) as Record<string, unknown>;

    expect(detail).not.toHaveProperty("calderaProfile");
    expect(detail).not.toHaveProperty("stixId");
    expect(detail).not.toHaveProperty("id");
    expect(detail).not.toHaveProperty("dataSource");
    expect(detail).not.toHaveProperty("confidence");
  });

  it("throws NOT_FOUND for invalid actorId", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    await expect(
      caller.platformStats.publicActorDetail({ actorId: "nonexistent-actor-xyz" })
    ).rejects.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════
//  HOMEPAGE STATS TESTS
// ═══════════════════════════════════════════════════════════════════
describe("platformStats.getHomepageStats", () => {
  it("returns dynamic stats without authentication", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    const stats = await caller.platformStats.getHomepageStats();

    expect(stats).toBeDefined();
    expect(typeof stats.exploitCatalogTotal).toBe("number");
    expect(typeof stats.threatActors).toBe("number");
    expect(typeof stats.platformModules).toBe("number");
    expect(stats.platformModules).toBe(32);
    expect(stats.threatActors).toBeGreaterThan(0);
    expect(typeof stats.lastUpdated).toBe("number");
  });
});

// ═══════════════════════════════════════════════════════════════════
//  CALDERA STATS — THREAT ACTOR COUNT
// ═══════════════════════════════════════════════════════════════════
describe("calderaProxy.getStats", () => {
  it("includes totalThreatActors field", async () => {
    const caller = appRouter.createCaller(createPublicContext());
    const stats = await caller.calderaProxy.getStats();

    expect(stats).toBeDefined();
    expect(typeof stats.totalThreatActors).toBe("number");
    expect(stats.totalThreatActors).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════
//  CRAWL-PHISH GENERATOR UNIT TESTS
// ═══════════════════════════════════════════════════════════════════
describe("crawl-phish-generator", () => {
  it("module exports expected functions", async () => {
    const mod = await import("./lib/crawl-phish-generator");

    expect(typeof mod.extractBranding).toBe("function");
    expect(typeof mod.generateLoginCloneTemplate).toBe("function");
    expect(typeof mod.generateSupplyChainTemplates).toBe("function");
    expect(typeof mod.detectVendors).toBe("function");
    expect(typeof mod.generatePhishingFromCrawl).toBe("function");
  });

  it("detectVendors identifies Microsoft 365 from URL patterns", async () => {
    const { detectVendors } = await import("./lib/crawl-phish-generator");

    const result = detectVendors({
      resourceUrls: ["https://aadcdn.msftauth.net/shared/1.0/content/js/OldConvergedLogin.js"],
      externalLinks: ["https://portal.office.com", "https://login.microsoftonline.com/common/oauth2/authorize"],
      detectedTechnologies: [{ name: "Microsoft ASP.NET", category: "framework" }],
      rawHeaders: {},
    });

    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    const msVendor = result.find(v => v.vendor === "Microsoft 365");
    expect(msVendor).toBeDefined();
    expect(msVendor!.confidence).toBeGreaterThan(0);
  });

  it("detectVendors identifies Okta from URL patterns", async () => {
    const { detectVendors } = await import("./lib/crawl-phish-generator");

    const result = detectVendors({
      resourceUrls: ["https://ok1static.oktacdn.com/assets/js/sdk/okta-signin-widget/7.0.0/js/okta-sign-in.min.js"],
      externalLinks: ["https://company.okta.com/login/login.htm"],
      detectedTechnologies: [],
      rawHeaders: {},
    });

    expect(result).toBeDefined();
    const oktaVendor = result.find(v => v.vendor === "Okta");
    expect(oktaVendor).toBeDefined();
  });

  it("detectVendors returns empty array for unknown sites", async () => {
    const { detectVendors } = await import("./lib/crawl-phish-generator");

    const result = detectVendors({
      resourceUrls: [],
      externalLinks: [],
      detectedTechnologies: [],
      rawHeaders: {},
    });

    expect(Array.isArray(result)).toBe(true);
  });

  it("extractBranding extracts domain and company name", async () => {
    const { extractBranding } = await import("./lib/crawl-phish-generator");

    const result = extractBranding({
      domain: "www.acmecorp.com",
      pageTitle: "Acme Corp - Employee Portal",
      metaDescription: "Employee portal for Acme Corp",
      resourceUrls: ["/logo.png", "/favicon.ico"],
      externalLinks: [],
      detectedTechnologies: [],
      rawHeaders: {},
    });

    expect(result).toBeDefined();
    expect(result.domain).toBe("www.acmecorp.com");
    expect(result.pageTitle).toBe("Acme Corp - Employee Portal");
    expect(typeof result.companyName).toBe("string");
    expect(result.companyName.length).toBeGreaterThan(0);
  });

  it("generateLoginCloneTemplate produces valid GoPhish HTML", async () => {
    const { generateLoginCloneTemplate } = await import("./lib/crawl-phish-generator");

    const template = generateLoginCloneTemplate({
      form: {
        action: "/auth/login",
        method: "POST",
        inputs: [
          { name: "username", type: "email" },
          { name: "password", type: "password" },
        ],
        hasPasswordField: true,
        hasFileUpload: false,
      },
      branding: {
        domain: "acmecorp.com",
        pageTitle: "Acme Corp - Sign In",
        logoUrls: [],
        faviconUrl: null,
        primaryColor: "#1a73e8",
        accentColor: null,
        fontFamily: null,
        companyName: "Acme Corp",
        metaDescription: "",
      },
      sourceUrl: "https://acmecorp.com/login",
      vendorMatch: undefined,
    });

    expect(template).toBeDefined();
    expect(template.landingPageHtml).toContain("{{.URL}}");
    expect(template.landingPageHtml).toContain("{{.TrackingURL}}");
    expect(template.landingPageHtml).toContain("Acme Corp");
    expect(template.landingPageHtml).toContain("<form");
    expect(template.landingPageHtml).toContain("password");
    expect(template.type).toBe("login_clone");
  });

  it("generateSupplyChainTemplates produces vendor-matched templates", async () => {
    const { generateSupplyChainTemplates } = await import("./lib/crawl-phish-generator");

    const templates = generateSupplyChainTemplates({
      vendors: [
        {
          vendor: "Microsoft 365",
          vendorType: "sso",
          confidence: 85,
          evidence: ["External script: https://aadcdn.msftauth.net/shared/1.0/content/js/OldConvergedLogin.js"],
          phishingRelevance: "high",
          templateAvailable: true,
        },
      ],
      branding: {
        domain: "acmecorp.com",
        pageTitle: "Acme Corp",
        logoUrls: [],
        faviconUrl: null,
        primaryColor: "#1a73e8",
        accentColor: null,
        fontFamily: null,
        companyName: "Acme Corp",
        metaDescription: "",
      },
    });

    expect(templates).toBeDefined();
    expect(Array.isArray(templates)).toBe(true);
    expect(templates.length).toBeGreaterThan(0);
    const msTemplate = templates[0];
    expect(msTemplate.type).toBe("supply_chain");
    expect(msTemplate.emailHtml).toContain("{{.URL}}");
    expect(msTemplate.vendorMatch).toBe("Microsoft 365");
  });
});
