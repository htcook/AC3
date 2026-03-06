import { describe, expect, it, vi, beforeEach } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createTestContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-operator",
    email: "operator@aceofcloud.io",
    name: "Test Operator",
    loginMethod: "manus",
    role: "operator",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

describe("engagementOps.getScanModes", () => {
  it("returns three scan modes with correct structure", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.engagementOps.getScanModes();

    expect(result).toBeDefined();
    expect(result.modes).toHaveLength(3);

    // Verify each mode has required fields
    for (const mode of result.modes) {
      expect(mode).toHaveProperty("value");
      expect(mode).toHaveProperty("label");
      expect(mode).toHaveProperty("description");
      expect(mode).toHaveProperty("connectorCount");
      expect(mode).toHaveProperty("techniques");
      expect(mode).toHaveProperty("restrictions");
      expect(typeof mode.label).toBe("string");
      expect(typeof mode.description).toBe("string");
      expect(typeof mode.connectorCount).toBe("number");
      expect(Array.isArray(mode.techniques)).toBe(true);
      expect(Array.isArray(mode.restrictions)).toBe(true);
    }
  });

  it("returns modes in correct order: strict_passive, standard, active", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.engagementOps.getScanModes();

    expect(result.modes[0].value).toBe("strict_passive");
    expect(result.modes[1].value).toBe("standard");
    expect(result.modes[2].value).toBe("active");
  });

  it("strict_passive has 23 connectors, standard 28, active 31", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.engagementOps.getScanModes();

    expect(result.modes[0].connectorCount).toBe(23);
    expect(result.modes[1].connectorCount).toBe(28);
    expect(result.modes[2].connectorCount).toBe(31);
  });

  it("each mode has non-empty label and description", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.engagementOps.getScanModes();

    for (const mode of result.modes) {
      expect(mode.label.length).toBeGreaterThan(0);
      expect(mode.description.length).toBeGreaterThan(0);
      expect(mode.techniques.length).toBeGreaterThan(0);
      expect(mode.restrictions.length).toBeGreaterThan(0);
    }
  });

  it("strict_passive has more restrictions than active", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.engagementOps.getScanModes();

    const strictRestrictions = result.modes[0].restrictions.length;
    const activeRestrictions = result.modes[2].restrictions.length;
    expect(strictRestrictions).toBeGreaterThan(activeRestrictions);
  });
});

describe("passive-guard scan mode descriptions", () => {
  it("getScanModeDescription returns correct labels", async () => {
    const { getScanModeDescription } = await import("./lib/passive/passive-guard");

    expect(getScanModeDescription("strict_passive").label).toBe("Strict Passive");
    expect(getScanModeDescription("standard").label).toBe("Standard");
    expect(getScanModeDescription("active").label).toBe("Active");
  });

  it("filterConnectors blocks active connectors in strict_passive mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");
    const { PassiveConnector } = await import("./lib/passive/types") as any;

    // Create mock connectors
    const mockConnectors = [
      { name: "crtsh", description: "CT logs", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "http_security", description: "HTTP headers", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "dns_deep", description: "DNS resolution", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
    ];

    const result = filterConnectors(mockConnectors as any, "strict_passive");
    expect(result.allowed.map(c => c.name)).toContain("crtsh");
    expect(result.allowed.map(c => c.name)).not.toContain("http_security");
    expect(result.allowed.map(c => c.name)).not.toContain("dns_deep");
    expect(result.blocked.map(b => b.name)).toContain("http_security");
    expect(result.blocked.map(b => b.name)).toContain("dns_deep");
  });

  it("filterConnectors allows DNS connectors in standard mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");

    const mockConnectors = [
      { name: "crtsh", description: "CT logs", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "http_security", description: "HTTP headers", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "dns_deep", description: "DNS resolution", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "rdap", description: "RDAP lookup", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
    ];

    const result = filterConnectors(mockConnectors as any, "standard");
    expect(result.allowed.map(c => c.name)).toContain("crtsh");
    expect(result.allowed.map(c => c.name)).toContain("dns_deep");
    expect(result.allowed.map(c => c.name)).toContain("rdap");
    expect(result.allowed.map(c => c.name)).not.toContain("http_security");
    expect(result.blocked.map(b => b.name)).toContain("http_security");
  });

  it("filterConnectors allows all connectors in active mode", async () => {
    const { filterConnectors } = await import("./lib/passive/passive-guard");

    const mockConnectors = [
      { name: "crtsh", description: "CT logs", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "http_security", description: "HTTP headers", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "dns_deep", description: "DNS resolution", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
      { name: "container-discovery", description: "Container discovery", requiresApiKey: false, freeUrl: "", collect: async () => ({} as any) },
    ];

    const result = filterConnectors(mockConnectors as any, "active");
    expect(result.allowed).toHaveLength(4);
    expect(result.blocked).toHaveLength(0);
  });

  it("getDefaultPolicy returns correct flags for each mode", async () => {
    const { getDefaultPolicy } = await import("./lib/passive/passive-guard");

    const strictPolicy = getDefaultPolicy("strict_passive");
    expect(strictPolicy.scanMode).toBe("strict_passive");
    expect(strictPolicy.allowDnsResolution).toBe(false);
    expect(strictPolicy.allowWellKnownFetch).toBe(false);

    const standardPolicy = getDefaultPolicy("standard");
    expect(standardPolicy.scanMode).toBe("standard");
    expect(standardPolicy.allowDnsResolution).toBe(true);
    expect(standardPolicy.allowWellKnownFetch).toBe(true);

    const activePolicy = getDefaultPolicy("active");
    expect(activePolicy.scanMode).toBe("active");
    expect(activePolicy.allowDnsResolution).toBe(true);
    expect(activePolicy.allowWellKnownFetch).toBe(true);
  });
});
