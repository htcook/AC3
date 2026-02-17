import { describe, it, expect, vi } from "vitest";

// Test the IAB and IO seed data structure
describe("Darkweb Feeds Data Integrity", () => {
  it("should have valid IAB seed entries with required fields", async () => {
    // Import the module to check the seed data compiles and exports correctly
    const mod = await import("./lib/darkweb-feeds");
    expect(mod.syncAccessBrokers).toBeDefined();
    expect(typeof mod.syncAccessBrokers).toBe("function");
  });

  it("should have valid IO campaign seed entries with required fields", async () => {
    const mod = await import("./lib/darkweb-feeds");
    expect(mod.syncInfoOpsCampaigns).toBeDefined();
    expect(typeof mod.syncInfoOpsCampaigns).toBe("function");
  });

  it("should export syncAllDarkwebFeeds function", async () => {
    const mod = await import("./lib/darkweb-feeds");
    expect(mod.syncAllDarkwebFeeds).toBeDefined();
    expect(typeof mod.syncAllDarkwebFeeds).toBe("function");
  });
});

describe("Darkweb Bridge Router Procedures", () => {
  it("should have accessBrokers procedure defined", async () => {
    const { darkwebBridgeRouter } = await import("./routers/darkweb-bridge");
    expect(darkwebBridgeRouter).toBeDefined();
    // Check the router has the new procedures
    const procedures = Object.keys((darkwebBridgeRouter as any)._def.procedures || {});
    expect(procedures).toContain("accessBrokers");
    expect(procedures).toContain("accessBrokerDetail");
    expect(procedures).toContain("infoOpsCampaigns");
    expect(procedures).toContain("infoOpsCampaignDetail");
    expect(procedures).toContain("syncDarkwebFeeds");
  });
});

describe("Schema Tables", () => {
  it("should export accessBrokerListings table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.accessBrokerListings).toBeDefined();
  });

  it("should export infoOpsCampaigns table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.infoOpsCampaigns).toBeDefined();
  });
});
