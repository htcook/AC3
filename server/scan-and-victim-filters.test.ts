import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): { ctx: TrpcContext } {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-user",
    email: "test@example.com",
    name: "Test User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  const ctx: TrpcContext = {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };

  return { ctx };
}

describe("domainIntel.listScans", () => {
  it("returns scan list without 503 error (lightweight columns only)", async () => {
    const { ctx } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const scans = await caller.domainIntel.listScans();

    expect(Array.isArray(scans)).toBe(true);
    // Should return scan records
    if (scans.length > 0) {
      const scan = scans[0];
      // Should have summary fields
      expect(scan).toHaveProperty("id");
      expect(scan).toHaveProperty("primaryDomain");
      expect(scan).toHaveProperty("status");
      // Should NOT have massive JSON fields (they should be excluded)
      expect(scan).not.toHaveProperty("pipelineOutput");
      expect(scan).not.toHaveProperty("executiveSummary");
      expect(scan).not.toHaveProperty("threatModelSummary");
      expect(scan).not.toHaveProperty("campaignRecommendations");
    }
  });
});

describe("darkwebIntel.recentVictimEvents", () => {
  it("returns victim events with filter options and IOC counts", async () => {
    const { ctx } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.darkwebIntel.recentVictimEvents({});

    expect(result).toHaveProperty("data");
    expect(result).toHaveProperty("filters");
    expect(result).toHaveProperty("source", "local_database");
    expect(Array.isArray(result.data)).toBe(true);
    expect(result.filters).toHaveProperty("countries");
    expect(result.filters).toHaveProperty("sectors");
    expect(result.filters).toHaveProperty("actors");
    expect(Array.isArray(result.filters.countries)).toBe(true);
    expect(Array.isArray(result.filters.sectors)).toBe(true);
    expect(Array.isArray(result.filters.actors)).toBe(true);

    // Each event should have iocCount field
    if (result.data.length > 0) {
      expect(result.data[0]).toHaveProperty("iocCount");
      expect(typeof result.data[0].iocCount).toBe("number");
    }
  });

  it("filters by country when provided", async () => {
    const { ctx } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    // First get unfiltered to find a country
    const unfiltered = await caller.darkwebIntel.recentVictimEvents({});
    if (unfiltered.filters.countries.length === 0) return; // skip if no data

    const country = unfiltered.filters.countries[0];
    const filtered = await caller.darkwebIntel.recentVictimEvents({ country });

    expect(filtered.data.length).toBeLessThanOrEqual(unfiltered.data.length);
    // All results should match the filter
    for (const evt of filtered.data) {
      expect(evt.victimCountry).toBe(country);
    }
  });

  it("filters by actor name when provided", async () => {
    const { ctx } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const unfiltered = await caller.darkwebIntel.recentVictimEvents({});
    if (unfiltered.filters.actors.length === 0) return;

    const actorName = unfiltered.filters.actors[0];
    const filtered = await caller.darkwebIntel.recentVictimEvents({ actorName });

    expect(filtered.data.length).toBeLessThanOrEqual(unfiltered.data.length);
    for (const evt of filtered.data) {
      expect(evt.actorName).toBe(actorName);
    }
  });

  it("respects limit parameter", async () => {
    const { ctx } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.darkwebIntel.recentVictimEvents({ limit: 5 });
    expect(result.data.length).toBeLessThanOrEqual(5);
  });
});

describe("darkwebIntel.alertDetail", () => {
  it("returns enriched alert with feedIocs when event exists", async () => {
    const { ctx } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    // First get a victim event to use its ID
    const events = await caller.darkwebIntel.recentVictimEvents({ limit: 1 });
    if (events.data.length === 0) return; // skip if no data

    const eventId = events.data[0].id;
    const detail = await caller.darkwebIntel.alertDetail({ eventId });

    // alertDetail can return null if event not found
    if (detail === null) return;

    expect(detail).toHaveProperty("event");
    expect(detail).toHaveProperty("actorIocs");
    expect(detail).toHaveProperty("feedIocs");
    expect(detail).toHaveProperty("relatedEvents");
    expect(Array.isArray(detail.actorIocs)).toBe(true);
    expect(Array.isArray((detail as any).feedIocs)).toBe(true);
    expect(Array.isArray(detail.relatedEvents)).toBe(true);

    // feedIocs should have proper structure if present
    const feedIocs = (detail as any).feedIocs;
    if (feedIocs.length > 0) {
      const ioc = feedIocs[0];
      expect(ioc).toHaveProperty("iocType");
      expect(ioc).toHaveProperty("iocValue");
      expect(ioc).toHaveProperty("source");
    }
  });

  it("returns null for non-existent event", async () => {
    const { ctx } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const detail = await caller.darkwebIntel.alertDetail({ eventId: 999999 });
    expect(detail).toBeNull();
  });
});
