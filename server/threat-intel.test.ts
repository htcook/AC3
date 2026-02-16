import { describe, expect, it, vi, beforeEach } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
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

  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"],
  };
}

describe("threatIntel router", () => {
  let caller: ReturnType<typeof appRouter.createCaller>;

  beforeEach(() => {
    caller = appRouter.createCaller(createAuthContext());
  });

  describe("stats", () => {
    it("returns catalog stats with expected shape", async () => {
      const stats = await caller.threatIntel.stats();
      expect(stats).toBeDefined();
      expect(typeof stats.totalActors).toBe("number");
      expect(stats.byType).toBeDefined();
      expect(typeof stats.byType.apt).toBe("number");
      expect(typeof stats.byType.ransomware).toBe("number");
      expect(typeof stats.byType.cybercrime).toBe("number");
      expect(typeof stats.byType.hacktivist).toBe("number");
      // New types may or may not be present depending on data
      // They should be numbers if present, or undefined if no actors of that type exist
      if (stats.byType.access_broker !== undefined) {
        expect(typeof stats.byType.access_broker).toBe("number");
      }
      if (stats.byType.influence_ops !== undefined) {
        expect(typeof stats.byType.influence_ops).toBe("number");
      }
    });
  });

  describe("list", () => {
    it("returns paginated actor list with default params", async () => {
      const result = await caller.threatIntel.list({
        page: 1,
        pageSize: 10,
        type: "all",
        threatLevel: "all",
        sortBy: "name",
        sortOrder: "asc",
      });
      expect(result).toBeDefined();
      expect(Array.isArray(result.actors)).toBe(true);
      expect(typeof result.total).toBe("number");
    });

    it("filters by type correctly", async () => {
      const result = await caller.threatIntel.list({
        page: 1,
        pageSize: 10,
        type: "access_broker",
        threatLevel: "all",
        sortBy: "name",
        sortOrder: "asc",
      });
      expect(result).toBeDefined();
      expect(Array.isArray(result.actors)).toBe(true);
      // All returned actors should be access_broker type
      for (const actor of result.actors) {
        expect(actor.type).toBe("access_broker");
      }
    });

    it("filters by influence_ops type", async () => {
      const result = await caller.threatIntel.list({
        page: 1,
        pageSize: 10,
        type: "influence_ops",
        threatLevel: "all",
        sortBy: "name",
        sortOrder: "asc",
      });
      expect(result).toBeDefined();
      expect(Array.isArray(result.actors)).toBe(true);
      for (const actor of result.actors) {
        expect(actor.type).toBe("influence_ops");
      }
    });

    it("supports search parameter", async () => {
      const result = await caller.threatIntel.list({
        page: 1,
        pageSize: 10,
        type: "all",
        threatLevel: "all",
        search: "nonexistent-actor-xyz",
        sortBy: "name",
        sortOrder: "asc",
      });
      expect(result).toBeDefined();
      expect(result.actors.length).toBe(0);
    });
  });

  describe("ransomwareStats", () => {
    it("returns ransomware stats with expected shape", async () => {
      const stats = await caller.threatIntel.ransomwareStats();
      expect(stats).toBeDefined();
      expect(typeof stats.totalGroups).toBe("number");
      expect(typeof stats.activeGroups).toBe("number");
      expect(typeof stats.totalVictims).toBe("number");
    });
  });

  describe("ransomwareList", () => {
    it("returns paginated ransomware group list", async () => {
      const result = await caller.threatIntel.ransomwareList({
        page: 1,
        pageSize: 10,
        trend: "all",
        sortBy: "activityScore",
        sortOrder: "desc",
      });
      expect(result).toBeDefined();
      expect(Array.isArray(result.groups)).toBe(true);
      expect(typeof result.total).toBe("number");
    });
  });

  describe("recentEvents", () => {
    it("returns recent events array", async () => {
      const events = await caller.threatIntel.recentEvents({ limit: 10 });
      expect(Array.isArray(events)).toBe(true);
    });
  });

  describe("techniqueCoverage", () => {
    it("returns technique coverage data", async () => {
      const coverage = await caller.threatIntel.techniqueCoverage();
      expect(coverage).toBeDefined();
      expect(typeof coverage.totalTechniques).toBe("number");
      expect(Array.isArray(coverage.topTechniques)).toBe(true);
      expect(Array.isArray(coverage.byTactic)).toBe(true);
    });
  });

  describe("syncHistory", () => {
    it("returns sync history array", async () => {
      const history = await caller.threatIntel.syncHistory({ limit: 5 });
      expect(Array.isArray(history)).toBe(true);
    });
  });
});
