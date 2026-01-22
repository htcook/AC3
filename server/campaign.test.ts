import { describe, expect, it, vi, beforeEach } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type CookieCall = {
  name: string;
  options: Record<string, unknown>;
};

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(role: "user" | "admin" = "user"): { ctx: TrpcContext; clearedCookies: CookieCall[] } {
  const clearedCookies: CookieCall[] = [];

  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-user",
    email: "test@example.com",
    name: "Test User",
    loginMethod: "manus",
    role,
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
      clearCookie: (name: string, options: Record<string, unknown>) => {
        clearedCookies.push({ name, options });
      },
    } as TrpcContext["res"],
  };

  return { ctx, clearedCookies };
}

// Mock the database functions
vi.mock("./db", () => ({
  getCampaigns: vi.fn().mockResolvedValue([
    {
      id: 1,
      name: "Test Campaign",
      description: "A test campaign",
      status: "draft",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ]),
  getCampaignById: vi.fn().mockResolvedValue({
    id: 1,
    name: "Test Campaign",
    description: "A test campaign",
    status: "draft",
    createdAt: new Date(),
    updatedAt: new Date(),
  }),
  getCampaignAgents: vi.fn().mockResolvedValue([
    { id: 1, campaignId: 1, agentName: "Test Agent", platform: "windows", status: "pending" },
  ]),
  getCampaignAbilities: vi.fn().mockResolvedValue([
    { id: 1, campaignId: 1, abilityId: "test-1", abilityName: "Test Ability", tactic: "Reconnaissance", status: "pending" },
  ]),
  createCampaign: vi.fn().mockResolvedValue(1),
  updateCampaign: vi.fn().mockResolvedValue(undefined),
  deleteCampaign: vi.fn().mockResolvedValue(undefined),
  addCampaignAgent: vi.fn().mockResolvedValue(1),
  deleteCampaignAgent: vi.fn().mockResolvedValue(undefined),
  addCampaignAbility: vi.fn().mockResolvedValue(1),
  addCampaignAbilities: vi.fn().mockResolvedValue(undefined),
  deleteCampaignAbility: vi.fn().mockResolvedValue(undefined),
  logActivity: vi.fn().mockResolvedValue(undefined),
}));

describe("campaign router", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("campaign.list", () => {
    it("returns list of campaigns for authenticated user", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.list();

      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe("campaign.get", () => {
    it("returns campaign with agents and abilities", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.get({ id: 1 });

      expect(result).toBeDefined();
      expect(result.id).toBe(1);
      expect(result.name).toBe("Test Campaign");
      expect(result.agents).toBeDefined();
      expect(result.abilities).toBeDefined();
    });
  });

  describe("campaign.create", () => {
    it("creates a new campaign", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.create({
        name: "New Campaign",
        description: "Test description",
        targetEnvironment: "Test Environment",
      });

      expect(result).toHaveProperty("id");
      expect(result.id).toBe(1);
    });
  });

  describe("campaign.update", () => {
    it("updates campaign status", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.update({
        id: 1,
        status: "ready",
      });

      expect(result).toEqual({ success: true });
    });
  });

  describe("campaign.delete", () => {
    it("deletes campaign for admin user", async () => {
      const { ctx } = createAuthContext("admin");
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.delete({ id: 1 });

      expect(result).toEqual({ success: true });
    });

    it("throws error for non-admin user", async () => {
      const { ctx } = createAuthContext("user");
      const caller = appRouter.createCaller(ctx);

      await expect(caller.campaign.delete({ id: 1 })).rejects.toThrow();
    });
  });

  describe("campaign.addAgent", () => {
    it("adds agent to campaign", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.addAgent({
        campaignId: 1,
        agentName: "Test Agent",
        platform: "windows",
        hostname: "test-host",
      });

      expect(result).toHaveProperty("id");
    });
  });

  describe("campaign.removeAgent", () => {
    it("removes agent from campaign", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.removeAgent({ id: 1 });

      expect(result).toEqual({ success: true });
    });
  });

  describe("campaign.addAbilities", () => {
    it("adds multiple abilities to campaign", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.addAbilities({
        campaignId: 1,
        abilities: [
          { abilityId: "test-1", abilityName: "Test Ability 1", tactic: "Reconnaissance" },
          { abilityId: "test-2", abilityName: "Test Ability 2", tactic: "Initial Access" },
        ],
      });

      expect(result).toEqual({ success: true });
    });
  });

  describe("campaign.removeAbility", () => {
    it("removes ability from campaign", async () => {
      const { ctx } = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaign.removeAbility({ id: 1 });

      expect(result).toEqual({ success: true });
    });
  });
});
