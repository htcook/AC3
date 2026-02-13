import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import {
  linkCampaignToEngagement,
  getCampaignsByEngagement,
  getEngagementByCampaign,
  getAllCampaignEngagementLinks,
  unlinkCampaignFromEngagement,
  createEngagement,
} from "./db";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-user",
    email: "test@aceofcloud.com",
    name: "Test User",
    loginMethod: "manus",
    role: "admin",
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

describe("campaignEngagements", () => {
  let testEngagementId: number;
  let testLinkId: number;

  beforeAll(async () => {
    // Create a test engagement
    testEngagementId = await createEngagement({
      name: "Test Engagement for Linking",
      customerName: "Test Corp",
      engagementType: "phishing",
      status: "active",
    });
  });

  describe("DB helpers", () => {
    it("should link a campaign to an engagement", async () => {
      const id = await linkCampaignToEngagement({
        engagementId: testEngagementId,
        gophishCampaignId: 999,
        gophishCampaignName: "Test Campaign",
      });
      expect(id).toBeDefined();
      expect(typeof id).toBe("number");
      testLinkId = id;
    });

    it("should retrieve campaigns by engagement", async () => {
      const links = await getCampaignsByEngagement(testEngagementId);
      expect(Array.isArray(links)).toBe(true);
      expect(links.length).toBeGreaterThanOrEqual(1);
      expect(links[0].gophishCampaignId).toBe(999);
    });

    it("should retrieve engagement by campaign ID", async () => {
      const link = await getEngagementByCampaign(999);
      expect(link).toBeDefined();
      expect(link?.engagementId).toBe(testEngagementId);
    });

    it("should list all campaign-engagement links", async () => {
      const all = await getAllCampaignEngagementLinks();
      expect(Array.isArray(all)).toBe(true);
      expect(all.length).toBeGreaterThanOrEqual(1);
    });

    it("should unlink a campaign from an engagement", async () => {
      await unlinkCampaignFromEngagement(testLinkId);
      const links = await getCampaignsByEngagement(testEngagementId);
      const found = links.find((l) => l.id === testLinkId);
      expect(found).toBeUndefined();
    });
  });

  describe("tRPC procedures", () => {
    let linkedId: number;

    it("should link campaign via tRPC", async () => {
      const ctx = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaignEngagements.link({
        engagementId: testEngagementId,
        gophishCampaignId: 1001,
        gophishCampaignName: "tRPC Test Campaign",
        notes: "Created via test",
      });

      expect(result.id).toBeDefined();
      expect(typeof result.id).toBe("number");
      linkedId = result.id;
    });

    it("should list links by engagement via tRPC", async () => {
      const ctx = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const links = await caller.campaignEngagements.byEngagement({
        engagementId: testEngagementId,
      });

      expect(Array.isArray(links)).toBe(true);
      expect(links.length).toBeGreaterThanOrEqual(1);
      const found = links.find((l) => l.gophishCampaignId === 1001);
      expect(found).toBeDefined();
      expect(found?.gophishCampaignName).toBe("tRPC Test Campaign");
    });

    it("should get engagement by campaign via tRPC", async () => {
      const ctx = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const link = await caller.campaignEngagements.byCampaign({
        gophishCampaignId: 1001,
      });

      expect(link).toBeDefined();
      expect(link?.engagementId).toBe(testEngagementId);
    });

    it("should list all links via tRPC", async () => {
      const ctx = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const all = await caller.campaignEngagements.listAll();
      expect(Array.isArray(all)).toBe(true);
      expect(all.length).toBeGreaterThanOrEqual(1);
    });

    it("should unlink campaign via tRPC", async () => {
      const ctx = createAuthContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.campaignEngagements.unlink({ id: linkedId });
      expect(result.success).toBe(true);

      // Verify it's gone
      const links = await caller.campaignEngagements.byEngagement({
        engagementId: testEngagementId,
      });
      const found = links.find((l) => l.gophishCampaignId === 1001);
      expect(found).toBeUndefined();
    });
  });
});
