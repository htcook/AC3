import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

/**
 * Tests for the FAQ data structures and Security Report API endpoints.
 * These tests verify:
 * 1. GoPhish FAQ data is well-formed and searchable
 * 2. Caldera FAQ data is well-formed and searchable
 * 3. The GoPhish and Caldera proxy endpoints exist and are callable
 */

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "sample-user",
    email: "sample@example.com",
    name: "Sample User",
    loginMethod: "manus",
    role: "user",
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

describe("FAQ Data Validation", () => {
  it("GoPhish FAQ items have required fields", async () => {
    // Dynamic import since this is a client-side module
    const { gophishFAQItems } = await import("../client/src/data/gophish-faq");
    
    expect(gophishFAQItems).toBeDefined();
    expect(Array.isArray(gophishFAQItems)).toBe(true);
    expect(gophishFAQItems.length).toBeGreaterThan(5);
    
    for (const item of gophishFAQItems) {
      expect(item.id).toBeTruthy();
      expect(item.question).toBeTruthy();
      expect(item.answer).toBeTruthy();
      expect(item.category).toBeTruthy();
      expect(Array.isArray(item.tags)).toBe(true);
      expect(item.tags.length).toBeGreaterThan(0);
      expect(['low', 'medium', 'high', 'critical']).toContain(item.severity);
    }
  });

  it("GoPhish FAQ items have unique IDs", async () => {
    const { gophishFAQItems } = await import("../client/src/data/gophish-faq");
    const ids = gophishFAQItems.map(item => item.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("GoPhish FAQ covers key troubleshooting categories", async () => {
    const { gophishFAQItems } = await import("../client/src/data/gophish-faq");
    const categories = new Set(gophishFAQItems.map(item => item.category));
    
    // Should cover email delivery, SMTP, landing pages, campaigns
    expect(categories.size).toBeGreaterThanOrEqual(3);
  });

  it("GoPhish FAQ includes spam/deliverability troubleshooting", async () => {
    const { gophishFAQItems } = await import("../client/src/data/gophish-faq");
    const spamItems = gophishFAQItems.filter(item => 
      item.question.toLowerCase().includes('spam') || 
      item.tags.some(t => t.toLowerCase().includes('spam'))
    );
    expect(spamItems.length).toBeGreaterThan(0);
  });

  it("Caldera FAQ items have required fields", async () => {
    const { calderaFAQItems } = await import("../client/src/data/caldera-faq");
    
    expect(calderaFAQItems).toBeDefined();
    expect(Array.isArray(calderaFAQItems)).toBe(true);
    expect(calderaFAQItems.length).toBeGreaterThan(5);
    
    for (const item of calderaFAQItems) {
      expect(item.id).toBeTruthy();
      expect(item.question).toBeTruthy();
      expect(item.answer).toBeTruthy();
      expect(item.category).toBeTruthy();
      expect(Array.isArray(item.tags)).toBe(true);
      expect(item.tags.length).toBeGreaterThan(0);
      expect(['low', 'medium', 'high', 'critical']).toContain(item.severity);
    }
  });

  it("Caldera FAQ items have unique IDs", async () => {
    const { calderaFAQItems } = await import("../client/src/data/caldera-faq");
    const ids = calderaFAQItems.map(item => item.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("Caldera FAQ covers agent troubleshooting", async () => {
    const { calderaFAQItems } = await import("../client/src/data/caldera-faq");
    const agentItems = calderaFAQItems.filter(item => 
      item.category === 'Agents' || 
      item.tags.some(t => t.toLowerCase().includes('agent'))
    );
    expect(agentItems.length).toBeGreaterThan(0);
  });

  it("Caldera FAQ covers ability failure troubleshooting", async () => {
    const { calderaFAQItems } = await import("../client/src/data/caldera-faq");
    const abilityItems = calderaFAQItems.filter(item => 
      item.category === 'Abilities' || 
      item.tags.some(t => t.toLowerCase().includes('ability') || t.toLowerCase().includes('executor'))
    );
    expect(abilityItems.length).toBeGreaterThan(0);
  });

  it("Caldera FAQ covers operations troubleshooting", async () => {
    const { calderaFAQItems } = await import("../client/src/data/caldera-faq");
    const opsItems = calderaFAQItems.filter(item => 
      item.category === 'Operations'
    );
    expect(opsItems.length).toBeGreaterThan(0);
  });
});

describe("Security Report API Endpoints", () => {
  it("gophishProxy.getCampaigns endpoint exists on the router", () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    
    // Verify the endpoint exists (it will fail on network call, but the procedure should be defined)
    expect(typeof caller.gophishProxy.getCampaigns).toBe("function");
  });

  it("gophishProxy.getStatus endpoint exists on the router", () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    
    expect(typeof caller.gophishProxy.getStatus).toBe("function");
  });

  it("calderaProxy.getOperations endpoint exists on the router", () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    
    expect(typeof caller.calderaProxy.getOperations).toBe("function");
  });

  it("calderaProxy.getStats endpoint exists on the router", () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    
    expect(typeof caller.calderaProxy.getStats).toBe("function");
  });

  it("calderaProxy.getAdversaries endpoint exists on the router", () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    
    expect(typeof caller.calderaProxy.getAdversaries).toBe("function");
  });

  it("calderaProxy.getAgents endpoint exists on the router", () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    
    expect(typeof caller.calderaProxy.getAgents).toBe("function");
  });
});
