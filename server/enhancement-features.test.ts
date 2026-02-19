import { describe, expect, it, beforeAll } from "vitest";
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

// ─── Emulation Playbooks ──────────────────────────────────────────────────────

describe("emulationPlaybooks router", () => {
  const { ctx } = createAuthContext();
  const caller = appRouter.createCaller(ctx);

  it("lists playbooks (empty initially)", async () => {
    const result = await caller.emulationPlaybooks.list({});
    expect(result).toHaveProperty("items");
    expect(Array.isArray(result.items)).toBe(true);
  });

  it("creates a playbook", async () => {
    const result = await caller.emulationPlaybooks.create({
      name: "Test Playbook",
      description: "A test adversary emulation playbook",
    });
    expect(result).toHaveProperty("playbookId");
    expect(typeof result.playbookId).toBe("string");
  });

  it("retrieves a created playbook", async () => {
    const created = await caller.emulationPlaybooks.create({
      name: "Retrieve Test",
      description: "For retrieval",
    });
    const result = await caller.emulationPlaybooks.get({ playbookId: created.playbookId });
    expect(result.name).toBe("Retrieve Test");
    expect(result.playbookId).toBe(created.playbookId);
  });

  it("deletes a playbook", async () => {
    const created = await caller.emulationPlaybooks.create({
      name: "Delete Me",
      description: "To be deleted",
    });
    const result = await caller.emulationPlaybooks.delete({ playbookId: created.playbookId });
    expect(result).toEqual({ success: true });
  });
});

// ─── Evidence Collection ──────────────────────────────────────────────────────

describe("evidence router", () => {
  const { ctx } = createAuthContext();
  const caller = appRouter.createCaller(ctx);

  it("lists evidence items (empty initially)", async () => {
    const result = await caller.evidence.list({});
    expect(result).toHaveProperty("items");
    expect(Array.isArray(result.items)).toBe(true);
  });

  it("creates an evidence item", async () => {
    const result = await caller.evidence.create({
      title: "Test Evidence",
      type: "screenshot",
      description: "A test evidence item",
    });
    expect(result).toHaveProperty("evidenceId");
    expect(typeof result.evidenceId).toBe("string");
  });

  it("retrieves evidence with chain of custody", async () => {
    const created = await caller.evidence.create({
      title: "Chain Test",
      type: "log_file",
      description: "Testing chain of custody",
    });
    const result = await caller.evidence.get({ evidenceId: created.evidenceId });
    expect(result.title).toBe("Chain Test");
    expect(result).toHaveProperty("custodyLog");
    expect(Array.isArray(result.custodyLog)).toBe(true);
  });

  it("deletes evidence", async () => {
    const created = await caller.evidence.create({
      title: "Delete Me",
      type: "pcap",
      description: "To be deleted",
    });
    const result = await caller.evidence.delete({ evidenceId: created.evidenceId });
    expect(result).toEqual({ success: true });
  });
});

// ─── Attack Paths ─────────────────────────────────────────────────────────────

describe("attackPaths router", () => {
  const { ctx } = createAuthContext();
  const caller = appRouter.createCaller(ctx);

  it("lists attack paths (empty initially)", async () => {
    const result = await caller.attackPaths.list({});
    expect(result).toHaveProperty("items");
    expect(Array.isArray(result.items)).toBe(true);
  });

  it("creates an attack path", async () => {
    const result = await caller.attackPaths.create({
      name: "Test Attack Path",
      description: "A test attack path",
    });
    expect(result).toHaveProperty("pathId");
    expect(typeof result.pathId).toBe("string");
  });

  it("retrieves an attack path", async () => {
    const created = await caller.attackPaths.create({
      name: "Retrieve Path",
      description: "For retrieval",
    });
    const result = await caller.attackPaths.get({ pathId: created.pathId });
    expect(result.name).toBe("Retrieve Path");
  });

  it("gets stats", async () => {
    const result = await caller.attackPaths.stats();
    expect(result).toHaveProperty("total");
    expect(typeof result.total).toBe("number");
  });

  it("deletes an attack path", async () => {
    const created = await caller.attackPaths.create({
      name: "Delete Path",
      description: "To be deleted",
    });
    const result = await caller.attackPaths.delete({ pathId: created.pathId });
    expect(result).toEqual({ success: true });
  });
});

// ─── Purple Team ──────────────────────────────────────────────────────────────

describe("purpleTeam router", () => {
  const { ctx } = createAuthContext();
  const caller = appRouter.createCaller(ctx);

  it("lists detection tests (empty initially)", async () => {
    const result = await caller.purpleTeam.listTests({});
    expect(result).toHaveProperty("items");
    expect(Array.isArray(result.items)).toBe(true);
  });

  it("creates a detection test", async () => {
    const result = await caller.purpleTeam.createTest({
      techniqueId: "T1059.001",
      techniqueName: "PowerShell",
      tactic: "execution",
      detected: true,
      isGap: false,
      executionResult: "success",
    });
    expect(result).toHaveProperty("testId");
    expect(typeof result.testId).toBe("string");
  });

  it("gets stats", async () => {
    const result = await caller.purpleTeam.stats();
    expect(result).toHaveProperty("totalTests");
    expect(result).toHaveProperty("coverageRate");
    expect(typeof result.totalTests).toBe("number");
  });

  it("gets coverage matrix", async () => {
    const result = await caller.purpleTeam.coverageMatrix();
    expect(result).toHaveProperty("matrix");
    expect(result).toHaveProperty("summary");
    expect(Array.isArray(result.matrix)).toBe(true);
  });

  it("deletes a detection test", async () => {
    const created = await caller.purpleTeam.createTest({
      techniqueId: "T1059.002",
      techniqueName: "AppleScript",
      tactic: "execution",
      detected: false,
      isGap: true,
      executionResult: "success",
    });
    const result = await caller.purpleTeam.deleteTest({ testId: created.testId });
    expect(result).toEqual({ success: true });
  });
});

// ─── Webhooks ─────────────────────────────────────────────────────────────────

describe("webhooks router", () => {
  const { ctx } = createAuthContext();
  const caller = appRouter.createCaller(ctx);

  it("lists webhooks (empty initially)", async () => {
    const result = await caller.webhooks.list({});
    expect(result).toHaveProperty("items");
    expect(Array.isArray(result.items)).toBe(true);
  });

  it("lists available events", async () => {
    const result = await caller.webhooks.availableEvents();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0]).toHaveProperty("event");
    expect(result[0]).toHaveProperty("description");
  });

  it("creates a webhook", async () => {
    const result = await caller.webhooks.create({
      name: "Test Webhook",
      url: "https://example.com/webhook",
      format: "json",
      events: ["operation.started", "scan.completed"],
    });
    expect(result).toHaveProperty("webhookId");
    expect(typeof result.webhookId).toBe("string");
  });

  it("retrieves a webhook with deliveries", async () => {
    const created = await caller.webhooks.create({
      name: "Retrieve Webhook",
      url: "https://example.com/hook2",
      format: "json",
      events: ["operation.started"],
    });
    const result = await caller.webhooks.get({ webhookId: created.webhookId });
    expect(result.name).toBe("Retrieve Webhook");
    expect(result).toHaveProperty("deliveries");
  });

  it("gets stats", async () => {
    const result = await caller.webhooks.stats();
    expect(result).toHaveProperty("totalWebhooks");
    expect(result).toHaveProperty("activeWebhooks");
    expect(typeof result.totalWebhooks).toBe("number");
  });

  it("deletes a webhook", async () => {
    const created = await caller.webhooks.create({
      name: "Delete Webhook",
      url: "https://example.com/hook3",
      format: "json",
      events: ["scan.completed"],
    });
    const result = await caller.webhooks.delete({ webhookId: created.webhookId });
    expect(result).toEqual({ success: true });
  });
});
