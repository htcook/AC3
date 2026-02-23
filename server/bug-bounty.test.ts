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
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: () => {} } as TrpcContext["res"],
  };
  return { ctx };
}

const caller = appRouter.createCaller(createAuthContext().ctx);

describe("bugBounty router", () => {
  it("returns credential status", async () => {
    const status = await caller.bugBounty.credentialStatus();
    expect(status).toHaveProperty("hackerOne");
    expect(status).toHaveProperty("bugcrowd");
    expect(status.hackerOne).toHaveProperty("configured");
    expect(status.bugcrowd).toHaveProperty("configured");
    expect(typeof status.hackerOne.configured).toBe("boolean");
    expect(typeof status.bugcrowd.configured).toBe("boolean");
  });

  it("returns empty stats initially", async () => {
    const stats = await caller.bugBounty.stats();
    expect(stats).toHaveProperty("programs");
    expect(stats).toHaveProperty("findings");
    expect(stats).toHaveProperty("correlations");
    expect(stats).toHaveProperty("severityBreakdown");
    expect(stats).toHaveProperty("platformBreakdown");
    expect(stats).toHaveProperty("topPrograms");
    expect(stats).toHaveProperty("correlationBreakdown");
    expect(typeof stats.programs).toBe("number");
    expect(typeof stats.findings).toBe("number");
  });

  it("adds a manual program", async () => {
    const result = await caller.bugBounty.addProgram({
      platform: "manual",
      handle: "test-program",
      name: "Test Bug Bounty Program",
      url: "https://example.com/bounty",
    });
    expect(result).toHaveProperty("id");
    expect(Number(result.id)).toBeGreaterThan(0);
  });

  it("lists programs", async () => {
    const result = await caller.bugBounty.listPrograms({
      platform: "all",
      limit: 25,
      offset: 0,
    });
    expect(result).toHaveProperty("programs");
    expect(result).toHaveProperty("total");
    expect(Array.isArray(result.programs)).toBe(true);
    expect(result.total).toBeGreaterThanOrEqual(1);
  });

  it("adds a manual finding", async () => {
    const result = await caller.bugBounty.addFinding({
      platform: "manual",
      title: "XSS in login form",
      severityRating: "high",
      cveIds: ["CVE-2024-9999"],
      cweId: "CWE-79",
      assetIdentifier: "login.example.com",
      summary: "Reflected XSS via username parameter",
    });
    expect(result).toHaveProperty("id");
    expect(Number(result.id)).toBeGreaterThan(0);
  });

  it("lists findings with filters", async () => {
    const result = await caller.bugBounty.listFindings({
      platform: "all",
      severity: "high",
      limit: 25,
      offset: 0,
    });
    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("total");
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it("runs correlation engine", async () => {
    const result = await caller.bugBounty.runCorrelation({});
    expect(result).toHaveProperty("total");
    expect(result).toHaveProperty("newCorrelations");
    expect(typeof result.total).toBe("number");
    expect(typeof result.newCorrelations).toBe("number");
  }, 30000);

  it("lists correlations", async () => {
    const result = await caller.bugBounty.listCorrelations({
      limit: 50,
      offset: 0,
    });
    expect(Array.isArray(result)).toBe(true);
  });

  it("returns sync history", async () => {
    const result = await caller.bugBounty.syncHistory({ limit: 10 });
    expect(Array.isArray(result)).toBe(true);
  });

  it("matches domains to programs", async () => {
    const result = await caller.bugBounty.matchDomainsToPrograms();
    expect(result).toHaveProperty("matches");
    expect(result).toHaveProperty("total");
    expect(Array.isArray(result.matches)).toBe(true);
    expect(typeof result.total).toBe("number");
  });

  it("deletes a finding", async () => {
    const added = await caller.bugBounty.addFinding({
      platform: "manual",
      title: "To be deleted",
      severityRating: "low",
    });
    const result = await caller.bugBounty.deleteFinding({ id: Number(added.id) });
    expect(result.success).toBe(true);
  });

  it("deletes a program", async () => {
    const added = await caller.bugBounty.addProgram({
      platform: "manual",
      handle: "to-delete",
      name: "Delete Me",
    });
    const result = await caller.bugBounty.deleteProgram({ id: Number(added.id) });
    expect(result.success).toBe(true);
  });
});
