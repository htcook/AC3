import { describe, expect, it, vi, beforeEach } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

// Mock fetch for Caldera API calls
const mockFetch = vi.fn();
global.fetch = mockFetch;

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(role: "admin" | "user" | "viewer" = "admin"): TrpcContext {
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

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

function createPublicContext(): TrpcContext {
  return {
    user: null,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

describe("auth router", () => {
  it("returns null for unauthenticated users", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.auth.me();
    expect(result).toBeNull();
  });

  it("returns user data for authenticated users", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.auth.me();
    expect(result).not.toBeNull();
    expect(result?.name).toBe("Test User");
    expect(result?.role).toBe("admin");
  });

  it("logout clears the session cookie", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const result = await caller.auth.logout();
    expect(result).toEqual({ success: true });
    expect(ctx.res.clearCookie).toHaveBeenCalled();
  });
});

describe("server router", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("requires authentication for server list", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    await expect(caller.server.list()).rejects.toThrow();
  });

  it("allows authenticated users to list servers", async () => {
    const ctx = createAuthContext("viewer");
    const caller = appRouter.createCaller(ctx);
    // This will return empty array since no servers exist in test DB
    const result = await caller.server.list();
    expect(Array.isArray(result)).toBe(true);
  });

  it("requires admin role to create servers", async () => {
    const ctx = createAuthContext("viewer");
    const caller = appRouter.createCaller(ctx);
    await expect(
      caller.server.create({
        name: "Test Server",
        ipAddress: "192.168.1.1",
      })
    ).rejects.toThrow("Admin access required");
  });
});

describe("credentials router", () => {
  it("requires authentication to list credentials", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    await expect(caller.credentials.list({ serverId: 1 })).rejects.toThrow();
  });

  it("requires admin role to create credentials", async () => {
    const ctx = createAuthContext("user");
    const caller = appRouter.createCaller(ctx);
    await expect(
      caller.credentials.create({
        serverId: 1,
        credentialType: "admin_login",
        username: "admin",
        password: "password123",
      })
    ).rejects.toThrow("Admin access required");
  });
});

describe("team router", () => {
  it("requires admin role to list team members", async () => {
    const ctx = createAuthContext("user");
    const caller = appRouter.createCaller(ctx);
    await expect(caller.team.list()).rejects.toThrow("Admin access required");
  });

  it("allows admin to list team members", async () => {
    const ctx = createAuthContext("admin");
    const caller = appRouter.createCaller(ctx);
    const result = await caller.team.list();
    expect(Array.isArray(result)).toBe(true);
  });

  it("requires admin role to update user roles", async () => {
    const ctx = createAuthContext("viewer");
    const caller = appRouter.createCaller(ctx);
    await expect(
      caller.team.updateRole({ userId: 2, role: "admin" })
    ).rejects.toThrow("Admin access required");
  });
});

describe("activity router", () => {
  it("requires authentication to view activity logs", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    await expect(caller.activity.list({})).rejects.toThrow();
  });

  it("allows authenticated users to view activity logs", async () => {
    const ctx = createAuthContext("viewer");
    const caller = appRouter.createCaller(ctx);
    const result = await caller.activity.list({});
    expect(Array.isArray(result)).toBe(true);
  });
});

describe("caldera router", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("requires authentication to get stats", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    await expect(caller.caldera.getStats({ serverId: 1 })).rejects.toThrow();
  });

  it("requires authentication to get adversaries", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    await expect(caller.caldera.getAdversaries({ serverId: 1 })).rejects.toThrow();
  });

  it("requires authentication to get operations", async () => {
    const ctx = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    await expect(caller.caldera.getOperations({ serverId: 1 })).rejects.toThrow();
  });
});
