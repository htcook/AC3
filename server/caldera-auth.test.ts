import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function createPublicContext() {
  const cookies: Record<string, { value: string; options: any }> = {};

  const ctx: TrpcContext = {
    user: null,
    req: {
      protocol: "https",
      hostname: "localhost",
      headers: { host: "localhost:3000" },
      cookies: {},
    } as any,
    res: {
      cookie: (name: string, value: string, options: any) => {
        cookies[name] = { value, options };
      },
      clearCookie: () => {},
    } as any,
  };

  return { ctx, cookies };
}

describe("calderaAuth.login", () => {
  it("accepts red / PVYedK$BUAYzyXaAegdEl2Dz and returns success", async () => {
    const { ctx, cookies } = createPublicContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.calderaAuth.login({
      username: "red",
      password: "PVYedK$BUAYzyXaAegdEl2Dz",
    });

    expect(result.success).toBe(true);
    expect(result.user?.username).toBe("red");
    expect(result.user?.role).toBe("admin");
    // Verify cookie was set
    expect(cookies["caldera_session"]).toBeDefined();
    expect(cookies["caldera_session"].value).toBeTruthy();
  });

  it("accepts admin / PVYedK$BUAYzyXaAegdEl2Dz and returns success", async () => {
    const { ctx, cookies } = createPublicContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.calderaAuth.login({
      username: "admin",
      password: "PVYedK$BUAYzyXaAegdEl2Dz",
    });

    expect(result.success).toBe(true);
    expect(result.user?.username).toBe("admin");
    expect(result.user?.role).toBe("admin");
  });

  it("accepts blue / PVYedK$BUAYzyXaAegdEl2Dz and returns success", async () => {
    const { ctx, cookies } = createPublicContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.calderaAuth.login({
      username: "blue",
      password: "PVYedK$BUAYzyXaAegdEl2Dz",
    });

    expect(result.success).toBe(true);
    expect(result.user?.username).toBe("blue");
    expect(result.user?.role).toBe("user");
  });

  it("rejects invalid password", async () => {
    const { ctx } = createPublicContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.calderaAuth.login({
      username: "red",
      password: "wrongpassword",
    });

    expect(result.success).toBe(false);
  });

  it("rejects invalid username", async () => {
    const { ctx } = createPublicContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.calderaAuth.login({
      username: "hacker",
      password: "PVYedK$BUAYzyXaAegdEl2Dz",
    });

    expect(result.success).toBe(false);
  });

  it("validates password resolution works correctly", async () => {
    // The resolveCalderaPassword function should return the custom password
    // regardless of the CALDERA_PASSWORD env var value
    const { ctx } = createPublicContext();
    const caller = appRouter.createCaller(ctx);
    // If login succeeds with the custom password, resolution is working
    const result = await caller.calderaAuth.login({
      username: "red",
      password: "PVYedK$BUAYzyXaAegdEl2Dz",
    });
    expect(result.success).toBe(true);
  });
});

describe("calderaAuth.session", () => {
  it("returns unauthenticated when no cookie present", async () => {
    const { ctx } = createPublicContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.calderaAuth.session();

    expect(result.authenticated).toBe(false);
    expect(result.user).toBeNull();
  });
});
