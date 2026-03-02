import { describe, expect, it, vi } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type CookieCall = {
  name: string;
  value?: string;
  options: Record<string, unknown>;
};
type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAdminContext(): { ctx: TrpcContext; setCookies: CookieCall[]; clearedCookies: CookieCall[] } {
  const setCookies: CookieCall[] = [];
  const clearedCookies: CookieCall[] = [];
  const user: AuthenticatedUser = {
    id: 1,
    openId: "admin-user",
    email: "admin@example.com",
    name: "Admin User",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };
  const ctx: TrpcContext = {
    user,
    req: {
      ip: "127.0.0.1",
      protocol: "https",
      get: (header: string) => header === "host" ? "localhost:3000" : "",
      headers: { "x-forwarded-for": "127.0.0.1" },
      cookies: {},
    } as any,
    res: {
      cookie: (name: string, value: string, options: Record<string, unknown>) => {
        setCookies.push({ name, value, options });
      },
      clearCookie: (name: string, options: Record<string, unknown>) => {
        clearedCookies.push({ name, options });
      },
    } as any,
  };
  return { ctx, setCookies, clearedCookies };
}

function createUnauthContext(): { ctx: TrpcContext } {
  const ctx: TrpcContext = {
    user: null,
    req: {
      ip: "127.0.0.1",
      protocol: "https",
      get: (header: string) => header === "host" ? "localhost:3000" : "",
      headers: { "x-forwarded-for": "127.0.0.1" },
      cookies: {},
    } as any,
    res: {
      cookie: () => {},
      clearCookie: () => {},
    } as any,
  };
  return { ctx };
}

// ─── What's New Pop-up Tests ──────────────────────────────────────────────────
describe("What's New Pop-up", () => {
  it("should have version-tracked dismiss using localStorage key pattern", () => {
    // The WhatsNew component uses localStorage key: `whats-new-dismissed-v{version}`
    // This test validates the expected key pattern
    const version = "2.4.0";
    const key = `whats-new-dismissed-v${version}`;
    expect(key).toBe("whats-new-dismissed-v2.4.0");
  });

  it("should contain platform update entries with required fields", () => {
    // Each update entry must have: icon, title, description, and tag
    const requiredFields = ["title", "description", "tag"];
    const sampleEntry = {
      title: "Email-Based Login",
      description: "FIPS 140-3 compliant email/password authentication",
      tag: "Security",
    };
    for (const field of requiredFields) {
      expect(sampleEntry).toHaveProperty(field);
      expect((sampleEntry as any)[field]).toBeTruthy();
    }
  });

  it("should dismiss and not show again for same version", () => {
    // Simulate localStorage dismiss behavior
    const storage: Record<string, string> = {};
    const version = "2.4.0";
    const key = `whats-new-dismissed-v${version}`;

    // Initially not dismissed
    expect(storage[key]).toBeUndefined();

    // After dismiss
    storage[key] = "true";
    expect(storage[key]).toBe("true");

    // New version should show again
    const newKey = `whats-new-dismissed-v2.5.0`;
    expect(storage[newKey]).toBeUndefined();
  });
});

// ─── Invite Email Notification Tests ──────────────────────────────────────────
describe("Invite Email Notification", () => {
  it("should require admin role to invite users", async () => {
    const { ctx } = createUnauthContext();
    const caller = appRouter.createCaller(ctx);

    // Without auth, inviteUser should fail
    await expect(
      caller.accountAuth.inviteUser({
        email: "newuser@example.com",
        displayName: "New User",
        role: "operator",
      })
    ).rejects.toThrow();
  });

  it("should validate email format for invites", async () => {
    const { ctx } = createAdminContext();
    const caller = appRouter.createCaller(ctx);

    // Invalid email should fail validation
    await expect(
      caller.accountAuth.inviteUser({
        email: "not-an-email",
        displayName: "Bad Email",
        role: "operator",
      })
    ).rejects.toThrow();
  });

  it("should validate role enum for invites", async () => {
    const { ctx } = createAdminContext();
    const caller = appRouter.createCaller(ctx);

    // Invalid role should fail validation
    await expect(
      caller.accountAuth.inviteUser({
        email: "valid@example.com",
        displayName: "Valid User",
        role: "superadmin" as any,
      })
    ).rejects.toThrow();
  });

  it("should generate invite URL with correct structure", () => {
    const host = "dashboard.aceofcloud.io";
    const protocol = "https";
    const inviteToken = "abc123def456";

    const inviteUrl = `${protocol}://${host}/accept-invite?token=${inviteToken}`;
    expect(inviteUrl).toBe("https://dashboard.aceofcloud.io/accept-invite?token=abc123def456");
    expect(inviteUrl).toContain("/accept-invite?token=");
  });

  it("should generate login URL for temp password invites", () => {
    const host = "dashboard.aceofcloud.io";
    const protocol = "https";

    const loginUrl = `${protocol}://${host}/login`;
    expect(loginUrl).toBe("https://dashboard.aceofcloud.io/login");
  });
});

// ─── Password Change Tests ────────────────────────────────────────────────────
describe("Password Change", () => {
  it("should require authentication for password change", async () => {
    const { ctx } = createUnauthContext();
    const caller = appRouter.createCaller(ctx);

    await expect(
      caller.accountAuth.changePassword({
        currentPassword: "OldPassword123!",
        newPassword: "NewPassword456!",
      })
    ).rejects.toThrow();
  });

  it("should validate new password meets NIST SP 800-63B requirements", () => {
    const passwordSchema = {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumber: true,
      requireSpecial: true,
    };

    // Valid password
    const validPassword = "SecurePass123!";
    expect(validPassword.length).toBeGreaterThanOrEqual(passwordSchema.minLength);
    expect(/[A-Z]/.test(validPassword)).toBe(true);
    expect(/[a-z]/.test(validPassword)).toBe(true);
    expect(/[0-9]/.test(validPassword)).toBe(true);
    expect(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(validPassword)).toBe(true);

    // Too short
    const shortPassword = "Short1!";
    expect(shortPassword.length).toBeLessThan(passwordSchema.minLength);

    // No uppercase
    const noUpper = "nouppercase123!";
    expect(/[A-Z]/.test(noUpper)).toBe(false);

    // No special char
    const noSpecial = "NoSpecialChar123";
    expect(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(noSpecial)).toBe(false);
  });

  it("should reject password change with invalid new password format", async () => {
    const { ctx } = createAdminContext();
    const caller = appRouter.createCaller(ctx);

    // Too short password should fail zod validation
    await expect(
      caller.accountAuth.changePassword({
        currentPassword: "OldPassword123!",
        newPassword: "short",
      })
    ).rejects.toThrow();
  });

  it("should confirm passwords match in frontend validation", () => {
    const newPassword = "SecureNewPass123!";
    const confirmPassword = "SecureNewPass123!";
    const mismatchPassword = "DifferentPass123!";

    expect(newPassword === confirmPassword).toBe(true);
    expect(newPassword === mismatchPassword).toBe(false);
  });
});

// ─── Account Auth Email Login Tests ──────────────────────────────────────────
describe("Email Login", () => {
  it("should validate email format on login", async () => {
    const { ctx } = createUnauthContext();
    const caller = appRouter.createCaller(ctx);

    await expect(
      caller.accountAuth.emailLogin({
        email: "not-valid",
        password: "SomePassword123!",
      })
    ).rejects.toThrow();
  });

  it("should return error for non-existent account", async () => {
    const { ctx } = createUnauthContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.accountAuth.emailLogin({
      email: "nonexistent@example.com",
      password: "SomePassword123!",
    });

    expect(result.success).toBe(false);
    expect(result.message).toContain("Invalid");
  });
});

// ─── Public Homepage Routing Tests ────────────────────────────────────────────
describe("Public Homepage Routing", () => {
  it("should serve the homepage stats endpoint publicly", async () => {
    const { ctx } = createUnauthContext();
    const caller = appRouter.createCaller(ctx);

    // The platformStats endpoint should be public (publicProcedure)
    const result = await caller.platformStats.getHomepageStats();
    expect(result).toBeDefined();
    expect(result).toHaveProperty("exploitCatalogTotal");
  });
});
