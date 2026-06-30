/**
 * Engagement Access Guard — Tenant Isolation Tests
 *
 * Verifies that non-admin users can only access their own engagements,
 * while admin/operator/team_lead users have full access.
 */
import { describe, it, expect, vi } from "vitest";
import {
  hasFullAccess,
  scopeEngagementWhere,
  assertEngagementAccess,
  getUserEngagementIds,
} from "./engagement-access-guard";

// ─── Mock user factories ─────────────────────────────────────────────────────

function makeUser(overrides: Partial<{ id: number; role: string; name: string }> = {}) {
  return {
    id: overrides.id ?? 1,
    role: (overrides.role ?? "user") as any,
    name: overrides.name ?? "Test User",
    openId: "test-open-id",
    email: "test@example.com",
    avatarUrl: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    tenantId: null,
  };
}

// ─── hasFullAccess ───────────────────────────────────────────────────────────

describe("hasFullAccess", () => {
  it("returns true for admin role", () => {
    expect(hasFullAccess(makeUser({ role: "admin" }))).toBe(true);
  });

  it("returns true for team_lead role", () => {
    expect(hasFullAccess(makeUser({ role: "team_lead" }))).toBe(true);
  });

  it("returns true for operator role", () => {
    expect(hasFullAccess(makeUser({ role: "operator" }))).toBe(true);
  });

  it("returns false for client role", () => {
    expect(hasFullAccess(makeUser({ role: "client" }))).toBe(false);
  });

  it("returns false for user role", () => {
    expect(hasFullAccess(makeUser({ role: "user" }))).toBe(false);
  });

  it("returns false for viewer role", () => {
    expect(hasFullAccess(makeUser({ role: "viewer" }))).toBe(false);
  });

  it("returns false for analyst role", () => {
    expect(hasFullAccess(makeUser({ role: "analyst" }))).toBe(false);
  });

  it("returns false for executive role", () => {
    expect(hasFullAccess(makeUser({ role: "executive" }))).toBe(false);
  });

  it("returns false for soc role", () => {
    expect(hasFullAccess(makeUser({ role: "soc" }))).toBe(false);
  });
});

// ─── scopeEngagementWhere ────────────────────────────────────────────────────

describe("scopeEngagementWhere", () => {
  it("returns null for admin users (no filter needed)", () => {
    expect(scopeEngagementWhere(makeUser({ role: "admin" }))).toBeNull();
  });

  it("returns null for operator users (no filter needed)", () => {
    expect(scopeEngagementWhere(makeUser({ role: "operator" }))).toBeNull();
  });

  it("returns a SQL condition for client users", () => {
    const condition = scopeEngagementWhere(makeUser({ id: 42, role: "client" }));
    expect(condition).not.toBeNull();
    // The condition should be a drizzle SQL expression
    expect(condition).toBeDefined();
  });

  it("returns a SQL condition for user role", () => {
    const condition = scopeEngagementWhere(makeUser({ id: 7, role: "user" }));
    expect(condition).not.toBeNull();
    expect(condition).toBeDefined();
  });
});

// ─── assertEngagementAccess ──────────────────────────────────────────────────

describe("assertEngagementAccess", () => {
  it("allows admin users without DB check", async () => {
    const mockDb = {} as any; // Should not be called
    // Admin should pass without any DB query
    await expect(
      assertEngagementAccess(mockDb, 123, makeUser({ role: "admin" }))
    ).resolves.toBeUndefined();
  });

  it("allows operator users without DB check", async () => {
    const mockDb = {} as any;
    await expect(
      assertEngagementAccess(mockDb, 123, makeUser({ role: "operator" }))
    ).resolves.toBeUndefined();
  });

  it("allows team_lead users without DB check", async () => {
    const mockDb = {} as any;
    await expect(
      assertEngagementAccess(mockDb, 123, makeUser({ role: "team_lead" }))
    ).resolves.toBeUndefined();
  });

  it("throws FORBIDDEN for client user accessing another user's engagement", async () => {
    // Mock DB that returns an engagement owned by user 99
    const mockDb = {
      select: () => ({
        from: () => ({
          where: () => ({
            limit: () => [{ createdBy: 99 }],
          }),
        }),
      }),
    } as any;

    await expect(
      assertEngagementAccess(mockDb, 123, makeUser({ id: 42, role: "client" }))
    ).rejects.toThrow();
  });

  it("allows client user accessing their own engagement", async () => {
    const mockDb = {
      select: () => ({
        from: () => ({
          where: () => ({
            limit: () => [{ createdBy: 42 }],
          }),
        }),
      }),
    } as any;

    await expect(
      assertEngagementAccess(mockDb, 123, makeUser({ id: 42, role: "client" }))
    ).resolves.toBeUndefined();
  });

  it("throws NOT_FOUND for non-existent engagement", async () => {
    const mockDb = {
      select: () => ({
        from: () => ({
          where: () => ({
            limit: () => [],
          }),
        }),
      }),
    } as any;

    await expect(
      assertEngagementAccess(mockDb, 999, makeUser({ id: 42, role: "client" }))
    ).rejects.toThrow();
  });
});

// ─── getUserEngagementIds ────────────────────────────────────────────────────

describe("getUserEngagementIds", () => {
  it("returns null for admin users (no restriction)", async () => {
    const mockDb = {} as any;
    const result = await getUserEngagementIds(mockDb, makeUser({ role: "admin" }));
    expect(result).toBeNull();
  });

  it("returns array of engagement IDs for client users", async () => {
    const mockDb = {
      select: () => ({
        from: () => ({
          where: () => [{ id: 1 }, { id: 2 }, { id: 5 }],
        }),
      }),
    } as any;

    const result = await getUserEngagementIds(mockDb, makeUser({ id: 42, role: "client" }));
    expect(result).toEqual([1, 2, 5]);
  });

  it("returns empty array for client user with no engagements", async () => {
    const mockDb = {
      select: () => ({
        from: () => ({
          where: () => [],
        }),
      }),
    } as any;

    const result = await getUserEngagementIds(mockDb, makeUser({ id: 42, role: "client" }));
    expect(result).toEqual([]);
  });
});
