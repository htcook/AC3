/**
 * Engagement Access Guard — Row-Level Security for Multi-Tenancy
 *
 * Enforces that non-admin users can only access engagements they created.
 * Admin/operator/team_lead roles retain full visibility across all engagements.
 * Customer-facing roles (client, user, viewer, analyst, executive, soc) are
 * scoped to their own engagements via the `createdBy` column.
 *
 * Usage:
 *   import { scopeEngagementWhere, assertEngagementAccess, FULL_ACCESS_ROLES } from "./engagement-access-guard";
 *
 *   // In a list query:
 *   const where = scopeEngagementWhere(ctx.user);
 *   const rows = await db.select().from(engagements).where(where ? and(where, ...otherConds) : and(...otherConds));
 *
 *   // In a single-record query:
 *   await assertEngagementAccess(db, engagementId, ctx.user);
 */
import { eq, and, SQL, sql } from "drizzle-orm";
import { TRPCError } from "@trpc/server";
import { engagements } from "../../drizzle/schema";

// ─── Role Classification ─────────────────────────────────────────────────────

/**
 * Roles with full visibility across all engagements.
 * These are internal AC3 staff roles.
 */
export const FULL_ACCESS_ROLES = new Set([
  "admin",
  "operator",
  "team_lead",
]);

/**
 * Roles scoped to their own engagements only.
 * These are customer-facing or limited-access roles.
 */
export const SCOPED_ROLES = new Set([
  "client",
  "user",
  "viewer",
  "analyst",
  "executive",
  "soc",
]);

export interface AccessUser {
  id: number;
  role: string;
}

/**
 * Returns true if the user has full (unscoped) access to all engagements.
 */
export function hasFullAccess(user: AccessUser): boolean {
  return FULL_ACCESS_ROLES.has(user.role);
}

// ─── Query Scoping ───────────────────────────────────────────────────────────

/**
 * Returns a WHERE clause that scopes engagement queries to the user's own
 * engagements. Returns `null` for admin-level roles (no scoping needed).
 *
 * @example
 * const scope = scopeEngagementWhere(ctx.user);
 * const rows = await db.select().from(engagements)
 *   .where(scope ? and(scope, eq(engagements.status, 'active')) : eq(engagements.status, 'active'));
 */
export function scopeEngagementWhere(user: AccessUser): SQL | null {
  if (hasFullAccess(user)) return null;
  return eq(engagements.createdBy, user.id);
}

/**
 * Combines engagement scoping with additional WHERE conditions.
 * Handles the null case (admin = no scoping) transparently.
 *
 * @example
 * const rows = await db.select().from(engagements)
 *   .where(scopedAnd(ctx.user, eq(engagements.status, 'active')));
 */
export function scopedAnd(user: AccessUser, ...conditions: (SQL | undefined)[]): SQL | undefined {
  const scope = scopeEngagementWhere(user);
  const validConditions = conditions.filter((c): c is SQL => c !== undefined);
  if (scope) {
    return and(scope, ...validConditions);
  }
  if (validConditions.length === 0) return undefined;
  if (validConditions.length === 1) return validConditions[0];
  return and(...validConditions);
}

// ─── Single-Record Access Check ──────────────────────────────────────────────

/**
 * Asserts that the user has access to a specific engagement.
 * Throws FORBIDDEN if the user is scoped and the engagement was not created by them.
 *
 * @param db - Drizzle database instance
 * @param engagementId - The engagement ID to check
 * @param user - The requesting user
 * @throws TRPCError with code FORBIDDEN if access is denied
 * @throws TRPCError with code NOT_FOUND if the engagement doesn't exist
 */
export async function assertEngagementAccess(
  db: any,
  engagementId: number,
  user: AccessUser
): Promise<void> {
  if (hasFullAccess(user)) return; // Admin-level roles skip the check

  const [row] = await db
    .select({ createdBy: engagements.createdBy })
    .from(engagements)
    .where(eq(engagements.id, engagementId))
    .limit(1);

  if (!row) {
    throw new TRPCError({
      code: "NOT_FOUND",
      message: `Engagement #${engagementId} not found`,
    });
  }

  if (row.createdBy !== user.id) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "You do not have access to this engagement",
    });
  }
}

/**
 * Returns the list of engagement IDs the user has access to.
 * For admin-level roles, returns null (meaning "all").
 * For scoped roles, returns an array of engagement IDs created by the user.
 *
 * Useful for filtering related tables (findings, reports, errors) that
 * reference engagementId but don't have a direct createdBy column.
 */
export async function getUserEngagementIds(
  db: any,
  user: AccessUser
): Promise<number[] | null> {
  if (hasFullAccess(user)) return null; // null = all engagements

  const rows = await db
    .select({ id: engagements.id })
    .from(engagements)
    .where(eq(engagements.createdBy, user.id));

  return rows.map((r: { id: number }) => r.id);
}

/**
 * Builds a SQL IN clause for engagement IDs the user can access.
 * Returns null for admin-level roles (no filtering needed).
 * Returns a SQL condition for scoped roles.
 *
 * @param column - The engagementId column to filter on (e.g., engagementFindings.engagementId)
 * @param engagementIds - Pre-fetched list of accessible engagement IDs (from getUserEngagementIds)
 */
export function scopeByEngagementIds(
  column: any,
  engagementIds: number[] | null
): SQL | null {
  if (engagementIds === null) return null; // Admin = no filter
  if (engagementIds.length === 0) {
    // User has no engagements — return impossible condition
    return sql`1 = 0`;
  }
  return sql`${column} IN (${sql.join(engagementIds.map(id => sql`${id}`), sql`, `)})`;
}
