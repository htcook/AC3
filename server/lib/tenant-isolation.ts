/**
 * Tenant Isolation Middleware — P0 Gap Remediation
 * 
 * Provides row-level security enforcement across all tenant-scoped tables.
 * Every protected procedure that accesses tenant-scoped data MUST use the
 * tenant context injected by this middleware.
 * 
 * Architecture:
 * 1. TenantMiddleware resolves the user's active tenant from tenantMemberships
 * 2. Injects tenantId + tenantRole into the tRPC context
 * 3. TenantScopedQuery helpers enforce WHERE tenant_id = ? on all queries
 * 4. Cross-tenant access is structurally impossible when using these helpers
 */

import { TRPCError } from "@trpc/server";
import { eq, and, sql, SQL } from "drizzle-orm";
import type { MySqlColumn } from "drizzle-orm/mysql-core";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TenantContext {
  tenantId: number;
  tenantRole: "owner" | "admin" | "operator" | "viewer";
  tenantName: string;
  tenantPlan: "free" | "pro" | "enterprise";
}

export interface TenantIsolationConfig {
  /** If true, allow users with no tenant membership (e.g., super-admins) */
  allowUntenanted?: boolean;
  /** If true, require specific tenant roles for this operation */
  requiredRoles?: Array<"owner" | "admin" | "operator" | "viewer">;
}

// ─── Tenant Resolution ──────────────────────────────────────────────────────

/**
 * Resolves the active tenant for a user. If the user belongs to multiple tenants,
 * uses the X-Tenant-Id header to disambiguate. Falls back to the first tenant.
 */
export async function resolveUserTenant(
  userId: number,
  requestedTenantId?: number | null
): Promise<TenantContext | null> {
  const { getDb } = await import("../db");
  const { tenantMemberships, tenants } = await import("../../drizzle/schema");
  const db = await getDb();
  if (!db) return null;

  // Get all tenant memberships for this user
  const memberships = await db
    .select({
      tenantId: tenantMemberships.tenantId,
      tenantRole: tenantMemberships.role,
      tenantName: tenants.name,
      tenantPlan: tenants.plan,
      isActive: tenants.isActive,
    })
    .from(tenantMemberships)
    .innerJoin(tenants, eq(tenantMemberships.tenantId, tenants.id))
    .where(
      and(
        eq(tenantMemberships.userId, userId),
        eq(tenants.isActive, true)
      )
    );

  if (memberships.length === 0) return null;

  // If a specific tenant was requested, validate membership
  if (requestedTenantId) {
    const match = memberships.find((m) => m.tenantId === requestedTenantId);
    if (!match) return null; // User is not a member of the requested tenant
    return {
      tenantId: match.tenantId,
      tenantRole: match.tenantRole,
      tenantName: match.tenantName,
      tenantPlan: match.tenantPlan,
    };
  }

  // Default to the first active tenant (owner > admin > operator > viewer priority)
  const rolePriority = { owner: 0, admin: 1, operator: 2, viewer: 3 };
  const sorted = memberships.sort(
    (a, b) => rolePriority[a.tenantRole] - rolePriority[b.tenantRole]
  );
  const primary = sorted[0];
  return {
    tenantId: primary.tenantId,
    tenantRole: primary.tenantRole,
    tenantName: primary.tenantName,
    tenantPlan: primary.tenantPlan,
  };
}

// ─── Auto-Provisioning ──────────────────────────────────────────────────────

/**
 * Creates a default tenant for a user if they don't belong to any tenant.
 * This is used during first login to ensure every user has a tenant context.
 */
export async function autoProvisionTenant(
  userId: number,
  userName: string | null
): Promise<TenantContext> {
  const { getDb } = await import("../db");
  const { tenants, tenantMemberships } = await import("../../drizzle/schema");
  const db = await getDb();
  if (!db) throw new Error("Database unavailable for tenant provisioning");

  const tenantName = userName ? `${userName}'s Workspace` : "Default Workspace";
  const slug = `tenant-${userId}-${Date.now()}`;

  const [result] = await db.insert(tenants).values({
    name: tenantName,
    slug,
    isActive: true,
    maxUsers: 50,
    plan: "free",
  });

  const tenantId = result.insertId;

  await db.insert(tenantMemberships).values({
    tenantId,
    userId,
    role: "owner",
  });

  return {
    tenantId,
    tenantRole: "owner",
    tenantName,
    tenantPlan: "free",
  };
}

// ─── Scoped Query Helpers ───────────────────────────────────────────────────

/**
 * Creates a WHERE clause that enforces tenant isolation on a query.
 * Use this in every query that accesses tenant-scoped data.
 * 
 * @example
 * const rows = await db.select().from(engagements)
 *   .where(tenantWhere(engagements.tenantId, ctx.tenant.tenantId));
 */
export function tenantWhere(
  column: MySqlColumn,
  tenantId: number
): SQL {
  return eq(column, tenantId);
}

/**
 * Combines tenant isolation with additional conditions.
 * 
 * @example
 * const rows = await db.select().from(engagements)
 *   .where(tenantAnd(engagements.tenantId, ctx.tenant.tenantId, 
 *     eq(engagements.status, 'active')));
 */
export function tenantAnd(
  column: MySqlColumn,
  tenantId: number,
  ...conditions: SQL[]
): SQL {
  return and(eq(column, tenantId), ...conditions)!;
}

/**
 * Validates that a specific record belongs to the given tenant.
 * Throws FORBIDDEN if the record doesn't belong to the tenant.
 * 
 * @example
 * await assertTenantOwnership(db, engagements, engagements.tenantId, 
 *   engagements.id, engagementId, ctx.tenant.tenantId);
 */
export async function assertTenantOwnership(
  db: any,
  table: any,
  tenantColumn: MySqlColumn,
  idColumn: MySqlColumn,
  recordId: number,
  tenantId: number
): Promise<void> {
  const rows = await db
    .select({ id: idColumn })
    .from(table)
    .where(and(eq(idColumn, recordId), eq(tenantColumn, tenantId)))
    .limit(1);

  if (rows.length === 0) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "Access denied: resource does not belong to your tenant",
    });
  }
}

// ─── Tenant-Scoped Insert Helper ────────────────────────────────────────────

/**
 * Adds tenantId to an insert values object.
 * Ensures every new record is tagged with the correct tenant.
 * 
 * @example
 * await db.insert(engagements).values(
 *   withTenant(ctx.tenant.tenantId, { name: 'Test', ... })
 * );
 */
export function withTenant<T extends Record<string, any>>(
  tenantId: number,
  values: T
): T & { tenantId: number } {
  return { ...values, tenantId };
}

// ─── Audit Logging ──────────────────────────────────────────────────────────

/**
 * Logs a tenant-scoped action to the activity log.
 */
export async function logTenantAction(
  userId: number,
  tenantId: number,
  action: string,
  details: string
): Promise<void> {
  try {
    const { getDb } = await import("../db");
    const { activityLogs } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) return;

    await db.insert(activityLogs).values({
      userId,
      action,
      details: `[Tenant:${tenantId}] ${details}`,
      ipAddress: "system",
    });
  } catch {
    // Non-critical — don't fail the operation if audit logging fails
  }
}

// ─── Cross-Tenant Access Detection ─────────────────────────────────────────

/**
 * Detects and blocks potential cross-tenant access attempts.
 * Call this when a request references a resource ID that might belong
 * to a different tenant.
 */
export async function detectCrossTenantAccess(
  db: any,
  table: any,
  tenantColumn: MySqlColumn,
  idColumn: MySqlColumn,
  recordId: number,
  expectedTenantId: number,
  userId: number
): Promise<boolean> {
  const rows = await db
    .select({ tenantId: tenantColumn })
    .from(table)
    .where(eq(idColumn, recordId))
    .limit(1);

  if (rows.length === 0) return false; // Record doesn't exist
  
  const actualTenantId = rows[0].tenantId;
  if (actualTenantId !== expectedTenantId) {
    // Log the cross-tenant access attempt
    await logTenantAction(
      userId,
      expectedTenantId,
      "CROSS_TENANT_ACCESS_BLOCKED",
      `User ${userId} attempted to access record ${recordId} belonging to tenant ${actualTenantId}`
    );
    return true; // Cross-tenant access detected
  }
  return false;
}

// ─── Tenant Statistics ──────────────────────────────────────────────────────

export async function getTenantStats(tenantId: number) {
  const { getDb } = await import("../db");
  const { tenantMemberships, engagements } = await import("../../drizzle/schema");
  const db = await getDb();
  if (!db) return null;

  const [memberCount] = await db
    .select({ count: sql<number>`count(*)` })
    .from(tenantMemberships)
    .where(eq(tenantMemberships.tenantId, tenantId));

  // Count engagements if the table has tenantId
  let engagementCount = 0;
  try {
    const [engCount] = await db
      .select({ count: sql<number>`count(*)` })
      .from(engagements)
      .where(eq(engagements.tenantId, tenantId));
    engagementCount = engCount?.count ?? 0;
  } catch {
    // tenantId column may not exist yet during migration
  }

  return {
    memberCount: memberCount?.count ?? 0,
    engagementCount,
  };
}
