import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/tenant-isolation.ts
import { TRPCError } from "@trpc/server";
import { eq, and, sql } from "drizzle-orm";
async function resolveUserTenant(userId, requestedTenantId) {
  const { getDb } = await import("./db-UO2A3C4N.js");
  const { tenantMemberships, tenants } = await import("./schema-RL5B6OMI.js");
  const db = await getDb();
  if (!db) return null;
  const memberships = await db.select({
    tenantId: tenantMemberships.tmTenantId,
    tenantRole: tenantMemberships.tmRole,
    tenantName: tenants.tenantName,
    tenantPlan: tenants.tenantPlan,
    isActive: tenants.tenantIsActive
  }).from(tenantMemberships).innerJoin(tenants, eq(tenantMemberships.tmTenantId, tenants.id)).where(
    and(
      eq(tenantMemberships.tmUserId, userId),
      eq(tenants.tenantIsActive, 1)
    )
  );
  if (memberships.length === 0) return null;
  if (requestedTenantId) {
    const match = memberships.find((m) => m.tenantId === requestedTenantId);
    if (!match) return null;
    return {
      tenantId: match.tenantId,
      tenantRole: match.tenantRole,
      tenantName: match.tenantName,
      tenantPlan: match.tenantPlan
    };
  }
  const rolePriority = { owner: 0, admin: 1, operator: 2, viewer: 3 };
  const sorted = memberships.sort(
    (a, b) => rolePriority[a.tenantRole] - rolePriority[b.tenantRole]
  );
  const primary = sorted[0];
  return {
    tenantId: primary.tenantId,
    tenantRole: primary.tenantRole,
    tenantName: primary.tenantName,
    tenantPlan: primary.tenantPlan
  };
}
async function autoProvisionTenant(userId, userName) {
  const { getDb } = await import("./db-UO2A3C4N.js");
  const { tenants, tenantMemberships } = await import("./schema-RL5B6OMI.js");
  const db = await getDb();
  if (!db) throw new Error("Database unavailable for tenant provisioning");
  const tenantName = userName ? `${userName}'s Workspace` : "Default Workspace";
  const slug = `tenant-${userId}-${Date.now()}`;
  const [result] = await db.insert(tenants).values({
    tenantName,
    tenantSlug: slug,
    tenantIsActive: 1,
    tenantMaxUsers: 50,
    tenantPlan: "free"
  });
  const tenantId = result.insertId;
  await db.insert(tenantMemberships).values({
    tmTenantId: tenantId,
    tmUserId: userId,
    tmRole: "owner"
  });
  return {
    tenantId,
    tenantRole: "owner",
    tenantName,
    tenantPlan: "free"
  };
}
function tenantWhere(column, tenantId) {
  return eq(column, tenantId);
}
function tenantAnd(column, tenantId, ...conditions) {
  return and(eq(column, tenantId), ...conditions);
}
async function assertTenantOwnership(db, table, tenantColumn, idColumn, recordId, tenantId) {
  const rows = await db.select({ id: idColumn }).from(table).where(and(eq(idColumn, recordId), eq(tenantColumn, tenantId))).limit(1);
  if (rows.length === 0) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "Access denied: resource does not belong to your tenant"
    });
  }
}
function withTenant(tenantId, values) {
  return { ...values, tenantId };
}
async function logTenantAction(userId, tenantId, action, details) {
  try {
    const { getDb } = await import("./db-UO2A3C4N.js");
    const { activityLogs } = await import("./schema-RL5B6OMI.js");
    const db = await getDb();
    if (!db) return;
    await db.insert(activityLogs).values({
      userId,
      action,
      details: `[Tenant:${tenantId}] ${details}`,
      ipAddress: "system"
    });
  } catch {
  }
}
async function detectCrossTenantAccess(db, table, tenantColumn, idColumn, recordId, expectedTenantId, userId) {
  const rows = await db.select({ tenantId: tenantColumn }).from(table).where(eq(idColumn, recordId)).limit(1);
  if (rows.length === 0) return false;
  const actualTenantId = rows[0].tenantId;
  if (actualTenantId !== expectedTenantId) {
    await logTenantAction(
      userId,
      expectedTenantId,
      "CROSS_TENANT_ACCESS_BLOCKED",
      `User ${userId} attempted to access record ${recordId} belonging to tenant ${actualTenantId}`
    );
    return true;
  }
  return false;
}
async function getTenantStats(tenantId) {
  const { getDb } = await import("./db-UO2A3C4N.js");
  const { tenantMemberships, engagements } = await import("./schema-RL5B6OMI.js");
  const db = await getDb();
  if (!db) return null;
  const [memberCount] = await db.select({ count: sql`count(*)` }).from(tenantMemberships).where(eq(tenantMemberships.tmTenantId, tenantId));
  let engagementCount = 0;
  try {
    const [engCount] = await db.select({ count: sql`count(*)` }).from(engagements).where(eq(engagements.engTenantId, tenantId));
    engagementCount = engCount?.count ?? 0;
  } catch {
  }
  return {
    memberCount: memberCount?.count ?? 0,
    engagementCount
  };
}
var init_tenant_isolation = __esm({
  "server/lib/tenant-isolation.ts"() {
  }
});
init_tenant_isolation();
export {
  assertTenantOwnership,
  autoProvisionTenant,
  detectCrossTenantAccess,
  getTenantStats,
  logTenantAction,
  resolveUserTenant,
  tenantAnd,
  tenantWhere,
  withTenant
};
