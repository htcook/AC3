import {
  engagements,
  init_schema
} from "./chunk-YQRYZ5JK.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/engagement-access-guard.ts
import { eq, and, sql } from "drizzle-orm";
import { TRPCError } from "@trpc/server";
function hasFullAccess(user) {
  return FULL_ACCESS_ROLES.has(user.role);
}
function scopeEngagementWhere(user) {
  if (hasFullAccess(user)) return null;
  return eq(engagements.createdBy, user.id);
}
function scopedAnd(user, ...conditions) {
  const scope = scopeEngagementWhere(user);
  const validConditions = conditions.filter((c) => c !== void 0);
  if (scope) {
    return and(scope, ...validConditions);
  }
  if (validConditions.length === 0) return void 0;
  if (validConditions.length === 1) return validConditions[0];
  return and(...validConditions);
}
async function assertEngagementAccess(db, engagementId, user) {
  if (hasFullAccess(user)) return;
  const [row] = await db.select({ createdBy: engagements.createdBy }).from(engagements).where(eq(engagements.id, engagementId)).limit(1);
  if (!row) {
    throw new TRPCError({
      code: "NOT_FOUND",
      message: `Engagement #${engagementId} not found`
    });
  }
  if (row.createdBy !== user.id) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "You do not have access to this engagement"
    });
  }
}
async function getUserEngagementIds(db, user) {
  if (hasFullAccess(user)) return null;
  const rows = await db.select({ id: engagements.id }).from(engagements).where(eq(engagements.createdBy, user.id));
  return rows.map((r) => r.id);
}
function scopeByEngagementIds(column, engagementIds) {
  if (engagementIds === null) return null;
  if (engagementIds.length === 0) {
    return sql`1 = 0`;
  }
  return sql`${column} IN (${sql.join(engagementIds.map((id) => sql`${id}`), sql`, `)})`;
}
var FULL_ACCESS_ROLES, SCOPED_ROLES;
var init_engagement_access_guard = __esm({
  "server/lib/engagement-access-guard.ts"() {
    init_schema();
    FULL_ACCESS_ROLES = /* @__PURE__ */ new Set([
      "admin",
      "operator",
      "team_lead"
    ]);
    SCOPED_ROLES = /* @__PURE__ */ new Set([
      "client",
      "user",
      "viewer",
      "analyst",
      "executive",
      "soc"
    ]);
  }
});

export {
  FULL_ACCESS_ROLES,
  SCOPED_ROLES,
  hasFullAccess,
  scopeEngagementWhere,
  scopedAnd,
  assertEngagementAccess,
  getUserEngagementIds,
  scopeByEngagementIds,
  init_engagement_access_guard
};
