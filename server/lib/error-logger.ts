/**
 * Platform Error Logger — captures and persists runtime errors
 * for triage during production pen-test engagements.
 * Fire-and-forget: never throws, never blocks engagement flow.
 *
 * Engagement-scoped filtering:
 *   Errors carry an optional `engagementContext` JSON column with
 *   { engagementId, engagementName, ... }.  The dashboard can filter
 *   by engagement so operators see only errors relevant to their
 *   active pen-test.
 */
import { eq, desc, sql, and, like } from "drizzle-orm";
import { platformErrors } from "../../drizzle/schema";

async function getDb() {
  const { getDb: _getDb } = await import("../db");
  return _getDb();
}

export interface LogErrorInput {
  source: "client" | "server" | "unhandled_rejection" | "react_boundary" | "trpc";
  severity?: "critical" | "error" | "warning" | "info";
  message: string;
  stack?: string | null;
  page?: string | null;
  endpoint?: string | null;
  statusCode?: number | null;
  userId?: number | null;
  engagementContext?: Record<string, unknown> | null;
  clientMeta?: Record<string, unknown> | null;
  retryCount?: number;
  autoRecovered?: boolean;
}

export async function logPlatformError(input: LogErrorInput): Promise<number | null> {
  try {
    const db = await getDb();
    if (!db) {
      console.error("[ErrorLogger] DB unavailable, logging to console:", input.message);
      return null;
    }
    const [result] = await db.insert(platformErrors).values({
      source: input.source,
      severity: input.severity || "error",
      message: input.message.slice(0, 65535),
      stack: input.stack?.slice(0, 16777215) || null,
      page: input.page?.slice(0, 512) || null,
      endpoint: input.endpoint?.slice(0, 256) || null,
      statusCode: input.statusCode || null,
      userId: input.userId || null,
      engagementContext: input.engagementContext || null,
      clientMeta: input.clientMeta || null,
      retryCount: input.retryCount || 0,
      autoRecovered: input.autoRecovered || false,
    }).$returningId();
    return result?.id ?? null;
  } catch (err) {
    console.error("[ErrorLogger] Failed to persist error:", err);
    console.error("[ErrorLogger] Original error:", input.message);
    return null;
  }
}

// ─── Engagement-scoped condition builder ────────────────────────────────────
function buildEngagementConditions(engagementId?: number, engagementName?: string): any[] {
  const conditions: any[] = [];
  if (engagementId) {
    conditions.push(sql`JSON_EXTRACT(${platformErrors.engagementContext}, '$.engagementId') = ${engagementId}`);
  }
  if (engagementName) {
    conditions.push(sql`JSON_EXTRACT(${platformErrors.engagementContext}, '$.engagementName') LIKE ${`%${engagementName}%`}`);
  }
  return conditions;
}

export async function getRecentErrors(opts: {
  limit?: number;
  offset?: number;
  source?: string;
  severity?: string;
  resolved?: boolean;
  search?: string;
  /** Filter errors by engagement ID — isolates issues per client engagement */
  engagementId?: number;
  /** Filter errors by engagement name */
  engagementName?: string;
  /** Tenant isolation: restrict to errors from these engagement IDs only (non-admin users) */
  allowedEngagementIds?: number[];
} = {}): Promise<{ errors: any[]; total: number }> {
  const db = await getDb();
  if (!db) return { errors: [], total: 0 };
  const conditions: any[] = [];
  if (opts.source) conditions.push(eq(platformErrors.source, opts.source));
  if (opts.severity) conditions.push(eq(platformErrors.severity, opts.severity));
  if (opts.resolved !== undefined) conditions.push(eq(platformErrors.resolved, opts.resolved));
  if (opts.search) conditions.push(like(platformErrors.message, `%${opts.search}%`));
  // Engagement-scoped filtering
  conditions.push(...buildEngagementConditions(opts.engagementId, opts.engagementName));
  // Tenant isolation: only show errors from user's own engagements
  if (opts.allowedEngagementIds !== undefined) {
    if (opts.allowedEngagementIds.length === 0) {
      return { errors: [], total: 0 }; // User has no engagements
    }
    const idList = opts.allowedEngagementIds.map(id => String(id)).join(',');
    conditions.push(sql`JSON_EXTRACT(${platformErrors.engagementContext}, '$.engagementId') IN (${sql.raw(idList)})`);
  }
  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(where);
  const errors = await db.select().from(platformErrors).where(where).orderBy(desc(platformErrors.createdAt)).limit(opts.limit || 50).offset(opts.offset || 0);
  return { errors, total: Number(countResult?.count || 0) };
}

export async function resolveError(id: number, resolved: boolean, note?: string): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.update(platformErrors).set({
    resolved,
    resolvedNote: note || null,
    resolvedAt: resolved ? new Date() : null,
  }).where(eq(platformErrors.id, id));
}

export async function getErrorStats(opts: {
  engagementId?: number;
  engagementName?: string;
  /** Tenant isolation: restrict to errors from these engagement IDs only */
  allowedEngagementIds?: number[];
} = {}): Promise<{
  total: number; unresolved: number; critical: number; last24h: number; bySource: Record<string, number>;
}> {
  const db = await getDb();
  if (!db) return { total: 0, unresolved: 0, critical: 0, last24h: 0, bySource: {} };

  const engConds = buildEngagementConditions(opts.engagementId, opts.engagementName);
  // Tenant isolation: restrict stats to user's own engagements
  if (opts.allowedEngagementIds !== undefined) {
    if (opts.allowedEngagementIds.length === 0) {
      return { total: 0, unresolved: 0, critical: 0, last24h: 0, bySource: {} };
    }
    const idList = opts.allowedEngagementIds.map(id => String(id)).join(',');
    engConds.push(sql`JSON_EXTRACT(${platformErrors.engagementContext}, '$.engagementId') IN (${sql.raw(idList)})`);
  }
  const baseWhere = engConds.length > 0 ? and(...engConds) : undefined;

  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(baseWhere);
  const [unresolved] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(
    engConds.length > 0 ? and(eq(platformErrors.resolved, false), ...engConds) : eq(platformErrors.resolved, false)
  );
  const [critical] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(
    engConds.length > 0
      ? and(eq(platformErrors.severity, "critical"), eq(platformErrors.resolved, false), ...engConds)
      : and(eq(platformErrors.severity, "critical"), eq(platformErrors.resolved, false))
  );
  const [last24h] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(
    engConds.length > 0
      ? and(sql`${platformErrors.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`, ...engConds)
      : sql`${platformErrors.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`
  );
  const bySourceRows = await db.select({ source: platformErrors.source, count: sql<number>`COUNT(*)` }).from(platformErrors).where(
    engConds.length > 0 ? and(eq(platformErrors.resolved, false), ...engConds) : eq(platformErrors.resolved, false)
  ).groupBy(platformErrors.source);
  const bySource: Record<string, number> = {};
  for (const row of bySourceRows) bySource[row.source] = Number(row.count);
  return { total: Number(total?.count || 0), unresolved: Number(unresolved?.count || 0), critical: Number(critical?.count || 0), last24h: Number(last24h?.count || 0), bySource };
}

/**
 * List distinct engagements that have logged errors.
 * Returns engagement IDs and names extracted from the JSON engagement_context column.
 */
export async function getEngagementList(): Promise<Array<{ engagementId: number; engagementName: string; errorCount: number }>> {
  const db = await getDb();
  if (!db) return [];
  try {
    const rows = await db.execute(sql`
      SELECT
        JSON_EXTRACT(engagement_context, '$.engagementId') AS engagement_id,
        JSON_EXTRACT(engagement_context, '$.engagementName') AS engagement_name,
        COUNT(*) AS error_count
      FROM platform_errors
      WHERE engagement_context IS NOT NULL
        AND JSON_EXTRACT(engagement_context, '$.engagementId') IS NOT NULL
      GROUP BY engagement_id, engagement_name
      ORDER BY error_count DESC
    `);
    const result: Array<{ engagementId: number; engagementName: string; errorCount: number }> = [];
    const rowArray = Array.isArray(rows) ? (rows[0] || rows) : [];
    for (const row of (rowArray as any[])) {
      result.push({
        engagementId: Number(row.engagement_id),
        engagementName: String(row.engagement_name || "Unknown"),
        errorCount: Number(row.error_count),
      });
    }
    return result;
  } catch (err) {
    console.error("[ErrorLogger] getEngagementList failed:", err);
    return [];
  }
}

export async function purgeOldErrors(olderThanDays: number = 30): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  const [result] = await db.delete(platformErrors).where(and(eq(platformErrors.resolved, true), sql`${platformErrors.createdAt} < DATE_SUB(NOW(), INTERVAL ${olderThanDays} DAY)`));
  return (result as any)?.affectedRows || 0;
}
