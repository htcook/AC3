/**
 * Platform Error Logger — captures and persists runtime errors
 * for triage during production pen-test engagements.
 * Fire-and-forget: never throws, never blocks engagement flow.
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

export async function getRecentErrors(opts: {
  limit?: number;
  offset?: number;
  source?: string;
  severity?: string;
  resolved?: boolean;
  search?: string;
} = {}): Promise<{ errors: any[]; total: number }> {
  const db = await getDb();
  if (!db) return { errors: [], total: 0 };
  const conditions: any[] = [];
  if (opts.source) conditions.push(eq(platformErrors.source, opts.source));
  if (opts.severity) conditions.push(eq(platformErrors.severity, opts.severity));
  if (opts.resolved !== undefined) conditions.push(eq(platformErrors.resolved, opts.resolved));
  if (opts.search) conditions.push(like(platformErrors.message, `%${opts.search}%`));
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

export async function getErrorStats(): Promise<{
  total: number; unresolved: number; critical: number; last24h: number; bySource: Record<string, number>;
}> {
  const db = await getDb();
  if (!db) return { total: 0, unresolved: 0, critical: 0, last24h: 0, bySource: {} };
  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors);
  const [unresolved] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(eq(platformErrors.resolved, false));
  const [critical] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(and(eq(platformErrors.severity, "critical"), eq(platformErrors.resolved, false)));
  const [last24h] = await db.select({ count: sql<number>`COUNT(*)` }).from(platformErrors).where(sql`${platformErrors.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);
  const bySourceRows = await db.select({ source: platformErrors.source, count: sql<number>`COUNT(*)` }).from(platformErrors).where(eq(platformErrors.resolved, false)).groupBy(platformErrors.source);
  const bySource: Record<string, number> = {};
  for (const row of bySourceRows) bySource[row.source] = Number(row.count);
  return { total: Number(total?.count || 0), unresolved: Number(unresolved?.count || 0), critical: Number(critical?.count || 0), last24h: Number(last24h?.count || 0), bySource };
}

export async function purgeOldErrors(olderThanDays: number = 30): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  const [result] = await db.delete(platformErrors).where(and(eq(platformErrors.resolved, true), sql`${platformErrors.createdAt} < DATE_SUB(NOW(), INTERVAL ${olderThanDays} DAY)`));
  return (result as any)?.affectedRows || 0;
}
