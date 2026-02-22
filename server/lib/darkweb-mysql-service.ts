/**
 * Darkweb MySQL CRUD Service
 *
 * Query helpers for all darkweb intelligence tables.
 * Used by the tRPC router to serve the Darkweb Intel UI.
 */

import { getDb } from "../db";
import {
  undergroundIntelEvents,
  networkEvents,
  iabActivity,
  influenceOperations,
  credentialExposures,
  darkwebEnrichedRecords,
  darkwebFeedRegistry,
  ransomwareAffiliates,
  type InsertUndergroundIntelEvent,
  type InsertNetworkEvent,
  type InsertIabActivity,
  type InsertInfluenceOperation,
  type InsertCredentialExposure,
  type InsertRansomwareAffiliate,
} from "../../drizzle/schema";
import { eq, desc, sql, like, and, or, gte, lte, inArray } from "drizzle-orm";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── Underground Intel Events ────────────────────────────────────────────

export async function getUndergroundEvents(opts: {
  category?: string;
  source?: string;
  severity?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await requireDb();
  const conditions: any[] = [];
  if (opts.category) conditions.push(eq(undergroundIntelEvents.category, opts.category as any));
  if (opts.source) conditions.push(eq(undergroundIntelEvents.source, opts.source));
  if (opts.severity) conditions.push(eq(undergroundIntelEvents.severity, opts.severity as any));
  if (opts.search) conditions.push(
    or(
      like(undergroundIntelEvents.title, `%${opts.search}%`),
      like(undergroundIntelEvents.description, `%${opts.search}%`),
      like(undergroundIntelEvents.actorName, `%${opts.search}%`),
    )
  );

  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const events = await db.select().from(undergroundIntelEvents)
    .where(where)
    .orderBy(desc(undergroundIntelEvents.createdAt))
    .limit(opts.limit || 50)
    .offset(opts.offset || 0);

  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(undergroundIntelEvents).where(where);

  return { events, total: countResult?.count || 0 };
}

export async function getUndergroundEventById(id: number) {
  const db = await requireDb();
  const [event] = await db.select().from(undergroundIntelEvents).where(eq(undergroundIntelEvents.id, id)).limit(1);
  return event || null;
}

export async function getUndergroundEventStats() {
  const db = await requireDb();
  const [stats] = await db.select({
    total: sql<number>`COUNT(*)`,
    ransomware: sql<number>`SUM(CASE WHEN uie_category = 'ransomware' THEN 1 ELSE 0 END)`,
    credential: sql<number>`SUM(CASE WHEN uie_category = 'credential' THEN 1 ELSE 0 END)`,
    iab: sql<number>`SUM(CASE WHEN uie_category = 'iab' THEN 1 ELSE 0 END)`,
    malware: sql<number>`SUM(CASE WHEN uie_category = 'malware' THEN 1 ELSE 0 END)`,
    influence: sql<number>`SUM(CASE WHEN uie_category = 'influence' THEN 1 ELSE 0 END)`,
    botnet: sql<number>`SUM(CASE WHEN uie_category = 'botnet' THEN 1 ELSE 0 END)`,
    phishing: sql<number>`SUM(CASE WHEN uie_category = 'phishing' THEN 1 ELSE 0 END)`,
    exploit: sql<number>`SUM(CASE WHEN uie_category = 'exploit' THEN 1 ELSE 0 END)`,
    dataLeak: sql<number>`SUM(CASE WHEN uie_category = 'data_leak' THEN 1 ELSE 0 END)`,
    critical: sql<number>`SUM(CASE WHEN uie_severity = 'critical' THEN 1 ELSE 0 END)`,
    high: sql<number>`SUM(CASE WHEN uie_severity = 'high' THEN 1 ELSE 0 END)`,
    enriched: sql<number>`SUM(CASE WHEN uie_enriched = true THEN 1 ELSE 0 END)`,
  }).from(undergroundIntelEvents);

  const [sourceCounts] = await db.select({
    distinctSources: sql<number>`COUNT(DISTINCT uie_source)`,
  }).from(undergroundIntelEvents);

  return {
    ...stats,
    distinctSources: sourceCounts?.distinctSources || 0,
  };
}

// ─── Network Events ──────────────────────────────────────────────────────

export async function getNetworkEvents(opts: {
  eventType?: string;
  source?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await requireDb();
  const conditions: any[] = [];
  if (opts.eventType) conditions.push(eq(networkEvents.eventType, opts.eventType as any));
  if (opts.source) conditions.push(eq(networkEvents.source, opts.source));
  if (opts.search) conditions.push(
    or(
      like(networkEvents.ipAddress, `%${opts.search}%`),
      like(networkEvents.hostname, `%${opts.search}%`),
      like(networkEvents.malwareFamily, `%${opts.search}%`),
    )
  );

  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const events = await db.select().from(networkEvents)
    .where(where)
    .orderBy(desc(networkEvents.createdAt))
    .limit(opts.limit || 50)
    .offset(opts.offset || 0);

  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(networkEvents).where(where);

  return { events, total: countResult?.count || 0 };
}

export async function getNetworkEventStats() {
  const db = await requireDb();
  const [stats] = await db.select({
    total: sql<number>`COUNT(*)`,
    c2Servers: sql<number>`SUM(CASE WHEN ne_event_type = 'c2_server' THEN 1 ELSE 0 END)`,
    botnetControllers: sql<number>`SUM(CASE WHEN ne_event_type = 'botnet_controller' THEN 1 ELSE 0 END)`,
    maliciousIps: sql<number>`SUM(CASE WHEN ne_event_type = 'malicious_ip' THEN 1 ELSE 0 END)`,
    torExitNodes: sql<number>`SUM(CASE WHEN ne_event_type = 'tor_exit_node' THEN 1 ELSE 0 END)`,
    sslBlacklist: sql<number>`SUM(CASE WHEN ne_event_type = 'ssl_blacklist' THEN 1 ELSE 0 END)`,
    active: sql<number>`SUM(CASE WHEN ne_status = 'active' THEN 1 ELSE 0 END)`,
  }).from(networkEvents);
  return stats;
}

// ─── IAB Activity ────────────────────────────────────────────────────────

export async function getIabActivities(opts: {
  status?: string;
  listingType?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await requireDb();
  const conditions: any[] = [];
  if (opts.status) conditions.push(eq(iabActivity.status, opts.status as any));
  if (opts.listingType) conditions.push(eq(iabActivity.listingType, opts.listingType as any));
  if (opts.search) conditions.push(
    or(
      like(iabActivity.brokerName, `%${opts.search}%`),
      like(iabActivity.description, `%${opts.search}%`),
    )
  );

  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const activities = await db.select().from(iabActivity)
    .where(where)
    .orderBy(desc(iabActivity.createdAt))
    .limit(opts.limit || 50)
    .offset(opts.offset || 0);

  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(iabActivity).where(where);

  return { activities, total: countResult?.count || 0 };
}

// ─── Credential Exposures ────────────────────────────────────────────────

export async function getCredentialExposures(opts: {
  severity?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await requireDb();
  const conditions: any[] = [];
  if (opts.severity) conditions.push(eq(credentialExposures.severity, opts.severity as any));
  if (opts.search) conditions.push(
    or(
      like(credentialExposures.breachName, `%${opts.search}%`),
      like(credentialExposures.domain, `%${opts.search}%`),
    )
  );

  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const exposures = await db.select().from(credentialExposures)
    .where(where)
    .orderBy(desc(credentialExposures.createdAt))
    .limit(opts.limit || 50)
    .offset(opts.offset || 0);

  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(credentialExposures).where(where);

  return { exposures, total: countResult?.count || 0 };
}

export async function getCredentialExposureStats() {
  const db = await requireDb();
  const [stats] = await db.select({
    total: sql<number>`COUNT(*)`,
    totalRecords: sql<number>`SUM(ce_total_records)`,
    critical: sql<number>`SUM(CASE WHEN ce_severity = 'critical' THEN 1 ELSE 0 END)`,
    high: sql<number>`SUM(CASE WHEN ce_severity = 'high' THEN 1 ELSE 0 END)`,
    verified: sql<number>`SUM(CASE WHEN ce_is_verified = true THEN 1 ELSE 0 END)`,
  }).from(credentialExposures);
  return stats;
}

// ─── Influence Operations ────────────────────────────────────────────────

export async function getInfluenceOperations(opts: {
  status?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await requireDb();
  const conditions: any[] = [];
  if (opts.status) conditions.push(eq(influenceOperations.status, opts.status as any));
  if (opts.search) conditions.push(
    or(
      like(influenceOperations.operationName, `%${opts.search}%`),
      like(influenceOperations.attributedTo, `%${opts.search}%`),
    )
  );

  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const ops = await db.select().from(influenceOperations)
    .where(where)
    .orderBy(desc(influenceOperations.createdAt))
    .limit(opts.limit || 50)
    .offset(opts.offset || 0);

  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(influenceOperations).where(where);

  return { operations: ops, total: countResult?.count || 0 };
}

// ─── Enriched Records ────────────────────────────────────────────────────

export async function getEnrichedRecords(opts: {
  minRiskScore?: number;
  limit?: number;
  offset?: number;
}) {
  const db = await requireDb();
  const conditions: any[] = [];
  if (opts.minRiskScore) conditions.push(gte(darkwebEnrichedRecords.riskScore, opts.minRiskScore));

  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const records = await db.select().from(darkwebEnrichedRecords)
    .where(where)
    .orderBy(desc(darkwebEnrichedRecords.riskScore))
    .limit(opts.limit || 50)
    .offset(opts.offset || 0);

  return records;
}

// ─── Ransomware Affiliates ───────────────────────────────────────────────

export async function getRansomwareAffiliates(opts: {
  status?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await requireDb();
  const conditions: any[] = [];
  if (opts.status) conditions.push(eq(ransomwareAffiliates.status, opts.status as any));
  if (opts.search) conditions.push(
    or(
      like(ransomwareAffiliates.affiliateName, `%${opts.search}%`),
      like(ransomwareAffiliates.primaryGroup, `%${opts.search}%`),
    )
  );

  const where = conditions.length > 0 ? and(...conditions) : undefined;
  const affiliates = await db.select().from(ransomwareAffiliates)
    .where(where)
    .orderBy(desc(ransomwareAffiliates.activityScore))
    .limit(opts.limit || 50)
    .offset(opts.offset || 0);

  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(ransomwareAffiliates).where(where);

  return { affiliates, total: countResult?.count || 0 };
}

// ─── Feed Registry ───────────────────────────────────────────────────────

export async function getFeedRegistry() {
  const db = await requireDb();
  return db.select().from(darkwebFeedRegistry).orderBy(darkwebFeedRegistry.feedName);
}

export async function toggleFeed(feedName: string, enabled: boolean) {
  const db = await requireDb();
  await db.update(darkwebFeedRegistry)
    .set({ enabled })
    .where(eq(darkwebFeedRegistry.feedName, feedName));
}

// ─── Dashboard Stats ─────────────────────────────────────────────────────

export async function getDarkwebDashboardStats() {
  const [eventStats, netStats, credStats] = await Promise.all([
    getUndergroundEventStats(),
    getNetworkEventStats(),
    getCredentialExposureStats(),
  ]);

  return {
    undergroundEvents: eventStats,
    networkEvents: netStats,
    credentialExposures: credStats,
  };
}
