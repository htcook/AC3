import { eq, desc, inArray, like, and, sql, not, or, gt, ne } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { 
  InsertUser, users, 
  serverConfigs, InsertServerConfig, ServerConfig,
  serverCredentials, InsertServerCredential, ServerCredential,
  activityLogs, InsertActivityLog,
  calderaStats, InsertCalderaStats, CalderaStats,
  engagementOpsSnapshots,
  llmTelemetry, InsertLlmTelemetry, LlmTelemetry,
  exploitPlanHistory, InsertExploitPlanHistory, ExploitPlanHistory,
  trainingLabSessions, InsertTrainingLabSession, SelectTrainingLabSession,
  trainingLabFeedback, InsertTrainingLabFeedback, SelectTrainingLabFeedback,
  exploitLearningOutcomes, exploitLearningPatterns, exploitLearningChains,
  customerIntegrations, integrationHealthChecks, integrationExecutionLog,
  deploymentHistory, irRunbookEntries
} from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;
let _dbLastCheck = 0;
const DB_RETRY_INTERVAL = 2000; // retry every 2s if connection failed

export async function getDb() {
  if (_db) {
    // Verify cached connection is still alive
    try {
      const { sql } = await import('drizzle-orm');
      await _db.execute(sql`SELECT 1`);
      return _db;
    } catch {
      console.warn('[Database] Cached connection lost, reconnecting...');
      _db = null;
    }
  }

  const now = Date.now();
  if (!process.env.DATABASE_URL) {
    return null;
  }

  // Avoid hammering reconnect on every call
  if (now - _dbLastCheck < DB_RETRY_INTERVAL) {
    return null;
  }
  _dbLastCheck = now;

  try {
    // Strip ssl query param from URL (mysql2 can't parse it from URL string)
    // and pass ssl config as a connection option instead
    let dbUrl = process.env.DATABASE_URL!;
    const needsSsl = dbUrl.includes('tidbcloud.com') || dbUrl.includes('ssl=');
    // Remove ssl param from URL to avoid mysql2 parsing errors
    dbUrl = dbUrl.replace(/[?&]ssl=[^&]*/g, '').replace(/\?$/, '');
    
    if (needsSsl) {
      // FIPS 140-3: Enforce FIPS-approved TLS cipher suites on DB connection
      const { getFIPSDatabaseSSLConfig } = await import('./lib/fips-tls');
      const fipsSSL = getFIPSDatabaseSSLConfig();
      // Pool sizing: 25 connections supports 2-3 concurrent pentesters
      // Each pentester generates ~5-10 concurrent queries (scan results, phase updates, vuln inserts)
      // Override via DB_POOL_SIZE env var for different instance sizes
      const poolSize = parseInt(process.env.DB_POOL_SIZE || '25', 10);
      const mysql2 = await import('mysql2');
      const pool = mysql2.createPool({
        uri: dbUrl,
        ...fipsSSL,
        waitForConnections: true,
        connectionLimit: poolSize,
        connectTimeout: 15000,    // 15s connect timeout (TiDB cold-start can be slow)
        idleTimeout: 30000,       // 30s idle timeout (free connections faster under load)
        queueLimit: 50,           // Max 50 queued requests before rejecting
        enableKeepAlive: true,    // Keep connections alive across idle periods
        keepAliveInitialDelay: 10000, // 10s keepalive ping interval
      });
      _db = drizzle({ client: pool });
      console.log('[Database] FIPS TLS enforced on connection');
    } else {
      _db = drizzle(dbUrl);
    }
    // Verify the connection actually works
    const { sql } = await import('drizzle-orm');
    await _db!.execute(sql`SELECT 1`);
    console.log('[Database] Connected successfully');
    return _db;
  } catch (error) {
    console.warn('[Database] Failed to connect:', error);
    _db = null;
    return null;
  }
}

/**
 * Get database connection with automatic retry (up to 3 attempts).
 * Use this for write operations that must not silently fail.
 */
export async function getDbRequired(): Promise<ReturnType<typeof drizzle>> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    // Reset cooldown so each attempt actually tries
    _dbLastCheck = 0;
    const conn = await getDb();
    if (conn) return conn;
    if (attempt < 3) {
      console.warn(`[Database] Retry ${attempt}/3 — waiting 1s...`);
      await new Promise(r => setTimeout(r, 1000));
    }
  }
  throw new Error('Database not available after 3 retries — please try again in a few seconds');
}

/**
 * Force-reconnect the database (useful after transient failures).
 * Clears the cached connection so the next getDb() call retries.
 */
export function resetDbConnection() {
  _db = null;
  _dbLastCheck = 0;
}

// User operations
export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = { openId: user.openId };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

export async function getAllUsers() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(users).orderBy(desc(users.createdAt));
}

export async function updateUserRole(userId: number, role: "user" | "admin" | "viewer") {
  const db = await getDb();
  if (!db) return;
  await db.update(users).set({ role }).where(eq(users.id, userId));
}

// Server config operations
export async function createServerConfig(config: InsertServerConfig) {
  const db = await getDbRequired();
  const result = await db.insert(serverConfigs).values(config);
  return result[0].insertId;
}

export async function getServerConfigs() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(serverConfigs).orderBy(desc(serverConfigs.createdAt));
}

export async function getServerConfigById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(serverConfigs).where(eq(serverConfigs.id, id)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

export async function updateServerStatus(id: number, status: "online" | "offline" | "unknown") {
  const db = await getDb();
  if (!db) return;
  await db.update(serverConfigs).set({ status, lastHealthCheck: new Date() }).where(eq(serverConfigs.id, id));
}

// Credential operations
export async function createCredential(credential: InsertServerCredential) {
  const db = await getDbRequired();
  await db.insert(serverCredentials).values(credential);
}

export async function getCredentialsByServerId(serverId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(serverCredentials).where(eq(serverCredentials.serverId, serverId));
}

export async function updateCredential(id: number, updates: Partial<InsertServerCredential>) {
  const db = await getDb();
  if (!db) return;
  await db.update(serverCredentials).set(updates).where(eq(serverCredentials.id, id));
}

// Activity log operations
export async function logActivity(log: InsertActivityLog) {
  const db = await getDb();
  if (!db) return;
  await db.insert(activityLogs).values(log);
}

export async function getActivityLogs(limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(activityLogs).orderBy(desc(activityLogs.createdAt)).limit(limit);
}

export async function getActivityLogsByServer(serverId: number, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(activityLogs).where(eq(activityLogs.serverId, serverId)).orderBy(desc(activityLogs.createdAt)).limit(limit);
}

// Cyber C2 stats operations
export async function upsertCalderaStats(stats: InsertCalderaStats) {
  const db = await getDb();
  if (!db) return;
  
  const existing = await db.select().from(calderaStats).where(eq(calderaStats.serverId, stats.serverId)).limit(1);
  
  if (existing.length > 0) {
    await db.update(calderaStats).set({
      ...stats,
      lastUpdated: new Date()
    }).where(eq(calderaStats.serverId, stats.serverId));
  } else {
    await db.insert(calderaStats).values(stats);
  }
}

export async function getCalderaStatsByServerId(serverId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(calderaStats).where(eq(calderaStats.serverId, serverId)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}


import { 
  campaigns, InsertCampaign, Campaign,
  campaignAgents, InsertCampaignAgent, CampaignAgent,
  campaignAbilities, InsertCampaignAbility, CampaignAbility
} from "../drizzle/schema";

// Campaign operations
export async function createCampaign(campaign: InsertCampaign) {
  const db = await getDbRequired();
  const result = await db.insert(campaigns).values(campaign);
  return result[0].insertId;
}

export async function getCampaigns() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaigns).orderBy(desc(campaigns.createdAt));
}

export async function getCampaignById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(campaigns).where(eq(campaigns.id, id)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

export async function updateCampaign(id: number, updates: Partial<InsertCampaign>) {
  const db = await getDb();
  if (!db) return;
  await db.update(campaigns).set(updates).where(eq(campaigns.id, id));
}

export async function deleteCampaign(id: number) {
  const db = await getDb();
  if (!db) return;
  // Delete related agents and abilities first
  await db.delete(campaignAgents).where(eq(campaignAgents.campaignId, id));
  await db.delete(campaignAbilities).where(eq(campaignAbilities.campaignId, id));
  await db.delete(campaigns).where(eq(campaigns.id, id));
}

// Campaign agent operations
export async function addCampaignAgent(agent: InsertCampaignAgent) {
  const db = await getDbRequired();
  const result = await db.insert(campaignAgents).values(agent);
  return result[0].insertId;
}

export async function getCampaignAgents(campaignId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignAgents).where(eq(campaignAgents.campaignId, campaignId));
}

export async function updateCampaignAgentStatus(id: number, status: "pending" | "deployed" | "active" | "inactive") {
  const db = await getDb();
  if (!db) return;
  await db.update(campaignAgents).set({ status }).where(eq(campaignAgents.id, id));
}

export async function deleteCampaignAgent(id: number) {
  const db = await getDb();
  if (!db) return;
  await db.delete(campaignAgents).where(eq(campaignAgents.id, id));
}

// Campaign ability operations
export async function addCampaignAbility(ability: InsertCampaignAbility) {
  const db = await getDbRequired();
  const result = await db.insert(campaignAbilities).values(ability);
  return result[0].insertId;
}

export async function addCampaignAbilities(abilities: InsertCampaignAbility[]) {
  const db = await getDbRequired();
  if (abilities.length === 0) return;
  await db.insert(campaignAbilities).values(abilities);
}

export async function getCampaignAbilities(campaignId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignAbilities).where(eq(campaignAbilities.campaignId, campaignId)).orderBy(campaignAbilities.executionOrder);
}

export async function updateCampaignAbilityStatus(id: number, status: "pending" | "running" | "completed" | "failed" | "skipped") {
  const db = await getDb();
  if (!db) return;
  const updates: Partial<InsertCampaignAbility> = { status };
  if (status === 'completed' || status === 'failed') {
    updates.executedAt = new Date();
  }
  await db.update(campaignAbilities).set(updates).where(eq(campaignAbilities.id, id));
}

export async function deleteCampaignAbility(id: number) {
  const db = await getDb();
  if (!db) return;
  await db.delete(campaignAbilities).where(eq(campaignAbilities.id, id));
}

export async function reorderCampaignAbilities(campaignId: number, abilityIds: number[]) {
  const db = await getDb();
  if (!db) return;
  for (let i = 0; i < abilityIds.length; i++) {
    await db.update(campaignAbilities)
      .set({ executionOrder: i })
      .where(eq(campaignAbilities.id, abilityIds[i]));
  }
}

// Engagement operations
import { engagements, InsertEngagement, Engagement } from "../drizzle/schema";

export async function createEngagement(engagement: InsertEngagement) {
  const db = await getDbRequired();
  try {
    // Default autoResumeOnRestart to 1 (enabled) so engagements auto-resume after server restarts
    const values = { autoResumeOnRestart: 1, ...engagement };
    const result = await db.insert(engagements).values(values);
    return result[0].insertId;
  } catch (err: any) {
    // On connection-level errors, reset and retry once
    if (err?.code === 'ECONNRESET' || err?.code === 'PROTOCOL_CONNECTION_LOST' || err?.message?.includes('ECONNREFUSED')) {
      resetDbConnection();
      const retryDb = await getDbRequired();
      const result = await retryDb.insert(engagements).values(engagement);
      return result[0].insertId;
    }
    throw err;
  }
}

export async function getEngagements(scopeUser?: { id: number; role: string } | null) {
  const db = await getDb();
  if (!db) return [];
  const { scopeEngagementWhere } = await import('./lib/engagement-access-guard');
  const scope = scopeUser ? scopeEngagementWhere(scopeUser) : null;
  if (scope) {
    return db.select().from(engagements).where(scope).orderBy(desc(engagements.updatedAt));
  }
  return db.select().from(engagements).orderBy(desc(engagements.updatedAt));
}

export async function getEngagementById(id: number, scopeUser?: { id: number; role: string } | null) {
  const db = await getDb();
  if (!db) return undefined;
  const { scopedAnd } = await import('./lib/engagement-access-guard');
  const where = scopeUser
    ? scopedAnd(scopeUser, eq(engagements.id, id))
    : eq(engagements.id, id);
  const result = await db.select().from(engagements).where(where).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

export async function updateEngagement(id: number, updates: Partial<InsertEngagement>) {
  const db = await getDb();
  if (!db) return;
  await db.update(engagements).set(updates).where(eq(engagements.id, id));
}

export async function deleteEngagement(id: number) {
  const db = await getDb();
  if (!db) return;
  // Clean up related records first
  await db.delete(engagementReports).where(eq(engagementReports.engagementId, id));
  await db.delete(campaignEngagements).where(eq(campaignEngagements.engagementId, id));
  await db.delete(engagements).where(eq(engagements.id, id));
}

export async function bulkDeleteEngagements(ids: number[]) {
  const db = await getDb();
  if (!db || ids.length === 0) return { deleted: 0 };
  // Clean up related records first
  await db.delete(engagementReports).where(inArray(engagementReports.engagementId, ids));
  await db.delete(campaignEngagements).where(inArray(campaignEngagements.engagementId, ids));
  const result = await db.delete(engagements).where(inArray(engagements.id, ids));
  return { deleted: result[0].affectedRows };
}

// Campaign-Engagement linking operations
import { campaignEngagements, InsertCampaignEngagement, CampaignEngagement } from "../drizzle/schema";

export async function linkCampaignToEngagement(link: InsertCampaignEngagement) {
  const db = await getDbRequired();
  const result = await db.insert(campaignEngagements).values(link);
  return result[0].insertId;
}

export async function getCampaignsByEngagement(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignEngagements)
    .where(eq(campaignEngagements.engagementId, engagementId))
    .orderBy(desc(campaignEngagements.createdAt));
}

export async function getEngagementByCampaign(gophishCampaignId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(campaignEngagements)
    .where(eq(campaignEngagements.gophishCampaignId, gophishCampaignId))
    .limit(1);
  return result.length > 0 ? result[0] : undefined;
}

export async function getAllCampaignEngagementLinks() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignEngagements).orderBy(desc(campaignEngagements.createdAt));
}

export async function unlinkCampaignFromEngagement(id: number) {
  const db = await getDb();
  if (!db) return;
  await db.delete(campaignEngagements).where(eq(campaignEngagements.id, id));
}

// ==================== OSINT DOMAIN RECON ====================
import { domainRecon, InsertDomainRecon, typosquatDomains, InsertTyposquatDomain, osintFindings, InsertOsintFinding } from "../drizzle/schema";

export async function createDomainRecon(recon: InsertDomainRecon) {
  const db = await getDbRequired();
  // Dedup guard: check if domain already exists for this engagement
  if (recon.engagementId && recon.domain) {
    const existing = await db.select({ id: domainRecon.id }).from(domainRecon)
      .where(and(eq(domainRecon.engagementId, recon.engagementId), eq(domainRecon.domain, recon.domain)))
      .limit(1);
    if (existing.length > 0) return existing[0].id;
  }
  const result = await db.insert(domainRecon).values(recon);
  return Number(result[0].insertId);
}

export async function updateDomainRecon(id: number, data: Partial<InsertDomainRecon>) {
  const db = await getDb();
  if (!db) return;
  await db.update(domainRecon).set(data).where(eq(domainRecon.id, id));
}

export async function getDomainReconByEngagement(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(domainRecon)
    .where(eq(domainRecon.engagementId, engagementId))
    .orderBy(desc(domainRecon.createdAt));
}

export async function getDomainReconById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(domainRecon).where(eq(domainRecon.id, id)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

// ==================== TYPOSQUAT DOMAINS ====================

export async function createTyposquatDomain(domain: InsertTyposquatDomain) {
  const db = await getDbRequired();
  // Dedup guard: check if typosquat already exists for this engagement
  if (domain.engagementId && domain.originalDomain && domain.permutedDomain) {
    const existing = await db.select({ id: typosquatDomains.id }).from(typosquatDomains)
      .where(and(
        eq(typosquatDomains.engagementId, domain.engagementId),
        eq(typosquatDomains.originalDomain, domain.originalDomain),
        eq(typosquatDomains.permutedDomain, domain.permutedDomain)
      ))
      .limit(1);
    if (existing.length > 0) return existing[0].id;
  }
  const result = await db.insert(typosquatDomains).values(domain);
  return Number(result[0].insertId);
}

export async function bulkCreateTyposquatDomains(domains: InsertTyposquatDomain[]) {
  const db = await getDbRequired();
  if (domains.length === 0) return;
  // Dedup guard: filter out domains that already exist for this engagement
  const engId = domains[0]?.engagementId;
  if (engId) {
    const existing = await db.select({
      originalDomain: typosquatDomains.originalDomain,
      permutedDomain: typosquatDomains.permutedDomain,
    }).from(typosquatDomains).where(eq(typosquatDomains.engagementId, engId));
    const existingSet = new Set(existing.map(e => `${e.originalDomain}||${e.permutedDomain}`));
    const newDomains = domains.filter(d => !existingSet.has(`${d.originalDomain}||${d.permutedDomain}`));
    if (newDomains.length === 0) return;
    await db.insert(typosquatDomains).values(newDomains);
    return;
  }
  await db.insert(typosquatDomains).values(domains);
}

export async function updateTyposquatDomain(id: number, data: Partial<InsertTyposquatDomain>) {
  const db = await getDb();
  if (!db) return;
  await db.update(typosquatDomains).set(data).where(eq(typosquatDomains.id, id));
}

export async function getTyposquatsByRecon(reconId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(typosquatDomains)
    .where(eq(typosquatDomains.reconId, reconId))
    .orderBy(desc(typosquatDomains.createdAt));
}

export async function getTyposquatsByEngagement(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(typosquatDomains)
    .where(eq(typosquatDomains.engagementId, engagementId))
    .orderBy(desc(typosquatDomains.createdAt));
}

// ==================== OSINT FINDINGS ====================

export async function createOsintFinding(finding: InsertOsintFinding) {
  const db = await getDbRequired();
  // Dedup guard: check if finding already exists for this engagement
  if (finding.engagementId && finding.category && finding.title) {
    const existing = await db.select({ id: osintFindings.id }).from(osintFindings)
      .where(and(
        eq(osintFindings.engagementId, finding.engagementId),
        eq(osintFindings.category, finding.category),
        eq(osintFindings.title, finding.title)
      ))
      .limit(1);
    if (existing.length > 0) return existing[0].id;
  }
  const result = await db.insert(osintFindings).values(finding);
  return Number(result[0].insertId);
}

export async function bulkCreateOsintFindings(findings: InsertOsintFinding[]) {
  const db = await getDbRequired();
  if (findings.length === 0) return;
  // Dedup guard: filter out findings that already exist for this engagement
  const engId = findings[0]?.engagementId;
  if (engId) {
    const existing = await db.select({
      category: osintFindings.category,
      title: osintFindings.title,
    }).from(osintFindings).where(eq(osintFindings.engagementId, engId));
    const existingSet = new Set(existing.map(e => `${e.category}||${e.title}`));
    const newFindings = findings.filter(f => !existingSet.has(`${f.category}||${f.title}`));
    if (newFindings.length === 0) return;
    await db.insert(osintFindings).values(newFindings);
    return;
  }
  await db.insert(osintFindings).values(findings);
}

export async function getOsintFindingsByEngagement(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintFindings)
    .where(eq(osintFindings.engagementId, engagementId))
    .orderBy(desc(osintFindings.createdAt));
}

export async function getOsintFindingsByRecon(reconId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintFindings)
    .where(eq(osintFindings.reconId, reconId))
    .orderBy(desc(osintFindings.createdAt));
}

// ==================== OSINT Monitors ====================
import { osintMonitors, InsertOsintMonitor, osintMonitorChanges, InsertOsintMonitorChange, engagementReports, InsertEngagementReport } from "../drizzle/schema";

export async function createOsintMonitor(monitor: InsertOsintMonitor) {
  const db = await getDbRequired();
  const result = await db.insert(osintMonitors).values(monitor);
  return Number(result[0].insertId);
}

export async function getOsintMonitors() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitors).orderBy(desc(osintMonitors.createdAt));
}

export async function getOsintMonitorById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(osintMonitors).where(eq(osintMonitors.id, id));
  return rows[0] || null;
}

export async function getEnabledMonitors() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitors).where(eq(osintMonitors.enabled, true));
}

export async function updateOsintMonitor(id: number, updates: Partial<InsertOsintMonitor>) {
  const db = await getDbRequired();
  await db.update(osintMonitors).set(updates).where(eq(osintMonitors.id, id));
}

export async function deleteOsintMonitor(id: number) {
  const db = await getDbRequired();
  await db.delete(osintMonitors).where(eq(osintMonitors.id, id));
}

// ==================== OSINT Monitor Changes ====================

export async function createMonitorChange(change: InsertOsintMonitorChange) {
  const db = await getDbRequired();
  const result = await db.insert(osintMonitorChanges).values(change);
  return Number(result[0].insertId);
}

export async function bulkCreateMonitorChanges(changes: InsertOsintMonitorChange[]) {
  const db = await getDbRequired();
  if (changes.length === 0) return;
  await db.insert(osintMonitorChanges).values(changes);
}

export async function getMonitorChanges(monitorId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitorChanges)
    .where(eq(osintMonitorChanges.monitorId, monitorId))
    .orderBy(desc(osintMonitorChanges.createdAt));
}

export async function getUnacknowledgedChanges() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitorChanges)
    .where(eq(osintMonitorChanges.acknowledged, false))
    .orderBy(desc(osintMonitorChanges.createdAt));
}

export async function acknowledgeChange(id: number, userId: number) {
  const db = await getDbRequired();
  await db.update(osintMonitorChanges).set({
    acknowledged: true,
    acknowledgedBy: userId,
    acknowledgedAt: new Date(),
  }).where(eq(osintMonitorChanges.id, id));
}

// ==================== Engagement Reports ====================

export async function createEngagementReport(report: InsertEngagementReport) {
  const db = await getDbRequired();
  const result = await db.insert(engagementReports).values(report);
  return Number(result[0].insertId);
}

export async function getEngagementReports(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementReports)
    .where(eq(engagementReports.engagementId, engagementId))
    .orderBy(desc(engagementReports.createdAt));
}

export async function getReportById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(engagementReports).where(eq(engagementReports.id, id));
  return rows[0] || null;
}

export async function updateReport(id: number, updates: Partial<InsertEngagementReport>) {
  const db = await getDbRequired();
  await db.update(engagementReports).set(updates).where(eq(engagementReports.id, id));
}

export async function deleteReport(id: number) {
  const db = await getDbRequired();
  await db.delete(engagementReports).where(eq(engagementReports.id, id));
}

export async function getAllReports() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementReports).orderBy(desc(engagementReports.createdAt));
}

// ─── Domain Intel Scans & Discovered Assets ──────────────────────────
import { domainIntelScans, InsertDomainIntelScan, discoveredAssets, InsertDiscoveredAsset } from "../drizzle/schema";

export async function createDomainIntelScan(scan: InsertDomainIntelScan) {
  const db = await getDbRequired();
  const result = await db.insert(domainIntelScans).values(scan);
  return Number(result[0].insertId);
}

export async function getDomainIntelScans() {
  const db = await getDb();
  if (!db) return [];
  // Select only summary columns needed for the list view.
  // Excludes large JSON blobs (pipelineOutput, campaignRecommendations, orgProfile)
  // and large text fields (executiveSummary, threatModelSummary) to prevent 503 timeouts.
  return db.select({
    id: domainIntelScans.id,
    engagementId: domainIntelScans.engagementId,
    primaryDomain: domainIntelScans.primaryDomain,
    clientType: domainIntelScans.clientType,
    sector: domainIntelScans.sector,
    status: domainIntelScans.status,
    totalAssets: domainIntelScans.totalAssets,
    totalFindings: domainIntelScans.totalFindings,
    confirmedFindings: domainIntelScans.confirmedFindings,
    probableFindings: domainIntelScans.probableFindings,
    potentialFindings: domainIntelScans.potentialFindings,
    discoveryCoverageScore: domainIntelScans.discoveryCoverageScore,
    discoveryCoverageBand: domainIntelScans.discoveryCoverageBand,
    overallRiskScore: domainIntelScans.overallRiskScore,
    overallRiskBand: domainIntelScans.overallRiskBand,
    createdBy: domainIntelScans.createdBy,
    createdAt: domainIntelScans.createdAt,
    updatedAt: domainIntelScans.updatedAt,
  }).from(domainIntelScans)
    .where(
      not(
        sql`${domainIntelScans.primaryDomain} REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$'`
      )
    )
    .orderBy(desc(domainIntelScans.updatedAt), desc(domainIntelScans.createdAt));
}

export async function getDomainIntelScanById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, id));
  return rows[0] || null;
}

/**
 * Find the most recent completed scan for the same primary domain,
 * excluding the current scan. Used for delta comparison.
 */
export async function getPreviousCompletedScan(primaryDomain: string, excludeScanId: number) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select()
    .from(domainIntelScans)
    .where(
      and(
        eq(domainIntelScans.primaryDomain, primaryDomain),
        not(eq(domainIntelScans.id, excludeScanId)),
        or(
          eq(domainIntelScans.status, 'completed'),
          eq(domainIntelScans.status, 'scan_complete'),
        ),
      ),
    )
    .orderBy(sql`created_at DESC`)
    .limit(1);
  return rows[0] || null;
}

export async function updateDomainIntelScan(id: number, updates: Partial<InsertDomainIntelScan>) {
  const db = await getDbRequired();
  await db.update(domainIntelScans).set(updates).where(eq(domainIntelScans.id, id));
}

export async function createDiscoveredAsset(asset: InsertDiscoveredAsset) {
  const db = await getDbRequired();
  const result = await db.insert(discoveredAssets).values(asset);
  return Number(result[0].insertId);
}

export async function bulkCreateDiscoveredAssets(assets: InsertDiscoveredAsset[]) {
  const db = await getDbRequired();
  if (assets.length === 0) return;
  await db.insert(discoveredAssets).values(assets);
}

export async function getDiscoveredAssetsByScan(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));
}

export async function excludeDiscoveredAsset(assetId: number, reason: string) {
  const db = await getDbRequired();
  await db.update(discoveredAssets).set({
    excluded: true,
    exclusionReason: reason,
    excludedAt: new Date(),
  }).where(eq(discoveredAssets.id, assetId));
}

export async function includeDiscoveredAsset(assetId: number) {
  const db = await getDbRequired();
  await db.update(discoveredAssets).set({
    excluded: false,
    exclusionReason: null,
    excludedAt: null,
  }).where(eq(discoveredAssets.id, assetId));
}

export async function bulkExcludeDiscoveredAssets(assetIds: number[], reason: string) {
  const db = await getDbRequired();
  for (const id of assetIds) {
    await db.update(discoveredAssets).set({
      excluded: true,
      exclusionReason: reason,
      excludedAt: new Date(),
    }).where(eq(discoveredAssets.id, id));
  }
}

export async function bulkIncludeDiscoveredAssets(assetIds: number[]) {
  const db = await getDbRequired();
  for (const id of assetIds) {
    await db.update(discoveredAssets).set({
      excluded: false,
      exclusionReason: null,
      excludedAt: null,
    }).where(eq(discoveredAssets.id, id));
  }
}

export async function deleteDiscoveredAssetsByScan(scanId: number) {
  const db = await getDbRequired();
  await db.delete(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));
}

export async function deleteDomainIntelScan(scanId: number) {
  const db = await getDbRequired();
  await db.delete(domainIntelScans).where(eq(domainIntelScans.id, scanId));
}

export async function getDomainIntelScansByEngagement(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(domainIntelScans).where(eq(domainIntelScans.engagementId, engagementId)).orderBy(desc(domainIntelScans.updatedAt), desc(domainIntelScans.createdAt));
}

// ─── Threat Actor Database ───────────────────────────────────────────────
import { 
  threatActors, InsertThreatActor, ThreatActor,
  threatActorAbilities, InsertThreatActorAbility,
  threatActorIocs, InsertThreatActorIoc,
  iocFeeds, InsertIocFeed, IocFeed,
  engagementPipelines, InsertEngagementPipeline,
  iocSyncLogs, InsertIocSyncLog
} from "../drizzle/schema";
// drizzle-orm operators imported at top of file

export async function listThreatActors(filters?: {
  type?: string;
  origin?: string;
  threatLevel?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await getDb();
  if (!db) return { actors: [], total: 0 };
  
  const conditions: any[] = [];
  // Exclude OFAC sanctions data from the threat catalog display.
  // OFAC entities are not threat actors — they're sanctioned individuals/orgs.
  // They remain in the DB for cross-reference but should not appear in the catalog.
  conditions.push(sql`(${threatActors.dataSource} IS NULL OR ${threatActors.dataSource} != 'OFAC SDN List')`);
  if (filters?.type && filters.type !== 'all') {
    conditions.push(eq(threatActors.actorType, filters.type as any));
  }
  if (filters?.origin && filters.origin !== 'all') {
    conditions.push(eq(threatActors.origin, filters.origin));
  }
  if (filters?.threatLevel && filters.threatLevel !== 'all') {
    conditions.push(eq(threatActors.threatLevel, filters.threatLevel as any));
  }
  if (filters?.search) {
    conditions.push(
      sql`(${threatActors.name} LIKE ${`%${filters.search}%`} OR ${threatActors.description} LIKE ${`%${filters.search}%`} OR JSON_SEARCH(${threatActors.aliases}, 'one', ${`%${filters.search}%`}) IS NOT NULL)`
    );
  }
  
  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
  
  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(threatActors)
    .where(whereClause);
  
  const actors = await db.select()
    .from(threatActors)
    .where(whereClause)
    .orderBy(desc(threatActors.confidence))
    .limit(filters?.limit || 50)
    .offset(filters?.offset || 0);
  
  return { actors, total: Number(countResult.count) };
}

export async function getThreatActor(actorId: string) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId));
  return results[0] || null;
}

export async function getThreatActorById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(threatActors).where(eq(threatActors.id, id));
  return results[0] || null;
}

export async function updateThreatActor(actorId: string, updates: Partial<InsertThreatActor>) {
  const db = await getDbRequired();
  await db.update(threatActors).set(updates).where(eq(threatActors.actorId, actorId));
}

export async function getThreatActorStats() {
  const db = await getDb();
  if (!db) return { total: 0, byType: [], byOrigin: [], byThreatLevel: [] };
  
  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(threatActors);
  const byType = await db.select({ 
    type: threatActors.actorType, 
    count: sql<number>`COUNT(*)` 
  }).from(threatActors).groupBy(threatActors.actorType);
  const byOrigin = await db.select({ 
    origin: threatActors.origin, 
    count: sql<number>`COUNT(*)` 
  }).from(threatActors).groupBy(threatActors.origin).orderBy(sql`COUNT(*) DESC`).limit(15);
  const byThreatLevel = await db.select({ 
    level: threatActors.threatLevel, 
    count: sql<number>`COUNT(*)` 
  }).from(threatActors).groupBy(threatActors.threatLevel);
  
  return { total: Number(total.count), byType, byOrigin, byThreatLevel };
}

export async function getThreatActorCount(): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  const [result] = await db.select({ count: sql<number>`COUNT(*)` }).from(threatActors)
    .where(sql`(${threatActors.dataSource} IS NULL OR ${threatActors.dataSource} != 'OFAC SDN List')`);
  return Number(result.count);
}

// ─── Threat Actor Abilities ──────────────────────────────────────────────
export async function listThreatActorAbilities(actorId: string) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatActorAbilities).where(eq(threatActorAbilities.actorId, actorId));
}

export async function createThreatActorAbility(ability: InsertThreatActorAbility) {
  const db = await getDbRequired();
  const result = await db.insert(threatActorAbilities).values(ability);
  return Number(result[0].insertId);
}

export async function listAllAbilities(filters?: {
  tactic?: string;
  search?: string;
  actorId?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await getDb();
  if (!db) return { abilities: [], total: 0 };
  
  const conditions: any[] = [];
  if (filters?.tactic && filters.tactic !== 'all') {
    conditions.push(eq(threatActorAbilities.tactic, filters.tactic));
  }
  if (filters?.actorId) {
    conditions.push(eq(threatActorAbilities.actorId, filters.actorId));
  }
  if (filters?.search) {
    conditions.push(
      sql`(${threatActorAbilities.name} LIKE ${`%${filters.search}%`} OR ${threatActorAbilities.description} LIKE ${`%${filters.search}%`})`
    );
  }
  
  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
  
  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(threatActorAbilities)
    .where(whereClause);
  
  const abilities = await db.select()
    .from(threatActorAbilities)
    .where(whereClause)
    .limit(filters?.limit || 50)
    .offset(filters?.offset || 0);
  
  return { abilities, total: Number(countResult.count) };
}

// ─── Threat Actor IOCs ───────────────────────────────────────────────────
export async function listThreatActorIocs(actorId: string) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatActorIocs).where(eq(threatActorIocs.actorId, actorId));
}

export async function createThreatActorIoc(ioc: InsertThreatActorIoc) {
  const db = await getDbRequired();
  const result = await db.insert(threatActorIocs).values(ioc);
  return Number(result[0].insertId);
}

export async function bulkCreateThreatActorIocs(iocs: InsertThreatActorIoc[]) {
  const db = await getDbRequired();
  if (iocs.length === 0) return;
  await db.insert(threatActorIocs).values(iocs);
}

// ─── IOC Feeds ───────────────────────────────────────────────────────────
export async function createIocFeedEntry(entry: InsertIocFeed) {
  const db = await getDbRequired();
  const result = await db.insert(iocFeeds).values(entry);
  return Number(result[0].insertId);
}

export async function bulkCreateIocFeedEntries(entries: InsertIocFeed[]) {
  const db = await getDbRequired();
  if (entries.length === 0) return;
  await db.insert(iocFeeds).values(entries);
}

export async function listIocFeedEntries(filters?: {
  feedSource?: string;
  severity?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await getDb();
  if (!db) return { entries: [], total: 0 };
  
  const conditions: any[] = [];
  if (filters?.feedSource && filters.feedSource !== 'all') {
    conditions.push(eq(iocFeeds.feedSource, filters.feedSource));
  }
  if (filters?.severity && filters.severity !== 'all') {
    conditions.push(eq(iocFeeds.feedSeverity, filters.severity as any));
  }
  if (filters?.search) {
    conditions.push(
      sql`(${iocFeeds.title} LIKE ${`%${filters.search}%`} OR ${iocFeeds.iocValue} LIKE ${`%${filters.search}%`})`
    );
  }
  
  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
  
  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(iocFeeds)
    .where(whereClause);
  
  const entries = await db.select()
    .from(iocFeeds)
    .where(whereClause)
    .orderBy(desc(iocFeeds.createdAt))
    .limit(filters?.limit || 50)
    .offset(filters?.offset || 0);
  
  return { entries, total: Number(countResult.count) };
}

export async function getIocFeedStats() {
  const db = await getDb();
  if (!db) return { total: 0, bySource: [], bySeverity: [], recentCount: 0 };
  
  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(iocFeeds);
  const bySource = await db.select({ 
    source: iocFeeds.feedSource, 
    count: sql<number>`COUNT(*)` 
  }).from(iocFeeds).groupBy(iocFeeds.feedSource);
  const bySeverity = await db.select({ 
    severity: iocFeeds.feedSeverity, 
    count: sql<number>`COUNT(*)` 
  }).from(iocFeeds).groupBy(iocFeeds.feedSeverity);
  const [recent] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(iocFeeds)
    .where(sql`${iocFeeds.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);
  
  return { total: Number(total.count), bySource, bySeverity, recentCount: Number(recent.count) };
}

// ─── Engagement Pipelines ────────────────────────────────────────────────
// Friendly interface that callers use (maps to schema column names)
interface CreatePipelineInput {
  userId: number;
  name: string;
  status?: string;
  targetDomains?: any;
  clientType?: string;
  orgProfile?: any;
  recommendedActors?: any;
  engagementId?: number;
  currentStep?: number;
  totalSteps?: number;
  stepLog?: any;
  errorMessage?: string;
}
export async function createEngagementPipeline(pipeline: CreatePipelineInput) {
  const db = await getDbRequired();
  const result = await db.insert(engagementPipelines).values({
    userId: pipeline.userId,
    pipelineName: pipeline.name,
    pipelineStatus: (pipeline.status as any) || 'pending',
    targetDomains: pipeline.targetDomains,
    pipelineClientType: pipeline.clientType,
    orgProfile: pipeline.orgProfile,
    recommendedActors: pipeline.recommendedActors,
    engagementId: pipeline.engagementId,
    currentStep: pipeline.currentStep ?? 0,
    totalSteps: pipeline.totalSteps ?? 6,
    stepLog: pipeline.stepLog,
    errorMessage: pipeline.errorMessage,
  });
  return Number(result[0].insertId);
}

export async function getEngagementPipeline(id: number) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(engagementPipelines).where(eq(engagementPipelines.id, id));
  return results[0] || null;
}

export async function updateEngagementPipeline(id: number, updates: Partial<CreatePipelineInput> & Record<string, any>) {
  const db = await getDbRequired();
  // Map friendly field names to schema column names
  const mapped: Record<string, any> = {};
  if (updates.name !== undefined) mapped.pipelineName = updates.name;
  if (updates.status !== undefined) mapped.pipelineStatus = updates.status;
  if (updates.clientType !== undefined) mapped.pipelineClientType = updates.clientType;
  // Pass through fields that already match schema column names
  for (const key of ['userId', 'targetDomains', 'orgProfile', 'recommendedActors', 'engagementId', 'currentStep', 'totalSteps', 'stepLog', 'errorMessage', 'completedAt', 'riskSummary', 'pipelineName', 'pipelineStatus', 'pipelineClientType', 'calderaOperationId', 'calderaAdversaryId', 'calderaAbilitiesDeployed', 'gophishCampaignId', 'gophishTemplateId', 'gophishLandingPageId', 'intelScanId']) {
    if (updates[key] !== undefined && !(key in mapped)) mapped[key] = updates[key];
  }
  await db.update(engagementPipelines).set(mapped).where(eq(engagementPipelines.id, id));
}

export async function listEngagementPipelines(limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementPipelines).orderBy(desc(engagementPipelines.createdAt)).limit(limit);
}


// ─── IOC Sync Logs ──────────────────────────────────────────────────────
export async function createIocSyncLog(log: InsertIocSyncLog) {
  const db = await getDbRequired();
  const result = await db.insert(iocSyncLogs).values(log);
  return Number(result[0].insertId);
}

export async function updateIocSyncLog(id: number, updates: Partial<InsertIocSyncLog>) {
  const db = await getDbRequired();
  await db.update(iocSyncLogs).set(updates).where(eq(iocSyncLogs.id, id));
}

export async function listIocSyncLogs(limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(iocSyncLogs).orderBy(desc(iocSyncLogs.createdAt)).limit(limit);
}

export async function getLastIocSync() {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(iocSyncLogs)
    .where(eq(iocSyncLogs.status, 'completed'))
    .orderBy(desc(iocSyncLogs.completedAt))
    .limit(1);
  return rows[0] || null;
}


// ─── Threat Actor CRUD ──────────────────────────────────────────────────
export async function createThreatActor(actor: InsertThreatActor) {
  const db = await getDbRequired();
  const result = await db.insert(threatActors).values(actor);
  return Number(result[0].insertId);
}

export async function upsertThreatActor(actor: InsertThreatActor) {
  const db = await getDbRequired();
  // Check if actor already exists
  const existing = await db.select().from(threatActors).where(eq(threatActors.actorId, actor.actorId));
  if (existing.length > 0) {
    // Update existing - merge calderaProfile if present
    const updates: Partial<InsertThreatActor> = {};
    if (actor.calderaProfile) updates.calderaProfile = actor.calderaProfile;
    if (actor.description && !existing[0].description) updates.description = actor.description;
    if (actor.tools) updates.tools = actor.tools;
    if (Object.keys(updates).length > 0) {
      await db.update(threatActors).set(updates).where(eq(threatActors.actorId, actor.actorId));
    }
    return existing[0].id;
  }
  // Create new
  const result = await db.insert(threatActors).values(actor);
  return Number(result[0].insertId);
}

export async function bulkUpsertThreatActors(actors: InsertThreatActor[]) {
  const results: Array<{ actorId: string; id: number; action: 'created' | 'updated' | 'skipped' }> = [];
  for (const actor of actors) {
    try {
      const id = await upsertThreatActor(actor);
      results.push({ actorId: actor.actorId, id, action: id ? 'created' : 'updated' });
    } catch (err: any) {
      console.warn(`[DB] Failed to upsert threat actor ${actor.actorId}:`, err.message);
      results.push({ actorId: actor.actorId, id: 0, action: 'skipped' });
    }
  }
  return results;
}


// ─── TTP Knowledge Base ─────────────────────────────────────────────────
import { ttpKnowledge, InsertTtpKnowledge, TtpKnowledge } from "../drizzle/schema";

export async function upsertTtpKnowledge(entry: InsertTtpKnowledge) {
  const db = await getDbRequired();
  const existing = await db.select().from(ttpKnowledge).where(eq(ttpKnowledge.techniqueId, entry.techniqueId));
  if (existing.length > 0) {
    await db.update(ttpKnowledge).set({ ...entry, updatedAt: new Date() }).where(eq(ttpKnowledge.techniqueId, entry.techniqueId));
    return existing[0].id;
  }
  const result = await db.insert(ttpKnowledge).values(entry);
  return Number(result[0].insertId);
}

export async function getTtpKnowledge(techniqueId: string) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(ttpKnowledge).where(eq(ttpKnowledge.techniqueId, techniqueId));
  return rows[0] || null;
}

export async function listTtpKnowledge(filters?: {
  tactic?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await getDb();
  if (!db) return { entries: [], total: 0 };
  
  const conditions: any[] = [];
  if (filters?.tactic) conditions.push(eq(ttpKnowledge.tactic, filters.tactic));
  if (filters?.search) {
    conditions.push(
      sql`(${ttpKnowledge.techniqueId} LIKE ${`%${filters.search}%`} OR ${ttpKnowledge.techniqueName} LIKE ${`%${filters.search}%`})`
    );
  }
  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
  
  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` }).from(ttpKnowledge).where(whereClause);
  const entries = await db.select().from(ttpKnowledge)
    .where(whereClause)
    .orderBy(ttpKnowledge.techniqueId)
    .limit(filters?.limit || 50)
    .offset(filters?.offset || 0);
  
  return { entries, total: Number(countResult.count) };
}

export async function getTtpKnowledgeStats() {
  const db = await getDb();
  if (!db) return { total: 0, byTactic: [], enriched: 0 };
  
  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(ttpKnowledge);
  const byTactic = await db.select({
    tactic: ttpKnowledge.tactic,
    count: sql<number>`COUNT(*)`,
  }).from(ttpKnowledge).groupBy(ttpKnowledge.tactic);
  const [enriched] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(ttpKnowledge)
    .where(sql`${ttpKnowledge.detectionRules} IS NOT NULL AND JSON_LENGTH(${ttpKnowledge.detectionRules}) > 0`);
  
  return { total: Number(total.count), byTactic, enriched: Number(enriched.count) };
}


// ─── False Positive Management ──────────────────────────────────────────
import { falsePositiveFindings, InsertFalsePositiveFinding, FalsePositiveFinding } from "../drizzle/schema";

export async function createFalsePositive(fp: {
  scanId: number;
  assetId: number;
  findingIndex: number;
  findingHash: string;
  findingTitle: string;
  findingType: string | null;
  findingSeverity: string | null;
  reason: string;
  markedBy: string;
}) {
  const db = await getDbRequired();
  const [result] = await db.insert(falsePositiveFindings).values({
    scanId: fp.scanId,
    assetId: fp.assetId,
    findingIndex: fp.findingIndex,
    findingHash: fp.findingHash,
    findingTitle: fp.findingTitle,
    findingType: fp.findingType,
    findingSeverity: fp.findingSeverity,
    reason: fp.reason,
    status: "false_positive",
    markedBy: fp.markedBy,
  });
  return result.insertId;
}

export async function reinstateFalsePositive(fpId: number, reinstatedBy: string, reason: string) {
  const db = await getDbRequired();
  await db.update(falsePositiveFindings)
    .set({
      status: "reinstated",
      reinstatedBy,
      reinstatedAt: new Date(),
      reinstatedReason: reason,
    })
    .where(eq(falsePositiveFindings.id, fpId));
}

export async function getFalsePositivesByScan(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(falsePositiveFindings)
    .where(eq(falsePositiveFindings.scanId, scanId))
    .orderBy(sql`${falsePositiveFindings.markedAt} DESC`);
}

export async function getAllFalsePositives() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(falsePositiveFindings)
    .orderBy(sql`${falsePositiveFindings.markedAt} DESC`)
    .limit(500);
}

/**
 * Get all active (non-reinstated) false positive hashes.
 * Used by the pipeline to inject FP context into LLM prompts
 * and to auto-flag findings that match known FP patterns.
 */
export async function getActiveFPHashes(): Promise<{ hash: string; title: string; reason: string; count: number }[]> {
  const db = await getDb();
  if (!db) return [];
  const results = await db.select({
    hash: falsePositiveFindings.findingHash,
    title: falsePositiveFindings.findingTitle,
    reason: falsePositiveFindings.reason,
    count: sql<number>`COUNT(*)`,
  })
    .from(falsePositiveFindings)
    .where(eq(falsePositiveFindings.fpStatus, "false_positive"))
    .groupBy(falsePositiveFindings.findingHash, falsePositiveFindings.findingTitle, falsePositiveFindings.reason);
  return results.map(r => ({ hash: r.hash, title: r.title, reason: r.reason, count: Number(r.count) }));
}

/**
 * Get FP context for LLM injection — summarizes false positive patterns
 * by category and severity for the LLM to learn from.
 */
export async function getFPContextForLLM(): Promise<{
  totalFPs: number;
  patterns: { title: string; type: string | null; severity: string | null; reason: string; occurrences: number }[];
  categorySummary: { type: string; count: number; fpRate: string }[];
}> {
  const db = await getDb();
  if (!db) return { totalFPs: 0, patterns: [], categorySummary: [] };

  // Get all active FP patterns grouped by finding hash
  const patterns = await db.select({
    title: falsePositiveFindings.findingTitle,
    type: falsePositiveFindings.findingType,
    severity: falsePositiveFindings.findingSeverity,
    reason: falsePositiveFindings.reason,
    occurrences: sql<number>`COUNT(*)`,
  })
    .from(falsePositiveFindings)
    .where(eq(falsePositiveFindings.fpStatus, "false_positive"))
    .groupBy(
      falsePositiveFindings.findingTitle,
      falsePositiveFindings.findingType,
      falsePositiveFindings.findingSeverity,
      falsePositiveFindings.reason
    )
    .orderBy(sql`COUNT(*) DESC`)
    .limit(50);

  // Get category summary
  const categorySummary = await db.select({
    type: falsePositiveFindings.findingType,
    count: sql<number>`COUNT(*)`,
  })
    .from(falsePositiveFindings)
    .where(eq(falsePositiveFindings.fpStatus, "false_positive"))
    .groupBy(falsePositiveFindings.findingType)
    .orderBy(sql`COUNT(*) DESC`);

  const [totalRow] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(falsePositiveFindings)
    .where(eq(falsePositiveFindings.fpStatus, "false_positive"));

  return {
    totalFPs: Number(totalRow.count),
    patterns: patterns.map(p => ({
      title: p.title,
      type: p.type,
      severity: p.severity,
      reason: p.reason,
      occurrences: Number(p.occurrences),
    })),
    categorySummary: categorySummary.map(c => ({
      type: c.type || 'unknown',
      count: Number(c.count),
      fpRate: 'N/A', // Will be calculated when we have total findings per category
    })),
  };
}

/**
 * Check if a specific finding hash is already marked as FP.
 * Used for post-scan auto-suppression.
 */
export async function isFindingFalsePositive(findingHash: string): Promise<boolean> {
  const db = await getDb();
  if (!db) return false;
  const [result] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(falsePositiveFindings)
    .where(and(
      eq(falsePositiveFindings.findingHash, findingHash),
      eq(falsePositiveFindings.fpStatus, "false_positive")
    ));
  return Number(result.count) > 0;
}

/**
 * Batch check multiple finding hashes against FP database.
 * Returns a Set of hashes that are known false positives.
 */
export async function batchCheckFalsePositives(hashes: string[]): Promise<Set<string>> {
  const db = await getDb();
  if (!db) return new Set();
  if (hashes.length === 0) return new Set();
  const results = await db.select({ hash: falsePositiveFindings.findingHash })
    .from(falsePositiveFindings)
    .where(and(
      inArray(falsePositiveFindings.findingHash, hashes),
      eq(falsePositiveFindings.fpStatus, "false_positive")
    ));
  return new Set(results.map(r => r.hash));
}

// ─── Client Portal Share Tokens ───────────────────────────────────────────────
import { engagementShares, InsertEngagementShare, EngagementShare } from "../drizzle/schema";
import crypto from "crypto";

/** Generate a cryptographically secure URL-safe share token */
function generateShareToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

export async function createEngagementShare(share: Omit<InsertEngagementShare, "token">): Promise<EngagementShare | undefined> {
  const db = await getDb();
  if (!db) return undefined;
  const token = generateShareToken();
  const result = await db.insert(engagementShares).values({ ...share, token });
  const insertId = result[0].insertId;
  const [created] = await db.select().from(engagementShares).where(eq(engagementShares.id, insertId));
  return created;
}

export async function getEngagementShareByToken(token: string): Promise<EngagementShare | undefined> {
  const db = await getDb();
  if (!db) return undefined;
  const [share] = await db.select().from(engagementShares).where(eq(engagementShares.token, token));
  return share;
}

export async function getEngagementSharesByEngagement(engagementId: number): Promise<EngagementShare[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementShares).where(eq(engagementShares.engagementId, engagementId)).orderBy(desc(engagementShares.createdAt));
}

export async function updateEngagementShare(id: number, updates: Partial<InsertEngagementShare>): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.update(engagementShares).set(updates).where(eq(engagementShares.id, id));
}

export async function deleteEngagementShare(id: number): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.delete(engagementShares).where(eq(engagementShares.id, id));
}

export async function incrementShareViewCount(id: number): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.update(engagementShares).set({
    viewCount: sql`${engagementShares.viewCount} + 1`,
    lastAccessedAt: new Date(),
  }).where(eq(engagementShares.id, id));
}

export async function getAllEngagementShares(): Promise<EngagementShare[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementShares).orderBy(desc(engagementShares.createdAt));
}


// ─── Scoring Audit Log Helpers ───────────────────────────────────────
import { scoringAuditLog, ScoringAuditEntry } from "../drizzle/schema";

export interface RescoringAuditEntry {
  assetId: number;
  scanId?: number | null;
  profileId?: number | null;
  carverScores?: any;
  shockScores?: any;
  cvssEstimate?: number | null;
  missionImpactScore?: number | null;
  impactScore?: number | null;
  likelihoodScore?: number | null;
  hybridRiskScore?: number | null;
  riskBand?: string | null;
  weightsSnapshot?: any;
  computedBy?: string | null;
  // Dynamic re-scoring fields
  triggerType?: string | null;
  previousScore?: number | null;
  delta?: number | null;
  changeDescription?: string | null;
  factorChanges?: any;
  pipelinePhase?: string | null;
}

export async function insertScoringAuditEntry(entry: RescoringAuditEntry): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.insert(scoringAuditLog).values(entry);
}

export async function bulkInsertScoringAuditEntries(entries: RescoringAuditEntry[]): Promise<void> {
  const db = await getDb();
  if (!db) return;
  if (entries.length === 0) return;
  // Batch insert in chunks of 20 to avoid oversized queries
  const BATCH_SIZE = 20;
  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);
    await db.insert(scoringAuditLog).values(batch);
  }
}

export async function getScoringTimelineByAsset(assetId: number, limit = 50): Promise<ScoringAuditEntry[]> {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(scoringAuditLog)
    .where(eq(scoringAuditLog.assetId, assetId))
    .orderBy(desc(scoringAuditLog.computedAt))
    .limit(limit);
}

export async function getScoringTimelineByScan(scanId: number, limit = 200): Promise<ScoringAuditEntry[]> {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(scoringAuditLog)
    .where(eq(scoringAuditLog.scanId, scanId))
    .orderBy(desc(scoringAuditLog.computedAt))
    .limit(limit);
}

// ─── CISA KEV Lookup Helpers ────────────────────────────────────────────────
/**
 * Check if a CVE ID is listed in the CISA Known Exploited Vulnerabilities catalog.
 * Returns the KEV entry if found, null otherwise.
 */
export async function lookupKevByCve(cveId: string): Promise<IocFeed | null> {
  const db = await getDb();
  if (!db) return null;
  const [entry] = await db
    .select()
    .from(iocFeeds)
    .where(and(eq(iocFeeds.feedSource, "cisa_kev"), eq(iocFeeds.cveId, cveId)))
    .limit(1);
  return entry || null;
}

/**
 * Batch check multiple CVE IDs against the KEV catalog.
 * Returns a Map of cveId → KEV entry for those that are listed.
 */
export async function batchLookupKev(cveIds: string[]): Promise<Map<string, IocFeed>> {
  const db = await getDb();
  const result = new Map<string, IocFeed>();
  if (!db || cveIds.length === 0) return result;
  const entries = await db
    .select()
    .from(iocFeeds)
    .where(and(eq(iocFeeds.feedSource, "cisa_kev"), inArray(iocFeeds.cveId, cveIds)));
  for (const entry of entries) {
    if (entry.cveId) result.set(entry.cveId, entry);
  }
  return result;
}

// ─── Discovery Chain DB Helpers ─────────────────────────────────────────────

import { chainRuns, InsertChainRunRow, ChainRunRow, chainStageResults, InsertChainStageResultRow, ChainStageResultRow } from "../drizzle/schema";

export async function insertChainRun(data: InsertChainRunRow): Promise<ChainRunRow | null> {
  const db = await getDb();
  if (!db) return null;
  await db.insert(chainRuns).values(data);
  const [row] = await db.select().from(chainRuns).where(eq(chainRuns.chainId, data.chainId)).limit(1);
  return row || null;
}

export async function updateChainRunDb(chainId: string, data: Partial<InsertChainRunRow>): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.update(chainRuns).set(data).where(eq(chainRuns.chainId, chainId));
}

export async function getChainRunByChainId(chainId: string): Promise<ChainRunRow | null> {
  const db = await getDb();
  if (!db) return null;
  const [row] = await db.select().from(chainRuns).where(eq(chainRuns.chainId, chainId)).limit(1);
  return row || null;
}

export async function listChainRunsDb(filter?: {
  status?: string;
  engagementId?: number;
  limit?: number;
  offset?: number;
}): Promise<{ total: number; runs: ChainRunRow[] }> {
  const db = await getDb();
  if (!db) return { total: 0, runs: [] };
  const conditions: any[] = [];
  if (filter?.status) conditions.push(eq(chainRuns.status, filter.status));
  if (filter?.engagementId) conditions.push(eq(chainRuns.engagementId, filter.engagementId));
  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
  const [countResult] = await db.select({ count: sql<number>`COUNT(*)` }).from(chainRuns).where(whereClause);
  const rows = await db.select().from(chainRuns).where(whereClause).orderBy(desc(chainRuns.startedAt)).limit(filter?.limit || 25).offset(filter?.offset || 0);
  return { total: Number(countResult?.count || 0), runs: rows };
}

export async function deleteChainRunDb(chainId: string): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.delete(chainStageResults).where(eq(chainStageResults.chainId, chainId));
  await db.delete(chainRuns).where(eq(chainRuns.chainId, chainId));
}

export async function upsertChainStageResultDb(data: InsertChainStageResultRow): Promise<void> {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select().from(chainStageResults)
    .where(and(eq(chainStageResults.chainId, data.chainId), eq(chainStageResults.stageId, data.stageId)))
    .limit(1);
  if (existing.length > 0) {
    await db.update(chainStageResults).set(data)
      .where(and(eq(chainStageResults.chainId, data.chainId), eq(chainStageResults.stageId, data.stageId)));
  } else {
    await db.insert(chainStageResults).values(data);
  }
}

export async function getChainStageResultsDb(chainId: string): Promise<ChainStageResultRow[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(chainStageResults).where(eq(chainStageResults.chainId, chainId));
}

/**
 * Get KEV catalog statistics: total entries, ransomware-linked, overdue by CISA deadline.
 */
export async function getKevStats(): Promise<{
  totalKev: number;
  ransomwareLinked: number;
  overdueByDeadline: number;
  recentlyAdded: number;
}> {
  const db = await getDb();
  if (!db) return { totalKev: 0, ransomwareLinked: 0, overdueByDeadline: 0, recentlyAdded: 0 };
  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(iocFeeds).where(eq(iocFeeds.feedSource, "cisa_kev"));
  const [ransomware] = await db.select({ count: sql<number>`COUNT(*)` }).from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), eq(iocFeeds.knownRansomware, true)));
  const now = new Date().toISOString().split("T")[0];
  const [overdue] = await db.select({ count: sql<number>`COUNT(*)` }).from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), sql`${iocFeeds.dueDate} < ${now}`));
  const [recent] = await db.select({ count: sql<number>`COUNT(*)` }).from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), sql`${iocFeeds.createdAt} > DATE_SUB(NOW(), INTERVAL 7 DAY)`));
  return {
    totalKev: Number(total?.count || 0),
    ransomwareLinked: Number(ransomware?.count || 0),
    overdueByDeadline: Number(overdue?.count || 0),
    recentlyAdded: Number(recent?.count || 0),
  };
}


// ─── CARVER Risk Cards ────────────────────────────────────────────────────
import { carverRiskCards, InsertCarverRiskCard, CarverRiskCard } from "../drizzle/schema";

export async function createCarverRiskCard(card: InsertCarverRiskCard): Promise<number> {
  const db = await getDbRequired();
  const [result] = await db.insert(carverRiskCards).values(card);
  return result.insertId;
}

export async function createCarverRiskCardsBatch(cards: InsertCarverRiskCard[]): Promise<number> {
  if (cards.length === 0) return 0;
  const db = await getDbRequired();
  const [result] = await db.insert(carverRiskCards).values(cards);
  return result.affectedRows;
}

export async function getCarverRiskCards(opts?: { batchId?: string; domain?: string; sector?: string; limit?: number; offset?: number }): Promise<CarverRiskCard[]> {
  const db = await getDb();
  if (!db) return [];
  let query = db.select().from(carverRiskCards);
  const conditions: any[] = [];
  if (opts?.batchId) conditions.push(eq(carverRiskCards.batchId, opts.batchId));
  if (opts?.domain) conditions.push(eq(carverRiskCards.domain, opts.domain));
  if (opts?.sector) conditions.push(eq(carverRiskCards.inferredSector, opts.sector));
  if (conditions.length > 0) query = query.where(and(...conditions)) as any;
  return query.orderBy(desc(carverRiskCards.createdAt)).limit(opts?.limit || 500).offset(opts?.offset || 0);
}

export async function getCarverRiskCardById(id: number): Promise<CarverRiskCard | undefined> {
  const db = await getDb();
  if (!db) return undefined;
  const [card] = await db.select().from(carverRiskCards).where(eq(carverRiskCards.id, id));
  return card;
}

export async function getCarverRiskCardsByBatch(batchId: string): Promise<CarverRiskCard[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(carverRiskCards).where(eq(carverRiskCards.batchId, batchId)).orderBy(desc(carverRiskCards.createdAt));
}

export async function getCarverRiskCardStats() {
  const db = await getDb();
  if (!db) return { total: 0, bySector: [], byTier: [], batches: [] };
  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(carverRiskCards);
  const bySector = await db.select({ sector: carverRiskCards.inferredSector, count: sql<number>`COUNT(*)` }).from(carverRiskCards).groupBy(carverRiskCards.inferredSector);
  const byTier = await db.select({ tier: carverRiskCards.priorityTier, count: sql<number>`COUNT(*)` }).from(carverRiskCards).groupBy(carverRiskCards.priorityTier);
  const batches = await db.select({ batchId: carverRiskCards.batchId, count: sql<number>`COUNT(*)`, source: carverRiskCards.source }).from(carverRiskCards).groupBy(carverRiskCards.batchId, carverRiskCards.source);
  return { total: Number(total?.count || 0), bySector, byTier, batches };
}

export async function deleteCarverRiskCard(id: number) {
  const db = await getDbRequired();
  await db.delete(carverRiskCards).where(eq(carverRiskCards.id, id));
}

export async function deleteCarverRiskCardsByBatch(batchId: string) {
  const db = await getDbRequired();
  await db.delete(carverRiskCards).where(eq(carverRiskCards.batchId, batchId));
}

// ── Credential Attack Results ──────────────────────────────────────────────────
import {
  credentialAttackRuns, InsertCredentialAttackRun,
  credentialFindings, InsertCredentialFinding,
  zapProxySessions, InsertZapProxySession,
  pentestReports, InsertPentestReport,
} from "../drizzle/schema";

export async function createCredentialAttackRun(run: InsertCredentialAttackRun) {
  const db = await getDbRequired();
  const result = await db.insert(credentialAttackRuns).values(run);
  return result[0].insertId;
}

export async function updateCredentialAttackRun(id: number, updates: Partial<InsertCredentialAttackRun>) {
  const db = await getDbRequired();
  await db.update(credentialAttackRuns).set(updates).where(eq(credentialAttackRuns.id, id));
}

export async function getCredentialAttackRuns(userId: number, limit = 50) {
  const db = await getDbRequired();
  return db.select().from(credentialAttackRuns)
    .where(eq(credentialAttackRuns.userId, userId))
    .orderBy(desc(credentialAttackRuns.createdAt))
    .limit(limit);
}

export async function getCredentialAttackRunById(id: number) {
  const db = await getDbRequired();
  const rows = await db.select().from(credentialAttackRuns)
    .where(eq(credentialAttackRuns.id, id));
  return rows[0] ?? null;
}

export async function getCredentialAttackRunsByDomainScan(scanId: number) {
  const db = await getDbRequired();
  return db.select().from(credentialAttackRuns)
    .where(eq(credentialAttackRuns.domainIntelScanId, scanId))
    .orderBy(desc(credentialAttackRuns.createdAt));
}

export async function createCredentialFinding(finding: InsertCredentialFinding) {
  const db = await getDbRequired();
  const result = await db.insert(credentialFindings).values(finding);
  return result[0].insertId;
}

export async function createCredentialFindings(findings: InsertCredentialFinding[]) {
  if (findings.length === 0) return;
  const db = await getDbRequired();
  await db.insert(credentialFindings).values(findings);
}

export async function getCredentialFindingsByRun(runId: number) {
  const db = await getDbRequired();
  return db.select().from(credentialFindings)
    .where(eq(credentialFindings.attackRunId, runId))
    .orderBy(desc(credentialFindings.discoveredAt));
}

export async function getCredentialFindingsByDomainScan(scanId: number) {
  const db = await getDbRequired();
  return db.select().from(credentialFindings)
    .where(eq(credentialFindings.domainIntelScanId, scanId))
    .orderBy(desc(credentialFindings.discoveredAt));
}

export async function getAllCredentialFindings(userId: number, limit = 100) {
  const db = await getDbRequired();
  return db.select().from(credentialFindings)
    .where(eq(credentialFindings.userId, userId))
    .orderBy(desc(credentialFindings.discoveredAt))
    .limit(limit);
}

// ── ZAP Proxy Sessions ────────────────────────────────────────────────────────
export async function createZapProxySession(session: InsertZapProxySession) {
  const db = await getDbRequired();
  const result = await db.insert(zapProxySessions).values(session);
  return result[0].insertId;
}

export async function updateZapProxySession(id: number, updates: Partial<InsertZapProxySession>) {
  const db = await getDbRequired();
  await db.update(zapProxySessions).set(updates).where(eq(zapProxySessions.id, id));
}

export async function getZapProxySessions(userId: number, limit = 50) {
  const db = await getDbRequired();
  return db.select().from(zapProxySessions)
    .where(eq(zapProxySessions.userId, userId))
    .orderBy(desc(zapProxySessions.createdAt))
    .limit(limit);
}

export async function getZapProxySessionById(id: number) {
  const db = await getDbRequired();
  const rows = await db.select().from(zapProxySessions)
    .where(eq(zapProxySessions.id, id));
  return rows[0] ?? null;
}

export async function getZapSessionsByDomainScan(scanId: number) {
  const db = await getDbRequired();
  return db.select().from(zapProxySessions)
    .where(eq(zapProxySessions.domainIntelScanId, scanId))
    .orderBy(desc(zapProxySessions.createdAt));
}

// ── Pentest Reports ────────────────────────────────────────────────────────────
export async function createPentestReport(report: InsertPentestReport) {
  const db = await getDbRequired();
  const result = await db.insert(pentestReports).values(report);
  return result[0].insertId;
}

export async function updatePentestReport(id: number, updates: Partial<InsertPentestReport>) {
  const db = await getDbRequired();
  await db.update(pentestReports).set(updates).where(eq(pentestReports.id, id));
}

export async function getPentestReports(userId: number, limit = 50) {
  const db = await getDbRequired();
  return db.select().from(pentestReports)
    .where(eq(pentestReports.userId, userId))
    .orderBy(desc(pentestReports.createdAt))
    .limit(limit);
}

export async function getPentestReportById(id: number) {
  const db = await getDbRequired();
  const rows = await db.select().from(pentestReports)
    .where(eq(pentestReports.id, id));
  return rows[0] ?? null;
}

export async function deletePentestReport(id: number) {
  const db = await getDbRequired();
  await db.delete(pentestReports).where(eq(pentestReports.id, id));
}


// ── Enhanced Credential Attack Persistence (External Tools) ─────────────────

/** Save a credential attack run with external tool info */
export async function saveCredentialAttackWithTool(run: InsertCredentialAttackRun & {
  tool?: string;
  toolVersion?: string;
  rawOutput?: string;
  toolMetadata?: any;
  targetDomain?: string;
  failedAttempts?: number;
  stoppedReason?: string;
}) {
  const db = await getDbRequired();
  const result = await db.insert(credentialAttackRuns).values(run);
  return result[0].insertId;
}

/** Save credential finding with tool attribution */
export async function saveCredentialFindingWithTool(finding: InsertCredentialFinding & {
  tool?: string;
  responseSnippet?: string;
  additionalInfo?: string;
  validationStatus?: string;
}) {
  const db = await getDbRequired();
  const result = await db.insert(credentialFindings).values(finding);
  return result[0].insertId;
}

/** Get attack history with tool info, filterable by tool type */
export async function getCredentialAttackHistory(userId: number, opts?: {
  tool?: string;
  protocol?: string;
  status?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await getDbRequired();
  const conditions = [eq(credentialAttackRuns.userId, userId)];
  
  if (opts?.tool) {
    conditions.push(eq(credentialAttackRuns.tool, opts.tool));
  }
  if (opts?.protocol) {
    conditions.push(eq(credentialAttackRuns.protocol, opts.protocol));
  }
  if (opts?.status) {
    conditions.push(eq(credentialAttackRuns.status, opts.status as any));
  }
  
  return db.select().from(credentialAttackRuns)
    .where(and(...conditions))
    .orderBy(desc(credentialAttackRuns.createdAt))
    .limit(opts?.limit ?? 50)
    .offset(opts?.offset ?? 0);
}

/** Get attack history count for pagination */
export async function getCredentialAttackHistoryCount(userId: number, opts?: {
  tool?: string;
  protocol?: string;
  status?: string;
}) {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import('drizzle-orm');
  const conditions = [eq(credentialAttackRuns.userId, userId)];
  
  if (opts?.tool) {
    conditions.push(eq(credentialAttackRuns.tool, opts.tool));
  }
  if (opts?.protocol) {
    conditions.push(eq(credentialAttackRuns.protocol, opts.protocol));
  }
  if (opts?.status) {
    conditions.push(eq(credentialAttackRuns.status, opts.status as any));
  }
  
  const result = await db.select({ count: sqlTag`COUNT(*)`.as('count') })
    .from(credentialAttackRuns)
    .where(and(...conditions));
  return Number(result[0]?.count ?? 0);
}

/** Get all findings across all attacks, filterable */
export async function getCredentialFindingsHistory(userId: number, opts?: {
  tool?: string;
  protocol?: string;
  validationStatus?: string;
  limit?: number;
  offset?: number;
}) {
  const db = await getDbRequired();
  const conditions = [eq(credentialFindings.userId, userId)];
  
  if (opts?.tool) {
    conditions.push(eq(credentialFindings.tool, opts.tool));
  }
  if (opts?.protocol) {
    conditions.push(eq(credentialFindings.protocol, opts.protocol));
  }
  if (opts?.validationStatus) {
    conditions.push(eq(credentialFindings.validationStatus, opts.validationStatus));
  }
  
  return db.select().from(credentialFindings)
    .where(and(...conditions))
    .orderBy(desc(credentialFindings.discoveredAt))
    .limit(opts?.limit ?? 100)
    .offset(opts?.offset ?? 0);
}

/** Update finding validation status */
export async function updateCredentialFindingValidation(
  id: number,
  validationStatus: string,
  validatedBy?: number,
  notes?: string
) {
  const db = await getDbRequired();
  await db.update(credentialFindings).set({
    validationStatus,
    notes: notes ?? undefined,
  }).where(eq(credentialFindings.id, id));
}

/** Get attack stats summary for dashboard */
export async function getCredentialAttackStats(userId: number) {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import('drizzle-orm');
  
  const runs = await db.select({
    tool: credentialAttackRuns.tool,
    totalRuns: sqlTag`COUNT(*)`.as('total_runs'),
    totalAttempts: sqlTag`SUM(${credentialAttackRuns.totalAttempts})`.as('total_attempts'),
    totalSuccessful: sqlTag`SUM(${credentialAttackRuns.successfulAttempts})`.as('total_successful'),
    avgDuration: sqlTag`AVG(${credentialAttackRuns.durationMs})`.as('avg_duration'),
  })
    .from(credentialAttackRuns)
    .where(eq(credentialAttackRuns.userId, userId))
    .groupBy(credentialAttackRuns.tool);
  
  const findings = await db.select({
    tool: credentialFindings.tool,
    totalFindings: sqlTag`COUNT(*)`.as('total_findings'),
    validated: sqlTag`SUM(CASE WHEN ${credentialFindings.validationStatus} = 'validated' THEN 1 ELSE 0 END)`.as('validated'),
    falsePositives: sqlTag`SUM(CASE WHEN ${credentialFindings.validationStatus} = 'false_positive' THEN 1 ELSE 0 END)`.as('false_positives'),
  })
    .from(credentialFindings)
    .where(eq(credentialFindings.userId, userId))
    .groupBy(credentialFindings.tool);
  
  return { runs, findings };
}

// ─── Platform Credentials (for Burp Suite, etc.) ───────────────────────────
import { userPlatformCredentials } from "../drizzle/schema";

const CRED_ENCRYPTION_KEY = (() => {
  const secret = process.env.JWT_SECRET || "default-dev-key-do-not-use-in-prod";
  return crypto.createHash("sha256").update(secret).digest();
})();

function decryptCredential(encryptedText: string): string {
  try {
    const [ivHex, authTagHex, encrypted] = encryptedText.split(":");
    if (!ivHex || !authTagHex || !encrypted) return "";
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", CRED_ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch {
    return "";
  }
}

/**
 * List all active platform credentials for a user.
 * Used by Burp auto-scan to find connected Burp Suite Pro/Enterprise credentials.
 * Returns decrypted apiKey so the caller can connect to the Burp API.
 */
export async function listPlatformCredentials(userId: string | number) {
  const db = await getDb();
  if (!db) return [];
  const numericUserId = typeof userId === "string" ? parseInt(userId, 10) : userId;
  if (isNaN(numericUserId)) return [];
  const rows = await db
    .select()
    .from(userPlatformCredentials)
    .where(
      and(
        eq(userPlatformCredentials.userId, numericUserId),
        eq(userPlatformCredentials.isActive, 1)
      )
    );
  return rows.map((row) => ({
    id: row.id,
    userId: row.userId,
    platform: row.platform,
    displayName: row.displayName,
    apiUsername: row.apiUsername || "",
    apiKey: decryptCredential(row.apiKeyEncrypted),
    baseUrl: row.baseUrl || "",
    isActive: row.isActive,
    lastVerifiedAt: row.lastVerifiedAt,
    lastSyncAt: row.lastSyncAt,
    syncStatus: row.syncStatus,
    metadata: row.metadata,
  }));
}

// ─── Scan Results Persistence ───────────────────────────────────────────────
import { scanResults, InsertScanResult, ScanResult } from "../drizzle/schema";

/** Insert a single scan result row after a tool finishes executing. */
export async function insertScanResult(data: InsertScanResult): Promise<ScanResult | null> {
  const db = await getDb();
  if (!db) return null;

  // Dedup guard: check for existing result with same engagement + tool + target
  const [existing] = await db.select({ id: scanResults.id })
    .from(scanResults)
    .where(and(
      eq(scanResults.engagementId, data.engagementId),
      eq(scanResults.tool, data.tool),
      eq(scanResults.target, data.target)
    ))
    .limit(1);
  if (existing) {
    // Update the existing record with new data instead of creating a duplicate
    await db.update(scanResults).set({
      rawOutput: data.rawOutput,
      rawStderr: data.rawStderr,
      exitCode: data.exitCode,
      durationMs: data.durationMs,
      timedOut: data.timedOut,
      findings: data.findings,
      findingCount: data.findingCount,
      severitySummary: data.severitySummary,
      command: data.command,
    }).where(eq(scanResults.id, existing.id));
    const [result] = await db.select().from(scanResults).where(eq(scanResults.id, existing.id));
    return result;
  }

  const insertResult = await db.insert(scanResults).values(data);
  const insertedId = Number(insertResult[0].insertId);
  if (!insertedId) return null;
  const [result] = await db.select().from(scanResults).where(eq(scanResults.id, insertedId));
  return result;
}

/** Get all scan results for an engagement, ordered newest first. */
export async function getScanResultsByEngagement(engagementId: number): Promise<ScanResult[]> {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(scanResults)
    .where(eq(scanResults.engagementId, engagementId))
    .orderBy(sql`${scanResults.createdAt} DESC`);
}

/** Get scan results filtered by tool (e.g., "scanforge-discovery", "nuclei"). */
export async function getScanResultsByTool(engagementId: number, tool: string): Promise<ScanResult[]> {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(scanResults)
    .where(and(eq(scanResults.engagementId, engagementId), eq(scanResults.tool, tool)))
    .orderBy(sql`${scanResults.createdAt} DESC`);
}

/** Get a summary of scan results for an engagement: count per tool, total findings. */
export async function getScanResultsSummary(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select({
      tool: scanResults.tool,
      count: sql<number>`COUNT(*)`,
      totalFindings: sql<number>`COALESCE(SUM(${scanResults.findingCount}), 0)`,
      avgDurationMs: sql<number>`COALESCE(AVG(${scanResults.durationMs}), 0)`,
    })
    .from(scanResults)
    .where(eq(scanResults.engagementId, engagementId))
    .groupBy(scanResults.tool);
}


// ─── Engagement Ops State Persistence ───────────────────────────────────────
// Saves/loads the in-memory ops state to/from the database so it survives
// server crashes and restarts.

/**
 * Save (upsert) an ops state snapshot for an engagement.
 * Uses INSERT ... ON DUPLICATE KEY UPDATE pattern via engagementId.
 */
export async function saveOpsSnapshot(engagementId: number, state: any): Promise<void> {
  const db = await getDbRequired();
  // Import server instance ID for ownership tracking
  let serverInstanceId: string | undefined;
  try {
    const { SERVER_INSTANCE_ID } = await import('./lib/server-instance');
    serverInstanceId = SERVER_INSTANCE_ID;
  } catch { /* ignore if module not available */ }

  // Serialize the state — strip non-serializable fields (Set → Array already handled in getState)
  // Serialize Sets to Arrays for JSON storage
  const completedScansToSave = state.completedScans ? {
    nucleiCompleted: state.completedScans.nucleiCompleted instanceof Set ? Array.from(state.completedScans.nucleiCompleted) : (state.completedScans.nucleiCompleted || []),
    zapCompleted: state.completedScans.zapCompleted instanceof Set ? Array.from(state.completedScans.zapCompleted) : (state.completedScans.zapCompleted || []),
    hydraCompleted: state.completedScans.hydraCompleted instanceof Set ? Array.from(state.completedScans.hydraCompleted) : (state.completedScans.hydraCompleted || []),
    exploitCompleted: state.completedScans.exploitCompleted instanceof Set ? Array.from(state.completedScans.exploitCompleted) : (state.completedScans.exploitCompleted || []),
    lastCheckpointAt: state.completedScans.lastCheckpointAt || Date.now(),
  } : undefined;

  const stateToSave = {
    ...state,
    skippedDomains: state.skippedDomains instanceof Set ? Array.from(state.skippedDomains) : (state.skippedDomains || []),
    completedScans: completedScansToSave,
  };

  // Check if snapshot exists for this engagement
  const existing = await db.select({ id: engagementOpsSnapshots.id })
    .from(engagementOpsSnapshots)
    .where(eq(engagementOpsSnapshots.engagementId, engagementId))
    .limit(1);

  if (existing.length > 0) {
    await db.update(engagementOpsSnapshots)
      .set({
        stateJson: stateToSave,
        phase: state.phase || 'idle',
        isRunning: state.isRunning || false,
        assetCount: state.assets?.length || 0,
        ...(serverInstanceId ? { serverInstanceId } : {}),
      })
      .where(eq(engagementOpsSnapshots.engagementId, engagementId));
  } else {
    await db.insert(engagementOpsSnapshots).values({
      engagementId,
      stateJson: stateToSave,
      phase: state.phase || 'idle',
      isRunning: state.isRunning || false,
      assetCount: state.assets?.length || 0,
      ...(serverInstanceId ? { serverInstanceId } : {}),
    });
  }
}

/**
 * Load the latest ops state snapshot for an engagement.
 * Returns null if no snapshot exists.
 */
export async function loadOpsSnapshot(engagementId: number): Promise<any | null> {
  try {
    const db = await getDbRequired();
    const rows = await db.select()
      .from(engagementOpsSnapshots)
      .where(eq(engagementOpsSnapshots.engagementId, engagementId))
      .limit(1);

    if (rows.length === 0) return null;

    const snapshot = rows[0];
    const state = snapshot.stateJson as any;

    // Ensure all required fields exist (handles empty {} from DB reset)
    if (!state.engagementId) state.engagementId = engagementId;
    if (!state.phase) state.phase = 'idle';
    if (state.progress === undefined) state.progress = 0;
    if (state.isRunning === undefined) state.isRunning = false;
    if (state.isPaused === undefined) state.isPaused = false;
    if (!Array.isArray(state.assets)) state.assets = [];
    if (!Array.isArray(state.log)) state.log = [];
    if (!Array.isArray(state.approvalGates)) state.approvalGates = [];
    if (!state.stats) state.stats = { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 };
    // Ensure each asset has required arrays
    for (const asset of state.assets) {
      if (!Array.isArray(asset.ports)) asset.ports = [];
      if (!Array.isArray(asset.vulns)) asset.vulns = [];
      if (!Array.isArray(asset.zapFindings)) asset.zapFindings = [];
      if (!Array.isArray(asset.exploitAttempts)) asset.exploitAttempts = [];
      if (!Array.isArray(asset.toolResults)) asset.toolResults = [];
    }

    // Restore Set from array
    if (Array.isArray(state.skippedDomains)) {
      state.skippedDomains = new Set(state.skippedDomains);
    } else {
      state.skippedDomains = new Set();
    }

    // If the snapshot says it was running but the server restarted, mark it as crashed
    if (state.isRunning) {
      state.isRunning = false;
      state.phase = 'error';
      state.error = 'Server restarted during scan — state recovered from last snapshot. Assets are preserved. You can retry the scan.';
      const recoveryLog = {
        id: `log-${Date.now()}-recovery`,
        timestamp: Date.now(),
        phase: 'recon' as const,
        type: 'warning' as const,
        title: '⚠️ Scan Interrupted — State Recovered',
        detail: `The server restarted while the scan was running. ${state.assets?.length || 0} assets have been recovered from the last snapshot. You can reset and re-run the scan.`,
      };
      if (!state.log) state.log = [];
      state.log.push(recoveryLog);
    }

    return state;
  } catch (e: any) {
    console.error(`[OpsSnapshot] Failed to load snapshot for engagement #${engagementId}:`, e.message);
    return null;
  }
}

/**
 * Delete ops snapshot for an engagement (used when resetting state).
 */
export async function deleteOpsSnapshot(engagementId: number): Promise<void> {
  try {
    const db = await getDbRequired();
    await db.delete(engagementOpsSnapshots)
      .where(eq(engagementOpsSnapshots.engagementId, engagementId));
  } catch (e: any) {
    console.error(`[OpsSnapshot] Failed to delete snapshot for engagement #${engagementId}:`, e.message);
  }
}


// ─── LLM Telemetry Helpers ──────────────────────────────────────────────────

/**
 * Record a single LLM telemetry event. Fire-and-forget — errors are logged but
 * never propagated so telemetry never breaks the calling code path.
 */
export async function recordLlmTelemetry(entry: Omit<InsertLlmTelemetry, "id" | "createdAt">): Promise<void> {
  try {
    const db = await getDb();
    await db.insert(llmTelemetry).values(entry);
  } catch (e: any) {
    console.warn("[LLM Telemetry] Failed to record:", e.message);
  }
}

/**
 * Get summary statistics for LLM usage over a time window.
 */
export async function getLlmTelemetrySummary(windowHours: number = 24) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      COUNT(*) as total_calls,
      SUM(CASE WHEN llm_status = 'success' THEN 1 ELSE 0 END) as success_count,
      SUM(CASE WHEN llm_status = 'retried_success' THEN 1 ELSE 0 END) as retried_success_count,
      SUM(CASE WHEN llm_status = 'error' THEN 1 ELSE 0 END) as error_count,
      SUM(CASE WHEN llm_status = 'timeout' THEN 1 ELSE 0 END) as timeout_count,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms,
      MAX(latency_ms) as max_latency_ms,
      MIN(latency_ms) as min_latency_ms,
      ROUND(AVG(retry_count), 2) as avg_retries,
      SUM(COALESCE(tokens_in, 0)) as total_tokens_in,
      SUM(COALESCE(tokens_out, 0)) as total_tokens_out,
      SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) as total_tokens
    FROM llm_telemetry
    WHERE called_at >= DATE_SUB(NOW(), INTERVAL ${windowHours} HOUR)
  `);
  return (rows as any[])[0] || {};
}

/**
 * Get hourly time series data for LLM usage.
 */
export async function getLlmTelemetryTimeSeries(windowHours: number = 24) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      DATE_FORMAT(called_at, '%Y-%m-%d %H:00:00') as hour_bucket,
      COUNT(*) as total_calls,
      SUM(CASE WHEN llm_status IN ('success', 'retried_success') THEN 1 ELSE 0 END) as success_count,
      SUM(CASE WHEN llm_status IN ('error', 'timeout') THEN 1 ELSE 0 END) as failure_count,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms,
      ROUND(AVG(retry_count), 2) as avg_retries,
      SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) as total_tokens
    FROM llm_telemetry
    WHERE called_at >= DATE_SUB(NOW(), INTERVAL ${windowHours} HOUR)
    GROUP BY hour_bucket
    ORDER BY hour_bucket ASC
  `);
  return rows as any[];
}

/**
 * Get top callers by invocation count.
 */
export async function getLlmTelemetryTopCallers(windowHours: number = 24, limit: number = 15) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      caller,
      COUNT(*) as call_count,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms,
      SUM(CASE WHEN llm_status IN ('error', 'timeout') THEN 1 ELSE 0 END) as error_count,
      ROUND(SUM(CASE WHEN llm_status IN ('success', 'retried_success') THEN 1 ELSE 0 END) / COUNT(*) * 100, 1) as success_rate,
      SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) as total_tokens
    FROM llm_telemetry
    WHERE called_at >= DATE_SUB(NOW(), INTERVAL ${windowHours} HOUR)
    GROUP BY caller
    ORDER BY call_count DESC
    LIMIT ${limit}
  `);
  return rows as any[];
}

/**
 * Get recent errors for debugging.
 */
export async function getLlmTelemetryRecentErrors(limit: number = 20) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      id, called_at, caller, model, llm_status, http_status,
      latency_ms, retry_count, error_message, engagement_id
    FROM llm_telemetry
    WHERE llm_status IN ('error', 'timeout')
    ORDER BY called_at DESC
    LIMIT ${limit}
  `);
  return rows as any[];
}

/**
 * Get latency distribution buckets for histogram.
 */
export async function getLlmTelemetryLatencyDistribution(windowHours: number = 24) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      CASE
        WHEN latency_ms < 1000 THEN '<1s'
        WHEN latency_ms < 3000 THEN '1-3s'
        WHEN latency_ms < 5000 THEN '3-5s'
        WHEN latency_ms < 10000 THEN '5-10s'
        WHEN latency_ms < 30000 THEN '10-30s'
        WHEN latency_ms < 60000 THEN '30-60s'
        ELSE '>60s'
      END as latency_bucket,
      COUNT(*) as count
    FROM llm_telemetry
    WHERE called_at >= DATE_SUB(NOW(), INTERVAL ${windowHours} HOUR)
    GROUP BY latency_bucket
    ORDER BY MIN(latency_ms) ASC
  `);
  return rows as any[];
}

/**
 * Get model usage breakdown.
 */
export async function getLlmTelemetryModelUsage(windowHours: number = 24) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      model,
      COUNT(*) as call_count,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms,
      SUM(COALESCE(tokens_in, 0)) as total_tokens_in,
      SUM(COALESCE(tokens_out, 0)) as total_tokens_out,
      ROUND(SUM(CASE WHEN llm_status IN ('success', 'retried_success') THEN 1 ELSE 0 END) / COUNT(*) * 100, 1) as success_rate
    FROM llm_telemetry
    WHERE called_at >= DATE_SUB(NOW(), INTERVAL ${windowHours} HOUR)
    GROUP BY model
    ORDER BY call_count DESC
  `);
  return rows as any[];
}


// ─── Per-Engagement LLM Cost Tracking ─────────────────────────────────────────

/**
 * Pricing constants for cost estimation (per 1M tokens).
 * Based on Gemini 2.5 Flash pricing as of March 2026.
 * Update these when model pricing changes.
 */
const LLM_PRICING: Record<string, { inputPer1M: number; outputPer1M: number }> = {
  "gemini-2.5-flash": { inputPer1M: 0.15, outputPer1M: 0.60 },
  "gemini-2.0-flash": { inputPer1M: 0.10, outputPer1M: 0.40 },
  "gemini-1.5-pro": { inputPer1M: 3.50, outputPer1M: 10.50 },
  // Fallback for unknown models
  default: { inputPer1M: 0.15, outputPer1M: 0.60 },
};

function estimateCost(model: string, tokensIn: number, tokensOut: number): number {
  const pricing = LLM_PRICING[model] || LLM_PRICING.default;
  return (tokensIn / 1_000_000) * pricing.inputPer1M + (tokensOut / 1_000_000) * pricing.outputPer1M;
}

/**
 * Get LLM cost summary for a single engagement.
 */
export async function getEngagementLlmCost(engagementId: number) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      COUNT(*) as total_calls,
      SUM(CASE WHEN llm_status IN ('success', 'retried_success') THEN 1 ELSE 0 END) as success_count,
      SUM(CASE WHEN llm_status IN ('error', 'timeout') THEN 1 ELSE 0 END) as failure_count,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms,
      SUM(COALESCE(tokens_in, 0)) as total_tokens_in,
      SUM(COALESCE(tokens_out, 0)) as total_tokens_out,
      SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) as total_tokens,
      ROUND(AVG(retry_count), 2) as avg_retries,
      MIN(called_at) as first_call,
      MAX(called_at) as last_call
    FROM llm_telemetry
    WHERE engagement_id = ${engagementId}
  `);
  const row = (rows as any[])[0] || {};
  const tokensIn = Number(row.total_tokens_in) || 0;
  const tokensOut = Number(row.total_tokens_out) || 0;
  return {
    ...row,
    total_tokens_in: tokensIn,
    total_tokens_out: tokensOut,
    total_tokens: Number(row.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", tokensIn, tokensOut),
  };
}

/**
 * Get per-caller LLM cost breakdown for a single engagement.
 */
export async function getEngagementLlmCostBreakdown(engagementId: number) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      caller,
      COUNT(*) as call_count,
      SUM(CASE WHEN llm_status IN ('success', 'retried_success') THEN 1 ELSE 0 END) as success_count,
      SUM(CASE WHEN llm_status IN ('error', 'timeout') THEN 1 ELSE 0 END) as failure_count,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms,
      SUM(COALESCE(tokens_in, 0)) as tokens_in,
      SUM(COALESCE(tokens_out, 0)) as tokens_out,
      SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) as total_tokens
    FROM llm_telemetry
    WHERE engagement_id = ${engagementId}
    GROUP BY caller
    ORDER BY total_tokens DESC
  `);
  return (rows as any[]).map(r => ({
    ...r,
    tokens_in: Number(r.tokens_in) || 0,
    tokens_out: Number(r.tokens_out) || 0,
    total_tokens: Number(r.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", Number(r.tokens_in) || 0, Number(r.tokens_out) || 0),
  }));
}

/**
 * Get all engagements ranked by total LLM cost.
 */
export async function getAllEngagementLlmCosts(limit: number = 50) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      engagement_id,
      COUNT(*) as total_calls,
      SUM(CASE WHEN llm_status IN ('success', 'retried_success') THEN 1 ELSE 0 END) as success_count,
      SUM(CASE WHEN llm_status IN ('error', 'timeout') THEN 1 ELSE 0 END) as failure_count,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms,
      SUM(COALESCE(tokens_in, 0)) as tokens_in,
      SUM(COALESCE(tokens_out, 0)) as tokens_out,
      SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) as total_tokens,
      MIN(called_at) as first_call,
      MAX(called_at) as last_call
    FROM llm_telemetry
    WHERE engagement_id IS NOT NULL
    GROUP BY engagement_id
    ORDER BY total_tokens DESC
    LIMIT ${limit}
  `);
  return (rows as any[]).map(r => ({
    ...r,
    engagement_id: Number(r.engagement_id),
    tokens_in: Number(r.tokens_in) || 0,
    tokens_out: Number(r.tokens_out) || 0,
    total_tokens: Number(r.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", Number(r.tokens_in) || 0, Number(r.tokens_out) || 0),
  }));
}

/**
 * Get LLM cost time series for a single engagement (hourly buckets).
 */
export async function getEngagementLlmCostTimeSeries(engagementId: number) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      DATE_FORMAT(called_at, '%Y-%m-%d %H:00:00') as hour_bucket,
      COUNT(*) as total_calls,
      SUM(COALESCE(tokens_in, 0)) as tokens_in,
      SUM(COALESCE(tokens_out, 0)) as tokens_out,
      SUM(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) as total_tokens,
      ROUND(AVG(latency_ms), 0) as avg_latency_ms
    FROM llm_telemetry
    WHERE engagement_id = ${engagementId}
    GROUP BY hour_bucket
    ORDER BY hour_bucket ASC
  `);
  return (rows as any[]).map(r => ({
    ...r,
    tokens_in: Number(r.tokens_in) || 0,
    tokens_out: Number(r.tokens_out) || 0,
    total_tokens: Number(r.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", Number(r.tokens_in) || 0, Number(r.tokens_out) || 0),
  }));
}


// ─── Raw Telemetry for Hot Path Analyzer ────────────────────────────────────

/**
 * Get raw telemetry records for a specific engagement, formatted for the Hot Path Analyzer.
 * Returns individual records (not aggregated) so the analyzer can compute stability/determinism.
 */
export async function getEngagementLlmTelemetryRaw(engagementId: number, limit: number = 10000) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      caller,
      model,
      llm_status as llmStatus,
      latency_ms as latencyMs,
      COALESCE(tokens_in, 0) as tokensIn,
      COALESCE(tokens_out, 0) as tokensOut,
      called_at as calledAt,
      engagement_id as engagementId,
      error_message as errorMessage
    FROM llm_telemetry
    WHERE engagement_id = ${engagementId}
    ORDER BY called_at ASC
    LIMIT ${limit}
  `);
  return (rows as any[]).map(r => ({
    caller: r.caller || 'unknown',
    model: r.model || 'gemini-2.5-flash',
    llmStatus: r.llmStatus || 'success',
    latencyMs: Number(r.latencyMs) || 0,
    tokensIn: Number(r.tokensIn) || 0,
    tokensOut: Number(r.tokensOut) || 0,
    calledAt: String(r.calledAt),
    engagementId: Number(r.engagementId) || engagementId,
    errorMessage: r.errorMessage || undefined,
  }));
}

/**
 * Get raw telemetry records across all engagements for global hot path analysis.
 */
export async function getGlobalLlmTelemetryRaw(windowHours: number = 168, limit: number = 50000) {
  const db = await getDb();
  const { sql } = await import("drizzle-orm");
  const [rows] = await db.execute(sql`
    SELECT
      caller,
      model,
      llm_status as llmStatus,
      latency_ms as latencyMs,
      COALESCE(tokens_in, 0) as tokensIn,
      COALESCE(tokens_out, 0) as tokensOut,
      called_at as calledAt,
      engagement_id as engagementId,
      error_message as errorMessage
    FROM llm_telemetry
    WHERE called_at >= DATE_SUB(NOW(), INTERVAL ${windowHours} HOUR)
    ORDER BY called_at ASC
    LIMIT ${limit}
  `);
  return (rows as any[]).map(r => ({
    caller: r.caller || 'unknown',
    model: r.model || 'gemini-2.5-flash',
    llmStatus: r.llmStatus || 'success',
    latencyMs: Number(r.latencyMs) || 0,
    tokensIn: Number(r.tokensIn) || 0,
    tokensOut: Number(r.tokensOut) || 0,
    calledAt: String(r.calledAt),
    engagementId: r.engagementId ? Number(r.engagementId) : undefined,
    errorMessage: r.errorMessage || undefined,
  }));
}

// ─── Exploit Plan History ────────────────────────────────────────────────────

/**
 * Insert a new exploit plan history record.
 */
export async function insertExploitPlanHistory(data: InsertExploitPlanHistory) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const insertResult = await db.insert(exploitPlanHistory).values(data);
  const insertedId = Number(insertResult[0].insertId);
  return { id: insertedId };
}

/**
 * Get all exploit plan history records for an engagement, newest first.
 */
export async function getExploitPlanHistoryByEngagement(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(exploitPlanHistory)
    .where(eq(exploitPlanHistory.engagementId, engagementId))
    .orderBy(desc(exploitPlanHistory.createdAt));
}

/**
 * Get a single exploit plan history record by ID.
 */
export async function getExploitPlanHistoryById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db
    .select()
    .from(exploitPlanHistory)
    .where(eq(exploitPlanHistory.id, id))
    .limit(1);
  return rows[0] || null;
}

/**
 * Get exploit plan history by gate ID.
 */
export async function getExploitPlanHistoryByGateId(gateId: string) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db
    .select()
    .from(exploitPlanHistory)
    .where(eq(exploitPlanHistory.gateId, gateId))
    .limit(1);
  return rows[0] || null;
}

/**
 * Get summary stats for exploit plan history across all engagements.
 */
export async function getExploitPlanStats() {
  const db = await getDb();
  if (!db) return { total: 0, approved: 0, rejected: 0, modified: 0 };
  const [rows] = await db.execute(sql`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN plan_status = 'approved' THEN 1 ELSE 0 END) as approved,
      SUM(CASE WHEN plan_status = 'rejected' THEN 1 ELSE 0 END) as rejected,
      SUM(CASE WHEN plan_status = 'modified' THEN 1 ELSE 0 END) as modified
    FROM exploit_plan_history
  `);
  const r = (rows as any[])[0] || {};
  return {
    total: Number(r.total) || 0,
    approved: Number(r.approved) || 0,
    rejected: Number(r.rejected) || 0,
    modified: Number(r.modified) || 0,
  };
}


// ─── Training Lab Helpers ──────────────────────────────────────────────────

export async function createTrainingLabSession(data: InsertTrainingLabSession): Promise<SelectTrainingLabSession | null> {
  const db = await getDb();
  if (!db) return null;
  await db.insert(trainingLabSessions).values(data);
  const [row] = await db.select().from(trainingLabSessions)
    .where(eq(trainingLabSessions.sessionId, data.sessionId!))
    .limit(1);
  return row || null;
}

export async function updateTrainingLabSession(
  sessionId: string,
  update: Partial<InsertTrainingLabSession>
): Promise<void> {
  const db = await getDbRequired();
  await db.update(trainingLabSessions)
    .set(update)
    .where(eq(trainingLabSessions.sessionId, sessionId));
}

export async function getTrainingLabSession(sessionId: string): Promise<SelectTrainingLabSession | null> {
  const db = await getDb();
  if (!db) return null;
  const [row] = await db.select().from(trainingLabSessions)
    .where(eq(trainingLabSessions.sessionId, sessionId))
    .limit(1);
  return row || null;
}

export async function listTrainingLabSessions(limit = 50): Promise<SelectTrainingLabSession[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(trainingLabSessions)
    .orderBy(desc(trainingLabSessions.id))
    .limit(limit);
}

export async function insertTrainingLabFeedbackEntry(data: InsertTrainingLabFeedback): Promise<void> {
  const db = await getDbRequired();
  await db.insert(trainingLabFeedback).values(data);
}

export async function getTrainingLabFeedbackForSession(sessionId: string): Promise<SelectTrainingLabFeedback[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(trainingLabFeedback)
    .where(eq(trainingLabFeedback.sessionId, sessionId));
}


// ─── Cross-Session Context Persistence ──────────────────────────────────────
// Fetches historical scan data for the same domain to provide context to new scans.

export interface HistoricalScanContext {
  previousScanId: number;
  previousScanDate: string;
  previousRiskScore: number | null;
  previousRiskBand: string | null;
  previousTotalAssets: number | null;
  previousTotalFindings: number | null;
  previousConfirmedFindings: number | null;
  previousExecutiveSummary: string | null;
  previousAssets: {
    hostname: string;
    assetType: string | null;
    hybridRiskScore: number | null;
    riskBand: string | null;
    technologies: any;
    postureFindings: any;
    vulnRiskScore: number | null;
    excluded: boolean;
  }[];
  scanCount: number;
}

/**
 * Get the most recent completed scan for a given domain, along with its assets.
 * This provides historical context for new scans of the same target.
 */
export async function getHistoricalScanContext(
  primaryDomain: string,
  excludeScanId?: number
): Promise<HistoricalScanContext | null> {
  const db = await getDb();
  if (!db) return null;

  // Find the most recent completed scan for this domain
  const conditions = [
    eq(domainIntelScans.primaryDomain, primaryDomain),
    or(
      eq(domainIntelScans.status, 'completed'),
      eq(domainIntelScans.status, 'scan_complete')
    )!,
  ];
  if (excludeScanId) {
    conditions.push(ne(domainIntelScans.id, excludeScanId));
  }

  const previousScans = await db.select({
    id: domainIntelScans.id,
    overallRiskScore: domainIntelScans.overallRiskScore,
    overallRiskBand: domainIntelScans.overallRiskBand,
    totalAssets: domainIntelScans.totalAssets,
    totalFindings: domainIntelScans.totalFindings,
    confirmedFindings: domainIntelScans.confirmedFindings,
    executiveSummary: domainIntelScans.executiveSummary,
    createdAt: domainIntelScans.createdAt,
  }).from(domainIntelScans)
    .where(and(...conditions))
    .orderBy(desc(domainIntelScans.createdAt))
    .limit(1);

  if (previousScans.length === 0) return null;

  const prevScan = previousScans[0];

  // Count total scans for this domain
  const countResult = await db.select({
    count: sql<number>`COUNT(*)`,
  }).from(domainIntelScans)
    .where(eq(domainIntelScans.primaryDomain, primaryDomain));
  const scanCount = countResult[0]?.count || 1;

  // Fetch previous scan's assets (non-excluded only)
  const prevAssets = await db.select({
    hostname: discoveredAssets.hostname,
    assetType: discoveredAssets.assetType,
    hybridRiskScore: discoveredAssets.hybridRiskScore,
    riskBand: discoveredAssets.riskBand,
    technologies: discoveredAssets.technologies,
    postureFindings: discoveredAssets.postureFindings,
    vulnRiskScore: discoveredAssets.vulnRiskScore,
    excluded: discoveredAssets.excluded,
  }).from(discoveredAssets)
    .where(and(
      eq(discoveredAssets.scanId, prevScan.id),
      eq(discoveredAssets.excluded, 0)
    ));

  return {
    previousScanId: prevScan.id,
    previousScanDate: prevScan.createdAt,
    previousRiskScore: prevScan.overallRiskScore,
    previousRiskBand: prevScan.overallRiskBand,
    previousTotalAssets: prevScan.totalAssets,
    previousTotalFindings: prevScan.totalFindings,
    previousConfirmedFindings: prevScan.confirmedFindings,
    previousExecutiveSummary: prevScan.executiveSummary,
    previousAssets: prevAssets.map(a => ({
      hostname: a.hostname,
      assetType: a.assetType,
      hybridRiskScore: a.hybridRiskScore,
      riskBand: a.riskBand,
      technologies: a.technologies,
      postureFindings: a.postureFindings,
      vulnRiskScore: a.vulnRiskScore,
      excluded: !!a.excluded,
    })),
    scanCount,
  };
}

/**
 * Build a concise historical context string for LLM injection.
 * Summarizes previous scan findings so the LLM can reference them.
 */
export function buildHistoricalContextString(ctx: HistoricalScanContext): string {
  const parts: string[] = [
    `\n--- HISTORICAL SCAN CONTEXT (previous scan from ${ctx.previousScanDate}) ---`,
    `This is scan #${ctx.scanCount} for this domain. Previous scan ID: ${ctx.previousScanId}.`,
    `Previous overall risk: ${ctx.previousRiskScore ?? 'N/A'}/100 (${ctx.previousRiskBand ?? 'N/A'})`,
    `Previous assets: ${ctx.previousTotalAssets ?? 0}, findings: ${ctx.previousTotalFindings ?? 0} (${ctx.previousConfirmedFindings ?? 0} confirmed)`,
  ];

  if (ctx.previousAssets.length > 0) {
    const highRisk = ctx.previousAssets.filter(a => (a.hybridRiskScore ?? 0) >= 60);
    const medRisk = ctx.previousAssets.filter(a => (a.hybridRiskScore ?? 0) >= 30 && (a.hybridRiskScore ?? 0) < 60);

    if (highRisk.length > 0) {
      parts.push(`High-risk assets from previous scan (${highRisk.length}):`);
      for (const a of highRisk.slice(0, 15)) {
        const techs = Array.isArray(a.technologies) ? a.technologies.slice(0, 5).join(', ') : '';
        const findings = Array.isArray(a.postureFindings) ? a.postureFindings.length : 0;
        parts.push(`  - ${a.hostname} [${a.assetType || 'unknown'}] risk=${a.hybridRiskScore}, vulnRisk=${a.vulnRiskScore ?? 'N/A'}, techs=[${techs}], findings=${findings}`);
      }
    }

    if (medRisk.length > 0) {
      parts.push(`Medium-risk assets from previous scan (${medRisk.length}): ${medRisk.slice(0, 10).map(a => `${a.hostname}(${a.hybridRiskScore})`).join(', ')}`);
    }

    // Summarize technologies seen previously
    const allTechs = new Set<string>();
    for (const a of ctx.previousAssets) {
      if (Array.isArray(a.technologies)) {
        for (const t of a.technologies) allTechs.add(typeof t === 'string' ? t : String(t));
      }
    }
    if (allTechs.size > 0) {
      parts.push(`Technologies observed in previous scan: ${[...allTechs].slice(0, 30).join(', ')}`);
    }
  }

  if (ctx.previousExecutiveSummary) {
    // Truncate to avoid overwhelming the prompt
    const summary = ctx.previousExecutiveSummary.length > 500
      ? ctx.previousExecutiveSummary.slice(0, 500) + '...'
      : ctx.previousExecutiveSummary;
    parts.push(`Previous executive summary: ${summary}`);
  }

  parts.push('--- END HISTORICAL CONTEXT ---');
  parts.push('IMPORTANT: Compare your new findings against the historical data above. Flag any NEW assets or findings not seen before, and note any risk changes (improvements or regressions).');

  return parts.join('\n');
}


// ─── Exploitation Attempts (Evidence Persistence) ────────────────────────
import { exploitationAttempts } from "../drizzle/schema";

export interface InsertExploitationAttempt {
  engagementId: number;
  targetHost: string;
  targetPort?: number;
  targetService?: string;
  vulnerabilityId?: string;
  vulnerabilityCve?: string;
  exploitSource: 'metasploit' | 'nuclei' | 'manual' | 'custom' | 'hydra' | 'netexec' | 'caldera';
  exploitModule?: string;
  exploitConfig?: any;
  eaStatus: 'queued' | 'running' | 'succeeded' | 'failed' | 'error' | 'blocked';
  resultType?: 'shell' | 'credential' | 'info_leak' | 'dos' | 'rce' | 'file_access' | 'none';
  resultOutput?: string;
  shellObtained?: number;
  eaShellType?: string;
  eaAccessLevel?: 'none' | 'user' | 'admin' | 'system' | 'root';
  eaEvidence?: any;
  eaAttackTechnique?: string;
  matchConfidence?: number;
  eaOpsecRisk?: number;
  durationMs?: number;
  eaOperatorId?: number;
  eaAttemptedAt: number;
  eaCompletedAt?: number;
  screenshotUrls?: string[];
}

export async function insertExploitationAttempt(data: InsertExploitationAttempt) {
  const db = await getDbRequired();
  const result = await db.insert(exploitationAttempts).values(data as any);
  return { id: Number(result[0].insertId) };
}

export async function getExploitationAttempts(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(exploitationAttempts)
    .where(eq(exploitationAttempts.engagementId, engagementId))
    .orderBy(desc(exploitationAttempts.eaAttemptedAt));
}

export async function getExploitationAttemptById(id: number) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(exploitationAttempts).where(eq(exploitationAttempts.id, id));
  return rows[0] || null;
}

export async function updateExploitationAttempt(id: number, updates: Partial<InsertExploitationAttempt>) {
  const db = await getDbRequired();
  await db.update(exploitationAttempts).set(updates as any).where(eq(exploitationAttempts.id, id));
}

export async function getExploitationStats(engagementId: number) {
  const db = await getDb();
  if (!db) return { total: 0, succeeded: 0, failed: 0, error: 0, withEvidence: 0 };
  const rows = await db.select().from(exploitationAttempts)
    .where(eq(exploitationAttempts.engagementId, engagementId));
  return {
    total: rows.length,
    succeeded: rows.filter(r => r.eaStatus === 'succeeded').length,
    failed: rows.filter(r => r.eaStatus === 'failed').length,
    error: rows.filter(r => r.eaStatus === 'error').length,
    withEvidence: rows.filter(r => r.eaEvidence != null).length,
  };
}


// ═══ Engagement Result Persistence ═══════════════════════════════════════════

import { engagementResults, engagementFindings } from "../drizzle/schema";

export interface EngagementResultInput {
  engagementId: number;
  operatorId?: number;
  operatorName?: string;
  engagementType?: string;
  targetDomain?: string;
  status: 'completed' | 'error' | 'partial';
  startedAt?: number;
  completedAt?: number;
  durationMs?: number;
  stats: {
    hostsScanned?: number;
    portsFound?: number;
    vulnsFound?: number;
    verifiedVulns?: number;
    unverifiedVulns?: number;
    exploitsAttempted?: number;
    exploitsSucceeded?: number;
    sessionsOpened?: number;
    zapScansRun?: number;
  };
  severityBreakdown: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
  };
  owaspCoverage?: {
    score?: number;
    totalTested?: number;
    totalPartial?: number;
    totalGaps?: number;
    criticalGaps?: string[];
  };
  autoReportId?: string;
  summaryJson?: Record<string, any>;
}

export interface EngagementFindingInput {
  engagementId: number;
  resultId?: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cve?: string;
  cwe?: string;
  description?: string;
  endpoint?: string;
  hostname?: string;
  port?: number;
  source?: string;
  tool?: string;
  corroborationTier?: 'confirmed' | 'corroborated' | 'unverified';
  rawEvidence?: string;
  screenshotPath?: string;
  exploitAttempted?: boolean;
  exploitSucceeded?: boolean;
  exploitTechnique?: string;
  owaspCategory?: string;
  mitreTechnique?: string;
  sourceType?: 'scanner' | 'llm_inference' | 'manual';
}

/**
 * Save structured engagement results to the engagement_results table.
 * Returns the inserted result ID.
 */
export async function saveEngagementResult(input: EngagementResultInput): Promise<number> {
  const db = await getDbRequired();
  const now = Date.now();
  const [result] = await db.insert(engagementResults).values({
    engagementId: input.engagementId,
    operatorId: input.operatorId,
    operatorName: input.operatorName,
    engagementType: input.engagementType,
    targetDomain: input.targetDomain,
    status: input.status,
    startedAt: input.startedAt,
    completedAt: input.completedAt,
    durationMs: input.durationMs,
    hostsScanned: input.stats.hostsScanned || 0,
    portsFound: input.stats.portsFound || 0,
    vulnsFound: input.stats.vulnsFound || 0,
    verifiedVulns: input.stats.verifiedVulns || 0,
    unverifiedVulns: input.stats.unverifiedVulns || 0,
    exploitsAttempted: input.stats.exploitsAttempted || 0,
    exploitsSucceeded: input.stats.exploitsSucceeded || 0,
    sessionsOpened: input.stats.sessionsOpened || 0,
    zapScansRun: input.stats.zapScansRun || 0,
    criticalVulns: input.severityBreakdown.critical || 0,
    highVulns: input.severityBreakdown.high || 0,
    mediumVulns: input.severityBreakdown.medium || 0,
    lowVulns: input.severityBreakdown.low || 0,
    infoVulns: input.severityBreakdown.info || 0,
    owaspCoverageScore: input.owaspCoverage?.score,
    owaspTotalTested: input.owaspCoverage?.totalTested,
    owaspTotalPartial: input.owaspCoverage?.totalPartial,
    owaspTotalGaps: input.owaspCoverage?.totalGaps,
    owaspCriticalGaps: input.owaspCoverage?.criticalGaps,
    autoReportId: input.autoReportId,
    summaryJson: input.summaryJson,
    createdAt: now,
  });
  return Number(result.insertId);
}

/**
 * Save individual findings from an engagement to the engagement_findings table.
 * Accepts an array of findings and inserts them in batch.
 */
/**
 * Auto-classify OWASP Top 10 (2021) category from finding title/description.
 * Returns the OWASP category string or undefined if no match.
 */
function autoClassifyOwasp(title: string, description?: string): string | undefined {
  const text = `${title} ${description || ''}`.toLowerCase();
  // A01:2021 – Broken Access Control
  if (/\b(idor|broken access|insecure direct|privilege escalat|path traversal|directory traversal|unauthorized access|access control|forced browsing|cors misconfigur)/.test(text)) return 'A01:2021-Broken Access Control';
  // A02:2021 – Cryptographic Failures
  if (/\b(ssl|tls|weak cipher|cleartext|unencrypted|certificate|crypto|hsts|mixed content|http without)/.test(text)) return 'A02:2021-Cryptographic Failures';
  // A03:2021 – Injection
  if (/\b(sql.?inject|xss|cross.?site.?script|command.?inject|os.?command|code.?inject|ldap.?inject|xpath|ssti|template.?inject|crlf.?inject|header.?inject|log4j|log4shell|jndi)/.test(text)) return 'A03:2021-Injection';
  // A04:2021 – Insecure Design
  if (/\b(insecure design|\bbusiness logic\b|race condition|mass assignment)/.test(text)) return 'A04:2021-Insecure Design';
  // A05:2021 – Security Misconfiguration
  if (/\b(misconfig|default credential|default password|exposed.{0,25}(config|env|debug|admin|panel|backup|git|svn|ds_store)|directory listing|stack trace|verbose error|server.?header|x-powered|phpinfo|\.env\b|\.git\b|web\.config|crossdomain\.xml|security\.txt|robots\.txt.*disallow)/.test(text)) return 'A05:2021-Security Misconfiguration';
  // A06:2021 – Vulnerable and Outdated Components
  if (/\b(outdated|vulnerable component|known vulnerabilit|cve-\d|end.?of.?life|eol|unsupported version|deprecated|version.?disclosure)/.test(text)) return 'A06:2021-Vulnerable and Outdated Components';
  // A07:2021 – Identification and Authentication Failures
  if (/\b(brute.?force|weak password|credential.?stuff|session.?fixation|session.?hijack|authentication bypass|auth bypass|missing.?auth|broken.?auth|jwt|token.?leak|password.?reset)/.test(text)) return 'A07:2021-Identification and Authentication Failures';
  // A08:2021 – Software and Data Integrity Failures
  if (/\b(deserializ|insecure deserializ|ci.?cd|pipeline|integrity|unsigned|unverified update|supply chain)/.test(text)) return 'A08:2021-Software and Data Integrity Failures';
  // A09:2021 – Security Logging and Monitoring Failures
  if (/\b(logging|monitoring|audit|insufficient log|missing log)/.test(text)) return 'A09:2021-Security Logging and Monitoring Failures';
  // A10:2021 – Server-Side Request Forgery
  if (/\b(ssrf|server.?side request forgery)/.test(text)) return 'A10:2021-Server-Side Request Forgery';
  // Broader fallback patterns
  if (/\b(information.?disclos|sensitive.?data|data.?expos|data.?leak|pii)/.test(text)) return 'A02:2021-Cryptographic Failures';
  if (/\b(open.?redirect|url.?redirect)/.test(text)) return 'A01:2021-Broken Access Control';
  return undefined;
}

export async function saveEngagementFindings(findings: EngagementFindingInput[]): Promise<number> {
  if (findings.length === 0) return 0;
  const db = await getDbRequired();
  const now = Date.now();
  let inserted = 0;

  // P1-FIX: Deduplicate findings before insert.
  // Key = engagementId + normalized title + hostname + port (severity excluded from key to merge across severity levels).
  // When duplicates exist, MERGE evidence from ALL scanners into the canonical record.
  const dedupMap = new Map<string, EngagementFindingInput>();
  const TIER_RANK: Record<string, number> = { 'confirmed': 4, 'corroborated': 3, 'single-source': 2, 'unverified': 1 };
  const SEVERITY_RANK: Record<string, number> = { 'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1 };
  const scannerEvidenceMap = new Map<string, Array<{ scanner: string; tool: string; evidence: string; corroborationTier: string }>>();

  for (const f of findings) {
    // Normalize title: strip leading [Tool Name] prefixes, @ URL suffixes, and collapse whitespace
    const normTitle = (f.title || '')
      .replace(/^\[\w+(?:\s+\w+)*\]\s*/g, '')   // strip [Nuclei], [ZAP Active], etc.
      .replace(/\s*@\s*https?:\/\/\S+/g, '')       // strip @ http://... URL suffixes
      .replace(/\s+/g, ' ').trim().toLowerCase();
    const key = `${f.engagementId}|${normTitle}|${(f.hostname || '').toLowerCase()}|${f.port || 0}`;
    const existing = dedupMap.get(key);

    // Build evidence entry for this scanner
    const scannerName = (f.tool || f.source || 'unknown').toLowerCase();
    const evidenceEntry = {
      scanner: scannerName,
      tool: f.tool || f.source || 'unknown',
      evidence: f.rawEvidence || f.description || '',
      corroborationTier: f.corroborationTier || 'unverified',
    };

    if (!existing) {
      dedupMap.set(key, f);
      scannerEvidenceMap.set(key, [evidenceEntry]);
    } else {
      // MERGE: keep the richer base record but accumulate all scanner evidence
      const existingEvidence = scannerEvidenceMap.get(key) || [];
      // Only add if this scanner hasn't already contributed identical evidence
      const alreadyHas = existingEvidence.some(e => e.scanner === scannerName && e.evidence === evidenceEntry.evidence);
      if (!alreadyHas) {
        existingEvidence.push(evidenceEntry);
        scannerEvidenceMap.set(key, existingEvidence);
      }

      // Upgrade severity to highest reported
      if ((SEVERITY_RANK[(f.severity || '').toLowerCase()] || 0) > (SEVERITY_RANK[(existing.severity || '').toLowerCase()] || 0)) {
        existing.severity = f.severity;
      }
      // Upgrade corroboration tier
      if ((TIER_RANK[f.corroborationTier || 'unverified'] || 0) > (TIER_RANK[existing.corroborationTier || 'unverified'] || 0)) {
        existing.corroborationTier = f.corroborationTier;
      }
      // Multiple scanners = at least corroborated
      if (existingEvidence.length >= 2 && (TIER_RANK[existing.corroborationTier || 'unverified'] || 0) < 3) {
        existing.corroborationTier = 'corroborated';
      }
      // Merge CVE/CWE
      if (!existing.cve && f.cve) existing.cve = f.cve;
      if (!existing.cwe && f.cwe) existing.cwe = f.cwe;
      // Keep longest description
      if (f.description && (!existing.description || f.description.length > existing.description.length)) {
        existing.description = f.description;
      }
      // Merge exploit evidence
      if (f.exploitSucceeded && !existing.exploitSucceeded) {
        existing.exploitSucceeded = f.exploitSucceeded;
        existing.exploitTechnique = f.exploitTechnique;
      }
      if (f.exploitAttempted && !existing.exploitAttempted) {
        existing.exploitAttempted = f.exploitAttempted;
      }
    }
  }

  // Build merged rawEvidence from all scanner contributions
  for (const [key, finding] of Array.from(dedupMap.entries())) {
    const evidenceEntries = scannerEvidenceMap.get(key) || [];
    if (evidenceEntries.length > 1) {
      // Combine evidence from all scanners into rawEvidence
      const combinedEvidence = evidenceEntries
        .filter(e => e.evidence)
        .map(e => `=== [${e.tool}] ===\n${e.evidence}`)
        .join('\n\n');
      if (combinedEvidence) {
        finding.rawEvidence = combinedEvidence;
      }
      // Update source/tool to reflect all contributing scanners
      const uniqueScanners = Array.from(new Set(evidenceEntries.map(e => e.tool)));
      finding.source = uniqueScanners.join('+');
    }
  }

  const dedupedFindings = Array.from(dedupMap.values());
  const dedupedCount = findings.length - dedupedFindings.length;
  if (dedupedCount > 0) {
    const mergedScanners = Array.from(scannerEvidenceMap.entries()).filter(([, v]) => v.length > 1).length;
    console.log(`[saveEngagementFindings] Deduplicated ${dedupedCount} findings (${findings.length} → ${dedupedFindings.length}), ${mergedScanners} findings have multi-scanner evidence`);
  }

  // Cross-call dedup: check existing DB findings to prevent duplicates across separate calls
  // Key matches the in-batch dedup key: engagementId + normalized title + hostname + port (no severity)
  const engIds = Array.from(new Set(dedupedFindings.map(f => f.engagementId)));
  const existingTitleKeys = new Set<string>();
  for (const eid of engIds) {
    try {
      const existing = await db.select({ title: engagementFindings.title, hostname: engagementFindings.hostname, port: engagementFindings.port })
        .from(engagementFindings)
        .where(eq(engagementFindings.engagementId, eid));
      for (const e of existing) {
        const normExisting = (e.title || '')
          .replace(/^\[\w+(?:\s+\w+)*\]\s*/g, '')
          .replace(/\s*@\s*https?:\/\/\S+/g, '')
          .replace(/\s+/g, ' ').trim().toLowerCase();
        existingTitleKeys.add(`${eid}|${normExisting}|${(e.hostname || '').toLowerCase()}|${e.port || 0}`);
      }
    } catch { /* non-fatal */ }
  }
  const newFindings = dedupedFindings.filter(f => {
    const normTitle = (f.title || '')
      .replace(/^\[\w+(?:\s+\w+)*\]\s*/g, '')
      .replace(/\s*@\s*https?:\/\/\S+/g, '')
      .replace(/\s+/g, ' ').trim().toLowerCase();
    const key = `${f.engagementId}|${normTitle}|${(f.hostname || '').toLowerCase()}|${f.port || 0}`;
    return !existingTitleKeys.has(key);
  });
  if (newFindings.length < dedupedFindings.length) {
    console.log(`[saveEngagementFindings] Cross-call dedup: ${dedupedFindings.length - newFindings.length} already in DB, inserting ${newFindings.length} new`);
  }

  // Insert in batches of 50 to avoid query size limits
  for (let i = 0; i < newFindings.length; i += 50) {
    const batch = newFindings.slice(i, i + 50);
    await db.insert(engagementFindings).values(
      batch.map(f => ({
        engagementId: f.engagementId,
        resultId: f.resultId,
        title: f.title,
        severity: f.severity,
        cve: f.cve,
        cwe: f.cwe,
        description: f.description?.slice(0, 65000),
        endpoint: f.endpoint,
        hostname: f.hostname,
        port: f.port,
        source: f.source,
        tool: f.tool,
        corroborationTier: f.corroborationTier || 'unverified',
        rawEvidence: f.rawEvidence?.slice(0, 65000),
        screenshotPath: f.screenshotPath,
        exploitAttempted: f.exploitAttempted ? 1 : 0,
        exploitSucceeded: f.exploitSucceeded ? 1 : 0,
        exploitTechnique: f.exploitTechnique,
        owaspCategory: f.owaspCategory || autoClassifyOwasp(f.title || '', f.description) || null,
        mitreTechnique: f.mitreTechnique,
        sourceType: f.sourceType || 'scanner',
        createdAt: now,
      }))
    );
    inserted += batch.length;
  }
  return inserted; // returns count of newly inserted (excludes cross-call dupes)
}

/**
 * Get engagement results by engagement ID.
 */
export async function getEngagementResult(engagementId: number) {
  const db = await getDbRequired();
  const rows = await db.select().from(engagementResults)
    .where(eq(engagementResults.engagementId, engagementId))
    .limit(1);
  return rows[0] || null;
}

/**
 * Get all findings for an engagement.
 */
export async function getEngagementFindings(engagementId: number) {
  const db = await getDbRequired();
  return db.select().from(engagementFindings)
    .where(eq(engagementFindings.engagementId, engagementId));
}


// ─── Adaptive Strategy: Graduation Score Persistence ─────────────────────────

export async function insertGraduationScore(data: {
  domain: string;
  sector?: string | null;
  scanId?: number | null;
  engagementId?: number | null;
  pipelineType?: string;
  scores: {
    recon_analyst: number;
    exploit_selector: number;
    evasion_optimizer: number;
    cognitive_core: number;
    cloud_assessor: number;
    supply_chain_analyst: number;
  };
  summary?: string | null;
}): Promise<void> {
  const database = await getDb();
  if (!database) return;
  const overall = Math.round(
    Object.values(data.scores).reduce((s, v) => s + v, 0) / Object.keys(data.scores).length
  );
  await database.insert(schema.scanGraduationScores).values({
    domain: data.domain.toLowerCase(),
    sector: data.sector || null,
    scanId: data.scanId || null,
    engagementId: data.engagementId || null,
    pipelineType: data.pipelineType || 'di_scan',
    reconAnalyst: data.scores.recon_analyst,
    exploitSelector: data.scores.exploit_selector,
    evasionOptimizer: data.scores.evasion_optimizer,
    cognitiveCore: data.scores.cognitive_core,
    cloudAssessor: data.scores.cloud_assessor,
    supplyChainAnalyst: data.scores.supply_chain_analyst,
    overallScore: overall,
    summary: data.summary || null,
  });
}

export async function getGraduationScoresForDomain(domain: string, limit = 20): Promise<Array<{
  id: number;
  domain: string;
  sector: string | null;
  scanId: number | null;
  pipelineType: string;
  reconAnalyst: number;
  exploitSelector: number;
  evasionOptimizer: number;
  cognitiveCore: number;
  cloudAssessor: number;
  supplyChainAnalyst: number;
  overallScore: number;
  createdAt: string;
}>> {
  const database = await getDb();
  if (!database) return [];
  return database.select()
    .from(schema.scanGraduationScores)
    .where(eq(schema.scanGraduationScores.domain, domain.toLowerCase()))
    .orderBy(sql`created_at DESC`)
    .limit(limit) as any;
}

export async function getGraduationScoresBySector(sector: string, limit = 100): Promise<Array<{
  id: number;
  domain: string;
  sector: string | null;
  reconAnalyst: number;
  exploitSelector: number;
  evasionOptimizer: number;
  cognitiveCore: number;
  cloudAssessor: number;
  supplyChainAnalyst: number;
  overallScore: number;
  createdAt: string;
}>> {
  const database = await getDb();
  if (!database) return [];
  return database.select()
    .from(schema.scanGraduationScores)
    .where(eq(schema.scanGraduationScores.sector, sector))
    .orderBy(sql`created_at DESC`)
    .limit(limit) as any;
}

export async function getAvgGraduationScoresBySector(sector: string): Promise<{
  recon_analyst: number;
  exploit_selector: number;
  evasion_optimizer: number;
  cognitive_core: number;
  cloud_assessor: number;
  supply_chain_analyst: number;
  overall: number;
  sampleCount: number;
} | null> {
  const database = await getDb();
  if (!database) return null;
  const rows = await database.select({
    avgRecon: sql<number>`AVG(recon_analyst)`,
    avgExploit: sql<number>`AVG(exploit_selector)`,
    avgEvasion: sql<number>`AVG(evasion_optimizer)`,
    avgCognitive: sql<number>`AVG(cognitive_core)`,
    avgCloud: sql<number>`AVG(cloud_assessor)`,
    avgSupplyChain: sql<number>`AVG(supply_chain_analyst)`,
    avgOverall: sql<number>`AVG(overall_score)`,
    cnt: sql<number>`COUNT(*)`,
  })
    .from(schema.scanGraduationScores)
    .where(eq(schema.scanGraduationScores.sector, sector));
  const r = rows[0];
  if (!r || r.cnt === 0) return null;
  return {
    recon_analyst: Math.round(r.avgRecon),
    exploit_selector: Math.round(r.avgExploit),
    evasion_optimizer: Math.round(r.avgEvasion),
    cognitive_core: Math.round(r.avgCognitive),
    cloud_assessor: Math.round(r.avgCloud),
    supply_chain_analyst: Math.round(r.avgSupplyChain),
    overall: Math.round(r.avgOverall),
    sampleCount: r.cnt,
  };
}

// ─── Adaptive Strategy: Connector Performance Persistence ────────────────────

export async function insertConnectorPerformance(data: {
  connector: string;
  domain: string;
  sector?: string | null;
  scanId: number;
  observations: number;
  durationMs: number;
  status: 'completed' | 'failed' | 'skipped' | 'timeout';
  rateLimited?: boolean;
}): Promise<void> {
  const database = await getDb();
  if (!database) return;
  await database.insert(schema.connectorPerformanceHistory).values({
    connector: data.connector,
    domain: data.domain.toLowerCase(),
    sector: data.sector || null,
    scanId: data.scanId,
    observations: data.observations,
    durationMs: data.durationMs,
    status: data.status,
    rateLimited: data.rateLimited ? 1 : 0,
  });
}

export async function bulkInsertConnectorPerformance(entries: Array<{
  connector: string;
  domain: string;
  sector?: string | null;
  scanId: number;
  observations: number;
  durationMs: number;
  status: 'completed' | 'failed' | 'skipped' | 'timeout';
  rateLimited?: boolean;
}>): Promise<void> {
  const database = await getDb();
  if (!database || entries.length === 0) return;
  const values = entries.map(e => ({
    connector: e.connector,
    domain: e.domain.toLowerCase(),
    sector: e.sector || null,
    scanId: e.scanId,
    observations: e.observations,
    durationMs: e.durationMs,
    status: e.status,
    rateLimited: e.rateLimited ? 1 : 0,
  }));
  // Batch in chunks of 50 to avoid oversized queries
  for (let i = 0; i < values.length; i += 50) {
    const chunk = values.slice(i, i + 50);
    await database.insert(schema.connectorPerformanceHistory).values(chunk);
  }
}

export async function getConnectorPerformanceForDomain(domain: string, limit = 500): Promise<Array<{
  connector: string;
  domain: string;
  sector: string | null;
  scanId: number;
  observations: number;
  durationMs: number;
  status: string;
  createdAt: string;
}>> {
  const database = await getDb();
  if (!database) return [];
  return database.select()
    .from(schema.connectorPerformanceHistory)
    .where(eq(schema.connectorPerformanceHistory.domain, domain.toLowerCase()))
    .orderBy(sql`created_at DESC`)
    .limit(limit) as any;
}

export async function getConnectorPerformanceBySector(sector: string, limit = 1000): Promise<Array<{
  connector: string;
  domain: string;
  observations: number;
  durationMs: number;
  status: string;
  createdAt: string;
}>> {
  const database = await getDb();
  if (!database) return [];
  return database.select()
    .from(schema.connectorPerformanceHistory)
    .where(eq(schema.connectorPerformanceHistory.sector, sector))
    .orderBy(sql`created_at DESC`)
    .limit(limit) as any;
}

export async function getConnectorAvgsBySector(sector: string): Promise<Array<{
  connector: string;
  avgObservations: number;
  avgDurationMs: number;
  failureRate: number;
  totalRuns: number;
}>> {
  const database = await getDb();
  if (!database) return [];
  const rows = await database.select({
    connector: schema.connectorPerformanceHistory.connector,
    avgObs: sql<number>`AVG(observations)`,
    avgDur: sql<number>`AVG(duration_ms)`,
    totalRuns: sql<number>`COUNT(*)`,
    failCount: sql<number>`SUM(CASE WHEN status IN ('failed','timeout') THEN 1 ELSE 0 END)`,
  })
    .from(schema.connectorPerformanceHistory)
    .where(eq(schema.connectorPerformanceHistory.sector, sector))
    .groupBy(schema.connectorPerformanceHistory.connector);
  return rows.map(r => ({
    connector: r.connector,
    avgObservations: Math.round(r.avgObs * 10) / 10,
    avgDurationMs: Math.round(r.avgDur),
    failureRate: r.totalRuns > 0 ? Math.round((r.failCount / r.totalRuns) * 100) / 100 : 0,
    totalRuns: r.totalRuns,
  }));
}


// ─── Zero-Day Feed DB Helpers ────────────────────────────────────────────────

import * as zdSchema from "../drizzle/schema";

export async function saveZeroDayMatches(matches: Array<{
  scanId: number;
  engagementId?: string;
  domain: string;
  cve: string;
  vendor: string;
  product: string;
  matchType: "cve_exact" | "vendor_product" | "product_fuzzy";
  confidence: "high" | "medium" | "low";
  severity: "critical" | "high" | "medium";
  matchedAsset: string;
  zeroDayDescription?: string;
  zeroDayType?: string;
  advisoryUrl?: string;
}>) {
  if (matches.length === 0) return;
  const db = await getDb();
  if (!db) return;
  const values = matches.map(m => ({
    scanId: m.scanId,
    engagementId: m.engagementId || null,
    domain: m.domain,
    cve: m.cve,
    vendor: m.vendor,
    product: m.product,
    matchType: m.matchType,
    confidence: m.confidence,
    severity: m.severity,
    matchedAsset: m.matchedAsset,
    zeroDayDescription: m.zeroDayDescription || null,
    zeroDayType: m.zeroDayType || null,
    advisoryUrl: m.advisoryUrl || null,
  }));
  for (let i = 0; i < values.length; i += 50) {
    const chunk = values.slice(i, i + 50);
    await db.insert(zdSchema.zeroDayScanMatches).values(chunk);
  }
}

export async function getZeroDayMatchesByScan(scanId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(zdSchema.zeroDayScanMatches)
    .where(eq(zdSchema.zeroDayScanMatches.scanId, scanId))
    .orderBy(zdSchema.zeroDayScanMatches.severity);
}

export async function getZeroDayMatchesByDomain(domain: string, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(zdSchema.zeroDayScanMatches)
    .where(eq(zdSchema.zeroDayScanMatches.domain, domain))
    .orderBy(desc(zdSchema.zeroDayScanMatches.createdAt))
    .limit(limit);
}

export async function getZeroDayMatchesByEngagement(engagementId: string) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(zdSchema.zeroDayScanMatches)
    .where(eq(zdSchema.zeroDayScanMatches.engagementId, engagementId))
    .orderBy(zdSchema.zeroDayScanMatches.severity);
}

export async function getRecentZeroDayMatches(limit = 100) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(zdSchema.zeroDayScanMatches)
    .where(eq(zdSchema.zeroDayScanMatches.dismissed, 0))
    .orderBy(desc(zdSchema.zeroDayScanMatches.createdAt))
    .limit(limit);
}

export async function dismissZeroDayMatch(matchId: number) {
  const db = await getDb();
  if (!db) return;
  return db
    .update(zdSchema.zeroDayScanMatches)
    .set({ dismissed: 1 })
    .where(eq(zdSchema.zeroDayScanMatches.id, matchId));
}

export async function getZeroDayMatchStats() {
  const db = await getDb();
  if (!db) return { total: 0, critical: 0, high: 0, undismissed: 0 };
  const [total] = await db.select({ count: sql<number>`count(*)` }).from(zdSchema.zeroDayScanMatches);
  const [critical] = await db.select({ count: sql<number>`count(*)` }).from(zdSchema.zeroDayScanMatches).where(eq(zdSchema.zeroDayScanMatches.severity, "critical"));
  const [high] = await db.select({ count: sql<number>`count(*)` }).from(zdSchema.zeroDayScanMatches).where(eq(zdSchema.zeroDayScanMatches.severity, "high"));
  const [undismissed] = await db.select({ count: sql<number>`count(*)` }).from(zdSchema.zeroDayScanMatches).where(eq(zdSchema.zeroDayScanMatches.dismissed, 0));
  return {
    total: total?.count || 0,
    critical: critical?.count || 0,
    high: high?.count || 0,
    undismissed: undismissed?.count || 0,
  };
}


// ─── DI Incident Training Data Helpers ──────────────────────────────────────

import { diIncidentTrainingData } from "../drizzle/schema";

export async function insertDITrainingExample(data: {
  exampleId: string;
  scanId: number;
  domain: string;
  sector?: string;
  exampleType: 'incident_context' | 'actor_attribution' | 'breach_pattern' | 'ransomware_profile' | 'attack_surface_map';
  trainingMessages: any;
  qualityScore: number;
  qualityBand: 'high' | 'medium' | 'low' | 'rejected';
  incidentCount?: number;
  actorsDiscovered?: number;
  ttpsDiscovered?: number;
  riskScoreAtScan?: number;
  riskBandAtScan?: string;
}) {
  const db = await getDb();
  if (!db) return;
  await db.insert(diIncidentTrainingData).values(data);
}

export async function bulkInsertDITrainingExamples(examples: Array<{
  exampleId: string;
  scanId: number;
  domain: string;
  sector?: string;
  exampleType: 'incident_context' | 'actor_attribution' | 'breach_pattern' | 'ransomware_profile' | 'attack_surface_map';
  trainingMessages: any;
  qualityScore: number;
  qualityBand: 'high' | 'medium' | 'low' | 'rejected';
  incidentCount?: number;
  actorsDiscovered?: number;
  ttpsDiscovered?: number;
  riskScoreAtScan?: number;
  riskBandAtScan?: string;
}>) {
  if (examples.length === 0) return;
  const db = await getDb();
  if (!db) return;
  // Batch insert in chunks of 10
  for (let i = 0; i < examples.length; i += 10) {
    const batch = examples.slice(i, i + 10);
    await db.insert(diIncidentTrainingData).values(batch);
  }
}

export async function getDITrainingExamplesForDomain(domain: string, limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(diIncidentTrainingData)
    .where(eq(diIncidentTrainingData.domain, domain))
    .orderBy(desc(diIncidentTrainingData.qualityScore))
    .limit(limit);
}

export async function getDITrainingExamplesForSector(sector: string, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(diIncidentTrainingData)
    .where(eq(diIncidentTrainingData.sector, sector))
    .orderBy(desc(diIncidentTrainingData.qualityScore))
    .limit(limit);
}

export async function getHighQualityDITrainingExamples(limit = 100) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(diIncidentTrainingData)
    .where(eq(diIncidentTrainingData.qualityBand, 'high'))
    .orderBy(desc(diIncidentTrainingData.qualityScore))
    .limit(limit);
}

export async function updateDITrainingAnalystRating(exampleId: string, rating: 'accurate' | 'partially_accurate' | 'inaccurate', analystId: number, notes?: string) {
  const db = await getDb();
  if (!db) return;
  await db.update(diIncidentTrainingData)
    .set({
      analystRating: rating,
      analystId,
      analystNotes: notes || null,
      ratedAt: Date.now(),
      // Adjust quality based on analyst feedback
      qualityScore: rating === 'accurate' ? 0.95 : rating === 'partially_accurate' ? 0.6 : 0.1,
      qualityBand: rating === 'accurate' ? 'high' : rating === 'partially_accurate' ? 'medium' : 'rejected',
    })
    .where(eq(diIncidentTrainingData.exampleId, exampleId));
}

export async function incrementDITrainingUsage(exampleIds: string[]) {
  if (exampleIds.length === 0) return;
  const db = await getDb();
  if (!db) return;
  for (const eid of exampleIds) {
    await db.update(diIncidentTrainingData)
      .set({
        usedInPromptCount: sql`${diIncidentTrainingData.usedInPromptCount} + 1`,
        lastUsedAt: Date.now(),
      })
      .where(eq(diIncidentTrainingData.exampleId, eid));
  }
}

export async function getDITrainingStats() {
  const db = await getDb();
  if (!db) return { total: 0, high: 0, medium: 0, low: 0, rejected: 0, reviewed: 0, unreviewed: 0 };
  const [total] = await db.select({ count: sql<number>`count(*)` }).from(diIncidentTrainingData);
  const [high] = await db.select({ count: sql<number>`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, 'high'));
  const [medium] = await db.select({ count: sql<number>`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, 'medium'));
  const [low] = await db.select({ count: sql<number>`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, 'low'));
  const [rejected] = await db.select({ count: sql<number>`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, 'rejected'));
  const [reviewed] = await db.select({ count: sql<number>`count(*)` }).from(diIncidentTrainingData).where(sql`${diIncidentTrainingData.analystRating} != 'not_reviewed'`);
  return {
    total: total?.count || 0,
    high: high?.count || 0,
    medium: medium?.count || 0,
    low: low?.count || 0,
    rejected: rejected?.count || 0,
    reviewed: reviewed?.count || 0,
    unreviewed: (total?.count || 0) - (reviewed?.count || 0),
  };
}

// ─── Burp Suite Scan History ───
import { burpScanHistory } from "../drizzle/schema";

export async function createBurpScanRecord(record: {
  engagementId: number;
  credentialId: number;
  userId: string;
  scanId?: string;
  edition: string;
  status: string;
  targetUrls: string[];
  scanConfigName?: string;
  startedAt: number;
}) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const [result] = await db.insert(burpScanHistory).values({
    engagementId: record.engagementId,
    credentialId: record.credentialId,
    userId: record.userId,
    scanId: record.scanId || null,
    edition: record.edition,
    status: record.status,
    targetUrls: record.targetUrls,
    scanConfigName: record.scanConfigName || null,
    startedAt: record.startedAt,
  });
  return result.insertId;
}

export async function updateBurpScanRecord(id: number, updates: {
  scanId?: string;
  status?: string;
  progress?: number;
  issueCount?: number;
  importedCount?: number;
  error?: string | null;
  completedAt?: number | null;
  lastPollAt?: number | null;
  pollCount?: number;
  metadata?: any;
}) {
  const db = await getDb();
  if (!db) return;
  await db.update(burpScanHistory).set(updates).where(eq(burpScanHistory.id, id));
}

export async function getBurpScansByEngagement(engagementId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(burpScanHistory)
    .where(eq(burpScanHistory.engagementId, engagementId))
    .orderBy(desc(burpScanHistory.startedAt));
}

export async function getBurpScansByUser(userId: string) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(burpScanHistory)
    .where(eq(burpScanHistory.userId, userId))
    .orderBy(desc(burpScanHistory.startedAt));
}

export async function getDbBurpScanStats() {
  const db = await getDb();
  if (!db) return { total: 0, active: 0, completed: 0, failed: 0, totalIssues: 0, totalImported: 0 };
  const [total] = await db.select({ count: sql<number>`count(*)` }).from(burpScanHistory);
  const [active] = await db.select({ count: sql<number>`count(*)` }).from(burpScanHistory).where(sql`${burpScanHistory.status} IN ('pending','launching','running','polling','importing')`);
  const [completed] = await db.select({ count: sql<number>`count(*)` }).from(burpScanHistory).where(eq(burpScanHistory.status, "completed"));
  const [failed] = await db.select({ count: sql<number>`count(*)` }).from(burpScanHistory).where(eq(burpScanHistory.status, "failed"));
  const [issues] = await db.select({ sum: sql<number>`COALESCE(SUM(issue_count), 0)` }).from(burpScanHistory);
  const [imported] = await db.select({ sum: sql<number>`COALESCE(SUM(imported_count), 0)` }).from(burpScanHistory);
  return {
    total: total?.count || 0,
    active: active?.count || 0,
    completed: completed?.count || 0,
    failed: failed?.count || 0,
    totalIssues: issues?.sum || 0,
    totalImported: imported?.sum || 0,
  };
}


// ─── Engagement Timeline Events ─────────────────────────────────────────────

/**
 * Add a timeline event to an engagement.
 * Used by burp-auto-scan, zap-burp-pipeline, and other modules that need
 * to log structured events to the engagement timeline.
 */
export async function addTimelineEvent(params: {
  engagementId: number;
  eventType: 'phase_started' | 'phase_completed' | 'finding_discovered' | 'exploit_attempted' |
    'exploit_succeeded' | 'shell_obtained' | 'credential_found' | 'pivot_established' |
    'data_collected' | 'data_exfiltrated' | 'opsec_alert' | 'note_added' |
    'handoff_triggered' | 'objective_completed' | 'tool_executed' | 'scan_completed';
  title: string;
  description?: string;
  metadata?: Record<string, any>;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  phase?: string;
  sourceModule?: string;
  sourceId?: string;
  targetHost?: string;
  targetPort?: number;
  attackTechnique?: string;
  userId?: string;
}): Promise<number> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const { engagementTimelineEvents } = await import("../drizzle/schema");
  const result = await db.insert(engagementTimelineEvents).values({
    engagementId: params.engagementId,
    phase: params.phase || "vulnerability_analysis",
    eventType: params.eventType,
    severity: params.severity || "info",
    title: params.title,
    description: params.description,
    metadata: params.metadata ? JSON.stringify(params.metadata) : null,
    sourceModule: params.sourceModule || "burp-auto-scan",
    timestamp: Date.now(),
  });

  return (result as any)[0]?.insertId || 0;
}

/**
 * Get recent timeline events for an engagement.
 */
export async function getTimelineEvents(engagementId: number, limit = 50) {
  const db = await getDb();
  if (!db) return [];

  const { engagementTimelineEvents } = await import("../drizzle/schema");
  const { eq, desc } = await import("drizzle-orm");
  return db.select().from(engagementTimelineEvents)
    .where(eq(engagementTimelineEvents.engagementId, engagementId))
    .orderBy(desc(engagementTimelineEvents.timestamp))
    .limit(limit);
}


/**
 * Create a bug bounty finding from automated scanners (Burp Suite, ZAP, etc.).
 * Maps scanner output fields to the bugBountyFindings table columns.
 * Fields not in the schema (userId, state, metadata) are mapped to
 * the closest available columns (reporterUsername, substate, summary appendix).
 */
export async function createBugBountyFinding(params: {
  title: string;
  severityRating: string;
  summary: string;
  assetIdentifier: string;
  assetType: string;
  cweId: string | null;
  platform: string;
  programHandle: string;
  state?: string;
  userId?: string;
  metadata?: Record<string, any>;
}): Promise<{ id: number; deduplicated: boolean }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  const { bugBountyFindings } = await import("../drizzle/schema");
  const { and, eq } = await import("drizzle-orm");

  // ─── Deduplication check: same title + assetIdentifier + platform = duplicate ───
  const normalizedTitle = params.title.substring(0, 1024).trim();
  const normalizedAsset = (params.assetIdentifier || "").trim();
  const normalizedPlatform = (params.platform || "manual").trim();

  try {
    const existing = await db.select({ id: bugBountyFindings.id, severityRating: bugBountyFindings.severityRating })
      .from(bugBountyFindings)
      .where(
        and(
          eq(bugBountyFindings.title, normalizedTitle),
          eq(bugBountyFindings.assetIdentifier, normalizedAsset),
          eq(bugBountyFindings.platform, normalizedPlatform)
        )
      )
      .limit(1);

    if (existing.length > 0) {
      const existingId = existing[0].id;
      const existingSeverity = existing[0].severityRating || "info";
      const newSeverity = params.severityRating || "low";

      // Severity promotion: if re-scan found higher severity, upgrade the existing finding
      const severityRank: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if ((severityRank[newSeverity] || 0) > (severityRank[existingSeverity] || 0)) {
        await db.update(bugBountyFindings)
          .set({ severityRating: newSeverity })
          .where(eq(bugBountyFindings.id, existingId));
        console.log(`[BugBountyDedup] Promoted finding #${existingId} severity: ${existingSeverity} → ${newSeverity} ("${normalizedTitle}" on ${normalizedAsset})`);
      } else {
        console.log(`[BugBountyDedup] Skipped duplicate: "${normalizedTitle}" on ${normalizedAsset} (existing #${existingId})`);
      }

      return { id: existingId, deduplicated: true };
    }
  } catch (dedupErr: any) {
    // If dedup check fails (e.g., table doesn't exist yet), proceed with insert
    console.warn(`[BugBountyDedup] Dedup check failed, proceeding with insert: ${dedupErr.message}`);
  }

  // ─── New finding: build summary with metadata appendix ───
  let fullSummary = params.summary || "";
  if (params.metadata) {
    const metaLines: string[] = [];
    if (params.metadata.burpIssueType) metaLines.push(`Burp Issue Type: ${params.metadata.burpIssueType}`);
    if (params.metadata.confidence) metaLines.push(`Confidence: ${params.metadata.confidence}`);
    if (params.metadata.path) metaLines.push(`Path: ${params.metadata.path}`);
    if (params.metadata.source) metaLines.push(`Source: ${params.metadata.source}`);
    if (params.metadata.remediation) metaLines.push(`Remediation: ${params.metadata.remediation}`);
    if (params.metadata.issueBackground) metaLines.push(`Background: ${params.metadata.issueBackground}`);
    if (metaLines.length > 0) {
      fullSummary += `\n\n--- Scanner Metadata ---\n${metaLines.join("\n")}`;
    }
  }

  const result = await db.insert(bugBountyFindings).values({
    title: normalizedTitle,
    severityRating: params.severityRating || "low",
    platform: normalizedPlatform,
    programHandle: params.programHandle || null,
    assetIdentifier: normalizedAsset || null,
    assetType: params.assetType || null,
    cweId: params.cweId || null,
    summary: fullSummary || null,
    substate: params.state || "new",
    reporterUsername: params.userId ? `auto:${params.userId}` : "auto:scanner",
    externalId: `burp-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
  });

  const insertId = (result as any)[0]?.insertId || 0;
  return { id: insertId, deduplicated: false };
}


// ─── Exploit Learning Engine Persistence ────────────────────────────────────

/**
 * Insert an exploit attempt outcome into the database.
 */
export async function insertExploitOutcome(data: {
  attemptId: string;
  engagementId: number;
  vulnTitle: string;
  vulnCve?: string;
  vulnSeverity: string;
  vulnClass: string;
  targetHostname: string;
  targetPort?: number;
  targetTechnologies: string[];
  language: string;
  code: string;
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  guardrailPassed?: boolean;
  guardrailRiskScore?: number;
  guardrailBlockedReasons?: string[];
  falsePositive?: boolean;
  falsePositiveReasons?: string[];
  executionTimeMs: number;
  attemptNumber: number;
  previousAttemptIds: string[];
  correctionApplied?: string;
}): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  try {
    const result = await db.insert(exploitLearningOutcomes).values({
      attemptId: data.attemptId,
      engagementId: data.engagementId,
      vulnTitle: data.vulnTitle.slice(0, 512),
      vulnCve: data.vulnCve || null,
      vulnSeverity: data.vulnSeverity,
      vulnClass: data.vulnClass,
      targetHostname: data.targetHostname,
      targetPort: data.targetPort || null,
      targetTechnologies: data.targetTechnologies,
      language: data.language,
      code: data.code,
      success: data.success ? 1 : 0,
      exitCode: data.exitCode,
      stdout: (data.stdout || '').slice(0, 50000),
      stderr: (data.stderr || '').slice(0, 50000),
      guardrailPassed: data.guardrailPassed != null ? (data.guardrailPassed ? 1 : 0) : null,
      guardrailRiskScore: data.guardrailRiskScore ?? null,
      guardrailBlockedReasons: data.guardrailBlockedReasons || null,
      falsePositive: data.falsePositive ? 1 : 0,
      falsePositiveReasons: data.falsePositiveReasons || null,
      executionTimeMs: data.executionTimeMs,
      attemptNumber: data.attemptNumber,
      previousAttemptIds: data.previousAttemptIds,
      correctionApplied: data.correctionApplied || null,
    });
    return (result as any)[0]?.insertId || 0;
  } catch (err: any) {
    console.error(`[DB] insertExploitOutcome failed: ${err.message}`);
    return 0;
  }
}

/**
 * Upsert an exploit pattern (insert or update if pattern_key already exists).
 */
export async function upsertExploitPattern(data: {
  patternKey: string;
  vulnClass: string;
  techStack: string[];
  successfulApproaches: any[];
  failedApproaches: any[];
  knownChainIds?: number[];
  totalSuccesses: number;
  totalFailures: number;
  successRate: number;
  updatedAt: number;
}): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  try {
    const { eq } = await import('drizzle-orm');
    // Check if pattern exists
    const existing = await db.select({ id: exploitLearningPatterns.id })
      .from(exploitLearningPatterns)
      .where(eq(exploitLearningPatterns.patternKey, data.patternKey))
      .limit(1);

    if (existing.length > 0) {
      await db.update(exploitLearningPatterns)
        .set({
          successfulApproaches: data.successfulApproaches,
          failedApproaches: data.failedApproaches,
          knownChainIds: data.knownChainIds || null,
          totalSuccesses: data.totalSuccesses,
          totalFailures: data.totalFailures,
          successRate: data.successRate,
          updatedAt: data.updatedAt,
        })
        .where(eq(exploitLearningPatterns.patternKey, data.patternKey));
      return existing[0].id;
    } else {
      const result = await db.insert(exploitLearningPatterns).values({
        patternKey: data.patternKey,
        vulnClass: data.vulnClass,
        techStack: data.techStack,
        successfulApproaches: data.successfulApproaches,
        failedApproaches: data.failedApproaches,
        knownChainIds: data.knownChainIds || null,
        totalSuccesses: data.totalSuccesses,
        totalFailures: data.totalFailures,
        successRate: data.successRate,
        updatedAt: data.updatedAt,
      });
      return (result as any)[0]?.insertId || 0;
    }
  } catch (err: any) {
    console.error(`[DB] upsertExploitPattern failed: ${err.message}`);
    return 0;
  }
}

/**
 * Load all exploit patterns from the database.
 */
export async function loadAllExploitPatterns(): Promise<Array<{
  id: number;
  patternKey: string;
  vulnClass: string;
  techStack: string[];
  successfulApproaches: any[];
  failedApproaches: any[];
  knownChainIds: number[] | null;
  totalSuccesses: number;
  totalFailures: number;
  successRate: number;
  updatedAt: number;
}>> {
  const db = await getDb();
  if (!db) return [];
  try {
    const rows = await db.select().from(exploitLearningPatterns);
    return rows.map(r => ({
      id: r.id,
      patternKey: r.patternKey,
      vulnClass: r.vulnClass,
      techStack: (r.techStack as string[]) || [],
      successfulApproaches: (r.successfulApproaches as any[]) || [],
      failedApproaches: (r.failedApproaches as any[]) || [],
      knownChainIds: (r.knownChainIds as number[] | null),
      totalSuccesses: r.totalSuccesses,
      totalFailures: r.totalFailures,
      successRate: r.successRate,
      updatedAt: r.updatedAt,
    }));
  } catch (err: any) {
    console.error(`[DB] loadAllExploitPatterns failed: ${err.message}`);
    return [];
  }
}

/**
 * Insert an exploit chain into the database.
 * Returns the chain ID. If a chain with the same name already exists, returns its ID.
 */
export async function upsertExploitChain(data: {
  chainName: string;
  steps: any[];
  successRate: number;
  discoveredFrom: string;
  mitreTechniques?: string[];
  engagementId?: number;
  targetHostname?: string;
}): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  try {
    const { eq } = await import('drizzle-orm');
    const existing = await db.select({ id: exploitLearningChains.id })
      .from(exploitLearningChains)
      .where(eq(exploitLearningChains.chainName, data.chainName))
      .limit(1);

    if (existing.length > 0) {
      await db.update(exploitLearningChains)
        .set({
          steps: data.steps,
          successRate: data.successRate,
          mitreTechniques: data.mitreTechniques || null,
          timesUsed: sql`times_used + 1`,
          lastUsedAt: Date.now(),
        })
        .where(eq(exploitLearningChains.chainName, data.chainName));
      return existing[0].id;
    } else {
      const result = await db.insert(exploitLearningChains).values({
        chainName: data.chainName,
        steps: data.steps,
        successRate: data.successRate,
        discoveredFrom: data.discoveredFrom,
        mitreTechniques: data.mitreTechniques || null,
        engagementId: data.engagementId || null,
        targetHostname: data.targetHostname || null,
        timesUsed: 1,
        lastUsedAt: Date.now(),
      });
      return (result as any)[0]?.insertId || 0;
    }
  } catch (err: any) {
    console.error(`[DB] upsertExploitChain failed: ${err.message}`);
    return 0;
  }
}

/**
 * Load all exploit chains from the database.
 */
export async function loadAllExploitChains(): Promise<Array<{
  id: number;
  chainName: string;
  steps: any[];
  successRate: number;
  discoveredFrom: string;
  mitreTechniques: string[];
  engagementId: number | null;
  targetHostname: string | null;
  timesUsed: number;
  lastUsedAt: number | null;
}>> {
  const db = await getDb();
  if (!db) return [];
  try {
    const rows = await db.select().from(exploitLearningChains);
    return rows.map(r => ({
      id: r.id,
      chainName: r.chainName,
      steps: (r.steps as any[]) || [],
      successRate: r.successRate,
      discoveredFrom: r.discoveredFrom,
      mitreTechniques: (r.mitreTechniques as string[]) || [],
      engagementId: r.engagementId,
      targetHostname: r.targetHostname,
      timesUsed: r.timesUsed,
      lastUsedAt: r.lastUsedAt,
    }));
  } catch (err: any) {
    console.error(`[DB] loadAllExploitChains failed: ${err.message}`);
    return [];
  }
}

/**
 * Load recent exploit outcomes for a specific vuln class or engagement.
 */
export async function loadRecentExploitOutcomes(opts: {
  vulnClass?: string;
  engagementId?: number;
  limit?: number;
}): Promise<Array<{
  id: number;
  attemptId: string;
  engagementId: number;
  vulnTitle: string;
  vulnCve: string | null;
  vulnSeverity: string;
  vulnClass: string;
  targetHostname: string;
  success: boolean;
  exitCode: number;
  executionTimeMs: number;
  attemptNumber: number;
  guardrailPassed: boolean | null;
  guardrailRiskScore: number | null;
  falsePositive: boolean;
  createdAt: string;
}>> {
  const db = await getDb();
  if (!db) return [];
  try {
    const { eq, desc, and } = await import('drizzle-orm');
    const conditions = [];
    if (opts.vulnClass) conditions.push(eq(exploitLearningOutcomes.vulnClass, opts.vulnClass));
    if (opts.engagementId) conditions.push(eq(exploitLearningOutcomes.engagementId, opts.engagementId));

    const query = db.select({
      id: exploitLearningOutcomes.id,
      attemptId: exploitLearningOutcomes.attemptId,
      engagementId: exploitLearningOutcomes.engagementId,
      vulnTitle: exploitLearningOutcomes.vulnTitle,
      vulnCve: exploitLearningOutcomes.vulnCve,
      vulnSeverity: exploitLearningOutcomes.vulnSeverity,
      vulnClass: exploitLearningOutcomes.vulnClass,
      targetHostname: exploitLearningOutcomes.targetHostname,
      success: exploitLearningOutcomes.success,
      exitCode: exploitLearningOutcomes.exitCode,
      executionTimeMs: exploitLearningOutcomes.executionTimeMs,
      attemptNumber: exploitLearningOutcomes.attemptNumber,
      guardrailPassed: exploitLearningOutcomes.guardrailPassed,
      guardrailRiskScore: exploitLearningOutcomes.guardrailRiskScore,
      falsePositive: exploitLearningOutcomes.falsePositive,
      createdAt: exploitLearningOutcomes.createdAt,
    })
      .from(exploitLearningOutcomes)
      .orderBy(desc(exploitLearningOutcomes.id))
      .limit(opts.limit || 100);

    if (conditions.length > 0) {
      (query as any).where(conditions.length === 1 ? conditions[0] : and(...conditions));
    }

    const rows = await query;
    return rows.map(r => ({
      ...r,
      success: !!r.success,
      guardrailPassed: r.guardrailPassed != null ? !!r.guardrailPassed : null,
      falsePositive: !!r.falsePositive,
    }));
  } catch (err: any) {
    console.error(`[DB] loadRecentExploitOutcomes failed: ${err.message}`);
    return [];
  }
}

/**
 * Get aggregate learning stats from the database.
 */
export async function getExploitLearningDbStats(): Promise<{
  totalOutcomes: number;
  totalSuccesses: number;
  totalFailures: number;
  patternsStored: number;
  chainsStored: number;
  successRate: number;
}> {
  const db = await getDb();
  if (!db) return { totalOutcomes: 0, totalSuccesses: 0, totalFailures: 0, patternsStored: 0, chainsStored: 0, successRate: 0 };
  try {
    const { sql: sqlTag } = await import('drizzle-orm');
    const [outcomeStats] = await db.select({
      total: sqlTag<number>`COUNT(*)`,
      successes: sqlTag<number>`SUM(CASE WHEN success = 1 AND (false_positive = 0 OR false_positive IS NULL) THEN 1 ELSE 0 END)`,
    }).from(exploitLearningOutcomes);

    const [patternCount] = await db.select({
      count: sqlTag<number>`COUNT(*)`,
    }).from(exploitLearningPatterns);

    const [chainCount] = await db.select({
      count: sqlTag<number>`COUNT(*)`,
    }).from(exploitLearningChains);

    const total = Number(outcomeStats?.total || 0);
    const successes = Number(outcomeStats?.successes || 0);

    return {
      totalOutcomes: total,
      totalSuccesses: successes,
      totalFailures: total - successes,
      patternsStored: Number(patternCount?.count || 0),
      chainsStored: Number(chainCount?.count || 0),
      successRate: total > 0 ? successes / total : 0,
    };
  } catch (err: any) {
    console.error(`[DB] getExploitLearningDbStats failed: ${err.message}`);
    return { totalOutcomes: 0, totalSuccesses: 0, totalFailures: 0, patternsStored: 0, chainsStored: 0, successRate: 0 };
  }
}


// ═══════════════════════════════════════════════════════════════════════
// §INTEGRATION REGISTRY — DB-backed persistence
// ═══════════════════════════════════════════════════════════════════════

export type InsertCustomerIntegration = typeof customerIntegrations.$inferInsert;
export type SelectCustomerIntegration = typeof customerIntegrations.$inferSelect;

export async function createCustomerIntegration(data: InsertCustomerIntegration): Promise<number> {
  const db = await getDbRequired();
  const [result] = await db.insert(customerIntegrations).values(data);
  return (result as any).insertId;
}

export async function getCustomerIntegrationByIntegrationId(integrationId: string): Promise<SelectCustomerIntegration | undefined> {
  const db = await getDbRequired();
  const rows = await db.select().from(customerIntegrations).where(eq(customerIntegrations.integrationId, integrationId)).limit(1);
  return rows[0];
}

export async function getAllCustomerIntegrations(): Promise<SelectCustomerIntegration[]> {
  const db = await getDbRequired();
  return db.select().from(customerIntegrations).orderBy(desc(customerIntegrations.createdAt));
}

export async function getCustomerIntegrationsByCategory(category: string): Promise<SelectCustomerIntegration[]> {
  const db = await getDbRequired();
  return db.select().from(customerIntegrations).where(eq(customerIntegrations.category, category as any));
}

export async function getCustomerIntegrationsByStatus(status: string): Promise<SelectCustomerIntegration[]> {
  const db = await getDbRequired();
  return db.select().from(customerIntegrations).where(eq(customerIntegrations.status, status as any));
}

export async function getActiveCustomerIntegrationsByStage(stage: string): Promise<SelectCustomerIntegration[]> {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  return db.select().from(customerIntegrations)
    .where(and(
      eq(customerIntegrations.status, "active"),
      sqlTag`JSON_CONTAINS(${customerIntegrations.pipelineStages}, JSON_QUOTE(${stage}))`
    ));
}

export async function updateCustomerIntegration(integrationId: string, updates: Partial<InsertCustomerIntegration>): Promise<void> {
  const db = await getDbRequired();
  await db.update(customerIntegrations).set({ ...updates, updatedAt: Date.now() }).where(eq(customerIntegrations.integrationId, integrationId));
}

export async function deleteCustomerIntegration(integrationId: string): Promise<void> {
  const db = await getDbRequired();
  await db.delete(customerIntegrations).where(eq(customerIntegrations.integrationId, integrationId));
}

export async function getCustomerIntegrationStats(): Promise<{
  total: number; active: number; proposed: number; paused: number; error: number;
}> {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  const [stats] = await db.select({
    total: sqlTag<number>`COUNT(*)`,
    active: sqlTag<number>`SUM(CASE WHEN ${customerIntegrations.status} = 'active' THEN 1 ELSE 0 END)`,
    proposed: sqlTag<number>`SUM(CASE WHEN ${customerIntegrations.status} = 'proposed' THEN 1 ELSE 0 END)`,
    paused: sqlTag<number>`SUM(CASE WHEN ${customerIntegrations.status} = 'paused' THEN 1 ELSE 0 END)`,
    error: sqlTag<number>`SUM(CASE WHEN ${customerIntegrations.status} = 'error' THEN 1 ELSE 0 END)`,
  }).from(customerIntegrations);
  return {
    total: Number(stats?.total ?? 0),
    active: Number(stats?.active ?? 0),
    proposed: Number(stats?.proposed ?? 0),
    paused: Number(stats?.paused ?? 0),
    error: Number(stats?.error ?? 0),
  };
}

// ─── Health Checks ──────────────────────────────────────────────────

export type InsertHealthCheck = typeof integrationHealthChecks.$inferInsert;
export type SelectHealthCheck = typeof integrationHealthChecks.$inferSelect;

export async function createHealthCheck(data: InsertHealthCheck): Promise<number> {
  const db = await getDbRequired();
  const [result] = await db.insert(integrationHealthChecks).values(data);
  return (result as any).insertId;
}

export async function getRecentHealthChecks(integrationId: string, limit = 20): Promise<SelectHealthCheck[]> {
  const db = await getDbRequired();
  return db.select().from(integrationHealthChecks)
    .where(eq(integrationHealthChecks.integrationId, integrationId))
    .orderBy(desc(integrationHealthChecks.checkedAt))
    .limit(limit);
}

export async function getLatestHealthCheckPerIntegration(): Promise<SelectHealthCheck[]> {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  // Get the latest health check for each integration
  return db.select().from(integrationHealthChecks)
    .where(sqlTag`${integrationHealthChecks.id} IN (
      SELECT MAX(id) FROM integration_health_checks GROUP BY integration_id
    )`)
    .orderBy(desc(integrationHealthChecks.checkedAt));
}

export async function getHealthCheckHistory(integrationId: string, hoursBack = 24): Promise<SelectHealthCheck[]> {
  const db = await getDbRequired();
  const { gte } = await import("drizzle-orm");
  const cutoff = Date.now() - hoursBack * 60 * 60 * 1000;
  return db.select().from(integrationHealthChecks)
    .where(and(
      eq(integrationHealthChecks.integrationId, integrationId),
      gte(integrationHealthChecks.checkedAt, cutoff)
    ))
    .orderBy(desc(integrationHealthChecks.checkedAt));
}

// ─── Execution Logs ─────────────────────────────────────────────────

export type InsertExecutionLog = typeof integrationExecutionLog.$inferInsert;
export type SelectExecutionLog = typeof integrationExecutionLog.$inferSelect;

export async function createExecutionLog(data: InsertExecutionLog): Promise<number> {
  const db = await getDbRequired();
  const [result] = await db.insert(integrationExecutionLog).values(data);
  return (result as any).insertId;
}

export async function getExecutionLogsByIntegration(integrationId: string, limit = 50): Promise<SelectExecutionLog[]> {
  const db = await getDbRequired();
  return db.select().from(integrationExecutionLog)
    .where(eq(integrationExecutionLog.integrationId, integrationId))
    .orderBy(desc(integrationExecutionLog.executedAt))
    .limit(limit);
}

export async function getExecutionLogsByEngagement(engagementId: number): Promise<SelectExecutionLog[]> {
  const db = await getDbRequired();
  return db.select().from(integrationExecutionLog)
    .where(eq(integrationExecutionLog.engagementId, engagementId))
    .orderBy(desc(integrationExecutionLog.executedAt));
}

// ─── Deployment History ─────────────────────────────────────────────
export type InsertDeploymentHistory = typeof deploymentHistory.$inferInsert;
export type SelectDeploymentHistory = typeof deploymentHistory.$inferSelect;

export async function createDeployment(data: InsertDeploymentHistory): Promise<number> {
  const db = await getDbRequired();
  const [result] = await db.insert(deploymentHistory).values(data);
  return (result as any).insertId;
}

export async function listDeployments(opts?: { environment?: string; limit?: number }): Promise<SelectDeploymentHistory[]> {
  const db = await getDbRequired();
  const conditions = [];
  if (opts?.environment) {
    conditions.push(eq(deploymentHistory.environment, opts.environment as any));
  }
  return db.select().from(deploymentHistory)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(deploymentHistory.createdAt))
    .limit(opts?.limit ?? 50);
}

export async function getDeploymentById(deploymentId: string): Promise<SelectDeploymentHistory | undefined> {
  const db = await getDbRequired();
  const [row] = await db.select().from(deploymentHistory)
    .where(eq(deploymentHistory.deploymentId, deploymentId))
    .limit(1);
  return row;
}

export async function updateDeploymentStatus(deploymentId: string, status: string, errorMessage?: string): Promise<void> {
  const db = await getDbRequired();
  const updates: any = { status, updatedAt: new Date().toISOString() };
  if (status === 'success' || status === 'failed' || status === 'rolled_back') {
    updates.completedAt = new Date().toISOString();
  }
  if (errorMessage) updates.errorMessage = errorMessage;
  await db.update(deploymentHistory)
    .set(updates)
    .where(eq(deploymentHistory.deploymentId, deploymentId));
}

export async function getDeploymentStats(): Promise<{ total: number; success: number; failed: number; pending: number }> {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  const [stats] = await db.select({
    total: sqlTag<number>`COUNT(*)`,
    success: sqlTag<number>`SUM(CASE WHEN ${deploymentHistory.status} = 'success' THEN 1 ELSE 0 END)`,
    failed: sqlTag<number>`SUM(CASE WHEN ${deploymentHistory.status} = 'failed' THEN 1 ELSE 0 END)`,
    pending: sqlTag<number>`SUM(CASE WHEN ${deploymentHistory.status} IN ('pending', 'in_progress') THEN 1 ELSE 0 END)`,
  }).from(deploymentHistory);
  return {
    total: Number(stats?.total ?? 0),
    success: Number(stats?.success ?? 0),
    failed: Number(stats?.failed ?? 0),
    pending: Number(stats?.pending ?? 0),
  };
}

// ─── Incident Response Runbook ──────────────────────────────────────
export type InsertIrRunbookEntry = typeof irRunbookEntries.$inferInsert;
export type SelectIrRunbookEntry = typeof irRunbookEntries.$inferSelect;

export async function createIrRunbookEntry(data: InsertIrRunbookEntry): Promise<number> {
  const db = await getDbRequired();
  const [result] = await db.insert(irRunbookEntries).values(data);
  return (result as any).insertId;
}

export async function listIrRunbookEntries(opts?: { severity?: string; category?: string; activeOnly?: boolean }): Promise<SelectIrRunbookEntry[]> {
  const db = await getDbRequired();
  const conditions = [];
  if (opts?.severity) conditions.push(eq(irRunbookEntries.severity, opts.severity as any));
  if (opts?.category) conditions.push(eq(irRunbookEntries.category, opts.category as any));
  if (opts?.activeOnly) conditions.push(eq(irRunbookEntries.isActive, 1));
  return db.select().from(irRunbookEntries)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(irRunbookEntries.createdAt));
}

export async function getIrRunbookEntry(entryId: string): Promise<SelectIrRunbookEntry | undefined> {
  const db = await getDbRequired();
  const [row] = await db.select().from(irRunbookEntries)
    .where(eq(irRunbookEntries.entryId, entryId))
    .limit(1);
  return row;
}

export async function updateIrRunbookEntry(entryId: string, data: Partial<InsertIrRunbookEntry>): Promise<void> {
  const db = await getDbRequired();
  await db.update(irRunbookEntries)
    .set({ ...data, updatedAt: new Date().toISOString() } as any)
    .where(eq(irRunbookEntries.entryId, entryId));
}

export async function deleteIrRunbookEntry(entryId: string): Promise<void> {
  const db = await getDbRequired();
  await db.delete(irRunbookEntries)
    .where(eq(irRunbookEntries.entryId, entryId));
}

export async function searchIrRunbook(query: string): Promise<SelectIrRunbookEntry[]> {
  const db = await getDbRequired();
  return db.select().from(irRunbookEntries)
    .where(or(
      like(irRunbookEntries.alarmName, `%${query}%`),
      like(irRunbookEntries.triggerDescription, `%${query}%`),
      like(irRunbookEntries.owner, `%${query}%`)
    ))
    .orderBy(desc(irRunbookEntries.createdAt));
}

export async function incrementIrRunbookTriggerCount(entryId: string): Promise<void> {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  await db.update(irRunbookEntries)
    .set({
      triggerCount: sqlTag`${irRunbookEntries.triggerCount} + 1`,
      lastTriggeredAt: new Date().toISOString(),
    } as any)
    .where(eq(irRunbookEntries.entryId, entryId));
}
