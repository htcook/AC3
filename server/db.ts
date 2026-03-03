import { eq, desc, inArray, like, and, sql, not, or, gt, ne } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { 
  InsertUser, users, 
  serverConfigs, InsertServerConfig, ServerConfig,
  serverCredentials, InsertServerCredential, ServerCredential,
  activityLogs, InsertActivityLog,
  calderaStats, InsertCalderaStats, CalderaStats,
  engagementOpsSnapshots
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
      const mysql2 = await import('mysql2');
      const pool = mysql2.createPool({
        uri: dbUrl,
        ...fipsSSL,
        waitForConnections: true,
        connectionLimit: 10,
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

// Caldera stats operations
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
    const result = await db.insert(engagements).values(engagement);
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

export async function getEngagements() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagements).orderBy(desc(engagements.updatedAt));
}

export async function getEngagementById(id: number) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(engagements).where(eq(engagements.id, id)).limit(1);
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
  const result = await db.insert(typosquatDomains).values(domain);
  return Number(result[0].insertId);
}

export async function bulkCreateTyposquatDomains(domains: InsertTyposquatDomain[]) {
  const db = await getDbRequired();
  if (domains.length === 0) return;
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
  const result = await db.insert(osintFindings).values(finding);
  return Number(result[0].insertId);
}

export async function bulkCreateOsintFindings(findings: InsertOsintFinding[]) {
  const db = await getDbRequired();
  if (findings.length === 0) return;
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
  if (filters?.type && filters.type !== 'all') {
    conditions.push(eq(threatActors.type, filters.type as any));
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
    type: threatActors.type, 
    count: sql<number>`COUNT(*)` 
  }).from(threatActors).groupBy(threatActors.type);
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
  const [result] = await db.select({ count: sql<number>`COUNT(*)` }).from(threatActors);
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
    conditions.push(eq(iocFeeds.severity, filters.severity as any));
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
    severity: iocFeeds.severity, 
    count: sql<number>`COUNT(*)` 
  }).from(iocFeeds).groupBy(iocFeeds.severity);
  const [recent] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(iocFeeds)
    .where(sql`${iocFeeds.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);
  
  return { total: Number(total.count), bySource, bySeverity, recentCount: Number(recent.count) };
}

// ─── Engagement Pipelines ────────────────────────────────────────────────
export async function createEngagementPipeline(pipeline: InsertEngagementPipeline) {
  const db = await getDbRequired();
  const result = await db.insert(engagementPipelines).values(pipeline);
  return Number(result[0].insertId);
}

export async function getEngagementPipeline(id: number) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(engagementPipelines).where(eq(engagementPipelines.id, id));
  return results[0] || null;
}

export async function updateEngagementPipeline(id: number, updates: Partial<InsertEngagementPipeline>) {
  const db = await getDbRequired();
  await db.update(engagementPipelines).set(updates).where(eq(engagementPipelines.id, id));
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
    .where(eq(falsePositiveFindings.status, "false_positive"))
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
    .where(eq(falsePositiveFindings.status, "false_positive"))
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
    .where(eq(falsePositiveFindings.status, "false_positive"))
    .groupBy(falsePositiveFindings.findingType)
    .orderBy(sql`COUNT(*) DESC`);

  const [totalRow] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(falsePositiveFindings)
    .where(eq(falsePositiveFindings.status, "false_positive"));

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
      eq(falsePositiveFindings.status, "false_positive")
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
      eq(falsePositiveFindings.status, "false_positive")
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

// ─── Scan Results Persistence ───────────────────────────────────────────────
import { scanResults, InsertScanResult, ScanResult } from "../drizzle/schema";

/** Insert a single scan result row after a tool finishes executing. */
export async function insertScanResult(data: InsertScanResult): Promise<ScanResult | null> {
  const db = await getDb();
  if (!db) return null;
  const [row] = await db.insert(scanResults).values(data).$returningId();
  const [result] = await db.select().from(scanResults).where(eq(scanResults.id, row.id));
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

/** Get scan results filtered by tool (e.g., "nmap", "nuclei"). */
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
  // Serialize the state — strip non-serializable fields (Set → Array already handled in getState)
  const stateToSave = {
    ...state,
    skippedDomains: state.skippedDomains instanceof Set ? Array.from(state.skippedDomains) : (state.skippedDomains || []),
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
      })
      .where(eq(engagementOpsSnapshots.engagementId, engagementId));
  } else {
    await db.insert(engagementOpsSnapshots).values({
      engagementId,
      stateJson: stateToSave,
      phase: state.phase || 'idle',
      isRunning: state.isRunning || false,
      assetCount: state.assets?.length || 0,
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
