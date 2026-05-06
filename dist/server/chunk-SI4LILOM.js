import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  activityLogs,
  burpScanHistory,
  calderaStats,
  campaignAbilities,
  campaignAgents,
  campaignEngagements,
  campaigns,
  carverRiskCards,
  chainRuns,
  chainStageResults,
  credentialAttackRuns,
  credentialFindings,
  customerIntegrations,
  deploymentHistory,
  diIncidentTrainingData,
  discoveredAssets,
  domainIntelScans,
  domainRecon,
  engagementFindings,
  engagementOpsSnapshots,
  engagementPipelines,
  engagementReports,
  engagementResults,
  engagementShares,
  engagements,
  exploitLearningChains,
  exploitLearningOutcomes,
  exploitLearningPatterns,
  exploitPlanHistory,
  exploitationAttempts,
  falsePositiveFindings,
  init_schema,
  integrationExecutionLog,
  integrationHealthChecks,
  iocFeeds,
  iocSyncLogs,
  irRunbookEntries,
  llmTelemetry,
  osintFindings,
  osintMonitorChanges,
  osintMonitors,
  pentestReports,
  scanResults,
  scoringAuditLog,
  serverConfigs,
  serverCredentials,
  threatActorAbilities,
  threatActorIocs,
  threatActors,
  trainingLabFeedback,
  trainingLabSessions,
  ttpKnowledge,
  typosquatDomains,
  userPlatformCredentials,
  users,
  zapProxySessions,
  zeroDayScanMatches
} from "./chunk-YQRYZ5JK.js";
import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/db.ts
var db_exports = {};
__export(db_exports, {
  acknowledgeChange: () => acknowledgeChange,
  addCampaignAbilities: () => addCampaignAbilities,
  addCampaignAbility: () => addCampaignAbility,
  addCampaignAgent: () => addCampaignAgent,
  addTimelineEvent: () => addTimelineEvent,
  batchCheckFalsePositives: () => batchCheckFalsePositives,
  batchLookupKev: () => batchLookupKev,
  buildHistoricalContextString: () => buildHistoricalContextString,
  bulkCreateDiscoveredAssets: () => bulkCreateDiscoveredAssets,
  bulkCreateIocFeedEntries: () => bulkCreateIocFeedEntries,
  bulkCreateMonitorChanges: () => bulkCreateMonitorChanges,
  bulkCreateOsintFindings: () => bulkCreateOsintFindings,
  bulkCreateThreatActorIocs: () => bulkCreateThreatActorIocs,
  bulkCreateTyposquatDomains: () => bulkCreateTyposquatDomains,
  bulkDeleteEngagements: () => bulkDeleteEngagements,
  bulkExcludeDiscoveredAssets: () => bulkExcludeDiscoveredAssets,
  bulkIncludeDiscoveredAssets: () => bulkIncludeDiscoveredAssets,
  bulkInsertConnectorPerformance: () => bulkInsertConnectorPerformance,
  bulkInsertDITrainingExamples: () => bulkInsertDITrainingExamples,
  bulkInsertScoringAuditEntries: () => bulkInsertScoringAuditEntries,
  bulkUpsertThreatActors: () => bulkUpsertThreatActors,
  createBugBountyFinding: () => createBugBountyFinding,
  createBurpScanRecord: () => createBurpScanRecord,
  createCampaign: () => createCampaign,
  createCarverRiskCard: () => createCarverRiskCard,
  createCarverRiskCardsBatch: () => createCarverRiskCardsBatch,
  createCredential: () => createCredential,
  createCredentialAttackRun: () => createCredentialAttackRun,
  createCredentialFinding: () => createCredentialFinding,
  createCredentialFindings: () => createCredentialFindings,
  createCustomerIntegration: () => createCustomerIntegration,
  createDeployment: () => createDeployment,
  createDiscoveredAsset: () => createDiscoveredAsset,
  createDomainIntelScan: () => createDomainIntelScan,
  createDomainRecon: () => createDomainRecon,
  createEngagement: () => createEngagement,
  createEngagementPipeline: () => createEngagementPipeline,
  createEngagementReport: () => createEngagementReport,
  createEngagementShare: () => createEngagementShare,
  createExecutionLog: () => createExecutionLog,
  createFalsePositive: () => createFalsePositive,
  createHealthCheck: () => createHealthCheck,
  createIocFeedEntry: () => createIocFeedEntry,
  createIocSyncLog: () => createIocSyncLog,
  createIrRunbookEntry: () => createIrRunbookEntry,
  createMonitorChange: () => createMonitorChange,
  createOsintFinding: () => createOsintFinding,
  createOsintMonitor: () => createOsintMonitor,
  createPentestReport: () => createPentestReport,
  createServerConfig: () => createServerConfig,
  createThreatActor: () => createThreatActor,
  createThreatActorAbility: () => createThreatActorAbility,
  createThreatActorIoc: () => createThreatActorIoc,
  createTrainingLabSession: () => createTrainingLabSession,
  createTyposquatDomain: () => createTyposquatDomain,
  createZapProxySession: () => createZapProxySession,
  deleteCampaign: () => deleteCampaign,
  deleteCampaignAbility: () => deleteCampaignAbility,
  deleteCampaignAgent: () => deleteCampaignAgent,
  deleteCarverRiskCard: () => deleteCarverRiskCard,
  deleteCarverRiskCardsByBatch: () => deleteCarverRiskCardsByBatch,
  deleteChainRunDb: () => deleteChainRunDb,
  deleteCustomerIntegration: () => deleteCustomerIntegration,
  deleteDiscoveredAssetsByScan: () => deleteDiscoveredAssetsByScan,
  deleteDomainIntelScan: () => deleteDomainIntelScan,
  deleteEngagement: () => deleteEngagement,
  deleteEngagementShare: () => deleteEngagementShare,
  deleteIrRunbookEntry: () => deleteIrRunbookEntry,
  deleteOpsSnapshot: () => deleteOpsSnapshot,
  deleteOsintMonitor: () => deleteOsintMonitor,
  deletePentestReport: () => deletePentestReport,
  deleteReport: () => deleteReport,
  dismissZeroDayMatch: () => dismissZeroDayMatch,
  excludeDiscoveredAsset: () => excludeDiscoveredAsset,
  getActiveCustomerIntegrationsByStage: () => getActiveCustomerIntegrationsByStage,
  getActiveFPHashes: () => getActiveFPHashes,
  getActivityLogs: () => getActivityLogs,
  getActivityLogsByServer: () => getActivityLogsByServer,
  getAllCampaignEngagementLinks: () => getAllCampaignEngagementLinks,
  getAllCredentialFindings: () => getAllCredentialFindings,
  getAllCustomerIntegrations: () => getAllCustomerIntegrations,
  getAllEngagementLlmCosts: () => getAllEngagementLlmCosts,
  getAllEngagementShares: () => getAllEngagementShares,
  getAllFalsePositives: () => getAllFalsePositives,
  getAllReports: () => getAllReports,
  getAllUsers: () => getAllUsers,
  getAvgGraduationScoresBySector: () => getAvgGraduationScoresBySector,
  getBurpScansByEngagement: () => getBurpScansByEngagement,
  getBurpScansByUser: () => getBurpScansByUser,
  getCalderaStatsByServerId: () => getCalderaStatsByServerId,
  getCampaignAbilities: () => getCampaignAbilities,
  getCampaignAgents: () => getCampaignAgents,
  getCampaignById: () => getCampaignById,
  getCampaigns: () => getCampaigns,
  getCampaignsByEngagement: () => getCampaignsByEngagement,
  getCarverRiskCardById: () => getCarverRiskCardById,
  getCarverRiskCardStats: () => getCarverRiskCardStats,
  getCarverRiskCards: () => getCarverRiskCards,
  getCarverRiskCardsByBatch: () => getCarverRiskCardsByBatch,
  getChainRunByChainId: () => getChainRunByChainId,
  getChainStageResultsDb: () => getChainStageResultsDb,
  getConnectorAvgsBySector: () => getConnectorAvgsBySector,
  getConnectorPerformanceBySector: () => getConnectorPerformanceBySector,
  getConnectorPerformanceForDomain: () => getConnectorPerformanceForDomain,
  getCredentialAttackHistory: () => getCredentialAttackHistory,
  getCredentialAttackHistoryCount: () => getCredentialAttackHistoryCount,
  getCredentialAttackRunById: () => getCredentialAttackRunById,
  getCredentialAttackRuns: () => getCredentialAttackRuns,
  getCredentialAttackRunsByDomainScan: () => getCredentialAttackRunsByDomainScan,
  getCredentialAttackStats: () => getCredentialAttackStats,
  getCredentialFindingsByDomainScan: () => getCredentialFindingsByDomainScan,
  getCredentialFindingsByRun: () => getCredentialFindingsByRun,
  getCredentialFindingsHistory: () => getCredentialFindingsHistory,
  getCredentialsByServerId: () => getCredentialsByServerId,
  getCustomerIntegrationByIntegrationId: () => getCustomerIntegrationByIntegrationId,
  getCustomerIntegrationStats: () => getCustomerIntegrationStats,
  getCustomerIntegrationsByCategory: () => getCustomerIntegrationsByCategory,
  getCustomerIntegrationsByStatus: () => getCustomerIntegrationsByStatus,
  getDITrainingExamplesForDomain: () => getDITrainingExamplesForDomain,
  getDITrainingExamplesForSector: () => getDITrainingExamplesForSector,
  getDITrainingStats: () => getDITrainingStats,
  getDb: () => getDb,
  getDbBurpScanStats: () => getDbBurpScanStats,
  getDbRequired: () => getDbRequired,
  getDeploymentById: () => getDeploymentById,
  getDeploymentStats: () => getDeploymentStats,
  getDiscoveredAssetsByScan: () => getDiscoveredAssetsByScan,
  getDomainIntelScanById: () => getDomainIntelScanById,
  getDomainIntelScans: () => getDomainIntelScans,
  getDomainIntelScansByEngagement: () => getDomainIntelScansByEngagement,
  getDomainReconByEngagement: () => getDomainReconByEngagement,
  getDomainReconById: () => getDomainReconById,
  getEnabledMonitors: () => getEnabledMonitors,
  getEngagementByCampaign: () => getEngagementByCampaign,
  getEngagementById: () => getEngagementById,
  getEngagementFindings: () => getEngagementFindings,
  getEngagementLlmCost: () => getEngagementLlmCost,
  getEngagementLlmCostBreakdown: () => getEngagementLlmCostBreakdown,
  getEngagementLlmCostTimeSeries: () => getEngagementLlmCostTimeSeries,
  getEngagementLlmTelemetryRaw: () => getEngagementLlmTelemetryRaw,
  getEngagementPipeline: () => getEngagementPipeline,
  getEngagementReports: () => getEngagementReports,
  getEngagementResult: () => getEngagementResult,
  getEngagementShareByToken: () => getEngagementShareByToken,
  getEngagementSharesByEngagement: () => getEngagementSharesByEngagement,
  getEngagements: () => getEngagements,
  getExecutionLogsByEngagement: () => getExecutionLogsByEngagement,
  getExecutionLogsByIntegration: () => getExecutionLogsByIntegration,
  getExploitLearningDbStats: () => getExploitLearningDbStats,
  getExploitPlanHistoryByEngagement: () => getExploitPlanHistoryByEngagement,
  getExploitPlanHistoryByGateId: () => getExploitPlanHistoryByGateId,
  getExploitPlanHistoryById: () => getExploitPlanHistoryById,
  getExploitPlanStats: () => getExploitPlanStats,
  getExploitationAttemptById: () => getExploitationAttemptById,
  getExploitationAttempts: () => getExploitationAttempts,
  getExploitationStats: () => getExploitationStats,
  getFPContextForLLM: () => getFPContextForLLM,
  getFalsePositivesByScan: () => getFalsePositivesByScan,
  getGlobalLlmTelemetryRaw: () => getGlobalLlmTelemetryRaw,
  getGraduationScoresBySector: () => getGraduationScoresBySector,
  getGraduationScoresForDomain: () => getGraduationScoresForDomain,
  getHealthCheckHistory: () => getHealthCheckHistory,
  getHighQualityDITrainingExamples: () => getHighQualityDITrainingExamples,
  getHistoricalScanContext: () => getHistoricalScanContext,
  getIocFeedStats: () => getIocFeedStats,
  getIrRunbookEntry: () => getIrRunbookEntry,
  getKevStats: () => getKevStats,
  getLastIocSync: () => getLastIocSync,
  getLatestHealthCheckPerIntegration: () => getLatestHealthCheckPerIntegration,
  getLlmTelemetryLatencyDistribution: () => getLlmTelemetryLatencyDistribution,
  getLlmTelemetryModelUsage: () => getLlmTelemetryModelUsage,
  getLlmTelemetryRecentErrors: () => getLlmTelemetryRecentErrors,
  getLlmTelemetrySummary: () => getLlmTelemetrySummary,
  getLlmTelemetryTimeSeries: () => getLlmTelemetryTimeSeries,
  getLlmTelemetryTopCallers: () => getLlmTelemetryTopCallers,
  getMonitorChanges: () => getMonitorChanges,
  getOsintFindingsByEngagement: () => getOsintFindingsByEngagement,
  getOsintFindingsByRecon: () => getOsintFindingsByRecon,
  getOsintMonitorById: () => getOsintMonitorById,
  getOsintMonitors: () => getOsintMonitors,
  getPentestReportById: () => getPentestReportById,
  getPentestReports: () => getPentestReports,
  getPreviousCompletedScan: () => getPreviousCompletedScan,
  getRecentHealthChecks: () => getRecentHealthChecks,
  getRecentZeroDayMatches: () => getRecentZeroDayMatches,
  getReportById: () => getReportById,
  getScanResultsByEngagement: () => getScanResultsByEngagement,
  getScanResultsByTool: () => getScanResultsByTool,
  getScanResultsSummary: () => getScanResultsSummary,
  getScoringTimelineByAsset: () => getScoringTimelineByAsset,
  getScoringTimelineByScan: () => getScoringTimelineByScan,
  getServerConfigById: () => getServerConfigById,
  getServerConfigs: () => getServerConfigs,
  getThreatActor: () => getThreatActor,
  getThreatActorById: () => getThreatActorById,
  getThreatActorCount: () => getThreatActorCount,
  getThreatActorStats: () => getThreatActorStats,
  getTimelineEvents: () => getTimelineEvents,
  getTrainingLabFeedbackForSession: () => getTrainingLabFeedbackForSession,
  getTrainingLabSession: () => getTrainingLabSession,
  getTtpKnowledge: () => getTtpKnowledge,
  getTtpKnowledgeStats: () => getTtpKnowledgeStats,
  getTyposquatsByEngagement: () => getTyposquatsByEngagement,
  getTyposquatsByRecon: () => getTyposquatsByRecon,
  getUnacknowledgedChanges: () => getUnacknowledgedChanges,
  getUserByOpenId: () => getUserByOpenId,
  getZapProxySessionById: () => getZapProxySessionById,
  getZapProxySessions: () => getZapProxySessions,
  getZapSessionsByDomainScan: () => getZapSessionsByDomainScan,
  getZeroDayMatchStats: () => getZeroDayMatchStats,
  getZeroDayMatchesByDomain: () => getZeroDayMatchesByDomain,
  getZeroDayMatchesByEngagement: () => getZeroDayMatchesByEngagement,
  getZeroDayMatchesByScan: () => getZeroDayMatchesByScan,
  includeDiscoveredAsset: () => includeDiscoveredAsset,
  incrementDITrainingUsage: () => incrementDITrainingUsage,
  incrementIrRunbookTriggerCount: () => incrementIrRunbookTriggerCount,
  incrementShareViewCount: () => incrementShareViewCount,
  insertChainRun: () => insertChainRun,
  insertConnectorPerformance: () => insertConnectorPerformance,
  insertDITrainingExample: () => insertDITrainingExample,
  insertExploitOutcome: () => insertExploitOutcome,
  insertExploitPlanHistory: () => insertExploitPlanHistory,
  insertExploitationAttempt: () => insertExploitationAttempt,
  insertGraduationScore: () => insertGraduationScore,
  insertScanResult: () => insertScanResult,
  insertScoringAuditEntry: () => insertScoringAuditEntry,
  insertTrainingLabFeedbackEntry: () => insertTrainingLabFeedbackEntry,
  isFindingFalsePositive: () => isFindingFalsePositive,
  linkCampaignToEngagement: () => linkCampaignToEngagement,
  listAllAbilities: () => listAllAbilities,
  listChainRunsDb: () => listChainRunsDb,
  listDeployments: () => listDeployments,
  listEngagementPipelines: () => listEngagementPipelines,
  listIocFeedEntries: () => listIocFeedEntries,
  listIocSyncLogs: () => listIocSyncLogs,
  listIrRunbookEntries: () => listIrRunbookEntries,
  listPlatformCredentials: () => listPlatformCredentials,
  listThreatActorAbilities: () => listThreatActorAbilities,
  listThreatActorIocs: () => listThreatActorIocs,
  listThreatActors: () => listThreatActors,
  listTrainingLabSessions: () => listTrainingLabSessions,
  listTtpKnowledge: () => listTtpKnowledge,
  loadAllExploitChains: () => loadAllExploitChains,
  loadAllExploitPatterns: () => loadAllExploitPatterns,
  loadOpsSnapshot: () => loadOpsSnapshot,
  loadRecentExploitOutcomes: () => loadRecentExploitOutcomes,
  logActivity: () => logActivity,
  lookupKevByCve: () => lookupKevByCve,
  recordLlmTelemetry: () => recordLlmTelemetry,
  reinstateFalsePositive: () => reinstateFalsePositive,
  reorderCampaignAbilities: () => reorderCampaignAbilities,
  resetDbConnection: () => resetDbConnection,
  saveCredentialAttackWithTool: () => saveCredentialAttackWithTool,
  saveCredentialFindingWithTool: () => saveCredentialFindingWithTool,
  saveEngagementFindings: () => saveEngagementFindings,
  saveEngagementResult: () => saveEngagementResult,
  saveOpsSnapshot: () => saveOpsSnapshot,
  saveZeroDayMatches: () => saveZeroDayMatches,
  searchIrRunbook: () => searchIrRunbook,
  unlinkCampaignFromEngagement: () => unlinkCampaignFromEngagement,
  updateBurpScanRecord: () => updateBurpScanRecord,
  updateCampaign: () => updateCampaign,
  updateCampaignAbilityStatus: () => updateCampaignAbilityStatus,
  updateCampaignAgentStatus: () => updateCampaignAgentStatus,
  updateChainRunDb: () => updateChainRunDb,
  updateCredential: () => updateCredential,
  updateCredentialAttackRun: () => updateCredentialAttackRun,
  updateCredentialFindingValidation: () => updateCredentialFindingValidation,
  updateCustomerIntegration: () => updateCustomerIntegration,
  updateDITrainingAnalystRating: () => updateDITrainingAnalystRating,
  updateDeploymentStatus: () => updateDeploymentStatus,
  updateDomainIntelScan: () => updateDomainIntelScan,
  updateDomainRecon: () => updateDomainRecon,
  updateEngagement: () => updateEngagement,
  updateEngagementPipeline: () => updateEngagementPipeline,
  updateEngagementShare: () => updateEngagementShare,
  updateExploitationAttempt: () => updateExploitationAttempt,
  updateIocSyncLog: () => updateIocSyncLog,
  updateIrRunbookEntry: () => updateIrRunbookEntry,
  updateOsintMonitor: () => updateOsintMonitor,
  updatePentestReport: () => updatePentestReport,
  updateReport: () => updateReport,
  updateServerStatus: () => updateServerStatus,
  updateThreatActor: () => updateThreatActor,
  updateTrainingLabSession: () => updateTrainingLabSession,
  updateTyposquatDomain: () => updateTyposquatDomain,
  updateUserRole: () => updateUserRole,
  updateZapProxySession: () => updateZapProxySession,
  upsertCalderaStats: () => upsertCalderaStats,
  upsertChainStageResultDb: () => upsertChainStageResultDb,
  upsertExploitChain: () => upsertExploitChain,
  upsertExploitPattern: () => upsertExploitPattern,
  upsertThreatActor: () => upsertThreatActor,
  upsertTtpKnowledge: () => upsertTtpKnowledge,
  upsertUser: () => upsertUser
});
import { eq, desc, inArray, like, and, sql, not, or, ne } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import crypto from "crypto";
async function getDb() {
  if (_db) {
    try {
      const { sql: sql2 } = await import("drizzle-orm");
      await _db.execute(sql2`SELECT 1`);
      return _db;
    } catch {
      console.warn("[Database] Cached connection lost, reconnecting...");
      _db = null;
    }
  }
  const now = Date.now();
  if (!process.env.DATABASE_URL) {
    return null;
  }
  if (now - _dbLastCheck < DB_RETRY_INTERVAL) {
    return null;
  }
  _dbLastCheck = now;
  try {
    let dbUrl = process.env.DATABASE_URL;
    const needsSsl = dbUrl.includes("tidbcloud.com") || dbUrl.includes("ssl=");
    dbUrl = dbUrl.replace(/[?&]ssl=[^&]*/g, "").replace(/\?$/, "");
    if (needsSsl) {
      const { getFIPSDatabaseSSLConfig } = await import("./fips-tls-6H6YM4OG.js");
      const fipsSSL = getFIPSDatabaseSSLConfig();
      const poolSize = parseInt(process.env.DB_POOL_SIZE || "25", 10);
      const mysql2 = await import("mysql2");
      const pool = mysql2.createPool({
        uri: dbUrl,
        ...fipsSSL,
        waitForConnections: true,
        connectionLimit: poolSize,
        connectTimeout: 15e3,
        // 15s connect timeout (TiDB cold-start can be slow)
        idleTimeout: 3e4,
        // 30s idle timeout (free connections faster under load)
        queueLimit: 50,
        // Max 50 queued requests before rejecting
        enableKeepAlive: true,
        // Keep connections alive across idle periods
        keepAliveInitialDelay: 1e4
        // 10s keepalive ping interval
      });
      _db = drizzle({ client: pool });
      console.log("[Database] FIPS TLS enforced on connection");
    } else {
      _db = drizzle(dbUrl);
    }
    const { sql: sql2 } = await import("drizzle-orm");
    await _db.execute(sql2`SELECT 1`);
    console.log("[Database] Connected successfully");
    return _db;
  } catch (error) {
    console.warn("[Database] Failed to connect:", error);
    _db = null;
    return null;
  }
}
async function getDbRequired() {
  for (let attempt = 1; attempt <= 3; attempt++) {
    _dbLastCheck = 0;
    const conn = await getDb();
    if (conn) return conn;
    if (attempt < 3) {
      console.warn(`[Database] Retry ${attempt}/3 \u2014 waiting 1s...`);
      await new Promise((r) => setTimeout(r, 1e3));
    }
  }
  throw new Error("Database not available after 3 retries \u2014 please try again in a few seconds");
}
function resetDbConnection() {
  _db = null;
  _dbLastCheck = 0;
}
async function upsertUser(user) {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }
  try {
    const values = { openId: user.openId };
    const updateSet = {};
    const textFields = ["name", "email", "loginMethod"];
    const assignNullable = (field) => {
      const value = user[field];
      if (value === void 0) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };
    textFields.forEach(assignNullable);
    if (user.lastSignedIn !== void 0) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== void 0) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }
    if (!values.lastSignedIn) {
      values.lastSignedIn = /* @__PURE__ */ new Date();
    }
    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = /* @__PURE__ */ new Date();
    }
    await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}
async function getUserByOpenId(openId) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function getAllUsers() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(users).orderBy(desc(users.createdAt));
}
async function updateUserRole(userId, role) {
  const db = await getDb();
  if (!db) return;
  await db.update(users).set({ role }).where(eq(users.id, userId));
}
async function createServerConfig(config) {
  const db = await getDbRequired();
  const result = await db.insert(serverConfigs).values(config);
  return result[0].insertId;
}
async function getServerConfigs() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(serverConfigs).orderBy(desc(serverConfigs.createdAt));
}
async function getServerConfigById(id) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(serverConfigs).where(eq(serverConfigs.id, id)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function updateServerStatus(id, status) {
  const db = await getDb();
  if (!db) return;
  await db.update(serverConfigs).set({ status, lastHealthCheck: /* @__PURE__ */ new Date() }).where(eq(serverConfigs.id, id));
}
async function createCredential(credential) {
  const db = await getDbRequired();
  await db.insert(serverCredentials).values(credential);
}
async function getCredentialsByServerId(serverId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(serverCredentials).where(eq(serverCredentials.serverId, serverId));
}
async function updateCredential(id, updates) {
  const db = await getDb();
  if (!db) return;
  await db.update(serverCredentials).set(updates).where(eq(serverCredentials.id, id));
}
async function logActivity(log) {
  const db = await getDb();
  if (!db) return;
  await db.insert(activityLogs).values(log);
}
async function getActivityLogs(limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(activityLogs).orderBy(desc(activityLogs.createdAt)).limit(limit);
}
async function getActivityLogsByServer(serverId, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(activityLogs).where(eq(activityLogs.serverId, serverId)).orderBy(desc(activityLogs.createdAt)).limit(limit);
}
async function upsertCalderaStats(stats) {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select().from(calderaStats).where(eq(calderaStats.serverId, stats.serverId)).limit(1);
  if (existing.length > 0) {
    await db.update(calderaStats).set({
      ...stats,
      lastUpdated: /* @__PURE__ */ new Date()
    }).where(eq(calderaStats.serverId, stats.serverId));
  } else {
    await db.insert(calderaStats).values(stats);
  }
}
async function getCalderaStatsByServerId(serverId) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(calderaStats).where(eq(calderaStats.serverId, serverId)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function createCampaign(campaign) {
  const db = await getDbRequired();
  const result = await db.insert(campaigns).values(campaign);
  return result[0].insertId;
}
async function getCampaigns() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaigns).orderBy(desc(campaigns.createdAt));
}
async function getCampaignById(id) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(campaigns).where(eq(campaigns.id, id)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function updateCampaign(id, updates) {
  const db = await getDb();
  if (!db) return;
  await db.update(campaigns).set(updates).where(eq(campaigns.id, id));
}
async function deleteCampaign(id) {
  const db = await getDb();
  if (!db) return;
  await db.delete(campaignAgents).where(eq(campaignAgents.campaignId, id));
  await db.delete(campaignAbilities).where(eq(campaignAbilities.campaignId, id));
  await db.delete(campaigns).where(eq(campaigns.id, id));
}
async function addCampaignAgent(agent) {
  const db = await getDbRequired();
  const result = await db.insert(campaignAgents).values(agent);
  return result[0].insertId;
}
async function getCampaignAgents(campaignId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignAgents).where(eq(campaignAgents.campaignId, campaignId));
}
async function updateCampaignAgentStatus(id, status) {
  const db = await getDb();
  if (!db) return;
  await db.update(campaignAgents).set({ status }).where(eq(campaignAgents.id, id));
}
async function deleteCampaignAgent(id) {
  const db = await getDb();
  if (!db) return;
  await db.delete(campaignAgents).where(eq(campaignAgents.id, id));
}
async function addCampaignAbility(ability) {
  const db = await getDbRequired();
  const result = await db.insert(campaignAbilities).values(ability);
  return result[0].insertId;
}
async function addCampaignAbilities(abilities) {
  const db = await getDbRequired();
  if (abilities.length === 0) return;
  await db.insert(campaignAbilities).values(abilities);
}
async function getCampaignAbilities(campaignId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignAbilities).where(eq(campaignAbilities.campaignId, campaignId)).orderBy(campaignAbilities.executionOrder);
}
async function updateCampaignAbilityStatus(id, status) {
  const db = await getDb();
  if (!db) return;
  const updates = { status };
  if (status === "completed" || status === "failed") {
    updates.executedAt = /* @__PURE__ */ new Date();
  }
  await db.update(campaignAbilities).set(updates).where(eq(campaignAbilities.id, id));
}
async function deleteCampaignAbility(id) {
  const db = await getDb();
  if (!db) return;
  await db.delete(campaignAbilities).where(eq(campaignAbilities.id, id));
}
async function reorderCampaignAbilities(campaignId, abilityIds) {
  const db = await getDb();
  if (!db) return;
  for (let i = 0; i < abilityIds.length; i++) {
    await db.update(campaignAbilities).set({ executionOrder: i }).where(eq(campaignAbilities.id, abilityIds[i]));
  }
}
async function createEngagement(engagement) {
  const db = await getDbRequired();
  try {
    const values = { autoResumeOnRestart: 1, ...engagement };
    const result = await db.insert(engagements).values(values);
    return result[0].insertId;
  } catch (err) {
    if (err?.code === "ECONNRESET" || err?.code === "PROTOCOL_CONNECTION_LOST" || err?.message?.includes("ECONNREFUSED")) {
      resetDbConnection();
      const retryDb = await getDbRequired();
      const result = await retryDb.insert(engagements).values(engagement);
      return result[0].insertId;
    }
    throw err;
  }
}
async function getEngagements(scopeUser) {
  const db = await getDb();
  if (!db) return [];
  const { scopeEngagementWhere } = await import("./engagement-access-guard-KHLJNJGF.js");
  const scope = scopeUser ? scopeEngagementWhere(scopeUser) : null;
  if (scope) {
    return db.select().from(engagements).where(scope).orderBy(desc(engagements.updatedAt));
  }
  return db.select().from(engagements).orderBy(desc(engagements.updatedAt));
}
async function getEngagementById(id, scopeUser) {
  const db = await getDb();
  if (!db) return void 0;
  const { scopedAnd } = await import("./engagement-access-guard-KHLJNJGF.js");
  const where = scopeUser ? scopedAnd(scopeUser, eq(engagements.id, id)) : eq(engagements.id, id);
  const result = await db.select().from(engagements).where(where).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function updateEngagement(id, updates) {
  const db = await getDb();
  if (!db) return;
  await db.update(engagements).set(updates).where(eq(engagements.id, id));
}
async function deleteEngagement(id) {
  const db = await getDb();
  if (!db) return;
  await db.delete(engagementReports).where(eq(engagementReports.engagementId, id));
  await db.delete(campaignEngagements).where(eq(campaignEngagements.engagementId, id));
  await db.delete(engagements).where(eq(engagements.id, id));
}
async function bulkDeleteEngagements(ids) {
  const db = await getDb();
  if (!db || ids.length === 0) return { deleted: 0 };
  await db.delete(engagementReports).where(inArray(engagementReports.engagementId, ids));
  await db.delete(campaignEngagements).where(inArray(campaignEngagements.engagementId, ids));
  const result = await db.delete(engagements).where(inArray(engagements.id, ids));
  return { deleted: result[0].affectedRows };
}
async function linkCampaignToEngagement(link) {
  const db = await getDbRequired();
  const result = await db.insert(campaignEngagements).values(link);
  return result[0].insertId;
}
async function getCampaignsByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignEngagements).where(eq(campaignEngagements.engagementId, engagementId)).orderBy(desc(campaignEngagements.createdAt));
}
async function getEngagementByCampaign(gophishCampaignId) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(campaignEngagements).where(eq(campaignEngagements.gophishCampaignId, gophishCampaignId)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function getAllCampaignEngagementLinks() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(campaignEngagements).orderBy(desc(campaignEngagements.createdAt));
}
async function unlinkCampaignFromEngagement(id) {
  const db = await getDb();
  if (!db) return;
  await db.delete(campaignEngagements).where(eq(campaignEngagements.id, id));
}
async function createDomainRecon(recon) {
  const db = await getDbRequired();
  if (recon.engagementId && recon.domain) {
    const existing = await db.select({ id: domainRecon.id }).from(domainRecon).where(and(eq(domainRecon.engagementId, recon.engagementId), eq(domainRecon.domain, recon.domain))).limit(1);
    if (existing.length > 0) return existing[0].id;
  }
  const result = await db.insert(domainRecon).values(recon);
  return Number(result[0].insertId);
}
async function updateDomainRecon(id, data) {
  const db = await getDb();
  if (!db) return;
  await db.update(domainRecon).set(data).where(eq(domainRecon.id, id));
}
async function getDomainReconByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(domainRecon).where(eq(domainRecon.engagementId, engagementId)).orderBy(desc(domainRecon.createdAt));
}
async function getDomainReconById(id) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(domainRecon).where(eq(domainRecon.id, id)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function createTyposquatDomain(domain) {
  const db = await getDbRequired();
  if (domain.engagementId && domain.originalDomain && domain.permutedDomain) {
    const existing = await db.select({ id: typosquatDomains.id }).from(typosquatDomains).where(and(
      eq(typosquatDomains.engagementId, domain.engagementId),
      eq(typosquatDomains.originalDomain, domain.originalDomain),
      eq(typosquatDomains.permutedDomain, domain.permutedDomain)
    )).limit(1);
    if (existing.length > 0) return existing[0].id;
  }
  const result = await db.insert(typosquatDomains).values(domain);
  return Number(result[0].insertId);
}
async function bulkCreateTyposquatDomains(domains) {
  const db = await getDbRequired();
  if (domains.length === 0) return;
  const engId = domains[0]?.engagementId;
  if (engId) {
    const existing = await db.select({
      originalDomain: typosquatDomains.originalDomain,
      permutedDomain: typosquatDomains.permutedDomain
    }).from(typosquatDomains).where(eq(typosquatDomains.engagementId, engId));
    const existingSet = new Set(existing.map((e) => `${e.originalDomain}||${e.permutedDomain}`));
    const newDomains = domains.filter((d) => !existingSet.has(`${d.originalDomain}||${d.permutedDomain}`));
    if (newDomains.length === 0) return;
    await db.insert(typosquatDomains).values(newDomains);
    return;
  }
  await db.insert(typosquatDomains).values(domains);
}
async function updateTyposquatDomain(id, data) {
  const db = await getDb();
  if (!db) return;
  await db.update(typosquatDomains).set(data).where(eq(typosquatDomains.id, id));
}
async function getTyposquatsByRecon(reconId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(typosquatDomains).where(eq(typosquatDomains.reconId, reconId)).orderBy(desc(typosquatDomains.createdAt));
}
async function getTyposquatsByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(typosquatDomains).where(eq(typosquatDomains.engagementId, engagementId)).orderBy(desc(typosquatDomains.createdAt));
}
async function createOsintFinding(finding) {
  const db = await getDbRequired();
  if (finding.engagementId && finding.category && finding.title) {
    const existing = await db.select({ id: osintFindings.id }).from(osintFindings).where(and(
      eq(osintFindings.engagementId, finding.engagementId),
      eq(osintFindings.category, finding.category),
      eq(osintFindings.title, finding.title)
    )).limit(1);
    if (existing.length > 0) return existing[0].id;
  }
  const result = await db.insert(osintFindings).values(finding);
  return Number(result[0].insertId);
}
async function bulkCreateOsintFindings(findings) {
  const db = await getDbRequired();
  if (findings.length === 0) return;
  const engId = findings[0]?.engagementId;
  if (engId) {
    const existing = await db.select({
      category: osintFindings.category,
      title: osintFindings.title
    }).from(osintFindings).where(eq(osintFindings.engagementId, engId));
    const existingSet = new Set(existing.map((e) => `${e.category}||${e.title}`));
    const newFindings = findings.filter((f) => !existingSet.has(`${f.category}||${f.title}`));
    if (newFindings.length === 0) return;
    await db.insert(osintFindings).values(newFindings);
    return;
  }
  await db.insert(osintFindings).values(findings);
}
async function getOsintFindingsByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintFindings).where(eq(osintFindings.engagementId, engagementId)).orderBy(desc(osintFindings.createdAt));
}
async function getOsintFindingsByRecon(reconId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintFindings).where(eq(osintFindings.reconId, reconId)).orderBy(desc(osintFindings.createdAt));
}
async function createOsintMonitor(monitor) {
  const db = await getDbRequired();
  const result = await db.insert(osintMonitors).values(monitor);
  return Number(result[0].insertId);
}
async function getOsintMonitors() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitors).orderBy(desc(osintMonitors.createdAt));
}
async function getOsintMonitorById(id) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(osintMonitors).where(eq(osintMonitors.id, id));
  return rows[0] || null;
}
async function getEnabledMonitors() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitors).where(eq(osintMonitors.enabled, true));
}
async function updateOsintMonitor(id, updates) {
  const db = await getDbRequired();
  await db.update(osintMonitors).set(updates).where(eq(osintMonitors.id, id));
}
async function deleteOsintMonitor(id) {
  const db = await getDbRequired();
  await db.delete(osintMonitors).where(eq(osintMonitors.id, id));
}
async function createMonitorChange(change) {
  const db = await getDbRequired();
  const result = await db.insert(osintMonitorChanges).values(change);
  return Number(result[0].insertId);
}
async function bulkCreateMonitorChanges(changes) {
  const db = await getDbRequired();
  if (changes.length === 0) return;
  await db.insert(osintMonitorChanges).values(changes);
}
async function getMonitorChanges(monitorId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitorChanges).where(eq(osintMonitorChanges.monitorId, monitorId)).orderBy(desc(osintMonitorChanges.createdAt));
}
async function getUnacknowledgedChanges() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(osintMonitorChanges).where(eq(osintMonitorChanges.acknowledged, false)).orderBy(desc(osintMonitorChanges.createdAt));
}
async function acknowledgeChange(id, userId) {
  const db = await getDbRequired();
  await db.update(osintMonitorChanges).set({
    acknowledged: true,
    acknowledgedBy: userId,
    acknowledgedAt: /* @__PURE__ */ new Date()
  }).where(eq(osintMonitorChanges.id, id));
}
async function createEngagementReport(report) {
  const db = await getDbRequired();
  const result = await db.insert(engagementReports).values(report);
  return Number(result[0].insertId);
}
async function getEngagementReports(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementReports).where(eq(engagementReports.engagementId, engagementId)).orderBy(desc(engagementReports.createdAt));
}
async function getReportById(id) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(engagementReports).where(eq(engagementReports.id, id));
  return rows[0] || null;
}
async function updateReport(id, updates) {
  const db = await getDbRequired();
  await db.update(engagementReports).set(updates).where(eq(engagementReports.id, id));
}
async function deleteReport(id) {
  const db = await getDbRequired();
  await db.delete(engagementReports).where(eq(engagementReports.id, id));
}
async function getAllReports() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementReports).orderBy(desc(engagementReports.createdAt));
}
async function createDomainIntelScan(scan) {
  const db = await getDbRequired();
  const result = await db.insert(domainIntelScans).values(scan);
  return Number(result[0].insertId);
}
async function getDomainIntelScans() {
  const db = await getDb();
  if (!db) return [];
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
    updatedAt: domainIntelScans.updatedAt
  }).from(domainIntelScans).where(
    not(
      sql`${domainIntelScans.primaryDomain} REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$'`
    )
  ).orderBy(desc(domainIntelScans.updatedAt), desc(domainIntelScans.createdAt));
}
async function getDomainIntelScanById(id) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, id));
  return rows[0] || null;
}
async function getPreviousCompletedScan(primaryDomain, excludeScanId) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(domainIntelScans).where(
    and(
      eq(domainIntelScans.primaryDomain, primaryDomain),
      not(eq(domainIntelScans.id, excludeScanId)),
      or(
        eq(domainIntelScans.status, "completed"),
        eq(domainIntelScans.status, "scan_complete")
      )
    )
  ).orderBy(sql`created_at DESC`).limit(1);
  return rows[0] || null;
}
async function updateDomainIntelScan(id, updates) {
  const db = await getDbRequired();
  await db.update(domainIntelScans).set(updates).where(eq(domainIntelScans.id, id));
}
async function createDiscoveredAsset(asset) {
  const db = await getDbRequired();
  const result = await db.insert(discoveredAssets).values(asset);
  return Number(result[0].insertId);
}
async function bulkCreateDiscoveredAssets(assets) {
  const db = await getDbRequired();
  if (assets.length === 0) return;
  await db.insert(discoveredAssets).values(assets);
}
async function getDiscoveredAssetsByScan(scanId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));
}
async function excludeDiscoveredAsset(assetId, reason) {
  const db = await getDbRequired();
  await db.update(discoveredAssets).set({
    excluded: true,
    exclusionReason: reason,
    excludedAt: /* @__PURE__ */ new Date()
  }).where(eq(discoveredAssets.id, assetId));
}
async function includeDiscoveredAsset(assetId) {
  const db = await getDbRequired();
  await db.update(discoveredAssets).set({
    excluded: false,
    exclusionReason: null,
    excludedAt: null
  }).where(eq(discoveredAssets.id, assetId));
}
async function bulkExcludeDiscoveredAssets(assetIds, reason) {
  const db = await getDbRequired();
  for (const id of assetIds) {
    await db.update(discoveredAssets).set({
      excluded: true,
      exclusionReason: reason,
      excludedAt: /* @__PURE__ */ new Date()
    }).where(eq(discoveredAssets.id, id));
  }
}
async function bulkIncludeDiscoveredAssets(assetIds) {
  const db = await getDbRequired();
  for (const id of assetIds) {
    await db.update(discoveredAssets).set({
      excluded: false,
      exclusionReason: null,
      excludedAt: null
    }).where(eq(discoveredAssets.id, id));
  }
}
async function deleteDiscoveredAssetsByScan(scanId) {
  const db = await getDbRequired();
  await db.delete(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));
}
async function deleteDomainIntelScan(scanId) {
  const db = await getDbRequired();
  await db.delete(domainIntelScans).where(eq(domainIntelScans.id, scanId));
}
async function getDomainIntelScansByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(domainIntelScans).where(eq(domainIntelScans.engagementId, engagementId)).orderBy(desc(domainIntelScans.updatedAt), desc(domainIntelScans.createdAt));
}
async function listThreatActors(filters) {
  const db = await getDb();
  if (!db) return { actors: [], total: 0 };
  const conditions = [];
  if (filters?.type && filters.type !== "all") {
    conditions.push(eq(threatActors.actorType, filters.type));
  }
  if (filters?.origin && filters.origin !== "all") {
    conditions.push(eq(threatActors.origin, filters.origin));
  }
  if (filters?.threatLevel && filters.threatLevel !== "all") {
    conditions.push(eq(threatActors.threatLevel, filters.threatLevel));
  }
  if (filters?.search) {
    conditions.push(
      sql`(${threatActors.name} LIKE ${`%${filters.search}%`} OR ${threatActors.description} LIKE ${`%${filters.search}%`} OR JSON_SEARCH(${threatActors.aliases}, 'one', ${`%${filters.search}%`}) IS NOT NULL)`
    );
  }
  const whereClause = conditions.length > 0 ? and(...conditions) : void 0;
  const [countResult] = await db.select({ count: sql`COUNT(*)` }).from(threatActors).where(whereClause);
  const actors = await db.select().from(threatActors).where(whereClause).orderBy(desc(threatActors.confidence)).limit(filters?.limit || 50).offset(filters?.offset || 0);
  return { actors, total: Number(countResult.count) };
}
async function getThreatActor(actorId) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId));
  return results[0] || null;
}
async function getThreatActorById(id) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(threatActors).where(eq(threatActors.id, id));
  return results[0] || null;
}
async function updateThreatActor(actorId, updates) {
  const db = await getDbRequired();
  await db.update(threatActors).set(updates).where(eq(threatActors.actorId, actorId));
}
async function getThreatActorStats() {
  const db = await getDb();
  if (!db) return { total: 0, byType: [], byOrigin: [], byThreatLevel: [] };
  const [total] = await db.select({ count: sql`COUNT(*)` }).from(threatActors);
  const byType = await db.select({
    type: threatActors.actorType,
    count: sql`COUNT(*)`
  }).from(threatActors).groupBy(threatActors.actorType);
  const byOrigin = await db.select({
    origin: threatActors.origin,
    count: sql`COUNT(*)`
  }).from(threatActors).groupBy(threatActors.origin).orderBy(sql`COUNT(*) DESC`).limit(15);
  const byThreatLevel = await db.select({
    level: threatActors.threatLevel,
    count: sql`COUNT(*)`
  }).from(threatActors).groupBy(threatActors.threatLevel);
  return { total: Number(total.count), byType, byOrigin, byThreatLevel };
}
async function getThreatActorCount() {
  const db = await getDb();
  if (!db) return 0;
  const [result] = await db.select({ count: sql`COUNT(*)` }).from(threatActors);
  return Number(result.count);
}
async function listThreatActorAbilities(actorId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatActorAbilities).where(eq(threatActorAbilities.actorId, actorId));
}
async function createThreatActorAbility(ability) {
  const db = await getDbRequired();
  const result = await db.insert(threatActorAbilities).values(ability);
  return Number(result[0].insertId);
}
async function listAllAbilities(filters) {
  const db = await getDb();
  if (!db) return { abilities: [], total: 0 };
  const conditions = [];
  if (filters?.tactic && filters.tactic !== "all") {
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
  const whereClause = conditions.length > 0 ? and(...conditions) : void 0;
  const [countResult] = await db.select({ count: sql`COUNT(*)` }).from(threatActorAbilities).where(whereClause);
  const abilities = await db.select().from(threatActorAbilities).where(whereClause).limit(filters?.limit || 50).offset(filters?.offset || 0);
  return { abilities, total: Number(countResult.count) };
}
async function listThreatActorIocs(actorId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatActorIocs).where(eq(threatActorIocs.actorId, actorId));
}
async function createThreatActorIoc(ioc) {
  const db = await getDbRequired();
  const result = await db.insert(threatActorIocs).values(ioc);
  return Number(result[0].insertId);
}
async function bulkCreateThreatActorIocs(iocs) {
  const db = await getDbRequired();
  if (iocs.length === 0) return;
  await db.insert(threatActorIocs).values(iocs);
}
async function createIocFeedEntry(entry) {
  const db = await getDbRequired();
  const result = await db.insert(iocFeeds).values(entry);
  return Number(result[0].insertId);
}
async function bulkCreateIocFeedEntries(entries) {
  const db = await getDbRequired();
  if (entries.length === 0) return;
  await db.insert(iocFeeds).values(entries);
}
async function listIocFeedEntries(filters) {
  const db = await getDb();
  if (!db) return { entries: [], total: 0 };
  const conditions = [];
  if (filters?.feedSource && filters.feedSource !== "all") {
    conditions.push(eq(iocFeeds.feedSource, filters.feedSource));
  }
  if (filters?.severity && filters.severity !== "all") {
    conditions.push(eq(iocFeeds.feedSeverity, filters.severity));
  }
  if (filters?.search) {
    conditions.push(
      sql`(${iocFeeds.title} LIKE ${`%${filters.search}%`} OR ${iocFeeds.iocValue} LIKE ${`%${filters.search}%`})`
    );
  }
  const whereClause = conditions.length > 0 ? and(...conditions) : void 0;
  const [countResult] = await db.select({ count: sql`COUNT(*)` }).from(iocFeeds).where(whereClause);
  const entries = await db.select().from(iocFeeds).where(whereClause).orderBy(desc(iocFeeds.createdAt)).limit(filters?.limit || 50).offset(filters?.offset || 0);
  return { entries, total: Number(countResult.count) };
}
async function getIocFeedStats() {
  const db = await getDb();
  if (!db) return { total: 0, bySource: [], bySeverity: [], recentCount: 0 };
  const [total] = await db.select({ count: sql`COUNT(*)` }).from(iocFeeds);
  const bySource = await db.select({
    source: iocFeeds.feedSource,
    count: sql`COUNT(*)`
  }).from(iocFeeds).groupBy(iocFeeds.feedSource);
  const bySeverity = await db.select({
    severity: iocFeeds.feedSeverity,
    count: sql`COUNT(*)`
  }).from(iocFeeds).groupBy(iocFeeds.feedSeverity);
  const [recent] = await db.select({ count: sql`COUNT(*)` }).from(iocFeeds).where(sql`${iocFeeds.createdAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);
  return { total: Number(total.count), bySource, bySeverity, recentCount: Number(recent.count) };
}
async function createEngagementPipeline(pipeline) {
  const db = await getDbRequired();
  const result = await db.insert(engagementPipelines).values({
    userId: pipeline.userId,
    pipelineName: pipeline.name,
    pipelineStatus: pipeline.status || "pending",
    targetDomains: pipeline.targetDomains,
    pipelineClientType: pipeline.clientType,
    orgProfile: pipeline.orgProfile,
    recommendedActors: pipeline.recommendedActors,
    engagementId: pipeline.engagementId,
    currentStep: pipeline.currentStep ?? 0,
    totalSteps: pipeline.totalSteps ?? 6,
    stepLog: pipeline.stepLog,
    errorMessage: pipeline.errorMessage
  });
  return Number(result[0].insertId);
}
async function getEngagementPipeline(id) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(engagementPipelines).where(eq(engagementPipelines.id, id));
  return results[0] || null;
}
async function updateEngagementPipeline(id, updates) {
  const db = await getDbRequired();
  const mapped = {};
  if (updates.name !== void 0) mapped.pipelineName = updates.name;
  if (updates.status !== void 0) mapped.pipelineStatus = updates.status;
  if (updates.clientType !== void 0) mapped.pipelineClientType = updates.clientType;
  for (const key of ["userId", "targetDomains", "orgProfile", "recommendedActors", "engagementId", "currentStep", "totalSteps", "stepLog", "errorMessage", "completedAt", "riskSummary", "pipelineName", "pipelineStatus", "pipelineClientType", "calderaOperationId", "calderaAdversaryId", "calderaAbilitiesDeployed", "gophishCampaignId", "gophishTemplateId", "gophishLandingPageId", "intelScanId"]) {
    if (updates[key] !== void 0 && !(key in mapped)) mapped[key] = updates[key];
  }
  await db.update(engagementPipelines).set(mapped).where(eq(engagementPipelines.id, id));
}
async function listEngagementPipelines(limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementPipelines).orderBy(desc(engagementPipelines.createdAt)).limit(limit);
}
async function createIocSyncLog(log) {
  const db = await getDbRequired();
  const result = await db.insert(iocSyncLogs).values(log);
  return Number(result[0].insertId);
}
async function updateIocSyncLog(id, updates) {
  const db = await getDbRequired();
  await db.update(iocSyncLogs).set(updates).where(eq(iocSyncLogs.id, id));
}
async function listIocSyncLogs(limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(iocSyncLogs).orderBy(desc(iocSyncLogs.createdAt)).limit(limit);
}
async function getLastIocSync() {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(iocSyncLogs).where(eq(iocSyncLogs.status, "completed")).orderBy(desc(iocSyncLogs.completedAt)).limit(1);
  return rows[0] || null;
}
async function createThreatActor(actor) {
  const db = await getDbRequired();
  const result = await db.insert(threatActors).values(actor);
  return Number(result[0].insertId);
}
async function upsertThreatActor(actor) {
  const db = await getDbRequired();
  const existing = await db.select().from(threatActors).where(eq(threatActors.actorId, actor.actorId));
  if (existing.length > 0) {
    const updates = {};
    if (actor.calderaProfile) updates.calderaProfile = actor.calderaProfile;
    if (actor.description && !existing[0].description) updates.description = actor.description;
    if (actor.tools) updates.tools = actor.tools;
    if (Object.keys(updates).length > 0) {
      await db.update(threatActors).set(updates).where(eq(threatActors.actorId, actor.actorId));
    }
    return existing[0].id;
  }
  const result = await db.insert(threatActors).values(actor);
  return Number(result[0].insertId);
}
async function bulkUpsertThreatActors(actors) {
  const results = [];
  for (const actor of actors) {
    try {
      const id = await upsertThreatActor(actor);
      results.push({ actorId: actor.actorId, id, action: id ? "created" : "updated" });
    } catch (err) {
      console.warn(`[DB] Failed to upsert threat actor ${actor.actorId}:`, err.message);
      results.push({ actorId: actor.actorId, id: 0, action: "skipped" });
    }
  }
  return results;
}
async function upsertTtpKnowledge(entry) {
  const db = await getDbRequired();
  const existing = await db.select().from(ttpKnowledge).where(eq(ttpKnowledge.techniqueId, entry.techniqueId));
  if (existing.length > 0) {
    await db.update(ttpKnowledge).set({ ...entry, updatedAt: /* @__PURE__ */ new Date() }).where(eq(ttpKnowledge.techniqueId, entry.techniqueId));
    return existing[0].id;
  }
  const result = await db.insert(ttpKnowledge).values(entry);
  return Number(result[0].insertId);
}
async function getTtpKnowledge(techniqueId) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(ttpKnowledge).where(eq(ttpKnowledge.techniqueId, techniqueId));
  return rows[0] || null;
}
async function listTtpKnowledge(filters) {
  const db = await getDb();
  if (!db) return { entries: [], total: 0 };
  const conditions = [];
  if (filters?.tactic) conditions.push(eq(ttpKnowledge.tactic, filters.tactic));
  if (filters?.search) {
    conditions.push(
      sql`(${ttpKnowledge.techniqueId} LIKE ${`%${filters.search}%`} OR ${ttpKnowledge.techniqueName} LIKE ${`%${filters.search}%`})`
    );
  }
  const whereClause = conditions.length > 0 ? and(...conditions) : void 0;
  const [countResult] = await db.select({ count: sql`COUNT(*)` }).from(ttpKnowledge).where(whereClause);
  const entries = await db.select().from(ttpKnowledge).where(whereClause).orderBy(ttpKnowledge.techniqueId).limit(filters?.limit || 50).offset(filters?.offset || 0);
  return { entries, total: Number(countResult.count) };
}
async function getTtpKnowledgeStats() {
  const db = await getDb();
  if (!db) return { total: 0, byTactic: [], enriched: 0 };
  const [total] = await db.select({ count: sql`COUNT(*)` }).from(ttpKnowledge);
  const byTactic = await db.select({
    tactic: ttpKnowledge.tactic,
    count: sql`COUNT(*)`
  }).from(ttpKnowledge).groupBy(ttpKnowledge.tactic);
  const [enriched] = await db.select({ count: sql`COUNT(*)` }).from(ttpKnowledge).where(sql`${ttpKnowledge.detectionRules} IS NOT NULL AND JSON_LENGTH(${ttpKnowledge.detectionRules}) > 0`);
  return { total: Number(total.count), byTactic, enriched: Number(enriched.count) };
}
async function createFalsePositive(fp) {
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
    markedBy: fp.markedBy
  });
  return result.insertId;
}
async function reinstateFalsePositive(fpId, reinstatedBy, reason) {
  const db = await getDbRequired();
  await db.update(falsePositiveFindings).set({
    status: "reinstated",
    reinstatedBy,
    reinstatedAt: /* @__PURE__ */ new Date(),
    reinstatedReason: reason
  }).where(eq(falsePositiveFindings.id, fpId));
}
async function getFalsePositivesByScan(scanId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(falsePositiveFindings).where(eq(falsePositiveFindings.scanId, scanId)).orderBy(sql`${falsePositiveFindings.markedAt} DESC`);
}
async function getAllFalsePositives() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(falsePositiveFindings).orderBy(sql`${falsePositiveFindings.markedAt} DESC`).limit(500);
}
async function getActiveFPHashes() {
  const db = await getDb();
  if (!db) return [];
  const results = await db.select({
    hash: falsePositiveFindings.findingHash,
    title: falsePositiveFindings.findingTitle,
    reason: falsePositiveFindings.reason,
    count: sql`COUNT(*)`
  }).from(falsePositiveFindings).where(eq(falsePositiveFindings.fpStatus, "false_positive")).groupBy(falsePositiveFindings.findingHash, falsePositiveFindings.findingTitle, falsePositiveFindings.reason);
  return results.map((r) => ({ hash: r.hash, title: r.title, reason: r.reason, count: Number(r.count) }));
}
async function getFPContextForLLM() {
  const db = await getDb();
  if (!db) return { totalFPs: 0, patterns: [], categorySummary: [] };
  const patterns = await db.select({
    title: falsePositiveFindings.findingTitle,
    type: falsePositiveFindings.findingType,
    severity: falsePositiveFindings.findingSeverity,
    reason: falsePositiveFindings.reason,
    occurrences: sql`COUNT(*)`
  }).from(falsePositiveFindings).where(eq(falsePositiveFindings.fpStatus, "false_positive")).groupBy(
    falsePositiveFindings.findingTitle,
    falsePositiveFindings.findingType,
    falsePositiveFindings.findingSeverity,
    falsePositiveFindings.reason
  ).orderBy(sql`COUNT(*) DESC`).limit(50);
  const categorySummary = await db.select({
    type: falsePositiveFindings.findingType,
    count: sql`COUNT(*)`
  }).from(falsePositiveFindings).where(eq(falsePositiveFindings.fpStatus, "false_positive")).groupBy(falsePositiveFindings.findingType).orderBy(sql`COUNT(*) DESC`);
  const [totalRow] = await db.select({ count: sql`COUNT(*)` }).from(falsePositiveFindings).where(eq(falsePositiveFindings.fpStatus, "false_positive"));
  return {
    totalFPs: Number(totalRow.count),
    patterns: patterns.map((p) => ({
      title: p.title,
      type: p.type,
      severity: p.severity,
      reason: p.reason,
      occurrences: Number(p.occurrences)
    })),
    categorySummary: categorySummary.map((c) => ({
      type: c.type || "unknown",
      count: Number(c.count),
      fpRate: "N/A"
      // Will be calculated when we have total findings per category
    }))
  };
}
async function isFindingFalsePositive(findingHash) {
  const db = await getDb();
  if (!db) return false;
  const [result] = await db.select({ count: sql`COUNT(*)` }).from(falsePositiveFindings).where(and(
    eq(falsePositiveFindings.findingHash, findingHash),
    eq(falsePositiveFindings.fpStatus, "false_positive")
  ));
  return Number(result.count) > 0;
}
async function batchCheckFalsePositives(hashes) {
  const db = await getDb();
  if (!db) return /* @__PURE__ */ new Set();
  if (hashes.length === 0) return /* @__PURE__ */ new Set();
  const results = await db.select({ hash: falsePositiveFindings.findingHash }).from(falsePositiveFindings).where(and(
    inArray(falsePositiveFindings.findingHash, hashes),
    eq(falsePositiveFindings.fpStatus, "false_positive")
  ));
  return new Set(results.map((r) => r.hash));
}
function generateShareToken() {
  return crypto.randomBytes(32).toString("base64url");
}
async function createEngagementShare(share) {
  const db = await getDb();
  if (!db) return void 0;
  const token = generateShareToken();
  const result = await db.insert(engagementShares).values({ ...share, token });
  const insertId = result[0].insertId;
  const [created] = await db.select().from(engagementShares).where(eq(engagementShares.id, insertId));
  return created;
}
async function getEngagementShareByToken(token) {
  const db = await getDb();
  if (!db) return void 0;
  const [share] = await db.select().from(engagementShares).where(eq(engagementShares.token, token));
  return share;
}
async function getEngagementSharesByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementShares).where(eq(engagementShares.engagementId, engagementId)).orderBy(desc(engagementShares.createdAt));
}
async function updateEngagementShare(id, updates) {
  const db = await getDb();
  if (!db) return;
  await db.update(engagementShares).set(updates).where(eq(engagementShares.id, id));
}
async function deleteEngagementShare(id) {
  const db = await getDb();
  if (!db) return;
  await db.delete(engagementShares).where(eq(engagementShares.id, id));
}
async function incrementShareViewCount(id) {
  const db = await getDb();
  if (!db) return;
  await db.update(engagementShares).set({
    viewCount: sql`${engagementShares.viewCount} + 1`,
    lastAccessedAt: /* @__PURE__ */ new Date()
  }).where(eq(engagementShares.id, id));
}
async function getAllEngagementShares() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(engagementShares).orderBy(desc(engagementShares.createdAt));
}
async function insertScoringAuditEntry(entry) {
  const db = await getDb();
  if (!db) return;
  await db.insert(scoringAuditLog).values(entry);
}
async function bulkInsertScoringAuditEntries(entries) {
  const db = await getDb();
  if (!db) return;
  if (entries.length === 0) return;
  const BATCH_SIZE = 20;
  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);
    await db.insert(scoringAuditLog).values(batch);
  }
}
async function getScoringTimelineByAsset(assetId, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scoringAuditLog).where(eq(scoringAuditLog.assetId, assetId)).orderBy(desc(scoringAuditLog.computedAt)).limit(limit);
}
async function getScoringTimelineByScan(scanId, limit = 200) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scoringAuditLog).where(eq(scoringAuditLog.scanId, scanId)).orderBy(desc(scoringAuditLog.computedAt)).limit(limit);
}
async function lookupKevByCve(cveId) {
  const db = await getDb();
  if (!db) return null;
  const [entry] = await db.select().from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), eq(iocFeeds.cveId, cveId))).limit(1);
  return entry || null;
}
async function batchLookupKev(cveIds) {
  const db = await getDb();
  const result = /* @__PURE__ */ new Map();
  if (!db || cveIds.length === 0) return result;
  const entries = await db.select().from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), inArray(iocFeeds.cveId, cveIds)));
  for (const entry of entries) {
    if (entry.cveId) result.set(entry.cveId, entry);
  }
  return result;
}
async function insertChainRun(data) {
  const db = await getDb();
  if (!db) return null;
  await db.insert(chainRuns).values(data);
  const [row] = await db.select().from(chainRuns).where(eq(chainRuns.chainId, data.chainId)).limit(1);
  return row || null;
}
async function updateChainRunDb(chainId, data) {
  const db = await getDb();
  if (!db) return;
  await db.update(chainRuns).set(data).where(eq(chainRuns.chainId, chainId));
}
async function getChainRunByChainId(chainId) {
  const db = await getDb();
  if (!db) return null;
  const [row] = await db.select().from(chainRuns).where(eq(chainRuns.chainId, chainId)).limit(1);
  return row || null;
}
async function listChainRunsDb(filter) {
  const db = await getDb();
  if (!db) return { total: 0, runs: [] };
  const conditions = [];
  if (filter?.status) conditions.push(eq(chainRuns.status, filter.status));
  if (filter?.engagementId) conditions.push(eq(chainRuns.engagementId, filter.engagementId));
  const whereClause = conditions.length > 0 ? and(...conditions) : void 0;
  const [countResult] = await db.select({ count: sql`COUNT(*)` }).from(chainRuns).where(whereClause);
  const rows = await db.select().from(chainRuns).where(whereClause).orderBy(desc(chainRuns.startedAt)).limit(filter?.limit || 25).offset(filter?.offset || 0);
  return { total: Number(countResult?.count || 0), runs: rows };
}
async function deleteChainRunDb(chainId) {
  const db = await getDb();
  if (!db) return;
  await db.delete(chainStageResults).where(eq(chainStageResults.chainId, chainId));
  await db.delete(chainRuns).where(eq(chainRuns.chainId, chainId));
}
async function upsertChainStageResultDb(data) {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select().from(chainStageResults).where(and(eq(chainStageResults.chainId, data.chainId), eq(chainStageResults.stageId, data.stageId))).limit(1);
  if (existing.length > 0) {
    await db.update(chainStageResults).set(data).where(and(eq(chainStageResults.chainId, data.chainId), eq(chainStageResults.stageId, data.stageId)));
  } else {
    await db.insert(chainStageResults).values(data);
  }
}
async function getChainStageResultsDb(chainId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(chainStageResults).where(eq(chainStageResults.chainId, chainId));
}
async function getKevStats() {
  const db = await getDb();
  if (!db) return { totalKev: 0, ransomwareLinked: 0, overdueByDeadline: 0, recentlyAdded: 0 };
  const [total] = await db.select({ count: sql`COUNT(*)` }).from(iocFeeds).where(eq(iocFeeds.feedSource, "cisa_kev"));
  const [ransomware] = await db.select({ count: sql`COUNT(*)` }).from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), eq(iocFeeds.knownRansomware, true)));
  const now = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
  const [overdue] = await db.select({ count: sql`COUNT(*)` }).from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), sql`${iocFeeds.dueDate} < ${now}`));
  const [recent] = await db.select({ count: sql`COUNT(*)` }).from(iocFeeds).where(and(eq(iocFeeds.feedSource, "cisa_kev"), sql`${iocFeeds.createdAt} > DATE_SUB(NOW(), INTERVAL 7 DAY)`));
  return {
    totalKev: Number(total?.count || 0),
    ransomwareLinked: Number(ransomware?.count || 0),
    overdueByDeadline: Number(overdue?.count || 0),
    recentlyAdded: Number(recent?.count || 0)
  };
}
async function createCarverRiskCard(card) {
  const db = await getDbRequired();
  const [result] = await db.insert(carverRiskCards).values(card);
  return result.insertId;
}
async function createCarverRiskCardsBatch(cards) {
  if (cards.length === 0) return 0;
  const db = await getDbRequired();
  const [result] = await db.insert(carverRiskCards).values(cards);
  return result.affectedRows;
}
async function getCarverRiskCards(opts) {
  const db = await getDb();
  if (!db) return [];
  let query = db.select().from(carverRiskCards);
  const conditions = [];
  if (opts?.batchId) conditions.push(eq(carverRiskCards.batchId, opts.batchId));
  if (opts?.domain) conditions.push(eq(carverRiskCards.domain, opts.domain));
  if (opts?.sector) conditions.push(eq(carverRiskCards.inferredSector, opts.sector));
  if (conditions.length > 0) query = query.where(and(...conditions));
  return query.orderBy(desc(carverRiskCards.createdAt)).limit(opts?.limit || 500).offset(opts?.offset || 0);
}
async function getCarverRiskCardById(id) {
  const db = await getDb();
  if (!db) return void 0;
  const [card] = await db.select().from(carverRiskCards).where(eq(carverRiskCards.id, id));
  return card;
}
async function getCarverRiskCardsByBatch(batchId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(carverRiskCards).where(eq(carverRiskCards.batchId, batchId)).orderBy(desc(carverRiskCards.createdAt));
}
async function getCarverRiskCardStats() {
  const db = await getDb();
  if (!db) return { total: 0, bySector: [], byTier: [], batches: [] };
  const [total] = await db.select({ count: sql`COUNT(*)` }).from(carverRiskCards);
  const bySector = await db.select({ sector: carverRiskCards.inferredSector, count: sql`COUNT(*)` }).from(carverRiskCards).groupBy(carverRiskCards.inferredSector);
  const byTier = await db.select({ tier: carverRiskCards.priorityTier, count: sql`COUNT(*)` }).from(carverRiskCards).groupBy(carverRiskCards.priorityTier);
  const batches = await db.select({ batchId: carverRiskCards.batchId, count: sql`COUNT(*)`, source: carverRiskCards.source }).from(carverRiskCards).groupBy(carverRiskCards.batchId, carverRiskCards.source);
  return { total: Number(total?.count || 0), bySector, byTier, batches };
}
async function deleteCarverRiskCard(id) {
  const db = await getDbRequired();
  await db.delete(carverRiskCards).where(eq(carverRiskCards.id, id));
}
async function deleteCarverRiskCardsByBatch(batchId) {
  const db = await getDbRequired();
  await db.delete(carverRiskCards).where(eq(carverRiskCards.batchId, batchId));
}
async function createCredentialAttackRun(run) {
  const db = await getDbRequired();
  const result = await db.insert(credentialAttackRuns).values(run);
  return result[0].insertId;
}
async function updateCredentialAttackRun(id, updates) {
  const db = await getDbRequired();
  await db.update(credentialAttackRuns).set(updates).where(eq(credentialAttackRuns.id, id));
}
async function getCredentialAttackRuns(userId, limit = 50) {
  const db = await getDbRequired();
  return db.select().from(credentialAttackRuns).where(eq(credentialAttackRuns.userId, userId)).orderBy(desc(credentialAttackRuns.createdAt)).limit(limit);
}
async function getCredentialAttackRunById(id) {
  const db = await getDbRequired();
  const rows = await db.select().from(credentialAttackRuns).where(eq(credentialAttackRuns.id, id));
  return rows[0] ?? null;
}
async function getCredentialAttackRunsByDomainScan(scanId) {
  const db = await getDbRequired();
  return db.select().from(credentialAttackRuns).where(eq(credentialAttackRuns.domainIntelScanId, scanId)).orderBy(desc(credentialAttackRuns.createdAt));
}
async function createCredentialFinding(finding) {
  const db = await getDbRequired();
  const result = await db.insert(credentialFindings).values(finding);
  return result[0].insertId;
}
async function createCredentialFindings(findings) {
  if (findings.length === 0) return;
  const db = await getDbRequired();
  await db.insert(credentialFindings).values(findings);
}
async function getCredentialFindingsByRun(runId) {
  const db = await getDbRequired();
  return db.select().from(credentialFindings).where(eq(credentialFindings.attackRunId, runId)).orderBy(desc(credentialFindings.discoveredAt));
}
async function getCredentialFindingsByDomainScan(scanId) {
  const db = await getDbRequired();
  return db.select().from(credentialFindings).where(eq(credentialFindings.domainIntelScanId, scanId)).orderBy(desc(credentialFindings.discoveredAt));
}
async function getAllCredentialFindings(userId, limit = 100) {
  const db = await getDbRequired();
  return db.select().from(credentialFindings).where(eq(credentialFindings.userId, userId)).orderBy(desc(credentialFindings.discoveredAt)).limit(limit);
}
async function createZapProxySession(session) {
  const db = await getDbRequired();
  const result = await db.insert(zapProxySessions).values(session);
  return result[0].insertId;
}
async function updateZapProxySession(id, updates) {
  const db = await getDbRequired();
  await db.update(zapProxySessions).set(updates).where(eq(zapProxySessions.id, id));
}
async function getZapProxySessions(userId, limit = 50) {
  const db = await getDbRequired();
  return db.select().from(zapProxySessions).where(eq(zapProxySessions.userId, userId)).orderBy(desc(zapProxySessions.createdAt)).limit(limit);
}
async function getZapProxySessionById(id) {
  const db = await getDbRequired();
  const rows = await db.select().from(zapProxySessions).where(eq(zapProxySessions.id, id));
  return rows[0] ?? null;
}
async function getZapSessionsByDomainScan(scanId) {
  const db = await getDbRequired();
  return db.select().from(zapProxySessions).where(eq(zapProxySessions.domainIntelScanId, scanId)).orderBy(desc(zapProxySessions.createdAt));
}
async function createPentestReport(report) {
  const db = await getDbRequired();
  const result = await db.insert(pentestReports).values(report);
  return result[0].insertId;
}
async function updatePentestReport(id, updates) {
  const db = await getDbRequired();
  await db.update(pentestReports).set(updates).where(eq(pentestReports.id, id));
}
async function getPentestReports(userId, limit = 50) {
  const db = await getDbRequired();
  return db.select().from(pentestReports).where(eq(pentestReports.userId, userId)).orderBy(desc(pentestReports.createdAt)).limit(limit);
}
async function getPentestReportById(id) {
  const db = await getDbRequired();
  const rows = await db.select().from(pentestReports).where(eq(pentestReports.id, id));
  return rows[0] ?? null;
}
async function deletePentestReport(id) {
  const db = await getDbRequired();
  await db.delete(pentestReports).where(eq(pentestReports.id, id));
}
async function saveCredentialAttackWithTool(run) {
  const db = await getDbRequired();
  const result = await db.insert(credentialAttackRuns).values(run);
  return result[0].insertId;
}
async function saveCredentialFindingWithTool(finding) {
  const db = await getDbRequired();
  const result = await db.insert(credentialFindings).values(finding);
  return result[0].insertId;
}
async function getCredentialAttackHistory(userId, opts) {
  const db = await getDbRequired();
  const conditions = [eq(credentialAttackRuns.userId, userId)];
  if (opts?.tool) {
    conditions.push(eq(credentialAttackRuns.tool, opts.tool));
  }
  if (opts?.protocol) {
    conditions.push(eq(credentialAttackRuns.protocol, opts.protocol));
  }
  if (opts?.status) {
    conditions.push(eq(credentialAttackRuns.status, opts.status));
  }
  return db.select().from(credentialAttackRuns).where(and(...conditions)).orderBy(desc(credentialAttackRuns.createdAt)).limit(opts?.limit ?? 50).offset(opts?.offset ?? 0);
}
async function getCredentialAttackHistoryCount(userId, opts) {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  const conditions = [eq(credentialAttackRuns.userId, userId)];
  if (opts?.tool) {
    conditions.push(eq(credentialAttackRuns.tool, opts.tool));
  }
  if (opts?.protocol) {
    conditions.push(eq(credentialAttackRuns.protocol, opts.protocol));
  }
  if (opts?.status) {
    conditions.push(eq(credentialAttackRuns.status, opts.status));
  }
  const result = await db.select({ count: sqlTag`COUNT(*)`.as("count") }).from(credentialAttackRuns).where(and(...conditions));
  return Number(result[0]?.count ?? 0);
}
async function getCredentialFindingsHistory(userId, opts) {
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
  return db.select().from(credentialFindings).where(and(...conditions)).orderBy(desc(credentialFindings.discoveredAt)).limit(opts?.limit ?? 100).offset(opts?.offset ?? 0);
}
async function updateCredentialFindingValidation(id, validationStatus, validatedBy, notes) {
  const db = await getDbRequired();
  await db.update(credentialFindings).set({
    validationStatus,
    notes: notes ?? void 0
  }).where(eq(credentialFindings.id, id));
}
async function getCredentialAttackStats(userId) {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  const runs = await db.select({
    tool: credentialAttackRuns.tool,
    totalRuns: sqlTag`COUNT(*)`.as("total_runs"),
    totalAttempts: sqlTag`SUM(${credentialAttackRuns.totalAttempts})`.as("total_attempts"),
    totalSuccessful: sqlTag`SUM(${credentialAttackRuns.successfulAttempts})`.as("total_successful"),
    avgDuration: sqlTag`AVG(${credentialAttackRuns.durationMs})`.as("avg_duration")
  }).from(credentialAttackRuns).where(eq(credentialAttackRuns.userId, userId)).groupBy(credentialAttackRuns.tool);
  const findings = await db.select({
    tool: credentialFindings.tool,
    totalFindings: sqlTag`COUNT(*)`.as("total_findings"),
    validated: sqlTag`SUM(CASE WHEN ${credentialFindings.validationStatus} = 'validated' THEN 1 ELSE 0 END)`.as("validated"),
    falsePositives: sqlTag`SUM(CASE WHEN ${credentialFindings.validationStatus} = 'false_positive' THEN 1 ELSE 0 END)`.as("false_positives")
  }).from(credentialFindings).where(eq(credentialFindings.userId, userId)).groupBy(credentialFindings.tool);
  return { runs, findings };
}
function decryptCredential(encryptedText) {
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
async function listPlatformCredentials(userId) {
  const db = await getDb();
  if (!db) return [];
  const numericUserId = typeof userId === "string" ? parseInt(userId, 10) : userId;
  if (isNaN(numericUserId)) return [];
  const rows = await db.select().from(userPlatformCredentials).where(
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
    metadata: row.metadata
  }));
}
async function insertScanResult(data) {
  const db = await getDb();
  if (!db) return null;
  const [existing] = await db.select({ id: scanResults.id }).from(scanResults).where(and(
    eq(scanResults.engagementId, data.engagementId),
    eq(scanResults.tool, data.tool),
    eq(scanResults.target, data.target)
  )).limit(1);
  if (existing) {
    await db.update(scanResults).set({
      rawOutput: data.rawOutput,
      rawStderr: data.rawStderr,
      exitCode: data.exitCode,
      durationMs: data.durationMs,
      timedOut: data.timedOut,
      findings: data.findings,
      findingCount: data.findingCount,
      severitySummary: data.severitySummary,
      command: data.command
    }).where(eq(scanResults.id, existing.id));
    const [result2] = await db.select().from(scanResults).where(eq(scanResults.id, existing.id));
    return result2;
  }
  const insertResult = await db.insert(scanResults).values(data);
  const insertedId = Number(insertResult[0].insertId);
  if (!insertedId) return null;
  const [result] = await db.select().from(scanResults).where(eq(scanResults.id, insertedId));
  return result;
}
async function getScanResultsByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanResults).where(eq(scanResults.engagementId, engagementId)).orderBy(sql`${scanResults.createdAt} DESC`);
}
async function getScanResultsByTool(engagementId, tool) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(scanResults).where(and(eq(scanResults.engagementId, engagementId), eq(scanResults.tool, tool))).orderBy(sql`${scanResults.createdAt} DESC`);
}
async function getScanResultsSummary(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select({
    tool: scanResults.tool,
    count: sql`COUNT(*)`,
    totalFindings: sql`COALESCE(SUM(${scanResults.findingCount}), 0)`,
    avgDurationMs: sql`COALESCE(AVG(${scanResults.durationMs}), 0)`
  }).from(scanResults).where(eq(scanResults.engagementId, engagementId)).groupBy(scanResults.tool);
}
async function saveOpsSnapshot(engagementId, state) {
  const db = await getDbRequired();
  let serverInstanceId;
  try {
    const { SERVER_INSTANCE_ID } = await import("./server-instance-NCWNS3GF.js");
    serverInstanceId = SERVER_INSTANCE_ID;
  } catch {
  }
  const completedScansToSave = state.completedScans ? {
    nucleiCompleted: state.completedScans.nucleiCompleted instanceof Set ? Array.from(state.completedScans.nucleiCompleted) : state.completedScans.nucleiCompleted || [],
    zapCompleted: state.completedScans.zapCompleted instanceof Set ? Array.from(state.completedScans.zapCompleted) : state.completedScans.zapCompleted || [],
    hydraCompleted: state.completedScans.hydraCompleted instanceof Set ? Array.from(state.completedScans.hydraCompleted) : state.completedScans.hydraCompleted || [],
    exploitCompleted: state.completedScans.exploitCompleted instanceof Set ? Array.from(state.completedScans.exploitCompleted) : state.completedScans.exploitCompleted || [],
    lastCheckpointAt: state.completedScans.lastCheckpointAt || Date.now()
  } : void 0;
  const stateToSave = {
    ...state,
    skippedDomains: state.skippedDomains instanceof Set ? Array.from(state.skippedDomains) : state.skippedDomains || [],
    completedScans: completedScansToSave
  };
  const existing = await db.select({ id: engagementOpsSnapshots.id }).from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId)).limit(1);
  if (existing.length > 0) {
    await db.update(engagementOpsSnapshots).set({
      stateJson: stateToSave,
      phase: state.phase || "idle",
      isRunning: state.isRunning || false,
      assetCount: state.assets?.length || 0,
      ...serverInstanceId ? { serverInstanceId } : {}
    }).where(eq(engagementOpsSnapshots.engagementId, engagementId));
  } else {
    await db.insert(engagementOpsSnapshots).values({
      engagementId,
      stateJson: stateToSave,
      phase: state.phase || "idle",
      isRunning: state.isRunning || false,
      assetCount: state.assets?.length || 0,
      ...serverInstanceId ? { serverInstanceId } : {}
    });
  }
}
async function loadOpsSnapshot(engagementId) {
  try {
    const db = await getDbRequired();
    const rows = await db.select().from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId)).limit(1);
    if (rows.length === 0) return null;
    const snapshot = rows[0];
    const state = snapshot.stateJson;
    if (!state.engagementId) state.engagementId = engagementId;
    if (!state.phase) state.phase = "idle";
    if (state.progress === void 0) state.progress = 0;
    if (state.isRunning === void 0) state.isRunning = false;
    if (state.isPaused === void 0) state.isPaused = false;
    if (!Array.isArray(state.assets)) state.assets = [];
    if (!Array.isArray(state.log)) state.log = [];
    if (!Array.isArray(state.approvalGates)) state.approvalGates = [];
    if (!state.stats) state.stats = { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 };
    for (const asset of state.assets) {
      if (!Array.isArray(asset.ports)) asset.ports = [];
      if (!Array.isArray(asset.vulns)) asset.vulns = [];
      if (!Array.isArray(asset.zapFindings)) asset.zapFindings = [];
      if (!Array.isArray(asset.exploitAttempts)) asset.exploitAttempts = [];
      if (!Array.isArray(asset.toolResults)) asset.toolResults = [];
    }
    if (Array.isArray(state.skippedDomains)) {
      state.skippedDomains = new Set(state.skippedDomains);
    } else {
      state.skippedDomains = /* @__PURE__ */ new Set();
    }
    if (state.isRunning) {
      state.isRunning = false;
      state.phase = "error";
      state.error = "Server restarted during scan \u2014 state recovered from last snapshot. Assets are preserved. You can retry the scan.";
      const recoveryLog = {
        id: `log-${Date.now()}-recovery`,
        timestamp: Date.now(),
        phase: "recon",
        type: "warning",
        title: "\u26A0\uFE0F Scan Interrupted \u2014 State Recovered",
        detail: `The server restarted while the scan was running. ${state.assets?.length || 0} assets have been recovered from the last snapshot. You can reset and re-run the scan.`
      };
      if (!state.log) state.log = [];
      state.log.push(recoveryLog);
    }
    return state;
  } catch (e) {
    console.error(`[OpsSnapshot] Failed to load snapshot for engagement #${engagementId}:`, e.message);
    return null;
  }
}
async function deleteOpsSnapshot(engagementId) {
  try {
    const db = await getDbRequired();
    await db.delete(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.engagementId, engagementId));
  } catch (e) {
    console.error(`[OpsSnapshot] Failed to delete snapshot for engagement #${engagementId}:`, e.message);
  }
}
async function recordLlmTelemetry(entry) {
  try {
    const db = await getDb();
    await db.insert(llmTelemetry).values(entry);
  } catch (e) {
    console.warn("[LLM Telemetry] Failed to record:", e.message);
  }
}
async function getLlmTelemetrySummary(windowHours = 24) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows[0] || {};
}
async function getLlmTelemetryTimeSeries(windowHours = 24) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows;
}
async function getLlmTelemetryTopCallers(windowHours = 24, limit = 15) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows;
}
async function getLlmTelemetryRecentErrors(limit = 20) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
    SELECT
      id, called_at, caller, model, llm_status, http_status,
      latency_ms, retry_count, error_message, engagement_id
    FROM llm_telemetry
    WHERE llm_status IN ('error', 'timeout')
    ORDER BY called_at DESC
    LIMIT ${limit}
  `);
  return rows;
}
async function getLlmTelemetryLatencyDistribution(windowHours = 24) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows;
}
async function getLlmTelemetryModelUsage(windowHours = 24) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows;
}
function estimateCost(model, tokensIn, tokensOut) {
  const pricing = LLM_PRICING[model] || LLM_PRICING.default;
  return tokensIn / 1e6 * pricing.inputPer1M + tokensOut / 1e6 * pricing.outputPer1M;
}
async function getEngagementLlmCost(engagementId) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  const row = rows[0] || {};
  const tokensIn = Number(row.total_tokens_in) || 0;
  const tokensOut = Number(row.total_tokens_out) || 0;
  return {
    ...row,
    total_tokens_in: tokensIn,
    total_tokens_out: tokensOut,
    total_tokens: Number(row.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", tokensIn, tokensOut)
  };
}
async function getEngagementLlmCostBreakdown(engagementId) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows.map((r) => ({
    ...r,
    tokens_in: Number(r.tokens_in) || 0,
    tokens_out: Number(r.tokens_out) || 0,
    total_tokens: Number(r.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", Number(r.tokens_in) || 0, Number(r.tokens_out) || 0)
  }));
}
async function getAllEngagementLlmCosts(limit = 50) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows.map((r) => ({
    ...r,
    engagement_id: Number(r.engagement_id),
    tokens_in: Number(r.tokens_in) || 0,
    tokens_out: Number(r.tokens_out) || 0,
    total_tokens: Number(r.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", Number(r.tokens_in) || 0, Number(r.tokens_out) || 0)
  }));
}
async function getEngagementLlmCostTimeSeries(engagementId) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows.map((r) => ({
    ...r,
    tokens_in: Number(r.tokens_in) || 0,
    tokens_out: Number(r.tokens_out) || 0,
    total_tokens: Number(r.total_tokens) || 0,
    estimated_cost_usd: estimateCost("gemini-2.5-flash", Number(r.tokens_in) || 0, Number(r.tokens_out) || 0)
  }));
}
async function getEngagementLlmTelemetryRaw(engagementId, limit = 1e4) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows.map((r) => ({
    caller: r.caller || "unknown",
    model: r.model || "gemini-2.5-flash",
    llmStatus: r.llmStatus || "success",
    latencyMs: Number(r.latencyMs) || 0,
    tokensIn: Number(r.tokensIn) || 0,
    tokensOut: Number(r.tokensOut) || 0,
    calledAt: String(r.calledAt),
    engagementId: Number(r.engagementId) || engagementId,
    errorMessage: r.errorMessage || void 0
  }));
}
async function getGlobalLlmTelemetryRaw(windowHours = 168, limit = 5e4) {
  const db = await getDb();
  const { sql: sql2 } = await import("drizzle-orm");
  const [rows] = await db.execute(sql2`
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
  return rows.map((r) => ({
    caller: r.caller || "unknown",
    model: r.model || "gemini-2.5-flash",
    llmStatus: r.llmStatus || "success",
    latencyMs: Number(r.latencyMs) || 0,
    tokensIn: Number(r.tokensIn) || 0,
    tokensOut: Number(r.tokensOut) || 0,
    calledAt: String(r.calledAt),
    engagementId: r.engagementId ? Number(r.engagementId) : void 0,
    errorMessage: r.errorMessage || void 0
  }));
}
async function insertExploitPlanHistory(data) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const insertResult = await db.insert(exploitPlanHistory).values(data);
  const insertedId = Number(insertResult[0].insertId);
  return { id: insertedId };
}
async function getExploitPlanHistoryByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(exploitPlanHistory).where(eq(exploitPlanHistory.engagementId, engagementId)).orderBy(desc(exploitPlanHistory.createdAt));
}
async function getExploitPlanHistoryById(id) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(exploitPlanHistory).where(eq(exploitPlanHistory.id, id)).limit(1);
  return rows[0] || null;
}
async function getExploitPlanHistoryByGateId(gateId) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(exploitPlanHistory).where(eq(exploitPlanHistory.gateId, gateId)).limit(1);
  return rows[0] || null;
}
async function getExploitPlanStats() {
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
  const r = rows[0] || {};
  return {
    total: Number(r.total) || 0,
    approved: Number(r.approved) || 0,
    rejected: Number(r.rejected) || 0,
    modified: Number(r.modified) || 0
  };
}
async function createTrainingLabSession(data) {
  const db = await getDb();
  if (!db) return null;
  await db.insert(trainingLabSessions).values(data);
  const [row] = await db.select().from(trainingLabSessions).where(eq(trainingLabSessions.sessionId, data.sessionId)).limit(1);
  return row || null;
}
async function updateTrainingLabSession(sessionId, update) {
  const db = await getDbRequired();
  await db.update(trainingLabSessions).set(update).where(eq(trainingLabSessions.sessionId, sessionId));
}
async function getTrainingLabSession(sessionId) {
  const db = await getDb();
  if (!db) return null;
  const [row] = await db.select().from(trainingLabSessions).where(eq(trainingLabSessions.sessionId, sessionId)).limit(1);
  return row || null;
}
async function listTrainingLabSessions(limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(trainingLabSessions).orderBy(desc(trainingLabSessions.id)).limit(limit);
}
async function insertTrainingLabFeedbackEntry(data) {
  const db = await getDbRequired();
  await db.insert(trainingLabFeedback).values(data);
}
async function getTrainingLabFeedbackForSession(sessionId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(trainingLabFeedback).where(eq(trainingLabFeedback.sessionId, sessionId));
}
async function getHistoricalScanContext(primaryDomain, excludeScanId) {
  const db = await getDb();
  if (!db) return null;
  const conditions = [
    eq(domainIntelScans.primaryDomain, primaryDomain),
    or(
      eq(domainIntelScans.status, "completed"),
      eq(domainIntelScans.status, "scan_complete")
    )
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
    createdAt: domainIntelScans.createdAt
  }).from(domainIntelScans).where(and(...conditions)).orderBy(desc(domainIntelScans.createdAt)).limit(1);
  if (previousScans.length === 0) return null;
  const prevScan = previousScans[0];
  const countResult = await db.select({
    count: sql`COUNT(*)`
  }).from(domainIntelScans).where(eq(domainIntelScans.primaryDomain, primaryDomain));
  const scanCount = countResult[0]?.count || 1;
  const prevAssets = await db.select({
    hostname: discoveredAssets.hostname,
    assetType: discoveredAssets.assetType,
    hybridRiskScore: discoveredAssets.hybridRiskScore,
    riskBand: discoveredAssets.riskBand,
    technologies: discoveredAssets.technologies,
    postureFindings: discoveredAssets.postureFindings,
    vulnRiskScore: discoveredAssets.vulnRiskScore,
    excluded: discoveredAssets.excluded
  }).from(discoveredAssets).where(and(
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
    previousAssets: prevAssets.map((a) => ({
      hostname: a.hostname,
      assetType: a.assetType,
      hybridRiskScore: a.hybridRiskScore,
      riskBand: a.riskBand,
      technologies: a.technologies,
      postureFindings: a.postureFindings,
      vulnRiskScore: a.vulnRiskScore,
      excluded: !!a.excluded
    })),
    scanCount
  };
}
function buildHistoricalContextString(ctx) {
  const parts = [
    `
--- HISTORICAL SCAN CONTEXT (previous scan from ${ctx.previousScanDate}) ---`,
    `This is scan #${ctx.scanCount} for this domain. Previous scan ID: ${ctx.previousScanId}.`,
    `Previous overall risk: ${ctx.previousRiskScore ?? "N/A"}/100 (${ctx.previousRiskBand ?? "N/A"})`,
    `Previous assets: ${ctx.previousTotalAssets ?? 0}, findings: ${ctx.previousTotalFindings ?? 0} (${ctx.previousConfirmedFindings ?? 0} confirmed)`
  ];
  if (ctx.previousAssets.length > 0) {
    const highRisk = ctx.previousAssets.filter((a) => (a.hybridRiskScore ?? 0) >= 60);
    const medRisk = ctx.previousAssets.filter((a) => (a.hybridRiskScore ?? 0) >= 30 && (a.hybridRiskScore ?? 0) < 60);
    if (highRisk.length > 0) {
      parts.push(`High-risk assets from previous scan (${highRisk.length}):`);
      for (const a of highRisk.slice(0, 15)) {
        const techs = Array.isArray(a.technologies) ? a.technologies.slice(0, 5).join(", ") : "";
        const findings = Array.isArray(a.postureFindings) ? a.postureFindings.length : 0;
        parts.push(`  - ${a.hostname} [${a.assetType || "unknown"}] risk=${a.hybridRiskScore}, vulnRisk=${a.vulnRiskScore ?? "N/A"}, techs=[${techs}], findings=${findings}`);
      }
    }
    if (medRisk.length > 0) {
      parts.push(`Medium-risk assets from previous scan (${medRisk.length}): ${medRisk.slice(0, 10).map((a) => `${a.hostname}(${a.hybridRiskScore})`).join(", ")}`);
    }
    const allTechs = /* @__PURE__ */ new Set();
    for (const a of ctx.previousAssets) {
      if (Array.isArray(a.technologies)) {
        for (const t of a.technologies) allTechs.add(typeof t === "string" ? t : String(t));
      }
    }
    if (allTechs.size > 0) {
      parts.push(`Technologies observed in previous scan: ${[...allTechs].slice(0, 30).join(", ")}`);
    }
  }
  if (ctx.previousExecutiveSummary) {
    const summary = ctx.previousExecutiveSummary.length > 500 ? ctx.previousExecutiveSummary.slice(0, 500) + "..." : ctx.previousExecutiveSummary;
    parts.push(`Previous executive summary: ${summary}`);
  }
  parts.push("--- END HISTORICAL CONTEXT ---");
  parts.push("IMPORTANT: Compare your new findings against the historical data above. Flag any NEW assets or findings not seen before, and note any risk changes (improvements or regressions).");
  return parts.join("\n");
}
async function insertExploitationAttempt(data) {
  const db = await getDbRequired();
  const result = await db.insert(exploitationAttempts).values(data);
  return { id: Number(result[0].insertId) };
}
async function getExploitationAttempts(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(exploitationAttempts).where(eq(exploitationAttempts.engagementId, engagementId)).orderBy(desc(exploitationAttempts.eaAttemptedAt));
}
async function getExploitationAttemptById(id) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(exploitationAttempts).where(eq(exploitationAttempts.id, id));
  return rows[0] || null;
}
async function updateExploitationAttempt(id, updates) {
  const db = await getDbRequired();
  await db.update(exploitationAttempts).set(updates).where(eq(exploitationAttempts.id, id));
}
async function getExploitationStats(engagementId) {
  const db = await getDb();
  if (!db) return { total: 0, succeeded: 0, failed: 0, error: 0, withEvidence: 0 };
  const rows = await db.select().from(exploitationAttempts).where(eq(exploitationAttempts.engagementId, engagementId));
  return {
    total: rows.length,
    succeeded: rows.filter((r) => r.eaStatus === "succeeded").length,
    failed: rows.filter((r) => r.eaStatus === "failed").length,
    error: rows.filter((r) => r.eaStatus === "error").length,
    withEvidence: rows.filter((r) => r.eaEvidence != null).length
  };
}
async function saveEngagementResult(input) {
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
    createdAt: now
  });
  return Number(result.insertId);
}
function autoClassifyOwasp(title, description) {
  const text = `${title} ${description || ""}`.toLowerCase();
  if (/\b(idor|broken access|insecure direct|privilege escalat|path traversal|directory traversal|unauthorized access|access control|forced browsing|cors misconfigur)/.test(text)) return "A01:2021-Broken Access Control";
  if (/\b(ssl|tls|weak cipher|cleartext|unencrypted|certificate|crypto|hsts|mixed content|http without)/.test(text)) return "A02:2021-Cryptographic Failures";
  if (/\b(sql.?inject|xss|cross.?site.?script|command.?inject|os.?command|code.?inject|ldap.?inject|xpath|ssti|template.?inject|crlf.?inject|header.?inject|log4j|log4shell|jndi)/.test(text)) return "A03:2021-Injection";
  if (/\b(insecure design|\bbusiness logic\b|race condition|mass assignment)/.test(text)) return "A04:2021-Insecure Design";
  if (/\b(misconfig|default credential|default password|exposed.{0,25}(config|env|debug|admin|panel|backup|git|svn|ds_store)|directory listing|stack trace|verbose error|server.?header|x-powered|phpinfo|\.env\b|\.git\b|web\.config|crossdomain\.xml|security\.txt|robots\.txt.*disallow)/.test(text)) return "A05:2021-Security Misconfiguration";
  if (/\b(outdated|vulnerable component|known vulnerabilit|cve-\d|end.?of.?life|eol|unsupported version|deprecated|version.?disclosure)/.test(text)) return "A06:2021-Vulnerable and Outdated Components";
  if (/\b(brute.?force|weak password|credential.?stuff|session.?fixation|session.?hijack|authentication bypass|auth bypass|missing.?auth|broken.?auth|jwt|token.?leak|password.?reset)/.test(text)) return "A07:2021-Identification and Authentication Failures";
  if (/\b(deserializ|insecure deserializ|ci.?cd|pipeline|integrity|unsigned|unverified update|supply chain)/.test(text)) return "A08:2021-Software and Data Integrity Failures";
  if (/\b(logging|monitoring|audit|insufficient log|missing log)/.test(text)) return "A09:2021-Security Logging and Monitoring Failures";
  if (/\b(ssrf|server.?side request forgery)/.test(text)) return "A10:2021-Server-Side Request Forgery";
  if (/\b(information.?disclos|sensitive.?data|data.?expos|data.?leak|pii)/.test(text)) return "A02:2021-Cryptographic Failures";
  if (/\b(open.?redirect|url.?redirect)/.test(text)) return "A01:2021-Broken Access Control";
  return void 0;
}
async function saveEngagementFindings(findings) {
  if (findings.length === 0) return 0;
  const db = await getDbRequired();
  const now = Date.now();
  let inserted = 0;
  const dedupMap = /* @__PURE__ */ new Map();
  const TIER_RANK = { "confirmed": 4, "corroborated": 3, "single-source": 2, "unverified": 1 };
  for (const f of findings) {
    const normTitle = (f.title || "").replace(/^\[\w+(?:\s+\w+)*\]\s*/g, "").replace(/\s*@\s*https?:\/\/\S+/g, "").replace(/\s+/g, " ").trim().toLowerCase();
    const key = `${f.engagementId}|${normTitle}|${(f.severity || "").toLowerCase()}|${(f.hostname || "").toLowerCase()}|${f.port || 0}`;
    const existing = dedupMap.get(key);
    if (!existing) {
      dedupMap.set(key, f);
    } else {
      const existingScore = (existing.description?.length || 0) + (existing.cve ? 100 : 0) + (existing.exploitSucceeded ? 200 : 0) + (TIER_RANK[existing.corroborationTier || "unverified"] || 0) * 50;
      const newScore = (f.description?.length || 0) + (f.cve ? 100 : 0) + (f.exploitSucceeded ? 200 : 0) + (TIER_RANK[f.corroborationTier || "unverified"] || 0) * 50;
      if (newScore > existingScore) {
        dedupMap.set(key, f);
      }
    }
  }
  const dedupedFindings = Array.from(dedupMap.values());
  const dedupedCount = findings.length - dedupedFindings.length;
  if (dedupedCount > 0) {
    console.log(`[saveEngagementFindings] Deduplicated ${dedupedCount} findings (${findings.length} \u2192 ${dedupedFindings.length})`);
  }
  const engIds = [...new Set(dedupedFindings.map((f) => f.engagementId))];
  const existingTitleKeys = /* @__PURE__ */ new Set();
  for (const eid of engIds) {
    try {
      const existing = await db.select({ title: engagementFindings.title, severity: engagementFindings.severity, hostname: engagementFindings.hostname, port: engagementFindings.port }).from(engagementFindings).where(eq(engagementFindings.engagementId, eid));
      for (const e of existing) {
        const normExisting = (e.title || "").replace(/^\[\w+(?:\s+\w+)*\]\s*/g, "").replace(/\s*@\s*https?:\/\/\S+/g, "").replace(/\s+/g, " ").trim().toLowerCase();
        existingTitleKeys.add(`${eid}|${normExisting}|${(e.severity || "").toLowerCase()}|${(e.hostname || "").toLowerCase()}|${e.port || 0}`);
      }
    } catch {
    }
  }
  const newFindings = dedupedFindings.filter((f) => {
    const normTitle = (f.title || "").replace(/^\[\w+(?:\s+\w+)*\]\s*/g, "").replace(/\s*@\s*https?:\/\/\S+/g, "").replace(/\s+/g, " ").trim().toLowerCase();
    const key = `${f.engagementId}|${normTitle}|${(f.severity || "").toLowerCase()}|${(f.hostname || "").toLowerCase()}|${f.port || 0}`;
    return !existingTitleKeys.has(key);
  });
  if (newFindings.length < dedupedFindings.length) {
    console.log(`[saveEngagementFindings] Cross-call dedup: ${dedupedFindings.length - newFindings.length} already in DB, inserting ${newFindings.length} new`);
  }
  for (let i = 0; i < newFindings.length; i += 50) {
    const batch = newFindings.slice(i, i + 50);
    await db.insert(engagementFindings).values(
      batch.map((f) => ({
        engagementId: f.engagementId,
        resultId: f.resultId,
        title: f.title,
        severity: f.severity,
        cve: f.cve,
        cwe: f.cwe,
        description: f.description?.slice(0, 65e3),
        endpoint: f.endpoint,
        hostname: f.hostname,
        port: f.port,
        source: f.source,
        tool: f.tool,
        corroborationTier: f.corroborationTier || "unverified",
        rawEvidence: f.rawEvidence?.slice(0, 65e3),
        screenshotPath: f.screenshotPath,
        exploitAttempted: f.exploitAttempted ? 1 : 0,
        exploitSucceeded: f.exploitSucceeded ? 1 : 0,
        exploitTechnique: f.exploitTechnique,
        owaspCategory: f.owaspCategory || autoClassifyOwasp(f.title || "", f.description) || null,
        mitreTechnique: f.mitreTechnique,
        createdAt: now
      }))
    );
    inserted += batch.length;
  }
  return inserted;
}
async function getEngagementResult(engagementId) {
  const db = await getDbRequired();
  const rows = await db.select().from(engagementResults).where(eq(engagementResults.engagementId, engagementId)).limit(1);
  return rows[0] || null;
}
async function getEngagementFindings(engagementId) {
  const db = await getDbRequired();
  return db.select().from(engagementFindings).where(eq(engagementFindings.engagementId, engagementId));
}
async function insertGraduationScore(data) {
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
    pipelineType: data.pipelineType || "di_scan",
    reconAnalyst: data.scores.recon_analyst,
    exploitSelector: data.scores.exploit_selector,
    evasionOptimizer: data.scores.evasion_optimizer,
    cognitiveCore: data.scores.cognitive_core,
    cloudAssessor: data.scores.cloud_assessor,
    supplyChainAnalyst: data.scores.supply_chain_analyst,
    overallScore: overall,
    summary: data.summary || null
  });
}
async function getGraduationScoresForDomain(domain, limit = 20) {
  const database = await getDb();
  if (!database) return [];
  return database.select().from(schema.scanGraduationScores).where(eq(schema.scanGraduationScores.domain, domain.toLowerCase())).orderBy(sql`created_at DESC`).limit(limit);
}
async function getGraduationScoresBySector(sector, limit = 100) {
  const database = await getDb();
  if (!database) return [];
  return database.select().from(schema.scanGraduationScores).where(eq(schema.scanGraduationScores.sector, sector)).orderBy(sql`created_at DESC`).limit(limit);
}
async function getAvgGraduationScoresBySector(sector) {
  const database = await getDb();
  if (!database) return null;
  const rows = await database.select({
    avgRecon: sql`AVG(recon_analyst)`,
    avgExploit: sql`AVG(exploit_selector)`,
    avgEvasion: sql`AVG(evasion_optimizer)`,
    avgCognitive: sql`AVG(cognitive_core)`,
    avgCloud: sql`AVG(cloud_assessor)`,
    avgSupplyChain: sql`AVG(supply_chain_analyst)`,
    avgOverall: sql`AVG(overall_score)`,
    cnt: sql`COUNT(*)`
  }).from(schema.scanGraduationScores).where(eq(schema.scanGraduationScores.sector, sector));
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
    sampleCount: r.cnt
  };
}
async function insertConnectorPerformance(data) {
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
    rateLimited: data.rateLimited ? 1 : 0
  });
}
async function bulkInsertConnectorPerformance(entries) {
  const database = await getDb();
  if (!database || entries.length === 0) return;
  const values = entries.map((e) => ({
    connector: e.connector,
    domain: e.domain.toLowerCase(),
    sector: e.sector || null,
    scanId: e.scanId,
    observations: e.observations,
    durationMs: e.durationMs,
    status: e.status,
    rateLimited: e.rateLimited ? 1 : 0
  }));
  for (let i = 0; i < values.length; i += 50) {
    const chunk = values.slice(i, i + 50);
    await database.insert(schema.connectorPerformanceHistory).values(chunk);
  }
}
async function getConnectorPerformanceForDomain(domain, limit = 500) {
  const database = await getDb();
  if (!database) return [];
  return database.select().from(schema.connectorPerformanceHistory).where(eq(schema.connectorPerformanceHistory.domain, domain.toLowerCase())).orderBy(sql`created_at DESC`).limit(limit);
}
async function getConnectorPerformanceBySector(sector, limit = 1e3) {
  const database = await getDb();
  if (!database) return [];
  return database.select().from(schema.connectorPerformanceHistory).where(eq(schema.connectorPerformanceHistory.sector, sector)).orderBy(sql`created_at DESC`).limit(limit);
}
async function getConnectorAvgsBySector(sector) {
  const database = await getDb();
  if (!database) return [];
  const rows = await database.select({
    connector: schema.connectorPerformanceHistory.connector,
    avgObs: sql`AVG(observations)`,
    avgDur: sql`AVG(duration_ms)`,
    totalRuns: sql`COUNT(*)`,
    failCount: sql`SUM(CASE WHEN status IN ('failed','timeout') THEN 1 ELSE 0 END)`
  }).from(schema.connectorPerformanceHistory).where(eq(schema.connectorPerformanceHistory.sector, sector)).groupBy(schema.connectorPerformanceHistory.connector);
  return rows.map((r) => ({
    connector: r.connector,
    avgObservations: Math.round(r.avgObs * 10) / 10,
    avgDurationMs: Math.round(r.avgDur),
    failureRate: r.totalRuns > 0 ? Math.round(r.failCount / r.totalRuns * 100) / 100 : 0,
    totalRuns: r.totalRuns
  }));
}
async function saveZeroDayMatches(matches) {
  if (matches.length === 0) return;
  const db = await getDb();
  if (!db) return;
  const values = matches.map((m) => ({
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
    advisoryUrl: m.advisoryUrl || null
  }));
  for (let i = 0; i < values.length; i += 50) {
    const chunk = values.slice(i, i + 50);
    await db.insert(zeroDayScanMatches).values(chunk);
  }
}
async function getZeroDayMatchesByScan(scanId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(zeroDayScanMatches).where(eq(zeroDayScanMatches.scanId, scanId)).orderBy(zeroDayScanMatches.severity);
}
async function getZeroDayMatchesByDomain(domain, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(zeroDayScanMatches).where(eq(zeroDayScanMatches.domain, domain)).orderBy(desc(zeroDayScanMatches.createdAt)).limit(limit);
}
async function getZeroDayMatchesByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(zeroDayScanMatches).where(eq(zeroDayScanMatches.engagementId, engagementId)).orderBy(zeroDayScanMatches.severity);
}
async function getRecentZeroDayMatches(limit = 100) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(zeroDayScanMatches).where(eq(zeroDayScanMatches.dismissed, 0)).orderBy(desc(zeroDayScanMatches.createdAt)).limit(limit);
}
async function dismissZeroDayMatch(matchId) {
  const db = await getDb();
  if (!db) return;
  return db.update(zeroDayScanMatches).set({ dismissed: 1 }).where(eq(zeroDayScanMatches.id, matchId));
}
async function getZeroDayMatchStats() {
  const db = await getDb();
  if (!db) return { total: 0, critical: 0, high: 0, undismissed: 0 };
  const [total] = await db.select({ count: sql`count(*)` }).from(zeroDayScanMatches);
  const [critical] = await db.select({ count: sql`count(*)` }).from(zeroDayScanMatches).where(eq(zeroDayScanMatches.severity, "critical"));
  const [high] = await db.select({ count: sql`count(*)` }).from(zeroDayScanMatches).where(eq(zeroDayScanMatches.severity, "high"));
  const [undismissed] = await db.select({ count: sql`count(*)` }).from(zeroDayScanMatches).where(eq(zeroDayScanMatches.dismissed, 0));
  return {
    total: total?.count || 0,
    critical: critical?.count || 0,
    high: high?.count || 0,
    undismissed: undismissed?.count || 0
  };
}
async function insertDITrainingExample(data) {
  const db = await getDb();
  if (!db) return;
  await db.insert(diIncidentTrainingData).values(data);
}
async function bulkInsertDITrainingExamples(examples) {
  if (examples.length === 0) return;
  const db = await getDb();
  if (!db) return;
  for (let i = 0; i < examples.length; i += 10) {
    const batch = examples.slice(i, i + 10);
    await db.insert(diIncidentTrainingData).values(batch);
  }
}
async function getDITrainingExamplesForDomain(domain, limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(diIncidentTrainingData).where(eq(diIncidentTrainingData.domain, domain)).orderBy(desc(diIncidentTrainingData.qualityScore)).limit(limit);
}
async function getDITrainingExamplesForSector(sector, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(diIncidentTrainingData).where(eq(diIncidentTrainingData.sector, sector)).orderBy(desc(diIncidentTrainingData.qualityScore)).limit(limit);
}
async function getHighQualityDITrainingExamples(limit = 100) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, "high")).orderBy(desc(diIncidentTrainingData.qualityScore)).limit(limit);
}
async function updateDITrainingAnalystRating(exampleId, rating, analystId, notes) {
  const db = await getDb();
  if (!db) return;
  await db.update(diIncidentTrainingData).set({
    analystRating: rating,
    analystId,
    analystNotes: notes || null,
    ratedAt: Date.now(),
    // Adjust quality based on analyst feedback
    qualityScore: rating === "accurate" ? 0.95 : rating === "partially_accurate" ? 0.6 : 0.1,
    qualityBand: rating === "accurate" ? "high" : rating === "partially_accurate" ? "medium" : "rejected"
  }).where(eq(diIncidentTrainingData.exampleId, exampleId));
}
async function incrementDITrainingUsage(exampleIds) {
  if (exampleIds.length === 0) return;
  const db = await getDb();
  if (!db) return;
  for (const eid of exampleIds) {
    await db.update(diIncidentTrainingData).set({
      usedInPromptCount: sql`${diIncidentTrainingData.usedInPromptCount} + 1`,
      lastUsedAt: Date.now()
    }).where(eq(diIncidentTrainingData.exampleId, eid));
  }
}
async function getDITrainingStats() {
  const db = await getDb();
  if (!db) return { total: 0, high: 0, medium: 0, low: 0, rejected: 0, reviewed: 0, unreviewed: 0 };
  const [total] = await db.select({ count: sql`count(*)` }).from(diIncidentTrainingData);
  const [high] = await db.select({ count: sql`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, "high"));
  const [medium] = await db.select({ count: sql`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, "medium"));
  const [low] = await db.select({ count: sql`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, "low"));
  const [rejected] = await db.select({ count: sql`count(*)` }).from(diIncidentTrainingData).where(eq(diIncidentTrainingData.qualityBand, "rejected"));
  const [reviewed] = await db.select({ count: sql`count(*)` }).from(diIncidentTrainingData).where(sql`${diIncidentTrainingData.analystRating} != 'not_reviewed'`);
  return {
    total: total?.count || 0,
    high: high?.count || 0,
    medium: medium?.count || 0,
    low: low?.count || 0,
    rejected: rejected?.count || 0,
    reviewed: reviewed?.count || 0,
    unreviewed: (total?.count || 0) - (reviewed?.count || 0)
  };
}
async function createBurpScanRecord(record) {
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
    startedAt: record.startedAt
  });
  return result.insertId;
}
async function updateBurpScanRecord(id, updates) {
  const db = await getDb();
  if (!db) return;
  await db.update(burpScanHistory).set(updates).where(eq(burpScanHistory.id, id));
}
async function getBurpScansByEngagement(engagementId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(burpScanHistory).where(eq(burpScanHistory.engagementId, engagementId)).orderBy(desc(burpScanHistory.startedAt));
}
async function getBurpScansByUser(userId) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(burpScanHistory).where(eq(burpScanHistory.userId, userId)).orderBy(desc(burpScanHistory.startedAt));
}
async function getDbBurpScanStats() {
  const db = await getDb();
  if (!db) return { total: 0, active: 0, completed: 0, failed: 0, totalIssues: 0, totalImported: 0 };
  const [total] = await db.select({ count: sql`count(*)` }).from(burpScanHistory);
  const [active] = await db.select({ count: sql`count(*)` }).from(burpScanHistory).where(sql`${burpScanHistory.status} IN ('pending','launching','running','polling','importing')`);
  const [completed] = await db.select({ count: sql`count(*)` }).from(burpScanHistory).where(eq(burpScanHistory.status, "completed"));
  const [failed] = await db.select({ count: sql`count(*)` }).from(burpScanHistory).where(eq(burpScanHistory.status, "failed"));
  const [issues] = await db.select({ sum: sql`COALESCE(SUM(issue_count), 0)` }).from(burpScanHistory);
  const [imported] = await db.select({ sum: sql`COALESCE(SUM(imported_count), 0)` }).from(burpScanHistory);
  return {
    total: total?.count || 0,
    active: active?.count || 0,
    completed: completed?.count || 0,
    failed: failed?.count || 0,
    totalIssues: issues?.sum || 0,
    totalImported: imported?.sum || 0
  };
}
async function addTimelineEvent(params) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const { engagementTimelineEvents } = await import("./schema-OF2ORZ4R.js");
  const result = await db.insert(engagementTimelineEvents).values({
    engagementId: params.engagementId,
    phase: params.phase || "vulnerability_analysis",
    eventType: params.eventType,
    severity: params.severity || "info",
    title: params.title,
    description: params.description,
    metadata: params.metadata ? JSON.stringify(params.metadata) : null,
    sourceModule: params.sourceModule || "burp-auto-scan",
    timestamp: Date.now()
  });
  return result[0]?.insertId || 0;
}
async function getTimelineEvents(engagementId, limit = 50) {
  const db = await getDb();
  if (!db) return [];
  const { engagementTimelineEvents } = await import("./schema-OF2ORZ4R.js");
  const { eq: eq2, desc: desc2 } = await import("drizzle-orm");
  return db.select().from(engagementTimelineEvents).where(eq2(engagementTimelineEvents.engagementId, engagementId)).orderBy(desc2(engagementTimelineEvents.timestamp)).limit(limit);
}
async function createBugBountyFinding(params) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const { bugBountyFindings } = await import("./schema-OF2ORZ4R.js");
  const { and: and2, eq: eq2 } = await import("drizzle-orm");
  const normalizedTitle = params.title.substring(0, 1024).trim();
  const normalizedAsset = (params.assetIdentifier || "").trim();
  const normalizedPlatform = (params.platform || "manual").trim();
  try {
    const existing = await db.select({ id: bugBountyFindings.id, severityRating: bugBountyFindings.severityRating }).from(bugBountyFindings).where(
      and2(
        eq2(bugBountyFindings.title, normalizedTitle),
        eq2(bugBountyFindings.assetIdentifier, normalizedAsset),
        eq2(bugBountyFindings.platform, normalizedPlatform)
      )
    ).limit(1);
    if (existing.length > 0) {
      const existingId = existing[0].id;
      const existingSeverity = existing[0].severityRating || "info";
      const newSeverity = params.severityRating || "low";
      const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if ((severityRank[newSeverity] || 0) > (severityRank[existingSeverity] || 0)) {
        await db.update(bugBountyFindings).set({ severityRating: newSeverity }).where(eq2(bugBountyFindings.id, existingId));
        console.log(`[BugBountyDedup] Promoted finding #${existingId} severity: ${existingSeverity} \u2192 ${newSeverity} ("${normalizedTitle}" on ${normalizedAsset})`);
      } else {
        console.log(`[BugBountyDedup] Skipped duplicate: "${normalizedTitle}" on ${normalizedAsset} (existing #${existingId})`);
      }
      return { id: existingId, deduplicated: true };
    }
  } catch (dedupErr) {
    console.warn(`[BugBountyDedup] Dedup check failed, proceeding with insert: ${dedupErr.message}`);
  }
  let fullSummary = params.summary || "";
  if (params.metadata) {
    const metaLines = [];
    if (params.metadata.burpIssueType) metaLines.push(`Burp Issue Type: ${params.metadata.burpIssueType}`);
    if (params.metadata.confidence) metaLines.push(`Confidence: ${params.metadata.confidence}`);
    if (params.metadata.path) metaLines.push(`Path: ${params.metadata.path}`);
    if (params.metadata.source) metaLines.push(`Source: ${params.metadata.source}`);
    if (params.metadata.remediation) metaLines.push(`Remediation: ${params.metadata.remediation}`);
    if (params.metadata.issueBackground) metaLines.push(`Background: ${params.metadata.issueBackground}`);
    if (metaLines.length > 0) {
      fullSummary += `

--- Scanner Metadata ---
${metaLines.join("\n")}`;
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
    externalId: `burp-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`
  });
  const insertId = result[0]?.insertId || 0;
  return { id: insertId, deduplicated: false };
}
async function insertExploitOutcome(data) {
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
      stdout: (data.stdout || "").slice(0, 5e4),
      stderr: (data.stderr || "").slice(0, 5e4),
      guardrailPassed: data.guardrailPassed != null ? data.guardrailPassed ? 1 : 0 : null,
      guardrailRiskScore: data.guardrailRiskScore ?? null,
      guardrailBlockedReasons: data.guardrailBlockedReasons || null,
      falsePositive: data.falsePositive ? 1 : 0,
      falsePositiveReasons: data.falsePositiveReasons || null,
      executionTimeMs: data.executionTimeMs,
      attemptNumber: data.attemptNumber,
      previousAttemptIds: data.previousAttemptIds,
      correctionApplied: data.correctionApplied || null
    });
    return result[0]?.insertId || 0;
  } catch (err) {
    console.error(`[DB] insertExploitOutcome failed: ${err.message}`);
    return 0;
  }
}
async function upsertExploitPattern(data) {
  const db = await getDb();
  if (!db) return 0;
  try {
    const { eq: eq2 } = await import("drizzle-orm");
    const existing = await db.select({ id: exploitLearningPatterns.id }).from(exploitLearningPatterns).where(eq2(exploitLearningPatterns.patternKey, data.patternKey)).limit(1);
    if (existing.length > 0) {
      await db.update(exploitLearningPatterns).set({
        successfulApproaches: data.successfulApproaches,
        failedApproaches: data.failedApproaches,
        knownChainIds: data.knownChainIds || null,
        totalSuccesses: data.totalSuccesses,
        totalFailures: data.totalFailures,
        successRate: data.successRate,
        updatedAt: data.updatedAt
      }).where(eq2(exploitLearningPatterns.patternKey, data.patternKey));
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
        updatedAt: data.updatedAt
      });
      return result[0]?.insertId || 0;
    }
  } catch (err) {
    console.error(`[DB] upsertExploitPattern failed: ${err.message}`);
    return 0;
  }
}
async function loadAllExploitPatterns() {
  const db = await getDb();
  if (!db) return [];
  try {
    const rows = await db.select().from(exploitLearningPatterns);
    return rows.map((r) => ({
      id: r.id,
      patternKey: r.patternKey,
      vulnClass: r.vulnClass,
      techStack: r.techStack || [],
      successfulApproaches: r.successfulApproaches || [],
      failedApproaches: r.failedApproaches || [],
      knownChainIds: r.knownChainIds,
      totalSuccesses: r.totalSuccesses,
      totalFailures: r.totalFailures,
      successRate: r.successRate,
      updatedAt: r.updatedAt
    }));
  } catch (err) {
    console.error(`[DB] loadAllExploitPatterns failed: ${err.message}`);
    return [];
  }
}
async function upsertExploitChain(data) {
  const db = await getDb();
  if (!db) return 0;
  try {
    const { eq: eq2 } = await import("drizzle-orm");
    const existing = await db.select({ id: exploitLearningChains.id }).from(exploitLearningChains).where(eq2(exploitLearningChains.chainName, data.chainName)).limit(1);
    if (existing.length > 0) {
      await db.update(exploitLearningChains).set({
        steps: data.steps,
        successRate: data.successRate,
        mitreTechniques: data.mitreTechniques || null,
        timesUsed: sql`times_used + 1`,
        lastUsedAt: Date.now()
      }).where(eq2(exploitLearningChains.chainName, data.chainName));
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
        lastUsedAt: Date.now()
      });
      return result[0]?.insertId || 0;
    }
  } catch (err) {
    console.error(`[DB] upsertExploitChain failed: ${err.message}`);
    return 0;
  }
}
async function loadAllExploitChains() {
  const db = await getDb();
  if (!db) return [];
  try {
    const rows = await db.select().from(exploitLearningChains);
    return rows.map((r) => ({
      id: r.id,
      chainName: r.chainName,
      steps: r.steps || [],
      successRate: r.successRate,
      discoveredFrom: r.discoveredFrom,
      mitreTechniques: r.mitreTechniques || [],
      engagementId: r.engagementId,
      targetHostname: r.targetHostname,
      timesUsed: r.timesUsed,
      lastUsedAt: r.lastUsedAt
    }));
  } catch (err) {
    console.error(`[DB] loadAllExploitChains failed: ${err.message}`);
    return [];
  }
}
async function loadRecentExploitOutcomes(opts) {
  const db = await getDb();
  if (!db) return [];
  try {
    const { eq: eq2, desc: desc2, and: and2 } = await import("drizzle-orm");
    const conditions = [];
    if (opts.vulnClass) conditions.push(eq2(exploitLearningOutcomes.vulnClass, opts.vulnClass));
    if (opts.engagementId) conditions.push(eq2(exploitLearningOutcomes.engagementId, opts.engagementId));
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
      createdAt: exploitLearningOutcomes.createdAt
    }).from(exploitLearningOutcomes).orderBy(desc2(exploitLearningOutcomes.id)).limit(opts.limit || 100);
    if (conditions.length > 0) {
      query.where(conditions.length === 1 ? conditions[0] : and2(...conditions));
    }
    const rows = await query;
    return rows.map((r) => ({
      ...r,
      success: !!r.success,
      guardrailPassed: r.guardrailPassed != null ? !!r.guardrailPassed : null,
      falsePositive: !!r.falsePositive
    }));
  } catch (err) {
    console.error(`[DB] loadRecentExploitOutcomes failed: ${err.message}`);
    return [];
  }
}
async function getExploitLearningDbStats() {
  const db = await getDb();
  if (!db) return { totalOutcomes: 0, totalSuccesses: 0, totalFailures: 0, patternsStored: 0, chainsStored: 0, successRate: 0 };
  try {
    const { sql: sqlTag } = await import("drizzle-orm");
    const [outcomeStats] = await db.select({
      total: sqlTag`COUNT(*)`,
      successes: sqlTag`SUM(CASE WHEN success = 1 AND (false_positive = 0 OR false_positive IS NULL) THEN 1 ELSE 0 END)`
    }).from(exploitLearningOutcomes);
    const [patternCount] = await db.select({
      count: sqlTag`COUNT(*)`
    }).from(exploitLearningPatterns);
    const [chainCount] = await db.select({
      count: sqlTag`COUNT(*)`
    }).from(exploitLearningChains);
    const total = Number(outcomeStats?.total || 0);
    const successes = Number(outcomeStats?.successes || 0);
    return {
      totalOutcomes: total,
      totalSuccesses: successes,
      totalFailures: total - successes,
      patternsStored: Number(patternCount?.count || 0),
      chainsStored: Number(chainCount?.count || 0),
      successRate: total > 0 ? successes / total : 0
    };
  } catch (err) {
    console.error(`[DB] getExploitLearningDbStats failed: ${err.message}`);
    return { totalOutcomes: 0, totalSuccesses: 0, totalFailures: 0, patternsStored: 0, chainsStored: 0, successRate: 0 };
  }
}
async function createCustomerIntegration(data) {
  const db = await getDbRequired();
  const [result] = await db.insert(customerIntegrations).values(data);
  return result.insertId;
}
async function getCustomerIntegrationByIntegrationId(integrationId) {
  const db = await getDbRequired();
  const rows = await db.select().from(customerIntegrations).where(eq(customerIntegrations.integrationId, integrationId)).limit(1);
  return rows[0];
}
async function getAllCustomerIntegrations() {
  const db = await getDbRequired();
  return db.select().from(customerIntegrations).orderBy(desc(customerIntegrations.createdAt));
}
async function getCustomerIntegrationsByCategory(category) {
  const db = await getDbRequired();
  return db.select().from(customerIntegrations).where(eq(customerIntegrations.category, category));
}
async function getCustomerIntegrationsByStatus(status) {
  const db = await getDbRequired();
  return db.select().from(customerIntegrations).where(eq(customerIntegrations.status, status));
}
async function getActiveCustomerIntegrationsByStage(stage) {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  return db.select().from(customerIntegrations).where(and(
    eq(customerIntegrations.status, "active"),
    sqlTag`JSON_CONTAINS(${customerIntegrations.pipelineStages}, JSON_QUOTE(${stage}))`
  ));
}
async function updateCustomerIntegration(integrationId, updates) {
  const db = await getDbRequired();
  await db.update(customerIntegrations).set({ ...updates, updatedAt: Date.now() }).where(eq(customerIntegrations.integrationId, integrationId));
}
async function deleteCustomerIntegration(integrationId) {
  const db = await getDbRequired();
  await db.delete(customerIntegrations).where(eq(customerIntegrations.integrationId, integrationId));
}
async function getCustomerIntegrationStats() {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  const [stats] = await db.select({
    total: sqlTag`COUNT(*)`,
    active: sqlTag`SUM(CASE WHEN ${customerIntegrations.status} = 'active' THEN 1 ELSE 0 END)`,
    proposed: sqlTag`SUM(CASE WHEN ${customerIntegrations.status} = 'proposed' THEN 1 ELSE 0 END)`,
    paused: sqlTag`SUM(CASE WHEN ${customerIntegrations.status} = 'paused' THEN 1 ELSE 0 END)`,
    error: sqlTag`SUM(CASE WHEN ${customerIntegrations.status} = 'error' THEN 1 ELSE 0 END)`
  }).from(customerIntegrations);
  return {
    total: Number(stats?.total ?? 0),
    active: Number(stats?.active ?? 0),
    proposed: Number(stats?.proposed ?? 0),
    paused: Number(stats?.paused ?? 0),
    error: Number(stats?.error ?? 0)
  };
}
async function createHealthCheck(data) {
  const db = await getDbRequired();
  const [result] = await db.insert(integrationHealthChecks).values(data);
  return result.insertId;
}
async function getRecentHealthChecks(integrationId, limit = 20) {
  const db = await getDbRequired();
  return db.select().from(integrationHealthChecks).where(eq(integrationHealthChecks.integrationId, integrationId)).orderBy(desc(integrationHealthChecks.checkedAt)).limit(limit);
}
async function getLatestHealthCheckPerIntegration() {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  return db.select().from(integrationHealthChecks).where(sqlTag`${integrationHealthChecks.id} IN (
      SELECT MAX(id) FROM integration_health_checks GROUP BY integration_id
    )`).orderBy(desc(integrationHealthChecks.checkedAt));
}
async function getHealthCheckHistory(integrationId, hoursBack = 24) {
  const db = await getDbRequired();
  const { gte } = await import("drizzle-orm");
  const cutoff = Date.now() - hoursBack * 60 * 60 * 1e3;
  return db.select().from(integrationHealthChecks).where(and(
    eq(integrationHealthChecks.integrationId, integrationId),
    gte(integrationHealthChecks.checkedAt, cutoff)
  )).orderBy(desc(integrationHealthChecks.checkedAt));
}
async function createExecutionLog(data) {
  const db = await getDbRequired();
  const [result] = await db.insert(integrationExecutionLog).values(data);
  return result.insertId;
}
async function getExecutionLogsByIntegration(integrationId, limit = 50) {
  const db = await getDbRequired();
  return db.select().from(integrationExecutionLog).where(eq(integrationExecutionLog.integrationId, integrationId)).orderBy(desc(integrationExecutionLog.executedAt)).limit(limit);
}
async function getExecutionLogsByEngagement(engagementId) {
  const db = await getDbRequired();
  return db.select().from(integrationExecutionLog).where(eq(integrationExecutionLog.engagementId, engagementId)).orderBy(desc(integrationExecutionLog.executedAt));
}
async function createDeployment(data) {
  const db = await getDbRequired();
  const [result] = await db.insert(deploymentHistory).values(data);
  return result.insertId;
}
async function listDeployments(opts) {
  const db = await getDbRequired();
  const conditions = [];
  if (opts?.environment) {
    conditions.push(eq(deploymentHistory.environment, opts.environment));
  }
  return db.select().from(deploymentHistory).where(conditions.length > 0 ? and(...conditions) : void 0).orderBy(desc(deploymentHistory.createdAt)).limit(opts?.limit ?? 50);
}
async function getDeploymentById(deploymentId) {
  const db = await getDbRequired();
  const [row] = await db.select().from(deploymentHistory).where(eq(deploymentHistory.deploymentId, deploymentId)).limit(1);
  return row;
}
async function updateDeploymentStatus(deploymentId, status, errorMessage) {
  const db = await getDbRequired();
  const updates = { status, updatedAt: (/* @__PURE__ */ new Date()).toISOString() };
  if (status === "success" || status === "failed" || status === "rolled_back") {
    updates.completedAt = (/* @__PURE__ */ new Date()).toISOString();
  }
  if (errorMessage) updates.errorMessage = errorMessage;
  await db.update(deploymentHistory).set(updates).where(eq(deploymentHistory.deploymentId, deploymentId));
}
async function getDeploymentStats() {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  const [stats] = await db.select({
    total: sqlTag`COUNT(*)`,
    success: sqlTag`SUM(CASE WHEN ${deploymentHistory.status} = 'success' THEN 1 ELSE 0 END)`,
    failed: sqlTag`SUM(CASE WHEN ${deploymentHistory.status} = 'failed' THEN 1 ELSE 0 END)`,
    pending: sqlTag`SUM(CASE WHEN ${deploymentHistory.status} IN ('pending', 'in_progress') THEN 1 ELSE 0 END)`
  }).from(deploymentHistory);
  return {
    total: Number(stats?.total ?? 0),
    success: Number(stats?.success ?? 0),
    failed: Number(stats?.failed ?? 0),
    pending: Number(stats?.pending ?? 0)
  };
}
async function createIrRunbookEntry(data) {
  const db = await getDbRequired();
  const [result] = await db.insert(irRunbookEntries).values(data);
  return result.insertId;
}
async function listIrRunbookEntries(opts) {
  const db = await getDbRequired();
  const conditions = [];
  if (opts?.severity) conditions.push(eq(irRunbookEntries.severity, opts.severity));
  if (opts?.category) conditions.push(eq(irRunbookEntries.category, opts.category));
  if (opts?.activeOnly) conditions.push(eq(irRunbookEntries.isActive, 1));
  return db.select().from(irRunbookEntries).where(conditions.length > 0 ? and(...conditions) : void 0).orderBy(desc(irRunbookEntries.createdAt));
}
async function getIrRunbookEntry(entryId) {
  const db = await getDbRequired();
  const [row] = await db.select().from(irRunbookEntries).where(eq(irRunbookEntries.entryId, entryId)).limit(1);
  return row;
}
async function updateIrRunbookEntry(entryId, data) {
  const db = await getDbRequired();
  await db.update(irRunbookEntries).set({ ...data, updatedAt: (/* @__PURE__ */ new Date()).toISOString() }).where(eq(irRunbookEntries.entryId, entryId));
}
async function deleteIrRunbookEntry(entryId) {
  const db = await getDbRequired();
  await db.delete(irRunbookEntries).where(eq(irRunbookEntries.entryId, entryId));
}
async function searchIrRunbook(query) {
  const db = await getDbRequired();
  return db.select().from(irRunbookEntries).where(or(
    like(irRunbookEntries.alarmName, `%${query}%`),
    like(irRunbookEntries.triggerDescription, `%${query}%`),
    like(irRunbookEntries.owner, `%${query}%`)
  )).orderBy(desc(irRunbookEntries.createdAt));
}
async function incrementIrRunbookTriggerCount(entryId) {
  const db = await getDbRequired();
  const { sql: sqlTag } = await import("drizzle-orm");
  await db.update(irRunbookEntries).set({
    triggerCount: sqlTag`${irRunbookEntries.triggerCount} + 1`,
    lastTriggeredAt: (/* @__PURE__ */ new Date()).toISOString()
  }).where(eq(irRunbookEntries.entryId, entryId));
}
var _db, _dbLastCheck, DB_RETRY_INTERVAL, CRED_ENCRYPTION_KEY, LLM_PRICING;
var init_db = __esm({
  "server/db.ts"() {
    init_schema();
    init_env();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    init_schema();
    _db = null;
    _dbLastCheck = 0;
    DB_RETRY_INTERVAL = 2e3;
    CRED_ENCRYPTION_KEY = (() => {
      const secret = process.env.JWT_SECRET || "default-dev-key-do-not-use-in-prod";
      return crypto.createHash("sha256").update(secret).digest();
    })();
    LLM_PRICING = {
      "gemini-2.5-flash": { inputPer1M: 0.15, outputPer1M: 0.6 },
      "gemini-2.0-flash": { inputPer1M: 0.1, outputPer1M: 0.4 },
      "gemini-1.5-pro": { inputPer1M: 3.5, outputPer1M: 10.5 },
      // Fallback for unknown models
      default: { inputPer1M: 0.15, outputPer1M: 0.6 }
    };
  }
});

export {
  getDb,
  getDbRequired,
  resetDbConnection,
  upsertUser,
  getUserByOpenId,
  getAllUsers,
  updateUserRole,
  createServerConfig,
  getServerConfigs,
  getServerConfigById,
  updateServerStatus,
  createCredential,
  getCredentialsByServerId,
  updateCredential,
  logActivity,
  getActivityLogs,
  getActivityLogsByServer,
  upsertCalderaStats,
  getCalderaStatsByServerId,
  createCampaign,
  getCampaigns,
  getCampaignById,
  updateCampaign,
  deleteCampaign,
  addCampaignAgent,
  getCampaignAgents,
  updateCampaignAgentStatus,
  deleteCampaignAgent,
  addCampaignAbility,
  addCampaignAbilities,
  getCampaignAbilities,
  updateCampaignAbilityStatus,
  deleteCampaignAbility,
  reorderCampaignAbilities,
  createEngagement,
  getEngagements,
  getEngagementById,
  updateEngagement,
  deleteEngagement,
  bulkDeleteEngagements,
  linkCampaignToEngagement,
  getCampaignsByEngagement,
  getEngagementByCampaign,
  getAllCampaignEngagementLinks,
  unlinkCampaignFromEngagement,
  createDomainRecon,
  updateDomainRecon,
  getDomainReconByEngagement,
  getDomainReconById,
  createTyposquatDomain,
  bulkCreateTyposquatDomains,
  updateTyposquatDomain,
  getTyposquatsByRecon,
  getTyposquatsByEngagement,
  createOsintFinding,
  bulkCreateOsintFindings,
  getOsintFindingsByEngagement,
  getOsintFindingsByRecon,
  createOsintMonitor,
  getOsintMonitors,
  getOsintMonitorById,
  getEnabledMonitors,
  updateOsintMonitor,
  deleteOsintMonitor,
  createMonitorChange,
  bulkCreateMonitorChanges,
  getMonitorChanges,
  getUnacknowledgedChanges,
  acknowledgeChange,
  createEngagementReport,
  getEngagementReports,
  getReportById,
  updateReport,
  deleteReport,
  getAllReports,
  createDomainIntelScan,
  getDomainIntelScans,
  getDomainIntelScanById,
  getPreviousCompletedScan,
  updateDomainIntelScan,
  createDiscoveredAsset,
  bulkCreateDiscoveredAssets,
  getDiscoveredAssetsByScan,
  excludeDiscoveredAsset,
  includeDiscoveredAsset,
  bulkExcludeDiscoveredAssets,
  bulkIncludeDiscoveredAssets,
  deleteDiscoveredAssetsByScan,
  deleteDomainIntelScan,
  getDomainIntelScansByEngagement,
  listThreatActors,
  getThreatActor,
  getThreatActorById,
  updateThreatActor,
  getThreatActorStats,
  getThreatActorCount,
  listThreatActorAbilities,
  createThreatActorAbility,
  listAllAbilities,
  listThreatActorIocs,
  createThreatActorIoc,
  bulkCreateThreatActorIocs,
  createIocFeedEntry,
  bulkCreateIocFeedEntries,
  listIocFeedEntries,
  getIocFeedStats,
  createEngagementPipeline,
  getEngagementPipeline,
  updateEngagementPipeline,
  listEngagementPipelines,
  createIocSyncLog,
  updateIocSyncLog,
  listIocSyncLogs,
  getLastIocSync,
  createThreatActor,
  upsertThreatActor,
  bulkUpsertThreatActors,
  upsertTtpKnowledge,
  getTtpKnowledge,
  listTtpKnowledge,
  getTtpKnowledgeStats,
  createFalsePositive,
  reinstateFalsePositive,
  getFalsePositivesByScan,
  getAllFalsePositives,
  getActiveFPHashes,
  getFPContextForLLM,
  isFindingFalsePositive,
  batchCheckFalsePositives,
  createEngagementShare,
  getEngagementShareByToken,
  getEngagementSharesByEngagement,
  updateEngagementShare,
  deleteEngagementShare,
  incrementShareViewCount,
  getAllEngagementShares,
  insertScoringAuditEntry,
  bulkInsertScoringAuditEntries,
  getScoringTimelineByAsset,
  getScoringTimelineByScan,
  lookupKevByCve,
  batchLookupKev,
  insertChainRun,
  updateChainRunDb,
  getChainRunByChainId,
  listChainRunsDb,
  deleteChainRunDb,
  upsertChainStageResultDb,
  getChainStageResultsDb,
  getKevStats,
  createCarverRiskCard,
  createCarverRiskCardsBatch,
  getCarverRiskCards,
  getCarverRiskCardById,
  getCarverRiskCardsByBatch,
  getCarverRiskCardStats,
  deleteCarverRiskCard,
  deleteCarverRiskCardsByBatch,
  createCredentialAttackRun,
  updateCredentialAttackRun,
  getCredentialAttackRuns,
  getCredentialAttackRunById,
  getCredentialAttackRunsByDomainScan,
  createCredentialFinding,
  createCredentialFindings,
  getCredentialFindingsByRun,
  getCredentialFindingsByDomainScan,
  getAllCredentialFindings,
  createZapProxySession,
  updateZapProxySession,
  getZapProxySessions,
  getZapProxySessionById,
  getZapSessionsByDomainScan,
  createPentestReport,
  updatePentestReport,
  getPentestReports,
  getPentestReportById,
  deletePentestReport,
  saveCredentialAttackWithTool,
  saveCredentialFindingWithTool,
  getCredentialAttackHistory,
  getCredentialAttackHistoryCount,
  getCredentialFindingsHistory,
  updateCredentialFindingValidation,
  getCredentialAttackStats,
  listPlatformCredentials,
  insertScanResult,
  getScanResultsByEngagement,
  getScanResultsByTool,
  getScanResultsSummary,
  saveOpsSnapshot,
  loadOpsSnapshot,
  deleteOpsSnapshot,
  recordLlmTelemetry,
  getLlmTelemetrySummary,
  getLlmTelemetryTimeSeries,
  getLlmTelemetryTopCallers,
  getLlmTelemetryRecentErrors,
  getLlmTelemetryLatencyDistribution,
  getLlmTelemetryModelUsage,
  getEngagementLlmCost,
  getEngagementLlmCostBreakdown,
  getAllEngagementLlmCosts,
  getEngagementLlmCostTimeSeries,
  getEngagementLlmTelemetryRaw,
  getGlobalLlmTelemetryRaw,
  insertExploitPlanHistory,
  getExploitPlanHistoryByEngagement,
  getExploitPlanHistoryById,
  getExploitPlanHistoryByGateId,
  getExploitPlanStats,
  createTrainingLabSession,
  updateTrainingLabSession,
  getTrainingLabSession,
  listTrainingLabSessions,
  insertTrainingLabFeedbackEntry,
  getTrainingLabFeedbackForSession,
  getHistoricalScanContext,
  buildHistoricalContextString,
  insertExploitationAttempt,
  getExploitationAttempts,
  getExploitationAttemptById,
  updateExploitationAttempt,
  getExploitationStats,
  saveEngagementResult,
  saveEngagementFindings,
  getEngagementResult,
  getEngagementFindings,
  insertGraduationScore,
  getGraduationScoresForDomain,
  getGraduationScoresBySector,
  getAvgGraduationScoresBySector,
  insertConnectorPerformance,
  bulkInsertConnectorPerformance,
  getConnectorPerformanceForDomain,
  getConnectorPerformanceBySector,
  getConnectorAvgsBySector,
  saveZeroDayMatches,
  getZeroDayMatchesByScan,
  getZeroDayMatchesByDomain,
  getZeroDayMatchesByEngagement,
  getRecentZeroDayMatches,
  dismissZeroDayMatch,
  getZeroDayMatchStats,
  insertDITrainingExample,
  bulkInsertDITrainingExamples,
  getDITrainingExamplesForDomain,
  getDITrainingExamplesForSector,
  getHighQualityDITrainingExamples,
  updateDITrainingAnalystRating,
  incrementDITrainingUsage,
  getDITrainingStats,
  createBurpScanRecord,
  updateBurpScanRecord,
  getBurpScansByEngagement,
  getBurpScansByUser,
  getDbBurpScanStats,
  addTimelineEvent,
  getTimelineEvents,
  createBugBountyFinding,
  insertExploitOutcome,
  upsertExploitPattern,
  loadAllExploitPatterns,
  upsertExploitChain,
  loadAllExploitChains,
  loadRecentExploitOutcomes,
  getExploitLearningDbStats,
  createCustomerIntegration,
  getCustomerIntegrationByIntegrationId,
  getAllCustomerIntegrations,
  getCustomerIntegrationsByCategory,
  getCustomerIntegrationsByStatus,
  getActiveCustomerIntegrationsByStage,
  updateCustomerIntegration,
  deleteCustomerIntegration,
  getCustomerIntegrationStats,
  createHealthCheck,
  getRecentHealthChecks,
  getLatestHealthCheckPerIntegration,
  getHealthCheckHistory,
  createExecutionLog,
  getExecutionLogsByIntegration,
  getExecutionLogsByEngagement,
  createDeployment,
  listDeployments,
  getDeploymentById,
  updateDeploymentStatus,
  getDeploymentStats,
  createIrRunbookEntry,
  listIrRunbookEntries,
  getIrRunbookEntry,
  updateIrRunbookEntry,
  deleteIrRunbookEntry,
  searchIrRunbook,
  incrementIrRunbookTriggerCount,
  db_exports,
  init_db
};
