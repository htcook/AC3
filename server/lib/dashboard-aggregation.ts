/**
 * Dashboard Aggregation Helpers
 * 
 * Provides real aggregated data for all six role-based dashboards.
 * Each function queries the database and returns structured data
 * ready for the frontend dashboard cards.
 */

import { getDb } from "../db";
import { sql, eq, desc, gt, count, sum } from "drizzle-orm";
import {
  engagements,
  engagementTimelineEvents,
  opsecEvents,
  credentialFindings,
  exploitationAttempts,
  obtainedShells,
  privescFindings,
  lateralMovementPaths,
  pivotHosts,
  discoveredAssets,
  osintFindings,
  domainRecon,
  domainIntelScans,
  threatActors,
  threatActorIocs,
  iocFeeds,
  ransomwareGroups,
  ransomwareEvents,
  threatIntelUpdates,
  users,
  activityLogs,
  serverConfigs,
  defenseScores,
  scanObservations,
  pentestReports,
  carverRiskCards,
  platformErrors,
  vendorIntegrations,
} from "../../drizzle/schema";

// ─── Shared Helpers ─────────────────────────────────────────────────────────

async function safeQuery<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    const db = await getDb();
    if (!db) return fallback;
    return await fn();
  } catch (err) {
    console.error("[DashboardAggregation] Query failed:", err);
    return fallback;
  }
}

/** Return a Date object representing N hours ago (for timestamp columns) */
function hoursAgo(hours: number): Date {
  return new Date(Date.now() - hours * 60 * 60 * 1000);
}

/** Return ms epoch representing N hours ago (for bigint timestamp columns) */
function hoursAgoMs(hours: number): number {
  return Date.now() - hours * 60 * 60 * 1000;
}

// ─── Operator Dashboard Data ────────────────────────────────────────────────

export interface OperatorDashboardData {
  activeEngagements: number;
  totalEngagements: number;
  opsecScore: number;
  opsecTrend: "rising" | "falling" | "stable";
  recentOpsecEvents: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  credentialsFound: number;
  shellsObtained: number;
  exploitAttempts: number;
  exploitSuccessRate: number;
  pivotHostCount: number;
  lateralPathCount: number;
  privescPathCount: number;
  recentActivity: Array<{
    id: number;
    type: string;
    title: string;
    timestamp: number;
    phase: string;
  }>;
}

export async function getOperatorDashboardData(): Promise<OperatorDashboardData> {
  return safeQuery(async () => {
    const db = (await getDb())!;

    const [engagementStats] = await db
      .select({
        total: count(),
        active: sum(sql`CASE WHEN ${engagements.status} = 'active' THEN 1 ELSE 0 END`),
      })
      .from(engagements);

    const recentOpsec = await db
      .select({ riskScore: opsecEvents.riskScore })
      .from(opsecEvents)
      .orderBy(desc(opsecEvents.timestamp))
      .limit(20);

    const avgOpsecScore = recentOpsec.length > 0
      ? Math.round(recentOpsec.reduce((s, e) => s + (e.riskScore || 0), 0) / recentOpsec.length)
      : 0;

    let opsecTrend: "rising" | "falling" | "stable" = "stable";
    if (recentOpsec.length >= 10) {
      const recent5 = recentOpsec.slice(0, 5).reduce((s, e) => s + (e.riskScore || 0), 0) / 5;
      const prev5 = recentOpsec.slice(5, 10).reduce((s, e) => s + (e.riskScore || 0), 0) / 5;
      if (recent5 > prev5 + 5) opsecTrend = "rising";
      else if (recent5 < prev5 - 5) opsecTrend = "falling";
    }

    const [opsecCount24h] = await db
      .select({ cnt: count() })
      .from(opsecEvents)
      .where(gt(opsecEvents.timestamp, hoursAgoMs(24)));

    const [credStats] = await db.select({ total: count() }).from(credentialFindings);
    const [shellStats] = await db.select({ total: count() }).from(obtainedShells);

    const exploitRows = await db
      .select({
        total: count(),
        successful: sum(sql`CASE WHEN ${exploitationAttempts.status} = 'success' THEN 1 ELSE 0 END`),
      })
      .from(exploitationAttempts);
    const exploitTotal = Number(exploitRows[0]?.total || 0);
    const exploitSuccess = Number(exploitRows[0]?.successful || 0);

    const [pivotStats] = await db.select({ total: count() }).from(pivotHosts);
    const [lateralStats] = await db.select({ total: count() }).from(lateralMovementPaths);
    const [privescStats] = await db.select({ total: count() }).from(privescFindings);

    const findingsBySeverity = await db
      .select({ severity: scanObservations.severity, cnt: count() })
      .from(scanObservations)
      .groupBy(scanObservations.severity);

    const criticalCount = Number(findingsBySeverity.find(f => f.severity === "critical")?.cnt || 0);
    const highCount = Number(findingsBySeverity.find(f => f.severity === "high")?.cnt || 0);
    const totalFindingsCount = findingsBySeverity.reduce((s, f) => s + Number(f.cnt), 0);

    const recentTimeline = await db
      .select({
        id: engagementTimelineEvents.id,
        eventType: engagementTimelineEvents.eventType,
        title: engagementTimelineEvents.title,
        timestamp: engagementTimelineEvents.timestamp,
        phase: engagementTimelineEvents.phase,
      })
      .from(engagementTimelineEvents)
      .orderBy(desc(engagementTimelineEvents.timestamp))
      .limit(10);

    return {
      activeEngagements: Number(engagementStats?.active || 0),
      totalEngagements: Number(engagementStats?.total || 0),
      opsecScore: avgOpsecScore,
      opsecTrend,
      recentOpsecEvents: Number(opsecCount24h?.cnt || 0),
      totalFindings: totalFindingsCount,
      criticalFindings: criticalCount,
      highFindings: highCount,
      credentialsFound: Number(credStats?.total || 0),
      shellsObtained: Number(shellStats?.total || 0),
      exploitAttempts: exploitTotal,
      exploitSuccessRate: exploitTotal > 0 ? Math.round((exploitSuccess / exploitTotal) * 100) : 0,
      pivotHostCount: Number(pivotStats?.total || 0),
      lateralPathCount: Number(lateralStats?.total || 0),
      privescPathCount: Number(privescStats?.total || 0),
      recentActivity: recentTimeline.map(e => ({
        id: e.id,
        type: e.eventType || "unknown",
        title: e.title || "Untitled",
        timestamp: Number(e.timestamp) || Date.now(),
        phase: e.phase || "unknown",
      })),
    };
  }, {
    activeEngagements: 0, totalEngagements: 0, opsecScore: 0, opsecTrend: "stable" as const,
    recentOpsecEvents: 0, totalFindings: 0, criticalFindings: 0, highFindings: 0,
    credentialsFound: 0, shellsObtained: 0, exploitAttempts: 0, exploitSuccessRate: 0,
    pivotHostCount: 0, lateralPathCount: 0, privescPathCount: 0, recentActivity: [],
  });
}

// ─── Executive Dashboard Data ───────────────────────────────────────────────

export interface ExecutiveDashboardData {
  riskPostureScore: number;
  riskTrend: "improving" | "worsening" | "stable";
  complianceCoverage: number;
  totalEngagements: number;
  completedEngagements: number;
  activeEngagements: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  reportsGenerated: number;
  defenseScoreAvg: number;
  riskCardCount: number;
  criticalRiskCards: number;
  recentEngagements: Array<{ id: number; name: string; type: string; status: string }>;
}

export async function getExecutiveDashboardData(): Promise<ExecutiveDashboardData> {
  return safeQuery(async () => {
    const db = (await getDb())!;

    const engagementRows = await db
      .select({
        total: count(),
        active: sum(sql`CASE WHEN ${engagements.status} = 'active' THEN 1 ELSE 0 END`),
        completed: sum(sql`CASE WHEN ${engagements.status} = 'completed' THEN 1 ELSE 0 END`),
      })
      .from(engagements);

    const vulnRows = await db
      .select({
        total: count(),
        critical: sum(sql`CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END`),
        high: sum(sql`CASE WHEN ${scanObservations.severity} = 'high' THEN 1 ELSE 0 END`),
      })
      .from(scanObservations);

    const defenseRows = await db
      .select({ score: defenseScores.overallScore })
      .from(defenseScores)
      .orderBy(desc(defenseScores.createdAt))
      .limit(10);
    const avgDefense = defenseRows.length > 0
      ? Math.round(defenseRows.reduce((s, r) => s + Number(r.score || 0), 0) / defenseRows.length)
      : 0;

    const riskCardRows = await db
      .select({
        total: count(),
        critical: sum(sql`CASE WHEN ${carverRiskCards.priorityTier} = 'P0' THEN 1 ELSE 0 END`),
      })
      .from(carverRiskCards);

    const [reportStats] = await db.select({ total: count() }).from(pentestReports);

    const opsecRows = await db
      .select({ riskScore: opsecEvents.riskScore })
      .from(opsecEvents)
      .orderBy(desc(opsecEvents.timestamp))
      .limit(50);
    const avgRisk = opsecRows.length > 0
      ? opsecRows.reduce((s, r) => s + (r.riskScore || 0), 0) / opsecRows.length
      : 50;
    const riskPosture = Math.max(0, Math.min(100, Math.round(100 - avgRisk)));

    let riskTrend: "improving" | "worsening" | "stable" = "stable";
    if (opsecRows.length >= 20) {
      const recent = opsecRows.slice(0, 10).reduce((s, r) => s + (r.riskScore || 0), 0) / 10;
      const prev = opsecRows.slice(10, 20).reduce((s, r) => s + (r.riskScore || 0), 0) / 10;
      if (recent < prev - 3) riskTrend = "improving";
      else if (recent > prev + 3) riskTrend = "worsening";
    }

    const totalVulns = Number(vulnRows[0]?.total || 0);
    const critVulns = Number(vulnRows[0]?.critical || 0);
    const highVulns = Number(vulnRows[0]?.high || 0);
    const compliancePct = totalVulns > 0
      ? Math.round(((totalVulns - critVulns - highVulns) / totalVulns) * 100)
      : 100;

    const recentEngs = await db
      .select({
        id: engagements.id,
        name: engagements.name,
        engagementType: engagements.engagementType,
        status: engagements.status,
      })
      .from(engagements)
      .orderBy(desc(engagements.createdAt))
      .limit(5);

    return {
      riskPostureScore: riskPosture,
      riskTrend,
      complianceCoverage: compliancePct,
      totalEngagements: Number(engagementRows[0]?.total || 0),
      completedEngagements: Number(engagementRows[0]?.completed || 0),
      activeEngagements: Number(engagementRows[0]?.active || 0),
      totalVulnerabilities: totalVulns,
      criticalVulnerabilities: critVulns,
      highVulnerabilities: highVulns,
      reportsGenerated: Number(reportStats?.total || 0),
      defenseScoreAvg: avgDefense,
      riskCardCount: Number(riskCardRows[0]?.total || 0),
      criticalRiskCards: Number(riskCardRows[0]?.critical || 0),
      recentEngagements: recentEngs.map(e => ({
        id: e.id, name: e.name,
        type: e.engagementType || "pentest",
        status: e.status || "planning",
      })),
    };
  }, {
    riskPostureScore: 50, riskTrend: "stable" as const, complianceCoverage: 100,
    totalEngagements: 0, completedEngagements: 0, activeEngagements: 0,
    totalVulnerabilities: 0, criticalVulnerabilities: 0, highVulnerabilities: 0,
    reportsGenerated: 0, defenseScoreAvg: 0,
    riskCardCount: 0, criticalRiskCards: 0, recentEngagements: [],
  });
}

// ─── Analyst Dashboard Data ─────────────────────────────────────────────────

export interface AnalystDashboardData {
  threatActorCount: number;
  activeThreatActors: number;
  iocCount: number;
  iocFeedCount: number;
  ransomwareGroupCount: number;
  recentRansomwareEvents: number;
  threatIntelSweeps: number;
  osintFindingsCount: number;
  domainReconCount: number;
  domainIntelScanCount: number;
  discoveredAssetCount: number;
  vulnerabilitiesBySeverity: Array<{ severity: string; count: number }>;
  topThreatActors: Array<{ id: number; name: string; sophistication: string }>;
}

export async function getAnalystDashboardData(): Promise<AnalystDashboardData> {
  return safeQuery(async () => {
    const db = (await getDb())!;

    const [taStats] = await db
      .select({
        total: count(),
        active: sum(sql`CASE WHEN ${threatActors.active} = 1 THEN 1 ELSE 0 END`),
      })
      .from(threatActors);

    const [iocStats] = await db.select({ total: count() }).from(threatActorIocs);
    const [feedStats] = await db.select({ total: count() }).from(iocFeeds);

    const [rwStats] = await db.select({ total: count() }).from(ransomwareGroups);
    const [rwEventStats] = await db
      .select({ total: count() })
      .from(ransomwareEvents)
      .where(gt(ransomwareEvents.createdAt, hoursAgo(720)));

    const [tiStats] = await db
      .select({ total: count() })
      .from(threatIntelUpdates)
      .where(gt(threatIntelUpdates.tiuStartedAt, hoursAgo(720)));

    const [osintStats] = await db.select({ total: count() }).from(osintFindings);
    const [domainStats] = await db.select({ total: count() }).from(domainRecon);
    const [diStats] = await db.select({ total: count() }).from(domainIntelScans);
    const [assetStats] = await db.select({ total: count() }).from(discoveredAssets);

    const vulnBySeverity = await db
      .select({ severity: scanObservations.severity, cnt: count() })
      .from(scanObservations)
      .groupBy(scanObservations.severity);

    const topActors = await db
      .select({
        id: threatActors.id,
        name: threatActors.name,
        sophistication: threatActors.sophistication,
      })
      .from(threatActors)
      .where(eq(threatActors.active, true))
      .limit(5);

    return {
      threatActorCount: Number(taStats?.total || 0),
      activeThreatActors: Number(taStats?.active || 0),
      iocCount: Number(iocStats?.total || 0),
      iocFeedCount: Number(feedStats?.total || 0),
      ransomwareGroupCount: Number(rwStats?.total || 0),
      recentRansomwareEvents: Number(rwEventStats?.total || 0),
      threatIntelSweeps: Number(tiStats?.total || 0),
      osintFindingsCount: Number(osintStats?.total || 0),
      domainReconCount: Number(domainStats?.total || 0),
      domainIntelScanCount: Number(diStats?.total || 0),
      discoveredAssetCount: Number(assetStats?.total || 0),
      vulnerabilitiesBySeverity: vulnBySeverity.map(v => ({
        severity: v.severity || "info",
        count: Number(v.cnt),
      })),
      topThreatActors: topActors.map(a => ({
        id: a.id,
        name: a.name,
        sophistication: a.sophistication || "unknown",
      })),
    };
  }, {
    threatActorCount: 0, activeThreatActors: 0, iocCount: 0, iocFeedCount: 0,
    ransomwareGroupCount: 0, recentRansomwareEvents: 0, threatIntelSweeps: 0,
    osintFindingsCount: 0, domainReconCount: 0, domainIntelScanCount: 0,
    discoveredAssetCount: 0, vulnerabilitiesBySeverity: [], topThreatActors: [],
  });
}

// ─── Team Lead Dashboard Data ───────────────────────────────────────────────

export interface TeamLeadDashboardData {
  totalTeamMembers: number;
  activeOperators: number;
  engagementPipeline: {
    planning: number;
    active: number;
    paused: number;
    completed: number;
    archived: number;
  };
  totalFindings: number;
  criticalFindings: number;
  reportsDelivered: number;
  recentEngagements: Array<{
    id: number;
    name: string;
    customerName: string;
    status: string;
    engagementType: string;
    startDate: number | null;
  }>;
}

export async function getTeamLeadDashboardData(): Promise<TeamLeadDashboardData> {
  return safeQuery(async () => {
    const db = (await getDb())!;

    const userRows = await db
      .select({
        total: count(),
        operators: sum(sql`CASE WHEN ${users.role} IN ('operator', 'admin') THEN 1 ELSE 0 END`),
      })
      .from(users);

    const pipelineRows = await db
      .select({ status: engagements.status, cnt: count() })
      .from(engagements)
      .groupBy(engagements.status);

    const pipeline = { planning: 0, active: 0, paused: 0, completed: 0, archived: 0 };
    for (const row of pipelineRows) {
      const s = (row.status || "") as keyof typeof pipeline;
      if (s in pipeline) pipeline[s] = Number(row.cnt);
    }

    const [findingStats] = await db
      .select({
        total: count(),
        critical: sum(sql`CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END`),
      })
      .from(scanObservations);

    const [reportStats] = await db.select({ total: count() }).from(pentestReports);

    const recentEngs = await db
      .select({
        id: engagements.id,
        name: engagements.name,
        customerName: engagements.customerName,
        status: engagements.status,
        engagementType: engagements.engagementType,
        startDate: engagements.startDate,
      })
      .from(engagements)
      .orderBy(desc(engagements.createdAt))
      .limit(10);

    return {
      totalTeamMembers: Number(userRows[0]?.total || 0),
      activeOperators: Number(userRows[0]?.operators || 0),
      engagementPipeline: pipeline,
      totalFindings: Number(findingStats?.total || 0),
      criticalFindings: Number(findingStats?.critical || 0),
      reportsDelivered: Number(reportStats?.total || 0),
      recentEngagements: recentEngs.map(e => ({
        id: e.id,
        name: e.name,
        customerName: e.customerName,
        status: e.status || "planning",
        engagementType: e.engagementType || "pentest",
        startDate: e.startDate ? new Date(e.startDate).getTime() : null,
      })),
    };
  }, {
    totalTeamMembers: 0, activeOperators: 0,
    engagementPipeline: { planning: 0, active: 0, paused: 0, completed: 0, archived: 0 },
    totalFindings: 0, criticalFindings: 0, reportsDelivered: 0, recentEngagements: [],
  });
}

// ─── Client Dashboard Data ──────────────────────────────────────────────────

export interface ClientDashboardData {
  assessmentStatus: string;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  reportsAvailable: number;
  lastReportDate: number | null;
  findingsBySeverity: Array<{ severity: string; count: number }>;
}

export async function getClientDashboardData(): Promise<ClientDashboardData> {
  return safeQuery(async () => {
    const db = (await getDb())!;

    const [latestEng] = await db
      .select({ status: engagements.status })
      .from(engagements)
      .orderBy(desc(engagements.createdAt))
      .limit(1);

    const findingsBySev = await db
      .select({ severity: scanObservations.severity, cnt: count() })
      .from(scanObservations)
      .groupBy(scanObservations.severity);

    const sevMap: Record<string, number> = {};
    let totalF = 0;
    for (const f of findingsBySev) {
      sevMap[f.severity || "info"] = Number(f.cnt);
      totalF += Number(f.cnt);
    }

    const reportRows = await db
      .select({ id: pentestReports.id, createdAt: pentestReports.createdAt })
      .from(pentestReports)
      .orderBy(desc(pentestReports.createdAt));
    const reportCount = reportRows.length;
    const lastReport = reportRows.length > 0 ? new Date(reportRows[0].createdAt).getTime() : null;

    return {
      assessmentStatus: latestEng?.status || "No assessments",
      totalFindings: totalF,
      criticalFindings: sevMap["critical"] || 0,
      highFindings: sevMap["high"] || 0,
      mediumFindings: sevMap["medium"] || 0,
      lowFindings: sevMap["low"] || 0,
      infoFindings: sevMap["info"] || 0,
      reportsAvailable: reportCount,
      lastReportDate: lastReport,
      findingsBySeverity: findingsBySev.map(f => ({
        severity: f.severity || "info",
        count: Number(f.cnt),
      })),
    };
  }, {
    assessmentStatus: "No assessments", totalFindings: 0, criticalFindings: 0,
    highFindings: 0, mediumFindings: 0, lowFindings: 0, infoFindings: 0,
    reportsAvailable: 0, lastReportDate: null, findingsBySeverity: [],
  });
}

// ─── Admin Dashboard Data ───────────────────────────────────────────────────

export interface AdminDashboardData {
  totalUsers: number;
  usersByRole: Array<{ role: string; count: number }>;
  activeUsersLast7d: number;
  totalServers: number;
  onlineServers: number;
  integrationCount: number;
  activeIntegrations: number;
  platformErrors24h: number;
  totalEngagements: number;
  recentErrors: Array<{ id: number; message: string; severity: string; timestamp: number }>;
  recentActivity: Array<{ id: number; action: string; userId: number | null; timestamp: number }>;
}

export async function getAdminDashboardData(): Promise<AdminDashboardData> {
  return safeQuery(async () => {
    const db = (await getDb())!;

    const usersByRole = await db
      .select({ role: users.role, cnt: count() })
      .from(users)
      .groupBy(users.role);

    const totalUsers = usersByRole.reduce((s, r) => s + Number(r.cnt), 0);

    const [activeUsers] = await db
      .select({ total: sql<number>`COUNT(DISTINCT ${activityLogs.userId})` })
      .from(activityLogs)
      .where(gt(activityLogs.createdAt, hoursAgo(168)));

    const serverRows = await db
      .select({
        total: count(),
        online: sum(sql`CASE WHEN ${serverConfigs.status} = 'online' THEN 1 ELSE 0 END`),
      })
      .from(serverConfigs);

    const [intStats] = await db
      .select({
        total: count(),
        active: sum(sql`CASE WHEN ${vendorIntegrations.enabled} = 1 THEN 1 ELSE 0 END`),
      })
      .from(vendorIntegrations);

    const [errorStats] = await db
      .select({ total: count() })
      .from(platformErrors)
      .where(gt(platformErrors.createdAt, hoursAgo(24)));

    const [engStats] = await db.select({ total: count() }).from(engagements);

    const recentErrors = await db
      .select({
        id: platformErrors.id,
        message: platformErrors.message,
        severity: platformErrors.severity,
        createdAt: platformErrors.createdAt,
      })
      .from(platformErrors)
      .orderBy(desc(platformErrors.createdAt))
      .limit(5);

    const recentAct = await db
      .select({
        id: activityLogs.id,
        action: activityLogs.action,
        userId: activityLogs.userId,
        createdAt: activityLogs.createdAt,
      })
      .from(activityLogs)
      .orderBy(desc(activityLogs.createdAt))
      .limit(10);

    return {
      totalUsers,
      usersByRole: usersByRole.map(r => ({ role: r.role || "user", count: Number(r.cnt) })),
      activeUsersLast7d: Number(activeUsers?.total || 0),
      totalServers: Number(serverRows[0]?.total || 0),
      onlineServers: Number(serverRows[0]?.online || 0),
      integrationCount: Number(intStats?.total || 0),
      activeIntegrations: Number(intStats?.active || 0),
      platformErrors24h: Number(errorStats?.total || 0),
      totalEngagements: Number(engStats?.total || 0),
      recentErrors: recentErrors.map(e => ({
        id: e.id,
        message: e.message || "Unknown error",
        severity: e.severity || "error",
        timestamp: new Date(e.createdAt).getTime(),
      })),
      recentActivity: recentAct.map(a => ({
        id: a.id,
        action: a.action || "unknown",
        userId: a.userId,
        timestamp: new Date(a.createdAt).getTime(),
      })),
    };
  }, {
    totalUsers: 0, usersByRole: [], activeUsersLast7d: 0,
    totalServers: 0, onlineServers: 0, integrationCount: 0, activeIntegrations: 0,
    platformErrors24h: 0, totalEngagements: 0,
    recentErrors: [], recentActivity: [],
  });
}
