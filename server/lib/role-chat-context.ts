/**
 * Role-Aware Context Enrichment for AI Chat
 *
 * Fetches live dashboard data relevant to each role and formats it
 * as context strings to inject into the LLM system prompt.
 * This gives the AI real-time awareness of the platform state.
 */

import { getDb } from "../db";
import { sql, desc, gt, eq, count, sum } from "drizzle-orm";
import {
  engagements,
  opsecEvents,
  scanObservations,
  threatActors,
  threatActorIocs,
  ransomwareGroups,
  users,
  serverConfigs,
  platformErrors,
  activityLogs,
  pentestReports,
  defenseScores,
  engagementTimelineEvents,
  vendorIntegrations,
} from "../../drizzle/schema";

function hoursAgo(h: number): Date {
  return new Date(Date.now() - h * 3600_000);
}
function hoursAgoMs(h: number): number {
  return Date.now() - h * 3600_000;
}

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try { return await fn(); } catch { return fallback; }
}

// ─── Operator Context ───────────────────────────────────────────────────────

export async function getOperatorContext(): Promise<string> {
  return safe(async () => {
    const db = (await getDb())!;

    const [engStats] = await db.select({
      total: count(),
      active: sum(sql`CASE WHEN ${engagements.status} = 'active' THEN 1 ELSE 0 END`),
    }).from(engagements);

    const recentOpsec = await db.select({ riskScore: opsecEvents.riskScore })
      .from(opsecEvents).orderBy(desc(opsecEvents.timestamp)).limit(10);
    const avgOpsec = recentOpsec.length > 0
      ? Math.round(recentOpsec.reduce((s, e) => s + (e.riskScore || 0), 0) / recentOpsec.length)
      : 0;

    const [findings] = await db.select({
      total: count(),
      critical: sum(sql`CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END`),
      high: sum(sql`CASE WHEN ${scanObservations.severity} = 'high' THEN 1 ELSE 0 END`),
    }).from(scanObservations);

    const recentEvents = await db.select({
      title: engagementTimelineEvents.title,
      eventType: engagementTimelineEvents.eventType,
      phase: engagementTimelineEvents.phase,
    }).from(engagementTimelineEvents)
      .orderBy(desc(engagementTimelineEvents.timestamp)).limit(5);

    const lines = [
      `\n--- LIVE OPERATOR CONTEXT ---`,
      `Engagements: ${engStats?.total || 0} total, ${engStats?.active || 0} active`,
      `OPSEC Risk Score (avg last 10): ${avgOpsec}/100 ${avgOpsec > 70 ? '⚠️ HIGH RISK' : avgOpsec > 40 ? '⚡ MODERATE' : '✅ LOW'}`,
      `Findings: ${findings?.total || 0} total (${findings?.critical || 0} critical, ${findings?.high || 0} high)`,
    ];
    if (recentEvents.length > 0) {
      lines.push(`Recent activity:`);
      for (const e of recentEvents) {
        lines.push(`  - [${e.eventType}] ${e.title} (phase: ${e.phase})`);
      }
    }
    return lines.join("\n");
  }, "");
}

// ─── Executive Context ──────────────────────────────────────────────────────

export async function getExecutiveContext(): Promise<string> {
  return safe(async () => {
    const db = (await getDb())!;

    const [engStats] = await db.select({
      total: count(),
      active: sum(sql`CASE WHEN ${engagements.status} = 'active' THEN 1 ELSE 0 END`),
      completed: sum(sql`CASE WHEN ${engagements.status} = 'completed' THEN 1 ELSE 0 END`),
    }).from(engagements);

    const [vulns] = await db.select({
      total: count(),
      critical: sum(sql`CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END`),
      high: sum(sql`CASE WHEN ${scanObservations.severity} = 'high' THEN 1 ELSE 0 END`),
    }).from(scanObservations);

    const defRows = await db.select({ score: defenseScores.overallScore })
      .from(defenseScores).orderBy(desc(defenseScores.createdAt)).limit(5);
    const avgDef = defRows.length > 0
      ? Math.round(defRows.reduce((s, r) => s + Number(r.score || 0), 0) / defRows.length)
      : 0;

    const [reports] = await db.select({ total: count() }).from(pentestReports);

    const opsecRows = await db.select({ riskScore: opsecEvents.riskScore })
      .from(opsecEvents).orderBy(desc(opsecEvents.timestamp)).limit(20);
    const avgRisk = opsecRows.length > 0
      ? opsecRows.reduce((s, r) => s + (r.riskScore || 0), 0) / opsecRows.length : 50;
    const riskPosture = Math.max(0, Math.min(100, Math.round(100 - avgRisk)));

    return [
      `\n--- LIVE EXECUTIVE CONTEXT ---`,
      `Risk Posture Score: ${riskPosture}/100 ${riskPosture >= 70 ? '✅ GOOD' : riskPosture >= 40 ? '⚡ NEEDS ATTENTION' : '⚠️ CRITICAL'}`,
      `Defense Score (avg): ${avgDef}/100`,
      `Engagements: ${engStats?.total || 0} total (${engStats?.active || 0} active, ${engStats?.completed || 0} completed)`,
      `Vulnerabilities: ${vulns?.total || 0} total (${vulns?.critical || 0} critical, ${vulns?.high || 0} high)`,
      `Reports Generated: ${reports?.total || 0}`,
    ].join("\n");
  }, "");
}

// ─── Analyst Context ────────────────────────────────────────────────────────

export async function getAnalystContext(): Promise<string> {
  return safe(async () => {
    const db = (await getDb())!;

    const [taStats] = await db.select({
      total: count(),
      active: sum(sql`CASE WHEN ${threatActors.active} = 1 THEN 1 ELSE 0 END`),
    }).from(threatActors);

    const [iocStats] = await db.select({ total: count() }).from(threatActorIocs);
    const [rwStats] = await db.select({ total: count() }).from(ransomwareGroups);

    const [vulns] = await db.select({
      total: count(),
      critical: sum(sql`CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END`),
    }).from(scanObservations);

    const topActors = await db.select({ name: threatActors.name, sophistication: threatActors.sophistication })
      .from(threatActors).where(eq(threatActors.active, true)).limit(5);

    const lines = [
      `\n--- LIVE ANALYST CONTEXT ---`,
      `Threat Actors Tracked: ${taStats?.total || 0} (${taStats?.active || 0} active)`,
      `IOCs in Database: ${iocStats?.total || 0}`,
      `Ransomware Groups: ${rwStats?.total || 0}`,
      `Vulnerabilities: ${vulns?.total || 0} (${vulns?.critical || 0} critical)`,
    ];
    if (topActors.length > 0) {
      lines.push(`Active Threat Actors: ${topActors.map(a => `${a.name} (${a.sophistication || 'unknown'})`).join(', ')}`);
    }
    return lines.join("\n");
  }, "");
}

// ─── Team Lead Context ──────────────────────────────────────────────────────

export async function getTeamLeadContext(): Promise<string> {
  return safe(async () => {
    const db = (await getDb())!;

    const pipelineRows = await db.select({ status: engagements.status, cnt: count() })
      .from(engagements).groupBy(engagements.status);
    const pipeline: Record<string, number> = {};
    for (const r of pipelineRows) pipeline[r.status || "unknown"] = Number(r.cnt);

    const [teamStats] = await db.select({
      total: count(),
      operators: sum(sql`CASE WHEN ${users.role} IN ('operator', 'admin') THEN 1 ELSE 0 END`),
    }).from(users);

    const [findings] = await db.select({
      total: count(),
      critical: sum(sql`CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END`),
    }).from(scanObservations);

    const [reports] = await db.select({ total: count() }).from(pentestReports);

    const recentEngs = await db.select({ name: engagements.name, status: engagements.status, customerName: engagements.customerName })
      .from(engagements).orderBy(desc(engagements.createdAt)).limit(5);

    const lines = [
      `\n--- LIVE TEAM LEAD CONTEXT ---`,
      `Team: ${teamStats?.total || 0} members (${teamStats?.operators || 0} operators)`,
      `Pipeline: ${Object.entries(pipeline).map(([k, v]) => `${k}: ${v}`).join(', ')}`,
      `Findings: ${findings?.total || 0} total (${findings?.critical || 0} critical)`,
      `Reports Delivered: ${reports?.total || 0}`,
    ];
    if (recentEngs.length > 0) {
      lines.push(`Recent Engagements:`);
      for (const e of recentEngs) {
        lines.push(`  - ${e.name} (${e.customerName}) — ${e.status}`);
      }
    }
    return lines.join("\n");
  }, "");
}

// ─── Client Context ─────────────────────────────────────────────────────────

export async function getClientContext(): Promise<string> {
  return safe(async () => {
    const db = (await getDb())!;

    const findingsBySev = await db.select({ severity: scanObservations.severity, cnt: count() })
      .from(scanObservations).groupBy(scanObservations.severity);
    const sevMap: Record<string, number> = {};
    let totalF = 0;
    for (const f of findingsBySev) { sevMap[f.severity || "info"] = Number(f.cnt); totalF += Number(f.cnt); }

    const [reports] = await db.select({ total: count() }).from(pentestReports);

    const [latestEng] = await db.select({ name: engagements.name, status: engagements.status })
      .from(engagements).orderBy(desc(engagements.createdAt)).limit(1);

    return [
      `\n--- LIVE CLIENT CONTEXT ---`,
      `Assessment Status: ${latestEng?.status || 'No active assessments'}`,
      `Current Engagement: ${latestEng?.name || 'N/A'}`,
      `Total Findings: ${totalF} (Critical: ${sevMap["critical"] || 0}, High: ${sevMap["high"] || 0}, Medium: ${sevMap["medium"] || 0}, Low: ${sevMap["low"] || 0})`,
      `Reports Available: ${reports?.total || 0}`,
    ].join("\n");
  }, "");
}

// ─── Admin Context ──────────────────────────────────────────────────────────

export async function getAdminContext(): Promise<string> {
  return safe(async () => {
    const db = (await getDb())!;

    const [userStats] = await db.select({ total: count() }).from(users);

    const [serverStats] = await db.select({
      total: count(),
      online: sum(sql`CASE WHEN ${serverConfigs.status} = 'online' THEN 1 ELSE 0 END`),
    }).from(serverConfigs);

    const [errors24h] = await db.select({ total: count() })
      .from(platformErrors).where(gt(platformErrors.createdAt, hoursAgo(24)));

    const recentErrors = await db.select({ message: platformErrors.message, severity: platformErrors.severity })
      .from(platformErrors).orderBy(desc(platformErrors.createdAt)).limit(3);

    const [intStats] = await db.select({
      total: count(),
      active: sum(sql`CASE WHEN ${vendorIntegrations.enabled} = 1 THEN 1 ELSE 0 END`),
    }).from(vendorIntegrations);

    const [activeUsers7d] = await db.select({ total: sql<number>`COUNT(DISTINCT ${activityLogs.userId})` })
      .from(activityLogs).where(gt(activityLogs.createdAt, hoursAgo(168)));

    const lines = [
      `\n--- LIVE ADMIN CONTEXT ---`,
      `Users: ${userStats?.total || 0} total, ${activeUsers7d?.total || 0} active (7d)`,
      `Servers: ${serverStats?.total || 0} total, ${serverStats?.online || 0} online`,
      `Integrations: ${intStats?.total || 0} total, ${intStats?.active || 0} active`,
      `Platform Errors (24h): ${errors24h?.total || 0}`,
    ];
    if (recentErrors.length > 0) {
      lines.push(`Recent Errors:`);
      for (const e of recentErrors) {
        lines.push(`  - [${e.severity}] ${(e.message || '').slice(0, 100)}`);
      }
    }
    return lines.join("\n");
  }, "");
}

// ─── SOC Context ──────────────────────────────────────────────────────────

export async function getSocContext(): Promise<string> {
  return safe(async () => {
    const db = (await getDb())!;

    // Threat actor landscape — SOC needs full awareness
    const [taStats] = await db.select({
      total: count(),
      active: sum(sql`CASE WHEN ${threatActors.active} = 1 THEN 1 ELSE 0 END`),
    }).from(threatActors);
    const [iocStats] = await db.select({ total: count() }).from(threatActorIocs);
    const [rwStats] = await db.select({ total: count() }).from(ransomwareGroups);

    // Vulnerability posture for triage context
    const [vulns] = await db.select({
      total: count(),
      critical: sum(sql`CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END`),
      high: sum(sql`CASE WHEN ${scanObservations.severity} = 'high' THEN 1 ELSE 0 END`),
    }).from(scanObservations);

    // Opsec events (last 24h) — SOC monitors for detection triggers
    const oneDayAgo = new Date(Date.now() - 86400000);
    const [opsecRecent] = await db.select({ total: count() })
      .from(opsecEvents)
      .where(gt(opsecEvents.createdAt, oneDayAgo));

    // Active engagements for emulation awareness
    const activeEngagements = await db.select({ name: engagements.name, status: engagements.status })
      .from(engagements)
      .where(eq(engagements.status, "active"))
      .limit(5);

    // Top active threat actors for SOC threat awareness
    const topActors = await db.select({
      name: threatActors.name,
      sophistication: threatActors.sophistication,
      type: threatActors.actorType,
    }).from(threatActors).where(eq(threatActors.active, true)).limit(10);

    // Defense scores for detection coverage context
    const defScores = await db.select({
      category: defenseScores.category,
      score: defenseScores.overallScore,
    }).from(defenseScores).orderBy(desc(defenseScores.createdAt)).limit(10);

    const lines = [
      `\n--- LIVE SOC CONTEXT ---`,
      `Threat Landscape: ${taStats?.total || 0} actors tracked (${taStats?.active || 0} active), ${iocStats?.total || 0} IOCs, ${rwStats?.total || 0} ransomware groups`,
      `Vulnerability Posture: ${vulns?.total || 0} findings (${vulns?.critical || 0} critical, ${vulns?.high || 0} high)`,
      `Opsec Events (24h): ${opsecRecent?.total || 0} events — monitor for detection triggers`,
    ];

    if (topActors.length > 0) {
      lines.push(`Active Threat Actors: ${topActors.map(a => `${a.name} [${a.type || 'unknown'}/${a.sophistication || '?'}]`).join(', ')}`);
    }

    if (activeEngagements.length > 0) {
      lines.push(`Active Emulations: ${activeEngagements.map(e => e.name).join(', ')} — validate detection coverage`);
    }

    if (defScores.length > 0) {
      lines.push(`Defense Scores: ${defScores.map(d => `${d.category}: ${d.score}`).join(', ')}`);
    }

    lines.push(`SOC Focus Areas: Alert triage, detection engineering, threat hunting, Sigma/YARA rule generation, emulation validation, IOC correlation`);
    return lines.join("\n");
  }, "");
}

/**
 * Get the appropriate context enrichment for a given role.
 */
export async function getRoleContext(role: string): Promise<string> {
  switch (role) {
    case "operator": return getOperatorContext();
    case "executive": return getExecutiveContext();
    case "analyst": return getAnalystContext();
    case "team_lead": return getTeamLeadContext();
    case "client": return getClientContext();
    case "admin": return getAdminContext();
    case "soc": return getSocContext();
    default: return getOperatorContext();
  }
}
