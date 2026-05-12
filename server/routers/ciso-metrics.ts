import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { getDb } from "../db";
import { sql, eq, desc, count, and, gte, lte, isNotNull, asc } from "drizzle-orm";
import {
  phishingDrafts,
  edrTestResults,
  edrCoverageMatrix,
  edrTestCatalog,
  c2ExecutionLog,
  atomicTests,
  customerIntelligenceProfiles,
  remediationTasks,
  vulnScanSnapshots,
  engagementFindings,
  engagements,
  complianceReports,
} from "../../drizzle/schema";

// ─── CISO Metrics Router ────────────────────────────────────────────────────
// Board-ready metrics that CISOs care about:
// - Phishing susceptibility trends
// - Detection validation rates
// - Posture scoring over time
// - Remediation velocity & SLA compliance
//
// Author: Harrison Cook — AceofCloud (https://aceofcloud.com)

// ── MITRE ATT&CK Tactic Definitions ─────────────────────────────────────────
const MITRE_TACTICS = [
  { id: "TA0043", name: "Reconnaissance", shortName: "Recon" },
  { id: "TA0042", name: "Resource Development", shortName: "Res Dev" },
  { id: "TA0001", name: "Initial Access", shortName: "Init Access" },
  { id: "TA0002", name: "Execution", shortName: "Execution" },
  { id: "TA0003", name: "Persistence", shortName: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation", shortName: "Priv Esc" },
  { id: "TA0005", name: "Defense Evasion", shortName: "Def Evasion" },
  { id: "TA0006", name: "Credential Access", shortName: "Cred Access" },
  { id: "TA0007", name: "Discovery", shortName: "Discovery" },
  { id: "TA0008", name: "Lateral Movement", shortName: "Lat Movement" },
  { id: "TA0009", name: "Collection", shortName: "Collection" },
  { id: "TA0011", name: "Command and Control", shortName: "C2" },
  { id: "TA0010", name: "Exfiltration", shortName: "Exfiltration" },
  { id: "TA0040", name: "Impact", shortName: "Impact" },
];

// Map common tactic name variations to canonical tactic IDs
function normalizeTactic(raw: string): string | null {
  const lower = raw.toLowerCase().replace(/[_-]/g, " ").trim();
  const map: Record<string, string> = {
    "reconnaissance": "TA0043", "recon": "TA0043",
    "resource development": "TA0042",
    "initial access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege escalation": "TA0004", "priv esc": "TA0004",
    "defense evasion": "TA0005", "def evasion": "TA0005",
    "credential access": "TA0006", "cred access": "TA0006",
    "discovery": "TA0007",
    "lateral movement": "TA0008", "lat movement": "TA0008",
    "collection": "TA0009",
    "command and control": "TA0011", "c2": "TA0011", "command control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    // EDR test categories
    "process injection": "TA0005",
    "credential_access": "TA0006",
    "defense_evasion": "TA0005",
    "lateral_movement": "TA0008",
    "privilege_escalation": "TA0004",
    "command_and_control": "TA0011",
  };
  // Direct tactic ID match
  if (lower.startsWith("ta")) return lower.toUpperCase();
  return map[lower] || null;
}

export const cisoMetricsRouter = router({
  // ── Phishing Susceptibility Trends ──────────────────────────────────────
  // Aggregates phishing campaign stats over time: click rates, report rates,
  // credential captures, and campaign outcomes.
  phishingSusceptibility: protectedProcedure.query(async () => {
    const drizzleDb = await getDb();
    if (!drizzleDb) return {
      campaigns: [],
      summary: { totalCampaigns: 0, avgClickRate: 0, avgReportRate: 0, totalTargets: 0, totalClicked: 0, totalReported: 0, totalCredsCaptured: 0, trend: "stable" as const },
    };

    // Get all launched/completed phishing campaigns with stats
    const campaigns = await drizzleDb.select({
      id: phishingDrafts.id,
      name: phishingDrafts.campaignName,
      type: phishingDrafts.campaignType,
      status: phishingDrafts.draftStatus,
      priority: phishingDrafts.draftPriority,
      targetDomain: phishingDrafts.targetDomain,
      targetSector: phishingDrafts.targetSector,
      stats: phishingDrafts.campaignStats,
      launchDate: phishingDrafts.launchDate,
      createdAt: phishingDrafts.createdAt,
      engagementId: phishingDrafts.engagementId,
    })
      .from(phishingDrafts)
      .where(
        sql`${phishingDrafts.draftStatus} IN ('launched', 'completed') AND ${phishingDrafts.campaignStats} IS NOT NULL`
      )
      .orderBy(desc(phishingDrafts.createdAt))
      .limit(50);

    // Parse campaign stats and aggregate
    let totalTargets = 0;
    let totalClicked = 0;
    let totalReported = 0;
    let totalCredsCaptured = 0;
    let totalOpened = 0;
    const clickRates: number[] = [];

    const parsedCampaigns = campaigns.map(c => {
      const stats = (c.stats as any) || {};
      const sent = stats.total || stats.sent || 0;
      const opened = stats.opened || 0;
      const clicked = stats.clicked || 0;
      const submitted = stats.submitted_data || stats.submitted || stats.credentials_captured || 0;
      const reported = stats.reported || stats.email_reported || 0;
      const clickRate = sent > 0 ? Math.round((clicked / sent) * 100) : 0;
      const openRate = sent > 0 ? Math.round((opened / sent) * 100) : 0;
      const reportRate = sent > 0 ? Math.round((reported / sent) * 100) : 0;

      totalTargets += sent;
      totalClicked += clicked;
      totalReported += reported;
      totalCredsCaptured += submitted;
      totalOpened += opened;
      if (sent > 0) clickRates.push(clickRate);

      return {
        id: c.id,
        name: c.name,
        type: c.type,
        status: c.status,
        priority: c.priority,
        targetDomain: c.targetDomain,
        targetSector: c.targetSector,
        engagementId: c.engagementId,
        launchDate: c.launchDate || c.createdAt,
        metrics: {
          sent,
          opened,
          clicked,
          submitted,
          reported,
          clickRate,
          openRate,
          reportRate,
        },
      };
    });

    const avgClickRate = clickRates.length > 0
      ? Math.round(clickRates.reduce((a, b) => a + b, 0) / clickRates.length)
      : 0;
    const avgReportRate = totalTargets > 0
      ? Math.round((totalReported / totalTargets) * 100)
      : 0;

    // Determine trend: compare first half vs second half of campaigns
    let trend: "improving" | "declining" | "stable" = "stable";
    if (clickRates.length >= 4) {
      const mid = Math.floor(clickRates.length / 2);
      const olderAvg = clickRates.slice(mid).reduce((a, b) => a + b, 0) / (clickRates.length - mid);
      const newerAvg = clickRates.slice(0, mid).reduce((a, b) => a + b, 0) / mid;
      if (newerAvg < olderAvg - 3) trend = "improving";
      else if (newerAvg > olderAvg + 3) trend = "declining";
    }

    return {
      campaigns: parsedCampaigns,
      summary: {
        totalCampaigns: parsedCampaigns.length,
        avgClickRate,
        avgReportRate,
        totalTargets,
        totalClicked,
        totalReported,
        totalCredsCaptured,
        trend,
      },
    };
  }),

  // ── Detection & Control Validation ──────────────────────────────────────
  // Aggregates EDR test results and C2 execution logs to show:
  // - Detection hit rate (% of tests where EDR detected the attack)
  // - Technique success rate (% of C2 techniques that succeeded)
  // - Breakdown by detection result type
  detectionValidation: protectedProcedure.query(async () => {
    const drizzleDb = await getDb();
    if (!drizzleDb) return {
      edr: { total: 0, detected: 0, missed: 0, partial: 0, delayed: 0, blocked: 0, detectionRate: 0, missRate: 0 },
      c2: { total: 0, succeeded: 0, failed: 0, successRate: 0 },
      controlCoverage: 0,
      recentTests: [],
    };

    // EDR test result aggregation
    const edrResults = await drizzleDb.select({
      result: edrTestResults.detectionResult,
      cnt: count(),
    })
      .from(edrTestResults)
      .where(isNotNull(edrTestResults.detectionResult))
      .groupBy(edrTestResults.detectionResult);

    const edrMap: Record<string, number> = {};
    let edrTotal = 0;
    for (const r of edrResults) {
      edrMap[r.result || "unknown"] = r.cnt;
      edrTotal += r.cnt;
    }

    const detected = edrMap["detected"] || 0;
    const missed = edrMap["missed"] || 0;
    const partial = edrMap["partial"] || 0;
    const delayed = edrMap["delayed"] || 0;
    const blocked = edrMap["blocked"] || 0;

    // C2 execution log aggregation (technique success/fail)
    const c2Results = await drizzleDb.select({
      success: c2ExecutionLog.celSuccess,
      cnt: count(),
    })
      .from(c2ExecutionLog)
      .groupBy(c2ExecutionLog.celSuccess);

    let c2Total = 0;
    let c2Succeeded = 0;
    let c2Failed = 0;
    for (const r of c2Results) {
      c2Total += r.cnt;
      if (r.success === 1) c2Succeeded += r.cnt;
      else c2Failed += r.cnt;
    }

    // Control coverage: % of compliance controls that are covered (not gap)
    const compReports = await drizzleDb.select({
      totalControls: complianceReports.totalControls,
      coveredControls: complianceReports.coveredControls,
      gapControls: complianceReports.gapControls,
    })
      .from(complianceReports)
      .orderBy(desc(complianceReports.createdAt))
      .limit(20);

    let totalControls = 0;
    let coveredControls = 0;
    for (const r of compReports) {
      totalControls += r.totalControls || 0;
      coveredControls += r.coveredControls || 0;
    }
    const controlCoverage = totalControls > 0 ? Math.round((coveredControls / totalControls) * 100) : 0;

    // Recent EDR test results (last 10)
    const recentTests = await drizzleDb.select({
      id: edrTestResults.id,
      result: edrTestResults.detectionResult,
      alertTitle: edrTestResults.alertTitle,
      alertSeverity: edrTestResults.alertSeverity,
      detectionTimeMs: edrTestResults.detectionTimeMs,
      responseAction: edrTestResults.responseAction,
      engagementId: edrTestResults.engagementId,
    })
      .from(edrTestResults)
      .where(isNotNull(edrTestResults.detectionResult))
      .orderBy(desc(edrTestResults.id))
      .limit(10);

    return {
      edr: {
        total: edrTotal,
        detected,
        missed,
        partial,
        delayed,
        blocked,
        detectionRate: edrTotal > 0 ? Math.round(((detected + blocked) / edrTotal) * 100) : 0,
        missRate: edrTotal > 0 ? Math.round((missed / edrTotal) * 100) : 0,
      },
      c2: {
        total: c2Total,
        succeeded: c2Succeeded,
        failed: c2Failed,
        successRate: c2Total > 0 ? Math.round((c2Succeeded / c2Total) * 100) : 0,
      },
      controlCoverage,
      recentTests: recentTests.map(t => ({
        id: t.id,
        result: t.result,
        alertTitle: t.alertTitle,
        alertSeverity: t.alertSeverity,
        detectionTimeMs: t.detectionTimeMs,
        responseAction: t.responseAction,
        engagementId: t.engagementId,
      })),
    };
  }),

  // ── Posture History & Trending ──────────────────────────────────────────
  // Pulls from customerIntelligenceProfiles for posture score trends,
  // findings trends, recurring weaknesses, and persistent gaps.
  postureHistory: protectedProcedure.query(async () => {
    const drizzleDb = await getDb();
    if (!drizzleDb) return {
      profiles: [],
      aggregatePosture: { avgScore: 0, bestScore: 0, worstScore: 0, trend: "stable" as const },
      topWeaknesses: [],
      persistentGaps: [],
    };

    const profiles = await drizzleDb.select({
      id: customerIntelligenceProfiles.id,
      customerId: customerIntelligenceProfiles.customerId,
      customerName: customerIntelligenceProfiles.customerName,
      score: customerIntelligenceProfiles.overallPostureScore,
      grade: customerIntelligenceProfiles.postureGrade,
      trend: customerIntelligenceProfiles.postureTrend,
      totalEngagements: customerIntelligenceProfiles.totalEngagements,
      totalFindings: customerIntelligenceProfiles.totalFindings,
      totalCritical: customerIntelligenceProfiles.totalCritical,
      totalHigh: customerIntelligenceProfiles.totalHigh,
      postureTrendData: customerIntelligenceProfiles.postureTrendData,
      findingsTrendData: customerIntelligenceProfiles.findingsTrendData,
      recurringWeaknesses: customerIntelligenceProfiles.recurringWeaknesses,
      persistentGaps: customerIntelligenceProfiles.persistentGaps,
      attackSurfaceSize: customerIntelligenceProfiles.attackSurfaceSize,
      attackSurfaceTrend: customerIntelligenceProfiles.attackSurfaceTrend,
      openGaps: customerIntelligenceProfiles.openGapsCount,
      resolvedGaps: customerIntelligenceProfiles.resolvedGapsCount,
      lastEngagementDate: customerIntelligenceProfiles.lastEngagementDate,
      lastUpdated: customerIntelligenceProfiles.lastUpdated,
    })
      .from(customerIntelligenceProfiles)
      .orderBy(desc(customerIntelligenceProfiles.lastUpdated))
      .limit(50);

    // Aggregate posture scores
    const scores = profiles.filter(p => p.score != null).map(p => p.score!);
    const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    const bestScore = scores.length > 0 ? Math.round(Math.max(...scores)) : 0;
    const worstScore = scores.length > 0 ? Math.round(Math.min(...scores)) : 0;

    // Aggregate recurring weaknesses across all profiles
    const weaknessMap: Record<string, { count: number; lastSeen: string; trend: string }> = {};
    for (const p of profiles) {
      const weaknesses = p.recurringWeaknesses as Array<{ category: string; count: number; lastSeen: string; trend: string }> | null;
      if (weaknesses) {
        for (const w of weaknesses) {
          if (!weaknessMap[w.category]) {
            weaknessMap[w.category] = { count: 0, lastSeen: w.lastSeen, trend: w.trend };
          }
          weaknessMap[w.category].count += w.count;
          if (w.lastSeen > weaknessMap[w.category].lastSeen) {
            weaknessMap[w.category].lastSeen = w.lastSeen;
          }
        }
      }
    }

    const topWeaknesses = Object.entries(weaknessMap)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10)
      .map(([category, data]) => ({ category, ...data }));

    // Aggregate persistent gaps
    const gapMap: Record<string, { title: string; firstSeen: string; occurrences: number }> = {};
    for (const p of profiles) {
      const gaps = p.persistentGaps as Array<{ gapId: number; title: string; firstSeen: string; occurrences: number }> | null;
      if (gaps) {
        for (const g of gaps) {
          const key = g.title;
          if (!gapMap[key]) {
            gapMap[key] = { title: g.title, firstSeen: g.firstSeen, occurrences: 0 };
          }
          gapMap[key].occurrences += g.occurrences;
          if (g.firstSeen < gapMap[key].firstSeen) {
            gapMap[key].firstSeen = g.firstSeen;
          }
        }
      }
    }

    const persistentGaps = Object.values(gapMap)
      .sort((a, b) => b.occurrences - a.occurrences)
      .slice(0, 10);

    // Determine overall trend
    let aggregateTrend: "improving" | "declining" | "stable" = "stable";
    const trendCounts = profiles.reduce((acc, p) => {
      if (p.trend === "improving") acc.improving++;
      else if (p.trend === "declining") acc.declining++;
      else acc.stable++;
      return acc;
    }, { improving: 0, declining: 0, stable: 0 });
    if (trendCounts.improving > trendCounts.declining + 2) aggregateTrend = "improving";
    else if (trendCounts.declining > trendCounts.improving + 2) aggregateTrend = "declining";

    return {
      profiles: profiles.map(p => ({
        id: p.id,
        customerId: p.customerId,
        customerName: p.customerName,
        score: p.score ? Math.round(p.score) : null,
        grade: p.grade,
        trend: p.trend,
        totalEngagements: p.totalEngagements,
        totalFindings: p.totalFindings,
        totalCritical: p.totalCritical,
        totalHigh: p.totalHigh,
        attackSurfaceSize: p.attackSurfaceSize,
        openGaps: p.openGaps,
        resolvedGaps: p.resolvedGaps,
        postureTrendData: p.postureTrendData,
        findingsTrendData: p.findingsTrendData,
        attackSurfaceTrend: p.attackSurfaceTrend,
        lastEngagementDate: p.lastEngagementDate,
        lastUpdated: p.lastUpdated,
      })),
      aggregatePosture: { avgScore, bestScore, worstScore, trend: aggregateTrend },
      topWeaknesses,
      persistentGaps,
    };
  }),

  // ── Remediation Velocity & SLA Compliance ───────────────────────────────
  // Tracks remediation task status, SLA compliance, and mean time to remediate.
  remediationMetrics: protectedProcedure.query(async () => {
    const drizzleDb = await getDb();
    if (!drizzleDb) return {
      summary: { total: 0, open: 0, inProgress: 0, fixed: 0, verified: 0, deferred: 0, wontFix: 0 },
      bySeverity: [],
      slaCompliance: { total: 0, withinSla: 0, overdue: 0, complianceRate: 0 },
      mttr: { avgDays: 0, medianDays: 0, criticalAvgDays: 0, highAvgDays: 0 },
      recentFixed: [],
    };

    // Status breakdown
    const statusRows = await drizzleDb.select({
      status: remediationTasks.status,
      cnt: count(),
    })
      .from(remediationTasks)
      .groupBy(remediationTasks.status);

    const statusMap: Record<string, number> = {};
    let total = 0;
    for (const r of statusRows) {
      statusMap[r.status] = r.cnt;
      total += r.cnt;
    }

    // Severity breakdown
    const severityRows = await drizzleDb.select({
      severity: remediationTasks.severity,
      status: remediationTasks.status,
      cnt: count(),
    })
      .from(remediationTasks)
      .groupBy(remediationTasks.severity, remediationTasks.status);

    const severityMap: Record<string, { total: number; open: number; fixed: number; verified: number }> = {};
    for (const r of severityRows) {
      const sev = r.severity;
      if (!severityMap[sev]) severityMap[sev] = { total: 0, open: 0, fixed: 0, verified: 0 };
      severityMap[sev].total += r.cnt;
      if (r.status === "open" || r.status === "assigned" || r.status === "in_progress") {
        severityMap[sev].open += r.cnt;
      } else if (r.status === "fixed") {
        severityMap[sev].fixed += r.cnt;
      } else if (r.status === "verified") {
        severityMap[sev].verified += r.cnt;
      }
    }

    const bySeverity = ["critical", "high", "medium", "low", "info"]
      .filter(s => severityMap[s])
      .map(s => ({ severity: s, ...severityMap[s] }));

    // SLA compliance: tasks with slaDeadline that are fixed/verified before deadline
    const slaRows = await drizzleDb.select({
      id: remediationTasks.id,
      slaDeadline: remediationTasks.slaDeadline,
      fixedAt: remediationTasks.fixedAt,
      status: remediationTasks.status,
    })
      .from(remediationTasks)
      .where(isNotNull(remediationTasks.slaDeadline));

    let slaTotal = slaRows.length;
    let withinSla = 0;
    let overdue = 0;
    const now = new Date();
    for (const r of slaRows) {
      const deadline = r.slaDeadline ? new Date(r.slaDeadline) : null;
      if (!deadline) continue;
      if (r.status === "fixed" || r.status === "verified") {
        const fixDate = r.fixedAt ? new Date(r.fixedAt) : now;
        if (fixDate <= deadline) withinSla++;
        else overdue++;
      } else if (now > deadline) {
        overdue++;
      } else {
        withinSla++; // still within SLA window
      }
    }

    // MTTR: mean time to remediate (for fixed/verified tasks)
    const fixedTasks = await drizzleDb.select({
      severity: remediationTasks.severity,
      createdAt: remediationTasks.createdAt,
      fixedAt: remediationTasks.fixedAt,
    })
      .from(remediationTasks)
      .where(isNotNull(remediationTasks.fixedAt))
      .limit(200);

    const remediationDays: number[] = [];
    const criticalDays: number[] = [];
    const highDays: number[] = [];
    for (const t of fixedTasks) {
      if (t.createdAt && t.fixedAt) {
        const days = Math.max(0, (new Date(t.fixedAt).getTime() - new Date(t.createdAt).getTime()) / (1000 * 60 * 60 * 24));
        remediationDays.push(days);
        if (t.severity === "critical") criticalDays.push(days);
        if (t.severity === "high") highDays.push(days);
      }
    }

    const avgDays = remediationDays.length > 0
      ? Math.round(remediationDays.reduce((a, b) => a + b, 0) / remediationDays.length * 10) / 10
      : 0;
    const sortedDays = [...remediationDays].sort((a, b) => a - b);
    const medianDays = sortedDays.length > 0
      ? Math.round(sortedDays[Math.floor(sortedDays.length / 2)] * 10) / 10
      : 0;
    const criticalAvgDays = criticalDays.length > 0
      ? Math.round(criticalDays.reduce((a, b) => a + b, 0) / criticalDays.length * 10) / 10
      : 0;
    const highAvgDays = highDays.length > 0
      ? Math.round(highDays.reduce((a, b) => a + b, 0) / highDays.length * 10) / 10
      : 0;

    // Recently fixed tasks
    const recentFixed = await drizzleDb.select({
      id: remediationTasks.id,
      title: remediationTasks.title,
      severity: remediationTasks.severity,
      fixedAt: remediationTasks.fixedAt,
      affectedAsset: remediationTasks.affectedAsset,
    })
      .from(remediationTasks)
      .where(isNotNull(remediationTasks.fixedAt))
      .orderBy(desc(remediationTasks.fixedAt))
      .limit(10);

    return {
      summary: {
        total,
        open: (statusMap["open"] || 0) + (statusMap["assigned"] || 0),
        inProgress: statusMap["in_progress"] || 0,
        fixed: statusMap["fixed"] || 0,
        verified: statusMap["verified"] || 0,
        deferred: statusMap["deferred"] || 0,
        wontFix: statusMap["wont_fix"] || 0,
      },
      bySeverity,
      slaCompliance: {
        total: slaTotal,
        withinSla,
        overdue,
        complianceRate: slaTotal > 0 ? Math.round((withinSla / slaTotal) * 100) : 0,
      },
      mttr: { avgDays, medianDays, criticalAvgDays, highAvgDays },
      recentFixed: recentFixed.map(t => ({
        id: t.id,
        title: t.title,
        severity: t.severity,
        fixedAt: t.fixedAt,
        affectedAsset: t.affectedAsset,
      })),
    };
  }),

  // ── Vulnerability Trend Over Time ───────────────────────────────────────
  // Aggregates vuln scan snapshots to show severity trends across engagements.
  vulnTrend: protectedProcedure.query(async () => {
    const drizzleDb = await getDb();
    if (!drizzleDb) return { snapshots: [], summary: { totalScans: 0, latestCritical: 0, latestHigh: 0, trend: "stable" as const } };

    const snapshots = await drizzleDb.select({
      id: vulnScanSnapshots.id,
      engagementId: vulnScanSnapshots.engagementId,
      type: vulnScanSnapshots.snapshotType,
      totalVulns: vulnScanSnapshots.totalVulns,
      critical: vulnScanSnapshots.criticalCount,
      high: vulnScanSnapshots.highCount,
      medium: vulnScanSnapshots.mediumCount,
      low: vulnScanSnapshots.lowCount,
      totalAssets: vulnScanSnapshots.totalAssets,
      totalExploits: vulnScanSnapshots.totalExploits,
      newVulns: vulnScanSnapshots.newVulnsFound,
      resolved: vulnScanSnapshots.resolvedVulns,
      createdAt: vulnScanSnapshots.createdAt,
    })
      .from(vulnScanSnapshots)
      .orderBy(desc(vulnScanSnapshots.createdAt))
      .limit(100);

    const latest = snapshots[0];
    const oldest = snapshots[snapshots.length - 1];
    let trend: "improving" | "declining" | "stable" = "stable";
    if (latest && oldest) {
      const latestSeverity = (latest.critical || 0) * 4 + (latest.high || 0) * 3;
      const oldestSeverity = (oldest.critical || 0) * 4 + (oldest.high || 0) * 3;
      if (latestSeverity < oldestSeverity - 5) trend = "improving";
      else if (latestSeverity > oldestSeverity + 5) trend = "declining";
    }

    return {
      snapshots: snapshots.reverse().map(s => ({
        id: s.id,
        engagementId: s.engagementId,
        type: s.type,
        totalVulns: s.totalVulns,
        critical: s.critical,
        high: s.high,
        medium: s.medium,
        low: s.low,
        totalAssets: s.totalAssets,
        totalExploits: s.totalExploits,
        newVulns: s.newVulns,
        resolved: s.resolved,
        date: s.createdAt,
      })),
      summary: {
        totalScans: snapshots.length,
        latestCritical: latest?.critical || 0,
        latestHigh: latest?.high || 0,
        trend,
      },
    };
  }),

  // ── MITRE ATT&CK Heatmap ───────────────────────────────────────────────
  // Aggregates C2 execution logs, EDR coverage matrix, and Caldera abilities
  // into a tactic × technique grid with success/fail/blocked counts.
  mitreHeatmap: protectedProcedure.query(async () => {
    const drizzleDb = await getDb();
    if (!drizzleDb) return { tactics: MITRE_TACTICS, techniques: [], coverage: { totalTechniques: 0, testedTechniques: 0, coveragePercent: 0 } };

    // 1. C2 execution logs grouped by technique
    const c2Rows = await drizzleDb.select({
      techniqueId: c2ExecutionLog.techniqueId,
      success: c2ExecutionLog.celSuccess,
      cnt: count(),
    })
      .from(c2ExecutionLog)
      .groupBy(c2ExecutionLog.techniqueId, c2ExecutionLog.celSuccess);

    // 2. EDR coverage matrix (already has tactic+technique+detected/missed/blocked)
    const edrRows = await drizzleDb.select({
      tacticId: edrCoverageMatrix.mitreTacticId,
      techniqueId: edrCoverageMatrix.mitreTechniqueId,
      totalTests: edrCoverageMatrix.totalTests,
      detected: edrCoverageMatrix.detected,
      missed: edrCoverageMatrix.missed,
      partial: edrCoverageMatrix.partial,
      blocked: edrCoverageMatrix.blocked,
      coverageScore: edrCoverageMatrix.coverageScore,
    })
      .from(edrCoverageMatrix);

    // 3. Atomic tests for technique → tactic mapping
    const abilityRows = await drizzleDb.select({
      techniqueId: atomicTests.techniqueId,
      techniqueName: atomicTests.techniqueName,
      tactic: atomicTests.mitreTactic,
    })
      .from(atomicTests)
      .groupBy(atomicTests.techniqueId, atomicTests.techniqueName, atomicTests.mitreTactic);

    // 4. EDR test catalog for technique → tactic mapping via category
    const catalogRows = await drizzleDb.select({
      techniqueId: edrTestCatalog.mitreTechniqueId,
      techniqueName: edrTestCatalog.mitreTechniqueName,
      category: edrTestCatalog.testCategory,
    })
      .from(edrTestCatalog)
      .where(isNotNull(edrTestCatalog.mitreTechniqueId));

    // Build technique map: techniqueId → { name, tacticId, succeeded, failed, blocked, detected, missed, tested }
    type TechniqueData = {
      id: string;
      name: string;
      tacticId: string;
      succeeded: number;
      failed: number;
      blocked: number;
      detected: number;
      missed: number;
      partial: number;
      totalTests: number;
      coverageScore: number | null;
    };
    const techMap: Record<string, TechniqueData> = {};

    function ensureTech(id: string, name?: string, tacticId?: string): TechniqueData {
      if (!techMap[id]) {
        techMap[id] = { id, name: name || id, tacticId: tacticId || "TA0002", succeeded: 0, failed: 0, blocked: 0, detected: 0, missed: 0, partial: 0, totalTests: 0, coverageScore: null };
      }
      if (name && techMap[id].name === id) techMap[id].name = name;
      if (tacticId) techMap[id].tacticId = tacticId;
      return techMap[id];
    }

    // Map abilities to techniques with tactic
    for (const a of abilityRows) {
      const tacticId = a.tactic ? normalizeTactic(a.tactic) : null;
      ensureTech(a.techniqueId, a.techniqueName, tacticId || undefined);
    }

    // Map catalog entries
    for (const c of catalogRows) {
      if (!c.techniqueId) continue;
      const tacticId = normalizeTactic(c.category);
      ensureTech(c.techniqueId, c.techniqueName || undefined, tacticId || undefined);
    }

    // Aggregate C2 execution results
    for (const r of c2Rows) {
      const tech = ensureTech(r.techniqueId);
      if (r.success === 1) tech.succeeded += r.cnt;
      else tech.failed += r.cnt;
    }

    // Aggregate EDR coverage
    for (const r of edrRows) {
      const tech = ensureTech(r.techniqueId, undefined, r.tacticId);
      tech.detected += r.detected || 0;
      tech.missed += r.missed || 0;
      tech.partial += r.partial || 0;
      tech.blocked += r.blocked || 0;
      tech.totalTests += r.totalTests || 0;
      if (r.coverageScore != null) tech.coverageScore = r.coverageScore;
    }

    // Build output grouped by tactic
    const techniques = Object.values(techMap).map(t => {
      const total = t.succeeded + t.failed + t.blocked;
      const edrTotal = t.detected + t.missed + t.partial + t.blocked;
      return {
        id: t.id,
        name: t.name,
        tacticId: t.tacticId,
        c2: {
          total,
          succeeded: t.succeeded,
          failed: t.failed,
          successRate: total > 0 ? Math.round((t.succeeded / total) * 100) : 0,
        },
        edr: {
          total: edrTotal,
          detected: t.detected,
          missed: t.missed,
          partial: t.partial,
          blocked: t.blocked,
          detectionRate: edrTotal > 0 ? Math.round(((t.detected + t.blocked) / edrTotal) * 100) : 0,
        },
        coverageScore: t.coverageScore,
        // Heat level: 0=untested, 1=all detected/blocked, 2=mostly detected, 3=mixed, 4=mostly missed, 5=all missed
        heatLevel: total === 0 && edrTotal === 0 ? 0
          : (t.succeeded === 0 && t.missed === 0) ? 1
          : (t.succeeded > 0 && t.missed === 0 && t.detected > t.succeeded) ? 2
          : (t.missed > t.detected + t.blocked) ? 4
          : (t.missed > 0 && t.detected === 0 && t.blocked === 0) ? 5
          : 3,
      };
    });

    const testedTechniques = techniques.filter(t => t.c2.total > 0 || t.edr.total > 0).length;

    return {
      tactics: MITRE_TACTICS,
      techniques,
      coverage: {
        totalTechniques: techniques.length,
        testedTechniques,
        coveragePercent: techniques.length > 0 ? Math.round((testedTechniques / techniques.length) * 100) : 0,
      },
    };
  }),
});
