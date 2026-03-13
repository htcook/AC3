import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { invokeLLM } from "../_core/llm";
import { desc, sql, and, gte, isNotNull, eq, count } from "drizzle-orm";
import {
  activityLogs,
  offensiveAuditLog,
  opsecEvents,
  opsecScores,
  scanResults,
  engagements,
  scanObservations,
  agentAuditLog,
} from "../../drizzle/schema";

// ─── Unified Activity Event Type ────────────────────────────────────────
interface UnifiedEvent {
  id: string;
  timestamp: string;
  category: "scan" | "engagement" | "opsec" | "agent" | "system";
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  source: string;
  metadata?: Record<string, unknown>;
}

// ─── OPSEC Gauge Result ─────────────────────────────────────────────────
interface OpsecGaugeResult {
  overallScore: number;          // 0-100 (100 = fully stealthy)
  noiseLevel: string;            // stealth | low | moderate | elevated | critical
  detectionChance: number;       // 0-100%
  activeEngagements: number;
  totalOpsecEvents: number;
  highRiskEvents: number;
  burnedAssets: string[];
  recentAlerts: number;          // alerts in last 24h
  breakdown: {
    stealthScore: number;        // 0-100 based on noise level
    exposureScore: number;       // 0-100 based on detection probability
    assetHealthScore: number;    // 0-100 based on burned assets
    eventVelocityScore: number;  // 0-100 based on event frequency
  };
  recommendations: string[];
}

export const operatorCockpitRouter = router({
  /**
   * Unified Activity Timeline — aggregates events from multiple sources
   * into a single time-ordered feed for the Operator Cockpit.
   */
  activityTimeline: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).default(50),
      hoursBack: z.number().min(1).max(720).default(24),
      categories: z.array(z.enum(["scan", "engagement", "opsec", "agent", "system"])).optional(),
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { events: [], totalCount: 0 };

      const limit = input?.limit ?? 50;
      const hoursBack = input?.hoursBack ?? 24;
      const categories = input?.categories;
      const engagementId = input?.engagementId;
      const cutoff = new Date(Date.now() - hoursBack * 60 * 60 * 1000).toISOString();

      const events: UnifiedEvent[] = [];

      // ── Source 1: Activity Logs (system events) ──
      if (!categories || categories.includes("system")) {
        try {
          const logs = await db.select().from(activityLogs)
            .where(gte(activityLogs.createdAt, cutoff))
            .orderBy(desc(activityLogs.createdAt))
            .limit(limit);

          for (const log of logs) {
            events.push({
              id: `sys-${log.id}`,
              timestamp: log.createdAt,
              category: "system",
              severity: categorizeSystemSeverity(log.action),
              title: formatSystemAction(log.action),
              description: log.details || log.action,
              source: "activity_logs",
              metadata: { userId: log.userId, ipAddress: log.ipAddress },
            });
          }
        } catch { /* table may be empty */ }
      }

      // ── Source 2: Offensive Audit Log (engagement/scan events) ──
      if (!categories || categories.includes("engagement") || categories.includes("scan")) {
        try {
          const offConditions = [gte(offensiveAuditLog.createdAt, cutoff)];
          if (engagementId) offConditions.push(eq(offensiveAuditLog.engagementId, engagementId));
          const offLogs = await db.select().from(offensiveAuditLog)
            .where(and(...offConditions))
            .orderBy(desc(offensiveAuditLog.createdAt))
            .limit(limit);

          for (const log of offLogs) {
            const cat = ["msf_check", "msf_auxiliary", "msf_exploit", "active_probe"].includes(log.actionType)
              ? "scan" as const
              : "engagement" as const;

            if (categories && !categories.includes(cat)) continue;

            events.push({
              id: `off-${log.id}`,
              timestamp: log.createdAt,
              category: cat,
              severity: riskTierToSeverity(log.riskTier),
              title: formatOffensiveAction(log.actionType, log.target),
              description: `${log.moduleOrTool || log.actionType} → ${log.target}${log.targetPort ? `:${log.targetPort}` : ""} [${log.resultStatus}]`,
              source: "offensive_audit_log",
              metadata: {
                engagementId: log.engagementId,
                operatorName: log.operatorName,
                riskTier: log.riskTier,
                resultStatus: log.resultStatus,
                roeStatus: log.roeStatus,
              },
            });
          }
        } catch { /* table may be empty */ }
      }

      // ── Source 3: OPSEC Events ──
      if (!categories || categories.includes("opsec")) {
        try {
          const opsConditions = [gte(opsecEvents.opsecCreatedAt, cutoff)];
          if (engagementId) opsConditions.push(eq(opsecEvents.engagementId, engagementId));
          const opsEvents = await db.select().from(opsecEvents)
            .where(and(...opsConditions))
            .orderBy(desc(opsecEvents.opsecCreatedAt))
            .limit(limit);

          for (const ev of opsEvents) {
            events.push({
              id: `ops-${ev.id}`,
              timestamp: ev.opsecCreatedAt,
              category: "opsec",
              severity: opsecRiskToSeverity(ev.riskScore),
              title: `OPSEC: ${ev.opsecActionType}`,
              description: ev.opsecActionDescription,
              source: "opsec_events",
              metadata: {
                riskScore: ev.riskScore,
                detectionProbability: ev.detectionProbability,
                networkNoise: ev.networkNoise,
                wasDetected: ev.wasDetected,
                saferAlternative: ev.saferAlternative,
              },
            });
          }
        } catch { /* table may be empty */ }
      }

      // ── Source 4: Agent Audit Log ──
      if (!categories || categories.includes("agent")) {
        try {
          const agentLogs = await db.select().from(agentAuditLog)
            .where(gte(agentAuditLog.createdAt, cutoff))
            .orderBy(desc(agentAuditLog.createdAt))
            .limit(limit);

          for (const log of agentLogs) {
            events.push({
              id: `agt-${log.id}`,
              timestamp: log.createdAt,
              category: "agent",
              severity: agentEventSeverity(log.eventType),
              title: `Agent: ${formatAgentEvent(log.eventType)}`,
              description: `Agent ${log.agentId} — ${log.eventType}`,
              source: "agent_audit_log",
              metadata: {
                agentId: log.agentId,
                eventType: log.eventType,
                actorType: log.actorType,
              },
            });
          }
        } catch { /* table may be empty */ }
      }

      // Sort all events by timestamp descending
      events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      return {
        events: events.slice(0, limit),
        totalCount: events.length,
      };
    }),

  /**
   * OPSEC Gauge — calculates a real-time composite OPSEC score
   * from actual engagement data, events, and scores.
   */
  opsecGauge: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }): Promise<OpsecGaugeResult> => {
    const db = await getDb();
    if (!db) return defaultOpsecGauge();
    const engagementId = input?.engagementId;

    const now = Date.now();
    const last24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const last7d = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();

    // ── 1. Active Engagements ──
    let activeEngagements = 0;
    try {
      const result = await db.select({ cnt: count() }).from(engagements)
        .where(eq(engagements.status, "active"));
      activeEngagements = result[0]?.cnt ?? 0;
    } catch { /* */ }

    // ── 2. OPSEC Events (last 7 days) ──
    let totalOpsecEvents = 0;
    let highRiskEvents = 0;
    let recentAlerts = 0;
    let avgDetectionProb = 0;
    let avgRiskScore = 0;
    let noiseLevels: string[] = [];

    try {
      const opsecConditions = [gte(opsecEvents.opsecCreatedAt, last7d)];
      if (engagementId) opsecConditions.push(eq(opsecEvents.engagementId, engagementId));
      const opsEvents = await db.select().from(opsecEvents)
        .where(and(...opsecConditions))
        .orderBy(desc(opsecEvents.opsecCreatedAt))
        .limit(500);

      totalOpsecEvents = opsEvents.length;

      let totalDetection = 0;
      let totalRisk = 0;
      let detectionCount = 0;

      for (const ev of opsEvents) {
        if (ev.riskScore >= 70) highRiskEvents++;
        if (new Date(ev.opsecCreatedAt).getTime() > now - 24 * 60 * 60 * 1000) {
          recentAlerts++;
        }
        if (ev.detectionProbability != null) {
          totalDetection += ev.detectionProbability;
          detectionCount++;
        }
        totalRisk += ev.riskScore;
        if (ev.networkNoise) noiseLevels.push(ev.networkNoise);
      }

      avgDetectionProb = detectionCount > 0 ? totalDetection / detectionCount : 0;
      avgRiskScore = totalOpsecEvents > 0 ? totalRisk / totalOpsecEvents : 0;
    } catch { /* */ }

    // ── 3. Latest OPSEC Scores (per engagement) ──
    let burnedAssets: string[] = [];
    let latestNoiseLevel = "stealth";
    let latestDetectionChance = 0;

    try {
      const scoreConditions = engagementId
        ? [eq(opsecScores.engagementId, engagementId)]
        : [];
      const scores = await db.select().from(opsecScores)
        .where(scoreConditions.length > 0 ? and(...scoreConditions) : undefined)
        .orderBy(desc(opsecScores.opsecScoreUpdatedAt))
        .limit(20);

      for (const score of scores) {
        if (score.currentNoiseLevel) {
          latestNoiseLevel = getWorstNoiseLevel(latestNoiseLevel, score.currentNoiseLevel);
        }
        if (score.estimatedDetectionChance != null) {
          latestDetectionChance = Math.max(latestDetectionChance, score.estimatedDetectionChance);
        }
        if (score.burnedAssets) {
          const assets = typeof score.burnedAssets === "string"
            ? JSON.parse(score.burnedAssets)
            : score.burnedAssets;
          if (Array.isArray(assets)) {
            burnedAssets.push(...assets.map((a: any) => typeof a === "string" ? a : a.name || a.asset || JSON.stringify(a)));
          }
        }
      }
    } catch { /* */ }

    // Deduplicate burned assets
    burnedAssets = [...new Set(burnedAssets)];

    // ── 4. Scan Observations — recent critical/high findings ──
    let recentCriticalFindings = 0;
    try {
      const critFindings = await db.select({ cnt: count() }).from(scanObservations)
        .where(and(
          gte(scanObservations.firstSeenAt, last24h),
          sql`${scanObservations.severity} IN ('critical', 'high')`
        ));
      recentCriticalFindings = critFindings[0]?.cnt ?? 0;
    } catch { /* */ }

    // ── 5. Calculate Composite Scores ──
    const stealthScore = calculateStealthScore(latestNoiseLevel, noiseLevels);
    const exposureScore = calculateExposureScore(avgDetectionProb, latestDetectionChance);
    const assetHealthScore = calculateAssetHealthScore(burnedAssets.length);
    const eventVelocityScore = calculateEventVelocityScore(recentAlerts, totalOpsecEvents, highRiskEvents);

    const overallScore = Math.round(
      stealthScore * 0.35 +
      exposureScore * 0.30 +
      assetHealthScore * 0.20 +
      eventVelocityScore * 0.15
    );

    // ── 6. Generate Recommendations ──
    const recommendations = generateRecommendations({
      stealthScore, exposureScore, assetHealthScore, eventVelocityScore,
      burnedAssets, highRiskEvents, recentAlerts, latestNoiseLevel,
    });

    return {
      overallScore,
      noiseLevel: latestNoiseLevel,
      detectionChance: Math.round(latestDetectionChance),
      activeEngagements,
      totalOpsecEvents,
      highRiskEvents,
      burnedAssets,
      recentAlerts,
      breakdown: {
        stealthScore: Math.round(stealthScore),
        exposureScore: Math.round(exposureScore),
        assetHealthScore: Math.round(assetHealthScore),
        eventVelocityScore: Math.round(eventVelocityScore),
      },
      recommendations,
    };
  }),

  /**
   * Quick Stats — lightweight counts for the cockpit header cards
   */
  quickStats: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
    const db = await getDb();
    if (!db) return { activeEngagements: 0, runningScans: 0, criticalFindings: 0, opsecScore: 100 };
    const engagementId = input?.engagementId;

    let activeEngagements = 0;
    let runningScans = 0;
    let criticalFindings = 0;

    try {
      const engResult = await db.select({ cnt: count() }).from(engagements)
        .where(eq(engagements.status, "active"));
      activeEngagements = engResult[0]?.cnt ?? 0;
    } catch { /* */ }

    try {
      const scanResult = await db.select({ cnt: count() }).from(scanResults)
        .where(sql`${scanResults.exitCode} IS NULL`);
      runningScans = scanResult[0]?.cnt ?? 0;
    } catch { /* */ }

    try {
      const critResult = await db.select({ cnt: count() }).from(scanObservations)
        .where(eq(scanObservations.severity, "critical"));
      criticalFindings = critResult[0]?.cnt ?? 0;
    } catch { /* */ }

    return { activeEngagements, runningScans, criticalFindings };
  }),

  /**
   * LLM Campaign Advisor — generates contextual next-action recommendations
   * based on current OPSEC score, active engagements, and recent events.
   */
  campaignAdvice: protectedProcedure
    .input(z.object({
      opsecScore: z.number().min(0).max(100).optional(),
      noiseLevel: z.string().optional(),
      detectionChance: z.number().min(0).max(100).optional(),
      activeEngagements: z.number().optional(),
      highRiskEvents: z.number().optional(),
      burnedAssets: z.array(z.string()).optional(),
      recentEvents: z.array(z.object({
        category: z.string(),
        severity: z.string(),
        title: z.string(),
        description: z.string(),
      })).optional(),
    }).optional())
    .mutation(async ({ input }) => {
      const opsecScore = input?.opsecScore ?? 100;
      const noiseLevel = input?.noiseLevel ?? "stealth";
      const detectionChance = input?.detectionChance ?? 0;
      const activeEngagements = input?.activeEngagements ?? 0;
      const highRiskEvents = input?.highRiskEvents ?? 0;
      const burnedAssets = input?.burnedAssets ?? [];
      const recentEvents = input?.recentEvents ?? [];

      // Build a context-rich prompt for the LLM
      const recentEventsSummary = recentEvents.slice(0, 10).map(e =>
        `- [${e.severity.toUpperCase()}] ${e.category}: ${e.title} — ${e.description}`
      ).join("\n");

      const systemPrompt = `You are an expert Red Team Campaign Advisor embedded in an offensive security operations platform. Your role is to provide concise, actionable tactical recommendations based on the current operational state.

Rules:
- Be specific and tactical, not generic
- Reference specific MITRE ATT&CK techniques when relevant (use T-codes)
- Consider OPSEC implications of every recommendation
- If OPSEC score is low, prioritize stealth recovery actions
- If burned assets exist, recommend rotation strategies
- Keep each recommendation to 1-2 sentences
- Return exactly 3-5 recommendations
- Format as a JSON array of objects with "priority" (high/medium/low), "action" (short title), and "detail" (explanation)
- Do not include any sensitivity markings or classified references`;

      const userPrompt = `Current Operational State:
- OPSEC Score: ${opsecScore}/100 (${opsecScore > 70 ? "CLEAN" : opsecScore > 40 ? "MODERATE" : "ELEVATED RISK"})
- Noise Level: ${noiseLevel}
- Detection Chance: ${detectionChance}%
- Active Engagements: ${activeEngagements}
- High-Risk Events (7d): ${highRiskEvents}
- Burned Assets: ${burnedAssets.length > 0 ? burnedAssets.join(", ") : "None"}

Recent Activity:
${recentEventsSummary || "No recent events."}

Provide tactical recommendations for the next operational actions.`;

      try {
        const response = await invokeLLM({
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userPrompt },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "campaign_advice",
              strict: true,
              schema: {
                type: "object",
                properties: {
                  recommendations: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        priority: { type: "string", enum: ["high", "medium", "low"] },
                        action: { type: "string", description: "Short action title" },
                        detail: { type: "string", description: "1-2 sentence explanation" },
                        technique: { type: "string", description: "MITRE ATT&CK T-code if applicable, or empty string" },
                      },
                      required: ["priority", "action", "detail", "technique"],
                      additionalProperties: false,
                    },
                  },
                  summary: { type: "string", description: "One-sentence operational summary" },
                },
                required: ["recommendations", "summary"],
                additionalProperties: false,
              },
            },
          },
          _caller: "operator-cockpit-advisor",
        });

        const content = response.choices?.[0]?.message?.content;
        if (content) {
          const parsed = JSON.parse(content);
          return {
            success: true,
            summary: parsed.summary || "Analysis complete.",
            recommendations: parsed.recommendations || [],
            generatedAt: new Date().toISOString(),
          };
        }

        return {
          success: false,
          summary: "Unable to generate recommendations at this time.",
          recommendations: [],
          generatedAt: new Date().toISOString(),
        };
      } catch (error: any) {
        console.error("[CampaignAdvisor] LLM error:", error?.message);
        return {
          success: false,
          summary: "Campaign advisor temporarily unavailable.",
          recommendations: [],
          generatedAt: new Date().toISOString(),
        };
      }
    }),
});

// ─── Helper Functions ───────────────────────────────────────────────────

function defaultOpsecGauge(): OpsecGaugeResult {
  return {
    overallScore: 100,
    noiseLevel: "stealth",
    detectionChance: 0,
    activeEngagements: 0,
    totalOpsecEvents: 0,
    highRiskEvents: 0,
    burnedAssets: [],
    recentAlerts: 0,
    breakdown: { stealthScore: 100, exposureScore: 100, assetHealthScore: 100, eventVelocityScore: 100 },
    recommendations: ["No active operations — OPSEC posture is clean."],
  };
}

function categorizeSystemSeverity(action: string): UnifiedEvent["severity"] {
  if (/delete|remove|revoke|terminate/i.test(action)) return "high";
  if (/create|update|modify|deploy/i.test(action)) return "medium";
  if (/login|logout|view|list/i.test(action)) return "info";
  return "low";
}

function formatSystemAction(action: string): string {
  return action.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function riskTierToSeverity(tier: string): UnifiedEvent["severity"] {
  switch (tier) {
    case "red": return "critical";
    case "orange": return "high";
    case "yellow": return "medium";
    default: return "low";
  }
}

function formatOffensiveAction(actionType: string, target: string): string {
  const labels: Record<string, string> = {
    active_probe: "Active Probe",
    msf_check: "Metasploit Check",
    msf_auxiliary: "MSF Auxiliary Module",
    msf_exploit: "MSF Exploit",
    phishing_launch: "Phishing Campaign Launch",
    caldera_operation: "Caldera Operation",
    payload_delivery: "Payload Delivery",
    session_interaction: "Session Interaction",
  };
  return `${labels[actionType] || actionType} → ${target}`;
}

function opsecRiskToSeverity(riskScore: number): UnifiedEvent["severity"] {
  if (riskScore >= 80) return "critical";
  if (riskScore >= 60) return "high";
  if (riskScore >= 40) return "medium";
  if (riskScore >= 20) return "low";
  return "info";
}

function agentEventSeverity(eventType: string): UnifiedEvent["severity"] {
  const critical = ["terminated", "lost", "rejected"];
  const high = ["task_failed", "deregistered"];
  const medium = ["task_assigned", "task_sent", "task_completed", "artifact_uploaded", "payload_downloaded"];
  if (critical.includes(eventType)) return "critical";
  if (high.includes(eventType)) return "high";
  if (medium.includes(eventType)) return "medium";
  return "info";
}

function formatAgentEvent(eventType: string): string {
  return eventType.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

const NOISE_LEVELS = ["stealth", "low", "moderate", "elevated", "critical"];

function getWorstNoiseLevel(a: string, b: string): string {
  const ai = NOISE_LEVELS.indexOf(a);
  const bi = NOISE_LEVELS.indexOf(b);
  return NOISE_LEVELS[Math.max(ai, bi)] || a;
}

function calculateStealthScore(currentNoise: string, recentNoiseLevels: string[]): number {
  const noiseIndex = NOISE_LEVELS.indexOf(currentNoise);
  const baseScore = Math.max(0, 100 - noiseIndex * 25);

  // Penalize for frequent loud events
  const loudEvents = recentNoiseLevels.filter(n => NOISE_LEVELS.indexOf(n) >= 3).length;
  const penalty = Math.min(30, loudEvents * 5);

  return Math.max(0, baseScore - penalty);
}

function calculateExposureScore(avgDetection: number, maxDetection: number): number {
  // Higher detection = lower score
  const avgPenalty = avgDetection * 0.6;
  const maxPenalty = maxDetection * 0.4;
  return Math.max(0, 100 - avgPenalty - maxPenalty);
}

function calculateAssetHealthScore(burnedCount: number): number {
  if (burnedCount === 0) return 100;
  if (burnedCount <= 2) return 70;
  if (burnedCount <= 5) return 40;
  return Math.max(0, 20 - (burnedCount - 5) * 5);
}

function calculateEventVelocityScore(recentAlerts: number, totalEvents: number, highRisk: number): number {
  // Low alert rate = high score
  let score = 100;
  score -= Math.min(40, recentAlerts * 8);       // Penalize recent alerts heavily
  score -= Math.min(30, highRisk * 6);            // Penalize high-risk events
  score -= Math.min(20, Math.floor(totalEvents / 10) * 2); // Gentle penalty for volume
  return Math.max(0, score);
}

function generateRecommendations(ctx: {
  stealthScore: number;
  exposureScore: number;
  assetHealthScore: number;
  eventVelocityScore: number;
  burnedAssets: string[];
  highRiskEvents: number;
  recentAlerts: number;
  latestNoiseLevel: string;
}): string[] {
  const recs: string[] = [];

  if (ctx.stealthScore < 50) {
    recs.push(`Noise level is ${ctx.latestNoiseLevel} — consider switching to passive reconnaissance or reducing scan intensity.`);
  }
  if (ctx.exposureScore < 50) {
    recs.push("Detection probability is elevated — rotate infrastructure or use evasion techniques.");
  }
  if (ctx.burnedAssets.length > 0) {
    recs.push(`${ctx.burnedAssets.length} asset(s) burned — rotate: ${ctx.burnedAssets.slice(0, 3).join(", ")}${ctx.burnedAssets.length > 3 ? "..." : ""}`);
  }
  if (ctx.recentAlerts > 5) {
    recs.push(`${ctx.recentAlerts} OPSEC alerts in the last 24h — slow operations tempo and review recent actions.`);
  }
  if (ctx.highRiskEvents > 3) {
    recs.push(`${ctx.highRiskEvents} high-risk events this week — review ROE compliance and consider de-escalation.`);
  }
  if (ctx.eventVelocityScore < 40) {
    recs.push("Event velocity is high — introduce delays between actions to reduce detection signature.");
  }

  if (recs.length === 0) {
    recs.push("OPSEC posture is healthy — continue current operational tempo.");
  }

  return recs;
}
