import {
  SCAN_API_KEY,
  SCAN_SERVICE_URL,
  init_scan_service_url
} from "./chunk-UYX5D64U.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/learning-engine-api.ts
async function learningFetch(path, options) {
  const url = `${LEARNING_BASE}${path}`;
  const timeout = options?.timeout || 15e3;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "X-Scan-Key": API_KEY,
        ...options?.headers || {}
      }
    });
    clearTimeout(timer);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return await res.json();
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      console.warn(`${LOG} Timeout fetching ${path}`);
      throw new Error(`Learning engine timeout: ${path}`);
    }
    console.warn(`${LOG} Error fetching ${path}: ${err.message}`);
    throw err;
  }
}
async function getLearningHealth() {
  const raw = await learningFetch("/learning/health");
  const rawStatus = raw?.status || "unknown";
  const status = rawStatus === "ok" ? "healthy" : rawStatus;
  const uptimeSec = raw?.uptime ?? 0;
  const hours = Math.floor(uptimeSec / 3600);
  const minutes = Math.floor(uptimeSec % 3600 / 60);
  const uptimeStr = hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
  return {
    status,
    service: raw?.service || "learning-engine",
    uptime: uptimeStr,
    groundTruthTargets: raw?.stats?.groundTruthTargets ?? 0,
    totalVulns: raw?.stats?.totalVulns ?? 0,
    accuracyScores: raw?.stats?.accuracyScores ?? 0,
    learningEvents: raw?.stats?.learningEvents ?? 0,
    engagementRuns: raw?.stats?.engagementRuns ?? 0,
    timestamp: raw?.timestamp
  };
}
async function getLearningDashboard() {
  const [raw, threatStatsRaw] = await Promise.all([
    learningFetch("/api/learning/dashboard"),
    learningFetch("/api/learning/threat-stats").catch(() => null)
  ]);
  const streams = raw?.streams || {};
  const lab = streams.trainingLab || {};
  const threat = streams.threatActor || {};
  const topGroups = (threatStatsRaw?.topGroups || []).map((g) => ({
    groupId: g.threat_group_id ?? g.groupId,
    name: g.threat_group_name ?? g.name,
    matchCount: g.detections ?? g.matchCount ?? 0,
    confidence: g.avg_confidence ?? g.confidence ?? 0,
    ttpCount: g.ttp_count ?? g.ttpCount ?? 0,
    sessions: g.sessions ?? 0
  }));
  return {
    trainingLab: {
      groundTruthTargets: lab.groundTruthTargets ?? 0,
      totalVulns: lab.totalGroundTruthVulns ?? 0,
      totalGroundTruthVulns: lab.totalGroundTruthVulns ?? 0,
      engagementRuns: lab.total_scans ?? 0,
      avgPrecision: lab.avg_precision ?? 0,
      avgRecall: lab.avg_recall ?? 0,
      avgF1: lab.avg_f1 ?? 0,
      avgAccuracy: lab.avg_f1 ?? 0,
      perTarget: (lab.perTarget || []).map((t) => ({
        target: t.target_preset,
        scans: t.scans,
        avgF1: t.avg_f1,
        lastScan: t.last_scan
      }))
    },
    threatActor: {
      totalGroups: threat.catalogGroups ?? 0,
      totalTTPs: threat.catalogTTPs ?? 0,
      totalCVEs: threat.catalogCVEs ?? 0,
      attributionRuns: threat.total_scans ?? 0,
      avgConfidence: threat.avg_confidence ?? 0,
      avgTtpCoverage: threat.avg_ttp_coverage ?? 0,
      avgCveCoverage: threat.avg_cve_coverage ?? 0,
      ttpDetections: threatStatsRaw?.overall?.total_ttps_detected ?? 0,
      cveCoverage: threatStatsRaw?.overall?.total_cves_detected ?? 0,
      topGroups,
      recentEvents: threat.recentEvents || []
    }
  };
}
async function scoreFindings(input) {
  return learningFetch("/api/learning/score", {
    method: "POST",
    body: JSON.stringify(input)
  });
}
async function recordEngagement(input) {
  return learningFetch("/api/learning/engagement", {
    method: "POST",
    body: JSON.stringify(input)
  });
}
async function recordLearningEvent(input) {
  return learningFetch("/api/learning/event", {
    method: "POST",
    body: JSON.stringify(input)
  });
}
async function getAccuracyTrend(target, limit) {
  const params = new URLSearchParams();
  if (target) params.set("target", target);
  if (limit) params.set("limit", String(limit));
  const raw = await learningFetch(`/api/learning/trend?${params}`);
  return {
    trend: (raw?.scores || []).map((s) => ({
      target: s.target_preset,
      f1Score: s.f1_score ?? 0,
      precision: s.precision_score ?? 0,
      recall: s.recall_score ?? 0,
      truePositives: s.true_positives ?? 0,
      falsePositives: s.false_positives ?? 0,
      falseNegatives: s.false_negatives ?? 0,
      totalFindings: s.total_findings ?? 0,
      groundTruthCount: s.ground_truth_count ?? 0,
      timestamp: s.created_at
    }))
  };
}
async function getAccuracyStats() {
  return learningFetch("/api/learning/stats");
}
async function getVulnAccuracyBreakdown() {
  const raw = await learningFetch("/api/learning/vuln-accuracy");
  return {
    breakdown: (raw?.breakdown || []).map((b) => ({
      vulnType: b.vulnType,
      avgF1: (b.detectionRate ?? 0) / 100,
      // convert 0-100 to 0-1 for pct()
      totalRuns: (b.timesFound ?? 0) + (b.timesMissed ?? 0),
      detectionRate: b.detectionRate ?? 0,
      timesFound: b.timesFound ?? 0,
      timesMissed: b.timesMissed ?? 0,
      targets: b.targets || []
    }))
  };
}
async function getGroundTruth(target) {
  if (target) {
    const raw2 = await learningFetch(`/api/learning/ground-truth/${encodeURIComponent(target)}`);
    return { targets: { [target]: raw2?.vulns || [] } };
  }
  const raw = await learningFetch("/api/learning/ground-truth");
  const summaryList = raw?.targets || [];
  const targets = {};
  const BATCH = 6;
  for (let i = 0; i < summaryList.length; i += BATCH) {
    const batch = summaryList.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(
        (t) => learningFetch(`/api/learning/ground-truth/${encodeURIComponent(t.target)}`).then((r) => ({ target: t.target, vulns: r?.vulns || [] })).catch(() => ({ target: t.target, vulns: [] }))
      )
    );
    for (const r of results) {
      if (r.status === "fulfilled") {
        targets[r.value.target] = r.value.vulns;
      }
    }
  }
  return { targets };
}
async function getEngagementRuns(target, limit) {
  const params = new URLSearchParams();
  if (target) params.set("target", target);
  if (limit) params.set("limit", String(limit));
  const raw = await learningFetch(`/api/learning/runs?${params}`);
  return {
    runs: (raw?.runs || []).map((r) => ({
      engagementId: r.engagement_id,
      targetPreset: r.target_preset,
      targetUrl: r.target_url,
      scanType: r.scan_type,
      status: r.status,
      precision: r.precision_score ?? 0,
      recall: r.recall_score ?? 0,
      f1Score: r.f1_score ?? 0,
      truePositives: r.total_findings ?? 0,
      falseNegatives: 0,
      timestamp: r.completed_at || r.started_at
    }))
  };
}
async function getLearningEvents(opts) {
  const params = new URLSearchParams();
  if (opts?.target) params.set("target", opts.target);
  if (opts?.session) params.set("session", opts.session);
  if (opts?.limit) params.set("limit", String(opts.limit));
  const raw = await learningFetch(`/api/learning/events?${params}`);
  return {
    events: (raw?.events || []).map((e) => ({
      sessionId: e.session_id,
      engagementId: e.engagement_id,
      targetPreset: e.target_preset,
      eventType: e.event_type,
      phase: e.phase,
      decision: e.decision,
      contextUsed: e.context_used,
      knowledgeModules: e.knowledge_modules ? JSON.parse(e.knowledge_modules) : [],
      outcome: e.outcome,
      confidence: e.confidence,
      groundTruthMatch: e.ground_truth_match === 1,
      metadata: e.metadata ? JSON.parse(e.metadata) : null,
      timestamp: e.created_at
    }))
  };
}
async function scoreThreatAttribution(input) {
  return learningFetch("/api/learning/threat-score", {
    method: "POST",
    body: JSON.stringify(input)
  });
}
async function getThreatTrend(limit) {
  const params = new URLSearchParams();
  if (limit) params.set("limit", String(limit));
  const raw = await learningFetch(`/api/learning/threat-trend?${params}`);
  return {
    trend: (raw?.scores || []).map((s) => {
      let topGroup = "\u2014";
      try {
        const tg = JSON.parse(s.top_groups || "[]");
        if (tg[0]) topGroup = tg[0].name || tg[0].id;
      } catch {
      }
      return {
        topGroup,
        ttpsMatched: s.ttps_detected ?? 0,
        cvesMatched: s.cves_detected ?? 0,
        confidence: s.attribution_confidence ?? 0,
        timestamp: s.created_at
      };
    })
  };
}
async function getThreatStats() {
  const raw = await learningFetch("/api/learning/threat-stats");
  return {
    topGroups: (raw?.topGroups || []).map((g) => ({
      groupId: g.threat_group_id,
      groupName: g.threat_group_name,
      matchCount: g.detections ?? 0,
      avgConfidence: g.avg_confidence ?? 0
    })),
    topTechniques: raw?.topTechniques || [],
    topCVEs: raw?.topCVEs || [],
    catalogSummary: raw?.catalogSummary || {},
    overall: raw?.overall || {}
  };
}
async function getThreatGroupLearning(groupId) {
  return learningFetch(`/api/learning/threat-group/${encodeURIComponent(groupId)}`);
}
async function getThreatGroupProfile(groupId) {
  const raw = await learningFetch(`/api/learning/threat-group/${encodeURIComponent(groupId)}`);
  if (!raw?.group) return null;
  const g = raw.group;
  return {
    id: g.id,
    name: g.name,
    aliases: g.aliases || [],
    type: g.type,
    origin: g.origin,
    threatLevel: g.threatLevel,
    active: g.active,
    description: g.description,
    motivation: g.motivation,
    targetSectors: g.targetSectors || [],
    targetRegions: g.targetRegions || [],
    mitreGroupId: g.mitreGroupId,
    ttps: (g.ttps || []).map((t) => ({
      techniqueId: t.techniqueId,
      techniqueName: t.techniqueName,
      tactic: t.tactic,
      description: t.description,
      frequency: t.frequency
    })),
    tools: (g.tools || []).map((t) => ({
      name: t.name,
      category: t.category,
      description: t.description
    })),
    exploitedCVEs: g.exploitedCVEs || [],
    initialAccessMethods: g.initialAccessMethods || [],
    defenseRecommendations: (g.defenseRecommendations || []).map((d) => ({
      priority: d.priority,
      category: d.category,
      recommendation: d.recommendation,
      siemQuery: d.siemQuery,
      mitreTechniques: d.mitreTechniques || []
    })),
    detectionHints: g.detectionHints || []
  };
}
async function listThreatGroups() {
  const stats = await getThreatStats();
  return stats.topGroups;
}
var LEARNING_BASE, API_KEY, LOG;
var init_learning_engine_api = __esm({
  "server/lib/learning-engine-api.ts"() {
    "use strict";
    init_scan_service_url();
    LEARNING_BASE = SCAN_SERVICE_URL;
    API_KEY = SCAN_API_KEY;
    LOG = "[LearningAPI]";
  }
});

export {
  getLearningHealth,
  getLearningDashboard,
  scoreFindings,
  recordEngagement,
  recordLearningEvent,
  getAccuracyTrend,
  getAccuracyStats,
  getVulnAccuracyBreakdown,
  getGroundTruth,
  getEngagementRuns,
  getLearningEvents,
  scoreThreatAttribution,
  getThreatTrend,
  getThreatStats,
  getThreatGroupLearning,
  getThreatGroupProfile,
  listThreatGroups,
  init_learning_engine_api
};
