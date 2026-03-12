/**
 * Learning Engine API Client
 * ──────────────────────────
 * HTTP client for the dual-stream learning engine running on the DO droplet.
 * Provides typed methods for both training lab and threat actor learning streams.
 */

import { SCAN_SERVICE_URL, SCAN_API_KEY } from "./scan-service-url";

const LEARNING_BASE = `${SCAN_SERVICE_URL}/learning`;
const API_KEY = SCAN_API_KEY;
const LOG = "[LearningAPI]";

async function learningFetch(path: string, options?: RequestInit & { timeout?: number }) {
  const url = `${LEARNING_BASE}${path}`;
  const timeout = options?.timeout || 15000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "X-Scan-Key": API_KEY,
        ...(options?.headers || {}),
      },
    });
    clearTimeout(timer);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return await res.json();
  } catch (err: any) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      console.warn(`${LOG} Timeout fetching ${path}`);
      throw new Error(`Learning engine timeout: ${path}`);
    }
    console.warn(`${LOG} Error fetching ${path}: ${err.message}`);
    throw err;
  }
}

// ═══ Health ═══════════════════════════════════════════════════════════════════
export async function getLearningHealth() {
  const raw = await learningFetch("/health");
  return {
    status: raw?.status || "unknown",
    service: raw?.service || "learning-engine",
    uptime: raw?.uptime ?? 0,
    groundTruthTargets: raw?.stats?.groundTruthTargets ?? 0,
    totalVulns: raw?.stats?.totalVulns ?? 0,
    accuracyScores: raw?.stats?.accuracyScores ?? 0,
    learningEvents: raw?.stats?.learningEvents ?? 0,
    engagementRuns: raw?.stats?.engagementRuns ?? 0,
    timestamp: raw?.timestamp,
  };
}

// ═══ Combined Dashboard ══════════════════════════════════════════════════════
export async function getLearningDashboard() {
  const raw = await learningFetch("/api/learning/dashboard");
  const streams = raw?.streams || {};
  const lab = streams.trainingLab || {};
  const threat = streams.threatActor || {};
  return {
    trainingLab: {
      groundTruthTargets: lab.groundTruthTargets ?? 0,
      totalVulns: lab.totalGroundTruthVulns ?? 0,
      engagementRuns: lab.total_scans ?? 0,
      avgPrecision: lab.avg_precision ?? 0,
      avgRecall: lab.avg_recall ?? 0,
      avgF1: lab.avg_f1 ?? 0,
      avgAccuracy: lab.avg_f1 ?? 0,
      perTarget: (lab.perTarget || []).map((t: any) => ({
        target: t.target_preset,
        scans: t.scans,
        avgF1: t.avg_f1,
        lastScan: t.last_scan,
      })),
    },
    threatActor: {
      totalGroups: threat.catalogGroups ?? 0,
      totalTTPs: threat.catalogTTPs ?? 0,
      totalCVEs: threat.catalogCVEs ?? 0,
      attributionRuns: threat.total_scans ?? 0,
      avgConfidence: threat.avg_confidence ?? 0,
      avgTtpCoverage: threat.avg_ttp_coverage ?? 0,
      avgCveCoverage: threat.avg_cve_coverage ?? 0,
      topGroups: threat.topGroups || [],
      recentEvents: threat.recentEvents || [],
    },
  };
}

// ═══ Training Lab Stream ═════════════════════════════════════════════════════

export interface ScoreFindingsInput {
  sessionId: string;
  engagementId?: string;
  targetPreset: string;
  targetUrl?: string;
  scanType?: string;
  findings: { name: string; severity?: string; cwe?: string; owasp?: string; endpoint?: string; confidence?: number }[];
}

export async function scoreFindings(input: ScoreFindingsInput) {
  return learningFetch("/api/learning/score", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function recordEngagement(input: {
  engagementId: string;
  targetPreset: string;
  targetUrl?: string;
  scanType?: string;
}) {
  return learningFetch("/api/learning/engagement", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function recordLearningEvent(input: {
  sessionId: string;
  engagementId?: string;
  targetPreset: string;
  eventType: string;
  phase?: string;
  decision?: string;
  contextUsed?: string;
  knowledgeModules?: string[];
  outcome?: string;
  confidence?: number;
  groundTruthMatch?: boolean;
  metadata?: Record<string, any>;
}) {
  return learningFetch("/api/learning/event", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function getAccuracyTrend(target?: string, limit?: number) {
  const params = new URLSearchParams();
  if (target) params.set("target", target);
  if (limit) params.set("limit", String(limit));
  const raw = await learningFetch(`/api/learning/trend?${params}`);
  return {
    trend: (raw?.scores || []).map((s: any) => ({
      target: s.target_preset,
      f1Score: s.f1_score ?? 0,
      precision: s.precision_score ?? 0,
      recall: s.recall_score ?? 0,
      truePositives: s.true_positives ?? 0,
      falsePositives: s.false_positives ?? 0,
      falseNegatives: s.false_negatives ?? 0,
      totalFindings: s.total_findings ?? 0,
      groundTruthCount: s.ground_truth_count ?? 0,
      timestamp: s.created_at,
    })),
  };
}

export async function getAccuracyStats() {
  return learningFetch("/api/learning/stats");
}

export async function getVulnAccuracyBreakdown() {
  const raw = await learningFetch("/api/learning/vuln-accuracy");
  return {
    breakdown: (raw?.breakdown || []).map((b: any) => ({
      vulnType: b.vulnType,
      avgF1: (b.detectionRate ?? 0) / 100,  // convert 0-100 to 0-1 for pct()
      totalRuns: (b.timesFound ?? 0) + (b.timesMissed ?? 0),
      detectionRate: b.detectionRate ?? 0,
      timesFound: b.timesFound ?? 0,
      timesMissed: b.timesMissed ?? 0,
      targets: b.targets || [],
    })),
  };
}

export async function getGroundTruth(target?: string) {
  if (target) {
    // Single target: returns { target, vulns: [...] }
    const raw = await learningFetch(`/api/learning/ground-truth/${encodeURIComponent(target)}`);
    return { targets: { [target]: raw?.vulns || [] } };
  }
  // All targets: returns { targets: [{ target, vulnCount, severities, categories }] }
  // We need to fetch each target's vulns individually for the ground truth view
  const raw = await learningFetch("/api/learning/ground-truth");
  const summaryList = raw?.targets || [];
  const targets: Record<string, any[]> = {};
  // Fetch detailed vulns for each target in parallel (max 6 concurrent)
  const BATCH = 6;
  for (let i = 0; i < summaryList.length; i += BATCH) {
    const batch = summaryList.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map((t: any) =>
        learningFetch(`/api/learning/ground-truth/${encodeURIComponent(t.target)}`)
          .then((r: any) => ({ target: t.target, vulns: r?.vulns || [] }))
          .catch(() => ({ target: t.target, vulns: [] }))
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

export async function getEngagementRuns(target?: string, limit?: number) {
  const params = new URLSearchParams();
  if (target) params.set("target", target);
  if (limit) params.set("limit", String(limit));
  const raw = await learningFetch(`/api/learning/runs?${params}`);
  return {
    runs: (raw?.runs || []).map((r: any) => ({
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
      timestamp: r.completed_at || r.started_at,
    })),
  };
}

export async function getLearningEvents(opts?: { target?: string; session?: string; limit?: number }) {
  const params = new URLSearchParams();
  if (opts?.target) params.set("target", opts.target);
  if (opts?.session) params.set("session", opts.session);
  if (opts?.limit) params.set("limit", String(opts.limit));
  const raw = await learningFetch(`/api/learning/events?${params}`);
  return {
    events: (raw?.events || []).map((e: any) => ({
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
      timestamp: e.created_at,
    })),
  };
}

// ═══ Threat Actor Stream ═════════════════════════════════════════════════════

export interface ThreatScoreInput {
  sessionId: string;
  engagementId?: string;
  targetUrl?: string;
  scanType?: string;
  ttps: { techniqueId?: string; techniqueName?: string; tactic?: string; cve?: string; tool?: string }[];
  cves: string[];
}

export async function scoreThreatAttribution(input: ThreatScoreInput) {
  return learningFetch("/api/learning/threat-score", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function getThreatTrend(limit?: number) {
  const params = new URLSearchParams();
  if (limit) params.set("limit", String(limit));
  const raw = await learningFetch(`/api/learning/threat-trend?${params}`);
  return {
    trend: (raw?.scores || []).map((s: any) => {
      let topGroup = "—";
      try {
        const tg = JSON.parse(s.top_groups || "[]");
        if (tg[0]) topGroup = tg[0].name || tg[0].id;
      } catch {}
      return {
        topGroup,
        ttpsMatched: s.ttps_detected ?? 0,
        cvesMatched: s.cves_detected ?? 0,
        confidence: s.attribution_confidence ?? 0,
        timestamp: s.created_at,
      };
    }),
  };
}

export async function getThreatStats() {
  const raw = await learningFetch("/api/learning/threat-stats");
  return {
    topGroups: (raw?.topGroups || []).map((g: any) => ({
      groupId: g.threat_group_id,
      groupName: g.threat_group_name,
      matchCount: g.detections ?? 0,
      avgConfidence: g.avg_confidence ?? 0,
    })),
    topTechniques: raw?.topTechniques || [],
    topCVEs: raw?.topCVEs || [],
    catalogSummary: raw?.catalogSummary || {},
    overall: raw?.overall || {},
  };
}

export async function getThreatGroupLearning(groupId: string) {
  return learningFetch(`/api/learning/threat-group/${encodeURIComponent(groupId)}`);
}
