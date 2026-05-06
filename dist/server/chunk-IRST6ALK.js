import {
  getDb,
  init_db
} from "./chunk-SI4LILOM.js";
import {
  customerIntelligenceProfiles,
  init_schema,
  intelligenceGaps
} from "./chunk-YQRYZ5JK.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/customer-intel-profile.ts
import { eq, desc, sql, count } from "drizzle-orm";
function calculatePostureScore(input) {
  if (input.totalAssets === 0) return 100;
  const severityPenalty = input.critical * 15 + input.high * 8 + input.medium * 3 + input.low * 1;
  const densityPenalty = Math.min(severityPenalty / input.totalAssets, 100);
  const totalGaps = input.openGaps + input.resolvedGaps;
  const gapResolutionBonus = totalGaps > 0 ? input.resolvedGaps / totalGaps * 10 : 5;
  const raw = 100 - densityPenalty + gapResolutionBonus;
  return Math.max(0, Math.min(100, Math.round(raw * 10) / 10));
}
function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}
function determineTrend(trendData) {
  if (trendData.length < 2) return "stable";
  const recent = trendData.slice(-3);
  const first = recent[0].score;
  const last = recent[recent.length - 1].score;
  const delta = last - first;
  if (delta > 5) return "improving";
  if (delta < -5) return "declining";
  return "stable";
}
async function getOrCreateProfile(customerId, customerName) {
  const db = await getDb();
  const existing = await db.select().from(customerIntelligenceProfiles).where(eq(customerIntelligenceProfiles.customerId, customerId)).limit(1);
  if (existing.length > 0) return existing[0];
  await db.insert(customerIntelligenceProfiles).values({
    customerId,
    customerName,
    overallPostureScore: null,
    postureGrade: null,
    postureTrend: "stable",
    totalEngagements: 0,
    totalDIScans: 0,
    totalFindings: 0,
    totalCritical: 0,
    totalHigh: 0,
    totalMedium: 0,
    totalLow: 0,
    postureTrendData: [],
    findingsTrendData: [],
    recurringWeaknesses: [],
    persistentGaps: [],
    knownTechnologies: [],
    technologyChanges: [],
    attackSurfaceSize: null,
    attackSurfaceTrend: [],
    strategicRecommendations: [],
    openGapsCount: 0,
    resolvedGapsCount: 0,
    lastEngagementDate: null
  });
  const created = await db.select().from(customerIntelligenceProfiles).where(eq(customerIntelligenceProfiles.customerId, customerId)).limit(1);
  return created[0];
}
async function getProfile(customerId) {
  const db = await getDb();
  const rows = await db.select().from(customerIntelligenceProfiles).where(eq(customerIntelligenceProfiles.customerId, customerId)).limit(1);
  return rows[0] || null;
}
async function listProfiles(opts) {
  const db = await getDb();
  return db.select().from(customerIntelligenceProfiles).orderBy(desc(customerIntelligenceProfiles.lastUpdated)).limit(opts?.limit ?? 50).offset(opts?.offset ?? 0);
}
async function updateProfileFromEngagement(snapshot) {
  const db = await getDb();
  const profile = await getOrCreateProfile(snapshot.customerId, snapshot.customerName);
  const postureTrend = profile.postureTrendData || [];
  const findingsTrend = profile.findingsTrendData || [];
  const recurringWeaknesses = profile.recurringWeaknesses || [];
  const knownTech = profile.knownTechnologies || [];
  const techChanges = profile.technologyChanges || [];
  const surfaceTrend = profile.attackSurfaceTrend || [];
  const newTotalFindings = (profile.totalFindings || 0) + snapshot.findings.total;
  const newTotalCritical = (profile.totalCritical || 0) + snapshot.findings.critical;
  const newTotalHigh = (profile.totalHigh || 0) + snapshot.findings.high;
  const newTotalMedium = (profile.totalMedium || 0) + snapshot.findings.medium;
  const newTotalLow = (profile.totalLow || 0) + snapshot.findings.low;
  const gapRows = await db.select({
    status: intelligenceGaps.status,
    cnt: count()
  }).from(intelligenceGaps).where(eq(intelligenceGaps.customerId, snapshot.customerId)).groupBy(intelligenceGaps.status);
  let openGaps = 0;
  let resolvedGaps = 0;
  for (const row of gapRows) {
    const c = Number(row.cnt);
    if (row.status === "open" || row.status === "acknowledged") openGaps += c;
    if (row.status === "resolved" || row.status === "mitigated") resolvedGaps += c;
  }
  const postureScore = calculatePostureScore({
    totalFindings: newTotalFindings,
    critical: newTotalCritical,
    high: newTotalHigh,
    medium: newTotalMedium,
    low: newTotalLow,
    totalAssets: snapshot.assets.total,
    openGaps,
    resolvedGaps
  });
  postureTrend.push({
    date: snapshot.date,
    score: postureScore,
    engagementId: snapshot.engagementId
  });
  findingsTrend.push({
    date: snapshot.date,
    critical: snapshot.findings.critical,
    high: snapshot.findings.high,
    medium: snapshot.findings.medium,
    low: snapshot.findings.low
  });
  if (snapshot.weaknessCategories) {
    for (const cat of snapshot.weaknessCategories) {
      const existing = recurringWeaknesses.find((w) => w.category === cat);
      if (existing) {
        existing.count += 1;
        existing.lastSeen = snapshot.date;
        existing.trend = existing.count >= 3 ? "persistent" : "recurring";
      } else {
        recurringWeaknesses.push({
          category: cat,
          count: 1,
          lastSeen: snapshot.date,
          trend: "new"
        });
      }
    }
  }
  if (snapshot.technologies && snapshot.technologies.length > 0) {
    const newTech = snapshot.technologies;
    const added = newTech.filter((t) => !knownTech.includes(t));
    const removed = knownTech.filter((t) => !newTech.includes(t));
    if (added.length > 0 || removed.length > 0) {
      techChanges.push({
        date: snapshot.date,
        ...added.length > 0 ? { added } : {},
        ...removed.length > 0 ? { removed } : {}
      });
    }
    const updatedTech = Array.from(/* @__PURE__ */ new Set([...knownTech, ...newTech]));
    await db.update(customerIntelligenceProfiles).set({ knownTechnologies: updatedTech }).where(eq(customerIntelligenceProfiles.id, profile.id));
  }
  surfaceTrend.push({
    date: snapshot.date,
    hosts: snapshot.assets.hosts,
    services: snapshot.assets.services,
    exposedPorts: snapshot.assets.exposedPorts
  });
  const recommendations = generateStrategicRecommendations({
    postureScore,
    recurringWeaknesses,
    openGaps,
    findings: {
      critical: newTotalCritical,
      high: newTotalHigh
    },
    surfaceTrend
  });
  const trend = determineTrend(postureTrend);
  await db.update(customerIntelligenceProfiles).set({
    customerName: snapshot.customerName,
    overallPostureScore: postureScore,
    postureGrade: scoreToGrade(postureScore),
    postureTrend: trend,
    totalEngagements: (profile.totalEngagements || 0) + 1,
    totalFindings: newTotalFindings,
    totalCritical: newTotalCritical,
    totalHigh: newTotalHigh,
    totalMedium: newTotalMedium,
    totalLow: newTotalLow,
    postureTrendData: postureTrend,
    findingsTrendData: findingsTrend,
    recurringWeaknesses,
    technologyChanges: techChanges,
    attackSurfaceSize: snapshot.assets.total,
    attackSurfaceTrend: surfaceTrend,
    strategicRecommendations: recommendations,
    openGapsCount: openGaps,
    resolvedGapsCount: resolvedGaps,
    lastEngagementDate: snapshot.date
  }).where(eq(customerIntelligenceProfiles.id, profile.id));
}
async function incrementDIScanCount(customerId) {
  const db = await getDb();
  await db.update(customerIntelligenceProfiles).set({
    totalDIScans: sql`${customerIntelligenceProfiles.totalDIScans} + 1`
  }).where(eq(customerIntelligenceProfiles.customerId, customerId));
}
function generateStrategicRecommendations(input) {
  const recs = [];
  if (input.findings.critical > 0) {
    recs.push({
      priority: "critical",
      title: "Remediate critical-severity findings immediately",
      rationale: `${input.findings.critical} critical finding(s) represent exploitable conditions with severe business impact`,
      effort: "Varies by finding",
      impact: "Eliminates highest-risk exposure vectors"
    });
  }
  const persistent = input.recurringWeaknesses.filter((w) => w.count >= 3);
  if (persistent.length > 0) {
    recs.push({
      priority: "high",
      title: `Address ${persistent.length} persistent weakness pattern(s)`,
      rationale: `Categories recurring across 3+ engagements: ${persistent.map((w) => w.category).join(", ")}. These indicate systemic issues that point-fixes won't resolve.`,
      effort: "Medium-term program investment",
      impact: "Breaks recurring vulnerability patterns"
    });
  }
  if (input.openGaps > 5) {
    recs.push({
      priority: "high",
      title: "Close intelligence gaps to improve assessment coverage",
      rationale: `${input.openGaps} open intelligence gaps mean significant portions of the attack surface remain unassessed`,
      effort: "Requires scope expansion and tool investment",
      impact: "Reduces unknown risk exposure"
    });
  }
  if (input.surfaceTrend.length >= 2) {
    const first = input.surfaceTrend[0];
    const last = input.surfaceTrend[input.surfaceTrend.length - 1];
    const growth = (last.hosts - first.hosts) / Math.max(first.hosts, 1) * 100;
    if (growth > 20) {
      recs.push({
        priority: "medium",
        title: "Implement attack surface management program",
        rationale: `Attack surface grew ${Math.round(growth)}% (${first.hosts} \u2192 ${last.hosts} hosts). Unmanaged growth increases exposure.`,
        effort: "Ongoing operational program",
        impact: "Controls exposure growth rate"
      });
    }
  }
  if (input.postureScore < 60) {
    recs.push({
      priority: "high",
      title: "Invest in foundational security hygiene program",
      rationale: `Overall posture score of ${input.postureScore}/100 (Grade ${scoreToGrade(input.postureScore)}) indicates significant security debt`,
      effort: "Multi-quarter program",
      impact: "Raises baseline security posture across the organization"
    });
  }
  return recs;
}
var init_customer_intel_profile = __esm({
  "server/lib/customer-intel-profile.ts"() {
    init_db();
    init_schema();
  }
});

export {
  calculatePostureScore,
  scoreToGrade,
  determineTrend,
  getOrCreateProfile,
  getProfile,
  listProfiles,
  updateProfileFromEngagement,
  incrementDIScanCount,
  init_customer_intel_profile
};
