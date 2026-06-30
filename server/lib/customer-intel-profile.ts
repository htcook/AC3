/**
 * Customer Intelligence Profile Module
 * 
 * Cumulative cross-engagement data model that builds over time.
 * Aggregates findings, trends, recurring weaknesses, and strategic
 * recommendations across all engagements and DI scans for a customer.
 * 
 * Key capabilities:
 *   - Profile creation and auto-update on engagement completion
 *   - Posture score calculation and trend tracking
 *   - Recurring weakness detection across engagements
 *   - Technology stack change tracking
 *   - Attack surface size trending
 *   - Strategic recommendation generation
 *   - Persistent gap tracking (gaps that recur across engagements)
 */

import { getDb } from "../db";
import { customerIntelligenceProfiles, intelligenceGaps } from "../../drizzle/schema";
import { eq, and, desc, sql, count } from "drizzle-orm";

// ── Types ──────────────────────────────────────────────────────────────────

export interface PostureScoreInput {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  totalAssets: number;
  openGaps: number;
  resolvedGaps: number;
}

export interface EngagementSnapshot {
  engagementId: number;
  date: string;
  customerId: string;
  customerName: string;
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  assets: {
    total: number;
    hosts: number;
    services: number;
    exposedPorts: number;
  };
  technologies?: string[];
  weaknessCategories?: string[];
}

export interface CustomerProfile {
  id: number;
  customerId: string;
  customerName: string;
  overallPostureScore: number | null;
  postureGrade: string | null;
  postureTrend: string | null;
  totalEngagements: number;
  totalDIScans: number;
  totalFindings: number;
  totalCritical: number;
  totalHigh: number;
  totalMedium: number;
  totalLow: number;
  postureTrendData: Array<{ date: string; score: number; engagementId?: number }>;
  findingsTrendData: Array<{ date: string; critical: number; high: number; medium: number; low: number }>;
  recurringWeaknesses: Array<{ category: string; count: number; lastSeen: string; trend: string }>;
  persistentGaps: Array<{ gapId: number; title: string; firstSeen: string; occurrences: number }>;
  knownTechnologies: string[];
  technologyChanges: Array<{ date: string; added?: string[]; removed?: string[] }>;
  attackSurfaceSize: number | null;
  attackSurfaceTrend: Array<{ date: string; hosts: number; services: number; exposedPorts: number }>;
  strategicRecommendations: Array<{ priority: string; title: string; rationale: string; effort: string; impact: string }>;
  openGapsCount: number;
  resolvedGapsCount: number;
  lastEngagementDate: string | null;
  lastUpdated: string;
  createdAt: string;
}

// ── Posture Scoring ────────────────────────────────────────────────────────

/**
 * Calculate an overall security posture score (0-100).
 * Higher = better security posture.
 * 
 * Factors:
 *   - Finding severity distribution (weighted)
 *   - Finding density per asset
 *   - Gap resolution rate
 */
export function calculatePostureScore(input: PostureScoreInput): number {
  if (input.totalAssets === 0) return 100; // No assets = nothing to score

  // Severity-weighted finding penalty
  const severityPenalty =
    (input.critical * 15) +
    (input.high * 8) +
    (input.medium * 3) +
    (input.low * 1);

  // Normalize by asset count (findings per asset)
  const densityPenalty = Math.min(severityPenalty / input.totalAssets, 100);

  // Gap resolution bonus (0-10 points)
  const totalGaps = input.openGaps + input.resolvedGaps;
  const gapResolutionBonus = totalGaps > 0
    ? (input.resolvedGaps / totalGaps) * 10
    : 5; // Neutral if no gaps

  // Base score minus penalties plus bonuses
  const raw = 100 - densityPenalty + gapResolutionBonus;
  return Math.max(0, Math.min(100, Math.round(raw * 10) / 10));
}

/**
 * Convert posture score to letter grade
 */
export function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Determine posture trend from historical data
 */
export function determineTrend(
  trendData: Array<{ date: string; score: number }>
): "improving" | "declining" | "stable" {
  if (trendData.length < 2) return "stable";

  // Compare last 3 data points (or fewer if not enough)
  const recent = trendData.slice(-3);
  const first = recent[0].score;
  const last = recent[recent.length - 1].score;
  const delta = last - first;

  if (delta > 5) return "improving";
  if (delta < -5) return "declining";
  return "stable";
}

// ── Core Functions ─────────────────────────────────────────────────────────

/**
 * Get or create a customer intelligence profile
 */
export async function getOrCreateProfile(
  customerId: string,
  customerName: string
): Promise<typeof customerIntelligenceProfiles.$inferSelect> {
  const db = await getDb();
  const existing = await db
    .select()
    .from(customerIntelligenceProfiles)
    .where(eq(customerIntelligenceProfiles.customerId, customerId))
    .limit(1);

  if (existing.length > 0) return existing[0];

  await db!.insert(customerIntelligenceProfiles).values({
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
    lastEngagementDate: null,
  });

  const created = await db!
    .select()
    .from(customerIntelligenceProfiles)
    .where(eq(customerIntelligenceProfiles.customerId, customerId))
    .limit(1);

  return created[0];
}

/**
 * Get a customer profile by ID
 */
export async function getProfile(
  customerId: string
): Promise<typeof customerIntelligenceProfiles.$inferSelect | null> {
  const db = await getDb();
  const rows = await db!
    .select()
    .from(customerIntelligenceProfiles)
    .where(eq(customerIntelligenceProfiles.customerId, customerId))
    .limit(1);
  return rows[0] || null;
}

/**
 * List all customer profiles
 */
export async function listProfiles(opts?: {
  limit?: number;
  offset?: number;
}): Promise<Array<typeof customerIntelligenceProfiles.$inferSelect>> {
  const db = await getDb();
  return db!
    .select()
    .from(customerIntelligenceProfiles)
    .orderBy(desc(customerIntelligenceProfiles.lastUpdated))
    .limit(opts?.limit ?? 50)
    .offset(opts?.offset ?? 0);
}

/**
 * Update a customer profile after an engagement completes.
 * This is the main entry point for the auto-update hook.
 */
export async function updateProfileFromEngagement(
  snapshot: EngagementSnapshot
): Promise<void> {
  const db = await getDb();
  const profile = await getOrCreateProfile(snapshot.customerId, snapshot.customerName);

  // Parse existing JSON fields
  const postureTrend = (profile.postureTrendData as any[]) || [];
  const findingsTrend = (profile.findingsTrendData as any[]) || [];
  const recurringWeaknesses = (profile.recurringWeaknesses as any[]) || [];
  const knownTech = (profile.knownTechnologies as string[]) || [];
  const techChanges = (profile.technologyChanges as any[]) || [];
  const surfaceTrend = (profile.attackSurfaceTrend as any[]) || [];

  // Update cumulative counts
  const newTotalFindings = (profile.totalFindings || 0) + snapshot.findings.total;
  const newTotalCritical = (profile.totalCritical || 0) + snapshot.findings.critical;
  const newTotalHigh = (profile.totalHigh || 0) + snapshot.findings.high;
  const newTotalMedium = (profile.totalMedium || 0) + snapshot.findings.medium;
  const newTotalLow = (profile.totalLow || 0) + snapshot.findings.low;

  // Get gap counts for this customer
  const gapRows = await db!
    .select({
      status: intelligenceGaps.status,
      cnt: count(),
    })
    .from(intelligenceGaps)
    .where(eq(intelligenceGaps.customerId, snapshot.customerId))
    .groupBy(intelligenceGaps.status);

  let openGaps = 0;
  let resolvedGaps = 0;
  for (const row of gapRows) {
    const c = Number(row.cnt);
    if (row.status === "open" || row.status === "acknowledged") openGaps += c;
    if (row.status === "resolved" || row.status === "mitigated") resolvedGaps += c;
  }

  // Calculate new posture score
  const postureScore = calculatePostureScore({
    totalFindings: newTotalFindings,
    critical: newTotalCritical,
    high: newTotalHigh,
    medium: newTotalMedium,
    low: newTotalLow,
    totalAssets: snapshot.assets.total,
    openGaps,
    resolvedGaps,
  });

  // Update posture trend
  postureTrend.push({
    date: snapshot.date,
    score: postureScore,
    engagementId: snapshot.engagementId,
  });

  // Update findings trend
  findingsTrend.push({
    date: snapshot.date,
    critical: snapshot.findings.critical,
    high: snapshot.findings.high,
    medium: snapshot.findings.medium,
    low: snapshot.findings.low,
  });

  // Update recurring weaknesses
  if (snapshot.weaknessCategories) {
    for (const cat of snapshot.weaknessCategories) {
      const existing = recurringWeaknesses.find((w: any) => w.category === cat);
      if (existing) {
        existing.count += 1;
        existing.lastSeen = snapshot.date;
        existing.trend = existing.count >= 3 ? "persistent" : "recurring";
      } else {
        recurringWeaknesses.push({
          category: cat,
          count: 1,
          lastSeen: snapshot.date,
          trend: "new",
        });
      }
    }
  }

  // Track technology changes
  if (snapshot.technologies && snapshot.technologies.length > 0) {
    const newTech = snapshot.technologies;
    const added = newTech.filter((t) => !knownTech.includes(t));
    const removed = knownTech.filter((t) => !newTech.includes(t));

    if (added.length > 0 || removed.length > 0) {
      techChanges.push({
        date: snapshot.date,
        ...(added.length > 0 ? { added } : {}),
        ...(removed.length > 0 ? { removed } : {}),
      });
    }

    // Update known technologies to latest
    const updatedTech = Array.from(new Set([...knownTech, ...newTech]));

    await db!
      .update(customerIntelligenceProfiles)
      .set({ knownTechnologies: updatedTech })
      .where(eq(customerIntelligenceProfiles.id, profile.id));
  }

  // Update attack surface trend
  surfaceTrend.push({
    date: snapshot.date,
    hosts: snapshot.assets.hosts,
    services: snapshot.assets.services,
    exposedPorts: snapshot.assets.exposedPorts,
  });

  // Generate strategic recommendations
  const recommendations = generateStrategicRecommendations({
    postureScore,
    recurringWeaknesses,
    openGaps,
    findings: {
      critical: newTotalCritical,
      high: newTotalHigh,
    },
    surfaceTrend,
  });

  // Determine overall trend
  const trend = determineTrend(postureTrend);

  // Persist all updates
  await db!
    .update(customerIntelligenceProfiles)
    .set({
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
      lastEngagementDate: snapshot.date,
    })
    .where(eq(customerIntelligenceProfiles.id, profile.id));
}

/**
 * Increment DI scan count for a customer
 */
export async function incrementDIScanCount(customerId: string): Promise<void> {
  const db = await getDb();
  await db!
    .update(customerIntelligenceProfiles)
    .set({
      totalDIScans: sql`${customerIntelligenceProfiles.totalDIScans} + 1`,
    })
    .where(eq(customerIntelligenceProfiles.customerId, customerId));
}

// ── Strategic Recommendations ──────────────────────────────────────────────

interface RecommendationInput {
  postureScore: number;
  recurringWeaknesses: Array<{ category: string; count: number; trend: string }>;
  openGaps: number;
  findings: { critical: number; high: number };
  surfaceTrend: Array<{ date: string; hosts: number; services: number; exposedPorts: number }>;
}

function generateStrategicRecommendations(
  input: RecommendationInput
): Array<{ priority: string; title: string; rationale: string; effort: string; impact: string }> {
  const recs: Array<{ priority: string; title: string; rationale: string; effort: string; impact: string }> = [];

  // Critical findings
  if (input.findings.critical > 0) {
    recs.push({
      priority: "critical",
      title: "Remediate critical-severity findings immediately",
      rationale: `${input.findings.critical} critical finding(s) represent exploitable conditions with severe business impact`,
      effort: "Varies by finding",
      impact: "Eliminates highest-risk exposure vectors",
    });
  }

  // Recurring weaknesses
  const persistent = input.recurringWeaknesses.filter((w) => w.count >= 3);
  if (persistent.length > 0) {
    recs.push({
      priority: "high",
      title: `Address ${persistent.length} persistent weakness pattern(s)`,
      rationale: `Categories recurring across 3+ engagements: ${persistent.map((w) => w.category).join(", ")}. These indicate systemic issues that point-fixes won't resolve.`,
      effort: "Medium-term program investment",
      impact: "Breaks recurring vulnerability patterns",
    });
  }

  // Open intelligence gaps
  if (input.openGaps > 5) {
    recs.push({
      priority: "high",
      title: "Close intelligence gaps to improve assessment coverage",
      rationale: `${input.openGaps} open intelligence gaps mean significant portions of the attack surface remain unassessed`,
      effort: "Requires scope expansion and tool investment",
      impact: "Reduces unknown risk exposure",
    });
  }

  // Attack surface growth
  if (input.surfaceTrend.length >= 2) {
    const first = input.surfaceTrend[0];
    const last = input.surfaceTrend[input.surfaceTrend.length - 1];
    const growth = ((last.hosts - first.hosts) / Math.max(first.hosts, 1)) * 100;
    if (growth > 20) {
      recs.push({
        priority: "medium",
        title: "Implement attack surface management program",
        rationale: `Attack surface grew ${Math.round(growth)}% (${first.hosts} → ${last.hosts} hosts). Unmanaged growth increases exposure.`,
        effort: "Ongoing operational program",
        impact: "Controls exposure growth rate",
      });
    }
  }

  // Low posture score
  if (input.postureScore < 60) {
    recs.push({
      priority: "high",
      title: "Invest in foundational security hygiene program",
      rationale: `Overall posture score of ${input.postureScore}/100 (Grade ${scoreToGrade(input.postureScore)}) indicates significant security debt`,
      effort: "Multi-quarter program",
      impact: "Raises baseline security posture across the organization",
    });
  }

  return recs;
}
