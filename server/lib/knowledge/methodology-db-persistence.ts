/**
 * Methodology DB Persistence & Training/Graduation Bridge
 *
 * Responsibilities:
 *   1. Persist learned methodologies to DB so they survive server restarts
 *   2. Hydrate the in-memory methodology store from DB on startup
 *   3. Record per-attempt outcomes to methodology_attempts table
 *   4. Maintain aggregated performance stats in methodology_performance table
 *   5. Generate training examples from methodology-guided exploits
 *   6. Feed methodology success rates into graduation scoring
 */

import { getDb } from "../../db";
import {
  exploitMethodologies,
  methodologyAttempts,
  methodologyPerformance,
} from "../../../drizzle/schema";
import { eq, desc, sql, and, gte } from "drizzle-orm";
import type { ExploitMethodology } from "./exploit-methodology-knowledge";

// ─── DB Persistence ────────────────────────────────────────────────────────

/**
 * Persist a learned methodology to the DB.
 * Called when ingestExploitFeedback creates a new 'learned' methodology.
 */
export async function persistMethodology(methodology: ExploitMethodology): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;
    await db.insert(exploitMethodologies).values({
      id: methodology.id,
      vulnClass: methodology.vulnClass,
      name: methodology.name,
      techStack: methodology.techStack,
      owaspCategory: methodology.owaspCategory || null,
      mitreTechniques: methodology.mitreTechniques || null,
      cweIds: methodology.cweIds || null,
      steps: methodology.steps,
      payloads: methodology.payloads,
      detectionSignatures: methodology.detectionSignatures,
      escalationPaths: methodology.escalationPaths || null,
      successCriteria: methodology.successCriteria,
      failureModes: methodology.failureModes || null,
      weight: methodology.weight,
      source: methodology.source,
      successCount: methodology.successCount,
      attemptCount: methodology.attemptCount,
      createdAt: Date.now(),
      updatedAt: methodology.updatedAt,
    }).onDuplicateKeyUpdate({
      set: {
        weight: methodology.weight,
        successCount: methodology.successCount,
        attemptCount: methodology.attemptCount,
        updatedAt: methodology.updatedAt,
      },
    });
  } catch (err: any) {
    console.warn(`[MethodologyDB] Failed to persist methodology ${methodology.id}:`, err.message);
  }
}

/**
 * Update methodology stats in DB after a feedback event.
 */
export async function updateMethodologyStats(
  methodologyId: string,
  weight: number,
  successCount: number,
  attemptCount: number,
): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;
    await db.update(exploitMethodologies)
      .set({ weight, successCount, attemptCount, updatedAt: Date.now() })
      .where(eq(exploitMethodologies.id, methodologyId));
  } catch (err: any) {
    console.warn(`[MethodologyDB] Failed to update stats for ${methodologyId}:`, err.message);
  }
}

/**
 * Load all learned methodologies from DB for hydration on startup.
 */
export async function loadLearnedMethodologies(): Promise<ExploitMethodology[]> {
  try {
    const db = await getDb();
    if (!db) return [];
    const rows = await db.select().from(exploitMethodologies)
      .where(eq(exploitMethodologies.source, 'learned'))
      .orderBy(desc(exploitMethodologies.weight));

    return rows.map(row => ({
      id: row.id,
      vulnClass: row.vulnClass,
      name: row.name,
      techStack: row.techStack as string[],
      owaspCategory: row.owaspCategory || undefined,
      mitreTechniques: row.mitreTechniques as string[] | undefined,
      cweIds: row.cweIds as string[] | undefined,
      steps: row.steps as ExploitMethodology['steps'],
      payloads: row.payloads as ExploitMethodology['payloads'],
      detectionSignatures: row.detectionSignatures as string[],
      escalationPaths: (row.escalationPaths as ExploitMethodology['escalationPaths']) || [],
      successCriteria: row.successCriteria as string[],
      failureModes: (row.failureModes as ExploitMethodology['failureModes']) || [],
      weight: row.weight,
      source: row.source as 'learned',
      successCount: row.successCount,
      attemptCount: row.attemptCount,
      updatedAt: row.updatedAt,
    }));
  } catch (err: any) {
    console.warn(`[MethodologyDB] Failed to load learned methodologies:`, err.message);
    return [];
  }
}

// ─── Attempt Recording ─────────────────────────────────────────────────────

export interface MethodologyAttemptRecord {
  methodologyId?: string;
  engagementId?: number;
  vulnClass: string;
  techStack: string[];
  target?: string;
  port?: number;
  success: boolean;
  approach: string;
  payloadUsed?: string;
  failureReason?: string;
  executionTimeMs?: number;
}

/**
 * Record a methodology attempt to the DB.
 * Returns the inserted ID for linking to training examples.
 */
export async function recordMethodologyAttempt(
  record: MethodologyAttemptRecord,
): Promise<number | null> {
  try {
    const db = await getDb();
    if (!db) return null;
    const [result] = await db.insert(methodologyAttempts).values({
      methodologyId: record.methodologyId || null,
      engagementId: record.engagementId || null,
      vulnClass: record.vulnClass,
      techStack: record.techStack,
      target: record.target || null,
      port: record.port || null,
      success: record.success ? 1 : 0,
      approach: record.approach,
      payloadUsed: record.payloadUsed || null,
      failureReason: record.failureReason || null,
      executionTimeMs: record.executionTimeMs || null,
      trainingExampleGenerated: 0,
      createdAt: Date.now(),
    });
    return (result as any).insertId || null;
  } catch (err: any) {
    console.warn(`[MethodologyDB] Failed to record attempt:`, err.message);
    return null;
  }
}

/**
 * Mark an attempt as having generated a training example.
 */
export async function markAttemptAsTrainingSource(
  attemptId: number,
  trainingExampleId: string,
  graduationImpact: number,
): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;
    await db.update(methodologyAttempts)
      .set({
        trainingExampleGenerated: 1,
        trainingExampleId: trainingExampleId,
        graduationScoreImpact: graduationImpact,
      })
      .where(eq(methodologyAttempts.id, attemptId));
  } catch (err: any) {
    console.warn(`[MethodologyDB] Failed to mark attempt ${attemptId} as training source:`, err.message);
  }
}

// ─── Performance Aggregation ───────────────────────────────────────────────

/**
 * Update the aggregated performance stats for a vuln_class + tech_stack combo.
 */
export async function updatePerformanceStats(
  vulnClass: string,
  techStack: string[],
  success: boolean,
  executionTimeMs?: number,
): Promise<void> {
  const techStackKey = techStack.length > 0 ? techStack.sort().join('|').toLowerCase() : 'universal';
  const now = Date.now();

  try {
    const db = await getDb();
    if (!db) return;
    // Try to update existing row
    const [existing] = await db.select().from(methodologyPerformance)
      .where(and(
        eq(methodologyPerformance.vulnClass, vulnClass),
        eq(methodologyPerformance.techStackKey, techStackKey),
      ))
      .limit(1);

    if (existing) {
      const newAttempts = existing.totalAttempts + 1;
      const newSuccesses = existing.totalSuccesses + (success ? 1 : 0);
      const newRate = newSuccesses / newAttempts;
      const newAvgTime = executionTimeMs
        ? Math.round(((existing.avgExecutionTimeMs || 0) * existing.totalAttempts + executionTimeMs) / newAttempts)
        : existing.avgExecutionTimeMs;

      await db.update(methodologyPerformance)
        .set({
          totalAttempts: newAttempts,
          totalSuccesses: newSuccesses,
          successRate: newRate,
          avgExecutionTimeMs: newAvgTime,
          lastAttemptAt: now,
          lastSuccessAt: success ? now : existing.lastSuccessAt,
          updatedAt: now,
        })
        .where(eq(methodologyPerformance.id, existing.id));
    } else {
      await db.insert(methodologyPerformance).values({
        vulnClass,
        techStackKey,
        totalAttempts: 1,
        totalSuccesses: success ? 1 : 0,
        successRate: success ? 1.0 : 0.0,
        avgExecutionTimeMs: executionTimeMs || null,
        lastAttemptAt: now,
        lastSuccessAt: success ? now : null,
        updatedAt: now,
      });
    }
  } catch (err: any) {
    console.warn(`[MethodologyDB] Failed to update performance stats:`, err.message);
  }
}

// ─── Training Pipeline Integration ─────────────────────────────────────────

/**
 * Generate a training example from a methodology-guided exploit outcome.
 * Returns a structured training example suitable for the LLM training pipeline.
 */
export function generateMethodologyTrainingExample(
  attempt: MethodologyAttemptRecord & { methodology?: ExploitMethodology },
): {
  model: 'exploit_selector';
  messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>;
  quality: 'high' | 'medium' | 'low';
  qualityScore: number;
  metadata: Record<string, any>;
} | null {
  if (!attempt.success) return null; // Only successful exploits become training examples

  const methodology = attempt.methodology;
  const stepsContext = methodology
    ? methodology.steps.map(s => `${s.order}. ${s.description}`).join('\n')
    : 'No structured methodology available';

  const payloadContext = methodology
    ? methodology.payloads.map(p => `- ${p.name}: ${p.payload}`).join('\n')
    : attempt.payloadUsed || 'No payload recorded';

  return {
    model: 'exploit_selector',
    messages: [
      {
        role: 'system',
        content: `You are an exploit selection specialist. Given a vulnerability class and target context, select and execute the optimal exploitation technique using parameterized methodology templates.`,
      },
      {
        role: 'user',
        content: [
          `Vulnerability Class: ${attempt.vulnClass}`,
          `Target: ${attempt.target || 'unknown'}`,
          `Port: ${attempt.port || 'unknown'}`,
          `Tech Stack: ${attempt.techStack.join(', ') || 'unknown'}`,
          methodology ? `\nAvailable Methodology: ${methodology.name}` : '',
          methodology ? `Steps:\n${stepsContext}` : '',
          methodology ? `Known Payloads:\n${payloadContext}` : '',
        ].filter(Boolean).join('\n'),
      },
      {
        role: 'assistant',
        content: [
          `Approach: ${attempt.approach}`,
          attempt.payloadUsed ? `Payload Used: ${attempt.payloadUsed}` : '',
          `Result: Successful exploitation of ${attempt.vulnClass} vulnerability`,
          methodology ? `Methodology Used: ${methodology.name} (${methodology.id})` : 'Ad-hoc exploitation approach',
        ].filter(Boolean).join('\n'),
      },
    ],
    quality: methodology ? 'high' : 'medium',
    qualityScore: methodology ? 0.95 : 0.75,
    metadata: {
      vulnClass: attempt.vulnClass,
      techStack: attempt.techStack,
      methodologyId: attempt.methodologyId,
      methodologySource: methodology?.source,
      engagementId: attempt.engagementId,
      executionTimeMs: attempt.executionTimeMs,
    },
  };
}

// ─── Graduation Integration ────────────────────────────────────────────────

/**
 * Get methodology-based graduation metrics for the exploit_selector model.
 * Returns data that should be factored into the graduation scoring.
 */
export async function getMethodologyGraduationMetrics(
  engagementId?: number,
): Promise<{
  totalMethodologyAttempts: number;
  totalMethodologySuccesses: number;
  methodologySuccessRate: number;
  learnedMethodologiesCreated: number;
  vulnClassesCovered: number;
  topPerformingClasses: Array<{ vulnClass: string; successRate: number; attempts: number }>;
  methodologyGuidedExploitRate: number; // % of exploits that used a methodology
}> {
  try {
    const db = await getDb();
    if (!db) throw new Error('DB not available');
    // Get attempt stats
    const attemptFilter = engagementId
      ? and(eq(methodologyAttempts.engagementId, engagementId))
      : undefined;

    const attempts = await db.select({
      total: sql<number>`COUNT(*)`,
      successes: sql<number>`SUM(CASE WHEN ${methodologyAttempts.success} = 1 THEN 1 ELSE 0 END)`,
      withMethodology: sql<number>`SUM(CASE WHEN ${methodologyAttempts.methodologyId} IS NOT NULL THEN 1 ELSE 0 END)`,
      uniqueClasses: sql<number>`COUNT(DISTINCT ${methodologyAttempts.vulnClass})`,
    }).from(methodologyAttempts)
      .where(attemptFilter || sql`1=1`);

    const stats = attempts[0] || { total: 0, successes: 0, withMethodology: 0, uniqueClasses: 0 };

    // Get learned methodologies count
    const [learnedCount] = await db.select({
      count: sql<number>`COUNT(*)`,
    }).from(exploitMethodologies)
      .where(eq(exploitMethodologies.source, 'learned'));

    // Get top performing vuln classes from aggregated performance
    const topClasses = await db.select({
      vulnClass: methodologyPerformance.vulnClass,
      successRate: methodologyPerformance.successRate,
      attempts: methodologyPerformance.totalAttempts,
    }).from(methodologyPerformance)
      .where(gte(methodologyPerformance.totalAttempts, 2))
      .orderBy(desc(methodologyPerformance.successRate))
      .limit(10);

    const total = Number(stats.total) || 0;
    const successes = Number(stats.successes) || 0;
    const withMethodology = Number(stats.withMethodology) || 0;

    return {
      totalMethodologyAttempts: total,
      totalMethodologySuccesses: successes,
      methodologySuccessRate: total > 0 ? successes / total : 0,
      learnedMethodologiesCreated: Number(learnedCount?.count) || 0,
      vulnClassesCovered: Number(stats.uniqueClasses) || 0,
      topPerformingClasses: topClasses.map(c => ({
        vulnClass: c.vulnClass,
        successRate: c.successRate,
        attempts: c.attempts,
      })),
      methodologyGuidedExploitRate: total > 0 ? withMethodology / total : 0,
    };
  } catch (err: any) {
    console.warn(`[MethodologyDB] Failed to get graduation metrics:`, err.message);
    return {
      totalMethodologyAttempts: 0,
      totalMethodologySuccesses: 0,
      methodologySuccessRate: 0,
      learnedMethodologiesCreated: 0,
      vulnClassesCovered: 0,
      topPerformingClasses: [],
      methodologyGuidedExploitRate: 0,
    };
  }
}

/**
 * Compute the methodology bonus for exploit_selector graduation scoring.
 * Returns 0-20 bonus points based on methodology knowledge system effectiveness.
 */
export async function computeMethodologyGraduationBonus(
  engagementId?: number,
): Promise<{ bonus: number; rationale: string }> {
  const metrics = await getMethodologyGraduationMetrics(engagementId);

  let bonus = 0;
  const reasons: string[] = [];

  // Up to 5 pts for methodology-guided exploit rate (using structured knowledge)
  if (metrics.methodologyGuidedExploitRate > 0.5) {
    bonus += 5;
    reasons.push(`${Math.round(metrics.methodologyGuidedExploitRate * 100)}% methodology-guided`);
  } else if (metrics.methodologyGuidedExploitRate > 0.2) {
    bonus += 3;
    reasons.push(`${Math.round(metrics.methodologyGuidedExploitRate * 100)}% methodology-guided`);
  }

  // Up to 5 pts for methodology success rate
  if (metrics.methodologySuccessRate > 0.3 && metrics.totalMethodologyAttempts >= 3) {
    bonus += 5;
    reasons.push(`${Math.round(metrics.methodologySuccessRate * 100)}% methodology success rate`);
  } else if (metrics.methodologySuccessRate > 0.1 && metrics.totalMethodologyAttempts >= 2) {
    bonus += 2;
    reasons.push(`${Math.round(metrics.methodologySuccessRate * 100)}% methodology success rate`);
  }

  // Up to 5 pts for learning new methodologies from successful exploits
  if (metrics.learnedMethodologiesCreated >= 5) {
    bonus += 5;
    reasons.push(`${metrics.learnedMethodologiesCreated} new methodologies learned`);
  } else if (metrics.learnedMethodologiesCreated >= 2) {
    bonus += 3;
    reasons.push(`${metrics.learnedMethodologiesCreated} new methodologies learned`);
  } else if (metrics.learnedMethodologiesCreated >= 1) {
    bonus += 1;
    reasons.push(`${metrics.learnedMethodologiesCreated} new methodology learned`);
  }

  // Up to 5 pts for vuln class coverage breadth
  if (metrics.vulnClassesCovered >= 8) {
    bonus += 5;
    reasons.push(`${metrics.vulnClassesCovered} vuln classes covered`);
  } else if (metrics.vulnClassesCovered >= 4) {
    bonus += 3;
    reasons.push(`${metrics.vulnClassesCovered} vuln classes covered`);
  } else if (metrics.vulnClassesCovered >= 2) {
    bonus += 1;
    reasons.push(`${metrics.vulnClassesCovered} vuln classes covered`);
  }

  return {
    bonus: Math.min(20, bonus),
    rationale: reasons.length > 0
      ? `Methodology knowledge bonus: +${Math.min(20, bonus)} (${reasons.join(', ')})`
      : 'No methodology knowledge data available',
  };
}
