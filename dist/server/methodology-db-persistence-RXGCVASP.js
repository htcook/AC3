import {
  getDb,
  init_db
} from "./chunk-B7OU3XQL.js";
import "./chunk-NRYVRXXR.js";
import {
  exploitMethodologies,
  init_schema,
  methodologyAttempts,
  methodologyPerformance
} from "./chunk-TYPEU32S.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/knowledge/methodology-db-persistence.ts
import { eq, desc, sql, and, gte } from "drizzle-orm";
async function persistMethodology(methodology) {
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
      updatedAt: methodology.updatedAt
    }).onDuplicateKeyUpdate({
      set: {
        weight: methodology.weight,
        successCount: methodology.successCount,
        attemptCount: methodology.attemptCount,
        updatedAt: methodology.updatedAt
      }
    });
  } catch (err) {
    console.warn(`[MethodologyDB] Failed to persist methodology ${methodology.id}:`, err.message);
  }
}
async function updateMethodologyStats(methodologyId, weight, successCount, attemptCount) {
  try {
    const db = await getDb();
    if (!db) return;
    await db.update(exploitMethodologies).set({ weight, successCount, attemptCount, updatedAt: Date.now() }).where(eq(exploitMethodologies.id, methodologyId));
  } catch (err) {
    console.warn(`[MethodologyDB] Failed to update stats for ${methodologyId}:`, err.message);
  }
}
async function loadLearnedMethodologies() {
  try {
    const db = await getDb();
    if (!db) return [];
    const rows = await db.select().from(exploitMethodologies).where(eq(exploitMethodologies.source, "learned")).orderBy(desc(exploitMethodologies.weight));
    return rows.map((row) => ({
      id: row.id,
      vulnClass: row.vulnClass,
      name: row.name,
      techStack: row.techStack,
      owaspCategory: row.owaspCategory || void 0,
      mitreTechniques: row.mitreTechniques,
      cweIds: row.cweIds,
      steps: row.steps,
      payloads: row.payloads,
      detectionSignatures: row.detectionSignatures,
      escalationPaths: row.escalationPaths || [],
      successCriteria: row.successCriteria,
      failureModes: row.failureModes || [],
      weight: row.weight,
      source: row.source,
      successCount: row.successCount,
      attemptCount: row.attemptCount,
      updatedAt: row.updatedAt
    }));
  } catch (err) {
    console.warn(`[MethodologyDB] Failed to load learned methodologies:`, err.message);
    return [];
  }
}
async function recordMethodologyAttempt(record) {
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
      createdAt: Date.now()
    });
    return result.insertId || null;
  } catch (err) {
    console.warn(`[MethodologyDB] Failed to record attempt:`, err.message);
    return null;
  }
}
async function markAttemptAsTrainingSource(attemptId, trainingExampleId, graduationImpact) {
  try {
    const db = await getDb();
    if (!db) return;
    await db.update(methodologyAttempts).set({
      trainingExampleGenerated: 1,
      trainingExampleId,
      graduationScoreImpact: graduationImpact
    }).where(eq(methodologyAttempts.id, attemptId));
  } catch (err) {
    console.warn(`[MethodologyDB] Failed to mark attempt ${attemptId} as training source:`, err.message);
  }
}
async function updatePerformanceStats(vulnClass, techStack, success, executionTimeMs) {
  const techStackKey = techStack.length > 0 ? techStack.sort().join("|").toLowerCase() : "universal";
  const now = Date.now();
  try {
    const db = await getDb();
    if (!db) return;
    const [existing] = await db.select().from(methodologyPerformance).where(and(
      eq(methodologyPerformance.vulnClass, vulnClass),
      eq(methodologyPerformance.techStackKey, techStackKey)
    )).limit(1);
    if (existing) {
      const newAttempts = existing.totalAttempts + 1;
      const newSuccesses = existing.totalSuccesses + (success ? 1 : 0);
      const newRate = newSuccesses / newAttempts;
      const newAvgTime = executionTimeMs ? Math.round(((existing.avgExecutionTimeMs || 0) * existing.totalAttempts + executionTimeMs) / newAttempts) : existing.avgExecutionTimeMs;
      await db.update(methodologyPerformance).set({
        totalAttempts: newAttempts,
        totalSuccesses: newSuccesses,
        successRate: newRate,
        avgExecutionTimeMs: newAvgTime,
        lastAttemptAt: now,
        lastSuccessAt: success ? now : existing.lastSuccessAt,
        updatedAt: now
      }).where(eq(methodologyPerformance.id, existing.id));
    } else {
      await db.insert(methodologyPerformance).values({
        vulnClass,
        techStackKey,
        totalAttempts: 1,
        totalSuccesses: success ? 1 : 0,
        successRate: success ? 1 : 0,
        avgExecutionTimeMs: executionTimeMs || null,
        lastAttemptAt: now,
        lastSuccessAt: success ? now : null,
        updatedAt: now
      });
    }
  } catch (err) {
    console.warn(`[MethodologyDB] Failed to update performance stats:`, err.message);
  }
}
function generateMethodologyTrainingExample(attempt) {
  if (!attempt.success) return null;
  const methodology = attempt.methodology;
  const stepsContext = methodology ? methodology.steps.map((s) => `${s.order}. ${s.description}`).join("\n") : "No structured methodology available";
  const payloadContext = methodology ? methodology.payloads.map((p) => `- ${p.name}: ${p.payload}`).join("\n") : attempt.payloadUsed || "No payload recorded";
  return {
    model: "exploit_selector",
    messages: [
      {
        role: "system",
        content: `You are an exploit selection specialist. Given a vulnerability class and target context, select and execute the optimal exploitation technique using parameterized methodology templates.`
      },
      {
        role: "user",
        content: [
          `Vulnerability Class: ${attempt.vulnClass}`,
          `Target: ${attempt.target || "unknown"}`,
          `Port: ${attempt.port || "unknown"}`,
          `Tech Stack: ${attempt.techStack.join(", ") || "unknown"}`,
          methodology ? `
Available Methodology: ${methodology.name}` : "",
          methodology ? `Steps:
${stepsContext}` : "",
          methodology ? `Known Payloads:
${payloadContext}` : ""
        ].filter(Boolean).join("\n")
      },
      {
        role: "assistant",
        content: [
          `Approach: ${attempt.approach}`,
          attempt.payloadUsed ? `Payload Used: ${attempt.payloadUsed}` : "",
          `Result: Successful exploitation of ${attempt.vulnClass} vulnerability`,
          methodology ? `Methodology Used: ${methodology.name} (${methodology.id})` : "Ad-hoc exploitation approach"
        ].filter(Boolean).join("\n")
      }
    ],
    quality: methodology ? "high" : "medium",
    qualityScore: methodology ? 0.95 : 0.75,
    metadata: {
      vulnClass: attempt.vulnClass,
      techStack: attempt.techStack,
      methodologyId: attempt.methodologyId,
      methodologySource: methodology?.source,
      engagementId: attempt.engagementId,
      executionTimeMs: attempt.executionTimeMs
    }
  };
}
async function getMethodologyGraduationMetrics(engagementId) {
  try {
    const db = await getDb();
    if (!db) throw new Error("DB not available");
    const attemptFilter = engagementId ? and(eq(methodologyAttempts.engagementId, engagementId)) : void 0;
    const attempts = await db.select({
      total: sql`COUNT(*)`,
      successes: sql`SUM(CASE WHEN ${methodologyAttempts.success} = 1 THEN 1 ELSE 0 END)`,
      withMethodology: sql`SUM(CASE WHEN ${methodologyAttempts.methodologyId} IS NOT NULL THEN 1 ELSE 0 END)`,
      uniqueClasses: sql`COUNT(DISTINCT ${methodologyAttempts.vulnClass})`
    }).from(methodologyAttempts).where(attemptFilter || sql`1=1`);
    const stats = attempts[0] || { total: 0, successes: 0, withMethodology: 0, uniqueClasses: 0 };
    const [learnedCount] = await db.select({
      count: sql`COUNT(*)`
    }).from(exploitMethodologies).where(eq(exploitMethodologies.source, "learned"));
    const topClasses = await db.select({
      vulnClass: methodologyPerformance.vulnClass,
      successRate: methodologyPerformance.successRate,
      attempts: methodologyPerformance.totalAttempts
    }).from(methodologyPerformance).where(gte(methodologyPerformance.totalAttempts, 2)).orderBy(desc(methodologyPerformance.successRate)).limit(10);
    const total = Number(stats.total) || 0;
    const successes = Number(stats.successes) || 0;
    const withMethodology = Number(stats.withMethodology) || 0;
    return {
      totalMethodologyAttempts: total,
      totalMethodologySuccesses: successes,
      methodologySuccessRate: total > 0 ? successes / total : 0,
      learnedMethodologiesCreated: Number(learnedCount?.count) || 0,
      vulnClassesCovered: Number(stats.uniqueClasses) || 0,
      topPerformingClasses: topClasses.map((c) => ({
        vulnClass: c.vulnClass,
        successRate: c.successRate,
        attempts: c.attempts
      })),
      methodologyGuidedExploitRate: total > 0 ? withMethodology / total : 0
    };
  } catch (err) {
    console.warn(`[MethodologyDB] Failed to get graduation metrics:`, err.message);
    return {
      totalMethodologyAttempts: 0,
      totalMethodologySuccesses: 0,
      methodologySuccessRate: 0,
      learnedMethodologiesCreated: 0,
      vulnClassesCovered: 0,
      topPerformingClasses: [],
      methodologyGuidedExploitRate: 0
    };
  }
}
async function computeMethodologyGraduationBonus(engagementId) {
  const metrics = await getMethodologyGraduationMetrics(engagementId);
  let bonus = 0;
  const reasons = [];
  if (metrics.methodologyGuidedExploitRate > 0.5) {
    bonus += 5;
    reasons.push(`${Math.round(metrics.methodologyGuidedExploitRate * 100)}% methodology-guided`);
  } else if (metrics.methodologyGuidedExploitRate > 0.2) {
    bonus += 3;
    reasons.push(`${Math.round(metrics.methodologyGuidedExploitRate * 100)}% methodology-guided`);
  }
  if (metrics.methodologySuccessRate > 0.3 && metrics.totalMethodologyAttempts >= 3) {
    bonus += 5;
    reasons.push(`${Math.round(metrics.methodologySuccessRate * 100)}% methodology success rate`);
  } else if (metrics.methodologySuccessRate > 0.1 && metrics.totalMethodologyAttempts >= 2) {
    bonus += 2;
    reasons.push(`${Math.round(metrics.methodologySuccessRate * 100)}% methodology success rate`);
  }
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
    rationale: reasons.length > 0 ? `Methodology knowledge bonus: +${Math.min(20, bonus)} (${reasons.join(", ")})` : "No methodology knowledge data available"
  };
}
var init_methodology_db_persistence = __esm({
  "server/lib/knowledge/methodology-db-persistence.ts"() {
    init_db();
    init_schema();
  }
});
init_methodology_db_persistence();
export {
  computeMethodologyGraduationBonus,
  generateMethodologyTrainingExample,
  getMethodologyGraduationMetrics,
  loadLearnedMethodologies,
  markAttemptAsTrainingSource,
  persistMethodology,
  recordMethodologyAttempt,
  updateMethodologyStats,
  updatePerformanceStats
};
