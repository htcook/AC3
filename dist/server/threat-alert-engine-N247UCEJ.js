import {
  init_notification,
  notifyOwner
} from "./chunk-V73EMRJ6.js";
import {
  getDb,
  init_db
} from "./chunk-AX6SVAQZ.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  threatAlertHistory,
  threatAlertThresholds
} from "./chunk-DQZ564DJ.js";
import "./chunk-KFQGP6VL.js";

// server/lib/threat-alert-engine.ts
init_db();
init_schema();
init_notification();
import { eq, desc, and } from "drizzle-orm";
async function checkAlertThresholds(input) {
  const db = await getDb();
  if (!db) return { alertsFired: 0, alerts: [] };
  const thresholds = await db.select().from(threatAlertThresholds).where(eq(threatAlertThresholds.enabled, 1));
  if (thresholds.length === 0) return { alertsFired: 0, alerts: [] };
  const cutoff24h = Date.now() - 24 * 60 * 60 * 1e3;
  const recentAlerts = await db.select({
    actorId: threatAlertHistory.actorId,
    thresholdId: threatAlertHistory.thresholdId
  }).from(threatAlertHistory).where(and(
    eq(threatAlertHistory.notificationSent, 1)
  )).limit(500);
  const recentAlertKeys = new Set(
    recentAlerts.filter((a) => true).map((a) => `${a.thresholdId}:${a.actorId}`)
  );
  const alerts = [];
  for (const threshold of thresholds) {
    if (threshold.scanId && threshold.scanId !== input.scanId) continue;
    for (const actor of input.matchedActors) {
      if (actor.relevanceScore < threshold.relevanceThreshold) continue;
      if (threshold.threatLevelFilter !== "any") {
        const levelOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        const actorLevel = levelOrder[actor.threatLevel || "medium"] || 2;
        const filterLevel = levelOrder[threshold.threatLevelFilter || "any"] || 0;
        if (actorLevel < filterLevel) continue;
      }
      const reasons = [];
      if (actor.relevanceScore >= threshold.relevanceThreshold) {
        reasons.push(`Relevance ${actor.relevanceScore} >= threshold ${threshold.relevanceThreshold}`);
      }
      if (threshold.notifyOnRising && input.risingActors?.has(actor.actorId)) {
        reasons.push("Activity trend: RISING");
      }
      if (threshold.notifyOnNew && input.iocOverlapActors?.has(actor.actorId)) {
        reasons.push(`IOC overlap detected (${actor.iocCount} indicators)`);
      }
      const triggerReason = reasons.join("; ");
      const alertKey = `${threshold.id}:${actor.actorId}`;
      if (recentAlertKeys.has(alertKey)) {
        alerts.push({
          actorId: actor.actorId,
          actorName: actor.name,
          relevanceScore: actor.relevanceScore,
          triggerReason,
          notified: false
        });
        continue;
      }
      let notified = false;
      try {
        const success = await notifyOwner({
          title: `Threat Alert: ${actor.name} (Score: ${actor.relevanceScore})`,
          content: [
            `**Threat Actor:** ${actor.name} (${actor.threatLevel?.toUpperCase()})`,
            `**Relevance Score:** ${actor.relevanceScore}/100`,
            `**Trigger:** ${triggerReason}`,
            actor.matchedSectors.length > 0 ? `**Matched Sectors:** ${actor.matchedSectors.join(", ")}` : "",
            actor.attackVectors.length > 0 ? `**Attack Vectors:** ${actor.attackVectors.join(", ")}` : "",
            `**Action Required:** Review actor profile and update detection rules.`
          ].filter(Boolean).join("\n")
        });
        notified = success;
      } catch (err) {
        console.error(`[ThreatAlert] Failed to notify for ${actor.name}:`, err);
      }
      try {
        await db.insert(threatAlertHistory).values({
          thresholdId: threshold.id,
          scanId: input.scanId,
          actorId: actor.actorId,
          actorName: actor.name,
          relevanceScore: actor.relevanceScore,
          threatLevel: actor.threatLevel,
          triggerReason,
          notificationSent: notified ? 1 : 0,
          notificationError: notified ? null : "Notification service unavailable"
        });
      } catch (err) {
        console.error(`[ThreatAlert] Failed to record alert history:`, err);
      }
      alerts.push({
        actorId: actor.actorId,
        actorName: actor.name,
        relevanceScore: actor.relevanceScore,
        triggerReason,
        notified
      });
    }
  }
  return {
    alertsFired: alerts.filter((a) => a.notified).length,
    alerts
  };
}
async function getAlertThresholds() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatAlertThresholds).orderBy(desc(threatAlertThresholds.createdAt));
}
async function upsertAlertThreshold(data) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  if (data.id) {
    await db.update(threatAlertThresholds).set({
      label: data.label,
      scanId: data.scanId ?? null,
      relevanceThreshold: data.relevanceThreshold,
      threatLevelFilter: data.threatLevelFilter || "any",
      enabled: data.enabled !== false ? 1 : 0,
      notifyOnNew: data.notifyOnNew !== false ? 1 : 0,
      notifyOnRising: data.notifyOnRising !== false ? 1 : 0
    }).where(eq(threatAlertThresholds.id, data.id));
    return { id: data.id };
  } else {
    const [result] = await db.insert(threatAlertThresholds).values({
      label: data.label,
      scanId: data.scanId ?? null,
      relevanceThreshold: data.relevanceThreshold,
      threatLevelFilter: data.threatLevelFilter || "any",
      enabled: data.enabled !== false ? 1 : 0,
      notifyOnNew: data.notifyOnNew !== false ? 1 : 0,
      notifyOnRising: data.notifyOnRising !== false ? 1 : 0,
      createdBy: data.createdBy
    });
    return { id: result.insertId };
  }
}
async function deleteAlertThreshold(id) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.delete(threatAlertThresholds).where(eq(threatAlertThresholds.id, id));
}
async function getAlertHistory(opts) {
  const db = await getDb();
  if (!db) return [];
  let query = db.select().from(threatAlertHistory).orderBy(desc(threatAlertHistory.createdAt)).limit(opts?.limit || 50);
  if (opts?.scanId) {
    query = db.select().from(threatAlertHistory).where(eq(threatAlertHistory.scanId, opts.scanId)).orderBy(desc(threatAlertHistory.createdAt)).limit(opts?.limit || 50);
  }
  return query;
}
export {
  checkAlertThresholds,
  deleteAlertThreshold,
  getAlertHistory,
  getAlertThresholds,
  upsertAlertThreshold
};
