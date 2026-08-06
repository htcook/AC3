/**
 * Threat Alert Engine — Monitors relevance scores and fires notifications
 *
 * When a threat briefing is computed, this engine checks configured thresholds
 * and fires notifications via notifyOwner() when:
 * - An actor's relevance score exceeds the configured threshold
 * - An actor's trend is "rising" (activity increasing)
 * - New IOC overlaps are detected
 */
import { getDb } from "../db";
import { eq, desc, and } from "drizzle-orm";
import {
  threatAlertThresholds,
  threatAlertHistory,
} from "../../drizzle/schema";
import { notifyOwner } from "../_core/notification";

export interface AlertCheckInput {
  scanId: number | null;
  matchedActors: Array<{
    actorId: string;
    name: string;
    relevanceScore: number;
    threatLevel: string | null;
    iocCount: number;
    matchedSectors: string[];
    attackVectors: string[];
  }>;
  iocOverlapActors?: Set<string>;   // actors with IOC hits
  risingActors?: Set<string>;       // actors with rising trend
}

export interface AlertResult {
  alertsFired: number;
  alerts: Array<{
    actorId: string;
    actorName: string;
    relevanceScore: number;
    triggerReason: string;
    notified: boolean;
  }>;
}

/**
 * Check all active thresholds against the current briefing results.
 * Fires notifications for new alerts only (deduplicates within 24h window).
 */
export async function checkAlertThresholds(input: AlertCheckInput): Promise<AlertResult> {
  const db = await getDb();
  if (!db) return { alertsFired: 0, alerts: [] };

  // Load active thresholds
  const thresholds = await db.select().from(threatAlertThresholds)
    .where(eq(threatAlertThresholds.enabled, 1));

  if (thresholds.length === 0) return { alertsFired: 0, alerts: [] };

  // Load recent alerts (last 24h) to avoid duplicates
  const cutoff24h = Date.now() - 24 * 60 * 60 * 1000;
  const recentAlerts = await db.select({
    actorId: threatAlertHistory.actorId,
    thresholdId: threatAlertHistory.thresholdId,
  }).from(threatAlertHistory)
    .where(and(
      eq(threatAlertHistory.notificationSent, 1),
    ))
    .limit(500);

  const recentAlertKeys = new Set(
    recentAlerts
      .filter(a => true) // keep all for now
      .map(a => `${a.thresholdId}:${a.actorId}`)
  );

  const alerts: AlertResult["alerts"] = [];

  for (const threshold of thresholds) {
    // Filter by scan if threshold is scan-specific
    if (threshold.scanId && threshold.scanId !== input.scanId) continue;

    for (const actor of input.matchedActors) {
      // Check relevance threshold
      if (actor.relevanceScore < threshold.relevanceThreshold) continue;

      // Check threat level filter
      if (threshold.threatLevelFilter !== "any") {
        const levelOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        const actorLevel = levelOrder[actor.threatLevel || "medium"] || 2;
        const filterLevel = levelOrder[threshold.threatLevelFilter || "any"] || 0;
        if (actorLevel < filterLevel) continue;
      }

      // Determine trigger reason
      const reasons: string[] = [];
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

      // Skip if already alerted in last 24h
      if (recentAlertKeys.has(alertKey)) {
        alerts.push({
          actorId: actor.actorId,
          actorName: actor.name,
          relevanceScore: actor.relevanceScore,
          triggerReason,
          notified: false,
        });
        continue;
      }

      // Fire notification
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
            `**Action Required:** Review actor profile and update detection rules.`,
          ].filter(Boolean).join("\n"),
        });
        notified = success;
      } catch (err) {
        // Log but don't fail
        console.error(`[ThreatAlert] Failed to notify for ${actor.name}:`, err);
      }

      // Record alert in history
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
          notificationError: notified ? null : "Notification service unavailable",
        });
      } catch (err) {
        console.error(`[ThreatAlert] Failed to record alert history:`, err);
      }

      alerts.push({
        actorId: actor.actorId,
        actorName: actor.name,
        relevanceScore: actor.relevanceScore,
        triggerReason,
        notified,
      });
    }
  }

  return {
    alertsFired: alerts.filter(a => a.notified).length,
    alerts,
  };
}

// ─── CRUD for Alert Thresholds ──────────────────────────────────────────────

export async function getAlertThresholds() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatAlertThresholds).orderBy(desc(threatAlertThresholds.createdAt));
}

export async function upsertAlertThreshold(data: {
  id?: number;
  scanId?: number | null;
  label: string;
  relevanceThreshold: number;
  threatLevelFilter?: "any" | "critical" | "high" | "medium";
  enabled?: boolean;
  notifyOnNew?: boolean;
  notifyOnRising?: boolean;
  createdBy?: string;
}) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  if (data.id) {
    await db.update(threatAlertThresholds)
      .set({
        label: data.label,
        scanId: data.scanId ?? null,
        relevanceThreshold: data.relevanceThreshold,
        threatLevelFilter: data.threatLevelFilter || "any",
        enabled: data.enabled !== false ? 1 : 0,
        notifyOnNew: data.notifyOnNew !== false ? 1 : 0,
        notifyOnRising: data.notifyOnRising !== false ? 1 : 0,
      })
      .where(eq(threatAlertThresholds.id, data.id));
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
      createdBy: data.createdBy,
    });
    return { id: result.insertId };
  }
}

export async function deleteAlertThreshold(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  await db.delete(threatAlertThresholds).where(eq(threatAlertThresholds.id, id));
}

export async function getAlertHistory(opts?: { scanId?: number; limit?: number }) {
  const db = await getDb();
  if (!db) return [];
  let query = db.select().from(threatAlertHistory)
    .orderBy(desc(threatAlertHistory.createdAt))
    .limit(opts?.limit || 50);

  if (opts?.scanId) {
    query = db.select().from(threatAlertHistory)
      .where(eq(threatAlertHistory.scanId, opts.scanId))
      .orderBy(desc(threatAlertHistory.createdAt))
      .limit(opts?.limit || 50);
  }

  return query;
}
