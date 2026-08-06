/**
 * Notification Preferences per Engagement
 * 
 * Controls which events trigger email vs in-app-only alerts.
 * Operators can configure per-engagement notification routing.
 */

import { eq, and } from "drizzle-orm";
import { engagementNotificationPrefs } from "../../drizzle/schema";

// ─── Types ───────────────────────────────────────────────────────────────────

export const NOTIFICATION_EVENT_TYPES = [
  "exploit_plan_approved",
  "exploit_plan_denied",
  "exploit_plan_modified",
  "phase_completed",
  "gate_timeout",
  "roe_uploaded",
] as const;

export type NotificationEventType = typeof NOTIFICATION_EVENT_TYPES[number];

export const NOTIFICATION_CHANNELS = ["email", "in_app", "both", "none"] as const;
export type NotificationChannel = typeof NOTIFICATION_CHANNELS[number];

export interface NotificationPref {
  id: number;
  engagementId: number;
  eventType: string;
  channel: string;
  enabled: number;
  createdBy: string | null;
  updatedAt: string;
  createdAt: string;
}

export interface UpsertNotificationPrefInput {
  engagementId: number;
  eventType: NotificationEventType;
  channel: NotificationChannel;
  createdBy?: string;
}

// ─── Default Preferences ─────────────────────────────────────────────────────

/** Default channel for each event type when no explicit preference is set */
export const DEFAULT_NOTIFICATION_PREFS: Record<NotificationEventType, NotificationChannel> = {
  exploit_plan_approved: "both",
  exploit_plan_denied: "both",
  exploit_plan_modified: "both",
  phase_completed: "in_app",
  gate_timeout: "email",
  roe_uploaded: "in_app",
};

// ─── DB Helpers ──────────────────────────────────────────────────────────────

/**
 * Get all notification preferences for an engagement.
 * Returns the stored prefs merged with defaults for any missing event types.
 */
export async function getNotificationPrefs(
  engagementId: number
): Promise<Record<NotificationEventType, NotificationChannel>> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) {
    return { ...DEFAULT_NOTIFICATION_PREFS };
  }

  const rows = await db
    .select()
    .from(engagementNotificationPrefs)
    .where(eq(engagementNotificationPrefs.engagementId, engagementId));

  // Start with defaults, overlay stored preferences
  const result = { ...DEFAULT_NOTIFICATION_PREFS };
  for (const row of rows) {
    if (
      NOTIFICATION_EVENT_TYPES.includes(row.eventType as NotificationEventType) &&
      NOTIFICATION_CHANNELS.includes(row.channel as NotificationChannel) &&
      row.enabled
    ) {
      result[row.eventType as NotificationEventType] = row.channel as NotificationChannel;
    } else if (!row.enabled) {
      result[row.eventType as NotificationEventType] = "none";
    }
  }

  return result;
}

/**
 * Get the notification channel for a specific event type on an engagement.
 */
export async function getNotificationChannel(
  engagementId: number,
  eventType: NotificationEventType
): Promise<NotificationChannel> {
  const prefs = await getNotificationPrefs(engagementId);
  return prefs[eventType];
}

/**
 * Check whether email should be sent for a given event on an engagement.
 */
export async function shouldSendEmail(
  engagementId: number,
  eventType: NotificationEventType
): Promise<boolean> {
  const channel = await getNotificationChannel(engagementId, eventType);
  return channel === "email" || channel === "both";
}

/**
 * Check whether in-app notification should be created for a given event.
 */
export async function shouldNotifyInApp(
  engagementId: number,
  eventType: NotificationEventType
): Promise<boolean> {
  const channel = await getNotificationChannel(engagementId, eventType);
  return channel === "in_app" || channel === "both";
}

/**
 * Upsert a notification preference for an engagement + event type.
 * If a row already exists for this (engagement_id, event_type), update it.
 * Otherwise, insert a new row.
 */
export async function upsertNotificationPref(
  input: UpsertNotificationPrefInput
): Promise<void> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) return;

  const existing = await db
    .select()
    .from(engagementNotificationPrefs)
    .where(
      and(
        eq(engagementNotificationPrefs.engagementId, input.engagementId),
        eq(engagementNotificationPrefs.eventType, input.eventType)
      )
    )
    .limit(1);

  if (existing.length > 0) {
    await db
      .update(engagementNotificationPrefs)
      .set({
        channel: input.channel,
        enabled: input.channel === "none" ? 0 : 1,
        createdBy: input.createdBy ?? existing[0].createdBy,
      })
      .where(eq(engagementNotificationPrefs.id, existing[0].id));
  } else {
    await db.insert(engagementNotificationPrefs).values({
      engagementId: input.engagementId,
      eventType: input.eventType,
      channel: input.channel,
      enabled: input.channel === "none" ? 0 : 1,
      createdBy: input.createdBy ?? null,
    });
  }
}

/**
 * Bulk upsert notification preferences for an engagement.
 * Useful for the settings UI where all prefs are saved at once.
 */
export async function bulkUpsertNotificationPrefs(
  engagementId: number,
  prefs: Array<{ eventType: NotificationEventType; channel: NotificationChannel }>,
  createdBy?: string
): Promise<void> {
  for (const pref of prefs) {
    await upsertNotificationPref({
      engagementId,
      eventType: pref.eventType,
      channel: pref.channel,
      createdBy,
    });
  }
}

/**
 * Get raw preference rows for an engagement (for admin/debug views).
 */
export async function getRawNotificationPrefs(
  engagementId: number
): Promise<NotificationPref[]> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) return [];

  const rows = await db
    .select()
    .from(engagementNotificationPrefs)
    .where(eq(engagementNotificationPrefs.engagementId, engagementId));

  return rows as unknown as NotificationPref[];
}
