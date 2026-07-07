/**
 * Notification Preferences Router
 * 
 * Allows operators to configure per-engagement notification routing:
 * which events trigger email, in-app, both, or no notification.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  getNotificationPrefs,
  upsertNotificationPref,
  bulkUpsertNotificationPrefs,
  getRawNotificationPrefs,
  NOTIFICATION_EVENT_TYPES,
  NOTIFICATION_CHANNELS,
  type NotificationEventType,
  type NotificationChannel,
} from "../lib/notification-preferences";

const eventTypeSchema = z.enum(NOTIFICATION_EVENT_TYPES as unknown as [string, ...string[]]);
const channelSchema = z.enum(NOTIFICATION_CHANNELS as unknown as [string, ...string[]]);

export const notificationPreferencesRouter = router({
  /**
   * Get merged notification preferences for an engagement.
   * Returns defaults for any event types without explicit prefs.
   */
  getPrefs: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const prefs = await getNotificationPrefs(input.engagementId);
      return {
        engagementId: input.engagementId,
        preferences: prefs,
        eventTypes: NOTIFICATION_EVENT_TYPES,
        channels: NOTIFICATION_CHANNELS,
      };
    }),

  /**
   * Get raw preference rows (for admin/debug views).
   */
  getRawPrefs: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return getRawNotificationPrefs(input.engagementId);
    }),

  /**
   * Update a single notification preference.
   */
  updatePref: protectedProcedure
    .input(
      z.object({
        engagementId: z.number(),
        eventType: eventTypeSchema,
        channel: channelSchema,
      })
    )
    .mutation(async ({ input, ctx }) => {
      await upsertNotificationPref({
        engagementId: input.engagementId,
        eventType: input.eventType as NotificationEventType,
        channel: input.channel as NotificationChannel,
        createdBy: ctx.user?.email ?? ctx.user?.name ?? undefined,
      });
      return { success: true };
    }),

  /**
   * Bulk update all notification preferences for an engagement.
   * Used by the settings UI to save all prefs at once.
   */
  bulkUpdatePrefs: protectedProcedure
    .input(
      z.object({
        engagementId: z.number(),
        preferences: z.array(
          z.object({
            eventType: eventTypeSchema,
            channel: channelSchema,
          })
        ),
      })
    )
    .mutation(async ({ input, ctx }) => {
      await bulkUpsertNotificationPrefs(
        input.engagementId,
        input.preferences.map((p) => ({
          eventType: p.eventType as NotificationEventType,
          channel: p.channel as NotificationChannel,
        })),
        ctx.user?.email ?? ctx.user?.name ?? undefined
      );
      return { success: true, count: input.preferences.length };
    }),
});
