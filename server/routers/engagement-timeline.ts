/**
 * Engagement Timeline Router
 * 
 * Exposes the unified kill chain timeline to the frontend with
 * filtering, stats, and engagement-level summaries.
 */

import { z } from 'zod';
import { router, protectedProcedure, publicProcedure } from '../_core/trpc';
import {
  getEngagementTimeline,
  getEngagementSummary,
  type KillChainPhase,
  type EventSource,
  type EventSeverity,
} from '../lib/engagement-timeline';
import { getDb } from '../db';
import { engagements } from '../../drizzle/schema';
import { desc, eq } from 'drizzle-orm';

const killChainPhaseEnum = z.enum([
  'reconnaissance',
  'weaponization',
  'delivery',
  'exploitation',
  'installation',
  'command_control',
  'actions_on_objectives',
]);

const eventSourceEnum = z.enum([
  'domain_recon',
  'domain_intel_scan',
  'phishing_draft',
  'gophish_campaign',
  'typosquat_domain',
  'exploit_job',
  'caldera_operation',
  'caldera_agent',
  'activity_log',
  'engagement_pipeline',
]);

const eventSeverityEnum = z.enum(['info', 'low', 'medium', 'high', 'critical']);

export const engagementTimelineRouter = router({
  // Get the unified timeline with filtering
  getTimeline: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      phases: z.array(killChainPhaseEnum).optional(),
      sources: z.array(eventSourceEnum).optional(),
      severity: z.array(eventSeverityEnum).optional(),
      startDate: z.number().optional(),
      endDate: z.number().optional(),
      targetDomain: z.string().optional(),
      limit: z.number().min(1).max(1000).optional(),
      offset: z.number().min(0).optional(),
    }).optional())
    .query(async ({ input }) => {
      const filter = input || {};
      return getEngagementTimeline({
        engagementId: filter.engagementId,
        phases: filter.phases as KillChainPhase[] | undefined,
        sources: filter.sources as EventSource[] | undefined,
        severity: filter.severity as EventSeverity[] | undefined,
        startDate: filter.startDate,
        endDate: filter.endDate,
        targetDomain: filter.targetDomain,
        limit: filter.limit,
        offset: filter.offset,
      });
    }),

  // Get engagement-level summary with kill chain progress
  getEngagementSummary: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return getEngagementSummary(input.engagementId);
    }),

  // List all engagements with their timeline stats (for the overview page)
  listEngagementsWithStats: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(50).optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];

      const limit = input?.limit || 20;
      const engs = await db.select().from(engagements)
        .orderBy(desc(engagements.updatedAt))
        .limit(limit);

      // Get timeline stats for each engagement in parallel
      const results = await Promise.all(
        engs.map(async (eng) => {
          const { stats } = await getEngagementTimeline({
            engagementId: eng.id,
            limit: 500,
          });
          // Also check domain-based events
          let domainStats = null;
          if (eng.targetDomain) {
            const domainResult = await getEngagementTimeline({
              targetDomain: eng.targetDomain,
              limit: 500,
            });
            domainStats = domainResult.stats;
          }

          return {
            engagement: {
              id: eng.id,
              name: eng.name,
              customerName: eng.customerName,
              type: eng.engagementType,
              status: eng.status,
              targetDomain: eng.targetDomain,
              startDate: eng.startDate ? new Date(eng.startDate).getTime() : null,
              endDate: eng.endDate ? new Date(eng.endDate).getTime() : null,
              calderaOperationId: eng.calderaOperationId,
              gophishCampaignId: eng.gophishCampaignId,
              updatedAt: new Date(eng.updatedAt).getTime(),
            },
            stats: {
              totalEvents: stats.totalEvents + (domainStats?.totalEvents || 0),
              phasesReached: Array.from(new Set([...stats.phasesReached, ...(domainStats?.phasesReached || [])])),
              furthestPhase: getFurthestPhase(stats.phasesReached, domainStats?.phasesReached || []),
              byPhase: mergePhaseStats(stats.byPhase, domainStats?.byPhase),
            },
          };
        })
      );

      return results;
    }),

  // Get global timeline stats (across all engagements)
  getGlobalStats: protectedProcedure.query(async () => {
    const { stats } = await getEngagementTimeline({ limit: 1000 });
    return stats;
  }),
});

// Helper to determine the furthest kill chain phase reached
function getFurthestPhase(phases1: string[], phases2: string[]): string | null {
  const order = [
    'reconnaissance',
    'weaponization',
    'delivery',
    'exploitation',
    'installation',
    'command_control',
    'actions_on_objectives',
  ];
  const allPhases = Array.from(new Set([...phases1, ...phases2]));
  let furthest: string | null = null;
  for (const phase of order) {
    if (allPhases.includes(phase)) furthest = phase;
  }
  return furthest;
}

// Helper to merge phase stats from engagement-based and domain-based queries
function mergePhaseStats(
  stats1: Record<string, number>,
  stats2?: Record<string, number> | null
): Record<string, number> {
  if (!stats2) return stats1;
  const merged: Record<string, number> = { ...stats1 };
  for (const [key, val] of Object.entries(stats2)) {
    merged[key] = (merged[key] || 0) + val;
  }
  return merged;
}
