/**
 * Threat Intelligence Matching Router
 * 
 * Exposes the threat group matching engine to the frontend.
 * Provides endpoints for:
 *   - Matching engagement findings to threat groups
 *   - Getting threat group profiles with attack history
 *   - FedRAMP SaaS provider correlation
 *   - Engagement fingerprint extraction
 */

import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import {
  matchThreatGroups,
  getThreatGroupProfile,
  getFedRAMPProviders,
  getFedRAMPProviderCount,
  extractEngagementFingerprint,
} from "../lib/threat-group-matcher";
import { getThreatGroupSummary } from "../lib/threat-group-knowledge";

export const threatIntelMatchingRouter = router({
  // ── Match threat groups to engagement findings ──────────────────────────
  matchGroups: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      minScore: z.number().min(0).max(100).optional(),
      maxResults: z.number().min(1).max(50).optional(),
    }))
    .query(async ({ input }) => {
      const result = await matchThreatGroups(input.engagementId, {
        minScore: input.minScore,
        maxResults: input.maxResults,
      });

      // Serialize for transport (strip heavy nested data for list view)
      return {
        fingerprint: result.fingerprint,
        totalGroupsAnalyzed: result.totalGroupsAnalyzed,
        matchTimestamp: result.matchTimestamp,
        matches: result.matches.map(m => ({
          groupId: m.group.id,
          groupName: m.group.name,
          groupType: m.group.type,
          origin: m.group.origin,
          threatLevel: m.group.threatLevel,
          active: m.group.active,
          aliases: m.group.aliases.slice(0, 3),
          matchScore: m.matchScore,
          riskLevel: m.riskLevel,
          matchSummary: m.matchSummary,
          sectorRelevance: m.sectorRelevance,
          matchedTechniqueCount: m.matchedTechniques.length,
          matchedCVECount: m.matchedCVEs.length,
          matchedToolCount: m.matchedTools.length,
          matchedTacticCount: m.matchedTactics.length,
          fedrampExposureCount: m.fedrampExposure.length,
          topMatchedTechniques: m.matchedTechniques.slice(0, 5),
          topMatchedCVEs: m.matchedCVEs.slice(0, 5),
          targetSectors: m.group.targetSectors.slice(0, 5),
        })),
      };
    }),

  // ── Get detailed threat group profile ───────────────────────────────────
  groupProfile: protectedProcedure
    .input(z.object({
      groupId: z.string(),
      engagementSectors: z.array(z.string()).optional(),
    }))
    .query(async ({ input }) => {
      const profile = await getThreatGroupProfile(input.groupId, input.engagementSectors);
      if (!profile) return null;

      return {
        group: {
          id: profile.group.id,
          name: profile.group.name,
          aliases: profile.group.aliases,
          type: profile.group.type,
          origin: profile.group.origin,
          threatLevel: profile.group.threatLevel,
          active: profile.group.active,
          description: profile.group.description,
          motivation: profile.group.motivation,
          targetSectors: profile.group.targetSectors,
          targetRegions: profile.group.targetRegions,
          initialAccessMethods: profile.group.initialAccessMethods,
          defenseRecommendations: profile.group.defenseRecommendations,
          detectionHints: profile.group.detectionHints,
          exploitedCVEs: profile.group.exploitedCVEs,
          mitreGroupId: profile.group.mitreGroupId,
          ttps: profile.group.ttps,
          tools: profile.group.tools,
        },
        attackHistory: profile.attackHistory,
        iocs: profile.iocs,
        abilities: profile.abilities,
        fedrampExposure: profile.fedrampExposure,
        relatedGroups: profile.relatedGroups,
      };
    }),

  // ── Get engagement fingerprint ──────────────────────────────────────────
  fingerprint: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      return extractEngagementFingerprint(input.engagementId);
    }),

  // ── FedRAMP provider catalog ────────────────────────────────────────────
  fedrampProviders: protectedProcedure
    .input(z.object({
      sector: z.string().optional(),
      impactLevel: z.string().optional(),
      serviceModel: z.string().optional(),
      category: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const providers = getFedRAMPProviders(input);
      return {
        providers,
        totalCount: getFedRAMPProviderCount(),
      };
    }),

  // ── Threat group summary stats ──────────────────────────────────────────
  summary: protectedProcedure.query(async () => {
    const summary = getThreatGroupSummary();
    return {
      ...summary,
      totalTechniques: summary.totalTTPs,
      fedrampProviderCount: getFedRAMPProviderCount(),
    };
  }),
});
