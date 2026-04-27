/**
 * VA & Bug Bounty tRPC Router
 * 
 * Endpoints for:
 * - Verification profiles (list, get)
 * - VA pipeline configuration
 * - Bug bounty policy parsing and scope checking
 * - License-tier gating checks
 * - Finding normalization batch processing
 * - Cross-training data
 */

import { z } from 'zod';
import { router, protectedProcedure } from '../_core/trpc.js';
import {
  VERIFICATION_PROFILES,
  listVerificationProfiles,
  getVerificationProfile,
  buildVAPipelineConfig,
  prioritizeFindings,
  buildVAReportData,
  type VAPipelineConfig,
} from '../lib/verification-profile.js';
import {
  batchNormalize,
  type NormalizedFinding,
} from '../lib/finding-normalization.js';
import {
  parseProgramUrl,
  createSkeletonPolicy,
  checkScope,
  batchCheckScope,
  formatSubmission,
  checkOriginality,
  type PolicyROE,
  type BugBountyFinding,
  type KnownIssue,
} from '../lib/bug-bounty-policy-parser.js';
import {
  checkEngagementTypeAllowed,
  checkConcurrentEngagementLimit,
  checkFeatureAvailable,
  getAvailableEngagementTypes,
  getTierComparison,
  TIER_CONFIGS,
  ENGAGEMENT_TYPE_INFO,
  type LicenseTier,
  type EngagementType,
} from '../lib/license-tier-gating.js';
import {
  PatternRepository,
  CalibrationPipeline,
  ToolEffectivenessTracker,
  getReproductionGuidelines,
  processCrossTrainingBatch,
  type OutcomeLogEntry,
} from '../lib/cross-training.js';

// In-memory stores (would be persisted to DB in production)
const patternRepo = new PatternRepository();
const calibrationPipeline = new CalibrationPipeline();
const toolTracker = new ToolEffectivenessTracker();

export const vaBugBountyRouter = router({
  // ─── Verification Profiles ─────────────────────────────────────────────────
  
  listVerificationProfiles: protectedProcedure
    .query(() => {
      return listVerificationProfiles();
    }),
  
  getVerificationProfile: protectedProcedure
    .input(z.object({ profileId: z.string() }))
    .query(({ input }) => {
      const profile = getVerificationProfile(input.profileId);
      if (!profile) throw new Error(`Profile not found: ${input.profileId}`);
      return profile;
    }),
  
  buildVAPipelineConfig: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      profileId: z.string(),
      targets: z.array(z.string()),
      selectedFrameworks: z.array(z.string()).optional(),
    }))
    .mutation(({ input }) => {
      return buildVAPipelineConfig(input);
    }),
  
  // ─── Finding Normalization ─────────────────────────────────────────────────
  
  batchNormalizeFindings: protectedProcedure
    .input(z.object({
      nucleiFindings: z.array(z.any()).optional(),
      zapFindings: z.array(z.any()).optional(),
      burpFindings: z.array(z.any()).optional(),
      trivyFindings: z.array(z.any()).optional(),
    }))
    .mutation(({ input }) => {
      return batchNormalize(input);
    }),
  
  prioritizeFindings: protectedProcedure
    .input(z.object({
      findings: z.array(z.any()),
      profileId: z.string(),
    }))
    .mutation(({ input }) => {
      const profile = getVerificationProfile(input.profileId) || VERIFICATION_PROFILES['standard-va'];
      return prioritizeFindings(input.findings as NormalizedFinding[], profile);
    }),
  
  buildVAReport: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      profileId: z.string(),
      findings: z.array(z.any()),
      scannerCoverage: z.object({
        scannersUsed: z.array(z.string()),
        totalTargets: z.number(),
        totalAssetsDiscovered: z.number(),
        scanDurationMinutes: z.number(),
      }),
      selectedFrameworks: z.array(z.string()),
    }))
    .mutation(({ input }) => {
      const profile = getVerificationProfile(input.profileId) || VERIFICATION_PROFILES['standard-va'];
      const prioritized = prioritizeFindings(input.findings as NormalizedFinding[], profile);
      return buildVAReportData({
        engagementId: input.engagementId,
        profileId: input.profileId,
        findings: prioritized,
        scannerCoverage: input.scannerCoverage,
        selectedFrameworks: input.selectedFrameworks,
      });
    }),
  
  // ─── Bug Bounty Policy ────────────────────────────────────────────────────
  
  parseProgramUrl: protectedProcedure
    .input(z.object({ url: z.string() }))
    .mutation(({ input }) => {
      const parsed = parseProgramUrl(input.url);
      if (!parsed) {
        return { success: false as const, error: 'Could not parse program URL. Supported platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack' };
      }
      const skeleton = createSkeletonPolicy({
        ...parsed,
        programUrl: input.url,
      });
      return { success: true as const, policy: skeleton };
    }),
  
  checkScope: protectedProcedure
    .input(z.object({
      target: z.string(),
      policy: z.any(), // PolicyROE
    }))
    .query(({ input }) => {
      return checkScope(input.target, input.policy as PolicyROE);
    }),
  
  batchCheckScope: protectedProcedure
    .input(z.object({
      targets: z.array(z.string()),
      policy: z.any(), // PolicyROE
    }))
    .mutation(({ input }) => {
      const results = batchCheckScope(input.targets, input.policy as PolicyROE);
      return Object.fromEntries(results);
    }),
  
  formatSubmission: protectedProcedure
    .input(z.object({
      finding: z.any(), // BugBountyFinding
      platform: z.enum(['hackerone', 'bugcrowd', 'intigriti', 'synack', 'yeswehack', 'custom']),
    }))
    .mutation(({ input }) => {
      return formatSubmission(input.finding as BugBountyFinding, input.platform);
    }),
  
  checkOriginality: protectedProcedure
    .input(z.object({
      finding: z.any(), // BugBountyFinding
      knownIssues: z.array(z.any()).optional(),
      previousFindings: z.array(z.any()).optional(),
    }))
    .mutation(({ input }) => {
      return checkOriginality(
        input.finding as BugBountyFinding,
        (input.knownIssues || []) as KnownIssue[],
        (input.previousFindings || []) as BugBountyFinding[]
      );
    }),
  
  getReproductionGuidelines: protectedProcedure
    .input(z.object({ vulnClass: z.string() }))
    .query(({ input }) => {
      return getReproductionGuidelines(input.vulnClass);
    }),
  
  // ─── License-Tier Gating ──────────────────────────────────────────────────
  
  checkEngagementTypeAllowed: protectedProcedure
    .input(z.object({
      engagementType: z.enum(['vulnerability_assessment', 'bug_bounty', 'phishing', 'tabletop', 'pentest', 'purple_team', 'red_team']),
      currentTier: z.enum(['standard', 'professional', 'enterprise']),
    }))
    .query(({ input }) => {
      return checkEngagementTypeAllowed(input.engagementType, input.currentTier);
    }),
  
  getAvailableEngagementTypes: protectedProcedure
    .input(z.object({
      currentTier: z.enum(['standard', 'professional', 'enterprise']),
    }))
    .query(({ input }) => {
      return getAvailableEngagementTypes(input.currentTier);
    }),
  
  getTierComparison: protectedProcedure
    .query(() => {
      return getTierComparison();
    }),
  
  getEngagementTypeInfo: protectedProcedure
    .query(() => {
      return Object.values(ENGAGEMENT_TYPE_INFO);
    }),
  
  checkFeatureAvailable: protectedProcedure
    .input(z.object({
      featureId: z.string(),
      currentTier: z.enum(['standard', 'professional', 'enterprise']),
    }))
    .query(({ input }) => {
      return checkFeatureAvailable(input.featureId, input.currentTier);
    }),
  
  // ─── Cross-Training ───────────────────────────────────────────────────────
  
  processCrossTrainingBatch: protectedProcedure
    .input(z.object({
      outcomes: z.array(z.any()),
    }))
    .mutation(({ input }) => {
      return processCrossTrainingBatch(
        input.outcomes as OutcomeLogEntry[],
        patternRepo,
        calibrationPipeline,
        toolTracker
      );
    }),
  
  getPatternRepositoryStats: protectedProcedure
    .query(() => {
      return patternRepo.getStats();
    }),
  
  getHighConfidencePatterns: protectedProcedure
    .input(z.object({ minConfidence: z.number().optional() }))
    .query(({ input }) => {
      return patternRepo.getHighConfidencePatterns(input.minConfidence);
    }),
  
  getScannerCalibration: protectedProcedure
    .input(z.object({ scanner: z.string() }))
    .query(({ input }) => {
      return calibrationPipeline.getScannerCalibration(input.scanner);
    }),
  
  getToolEffectivenessSummary: protectedProcedure
    .query(() => {
      return toolTracker.getEffectivenessSummary();
    }),
});
