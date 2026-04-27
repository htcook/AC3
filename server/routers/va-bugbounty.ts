/**
 * VA & Bug Bounty tRPC Router
 * 
 * Endpoints for:
 * - Verification profiles (list, get)
 * - VA pipeline configuration
 * - Bug bounty policy parsing and scope checking
 * - License-tier gating checks
 * - Finding normalization batch processing
 * - Live engagement normalization pipeline
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
  normalizeNucleiFinding,
  normalizeZapFinding,
  deduplicateFindings,
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
  
  // ─── Live Engagement Normalization Pipeline ────────────────────────────────
  
  /**
   * Normalize all findings from a live engagement's ops state.
   * Pulls vulns + zapFindings from each asset, runs them through the
   * finding-normalization layer (batchNormalize), and returns a unified
   * NormalizedFinding[] with dedup, corroboration tiers, and stats.
   */
  normalizeEngagementFindings: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator.js');

      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new Error(`No ops state found for engagement ${input.engagementId}`);

      // Collect raw findings from all assets in the engagement
      const nucleiRaw: any[] = [];
      const zapRaw: any[] = [];
      const otherRaw: any[] = [];

      for (const asset of (state.assets || [])) {
        // Vulns from Nuclei (or other scanners stored in vulns[])
        for (const v of (asset.vulns || [])) {
          if (v.source === 'nuclei' || v.nucleiTemplateId || v.templateId) {
            nucleiRaw.push({
              templateId: v.nucleiTemplateId || v.templateId || v.id || 'unknown',
              info: {
                name: v.title,
                severity: v.severity || 'info',
                description: v.description || v.title,
                classification: {
                  cveId: v.cve ? [v.cve] : [],
                  cweId: v.cweId ? [v.cweId] : (v.cwe ? [v.cwe] : []),
                },
                tags: v.tags || [],
              },
              host: asset.hostname || asset.ip || 'unknown',
              ip: asset.ip,
              port: v.port?.toString(),
              matchedAt: v.url || `${asset.hostname}:${v.port || 443}`,
              timestamp: v.timestamp || Date.now(),
              extractorResults: v.evidence ? [{ name: 'evidence', values: [v.evidence] }] : [],
            });
          } else {
            otherRaw.push({ ...v, hostname: asset.hostname, ip: asset.ip });
          }
        }

        // ZAP findings
        for (const zf of (asset.zapFindings || [])) {
          zapRaw.push({
            alert: zf.alert,
            risk: zf.risk || 'Informational',
            confidence: zf.confidence || 'Medium',
            url: zf.url || `https://${asset.hostname}`,
            description: zf.description || zf.alert,
            solution: zf.solution || '',
            reference: zf.reference || '',
            cweid: zf.cweId?.toString() || zf.cweid?.toString() || '',
            wascid: zf.wascid || '',
            evidence: zf.evidence || '',
            param: zf.param || '',
            attack: zf.attack || '',
            method: zf.method || 'GET',
          });
        }
      }

      // Run through normalization pipeline
      const result = batchNormalize({
        nucleiFindings: nucleiRaw.length > 0 ? nucleiRaw : undefined,
        zapFindings: zapRaw.length > 0 ? zapRaw : undefined,
      });

      // Also normalize "other" scanner vulns that don't fit nuclei/zap format
      const otherCount = otherRaw.length;

      return {
        ...result,
        otherScannerFindings: otherCount,
        engagementId: input.engagementId,
        totalAssetsAnalyzed: (state.assets || []).length,
      };
    }),
  
  // ─── Bug Bounty Policy ────────────────────────────────────────────────────
  
  /**
   * Parse a bug bounty program URL into a PolicyROE skeleton.
   * Used by the BugBountyWorkspace to parse program pages.
   */
  parseBugBountyPolicy: protectedProcedure
    .input(z.object({ programUrl: z.string() }))
    .mutation(({ input }) => {
      const parsed = parseProgramUrl(input.programUrl);
      if (!parsed) {
        throw new Error('Could not parse program URL. Supported platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack');
      }
      const skeleton = createSkeletonPolicy({
        ...parsed,
        programUrl: input.programUrl,
      });
      return skeleton;
    }),

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

  // ─── Engagement-to-BugBounty Bridge ───────────────────────────────────────

  /**
   * List normalized findings from an engagement that can be used in the
   * Bug Bounty Workspace. Returns findings enriched with engagement context
   * so they can be selected, documented, and formatted for submission.
   */
  listEngagementFindingsForBounty: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator.js');

      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new Error(`No ops state found for engagement ${input.engagementId}`);

      // Collect raw findings
      const nucleiRaw: any[] = [];
      const zapRaw: any[] = [];

      for (const asset of (state.assets || [])) {
        for (const v of (asset.vulns || [])) {
          if (v.source === 'nuclei' || v.nucleiTemplateId || v.templateId) {
            nucleiRaw.push({
              templateId: v.nucleiTemplateId || v.templateId || v.id || 'unknown',
              info: {
                name: v.title,
                severity: v.severity || 'info',
                description: v.description || v.title,
                classification: {
                  cveId: v.cve ? [v.cve] : [],
                  cweId: v.cweId ? [v.cweId] : (v.cwe ? [v.cwe] : []),
                },
                tags: v.tags || [],
              },
              host: asset.hostname || asset.ip || 'unknown',
              ip: asset.ip,
              port: v.port?.toString(),
              matchedAt: v.url || `${asset.hostname}:${v.port || 443}`,
              timestamp: v.timestamp || Date.now(),
              extractorResults: v.evidence ? [{ name: 'evidence', values: [v.evidence] }] : [],
            });
          }
        }
        for (const zf of (asset.zapFindings || [])) {
          zapRaw.push({
            alert: zf.alert,
            risk: zf.risk || 'Informational',
            confidence: zf.confidence || 'Medium',
            url: zf.url || `https://${asset.hostname}`,
            description: zf.description || zf.alert,
            solution: zf.solution || '',
            reference: zf.reference || '',
            cweid: zf.cweId?.toString() || zf.cweid?.toString() || '',
            wascid: zf.wascid || '',
            evidence: zf.evidence || '',
            param: zf.param || '',
            attack: zf.attack || '',
            method: zf.method || 'GET',
          });
        }
      }

      const result = batchNormalize({
        nucleiFindings: nucleiRaw.length > 0 ? nucleiRaw : undefined,
        zapFindings: zapRaw.length > 0 ? zapRaw : undefined,
      });

      // Convert normalized findings to BugBountyFinding-compatible format
      const bountyFindings = result.findings.map((nf: any) => ({
        id: nf.findingId || nf.fingerprint,
        title: nf.title,
        severity: nf.severity,
        vulnClass: nf.vulnClass || 'unknown',
        target: nf.affectedAsset?.hostname || 'unknown',
        description: nf.description || '',
        cveIds: nf.cveIds || [],
        cweIds: nf.cweIds || [],
        corroborationTier: nf.corroborationTier,
        sourceCount: nf.sources?.length || 1,
        detectionConfidence: nf.detectionConfidence,
        evidence: nf.evidence || [],
        // Pre-fill BugBountyFinding fields
        reproductionSteps: [],
        prerequisites: [],
        impactAnalysis: {
          technicalImpact: nf.description || '',
          businessImpact: '',
          affectedUsers: 'unknown',
          dataAtRisk: [],
        },
        originalityIndicators: {
          isNovelChain: false,
          uniqueEndpoint: false,
          requiresSpecificConditions: false,
          bypassesExistingFix: false,
        },
      }));

      return {
        findings: bountyFindings,
        engagementId: input.engagementId,
        totalAssets: (state.assets || []).length,
        stats: result.stats,
      };
    }),
});
