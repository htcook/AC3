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
import crypto from 'crypto';
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
   * Parse a bug bounty program URL into a PolicyROE skeleton,
   * then enrich it with live structured scopes from the HackerOne API.
   * Returns a frontend-compatible PolicyROE with populated scope data.
   */
  parseBugBountyPolicy: protectedProcedure
    .input(z.object({ programUrl: z.string(), autoCreateEngagement: z.boolean().optional() }))
    .mutation(async ({ ctx, input }) => {
      const parsed = parseProgramUrl(input.programUrl);
      if (!parsed) {
        // Unknown platform — try LLM-based parsing for any URL
        const { parseUnknownProgramUrl, autoCreateEngagement } = await import('../lib/auto-engagement-creator.js');
        const customResult = await parseUnknownProgramUrl(input.programUrl);
        if (!customResult || customResult.scope.inScope.length === 0) {
          throw new Error('Could not parse program URL. Supported platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack, OpenBugBounty, or any page with identifiable scope data.');
        }
        // Auto-create engagement if sufficient data (default: true)
        let autoEngagement = undefined;
        if (input.autoCreateEngagement !== false) {
          autoEngagement = await autoCreateEngagement(customResult, ctx.user.id, customResult.parseConfidence || 0.6);
        }
        return { ...customResult, autoEngagement };
      }

      // Check cache first (6-hour TTL)
      const cacheKey = `${parsed.platform}:${parsed.programSlug}`;
      const cached = await getPolicyCacheEntry(cacheKey);
      if (cached) {
        // Auto-create engagement from cached result if requested
        let autoEngagement = undefined;
        if (input.autoCreateEngagement !== false) {
          try {
            const { autoCreateEngagement } = await import('../lib/auto-engagement-creator.js');
            autoEngagement = await autoCreateEngagement(cached, ctx.user.id, 0.7);
          } catch (err: any) {
            console.warn(`[BB Workspace] Auto-engagement creation failed (cached):`, err.message);
          }
        }
        return { ...cached, autoEngagement };
      }

      const skeleton = createSkeletonPolicy({
        ...parsed,
        programUrl: input.programUrl,
      });

      // For HackerOne programs, fetch live structured scopes
      if (parsed.platform === 'hackerone') {
        try {
          const creds = await resolveH1CredentialsForBBWorkspace(ctx.user.id);
          if (creds) {
            // Fetch structured scopes (up to 3 pages)
            const inScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }> = [];
            const outOfScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }> = [];

            for (let page = 1; page <= 3; page++) {
              const scopePath = `/programs/${encodeURIComponent(parsed.programSlug)}/structured_scopes?page[number]=${page}&page[size]=25`;
              const scopeData = await h1FetchForBBWorkspace(scopePath, creds.username, creds.token);
              if (!scopeData?.data?.length) break;

              for (const item of scopeData.data) {
                const attrs = item.attributes || {};
                const assetType = mapH1AssetType(attrs.asset_type);
                const entry = {
                  type: assetType,
                  value: attrs.asset_identifier || 'unknown',
                  eligible: !!attrs.eligible_for_bounty,
                  notes: attrs.instruction || (attrs.max_severity ? `Max severity: ${attrs.max_severity}` : undefined),
                };

                if (attrs.eligible_for_submission !== false) {
                  inScope.push(entry);
                } else {
                  outOfScope.push(entry);
                }
              }
            }

            // Also try to fetch program info for name and bounty data
            try {
              const programPath = `/programs/${encodeURIComponent(parsed.programSlug)}`;
              const programData = await h1FetchForBBWorkspace(programPath, creds.username, creds.token);
              if (programData?.attributes) {
                const pAttrs = programData.attributes;
                skeleton.programName = pAttrs.name || pAttrs.handle || parsed.programSlug;
              }
            } catch {
              // Program info fetch is optional, skeleton name is fine
            }

            // Populate the skeleton scope
            skeleton.scope.inScope = inScope.map(s => ({
              type: s.type as any,
              target: s.value,
              instruction: s.notes,
              bountyEligible: s.eligible,
            }));
            skeleton.scope.outOfScope = outOfScope.map(s => ({
              type: s.type as any,
              target: s.value,
              instruction: s.notes,
              bountyEligible: false,
            }));

            // Detect wildcard domains
            skeleton.scope.wildcardDomains = inScope
              .filter(s => s.value.startsWith('*.'))
              .map(s => s.value);

            skeleton.parseConfidence = 0.8; // High confidence with live API data
          }
        } catch (err: any) {
          // If API fetch fails, return skeleton with error note
          console.warn(`[BB Workspace] Failed to fetch H1 scopes for ${parsed.programSlug}:`, err.message);
          skeleton.parseConfidence = 0.3;
        }
      }

      // For Bugcrowd programs, fetch scope from bounty-targets-data
      if (parsed.platform === 'bugcrowd') {
        try {
          const bcData = await fetchBountyTargetsData('bugcrowd');
          if (bcData) {
            const program = findBugcrowdProgram(bcData, parsed.programSlug, input.programUrl);
            if (program) {
              skeleton.programName = program.name || parsed.programSlug;
              if (program.targets?.in_scope) {
                skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                  type: mapBugcrowdAssetType(t.type),
                  target: t.target || t.name || t.uri || 'unknown',
                  instruction: t.name && t.name !== t.target ? t.name : undefined,
                  bountyEligible: true,
                }));
              }
              if (program.targets?.out_of_scope) {
                skeleton.scope.outOfScope = program.targets.out_of_scope.map((t: any) => ({
                  type: mapBugcrowdAssetType(t.type),
                  target: t.target || t.name || t.uri || 'unknown',
                  instruction: t.name && t.name !== t.target ? t.name : undefined,
                  bountyEligible: false,
                }));
              }
              skeleton.scope.wildcardDomains = skeleton.scope.inScope
                .filter(s => s.target.startsWith('*.'))
                .map(s => s.target);
              if (program.max_payout) {
                skeleton.bounty.hasBounty = true;
                skeleton.bounty.ranges = [{ severity: 'critical', minBounty: 0, maxBounty: program.max_payout }];
              }
              if (program.safe_harbor) {
                skeleton.rules.safeHarborStatement = `Safe harbor: ${program.safe_harbor}`;
              }
              skeleton.parseConfidence = 0.75;
            }
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Failed to fetch Bugcrowd scopes for ${parsed.programSlug}:`, err.message);
          skeleton.parseConfidence = 0.3;
        }
      }

      // For Intigriti programs, fetch scope from bounty-targets-data
      if (parsed.platform === 'intigriti') {
        try {
          const igData = await fetchBountyTargetsData('intigriti');
          if (igData) {
            const program = findIntigritiProgram(igData, parsed.programSlug, input.programUrl);
            if (program) {
              skeleton.programName = program.name || parsed.programSlug;
              if (program.targets?.in_scope) {
                skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                  type: mapIntigritiAssetType(t.type),
                  target: t.endpoint || 'unknown',
                  instruction: t.description || undefined,
                  bountyEligible: t.impact !== 'Out of scope' && t.impact !== 'No Bounty',
                }));
              }
              if (program.targets?.out_of_scope) {
                skeleton.scope.outOfScope = program.targets.out_of_scope.map((t: any) => ({
                  type: mapIntigritiAssetType(t.type),
                  target: t.endpoint || 'unknown',
                  instruction: t.description || undefined,
                  bountyEligible: false,
                }));
              }
              skeleton.scope.wildcardDomains = skeleton.scope.inScope
                .filter(s => s.target.startsWith('*.'))
                .map(s => s.target);
              if (program.min_bounty || program.max_bounty) {
                skeleton.bounty.hasBounty = true;
                skeleton.bounty.ranges = [{
                  severity: 'critical',
                  minBounty: program.min_bounty?.value || 0,
                  maxBounty: program.max_bounty?.value || 0,
                }];
                skeleton.bounty.currency = program.max_bounty?.currency || 'USD';
              }
              skeleton.parseConfidence = 0.75;
            }
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Failed to fetch Intigriti scopes for ${parsed.programSlug}:`, err.message);
          skeleton.parseConfidence = 0.3;
        }
      }

      // For YesWeHack programs, fetch scope from bounty-targets-data
      if (parsed.platform === 'yeswehack') {
        try {
          const ywhData = await fetchBountyTargetsData('yeswehack');
          if (ywhData) {
            const program = findYesWeHackProgram(ywhData, parsed.programSlug, input.programUrl);
            if (program) {
              skeleton.programName = program.title || parsed.programSlug;
              if (program.targets?.in_scope) {
                skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                  type: mapBugcrowdAssetType(t.type), // similar format
                  target: t.target || 'unknown',
                  instruction: undefined,
                  bountyEligible: true,
                }));
              }
              if (program.targets?.out_of_scope) {
                skeleton.scope.outOfScope = program.targets.out_of_scope.map((t: any) => ({
                  type: mapBugcrowdAssetType(t.type),
                  target: t.target || 'unknown',
                  instruction: undefined,
                  bountyEligible: false,
                }));
              }
              skeleton.scope.wildcardDomains = skeleton.scope.inScope
                .filter(s => s.target.startsWith('*.'))
                .map(s => s.target);
              if (program.min_bounty || program.max_bounty) {
                skeleton.bounty.hasBounty = true;
                skeleton.bounty.ranges = [{
                  severity: 'critical',
                  minBounty: program.min_bounty || 0,
                  maxBounty: program.max_bounty || 0,
                }];
              }
              skeleton.parseConfidence = 0.75;
            }
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Failed to fetch YesWeHack scopes for ${parsed.programSlug}:`, err.message);
          skeleton.parseConfidence = 0.3;
        }
      }

      // For OpenBugBounty programs, scope is the domain itself
      if (parsed.platform === 'openbugbounty') {
        try {
          // The slug IS the program owner, and the domain is typically their website
          // OpenBugBounty programs are domain-based
          const obbDomain = await fetchOpenBugBountyDomain(parsed.programSlug);
          if (obbDomain) {
            skeleton.programName = `${parsed.programSlug} (OpenBugBounty)`;
            skeleton.scope.inScope = [{
              type: 'domain',
              target: obbDomain,
              instruction: 'OpenBugBounty program — only XSS, CSRF, and other web vulnerabilities accepted',
              bountyEligible: false, // OBB is typically non-bounty
            }];
            skeleton.scope.wildcardDomains = [`*.${obbDomain}`];
            skeleton.rules.prohibitedActions = [
              'No automated scanning without permission',
              'No denial of service testing',
              'Report only XSS, CSRF, open redirect, and similar web vulnerabilities',
            ];
            skeleton.parseConfidence = 0.6;
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Failed to fetch OBB data for ${parsed.programSlug}:`, err.message);
          skeleton.parseConfidence = 0.3;
        }
      }

      // Build frontend-compatible result
      const result = {
        programName: skeleton.programName,
        platform: skeleton.platform,
        programUrl: skeleton.programUrl,
        scope: {
          inScope: skeleton.scope.inScope.map(s => ({
            type: s.type,
            value: s.target,
            eligible: s.bountyEligible,
            notes: s.instruction,
          })),
          outOfScope: skeleton.scope.outOfScope.map(s => ({
            type: s.type,
            value: s.target,
            eligible: false,
            notes: s.instruction,
          })),
        },
        rules: [
          ...skeleton.rules.prohibitedActions,
          skeleton.rules.disclosurePolicy !== 'none' ? `Disclosure: ${skeleton.rules.disclosurePolicy}` : null,
          skeleton.rules.requiresVPN ? 'VPN required' : null,
          skeleton.rules.requiresAccountCreation ? 'Account creation required' : null,
          skeleton.rules.testingHoursRestriction ? `Testing hours: ${skeleton.rules.testingHoursRestriction}` : null,
        ].filter(Boolean) as string[],
        rewardRange: skeleton.bounty.hasBounty && skeleton.bounty.ranges.length > 0 ? {
          low: Math.min(...skeleton.bounty.ranges.map(r => r.minBounty)),
          high: Math.max(...skeleton.bounty.ranges.map(r => r.maxBounty)),
          currency: skeleton.bounty.currency === 'USD' ? '$' : skeleton.bounty.currency,
        } : undefined,
        safeHarbor: !!skeleton.rules.safeHarborStatement,
        responseTimeSla: skeleton.responseExpectations.firstResponseDays ? {
          firstResponse: `${skeleton.responseExpectations.firstResponseDays}d`,
          triage: skeleton.responseExpectations.triageDays ? `${skeleton.responseExpectations.triageDays}d` : 'N/A',
          bountyDecision: skeleton.responseExpectations.bountyPaymentDays ? `${skeleton.responseExpectations.bountyPaymentDays}d` : 'N/A',
        } : undefined,
        parsedAt: new Date(skeleton.parsedAt).toISOString(),
      };

      // Cache the result (6-hour TTL)
      await setPolicyCacheEntry(cacheKey, parsed.platform, parsed.programSlug, input.programUrl, result);

      // Auto-create engagement if sufficient data (default: true for known platforms)
      let autoEngagement = undefined;
      if (input.autoCreateEngagement !== false && skeleton.parseConfidence >= 0.5) {
        try {
          const { autoCreateEngagement } = await import('../lib/auto-engagement-creator.js');
          autoEngagement = await autoCreateEngagement(result, ctx.user.id, skeleton.parseConfidence);
        } catch (err: any) {
          console.warn(`[BB Workspace] Auto-engagement creation failed for ${result.programName}:`, err.message);
          // Non-fatal: parsing still succeeds without auto-engagement
        }
      }

      return { ...result, autoEngagement };
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

  // ─── Active Engagements Listing (for dropdowns) ───────────────────────────

  /**
   * List active engagements with basic info for dropdown selectors.
   * Used by the Bug Bounty Import tab and Triage Queue to browse engagements
   * instead of requiring users to type IDs manually.
   */
  listActiveEngagements: protectedProcedure
    .query(async ({ ctx }) => {
      try {
        const db = await import('../db.js');
        const engagements = await db.getEngagements(ctx.user);
        // Return a simplified list suitable for dropdown selectors
        return (engagements || []).map((e: any) => ({
          id: e.id,
          name: e.name || e.clientName || `Engagement #${e.id}`,
          clientName: e.clientName || '',
          engagementType: e.engagementType || 'pentest',
          status: e.status || 'active',
          targetDomain: e.targetDomain || '',
          createdAt: e.createdAt,
        })).filter((e: any) => e.status !== 'archived');
      } catch {
        return [];
      }
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

  // ─── Refresh Scope (Cache Invalidation) ──────────────────────────────────

  /**
   * Invalidate the cached policy for a program URL and re-fetch fresh scope data.
   * This is the backend for the "Refresh Scope" button in the BB Workspace.
   */
  refreshBugBountyPolicy: protectedProcedure
    .input(z.object({ programUrl: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const parsed = parseProgramUrl(input.programUrl);
      if (!parsed) {
        throw new Error('Could not parse program URL');
      }

      // Invalidate the cache entry
      const cacheKey = `${parsed.platform}:${parsed.programSlug}`;
      await deletePolicyCacheEntry(cacheKey);
      console.log(`[BB Workspace] Cache invalidated for ${cacheKey}, re-fetching...`);

      // Re-run the full parse (which will now skip cache and fetch fresh data)
      // We reuse the parseBugBountyPolicy logic by calling the same flow
      const skeleton = createSkeletonPolicy({
        ...parsed,
        programUrl: input.programUrl,
      });

      // HackerOne
      if (parsed.platform === 'hackerone') {
        try {
          const creds = await resolveH1CredentialsForBBWorkspace(ctx.user.id);
          if (creds) {
            const inScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }> = [];
            const outOfScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }> = [];
            for (let page = 1; page <= 3; page++) {
              const scopePath = `/programs/${encodeURIComponent(parsed.programSlug)}/structured_scopes?page[number]=${page}&page[size]=25`;
              const scopeData = await h1FetchForBBWorkspace(scopePath, creds.username, creds.token);
              if (!scopeData?.data?.length) break;
              for (const item of scopeData.data) {
                const attrs = item.attributes || {};
                const entry = {
                  type: mapH1AssetType(attrs.asset_type),
                  value: attrs.asset_identifier || 'unknown',
                  eligible: !!attrs.eligible_for_bounty,
                  notes: attrs.instruction || (attrs.max_severity ? `Max severity: ${attrs.max_severity}` : undefined),
                };
                if (attrs.eligible_for_submission !== false) inScope.push(entry);
                else outOfScope.push(entry);
              }
            }
            skeleton.scope.inScope = inScope.map(s => ({ type: s.type as any, target: s.value, instruction: s.notes, bountyEligible: s.eligible }));
            skeleton.scope.outOfScope = outOfScope.map(s => ({ type: s.type as any, target: s.value, instruction: s.notes, bountyEligible: false }));
            skeleton.scope.wildcardDomains = inScope.filter(s => s.value.startsWith('*.')).map(s => s.value);
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Refresh H1 fetch failed:`, err.message);
        }
      }

      // Bugcrowd
      if (parsed.platform === 'bugcrowd') {
        try {
          // Force fresh fetch by clearing the in-memory bounty-targets cache
          bountyTargetsCache.bugcrowd = null;
          bountyTargetsCacheTimestamp.bugcrowd = 0;
          const bcData = await fetchBountyTargetsData('bugcrowd');
          if (bcData) {
            const program = findBugcrowdProgram(bcData, parsed.programSlug, input.programUrl);
            if (program) {
              skeleton.programName = program.name || parsed.programSlug;
              if (program.targets?.in_scope) {
                skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                  type: mapBugcrowdAssetType(t.type), target: t.target || 'unknown',
                  instruction: t.name || undefined, bountyEligible: true,
                }));
              }
              if (program.targets?.out_of_scope) {
                skeleton.scope.outOfScope = program.targets.out_of_scope.map((t: any) => ({
                  type: mapBugcrowdAssetType(t.type), target: t.target || 'unknown',
                  instruction: t.name || undefined, bountyEligible: false,
                }));
              }
              if (program.max_payout) {
                skeleton.bounty.hasBounty = true;
                skeleton.bounty.ranges = [{ severity: 'critical', minBounty: 0, maxBounty: program.max_payout }];
              }
            }
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Refresh Bugcrowd fetch failed:`, err.message);
        }
      }

      // Intigriti
      if (parsed.platform === 'intigriti') {
        try {
          bountyTargetsCache.intigriti = null;
          bountyTargetsCacheTimestamp.intigriti = 0;
          const igData = await fetchBountyTargetsData('intigriti');
          if (igData) {
            const program = findIntigritiProgram(igData, parsed.programSlug, input.programUrl);
            if (program) {
              skeleton.programName = program.name || parsed.programSlug;
              if (program.targets?.in_scope) {
                skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                  type: mapIntigritiAssetType(t.type), target: t.endpoint || 'unknown',
                  instruction: t.description || undefined, bountyEligible: t.impact !== 'Out of scope' && t.impact !== 'No Bounty',
                }));
              }
              if (program.targets?.out_of_scope) {
                skeleton.scope.outOfScope = program.targets.out_of_scope.map((t: any) => ({
                  type: mapIntigritiAssetType(t.type), target: t.endpoint || 'unknown',
                  instruction: t.description || undefined, bountyEligible: false,
                }));
              }
              if (program.min_bounty || program.max_bounty) {
                skeleton.bounty.hasBounty = true;
                skeleton.bounty.ranges = [{ severity: 'critical', minBounty: program.min_bounty?.value || 0, maxBounty: program.max_bounty?.value || 0 }];
                skeleton.bounty.currency = program.max_bounty?.currency || 'USD';
              }
            }
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Refresh Intigriti fetch failed:`, err.message);
        }
      }

      // YesWeHack
      if (parsed.platform === 'yeswehack') {
        try {
          bountyTargetsCache.yeswehack = null;
          bountyTargetsCacheTimestamp.yeswehack = 0;
          const ywhData = await fetchBountyTargetsData('yeswehack');
          if (ywhData) {
            const program = findYesWeHackProgram(ywhData, parsed.programSlug);
            if (program) {
              skeleton.programName = program.title || program.name || parsed.programSlug;
              if (program.targets?.in_scope) {
                skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                  type: mapBugcrowdAssetType(t.type), target: t.target || 'unknown',
                  instruction: t.scope || undefined, bountyEligible: true,
                }));
              }
            }
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Refresh YWH fetch failed:`, err.message);
        }
      }

      // OpenBugBounty
      if (parsed.platform === 'openbugbounty') {
        try {
          const obbDomain = await fetchOpenBugBountyDomain(parsed.programSlug);
          if (obbDomain) {
            skeleton.programName = `${parsed.programSlug} (OpenBugBounty)`;
            skeleton.scope.inScope = [{ type: 'domain', target: obbDomain, instruction: 'OpenBugBounty — XSS/CSRF only', bountyEligible: false }];
          }
        } catch (err: any) {
          console.warn(`[BB Workspace] Refresh OBB fetch failed:`, err.message);
        }
      }

      // Build result and cache it
      const result = {
        programName: skeleton.programName,
        platform: skeleton.platform,
        programUrl: skeleton.programUrl,
        scope: {
          inScope: skeleton.scope.inScope.map(s => ({ type: s.type, value: s.target, eligible: s.bountyEligible, notes: s.instruction })),
          outOfScope: skeleton.scope.outOfScope.map(s => ({ type: s.type, value: s.target, eligible: false, notes: s.instruction })),
        },
        rules: [
          ...skeleton.rules.prohibitedActions,
          skeleton.rules.disclosurePolicy !== 'none' ? `Disclosure: ${skeleton.rules.disclosurePolicy}` : null,
          skeleton.rules.requiresVPN ? 'VPN required' : null,
          skeleton.rules.requiresAccountCreation ? 'Account creation required' : null,
          skeleton.rules.testingHoursRestriction ? `Testing hours: ${skeleton.rules.testingHoursRestriction}` : null,
        ].filter(Boolean) as string[],
        rewardRange: skeleton.bounty.hasBounty && skeleton.bounty.ranges.length > 0 ? {
          low: Math.min(...skeleton.bounty.ranges.map(r => r.minBounty)),
          high: Math.max(...skeleton.bounty.ranges.map(r => r.maxBounty)),
          currency: skeleton.bounty.currency === 'USD' ? '$' : skeleton.bounty.currency,
        } : undefined,
        safeHarbor: !!skeleton.rules.safeHarborStatement,
        responseTimeSla: skeleton.responseExpectations.firstResponseDays ? {
          firstResponse: `${skeleton.responseExpectations.firstResponseDays}d`,
          triage: skeleton.responseExpectations.triageDays ? `${skeleton.responseExpectations.triageDays}d` : 'N/A',
          bountyDecision: skeleton.responseExpectations.bountyPaymentDays ? `${skeleton.responseExpectations.bountyPaymentDays}d` : 'N/A',
        } : undefined,
        parsedAt: new Date().toISOString(),
      };

      await setPolicyCacheEntry(cacheKey, parsed.platform, parsed.programSlug, input.programUrl, result);
      return result;
    }),

  // ─── Create Engagement from Parsed Scope ─────────────────────────────────

  /**
   * Create a new engagement directly from parsed scope data.
   * Used when "Sync to Engagement" is clicked but no engagement exists.
   * Calls the auto-engagement creator with all in-scope assets (including
   * source code assets that need build-out requirements).
   */
  createEngagementFromScope: protectedProcedure
    .input(z.object({
      programName: z.string(),
      programUrl: z.string(),
      platform: z.string(),
      inScopeTargets: z.array(z.object({
        type: z.string(),
        value: z.string(),
        eligible: z.boolean().optional(),
        notes: z.string().optional(),
      })),
      outOfScopeTargets: z.array(z.object({
        type: z.string(),
        value: z.string(),
        eligible: z.boolean().optional(),
        notes: z.string().optional(),
      })).optional(),
      rules: z.array(z.string()).optional(),
      rewardRange: z.object({
        low: z.number(),
        high: z.number(),
        currency: z.string(),
      }).optional(),
      safeHarbor: z.boolean().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const { autoCreateEngagement } = await import('../lib/auto-engagement-creator.js');

      // Build a ParsedPolicyResult from the input
      const policyResult = {
        programName: input.programName,
        platform: input.platform,
        programUrl: input.programUrl,
        scope: {
          inScope: input.inScopeTargets.map(t => ({
            type: t.type,
            value: t.value,
            eligible: t.eligible !== false,
            notes: t.notes,
          })),
          outOfScope: (input.outOfScopeTargets || []).map(t => ({
            type: t.type,
            value: t.value,
            eligible: false,
            notes: t.notes,
          })),
        },
        rules: input.rules || [],
        rewardRange: input.rewardRange,
        safeHarbor: input.safeHarbor ?? false,
        parsedAt: new Date().toISOString(),
        parseConfidence: 0.9, // High confidence since user explicitly triggered
      };

      const result = await autoCreateEngagement(policyResult, ctx.user.id, 0.9);
      return result;
    }),

  // ─── Sync Scope to Engagement Assets ─────────────────────────────────────

  /**
   * Take the parsed in-scope targets from a BB workspace policy and add them
   * as targets to an existing engagement. This bridges the BB workspace
   * to the engagement ops pipeline.
   */
  syncScopeToEngagement: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      inScopeTargets: z.array(z.object({
        type: z.string(),
        value: z.string(),
        eligible: z.boolean().optional(),
        notes: z.string().optional(),
      })),
      programName: z.string().optional(),
      programUrl: z.string().optional(),
      platform: z.string().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await import('../db.js');
      const engagement = await db.getEngagementById(input.engagementId);
      if (!engagement) {
        throw new Error(`Engagement #${input.engagementId} not found`);
      }

      // Extract domains, IPs, and URLs from in-scope targets
      const domains: string[] = [];
      const ips: string[] = [];
      const urls: string[] = [];

      for (const target of input.inScopeTargets) {
        const val = target.value.trim();
        if (!val || val === 'unknown') continue;

        const lowerType = target.type.toLowerCase();

        if (lowerType === 'ip' || lowerType === 'cidr' || /^\d{1,3}(\.\d{1,3}){3}/.test(val)) {
          ips.push(val);
        } else if (lowerType === 'url' || /^https?:\/\//i.test(val)) {
          urls.push(val);
          // Also extract the hostname
          try {
            const hostname = new URL(val.startsWith('http') ? val : `https://${val}`).hostname;
            if (hostname && !domains.includes(hostname)) domains.push(hostname);
          } catch { /* not a valid URL */ }
        } else if (lowerType === 'domain' || lowerType === 'wildcard' || val.includes('.')) {
          // Strip wildcard prefix for domain matching
          const clean = val.replace(/^\*\./, '');
          if (clean && !domains.includes(clean)) domains.push(clean);
          // Also keep the wildcard version if present
          if (val.startsWith('*.') && !domains.includes(val)) domains.push(val);
        } else if (lowerType === 'source_code' || lowerType === 'hardware' || lowerType === 'other') {
          // Non-network targets — skip for engagement asset population
          continue;
        } else {
          // Default: treat as domain
          if (val.includes('.')) domains.push(val);
        }
      }

      // Merge with existing engagement targets
      const existingDomains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
      const existingIps = (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean);
      const allDomains = [...new Set([...existingDomains, ...domains])];
      const allIps = [...new Set([...existingIps, ...ips])];

      // Update the engagement record
      const updates: any = {
        targetDomain: allDomains.join(', '),
        targetIpRange: allIps.join(', '),
      };

      // Also set bug bounty metadata if provided
      if (input.programUrl) updates.bugBountyProgramUrl = input.programUrl;
      if (input.platform) {
        const validPlatforms = ['hackerone', 'bugcrowd', 'intigriti', 'synack', 'yeswehack', 'custom'] as const;
        const plat = input.platform.toLowerCase();
        if (validPlatforms.includes(plat as any)) {
          updates.bugBountyPlatform = plat;
        }
      }

      await db.updateEngagement(input.engagementId, updates);

      // Also update the in-memory ops state if it exists
      try {
        const { getOpsState, getOpsStateWithRecovery, initOpsState } = await import('../lib/engagement-orchestrator.js');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) state = initOpsState(input.engagementId, engagement.engagementType);

        for (const d of allDomains) {
          if (!state.assets.find((a: any) => a.hostname === d)) {
            state.assets.push({ hostname: d, type: 'unknown', ports: [], vulns: [], zapFindings: [], exploitAttempts: [], toolResults: [], status: 'pending' });
          }
        }
        for (const ip of allIps) {
          if (!state.assets.find((a: any) => a.ip === ip || a.hostname === ip)) {
            state.assets.push({ hostname: ip, ip, type: 'unknown', ports: [], vulns: [], zapFindings: [], exploitAttempts: [], toolResults: [], status: 'pending' });
          }
        }
      } catch (err: any) {
        console.warn(`[BB Workspace] Failed to update ops state:`, err.message);
      }

      const newDomains = domains.filter(d => !existingDomains.includes(d));
      const newIps = ips.filter(ip => !existingIps.includes(ip));

      await db.logActivity({
        userId: ctx.user.id,
        action: 'bb_scope_synced',
        details: `Synced ${newDomains.length + newIps.length} new targets from ${input.programName || 'BB program'} to engagement #${input.engagementId}`,
      });

      return {
        engagementId: input.engagementId,
        totalDomainsAdded: newDomains.length,
        totalIpsAdded: newIps.length,
        totalTargets: allDomains.length + allIps.length,
        newDomains,
        newIps,
        skippedTypes: input.inScopeTargets.filter(t => ['source_code', 'hardware', 'other'].includes(t.type.toLowerCase())).length,
      };
    }),

  // ─── Refresh All Scopes (Batch) ─────────────────────────────────────────────

  /**
   * Batch-refresh scopes for multiple programs at once.
   * Accepts an array of program URLs, invalidates their cache entries,
   * and re-fetches fresh scope data for each. Returns per-program results.
   * Useful for engagements that target multiple bug bounty programs.
   */
  refreshAllScopes: protectedProcedure
    .input(z.object({
      programUrls: z.array(z.string()).min(1).max(50),
    }))
    .mutation(async ({ ctx, input }) => {
      const results: Array<{
        programUrl: string;
        status: 'success' | 'error';
        programName?: string;
        platform?: string;
        inScopeCount?: number;
        outOfScopeCount?: number;
        error?: string;
      }> = [];

      // Process each URL sequentially to avoid rate limiting
      for (const programUrl of input.programUrls) {
        try {
          const parsed = parseProgramUrl(programUrl);
          if (!parsed) {
            results.push({ programUrl, status: 'error', error: 'Could not parse URL' });
            continue;
          }

          // Invalidate cache
          const cacheKey = `${parsed.platform}:${parsed.programSlug}`;
          await deletePolicyCacheEntry(cacheKey);

          // Re-fetch by calling the same logic as refreshBugBountyPolicy
          const skeleton = createSkeletonPolicy({ ...parsed, programUrl });

          // Platform-specific fetch
          if (parsed.platform === 'hackerone') {
            try {
              const creds = await resolveH1CredentialsForBBWorkspace(ctx.user.id);
              if (creds) {
                const inScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }> = [];
                const outOfScope: Array<{ type: string; value: string; eligible: boolean; notes?: string }> = [];
                for (let page = 1; page <= 3; page++) {
                  const scopePath = `/programs/${encodeURIComponent(parsed.programSlug)}/structured_scopes?page[number]=${page}&page[size]=25`;
                  const scopeData = await h1FetchForBBWorkspace(scopePath, creds.username, creds.token);
                  if (!scopeData?.data?.length) break;
                  for (const item of scopeData.data) {
                    const attrs = item.attributes || {};
                    const entry = {
                      type: mapH1AssetType(attrs.asset_type),
                      value: attrs.asset_identifier || 'unknown',
                      eligible: !!attrs.eligible_for_bounty,
                      notes: attrs.instruction || (attrs.max_severity ? `Max severity: ${attrs.max_severity}` : undefined),
                    };
                    if (attrs.eligible_for_submission !== false) inScope.push(entry);
                    else outOfScope.push(entry);
                  }
                }
                skeleton.scope.inScope = inScope.map(s => ({ type: s.type as any, target: s.value, instruction: s.notes, bountyEligible: s.eligible }));
                skeleton.scope.outOfScope = outOfScope.map(s => ({ type: s.type as any, target: s.value, instruction: s.notes, bountyEligible: false }));
              }
            } catch (err: any) { console.warn(`[Batch Refresh] H1 error for ${parsed.programSlug}:`, err.message); }
          } else if (parsed.platform === 'bugcrowd') {
            try {
              const bcData = await fetchBountyTargetsData('bugcrowd');
              if (bcData) {
                const program = findBugcrowdProgram(bcData, parsed.programSlug, programUrl);
                if (program) {
                  skeleton.programName = program.name || parsed.programSlug;
                  if (program.targets?.in_scope) {
                    skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                      type: mapBugcrowdAssetType(t.type), target: t.target || 'unknown',
                      instruction: t.name || undefined, bountyEligible: true,
                    }));
                  }
                  if (program.targets?.out_of_scope) {
                    skeleton.scope.outOfScope = program.targets.out_of_scope.map((t: any) => ({
                      type: mapBugcrowdAssetType(t.type), target: t.target || 'unknown',
                      instruction: t.name || undefined, bountyEligible: false,
                    }));
                  }
                }
              }
            } catch (err: any) { console.warn(`[Batch Refresh] Bugcrowd error for ${parsed.programSlug}:`, err.message); }
          } else if (parsed.platform === 'intigriti') {
            try {
              const igData = await fetchBountyTargetsData('intigriti');
              if (igData) {
                const program = findIntigritiProgram(igData, parsed.programSlug, programUrl);
                if (program) {
                  skeleton.programName = program.name || parsed.programSlug;
                  if (program.targets?.in_scope) {
                    skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                      type: mapIntigritiAssetType(t.type), target: t.endpoint || 'unknown',
                      instruction: t.description || undefined, bountyEligible: t.impact !== 'Out of scope' && t.impact !== 'No Bounty',
                    }));
                  }
                  if (program.targets?.out_of_scope) {
                    skeleton.scope.outOfScope = program.targets.out_of_scope.map((t: any) => ({
                      type: mapIntigritiAssetType(t.type), target: t.endpoint || 'unknown',
                      instruction: t.description || undefined, bountyEligible: false,
                    }));
                  }
                }
              }
            } catch (err: any) { console.warn(`[Batch Refresh] Intigriti error for ${parsed.programSlug}:`, err.message); }
          } else if (parsed.platform === 'yeswehack') {
            try {
              const ywhData = await fetchBountyTargetsData('yeswehack');
              if (ywhData) {
                const program = findYesWeHackProgram(ywhData, parsed.programSlug);
                if (program) {
                  skeleton.programName = program.title || program.name || parsed.programSlug;
                  if (program.targets?.in_scope) {
                    skeleton.scope.inScope = program.targets.in_scope.map((t: any) => ({
                      type: mapBugcrowdAssetType(t.type), target: t.target || 'unknown',
                      instruction: t.scope || undefined, bountyEligible: true,
                    }));
                  }
                }
              }
            } catch (err: any) { console.warn(`[Batch Refresh] YWH error for ${parsed.programSlug}:`, err.message); }
          } else if (parsed.platform === 'openbugbounty') {
            try {
              const obbDomain = await fetchOpenBugBountyDomain(parsed.programSlug);
              if (obbDomain) {
                skeleton.programName = `${parsed.programSlug} (OpenBugBounty)`;
                skeleton.scope.inScope = [{ type: 'domain', target: obbDomain, instruction: 'OpenBugBounty — XSS/CSRF only', bountyEligible: false }];
              }
            } catch (err: any) { console.warn(`[Batch Refresh] OBB error for ${parsed.programSlug}:`, err.message); }
          }

          // Build result and cache
          const result = {
            programName: skeleton.programName,
            platform: skeleton.platform,
            programUrl: skeleton.programUrl,
            scope: {
              inScope: skeleton.scope.inScope.map(s => ({ type: s.type, value: s.target, eligible: s.bountyEligible, notes: s.instruction })),
              outOfScope: skeleton.scope.outOfScope.map(s => ({ type: s.type, value: s.target, eligible: false, notes: s.instruction })),
            },
            rules: [
              ...skeleton.rules.prohibitedActions,
              skeleton.rules.disclosurePolicy !== 'none' ? `Disclosure: ${skeleton.rules.disclosurePolicy}` : null,
            ].filter(Boolean) as string[],
            rewardRange: skeleton.bounty.hasBounty && skeleton.bounty.ranges.length > 0 ? {
              low: Math.min(...skeleton.bounty.ranges.map(r => r.minBounty)),
              high: Math.max(...skeleton.bounty.ranges.map(r => r.maxBounty)),
              currency: skeleton.bounty.currency === 'USD' ? '$' : skeleton.bounty.currency,
            } : undefined,
            parsedAt: new Date().toISOString(),
          };

          await setPolicyCacheEntry(cacheKey, parsed.platform, parsed.programSlug, programUrl, result);

          results.push({
            programUrl,
            status: 'success',
            programName: skeleton.programName,
            platform: parsed.platform,
            inScopeCount: skeleton.scope.inScope.length,
            outOfScopeCount: skeleton.scope.outOfScope.length,
          });
        } catch (err: any) {
          results.push({ programUrl, status: 'error', error: err.message });
        }
      }

      const successCount = results.filter(r => r.status === 'success').length;
      const errorCount = results.filter(r => r.status === 'error').length;
      console.log(`[BB Workspace] Batch refresh complete: ${successCount} success, ${errorCount} errors`);

      return {
        total: results.length,
        successCount,
        errorCount,
        results,
      };
    }),
});

// ─── HackerOne API Helpers for Bug Bounty Workspace ─────────────────────────

const H1_BASE = "https://api.hackerone.com/v1/hackers";

const ENCRYPTION_KEY_BB = process.env.JWT_SECRET
  ? crypto.createHash("sha256").update(process.env.JWT_SECRET).digest()
  : crypto.randomBytes(32);

function decryptBB(encryptedText: string): string {
  const [ivHex, authTagHex, encrypted] = encryptedText.split(":");
  if (!ivHex || !authTagHex || !encrypted) throw new Error("Invalid encrypted format");
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY_BB, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

async function h1FetchForBBWorkspace(path: string, username?: string, token?: string) {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (username && token) {
    headers.Authorization = "Basic " + Buffer.from(`${username}:${token}`).toString("base64");
  }
  const res = await fetch(`${H1_BASE}${path}`, { headers, signal: AbortSignal.timeout(15000) });
  if (!res.ok) {
    throw new Error(`HackerOne API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

/**
 * Unified H1 credential resolution — delegates to credential-service.ts
 * which handles: DB per-user lookup → env var fallback.
 * This ensures all BB platform credential fixes apply universally.
 */
async function resolveH1CredentialsForBBWorkspace(userId: number): Promise<{ username: string; token: string } | null> {
  try {
    const { getH1CredentialsForUser } = await import('../lib/credential-service.js');
    const creds = await getH1CredentialsForUser(userId);
    if (creds) {
      return { username: creds.username, token: creds.apiKey };
    }
  } catch (err: any) {
    console.warn('[BBWorkspace] credential-service lookup failed:', err.message);
  }
  // No direct env fallback — credential-service already handles DB → env with validation
  return null;
}

/**
 * Map HackerOne asset_type strings to our ScopeTarget type values.
 */
function mapH1AssetType(h1Type?: string): string {
  if (!h1Type) return 'other';
  const mapping: Record<string, string> = {
    'URL': 'url',
    'CIDR': 'cidr',
    'DOMAIN': 'domain',
    'WILDCARD': 'domain',
    'IP_ADDRESS': 'ip',
    'SOURCE_CODE': 'source_code',
    'MOBILE_APPLICATION': 'mobile_app',
    'DOWNLOADABLE_EXECUTABLES': 'other',
    'HARDWARE': 'other',
    'OTHER': 'other',
    'SMART_CONTRACT': 'other',
    'AI_MODEL': 'other',
    'WINDOWS_APP': 'other',
    'APPLE_STORE_APP_ID': 'mobile_app',
    'GOOGLE_PLAY_APP_ID': 'mobile_app',
    'TESTFLIGHT': 'mobile_app',
    'OTHER_IPA': 'mobile_app',
    'OTHER_APK': 'mobile_app',
  };
  return mapping[h1Type.toUpperCase()] || 'other';
}

// ─── Bounty-Targets-Data Helpers (Bugcrowd, Intigriti, YesWeHack) ─────────

const BOUNTY_TARGETS_BASE = 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data';

// In-memory cache with TTL (1 hour)
const bountyTargetsCache: Record<string, { data: any[]; fetchedAt: number }> = {};
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Fetch platform scope data from the bounty-targets-data GitHub repo.
 * Uses an in-memory cache with 1-hour TTL.
 */
async function fetchBountyTargetsData(platform: 'bugcrowd' | 'intigriti' | 'yeswehack'): Promise<any[] | null> {
  const cacheKey = platform;
  const cached = bountyTargetsCache[cacheKey];
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.data;
  }

  const fileMap: Record<string, string> = {
    bugcrowd: 'bugcrowd_data.json',
    intigriti: 'intigriti_data.json',
    yeswehack: 'yeswehack_data.json',
  };

  const url = `${BOUNTY_TARGETS_BASE}/${fileMap[platform]}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!res.ok) {
    console.warn(`[BB Workspace] Failed to fetch ${platform} data: ${res.status}`);
    return null;
  }

  const data = await res.json() as any[];
  bountyTargetsCache[cacheKey] = { data, fetchedAt: Date.now() };
  return data;
}

/**
 * Find a Bugcrowd program by slug or URL match.
 */
function findBugcrowdProgram(data: any[], slug: string, programUrl: string): any | null {
  const slugLower = slug.toLowerCase();
  const urlLower = programUrl.toLowerCase();

  // Try exact URL match first
  let found = data.find((p: any) => p.url?.toLowerCase() === urlLower);
  if (found) return found;

  // Try slug match in URL
  found = data.find((p: any) => {
    const pUrl = (p.url || '').toLowerCase();
    return pUrl.includes(`/${slugLower}`) || pUrl.endsWith(`/${slugLower}`);
  });
  if (found) return found;

  // Try name match
  found = data.find((p: any) => {
    const pName = (p.name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    return pName === slugLower.replace(/[^a-z0-9]/g, '');
  });
  return found || null;
}

/**
 * Find an Intigriti program by handle or URL match.
 */
function findIntigritiProgram(data: any[], slug: string, programUrl: string): any | null {
  const slugLower = slug.toLowerCase();
  const urlLower = programUrl.toLowerCase();

  // Try exact URL match
  let found = data.find((p: any) => p.url?.toLowerCase() === urlLower);
  if (found) return found;

  // Try handle match
  found = data.find((p: any) =>
    (p.handle || '').toLowerCase() === slugLower ||
    (p.company_handle || '').toLowerCase() === slugLower
  );
  if (found) return found;

  // Try URL contains slug
  found = data.find((p: any) => {
    const pUrl = (p.url || '').toLowerCase();
    return pUrl.includes(`/${slugLower}/`) || pUrl.includes(`/${slugLower}`);
  });
  return found || null;
}

/**
 * Find a YesWeHack program by slug or URL match.
 */
function findYesWeHackProgram(data: any[], slug: string, programUrl: string): any | null {
  const slugLower = slug.toLowerCase();
  const urlLower = programUrl.toLowerCase();

  // Try exact URL match
  let found = data.find((p: any) => p.url?.toLowerCase() === urlLower);
  if (found) return found;

  // Try slug match
  found = data.find((p: any) => {
    const pSlug = (p.slug || '').toLowerCase();
    return pSlug === slugLower;
  });
  if (found) return found;

  // Try title match
  found = data.find((p: any) => {
    const pTitle = (p.title || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    return pTitle === slugLower.replace(/[^a-z0-9]/g, '');
  });
  return found || null;
}

/**
 * Map Bugcrowd asset type strings to our ScopeTarget type values.
 */
function mapBugcrowdAssetType(bcType?: string): string {
  if (!bcType) return 'other';
  const mapping: Record<string, string> = {
    'website': 'url',
    'api': 'url',
    'android': 'mobile_app',
    'ios': 'mobile_app',
    'hardware': 'other',
    'other': 'other',
  };
  return mapping[bcType.toLowerCase()] || 'other';
}

/**
 * Map Intigriti asset type strings to our ScopeTarget type values.
 */
function mapIntigritiAssetType(igType?: string): string {
  if (!igType) return 'other';
  const mapping: Record<string, string> = {
    'url': 'url',
    'domain': 'domain',
    'android': 'mobile_app',
    'ios': 'mobile_app',
    'iprange': 'cidr',
    'device': 'other',
    'other': 'other',
  };
  return mapping[igType.toLowerCase()] || 'other';
}

// ─── OpenBugBounty Helpers ─────────────────────────────────────────────────

/**
 * Fetch domain info from OpenBugBounty.
 * The slug is the program name, and we extract the domain from the OBB page.
 */
async function fetchOpenBugBountyDomain(slug: string): Promise<string | null> {
  // OpenBugBounty slugs are typically the domain name itself
  // e.g., https://openbugbounty.org/bugbounty/example.com/
  // The slug IS the domain
  if (slug.includes('.')) {
    return slug;
  }

  // If it's not a domain, try fetching the OBB page
  try {
    const res = await fetch(`https://www.openbugbounty.org/bugbounty/${encodeURIComponent(slug)}/`, {
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'CalderaDashboard/1.0' },
    });
    if (!res.ok) return null;

    const html = await res.text();
    // Try to extract domain from the page content
    const domainMatch = html.match(/<title>.*?Bug Bounty.*?(?:for|of)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    if (domainMatch) return domainMatch[1];

    // Fallback: the slug might be the domain
    return slug;
  } catch {
    return slug; // Best effort: assume slug is the domain
  }
}

// ─── Policy Cache Helpers ─────────────────────────────────────────────────

const POLICY_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

/**
 * Get a cached parsed policy result from the database.
 * Returns null if not found or expired.
 */
async function getPolicyCacheEntry(cacheKey: string): Promise<any | null> {
  try {
    const { getDb: _getDb } = await import('../db.js');
    const { parsedPolicyCache } = await import('../../drizzle/schema.js');
    const { eq, gt } = await import('drizzle-orm');
    const db = await _getDb();
    if (!db) return null;

    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const [entry] = await db
      .select()
      .from(parsedPolicyCache)
      .where(
        eq(parsedPolicyCache.cacheKey, cacheKey)
      )
      .limit(1);

    if (!entry) return null;

    // Check if expired
    const expiresAt = new Date(entry.expiresAt).getTime();
    if (Date.now() > expiresAt) {
      // Expired, delete and return null
      await db.delete(parsedPolicyCache).where(eq(parsedPolicyCache.cacheKey, cacheKey));
      return null;
    }

    console.log(`[BB Workspace] Cache hit for ${cacheKey}`);
    return entry.parsedResult;
  } catch (err: any) {
    console.warn(`[BB Workspace] Cache read error:`, err.message);
    return null;
  }
}

/**
 * Store a parsed policy result in the database cache.
 */
async function setPolicyCacheEntry(
  cacheKey: string,
  platform: string,
  programSlug: string,
  programUrl: string,
  result: any
): Promise<void> {
  try {
    const { getDb: _getDb } = await import('../db.js');
    const { parsedPolicyCache } = await import('../../drizzle/schema.js');
    const { eq } = await import('drizzle-orm');
    const db = await _getDb();
    if (!db) return;

    const expiresAt = new Date(Date.now() + POLICY_CACHE_TTL_MS).toISOString().slice(0, 19).replace('T', ' ');

    // Upsert: delete old entry if exists, then insert
    await db.delete(parsedPolicyCache).where(eq(parsedPolicyCache.cacheKey, cacheKey));
    await db.insert(parsedPolicyCache).values({
      cacheKey,
      platform,
      programSlug,
      programUrl,
      parsedResult: result,
      expiresAt,
    });

    console.log(`[BB Workspace] Cached policy for ${cacheKey} (expires: ${expiresAt})`);
  } catch (err: any) {
    console.warn(`[BB Workspace] Cache write error:`, err.message);
    // Non-fatal: parsing still works without cache
  }
}


/**
 * Delete a cached policy entry (used by refresh flow).
 */
async function deletePolicyCacheEntry(cacheKey: string): Promise<void> {
  try {
    const { getDb: _getDb } = await import('../db.js');
    const { parsedPolicyCache } = await import('../../drizzle/schema.js');
    const { eq } = await import('drizzle-orm');
    const db = await _getDb();
    if (!db) return;

    await db.delete(parsedPolicyCache).where(eq(parsedPolicyCache.cacheKey, cacheKey));
    console.log(`[BB Workspace] Cache entry deleted for ${cacheKey}`);
  } catch (err: any) {
    console.warn(`[BB Workspace] Cache delete error:`, err.message);
  }
}
