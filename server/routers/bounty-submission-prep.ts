/**
 * Bounty Submission Prep Router
 * 
 * tRPC procedures for the Submission Prep UI panel:
 * - Get hypotheses for an engagement (from post-recon generation)
 * - Generate optimized submissions from hypotheses or findings
 * - Edit/refine submissions before filing
 * - Export submissions in HackerOne/Bugcrowd format
 * - Record rejection feedback into the negative example pipeline
 * - Get calibration drift status
 */

import { z } from 'zod';
import { router, protectedProcedure } from '../_core/trpc';
import { TRPCError } from '@trpc/server';

export const bountySubmissionPrepRouter = router({
  /** Get hypothesis results for an engagement (generated during post-recon phase) */
  getHypotheses: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) return { available: false as const, hypotheses: [], summary: null, reconQuality: null };

      const results = (state.metadata as any)?.hypothesisResults;
      if (!results) return { available: false as const, hypotheses: [], summary: null, reconQuality: null };

      return {
        available: true as const,
        hypotheses: results.hypotheses || [],
        summary: results.summary || null,
        reconQuality: results.reconQuality || null,
        generatedAt: results.generatedAt,
      };
    }),

  /** Regenerate hypotheses for an engagement (manual trigger) */
  regenerateHypotheses: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });
      if (state.assets.length === 0) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No assets discovered yet' });

      const { runHypothesisGeneration } = await import('../lib/hypothesis-orchestrator-hook');
      const result = runHypothesisGeneration(state);
      return result;
    }),

  /** Generate an optimized submission from a hypothesis */
  generateSubmission: protectedProcedure
    .input(z.object({
      hypothesisId: z.string(),
      engagementId: z.number(),
      platform: z.enum(['hackerone', 'bugcrowd', 'intigriti', 'other']).default('hackerone'),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });

      const hypothesisResults = (state.metadata as any)?.hypothesisResults;
      if (!hypothesisResults?.hypotheses) throw new TRPCError({ code: 'NOT_FOUND', message: 'No hypotheses generated' });

      const hypothesis = hypothesisResults.hypotheses.find((h: any) => h.id === input.hypothesisId);
      if (!hypothesis) throw new TRPCError({ code: 'NOT_FOUND', message: `Hypothesis ${input.hypothesisId} not found` });

      const { optimizeSubmission } = await import('../lib/bounty-submission-optimizer');

      const findingInput = {
        vulnClass: hypothesis.vulnClass,
        title: hypothesis.title,
        description: hypothesis.description,
        affectedEndpoint: hypothesis.affectedEndpoint,
        severity: hypothesis.potentialSeverity || 'medium',
        cweId: hypothesis.tags?.find((t: string) => t.startsWith('CWE-')),
        technology: hypothesis.tags?.find((t: string) => !t.startsWith('CWE-')),
        programHandle: hypothesisResults.programHandle,
        platform: input.platform,
        reproductionEvidence: hypothesis.verificationSteps?.map((step: any) => ({
          type: 'code' as const,
          content: step.action,
          description: step.expectedOutcome,
        })),
        impactDescription: hypothesis.reasoning?.join('. '),
      };

      const submission = optimizeSubmission(findingInput);
      return {
        submission,
        hypothesis: {
          id: hypothesis.id,
          title: hypothesis.title,
          confidence: hypothesis.confidence,
          confidenceScore: hypothesis.confidenceScore,
        },
      };
    }),

  /** Generate submissions for all high-confidence hypotheses in batch */
  batchGenerateSubmissions: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      minConfidence: z.enum(['high', 'medium', 'low', 'speculative']).default('medium'),
      platform: z.enum(['hackerone', 'bugcrowd', 'intigriti', 'other']).default('hackerone'),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });

      const hypothesisResults = (state.metadata as any)?.hypothesisResults;
      if (!hypothesisResults?.hypotheses) throw new TRPCError({ code: 'NOT_FOUND', message: 'No hypotheses generated' });

      const confidenceOrder = ['high', 'medium', 'low', 'speculative'];
      const minIdx = confidenceOrder.indexOf(input.minConfidence);
      const eligible = hypothesisResults.hypotheses.filter((h: any) =>
        confidenceOrder.indexOf(h.confidence) <= minIdx
      );

      const { batchOptimizeSubmissions } = await import('../lib/bounty-submission-optimizer');

      const findingInputs = eligible.map((h: any) => ({
        vulnClass: h.vulnClass,
        title: h.title,
        description: h.description,
        affectedEndpoint: h.affectedEndpoint,
        severity: h.potentialSeverity || 'medium',
        cweId: h.tags?.find((t: string) => t.startsWith('CWE-')),
        programHandle: hypothesisResults.programHandle,
        platform: input.platform,
        impactDescription: h.reasoning?.join('. '),
      }));

      const submissions = batchOptimizeSubmissions(findingInputs);
      return {
        submissions: submissions.map((s: any, i: number) => ({
          submission: s,
          hypothesis: {
            id: eligible[i].id,
            title: eligible[i].title,
            confidence: eligible[i].confidence,
            confidenceScore: eligible[i].confidenceScore,
            vulnClass: eligible[i].vulnClass,
          },
        })),
        total: submissions.length,
        avgQualityScore: submissions.reduce((sum: number, s: any) => sum + s.qualityScore, 0) / Math.max(submissions.length, 1),
      };
    }),

  /** Record a submission rejection (feeds into negative example pipeline) */
  recordRejection: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      hypothesisId: z.string().optional(),
      vulnClass: z.string(),
      title: z.string(),
      affectedEndpoint: z.string(),
      severity: z.string(),
      rejectionReason: z.enum([
        'false_positive', 'duplicate', 'out_of_scope', 'informational_only',
        'not_reproducible', 'intended_behavior', 'insufficient_impact',
        'known_issue', 'wont_fix', 'spam', 'invalid_vulnerability', 'already_patched',
      ]),
      rejectionDetail: z.string(),
      programHandle: z.string().optional(),
      triagerFeedback: z.string().optional(),
      lessonsLearned: z.array(z.string()).default([]),
    }))
    .mutation(async ({ input }) => {
      const { feedbackLoop } = await import('../lib/negative-example-feedback-loop');
      const { confidenceCalibrationEngine } = await import('../lib/bounty-confidence-calibration');
      const { crossTrainingBus } = await import('../lib/cross-training-event-bus');
      const { negativeExampleRepo } = await import('../lib/bounty-negative-examples');

      const example = {
        id: `neg-${input.engagementId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        vulnClass: input.vulnClass,
        title: input.title,
        affectedEndpoint: input.affectedEndpoint,
        severity: input.severity,
        rejectionReason: input.rejectionReason,
        rejectionDetail: input.rejectionDetail,
        programHandle: input.programHandle,
        submittedAt: new Date().toISOString(),
        rejectedAt: new Date().toISOString(),
        triagerFeedback: input.triagerFeedback,
        lessonsLearned: input.lessonsLearned.length > 0
          ? input.lessonsLearned
          : [`${input.rejectionReason}: ${input.rejectionDetail}`],
        tags: [input.vulnClass, input.rejectionReason],
      };

      // Add to negative example repository
      negativeExampleRepo.addExample(example);

      // Process through feedback loop (calibration + event bus)
      const result = feedbackLoop.processRejection(example, confidenceCalibrationEngine, crossTrainingBus);

      return {
        processed: result.processed,
        calibrationUpdated: result.calibrationUpdated,
        eventPublished: result.eventPublished,
        driftDetected: result.driftDetected,
        driftReport: result.driftReport || null,
      };
    }),

  /** Get calibration drift status */
  getCalibrationStatus: protectedProcedure
    .query(async () => {
      const { confidenceCalibrationEngine } = await import('../lib/bounty-confidence-calibration');
      const { feedbackLoop } = await import('../lib/negative-example-feedback-loop');
      const { negativeExampleRepo } = await import('../lib/bounty-negative-examples');

      const drift = confidenceCalibrationEngine.detectDrift();
      const feedbackStats = feedbackLoop.getStats();
      const negativeStats = negativeExampleRepo.getStats();
      const patterns = negativeExampleRepo.analyzePatterns();

      return {
        drift,
        feedbackStats,
        negativeStats,
        topPatterns: patterns.slice(0, 5),
      };
    }),

  /** Get scan priority adjustments from hypotheses */
  getScanPriorities: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) return { priorities: [] };

      const priorities = (state.metadata as any)?.hypothesisScanPriorities || [];
      return { priorities };
    }),

  /** Export a submission in platform-specific format (markdown for copy-paste) */
  exportSubmission: protectedProcedure
    .input(z.object({
      title: z.string(),
      severity: z.string(),
      severityJustification: z.string(),
      summary: z.string(),
      impactStatement: z.string(),
      reproductionSteps: z.array(z.object({
        stepNumber: z.number(),
        action: z.string(),
        expectedResult: z.string(),
        evidence: z.string().optional(),
      })),
      technicalDetails: z.string(),
      remediation: z.string(),
      references: z.array(z.string()),
      cweId: z.string(),
      cvssVector: z.string().optional(),
      cvssScore: z.number().optional(),
      platform: z.enum(['hackerone', 'bugcrowd', 'intigriti', 'other']).default('hackerone'),
    }))
    .mutation(async ({ input }) => {
      const lines: string[] = [];

      if (input.platform === 'hackerone') {
        lines.push(`## Summary`);
        lines.push(input.summary);
        lines.push('');
        lines.push(`## Severity`);
        lines.push(`**${input.severity.toUpperCase()}** — ${input.severityJustification}`);
        if (input.cvssVector) lines.push(`CVSS: ${input.cvssVector} (${input.cvssScore})`);
        lines.push('');
        lines.push(`## Impact`);
        lines.push(input.impactStatement);
        lines.push('');
        lines.push(`## Steps to Reproduce`);
        for (const step of input.reproductionSteps) {
          lines.push(`${step.stepNumber}. ${step.action}`);
          lines.push(`   Expected: ${step.expectedResult}`);
          if (step.evidence) lines.push(`   Evidence: ${step.evidence}`);
        }
        lines.push('');
        lines.push(`## Technical Details`);
        lines.push(input.technicalDetails);
        lines.push('');
        lines.push(`## Remediation`);
        lines.push(input.remediation);
        lines.push('');
        lines.push(`## Weakness`);
        lines.push(input.cweId);
        if (input.references.length > 0) {
          lines.push('');
          lines.push(`## References`);
          for (const ref of input.references) {
            lines.push(`- ${ref}`);
          }
        }
      } else if (input.platform === 'bugcrowd') {
        lines.push(`# ${input.title}`);
        lines.push('');
        lines.push(`**Priority:** ${input.severity.toUpperCase()}`);
        lines.push(`**CWE:** ${input.cweId}`);
        if (input.cvssVector) lines.push(`**CVSS:** ${input.cvssVector} (${input.cvssScore})`);
        lines.push('');
        lines.push(`## Description`);
        lines.push(input.summary);
        lines.push('');
        lines.push(`## Proof of Concept`);
        for (const step of input.reproductionSteps) {
          lines.push(`${step.stepNumber}. ${step.action}`);
          if (step.evidence) lines.push(`   \`${step.evidence}\``);
        }
        lines.push('');
        lines.push(`## Impact`);
        lines.push(input.impactStatement);
        lines.push('');
        lines.push(`## Remediation`);
        lines.push(input.remediation);
      } else {
        lines.push(`# ${input.title}`);
        lines.push('');
        lines.push(`**Severity:** ${input.severity} | **CWE:** ${input.cweId}`);
        lines.push('');
        lines.push(input.summary);
        lines.push('');
        lines.push(`## Steps to Reproduce`);
        for (const step of input.reproductionSteps) {
          lines.push(`${step.stepNumber}. ${step.action} → ${step.expectedResult}`);
        }
        lines.push('');
        lines.push(`## Impact`);
        lines.push(input.impactStatement);
        lines.push('');
        lines.push(`## Fix`);
        lines.push(input.remediation);
      }

      return {
        markdown: lines.join('\n'),
        platform: input.platform,
        characterCount: lines.join('\n').length,
      };
    }),
});
