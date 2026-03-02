import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { and, eq, max, min, not, or, sql } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const validationRouter = router({
    /** Get validation candidates for a scan (preview before running) */
    getCandidates: protectedProcedure
      .input(z.object({ scanId: z.number(), maxCandidates: z.number().default(10) }))
      .query(async ({ input }) => {
        const { discoveredAssets, unifiedExploitCatalog } = await import('../../drizzle/schema');
        const { getDbRequired } = await import('../db');
        const { eq } = await import('drizzle-orm');
        const { selectCandidates } = await import('../lib/validation-engine');
        const dbConn = await getDbRequired();

        const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
        const catalog = await dbConn.select({
          catalogId: unifiedExploitCatalog.catalogId,
          msfModule: unifiedExploitCatalog.msfModule,
          msfRank: unifiedExploitCatalog.msfRank,
          cveIds: unifiedExploitCatalog.cveIds,
          cvssScore: unifiedExploitCatalog.cvssScore,
          source: unifiedExploitCatalog.source,
        }).from(unifiedExploitCatalog).where(eq(unifiedExploitCatalog.enabled, true));

        const candidates = selectCandidates(assets as any, catalog as any, input.maxCandidates);
        return { candidates, totalAssets: assets.length, totalCatalogEntries: catalog.length };
      }),

    /** Start a validation run */
    startRun: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        msfServerId: z.number(),
        mode: z.enum(['check_only', 'auxiliary_scan', 'safe_exploit']).default('check_only'),
        maxCandidates: z.number().min(1).max(50).default(10),
        timeoutPerCandidate: z.number().min(10).max(300).default(60),
        requireApproval: z.boolean().default(true),
        scopeRestrictions: z.array(z.string()).default([]),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { validationRuns, validationResults: vResults, discoveredAssets, unifiedExploitCatalog, metasploitServers } = await import('../../drizzle/schema');
        const { getDbRequired } = await import('../db');
        const { eq } = await import('drizzle-orm');
        const { selectCandidates, validateCandidate, computeAssetValidationScore } = await import('../lib/validation-engine');
        const { MsfClient } = await import('../lib/msf-client');
        const { enforceROE, getEngagementROE, logOffensiveAction, ACTION_RISK_MAP } = await import('../lib/roe-guard');
        const dbConn = await getDbRequired();

        // ─── ROE Enforcement ───
        const riskTier = input.mode === 'safe_exploit' ? 'red' as const : 'orange' as const;
        if (input.engagementId) {
          const roe = await getEngagementROE(input.engagementId);
          if (roe) enforceROE(roe, riskTier, `Validation run (${input.mode}) on scan #${input.scanId}`);
        }
        // Log the offensive action
        logOffensiveAction({
          engagementId: input.engagementId ?? null,
          operatorId: ctx.user.openId,
          operatorName: ctx.user.name ?? null,
          actionType: input.mode === 'safe_exploit' ? 'msf_exploit' : input.mode === 'auxiliary_scan' ? 'msf_auxiliary' : 'msf_check',
          riskTier,
          target: `scan:${input.scanId}`,
          moduleOrTool: `MSF Validation Engine (${input.mode})`,
          resultStatus: 'pending_approval',
        }).catch(() => {});

        // Verify exploit server is online
        const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.msfServerId)).limit(1);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND', message: 'Exploit server not found' });
        if (server.status !== 'online') throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'Exploit server is not online' });

        // Select candidates
        const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
        const catalog = await dbConn.select({
          catalogId: unifiedExploitCatalog.catalogId,
          msfModule: unifiedExploitCatalog.msfModule,
          msfRank: unifiedExploitCatalog.msfRank,
          cveIds: unifiedExploitCatalog.cveIds,
          cvssScore: unifiedExploitCatalog.cvssScore,
          source: unifiedExploitCatalog.source,
        }).from(unifiedExploitCatalog).where(eq(unifiedExploitCatalog.enabled, true));

        const candidates = selectCandidates(assets as any, catalog as any, input.maxCandidates);
        if (candidates.length === 0) {
          throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'No validation candidates found. Ensure the scan has assets with KEV-confirmed CVEs or known MSF modules.' });
        }

        // Create the run record
        const [run] = await dbConn.insert(validationRuns).values({
          scanId: input.scanId,
          msfServerId: input.msfServerId,
          engagementId: input.engagementId ?? null,
          mode: input.mode,
          maxCandidates: input.maxCandidates,
          timeoutPerCandidate: input.timeoutPerCandidate,
          requireApproval: input.requireApproval,
          scopeRestrictions: input.scopeRestrictions,
          status: 'running',
          totalCandidates: candidates.length,
          operatorId: ctx.user.openId,
          startedAt: new Date(),
        }).$returningId();

        const runId = run.id;
        const config = {
          scanId: input.scanId,
          msfServerId: input.msfServerId,
          mode: input.mode,
          maxCandidates: input.maxCandidates,
          requireApproval: input.requireApproval,
          timeoutPerCandidate: input.timeoutPerCandidate,
          scopeRestrictions: input.scopeRestrictions,
          operatorId: ctx.user.openId,
          engagementId: input.engagementId ?? null,
        };

        // Run validation asynchronously (don't block the response)
        (async () => {
          const msfClient = MsfClient.fromServerConfig(server);
          if (!msfClient) {
            await dbConn.update(validationRuns).set({ status: 'failed', errorMessage: 'Could not create MSF client', completedAt: new Date() }).where(eq(validationRuns.id, runId));
            return;
          }

          const { captureFullEvidence } = await import('../lib/evidence-capture');
          const results: any[] = [];
          let validatedCount = 0, notVulnCount = 0, inconclusiveCount = 0, errorCount = 0, skippedCount = 0;
          let totalScoreAdj = 0;

          for (const candidate of candidates) {
            try {
              const result = await validateCandidate(candidate, msfClient, config as any);
              results.push(result);

              // ─── Evidence Capture ───
              let evidenceUrl: string | null = null;
              let evidenceArtifacts: any[] | null = null;
              try {
                const captureCtx = {
                  runId,
                  scanId: input.scanId,
                  candidateId: `${candidate.assetId}-${candidate.cveId}`,
                  assetHostname: candidate.hostname,
                  cveId: candidate.cveId,
                  msfModule: candidate.msfModule,
                  mode: result.mode,
                  targetIp: candidate.hostname, // IP resolved from hostname
                  targetPort: null,
                };
                const captured = await captureFullEvidence(
                  msfClient,
                  captureCtx,
                  {
                    status: result.status,
                    exploitable: result.exploitable,
                    rawOutput: result.rawOutput,
                    evidence: result.evidence,
                    durationMs: result.durationMs,
                    scoreAdjustment: result.scoreAdjustment,
                  },
                  result.evidence?.sessionId ? String(result.evidence.sessionId) : null,
                  null, // jobId not tracked in ValidationEvidence — console output captured via session
                );
                if (captured) {
                  evidenceUrl = captured.reportUrl;
                  evidenceArtifacts = captured.artifacts;
                  console.log(`[Validation] Evidence captured for ${candidate.cveId} on ${candidate.hostname}: ${captured.artifacts.length} artifacts`);
                }
              } catch (evErr: any) {
                console.error(`[Validation] Evidence capture failed (non-fatal):`, evErr.message);
              }

              // Insert result record
              await dbConn.insert(vResults).values({
                runId,
                assetId: result.assetId,
                cveId: result.cveId,
                hostname: result.hostname,
                msfModule: result.msfModule,
                mode: result.mode,
                status: result.status,
                exploitable: result.exploitable,
                rawOutput: result.rawOutput,
                evidence: result.evidence,
                scoreAdjustment: result.scoreAdjustment,
                previousRiskScore: candidate.currentRiskScore,
                durationMs: result.durationMs,
                errorMessage: result.errorMessage,
                evidenceUrl,
                evidenceArtifacts,
              });

              // Update counters
              switch (result.status) {
                case 'validated': validatedCount++; totalScoreAdj += result.scoreAdjustment; break;
                case 'not_vulnerable': notVulnCount++; break;
                case 'inconclusive': inconclusiveCount++; break;
                case 'error': errorCount++; break;
                case 'skipped': skippedCount++; break;
              }

              // If validated, update the asset's risk score and record in scoring audit log
              if (result.exploitable && result.scoreAdjustment > 0) {
                const newScore = Math.min(100, candidate.currentRiskScore + result.scoreAdjustment);
                const newBand = newScore >= 80 ? 'critical' : newScore >= 60 ? 'high' : newScore >= 40 ? 'medium' : 'low';
                await dbConn.update(discoveredAssets)
                  .set({ hybridRiskScore: newScore, riskBand: newBand, lastScoredAt: new Date() })
                  .where(eq(discoveredAssets.id, candidate.assetId));

                // Update the result with the new score
                await dbConn.update(vResults)
                  .set({ newRiskScore: newScore })
                  .where(eq(vResults.runId, runId));

                // Record re-scoring event in audit log for Dynamic Scoring Timeline
                const { scoringAuditLog } = await import('../../drizzle/schema');
                await dbConn.insert(scoringAuditLog).values({
                  assetId: candidate.assetId,
                  scanId: input.scanId,
                  hybridRiskScore: newScore,
                  riskBand: newBand,
                  previousScore: candidate.currentRiskScore,
                  delta: result.scoreAdjustment,
                  triggerType: 'exploit_validation',
                  pipelinePhase: 'validation_engine',
                  changeDescription: `Exploitation validated: ${result.cveId} via ${result.msfModule || 'auxiliary check'} — confirmed exploitable (+${result.scoreAdjustment})`,
                  factorChanges: [{
                    factor: 'exploitability',
                    previousValue: 'unconfirmed',
                    newValue: 'confirmed_exploitable',
                    reason: `CVE ${result.cveId} validated via ${config.mode} mode`,
                  }],
                  computedBy: 'validation-engine',
                });
              } else if (result.status === 'not_vulnerable') {
                // Record negative validation — reduces false positive noise in timeline
                const { scoringAuditLog } = await import('../../drizzle/schema');
                await dbConn.insert(scoringAuditLog).values({
                  assetId: candidate.assetId,
                  scanId: input.scanId,
                  hybridRiskScore: candidate.currentRiskScore,
                  riskBand: candidate.currentRiskScore >= 80 ? 'critical' : candidate.currentRiskScore >= 60 ? 'high' : candidate.currentRiskScore >= 40 ? 'medium' : 'low',
                  previousScore: candidate.currentRiskScore,
                  delta: 0,
                  triggerType: 'exploit_validation_negative',
                  pipelinePhase: 'validation_engine',
                  changeDescription: `Exploitation check negative: ${result.cveId} — not exploitable in current configuration`,
                  factorChanges: [{
                    factor: 'exploitability',
                    previousValue: 'unconfirmed',
                    newValue: 'not_exploitable',
                    reason: `CVE ${result.cveId} check returned not vulnerable`,
                  }],
                  computedBy: 'validation-engine',
                });
              }
            } catch (err: any) {
              errorCount++;
              console.error(`[Validation] Error validating ${candidate.hostname}:${candidate.cveId}:`, err.message);
            }
          }

          // Update run summary
          const avgAdj = validatedCount > 0 ? totalScoreAdj / validatedCount : 0;
          await dbConn.update(validationRuns).set({
            status: 'completed',
            validated: validatedCount,
            notVulnerable: notVulnCount,
            inconclusive: inconclusiveCount,
            errors: errorCount,
            skipped: skippedCount,
            avgScoreAdjustment: Math.round(avgAdj * 100) / 100,
            completedAt: new Date(),
            totalDurationMs: Date.now() - Date.now(),
          }).where(eq(validationRuns.id, runId));

          console.log(`[Validation] Run ${runId} completed: ${validatedCount} validated, ${notVulnCount} not vulnerable, ${inconclusiveCount} inconclusive, ${errorCount} errors, ${skippedCount} skipped`);

          // ─── Post-completion re-scoring hook: recalculate scan overall risk ───
          if (validatedCount > 0) {
            try {
              const { domainIntelScans } = await import('../../drizzle/schema');
              const allAssets = await dbConn.select({ hybridRiskScore: discoveredAssets.hybridRiskScore })
                .from(discoveredAssets)
                .where(eq(discoveredAssets.scanId, input.scanId));
              if (allAssets.length > 0) {
                const scores = allAssets.map(a => a.hybridRiskScore ?? 0);
                const maxScore = Math.max(...scores);
                const avgScore = scores.reduce((s, v) => s + v, 0) / scores.length;
                const newOverall = Math.round(maxScore * 0.6 + avgScore * 0.4);
                const newBand = newOverall >= 80 ? 'critical' : newOverall >= 60 ? 'high' : newOverall >= 40 ? 'medium' : 'low';
                await dbConn.update(domainIntelScans).set({
                  overallRiskScore: newOverall,
                  overallRiskBand: newBand,
                }).where(eq(domainIntelScans.id, input.scanId));
                console.log(`[Validation] Scan ${input.scanId} re-scored: overall=${newOverall} (${newBand}) after ${validatedCount} exploit validations`);
              }
            } catch (resErr: any) {
              console.error(`[Validation] Post-completion re-scoring failed:`, resErr.message);
            }
          }
        })().catch(async (err) => {
          console.error(`[Validation] Run ${runId} failed:`, err);
          await dbConn.update(validationRuns).set({ status: 'failed', errorMessage: String(err.message || err), completedAt: new Date() }).where(eq(validationRuns.id, runId));
        });

        return { runId, totalCandidates: candidates.length, status: 'running', mode: input.mode };
      }),

    /** Get a validation run with its results */
    getRun: protectedProcedure
      .input(z.object({ runId: z.number() }))
      .query(async ({ input }) => {
        const { validationRuns, validationResults: vResults } = await import('../../drizzle/schema');
        const { getDbRequired } = await import('../db');
        const { eq } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        const [run] = await dbConn.select().from(validationRuns).where(eq(validationRuns.id, input.runId)).limit(1);
        if (!run) throw new TRPCError({ code: 'NOT_FOUND' });

        const results = await dbConn.select().from(vResults).where(eq(vResults.runId, input.runId));
        return { run, results };
      }),

    /** List all validation runs for a scan */
    listRuns: protectedProcedure
      .input(z.object({ scanId: z.number().optional(), limit: z.number().default(20) }))
      .query(async ({ input }) => {
        const { validationRuns } = await import('../../drizzle/schema');
        const { getDbRequired } = await import('../db');
        const { eq, sql } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        const conditions: any[] = [];
        if (input.scanId) conditions.push(eq(validationRuns.scanId, input.scanId));

        const runs = await dbConn.select().from(validationRuns)
          .where(conditions.length > 0 ? conditions[0] : undefined)
          .orderBy(sql`${validationRuns.startedAt} DESC`)
          .limit(input.limit);
        return runs;
      }),

    /** Approve a pending safe_exploit candidate */
    approveCandidate: protectedProcedure
      .input(z.object({ resultId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { validationResults: vResults } = await import('../../drizzle/schema');
        const { getDbRequired } = await import('../db');
        const { eq } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        const [result] = await dbConn.select().from(vResults).where(eq(vResults.id, input.resultId)).limit(1);
        if (!result) throw new TRPCError({ code: 'NOT_FOUND' });
        if (result.status !== 'approved_pending') throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'Result is not pending approval' });

        await dbConn.update(vResults).set({ status: 'pending' }).where(eq(vResults.id, input.resultId));
        return { approved: true, resultId: input.resultId };
      }),

    /** Cancel a running validation run */
    cancelRun: protectedProcedure
      .input(z.object({ runId: z.number() }))
      .mutation(async ({ input }) => {
        const { validationRuns } = await import('../../drizzle/schema');
        const { getDbRequired } = await import('../db');
        const { eq } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        await dbConn.update(validationRuns).set({ status: 'cancelled', completedAt: new Date() }).where(eq(validationRuns.id, input.runId));
        return { cancelled: true };
      }),

    /** Get validation summary for a scan (for DomainIntelResults integration) */
    getScanValidationSummary: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const { validationRuns, validationResults: vResults } = await import('../../drizzle/schema');
        const { getDbRequired } = await import('../db');
        const { eq, sql, and } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        // Get the latest completed run for this scan
        const [latestRun] = await dbConn.select().from(validationRuns)
          .where(and(eq(validationRuns.scanId, input.scanId), eq(validationRuns.status, 'completed')))
          .orderBy(sql`${validationRuns.startedAt} DESC`)
          .limit(1);

        if (!latestRun) return { hasValidation: false, run: null, results: [], exploitableCount: 0, totalValidated: 0 };

        const results = await dbConn.select().from(vResults).where(eq(vResults.runId, latestRun.id));
        const exploitableCount = results.filter(r => r.exploitable).length;

        return {
          hasValidation: true,
          run: latestRun,
          results,
          exploitableCount,
          totalValidated: results.filter(r => r.status === 'validated' || r.status === 'not_vulnerable').length,
        };
      }),
  });
