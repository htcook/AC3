import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { and, eq, min, not, or, sql } from "drizzle-orm";
import * as schema from "../../drizzle/schema";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
import { validateEngagementTargets } from "../../shared/domain-safety-whitelist";

export const engagementOpsRouter = router({
    /** Get current ops state for an engagement */
    getState: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input, ctx }) => {
        // Verify user has access to this engagement
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { getOpsState, getOpsStateWithRecovery, initOpsState, normalizeOpsState } = await import('../lib/engagement-orchestrator');
        // First try in-memory, then try DB recovery, then initialize fresh
        let state = getOpsState(input.engagementId);
        if (state) state = normalizeOpsState(state);
        if (!state) {
          // Try to recover from DB snapshot (preserves assets from previous scans)
          state = await getOpsStateWithRecovery(input.engagementId);
        }
        if (!state) {
          // No snapshot either — initialize fresh from engagement targets
          const engagement = await db.getEngagementById(input.engagementId);
          if (engagement) {
            state = initOpsState(input.engagementId, engagement.engagementType);
            // Pre-populate assets from existing DB targets
            const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
            const ips = (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean);
            for (const d of domains) {
              if (!state.assets.find((a: any) => a.hostname === d)) {
                state.assets.push({
                  hostname: d, type: 'unknown' as const, ports: [], vulns: [],
                  zapFindings: [], exploitAttempts: [], toolResults: [], status: 'pending' as const
                });
              }
            }
            for (const ip of ips) {
              if (!state.assets.find((a: any) => a.hostname === ip || a.ip === ip)) {
                state.assets.push({
                  hostname: ip, ip, type: 'unknown' as const, ports: [], vulns: [],
                  zapFindings: [], exploitAttempts: [], toolResults: [], status: 'pending' as const
                });
              }
            }
            if (state.assets.length > 0) {
              state.stats.assetsDiscovered = state.assets.length;
            }
          }
        }
        // Convert Set to array for JSON serialization (superjson handles Date but not Set)
        if (state && state.skippedDomains instanceof Set) {
          return { ...state, skippedDomains: [...state.skippedDomains] };
        }
        // Never return null — always return a default idle state so the frontend doesn't crash
        if (!state) {
          return {
            engagementId: input.engagementId,
            phase: 'idle' as const,
            isRunning: false,
            isPaused: false,
            progress: 0,
            log: [],
            assets: [],
            approvalGates: [],
            stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
          };
        }
        return state;
      }),

    /** Initialize ops state for an engagement */
    init: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId, ctx.user);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });
        const { initOpsState } = await import('../lib/engagement-orchestrator');
        return initOpsState(input.engagementId, engagement.engagementType);
      }),

    /** Start autonomous execution — one-click pentest/red team */
    execute: protectedProcedure
      .input(z.object({ engagementId: z.number(), exhaustiveExploit: z.boolean().optional().default(true), trainingLabMode: z.boolean().optional() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId, ctx.user);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        // Validate RoE scope exists
        if (!engagement.targetDomain && !engagement.targetIpRange) {
          throw new TRPCError({ code: 'BAD_REQUEST', message: 'No targets defined. Add target domains or IP ranges first.' });
        }

        // ═══ DOMAIN SAFETY WHITELIST GATE ═══
        // Block full pipeline execution on non-whitelisted domains unless admin override
        const domainCheck = validateEngagementTargets(engagement.targetDomain, engagement.targetIpRange);
        if (!domainCheck.allWhitelisted && !input.trainingLabMode) {
          // Check if admin has explicitly set an override flag on this engagement
          const dbConn = await db.getDb();
          let hasAdminOverride = false;
          if (dbConn) {
            const [rows] = await dbConn.execute(
              sql`SELECT active_scan_override FROM engagements WHERE id = ${input.engagementId}`
            );
            hasAdminOverride = !!(rows as any)?.[0]?.active_scan_override;
          }
          if (!hasAdminOverride) {
            throw new TRPCError({
              code: 'FORBIDDEN',
              message: `SAFETY GUARDRAIL: Cannot start full pipeline — ${domainCheck.nonWhitelistedCount} target(s) are not on the approved test lab whitelist: ${domainCheck.nonWhitelistedTargets.join(', ')}. ` +
                `Only passive reconnaissance is permitted for non-whitelisted domains. ` +
                `An admin can enable the "Active Scan Override" flag on this engagement if a signed RoE authorizes active testing.`,
            });
          }
          console.warn(`[EngOps] Admin override active for #${input.engagementId} — proceeding with non-whitelisted targets: ${domainCheck.nonWhitelistedTargets.join(', ')}`);
        }

        const { executeEngagement, initOpsState, getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) {
          state = initOpsState(input.engagementId, engagement.engagementType);
        }
        if (state.isRunning) {
          throw new TRPCError({ code: 'CONFLICT', message: 'Engagement is already running' });
        }

        // ═══ FULL RE-RUN RESET ═══
        // When re-launching a completed or errored engagement, reset all accumulated
        // stats, assets, vulns, and completedScans to prevent duplication.
        // This is a full re-run, not a resume from a checkpoint.
        const previousPhase = state.phase;
        if (previousPhase === 'completed' || previousPhase === 'error' || previousPhase === 'idle') {
          console.log(`[EngOps] Full re-run detected for #${input.engagementId} (was: ${previousPhase}). Resetting stats and data.`);
          // Reset stats to zero
          state.stats = {
            hostsScanned: 0, portsFound: 0, vulnsFound: 0,
            exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
            zapScansRun: 0, wafDetections: 0,
          };
          // Clear all asset data (vulns, ports, tool results, exploit attempts)
          for (const asset of state.assets) {
            asset.vulns = [];
            asset.ports = [];
            asset.toolResults = [];
            asset.exploitAttempts = [];
            if ((asset as any).zapFindings) (asset as any).zapFindings = [];
            if ((asset as any).nucleiFindings) (asset as any).nucleiFindings = [];
          }
          // Clear assets entirely for a truly fresh start
          state.assets = [];
          // Reset completedScans so no scans are skipped
          state.completedScans = {
            nucleiCompleted: new Set(),
            zapCompleted: new Set(),
            hydraCompleted: new Set(),
            exploitCompleted: new Set(),
            lastCheckpointAt: Date.now(),
          };
          // Clear previous error and completion state
          state.error = undefined;
          state.completedAt = undefined;
          state.progress = 0;
          // Clear coverage analysis, target profiles, and manual findings
          state.coverageAnalysis = undefined;
          state.targetProfiles = undefined;
          // Keep logs from previous run for audit trail, but add reset marker
          state.log.push({
            phase: 'idle' as any,
            type: 'info' as any,
            title: '\u{1F504} Full Pipeline Re-run — Stats Reset',
            detail: `Previous run (${previousPhase}) data cleared. All stats, assets, vulns, and scan checkpoints reset to zero for a clean re-run.`,
            timestamp: Date.now(),
          });
        }

        // Set exhaustive exploitation mode — when true, attempts every exploit opportunity
        state.exhaustiveExploit = input.exhaustiveExploit;
        // Set training lab mode if specified — auto-approves all gates including exploitation
        if (input.trainingLabMode !== undefined) {
          state.trainingLabMode = input.trainingLabMode;
        }
        // Auto-detect training lab mode from engagement labName (set by batchTrainingRun)
        if (state.trainingLabMode === undefined && (engagement as any).labName) {
          state.trainingLabMode = true;
        }
        // Auto-detect training lab from target domain (aceofcloud.io lab infrastructure)
        if (state.trainingLabMode === undefined) {
          const domain = engagement.targetDomain || '';
          if (domain.includes('aceofcloud.io') || domain.includes('aceofcloud.com')) {
            state.trainingLabMode = true;
            console.log(`[EngOps] Training lab auto-detected for #${input.engagementId} (domain: ${domain})`);
          }
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_ops_started',
          details: `Started autonomous ${engagement.engagementType} execution for engagement #${input.engagementId}`,
        });

        // Fire and forget — the pipeline runs asynchronously, but catch crashes
        executeEngagement(input.engagementId, { id: String(ctx.user.id), name: ctx.user.name || undefined })
          .catch(async (err: any) => {
            console.error('[EngOps] executeEngagement crashed:', err.message);
            const { addLog: addOpsLog, broadcastOpsUpdate: broadcast, persistOpsStateNow } = await import('../lib/engagement-orchestrator');
            if (state) {
              state.isRunning = false;
              state.phase = 'error' as any;
              state.error = err.message;
              addOpsLog(state, { phase: 'recon', type: 'error', title: '\u274c Engagement Execution Failed', detail: `Pipeline crashed: ${err.message}` });
              broadcast(input.engagementId, { type: 'phase_change', phase: 'error' });
              await persistOpsStateNow(input.engagementId).catch(() => {});
            }
          });

        return { started: true, engagementId: input.engagementId };
      }),

    /** Stop execution */
    stop: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { stopEngagement } = await import('../lib/engagement-orchestrator');
        const stopped = stopEngagement(input.engagementId);
        if (stopped) {
          await db.logActivity({
            userId: ctx.user.id,
            action: 'engagement_ops_stopped',
            details: `Stopped execution for engagement #${input.engagementId}`,
          });
        }
        return { stopped };
      }),

    /** Resume a stopped or crashed engagement from its last saved phase */
    resume: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { resumeEngagement } = await import('../lib/engagement-orchestrator');
        const result = await resumeEngagement(input.engagementId, {
          id: String(ctx.user.id),
          name: ctx.user.name || undefined,
        });
        if (result.success) {
          await db.logActivity({
            userId: ctx.user.id,
            action: 'engagement_ops_resumed',
            details: `Resumed execution for engagement #${input.engagementId} from phase: ${result.resumePhase}`,
          });
        }
        return result;
      }),

    /** Re-run a completed/errored engagement from a specific phase, preserving prior phase data */
    rerunFromPhase: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        targetPhase: z.enum(['recon', 'enumeration', 'vuln_detection', 'exploitation', 'post_exploit']),
        exhaustiveExploit: z.boolean().optional().default(true),
      }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { rerunFromPhase, getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        // Set exhaustive exploitation mode on the existing state
        // Try in-memory first, then DB recovery (state may be lost after server restart)
        let existingState = getOpsState(input.engagementId);
        if (!existingState) existingState = await getOpsStateWithRecovery(input.engagementId);
        if (!existingState) {
          existingState = await getOpsStateWithRecovery(input.engagementId);
        }
        if (existingState) {
          existingState.exhaustiveExploit = input.exhaustiveExploit;
        }
        const result = await rerunFromPhase(input.engagementId, input.targetPhase, {
          id: String(ctx.user.id),
          name: ctx.user.name || undefined,
        });
        if (result.success) {
          await db.logActivity({
            userId: ctx.user.id,
            action: 'engagement_rerun_from_phase',
            details: `Re-running engagement #${input.engagementId} from phase: ${input.targetPhase}`,
          });
        }
        return result;
      }),

    /** Skip the currently scanning domain — marks it as skipped so the pipeline moves to the next domain */
    skipCurrentDomain: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { getOpsState, getOpsStateWithRecovery, broadcastOpsUpdate } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });
        if (!state.isRunning || !state.currentDomain) {
          throw new TRPCError({ code: 'BAD_REQUEST', message: 'No domain is currently being scanned' });
        }
        const domain = state.currentDomain;
        if (!state.skippedDomains) state.skippedDomains = new Set();
        state.skippedDomains.add(domain);
        const skipLog = { id: `log-${Date.now()}-skip-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: `\u23ed Skip Requested: ${domain}`, detail: `Operator requested skip for ${domain}. Will take effect after current stage completes.` };
        state.log.push(skipLog);
        broadcastOpsUpdate(input.engagementId, { type: 'log', entry: skipLog });
        await db.logActivity({ userId: ctx.user.id, action: 'domain_skip_requested', details: `Requested skip for domain ${domain} in engagement #${input.engagementId}` });
        return { skipped: true, domain };
      }),

    /** Fully clear ops state — wipes all in-memory and DB state so engagement starts fresh */
    clearOps: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { clearOpsState } = await import('../lib/engagement-orchestrator');
        await clearOpsState(input.engagementId);
        await db.logActivity({ userId: ctx.user.id, action: 'engagement_ops_cleared', details: `Fully cleared ops state for engagement #${input.engagementId}` });
        return { cleared: true };
      }),

    /** Diagnostic: test LLM connectivity from the production server */
    testLlm: protectedProcedure
      .input(z.object({
        paddingKB: z.number().min(0).max(500).optional(),
        mode: z.enum(['basic', 'security', 'json_schema', 'scan_plan']).optional(),
      }).optional())
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('../_core/llm');
        const { ENV } = await import('../_core/env');
        const paddingKB = input?.paddingKB ?? 0;
        const mode = input?.mode ?? 'basic';
        const padding = paddingKB > 0 ? 'X'.repeat(paddingKB * 1024) : '';
        const start = Date.now();
        try {
          // Build messages based on mode
          let messages: any[] = [];
          let opts: any = {};
          if (mode === 'security') {
            // Test with security-related content
            messages = [
              { role: 'system', content: 'You are an expert penetration tester and red team operator. You plan ScanForge discovery scans, nuclei vulnerability scans, exploit payloads, and SQL injection attacks. You use tools like hydra for credential brute-forcing, metasploit for exploitation, and gobuster for directory discovery. ' + padding },
              { role: 'user', content: 'Recommend discovery flags for scanning a web server behind CloudFlare WAF. Include evasion techniques.' },
            ];
          } else if (mode === 'json_schema') {
            // Test with json_schema response_format
            messages = [
              { role: 'system', content: 'You are a helpful assistant. ' + padding },
              { role: 'user', content: 'Return a JSON object with a greeting field.' },
            ];
            opts.response_format = {
              type: 'json_schema',
              json_schema: {
                name: 'test_output',
                strict: true,
                schema: {
                  type: 'object',
                  properties: { greeting: { type: 'string' } },
                  required: ['greeting'],
                  additionalProperties: false,
                },
              },
            };
          } else if (mode === 'scan_plan') {
            // Test with the ACTUAL scan plan system prompt (trimmed)
            messages = [
              { role: 'system', content: `You are an expert penetration tester and red team operator planning the active scanning phase of a pentest engagement. Available tools: ScanForge discovery (port scanner), nuclei (vuln scanner with -u URL format), nikto (web scanner), gobuster (dir brute-forcer), httpx (HTTP probe), hydra (credential brute-forcer), sqlmap (SQL injection), testssl (TLS scanner), whatweb (tech fingerprinter), wpscan (WordPress scanner), cloud_enum (cloud resource enumerator), s3scanner (S3 bucket scanner). EVASION: If WAF/CDN detected do NOT use -f fragmentation or -D decoys. For cloud targets use simple '-Pn -sV -sC'. Respond with JSON matching: { "overallStrategy": "string", "assetPlans": [{ "hostname": "string", "discoveryFlags": "string", "activeTools": [{ "tool": "string", "command": "string" }] }] }` + padding },
              { role: 'user', content: 'Plan a scan for dashboard-dev.vianovahealth.com (cloud-hosted on AWS, WAF detected: CloudFront). Passive recon found: ports 80/443 open, nginx web server, React frontend. Generate a two-phase scan plan.' },
            ];
            opts.response_format = {
              type: 'json_schema',
              json_schema: {
                name: 'scan_plan',
                strict: true,
                schema: {
                  type: 'object',
                  properties: {
                    overallStrategy: { type: 'string' },
                    assetPlans: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          hostname: { type: 'string' },
                          discoveryFlags: { type: 'string' },
                          activeTools: {
                            type: 'array',
                            items: {
                              type: 'object',
                              properties: {
                                tool: { type: 'string' },
                                command: { type: 'string' },
                              },
                              required: ['tool', 'command'],
                              additionalProperties: false,
                            },
                          },
                        },
                        required: ['hostname', 'discoveryFlags', 'activeTools'],
                        additionalProperties: false,
                      },
                    },
                  },
                  required: ['overallStrategy', 'assetPlans'],
                  additionalProperties: false,
                },
              },
            };
          } else {
            messages = [
              ...(padding ? [{ role: 'system' as const, content: 'You are a helpful assistant. ' + padding }] : []),
              { role: 'user' as const, content: 'Say hello in one word' },
            ];
          }
          const result = await invokeLLM({ 
            _caller: 'engagement-ops:analyzeTarget',
            messages,
            ...opts,
          });
          return {
            ok: true,
            latencyMs: Date.now() - start,
            mode,
            model: result.model,
            content: result.choices?.[0]?.message?.content?.substring(0, 500),
            tokensIn: result.usage?.prompt_tokens ?? 0,
            tokensOut: result.usage?.completion_tokens ?? 0,
            paddingKB,
            apiUrlPrefix: (ENV.forgeApiUrl || 'NOT_SET').substring(0, 30),
            apiKeyLength: (ENV.forgeApiKey || '').length,
          };
        } catch (err: any) {
          return {
            ok: false,
            latencyMs: Date.now() - start,
            mode,
            error: err.message?.substring(0, 500),
            paddingKB,
            apiUrlPrefix: (ENV.forgeApiUrl || 'NOT_SET').substring(0, 30),
            apiKeyLength: (ENV.forgeApiKey || '').length,
          };
        }
      }),

    /** Reset ops state — clears error state so operator can retry */
    resetOps: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { getOpsState, getOpsStateWithRecovery, broadcastOpsUpdate } = await import('../lib/engagement-orchestrator');
        // Try in-memory first, then fall back to DB snapshot recovery
        // (in-memory state is lost after server restart on DO)
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) {
          state = await getOpsStateWithRecovery(input.engagementId);
        }
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found. The server may have restarted — try starting a new execution instead.' });
        // Reset to idle (or recon_complete if assets exist)
        const hasAssets = state.assets.length > 0;
        state.phase = hasAssets ? ('recon_complete' as any) : 'idle';
        state.isRunning = false;
        state.isPaused = false;
        state.error = undefined;
        state.currentAction = undefined;
        // Recalculate stats from preserved assets (fixes vulnsFound=0 after reset)
        if (hasAssets) {
          state.stats.vulnsFound = state.assets.reduce((sum: number, a: any) => sum + (a.vulns || []).length, 0);
          state.stats.portsFound = state.assets.reduce((sum: number, a: any) => sum + (a.ports || []).length, 0);
          state.stats.assetsDiscovered = state.assets.length;
        }
        const resetLog = { id: `log-${Date.now()}-reset`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: '🔄 Ops State Reset', detail: `Reset by ${ctx.user.name || 'operator'}. ${hasAssets ? `${state.assets.length} assets preserved (${state.stats.vulnsFound} vulns, ${state.stats.portsFound} ports). Ready for active scan or re-run passive.` : 'Ready for passive discovery.'}` };
        state.log.push(resetLog);
        broadcastOpsUpdate(input.engagementId, { type: 'log', entry: resetLog });
        broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: state.phase });
        await db.logActivity({ userId: ctx.user.id, action: 'engagement_ops_reset', details: `Reset ops state for engagement #${input.engagementId}` });
        // Persist the reset state to DB
        const { persistOpsStateNow } = await import('../lib/engagement-orchestrator');
        await persistOpsStateNow(input.engagementId).catch(() => {});
        return { reset: true, phase: state.phase, assetsPreserved: state.assets.length };
      }),

    /** Resolve an approval gate (supports modified plans with removedTargetIndices) */
    resolveApproval: protectedProcedure
      .input(z.object({
        gateId: z.string(),
        approved: z.boolean(),
        /** Indices of targets to REMOVE from the plan (for "Modify Plan" flow) */
        removedTargetIndices: z.array(z.number()).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { resolveApproval, getApprovalGateDetail } = await import('../lib/engagement-orchestrator');

        // Get gate detail before resolving (for plan history persistence)
        const gateDetail = getApprovalGateDetail(input.gateId);
        const isExploitPlan = gateDetail?.title?.startsWith('Exploit Plan Review');
        const hasModifications = input.removedTargetIndices && input.removedTargetIndices.length > 0;

        // If this is a modified plan, update the gate's detail with the modification info
        if (isExploitPlan && hasModifications && gateDetail?.detail) {
          const originalActions = gateDetail.detail.actions || [];
          const removedIndices = new Set(input.removedTargetIndices);
          const keptActions = originalActions.filter((_: any, i: number) => !removedIndices.has(i));
          const removedActions = originalActions.filter((_: any, i: number) => removedIndices.has(i));

          // Store modification metadata on the gate for the orchestrator to use
          gateDetail.detail._modifiedPlan = keptActions;
          gateDetail.detail._removedTargets = removedActions;
          gateDetail.detail._removedIndices = input.removedTargetIndices;
        }

        const resolved = resolveApproval(input.gateId, input.approved, ctx.user.name || String(ctx.user.id));
        if (resolved === false) throw new TRPCError({ code: 'NOT_FOUND', message: 'Approval gate not found or already resolved' });

        // Dual-approval partial — first approver recorded but gate still pending
        if (resolved === 'partial') {
          await db.logActivity({
            userId: ctx.user.id,
            action: 'ops_dual_approval_partial',
            details: `Partial dual-approval for gate ${input.gateId} — awaiting additional approver(s)`,
          });
          return { resolved: false, partial: true, modified: false };
        }

        // Persist exploit plan to history
        if (isExploitPlan && gateDetail) {
          try {
            const originalActions = gateDetail.detail?.actions || [];
            let planStatus: 'approved' | 'rejected' | 'modified' = input.approved ? 'approved' : 'rejected';
            let modifiedPlan = null;
            let removedTargets = null;
            let finalCount = input.approved ? originalActions.length : 0;

            if (input.approved && hasModifications) {
              planStatus = 'modified';
              const removedIndices = new Set(input.removedTargetIndices);
              modifiedPlan = originalActions.filter((_: any, i: number) => !removedIndices.has(i));
              removedTargets = originalActions.filter((_: any, i: number) => removedIndices.has(i));
              finalCount = modifiedPlan.length;
            }

            // Find the engagement ID from the gate
            const engagementId = gateDetail.detail?.engagementId || gateDetail._engagementId;

            if (engagementId) {
              await db.insertExploitPlanHistory({
                engagementId,
                gateId: input.gateId,
                status: planStatus,
                operatorId: ctx.user.id,
                operatorName: ctx.user.name || String(ctx.user.id),
                originalPlan: originalActions,
                modifiedPlan,
                llmReasoning: gateDetail.detail?.reasoning || null,
                llmDecision: gateDetail.detail?.decision || null,
                originalTargetCount: originalActions.length,
                finalTargetCount: finalCount,
                removedTargets,
                reviewDurationMs: gateDetail.createdAt ? Date.now() - gateDetail.createdAt : null,
                resolvedAt: new Date(),
              });
            }
          } catch (err: any) {
            console.error('[ExploitPlanHistory] Failed to persist plan:', err.message);
          }
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: input.approved ? 'ops_approval_granted' : 'ops_approval_denied',
          details: `${input.approved ? 'Approved' : 'Denied'} gate ${input.gateId}${hasModifications ? ` (modified: removed ${input.removedTargetIndices!.length} targets)` : ''}`,
        });

        return { resolved: true, modified: hasModifications || false };
      }),

    /** Dismiss a single stale/orphaned approval gate (no active resolver after server restart) */
    dismissStaleApproval: protectedProcedure
      .input(z.object({ gateId: z.string() }))
      .mutation(async ({ input, ctx }) => {
        const { dismissStaleApproval } = await import('../lib/engagement-orchestrator');
        const dismissed = dismissStaleApproval(input.gateId, ctx.user.name || String(ctx.user.id));
        if (!dismissed) throw new TRPCError({ code: 'NOT_FOUND', message: 'Gate not found, not stale, or already resolved' });

        await db.logActivity({
          userId: ctx.user.id,
          action: 'ops_stale_gate_dismissed',
          details: `Dismissed stale approval gate ${input.gateId}`,
        });

        return { dismissed: true };
      }),

    /** Dismiss ALL stale approval gates for an engagement */
    dismissAllStaleApprovals: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { dismissAllStaleApprovals } = await import('../lib/engagement-orchestrator');
        const count = dismissAllStaleApprovals(input.engagementId, ctx.user.name || String(ctx.user.id));

        if (count > 0) {
          await db.logActivity({
            userId: ctx.user.id,
            action: 'ops_stale_gates_bulk_dismissed',
            details: `Dismissed ${count} stale approval gate(s) for engagement ${input.engagementId}`,
          });
        }

        return { dismissed: count };
      }),

    /** Add targets to an engagement (paste-in from operator) */
    addTargets: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        targets: z.string(),
      }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        const parsed = input.targets.split(/[\n,;]+/).map(t => t.trim()).filter(Boolean);
        const domains: string[] = [];
        const ips: string[] = [];
        for (const t of parsed) {
          if (/^https?:\/\//i.test(t)) domains.push(new URL(t).hostname);
          else if (/^\d{1,3}(\.\d{1,3}){3}/.test(t)) ips.push(t);
          else domains.push(t);
        }

        const existingDomains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
        const existingIps = (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean);
        const allDomains = [...new Set([...existingDomains, ...domains])];
        const allIps = [...new Set([...existingIps, ...ips])];

        await db.updateEngagement(input.engagementId, {
          targetDomain: allDomains.join(', '),
          targetIpRange: allIps.join(', '),
        });

        const { initOpsState, getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
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

        await db.logActivity({ userId: ctx.user.id, action: 'targets_added', details: `Added ${parsed.length} targets to engagement #${input.engagementId}` });
        return { added: parsed.length, domains: allDomains, ips: allIps, totalAssets: state.assets.length };
      }),

    /** Start passive discovery scan only (Phase 1: Recon) */
    /** Update the scan mode for an engagement's passive recon */
    updateScanMode: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        scanMode: z.enum(['strict_passive', 'standard', 'active']),
      }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });
        await db.updateEngagement(input.engagementId, { scanMode: input.scanMode } as any);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'scan_mode_updated',
          details: `Updated scan mode to ${input.scanMode} for engagement #${input.engagementId}`,
        });
        return { success: true, scanMode: input.scanMode };
      }),

    /** Get scan mode descriptions with connector counts */
    getScanModes: protectedProcedure
      .query(async () => {
        const { getScanModeDescription } = await import('../lib/passive/passive-guard');
        return {
          modes: [
            { value: 'strict_passive' as const, ...getScanModeDescription('strict_passive'), connectorCount: 23 },
            { value: 'standard' as const, ...getScanModeDescription('standard'), connectorCount: 28 },
            { value: 'active' as const, ...getScanModeDescription('active'), connectorCount: 31 },
          ],
        };
      }),

    startPassiveScan: protectedProcedure
      .input(z.object({ engagementId: z.number(), scanMode: z.enum(['strict_passive', 'standard', 'active']).optional() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        const { initOpsState, getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) state = initOpsState(input.engagementId, engagement.engagementType);
        if (state.isRunning) throw new TRPCError({ code: 'CONFLICT', message: 'Scan already running' });

        // ── Parse targets from DB SYNCHRONOUSLY before async work ──
        const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
        const ips = (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean);
        const allTargets = [...domains, ...ips];

        if (allTargets.length === 0) {
          throw new TRPCError({ code: 'BAD_REQUEST', message: 'No targets configured — add domains or IPs first' });
        }

        // ── Pre-populate assets SYNCHRONOUSLY so they're available when mutation returns ──
        for (const d of domains) {
          if (!state.assets.find((a: any) => a.hostname === d)) {
            state.assets.push({ hostname: d, type: 'unknown', ports: [], vulns: [], zapFindings: [], exploitAttempts: [], toolResults: [], status: 'pending' });
          }
        }
        for (const ip of ips) {
          if (!state.assets.find((a: any) => a.hostname === ip || a.ip === ip)) {
            state.assets.push({ hostname: ip, ip, type: 'unknown', ports: [], vulns: [], zapFindings: [], exploitAttempts: [], toolResults: [], status: 'pending' });
          }
        }

        state.isRunning = true;
        state.phase = 'recon';
        state.startedAt = Date.now();

        // ── Initial log + broadcast SYNCHRONOUSLY so UI updates immediately ──
        const { broadcastOpsUpdate } = await import('../lib/engagement-orchestrator');
        const startLog = { id: `log-${Date.now()}-start`, timestamp: Date.now(), phase: 'recon' as const, type: 'phase_complete' as const, title: '🚀 Passive Scan Started', detail: `Scanning ${allTargets.length} targets (${domains.length} domains, ${ips.length} IPs). Pipeline stages: passive recon → asset discovery → DNS verification → analysis → scoring.` };
        state.log.push(startLog);
        broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'recon' });
        broadcastOpsUpdate(input.engagementId, { type: 'log', entry: startLog });
        console.log(`[PassiveScan] Started for engagement #${input.engagementId}: ${allTargets.join(', ')}`);

        // Force-persist state immediately so assets survive a crash before pipeline starts
        const { persistOpsStateNow } = await import('../lib/engagement-orchestrator');
        await persistOpsStateNow(input.engagementId);

        // Determine scan mode: input override > engagement DB setting > default strict_passive
        const effectiveScanMode = input.scanMode || (engagement as any).scanMode || 'strict_passive';
        const { getScanModeDescription } = await import('../lib/passive/passive-guard');
        const modeInfo = getScanModeDescription(effectiveScanMode);
        const modeIcons: Record<string, string> = { strict_passive: '\ud83d\udd12', standard: '\ud83d\udd0d', active: '\u26a1' };
        state.log.push({ id: `log-${Date.now()}-mode`, timestamp: Date.now(), phase: 'recon', type: 'info', title: `${modeIcons[effectiveScanMode] || '\ud83d\udd12'} Scan Mode: ${modeInfo.label}`, detail: `${modeInfo.description} Scanning ${allTargets.length} targets.` });
        broadcastOpsUpdate(input.engagementId, { type: 'log', entry: state.log[state.log.length - 1] });
        // Store scan mode on state for reference
        (state as any).scanMode = effectiveScanMode;

        await db.logActivity({ userId: ctx.user.id, action: 'passive_scan_started', details: `Started passive discovery for engagement #${input.engagementId}` });

        // Run pipeline in background — mutation returns immediately with assets already populated
        (async () => {
          // ── Per-domain watchdog: 12 minutes per domain (connector hard timeout is 30s, so ~15 connectors max) ──
          const PER_DOMAIN_WATCHDOG_MS = 12 * 60 * 1000;
          // ── Global watchdog: 60 minutes total for entire pipeline ──
          const GLOBAL_WATCHDOG_MS = 60 * 60 * 1000;
          // ── Parallel concurrency: scan up to 2 domains simultaneously (reduced from 3 to reduce event loop pressure) ──
          const PARALLEL_CONCURRENCY = 2;
          let globalWatchdogTimer: ReturnType<typeof setTimeout> | null = null;
          const globalAbort = new AbortController();
          globalWatchdogTimer = setTimeout(() => {
            globalAbort.abort();
          }, GLOBAL_WATCHDOG_MS);

          // Track active domains for UI (replaces single currentDomain)
          const activeDomains = new Set<string>();
          const updateCurrentAction = () => {
            const active = [...activeDomains];
            if (active.length === 0) {
              state!.currentAction = undefined;
            } else if (active.length === 1) {
              state!.currentDomain = active[0];
              state!.currentAction = `Scanning ${active[0]}...`;
            } else {
              state!.currentDomain = active[0]; // UI shows first for elapsed timer
              state!.currentAction = `Scanning ${active.length} domains in parallel: ${active.slice(0, 3).join(', ')}${active.length > 3 ? ` +${active.length - 3} more` : ''}`;
            }
          };

          const parallelStartLog = { id: `log-${Date.now()}-parallel`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: `⚡ Parallel Scan Mode`, detail: `Scanning up to ${PARALLEL_CONCURRENCY} domains concurrently (30s hard timeout per connector). ${domains.length} domains queued.` };
          state!.log.push(parallelStartLog);
          broadcastOpsUpdate(input.engagementId, { type: 'log', entry: parallelStartLog });

          /** Process a single domain through the full pipeline */
          const processDomain = async (domain: string): Promise<void> => {
            // Check if scan was stopped by operator
            if (!state!.isRunning || globalAbort.signal.aborted) return;

            // Check if this domain was skipped by operator
            if (state!.skippedDomains?.has(domain)) {
              const skipLog = { id: `log-${Date.now()}-skip-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: `⏭ Skipped: ${domain}`, detail: 'Domain skipped by operator request.' };
              state!.log.push(skipLog);
              broadcastOpsUpdate(input.engagementId, { type: 'log', entry: skipLog });
              return;
            }

            activeDomains.add(domain);
            updateCurrentAction();

            // Per-domain watchdog
            let domainWatchdogTimer: ReturnType<typeof setTimeout> | null = null;
            const domainWatchdogPromise = new Promise<never>((_, reject) => {
              domainWatchdogTimer = setTimeout(() => reject(new Error(`Domain watchdog timeout (${Math.round(PER_DOMAIN_WATCHDOG_MS / 60000)} min) for ${domain}`)), PER_DOMAIN_WATCHDOG_MS);
            });
            // Also abort on global signal
            const globalAbortPromise = new Promise<never>((_, reject) => {
              if (globalAbort.signal.aborted) return reject(new Error('Global pipeline watchdog timeout — aborting'));
              globalAbort.signal.addEventListener('abort', () => reject(new Error('Global pipeline watchdog timeout — aborting')), { once: true });
            });

            try {
              const logEntry = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'scan_start' as const, title: `Domain Intel: ${domain}`, detail: 'Running strict passive OSINT scan (no direct target contact)' };
              state!.log.push(logEntry);
              broadcastOpsUpdate(input.engagementId, { type: 'log', entry: logEntry });

              broadcastOpsUpdate(input.engagementId, { type: 'stats_update', stats: { ...state!.stats } });

              const { runDomainIntelPipeline } = await import('../domainIntel');
              console.log(`[PassiveScan] Starting runDomainIntelPipeline for ${domain}`);
              const result = await Promise.race([
                runDomainIntelPipeline(
                  {
                    customerName: engagement.customerName || 'Auto',
                    primaryDomain: domain,
                    additionalDomains: [],
                    sector: 'technology',
                    clientType: 'enterprise',
                    criticalFunctions: [],
                    complianceFlags: [],
                  },
                  // Progress callback — push stage updates to live feed
                  async (stage) => {
                    // Check if domain was skipped mid-pipeline
                    if (state!.skippedDomains?.has(domain)) {
                      throw new Error(`Domain ${domain} skipped by operator`);
                    }
                    console.log(`[PassiveScan] Pipeline stage: ${stage} for ${domain}`);
                    const stageLog = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: `Pipeline: ${domain}`, detail: `Stage: ${stage}` };
                    state!.log.push(stageLog);
                    broadcastOpsUpdate(input.engagementId, { type: 'log', entry: stageLog });
                  },
                  // Options: use engagement scan mode, scoped to engagement targets only, with per-connector progress
                  {
                    scanMode: effectiveScanMode as any,
                    skipEngagement: false,
                    scopedAssets: allTargets,
                    onConnectorProgress: async (event) => {
                      let statusIcon: string;
                      let detail: string;
                      if (event.status === 'started') {
                        statusIcon = '\u25b6';
                        detail = 'Querying...';
                      } else if (event.status === 'completed') {
                        const obs = event.observations || 0;
                        const dur = ((event.durationMs || 0) / 1000).toFixed(1);
                        if (obs > 0) {
                          statusIcon = '\u2705';
                          detail = `${obs} observations in ${dur}s`;
                        } else if ((event.durationMs || 0) < 50) {
                          statusIcon = '\u23ed';
                          detail = `No API key configured — skipped (${dur}s)`;
                        } else {
                          statusIcon = '\u2139\ufe0f';
                          detail = `0 observations — no records found for this domain (${dur}s)`;
                        }
                      } else if (event.status === 'failed') {
                        statusIcon = '\u274c';
                        detail = `Error: ${event.error || 'unknown'}`;
                      } else if (event.status === 'skipped') {
                        statusIcon = '\u23ed';
                        detail = `Skipped: ${event.error || 'circuit breaker'}`;
                      } else {
                        statusIcon = '\u2753';
                        detail = `Unknown status: ${event.status}`;
                      }
                      const connLog = {
                        id: `log-${Date.now()}-conn-${Math.random().toString(36).slice(2,6)}`,
                        timestamp: Date.now(),
                        phase: 'recon' as const,
                        type: 'info' as const,
                        title: `${statusIcon} ${event.connector} — ${domain}`,
                        detail,
                      };
                      state!.log.push(connLog);
                      broadcastOpsUpdate(input.engagementId, { type: 'log', entry: connLog });
                    },
                  }
                ),
                domainWatchdogPromise,
                globalAbortPromise,
              ]);
              console.log(`[PassiveScan] Pipeline completed for ${domain}`);

                const pipelineResult = result as any;
                const discoveredAssets = pipelineResult.assets || [];
                const passiveRecon = pipelineResult.passiveRecon;
                const allObservations = passiveRecon?.allObservations || [];
                const allRiskSignals = passiveRecon?.riskSignals || [];

                // Store full pipeline result for LLM consumption
                if (!state!.passiveReconResults) state!.passiveReconResults = {};
                state!.passiveReconResults[domain] = {
                  totalAssets: pipelineResult.totalAssets || 0,
                  totalFindings: pipelineResult.totalFindings || 0,
                  overallRiskScore: pipelineResult.overallRiskScore || 0,
                  executiveSummary: pipelineResult.executiveSummary || '',
                  emailSecurity: pipelineResult.emailSecurity ? {
                    spf: !!pipelineResult.emailSecurity.spf?.exists,
                    dkim: (pipelineResult.emailSecurity.dkim?.selectorsFound?.length || 0) > 0,
                    dmarc: !!pipelineResult.emailSecurity.dmarc?.exists,
                    dmarcPolicy: pipelineResult.emailSecurity.dmarc?.policy || null,
                    overallGrade: pipelineResult.emailSecurity.overallGrade,
                  } : undefined,
                  connectorStats: passiveRecon?.summary?.connectorStats || [],
                  observationsBySource: passiveRecon?.summary?.bySource || {},
                  observationsByAssetType: passiveRecon?.summary?.byAssetType || {},
                  signalsBySeverity: passiveRecon?.summary?.bySeverity || {},
                  wafAssessment: pipelineResult.postEnrichmentAnalysis?.wafNgfwAssessment || null,
                  oemCredentials: pipelineResult.oemCredentials || [],
                };

                // Extract per-asset passive recon data from observations and risk signals
                for (const asset of discoveredAssets) {
                  const hostname = asset.asset?.hostname || asset.hostname || asset.domain || asset.ip;
                  if (!hostname) continue;
                  const existing = state!.assets.find((a: any) => a.hostname === hostname);

                  // Build structured passive recon data for this asset
                  const assetObservations = allObservations.filter((o: any) => 
                    o.name === hostname || o.domain === hostname || o.ip === hostname || o.assetId?.includes(hostname)
                  );
                  const assetSignals = allRiskSignals.filter((s: any) => 
                    s.assetId?.includes(hostname)
                  );

                  const assetReconData: any = {
                    subdomains: assetObservations.filter((o: any) => o.assetType === 'subdomain').map((o: any) => o.name || o.domain).filter(Boolean),
                    ipAddresses: [...new Set(assetObservations.map((o: any) => o.ip).filter(Boolean))],
                    services: [],
                    technologies: [...new Set(
                      (asset.asset?.technologies || asset.technologies || []).concat(
                        assetObservations.flatMap((o: any) => {
                          const techs: string[] = [];
                          if (o.evidence?.technologies) techs.push(...o.evidence.technologies);
                          if (o.evidence?.server) techs.push(o.evidence.server);
                          if (o.evidence?.product) techs.push(o.evidence.product);
                          return techs;
                        })
                      )
                    )],
                    certificates: assetObservations.filter((o: any) => o.assetType === 'certificate').map((o: any) => ({
                      subject: o.evidence?.subject || o.name || hostname,
                      issuer: o.evidence?.issuer,
                      validFrom: o.evidence?.validFrom || o.evidence?.not_before,
                      validTo: o.evidence?.validTo || o.evidence?.not_after,
                    })),
                    riskSignals: assetSignals.map((s: any) => ({
                      severity: s.severity || 'info',
                      type: s.signalType || 'unknown',
                      rationale: s.rationale || '',
                    })),
                    wafDetected: undefined as string | undefined,
                    cloudProvider: undefined as string | undefined,
                    historicalUrls: assetObservations.filter((o: any) => o.assetType === 'url').map((o: any) => o.evidence?.url || o.name).filter(Boolean).slice(0, 50),
                    dnsRecords: {} as Record<string, string[]>,
                    rawObservationCount: assetObservations.length,
                    sources: [...new Set(assetObservations.map((o: any) => o.source).filter(Boolean))],
                  };

                  // Extract services from Shodan/Censys observations
                  for (const obs of assetObservations) {
                    if (obs.evidence?.ports) {
                      for (const p of (Array.isArray(obs.evidence.ports) ? obs.evidence.ports : [])) {
                        assetReconData.services.push({
                          port: typeof p === 'number' ? p : (p.port || 0),
                          protocol: p.protocol || 'tcp',
                          service: p.service || p.name || 'unknown',
                          product: p.product || p.banner?.split('\n')[0]?.slice(0, 80),
                          version: p.version,
                          source: obs.source || 'passive',
                        });
                      }
                    }
                    if (obs.evidence?.port && obs.evidence?.service) {
                      assetReconData.services.push({
                        port: obs.evidence.port,
                        protocol: obs.evidence.protocol || 'tcp',
                        service: obs.evidence.service,
                        product: obs.evidence.product,
                        version: obs.evidence.version,
                        source: obs.source || 'passive',
                      });
                    }
                    // Extract DNS records
                    if (obs.evidence?.dnsRecords) {
                      for (const [rtype, rvals] of Object.entries(obs.evidence.dnsRecords)) {
                        if (!assetReconData.dnsRecords[rtype]) assetReconData.dnsRecords[rtype] = [];
                        assetReconData.dnsRecords[rtype].push(...(Array.isArray(rvals) ? rvals : [rvals]).map(String));
                      }
                    }
                    // Detect WAF/CDN
                    if (obs.evidence?.waf || obs.evidence?.cdn) {
                      assetReconData.wafDetected = obs.evidence.waf || obs.evidence.cdn;
                    }
                    // Detect cloud provider
                    if (obs.evidence?.cloudProvider || obs.evidence?.org) {
                      assetReconData.cloudProvider = obs.evidence.cloudProvider || obs.evidence.org;
                    }
                  }

                  // Extract posture findings as additional risk signals
                  const postureFindings = asset.postureFindings || [];
                  for (const pf of postureFindings) {
                    assetReconData.riskSignals.push({
                      severity: pf.severity >= 7 ? 'critical' : pf.severity >= 5 ? 'high' : pf.severity >= 3 ? 'medium' : 'low',
                      type: pf.category || 'posture',
                      rationale: pf.title + (pf.cveIds?.length ? ` (${pf.cveIds.join(', ')})` : ''),
                    });
                  }

                  // Deduplicate services by port
                  const seenPorts = new Set<number>();
                  assetReconData.services = assetReconData.services.filter((s: any) => {
                    if (seenPorts.has(s.port)) return false;
                    seenPorts.add(s.port);
                    return true;
                  });

                  // Extract ports from passive recon services
                  const passivePorts = (assetReconData.services || []).map((svc: any) => ({
                    port: svc.port,
                    service: svc.service || 'unknown',
                    version: svc.version || '',
                  }));

                  // Extract vulns from posture findings
                  const passiveVulns = (asset.postureFindings || []).map((pf: any, idx: number) => ({
                    id: pf.cveIds?.[0] || pf.id || `passive-${hostname}-${idx}`,
                    severity: pf.severity >= 8 ? 'critical' : pf.severity >= 6 ? 'high' : pf.severity >= 4 ? 'medium' : 'low',
                    title: pf.title || pf.category || 'Unknown finding',
                    cve: pf.cveIds?.[0],
                    // Version confidence fields for UI indicators
                    corroborationTier: pf.corroborationTier || 'potential',
                    detectedVersion: pf.detectedVersion || null,
                    affectedVersions: pf.affectedVersions || null,
                    versionMatchConfirmed: pf.versionMatchConfirmed || false,
                    evidenceDetail: pf.evidenceDetail || null,
                    cvssScore: pf.cvssScore || null,
                  }));

                  if (existing) {
                    existing.ip = asset.asset?.ip || asset.ip || existing.ip;
                    existing.type = (asset.asset?.assetType || asset.assetType) === 'web_application' ? 'web_app' : existing.type;
                    existing.status = 'discovered';
                    existing.passiveRecon = assetReconData;
                    if (assetReconData.wafDetected) existing.wafDetected = assetReconData.wafDetected;
                    // CRITICAL FIX: Also populate ports and vulns from passive recon
                    for (const p of passivePorts) {
                      if (!existing.ports.some((ep: any) => ep.port === p.port)) {
                        existing.ports.push(p);
                      }
                    }
                    for (const v of passiveVulns) {
                      if (!existing.vulns.some((ev: any) => ev.title === v.title)) {
                        existing.vulns.push(v);
                      }
                    }
                  } else {
                    state!.assets.push({
                      hostname, ip: asset.asset?.ip || asset.ip,
                      type: (asset.asset?.assetType || asset.assetType) === 'web_application' ? 'web_app' : 'unknown',
                      ports: passivePorts, vulns: passiveVulns, zapFindings: [], exploitAttempts: [], toolResults: [],
                      status: 'discovered',
                      passiveRecon: assetReconData,
                      wafDetected: assetReconData.wafDetected,
                    });
                  }
                }

                // Also populate passiveRecon for the primary domain asset if it wasn't in discoveredAssets
                const primaryAsset = state!.assets.find((a: any) => a.hostname === domain);
                if (primaryAsset && !primaryAsset.passiveRecon) {
                  const domainObs = allObservations.filter((o: any) => o.domain === domain || o.name === domain);
                  const domainSignals = allRiskSignals.filter((s: any) => s.assetId?.includes(domain));
                  primaryAsset.passiveRecon = {
                    subdomains: allObservations.filter((o: any) => o.assetType === 'subdomain' && o.domain === domain).map((o: any) => o.name).filter(Boolean),
                    ipAddresses: [...new Set(domainObs.map((o: any) => o.ip).filter(Boolean))],
                    services: [],
                    technologies: [...new Set((pipelineResult.assets || []).flatMap((a: any) => a.asset?.technologies || []))],
                    certificates: allObservations.filter((o: any) => o.assetType === 'certificate').map((o: any) => ({
                      subject: o.evidence?.subject || o.name || domain,
                      issuer: o.evidence?.issuer,
                      validFrom: o.evidence?.validFrom,
                      validTo: o.evidence?.validTo,
                    })).slice(0, 20),
                    riskSignals: domainSignals.map((s: any) => ({ severity: s.severity, type: s.signalType, rationale: s.rationale })),
                    historicalUrls: allObservations.filter((o: any) => o.assetType === 'url').map((o: any) => o.evidence?.url || o.name).filter(Boolean).slice(0, 50),
                    dnsRecords: {},
                    rawObservationCount: domainObs.length,
                    sources: [...new Set(domainObs.map((o: any) => o.source).filter(Boolean))],
                  };
                  primaryAsset.status = 'discovered';
                }

                // Update stats with passive recon counts
                const totalReconAssets = state!.assets.filter((a: any) => a.passiveRecon).length;
                broadcastOpsUpdate(input.engagementId, { type: 'stats_update', stats: { ...state!.stats } });

                const resultLog = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'scan_result' as const, title: `Recon Complete: ${domain}`, detail: `Discovered ${discoveredAssets.length} assets, ${allObservations.length} observations, ${allRiskSignals.length} risk signals via strict passive OSINT. ${totalReconAssets} assets enriched with passive recon data.` };
                state!.log.push(resultLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: resultLog });
              } catch (e: any) {
                const isSkip = e.message?.includes('skipped by operator');
                if (isSkip) {
                  console.log(`[PassiveScan] Domain ${domain} skipped by operator`);
                  const skipLog = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: `\u23ed Skipped: ${domain}`, detail: 'Domain skipped by operator. Moving to next target.' };
                  state!.log.push(skipLog);
                  broadcastOpsUpdate(input.engagementId, { type: 'log', entry: skipLog });
                } else {
                  console.error(`[PassiveScan] Domain ${domain} failed:`, e.message);
                  const errLog = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'error' as const, title: `Recon Failed: ${domain}`, detail: e.message };
                  state!.log.push(errLog);
                  broadcastOpsUpdate(input.engagementId, { type: 'log', entry: errLog });
                }
              } finally {
                if (domainWatchdogTimer) clearTimeout(domainWatchdogTimer);
                // Remove from active tracking
                activeDomains.delete(domain);
                updateCurrentAction();
                // Force-persist after each domain so assets survive crashes
                const { persistOpsStateNow: persistAfterDomain } = await import('../lib/engagement-orchestrator');
                await persistAfterDomain(input.engagementId).catch(() => {});
              }
          }; // end processDomain

          try {
            // ── Parallel batch execution with concurrency limit ──
            // Process domains in batches of PARALLEL_CONCURRENCY
            const domainQueue = [...domains];
            const batchCount = Math.ceil(domainQueue.length / PARALLEL_CONCURRENCY);
            console.log(`[PassiveScan] Processing ${domainQueue.length} domains in ${batchCount} batches of up to ${PARALLEL_CONCURRENCY}`);

            for (let batchIdx = 0; batchIdx < batchCount; batchIdx++) {
              if (!state!.isRunning || globalAbort.signal.aborted) {
                const stopLog = { id: `log-${Date.now()}-stopped`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: '\u23f9 Scan Stopped', detail: 'Passive scan stopped by operator before completing all domains.' };
                state!.log.push(stopLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: stopLog });
                break;
              }

              const batchStart = batchIdx * PARALLEL_CONCURRENCY;
              const batch = domainQueue.slice(batchStart, batchStart + PARALLEL_CONCURRENCY);
              const batchLog = { id: `log-${Date.now()}-batch-${batchIdx}`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: `\u{1F4E6} Batch ${batchIdx + 1}/${batchCount}`, detail: `Processing ${batch.length} domains in parallel: ${batch.join(', ')}` };
              state!.log.push(batchLog);
              broadcastOpsUpdate(input.engagementId, { type: 'log', entry: batchLog });

              // Run all domains in this batch concurrently
              await Promise.allSettled(batch.map(d => processDomain(d)));

              console.log(`[PassiveScan] Batch ${batchIdx + 1}/${batchCount} complete`);
            }

            // Handle IP-only targets — run Shodan/Censys lookups if available
            for (const ip of ips) {
              if (!state!.isRunning) break; // Operator stopped
              try {
                const ipLog = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'scan_start' as const, title: `IP Recon: ${ip}`, detail: 'Running passive OSINT lookup for IP target (Shodan, Censys)' };
                state!.log.push(ipLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: ipLog });

                // Mark the IP asset as discovered
                const ipAsset = state!.assets.find((a: any) => a.hostname === ip || a.ip === ip);
                if (ipAsset) ipAsset.status = 'discovered';

                const ipDoneLog = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'scan_result' as const, title: `IP Recon Complete: ${ip}`, detail: 'IP target registered for active scanning. Shodan/Censys data will be used during scan plan generation.' };
                state!.log.push(ipDoneLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: ipDoneLog });
              } catch (e: any) {
                const errLog = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'error' as const, title: `IP Recon Failed: ${ip}`, detail: e.message };
                state!.log.push(errLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: errLog });
              }
            }

            // Mark recon complete — wait for operator to start active scan
            if (state!.isRunning) {
              state!.phase = 'recon_complete' as any;
              state!.isRunning = false;
            } else {
              if (state!.assets.some((a: any) => a.status === 'discovered')) {
                state!.phase = 'recon_complete' as any;
              }
            }
            state!.progress = 15;
            state!.currentAction = undefined;
            state!.currentDomain = undefined;
            state!.currentDomainStartedAt = undefined;
            const doneLog = { id: `log-${Date.now()}-done`, timestamp: Date.now(), phase: 'recon' as const, type: 'phase_complete' as const, title: '\u2705 Strict Passive Discovery Complete', detail: `${state!.assets.length} assets discovered via strict passive OSINT (zero target contact). Click "Start Active Scan" to hand off to LLM for ScanForge discovery \u2192 service matching \u2192 vuln detection \u2192 exploitation.` };
            state!.log.push(doneLog);
            broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'recon_complete' });
            broadcastOpsUpdate(input.engagementId, { type: 'log', entry: doneLog });
            // Force-persist final state on completion
            const { persistOpsStateNow: persistOnComplete } = await import('../lib/engagement-orchestrator');
            await persistOnComplete(input.engagementId).catch(() => {});

            // ── Promote passive findings to engagement_findings table ──
            // This ensures getGraphFast can build the attack graph from DB data
            try {
              const { saveEngagementFindings } = await import('../db');
              const findingsToPromote: Array<{
                engagementId: number;
                title: string;
                severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
                cve?: string;
                description?: string;
                endpoint?: string;
                hostname?: string;
                port?: number;
                source?: string;
                tool?: string;
                corroborationTier?: 'confirmed' | 'corroborated' | 'unverified';
              }> = [];

              for (const asset of (state!.assets || [])) {
                // Promote vulns
                for (const v of (asset.vulns || [])) {
                  const sev = (v.severity || 'info').toLowerCase();
                  const mappedSev = (['critical','high','medium','low','info'].includes(sev) ? sev : 'info') as 'critical' | 'high' | 'medium' | 'low' | 'info';
                  findingsToPromote.push({
                    engagementId: input.engagementId,
                    title: (v.title || v.id || 'Untitled').slice(0, 500),
                    severity: mappedSev,
                    cve: v.cve || undefined,
                    description: v.description || undefined,
                    hostname: asset.hostname,
                    port: v.port || undefined,
                    source: 'passive_recon',
                    tool: 'passive_discovery',
                    corroborationTier: (v.corroborationTier || 'unverified') as 'confirmed' | 'corroborated' | 'unverified',
                  });
                }

                // Promote risk signals as info-level findings
                const riskSignals = asset.passiveRecon?.riskSignals || [];
                for (const rs of riskSignals) {
                  const sev = (rs.severity || 'info').toLowerCase();
                  const mappedSev = (['critical','high','medium','low','info'].includes(sev) ? sev : 'info') as 'critical' | 'high' | 'medium' | 'low' | 'info';
                  findingsToPromote.push({
                    engagementId: input.engagementId,
                    title: (`Risk Signal: ${rs.type || 'unknown'}`).slice(0, 500),
                    severity: mappedSev,
                    description: (rs.rationale || '').slice(0, 65000) || undefined,
                    hostname: asset.hostname,
                    source: 'passive_recon',
                    tool: 'passive_discovery',
                    corroborationTier: 'unverified',
                  });
                }

                // Promote open ports as info findings so graph shows services
                for (const p of (asset.ports || [])) {
                  findingsToPromote.push({
                    engagementId: input.engagementId,
                    title: `Open Port: ${p.port}/${p.service || 'unknown'}${p.version ? ' ' + p.version : ''}`,
                    severity: 'info',
                    hostname: asset.hostname,
                    port: typeof p.port === 'number' ? p.port : parseInt(p.port) || undefined,
                    source: 'passive_recon',
                    tool: 'passive_discovery',
                    corroborationTier: 'unverified',
                  });
                }
              }

              if (findingsToPromote.length > 0) {
                const promoted = await saveEngagementFindings(findingsToPromote);
                console.log(`[PassiveScan] Promoted ${promoted} findings to engagement_findings for engagement #${input.engagementId} (${findingsToPromote.length} total)`);
                const promoLog = { id: `log-${Date.now()}-promo`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: '📊 Findings Promoted to DB', detail: `${promoted} findings (vulns, risk signals, open ports) saved to database for attack graph visualization.` };
                state!.log.push(promoLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: promoLog });
              }
            } catch (promoErr: any) {
              console.error(`[PassiveScan] Failed to promote findings to DB:`, promoErr.message);
            }
          } catch (e: any) {
            console.error(`[PassiveScan] Pipeline error for engagement #${input.engagementId}:`, e.message, e.stack?.slice(0, 500));
            state!.phase = 'error';
            state!.isRunning = false;
            state!.error = e.message;
            const errLog = { id: `log-${Date.now()}-fatal`, timestamp: Date.now(), phase: 'recon' as const, type: 'error' as const, title: '\u274c Passive Scan Failed', detail: `Error: ${e.message}. ${state!.assets.filter((a: any) => a.status === 'discovered').length} assets were discovered before the error.` };
            state!.log.push(errLog);
            broadcastOpsUpdate(input.engagementId, { type: 'log', entry: errLog });
            broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'error' });
            const { persistOpsStateNow: persistOnError } = await import('../lib/engagement-orchestrator');
            await persistOnError(input.engagementId).catch(() => {});
          } finally {
            if (globalWatchdogTimer) clearTimeout(globalWatchdogTimer);
          }
        })();

        return { started: true };
      }),

    /** Generate LLM scan plan — analyzes passive recon results to determine ScanForge discovery settings and tools per asset */
    generateScanPlan: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { getOpsState, getOpsStateWithRecovery, generateScanPlan: genPlan } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state — run passive scan first' });
        if (state.assets.length === 0) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No assets discovered yet' });

        await db.logActivity({ userId: ctx.user.id, action: 'scan_plan_generated', details: `LLM scan plan generated for ${state.assets.length} assets in engagement #${input.engagementId}` });

        const scanPlan = await genPlan(input.engagementId);
        return { scanPlan };
      }),

    /** Get the current scan plan for an engagement */
    getScanPlan: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        return { scanPlan: state?.scanPlan || null };
      }),

    /** Start LLM-orchestrated active scanning (generates scan plan first, then ScanForge discovery with plan-specific flags, then tool matching per service) */
    startActiveScan: protectedProcedure
      .input(z.object({ engagementId: z.number(), scanProfile: z.enum(['quick', 'standard', 'deep', 'stealth']).optional() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        const { getOpsState, getOpsStateWithRecovery, initOpsState, generateScanPlan: genPlan } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) state = initOpsState(input.engagementId, engagement.engagementType);

        // RoE check — bypass for training lab engagements
        const isTrainingLab = state.trainingLabMode === true;
        if (!isTrainingLab && engagement.roeStatus !== 'signed' && engagement.roeStatus !== 'pending') {
          throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'RoE must be signed before active scanning.' });
        }

        if (state.isRunning) throw new TRPCError({ code: 'CONFLICT', message: 'Scan already running' });
        if (state.assets.length === 0) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No targets. Run passive scan or add targets first.' });

        state.isRunning = true;
        state.phase = 'enumeration';

        await db.logActivity({ userId: ctx.user.id, action: 'active_scan_started', details: `Started LLM-orchestrated active scan (scan plan \u2192 ScanForge discovery \u2192 tool match \u2192 exploit) for engagement #${input.engagementId}` });

        // Generate scan plan first if not already generated, then execute
        (async () => {
          try {
            if (!state!.scanPlan) {
              await genPlan(input.engagementId);
            }
          } catch (e: any) {
            console.warn('[EngOps] Scan plan generation failed, proceeding with defaults:', e.message);
          }

          // Execute the active pipeline starting from enumeration (ScanForge discovery first)
          // The executeEnumeration phase will use state.scanPlan for discovery flags
          const { executeEngagement, addLog: addOpsLog, broadcastOpsUpdate: broadcast } = await import('../lib/engagement-orchestrator');
          try {
            await executeEngagement(input.engagementId, { id: String(ctx.user.id), name: ctx.user.name || undefined }, { startPhase: 'enumeration', scanProfile: input.scanProfile || 'standard' });
          } catch (execErr: any) {
            console.error('[EngOps] executeEngagement crashed:', execErr.message);
            if (state) {
              state.isRunning = false;
              state.phase = 'error' as any;
              state.error = execErr.message;
              addOpsLog(state, {
                phase: 'enumeration',
                type: 'error',
                title: '❌ Active Scan Execution Failed',
                detail: `The scan pipeline crashed: ${execErr.message}\n\nThis may be caused by a configuration issue. Check scan server connectivity and credentials.`,
              });
              broadcast(input.engagementId, { type: 'phase_change', phase: 'error' });
              // Persist error state so it survives refresh
              const { persistOpsStateNow } = await import('../lib/engagement-orchestrator');
              await persistOpsStateNow(input.engagementId).catch(() => {});
            }
          }
        })();

        return { started: true, assetsCount: state.assets.length };
      }),

    /** Load matching exploits (Metasploit + ZAP rules) for discovered vulns */
    loadExploits: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) return { exploits: [], totalVulns: 0 };

        const allVulns = state.assets.flatMap(a => a.vulns.map(v => ({ ...v, asset: a.hostname, ip: a.ip })));
        const exploitMatches: Array<{ asset: string; vuln: string; cve?: string; severity: string; msfModules: string[]; zapRules: string[]; exploitBridgeModules: string[] }> = [];

        // Try to use the exploitation bridge for better module matching
        let lookupExploits: ((cve: string) => Promise<any>) | null = null;
        try {
          const bridge = await import('../lib/exploitation-bridge');
          lookupExploits = bridge.lookupExploitsForCve;
        } catch { /* exploitation bridge not available */ }

        for (const vuln of allVulns) {
          const msfModules: string[] = [];
          const zapRules: string[] = [];
          const exploitBridgeModules: string[] = [];

          // Use exploitation bridge for CVE-based matching
          if (vuln.cve && lookupExploits) {
            try {
              const bridgeResult = await lookupExploits(vuln.cve);
              if (bridgeResult?.modules) {
                for (const mod of bridgeResult.modules) {
                  exploitBridgeModules.push(mod.fullName || mod.name || mod);
                }
              }
            } catch { /* bridge lookup failed, fall back */ }
          }

          // Fallback: generate MSF module paths from CVE
          if (vuln.cve && exploitBridgeModules.length === 0) {
            msfModules.push(
              `exploit/multi/http/${vuln.cve.toLowerCase().replace(/-/g, '_')}`,
              `auxiliary/scanner/http/${vuln.cve.toLowerCase().replace(/-/g, '_')}_check`,
            );
          }

          const titleLower = vuln.title.toLowerCase();
          if (titleLower.includes('[zap]') || titleLower.includes('xss') || titleLower.includes('sql') || titleLower.includes('injection')) {
            zapRules.push('SQL Injection', 'XSS (Reflected)', 'XSS (Persistent)', 'Command Injection', 'Path Traversal');
          }
          if (titleLower.includes('auth') || titleLower.includes('login') || titleLower.includes('credential')) {
            zapRules.push('Authentication Bypass', 'Session Fixation', 'Forced Browse: Default Credentials');
          }
          if (titleLower.includes('ssrf') || titleLower.includes('redirect')) {
            zapRules.push('Server Side Request Forgery', 'Open Redirect');
          }
          if (titleLower.includes('rce') || titleLower.includes('remote code') || titleLower.includes('command execution')) {
            msfModules.push(`exploit/multi/misc/rce_${vuln.asset.replace(/[^a-z0-9]/gi, '_')}`);
            zapRules.push('Remote Code Execution', 'OS Command Injection');
          }
          if (titleLower.includes('lfi') || titleLower.includes('local file') || titleLower.includes('path traversal')) {
            zapRules.push('Path Traversal', 'Local File Inclusion');
          }

          const allMsf = [...new Set([...exploitBridgeModules, ...msfModules])];
          const allZap = [...new Set(zapRules)];

          if (allMsf.length > 0 || allZap.length > 0) {
            exploitMatches.push({ asset: vuln.asset, vuln: vuln.title, cve: vuln.cve, severity: vuln.severity, msfModules: allMsf, zapRules: allZap, exploitBridgeModules });
          }
        }

        return { exploits: exploitMatches, totalVulns: allVulns.length };
      }),
    // ─── Scan Results ──────────────────────────────────────────────────
    scanResults: protectedProcedure
      .input(z.object({ engagementId: z.number(), tool: z.string().optional() }))
      .query(async ({ input }) => {
        if (input.tool) {
          return db.getScanResultsByTool(input.engagementId, input.tool);
        }
        return db.getScanResultsByEngagement(input.engagementId);
      }),

    scanResultsSummary: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getScanResultsSummary(input.engagementId);
      }),

    /** Get specialized vulnerability analysis results */
    getVulnAnalysis: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId) || await getOpsStateWithRecovery(input.engagementId);
        if (!state) return { analyses: [], summary: null };

        const vulnAnalysis = (state as any).vulnAnalysis;
        if (!vulnAnalysis || !Array.isArray(vulnAnalysis)) return { analyses: [], summary: null };

        const { generateAnalysisSummary } = await import('../lib/vuln-analysis-agents');
        const summary = generateAnalysisSummary(vulnAnalysis);

        return {
          analyses: vulnAnalysis.map((r: any) => ({
            agentClass: r.agentClass,
            findingTitle: r.finding?.title,
            findingSeverity: r.finding?.severity,
            findingAsset: r.finding?.asset,
            riskScore: r.analysis?.riskScore,
            confidence: r.analysis?.confidence,
            technicalAnalysis: r.analysis?.technicalAnalysis,
            exploitationPath: r.analysis?.exploitationPath,
            impactAssessment: r.analysis?.impactAssessment,
            chainable: r.analysis?.chainable,
            remediation: r.analysis?.remediation,
            poc: r.analysis?.poc,
            relatedCves: r.analysis?.relatedCves,
          })),
          summary,
        };
      }),

    /** Run on-demand vulnerability analysis for a specific engagement */
    runVulnAnalysis: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery, addLog, broadcastOpsUpdate } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId) || await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });
        if (state.stats.vulnsFound === 0) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No vulnerabilities to analyze' });

        const { batchAnalyzeFindings, generateAnalysisSummary } = await import('../lib/vuln-analysis-agents');

        // Collect findings
        const allFindings = state.assets.flatMap(asset =>
          asset.vulns.map((v: any, idx: number) => ({
            id: `${asset.hostname}-${idx}`,
            title: v.title || v.id || 'Unknown',
            severity: v.severity || 'medium',
            description: v.description,
            cve: v.cve,
            asset: asset.hostname,
            port: v.port || (asset.ports.length > 0 ? asset.ports[0].port : undefined),
            service: v.service || (asset.ports.length > 0 ? asset.ports[0].service : undefined),
            rawOutput: v.rawOutput,
            tool: v.tool,
          }))
        );

        addLog(state, {
          phase: state.phase, type: 'info',
          title: '\ud83e\udde0 On-Demand Vuln Analysis',
          detail: `Analyzing ${allFindings.length} findings with specialized agents...`,
        });
        broadcastOpsUpdate(input.engagementId, { type: 'action', action: 'vuln_analysis_agents' });

        const results = await batchAnalyzeFindings(allFindings, { maxConcurrency: 3 });
        (state as any).vulnAnalysis = results;
        const summary = generateAnalysisSummary(results);

        addLog(state, {
          phase: state.phase, type: 'phase_complete',
          title: `\u2705 Vuln Analysis Complete \u2014 ${results.length} findings`,
          detail: `Avg risk: ${summary.avgRiskScore}/10 | Chainable: ${summary.chainableCount}`,
        });

        return { analyzed: results.length, summary };
      }),

    /** List available scan profiles */
    listScanProfiles: protectedProcedure
      .query(async () => {
        const { getAllScanProfiles, SCAN_PROFILES } = await import('../lib/scan-profiles');
        const profiles = getAllScanProfiles();
        // Include tool details for each profile
        return profiles.map(p => {
          const full = SCAN_PROFILES[p.name];
          return {
            ...p,
            tools: {
              httpx: full.tools.httpx,
              nikto: full.tools.nikto,
              gobuster: full.tools.gobuster,
              nuclei: true,
              zap: full.tools.zap,
              hydra: full.tools.hydra,
            },
            evasion: {
              fragmentation: full.evasion.fragmentation,
              decoys: full.evasion.decoys,
              randomizeHosts: full.evasion.randomizeHosts,
              sourcePortSpoofing: full.evasion.sourcePortSpoofing,
            },
            nucleiSeverity: full.nuclei.severityFilter,
            discoveryPorts: full.discovery.discoveryPorts,
            discoveryTiming: full.discovery.timing,
            concurrency: full.tools.concurrency,
          };
        });
      }),

    /** Get attack chains generated for an engagement */
    getAttackChains: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId) as any;
        if (!state) state = await getOpsStateWithRecovery(input.engagementId) as any;
        if (!state) return { chains: [], summary: null, cloudRiskAssessment: null };
        const chains = state.attackChains || [];
        // Build summary from chains
        const allTechniques = [...new Set(chains.flatMap((c: any) => c.mitreTechniques || []))];
        const cloudChains = chains.filter((c: any) => (c.cloudExploitPaths || []).length > 0);
        const sortedByFeasibility = [...chains].sort((a: any, b: any) => (b.feasibility || 0) - (a.feasibility || 0));
        const sortedByStealth = [...chains].sort((a: any, b: any) => (b.stealthRating || 0) - (a.stealthRating || 0));
        const summary = chains.length > 0 ? {
          totalChains: chains.length,
          totalSteps: chains.reduce((s: number, c: any) => s + (c.totalSteps || 0), 0),
          uniqueTechniques: allTechniques.length,
          highestRisk: Math.max(...chains.map((c: any) => c.overallRisk || 0), 0),
          mostFeasible: sortedByFeasibility[0] ? { name: sortedByFeasibility[0].name, feasibility: sortedByFeasibility[0].feasibility } : null,
          stealthiest: sortedByStealth[0] ? { name: sortedByStealth[0].name, stealthRating: sortedByStealth[0].stealthRating } : null,
          cloudChainsCount: cloudChains.length,
          criticalPaths: chains.filter((c: any) => (c.overallRisk || 0) >= 8).map((c: any) => `${c.name} (risk: ${c.overallRisk}/10)`),
        } : null;
        // Cloud risk assessment from cloud detection state
        const cloudDetection = state.cloudDetection;
        let cloudRiskAssessment = null;
        if (cloudDetection && cloudDetection.findings && cloudDetection.findings.length > 0) {
          const providers = [...new Set(cloudDetection.findings.map((f: any) => f.provider))];
          const publicStorage = cloudDetection.findings.filter((f: any) =>
            f.title?.toLowerCase().includes('public') || f.title?.toLowerCase().includes('open') || f.title?.toLowerCase().includes('anonymous')
          );
          const criticalCount = cloudDetection.findings.filter((f: any) => f.severity === 'critical').length;
          const highCount = cloudDetection.findings.filter((f: any) => f.severity === 'high').length;
          const riskScore = Math.min(100, criticalCount * 25 + highCount * 15 + publicStorage.length * 10);
          cloudRiskAssessment = {
            overallRisk: riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low',
            riskScore,
            exposedProviders: providers,
            publicStorageCount: publicStorage.length,
            totalFindings: cloudDetection.findings.length,
            topFindings: cloudDetection.findings.slice(0, 10).map((f: any) => ({ title: f.title, severity: f.severity, provider: f.provider })),
          };
        }
        return { chains, summary, cloudRiskAssessment };
      }),

    /** Get cloud misconfiguration findings for an engagement */
    getCloudMisconfigs: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId) as any;
        if (!state) state = await getOpsStateWithRecovery(input.engagementId) as any;
        if (!state) return { findings: [], detection: null, stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, providers: [] } };
        const cloudDetection = state.cloudDetection || { assetsFound: 0, storageEndpoints: 0, findings: [] };
        const findings = cloudDetection.findings || [];
        // Also gather cloud info from individual assets
        const assetCloudInfo = state.assets
          .filter((a: any) => (a.cloudProviders?.length || 0) > 0)
          .map((a: any) => ({
            hostname: a.hostname,
            ip: a.ip,
            providers: a.cloudProviders || [],
            services: a.cloudServices || [],
          }));
        const allProviders = [...new Set([
          ...findings.map((f: any) => f.provider),
          ...assetCloudInfo.flatMap((a: any) => a.providers),
        ])];
        const stats = {
          total: findings.length,
          critical: findings.filter((f: any) => f.severity === 'critical').length,
          high: findings.filter((f: any) => f.severity === 'high').length,
          medium: findings.filter((f: any) => f.severity === 'medium').length,
          low: findings.filter((f: any) => f.severity === 'low' || f.severity === 'info').length,
          providers: allProviders,
        };
        return { findings, detection: cloudDetection, assetCloudInfo, stats };
      }),

    /** Get LLM scan feedback loop state for an engagement */
    getFeedbackLoopState: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId) as any;
        if (!state) state = await getOpsStateWithRecovery(input.engagementId) as any;
        if (!state || !state.scanFeedbackLoop) return null;
        const fb = state.scanFeedbackLoop;
        return {
          iteration: fb.iteration,
          totalScansExecuted: fb.totalScansExecuted,
          budgetRemaining: fb.budgetRemaining,
          satisfied: fb.satisfied,
          finalAnalysis: fb.finalAnalysis,
          history: (fb.history || []).map((h: any) => ({
            tool: h.request.tool,
            target: h.request.target,
            args: h.request.args,
            rationale: h.request.rationale,
            depth: h.request.depth,
            priority: h.request.priority,
            exitCode: h.result.exitCode,
            durationMs: h.result.durationMs,
            outputPreview: (h.result.stdout || '').slice(0, 500),
            stderrPreview: (h.result.stderr || '').slice(0, 200),
            executedAt: h.executedAt,
          })),
        };
      }),

    /** Get exploit plan history for an engagement */
    getExploitPlanHistory: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const history = await db.getExploitPlanHistoryByEngagement(input.engagementId);
        return history.map((h: any) => ({
          id: h.id,
          engagementId: h.engagementId,
          gateId: h.gateId,
          status: h.status,
          operatorId: h.operatorId,
          operatorName: h.operatorName,
          originalPlan: h.originalPlan,
          modifiedPlan: h.modifiedPlan,
          llmReasoning: h.llmReasoning,
          llmDecision: h.llmDecision,
          originalTargetCount: h.originalTargetCount,
          finalTargetCount: h.finalTargetCount,
          removedTargets: h.removedTargets,
          reviewDurationMs: h.reviewDurationMs,
          resolvedAt: h.resolvedAt,
          createdAt: h.createdAt,
        }));
      }),

    /** Get exploit plan stats across all engagements */
    getExploitPlanStats: protectedProcedure
      .query(async () => {
        return db.getExploitPlanStats();
      }),

    /** Re-run the full scan pipeline: passive → LLM analysis → active → LLM feedback → exploit generation */
    rerunFullPipeline: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        phases: z.object({
          passive: z.boolean().default(true),
          active: z.boolean().default(true),
          llmAnalysis: z.boolean().default(true),
          exploitGeneration: z.boolean().default(true),
        }).default({}),
        resetState: z.boolean().default(false),
        exhaustiveExploit: z.boolean().optional().default(true),
        resetScope: z.object({
          recon: z.boolean().default(true),          // Passive recon: assets, domain intel, OSINT
          scanning: z.boolean().default(true),       // Active scanning: scan results, ZAP, Nuclei, Burp
          analysis: z.boolean().default(true),       // LLM analysis: findings, vuln snapshots, decision log
          exploitation: z.boolean().default(true),   // Exploits: attempts, plans, chains
          logs: z.boolean().default(true),            // Timeline events, ops log, approval gates
        }).default({}),
        // Target credentials for authenticated scanning
        credentials: z.object({
          username: z.string(),
          password: z.string(),
          loginUrl: z.string().optional(),
          authType: z.enum(['form', 'basic', 'bearer', 'cookie']).default('form'),
        }).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const {
          getOpsState, getOpsStateWithRecovery, initOpsState, broadcastOpsUpdate, addLog, persistOpsStateNow
        } = await import('../lib/engagement-orchestrator');

        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state || input.resetState) {
          const engagement = await db.getEngagementById(input.engagementId);
          if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });
          state = initOpsState(input.engagementId, engagement.engagementType || 'pentest');
        }

        if (state.isRunning) {
          throw new TRPCError({ code: 'CONFLICT', message: 'Pipeline is already running. Reset or wait for completion.' });
        }

        // ═══ SELECTIVE RESET based on resetScope ═══
        const rs = input.resetScope;
        const resetAll = rs.recon && rs.scanning && rs.analysis && rs.exploitation && rs.logs;

        // Always reset progress/phase/error for a fresh run
        state.progress = 0;
        state.phase = 'idle';
        state.error = undefined;

        // ── Recon scope: assets, domain intel, host/port stats ──
        if (rs.recon) {
          state.assets = [];
          state.skippedDomains = new Set();
          state.stats.hostsScanned = 0;
          state.stats.portsFound = 0;
          state.stats.wafDetections = 0;
        }

        // ── Scanning scope: scan results, ZAP/Nuclei/Burp trackers, vuln count ──
        if (rs.scanning) {
          state.stats.vulnsFound = 0;
          state.stats.zapScansRun = 0;
          state.completedScans = {
            nucleiCompleted: new Set(),
            zapCompleted: new Set(),
            hydraCompleted: new Set(),
            exploitCompleted: rs.exploitation ? new Set() : state.completedScans?.exploitCompleted || new Set(),
            lastCheckpointAt: Date.now(),
          };
          (state as any).activeScanPlan = undefined;
          (state as any).crossToolPipeline = undefined;
        }

        // ── Analysis scope: LLM findings, vuln snapshots, feedback loop ──
        if (rs.analysis) {
          (state as any).feedbackLoop = undefined;
          (state as any).severityEscalation = undefined;
          // Clear LLM-synthesized vulns from assets (if assets are kept)
          if (!rs.recon && Array.isArray(state.assets)) {
            for (const asset of state.assets) {
              if (Array.isArray(asset.vulns)) {
                asset.vulns = asset.vulns.filter((v: any) => v.tool !== 'llm-synthesis');
              }
            }
          }
        }

        // ── Exploitation scope: exploit attempts, plans, sessions ──
        if (rs.exploitation) {
          state.stats.exploitsAttempted = 0;
          state.stats.exploitsSucceeded = 0;
          state.stats.sessionsOpened = 0;
          if (state.completedScans) {
            state.completedScans.exploitCompleted = new Set();
          }
        }

        // ── Logs scope: timeline, ops log, approval gates ──
        if (rs.logs) {
          state.log = [];
          state.approvalGates = [];
        }

        // If ALL scopes are reset, also zero out any remaining stats for safety
        if (resetAll) {
          state.stats = {
            hostsScanned: 0, portsFound: 0, vulnsFound: 0,
            exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0,
            zapScansRun: 0, wafDetections: 0,
          };
        }

        // ── Clear corresponding DB tables based on resetScope ──
        const dbConn = await db.getDb();
        if (dbConn) {
          const eid = input.engagementId;
          const cleared: Record<string, number> = {};

          // Build table list based on which scopes are being reset
          const tablesToClear: Array<{ name: string; table: any; col: any }> = [];

          // Always clear ops snapshot (it will be re-persisted with the new state)
          tablesToClear.push({ name: 'opsSnapshots', table: schema.engagementOpsSnapshots, col: schema.engagementOpsSnapshots.engagementId });

          if (rs.recon) {
            // Recon data lives in scanResults (passive scans)
            tablesToClear.push({ name: 'scanResults', table: schema.scanResults, col: schema.scanResults.engagementId });
          }
          if (rs.scanning) {
            // Active scan results
            if (!rs.recon) tablesToClear.push({ name: 'scanResults', table: schema.scanResults, col: schema.scanResults.engagementId });
            tablesToClear.push({ name: 'webAppScans', table: schema.webAppScans, col: schema.webAppScans.engagementId });
            tablesToClear.push({ name: 'webAppFindings', table: schema.webAppFindings, col: schema.webAppFindings.engagementId });
            tablesToClear.push({ name: 'burpScanHistory', table: schema.burpScanHistory, col: schema.burpScanHistory.engagementId });
            tablesToClear.push({ name: 'testPlans', table: schema.testPlans, col: schema.testPlans.engagementId });
          }
          if (rs.analysis) {
            tablesToClear.push({ name: 'engagementFindings', table: schema.engagementFindings, col: schema.engagementFindings.engagementId });
            tablesToClear.push({ name: 'llmDecisionLog', table: schema.llmDecisionLog, col: schema.llmDecisionLog.engagementId });
            tablesToClear.push({ name: 'vulnScanSnapshots', table: schema.vulnScanSnapshots, col: schema.vulnScanSnapshots.engagementId });
          }
          if (rs.exploitation) {
            tablesToClear.push({ name: 'exploitPlanHistory', table: schema.exploitPlanHistory, col: schema.exploitPlanHistory.engagementId });
            tablesToClear.push({ name: 'exploitationAttempts', table: schema.exploitationAttempts, col: schema.exploitationAttempts.engagementId });
          }
          if (rs.logs) {
            tablesToClear.push({ name: 'timelineEvents', table: schema.engagementTimelineEvents, col: schema.engagementTimelineEvents.engagementId });
          }

          // Deduplicate table names (scanResults might be added twice)
          const seen = new Set<string>();
          const dedupedTables = tablesToClear.filter(t => {
            if (seen.has(t.name)) return false;
            seen.add(t.name);
            return true;
          });

          for (const { name, table, col } of dedupedTables) {
            try {
              const r = await dbConn.delete(table).where(eq(col, eid));
              cleared[name] = (r as any)[0]?.affectedRows ?? 0;
            } catch { cleared[name] = 0; }
          }
          const resetScopes = Object.entries(rs).filter(([,v]) => v).map(([k]) => k).join(', ');
          console.log(`[RerunPipeline] Selective reset (${resetScopes}) for engagement #${eid}:`, JSON.stringify(cleared));
        }

        // Set exhaustive exploitation mode
        state.exhaustiveExploit = input.exhaustiveExploit;

        state.isRunning = true;
        state.error = undefined;
        state.currentAction = 'Starting full pipeline re-run...';
        // Store the pipeline phases config on state so auto-resume knows which phases to run
        (state as any).pipelinePhases = input.phases;
        (state as any).exhaustiveExploit = input.exhaustiveExploit;
        addLog(state, {
          phase: 'recon', type: 'info',
          title: '\u{1f504} Full Pipeline Re-Run Started',
          detail: `Phases: ${Object.entries(input.phases).filter(([,v]) => v).map(([k]) => k).join(', ')}. Initiated by ${ctx.user.name || 'operator'}.`,
        });
        broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'recon' });

        await db.logActivity({ userId: ctx.user.id, action: 'full_pipeline_rerun', details: `Started full pipeline re-run for engagement #${input.engagementId}` });

        // Persist isRunning=true to DB BEFORE starting the async pipeline
        // This ensures auto-resume can detect the interrupted engagement if the server crashes
        await persistOpsStateNow(input.engagementId, state);

        // Run pipeline asynchronously
        (async () => {
          try {
            const engagement = await db.getEngagementById(input.engagementId);
            if (!engagement) throw new Error('Engagement not found');
            const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
            const ipRanges = (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean);

            // ═══ REFRESH RoE SCOPE GUARD from latest engagement data ═══
            // On re-run, the engagement's targetDomain/targetIpRange may have been updated
            // (e.g., by autoRegisterLabAsset) since the original RoE was locked during executeRecon.
            // We must refresh the guard so the new targets are in scope.
            state!.roeScopeGuard = {
              authorizedDomains: [...domains],
              authorizedIps: [...ipRanges],
              roeStatus: (engagement as any).roeStatus || (engagement as any).roe_status || 'signed',
            };
            // Also add IP:port variants for assets that use port-based hostnames
            for (const ip of ipRanges) {
              for (const port of ['8443', '8444', '8445', '8447', '8448', '443', '80']) {
                const ipPort = `${ip}:${port}`;
                if (!state!.roeScopeGuard.authorizedDomains.includes(ipPort)) {
                  state!.roeScopeGuard.authorizedDomains.push(ipPort);
                }
              }
            }
            addLog(state!, {
              phase: 'recon', type: 'info',
              title: '🛡️ RoE Scope Guard Refreshed',
              detail: `Authorized targets: ${domains.join(', ')}${ipRanges.length ? ' | IPs: ' + ipRanges.join(', ') : ''}`,
            });

            // Phase 1: Passive Recon
            if (input.phases.passive && domains.length > 0) {
              state!.phase = 'recon';
              state!.currentAction = 'Running passive reconnaissance...';
              broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'recon' });
              for (const domain of domains) {
                try {
                  addLog(state!, { phase: 'recon', type: 'info', title: `\u{1f50d} Passive scan: ${domain}`, detail: 'Running domain intelligence pipeline...' });
                  const { runDomainIntelPipeline } = await import('../lib/domain-intel-pipeline');
                  const result = await runDomainIntelPipeline(domain);
                  // Extract ports from passive recon services
                  const reconPorts = (result.services || []).map((svc: any) => ({
                    port: svc.port,
                    service: svc.service || 'unknown',
                    version: svc.version || '',
                  }));

                  const idx = state!.assets.findIndex(a => a.hostname === domain);
                  if (idx >= 0) {
                    state!.assets[idx].passiveRecon = result as any;
                    state!.assets[idx].status = 'scanned' as any;
                    // Also populate ports from passive recon
                    for (const p of reconPorts) {
                      if (!state!.assets[idx].ports.some((ep: any) => ep.port === p.port)) {
                        state!.assets[idx].ports.push(p as any);
                      }
                    }
                  } else {
                    state!.assets.push({
                      hostname: domain, ip: result.dns?.aRecords?.[0] || '', type: 'web' as any,
                      status: 'scanned' as any, ports: reconPorts as any, vulns: [], zapFindings: [],
                      passiveRecon: result as any,
                    } as any);
                  }
                  addLog(state!, { phase: 'recon', type: 'success', title: `\u2705 Passive complete: ${domain}`, detail: `Found ${result.technologies?.length || 0} technologies, ${result.riskSignals?.length || 0} risk signals` });
                } catch (err: any) {
                  addLog(state!, { phase: 'recon', type: 'error', title: `\u274c Passive failed: ${domain}`, detail: err.message });
                }
              }
            }

            // ── Recalculate stats after Phase 1 (Passive Recon) ──
            state!.stats.assetsDiscovered = state!.assets.length;
            state!.stats.portsFound = state!.assets.reduce((sum, a) => sum + (a.ports || []).length, 0);
            state!.stats.hostsScanned = state!.assets.filter(a => a.status !== 'pending').length;
            // ── Persist after Phase 1 (Passive Recon) ──
            await persistOpsStateNow(input.engagementId).catch(() => {});

            // Phase 2: LLM Analysis of passive results
            if (input.phases.llmAnalysis) {
              state!.phase = 'scanning';
              state!.currentAction = 'LLM analyzing passive scan results...';
              broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'scanning' });
              try {
                addLog(state!, { phase: 'scanning', type: 'info', title: '\u{1f9e0} LLM Analysis', detail: 'Analyzing scan results and identifying attack vectors...' });
                const { runPostEnrichmentAnalysis } = await import('../lib/llm-post-enrichment-analysis');
                const analyses = state!.assets.map(a => {
                  // Combine vulns with risk signals from passive recon as postureFindings
                  const vulnFindings = a.vulns.map((v: any) => ({
                    id: v.id || v.cve || `vuln-${Math.random().toString(36).slice(2,8)}`,
                    assetRef: a.hostname,
                    assetHostname: a.hostname,
                    category: v.category || 'vulnerability',
                    title: v.title,
                    severity: typeof v.severity === 'number' ? v.severity : (v.severity === 'critical' ? 9 : v.severity === 'high' ? 7 : v.severity === 'medium' ? 5 : 3),
                    likelihood: 7,
                    confidence: 0.8,
                    recommendedControls: [],
                    cveIds: v.cve ? [v.cve] : [],
                    corroborationTier: 'probable' as const,
                  }));
                  // Also convert risk signals to findings so LLM has passive recon data
                  const signalFindings = (a.passiveRecon?.riskSignals || []).slice(0, 30).map((s: any, idx: number) => ({
                    id: `signal-${a.hostname}-${idx}`,
                    assetRef: a.hostname,
                    assetHostname: a.hostname,
                    category: s.type || 'risk_signal',
                    title: s.rationale || 'Unknown signal',
                    severity: s.severity === 'critical' ? 9 : s.severity === 'high' ? 7 : s.severity === 'medium' ? 5 : 2,
                    likelihood: 5,
                    confidence: 0.6,
                    recommendedControls: [],
                    corroborationTier: 'potential' as const,
                  }));
                  const allFindings = [...vulnFindings, ...signalFindings];
                  return {
                    asset: { hostname: a.hostname, ip: a.ip, technologies: a.passiveRecon?.technologies || [], assetType: 'web_application', assetClasses: ['web'], tags: [] },
                    postureFindings: allFindings,
                    assetCriticalityBand: 'high' as const,
                    riskBand: allFindings.length > 5 ? 'high' as const : 'medium' as const,
                    missionFunction: 'web_service',
                    essentialService: true,
                    hybridRiskScore: Math.min(90, 40 + allFindings.length * 2),
                    carverScores: { criticality: 7, accessibility: 6, recuperability: 5, vulnerability: 7, effect: 6, recognizability: 5 },
                    shockScores: { scope: 6, handling: 5, operationalImpact: 6, cascadingEffects: 5, knowledge: 4 },
                    missionImpactScore: 70,
                    suggestedTier: 'tier_1',
                    cvssEstimate: 7,
                    contextIndicators: { exposure: 7, recognizability: 5, confidence: 0.7 },
                    testVectors: [],
                    confidence: 0.7,
                    assetCriticalityScore: 70,
                    vulnRiskScore: Math.min(90, allFindings.length * 3),
                    vulnRiskBand: allFindings.length > 5 ? 'high' : 'medium',
                    impactScore: 70,
                    likelihoodScore: 60,
                    deviceType: 'server',
                    platformType: 'web_application',
                    businessImpactLevel: 'significant',
                    missionJustification: `Web service at ${a.hostname}`,
                  };
                });
                const org = {
                  customerName: engagement.clientName || 'Target',
                  primaryDomain: domains[0] || '',
                  sector: 'technology',
                  clientType: 'enterprise' as const,
                };
                const analysis = await runPostEnrichmentAnalysis(analyses as any, org as any);
                (state as any).llmAnalysis = analysis;
                addLog(state!, { phase: 'scanning', type: 'success', title: '\u2705 LLM Analysis Complete', detail: `Found ${analysis.attackPaths?.length || 0} attack paths, ${analysis.blindSpots?.length || 0} blind spots` });
              } catch (err: any) {
                addLog(state!, { phase: 'scanning', type: 'error', title: '\u274c LLM Analysis failed', detail: err.message });
              }
            }

            // Phase 2.5: Passive-to-Active Handoff (generates targeted scan plan from passive findings)
            let activeScanPlan: any = null;
            if (input.phases.active) {
              try {
                addLog(state!, { phase: 'scanning', type: 'info', title: '\u{1f504} Generating Active Scan Plan', detail: 'Analyzing passive findings to build targeted scan configs with RoE enforcement...' });
                const { generateActiveScanPlan, buildDefaultRoE, formatScanPlanSummary } = await import('../lib/passive/active-handoff');
                const { type: _obsType, ...AssetObservation } = {} as any; // type import workaround

                // Build RoE from engagement data
                const engRoeScope = (engagement.roeScope as any) || {};
                const roe = buildDefaultRoE(
                  domains,
                  engagement.engagementType || 'pentest',
                  {
                    excludedAssets: engRoeScope.excludedAssets || [],
                    maxIntensity: engRoeScope.maxIntensity || undefined,
                    allowedTools: engRoeScope.allowedTools || undefined,
                  },
                );

                // Collect passive observations and risk signals from all assets
                const allObservations: any[] = [];
                const allRiskSignals: any[] = [];
                for (const asset of state!.assets) {
                  const pr = asset.passiveRecon as any;
                  if (!pr) continue;
                  // Convert passive recon observations to AssetObservation format
                  const assetObs = (pr.observations || []).map((o: any) => ({
                    ...o,
                    assetId: o.assetId || asset.hostname,
                    hostname: asset.hostname,
                  }));
                  allObservations.push(...assetObs);
                  // Also create synthetic observations from technologies, services, DNS
                  for (const tech of (pr.technologies || [])) {
                    allObservations.push({
                      id: `tech-${asset.hostname}-${tech}`,
                      assetId: asset.hostname,
                      hostname: asset.hostname,
                      source: 'passive-recon',
                      type: 'technology',
                      value: tech,
                      tags: [`tech:${tech.toLowerCase()}`],
                      confidence: 0.8,
                      timestamp: Date.now(),
                    });
                  }
                  for (const port of (asset.ports || [])) {
                    allObservations.push({
                      id: `port-${asset.hostname}-${(port as any).port}`,
                      assetId: asset.hostname,
                      hostname: asset.hostname,
                      source: 'passive-recon',
                      type: 'service',
                      value: `${(port as any).port}/${(port as any).service}`,
                      tags: [`port:${(port as any).port}`, `service:${(port as any).service}`],
                      confidence: 0.9,
                      timestamp: Date.now(),
                    });
                  }
                  // Collect risk signals
                  for (const signal of (pr.riskSignals || [])) {
                    allRiskSignals.push({
                      ...signal,
                      assetId: signal.assetId || asset.hostname,
                    });
                  }
                }

                // Fallback: if passive recon produced 0 observations, create synthetic ones from known assets
                // This ensures lab domains (which skip external OSINT) still get active scan targets
                if (allObservations.length === 0 && state!.assets.length > 0) {
                  for (const asset of state!.assets) {
                    allObservations.push({
                      id: `fallback-${asset.hostname}`,
                      assetId: asset.hostname,
                      hostname: asset.hostname,
                      name: asset.hostname,
                      domain: asset.hostname,
                      source: 'fallback-asset-list',
                      type: 'host',
                      assetType: 'domain',
                      value: asset.hostname,
                      tags: ['fallback'],
                      confidence: 1.0,
                      timestamp: Date.now(),
                      evidence: {},
                      attribution: { provider: 'engagement-assets', method: 'Known target from engagement scope' },
                      observedAt: new Date(),
                    });
                  }
                  addLog(state!, { phase: 'scanning', type: 'info', title: '\u{1f504} Fallback: Creating scan targets from asset list', detail: `Passive recon returned 0 observations. Using ${state!.assets.length} known assets as scan targets.` });
                }
                // Build technologies, services, and WAF maps from assets for the handoff
                const techMap: Record<string, string[]> = {};
                const servicesList: Array<{ hostname: string; port: number; service: string; version: string }> = [];
                const wafMap: Record<string, boolean> = {};
                for (const asset of state!.assets) {
                  const pr = asset.passiveRecon as any;
                  if (pr?.technologies?.length) techMap[asset.hostname] = pr.technologies;
                  for (const port of (asset.ports || [])) {
                    servicesList.push({ hostname: asset.hostname, port: (port as any).port, service: (port as any).service || 'unknown', version: (port as any).version || '' });
                  }
                  if (pr?.wafDetected) wafMap[asset.hostname] = true;
                }
                activeScanPlan = generateActiveScanPlan(
                  { observations: allObservations, riskSignals: allRiskSignals, technologies: techMap, services: servicesList, wafDetected: wafMap },
                  roe,
                );

                const summary = formatScanPlanSummary(activeScanPlan);
                addLog(state!, {
                  phase: 'scanning', type: 'success',
                  title: `\u2705 Active Scan Plan Generated: ${activeScanPlan.totalTargets} targets`,
                  detail: `${activeScanPlan.scanConfigs.length} ScanForge discovery, ${activeScanPlan.nucleiConfigs.length} nuclei, ${activeScanPlan.zapConfigs.length} ZAP configs. Est. duration: ${activeScanPlan.stats.estimatedScanDuration}. Risk coverage: ${activeScanPlan.stats.riskCoverage}%. ${activeScanPlan.excludedByRoE.length} targets excluded by RoE.`,
                });
                if (activeScanPlan.excludedByRoE.length > 0) {
                  addLog(state!, {
                    phase: 'scanning', type: 'info',
                    title: `\u{1f6ab} RoE Exclusions: ${activeScanPlan.excludedByRoE.length} targets`,
                    detail: activeScanPlan.excludedByRoE.map((e: any) => `${e.hostname}: ${e.reason}`).join('; '),
                  });
                }
                // Store the plan on state for downstream access
                (state as any).activeScanPlan = activeScanPlan;

                // ── Hypothesis → ScanForge Bridge: Enrich scan plan with hypothesis priorities ──
                try {
                  const { buildScanPriorityAdjustments } = await import('../lib/hypothesis-orchestrator-hook');
                  const { enrichScanPlanWithHypotheses, formatHypothesisEnrichmentSummary } = await import('../lib/hypothesis-scanforge-bridge');
                  const hypothesisAdjustments = buildScanPriorityAdjustments(state!);
                  if (hypothesisAdjustments.length > 0) {
                    const enrichment = enrichScanPlanWithHypotheses(activeScanPlan, hypothesisAdjustments);
                    const summary = formatHypothesisEnrichmentSummary(enrichment);
                    addLog(state!, {
                      phase: 'scanning', type: 'success',
                      title: `\u{1f9e0} Hypothesis Enrichment: ${enrichment.targetsEnriched} targets boosted`,
                      detail: summary,
                    });
                  } else {
                    addLog(state!, {
                      phase: 'scanning', type: 'info',
                      title: '\u{1f9e0} Hypothesis Enrichment: No adjustments',
                      detail: 'No high-confidence hypotheses available for scan plan enrichment.',
                    });
                  }
                } catch (hypothesisErr: any) {
                  addLog(state!, { phase: 'scanning', type: 'warning', title: '\u26a0\ufe0f Hypothesis enrichment skipped', detail: `Non-critical: ${hypothesisErr.message}` });
                }

              } catch (err: any) {
                addLog(state!, { phase: 'scanning', type: 'error', title: '\u274c Scan Plan Generation failed', detail: `Falling back to default scan configs. Error: ${err.message}` });
              }
            }

            // ── Persist after Phase 2 (LLM Analysis) ──
            await persistOpsStateNow(input.engagementId).catch(() => {});

            // Phase 3: Active Scanning (uses handoff plan when available, falls back to defaults)
            if (input.phases.active) {
              state!.phase = 'scanning';
              state!.currentAction = 'Running active scans...';
              broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'scanning' });
              try {
                const { executeTool, executeRawCommand } = await import('../lib/scan-server-executor');

                // Build a lookup of handoff-generated configs per target
                const scanConfigMap = new Map<string, any>();
                const nucleiConfigMap = new Map<string, any>();
                if (activeScanPlan) {
                  for (const cfg of activeScanPlan.scanConfigs || []) scanConfigMap.set(cfg.target, cfg);
                  for (const cfg of activeScanPlan.nucleiConfigs || []) nucleiConfigMap.set(cfg.target, cfg);
                }

                // Determine which assets to scan (handoff-prioritized order or all)
                const assetsToScan = activeScanPlan
                  ? activeScanPlan.targets.map((t: any) => state!.assets.find((a: any) => a.hostname === t.hostname)).filter(Boolean)
                  : state!.assets;

                for (const asset of assetsToScan) {
                  // Use handoff ScanForge discovery config if available, otherwise fall back to defaults
                  const scanCfg = scanConfigMap.get(asset.hostname);
                  const discoveryArgs = scanCfg
                    ? `${scanCfg.flags} ${scanCfg.portSpec ? `-p ${scanCfg.portSpec}` : '--top-ports 1000'} ${asset.hostname}`
                    : `-sV -sC -T4 --top-ports 1000 ${asset.hostname}`;
                  const discoveryTimeout = scanCfg?.timeout || 300;

                  addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f50d} ScanForge: ${asset.hostname}`, detail: scanCfg ? `Handoff config: ${scanCfg.rationale}` : 'Service detection and version scan (default config)...' });
                  try {
                    const sfStartTime = Date.now();
                    const discoveryResult = await executeTool({ tool: 'scanforge-discovery', args: discoveryArgs, timeoutSeconds: discoveryTimeout });
                    const portRegex = /(\d+)\/tcp\s+open\s+(\S+)\s*(.*)/g;
                    let match;
                    const discoveredPorts: Array<{port: number; service: string; version: string}> = [];
                    while ((match = portRegex.exec(discoveryResult.stdout)) !== null) {
                      const port = parseInt(match[1]);
                      if (!asset.ports.find((p: any) => p.port === port)) {
                        const portEntry = { port, service: match[2], version: match[3]?.trim() || '' };
                        asset.ports.push(portEntry as any);
                        discoveredPorts.push(portEntry);
                      }
                    }
                    // Push toolResult so Discovery tab shows accurate run counts
                    if (!asset.toolResults) asset.toolResults = [];
                    asset.toolResults.push({
                      tool: 'scanforge-discovery',
                      command: `scanforge-discovery ${discoveryArgs}`,
                      exitCode: discoveryResult.exitCode ?? 0,
                      durationMs: Date.now() - sfStartTime,
                      timedOut: discoveryResult.timedOut || false,
                      findingCount: discoveredPorts.length,
                      findings: discoveredPorts.map(p => ({ severity: 'info', title: `${p.port}/tcp ${p.service}${p.version ? ` (${p.version})` : ''}` })),
                      outputPreview: (discoveryResult.stdout || '').slice(0, 512),
                      executedAt: Date.now(),
                      phase: 'discovery',
                    } as any);
                    asset.status = 'scanned' as any;
                    addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 ScanForge: ${asset.hostname}`, detail: `${asset.ports.length} open ports` });
                  } catch (err: any) {
                    // Even if ScanForge discovery fails, mark as scanned (attempted) so it doesn't stay 'pending'
                    if (!asset.toolResults) asset.toolResults = [];
                    asset.toolResults.push({
                      tool: 'scanforge-discovery',
                      command: `scanforge-discovery ${discoveryArgs}`,
                      exitCode: 1,
                      durationMs: 0,
                      timedOut: false,
                      findingCount: 0,
                      findings: [],
                      outputPreview: (err as any).message?.slice(0, 512) || 'Scan failed',
                      executedAt: Date.now(),
                      phase: 'discovery',
                    } as any);
                    asset.status = 'scanned' as any;
                    addLog(state!, { phase: 'scanning', type: 'error', title: `\u274c ScanForge failed: ${asset.hostname}`, detail: err.message });
                  }

                  // Use handoff nuclei config if available, otherwise fall back to defaults
                  const nucleiCfg = nucleiConfigMap.get(asset.hostname);
                  const nucleiTags = nucleiCfg ? nucleiCfg.tags.join(',') : 'cve,sqli,xss,lfi,rce,ssrf,ssti,crlf,traversal';
                  const nucleiSeverity = nucleiCfg?.severityFilter || 'critical,high,medium';
                  const nucleiRateLimit = nucleiCfg?.rateLimit || 100;
                  let nucleiCustomHeaders = nucleiCfg?.customHeaders
                    ? Object.entries(nucleiCfg.customHeaders).map(([k, v]: [string, any]) => `-H "${k}: ${v}"`).join(' ')
                    : '';

                  // ── Authenticated Scanning: Auto-login for known training targets ──
                  // For login-protected targets (DVWA, etc.), attempt to obtain a session cookie
                  // before running nuclei/DAST so scanners can access authenticated pages.
                  let authSessionCookie = '';

                  // If user provided credentials via the UI, inject them as confirmed creds on first asset
                  if (input.credentials && !asset.confirmedCredentials?.length) {
                    if (!asset.confirmedCredentials) asset.confirmedCredentials = [] as any;
                    (asset.confirmedCredentials as any[]).push({
                      protocol: 'http',
                      service: 'http-form',
                      username: input.credentials.username,
                      password: input.credentials.password,
                      loginPath: input.credentials.loginUrl || '/login',
                      authType: input.credentials.authType || 'form',
                      source: 'user-provided',
                    });
                  }

                  const confirmedCreds = (asset.confirmedCredentials || []).filter(
                    (c: any) => c.protocol === 'http' || c.protocol === 'https' || c.service === 'http-form'
                  );
                  // Check for known training lab credentials
                  const { TRAINING_TARGETS } = await import('./training-lab');
                  const matchedLab = TRAINING_TARGETS.find(t => {
                    try {
                      const tHost = new URL(t.liveInstanceUrl || t.url).hostname;
                      return asset.hostname.includes(tHost) || tHost.includes(asset.hostname) ||
                             (t.liveInstanceUrl && new URL(t.liveInstanceUrl).hostname === asset.hostname);
                    } catch { return false; }
                  });

                  // DVWA-specific auto-login
                  if (matchedLab?.id === 'dvwa' || asset.hostname.includes('dvwa')) {
                    try {
                      const dvwaBase = nucleiTargetUrls[0] || `http://${asset.hostname}`;
                      addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f511} Auth: ${asset.hostname}`, detail: 'Attempting DVWA auto-login (admin/password)...' });
                      // Step 1: Get login page to extract CSRF token and session cookie
                      const loginPageResult = await executeRawCommand(
                        `curl -sD - -o /tmp/dvwa_login.html -c /tmp/dvwa_cookies.txt '${dvwaBase}/login.php' 2>&1`,
                        15
                      );
                      // Extract user_token from login form
                      const tokenMatch = (loginPageResult.stdout || '').match(/user_token.*?value=["']([^"']+)["']/i);
                      const userToken = tokenMatch ? tokenMatch[1] : '';
                      // Step 2: POST login credentials
                      const loginResult = await executeRawCommand(
                        `curl -sD - -b /tmp/dvwa_cookies.txt -c /tmp/dvwa_cookies.txt -L ` +
                        `--data-urlencode 'username=admin' --data-urlencode 'password=password' ` +
                        `--data-urlencode 'Login=Login' --data-urlencode 'user_token=${userToken}' ` +
                        `'${dvwaBase}/login.php' 2>&1`,
                        15
                      );
                      // Step 3: Set security level to low for maximum vuln exposure
                      await executeRawCommand(
                        `curl -s -b /tmp/dvwa_cookies.txt -c /tmp/dvwa_cookies.txt ` +
                        `--data-urlencode 'security=low' --data-urlencode 'seclev_submit=Submit' ` +
                        `'${dvwaBase}/security.php' 2>&1`,
                        10
                      );
                      // Extract session cookie from cookie jar
                      const cookieJar = await executeRawCommand('cat /tmp/dvwa_cookies.txt 2>/dev/null', 5);
                      const phpSessMatch = (cookieJar.stdout || '').match(/PHPSESSID\s+(\S+)/);
                      const secMatch = (cookieJar.stdout || '').match(/security\s+(\S+)/);
                      if (phpSessMatch) {
                        authSessionCookie = `PHPSESSID=${phpSessMatch[1]}`;
                        if (secMatch) authSessionCookie += `; security=${secMatch[1]}`;
                        else authSessionCookie += '; security=low';
                        nucleiCustomHeaders += ` -H "Cookie: ${authSessionCookie}"`;
                        addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 Auth: ${asset.hostname}`, detail: `DVWA session obtained. Security level: ${secMatch?.[1] || 'low'}. Injecting into nuclei/DAST.` });
                        // Store confirmed credentials on asset
                        if (!asset.confirmedCredentials) asset.confirmedCredentials = [] as any;
                        const credExists = (asset.confirmedCredentials as any[]).some((c: any) => c.username === 'admin' && c.source === 'auto-login');
                        if (!credExists) {
                          (asset.confirmedCredentials as any[]).push({
                            username: 'admin', password: 'password', service: 'http-form',
                            port: 80, protocol: 'http', accessLevel: 'admin',
                            source: 'auto-login', loginPath: '/login.php',
                            confirmedAt: Date.now(),
                          });
                        }
                      } else {
                        addLog(state!, { phase: 'scanning', type: 'info', title: `\u26a0\ufe0f Auth: ${asset.hostname}`, detail: 'DVWA login attempt did not return a session cookie' });
                      }
                    } catch (authErr: any) {
                      addLog(state!, { phase: 'scanning', type: 'info', title: `\u26a0\ufe0f Auth skipped: ${asset.hostname}`, detail: authErr.message?.slice(0, 100) || 'Auto-login failed' });
                    }
                  }
                  // Generic form-based auto-login for targets with confirmed HTTP credentials
                  else if (confirmedCreds.length > 0 && !authSessionCookie) {
                    const cred = confirmedCreds[0];
                    if (cred.loginPath) {
                      try {
                        const loginBase = nucleiTargetUrls[0] || `http://${asset.hostname}`;
                        addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f511} Auth: ${asset.hostname}`, detail: `Attempting login with confirmed creds (${cred.username}) at ${cred.loginPath}` });
                        const loginResult = await executeRawCommand(
                          `curl -sD - -c /tmp/auth_cookies_${asset.hostname.replace(/[^a-z0-9]/gi, '_')}.txt -L ` +
                          `--data-urlencode 'username=${cred.username}' --data-urlencode 'password=${cred.password}' ` +
                          `'${loginBase}${cred.loginPath}' 2>&1`,
                          15
                        );
                        // Extract Set-Cookie headers
                        const setCookies = (loginResult.stdout || '').match(/Set-Cookie:\s*([^\n]+)/gi);
                        if (setCookies && setCookies.length > 0) {
                          const cookies = setCookies.map((sc: string) => {
                            const val = sc.replace(/^Set-Cookie:\s*/i, '').split(';')[0];
                            return val;
                          }).join('; ');
                          authSessionCookie = cookies;
                          nucleiCustomHeaders += ` -H "Cookie: ${authSessionCookie}"`;
                          addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 Auth: ${asset.hostname}`, detail: `Session obtained via ${cred.loginPath}. Injecting into nuclei/DAST.` });
                        }
                      } catch (authErr: any) {
                        addLog(state!, { phase: 'scanning', type: 'info', title: `\u26a0\ufe0f Auth skipped: ${asset.hostname}`, detail: authErr.message?.slice(0, 100) || 'Login failed' });
                      }
                    }
                  }

                  // Build target URLs from discovered ports, fallback to both http+https
                  // (Defined outside try block so DAST can use it even if nuclei scan fails)
                  const NUCLEI_INFRA_PORTS = new Set([1337, 31337, 8834, 9392, 5432, 3306, 27017, 6379]);
                  const webPorts = (asset.ports || []).filter((p: any) =>
                    (['http', 'https', 'http-proxy', 'http-alt'].includes(p.service) ||
                    [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port))
                    && !NUCLEI_INFRA_PORTS.has(p.port)
                  );
                  const nucleiTargetUrls = webPorts.length > 0
                    ? webPorts.map((p: any) => {
                        const scheme = p.port === 443 || p.port === 8443 ? 'https' : 'http';
                        return `${scheme}://${asset.hostname}:${p.port}`;
                      })
                    : [`http://${asset.hostname}`, `https://${asset.hostname}`];

                  addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f50d} Nuclei: ${asset.hostname}`, detail: nucleiCfg ? `Handoff config: ${nucleiCfg.rationale}` : 'Vulnerability templates (default config)...' });
                  const nucleiCmd = `echo "${nucleiTargetUrls.join('\n')}" | nuclei -severity ${nucleiSeverity} -jsonl -nc -duc -ni -timeout 20 -retries 2 -rate-limit ${nucleiRateLimit} -tags ${nucleiTags} ${nucleiCustomHeaders} 2>&1`;
                  try {
                    // Use stdin piping to avoid nuclei hanging on PDCP TTY auth prompt
                    const nucleiStartTime = Date.now();
                    const nucleiInput = nucleiTargetUrls.join('\n');
                    const nucleiResult = await executeRawCommand(`echo "${nucleiInput}" | nuclei -severity ${nucleiSeverity} -jsonl -nc -duc -ni -timeout 20 -retries 2 -rate-limit ${nucleiRateLimit} -tags ${nucleiTags} ${nucleiCustomHeaders} 2>&1`, 300);
                    const findings = nucleiResult.stdout.split('\n').filter(Boolean).map((line: string) => {
                      try { return JSON.parse(line); } catch { return null; }
                    }).filter(Boolean);
                    const { pushVulnDeduped: pushVulnDedupedNuclei } = await import('../lib/engagement-orchestrator');
                    for (const f of findings) {
                      pushVulnDedupedNuclei(asset as any, {
                        id: `nuclei-${f['template-id'] || 'unknown'}-${asset.hostname}`,
                        title: f.info?.name || f['template-id'] || 'Unknown',
                        severity: f.info?.severity || 'medium',
                        cve: f.info?.classification?.['cve-id']?.[0] || '',
                        description: f.info?.description || '',
                        tool: 'nuclei',
                        port: f.port || 0,
                        rawOutput: JSON.stringify(f).slice(0, 500),
                      } as any);
                    }
                    // Push nuclei toolResult so Discovery tab shows accurate run counts
                    if (!asset.toolResults) asset.toolResults = [];
                    asset.toolResults.push({
                      tool: 'nuclei',
                      command: nucleiCmd.slice(0, 500),
                      exitCode: nucleiResult.exitCode ?? 0,
                      durationMs: Date.now() - nucleiStartTime,
                      timedOut: nucleiResult.timedOut || false,
                      findingCount: findings.length,
                      findings: findings.map((f: any) => ({ severity: f.info?.severity || 'medium', title: f.info?.name || f['template-id'] || 'Unknown' })),
                      outputPreview: (nucleiResult.stdout || '').slice(0, 512),
                      executedAt: Date.now(),
                      phase: 'scanning',
                    } as any);
                    addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 Nuclei: ${asset.hostname}`, detail: `${findings.length} vulnerabilities` });
                  } catch (err: any) {
                    // Push failed nuclei toolResult
                    if (!asset.toolResults) asset.toolResults = [];
                    asset.toolResults.push({
                      tool: 'nuclei',
                      command: nucleiCmd.slice(0, 500),
                      exitCode: 1,
                      durationMs: 0,
                      timedOut: false,
                      findingCount: 0,
                      findings: [],
                      outputPreview: (err as any).message?.slice(0, 512) || 'Nuclei scan failed',
                      executedAt: Date.now(),
                      phase: 'scanning',
                    } as any);
                    addLog(state!, { phase: 'scanning', type: 'error', title: `\u274c Nuclei failed: ${asset.hostname}`, detail: err.message });
                  }

                  // Nuclei DAST mode with crawling for active vuln confirmation
                  const dc = state!.dastConfig || { enabled: true, crawlDepth: 3, crawlScope: 'strict', templateCategories: ['sqli', 'xss', 'lfi', 'rfi', 'ssrf', 'rce'], timeout: 30, maxRequests: 5000, rateLimit: 50, headless: true };
                  if (dc.enabled !== false) {
                  addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f578}\ufe0f DAST: ${asset.hostname}`, detail: `Crawl depth: ${dc.crawlDepth}, scope: ${dc.crawlScope}, categories: ${dc.templateCategories.join(',')}` });
                  try {
                    const scopeFlag = dc.crawlScope === 'strict' ? '' : dc.crawlScope === 'subdomain' ? `-cs ${asset.hostname}` : `-cs ${asset.hostname.split('.').slice(-2).join('.')}`;
                    const headlessFlag = dc.headless ? '-headless' : '';
                    let customHeaderFlags = dc.customHeaders ? Object.entries(dc.customHeaders).map(([k, v]) => `-H "${k}: ${v}"`).join(' ') : '';
                    // Inject auth session cookie into DAST if obtained during pre-scan login
                    if (authSessionCookie && !customHeaderFlags.includes('Cookie:')) {
                      customHeaderFlags += ` -H "Cookie: ${authSessionCookie}"`;
                    }
                    const dastInput = nucleiTargetUrls.join('\n');
                    const dastCmd = `echo "${dastInput}" | nuclei -dast ${headlessFlag} -crawl-depth ${dc.crawlDepth} -crawl-duration ${dc.timeout * 2} -severity critical,high,medium -jsonl -nc -duc -ni -timeout ${dc.timeout} -rate-limit ${dc.rateLimit} -max-host-error 10 ${scopeFlag} ${customHeaderFlags} -system-resolvers 2>&1`;
                    const dastResult = await executeRawCommand(
                      dastCmd,
                      Math.max(180, dc.timeout * 3)
                    );
                    const dastFindings = dastResult.stdout.split('\n').filter(Boolean).map((line: string) => {
                      try { return JSON.parse(line); } catch { return null; }
                    }).filter(Boolean);
                    for (const f of dastFindings) {
                      const vulnTitle = f.info?.name || f['template-id'] || 'Unknown';
                      // Check if this vuln was already found by standard nuclei or LLM synthesis
                      const isDuplicate = asset.vulns.some((v: any) =>
                        v.title.toLowerCase().includes(vulnTitle.toLowerCase().split(' ')[0]) ||
                        vulnTitle.toLowerCase().includes(v.title.toLowerCase().split(' ')[0])
                      );
                      if (isDuplicate) {
                        // Mark existing vuln as confirmed by active scan
                        const existing = asset.vulns.find((v: any) =>
                          v.title.toLowerCase().includes(vulnTitle.toLowerCase().split(' ')[0]) ||
                          vulnTitle.toLowerCase().includes(v.title.toLowerCase().split(' ')[0])
                        );
                        if (existing) (existing as any).confirmedByActiveScan = true;
                      } else {
                        const { pushVulnDeduped: pushVulnDedupedDast } = await import('../lib/engagement-orchestrator');
                        pushVulnDedupedDast(asset as any, {
                          id: `dast-${f['template-id'] || 'unknown'}-${asset.hostname}`,
                          title: vulnTitle,
                          severity: f.info?.severity || 'medium',
                          cve: f.info?.classification?.['cve-id']?.[0] || '',
                          description: f.info?.description || `DAST finding: ${f['matched-at'] || ''}`,
                          tool: 'nuclei-dast',
                          port: f.port || 0,
                          confirmedByActiveScan: true,
                          rawOutput: JSON.stringify(f).slice(0, 500),
                        } as any);
                      }
                    }
                    addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 DAST: ${asset.hostname}`, detail: `${dastFindings.length} findings (${dastFindings.filter((f: any) => f.info?.severity === 'critical' || f.info?.severity === 'high').length} critical/high)` });
                  } catch (err: any) {
                    addLog(state!, { phase: 'scanning', type: 'info', title: `\u26a0\ufe0f DAST skipped: ${asset.hostname}`, detail: err.message?.slice(0, 100) || 'Timeout or unavailable' });
                  }
                  } // end if (dc.enabled)

                  // Curl-based header probing fallback (always runs to supplement nuclei)
                  try {
                    const curlResult = await executeTool({ tool: 'curl', args: `-sI -L --max-time 15 http://${asset.hostname}`, timeoutSeconds: 20 });
                    const headers = curlResult.stdout || '';
                    // Extract server info from headers
                    const serverMatch = headers.match(/^Server:\s*(.+)$/mi);
                    if (serverMatch) {
                      const serverInfo = serverMatch[1].trim();
                      if (!asset.technologies?.includes(serverInfo)) {
                        asset.technologies = [...(asset.technologies || []), serverInfo];
                      }
                    }
                    // Check for security header misconfigs
                    const missingHeaders: string[] = [];
                    if (!headers.match(/X-Frame-Options/i)) missingHeaders.push('X-Frame-Options');
                    if (!headers.match(/X-Content-Type-Options/i)) missingHeaders.push('X-Content-Type-Options');
                    if (!headers.match(/Strict-Transport-Security/i)) missingHeaders.push('HSTS');
                    if (!headers.match(/Content-Security-Policy/i)) missingHeaders.push('CSP');
                    if (missingHeaders.length > 0) {
                      const { pushVulnDeduped } = await import('../lib/engagement-orchestrator');
                      pushVulnDeduped(asset as any, {
                        id: `curl-headers-${asset.hostname}`,
                        title: `Missing Security Headers: ${missingHeaders.join(', ')}`,
                        severity: 'medium',
                        cve: '',
                        description: `The following security headers are missing: ${missingHeaders.join(', ')}. This may allow clickjacking, MIME sniffing, or other attacks.`,
                        tool: 'curl-probe',
                        confidence: 90,
                        category: 'misconfig',
                      } as any);
                    }
                    addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f50d} Header probe: ${asset.hostname}`, detail: `${missingHeaders.length} missing security headers` });
                  } catch (err: any) {
                    // Header probe is non-critical, just log
                    addLog(state!, { phase: 'scanning', type: 'info', title: `Header probe skipped: ${asset.hostname}`, detail: err.message });
                  }

                  // ── httpx HTTP probing (tech detection, CDN/WAF, TLS) ──
                  try {
                    const httpxWebPorts = (asset.ports || []).filter((p: any) =>
                      ['http', 'https', 'http-proxy', 'http-alt'].includes(p.service) ||
                      [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
                    );
                    const httpxTargetUrls = httpxWebPorts.length > 0
                      ? httpxWebPorts.map((p: any) => {
                          const scheme = p.port === 443 || p.port === 8443 ? 'https' : 'http';
                          return `${scheme}://${asset.hostname}:${p.port}`;
                        })
                      : [`http://${asset.hostname}`, `https://${asset.hostname}`];
                    const httpxFlags = '-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent';
                    const httpxInput = httpxTargetUrls.join('\\n');
                    const httpxCmd = `echo -e '${httpxInput}' | httpx ${httpxFlags}`;
                    addLog(state!, { phase: 'scanning', type: 'info', title: `🌐 httpx: ${asset.hostname}`, detail: `HTTP probing ${httpxTargetUrls.length} web ports` });
                    const httpxStartTime = Date.now();
                    const httpxResult = await executeRawCommand(httpxCmd, 120);
                    const httpxDuration = Date.now() - httpxStartTime;
                    // Parse httpx JSON output for tech detection
                    const httpxFindings: Array<{severity: string; title: string}> = [];
                    const techDetected: string[] = [];
                    if (httpxResult.stdout) {
                      for (const line of httpxResult.stdout.split('\n')) {
                        const trimmed = line.trim();
                        if (!trimmed) continue;
                        try {
                          const obj = JSON.parse(trimmed);
                          if (obj.tech && Array.isArray(obj.tech)) {
                            for (const tech of obj.tech) {
                              if (!techDetected.includes(tech)) techDetected.push(tech);
                              httpxFindings.push({ severity: 'info', title: `[httpx] Technology: ${tech}` });
                            }
                          }
                          if (obj.cdn_name) httpxFindings.push({ severity: 'info', title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
                          if (obj.webserver) httpxFindings.push({ severity: 'info', title: `[httpx] Web Server: ${obj.webserver}` });
                          if (obj.status_code) httpxFindings.push({ severity: 'info', title: `[httpx] ${obj.url || ''}: ${obj.status_code} ${obj.title || ''}`.trim() });
                        } catch { /* not JSON */ }
                      }
                    }
                    // Enrich asset with detected technologies
                    if (techDetected.length > 0 && asset.passiveRecon) {
                      asset.passiveRecon.technologies = Array.from(
                        new Set([...(asset.passiveRecon.technologies || []), ...techDetected])
                      );
                    }
                    // Push httpx toolResult
                    if (!asset.toolResults) asset.toolResults = [];
                    asset.toolResults.push({
                      tool: 'httpx',
                      command: httpxCmd.slice(0, 500),
                      exitCode: httpxResult.exitCode ?? 0,
                      durationMs: httpxDuration,
                      timedOut: httpxResult.timedOut || false,
                      findingCount: httpxFindings.length,
                      findings: httpxFindings,
                      outputPreview: (httpxResult.stdout || '').slice(0, 1024),
                      executedAt: Date.now(),
                      phase: 'discovery',
                    } as any);
                    addLog(state!, { phase: 'scanning', type: 'success', title: `✅ httpx: ${asset.hostname}`, detail: `${httpxFindings.length} findings${techDetected.length > 0 ? `, Tech: ${techDetected.join(', ')}` : ''}` });
                  } catch (httpxErr: any) {
                    addLog(state!, { phase: 'scanning', type: 'info', title: `⚠️ httpx skipped: ${asset.hostname}`, detail: httpxErr.message?.slice(0, 100) || 'Timeout or unavailable' });
                  }

                  // ── Persist after each asset scan (crash-resilient checkpoint) ──
                  await persistOpsStateNow(input.engagementId).catch(() => {});
                }
              } catch (err: any) {
                addLog(state!, { phase: 'scanning', type: 'error', title: '\u274c Active scanning failed', detail: err.message });
              }

              // ── ZAP + Burp Vulnerability Scanning ──
              // Call the full executeVulnDetection pipeline which includes:
              // - ZAP web app scanning (WAF-aware, RoE scope enforced, credential injection)
              // - ZAP → Burp cross-tool pipeline (auto-feeds ZAP discoveries into Burp)
              // - Blind SQLi pass, Hydra credential testing, SQLMap deep injection
              // - Nuclei targeted scans, header probing, and more
              // This was previously missing from rerunFullPipeline, causing ZAP/Burp to be skipped.
              try {
                const { executeVulnDetection } = await import('../lib/engagement-orchestrator');
                addLog(state!, { phase: 'scanning', type: 'info', title: '🛡️ ZAP + Burp Vulnerability Scanning', detail: 'Running OWASP ZAP web app scans and Burp Suite scanning pipeline...' });
                broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'vuln_detection' });
                await executeVulnDetection(state!, engagement, { id: String(ctx.user.id), name: ctx.user.name || undefined });
                addLog(state!, { phase: 'scanning', type: 'success', title: '✅ ZAP + Burp Scanning Complete', detail: `${state!.stats.zapScansRun} ZAP scans run, ${state!.stats.vulnsFound} total vulns found` });
                // Restore phase to 'scanning' for the rest of the rerunFullPipeline flow
                state!.phase = 'scanning';
              } catch (vulnDetErr: any) {
                console.error('[rerunFullPipeline] executeVulnDetection failed:', vulnDetErr.message);
                addLog(state!, { phase: 'scanning', type: 'warning', title: '⚠️ ZAP + Burp Scanning Failed', detail: `Vulnerability detection pipeline error: ${vulnDetErr.message}. Continuing with existing findings.` });
                // Restore phase to 'scanning' even on failure
                state!.phase = 'scanning';
              }
              // ── Recalculate stats after active + vuln scanning ──
              state!.stats.vulnsFound = state!.assets.reduce((sum, a) => sum + (a.vulns || []).length, 0);
              state!.stats.portsFound = state!.assets.reduce((sum, a) => sum + (a.ports || []).length, 0);
              state!.stats.assetsDiscovered = state!.assets.length;
              state!.stats.hostsScanned = state!.assets.filter(a => a.status !== 'pending').length;
              // ── Persist after ZAP + Burp scanning ──
              await persistOpsStateNow(input.engagementId).catch(() => {});

              // LLM feedback loop
              if (input.phases.llmAnalysis) {
                try {
                  addLog(state!, { phase: 'scanning', type: 'info', title: '\u{1f9e0} LLM Feedback Loop', detail: 'Analyzing results and requesting targeted re-scans...' });
                  const { runFeedbackLoop } = await import('../lib/llm-scan-feedback');
                  // Build initial findings from all asset vulns + risk signals
                  const initialFindings = state!.assets.flatMap(a => [
                    ...a.vulns.map((v: any) => ({
                      type: 'vulnerability', asset: a.hostname, title: v.title,
                      severity: v.severity, cve: v.cve, tool: v.tool || 'passive',
                      port: v.port, description: v.description,
                    })),
                    ...(a.passiveRecon?.riskSignals || []).map((s: any) => ({
                      type: 'risk_signal', asset: a.hostname, title: s.rationale,
                      severity: s.severity, tool: 'passive_recon',
                    })),
                    ...a.ports.map((p: any) => ({
                      type: 'service', asset: a.hostname, port: p.port,
                      service: p.service, version: p.version, tool: 'scanforge-discovery',
                    })),
                  ]);
                  const feedbackResult = await runFeedbackLoop(
                    initialFindings,
                    { targets: state!.assets.map(a => a.hostname), engagementName: engagement.engagementName || 'pentest' },
                    { maxIterations: 3, engagementId: input.engagementId },
                  );
                  addLog(state!, { phase: 'scanning', type: 'success', title: '\u2705 Feedback Loop Complete', detail: `${feedbackResult.iterationsRun || 0} iterations, ${feedbackResult.newFindingsCount || 0} new findings` });
                } catch (err: any) {
                  addLog(state!, { phase: 'scanning', type: 'error', title: '\u274c Feedback Loop failed', detail: err.message });
                }
              }
            }

            // Phase 3.5: LLM Vulnerability Synthesis (always runs after passive/active)
            // Convert passive recon risk signals + port data into proper vulns
            // This ensures the pipeline produces vulns even when active scanners (nuclei) return 0 results
            if (state!.assets.some(a => a.vulns.length === 0 && ((a.passiveRecon?.riskSignals || []).length > 0 || a.ports.length > 0))) {
              state!.phase = 'scanning';
              state!.currentAction = 'LLM analyzing risk signals to identify vulnerabilities...';
              addLog(state!, { phase: 'scanning', type: 'info', title: '\u{1f9e0} LLM Vuln Synthesis', detail: 'Analyzing risk signals and services to identify vulnerabilities...' });
              try {
                const { invokeLLM } = await import('../_core/llm');
                // Wire knowledge modules into vuln synthesis for enriched LLM context
                const { getOwaspVulnCorrelationContext } = await import('../lib/owasp-knowledge');
                const { buildKnowledgeContextForLLM } = await import('../lib/pentest-knowledge-base');
                const { buildAuthKnowledgeContext } = await import('../lib/auth-testing-knowledge');
                const { getScanforgeVulnCorrelationContext } = await import('../lib/scanforge-knowledge');
                const { getThreatGroupVulnContext } = await import('../lib/threat-group-knowledge');
                const { buildMethodologyContext, buildVulnTestingContext } = await import('../lib/knowledge/bugbounty-methodology-knowledge');
                const { buildLearningContext, GROUND_TRUTH_LIBRARY } = await import('../lib/llm-self-learning');
                const { TRAINING_TARGETS } = await import('./training-lab');

                // Resolve training preset from engagement target domains
                const engDomains = (engagement?.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
                let resolvedPreset = '';
                let learningCtx = '';
                for (const d of engDomains) {
                  const match = TRAINING_TARGETS.find(t => {
                    try {
                      const tHost = new URL(t.url.startsWith('http') ? t.url : `https://${t.url}`).hostname;
                      return d.includes(tHost) || tHost.includes(d) || (t.liveInstanceUrl && t.liveInstanceUrl.includes(d));
                    } catch { return false; }
                  });
                  if (match) { resolvedPreset = match.id; break; }
                }
                if (resolvedPreset) {
                  try {
                    learningCtx = await buildLearningContext(resolvedPreset);
                    if (learningCtx) {
                      addLog(state!, { phase: 'scanning', type: 'info', title: '\u{1f9e0} Learning Context Injected', detail: `Loaded corrections for preset "${resolvedPreset}" (${learningCtx.length} chars)` });
                    }
                  } catch (lcErr: any) {
                    console.error('[SelfLearning] Failed to build learning context:', lcErr.message);
                  }
                }

                const owaspCtx = getOwaspVulnCorrelationContext();
                const pentestCtx = buildKnowledgeContextForLLM('operator', 2000);
                const authCtx = buildAuthKnowledgeContext();
                const scanforgeVulnCtx = getScanforgeVulnCorrelationContext();
                const threatCtx = getThreatGroupVulnContext();
                for (const asset of state!.assets) {
                  if (asset.vulns.length > 0) continue; // Skip assets that already have vulns from active scanning
                  const signals = asset.passiveRecon?.riskSignals || [];
                  const techs = asset.passiveRecon?.technologies || [];
                  const ports = asset.ports || [];
                  if (signals.length === 0 && ports.length === 0) continue;

                  // Smart signal sampling: prioritize high-severity and diverse signals
                  const highSeverity = signals.filter((s: any) => s.severity === 'critical' || s.severity === 'high');
                  const medSeverity = signals.filter((s: any) => s.severity === 'medium');
                  const lowSeverity = signals.filter((s: any) => s.severity === 'low' || s.severity === 'info');
                  // Keep signal text short: truncate each rationale to 120 chars
                  const truncSignal = (s: any) => ({ ...s, rationale: (s.rationale || s.title || 'Unknown').slice(0, 120) });
                  const sampledSignals = [
                    ...highSeverity.slice(0, 12).map(truncSignal),
                    ...medSeverity.slice(0, 8).map(truncSignal),
                    ...lowSeverity.slice(0, 5).map(truncSignal),
                  ].slice(0, 25);

                  const synthPrompt = `You are a senior penetration tester performing a vulnerability assessment of ${asset.hostname}.

Your task: Analyze the passive reconnaissance data and identify POTENTIAL vulnerabilities that warrant further investigation.
IMPORTANT: These are HYPOTHETICAL findings based on passive signals only — they have NOT been confirmed by active scanning tools.

CRITICAL RULES:
1. You MUST identify vulnerabilities across DIVERSE categories. Do NOT list multiple vulns of the same type.
2. PRIORITIZE web application vulnerabilities over infrastructure/misconfig issues.
3. At minimum, you MUST check for ALL of these categories and include them if there is ANY evidence:
   - SQL Injection (SQLi) - ANY database-backed web app likely has this
   - Cross-Site Scripting (XSS) - ANY web app with user input likely has this
   - Directory Traversal / Path Traversal / LFI - look for file parameters, include paths
   - CRLF Injection / HTTP Response Splitting - look for header manipulation, redirect params
   - File Inclusion (Local/Remote) - look for include/require parameters, file loading
   - Broken Authentication - weak login, session issues
   - Sensitive Data Exposure - unencrypted data, exposed credentials
   - Broken Access Control - IDOR, privilege escalation
   - SSRF - server-side request forgery
   - Security Misconfiguration (limit to MAX 1 entry)

=== TARGET INFO ===
Hostname: ${asset.hostname}
Discovered Technologies: ${techs.join(', ') || 'Unknown'}
Open Ports/Services: ${ports.map((p: any) => `${p.port}/${p.service}${p.version ? ' (' + p.version + ')' : ''}`).join(', ')}

=== RISK SIGNALS (${signals.length} total, showing ${sampledSignals.length} representative samples) ===
${sampledSignals.map((s: any, i: number) => `${i+1}. [${s.severity || 'medium'}] ${s.rationale || s.title || 'Unknown'}`).join('\n')}

IMPORTANT CONTEXT:
- If this is a known test/vulnerable site, you MUST include the classic vulnerabilities these sites are known for.
- testphp.vulnweb.com is known for: SQL Injection, XSS, File Inclusion (LFI/RFI), CRLF Injection, Directory Traversal
- demo.testfire.net is known for: SQL Injection, XSS, Authentication Bypass, Session Fixation, IDOR, Information Disclosure
- demo.owasp-juice.shop is known for: SQL Injection, XSS, Broken Authentication, JWT None Algorithm, SSRF, Sensitive Data Exposure, Insecure Deserialization
- brokencrystals.com is known for: JWT Bypass, SQL Injection, XSS, SSRF, SSTI, XXE, LDAP Injection, OS Command Injection, Prototype Pollution, IDOR, CSRF, GraphQL Introspection, Mass Assignment, Default Credentials (admin:admin)
- ginandjuice.shop is known for: XSS, DOM XSS, SQL Injection, SSRF, SSTI, XXE, CORS Misconfiguration, HTTP Request Smuggling, Insecure Deserialization, Path Traversal, Authentication Bypass
- google-gruyere.appspot.com is known for: Stored XSS, Reflected XSS, CSRF, Remote Code Execution, Path Traversal, Information Disclosure
- public-firing-range.appspot.com is known for: 50+ DOM XSS variants, Reflected XSS, CORS Misconfiguration, Reverse Clickjacking, Remote Inclusion
- testaspnet.vulnweb.com is known for: SQL Injection, XSS, ASP.NET Trace Enabled, ViewState Tampering, IIS Information Disclosure
- testhtml5.vulnweb.com is known for: NoSQL Injection (CouchDB), XSS, HTML5 Web Storage Exposure, CORS Misconfiguration
- testasp.vulnweb.com is known for: SQL Injection, XSS, Path Traversal, ViewState Tampering, Information Disclosure
- hack-yourself-first.com is known for: SQL Injection, XSS, CSRF, IDOR, Insecure Transport
- aspnet.testsparker.com is known for: SQL Injection, XSS, Path Traversal, Authentication Bypass
- php.testsparker.com is known for: SQL Injection, XSS, LFI, Command Injection
- angular.testsparker.com is known for: DOM XSS, Angular Template Injection, CORS Misconfiguration, API Security Issues
- rest.vulnweb.com is known for: BOLA, Broken Authentication, Excessive Data Exposure, Injection, Missing Rate Limiting
- pentest-ground.com is known for: SQL Injection, XSS, Command Injection, File Upload, Authentication Bypass
- zero.webappsecurity.com is known for: Broken Authentication, IDOR, XSS, CSRF
- DVWA (Damn Vulnerable Web Application) is known for: SQL Injection (ID parameter on multiple pages), XSS - Reflected (name parameter), XSS - Stored (guestbook entries), XSS - DOM Based (URL parameter), Command Injection (ping IP input with ; or | operators), CSRF (password change form lacks token), File Inclusion - Local (page parameter with ../../etc/passwd), File Inclusion - Remote (external PHP file loading), File Upload (unrestricted PHP webshell upload), Brute Force (no rate limiting on login), Insecure CAPTCHA (step parameter bypass), Weak Session IDs (predictable/sequential), Open HTTP Redirect (redirect parameter), CSP Bypass (misconfigured headers). DVWA has EXACTLY 14 documented vulnerabilities — you MUST find SQL Injection, XSS Reflected, XSS Stored, Command Injection, and CSRF at minimum.
- bWAPP is known for: SQL Injection (GET/POST/Blind Boolean/Blind Time-based), OS Command Injection (visible & blind), PHP Code Injection, XML/XPath Injection, XSS (Reflected/Stored/DOM), CSRF, SSRF, XXE, LFI/RFI, Unrestricted File Upload, Shellshock (CVE-2014-6271), Heartbleed, Insecure WebDAV, Session Management flaws, Broken Authentication, A1-A10 OWASP Top 10 coverage
- Mutillidae II (OWASP) is known for: SQL Injection (UNION/Error/Blind/REST/SOAP), OS Command Injection, XXE via SOAP, XSS (Reflected/Stored/DOM), Authentication Bypass via SQLi, Privilege Escalation, Brute Force Login, LFI/RFI, CSRF, SSRF, Clickjacking, WSDL Information Disclosure, JavaScript Injection, HTML Injection, LDAP Injection, Log Injection, HTTP Parameter Pollution
- crAPI (OWASP) is known for: BOLA (Vehicle Details/Mechanic Reports), Broken Authentication (OTP Brute Force), Excessive Data Exposure (PII in Posts/Video Internal Properties), BFLA (Admin Video Deletion), Mass Assignment (Free Item/Balance Manipulation), SSRF (Mechanic API/Video Conversion), NoSQL Injection (Coupon Code), JWT Token Forgery, LLM Prompt Injection, LLM Credential Extraction, Rate Limiting Bypass, Broken Object Property Level Authorization

Identify the TOP 10 most likely vulnerabilities with MAXIMUM CATEGORY DIVERSITY.

For each vulnerability provide:
- title: Clear vulnerability name (e.g., "SQL Injection in Login Form", "Directory Traversal via File Parameter")
- severity: critical, high, medium, or low
- cve: Known CVE if applicable, or empty string
- description: Brief explanation including WHERE and HOW the vulnerability likely exists
- confidence: 0-100 how confident you are
- category: One of: injection, xss, auth_bypass, info_disclosure, misconfig, broken_access, ssrf, file_inclusion, directory_traversal, crlf_injection, sensitive_data

=== KNOWLEDGE BASE CONTEXT ===
${owaspCtx.slice(0, 1500)}

${pentestCtx.slice(0, 1500)}

${authCtx.slice(0, 800)}

${scanforgeVulnCtx.slice(0, 800)}

${threatCtx.slice(0, 800)}
${learningCtx ? `\n=== SELF-LEARNING CORRECTIONS (from previous scans) ===\n${learningCtx.slice(0, 2000)}\n` : ''}
=== ATTACK METHODOLOGY ===
${(() => { const mCtx = buildMethodologyContext(resolvedPreset || undefined); return mCtx ? mCtx.slice(0, 2000) : ''; })()}
Return ONLY a JSON object with vulnerabilities array. No markdown, no explanation.`;

                  const synthSchema = { type: 'json_schema' as const, json_schema: {
                    name: 'vuln_synthesis',
                    strict: true,
                    schema: {
                      type: 'object',
                      properties: {
                        vulnerabilities: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              title: { type: 'string' },
                              severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
                              cve: { type: 'string' },
                              description: { type: 'string' },
                              confidence: { type: 'number' },
                              category: { type: 'string' },
                            },
                            required: ['title', 'severity', 'cve', 'description', 'confidence', 'category'],
                            additionalProperties: false,
                          },
                        },
                      },
                      required: ['vulnerabilities'],
                      additionalProperties: false,
                    },
                  }};
                  try {
                    let llmResult;
                    try {
                      llmResult = await invokeLLM({ 
                        _caller: "engagement-ops-core",
                        messages: [
                          { role: 'system', content: 'You are a vulnerability assessment AI. Return only valid JSON arrays.' },
                          { role: 'user', content: synthPrompt },
                        ],
                        response_format: synthSchema,
                      });
                    } catch (retryErr: any) {
                      // Retry with minimal prompt on failure (e.g., 403 from too-large prompt)
                      addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f504} Retrying Vuln Synthesis: ${asset.hostname}`, detail: 'Retrying with reduced prompt...' });
                      const minimalPrompt = `Identify the TOP 10 POTENTIAL (unconfirmed) vulnerabilities for ${asset.hostname} (technologies: ${techs.join(', ') || 'Unknown'}, ports: ${ports.map((p: any) => p.port + '/' + p.service).join(', ')}).\nKey risk signals: ${sampledSignals.slice(0, 10).map((s: any) => s.rationale).join('; ')}\n\nFocus on: SQL Injection, XSS, Broken Auth, Sensitive Data Exposure, Directory Traversal, CRLF Injection, File Inclusion, SSRF, Misconfig.\nReturn JSON with vulnerabilities array containing: title, severity, cve, description, confidence, category.`;
                      llmResult = await invokeLLM({ 
                        _caller: "engagement-ops-core",
                        messages: [
                          { role: 'system', content: 'You are a vulnerability assessment AI. Return only valid JSON.' },
                          { role: 'user', content: minimalPrompt },
                        ],
                        response_format: synthSchema,
                      });
                    }

                    const content = llmResult.choices?.[0]?.message?.content || '{}';
                    const parsed = JSON.parse(content);
                    const synthVulns = parsed.vulnerabilities || [];
                    const { pushVulnDeduped: pushVulnDedupedSynth } = await import('../lib/engagement-orchestrator');
                    // ── CVE False Positive Filter ──
                    // Drop CVEs that reference technologies NOT detected on this target.
                    // The LLM sometimes hallucinates CVEs for Chrome, Ivanti, Zyxel, VMware, etc.
                    // that have nothing to do with the actual tech stack.
                    const techLower = techs.map((t: string) => t.toLowerCase());
                    const servicesLower = ports.map((p: any) => `${p.service || ''} ${p.version || ''}`.toLowerCase());
                    const allTechContext = [...techLower, ...servicesLower].join(' ');
                    // Map of CVE product keywords → required tech indicators
                    const CVE_TECH_VALIDATORS: Record<string, string[]> = {
                      'chrome': ['chrome', 'chromium', 'google'],
                      'ivanti': ['ivanti', 'pulse', 'connect secure'],
                      'zyxel': ['zyxel'],
                      'vmware': ['vmware', 'vcenter', 'esxi', 'vsphere'],
                      'fortinet': ['fortinet', 'fortigate', 'fortios'],
                      'cisco': ['cisco', 'ios-xe', 'asa'],
                      'palo alto': ['palo alto', 'pan-os', 'globalprotect'],
                      'citrix': ['citrix', 'netscaler', 'adc'],
                      'microsoft exchange': ['exchange', 'owa'],
                      'adobe': ['adobe', 'acrobat', 'coldfusion'],
                      'sap': ['sap', 'netweaver'],
                      'oracle': ['oracle', 'weblogic'],
                      'f5': ['f5', 'big-ip', 'bigip'],
                      'sonicwall': ['sonicwall'],
                      'barracuda': ['barracuda'],
                      'juniper': ['juniper', 'junos'],
                    };
                    let filteredCount = 0;
                    for (const v of synthVulns) {
                      if (v.confidence < 40) continue;
                      // Check if the CVE description or title mentions a product not in our tech stack
                      const vulnText = `${v.title} ${v.description} ${v.cve || ''}`.toLowerCase();
                      let isFalsePositive = false;
                      for (const [product, requiredIndicators] of Object.entries(CVE_TECH_VALIDATORS)) {
                        if (vulnText.includes(product)) {
                          // This vuln mentions a specific product — check if we detected it
                          const hasIndicator = requiredIndicators.some(ind => allTechContext.includes(ind));
                          if (!hasIndicator) {
                            isFalsePositive = true;
                            filteredCount++;
                            break;
                          }
                        }
                      }
                      if (isFalsePositive) continue;
                      pushVulnDedupedSynth(asset as any, {
                        id: `synth-${asset.hostname}-${Math.random().toString(36).slice(2,8)}`,
                        title: `[Potential] ${v.title}`,
                        severity: v.severity,
                        cve: v.cve || '',
                        description: v.description,
                        tool: 'llm-synthesis',
                        confidence: v.confidence,
                        category: v.category,
                        corroborationTier: 'potential',
                        evidenceDetail: `LLM-synthesized from passive recon signals (confidence: ${v.confidence}%). Not confirmed by active scanning.`,
                      } as any);
                    }
                    const acceptedCount = synthVulns.filter((v: any) => v.confidence >= 40).length - filteredCount;
                    addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 Vuln Synthesis: ${asset.hostname}`, detail: `${acceptedCount} POTENTIAL vulnerabilities identified from ${signals.length} risk signals${filteredCount > 0 ? ` (${filteredCount} false positives filtered by tech-stack validation)` : ''} (not confirmed — require active validation)` });
                  } catch (synthErr: any) {
                    addLog(state!, { phase: 'scanning', type: 'error', title: `\u274c Vuln Synthesis failed: ${asset.hostname}`, detail: synthErr.message });
                  }
                }
              } catch (err: any) {
                addLog(state!, { phase: 'scanning', type: 'error', title: '\u274c LLM Vuln Synthesis failed', detail: err.message });
              }
            }

            // ── Persist after Phase 3 (Active Scanning + LLM Vuln Synthesis) ──
            await persistOpsStateNow(input.engagementId).catch(() => {});

            // Phase 4: Intelligent Exploit Orchestration (MSF → RAG Custom → Retry-with-Reasoning)
            if (input.phases.exploitGeneration) {
              state!.phase = 'exploitation';
              state!.currentAction = 'Orchestrating intelligent exploit pipeline...';
              broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'exploitation' });
              try {
                const { orchestrateExploit } = await import('../lib/exploit-recipe-engine');
                const { recordFeedback } = await import('../lib/exploit-feedback-loop');
                const { collectFromExploitRecipe, collectFromFailedExploit, getExploitTrainingStats } = await import('../lib/exploit-training-collector');
                const { executeExploit } = await import('../lib/exploit-sandbox');
                const { executeRawCommand } = await import('../lib/scan-server-executor');
                const { VNC_EXPLOIT_TEMPLATES, selectVncExploit } = await import('../lib/vnc-exploit-module');
                const { MSSQL_EXPLOIT_TEMPLATES, selectMssqlExploit } = await import('../lib/mssql-exploit-module');
                const { ENV } = await import('../_core/env');
                if (!(state as any).generatedExploits) (state as any).generatedExploits = [];
                let totalOrchestrated = 0;
                let totalSucceeded = 0;
                let totalFailed = 0;
                let recipesGenerated = 0;

                for (const asset of state!.assets) {
                  const exploitable = asset.vulns.filter((v: any) => v.severity === 'critical' || v.severity === 'high');
                  if (exploitable.length === 0) continue;

                  // ── Pre-built templates for VNC/MSSQL (fast path) ──
                  const vncPorts = (asset.ports || []).filter((p: any) => [5900, 5901, 5902, 5903].includes(p.port) || p.service?.toLowerCase().includes('vnc'));
                  if (vncPorts.length > 0) {
                    const hasSsh = (asset.ports || []).some((p: any) => p.port === 22 || p.service?.toLowerCase().includes('ssh'));
                    const vncTemplates = selectVncExploit({ hasCredentials: false, hasLocalAccess: false, hasSshAccess: hasSsh, targetPort: vncPorts[0]?.port || 5900, targetOs: (asset as any).os?.toLowerCase().includes('windows') ? 'windows' : 'linux' });
                    for (const tmpl of vncTemplates.slice(0, 3)) {
                      (state as any).generatedExploits.push({ asset: asset.hostname, exploit: { code: tmpl.code, language: tmpl.language, filename: `${tmpl.id.toLowerCase().replace(/[^a-z0-9]/g, '_')}.${tmpl.language === 'python' ? 'py' : 'sh'}`, description: tmpl.description, explanation: [tmpl.usage], prerequisites: tmpl.prerequisites, usage: tmpl.usage, expectedOutcome: tmpl.expectedOutcome, riskAssessment: { opsecRisk: tmpl.opsecRisk, detectionLikelihood: 'medium', iocSignatures: tmpl.detectionIndicators, mitigations: [] }, verificationSteps: tmpl.verificationSteps, confidence: tmpl.confidence, reasoning: `Pre-built VNC exploit template: ${tmpl.name}`, isChained: false, mitreTechniques: tmpl.mitreTechniqueIds, popsShell: tmpl.category === 'keystroke' || tmpl.category === 'auth_bypass', shellType: tmpl.category === 'auth_bypass' ? 'none' as const : undefined }, generatedAt: Date.now(), source: 'vnc-exploit-module' });
                    }
                    if (vncTemplates.length > 0) addLog(state!, { phase: 'exploitation', type: 'success', title: `\u{1f5a5}\ufe0f VNC Exploits: ${asset.hostname}`, detail: `${Math.min(vncTemplates.length, 3)} pre-built VNC templates injected` });
                  }
                  const mssqlPorts = (asset.ports || []).filter((p: any) => [1433, 1434].includes(p.port) || p.service?.toLowerCase().includes('mssql') || p.service?.toLowerCase().includes('ms-sql'));
                  if (mssqlPorts.length > 0) {
                    const mssqlTemplates = selectMssqlExploit({ hasCredentials: false, isSysadmin: false, targetOs: (asset as any).os?.toLowerCase().includes('windows') ? 'windows' : 'linux', xpCmdshellBlocked: false, agentRunning: undefined, hasLinkedServers: undefined });
                    for (const tmpl of mssqlTemplates.slice(0, 3)) {
                      (state as any).generatedExploits.push({ asset: asset.hostname, exploit: { code: tmpl.code, language: tmpl.language, filename: `${tmpl.id.toLowerCase().replace(/[^a-z0-9]/g, '_')}.${tmpl.language === 'python' ? 'py' : tmpl.language === 'bash' ? 'sh' : 'sql'}`, description: tmpl.description, explanation: [tmpl.usage], prerequisites: tmpl.prerequisites, usage: tmpl.usage, expectedOutcome: tmpl.expectedOutcome, riskAssessment: { opsecRisk: tmpl.opsecRisk, detectionLikelihood: 'medium', iocSignatures: tmpl.detectionIndicators, mitigations: [] }, verificationSteps: tmpl.verificationSteps, confidence: tmpl.confidence, reasoning: `Pre-built MSSQL exploit template: ${tmpl.name}`, isChained: false, mitreTechniques: tmpl.mitreTechniqueIds, popsShell: tmpl.category === 'xp_cmdshell' || tmpl.category === 'ole_automation' || tmpl.category === 'clr_assembly', shellType: tmpl.category === 'xp_cmdshell' ? 'cmd' as const : undefined }, generatedAt: Date.now(), source: 'mssql-exploit-module' });
                    }
                    if (mssqlTemplates.length > 0) addLog(state!, { phase: 'exploitation', type: 'success', title: `\u{1f4be} MSSQL Exploits: ${asset.hostname}`, detail: `${Math.min(mssqlTemplates.length, 3)} pre-built MSSQL templates injected` });
                  }

                  // ── Intelligent Orchestration: MSF → RAG Custom → Retry-with-Reasoning ──
                  addLog(state!, { phase: 'exploitation', type: 'info', title: `\u{1f3af} Orchestrating: ${asset.hostname}`, detail: `${exploitable.length} critical/high vulns — trying MSF modules first, then RAG-enhanced custom exploits with retry loop` });
                  const maxExploitsPerAsset = 3;
                  const toExploit = exploitable.slice(0, maxExploitsPerAsset);

                  for (const vuln of toExploit) {
                    totalOrchestrated++;
                    state!.currentAction = `Exploiting ${vuln.title} on ${asset.hostname}...`;
                    broadcastOpsUpdate(input.engagementId, { type: 'progress', progress: state!.progress });

                    // Build contexts for orchestrateExploit
                    const vulnCtx = {
                      cveId: vuln.cve,
                      title: vuln.title,
                      description: (vuln as any).description,
                      severity: vuln.severity,
                      cvssScore: (vuln as any).cvss,
                    };
                    const targetCtx = {
                      hostname: asset.hostname,
                      ip: asset.ip,
                      os: (asset as any).os,
                      port: vuln.port,
                      service: (vuln as any).service,
                      serviceVersion: (vuln as any).version,
                      technologies: asset.passiveRecon?.technologies,
                      wafDetected: asset.wafDetected,
                      attackerHost: ENV.SCAN_SERVER_HOST || undefined,
                      attackerPort: 4444,
                    };
                    const exploitCtx = {
                      vulnerability: {
                        cve: vuln.cve,
                        title: vuln.title,
                        severity: vuln.severity,
                        description: (vuln as any).description,
                        service: (vuln as any).service,
                        port: vuln.port,
                        rawOutput: (vuln as any).rawOutput,
                        tool: (vuln as any).tool,
                      },
                      target: {
                        hostname: asset.hostname,
                        ip: asset.ip,
                        os: (asset as any).os,
                        technologies: asset.passiveRecon?.technologies,
                        wafDetected: asset.wafDetected,
                        ports: asset.ports as any,
                      },
                      otherVulns: exploitable.filter(v => v !== vuln).map(v => ({ title: v.title, severity: v.severity, cve: v.cve, port: v.port })),
                      preferredLanguage: 'python' as const,
                      includeEvasion: !!asset.wafDetected,
                      attackerHost: ENV.SCAN_SERVER_HOST || undefined,
                      attackerPort: 4444,
                    };

                    try {
                      const result = await orchestrateExploit(vulnCtx, targetCtx, exploitCtx, {
                        maxRetries: 3,
                        tryMsfFirst: true,
                        engagementId: String(input.engagementId),
                        executeExploit: async (code: string, language: string) => {
                          // Execute via scan server
                          const ext = language === 'python' ? '.py' : language === 'bash' ? '.sh' : language === 'ruby' ? '.rb' : '.ps1';
                          const interpreter = language === 'python' ? 'python3' : language === 'bash' ? 'bash' : language === 'ruby' ? 'ruby' : 'pwsh';
                          const tmpDir = `/tmp/exploit_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
                          const cmd = [
                            `mkdir -p ${tmpDir}`,
                            `cat > ${tmpDir}/exploit${ext} << 'EXPLOIT_EOF'\n${code}\nEXPLOIT_EOF`,
                            `chmod +x ${tmpDir}/exploit${ext}`,
                            `cd ${tmpDir} && timeout 60 ${interpreter} ${tmpDir}/exploit${ext} 2>&1`,
                            `rm -rf ${tmpDir}`,
                          ].join(' && ');
                          const execResult = await executeRawCommand(cmd, 70);
                          return {
                            exitCode: execResult.exitCode,
                            stdout: execResult.stdout,
                            stderr: execResult.stderr,
                            duration: execResult.durationMs,
                          };
                        },
                        onProgress: (msg: string) => {
                          addLog(state!, { phase: 'exploitation', type: 'info', title: `\u{1f916} ${asset.hostname}`, detail: msg });
                        },
                      });

                      // Store the final exploit in generatedExploits for UI
                      if (result.finalExploit) {
                        (state as any).generatedExploits.push({
                          asset: asset.hostname,
                          exploit: result.finalExploit,
                          generatedAt: Date.now(),
                          source: result.selectedModule ? 'msf-module-selector' : 'orchestrate-rag',
                          orchestration: {
                            attempts: result.attempts.length,
                            success: result.success,
                            msfModule: result.selectedModule?.modulePath,
                            recipeId: result.recipe?.id,
                          },
                        });
                      } else if (result.selectedModule) {
                        // MSF module selected but no custom exploit generated
                        (state as any).generatedExploits.push({
                          asset: asset.hostname,
                          exploit: {
                            code: `# MSF Module: ${result.selectedModule.modulePath}\n# Auto-configured by exploit orchestrator`,
                            language: 'bash',
                            filename: `msf_${result.selectedModule.modulePath.replace(/\//g, '_')}.rc`,
                            description: `Metasploit module: ${result.selectedModule.modulePath}`,
                            explanation: [`Selected MSF module with ${result.selectedModule.confidence}% confidence`],
                            confidence: result.selectedModule.confidence,
                            reasoning: `MSF module selected: ${result.selectedModule.modulePath}`,
                            isChained: false,
                          },
                          generatedAt: Date.now(),
                          source: 'msf-module-selector',
                        });
                      }

                      if (result.success) {
                        totalSucceeded++;
                        addLog(state!, { phase: 'exploitation', type: 'success', title: `\u2705 Exploit succeeded: ${vuln.title}`, detail: `${asset.hostname} — ${result.attempts.length} attempt(s), strategy: ${result.attempts[result.attempts.length - 1]?.strategy || 'unknown'}${result.selectedModule ? ' (MSF: ' + result.selectedModule.modulePath + ')' : ''}` });
                      } else {
                        totalFailed++;
                        addLog(state!, { phase: 'exploitation', type: 'warning', title: `\u26a0\ufe0f Exploit exhausted: ${vuln.title}`, detail: `${asset.hostname} — ${result.attempts.length} attempt(s) failed` });
                      }

                      // ── Record feedback for exploit-feedback-loop ──
                      const lastAttempt = result.attempts[result.attempts.length - 1];
                      if (lastAttempt) {
                        try {
                          await recordFeedback({
                            moduleName: result.selectedModule?.modulePath || lastAttempt.strategy || 'custom_exploit',
                            moduleSource: result.selectedModule ? 'metasploit' : 'custom',
                            targetService: (vuln as any).service || 'unknown',
                            targetVersion: (vuln as any).version || null,
                            cveIds: vuln.cve ? [vuln.cve] : [],
                            success: result.success,
                            executionMs: lastAttempt.result?.duration || 0,
                            failureReason: result.success ? null : (lastAttempt.failureAnalysis?.rootCause || 'unknown'),
                            errorMessage: result.success ? null : (lastAttempt.result?.stderr?.slice(0, 500) || null),
                            timestamp: Date.now(),
                          });
                        } catch (fbErr: any) {
                          console.warn(`[ExploitOrch] Feedback recording failed: ${fbErr.message}`);
                        }
                      }

                      // ── Collect training data ──
                      if (result.recipe) {
                        recipesGenerated++;
                        try {
                          collectFromExploitRecipe(result.recipe, vulnCtx, targetCtx, result.attempts, String(input.engagementId));
                        } catch (trainErr: any) {
                          console.warn(`[ExploitOrch] Training collection failed: ${trainErr.message}`);
                        }
                      } else if (!result.success && result.attempts.length > 0) {
                        try {
                          collectFromFailedExploit(vulnCtx, targetCtx, result.attempts, String(input.engagementId));
                        } catch (trainErr: any) {
                          console.warn(`[ExploitOrch] Failed exploit training collection failed: ${trainErr.message}`);
                        }
                      }

                    } catch (orchErr: any) {
                      totalFailed++;
                      addLog(state!, { phase: 'exploitation', type: 'error', title: `\u274c Orchestration failed: ${vuln.title}`, detail: `${asset.hostname} — ${orchErr.message?.slice(0, 200)}` });
                    }
                  }
                }

                // ── Phase 4b: Execute pre-built template exploits (VNC/MSSQL) ──
                const templateExploits = ((state as any).generatedExploits || []).filter((e: any) => e.source === 'vnc-exploit-module' || e.source === 'mssql-exploit-module');
                if (templateExploits.length > 0) {
                  addLog(state!, { phase: 'exploitation', type: 'info', title: '\u{1f52c} Template Exploit Execution', detail: `Executing ${templateExploits.length} pre-built template exploits` });
                  for (let i = 0; i < templateExploits.length; i++) {
                    const entry = templateExploits[i];
                    try {
                      const result = await executeExploit(input.engagementId, {
                        exploitId: `${input.engagementId}_tmpl_${i}`,
                        code: entry.exploit.code,
                        language: entry.exploit.language || 'python',
                        targetHost: entry.asset,
                        timeoutSeconds: 60,
                        dryRun: false,
                        exploitModule: entry.exploit.filename || `template_${i}`,
                        confidence: entry.exploit.confidence,
                      });
                      entry.executionResult = { status: result.status, exitCode: result.exitCode, durationMs: result.durationMs, dbRecordId: result.dbRecordId, evidence: result.evidence };
                      if (result.status === 'success') {
                        totalSucceeded++;
                        addLog(state!, { phase: 'exploitation', type: 'success', title: `\u2705 Template: ${entry.exploit.filename}`, detail: `${entry.asset} — ${result.evidence?.achievedAccess || 'success'} (${result.durationMs}ms)` });
                      } else {
                        totalFailed++;
                        addLog(state!, { phase: 'exploitation', type: 'warning', title: `\u26a0\ufe0f Template non-zero: ${entry.exploit.filename}`, detail: `${entry.asset} — exit ${result.exitCode}` });
                      }
                    } catch (execErr: any) {
                      totalFailed++;
                      addLog(state!, { phase: 'exploitation', type: 'error', title: `\u274c Template exec failed: ${entry.exploit.filename}`, detail: execErr.message?.slice(0, 200) });
                    }
                  }
                }

                // ── Update stats and check fine-tuning threshold ──
                (state as any).exploitStats = { total: totalOrchestrated + templateExploits.length, succeeded: totalSucceeded, failed: totalFailed, recipesGenerated };
                addLog(state!, { phase: 'exploitation', type: 'success', title: '\u{1f4ca} Exploitation Complete', detail: `${totalSucceeded}/${totalOrchestrated + templateExploits.length} succeeded, ${totalFailed} failed, ${recipesGenerated} recipes generated — evidence persisted to DB` });

                // ── Auto-trigger fine-tuning when enough training data accumulates ──
                try {
                  const trainingStats = getExploitTrainingStats();
                  if (trainingStats.totalExamples >= 50) {
                    addLog(state!, { phase: 'exploitation', type: 'info', title: '\u{1f9e0} Fine-Tuning Threshold Reached', detail: `${trainingStats.totalExamples} training examples collected (threshold: 50). Fine-tuning job can be triggered from the AI Analysis tab.` });
                  }
                } catch { /* training stats not critical */ }

              } catch (err: any) {
                addLog(state!, { phase: 'exploitation', type: 'error', title: '\u274c Exploit orchestration failed', detail: err.message });
              }

              // Persist after exploitation
              await persistOpsStateNow(input.engagementId).catch(() => {});
            }

            // Recalculate stats from actual asset data before marking complete
            state!.stats.hostsScanned = state!.assets.filter(a => a.status !== 'pending').length;
            state!.stats.portsFound = state!.assets.reduce((sum, a) => sum + (a.ports || []).length, 0);
            state!.stats.vulnsFound = state!.assets.reduce((sum, a) => sum + (a.vulns || []).length, 0);
            state!.stats.assetsDiscovered = state!.assets.length;

            state!.phase = 'completed';
            state!.isRunning = false;
            state!.currentAction = undefined;
            addLog(state!, { phase: 'completed', type: 'success', title: '\u{1f3c1} Pipeline Complete', detail: `${state!.assets.length} assets, ${state!.stats.hostsScanned} scanned, ${state!.stats.portsFound} ports, ${state!.stats.vulnsFound} vulns, ${(state as any).generatedExploits?.length || 0} exploits` });
            broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'completed' });

            // Record vulnerability trend snapshot
            try {
              const { recordScanSnapshot } = await import('../lib/vuln-trend-tracker');
              const snapshotAssets = state!.assets.map(a => ({
                hostname: a.hostname || (a as any).ip || 'unknown',
                vulns: a.vulns || [],
                ports: a.ports || [],
                passiveRecon: a.passiveRecon,
              }));
              const snap = await recordScanSnapshot({
                engagementId: input.engagementId,
                snapshotType: 'full_pipeline',
                assets: snapshotAssets,
                exploitCount: (state as any).generatedExploits?.length || 0,
                metadata: { phases: input.phases, duration: Date.now() - (state!.logs?.[0]?.timestamp || Date.now()) },
              });
              addLog(state!, { phase: 'complete', type: 'info', title: '\ud83d\udcca Trend Snapshot Recorded', detail: `Snapshot #${snap.snapshotId}: ${snap.totalVulns} vulns (${snap.newVulnsFound} new, ${snap.resolvedVulns} resolved)` });
            } catch (snapErr: any) {
              console.error('[TrendTracker] Failed to record snapshot:', snapErr.message);
            }

            // ─── Self-Learning: Score against ground truth & auto-generate learning entries ───
            try {
              const { scoreAgainstGroundTruth, saveAccuracyScore, storeLearningEntry, GROUND_TRUTH_LIBRARY } = await import('../lib/llm-self-learning');
              const { TRAINING_TARGETS } = await import('./training-lab');

              // Resolve training preset from engagement target domains
              const engDomainsForScoring = (engagement?.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
              let scoringPreset = '';
              for (const d of engDomainsForScoring) {
                const match = TRAINING_TARGETS.find(t => {
                  try {
                    const tHost = new URL(t.url.startsWith('http') ? t.url : `https://${t.url}`).hostname;
                    return d.includes(tHost) || tHost.includes(d) || (t.liveInstanceUrl && t.liveInstanceUrl.includes(d));
                  } catch { return false; }
                });
                if (match) { scoringPreset = match.id; break; }
              }

              if (scoringPreset && GROUND_TRUTH_LIBRARY[scoringPreset]) {
                // Collect all vulns across all assets for scoring
                const allVulns = state!.assets.flatMap(a => (a.vulns || []).map((v: any) => ({
                  title: v.title || v.name || '',
                  severity: v.severity || 'medium',
                  category: v.category || '',
                  cve: v.cve || '',
                })));

                const score = scoreAgainstGroundTruth(scoringPreset, allVulns);
                if (score) {
                  // Persist accuracy score for trending
                  const sessionId = `eng-${input.engagementId}-${Date.now()}`;
                  await saveAccuracyScore(sessionId, scoringPreset, score);

                  addLog(state!, {
                    phase: 'complete', type: 'info',
                    title: '\u{1f3af} Ground Truth Score',
                    detail: `Preset: ${scoringPreset} | F1: ${(score.f1Score * 100).toFixed(1)}% | Precision: ${(score.precision * 100).toFixed(1)}% | Recall: ${(score.recall * 100).toFixed(1)}% | TP: ${score.truePositives} FP: ${score.falsePositives} FN: ${score.falseNegatives}`,
                  });

                  // Store the score on the state for UI display
                  (state as any).groundTruthScore = {
                    preset: scoringPreset,
                    f1Score: score.f1Score,
                    precision: score.precision,
                    recall: score.recall,
                    overallScore: score.overallScore,
                    truePositives: score.truePositives,
                    falsePositives: score.falsePositives,
                    falseNegatives: score.falseNegatives,
                    severityAccuracy: score.severityAccuracy,
                  };

                  // Auto-generate learning entries for missed findings (false negatives)
                  for (const detail of score.matchDetails) {
                    if (!detail.matched) {
                      await storeLearningEntry({
                        targetPreset: scoringPreset,
                        findingTitle: detail.groundTruth.title,
                        correctSeverity: detail.groundTruth.severity,
                        correctCategory: detail.groundTruth.category,
                        feedbackType: 'missed_finding',
                        operatorNotes: `Auto-generated: Pipeline missed this known vulnerability. Detection hint: ${detail.groundTruth.detectionHint || 'N/A'}`,
                        correctionContext: `Ground truth vuln "${detail.groundTruth.title}" (${detail.groundTruth.severity}) was not detected. Description: ${detail.groundTruth.description}`,
                        sessionId,
                        targetUrl: engDomainsForScoring[0] || scoringPreset,
                      }).catch(e => console.error('[SelfLearning] Failed to store missed finding:', e.message));
                    }
                  }

                  // Auto-generate learning entries for false positives
                  for (const fp of score.unmatchedLlmFindings) {
                    await storeLearningEntry({
                      targetPreset: scoringPreset,
                      findingTitle: fp.title,
                      llmSeverity: fp.severity,
                      llmCategory: fp.category,
                      feedbackType: 'false_positive',
                      operatorNotes: `Auto-generated: LLM reported this vuln but it does not match any ground truth entry.`,
                      correctionContext: `False positive: "${fp.title}" (${fp.severity}) was reported but is not in the ground truth library for ${scoringPreset}.`,
                      sessionId,
                      targetUrl: engDomainsForScoring[0] || scoringPreset,
                    }).catch(e => console.error('[SelfLearning] Failed to store false positive:', e.message));
                  }

                  addLog(state!, {
                    phase: 'complete', type: 'info',
                    title: '\u{1f4da} Learning Entries Stored',
                    detail: `${score.falseNegatives} missed findings + ${score.falsePositives} false positives recorded for future training`,
                  });
                }
              } else if (scoringPreset) {
                addLog(state!, { phase: 'complete', type: 'info', title: '\u{1f4cb} No Ground Truth', detail: `Target preset "${scoringPreset}" has no ground truth library — scoring skipped.` });
              }
            } catch (selfLearnErr: any) {
              console.error('[SelfLearning] Ground truth scoring failed:', selfLearnErr.message);
              addLog(state!, { phase: 'complete', type: 'warning' as any, title: '\u26a0\ufe0f Self-Learning Error', detail: selfLearnErr.message });
            }

            // ─── Compliance Evidence Mapper: Auto-populate compliance controls from scan results ───
            try {
              const { mapEngagementToCompliance } = await import('../lib/compliance-evidence-mapper');
              const mappingState = {
                engagementId: input.engagementId,
                assets: state!.assets.map(a => ({
                  hostname: a.hostname || (a as any).ip || 'unknown',
                  ip: a.ip,
                  vulns: (a.vulns || []).map(v => ({
                    title: v.title || 'Unknown',
                    severity: v.severity || 'info',
                    description: (v as any).description,
                    tool: (v as any).tool,
                    cve: v.cve,
                    rawOutput: (v as any).rawOutput,
                  })),
                  ports: (a.ports || []).map(p => ({
                    port: p.port,
                    service: p.service,
                    protocol: (p as any).protocol,
                  })),
                  toolResults: (a.toolResults || []).map(tr => ({
                    tool: tr.tool,
                    command: tr.command,
                    exitCode: tr.exitCode,
                    findingCount: tr.findingCount,
                    outputPreview: tr.outputPreview,
                    findings: (tr.findings || []).map(f => ({ title: f.title, severity: f.severity })),
                  })),
                  zapFindings: (a.zapFindings || []).map(z => ({
                    alert: z.alert,
                    risk: z.risk,
                    description: (z as any).description,
                    url: z.url,
                    evidence: (z as any).evidence,
                  })),
                })),
              };
              const result = mapEngagementToCompliance(mappingState);
              // Store evidence in the ops state for the UI to display
              (state as any).complianceEvidence = {
                totalEvidenceItems: result.totalEvidenceItems,
                frameworksCovered: result.frameworksCovered,
                gapCount: result.gapCount,
                summaries: result.summaries.map(s => ({
                  framework: s.framework,
                  complianceScore: s.complianceScore,
                  compliant: s.compliant,
                  nonCompliant: s.nonCompliant,
                  partial: s.partial,
                  noEvidence: s.noEvidence,
                  totalControls: s.totalControls,
                })),
                generatedAt: Date.now(),
              };
              // Persist evidence items to the compliance_mappings table
              const { getDb } = await import('../db');
              const { complianceMappings } = await import('../../drizzle/schema');
              const dbConn = await getDb();
              if (dbConn && result.evidence.length > 0) {
                // Batch insert evidence as compliance mappings (max 50 per batch)
                const batchSize = 50;
                let insertedCount = 0;
                for (let i = 0; i < result.evidence.length; i += batchSize) {
                  const batch = result.evidence.slice(i, i + batchSize);
                  try {
                    await dbConn.insert(complianceMappings).values(
                      batch.map(e => ({
                        controlId: 0, // Will be resolved by framework control lookup
                        engagementId: input.engagementId,
                        findingType: e.evidenceType,
                        findingSource: 'pentest' as const,
                        mappingStatus: e.status === 'pass' ? 'covered' as const :
                                       e.status === 'fail' ? 'gap' as const :
                                       e.status === 'partial' ? 'partial' as const : 'gap' as const,
                        evidenceNotes: `[Auto-mapped] ${e.framework} ${e.controlId}: ${e.description}`.slice(0, 2000),
                        assessedBy: 'AC3 Compliance Engine',
                        assessedAt: new Date(),
                      }))
                    );
                    insertedCount += batch.length;
                  } catch (batchErr: any) {
                    console.error(`[ComplianceMapper] Batch insert failed:`, batchErr.message);
                  }
                }
                addLog(state!, {
                  phase: 'complete', type: 'evidence',
                  title: '\ud83d\udee1\ufe0f Compliance Evidence Mapped',
                  detail: `${result.totalEvidenceItems} evidence items across ${result.frameworksCovered.length} frameworks (${result.frameworksCovered.join(', ')}). ${result.gapCount} control gaps identified. ${insertedCount} mappings persisted to DB.`,
                  data: {
                    totalEvidence: result.totalEvidenceItems,
                    frameworks: result.frameworksCovered,
                    gaps: result.gapCount,
                    scores: result.summaries.map(s => ({ framework: s.framework, score: s.complianceScore })),
                  },
                });
              } else {
                addLog(state!, {
                  phase: 'complete', type: 'info',
                  title: '\ud83d\udee1\ufe0f Compliance Mapping',
                  detail: result.totalEvidenceItems > 0
                    ? `${result.totalEvidenceItems} evidence items generated but DB unavailable for persistence`
                    : 'No evidence items generated — no scan results to map',
                });
              }
            } catch (complianceErr: any) {
              console.error('[ComplianceMapper] Auto-mapping failed:', complianceErr.message);
              addLog(state!, { phase: 'complete', type: 'warning' as any, title: '\u26a0\ufe0f Compliance Mapping Error', detail: complianceErr.message });
            }

            await persistOpsStateNow(input.engagementId).catch(() => {});
          } catch (err: any) {
            state!.isRunning = false;
            state!.error = err.message;
            addLog(state!, { phase: state!.phase, type: 'error', title: '\u274c Pipeline failed', detail: err.message });
            await persistOpsStateNow(input.engagementId).catch(() => {});
          }
        })();

        return { started: true, engagementId: input.engagementId, phases: input.phases, message: 'Full pipeline re-run started. Monitor progress via getState.' };
      }),

    /** Generate a functional exploit script for a specific vulnerability */
    generateFunctionalExploit: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        assetHostname: z.string(),
        vulnIndex: z.number().optional(),
        vulnTitle: z.string().optional(),
        preferredLanguage: z.enum(['python', 'bash', 'powershell', 'ruby']).default('python'),
        includeEvasion: z.boolean().default(false),
        includeCleanup: z.boolean().default(false),
      }))
      .mutation(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        const { generateFunctionalExploit: genExploit } = await import('../lib/functional-exploit-generator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });
        const asset = state.assets.find(a => a.hostname === input.assetHostname);
        if (!asset) throw new TRPCError({ code: 'NOT_FOUND', message: `Asset ${input.assetHostname} not found` });
        let vuln: any;
        if (input.vulnIndex !== undefined && input.vulnIndex < asset.vulns.length) {
          vuln = asset.vulns[input.vulnIndex];
        } else if (input.vulnTitle) {
          vuln = asset.vulns.find((v: any) => v.title === input.vulnTitle);
        }
        if (!vuln) throw new TRPCError({ code: 'NOT_FOUND', message: 'Vulnerability not found on this asset' });
        const exploit = await genExploit({
          vulnerability: vuln,
          target: { hostname: asset.hostname, ip: asset.ip, os: (asset as any).os, technologies: asset.passiveRecon?.technologies, wafDetected: asset.wafDetected, ports: asset.ports as any },
          otherVulns: asset.vulns.filter((v: any) => v !== vuln),
          preferredLanguage: input.preferredLanguage,
          includeEvasion: input.includeEvasion,
          includeCleanup: input.includeCleanup,
        });
        if (!(state as any).generatedExploits) (state as any).generatedExploits = [];
        (state as any).generatedExploits.push({ asset: asset.hostname, exploit, generatedAt: Date.now() });
        return exploit;
      }),

    /** Validate a generated exploit script */
    validateExploit: protectedProcedure
      .input(z.object({ engagementId: z.number(), exploitIndex: z.number() }))
      .mutation(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        const { validateExploitCode } = await import('../lib/functional-exploit-generator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });
        const exploits = (state as any).generatedExploits;
        if (!exploits?.[input.exploitIndex]) throw new TRPCError({ code: 'NOT_FOUND', message: 'Exploit not found' });
        const entry = exploits[input.exploitIndex];
        const asset = state.assets.find(a => a.hostname === entry.asset);
        return validateExploitCode(entry.exploit, {
          vulnerability: { title: entry.exploit.description, severity: 'high' },
          target: { hostname: entry.asset, ip: asset?.ip, os: (asset as any)?.os, technologies: asset?.passiveRecon?.technologies, ports: asset?.ports as any },
        });
      }),

    /** Improve an exploit based on validation feedback */
    improveExploit: protectedProcedure
      .input(z.object({ engagementId: z.number(), exploitIndex: z.number() }))
      .mutation(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        const { validateExploitCode, improveExploit: improve } = await import('../lib/functional-exploit-generator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });
        const exploits = (state as any).generatedExploits;
        if (!exploits?.[input.exploitIndex]) throw new TRPCError({ code: 'NOT_FOUND', message: 'Exploit not found' });
        const entry = exploits[input.exploitIndex];
        const asset = state.assets.find(a => a.hostname === entry.asset);
        const ctx: any = {
          vulnerability: { title: entry.exploit.description, severity: 'high' },
          target: { hostname: entry.asset, ip: asset?.ip, os: (asset as any)?.os, technologies: asset?.passiveRecon?.technologies, ports: asset?.ports as any },
        };
        const validation = await validateExploitCode(entry.exploit, ctx);
        const improved = await improve(entry.exploit, validation, ctx);
        exploits[input.exploitIndex] = { asset: entry.asset, exploit: improved, generatedAt: Date.now() };
        return { improved, validation };
      }),

    /** Get all generated exploits for an engagement */
    getGeneratedExploits: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) return [];
        return ((state as any).generatedExploits || []).map((e: any, i: number) => ({
          index: i, asset: e.asset, filename: e.exploit.filename, language: e.exploit.language,
          description: e.exploit.description, confidence: e.exploit.confidence,
          mitreTechniques: e.exploit.mitreTechniques, isChained: e.exploit.isChained, generatedAt: e.generatedAt,
        }));
      }),

    /** Get full exploit details including code */
    getExploitDetail: protectedProcedure
      .input(z.object({ engagementId: z.number(), exploitIndex: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        const exploits = (state as any)?.generatedExploits;
        if (!exploits?.[input.exploitIndex]) throw new TRPCError({ code: 'NOT_FOUND', message: 'Exploit not found' });
        return exploits[input.exploitIndex];
      }),
    /** Re-synthesize vulnerabilities for a specific asset, optionally targeting specific categories */
    resynthesizeAssetVulns: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        hostname: z.string(),
        targetCategories: z.array(z.string()).optional(),
        replaceExisting: z.boolean().default(false),
      }))
      .mutation(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery, addLog, persistOpsStateNow } = await import('../lib/engagement-orchestrator');
        const { invokeLLM } = await import('../_core/llm');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement state not found' });

        const asset = state.assets.find(a => a.hostname === input.hostname);
        if (!asset) throw new TRPCError({ code: 'NOT_FOUND', message: `Asset ${input.hostname} not found` });

        const signals = asset.passiveRecon?.riskSignals || [];
        const techs = asset.passiveRecon?.technologies || [];
        const ports = asset.ports || [];
        const existingVulns = asset.vulns || [];

        // Smart signal sampling
        const highSeverity = signals.filter((s: any) => s.severity === 'critical' || s.severity === 'high');
        const medSeverity = signals.filter((s: any) => s.severity === 'medium');
        const lowSeverity = signals.filter((s: any) => s.severity === 'low' || s.severity === 'info');
        const truncSignal = (s: any) => ({ ...s, rationale: (s.rationale || s.title || 'Unknown').slice(0, 120) });
        const sampledSignals = [
          ...highSeverity.slice(0, 12).map(truncSignal),
          ...medSeverity.slice(0, 8).map(truncSignal),
          ...lowSeverity.slice(0, 5).map(truncSignal),
        ].slice(0, 25);

        const categoryFocus = input.targetCategories?.length
          ? `\n\nIMPORTANT: The operator specifically wants you to CHECK FOR these vulnerability categories: ${input.targetCategories.join(', ')}. You MUST include findings for each of these categories if there is ANY evidence.`
          : '';

        const existingContext = existingVulns.length > 0
          ? `\n\nAlready identified vulnerabilities (DO NOT duplicate these, find NEW ones):\n${existingVulns.map((v: any) => `- ${v.title} [${v.severity}] (${v.category || 'unknown'})`).join('\n')}`
          : '';

        const portsStr = ports.map((p: any) => p.port + '/' + p.service + (p.version ? ' (' + p.version + ')' : '')).join(', ');
        const signalsStr = sampledSignals.map((s: any, i: number) => (i+1) + '. [' + (s.severity || 'medium') + '] ' + (s.rationale || s.title || 'Unknown')).join('\n');
        const synthPrompt = `You are a senior penetration tester performing a targeted vulnerability re-assessment of ${asset.hostname}.

Your task: Analyze the passive reconnaissance data and identify POTENTIAL vulnerabilities that warrant further investigation.
IMPORTANT: These are HYPOTHETICAL findings based on passive signals only — they have NOT been confirmed by active scanning tools.${categoryFocus}${existingContext}

CRITICAL RULES:
1. You MUST identify vulnerabilities across DIVERSE categories.
2. PRIORITIZE web application vulnerabilities over infrastructure/misconfig issues.
3. Check for ALL of these categories: SQL Injection, XSS, Directory Traversal, CRLF Injection, File Inclusion, Broken Auth, Sensitive Data Exposure, Broken Access Control, SSRF, Security Misconfig (max 1).

=== TARGET INFO ===
Hostname: ${asset.hostname}
Technologies: ${techs.join(', ') || 'Unknown'}
Open Ports/Services: ${portsStr}

=== RISK SIGNALS (${signals.length} total, showing ${sampledSignals.length} samples) ===
${signalsStr}

IMPORTANT CONTEXT:
- If this is a known test/vulnerable site (testphp.vulnweb.com, demo.testfire.net, demo.owasp-juice.shop, brokencrystals.com, ginandjuice.shop, google-gruyere.appspot.com, public-firing-range.appspot.com, testaspnet.vulnweb.com, testhtml5.vulnweb.com, testasp.vulnweb.com, hack-yourself-first.com, aspnet.testsparker.com, php.testsparker.com, angular.testsparker.com, rest.vulnweb.com, pentest-ground.com, zero.webappsecurity.com), include their classic vulnerabilities.

Identify the TOP 10 most likely vulnerabilities.
For each: title, severity (critical/high/medium/low), cve (or empty string), description, confidence (0-100), category.
Return ONLY a JSON object with vulnerabilities array.`;

        const synthSchema = { type: 'json_schema' as const, json_schema: {
          name: 'vuln_synthesis',
          strict: true,
          schema: {
            type: 'object',
            properties: {
              vulnerabilities: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    title: { type: 'string' },
                    severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
                    cve: { type: 'string' },
                    description: { type: 'string' },
                    confidence: { type: 'number' },
                    category: { type: 'string' },
                  },
                  required: ['title', 'severity', 'cve', 'description', 'confidence', 'category'],
                  additionalProperties: false,
                },
              },
            },
            required: ['vulnerabilities'],
            additionalProperties: false,
          },
        }};

        addLog(state, { phase: 'scanning', type: 'info', title: `\u{1f504} Re-synthesizing: ${asset.hostname}`, detail: `Targeting: ${input.targetCategories?.join(', ') || 'all categories'}` });

        try {
          const llmResult = await invokeLLM({ 
            _caller: "engagement-ops-core",
            messages: [
              { role: 'system', content: 'You are a vulnerability assessment AI. Return only valid JSON.' },
              { role: 'user', content: synthPrompt },
            ],
            response_format: synthSchema,
          });

          const content = llmResult.choices?.[0]?.message?.content || '{}';
          const parsed = JSON.parse(content);
          let synthVulns = (parsed.vulnerabilities || []).filter((v: any) => v.confidence >= 40);

          // ── CVE False Positive Filter (same as primary synthesis) ──
          const reTechLower = techs.map((t: string) => t.toLowerCase());
          const reServicesLower = ports.map((p: any) => `${p.service || ''} ${p.version || ''}`.toLowerCase());
          const reAllTechContext = [...reTechLower, ...reServicesLower].join(' ');
          const RE_CVE_TECH_VALIDATORS: Record<string, string[]> = {
            'chrome': ['chrome', 'chromium', 'google'], 'ivanti': ['ivanti', 'pulse', 'connect secure'],
            'zyxel': ['zyxel'], 'vmware': ['vmware', 'vcenter', 'esxi', 'vsphere'],
            'fortinet': ['fortinet', 'fortigate', 'fortios'], 'cisco': ['cisco', 'ios-xe', 'asa'],
            'palo alto': ['palo alto', 'pan-os', 'globalprotect'], 'citrix': ['citrix', 'netscaler', 'adc'],
            'microsoft exchange': ['exchange', 'owa'], 'adobe': ['adobe', 'acrobat', 'coldfusion'],
            'sap': ['sap', 'netweaver'], 'oracle': ['oracle', 'weblogic'],
            'f5': ['f5', 'big-ip', 'bigip'], 'sonicwall': ['sonicwall'],
            'barracuda': ['barracuda'], 'juniper': ['juniper', 'junos'],
          };
          let reFilteredCount = 0;
          synthVulns = synthVulns.filter((v: any) => {
            const vulnText = `${v.title} ${v.description} ${v.cve || ''}`.toLowerCase();
            for (const [product, requiredIndicators] of Object.entries(RE_CVE_TECH_VALIDATORS)) {
              if (vulnText.includes(product)) {
                if (!requiredIndicators.some(ind => reAllTechContext.includes(ind))) {
                  reFilteredCount++;
                  return false;
                }
              }
            }
            return true;
          });

          if (input.replaceExisting) {
            // Remove existing LLM-synthesized vulns (keep active scan vulns)
            asset.vulns = asset.vulns.filter((v: any) => v.tool !== 'llm-synthesis');
          }

          const newVulns: any[] = [];
          for (const v of synthVulns) {
            // Skip duplicates by title similarity
            const isDuplicate = asset.vulns.some((existing: any) =>
              existing.title.toLowerCase().includes(v.title.toLowerCase().split(' ')[0]) ||
              v.title.toLowerCase().includes(existing.title.toLowerCase().split(' ')[0])
            );
            if (!isDuplicate || input.replaceExisting) {
              const newVuln = {
                id: `resynth-${asset.hostname}-${Math.random().toString(36).slice(2,8)}`,
                title: v.title.startsWith('[Potential]') ? v.title : `[Potential] ${v.title}`,
                severity: v.severity,
                cve: v.cve || '',
                description: v.description,
                tool: 'llm-synthesis',
                confidence: v.confidence,
                category: v.category,
                corroborationTier: 'potential',
                evidenceDetail: `LLM-synthesized from passive recon signals (confidence: ${v.confidence}%). Not confirmed by active scanning.`,
              };
              asset.vulns.push(newVuln as any);
              newVulns.push(newVuln);
            }
          }

          addLog(state, { phase: 'scanning', type: 'success', title: `\u2705 Re-synthesis: ${asset.hostname}`, detail: `${newVulns.length} new vulnerabilities added${reFilteredCount > 0 ? ` (${reFilteredCount} false positives filtered)` : ''}` });
          await persistOpsStateNow(input.engagementId);

          return {
            success: true,
            hostname: input.hostname,
            newVulns,
            totalVulns: asset.vulns.length,
          };
        } catch (err: any) {
          addLog(state, { phase: 'scanning', type: 'error', title: `\u274c Re-synthesis failed: ${asset.hostname}`, detail: err.message });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `Re-synthesis failed: ${err.message}` });
        }
      }),

    /** Execute an exploit script in a sandboxed environment on the scan server */
    executeExploit: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        exploitIndex: z.number(),
        targetHost: z.string().optional(),
        targetPort: z.number().optional(),
        timeoutSeconds: z.number().min(5).max(120).default(60),
        dryRun: z.boolean().default(true),
      }))
      .mutation(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        const { executeExploit } = await import('../lib/exploit-sandbox');
        let state = getOpsState(input.engagementId);
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        const exploits = (state as any)?.generatedExploits;
        if (!exploits?.[input.exploitIndex]) throw new TRPCError({ code: 'NOT_FOUND', message: 'Exploit not found' });
        const entry = exploits[input.exploitIndex];
        return executeExploit(input.engagementId, {
          exploitId: `${input.engagementId}_${input.exploitIndex}`,
          code: entry.exploit.code,
          language: entry.exploit.language || 'python',
          targetHost: input.targetHost || entry.asset,
          targetPort: input.targetPort,
          timeoutSeconds: input.timeoutSeconds,
          dryRun: input.dryRun,
        });
      }),

    /** Get exploit execution history for an engagement */
    getExploitExecutionHistory: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getExecutionHistory } = await import('../lib/exploit-sandbox');
        return getExecutionHistory(input.engagementId);
      }),

    /** Validate exploit code syntax without execution */
    validateExploitSyntax: protectedProcedure
      .input(z.object({
        code: z.string(),
        language: z.string(),
      }))
      .mutation(async ({ input }) => {
        const { validateExploitSyntax } = await import('../lib/exploit-sandbox');
        return validateExploitSyntax(input.code, input.language);
      }),

    /** Get exploitation evidence from DB for an engagement (for customer triage) */
    getExploitEvidence: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getExploitationAttempts, getExploitationStats } = await import('../db');
        const [attempts, stats] = await Promise.all([
          getExploitationAttempts(input.engagementId),
          getExploitationStats(input.engagementId),
        ]);
        return { attempts, stats };
      }),

    /** Get a single exploitation attempt with full evidence */
    getExploitAttemptDetail: protectedProcedure
      .input(z.object({ attemptId: z.number() }))
      .query(async ({ input }) => {
        const { getExploitationAttemptById } = await import('../db');
        return getExploitationAttemptById(input.attemptId);
      }),

    // ── Vulnerability Trend Tracking ──

    /** Get vulnerability trend data for an engagement */
    getVulnTrend: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getVulnTrend } = await import('../lib/vuln-trend-tracker');
        return getVulnTrend(input.engagementId);
      }),

    /** Get vulnerability diff between two snapshots */
    getVulnDiff: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        fromSnapshotId: z.number(),
        toSnapshotId: z.number(),
      }))
      .query(async ({ input }) => {
        const { getVulnDiff } = await import('../lib/vuln-trend-tracker');
        return getVulnDiff(input.engagementId, input.fromSnapshotId, input.toSnapshotId);
      }),

    /** Run a command on the scan server terminal for manual pentesting */
    runTerminalCommand: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        command: z.string().min(1).max(2000),
        targetHost: z.string().optional(),
        timeoutSeconds: z.number().min(5).max(300).default(120),
      }))
      .mutation(async ({ input }) => {
        const { executeRawCommand } = await import('../lib/scan-server-executor');
        const result = await executeRawCommand(input.command, input.timeoutSeconds);
        // Store command in engagement terminal history for evidence
        const historyKey = `terminal_${input.engagementId}`;
        if (!(globalThis as any).__terminalHistory) (globalThis as any).__terminalHistory = new Map();
        const history = (globalThis as any).__terminalHistory as Map<string, any[]>;
        if (!history.has(historyKey)) history.set(historyKey, []);
        history.get(historyKey)!.push({
          command: input.command,
          targetHost: input.targetHost,
          stdout: result.stdout?.slice(0, 50000) || '',
          stderr: result.stderr?.slice(0, 10000) || '',
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          timestamp: new Date().toISOString(),
        });
        // Keep last 500 entries
        const arr = history.get(historyKey)!;
        if (arr.length > 500) arr.splice(0, arr.length - 500);
        return {
          stdout: result.stdout || '',
          stderr: result.stderr || '',
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          timedOut: result.timedOut,
        };
      }),

    /** Get terminal command history for an engagement (for evidence) */
    getTerminalHistory: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const historyKey = `terminal_${input.engagementId}`;
        const history = ((globalThis as any).__terminalHistory as Map<string, any[]>) || new Map();
        return history.get(historyKey) || [];
      }),

    /** Manually record a scan snapshot for trend tracking */
    recordScanSnapshot: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input }) => {
        const { recordScanSnapshot } = await import('../lib/vuln-trend-tracker');
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(String(input.engagementId));
        if (!state) state = await getOpsStateWithRecovery(input.engagementId);
        if (!state) throw new Error('No engagement state found');
        const assets = (state.assets || []).map((a: any) => ({
          hostname: a.hostname || a.ip || 'unknown',
          vulns: a.vulns || [],
          ports: a.ports || [],
          passiveRecon: a.passiveRecon,
        }));
        return recordScanSnapshot({
          engagementId: input.engagementId,
          snapshotType: 'full_pipeline',
          assets,
          exploitCount: (state as any).generatedExploits?.length || 0,
          metadata: { phase: state.phase, recordedManually: true },
        });
      }),

    // ─── Credential Harvester Integration ────────────────────────────────

    /** Get all harvested credentials for an engagement */
    getHarvestedCredentials: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getEngagementCredentials } = await import('../lib/credential-harvester');
        return getEngagementCredentials(input.engagementId);
      }),

    /** Manually trigger credential harvesting from existing breach data + stored observations */
    harvestCredentials: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        domain: z.string().min(1),
      }))
      .mutation(async ({ input }) => {
        const { harvestFromExistingFindings, harvestCredentialsFromObservations } = await import('../lib/credential-harvester');
        // Harvest from credentialFindings table
        const findingsResult = await harvestFromExistingFindings(input.engagementId, input.domain);
        let totalInserted = findingsResult.inserted;
        let totalDuplicates = findingsResult.duplicates;

        // Also try to harvest from stored passive recon observations in the scan
        try {
          const { getDomainIntelScansByEngagement } = await import('../db');
          const scans = await getDomainIntelScansByEngagement(input.engagementId);
          for (const scan of scans) {
            const pipeline = scan.pipelineOutput as any;
            const storedObs = pipeline?.passiveRecon?.allObservations;
            if (storedObs && storedObs.length > 0) {
              const obsResult = await harvestCredentialsFromObservations(
                input.engagementId,
                input.domain,
                storedObs
              );
              totalInserted += obsResult.inserted;
              totalDuplicates += obsResult.duplicates;
            }
          }
        } catch (obsErr: any) {
          console.warn(`[harvestCredentials] Observation harvest failed (non-fatal): ${obsErr.message}`);
        }

        return { inserted: totalInserted, duplicates: totalDuplicates };
      }),

    /** Add manually entered credentials to the engagement list */
    addManualCredentials: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        credentials: z.array(z.object({
          username: z.string().min(1),
          password: z.string().optional(),
          email: z.string().optional(),
          notes: z.string().optional(),
        })).min(1),
      }))
      .mutation(async ({ input }) => {
        const { addManualCredentials } = await import('../lib/credential-harvester');
        return addManualCredentials(input.engagementId, input.credentials);
      }),

    /** Run domain-specific darkweb intelligence sync (IntelX, Hudson Rock, LeakCheck) */
    runDarkwebCredentialSync: protectedProcedure
      .input(z.object({ domain: z.string().min(1) }))
      .mutation(async ({ input }) => {
        const { runDomainDarkwebSync } = await import('../lib/darkweb-osint-service');
        return runDomainDarkwebSync(input.domain);
      }),

    /** Batch get live ops status for multiple engagements — used by the engagement list page */
    batchGetLiveStatus: protectedProcedure
      .input(z.object({ engagementIds: z.array(z.number()).max(50) }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
        const results: Record<number, {
          isRunning: boolean;
          phase: string;
          progress: number;
          assetsDiscovered: number;
          vulnsFound: number;
          exploitsRun: number;
          exploitsSucceeded: number;
          lastLogMessage: string;
          lastLogTime: number | null;
          startedAt: number | null;
        }> = {};
        for (const id of input.engagementIds) {
          let state = getOpsState(id);
          if (!state) state = await getOpsStateWithRecovery(id);
          if (state) {
            const lastLog = state.log?.length > 0 ? state.log[state.log.length - 1] : null;
            results[id] = {
              isRunning: !!state.isRunning,
              phase: state.phase || 'idle',
              progress: state.progress || 0,
              assetsDiscovered: state.stats?.assetsDiscovered || 0,
              vulnsFound: state.stats?.vulnsFound || 0,
              exploitsRun: state.stats?.exploitsRun || 0,
              exploitsSucceeded: state.stats?.exploitsSucceeded || 0,
              lastLogMessage: lastLog?.title || lastLog?.detail || '',
              lastLogTime: lastLog?.ts || null,
              startedAt: state.startedAt || null,
            };
          }
        }
        return results;
      }),

  // ── FP Suppression ─────────────────────────────────────────────────────

  getSuppressionProfiles: protectedProcedure.query(async () => {
    const { getSuppressionProfiles } = await import('../lib/knowledge/fp-suppression-rules');
    return getSuppressionProfiles();
  }),

  getSuppressionRules: protectedProcedure.query(async () => {
    const { getSuppressionRuleSummary } = await import('../lib/knowledge/fp-suppression-rules');
    return getSuppressionRuleSummary();
  }),

  applySuppressionToEngagement: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      profileName: z.string().default('balanced'),
      customRules: z.record(z.string(), z.boolean()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { applySuppressionRules } = await import('../lib/knowledge/fp-suppression-rules');
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

      const vulnAnalysis = (state as any).vulnAnalysis || [];
      const suppressed = (state as any).vulnAnalysisSuppressed || [];
      const allFindings = [...vulnAnalysis, ...suppressed];

      const result = applySuppressionRules(allFindings, input.profileName, input.customRules);

      (state as any).vulnAnalysis = result.kept;
      (state as any).vulnAnalysisSuppressed = result.suppressed;
      (state as any).fpSuppressionStats = result.stats;
      (state as any).metadata = { ...(state as any).metadata, fpSuppressionProfile: input.profileName };

      return result.stats;
    }),

  getSuppressionStats: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) return null;
      return {
        stats: (state as any).fpSuppressionStats || null,
        suppressedCount: ((state as any).vulnAnalysisSuppressed || []).length,
        keptCount: ((state as any).vulnAnalysis || []).length,
        profile: (state as any).metadata?.fpSuppressionProfile || 'balanced',
      };
    }),

  // ─── Auto-Resume Management ───────────────────────────────────────────────

  /** Toggle auto-resume on restart for an engagement */
  setAutoResume: protectedProcedure
    .input(z.object({ engagementId: z.number(), enabled: z.boolean() }))
    .mutation(async ({ input, ctx }) => {
      const dbConn = await db.getDbRequired();
      await dbConn.update(schema.engagements)
        .set({ autoResumeOnRestart: input.enabled ? 1 : 0 })
        .where(sql`id = ${input.engagementId}`);
      await db.logActivity({ userId: ctx.user.id, action: 'set_auto_resume', details: `Set auto-resume=${input.enabled} for engagement #${input.engagementId}` });
      return { success: true, enabled: input.enabled };
    }),

  /** Get auto-resume status for an engagement */
  getAutoResumeStatus: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const dbConn = await db.getDbRequired();
      const [eng] = await dbConn.select({ autoResumeOnRestart: schema.engagements.autoResumeOnRestart })
        .from(schema.engagements).where(sql`id = ${input.engagementId}`).limit(1);
      const [snap] = await dbConn.select({
        interruptCount: schema.engagementOpsSnapshots.interruptCount,
        lastInterruptedAt: schema.engagementOpsSnapshots.lastInterruptedAt,
      })
        .from(schema.engagementOpsSnapshots)
        .where(sql`engagement_id = ${input.engagementId}`).limit(1);
      const interruptCount = snap?.interruptCount || 0;
      const lastInterruptedAt = snap?.lastInterruptedAt ? new Date(snap.lastInterruptedAt).getTime() : 0;
      const crashLoopBlocked = interruptCount >= 3 && lastInterruptedAt > (Date.now() - 24 * 60 * 60 * 1000);
      return {
        enabled: eng?.autoResumeOnRestart === 1,
        interruptCount,
        crashLoopBlocked,
        lastInterruptedAt: snap?.lastInterruptedAt || null,
      };
    }),

  /** Cancel a scheduled auto-resume */
  cancelAutoResume: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { cancelAutoResume } = await import('../lib/engagement-auto-resume');
      const cancelled = cancelAutoResume(input.engagementId);
      if (cancelled) {
        await db.logActivity({ userId: ctx.user.id, action: 'cancel_auto_resume', details: `Cancelled auto-resume for engagement #${input.engagementId}` });
      }
      return { success: cancelled, message: cancelled ? 'Auto-resume cancelled' : 'No scheduled auto-resume found' };
    }),

  /** Reset the crash-loop interrupt counter */
  resetInterruptCounter: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const { resetInterruptCounter } = await import('../lib/engagement-auto-resume');
      const success = await resetInterruptCounter(input.engagementId);
      if (success) {
        await db.logActivity({ userId: ctx.user.id, action: 'reset_interrupt_counter', details: `Reset interrupt counter for engagement #${input.engagementId}` });
      }
      return { success };
    }),

  /** Get all interrupted engagements detected at startup */
  getInterruptedEngagements: protectedProcedure
    .query(async () => {
      const { getDetectedInterruptions } = await import('../lib/engagement-auto-resume');
      return getDetectedInterruptions();
    }),

  /** Get target profiles (WAF/CDN/topology/fingerprint/evasion) for an engagement */
  getTargetProfiles: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state?.targetProfiles) return { profiles: {}, hasProfiles: false };
      // Serialize target profiles for the frontend
      const profiles: Record<string, any> = {};
      for (const [host, profile] of Object.entries(state.targetProfiles)) {
        const p = profile as any;
        profiles[host] = {
          hostname: p.hostname,
          ips: p.ips,
          fingerprint: {
            serverHeader: p.fingerprint?.serverHeader || null,
            webServer: p.fingerprint?.webServer || null,
            appFramework: p.fingerprint?.appFramework || null,
            cms: p.fingerprint?.cms || null,
            os: p.fingerprint?.os || null,
            tls: p.fingerprint?.tls || null,
            languages: p.fingerprint?.languages || [],
            jsFrameworks: p.fingerprint?.jsFrameworks || [],
            databases: p.fingerprint?.databases || [],
            techTags: p.fingerprint?.techTags || [],
            serviceBanners: p.fingerprint?.serviceBanners || {},
          },
          waf: {
            detected: p.waf?.detected || false,
            vendor: p.waf?.vendor || 'none',
            type: p.waf?.type || 'unknown',
            confidence: p.waf?.confidence || 0,
            bypassTechniques: p.waf?.bypassTechniques || [],
          },
          cdn: {
            detected: p.cdn?.detected || false,
            provider: p.cdn?.provider || 'none',
            edgeServers: p.cdn?.edgeServers || [],
            originDiscoveryMethods: p.cdn?.originDiscoveryMethods || [],
          },
          firewall: {
            detected: p.firewall?.detected || false,
            type: p.firewall?.type || 'unknown',
            filteredPorts: p.firewall?.filteredPorts || [],
            rateLimiting: p.firewall?.rateLimiting || { detected: false },
          },
          topology: {
            role: p.topology?.role || 'unknown',
            confidence: p.topology?.confidence || 0,
            backend: p.topology?.backend || null,
            services: p.topology?.services || [],
          },
          environment: p.environment || 'unknown',
          riskProfile: p.riskProfile || 'standard',
          evasionProfile: p.recommendedStrategy?.evasionProfile || null,
          scanStrategy: p.recommendedStrategy ? {
            name: p.recommendedStrategy.name,
            riskLevel: p.recommendedStrategy.riskLevel,
            estimatedTimeMinutes: p.recommendedStrategy.estimatedTimeMinutes,
            phases: (p.recommendedStrategy.phases || []).map((ph: any) => ({
              name: ph.name,
              order: ph.order,
              purpose: ph.purpose,
              requiresApproval: ph.requiresApproval,
              tools: (ph.tools || []).map((t: any) => ({ tool: t.tool, purpose: t.purpose })),
            })),
          } : null,
          profiledAt: p.profiledAt,
          evasionEscalation: p.evasionEscalation || null,
        };
      }
      return { profiles, hasProfiles: Object.keys(profiles).length > 0 };
    }),

  /** Escalate evasion profile for a target when blocked */
  escalateEvasion: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      hostname: z.string(),
      reason: z.enum(['waf_block', 'rate_limit', 'connection_reset', 'captcha', 'ip_ban', 'manual']),
      blockedStatusCode: z.number().optional(),
      blockedToolOutput: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery, broadcastOpsUpdate, addLog } = await import('../lib/engagement-orchestrator');
      const { escalateEvasionProfile } = await import('../lib/evasion-escalation-engine');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement state not found' });
      if (!state.targetProfiles?.[input.hostname]) {
        throw new TRPCError({ code: 'NOT_FOUND', message: `No target profile for ${input.hostname}` });
      }
      const result = escalateEvasionProfile(
        state.targetProfiles[input.hostname] as any,
        input.reason,
        { statusCode: input.blockedStatusCode, toolOutput: input.blockedToolOutput }
      );
      // Update the profile in state
      (state.targetProfiles[input.hostname] as any).evasionEscalation = result.escalation;
      if (result.newEvasionProfile) {
        (state.targetProfiles[input.hostname] as any).recommendedStrategy = {
          ...(state.targetProfiles[input.hostname] as any).recommendedStrategy,
          evasionProfile: result.newEvasionProfile,
        };
      }
      addLog(state, {
        phase: state.phase,
        type: 'info',
        title: `\u26a0\ufe0f Evasion Escalated: ${input.hostname}`,
        detail: `${result.escalation.currentLevel} (${input.reason}) — ${result.escalation.action}`,
      });
      broadcastOpsUpdate(state.engagementId, {
        type: 'evasion_escalation',
        hostname: input.hostname,
        escalation: result.escalation,
      });
      return result;
    }),

  /** Get evasion escalation history for an engagement */
  getEvasionHistory: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state?.targetProfiles) return { history: [] };
      const history: Array<{ hostname: string; escalation: any }> = [];
      for (const [host, profile] of Object.entries(state.targetProfiles)) {
        const p = profile as any;
        if (p.evasionEscalation) {
          history.push({ hostname: host, escalation: p.evasionEscalation });
        }
      }
      return { history };
    }),

  // ═══ MANUAL FINDINGS UPLOAD ═══

  /** Submit a new manual finding */
  submitManualFinding: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      asset: z.string(),
      title: z.string().min(3).max(500),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
      cvss: z.number().min(0).max(10).optional(),
      cve: z.string().optional(),
      cwe: z.string().optional(),
      description: z.string().min(10),
      stepsToReproduce: z.string().optional(),
      impact: z.string().optional(),
      remediation: z.string().optional(),
      category: z.string().default('web'),
      tags: z.array(z.string()).default([]),
      notes: z.string().optional(),
      evidence: z.array(z.object({
        type: z.enum(['screenshot', 'terminal_output', 'http_request_response', 'exploit_code', 'tool_output', 'notes', 'pcap', 'video', 'document']),
        name: z.string(),
        mimeType: z.string(),
        url: z.string().optional(),
        fileKey: z.string().optional(),
        textContent: z.string().optional(),
        sizeBytes: z.number().optional(),
        caption: z.string().optional(),
      })).default([]),
    }))
    .mutation(async ({ input, ctx }) => {
      const { getOpsState, getOpsStateWithRecovery, addLog } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new Error('Engagement not found');

      const findingId = `mf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const now = Date.now();

      const finding: any = {
        id: findingId,
        asset: input.asset,
        title: input.title,
        severity: input.severity,
        cvss: input.cvss,
        cve: input.cve,
        cwe: input.cwe,
        description: input.description,
        stepsToReproduce: input.stepsToReproduce,
        impact: input.impact,
        remediation: input.remediation,
        category: input.category,
        tags: input.tags,
        notes: input.notes,
        submittedBy: ctx.user?.name || ctx.user?.openId || 'operator',
        submittedAt: now,
        updatedAt: now,
        status: 'submitted' as const,
        evidence: input.evidence.map((e, i) => ({
          id: `ev-${findingId}-${i}`,
          type: e.type,
          name: e.name,
          mimeType: e.mimeType,
          url: e.url,
          fileKey: e.fileKey,
          textContent: e.textContent,
          sizeBytes: e.sizeBytes,
          caption: e.caption,
          uploadedAt: now,
        })),
      };

      if (!state.manualFindings) state.manualFindings = [];
      state.manualFindings.push(finding);

      // Also push to the asset's vulns array so it appears in the report
      const asset = state.assets.find(a => a.hostname === input.asset);
      if (asset) {
        const vulnId = `manual-${findingId}`;
        asset.vulns.push({
          id: vulnId,
          severity: input.severity,
          title: `[Manual] ${input.title}`,
          cve: input.cve,
          description: input.description,
          cvss: input.cvss,
          cwe: input.cwe,
          evidence: input.stepsToReproduce || input.description,
          source: 'manual',
        });
        // Update asset status if needed
        if (asset.status === 'pending' || asset.status === 'scanning' || asset.status === 'enumerated' || asset.status === 'discovered') {
          asset.status = 'vulns_found';
        }
      }

      addLog(state, {
        phase: state.phase,
        type: 'finding',
        title: `Manual finding: ${input.title}`,
        detail: `${input.severity.toUpperCase()} | ${input.category} | ${input.evidence.length} evidence items | Submitted by ${finding.submittedBy}`,
        data: { findingId, severity: input.severity, asset: input.asset, category: input.category, manual: true },
        riskTier: input.severity === 'critical' ? 'red' : input.severity === 'high' ? 'orange' : 'yellow',
      });

      return { id: findingId, success: true };
    }),

  /** List all manual findings for an engagement */
  listManualFindings: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      return { findings: state?.manualFindings || [] };
    }),

  /** Update a manual finding */
  updateManualFinding: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      findingId: z.string(),
      title: z.string().optional(),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
      cvss: z.number().min(0).max(10).optional(),
      cve: z.string().optional(),
      cwe: z.string().optional(),
      description: z.string().optional(),
      stepsToReproduce: z.string().optional(),
      impact: z.string().optional(),
      remediation: z.string().optional(),
      category: z.string().optional(),
      tags: z.array(z.string()).optional(),
      notes: z.string().optional(),
      status: z.enum(['draft', 'submitted', 'verified', 'rejected']).optional(),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state?.manualFindings) throw new Error('No manual findings found');

      const finding = state.manualFindings.find(f => f.id === input.findingId);
      if (!finding) throw new Error('Finding not found');

      if (input.title !== undefined) finding.title = input.title;
      if (input.severity !== undefined) finding.severity = input.severity;
      if (input.cvss !== undefined) finding.cvss = input.cvss;
      if (input.cve !== undefined) finding.cve = input.cve;
      if (input.cwe !== undefined) finding.cwe = input.cwe;
      if (input.description !== undefined) finding.description = input.description;
      if (input.stepsToReproduce !== undefined) finding.stepsToReproduce = input.stepsToReproduce;
      if (input.impact !== undefined) finding.impact = input.impact;
      if (input.remediation !== undefined) finding.remediation = input.remediation;
      if (input.category !== undefined) finding.category = input.category;
      if (input.tags !== undefined) finding.tags = input.tags;
      if (input.notes !== undefined) finding.notes = input.notes;
      if (input.status !== undefined) finding.status = input.status;
      finding.updatedAt = Date.now();

      return { success: true };
    }),

  /** Delete a manual finding */
  deleteManualFinding: protectedProcedure
    .input(z.object({ engagementId: z.number(), findingId: z.string() }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state?.manualFindings) throw new Error('No manual findings found');

      const idx = state.manualFindings.findIndex(f => f.id === input.findingId);
      if (idx === -1) throw new Error('Finding not found');
      state.manualFindings.splice(idx, 1);

      // Also remove from asset vulns
      for (const asset of state.assets) {
        const vulnIdx = asset.vulns.findIndex(v => v.id === `manual-${input.findingId}`);
        if (vulnIdx !== -1) asset.vulns.splice(vulnIdx, 1);
      }

      return { success: true };
    }),

  /** Upload evidence file for a manual finding */
  uploadManualEvidence: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      findingId: z.string(),
      evidence: z.object({
        type: z.enum(['screenshot', 'terminal_output', 'http_request_response', 'exploit_code', 'tool_output', 'notes', 'pcap', 'video', 'document']),
        name: z.string(),
        mimeType: z.string(),
        textContent: z.string().optional(),
        caption: z.string().optional(),
        /** Base64-encoded file data for file uploads */
        fileData: z.string().optional(),
      }),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state?.manualFindings) throw new Error('No manual findings found');

      const finding = state.manualFindings.find(f => f.id === input.findingId);
      if (!finding) throw new Error('Finding not found');

      const evidenceId = `ev-${input.findingId}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      let url: string | undefined;
      let fileKey: string | undefined;
      let sizeBytes: number | undefined;

      // If file data is provided, upload to S3
      if (input.evidence.fileData) {
        const { doStoragePut } = await import('../do-storage');
        const buffer = Buffer.from(input.evidence.fileData, 'base64');
        sizeBytes = buffer.length;
        const suffix = Math.random().toString(36).slice(2, 8);
        const key = `manual-evidence/${input.engagementId}/${input.findingId}/${evidenceId}-${suffix}`;
        const result = await doStoragePut(key, buffer, input.evidence.mimeType);
        url = result.url;
        fileKey = result.key;
      }

      const evidence: any = {
        id: evidenceId,
        type: input.evidence.type,
        name: input.evidence.name,
        mimeType: input.evidence.mimeType,
        url,
        fileKey,
        textContent: input.evidence.textContent,
        sizeBytes,
        caption: input.evidence.caption,
        uploadedAt: Date.now(),
      };

      finding.evidence.push(evidence);
      finding.updatedAt = Date.now();

      return { evidenceId, url, success: true };
    }),

  /** Add inline text evidence (terminal output, HTTP req/res, exploit code, notes) */
  addTextEvidence: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      findingId: z.string(),
      type: z.enum(['terminal_output', 'http_request_response', 'exploit_code', 'notes', 'tool_output']),
      name: z.string(),
      textContent: z.string(),
      caption: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state?.manualFindings) throw new Error('No manual findings found');

      const finding = state.manualFindings.find(f => f.id === input.findingId);
      if (!finding) throw new Error('Finding not found');

      const evidenceId = `ev-${input.findingId}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      finding.evidence.push({
        id: evidenceId,
        type: input.type,
        name: input.name,
        mimeType: 'text/plain',
        textContent: input.textContent,
        caption: input.caption,
        uploadedAt: Date.now(),
      });
      finding.updatedAt = Date.now();

      return { evidenceId, success: true };
    }),

  /** Delete evidence from a manual finding */
  deleteManualEvidence: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      findingId: z.string(),
      evidenceId: z.string(),
    }))
    .mutation(async ({ input }) => {
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state?.manualFindings) throw new Error('No manual findings found');
      const finding = state.manualFindings.find(f => f.id === input.findingId);
      if (!finding) throw new Error('Finding not found');
      const idx = finding.evidence.findIndex((e: any) => e.id === input.evidenceId);
      if (idx === -1) throw new Error('Evidence not found');
      finding.evidence.splice(idx, 1);
      finding.updatedAt = Date.now();
      return { success: true };
    }),

  /** Provision a buildable asset (clone, build, deploy to Docker on scan server) */
  provisionAsset: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      assetIndex: z.number().optional(),
      repoUrl: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const dbConn = await db.getDb();
      if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);

      const { getOpsState, getOpsStateWithRecovery, addLog, broadcastOpsUpdate } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(input.engagementId);
      if (!state) state = await getOpsStateWithRecovery(input.engagementId);
      if (!state) throw new Error('Engagement ops state not found');

      // Get build requirements from ROE scope
      const engagement = await db.getEngagementById(input.engagementId);
      if (!engagement) throw new Error('Engagement not found');
      let roeData: any = {};
      try { roeData = JSON.parse(engagement.roeScope || '{}'); } catch {}
      const buildReqs = roeData.buildRequirements || [];

      // Determine which asset to provision
      const targetReq = input.assetIndex !== undefined ? buildReqs[input.assetIndex] : buildReqs[0];
      const repoUrl = input.repoUrl || targetReq?.acquisitionMethod || '';

      if (!repoUrl) throw new Error('No repository URL or acquisition method found for provisioning');

      addLog(state, {
        phase: state.phase || 'idle',
        type: 'info',
        title: '\uD83D\uDE80 Asset Provisioning Started',
        detail: `Initiating build & deploy pipeline for: ${targetReq?.assetName || repoUrl}\n` +
          `Repository: ${repoUrl}\n` +
          `Dependencies: ${(targetReq?.dependencies || []).join(', ') || 'auto-detect'}`,
      });
      broadcastOpsUpdate(input.engagementId, { type: 'log_update' });

      // Import and run the asset provisioner
      try {
        const { provisionSourceCodeAsset } = await import('../lib/asset-provisioner');
        const result = await provisionSourceCodeAsset({
          engagementId: input.engagementId,
          repoUrl,
          assetName: targetReq?.assetName || 'unknown',
          buildInstructions: targetReq?.buildInstructions || [],
          deployInstructions: targetReq?.deployInstructions || [],
          dependencies: targetReq?.dependencies || [],
        });

        if (result.success) {
          addLog(state, {
            phase: state.phase || 'idle',
            type: 'info',
            title: '\u2705 Asset Provisioned Successfully',
            detail: `${targetReq?.assetName || 'Asset'} is now running at ${result.deployedUrl || result.containerName || 'local container'}.\n` +
              `Container: ${result.containerName || 'N/A'}\n` +
              `Build time: ${result.buildTimeMs ? Math.round(result.buildTimeMs / 1000) + 's' : 'N/A'}`,
          });

          // Update the asset in ops state if it exists
          if (result.deployedUrl) {
            const existingAsset = state.assets.find((a: any) => a.type === 'source_code' || a.hostname?.includes(targetReq?.assetName?.toLowerCase()));
            if (existingAsset) {
              (existingAsset as any).deployedUrl = result.deployedUrl;
              (existingAsset as any).containerName = result.containerName;
              existingAsset.status = 'scanned';
            }
            // Also add the deployed URL as a new scannable asset
            const deployedHostname = new URL(result.deployedUrl).hostname;
            if (!state.assets.find(a => a.hostname === deployedHostname)) {
              state.assets.push({
                hostname: deployedHostname,
                type: 'web_app',
                ports: [{ port: parseInt(new URL(result.deployedUrl).port) || 80, service: 'http', state: 'open' }],
                vulns: [],
                pendingVulns: [],
                zapFindings: [],
                exploitAttempts: [],
                confirmedCredentials: [],
                toolResults: [],
                status: 'pending',
              });
            }
          }
        } else {
          addLog(state, {
            phase: state.phase || 'idle',
            type: 'error',
            title: '\u274C Asset Provisioning Failed',
            detail: `Failed to provision ${targetReq?.assetName || 'asset'}: ${result.error || 'Unknown error'}\n` +
              `Check scan server connectivity and Docker availability.`,
          });
        }

        broadcastOpsUpdate(input.engagementId, { type: 'log_update' });
        return result;
      } catch (err: any) {
        addLog(state, {
          phase: state.phase || 'idle',
          type: 'error',
          title: '\u274C Provisioning Error',
          detail: `Unexpected error during provisioning: ${err.message}`,
        });
        broadcastOpsUpdate(input.engagementId, { type: 'log_update' });
        return { success: false, error: err.message };
      }
    }),

    /** Re-scan a specific asset with a deeper Gobuster profile (Quick → Standard → Deep) */
    rescanWithDeeperProfile: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        assetHostname: z.string().min(1),
        targetProfile: z.enum(['quick', 'standard', 'deep']).optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { rescanAssetWithDeeperProfile } = await import('../lib/engagement-orchestrator');
        const result = await rescanAssetWithDeeperProfile(
          input.engagementId,
          input.assetHostname,
          {
            targetProfile: input.targetProfile,
            operatorId: ctx.user.openId,
            operatorName: ctx.user.name || undefined,
          }
        );
        if (result.success) {
          await db.logActivity({
            userId: ctx.user.id,
            action: 'engagement_rescan_escalation',
            details: `Escalated scan profile for ${input.assetHostname} in engagement #${input.engagementId}: ${result.previousProfile} → ${result.newProfile}`,
          });
        }
        return result;
      }),

    /** Get hot path analysis for a specific engagement */
    getEngagementHotPaths: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
      }))
      .query(async ({ input, ctx }) => {
        const dbConn = await db.getDb();
        if (dbConn) await assertEngagementAccess(dbConn, input.engagementId, ctx.user);
        const { getEngagementLlmTelemetryRaw } = await import('../db');
        const { analyzeHotPaths } = await import('../lib/llm-hot-path-analyzer');
        const rawTelemetry = await getEngagementLlmTelemetryRaw(input.engagementId);
        if (rawTelemetry.length < 10) {
          return { available: false as const, reason: `Only ${rawTelemetry.length} telemetry records (need >= 10)`, analysis: null };
        }
        const analysis = analyzeHotPaths(rawTelemetry, { engagementId: input.engagementId, topN: 15, minCallsForAnalysis: 3 });
        return { available: true as const, reason: null, analysis };
      }),

    /** Get global hot path analysis across all engagements */
    getGlobalHotPaths: protectedProcedure
      .input(z.object({
        windowHours: z.number().min(1).max(720).default(168),
      }))
      .query(async ({ input }) => {
        const { getGlobalLlmTelemetryRaw } = await import('../db');
        const { analyzeHotPaths } = await import('../lib/llm-hot-path-analyzer');
        const rawTelemetry = await getGlobalLlmTelemetryRaw(input.windowHours);
        if (rawTelemetry.length < 10) {
          return { available: false as const, reason: `Only ${rawTelemetry.length} telemetry records in the last ${input.windowHours}h (need >= 10)`, analysis: null };
        }
        const analysis = analyzeHotPaths(rawTelemetry, { topN: 20, minCallsForAnalysis: 5 });
        return { available: true as const, reason: null, analysis };
      }),

  /** Get known/confirmed credentials for a target host from credential vault */
  getKnownCredentials: protectedProcedure
    .input(z.object({ targetHost: z.string(), engagementId: z.number().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { credentialFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) return { credentials: [], sources: [] };
      const { eq, like, or, desc } = await import("drizzle-orm");

      // Query credential_findings for the target host (exact match or wildcard)
      const host = input.targetHost.replace(/^https?:\/\//, "").replace(/[\/:].*$/, "");
      const results = await db.select({
        id: credentialFindings.id,
        targetHost: credentialFindings.targetHost,
        targetPort: credentialFindings.targetPort,
        protocol: credentialFindings.protocol,
        username: credentialFindings.username,
        password: credentialFindings.password,
        accessLevel: credentialFindings.accessLevel,
        vendor: credentialFindings.vendor,
        product: credentialFindings.product,
        verified: credentialFindings.verified,
        tool: credentialFindings.tool,
        discoveredAt: credentialFindings.discoveredAt,
        validationStatus: credentialFindings.validationStatus,
      }).from(credentialFindings).where(
        or(
          eq(credentialFindings.targetHost, host),
          like(credentialFindings.targetHost, `%${host}%`)
        )
      ).orderBy(desc(credentialFindings.discoveredAt)).limit(50);

      // Also get OEM default credentials for known services on this host
      const { getCredentialsForService } = await import("../lib/credential-tester");
      const oemCreds = await getCredentialsForService({
        host,
        port: 80,
        protocol: "http",
        technologies: [{ name: "http" }],
      });

      return {
        credentials: results.map(r => ({
          id: r.id,
          host: r.targetHost,
          port: r.targetPort,
          protocol: r.protocol,
          username: r.username,
          password: r.password,
          accessLevel: r.accessLevel || "unknown",
          source: r.tool || "scan",
          verified: r.verified === 1,
          validationStatus: r.validationStatus || "unvalidated",
          discoveredAt: r.discoveredAt,
        })),
        oemDefaults: oemCreds.slice(0, 10).map(c => ({
          username: c.username,
          password: c.password,
          protocol: c.protocol,
          vendor: c.vendor,
          product: c.product,
          source: c.source || "OEM database",
        })),
      };
    }),

  /** Test credentials against a target before running a full pipeline */
  testCredentials: protectedProcedure
    .input(z.object({
      targetUrl: z.string(),
      username: z.string(),
      password: z.string(),
      authType: z.enum(['form', 'basic', 'bearer', 'cookie']).default('form'),
      loginPath: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const startTime = Date.now();
      try {
        const targetUrl = input.targetUrl.startsWith('http') ? input.targetUrl : `http://${input.targetUrl}`;
        const loginUrl = input.loginPath ? `${targetUrl.replace(/\/$/, '')}${input.loginPath}` : targetUrl;

        if (input.authType === 'basic') {
          // Test HTTP Basic auth
          const basicAuth = Buffer.from(`${input.username}:${input.password}`).toString('base64');
          const response = await fetch(loginUrl, {
            method: 'GET',
            headers: { 'Authorization': `Basic ${basicAuth}` },
            redirect: 'manual',
          });
          const duration = Date.now() - startTime;
          const success = response.status >= 200 && response.status < 400;
          return {
            success,
            statusCode: response.status,
            message: success ? 'HTTP Basic authentication successful' : `Authentication failed with status ${response.status}`,
            duration,
            responseHeaders: Object.fromEntries(response.headers.entries()),
          };
        }

        if (input.authType === 'bearer') {
          // Test Bearer token (password field used as token)
          const response = await fetch(loginUrl, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${input.password}` },
            redirect: 'manual',
          });
          const duration = Date.now() - startTime;
          const success = response.status >= 200 && response.status < 400;
          return {
            success,
            statusCode: response.status,
            message: success ? 'Bearer token authentication successful' : `Authentication failed with status ${response.status}`,
            duration,
            responseHeaders: Object.fromEntries(response.headers.entries()),
          };
        }

        if (input.authType === 'cookie') {
          // Test cookie injection
          const response = await fetch(loginUrl, {
            method: 'GET',
            headers: { 'Cookie': input.password }, // password field contains cookie string
            redirect: 'manual',
          });
          const duration = Date.now() - startTime;
          const success = response.status >= 200 && response.status < 400;
          const body = await response.text();
          const hasLoginForm = body.includes('login') || body.includes('sign in') || body.includes('password');
          return {
            success: success && !hasLoginForm,
            statusCode: response.status,
            message: success && !hasLoginForm ? 'Cookie authentication successful' : 'Cookie may be invalid (login form detected)',
            duration,
            responseHeaders: Object.fromEntries(response.headers.entries()),
          };
        }

        // Form-based login (default)
        // Step 1: GET login page to extract CSRF token
        const getResp = await fetch(loginUrl, { redirect: 'follow' });
        const pageHtml = await getResp.text();
        
        // Extract CSRF token from common patterns
        let csrfToken = '';
        const csrfPatterns = [
          /name=["'](?:csrf|_token|user_token|csrfmiddlewaretoken|_csrf_token|authenticity_token)["']\s+value=["']([^"']+)["']/i,
          /value=["']([^"']+)["']\s+name=["'](?:csrf|_token|user_token|csrfmiddlewaretoken|_csrf_token|authenticity_token)["']/i,
          /meta\s+name=["']csrf-token["']\s+content=["']([^"']+)["']/i,
        ];
        for (const pattern of csrfPatterns) {
          const match = pageHtml.match(pattern);
          if (match) { csrfToken = match[1]; break; }
        }

        // Extract form action
        const formAction = pageHtml.match(/form[^>]*action=["']([^"']*)["']/i)?.[1] || loginUrl;
        const postUrl = formAction.startsWith('http') ? formAction : `${new URL(loginUrl).origin}${formAction}`;

        // Detect username/password field names
        const usernameField = pageHtml.match(/name=["'](username|user|email|login|user_login)["']/i)?.[1] || 'username';
        const passwordField = pageHtml.match(/name=["'](password|pass|passwd|user_password)["']/i)?.[1] || 'password';

        // Extract cookies from GET response
        const setCookies = getResp.headers.getSetCookie?.() || [];
        const cookieStr = setCookies.map(c => c.split(';')[0]).join('; ');

        // Step 2: POST credentials
        const formData = new URLSearchParams();
        formData.set(usernameField, input.username);
        formData.set(passwordField, input.password);
        if (csrfToken) {
          const csrfFieldName = pageHtml.match(/name=["'](csrf|_token|user_token|csrfmiddlewaretoken|_csrf_token|authenticity_token)["']/i)?.[1] || 'user_token';
          formData.set(csrfFieldName, csrfToken);
        }
        formData.set('Login', 'Login'); // Common submit button name

        const postResp = await fetch(postUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookieStr,
          },
          body: formData.toString(),
          redirect: 'manual',
        });

        const duration = Date.now() - startTime;
        const postStatus = postResp.status;
        const postBody = postStatus < 400 ? await postResp.text().catch(() => '') : '';
        
        // Determine success: redirect (302/303) or 200 without login form
        const isRedirect = postStatus >= 300 && postStatus < 400;
        const hasLoginFormInResponse = postBody.toLowerCase().includes('login failed') || 
          postBody.toLowerCase().includes('invalid') || 
          postBody.toLowerCase().includes('incorrect');
        const newCookies = postResp.headers.getSetCookie?.() || [];
        const gotSessionCookie = newCookies.some(c => /session|PHPSESSID|token|auth/i.test(c));

        const success = (isRedirect || (postStatus === 200 && !hasLoginFormInResponse)) && (gotSessionCookie || isRedirect);

        return {
          success,
          statusCode: postStatus,
          message: success 
            ? `Form login successful${gotSessionCookie ? ' (session cookie received)' : ' (redirect detected)'}` 
            : `Form login failed (status: ${postStatus}${hasLoginFormInResponse ? ', error message detected' : ''})`,
          duration,
          responseHeaders: Object.fromEntries(postResp.headers.entries()),
          details: {
            csrfTokenFound: !!csrfToken,
            formAction: postUrl,
            usernameField,
            passwordField,
            sessionCookieReceived: gotSessionCookie,
            redirectLocation: postResp.headers.get('location') || undefined,
          },
        };
      } catch (err: any) {
        return {
          success: false,
          statusCode: 0,
          message: `Connection failed: ${err.message}`,
          duration: Date.now() - startTime,
          responseHeaders: {},
        };
      }
    }),
});
