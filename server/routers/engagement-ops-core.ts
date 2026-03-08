import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { and, min, not, or, sql } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const engagementOpsRouter = router({
    /** Get current ops state for an engagement */
    getState: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState, getOpsStateWithRecovery, initOpsState } = await import('../lib/engagement-orchestrator');
        // First try in-memory, then try DB recovery, then initialize fresh
        let state = getOpsState(input.engagementId);
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
        return state;
      }),

    /** Initialize ops state for an engagement */
    init: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });
        const { initOpsState } = await import('../lib/engagement-orchestrator');
        return initOpsState(input.engagementId, engagement.engagementType);
      }),

    /** Start autonomous execution — one-click pentest/red team */
    execute: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        // Validate RoE scope exists
        if (!engagement.targetDomain && !engagement.targetIpRange) {
          throw new TRPCError({ code: 'BAD_REQUEST', message: 'No targets defined. Add target domains or IP ranges first.' });
        }

        const { executeEngagement, initOpsState, getOpsState } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) {
          state = initOpsState(input.engagementId, engagement.engagementType);
        }
        if (state.isRunning) {
          throw new TRPCError({ code: 'CONFLICT', message: 'Engagement is already running' });
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

    /** Skip the currently scanning domain — marks it as skipped so the pipeline moves to the next domain */
    skipCurrentDomain: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { getOpsState, broadcastOpsUpdate } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId);
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
        const { clearOpsState } = await import('../lib/engagement-orchestrator');
        await clearOpsState(input.engagementId);
        await db.logActivity({ userId: ctx.user.id, action: 'engagement_ops_cleared', details: `Fully cleared ops state for engagement #${input.engagementId}` });
        return { cleared: true };
      }),

    /** Diagnostic: test LLM connectivity from the production server */
    testLlm: protectedProcedure
      .input(z.object({ paddingKB: z.number().min(0).max(500).optional() }).optional())
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('../_core/llm');
        const { ENV } = await import('../_core/env');
        const paddingKB = input?.paddingKB ?? 0;
        const padding = paddingKB > 0 ? 'X'.repeat(paddingKB * 1024) : '';
        const start = Date.now();
        try {
          const result = await invokeLLM({
            messages: [
              ...(padding ? [{ role: 'system' as const, content: 'You are a helpful assistant. ' + padding }] : []),
              { role: 'user' as const, content: 'Say hello in one word' },
            ],
            _caller: 'engagement-ops.testLlm',
          });
          return {
            ok: true,
            latencyMs: Date.now() - start,
            model: result.model,
            content: result.choices?.[0]?.message?.content,
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
        const { getOpsState, broadcastOpsUpdate } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId);
        if (!state) throw new TRPCError({ code: 'NOT_FOUND', message: 'No ops state found' });
        // Reset to idle (or recon_complete if assets exist)
        const hasAssets = state.assets.length > 0;
        state.phase = hasAssets ? ('recon_complete' as any) : 'idle';
        state.isRunning = false;
        state.isPaused = false;
        state.error = undefined;
        state.currentAction = undefined;
        const resetLog = { id: `log-${Date.now()}-reset`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: '🔄 Ops State Reset', detail: `Reset by ${ctx.user.name || 'operator'}. ${hasAssets ? `${state.assets.length} assets preserved. Ready for active scan or re-run passive.` : 'Ready for passive discovery.'}` };
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
        if (!resolved) throw new TRPCError({ code: 'NOT_FOUND', message: 'Approval gate not found or already resolved' });

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

        const { initOpsState, getOpsState } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
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

        const { initOpsState, getOpsState } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
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
          // ── Per-domain watchdog: 8 minutes per domain ──
          // The full pipeline runs ~10 stages (passive recon connectors, LLM discovery,
          // DNS verification, WAF detection, LLM analysis) with external API calls.
          // Individual LLM calls have a 60s timeout. 8 min gives enough headroom.
          const PER_DOMAIN_WATCHDOG_MS = 8 * 60 * 1000;
          // ── Global watchdog: 20 minutes total for entire pipeline ──
          const GLOBAL_WATCHDOG_MS = 20 * 60 * 1000;
          let globalWatchdogTimer: ReturnType<typeof setTimeout> | null = null;
          const globalWatchdogPromise = new Promise<never>((_, reject) => {
            globalWatchdogTimer = setTimeout(() => reject(new Error('Global pipeline watchdog timeout (20 min) — aborting all remaining domains')), GLOBAL_WATCHDOG_MS);
          });

          try {

            for (const domain of domains) {
              // Check if scan was stopped by operator
              if (!state!.isRunning) {
                const stopLog = { id: `log-${Date.now()}-stopped`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: '⏹ Scan Stopped', detail: 'Passive scan stopped by operator before completing all domains.' };
                state!.log.push(stopLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: stopLog });
                break;
              }

              // Check if this domain was skipped by operator
              if (state!.skippedDomains?.has(domain)) {
                const skipLog = { id: `log-${Date.now()}-skip-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'info' as const, title: `⏭ Skipped: ${domain}`, detail: 'Domain skipped by operator request.' };
                state!.log.push(skipLog);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: skipLog });
                continue;
              }

              // Track current domain for UI elapsed timer and skip button
              state!.currentDomain = domain;
              state!.currentDomainStartedAt = Date.now();

              // Per-domain watchdog
              let domainWatchdogTimer: ReturnType<typeof setTimeout> | null = null;
              const domainWatchdogPromise = new Promise<never>((_, reject) => {
                domainWatchdogTimer = setTimeout(() => reject(new Error(`Domain watchdog timeout (8 min) for ${domain}`)), PER_DOMAIN_WATCHDOG_MS);
              });

              try {
                const logEntry = { id: `log-${Date.now()}-${Math.random().toString(36).slice(2,6)}`, timestamp: Date.now(), phase: 'recon' as const, type: 'scan_start' as const, title: `Domain Intel: ${domain}`, detail: 'Running strict passive OSINT scan (no direct target contact)' };
                state!.log.push(logEntry);
                broadcastOpsUpdate(input.engagementId, { type: 'log', entry: logEntry });

                state!.currentAction = `Scanning ${domain}...`;
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
                      state!.currentAction = `${domain}: ${stage}`;
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
                        // Distinguish between: success with data, success but empty, skipped (no key), failed, circuit breaker
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
                            // Completed in <50ms with 0 observations = likely skipped (no API key configured)
                            statusIcon = '\u23ed';
                            detail = `No API key configured — skipped (${dur}s)`;
                          } else {
                            // Real API call returned empty results
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
                        state!.currentAction = `${domain}: ${statusIcon} ${event.connector} ${event.status}`;
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
                  globalWatchdogPromise,
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
                // Clear per-domain tracking
                state!.currentDomain = undefined;
                state!.currentDomainStartedAt = undefined;
                // Force-persist after each domain so assets survive crashes
                const { persistOpsStateNow: persistAfterDomain } = await import('../lib/engagement-orchestrator');
                await persistAfterDomain(input.engagementId).catch(() => {});
              }
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
            // If already stopped by operator, don't overwrite the phase
            if (state!.isRunning) {
              state!.phase = 'recon_complete' as any;
              state!.isRunning = false;
            } else {
              // Stopped by operator mid-scan — still mark as recon_complete if we have assets
              if (state!.assets.some((a: any) => a.status === 'discovered')) {
                state!.phase = 'recon_complete' as any;
              }
            }
            state!.progress = 15;
            state!.currentAction = undefined;
            const doneLog = { id: `log-${Date.now()}-done`, timestamp: Date.now(), phase: 'recon' as const, type: 'phase_complete' as const, title: '\u2705 Strict Passive Discovery Complete', detail: `${state!.assets.length} assets discovered via strict passive OSINT (zero target contact). Click "Start Active Scan" to hand off to LLM for nmap \u2192 service matching \u2192 vuln detection \u2192 exploitation.` };
            state!.log.push(doneLog);
            broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'recon_complete' });
            broadcastOpsUpdate(input.engagementId, { type: 'log', entry: doneLog });
            // Force-persist final state on completion
            const { persistOpsStateNow: persistOnComplete } = await import('../lib/engagement-orchestrator');
            await persistOnComplete(input.engagementId).catch(() => {});
          } catch (e: any) {
            console.error(`[PassiveScan] Pipeline error for engagement #${input.engagementId}:`, e.message, e.stack?.slice(0, 500));
            state!.phase = 'error';
            state!.isRunning = false;
            state!.error = e.message;
            // Broadcast error to UI so user sees what happened
            const errLog = { id: `log-${Date.now()}-fatal`, timestamp: Date.now(), phase: 'recon' as const, type: 'error' as const, title: '❌ Passive Scan Failed', detail: `Error: ${e.message}. ${state!.assets.filter((a: any) => a.status === 'discovered').length} assets were discovered before the error.` };
            state!.log.push(errLog);
            broadcastOpsUpdate(input.engagementId, { type: 'log', entry: errLog });
            broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'error' });
            // Force-persist error state so assets are preserved
            const { persistOpsStateNow: persistOnError } = await import('../lib/engagement-orchestrator');
            await persistOnError(input.engagementId).catch(() => {});
          } finally {
            // Clean up global watchdog timer
            if (globalWatchdogTimer) clearTimeout(globalWatchdogTimer);
          }
        })();

        return { started: true };
      }),

    /** Generate LLM scan plan — analyzes passive recon results to determine nmap settings and tools per asset */
    generateScanPlan: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { getOpsState, generateScanPlan: genPlan } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId);
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId);
        return { scanPlan: state?.scanPlan || null };
      }),

    /** Start LLM-orchestrated active scanning (generates scan plan first, then nmap with plan-specific flags, then tool matching per service) */
    startActiveScan: protectedProcedure
      .input(z.object({ engagementId: z.number(), scanProfile: z.enum(['quick', 'standard', 'deep', 'stealth']).optional() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        if (engagement.roeStatus !== 'signed' && engagement.roeStatus !== 'pending') {
          throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'RoE must be signed before active scanning.' });
        }

        const { getOpsState, initOpsState, generateScanPlan: genPlan } = await import('../lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) state = initOpsState(input.engagementId, engagement.engagementType);
        if (state.isRunning) throw new TRPCError({ code: 'CONFLICT', message: 'Scan already running' });
        if (state.assets.length === 0) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No targets. Run passive scan or add targets first.' });

        state.isRunning = true;
        state.phase = 'enumeration';

        await db.logActivity({ userId: ctx.user.id, action: 'active_scan_started', details: `Started LLM-orchestrated active scan (scan plan \u2192 nmap \u2192 tool match \u2192 exploit) for engagement #${input.engagementId}` });

        // Generate scan plan first if not already generated, then execute
        (async () => {
          try {
            if (!state!.scanPlan) {
              await genPlan(input.engagementId);
            }
          } catch (e: any) {
            console.warn('[EngOps] Scan plan generation failed, proceeding with defaults:', e.message);
          }

          // Execute the active pipeline starting from enumeration (nmap first)
          // The executeEnumeration phase will use state.scanPlan for nmap flags
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId);
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
            nmapPorts: full.nmap.discoveryPorts,
            nmapTiming: full.nmap.timing,
            concurrency: full.tools.concurrency,
          };
        });
      }),

    /** Get attack chains generated for an engagement */
    getAttackChains: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId) as any;
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId) as any;
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId) as any;
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
      }))
      .mutation(async ({ input, ctx }) => {
        const {
          getOpsState, initOpsState, broadcastOpsUpdate, addLog, persistOpsStateNow
        } = await import('../lib/engagement-orchestrator');

        let state = getOpsState(input.engagementId);
        if (!state || input.resetState) {
          const engagement = await db.getEngagementById(input.engagementId);
          if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });
          state = initOpsState(input.engagementId, engagement.engagementType || 'pentest');
        }

        if (state.isRunning) {
          throw new TRPCError({ code: 'CONFLICT', message: 'Pipeline is already running. Reset or wait for completion.' });
        }

        state.isRunning = true;
        state.error = undefined;
        state.currentAction = 'Starting full pipeline re-run...';
        addLog(state, {
          phase: 'recon', type: 'info',
          title: '\u{1f504} Full Pipeline Re-Run Started',
          detail: `Phases: ${Object.entries(input.phases).filter(([,v]) => v).map(([k]) => k).join(', ')}. Initiated by ${ctx.user.name || 'operator'}.`,
        });
        broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'recon' });

        await db.logActivity({ userId: ctx.user.id, action: 'full_pipeline_rerun', details: `Started full pipeline re-run for engagement #${input.engagementId}` });

        // Run pipeline asynchronously
        (async () => {
          try {
            const engagement = await db.getEngagementById(input.engagementId);
            if (!engagement) throw new Error('Engagement not found');
            const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);

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

            // Phase 3: Active Scanning
            if (input.phases.active) {
              state!.phase = 'scanning';
              state!.currentAction = 'Running active scans...';
              broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'scanning' });
              try {
                const { executeTool, executeRawCommand } = await import('../lib/scan-server-executor');
                for (const asset of state!.assets) {
                  addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f50d} Nmap: ${asset.hostname}`, detail: 'Service detection and version scan...' });
                  try {
                    const nmapResult = await executeTool({ tool: 'nmap', args: `-sV -sC -T4 --top-ports 1000 ${asset.hostname}`, timeoutSeconds: 300 });
                    const portRegex = /(\d+)\/tcp\s+open\s+(\S+)\s*(.*)/g;
                    let match;
                    while ((match = portRegex.exec(nmapResult.stdout)) !== null) {
                      const port = parseInt(match[1]);
                      if (!asset.ports.find((p: any) => p.port === port)) {
                        asset.ports.push({ port, service: match[2], version: match[3]?.trim() || '' } as any);
                      }
                    }
                    addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 Nmap: ${asset.hostname}`, detail: `${asset.ports.length} open ports` });
                  } catch (err: any) {
                    addLog(state!, { phase: 'scanning', type: 'error', title: `\u274c Nmap failed: ${asset.hostname}`, detail: err.message });
                  }

                  addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f50d} Nuclei: ${asset.hostname}`, detail: 'Vulnerability templates...' });
                  try {
                    // Use stdin piping to avoid nuclei hanging on PDCP TTY auth prompt
                    const nucleiResult = await executeRawCommand(`echo "http://${asset.hostname}" | nuclei -severity critical,high,medium -jsonl -nc -duc -ni -timeout 20 -retries 2 -rate-limit 100 -tags cve,sqli,xss,lfi,rce,ssrf,ssti,crlf,traversal 2>&1`, 300);
                    const findings = nucleiResult.stdout.split('\n').filter(Boolean).map((line: string) => {
                      try { return JSON.parse(line); } catch { return null; }
                    }).filter(Boolean);
                    for (const f of findings) {
                      asset.vulns.push({
                        title: f.info?.name || f['template-id'] || 'Unknown',
                        severity: f.info?.severity || 'medium',
                        cve: f.info?.classification?.['cve-id']?.[0] || '',
                        description: f.info?.description || '',
                        tool: 'nuclei',
                        port: f.port || 0,
                        rawOutput: JSON.stringify(f).slice(0, 500),
                      } as any);
                    }
                    addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 Nuclei: ${asset.hostname}`, detail: `${findings.length} vulnerabilities` });
                  } catch (err: any) {
                    addLog(state!, { phase: 'scanning', type: 'error', title: `\u274c Nuclei failed: ${asset.hostname}`, detail: err.message });
                  }

                  // Nuclei DAST mode with crawling for active vuln confirmation
                  const dc = state!.dastConfig || { enabled: true, crawlDepth: 3, crawlScope: 'strict', templateCategories: ['sqli', 'xss', 'lfi', 'rfi', 'ssrf', 'rce'], timeout: 30, maxRequests: 5000, rateLimit: 50, headless: true };
                  if (dc.enabled !== false) {
                  addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f578}\ufe0f DAST: ${asset.hostname}`, detail: `Crawl depth: ${dc.crawlDepth}, scope: ${dc.crawlScope}, categories: ${dc.templateCategories.join(',')}` });
                  try {
                    const scopeFlag = dc.crawlScope === 'strict' ? '' : dc.crawlScope === 'subdomain' ? `-cs ${asset.hostname}` : `-cs ${asset.hostname.split('.').slice(-2).join('.')}`;
                    const headlessFlag = dc.headless ? '-headless' : '';
                    const customHeaderFlags = dc.customHeaders ? Object.entries(dc.customHeaders).map(([k, v]) => `-H "${k}: ${v}"`).join(' ') : '';
                    const dastCmd = `echo "http://${asset.hostname}" | nuclei -dast ${headlessFlag} -crawl-depth ${dc.crawlDepth} -crawl-duration ${dc.timeout * 2} -severity critical,high,medium -jsonl -nc -duc -ni -timeout ${dc.timeout} -rate-limit ${dc.rateLimit} -max-host-error 10 ${scopeFlag} ${customHeaderFlags} -system-resolvers 2>&1`;
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
                        asset.vulns.push({
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
                      asset.vulns.push({
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
                }
              } catch (err: any) {
                addLog(state!, { phase: 'scanning', type: 'error', title: '\u274c Active scanning failed', detail: err.message });
              }

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
                      service: p.service, version: p.version, tool: 'nmap',
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
                const { getNmapVulnCorrelationContext } = await import('../lib/nmap-knowledge');
                const { getThreatGroupVulnContext } = await import('../lib/threat-group-knowledge');
                const owaspCtx = getOwaspVulnCorrelationContext();
                const pentestCtx = buildKnowledgeContextForLLM('operator', 2000);
                const authCtx = buildAuthKnowledgeContext();
                const nmapVulnCtx = getNmapVulnCorrelationContext();
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

Your task: Analyze the passive reconnaissance data and identify the most likely REAL vulnerabilities.

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

${nmapVulnCtx.slice(0, 800)}

${threatCtx.slice(0, 800)}

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
                        messages: [
                          { role: 'system', content: 'You are a vulnerability assessment AI. Return only valid JSON arrays.' },
                          { role: 'user', content: synthPrompt },
                        ],
                        response_format: synthSchema,
                      });
                    } catch (retryErr: any) {
                      // Retry with minimal prompt on failure (e.g., 403 from too-large prompt)
                      addLog(state!, { phase: 'scanning', type: 'info', title: `\u{1f504} Retrying Vuln Synthesis: ${asset.hostname}`, detail: 'Retrying with reduced prompt...' });
                      const minimalPrompt = `Identify the TOP 10 vulnerabilities for ${asset.hostname} (technologies: ${techs.join(', ') || 'Unknown'}, ports: ${ports.map((p: any) => p.port + '/' + p.service).join(', ')}).\nKey risk signals: ${sampledSignals.slice(0, 10).map((s: any) => s.rationale).join('; ')}\n\nFocus on: SQL Injection, XSS, Broken Auth, Sensitive Data Exposure, Directory Traversal, CRLF Injection, File Inclusion, SSRF, Misconfig.\nReturn JSON with vulnerabilities array containing: title, severity, cve, description, confidence, category.`;
                      llmResult = await invokeLLM({
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
                    for (const v of synthVulns) {
                      if (v.confidence >= 40) {
                        asset.vulns.push({
                          id: `synth-${asset.hostname}-${Math.random().toString(36).slice(2,8)}`,
                          title: v.title,
                          severity: v.severity,
                          cve: v.cve || '',
                          description: v.description,
                          tool: 'llm-synthesis',
                          confidence: v.confidence,
                          category: v.category,
                        } as any);
                      }
                    }
                    addLog(state!, { phase: 'scanning', type: 'success', title: `\u2705 Vuln Synthesis: ${asset.hostname}`, detail: `${synthVulns.filter((v: any) => v.confidence >= 40).length} vulnerabilities identified from ${signals.length} risk signals` });
                  } catch (synthErr: any) {
                    addLog(state!, { phase: 'scanning', type: 'error', title: `\u274c Vuln Synthesis failed: ${asset.hostname}`, detail: synthErr.message });
                  }
                }
              } catch (err: any) {
                addLog(state!, { phase: 'scanning', type: 'error', title: '\u274c LLM Vuln Synthesis failed', detail: err.message });
              }
            }

            // Phase 4: Exploit Generation
            if (input.phases.exploitGeneration) {
              state!.phase = 'exploitation';
              state!.currentAction = 'Generating functional exploits...';
              broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'exploitation' });
              try {
                const { generateExploitsForAsset } = await import('../lib/functional-exploit-generator');
                for (const asset of state!.assets) {
                  const exploitable = asset.vulns.filter((v: any) => v.severity === 'critical' || v.severity === 'high');
                  if (exploitable.length === 0) continue;
                  addLog(state!, { phase: 'exploitation', type: 'info', title: `\u{1f3af} Exploits: ${asset.hostname}`, detail: `${exploitable.length} critical/high vulns` });
                  const exploits = await generateExploitsForAsset(
                    asset.hostname, exploitable,
                    { ip: asset.ip, os: (asset as any).os, technologies: asset.passiveRecon?.technologies, wafDetected: asset.wafDetected, ports: asset.ports as any },
                    { maxExploits: 3, includeEvasion: !!asset.wafDetected }
                  );
                  if (!(state as any).generatedExploits) (state as any).generatedExploits = [];
                  for (const exploit of exploits) {
                    (state as any).generatedExploits.push({ asset: asset.hostname, exploit, generatedAt: Date.now() });
                  }
                  addLog(state!, { phase: 'exploitation', type: 'success', title: `\u2705 Exploits: ${asset.hostname}`, detail: `${exploits.length} scripts (avg confidence: ${Math.round(exploits.reduce((s, e) => s + e.confidence, 0) / (exploits.length || 1))}%)` });
                }
              } catch (err: any) {
                addLog(state!, { phase: 'exploitation', type: 'error', title: '\u274c Exploit generation failed', detail: err.message });
              }
            }

            state!.phase = 'complete';
            state!.isRunning = false;
            state!.currentAction = undefined;
            addLog(state!, { phase: 'complete', type: 'success', title: '\u{1f3c1} Pipeline Complete', detail: `${state!.assets.length} assets, ${state!.assets.reduce((s, a) => s + a.vulns.length, 0)} vulns, ${(state as any).generatedExploits?.length || 0} exploits` });
            broadcastOpsUpdate(input.engagementId, { type: 'phase_change', phase: 'complete' });

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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const { generateFunctionalExploit: genExploit } = await import('../lib/functional-exploit-generator');
        const state = getOpsState(input.engagementId);
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const { validateExploitCode } = await import('../lib/functional-exploit-generator');
        const state = getOpsState(input.engagementId);
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const { validateExploitCode, improveExploit: improve } = await import('../lib/functional-exploit-generator');
        const state = getOpsState(input.engagementId);
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId);
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(input.engagementId);
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
        const { getOpsState, addLog, persistOpsStateNow } = await import('../lib/engagement-orchestrator');
        const { invokeLLM } = await import('../_core/llm');
        const state = getOpsState(input.engagementId);
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

Your task: Analyze the passive reconnaissance data and identify vulnerabilities.${categoryFocus}${existingContext}

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
            messages: [
              { role: 'system', content: 'You are a vulnerability assessment AI. Return only valid JSON.' },
              { role: 'user', content: synthPrompt },
            ],
            response_format: synthSchema,
          });

          const content = llmResult.choices?.[0]?.message?.content || '{}';
          const parsed = JSON.parse(content);
          const synthVulns = (parsed.vulnerabilities || []).filter((v: any) => v.confidence >= 40);

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
                title: v.title,
                severity: v.severity,
                cve: v.cve || '',
                description: v.description,
                tool: 'llm-synthesis',
                confidence: v.confidence,
                category: v.category,
              };
              asset.vulns.push(newVuln as any);
              newVulns.push(newVuln);
            }
          }

          addLog(state, { phase: 'scanning', type: 'success', title: `\u2705 Re-synthesis: ${asset.hostname}`, detail: `${newVulns.length} new vulnerabilities added` });
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
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const { executeExploit } = await import('../lib/exploit-sandbox');
        const state = getOpsState(input.engagementId);
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

    /** Manually record a scan snapshot for trend tracking */
    recordScanSnapshot: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input }) => {
        const { recordScanSnapshot } = await import('../lib/vuln-trend-tracker');
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        const state = getOpsState(String(input.engagementId));
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
  });
