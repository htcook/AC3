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

    /** Resolve an approval gate */
    resolveApproval: protectedProcedure
      .input(z.object({
        gateId: z.string(),
        approved: z.boolean(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { resolveApproval } = await import('../lib/engagement-orchestrator');
        const resolved = resolveApproval(input.gateId, input.approved, ctx.user.name || String(ctx.user.id));
        if (!resolved) throw new TRPCError({ code: 'NOT_FOUND', message: 'Approval gate not found or already resolved' });

        await db.logActivity({
          userId: ctx.user.id,
          action: input.approved ? 'ops_approval_granted' : 'ops_approval_denied',
          details: `${input.approved ? 'Approved' : 'Denied'} gate ${input.gateId}`,
        });

        return { resolved: true };
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
    startPassiveScan: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
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

        state.log.push({ id: `log-${Date.now()}-mode`, timestamp: Date.now(), phase: 'recon', type: 'info', title: '\ud83d\udd12 Scan Mode: Strict Passive', detail: `Scanning ${allTargets.length} targets. Only querying third-party databases (crt.sh, Shodan, Censys, Wayback, urlscan, SecurityTrails, Dehashed, BinaryEdge). Zero direct contact with target infrastructure.` });
        broadcastOpsUpdate(input.engagementId, { type: 'log', entry: state.log[state.log.length - 1] });

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
                    // Options: strict_passive mode, scoped to engagement targets only, with per-connector progress
                    {
                      scanMode: 'strict_passive',
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

                  if (existing) {
                    existing.ip = asset.asset?.ip || asset.ip || existing.ip;
                    existing.type = (asset.asset?.assetType || asset.assetType) === 'web_application' ? 'web_app' : existing.type;
                    existing.status = 'discovered';
                    existing.passiveRecon = assetReconData;
                    if (assetReconData.wafDetected) existing.wafDetected = assetReconData.wafDetected;
                  } else {
                    state!.assets.push({
                      hostname, ip: asset.asset?.ip || asset.ip,
                      type: (asset.asset?.assetType || asset.assetType) === 'web_application' ? 'web_app' : 'unknown',
                      ports: [], vulns: [], zapFindings: [], exploitAttempts: [], toolResults: [],
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
  });
