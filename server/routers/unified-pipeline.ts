/**
 * Unified Attack Lifecycle Pipeline Router
 * 
 * Provides tRPC endpoints for orchestrating the full attack lifecycle
 * across all integrated tools: OSINT connectors, ZAP, Nuclei, Sliver C2,
 * Atomic Red Team, Metasploit, Caldera, and GoPhish.
 */

import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  PIPELINE_STAGES,
  TOOL_PHASE_MATRIX,
  ACTIVE_DISCOVERY_SOURCES,
  EXTENDED_SOURCE_WEIGHTS,
  correlateFindings,
  getPhaseTools,
  convertZapFindings,
  convertNucleiFindings,
  convertSliverFindings,
  convertAtomicFindings,
  convertMetasploitFindings,
  convertOsintFindings,
  generatePipelineSummary,
  generateTimelineEvents,
  type PipelinePhase,
  type PipelineTarget,
  type PipelineFinding,
  type PipelinePhaseResult,
  type PipelineRun,
  type ToolModule,
} from "../lib/unified-pipeline";

// ─── In-memory pipeline run store ────────────────────────────────────
const pipelineRuns = new Map<string, PipelineRun>();
let runCounter = 0;

function generateRunId(): string {
  return `run-${++runCounter}-${Date.now().toString(36)}`;
}

export const unifiedPipelineRouter = router({
  /**
   * Get pipeline stage definitions with tool descriptions.
   */
  getStages: protectedProcedure.query(() => {
    return PIPELINE_STAGES.map(stage => ({
      ...stage,
      toolDetails: stage.tools.map(tool => ({
        tool,
        ...TOOL_PHASE_MATRIX[tool],
      })),
    }));
  }),

  /**
   * Get the complete tool-to-phase matrix showing which tools
   * contribute to which phases and their data flow relationships.
   */
  getToolMatrix: protectedProcedure.query(() => {
    return Object.entries(TOOL_PHASE_MATRIX).map(([tool, config]) => ({
      tool,
      ...config,
    }));
  }),

  /**
   * Get recommended tools for a specific phase based on prior findings.
   */
  getPhaseRecommendations: protectedProcedure
    .input(z.object({
      phase: z.enum(['recon', 'enumeration', 'vulnerability_assessment', 'exploitation', 'post_exploitation', 'reporting']),
      runId: z.string().optional(),
      domain: z.string().optional(),
    }))
    .query(({ input }) => {
      const run = input.runId ? pipelineRuns.get(input.runId) : undefined;
      const priorFindings = run
        ? run.phases.flatMap(p => p.findings)
        : [];

      const target: PipelineTarget = {
        domain: input.domain || 'unknown',
        scope: { inScope: [input.domain || '*'], outOfScope: [] },
      };

      return getPhaseTools(input.phase as PipelinePhase, target, priorFindings);
    }),

  /**
   * Start a new pipeline run with target configuration.
   */
  startRun: protectedProcedure
    .input(z.object({
      domain: z.string(),
      targetIps: z.array(z.string()).optional(),
      targetUrls: z.array(z.string()).optional(),
      openApiSpecUrl: z.string().optional(),
      graphqlEndpoint: z.string().optional(),
      inScope: z.array(z.string()).optional(),
      outOfScope: z.array(z.string()).optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate all targets against engagement ROE ──
      if (input.engagementId) {
        const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
        const allTargets = [
          input.domain,
          ...(input.targetIps || []),
          ...(input.targetUrls || []),
        ].filter(Boolean);
        if (allTargets.length > 0) {
          await enforceMultiTargetScope(input.engagementId, allTargets, "Unified Pipeline", ctx);
        }
      }

      const runId = generateRunId();
      const target: PipelineTarget = {
        domain: input.domain,
        targetIps: input.targetIps,
        targetUrls: input.targetUrls,
        openApiSpecUrl: input.openApiSpecUrl,
        graphqlEndpoint: input.graphqlEndpoint,
        scope: {
          inScope: input.inScope || [input.domain],
          outOfScope: input.outOfScope || [],
        },
        engagementId: input.engagementId,
      };

      const run: PipelineRun = {
        id: runId,
        target,
        phases: PIPELINE_STAGES.map(stage => ({
          phase: stage.phase,
          status: 'pending' as const,
          toolResults: [],
          findings: [],
          startedAt: 0,
        })),
        status: 'pending',
        totalFindings: 0,
        findingsBySeverity: {},
        findingsByPhase: {} as Record<PipelinePhase, number>,
        findingsByTool: {},
        attackCoverage: {
          techniquesUsed: [],
          tacticsUsed: [],
          coveragePercent: 0,
        },
        startedAt: Date.now(),
        engagementId: input.engagementId,
      };

      pipelineRuns.set(runId, run);
      return { runId, status: 'pending', target };
    }),

  /**
   * Submit findings from a tool execution to a pipeline run.
   * This is the main integration point — each tool's results
   * flow through here to be normalized and correlated.
   */
  submitFindings: protectedProcedure
    .input(z.object({
      runId: z.string(),
      phase: z.enum(['recon', 'enumeration', 'vulnerability_assessment', 'exploitation', 'post_exploitation', 'reporting']),
      tool: z.string(),
      findings: z.array(z.any()),
      durationMs: z.number().optional(),
      errors: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const run = pipelineRuns.get(input.runId);
      if (!run) throw new Error(`Pipeline run ${input.runId} not found`);

      const phase = input.phase as PipelinePhase;
      const tool = input.tool as ToolModule;

      // Convert raw findings to pipeline format based on tool type
      let pipelineFindings: PipelineFinding[];
      switch (tool) {
        case 'zap_passive':
        case 'zap_active':
          pipelineFindings = convertZapFindings(input.findings, phase);
          break;
        case 'nuclei_info':
        case 'nuclei_vuln':
        case 'nuclei_critical':
          pipelineFindings = convertNucleiFindings(input.findings, phase);
          break;
        case 'sliver_c2':
          pipelineFindings = convertSliverFindings(input.findings, phase);
          break;
        case 'manjusaka_c2':
          pipelineFindings = convertSliverFindings(input.findings, phase); // Same C2 finding format
          break;
        case 'atomic_red_team':
          pipelineFindings = convertAtomicFindings(input.findings, phase);
          break;
        case 'metasploit':
          pipelineFindings = convertMetasploitFindings(input.findings, phase);
          break;
        case 'passive_osint':
          pipelineFindings = convertOsintFindings(input.findings, phase);
          break;
        default:
          // Generic conversion for other tools
          pipelineFindings = input.findings.map((f: any, i: number) => ({
            id: `${tool}-${phase}-${i}`,
            phase,
            tool,
            type: f.type || 'vulnerability',
            severity: f.severity || 'info',
            title: f.title || f.name || 'Unknown',
            description: f.description || '',
            host: f.host || f.target || '',
            port: f.port,
            cveId: f.cveId,
            cweId: f.cweId,
            attackTechnique: f.attackTechnique || f.techniqueId,
            confidence: f.confidence || 50,
            evidence: f.evidence || f,
            timestamp: f.timestamp || Date.now(),
            crossRefs: [],
            corroborated: false,
            corroboratingTools: [],
          }));
      }

      // Add to phase results
      const phaseResult = run.phases.find(p => p.phase === phase);
      if (phaseResult) {
        if (phaseResult.status === 'pending') {
          phaseResult.status = 'running';
          phaseResult.startedAt = Date.now();
        }
        phaseResult.findings.push(...pipelineFindings);
        phaseResult.toolResults.push({
          tool,
          status: (input.errors?.length || 0) > 0 ? 'failed' : 'success',
          findingCount: pipelineFindings.length,
          durationMs: input.durationMs || 0,
          errors: input.errors || [],
        });
      }

      // Update run status
      run.status = 'running';

      // ─── SSIL: Auto-ingest pipeline findings into observation normalizer ───
      try {
        const { ingestUnifiedPipelineFindings } = await import("../lib/observation-ingestor");
        const ingestion = await ingestUnifiedPipelineFindings(input.tool, input.findings);
        console.log(`[UnifiedPipeline→SSIL] ${input.tool}: Ingested ${ingestion.observations} observations, ${ingestion.signals} signals, ${ingestion.riskCards} risk cards`);
      } catch (err: any) {
        console.error(`[UnifiedPipeline→SSIL] Ingestion failed (non-fatal): ${err.message}`);
      }

      return {
        findingsAdded: pipelineFindings.length,
        totalFindings: run.phases.reduce((sum, p) => sum + p.findings.length, 0),
      };
    }),

  /**
   * Complete a phase and trigger cross-tool correlation.
   */
  completePhase: protectedProcedure
    .input(z.object({
      runId: z.string(),
      phase: z.enum(['recon', 'enumeration', 'vulnerability_assessment', 'exploitation', 'post_exploitation', 'reporting']),
    }))
    .mutation(({ input }) => {
      const run = pipelineRuns.get(input.runId);
      if (!run) throw new Error(`Pipeline run ${input.runId} not found`);

      const phaseResult = run.phases.find(p => p.phase === input.phase);
      if (!phaseResult) throw new Error(`Phase ${input.phase} not found`);

      // Run cross-tool correlation on all findings so far
      const allFindings = run.phases.flatMap(p => p.findings);
      const correlated = correlateFindings(allFindings);

      // Update findings with correlation data
      for (const phase of run.phases) {
        phase.findings = phase.findings.map(f => {
          const corr = correlated.find(c => c.id === f.id);
          return corr || f;
        });
      }

      phaseResult.status = 'completed';
      phaseResult.completedAt = Date.now();
      phaseResult.durationMs = phaseResult.completedAt - phaseResult.startedAt;

      // Generate summary
      const summary = generatePipelineSummary(run.target, run.phases);
      run.totalFindings = summary.totalFindings;
      run.findingsBySeverity = summary.findingsBySeverity;
      run.findingsByPhase = summary.findingsByPhase;
      run.findingsByTool = summary.findingsByTool;
      run.attackCoverage = summary.attackCoverage;

      // Check if all phases are complete
      const allComplete = run.phases.every(p => p.status === 'completed' || p.status === 'skipped');
      if (allComplete) {
        run.status = 'completed';
        run.completedAt = Date.now();
      }

      return {
        phase: input.phase,
        status: phaseResult.status,
        findingsInPhase: phaseResult.findings.length,
        corroboratedCount: phaseResult.findings.filter(f => f.corroborated).length,
        nextPhase: getNextPhase(input.phase as PipelinePhase),
      };
    }),

  /**
   * Get the current state of a pipeline run.
   */
  getRun: protectedProcedure
    .input(z.object({ runId: z.string() }))
    .query(({ input }) => {
      const run = pipelineRuns.get(input.runId);
      if (!run) throw new Error(`Pipeline run ${input.runId} not found`);

      return {
        ...run,
        phases: run.phases.map(p => ({
          ...p,
          findings: p.findings.slice(0, 100), // Limit findings in response
          totalFindings: p.findings.length,
        })),
      };
    }),

  /**
   * Get all findings from a pipeline run with filtering.
   */
  getFindings: protectedProcedure
    .input(z.object({
      runId: z.string(),
      phase: z.enum(['recon', 'enumeration', 'vulnerability_assessment', 'exploitation', 'post_exploitation', 'reporting']).optional(),
      tool: z.string().optional(),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
      corroboratedOnly: z.boolean().optional(),
      limit: z.number().default(100),
      offset: z.number().default(0),
    }))
    .query(({ input }) => {
      const run = pipelineRuns.get(input.runId);
      if (!run) throw new Error(`Pipeline run ${input.runId} not found`);

      let findings = run.phases.flatMap(p => p.findings);

      if (input.phase) findings = findings.filter(f => f.phase === input.phase);
      if (input.tool) findings = findings.filter(f => f.tool === input.tool);
      if (input.severity) findings = findings.filter(f => f.severity === input.severity);
      if (input.corroboratedOnly) findings = findings.filter(f => f.corroborated);

      return {
        total: findings.length,
        findings: findings.slice(input.offset, input.offset + input.limit),
        bySeverity: {
          critical: findings.filter(f => f.severity === 'critical').length,
          high: findings.filter(f => f.severity === 'high').length,
          medium: findings.filter(f => f.severity === 'medium').length,
          low: findings.filter(f => f.severity === 'low').length,
          info: findings.filter(f => f.severity === 'info').length,
        },
        byTool: Object.fromEntries(
          Array.from(new Set(findings.map(f => f.tool))).map(t => [t, findings.filter(f => f.tool === t).length])
        ),
      };
    }),

  /**
   * Generate timeline events from a pipeline run for the engagement timeline.
   */
  getTimeline: protectedProcedure
    .input(z.object({ runId: z.string() }))
    .query(({ input }) => {
      const run = pipelineRuns.get(input.runId);
      if (!run) throw new Error(`Pipeline run ${input.runId} not found`);

      const allFindings = run.phases.flatMap(p => p.findings);
      return generateTimelineEvents(allFindings);
    }),

  /**
   * Get discovery coverage extension data from active tools.
   */
  getDiscoveryCoverage: protectedProcedure.query(() => {
    return ACTIVE_DISCOVERY_SOURCES;
  }),

  /**
   * Get extended corroboration source weights.
   */
  getCorroborationWeights: protectedProcedure.query(() => {
    return EXTENDED_SOURCE_WEIGHTS;
  }),

  /**
   * List all pipeline runs.
   */
  listRuns: protectedProcedure
    .input(z.object({
      limit: z.number().default(20),
      status: z.enum(['pending', 'running', 'completed', 'failed', 'cancelled']).optional(),
    }).optional())
    .query(({ input }) => {
      const limit = input?.limit || 20;
      let runs = Array.from(pipelineRuns.values())
        .sort((a, b) => b.startedAt - a.startedAt);

      if (input?.status) {
        runs = runs.filter(r => r.status === input.status);
      }

      return runs.slice(0, limit).map(run => ({
        id: run.id,
        domain: run.target.domain,
        status: run.status,
        totalFindings: run.totalFindings,
        findingsBySeverity: run.findingsBySeverity,
        attackCoverage: run.attackCoverage,
        startedAt: run.startedAt,
        completedAt: run.completedAt,
        phasesCompleted: run.phases.filter(p => p.status === 'completed').length,
        totalPhases: run.phases.length,
      }));
    }),

  /**
   * Cancel a running pipeline.
   */
  cancelRun: protectedProcedure
    .input(z.object({ runId: z.string() }))
    .mutation(({ input }) => {
      const run = pipelineRuns.get(input.runId);
      if (!run) throw new Error(`Pipeline run ${input.runId} not found`);

      run.status = 'cancelled';
      run.completedAt = Date.now();

      return { runId: input.runId, status: 'cancelled' };
    }),

  /**
   * Get ATT&CK coverage from a pipeline run — which techniques were tested.
   */
  getAttackCoverage: protectedProcedure
    .input(z.object({ runId: z.string() }))
    .query(({ input }) => {
      const run = pipelineRuns.get(input.runId);
      if (!run) throw new Error(`Pipeline run ${input.runId} not found`);

      const allFindings = run.phases.flatMap(p => p.findings);
      const techniqueMap = new Map<string, {
        technique: string;
        tools: Set<string>;
        phases: Set<string>;
        findings: number;
        severity: string;
      }>();

      for (const f of allFindings) {
        if (!f.attackTechnique) continue;
        const existing = techniqueMap.get(f.attackTechnique);
        if (existing) {
          existing.tools.add(f.tool);
          existing.phases.add(f.phase);
          existing.findings++;
          if (severityRank(f.severity) > severityRank(existing.severity)) {
            existing.severity = f.severity;
          }
        } else {
          techniqueMap.set(f.attackTechnique, {
            technique: f.attackTechnique,
            tools: new Set([f.tool]),
            phases: new Set([f.phase]),
            findings: 1,
            severity: f.severity,
          });
        }
      }

      return Array.from(techniqueMap.values()).map(t => ({
        technique: t.technique,
        tools: Array.from(t.tools),
        phases: Array.from(t.phases),
        findings: t.findings,
        severity: t.severity,
      }));
    }),
});

// ─── Helpers ────────────────────────────────────────────────────────

function getNextPhase(current: PipelinePhase): PipelinePhase | null {
  const order: PipelinePhase[] = ['recon', 'enumeration', 'vulnerability_assessment', 'exploitation', 'post_exploitation', 'reporting'];
  const idx = order.indexOf(current);
  return idx < order.length - 1 ? order[idx + 1] : null;
}

function severityRank(severity: string): number {
  const ranks: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return ranks[severity] || 0;
}
