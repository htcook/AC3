// @ts-nocheck
/**
 * Accuracy Engine Router
 * ──────────────────────
 * Exposes all 11 accuracy enhancement modules as tRPC endpoints:
 *   P0: Cross-Source Corroboration, Dynamic CVE Matching, Remediation Verification
 *   P1: Compensating Controls, Pre-Flight Checks, Active Probes
 *   P2: Temporal Decay, Attack Chains, Exploit Feedback Loop
 *   P3: LLM Rule Generation, Rule-Evidence Validation
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";

// ─── P0-1: Cross-Source Corroboration ────────────────────────────────

const corroborationRouter = router({
  /** Run corroboration analysis on a set of observations */
  analyze: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { discoveredAssets } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { corroborateFindings, SOURCE_RELIABILITY } = await import("../lib/passive/corroboration-engine");

      const dbConn = await getDbRequired();
      const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      // Build ConnectorResult[] grouped by source
      const sourceMap = new Map<string, any[]>();
      for (const a of assets) {
        const src = (a as any).source || "unknown";
        if (!sourceMap.has(src)) sourceMap.set(src, []);
        sourceMap.get(src)!.push(a);
      }

      const connectorResults = Array.from(sourceMap.entries()).map(([connector, items]) => ({
        connector,
        domain: (items[0] as any).hostname || (items[0] as any).domain || "",
        observations: items.map((a: any) => ({
          assetId: String(a.id || a.ip || a.hostname),
          domain: a.domain || a.hostname || "",
          assetType: (a.assetType || "ip") as any,
          name: a.hostname || a.ip || "",
          ip: a.ip || undefined,
          source: connector,
          observedAt: a.createdAt ? new Date(a.createdAt) : new Date(),
          tags: a.tags || [],
          evidence: a.rawData || {},
          attribution: {
            provider: connector,
            method: `Discovered via ${connector} scan`,
          },
        })),
        errors: [],
        durationMs: 0,
        rateLimited: false,
      }));

      const result = corroborateFindings(connectorResults, []);
      return {
        stats: result.stats,
        highConfidence: result.corroboratedObservations.filter(o => o.corroboration.tier === "high-confidence").length,
        mediumConfidence: result.corroboratedObservations.filter(o => o.corroboration.tier === "corroborated").length,
        lowConfidence: result.corroboratedObservations.filter(o => o.corroboration.tier === "unverified").length,
        totalObservations: result.totalObservations,
        sourceReliability: SOURCE_RELIABILITY,
        findings: result.corroboratedObservations.slice(0, 50).map(o => ({
          ip: (o as any).ip,
          hostname: (o as any).name,
          port: (o as any).port,
          service: (o as any).service,
          version: (o as any).version,
          corroborationScore: o.corroboration.confidenceMultiplier,
          sourceCount: o.corroboration.sourceCount,
          sources: o.corroboration.confirmingSources,
          confidenceTier: o.corroboration.tier,
        })),
      };
    }),

  /** Get source reliability ratings */
  sourceReliability: protectedProcedure.query(async () => {
    const { SOURCE_RELIABILITY } = await import("../lib/passive/corroboration-engine");
    return { ratings: SOURCE_RELIABILITY };
  }),
});

// ─── P0-2: Dynamic CVE-to-Product Matching ───────────────────────────

const cveMatcherRouter = router({
  /** Match a technology/version against NVD CVE database */
  match: protectedProcedure
    .input(z.object({
      technology: z.string().min(1),
      version: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const { matchTechnologyCves } = await import("../lib/dynamic-cpe-matcher");
      return await matchTechnologyCves(input.technology, input.version);
    }),

  /** Batch match multiple technologies */
  batchMatch: protectedProcedure
    .input(z.object({
      items: z.array(z.object({
        technology: z.string().min(1),
        version: z.string().optional(),
      })).max(50),
    }))
    .mutation(async ({ input }) => {
      const { matchTechnologyCves } = await import("../lib/dynamic-cpe-matcher");
      const results = await Promise.all(
        input.items.map(async (item) => {
          const result = await matchTechnologyCves(item.technology, item.version);
          return { ...item, ...result };
        })
      );
      return { results, totalMatched: results.filter((r: any) => r.totalCves > 0).length };
    }),

  /** Match all technologies found in a scan */
  scanMatch: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { discoveredAssets } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { matchTechnologyCves } = await import("../lib/dynamic-cpe-matcher");

      const dbConn = await getDbRequired();
      const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      const techPairs = new Map<string, { technology: string; version?: string }>();
      for (const a of assets) {
        const tech = (a as any).service || (a as any).technology;
        const ver = (a as any).version;
        if (tech) {
          const key = `${tech}:${ver || ""}`;
          if (!techPairs.has(key)) techPairs.set(key, { technology: tech, version: ver || undefined });
        }
      }

      const results = await Promise.all(
        Array.from(techPairs.values()).slice(0, 30).map(async (pair) => {
          const result = await matchTechnologyCves(pair.technology, pair.version);
          return { ...pair, ...result };
        })
      );

      return {
        totalTechnologies: techPairs.size,
        matched: results.filter((r: any) => r.totalCves > 0).length,
        results: results.sort((a: any, b: any) => b.totalCves - a.totalCves),
      };
    }),
});

// ─── P0-3: Remediation Verification ──────────────────────────────────

const remediationRouter = router({
  /** Create a remediation tracking record */
  create: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      findingId: z.string(),
      cveId: z.string().nullable().default(null),
      target: z.string().min(1),
      port: z.number().nullable().default(null),
      service: z.string().nullable().default(null),
      validationId: z.string(),
      exploitModule: z.string(),
      severity: z.enum(["critical", "high", "medium", "low"]),
      validatedAt: z.number(),
    }))
    .mutation(async ({ input }) => {
      const { createRemediationRecord } = await import("../lib/remediation-verification") as any;
      return createRemediationRecord({ ...input, findingId: Number((input as any).findingId || 0) } as any);
    }),

  /** Mark a finding as remediated */
  markRemediated: protectedProcedure
    .input(z.object({
      recordId: z.string(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { markRemediationApplied } = await import("../lib/remediation-verification") as any;
      const record = markRemediationApplied(Number(input.recordId), input.notes);
      if (!record) throw new TRPCError({ code: "NOT_FOUND", message: "Remediation record not found" });
      return record;
    }),

  /** Queue a finding for re-verification */
  queueVerification: protectedProcedure
    .input(z.object({ recordId: z.string() }))
    .mutation(async ({ input }) => {
      const { queueForVerification } = await import("../lib/remediation-verification") as any;
      const record = queueForVerification(Number(input.recordId));
      if (!record) throw new TRPCError({ code: "NOT_FOUND" });
      return record;
    }),

  /** Record a verification attempt result */
  recordVerification: protectedProcedure
    .input(z.object({
      recordId: z.string(),
      result: z.enum(["verified_fixed", "still_vulnerable", "inconclusive", "error"]),
      exploitModule: z.string(),
      exploitOutput: z.string().nullable().default(null),
      evidenceUrl: z.string().nullable().default(null),
      durationMs: z.number(),
      notes: z.string().nullable().default(null),
    }))
    .mutation(async ({ input }) => {
      const { recordVerificationAttempt } = await import("../lib/remediation-verification") as any;
      const { recordId, ...attempt } = input;
      const record = recordVerificationAttempt(Number(recordId), attempt);
      if (!record) throw new TRPCError({ code: "NOT_FOUND" });
      return record;
    }),

  /** Get remediation summary */
  summary: protectedProcedure.query(async () => {
    const { getRemediationSummary } = await import("../lib/remediation-verification") as any;
    return getRemediationSummary();
  }),

  /** Get records by scan */
  byScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const remMod = await import("../lib/remediation-verification") as any;
      const getRecordsByScan = remMod.getRecordsByFinding || remMod.getRecordsByScan;
      return getRecordsByScan(input.scanId);
    }),

  /** Get a single record with timeline */
  getRecord: protectedProcedure
    .input(z.object({ recordId: z.string() }))
    .query(async ({ input }) => {
      const { getRemediationRecord, getRemediationTimeline } = await import("../lib/remediation-verification") as any;
      const record = getRemediationRecord(Number(input.recordId));
      if (!record) return null;
      const timeline = getRemediationTimeline(Number(input.recordId));
      return { ...record, timeline };
    }),

  /** Get overdue findings */
  overdue: protectedProcedure.query(async () => {
    const { getOverdueFindings } = await import("../lib/remediation-verification") as any;
    return getOverdueFindings();
  }),

  /** Get records needing verification */
  needsVerification: protectedProcedure.query(async () => {
    const { getRecordsNeedingVerification } = await import("../lib/remediation-verification") as any;
    return getRecordsNeedingVerification();
  }),
});

// ─── P1-1: Compensating Control Awareness ────────────────────────────

const controlsRouter = router({
  /** Detect compensating controls for a target from HTTP headers */
  detect: protectedProcedure
    .input(z.object({
      target: z.string().min(1),
      port: z.number().default(443),
    }))
    .mutation(async ({ input }) => {
      const { detectControlsFromHeaders } = await import("../lib/compensating-controls");
      try {
        const url = `https://${input.target}:${input.port}`;
        const response = await fetch(url, { signal: AbortSignal.timeout(10000), redirect: "follow" });
        const headers: Record<string, string> = {};
        response.headers.forEach((v, k) => { headers[k] = v; });
        const controls = detectControlsFromHeaders(headers);
        return { target: input.target, controls, headerCount: Object.keys(headers).length };
      } catch {
        return { target: input.target, controls: [], headerCount: 0, error: "Could not reach target" };
      }
    }),

  /** Assess controls for a scan's observations and compute severity adjustments */
  assessScan: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      findingSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),
    }))
    .query(async ({ input }) => {
      const { discoveredAssets } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { detectControlsFromObservations, assessControls } = await import("../lib/compensating-controls");

      const dbConn = await getDbRequired();
      const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      // Build observations in the format expected by detectControlsFromObservations
      const observations = assets.map((a: any) => ({
        assetType: a.assetType || a.service || "technology",
        value: a.hostname || a.ip || a.service || "",
        source: a.source || "unknown",
        metadata: a.rawData || {},
      }));

      const controls = detectControlsFromObservations(observations);
      const assessment = assessControls(controls, input.findingSeverity);

      return {
        totalControls: controls.length,
        assessment,
        controlsByCategory: controls.reduce((acc: Record<string, number>, c: any) => {
          acc[c.category] = (acc[c.category] || 0) + 1;
          return acc;
        }, {}),
      };
    }),
});

// ─── P1-2: Exploit Pre-Flight Checks ────────────────────────────────

const preFlightRouter = router({
  /** Run pre-flight checks for a specific exploit module against a target */
  check: protectedProcedure
    .input(z.object({
      moduleName: z.string().min(1),
      targetService: z.string().default(""),
      targetPort: z.number().nullable().default(null),
      affectedVersions: z.string().nullable().default(null),
      affectedProducts: z.array(z.string()).default([]),
      requiredConditions: z.array(z.string()).default([]),
      attackVector: z.enum(["network", "adjacent", "local", "physical"]).default("network"),
      reliability: z.enum(["excellent", "good", "average", "low", "manual"]).default("average"),
      cveIds: z.array(z.string()).default([]),
      // Target info
      targetHost: z.string().min(1),
      detectedVersion: z.string().nullable().default(null),
      detectedServices: z.array(z.object({
        port: z.number(),
        service: z.string(),
        version: z.string().optional(),
      })).default([]),
      detectedFeatures: z.array(z.string()).default([]),
      isExternal: z.boolean().default(true),
    }))
    .query(async ({ input }) => {
      const { runPreFlightChecks, getExploitSuccessRate } = await import("../lib/exploit-preflight");
      const history = getExploitSuccessRate(input.moduleName);
      const module = {
        moduleName: input.moduleName,
        targetService: input.targetService,
        targetPort: input.targetPort,
        affectedVersions: input.affectedVersions,
        affectedProducts: input.affectedProducts,
        requiredConditions: input.requiredConditions,
        attackVector: input.attackVector,
        reliability: input.reliability,
        historicalSuccessRate: history.rate,
        historicalAttempts: history.attempts,
        cveIds: input.cveIds,
      };
      const target = {
        host: input.targetHost,
        detectedVersion: input.detectedVersion,
        detectedServices: input.detectedServices,
        detectedFeatures: input.detectedFeatures,
        isExternal: input.isExternal,
      };
      return runPreFlightChecks(module, target);
    }),

  /** Batch pre-flight checks for all modules against a target */
  batchCheck: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      targetHost: z.string(),
      detectedVersion: z.string().nullable().default(null),
      detectedServices: z.array(z.object({
        port: z.number(),
        service: z.string(),
        version: z.string().optional(),
      })).default([]),
      detectedFeatures: z.array(z.string()).default([]),
      isExternal: z.boolean().default(true),
    }))
    .query(async ({ input }) => {
      const { unifiedExploitCatalog } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { batchPreFlightChecks, filterViableModules, getExploitSuccessRate } = await import("../lib/exploit-preflight");

      const dbConn = await getDbRequired();
      const catalog = await dbConn.select().from(unifiedExploitCatalog).where(eq(unifiedExploitCatalog.enabled, true));

      const modules = catalog.slice(0, 30).map((c: any) => {
        const history = getExploitSuccessRate(c.msfModule || c.catalogId);
        return {
          moduleName: c.msfModule || c.catalogId,
          targetService: c.targetService || "",
          targetPort: c.targetPort || null,
          affectedVersions: c.affectedVersions || null,
          affectedProducts: c.affectedProducts || [],
          requiredConditions: [],
          attackVector: "network" as const,
          reliability: (c.msfRank || "average") as "excellent" | "good" | "average" | "low" | "manual",
          historicalSuccessRate: history.rate,
          historicalAttempts: history.attempts,
          cveIds: c.cveIds || [],
        };
      });

      const target = {
        host: input.targetHost,
        detectedVersion: input.detectedVersion,
        detectedServices: input.detectedServices,
        detectedFeatures: input.detectedFeatures,
        isExternal: input.isExternal,
      };

      const results = batchPreFlightChecks(modules, target);
      const viable = filterViableModules(results);

      return {
        totalModules: modules.length,
        totalViable: viable.length,
        viableRate: modules.length > 0 ? Math.round((viable.length / modules.length) * 100) : 0,
        results: results.slice(0, 50).map((r: any) => ({
          exploitModule: r.exploitModule,
          target: r.target,
          port: r.port,
          verdict: r.verdict,
          overallConfidence: r.overallConfidence,
          estimatedSuccessRate: r.estimatedSuccessRate,
          passedChecks: r.checks.filter(c => c.passed).length,
          totalChecks: r.checks.length,
          recommendation: r.recommendation,
        })),
      };
    }),

  /** Get historical exploit success rate for a module */
  successRate: protectedProcedure
    .input(z.object({ moduleName: z.string() }))
    .query(async ({ input }) => {
      const { getExploitSuccessRate } = await import("../lib/exploit-preflight");
      return getExploitSuccessRate(input.moduleName);
    }),
});

// ─── P1-3: Active Verification Probes ────────────────────────────────

const probesRouter = router({
  /** List available probe templates */
  listTemplates: protectedProcedure
    .input(z.object({
      cveIds: z.array(z.string()).optional(),
      tag: z.string().optional(),
    }).default({}))
    .query(async ({ input }) => {
      const { PROBE_TEMPLATES, getProbesForCves, getProbesByTag } = await import("../lib/active-probes");
      if (input.cveIds && input.cveIds.length > 0) {
        return { probes: getProbesForCves(input.cveIds) };
      }
      if (input.tag) {
        return { probes: getProbesByTag(input.tag) };
      }
      return {
        probes: PROBE_TEMPLATES.map(p => ({
          id: p.id,
          name: p.name,
          cveIds: p.cveIds,
          type: p.type,
          severity: p.severity,
          tags: p.tags,
          targetService: p.targetService,
        })),
      };
    }),

  /** Run a probe scan against a target */
  runScan: protectedProcedure
    .input(z.object({
      target: z.string().min(1),
      port: z.number().optional(),
      cveIds: z.array(z.string()).optional(),
      probeIds: z.array(z.string()).optional(),
      timeoutMs: z.number().default(10000),
    }))
    .mutation(async ({ input }) => {
      const { runProbeScan, getProbesForCves, PROBE_TEMPLATES } = await import("../lib/active-probes");

      let templates: typeof PROBE_TEMPLATES | undefined;
      if (input.probeIds && input.probeIds.length > 0) {
        templates = PROBE_TEMPLATES.filter(p => input.probeIds!.includes(p.id));
      } else if (input.cveIds && input.cveIds.length > 0) {
        templates = getProbesForCves(input.cveIds);
      }

      const result = await runProbeScan(input.target, {
        port: input.port,
        templates,
        timeoutMs: input.timeoutMs,
      });
      return result;
    }),
});

// ─── P2-1: Temporal Decay Scoring ────────────────────────────────────

const temporalRouter = router({
  /** Calculate temporal decay score for a finding */
  score: protectedProcedure
    .input(z.object({
      baseScore: z.number().min(0).max(10),
      baseSeverity: z.enum(["critical", "high", "medium", "low"]),
      cvePublishedDate: z.number().nullable().default(null),
      findingFirstSeen: z.number(),
      lastValidated: z.number().nullable().default(null),
      patchAvailableDate: z.number().nullable().default(null),
      kevAddedDate: z.number().nullable().default(null),
      exploitPublicDate: z.number().nullable().default(null),
    }))
    .query(async ({ input }) => {
      const { calculateTemporalScore } = await import("../lib/temporal-decay");
      return calculateTemporalScore(input);
    }),

  /** Batch temporal scores for all findings in a scan */
  scanScores: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { discoveredAssets } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { batchTemporalScores } = await import("../lib/temporal-decay");

      const dbConn = await getDbRequired();
      const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      const items = assets.map((a: any, i: number) => ({
        id: String(a.id || i),
        factors: {
          cvePublishedDate: a.cvePublishedDate ? new Date(a.cvePublishedDate).getTime() : null,
          findingFirstSeen: a.createdAt ? new Date(a.createdAt).getTime() : Date.now(),
          lastValidated: null,
          patchAvailableDate: null,
          kevAddedDate: a.isKev ? Date.now() - 30 * 24 * 60 * 60 * 1000 : null,
          exploitPublicDate: null,
          baseSeverity: (a.severity || "medium") as "critical" | "high" | "medium" | "low",
          baseScore: a.cvssScore || a.riskScore || 5.0,
        },
      }));

      const scoresMap = batchTemporalScores(items);
      const scores = Array.from(scoresMap.values());

      // Summarize urgency distribution
      const urgencyDist: Record<string, number> = {};
      for (const s of scores) {
        urgencyDist[s.urgencyLevel] = (urgencyDist[s.urgencyLevel] || 0) + 1;
      }

      return {
        totalScored: scores.length,
        urgencyDistribution: urgencyDist,
        averageMultiplier: scores.length > 0 ? +(scores.reduce((sum, x) => sum + x.temporalMultiplier, 0) / scores.length).toFixed(3) : 1,
        scores: scores.slice(0, 50).map(s => ({
          adjustedScore: s.adjustedScore,
          adjustedSeverity: s.adjustedSeverity,
          temporalMultiplier: s.temporalMultiplier,
          urgencyLevel: s.urgencyLevel,
          rationale: s.rationale,
          decayWarnings: s.decayWarnings,
        })),
      };
    }),
});

// ─── P2-2: Attack Chain Validation ───────────────────────────────────

const attackChainRouter = router({
  /** Analyze attack chains in a scan */
  analyze: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { discoveredAssets } = await import("../../drizzle/schema");
      const { getDbRequired } = await import("../db");
      const { eq } = await import("drizzle-orm");
      const { analyzeAttackChains, CHAIN_PATTERNS } = await import("../lib/attack-chain-validation");

      const dbConn = await getDbRequired();
      const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      const findings = assets.map((a: any) => ({
        id: String(a.id),
        title: a.title || a.service || `${a.ip}:${a.port}`,
        severity: (a.severity || "medium") as "critical" | "high" | "medium" | "low" | "info",
        description: a.description || `${a.service || ""} ${a.version || ""} on ${a.ip}:${a.port}`,
        target: a.ip || a.hostname || "",
        port: a.port || null,
        cveId: a.cves?.[0] || null,
        validated: a.exploitable || false,
        attackTechnique: a.technique || undefined,
      }));

      const result = analyzeAttackChains(findings);
      return {
        totalChains: result.totalChainsFound,
        criticalChains: result.criticalChains,
        highChains: result.highChains,
        maxChainLength: result.maxChainLength,
        coverageByPhase: result.coverageByPhase,
        summary: result.summary,
        chains: result.chains.slice(0, 20).map((c: any) => ({
          id: c.id,
          name: c.name,
          description: c.description,
          linkCount: c.links.length,
          chainSeverity: c.chainSeverity,
          chainScore: c.chainScore,
          killChainCoverage: c.killChainCoverage,
          feasibility: c.feasibility,
          businessImpact: c.businessImpact,
          impactDescription: c.impactDescription,
        })),
        availablePatterns: CHAIN_PATTERNS.map(p => ({ id: p.id, name: p.name, description: p.description })),
      };
    }),
});

// ─── P2-3: Exploit Module Feedback Loop ──────────────────────────────

const feedbackRouter = router({
  /** Record exploit feedback */
  record: protectedProcedure
    .input(z.object({
      moduleName: z.string().min(1),
      moduleSource: z.enum(["metasploit", "exploitdb", "llm_generated", "custom", "nuclei"]),
      targetService: z.string(),
      targetVersion: z.string().nullable().default(null),
      cveIds: z.array(z.string()).default([]),
      success: z.boolean(),
      executionMs: z.number(),
      failureReason: z.string().nullable().default(null),
      errorMessage: z.string().nullable().default(null),
    }))
    .mutation(async ({ input }) => {
      const { recordFeedback } = await import("../lib/exploit-feedback-loop");
      const perf = recordFeedback({
        ...input,
        timestamp: Date.now(),
      });
      return {
        moduleName: perf.moduleName,
        status: perf.status,
        successRate: perf.successRate,
        totalAttempts: perf.totalAttempts,
        trend: perf.trend,
        recommendation: perf.recommendation,
      };
    }),

  /** Get module performance data */
  modulePerformance: protectedProcedure
    .input(z.object({ moduleName: z.string() }))
    .query(async ({ input }) => {
      const { getModulePerformance } = await import("../lib/exploit-feedback-loop");
      return getModulePerformance(input.moduleName);
    }),

  /** Rank modules for a target service */
  rankModules: protectedProcedure
    .input(z.object({ targetService: z.string() }))
    .query(async ({ input }) => {
      const { rankModulesForService } = await import("../lib/exploit-feedback-loop");
      return rankModulesForService(input.targetService);
    }),

  /** Get overall feedback summary */
  summary: protectedProcedure.query(async () => {
    const { getFeedbackSummary } = await import("../lib/exploit-feedback-loop");
    return getFeedbackSummary();
  }),

  /** Get modules needing attention (degraded/retired) */
  needsAttention: protectedProcedure.query(async () => {
    const { getModulesNeedingAttention } = await import("../lib/exploit-feedback-loop");
    return getModulesNeedingAttention();
  }),

  /** Generate LLM improvement prompt for a module */
  improvementPrompt: protectedProcedure
    .input(z.object({ moduleName: z.string() }))
    .query(async ({ input }) => {
      const { generateLlmFeedbackPrompt } = await import("../lib/exploit-feedback-loop");
      const prompt = generateLlmFeedbackPrompt(input.moduleName);
      return { moduleName: input.moduleName, prompt };
    }),
});

// ─── P3-1: LLM Rule Generation ──────────────────────────────────────

const ruleGenRouter = router({
  /** Generate detection rules for a CVE/finding */
  generate: protectedProcedure
    .input(z.object({
      exploitModule: z.string(),
      cveIds: z.array(z.string()),
      targetService: z.string(),
      targetPort: z.number().nullable().default(null),
      attackTechnique: z.string().default(""),
      exploitOutput: z.string().nullable().default(null),
      evidenceArtifacts: z.array(z.string()).default([]),
      severity: z.enum(["critical", "high", "medium", "low"]),
      requestedFormats: z.array(z.enum(["sigma", "yara", "snort", "suricata", "kql", "spl"])).default(["sigma", "yara", "snort"]),
    }))
    .mutation(async ({ input }) => {
      const { generateDetectionRules } = await import("../lib/llm-rule-generator");
      return await generateDetectionRules(input);
    }),

  /** Get all rules for a CVE */
  byCve: protectedProcedure
    .input(z.object({ cveId: z.string() }))
    .query(async ({ input }) => {
      const { getRulesForCve } = await import("../lib/llm-rule-generator");
      return getRulesForCve(input.cveId);
    }),

  /** Get rules by format */
  byFormat: protectedProcedure
    .input(z.object({ format: z.enum(["sigma", "yara", "snort", "suricata", "kql", "spl"]) }))
    .query(async ({ input }) => {
      const { getRulesByFormat } = await import("../lib/llm-rule-generator");
      return getRulesByFormat(input.format);
    }),

  /** Get the full rule library summary */
  library: protectedProcedure.query(async () => {
    const { getRuleLibrary } = await import("../lib/llm-rule-generator");
    return getRuleLibrary();
  }),

  /** Validate a rule (mark as validated/invalidated) */
  validate: protectedProcedure
    .input(z.object({
      ruleId: z.string(),
      validated: z.boolean(),
      notes: z.string().nullable().default(null),
    }))
    .mutation(async ({ input }) => {
      const { validateRule } = await import("../lib/llm-rule-generator");
      const rule = validateRule(input.ruleId, input.validated, input.notes);
      if (!rule) throw new TRPCError({ code: "NOT_FOUND" });
      return rule;
    }),
});

// ─── P3-2: Rule-Evidence Validation ──────────────────────────────────

const ruleEvidenceRouter = router({
  /** Validate a rule against a single evidence artifact */
  validate: protectedProcedure
    .input(z.object({
      ruleId: z.string(),
      evidence: z.object({
        id: z.string(),
        type: z.enum(["console_output", "session_info", "evidence_report", "text_screenshot", "network_capture", "file_artifact"]),
        content: z.string(),
        mimeType: z.string().default("text/plain"),
        capturedAt: z.number(),
        exploitModule: z.string(),
        targetHost: z.string(),
        targetPort: z.number().nullable().default(null),
      }),
    }))
    .mutation(async ({ input }) => {
      const { validateRuleAgainstEvidence } = await import("../lib/rule-evidence-validator");
      const { getRule } = await import("../lib/llm-rule-generator");
      const rule = getRule(input.ruleId);
      if (!rule) throw new TRPCError({ code: "NOT_FOUND", message: "Rule not found" });
      return validateRuleAgainstEvidence(rule, input.evidence);
    }),

  /** Batch validate all rules for a CVE against evidence artifacts */
  batchValidate: protectedProcedure
    .input(z.object({
      cveId: z.string(),
      evidenceArtifacts: z.array(z.object({
        id: z.string(),
        type: z.enum(["console_output", "session_info", "evidence_report", "text_screenshot", "network_capture", "file_artifact"]),
        content: z.string(),
        mimeType: z.string().default("text/plain"),
        capturedAt: z.number(),
        exploitModule: z.string(),
        targetHost: z.string(),
        targetPort: z.number().nullable().default(null),
      })),
    }))
    .mutation(async ({ input }) => {
      const { batchValidateRules } = await import("../lib/rule-evidence-validator");
      const { getRulesForCve } = await import("../lib/llm-rule-generator");
      const rules = getRulesForCve(input.cveId);
      if (rules.length === 0) {
        return {
          totalRules: 0,
          totalEvidence: 0,
          rulesValidated: 0,
          rulesDetected: 0,
          detectionRate: 0,
          averageCoverage: 0,
          byFormat: {},
          results: [],
        };
      }
      return batchValidateRules(rules, input.evidenceArtifacts);
    }),
});

// ─── Combined Accuracy Engine Router ─────────────────────────────────

export const accuracyEngineRouter = router({
  corroboration: corroborationRouter,
  cveMatcher: cveMatcherRouter,
  remediation: remediationRouter,
  controls: controlsRouter,
  preFlight: preFlightRouter,
  probes: probesRouter,
  temporal: temporalRouter,
  attackChains: attackChainRouter,
  feedback: feedbackRouter,
  ruleGen: ruleGenRouter,
  ruleEvidence: ruleEvidenceRouter,
});
