import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { vulnAttackChains, vulnAttackChainSteps, riskRegisterEntries, discoveredAssets, domainIntelScans, engagementFindings } from "../../drizzle/schema";
import { eq, and, or, like, sql, desc, asc, count, inArray } from "drizzle-orm";
import { randomUUID } from "crypto";

const SEV_SCORE: Record<string, number> = { critical: 10, high: 8, moderate: 5, low: 3, informational: 1 };

function computeCompositeScore(steps: { severity: string }[]): { score: number; severity: string } {
  if (steps.length === 0) return { score: 0, severity: "informational" };
  const maxSev = Math.max(...steps.map(s => SEV_SCORE[s.severity] || 1));
  const chainBonus = Math.min(steps.length * 0.5, 3);
  let escalationBonus = 0;
  for (let i = 1; i < steps.length; i++) {
    if ((SEV_SCORE[steps[i].severity] || 1) > (SEV_SCORE[steps[i - 1].severity] || 1)) escalationBonus += 0.5;
  }
  const composite = Math.min(maxSev + chainBonus + escalationBonus, 10);
  const severity = composite >= 9 ? "critical" : composite >= 7 ? "high" : composite >= 4 ? "moderate" : composite >= 2 ? "low" : "informational";
  return { score: Math.round(composite * 10) / 10, severity };
}

async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

export const attackChainsRouter = router({
  list: protectedProcedure
    .input(z.object({
      page: z.number().min(1).default(1),
      pageSize: z.number().min(1).max(100).default(25),
      status: z.string().optional(),
      severity: z.string().optional(),
      search: z.string().optional(),
      sortBy: z.enum(["createdAt", "compositeRiskScore", "compositeSeverity", "name"]).default("compositeRiskScore"),
      sortDir: z.enum(["asc", "desc"]).default("desc"),
    }))
    .query(async ({ input }) => {
      const db = await requireDb();
      const { page, pageSize, status, severity, search, sortBy, sortDir } = input;
      const conditions: any[] = [];
      if (status) conditions.push(eq(vulnAttackChains.status, status as any));
      if (severity) conditions.push(eq(vulnAttackChains.compositeSeverity, severity as any));
      if (search) conditions.push(or(like(vulnAttackChains.name, `%${search}%`), like(vulnAttackChains.chainId, `%${search}%`), like(vulnAttackChains.entryPoint, `%${search}%`)));
      const where = conditions.length > 0 ? and(...conditions) : undefined;
      const sortCol = sortBy === "compositeRiskScore" ? vulnAttackChains.compositeRiskScore : sortBy === "compositeSeverity" ? vulnAttackChains.compositeSeverity : sortBy === "name" ? vulnAttackChains.name : vulnAttackChains.createdAt;
      const orderFn = sortDir === "asc" ? asc : desc;
      const [items, [{ total }]] = await Promise.all([
        db.select().from(vulnAttackChains).where(where).orderBy(orderFn(sortCol)).limit(pageSize).offset((page - 1) * pageSize),
        db.select({ total: count() }).from(vulnAttackChains).where(where),
      ]);
      const chainIds = items.map(i => i.chainId);
      let stepCounts: Record<string, number> = {};
      if (chainIds.length > 0) {
        const counts = await db.select({ chainId: vulnAttackChainSteps.chainId, count: count() }).from(vulnAttackChainSteps).where(inArray(vulnAttackChainSteps.chainId, chainIds)).groupBy(vulnAttackChainSteps.chainId);
        stepCounts = Object.fromEntries(counts.map(c => [c.chainId, c.count]));
      }
      return { items: items.map(i => ({ ...i, stepCount: stepCounts[i.chainId] || 0 })), total, page, pageSize, totalPages: Math.ceil(total / pageSize) };
    }),

  get: protectedProcedure.input(z.object({ id: z.number() })).query(async ({ input }) => {
    const db = await requireDb();
    const [chain] = await db.select().from(vulnAttackChains).where(eq(vulnAttackChains.id, input.id));
    if (!chain) throw new TRPCError({ code: "NOT_FOUND", message: "Attack chain not found" });
    const steps = await db.select().from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, chain.chainId)).orderBy(asc(vulnAttackChainSteps.stepOrder));
    const linkedPoams = await db.select().from(riskRegisterEntries).where(eq(riskRegisterEntries.attackChainId, chain.chainId));
    return { ...chain, steps, linkedPoams };
  }),

  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1), description: z.string().optional(), entryPoint: z.string().optional(), finalTarget: z.string().optional(),
      impactDescription: z.string().optional(), mitreTechniques: z.array(z.string()).optional(), killChainPhases: z.array(z.string()).optional(),
      engagementId: z.number().optional(), sourceType: z.enum(["manual", "auto_correlated", "pentest", "red_team", "ctem"]).default("manual"),
      steps: z.array(z.object({
        title: z.string().min(1), description: z.string().optional(),
        findingType: z.enum(["vulnerability", "misconfiguration", "credential", "exposure", "social_engineering", "privilege_escalation", "lateral_movement", "data_access"]).default("vulnerability"),
        severity: z.enum(["critical", "high", "moderate", "low", "informational"]).default("moderate"),
        cveId: z.string().optional(), cweId: z.string().optional(), affectedAsset: z.string().optional(),
        mitreTechnique: z.string().optional(), mitreTactic: z.string().optional(), evidence: z.string().optional(),
      })),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const chainId = `CHAIN-${randomUUID().split("-")[0].toUpperCase()}`;
      const { score, severity } = computeCompositeScore(input.steps);
      const [result] = await db.insert(vulnAttackChains).values({
        chainId, name: input.name, description: input.description || null, compositeRiskScore: score, compositeSeverity: severity as any,
        entryPoint: input.entryPoint || null, finalTarget: input.finalTarget || null, impactDescription: input.impactDescription || null,
        mitreTechniques: input.mitreTechniques || null, killChainPhases: input.killChainPhases || null,
        engagementId: input.engagementId || null, sourceType: input.sourceType, createdBy: ctx.user.id,
      });
      for (let i = 0; i < input.steps.length; i++) {
        const s = input.steps[i];
        await db.insert(vulnAttackChainSteps).values({
          chainId, stepOrder: i + 1, title: s.title, description: s.description || null, findingType: s.findingType, severity: s.severity,
          cveId: s.cveId || null, cweId: s.cweId || null, affectedAsset: s.affectedAsset || null,
          mitreTechnique: s.mitreTechnique || null, mitreTactic: s.mitreTactic || null, evidence: s.evidence || null,
        });
      }
      return { id: result.insertId, chainId, compositeRiskScore: score, compositeSeverity: severity };
    }),

  update: protectedProcedure
    .input(z.object({
      id: z.number(), name: z.string().optional(), description: z.string().optional(), entryPoint: z.string().optional(),
      finalTarget: z.string().optional(), impactDescription: z.string().optional(),
      status: z.enum(["active", "mitigated", "accepted", "investigating"]).optional(),
      mitreTechniques: z.array(z.string()).optional(), killChainPhases: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { id, ...updates } = input;
      await db.update(vulnAttackChains).set(updates as any).where(eq(vulnAttackChains.id, id));
      return { success: true };
    }),

  addStep: protectedProcedure
    .input(z.object({
      chainId: z.string(), title: z.string().min(1), description: z.string().optional(),
      findingType: z.enum(["vulnerability", "misconfiguration", "credential", "exposure", "social_engineering", "privilege_escalation", "lateral_movement", "data_access"]).default("vulnerability"),
      severity: z.enum(["critical", "high", "moderate", "low", "informational"]).default("moderate"),
      cveId: z.string().optional(), cweId: z.string().optional(), affectedAsset: z.string().optional(),
      mitreTechnique: z.string().optional(), mitreTactic: z.string().optional(), evidence: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const existing = await db.select({ stepOrder: vulnAttackChainSteps.stepOrder }).from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, input.chainId)).orderBy(desc(vulnAttackChainSteps.stepOrder)).limit(1);
      const nextOrder = (existing[0]?.stepOrder || 0) + 1;
      const { chainId, ...stepData } = input;
      await db.insert(vulnAttackChainSteps).values({ chainId, stepOrder: nextOrder, ...stepData, description: stepData.description || null, cveId: stepData.cveId || null, cweId: stepData.cweId || null, affectedAsset: stepData.affectedAsset || null, mitreTechnique: stepData.mitreTechnique || null, mitreTactic: stepData.mitreTactic || null, evidence: stepData.evidence || null });
      const allSteps = await db.select({ severity: vulnAttackChainSteps.severity }).from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, chainId));
      const { score, severity } = computeCompositeScore(allSteps);
      await db.update(vulnAttackChains).set({ compositeRiskScore: score, compositeSeverity: severity as any }).where(eq(vulnAttackChains.chainId, chainId));
      return { stepOrder: nextOrder, compositeRiskScore: score, compositeSeverity: severity };
    }),

  removeStep: protectedProcedure
    .input(z.object({ stepId: z.number(), chainId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.delete(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.id, input.stepId));
      const allSteps = await db.select({ severity: vulnAttackChainSteps.severity }).from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, input.chainId));
      const { score, severity } = computeCompositeScore(allSteps);
      await db.update(vulnAttackChains).set({ compositeRiskScore: score, compositeSeverity: severity as any }).where(eq(vulnAttackChains.chainId, input.chainId));
      return { success: true, compositeRiskScore: score, compositeSeverity: severity };
    }),

  delete: protectedProcedure
    .input(z.object({ id: z.number(), chainId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.delete(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, input.chainId));
      await db.update(riskRegisterEntries).set({ attackChainId: null }).where(eq(riskRegisterEntries.attackChainId, input.chainId));
      await db.delete(vulnAttackChains).where(eq(vulnAttackChains.id, input.id));
      return { success: true };
    }),

  linkPoam: protectedProcedure
    .input(z.object({ chainId: z.string(), poamId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.update(riskRegisterEntries).set({ attackChainId: input.chainId }).where(eq(riskRegisterEntries.id, input.poamId));
      return { success: true };
    }),

  unlinkPoam: protectedProcedure
    .input(z.object({ poamId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      await db.update(riskRegisterEntries).set({ attackChainId: null }).where(eq(riskRegisterEntries.id, input.poamId));
      return { success: true };
    }),

  recalculateScore: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const [chain] = await db.select().from(vulnAttackChains).where(eq(vulnAttackChains.id, input.id));
      if (!chain) throw new TRPCError({ code: "NOT_FOUND" });
      const steps = await db.select().from(vulnAttackChainSteps).where(eq(vulnAttackChainSteps.chainId, chain.chainId)).orderBy(asc(vulnAttackChainSteps.stepOrder));
      const sevMap: Record<string, number> = { critical: 10, high: 8, moderate: 5, low: 3, informational: 1 };
      if (steps.length === 0) {
        await db.update(vulnAttackChains).set({ compositeRiskScore: 0, compositeSeverity: "low" }).where(eq(vulnAttackChains.id, input.id));
        return { compositeRiskScore: 0, compositeSeverity: "low" };
      }
      const maxSev = Math.max(...steps.map(s => sevMap[s.severity] || 0));
      const avgSev = steps.reduce((sum, s) => sum + (sevMap[s.severity] || 0), 0) / steps.length;
      const chainLenBonus = Math.min(steps.length * 0.3, 2);
      const composite = Math.min(10, maxSev * 0.6 + avgSev * 0.25 + chainLenBonus + 0.15);
      const compSev = composite >= 9 ? "critical" : composite >= 7 ? "high" : composite >= 4 ? "moderate" : composite >= 2 ? "low" : "informational";
      await db.update(vulnAttackChains).set({ compositeRiskScore: Math.round(composite * 10) / 10, compositeSeverity: compSev }).where(eq(vulnAttackChains.id, input.id));
      return { compositeRiskScore: Math.round(composite * 10) / 10, compositeSeverity: compSev };
    }),

  autoCorrelate: protectedProcedure
    .input(z.object({
      scanId: z.number().optional(),
      engagementId: z.number().optional(),
      minConfidence: z.number().default(50),
    }))
    .mutation(async ({ input }) => {
      const db = await requireDb();
      const { correlateFindings, CorrelationFinding } = await import("../lib/attack-chain-correlator");

      // Gather findings from DI scan assets and/or engagement findings
      const findings: any[] = [];

      if (input.scanId) {
        const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
        for (const a of assets) {
          const postureFindings = (a.postureFindings as any[]) || [];
          if (postureFindings.length > 0) {
            for (const pf of postureFindings) {
              findings.push({
                id: a.id * 10000 + (pf.id || Math.random() * 1000 | 0),
                title: pf.title || pf.finding || `Finding on ${a.hostname}`,
                severity: pf.severity || "medium",
                hostname: a.hostname,
                cve: pf.cve || null,
                cwe: pf.cwe || null,
                mitreTechnique: pf.mitreTechnique || null,
                port: pf.port || null,
                source: "di_scan",
                tool: pf.tool || "passive_recon",
                description: pf.description || pf.detail || null,
                technologies: a.technologies,
                hybridRiskScore: a.hybridRiskScore,
                assetType: a.assetType,
              });
            }
          } else {
            // Create a synthetic finding from the asset itself if it has risk
            if (a.hybridRiskScore && a.hybridRiskScore > 30) {
              findings.push({
                id: a.id,
                title: `Elevated Risk Asset: ${a.hostname}`,
                severity: a.riskBand === "critical" ? "critical" : a.riskBand === "high" ? "high" : "medium",
                hostname: a.hostname,
                source: "di_scan",
                tool: "risk_scoring",
                description: `Asset ${a.hostname} has hybrid risk score of ${a.hybridRiskScore}`,
                technologies: a.technologies,
                hybridRiskScore: a.hybridRiskScore,
                assetType: a.assetType,
              });
            }
          }
        }
      }

      if (input.engagementId) {
        const engFindings = await db.select().from(engagementFindings)
          .where(eq(engagementFindings.engagementId, input.engagementId));
        for (const ef of engFindings) {
          findings.push({
            id: ef.id,
            title: ef.title,
            severity: ef.severity,
            hostname: ef.hostname || "unknown",
            cve: ef.cve,
            cwe: ef.cwe,
            mitreTechnique: ef.mitreTechnique,
            port: ef.port,
            source: ef.source,
            tool: ef.tool,
            description: ef.description,
            endpoint: ef.endpoint,
          });
        }
      }

      if (findings.length < 2) {
        return { chainsCreated: 0, totalFindings: findings.length, message: "Not enough findings to correlate (need at least 2)" };
      }

      // Run correlation engine
      const correlatedChains = correlateFindings(findings).filter(c => c.confidence >= input.minConfidence);

      // Persist correlated chains to database
      let chainsCreated = 0;
      for (const cc of correlatedChains) {
        const chainId = `AC-${Date.now()}-${randomUUID().slice(0, 8)}`;
        const [inserted] = await db.insert(vulnAttackChains).values({
          chainId,
          name: cc.name,
          description: cc.description,
          entryPoint: cc.entryPoint,
          finalTarget: cc.finalTarget,
          mitreTactics: JSON.stringify(cc.mitreTactics),
          compositeRiskScore: Math.round(cc.compositeRiskScore * 10) / 10,
          compositeSeverity: cc.compositeSeverity as any,
          status: "active",
          discoveredBy: "auto_correlator",
          metadata: JSON.stringify({ correlationSignals: cc.correlationSignals, confidence: cc.confidence, sourceType: input.scanId ? "di_scan" : "engagement", sourceId: input.scanId || input.engagementId }),
        }).$returningId();

        // Insert steps
        for (const step of cc.steps) {
          await db.insert(vulnAttackChainSteps).values({
            chainId,
            stepOrder: step.stepOrder,
            title: step.title,
            description: step.description,
            severity: step.severity as any,
            cveId: step.cveId || null,
            cweId: step.cweId || null,
            affectedAsset: step.affectedAsset,
            mitreTechnique: step.mitreTechnique || null,
            mitreTactic: step.mitreTactic || null,
            findingType: step.findingType as any,
          });
        }
        chainsCreated++;
      }

      return {
        chainsCreated,
        totalFindings: findings.length,
        chainsDetected: correlatedChains.length,
        chains: correlatedChains.map(c => ({ name: c.name, steps: c.steps.length, confidence: c.confidence, compositeRiskScore: Math.round(c.compositeRiskScore * 10) / 10, compositeSeverity: c.compositeSeverity })),
      };
    }),

  // End-to-end pipeline: DI scan → auto-correlate → risk register → export
  e2ePipeline: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      engagementId: z.number().optional(),
      autoPopulateRiskRegister: z.boolean().default(true),
      minConfidence: z.number().default(50),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await requireDb();
      const { correlateFindings } = await import("../lib/attack-chain-correlator");

      // Step 1: Verify scan exists
      const [scan] = await db.select().from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId));
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "DI scan not found" });

      // Step 2: Gather all findings
      const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
      const findings: any[] = [];
      for (const a of assets) {
        const postureFindings = (a.postureFindings as any[]) || [];
        for (const pf of postureFindings) {
          findings.push({
            id: a.id * 10000 + (pf.id || Math.random() * 1000 | 0),
            title: pf.title || pf.finding || `Finding on ${a.hostname}`,
            severity: pf.severity || "medium",
            hostname: a.hostname,
            cve: pf.cve || null, cwe: pf.cwe || null,
            mitreTechnique: pf.mitreTechnique || null,
            port: pf.port || null,
            source: "di_scan", tool: pf.tool || "passive_recon",
            description: pf.description || pf.detail || null,
          });
        }
        if (postureFindings.length === 0 && a.hybridRiskScore && a.hybridRiskScore > 30) {
          findings.push({
            id: a.id, title: `Elevated Risk: ${a.hostname}`,
            severity: a.riskBand === "critical" ? "critical" : a.riskBand === "high" ? "high" : "medium",
            hostname: a.hostname, source: "di_scan", tool: "risk_scoring",
            description: `Hybrid risk score: ${a.hybridRiskScore}`,
          });
        }
      }

      if (input.engagementId) {
        const engFindings = await db.select().from(engagementFindings)
          .where(eq(engagementFindings.engagementId, input.engagementId));
        for (const ef of engFindings) {
          findings.push({
            id: ef.id, title: ef.title, severity: ef.severity,
            hostname: ef.hostname || "unknown", cve: ef.cve, cwe: ef.cwe,
            mitreTechnique: ef.mitreTechnique, port: ef.port,
            source: ef.source, tool: ef.tool, description: ef.description,
          });
        }
      }

      // Step 3: Run auto-correlation
      const correlatedChains = correlateFindings(findings).filter(c => c.confidence >= input.minConfidence);

      // Step 4: Persist chains
      let chainsCreated = 0;
      const chainIds: string[] = [];
      for (const cc of correlatedChains) {
        const chainId = `AC-${Date.now()}-${randomUUID().slice(0, 8)}`;
        chainIds.push(chainId);
        await db.insert(vulnAttackChains).values({
          chainId, name: cc.name, description: cc.description,
          entryPoint: cc.entryPoint, finalTarget: cc.finalTarget,
          mitreTactics: JSON.stringify(cc.mitreTactics),
          compositeRiskScore: Math.round(cc.compositeRiskScore * 10) / 10,
          compositeSeverity: cc.compositeSeverity as any,
          status: "active", discoveredBy: "e2e_pipeline",
          metadata: JSON.stringify({ scanId: input.scanId, scanDomain: scan.primaryDomain, confidence: cc.confidence, correlationSignals: cc.correlationSignals }),
        });
        for (const step of cc.steps) {
          await db.insert(vulnAttackChainSteps).values({
            chainId, stepOrder: step.stepOrder, title: step.title,
            description: step.description, severity: step.severity as any,
            cveId: step.cveId || null, cweId: step.cweId || null,
            affectedAsset: step.affectedAsset, mitreTechnique: step.mitreTechnique || null,
            mitreTactic: step.mitreTactic || null, findingType: step.findingType as any,
          });
        }
        chainsCreated++;
      }

      // Step 5: Auto-populate risk register
      let poamEntriesCreated = 0;
      if (input.autoPopulateRiskRegister) {
        for (const cc of correlatedChains) {
          const poamId = `POAM-${Date.now()}-${randomUUID().slice(0, 6)}`;
          await db.insert(riskRegisterEntries).values({
            poamId,
            weaknessName: cc.name,
            weaknessDescription: cc.description,
            severity: (cc.compositeSeverity === "moderate" ? "medium" : cc.compositeSeverity) as any,
            status: "open",
            source: "auto_correlation",
            sourceRef: `scan:${input.scanId}`,
            detectedDate: new Date().toISOString().slice(0, 19).replace("T", " "),
            affectedAssets: cc.entryPoint,
            controlId: null,
            scheduledCompletionDate: new Date(Date.now() + (cc.compositeSeverity === "critical" ? 15 : cc.compositeSeverity === "high" ? 30 : 90) * 86400000).toISOString().slice(0, 19).replace("T", " "),
            mitigationPlan: `Remediate ${cc.steps.length}-step attack chain: ${cc.steps.map(s => s.title).join(" → ")}`,
            riskDecision: "pending",
            createdBy: ctx.user?.id || null,
          });
          poamEntriesCreated++;
        }
      }

      return {
        scanDomain: scan.primaryDomain,
        totalAssets: assets.length,
        totalFindings: findings.length,
        chainsDetected: correlatedChains.length,
        chainsCreated,
        poamEntriesCreated,
        chains: correlatedChains.map(c => ({
          name: c.name, steps: c.steps.length, confidence: c.confidence,
          compositeRiskScore: Math.round(c.compositeRiskScore * 10) / 10,
          compositeSeverity: c.compositeSeverity,
          correlationSignals: c.correlationSignals,
        })),
      };
    }),

  // List available DI scans for correlation
  availableScans: protectedProcedure.query(async () => {
    const db = await requireDb();
    const scans = await db.select({
      id: domainIntelScans.id,
      primaryDomain: domainIntelScans.primaryDomain,
      status: domainIntelScans.status,
      totalAssets: domainIntelScans.totalAssets,
      totalFindings: domainIntelScans.totalFindings,
      createdAt: domainIntelScans.createdAt,
    }).from(domainIntelScans)
      .where(eq(domainIntelScans.status, "completed"))
      .orderBy(desc(domainIntelScans.createdAt))
      .limit(50);
    return scans;
  }),

  summary: protectedProcedure.query(async () => {
    const db = await requireDb();
    const allChains = await db.select().from(vulnAttackChains);
    const active = allChains.filter(c => c.status === "active");
    const bySeverity = ["critical", "high", "moderate", "low", "informational"].map(sev => ({ severity: sev, count: active.filter(c => c.compositeSeverity === sev).length }));
    const topChains = active.sort((a, b) => (b.compositeRiskScore || 0) - (a.compositeRiskScore || 0)).slice(0, 5);
    return {
      totalActive: active.length, totalMitigated: allChains.filter(c => c.status === "mitigated").length, bySeverity,
      topChains: topChains.map(c => ({ id: c.id, chainId: c.chainId, name: c.name, compositeRiskScore: c.compositeRiskScore, compositeSeverity: c.compositeSeverity, entryPoint: c.entryPoint, finalTarget: c.finalTarget })),
    };
  }),
});
