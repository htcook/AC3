/**
 * SSIL (Service Scanner Integration Layer) Router
 *
 * Exposes three SSIL capabilities via tRPC:
 * 1. Scan Policy Engine — profile management, policy evaluation, violation log
 * 2. LLM Guardrails — configuration, stats, violation history
 * 3. Observation Normalizer — ingest, query, signal derivation, risk cards
 *
 * Author: Harrison Cook — AceofCloud
 */

import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb, getDbRequired } from "../db";
import {
  scanObservations,
  scanSignals,
  scanRiskCards,
  scanPolicies,
  guardrailViolations,
} from "../../drizzle/schema";
import { desc, eq, sql, and, gte, lte } from "drizzle-orm";
import { getScanPolicyEngine, type ScanMode, type ScannerName } from "../lib/scan-policy-engine";
import { getLLMGuardrails, type GuardrailContext } from "../lib/llm-guardrails";
import {
  adaptNmapResults,
  adaptNucleiResults,
  adaptZgrab2Results,
  adaptWebCrawlerResults,
  adaptDomainIntelResults,
  adaptVulnScanResults,
  deriveSignals,
  generateRiskCards,
  observationToInsert,
  type NmapRawResult,
  type NucleiRawResult,
  type Zgrab2RawResult,
  type WebCrawlerRawResult,
  type DomainIntelRawResult,
  type VulnScanRawResult,
} from "../lib/observation-normalizer";

// Admin-only procedure
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== "admin") {
    throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
  }
  return next({ ctx });
});

export const ssilRouter = router({
  // ═══════════════════════════════════════════════════════════════════════
  // §1 — SCAN POLICY ENGINE
  // ═══════════════════════════════════════════════════════════════════════

  /** Get the active scan policy profile */
  getActivePolicy: protectedProcedure.query(() => {
    const engine = getScanPolicyEngine();
    return {
      activeProfileId: engine.getActiveProfileId(),
      profile: engine.getActiveProfile(),
      attestation: engine.getAttestation(),
    };
  }),

  /** List all available scan policy profiles */
  listPolicies: protectedProcedure.query(() => {
    const engine = getScanPolicyEngine();
    return engine.listProfiles();
  }),

  /** Set the active scan policy profile */
  setActivePolicy: adminProcedure
    .input(z.object({ profileId: z.string() }))
    .mutation(({ input }) => {
      const engine = getScanPolicyEngine();
      engine.setActiveProfile(input.profileId);
      return {
        success: true,
        activeProfileId: engine.getActiveProfileId(),
        attestation: engine.getAttestation(),
      };
    }),

  /** Evaluate whether a scan request is permitted */
  evaluateScanRequest: protectedProcedure
    .input(
      z.object({
        scanner: z.string(),
        mode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]),
        host: z.string(),
        port: z.number().int().min(0).max(65535),
        protocol: z.string().optional(),
        templateTags: z.array(z.string()).optional(),
        httpMethod: z.string().optional(),
        hasBody: z.boolean().optional(),
      })
    )
    .query(({ input }) => {
      const engine = getScanPolicyEngine();
      return engine.canExecute({
        scanner: input.scanner as ScannerName,
        mode: input.mode as ScanMode,
        asset: {
          host: input.host,
          port: input.port,
          protocol: input.protocol,
        },
        templateTags: input.templateTags,
        httpMethod: input.httpMethod,
        hasBody: input.hasBody,
      });
    }),

  /** Get escalation rules */
  getEscalationRules: protectedProcedure.query(() => {
    const engine = getScanPolicyEngine();
    return engine.getEscalationRules();
  }),

  /** Get policy violation log */
  getPolicyViolations: protectedProcedure
    .input(z.object({ limit: z.number().int().min(1).max(200).default(50) }).optional())
    .query(({ input }) => {
      const engine = getScanPolicyEngine();
      return engine.getViolations(input?.limit || 50);
    }),

  /** Get rate limiter stats */
  getRateLimiterStats: protectedProcedure.query(() => {
    const engine = getScanPolicyEngine();
    return engine.getRateLimiterStats();
  }),

  /** Get full policy engine state (for dashboard) */
  getPolicyEngineState: protectedProcedure.query(() => {
    const engine = getScanPolicyEngine();
    return engine.toJSON();
  }),

  // ═══════════════════════════════════════════════════════════════════════
  // §2 — LLM GUARDRAILS
  // ═══════════════════════════════════════════════════════════════════════

  /** Get LLM guardrails configuration and stats */
  getGuardrailsStatus: protectedProcedure.query(() => {
    const guardrails = getLLMGuardrails();
    return guardrails.toJSON();
  }),

  /** Set LLM guardrails context */
  setGuardrailContext: adminProcedure
    .input(
      z.object({
        context: z.enum(["analyst", "risk_card", "caldera_hooks", "detection", "phishing", "report", "general"]),
      })
    )
    .mutation(({ input }) => {
      const guardrails = getLLMGuardrails();
      guardrails.setContext(input.context as GuardrailContext);
      return { success: true, config: guardrails.getConfig() };
    }),

  /** Toggle LLM guardrails enabled/disabled */
  toggleGuardrails: adminProcedure
    .input(z.object({ enabled: z.boolean() }))
    .mutation(({ input }) => {
      const guardrails = getLLMGuardrails();
      guardrails.setEnabled(input.enabled);
      return { success: true, enabled: input.enabled };
    }),

  /** Toggle strict passive mode for LLM guardrails */
  toggleStrictPassiveMode: adminProcedure
    .input(z.object({ enabled: z.boolean() }))
    .mutation(({ input }) => {
      const guardrails = getLLMGuardrails();
      guardrails.setStrictPassiveMode(input.enabled);
      return { success: true, strictPassiveMode: input.enabled };
    }),

  /** Get guardrail violation history */
  getGuardrailViolations: protectedProcedure
    .input(z.object({ limit: z.number().int().min(1).max(200).default(50) }).optional())
    .query(({ input }) => {
      const guardrails = getLLMGuardrails();
      return guardrails.getViolations(input?.limit || 50);
    }),

  /** Get guardrail violations from database */
  getPersistedGuardrailViolations: protectedProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(200).default(50),
        action: z.enum(["blocked", "sanitized", "warned"]).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      const limit = input?.limit || 50;
      return db.select().from(guardrailViolations).orderBy(desc(guardrailViolations.id)).limit(limit);
    }),

  // ═══════════════════════════════════════════════════════════════════════
  // §3 — OBSERVATION NORMALIZER
  // ═══════════════════════════════════════════════════════════════════════

  /** Ingest raw scanner results and normalize them */
  ingestObservations: adminProcedure
    .input(
      z.object({
        scanner: z.enum(["nmap", "nuclei", "zgrab2", "web_crawler", "domain_intel", "vuln_scanner"]),
        rawResults: z.array(z.any()),
      })
    )
    .mutation(async ({ input }) => {
      let adapterResult;

      switch (input.scanner) {
        case "nmap":
          adapterResult = adaptNmapResults(input.rawResults as NmapRawResult[]);
          break;
        case "nuclei":
          adapterResult = adaptNucleiResults(input.rawResults as NucleiRawResult[]);
          break;
        case "zgrab2":
          adapterResult = adaptZgrab2Results(input.rawResults as Zgrab2RawResult[]);
          break;
        case "web_crawler":
          adapterResult = adaptWebCrawlerResults(input.rawResults as WebCrawlerRawResult[]);
          break;
        case "domain_intel":
          adapterResult = adaptDomainIntelResults(input.rawResults as DomainIntelRawResult[]);
          break;
        case "vuln_scanner":
          adapterResult = adaptVulnScanResults(input.rawResults as VulnScanRawResult[]);
          break;
        default:
          throw new TRPCError({ code: "BAD_REQUEST", message: `Unknown scanner: ${input.scanner}` });
      }

      // Store observations in database
      const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });
      let stored = 0;
      for (const obs of adapterResult.observations) {
        try {
          const insert = observationToInsert(obs);
          await db.insert(scanObservations).values(insert).onDuplicateKeyUpdate({
            set: {
              severity: insert.severity,
              confidence: insert.confidence,
              evidenceSummary: insert.evidenceSummary,
              ingestedAt: Date.now(),
            },
          });
          stored++;
        } catch (err: any) {
          adapterResult.metrics.errors.push(`DB insert error: ${err.message}`);
        }
      }

      // Derive signals
      const signals = deriveSignals(adapterResult.observations);
      let signalsStored = 0;
      for (const signal of signals) {
        try {
          await db.insert(scanSignals).values(signal).onDuplicateKeyUpdate({
            set: {
              confidence: signal.confidence,
              rationale: signal.rationale,
              createdAt: Date.now(),
            },
          });
          signalsStored++;
        } catch (err: any) {
          adapterResult.metrics.errors.push(`Signal insert error: ${err.message}`);
        }
      }

      // Generate risk cards
      const riskCards = generateRiskCards(signals);
      let cardsStored = 0;
      for (const card of riskCards) {
        try {
          await db.insert(scanRiskCards).values(card).onDuplicateKeyUpdate({
            set: {
              finalScore: card.finalScore,
              summary: card.summary,
              createdAt: Date.now(),
            },
          });
          cardsStored++;
        } catch (err: any) {
          adapterResult.metrics.errors.push(`Risk card insert error: ${err.message}`);
        }
      }

      return {
        observationsIngested: stored,
        signalsDerived: signalsStored,
        riskCardsGenerated: cardsStored,
        metrics: adapterResult.metrics,
      };
    }),

  /** List observations with filtering */
  listObservations: protectedProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(500).default(50),
        offset: z.number().int().min(0).default(0),
        scannerName: z.string().optional(),
        observationType: z.string().optional(),
        severity: z.string().optional(),
        assetHost: z.string().optional(),
        minConfidence: z.number().min(0).max(1).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });
      const limit = input?.limit || 50;
      const offset = input?.offset || 0;

      const conditions = [];
      if (input?.scannerName) conditions.push(eq(scanObservations.scannerName, input.scannerName));
      if (input?.observationType) conditions.push(eq(scanObservations.observationType, input.observationType as any));
      if (input?.severity) conditions.push(eq(scanObservations.severity, input.severity as any));
      if (input?.assetHost) conditions.push(eq(scanObservations.assetHost, input.assetHost));
      if (input?.minConfidence) conditions.push(gte(scanObservations.confidence, input.minConfidence));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [observations, countResult] = await Promise.all([
        db.select().from(scanObservations).where(where).orderBy(desc(scanObservations.id)).limit(limit).offset(offset),
        db.select({ count: sql<number>`count(*)` }).from(scanObservations).where(where),
      ]);

      return {
        observations,
        total: countResult[0]?.count || 0,
        limit,
        offset,
      };
    }),

  /** Get observation by ID */
  getObservation: protectedProcedure
    .input(z.object({ observationId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });
      const [obs] = await db.select().from(scanObservations).where(eq(scanObservations.observationId, input.observationId));
      if (!obs) throw new TRPCError({ code: "NOT_FOUND", message: "Observation not found" });
      return obs;
    }),

  /** List signals */
  listSignals: protectedProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(200).default(50),
        assetId: z.string().optional(),
        signalType: z.string().optional(),
        category: z.string().optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });
      const limit = input?.limit || 50;

      const conditions = [];
      if (input?.assetId) conditions.push(eq(scanSignals.assetId, input.assetId));
      if (input?.signalType) conditions.push(eq(scanSignals.signalType, input.signalType as any));
      if (input?.category) conditions.push(eq(scanSignals.category, input.category));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      return db.select().from(scanSignals).where(where).orderBy(desc(scanSignals.id)).limit(limit);
    }),

  /** List risk cards */
  listRiskCards: protectedProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(200).default(50),
        assetId: z.string().optional(),
        minScore: z.number().min(0).max(10).optional(),
      }).optional()
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });
      const limit = input?.limit || 50;

      const conditions = [];
      if (input?.assetId) conditions.push(eq(scanRiskCards.assetId, input.assetId));
      if (input?.minScore) conditions.push(gte(scanRiskCards.finalScore, input.minScore));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      return db.select().from(scanRiskCards).where(where).orderBy(desc(scanRiskCards.finalScore)).limit(limit);
    }),

  /** Get observation statistics for dashboard */
  getObservationStats: protectedProcedure.query(async () => {
    const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });

    const [totalObs] = await db.select({ count: sql<number>`count(*)` }).from(scanObservations);
    const [totalSignals] = await db.select({ count: sql<number>`count(*)` }).from(scanSignals);
    const [totalCards] = await db.select({ count: sql<number>`count(*)` }).from(scanRiskCards);

    // Severity distribution
    const severityDist = await db
      .select({
        severity: scanObservations.severity,
        count: sql<number>`count(*)`,
      })
      .from(scanObservations)
      .groupBy(scanObservations.severity);

    // Scanner distribution
    const scannerDist = await db
      .select({
        scanner: scanObservations.scannerName,
        count: sql<number>`count(*)`,
      })
      .from(scanObservations)
      .groupBy(scanObservations.scannerName);

    // Type distribution
    const typeDist = await db
      .select({
        type: scanObservations.observationType,
        count: sql<number>`count(*)`,
      })
      .from(scanObservations)
      .groupBy(scanObservations.observationType);

    return {
      totalObservations: totalObs?.count || 0,
      totalSignals: totalSignals?.count || 0,
      totalRiskCards: totalCards?.count || 0,
      severityDistribution: severityDist,
      scannerDistribution: scannerDist,
      typeDistribution: typeDist,
    };
  }),

  /** Get SSIL dashboard summary (combines all three features) */
  getDashboardSummary: protectedProcedure.query(async () => {
    const engine = getScanPolicyEngine();
    const guardrails = getLLMGuardrails();
    const db = await getDb();
      if (!db) throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Database unavailable' });

    const [obsCount] = await db.select({ count: sql<number>`count(*)` }).from(scanObservations);
    const [sigCount] = await db.select({ count: sql<number>`count(*)` }).from(scanSignals);
    const [cardCount] = await db.select({ count: sql<number>`count(*)` }).from(scanRiskCards);

    return {
      policy: {
        activeProfile: engine.getActiveProfileId(),
        attestation: engine.getAttestation(),
        violationCount: engine.getViolationCount(),
        rateLimiterStats: engine.getRateLimiterStats(),
      },
      guardrails: guardrails.toJSON(),
      observations: {
        total: obsCount?.count || 0,
        signals: sigCount?.count || 0,
        riskCards: cardCount?.count || 0,
      },
    };
  }),
});
