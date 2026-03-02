import { notifyOwner } from "../_core/notification";
import * as db from "../db";
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
import { protectedProcedure, router, adminProcedure} from "../_core/trpc";
import { getDb, getDbRequired } from "../db";
import {
  scanObservations,
  scanSignals,
  scanRiskCards,
  scanPolicies,
  guardrailViolations,
  observationAlertRules,
  observationAlertHistory,
} from "../../drizzle/schema";
import { getAlertRulesEngine, DEFAULT_ALERT_RULES, type AlertRuleConditions, type AlertTriggerType } from "../lib/alert-rules-engine";
import { getCorrelationEngine, type ObservationRow, type SignalRow, type RiskCardRow } from "../lib/correlation-engine";
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

  // ─── Real-Time Streaming ─────────────────────────────────────────────────

  /** Poll for recent ingestion events (long-polling style) */
  streamEvents: protectedProcedure
    .input(z.object({
      since: z.number().optional(),
      limit: z.number().min(1).max(100).default(50),
    }))
    .query(async ({ input }) => {
      const { getRecentEvents, getIngestionStats } = await import("../lib/observation-ingestor");
      const events = getRecentEvents(input.since, input.limit);
      const stats = getIngestionStats();
      return { events, stats, serverTime: Date.now() };
    }),

  /** Get ingestion stats per scanner */
  ingestionStats: protectedProcedure.query(async () => {
    const { getIngestionStats } = await import("../lib/observation-ingestor");
    return getIngestionStats();
  }),

  /** Get recent observations with pagination for live view */
  liveObservations: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(25),
      cursor: z.number().optional(),
      scanner: z.string().optional(),
      severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const conditions = [];
      if (input.cursor) conditions.push(lte(scanObservations.id, input.cursor));
      if (input.scanner) conditions.push(eq(scanObservations.scannerName, input.scanner));
      if (input.severity) conditions.push(eq(scanObservations.severity, input.severity));

      const rows = await db.select()
        .from(scanObservations)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(scanObservations.id))
        .limit(input.limit + 1);

      const hasMore = rows.length > input.limit;
      const items = hasMore ? rows.slice(0, input.limit) : rows;
      const nextCursor = hasMore ? items[items.length - 1]?.id : undefined;

      return { items, nextCursor, hasMore };
    }),

  /** Get risk cards with full details for drill-down */
  getRiskCard: protectedProcedure
    .input(z.object({ riskId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [card] = await db.select().from(scanRiskCards).where(eq(scanRiskCards.riskId, input.riskId));
      if (!card) throw new TRPCError({ code: "NOT_FOUND", message: "Risk card not found" });

      // Fetch contributing signals
      const signalIds = (card as any).signalIds as string[] | null;
      let signals: any[] = [];
      if (signalIds && signalIds.length > 0) {
        const { inArray } = await import("drizzle-orm");
        signals = await db.select().from(scanSignals).where(inArray(scanSignals.signalId, signalIds));
      } else {
        // Fallback: fetch signals by assetId
        signals = await db.select().from(scanSignals).where(eq(scanSignals.assetId, card.assetId));
      }

      // Fetch related observations
      const observationIds = signals.flatMap((s: any) => (s.sourceObservations as string[]) || []);
      let observations: any[] = [];
      if (observationIds.length > 0) {
        const { inArray } = await import("drizzle-orm");
        const uniqueIds = [...new Set(observationIds)];
        observations = await db.select().from(scanObservations).where(inArray(scanObservations.observationId, uniqueIds));
      }

      return { card, signals, observations };
    }),

  /** List all risk cards with pagination */
  listRiskCardsPaginated: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(25),
      offset: z.number().default(0),
      minScore: z.number().optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const conditions = [];
      if (input.minScore !== undefined) conditions.push(gte(scanRiskCards.finalScore, input.minScore));

      const [countResult] = await db.select({ count: sql<number>`count(*)` })
        .from(scanRiskCards)
        .where(conditions.length ? and(...conditions) : undefined);

      const cards = await db.select()
        .from(scanRiskCards)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(scanRiskCards.finalScore))
        .limit(input.limit)
        .offset(input.offset);

      return { cards, total: countResult?.count || 0 };
    }),

  /** Get signals for a specific asset */
  getAssetSignals: protectedProcedure
    .input(z.object({ assetId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      return db.select().from(scanSignals).where(eq(scanSignals.assetId, input.assetId));
    }),

  // ─── Alert Rules CRUD ────────────────────────────────────────────────

  /** List all alert rules */
  listAlertRules: protectedProcedure.query(async () => {
    const db = await getDbRequired();
    const rules = await db.select().from(observationAlertRules).orderBy(desc(observationAlertRules.createdAt));
    return rules;
  }),

  /** Create a new alert rule */
  createAlertRule: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      description: z.string().optional(),
      triggerType: z.enum(["critical_cve", "new_open_port", "high_severity_signal", "risk_score_threshold", "observation_count", "new_vulnerability", "tls_expiry", "misconfiguration", "custom"]),
      conditions: z.record(z.unknown()),
      notifyOwner: z.boolean().default(true),
      cooldownMinutes: z.number().min(1).default(60),
      isEnabled: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const ruleId = `rule-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
      const now = Date.now();
      await db.insert(observationAlertRules).values({
        ruleId,
        name: input.name,
        description: input.description || null,
        isEnabled: input.isEnabled,
        triggerType: input.triggerType,
        conditions: input.conditions,
        notifyOwner: input.notifyOwner,
        cooldownMinutes: input.cooldownMinutes,
        createdBy: ctx.user?.name || ctx.user?.openId || "system",
        createdAt: now,
        updatedAt: now,
      });
      // Sync to in-memory engine
      const engine = getAlertRulesEngine();
      engine.addRule({
        ruleId,
        name: input.name,
        description: input.description,
        isEnabled: input.isEnabled,
        triggerType: input.triggerType as AlertTriggerType,
        conditions: input.conditions as AlertRuleConditions,
        notifyOwner: input.notifyOwner,
        cooldownMinutes: input.cooldownMinutes,
        triggerCount: 0,
      });
      return { ruleId };
    }),

  /** Update an alert rule */
  updateAlertRule: protectedProcedure
    .input(z.object({
      ruleId: z.string(),
      name: z.string().min(1).max(255).optional(),
      description: z.string().optional(),
      isEnabled: z.boolean().optional(),
      conditions: z.record(z.unknown()).optional(),
      notifyOwner: z.boolean().optional(),
      cooldownMinutes: z.number().min(1).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const updates: Record<string, unknown> = { updatedAt: Date.now() };
      if (input.name !== undefined) updates.name = input.name;
      if (input.description !== undefined) updates.description = input.description;
      if (input.isEnabled !== undefined) updates.isEnabled = input.isEnabled;
      if (input.conditions !== undefined) updates.conditions = input.conditions;
      if (input.notifyOwner !== undefined) updates.notifyOwner = input.notifyOwner;
      if (input.cooldownMinutes !== undefined) updates.cooldownMinutes = input.cooldownMinutes;
      await db.update(observationAlertRules).set(updates as any).where(eq(observationAlertRules.ruleId, input.ruleId));
      // Sync to in-memory engine
      const engine = getAlertRulesEngine();
      const existing = engine.getRule(input.ruleId);
      if (existing) {
        if (input.name !== undefined) existing.name = input.name;
        if (input.description !== undefined) existing.description = input.description;
        if (input.isEnabled !== undefined) existing.isEnabled = input.isEnabled;
        if (input.conditions !== undefined) existing.conditions = input.conditions as AlertRuleConditions;
        if (input.notifyOwner !== undefined) existing.notifyOwner = input.notifyOwner;
        if (input.cooldownMinutes !== undefined) existing.cooldownMinutes = input.cooldownMinutes;
      }
      return { success: true };
    }),

  /** Delete an alert rule */
  deleteAlertRule: protectedProcedure
    .input(z.object({ ruleId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(observationAlertRules).where(eq(observationAlertRules.ruleId, input.ruleId));
      getAlertRulesEngine().removeRule(input.ruleId);
      return { success: true };
    }),

  /** Toggle alert rule enabled/disabled */
  toggleAlertRule: protectedProcedure
    .input(z.object({ ruleId: z.string(), isEnabled: z.boolean() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.update(observationAlertRules).set({ isEnabled: input.isEnabled, updatedAt: Date.now() } as any).where(eq(observationAlertRules.ruleId, input.ruleId));
      const engine = getAlertRulesEngine();
      if (input.isEnabled) engine.enableRule(input.ruleId);
      else engine.disableRule(input.ruleId);
      return { success: true };
    }),

  /** Seed default alert rules */
  seedDefaultAlertRules: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbRequired();
    const now = Date.now();
    let seeded = 0;
    for (const preset of DEFAULT_ALERT_RULES) {
      const existing = await db.select().from(observationAlertRules).where(eq(observationAlertRules.ruleId, preset.ruleId)).limit(1);
      if (existing.length === 0) {
        await db.insert(observationAlertRules).values({
          ruleId: preset.ruleId,
          name: preset.name,
          description: preset.description || null,
          isEnabled: preset.isEnabled,
          triggerType: preset.triggerType,
          conditions: preset.conditions as Record<string, unknown>,
          notifyOwner: preset.notifyOwner,
          cooldownMinutes: preset.cooldownMinutes,
          createdBy: ctx.user?.name || "system",
          createdAt: now,
          updatedAt: now,
        });
        seeded++;
      }
    }
    return { seeded, total: DEFAULT_ALERT_RULES.length };
  }),

  /** Get alert history */
  getAlertHistory: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
      severity: z.enum(["info", "low", "medium", "high", "critical"]).optional(),
      ruleId: z.string().optional(),
      acknowledged: z.boolean().optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const conditions = [];
      if (input.severity) conditions.push(eq(observationAlertHistory.severity, input.severity));
      if (input.ruleId) conditions.push(eq(observationAlertHistory.ruleId, input.ruleId));
      if (input.acknowledged === true) conditions.push(sql`${observationAlertHistory.acknowledgedAt} IS NOT NULL`);
      if (input.acknowledged === false) conditions.push(sql`${observationAlertHistory.acknowledgedAt} IS NULL`);

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
      const [alerts, countResult] = await Promise.all([
        db.select().from(observationAlertHistory).where(whereClause).orderBy(desc(observationAlertHistory.triggeredAt)).limit(input.limit).offset(input.offset),
        db.select({ count: sql<number>`count(*)` }).from(observationAlertHistory).where(whereClause).then(r => r[0]),
      ]);
      return { alerts, total: countResult?.count || 0 };
    }),

  /** Acknowledge an alert */
  acknowledgeAlert: protectedProcedure
    .input(z.object({ alertId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      await db.update(observationAlertHistory).set({
        acknowledgedAt: Date.now(),
        acknowledgedBy: ctx.user?.name || ctx.user?.openId || "system",
      } as any).where(eq(observationAlertHistory.alertId, input.alertId));
      return { success: true };
    }),

  /** Dismiss an alert */
  dismissAlert: protectedProcedure
    .input(z.object({ alertId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.update(observationAlertHistory).set({
        dismissedAt: Date.now(),
      } as any).where(eq(observationAlertHistory.alertId, input.alertId));
      return { success: true };
    }),

  /** Get alert engine stats */
  getAlertStats: protectedProcedure.query(async () => {
    const db = await getDbRequired();
    const [totalRules] = await db.select({ count: sql<number>`count(*)` }).from(observationAlertRules);
    const [enabledRules] = await db.select({ count: sql<number>`count(*)` }).from(observationAlertRules).where(eq(observationAlertRules.isEnabled, true));
    const [totalAlerts] = await db.select({ count: sql<number>`count(*)` }).from(observationAlertHistory);
    const [unacknowledged] = await db.select({ count: sql<number>`count(*)` }).from(observationAlertHistory).where(sql`${observationAlertHistory.acknowledgedAt} IS NULL AND ${observationAlertHistory.dismissedAt} IS NULL`);
    const severityCounts = await db.select({
      severity: observationAlertHistory.severity,
      count: sql<number>`count(*)`,
    }).from(observationAlertHistory).groupBy(observationAlertHistory.severity);

    return {
      totalRules: totalRules?.count || 0,
      enabledRules: enabledRules?.count || 0,
      totalAlerts: totalAlerts?.count || 0,
      unacknowledged: unacknowledged?.count || 0,
      alertsBySeverity: Object.fromEntries(severityCounts.map(r => [r.severity, r.count])),
    };
  }),

  // ─── Cross-Scanner Correlation ───────────────────────────────────────

  /** Get correlated asset view */
  getCorrelatedAssets: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
      minRiskScore: z.number().min(0).max(100).optional(),
      hostFilter: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      // Fetch all observations, signals, and risk cards
      const observations = await db.select().from(scanObservations).orderBy(desc(scanObservations.observedAt));
      const signals = await db.select().from(scanSignals);
      const riskCards = await db.select().from(scanRiskCards);

      const engine = getCorrelationEngine();
      let assets = engine.correlateByAsset(
        observations as unknown as ObservationRow[],
        signals as unknown as SignalRow[],
        riskCards as unknown as RiskCardRow[]
      );

      // Apply filters
      if (input.minRiskScore !== undefined) {
        assets = assets.filter(a => a.compositeRiskScore >= input.minRiskScore!);
      }
      if (input.hostFilter) {
        const filter = input.hostFilter.toLowerCase();
        assets = assets.filter(a => a.host.toLowerCase().includes(filter));
      }

      const total = assets.length;
      const paged = assets.slice(input.offset, input.offset + input.limit);
      return { assets: paged, total };
    }),

  /** Get attack surface summary */
  getAttackSurfaceSummary: protectedProcedure.query(async () => {
    const db = await getDbRequired();
    const observations = await db.select().from(scanObservations);
    const signals = await db.select().from(scanSignals);
    const riskCards = await db.select().from(scanRiskCards);

    const engine = getCorrelationEngine();
    const assets = engine.correlateByAsset(
      observations as unknown as ObservationRow[],
      signals as unknown as SignalRow[],
      riskCards as unknown as RiskCardRow[]
    );
    return engine.generateAttackSurfaceSummary(assets);
  }),

  /** Get asset detail with timeline */
  getAssetCorrelationDetail: protectedProcedure
    .input(z.object({ assetId: z.string(), timelineBucketMinutes: z.number().default(60) }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const observations = await db.select().from(scanObservations).where(eq(scanObservations.assetId, input.assetId));
      const signals = await db.select().from(scanSignals).where(eq(scanSignals.assetId, input.assetId));
      const riskCards = await db.select().from(scanRiskCards).where(eq(scanRiskCards.assetId, input.assetId));

      const engine = getCorrelationEngine();
      const assets = engine.correlateByAsset(
        observations as unknown as ObservationRow[],
        signals as unknown as SignalRow[],
        riskCards as unknown as RiskCardRow[]
      );
      const asset = assets[0] || null;
      const timeline = engine.buildAssetTimeline(
        observations as unknown as ObservationRow[],
        input.assetId,
        input.timelineBucketMinutes
      );
      return { asset, timeline };
    }),
});
