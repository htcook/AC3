/**
 * Actor Genome Engine — tRPC Router
 *
 * Exposes the behavioral attribution scoring engine via tRPC procedures.
 * All procedures are protected (require authentication).
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  scoreIncident,
  getAllActorProfiles,
  getActorProfile,
  getProfileCompleteness,
  getActorTradecraft,
  getActorTemporalAnalysis,
  compareActorGenomes,
  getAllCampaigns,
  getWeightPresets,
  type IncidentObservation,
} from "../lib/actor-genome-engine";
import {
  clusterIncidents,
  analyzeTemporalPatterns,
  detectInfrastructureOverlap,
} from "../lib/actor-genome-clustering";

export const actorGenomeRouter = router({
  // ─── Attribution Scoring ────────────────────────────────────────────────────

  /** Score an incident against all actor profiles */
  scoreIncident: protectedProcedure
    .input(z.object({
      id: z.string(),
      title: z.string(),
      timestamp: z.number(),
      victimSector: z.string(),
      victimCountry: z.string(),
      victimTechnology: z.array(z.string()).default([]),
      initialAccess: z.array(z.string()).default([]),
      techniques: z.array(z.string()).default([]),
      malwareObserved: z.array(z.string()).default([]),
      toolsUsed: z.array(z.string()).default([]),
      persistenceMethods: z.array(z.string()).default([]),
      c2Methods: z.array(z.string()).default([]),
      lateralMovement: z.array(z.string()).default([]),
      exfiltrationMethods: z.array(z.string()).default([]),
      impactType: z.string(),
      sourceIps: z.array(z.string()).default([]),
      domains: z.array(z.string()).default([]),
      jarmHashes: z.array(z.string()).default([]),
      ja3Hashes: z.array(z.string()).default([]),
      tlsCerts: z.array(z.string()).default([]),
      asnNumbers: z.array(z.string()).default([]),
      plcVendors: z.array(z.string()).default([]),
      icsProtocols: z.array(z.string()).default([]),
      safetySystemTargeted: z.boolean().default(false),
      hmiModified: z.boolean().default(false),
      plcLogicChanged: z.boolean().default(false),
      credentialReuse: z.boolean().default(false),
      propagandaLeft: z.boolean().default(false),
      propagandaText: z.string().nullable().default(null),
      dwellTimeDays: z.number().nullable().default(null),
      operatingHoursUtc: z.array(z.number()).nullable().default(null),
      publicClaims: z.array(z.object({
        persona: z.string(),
        platform: z.string(),
        timestamp: z.number(),
      })).default([]),
      relatedAdvisories: z.array(z.string()).default([]),
      // Optional weight overrides
      weightPreset: z.enum(["default", "ics_ot"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const observation: IncidentObservation = input;
      const weights = input.weightPreset === "ics_ot" ? getWeightPresets().ics_ot : undefined;
      return scoreIncident(observation, { weights });
    }),

  // ─── Actor Profiles ─────────────────────────────────────────────────────────

  /** Get all actor genome profiles (summary view) */
  listProfiles: protectedProcedure.query(async () => {
    const profiles = getAllActorProfiles();
    return profiles.map(p => ({
      actorId: p.actorId,
      name: p.name,
      aliases: p.aliases,
      origin: p.origin,
      motivation: p.motivation,
      sophistication: p.sophistication,
      firstSeen: p.firstSeen,
      lastActive: p.lastActive,
      profileCompleteness: p.profileCompleteness,
      campaignCount: p.campaigns.length,
      tradecraftCount: p.tradecraftFingerprints.length,
      genomeFeatureCount: p.genome.length,
      attribution: p.attribution,
    }));
  }),

  /** Get full actor genome profile */
  getProfile: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      return getActorProfile(input.actorId) || null;
    }),

  /** Get profile completeness scores */
  profileCompleteness: protectedProcedure.query(async () => {
    return getProfileCompleteness();
  }),

  /** Get tradecraft fingerprints for an actor */
  getTradecraft: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      return getActorTradecraft(input.actorId);
    }),

  /** Get temporal analysis for an actor */
  getTemporalAnalysis: protectedProcedure
    .input(z.object({ actorId: z.string() }))
    .query(async ({ input }) => {
      return getActorTemporalAnalysis(input.actorId);
    }),

  /** Compare two actor genomes */
  compareActors: protectedProcedure
    .input(z.object({
      actorId1: z.string(),
      actorId2: z.string(),
    }))
    .query(async ({ input }) => {
      return compareActorGenomes(input.actorId1, input.actorId2);
    }),

  // ─── Campaigns ──────────────────────────────────────────────────────────────

  /** Get all campaigns across all actors */
  listCampaigns: protectedProcedure.query(async () => {
    return getAllCampaigns();
  }),

  // ─── Clustering & Analysis ──────────────────────────────────────────────────

  /** Cluster incidents by behavioral similarity */
  clusterIncidents: protectedProcedure
    .input(z.object({
      incidents: z.array(z.object({
        id: z.string(),
        title: z.string(),
        timestamp: z.number(),
        victimSector: z.string(),
        victimCountry: z.string(),
        victimTechnology: z.array(z.string()).default([]),
        initialAccess: z.array(z.string()).default([]),
        techniques: z.array(z.string()).default([]),
        malwareObserved: z.array(z.string()).default([]),
        toolsUsed: z.array(z.string()).default([]),
        persistenceMethods: z.array(z.string()).default([]),
        c2Methods: z.array(z.string()).default([]),
        lateralMovement: z.array(z.string()).default([]),
        exfiltrationMethods: z.array(z.string()).default([]),
        impactType: z.string(),
        sourceIps: z.array(z.string()).default([]),
        domains: z.array(z.string()).default([]),
        jarmHashes: z.array(z.string()).default([]),
        ja3Hashes: z.array(z.string()).default([]),
        tlsCerts: z.array(z.string()).default([]),
        asnNumbers: z.array(z.string()).default([]),
        plcVendors: z.array(z.string()).default([]),
        icsProtocols: z.array(z.string()).default([]),
        safetySystemTargeted: z.boolean().default(false),
        hmiModified: z.boolean().default(false),
        plcLogicChanged: z.boolean().default(false),
        credentialReuse: z.boolean().default(false),
        propagandaLeft: z.boolean().default(false),
        propagandaText: z.string().nullable().default(null),
        dwellTimeDays: z.number().nullable().default(null),
        operatingHoursUtc: z.array(z.number()).nullable().default(null),
        publicClaims: z.array(z.object({
          persona: z.string(),
          platform: z.string(),
          timestamp: z.number(),
        })).default([]),
        relatedAdvisories: z.array(z.string()).default([]),
      })),
      similarityThreshold: z.number().min(0).max(1).default(0.6),
      minClusterSize: z.number().min(1).default(2),
    }))
    .mutation(async ({ input }) => {
      return clusterIncidents(input.incidents as IncidentObservation[], {
        similarityThreshold: input.similarityThreshold,
        minClusterSize: input.minClusterSize,
      });
    }),

  /** Analyze temporal patterns from incidents */
  analyzeTemporalPatterns: protectedProcedure
    .input(z.object({
      incidents: z.array(z.object({
        id: z.string(),
        title: z.string(),
        timestamp: z.number(),
        victimSector: z.string(),
        victimCountry: z.string(),
        victimTechnology: z.array(z.string()).default([]),
        initialAccess: z.array(z.string()).default([]),
        techniques: z.array(z.string()).default([]),
        malwareObserved: z.array(z.string()).default([]),
        toolsUsed: z.array(z.string()).default([]),
        persistenceMethods: z.array(z.string()).default([]),
        c2Methods: z.array(z.string()).default([]),
        lateralMovement: z.array(z.string()).default([]),
        exfiltrationMethods: z.array(z.string()).default([]),
        impactType: z.string(),
        sourceIps: z.array(z.string()).default([]),
        domains: z.array(z.string()).default([]),
        jarmHashes: z.array(z.string()).default([]),
        ja3Hashes: z.array(z.string()).default([]),
        tlsCerts: z.array(z.string()).default([]),
        asnNumbers: z.array(z.string()).default([]),
        plcVendors: z.array(z.string()).default([]),
        icsProtocols: z.array(z.string()).default([]),
        safetySystemTargeted: z.boolean().default(false),
        hmiModified: z.boolean().default(false),
        plcLogicChanged: z.boolean().default(false),
        credentialReuse: z.boolean().default(false),
        propagandaLeft: z.boolean().default(false),
        propagandaText: z.string().nullable().default(null),
        dwellTimeDays: z.number().nullable().default(null),
        operatingHoursUtc: z.array(z.number()).nullable().default(null),
        publicClaims: z.array(z.object({
          persona: z.string(),
          platform: z.string(),
          timestamp: z.number(),
        })).default([]),
        relatedAdvisories: z.array(z.string()).default([]),
      })),
      geopoliticalEvents: z.array(z.object({
        event: z.string(),
        date: z.number(),
      })).default([]),
    }))
    .mutation(async ({ input }) => {
      return analyzeTemporalPatterns(
        input.incidents as IncidentObservation[],
        input.geopoliticalEvents.length > 0 ? input.geopoliticalEvents : undefined
      );
    }),

  /** Detect infrastructure overlaps across incidents */
  detectInfrastructureOverlap: protectedProcedure
    .input(z.object({
      incidents: z.array(z.object({
        id: z.string(),
        title: z.string(),
        timestamp: z.number(),
        victimSector: z.string(),
        victimCountry: z.string(),
        victimTechnology: z.array(z.string()).default([]),
        initialAccess: z.array(z.string()).default([]),
        techniques: z.array(z.string()).default([]),
        malwareObserved: z.array(z.string()).default([]),
        toolsUsed: z.array(z.string()).default([]),
        persistenceMethods: z.array(z.string()).default([]),
        c2Methods: z.array(z.string()).default([]),
        lateralMovement: z.array(z.string()).default([]),
        exfiltrationMethods: z.array(z.string()).default([]),
        impactType: z.string(),
        sourceIps: z.array(z.string()).default([]),
        domains: z.array(z.string()).default([]),
        jarmHashes: z.array(z.string()).default([]),
        ja3Hashes: z.array(z.string()).default([]),
        tlsCerts: z.array(z.string()).default([]),
        asnNumbers: z.array(z.string()).default([]),
        plcVendors: z.array(z.string()).default([]),
        icsProtocols: z.array(z.string()).default([]),
        safetySystemTargeted: z.boolean().default(false),
        hmiModified: z.boolean().default(false),
        plcLogicChanged: z.boolean().default(false),
        credentialReuse: z.boolean().default(false),
        propagandaLeft: z.boolean().default(false),
        propagandaText: z.string().nullable().default(null),
        dwellTimeDays: z.number().nullable().default(null),
        operatingHoursUtc: z.array(z.number()).nullable().default(null),
        publicClaims: z.array(z.object({
          persona: z.string(),
          platform: z.string(),
          timestamp: z.number(),
        })).default([]),
        relatedAdvisories: z.array(z.string()).default([]),
      })),
    }))
    .mutation(async ({ input }) => {
      return detectInfrastructureOverlap(input.incidents as IncidentObservation[]);
    }),

  // ─── Weight Presets ─────────────────────────────────────────────────────────

  /** Get available weight presets */
  getWeightPresets: protectedProcedure.query(async () => {
    return getWeightPresets();
  }),

  // ─── Training Pipeline ────────────────────────────────────────────────────────

  /** Trigger a manual training run */
  runTraining: protectedProcedure.mutation(async () => {
    const { runGenomeTraining } = await import("../lib/actor-genome-training-pipeline");
    return runGenomeTraining("manual");
  }),

  /** Get the latest training result */
  getLatestTraining: protectedProcedure.query(async () => {
    const { getLatestTrainingResult } = await import("../lib/actor-genome-training-pipeline");
    return getLatestTrainingResult();
  }),

  /** Get training history */
  getTrainingHistory: protectedProcedure.query(async () => {
    const { getTrainingHistory } = await import("../lib/actor-genome-training-pipeline");
    return getTrainingHistory(20);
  }),

  // ─── Advisory Ingestion ───────────────────────────────────────────────────────

  /** Trigger a manual advisory ingestion run */
  runAdvisoryIngestion: protectedProcedure.mutation(async () => {
    const { runAdvisoryIngestion } = await import("../lib/advisory-ingestion-scheduler");
    return runAdvisoryIngestion("manual");
  }),

  // ─── False Flag Detection ────────────────────────────────────────────────────

  /** Analyze an incident for false flag indicators */
  analyzeFalseFlag: protectedProcedure
    .input(z.object({
      id: z.string(),
      title: z.string(),
      claimedActor: z.string().nullable().default(null),
      attributedActor: z.string().nullable().default(null),
      timestamp: z.number(),
      victimSector: z.string(),
      victimCountry: z.string(),
      techniques: z.array(z.string()).default([]),
      malwareObserved: z.array(z.string()).default([]),
      toolsUsed: z.array(z.string()).default([]),
      c2Methods: z.array(z.string()).default([]),
      initialAccess: z.array(z.string()).default([]),
      sourceIps: z.array(z.string()).default([]),
      domains: z.array(z.string()).default([]),
      jarmHashes: z.array(z.string()).default([]),
      ja3Hashes: z.array(z.string()).default([]),
      tlsCerts: z.array(z.string()).default([]),
      asnNumbers: z.array(z.string()).default([]),
      domainRegistrationDates: z.record(z.string(), z.number()).optional(),
      compileTimestamps: z.array(z.number()).optional(),
      operatingHoursUtc: z.array(z.number()).optional(),
      dwellTimeDays: z.number().nullable().default(null),
      propagandaText: z.string().nullable().default(null),
      malwareStrings: z.array(z.string()).optional(),
      ransomNoteText: z.string().nullable().default(null),
      codeComments: z.array(z.string()).optional(),
      publicClaims: z.array(z.object({
        persona: z.string(),
        platform: z.string(),
        timestamp: z.number(),
        text: z.string().optional(),
      })).default([]),
      relatedAdvisories: z.array(z.string()).default([]),
      geopoliticalContext: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeFalseFlag } = await import("../lib/false-flag-detection");
      return analyzeFalseFlag(input);
    }),

  // ─── Enhanced False Flag Analysis (with Case Library) ─────────────────────
  analyzeFalseFlagEnhanced: protectedProcedure
    .input(z.object({
      id: z.string(),
      title: z.string(),
      claimedActor: z.string().nullable().default(null),
      attributedActor: z.string().nullable().default(null),
      observedTechniques: z.array(z.string()).default([]),
      malwareFamilies: z.array(z.string()).default([]),
      targetSector: z.string().default(''),
      targetCountry: z.string().default(''),
      c2Methods: z.array(z.string()).default([]),
      initialAccess: z.array(z.string()).default([]),
      sourceIps: z.array(z.string()).default([]),
      domains: z.array(z.string()).default([]),
      jarmHashes: z.array(z.string()).default([]),
      ja3Hashes: z.array(z.string()).default([]),
      tlsCerts: z.array(z.string()).default([]),
      asnNumbers: z.array(z.string()).default([]),
      domainRegistrationDates: z.record(z.string(), z.number()).optional(),
      compileTimestamps: z.array(z.number()).optional(),
      operatingHoursUtc: z.array(z.number()).optional(),
      dwellTimeDays: z.number().nullable().default(null),
      propagandaText: z.string().nullable().default(null),
      malwareStrings: z.array(z.string()).optional(),
      ransomNoteText: z.string().nullable().default(null),
      codeComments: z.array(z.string()).optional(),
      publicClaims: z.array(z.object({
        persona: z.string(),
        platform: z.string(),
        timestamp: z.number(),
        text: z.string().optional(),
      })).default([]),
      relatedAdvisories: z.array(z.string()).default([]),
      geopoliticalContext: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { analyzeWithCaseLibrary } = await import("../lib/false-flag-detection");
      return analyzeWithCaseLibrary(input);
    }),

  // ─── Case Library Endpoints ─────────────────────────────────────────────────
  getCaseLibrary: protectedProcedure
    .query(async () => {
      const { getFalseFlagCaseLibrary } = await import("../lib/false-flag-detection");
      return getFalseFlagCaseLibrary();
    }),

  getCaseById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const { getFalseFlagCase } = await import("../lib/false-flag-detection");
      return getFalseFlagCase(input.id) || null;
    }),

  getCasesByCountry: protectedProcedure
    .input(z.object({ country: z.string() }))
    .query(async ({ input }) => {
      const { getFalseFlagCasesByCountry } = await import("../lib/false-flag-detection");
      return getFalseFlagCasesByCountry(input.country);
    }),

  getCalibratedWeights: protectedProcedure
    .query(async () => {
      const { computeCalibratedWeights } = await import("../lib/false-flag-case-library");
      return computeCalibratedWeights();
    }),

  getTechniqueStats: protectedProcedure
    .query(async () => {
      const { getTechniqueEffectiveness } = await import("../lib/false-flag-case-library");
      return getTechniqueEffectiveness();
    }),

  // ─── Live Case Library Enrichment ──────────────────────────────────────────

  getEnrichmentStatus: protectedProcedure
    .query(async () => {
      const { getEnrichmentStatus } = await import("../lib/false-flag-auto-enrichment");
      return getEnrichmentStatus();
    }),

  getPendingCandidates: protectedProcedure
    .query(async () => {
      const { getPendingCandidates } = await import("../lib/false-flag-auto-enrichment");
      return getPendingCandidates();
    }),

  getAllCandidates: protectedProcedure
    .input(z.object({ status: z.enum(["pending_review", "approved", "rejected", "needs_more_data"]).optional() }))
    .query(async ({ input }) => {
      const { getAllCandidates } = await import("../lib/false-flag-auto-enrichment");
      return getAllCandidates(input.status);
    }),

  getCandidateById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const { getCandidateById } = await import("../lib/false-flag-auto-enrichment");
      return getCandidateById(input.id);
    }),

  approveCandidate: protectedProcedure
    .input(z.object({
      id: z.string(),
      notes: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { approveCandidate, candidateToCaseEntry } = await import("../lib/false-flag-auto-enrichment");
      const approved = approveCandidate(input.id, input.notes, ctx.user.openId);
      if (!approved) throw new Error("Candidate not found");
      const caseEntry = candidateToCaseEntry(approved);
      return { approved, caseEntry };
    }),

  rejectCandidate: protectedProcedure
    .input(z.object({
      id: z.string(),
      notes: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { rejectCandidate } = await import("../lib/false-flag-auto-enrichment");
      const rejected = rejectCandidate(input.id, input.notes, ctx.user.openId);
      if (!rejected) throw new Error("Candidate not found");
      return rejected;
    }),

  markCandidateNeedsData: protectedProcedure
    .input(z.object({
      id: z.string(),
      notes: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { markNeedsMoreData } = await import("../lib/false-flag-auto-enrichment");
      const updated = markNeedsMoreData(input.id, input.notes, ctx.user.openId);
      if (!updated) throw new Error("Candidate not found");
      return updated;
    }),

  runManualEnrichment: protectedProcedure
    .input(z.object({
      reports: z.array(z.object({
        id: z.string(),
        title: z.string(),
        source: z.string(),
        publishDate: z.number(),
        content: z.string(),
        url: z.string().optional(),
        cves: z.array(z.string()).optional(),
        attributedActor: z.string().optional(),
      })),
    }))
    .mutation(async ({ input }) => {
      const { runEnrichmentCycle } = await import("../lib/false-flag-auto-enrichment");
      return runEnrichmentCycle(input.reports);
    }),
});
