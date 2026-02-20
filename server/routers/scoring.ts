/**
 * CARVER+Shock / CVSS Hybrid Scoring Router (Enhanced)
 * ─────────────────────────────────────────────────────
 * Manages scoring profiles, LLM-based asset classification,
 * dynamic re-scoring with mission function baselines, and
 * heat map data for attack path visualization.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import {
  scoringProfiles,
  scoringAuditLog,
  discoveredAssets,
  domainIntelScans,
} from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import {
  computeHybridRisk,
  dbProfileToScoringProfile,
  DEFAULT_PROFILE,
  PRESET_PROFILES,
  applyMissionBaselines,
  classifyAssets,
  generateHeatMapData,
  riskScoreToHeatColor,
  generateRescoringEvent,
  isSignificantChange,
  businessImpactToMultiplier,
  MISSION_FUNCTIONS,
  ESSENTIAL_SERVICES,
  BUSINESS_IMPACT_LEVELS,
  MISSION_FUNCTION_BASELINES,
  ESSENTIAL_SERVICE_BASELINES,
  type ScoringInput,
  type ScoringProfile,
  type ScoringResult,
  type CarverScores,
  type ShockScores,
  type RescoringEvent,
} from "../lib/scoring-engine";

async function getDbSafe() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

/** Build a ScoringInput from an asset row, applying mission function baselines */
function buildScoringInput(asset: any, profile: ScoringProfile): ScoringInput {
  let carver: CarverScores = (asset.carverScores as any) || {
    criticality: 3, accessibility: 3, recuperability: 3,
    vulnerability: 3, effect: 3, recognizability: 3,
  };
  let shock: ShockScores = (asset.shockScores as any) || {
    scope: 3, handling: 3, operationalImpact: 3,
    cascadingEffects: 3, knowledge: 3,
  };

  // Apply mission function and essential service baselines
  let missionMultiplier = 1.0;
  if (asset.missionFunction) {
    const baselines = applyMissionBaselines(
      carver,
      shock,
      asset.missionFunction,
      asset.essentialService ?? undefined
    );
    carver = baselines.carver;
    shock = baselines.shock;
    missionMultiplier = baselines.missionMultiplier;
  }

  // Override with business impact level multiplier if available
  if (asset.businessImpactLevel) {
    const bilMult = businessImpactToMultiplier(asset.businessImpactLevel);
    missionMultiplier = Math.max(missionMultiplier, bilMult);
  }

  return {
    carver,
    shock,
    cvssEstimate: asset.cvssEstimate ?? 5,
    exposure: (asset.likelihoodScore ?? 50) / 100,
    confidence: (asset.confidence ?? 70) / 100,
    confirmedVulnScore: asset.vulnRiskScore ?? undefined,
    missionMultiplier,
    businessImpactLevel: asset.businessImpactLevel ?? undefined,
  };
}

export const scoringRouter = router({
  // ─── Profile Management ─────────────────────────────────────────────

  listProfiles: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    return db.select().from(scoringProfiles).orderBy(desc(scoringProfiles.createdAt));
  }),

  getProfile: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.id));
      return row ?? null;
    }),

  getPresets: protectedProcedure.query(() => {
    return Object.entries(PRESET_PROFILES).map(([key, val]) => ({
      key,
      name: val.name,
      description: val.description,
      profile: val.profile,
    }));
  }),

  /** Get mission function taxonomy (for UI dropdowns and reference) */
  getTaxonomy: protectedProcedure.query(() => {
    return {
      missionFunctions: MISSION_FUNCTIONS.map(mf => ({
        key: mf,
        label: mf.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
        baseline: MISSION_FUNCTION_BASELINES[mf] ?? null,
      })),
      essentialServices: ESSENTIAL_SERVICES.map(es => ({
        key: es,
        label: es.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
        baseline: ESSENTIAL_SERVICE_BASELINES[es] ?? null,
      })),
      businessImpactLevels: BUSINESS_IMPACT_LEVELS.map(bil => ({
        key: bil,
        label: bil.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
        multiplier: businessImpactToMultiplier(bil),
      })),
    };
  }),

  createProfile: protectedProcedure
    .input(
      z.object({
        name: z.string().min(1).max(255),
        description: z.string().optional(),
        engagementId: z.number().optional(),
        isDefault: z.boolean().optional(),
        wCriticality: z.number().min(0).max(10).default(2.0),
        wAccessibility: z.number().min(0).max(10).default(1.5),
        wRecuperability: z.number().min(0).max(10).default(1.0),
        wVulnerability: z.number().min(0).max(10).default(1.5),
        wEffect: z.number().min(0).max(10).default(1.5),
        wRecognizability: z.number().min(0).max(10).default(0.5),
        wScope: z.number().min(0).max(10).default(1.5),
        wHandling: z.number().min(0).max(10).default(1.0),
        wOperationalImpact: z.number().min(0).max(10).default(2.0),
        wCascadingEffects: z.number().min(0).max(10).default(1.5),
        wKnowledge: z.number().min(0).max(10).default(1.0),
        carverWeight: z.number().min(0).max(1).default(0.4),
        shockWeight: z.number().min(0).max(1).default(0.3),
        cvssWeight: z.number().min(0).max(1).default(0.3),
        criticalThreshold: z.number().min(0).max(100).default(85),
        highThreshold: z.number().min(0).max(100).default(65),
        mediumThreshold: z.number().min(0).max(100).default(40),
        presetKey: z.string().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      let data = { ...input };
      if (input.presetKey && PRESET_PROFILES[input.presetKey]) {
        const preset = PRESET_PROFILES[input.presetKey].profile;
        data = {
          ...data,
          wCriticality: preset.carverWeights.criticality,
          wAccessibility: preset.carverWeights.accessibility,
          wRecuperability: preset.carverWeights.recuperability,
          wVulnerability: preset.carverWeights.vulnerability,
          wEffect: preset.carverWeights.effect,
          wRecognizability: preset.carverWeights.recognizability,
          wScope: preset.shockWeights.scope,
          wHandling: preset.shockWeights.handling,
          wOperationalImpact: preset.shockWeights.operationalImpact,
          wCascadingEffects: preset.shockWeights.cascadingEffects,
          wKnowledge: preset.shockWeights.knowledge,
          carverWeight: preset.carverWeight,
          shockWeight: preset.shockWeight,
          cvssWeight: preset.cvssWeight,
          criticalThreshold: preset.criticalThreshold,
          highThreshold: preset.highThreshold,
          mediumThreshold: preset.mediumThreshold,
        };
      }
      if (data.isDefault) {
        await db.update(scoringProfiles).set({ isDefault: false }).where(eq(scoringProfiles.isDefault, true));
      }
      const { presetKey, ...insertData } = data;
      const [result] = await db.insert(scoringProfiles).values({ ...insertData, createdBy: ctx.user.id });
      return { id: result.insertId };
    }),

  updateProfile: protectedProcedure
    .input(
      z.object({
        id: z.number(),
        name: z.string().min(1).max(255).optional(),
        description: z.string().optional(),
        wCriticality: z.number().min(0).max(10).optional(),
        wAccessibility: z.number().min(0).max(10).optional(),
        wRecuperability: z.number().min(0).max(10).optional(),
        wVulnerability: z.number().min(0).max(10).optional(),
        wEffect: z.number().min(0).max(10).optional(),
        wRecognizability: z.number().min(0).max(10).optional(),
        wScope: z.number().min(0).max(10).optional(),
        wHandling: z.number().min(0).max(10).optional(),
        wOperationalImpact: z.number().min(0).max(10).optional(),
        wCascadingEffects: z.number().min(0).max(10).optional(),
        wKnowledge: z.number().min(0).max(10).optional(),
        carverWeight: z.number().min(0).max(1).optional(),
        shockWeight: z.number().min(0).max(1).optional(),
        cvssWeight: z.number().min(0).max(1).optional(),
        criticalThreshold: z.number().min(0).max(100).optional(),
        highThreshold: z.number().min(0).max(100).optional(),
        mediumThreshold: z.number().min(0).max(100).optional(),
        isDefault: z.boolean().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const { id, ...updates } = input;
      if (updates.isDefault) {
        await db.update(scoringProfiles).set({ isDefault: false }).where(eq(scoringProfiles.isDefault, true));
      }
      await db.update(scoringProfiles).set({ ...updates, updatedAt: new Date() }).where(eq(scoringProfiles.id, id));
      return { success: true };
    }),

  deleteProfile: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(scoringProfiles).where(eq(scoringProfiles.id, input.id));
      return { success: true };
    }),

  // ─── LLM Asset Classification ──────────────────────────────────────

  /** Classify assets in a scan using LLM to determine mission function,
   *  essential service, business impact level, and inter-asset dependencies.
   *  This is the key differentiator: the LLM is trained on IT asset taxonomies
   *  to infer what each asset does for the organization. */
  classifyAssets: protectedProcedure
    .input(
      z.object({
        scanId: z.number(),
        orgName: z.string().default("Target Organization"),
        orgSector: z.string().default("technology"),
        criticalFunctions: z.array(z.string()).default(["revenue_generation", "customer_data", "authentication"]),
        complianceFlags: z.array(z.string()).default([]),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();

      const assets = await db
        .select()
        .from(discoveredAssets)
        .where(eq(discoveredAssets.scanId, input.scanId));

      if (assets.length === 0) return { classified: 0, results: [] };

      // Prepare asset data for LLM classification
      const assetData = assets.map(a => ({
        assetId: a.assetId || `asset-${a.id}`,
        hostname: a.hostname,
        assetType: a.assetType || "unknown",
        assetClasses: (a.assetClasses as string[]) || [],
        tags: (a.tags as string[]) || [],
        technologies: (a.technologies as any[]) || [],
        url: a.url || undefined,
      }));

      // Run LLM classification in batches of 15
      const batchSize = 15;
      const allClassifications = new Map<string, any>();

      for (let i = 0; i < assetData.length; i += batchSize) {
        const batch = assetData.slice(i, i + batchSize);
        const classifications = await classifyAssets(batch, {
          name: input.orgName,
          sector: input.orgSector,
          criticalFunctions: input.criticalFunctions,
          complianceFlags: input.complianceFlags,
        });
        for (const [key, val] of Array.from(classifications.entries())) {
          allClassifications.set(key, val);
        }
      }

      // Update assets with classification results
      const results: Array<{
        assetId: number;
        hostname: string;
        missionFunction: string;
        essentialService: string;
        businessImpactLevel: string;
        assetPurpose: string;
        confidence: number;
      }> = [];

      for (const asset of assets) {
        const assetKey = asset.assetId || `asset-${asset.id}`;
        const classification = allClassifications.get(assetKey);
        if (!classification) continue;

        await db
          .update(discoveredAssets)
          .set({
            missionFunction: classification.missionFunction,
            essentialService: classification.essentialService,
            assetPurpose: classification.assetPurpose,
            businessImpactLevel: classification.businessImpactLevel,
            missionDependencies: classification.missionDependencies,
            llmClassification: classification,
          })
          .where(eq(discoveredAssets.id, asset.id));

        results.push({
          assetId: asset.id,
          hostname: asset.hostname,
          missionFunction: classification.missionFunction,
          essentialService: classification.essentialService,
          businessImpactLevel: classification.businessImpactLevel,
          assetPurpose: classification.assetPurpose,
          confidence: classification.classificationConfidence,
        });
      }

      return { classified: results.length, results };
    }),

  /** Manually update an asset's mission classification */
  updateAssetClassification: protectedProcedure
    .input(
      z.object({
        assetId: z.number(),
        missionFunction: z.string().optional(),
        essentialService: z.string().optional(),
        businessImpactLevel: z.string().optional(),
        assetPurpose: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const { assetId, ...updates } = input;
      const setData: any = {};
      if (updates.missionFunction !== undefined) setData.missionFunction = updates.missionFunction;
      if (updates.essentialService !== undefined) setData.essentialService = updates.essentialService;
      if (updates.businessImpactLevel !== undefined) setData.businessImpactLevel = updates.businessImpactLevel;
      if (updates.assetPurpose !== undefined) setData.assetPurpose = updates.assetPurpose;

      await db.update(discoveredAssets).set(setData).where(eq(discoveredAssets.id, assetId));
      return { success: true };
    }),

  // ─── Scoring Operations (Enhanced with Mission Baselines) ──────────

  /** Score a single asset with mission function baselines applied */
  scoreAsset: protectedProcedure
    .input(
      z.object({
        assetId: z.number(),
        profileId: z.number().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [asset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      if (!asset) throw new Error("Asset not found");

      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      const scoringInput = buildScoringInput(asset, profile);
      const result = computeHybridRisk(scoringInput, profile);

      // Capture previous score for delta tracking
      const previousScore = asset.hybridRiskScore ?? 0;
      const previousBand = asset.riskBand ?? "low";

      await db
        .update(discoveredAssets)
        .set({
          hybridRiskScore: result.hybridRiskScore,
          riskBand: result.riskBand,
          missionImpactScore: Math.round(result.missionImpactScore * 10) / 10,
          impactScore: result.impactScore,
          likelihoodScore: result.likelihoodScore,
          scoringVersion: sql`COALESCE(${discoveredAssets.scoringVersion}, 0) + 1`,
          lastScoredAt: new Date(),
          scoringProfileId: input.profileId ?? null,
        })
        .where(eq(discoveredAssets.id, input.assetId));

      await db.insert(scoringAuditLog).values({
        assetId: input.assetId,
        scanId: asset.scanId,
        profileId: input.profileId ?? null,
        carverScores: scoringInput.carver,
        shockScores: scoringInput.shock,
        cvssEstimate: asset.cvssEstimate ?? 5,
        missionImpactScore: result.missionImpactScore,
        impactScore: result.impactScore,
        likelihoodScore: result.likelihoodScore,
        hybridRiskScore: result.hybridRiskScore,
        riskBand: result.riskBand,
        weightsSnapshot: profile,
        computedBy: ctx.user.openId,
      });

      return {
        ...result,
        delta: result.hybridRiskScore - previousScore,
        previousBand,
        missionFunction: asset.missionFunction,
        essentialService: asset.essentialService,
        businessImpactLevel: asset.businessImpactLevel,
      };
    }),

  /** Batch re-score all assets in a scan with mission function baselines */
  batchRescore: protectedProcedure
    .input(
      z.object({
        scanId: z.number(),
        profileId: z.number().optional(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      const results: Array<{
        assetId: number;
        hostname: string;
        oldScore: number;
        newScore: number;
        delta: number;
        riskBand: string;
        missionFunction: string | null;
        businessImpactLevel: string | null;
        significant: boolean;
      }> = [];

      for (const asset of assets) {
        const scoringInput = buildScoringInput(asset, profile);
        const result = computeHybridRisk(scoringInput, profile);
        const oldScore = asset.hybridRiskScore ?? 0;
        const delta = result.hybridRiskScore - oldScore;

        await db
          .update(discoveredAssets)
          .set({
            hybridRiskScore: result.hybridRiskScore,
            riskBand: result.riskBand,
            missionImpactScore: Math.round(result.missionImpactScore * 10) / 10,
            impactScore: result.impactScore,
            likelihoodScore: result.likelihoodScore,
            scoringVersion: sql`COALESCE(${discoveredAssets.scoringVersion}, 0) + 1`,
            lastScoredAt: new Date(),
            scoringProfileId: input.profileId ?? null,
          })
          .where(eq(discoveredAssets.id, asset.id));

        await db.insert(scoringAuditLog).values({
          assetId: asset.id,
          scanId: input.scanId,
          profileId: input.profileId ?? null,
          carverScores: scoringInput.carver,
          shockScores: scoringInput.shock,
          cvssEstimate: asset.cvssEstimate ?? 5,
          missionImpactScore: result.missionImpactScore,
          impactScore: result.impactScore,
          likelihoodScore: result.likelihoodScore,
          hybridRiskScore: result.hybridRiskScore,
          riskBand: result.riskBand,
          weightsSnapshot: profile,
          computedBy: ctx.user.openId,
        });

        const significant = Math.abs(delta) >= 15 || (result.riskBand !== (asset.riskBand ?? "low"));

        results.push({
          assetId: asset.id,
          hostname: asset.hostname,
          oldScore,
          newScore: result.hybridRiskScore,
          delta,
          riskBand: result.riskBand,
          missionFunction: asset.missionFunction,
          businessImpactLevel: asset.businessImpactLevel,
          significant,
        });
      }

      const significantChanges = results.filter(r => r.significant);

      return {
        scored: results.length,
        significantChanges: significantChanges.length,
        results: results.sort((a, b) => b.newScore - a.newScore),
      };
    }),

  /** Full pipeline: classify assets with LLM, then re-score with mission baselines */
  classifyAndRescore: protectedProcedure
    .input(
      z.object({
        scanId: z.number(),
        profileId: z.number().optional(),
        orgName: z.string().default("Target Organization"),
        orgSector: z.string().default("technology"),
        criticalFunctions: z.array(z.string()).default(["revenue_generation", "customer_data", "authentication"]),
        complianceFlags: z.array(z.string()).default([]),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      // Step 1: Classify assets
      const assets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
      if (assets.length === 0) return { classified: 0, scored: 0, results: [] };

      const assetData = assets.map(a => ({
        assetId: a.assetId || `asset-${a.id}`,
        hostname: a.hostname,
        assetType: a.assetType || "unknown",
        assetClasses: (a.assetClasses as string[]) || [],
        tags: (a.tags as string[]) || [],
        technologies: (a.technologies as any[]) || [],
        url: a.url || undefined,
      }));

      const batchSize = 15;
      const allClassifications = new Map<string, any>();
      for (let i = 0; i < assetData.length; i += batchSize) {
        const batch = assetData.slice(i, i + batchSize);
        const classifications = await classifyAssets(batch, {
          name: input.orgName,
          sector: input.orgSector,
          criticalFunctions: input.criticalFunctions,
          complianceFlags: input.complianceFlags,
        });
        for (const [key, val] of Array.from(classifications.entries())) allClassifications.set(key, val);
      }

      // Step 2: Update classifications
      for (const asset of assets) {
        const assetKey = asset.assetId || `asset-${asset.id}`;
        const classification = allClassifications.get(assetKey);
        if (!classification) continue;
        await db.update(discoveredAssets).set({
          missionFunction: classification.missionFunction,
          essentialService: classification.essentialService,
          assetPurpose: classification.assetPurpose,
          businessImpactLevel: classification.businessImpactLevel,
          missionDependencies: classification.missionDependencies,
          llmClassification: classification,
        }).where(eq(discoveredAssets.id, asset.id));
      }

      // Step 3: Re-score with updated classifications
      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      // Re-fetch assets with updated classifications
      const updatedAssets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      const results: Array<{
        assetId: number;
        hostname: string;
        missionFunction: string | null;
        essentialService: string | null;
        businessImpactLevel: string | null;
        oldScore: number;
        newScore: number;
        delta: number;
        riskBand: string;
      }> = [];

      for (const asset of updatedAssets) {
        const scoringInput = buildScoringInput(asset, profile);
        const result = computeHybridRisk(scoringInput, profile);
        const oldScore = asset.hybridRiskScore ?? 0;

        await db.update(discoveredAssets).set({
          hybridRiskScore: result.hybridRiskScore,
          riskBand: result.riskBand,
          missionImpactScore: Math.round(result.missionImpactScore * 10) / 10,
          impactScore: result.impactScore,
          likelihoodScore: result.likelihoodScore,
          scoringVersion: sql`COALESCE(${discoveredAssets.scoringVersion}, 0) + 1`,
          lastScoredAt: new Date(),
          scoringProfileId: input.profileId ?? null,
        }).where(eq(discoveredAssets.id, asset.id));

        await db.insert(scoringAuditLog).values({
          assetId: asset.id,
          scanId: input.scanId,
          profileId: input.profileId ?? null,
          carverScores: scoringInput.carver,
          shockScores: scoringInput.shock,
          cvssEstimate: asset.cvssEstimate ?? 5,
          missionImpactScore: result.missionImpactScore,
          impactScore: result.impactScore,
          likelihoodScore: result.likelihoodScore,
          hybridRiskScore: result.hybridRiskScore,
          riskBand: result.riskBand,
          weightsSnapshot: profile,
          computedBy: ctx.user.openId,
        });

        results.push({
          assetId: asset.id,
          hostname: asset.hostname,
          missionFunction: asset.missionFunction,
          essentialService: asset.essentialService,
          businessImpactLevel: asset.businessImpactLevel,
          oldScore,
          newScore: result.hybridRiskScore,
          delta: result.hybridRiskScore - oldScore,
          riskBand: result.riskBand,
        });
      }

      return {
        classified: allClassifications.size,
        scored: results.length,
        results: results.sort((a, b) => b.newScore - a.newScore),
      };
    }),

  /** Simulate scoring with a profile (preview mode, no save) */
  simulateScore: protectedProcedure
    .input(
      z.object({
        carver: z.object({
          criticality: z.number().min(0).max(10),
          accessibility: z.number().min(0).max(10),
          recuperability: z.number().min(0).max(10),
          vulnerability: z.number().min(0).max(10),
          effect: z.number().min(0).max(10),
          recognizability: z.number().min(0).max(10),
        }),
        shock: z.object({
          scope: z.number().min(0).max(10),
          handling: z.number().min(0).max(10),
          operationalImpact: z.number().min(0).max(10),
          cascadingEffects: z.number().min(0).max(10),
          knowledge: z.number().min(0).max(10),
        }),
        cvssEstimate: z.number().min(0).max(10).default(5),
        exposure: z.number().min(0).max(1).default(0.5),
        confidence: z.number().min(0).max(1).default(0.7),
        confirmedVulnScore: z.number().min(0).max(100).optional(),
        profileId: z.number().optional(),
        missionFunction: z.string().optional(),
        essentialService: z.string().optional(),
        businessImpactLevel: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();

      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      let carver = input.carver;
      let shock = input.shock;
      let missionMultiplier = 1.0;

      // Apply mission baselines if provided
      if (input.missionFunction) {
        const baselines = applyMissionBaselines(
          carver as CarverScores,
          shock as ShockScores,
          input.missionFunction,
          input.essentialService
        );
        carver = baselines.carver;
        shock = baselines.shock;
        missionMultiplier = baselines.missionMultiplier;
      }

      if (input.businessImpactLevel) {
        const bilMult = businessImpactToMultiplier(input.businessImpactLevel);
        missionMultiplier = Math.max(missionMultiplier, bilMult);
      }

      const scoringInput: ScoringInput = {
        carver: carver as CarverScores,
        shock: shock as ShockScores,
        cvssEstimate: input.cvssEstimate,
        exposure: input.exposure,
        confidence: input.confidence,
        confirmedVulnScore: input.confirmedVulnScore,
        missionMultiplier,
        businessImpactLevel: input.businessImpactLevel as any,
      };

      const result = computeHybridRisk(scoringInput, profile);

      return {
        ...result,
        appliedMissionFunction: input.missionFunction ?? null,
        appliedEssentialService: input.essentialService ?? null,
        appliedMissionMultiplier: missionMultiplier,
        adjustedCarver: carver,
        adjustedShock: shock,
      };
    }),

  // ─── Heat Map Data ──────────────────────────────────────────────────

  getHeatMapData: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const assets = await db
        .select({
          id: discoveredAssets.id,
          hostname: discoveredAssets.hostname,
          assetType: discoveredAssets.assetType,
          hybridRiskScore: discoveredAssets.hybridRiskScore,
          riskBand: discoveredAssets.riskBand,
          missionImpactScore: discoveredAssets.missionImpactScore,
          impactScore: discoveredAssets.impactScore,
          likelihoodScore: discoveredAssets.likelihoodScore,
          carverScores: discoveredAssets.carverScores,
          shockScores: discoveredAssets.shockScores,
          cvssEstimate: discoveredAssets.cvssEstimate,
          assetCriticalityScore: discoveredAssets.assetCriticalityScore,
          assetCriticalityBand: discoveredAssets.assetCriticalityBand,
          vulnRiskScore: discoveredAssets.vulnRiskScore,
          missionFunction: discoveredAssets.missionFunction,
          essentialService: discoveredAssets.essentialService,
          businessImpactLevel: discoveredAssets.businessImpactLevel,
          assetPurpose: discoveredAssets.assetPurpose,
          scoringVersion: discoveredAssets.scoringVersion,
          lastScoredAt: discoveredAssets.lastScoredAt,
        })
        .from(discoveredAssets)
        .where(eq(discoveredAssets.scanId, input.scanId))
        .orderBy(desc(discoveredAssets.hybridRiskScore));

      // Generate heat map colors
      const heatMapAssets = assets.map(a => ({
        ...a,
        heatColor: riskScoreToHeatColor(a.hybridRiskScore ?? 0),
        intensity: Math.min(1, (a.hybridRiskScore ?? 0) / 100),
      }));

      // Distribution stats
      const scores = assets.map(a => a.hybridRiskScore ?? 0);
      const total = scores.length;
      const avg = total > 0 ? scores.reduce((a, b) => a + b, 0) / total : 0;
      const critical = scores.filter(s => s >= 85).length;
      const high = scores.filter(s => s >= 65 && s < 85).length;
      const medium = scores.filter(s => s >= 40 && s < 65).length;
      const low = scores.filter(s => s < 40).length;

      // Mission function distribution
      const missionFunctionDist: Record<string, { count: number; avgScore: number }> = {};
      for (const a of assets) {
        const mf = a.missionFunction || "unclassified";
        if (!missionFunctionDist[mf]) missionFunctionDist[mf] = { count: 0, avgScore: 0 };
        missionFunctionDist[mf].count++;
        missionFunctionDist[mf].avgScore += (a.hybridRiskScore ?? 0);
      }
      for (const mf of Object.keys(missionFunctionDist)) {
        missionFunctionDist[mf].avgScore = Math.round(missionFunctionDist[mf].avgScore / missionFunctionDist[mf].count);
      }

      // Business impact distribution
      const impactDist: Record<string, number> = {};
      for (const a of assets) {
        const bil = a.businessImpactLevel || "unclassified";
        impactDist[bil] = (impactDist[bil] || 0) + 1;
      }

      return {
        assets: heatMapAssets,
        stats: {
          total,
          averageScore: Math.round(avg),
          distribution: { critical, high, medium, low },
          missionFunctionDistribution: missionFunctionDist,
          businessImpactDistribution: impactDist,
        },
      };
    }),

  // ─── Audit Log ──────────────────────────────────────────────────────

  getAuditLog: protectedProcedure
    .input(
      z.object({
        assetId: z.number().optional(),
        scanId: z.number().optional(),
        limit: z.number().min(1).max(200).default(50),
      })
    )
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input.assetId) conditions.push(eq(scoringAuditLog.assetId, input.assetId));
      if (input.scanId) conditions.push(eq(scoringAuditLog.scanId, input.scanId));
      return db
        .select()
        .from(scoringAuditLog)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(scoringAuditLog.computedAt))
        .limit(input.limit);
    }),

  // ─── Available Scans ────────────────────────────────────────────────

  listScoredScans: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    return db
      .select({
        id: domainIntelScans.id,
        domain: domainIntelScans.primaryDomain,
        status: domainIntelScans.status,
        createdAt: domainIntelScans.createdAt,
      })
      .from(domainIntelScans)
      .where(eq(domainIntelScans.status, "completed"))
      .orderBy(desc(domainIntelScans.createdAt))
      .limit(50);
  }),
});
