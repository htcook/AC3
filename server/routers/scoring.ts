/**
 * CARVER+Shock / CVSS v4.0 Hybrid Scoring Router (Enhanced)
 * ─────────────────────────────────────────────────────────
 * Manages scoring profiles, LLM-based asset classification,
 * CVSS v4.0 vector parsing and feed-through, FIPS 199 categorization,
 * criticality tier management, dynamic re-scoring with mission
 * function baselines, and heat map data for attack path visualization.
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
  parseCvssV4Vector,
  buildCvssV4Vector,
  cvssV4ToCarverAdjustments,
  fips199ToCarverAdjustments,
  applyCriticalityTierFloors,
  applyDiscoveryTrigger,
  MISSION_FUNCTIONS,
  ESSENTIAL_SERVICES,
  BUSINESS_IMPACT_LEVELS,
  MISSION_FUNCTION_BASELINES,
  ESSENTIAL_SERVICE_BASELINES,
  CARVER_DIGITAL_TRANSLATION,
  SHOCK_DIGITAL_TRANSLATION,
  CRITICALITY_TIERS,
  DISCOVERY_PHASE_TRIGGERS,
  ASSET_DEVICE_TYPES,
  ASSET_PLATFORM_TYPES,
  type ScoringInput,
  type ScoringProfile,
  type ScoringResult,
  type CarverScores,
  type ShockScores,
  type RescoringEvent,
  type CriticalityTier,
  type Fips199Category,
} from "../lib/scoring-engine";
import {
  getIndustryVerticals,
  getIndustryTierBreakdown,
  computeIndustryEnhancedScore,
  batchIndustryScore,
  computeIndustryModifier,
  detectAllSignals,
  inferBiaFromSignals,
  determineShockLevel,
  computeFips199HighWatermark,
  computeFips199Adjustments,
  getFips199IndustryDefault,
  INDUSTRY_ASSET_BASELINES,
  INDUSTRY_RISK_MODIFIERS,
  TIER_WEIGHTS,
  HYBRID_FORMULA,
  SHOCK_MULTIPLIER_GUIDANCE,
  AUTO_BIA_RULES,
  FIPS_199_LEVEL_MAP,
  FIPS_199_INDUSTRY_DEFAULTS,
  type IndustryVertical,
  type AssetTier,
  type Fips199Category,
  type Fips199Level,
} from "../lib/industry-baseline-scoring";

async function getDbSafe() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

/** Build a ScoringInput from an asset row, applying mission function baselines and CVSS v4.0 feed-through */
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
    // Enhanced v4.0 fields
    cvssV4Vector: asset.cvssV4Vector ?? undefined,
    fips199: asset.fips199Category ? (asset.fips199Category as Fips199Category) : undefined,
    criticalityTier: asset.criticalityTier ?? undefined,
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
      deviceTypes: ASSET_DEVICE_TYPES.filter(t => t !== "unknown").map(dt => ({
        key: dt,
        label: dt.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
      })),
      platformTypes: ASSET_PLATFORM_TYPES.filter(t => t !== "unknown").map(pt => ({
        key: pt,
        label: pt.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
      })),
      criticalityTiers: Object.entries(CRITICALITY_TIERS).map(([tier, def]) => ({
        tier: Number(tier),
        name: def.name,
        rto: def.rto,
        description: def.description,
        missionMultiplier: def.missionMultiplier,
      })),
    };
  }),

  /** Get CARVER+Shock digital translation reference (FM 34-36 aligned) */
  getCarverReference: protectedProcedure.query(() => {
    return {
      carver: CARVER_DIGITAL_TRANSLATION,
      shock: SHOCK_DIGITAL_TRANSLATION,
    };
  }),

  /** Get available discovery phase triggers */
  getDiscoveryTriggers: protectedProcedure.query(() => {
    return Object.entries(DISCOVERY_PHASE_TRIGGERS).map(([key, val]) => ({
      key,
      description: val.description,
    }));
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

  // ─── CVSS v4.0 Operations ──────────────────────────────────────────

  /** Parse a CVSS v4.0 vector string and return structured metrics + CARVER feed-through */
  parseCvssV4: protectedProcedure
    .input(z.object({ vector: z.string() }))
    .query(({ input }) => {
      const parsed = parseCvssV4Vector(input.vector);
      if (!parsed) return { error: "Invalid CVSS v4.0 vector string", parsed: null, feedThrough: null };

      const feedThrough = cvssV4ToCarverAdjustments(parsed);
      return { error: null, parsed, feedThrough };
    }),

  /** Build a CVSS v4.0 vector string from individual metrics */
  buildCvssV4Vector: protectedProcedure
    .input(z.object({
      AV: z.enum(["N", "A", "L", "P"]),
      AC: z.enum(["L", "H"]),
      AT: z.enum(["N", "P"]),
      PR: z.enum(["N", "L", "H"]),
      UI: z.enum(["N", "P", "A"]),
      VC: z.enum(["N", "L", "H"]),
      VI: z.enum(["N", "L", "H"]),
      VA: z.enum(["N", "L", "H"]),
      SC: z.enum(["N", "L", "H"]),
      SI: z.enum(["N", "L", "H"]),
      SA: z.enum(["N", "L", "H"]),
      E: z.enum(["X", "A", "P", "U"]).optional(),
      CR: z.enum(["X", "H", "M", "L"]).optional(),
      IR: z.enum(["X", "H", "M", "L"]).optional(),
      AR: z.enum(["X", "H", "M", "L"]).optional(),
      S: z.enum(["X", "N", "P"]).optional(),
      AU: z.enum(["X", "N", "Y"]).optional(),
      R: z.enum(["X", "A", "U", "I"]).optional(),
      V: z.enum(["X", "D", "C"]).optional(),
      RE: z.enum(["X", "L", "M", "H"]).optional(),
    }))
    .query(({ input }) => {
      const vector = buildCvssV4Vector(input);
      const parsed = parseCvssV4Vector(vector);
      return { vector, parsed };
    }),

  /** Apply CVSS v4.0 vector to an asset and re-score */
  applyCvssV4ToAsset: protectedProcedure
    .input(z.object({
      assetId: z.number(),
      cvssV4Vector: z.string(),
      profileId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [asset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      if (!asset) throw new Error("Asset not found");

      const parsed = parseCvssV4Vector(input.cvssV4Vector);
      if (!parsed) throw new Error("Invalid CVSS v4.0 vector string");

      // Store the vector on the asset
      await db.update(discoveredAssets).set({
        cvssV4Vector: input.cvssV4Vector,
        cvssEstimate: Math.round(parsed.estimatedScore),
      }).where(eq(discoveredAssets.id, input.assetId));

      // Re-score with the new vector
      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      // Re-fetch asset with updated vector
      const [updatedAsset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      const scoringInput = buildScoringInput(updatedAsset, profile);
      const result = computeHybridRisk(scoringInput, profile);

      const previousScore = asset.hybridRiskScore ?? 0;
      const previousBand = asset.riskBand ?? "low";

      await db.update(discoveredAssets).set({
        hybridRiskScore: result.hybridRiskScore,
        riskBand: result.riskBand,
        missionImpactScore: Math.round(result.missionImpactScore * 10) / 10,
        impactScore: result.impactScore,
        likelihoodScore: result.likelihoodScore,
        scoringVersion: sql`COALESCE(${discoveredAssets.scoringVersion}, 0) + 1`,
        lastScoredAt: new Date(),
        scoringProfileId: input.profileId ?? null,
      }).where(eq(discoveredAssets.id, input.assetId));

      await db.insert(scoringAuditLog).values({
        assetId: input.assetId,
        scanId: asset.scanId,
        profileId: input.profileId ?? null,
        carverScores: scoringInput.carver,
        shockScores: scoringInput.shock,
        cvssEstimate: parsed.estimatedScore,
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
        cvssV4: parsed,
        feedThrough: cvssV4ToCarverAdjustments(parsed),
      };
    }),

  // ─── FIPS 199 Categorization ──────────────────────────────────────

  /** Apply FIPS 199 security categorization to an asset */
  applyFips199: protectedProcedure
    .input(z.object({
      assetId: z.number(),
      confidentiality: z.enum(["low", "moderate", "high"]),
      integrity: z.enum(["low", "moderate", "high"]),
      availability: z.enum(["low", "moderate", "high"]),
      profileId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [asset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      if (!asset) throw new Error("Asset not found");

      const fips199: Fips199Category = {
        confidentiality: input.confidentiality,
        integrity: input.integrity,
        availability: input.availability,
      };

      // Store FIPS 199 on the asset
      await db.update(discoveredAssets).set({
        fips199Category: fips199,
      }).where(eq(discoveredAssets.id, input.assetId));

      // Re-score
      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      const [updatedAsset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      const scoringInput = buildScoringInput(updatedAsset, profile);
      const result = computeHybridRisk(scoringInput, profile);

      const previousScore = asset.hybridRiskScore ?? 0;

      await db.update(discoveredAssets).set({
        hybridRiskScore: result.hybridRiskScore,
        riskBand: result.riskBand,
        missionImpactScore: Math.round(result.missionImpactScore * 10) / 10,
        impactScore: result.impactScore,
        likelihoodScore: result.likelihoodScore,
        scoringVersion: sql`COALESCE(${discoveredAssets.scoringVersion}, 0) + 1`,
        lastScoredAt: new Date(),
      }).where(eq(discoveredAssets.id, input.assetId));

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

      const fipsAdjustments = fips199ToCarverAdjustments(fips199);

      return {
        ...result,
        delta: result.hybridRiskScore - previousScore,
        fips199Applied: fips199,
        fipsAdjustments,
      };
    }),

  // ─── Criticality Tier Management ──────────────────────────────────

  /** Assign a criticality tier (1-5) to an asset and re-score */
  assignCriticalityTier: protectedProcedure
    .input(z.object({
      assetId: z.number(),
      tier: z.number().min(1).max(5),
      profileId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [asset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      if (!asset) throw new Error("Asset not found");

      const tier = input.tier as CriticalityTier;
      const tierDef = CRITICALITY_TIERS[tier];

      await db.update(discoveredAssets).set({
        criticalityTier: tier,
      }).where(eq(discoveredAssets.id, input.assetId));

      // Re-score
      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      const [updatedAsset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      const scoringInput = buildScoringInput(updatedAsset, profile);
      const result = computeHybridRisk(scoringInput, profile);

      const previousScore = asset.hybridRiskScore ?? 0;

      await db.update(discoveredAssets).set({
        hybridRiskScore: result.hybridRiskScore,
        riskBand: result.riskBand,
        missionImpactScore: Math.round(result.missionImpactScore * 10) / 10,
        impactScore: result.impactScore,
        likelihoodScore: result.likelihoodScore,
        scoringVersion: sql`COALESCE(${discoveredAssets.scoringVersion}, 0) + 1`,
        lastScoredAt: new Date(),
      }).where(eq(discoveredAssets.id, input.assetId));

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
        tierApplied: {
          tier,
          name: tierDef.name,
          rto: tierDef.rto,
          missionMultiplier: tierDef.missionMultiplier,
        },
      };
    }),

  // ─── Dynamic Re-Scoring (Discovery Phase Triggers) ────────────────

  /** Apply a discovery phase trigger to an asset and re-score dynamically */
  applyDiscoveryTrigger: protectedProcedure
    .input(z.object({
      assetId: z.number(),
      triggerType: z.string(),
      triggerData: z.any().default({}),
      profileId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [asset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      if (!asset) throw new Error("Asset not found");

      const currentCarver: CarverScores = (asset.carverScores as any) || {
        criticality: 3, accessibility: 3, recuperability: 3,
        vulnerability: 3, effect: 3, recognizability: 3,
      };
      const currentShock: ShockScores = (asset.shockScores as any) || {
        scope: 3, handling: 3, operationalImpact: 3,
        cascadingEffects: 3, knowledge: 3,
      };

      const { carver: newCarver, shock: newShock, likelihoodBoost } =
        applyDiscoveryTrigger(input.triggerType, input.triggerData, currentCarver, currentShock);

      // Update the raw CARVER/Shock scores on the asset
      await db.update(discoveredAssets).set({
        carverScores: newCarver,
        shockScores: newShock,
      }).where(eq(discoveredAssets.id, input.assetId));

      // Re-score with updated factors
      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      const [updatedAsset] = await db.select().from(discoveredAssets).where(eq(discoveredAssets.id, input.assetId));
      const scoringInput = buildScoringInput(updatedAsset, profile);
      // Add the likelihood boost from the trigger
      scoringInput.portLikelihoodBoost = (scoringInput.portLikelihoodBoost ?? 0) + likelihoodBoost;

      const result = computeHybridRisk(scoringInput, profile);

      const previousScore = asset.hybridRiskScore ?? 0;
      const previousBand = asset.riskBand ?? "low";

      await db.update(discoveredAssets).set({
        hybridRiskScore: result.hybridRiskScore,
        riskBand: result.riskBand,
        missionImpactScore: Math.round(result.missionImpactScore * 10) / 10,
        impactScore: result.impactScore,
        likelihoodScore: result.likelihoodScore,
        scoringVersion: sql`COALESCE(${discoveredAssets.scoringVersion}, 0) + 1`,
        lastScoredAt: new Date(),
      }).where(eq(discoveredAssets.id, input.assetId));

      await db.insert(scoringAuditLog).values({
        assetId: input.assetId,
        scanId: asset.scanId,
        profileId: input.profileId ?? null,
        carverScores: newCarver,
        shockScores: newShock,
        cvssEstimate: asset.cvssEstimate ?? 5,
        missionImpactScore: result.missionImpactScore,
        impactScore: result.impactScore,
        likelihoodScore: result.likelihoodScore,
        hybridRiskScore: result.hybridRiskScore,
        riskBand: result.riskBand,
        weightsSnapshot: profile,
        computedBy: ctx.user.openId,
      });

      // Build factor changes for the event
      const factorChanges: Array<{ factor: string; previousValue: number; newValue: number; reason: string }> = [];
      for (const key of Object.keys(currentCarver) as (keyof CarverScores)[]) {
        if (newCarver[key] !== currentCarver[key]) {
          factorChanges.push({
            factor: `CARVER.${key}`,
            previousValue: currentCarver[key],
            newValue: newCarver[key],
            reason: `Discovery trigger: ${input.triggerType}`,
          });
        }
      }
      for (const key of Object.keys(currentShock) as (keyof ShockScores)[]) {
        if (newShock[key] !== currentShock[key]) {
          factorChanges.push({
            factor: `Shock.${key}`,
            previousValue: currentShock[key],
            newValue: newShock[key],
            reason: `Discovery trigger: ${input.triggerType}`,
          });
        }
      }

      const event: RescoringEvent = {
        trigger: input.triggerType as any,
        assetId: String(input.assetId),
        previousScore,
        newScore: result.hybridRiskScore,
        previousBand,
        newBand: result.riskBand,
        delta: result.hybridRiskScore - previousScore,
        changeDescription: `Discovery trigger '${input.triggerType}' applied`,
        factorChanges,
        timestamp: Date.now(),
      };

      return {
        ...result,
        event,
        significant: isSignificantChange(event),
        factorChanges,
      };
    }),

  // ─── LLM Asset Classification (Enhanced) ──────────────────────────

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
        for (const [key, val] of Array.from(classifications.entries())) {
          allClassifications.set(key, val);
        }
      }

      const results: Array<{
        assetId: number;
        hostname: string;
        deviceType: string;
        platformType: string;
        missionFunction: string;
        essentialService: string;
        businessImpactLevel: string;
        assetPurpose: string;
        fips199Category: any;
        criticalityTier: number | null;
        confidence: number;
      }> = [];

      for (const asset of assets) {
        const assetKey = asset.assetId || `asset-${asset.id}`;
        const classification = allClassifications.get(assetKey);
        if (!classification) continue;

        const updateData: any = {
          missionFunction: classification.missionFunction,
          essentialService: classification.essentialService,
          assetPurpose: classification.assetPurpose,
          businessImpactLevel: classification.businessImpactLevel,
          missionDependencies: classification.missionDependencies,
          llmClassification: classification,
        };

        // Store enhanced classification fields if available
        if (classification.fips199Category) {
          updateData.fips199Category = classification.fips199Category;
        }
        if (classification.criticalityTier) {
          updateData.criticalityTier = classification.criticalityTier;
        }
        if (classification.deviceType) {
          updateData.deviceType = classification.deviceType;
        }
        if (classification.platformType) {
          updateData.platformType = classification.platformType;
        }

        await db
          .update(discoveredAssets)
          .set(updateData)
          .where(eq(discoveredAssets.id, asset.id));

        results.push({
          assetId: asset.id,
          hostname: asset.hostname,
          deviceType: classification.deviceType || "unknown",
          platformType: classification.platformType || "unknown",
          missionFunction: classification.missionFunction,
          essentialService: classification.essentialService,
          businessImpactLevel: classification.businessImpactLevel,
          assetPurpose: classification.assetPurpose,
          fips199Category: classification.fips199Category || null,
          criticalityTier: classification.criticalityTier || null,
          confidence: classification.classificationConfidence,
        });
      }

      return { classified: results.length, results };
    }),

  updateAssetClassification: protectedProcedure
    .input(
      z.object({
        assetId: z.number(),
        missionFunction: z.string().optional(),
        essentialService: z.string().optional(),
        businessImpactLevel: z.string().optional(),
        assetPurpose: z.string().optional(),
        deviceType: z.string().optional(),
        platformType: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const { assetId, ...updates } = input;
      const setData: any = {};
      for (const [key, val] of Object.entries(updates)) {
        if (val !== undefined) setData[key] = val;
      }
      await db.update(discoveredAssets).set(setData).where(eq(discoveredAssets.id, assetId));
      return { success: true };
    }),

  // ─── Scoring Operations ───────────────────────────────────────────

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
        criticalityTier: number | null;
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
          criticalityTier: asset.criticalityTier,
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

      for (const asset of assets) {
        const assetKey = asset.assetId || `asset-${asset.id}`;
        const classification = allClassifications.get(assetKey);
        if (!classification) continue;
        const updateData: any = {
          missionFunction: classification.missionFunction,
          essentialService: classification.essentialService,
          assetPurpose: classification.assetPurpose,
          businessImpactLevel: classification.businessImpactLevel,
          missionDependencies: classification.missionDependencies,
          llmClassification: classification,
        };
        if (classification.fips199Category) updateData.fips199Category = classification.fips199Category;
        if (classification.criticalityTier) updateData.criticalityTier = classification.criticalityTier;
        if (classification.deviceType) updateData.deviceType = classification.deviceType;
        if (classification.platformType) updateData.platformType = classification.platformType;
        await db.update(discoveredAssets).set(updateData).where(eq(discoveredAssets.id, asset.id));
      }

      let profile: ScoringProfile = DEFAULT_PROFILE;
      if (input.profileId) {
        const [row] = await db.select().from(scoringProfiles).where(eq(scoringProfiles.id, input.profileId));
        if (row) profile = dbProfileToScoringProfile(row);
      }

      const updatedAssets = await db.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));

      const results: Array<{
        assetId: number;
        hostname: string;
        missionFunction: string | null;
        essentialService: string | null;
        businessImpactLevel: string | null;
        criticalityTier: number | null;
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
          criticalityTier: asset.criticalityTier,
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

  /** Simulate scoring with a profile (preview mode, no save) — enhanced with CVSS v4.0 */
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
        cvssV4Vector: z.string().optional(),
        fips199: z.object({
          confidentiality: z.enum(["low", "moderate", "high"]),
          integrity: z.enum(["low", "moderate", "high"]),
          availability: z.enum(["low", "moderate", "high"]),
        }).optional(),
        criticalityTier: z.number().min(1).max(5).optional(),
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
        cvssV4Vector: input.cvssV4Vector,
        fips199: input.fips199,
        criticalityTier: input.criticalityTier as CriticalityTier | undefined,
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
          criticalityTier: discoveredAssets.criticalityTier,
          fips199Category: discoveredAssets.fips199Category,
          cvssV4Vector: discoveredAssets.cvssV4Vector,
        })
        .from(discoveredAssets)
        .where(eq(discoveredAssets.scanId, input.scanId))
        .orderBy(desc(discoveredAssets.hybridRiskScore));

      const heatMapAssets = assets.map(a => ({
        ...a,
        heatColor: riskScoreToHeatColor(a.hybridRiskScore ?? 0),
        intensity: Math.min(1, (a.hybridRiskScore ?? 0) / 100),
      }));

      const scores = assets.map(a => a.hybridRiskScore ?? 0);
      const total = scores.length;
      const avg = total > 0 ? scores.reduce((a, b) => a + b, 0) / total : 0;
      const critical = scores.filter(s => s >= 85).length;
      const high = scores.filter(s => s >= 65 && s < 85).length;
      const medium = scores.filter(s => s >= 40 && s < 65).length;
      const low = scores.filter(s => s < 40).length;

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

      const impactDist: Record<string, number> = {};
      for (const a of assets) {
        const bil = a.businessImpactLevel || "unclassified";
        impactDist[bil] = (impactDist[bil] || 0) + 1;
      }

      // Criticality tier distribution
      const tierDist: Record<string, number> = {};
      for (const a of assets) {
        const tier = a.criticalityTier ? `Tier ${a.criticalityTier}` : "Unassigned";
        tierDist[tier] = (tierDist[tier] || 0) + 1;
      }

      return {
        assets: heatMapAssets,
        stats: {
          total,
          averageScore: Math.round(avg),
          distribution: { critical, high, medium, low },
          missionFunctionDistribution: missionFunctionDist,
          businessImpactDistribution: impactDist,
          criticalityTierDistribution: tierDist,
        },
      };
    }),

  // ─── Scoring Timeline (Dynamic Scoring History) ───────────────────

  /** Get scoring history for an asset to visualize score changes over time */
  getAssetScoringTimeline: protectedProcedure
    .input(z.object({
      assetId: z.number(),
      limit: z.number().min(1).max(100).default(20),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      return db
        .select()
        .from(scoringAuditLog)
        .where(eq(scoringAuditLog.assetId, input.assetId))
        .orderBy(desc(scoringAuditLog.computedAt))
        .limit(input.limit);
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

  // ═══════════════════════════════════════════════════════════════════
  // INDUSTRY BASELINE SCORING ENDPOINTS
  // ═══════════════════════════════════════════════════════════════════

  /** Get all supported industry verticals */
  getIndustryVerticals: protectedProcedure.query(() => {
    return getIndustryVerticals();
  }),

  /** Get tier breakdown for a specific industry */
  getIndustryTierBreakdown: protectedProcedure
    .input(z.object({
      industry: z.enum([
        "Corporate_Enterprise",
        "Industrial_OT_Manufacturing",
        "Government_Federal_State",
        "Healthcare",
        "Financial_Services",
        "Energy_Utilities",
      ]),
    }))
    .query(({ input }) => {
      return {
        tiers: getIndustryTierBreakdown(input.industry),
        modifiers: computeIndustryModifier(input.industry),
        formula: HYBRID_FORMULA,
        shockGuidance: SHOCK_MULTIPLIER_GUIDANCE,
        autoBiaRules: AUTO_BIA_RULES,
      };
    }),

  /** Compute industry-enhanced score for a single asset */
  computeIndustryScore: protectedProcedure
    .input(z.object({
      carverTotal: z.number().min(0).max(70),
      cvssScore: z.number().min(0).max(10),
      shockComposite: z.number().min(0).max(10),
      industry: z.enum([
        "Corporate_Enterprise",
        "Industrial_OT_Manufacturing",
        "Government_Federal_State",
        "Healthcare",
        "Financial_Services",
        "Energy_Utilities",
      ]),
      assetInfo: z.object({
        hostname: z.string().optional(),
        assetType: z.string().optional(),
        services: z.array(z.string()).optional(),
        technologies: z.array(z.string()).optional(),
        ports: z.array(z.number()).optional(),
        description: z.string().optional(),
        tags: z.array(z.string()).optional(),
      }),
      biaMultiplierOverride: z.number().min(1.0).max(2.0).optional(),
      tierOverride: z.enum(["Tier_1_Strategic", "Tier_2_Operational", "Tier_3_Tactical"]).optional(),
    }))
    .mutation(({ input }) => {
      return computeIndustryEnhancedScore(input);
    }),

  /** Batch score assets with industry context */
  batchIndustryScore: protectedProcedure
    .input(z.object({
      industry: z.enum([
        "Corporate_Enterprise",
        "Industrial_OT_Manufacturing",
        "Government_Federal_State",
        "Healthcare",
        "Financial_Services",
        "Energy_Utilities",
      ]),
      assets: z.array(z.object({
        assetId: z.string(),
        carverTotal: z.number().min(0).max(70),
        cvssScore: z.number().min(0).max(10),
        shockComposite: z.number().min(0).max(10),
        assetInfo: z.object({
          hostname: z.string().optional(),
          assetType: z.string().optional(),
          services: z.array(z.string()).optional(),
          technologies: z.array(z.string()).optional(),
          ports: z.array(z.number()).optional(),
          description: z.string().optional(),
          tags: z.array(z.string()).optional(),
        }),
        biaMultiplierOverride: z.number().optional(),
        tierOverride: z.enum(["Tier_1_Strategic", "Tier_2_Operational", "Tier_3_Tactical"]).optional(),
      })),
    }))
    .mutation(({ input }) => {
      return batchIndustryScore(input.assets, input.industry);
    }),

  /** Detect asset signals and infer BIA */
  detectAssetSignals: protectedProcedure
    .input(z.object({
      hostname: z.string().optional(),
      services: z.array(z.string()).optional(),
      technologies: z.array(z.string()).optional(),
      ports: z.array(z.number()).optional(),
      description: z.string().optional(),
    }))
    .query(({ input }) => {
      const signals = detectAllSignals(input);
      const primaryBia = inferBiaFromSignals(input);
      return { signals, primaryBia };
    }),

  /** Get industry risk modifiers for comparison */
  getIndustryModifiers: protectedProcedure.query(() => {
    return INDUSTRY_RISK_MODIFIERS;
  }),

  // ═══════════════════════════════════════════════════════════════════
  // FIPS 199 SECURITY CATEGORIZATION ENDPOINTS
  // ═══════════════════════════════════════════════════════════════════

  /** Get FIPS 199 industry defaults for a specific industry + tier */
  getFips199Defaults: protectedProcedure
    .input(z.object({
      industry: z.enum([
        "Corporate_Enterprise",
        "Industrial_OT_Manufacturing",
        "Government_Federal_State",
        "Healthcare",
        "Financial_Services",
        "Energy_Utilities",
      ]),
      tier: z.enum(["Tier_1_Strategic", "Tier_2_Operational", "Tier_3_Tactical"]),
    }))
    .query(({ input }) => {
      const defaults = getFips199IndustryDefault(input.industry, input.tier);
      const adjustments = computeFips199Adjustments(defaults);
      return {
        category: defaults,
        adjustments,
        levelMap: FIPS_199_LEVEL_MAP,
      };
    }),

  /** Compute FIPS 199 adjustments from custom categorization */
  computeFips199: protectedProcedure
    .input(z.object({
      access: z.object({
        confidentiality: z.enum(["low", "moderate", "high"]),
        integrity: z.enum(["low", "moderate", "high"]),
        availability: z.enum(["low", "moderate", "high"]),
      }),
      storage: z.object({
        confidentiality: z.enum(["low", "moderate", "high"]),
        integrity: z.enum(["low", "moderate", "high"]),
        availability: z.enum(["low", "moderate", "high"]),
      }),
      transit: z.object({
        confidentiality: z.enum(["low", "moderate", "high"]),
        integrity: z.enum(["low", "moderate", "high"]),
        availability: z.enum(["low", "moderate", "high"]),
      }),
    }))
    .mutation(({ input }) => {
      const adjustments = computeFips199Adjustments(input);
      return { adjustments };
    }),

  /** Get all FIPS 199 industry defaults for comparison view */
  getAllFips199Defaults: protectedProcedure.query(() => {
    return FIPS_199_INDUSTRY_DEFAULTS;
  }),
});
