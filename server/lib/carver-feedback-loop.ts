/**
 * CARVER Feedback Loop
 *
 * Closes 3 critical gaps between LLM intelligence and CARVER scoring:
 *
 * 1. Post-enrichment LLM analysis → CARVER score adjustments
 *    Assets identified in attack chains get CARVER factor boosts
 *    (e.g., an asset in a critical attack chain gets higher accessibility/vulnerability)
 *
 * 2. CARVER-aware threat intel boosts (replaces flat +3)
 *    Trending exploits boost CARVER.vulnerability specifically
 *    Active threat actor targeting boosts CARVER.recognizability
 *    Exposed services boost CARVER.accessibility
 *
 * 3. Discovery context signals → CARVER reasoning
 *    Recently registered domains → CARVER.recognizability boost
 *    DNS changes → CARVER.effect boost (infrastructure instability)
 *    Shadow IT / unmanaged assets → CARVER.criticality boost
 *
 * Runs as Stage 3.995 — AFTER post-enrichment analysis (3.99) but BEFORE
 * overall risk calculation. This ensures LLM intelligence feeds back into
 * the scoring model before final risk bands are assigned.
 */

import type { AssetAnalysis, CarverScores, ShockScores } from "../domainIntel";
import type { PostEnrichmentAnalysis, AttackPath } from "./llm-post-enrichment-analysis";
import type { CrossModuleEnrichmentResult } from "./cross-module-enrichment";
import type { PassiveReconResult } from "./passive/index";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CarverFeedbackResult {
  adjustments: CarverAdjustment[];
  attackChainAssets: Map<string, AttackChainContext>;
  discoverySignals: DiscoverySignal[];
  threatIntelFactorBoosts: ThreatIntelFactorBoost[];
  summary: {
    totalAdjustments: number;
    assetsAffected: number;
    avgScoreChange: number;
    attackChainAssetsCount: number;
    discoverySignalsCount: number;
    threatIntelBoostsCount: number;
  };
}

export interface CarverAdjustment {
  assetId: string;
  hostname: string;
  source: "attack_chain" | "threat_intel" | "discovery_context" | "blind_spot";
  factor: keyof CarverScores | keyof ShockScores | "hybrid";
  previousValue: number;
  newValue: number;
  delta: number;
  reason: string;
  confidence: number; // 0-1
}

export interface AttackChainContext {
  chainIds: string[];
  chainNames: string[];
  positionInChains: Array<{ chainId: string; stepOrder: number; role: "entry_point" | "pivot" | "objective" }>;
  aggregateRisk: number;
  techniques: string[];
}

export interface DiscoverySignal {
  assetId: string;
  signalType: "recently_registered" | "dns_change" | "shadow_it" | "unmanaged" | "new_subdomain" | "certificate_change" | "whois_change" | "privacy_protected";
  description: string;
  carverFactor: keyof CarverScores;
  boost: number;
  evidence: Record<string, any>;
}

export interface ThreatIntelFactorBoost {
  assetId: string;
  hostname: string;
  originalAdjustment: number; // The old flat +3
  factorBoosts: Array<{
    factor: keyof CarverScores;
    boost: number;
    reason: string;
  }>;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/** Maximum per-factor adjustment from any single source */
const MAX_FACTOR_BOOST = 2;

/** Maximum cumulative adjustment across all sources for a single factor */
const MAX_CUMULATIVE_BOOST = 3;

/** Attack chain position multipliers */
const CHAIN_POSITION_WEIGHTS: Record<string, number> = {
  entry_point: 1.0,   // Entry points get full boost
  pivot: 0.7,         // Pivot points get 70%
  objective: 0.5,     // Objectives already have high criticality
};

/** Difficulty-to-accessibility mapping */
const DIFFICULTY_ACCESSIBILITY_MAP: Record<string, number> = {
  trivial: 2.0,
  easy: 1.5,
  moderate: 1.0,
  hard: 0.5,
  expert: 0.0,
};

// ─── Main Function ──────────────────────────────────────────────────────────

export function applyCarverFeedbackLoop(
  analyses: AssetAnalysis[],
  postEnrichment: PostEnrichmentAnalysis | undefined,
  crossModuleData: CrossModuleEnrichmentResult | undefined,
  passiveRecon: PassiveReconResult | undefined,
): CarverFeedbackResult {
  const adjustments: CarverAdjustment[] = [];
  const attackChainAssets = new Map<string, AttackChainContext>();
  const discoverySignals: DiscoverySignal[] = [];
  const threatIntelFactorBoosts: ThreatIntelFactorBoost[] = [];

  // Track cumulative boosts per asset per factor to enforce caps
  const cumulativeBoosts = new Map<string, Map<string, number>>();

  function getCumulative(assetId: string, factor: string): number {
    return cumulativeBoosts.get(assetId)?.get(factor) || 0;
  }

  function addCumulative(assetId: string, factor: string, boost: number): number {
    if (!cumulativeBoosts.has(assetId)) cumulativeBoosts.set(assetId, new Map());
    const current = getCumulative(assetId, factor);
    const capped = Math.min(boost, MAX_CUMULATIVE_BOOST - current);
    if (capped <= 0) return 0;
    cumulativeBoosts.get(assetId)!.set(factor, current + capped);
    return capped;
  }

  function applyFactorBoost(
    analysis: AssetAnalysis,
    factor: keyof CarverScores,
    rawBoost: number,
    source: CarverAdjustment["source"],
    reason: string,
    confidence: number,
  ): CarverAdjustment | null {
    const cappedBoost = Math.min(rawBoost, MAX_FACTOR_BOOST);
    const effectiveBoost = addCumulative(analysis.asset.assetId, factor, cappedBoost);
    if (effectiveBoost <= 0) return null;

    const prev = analysis.carverScores[factor];
    const newVal = Math.min(10, prev + effectiveBoost);
    analysis.carverScores[factor] = newVal;

    const adj: CarverAdjustment = {
      assetId: analysis.asset.assetId,
      hostname: analysis.asset.hostname,
      source,
      factor,
      previousValue: prev,
      newValue: newVal,
      delta: newVal - prev,
      reason,
      confidence,
    };
    adjustments.push(adj);
    return adj;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 1. ATTACK CHAIN → CARVER ADJUSTMENTS
  // ═══════════════════════════════════════════════════════════════════════

  if (postEnrichment?.attackPaths?.length) {
    for (const chain of postEnrichment.attackPaths) {
      if (!chain.steps?.length) continue;

      for (const step of chain.steps) {
        // Find the asset referenced in this attack step
        const targetAsset = step.targetAsset?.toLowerCase() || "";
        const matchedAnalysis = analyses.find(a =>
          a.asset.hostname.toLowerCase().includes(targetAsset) ||
          targetAsset.includes(a.asset.hostname.toLowerCase()) ||
          a.asset.assetId === targetAsset
        );
        if (!matchedAnalysis) continue;

        const assetId = matchedAnalysis.asset.assetId;

        // Determine position role in the chain
        const isFirst = step.order === 1 || step.order === Math.min(...chain.steps.map(s => s.order));
        const isLast = step.order === Math.max(...chain.steps.map(s => s.order));
        const role: "entry_point" | "pivot" | "objective" = isFirst ? "entry_point" : isLast ? "objective" : "pivot";
        const positionWeight = CHAIN_POSITION_WEIGHTS[role] || 0.5;

        // Build attack chain context
        if (!attackChainAssets.has(assetId)) {
          attackChainAssets.set(assetId, {
            chainIds: [],
            chainNames: [],
            positionInChains: [],
            aggregateRisk: 0,
            techniques: [],
          });
        }
        const ctx = attackChainAssets.get(assetId)!;
        if (!ctx.chainIds.includes(chain.id)) {
          ctx.chainIds.push(chain.id);
          ctx.chainNames.push(chain.name);
        }
        ctx.positionInChains.push({ chainId: chain.id, stepOrder: step.order, role });
        ctx.aggregateRisk = Math.max(ctx.aggregateRisk, chain.overallRisk);
        if (step.technique && !ctx.techniques.includes(step.technique)) {
          ctx.techniques.push(step.technique);
        }

        // Apply CARVER boosts based on chain position and difficulty
        const chainRiskFactor = Math.min(chain.overallRisk / 100, 1);
        const difficultyBoost = DIFFICULTY_ACCESSIBILITY_MAP[step.difficulty] || 0;

        // Entry points: boost accessibility (attacker can reach them)
        if (role === "entry_point") {
          applyFactorBoost(
            matchedAnalysis,
            "accessibility",
            (1.0 + difficultyBoost * 0.5) * positionWeight * chainRiskFactor,
            "attack_chain",
            `Entry point in attack chain "${chain.name}" (difficulty: ${step.difficulty}, chain risk: ${chain.overallRisk}/100)`,
            0.8,
          );
          // Entry points also get vulnerability boost if difficulty is low
          if (difficultyBoost >= 1.0) {
            applyFactorBoost(
              matchedAnalysis,
              "vulnerability",
              difficultyBoost * 0.5 * chainRiskFactor,
              "attack_chain",
              `Low-difficulty entry point in chain "${chain.name}" — ${step.technique}`,
              0.7,
            );
          }
        }

        // Pivot points: boost vulnerability (they enable lateral movement)
        if (role === "pivot") {
          applyFactorBoost(
            matchedAnalysis,
            "vulnerability",
            (0.8 + difficultyBoost * 0.3) * positionWeight * chainRiskFactor,
            "attack_chain",
            `Pivot point in attack chain "${chain.name}" — enables lateral movement via ${step.technique}`,
            0.7,
          );
        }

        // Objectives: boost effect (compromising them has high impact)
        if (role === "objective") {
          applyFactorBoost(
            matchedAnalysis,
            "effect",
            1.5 * positionWeight * chainRiskFactor,
            "attack_chain",
            `Objective of attack chain "${chain.name}" — compromise would achieve attacker goal`,
            0.8,
          );
        }

        // All chain assets: boost recognizability (attacker knows about them)
        applyFactorBoost(
          matchedAnalysis,
          "recognizability",
          0.5 * chainRiskFactor,
          "attack_chain",
          `Asset appears in ${ctx.chainIds.length} attack chain(s) — increased attacker awareness`,
          0.6,
        );
      }
    }

    console.log(
      `[CarverFeedback] Attack chain analysis: ${attackChainAssets.size} assets in ` +
      `${postEnrichment.attackPaths.length} chains, ${adjustments.length} CARVER adjustments`
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 2. CARVER-AWARE THREAT INTEL BOOSTS (replaces flat +3)
  // ═══════════════════════════════════════════════════════════════════════

  if (crossModuleData?.threatIntel?.status === "success") {
    const ti = crossModuleData.threatIntel;

    for (const adj of ti.riskAdjustments) {
      const targetAnalysis = analyses.find(a => a.asset.assetId === adj.assetId);
      if (!targetAnalysis) continue;

      const factorBoosts: ThreatIntelFactorBoost["factorBoosts"] = [];
      const reason = adj.reason.toLowerCase();

      // Parse the reason to determine which CARVER factors to boost
      if (reason.includes("exploit") || reason.includes("vulnerability") || reason.includes("cve")) {
        // Trending exploit → boost vulnerability
        const boost = applyFactorBoost(
          targetAnalysis,
          "vulnerability",
          Math.min(adj.adjustment * 0.6, MAX_FACTOR_BOOST),
          "threat_intel",
          `Trending exploit targeting this asset's technology stack: ${adj.reason}`,
          0.8,
        );
        if (boost) factorBoosts.push({ factor: "vulnerability", boost: boost.delta, reason: adj.reason });
      }

      if (reason.includes("threat actor") || reason.includes("apt") || reason.includes("campaign")) {
        // Active threat actor targeting → boost recognizability
        const boost = applyFactorBoost(
          targetAnalysis,
          "recognizability",
          Math.min(adj.adjustment * 0.5, MAX_FACTOR_BOOST),
          "threat_intel",
          `Active threat actor campaign targeting this technology: ${adj.reason}`,
          0.7,
        );
        if (boost) factorBoosts.push({ factor: "recognizability", boost: boost.delta, reason: adj.reason });
      }

      if (reason.includes("exposed") || reason.includes("internet-facing") || reason.includes("public")) {
        // Exposed service in threat context → boost accessibility
        const boost = applyFactorBoost(
          targetAnalysis,
          "accessibility",
          Math.min(adj.adjustment * 0.4, MAX_FACTOR_BOOST),
          "threat_intel",
          `Internet-exposed service in active threat landscape: ${adj.reason}`,
          0.7,
        );
        if (boost) factorBoosts.push({ factor: "accessibility", boost: boost.delta, reason: adj.reason });
      }

      // If no specific factor matched, distribute across vulnerability + recognizability
      if (factorBoosts.length === 0) {
        const vulnBoost = applyFactorBoost(
          targetAnalysis,
          "vulnerability",
          Math.min(adj.adjustment * 0.4, MAX_FACTOR_BOOST),
          "threat_intel",
          `Threat intel risk adjustment: ${adj.reason}`,
          0.6,
        );
        if (vulnBoost) factorBoosts.push({ factor: "vulnerability", boost: vulnBoost.delta, reason: adj.reason });

        const recogBoost = applyFactorBoost(
          targetAnalysis,
          "recognizability",
          Math.min(adj.adjustment * 0.3, MAX_FACTOR_BOOST),
          "threat_intel",
          `Threat intel risk adjustment: ${adj.reason}`,
          0.6,
        );
        if (recogBoost) factorBoosts.push({ factor: "recognizability", boost: recogBoost.delta, reason: adj.reason });
      }

      if (factorBoosts.length > 0) {
        threatIntelFactorBoosts.push({
          assetId: adj.assetId,
          hostname: targetAnalysis.asset.hostname,
          originalAdjustment: adj.adjustment,
          factorBoosts,
        });
      }
    }

    // Matching threat actors → boost recognizability for all assets with matching tech
    if (ti.matchingThreatActors?.length > 0) {
      const highRelevanceActors = ti.matchingThreatActors.filter(a => a.relevance === "high");
      if (highRelevanceActors.length > 0) {
        for (const analysis of analyses) {
          const techs = (analysis.asset.technologies || []).map(t => t.toLowerCase());
          for (const actor of highRelevanceActors) {
            const actorTechniques = actor.techniques.map(t => t.toLowerCase());
            // Check if any asset technology matches actor techniques
            const hasMatch = techs.some(tech =>
              actorTechniques.some(at => at.includes(tech) || tech.includes(at))
            );
            if (hasMatch) {
              applyFactorBoost(
                analysis,
                "recognizability",
                0.5,
                "threat_intel",
                `High-relevance threat actor "${actor.name}" actively targets technology on this asset`,
                0.7,
              );
            }
          }
        }
      }
    }

    console.log(
      `[CarverFeedback] Threat intel factor boosts: ${threatIntelFactorBoosts.length} assets received ` +
      `CARVER-specific adjustments (replacing flat +3 boosts)`
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 3. DISCOVERY CONTEXT SIGNALS → CARVER REASONING
  // ═══════════════════════════════════════════════════════════════════════

  if (passiveRecon) {
    // Extract discovery signals from passive recon observations
    for (const cr of passiveRecon.connectorResults) {
      for (const obs of cr.observations) {
        const tags = obs.tags || [];
        const evidence = obs.evidence || {};

        // Recently registered domains → recognizability boost
        if (tags.includes("recently_registered") || evidence.recently_registered) {
          const matchedAnalysis = analyses.find(a =>
            a.asset.hostname.includes(obs.domain || "") ||
            obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal: DiscoverySignal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "recently_registered",
              description: `Domain registered within the last year — may indicate shadow IT, phishing infrastructure, or rapid expansion`,
              carverFactor: "recognizability",
              boost: 1.0,
              evidence: { registrationDate: evidence.registration_date, domainAge: evidence.domain_age },
            };
            discoverySignals.push(signal);
            applyFactorBoost(
              matchedAnalysis,
              "recognizability",
              1.0,
              "discovery_context",
              signal.description,
              0.8,
            );
          }
        }

        // DNS changes / new subdomains → effect boost (infrastructure instability)
        if (tags.includes("dns_change") || tags.includes("new_subdomain") || evidence.dns_changed) {
          const matchedAnalysis = analyses.find(a =>
            a.asset.hostname.includes(obs.domain || "") ||
            obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal: DiscoverySignal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "dns_change",
              description: `Recent DNS changes detected — may indicate infrastructure migration, misconfiguration, or takeover risk`,
              carverFactor: "effect",
              boost: 0.5,
              evidence: { changeType: evidence.change_type, previousValue: evidence.previous_value },
            };
            discoverySignals.push(signal);
            applyFactorBoost(
              matchedAnalysis,
              "effect",
              0.5,
              "discovery_context",
              signal.description,
              0.6,
            );
          }
        }

        // Shadow IT / unmanaged assets → criticality boost
        if (tags.includes("shadow_it") || tags.includes("unmanaged") || evidence.shadow_it) {
          const matchedAnalysis = analyses.find(a =>
            a.asset.hostname.includes(obs.domain || "") ||
            obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal: DiscoverySignal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "shadow_it",
              description: `Asset appears to be unmanaged or shadow IT — may lack security controls and patching`,
              carverFactor: "vulnerability",
              boost: 1.5,
              evidence: { indicators: evidence.shadow_it_indicators },
            };
            discoverySignals.push(signal);
            applyFactorBoost(
              matchedAnalysis,
              "vulnerability",
              1.5,
              "discovery_context",
              signal.description,
              0.7,
            );
            // Shadow IT also gets accessibility boost (likely less protected)
            applyFactorBoost(
              matchedAnalysis,
              "accessibility",
              1.0,
              "discovery_context",
              `Unmanaged asset likely has weaker access controls`,
              0.6,
            );
          }
        }

        // WHOIS privacy protected → recognizability context
        if (tags.includes("whois_privacy") || tags.includes("privacy_protected") || evidence.privacy_protected) {
          const matchedAnalysis = analyses.find(a =>
            a.asset.hostname.includes(obs.domain || "") ||
            obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal: DiscoverySignal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "privacy_protected",
              description: `WHOIS privacy protection enabled — may indicate desire to hide ownership or infrastructure details`,
              carverFactor: "recognizability",
              boost: 0.3,
              evidence: { registrar: evidence.registrar },
            };
            discoverySignals.push(signal);
            // Small recognizability boost — privacy protection slightly increases suspicion
            applyFactorBoost(
              matchedAnalysis,
              "recognizability",
              0.3,
              "discovery_context",
              signal.description,
              0.4,
            );
          }
        }

        // Certificate changes → effect boost
        if (tags.includes("certificate_change") || tags.includes("cert_expiring") || evidence.cert_expiring_soon) {
          const matchedAnalysis = analyses.find(a =>
            a.asset.hostname.includes(obs.domain || "") ||
            obs.domain?.includes(a.asset.hostname)
          );
          if (matchedAnalysis) {
            const signal: DiscoverySignal = {
              assetId: matchedAnalysis.asset.assetId,
              signalType: "certificate_change",
              description: `Certificate change or expiration detected — may indicate infrastructure changes or security gaps`,
              carverFactor: "vulnerability",
              boost: 0.5,
              evidence: { certExpiry: evidence.cert_expiry, certIssuer: evidence.cert_issuer },
            };
            discoverySignals.push(signal);
            applyFactorBoost(
              matchedAnalysis,
              "vulnerability",
              0.5,
              "discovery_context",
              signal.description,
              0.5,
            );
          }
        }
      }
    }

    console.log(
      `[CarverFeedback] Discovery context: ${discoverySignals.length} signals from passive recon ` +
      `applied to CARVER factors`
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 4. BLIND SPOT → CARVER ADJUSTMENTS
  // ═══════════════════════════════════════════════════════════════════════

  if (postEnrichment?.blindSpots?.length) {
    for (const blindSpot of postEnrichment.blindSpots) {
      if (blindSpot.severity !== "critical" && blindSpot.severity !== "high") continue;

      // Blind spots affect all assets in the relevant area
      const areaLower = blindSpot.area.toLowerCase();
      for (const analysis of analyses) {
        const hostname = analysis.asset.hostname.toLowerCase();
        const techs = (analysis.asset.technologies || []).map(t => t.toLowerCase());
        const tags = (analysis.asset.tags || []).map(t => t.toLowerCase());

        // Check if this asset is in the blind spot's area
        const isRelevant =
          areaLower.includes(hostname) ||
          hostname.includes(areaLower) ||
          techs.some(t => areaLower.includes(t)) ||
          tags.some(t => areaLower.includes(t));

        if (isRelevant) {
          // Blind spots indicate we may be underestimating risk
          applyFactorBoost(
            analysis,
            "vulnerability",
            blindSpot.severity === "critical" ? 1.0 : 0.5,
            "blind_spot",
            `Blind spot in "${blindSpot.area}": ${blindSpot.description}`,
            blindSpot.severity === "critical" ? 0.7 : 0.5,
          );
        }
      }
    }

    console.log(
      `[CarverFeedback] Blind spot adjustments: ${postEnrichment.blindSpots.filter(b => b.severity === "critical" || b.severity === "high").length} ` +
      `critical/high blind spots processed`
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════════

  const affectedAssets = new Set(adjustments.map(a => a.assetId));
  const avgDelta = adjustments.length > 0
    ? adjustments.reduce((sum, a) => sum + a.delta, 0) / adjustments.length
    : 0;

  const result: CarverFeedbackResult = {
    adjustments,
    attackChainAssets,
    discoverySignals,
    threatIntelFactorBoosts,
    summary: {
      totalAdjustments: adjustments.length,
      assetsAffected: affectedAssets.size,
      avgScoreChange: Math.round(avgDelta * 100) / 100,
      attackChainAssetsCount: attackChainAssets.size,
      discoverySignalsCount: discoverySignals.length,
      threatIntelBoostsCount: threatIntelFactorBoosts.length,
    },
  };

  console.log(
    `[CarverFeedback] Complete: ${adjustments.length} adjustments across ${affectedAssets.size} assets ` +
    `(avg delta: ${result.summary.avgScoreChange}). ` +
    `Attack chains: ${attackChainAssets.size}, Discovery signals: ${discoverySignals.length}, ` +
    `Threat intel boosts: ${threatIntelFactorBoosts.length}`
  );

  return result;
}
