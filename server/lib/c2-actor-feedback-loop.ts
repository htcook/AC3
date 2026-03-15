/**
 * C2 Learning → Actor Profile Feedback Loop
 *
 * When emulations succeed or fail, this module updates actor profiles
 * with environmental context. Over time, the platform learns which
 * actors' techniques work against which defenses — and discovers
 * new TTPs from execution artifacts.
 *
 * Data flow:
 *  1. C2 execution completes → processExecutionFeedback() fires
 *  2. This module intercepts the LearningOutcome
 *  3. Updates the actor profile with:
 *     - Technique reliability per environment
 *     - New artifacts/IOCs discovered during execution
 *     - Defense evasion success/failure patterns
 *     - Novel technique variations observed in output
 *  4. Feeds back into:
 *     - Actor Context Provider (enriched technique data)
 *     - Behavioral Sequence Engine (execution order validation)
 *     - Sigma Rule Engine (detection rule refinement from real telemetry)
 *     - Campaign Advisor (technique selection optimization)
 *
 * Author: Harrison Cook — AceofCloud
 */

import type {
  ExecutionFeedback,
  LearningOutcome,
  TechniqueReliability,
} from "./c2-learning-engine";
import {
  getHistoryForTechnique,
  calculateTechniqueReliability,
  getExecutionHistory,
  getLearningStats,
} from "./c2-learning-engine";
import { invokeLLM } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────────

/** Actor-specific technique performance record */
export interface ActorTechniquePerformance {
  techniqueId: string;
  techniqueName: string;
  actorName: string;
  /** Success rate in emulations (0-100) */
  emulationSuccessRate: number;
  /** Total execution attempts */
  totalAttempts: number;
  /** Successful executions */
  successCount: number;
  /** Environments where this technique succeeded */
  successfulEnvironments: EnvironmentProfile[];
  /** Environments where this technique failed */
  failedEnvironments: EnvironmentProfile[];
  /** Defenses that blocked this technique */
  blockedByDefenses: string[];
  /** Defenses this technique evaded */
  evadedDefenses: string[];
  /** Artifacts discovered during execution */
  discoveredArtifacts: DiscoveredArtifact[];
  /** Novel variations observed */
  novelVariations: NovelVariation[];
  /** Last updated */
  lastUpdated: string;
}

export interface EnvironmentProfile {
  os: string;
  platform: string;
  defenses: string[];
  networkSegment?: string;
  timestamp: string;
}

export interface DiscoveredArtifact {
  type: "ioc" | "credential" | "config" | "tool_output" | "new_technique";
  value: string;
  context: string;
  discoveredAt: string;
  feedbackApplied: boolean;
}

export interface NovelVariation {
  /** Original technique this is a variation of */
  baseTechniqueId: string;
  /** Description of the variation */
  description: string;
  /** What makes this different from the base technique */
  differentiator: string;
  /** Confidence that this is genuinely novel (0-100) */
  noveltyConfidence: number;
  /** Source execution that revealed this */
  sourceExecutionId: string;
  /** Whether this has been fed back into the knowledge base */
  fedBack: boolean;
}

/** Aggregated actor learning profile */
export interface ActorLearningProfile {
  actorName: string;
  /** Technique performance records */
  techniquePerformance: ActorTechniquePerformance[];
  /** Overall emulation success rate */
  overallSuccessRate: number;
  /** Most reliable techniques for this actor */
  mostReliableTechniques: { techniqueId: string; successRate: number }[];
  /** Techniques that consistently fail */
  unreliableTechniques: { techniqueId: string; failureRate: number; commonBlocker: string }[];
  /** Defense evasion effectiveness */
  defenseEvasionProfile: {
    defense: string;
    evasionRate: number;
    techniquesThatEvade: string[];
    techniquesThatFail: string[];
  }[];
  /** Novel TTPs discovered through emulation */
  discoveredTTPs: NovelVariation[];
  /** Total emulations run */
  totalEmulations: number;
  /** Last emulation date */
  lastEmulation: string;
}

/** Feedback event for cross-module consumption */
export interface FeedbackEvent {
  type: "technique_success" | "technique_failure" | "novel_ttp" | "defense_evasion" | "new_artifact";
  actorName: string;
  techniqueId: string;
  data: any;
  timestamp: string;
}

// ─── In-Memory Stores ───────────────────────────────────────────────────

const performanceStore = new Map<string, ActorTechniquePerformance[]>();
const feedbackEventLog: FeedbackEvent[] = [];
const MAX_EVENTS = 5000;

// ─── Core: Process Execution Feedback for Actor Profiles ────────────────

/**
 * Process a C2 execution outcome and update the relevant actor profile.
 * This is the main entry point called after every emulation execution.
 */
export async function processActorFeedback(
  feedback: ExecutionFeedback,
  outcome: LearningOutcome,
  actorName: string,
  campaignContext?: {
    campaignId?: string;
    engagementId?: string;
    targetSector?: string;
  }
): Promise<{
  performanceUpdated: boolean;
  novelVariationsFound: number;
  artifactsDiscovered: number;
  feedbackEvents: FeedbackEvent[];
}> {
  const result = {
    performanceUpdated: false,
    novelVariationsFound: 0,
    artifactsDiscovered: 0,
    feedbackEvents: [] as FeedbackEvent[],
  };

  // Get or create actor performance records
  const actorPerf = performanceStore.get(actorName) || [];

  // Find or create performance record for this technique
  let techPerf = actorPerf.find(p => p.techniqueId === feedback.techniqueId);
  if (!techPerf) {
    techPerf = {
      techniqueId: feedback.techniqueId,
      techniqueName: feedback.techniqueId, // Will be enriched
      actorName,
      emulationSuccessRate: 0,
      totalAttempts: 0,
      successCount: 0,
      successfulEnvironments: [],
      failedEnvironments: [],
      blockedByDefenses: [],
      evadedDefenses: [],
      discoveredArtifacts: [],
      novelVariations: [],
      lastUpdated: new Date().toISOString(),
    };
    actorPerf.push(techPerf);
  }

  // Update execution stats
  techPerf.totalAttempts++;
  if (outcome.success) {
    techPerf.successCount++;
  }
  techPerf.emulationSuccessRate = Math.round((techPerf.successCount / techPerf.totalAttempts) * 100);
  techPerf.lastUpdated = new Date().toISOString();

  // Build environment profile
  const envProfile: EnvironmentProfile = {
    os: feedback.targetContext?.os || "unknown",
    platform: feedback.targetContext?.platform || "unknown",
    defenses: feedback.targetContext?.defenses || [],
    networkSegment: feedback.targetContext?.networkSegment,
    timestamp: new Date().toISOString(),
  };

  if (outcome.success) {
    techPerf.successfulEnvironments.push(envProfile);
    // Track defense evasion
    for (const defense of envProfile.defenses) {
      if (!techPerf.evadedDefenses.includes(defense)) {
        techPerf.evadedDefenses.push(defense);
      }
    }
    // Emit success event
    const event: FeedbackEvent = {
      type: "technique_success",
      actorName,
      techniqueId: feedback.techniqueId,
      data: { environment: envProfile, confidence: outcome.confidenceAdjustment },
      timestamp: new Date().toISOString(),
    };
    feedbackEventLog.unshift(event);
    result.feedbackEvents.push(event);
  } else {
    techPerf.failedEnvironments.push(envProfile);
    // Track blocking defenses
    for (const defense of envProfile.defenses) {
      if (!techPerf.blockedByDefenses.includes(defense)) {
        techPerf.blockedByDefenses.push(defense);
      }
    }
    // Emit failure event
    const event: FeedbackEvent = {
      type: "technique_failure",
      actorName,
      techniqueId: feedback.techniqueId,
      data: { environment: envProfile, blockers: envProfile.defenses },
      timestamp: new Date().toISOString(),
    };
    feedbackEventLog.unshift(event);
    result.feedbackEvents.push(event);
  }

  // Process extracted artifacts
  for (const artifact of outcome.extractedArtifacts || []) {
    const discovered: DiscoveredArtifact = {
      type: categorizeArtifact(artifact),
      value: artifact.value || JSON.stringify(artifact),
      context: artifact.context || `Discovered during ${feedback.techniqueId} execution`,
      discoveredAt: new Date().toISOString(),
      feedbackApplied: false,
    };
    techPerf.discoveredArtifacts.push(discovered);
    result.artifactsDiscovered++;

    if (discovered.type === "new_technique") {
      const event: FeedbackEvent = {
        type: "new_artifact",
        actorName,
        techniqueId: feedback.techniqueId,
        data: discovered,
        timestamp: new Date().toISOString(),
      };
      feedbackEventLog.unshift(event);
      result.feedbackEvents.push(event);
    }
  }

  // Check for novel technique variations
  const novelVariations = await detectNovelVariations(feedback, outcome, actorName);
  for (const variation of novelVariations) {
    techPerf.novelVariations.push(variation);
    result.novelVariationsFound++;

    const event: FeedbackEvent = {
      type: "novel_ttp",
      actorName,
      techniqueId: feedback.techniqueId,
      data: variation,
      timestamp: new Date().toISOString(),
    };
    feedbackEventLog.unshift(event);
    result.feedbackEvents.push(event);
  }

  // Store updated performance
  performanceStore.set(actorName, actorPerf);
  result.performanceUpdated = true;

  // Trim event log
  if (feedbackEventLog.length > MAX_EVENTS) {
    feedbackEventLog.length = MAX_EVENTS;
  }

  return result;
}

function categorizeArtifact(artifact: any): DiscoveredArtifact["type"] {
  const type = (artifact.type || "").toLowerCase();
  if (type.includes("ioc") || type.includes("hash") || type.includes("ip") || type.includes("domain")) return "ioc";
  if (type.includes("credential") || type.includes("password") || type.includes("token")) return "credential";
  if (type.includes("config") || type.includes("setting")) return "config";
  if (type.includes("technique") || type.includes("novel")) return "new_technique";
  return "tool_output";
}

// ─── Novel Variation Detection ──────────────────────────────────────────

/**
 * Analyze execution output for novel technique variations.
 * Uses LLM to identify when an execution reveals a new way to
 * accomplish a known technique.
 */
async function detectNovelVariations(
  feedback: ExecutionFeedback,
  outcome: LearningOutcome,
  actorName: string
): Promise<NovelVariation[]> {
  // Only analyze successful executions with meaningful output
  if (!outcome.success) return [];
  const output = feedback.taskResult?.stdout || "";
  if (output.length < 50) return [];

  // Check if lessons learned suggest something novel
  const novelLessons = (outcome.lessonsLearned || []).filter(
    (l: string) => l.toLowerCase().includes("novel") ||
      l.toLowerCase().includes("unexpected") ||
      l.toLowerCase().includes("new method") ||
      l.toLowerCase().includes("variant")
  );

  if (novelLessons.length === 0 && (outcome.crossFrameworkNotes || []).length === 0) {
    return [];
  }

  try {
    const response = await invokeLLM({
      _caller: "c2-actor-feedback-loop.detectNovelVariations",
      messages: [
        {
          role: "system",
          content: `You are a threat intelligence analyst reviewing C2 execution output. Determine if the execution reveals a novel variation of the base technique. A "novel variation" is a new method, tool combination, or approach that differs from the standard execution of this MITRE technique. Return JSON with "variations" array, each with: description, differentiator, noveltyConfidence (0-100). Return empty array if nothing novel.`,
        },
        {
          role: "user",
          content: `Base technique: ${feedback.techniqueId}\nActor: ${actorName}\nLessons: ${novelLessons.join("; ")}\nCross-framework notes: ${(outcome.crossFrameworkNotes || []).join("; ")}\nOutput excerpt: ${output.slice(0, 500)}`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "novel_variations",
          strict: true,
          schema: {
            type: "object",
            properties: {
              variations: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    description: { type: "string" },
                    differentiator: { type: "string" },
                    noveltyConfidence: { type: "number" },
                  },
                  required: ["description", "differentiator", "noveltyConfidence"],
                  additionalProperties: false,
                },
              },
            },
            required: ["variations"],
            additionalProperties: false,
          },
        },
      },
    });

    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return (parsed.variations || [])
      .filter((v: any) => v.noveltyConfidence > 30)
      .map((v: any) => ({
        baseTechniqueId: feedback.techniqueId,
        description: v.description,
        differentiator: v.differentiator,
        noveltyConfidence: v.noveltyConfidence,
        sourceExecutionId: `exec-${Date.now()}`,
        fedBack: false,
      }));
  } catch {
    return [];
  }
}

// ─── Build Actor Learning Profiles ──────────────────────────────────────

/**
 * Build a comprehensive learning profile for an actor based on
 * all emulation execution history.
 */
export function buildActorLearningProfile(actorName: string): ActorLearningProfile | null {
  const actorPerf = performanceStore.get(actorName);
  if (!actorPerf || actorPerf.length === 0) return null;

  const totalEmulations = actorPerf.reduce((sum, p) => sum + p.totalAttempts, 0);
  const totalSuccesses = actorPerf.reduce((sum, p) => sum + p.successCount, 0);

  // Most reliable techniques
  const mostReliable = [...actorPerf]
    .filter(p => p.totalAttempts >= 2)
    .sort((a, b) => b.emulationSuccessRate - a.emulationSuccessRate)
    .slice(0, 10)
    .map(p => ({ techniqueId: p.techniqueId, successRate: p.emulationSuccessRate }));

  // Unreliable techniques
  const unreliable = [...actorPerf]
    .filter(p => p.totalAttempts >= 2 && p.emulationSuccessRate < 50)
    .sort((a, b) => a.emulationSuccessRate - b.emulationSuccessRate)
    .slice(0, 10)
    .map(p => ({
      techniqueId: p.techniqueId,
      failureRate: 100 - p.emulationSuccessRate,
      commonBlocker: p.blockedByDefenses[0] || "Unknown",
    }));

  // Defense evasion profile
  const defenseMap = new Map<string, { evaded: string[]; blocked: string[] }>();
  for (const perf of actorPerf) {
    for (const defense of perf.evadedDefenses) {
      const entry = defenseMap.get(defense) || { evaded: [], blocked: [] };
      entry.evaded.push(perf.techniqueId);
      defenseMap.set(defense, entry);
    }
    for (const defense of perf.blockedByDefenses) {
      const entry = defenseMap.get(defense) || { evaded: [], blocked: [] };
      entry.blocked.push(perf.techniqueId);
      defenseMap.set(defense, entry);
    }
  }

  const defenseEvasionProfile = Array.from(defenseMap.entries()).map(([defense, data]) => ({
    defense,
    evasionRate: data.evaded.length / (data.evaded.length + data.blocked.length) * 100,
    techniquesThatEvade: [...new Set(data.evaded)],
    techniquesThatFail: [...new Set(data.blocked)],
  }));

  // Collect all novel variations
  const discoveredTTPs = actorPerf.flatMap(p => p.novelVariations);

  // Find last emulation date
  const lastEmulation = actorPerf
    .map(p => p.lastUpdated)
    .sort()
    .reverse()[0] || "Never";

  return {
    actorName,
    techniquePerformance: actorPerf,
    overallSuccessRate: totalEmulations > 0 ? Math.round((totalSuccesses / totalEmulations) * 100) : 0,
    mostReliableTechniques: mostReliable,
    unreliableTechniques: unreliable,
    defenseEvasionProfile,
    discoveredTTPs,
    totalEmulations,
    lastEmulation,
  };
}

// ─── Cross-Module Feedback Consumers ────────────────────────────────────

/**
 * Get feedback events for the Sigma Rule Engine.
 * Returns telemetry data that can be used to refine detection rules.
 */
export function getFeedbackForSigmaRules(actorName?: string): {
  successfulTechniques: { techniqueId: string; environments: EnvironmentProfile[] }[];
  failedTechniques: { techniqueId: string; blockers: string[] }[];
  novelVariations: NovelVariation[];
  telemetrySignals: any[];
} {
  const events = actorName
    ? feedbackEventLog.filter(e => e.actorName === actorName)
    : feedbackEventLog;

  const successfulTechniques = events
    .filter(e => e.type === "technique_success")
    .map(e => ({
      techniqueId: e.techniqueId,
      environments: [e.data.environment],
    }));

  const failedTechniques = events
    .filter(e => e.type === "technique_failure")
    .map(e => ({
      techniqueId: e.techniqueId,
      blockers: e.data.blockers || [],
    }));

  const novelVariations = events
    .filter(e => e.type === "novel_ttp")
    .map(e => e.data as NovelVariation);

  return {
    successfulTechniques,
    failedTechniques,
    novelVariations,
    telemetrySignals: events.filter(e => e.type === "new_artifact").map(e => e.data),
  };
}

/**
 * Get feedback events for the Campaign Advisor.
 * Returns technique reliability data to optimize campaign planning.
 */
export function getFeedbackForCampaignAdvisor(actorName: string): {
  recommendedTechniques: { techniqueId: string; successRate: number; reason: string }[];
  avoidTechniques: { techniqueId: string; failureRate: number; reason: string }[];
  environmentalInsights: string[];
} {
  const profile = buildActorLearningProfile(actorName);
  if (!profile) {
    return { recommendedTechniques: [], avoidTechniques: [], environmentalInsights: [] };
  }

  const recommended = profile.mostReliableTechniques.map(t => ({
    techniqueId: t.techniqueId,
    successRate: t.successRate,
    reason: `${t.successRate}% success rate in emulations`,
  }));

  const avoid = profile.unreliableTechniques.map(t => ({
    techniqueId: t.techniqueId,
    failureRate: t.failureRate,
    reason: `${t.failureRate}% failure rate, commonly blocked by ${t.commonBlocker}`,
  }));

  const environmentalInsights = profile.defenseEvasionProfile.map(d =>
    `${d.defense}: ${Math.round(d.evasionRate)}% evasion rate (${d.techniquesThatEvade.length} techniques evade, ${d.techniquesThatFail.length} blocked)`
  );

  return { recommendedTechniques: recommended, avoidTechniques: avoid, environmentalInsights };
}

/**
 * Get feedback events for the Behavioral Sequence Engine.
 * Returns execution order data to validate/update sequences.
 */
export function getFeedbackForSequenceEngine(actorName?: string): {
  executionOrders: { techniqueId: string; position: number; success: boolean; timestamp: string }[];
  chainBreaks: { fromTechnique: string; toTechnique: string; reason: string }[];
} {
  const events = actorName
    ? feedbackEventLog.filter(e => e.actorName === actorName)
    : feedbackEventLog;

  // Build execution order from events
  const executionOrders = events
    .filter(e => e.type === "technique_success" || e.type === "technique_failure")
    .map((e, i) => ({
      techniqueId: e.techniqueId,
      position: i,
      success: e.type === "technique_success",
      timestamp: e.timestamp,
    }));

  // Identify chain breaks (where a failure interrupted a sequence)
  const chainBreaks: { fromTechnique: string; toTechnique: string; reason: string }[] = [];
  for (let i = 0; i < executionOrders.length - 1; i++) {
    if (!executionOrders[i]!.success) {
      chainBreaks.push({
        fromTechnique: executionOrders[i]!.techniqueId,
        toTechnique: executionOrders[i + 1]?.techniqueId || "end",
        reason: "Technique failure interrupted sequence",
      });
    }
  }

  return { executionOrders, chainBreaks };
}

// ─── Query Functions ────────────────────────────────────────────────────

/** Get all actors with learning profiles */
export function getProfiledActors(): string[] {
  return Array.from(performanceStore.keys());
}

/** Get recent feedback events */
export function getRecentFeedbackEvents(limit = 50, actorName?: string): FeedbackEvent[] {
  const events = actorName
    ? feedbackEventLog.filter(e => e.actorName === actorName)
    : feedbackEventLog;
  return events.slice(0, limit);
}

/** Get feedback loop statistics */
export function getFeedbackLoopStats(): {
  totalFeedbackEvents: number;
  actorsProfiled: number;
  totalNovelVariations: number;
  totalArtifactsDiscovered: number;
  avgSuccessRate: number;
  topPerformingActors: { name: string; successRate: number }[];
  recentEvents: number;
} {
  let totalNovel = 0;
  let totalArtifacts = 0;
  let totalSuccess = 0;
  let totalAttempts = 0;
  const actorRates: { name: string; successRate: number }[] = [];

  for (const [actorName, perfs] of performanceStore) {
    let actorTotal = 0;
    let actorSuccess = 0;
    for (const perf of perfs) {
      totalNovel += perf.novelVariations.length;
      totalArtifacts += perf.discoveredArtifacts.length;
      totalSuccess += perf.successCount;
      totalAttempts += perf.totalAttempts;
      actorTotal += perf.totalAttempts;
      actorSuccess += perf.successCount;
    }
    if (actorTotal > 0) {
      actorRates.push({ name: actorName, successRate: Math.round((actorSuccess / actorTotal) * 100) });
    }
  }

  actorRates.sort((a, b) => b.successRate - a.successRate);

  const oneDayAgo = new Date(Date.now() - 86400000).toISOString();
  const recentEvents = feedbackEventLog.filter(e => e.timestamp > oneDayAgo).length;

  return {
    totalFeedbackEvents: feedbackEventLog.length,
    actorsProfiled: performanceStore.size,
    totalNovelVariations: totalNovel,
    totalArtifactsDiscovered: totalArtifacts,
    avgSuccessRate: totalAttempts > 0 ? Math.round((totalSuccess / totalAttempts) * 100) : 0,
    topPerformingActors: actorRates.slice(0, 5),
    recentEvents,
  };
}
