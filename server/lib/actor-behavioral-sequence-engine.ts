/**
 * Actor Behavioral Sequence Engine
 *
 * Models the specific ORDER in which threat actors chain techniques.
 * Transforms flat "technique lists" into "attack narratives" — the
 * actual kill chain sequences observed in real incidents.
 *
 * Key capabilities:
 *  1. Extract attack sequences from incident reports per actor
 *  2. Build probabilistic transition models (technique A → technique B)
 *  3. Identify actor-specific "signature sequences" (unique chains)
 *  4. Generate predicted attack paths for new engagements
 *  5. Compare actor behavioral fingerprints
 *  6. Feed sequence data back into campaign design and emulation
 *
 * Data sources:
 *  - Incident reports (attack sequences, TTPs extracted)
 *  - TTP knowledge base (prerequisite/follow-up chains)
 *  - C2 execution history (actual execution order)
 *  - Threat actor catalog (known techniques per actor)
 *
 * Author: Harrison Cook — AceofCloud
 */

import { getDb } from "../db";
import {
  incidentReports,
  threatActors,
  ttpKnowledge,
  attackSequenceTemplates,
} from "../../drizzle/schema";
import { eq, desc, sql, inArray, or, isNotNull } from "drizzle-orm";
import { invokeLLM } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────────

/** A single step in a behavioral sequence */
export interface SequenceStep {
  /** Position in the sequence (0-based) */
  position: number;
  /** MITRE ATT&CK technique ID */
  techniqueId: string;
  /** Technique name */
  techniqueName: string;
  /** Tactic phase */
  tactic: string;
  /** Tools used at this step */
  tools: string[];
  /** Duration estimate (if available from reports) */
  estimatedDuration?: string;
  /** Description of what happens at this step */
  description: string;
  /** Confidence that this step occurs at this position (0-100) */
  positionConfidence: number;
}

/** A complete behavioral sequence for an actor */
export interface BehavioralSequence {
  /** Unique sequence ID */
  id: string;
  /** Actor name */
  actorName: string;
  /** Actor type (apt, cybercrime, ransomware, hacktivist) */
  actorType: string;
  /** Sequence name/label */
  name: string;
  /** Description of the overall attack narrative */
  description: string;
  /** Ordered steps */
  steps: SequenceStep[];
  /** Target environment this sequence is optimized for */
  targetEnvironment: {
    sectors: string[];
    platforms: string[];
    regions: string[];
  };
  /** How many incident reports corroborate this sequence */
  corroboratingReports: number;
  /** Overall confidence (0-100) */
  confidence: number;
  /** Whether this is a "signature" sequence unique to this actor */
  isSignature: boolean;
  /** Source of this sequence */
  source: string; // incident_reports, ttp_knowledge, c2_history, llm_inferred
  /** When this sequence was last updated */
  lastUpdated: string;
}

/** Transition probability between two techniques */
export interface TechniqueTransition {
  fromTechniqueId: string;
  fromTechniqueName: string;
  toTechniqueId: string;
  toTechniqueName: string;
  probability: number; // 0-1
  observedCount: number;
  actors: string[];
  avgTimeBetween?: string;
}

/** Actor behavioral fingerprint — their unique attack signature */
export interface ActorFingerprint {
  actorName: string;
  actorType: string;
  /** Preferred initial access techniques (ranked) */
  initialAccessPreferences: { techniqueId: string; name: string; frequency: number }[];
  /** Preferred persistence mechanisms */
  persistencePreferences: { techniqueId: string; name: string; frequency: number }[];
  /** Preferred lateral movement techniques */
  lateralMovementPreferences: { techniqueId: string; name: string; frequency: number }[];
  /** Preferred exfiltration methods */
  exfilPreferences: { techniqueId: string; name: string; frequency: number }[];
  /** Signature tool combinations */
  signatureToolCombos: string[][];
  /** Average kill chain length */
  avgKillChainLength: number;
  /** Dwell time estimate */
  estimatedDwellTime: string;
  /** Sophistication indicators */
  sophisticationMarkers: string[];
  /** Total sequences analyzed */
  sequencesAnalyzed: number;
}

/** Predicted attack path for a new engagement */
export interface PredictedAttackPath {
  actorName: string;
  pathName: string;
  steps: SequenceStep[];
  overallProbability: number;
  basedOnSequences: number;
  targetFit: number; // 0-100 how well this path fits the target
  alternativePaths: number;
}

// ─── In-Memory Sequence Store ───────────────────────────────────────────

const sequenceStore: BehavioralSequence[] = [];
const transitionStore: TechniqueTransition[] = [];

// ─── Core: Extract Sequences from Incident Reports ──────────────────────

/**
 * Extract behavioral sequences from all incident reports in the database.
 * This is the primary learning function that builds the sequence model.
 */
export async function extractSequencesFromReports(): Promise<{
  sequencesExtracted: number;
  transitionsBuilt: number;
  actorsProcessed: number;
  errors: string[];
}> {
  const db = await getDb();
  if (!db) return { sequencesExtracted: 0, transitionsBuilt: 0, actorsProcessed: 0, errors: ["Database not available"] };

  const result = { sequencesExtracted: 0, transitionsBuilt: 0, actorsProcessed: 0, errors: [] as string[] };

  // Get all incident reports with attack sequences
  const reports = await db.select().from(incidentReports)
    .where(isNotNull(incidentReports.attackSequence))
    .orderBy(desc(incidentReports.id))
    .limit(500);

  // Group reports by actor
  const actorReports = new Map<string, any[]>();

  for (const report of reports) {
    const actors = (report.actorsIdentified as any[]) || [];
    for (const actor of actors) {
      const name = actor.name || "Unknown";
      const existing = actorReports.get(name) || [];
      existing.push(report);
      actorReports.set(name, existing);
    }
    // Also add to "Unknown" if no actors identified
    if (actors.length === 0) {
      const existing = actorReports.get("Unattributed") || [];
      existing.push(report);
      actorReports.set("Unattributed", existing);
    }
  }

  // Process each actor's reports to build sequences
  for (const [actorName, actorReportList] of actorReports) {
    try {
      const sequences = buildSequencesForActor(actorName, actorReportList);
      for (const seq of sequences) {
        // Check for duplicates
        const existing = sequenceStore.findIndex(s => s.id === seq.id);
        if (existing >= 0) {
          sequenceStore[existing] = seq;
        } else {
          sequenceStore.push(seq);
        }
        result.sequencesExtracted++;
      }

      // Build transitions from this actor's sequences
      const transitions = buildTransitionsFromSequences(sequences);
      for (const trans of transitions) {
        const existing = transitionStore.findIndex(t =>
          t.fromTechniqueId === trans.fromTechniqueId &&
          t.toTechniqueId === trans.toTechniqueId
        );
        if (existing >= 0) {
          // Merge
          transitionStore[existing]!.observedCount += trans.observedCount;
          transitionStore[existing]!.probability = (transitionStore[existing]!.probability + trans.probability) / 2;
          for (const actor of trans.actors) {
            if (!transitionStore[existing]!.actors.includes(actor)) {
              transitionStore[existing]!.actors.push(actor);
            }
          }
        } else {
          transitionStore.push(trans);
        }
        result.transitionsBuilt++;
      }

      result.actorsProcessed++;
    } catch (e: any) {
      result.errors.push(`${actorName}: ${e.message}`);
    }
  }

  console.log(`[BehavioralSequenceEngine] Extracted ${result.sequencesExtracted} sequences, ${result.transitionsBuilt} transitions from ${result.actorsProcessed} actors`);
  return result;
}

function buildSequencesForActor(actorName: string, reports: any[]): BehavioralSequence[] {
  const sequences: BehavioralSequence[] = [];

  for (const report of reports) {
    const attackSequence = (report.attackSequence as any[]) || [];
    if (attackSequence.length < 2) continue;

    const steps: SequenceStep[] = [];
    let position = 0;

    for (const phase of attackSequence) {
      const techniques = phase.techniques || phase.technique || [];
      const techArray = Array.isArray(techniques) ? techniques : [techniques];

      for (const tech of techArray) {
        const techId = tech.techniqueId || tech.id || tech;
        if (!techId || typeof techId !== "string") continue;

        steps.push({
          position,
          techniqueId: techId,
          techniqueName: tech.name || tech.techniqueName || techId,
          tactic: phase.tactic || phase.phase || "unknown",
          tools: (tech.tools as string[]) || [],
          estimatedDuration: phase.duration || undefined,
          description: tech.description || phase.description || "",
          positionConfidence: 70,
        });
        position++;
      }
    }

    if (steps.length < 2) continue;

    const actors = (report.actorsIdentified as any[]) || [];
    const actorInfo = actors.find((a: any) => a.name === actorName) || actors[0] || {};
    const targetSectors = (report.targetSectors as string[]) || [];

    sequences.push({
      id: `seq-${actorName.toLowerCase().replace(/\s+/g, "-")}-${report.id}`,
      actorName,
      actorType: actorInfo.type || "unknown",
      name: `${actorName} — ${report.title || "Incident " + report.id}`,
      description: (report.summary || "").slice(0, 500),
      steps,
      targetEnvironment: {
        sectors: targetSectors,
        platforms: extractPlatforms(report),
        regions: (report.targetRegions as string[]) || [],
      },
      corroboratingReports: 1,
      confidence: calculateSequenceConfidence(steps, report),
      isSignature: false,
      source: "incident_reports",
      lastUpdated: new Date().toISOString(),
    });
  }

  // Identify signature sequences (unique to this actor)
  identifySignatureSequences(sequences);

  return sequences;
}

function extractPlatforms(report: any): string[] {
  const platforms: string[] = [];
  const text = JSON.stringify(report).toLowerCase();
  if (text.includes("windows")) platforms.push("windows");
  if (text.includes("linux")) platforms.push("linux");
  if (text.includes("macos") || text.includes("mac os")) platforms.push("macos");
  if (text.includes("aws")) platforms.push("aws");
  if (text.includes("azure")) platforms.push("azure");
  if (text.includes("gcp") || text.includes("google cloud")) platforms.push("gcp");
  return platforms;
}

function calculateSequenceConfidence(steps: SequenceStep[], report: any): number {
  let confidence = 50;
  // More steps = more detailed = higher confidence
  confidence += Math.min(20, steps.length * 3);
  // Reports with MITRE IDs are higher quality
  const mitreSteps = steps.filter(s => s.techniqueId.startsWith("T"));
  confidence += Math.min(15, mitreSteps.length * 3);
  // Reports with tools mentioned are more actionable
  const toolSteps = steps.filter(s => s.tools.length > 0);
  confidence += Math.min(15, toolSteps.length * 3);
  return Math.min(100, confidence);
}

function identifySignatureSequences(sequences: BehavioralSequence[]): void {
  // A signature sequence has a unique combination of techniques in a specific order
  for (const seq of sequences) {
    const techChain = seq.steps.map(s => s.techniqueId).join("→");
    // If this exact chain appears only once, it's a potential signature
    const matchCount = sequences.filter(s =>
      s.steps.map(st => st.techniqueId).join("→") === techChain
    ).length;
    seq.isSignature = matchCount <= 2 && seq.steps.length >= 3;
  }
}

// ─── Build Technique Transitions ────────────────────────────────────────

function buildTransitionsFromSequences(sequences: BehavioralSequence[]): TechniqueTransition[] {
  const transitionMap = new Map<string, TechniqueTransition>();

  for (const seq of sequences) {
    for (let i = 0; i < seq.steps.length - 1; i++) {
      const from = seq.steps[i]!;
      const to = seq.steps[i + 1]!;
      const key = `${from.techniqueId}→${to.techniqueId}`;

      const existing = transitionMap.get(key);
      if (existing) {
        existing.observedCount++;
        if (!existing.actors.includes(seq.actorName)) {
          existing.actors.push(seq.actorName);
        }
      } else {
        transitionMap.set(key, {
          fromTechniqueId: from.techniqueId,
          fromTechniqueName: from.techniqueName,
          toTechniqueId: to.techniqueId,
          toTechniqueName: to.techniqueName,
          probability: 0, // Calculated after all transitions are collected
          observedCount: 1,
          actors: [seq.actorName],
        });
      }
    }
  }

  // Calculate probabilities
  const fromCounts = new Map<string, number>();
  for (const trans of transitionMap.values()) {
    fromCounts.set(trans.fromTechniqueId, (fromCounts.get(trans.fromTechniqueId) || 0) + trans.observedCount);
  }
  for (const trans of transitionMap.values()) {
    const total = fromCounts.get(trans.fromTechniqueId) || 1;
    trans.probability = trans.observedCount / total;
  }

  return Array.from(transitionMap.values());
}

// ─── Enrich from TTP Knowledge Base ─────────────────────────────────────

/**
 * Enrich sequences with prerequisite/follow-up data from the TTP knowledge base.
 * This fills gaps where incident reports don't provide full sequences.
 */
export async function enrichFromTTPKnowledge(): Promise<{
  transitionsAdded: number;
  sequencesEnriched: number;
}> {
  const db = await getDb();
  if (!db) return { transitionsAdded: 0, sequencesEnriched: 0 };

  const result = { transitionsAdded: 0, sequencesEnriched: 0 };

  const allTTPs = await db.select().from(ttpKnowledge).limit(500);

  for (const ttp of allTTPs) {
    const prerequisites = (ttp.prerequisiteTechniques as string[]) || [];
    const followUps = (ttp.followUpTechniques as string[]) || [];

    // Add transitions from prerequisites → this technique
    for (const prereq of prerequisites) {
      const key = `${prereq}→${ttp.techniqueId}`;
      const existing = transitionStore.find(t =>
        t.fromTechniqueId === prereq && t.toTechniqueId === ttp.techniqueId
      );
      if (!existing) {
        transitionStore.push({
          fromTechniqueId: prereq,
          fromTechniqueName: prereq,
          toTechniqueId: ttp.techniqueId,
          toTechniqueName: ttp.techniqueName,
          probability: 0.3, // Lower confidence since it's from KB, not observed
          observedCount: 0,
          actors: [],
        });
        result.transitionsAdded++;
      } else {
        // Boost confidence if KB corroborates observed transitions
        existing.probability = Math.min(1, existing.probability + 0.1);
      }
    }

    // Add transitions from this technique → follow-ups
    for (const followUp of followUps) {
      const existing = transitionStore.find(t =>
        t.fromTechniqueId === ttp.techniqueId && t.toTechniqueId === followUp
      );
      if (!existing) {
        transitionStore.push({
          fromTechniqueId: ttp.techniqueId,
          fromTechniqueName: ttp.techniqueName,
          toTechniqueId: followUp,
          toTechniqueName: followUp,
          probability: 0.3,
          observedCount: 0,
          actors: [],
        });
        result.transitionsAdded++;
      } else {
        existing.probability = Math.min(1, existing.probability + 0.1);
      }
    }
  }

  return result;
}

// ─── Build Actor Fingerprints ───────────────────────────────────────────

/**
 * Build a behavioral fingerprint for a specific actor.
 * Aggregates all their sequences into a profile of preferences.
 */
export function buildActorFingerprint(actorName: string): ActorFingerprint | null {
  const actorSequences = sequenceStore.filter(s => s.actorName === actorName);
  if (actorSequences.length === 0) return null;

  const tacticFrequency = new Map<string, Map<string, number>>();
  const toolCombos: string[][] = [];
  let totalSteps = 0;

  for (const seq of actorSequences) {
    const seqTools: string[] = [];
    for (const step of seq.steps) {
      totalSteps++;
      const tacticMap = tacticFrequency.get(step.tactic) || new Map<string, number>();
      tacticMap.set(step.techniqueId, (tacticMap.get(step.techniqueId) || 0) + 1);
      tacticFrequency.set(step.tactic, tacticMap);
      seqTools.push(...step.tools);
    }
    if (seqTools.length > 0) toolCombos.push([...new Set(seqTools)]);
  }

  const buildPreferences = (tacticKeywords: string[]) => {
    const combined = new Map<string, { name: string; count: number }>();
    for (const [tactic, techMap] of tacticFrequency) {
      if (tacticKeywords.some(kw => tactic.toLowerCase().includes(kw))) {
        for (const [techId, count] of techMap) {
          const existing = combined.get(techId);
          if (existing) {
            existing.count += count;
          } else {
            combined.set(techId, { name: techId, count });
          }
        }
      }
    }
    return Array.from(combined.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 5)
      .map(([techId, data]) => ({
        techniqueId: techId,
        name: data.name,
        frequency: data.count,
      }));
  };

  // Identify sophistication markers
  const sophisticationMarkers: string[] = [];
  const avgLength = totalSteps / actorSequences.length;
  if (avgLength > 8) sophisticationMarkers.push("Long kill chains (>8 steps)");
  if (actorSequences.some(s => s.steps.some(st => st.tactic.toLowerCase().includes("evasion")))) {
    sophisticationMarkers.push("Defense evasion capabilities");
  }
  if (actorSequences.some(s => s.isSignature)) {
    sophisticationMarkers.push("Unique signature sequences");
  }
  if (toolCombos.some(tc => tc.length > 3)) {
    sophisticationMarkers.push("Multi-tool operations");
  }

  // Estimate dwell time from sequence lengths
  let dwellTime = "Unknown";
  if (avgLength > 10) dwellTime = "Extended (weeks to months)";
  else if (avgLength > 6) dwellTime = "Moderate (days to weeks)";
  else if (avgLength > 3) dwellTime = "Short (hours to days)";
  else dwellTime = "Rapid (minutes to hours)";

  return {
    actorName,
    actorType: actorSequences[0]?.actorType || "unknown",
    initialAccessPreferences: buildPreferences(["initial", "reconnaissance"]),
    persistencePreferences: buildPreferences(["persistence"]),
    lateralMovementPreferences: buildPreferences(["lateral"]),
    exfilPreferences: buildPreferences(["exfil", "collection", "impact"]),
    signatureToolCombos: toolCombos.slice(0, 5),
    avgKillChainLength: Math.round(avgLength * 10) / 10,
    estimatedDwellTime: dwellTime,
    sophisticationMarkers,
    sequencesAnalyzed: actorSequences.length,
  };
}

// ─── Predict Attack Paths ───────────────────────────────────────────────

/**
 * Predict the most likely attack paths for a given actor against a target.
 * Uses the transition model and actor fingerprint to generate paths.
 */
export async function predictAttackPaths(
  actorName: string,
  targetContext: {
    sector?: string;
    platform?: string;
    technologies?: string[];
  },
  maxPaths = 3
): Promise<PredictedAttackPath[]> {
  const fingerprint = buildActorFingerprint(actorName);
  const actorSequences = sequenceStore.filter(s => s.actorName === actorName);

  if (!fingerprint || actorSequences.length === 0) {
    // Fall back to LLM-inferred paths
    return inferAttackPaths(actorName, targetContext, maxPaths);
  }

  const paths: PredictedAttackPath[] = [];

  // Strategy 1: Use most common observed sequences
  const sortedSequences = [...actorSequences].sort((a, b) => b.confidence - a.confidence);

  for (const seq of sortedSequences.slice(0, maxPaths)) {
    // Calculate target fit
    let targetFit = 50;
    if (targetContext.sector && seq.targetEnvironment.sectors.some(s =>
      s.toLowerCase().includes(targetContext.sector!.toLowerCase())
    )) {
      targetFit += 25;
    }
    if (targetContext.platform && seq.targetEnvironment.platforms.some(p =>
      p.toLowerCase().includes(targetContext.platform!.toLowerCase())
    )) {
      targetFit += 25;
    }

    paths.push({
      actorName,
      pathName: seq.name,
      steps: seq.steps,
      overallProbability: seq.confidence / 100,
      basedOnSequences: seq.corroboratingReports,
      targetFit: Math.min(100, targetFit),
      alternativePaths: sortedSequences.length - 1,
    });
  }

  // Strategy 2: Build a new path using transition probabilities
  if (fingerprint.initialAccessPreferences.length > 0 && paths.length < maxPaths) {
    const startTech = fingerprint.initialAccessPreferences[0]!;
    const generatedPath = walkTransitionGraph(startTech.techniqueId, actorName, 10);

    if (generatedPath.length >= 3) {
      paths.push({
        actorName,
        pathName: `${actorName} — Predicted Path (transition model)`,
        steps: generatedPath,
        overallProbability: generatedPath.reduce((acc, s) => acc * (s.positionConfidence / 100), 1),
        basedOnSequences: actorSequences.length,
        targetFit: 50,
        alternativePaths: paths.length,
      });
    }
  }

  return paths;
}

function walkTransitionGraph(startTechId: string, actorName: string, maxSteps: number): SequenceStep[] {
  const steps: SequenceStep[] = [];
  let currentTechId = startTechId;
  const visited = new Set<string>();

  for (let i = 0; i < maxSteps; i++) {
    visited.add(currentTechId);

    // Find the transition with highest probability for this actor
    const transitions = transitionStore
      .filter(t => t.fromTechniqueId === currentTechId && !visited.has(t.toTechniqueId))
      .sort((a, b) => {
        // Prefer transitions observed for this actor
        const aActorBonus = a.actors.includes(actorName) ? 0.3 : 0;
        const bActorBonus = b.actors.includes(actorName) ? 0.3 : 0;
        return (b.probability + bActorBonus) - (a.probability + aActorBonus);
      });

    if (transitions.length === 0) break;

    const bestTransition = transitions[0]!;
    steps.push({
      position: i,
      techniqueId: bestTransition.toTechniqueId,
      techniqueName: bestTransition.toTechniqueName,
      tactic: "predicted",
      tools: [],
      description: `Predicted step via transition model (p=${bestTransition.probability.toFixed(2)})`,
      positionConfidence: Math.round(bestTransition.probability * 100),
    });

    currentTechId = bestTransition.toTechniqueId;
  }

  return steps;
}

async function inferAttackPaths(
  actorName: string,
  targetContext: any,
  maxPaths: number
): Promise<PredictedAttackPath[]> {
  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content: `You are a threat intelligence analyst. Given a threat actor name and target context, predict the most likely attack paths they would use. Return a JSON object with a "paths" array, each containing: name (string), steps (array of {techniqueId, techniqueName, tactic, description}), probability (0-1).`,
        },
        {
          role: "user",
          content: `Predict ${maxPaths} attack paths for "${actorName}" targeting: sector=${targetContext.sector || "unknown"}, platform=${targetContext.platform || "unknown"}, technologies=${(targetContext.technologies || []).join(", ") || "unknown"}`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "attack_paths",
          strict: true,
          schema: {
            type: "object",
            properties: {
              paths: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    steps: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          techniqueId: { type: "string" },
                          techniqueName: { type: "string" },
                          tactic: { type: "string" },
                          description: { type: "string" },
                        },
                        required: ["techniqueId", "techniqueName", "tactic", "description"],
                        additionalProperties: false,
                      },
                    },
                    probability: { type: "number" },
                  },
                  required: ["name", "steps", "probability"],
                  additionalProperties: false,
                },
              },
            },
            required: ["paths"],
            additionalProperties: false,
          },
        },
      },
    });

    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return (parsed.paths || []).slice(0, maxPaths).map((p: any) => ({
      actorName,
      pathName: p.name,
      steps: (p.steps || []).map((s: any, i: number) => ({
        position: i,
        techniqueId: s.techniqueId,
        techniqueName: s.techniqueName,
        tactic: s.tactic,
        tools: [],
        description: s.description,
        positionConfidence: Math.round((p.probability || 0.5) * 100),
      })),
      overallProbability: p.probability || 0.5,
      basedOnSequences: 0,
      targetFit: 50,
      alternativePaths: (parsed.paths || []).length - 1,
    }));
  } catch {
    return [];
  }
}

// ─── Compare Actor Fingerprints ─────────────────────────────────────────

/**
 * Compare two actors' behavioral fingerprints to find similarities
 * and differences. Useful for attribution and purple team planning.
 */
export function compareActorFingerprints(
  actor1: string,
  actor2: string
): {
  actor1Fingerprint: ActorFingerprint | null;
  actor2Fingerprint: ActorFingerprint | null;
  sharedTechniques: string[];
  uniqueToActor1: string[];
  uniqueToActor2: string[];
  similarityScore: number;
  comparison: string;
} {
  const fp1 = buildActorFingerprint(actor1);
  const fp2 = buildActorFingerprint(actor2);

  if (!fp1 || !fp2) {
    return {
      actor1Fingerprint: fp1,
      actor2Fingerprint: fp2,
      sharedTechniques: [],
      uniqueToActor1: [],
      uniqueToActor2: [],
      similarityScore: 0,
      comparison: `Insufficient data to compare ${actor1} and ${actor2}`,
    };
  }

  const allTechs1 = new Set([
    ...fp1.initialAccessPreferences.map(p => p.techniqueId),
    ...fp1.persistencePreferences.map(p => p.techniqueId),
    ...fp1.lateralMovementPreferences.map(p => p.techniqueId),
    ...fp1.exfilPreferences.map(p => p.techniqueId),
  ]);

  const allTechs2 = new Set([
    ...fp2.initialAccessPreferences.map(p => p.techniqueId),
    ...fp2.persistencePreferences.map(p => p.techniqueId),
    ...fp2.lateralMovementPreferences.map(p => p.techniqueId),
    ...fp2.exfilPreferences.map(p => p.techniqueId),
  ]);

  const shared = [...allTechs1].filter(t => allTechs2.has(t));
  const unique1 = [...allTechs1].filter(t => !allTechs2.has(t));
  const unique2 = [...allTechs2].filter(t => !allTechs1.has(t));

  const totalUnique = new Set([...allTechs1, ...allTechs2]).size;
  const similarityScore = totalUnique > 0 ? Math.round((shared.length / totalUnique) * 100) : 0;

  const comparison = [
    `${actor1} vs ${actor2}: ${similarityScore}% technique overlap`,
    `Shared: ${shared.length} techniques | Unique to ${actor1}: ${unique1.length} | Unique to ${actor2}: ${unique2.length}`,
    `Kill chain length: ${actor1}=${fp1.avgKillChainLength} steps vs ${actor2}=${fp2.avgKillChainLength} steps`,
    `Dwell time: ${actor1}=${fp1.estimatedDwellTime} vs ${actor2}=${fp2.estimatedDwellTime}`,
  ].join("\n");

  return {
    actor1Fingerprint: fp1,
    actor2Fingerprint: fp2,
    sharedTechniques: shared,
    uniqueToActor1: unique1,
    uniqueToActor2: unique2,
    similarityScore,
    comparison,
  };
}

// ─── Query Functions ────────────────────────────────────────────────────

/** Get all sequences for a specific actor */
export function getActorSequences(actorName: string): BehavioralSequence[] {
  return sequenceStore.filter(s => s.actorName === actorName);
}

/** Get all stored sequences */
export function getAllSequences(): BehavioralSequence[] {
  return [...sequenceStore];
}

/** Get transitions from a specific technique */
export function getTransitionsFrom(techniqueId: string): TechniqueTransition[] {
  return transitionStore
    .filter(t => t.fromTechniqueId === techniqueId)
    .sort((a, b) => b.probability - a.probability);
}

/** Get all transitions */
export function getAllTransitions(): TechniqueTransition[] {
  return [...transitionStore];
}

/** Get all actors that have behavioral sequences */
export function getSequencedActors(): string[] {
  return [...new Set(sequenceStore.map(s => s.actorName))];
}

/** Get sequence statistics */
export function getSequenceStats(): {
  totalSequences: number;
  totalTransitions: number;
  actorsWithSequences: number;
  signatureSequences: number;
  avgSequenceLength: number;
  topTransitions: TechniqueTransition[];
} {
  const avgLength = sequenceStore.length > 0
    ? sequenceStore.reduce((sum, s) => sum + s.steps.length, 0) / sequenceStore.length
    : 0;

  return {
    totalSequences: sequenceStore.length,
    totalTransitions: transitionStore.length,
    actorsWithSequences: new Set(sequenceStore.map(s => s.actorName)).size,
    signatureSequences: sequenceStore.filter(s => s.isSignature).length,
    avgSequenceLength: Math.round(avgLength * 10) / 10,
    topTransitions: [...transitionStore]
      .sort((a, b) => b.observedCount - a.observedCount)
      .slice(0, 10),
  };
}
