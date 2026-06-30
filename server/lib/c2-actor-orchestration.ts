/**
 * C2 Actor-Driven Orchestration
 * 
 * Wires the Actor Context Provider and Behavioral Sequence Engine into the
 * C2 Orchestrator so that orchestration plans follow actor-specific technique
 * chaining, framework preferences, and timing patterns instead of generic
 * kill chain ordering.
 */

import {
  getActorContext,
  type ActorContext,
  type ActorTechnique,
  type EngagementContext,
} from "./actor-context-provider";
import {
  getActorSequences,
  predictAttackPaths,
  getTransitionsFrom,
  buildActorFingerprint,
  type BehavioralSequence,
  type SequenceStep,
  type ActorFingerprint,
  type PredictedAttackPath,
} from "./actor-behavioral-sequence-engine";
import {
  getFrameworkCapabilities,
  getDefaultFrameworkPriority,
} from "./c2-orchestrator";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ActorOrchestrationProfile {
  /** Actor name */
  actorName: string;
  /** Actor type (apt, cybercrime, ransomware, hacktivist) */
  actorType: string;
  /** Preferred frameworks based on actor's known tooling */
  frameworkPreferences: Record<string, string[]>;
  /** Technique ordering derived from behavioral sequences */
  techniqueChaining: TechniqueChain[];
  /** Timing patterns (dwell time, jitter, work hours) */
  timingProfile: TimingProfile;
  /** OPSEC preferences derived from actor behavior */
  opsecProfile: OpsecProfile;
  /** Predicted attack paths for the current target */
  predictedPaths: PredictedAttackPath[];
  /** Actor fingerprint for behavioral fidelity */
  fingerprint: ActorFingerprint | null;
}

export interface TechniqueChain {
  /** Source technique */
  fromTechnique: string;
  fromTechniqueName: string;
  /** Target technique */
  toTechnique: string;
  toTechniqueName: string;
  /** How often this transition is observed (0-100) */
  transitionProbability: number;
  /** Recommended delay between techniques (ms) */
  recommendedDelayMs: number;
  /** Tools typically used in this transition */
  tools: string[];
}

export interface TimingProfile {
  /** Average dwell time between phases (ms) */
  avgDwellTimeMs: number;
  /** Whether the actor operates during business hours */
  businessHoursOnly: boolean;
  /** Preferred time windows (UTC hours) */
  activeHours: { start: number; end: number }[];
  /** Jitter range for C2 callbacks (ms) */
  c2JitterRange: { min: number; max: number };
  /** Sleep interval for beacons (ms) */
  beaconSleepMs: number;
}

export interface OpsecProfile {
  /** Noise level (1=silent, 10=loud) */
  noiseLevel: number;
  /** Whether actor typically uses encrypted C2 */
  encryptedC2: boolean;
  /** Whether actor uses living-off-the-land techniques */
  lotlPreference: boolean;
  /** Whether actor cleans up artifacts */
  antiForensics: boolean;
  /** Preferred evasion techniques */
  evasionTechniques: string[];
  /** Whether actor uses process injection */
  processInjection: boolean;
  /** Whether actor uses fileless techniques */
  filelessPreference: boolean;
}

// ─── Actor-to-Framework Mapping ───────────────────────────────────────────────

/**
 * Known actor-to-tool mappings based on threat intelligence.
 * Maps actor names/types to the C2 frameworks they're known to use.
 */
const ACTOR_FRAMEWORK_MAP: Record<string, {
  primary: string[];
  secondary: string[];
  knownTools: string[];
}> = {
  // APT groups
  "APT29": {
    primary: ["cobaltstrike", "sliver"],
    secondary: ["empire", "caldera"],
    knownTools: ["Cobalt Strike", "Brute Ratel", "Sliver", "EnvyScout", "SUNBURST"],
  },
  "APT28": {
    primary: ["empire", "metasploit"],
    secondary: ["cobaltstrike", "caldera"],
    knownTools: ["X-Agent", "Zebrocy", "Responder", "Mimikatz"],
  },
  "APT41": {
    primary: ["cobaltstrike", "metasploit"],
    secondary: ["empire", "sliver"],
    knownTools: ["Cobalt Strike", "ShadowPad", "PlugX", "China Chopper"],
  },
  "Lazarus Group": {
    primary: ["metasploit", "empire"],
    secondary: ["cobaltstrike", "caldera"],
    knownTools: ["BLINDINGCAN", "HOPLIGHT", "DTrack", "AppleJeus"],
  },
  "FIN7": {
    primary: ["cobaltstrike", "metasploit"],
    secondary: ["empire", "caldera"],
    knownTools: ["Cobalt Strike", "Carbanak", "GRIFFON", "BOOSTWRITE"],
  },
  "FIN11": {
    primary: ["cobaltstrike", "empire"],
    secondary: ["metasploit", "caldera"],
    knownTools: ["Cobalt Strike", "CLOP", "FlawedAmmyy"],
  },
  "Sandworm": {
    primary: ["metasploit", "empire"],
    secondary: ["caldera", "cobaltstrike"],
    knownTools: ["Industroyer", "NotPetya", "BlackEnergy", "CaddyWiper"],
  },
  "Turla": {
    primary: ["empire", "cobaltstrike"],
    secondary: ["metasploit", "sliver"],
    knownTools: ["Carbon", "Kazuar", "Snake", "ComRAT", "LightNeuron"],
  },
  // Ransomware groups
  "LockBit": {
    primary: ["cobaltstrike", "metasploit"],
    secondary: ["sliver", "empire"],
    knownTools: ["Cobalt Strike", "StealBit", "ProxyShell exploits"],
  },
  "BlackCat/ALPHV": {
    primary: ["cobaltstrike", "sliver"],
    secondary: ["metasploit", "empire"],
    knownTools: ["Cobalt Strike", "Brute Ratel", "Evilginx2"],
  },
  "Conti": {
    primary: ["cobaltstrike", "empire"],
    secondary: ["metasploit", "caldera"],
    knownTools: ["Cobalt Strike", "BazarLoader", "TrickBot", "Anchor"],
  },
  "REvil": {
    primary: ["metasploit", "cobaltstrike"],
    secondary: ["empire", "caldera"],
    knownTools: ["Sodinokibi", "Kaseya exploit", "Cobalt Strike"],
  },
};

/**
 * Actor type to general OPSEC profile mapping
 */
const ACTOR_TYPE_PROFILES: Record<string, Partial<OpsecProfile>> = {
  apt: {
    noiseLevel: 2,
    encryptedC2: true,
    lotlPreference: true,
    antiForensics: true,
    processInjection: true,
    filelessPreference: true,
    evasionTechniques: ["process-injection", "timestomping", "log-clearing", "dll-sideloading"],
  },
  cybercrime: {
    noiseLevel: 5,
    encryptedC2: true,
    lotlPreference: false,
    antiForensics: false,
    processInjection: false,
    filelessPreference: false,
    evasionTechniques: ["obfuscation", "packing", "anti-vm"],
  },
  ransomware: {
    noiseLevel: 7,
    encryptedC2: true,
    lotlPreference: false,
    antiForensics: true,
    processInjection: true,
    filelessPreference: false,
    evasionTechniques: ["safe-mode-boot", "service-disabling", "shadow-copy-deletion"],
  },
  hacktivist: {
    noiseLevel: 8,
    encryptedC2: false,
    lotlPreference: false,
    antiForensics: false,
    processInjection: false,
    filelessPreference: false,
    evasionTechniques: ["vpn", "tor", "proxy-chains"],
  },
};

// ─── Core Functions ───────────────────────────────────────────────────────────

/**
 * Build an actor-driven orchestration profile that can be used to customize
 * C2 orchestration plans to emulate a specific threat actor's behavior.
 */
export async function buildActorOrchestrationProfile(
  actorName: string,
  targetContext: {
    targetDomain?: string;
    targetSector?: string;
    targetRegion?: string;
    technologies?: string[];
    platform?: string;
  } = {}
): Promise<ActorOrchestrationProfile> {
  // Get actor context from the provider
  const actorCtx = await getActorContext({
    actorIds: [],
    requestingModule: "c2-orchestrator",
    targetDomain: targetContext.targetDomain,
    targetSector: targetContext.targetSector,
    targetRegion: targetContext.targetRegion,
    technologies: targetContext.technologies,
    includeNovelTechniques: true,
  });

  // Get behavioral sequences for this actor
  const sequences = getActorSequences(actorName);
  const fingerprint = buildActorFingerprint(actorName);

  // Predict attack paths for the target
  const predictedPaths = await predictAttackPaths(actorName, {
    sector: targetContext.targetSector,
    platform: targetContext.platform,
    technologies: targetContext.technologies,
  }, 5);

  // Determine actor type
  const matchedActor = actorCtx.actors.find(
    a => a.actorId.toLowerCase() === actorName.toLowerCase() ||
         a.actorId.toLowerCase().includes(actorName.toLowerCase())
  );
  const actorType = matchedActor?.type || "apt";

  // Build framework preferences
  const frameworkPreferences = buildFrameworkPreferences(actorName, actorType, actorCtx);

  // Build technique chaining from behavioral sequences
  const techniqueChaining = buildTechniqueChaining(actorName, sequences, actorCtx);

  // Build timing profile
  const timingProfile = buildTimingProfile(actorType, fingerprint);

  // Build OPSEC profile
  const opsecProfile = buildOpsecProfile(actorName, actorType, actorCtx);

  return {
    actorName,
    actorType,
    frameworkPreferences,
    techniqueChaining,
    timingProfile,
    opsecProfile,
    predictedPaths,
    fingerprint,
  };
}

/**
 * Generate actor-aware framework overrides for createOrchestrationPlan.
 * Returns a frameworkOverrides object that prioritizes frameworks the actor
 * is known to use.
 */
export function generateFrameworkOverrides(
  profile: ActorOrchestrationProfile
): Record<string, string[]> {
  const defaults = getDefaultFrameworkPriority();
  const overrides: Record<string, string[]> = {};

  for (const [phase, defaultPriority] of Object.entries(defaults)) {
    const actorPrefs = profile.frameworkPreferences[phase];
    if (actorPrefs && actorPrefs.length > 0) {
      // Actor-preferred frameworks first, then fill with defaults
      const seen = new Set(actorPrefs);
      const merged = [
        ...actorPrefs,
        ...defaultPriority.filter((f: string) => !seen.has(f)),
      ];
      overrides[phase] = merged;
    } else {
      overrides[phase] = defaultPriority as string[];
    }
  }

  return overrides;
}

/**
 * Reorder orchestration steps to match actor behavioral sequences.
 * Takes existing steps and reorders them based on the actor's known
 * technique chaining patterns.
 */
export function reorderStepsForActor(
  steps: Array<{ id: string; techniqueId?: string; order: number; phase: string }>,
  profile: ActorOrchestrationProfile
): Array<{ id: string; techniqueId?: string; order: number; phase: string }> {
  if (profile.techniqueChaining.length === 0 || steps.length <= 1) {
    return steps;
  }

  // Build a transition graph from the actor's chaining patterns
  const transitionMap = new Map<string, { next: string; probability: number }[]>();
  for (const chain of profile.techniqueChaining) {
    const existing = transitionMap.get(chain.fromTechnique) || [];
    existing.push({ next: chain.toTechnique, probability: chain.transitionProbability });
    transitionMap.set(chain.fromTechnique, existing);
  }

  // Greedy reordering: start with the step whose technique has the most
  // outgoing transitions (likely the initial access technique)
  const reordered: typeof steps = [];
  const remaining = new Set(steps.map((_, i) => i));

  // Find the best starting step
  let bestStart = 0;
  let bestStartScore = -1;
  for (let i = 0; i < steps.length; i++) {
    const tid = steps[i].techniqueId;
    if (!tid) continue;
    const transitions = transitionMap.get(tid);
    const score = transitions ? transitions.reduce((s, t) => s + t.probability, 0) : 0;
    // Prefer early kill chain phases as starting points
    const phaseBonus = steps[i].phase === "reconnaissance" ? 100 :
                       steps[i].phase === "delivery" ? 80 :
                       steps[i].phase === "exploitation" ? 60 : 0;
    if (score + phaseBonus > bestStartScore) {
      bestStartScore = score + phaseBonus;
      bestStart = i;
    }
  }

  reordered.push(steps[bestStart]);
  remaining.delete(bestStart);

  // Greedily pick the next step that has the highest transition probability
  // from the current step
  while (remaining.size > 0) {
    const currentTechnique = reordered[reordered.length - 1].techniqueId;
    let bestNext = -1;
    let bestScore = -1;

    for (const idx of remaining) {
      const candidateTechnique = steps[idx].techniqueId;
      if (!candidateTechnique || !currentTechnique) {
        // No technique mapping — use original order as tiebreaker
        const orderScore = 1000 - steps[idx].order;
        if (orderScore > bestScore && bestNext === -1) {
          bestScore = orderScore;
          bestNext = idx;
        }
        continue;
      }

      const transitions = transitionMap.get(currentTechnique) || [];
      const match = transitions.find(t => t.next === candidateTechnique);
      const score = match ? match.probability * 10 : 0;

      // Also check global transitions from the behavioral sequence engine
      const globalTransitions = getTransitionsFrom(currentTechnique);
      const globalMatch = globalTransitions.find(t => t.toTechniqueId === candidateTechnique);
      const globalScore = globalMatch ? globalMatch.probability * 5 : 0;

      const totalScore = score + globalScore;
      if (totalScore > bestScore) {
        bestScore = totalScore;
        bestNext = idx;
      }
    }

    // If no good transition found, pick the step with the lowest original order
    if (bestNext === -1) {
      let minOrder = Infinity;
      for (const idx of remaining) {
        if (steps[idx].order < minOrder) {
          minOrder = steps[idx].order;
          bestNext = idx;
        }
      }
    }

    if (bestNext >= 0) {
      reordered.push(steps[bestNext]);
      remaining.delete(bestNext);
    } else {
      break;
    }
  }

  // Reassign order numbers
  return reordered.map((step, i) => ({ ...step, order: i }));
}

/**
 * Calculate recommended delays between orchestration steps based on
 * the actor's timing profile and technique chaining patterns.
 */
export function calculateActorDelays(
  steps: Array<{ techniqueId?: string; phase: string }>,
  profile: ActorOrchestrationProfile
): number[] {
  const delays: number[] = [];

  for (let i = 0; i < steps.length; i++) {
    if (i === 0) {
      delays.push(0);
      continue;
    }

    const prevTechnique = steps[i - 1].techniqueId;
    const currTechnique = steps[i].techniqueId;

    // Check if there's a specific delay for this transition
    if (prevTechnique && currTechnique) {
      const chain = profile.techniqueChaining.find(
        c => c.fromTechnique === prevTechnique && c.toTechnique === currTechnique
      );
      if (chain && chain.recommendedDelayMs > 0) {
        delays.push(chain.recommendedDelayMs);
        continue;
      }
    }

    // Phase transition delays
    const prevPhase = steps[i - 1].phase;
    const currPhase = steps[i].phase;
    if (prevPhase !== currPhase) {
      // Inter-phase delay based on actor dwell time
      delays.push(profile.timingProfile.avgDwellTimeMs);
    } else {
      // Intra-phase delay — shorter, based on jitter
      const jitter = profile.timingProfile.c2JitterRange;
      delays.push(Math.floor((jitter.min + jitter.max) / 2));
    }
  }

  return delays;
}

/**
 * Generate an actor emulation plan summary that describes the orchestration
 * in terms of the actor's known behavior — useful for engagement reports.
 */
export function generateEmulationNarrative(
  profile: ActorOrchestrationProfile,
  steps: Array<{ label: string; techniqueId?: string; phase: string; framework: string }>
): string {
  const lines: string[] = [];

  lines.push(`## ${profile.actorName} Emulation Plan`);
  lines.push("");
  lines.push(`**Actor Type:** ${profile.actorType.toUpperCase()}`);
  lines.push(`**OPSEC Level:** ${profile.opsecProfile.noiseLevel}/10 noise`);
  lines.push(`**C2 Profile:** ${profile.opsecProfile.encryptedC2 ? "Encrypted" : "Cleartext"}, ` +
    `${profile.timingProfile.beaconSleepMs / 1000}s beacon sleep`);
  lines.push("");

  if (profile.predictedPaths.length > 0) {
    lines.push("### Predicted Attack Paths");
    for (const path of profile.predictedPaths.slice(0, 3)) {
      lines.push(`- **${path.pathName}** (${Math.round(path.overallProbability * 100)}% probability, ` +
        `${path.targetFit}% target fit)`);
      for (const step of path.steps.slice(0, 5)) {
        lines.push(`  ${step.position + 1}. ${step.techniqueName} (${step.techniqueId}) — ${step.tactic}`);
      }
    }
    lines.push("");
  }

  lines.push("### Orchestration Steps");
  const phaseGroups = new Map<string, typeof steps>();
  for (const step of steps) {
    const group = phaseGroups.get(step.phase) || [];
    group.push(step);
    phaseGroups.set(step.phase, group);
  }

  for (const [phase, phaseSteps] of phaseGroups) {
    lines.push(`\n#### ${phase.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}`);
    for (const step of phaseSteps) {
      lines.push(`- ${step.label} (${step.techniqueId || "custom"}) → ${step.framework}`);
    }
  }

  lines.push("");
  lines.push("### Behavioral Fidelity Notes");
  if (profile.opsecProfile.lotlPreference) {
    lines.push("- Actor prefers living-off-the-land techniques — prioritize native OS tools");
  }
  if (profile.opsecProfile.filelessPreference) {
    lines.push("- Actor favors fileless execution — minimize disk artifacts");
  }
  if (profile.opsecProfile.antiForensics) {
    lines.push("- Actor performs anti-forensics — include artifact cleanup steps");
  }
  if (profile.timingProfile.businessHoursOnly) {
    lines.push("- Actor operates during business hours — schedule execution accordingly");
  }
  if (profile.opsecProfile.evasionTechniques.length > 0) {
    lines.push(`- Known evasion: ${profile.opsecProfile.evasionTechniques.join(", ")}`);
  }

  return lines.join("\n");
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

function buildFrameworkPreferences(
  actorName: string,
  actorType: string,
  actorCtx: ActorContext
): Record<string, string[]> {
  const defaults = getDefaultFrameworkPriority();
  const prefs: Record<string, string[]> = {};

  // Check if we have a known mapping for this actor
  const knownMapping = ACTOR_FRAMEWORK_MAP[actorName];

  // Also check actor tooling from the context provider
  const actorTools = actorCtx.tooling.map(t => t.name.toLowerCase());

  for (const [phase, defaultPriority] of Object.entries(defaults)) {
    const phasePriority = [...(defaultPriority as string[])];

    if (knownMapping) {
      // Boost primary frameworks to the front
      for (const fw of [...knownMapping.primary].reverse()) {
        const idx = phasePriority.indexOf(fw);
        if (idx > 0) {
          phasePriority.splice(idx, 1);
          phasePriority.unshift(fw);
        }
      }
    }

    // Cross-reference with actor tooling from live intelligence
    const toolToFramework: Record<string, string> = {
      "cobalt strike": "cobaltstrike",
      "brute ratel": "cobaltstrike", // Similar C2 profile
      "sliver": "sliver",
      "metasploit": "metasploit",
      "meterpreter": "metasploit",
      "empire": "empire",
      "powershell empire": "empire",
    };

    for (const tool of actorTools) {
      const fw = toolToFramework[tool];
      if (fw && phasePriority.includes(fw)) {
        const idx = phasePriority.indexOf(fw);
        if (idx > 1) {
          phasePriority.splice(idx, 1);
          phasePriority.splice(1, 0, fw); // Second priority (after any known primary)
        }
      }
    }

    prefs[phase] = phasePriority;
  }

  return prefs;
}

function buildTechniqueChaining(
  actorName: string,
  sequences: BehavioralSequence[],
  actorCtx: ActorContext
): TechniqueChain[] {
  const chains: TechniqueChain[] = [];
  const seen = new Set<string>();

  // Extract chains from behavioral sequences
  for (const seq of sequences) {
    for (let i = 0; i < seq.steps.length - 1; i++) {
      const from = seq.steps[i];
      const to = seq.steps[i + 1];
      const key = `${from.techniqueId}->${to.techniqueId}`;

      if (seen.has(key)) continue;
      seen.add(key);

      // Calculate recommended delay based on step positions
      const positionDelta = to.position - from.position;
      const baseDelay = positionDelta <= 1 ? 5000 : positionDelta * 30000;

      chains.push({
        fromTechnique: from.techniqueId,
        fromTechniqueName: from.techniqueName,
        toTechnique: to.techniqueId,
        toTechniqueName: to.techniqueName,
        transitionProbability: seq.confidence * (1 - (i / seq.steps.length) * 0.3),
        recommendedDelayMs: baseDelay,
        tools: [...new Set([...from.tools, ...to.tools])],
      });
    }
  }

  // Supplement with actor technique prerequisites/followups from the context provider
  for (const technique of actorCtx.techniques) {
    for (const followUp of technique.followUps || []) {
      const key = `${technique.techniqueId}->${followUp}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const followUpTechnique = actorCtx.techniques.find(t => t.techniqueId === followUp);
      chains.push({
        fromTechnique: technique.techniqueId,
        fromTechniqueName: technique.techniqueName,
        toTechnique: followUp,
        toTechniqueName: followUpTechnique?.techniqueName || followUp,
        transitionProbability: technique.confidence * 0.6,
        recommendedDelayMs: 15000,
        tools: technique.tools,
      });
    }
  }

  // Sort by transition probability
  chains.sort((a, b) => b.transitionProbability - a.transitionProbability);

  return chains;
}

function buildTimingProfile(
  actorType: string,
  fingerprint: ActorFingerprint | null
): TimingProfile {
  // Base profiles by actor type
  const baseProfiles: Record<string, TimingProfile> = {
    apt: {
      avgDwellTimeMs: 3600000, // 1 hour between phases
      businessHoursOnly: true,
      activeHours: [{ start: 8, end: 17 }],
      c2JitterRange: { min: 30000, max: 120000 },
      beaconSleepMs: 60000,
    },
    cybercrime: {
      avgDwellTimeMs: 600000, // 10 minutes
      businessHoursOnly: false,
      activeHours: [{ start: 0, end: 24 }],
      c2JitterRange: { min: 5000, max: 30000 },
      beaconSleepMs: 30000,
    },
    ransomware: {
      avgDwellTimeMs: 300000, // 5 minutes — fast lateral movement
      businessHoursOnly: false,
      activeHours: [{ start: 0, end: 6 }, { start: 22, end: 24 }], // Off-hours
      c2JitterRange: { min: 1000, max: 10000 },
      beaconSleepMs: 10000,
    },
    hacktivist: {
      avgDwellTimeMs: 120000, // 2 minutes — fast and loud
      businessHoursOnly: false,
      activeHours: [{ start: 0, end: 24 }],
      c2JitterRange: { min: 1000, max: 5000 },
      beaconSleepMs: 5000,
    },
  };

  const profile = baseProfiles[actorType] || baseProfiles.apt;

  // Refine with fingerprint data if available
  if (fingerprint) {
    if (fingerprint.estimatedDwellTime && fingerprint.estimatedDwellTime !== 'unknown') {
      // Parse estimated dwell time string (e.g., '30-90 days') into ms
      const match = fingerprint.estimatedDwellTime.match(/(\d+)/);
      if (match) {
        const days = parseInt(match[1], 10);
        profile.avgDwellTimeMs = days * 86400000 / 10; // Scale down for emulation
      }
    }
  }

  return profile;
}

function buildOpsecProfile(
  actorName: string,
  actorType: string,
  actorCtx: ActorContext
): OpsecProfile {
  const baseProfile = ACTOR_TYPE_PROFILES[actorType] || ACTOR_TYPE_PROFILES.apt;

  const profile: OpsecProfile = {
    noiseLevel: baseProfile.noiseLevel || 5,
    encryptedC2: baseProfile.encryptedC2 ?? true,
    lotlPreference: baseProfile.lotlPreference ?? false,
    antiForensics: baseProfile.antiForensics ?? false,
    processInjection: baseProfile.processInjection ?? false,
    filelessPreference: baseProfile.filelessPreference ?? false,
    evasionTechniques: [...(baseProfile.evasionTechniques || [])],
  };

  // Enrich from actor techniques
  const evasionTechniques = actorCtx.techniques.filter(
    t => t.tactic.toLowerCase().includes("defense-evasion") ||
         t.tactic.toLowerCase().includes("evasion")
  );

  for (const tech of evasionTechniques) {
    if (tech.techniqueId === "T1055" || tech.techniqueName.toLowerCase().includes("process injection")) {
      profile.processInjection = true;
    }
    if (tech.techniqueId === "T1059" || tech.techniqueName.toLowerCase().includes("scripting")) {
      profile.lotlPreference = true;
    }
    if (tech.techniqueId === "T1070" || tech.techniqueName.toLowerCase().includes("indicator removal")) {
      profile.antiForensics = true;
    }
    if (!profile.evasionTechniques.includes(tech.techniqueName)) {
      profile.evasionTechniques.push(tech.techniqueName);
    }
  }

  return profile;
}

// ─── Phishing Template Selection ──────────────────────────────────────────────

/**
 * Actor-to-phishing-technique mapping based on known social engineering patterns.
 */
const ACTOR_PHISHING_PATTERNS: Record<string, {
  preferredExploitIds: string[];
  preferredCategories: string[];
  preferredTags: string[];
  description: string;
}> = {
  "APT29": {
    preferredExploitIds: ["cred-oauth-consent", "cred-device-code", "mfa-aitm-proxy", "post-email-rule"],
    preferredCategories: ["credential_harvesting", "mfa_bypass"],
    preferredTags: ["oauth", "token-theft", "microsoft365", "aitm"],
    description: "APT29 favors OAuth consent phishing and device code flows for persistent token access",
  },
  "APT28": {
    preferredExploitIds: ["cred-bitb-sso", "cred-progressive-mfa", "payload-html-smuggling"],
    preferredCategories: ["credential_harvesting", "payload_delivery"],
    preferredTags: ["sso", "credential-capture", "html-smuggling"],
    description: "APT28 uses browser-in-browser SSO phishing and HTML smuggling for payload delivery",
  },
  "FIN7": {
    preferredExploitIds: ["payload-clickfix", "payload-html-smuggling", "lp-keylogger", "post-session-hijack"],
    preferredCategories: ["payload_delivery", "landing_page_exploits"],
    preferredTags: ["social-engineering", "powershell", "keylogger", "session-hijacking"],
    description: "FIN7 uses ClickFix social engineering and invoice-themed lures with embedded payloads",
  },
  "Lazarus Group": {
    preferredExploitIds: ["payload-html-smuggling", "payload-clickfix", "lp-browser-fingerprint"],
    preferredCategories: ["payload_delivery", "landing_page_exploits"],
    preferredTags: ["html-smuggling", "social-engineering", "fingerprinting"],
    description: "Lazarus uses job-themed lures with HTML smuggling and browser fingerprinting",
  },
  "LockBit": {
    preferredExploitIds: ["cred-bitb-sso", "mfa-push-fatigue", "payload-html-smuggling"],
    preferredCategories: ["credential_harvesting", "mfa_bypass", "payload_delivery"],
    preferredTags: ["credential-capture", "push-bombing", "html-smuggling"],
    description: "LockBit affiliates use credential harvesting and MFA fatigue for initial access",
  },
  "BlackCat/ALPHV": {
    preferredExploitIds: ["mfa-aitm-proxy", "cred-bitb-sso", "post-session-hijack"],
    preferredCategories: ["mfa_bypass", "credential_harvesting"],
    preferredTags: ["aitm", "evilginx", "session-hijacking", "mfa-bypass"],
    description: "BlackCat uses AiTM proxy phishing (Evilginx) for MFA bypass and session hijacking",
  },
  "Conti": {
    preferredExploitIds: ["payload-html-smuggling", "cred-bitb-sso", "mfa-push-fatigue"],
    preferredCategories: ["payload_delivery", "credential_harvesting", "mfa_bypass"],
    preferredTags: ["html-smuggling", "credential-capture", "push-bombing"],
    description: "Conti operators use BazarLoader delivery via HTML smuggling and credential phishing",
  },
  "Turla": {
    preferredExploitIds: ["evasion-redirect-chain", "evasion-captcha-gate", "lp-browser-fingerprint", "post-email-rule"],
    preferredCategories: ["evasion", "landing_page_exploits"],
    preferredTags: ["redirect", "anti-scanner", "fingerprinting", "email-forwarding"],
    description: "Turla uses sophisticated redirect chains and anti-analysis gates for targeted delivery",
  },
};

export interface ActorPhishingRecommendation {
  /** Actor name */
  actorName: string;
  /** Why these exploits were selected */
  rationale: string;
  /** Recommended exploit IDs in priority order */
  recommendedExploitIds: string[];
  /** Recommended categories */
  recommendedCategories: string[];
  /** Tags to filter by */
  filterTags: string[];
  /** Confidence in the recommendation (0-100) */
  confidence: number;
  /** Source of the recommendation */
  source: "known_pattern" | "technique_inference" | "behavioral_sequence" | "generic";
}

/**
 * Get actor-specific phishing template recommendations.
 * Uses known actor patterns, technique-to-exploit mapping, and behavioral
 * sequences to recommend the most realistic phishing exploits for emulation.
 */
export async function getActorPhishingRecommendations(
  actorName: string,
  targetContext: {
    targetDomain?: string;
    targetSector?: string;
    technologies?: string[];
    usesSSO?: boolean;
    usesMfa?: boolean;
    idpProvider?: string;
  } = {}
): Promise<ActorPhishingRecommendation> {
  // Check known patterns first
  const knownPattern = ACTOR_PHISHING_PATTERNS[actorName];
  if (knownPattern) {
    return {
      actorName,
      rationale: knownPattern.description,
      recommendedExploitIds: knownPattern.preferredExploitIds,
      recommendedCategories: knownPattern.preferredCategories,
      filterTags: knownPattern.preferredTags,
      confidence: 90,
      source: "known_pattern",
    };
  }

  // Fall back to technique-based inference
  const actorCtx = await getActorContext({
    requestingModule: "phishing-selection",
    targetDomain: targetContext.targetDomain,
    targetSector: targetContext.targetSector,
    technologies: targetContext.technologies,
    includeNovelTechniques: false,
  });

  const matchedActor = actorCtx.actors.find(
    a => a.actorId.toLowerCase().includes(actorName.toLowerCase())
  );

  if (!matchedActor) {
    // Generic recommendation based on target context
    return buildGenericPhishingRecommendation(targetContext);
  }

  // Map actor techniques to phishing exploits
  const techniqueToExploit: Record<string, string[]> = {
    "T1566": ["cred-bitb-sso", "payload-html-smuggling", "payload-clickfix"],
    "T1566.001": ["payload-html-smuggling", "payload-clickfix"],
    "T1566.002": ["evasion-redirect-chain", "payload-qr-phishing"],
    "T1528": ["cred-oauth-consent", "cred-device-code"],
    "T1556": ["cred-bitb-sso", "cred-progressive-mfa"],
    "T1556.006": ["cred-bitb-sso", "cred-progressive-mfa"],
    "T1539": ["post-session-hijack", "mfa-aitm-proxy"],
    "T1557": ["mfa-aitm-proxy"],
    "T1621": ["mfa-push-fatigue", "lp-fake-mfa-push"],
    "T1204": ["payload-clickfix", "payload-html-smuggling"],
    "T1204.002": ["payload-clickfix", "payload-html-smuggling"],
    "T1027.006": ["payload-html-smuggling"],
    "T1056.001": ["lp-keylogger"],
    "T1114": ["post-email-rule"],
    "T1114.003": ["post-email-rule"],
  };

  const exploitIds = new Set<string>();
  const categories = new Set<string>();
  const tags = new Set<string>();

  for (const technique of actorCtx.techniques) {
    const mappedExploits = techniqueToExploit[technique.techniqueId];
    if (mappedExploits) {
      mappedExploits.forEach(e => exploitIds.add(e));
    }
    // Map tactics to categories
    if (technique.tactic.includes("credential")) categories.add("credential_harvesting");
    if (technique.tactic.includes("initial-access")) categories.add("payload_delivery");
    if (technique.tactic.includes("defense-evasion")) categories.add("evasion");
  }

  // Add context-aware recommendations
  if (targetContext.usesSSO) {
    exploitIds.add("cred-bitb-sso");
    exploitIds.add("cred-oauth-consent");
    tags.add("sso");
  }
  if (targetContext.usesMfa) {
    exploitIds.add("mfa-aitm-proxy");
    exploitIds.add("mfa-push-fatigue");
    categories.add("mfa_bypass");
    tags.add("mfa-bypass");
  }

  return {
    actorName,
    rationale: `Inferred from ${actorCtx.techniques.length} known techniques attributed to ${actorName}`,
    recommendedExploitIds: Array.from(exploitIds),
    recommendedCategories: Array.from(categories),
    filterTags: Array.from(tags),
    confidence: 65,
    source: "technique_inference",
  };
}

/**
 * Get all known actor phishing patterns for display/selection.
 */
export function getKnownActorPhishingPatterns(): Array<{
  actorName: string;
  description: string;
  exploitCount: number;
  categories: string[];
}> {
  return Object.entries(ACTOR_PHISHING_PATTERNS).map(([name, pattern]) => ({
    actorName: name,
    description: pattern.description,
    exploitCount: pattern.preferredExploitIds.length,
    categories: pattern.preferredCategories,
  }));
}

function buildGenericPhishingRecommendation(
  targetContext: {
    usesSSO?: boolean;
    usesMfa?: boolean;
    idpProvider?: string;
  }
): ActorPhishingRecommendation {
  const exploitIds: string[] = [];
  const categories: string[] = [];
  const tags: string[] = [];

  if (targetContext.usesSSO) {
    exploitIds.push("cred-bitb-sso", "cred-oauth-consent");
    categories.push("credential_harvesting");
    tags.push("sso");
  }
  if (targetContext.usesMfa) {
    exploitIds.push("mfa-aitm-proxy", "mfa-push-fatigue", "cred-progressive-mfa");
    categories.push("mfa_bypass");
    tags.push("mfa-bypass");
  }
  if (!targetContext.usesSSO && !targetContext.usesMfa) {
    exploitIds.push("cred-bitb-sso", "payload-clickfix", "payload-html-smuggling");
    categories.push("credential_harvesting", "payload_delivery");
  }

  return {
    actorName: "generic",
    rationale: "No specific actor pattern found — recommendations based on target environment",
    recommendedExploitIds: exploitIds,
    recommendedCategories: categories,
    filterTags: tags,
    confidence: 40,
    source: "generic",
  };
}
