/**
 * Actor Module Connectors — Bridges the Actor Context Provider into
 * previously disconnected offensive and defensive modules.
 *
 * Each connector enriches a specific module's output with actor-driven
 * intelligence: which actors use these techniques, what tools they prefer,
 * what behavioral patterns to expect, and what novel TTPs to watch for.
 *
 * Connected Modules:
 *  1. AD Attack Engine — actor-prioritized attack paths
 *  2. Cloud Attack Paths — actor-driven cloud misconfig prioritization
 *  3. Credential Tester — actor-preferred credential patterns
 *  4. ZAP Attack Playbooks — actor-specific web attack prioritization
 *  5. Sigma Rule Engine — actor-driven detection rule generation
 *  6. Cloud Security Validation — actor-informed benchmark prioritization
 *
 * Author: Harrison Cook — AceofCloud
 */

import type { ActorContext, ActorTechnique, EngagementContext } from "./actor-context-provider";
import {
  getADAttackContext,
  getCloudAttackContext,
  getCredentialAttackContext,
  getZAPPlaybookContext,
  getSigmaRuleContext,
  getActorContext,
  summarizeForPrompt,
} from "./actor-context-provider";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ActorEnrichedAttack {
  /** Original attack definition */
  attack: any;
  /** Actors known to use this technique */
  actorAttribution: { name: string; type: string; confidence: number }[];
  /** Actor-specific execution methods */
  actorExecutionMethods: string[];
  /** Actor-specific tools for this technique */
  actorTools: string[];
  /** C2 execution reliability (if available) */
  executionReliability: number;
  /** Behavioral context — how actors chain this with other techniques */
  chainContext: { prerequisites: string[]; followUps: string[] };
  /** Priority boost from actor intelligence (0-100) */
  actorPriorityBoost: number;
  /** Whether this is a novel/emerging technique */
  isNovel: boolean;
}

export interface ActorEnrichedCredentialProfile {
  /** Service type being targeted */
  serviceType: string;
  /** Actor-preferred credential patterns for this service */
  actorPreferredPatterns: {
    actorName: string;
    pattern: string;
    tools: string[];
    successRate: number;
  }[];
  /** Default credentials actors commonly exploit */
  actorExploitedDefaults: string[];
  /** Brute force strategies actors prefer */
  actorBruteForceStrategies: string[];
  /** IOCs associated with credential theft by these actors */
  credentialTheftIOCs: string[];
}

export interface ActorEnrichedPlaybook {
  /** Original playbook config */
  playbook: any;
  /** Actor-prioritized scan rules */
  actorPrioritizedRules: {
    ruleId: string;
    actorRelevance: string[];
    priorityBoost: number;
  }[];
  /** Actor-specific injection patterns */
  actorInjectionPatterns: string[];
  /** Web techniques actors are known to use */
  actorWebTechniques: {
    techniqueId: string;
    techniqueName: string;
    actors: string[];
  }[];
}

export interface ActorEnrichedSigmaSet {
  /** Original sigma rule set */
  ruleSet: any;
  /** Additional rules generated from actor behavioral patterns */
  actorBehavioralRules: any[];
  /** Rules generated from novel/emerging techniques */
  novelTechniqueRules: any[];
  /** Detection coverage gaps for actor techniques */
  coverageGaps: {
    techniqueId: string;
    techniqueName: string;
    actors: string[];
    gapType: string;
  }[];
}

// ─── 1. AD Attack Engine Connector ──────────────────────────────────────

/**
 * Enriches AD attack analysis with actor context.
 * Prioritizes attacks based on which threat actors target the engagement's
 * sector/region and which AD techniques they prefer.
 */
export async function enrichADAttackAnalysis(
  adAttacks: any[],
  engagementCtx: Partial<EngagementContext> = {}
): Promise<{
  enrichedAttacks: ActorEnrichedAttack[];
  actorSummary: string;
  topActors: string[];
  novelADTechniques: any[];
}> {
  const actorCtx = await getADAttackContext(engagementCtx);

  // Build a lookup of actor techniques by MITRE ID
  const techByMitre = new Map<string, ActorTechnique>();
  for (const tech of actorCtx.techniques) {
    techByMitre.set(tech.techniqueId, tech);
  }

  const enrichedAttacks: ActorEnrichedAttack[] = adAttacks.map(attack => {
    const mitreTechniques: string[] = attack.mitreTechniques || [];
    let actorPriorityBoost = 0;
    const actorAttribution: { name: string; type: string; confidence: number }[] = [];
    const actorExecutionMethods: string[] = [];
    const actorTools: string[] = [];
    let executionReliability = -1;
    const prerequisites: string[] = [];
    const followUps: string[] = [];

    for (const mitreId of mitreTechniques) {
      const actorTech = techByMitre.get(mitreId);
      if (actorTech) {
        // Add actor attribution
        for (const actorName of actorTech.usedBy) {
          const actor = actorCtx.actors.find(a => a.name === actorName);
          if (actor && !actorAttribution.some(a => a.name === actorName)) {
            actorAttribution.push({
              name: actorName,
              type: actor.type,
              confidence: actor.matchScore,
            });
          }
        }

        // Boost priority based on actor relevance
        actorPriorityBoost += actorTech.usedBy.length * 10;
        actorPriorityBoost += actorTech.confidence / 5;

        // Collect execution methods and tools
        for (const method of actorTech.executionMethods) {
          const methodStr = typeof method === "string" ? method : (method.method || method.description || "");
          if (methodStr && !actorExecutionMethods.includes(methodStr)) {
            actorExecutionMethods.push(methodStr);
          }
        }
        for (const tool of actorTech.tools) {
          if (!actorTools.includes(tool)) actorTools.push(tool);
        }

        // Get execution reliability from C2 insights
        const insight = actorCtx.executionInsights.find(i => i.techniqueId === mitreId);
        if (insight) {
          executionReliability = Math.max(executionReliability, insight.successRate);
        }

        // Chain context
        for (const p of actorTech.prerequisites) {
          if (!prerequisites.includes(p)) prerequisites.push(p);
        }
        for (const f of actorTech.followUps) {
          if (!followUps.includes(f)) followUps.push(f);
        }
      }
    }

    return {
      attack,
      actorAttribution,
      actorExecutionMethods: actorExecutionMethods.slice(0, 5),
      actorTools: actorTools.slice(0, 10),
      executionReliability,
      chainContext: { prerequisites: prerequisites.slice(0, 5), followUps: followUps.slice(0, 5) },
      actorPriorityBoost: Math.min(100, actorPriorityBoost),
      isNovel: false,
    };
  });

  // Sort by actor priority boost (highest first)
  enrichedAttacks.sort((a, b) => b.actorPriorityBoost - a.actorPriorityBoost);

  // Find novel AD-relevant techniques
  const novelADTechniques = actorCtx.novelTechniques.filter(nt =>
    nt.tactic.toLowerCase().includes("credential") ||
    nt.tactic.toLowerCase().includes("lateral") ||
    nt.tactic.toLowerCase().includes("persistence") ||
    nt.tactic.toLowerCase().includes("privilege")
  );

  return {
    enrichedAttacks,
    actorSummary: summarizeForPrompt(actorCtx, 1500),
    topActors: actorCtx.actors.slice(0, 5).map(a => a.name),
    novelADTechniques,
  };
}

// ─── 2. Cloud Attack Paths Connector ────────────────────────────────────

/**
 * Enriches cloud attack path analysis with actor context.
 * Prioritizes cloud misconfigurations based on which actors target cloud
 * infrastructure and which cloud techniques they prefer.
 */
export async function enrichCloudAttackPaths(
  cloudAttacks: any[],
  engagementCtx: Partial<EngagementContext> = {}
): Promise<{
  enrichedAttacks: ActorEnrichedAttack[];
  actorSummary: string;
  cloudActors: { name: string; cloudTechniques: string[]; preferredProvider: string }[];
  novelCloudTechniques: any[];
}> {
  const actorCtx = await getCloudAttackContext(engagementCtx);

  const techByMitre = new Map<string, ActorTechnique>();
  for (const tech of actorCtx.techniques) {
    techByMitre.set(tech.techniqueId, tech);
  }

  const enrichedAttacks: ActorEnrichedAttack[] = cloudAttacks.map(attack => {
    const mitreTechniques: string[] = attack.mitreTechniques || [];
    let actorPriorityBoost = 0;
    const actorAttribution: { name: string; type: string; confidence: number }[] = [];
    const actorTools: string[] = [];

    for (const mitreId of mitreTechniques) {
      const actorTech = techByMitre.get(mitreId);
      if (actorTech) {
        for (const actorName of actorTech.usedBy) {
          const actor = actorCtx.actors.find(a => a.name === actorName);
          if (actor && !actorAttribution.some(a => a.name === actorName)) {
            actorAttribution.push({ name: actorName, type: actor.type, confidence: actor.matchScore });
          }
        }
        actorPriorityBoost += actorTech.usedBy.length * 10 + actorTech.confidence / 5;
        for (const tool of actorTech.tools) {
          if (!actorTools.includes(tool)) actorTools.push(tool);
        }
      }
    }

    return {
      attack,
      actorAttribution,
      actorExecutionMethods: [],
      actorTools,
      executionReliability: -1,
      chainContext: { prerequisites: [], followUps: [] },
      actorPriorityBoost: Math.min(100, actorPriorityBoost),
      isNovel: false,
    };
  });

  enrichedAttacks.sort((a, b) => b.actorPriorityBoost - a.actorPriorityBoost);

  // Build cloud-specific actor profiles
  const cloudActors = actorCtx.actors.slice(0, 10).map(actor => {
    const cloudTechs = actorCtx.techniques
      .filter(t => t.usedBy.includes(actor.name))
      .map(t => t.techniqueId);

    // Determine preferred cloud provider based on techniques
    const awsCount = cloudTechs.filter(t => t.includes("T1078") || t.includes("T1098")).length;
    const azureCount = cloudTechs.filter(t => t.includes("T1136") || t.includes("T1556")).length;
    const gcpCount = cloudTechs.filter(t => t.includes("T1537") || t.includes("T1530")).length;

    let preferredProvider = "multi-cloud";
    if (awsCount > azureCount && awsCount > gcpCount) preferredProvider = "aws";
    else if (azureCount > awsCount && azureCount > gcpCount) preferredProvider = "azure";
    else if (gcpCount > awsCount && gcpCount > azureCount) preferredProvider = "gcp";

    return { name: actor.name, cloudTechniques: cloudTechs, preferredProvider };
  });

  const novelCloudTechniques = actorCtx.novelTechniques.filter(nt =>
    nt.tactic.toLowerCase().includes("initial") ||
    nt.tactic.toLowerCase().includes("privilege") ||
    nt.tactic.toLowerCase().includes("persistence") ||
    nt.tactic.toLowerCase().includes("collection")
  );

  return {
    enrichedAttacks,
    actorSummary: summarizeForPrompt(actorCtx, 1500),
    cloudActors,
    novelCloudTechniques,
  };
}

// ─── 3. Credential Engine Connector ─────────────────────────────────────

/**
 * Enriches credential testing with actor intelligence.
 * Provides actor-preferred credential patterns, brute force strategies,
 * and default credential exploitation preferences.
 */
export async function enrichCredentialTesting(
  serviceTypes: string[],
  engagementCtx: Partial<EngagementContext> = {}
): Promise<{
  profiles: ActorEnrichedCredentialProfile[];
  actorSummary: string;
  topCredentialActors: string[];
}> {
  const actorCtx = await getCredentialAttackContext(engagementCtx);

  // Map credential-related techniques to service types
  const credTechniques = actorCtx.techniques.filter(t =>
    t.tactic.toLowerCase().includes("credential") ||
    t.tactic.toLowerCase().includes("brute") ||
    t.tactic.toLowerCase().includes("initial")
  );

  const profiles: ActorEnrichedCredentialProfile[] = serviceTypes.map(serviceType => {
    const relevantTechs = credTechniques.filter(t => {
      const techName = t.techniqueName.toLowerCase();
      const svc = serviceType.toLowerCase();
      // Match technique to service type
      if (svc.includes("ssh") && (techName.includes("ssh") || techName.includes("remote"))) return true;
      if (svc.includes("rdp") && (techName.includes("rdp") || techName.includes("remote"))) return true;
      if (svc.includes("web") && (techName.includes("web") || techName.includes("http") || techName.includes("application"))) return true;
      if (svc.includes("smb") && (techName.includes("smb") || techName.includes("windows"))) return true;
      if (svc.includes("ftp") && (techName.includes("ftp") || techName.includes("file"))) return true;
      if (svc.includes("database") && (techName.includes("sql") || techName.includes("database"))) return true;
      // Default: include all credential techniques
      return t.tactic.toLowerCase().includes("credential");
    });

    const actorPreferredPatterns = relevantTechs.slice(0, 5).map(t => ({
      actorName: t.usedBy[0] || "Unknown",
      pattern: `${t.techniqueName} (${t.techniqueId})`,
      tools: t.tools.slice(0, 3),
      successRate: t.executionReliability >= 0 ? t.executionReliability : t.confidence,
    }));

    // Extract credential-specific IOCs
    const credIOCs = actorCtx.iocs
      .filter(ioc => ioc.type === "hash" || ioc.type === "domain" || ioc.context.toLowerCase().includes("credential"))
      .slice(0, 10)
      .map(ioc => `${ioc.type}:${ioc.value}`);

    // Extract brute force strategies from behavioral patterns
    const bruteForceStrategies = actorCtx.behavioralPatterns
      .filter(bp => bp.patternType === "initial_access_preference" || bp.description.toLowerCase().includes("brute"))
      .map(bp => `${bp.actorName}: ${bp.description.slice(0, 100)}`);

    // Extract default credential exploitation from actor tooling
    const defaultCredTools = actorCtx.tooling
      .filter(t => t.name.toLowerCase().includes("cred") || t.name.toLowerCase().includes("brute") || t.name.toLowerCase().includes("hydra"))
      .map(t => `${t.name} (used by ${t.usedBy.join(", ")})`);

    return {
      serviceType,
      actorPreferredPatterns,
      actorExploitedDefaults: defaultCredTools.slice(0, 5),
      actorBruteForceStrategies: bruteForceStrategies.slice(0, 5),
      credentialTheftIOCs: credIOCs,
    };
  });

  const topCredentialActors = actorCtx.actors
    .filter(a => actorCtx.techniques.some(t =>
      t.usedBy.includes(a.name) && t.tactic.toLowerCase().includes("credential")
    ))
    .slice(0, 5)
    .map(a => a.name);

  return {
    profiles,
    actorSummary: summarizeForPrompt(actorCtx, 1000),
    topCredentialActors,
  };
}

// ─── 4. ZAP Attack Playbooks Connector ──────────────────────────────────

/**
 * Enriches ZAP web application playbooks with actor context.
 * Prioritizes scan rules based on which web attack techniques are preferred
 * by matched threat actors.
 */
export async function enrichZAPPlaybooks(
  playbook: any,
  technologies: string[],
  engagementCtx: Partial<EngagementContext> = {}
): Promise<ActorEnrichedPlaybook> {
  const actorCtx = await getZAPPlaybookContext({
    ...engagementCtx,
    technologies,
  });

  // Map actor techniques to ZAP-relevant web attack categories
  const webTechniques = actorCtx.techniques.filter(t => {
    const tactic = t.tactic.toLowerCase();
    const name = t.techniqueName.toLowerCase();
    return tactic.includes("initial") ||
      tactic.includes("execution") ||
      tactic.includes("reconnaissance") ||
      name.includes("injection") ||
      name.includes("exploit") ||
      name.includes("web") ||
      name.includes("application") ||
      name.includes("scripting") ||
      name.includes("xss") ||
      name.includes("sql");
  });

  // Build actor-prioritized rules
  const actorPrioritizedRules = (playbook.scanRules || []).map((rule: any) => {
    const ruleNameLower = (rule.name || "").toLowerCase();
    const relevantActors = webTechniques
      .filter(t => {
        const techName = t.techniqueName.toLowerCase();
        return ruleNameLower.includes(techName.split(" ")[0] || "") ||
          techName.includes(ruleNameLower.split(" ")[0] || "");
      })
      .flatMap(t => t.usedBy);

    return {
      ruleId: rule.id || rule.name,
      actorRelevance: [...new Set(relevantActors)],
      priorityBoost: relevantActors.length * 15,
    };
  });

  // Extract actor-specific injection patterns from behavioral patterns
  const actorInjectionPatterns = actorCtx.behavioralPatterns
    .filter(bp =>
      bp.description.toLowerCase().includes("inject") ||
      bp.description.toLowerCase().includes("exploit") ||
      bp.description.toLowerCase().includes("web")
    )
    .map(bp => `${bp.actorName}: ${bp.description.slice(0, 150)}`);

  const actorWebTechniques = webTechniques.slice(0, 15).map(t => ({
    techniqueId: t.techniqueId,
    techniqueName: t.techniqueName,
    actors: t.usedBy,
  }));

  return {
    playbook,
    actorPrioritizedRules,
    actorInjectionPatterns: actorInjectionPatterns.slice(0, 10),
    actorWebTechniques,
  };
}

// ─── 5. Sigma Rule Engine Connector ─────────────────────────────────────

/**
 * Enriches Sigma rule generation with actor context.
 * Generates additional detection rules based on actor behavioral patterns,
 * novel techniques, and C2 execution insights.
 */
export async function enrichSigmaRuleGeneration(
  existingRuleSet: any,
  engagementCtx: Partial<EngagementContext> = {}
): Promise<ActorEnrichedSigmaSet> {
  const actorCtx = await getSigmaRuleContext(engagementCtx);

  // Generate behavioral rules from actor patterns
  const actorBehavioralRules: any[] = [];

  for (const pattern of actorCtx.behavioralPatterns.slice(0, 10)) {
    if (pattern.techniques.length === 0) continue;

    actorBehavioralRules.push({
      id: `actor-behavioral-${pattern.actorName.toLowerCase().replace(/\s+/g, "-")}-${pattern.patternType}`,
      title: `${pattern.actorName} ${pattern.patternType.replace(/_/g, " ")} Detection`,
      description: `Detects ${pattern.actorName} behavioral pattern: ${pattern.description.slice(0, 200)}`,
      level: pattern.confidence > 70 ? "high" : "medium",
      status: "experimental",
      techniques: pattern.techniques,
      actorName: pattern.actorName,
      confidence: pattern.confidence,
      sourceReports: pattern.sourceReports,
    });
  }

  // Generate rules from novel techniques
  const novelTechniqueRules: any[] = [];

  for (const novel of actorCtx.novelTechniques.filter(n => n.noveltyConfidence > 40).slice(0, 10)) {
    novelTechniqueRules.push({
      id: `novel-technique-${novel.tempId}`,
      title: `Emerging Technique Detection — ${novel.name}`,
      description: `Detects novel technique "${novel.name}" discovered from ${novel.discoverySource}. ${novel.analysis.slice(0, 200)}`,
      level: novel.noveltyConfidence > 70 ? "high" : "medium",
      status: "experimental",
      closestMitreId: novel.closestMitreId,
      observedActors: novel.observedActors,
      noveltyConfidence: novel.noveltyConfidence,
    });
  }

  // Identify detection coverage gaps
  const existingRuleIds = new Set(
    ((existingRuleSet?.rules || []) as any[]).map((r: any) => r.techniqueId || r.techniques?.[0])
  );

  const coverageGaps = actorCtx.techniques
    .filter(t => !existingRuleIds.has(t.techniqueId) && t.detectionCoverage.sigma === 0)
    .map(t => ({
      techniqueId: t.techniqueId,
      techniqueName: t.techniqueName,
      actors: t.usedBy,
      gapType: t.redTeamValue > 7 ? "critical-gap" : "coverage-gap",
    }));

  return {
    ruleSet: existingRuleSet,
    actorBehavioralRules,
    novelTechniqueRules,
    coverageGaps: coverageGaps.slice(0, 20),
  };
}

// ─── 6. Cloud Security Validation Connector ─────────────────────────────

/**
 * Enriches cloud security validation with actor-informed prioritization.
 * Prioritizes CIS benchmark checks based on which cloud misconfigurations
 * are most commonly exploited by matched threat actors.
 */
export async function enrichCloudSecurityValidation(
  provider: "aws" | "azure" | "gcp",
  benchmarkResults: any[],
  engagementCtx: Partial<EngagementContext> = {}
): Promise<{
  enrichedResults: (any & { actorRelevance: string[]; actorPriorityBoost: number })[];
  actorCloudInsights: string;
  criticalActorExploitedChecks: string[];
}> {
  const actorCtx = await getCloudAttackContext(engagementCtx);

  // Map cloud techniques to benchmark check categories
  const cloudTechNames = actorCtx.techniques.map(t => t.techniqueName.toLowerCase());

  const enrichedResults = benchmarkResults.map(result => {
    const checkName = (result.name || result.title || "").toLowerCase();
    const checkDesc = (result.description || "").toLowerCase();

    // Find actors whose techniques match this check
    const relevantActors: string[] = [];
    let priorityBoost = 0;

    for (const tech of actorCtx.techniques) {
      const techName = tech.techniqueName.toLowerCase();
      if (
        checkName.includes(techName.split(" ")[0] || "") ||
        checkDesc.includes(techName.split(" ")[0] || "") ||
        (checkName.includes("iam") && techName.includes("account")) ||
        (checkName.includes("encryption") && techName.includes("data")) ||
        (checkName.includes("logging") && techName.includes("evasion")) ||
        (checkName.includes("network") && techName.includes("network"))
      ) {
        for (const actor of tech.usedBy) {
          if (!relevantActors.includes(actor)) relevantActors.push(actor);
        }
        priorityBoost += tech.usedBy.length * 5 + tech.redTeamValue;
      }
    }

    return {
      ...result,
      actorRelevance: relevantActors,
      actorPriorityBoost: Math.min(100, priorityBoost),
    };
  });

  // Sort by actor priority
  enrichedResults.sort((a, b) => b.actorPriorityBoost - a.actorPriorityBoost);

  // Identify checks that are actively exploited by matched actors
  const criticalActorExploitedChecks = enrichedResults
    .filter(r => r.actorRelevance.length > 0 && r.actorPriorityBoost > 30)
    .slice(0, 10)
    .map(r => `${r.name || r.title}: exploited by ${r.actorRelevance.join(", ")}`);

  return {
    enrichedResults,
    actorCloudInsights: summarizeForPrompt(actorCtx, 1000),
    criticalActorExploitedChecks,
  };
}

// ─── Utility: Get Actor Context for Any Module ──────────────────────────

/**
 * Generic enrichment for any module not covered by specific connectors.
 * Returns a prompt-ready summary and the full actor context.
 */
export async function getModuleActorEnrichment(
  moduleName: string,
  engagementCtx: Partial<EngagementContext> = {}
): Promise<{
  context: ActorContext;
  promptSummary: string;
  topActors: string[];
  topTechniques: string[];
  activeIOCs: number;
  novelCount: number;
}> {
  const context = await getActorContext({
    requestingModule: moduleName,
    includeNovelTechniques: true,
    ...engagementCtx,
  });

  return {
    context,
    promptSummary: summarizeForPrompt(context),
    topActors: context.actors.slice(0, 5).map(a => a.name),
    topTechniques: context.techniques.slice(0, 10).map(t => `${t.techniqueId} ${t.techniqueName}`),
    activeIOCs: context.iocs.length,
    novelCount: context.novelTechniques.length,
  };
}
