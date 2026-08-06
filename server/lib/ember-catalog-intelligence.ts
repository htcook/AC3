/**
 * Ember Catalog Intelligence Module
 * 
 * Bridges the enriched threat actor catalog (exploit playbooks, attack chains,
 * DFIR observations, IOC-to-TTP mappings) into Ember's cognitive core, enabling
 * threat-actor-informed red team exercise planning and execution.
 * 
 * This module:
 * 1. Builds threat-actor-aware system prompt context for Ember's LLM
 * 2. Generates actor-specific operation plans from catalog data
 * 3. Selects and loads appropriate capability modules based on actor TTPs
 * 4. Provides real-world technique context from DFIR observations
 * 5. Integrates phishing knowledge for initial access planning
 */

import { sql, eq, inArray, desc } from "drizzle-orm";
import {
  exploitPlaybooks,
  attackChainsCatalog,
  dfirObservations,
  iocTtpMappings,
  threatActors,
  threatActorAbilities,
  threatActorIocs,
} from "../../drizzle/schema";

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface EmberThreatContext {
  /** Matched threat actors relevant to the target */
  matchedActors: ActorProfile[];
  /** Prioritized attack chains from the catalog */
  attackChains: ChainSummary[];
  /** Relevant exploit playbooks with real-world commands */
  playbooks: PlaybookSummary[];
  /** DFIR-observed techniques with artifacts */
  dfirTechniques: DFIRTechniqueSummary[];
  /** Phishing initial access options */
  phishingOptions: PhishingOption[];
  /** IOC-derived technique intelligence */
  iocIntelligence: IOCIntelSummary[];
  /** Recommended Ember capability modules to load */
  recommendedModules: string[];
  /** System prompt context block for Ember's LLM */
  systemPromptContext: string;
}

export interface ActorProfile {
  actorId: string;
  name: string;
  aliases: string[];
  origin: string;
  motivation: string;
  targetSectors: string[];
  primaryTactics: string[];
  signatureTools: string[];
  knownCVEs: string[];
  abilityCount: number;
  playbookCount: number;
  chainCount: number;
}

export interface ChainSummary {
  chainName: string;
  actorName: string;
  objective: string;
  stepCount: number;
  killChainPhases: string[];
  techniques: string[];
  estimatedDuration: string;
  confidence: string;
}

export interface PlaybookSummary {
  name: string;
  actorName: string;
  vulnClass: string;
  techniqueId: string;
  platform: string;
  toolsUsed: string[];
  command: string;       // The actual command (truncated for prompt)
  confidence: string;
}

export interface DFIRTechniqueSummary {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  actorName: string;
  description: string;
  toolsObserved: string[];
  reportSource: string;
  confidence: string;
}

export interface PhishingOption {
  name: string;
  category: string;
  mitreId: string;
  effectiveness: number;
  description: string;
  deliveryMethod: string;
}

export interface IOCIntelSummary {
  iocType: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  reasoning: string;
  confidence: string;
}

// ─── Capability Module Mapping ───────────────────────────────────────────────

const TACTIC_TO_EMBER_MODULES: Record<string, string[]> = {
  "reconnaissance": ["ember.cognitive.env_analyzer"],
  "initial-access": ["ember.cognitive.attack_planner"],
  "execution": ["ember.exec.shell", "ember.exec.powershell"],
  "persistence": ["ember.persist.registry", "ember.persist.scheduled_task", "ember.persist.startup_folder"],
  "privilege-escalation": ["ember.privesc.token_manipulation", "ember.privesc.uac_bypass", "ember.privesc.suid_exploiter", "ember.privesc.kernel_exploit"],
  "defense-evasion": ["ember.evasion.amsi_bypass", "ember.evasion.etw_patch", "ember.evasion.log_cleaner", "ember.evasion.timestomp"],
  "credential-access": ["ember.cred.lsass_dump", "ember.cred.sam_extract", "ember.cred.kerberoast", "ember.cred.token_steal"],
  "discovery": ["ember.cognitive.env_analyzer"],
  "lateral-movement": ["ember.lateral.psexec", "ember.lateral.wmi_exec", "ember.lateral.ssh_pivot", "ember.lateral.pass_the_hash", "ember.lateral.rdp_hijack"],
  "collection": ["ember.collect.file_harvest", "ember.collect.screenshot", "ember.collect.keylogger", "ember.collect.clipboard"],
  "command-and-control": [],
  "exfiltration": ["ember.exfil.https_chunked", "ember.exfil.dns_tunnel", "ember.exfil.steganographic"],
  "impact": [],
};

// ─── Build Threat Context ────────────────────────────────────────────────────

/**
 * Build comprehensive threat actor context for Ember's cognitive core.
 * Queries the enriched catalog and assembles a structured context that
 * enables Ember to plan and execute actor-specific red team exercises.
 */
export async function buildEmberThreatContext(params: {
  targetPlatform?: string;      // windows | linux | darwin
  targetSector?: string;        // e.g., "financial", "healthcare"
  targetTechStack?: string[];   // e.g., ["apache", "mysql", "php"]
  actorIds?: string[];          // Specific actors to emulate
  maxActors?: number;
  maxPlaybooks?: number;
  maxChains?: number;
}): Promise<EmberThreatContext> {
  const { getDb } = await import("../db");
  const db = await getDb();
  
  const context: EmberThreatContext = {
    matchedActors: [],
    attackChains: [],
    playbooks: [],
    dfirTechniques: [],
    phishingOptions: [],
    iocIntelligence: [],
    recommendedModules: [],
    systemPromptContext: "",
  };
  
  if (!db) return context;
  
  const maxActors = params.maxActors || 5;
  const maxPlaybooks = params.maxPlaybooks || 15;
  const maxChains = params.maxChains || 10;
  
  try {
    // ── 1. Match relevant threat actors ──────────────────────────────────
    let actorRows: any[];
    if (params.actorIds && params.actorIds.length > 0) {
      const [rows] = await db.execute(
        sql`SELECT a.*, 
            (SELECT COUNT(*) FROM threat_actor_abilities ab WHERE ab.actorId = a.actorId) as abilityCount,
            (SELECT COUNT(*) FROM exploit_playbooks pb WHERE pb.actorId = a.actorId) as playbookCount,
            (SELECT COUNT(*) FROM attack_chains_catalog ac WHERE ac.actorId = a.actorId) as chainCount
          FROM threat_actors a 
          WHERE a.actorId IN (${sql.join(params.actorIds.map(id => sql`${id}`), sql`,`)})
          LIMIT ${maxActors}`
      );
      actorRows = rows as any[];
    } else {
      // Match by sector/motivation — get actors with the most catalog data
      const [rows] = await db.execute(
        sql`SELECT a.*, 
            (SELECT COUNT(*) FROM threat_actor_abilities ab WHERE ab.actorId = a.actorId) as abilityCount,
            (SELECT COUNT(*) FROM exploit_playbooks pb WHERE pb.actorId = a.actorId) as playbookCount,
            (SELECT COUNT(*) FROM attack_chains_catalog ac WHERE ac.actorId = a.actorId) as chainCount
          FROM threat_actors a 
          WHERE a.active = 1
          ORDER BY (SELECT COUNT(*) FROM threat_actor_abilities ab WHERE ab.actorId = a.actorId) DESC
          LIMIT ${maxActors}`
      );
      actorRows = rows as any[];
    }
    
    for (const actor of actorRows) {
      const aliases = actor.aliases ? (typeof actor.aliases === "string" ? JSON.parse(actor.aliases) : actor.aliases) : [];
      const targetSectors = actor.targetSectors ? (typeof actor.targetSectors === "string" ? JSON.parse(actor.targetSectors) : actor.targetSectors) : [];
      const tools = actor.tools ? (typeof actor.tools === "string" ? JSON.parse(actor.tools) : actor.tools) : [];
      const cves = actor.exploitedCves ? (typeof actor.exploitedCves === "string" ? JSON.parse(actor.exploitedCves) : actor.exploitedCves) : [];
      
      context.matchedActors.push({
        actorId: actor.actorId,
        name: actor.name,
        aliases: aliases.slice(0, 5),
        origin: actor.origin || "Unknown",
        motivation: actor.motivation || "Unknown",
        targetSectors: targetSectors.slice(0, 5),
        primaryTactics: actor.primaryTactics ? (typeof actor.primaryTactics === "string" ? JSON.parse(actor.primaryTactics) : actor.primaryTactics) : [],
        signatureTools: (Array.isArray(tools) ? tools : tools.map?.((t: any) => t.name || t) || []).slice(0, 10),
        knownCVEs: cves.slice(0, 10),
        abilityCount: Number(actor.abilityCount) || 0,
        playbookCount: Number(actor.playbookCount) || 0,
        chainCount: Number(actor.chainCount) || 0,
      });
    }
    
    const actorIds = context.matchedActors.map(a => a.actorId);
    
    // ── 2. Get relevant attack chains ────────────────────────────────────
    if (actorIds.length > 0) {
      try {
        const [chainRows] = await db.execute(
          sql`SELECT ac.*, ta.name as actorName 
            FROM attack_chains_catalog ac 
            LEFT JOIN threat_actors ta ON ac.actorId = ta.actorId
            WHERE ac.actorId IN (${sql.join(actorIds.map(id => sql`${id}`), sql`,`)})
            ORDER BY ac.confidence DESC
            LIMIT ${maxChains}`
        );
        
        for (const chain of (chainRows as any[])) {
          const steps = typeof chain.steps === "string" ? JSON.parse(chain.steps) : (chain.steps || []);
          const techniques = steps.map((s: any) => s.techniqueId).filter(Boolean);
          const phases = [...new Set(steps.map((s: any) => s.tactic || s.phase).filter(Boolean))];
          
          context.attackChains.push({
            chainName: chain.chainName || "Unnamed Chain",
            actorName: chain.actorName || "Unknown",
            objective: chain.objective || "",
            stepCount: steps.length,
            killChainPhases: phases,
            techniques,
            estimatedDuration: chain.estimatedDuration || `${steps.length * 5}m`,
            confidence: chain.confidence || "medium",
          });
        }
      } catch { /* table may be empty */ }
    }
    
    // ── 3. Get relevant exploit playbooks ────────────────────────────────
    if (actorIds.length > 0) {
      try {
        let platformFilter = "";
        if (params.targetPlatform) {
          platformFilter = params.targetPlatform;
        }
        
        const [pbRows] = await db.execute(
          sql`SELECT pb.*, ta.name as actorName 
            FROM exploit_playbooks pb 
            LEFT JOIN threat_actors ta ON pb.actorId = ta.actorId
            WHERE pb.actorId IN (${sql.join(actorIds.map(id => sql`${id}`), sql`,`)})
            ORDER BY pb.confidence DESC, pb.successRate DESC
            LIMIT ${maxPlaybooks}`
        );
        
        for (const pb of (pbRows as any[])) {
          const tools = typeof pb.toolsUsed === "string" ? JSON.parse(pb.toolsUsed) : (pb.toolsUsed || []);
          const steps = typeof pb.steps === "string" ? JSON.parse(pb.steps) : (pb.steps || []);
          const primaryStep = steps.find((s: any) => s.command || s.code) || steps[0];
          
          context.playbooks.push({
            name: pb.name || "Unnamed Playbook",
            actorName: pb.actorName || "Unknown",
            vulnClass: pb.vulnClass || "",
            techniqueId: pb.techniqueId || "",
            platform: pb.targetPlatform || "unknown",
            toolsUsed: tools.slice(0, 5),
            command: (primaryStep?.command || primaryStep?.code || "").substring(0, 200),
            confidence: pb.confidence || "medium",
          });
        }
      } catch { /* table may be empty */ }
    }
    
    // ── 4. Get DFIR-observed techniques ──────────────────────────────────
    try {
      const [dfirRows] = await db.execute(
        sql`SELECT d.*, ta.name as actorName 
          FROM dfir_observations d 
          LEFT JOIN threat_actors ta ON d.actorId = ta.actorId
          ORDER BY d.confidence DESC
          LIMIT 20`
      );
      
      for (const obs of (dfirRows as any[])) {
        const tools = typeof obs.toolsObserved === "string" ? JSON.parse(obs.toolsObserved) : (obs.toolsObserved || []);
        
        context.dfirTechniques.push({
          techniqueId: obs.techniqueId || "",
          techniqueName: obs.techniqueName || "",
          tactic: obs.tactic || "",
          actorName: obs.actorName || "Unknown",
          description: (obs.description || "").substring(0, 200),
          toolsObserved: tools.slice(0, 5),
          reportSource: obs.reportSource || "Unknown",
          confidence: obs.confidence || "medium",
        });
      }
    } catch { /* table may be empty */ }
    
    // ── 5. Get IOC-derived intelligence ──────────────────────────────────
    try {
      const [iocRows] = await db.execute(
        sql`SELECT * FROM ioc_ttp_mappings 
          WHERE confidence IN ('high', 'medium')
          ORDER BY confidence DESC
          LIMIT 15`
      );
      
      for (const mapping of (iocRows as any[])) {
        context.iocIntelligence.push({
          iocType: mapping.iocType || "",
          techniqueId: mapping.techniqueId || "",
          techniqueName: mapping.techniqueName || "",
          tactic: mapping.tactic || "",
          reasoning: (mapping.reasoning || "").substring(0, 150),
          confidence: mapping.confidence || "medium",
        });
      }
    } catch { /* table may be empty */ }
    
    // ── 6. Build phishing options from phishing-exploits knowledge ───────
    try {
      const { matchPhishingExploits, getPhishingMitreTechniques } = await import("./phishing-exploits");
      const techniques = getPhishingMitreTechniques();
      
      // Get top phishing techniques relevant to the target
      const matches = matchPhishingExploits({
        targetIndustry: params.targetSector,
        targetTechnology: params.targetTechStack,
        difficulty: "intermediate",
      });
      
      for (const match of (matches || []).slice(0, 5)) {
        context.phishingOptions.push({
          name: match.exploit.name,
          category: match.exploit.category,
          mitreId: match.exploit.mitreId,
          effectiveness: match.exploit.effectiveness,
          description: match.exploit.description.substring(0, 150),
          deliveryMethod: match.exploit.target === "email_template" ? "email" : match.exploit.target === "landing_page" ? "web" : "both",
        });
      }
    } catch { /* phishing module may not be available */ }
    
    // ── 7. Recommend Ember capability modules ────────────────────────────
    const allTactics = new Set<string>();
    context.attackChains.forEach(c => c.killChainPhases.forEach(p => allTactics.add(p)));
    context.playbooks.forEach(p => { if (p.techniqueId) allTactics.add(p.techniqueId.split(".")[0]); });
    context.dfirTechniques.forEach(d => { if (d.tactic) allTactics.add(d.tactic); });
    context.matchedActors.forEach(a => a.primaryTactics.forEach(t => allTactics.add(t)));
    
    const recommendedModules = new Set<string>();
    for (const tactic of allTactics) {
      const modules = TACTIC_TO_EMBER_MODULES[tactic.toLowerCase()] || [];
      modules.forEach(m => recommendedModules.add(m));
    }
    // Always include cognitive modules
    recommendedModules.add("ember.cognitive.attack_planner");
    recommendedModules.add("ember.cognitive.env_analyzer");
    recommendedModules.add("ember.cognitive.evasion_adapter");
    context.recommendedModules = [...recommendedModules];
    
    // ── 8. Build system prompt context ───────────────────────────────────
    context.systemPromptContext = buildSystemPromptContext(context);
    
  } catch (err: any) {
    console.error(`[EmberCatalogIntel] Error building threat context: ${err.message}`);
  }
  
  return context;
}

// ─── System Prompt Context Builder ───────────────────────────────────────────

function buildSystemPromptContext(ctx: EmberThreatContext): string {
  const sections: string[] = [];
  
  // Actor profiles
  if (ctx.matchedActors.length > 0) {
    sections.push("=== THREAT ACTOR INTELLIGENCE ===");
    for (const actor of ctx.matchedActors) {
      sections.push(`Actor: ${actor.name} (${actor.origin})`);
      if (actor.aliases.length > 0) sections.push(`  Aliases: ${actor.aliases.join(", ")}`);
      sections.push(`  Motivation: ${actor.motivation}`);
      if (actor.targetSectors.length > 0) sections.push(`  Target Sectors: ${actor.targetSectors.join(", ")}`);
      if (actor.primaryTactics.length > 0) sections.push(`  Primary Tactics: ${actor.primaryTactics.join(", ")}`);
      if (actor.signatureTools.length > 0) sections.push(`  Signature Tools: ${actor.signatureTools.join(", ")}`);
      if (actor.knownCVEs.length > 0) sections.push(`  Known CVEs: ${actor.knownCVEs.join(", ")}`);
      sections.push(`  Catalog Data: ${actor.abilityCount} abilities, ${actor.playbookCount} playbooks, ${actor.chainCount} chains`);
      sections.push("");
    }
  }
  
  // Attack chains
  if (ctx.attackChains.length > 0) {
    sections.push("=== KNOWN ATTACK CHAINS ===");
    sections.push("Use these real-world attack chains to guide your operation planning:");
    for (const chain of ctx.attackChains) {
      sections.push(`Chain: ${chain.chainName} (${chain.actorName})`);
      sections.push(`  Objective: ${chain.objective}`);
      sections.push(`  Phases: ${chain.killChainPhases.join(" → ")}`);
      sections.push(`  Techniques: ${chain.techniques.join(", ")}`);
      sections.push(`  Steps: ${chain.stepCount}, Duration: ${chain.estimatedDuration}, Confidence: ${chain.confidence}`);
      sections.push("");
    }
  }
  
  // Exploit playbooks
  if (ctx.playbooks.length > 0) {
    sections.push("=== EXPLOIT PLAYBOOKS (Real-World Commands) ===");
    sections.push("These are actual commands/scripts used by threat actors in the wild:");
    for (const pb of ctx.playbooks) {
      sections.push(`Playbook: ${pb.name} (${pb.actorName})`);
      sections.push(`  Vuln Class: ${pb.vulnClass} | Technique: ${pb.techniqueId} | Platform: ${pb.platform}`);
      if (pb.toolsUsed.length > 0) sections.push(`  Tools: ${pb.toolsUsed.join(", ")}`);
      if (pb.command) sections.push(`  Command: ${pb.command}`);
      sections.push("");
    }
  }
  
  // DFIR observations
  if (ctx.dfirTechniques.length > 0) {
    sections.push("=== DFIR-OBSERVED TECHNIQUES ===");
    sections.push("These techniques were observed in real incident response investigations:");
    for (const dfir of ctx.dfirTechniques.slice(0, 10)) {
      sections.push(`${dfir.techniqueId} ${dfir.techniqueName} (${dfir.tactic}) — ${dfir.actorName}`);
      sections.push(`  ${dfir.description}`);
      if (dfir.toolsObserved.length > 0) sections.push(`  Tools: ${dfir.toolsObserved.join(", ")}`);
      sections.push(`  Source: ${dfir.reportSource} | Confidence: ${dfir.confidence}`);
    }
    sections.push("");
  }
  
  // Phishing options
  if (ctx.phishingOptions.length > 0) {
    sections.push("=== PHISHING INITIAL ACCESS OPTIONS ===");
    for (const phish of ctx.phishingOptions) {
      sections.push(`${phish.name} (${phish.mitreId}) — Effectiveness: ${phish.effectiveness}/10`);
      sections.push(`  ${phish.description}`);
      sections.push(`  Delivery: ${phish.deliveryMethod}`);
    }
    sections.push("");
  }
  
  // IOC intelligence
  if (ctx.iocIntelligence.length > 0) {
    sections.push("=== IOC-DERIVED TECHNIQUE INTELLIGENCE ===");
    for (const ioc of ctx.iocIntelligence.slice(0, 8)) {
      sections.push(`${ioc.techniqueId} ${ioc.techniqueName} (from ${ioc.iocType} analysis)`);
      sections.push(`  ${ioc.reasoning}`);
    }
    sections.push("");
  }
  
  if (sections.length === 0) {
    return "No threat actor intelligence available from catalog. Proceed with standard methodology.";
  }
  
  return [
    "THREAT ACTOR INTELLIGENCE BRIEFING",
    "Use this intelligence to emulate real-world adversary behavior.",
    "Prioritize techniques and tools that match the threat actors below.",
    "Your operation should be indistinguishable from a real attack by these actors.",
    "",
    ...sections,
  ].join("\n");
}

// ─── Ember Operation Plan Generator ──────────────────────────────────────────

/**
 * Generate a threat-actor-specific operation plan for Ember to execute.
 * Uses the enriched catalog to create a realistic, actor-attributed operation.
 */
export async function generateActorEmulationPlan(params: {
  actorId: string;
  targetPlatform: string;
  objective: string;
  riskThreshold: number;
}): Promise<{
  operationName: string;
  actorName: string;
  phases: Array<{
    phase: string;
    technique: string;
    techniqueId: string;
    tool: string;
    command: string;
    emberModule: string;
    riskLevel: string;
  }>;
  estimatedDuration: string;
  recommendedModules: string[];
} | null> {
  const ctx = await buildEmberThreatContext({
    actorIds: [params.actorId],
    targetPlatform: params.targetPlatform,
    maxPlaybooks: 20,
    maxChains: 5,
  });
  
  if (ctx.matchedActors.length === 0) return null;
  
  const actor = ctx.matchedActors[0];
  const phases: Array<{
    phase: string;
    technique: string;
    techniqueId: string;
    tool: string;
    command: string;
    emberModule: string;
    riskLevel: string;
  }> = [];
  
  // Build phases from attack chains and playbooks
  if (ctx.attackChains.length > 0) {
    const chain = ctx.attackChains[0];
    for (const phase of chain.killChainPhases) {
      const matchingPlaybook = ctx.playbooks.find(p => 
        p.techniqueId && chain.techniques.includes(p.techniqueId)
      );
      const modules = TACTIC_TO_EMBER_MODULES[phase] || [];
      
      phases.push({
        phase,
        technique: matchingPlaybook?.vulnClass || phase,
        techniqueId: matchingPlaybook?.techniqueId || "",
        tool: matchingPlaybook?.toolsUsed[0] || "manual",
        command: matchingPlaybook?.command || "",
        emberModule: modules[0] || "ember.cognitive.attack_planner",
        riskLevel: ["initial-access", "execution", "privilege-escalation"].includes(phase) ? "high" : "medium",
      });
    }
  } else {
    // Fallback: build from actor's primary tactics
    for (const tactic of actor.primaryTactics.slice(0, 6)) {
      const modules = TACTIC_TO_EMBER_MODULES[tactic] || [];
      const matchingPlaybook = ctx.playbooks.find(p => p.platform === params.targetPlatform);
      
      phases.push({
        phase: tactic,
        technique: matchingPlaybook?.vulnClass || tactic,
        techniqueId: matchingPlaybook?.techniqueId || "",
        tool: matchingPlaybook?.toolsUsed[0] || "manual",
        command: matchingPlaybook?.command || "",
        emberModule: modules[0] || "ember.cognitive.attack_planner",
        riskLevel: "medium",
      });
    }
  }
  
  return {
    operationName: `${actor.name} Emulation — ${params.objective}`,
    actorName: actor.name,
    phases,
    estimatedDuration: `${phases.length * 10}m`,
    recommendedModules: ctx.recommendedModules,
  };
}

/**
 * Enhance Ember's system prompt with threat actor intelligence.
 * Call this before Ember's cognitive core analyzes the environment.
 */
export async function getEmberThreatPromptEnhancement(params: {
  targetPlatform?: string;
  targetSector?: string;
  targetTechStack?: string[];
  actorIds?: string[];
}): Promise<string> {
  const ctx = await buildEmberThreatContext(params);
  return ctx.systemPromptContext;
}
