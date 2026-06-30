/**
 * Catalog → Caldera Enrichment Bridge
 * 
 * Converts enriched threat actor catalog data (exploit playbooks, attack chains,
 * DFIR observations, IOC-to-TTP mappings) into actionable Caldera abilities and
 * operations for detailed, actor-specific red team exercises.
 * 
 * Flow: exploit_playbooks + attack_chains_catalog + dfir_observations → Caldera abilities → operations
 */

import { sql, eq } from "drizzle-orm";
import {
  exploitPlaybooks,
  attackChainsCatalog,
  dfirObservations,
  iocTtpMappings,
  threatActors,
  threatActorAbilities,
} from "../../drizzle/schema";

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface CatalogAbility {
  abilityId: string;
  name: string;
  description: string;
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  executor: {
    platform: string;       // windows | linux | darwin
    name: string;           // psh | sh | cmd | manual
    command: string;         // The actual command/script
    cleanup?: string;        // Cleanup command
    timeout?: number;
  };
  requirements: string[];
  source: "playbook" | "dfir" | "ioc_ttp" | "attack_chain";
  sourceId: string;
  actorAttribution: string[];  // Actor names that use this technique
  confidence: "high" | "medium" | "low";
  tags: string[];
}

export interface CatalogOperation {
  operationId: string;
  name: string;
  description: string;
  adversaryId: string;
  abilities: string[];      // Ordered ability IDs
  killChainPhases: string[];
  source: "attack_chain" | "dfir_chain" | "actor_profile";
  sourceId: string;
  actorAttribution: string[];
  objective: string;
  estimatedDuration: string;
  riskLevel: "low" | "medium" | "high" | "critical";
}

export interface EnrichmentResult {
  abilitiesGenerated: number;
  operationsGenerated: number;
  actorsEnriched: number;
  abilities: CatalogAbility[];
  operations: CatalogOperation[];
  errors: string[];
}

// ─── Platform Detection ──────────────────────────────────────────────────────

function detectPlatform(command: string, context: string): string {
  const combined = `${command} ${context}`.toLowerCase();
  if (combined.includes("powershell") || combined.includes("psh") || combined.includes(".exe") ||
      combined.includes("cmd /c") || combined.includes("reg add") || combined.includes("wmic") ||
      combined.includes("net user") || combined.includes("mimikatz") || combined.includes("certutil")) {
    return "windows";
  }
  if (combined.includes("bash") || combined.includes("/bin/sh") || combined.includes("chmod") ||
      combined.includes("crontab") || combined.includes("/etc/") || combined.includes("sudo") ||
      combined.includes("iptables") || combined.includes("systemctl")) {
    return "linux";
  }
  if (combined.includes("osascript") || combined.includes("launchctl") || combined.includes("defaults write")) {
    return "darwin";
  }
  return "linux"; // Default to linux
}

function detectExecutor(command: string, platform: string): string {
  if (platform === "windows") {
    if (command.toLowerCase().includes("powershell") || command.includes("$") || command.includes("Get-") ||
        command.includes("Invoke-") || command.includes("New-") || command.includes("Set-")) {
      return "psh";
    }
    return "cmd";
  }
  return "sh";
}

// ─── Tactic Normalization ────────────────────────────────────────────────────

const MITRE_TACTIC_MAP: Record<string, string> = {
  "reconnaissance": "reconnaissance",
  "recon": "reconnaissance",
  "resource development": "resource-development",
  "resource-development": "resource-development",
  "initial access": "initial-access",
  "initial-access": "initial-access",
  "execution": "execution",
  "persistence": "persistence",
  "privilege escalation": "privilege-escalation",
  "privilege-escalation": "privilege-escalation",
  "privesc": "privilege-escalation",
  "defense evasion": "defense-evasion",
  "defense-evasion": "defense-evasion",
  "evasion": "defense-evasion",
  "credential access": "credential-access",
  "credential-access": "credential-access",
  "credential dumping": "credential-access",
  "discovery": "discovery",
  "lateral movement": "lateral-movement",
  "lateral-movement": "lateral-movement",
  "collection": "collection",
  "command and control": "command-and-control",
  "command-and-control": "command-and-control",
  "c2": "command-and-control",
  "exfiltration": "exfiltration",
  "impact": "impact",
};

function normalizeTactic(tactic: string): string {
  return MITRE_TACTIC_MAP[tactic.toLowerCase().trim()] || tactic.toLowerCase().replace(/\s+/g, "-");
}

// ─── Ability Generation from Playbooks ───────────────────────────────────────

function generateAbilityFromPlaybook(playbook: any): CatalogAbility | null {
  try {
    const steps = typeof playbook.steps === "string" ? JSON.parse(playbook.steps) : playbook.steps;
    const tools = typeof playbook.toolsUsed === "string" ? JSON.parse(playbook.toolsUsed) : (playbook.toolsUsed || []);
    
    if (!steps || !Array.isArray(steps) || steps.length === 0) return null;
    
    // Find the primary execution step (the one with a command)
    const execStep = steps.find((s: any) => s.command || s.code || s.script) || steps[0];
    const command = execStep?.command || execStep?.code || execStep?.script || "";
    if (!command) return null;
    
    const platform = detectPlatform(command, playbook.description || "");
    const executor = detectExecutor(command, platform);
    
    return {
      abilityId: `catalog-pb-${playbook.id || Date.now().toString(36)}`,
      name: playbook.name || `Playbook: ${playbook.techniqueId || "Unknown"}`,
      description: playbook.description || `Exploit playbook from catalog: ${playbook.name}`,
      tactic: normalizeTactic(playbook.tactic || execStep?.phase || "execution"),
      techniqueId: playbook.techniqueId || "",
      techniqueName: playbook.techniqueName || "",
      executor: {
        platform,
        name: executor,
        command,
        cleanup: steps.find((s: any) => s.cleanup)?.cleanup,
        timeout: playbook.timeout || 120,
      },
      requirements: (playbook.prerequisites ? 
        (typeof playbook.prerequisites === "string" ? JSON.parse(playbook.prerequisites) : playbook.prerequisites) 
        : []),
      source: "playbook",
      sourceId: String(playbook.id || ""),
      actorAttribution: playbook.actorName ? [playbook.actorName] : [],
      confidence: playbook.confidence || "medium",
      tags: [...tools, playbook.vulnClass, playbook.targetPlatform].filter(Boolean),
    };
  } catch {
    return null;
  }
}

// ─── Ability Generation from DFIR Observations ──────────────────────────────

function generateAbilityFromDFIR(obs: any): CatalogAbility | null {
  try {
    const artifacts = typeof obs.artifacts === "string" ? JSON.parse(obs.artifacts) : (obs.artifacts || []);
    const tools = typeof obs.toolsObserved === "string" ? JSON.parse(obs.toolsObserved) : (obs.toolsObserved || []);
    
    // Find command artifacts
    const cmdArtifact = artifacts.find((a: any) => 
      a.type === "command" || a.type === "script" || a.type === "process_execution"
    );
    
    const command = cmdArtifact?.value || cmdArtifact?.command || "";
    if (!command) return null;
    
    const platform = detectPlatform(command, obs.description || "");
    const executor = detectExecutor(command, platform);
    
    return {
      abilityId: `catalog-dfir-${obs.id || Date.now().toString(36)}`,
      name: `DFIR: ${obs.techniqueName || obs.techniqueId || "Observed Technique"}`,
      description: `Technique observed in DFIR investigation: ${obs.description || ""}. Source: ${obs.reportSource || "Unknown"}`,
      tactic: normalizeTactic(obs.tactic || "execution"),
      techniqueId: obs.techniqueId || "",
      techniqueName: obs.techniqueName || "",
      executor: {
        platform,
        name: executor,
        command,
        timeout: 120,
      },
      requirements: [],
      source: "dfir",
      sourceId: String(obs.id || ""),
      actorAttribution: obs.actorName ? [obs.actorName] : [],
      confidence: obs.confidence || "medium",
      tags: [...tools, "dfir-observed", obs.reportSource].filter(Boolean),
    };
  } catch {
    return null;
  }
}

// ─── Ability Generation from IOC-to-TTP Mappings ────────────────────────────

function generateAbilityFromIOCTTP(mapping: any): CatalogAbility | null {
  try {
    const impliedCommand = mapping.impliedCommand || "";
    if (!impliedCommand) return null;
    
    const platform = detectPlatform(impliedCommand, mapping.description || "");
    const executor = detectExecutor(impliedCommand, platform);
    
    return {
      abilityId: `catalog-ioc-${mapping.id || Date.now().toString(36)}`,
      name: `IOC-Derived: ${mapping.techniqueName || mapping.techniqueId || "Implied Technique"}`,
      description: `Technique implied by IOC analysis: ${mapping.iocType} indicator "${(mapping.iocValue || "").substring(0, 50)}". ${mapping.reasoning || ""}`,
      tactic: normalizeTactic(mapping.tactic || "execution"),
      techniqueId: mapping.techniqueId || "",
      techniqueName: mapping.techniqueName || "",
      executor: {
        platform,
        name: executor,
        command: impliedCommand,
        timeout: 60,
      },
      requirements: [],
      source: "ioc_ttp",
      sourceId: String(mapping.id || ""),
      actorAttribution: mapping.actorName ? [mapping.actorName] : [],
      confidence: mapping.confidence || "low",
      tags: ["ioc-derived", mapping.iocType].filter(Boolean),
    };
  } catch {
    return null;
  }
}

// ─── Operation Generation from Attack Chains ─────────────────────────────────

function generateOperationFromChain(chain: any, abilities: CatalogAbility[]): CatalogOperation | null {
  try {
    const steps = typeof chain.steps === "string" ? JSON.parse(chain.steps) : (chain.steps || []);
    if (!steps || steps.length === 0) return null;
    
    // Map chain steps to ability IDs
    const orderedAbilityIds: string[] = [];
    const killChainPhases: string[] = [];
    
    for (const step of steps) {
      // Find matching ability by technique ID
      const matchingAbility = abilities.find(a => 
        a.techniqueId === step.techniqueId || 
        a.name.includes(step.techniqueName || "___never_match___")
      );
      if (matchingAbility) {
        orderedAbilityIds.push(matchingAbility.abilityId);
        if (!killChainPhases.includes(matchingAbility.tactic)) {
          killChainPhases.push(matchingAbility.tactic);
        }
      }
    }
    
    if (orderedAbilityIds.length === 0) return null;
    
    const actors = chain.actorName ? [chain.actorName] : [];
    
    return {
      operationId: `catalog-op-${chain.id || Date.now().toString(36)}`,
      name: chain.chainName || `${actors[0] || "Unknown"} Attack Chain`,
      description: chain.description || `Attack chain from catalog with ${orderedAbilityIds.length} steps across ${killChainPhases.length} kill chain phases.`,
      adversaryId: `catalog-adv-${chain.actorId || "generic"}`,
      abilities: orderedAbilityIds,
      killChainPhases,
      source: "attack_chain",
      sourceId: String(chain.id || ""),
      actorAttribution: actors,
      objective: chain.objective || "Complete attack chain execution",
      estimatedDuration: chain.estimatedDuration || `${orderedAbilityIds.length * 5}m`,
      riskLevel: chain.riskLevel || (orderedAbilityIds.length > 5 ? "high" : "medium"),
    };
  } catch {
    return null;
  }
}

// ─── Main Enrichment Function ────────────────────────────────────────────────

/**
 * Generate Caldera abilities and operations from the enriched threat actor catalog.
 * Reads from exploit_playbooks, attack_chains_catalog, dfir_observations, and ioc_ttp_mappings,
 * then produces structured abilities and operations ready for Caldera deployment.
 */
export async function enrichCalderaFromCatalog(options?: {
  actorId?: string;
  limit?: number;
  sources?: ("playbook" | "dfir" | "ioc_ttp" | "attack_chain")[];
}): Promise<EnrichmentResult> {
  const { getDb } = await import("../db");
  const db = await getDb();
  
  const result: EnrichmentResult = {
    abilitiesGenerated: 0,
    operationsGenerated: 0,
    actorsEnriched: 0,
    abilities: [],
    operations: [],
    errors: [],
  };
  
  if (!db) {
    result.errors.push("Database not available");
    return result;
  }
  
  const sources = options?.sources || ["playbook", "dfir", "ioc_ttp", "attack_chain"];
  const limit = options?.limit || 500;
  const actorFilter = options?.actorId;
  const enrichedActors = new Set<string>();
  
  // ── 1. Generate abilities from exploit playbooks ──────────────────────
  if (sources.includes("playbook")) {
    try {
      let query = sql`SELECT * FROM exploit_playbooks WHERE 1=1`;
      if (actorFilter) query = sql`SELECT * FROM exploit_playbooks WHERE actorId = ${actorFilter}`;
      const [rows] = await db.execute(query);
      const playbooks = rows as any[];
      
      for (const pb of playbooks.slice(0, limit)) {
        const ability = generateAbilityFromPlaybook(pb);
        if (ability) {
          result.abilities.push(ability);
          if (pb.actorId) enrichedActors.add(pb.actorId);
        }
      }
    } catch (err: any) {
      result.errors.push(`Playbook ingestion error: ${err.message}`);
    }
  }
  
  // ── 2. Generate abilities from DFIR observations ──────────────────────
  if (sources.includes("dfir")) {
    try {
      let query = sql`SELECT * FROM dfir_observations WHERE 1=1`;
      if (actorFilter) query = sql`SELECT * FROM dfir_observations WHERE actorId = ${actorFilter}`;
      const [rows] = await db.execute(query);
      const observations = rows as any[];
      
      for (const obs of observations.slice(0, limit)) {
        const ability = generateAbilityFromDFIR(obs);
        if (ability) {
          result.abilities.push(ability);
          if (obs.actorId) enrichedActors.add(obs.actorId);
        }
      }
    } catch (err: any) {
      result.errors.push(`DFIR ingestion error: ${err.message}`);
    }
  }
  
  // ── 3. Generate abilities from IOC-to-TTP mappings ────────────────────
  if (sources.includes("ioc_ttp")) {
    try {
      let query = sql`SELECT m.*, a.name as actorName FROM ioc_ttp_mappings m LEFT JOIN threat_actors a ON m.actorId = a.actorId WHERE m.impliedCommand IS NOT NULL AND m.impliedCommand != ''`;
      if (actorFilter) query = sql`SELECT m.*, a.name as actorName FROM ioc_ttp_mappings m LEFT JOIN threat_actors a ON m.actorId = a.actorId WHERE m.actorId = ${actorFilter} AND m.impliedCommand IS NOT NULL AND m.impliedCommand != ''`;
      const [rows] = await db.execute(query);
      const mappings = rows as any[];
      
      for (const mapping of mappings.slice(0, limit)) {
        const ability = generateAbilityFromIOCTTP(mapping);
        if (ability) {
          result.abilities.push(ability);
          if (mapping.actorId) enrichedActors.add(mapping.actorId);
        }
      }
    } catch (err: any) {
      result.errors.push(`IOC-TTP ingestion error: ${err.message}`);
    }
  }
  
  // ── 4. Generate operations from attack chains ─────────────────────────
  if (sources.includes("attack_chain")) {
    try {
      let query = sql`SELECT * FROM attack_chains_catalog WHERE 1=1`;
      if (actorFilter) query = sql`SELECT * FROM attack_chains_catalog WHERE actorId = ${actorFilter}`;
      const [rows] = await db.execute(query);
      const chains = rows as any[];
      
      for (const chain of chains.slice(0, limit)) {
        const operation = generateOperationFromChain(chain, result.abilities);
        if (operation) {
          result.operations.push(operation);
          if (chain.actorId) enrichedActors.add(chain.actorId);
        }
      }
    } catch (err: any) {
      result.errors.push(`Attack chain ingestion error: ${err.message}`);
    }
  }
  
  result.abilitiesGenerated = result.abilities.length;
  result.operationsGenerated = result.operations.length;
  result.actorsEnriched = enrichedActors.size;
  
  return result;
}

// ─── Push Enriched Abilities to Caldera ──────────────────────────────────────

/**
 * Push catalog-generated abilities to the Caldera C2 server as custom abilities.
 * Each ability is pushed via POST /api/v2/abilities.
 */
export async function pushCatalogAbilitiesToCaldera(abilities: CatalogAbility[]): Promise<{
  pushed: number;
  failed: number;
  errors: string[];
}> {
  const { ENV } = await import("../_core/env");
  const baseUrl = ENV.calderaBaseUrl || "";
  const apiKey = ENV.calderaApiKey || "";
  
  if (!baseUrl || !apiKey) {
    return { pushed: 0, failed: abilities.length, errors: ["Caldera not configured"] };
  }
  
  let pushed = 0;
  let failed = 0;
  const errors: string[] = [];
  
  for (const ability of abilities) {
    try {
      const payload = {
        ability_id: ability.abilityId,
        name: ability.name,
        description: ability.description,
        tactic: ability.tactic,
        technique: { attack_id: ability.techniqueId, name: ability.techniqueName },
        executors: [{
          platform: ability.executor.platform,
          name: ability.executor.name,
          command: ability.executor.command,
          cleanup: ability.executor.cleanup || [],
          timeout: ability.executor.timeout || 120,
        }],
        requirements: ability.requirements.map(r => ({ module: "plugins.stockpile.app.requirements.paw_provenance", relationship_match: [{ source: r }] })),
        singleton: false,
        plugin: "catalog-enrichment",
        access: { request: ability.executor.platform, response: ability.executor.platform },
      };
      
      const response = await fetch(`${baseUrl}/api/v2/abilities`, {
        method: "POST",
        headers: { KEY: apiKey, "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(15000),
      });
      
      if (response.ok) {
        pushed++;
      } else {
        failed++;
        errors.push(`${ability.abilityId}: HTTP ${response.status}`);
      }
    } catch (err: any) {
      failed++;
      errors.push(`${ability.abilityId}: ${err.message}`);
    }
  }
  
  return { pushed, failed, errors };
}

/**
 * Push a catalog-generated operation to Caldera as an adversary profile.
 */
export async function pushCatalogOperationToCaldera(operation: CatalogOperation): Promise<{
  success: boolean;
  adversaryId?: string;
  error?: string;
}> {
  const { ENV } = await import("../_core/env");
  const baseUrl = ENV.calderaBaseUrl || "";
  const apiKey = ENV.calderaApiKey || "";
  
  if (!baseUrl || !apiKey) {
    return { success: false, error: "Caldera not configured" };
  }
  
  try {
    const payload = {
      adversary_id: operation.adversaryId,
      name: operation.name,
      description: operation.description,
      atomic_ordering: operation.abilities,
      objective: operation.objective,
      tags: [...operation.actorAttribution, operation.source, operation.riskLevel],
    };
    
    const response = await fetch(`${baseUrl}/api/v2/adversaries`, {
      method: "POST",
      headers: { KEY: apiKey, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15000),
    });
    
    if (response.ok) {
      const data = await response.json().catch(() => null);
      return { success: true, adversaryId: data?.adversary_id || operation.adversaryId };
    }
    return { success: false, error: `HTTP ${response.status}` };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/**
 * Full enrichment pipeline: generate from catalog → push to Caldera → update actor profiles.
 */
export async function runFullCatalogEnrichment(options?: {
  actorId?: string;
  pushToCaldera?: boolean;
}): Promise<EnrichmentResult & { calderaPush?: { pushed: number; failed: number } }> {
  const enrichment = await enrichCalderaFromCatalog({ actorId: options?.actorId });
  
  if (options?.pushToCaldera && enrichment.abilities.length > 0) {
    const pushResult = await pushCatalogAbilitiesToCaldera(enrichment.abilities);
    
    // Also push operations
    for (const op of enrichment.operations) {
      await pushCatalogOperationToCaldera(op);
    }
    
    return { ...enrichment, calderaPush: { pushed: pushResult.pushed, failed: pushResult.failed } };
  }
  
  return enrichment;
}
