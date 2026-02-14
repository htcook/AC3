/**
 * Caldera Adversary Sync Service
 * 
 * Fetches all adversaries from the Caldera server and syncs them
 * into the local threat_actors database. This ensures both systems
 * stay aligned for efficient campaign building.
 * 
 * For each Caldera adversary:
 * 1. Map to a threat actor record with calderaProfile data
 * 2. Extract linked abilities and map to MITRE techniques
 * 3. Upsert into the threat_actors table (merge if exists)
 * 4. Sync abilities to threat_actor_abilities table
 */

import * as db from "../db";
import type { InsertThreatActor, InsertThreatActorAbility } from "../../drizzle/schema";
import { ENV } from "../_core/env";

const CALDERA_BASE_URL = ENV.calderaBaseUrl || "";
const CALDERA_API_KEY = ENV.calderaApiKey || "";

interface CalderaAdversary {
  adversary_id: string;
  name: string;
  description: string;
  atomic_ordering: string[];
  objective?: string;
  tags?: string[];
  has_repeatable_abilities?: boolean;
  plugin?: string;
}

interface CalderaAbility {
  ability_id: string;
  name: string;
  description: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
  platforms: Record<string, any>;
  singleton?: boolean;
  repeatable?: boolean;
  requirements?: any[];
  executors?: any[];
}

async function fetchCalderaAPI(endpoint: string): Promise<any> {
  if (!CALDERA_BASE_URL || !CALDERA_API_KEY) {
    throw new Error("Caldera credentials not configured");
  }
  const response = await fetch(`${CALDERA_BASE_URL}${endpoint}`, {
    headers: {
      "KEY": CALDERA_API_KEY,
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`Caldera API error: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

/** Normalize a Caldera adversary name to an actorId slug */
function toActorId(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .substring(0, 128);
}

/** Classify adversary type based on name/description heuristics */
function classifyType(name: string, description: string): "apt" | "cybercrime" | "ransomware" | "hacktivist" | "unknown" {
  const text = `${name} ${description}`.toLowerCase();
  if (/apt\d|apt-|advanced persistent|nation.?state|cozy|fancy|lazarus|turla|sandworm|charming|muddy|ember|wizard|panda|bear|kitten|dragon|spider/i.test(text)) return "apt";
  if (/ransomware|lockbit|revil|conti|blackcat|alphv|clop|hive|darkside|babuk|royal|play|medusa|akira|rhysida/i.test(text)) return "ransomware";
  if (/hacktivist|anonymous|lulz|killnet|noname/i.test(text)) return "hacktivist";
  if (/fin\d|carbanak|cobalt.*group|magecart|evil.*corp/i.test(text)) return "cybercrime";
  return "unknown";
}

/** Classify sophistication level */
function classifySophistication(name: string, description: string, abilityCount: number): "nation-state" | "advanced" | "intermediate" | "basic" {
  const text = `${name} ${description}`.toLowerCase();
  if (/nation.?state|apt\d|apt-|cozy|fancy|lazarus|turla|sandworm|charming|muddy/i.test(text)) return "nation-state";
  if (abilityCount > 10 || /advanced|sophisticated/i.test(text)) return "advanced";
  if (abilityCount > 3) return "intermediate";
  return "basic";
}

/** Classify threat level */
function classifyThreatLevel(type: string, abilityCount: number): "critical" | "high" | "medium" | "low" {
  if (type === "apt" && abilityCount > 5) return "critical";
  if (type === "apt" || type === "ransomware") return "high";
  if (abilityCount > 3) return "medium";
  return "low";
}

export interface SyncResult {
  totalCalderaAdversaries: number;
  created: number;
  updated: number;
  skipped: number;
  abilitiesSynced: number;
  errors: string[];
}

/**
 * Sync all Caldera adversaries into the threat actor database.
 * This is the main entry point for the sync operation.
 */
export async function syncCalderaAdversaries(): Promise<SyncResult> {
  console.log("[Caldera Sync] Starting adversary sync...");
  
  const result: SyncResult = {
    totalCalderaAdversaries: 0,
    created: 0,
    updated: 0,
    skipped: 0,
    abilitiesSynced: 0,
    errors: [],
  };

  try {
    // Fetch all adversaries and abilities from Caldera
    const [adversaries, abilities] = await Promise.all([
      fetchCalderaAPI("/api/v2/adversaries") as Promise<CalderaAdversary[]>,
      fetchCalderaAPI("/api/v2/abilities") as Promise<CalderaAbility[]>,
    ]);

    if (!Array.isArray(adversaries)) {
      throw new Error("Invalid adversaries response from Caldera");
    }

    result.totalCalderaAdversaries = adversaries.length;
    console.log(`[Caldera Sync] Found ${adversaries.length} adversaries and ${Array.isArray(abilities) ? abilities.length : 0} abilities`);

    // Build ability lookup map
    const abilityMap = new Map<string, CalderaAbility>();
    if (Array.isArray(abilities)) {
      for (const ability of abilities) {
        abilityMap.set(ability.ability_id, ability);
      }
    }

    // Process each adversary
    for (const adv of adversaries) {
      try {
        const actorId = toActorId(adv.name);
        const abilityIds = adv.atomic_ordering || [];
        const linkedAbilities = abilityIds
          .map(id => abilityMap.get(id))
          .filter((a): a is CalderaAbility => !!a);

        // Extract MITRE techniques from linked abilities
        const techniques = linkedAbilities
          .filter(a => a.technique_id)
          .map(a => ({
            id: a.technique_id,
            name: a.technique_name || a.technique_id,
            tactic: a.tactic,
            score: 1,
            description: a.description,
          }));

        // Deduplicate techniques by ID
        const uniqueTechniques = Array.from(
          new Map(techniques.map(t => [t.id, t])).values()
        );

        const type = classifyType(adv.name, adv.description || "");
        const sophistication = classifySophistication(adv.name, adv.description || "", linkedAbilities.length);
        const threatLevel = classifyThreatLevel(type, linkedAbilities.length);

        const threatActor: InsertThreatActor = {
          actorId,
          name: adv.name,
          aliases: adv.tags || [],
          type,
          origin: null,
          description: adv.description || `Caldera adversary profile: ${adv.name}`,
          motivation: type === "apt" ? "espionage" : type === "ransomware" ? "financial" : type === "cybercrime" ? "financial" : "unknown",
          threatLevel,
          sophistication,
          targetSectors: [],
          targetRegions: [],
          techniques: uniqueTechniques,
          tools: linkedAbilities.map(a => a.name).slice(0, 20),
          malware: [],
          calderaProfile: {
            id: adv.adversary_id,
            atomicOrdering: adv.atomic_ordering || [],
            objectives: adv.objective || null,
            plugin: adv.plugin || null,
            hasRepeatableAbilities: adv.has_repeatable_abilities || false,
          },
          dataSource: "caldera",
          confidence: 80,
        };

        // Upsert the threat actor
        const existingActor = await db.getThreatActor(actorId);
        if (existingActor) {
          // Update caldera profile and merge techniques
          const existingTechniques = (existingActor.techniques as any[]) || [];
          const mergedTechMap = new Map<string, any>();
          for (const t of existingTechniques) mergedTechMap.set(t.id, t);
          for (const t of uniqueTechniques) mergedTechMap.set(t.id, t);
          
          await db.updateThreatActor(actorId, {
            calderaProfile: threatActor.calderaProfile,
            techniques: Array.from(mergedTechMap.values()),
            tools: Array.from(new Set([
              ...((existingActor.tools as string[]) || []),
              ...((threatActor.tools as string[]) || []),
            ])).slice(0, 50),
          });
          result.updated++;
        } else {
          await db.createThreatActor(threatActor);
          result.created++;
        }

        // Sync abilities to threat_actor_abilities table
        const existingAbilities = await db.listThreatActorAbilities(actorId);
        const existingAbilityIds = new Set(existingAbilities.map((a: any) => a.abilityId));

        for (const ability of linkedAbilities) {
          if (!existingAbilityIds.has(ability.ability_id)) {
            try {
              await db.createThreatActorAbility({
                actorId,
                abilityId: ability.ability_id,
                name: ability.name,
                description: ability.description,
                tactic: ability.tactic,
                techniqueId: ability.technique_id,
                techniqueName: ability.technique_name,
                platforms: ability.platforms || {},
                singleton: ability.singleton || false,
                repeatable: ability.repeatable !== false,
                requirements: ability.requirements || [],
              });
              result.abilitiesSynced++;
            } catch (abilityErr: any) {
              // Skip duplicate abilities silently
              if (!abilityErr.message?.includes("Duplicate")) {
                result.errors.push(`Ability ${ability.ability_id} for ${actorId}: ${abilityErr.message}`);
              }
            }
          }
        }
      } catch (advErr: any) {
        result.errors.push(`Adversary ${adv.name}: ${advErr.message}`);
        result.skipped++;
      }
    }

    console.log(`[Caldera Sync] Complete: ${result.created} created, ${result.updated} updated, ${result.skipped} skipped, ${result.abilitiesSynced} abilities synced`);
    if (result.errors.length > 0) {
      console.warn(`[Caldera Sync] ${result.errors.length} errors:`, result.errors.slice(0, 5));
    }

    return result;
  } catch (err: any) {
    console.error("[Caldera Sync] Fatal error:", err.message);
    result.errors.push(`Fatal: ${err.message}`);
    return result;
  }
}
