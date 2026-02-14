/**
 * Caldera Adversary Sync Service
 * 
 * Fetches all adversaries from the Caldera server and syncs them
 * into the local threat_actors database. This ensures both systems
 * stay aligned for efficient campaign building.
 * 
 * Optimized for batch processing of 495+ adversaries with 1,940+ abilities.
 */

import * as db from "../db";
import type { InsertThreatActor } from "../../drizzle/schema";
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

function toActorId(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .substring(0, 128);
}

function classifyType(name: string, description: string): "apt" | "cybercrime" | "ransomware" | "hacktivist" | "unknown" {
  const text = `${name} ${description}`.toLowerCase();
  if (/apt\d|apt-|advanced persistent|nation.?state|cozy|fancy|lazarus|turla|sandworm|charming|muddy|ember|wizard|panda|bear|kitten|dragon|spider/i.test(text)) return "apt";
  if (/ransomware|lockbit|revil|conti|blackcat|alphv|clop|hive|darkside|babuk|royal|play|medusa|akira|rhysida/i.test(text)) return "ransomware";
  if (/hacktivist|anonymous|lulz|killnet|noname/i.test(text)) return "hacktivist";
  if (/fin\d|carbanak|cobalt.*group|magecart|evil.*corp/i.test(text)) return "cybercrime";
  return "unknown";
}

function classifySophistication(name: string, description: string, abilityCount: number): "nation-state" | "advanced" | "intermediate" | "basic" {
  const text = `${name} ${description}`.toLowerCase();
  if (/nation.?state|apt\d|apt-|cozy|fancy|lazarus|turla|sandworm|charming|muddy/i.test(text)) return "nation-state";
  if (abilityCount > 10 || /advanced|sophisticated/i.test(text)) return "advanced";
  if (abilityCount > 3) return "intermediate";
  return "basic";
}

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
 * Optimized with batch upserts and deduplication.
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
    console.log("[Caldera Sync] Fetching data from Caldera API...");
    const [adversaries, abilities] = await Promise.all([
      fetchCalderaAPI("/api/v2/adversaries") as Promise<CalderaAdversary[]>,
      fetchCalderaAPI("/api/v2/abilities") as Promise<CalderaAbility[]>,
    ]);

    if (!Array.isArray(adversaries)) {
      throw new Error("Invalid adversaries response from Caldera");
    }

    result.totalCalderaAdversaries = adversaries.length;
    console.log(`[Caldera Sync] Fetched ${adversaries.length} adversaries and ${Array.isArray(abilities) ? abilities.length : 0} abilities`);

    // Build ability lookup map
    const abilityMap = new Map<string, CalderaAbility>();
    if (Array.isArray(abilities)) {
      for (const ability of abilities) {
        abilityMap.set(ability.ability_id, ability);
      }
    }

    // Deduplicate adversaries by name (Caldera often has duplicates)
    const uniqueAdversaries = new Map<string, CalderaAdversary>();
    for (const adv of adversaries) {
      const actorId = toActorId(adv.name);
      const existing = uniqueAdversaries.get(actorId);
      // Keep the one with more abilities
      if (!existing || (adv.atomic_ordering?.length || 0) > (existing.atomic_ordering?.length || 0)) {
        uniqueAdversaries.set(actorId, adv);
      }
    }
    
    console.log(`[Caldera Sync] ${uniqueAdversaries.size} unique adversaries after dedup (from ${adversaries.length})`);

    // Process in batches of 25
    const BATCH_SIZE = 25;
    const entries = Array.from(uniqueAdversaries.entries());
    
    for (let i = 0; i < entries.length; i += BATCH_SIZE) {
      const batch = entries.slice(i, i + BATCH_SIZE);
      const batchNum = Math.floor(i / BATCH_SIZE) + 1;
      const totalBatches = Math.ceil(entries.length / BATCH_SIZE);
      
      if (batchNum % 5 === 1 || batchNum === totalBatches) {
        console.log(`[Caldera Sync] Processing batch ${batchNum}/${totalBatches}...`);
      }
      
      // Process batch concurrently with Promise.allSettled
      const batchPromises = batch.map(async ([actorId, adv]) => {
        try {
          const abilityIds = adv.atomic_ordering || [];
          const linkedAbilities = abilityIds
            .map(id => abilityMap.get(id))
            .filter((a): a is CalderaAbility => !!a);

          const techniques = linkedAbilities
            .filter(a => a.technique_id)
            .map(a => ({
              id: a.technique_id,
              name: a.technique_name || a.technique_id,
              tactic: a.tactic,
              score: 1,
              description: a.description,
            }));

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

          // Use upsertThreatActor for atomic create-or-update
          await db.upsertThreatActor(threatActor);
          
          return { actorId, created: true, abilities: linkedAbilities.length };
        } catch (advErr: any) {
          result.errors.push(`${adv.name}: ${advErr.message}`);
          result.skipped++;
          return { actorId, created: false, abilities: 0 };
        }
      });

      const batchResults = await Promise.allSettled(batchPromises);
      for (const br of batchResults) {
        if (br.status === "fulfilled" && br.value.created) {
          result.created++;
          result.abilitiesSynced += br.value.abilities;
        }
      }
    }

    console.log(`[Caldera Sync] Complete: ${result.created} synced, ${result.skipped} skipped, ${result.abilitiesSynced} abilities mapped`);
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
