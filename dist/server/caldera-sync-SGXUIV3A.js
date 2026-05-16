import {
  init_db,
  upsertThreatActor
} from "./chunk-RSFTEATL.js";
import {
  ENV,
  init_env
} from "./chunk-KDOLKO2A.js";
import "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/caldera-sync.ts
init_db();
init_env();
import cron from "node-cron";
var CALDERA_BASE_URL = ENV.calderaBaseUrl || "";
var CALDERA_API_KEY = ENV.calderaApiKey || "";
async function fetchCalderaAPI(endpoint, retries = 2) {
  if (!CALDERA_BASE_URL || !CALDERA_API_KEY) {
    throw new Error("Cyber C2 credentials not configured");
  }
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(`${CALDERA_BASE_URL}${endpoint}`, {
        headers: {
          "KEY": CALDERA_API_KEY,
          "Content-Type": "application/json"
        },
        signal: AbortSignal.timeout(3e4)
      });
      if (!response.ok) {
        throw new Error(`Caldera API error: ${response.status} ${response.statusText}`);
      }
      return response.json();
    } catch (err) {
      if (attempt === retries) throw err;
      console.warn(`[Cyber C2 Sync] Fetch attempt ${attempt + 1} failed for ${endpoint}, retrying in 3s...`);
      await new Promise((r) => setTimeout(r, 3e3));
    }
  }
}
function toActorId(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").substring(0, 128);
}
function classifyType(name, description) {
  const text = `${name} ${description}`.toLowerCase();
  if (/apt\d|apt-|advanced persistent|nation.?state|cozy|fancy|lazarus|turla|sandworm|charming|muddy|ember|wizard|panda|bear|kitten|dragon|spider/i.test(text)) return "apt";
  if (/ransomware|lockbit|revil|conti|blackcat|alphv|clop|hive|darkside|babuk|royal|play|medusa|akira|rhysida/i.test(text)) return "ransomware";
  if (/hacktivist|anonymous|lulz|killnet|noname/i.test(text)) return "hacktivist";
  if (/fin\d|carbanak|cobalt.*group|magecart|evil.*corp/i.test(text)) return "cybercrime";
  return "unknown";
}
function classifySophistication(name, description, abilityCount) {
  const text = `${name} ${description}`.toLowerCase();
  if (/nation.?state|apt\d|apt-|cozy|fancy|lazarus|turla|sandworm|charming|muddy/i.test(text)) return "nation-state";
  if (abilityCount > 10 || /advanced|sophisticated/i.test(text)) return "advanced";
  if (abilityCount > 3) return "intermediate";
  return "basic";
}
function classifyThreatLevel(type, abilityCount) {
  if (type === "apt" && abilityCount > 5) return "critical";
  if (type === "apt" || type === "ransomware") return "high";
  if (abilityCount > 3) return "medium";
  return "low";
}
async function syncCalderaAdversaries() {
  console.log("[Cyber C2 Sync] Starting adversary sync...");
  const result = {
    totalCalderaAdversaries: 0,
    created: 0,
    updated: 0,
    skipped: 0,
    abilitiesSynced: 0,
    errors: []
  };
  try {
    console.log("[Cyber C2 Sync] Fetching data from Cyber C2 API...");
    const [adversaries, abilities] = await Promise.all([
      fetchCalderaAPI("/api/v2/adversaries"),
      fetchCalderaAPI("/api/v2/abilities")
    ]);
    if (!Array.isArray(adversaries)) {
      throw new Error("Invalid adversaries response from Cyber C2");
    }
    result.totalCalderaAdversaries = adversaries.length;
    console.log(`[Cyber C2 Sync] Fetched ${adversaries.length} adversaries and ${Array.isArray(abilities) ? abilities.length : 0} abilities`);
    const abilityMap = /* @__PURE__ */ new Map();
    if (Array.isArray(abilities)) {
      for (const ability of abilities) {
        abilityMap.set(ability.ability_id, ability);
      }
    }
    const uniqueAdversaries = /* @__PURE__ */ new Map();
    for (const adv of adversaries) {
      const actorId = toActorId(adv.name);
      const existing = uniqueAdversaries.get(actorId);
      if (!existing || (adv.atomic_ordering?.length || 0) > (existing.atomic_ordering?.length || 0)) {
        uniqueAdversaries.set(actorId, adv);
      }
    }
    console.log(`[Cyber C2 Sync] ${uniqueAdversaries.size} unique adversaries after dedup (from ${adversaries.length})`);
    const BATCH_SIZE = 25;
    const entries = Array.from(uniqueAdversaries.entries());
    for (let i = 0; i < entries.length; i += BATCH_SIZE) {
      const batch = entries.slice(i, i + BATCH_SIZE);
      const batchNum = Math.floor(i / BATCH_SIZE) + 1;
      const totalBatches = Math.ceil(entries.length / BATCH_SIZE);
      if (batchNum % 5 === 1 || batchNum === totalBatches) {
        console.log(`[Cyber C2 Sync] Processing batch ${batchNum}/${totalBatches}...`);
      }
      const batchPromises = batch.map(async ([actorId, adv]) => {
        try {
          const abilityIds = adv.atomic_ordering || [];
          const linkedAbilities = abilityIds.map((id) => abilityMap.get(id)).filter((a) => !!a);
          const techniques = linkedAbilities.filter((a) => a.technique_id).map((a) => ({
            id: a.technique_id,
            name: a.technique_name || a.technique_id,
            tactic: a.tactic,
            score: 1,
            description: a.description
          }));
          const uniqueTechniques = Array.from(
            new Map(techniques.map((t) => [t.id, t])).values()
          );
          const type = classifyType(adv.name, adv.description || "");
          const sophistication = classifySophistication(adv.name, adv.description || "", linkedAbilities.length);
          const threatLevel = classifyThreatLevel(type, linkedAbilities.length);
          const threatActor = {
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
            tools: linkedAbilities.map((a) => a.name).slice(0, 20),
            malware: [],
            calderaProfile: {
              id: adv.adversary_id,
              atomicOrdering: adv.atomic_ordering || [],
              objectives: adv.objective || null,
              plugin: adv.plugin || null,
              hasRepeatableAbilities: adv.has_repeatable_abilities || false
            },
            dataSource: "caldera",
            confidence: 80
          };
          await upsertThreatActor(threatActor);
          return { actorId, created: true, abilities: linkedAbilities.length };
        } catch (advErr) {
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
    console.log(`[Cyber C2 Sync] Complete: ${result.created} synced, ${result.skipped} skipped, ${result.abilitiesSynced} abilities mapped`);
    if (result.errors.length > 0) {
      console.warn(`[Cyber C2 Sync] ${result.errors.length} errors:`, result.errors.slice(0, 5));
    }
    return result;
  } catch (err) {
    console.error("[Cyber C2 Sync] Fatal error:", err.message);
    result.errors.push(`Fatal: ${err.message}`);
    return result;
  }
}
function initCalderaSyncSchedule() {
  console.log("[Cyber C2 Sync] Scheduling daily sync at 07:00 UTC");
  const task = cron.schedule("0 7 * * *", async () => {
    console.log(`[Cyber C2 Sync] Scheduled sync starting at ${(/* @__PURE__ */ new Date()).toISOString()}`);
    try {
      const result = await syncCalderaAdversaries();
      console.log(`[Cyber C2 Sync] Scheduled sync complete: ${result.created} synced, ${result.skipped} skipped, ${result.abilitiesSynced} abilities`);
      if (result.created > 0) {
        try {
          const { onCalderaSyncComplete } = await import("./threat-intel-auto-enrich-4SUISHZQ.js");
          onCalderaSyncComplete(result).catch((err) => {
            console.warn(`[Cyber C2 Sync] Auto-enrich after sync failed:`, err.message);
          });
        } catch (e) {
        }
      }
    } catch (err) {
      console.error("[Cyber C2 Sync] Scheduled sync failed:", err.message);
    }
  }, {
    timezone: "UTC"
  });
  task.start();
  console.log("[Cyber C2 Sync] Daily sync cron job active");
}
export {
  initCalderaSyncSchedule,
  syncCalderaAdversaries
};
