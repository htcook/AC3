/**
 * Script to:
 * 1. Collect all techniques from the 20 enriched actors (using GET for queries)
 * 2. Generate detection rules for those techniques
 * 3. Create the Caldera adversary for the campaign
 */
import jwt from "jsonwebtoken";

const BASE_URL = "http://localhost:3000";
const JWT_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";
const token = jwt.sign({ username: "admin", role: "admin", loginTime: Date.now() }, JWT_SECRET, { expiresIn: "2h" });
const COOKIE = `caldera_session=${token}`;

async function trpcQuery(path, input = {}) {
  const url = `${BASE_URL}/api/trpc/${path}?input=${encodeURIComponent(JSON.stringify({ json: input }))}`;
  const resp = await fetch(url, { headers: { Cookie: COOKIE } });
  const data = await resp.json();
  return data.result?.data?.json || data.result?.data || data;
}

async function trpcMutation(path, input = {}, timeout = 120000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(`${BASE_URL}/api/trpc/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: COOKIE },
      body: JSON.stringify({ json: input }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (resp.status >= 400) {
      const t = await resp.text();
      throw new Error(`HTTP ${resp.status}: ${t.slice(0, 300)}`);
    }
    const data = await resp.json();
    return data.result?.data?.json || data.result?.data || data;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

const MATCHED_ACTORS = [
  "chimera", "redcurl", "apt29-g0016", "apt29-vcd-cloud-compromise-enhanced",
  "apt39-g0087", "apt5-g1023", "dragonfly-g0035", "ember-bear-g1003",
  "fox-kitten-g0117", "indrik-spider-g0119", "leviathan-g0065",
  "scattered-spider-g1015", "blue-mockingbird-g0108",
  "msp-target-complete-apt29-vcd-crowdstrike", "sandworm-team-g0034",
  "turla-g0010", "wizard-spider-g0102", "hafnium-g0125",
  "lazarus-group-g0032", "muddywater-g0069"
];

// ========== STEP 1: Collect techniques ==========
console.log("╔══════════════════════════════════════════════════════════╗");
console.log("║  Collect Techniques & Generate Detection Rules          ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

const allTechniqueIds = new Set();
const actorTechMap = {};

for (const actorId of MATCHED_ACTORS) {
  try {
    const actor = await trpcQuery("threatActorDb.get", { actorId });
    if (actor?.techniques && Array.isArray(actor.techniques)) {
      actorTechMap[actorId] = actor.techniques.length;
      actor.techniques.forEach(t => {
        if (t.id) allTechniqueIds.add(t.id);
      });
    }
  } catch (e) {
    // skip
  }
}

const techniqueIds = Array.from(allTechniqueIds);
console.log(`Collected ${techniqueIds.length} unique techniques from ${Object.keys(actorTechMap).length} actors:`);
Object.entries(actorTechMap).forEach(([id, count]) => console.log(`  ${id}: ${count} techniques`));

// ========== STEP 2: Generate detection rules in batches ==========
if (techniqueIds.length > 0) {
  console.log(`\nGenerating detection rules for ${techniqueIds.length} techniques...`);
  const BATCH = 10;
  let rulesGenerated = 0;
  for (let i = 0; i < techniqueIds.length; i += BATCH) {
    const batch = techniqueIds.slice(i, i + BATCH);
    const batchNum = Math.floor(i / BATCH) + 1;
    const totalBatches = Math.ceil(techniqueIds.length / BATCH);
    console.log(`  Batch ${batchNum}/${totalBatches}: ${batch.join(", ")}...`);
    try {
      const rules = await trpcQuery("ttpEngine.detectionRules", { techniqueIds: batch });
      rulesGenerated += batch.length;
      console.log(`    ✅ ${batch.length} rules generated`);
    } catch (e) {
      console.log(`    ⚠️ ${e.message.slice(0, 100)}`);
    }
    await new Promise(r => setTimeout(r, 500));
  }
  console.log(`\n✅ Detection rules generated for ${rulesGenerated}/${techniqueIds.length} techniques`);
}

// ========== STEP 3: Create Caldera adversary ==========
console.log("\n╔══════════════════════════════════════════════════════════╗");
console.log("║  Create Caldera Adversary for Campaign                  ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

try {
  const apt29 = await trpcQuery("threatActorDb.get", { actorId: "apt29-g0016" });
  const atomicOrdering = apt29?.calderaProfile?.atomicOrdering || [];
  console.log(`APT29 has ${atomicOrdering.length} abilities in Caldera`);
  
  const adversary = await trpcMutation("calderaProxy.createAdversary", {
    adversary_id: "aceofcloud-idp-compromise-2026",
    name: "AceofCloud IDP Compromise - APT29 Profile",
    description: "Custom adversary profile for AceofCloud Identity Provider Compromise purple team exercise. Based on APT29 TTPs targeting SSO/OWA infrastructure.",
    atomic_ordering: atomicOrdering.slice(0, 30),
    objective: "Compromise identity providers (Okta SSO, OWA) to gain persistent access",
  }, 30000);
  
  if (adversary?.success) {
    console.log(`✅ Caldera adversary created: aceofcloud-idp-compromise-2026`);
  } else {
    console.log(`⚠️ ${adversary?.error || JSON.stringify(adversary).slice(0, 200)}`);
  }
} catch (e) {
  console.log(`⚠️ ${e.message.slice(0, 150)}`);
}

console.log("\n" + "=".repeat(60));
console.log("DONE");
console.log("=".repeat(60));
