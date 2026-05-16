import {
  generateAdversaryProfile,
  init_c2_tactical_knowledge,
  scoreProfileCompleteness
} from "./chunk-RHR46T4U.js";
import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  init_schema,
  threatActors
} from "./chunk-L4JENJ4Z.js";

// server/lib/caldera-profile-push.ts
init_env();
init_db();
init_schema();
init_c2_tactical_knowledge();
import { eq, sql } from "drizzle-orm";
var CALDERA_BASE_URL = () => ENV.calderaBaseUrl || "";
var CALDERA_API_KEY = () => ENV.calderaApiKey || "";
async function calderaFetch(endpoint, method = "GET", body, retries = 2) {
  const baseUrl = CALDERA_BASE_URL();
  const apiKey = CALDERA_API_KEY();
  if (!baseUrl || !apiKey) {
    return { ok: false, status: 0, data: null };
  }
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(`${baseUrl}${endpoint}`, {
        method,
        headers: {
          KEY: apiKey,
          "Content-Type": "application/json"
        },
        body: body ? JSON.stringify(body) : void 0,
        signal: AbortSignal.timeout(3e4)
      });
      const data = response.ok ? await response.json().catch(() => null) : null;
      return { ok: response.ok, status: response.status, data };
    } catch (err) {
      if (attempt === retries) {
        return { ok: false, status: 0, data: null };
      }
      await new Promise((r) => setTimeout(r, 2e3));
    }
  }
  return { ok: false, status: 0, data: null };
}
async function pushProfileToCaldera(actorId) {
  const db = await getDb();
  if (!db) return { success: false, error: "Database not available" };
  const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (!actor) return { success: false, error: "Actor not found" };
  let profile = null;
  try {
    profile = typeof actor.calderaProfile === "string" ? JSON.parse(actor.calderaProfile) : actor.calderaProfile;
  } catch {
    profile = null;
  }
  if (!profile || !profile.atomicOrdering || profile.atomicOrdering.length === 0) {
    const generated = await generateAdversaryProfile(actorId);
    if (!generated) {
      return {
        success: false,
        error: "No profile available and auto-generation failed. Actor needs more abilities."
      };
    }
    profile = {
      id: generated.adversaryId,
      adversaryId: generated.adversaryId,
      name: generated.name,
      atomicOrdering: generated.atomicOrdering,
      abilityCount: generated.abilityCount,
      killChainPhases: generated.killChainPhases,
      deploymentStatus: "local_only"
    };
  }
  const payload = {
    name: profile.name || `${actor.name} Emulation Profile`,
    description: `Auto-generated adversary emulation profile for ${actor.name}. Covers ${profile.killChainPhases?.length || 0} kill chain phases with ${profile.atomicOrdering.length} abilities. Deployed from AC3 threat intelligence platform.`,
    atomic_ordering: profile.atomicOrdering,
    objective: profile.objectives || void 0,
    tags: [
      `actor:${actorId}`,
      `auto-generated`,
      `ac3`,
      ...actor.actorType ? [`type:${actor.actorType}`] : []
    ]
  };
  const updatedProfile = {
    ...profile,
    deploymentStatus: "pending"
  };
  await db.update(threatActors).set({ calderaProfile: JSON.stringify(updatedProfile) }).where(eq(threatActors.actorId, actorId));
  const existingCheck = await calderaFetch(`/api/v2/adversaries/${profile.adversaryId || profile.id}`);
  let result;
  if (existingCheck.ok && existingCheck.data) {
    result = await calderaFetch(
      `/api/v2/adversaries/${profile.adversaryId || profile.id}`,
      "PATCH",
      payload
    );
  } else {
    result = await calderaFetch("/api/v2/adversaries", "POST", payload);
  }
  const deployedAt = (/* @__PURE__ */ new Date()).toISOString();
  if (result.ok) {
    const calderaServerId = result.data?.adversary_id || result.data?.id || profile.adversaryId || profile.id;
    const deployedProfile = {
      ...profile,
      deploymentStatus: "deployed",
      calderaServerId,
      deployedAt,
      lastError: void 0
    };
    await db.update(threatActors).set({ calderaProfile: JSON.stringify(deployedProfile) }).where(eq(threatActors.actorId, actorId));
    console.log(
      `[Caldera Push] Successfully deployed profile for ${actor.name} (${calderaServerId})`
    );
    return {
      success: true,
      adversaryId: calderaServerId,
      calderaResponse: result.data,
      deployedAt
    };
  } else {
    const errorMsg = `Caldera API returned ${result.status}`;
    const failedProfile = {
      ...profile,
      deploymentStatus: "failed",
      lastError: errorMsg
    };
    await db.update(threatActors).set({ calderaProfile: JSON.stringify(failedProfile) }).where(eq(threatActors.actorId, actorId));
    console.error(`[Caldera Push] Failed to deploy profile for ${actor.name}: ${errorMsg}`);
    return { success: false, error: errorMsg };
  }
}
async function batchPushProfilesToCaldera(options) {
  const db = await getDb();
  if (!db) return { pushed: 0, skipped: 0, failed: 0, results: [] };
  const minScore = options?.minScore ?? 60;
  const maxBatch = options?.maxBatch ?? 50;
  const dryRun = options?.dryRun ?? false;
  const actors = await db.select().from(threatActors).where(
    sql`${threatActors.calderaProfile} IS NOT NULL AND ${threatActors.calderaProfile} != 'null'`
  ).limit(maxBatch);
  const results = [];
  let pushed = 0, skipped = 0, failed = 0;
  for (const actor of actors) {
    let profile = null;
    try {
      profile = typeof actor.calderaProfile === "string" ? JSON.parse(actor.calderaProfile) : actor.calderaProfile;
    } catch {
      continue;
    }
    if (!profile) continue;
    if (profile.deploymentStatus === "deployed") {
      skipped++;
      results.push({
        actorId: actor.actorId,
        actorName: actor.name,
        action: "skipped",
        reason: "Already deployed"
      });
      continue;
    }
    const score = await scoreProfileCompleteness(actor.actorId);
    if (score && score.score < minScore) {
      skipped++;
      results.push({
        actorId: actor.actorId,
        actorName: actor.name,
        action: "skipped",
        reason: `Score ${score.score} below threshold ${minScore}`
      });
      continue;
    }
    if (dryRun) {
      pushed++;
      results.push({
        actorId: actor.actorId,
        actorName: actor.name,
        action: "pushed",
        reason: "Would push (dry run)"
      });
      continue;
    }
    const result = await pushProfileToCaldera(actor.actorId);
    if (result.success) {
      pushed++;
      results.push({
        actorId: actor.actorId,
        actorName: actor.name,
        action: "pushed"
      });
    } else {
      failed++;
      results.push({
        actorId: actor.actorId,
        actorName: actor.name,
        action: "failed",
        reason: result.error
      });
    }
  }
  return { pushed, skipped, failed, results };
}
async function getDeploymentStatus() {
  const db = await getDb();
  if (!db) return [];
  const actors = await db.select({
    actorId: threatActors.actorId,
    name: threatActors.name,
    calderaProfile: threatActors.calderaProfile
  }).from(threatActors).where(
    sql`${threatActors.calderaProfile} IS NOT NULL AND ${threatActors.calderaProfile} != 'null'`
  );
  return actors.map((actor) => {
    let profile = null;
    try {
      profile = typeof actor.calderaProfile === "string" ? JSON.parse(actor.calderaProfile) : actor.calderaProfile;
    } catch {
      return null;
    }
    if (!profile) return null;
    return {
      actorId: actor.actorId,
      actorName: actor.name,
      status: profile.deploymentStatus || "local_only",
      abilityCount: profile.abilityCount || profile.atomicOrdering?.length || 0,
      deployedAt: profile.deployedAt,
      lastError: profile.lastError
    };
  }).filter(Boolean);
}
async function verifyDeployedProfile(actorId) {
  const db = await getDb();
  if (!db) return { exists: false, error: "Database not available" };
  const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (!actor) return { exists: false, error: "Actor not found" };
  let profile = null;
  try {
    profile = typeof actor.calderaProfile === "string" ? JSON.parse(actor.calderaProfile) : actor.calderaProfile;
  } catch {
    return { exists: false, error: "Invalid profile data" };
  }
  if (!profile?.calderaServerId) {
    return { exists: false, error: "No Caldera server ID \u2014 profile not deployed" };
  }
  const result = await calderaFetch(`/api/v2/adversaries/${profile.calderaServerId}`);
  return {
    exists: result.ok,
    calderaData: result.data,
    error: result.ok ? void 0 : `Caldera returned ${result.status}`
  };
}

export {
  pushProfileToCaldera,
  batchPushProfilesToCaldera,
  getDeploymentStatus,
  verifyDeployedProfile
};
