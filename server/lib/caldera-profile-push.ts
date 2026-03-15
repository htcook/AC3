/**
 * Caldera Adversary Profile Push Service
 *
 * Pushes auto-generated adversary profiles to the live Caldera C2 server
 * via the REST API (POST /api/v2/adversaries). Tracks deployment status
 * in the threat_actors table (calderaProfile JSON column).
 *
 * Flow:
 *   1. generateAdversaryProfile() creates the profile locally
 *   2. pushProfileToCaldera() sends it to the Caldera server
 *   3. Status is tracked: pending → deployed | failed
 *   4. Profiles can be synced back via pullProfileFromCaldera()
 */

import { ENV } from "../_core/env";
import { getDb } from "../db";
import { threatActors } from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";
import { generateAdversaryProfile, scoreProfileCompleteness } from "./c2-tactical-knowledge";

// ─── Types ───────────────────────────────────────────────────────────────

export interface CalderaAdversaryPayload {
  name: string;
  description: string;
  atomic_ordering: string[];
  objective?: string;
  tags?: string[];
}

export interface CalderaDeploymentResult {
  success: boolean;
  adversaryId?: string;
  calderaResponse?: any;
  error?: string;
  deployedAt?: string;
}

export interface CalderaProfileStatus {
  id: string;
  adversaryId: string;
  name: string;
  atomicOrdering: string[];
  abilityCount: number;
  killChainPhases: string[];
  deploymentStatus: "local_only" | "pending" | "deployed" | "failed" | "updated";
  calderaServerId?: string;
  deployedAt?: string;
  lastError?: string;
  objectives?: string | null;
  plugin?: string | null;
  hasRepeatableAbilities?: boolean;
}

// ─── Caldera API Client ──────────────────────────────────────────────────

const CALDERA_BASE_URL = () => ENV.calderaBaseUrl || "";
const CALDERA_API_KEY = () => ENV.calderaApiKey || "";

async function calderaFetch(
  endpoint: string,
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" = "GET",
  body?: any,
  retries = 2,
): Promise<{ ok: boolean; status: number; data: any }> {
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
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(30000),
      });

      const data = response.ok ? await response.json().catch(() => null) : null;
      return { ok: response.ok, status: response.status, data };
    } catch (err: any) {
      if (attempt === retries) {
        return { ok: false, status: 0, data: null };
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  return { ok: false, status: 0, data: null };
}

// ─── Push Profile to Caldera ─────────────────────────────────────────────

/**
 * Push a generated adversary profile to the live Caldera C2 server.
 * Creates a new adversary via POST /api/v2/adversaries.
 */
export async function pushProfileToCaldera(
  actorId: string,
): Promise<CalderaDeploymentResult> {
  const db = await getDb();
  if (!db) return { success: false, error: "Database not available" };

  // Get the actor and their current profile
  const [actor] = await db
    .select()
    .from(threatActors)
    .where(eq(threatActors.actorId, actorId))
    .limit(1);

  if (!actor) return { success: false, error: "Actor not found" };

  let profile: CalderaProfileStatus | null = null;
  try {
    profile =
      typeof actor.calderaProfile === "string"
        ? JSON.parse(actor.calderaProfile)
        : (actor.calderaProfile as CalderaProfileStatus | null);
  } catch {
    profile = null;
  }

  if (!profile || !profile.atomicOrdering || profile.atomicOrdering.length === 0) {
    // Try to generate the profile first
    const generated = await generateAdversaryProfile(actorId);
    if (!generated) {
      return {
        success: false,
        error: "No profile available and auto-generation failed. Actor needs more abilities.",
      };
    }
    profile = {
      id: generated.adversaryId,
      adversaryId: generated.adversaryId,
      name: generated.name,
      atomicOrdering: generated.atomicOrdering,
      abilityCount: generated.abilityCount,
      killChainPhases: generated.killChainPhases,
      deploymentStatus: "local_only",
    };
  }

  // Build the Caldera API payload
  const payload: CalderaAdversaryPayload = {
    name: profile.name || `${actor.name} Emulation Profile`,
    description: `Auto-generated adversary emulation profile for ${actor.name}. Covers ${profile.killChainPhases?.length || 0} kill chain phases with ${profile.atomicOrdering.length} abilities. Deployed from AC3 threat intelligence platform.`,
    atomic_ordering: profile.atomicOrdering,
    objective: profile.objectives || undefined,
    tags: [
      `actor:${actorId}`,
      `auto-generated`,
      `ace-c3`,
      ...(actor.actorType ? [`type:${actor.actorType}`] : []),
    ],
  };

  // Update status to pending
  const updatedProfile: CalderaProfileStatus = {
    ...profile,
    deploymentStatus: "pending",
  };
  await db
    .update(threatActors)
    .set({ calderaProfile: JSON.stringify(updatedProfile) })
    .where(eq(threatActors.actorId, actorId));

  // Check if this adversary already exists on the server
  const existingCheck = await calderaFetch(`/api/v2/adversaries/${profile.adversaryId || profile.id}`);

  let result: { ok: boolean; status: number; data: any };

  if (existingCheck.ok && existingCheck.data) {
    // Update existing adversary
    result = await calderaFetch(
      `/api/v2/adversaries/${profile.adversaryId || profile.id}`,
      "PATCH",
      payload,
    );
  } else {
    // Create new adversary
    result = await calderaFetch("/api/v2/adversaries", "POST", payload);
  }

  const deployedAt = new Date().toISOString();

  if (result.ok) {
    const calderaServerId =
      result.data?.adversary_id || result.data?.id || profile.adversaryId || profile.id;

    const deployedProfile: CalderaProfileStatus = {
      ...profile,
      deploymentStatus: "deployed",
      calderaServerId,
      deployedAt,
      lastError: undefined,
    };

    await db
      .update(threatActors)
      .set({ calderaProfile: JSON.stringify(deployedProfile) })
      .where(eq(threatActors.actorId, actorId));

    console.log(
      `[Caldera Push] Successfully deployed profile for ${actor.name} (${calderaServerId})`,
    );

    return {
      success: true,
      adversaryId: calderaServerId,
      calderaResponse: result.data,
      deployedAt,
    };
  } else {
    const errorMsg = `Caldera API returned ${result.status}`;
    const failedProfile: CalderaProfileStatus = {
      ...profile,
      deploymentStatus: "failed",
      lastError: errorMsg,
    };

    await db
      .update(threatActors)
      .set({ calderaProfile: JSON.stringify(failedProfile) })
      .where(eq(threatActors.actorId, actorId));

    console.error(`[Caldera Push] Failed to deploy profile for ${actor.name}: ${errorMsg}`);

    return { success: false, error: errorMsg };
  }
}

/**
 * Batch push all eligible profiles to Caldera.
 * Only pushes profiles that are "local_only" or "failed" status.
 */
export async function batchPushProfilesToCaldera(options?: {
  minScore?: number;
  maxBatch?: number;
  dryRun?: boolean;
}): Promise<{
  pushed: number;
  skipped: number;
  failed: number;
  results: Array<{
    actorId: string;
    actorName: string;
    action: "pushed" | "skipped" | "failed";
    reason?: string;
  }>;
}> {
  const db = await getDb();
  if (!db) return { pushed: 0, skipped: 0, failed: 0, results: [] };

  const minScore = options?.minScore ?? 60;
  const maxBatch = options?.maxBatch ?? 50;
  const dryRun = options?.dryRun ?? false;

  // Get actors with profiles that haven't been deployed
  const actors = await db
    .select()
    .from(threatActors)
    .where(
      sql`${threatActors.calderaProfile} IS NOT NULL AND ${threatActors.calderaProfile} != 'null'`,
    )
    .limit(maxBatch);

  const results: Array<{
    actorId: string;
    actorName: string;
    action: "pushed" | "skipped" | "failed";
    reason?: string;
  }> = [];
  let pushed = 0,
    skipped = 0,
    failed = 0;

  for (const actor of actors) {
    let profile: CalderaProfileStatus | null = null;
    try {
      profile =
        typeof actor.calderaProfile === "string"
          ? JSON.parse(actor.calderaProfile as string)
          : (actor.calderaProfile as CalderaProfileStatus | null);
    } catch {
      continue;
    }

    if (!profile) continue;

    // Skip already deployed profiles
    if (profile.deploymentStatus === "deployed") {
      skipped++;
      results.push({
        actorId: actor.actorId!,
        actorName: actor.name,
        action: "skipped",
        reason: "Already deployed",
      });
      continue;
    }

    // Check completeness score
    const score = await scoreProfileCompleteness(actor.actorId!);
    if (score && score.score < minScore) {
      skipped++;
      results.push({
        actorId: actor.actorId!,
        actorName: actor.name,
        action: "skipped",
        reason: `Score ${score.score} below threshold ${minScore}`,
      });
      continue;
    }

    if (dryRun) {
      pushed++;
      results.push({
        actorId: actor.actorId!,
        actorName: actor.name,
        action: "pushed",
        reason: "Would push (dry run)",
      });
      continue;
    }

    const result = await pushProfileToCaldera(actor.actorId!);
    if (result.success) {
      pushed++;
      results.push({
        actorId: actor.actorId!,
        actorName: actor.name,
        action: "pushed",
      });
    } else {
      failed++;
      results.push({
        actorId: actor.actorId!,
        actorName: actor.name,
        action: "failed",
        reason: result.error,
      });
    }
  }

  return { pushed, skipped, failed, results };
}

/**
 * Get deployment status for all actors with profiles.
 */
export async function getDeploymentStatus(): Promise<
  Array<{
    actorId: string;
    actorName: string;
    status: CalderaProfileStatus["deploymentStatus"];
    abilityCount: number;
    deployedAt?: string;
    lastError?: string;
  }>
> {
  const db = await getDb();
  if (!db) return [];

  const actors = await db
    .select({
      actorId: threatActors.actorId,
      name: threatActors.name,
      calderaProfile: threatActors.calderaProfile,
    })
    .from(threatActors)
    .where(
      sql`${threatActors.calderaProfile} IS NOT NULL AND ${threatActors.calderaProfile} != 'null'`,
    );

  return actors
    .map((actor) => {
      let profile: CalderaProfileStatus | null = null;
      try {
        profile =
          typeof actor.calderaProfile === "string"
            ? JSON.parse(actor.calderaProfile as string)
            : (actor.calderaProfile as CalderaProfileStatus | null);
      } catch {
        return null;
      }
      if (!profile) return null;

      return {
        actorId: actor.actorId!,
        actorName: actor.name,
        status: profile.deploymentStatus || "local_only",
        abilityCount: profile.abilityCount || profile.atomicOrdering?.length || 0,
        deployedAt: profile.deployedAt,
        lastError: profile.lastError,
      };
    })
    .filter(Boolean) as any[];
}

/**
 * Verify a deployed profile still exists on the Caldera server.
 */
export async function verifyDeployedProfile(
  actorId: string,
): Promise<{ exists: boolean; calderaData?: any; error?: string }> {
  const db = await getDb();
  if (!db) return { exists: false, error: "Database not available" };

  const [actor] = await db
    .select()
    .from(threatActors)
    .where(eq(threatActors.actorId, actorId))
    .limit(1);

  if (!actor) return { exists: false, error: "Actor not found" };

  let profile: CalderaProfileStatus | null = null;
  try {
    profile =
      typeof actor.calderaProfile === "string"
        ? JSON.parse(actor.calderaProfile as string)
        : (actor.calderaProfile as CalderaProfileStatus | null);
  } catch {
    return { exists: false, error: "Invalid profile data" };
  }

  if (!profile?.calderaServerId) {
    return { exists: false, error: "No Caldera server ID — profile not deployed" };
  }

  const result = await calderaFetch(`/api/v2/adversaries/${profile.calderaServerId}`);
  return {
    exists: result.ok,
    calderaData: result.data,
    error: result.ok ? undefined : `Caldera returned ${result.status}`,
  };
}
