/**
 * Multi-Platform Bug Bounty Sync Engine
 * 
 * Fetches programs and findings from connected bug bounty platforms:
 * - HackerOne (existing, enhanced)
 * - Bugcrowd (REST API v4)
 * - Intigriti (REST API v1)
 * - YesWeHack (OAuth2 API)
 * - Open Bug Bounty (public scraping)
 * - Immunefi (public API)
 */

import { getDb as _getDb } from "../db";
import {
  bugBountyPrograms,
  bugBountyFindings,
  bugBountySyncLogs,
  userPlatformCredentials,
} from "../../drizzle/schema";
import { eq, and, desc, sql } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  return db!;
}

// ─── Encryption helpers (mirror platform-credentials.ts) ───
const ALGO = "aes-256-gcm";
function getEncKey(): Buffer {
  const secret = process.env.JWT_SECRET || "fallback-secret-key-for-dev";
  return crypto.createHash("sha256").update(secret).digest();
}

function decrypt(encrypted: string): string {
  const buf = Buffer.from(encrypted, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv(ALGO, getEncKey(), iv);
  decipher.setAuthTag(tag);
  return decipher.update(ct, undefined, "utf8") + decipher.final("utf8");
}

// ─── Credential Resolution ───

export interface PlatformCredential {
  platform: string;
  apiKey: string;
  apiUsername?: string | null;
  label?: string | null;
}

async function resolveCredentials(
  userId: number,
  platform: string
): Promise<PlatformCredential | null> {
  const db = await getDbSafe();
  const [cred] = await db
    .select()
    .from(userPlatformCredentials)
    .where(
      and(
        eq(userPlatformCredentials.userId, userId),
        eq(userPlatformCredentials.platform, platform as any),
        eq(userPlatformCredentials.isActive, true)
      )
    )
    .limit(1);

  if (!cred) {
    // Fallback: try credential-service (DB any-user fallback + validated env vars)
    try {
      const { getH1CredentialsForUser, getPlatformCredentials } = await import('./credential-service');
      if (platform === 'hackerone') {
        const h1Creds = await getH1CredentialsForUser(userId);
        if (h1Creds) {
          return { platform, apiKey: h1Creds.apiKey, apiUsername: h1Creds.username };
        }
      } else {
        const platCreds = await getPlatformCredentials(platform, userId);
        if (platCreds) {
          return { platform, apiKey: platCreds.apiKey, apiUsername: platCreds.username };
        }
      }
    } catch (e: any) {
      console.warn(`[BountyPlatformSync] credential-service fallback failed for ${platform}:`, e.message);
    }
    return null;
  }

  try {
    return {
      platform: cred.platform,
      apiKey: decrypt(cred.apiKeyEncrypted),
      apiUsername: cred.apiUsername,
      label: cred.label,
    };
  } catch {
    return null;
  }
}

// ─── Platform API Fetchers ───

async function fetchJSON(url: string, headers: Record<string, string> = {}) {
  const resp = await fetch(url, {
    headers: { Accept: "application/json", ...headers },
  });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}: ${resp.statusText} from ${url}`);
  }
  return resp.json();
}

// ── Bugcrowd ──

async function syncBugcrowdPrograms(
  cred: PlatformCredential,
  pages: number = 3
): Promise<{ synced: number; errors: string[] }> {
  const db = await getDbSafe();
  let synced = 0;
  const errors: string[] = [];

  for (let page = 1; page <= pages; page++) {
    try {
      const data = await fetchJSON(
        `https://api.bugcrowd.com/programs?page[limit]=25&page[offset]=${(page - 1) * 25}&fields[program]=code,name,description,min_reward,max_reward,program_url,starts_at,ends_at`,
        { Authorization: `Token ${cred.apiKey}` }
      );

      if (!data?.data?.length) break;

      for (const prog of data.data) {
        const attrs = prog.attributes || {};
        const handle = prog.attributes?.code || prog.id;

        const existing = await db
          .select()
          .from(bugBountyPrograms)
          .where(
            and(
              eq(bugBountyPrograms.platform, "bugcrowd"),
              eq(bugBountyPrograms.handle, handle)
            )
          )
          .limit(1);

        if (!existing.length) {
          await db.insert(bugBountyPrograms).values({
            platform: "bugcrowd",
            handle,
            name: attrs.name || handle,
            url: attrs.program_url || `https://bugcrowd.com/${handle}`,
            minBounty: attrs.min_reward || 0,
            maxBounty: attrs.max_reward || 0,
            state: "open",
            lastSyncedAt: new Date(),
          });
          synced++;
        } else {
          await db
            .update(bugBountyPrograms)
            .set({
              name: attrs.name || existing[0].name,
              minBounty: attrs.min_reward || existing[0].minBounty,
              maxBounty: attrs.max_reward || existing[0].maxBounty,
              lastSyncedAt: new Date(),
            })
            .where(eq(bugBountyPrograms.id, existing[0].id));
          synced++;
        }
      }
    } catch (err: any) {
      errors.push(`Bugcrowd page ${page}: ${err.message}`);
    }
  }

  return { synced, errors };
}

async function syncBugcrowdSubmissions(
  cred: PlatformCredential,
  pages: number = 3
): Promise<{ synced: number; errors: string[] }> {
  const db = await getDbSafe();
  let synced = 0;
  const errors: string[] = [];

  for (let page = 1; page <= pages; page++) {
    try {
      const data = await fetchJSON(
        `https://api.bugcrowd.com/submissions?page[limit]=25&page[offset]=${(page - 1) * 25}&fields[submission]=title,severity,state,submitted_at,vulnerability_references,caption`,
        { Authorization: `Token ${cred.apiKey}` }
      );

      if (!data?.data?.length) break;

      for (const sub of data.data) {
        const attrs = sub.attributes || {};
        const externalId = sub.id;

        const existing = await db
          .select()
          .from(bugBountyFindings)
          .where(
            and(
              eq(bugBountyFindings.platform, "bugcrowd"),
              eq(bugBountyFindings.externalId, externalId)
            )
          )
          .limit(1);

        if (!existing.length) {
          const severityMap: Record<string, string> = {
            "1": "low",
            "2": "medium",
            "3": "high",
            "4": "critical",
          };

          await db.insert(bugBountyFindings).values({
            platform: "bugcrowd",
            externalId,
            title: attrs.title || attrs.caption || "Untitled",
            severityRating: severityMap[String(attrs.severity)] || "medium",
            state: attrs.state || "new",
            disclosedAt: attrs.submitted_at ? new Date(attrs.submitted_at) : null,
            reportUrl: `https://bugcrowd.com/submissions/${externalId}`,
          });
          synced++;
        }
      }
    } catch (err: any) {
      errors.push(`Bugcrowd submissions page ${page}: ${err.message}`);
    }
  }

  return { synced, errors };
}

// ── Intigriti ──

async function syncIntigritiPrograms(
  cred: PlatformCredential,
  pages: number = 3
): Promise<{ synced: number; errors: string[] }> {
  const db = await getDbSafe();
  let synced = 0;
  const errors: string[] = [];

  for (let page = 0; page < pages; page++) {
    try {
      const data = await fetchJSON(
        `https://api.intigriti.com/core/researcher/programs?offset=${page * 25}&limit=25`,
        { Authorization: `Bearer ${cred.apiKey}` }
      );

      const programs = data?.records || data || [];
      if (!Array.isArray(programs) || !programs.length) break;

      for (const prog of programs) {
        const handle = prog.handle || prog.programId || prog.id;
        if (!handle) continue;

        const existing = await db
          .select()
          .from(bugBountyPrograms)
          .where(
            and(
              eq(bugBountyPrograms.platform, "intigriti"),
              eq(bugBountyPrograms.handle, String(handle))
            )
          )
          .limit(1);

        if (!existing.length) {
          await db.insert(bugBountyPrograms).values({
            platform: "intigriti",
            handle: String(handle),
            name: prog.name || prog.title || String(handle),
            url: prog.url || `https://app.intigriti.com/researcher/programs/${handle}/detail`,
            minBounty: prog.minBounty || 0,
            maxBounty: prog.maxBounty || 0,
            state: prog.status === "open" ? "open" : prog.status || "open",
            lastSyncedAt: new Date(),
          });
          synced++;
        } else {
          await db
            .update(bugBountyPrograms)
            .set({
              name: prog.name || existing[0].name,
              lastSyncedAt: new Date(),
            })
            .where(eq(bugBountyPrograms.id, existing[0].id));
          synced++;
        }
      }
    } catch (err: any) {
      errors.push(`Intigriti page ${page}: ${err.message}`);
    }
  }

  return { synced, errors };
}

// ── YesWeHack ──

async function getYWHToken(cred: PlatformCredential): Promise<string | null> {
  try {
    const resp = await fetch("https://api.yeswehack.com/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: cred.apiUsername,
        password: cred.apiKey,
      }),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data?.token || null;
  } catch {
    return null;
  }
}

async function syncYesWeHackPrograms(
  cred: PlatformCredential,
  pages: number = 3
): Promise<{ synced: number; errors: string[] }> {
  const db = await getDbSafe();
  let synced = 0;
  const errors: string[] = [];

  const token = await getYWHToken(cred);
  if (!token) {
    return { synced: 0, errors: ["Failed to authenticate with YesWeHack"] };
  }

  for (let page = 1; page <= pages; page++) {
    try {
      const data = await fetchJSON(
        `https://api.yeswehack.com/programs?page=${page}`,
        { Authorization: `Bearer ${token}` }
      );

      const programs = data?.items || [];
      if (!programs.length) break;

      for (const prog of programs) {
        const handle = prog.slug || prog.id;
        if (!handle) continue;

        const existing = await db
          .select()
          .from(bugBountyPrograms)
          .where(
            and(
              eq(bugBountyPrograms.platform, "yeswehack"),
              eq(bugBountyPrograms.handle, String(handle))
            )
          )
          .limit(1);

        if (!existing.length) {
          await db.insert(bugBountyPrograms).values({
            platform: "yeswehack",
            handle: String(handle),
            name: prog.title || prog.name || String(handle),
            url: `https://yeswehack.com/programs/${handle}`,
            minBounty: prog.min_bounty || 0,
            maxBounty: prog.max_bounty || 0,
            state: prog.public ? "open" : "private",
            lastSyncedAt: new Date(),
          });
          synced++;
        } else {
          await db
            .update(bugBountyPrograms)
            .set({
              name: prog.title || existing[0].name,
              lastSyncedAt: new Date(),
            })
            .where(eq(bugBountyPrograms.id, existing[0].id));
          synced++;
        }
      }
    } catch (err: any) {
      errors.push(`YesWeHack page ${page}: ${err.message}`);
    }
  }

  return { synced, errors };
}

// ── Open Bug Bounty (public) ──

async function syncOpenBugBountyPrograms(): Promise<{
  synced: number;
  errors: string[];
}> {
  const db = await getDbSafe();
  let synced = 0;
  const errors: string[] = [];

  try {
    // Open Bug Bounty has a public JSON feed
    const data = await fetchJSON(
      "https://www.openbugbounty.org/api/1/search/?type=responsible"
    );

    const entries = Array.isArray(data) ? data.slice(0, 50) : [];

    for (const entry of entries) {
      const handle = entry.host || entry.url;
      if (!handle) continue;

      const existing = await db
        .select()
        .from(bugBountyPrograms)
        .where(
          and(
            eq(bugBountyPrograms.platform, "open_bug_bounty"),
            eq(bugBountyPrograms.handle, String(handle))
          )
        )
        .limit(1);

      if (!existing.length) {
        await db.insert(bugBountyPrograms).values({
          platform: "open_bug_bounty",
          handle: String(handle),
          name: entry.host || String(handle),
          url: entry.url || `https://www.openbugbounty.org/search/?search=${handle}`,
          minBounty: 0,
          maxBounty: 0,
          state: "open",
          lastSyncedAt: new Date(),
        });
        synced++;
      }
    }
  } catch (err: any) {
    errors.push(`Open Bug Bounty: ${err.message}`);
  }

  return { synced, errors };
}

// ── Immunefi (public) ──

async function syncImmunefiPrograms(): Promise<{
  synced: number;
  errors: string[];
}> {
  const db = await getDbSafe();
  let synced = 0;
  const errors: string[] = [];

  try {
    // Immunefi has a public bounties endpoint
    const data = await fetchJSON("https://immunefi.com/api/bounties");

    const bounties = Array.isArray(data) ? data.slice(0, 100) : [];

    for (const bounty of bounties) {
      const handle = bounty.id || bounty.slug || bounty.project;
      if (!handle) continue;

      const existing = await db
        .select()
        .from(bugBountyPrograms)
        .where(
          and(
            eq(bugBountyPrograms.platform, "immunefi"),
            eq(bugBountyPrograms.handle, String(handle))
          )
        )
        .limit(1);

      if (!existing.length) {
        await db.insert(bugBountyPrograms).values({
          platform: "immunefi",
          handle: String(handle),
          name: bounty.project || bounty.name || String(handle),
          url: bounty.url || `https://immunefi.com/bug-bounty/${handle}`,
          minBounty: 0,
          maxBounty: bounty.maximum_reward || bounty.maxBounty || 0,
          state: bounty.status === "active" ? "open" : bounty.status || "open",
          lastSyncedAt: new Date(),
        });
        synced++;
      }
    }
  } catch (err: any) {
    errors.push(`Immunefi: ${err.message}`);
  }

  return { synced, errors };
}

// ─── Main Sync Orchestrator ───

export interface SyncResult {
  platform: string;
  synced: number;
  errors: string[];
  duration: number;
}

export async function syncPlatform(
  userId: number,
  platform: string,
  pages: number = 3
): Promise<SyncResult> {
  const start = Date.now();
  const db = await getDbSafe();

  // Create sync log
  const [logResult] = await db.insert(bugBountySyncLogs).values({
    platform,
    syncType: "auto_sync",
    status: "running",
  });
  const logId = logResult.insertId;

  let result: { synced: number; errors: string[] } = { synced: 0, errors: [] };

  try {
    switch (platform) {
      case "bugcrowd": {
        const cred = await resolveCredentials(userId, "bugcrowd");
        if (!cred) throw new Error("No Bugcrowd credentials configured");
        const programs = await syncBugcrowdPrograms(cred, pages);
        const submissions = await syncBugcrowdSubmissions(cred, pages);
        result = {
          synced: programs.synced + submissions.synced,
          errors: [...programs.errors, ...submissions.errors],
        };
        break;
      }
      case "intigriti": {
        const cred = await resolveCredentials(userId, "intigriti");
        if (!cred) throw new Error("No Intigriti credentials configured");
        result = await syncIntigritiPrograms(cred, pages);
        break;
      }
      case "yeswehack": {
        const cred = await resolveCredentials(userId, "yeswehack");
        if (!cred) throw new Error("No YesWeHack credentials configured");
        result = await syncYesWeHackPrograms(cred, pages);
        break;
      }
      case "open_bug_bounty": {
        result = await syncOpenBugBountyPrograms();
        break;
      }
      case "immunefi": {
        result = await syncImmunefiPrograms();
        break;
      }
      default:
        throw new Error(`Unsupported platform for auto-sync: ${platform}`);
    }

    await db
      .update(bugBountySyncLogs)
      .set({
        status: result.errors.length > 0 ? "completed" : "completed",
        itemsSynced: result.synced,
        completedAt: new Date(),
        errorMessage: result.errors.length > 0 ? result.errors.join("; ") : null,
      })
      .where(eq(bugBountySyncLogs.id, Number(logId)));
  } catch (err: any) {
    result.errors.push(err.message);
    await db
      .update(bugBountySyncLogs)
      .set({
        status: "failed",
        errorMessage: err.message,
        completedAt: new Date(),
      })
      .where(eq(bugBountySyncLogs.id, Number(logId)));
  }

  return {
    platform,
    synced: result.synced,
    errors: result.errors,
    duration: Date.now() - start,
  };
}

/**
 * Sync all platforms that have active credentials for a given user.
 * Also syncs public platforms (Open Bug Bounty, Immunefi) regardless of credentials.
 */
export async function syncAllPlatforms(
  userId: number,
  pages: number = 3
): Promise<SyncResult[]> {
  const db = await getDbSafe();
  const results: SyncResult[] = [];

  // Get all active credentials for this user
  const creds = await db
    .select()
    .from(userPlatformCredentials)
    .where(
      and(
        eq(userPlatformCredentials.userId, userId),
        eq(userPlatformCredentials.isActive, true)
      )
    );

  const credPlatforms = new Set(creds.map((c) => c.platform));

  // Sync platforms with credentials
  const platformsToSync = ["bugcrowd", "intigriti", "yeswehack"];
  for (const platform of platformsToSync) {
    if (credPlatforms.has(platform)) {
      const result = await syncPlatform(userId, platform, pages);
      results.push(result);
    }
  }

  // Always sync public platforms
  const publicPlatforms = ["open_bug_bounty", "immunefi"];
  for (const platform of publicPlatforms) {
    const result = await syncPlatform(userId, platform, pages);
    results.push(result);
  }

  return results;
}
