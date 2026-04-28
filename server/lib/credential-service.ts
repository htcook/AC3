/**
 * Credential Service
 * 
 * Provides per-user API credential lookup from the user_platform_credentials table.
 * Falls back to any active credential in the DB, then global environment variables.
 * 
 * Resolution order for HackerOne:
 * 1. User-specific credentials from DB (if userId provided)
 * 2. ANY active HackerOne credential from DB (owner/admin fallback)
 * 3. Global environment variables (HACKERONE_API_USERNAME / HACKERONE_API_KEY)
 * 4. null (no credentials available)
 * 
 * Used by:
 * - bug-bounty-intelligence.ts (HackerOne enrichment)
 * - bounty-intel-scheduler.ts (background HackerOne sync)
 * - engagement-orchestrator.ts (passes user context through pipeline)
 * - cross-module-enrichment.ts
 * - discovery-engine.ts
 * - va-bugbounty.ts (BB workspace parser)
 * - bug-bounty.ts (H1 sync)
 */

import { getDb as _getDb } from "../db";
import { userPlatformCredentials } from "../../drizzle/schema";
import { eq, and } from "drizzle-orm";
import crypto from "crypto";

// ─── Encryption (must match platform-credentials.ts) ────────────────────────

const ENCRYPTION_KEY = process.env.JWT_SECRET
  ? crypto.createHash("sha256").update(process.env.JWT_SECRET).digest()
  : crypto.randomBytes(32);

function decrypt(encryptedText: string): string {
  const [ivHex, authTagHex, encrypted] = encryptedText.split(":");
  if (!ivHex || !authTagHex || !encrypted) throw new Error("Invalid encrypted format");
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ─── Types ──────────────────────────────────────────────────────────────────

export interface PlatformCredentials {
  username: string;
  apiKey: string;
  baseUrl?: string;
  source: "user_db" | "env_var";
  userId?: number;
}

// ─── H1 API Validation ─────────────────────────────────────────────────────

const H1_API_BASE = "https://api.hackerone.com";

/**
 * Quick validation of H1 credentials by hitting /v1/hackers/programs (lightweight).
 * Returns true if the credentials are accepted (HTTP 200).
 */
async function validateH1Credentials(username: string, apiKey: string): Promise<boolean> {
  try {
    const basicAuth = Buffer.from(`${username}:${apiKey}`).toString("base64");
    const resp = await fetch(`${H1_API_BASE}/v1/hackers/programs?page%5Bsize%5D=1`, {
      method: "GET",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(10000),
    });
    return resp.status === 200;
  } catch {
    return false;
  }
}

// ─── Credential Lookup ──────────────────────────────────────────────────────

/**
 * Get HackerOne API credentials for a specific user.
 * 
 * Resolution order:
 * 1. User-specific credentials from user_platform_credentials table (if userId provided)
 * 2. ANY active HackerOne credential from the DB (fallback for background jobs / shared use)
 * 3. Global environment variables (HACKERONE_API_USERNAME / HACKERONE_API_KEY)
 *    — only if they pass a quick validation check (prevents stale BYOK creds)
 * 4. null (no credentials available)
 */
export async function getH1CredentialsForUser(
  userId?: number | string | null
): Promise<PlatformCredentials | null> {
  try {
    const db = await _getDb();
    if (db) {
      // 1. Try user-specific credentials from DB
      if (userId) {
        const numericUserId = typeof userId === "string" ? parseInt(userId, 10) : userId;
        if (!isNaN(numericUserId)) {
          const rows = await db
            .select()
            .from(userPlatformCredentials)
            .where(
              and(
                eq(userPlatformCredentials.userId, numericUserId),
                eq(userPlatformCredentials.platform, "hackerone"),
                eq(userPlatformCredentials.isActive, 1)
              )
            )
            .limit(1);

          if (rows.length > 0) {
            const cred = rows[0];
            try {
              const apiKey = decrypt(cred.apiKeyEncrypted);
              return {
                username: cred.apiUsername || "",
                apiKey,
                baseUrl: cred.baseUrl || undefined,
                source: "user_db",
                userId: numericUserId,
              };
            } catch (decryptErr: any) {
              console.warn(`[CredentialService] Failed to decrypt H1 credentials for user ${numericUserId}:`, decryptErr.message);
            }
          }
        }
      }

      // 2. Try ANY active HackerOne credential from the DB (owner/admin fallback)
      const anyRows = await db
        .select()
        .from(userPlatformCredentials)
        .where(
          and(
            eq(userPlatformCredentials.platform, "hackerone"),
            eq(userPlatformCredentials.isActive, 1)
          )
        )
        .limit(5); // get a few in case some fail to decrypt

      for (const cred of anyRows) {
        try {
          const apiKey = decrypt(cred.apiKeyEncrypted);
          console.log(`[CredentialService] Using H1 credentials from DB (user ${cred.userId}, username: ${cred.apiUsername})`);
          return {
            username: cred.apiUsername || "",
            apiKey,
            baseUrl: cred.baseUrl || undefined,
            source: "user_db",
            userId: cred.userId,
          };
        } catch (decryptErr: any) {
          console.warn(`[CredentialService] Failed to decrypt H1 credentials for user ${cred.userId}:`, decryptErr.message);
          continue;
        }
      }
    }
  } catch (dbErr: any) {
    console.warn("[CredentialService] DB lookup failed, falling back to env vars:", dbErr.message);
  }

  // 3. Fall back to global env vars — but validate first to catch stale BYOK creds
  const envKey = process.env.HACKERONE_API_KEY;
  const envUsername = process.env.HACKERONE_API_USERNAME;
  if (envKey) {
    const username = envUsername || "htc0";
    // Quick validation to prevent using stale/revoked credentials
    const isValid = await validateH1Credentials(username, envKey);
    if (isValid) {
      return {
        username,
        apiKey: envKey,
        source: "env_var",
      };
    } else {
      console.warn(`[CredentialService] Env H1 credentials (${username}) failed validation — skipping`);
    }
  }

  // 4. No credentials available
  return null;
}

/**
 * Get credentials for any supported platform.
 * Currently supports: hackerone, bugcrowd, intigriti, synack, yeswehack, hackthebox
 */
export async function getPlatformCredentials(
  platform: string,
  userId?: number | string | null
): Promise<PlatformCredentials | null> {
  if (platform === "hackerone") {
    return getH1CredentialsForUser(userId);
  }

  // Generic lookup for other platforms
  try {
    const db = await _getDb();
    if (db) {
      // 1. Try user-specific
      if (userId) {
        const numericUserId = typeof userId === "string" ? parseInt(userId, 10) : userId;
        if (!isNaN(numericUserId)) {
          const rows = await db
            .select()
            .from(userPlatformCredentials)
            .where(
              and(
                eq(userPlatformCredentials.userId, numericUserId),
                eq(userPlatformCredentials.platform, platform as any),
                eq(userPlatformCredentials.isActive, 1)
              )
            )
            .limit(1);

          if (rows.length > 0) {
            const cred = rows[0];
            try {
              const apiKey = decrypt(cred.apiKeyEncrypted);
              return {
                username: cred.apiUsername || "",
                apiKey,
                baseUrl: cred.baseUrl || undefined,
                source: "user_db",
                userId: numericUserId,
              };
            } catch (decryptErr: any) {
              console.warn(`[CredentialService] Failed to decrypt ${platform} credentials for user ${numericUserId}:`, decryptErr.message);
            }
          }
        }
      }

      // 2. Try ANY active credential for this platform
      const anyRows = await db
        .select()
        .from(userPlatformCredentials)
        .where(
          and(
            eq(userPlatformCredentials.platform, platform as any),
            eq(userPlatformCredentials.isActive, 1)
          )
        )
        .limit(5);

      for (const cred of anyRows) {
        try {
          const apiKey = decrypt(cred.apiKeyEncrypted);
          return {
            username: cred.apiUsername || "",
            apiKey,
            baseUrl: cred.baseUrl || undefined,
            source: "user_db",
            userId: cred.userId,
          };
        } catch {
          continue;
        }
      }
    }
  } catch (dbErr: any) {
    console.warn(`[CredentialService] DB lookup failed for ${platform}:`, dbErr.message);
  }

  return null;
}
