/**
 * Credential Service
 * 
 * Provides per-user API credential lookup from the user_platform_credentials table.
 * Falls back to global environment variables when no user-specific credentials exist.
 * 
 * Used by:
 * - bug-bounty-intelligence.ts (HackerOne enrichment)
 * - bounty-intel-scheduler.ts (background HackerOne sync)
 * - engagement-orchestrator.ts (passes user context through pipeline)
 * - cross-module-enrichment.ts
 * - discovery-engine.ts
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

// ─── Credential Lookup ──────────────────────────────────────────────────────

/**
 * Get HackerOne API credentials for a specific user.
 * 
 * Resolution order:
 * 1. User-specific credentials from user_platform_credentials table (if userId provided)
 * 2. Global environment variables (HACKERONE_API_USERNAME / HACKERONE_API_KEY)
 * 3. null (no credentials available)
 */
export async function getH1CredentialsForUser(
  userId?: number | string | null
): Promise<PlatformCredentials | null> {
  // 1. Try user-specific credentials from DB
  if (userId) {
    try {
      const db = await _getDb();
      if (db) {
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
    } catch (dbErr: any) {
      console.warn("[CredentialService] DB lookup failed, falling back to env vars:", dbErr.message);
    }
  }

  // 2. Fall back to global env vars
  const envKey = process.env.HACKERONE_API_KEY;
  const envUsername = process.env.HACKERONE_API_USERNAME;
  if (envKey) {
    return {
      username: envUsername || "htc0",
      apiKey: envKey,
      source: "env_var",
    };
  }

  // 3. No credentials available
  return null;
}

/**
 * Get credentials for any supported platform.
 * Currently supports: hackerone, bugcrowd, intigriti, synack, yeswehack
 */
export async function getPlatformCredentials(
  platform: string,
  userId?: number | string | null
): Promise<PlatformCredentials | null> {
  if (platform === "hackerone") {
    return getH1CredentialsForUser(userId);
  }

  // Generic lookup for other platforms
  if (userId) {
    try {
      const db = await _getDb();
      if (db) {
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
    } catch (dbErr: any) {
      console.warn(`[CredentialService] DB lookup failed for ${platform}:`, dbErr.message);
    }
  }

  return null;
}
