import {
  getDb,
  init_db
} from "./chunk-5G2CDI2L.js";
import {
  init_schema,
  userPlatformCredentials
} from "./chunk-2ZYBVKLY.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/credential-service.ts
import { eq, and } from "drizzle-orm";
import crypto from "crypto";
function decrypt(encryptedText) {
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
async function validateH1Credentials(username, apiKey) {
  try {
    const basicAuth = Buffer.from(`${username}:${apiKey}`).toString("base64");
    const resp = await fetch(`${H1_API_BASE}/v1/hackers/programs?page%5Bsize%5D=1`, {
      method: "GET",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        Accept: "application/json"
      },
      signal: AbortSignal.timeout(1e4)
    });
    return resp.status === 200;
  } catch {
    return false;
  }
}
async function getH1CredentialsForUser(userId) {
  try {
    const db = await getDb();
    if (db) {
      if (userId) {
        const numericUserId = typeof userId === "string" ? parseInt(userId, 10) : userId;
        if (!isNaN(numericUserId)) {
          const rows = await db.select().from(userPlatformCredentials).where(
            and(
              eq(userPlatformCredentials.userId, numericUserId),
              eq(userPlatformCredentials.platform, "hackerone"),
              eq(userPlatformCredentials.isActive, 1)
            )
          ).limit(1);
          if (rows.length > 0) {
            const cred = rows[0];
            try {
              const apiKey = decrypt(cred.apiKeyEncrypted);
              return {
                username: cred.apiUsername || "",
                apiKey,
                baseUrl: cred.baseUrl || void 0,
                source: "user_db",
                userId: numericUserId
              };
            } catch (decryptErr) {
              console.warn(`[CredentialService] Failed to decrypt H1 credentials for user ${numericUserId}:`, decryptErr.message);
            }
          }
        }
      }
      const anyRows = await db.select().from(userPlatformCredentials).where(
        and(
          eq(userPlatformCredentials.platform, "hackerone"),
          eq(userPlatformCredentials.isActive, 1)
        )
      ).limit(5);
      for (const cred of anyRows) {
        try {
          const apiKey = decrypt(cred.apiKeyEncrypted);
          console.log(`[CredentialService] Using H1 credentials from DB (user ${cred.userId}, username: ${cred.apiUsername})`);
          return {
            username: cred.apiUsername || "",
            apiKey,
            baseUrl: cred.baseUrl || void 0,
            source: "user_db",
            userId: cred.userId
          };
        } catch (decryptErr) {
          console.warn(`[CredentialService] Failed to decrypt H1 credentials for user ${cred.userId}:`, decryptErr.message);
          continue;
        }
      }
    }
  } catch (dbErr) {
    console.warn("[CredentialService] DB lookup failed, falling back to env vars:", dbErr.message);
  }
  const envKey = process.env.HACKERONE_API_KEY;
  const envUsername = process.env.HACKERONE_API_USERNAME;
  if (envKey) {
    const username = envUsername || "htc0";
    const isValid = await validateH1Credentials(username, envKey);
    if (isValid) {
      return {
        username,
        apiKey: envKey,
        source: "env_var"
      };
    } else {
      console.warn(`[CredentialService] Env H1 credentials (${username}) failed validation \u2014 skipping`);
    }
  }
  return null;
}
async function getPlatformCredentials(platform, userId) {
  if (platform === "hackerone") {
    return getH1CredentialsForUser(userId);
  }
  try {
    const db = await getDb();
    if (db) {
      if (userId) {
        const numericUserId = typeof userId === "string" ? parseInt(userId, 10) : userId;
        if (!isNaN(numericUserId)) {
          const rows = await db.select().from(userPlatformCredentials).where(
            and(
              eq(userPlatformCredentials.userId, numericUserId),
              eq(userPlatformCredentials.platform, platform),
              eq(userPlatformCredentials.isActive, 1)
            )
          ).limit(1);
          if (rows.length > 0) {
            const cred = rows[0];
            try {
              const apiKey = decrypt(cred.apiKeyEncrypted);
              return {
                username: cred.apiUsername || "",
                apiKey,
                baseUrl: cred.baseUrl || void 0,
                source: "user_db",
                userId: numericUserId
              };
            } catch (decryptErr) {
              console.warn(`[CredentialService] Failed to decrypt ${platform} credentials for user ${numericUserId}:`, decryptErr.message);
            }
          }
        }
      }
      const anyRows = await db.select().from(userPlatformCredentials).where(
        and(
          eq(userPlatformCredentials.platform, platform),
          eq(userPlatformCredentials.isActive, 1)
        )
      ).limit(5);
      for (const cred of anyRows) {
        try {
          const apiKey = decrypt(cred.apiKeyEncrypted);
          return {
            username: cred.apiUsername || "",
            apiKey,
            baseUrl: cred.baseUrl || void 0,
            source: "user_db",
            userId: cred.userId
          };
        } catch {
          continue;
        }
      }
    }
  } catch (dbErr) {
    console.warn(`[CredentialService] DB lookup failed for ${platform}:`, dbErr.message);
  }
  return null;
}
var ENCRYPTION_KEY, H1_API_BASE;
var init_credential_service = __esm({
  "server/lib/credential-service.ts"() {
    init_db();
    init_schema();
    ENCRYPTION_KEY = process.env.JWT_SECRET ? crypto.createHash("sha256").update(process.env.JWT_SECRET).digest() : crypto.randomBytes(32);
    H1_API_BASE = "https://api.hackerone.com";
  }
});

export {
  getH1CredentialsForUser,
  getPlatformCredentials,
  init_credential_service
};
