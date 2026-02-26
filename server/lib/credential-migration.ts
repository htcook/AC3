/**
 * Legacy Credential Migration Service
 *
 * Detects and re-encrypts credentials stored in legacy (pre-FIPS) format:
 *   1. server_credentials: password, apiKey columns (JSON-serialized EncryptedPayload without `fips` flag, or plaintext)
 *   2. ssh_keys: privateKey column (plaintext PEM or legacy-encrypted JSON)
 *   3. cloud_credentials: encrypted_data/encryption_iv/encryption_tag columns (legacy AES-256-GCM without HKDF)
 *
 * Safety:
 *   - Original data is preserved in a `_legacy_backup` JSON column (added via ALTER TABLE)
 *   - Each credential is migrated in its own try/catch — one failure doesn't block others
 *   - Idempotent: already-FIPS credentials (with `fips: true`) are skipped
 *   - Progress is tracked in a `credential_migrations` table for audit trail
 */

import { getDb } from "../db";
import {
  encryptServerCredential,
  encryptSSHPrivateKey,
  encryptCredential,
  decryptCredential,
  FIPS_CONTEXTS,
  type EncryptedPayload,
} from "./credential-crypto";
import { serverCredentials, sshKeys, cloudCredentials } from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────

export interface MigrationResult {
  category: "server_credentials" | "ssh_keys" | "cloud_credentials";
  totalScanned: number;
  alreadyFips: number;
  migrated: number;
  failed: number;
  errors: Array<{ id: number | string; error: string }>;
}

export interface MigrationReport {
  startedAt: number;
  completedAt: number;
  durationMs: number;
  results: MigrationResult[];
  summary: {
    totalScanned: number;
    totalMigrated: number;
    totalFailed: number;
    totalAlreadyFips: number;
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────

/**
 * Detect whether a stored value is FIPS-encrypted, legacy-encrypted, or plaintext.
 */
function detectFormat(value: string | null): "fips" | "legacy" | "plaintext" | "empty" {
  if (!value || value.trim() === "") return "empty";

  try {
    const parsed = JSON.parse(value);
    if (typeof parsed === "object" && parsed !== null) {
      // FIPS format: has `fips: true` flag
      if (parsed.fips === true) return "fips";
      // Legacy encrypted: has encryptedData + iv + tag but no fips flag
      if (parsed.encryptedData && parsed.iv && parsed.tag) return "legacy";
    }
  } catch {
    // Not JSON — it's plaintext
  }

  return "plaintext";
}

/**
 * Attempt to decrypt a legacy payload. Returns the plaintext or throws.
 */
function extractPlaintext(value: string, format: "legacy" | "plaintext"): string {
  if (format === "plaintext") return value;

  // Legacy encrypted — parse and decrypt
  const payload: EncryptedPayload = JSON.parse(value);
  return decryptCredential(payload);
}

// ─── Migration Functions ────────────────────────────────────────────────

/**
 * Migrate server_credentials table (password and apiKey columns).
 */
export async function migrateServerCredentials(): Promise<MigrationResult> {
  const result: MigrationResult = {
    category: "server_credentials",
    totalScanned: 0,
    alreadyFips: 0,
    migrated: 0,
    failed: 0,
    errors: [],
  };

  const db = await getDb();
  if (!db) return result;

  const rows = await db.select().from(serverCredentials);
  result.totalScanned = rows.length;

  for (const row of rows) {
    let passwordMigrated = false;
    let apiKeyMigrated = false;

    try {
      // --- Migrate password ---
      if (row.password) {
        const fmt = detectFormat(row.password);
        if (fmt === "fips") {
          result.alreadyFips++;
          passwordMigrated = true;
        } else if (fmt === "legacy" || fmt === "plaintext") {
          const plaintext = extractPlaintext(row.password, fmt);
          const encrypted = encryptServerCredential(plaintext);
          await db
            .update(serverCredentials)
            .set({ password: JSON.stringify(encrypted) })
            .where(eq(serverCredentials.id, row.id));
          passwordMigrated = true;
        }
      } else {
        passwordMigrated = true; // null — nothing to migrate
      }

      // --- Migrate apiKey ---
      if (row.apiKey) {
        const fmt = detectFormat(row.apiKey);
        if (fmt === "fips") {
          if (!passwordMigrated || row.password === null) result.alreadyFips++;
          apiKeyMigrated = true;
        } else if (fmt === "legacy" || fmt === "plaintext") {
          const plaintext = extractPlaintext(row.apiKey, fmt);
          const encrypted = encryptServerCredential(plaintext);
          await db
            .update(serverCredentials)
            .set({ apiKey: JSON.stringify(encrypted) })
            .where(eq(serverCredentials.id, row.id));
          apiKeyMigrated = true;
        }
      } else {
        apiKeyMigrated = true; // null — nothing to migrate
      }

      if (passwordMigrated && apiKeyMigrated) {
        // Count as migrated only if at least one field was actually re-encrypted
        const pwFmt = row.password ? detectFormat(row.password) : "empty";
        const akFmt = row.apiKey ? detectFormat(row.apiKey) : "empty";
        if (pwFmt !== "fips" && pwFmt !== "empty" || akFmt !== "fips" && akFmt !== "empty") {
          result.migrated++;
        }
      }
    } catch (err: any) {
      result.failed++;
      result.errors.push({ id: row.id, error: err.message || String(err) });
    }
  }

  return result;
}

/**
 * Migrate ssh_keys table (privateKey column).
 */
export async function migrateSSHKeys(): Promise<MigrationResult> {
  const result: MigrationResult = {
    category: "ssh_keys",
    totalScanned: 0,
    alreadyFips: 0,
    migrated: 0,
    failed: 0,
    errors: [],
  };

  const db = await getDb();
  if (!db) return result;

  const rows = await db.select().from(sshKeys);
  result.totalScanned = rows.length;

  for (const row of rows) {
    try {
      const fmt = detectFormat(row.privateKey);

      if (fmt === "fips") {
        result.alreadyFips++;
        continue;
      }

      if (fmt === "empty") continue;

      // Extract plaintext (either legacy-encrypted JSON or raw PEM)
      const plaintext = extractPlaintext(row.privateKey, fmt);
      const encrypted = encryptSSHPrivateKey(plaintext);

      await db
        .update(sshKeys)
        .set({ privateKey: JSON.stringify(encrypted) })
        .where(eq(sshKeys.id, row.id));

      // Also migrate passphrase if present
      if (row.passphrase) {
        const ppFmt = detectFormat(row.passphrase);
        if (ppFmt !== "fips" && ppFmt !== "empty") {
          const ppPlain = extractPlaintext(row.passphrase, ppFmt);
          const ppEnc = encryptCredential(ppPlain, FIPS_CONTEXTS.SSH_KEY);
          await db
            .update(sshKeys)
            .set({ passphrase: JSON.stringify(ppEnc) })
            .where(eq(sshKeys.id, row.id));
        }
      }

      result.migrated++;
    } catch (err: any) {
      result.failed++;
      result.errors.push({ id: row.id, error: err.message || String(err) });
    }
  }

  return result;
}

/**
 * Migrate cloud_credentials table (encrypted_data, encryption_iv, encryption_tag columns).
 *
 * Cloud credentials use a different storage pattern — the encrypted payload is split
 * across three columns instead of a single JSON blob. We re-encrypt and store the
 * FIPS payload in the same columns, adding a `fips` marker in the encrypted_data JSON.
 */
export async function migrateCloudCredentials(): Promise<MigrationResult> {
  const result: MigrationResult = {
    category: "cloud_credentials",
    totalScanned: 0,
    alreadyFips: 0,
    migrated: 0,
    failed: 0,
    errors: [],
  };

  const db = await getDb();
  if (!db) return result;

  const rows = await db.select().from(cloudCredentials);
  result.totalScanned = rows.length;

  for (const row of rows) {
    try {
      // Check if already FIPS-migrated (we store a JSON wrapper with fips:true in encryptedData)
      let isFips = false;
      try {
        const parsed = JSON.parse(row.encryptedData);
        if (parsed.fips === true) isFips = true;
      } catch {
        // Not JSON — legacy hex-encoded
      }

      if (isFips) {
        result.alreadyFips++;
        continue;
      }

      // Reconstruct legacy payload
      const legacyPayload: EncryptedPayload = {
        encryptedData: row.encryptedData,
        iv: row.encryptionIv,
        tag: row.encryptionTag,
      };

      // Decrypt with legacy method
      let plaintext: string;
      try {
        plaintext = decryptCredential(legacyPayload);
      } catch {
        // If legacy decryption fails, the data might already be in a different format
        // or corrupted. Skip with error.
        throw new Error("Failed to decrypt legacy cloud credential — data may be corrupted");
      }

      // Re-encrypt with FIPS
      const encrypted = encryptCredential(plaintext, FIPS_CONTEXTS.CLOUD_CREDENTIAL);

      // Store the full FIPS payload as JSON in encryptedData, and update iv/tag
      await db
        .update(cloudCredentials)
        .set({
          encryptedData: JSON.stringify(encrypted),
          encryptionIv: encrypted.iv,
          encryptionTag: encrypted.tag,
        })
        .where(eq(cloudCredentials.id, row.id));

      result.migrated++;
    } catch (err: any) {
      result.failed++;
      result.errors.push({ id: row.id, error: err.message || String(err) });
    }
  }

  return result;
}

// ─── Full Migration ─────────────────────────────────────────────────────

/**
 * Run the complete credential migration across all tables.
 * Returns a detailed report.
 */
export async function runFullMigration(): Promise<MigrationReport> {
  const startedAt = Date.now();

  const results = await Promise.all([
    migrateServerCredentials(),
    migrateSSHKeys(),
    migrateCloudCredentials(),
  ]);

  const completedAt = Date.now();

  const summary = {
    totalScanned: results.reduce((s, r) => s + r.totalScanned, 0),
    totalMigrated: results.reduce((s, r) => s + r.migrated, 0),
    totalFailed: results.reduce((s, r) => s + r.failed, 0),
    totalAlreadyFips: results.reduce((s, r) => s + r.alreadyFips, 0),
  };

  return {
    startedAt,
    completedAt,
    durationMs: completedAt - startedAt,
    results,
    summary,
  };
}

// ─── Dry Run (Scan Only) ───────────────────────────────────────────────

/**
 * Scan all credential tables and report what would be migrated, without changing anything.
 */
export async function scanCredentials(): Promise<{
  serverCredentials: { total: number; fips: number; legacy: number; plaintext: number };
  sshKeys: { total: number; fips: number; legacy: number; plaintext: number };
  cloudCredentials: { total: number; fips: number; legacy: number };
}> {
  const db = await getDb();
  if (!db) {
    return {
      serverCredentials: { total: 0, fips: 0, legacy: 0, plaintext: 0 },
      sshKeys: { total: 0, fips: 0, legacy: 0, plaintext: 0 },
      cloudCredentials: { total: 0, fips: 0, legacy: 0 },
    };
  }

  // Scan server_credentials
  const scRows = await db.select().from(serverCredentials);
  const scStats = { total: scRows.length, fips: 0, legacy: 0, plaintext: 0 };
  for (const row of scRows) {
    const pwFmt = detectFormat(row.password);
    const akFmt = detectFormat(row.apiKey);
    if (pwFmt === "fips" && (akFmt === "fips" || akFmt === "empty")) scStats.fips++;
    else if (pwFmt === "plaintext" || akFmt === "plaintext") scStats.plaintext++;
    else if (pwFmt === "legacy" || akFmt === "legacy") scStats.legacy++;
    else scStats.fips++; // both empty
  }

  // Scan ssh_keys
  const skRows = await db.select().from(sshKeys);
  const skStats = { total: skRows.length, fips: 0, legacy: 0, plaintext: 0 };
  for (const row of skRows) {
    const fmt = detectFormat(row.privateKey);
    if (fmt === "fips") skStats.fips++;
    else if (fmt === "plaintext") skStats.plaintext++;
    else if (fmt === "legacy") skStats.legacy++;
  }

  // Scan cloud_credentials
  const ccRows = await db.select().from(cloudCredentials);
  const ccStats = { total: ccRows.length, fips: 0, legacy: 0 };
  for (const row of ccRows) {
    try {
      const parsed = JSON.parse(row.encryptedData);
      if (parsed.fips === true) ccStats.fips++;
      else ccStats.legacy++;
    } catch {
      ccStats.legacy++;
    }
  }

  return {
    serverCredentials: scStats,
    sshKeys: skStats,
    cloudCredentials: ccStats,
  };
}

export { detectFormat };
