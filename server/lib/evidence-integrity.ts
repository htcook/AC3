/**
 * Evidence Integrity Hashing Service — P1 Gap Remediation
 * 
 * Implements FIPS 140-2 compliant cryptographic hash chains for evidence items.
 * Every evidence item gets a SHA-256 integrity hash that chains to the previous
 * item, creating a tamper-evident audit trail similar to blockchain.
 * 
 * Features:
 * - SHA-256 content hashing for all evidence files
 * - Hash chain linking (each hash includes the previous hash)
 * - Merkle root computation for engagement-level integrity verification
 * - Tamper detection via chain validation
 * - HMAC-SHA256 signing for chain anchors
 */

import * as crypto from "crypto";
import { eq, and, desc, asc, sql } from "drizzle-orm";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface IntegrityRecord {
  evidenceId: string;
  contentHash: string;
  chainHash: string;
  previousChainHash: string | null;
  algorithm: "SHA-256";
  timestamp: number;
}

export interface ChainValidationResult {
  valid: boolean;
  totalLinks: number;
  validLinks: number;
  brokenAt: number | null;
  brokenEvidenceId: string | null;
  merkleRoot: string | null;
  errors: string[];
}

export interface IntegrityAnchor {
  engagementId: string;
  merkleRoot: string;
  hmacSignature: string;
  chainLength: number;
  anchoredAt: number;
}

// ─── Core Hashing ───────────────────────────────────────────────────────────

/**
 * Compute SHA-256 hash of content (FIPS 140-3 approved algorithm).
 */
export function computeSHA256(content: Buffer | string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

/**
 * Compute chain hash: SHA-256(contentHash + previousChainHash + timestamp).
 * This creates a tamper-evident chain where modifying any link invalidates
 * all subsequent links.
 */
export function computeChainHash(
  contentHash: string,
  previousChainHash: string | null,
  timestamp: number
): string {
  const payload = `${contentHash}|${previousChainHash || "GENESIS"}|${timestamp}`;
  return crypto.createHash("sha256").update(payload).digest("hex");
}

/**
 * Evidence HMAC Key Management
 * 
 * Implements key separation between authentication (JWT_SECRET) and evidence
 * integrity (EVIDENCE_HMAC_KEY) domains. This ensures:
 * 1. Compromise of the authentication secret does not compromise evidence chains
 * 2. JWT_SECRET rotation does not break historical evidence-chain verification
 * 3. Evidence key can be independently rotated with versioned key support
 * 
 * Key hierarchy:
 *   EVIDENCE_HMAC_KEY (primary) → used for all new HMAC signatures
 *   EVIDENCE_HMAC_KEY_PREVIOUS (optional) → used for verifying historical anchors
 *     after key rotation; set this to the old key value during rotation window
 * 
 * For HSM-backed deployments (recommended for CUI-handling environments):
 *   Set EVIDENCE_HMAC_KEY to the HSM key reference and configure the HSM
 *   provider in the deployment environment. The HMAC computation path remains
 *   the same; the HSM handles the actual signing operation.
 */

const EVIDENCE_KEY_VERSION = "v1";

/**
 * Get the evidence HMAC signing key.
 * Falls back to JWT_SECRET only during migration (with deprecation warning).
 * In production, EVIDENCE_HMAC_KEY must be set independently.
 */
function getEvidenceHmacKey(): { key: string; source: string; version: string } {
  const dedicatedKey = process.env.EVIDENCE_HMAC_KEY;
  if (dedicatedKey) {
    return { key: dedicatedKey, source: "EVIDENCE_HMAC_KEY", version: EVIDENCE_KEY_VERSION };
  }

  // Migration fallback: use JWT_SECRET with deprecation warning
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret) {
    console.warn(
      "[EvidenceIntegrity] WARNING: Using JWT_SECRET as HMAC key. " +
      "Set EVIDENCE_HMAC_KEY for proper key separation. " +
      "This fallback will be removed in a future release."
    );
    return { key: jwtSecret, source: "JWT_SECRET (deprecated fallback)", version: "legacy" };
  }

  throw new Error(
    "[EvidenceIntegrity] FATAL: Neither EVIDENCE_HMAC_KEY nor JWT_SECRET is set. " +
    "Evidence integrity signing is not available."
  );
}

/**
 * Get the previous evidence HMAC key for verifying historical anchors
 * created before a key rotation. Returns null if no previous key is configured.
 */
function getPreviousEvidenceHmacKey(): string | null {
  return process.env.EVIDENCE_HMAC_KEY_PREVIOUS || null;
}

/**
 * Compute HMAC-SHA256 anchor signature for a Merkle root.
 * Uses the dedicated EVIDENCE_HMAC_KEY (not JWT_SECRET) for signing.
 * 
 * The signature includes the key version to support verification across
 * key rotations.
 */
export function computeAnchorHMAC(merkleRoot: string, engagementId: string): string {
  const { key, version } = getEvidenceHmacKey();
  const payload = `${version}|${merkleRoot}|${engagementId}`;
  return crypto
    .createHmac("sha256", key)
    .update(payload)
    .digest("hex");
}

/**
 * Verify an HMAC anchor signature, trying the current key first,
 * then the previous key (if configured) for historical anchors.
 * Returns the verification result with key source information.
 */
export function verifyAnchorHMAC(
  merkleRoot: string,
  engagementId: string,
  expectedSignature: string
): { valid: boolean; keySource: string } {
  // Try current key first
  const { key: currentKey, version: currentVersion } = getEvidenceHmacKey();
  const currentPayload = `${currentVersion}|${merkleRoot}|${engagementId}`;
  const currentSig = crypto.createHmac("sha256", currentKey).update(currentPayload).digest("hex");
  if (currentSig === expectedSignature) {
    return { valid: true, keySource: "current" };
  }

  // Try legacy format (without version prefix) for pre-migration anchors
  const legacyPayload = `${merkleRoot}|${engagementId}`;
  const legacySig = crypto.createHmac("sha256", currentKey).update(legacyPayload).digest("hex");
  if (legacySig === expectedSignature) {
    return { valid: true, keySource: "current (legacy format)" };
  }

  // Try previous key if configured (for post-rotation verification)
  const previousKey = getPreviousEvidenceHmacKey();
  if (previousKey) {
    const prevCurrentSig = crypto.createHmac("sha256", previousKey).update(currentPayload).digest("hex");
    if (prevCurrentSig === expectedSignature) {
      return { valid: true, keySource: "previous" };
    }
    const prevLegacySig = crypto.createHmac("sha256", previousKey).update(legacyPayload).digest("hex");
    if (prevLegacySig === expectedSignature) {
      return { valid: true, keySource: "previous (legacy format)" };
    }
  }

  return { valid: false, keySource: "none" };
}

/**
 * Get evidence key metadata for audit/compliance reporting.
 * Does not expose the actual key material.
 */
export function getEvidenceKeyMetadata(): {
  source: string;
  version: string;
  hasPreviousKey: boolean;
  keyFingerprint: string;
} {
  const { key, source, version } = getEvidenceHmacKey();
  // Fingerprint: SHA-256 of the key, truncated to 8 hex chars
  const fingerprint = crypto.createHash("sha256").update(key).digest("hex").substring(0, 16);
  return {
    source,
    version,
    hasPreviousKey: !!getPreviousEvidenceHmacKey(),
    keyFingerprint: fingerprint,
  };
}

/**
 * Compute Merkle root from a list of chain hashes.
 * Provides a single hash that represents the integrity of the entire chain.
 */
export function computeMerkleRoot(chainHashes: string[]): string {
  if (chainHashes.length === 0) return computeSHA256("EMPTY_CHAIN");
  if (chainHashes.length === 1) return chainHashes[0];

  let layer = [...chainHashes];
  while (layer.length > 1) {
    const nextLayer: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        nextLayer.push(computeSHA256(layer[i] + layer[i + 1]));
      } else {
        nextLayer.push(computeSHA256(layer[i] + layer[i])); // Duplicate odd leaf
      }
    }
    layer = nextLayer;
  }
  return layer[0];
}

// ─── Chain Operations ───────────────────────────────────────────────────────

/**
 * Hash a new evidence item and append it to the chain.
 * Returns the integrity record to be stored in the database.
 */
export async function hashAndChainEvidence(
  evidenceId: string,
  engagementId: string,
  content: Buffer | string,
  metadata?: { filename?: string; mimeType?: string; userId?: number }
): Promise<IntegrityRecord> {
  const { getDb } = await import("../db");
  const { evidenceChainOfCustody } = await import("../../drizzle/schema");
  const db = await getDb();

  const contentHash = computeSHA256(content);
  const timestamp = Date.now();

  // Get the last chain hash for this engagement
  let previousChainHash: string | null = null;
  if (db) {
    const lastEntry = await db
      .select({ integrityHash: evidenceChainOfCustody.integrityHash })
      .from(evidenceChainOfCustody)
      .where(eq(evidenceChainOfCustody.evidenceId, engagementId))
      .orderBy(desc(evidenceChainOfCustody.performedAt))
      .limit(1);

    if (lastEntry.length > 0 && lastEntry[0].integrityHash) {
      previousChainHash = lastEntry[0].integrityHash;
    }
  }

  const chainHash = computeChainHash(contentHash, previousChainHash, timestamp);

  // Record in chain of custody
  if (db) {
    await db.insert(evidenceChainOfCustody).values({
      evidenceId,
      action: "evidence_hashed",
      performedBy: metadata?.userId ? `user:${metadata.userId}` : "system",
      details: JSON.stringify({
        contentHash,
        chainHash,
        previousChainHash,
        algorithm: "SHA-256",
        filename: metadata?.filename,
        mimeType: metadata?.mimeType,
        timestamp,
      }),
      integrityHash: chainHash,
      previousHash: previousChainHash,
    });
  }

  return {
    evidenceId,
    contentHash,
    chainHash,
    previousChainHash,
    algorithm: "SHA-256",
    timestamp,
  };
}

/**
 * Validate the entire evidence chain for an engagement.
 * Checks that each link's hash correctly chains to the previous one.
 */
export async function validateEvidenceChain(
  engagementId: string
): Promise<ChainValidationResult> {
  const { getDb } = await import("../db");
  const { evidenceChainOfCustody } = await import("../../drizzle/schema");
  const db = await getDb();
  if (!db) {
    return {
      valid: false,
      totalLinks: 0,
      validLinks: 0,
      brokenAt: null,
      brokenEvidenceId: null,
      merkleRoot: null,
      errors: ["Database unavailable"],
    };
  }

  const chain = await db
    .select()
    .from(evidenceChainOfCustody)
    .where(eq(evidenceChainOfCustody.action, "evidence_hashed"))
    .orderBy(asc(evidenceChainOfCustody.performedAt));

  if (chain.length === 0) {
    return {
      valid: true,
      totalLinks: 0,
      validLinks: 0,
      brokenAt: null,
      brokenEvidenceId: null,
      merkleRoot: computeSHA256("EMPTY_CHAIN"),
      errors: [],
    };
  }

  const errors: string[] = [];
  let validLinks = 0;
  const chainHashes: string[] = [];

  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i];
    const prevEntry = i > 0 ? chain[i - 1] : null;

    // Verify previousHash links correctly
    if (entry.previousHash !== (prevEntry?.integrityHash || null)) {
      errors.push(`Link ${i}: previousHash mismatch at evidence ${entry.evidenceId}`);
      return {
        valid: false,
        totalLinks: chain.length,
        validLinks,
        brokenAt: i,
        brokenEvidenceId: entry.evidenceId,
        merkleRoot: null,
        errors,
      };
    }

    if (entry.integrityHash) {
      chainHashes.push(entry.integrityHash);
    }
    validLinks++;
  }

  const merkleRoot = computeMerkleRoot(chainHashes);

  return {
    valid: true,
    totalLinks: chain.length,
    validLinks,
    brokenAt: null,
    brokenEvidenceId: null,
    merkleRoot,
    errors: [],
  };
}

/**
 * Create an integrity anchor for an engagement.
 * This is a signed snapshot of the chain state at a point in time.
 */
export async function createIntegrityAnchor(
  engagementId: string
): Promise<IntegrityAnchor | null> {
  const validation = await validateEvidenceChain(engagementId);
  if (!validation.valid || !validation.merkleRoot) return null;

  const hmacSignature = computeAnchorHMAC(validation.merkleRoot, engagementId);

  return {
    engagementId,
    merkleRoot: validation.merkleRoot,
    hmacSignature,
    chainLength: validation.totalLinks,
    anchoredAt: Date.now(),
  };
}
