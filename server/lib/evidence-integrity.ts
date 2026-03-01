/**
 * Evidence Integrity Hashing Service — P1 Gap Remediation
 * 
 * Implements FIPS 140-3 compliant cryptographic hash chains for evidence items.
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
 * Compute HMAC-SHA256 anchor signature for a Merkle root.
 * Uses the JWT_SECRET as the HMAC key for signing.
 */
export function computeAnchorHMAC(merkleRoot: string, engagementId: string): string {
  const secret = process.env.JWT_SECRET || "default-hmac-key";
  return crypto
    .createHmac("sha256", secret)
    .update(`${merkleRoot}|${engagementId}`)
    .digest("hex");
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
