import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/evidence-integrity.ts
import * as crypto from "crypto";
import { eq, desc, asc } from "drizzle-orm";
function computeSHA256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}
function computeChainHash(contentHash, previousChainHash, timestamp) {
  const payload = `${contentHash}|${previousChainHash || "GENESIS"}|${timestamp}`;
  return crypto.createHash("sha256").update(payload).digest("hex");
}
function getEvidenceHmacKey() {
  const dedicatedKey = process.env.EVIDENCE_HMAC_KEY;
  if (dedicatedKey) {
    return { key: dedicatedKey, source: "EVIDENCE_HMAC_KEY", version: EVIDENCE_KEY_VERSION };
  }
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret) {
    console.warn(
      "[EvidenceIntegrity] WARNING: Using JWT_SECRET as HMAC key. Set EVIDENCE_HMAC_KEY for proper key separation. This fallback will be removed in a future release."
    );
    return { key: jwtSecret, source: "JWT_SECRET (deprecated fallback)", version: "legacy" };
  }
  throw new Error(
    "[EvidenceIntegrity] FATAL: Neither EVIDENCE_HMAC_KEY nor JWT_SECRET is set. Evidence integrity signing is not available."
  );
}
function getPreviousEvidenceHmacKey() {
  return process.env.EVIDENCE_HMAC_KEY_PREVIOUS || null;
}
function computeAnchorHMAC(merkleRoot, engagementId) {
  const { key, version } = getEvidenceHmacKey();
  const payload = `${version}|${merkleRoot}|${engagementId}`;
  return crypto.createHmac("sha256", key).update(payload).digest("hex");
}
function verifyAnchorHMAC(merkleRoot, engagementId, expectedSignature) {
  const { key: currentKey, version: currentVersion } = getEvidenceHmacKey();
  const currentPayload = `${currentVersion}|${merkleRoot}|${engagementId}`;
  const currentSig = crypto.createHmac("sha256", currentKey).update(currentPayload).digest("hex");
  if (currentSig === expectedSignature) {
    return { valid: true, keySource: "current" };
  }
  const legacyPayload = `${merkleRoot}|${engagementId}`;
  const legacySig = crypto.createHmac("sha256", currentKey).update(legacyPayload).digest("hex");
  if (legacySig === expectedSignature) {
    return { valid: true, keySource: "current (legacy format)" };
  }
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
function getEvidenceKeyMetadata() {
  const { key, source, version } = getEvidenceHmacKey();
  const fingerprint = crypto.createHash("sha256").update(key).digest("hex").substring(0, 16);
  return {
    source,
    version,
    hasPreviousKey: !!getPreviousEvidenceHmacKey(),
    keyFingerprint: fingerprint
  };
}
function computeMerkleRoot(chainHashes) {
  if (chainHashes.length === 0) return computeSHA256("EMPTY_CHAIN");
  if (chainHashes.length === 1) return chainHashes[0];
  let layer = [...chainHashes];
  while (layer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        nextLayer.push(computeSHA256(layer[i] + layer[i + 1]));
      } else {
        nextLayer.push(computeSHA256(layer[i] + layer[i]));
      }
    }
    layer = nextLayer;
  }
  return layer[0];
}
async function hashAndChainEvidence(evidenceId, engagementId, content, metadata) {
  const { getDb } = await import("./db-JLHOBMS4.js");
  const { evidenceChainOfCustody } = await import("./schema-TZDA52RN.js");
  const db = await getDb();
  const contentHash = computeSHA256(content);
  const timestamp = Date.now();
  let previousChainHash = null;
  if (db) {
    const lastEntry = await db.select({ integrityHash: evidenceChainOfCustody.integrityHash }).from(evidenceChainOfCustody).where(eq(evidenceChainOfCustody.evidenceId, engagementId)).orderBy(desc(evidenceChainOfCustody.performedAt)).limit(1);
    if (lastEntry.length > 0 && lastEntry[0].integrityHash) {
      previousChainHash = lastEntry[0].integrityHash;
    }
  }
  const chainHash = computeChainHash(contentHash, previousChainHash, timestamp);
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
        timestamp
      }),
      integrityHash: chainHash,
      previousHash: previousChainHash
    });
  }
  return {
    evidenceId,
    contentHash,
    chainHash,
    previousChainHash,
    algorithm: "SHA-256",
    timestamp
  };
}
async function validateEvidenceChain(engagementId) {
  const { getDb } = await import("./db-JLHOBMS4.js");
  const { evidenceChainOfCustody } = await import("./schema-TZDA52RN.js");
  const db = await getDb();
  if (!db) {
    return {
      valid: false,
      totalLinks: 0,
      validLinks: 0,
      brokenAt: null,
      brokenEvidenceId: null,
      merkleRoot: null,
      errors: ["Database unavailable"]
    };
  }
  const chain = await db.select().from(evidenceChainOfCustody).where(eq(evidenceChainOfCustody.action, "evidence_hashed")).orderBy(asc(evidenceChainOfCustody.performedAt));
  if (chain.length === 0) {
    return {
      valid: true,
      totalLinks: 0,
      validLinks: 0,
      brokenAt: null,
      brokenEvidenceId: null,
      merkleRoot: computeSHA256("EMPTY_CHAIN"),
      errors: []
    };
  }
  const errors = [];
  let validLinks = 0;
  const chainHashes = [];
  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i];
    const prevEntry = i > 0 ? chain[i - 1] : null;
    if (entry.previousHash !== (prevEntry?.integrityHash || null)) {
      errors.push(`Link ${i}: previousHash mismatch at evidence ${entry.evidenceId}`);
      return {
        valid: false,
        totalLinks: chain.length,
        validLinks,
        brokenAt: i,
        brokenEvidenceId: entry.evidenceId,
        merkleRoot: null,
        errors
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
    errors: []
  };
}
async function createIntegrityAnchor(engagementId) {
  const validation = await validateEvidenceChain(engagementId);
  if (!validation.valid || !validation.merkleRoot) return null;
  const hmacSignature = computeAnchorHMAC(validation.merkleRoot, engagementId);
  return {
    engagementId,
    merkleRoot: validation.merkleRoot,
    hmacSignature,
    chainLength: validation.totalLinks,
    anchoredAt: Date.now()
  };
}
var EVIDENCE_KEY_VERSION;
var init_evidence_integrity = __esm({
  "server/lib/evidence-integrity.ts"() {
    EVIDENCE_KEY_VERSION = "v1";
  }
});
init_evidence_integrity();
export {
  computeAnchorHMAC,
  computeChainHash,
  computeMerkleRoot,
  computeSHA256,
  createIntegrityAnchor,
  getEvidenceKeyMetadata,
  hashAndChainEvidence,
  validateEvidenceChain,
  verifyAnchorHMAC
};
