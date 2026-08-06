/**
 * FIPS 140-3 Cryptographic Policy Module
 * 
 * Centralizes all cryptographic operations to ensure FIPS 140-3 compliance
 * across the platform. All customer-facing data encryption, hashing, and
 * integrity verification MUST use functions from this module.
 * 
 * Reference Standards:
 * - FIPS 140-3 (Cryptographic Module Validation Program)
 * - NIST SP 800-52 Rev. 2 (TLS Guidelines)
 * - NIST SP 800-56A Rev. 3 (Key Establishment)
 * - NIST SP 800-38D (AES-GCM)
 * - NIST SP 800-132 (PBKDF)
 * 
 * Approved Algorithms:
 * - Encryption: AES-256-GCM (primary), AES-128-GCM (acceptable)
 * - Hashing: SHA-256 (minimum), SHA-384 (preferred), SHA-512, SHA-3
 * - HMAC: HMAC-SHA-256 (minimum), HMAC-SHA-384 (preferred)
 * - Key Exchange: ECDHE with NIST P-256/P-384
 * - Signatures: ECDSA (FIPS 186-5), RSA ≥ 2048-bit
 * - KDF: HKDF (SP 800-56C)
 */

import crypto from "crypto";

// ─── FIPS Policy Constants ─────────────────────────────────────────────────────

export const FIPS_POLICY = {
  version: "FIPS-140-3",
  lastUpdated: "2026-05-16",
  
  // Approved symmetric encryption
  encryption: {
    primary: "aes-256-gcm" as const,
    acceptable: ["aes-256-gcm", "aes-128-gcm", "aes-256-ccm", "aes-128-ccm"] as const,
    prohibited: ["des", "3des", "rc4", "blowfish", "aes-256-cbc", "aes-128-cbc", "chacha20-poly1305"] as const,
    keyLengthBits: 256,
    ivLengthBytes: 12, // 96-bit IV for GCM (NIST SP 800-38D)
    tagLengthBytes: 16, // 128-bit auth tag for GCM
  },
  
  // Approved hash algorithms
  hashing: {
    primary: "sha384" as const,
    minimum: "sha256" as const,
    approved: ["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"] as const,
    prohibited: ["md5", "sha1", "ripemd160"] as const,
  },
  
  // Approved HMAC algorithms
  hmac: {
    primary: "sha384" as const,
    minimum: "sha256" as const,
    approved: ["sha256", "sha384", "sha512"] as const,
  },
  
  // TLS requirements (NIST SP 800-52 Rev. 2)
  tls: {
    minimumVersion: "TLSv1.2" as const,
    preferredVersion: "TLSv1.3" as const,
    prohibited: ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"] as const,
    preferredCipherSuites: [
      // TLS 1.3 (all FIPS-approved)
      "TLS_AES_256_GCM_SHA384",
      "TLS_AES_128_GCM_SHA256",
      // TLS 1.2 ECDHE (forward secrecy + AEAD)
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      // TLS 1.2 DHE (forward secrecy + AEAD)
      "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    ] as const,
  },
  
  // Key requirements
  keys: {
    minimumRsaBits: 2048,
    preferredRsaBits: 4096,
    approvedEcCurves: ["P-256", "P-384", "P-521"] as const,
    preferredEcCurve: "P-384" as const,
    minimumDhBits: 2048,
  },
  
  // CSPRNG requirements
  random: {
    source: "crypto.randomBytes" as const, // Uses OS CSPRNG
    minimumEntropyBits: 256,
  },
} as const;

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface EncryptedPayload {
  ciphertext: string;  // Base64-encoded
  iv: string;          // Base64-encoded, 96-bit
  tag: string;         // Base64-encoded, 128-bit auth tag
  algorithm: string;   // Always "aes-256-gcm"
  keyId: string;       // Key identifier for rotation
  timestamp: number;   // UTC ms when encrypted
}

export interface IntegrityRecord {
  hash: string;        // Hex-encoded hash
  algorithm: string;   // Hash algorithm used
  timestamp: number;   // UTC ms when computed
  dataLength: number;  // Original data length in bytes
}

export interface HmacRecord {
  mac: string;         // Hex-encoded HMAC
  algorithm: string;   // HMAC algorithm used
  keyId: string;       // Key identifier
  timestamp: number;   // UTC ms when computed
}

export interface CryptoAuditEntry {
  operation: "encrypt" | "decrypt" | "hash" | "hmac" | "sign" | "verify" | "key_derive" | "random";
  algorithm: string;
  timestamp: number;
  success: boolean;
  dataLengthBytes?: number;
  keyId?: string;
  errorMessage?: string;
  context?: string;    // e.g., "roe_document_upload", "customer_communication"
}

// ─── Audit Log ─────────────────────────────────────────────────────────────────

const auditLog: CryptoAuditEntry[] = [];
const MAX_AUDIT_ENTRIES = 10000;

function logCryptoOperation(entry: CryptoAuditEntry): void {
  auditLog.push(entry);
  if (auditLog.length > MAX_AUDIT_ENTRIES) {
    auditLog.splice(0, auditLog.length - MAX_AUDIT_ENTRIES);
  }
}

export function getCryptoAuditLog(limit = 100): CryptoAuditEntry[] {
  return auditLog.slice(-limit);
}

export function getCryptoAuditStats(): {
  totalOperations: number;
  byOperation: Record<string, number>;
  failureCount: number;
  lastOperation: CryptoAuditEntry | null;
} {
  const byOperation: Record<string, number> = {};
  let failureCount = 0;
  for (const entry of auditLog) {
    byOperation[entry.operation] = (byOperation[entry.operation] || 0) + 1;
    if (!entry.success) failureCount++;
  }
  return {
    totalOperations: auditLog.length,
    byOperation,
    failureCount,
    lastOperation: auditLog.length > 0 ? auditLog[auditLog.length - 1] : null,
  };
}

// ─── CSPRNG ────────────────────────────────────────────────────────────────────

/** Generate cryptographically secure random bytes (FIPS-approved CSPRNG) */
export function secureRandomBytes(length: number): Buffer {
  if (length < 1 || length > 65536) {
    throw new Error(`[FIPS] Invalid random byte length: ${length}. Must be 1-65536.`);
  }
  const bytes = crypto.randomBytes(length);
  logCryptoOperation({
    operation: "random",
    algorithm: "CSPRNG",
    timestamp: Date.now(),
    success: true,
    dataLengthBytes: length,
  });
  return bytes;
}

/** Generate a random hex string of specified byte length */
export function secureRandomHex(byteLength: number): string {
  return secureRandomBytes(byteLength).toString("hex");
}

/** Generate a URL-safe random token */
export function secureRandomToken(byteLength = 32): string {
  return secureRandomBytes(byteLength).toString("base64url");
}

// ─── Hashing (SHA-256 / SHA-384 / SHA-512) ─────────────────────────────────────

/** 
 * Compute a FIPS-approved hash digest.
 * Default: SHA-384 (preferred). Minimum: SHA-256.
 */
export function fipsHash(
  data: string | Buffer,
  algorithm: "sha256" | "sha384" | "sha512" | "sha3-256" | "sha3-384" | "sha3-512" = "sha384"
): IntegrityRecord {
  if (!FIPS_POLICY.hashing.approved.includes(algorithm)) {
    throw new Error(`[FIPS] Hash algorithm "${algorithm}" is not approved.`);
  }
  
  const dataBuffer = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  
  try {
    const hash = crypto.createHash(algorithm).update(dataBuffer).digest("hex");
    
    const record: IntegrityRecord = {
      hash,
      algorithm,
      timestamp: Date.now(),
      dataLength: dataBuffer.length,
    };
    
    logCryptoOperation({
      operation: "hash",
      algorithm,
      timestamp: record.timestamp,
      success: true,
      dataLengthBytes: dataBuffer.length,
    });
    
    return record;
  } catch (err: any) {
    logCryptoOperation({
      operation: "hash",
      algorithm,
      timestamp: Date.now(),
      success: false,
      errorMessage: err.message,
    });
    throw new Error(`[FIPS] Hash operation failed: ${err.message}`);
  }
}

/** Quick SHA-256 hash returning hex string */
export function sha256(data: string | Buffer): string {
  return fipsHash(data, "sha256").hash;
}

/** Quick SHA-384 hash returning hex string */
export function sha384(data: string | Buffer): string {
  return fipsHash(data, "sha384").hash;
}

// ─── HMAC (HMAC-SHA-256 / HMAC-SHA-384) ────────────────────────────────────────

/**
 * Compute a FIPS-approved HMAC.
 * Default: HMAC-SHA-384 (preferred). Minimum: HMAC-SHA-256.
 */
export function fipsHmac(
  data: string | Buffer,
  key: string | Buffer,
  algorithm: "sha256" | "sha384" | "sha512" = "sha384",
  keyId = "default"
): HmacRecord {
  if (!FIPS_POLICY.hmac.approved.includes(algorithm)) {
    throw new Error(`[FIPS] HMAC algorithm "${algorithm}" is not approved.`);
  }
  
  const keyBuffer = typeof key === "string" ? Buffer.from(key, "utf-8") : key;
  const dataBuffer = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  
  // FIPS requires minimum key length equal to hash output length
  const minKeyLength = algorithm === "sha256" ? 32 : algorithm === "sha384" ? 48 : 64;
  if (keyBuffer.length < minKeyLength) {
    console.warn(`[FIPS] HMAC key length (${keyBuffer.length}) is below recommended minimum (${minKeyLength}) for ${algorithm}`);
  }
  
  try {
    const mac = crypto.createHmac(algorithm, keyBuffer).update(dataBuffer).digest("hex");
    
    const record: HmacRecord = {
      mac,
      algorithm: `hmac-${algorithm}`,
      keyId,
      timestamp: Date.now(),
    };
    
    logCryptoOperation({
      operation: "hmac",
      algorithm: `hmac-${algorithm}`,
      timestamp: record.timestamp,
      success: true,
      dataLengthBytes: dataBuffer.length,
      keyId,
    });
    
    return record;
  } catch (err: any) {
    logCryptoOperation({
      operation: "hmac",
      algorithm: `hmac-${algorithm}`,
      timestamp: Date.now(),
      success: false,
      keyId,
      errorMessage: err.message,
    });
    throw new Error(`[FIPS] HMAC operation failed: ${err.message}`);
  }
}

/** Verify an HMAC against expected value (constant-time comparison) */
export function fipsHmacVerify(
  data: string | Buffer,
  key: string | Buffer,
  expectedMac: string,
  algorithm: "sha256" | "sha384" | "sha512" = "sha384"
): boolean {
  const computed = fipsHmac(data, key, algorithm);
  const expectedBuffer = Buffer.from(expectedMac, "hex");
  const computedBuffer = Buffer.from(computed.mac, "hex");
  
  if (expectedBuffer.length !== computedBuffer.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(computedBuffer, expectedBuffer);
}

// ─── AES-256-GCM Encryption ────────────────────────────────────────────────────

/**
 * Encrypt data using AES-256-GCM (FIPS 140-3 approved).
 * 
 * Uses a 96-bit random IV (NIST SP 800-38D recommendation) and
 * produces a 128-bit authentication tag for integrity verification.
 */
export function fipsEncrypt(
  plaintext: string | Buffer,
  key: Buffer,
  keyId = "default",
  aad?: Buffer, // Additional Authenticated Data
  context?: string
): EncryptedPayload {
  // Validate key length (256 bits = 32 bytes)
  if (key.length !== 32) {
    throw new Error(`[FIPS] AES-256-GCM requires a 256-bit (32-byte) key. Got ${key.length} bytes.`);
  }
  
  const iv = secureRandomBytes(FIPS_POLICY.encryption.ivLengthBytes);
  const plaintextBuffer = typeof plaintext === "string" ? Buffer.from(plaintext, "utf-8") : plaintext;
  
  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
      authTagLength: FIPS_POLICY.encryption.tagLengthBytes,
    });
    
    if (aad) {
      cipher.setAAD(aad);
    }
    
    const encrypted = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
    const tag = cipher.getAuthTag();
    
    const payload: EncryptedPayload = {
      ciphertext: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
      algorithm: "aes-256-gcm",
      keyId,
      timestamp: Date.now(),
    };
    
    logCryptoOperation({
      operation: "encrypt",
      algorithm: "aes-256-gcm",
      timestamp: payload.timestamp,
      success: true,
      dataLengthBytes: plaintextBuffer.length,
      keyId,
      context,
    });
    
    return payload;
  } catch (err: any) {
    logCryptoOperation({
      operation: "encrypt",
      algorithm: "aes-256-gcm",
      timestamp: Date.now(),
      success: false,
      keyId,
      errorMessage: err.message,
      context,
    });
    throw new Error(`[FIPS] Encryption failed: ${err.message}`);
  }
}

/**
 * Decrypt data using AES-256-GCM (FIPS 140-3 approved).
 * Verifies the authentication tag to ensure integrity.
 */
export function fipsDecrypt(
  payload: EncryptedPayload,
  key: Buffer,
  aad?: Buffer,
  context?: string
): Buffer {
  if (payload.algorithm !== "aes-256-gcm") {
    throw new Error(`[FIPS] Unsupported decryption algorithm: ${payload.algorithm}. Only aes-256-gcm is approved.`);
  }
  
  if (key.length !== 32) {
    throw new Error(`[FIPS] AES-256-GCM requires a 256-bit (32-byte) key. Got ${key.length} bytes.`);
  }
  
  const iv = Buffer.from(payload.iv, "base64");
  const ciphertext = Buffer.from(payload.ciphertext, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, {
      authTagLength: FIPS_POLICY.encryption.tagLengthBytes,
    });
    
    decipher.setAuthTag(tag);
    
    if (aad) {
      decipher.setAAD(aad);
    }
    
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    
    logCryptoOperation({
      operation: "decrypt",
      algorithm: "aes-256-gcm",
      timestamp: Date.now(),
      success: true,
      dataLengthBytes: decrypted.length,
      keyId: payload.keyId,
      context,
    });
    
    return decrypted;
  } catch (err: any) {
    logCryptoOperation({
      operation: "decrypt",
      algorithm: "aes-256-gcm",
      timestamp: Date.now(),
      success: false,
      keyId: payload.keyId,
      errorMessage: err.message,
      context,
    });
    throw new Error(`[FIPS] Decryption failed (authentication tag mismatch or corrupted data): ${err.message}`);
  }
}

// ─── Key Derivation (HKDF — SP 800-56C) ────────────────────────────────────────

/**
 * Derive a key using HKDF (FIPS-approved per SP 800-56C).
 * Returns a Promise that resolves to the derived key buffer.
 */
export function fipsKeyDerive(
  ikm: string | Buffer,
  salt: string | Buffer,
  info: string,
  keyLengthBytes = 32,
  algorithm: "sha256" | "sha384" | "sha512" = "sha384"
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const ikmBuffer = typeof ikm === "string" ? Buffer.from(ikm, "utf-8") : ikm;
    const saltBuffer = typeof salt === "string" ? Buffer.from(salt, "utf-8") : salt;
    
    crypto.hkdf(algorithm, ikmBuffer, saltBuffer, info, keyLengthBytes, (err, derivedKey) => {
      if (err) {
        logCryptoOperation({
          operation: "key_derive",
          algorithm: `hkdf-${algorithm}`,
          timestamp: Date.now(),
          success: false,
          errorMessage: err.message,
        });
        reject(new Error(`[FIPS] Key derivation failed: ${err.message}`));
      } else {
        logCryptoOperation({
          operation: "key_derive",
          algorithm: `hkdf-${algorithm}`,
          timestamp: Date.now(),
          success: true,
          dataLengthBytes: keyLengthBytes,
        });
        resolve(Buffer.from(derivedKey));
      }
    });
  });
}

// ─── Document Encryption Helpers ────────────────────────────────────────────────

/**
 * Encrypt a document (ROE, report, etc.) for secure storage.
 * Uses AES-256-GCM with the document ID as AAD for binding.
 */
export function encryptDocument(
  documentContent: string | Buffer,
  encryptionKey: Buffer,
  documentId: string,
  keyId = "doc-key-v1"
): EncryptedPayload {
  const aad = Buffer.from(documentId, "utf-8");
  return fipsEncrypt(documentContent, encryptionKey, keyId, aad, `document:${documentId}`);
}

/**
 * Decrypt a document from secure storage.
 */
export function decryptDocument(
  payload: EncryptedPayload,
  encryptionKey: Buffer,
  documentId: string
): Buffer {
  const aad = Buffer.from(documentId, "utf-8");
  return fipsDecrypt(payload, encryptionKey, aad, `document:${documentId}`);
}

/**
 * Compute integrity hash for a document (for tamper detection).
 */
export function computeDocumentIntegrity(
  documentContent: string | Buffer,
  documentId: string
): IntegrityRecord {
  const combined = typeof documentContent === "string"
    ? `${documentId}:${documentContent}`
    : Buffer.concat([Buffer.from(`${documentId}:`), documentContent]);
  return fipsHash(combined, "sha384");
}

// ─── FIPS Compliance Validation ─────────────────────────────────────────────────

export interface FipsComplianceCheck {
  category: string;
  check: string;
  status: "pass" | "fail" | "warning" | "info";
  detail: string;
  standard: string;
}

/**
 * Run a comprehensive FIPS 140-3 compliance check on the current environment.
 */
export function runFipsComplianceChecks(): FipsComplianceCheck[] {
  const checks: FipsComplianceCheck[] = [];
  
  // 1. Check Node.js crypto availability
  try {
    crypto.randomBytes(32);
    checks.push({
      category: "CSPRNG",
      check: "Cryptographically secure random number generator",
      status: "pass",
      detail: "crypto.randomBytes() operational (OS CSPRNG)",
      standard: "FIPS 140-3 §4.9",
    });
  } catch {
    checks.push({
      category: "CSPRNG",
      check: "Cryptographically secure random number generator",
      status: "fail",
      detail: "crypto.randomBytes() not available",
      standard: "FIPS 140-3 §4.9",
    });
  }
  
  // 2. Check AES-256-GCM availability
  const ciphers = crypto.getCiphers();
  if (ciphers.includes("aes-256-gcm")) {
    checks.push({
      category: "Encryption",
      check: "AES-256-GCM availability",
      status: "pass",
      detail: "AES-256-GCM cipher available in OpenSSL",
      standard: "NIST SP 800-38D",
    });
  } else {
    checks.push({
      category: "Encryption",
      check: "AES-256-GCM availability",
      status: "fail",
      detail: "AES-256-GCM not available — FIPS encryption impossible",
      standard: "NIST SP 800-38D",
    });
  }
  
  // 3. Check SHA-384 availability
  const hashes = crypto.getHashes();
  for (const algo of ["sha256", "sha384", "sha512"] as const) {
    checks.push({
      category: "Hashing",
      check: `${algo.toUpperCase()} availability`,
      status: hashes.includes(algo) ? "pass" : "fail",
      detail: hashes.includes(algo) ? `${algo} available` : `${algo} not available`,
      standard: "FIPS 180-4",
    });
  }
  
  // 4. Check HKDF availability
  try {
    checks.push({
      category: "Key Derivation",
      check: "HKDF availability",
      status: typeof crypto.hkdf === "function" ? "pass" : "fail",
      detail: typeof crypto.hkdf === "function" ? "HKDF function available" : "HKDF not available",
      standard: "NIST SP 800-56C",
    });
  } catch {
    checks.push({
      category: "Key Derivation",
      check: "HKDF availability",
      status: "fail",
      detail: "HKDF check failed",
      standard: "NIST SP 800-56C",
    });
  }
  
  // 5. Check for prohibited algorithms (ensure they're not in use)
  for (const prohibited of FIPS_POLICY.hashing.prohibited) {
    const available = hashes.includes(prohibited);
    checks.push({
      category: "Prohibited Algorithms",
      check: `${prohibited.toUpperCase()} not in use`,
      status: "info",
      detail: available
        ? `${prohibited} is available in OpenSSL but MUST NOT be used for FIPS operations`
        : `${prohibited} not available (good)`,
      standard: "FIPS 140-3 §4.2",
    });
  }
  
  // 6. OpenSSL version check
  const opensslVersion = crypto.constants?.OPENSSL_VERSION_TEXT || process.versions.openssl || "unknown";
  checks.push({
    category: "Cryptographic Module",
    check: "OpenSSL version",
    status: "info",
    detail: `OpenSSL version: ${opensslVersion}`,
    standard: "FIPS 140-3",
  });
  
  // 7. Check timing-safe comparison availability
  checks.push({
    category: "Side-Channel Protection",
    check: "Timing-safe comparison",
    status: typeof crypto.timingSafeEqual === "function" ? "pass" : "fail",
    detail: typeof crypto.timingSafeEqual === "function"
      ? "crypto.timingSafeEqual() available for constant-time comparisons"
      : "Timing-safe comparison not available — vulnerable to timing attacks",
    standard: "FIPS 140-3 §4.5",
  });
  
  return checks;
}

// ─── Security Headers ──────────────────────────────────────────────────────────

/**
 * FIPS 140-3 compliant security headers for all HTTP responses.
 * Implements NIST SP 800-52 Rev. 2 and OWASP recommendations.
 */
export const FIPS_SECURITY_HEADERS = {
  // Force HTTPS for 2 years with subdomains and preload
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  
  // Prevent MIME type sniffing
  "X-Content-Type-Options": "nosniff",
  
  // Prevent clickjacking
  "X-Frame-Options": "DENY",
  
  // Disable XSS auditor (CSP handles this now)
  "X-XSS-Protection": "0",
  
  // Control referrer information
  "Referrer-Policy": "strict-origin-when-cross-origin",
  
  // Restrict browser features
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
  
  // Prevent caching of sensitive data
  "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
  "Pragma": "no-cache",
  
  // Cross-origin isolation
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
} as const;

/**
 * Generate Content-Security-Policy header value.
 * Strict CSP that blocks inline scripts and styles by default.
 */
export function generateCSP(nonce?: string): string {
  const scriptSrc = nonce
    ? `'nonce-${nonce}' 'strict-dynamic'`
    : "'self'";
  
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https: blob:",
    "connect-src 'self' https:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "upgrade-insecure-requests",
  ].join("; ");
}

// ─── TLS Validation ─────────────────────────────────────────────────────────────

export interface TlsValidationResult {
  compliant: boolean;
  version: string;
  cipherSuite: string;
  issues: string[];
  recommendations: string[];
}

/**
 * Validate that a TLS connection meets FIPS 140-3 requirements.
 * Call this with the TLS socket info from an incoming request.
 */
export function validateTlsConnection(tlsInfo: {
  version?: string;
  cipher?: { name: string; version: string; standardName?: string };
}): TlsValidationResult {
  const issues: string[] = [];
  const recommendations: string[] = [];
  const version = tlsInfo.version || "unknown";
  const cipherName = tlsInfo.cipher?.standardName || tlsInfo.cipher?.name || "unknown";
  
  // Check TLS version
  if (version === "TLSv1.3") {
    // TLS 1.3 — all cipher suites are FIPS-approved
  } else if (version === "TLSv1.2") {
    recommendations.push("Consider upgrading to TLS 1.3 for improved security");
  } else if (["TLSv1.1", "TLSv1", "SSLv3", "SSLv2"].includes(version)) {
    issues.push(`Prohibited TLS version: ${version}. Minimum required: TLS 1.2`);
  }
  
  // Check cipher suite against approved list
  const isApprovedCipher = FIPS_POLICY.tls.preferredCipherSuites.some(
    suite => cipherName.includes(suite) || suite.includes(cipherName)
  );
  
  if (!isApprovedCipher && cipherName !== "unknown") {
    // Check for known non-FIPS ciphers
    if (cipherName.includes("RC4") || cipherName.includes("DES") || cipherName.includes("NULL")) {
      issues.push(`Prohibited cipher suite: ${cipherName}`);
    } else if (cipherName.includes("CBC")) {
      recommendations.push(`CBC cipher detected (${cipherName}). Prefer GCM or CCM modes.`);
    }
  }
  
  return {
    compliant: issues.length === 0,
    version,
    cipherSuite: cipherName,
    issues,
    recommendations,
  };
}

// ─── Export Policy Summary ──────────────────────────────────────────────────────

export function getFipsPolicySummary(): {
  version: string;
  lastUpdated: string;
  encryption: string;
  hashing: string;
  hmac: string;
  tlsMinimum: string;
  keyExchange: string;
  complianceChecks: FipsComplianceCheck[];
} {
  return {
    version: FIPS_POLICY.version,
    lastUpdated: FIPS_POLICY.lastUpdated,
    encryption: `${FIPS_POLICY.encryption.primary} (${FIPS_POLICY.encryption.keyLengthBits}-bit key, ${FIPS_POLICY.encryption.ivLengthBytes * 8}-bit IV, ${FIPS_POLICY.encryption.tagLengthBytes * 8}-bit auth tag)`,
    hashing: `${FIPS_POLICY.hashing.primary} (preferred), ${FIPS_POLICY.hashing.minimum} (minimum)`,
    hmac: `HMAC-${FIPS_POLICY.hmac.primary} (preferred), HMAC-${FIPS_POLICY.hmac.minimum} (minimum)`,
    tlsMinimum: FIPS_POLICY.tls.minimumVersion,
    keyExchange: `ECDHE with ${FIPS_POLICY.keys.approvedEcCurves.join("/")} curves`,
    complianceChecks: runFipsComplianceChecks(),
  };
}
