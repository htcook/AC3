/**
 * FIPS 140-3 Cryptographic Service
 *
 * Platform-wide cryptographic operations using FIPS-validated algorithms.
 * All operations route through OpenSSL 3.x FIPS provider when available,
 * with runtime validation that only approved algorithms are in use.
 *
 * Approved algorithms:
 *   Symmetric:  AES-256-GCM, AES-128-GCM
 *   Hash:       SHA-256, SHA-384, SHA-512
 *   MAC:        HMAC-SHA256, HMAC-SHA384
 *   Signature:  ECDSA P-256 (ES256), ECDSA P-384 (ES384), RSA-2048+
 *   KDF:        HKDF-SHA256, PBKDF2-HMAC-SHA256
 *   Random:     CTR_DRBG (via crypto.randomBytes)
 *
 * Prohibited: MD5, SHA-1 (signatures), DES, 3DES, RC4, Blowfish, RSA < 2048
 */

import crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
  algorithm: "aes-256-gcm";
  keyDerivation: "hkdf-sha256" | "direct";
}

export interface PasswordHash {
  hash: string;
  salt: string;
  iterations: number;
  algorithm: "pbkdf2-sha256";
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
  curve: "P-256" | "P-384";
}

export interface FIPSComplianceReport {
  fipsProviderActive: boolean;
  opensslVersion: string;
  nodeVersion: string;
  approvedAlgorithms: {
    symmetric: string[];
    hash: string[];
    mac: string[];
    signature: string[];
    kdf: string[];
    random: string[];
  };
  prohibitedAlgorithms: string[];
  tlsCiphers: { tls12: string; tls13: string };
  complianceLevel: "full" | "partial" | "software-only";
  timestamp: number;
}

export interface AuditChainEntry {
  recordHash: string;
  previousHash: string;
}

// ─── Constants ────────────────────────────────────────────────────────────

/** FIPS-approved TLS 1.2 cipher suites */
const FIPS_TLS12_CIPHERS = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
].join(":");

/** FIPS-approved TLS 1.3 cipher suites */
const FIPS_TLS13_CIPHERS = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
].join(":");

/** Algorithms explicitly prohibited under FIPS 140-3 */
const PROHIBITED_ALGORITHMS = [
  "md5",
  "sha1",
  "des",
  "des-ede3",
  "des3",
  "rc4",
  "blowfish",
  "bf",
  "rc2",
] as const;

/** PBKDF2 iterations — OWASP 2023 recommendation for SHA-256 */
const PBKDF2_ITERATIONS = 600_000;

/** AES-256-GCM IV length (96 bits per NIST SP 800-38D) */
const GCM_IV_LENGTH = 12;

/** AES-256-GCM auth tag length (128 bits) */
const GCM_TAG_LENGTH = 16;

// ─── Service ──────────────────────────────────────────────────────────────

export class FIPSCryptoService {
  private masterKey: Buffer;
  private fipsEnabled: boolean;

  constructor(masterKeyHex?: string) {
    this.fipsEnabled = this.detectFIPSMode();

    if (masterKeyHex) {
      const keyBuf = Buffer.from(masterKeyHex, "hex");
      if (keyBuf.length !== 32) {
        throw new Error("Master key must be exactly 32 bytes (256 bits) for AES-256");
      }
      this.masterKey = keyBuf;
    } else {
      // Generate a random master key (for dev/test; production should inject via env)
      this.masterKey = crypto.randomBytes(32);
    }
  }

  // ─── FIPS Mode Detection ──────────────────────────────────────────────

  /** Check if the OpenSSL FIPS provider is active */
  detectFIPSMode(): boolean {
    try {
      return crypto.getFips() === 1;
    } catch {
      return false;
    }
  }

  /** Whether FIPS provider is active */
  get isFIPSEnabled(): boolean {
    return this.fipsEnabled;
  }

  // ─── Compliance Reporting ─────────────────────────────────────────────

  /** Generate a comprehensive FIPS compliance report */
  getComplianceReport(): FIPSComplianceReport {
    return {
      fipsProviderActive: this.fipsEnabled,
      opensslVersion: (crypto as any).constants?.OPENSSL_VERSION_TEXT ?? process.versions.openssl ?? "unknown",
      nodeVersion: process.version,
      approvedAlgorithms: {
        symmetric: ["aes-256-gcm", "aes-128-gcm"],
        hash: ["sha256", "sha384", "sha512"],
        mac: ["hmac-sha256", "hmac-sha384"],
        signature: ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"],
        kdf: ["hkdf-sha256", "pbkdf2-sha256"],
        random: ["ctr-drbg"],
      },
      prohibitedAlgorithms: [...PROHIBITED_ALGORITHMS],
      tlsCiphers: {
        tls12: FIPS_TLS12_CIPHERS,
        tls13: FIPS_TLS13_CIPHERS,
      },
      complianceLevel: this.fipsEnabled ? "full" : "software-only",
      timestamp: Date.now(),
    };
  }

  /** Validate that a given algorithm name is FIPS-approved */
  isApprovedAlgorithm(algorithm: string): boolean {
    const lower = algorithm.toLowerCase();
    return !PROHIBITED_ALGORITHMS.some((p) => lower.includes(p));
  }

  // ─── Symmetric Encryption (AES-256-GCM) ──────────────────────────────

  /** Encrypt data using AES-256-GCM */
  encrypt(plaintext: Buffer | string, context?: string): EncryptedPayload {
    const iv = crypto.randomBytes(GCM_IV_LENGTH);
    const key = context ? this.deriveKey(this.masterKey, context) : this.masterKey;

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
      authTagLength: GCM_TAG_LENGTH,
    });
    const input = typeof plaintext === "string" ? Buffer.from(plaintext, "utf-8") : plaintext;
    const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertext: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      algorithm: "aes-256-gcm",
      keyDerivation: context ? "hkdf-sha256" : "direct",
    };
  }

  /** Decrypt AES-256-GCM encrypted payload */
  decrypt(payload: EncryptedPayload, context?: string): Buffer {
    if (payload.algorithm !== "aes-256-gcm") {
      throw new Error(`Unsupported algorithm: ${payload.algorithm}. Only aes-256-gcm is approved.`);
    }

    const key = context ? this.deriveKey(this.masterKey, context) : this.masterKey;
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(payload.iv, "base64"),
      { authTagLength: GCM_TAG_LENGTH }
    );
    decipher.setAuthTag(Buffer.from(payload.authTag, "base64"));

    return Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, "base64")),
      decipher.final(),
    ]);
  }

  // ─── Key Derivation (HKDF-SHA256) ────────────────────────────────────

  /** Derive a key using HKDF (RFC 5869) with SHA-256 */
  deriveKey(ikm: Buffer, info: string, length: number = 32): Buffer {
    return Buffer.from(crypto.hkdfSync("sha256", ikm, Buffer.alloc(0), info, length));
  }

  // ─── Digital Signatures (ECDSA) ──────────────────────────────────────

  /** Generate an ECDSA key pair */
  generateKeyPair(curve: "P-256" | "P-384" = "P-256"): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: curve,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return { publicKey, privateKey, curve };
  }

  /** Sign data with ECDSA + SHA-256 */
  sign(data: Buffer | string, privateKeyPem: string): string {
    const signer = crypto.createSign("SHA256");
    signer.update(typeof data === "string" ? data : data);
    signer.end();
    return signer.sign(privateKeyPem, "base64");
  }

  /** Verify an ECDSA + SHA-256 signature */
  verify(data: Buffer | string, signature: string, publicKeyPem: string): boolean {
    const verifier = crypto.createVerify("SHA256");
    verifier.update(typeof data === "string" ? data : data);
    verifier.end();
    return verifier.verify(publicKeyPem, signature, "base64");
  }

  // ─── HMAC (SHA-256) ──────────────────────────────────────────────────

  /** Compute HMAC-SHA256 */
  hmac(data: Buffer | string, key?: Buffer): string {
    const hmacKey = key ?? this.masterKey;
    return crypto
      .createHmac("sha256", hmacKey)
      .update(typeof data === "string" ? data : data)
      .digest("hex");
  }

  /** Verify HMAC-SHA256 using timing-safe comparison */
  verifyHmac(data: Buffer | string, expectedHmac: string, key?: Buffer): boolean {
    const computed = this.hmac(data, key);
    try {
      return crypto.timingSafeEqual(
        Buffer.from(computed, "hex"),
        Buffer.from(expectedHmac, "hex")
      );
    } catch {
      return false;
    }
  }

  // ─── Hashing (SHA-256/384/512) ────────────────────────────────────────

  /** Compute SHA hash */
  hash(data: Buffer | string, algorithm: "sha256" | "sha384" | "sha512" = "sha256"): string {
    return crypto
      .createHash(algorithm)
      .update(typeof data === "string" ? data : data)
      .digest("hex");
  }

  // ─── Password Hashing (PBKDF2-HMAC-SHA256) ───────────────────────────

  /** Hash a password using PBKDF2-HMAC-SHA256 (FIPS-validated) */
  hashPassword(password: string): PasswordHash {
    const salt = crypto.randomBytes(32);
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 64, "sha256");
    return {
      hash: hash.toString("base64"),
      salt: salt.toString("base64"),
      iterations: PBKDF2_ITERATIONS,
      algorithm: "pbkdf2-sha256",
    };
  }

  /** Verify a password against a stored PBKDF2 hash */
  verifyPassword(password: string, stored: PasswordHash): boolean {
    const hash = crypto.pbkdf2Sync(
      password,
      Buffer.from(stored.salt, "base64"),
      stored.iterations,
      64,
      "sha256"
    );
    try {
      return crypto.timingSafeEqual(hash, Buffer.from(stored.hash, "base64"));
    } catch {
      return false;
    }
  }

  // ─── Secure Random ────────────────────────────────────────────────────

  /** Generate cryptographically secure random bytes */
  randomBytes(length: number): Buffer {
    return crypto.randomBytes(length);
  }

  /** Generate a UUID v4 */
  uuid(): string {
    return crypto.randomUUID();
  }

  // ─── JWT (ECDSA ES256) ────────────────────────────────────────────────

  /** Create a JWT signed with ECDSA P-256 (ES256) */
  createJWT(
    payload: Record<string, unknown>,
    privateKeyPem: string,
    expiresInSeconds: number = 3600
  ): string {
    const header = { alg: "ES256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);
    const fullPayload = { ...payload, iat: now, exp: now + expiresInSeconds };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
    const signingInput = `${headerB64}.${payloadB64}`;

    const sig = this.sign(signingInput, privateKeyPem);
    const sigB64 = Buffer.from(sig, "base64").toString("base64url");

    return `${signingInput}.${sigB64}`;
  }

  /** Verify and decode a JWT */
  verifyJWT(token: string, publicKeyPem: string): { valid: boolean; payload?: Record<string, unknown>; error?: string } {
    const parts = token.split(".");
    if (parts.length !== 3) return { valid: false, error: "Invalid JWT format" };

    const [headerB64, payloadB64, sigB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = Buffer.from(sigB64, "base64url").toString("base64");

    if (!this.verify(signingInput, signature, publicKeyPem)) {
      return { valid: false, error: "Invalid signature" };
    }

    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { valid: false, error: "Token expired" };
    }

    return { valid: true, payload };
  }

  // ─── Audit Log Integrity Chain ────────────────────────────────────────

  /** Create a chained HMAC for audit log tamper detection */
  chainAuditRecord(record: string, previousHash: string): AuditChainEntry {
    const recordHash = this.hmac(`${previousHash}|${record}`);
    return { recordHash, previousHash };
  }

  /** Verify an audit chain entry */
  verifyAuditChain(record: string, entry: AuditChainEntry): boolean {
    const expected = this.hmac(`${entry.previousHash}|${record}`);
    try {
      return crypto.timingSafeEqual(
        Buffer.from(expected, "hex"),
        Buffer.from(entry.recordHash, "hex")
      );
    } catch {
      return false;
    }
  }
}

// ─── Singleton Instance ───────────────────────────────────────────────────

let _instance: FIPSCryptoService | null = null;

/** Get or create the platform-wide FIPS crypto service singleton */
export function getFIPSCrypto(masterKeyHex?: string): FIPSCryptoService {
  if (!_instance) {
    _instance = new FIPSCryptoService(masterKeyHex);
  }
  return _instance;
}

/** Reset the singleton (for testing) */
export function resetFIPSCrypto(): void {
  _instance = null;
}
