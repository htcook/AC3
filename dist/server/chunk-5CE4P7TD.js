// server/lib/fips-crypto.ts
import crypto from "node:crypto";
var FIPS_TLS12_CIPHERS = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256"
].join(":");
var FIPS_TLS13_CIPHERS = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256"
].join(":");
var PROHIBITED_ALGORITHMS = [
  "md5",
  "sha1",
  "des",
  "des-ede3",
  "des3",
  "rc4",
  "blowfish",
  "bf",
  "rc2"
];
var PBKDF2_ITERATIONS = 6e5;
var GCM_IV_LENGTH = 12;
var GCM_TAG_LENGTH = 16;
var FIPSCryptoService = class {
  constructor(masterKeyHex) {
    this.fipsEnabled = this.detectFIPSMode();
    if (masterKeyHex) {
      const keyBuf = Buffer.from(masterKeyHex, "hex");
      if (keyBuf.length !== 32) {
        throw new Error("Master key must be exactly 32 bytes (256 bits) for AES-256");
      }
      this.masterKey = keyBuf;
    } else {
      this.masterKey = crypto.randomBytes(32);
    }
  }
  // ─── FIPS Mode Detection ──────────────────────────────────────────────
  /** Check if the OpenSSL FIPS provider is active */
  detectFIPSMode() {
    try {
      return crypto.getFips() === 1;
    } catch {
      return false;
    }
  }
  /** Whether FIPS provider is active */
  get isFIPSEnabled() {
    return this.fipsEnabled;
  }
  // ─── Compliance Reporting ─────────────────────────────────────────────
  /** Generate a comprehensive FIPS compliance report */
  getComplianceReport() {
    return {
      fipsProviderActive: this.fipsEnabled,
      opensslVersion: crypto.constants?.OPENSSL_VERSION_TEXT ?? process.versions.openssl ?? "unknown",
      nodeVersion: process.version,
      approvedAlgorithms: {
        symmetric: ["aes-256-gcm", "aes-128-gcm"],
        hash: ["sha256", "sha384", "sha512"],
        mac: ["hmac-sha256", "hmac-sha384"],
        signature: ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-4096"],
        kdf: ["hkdf-sha256", "pbkdf2-sha256"],
        random: ["ctr-drbg"]
      },
      prohibitedAlgorithms: [...PROHIBITED_ALGORITHMS],
      tlsCiphers: {
        tls12: FIPS_TLS12_CIPHERS,
        tls13: FIPS_TLS13_CIPHERS
      },
      complianceLevel: this.fipsEnabled ? "full" : "software-only",
      timestamp: Date.now()
    };
  }
  /** Validate that a given algorithm name is FIPS-approved */
  isApprovedAlgorithm(algorithm) {
    const lower = algorithm.toLowerCase();
    return !PROHIBITED_ALGORITHMS.some((p) => lower.includes(p));
  }
  // ─── Symmetric Encryption (AES-256-GCM) ──────────────────────────────
  /** Encrypt data using AES-256-GCM */
  encrypt(plaintext, context) {
    const iv = crypto.randomBytes(GCM_IV_LENGTH);
    const key = context ? this.deriveKey(this.masterKey, context) : this.masterKey;
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
      authTagLength: GCM_TAG_LENGTH
    });
    const input = typeof plaintext === "string" ? Buffer.from(plaintext, "utf-8") : plaintext;
    const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      ciphertext: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      algorithm: "aes-256-gcm",
      keyDerivation: context ? "hkdf-sha256" : "direct"
    };
  }
  /** Decrypt AES-256-GCM encrypted payload */
  decrypt(payload, context) {
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
      decipher.final()
    ]);
  }
  // ─── Key Derivation (HKDF-SHA256) ────────────────────────────────────
  /** Derive a key using HKDF (RFC 5869) with SHA-256 */
  deriveKey(ikm, info, length = 32) {
    return Buffer.from(crypto.hkdfSync("sha256", ikm, Buffer.alloc(0), info, length));
  }
  // ─── Digital Signatures (ECDSA) ──────────────────────────────────────
  /** Generate an ECDSA key pair */
  generateKeyPair(curve = "P-256") {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: curve,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" }
    });
    return { publicKey, privateKey, curve };
  }
  /** Sign data with ECDSA + SHA-256 */
  sign(data, privateKeyPem) {
    const signer = crypto.createSign("SHA256");
    signer.update(typeof data === "string" ? data : data);
    signer.end();
    return signer.sign(privateKeyPem, "base64");
  }
  /** Verify an ECDSA + SHA-256 signature */
  verify(data, signature, publicKeyPem) {
    const verifier = crypto.createVerify("SHA256");
    verifier.update(typeof data === "string" ? data : data);
    verifier.end();
    return verifier.verify(publicKeyPem, signature, "base64");
  }
  // ─── HMAC (SHA-256) ──────────────────────────────────────────────────
  /** Compute HMAC-SHA256 */
  hmac(data, key) {
    const hmacKey = key ?? this.masterKey;
    return crypto.createHmac("sha256", hmacKey).update(typeof data === "string" ? data : data).digest("hex");
  }
  /** Verify HMAC-SHA256 using timing-safe comparison */
  verifyHmac(data, expectedHmac, key) {
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
  hash(data, algorithm = "sha256") {
    return crypto.createHash(algorithm).update(typeof data === "string" ? data : data).digest("hex");
  }
  // ─── Password Hashing (PBKDF2-HMAC-SHA256) ───────────────────────────
  /** Hash a password using PBKDF2-HMAC-SHA256 (FIPS-validated) */
  hashPassword(password) {
    const salt = crypto.randomBytes(32);
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 64, "sha256");
    return {
      hash: hash.toString("base64"),
      salt: salt.toString("base64"),
      iterations: PBKDF2_ITERATIONS,
      algorithm: "pbkdf2-sha256"
    };
  }
  /** Verify a password against a stored PBKDF2 hash */
  verifyPassword(password, stored) {
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
  randomBytes(length) {
    return crypto.randomBytes(length);
  }
  /** Generate a UUID v4 */
  uuid() {
    return crypto.randomUUID();
  }
  // ─── JWT (ECDSA ES256) ────────────────────────────────────────────────
  /** Create a JWT signed with ECDSA P-256 (ES256) */
  createJWT(payload, privateKeyPem, expiresInSeconds = 3600) {
    const header = { alg: "ES256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1e3);
    const fullPayload = { ...payload, iat: now, exp: now + expiresInSeconds };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = this.sign(signingInput, privateKeyPem);
    const sigB64 = Buffer.from(sig, "base64").toString("base64url");
    return `${signingInput}.${sigB64}`;
  }
  /** Verify and decode a JWT */
  verifyJWT(token, publicKeyPem) {
    const parts = token.split(".");
    if (parts.length !== 3) return { valid: false, error: "Invalid JWT format" };
    const [headerB64, payloadB64, sigB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = Buffer.from(sigB64, "base64url").toString("base64");
    if (!this.verify(signingInput, signature, publicKeyPem)) {
      return { valid: false, error: "Invalid signature" };
    }
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    const now = Math.floor(Date.now() / 1e3);
    if (payload.exp && payload.exp < now) {
      return { valid: false, error: "Token expired" };
    }
    return { valid: true, payload };
  }
  // ─── Audit Log Integrity Chain ────────────────────────────────────────
  /** Create a chained HMAC for audit log tamper detection */
  chainAuditRecord(record, previousHash) {
    const recordHash = this.hmac(`${previousHash}|${record}`);
    return { recordHash, previousHash };
  }
  /** Verify an audit chain entry */
  verifyAuditChain(record, entry) {
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
};
var _instance = null;
function getFIPSCrypto(masterKeyHex) {
  if (!_instance) {
    _instance = new FIPSCryptoService(masterKeyHex);
  }
  return _instance;
}

export {
  getFIPSCrypto
};
