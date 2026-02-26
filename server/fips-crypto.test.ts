import { describe, expect, it, beforeEach } from "vitest";
import {
  FIPSCryptoService,
  getFIPSCrypto,
  resetFIPSCrypto,
  type EncryptedPayload,
  type PasswordHash,
} from "./lib/fips-crypto";

describe("FIPSCryptoService", () => {
  let crypto: FIPSCryptoService;

  beforeEach(() => {
    resetFIPSCrypto();
    crypto = new FIPSCryptoService();
  });

  // ─── Compliance Report ────────────────────────────────────────────────

  describe("getComplianceReport", () => {
    it("returns a valid compliance report structure", () => {
      const report = crypto.getComplianceReport();

      expect(report).toHaveProperty("fipsProviderActive");
      expect(report).toHaveProperty("opensslVersion");
      expect(report).toHaveProperty("nodeVersion");
      expect(report).toHaveProperty("approvedAlgorithms");
      expect(report).toHaveProperty("prohibitedAlgorithms");
      expect(report).toHaveProperty("tlsCiphers");
      expect(report).toHaveProperty("complianceLevel");
      expect(report).toHaveProperty("timestamp");

      expect(typeof report.fipsProviderActive).toBe("boolean");
      expect(["full", "partial", "software-only"]).toContain(report.complianceLevel);
    });

    it("lists all required approved algorithm categories", () => {
      const report = crypto.getComplianceReport();
      const algos = report.approvedAlgorithms;

      expect(algos.symmetric).toContain("aes-256-gcm");
      expect(algos.hash).toContain("sha256");
      expect(algos.mac).toContain("hmac-sha256");
      expect(algos.signature).toContain("ecdsa-p256");
      expect(algos.kdf).toContain("hkdf-sha256");
    });

    it("lists prohibited algorithms", () => {
      const report = crypto.getComplianceReport();
      expect(report.prohibitedAlgorithms).toContain("md5");
      expect(report.prohibitedAlgorithms).toContain("sha1");
      expect(report.prohibitedAlgorithms).toContain("des");
      expect(report.prohibitedAlgorithms).toContain("rc4");
    });
  });

  // ─── Algorithm Validation ─────────────────────────────────────────────

  describe("isApprovedAlgorithm", () => {
    it("approves FIPS-valid algorithms", () => {
      expect(crypto.isApprovedAlgorithm("aes-256-gcm")).toBe(true);
      expect(crypto.isApprovedAlgorithm("sha256")).toBe(true);
      expect(crypto.isApprovedAlgorithm("ecdsa")).toBe(true);
    });

    it("rejects prohibited algorithms", () => {
      expect(crypto.isApprovedAlgorithm("md5")).toBe(false);
      expect(crypto.isApprovedAlgorithm("sha1")).toBe(false);
      expect(crypto.isApprovedAlgorithm("des")).toBe(false);
      expect(crypto.isApprovedAlgorithm("rc4")).toBe(false);
      expect(crypto.isApprovedAlgorithm("blowfish")).toBe(false);
    });
  });

  // ─── AES-256-GCM Encryption ───────────────────────────────────────────

  describe("encrypt / decrypt", () => {
    it("encrypts and decrypts a string", () => {
      const plaintext = "Hello, FIPS 140-3!";
      const encrypted = crypto.encrypt(plaintext);
      const decrypted = crypto.decrypt(encrypted);

      expect(decrypted.toString("utf-8")).toBe(plaintext);
    });

    it("encrypts and decrypts a Buffer", () => {
      const data = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      const encrypted = crypto.encrypt(data);
      const decrypted = crypto.decrypt(encrypted);

      expect(decrypted).toEqual(data);
    });

    it("uses aes-256-gcm algorithm", () => {
      const encrypted = crypto.encrypt("test");
      expect(encrypted.algorithm).toBe("aes-256-gcm");
    });

    it("produces different ciphertexts for the same plaintext (unique IV)", () => {
      const a = crypto.encrypt("same input");
      const b = crypto.encrypt("same input");

      expect(a.iv).not.toBe(b.iv);
      expect(a.ciphertext).not.toBe(b.ciphertext);
    });

    it("supports context-based key derivation", () => {
      const plaintext = "context-specific data";
      const encrypted = crypto.encrypt(plaintext, "context-a");

      expect(encrypted.keyDerivation).toBe("hkdf-sha256");

      const decrypted = crypto.decrypt(encrypted, "context-a");
      expect(decrypted.toString("utf-8")).toBe(plaintext);
    });

    it("fails to decrypt with wrong context", () => {
      const encrypted = crypto.encrypt("secret", "context-a");

      expect(() => crypto.decrypt(encrypted, "context-b")).toThrow();
    });

    it("fails to decrypt with tampered ciphertext", () => {
      const encrypted = crypto.encrypt("test data");
      const tampered: EncryptedPayload = {
        ...encrypted,
        ciphertext: Buffer.from("tampered").toString("base64"),
      };

      expect(() => crypto.decrypt(tampered)).toThrow();
    });

    it("fails to decrypt with tampered auth tag", () => {
      const encrypted = crypto.encrypt("test data");
      const tampered: EncryptedPayload = {
        ...encrypted,
        authTag: Buffer.alloc(16).toString("base64"),
      };

      expect(() => crypto.decrypt(tampered)).toThrow();
    });
  });

  // ─── Key Derivation (HKDF) ───────────────────────────────────────────

  describe("deriveKey", () => {
    it("derives a 32-byte key by default", () => {
      const key = crypto.deriveKey(Buffer.alloc(32), "test-info");
      expect(key.length).toBe(32);
    });

    it("derives different keys for different info strings", () => {
      const ikm = Buffer.alloc(32, 0xaa);
      const keyA = crypto.deriveKey(ikm, "info-a");
      const keyB = crypto.deriveKey(ikm, "info-b");

      expect(keyA).not.toEqual(keyB);
    });

    it("produces deterministic output for same inputs", () => {
      const ikm = Buffer.alloc(32, 0xbb);
      const keyA = crypto.deriveKey(ikm, "same-info");
      const keyB = crypto.deriveKey(ikm, "same-info");

      expect(keyA).toEqual(keyB);
    });
  });

  // ─── ECDSA Signatures ────────────────────────────────────────────────

  describe("generateKeyPair / sign / verify", () => {
    it("generates a P-256 key pair", () => {
      const kp = crypto.generateKeyPair("P-256");
      expect(kp.curve).toBe("P-256");
      expect(kp.publicKey).toContain("BEGIN PUBLIC KEY");
      expect(kp.privateKey).toContain("BEGIN PRIVATE KEY");
    });

    it("generates a P-384 key pair", () => {
      const kp = crypto.generateKeyPair("P-384");
      expect(kp.curve).toBe("P-384");
    });

    it("signs and verifies data", () => {
      const kp = crypto.generateKeyPair("P-256");
      const signature = crypto.sign("test data", kp.privateKey);
      const valid = crypto.verify("test data", signature, kp.publicKey);

      expect(valid).toBe(true);
    });

    it("rejects tampered data", () => {
      const kp = crypto.generateKeyPair("P-256");
      const signature = crypto.sign("original data", kp.privateKey);
      const valid = crypto.verify("tampered data", signature, kp.publicKey);

      expect(valid).toBe(false);
    });

    it("rejects wrong public key", () => {
      const kp1 = crypto.generateKeyPair("P-256");
      const kp2 = crypto.generateKeyPair("P-256");
      const signature = crypto.sign("test", kp1.privateKey);
      const valid = crypto.verify("test", signature, kp2.publicKey);

      expect(valid).toBe(false);
    });
  });

  // ─── HMAC-SHA256 ──────────────────────────────────────────────────────

  describe("hmac / verifyHmac", () => {
    it("computes a hex HMAC", () => {
      const result = crypto.hmac("test data");
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    });

    it("verifies a valid HMAC", () => {
      const hmacVal = crypto.hmac("test data");
      expect(crypto.verifyHmac("test data", hmacVal)).toBe(true);
    });

    it("rejects a tampered HMAC", () => {
      const hmacVal = crypto.hmac("test data");
      expect(crypto.verifyHmac("test data", "0".repeat(64))).toBe(false);
    });

    it("rejects tampered data", () => {
      const hmacVal = crypto.hmac("original");
      expect(crypto.verifyHmac("tampered", hmacVal)).toBe(false);
    });

    it("uses timing-safe comparison", () => {
      // Verify it doesn't throw on length mismatch
      expect(crypto.verifyHmac("test", "short")).toBe(false);
    });
  });

  // ─── Hashing ──────────────────────────────────────────────────────────

  describe("hash", () => {
    it("computes SHA-256 by default", () => {
      const h = crypto.hash("test");
      expect(h).toMatch(/^[0-9a-f]{64}$/);
    });

    it("computes SHA-384", () => {
      const h = crypto.hash("test", "sha384");
      expect(h).toMatch(/^[0-9a-f]{96}$/);
    });

    it("computes SHA-512", () => {
      const h = crypto.hash("test", "sha512");
      expect(h).toMatch(/^[0-9a-f]{128}$/);
    });

    it("produces deterministic output", () => {
      expect(crypto.hash("hello")).toBe(crypto.hash("hello"));
    });
  });

  // ─── Password Hashing (PBKDF2) ───────────────────────────────────────

  describe("hashPassword / verifyPassword", () => {
    it("hashes a password with PBKDF2-SHA256", () => {
      const result = crypto.hashPassword("my-password");
      expect(result.algorithm).toBe("pbkdf2-sha256");
      expect(result.iterations).toBeGreaterThanOrEqual(600_000);
      expect(result.hash).toBeTruthy();
      expect(result.salt).toBeTruthy();
    });

    it("verifies a correct password", () => {
      const hashed = crypto.hashPassword("correct-password");
      expect(crypto.verifyPassword("correct-password", hashed)).toBe(true);
    });

    it("rejects an incorrect password", () => {
      const hashed = crypto.hashPassword("correct-password");
      expect(crypto.verifyPassword("wrong-password", hashed)).toBe(false);
    });

    it("produces different salts each time", () => {
      const a = crypto.hashPassword("same-password");
      const b = crypto.hashPassword("same-password");
      expect(a.salt).not.toBe(b.salt);
    });
  });

  // ─── Secure Random ────────────────────────────────────────────────────

  describe("randomBytes / uuid", () => {
    it("generates random bytes of specified length", () => {
      const bytes = crypto.randomBytes(32);
      expect(bytes.length).toBe(32);
    });

    it("generates unique random bytes", () => {
      const a = crypto.randomBytes(32);
      const b = crypto.randomBytes(32);
      expect(a).not.toEqual(b);
    });

    it("generates a valid UUID v4", () => {
      const uuid = crypto.uuid();
      expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    });
  });

  // ─── JWT (ES256) ──────────────────────────────────────────────────────

  describe("createJWT / verifyJWT", () => {
    it("creates and verifies a JWT", () => {
      const kp = crypto.generateKeyPair("P-256");
      const token = crypto.createJWT({ sub: "user-123" }, kp.privateKey, 3600);
      const result = crypto.verifyJWT(token, kp.publicKey);

      expect(result.valid).toBe(true);
      expect(result.payload?.sub).toBe("user-123");
    });

    it("rejects an expired JWT", () => {
      const kp = crypto.generateKeyPair("P-256");
      const token = crypto.createJWT({ sub: "user-123" }, kp.privateKey, -1);
      const result = crypto.verifyJWT(token, kp.publicKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Token expired");
    });

    it("rejects a JWT with wrong key", () => {
      const kp1 = crypto.generateKeyPair("P-256");
      const kp2 = crypto.generateKeyPair("P-256");
      const token = crypto.createJWT({ sub: "user-123" }, kp1.privateKey);
      const result = crypto.verifyJWT(token, kp2.publicKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid signature");
    });

    it("rejects malformed JWT", () => {
      const kp = crypto.generateKeyPair("P-256");
      const result = crypto.verifyJWT("not.a.valid.jwt.token", kp.publicKey);
      expect(result.valid).toBe(false);
    });
  });

  // ─── Audit Chain ──────────────────────────────────────────────────────

  describe("chainAuditRecord / verifyAuditChain", () => {
    it("creates a valid audit chain entry", () => {
      const entry = crypto.chainAuditRecord("record-1", "0".repeat(64));
      expect(entry.recordHash).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.previousHash).toBe("0".repeat(64));
    });

    it("verifies a valid chain entry", () => {
      const entry = crypto.chainAuditRecord("record-1", "0".repeat(64));
      expect(crypto.verifyAuditChain("record-1", entry)).toBe(true);
    });

    it("detects tampered records", () => {
      const entry = crypto.chainAuditRecord("record-1", "0".repeat(64));
      expect(crypto.verifyAuditChain("tampered-record", entry)).toBe(false);
    });

    it("chains multiple records correctly", () => {
      const entry1 = crypto.chainAuditRecord("record-1", "0".repeat(64));
      const entry2 = crypto.chainAuditRecord("record-2", entry1.recordHash);
      const entry3 = crypto.chainAuditRecord("record-3", entry2.recordHash);

      expect(crypto.verifyAuditChain("record-1", entry1)).toBe(true);
      expect(crypto.verifyAuditChain("record-2", entry2)).toBe(true);
      expect(crypto.verifyAuditChain("record-3", entry3)).toBe(true);

      // Verify chain linkage
      expect(entry2.previousHash).toBe(entry1.recordHash);
      expect(entry3.previousHash).toBe(entry2.recordHash);
    });
  });

  // ─── Singleton ────────────────────────────────────────────────────────

  describe("getFIPSCrypto singleton", () => {
    it("returns the same instance on repeated calls", () => {
      resetFIPSCrypto();
      const a = getFIPSCrypto();
      const b = getFIPSCrypto();
      expect(a).toBe(b);
    });

    it("accepts a master key hex", () => {
      resetFIPSCrypto();
      const keyHex = "a".repeat(64);
      const instance = getFIPSCrypto(keyHex);
      expect(instance).toBeTruthy();
    });
  });

  // ─── Constructor Validation ───────────────────────────────────────────

  describe("constructor", () => {
    it("rejects a master key that is not 32 bytes", () => {
      expect(() => new FIPSCryptoService("aabb")).toThrow("Master key must be exactly 32 bytes");
    });

    it("accepts a valid 32-byte master key", () => {
      const key = "a".repeat(64); // 32 bytes in hex
      const svc = new FIPSCryptoService(key);
      expect(svc).toBeTruthy();
    });
  });
});
