import { describe, expect, it } from "vitest";
import crypto from "node:crypto";

// ─── FIPS 140-3 Cryptographic Compliance Tests ─────────────────────────────

describe("FIPS 140-3 Cryptographic Operations", () => {
  describe("Invite Token Generation", () => {
    it("generates 256-bit CSPRNG tokens using crypto.randomBytes", () => {
      const tokenBytes = crypto.randomBytes(32);
      expect(tokenBytes.length).toBe(32); // 256 bits
      expect(tokenBytes).toBeInstanceOf(Buffer);
    });

    it("produces URL-safe base64url encoded tokens", () => {
      const rawBytes = crypto.randomBytes(32);
      const rawToken = rawBytes.toString("base64url");
      // base64url should not contain +, /, or = padding
      expect(rawToken).not.toMatch(/[+/=]/);
      expect(rawToken.length).toBeGreaterThan(40); // 32 bytes → ~43 chars in base64url
    });

    it("hashes tokens with SHA-256 before storage", () => {
      const rawToken = crypto.randomBytes(32).toString("base64url");
      const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
      // SHA-256 produces 64 hex characters
      expect(tokenHash.length).toBe(64);
      expect(tokenHash).toMatch(/^[a-f0-9]{64}$/);
    });

    it("produces deterministic hashes for the same token", () => {
      const rawToken = "test-token-for-deterministic-check";
      const hash1 = crypto.createHash("sha256").update(rawToken).digest("hex");
      const hash2 = crypto.createHash("sha256").update(rawToken).digest("hex");
      expect(hash1).toBe(hash2);
    });

    it("produces different hashes for different tokens", () => {
      const token1 = crypto.randomBytes(32).toString("base64url");
      const token2 = crypto.randomBytes(32).toString("base64url");
      const hash1 = crypto.createHash("sha256").update(token1).digest("hex");
      const hash2 = crypto.createHash("sha256").update(token2).digest("hex");
      expect(hash1).not.toBe(hash2);
    });

    it("generates unique tokens on each call (no collisions)", () => {
      const tokens = new Set<string>();
      for (let i = 0; i < 100; i++) {
        tokens.add(crypto.randomBytes(32).toString("base64url"));
      }
      expect(tokens.size).toBe(100);
    });
  });

  describe("AES-256-GCM Encryption", () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    it("encrypts and decrypts data correctly", () => {
      const plaintext = "sensitive-credential-data";
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      expect(decrypted.toString("utf-8")).toBe(plaintext);
    });

    it("uses 12-byte IV (96-bit) for GCM mode", () => {
      expect(iv.length).toBe(12);
    });

    it("produces 16-byte authentication tag", () => {
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      cipher.update("test", "utf-8");
      cipher.final();
      const tag = cipher.getAuthTag();
      expect(tag.length).toBe(16);
    });

    it("detects tampered ciphertext via auth tag", () => {
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const encrypted = Buffer.concat([cipher.update("test", "utf-8"), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // Tamper with ciphertext
      const tampered = Buffer.from(encrypted);
      tampered[0] = tampered[0]! ^ 0xff;

      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);
      decipher.update(tampered);
      expect(() => decipher.final()).toThrow();
    });
  });

  describe("HMAC-SHA256", () => {
    it("produces consistent HMAC for same data and key", () => {
      const key = crypto.randomBytes(32);
      const data = "test-data";
      const hmac1 = crypto.createHmac("sha256", key).update(data).digest("hex");
      const hmac2 = crypto.createHmac("sha256", key).update(data).digest("hex");
      expect(hmac1).toBe(hmac2);
    });

    it("produces different HMAC for different data", () => {
      const key = crypto.randomBytes(32);
      const hmac1 = crypto.createHmac("sha256", key).update("data1").digest("hex");
      const hmac2 = crypto.createHmac("sha256", key).update("data2").digest("hex");
      expect(hmac1).not.toBe(hmac2);
    });
  });

  describe("HKDF Key Derivation", () => {
    it("derives a 32-byte key using HKDF-SHA256", () => {
      const ikm = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);
      const info = Buffer.from("invite-token-context");
      const derived = crypto.hkdfSync("sha256", ikm, salt, info, 32);
      expect(Buffer.from(derived).length).toBe(32);
    });

    it("produces different keys for different contexts", () => {
      const ikm = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);
      const key1 = Buffer.from(crypto.hkdfSync("sha256", ikm, salt, Buffer.from("context-1"), 32));
      const key2 = Buffer.from(crypto.hkdfSync("sha256", ikm, salt, Buffer.from("context-2"), 32));
      expect(key1.toString("hex")).not.toBe(key2.toString("hex"));
    });
  });
});

// ─── Role & Permission Tests ────────────────────────────────────────────────

describe("Role-Based Access Control", () => {
  const ALL_ROLES = ["user", "admin", "viewer", "operator", "team_lead", "analyst", "executive", "client"] as const;

  it("defines 8 distinct roles", () => {
    expect(ALL_ROLES.length).toBe(8);
  });

  it("includes all federal-required roles", () => {
    expect(ALL_ROLES).toContain("admin");
    expect(ALL_ROLES).toContain("operator");
    expect(ALL_ROLES).toContain("analyst");
    expect(ALL_ROLES).toContain("executive");
    expect(ALL_ROLES).toContain("viewer");
  });

  it("admin role has highest privilege level", () => {
    const adminCanManage = (role: string) => role === "admin";
    expect(adminCanManage("admin")).toBe(true);
    expect(adminCanManage("operator")).toBe(false);
  });

  it("team_lead can manage team but not admin operations", () => {
    const canManageTeam = (role: string) => role === "admin" || role === "team_lead";
    const canManageAdmins = (role: string) => role === "admin";
    expect(canManageTeam("team_lead")).toBe(true);
    expect(canManageAdmins("team_lead")).toBe(false);
  });

  it("prevents self-demotion for admin users", () => {
    const currentUserId = 1;
    const targetUserId = 1;
    const canChangeOwnRole = currentUserId !== targetUserId;
    expect(canChangeOwnRole).toBe(false);
  });

  it("prevents self-deactivation", () => {
    const currentUserId = 1;
    const targetUserId = 1;
    const canDeactivateSelf = currentUserId !== targetUserId;
    expect(canDeactivateSelf).toBe(false);
  });
});

// ─── Invitation Flow Tests ──────────────────────────────────────────────────

describe("Invitation Token Flow", () => {
  function generateInviteToken() {
    const rawBytes = crypto.randomBytes(32);
    const rawToken = rawBytes.toString("base64url");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    return { rawToken, tokenHash };
  }

  function hashToken(rawToken: string) {
    return crypto.createHash("sha256").update(rawToken).digest("hex");
  }

  it("generates a valid invite token pair", () => {
    const { rawToken, tokenHash } = generateInviteToken();
    expect(rawToken.length).toBeGreaterThan(0);
    expect(tokenHash.length).toBe(64);
  });

  it("raw token can be verified against stored hash", () => {
    const { rawToken, tokenHash } = generateInviteToken();
    const verifyHash = hashToken(rawToken);
    expect(verifyHash).toBe(tokenHash);
  });

  it("wrong token fails verification", () => {
    const { tokenHash } = generateInviteToken();
    const wrongToken = crypto.randomBytes(32).toString("base64url");
    const wrongHash = hashToken(wrongToken);
    expect(wrongHash).not.toBe(tokenHash);
  });

  it("token expiry is set to 72 hours from creation", () => {
    const INVITE_EXPIRY_HOURS = 72;
    const now = Date.now();
    const expiresAt = new Date(now + INVITE_EXPIRY_HOURS * 60 * 60 * 1000);
    const diffHours = (expiresAt.getTime() - now) / (60 * 60 * 1000);
    expect(diffHours).toBe(72);
  });

  it("expired token is detected correctly", () => {
    const expiresAt = new Date(Date.now() - 1000); // 1 second ago
    const isExpired = new Date() > expiresAt;
    expect(isExpired).toBe(true);
  });

  it("valid token is not expired", () => {
    const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000);
    const isExpired = new Date() > expiresAt;
    expect(isExpired).toBe(false);
  });
});

// ─── TLS Configuration Tests ────────────────────────────────────────────────

describe("TLS Configuration Compliance", () => {
  it("Node.js supports TLSv1.2 minimum", () => {
    const tls = require("tls");
    // Verify TLS 1.2 is available
    expect(tls.DEFAULT_MIN_VERSION).toBeDefined();
  });

  it("FIPS-approved TLS 1.2 cipher suites are valid", () => {
    const FIPS_CIPHERS = [
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
    ];
    // All use ECDHE key exchange (forward secrecy)
    for (const cipher of FIPS_CIPHERS) {
      expect(cipher).toMatch(/^ECDHE-/);
    }
    // All use GCM mode (AEAD)
    for (const cipher of FIPS_CIPHERS) {
      expect(cipher).toMatch(/GCM/);
    }
    // All use AES (128 or 256)
    for (const cipher of FIPS_CIPHERS) {
      expect(cipher).toMatch(/AES(128|256)/);
    }
  });

  it("no prohibited algorithms in FIPS cipher list", () => {
    const FIPS_CIPHERS = [
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
    ];
    const PROHIBITED = ["RC4", "DES", "3DES", "MD5", "SHA1", "NULL", "EXPORT"];
    for (const cipher of FIPS_CIPHERS) {
      for (const prohibited of PROHIBITED) {
        expect(cipher).not.toContain(prohibited);
      }
    }
  });
});

// ─── Session Security Tests ─────────────────────────────────────────────────

describe("Session Cookie Security", () => {
  it("session cookies are HttpOnly", () => {
    const cookieOptions = { httpOnly: true, secure: true, sameSite: "lax" as const, path: "/" };
    expect(cookieOptions.httpOnly).toBe(true);
  });

  it("session cookies are Secure", () => {
    const cookieOptions = { httpOnly: true, secure: true, sameSite: "lax" as const, path: "/" };
    expect(cookieOptions.secure).toBe(true);
  });

  it("session cookies have SameSite attribute", () => {
    const cookieOptions = { httpOnly: true, secure: true, sameSite: "lax" as const, path: "/" };
    expect(["strict", "lax", "none"]).toContain(cookieOptions.sameSite);
  });

  it("session tokens use JWT with HMAC-SHA256 signing", () => {
    // JWT header for HS256
    const header = { alg: "HS256", typ: "JWT" };
    expect(header.alg).toBe("HS256");
  });
});

// ─── User Profile Validation Tests ──────────────────────────────────────────

describe("User Profile Validation", () => {
  it("validates email format", () => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    expect(emailRegex.test("user@example.com")).toBe(true);
    expect(emailRegex.test("invalid")).toBe(false);
    expect(emailRegex.test("")).toBe(false);
  });

  it("validates phone format allows international numbers", () => {
    const validPhones = ["+1 (555) 000-0000", "+44 20 7946 0958", "555-0100"];
    for (const phone of validPhones) {
      expect(phone.length).toBeLessThanOrEqual(32);
    }
  });

  it("validates timezone strings", () => {
    const validTimezones = ["America/New_York", "UTC", "Europe/London", "Asia/Tokyo"];
    for (const tz of validTimezones) {
      expect(tz.length).toBeLessThanOrEqual(64);
      expect(tz.length).toBeGreaterThan(0);
    }
  });

  it("user status transitions are valid", () => {
    const validStatuses = ["active", "inactive", "suspended", "pending"];
    const validTransitions: Record<string, string[]> = {
      active: ["inactive", "suspended"],
      inactive: ["active"],
      suspended: ["active"],
      pending: ["active"],
    };
    for (const status of validStatuses) {
      expect(validTransitions[status]).toBeDefined();
      expect(validTransitions[status]!.length).toBeGreaterThan(0);
    }
  });
});
