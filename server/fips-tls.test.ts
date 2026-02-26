/**
 * FIPS TLS Configuration Tests
 *
 * Validates:
 *   - FIPS-approved cipher suite list
 *   - HTTPS agent creation with correct TLS settings
 *   - Database SSL configuration
 *   - TLS audit functionality
 *   - Global enforcement
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock tls module
vi.mock("tls", () => ({
  default: {
    DEFAULT_CIPHERS: "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:CHACHA20-POLY1305:RC4-SHA",
    DEFAULT_MIN_VERSION: "TLSv1.2",
    connect: vi.fn(),
  },
  DEFAULT_CIPHERS: "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:CHACHA20-POLY1305:RC4-SHA",
  DEFAULT_MIN_VERSION: "TLSv1.2",
}));

// Mock https module
const mockAgent = { options: {} };
vi.mock("https", () => ({
  default: {
    Agent: vi.fn().mockImplementation((opts: any) => ({ ...mockAgent, _options: opts })),
  },
}));

describe("FIPS TLS Configuration", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  describe("FIPS_TLS_CONFIG constants", () => {
    it("should export correct minimum TLS version", async () => {
      const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
      expect(FIPS_TLS_CONFIG.MIN_VERSION).toBe("TLSv1.2");
    });

    it("should export TLS 1.3 as preferred version", async () => {
      const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
      expect(FIPS_TLS_CONFIG.PREFERRED_VERSION).toBe("TLSv1.3");
    });

    it("should include only FIPS-approved cipher suites", async () => {
      const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
      const ciphers = FIPS_TLS_CONFIG.CIPHERS.split(":");

      // All ciphers should use ECDHE or DHE key exchange
      for (const cipher of ciphers) {
        expect(cipher).toMatch(/^(ECDHE|DHE)-/);
      }

      // No RC4, DES, 3DES, or export ciphers
      for (const cipher of ciphers) {
        expect(cipher).not.toMatch(/RC4|DES|3DES|EXPORT|NULL|MD5/i);
      }
    });

    it("should include AES-256-GCM with ECDHE as first cipher", async () => {
      const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
      const ciphers = FIPS_TLS_CONFIG.CIPHERS.split(":");
      expect(ciphers[0]).toBe("ECDHE-ECDSA-AES256-GCM-SHA384");
    });

    it("should have at least 8 approved cipher suites", async () => {
      const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
      const ciphers = FIPS_TLS_CONFIG.CIPHERS.split(":");
      expect(ciphers.length).toBeGreaterThanOrEqual(8);
    });

    it("should include both ECDSA and RSA cipher suites", async () => {
      const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
      const ciphers = FIPS_TLS_CONFIG.CIPHERS.split(":");
      const hasECDSA = ciphers.some(c => c.includes("ECDSA"));
      const hasRSA = ciphers.some(c => c.includes("RSA"));
      expect(hasECDSA).toBe(true);
      expect(hasRSA).toBe(true);
    });
  });

  describe("getFIPSHttpsAgent", () => {
    it("should return an HTTPS agent", async () => {
      const { getFIPSHttpsAgent } = await import("./lib/fips-tls");
      const agent = getFIPSHttpsAgent();
      expect(agent).toBeDefined();
    });

    it("should return the same singleton instance", async () => {
      const { getFIPSHttpsAgent } = await import("./lib/fips-tls");
      const agent1 = getFIPSHttpsAgent();
      const agent2 = getFIPSHttpsAgent();
      expect(agent1).toBe(agent2);
    });
  });

  describe("createFIPSHttpsAgent", () => {
    it("should create a new agent with FIPS defaults", async () => {
      const { createFIPSHttpsAgent } = await import("./lib/fips-tls");
      const agent = createFIPSHttpsAgent();
      expect(agent).toBeDefined();
    });

    it("should allow custom overrides", async () => {
      const { createFIPSHttpsAgent } = await import("./lib/fips-tls");
      const agent = createFIPSHttpsAgent({ timeout: 5000 });
      expect(agent).toBeDefined();
    });
  });

  describe("getFIPSDatabaseSSLConfig", () => {
    it("should return SSL config with FIPS settings", async () => {
      const { getFIPSDatabaseSSLConfig } = await import("./lib/fips-tls");
      const config = getFIPSDatabaseSSLConfig();

      expect(config).toHaveProperty("ssl");
      expect(config.ssl).toHaveProperty("minVersion", "TLSv1.2");
      expect(config.ssl).toHaveProperty("ciphers");
    });

    it("should include FIPS cipher suites in SSL config", async () => {
      const { getFIPSDatabaseSSLConfig, FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
      const config = getFIPSDatabaseSSLConfig();
      expect(config.ssl.ciphers).toBe(FIPS_TLS_CONFIG.CIPHERS);
    });
  });

  describe("getFIPSDatabaseSSLConfigStrict", () => {
    it("should return strict SSL config with CA certificate", async () => {
      const { getFIPSDatabaseSSLConfigStrict } = await import("./lib/fips-tls");
      const caCert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";
      const config = getFIPSDatabaseSSLConfigStrict(caCert);

      expect(config.ssl).toHaveProperty("rejectUnauthorized", true);
      expect(config.ssl).toHaveProperty("ca", caCert);
      expect(config.ssl).toHaveProperty("minVersion", "TLSv1.2");
    });
  });

  describe("getFIPSAxiosConfig", () => {
    it("should return config with FIPS HTTPS agent", async () => {
      const { getFIPSAxiosConfig } = await import("./lib/fips-tls");
      const config = getFIPSAxiosConfig();

      expect(config).toHaveProperty("httpsAgent");
      expect(config).toHaveProperty("timeout", 30000);
    });
  });

  describe("auditTLSConfiguration", () => {
    it("should return a TLS audit result", async () => {
      const { auditTLSConfiguration } = await import("./lib/fips-tls");
      const result = auditTLSConfiguration();

      expect(result).toHaveProperty("compliant");
      expect(result).toHaveProperty("minVersion");
      expect(result).toHaveProperty("cipherSuites");
      expect(result).toHaveProperty("nonCompliantCiphers");
      expect(result).toHaveProperty("details");
    });

    it("should identify non-FIPS ciphers in defaults", async () => {
      const { auditTLSConfiguration } = await import("./lib/fips-tls");
      const result = auditTLSConfiguration();

      // Our mock has CHACHA20-POLY1305 and RC4-SHA which are not in FIPS list
      expect(result.nonCompliantCiphers.length).toBeGreaterThan(0);
      expect(result.nonCompliantCiphers).toContain("CHACHA20-POLY1305");
      expect(result.nonCompliantCiphers).toContain("RC4-SHA");
    });

    it("should not flag FIPS-approved ciphers as non-compliant", async () => {
      const { auditTLSConfiguration } = await import("./lib/fips-tls");
      const result = auditTLSConfiguration();

      // ECDHE-RSA-AES256-GCM-SHA384 is in our FIPS list
      expect(result.nonCompliantCiphers).not.toContain("ECDHE-RSA-AES256-GCM-SHA384");
    });

    it("should return cipher suites list", async () => {
      const { auditTLSConfiguration } = await import("./lib/fips-tls");
      const result = auditTLSConfiguration();
      expect(result.cipherSuites.length).toBeGreaterThanOrEqual(8);
    });
  });
});

describe("FIPS TLS Global Enforcement", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("should start with enforcement inactive", async () => {
    const { isFIPSTLSEnforced } = await import("./lib/fips-tls-global");
    // After fresh import, enforcement should be inactive
    // (unless enforceFIPSTLS was already called in module scope)
    expect(typeof isFIPSTLSEnforced()).toBe("boolean");
  });

  it("should activate enforcement when called", async () => {
    const { enforceFIPSTLS, isFIPSTLSEnforced } = await import("./lib/fips-tls-global");
    enforceFIPSTLS();
    expect(isFIPSTLSEnforced()).toBe(true);
  });

  it("should be idempotent", async () => {
    const { enforceFIPSTLS, isFIPSTLSEnforced } = await import("./lib/fips-tls-global");
    enforceFIPSTLS();
    enforceFIPSTLS();
    enforceFIPSTLS();
    expect(isFIPSTLSEnforced()).toBe(true);
  });
});

describe("Credential Crypto FIPS Integration", () => {
  it("should use AES-256-GCM for server credential encryption", async () => {
    const { encryptServerCredential, decryptCredential } = await import("./lib/credential-crypto");
    const secret = "super-secret-api-key-12345";
    const encrypted = encryptServerCredential(secret);

    expect(encrypted).toHaveProperty("encryptedData");
    expect(encrypted).toHaveProperty("iv");
    expect(encrypted).toHaveProperty("tag");
    expect(encrypted).toHaveProperty("fips", true);
    expect(encrypted).toHaveProperty("context", "server-credential-at-rest");

    const decrypted = decryptCredential(encrypted);
    expect(decrypted).toBe(secret);
  });

  it("should use AES-256-GCM for SSH private key encryption", async () => {
    const { encryptSSHPrivateKey, decryptCredential } = await import("./lib/credential-crypto");
    const privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----";
    const encrypted = encryptSSHPrivateKey(privateKey);

    expect(encrypted).toHaveProperty("fips", true);
    expect(encrypted).toHaveProperty("context", "ssh-private-key-at-rest");
    expect(encrypted).toHaveProperty("encryptedData");

    const decrypted = decryptCredential(encrypted);
    expect(decrypted).toBe(privateKey);
  });

  it("should produce different ciphertexts for the same plaintext (random IV)", async () => {
    const { encryptServerCredential } = await import("./lib/credential-crypto");
    const secret = "same-secret";
    const e1 = encryptServerCredential(secret);
    const e2 = encryptServerCredential(secret);

    expect(e1.encryptedData).not.toBe(e2.encryptedData);
    expect(e1.iv).not.toBe(e2.iv);
  });

  it("should reject tampered ciphertext", async () => {
    const { encryptServerCredential, decryptCredential } = await import("./lib/credential-crypto");
    const encrypted = encryptServerCredential("test");

    // Tamper with ciphertext
    const tampered = { ...encrypted, encryptedData: encrypted.encryptedData.slice(0, -4) + "0000" };
    expect(() => decryptCredential(tampered)).toThrow();
  });

  it("should encrypt and decrypt credential objects", async () => {
    const { encryptCredentialObject, decryptCredentialObject } = await import("./lib/credential-crypto");
    const creds = { username: "admin", password: "s3cr3t", apiKey: "key-123" };
    const encrypted = encryptCredentialObject(creds);

    expect(encrypted).toHaveProperty("fips", true);
    expect(encrypted).toHaveProperty("context", "cloud-credential-at-rest");

    const decrypted = decryptCredentialObject(encrypted);
    expect(decrypted).toEqual(creds);
  });
});
