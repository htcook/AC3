import { describe, expect, it } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── 1. FIPS TLS Module — Cipher Suite Validation ──────────────────────────

describe("FIPS 140-3 TLS: Cipher suite configuration", () => {
  it("exports FIPS_TLS_CONFIG with correct minimum version", async () => {
    const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
    expect(FIPS_TLS_CONFIG.MIN_VERSION).toBe("TLSv1.2");
  });

  it("exports FIPS_TLS_CONFIG with preferred TLS 1.3", async () => {
    const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
    expect(FIPS_TLS_CONFIG.PREFERRED_VERSION).toBe("TLSv1.3");
  });

  it("FIPS cipher list contains only approved algorithms", async () => {
    const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
    const ciphers = FIPS_TLS_CONFIG.CIPHERS.split(":");
    for (const cipher of ciphers) {
      expect(cipher).toMatch(/AES/);
      expect(cipher).toMatch(/ECDHE|DHE/);
      expect(cipher).not.toMatch(/RC4|3DES|DES-CBC|MD5/);
    }
  });

  it("FIPS cipher list does not include ChaCha20 or non-NIST algorithms", async () => {
    const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
    const ciphers = FIPS_TLS_CONFIG.CIPHERS;
    expect(ciphers).not.toContain("CHACHA20");
    expect(ciphers).not.toContain("POLY1305");
  });

  it("getFIPSHttpsAgent returns agent with correct TLS settings", async () => {
    const { getFIPSHttpsAgent } = await import("./lib/fips-tls");
    const agent = getFIPSHttpsAgent();
    expect(agent).toBeDefined();
    expect(agent.options).toBeDefined();
    expect(agent.options.minVersion).toBe("TLSv1.2");
  });

  it("createFIPSHttpsAgent allows overrides while keeping FIPS ciphers", async () => {
    const { createFIPSHttpsAgent, FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
    const agent = createFIPSHttpsAgent({ rejectUnauthorized: false });
    expect(agent.options.rejectUnauthorized).toBe(false);
    expect(agent.options.minVersion).toBe("TLSv1.2");
    expect(agent.options.ciphers).toBe(FIPS_TLS_CONFIG.CIPHERS);
  });

  it("auditTLSConfiguration returns a valid audit result", async () => {
    const { auditTLSConfiguration } = await import("./lib/fips-tls");
    const result = auditTLSConfiguration();
    expect(result).toHaveProperty("compliant");
    expect(result).toHaveProperty("minVersion");
    expect(result).toHaveProperty("cipherSuites");
    expect(result).toHaveProperty("nonCompliantCiphers");
    expect(result).toHaveProperty("details");
    expect(Array.isArray(result.cipherSuites)).toBe(true);
    expect(result.cipherSuites.length).toBeGreaterThan(0);
  });

  it("getFIPSDatabaseSSLConfig enforces TLS 1.2+ on DB connections", async () => {
    const { getFIPSDatabaseSSLConfig } = await import("./lib/fips-tls");
    const config = getFIPSDatabaseSSLConfig();
    expect(config.ssl).toBeDefined();
    expect(config.ssl.minVersion).toBe("TLSv1.2");
    expect(config.ssl.ciphers).toBeDefined();
    const ciphers = config.ssl.ciphers.split(":");
    for (const cipher of ciphers) {
      expect(cipher).toMatch(/AES/);
      expect(cipher).toMatch(/ECDHE|DHE/);
    }
  });
});

// ─── 2. FIPS SSH Module — Algorithm Validation ─────────────────────────────

describe("FIPS 140-3 SSH: Algorithm configuration", () => {
  it("exports FIPS_SSH_ALGORITHMS with all required fields", async () => {
    const { FIPS_SSH_ALGORITHMS } = await import("./lib/fips-ssh");
    expect(FIPS_SSH_ALGORITHMS).toHaveProperty("kex");
    expect(FIPS_SSH_ALGORITHMS).toHaveProperty("cipher");
    expect(FIPS_SSH_ALGORITHMS).toHaveProperty("serverHostKey");
    expect(FIPS_SSH_ALGORITHMS).toHaveProperty("hmac");
  });

  it("KEX algorithms are NIST-approved only", async () => {
    const { FIPS_SSH_CONFIG } = await import("./lib/fips-ssh");
    for (const kex of FIPS_SSH_CONFIG.KEX) {
      expect(kex).toMatch(/ecdh-sha2-nistp|diffie-hellman-group1[4-8]-sha/);
      expect(kex).not.toContain("curve25519");
      expect(kex).not.toMatch(/sha1$/);
    }
  });

  it("SSH ciphers are AES-only with GCM or CTR modes", async () => {
    const { FIPS_SSH_CONFIG } = await import("./lib/fips-ssh");
    for (const cipher of FIPS_SSH_CONFIG.CIPHERS) {
      expect(cipher).toMatch(/aes/);
      expect(cipher).toMatch(/gcm|ctr/);
      expect(cipher).not.toContain("chacha");
      expect(cipher).not.toContain("3des");
      expect(cipher).not.toContain("blowfish");
      expect(cipher).not.toContain("arcfour");
    }
  });

  it("SSH MACs use SHA-2 family only", async () => {
    const { FIPS_SSH_CONFIG } = await import("./lib/fips-ssh");
    for (const mac of FIPS_SSH_CONFIG.MACS) {
      expect(mac).toMatch(/sha2-256|sha2-512/);
      expect(mac).not.toMatch(/sha1/);
      expect(mac).not.toContain("md5");
    }
  });

  it("SSH host key algorithms use NIST curves or RSA-SHA2", async () => {
    const { FIPS_SSH_CONFIG } = await import("./lib/fips-ssh");
    for (const hk of FIPS_SSH_CONFIG.HOST_KEY) {
      expect(hk).toMatch(/ecdsa-sha2-nistp|rsa-sha2/);
      expect(hk).not.toContain("ed25519");
      expect(hk).not.toBe("ssh-rsa");
    }
  });

  it("isFIPSApprovedCipher validates correctly", async () => {
    const { isFIPSApprovedCipher } = await import("./lib/fips-ssh");
    expect(isFIPSApprovedCipher("aes256-gcm@openssh.com")).toBe(true);
    expect(isFIPSApprovedCipher("aes128-ctr")).toBe(true);
    expect(isFIPSApprovedCipher("chacha20-poly1305@openssh.com")).toBe(false);
    expect(isFIPSApprovedCipher("3des-cbc")).toBe(false);
  });

  it("isFIPSApprovedKex validates correctly", async () => {
    const { isFIPSApprovedKex } = await import("./lib/fips-ssh");
    expect(isFIPSApprovedKex("ecdh-sha2-nistp256")).toBe(true);
    expect(isFIPSApprovedKex("diffie-hellman-group14-sha256")).toBe(true);
    expect(isFIPSApprovedKex("curve25519-sha256")).toBe(false);
    expect(isFIPSApprovedKex("diffie-hellman-group1-sha1")).toBe(false);
  });

  it("isFIPSApprovedMac validates correctly", async () => {
    const { isFIPSApprovedMac } = await import("./lib/fips-ssh");
    expect(isFIPSApprovedMac("hmac-sha2-256")).toBe(true);
    expect(isFIPSApprovedMac("hmac-sha2-512-etm@openssh.com")).toBe(true);
    expect(isFIPSApprovedMac("hmac-sha1")).toBe(false);
    expect(isFIPSApprovedMac("hmac-md5")).toBe(false);
  });
});

// ─── 3. Global FIPS Enforcement ────────────────────────────────────────────

describe("FIPS 140-3 Global: enforceFIPSTLS is called at startup", () => {
  it("server/_core/index.ts imports and calls enforceFIPSTLS", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "_core/index.ts"),
      "utf-8"
    );
    expect(content).toContain("enforceFIPSTLS");
    expect(content).toContain("fips-tls-global");
  });

  it("enforceFIPSTLS is idempotent", async () => {
    const { enforceFIPSTLS, isFIPSTLSEnforced } = await import("./lib/fips-tls-global");
    enforceFIPSTLS();
    expect(isFIPSTLSEnforced()).toBe(true);
    enforceFIPSTLS();
    expect(isFIPSTLSEnforced()).toBe(true);
  });
});

// ─── 4. API Helpers — No NODE_TLS_REJECT_UNAUTHORIZED ──────────────────────

describe("FIPS 140-3 API Helpers: No global TLS bypass", () => {
  const filesToCheck = [
    { name: "api-helpers.ts", path: "server/lib/api-helpers.ts" },
    { name: "routers.ts", path: "server/routers.ts" },
    { name: "phishing-ops.ts", path: "server/routers/phishing-ops.ts" },
    { name: "phishing/shared.ts", path: "server/routers/phishing/shared.ts" },
    { name: "crawl-phish.ts", path: "server/routers/crawl-phish.ts" },
  ];

  for (const file of filesToCheck) {
    it(`${file.name} does NOT set NODE_TLS_REJECT_UNAUTHORIZED = '0'`, () => {
      const content = fs.readFileSync(
        path.join(__dirname, "..", file.path),
        "utf-8"
      );
      // Filter out comment lines and only check actual code
      const lines = content.split('\n');
      const assignmentLines = lines.filter(line => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return false;
        return /process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/.test(trimmed);
      });
      expect(assignmentLines).toHaveLength(0);
    });
  }

  it("api-helpers.ts uses FIPS HTTPS agent for GoPhish", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "lib/api-helpers.ts"),
      "utf-8"
    );
    expect(content).toContain("createFIPSHttpsAgent");
    expect(content).toContain("getFIPSHttpsAgent");
  });
});

// ─── 5. SSH Connections — FIPS Algorithms Enforced ─────────────────────────

describe("FIPS 140-3 SSH: All SSH connections use FIPS algorithms", () => {
  const sshFiles = [
    { name: "ssh-tunnel-manager.ts", path: "server/lib/ssh-tunnel-manager.ts" },
    { name: "scan-server-executor.ts", path: "server/lib/scan-server-executor.ts" },
    { name: "amass-engine.ts", path: "server/lib/amass-engine.ts" },
    { name: "nmap-orchestrator.ts", path: "server/lib/nmap-orchestrator.ts" },
    { name: "payload-generator.ts", path: "server/routers/payload-generator.ts" },
  ];

  for (const file of sshFiles) {
    it(`${file.name} imports FIPS_SSH_ALGORITHMS`, () => {
      const content = fs.readFileSync(
        path.join(__dirname, "..", file.path),
        "utf-8"
      );
      expect(content).toContain("FIPS_SSH_ALGORITHMS");
      expect(content).toContain("fips-ssh");
    });

    it(`${file.name} passes algorithms to .connect()`, () => {
      const content = fs.readFileSync(
        path.join(__dirname, "..", file.path),
        "utf-8"
      );
      const connectBlocks = content.split(".connect(");
      for (let i = 1; i < connectBlocks.length; i++) {
        const block = connectBlocks[i].split(");")[0];
        if (block.includes("host:") || block.includes("host,")) {
          expect(block).toContain("FIPS_SSH_ALGORITHMS");
        }
      }
    });
  }
});

// ─── 6. Database Connection — FIPS SSL ─────────────────────────────────────

describe("FIPS 140-3 Database: SSL configuration uses FIPS ciphers", () => {
  it("db.ts imports getFIPSDatabaseSSLConfig", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "db.ts"),
      "utf-8"
    );
    expect(content).toContain("getFIPSDatabaseSSLConfig");
    expect(content).toContain("fips-tls");
  });

  it("db.ts applies FIPS SSL config when connecting to TiDB", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "db.ts"),
      "utf-8"
    );
    expect(content).toContain("FIPS 140-3");
    expect(content).toContain("fipsSSL");
  });
});

// ─── 7. Non-FIPS Algorithm Rejection ───────────────────────────────────────

describe("FIPS 140-3: Non-approved algorithms are rejected", () => {
  it("SSH config does NOT include curve25519 or ed25519", async () => {
    const { FIPS_SSH_CONFIG } = await import("./lib/fips-ssh");
    const allAlgos = [
      ...FIPS_SSH_CONFIG.KEX,
      ...FIPS_SSH_CONFIG.CIPHERS,
      ...FIPS_SSH_CONFIG.MACS,
      ...FIPS_SSH_CONFIG.HOST_KEY,
    ].join(" ");
    expect(allAlgos).not.toContain("curve25519");
    expect(allAlgos).not.toContain("ed25519");
  });

  it("SSH config does NOT include SHA-1 based algorithms", async () => {
    const { FIPS_SSH_CONFIG } = await import("./lib/fips-ssh");
    const allAlgos = [
      ...FIPS_SSH_CONFIG.KEX,
      ...FIPS_SSH_CONFIG.MACS,
      ...FIPS_SSH_CONFIG.HOST_KEY,
    ];
    for (const algo of allAlgos) {
      expect(algo).not.toMatch(/-sha1$/);
      expect(algo).not.toBe("ssh-rsa");
    }
  });

  it("TLS config does NOT include CBC-SHA1 (SHA-1 MAC)", async () => {
    const { FIPS_TLS_CONFIG } = await import("./lib/fips-tls");
    const ciphers = FIPS_TLS_CONFIG.CIPHERS.split(":");
    for (const cipher of ciphers) {
      if (cipher.includes("CBC")) {
        expect(cipher).toMatch(/SHA256|SHA384|SHA512/);
      }
    }
  });
});
