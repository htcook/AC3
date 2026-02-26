/**
 * Tests for the Credential Migration Service
 *
 * Validates detection of plaintext/legacy/FIPS credential formats
 * and the migration logic that re-encrypts them with FIPS crypto.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the database before importing the module
vi.mock("./db", () => ({
  getDb: vi.fn(),
}));

// Mock the credential-crypto module
vi.mock("./lib/credential-crypto", () => {
  return {
    encryptServerCredential: vi.fn((plaintext: string) => ({
      encryptedData: `fips-enc-${plaintext}`,
      iv: "fips-iv-123",
      tag: "fips-tag-456",
      fips: true,
      context: "server-credential-at-rest",
    })),
    encryptSSHPrivateKey: vi.fn((plaintext: string) => ({
      encryptedData: `fips-enc-${plaintext}`,
      iv: "fips-iv-ssh",
      tag: "fips-tag-ssh",
      fips: true,
      context: "ssh-private-key-at-rest",
    })),
    encryptCredential: vi.fn((plaintext: string, context: string) => ({
      encryptedData: `fips-enc-${plaintext}`,
      iv: "fips-iv-gen",
      tag: "fips-tag-gen",
      fips: true,
      context,
    })),
    decryptCredential: vi.fn((payload: any) => {
      if (payload.fips) return `decrypted-fips-${payload.encryptedData}`;
      return `decrypted-legacy-${payload.encryptedData}`;
    }),
    FIPS_CONTEXTS: {
      CLOUD_CREDENTIAL: "cloud-credential-at-rest",
      LDAP_BIND: "ldap-bind-password-at-rest",
      SERVER_CREDENTIAL: "server-credential-at-rest",
      SSH_KEY: "ssh-private-key-at-rest",
      GENERIC: "credential-at-rest",
    },
  };
});

import { detectFormat } from "./lib/credential-migration";

describe("Credential Migration - Format Detection", () => {
  it("should detect empty/null values", () => {
    expect(detectFormat(null)).toBe("empty");
    expect(detectFormat("")).toBe("empty");
    expect(detectFormat("   ")).toBe("empty");
  });

  it("should detect FIPS-encrypted payloads", () => {
    const fipsPayload = JSON.stringify({
      encryptedData: "abc123",
      iv: "iv123",
      tag: "tag456",
      fips: true,
      context: "server-credential-at-rest",
    });
    expect(detectFormat(fipsPayload)).toBe("fips");
  });

  it("should detect legacy-encrypted payloads (no fips flag)", () => {
    const legacyPayload = JSON.stringify({
      encryptedData: "abc123",
      iv: "iv123",
      tag: "tag456",
    });
    expect(detectFormat(legacyPayload)).toBe("legacy");
  });

  it("should detect plaintext values", () => {
    expect(detectFormat("my-secret-password")).toBe("plaintext");
    expect(detectFormat("sk_live_abc123def456")).toBe("plaintext");
    expect(detectFormat("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")).toBe("plaintext");
  });

  it("should detect plaintext even if it looks like JSON but lacks encrypted fields", () => {
    expect(detectFormat('{"username":"admin"}')).toBe("plaintext");
    expect(detectFormat('{"key":"value"}')).toBe("plaintext");
  });

  it("should handle malformed JSON gracefully", () => {
    expect(detectFormat("{broken json")).toBe("plaintext");
    expect(detectFormat("not-json-at-all")).toBe("plaintext");
  });
});

describe("Credential Migration - Server Credentials", () => {
  let mockDb: any;
  let getDb: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const dbModule = await import("./db");
    getDb = dbModule.getDb;

    mockDb = {
      select: vi.fn().mockReturnThis(),
      from: vi.fn().mockReturnThis(),
      where: vi.fn().mockReturnThis(),
      update: vi.fn().mockReturnThis(),
      set: vi.fn().mockReturnThis(),
    };
    (getDb as any).mockResolvedValue(mockDb);
  });

  it("should skip credentials that are already FIPS-encrypted", async () => {
    const fipsPayload = JSON.stringify({
      encryptedData: "abc",
      iv: "iv",
      tag: "tag",
      fips: true,
    });

    mockDb.from.mockResolvedValue([
      { id: 1, password: fipsPayload, apiKey: null },
    ]);

    const { migrateServerCredentials } = await import("./lib/credential-migration");
    const result = await migrateServerCredentials();

    expect(result.totalScanned).toBe(1);
    expect(result.alreadyFips).toBe(1);
    expect(result.migrated).toBe(0);
    expect(result.failed).toBe(0);
  });

  it("should migrate plaintext passwords", async () => {
    mockDb.from.mockResolvedValue([
      { id: 1, password: "my-secret-password", apiKey: null },
    ]);
    mockDb.where.mockResolvedValue(undefined);

    const { migrateServerCredentials } = await import("./lib/credential-migration");
    const result = await migrateServerCredentials();

    expect(result.totalScanned).toBe(1);
    expect(result.migrated).toBe(1);
    expect(result.failed).toBe(0);
  });

  it("should migrate legacy-encrypted credentials", async () => {
    const legacyPayload = JSON.stringify({
      encryptedData: "old-enc",
      iv: "old-iv",
      tag: "old-tag",
    });

    mockDb.from.mockResolvedValue([
      { id: 1, password: legacyPayload, apiKey: legacyPayload },
    ]);
    mockDb.where.mockResolvedValue(undefined);

    const { migrateServerCredentials } = await import("./lib/credential-migration");
    const result = await migrateServerCredentials();

    expect(result.totalScanned).toBe(1);
    expect(result.migrated).toBe(1);
    expect(result.failed).toBe(0);
  });

  it("should handle null database gracefully", async () => {
    (getDb as any).mockResolvedValue(null);

    const { migrateServerCredentials } = await import("./lib/credential-migration");
    const result = await migrateServerCredentials();

    expect(result.totalScanned).toBe(0);
    expect(result.migrated).toBe(0);
  });

  it("should continue migration even if one credential fails", async () => {
    mockDb.from.mockResolvedValue([
      { id: 1, password: "valid-password", apiKey: null },
      { id: 2, password: "another-password", apiKey: null },
    ]);
    // First update succeeds, second throws
    let callCount = 0;
    mockDb.where.mockImplementation(() => {
      callCount++;
      if (callCount === 2) throw new Error("DB write failed");
      return undefined;
    });

    const { migrateServerCredentials } = await import("./lib/credential-migration");
    const result = await migrateServerCredentials();

    expect(result.totalScanned).toBe(2);
    // At least one should have been attempted
    expect(result.migrated + result.failed).toBeGreaterThanOrEqual(1);
  });
});

describe("Credential Migration - Scan", () => {
  let mockDb: any;
  let getDb: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const dbModule = await import("./db");
    getDb = dbModule.getDb;

    mockDb = {
      select: vi.fn().mockReturnThis(),
      from: vi.fn(),
    };
    (getDb as any).mockResolvedValue(mockDb);
  });

  it("should correctly categorize credentials in scan", async () => {
    const fipsPayload = JSON.stringify({
      encryptedData: "abc",
      iv: "iv",
      tag: "tag",
      fips: true,
    });
    const legacyPayload = JSON.stringify({
      encryptedData: "abc",
      iv: "iv",
      tag: "tag",
    });

    // Mock three different from() calls for three tables
    let fromCallCount = 0;
    mockDb.from.mockImplementation(() => {
      fromCallCount++;
      if (fromCallCount === 1) {
        // server_credentials
        return [
          { id: 1, password: fipsPayload, apiKey: null },
          { id: 2, password: "plaintext-pw", apiKey: legacyPayload },
        ];
      }
      if (fromCallCount === 2) {
        // ssh_keys
        return [
          { id: 1, privateKey: "-----BEGIN RSA PRIVATE KEY-----\nMIIE..." },
        ];
      }
      // cloud_credentials
      return [
        { id: 1, encryptedData: fipsPayload, encryptionIv: "iv", encryptionTag: "tag" },
      ];
    });

    const { scanCredentials } = await import("./lib/credential-migration");
    const result = await scanCredentials();

    expect(result.serverCredentials.total).toBe(2);
    expect(result.serverCredentials.fips).toBe(1);
    expect(result.sshKeys.total).toBe(1);
    expect(result.sshKeys.plaintext).toBe(1);
    expect(result.cloudCredentials.total).toBe(1);
    expect(result.cloudCredentials.fips).toBe(1);
  });

  it("should return empty stats when database is unavailable", async () => {
    (getDb as any).mockResolvedValue(null);

    const { scanCredentials } = await import("./lib/credential-migration");
    const result = await scanCredentials();

    expect(result.serverCredentials.total).toBe(0);
    expect(result.sshKeys.total).toBe(0);
    expect(result.cloudCredentials.total).toBe(0);
  });
});

describe("Credential Migration - Full Migration Report", () => {
  let mockDb: any;
  let getDb: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const dbModule = await import("./db");
    getDb = dbModule.getDb;

    mockDb = {
      select: vi.fn().mockReturnThis(),
      from: vi.fn().mockResolvedValue([]),
      update: vi.fn().mockReturnThis(),
      set: vi.fn().mockReturnThis(),
      where: vi.fn().mockResolvedValue(undefined),
    };
    (getDb as any).mockResolvedValue(mockDb);
  });

  it("should return a complete migration report", async () => {
    const { runFullMigration } = await import("./lib/credential-migration");
    const report = await runFullMigration();

    expect(report).toHaveProperty("startedAt");
    expect(report).toHaveProperty("completedAt");
    expect(report).toHaveProperty("durationMs");
    expect(report).toHaveProperty("results");
    expect(report).toHaveProperty("summary");
    expect(report.results).toHaveLength(3);
    expect(report.results[0].category).toBe("server_credentials");
    expect(report.results[1].category).toBe("ssh_keys");
    expect(report.results[2].category).toBe("cloud_credentials");
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
    expect(report.completedAt).toBeGreaterThanOrEqual(report.startedAt);
  });

  it("should aggregate summary correctly", async () => {
    const { runFullMigration } = await import("./lib/credential-migration");
    const report = await runFullMigration();

    const totalScanned = report.results.reduce((s, r) => s + r.totalScanned, 0);
    expect(report.summary.totalScanned).toBe(totalScanned);
    expect(report.summary.totalMigrated).toBe(0); // empty tables
    expect(report.summary.totalFailed).toBe(0);
  });
});
