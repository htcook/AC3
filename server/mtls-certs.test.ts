/**
 * Tests for the mTLS Certificate Service
 *
 * Validates ECDSA P-256 certificate generation, CA issuance,
 * client certificate signing, and certificate lifecycle management.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the database
vi.mock("./db", () => ({
  getDb: vi.fn(),
}));

// Mock credential-crypto for private key encryption
vi.mock("./lib/credential-crypto", () => ({
  encryptCredential: vi.fn((plaintext: string, context: string) => ({
    encryptedData: `enc-${plaintext.slice(0, 20)}`,
    iv: "mock-iv",
    tag: "mock-tag",
    fips: true,
    context,
  })),
  decryptCredential: vi.fn((payload: any) => {
    // Return a mock PEM private key
    return "-----BEGIN EC PRIVATE KEY-----\nMOCK\n-----END EC PRIVATE KEY-----\n";
  }),
  FIPS_CONTEXTS: {
    SSH_KEY: "ssh-private-key-at-rest",
    GENERIC: "credential-at-rest",
  },
}));

// Mock fips-crypto for key pair generation
vi.mock("./lib/fips-crypto", () => {
  const crypto = require("crypto");
  return {
    getFIPSCrypto: vi.fn(() => ({
      generateKeyPair: vi.fn((curve: string) => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
          namedCurve: curve || "prime256v1",
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });
        return { publicKey, privateKey, curve: curve || "P-256" };
      }),
      uuid: vi.fn(() => `test-uuid-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`),
    })),
  };
});

import {
  generateCACertificate,
  generateClientCertificate,
} from "./lib/mtls-certs";

describe("mTLS Certificate Generation - CA Certificate", () => {
  it("should generate a valid self-signed CA certificate", () => {
    const ca = generateCACertificate();

    expect(ca).toBeDefined();
    expect(ca.type).toBe("ca");
    expect(ca.commonName).toBe("AceofCloud Internal mTLS CA");
    expect(ca.issuer).toBe(ca.subject); // Self-signed
    expect(ca.certificate).toContain("-----BEGIN CERTIFICATE-----");
    expect(ca.certificate).toContain("-----END CERTIFICATE-----");
    expect(ca.privateKey).toContain("-----BEGIN");
    expect(ca.fingerprint).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex
    expect(ca.serialNumber).toMatch(/^[a-f0-9]+$/);
    expect(ca.status).toBe("active");
    expect(ca.validTo).toBeGreaterThan(ca.validFrom);
  });

  it("should generate CA with custom CN and validity", () => {
    const ca = generateCACertificate("Custom CA", 365);

    expect(ca.commonName).toBe("Custom CA");
    expect(ca.issuer).toBe("Custom CA");
    // 365 days in milliseconds
    const expectedDuration = 365 * 86400000;
    const actualDuration = ca.validTo - ca.validFrom;
    expect(actualDuration).toBeCloseTo(expectedDuration, -3); // within 1 second
  });

  it("should generate unique serial numbers for each CA", () => {
    const ca1 = generateCACertificate();
    const ca2 = generateCACertificate();

    expect(ca1.serialNumber).not.toBe(ca2.serialNumber);
    expect(ca1.id).not.toBe(ca2.id);
    expect(ca1.fingerprint).not.toBe(ca2.fingerprint);
  });

  it("should generate a valid DER-encoded certificate", () => {
    const ca = generateCACertificate();

    // Extract base64 content
    const b64 = ca.certificate
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s/g, "");

    // Should be valid base64
    const derBuffer = Buffer.from(b64, "base64");
    expect(derBuffer.length).toBeGreaterThan(100);

    // First byte should be 0x30 (SEQUENCE tag)
    expect(derBuffer[0]).toBe(0x30);
  });
});

describe("mTLS Certificate Generation - Client Certificate", () => {
  let caCert: any;

  beforeEach(() => {
    caCert = generateCACertificate();
  });

  it("should generate a client certificate signed by the CA", () => {
    const client = generateClientCertificate(
      caCert,
      "test-server.c2.aceofcloud.internal",
      "server-123"
    );

    expect(client).toBeDefined();
    expect(client.type).toBe("client");
    expect(client.commonName).toBe("test-server.c2.aceofcloud.internal");
    expect(client.issuer).toBe(caCert.commonName);
    expect(client.c2ServerId).toBe("server-123");
    expect(client.certificate).toContain("-----BEGIN CERTIFICATE-----");
    expect(client.privateKey).toContain("-----BEGIN");
    expect(client.status).toBe("active");
  });

  it("should generate different keys for each client cert", () => {
    const client1 = generateClientCertificate(caCert, "server1.c2", "s1");
    const client2 = generateClientCertificate(caCert, "server2.c2", "s2");

    expect(client1.fingerprint).not.toBe(client2.fingerprint);
    expect(client1.serialNumber).not.toBe(client2.serialNumber);
    expect(client1.privateKey).not.toBe(client2.privateKey);
  });

  it("should respect custom validity period", () => {
    const client = generateClientCertificate(caCert, "test.c2", "s1", 30);

    const expectedDuration = 30 * 86400000;
    const actualDuration = client.validTo - client.validFrom;
    expect(actualDuration).toBeCloseTo(expectedDuration, -3);
  });

  it("should set the issuer to the CA common name", () => {
    const customCA = generateCACertificate("My Custom CA");
    const client = generateClientCertificate(customCA, "client.c2", "s1");

    expect(client.issuer).toBe("My Custom CA");
    expect(client.subject).toBe("client.c2");
  });
});

describe("mTLS Certificate Service - Database Operations", () => {
  let mockDb: any;
  let getDb: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const dbModule = await import("./db");
    getDb = dbModule.getDb;

    mockDb = {
      execute: vi.fn().mockResolvedValue([]),
    };
    (getDb as any).mockResolvedValue(mockDb);
  });

  it("should list certificates from database", async () => {
    mockDb.execute.mockResolvedValue([
      {
        id: "cert-1",
        type: "ca",
        commonName: "Test CA",
        serialNumber: "abc123",
        issuer: "Test CA",
        subject: "Test CA",
        validFrom: Date.now(),
        validTo: Date.now() + 86400000,
        fingerprint: "abc123def456",
        certificate: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
        c2ServerId: null,
        status: "active",
        createdAt: Date.now(),
      },
    ]);

    const { listCertificates } = await import("./lib/mtls-certs");
    const certs = await listCertificates();

    expect(certs).toHaveLength(1);
    expect(certs[0].type).toBe("ca");
    expect(certs[0].commonName).toBe("Test CA");
  });

  it("should return empty list when database is unavailable", async () => {
    (getDb as any).mockResolvedValue(null);

    const { listCertificates } = await import("./lib/mtls-certs");
    const certs = await listCertificates();

    expect(certs).toEqual([]);
  });

  it("should revoke a certificate", async () => {
    mockDb.execute.mockResolvedValue(undefined);

    const { revokeCertificate } = await import("./lib/mtls-certs");
    const result = await revokeCertificate("cert-1");

    expect(result).toBe(true);
    expect(mockDb.execute).toHaveBeenCalled();
  });

  it("should return false when revoking with no database", async () => {
    (getDb as any).mockResolvedValue(null);

    const { revokeCertificate } = await import("./lib/mtls-certs");
    const result = await revokeCertificate("cert-1");

    expect(result).toBe(false);
  });

  it("should return null for mTLS config when no CA exists", async () => {
    mockDb.execute.mockResolvedValue([]);

    const { getMTLSConfigForServer } = await import("./lib/mtls-certs");
    const config = await getMTLSConfigForServer("server-1");

    expect(config).toBeNull();
  });

  it("should store certificate with encrypted private key", async () => {
    mockDb.execute.mockResolvedValue(undefined);

    const { storeCertificate, generateCACertificate } = await import("./lib/mtls-certs");
    const ca = generateCACertificate();

    await storeCertificate(ca);

    expect(mockDb.execute).toHaveBeenCalled();
  });
});

describe("mTLS Certificate Service - ensureCA", () => {
  let mockDb: any;
  let getDb: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const dbModule = await import("./db");
    getDb = dbModule.getDb;

    mockDb = {
      execute: vi.fn(),
    };
    (getDb as any).mockResolvedValue(mockDb);
  });

  it("should create a new CA if none exists", async () => {
    // First call (getActiveCACertificate) returns empty, second call (storeCertificate) succeeds
    mockDb.execute.mockResolvedValue([]);

    const { ensureCA } = await import("./lib/mtls-certs");
    const ca = await ensureCA();

    expect(ca).toBeDefined();
    expect(ca.type).toBe("ca");
    expect(ca.commonName).toBe("AceofCloud Internal mTLS CA");
  });

  it("should return existing CA if one is active", async () => {
    const existingCA = {
      id: "existing-ca",
      type: "ca",
      commonName: "Existing CA",
      serialNumber: "abc",
      issuer: "Existing CA",
      subject: "Existing CA",
      validFrom: Date.now(),
      validTo: Date.now() + 86400000 * 365,
      fingerprint: "abc123",
      certificate: "-----BEGIN CERTIFICATE-----\nEXISTING\n-----END CERTIFICATE-----",
      encryptedPrivateKey: JSON.stringify({ encryptedData: "enc", iv: "iv", tag: "tag", fips: true }),
      status: "active",
      createdAt: Date.now(),
    };

    mockDb.execute.mockResolvedValue([existingCA]);

    const { ensureCA } = await import("./lib/mtls-certs");
    const ca = await ensureCA();

    expect(ca.commonName).toBe("Existing CA");
  });
});

describe("mTLS Certificate - Crypto Properties", () => {
  it("should use ECDSA P-256 curve for all certificates", () => {
    const ca = generateCACertificate();
    // The certificate should be generated using P-256
    // We verify by checking the DER structure contains the P-256 OID
    const b64 = ca.certificate
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s/g, "");
    const der = Buffer.from(b64, "base64");

    // P-256 OID: 1.2.840.10045.3.1.7 → encoded as 06 08 2a 86 48 ce 3d 03 01 07
    const p256OID = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    expect(der.includes(p256OID)).toBe(true);
  });

  it("should use SHA-256 for certificate signatures", () => {
    const ca = generateCACertificate();
    const b64 = ca.certificate
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s/g, "");
    const der = Buffer.from(b64, "base64");

    // ECDSA with SHA-256 OID: 1.2.840.10045.4.3.2 → 06 08 2a 86 48 ce 3d 04 03 02
    const ecdsaSha256OID = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    expect(der.includes(ecdsaSha256OID)).toBe(true);
  });

  it("should generate certificates with positive serial numbers", () => {
    for (let i = 0; i < 10; i++) {
      const ca = generateCACertificate();
      const serialBytes = Buffer.from(ca.serialNumber, "hex");
      // High bit should be clear (positive integer)
      expect(serialBytes[0] & 0x80).toBe(0);
    }
  });

  it("should generate SHA-256 fingerprints", () => {
    const ca = generateCACertificate();
    // SHA-256 produces 64 hex characters
    expect(ca.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });
});
