import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for Client-Side Encryption (CSE) — envelope encryption for sensitive artifacts.
 * Tests cover: config resolution, encryption/decryption round-trip, key wrapping,
 * metadata sidecar creation, error handling, and CSE info diagnostics.
 */

// Mock S3 client — track PutObject and GetObject calls
const mockSend = vi.fn().mockResolvedValue({});
vi.mock("@aws-sdk/client-s3", () => ({
  S3Client: vi.fn().mockImplementation(() => ({
    send: mockSend,
  })),
  PutObjectCommand: vi.fn().mockImplementation((params) => ({ ...params, _type: "Put" })),
  GetObjectCommand: vi.fn().mockImplementation((params) => ({ ...params, _type: "Get" })),
  HeadObjectCommand: vi.fn().mockImplementation((params) => params),
  DeleteObjectCommand: vi.fn().mockImplementation((params) => params),
}));

vi.mock("@aws-sdk/s3-request-presigner", () => ({
  getSignedUrl: vi.fn().mockResolvedValue("https://signed-url.example.com/encrypted-key"),
}));

describe("Client-Side Encryption (CSE)", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    mockSend.mockReset();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("CSE Configuration", () => {
    it("should report CSE disabled when S3_CSE_ENABLED is not set", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";

      const { getCSEInfo } = await import("./do-storage");
      const info = getCSEInfo();
      expect(info.enabled).toBe(false);
      expect(info.mode).toBe("disabled");
    });

    it("should report CSE disabled when key ARN is missing", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      // No S3_CSE_KEY_ARN

      const { getCSEInfo } = await import("./do-storage");
      const info = getCSEInfo();
      expect(info.enabled).toBe(false);
    });

    it("should detect local key mode from non-ARN key material", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "my-super-secret-passphrase-for-dev";

      const { getCSEInfo } = await import("./do-storage");
      const info = getCSEInfo();
      expect(info.enabled).toBe(true);
      expect(info.mode).toBe("local");
      expect(info.keyId).toMatch(/^local:/);
    });

    it("should detect KMS mode from AWS KMS ARN", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "arn:aws:kms:us-gov-west-1:123456789:key/abc-def-ghi";

      const { getCSEInfo } = await import("./do-storage");
      const info = getCSEInfo();
      expect(info.enabled).toBe(true);
      expect(info.mode).toBe("kms");
      expect(info.keyId).toBe("arn:aws:kms:us-gov-west-1:123456789:key/abc-def-ghi");
    });

    it("should detect KMS mode from GovCloud ARN format", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "arn:aws-us-gov:kms:us-gov-west-1:123456789:key/gov-key-id";

      const { getCSEInfo } = await import("./do-storage");
      const info = getCSEInfo();
      expect(info.enabled).toBe(true);
      expect(info.mode).toBe("kms");
    });
  });

  describe("Encryption / Decryption Round-Trip (Local Mode)", () => {
    it("should encrypt and store data with CSE metadata sidecar", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "encrypted-bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "test-passphrase-for-unit-tests";
      process.env.S3_SSE_ALGORITHM = "aws:kms"; // Also has SSE (dual-layer)

      const { doStoragePutEncrypted } = await import("./do-storage");
      const result = await doStoragePutEncrypted(
        "exploits/custom-rce.py",
        "#!/usr/bin/env python3\nimport socket\n# RCE exploit code...",
        "text/x-python"
      );

      expect(result.key).toBe("exploits/custom-rce.py");
      expect(result.metadata.algorithm).toBe("aes-256-gcm");
      expect(result.metadata.version).toBe("1");
      expect(result.metadata.iv).toBeTruthy();
      expect(result.metadata.encryptedDEK).toBeTruthy();
      expect(result.metadata.authTag).toBeTruthy();
      expect(result.metadata.keyId).toMatch(/^local:/);

      // Verify two PutObject calls: ciphertext + metadata sidecar
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it("should produce different ciphertext for same plaintext (random DEK)", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "encrypted-bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "test-passphrase";

      const { doStoragePutEncrypted } = await import("./do-storage");

      const result1 = await doStoragePutEncrypted("test/file1.txt", "same content");
      const result2 = await doStoragePutEncrypted("test/file2.txt", "same content");

      // Different IVs and DEKs should produce different metadata
      expect(result1.metadata.iv).not.toBe(result2.metadata.iv);
      expect(result1.metadata.encryptedDEK).not.toBe(result2.metadata.encryptedDEK);
    });

    it("should decrypt data correctly (full round-trip)", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "encrypted-bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "round-trip-test-key";

      // We need to capture what was stored and return it on Get
      const storedObjects: Record<string, Buffer> = {};

      mockSend.mockImplementation(async (cmd: any) => {
        if (cmd._type === "Put") {
          storedObjects[cmd.Key] = Buffer.isBuffer(cmd.Body) ? cmd.Body : Buffer.from(cmd.Body);
          return {};
        }
        if (cmd._type === "Get") {
          const data = storedObjects[cmd.Key];
          if (!data) throw new Error(`Object not found: ${cmd.Key}`);
          return { Body: data };
        }
        return {};
      });

      const { doStoragePutEncrypted, doStorageGetDecrypted } = await import("./do-storage");

      const originalData = "TOP SECRET: exploit payload with credentials\npassword=hunter2";
      await doStoragePutEncrypted("secrets/creds.txt", originalData, "text/plain");

      const decrypted = await doStorageGetDecrypted("secrets/creds.txt");
      expect(decrypted.data.toString("utf-8")).toBe(originalData);
      expect(decrypted.originalContentType).toBe("text/plain");
      expect(decrypted.metadata.algorithm).toBe("aes-256-gcm");
    });

    it("should handle binary data (Buffer) correctly", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "encrypted-bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "binary-test-key";

      const storedObjects: Record<string, Buffer> = {};
      mockSend.mockImplementation(async (cmd: any) => {
        if (cmd._type === "Put") {
          storedObjects[cmd.Key] = Buffer.isBuffer(cmd.Body) ? cmd.Body : Buffer.from(cmd.Body);
          return {};
        }
        if (cmd._type === "Get") {
          const data = storedObjects[cmd.Key];
          if (!data) throw new Error(`Object not found: ${cmd.Key}`);
          return { Body: data };
        }
        return {};
      });

      const { doStoragePutEncrypted, doStorageGetDecrypted } = await import("./do-storage");

      // Create a binary payload (simulating a compiled exploit)
      const binaryData = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0xff, 0xfe]);
      await doStoragePutEncrypted("exploits/binary.elf", binaryData, "application/x-elf");

      const decrypted = await doStorageGetDecrypted("exploits/binary.elf");
      expect(Buffer.compare(decrypted.data, binaryData)).toBe(0);
      expect(decrypted.originalContentType).toBe("application/x-elf");
    });

    it("should fail decryption with wrong key", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "encrypted-bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "correct-key";

      const storedObjects: Record<string, Buffer> = {};
      mockSend.mockImplementation(async (cmd: any) => {
        if (cmd._type === "Put") {
          storedObjects[cmd.Key] = Buffer.isBuffer(cmd.Body) ? cmd.Body : Buffer.from(cmd.Body);
          return {};
        }
        if (cmd._type === "Get") {
          const data = storedObjects[cmd.Key];
          if (!data) throw new Error(`Object not found: ${cmd.Key}`);
          return { Body: data };
        }
        return {};
      });

      const mod1 = await import("./do-storage");
      await mod1.doStoragePutEncrypted("secrets/file.txt", "secret data");

      // Reset and reimport with different key
      vi.resetModules();
      process.env.S3_CSE_KEY_ARN = "wrong-key";

      // Re-mock after reset
      vi.mock("@aws-sdk/client-s3", () => ({
        S3Client: vi.fn().mockImplementation(() => ({ send: mockSend })),
        PutObjectCommand: vi.fn().mockImplementation((params) => ({ ...params, _type: "Put" })),
        GetObjectCommand: vi.fn().mockImplementation((params) => ({ ...params, _type: "Get" })),
        HeadObjectCommand: vi.fn().mockImplementation((params) => params),
        DeleteObjectCommand: vi.fn().mockImplementation((params) => params),
      }));
      vi.mock("@aws-sdk/s3-request-presigner", () => ({
        getSignedUrl: vi.fn().mockResolvedValue("https://signed-url.example.com/key"),
      }));

      const mod2 = await import("./do-storage");

      // Decryption should fail with wrong key (GCM auth tag mismatch)
      await expect(mod2.doStorageGetDecrypted("secrets/file.txt")).rejects.toThrow();
    });
  });

  describe("Error Handling", () => {
    it("should throw when CSE is not enabled but encrypt is called", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";
      // CSE not enabled

      const { doStoragePutEncrypted } = await import("./do-storage");
      await expect(
        doStoragePutEncrypted("test.txt", "data")
      ).rejects.toThrow(/not enabled/i);
    });

    it("should throw when CSE is not enabled but decrypt is called", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";

      const { doStorageGetDecrypted } = await import("./do-storage");
      await expect(
        doStorageGetDecrypted("test.txt")
      ).rejects.toThrow(/not enabled/i);
    });

    it("should throw when KMS mode is used without @aws-sdk/client-kms", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "arn:aws:kms:us-gov-west-1:123456:key/abc";

      const { doStoragePutEncrypted } = await import("./do-storage");
      await expect(
        doStoragePutEncrypted("test.txt", "data")
      ).rejects.toThrow(/client-kms/i);
    });
  });

  describe("CSE Metadata Structure", () => {
    it("should store metadata sidecar with correct structure", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "encrypted-bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "metadata-test-key";

      let metadataPayload: string = "";
      mockSend.mockImplementation(async (cmd: any) => {
        if (cmd._type === "Put" && cmd.Key.endsWith(".cse-meta.json")) {
          metadataPayload = cmd.Body.toString("utf-8");
        }
        return {};
      });

      const { doStoragePutEncrypted } = await import("./do-storage");
      await doStoragePutEncrypted("roe/engagement-123.pdf", "RoE document content", "application/pdf");

      const meta = JSON.parse(metadataPayload);
      expect(meta.algorithm).toBe("aes-256-gcm");
      expect(meta.version).toBe("1");
      expect(meta.iv).toBeTruthy();
      expect(meta.encryptedDEK).toBeTruthy();
      expect(meta.authTag).toBeTruthy();
      expect(meta.keyId).toMatch(/^local:/);
      expect(meta.originalContentType).toBe("application/pdf");
      expect(meta.encryptedAt).toBeTruthy();

      // Verify IV is 12 bytes (base64 of 12 bytes = 16 chars)
      const ivBytes = Buffer.from(meta.iv, "base64");
      expect(ivBytes.length).toBe(12);

      // Verify auth tag is 16 bytes (base64 of 16 bytes = 24 chars)
      const tagBytes = Buffer.from(meta.authTag, "base64");
      expect(tagBytes.length).toBe(16);
    });

    it("should store metadata at {key}.cse-meta.json path", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "encrypted-bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "path-test-key";

      const putKeys: string[] = [];
      mockSend.mockImplementation(async (cmd: any) => {
        if (cmd._type === "Put") {
          putKeys.push(cmd.Key);
        }
        return {};
      });

      const { doStoragePutEncrypted } = await import("./do-storage");
      await doStoragePutEncrypted("exploits/custom/rce-v2.py", "exploit code");

      expect(putKeys).toContain("exploits/custom/rce-v2.py");
      expect(putKeys).toContain("exploits/custom/rce-v2.py.cse-meta.json");
    });
  });

  describe("resetCSEConfig", () => {
    it("should allow reconfiguration after reset", async () => {
      process.env.S3_ENDPOINT = "https://s3.us-gov-west-1.amazonaws.com";
      process.env.S3_ACCESS_KEY = "key";
      process.env.S3_SECRET_KEY = "secret";
      process.env.S3_BUCKET = "bucket";
      process.env.S3_REGION = "us-gov-west-1";
      process.env.S3_CSE_ENABLED = "true";
      process.env.S3_CSE_KEY_ARN = "first-key";

      const { getCSEInfo, resetCSEConfig } = await import("./do-storage");

      const info1 = getCSEInfo();
      expect(info1.enabled).toBe(true);
      expect(info1.keyId).toMatch(/^local:/);

      // Change key and reset
      process.env.S3_CSE_KEY_ARN = "arn:aws:kms:us-gov-west-1:123:key/new";
      resetCSEConfig();

      const info2 = getCSEInfo();
      expect(info2.mode).toBe("kms");
    });
  });
});
