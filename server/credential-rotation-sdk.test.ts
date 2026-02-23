/**
 * Tests for Credential Auto-Rotation Engine (Real SDK Integration)
 *
 * These tests mock the underlying cloud SDK clients to verify the rotation
 * logic, error handling, validation retries, and rollback behaviour without
 * making actual API calls.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

// ─── Shared mock send functions ──────────────────────────────────────────────

let iamSendFn: ReturnType<typeof vi.fn>;
let stsSendFn: ReturnType<typeof vi.fn>;
let azureGetTokenFn: ReturnType<typeof vi.fn>;
let graphApiFn: ReturnType<typeof vi.fn>;
let graphPostFn: ReturnType<typeof vi.fn>;
let graphGetFn: ReturnType<typeof vi.fn>;
let gcpGetAccessTokenFn: ReturnType<typeof vi.fn>;
let fetchFn: ReturnType<typeof vi.fn>;

// ─── Mock AWS SDK ────────────────────────────────────────────────────────────

vi.mock("@aws-sdk/client-iam", () => {
  // Use a module-level reference that tests can swap
  const _send = (...args: any[]) => iamSendFn(...args);
  return {
    IAMClient: vi.fn().mockImplementation(() => ({ send: _send })),
    CreateAccessKeyCommand: vi.fn().mockImplementation((i: any) => ({ _type: "CreateAccessKey", ...i })),
    DeleteAccessKeyCommand: vi.fn().mockImplementation((i: any) => ({ _type: "DeleteAccessKey", ...i })),
    ListAccessKeysCommand: vi.fn().mockImplementation((i: any) => ({ _type: "ListAccessKeys", ...i })),
    GetUserCommand: vi.fn().mockImplementation((i: any) => ({ _type: "GetUser", ...i })),
  };
});

vi.mock("@aws-sdk/client-sts", () => {
  const _send = (...args: any[]) => stsSendFn(...args);
  return {
    STSClient: vi.fn().mockImplementation(() => ({ send: _send })),
    GetCallerIdentityCommand: vi.fn().mockImplementation((i: any) => ({ _type: "GetCallerIdentity", ...i })),
  };
});

// ─── Mock Azure SDK ──────────────────────────────────────────────────────────

vi.mock("@azure/identity", () => ({
  ClientSecretCredential: vi.fn().mockImplementation(() => ({
    getToken: (...args: any[]) => azureGetTokenFn(...args),
  })),
}));

vi.mock("@microsoft/microsoft-graph-client", () => ({
  Client: {
    init: vi.fn().mockImplementation(() => ({
      api: (path: string) => {
        graphApiFn(path);
        return {
          filter: () => ({
            select: () => ({
              get: (...args: any[]) => graphGetFn(...args),
            }),
          }),
          post: (...args: any[]) => graphPostFn(...args),
        };
      },
    })),
  },
}));

// ─── Mock GCP (google-auth-library) ──────────────────────────────────────────

vi.mock("google-auth-library", () => ({
  GoogleAuth: vi.fn().mockImplementation(() => ({
    getClient: vi.fn().mockImplementation(async () => ({
      getAccessToken: (...args: any[]) => gcpGetAccessTokenFn(...args),
    })),
  })),
}));

// ─── Import after mocks ─────────────────────────────────────────────────────

import {
  rotateAwsAccessKey,
  deleteAwsAccessKey,
  listAwsAccessKeys,
  rotateAzureClientSecret,
  removeAzurePassword,
  rotateGcpServiceAccountKey,
  deleteGcpServiceAccountKey,
  listGcpServiceAccountKeys,
  isPolicyDueForRotation,
  calculateNextRotation,
  evaluatePolicies,
  generateRotationSummary,
  DEFAULT_ROTATION_INTERVALS,
  type RotationPolicy,
  type RotationAuditEntry,
} from "./lib/credential-auto-rotation";

// ─── Test Setup ──────────────────────────────────────────────────────────────

const originalFetch = globalThis.fetch;

beforeEach(() => {
  iamSendFn = vi.fn();
  stsSendFn = vi.fn();
  azureGetTokenFn = vi.fn();
  graphApiFn = vi.fn();
  graphPostFn = vi.fn();
  graphGetFn = vi.fn();
  gcpGetAccessTokenFn = vi.fn();
  fetchFn = vi.fn();
  globalThis.fetch = fetchFn;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

// ═════════════════════════════════════════════════════════════════════════════
// AWS IAM Key Rotation Tests
// ═════════════════════════════════════════════════════════════════════════════

describe("AWS IAM Key Rotation (Real SDK)", () => {
  const awsCreds = {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
  };

  it("successfully rotates AWS access key", async () => {
    // When userName is provided, GetUser is skipped.
    // Call 1 (IAM): CreateAccessKey → new key pair
    iamSendFn.mockResolvedValueOnce({
      AccessKey: {
        AccessKeyId: "AKIANEWKEY123456789",
        SecretAccessKey: "newSecretKey123456789",
        UserName: "test-user",
      },
    });
    // STS GetCallerIdentity → validation of new key
    stsSendFn.mockResolvedValueOnce({ Account: "123456789012" });

    const result = await rotateAwsAccessKey(awsCreds, "test-user");

    expect(result.success).toBe(true);
    expect(result.provider).toBe("aws");
    expect(result.oldKeyId).toBe("AKIAIOSFODNN7EXAMPLE");
    expect(result.newKeyId).toBe("AKIANEWKEY123456789");
    expect(result.newCredentials).toBeTruthy();
    expect(result.newCredentials!.accessKeyId).toBe("AKIANEWKEY123456789");
    expect(result.newCredentials!.secretAccessKey).toBe("newSecretKey123456789");
    expect(result.newCredentials!.region).toBe("us-east-1");
    expect(result.error).toBeNull();
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("fails with incomplete credentials", async () => {
    const result = await rotateAwsAccessKey({ accessKeyId: "", secretAccessKey: "" });
    expect(result.success).toBe(false);
    expect(result.error).toContain("incomplete");
    expect(result.newCredentials).toBeNull();
  });

  it("handles CreateAccessKey failure", async () => {
    // When userName is provided, first IAM call is CreateAccessKey directly
    iamSendFn.mockRejectedValueOnce(new Error("LimitExceededException: Cannot exceed quota for AccessKeysPerUser: 2"));

    const result = await rotateAwsAccessKey(awsCreds, "test-user");

    expect(result.success).toBe(false);
    expect(result.error).toContain("LimitExceededException");
  });

  it("rolls back new key when STS validation fails", async () => {
    // First IAM call: CreateAccessKey (userName provided, so GetUser skipped)
    iamSendFn.mockResolvedValueOnce({
      AccessKey: {
        AccessKeyId: "AKIANEWKEY123456789",
        SecretAccessKey: "newSecretKey123456789",
      },
    });
    // STS validation fails all 3 retries
    stsSendFn.mockRejectedValue(new Error("InvalidClientTokenId"));
    // Rollback delete call (IAM)
    iamSendFn.mockResolvedValueOnce({});

    const result = await rotateAwsAccessKey(awsCreds, "test-user");

    expect(result.success).toBe(false);
    expect(result.error).toContain("STS validation");
  });

  it("resolves username from STS when GetUser fails", async () => {
    // GetUser fails
    iamSendFn.mockRejectedValueOnce(new Error("AccessDenied"));
    // STS GetCallerIdentity returns ARN for username resolution
    stsSendFn.mockResolvedValueOnce({
      Account: "123456789012",
      Arn: "arn:aws:iam::123456789012:user/fallback-user",
    });
    // CreateAccessKey
    iamSendFn.mockResolvedValueOnce({
      AccessKey: {
        AccessKeyId: "AKIANEWKEY999999999",
        SecretAccessKey: "newSecret999",
      },
    });
    // STS validation for new key
    stsSendFn.mockResolvedValueOnce({ Account: "123456789012" });

    const result = await rotateAwsAccessKey(awsCreds);

    expect(result.success).toBe(true);
    expect(result.newCredentials!.userName).toBe("fallback-user");
  });

  it("deletes old AWS access key", async () => {
    iamSendFn.mockResolvedValueOnce({});

    const result = await deleteAwsAccessKey(awsCreds, "AKIAOLDKEY123456789", "test-user");
    expect(result.success).toBe(true);
    expect(result.error).toBeNull();
  });

  it("handles delete failure gracefully", async () => {
    iamSendFn.mockRejectedValueOnce(new Error("NoSuchEntity"));

    const result = await deleteAwsAccessKey(awsCreds, "AKIAOLDKEY123456789", "test-user");
    expect(result.success).toBe(false);
    expect(result.error).toContain("NoSuchEntity");
  });

  it("lists AWS access keys", async () => {
    iamSendFn.mockResolvedValueOnce({
      AccessKeyMetadata: [
        { AccessKeyId: "AKIAKEY1", Status: "Active", CreateDate: new Date("2026-01-01") },
        { AccessKeyId: "AKIAKEY2", Status: "Inactive", CreateDate: new Date("2025-06-01") },
      ],
    });

    const result = await listAwsAccessKeys(awsCreds, "test-user");
    expect(result.error).toBeNull();
    expect(result.keys).toHaveLength(2);
    expect(result.keys[0].accessKeyId).toBe("AKIAKEY1");
    expect(result.keys[0].status).toBe("Active");
    expect(result.keys[1].status).toBe("Inactive");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Azure Credential Rotation Tests
// ═════════════════════════════════════════════════════════════════════════════

describe("Azure Credential Rotation (Real SDK)", () => {
  const azureCreds = {
    tenantId: "12345678-1234-1234-1234-123456789012",
    clientId: "abcdefgh-abcd-abcd-abcd-abcdefghijkl",
    clientSecret: "old-secret-value",
  };

  it("successfully rotates Azure client secret", async () => {
    // Token for current creds
    azureGetTokenFn.mockResolvedValueOnce({ token: "current-token-123" });
    // Graph: find application
    graphGetFn.mockResolvedValueOnce({ value: [{ id: "app-object-id-123" }] });
    // Graph: addPassword
    graphPostFn.mockResolvedValueOnce({ secretText: "new-secret-value-xyz", keyId: "new-key-id-456" });
    // Token for new creds (validation)
    azureGetTokenFn.mockResolvedValueOnce({ token: "new-token-456" });

    const result = await rotateAzureClientSecret(azureCreds);

    expect(result.success).toBe(true);
    expect(result.provider).toBe("azure");
    expect(result.newCredentials).toBeTruthy();
    expect(result.newCredentials!.clientSecret).toBe("new-secret-value-xyz");
    expect(result.newCredentials!.tenantId).toBe(azureCreds.tenantId);
    expect(result.newCredentials!.clientId).toBe(azureCreds.clientId);
    expect(result.newCredentials!.applicationObjectId).toBe("app-object-id-123");
    expect(result.newCredentials!.keyId).toBe("new-key-id-456");
    expect(result.error).toBeNull();
  });

  it("fails with incomplete Azure credentials", async () => {
    const result = await rotateAzureClientSecret({ tenantId: "", clientId: "", clientSecret: "" });
    expect(result.success).toBe(false);
    expect(result.error).toContain("incomplete");
  });

  it("handles authentication failure", async () => {
    azureGetTokenFn.mockRejectedValueOnce(new Error("AADSTS7000215: Invalid client secret"));

    const result = await rotateAzureClientSecret(azureCreds);
    expect(result.success).toBe(false);
    expect(result.error).toContain("Invalid client secret");
  });

  it("handles application not found", async () => {
    azureGetTokenFn.mockResolvedValueOnce({ token: "token-123" });
    graphGetFn.mockResolvedValueOnce({ value: [] });

    const result = await rotateAzureClientSecret(azureCreds);
    expect(result.success).toBe(false);
    expect(result.error).toContain("Could not find Azure application");
  });

  it("uses provided applicationObjectId", async () => {
    azureGetTokenFn.mockResolvedValueOnce({ token: "token-123" });
    graphPostFn.mockResolvedValueOnce({ secretText: "new-secret-direct", keyId: "direct-key-id" });
    azureGetTokenFn.mockResolvedValueOnce({ token: "new-token" });

    const result = await rotateAzureClientSecret(azureCreds, "known-object-id");
    expect(result.success).toBe(true);
    expect(result.newCredentials!.applicationObjectId).toBe("known-object-id");
  });

  it("removes old Azure password", async () => {
    azureGetTokenFn.mockResolvedValueOnce({ token: "token-123" });
    graphPostFn.mockResolvedValueOnce({});

    const result = await removeAzurePassword(azureCreds, "app-obj-id", "old-key-id");
    expect(result.success).toBe(true);
    expect(result.error).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// GCP Service Account Key Rotation Tests
// ═════════════════════════════════════════════════════════════════════════════

describe("GCP Service Account Key Rotation (Real SDK)", () => {
  const gcpCreds = {
    projectId: "my-project-123",
    clientEmail: "sa@my-project-123.iam.gserviceaccount.com",
    privateKey: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
    privateKeyId: "old-key-id-abc",
  };

  it("successfully rotates GCP service account key", async () => {
    gcpGetAccessTokenFn.mockResolvedValueOnce({ token: "gcp-access-token-123" });

    const newKeyJson = {
      project_id: "my-project-123",
      client_email: "sa@my-project-123.iam.gserviceaccount.com",
      private_key: "-----BEGIN RSA PRIVATE KEY-----\nNEWKEYDATA...\n-----END RSA PRIVATE KEY-----",
      private_key_id: "new-key-id-xyz",
      token_uri: "https://oauth2.googleapis.com/token",
    };

    fetchFn.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        name: "projects/my-project-123/serviceAccounts/sa@my-project-123.iam.gserviceaccount.com/keys/new-key-id-xyz",
        privateKeyData: Buffer.from(JSON.stringify(newKeyJson)).toString("base64"),
      }),
    });

    const result = await rotateGcpServiceAccountKey(gcpCreds);

    expect(result.success).toBe(true);
    expect(result.provider).toBe("gcp");
    expect(result.oldKeyId).toBe("old-key-id-abc");
    expect(result.newKeyId).toBe("new-key-id-xyz");
    expect(result.newCredentials).toBeTruthy();
    expect(result.newCredentials!.projectId).toBe("my-project-123");
    expect(result.newCredentials!.privateKey).toContain("NEWKEYDATA");
    expect(result.error).toBeNull();
  });

  it("fails with incomplete GCP credentials", async () => {
    const result = await rotateGcpServiceAccountKey({ projectId: "", clientEmail: "", privateKey: "" });
    expect(result.success).toBe(false);
    expect(result.error).toContain("incomplete");
  });

  it("handles GCP authentication failure", async () => {
    gcpGetAccessTokenFn.mockResolvedValueOnce({ token: null });

    const result = await rotateGcpServiceAccountKey(gcpCreds);
    expect(result.success).toBe(false);
    expect(result.error).toContain("Failed to authenticate");
  });

  it("handles GCP IAM createKey API failure", async () => {
    gcpGetAccessTokenFn.mockResolvedValueOnce({ token: "gcp-token" });

    fetchFn.mockResolvedValueOnce({
      ok: false,
      status: 403,
      text: async () => "Permission denied on resource project my-project-123",
    });

    const result = await rotateGcpServiceAccountKey(gcpCreds);
    expect(result.success).toBe(false);
    expect(result.error).toContain("403");
    expect(result.error).toContain("Permission denied");
  });

  it("deletes old GCP service account key", async () => {
    gcpGetAccessTokenFn.mockResolvedValueOnce({ token: "gcp-token" });
    fetchFn.mockResolvedValueOnce({ ok: true });

    const result = await deleteGcpServiceAccountKey(gcpCreds, "old-key-id-abc");
    expect(result.success).toBe(true);
    expect(result.error).toBeNull();
  });

  it("lists GCP service account keys", async () => {
    gcpGetAccessTokenFn.mockResolvedValueOnce({ token: "gcp-token" });

    fetchFn.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        keys: [
          {
            name: "projects/my-project/serviceAccounts/sa@proj.iam.gserviceaccount.com/keys/key1",
            validAfterTime: "2026-01-01T00:00:00Z",
            validBeforeTime: "2028-01-01T00:00:00Z",
            keyType: "USER_MANAGED",
          },
        ],
      }),
    });

    const result = await listGcpServiceAccountKeys(gcpCreds);
    expect(result.error).toBeNull();
    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].keyType).toBe("USER_MANAGED");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Policy Evaluation Tests
// ═════════════════════════════════════════════════════════════════════════════

describe("Policy Evaluation", () => {
  const basePolicy: RotationPolicy = {
    id: 1, credentialId: 1, provider: "aws", credentialName: "Test Credential",
    enabled: true, rotationIntervalDays: 90, lastRotatedAt: null, nextRotationAt: null,
    maxRetries: 3, retryCount: 0, createdBy: "test", createdAt: new Date(), updatedAt: new Date(),
  };

  it("marks never-rotated policy as due", () => {
    expect(isPolicyDueForRotation(basePolicy)).toBe(true);
  });

  it("marks disabled policy as not due", () => {
    expect(isPolicyDueForRotation({ ...basePolicy, enabled: false })).toBe(false);
  });

  it("marks recently-rotated policy as not due", () => {
    expect(isPolicyDueForRotation({
      ...basePolicy,
      lastRotatedAt: new Date(),
      nextRotationAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    })).toBe(false);
  });

  it("marks overdue policy as due", () => {
    expect(isPolicyDueForRotation({
      ...basePolicy,
      lastRotatedAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
      nextRotationAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
    })).toBe(true);
  });

  it("evaluates batch policies correctly", () => {
    const due = evaluatePolicies([
      basePolicy,
      { ...basePolicy, id: 2, enabled: false },
      { ...basePolicy, id: 3, lastRotatedAt: new Date(), nextRotationAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) },
    ]);
    expect(due).toHaveLength(1);
    expect(due[0].id).toBe(1);
  });
});

describe("Rotation Scheduling", () => {
  it("calculates next rotation date correctly", () => {
    const next = calculateNextRotation(new Date("2026-01-01T00:00:00Z"), 90);
    expect(next.toISOString().split("T")[0]).toBe("2026-03-31");
  });

  it("uses correct default intervals per provider", () => {
    expect(DEFAULT_ROTATION_INTERVALS.aws).toBe(90);
    expect(DEFAULT_ROTATION_INTERVALS.azure).toBe(180);
    expect(DEFAULT_ROTATION_INTERVALS.gcp).toBe(90);
  });
});

describe("Rotation Summary", () => {
  it("generates accurate summary", () => {
    const policies: RotationPolicy[] = [
      {
        id: 1, credentialId: 1, provider: "aws", credentialName: "AWS Key",
        enabled: true, rotationIntervalDays: 90, lastRotatedAt: null,
        nextRotationAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        maxRetries: 3, retryCount: 0, createdBy: "test", createdAt: new Date(), updatedAt: new Date(),
      },
      {
        id: 2, credentialId: 2, provider: "azure", credentialName: "Azure Secret",
        enabled: false, rotationIntervalDays: 180, lastRotatedAt: new Date(),
        nextRotationAt: null, maxRetries: 3, retryCount: 0, createdBy: "test",
        createdAt: new Date(), updatedAt: new Date(),
      },
    ];

    const auditEntries: RotationAuditEntry[] = [{
      id: 1, policyId: 1, credentialId: 1, provider: "aws",
      status: "success", oldKeyIdentifier: "old", newKeyIdentifier: "new",
      errorMessage: null, durationMs: 150, initiatedBy: "test", createdAt: new Date(),
    }];

    const summary = generateRotationSummary(policies, auditEntries);
    expect(summary.totalPolicies).toBe(2);
    expect(summary.enabledPolicies).toBe(1);
    expect(summary.duePolicies).toBe(1);
    expect(summary.recentRotations).toBe(1);
    expect(summary.failedRotations).toBe(0);
    expect(summary.nextRotationDate).toBeTruthy();
  });
});
