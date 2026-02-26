/**
 * FIPS Audit Scheduler Tests
 *
 * Tests the scheduled FIPS compliance audit, degradation detection,
 * and owner notification logic.
 *
 * The source (server/lib/fips-audit-scheduler.ts) imports:
 *   - "../db" → resolved from test file as "./db"
 *   - "../../drizzle/schema" → same
 *   - "./fips-crypto" → "./lib/fips-crypto"
 *   - "../_core/notification" → "./_core/notification"
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Shared mock state ──────────────────────────────────────────────────

let mockPreviousAuditRows: any[];
let mockInsertedRows: any[];

// ─── Mock notification ──────────────────────────────────────────────────

const mockNotifyOwner = vi.fn();
vi.mock("./_core/notification", () => ({
  notifyOwner: (...args: any[]) => mockNotifyOwner(...args),
}));

// ─── Mock drizzle-orm ───────────────────────────────────────────────────

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((a, b) => ({ _type: "eq", field: a, value: b })),
  desc: vi.fn((a) => ({ _type: "desc", field: a })),
}));

// ─── Mock schema ────────────────────────────────────────────────────────

vi.mock("../../drizzle/schema", () => ({
  fipsComplianceRecords: {
    id: "fips_compliance_records.id",
    checkType: "fips_compliance_records.checkType",
    status: "fips_compliance_records.status",
  },
}));

// ─── Mock FIPS crypto ───────────────────────────────────────────────────

vi.mock("./lib/fips-crypto", () => ({
  getFIPSCrypto: () => ({
    getComplianceReport: () => ({
      fipsProviderActive: false,
      complianceLevel: "software-only",
      opensslVersion: "OpenSSL 3.0.2",
      tlsCiphers: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
      approvedAlgorithms: ["aes-256-gcm", "sha-256", "ecdsa-p256"],
      prohibitedAlgorithms: ["des", "md5", "rc4"],
    }),
    encrypt: (data: string, context: string) => ({
      ciphertext: Buffer.from(data).toString("base64"),
      iv: "test-iv",
      tag: "test-tag",
      context,
    }),
    decrypt: (encrypted: any) => Buffer.from(encrypted.ciphertext, "base64"),
    generateKeyPair: () => ({
      privateKey: "mock-private-key",
      publicKey: "mock-public-key",
    }),
    sign: () => "mock-signature",
    verify: () => true,
    hmac: (data: string) => ({ mac: "mock-hmac", data }),
    verifyHmac: () => true,
    hashPassword: () => ({
      hash: "mock-hash",
      salt: "mock-salt",
      iterations: 600000,
    }),
    verifyPassword: () => true,
  }),
}));

// ─── Mock DB ────────────────────────────────────────────────────────────

vi.mock("./db", () => ({
  getDb: vi.fn(async () => ({
    insert: () => ({
      values: (row: any) => {
        mockInsertedRows.push(row);
        return Promise.resolve(undefined);
      },
    }),
    select: () => ({
      from: () => ({
        where: () => ({
          orderBy: () => ({
            limit: () => {
              // Return the most recent full_audit record.
              // The scheduler just inserted new records, but the mock
              // returns what we set as "previous" audit.
              // On the FIRST call, return the previous audit data.
              // The scheduler calls this once to find the previous audit.
              const rows = mockPreviousAuditRows.splice(0, 1);
              return Promise.resolve(rows);
            },
          }),
        }),
      }),
    }),
  })),
}));

// ─── Import SUT ─────────────────────────────────────────────────────────

import { runScheduledFipsAudit } from "./lib/fips-audit-scheduler";

// ─── Tests ──────────────────────────────────────────────────────────────

describe("FIPS Audit Scheduler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPreviousAuditRows = [];
    mockInsertedRows = [];
    mockNotifyOwner.mockResolvedValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ─── Audit Execution ──────────────────────────────────────────────

  describe("runScheduledFipsAudit", () => {
    it("should run all FIPS compliance checks", async () => {
      const result = await runScheduledFipsAudit();

      expect(result.timestamp).toBeGreaterThan(0);
      // 6 individual checks + 1 full_audit summary = 7
      expect(result.checks.length).toBe(7);
    });

    it("should include provider status check as warning when inactive", async () => {
      const result = await runScheduledFipsAudit();

      const check = result.checks.find((c) => c.checkType === "provider_status");
      expect(check).toBeDefined();
      expect(check!.component).toBe("openssl-fips-provider");
      expect(check!.status).toBe("warning");
    });

    it("should include AES-256-GCM check as compliant", async () => {
      const result = await runScheduledFipsAudit();

      const check = result.checks.find((c) => c.component === "aes-256-gcm");
      expect(check).toBeDefined();
      expect(check!.status).toBe("compliant");
    });

    it("should include ECDSA P-256 check as compliant", async () => {
      const result = await runScheduledFipsAudit();

      const check = result.checks.find((c) => c.component === "ecdsa-p256");
      expect(check).toBeDefined();
      expect(check!.status).toBe("compliant");
    });

    it("should include HMAC-SHA256 check as compliant", async () => {
      const result = await runScheduledFipsAudit();

      const check = result.checks.find((c) => c.component === "hmac-sha256");
      expect(check).toBeDefined();
      expect(check!.status).toBe("compliant");
    });

    it("should include PBKDF2 check as compliant", async () => {
      const result = await runScheduledFipsAudit();

      const check = result.checks.find((c) => c.component === "pbkdf2-sha256");
      expect(check).toBeDefined();
      expect(check!.status).toBe("compliant");
    });

    it("should include TLS cipher check as compliant", async () => {
      const result = await runScheduledFipsAudit();

      const check = result.checks.find((c) => c.checkType === "tls_cipher");
      expect(check).toBeDefined();
      expect(check!.status).toBe("compliant");
    });

    it("should include full_audit summary", async () => {
      const result = await runScheduledFipsAudit();

      const check = result.checks.find((c) => c.checkType === "full_audit");
      expect(check).toBeDefined();
      expect(check!.component).toBe("platform-wide");
      expect(check!.details).toHaveProperty("totalChecks");
      expect(check!.details).toHaveProperty("scheduledAudit", true);
    });

    it("should determine overall status as warning when provider is inactive", async () => {
      const result = await runScheduledFipsAudit();

      expect(result.overallStatus).toBe("warning");
    });

    it("should store audit results in the database", async () => {
      await runScheduledFipsAudit();

      // 7 checks should be inserted
      expect(mockInsertedRows.length).toBe(7);
    });
  });

  // ─── Degradation Detection ────────────────────────────────────────

  describe("Degradation detection", () => {
    it("should detect degradation when warnings increase from previous audit", async () => {
      mockPreviousAuditRows = [{
        id: 1,
        checkType: "full_audit",
        status: "compliant",
        details: { nonCompliant: 0, warnings: 0, totalChecks: 7 },
      }];

      const result = await runScheduledFipsAudit();

      expect(result.degraded).toBe(true);
    });

    it("should not detect degradation when status is same or better", async () => {
      mockPreviousAuditRows = [{
        id: 1,
        checkType: "full_audit",
        status: "warning",
        details: { nonCompliant: 0, warnings: 10, totalChecks: 7 },
      }];

      const result = await runScheduledFipsAudit();

      expect(result.degraded).toBe(false);
    });

    it("should not detect degradation on first audit (no previous)", async () => {
      mockPreviousAuditRows = [];

      const result = await runScheduledFipsAudit();

      expect(result.degraded).toBe(false);
    });

    it("should detect degradation when overall status worsens", async () => {
      mockPreviousAuditRows = [{
        id: 1,
        checkType: "full_audit",
        status: "compliant",
        details: { nonCompliant: 0, warnings: 0, totalChecks: 7 },
      }];

      const result = await runScheduledFipsAudit();

      // Current is "warning" > "compliant"
      expect(result.degraded).toBe(true);
    });
  });

  // ─── Owner Notifications ──────────────────────────────────────────

  describe("Owner notifications", () => {
    it("should send notification on degradation", async () => {
      mockPreviousAuditRows = [{
        id: 1,
        checkType: "full_audit",
        status: "compliant",
        details: { nonCompliant: 0, warnings: 0, totalChecks: 7 },
      }];

      const result = await runScheduledFipsAudit();

      expect(result.degraded).toBe(true);
      expect(mockNotifyOwner).toHaveBeenCalledTimes(1);
      expect(result.notificationSent).toBe(true);

      const call = mockNotifyOwner.mock.calls[0][0];
      expect(call.title).toContain("FIPS");
      expect(call.content).toContain("Overall Status");
    });

    it("should not send notification when no degradation", async () => {
      mockPreviousAuditRows = [{
        id: 1,
        checkType: "full_audit",
        status: "warning",
        details: { nonCompliant: 0, warnings: 10, totalChecks: 7 },
      }];

      const result = await runScheduledFipsAudit();

      expect(result.degraded).toBe(false);
      expect(mockNotifyOwner).not.toHaveBeenCalled();
      expect(result.notificationSent).toBe(false);
    });

    it("should handle notification failure gracefully", async () => {
      mockPreviousAuditRows = [{
        id: 1,
        checkType: "full_audit",
        status: "compliant",
        details: { nonCompliant: 0, warnings: 0, totalChecks: 7 },
      }];

      mockNotifyOwner.mockRejectedValueOnce(new Error("Notification service unavailable"));

      const result = await runScheduledFipsAudit();

      expect(result.degraded).toBe(true);
      expect(result.notificationSent).toBe(false);
    });

    it("should include warning components in notification content", async () => {
      mockPreviousAuditRows = [{
        id: 1,
        checkType: "full_audit",
        status: "compliant",
        details: { nonCompliant: 0, warnings: 0, totalChecks: 7 },
      }];

      await runScheduledFipsAudit();

      const call = mockNotifyOwner.mock.calls[0][0];
      expect(call.content).toContain("Warning Components");
      expect(call.content).toContain("openssl-fips-provider");
    });
  });
});
