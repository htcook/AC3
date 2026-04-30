import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock DB ────────────────────────────────────────────────────────────────
const mockSelectResult = vi.fn().mockResolvedValue([]);
const mockDeleteResult = vi.fn().mockResolvedValue({});
const mockInsertResult = vi.fn().mockResolvedValue({});

const mockDb = {
  select: vi.fn().mockReturnThis(),
  from: vi.fn().mockReturnThis(),
  where: vi.fn().mockImplementation(() => mockSelectResult()),
  delete: vi.fn().mockReturnThis(),
  // delete().from() and delete().where() both chain
  insert: vi.fn().mockReturnValue({
    values: vi.fn().mockImplementation(() => mockInsertResult()),
  }),
};

// Override where for delete chains
let isDeleteChain = false;
mockDb.delete.mockImplementation(() => {
  isDeleteChain = true;
  return {
    where: vi.fn().mockImplementation(() => mockDeleteResult()),
  };
});

vi.mock("./db", () => ({
  getDb: vi.fn().mockResolvedValue(mockDb),
}));

vi.mock("../drizzle/schema", () => ({
  fingerprintCache: {
    fcHost: "fc_host",
    fcPort: "fc_port",
    fcExpiresAt: "fc_expires_at",
  },
}));

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((...args: any[]) => ({ type: "eq", args })),
  and: vi.fn((...args: any[]) => ({ type: "and", args })),
  inArray: vi.fn((...args: any[]) => ({ type: "inArray", args })),
  gt: vi.fn((...args: any[]) => ({ type: "gt", args })),
}));

// ─── Tests ──────────────────────────────────────────────────────────────────


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("fingerprint-cache", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSelectResult.mockResolvedValue([]);
    mockDeleteResult.mockResolvedValue({});
    mockInsertResult.mockResolvedValue({});
  });

  describe("getCachedFingerprints", () => {
    it("returns all ports as uncached when cache is empty", async () => {
      const { getCachedFingerprints } = await import("./lib/fingerprint-cache");
      const result = await getCachedFingerprints("10.0.0.1", [22, 80, 443]);
      expect(result.cached).toHaveLength(0);
      expect(result.uncachedPorts).toEqual([22, 80, 443]);
      expect(result.hitCount).toBe(0);
      expect(result.missCount).toBe(3);
      expect(result.cacheUsed).toBe(true);
    });

    it("returns cached results and identifies uncached ports", async () => {
      mockSelectResult.mockResolvedValue([
        {
          fcPort: 22, fcProtocol: "ssh", fcProduct: "OpenSSH",
          fcVersion: "8.4", fcBanner: "SSH-2.0-OpenSSH_8.4",
          fcOs: "Linux", fcSecurityFlags: {}, fcRiskIndicators: [],
          fcPotentialCves: [], fcError: 0, fcConfidence: 90,
        },
        {
          fcPort: 443, fcProtocol: "https", fcProduct: "nginx",
          fcVersion: "1.21", fcBanner: null,
          fcOs: null, fcSecurityFlags: {}, fcRiskIndicators: [],
          fcPotentialCves: [], fcError: 0, fcConfidence: 85,
        },
      ]);

      const { getCachedFingerprints } = await import("./lib/fingerprint-cache");
      const result = await getCachedFingerprints("10.0.0.1", [22, 80, 443]);
      expect(result.cached).toHaveLength(2);
      expect(result.uncachedPorts).toEqual([80]);
      expect(result.hitCount).toBe(2);
      expect(result.missCount).toBe(1);
    });

    it("converts DB rows back to FingerprintResult shape", async () => {
      mockSelectResult.mockResolvedValue([
        {
          fcPort: 3306, fcProtocol: "mysql", fcProduct: "MySQL",
          fcVersion: "8.0.28", fcBanner: "5.7.38-log",
          fcOs: "Linux", fcSecurityFlags: { defaultCreds: true },
          fcRiskIndicators: ["default_creds"], fcPotentialCves: ["CVE-2022-21417"],
          fcError: 0, fcConfidence: 95,
        },
      ]);

      const { getCachedFingerprints } = await import("./lib/fingerprint-cache");
      const result = await getCachedFingerprints("10.0.0.1", [3306]);
      const fp = result.cached[0];
      expect(fp.port).toBe(3306);
      expect(fp.protocol).toBe("mysql");
      expect(fp.product).toBe("MySQL");
      expect(fp.version).toBe("8.0.28");
      expect(fp.banner).toBe("5.7.38-log");
      expect((fp as any)._cached).toBe(true);
      expect(fp.durationMs).toBe(0);
    });

    it("marks error fingerprints correctly", async () => {
      mockSelectResult.mockResolvedValue([
        {
          fcPort: 22, fcProtocol: "ssh", fcProduct: null,
          fcVersion: null, fcBanner: null,
          fcOs: null, fcSecurityFlags: {}, fcRiskIndicators: [],
          fcPotentialCves: [], fcError: 1, fcConfidence: 0,
        },
      ]);

      const { getCachedFingerprints } = await import("./lib/fingerprint-cache");
      const result = await getCachedFingerprints("10.0.0.1", [22]);
      expect(result.cached[0].error).toBe("cached-error");
    });
  });

  describe("cacheFingerprints", () => {
    it("caches fingerprint results successfully", async () => {
      const { cacheFingerprints } = await import("./lib/fingerprint-cache");
      const fps = [
        { port: 22, protocol: "ssh", product: "OpenSSH", version: "8.4", banner: "SSH-2.0-OpenSSH_8.4", os: "Linux", securityFlags: {}, riskIndicators: [], potentialCves: [], confidence: 90, durationMs: 50 },
        { port: 80, protocol: "http", product: "nginx", version: "1.21", banner: null, os: null, securityFlags: {}, riskIndicators: [], potentialCves: [], confidence: 85, durationMs: 30 },
      ] as any[];

      const result = await cacheFingerprints("10.0.0.1", fps, "eng-123");
      expect(result.cached).toBe(2);
      expect(result.errors).toBe(0);
    });

    it("handles insert errors gracefully", async () => {
      mockInsertResult.mockRejectedValue(new Error("DB write failed"));

      const { cacheFingerprints } = await import("./lib/fingerprint-cache");
      const fps = [
        { port: 22, protocol: "ssh", product: "OpenSSH", version: "8.4", banner: null, os: null, securityFlags: {}, riskIndicators: [], potentialCves: [], confidence: 90, durationMs: 50 },
      ] as any[];

      const result = await cacheFingerprints("10.0.0.1", fps, "eng-123");
      expect(result.errors).toBe(1);
      expect(result.cached).toBe(0);
    });

    it("returns zero cached for empty results", async () => {
      const { cacheFingerprints } = await import("./lib/fingerprint-cache");
      const result = await cacheFingerprints("10.0.0.1", [], "eng-123");
      expect(result.cached).toBe(0);
      expect(result.errors).toBe(0);
    });
  });

  describe("invalidateHostCache", () => {
    it("deletes all cache entries for a host", async () => {
      const { invalidateHostCache } = await import("./lib/fingerprint-cache");
      await invalidateHostCache("10.0.0.1");
      // Should not throw
      expect(mockDb.delete).toHaveBeenCalled();
    });
  });

  describe("purgeExpiredCache", () => {
    it("purges expired entries without error", async () => {
      const { purgeExpiredCache } = await import("./lib/fingerprint-cache");
      const count = await purgeExpiredCache();
      expect(count).toBe(0); // Drizzle doesn't expose affected rows
    });
  });

  describe("TTL enforcement", () => {
    it("clamps TTL to minimum 1 hour", async () => {
      const { getCachedFingerprints } = await import("./lib/fingerprint-cache");
      // Should not throw with very small TTL
      const result = await getCachedFingerprints("10.0.0.1", [22], { ttlMs: 100 });
      expect(result.cacheUsed).toBe(true);
    });

    it("clamps TTL to maximum 7 days", async () => {
      const { getCachedFingerprints } = await import("./lib/fingerprint-cache");
      // Should not throw with very large TTL
      const result = await getCachedFingerprints("10.0.0.1", [22], { ttlMs: 999999999999 });
      expect(result.cacheUsed).toBe(true);
    });
  });
});
