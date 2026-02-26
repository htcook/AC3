/**
 * C2 Health Check Service Tests
 *
 * Tests real HTTP health probes for CALDERA, Sliver, and Metasploit C2 servers.
 * The service maps statuses as follows:
 *   - HTTP 200 → "connected"
 *   - HTTP 401/403 → "error" (auth failure, server reachable)
 *   - HTTP 4xx/5xx → "error" (server reachable but unhealthy)
 *   - Network failure / timeout → "disconnected" (server unreachable)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the global fetch before importing the module
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Mock the FIPS crypto module
vi.mock("./lib/fips-crypto", () => ({
  getFIPSCrypto: () => ({
    decrypt: (encrypted: any) => {
      return Buffer.from(JSON.stringify({ apiKey: "test-key-123", token: "test-token" }));
    },
  }),
}));

import { checkC2Health, type C2ServerRecord } from "./lib/c2-health";

describe("C2 Health Check Service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ─── CALDERA Health Checks ───────────────────────────────────────────

  describe("CALDERA health checks", () => {
    const calderaServer: C2ServerRecord = {
      id: "c2-caldera-1",
      name: "Test CALDERA",
      type: "caldera",
      baseUrl: "https://caldera.example.com",
      authConfigEncrypted: "encrypted-config",
    };

    it("should return connected status on successful CALDERA health check", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          version: "5.0.0",
          plugins: ["sandcat", "stockpile", "atomic"],
        }),
        headers: { get: (k: string) => k === "date" ? "Wed, 26 Feb 2026 12:00:00 GMT" : null },
      });

      const result = await checkC2Health(calderaServer);

      expect(result.status).toBe("connected");
      expect(result.version).toBe("5.0.0");
      expect(result.capabilities).toContain("sandcat");
      expect(result.capabilities).toContain("stockpile");
      expect(result.latencyMs).toBeGreaterThanOrEqual(0);
      expect(result.message).toContain("CALDERA");
    });

    it("should return error on CALDERA 401 unauthorized (server reachable, auth failed)", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      });

      const result = await checkC2Health(calderaServer);

      expect(result.status).toBe("error");
      expect(result.message).toContain("401");
      expect(result.message).toContain("authentication");
    });

    it("should return disconnected on CALDERA network failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const result = await checkC2Health(calderaServer);

      expect(result.status).toBe("disconnected");
      expect(result.message).toContain("ECONNREFUSED");
    });

    it("should return disconnected on CALDERA timeout", async () => {
      const abortError = new DOMException("The operation was aborted", "AbortError");
      mockFetch.mockRejectedValueOnce(abortError);

      const result = await checkC2Health(calderaServer);

      expect(result.status).toBe("disconnected");
      expect(result.message).toContain("timed out");
    });

    it("should return error on CALDERA 500 server error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      const result = await checkC2Health(calderaServer);

      expect(result.status).toBe("error");
      expect(result.message).toContain("500");
    });
  });

  // ─── Sliver Health Checks ────────────────────────────────────────────

  describe("Sliver health checks", () => {
    const sliverServer: C2ServerRecord = {
      id: "c2-sliver-1",
      name: "Test Sliver",
      type: "sliver",
      baseUrl: "https://sliver.example.com:31337",
      authConfigEncrypted: "encrypted-config",
    };

    it("should return connected status on successful Sliver health check", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          version: "1.5.42",
        }),
        headers: { get: () => null },
      });

      const result = await checkC2Health(sliverServer);

      expect(result.status).toBe("connected");
      expect(result.version).toBe("1.5.42");
      expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it("should return error on Sliver 403 forbidden (auth failure)", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: "Forbidden",
      });

      const result = await checkC2Health(sliverServer);

      expect(result.status).toBe("error");
      expect(result.message).toContain("authentication");
    });

    it("should handle Sliver 404 by trying root endpoint", async () => {
      // First call: /health returns 404
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });
      // Second call: root returns 200
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const result = await checkC2Health(sliverServer);

      expect(result.status).toBe("connected");
      expect(result.message).toContain("root responded");
    });

    it("should return disconnected on Sliver network failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const result = await checkC2Health(sliverServer);

      expect(result.status).toBe("disconnected");
    });
  });

  // ─── Metasploit Health Checks ────────────────────────────────────────

  describe("Metasploit health checks", () => {
    const msfServer: C2ServerRecord = {
      id: "c2-msf-1",
      name: "Test Metasploit",
      type: "metasploit",
      baseUrl: "https://msf.example.com:55553",
      authConfigEncrypted: "encrypted-config",
    };

    it("should return connected status on successful Metasploit health check", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          version: "6.3.44",
          modules: { exploits: 2000, auxiliary: 500 },
        }),
        headers: { get: () => null },
      });

      const result = await checkC2Health(msfServer);

      expect(result.status).toBe("connected");
      expect(result.version).toBe("6.3.44");
      expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it("should return error on Metasploit 500 server error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      const result = await checkC2Health(msfServer);

      expect(result.status).toBe("error");
      expect(result.message).toContain("500");
    });

    it("should return disconnected on Metasploit DNS resolution failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("getaddrinfo ENOTFOUND msf.example.com"));

      const result = await checkC2Health(msfServer);

      expect(result.status).toBe("disconnected");
      expect(result.message).toContain("ENOTFOUND");
    });

    it("should return error on Metasploit 401 auth failure", async () => {
      // First call: version endpoint returns 401
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      });

      const result = await checkC2Health(msfServer);

      expect(result.status).toBe("error");
      expect(result.message).toContain("authentication");
    });
  });

  // ─── Edge Cases ──────────────────────────────────────────────────────

  describe("Edge cases", () => {
    it("should handle server with no auth config", async () => {
      const server: C2ServerRecord = {
        id: "c2-test",
        name: "No Auth Server",
        type: "caldera",
        baseUrl: "https://caldera.example.com",
        authConfigEncrypted: "",
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ version: "5.0.0", plugins: [] }),
        headers: { get: () => null },
      });

      const result = await checkC2Health(server);

      expect(result.status).toBe("connected");
    });

    it("should measure latency correctly", async () => {
      const server: C2ServerRecord = {
        id: "c2-latency",
        name: "Latency Test",
        type: "caldera",
        baseUrl: "https://caldera.example.com",
        authConfigEncrypted: "encrypted-config",
      };

      mockFetch.mockImplementation(() =>
        new Promise((resolve) =>
          setTimeout(() => resolve({
            ok: true,
            status: 200,
            json: async () => ({ version: "5.0.0", plugins: [] }),
            headers: { get: () => null },
          }), 50)
        )
      );

      const result = await checkC2Health(server);

      expect(result.latencyMs).toBeGreaterThanOrEqual(40);
    });

    it("should handle unknown C2 type", async () => {
      const server = {
        id: "c2-unknown",
        name: "Unknown Server",
        type: "unknown" as any,
        baseUrl: "https://unknown.example.com",
        authConfigEncrypted: "",
      };

      const result = await checkC2Health(server);

      expect(result.status).toBe("error");
      expect(result.message).toContain("Unknown");
    });
  });
});
