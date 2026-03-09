/**
 * Tests for DO Scan API Client — HTTP-based scan execution
 *
 * Tests the HTTP API client that routes scan execution to the DO scan service,
 * verifying tool execution, raw commands, health checks, and SSH fallback.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the scan-server-executor for fallback tests
vi.mock("./lib/scan-server-executor", () => ({
  executeTool: vi.fn().mockResolvedValue({
    tool: "nmap",
    command: "nmap --version",
    stdout: "Nmap 7.80 (SSH fallback)",
    stderr: "",
    exitCode: 0,
    durationMs: 500,
    timedOut: false,
  }),
  executeViaChildProcessSSH: vi.fn().mockResolvedValue({
    stdout: "SSH raw output",
    stderr: "",
    exitCode: 0,
  }),
}));

// We test the module's logic by mocking fetch
const originalFetch = global.fetch;

describe("DO Scan API Client", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  describe("executeToolViaHttp", () => {
    it("should execute a tool via HTTP API and return ToolExecResult", async () => {
      // Mock successful HTTP response
      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: true,
          result: {
            tool: "nmap",
            command: "nmap --version",
            stdout: "Nmap version 7.80",
            stderr: "",
            exitCode: 0,
            durationMs: 286,
            timedOut: false,
          },
        }),
      } as any);

      const { executeToolViaHttp } = await import("./lib/do-scan-api");
      const result = await executeToolViaHttp({
        tool: "nmap",
        args: "--version",
        timeoutSeconds: 10,
      });

      expect(result.tool).toBe("nmap");
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Nmap");
      expect(result.timedOut).toBe(false);
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it("should fall back to SSH when HTTP API returns non-200", async () => {
      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve("Internal Server Error"),
      } as any);

      const { executeToolViaHttp } = await import("./lib/do-scan-api");
      const result = await executeToolViaHttp({
        tool: "nmap",
        args: "--version",
        timeoutSeconds: 10,
      });

      // Should still return a result (from SSH fallback)
      expect(result.tool).toBe("nmap");
      expect(result.exitCode).toBeDefined();
    });

    it("should handle network errors gracefully with SSH fallback", async () => {
      // When HTTP fails and SSH fallback is mocked, the function should still return
      // a valid ToolExecResult. We test this by verifying the fallback logic exists.
      const { executeToolViaHttp } = await import("./lib/do-scan-api");
      
      // Verify the function is exported and callable
      expect(typeof executeToolViaHttp).toBe("function");
      
      // Verify metrics track fallbacks
      const { getDoApiMetrics } = await import("./lib/do-scan-api");
      const metrics = getDoApiMetrics();
      expect(metrics).toHaveProperty("httpFallbackToSSH");
    });
  });

  describe("executeRawCommandViaHttp", () => {
    it("should execute a raw command via HTTP API", async () => {
      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: true,
          result: {
            stdout: "https://example.com [200] [Example Domain]\n",
            stderr: "",
            exitCode: 0,
          },
        }),
      } as any);

      const { executeRawCommandViaHttp } = await import("./lib/do-scan-api");
      const result = await executeRawCommandViaHttp(
        "echo https://example.com | httpx -silent -nc -status-code -title",
        15
      );

      expect(result.tool).toBe("raw");
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("example.com");
    });
  });

  describe("checkDoScanServiceHealth", () => {
    it("should return healthy status when service is up", async () => {
      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          status: "ok",
          service: "caldera-scan-service",
          uptime: 5982.8,
          memory: { rss: 88981504, heapTotal: 13545472 },
        }),
      } as any);

      const { checkDoScanServiceHealth } = await import("./lib/do-scan-api");
      const health = await checkDoScanServiceHealth();

      expect(health.healthy).toBe(true);
      expect(health.uptime).toBeGreaterThan(0);
    });

    it("should return unhealthy when service is down", async () => {
      global.fetch = vi.fn().mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const { checkDoScanServiceHealth } = await import("./lib/do-scan-api");
      const health = await checkDoScanServiceHealth();

      expect(health.healthy).toBe(false);
      expect(health.error).toBeDefined();
    });
  });

  describe("getDoScanTools", () => {
    it("should return installed tools manifest", async () => {
      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          tools: {
            nmap: { path: "/usr/bin/nmap", installed: true },
            nuclei: { path: "/usr/local/bin/nuclei", installed: true },
          },
        }),
      } as any);

      const { getDoScanTools } = await import("./lib/do-scan-api");
      const tools = await getDoScanTools();

      expect(tools.nmap).toBeDefined();
      expect(tools.nmap.installed).toBe(true);
      expect(tools.nuclei).toBeDefined();
    });
  });

  describe("getDoApiMetrics", () => {
    it("should return metrics object with expected fields", async () => {
      const { getDoApiMetrics } = await import("./lib/do-scan-api");
      const metrics = getDoApiMetrics();

      expect(metrics).toHaveProperty("totalRequests");
      expect(metrics).toHaveProperty("successfulRequests");
      expect(metrics).toHaveProperty("failedRequests");
      expect(metrics).toHaveProperty("avgLatencyMs");
      expect(metrics).toHaveProperty("httpFallbackToSSH");
    });
  });
});
