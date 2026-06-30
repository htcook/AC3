/**
 * Tests for scan-server-inventory module.
 * Verifies:
 * 1. Tool inventory parsing and categorization
 * 2. LLM context formatting
 * 3. Cache behavior
 * 4. Error handling when scan server is unreachable
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the SSH executor
vi.mock("./scan-server-executor", () => ({
  executeRawCommand: vi.fn(),
}));

import { executeRawCommand } from "./scan-server-executor";
import { getToolInventory, getInventoryForLLM, invalidateInventoryCache } from "./scan-server-inventory";

const mockSSH = vi.mocked(executeRawCommand);

describe("scan-server-inventory", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateInventoryCache();
  });

  describe("getToolInventory", () => {
    it("should detect tools via which command when manifest is unavailable", async () => {
      // First call: manifest fails
      mockSSH.mockImplementation(async (cmd: string) => {
        if (cmd.includes("tool-manifest.json")) {
          return { stdout: "", stderr: "No such file", exitCode: 1, timedOut: false };
        }
        if (cmd.includes("CHECK:")) {
          // Simulate which results
          const lines = [
            "CHECK:nmap:/usr/bin/nmap",
            "CHECK:nuclei:/usr/local/bin/nuclei",
            "CHECK:masscan:NOT_FOUND",
            "CHECK:naabu:/usr/local/bin/naabu",
            "CHECK:httpx:/usr/local/bin/httpx",
            "CHECK:ffuf:/usr/local/bin/ffuf",
            "CHECK:hydra:NOT_FOUND",
            "CHECK:msfconsole:NOT_FOUND",
          ];
          return { stdout: lines.join("\n"), stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("VER:")) {
          return {
            stdout: "VER:nmap:7.94\nVER:nuclei:3.1.0\nVER:naabu:2.2.1",
            stderr: "",
            exitCode: 0,
            timedOut: false,
          };
        }
        if (cmd.includes("UPTIME:")) {
          return {
            stdout: "UPTIME:up 5 days\nDISK:42G\nMEM:3.2G\nCPU:4",
            stderr: "",
            exitCode: 0,
            timedOut: false,
          };
        }
        return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
      });

      const inventory = await getToolInventory(true);

      expect(inventory.serverReachable).toBe(true);
      expect(inventory.tools.length).toBeGreaterThan(0);

      const nmap = inventory.tools.find((t) => t.name === "nmap");
      expect(nmap?.installed).toBe(true);
      expect(nmap?.path).toBe("/usr/bin/nmap");
      expect(nmap?.category).toBe("port_scanning");

      const masscan = inventory.tools.find((t) => t.name === "masscan");
      expect(masscan?.installed).toBe(false);

      expect(inventory.resources?.uptime).toBe("up 5 days");
      expect(inventory.resources?.diskFree).toBe("42G");
      expect(inventory.resources?.cpuCores).toBe(4);
    });

    it("should use manifest when available", async () => {
      mockSSH.mockImplementation(async (cmd: string) => {
        if (cmd.includes("tool-manifest.json")) {
          return {
            stdout: JSON.stringify({
              tools: {
                nmap: { path: "/usr/bin/nmap", version: "7.94" },
                nuclei: { path: "/usr/local/bin/nuclei", version: "3.1.0" },
              },
            }),
            stderr: "",
            exitCode: 0,
            timedOut: false,
          };
        }
        if (cmd.includes("CHECK:")) {
          return { stdout: "CHECK:nmap:/usr/bin/nmap\nCHECK:nuclei:/usr/local/bin/nuclei", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("VER:")) {
          return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("UPTIME:")) {
          return { stdout: "UPTIME:up 1 day\nDISK:50G\nMEM:8G\nCPU:8", stderr: "", exitCode: 0, timedOut: false };
        }
        return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
      });

      const inventory = await getToolInventory(true);

      const nmap = inventory.tools.find((t) => t.name === "nmap");
      expect(nmap?.installed).toBe(true);
      expect(nmap?.version).toBe("7.94");
      expect(nmap?.path).toBe("/usr/bin/nmap");
    });

    it("should return unreachable status when SSH fails", async () => {
      mockSSH.mockRejectedValue(new Error("Connection refused"));

      const inventory = await getToolInventory(true);

      expect(inventory.serverReachable).toBe(false);
      expect(inventory.error).toContain("Failed to probe scan server tools via SSH");
      expect(inventory.tools).toHaveLength(0);
    });

    it("should use cache on second call within TTL", async () => {
      mockSSH.mockImplementation(async (cmd: string) => {
        if (cmd.includes("tool-manifest.json")) {
          return { stdout: "", stderr: "", exitCode: 1, timedOut: false };
        }
        if (cmd.includes("CHECK:")) {
          return { stdout: "CHECK:nmap:/usr/bin/nmap", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("VER:")) {
          return { stdout: "VER:nmap:7.94", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("UPTIME:")) {
          return { stdout: "UPTIME:up 1h\nDISK:10G\nMEM:2G\nCPU:2", stderr: "", exitCode: 0, timedOut: false };
        }
        return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
      });

      await getToolInventory(true);
      const callCount = mockSSH.mock.calls.length;

      // Second call should use cache
      await getToolInventory(false);
      expect(mockSSH.mock.calls.length).toBe(callCount); // No new SSH calls
    });

    it("should bypass cache when forceRefresh is true", async () => {
      mockSSH.mockImplementation(async (cmd: string) => {
        if (cmd.includes("tool-manifest.json")) {
          return { stdout: "", stderr: "", exitCode: 1, timedOut: false };
        }
        if (cmd.includes("CHECK:")) {
          return { stdout: "CHECK:nmap:/usr/bin/nmap", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("VER:")) {
          return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("UPTIME:")) {
          return { stdout: "UPTIME:up 1h\nDISK:10G\nMEM:2G\nCPU:2", stderr: "", exitCode: 0, timedOut: false };
        }
        return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
      });

      await getToolInventory(true);
      const callCount = mockSSH.mock.calls.length;

      // Force refresh should make new SSH calls
      await getToolInventory(true);
      expect(mockSSH.mock.calls.length).toBeGreaterThan(callCount);
    });
  });

  describe("getInventoryForLLM", () => {
    it("should format installed tools by category", () => {
      const inventory = {
        lastRefreshed: Date.now(),
        serverReachable: true,
        tools: [
          { name: "nmap", installed: true, path: "/usr/bin/nmap", version: "7.94", category: "port_scanning" as const, description: "Network mapper", requiresSudo: true },
          { name: "nuclei", installed: true, path: "/usr/local/bin/nuclei", version: "3.1.0", category: "vuln_scanning" as const, description: "Template-based vuln scanner", requiresSudo: false },
          { name: "masscan", installed: false, category: "port_scanning" as const, description: "High-speed port scanner", requiresSudo: true },
        ],
      };

      const output = getInventoryForLLM(inventory);

      expect(output).toContain("[SCAN SERVER TOOLS] 2/43 tools available:");
      expect(output).toContain("Port Scanning:");
      expect(output).toContain("nmap (7.94) [sudo]");
      expect(output).toContain("Vulnerability Scanning:");
      expect(output).toContain("nuclei (3.1.0)");
      expect(output).toContain("NOT INSTALLED (1):");
      expect(output).toContain("Do NOT generate commands for tools that are not installed.");
    });

    it("should handle unreachable server", () => {
      const inventory = {
        lastRefreshed: Date.now(),
        serverReachable: false,
        error: "Connection timeout",
        tools: [],
      };

      const output = getInventoryForLLM(inventory);
      expect(output).toContain("[SCAN SERVER UNREACHABLE]");
      expect(output).toContain("Connection timeout");
    });

    it("should handle empty tool list on reachable server", () => {
      const inventory = {
        lastRefreshed: Date.now(),
        serverReachable: true,
        tools: [],
      };

      const output = getInventoryForLLM(inventory);
      expect(output).toContain("Connected but no tools detected");
    });
  });

  describe("invalidateInventoryCache", () => {
    it("should force fresh probe on next call after invalidation", async () => {
      mockSSH.mockImplementation(async (cmd: string) => {
        if (cmd.includes("tool-manifest.json")) {
          return { stdout: "", stderr: "", exitCode: 1, timedOut: false };
        }
        if (cmd.includes("CHECK:")) {
          return { stdout: "CHECK:nmap:/usr/bin/nmap", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("VER:")) {
          return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
        }
        if (cmd.includes("UPTIME:")) {
          return { stdout: "UPTIME:up 1h\nDISK:10G\nMEM:2G\nCPU:2", stderr: "", exitCode: 0, timedOut: false };
        }
        return { stdout: "", stderr: "", exitCode: 0, timedOut: false };
      });

      await getToolInventory(true);
      const callCount = mockSSH.mock.calls.length;

      // Invalidate and call again — should make new SSH calls
      invalidateInventoryCache();
      await getToolInventory(false);
      expect(mockSSH.mock.calls.length).toBeGreaterThan(callCount);
    });
  });
});
