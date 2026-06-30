/**
 * Tests for ZAP Resource Cleanup — cleanupStaleScansForTarget()
 * 
 * Validates that stale ZAP spiders and active scans are stopped before
 * starting new scans, following commercial scanner best practices
 * (Burp Suite: max 1 concurrent scan per machine).
 */
import { describe, it, expect } from "vitest";

// We test the cleanup logic by validating the function signature, return type,
// and the ZAP API endpoints it should call. Since the actual ZAP instance
// is external, we test the logic patterns rather than live API calls.

describe("ZAP Resource Cleanup", () => {
  describe("cleanupStaleScansForTarget export", () => {
    it("should be exported from zap-scanner", async () => {
      const mod = await import("./lib/zap-scanner");
      expect(typeof mod.cleanupStaleScansForTarget).toBe("function");
    });

    it("should accept targetUrl and optional config", async () => {
      const mod = await import("./lib/zap-scanner");
      // Function should have 2 parameters (targetUrl, cfg)
      expect(mod.cleanupStaleScansForTarget.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("Cleanup return type contract", () => {
    it("should return stoppedSpiders, stoppedAscans, and errors", async () => {
      // The function returns { stoppedSpiders: number, stoppedAscans: number, errors: string[] }
      // We verify the type contract by checking the function exists and has the right shape
      const mod = await import("./lib/zap-scanner");
      expect(mod.cleanupStaleScansForTarget).toBeDefined();
      
      // Call with invalid config to trigger error path (no real ZAP connection)
      const result = await mod.cleanupStaleScansForTarget(
        "http://example.com",
        { baseUrl: "http://localhost:1", apiKey: "test", spiderMaxDepth: 5, spiderMaxChildren: 20, activeScanPolicy: "Default Policy", requestDelayMs: 20, maxAlertsPerScan: 1000 }
      );
      
      // Should return the expected shape even on error
      expect(result).toHaveProperty("stoppedSpiders");
      expect(result).toHaveProperty("stoppedAscans");
      expect(result).toHaveProperty("errors");
      expect(typeof result.stoppedSpiders).toBe("number");
      expect(typeof result.stoppedAscans).toBe("number");
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it("should handle invalid target URL gracefully", async () => {
      const mod = await import("./lib/zap-scanner");
      const result = await mod.cleanupStaleScansForTarget(
        "not-a-valid-url",
        { baseUrl: "http://localhost:1", apiKey: "test", spiderMaxDepth: 5, spiderMaxChildren: 20, activeScanPolicy: "Default Policy", requestDelayMs: 20, maxAlertsPerScan: 1000 }
      );
      
      // Should not throw, should return with errors
      expect(result.stoppedSpiders).toBe(0);
      expect(result.stoppedAscans).toBe(0);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("should return 0 stopped scans when ZAP is unreachable", async () => {
      const mod = await import("./lib/zap-scanner");
      const result = await mod.cleanupStaleScansForTarget(
        "http://zero.webappsecurity.com",
        { baseUrl: "http://127.0.0.1:1", apiKey: "fake", spiderMaxDepth: 5, spiderMaxChildren: 20, activeScanPolicy: "Default Policy", requestDelayMs: 20, maxAlertsPerScan: 1000 }
      );
      
      expect(result.stoppedSpiders).toBe(0);
      expect(result.stoppedAscans).toBe(0);
      // Should have errors from failed API calls
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe("ZAP API endpoint coverage", () => {
    // These tests verify the cleanup function uses the correct ZAP API endpoints
    // by checking the source code patterns
    
    it("should use spider/view/scans to list spiders", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      expect(source).toContain('"/JSON/spider/view/scans/"');
    });

    it("should use spider/action/stop to stop individual spiders", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      expect(source).toContain('"/JSON/spider/action/stop/"');
    });

    it("should use ascan/view/scans to list active scans", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      expect(source).toContain('"/JSON/ascan/view/scans/"');
    });

    it("should use ascan/action/stop to stop individual active scans", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      expect(source).toContain('"/JSON/ascan/action/stop/"');
    });

    it("should use spider/action/removeAllScans to free memory", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      expect(source).toContain('"/JSON/spider/action/removeAllScans/"');
    });

    it("should use ascan/action/removeAllScans to free memory", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      expect(source).toContain('"/JSON/ascan/action/removeAllScans/"');
    });
  });

  describe("Pre-scan cleanup integration in startScan", () => {
    it("should call cleanupStaleScansForTarget before starting spider", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      
      // The cleanup call should appear BEFORE the spider start
      const cleanupIndex = source.indexOf("cleanupStaleScansForTarget(params.targetUrl");
      const spiderStartIndex = source.indexOf('"/JSON/spider/action/scan/"');
      
      expect(cleanupIndex).toBeGreaterThan(-1);
      expect(spiderStartIndex).toBeGreaterThan(-1);
      expect(cleanupIndex).toBeLessThan(spiderStartIndex);
    });

    it("should have a 2-second pause after cleanup to let ZAP release resources", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      
      // Check for the setTimeout(r, 2000) pause after cleanup
      const cleanupSection = source.substring(
        source.indexOf("cleanupStaleScansForTarget(params.targetUrl"),
        source.indexOf("cleanupStaleScansForTarget(params.targetUrl") + 500
      );
      expect(cleanupSection).toContain("setTimeout");
      expect(cleanupSection).toContain("2000");
    });

    it("should treat cleanup failure as non-fatal", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      
      // The cleanup call should be wrapped in try/catch with a "non-fatal" comment
      const cleanupSection = source.substring(
        source.indexOf("Pre-scan cleanup"),
        source.indexOf("Pre-scan cleanup") + 1000
      );
      expect(cleanupSection).toContain("non-fatal");
      expect(cleanupSection).toContain("catch");
    });
  });

  describe("Spider state handling", () => {
    it("should stop spiders in RUNNING state", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      const cleanupFn = source.substring(
        source.indexOf("cleanupStaleScansForTarget"),
        source.indexOf("cleanupStaleScansForTarget") + 2000
      );
      expect(cleanupFn).toContain('"RUNNING"');
    });

    it("should stop spiders in NOT_STARTED state", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      const cleanupFn = source.substring(
        source.indexOf("cleanupStaleScansForTarget"),
        source.indexOf("cleanupStaleScansForTarget") + 2000
      );
      expect(cleanupFn).toContain('"NOT_STARTED"');
    });
  });

  describe("Active scan state handling", () => {
    it("should stop active scans in RUNNING state", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      const cleanupFn = source.substring(
        source.indexOf("cleanupStaleScansForTarget"),
        source.indexOf("cleanupStaleScansForTarget") + 2500
      );
      // RUNNING appears for both spider and ascan sections
      const ascanSection = cleanupFn.substring(cleanupFn.indexOf("Stop running active scans"));
      expect(ascanSection).toContain('"RUNNING"');
    });

    it("should stop active scans in PAUSED state", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      const cleanupFn = source.substring(
        source.indexOf("cleanupStaleScansForTarget"),
        source.indexOf("cleanupStaleScansForTarget") + 2500
      );
      expect(cleanupFn).toContain('"PAUSED"');
    });
  });

  describe("Memory cleanup behavior", () => {
    it("should only remove scan records when stale scans were found", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("./server/lib/zap-scanner.ts", "utf-8");
      const cleanupFn = source.substring(
        source.indexOf("cleanupStaleScansForTarget"),
        source.indexOf("cleanupStaleScansForTarget") + 3000
      );
      // The removeAllScans calls should be inside a conditional
      expect(cleanupFn).toContain("stoppedSpiders > 0 || stoppedAscans > 0");
    });
  });
});
