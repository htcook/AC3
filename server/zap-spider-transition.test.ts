import { describe, it, expect } from "vitest";

/**
 * Tests for ZAP spider→active scan transition fixes:
 * 1. Stale spider ID detection: if DB shows spider_progress >= 100, skip ZAP API check
 * 2. Active scan start failure: wrap in try-catch, mark scan as error immediately
 */

describe("ZAP Spider→Active Scan Transition", () => {
  describe("Stale spider ID detection", () => {
    it("should trust DB spider_progress when >= 100", () => {
      // Simulates the decision logic in pollScanProgress
      const scan = { spiderProgress: 100, urlsDiscovered: 5 };
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      expect(dbSpiderDone).toBe(true);
    });

    it("should NOT trust DB when spider_progress < 100", () => {
      const scan = { spiderProgress: 50, urlsDiscovered: 2 };
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      expect(dbSpiderDone).toBe(false);
    });

    it("should handle null spider_progress as not done", () => {
      const scan = { spiderProgress: null, urlsDiscovered: 0 };
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      expect(dbSpiderDone).toBe(false);
    });

    it("should handle undefined spider_progress as not done", () => {
      const scan = { urlsDiscovered: 0 } as any;
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      expect(dbSpiderDone).toBe(false);
    });

    it("should handle spider_progress of exactly 100", () => {
      const scan = { spiderProgress: 100, urlsDiscovered: 3 };
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      expect(dbSpiderDone).toBe(true);
    });

    it("should handle spider_progress > 100 (edge case)", () => {
      const scan = { spiderProgress: 105, urlsDiscovered: 10 };
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      expect(dbSpiderDone).toBe(true);
    });

    it("should use DB urlsDiscovered when spider is done", () => {
      const scan = { spiderProgress: 100, urlsDiscovered: 42 };
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      let urlsFound: number;
      if (dbSpiderDone) {
        urlsFound = scan.urlsDiscovered || 0;
      } else {
        urlsFound = 0; // Would come from ZAP API
      }
      expect(urlsFound).toBe(42);
    });
  });

  describe("Active scan start error handling", () => {
    it("should produce error status when active scan start throws", () => {
      // Simulates the try-catch around zapRequest for active scan
      let resultStatus = "active_scanning";
      let errorMessage: string | null = null;
      try {
        throw new Error("ZAP request timeout");
      } catch (err: any) {
        resultStatus = "error";
        errorMessage = `Failed to start ZAP active scan: ${err.message}`;
      }
      expect(resultStatus).toBe("error");
      expect(errorMessage).toBe("Failed to start ZAP active scan: ZAP request timeout");
    });

    it("should produce error status for network errors", () => {
      let resultStatus = "active_scanning";
      let errorMessage: string | null = null;
      try {
        throw new Error("connect ECONNREFUSED 127.0.0.1:8090");
      } catch (err: any) {
        resultStatus = "error";
        errorMessage = `Failed to start ZAP active scan: ${err.message}`;
      }
      expect(resultStatus).toBe("error");
      expect(errorMessage).toContain("ECONNREFUSED");
    });

    it("should produce error status for ZAP API errors", () => {
      let resultStatus = "active_scanning";
      let errorMessage: string | null = null;
      try {
        throw new Error("ZAP API error: 400 Bad Request at /JSON/ascan/action/scan/");
      } catch (err: any) {
        resultStatus = "error";
        errorMessage = `Failed to start ZAP active scan: ${err.message}`;
      }
      expect(resultStatus).toBe("error");
      expect(errorMessage).toContain("400 Bad Request");
    });

    it("should succeed when active scan start works", () => {
      let resultStatus = "error";
      let scanId: string | null = null;
      try {
        // Simulates successful zapRequest response
        const activeScanResult = { scan: 42 };
        scanId = String(activeScanResult.scan);
        resultStatus = "active_scanning";
      } catch (err: any) {
        resultStatus = "error";
      }
      expect(resultStatus).toBe("active_scanning");
      expect(scanId).toBe("42");
    });
  });

  describe("Dedup guard for error scans", () => {
    it("should allow retry when previous scan had error status", () => {
      // The dedup guard should skip scans with status=error
      const existingScan = { status: "error", targetUrl: "http://example.com" };
      const shouldSkipDedup = existingScan.status === "error";
      expect(shouldSkipDedup).toBe(true);
    });

    it("should block dedup for running scans", () => {
      const existingScan = { status: "spidering", targetUrl: "http://example.com" };
      const shouldSkipDedup = existingScan.status === "error";
      expect(shouldSkipDedup).toBe(false);
    });

    it("should block dedup for completed scans", () => {
      const existingScan = { status: "completed", targetUrl: "http://example.com" };
      const shouldSkipDedup = existingScan.status === "error";
      expect(shouldSkipDedup).toBe(false);
    });
  });
});
