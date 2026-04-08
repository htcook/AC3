import { describe, it, expect } from "vitest";

// Test the extractScopeUrls function and scan state management
// We import directly from the module
import { extractScopeUrls, getBurpAutoScanStats, getEngagementBurpScans, getBurpAutoScanState } from "./lib/burp-auto-scan";

describe("Burp Auto-Scan Module", () => {
  describe("extractScopeUrls", () => {
    it("extracts URLs from engagement targetUrl", () => {
      const engagement = { targetUrl: "https://example.com" };
      const urls = extractScopeUrls(engagement);
      expect(urls).toContain("https://example.com");
    });

    it("extracts URLs from engagement targetDomain", () => {
      const engagement = { targetDomain: "example.com" };
      const urls = extractScopeUrls(engagement);
      expect(urls).toContain("https://example.com");
    });

    it("extracts URLs from rptScopeAssets array", () => {
      const engagement = {
        rptScopeAssets: ["https://app.example.com", "api.example.com", "192.168.1.1"],
      };
      const urls = extractScopeUrls(engagement);
      expect(urls).toContain("https://app.example.com");
      expect(urls).toContain("https://api.example.com");
      expect(urls).toContain("https://192.168.1.1");
    });

    it("extracts URLs from scope JSON array", () => {
      const engagement = {
        scope: JSON.stringify([
          "https://web.example.com",
          { url: "https://api.example.com" },
          { target: "https://admin.example.com" },
        ]),
      };
      const urls = extractScopeUrls(engagement);
      expect(urls).toContain("https://web.example.com");
      expect(urls).toContain("https://api.example.com");
      expect(urls).toContain("https://admin.example.com");
    });

    it("extracts URLs from ops state discovered assets", () => {
      const engagement = {};
      const opsState = {
        assets: [
          { hostname: "server1.example.com", webApps: [{ url: "https://app.server1.example.com" }] },
          { hostname: "server2.example.com" },
        ],
      };
      const urls = extractScopeUrls(engagement, opsState);
      expect(urls).toContain("https://server1.example.com");
      expect(urls).toContain("https://app.server1.example.com");
      expect(urls).toContain("https://server2.example.com");
    });

    it("extracts URLs from scopeAssets JSON", () => {
      const engagement = {
        scopeAssets: JSON.stringify([
          { name: "https://target.example.com", type: "URL" },
          { name: "api.example.com", type: "DOMAIN" },
        ]),
      };
      const urls = extractScopeUrls(engagement);
      expect(urls).toContain("https://target.example.com");
      expect(urls).toContain("https://api.example.com");
    });

    it("deduplicates URLs", () => {
      const engagement = {
        targetUrl: "https://example.com",
        targetDomain: "example.com",
        rptScopeAssets: ["https://example.com"],
      };
      const urls = extractScopeUrls(engagement);
      const exampleCount = urls.filter((u: string) => u === "https://example.com").length;
      expect(exampleCount).toBe(1);
    });

    it("filters out non-HTTP URLs from scope JSON", () => {
      const engagement = {
        scope: JSON.stringify(["ftp://files.example.com", "ssh://server.example.com"]),
      };
      const urls = extractScopeUrls(engagement);
      // ftp:// and ssh:// don't start with http, so they should be filtered
      expect(urls.some((u: string) => u.startsWith("ftp://"))).toBe(false);
      expect(urls.some((u: string) => u.startsWith("ssh://"))).toBe(false);
    });

    it("handles empty engagement gracefully", () => {
      const urls = extractScopeUrls({});
      expect(urls).toEqual([]);
    });

    it("handles malformed scope JSON gracefully", () => {
      const engagement = { scope: "not-valid-json" };
      const urls = extractScopeUrls(engagement);
      // Should not throw
      expect(Array.isArray(urls)).toBe(true);
    });
  });

  describe("Scan state management", () => {
    it("returns empty stats when no scans exist", () => {
      const stats = getBurpAutoScanStats();
      expect(stats).toHaveProperty("active");
      expect(stats).toHaveProperty("completed");
      expect(stats).toHaveProperty("failed");
      expect(stats).toHaveProperty("totalIssues");
      expect(stats).toHaveProperty("totalImported");
      expect(typeof stats.active).toBe("number");
    });

    it("returns empty array for non-existent engagement scans", () => {
      const scans = getEngagementBurpScans(999999);
      expect(scans).toEqual([]);
    });

    it("returns null for non-existent scan state", () => {
      const state = getBurpAutoScanState(999999, 999999);
      expect(state).toBeNull();
    });
  });
});
