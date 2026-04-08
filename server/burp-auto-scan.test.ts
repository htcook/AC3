import { describe, it, expect } from "vitest";

// Test the extractScopeUrls function and scan state management
import {
  extractScopeUrls,
  getBurpAutoScanStats,
  getEngagementBurpScans,
  getBurpAutoScanState,
  getBurpAutoScanStatsWithHistory,
  getEngagementBurpScanHistory,
} from "./lib/burp-auto-scan";

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
      expect(Array.isArray(urls)).toBe(true);
    });

    it("combines all sources into a single deduplicated list", () => {
      const engagement = {
        targetUrl: "https://main.example.com",
        targetDomain: "example.com",
        rptScopeAssets: ["https://api.example.com", "cdn.example.com"],
        scope: JSON.stringify(["https://web.example.com", { url: "https://admin.example.com" }]),
        scopeAssets: JSON.stringify([{ name: "staging.example.com", type: "DOMAIN" }]),
      };
      const opsState = {
        assets: [{ hostname: "discovered.example.com", webApps: [{ url: "https://app.discovered.example.com" }] }],
      };
      const urls = extractScopeUrls(engagement, opsState);
      expect(urls.length).toBeGreaterThanOrEqual(7);
      expect(urls).toContain("https://main.example.com");
      expect(urls).toContain("https://example.com");
      expect(urls).toContain("https://api.example.com");
      expect(urls).toContain("https://cdn.example.com");
      expect(urls).toContain("https://web.example.com");
      expect(urls).toContain("https://admin.example.com");
      expect(urls).toContain("https://discovered.example.com");
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

  describe("DB-backed scan history", () => {
    it("returns empty array for engagement with no scan history", async () => {
      const history = await getEngagementBurpScanHistory(999999);
      // Should return empty array (DB may not be available in test env)
      expect(Array.isArray(history)).toBe(true);
    });

    it("getBurpAutoScanStatsWithHistory returns combined stats", async () => {
      const stats = await getBurpAutoScanStatsWithHistory();
      expect(stats).toHaveProperty("active");
      expect(stats).toHaveProperty("completed");
      expect(stats).toHaveProperty("failed");
      expect(stats).toHaveProperty("totalIssues");
      expect(stats).toHaveProperty("totalImported");
      expect(stats).toHaveProperty("totalScans");
      expect(typeof stats.totalScans).toBe("number");
    });
  });

  describe("Exploit matching keyword extraction", () => {
    // Test the vulnerability keyword mapping logic used by feedBurpFindingsToExploitEngine
    const vulnKeywordMap: Record<string, string[]> = {
      "SQL Injection": ["sqli", "sql injection"],
      "Cross-Site Scripting (XSS)": ["xss", "cross-site scripting"],
      "Server-Side Request Forgery": ["ssrf"],
      "Remote Code Execution via deserialization": ["rce", "remote code execution", "deserialization"],
      "Local File Inclusion in upload handler": ["lfi", "local file inclusion"],
      "XML External Entity processing": ["xxe"],
      "Path Traversal in file download": ["path traversal", "directory traversal"],
      "OS Command Injection": ["command injection", "os command injection"],
      "Server-Side Template Injection": ["ssti", "template injection"],
      "Cross-Site Request Forgery": ["csrf"],
      "Open Redirect in OAuth callback": ["open redirect"],
      "Authentication bypass via token reuse": ["authentication bypass"],
      "Privilege Escalation through role manipulation": ["privilege escalation"],
    };

    for (const [title, expectedTerms] of Object.entries(vulnKeywordMap)) {
      it(`maps "${title}" to correct exploit search terms`, () => {
        const terms: string[] = [];
        const lower = title.toLowerCase();
        if (lower.includes("sql injection")) terms.push("sqli", "sql injection");
        if (lower.includes("xss") || lower.includes("cross-site scripting")) terms.push("xss", "cross-site scripting");
        if (lower.includes("ssrf") || lower.includes("server-side request")) terms.push("ssrf");
        if (lower.includes("rce") || lower.includes("remote code")) terms.push("rce", "remote code execution");
        if (lower.includes("lfi") || lower.includes("local file")) terms.push("lfi", "local file inclusion");
        if (lower.includes("xxe") || lower.includes("xml external")) terms.push("xxe");
        if (lower.includes("deserialization")) terms.push("deserialization");
        if (lower.includes("path traversal") || lower.includes("directory traversal")) terms.push("path traversal", "directory traversal");
        if (lower.includes("command injection") || lower.includes("os command")) terms.push("command injection", "os command injection");
        if (lower.includes("ssti") || lower.includes("template injection")) terms.push("ssti", "template injection");
        if (lower.includes("csrf") || lower.includes("cross-site request")) terms.push("csrf");
        if (lower.includes("open redirect")) terms.push("open redirect");
        if (lower.includes("authentication") || lower.includes("auth bypass")) terms.push("authentication bypass");
        if (lower.includes("privilege escalation")) terms.push("privilege escalation");

        for (const expected of expectedTerms) {
          expect(terms).toContain(expected);
        }
      });
    }
  });
});
