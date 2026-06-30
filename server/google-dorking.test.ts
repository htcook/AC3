/**
 * Google Dorking Connector & Router Tests
 *
 * Tests the Google Dorking connector library (Google CSE API client),
 * dork template catalog, and the tRPC router procedures.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock fetch globally ─────────────────────────────────────────────────
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ─── Google Dorking Connector Tests ─────────────────────────────────────

describe("GoogleDorkingConnector", () => {
  let GoogleDorkingConnector: any;
  let DORK_TEMPLATES: any[];

  beforeEach(async () => {
    vi.clearAllMocks();
    const mod = await import("./lib/google-dorking-connector");
    GoogleDorkingConnector = mod.GoogleDorkingConnector;
    DORK_TEMPLATES = mod.DORK_TEMPLATES;
  });

  describe("constructor & configuration", () => {
    it("reports not configured when no API key or search engine ID", () => {
      const connector = new GoogleDorkingConnector("", "");
      expect(connector.isConfigured()).toBe(false);
    });

    it("reports configured when both API key and search engine ID are provided", () => {
      const connector = new GoogleDorkingConnector("test-key", "test-cx");
      expect(connector.isConfigured()).toBe(true);
    });

    it("falls back to process.env when constructor args are empty", () => {
      process.env.GOOGLE_CSE_API_KEY = "env-key";
      process.env.GOOGLE_CSE_ID = "env-cx";
      const connector = new GoogleDorkingConnector();
      expect(connector.isConfigured()).toBe(true);
      delete process.env.GOOGLE_CSE_API_KEY;
      delete process.env.GOOGLE_CSE_ID;
    });
  });

  describe("DORK_TEMPLATES catalog", () => {
    it("contains at least 30 dork templates", () => {
      expect(DORK_TEMPLATES.length).toBeGreaterThanOrEqual(30);
    });

    it("every template has required fields", () => {
      for (const t of DORK_TEMPLATES) {
        expect(t.id).toBeTruthy();
        expect(t.name).toBeTruthy();
        expect(t.category).toBeTruthy();
        expect(t.description).toBeTruthy();
        expect(t.query).toContain("{{domain}}");
        expect(["critical", "high", "medium", "low", "info"]).toContain(t.severity);
      }
    });

    it("has unique template IDs", () => {
      const ids = DORK_TEMPLATES.map((t: any) => t.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("covers all 10 categories", () => {
      const categories = new Set(DORK_TEMPLATES.map((t: any) => t.category));
      expect(categories.size).toBe(10);
      expect(categories).toContain("exposed_panels");
      expect(categories).toContain("sensitive_files");
      expect(categories).toContain("directory_listings");
      expect(categories).toContain("config_files");
      expect(categories).toContain("database_exposure");
      expect(categories).toContain("login_pages");
      expect(categories).toContain("error_messages");
      expect(categories).toContain("vulnerable_servers");
      expect(categories).toContain("cloud_exposure");
      expect(categories).toContain("api_exposure");
    });
  });

  describe("getTemplates", () => {
    it("returns all templates when no category filter", () => {
      const connector = new GoogleDorkingConnector("k", "c");
      const all = connector.getTemplates();
      expect(all.length).toBe(DORK_TEMPLATES.length);
    });

    it("filters by category", () => {
      const connector = new GoogleDorkingConnector("k", "c");
      const panels = connector.getTemplates("exposed_panels");
      expect(panels.length).toBeGreaterThan(0);
      expect(panels.every((t: any) => t.category === "exposed_panels")).toBe(true);
    });
  });

  describe("getCategories", () => {
    it("returns 10 categories with metadata", () => {
      const connector = new GoogleDorkingConnector("k", "c");
      const cats = connector.getCategories();
      expect(cats.length).toBe(10);
      for (const c of cats) {
        expect(c.id).toBeTruthy();
        expect(c.name).toBeTruthy();
        expect(c.description).toBeTruthy();
        expect(c.count).toBeGreaterThan(0);
      }
    });
  });

  describe("search", () => {
    it("throws when not configured", async () => {
      const connector = new GoogleDorkingConnector("", "");
      await expect(connector.search("test")).rejects.toThrow("not configured");
    });

    it("returns parsed results on successful API response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          searchInformation: { totalResults: "42", searchTime: "0.35" },
          items: [
            {
              title: "Admin Panel",
              link: "https://example.com/admin",
              snippet: "Login to admin panel",
              displayLink: "example.com",
              formattedUrl: "https://example.com/admin",
            },
          ],
        }),
      });

      const connector = new GoogleDorkingConnector("key", "cx");
      const result = await connector.search("site:example.com admin");

      expect(result.totalResults).toBe(42);
      expect(result.searchTime).toBeCloseTo(0.35);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].title).toBe("Admin Panel");
      expect(result.results[0].link).toBe("https://example.com/admin");
    });

    it("returns empty results when API returns no items", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          searchInformation: { totalResults: "0", searchTime: "0.1" },
        }),
      });

      const connector = new GoogleDorkingConnector("key", "cx");
      const result = await connector.search("site:nothing.com");

      expect(result.totalResults).toBe(0);
      expect(result.results).toHaveLength(0);
    });

    it("throws on 429 rate limit", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        text: async () => "Rate limit exceeded",
      });

      const connector = new GoogleDorkingConnector("key", "cx");
      await expect(connector.search("test")).rejects.toThrow("rate limit");
    });

    it("throws on other API errors", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        text: async () => "Forbidden",
      });

      const connector = new GoogleDorkingConnector("key", "cx");
      await expect(connector.search("test")).rejects.toThrow("403");
    });
  });

  describe("executeDork", () => {
    it("replaces {{domain}} in template query", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          searchInformation: { totalResults: "5", searchTime: "0.2" },
          items: [{ title: "Found", link: "https://target.com/admin", snippet: "Admin", displayLink: "target.com", formattedUrl: "https://target.com/admin" }],
        }),
      });

      const connector = new GoogleDorkingConnector("key", "cx");
      const template = DORK_TEMPLATES.find((t: any) => t.id === "admin-panel-1");
      const result = await connector.executeDork(template, "target.com");

      expect(result.query).toContain("site:target.com");
      expect(result.query).not.toContain("{{domain}}");
      expect(result.totalResults).toBe(5);
      expect(result.dorkTemplate.id).toBe("admin-panel-1");
    });

    it("returns empty result on API error (graceful degradation)", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const connector = new GoogleDorkingConnector("key", "cx");
      const template = DORK_TEMPLATES[0];
      const result = await connector.executeDork(template, "target.com");

      expect(result.totalResults).toBe(0);
      expect(result.results).toHaveLength(0);
    });
  });

  describe("executeCustomDork", () => {
    it("passes custom query directly to search", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          searchInformation: { totalResults: "10", searchTime: "0.5" },
          items: [{ title: "Custom Result", link: "https://example.com", snippet: "Found", displayLink: "example.com", formattedUrl: "https://example.com" }],
        }),
      });

      const connector = new GoogleDorkingConnector("key", "cx");
      const result = await connector.executeCustomDork('site:example.com filetype:env "DB_PASSWORD"');

      expect(result.totalResults).toBe(10);
      expect(result.results).toHaveLength(1);

      // Verify the fetch URL contains the custom query
      const fetchUrl = mockFetch.mock.calls[0][0];
      expect(fetchUrl).toContain("filetype%3Aenv");
    });
  });

  describe("runScan", () => {
    it("scans all templates when no category filter", async () => {
      // Mock all fetch calls to return empty results
      for (let i = 0; i < DORK_TEMPLATES.length; i++) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            searchInformation: { totalResults: "0", searchTime: "0.1" },
          }),
        });
      }

      const connector = new GoogleDorkingConnector("key", "cx");
      const summary = await connector.runScan("example.com", undefined, 0); // 0 delay for tests

      expect(summary.domain).toBe("example.com");
      expect(summary.totalFindings).toBe(0);
      expect(summary.scannedAt).toBeGreaterThan(0);
      expect(mockFetch).toHaveBeenCalledTimes(DORK_TEMPLATES.length);
    });

    it("filters by selected categories", async () => {
      const panelCount = DORK_TEMPLATES.filter((t: any) => t.category === "exposed_panels").length;

      for (let i = 0; i < panelCount; i++) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            searchInformation: { totalResults: "0", searchTime: "0.1" },
          }),
        });
      }

      const connector = new GoogleDorkingConnector("key", "cx");
      const summary = await connector.runScan("example.com", ["exposed_panels"], 0);

      expect(mockFetch).toHaveBeenCalledTimes(panelCount);
    });

    it("aggregates severity counts correctly", async () => {
      // Return results for the first template (which is critical severity)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          searchInformation: { totalResults: "3", searchTime: "0.2" },
          items: [
            { title: "A", link: "https://a.com", snippet: "a", displayLink: "a.com", formattedUrl: "https://a.com" },
            { title: "B", link: "https://b.com", snippet: "b", displayLink: "b.com", formattedUrl: "https://b.com" },
            { title: "C", link: "https://c.com", snippet: "c", displayLink: "c.com", formattedUrl: "https://c.com" },
          ],
        }),
      });

      // Rest return empty
      for (let i = 1; i < DORK_TEMPLATES.filter((t: any) => t.category === "exposed_panels").length; i++) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            searchInformation: { totalResults: "0", searchTime: "0.1" },
          }),
        });
      }

      const connector = new GoogleDorkingConnector("key", "cx");
      const summary = await connector.runScan("example.com", ["exposed_panels"], 0);

      expect(summary.totalFindings).toBe(3);
      expect(summary.results.length).toBe(1); // Only 1 dork had results
    });
  });
});

// ─── Router Tests ───────────────────────────────────────────────────────

describe("googleDorkingRouter", () => {
  describe("health procedure", () => {
    it("returns not configured when env vars are missing", async () => {
      delete process.env.GOOGLE_CSE_API_KEY;
      delete process.env.GOOGLE_CSE_ID;

      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const result = await caller.health();
      expect(result.configured).toBe(false);
      expect(result.connected).toBe(false);
      expect(result.templateCount).toBeGreaterThan(0);
    });
  });

  describe("categories procedure", () => {
    it("returns all 10 categories", async () => {
      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const cats = await caller.categories();
      expect(cats.length).toBe(10);
      expect(cats[0]).toHaveProperty("id");
      expect(cats[0]).toHaveProperty("name");
      expect(cats[0]).toHaveProperty("count");
      expect(cats[0]).toHaveProperty("description");
    });
  });

  describe("templates procedure", () => {
    it("returns all templates when no filter", async () => {
      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const templates = await caller.templates();
      expect(templates.length).toBeGreaterThanOrEqual(30);
    });

    it("filters by category when provided", async () => {
      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const templates = await caller.templates({ category: "cloud_exposure" });
      expect(templates.length).toBeGreaterThan(0);
      expect(templates.every((t: any) => t.category === "cloud_exposure")).toBe(true);
    });
  });

  describe("previewQuery procedure", () => {
    it("resolves {{domain}} in template query", async () => {
      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const result = await caller.previewQuery({ templateId: "admin-panel-1", domain: "target.com" });
      expect(result.query).toContain("site:target.com");
      expect(result.query).not.toContain("{{domain}}");
      expect(result.error).toBeNull();
    });

    it("returns error for unknown template", async () => {
      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const result = await caller.previewQuery({ templateId: "nonexistent", domain: "target.com" });
      expect(result.query).toBeNull();
      expect(result.error).toContain("not found");
    });
  });

  describe("executeDork procedure", () => {
    it("returns not configured when env vars missing", async () => {
      delete process.env.GOOGLE_CSE_API_KEY;
      delete process.env.GOOGLE_CSE_ID;

      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const result = await caller.executeDork({ templateId: "admin-panel-1", domain: "target.com" });
      expect(result.configured).toBe(false);
    });
  });

  describe("executeCustom procedure", () => {
    it("returns not configured when env vars missing", async () => {
      delete process.env.GOOGLE_CSE_API_KEY;
      delete process.env.GOOGLE_CSE_ID;

      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const result = await caller.executeCustom({ query: "site:example.com" });
      expect(result.configured).toBe(false);
    });
  });

  describe("runScan procedure", () => {
    it("returns not configured when env vars missing", async () => {
      delete process.env.GOOGLE_CSE_API_KEY;
      delete process.env.GOOGLE_CSE_ID;

      const { googleDorkingRouter } = await import("./routers/google-dorking");
      const caller = googleDorkingRouter.createCaller({
        user: { id: "u1", name: "Test", role: "admin" },
      } as any);

      const result = await caller.runScan({ domain: "example.com" });
      expect(result.configured).toBe(false);
      expect(result.summary).toBeNull();
    });
  });
});
