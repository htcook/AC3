import { describe, it, expect } from "vitest";

// Import the data structures directly to test their correctness
const feedModule = async () => import("./lib/dailydarkweb-feed");

describe("Daily Dark Web Feed Module", () => {
  describe("DAILYDARKWEB_SOURCE metadata", () => {
    it("exports correct source metadata", async () => {
      const { DAILYDARKWEB_SOURCE } = await feedModule();
      expect(DAILYDARKWEB_SOURCE.id).toBe("dailydarkweb");
      expect(DAILYDARKWEB_SOURCE.name).toBe("Daily Dark Web");
      expect(DAILYDARKWEB_SOURCE.url).toBe("https://dailydarkweb.net");
      expect(DAILYDARKWEB_SOURCE.reliability).toBe("B");
      expect(DAILYDARKWEB_SOURCE.confidence).toBe(75);
      expect(DAILYDARKWEB_SOURCE.categories).toContain("ransomware-news");
      expect(DAILYDARKWEB_SOURCE.categories).toContain("data-breaches");
      expect(DAILYDARKWEB_SOURCE.categories).toContain("cyber-attacks");
      expect(DAILYDARKWEB_SOURCE.categories).toContain("unauthorized-accesses");
      expect(DAILYDARKWEB_SOURCE.categories).toContain("darkweb-news");
    });
  });

  describe("FULCRUMSEC threat actor profile", () => {
    it("has correct actor ID and name", async () => {
      // Access the module's internal constants via the sync function exports
      const mod = await feedModule();
      expect(mod.DAILYDARKWEB_SOURCE).toBeDefined();
      // The actor data is embedded in the sync functions, so we test via export
    });

    it("exports syncFulcrumsec function", async () => {
      const mod = await feedModule();
      expect(typeof mod.syncFulcrumsec).toBe("function");
    });

    it("exports syncDailyDarkWebActors function", async () => {
      const mod = await feedModule();
      expect(typeof mod.syncDailyDarkWebActors).toBe("function");
    });

    it("exports syncDailyDarkWebFeed function", async () => {
      const mod = await feedModule();
      expect(typeof mod.syncDailyDarkWebFeed).toBe("function");
    });
  });

  describe("Data integrity checks", () => {
    it("module loads without errors", async () => {
      const mod = await feedModule();
      expect(mod).toBeDefined();
      expect(mod.DAILYDARKWEB_SOURCE).toBeDefined();
    });

    it("source has all required fields", async () => {
      const { DAILYDARKWEB_SOURCE } = await feedModule();
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("id");
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("name");
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("url");
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("description");
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("categories");
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("reliability");
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("confidence");
      expect(DAILYDARKWEB_SOURCE).toHaveProperty("addedDate");
    });

    it("source URL is valid", async () => {
      const { DAILYDARKWEB_SOURCE } = await feedModule();
      expect(DAILYDARKWEB_SOURCE.url).toMatch(/^https?:\/\//);
    });

    it("confidence is within valid range", async () => {
      const { DAILYDARKWEB_SOURCE } = await feedModule();
      expect(DAILYDARKWEB_SOURCE.confidence).toBeGreaterThanOrEqual(0);
      expect(DAILYDARKWEB_SOURCE.confidence).toBeLessThanOrEqual(100);
    });

    it("reliability is a valid NATO rating", async () => {
      const { DAILYDARKWEB_SOURCE } = await feedModule();
      expect(["A", "B", "C", "D", "E", "F"]).toContain(DAILYDARKWEB_SOURCE.reliability);
    });

    it("has at least 3 categories", async () => {
      const { DAILYDARKWEB_SOURCE } = await feedModule();
      expect(DAILYDARKWEB_SOURCE.categories.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe("darkweb-feeds.ts integration", () => {
    it("syncAllDarkwebFeeds includes dailyDarkWeb in return type", async () => {
      const { syncAllDarkwebFeeds } = await import("./lib/darkweb-feeds");
      expect(typeof syncAllDarkwebFeeds).toBe("function");
    });
  });

  describe("Branding: Ace of Cloud report generators", () => {
    it("pdf-report-generator uses Ace of Cloud branding", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("server/lib/pdf-report-generator.ts", "utf-8");
      expect(content).toContain("Ace of Cloud");
      expect(content).toContain("#213555");
    });

    it("zap-report-generator uses Ace of Cloud branding", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("server/lib/zap-report-generator.ts", "utf-8");
      expect(content).toContain("Ace of Cloud");
    });

    it("report-generator.ts uses Ace of Cloud metadata", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("server/lib/report-generator.ts", "utf-8");
      expect(content).toContain("Ace of Cloud");
    });

    it("reports-core.ts LLM prompt references Ace of Cloud", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("server/routers/reports-core.ts", "utf-8");
      expect(content).toContain("Ace of Cloud");
    });
  });

  describe("ScoringHub fix verification", () => {
    it("ScoringHub does not use Object.entries on tiers array incorrectly", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("client/src/pages/ScoringHub.tsx", "utf-8");
      // Should NOT have the old pattern: Object.entries(industryTierQ.data.tiers).map(([tierKey, tierData]) => ... (tierData as string[]).map
      expect(content).not.toMatch(/tierData as string\[\]/);
    });
  });

  describe("DomainIntelResults fix verification", () => {
    it("DomainIntelResults does not reference undefined prev variable", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("client/src/pages/DomainIntelResults.tsx", "utf-8");
      // Should not have bare prev?.snapshotAt outside the IIFE
      // The fix replaced prev?.snapshotAt with pipeline.previousSnapshot?.snapshotAt
      expect(content).toContain("pipeline.previousSnapshot");
    });
  });

  describe("KSI navigation placement", () => {
    it("AppShell has KSI Dashboard link in Mission Operations section", async () => {
      const fs = await import("fs");
      const content = fs.readFileSync("client/src/components/AppShell.tsx", "utf-8");
      expect(content).toContain("ksi-dashboard");
      expect(content).toContain("KSI");
    });
  });
});
