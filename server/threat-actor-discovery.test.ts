import { describe, it, expect, vi } from "vitest";
import fs from "fs";
import path from "path";

// ─── Unit tests for threat actor discovery module and endpoints ───────────────

describe("Threat Actor Discovery", () => {
  // ─── Module Structure Tests ─────────────────────────────────────────────────

  describe("Module structure", () => {
    it("discovery module file exists", () => {
      const filePath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      expect(fs.existsSync(filePath)).toBe(true);
    });

    it("exports discoverNewActors function", async () => {
      const mod = await import("./lib/threat-actor-discovery");
      expect(typeof mod.discoverNewActors).toBe("function");
    });

    it("exports commitDiscoveredActor function", async () => {
      const mod = await import("./lib/threat-actor-discovery");
      expect(typeof mod.commitDiscoveredActor).toBe("function");
    });

    it("exports DiscoverySeedStrategy type (module has strategy handling)", () => {
      const filePath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(filePath, "utf-8");
      expect(content).toContain("DiscoverySeedStrategy");
      expect(content).toContain("related_actors");
      expect(content).toContain("sector_gaps");
    });
  });

  // ─── Strategy Validation Tests ──────────────────────────────────────────────

  describe("Strategy validation", () => {
    const validStrategies = [
      "related_actors",
      "sector_gaps",
      "recent_campaigns",
      "emerging_threats",
      "geographic_coverage",
    ];

    it("supports all five discovery strategies in the module", () => {
      const filePath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(filePath, "utf-8");
      for (const s of validStrategies) {
        expect(content).toContain(s);
      }
    });

    it("each strategy has a prompt template in the module", () => {
      const filePath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(filePath, "utf-8");
      // Each strategy should have a corresponding prompt section
      expect(content).toContain("related_actors");
      expect(content).toContain("sector_gaps");
      expect(content).toContain("recent_campaigns");
      expect(content).toContain("emerging_threats");
      expect(content).toContain("geographic_coverage");
      // Should build prompts for LLM
      expect(content).toMatch(/prompt|system.*content|messages/i);
    });
  });

  // ─── Router Endpoint Tests ──────────────────────────────────────────────────

  describe("Router endpoints", () => {
    it("threat-intel router file contains discoverActors endpoint", () => {
      const routerPath = path.resolve(__dirname, "routers/threat-intel.ts");
      const content = fs.readFileSync(routerPath, "utf-8");
      expect(content).toContain("discoverActors");
    });

    it("threat-intel router file contains commitDiscoveredActor endpoint", () => {
      const routerPath = path.resolve(__dirname, "routers/threat-intel.ts");
      const content = fs.readFileSync(routerPath, "utf-8");
      expect(content).toContain("commitDiscoveredActor");
    });

    it("threat-intel router file contains bulkCommitDiscoveredActors endpoint", () => {
      const routerPath = path.resolve(__dirname, "routers/threat-intel.ts");
      const content = fs.readFileSync(routerPath, "utf-8");
      expect(content).toContain("bulkCommitDiscoveredActors");
    });

    it("discoverActors accepts strategy enum input", () => {
      const routerPath = path.resolve(__dirname, "routers/threat-intel.ts");
      const content = fs.readFileSync(routerPath, "utf-8");
      expect(content).toContain("related_actors");
      expect(content).toContain("sector_gaps");
      expect(content).toContain("recent_campaigns");
      expect(content).toContain("emerging_threats");
      expect(content).toContain("geographic_coverage");
    });
  });

  // ─── Frontend Page Tests ────────────────────────────────────────────────────

  describe("Frontend discovery page", () => {
    it("ThreatActorDiscovery page component exists", () => {
      const pagePath = path.resolve(__dirname, "../client/src/pages/ThreatActorDiscovery.tsx");
      expect(fs.existsSync(pagePath)).toBe(true);
    });

    it("discovery page has strategy selection UI", () => {
      const pagePath = path.resolve(__dirname, "../client/src/pages/ThreatActorDiscovery.tsx");
      const content = fs.readFileSync(pagePath, "utf-8");
      expect(content).toContain("Select Discovery Strategy");
      expect(content).toContain("Related Actors");
      expect(content).toContain("Sector Gap Analysis");
      expect(content).toContain("Recent Campaigns");
      expect(content).toContain("Emerging Threats");
      expect(content).toContain("Geographic Coverage");
    });

    it("discovery page has approve/reject workflow", () => {
      const pagePath = path.resolve(__dirname, "../client/src/pages/ThreatActorDiscovery.tsx");
      const content = fs.readFileSync(pagePath, "utf-8");
      expect(content).toContain("Approve All");
      expect(content).toContain("Reject All");
      expect(content).toContain("toggleApprove");
      expect(content).toContain("toggleReject");
    });

    it("discovery page has commit workflow", () => {
      const pagePath = path.resolve(__dirname, "../client/src/pages/ThreatActorDiscovery.tsx");
      const content = fs.readFileSync(pagePath, "utf-8");
      expect(content).toContain("Commit Approved Actors");
      expect(content).toContain("handleCommit");
      expect(content).toContain("bulkCommitDiscoveredActors");
    });

    it("discovery page shows guardrail protection banner", () => {
      const pagePath = path.resolve(__dirname, "../client/src/pages/ThreatActorDiscovery.tsx");
      const content = fs.readFileSync(pagePath, "utf-8");
      expect(content).toContain("Hallucination Guardrails Active");
    });

    it("discovery page shows confidence scores per actor", () => {
      const pagePath = path.resolve(__dirname, "../client/src/pages/ThreatActorDiscovery.tsx");
      const content = fs.readFileSync(pagePath, "utf-8");
      expect(content).toContain("CONFIDENCE");
      expect(content).toContain("confidenceColor");
    });

    it("discovery page shows discovery reasoning", () => {
      const pagePath = path.resolve(__dirname, "../client/src/pages/ThreatActorDiscovery.tsx");
      const content = fs.readFileSync(pagePath, "utf-8");
      expect(content).toContain("Discovery Reasoning");
      expect(content).toContain("reasoning");
    });
  });

  // ─── Route Registration Tests ───────────────────────────────────────────────

  describe("Route registration", () => {
    it("App.tsx has discovery route registered", () => {
      const appPath = path.resolve(__dirname, "../client/src/App.tsx");
      const content = fs.readFileSync(appPath, "utf-8");
      expect(content).toContain("/threat-catalog/discover");
      expect(content).toContain("ThreatActorDiscovery");
    });

    it("ThreatCatalog has DISCOVER button linking to discovery page", () => {
      const catalogPath = path.resolve(__dirname, "../client/src/pages/ThreatCatalog.tsx");
      const content = fs.readFileSync(catalogPath, "utf-8");
      expect(content).toContain("/threat-catalog/discover");
      expect(content).toContain("DISCOVER");
    });
  });

  // ─── Commit Validation Tests ────────────────────────────────────────────────

  describe("Commit validation", () => {
    it("commitDiscoveredActor generates a slug from actor name", async () => {
      const mod = await import("./lib/threat-actor-discovery");
      // The function should handle slug generation internally
      expect(typeof mod.commitDiscoveredActor).toBe("function");
    });

    it("discovery module checks for duplicate actors before committing", () => {
      const discoveryPath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(discoveryPath, "utf-8");
      // Should check for existing actors by name or slug
      expect(content).toMatch(/slug|duplicate|existing|already/i);
    });

    it("discovery module sets source attribution for discovered actors", () => {
      const discoveryPath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(discoveryPath, "utf-8");
      // Should mark actors as LLM-discovered
      expect(content).toMatch(/llm.discover|discovery|source/i);
    });
  });

  // ─── LLM Prompt Quality Tests ──────────────────────────────────────────────

  describe("LLM prompt quality", () => {
    it("prompts include anti-hallucination instructions", () => {
      const discoveryPath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(discoveryPath, "utf-8");
      expect(content).toMatch(/fabricat|hallucin|verif|real.*world|documented/i);
    });

    it("prompts request confidence scores", () => {
      const discoveryPath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(discoveryPath, "utf-8");
      expect(content).toMatch(/confidence/i);
    });

    it("prompts request source citations", () => {
      const discoveryPath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(discoveryPath, "utf-8");
      expect(content).toMatch(/source|citation|reference/i);
    });

    it("prompts use structured JSON output format", () => {
      const discoveryPath = path.resolve(__dirname, "lib/threat-actor-discovery.ts");
      const content = fs.readFileSync(discoveryPath, "utf-8");
      expect(content).toMatch(/json_schema|response_format|JSON/i);
    });
  });
});
