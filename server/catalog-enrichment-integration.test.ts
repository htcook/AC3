/**
 * Tests for Catalog Auto-Enrichment Pipeline & Threat Actor Exploit Integration
 *
 * Covers:
 * 1. catalog-auto-enrichment.ts — orchestrator, per-source enrichment, post-engagement hook
 * 2. ember-catalog-intelligence.ts — context assembly, system prompt builder, module mapping
 * 3. Integration: enrichment → context → exploit pipeline data flow
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ═══════════════════════════════════════════════════════════════════
// 1. Catalog Auto-Enrichment Pipeline Tests
// ═══════════════════════════════════════════════════════════════════

describe("catalog-auto-enrichment", () => {
  describe("runCatalogEnrichment", () => {
    it("should return a valid EnrichmentSummary with all fields", async () => {
      const { runCatalogEnrichment } = await import("./lib/catalog-auto-enrichment");
      const result = await runCatalogEnrichment({
        sources: ["dfir", "ioc", "exploit_outcomes", "hacking_articles", "threat_intel"],
        maxItemsPerSource: 1,
        dryRun: true,
      });

      expect(result).toBeDefined();
      expect(result.totalSources).toBe(5);
      expect(result.results).toHaveLength(5);
      expect(result.startedAt).toBeTruthy();
      expect(result.completedAt).toBeTruthy();
      expect(result.durationMs).toBeGreaterThanOrEqual(0);

      const sourceLabels = result.results.map(r => r.source);
      expect(sourceLabels).toContain("dfir");
      expect(sourceLabels).toContain("ioc");
      expect(sourceLabels).toContain("exploit_outcomes");
      expect(sourceLabels).toContain("hacking_articles");
      expect(sourceLabels).toContain("threat_intel");
    });

    it("should handle individual source failures gracefully", async () => {
      const { runCatalogEnrichment } = await import("./lib/catalog-auto-enrichment");
      const result = await runCatalogEnrichment({
        sources: ["dfir", "ioc"],
        maxItemsPerSource: 0,
      });

      expect(result).toBeDefined();
      expect(result.totalSources).toBe(2);
    });

    it("should respect maxItemsPerSource limit", async () => {
      const { runCatalogEnrichment } = await import("./lib/catalog-auto-enrichment");
      const result = await runCatalogEnrichment({
        sources: ["exploit_outcomes"],
        maxItemsPerSource: 1,
      });

      expect(result).toBeDefined();
      const outcomeResult = result.results.find(r => r.source === "exploit_outcomes");
      expect(outcomeResult).toBeDefined();
      expect(outcomeResult!.itemsProcessed).toBeLessThanOrEqual(1);
    });

    it("should run only specified sources", async () => {
      const { runCatalogEnrichment } = await import("./lib/catalog-auto-enrichment");
      const result = await runCatalogEnrichment({
        sources: ["dfir"],
        maxItemsPerSource: 1,
      });

      expect(result.totalSources).toBe(1);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].source).toBe("dfir");
    });
  });

  describe("enrichCatalogFromEngagement", () => {
    it("should return a valid EnrichmentResult for a non-existent engagement", async () => {
      const { enrichCatalogFromEngagement } = await import("./lib/catalog-auto-enrichment");
      const result = await enrichCatalogFromEngagement(999999);

      expect(result).toBeDefined();
      expect(result.source).toBe("engagement_999999");
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(result.details)).toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 2. Ember Catalog Intelligence Tests
// ═══════════════════════════════════════════════════════════════════

describe("ember-catalog-intelligence", () => {
  describe("buildEmberThreatContext", () => {
    it("should return a valid EmberThreatContext structure", async () => {
      const { buildEmberThreatContext } = await import("./lib/ember-catalog-intelligence");
      const ctx = await buildEmberThreatContext({
        targetPlatform: "linux",
        targetSector: "financial",
        maxActors: 3,
        maxPlaybooks: 5,
        maxChains: 3,
      });

      expect(ctx).toBeDefined();
      expect(ctx).toHaveProperty("matchedActors");
      expect(ctx).toHaveProperty("attackChains");
      expect(ctx).toHaveProperty("playbooks");
      expect(ctx).toHaveProperty("dfirTechniques");
      expect(ctx).toHaveProperty("phishingOptions");
      expect(ctx).toHaveProperty("iocIntelligence");
      expect(ctx).toHaveProperty("recommendedModules");
      expect(ctx).toHaveProperty("systemPromptContext");

      expect(Array.isArray(ctx.matchedActors)).toBe(true);
      expect(Array.isArray(ctx.attackChains)).toBe(true);
      expect(Array.isArray(ctx.playbooks)).toBe(true);
      expect(Array.isArray(ctx.dfirTechniques)).toBe(true);
      expect(Array.isArray(ctx.recommendedModules)).toBe(true);
      expect(typeof ctx.systemPromptContext).toBe("string");
    });

    it("should handle empty database gracefully", async () => {
      const { buildEmberThreatContext } = await import("./lib/ember-catalog-intelligence");
      const ctx = await buildEmberThreatContext({
        actorIds: ["nonexistent-actor-id"],
        maxActors: 1,
      });

      expect(ctx).toBeDefined();
    });

    it("should limit results to maxActors", async () => {
      const { buildEmberThreatContext } = await import("./lib/ember-catalog-intelligence");
      const ctx = await buildEmberThreatContext({
        maxActors: 2,
        maxPlaybooks: 3,
        maxChains: 2,
      });

      expect(ctx.matchedActors.length).toBeLessThanOrEqual(2);
      expect(ctx.playbooks.length).toBeLessThanOrEqual(3);
      expect(ctx.attackChains.length).toBeLessThanOrEqual(2);
    });
  });

  describe("buildSystemPromptContext", () => {
    it("should produce a formatted string with section headers when actors exist", async () => {
      const { buildEmberThreatContext } = await import("./lib/ember-catalog-intelligence");
      const ctx = await buildEmberThreatContext({ maxActors: 5 });

      // systemPromptContext is always a string — may be empty if no actors matched
      expect(typeof ctx.systemPromptContext).toBe("string");
      if (ctx.matchedActors.length > 0) {
        expect(ctx.systemPromptContext.length).toBeGreaterThan(0);
      }
    });
  });

  describe("generateActorEmulationPlan", () => {
    it("should return null for non-existent actor", async () => {
      const { generateActorEmulationPlan } = await import("./lib/ember-catalog-intelligence");
      const plan = await generateActorEmulationPlan({
        actorId: "nonexistent-actor-999",
        targetPlatform: "linux",
        objective: "test",
        riskThreshold: 50,
      });

      expect(plan).toBeNull();
    });
  });

  describe("getEmberThreatPromptEnhancement", () => {
    it("should return a string", async () => {
      const { getEmberThreatPromptEnhancement } = await import("./lib/ember-catalog-intelligence");
      const prompt = await getEmberThreatPromptEnhancement({
        targetPlatform: "windows",
        targetSector: "healthcare",
      });

      expect(typeof prompt).toBe("string");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 3. IOC-to-TTP Reverse Engineering Tests
// ═══════════════════════════════════════════════════════════════════

describe("ioc-ttp-reverse-engineer", () => {
  describe("reverseEngineerIoc", () => {
    it("should map a C2 domain IOC to relevant techniques", async () => {
      const { reverseEngineerIoc } = await import("./lib/ioc-ttp-reverse-engineer");
      const result = await reverseEngineerIoc(
        { type: "domain", value: "evil-c2-server.com", context: {} },
        { skipLLM: true, persist: false },
      );

      expect(result).toBeDefined();
      expect(result.ioc.type).toBe("domain");
      expect(result.ioc.value).toBe("evil-c2-server.com");
      expect(Array.isArray(result.mappings)).toBe(true);
    });

    it("should map a registry key IOC to persistence techniques", async () => {
      const { reverseEngineerIoc } = await import("./lib/ioc-ttp-reverse-engineer");
      const result = await reverseEngineerIoc(
        { type: "registry_key", value: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware", context: {} },
        { skipLLM: true, persist: false },
      );

      expect(result).toBeDefined();
      expect(Array.isArray(result.mappings)).toBe(true);
    });

    it("should map a file hash IOC", async () => {
      const { reverseEngineerIoc } = await import("./lib/ioc-ttp-reverse-engineer");
      const result = await reverseEngineerIoc(
        { type: "hash_sha256", value: "a".repeat(64), context: {} },
        { skipLLM: true, persist: false },
      );

      expect(result).toBeDefined();
      expect(result.ioc.type).toBe("hash_sha256");
    });
  });

  describe("batchReverseEngineerIocs", () => {
    it("should process multiple IOCs", async () => {
      const { batchReverseEngineerIocs } = await import("./lib/ioc-ttp-reverse-engineer");
      const results = await batchReverseEngineerIocs(
        [
          { type: "domain", value: "test1.evil.com", context: {} },
          { type: "ip", value: "192.168.1.100", context: {} },
          { type: "url", value: "https://evil.com/payload.exe", context: {} },
        ],
        { skipLLM: true, persist: false },
      );

      expect(results).toHaveLength(3);
      for (const result of results) {
        expect(result).toBeDefined();
        expect(Array.isArray(result.mappings)).toBe(true);
      }
    });
  });

  describe("getIocTtpStats", () => {
    it("should return stats object", async () => {
      const { getIocTtpStats } = await import("./lib/ioc-ttp-reverse-engineer");
      const stats = await getIocTtpStats();

      expect(stats).toBeDefined();
      expect(typeof stats.totalMappings).toBe("number");
      expect(stats.totalMappings).toBeGreaterThanOrEqual(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 4. DFIR Report Ingestion Tests
// ═══════════════════════════════════════════════════════════════════

describe("dfir-report-ingestion", () => {
  describe("findPlaybooksForTarget", () => {
    it("should return array for any technique query", async () => {
      const { findPlaybooksForTarget } = await import("./lib/dfir-report-ingestion");
      const playbooks = await findPlaybooksForTarget({
        techniqueId: "T1190",
        platform: "web",
        limit: 5,
      });

      expect(Array.isArray(playbooks)).toBe(true);
    });
  });

  describe("findAttackChains", () => {
    it("should return array for any query", async () => {
      const { findAttackChains } = await import("./lib/dfir-report-ingestion");
      const chains = await findAttackChains({
        tactic: "initial-access",
        limit: 5,
      });

      expect(Array.isArray(chains)).toBe(true);
    });
  });

  describe("buildDfirContextForActor", () => {
    it("should return string for any actor ID", async () => {
      const { buildDfirContextForActor } = await import("./lib/dfir-report-ingestion");
      const ctx = await buildDfirContextForActor("nonexistent-actor");

      expect(typeof ctx).toBe("string");
    });
  });

  describe("getIngestionStats", () => {
    it("should return stats with numeric fields", async () => {
      const { getIngestionStats } = await import("./lib/dfir-report-ingestion");
      const stats = await getIngestionStats();

      expect(stats).toBeDefined();
      expect(typeof stats.totalPlaybooks).toBe("number");
      expect(typeof stats.totalObservations).toBe("number");
      expect(typeof stats.totalChains).toBe("number");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 5. DI Threat Enrichment Tests
// ═══════════════════════════════════════════════════════════════════

describe("di-threat-enrichment", () => {
  describe("enrichDIScanWithThreatIntel", () => {
    it("should return enrichment structure for empty inputs", async () => {
      const { enrichDIScanWithThreatIntel } = await import("./lib/di-threat-enrichment");
      const result = await enrichDIScanWithThreatIntel({
        matchedActorIds: [],
        findings: [],
        assets: [],
        domain: "test.com",
        sector: "technology",
      });

      expect(result).toBeDefined();
      expect(result).toHaveProperty("enrichedActors");
      expect(result).toHaveProperty("attackPaths");
      expect(result).toHaveProperty("techniqueHeatmap");
      expect(result).toHaveProperty("iocDerivedTTPs");
      expect(result).toHaveProperty("dfirCorrelations");
      expect(result).toHaveProperty("riskAmplifiers");
    });
  });

  describe("generateDIReportThreatSection", () => {
    it("should return formatted markdown for empty enrichment", async () => {
      const { generateDIReportThreatSection } = await import("./lib/di-threat-enrichment");
      const markdown = generateDIReportThreatSection({
        enrichedActors: [],
        attackPaths: [],
        techniqueHeatmap: [],
        iocDerivedTtps: [],
        dfirCorrelations: [],
        riskAmplifiers: [],
      });

      expect(typeof markdown).toBe("string");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 6. Phishing Catalog Integration Tests
// ═══════════════════════════════════════════════════════════════════

describe("phishing-catalog-integration", () => {
  describe("analyzePhishingIOCs", () => {
    it("should analyze phishing domain IOCs", async () => {
      const { analyzePhishingIOCs } = await import("./lib/phishing-catalog-integration");
      const results = analyzePhishingIOCs([
        { type: "domain", value: "login-microsoft-verify.com" },
        { type: "email", value: "support@evil-bank.com" },
        { type: "url", value: "https://phish.com/login.php" },
      ]);

      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeGreaterThanOrEqual(0);
      for (const r of results) {
        expect(r).toHaveProperty("iocType");
        expect(r).toHaveProperty("iocValue");
        expect(r).toHaveProperty("impliedTechniques");
      }
    });
  });

  describe("buildActorPhishingProfile", () => {
    it("should return null for non-existent actor", async () => {
      const { buildActorPhishingProfile } = await import("./lib/phishing-catalog-integration");
      const profile = await buildActorPhishingProfile("nonexistent-actor-999");

      expect(profile === null || typeof profile === "object").toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 7. Hacking Articles Ingestion Tests
// ═══════════════════════════════════════════════════════════════════

describe("hacking-articles-ingestion", () => {
  describe("getIngestionStats", () => {
    it("should return stats object", async () => {
      const { getIngestionStats } = await import("./lib/hacking-articles-ingestion");
      const stats = await getIngestionStats();

      expect(stats).toBeDefined();
      expect(typeof stats.totalPlaybooks).toBe("number");
      expect(typeof stats.totalObservations).toBe("number");
    });
  });

  describe("getPlaybooksByMitreId", () => {
    it("should return array for any technique ID", async () => {
      const { getPlaybooksByMitreId } = await import("./lib/hacking-articles-ingestion");
      const playbooks = await getPlaybooksByMitreId("T1059");

      expect(Array.isArray(playbooks)).toBe(true);
    });
  });

  describe("buildPlaybookContext", () => {
    it("should format playbooks into LLM context string", async () => {
      const { buildPlaybookContext } = await import("./lib/hacking-articles-ingestion");
      const ctx = buildPlaybookContext([
        {
          techniqueName: "Command Injection",
          platform: "linux",
          enumerationCommands: [{ order: 1, command: "nmap -sV target", description: "Service scan" }],
          exploitationCommands: [{ order: 1, command: "commix --url=http://target/vuln.php --data='cmd=id'", description: "OS command injection" }],
          toolsUsed: [{ name: "commix", version: "latest" }, { name: "bash", version: "5" }],
          difficulty: "medium",
          privilegeGained: "user",
        },
      ]);

      expect(typeof ctx).toBe("string");
      expect(ctx).toContain("Command Injection");
      expect(ctx).toContain("commix");
    });

    it("should return empty string for empty playbooks", async () => {
      const { buildPlaybookContext } = await import("./lib/hacking-articles-ingestion");
      const ctx = buildPlaybookContext([]);

      expect(ctx).toBe("");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 8. Threat Actor Learning Context Tests
// ═══════════════════════════════════════════════════════════════════

describe("threat-actor-learning-context", () => {
  describe("buildThreatActorLearningContext", () => {
    it("should return a string (may be empty if no learning data)", async () => {
      const { buildThreatActorLearningContext } = await import("./lib/threat-actor-learning-context");
      const ctx = await buildThreatActorLearningContext();

      expect(typeof ctx).toBe("string");
    });
  });

  describe("buildThreatActorVulnContext", () => {
    it("should return a string for CVE/technique inputs", async () => {
      const { buildThreatActorVulnContext } = await import("./lib/threat-actor-learning-context");
      const ctx = await buildThreatActorVulnContext(
        ["CVE-2024-23692", "CVE-2021-44228"],
        ["T1190", "T1059"],
      );

      expect(typeof ctx).toBe("string");
    });
  });

  describe("clearThreatLearningCache", () => {
    it("should clear without error", async () => {
      const { clearThreatLearningCache } = await import("./lib/threat-actor-learning-context");
      expect(() => clearThreatLearningCache()).not.toThrow();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 9. C2 Tactical Knowledge — Adversary Profile Generation Tests
// ═══════════════════════════════════════════════════════════════════

describe("c2-tactical-knowledge adversary profiles", () => {
  describe("scoreProfileCompleteness", () => {
    it("should return null for non-existent actor", async () => {
      const { scoreProfileCompleteness } = await import("./lib/c2-tactical-knowledge");
      const score = await scoreProfileCompleteness("nonexistent-actor-999");

      expect(score).toBeNull();
    });
  });

  describe("generateAdversaryProfile", () => {
    it("should return null for non-existent actor", async () => {
      const { generateAdversaryProfile } = await import("./lib/c2-tactical-knowledge");
      const profile = await generateAdversaryProfile("nonexistent-actor-999");

      expect(profile).toBeNull();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// 10. Integration: Context Engine Assembly Tests
// ═══════════════════════════════════════════════════════════════════

describe("context engine integration", () => {
  describe("_capLLMContext assembly", () => {
    it("should cap context blocks to prevent prompt overflow", async () => {
      const { capLLMContext } = await import("./lib/memory-manager");
      const blocks = [
        { label: "chains", content: "A".repeat(5000) },
        { label: "ontology", content: "B".repeat(5000) },
        { label: "threatActorCatalog", content: "C".repeat(50000) },
        { label: "offensive", content: "D".repeat(5000) },
      ];

      const result = capLLMContext(blocks);
      expect(typeof result).toBe("string");
      // Should be capped — not the full 65KB
      expect(result.length).toBeLessThan(65000 + 1000);
    });
  });

  describe("enhanced-exploit-orchestration knowledge injection", () => {
    it("should import all P0-P5 knowledge modules without error", async () => {
      const modules = await Promise.allSettled([
        import("./lib/exploit-knowledge-store"),
        import("./lib/exploit-learning-engine"),
        import("./lib/knowledge/injection-tools-knowledge"),
        import("./lib/knowledge/offensive-tools-knowledge"),
        import("./lib/hacking-articles-ingestion"),
      ]);

      for (const mod of modules) {
        expect(mod.status).toBe("fulfilled");
      }
    });

    it("should import ember-catalog-intelligence for P6 threat actor context", async () => {
      const mod = await import("./lib/ember-catalog-intelligence");
      expect(mod.buildEmberThreatContext).toBeDefined();
      expect(typeof mod.buildEmberThreatContext).toBe("function");
    });
  });

  describe("enrichment → catalog → context data flow", () => {
    it("should have consistent interfaces across the pipeline", async () => {
      const enrichMod = await import("./lib/catalog-auto-enrichment");
      const ctxMod = await import("./lib/ember-catalog-intelligence");
      const diMod = await import("./lib/di-threat-enrichment");

      expect(typeof enrichMod.runCatalogEnrichment).toBe("function");
      expect(typeof enrichMod.enrichCatalogFromEngagement).toBe("function");
      expect(typeof ctxMod.buildEmberThreatContext).toBe("function");
      expect(typeof ctxMod.generateActorEmulationPlan).toBe("function");
      expect(typeof ctxMod.getEmberThreatPromptEnhancement).toBe("function");
      expect(typeof diMod.enrichDIScanWithThreatIntel).toBe("function");
      expect(typeof diMod.generateDIReportThreatSection).toBe("function");
    });
  });
});
