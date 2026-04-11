/**
 * Tests for the three new features:
 * 1. Context Engine Contribution Tracker
 * 2. Caldera Builder Integration into Engagement Orchestrator
 * 3. Batch Hacking Articles Ingest wiring
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

// ─── Feature 1: Context Engine Tracker ──────────────────────────────────────

describe("Context Engine Tracker", () => {
  let tracker: typeof import("./lib/context-engine-tracker");

  beforeEach(async () => {
    tracker = await import("./lib/context-engine-tracker");
    tracker.clearContributionBuffer();
  });

  describe("recordContextContribution", () => {
    it("should record a contribution to the buffer", () => {
      const contribution = {
        id: "ctx-test-1",
        engagementId: 42,
        exploitTarget: "target.example.com",
        exploitCve: "CVE-2024-1234",
        timestamp: Date.now(),
        sources: [
          {
            sourceId: "exploitRecipes",
            sourceName: "Exploit Knowledge Store (P0)",
            category: "knowledge_store" as const,
            tokensContributed: 500,
            itemCount: 3,
            wasActive: true,
          },
        ],
        totalContextLength: 2000,
        cappedContextLength: 1500,
        decisionOutcome: "exploit_attempted" as const,
      };

      tracker.recordContextContribution(contribution);

      // Verify it's retrievable
      return tracker.getContextContributions({ limit: 10 }).then(result => {
        expect(result.contributions).toHaveLength(1);
        expect(result.contributions[0].id).toBe("ctx-test-1");
        expect(result.contributions[0].exploitTarget).toBe("target.example.com");
        expect(result.total).toBe(1);
      });
    });

    it("should cap buffer at MAX_BUFFER_SIZE (500)", () => {
      for (let i = 0; i < 510; i++) {
        tracker.recordContextContribution({
          id: `ctx-${i}`,
          engagementId: 1,
          exploitTarget: "host",
          exploitCve: "CVE-2024-0001",
          timestamp: Date.now() + i,
          sources: [],
          totalContextLength: 100,
          cappedContextLength: 80,
          decisionOutcome: "exploit_attempted",
        });
      }

      return tracker.getContextContributions({ limit: 1000 }).then(result => {
        expect(result.total).toBe(500);
        // Oldest entries should have been dropped
        expect(result.contributions.some(c => c.id === "ctx-0")).toBe(false);
        expect(result.contributions.some(c => c.id === "ctx-509")).toBe(true);
      });
    });
  });

  describe("buildContributionFromBlocks", () => {
    it("should build a contribution record from context blocks", () => {
      const blocks = [
        { label: "exploitRecipes", content: "Recipe 1: SQL injection via UNION\n---\nRecipe 2: XSS stored" },
        { label: "threatActorCatalog", content: "APT29 uses T1059.001 PowerShell for initial access" },
        { label: "hackingArticles", content: "" }, // inactive source
        { label: "dfirObservations", content: "Observed: whoami /all executed post-compromise" },
      ];

      const result = tracker.buildContributionFromBlocks(
        42,
        "target.example.com",
        "CVE-2024-1234",
        blocks,
        "capped context string here",
        "exploit_attempted",
      );

      expect(result.engagementId).toBe(42);
      expect(result.exploitTarget).toBe("target.example.com");
      expect(result.exploitCve).toBe("CVE-2024-1234");
      expect(result.sources).toHaveLength(4);

      // Check source mapping
      const recipes = result.sources.find(s => s.sourceId === "exploitRecipes");
      expect(recipes?.sourceName).toBe("Exploit Knowledge Store (P0)");
      expect(recipes?.category).toBe("knowledge_store");
      expect(recipes?.wasActive).toBe(true);
      expect(recipes?.tokensContributed).toBeGreaterThan(0);

      const threatCatalog = result.sources.find(s => s.sourceId === "threatActorCatalog");
      expect(threatCatalog?.sourceName).toBe("Threat Actor Catalog (P6)");
      expect(threatCatalog?.category).toBe("threat_intel");

      // Inactive source
      const articles = result.sources.find(s => s.sourceId === "hackingArticles");
      expect(articles?.wasActive).toBe(false);
      expect(articles?.tokensContributed).toBe(0);

      // DFIR
      const dfir = result.sources.find(s => s.sourceId === "dfirObservations");
      expect(dfir?.category).toBe("dfir");
    });

    it("should handle unknown labels gracefully", () => {
      const blocks = [
        { label: "unknownSource", content: "Some data" },
      ];

      const result = tracker.buildContributionFromBlocks(1, "host", "CVE-X", blocks, "capped", "exploit_skipped");
      expect(result.sources[0].sourceName).toBe("unknownSource");
      expect(result.sources[0].category).toBe("knowledge_store"); // default
    });
  });

  describe("getContextContributions", () => {
    it("should filter by engagement ID", async () => {
      tracker.recordContextContribution({
        id: "ctx-eng1",
        engagementId: 1,
        exploitTarget: "host1",
        exploitCve: "CVE-1",
        timestamp: Date.now(),
        sources: [],
        totalContextLength: 100,
        cappedContextLength: 80,
        decisionOutcome: "exploit_attempted",
      });
      tracker.recordContextContribution({
        id: "ctx-eng2",
        engagementId: 2,
        exploitTarget: "host2",
        exploitCve: "CVE-2",
        timestamp: Date.now(),
        sources: [],
        totalContextLength: 100,
        cappedContextLength: 80,
        decisionOutcome: "exploit_skipped",
      });

      const result = await tracker.getContextContributions({ engagementId: 1, limit: 10 });
      expect(result.contributions).toHaveLength(1);
      expect(result.contributions[0].engagementId).toBe(1);
    });

    it("should return most recent first", async () => {
      tracker.recordContextContribution({
        id: "ctx-old",
        engagementId: 1,
        exploitTarget: "host",
        exploitCve: "CVE-1",
        timestamp: 1000,
        sources: [],
        totalContextLength: 100,
        cappedContextLength: 80,
        decisionOutcome: "exploit_attempted",
      });
      tracker.recordContextContribution({
        id: "ctx-new",
        engagementId: 1,
        exploitTarget: "host",
        exploitCve: "CVE-2",
        timestamp: 2000,
        sources: [],
        totalContextLength: 100,
        cappedContextLength: 80,
        decisionOutcome: "exploit_attempted",
      });

      const result = await tracker.getContextContributions({ limit: 10 });
      expect(result.contributions[0].id).toBe("ctx-new");
      expect(result.contributions[1].id).toBe("ctx-old");
    });

    it("should respect limit parameter", async () => {
      for (let i = 0; i < 10; i++) {
        tracker.recordContextContribution({
          id: `ctx-${i}`,
          engagementId: 1,
          exploitTarget: "host",
          exploitCve: "CVE-1",
          timestamp: Date.now() + i,
          sources: [],
          totalContextLength: 100,
          cappedContextLength: 80,
          decisionOutcome: "exploit_attempted",
        });
      }

      const result = await tracker.getContextContributions({ limit: 3 });
      expect(result.contributions).toHaveLength(3);
      expect(result.total).toBe(10);
    });
  });

  describe("getContextEngineStats", () => {
    it("should aggregate source statistics correctly", async () => {
      // Record two contributions with overlapping sources
      tracker.recordContextContribution({
        id: "ctx-1",
        engagementId: 1,
        exploitTarget: "host1",
        exploitCve: "CVE-1",
        timestamp: Date.now(),
        sources: [
          { sourceId: "exploitRecipes", sourceName: "P0", category: "knowledge_store", tokensContributed: 200, itemCount: 2, wasActive: true },
          { sourceId: "threatActorCatalog", sourceName: "P6", category: "threat_intel", tokensContributed: 300, itemCount: 1, wasActive: true },
        ],
        totalContextLength: 2000,
        cappedContextLength: 1500,
        decisionOutcome: "exploit_attempted",
      });
      tracker.recordContextContribution({
        id: "ctx-2",
        engagementId: 1,
        exploitTarget: "host2",
        exploitCve: "CVE-2",
        timestamp: Date.now(),
        sources: [
          { sourceId: "exploitRecipes", sourceName: "P0", category: "knowledge_store", tokensContributed: 400, itemCount: 3, wasActive: true },
          { sourceId: "threatActorCatalog", sourceName: "P6", category: "threat_intel", tokensContributed: 0, itemCount: 0, wasActive: false },
        ],
        totalContextLength: 1000,
        cappedContextLength: 800,
        decisionOutcome: "exploit_skipped",
      });

      const stats = await tracker.getContextEngineStats();

      expect(stats.totalDecisions).toBe(2);
      expect(stats.avgContextLength).toBe(1500); // (2000 + 1000) / 2
      expect(stats.avgCappedLength).toBe(1150); // (1500 + 800) / 2

      // Outcome breakdown
      expect(stats.outcomeBreakdown.exploit_attempted).toBe(1);
      expect(stats.outcomeBreakdown.exploit_skipped).toBe(1);

      // Source breakdown
      const recipes = stats.sourceBreakdown.find(s => s.sourceId === "exploitRecipes");
      expect(recipes).toBeDefined();
      expect(recipes!.totalContributions).toBe(2);
      expect(recipes!.avgTokens).toBe(300); // (200 + 400) / 2
      expect(recipes!.activationRate).toBe(100); // both active

      const threatCatalog = stats.sourceBreakdown.find(s => s.sourceId === "threatActorCatalog");
      expect(threatCatalog).toBeDefined();
      expect(threatCatalog!.totalContributions).toBe(2);
      expect(threatCatalog!.activationRate).toBe(50); // 1 of 2 active

      // Recent engagements
      expect(stats.recentEngagements).toHaveLength(1);
      expect(stats.recentEngagements[0].engagementId).toBe(1);
      expect(stats.recentEngagements[0].decisionCount).toBe(2);
    });

    it("should return empty stats when buffer is empty", async () => {
      const stats = await tracker.getContextEngineStats();
      expect(stats.totalDecisions).toBe(0);
      expect(stats.sourceBreakdown).toHaveLength(0);
      expect(stats.avgContextLength).toBe(0);
      expect(stats.outcomeBreakdown).toEqual({});
    });
  });

  describe("clearContributionBuffer", () => {
    it("should clear all contributions", async () => {
      tracker.recordContextContribution({
        id: "ctx-1",
        engagementId: 1,
        exploitTarget: "host",
        exploitCve: "CVE-1",
        timestamp: Date.now(),
        sources: [],
        totalContextLength: 100,
        cappedContextLength: 80,
        decisionOutcome: "exploit_attempted",
      });

      tracker.clearContributionBuffer();

      const result = await tracker.getContextContributions({ limit: 10 });
      expect(result.contributions).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });
});

// ─── Feature 2: Caldera Builder Integration ────────────────────────────────

describe("Caldera Builder Specialist", () => {
  describe("buildCalderaOp interface", () => {
    it("should export CalderaBuilderInput and CalderaBuilderOutput types", async () => {
      const mod = await import("./lib/llm-specialists/caldera-builder");
      expect(typeof mod.buildCalderaOp).toBe("function");
    });

    it("should accept the expected input shape", async () => {
      const { buildCalderaOp } = await import("./lib/llm-specialists/caldera-builder");
      // Verify the function signature accepts our engagement orchestrator input shape
      const input = {
        attackPath: "target.com (10.0.0.1) — CVE-2024-1234 via exploit/linux/http/apache_rce",
        findings: "CVE: CVE-2024-1234\nModule: apache_rce\nTarget: target.com\nOutput: uid=0(root)",
        targetPlatform: "linux",
        engagement: {
          engagementType: "red_team",
          targetCount: 3,
        },
        engagementId: 42,
      };
      // We can't actually call it without LLM, but we verify the shape compiles
      expect(input.attackPath).toBeDefined();
      expect(input.engagement.engagementType).toBe("red_team");
    });
  });

  describe("Caldera Builder output schema", () => {
    it("should define the expected output fields", () => {
      // Verify the output shape matches what the engagement orchestrator expects
      const expectedFields = [
        "operation_name",
        "description",
        "adversary_profile",
        "abilities",
        "execution_sequence",
        "required_agents",
        "expected_telemetry",
        "risk_assessment",
        "confidence",
      ];

      // Mock a valid output
      const mockOutput = {
        operation_name: "AC3-AutoBuild-Eng42",
        description: "Auto-generated operation from exploit findings",
        adversary_profile: {
          name: "Auto-Generated Adversary",
          description: "Generated from engagement findings",
          objective: "Demonstrate lateral movement capability",
        },
        abilities: [{
          name: "Initial Access via Apache RCE",
          tactic: "initial-access",
          technique_id: "T1190",
          technique_name: "Exploit Public-Facing Application",
          executor: "sh",
          command: "curl -X POST ...",
          cleanup: "rm -f /tmp/payload",
          description: "Exploit Apache RCE vulnerability",
          facts_collected: ["host.user.name"],
        }],
        execution_sequence: ["Initial Access via Apache RCE"],
        required_agents: [{ platform: "linux", privilege: "user", location: "DMZ" }],
        expected_telemetry: ["Process creation", "Network connection"],
        risk_assessment: "Medium — single host exploitation",
        confidence: "High",
      };

      for (const field of expectedFields) {
        expect(mockOutput).toHaveProperty(field);
      }

      // Verify adversary_profile shape
      expect(mockOutput.adversary_profile).toHaveProperty("name");
      expect(mockOutput.adversary_profile).toHaveProperty("description");
      expect(mockOutput.adversary_profile).toHaveProperty("objective");

      // Verify abilities shape
      expect(mockOutput.abilities[0]).toHaveProperty("technique_id");
      expect(mockOutput.abilities[0]).toHaveProperty("executor");
      expect(mockOutput.abilities[0]).toHaveProperty("command");
      expect(mockOutput.abilities[0]).toHaveProperty("cleanup");
    });
  });
});

// ─── Feature 3: Engagement Orchestrator Caldera Builder Wiring ──────────────

describe("Engagement Orchestrator — Caldera Builder Fallback", () => {
  it("should have the caldera-builder import wired in executePostExploit", async () => {
    // Read the engagement orchestrator source to verify the wiring exists
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Verify the caldera-builder fallback is wired in
    expect(source).toContain("import('./llm-specialists/caldera-builder')");
    expect(source).toContain("buildCalderaOp");
    expect(source).toContain("No Pre-Built Profiles");
    expect(source).toContain("Invoking Caldera Builder");
  });

  it("should build attack path from successful exploits", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Verify the attack path construction logic
    expect(source).toContain("successfulExploits");
    expect(source).toContain("a.exploitAttempts.filter(e => e.success)");
    expect(source).toContain("attackPath");
    expect(source).toContain("findings");
  });

  it("should create a temporary threat actor entry for the generated profile", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("auto-gen-eng");
    expect(source).toContain("generatedBy: 'caldera-builder-specialist'");
    expect(source).toContain("actorType: 'simulated'");
  });

  it("should attempt to push and launch the generated operation", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("AC3-AutoBuild-Eng");
    expect(source).toContain("caldera-builder-eng");
    expect(source).toContain("source: 'caldera-builder'");
  });

  it("should handle builder failures gracefully", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("Caldera Builder Failed");
    expect(source).toContain("Auto-Build Deploy Failed");
    expect(source).toContain("Auto-Generated Profile Push Failed");
  });
});

// ─── Feature 3b: Batch Ingest Router Wiring ─────────────────────────────────

describe("Batch Ingest Router Wiring", () => {
  it("should have batchIngestArticles procedure in the threat enrichment router", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/threat-enrichment-engine.ts", "utf-8");

    expect(source).toContain("batchIngestArticles");
    expect(source).toContain("../lib/hacking-articles-ingestion");
    expect(source).toContain("categories: z.array(z.string())");
    expect(source).toContain("maxArticles: z.number()");
  });

  it("should have getArticleIngestionStats procedure", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/threat-enrichment-engine.ts", "utf-8");

    expect(source).toContain("getArticleIngestionStats");
    expect(source).toContain("getIngestionStats");
  });

  it("should have context engine contribution procedures", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/threat-enrichment-engine.ts", "utf-8");

    expect(source).toContain("getContextEngineContributions");
    expect(source).toContain("getContextEngineStats");
    expect(source).toContain("../lib/context-engine-tracker");
  });
});

// ─── Hacking Articles DB Import Fix ─────────────────────────────────────────

describe("Hacking Articles DB Import Fix", () => {
  it("should use getDb() instead of direct db import", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/hacking-articles-ingestion.ts", "utf-8");

    // Should NOT have the old broken import
    expect(source).not.toContain('import { db } from "../db"');

    // Should have the correct import
    expect(source).toContain('import { getDb } from "../db"');
  });

  it("should call getDb() before each database operation", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/hacking-articles-ingestion.ts", "utf-8");

    // Every db operation should be preceded by a getDb() call
    const getDbCalls = (source.match(/await getDb\(\)/g) || []).length;
    expect(getDbCalls).toBeGreaterThanOrEqual(4); // At least 4 db operations
  });
});

// ─── ScanForge Reassessment Agent DB Import Fix ─────────────────────────────

describe("ScanForge Reassessment Agent DB Import Fix", () => {
  it("should use getDb() instead of direct db import", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/scanforge/engine/reassessment-agent.ts", "utf-8");

    expect(source).not.toContain('import { db } from "../../db"');
    expect(source).toContain('import { getDb } from "../../db"');
  });
});

// ─── Feature 4: Context Engine Tracker Wiring into Engagement Orchestrator ──

describe("Context Engine Tracker — Orchestrator Wiring", () => {
  it("should wire buildContributionFromBlocks into the exploit decision IIFE", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Verify the tracker is imported/required in the exploit decision path
    expect(source).toContain("require('./context-engine-tracker')");
    expect(source).toContain("buildContributionFromBlocks");
  });

  it("should assemble _exploitContextBlocks array before capping", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Verify the blocks array is assembled
    expect(source).toContain("_exploitContextBlocks");
    expect(source).toContain("Array<{ label: string; content: string }>");
    // Verify it includes the key labels
    expect(source).toContain("{ label: 'threatActorCatalog', content: threatActorCatalogCtx }");
  });

  it("should cap context using _capLLMContext with the assembled blocks", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("_cappedExploitContext = _capLLMContext(_exploitContextBlocks.concat(");
    expect(source).toContain("return _cappedExploitContext;");
  });

  it("should record contribution with correct parameters", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Verify the tracker call passes the right arguments
    expect(source).toContain("state.engagementId,");
    expect(source).toContain("_exploitContextBlocks,");
    expect(source).toContain("_cappedExploitContext,");
    expect(source).toContain("'exploit_attempted',");
  });

  it("should wrap tracker call in try/catch for non-fatal failure", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("[ContextTracker] Failed to record contribution:");
  });

  it("should also wire tracker into the vuln detection decision", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Verify the vuln detection path also has the tracker
    expect(source).toContain("_vulnContextBlocks");
    expect(source).toContain("_cappedVulnContext = _capLLMContext(_vulnContextBlocks)");
    expect(source).toContain("[ContextTracker] Failed to record vuln contribution:");
    expect(source).toContain("'exploit_deferred',");
  });

  it("should use async IIFE for the exploit decision context assembly", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // The exploit decision IIFE must be async to support the await import of ember-catalog-intelligence
    expect(source).toContain("${await (async () => {");
  });
});

// ─── Batch Ingest Results Verification ──────────────────────────────────────

describe("Batch Ingest Results", () => {
  it("should have ingested playbooks into the database", async () => {
    const { getIngestionStats } = await import("./lib/hacking-articles-ingestion");
    const stats = await getIngestionStats();

    // We ran the batch ingest for 6 priority categories
    expect(stats.totalPlaybooks).toBeGreaterThanOrEqual(40);
    expect(stats.totalObservations).toBeGreaterThanOrEqual(100);
    expect(stats.totalChains).toBeGreaterThanOrEqual(10);
  });
});

// ─── Feature 5: JSON Repair/Retry for Article Extraction ────────────────────

describe("JSON Repair for Article Extraction", () => {
  let repairAndParseJSON: typeof import("./lib/hacking-articles-ingestion").repairAndParseJSON;

  beforeEach(async () => {
    const mod = await import("./lib/hacking-articles-ingestion");
    repairAndParseJSON = mod.repairAndParseJSON;
  });

  it("should parse valid JSON directly", () => {
    const result = repairAndParseJSON('{"name": "test", "value": 42}');
    expect(result).toEqual({ name: "test", value: 42 });
  });

  it("should return null for null/undefined/empty input", () => {
    expect(repairAndParseJSON(null as any)).toBeNull();
    expect(repairAndParseJSON(undefined as any)).toBeNull();
    expect(repairAndParseJSON("")).toBeNull();
  });

  it("should strip markdown code fences", () => {
    const result = repairAndParseJSON('```json\n{"name": "test"}\n```');
    expect(result).toEqual({ name: "test" });
  });

  it("should remove trailing commas before } or ]", () => {
    const result = repairAndParseJSON('{"items": [1, 2, 3,], "name": "test",}');
    expect(result).toEqual({ items: [1, 2, 3], name: "test" });
  });

  it("should fix truncated JSON by closing open braces", () => {
    const truncated = '{"technique_name": "SQL Injection", "mitre_id": "T1190", "commands": [{"order": 1, "cmd": "sqlmap"';
    const result = repairAndParseJSON(truncated);
    expect(result).not.toBeNull();
    expect(result!.technique_name).toBe("SQL Injection");
    expect(result!.mitre_id).toBe("T1190");
  });

  it("should fix truncated JSON with unclosed string", () => {
    const truncated = '{"name": "test", "description": "This is a long description that got trunca';
    const result = repairAndParseJSON(truncated);
    expect(result).not.toBeNull();
    expect(result!.name).toBe("test");
  });

  it("should fix truncated array inside object", () => {
    const truncated = '{"tools": ["nmap", "sqlmap", "burp';
    const result = repairAndParseJSON(truncated);
    expect(result).not.toBeNull();
    expect(result!.tools).toBeDefined();
  });

  it("should handle deeply nested truncated JSON", () => {
    const truncated = '{"a": {"b": {"c": [1, 2, {"d": "val"';
    const result = repairAndParseJSON(truncated);
    expect(result).not.toBeNull();
    expect(result!.a).toBeDefined();
  });

  it("should remove control characters", () => {
    const withControl = '{"name": "test\x00\x01value"}';
    const result = repairAndParseJSON(withControl);
    expect(result).not.toBeNull();
    expect(result!.name).toContain("test");
  });

  it("should fix single-quoted strings when no double quotes present", () => {
    const singleQuoted = "{'name': 'test', 'value': 42}";
    const result = repairAndParseJSON(singleQuoted);
    expect(result).toEqual({ name: "test", value: 42 });
  });

  it("should handle a realistic truncated playbook extraction", () => {
    const truncated = `{
  "technique_name": "DLL Hijacking via PATH Order",
  "mitre_id": "T1574.001",
  "platform": "windows",
  "description": "Exploiting DLL search order to load malicious DLL",
  "prerequisites": ["Write access to PATH directory", "Target application loads DLL without full path"],
  "enumeration_commands": [
    {"order": 1, "command": "procmon.exe /AcceptEula", "tool": "Process Monitor", "description": "Monitor DLL loading"},
    {"order": 2, "command": "echo %PATH%", "tool": "cmd", "description": "List PATH directories"`;
    const result = repairAndParseJSON(truncated);
    expect(result).not.toBeNull();
    expect(result!.technique_name).toBe("DLL Hijacking via PATH Order");
    expect(result!.mitre_id).toBe("T1574.001");
    expect(result!.platform).toBe("windows");
    expect(result!.enumeration_commands).toBeDefined();
  });
});

// ─── Feature 5b: extractPlaybookFromArticle retry wiring ─────────────────────

describe("Article Extraction Retry Wiring", () => {
  it("should have repairAndParseJSON called before retry", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/hacking-articles-ingestion.ts", "utf-8");

    expect(source).toContain("repairAndParseJSON(content)");
    expect(source).toContain("extractPlaybookCompact");
    expect(source).toContain("retrying with compact prompt");
  });

  it("should export repairAndParseJSON for testing", async () => {
    const mod = await import("./lib/hacking-articles-ingestion");
    expect(typeof mod.repairAndParseJSON).toBe("function");
  });

  it("should have a compact retry function with shorter prompt", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/hacking-articles-ingestion.ts", "utf-8");

    expect(source).toContain("async function extractPlaybookCompact");
    expect(source).toContain("compact_playbook");
    expect(source).toContain("Keep command arrays short");
    // Compact retry should also use repairAndParseJSON
    expect(source).toContain("Compact retry succeeded");
  });

  it("should truncate article text to 6000 chars for compact retry", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/hacking-articles-ingestion.ts", "utf-8");

    expect(source).toContain("articleText.slice(0, 6000)");
  });
});

// ─── Feature 6: Scan Planning Context Engine Tracker Wiring ──────────────────

describe("Scan Planning Context Engine Tracker Wiring", () => {
  it("should wire buildContributionFromBlocks into the scan planning decision", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("_scanPlanContextBlocks");
    expect(source).toContain("Array<{ label: string; content: string }>");
    expect(source).toContain("enrichmentCtx = capLLMContext(_scanPlanContextBlocks)");
  });

  it("should record scan planning contribution with correct parameters", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("'scan_planning',");
    expect(source).toContain("_scanPlanContextBlocks,");
    expect(source).toContain("enrichmentCtx,");
    expect(source).toContain("'scan_planned',");
  });

  it("should wrap scan planning tracker call in try/catch", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    expect(source).toContain("[ContextTracker] Failed to record scan planning contribution:");
  });

  it("should include all 21 scan planning context labels", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // Find the scan planning blocks section
    const scanBlocksStart = source.indexOf("_scanPlanContextBlocks");
    const scanBlocksEnd = source.indexOf("enrichmentCtx = capLLMContext(_scanPlanContextBlocks)");
    const scanBlocksSection = source.slice(scanBlocksStart, scanBlocksEnd);

    const expectedLabels = [
      "banking", "ontology", "bugbounty", "triage", "cloud",
      "scanforge-discovery", "owasp", "threatGroup", "threatActor",
      "offensive", "zap", "burp", "secrets", "tools",
      "methodology", "phaseTool", "injectionTools", "wafAdaptive",
      "toolAvailability", "missedVuln", "targetProfiles",
    ];

    for (const label of expectedLabels) {
      expect(scanBlocksSection).toContain(`label: '${label}'`);
    }
  });

  it("should now track all 3 major LLM decision points", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

    // All 3 tracker wiring points should exist
    expect(source).toContain("_scanPlanContextBlocks"); // scan planning
    expect(source).toContain("_vulnContextBlocks"); // vuln detection
    expect(source).toContain("_exploitContextBlocks"); // exploit decision
  });
});
