import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Tests for the tiered LLM routing system.
 * Verifies that:
 * 1. max_tokens is capped at 16384 (not 32768)
 * 2. _priority parameter is accepted by InvokeParams
 * 3. Provider routing logic works correctly per tier
 * 4. Essential calls are tagged in accuracy-critical files
 * 5. Bulk calls are tagged in commodity task files
 */

describe("Tiered LLM Routing", () => {
  // ─── max_tokens fix ───────────────────────────────────────────────
  describe("max_tokens limit", () => {
    it("should set max_tokens to 16384, not 32768", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toContain("payload.max_tokens = 16384");
      expect(llmSource).not.toContain("payload.max_tokens = 32768");
    });
  });

  // ─── Priority parameter ───────────────────────────────────────────
  describe("_priority parameter", () => {
    it("should define LLMPriority type with three tiers", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toContain('"essential" | "standard" | "bulk"');
    });

    it("should accept _priority in InvokeParams", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toContain("_priority?: LLMPriority");
    });

    it("should default _priority to standard when not provided", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toContain("_priority = 'standard'");
    });
  });

  // ─── Provider resolution ──────────────────────────────────────────
  describe("resolveProvider routing", () => {
    it("should route essential calls to OpenAI when key is available", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      // resolveProvider should check priority and route essential to OpenAI
      expect(llmSource).toContain("case 'essential':");
      expect(llmSource).toMatch(/essential.*OpenAI/);
    });

    it("should route bulk calls to Forge always", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toContain("case 'bulk':");
      expect(llmSource).toMatch(/bulk.*Forge/);
    });

    it("should route standard calls to Forge by default", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toContain("case 'standard':");
      expect(llmSource).toMatch(/standard.*Forge/);
    });

    it("should fall back to Forge when OpenAI key is not set for essential calls", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toMatch(/essential but no OpenAI key.*Forge fallback/);
    });

    it("should pass priority to resolveProvider in invokeLLM", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toContain("resolveProvider(_priority)");
    });

    it("should log priority in the LLM request log line", async () => {
      const llmSource = await import("fs").then(fs =>
        fs.readFileSync("/home/ubuntu/caldera-dashboard/server/_core/llm.ts", "utf-8")
      );
      expect(llmSource).toMatch(/priority=.*_priority/);
    });
  });

  // ─── Essential call tagging ───────────────────────────────────────
  describe("essential call tagging", () => {
    const essentialFiles = [
      "server/lib/llm-specialists/vuln-verifier.ts",
      "server/lib/llm-specialists/attack-planner.ts",
      "server/lib/llm-specialists/hybrid-scorer.ts",
      "server/lib/llm-specialists/caldera-builder.ts",
      "server/lib/llm-specialists/scan-analyst.ts",
      "server/lib/ai-attack-planner.ts",
      "server/lib/exploit-asset-matcher.ts",
      "server/lib/scoring-engine.ts",
      "server/lib/chain-builder.ts",
      "server/lib/privesc-engine.ts",
    ];

    for (const file of essentialFiles) {
      it(`should tag ${file.split("/").pop()} as essential`, async () => {
        const fs = await import("fs");
        const filePath = `/home/ubuntu/caldera-dashboard/${file}`;
        if (fs.existsSync(filePath)) {
          const source = fs.readFileSync(filePath, "utf-8");
          expect(source).toContain("_priority: 'essential'");
        }
      });
    }
  });

  // ─── Bulk call tagging ────────────────────────────────────────────
  describe("bulk call tagging", () => {
    const bulkFiles = [
      "server/lib/llm-specialists/report-writer.ts",
      "server/lib/report-generator.ts",
      "server/lib/darkweb-enrichment-service.ts",
      "server/lib/entity-resolver.ts",
      "server/lib/ransomware-intel.ts",
      "server/lib/threat-intel-catalog.ts",
      "server/lib/campaign-advisor.ts",
      "server/routers/error-log.ts",
      "server/routers/reports-core.ts",
    ];

    for (const file of bulkFiles) {
      it(`should tag ${file.split("/").pop()} as bulk`, async () => {
        const fs = await import("fs");
        const filePath = `/home/ubuntu/caldera-dashboard/${file}`;
        if (fs.existsSync(filePath)) {
          const source = fs.readFileSync(filePath, "utf-8");
          expect(source).toContain("_priority: 'bulk'");
        }
      });
    }
  });

  // ─── domainIntel pipeline tagging ─────────────────────────────────
  describe("domainIntel pipeline tagging", () => {
    it("should tag risk analysis as essential in domainIntel.ts", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("/home/ubuntu/caldera-dashboard/server/domainIntel.ts", "utf-8");
      // Find the system message version (in the invokeLLM call)
      const systemMsgIdx = source.indexOf('"You are a cybersecurity risk analyst. Return only valid JSON."');
      expect(systemMsgIdx).toBeGreaterThan(-1);
      const essentialBefore = source.lastIndexOf("_priority: 'essential' as const", systemMsgIdx);
      expect(essentialBefore).toBeGreaterThan(-1);
      // Distance should be small (within the same invokeLLMWithTimeout call)
      expect(systemMsgIdx - essentialBefore).toBeLessThan(200);
    });

    it("should tag campaign designer as bulk in domainIntel.ts", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("/home/ubuntu/caldera-dashboard/server/domainIntel.ts", "utf-8");
      // Find the system message version (in the invokeLLM call), not the prompt template
      const systemMsgIdx = source.indexOf('"You are a red team campaign designer. Return only valid JSON."');
      expect(systemMsgIdx).toBeGreaterThan(-1);
      const bulkBefore = source.lastIndexOf("_priority: 'bulk' as const", systemMsgIdx);
      expect(bulkBefore).toBeGreaterThan(-1);
      expect(systemMsgIdx - bulkBefore).toBeLessThan(200);
    });

    it("should tag report writers as bulk in domainIntel.ts", async () => {
      const fs = await import("fs");
      const source = fs.readFileSync("/home/ubuntu/caldera-dashboard/server/domainIntel.ts", "utf-8");
      const reportWriterMatches = source.match(/cybersecurity report writer/g);
      expect(reportWriterMatches).not.toBeNull();
      expect(reportWriterMatches!.length).toBeGreaterThanOrEqual(2);
      // Both report writer calls should have bulk priority
      let searchFrom = 0;
      for (const _ of reportWriterMatches!) {
        const idx = source.indexOf("cybersecurity report writer", searchFrom);
        const bulkBefore = source.lastIndexOf("_priority: 'bulk'", idx);
        expect(bulkBefore).toBeGreaterThan(searchFrom > 0 ? searchFrom - 200 : -1);
        searchFrom = idx + 1;
      }
    });
  });

  // ─── Token conservation estimate ──────────────────────────────────
  describe("token conservation", () => {
    it("should have more bulk+standard calls than essential calls", async () => {
      const fs = await import("fs");
      const { execSync } = await import("child_process");
      const essentialCount = parseInt(
        execSync(
          "grep -rn \"_priority: 'essential'\" /home/ubuntu/caldera-dashboard/server/ --include='*.ts' | grep -v '.test.' | wc -l"
        ).toString().trim()
      );
      const bulkCount = parseInt(
        execSync(
          "grep -rn \"_priority: 'bulk'\" /home/ubuntu/caldera-dashboard/server/ --include='*.ts' | grep -v '.test.' | wc -l"
        ).toString().trim()
      );
      // Essential should be a minority of total calls (< 25 out of ~95)
      expect(essentialCount).toBeLessThan(25);
      expect(essentialCount).toBeGreaterThan(0);
      // Bulk should be significant
      expect(bulkCount).toBeGreaterThan(15);
      // Bulk should be more than essential
      expect(bulkCount).toBeGreaterThan(essentialCount);
    });
  });
});
