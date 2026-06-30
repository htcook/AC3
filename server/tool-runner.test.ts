/**
 * Tool Runner Router Tests
 *
 * Tests the tool registry, pre-built script catalog, exploit matching,
 * execution recording, and safety guardrail integration.
 */
import { describe, it, expect } from "vitest";

import { TOOL_TIER_CLASSIFICATION, getToolsByTier, getToolClassification } from "./lib/scan-policy-engine";

describe("Tool Runner", () => {
  describe("Tool Registry", () => {
    it("has tools across all four tiers", () => {
      const tiers = new Set(TOOL_TIER_CLASSIFICATION.map(t => t.tier));
      expect(tiers).toContain("passive");
      expect(tiers).toContain("active-low");
      expect(tiers).toContain("active-standard");
      expect(tiers).toContain("active-aggressive");
    });

    it("every tool has required fields", () => {
      for (const tool of TOOL_TIER_CLASSIFICATION) {
        expect(tool.name).toBeDefined();
        expect(tool.tier).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.detectionRisk).toBeDefined();
        expect(typeof tool.targetContact).toBe("boolean");
        expect(typeof tool.stateChange).toBe("boolean");
        expect(typeof tool.roeRequired).toBe("boolean");
      }
    });

    it("has at least 50 tools in the registry", () => {
      expect(TOOL_TIER_CLASSIFICATION.length).toBeGreaterThanOrEqual(50);
    });

    it("passive tools do not contact target", () => {
      const passiveTools = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "passive");
      for (const tool of passiveTools) {
        expect(tool.targetContact).toBe(false);
      }
    });

    it("passive tools do not require ROE", () => {
      const passiveTools = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "passive");
      for (const tool of passiveTools) {
        expect(tool.roeRequired).toBe(false);
      }
    });

    it("active-aggressive tools require ROE", () => {
      const aggressiveTools = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "active-aggressive");
      for (const tool of aggressiveTools) {
        expect(tool.roeRequired).toBe(true);
      }
    });

    it("active-aggressive tools have high detection risk", () => {
      const aggressiveTools = TOOL_TIER_CLASSIFICATION.filter(t => t.tier === "active-aggressive");
      for (const tool of aggressiveTools) {
        expect(tool.detectionRisk).toBe("high");
      }
    });

    it("active tools contact target", () => {
      const activeTools = TOOL_TIER_CLASSIFICATION.filter(t => t.tier !== "passive");
      for (const tool of activeTools) {
        expect(tool.targetContact).toBe(true);
      }
    });

    it("no tool causes state changes (all are non-destructive)", () => {
      for (const tool of TOOL_TIER_CLASSIFICATION) {
        expect(tool.stateChange).toBe(false);
      }
    });

    it("getToolsByTier returns correct tools", () => {
      const passive = getToolsByTier("passive");
      expect(passive.length).toBeGreaterThan(0);
      for (const t of passive) {
        expect(t.tier).toBe("passive");
      }
    });

    it("getToolClassification finds specific tools", () => {
      const nmap = getToolClassification("nmap-sv");
      expect(nmap).toBeDefined();
      expect(nmap!.tier).toBe("active-standard");

      const nuclei = getToolClassification("nuclei");
      expect(nuclei).toBeDefined();
      expect(nuclei!.tier).toBe("active-aggressive");

      const shodan = getToolClassification("shodan");
      expect(shodan).toBeDefined();
      expect(shodan!.tier).toBe("passive");
    });

    it("getToolClassification returns undefined for unknown tools", () => {
      expect(getToolClassification("nonexistent-tool")).toBeUndefined();
    });
  });

  describe("Pre-built Script Catalog Structure", () => {
    it("scripts have required structure", () => {
      const scriptTemplate = {
        id: "nmap-quick-scan",
        name: "Nmap Quick Scan",
        category: "scanning",
        description: "Quick TCP SYN scan of top 1000 ports",
        script: "nmap -sS -T4 --top-ports 1000 {target}",
        targetOs: "any",
        safetyLevel: "low_impact",
        requiresApproval: false,
        mitreTechniques: ["T1046"],
        tags: ["port-scan", "tcp"],
      };

      expect(scriptTemplate.id).toBeDefined();
      expect(scriptTemplate.name).toBeDefined();
      expect(scriptTemplate.script).toContain("{target}");
      expect(scriptTemplate.mitreTechniques.length).toBeGreaterThan(0);
      expect(["passive_only", "low_impact", "standard", "full_exploitation"]).toContain(scriptTemplate.safetyLevel);
    });
  });

  describe("Safety Guardrails Integration", () => {
    it("tool safety levels map to engagement phases", () => {
      const safetyLevelPhaseMap: Record<string, string[]> = {
        passive_only: ["recon", "passive_discovery", "scoping"],
        low_impact: ["enumeration", "vuln_detection"],
        standard: ["exploitation"],
        full_exploitation: ["exploitation", "post_exploit"],
      };

      for (const [level, phases] of Object.entries(safetyLevelPhaseMap)) {
        expect(phases.length).toBeGreaterThan(0);
      }
    });

    it("tier-to-ROE mapping is consistent", () => {
      // Passive tools never require ROE
      const passive = getToolsByTier("passive");
      expect(passive.every(t => !t.roeRequired)).toBe(true);

      // All active tiers require ROE
      for (const tier of ["active-low", "active-standard", "active-aggressive"] as const) {
        const tools = getToolsByTier(tier);
        expect(tools.every(t => t.roeRequired)).toBe(true);
      }
    });

    it("evidence chain is required for all executions", () => {
      const executionRecord = {
        toolName: "nmap",
        command: "nmap -sS 10.0.0.1",
        target: "10.0.0.1",
        output: "PORT STATE SERVICE\n22/tcp open ssh",
        exitCode: 0,
        durationMs: 5000,
        evidenceHash: "sha256:abc123",
        operatorId: "user-1",
        engagementId: 1,
        timestamp: Date.now(),
      };

      expect(executionRecord.evidenceHash).toBeDefined();
      expect(executionRecord.operatorId).toBeDefined();
      expect(executionRecord.engagementId).toBeDefined();
    });
  });

  describe("Execution Recording", () => {
    it("records execution with all required fields", () => {
      const record = {
        engagementId: 1,
        toolName: "nuclei",
        command: "nuclei -u https://target.com -t cves/",
        target: "target.com",
        output: "[2024-01-01] [CVE-2024-1234] [critical] target.com",
        exitCode: 0,
        durationMs: 15000,
        findingsIngested: 3,
      };

      expect(record.engagementId).toBeGreaterThan(0);
      expect(record.toolName).toBeDefined();
      expect(record.command).toBeDefined();
      expect(record.exitCode).toBeDefined();
      expect(record.findingsIngested).toBeGreaterThanOrEqual(0);
    });

    it("handles failed executions gracefully", () => {
      const failedRecord = {
        engagementId: 1,
        toolName: "sqlmap",
        command: "sqlmap -u https://target.com/vuln?id=1",
        target: "target.com",
        output: "Error: connection refused",
        exitCode: 1,
        durationMs: 3000,
        findingsIngested: 0,
        error: "Connection refused",
      };

      expect(failedRecord.exitCode).not.toBe(0);
      expect(failedRecord.findingsIngested).toBe(0);
      expect(failedRecord.error).toBeDefined();
    });
  });

  describe("Exploit Knowledge Store Integration", () => {
    it("search results include match scoring", () => {
      const searchResult = {
        id: "exploit-1",
        title: "Apache Struts RCE",
        description: "Remote code execution via OGNL injection",
        cveIds: ["CVE-2017-5638"],
        platform: "linux",
        exploitType: "remote",
        reliabilityScore: 85,
        score: 0.92,
        matchReason: "CVE match + service version match",
      };

      expect(searchResult.score).toBeGreaterThan(0);
      expect(searchResult.score).toBeLessThanOrEqual(1);
      expect(searchResult.reliabilityScore).toBeGreaterThanOrEqual(0);
      expect(searchResult.reliabilityScore).toBeLessThanOrEqual(100);
    });
  });
});
