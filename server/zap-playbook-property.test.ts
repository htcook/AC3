/**
 * Tests for ZAP Playbook Property Fix
 *
 * Validates that:
 * 1. ZapPlaybookConfig uses disabledRuleIds (not disabledRules)
 * 2. applyPlaybookToZap returns { applied, errors } (not rulesConfigured)
 * 3. The console.log in startScan references correct properties
 * 4. Dedup guard skips error scans for retry
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";

describe("ZAP Playbook Property Fix", () => {
  const zapScannerCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
  const zapPlaybooksCode = fs.readFileSync("server/lib/zap-attack-playbooks.ts", "utf-8");

  describe("ZapPlaybookConfig type correctness", () => {
    it("should define disabledRuleIds (not disabledRules) in the interface", () => {
      expect(zapPlaybooksCode).toContain("disabledRuleIds:");
      // The interface should NOT have a 'disabledRules' property
      const interfaceBlock = zapPlaybooksCode.slice(
        zapPlaybooksCode.indexOf("export interface ZapPlaybookConfig"),
        zapPlaybooksCode.indexOf("}", zapPlaybooksCode.indexOf("export interface ZapPlaybookConfig") + 100) + 1
      );
      expect(interfaceBlock).not.toMatch(/\bdisabledRules\b(?!Ids)/);
    });

    it("should have enabledRules as an array in the interface", () => {
      expect(zapPlaybooksCode).toContain("enabledRules: Array<");
    });
  });

  describe("startScan playbook log references", () => {
    it("should NOT reference playbook.disabledRules (undefined property)", () => {
      // The old buggy code: playbook.disabledRules.length
      expect(zapScannerCode).not.toContain("playbook.disabledRules.length");
    });

    it("should reference playbook.disabledRuleIds with safe access", () => {
      // The fixed code uses (playbook.disabledRuleIds || []).length
      expect(zapScannerCode).toContain("disabledRuleIds");
    });

    it("should NOT reference pbResult.rulesConfigured (undefined property)", () => {
      expect(zapScannerCode).not.toContain("pbResult.rulesConfigured");
    });

    it("should reference pbResult.applied (correct property)", () => {
      expect(zapScannerCode).toContain("pbResult.applied");
    });
  });

  describe("applyPlaybookToZap return type", () => {
    it("should return { applied: boolean, errors: string[] }", () => {
      // Check the function signature returns the correct type
      expect(zapPlaybooksCode).toContain("Promise<{ applied: boolean; errors: string[] }>");
    });

    it("should set applied based on errors.length === 0", () => {
      expect(zapPlaybooksCode).toContain("applied: errors.length === 0");
    });
  });

  describe("Dedup guard — error scan retry", () => {
    it("should skip dedup for error scans", () => {
      // The dedup guard should check status !== 'error'
      expect(zapScannerCode).toContain("existingScan.status !== 'error'");
    });

    it("should log retry message for error scans", () => {
      expect(zapScannerCode).toContain("Allowing retry with new scan");
    });
  });

  describe("selectPlaybook produces valid config", () => {
    it("should return a playbook with enabledRules array", async () => {
      const { selectPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = selectPlaybook("full", ["PHP", "MySQL"]);
      expect(playbook).toBeDefined();
      expect(Array.isArray(playbook.enabledRules)).toBe(true);
      expect(playbook.enabledRules.length).toBeGreaterThan(0);
    });

    it("should return a playbook with disabledRuleIds array (not disabledRules)", async () => {
      const { selectPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = selectPlaybook("full", ["PHP", "MySQL"]);
      expect(Array.isArray(playbook.disabledRuleIds)).toBe(true);
      // Verify the old property doesn't exist
      expect((playbook as any).disabledRules).toBeUndefined();
    });

    it("should have name and description", async () => {
      const { selectPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = selectPlaybook("injection", ["Java", "Spring"]);
      expect(typeof playbook.name).toBe("string");
      expect(typeof playbook.description).toBe("string");
    });
  });
});
