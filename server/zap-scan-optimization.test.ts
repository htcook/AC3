/**
 * Tests for ZAP Scan Optimization — Focused Fast Playbook & Active Scan Overrides
 *
 * Validates:
 * 1. buildTrainingLabPlaybook returns focused fast rules (not all rules)
 * 2. activeScanOverrides are present and correctly configured
 * 3. Time-based/slow rules are in disabledRuleIds
 * 4. boostPlaybookForTrainingLab adds activeScanOverrides
 * 5. applyPlaybookToZap interface supports activeScanOverrides
 * 6. pollScanProgress uses buildTrainingLabPlaybook for training lab scans (not selectPlaybook)
 * 7. Orchestrator timeout is 45 minutes for training labs
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";

describe("ZAP Scan Optimization — Focused Fast Playbook", () => {
  const zapPlaybooksCode = fs.readFileSync("server/lib/zap-attack-playbooks.ts", "utf-8");
  const zapScannerCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
  const orchestratorCode = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

  describe("buildTrainingLabPlaybook", () => {
    it("should return a playbook named 'training_lab_fast_focused'", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();
      expect(playbook.name).toBe("training_lab_fast_focused");
    });

    it("should have fewer than 35 enabled rules (focused, not all)", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();
      // Focused playbook should have ~25-30 fast rules, not 50+
      expect(playbook.enabledRules.length).toBeLessThan(35);
      expect(playbook.enabledRules.length).toBeGreaterThan(15);
    });

    it("should include key high-value rules (SQLi, XSS, Path Traversal, Cmd Injection)", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();
      const enabledIds = new Set(playbook.enabledRules.map(r => r.id));

      // Must include these critical rules
      expect(enabledIds.has(40018)).toBe(true); // SQL Injection (generic)
      expect(enabledIds.has(40012)).toBe(true); // XSS Reflected
      expect(enabledIds.has(6)).toBe(true);     // Path Traversal
      expect(enabledIds.has(90020)).toBe(true); // OS Command Injection
      expect(enabledIds.has(40014)).toBe(true); // XSS Persistent
    });

    it("should NOT include time-based SQLi rules in enabledRules", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();
      const enabledIds = new Set(playbook.enabledRules.map(r => r.id));

      // Time-based SQLi rules should NOT be enabled
      expect(enabledIds.has(40019)).toBe(false); // MySQL Time Based
      expect(enabledIds.has(40020)).toBe(false); // Hypersonic Time Based
      expect(enabledIds.has(40021)).toBe(false); // Oracle Time Based
      expect(enabledIds.has(40022)).toBe(false); // PostgreSQL Time Based
      expect(enabledIds.has(40027)).toBe(false); // MsSQL Time Based
    });

    it("should have time-based rules in disabledRuleIds", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();
      const disabledIds = new Set(playbook.disabledRuleIds);

      expect(disabledIds.has(40019)).toBe(true); // MySQL Time Based
      expect(disabledIds.has(40020)).toBe(true); // Hypersonic Time Based
      expect(disabledIds.has(90037)).toBe(true); // Time-based OS Cmd Injection
      expect(disabledIds.has(90024)).toBe(true); // Padding Oracle
      expect(disabledIds.has(30001)).toBe(true); // Buffer Overflow
    });

    it("should set all enabled rules to LOW threshold and INSANE strength", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();

      for (const rule of playbook.enabledRules) {
        expect(rule.threshold).toBe("LOW");
        expect(rule.strength).toBe("INSANE");
      }
    });
  });

  describe("activeScanOverrides", () => {
    it("should be defined in ZapPlaybookConfig interface", () => {
      expect(zapPlaybooksCode).toContain("activeScanOverrides?:");
      expect(zapPlaybooksCode).toContain("threadPerHost: number");
      expect(zapPlaybooksCode).toContain("maxRuleDurationInMins: number");
      expect(zapPlaybooksCode).toContain("maxScanDurationInMins: number");
      expect(zapPlaybooksCode).toContain("delayInMs: number");
    });

    it("should be present in buildTrainingLabPlaybook output", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();

      expect(playbook.activeScanOverrides).toBeDefined();
      expect(playbook.activeScanOverrides!.threadPerHost).toBe(10);
      expect(playbook.activeScanOverrides!.maxRuleDurationInMins).toBe(3);
      expect(playbook.activeScanOverrides!.maxScanDurationInMins).toBe(35);
      expect(playbook.activeScanOverrides!.delayInMs).toBe(0);
    });

    it("should be present in boostPlaybookForTrainingLab output", async () => {
      const { selectPlaybook, boostPlaybookForTrainingLab } = await import("./lib/zap-attack-playbooks");
      const base = selectPlaybook("full", ["PHP", "MySQL"]);
      const boosted = boostPlaybookForTrainingLab(base);

      expect(boosted.activeScanOverrides).toBeDefined();
      expect(boosted.activeScanOverrides!.threadPerHost).toBe(10);
      expect(boosted.activeScanOverrides!.maxRuleDurationInMins).toBe(3);
      expect(boosted.activeScanOverrides!.maxScanDurationInMins).toBe(35);
    });
  });

  describe("applyPlaybookToZap — activeScanOverrides handling", () => {
    it("should contain code to apply activeScanOverrides in applyPlaybookToZap", () => {
      // The function should check for activeScanOverrides and call ZAP API
      expect(zapPlaybooksCode).toContain("playbook.activeScanOverrides");
      expect(zapPlaybooksCode).toContain("setOptionThreadPerHost");
      expect(zapPlaybooksCode).toContain("setOptionMaxRuleDurationInMins");
      expect(zapPlaybooksCode).toContain("setOptionMaxScanDurationInMins");
      expect(zapPlaybooksCode).toContain("setOptionDelayInMs");
    });
  });

  describe("pollScanProgress — training lab playbook fix", () => {
    it("should use buildTrainingLabPlaybook for training lab scans (not selectPlaybook)", () => {
      // The critical bug fix: pollScanProgress should detect training lab scans
      // and use buildTrainingLabPlaybook instead of selectPlaybook("full")
      expect(zapScannerCode).toContain("buildTrainingLabPlaybook");
      // Should check for training lab indicators
      expect(zapScannerCode).toContain("isTrainingLab");
    });

    it("should detect training labs by scan name and target URL patterns", () => {
      // Check for the training lab detection patterns
      expect(zapScannerCode).toContain("juice-shop");
      expect(zapScannerCode).toContain("dvwa");
      expect(zapScannerCode).toContain("lab.aceofcloud");
    });
  });

  describe("startScan — uses buildTrainingLabPlaybook directly", () => {
    it("should call buildTrainingLabPlaybook (not boostPlaybookForTrainingLab) for training labs", () => {
      // The startScan function should use the focused fast playbook directly
      // instead of boosting a generic playbook
      const startScanSection = zapScannerCode.slice(
        zapScannerCode.indexOf("if (params.trainingLabMode)"),
        zapScannerCode.indexOf("if (params.trainingLabMode)") + 500
      );
      expect(startScanSection).toContain("buildTrainingLabPlaybook");
    });
  });

  describe("Orchestrator timeout", () => {
    it("should set ZAP timeout to 45 minutes for training labs", () => {
      expect(orchestratorCode).toContain("trainingLabMode ? 45 : 5");
    });

    it("should NOT use the old 25-minute timeout", () => {
      expect(orchestratorCode).not.toContain("trainingLabMode ? 25 : 5");
    });
  });

  describe("No duplicate rules in playbook", () => {
    it("should not have duplicate rule IDs in enabledRules", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();
      const ids = playbook.enabledRules.map(r => r.id);
      const uniqueIds = [...new Set(ids)];
      expect(ids.length).toBe(uniqueIds.length);
    });

    it("should not have overlap between enabledRules and disabledRuleIds", async () => {
      const { buildTrainingLabPlaybook } = await import("./lib/zap-attack-playbooks");
      const playbook = buildTrainingLabPlaybook();
      const enabledIds = new Set(playbook.enabledRules.map(r => r.id));
      const disabledIds = new Set(playbook.disabledRuleIds);

      const overlap = [...enabledIds].filter(id => disabledIds.has(id));
      expect(overlap).toEqual([]);
    });
  });
});
