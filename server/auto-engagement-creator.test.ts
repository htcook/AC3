/**
 * Tests for Auto-Engagement Creator
 *
 * Tests the sufficiency check logic and target extraction functions.
 * LLM and DB calls are mocked.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { hasSufficientData, type ParsedPolicyResult } from "./lib/auto-engagement-creator";

describe("Auto-Engagement Creator", () => {
  describe("hasSufficientData", () => {
    it("returns sufficient=true when there are in-scope targets and confidence >= 0.5", () => {
      const policy: ParsedPolicyResult = {
        programName: "Test Program",
        platform: "hackerone",
        programUrl: "https://hackerone.com/test-program",
        scope: {
          inScope: [
            { type: "domain", value: "example.com", eligible: true },
            { type: "url", value: "https://api.example.com", eligible: true },
          ],
          outOfScope: [],
        },
        rules: [],
        safeHarbor: true,
        parsedAt: new Date().toISOString(),
      };

      const result = hasSufficientData(policy, 0.8);
      expect(result.sufficient).toBe(true);
      expect(result.reason).toContain("2 in-scope targets");
    });

    it("returns sufficient=false when no in-scope targets", () => {
      const policy: ParsedPolicyResult = {
        programName: "Empty Program",
        platform: "bugcrowd",
        programUrl: "https://bugcrowd.com/empty",
        scope: {
          inScope: [],
          outOfScope: [{ type: "domain", value: "internal.example.com", eligible: false }],
        },
        rules: [],
        safeHarbor: false,
        parsedAt: new Date().toISOString(),
      };

      const result = hasSufficientData(policy, 0.8);
      expect(result.sufficient).toBe(false);
      expect(result.reason).toContain("No in-scope targets");
    });

    it("returns sufficient=false when program name is unknown", () => {
      const policy: ParsedPolicyResult = {
        programName: "unknown",
        platform: "custom",
        programUrl: "https://example.com/security",
        scope: {
          inScope: [{ type: "domain", value: "example.com", eligible: true }],
          outOfScope: [],
        },
        rules: [],
        safeHarbor: false,
        parsedAt: new Date().toISOString(),
      };

      const result = hasSufficientData(policy, 0.7);
      expect(result.sufficient).toBe(false);
      expect(result.reason).toContain("Program name could not be resolved");
    });

    it("returns sufficient=false when confidence is below 0.5", () => {
      const policy: ParsedPolicyResult = {
        programName: "Low Confidence Program",
        platform: "hackerone",
        programUrl: "https://hackerone.com/low-conf",
        scope: {
          inScope: [{ type: "domain", value: "example.com", eligible: true }],
          outOfScope: [],
        },
        rules: [],
        safeHarbor: false,
        parsedAt: new Date().toISOString(),
      };

      const result = hasSufficientData(policy, 0.3);
      expect(result.sufficient).toBe(false);
      expect(result.reason).toContain("Parse confidence too low");
    });

    it("uses default confidence of 0.6 when not provided", () => {
      const policy: ParsedPolicyResult = {
        programName: "Default Confidence",
        platform: "hackerone",
        programUrl: "https://hackerone.com/default",
        scope: {
          inScope: [{ type: "domain", value: "example.com", eligible: true }],
          outOfScope: [],
        },
        rules: [],
        safeHarbor: false,
        parsedAt: new Date().toISOString(),
      };

      // No confidence param — should use default 0.6 which is >= 0.5
      const result = hasSufficientData(policy);
      expect(result.sufficient).toBe(true);
    });

    it("handles edge case with exactly 0.5 confidence", () => {
      const policy: ParsedPolicyResult = {
        programName: "Edge Case",
        platform: "custom",
        programUrl: "https://example.com/security",
        scope: {
          inScope: [{ type: "url", value: "https://app.example.com", eligible: true }],
          outOfScope: [],
        },
        rules: [],
        safeHarbor: false,
        parsedAt: new Date().toISOString(),
      };

      const result = hasSufficientData(policy, 0.5);
      expect(result.sufficient).toBe(true);
    });

    it("handles multiple asset types in scope", () => {
      const policy: ParsedPolicyResult = {
        programName: "Multi-Asset Program",
        platform: "hackerone",
        programUrl: "https://hackerone.com/multi",
        scope: {
          inScope: [
            { type: "domain", value: "*.example.com", eligible: true },
            { type: "url", value: "https://api.example.com/v1", eligible: true },
            { type: "ip", value: "192.168.1.0/24", eligible: true },
            { type: "source_code", value: "https://github.com/example/repo", eligible: true, notes: "Main repository" },
            { type: "mobile_app", value: "com.example.app", eligible: true },
          ],
          outOfScope: [
            { type: "domain", value: "staging.example.com", eligible: false },
          ],
        },
        rules: ["No DoS", "No social engineering"],
        rewardRange: { low: 100, high: 50000, currency: "$" },
        safeHarbor: true,
        parsedAt: new Date().toISOString(),
      };

      const result = hasSufficientData(policy, 0.8);
      expect(result.sufficient).toBe(true);
      expect(result.reason).toContain("5 in-scope targets");
    });
  });
});
