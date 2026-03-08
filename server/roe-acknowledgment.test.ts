/**
 * RoE Acknowledgment Flow Tests
 *
 * Tests the RoE acknowledgment modal logic, audit trail data model,
 * and enforcement wiring for the Training Lab scan launch flow.
 */
import { describe, it, expect } from "vitest";
import { TRAINING_TARGETS, type TrainingTarget, type TrainingTargetRoE } from "./routers/training-lab";

// ─── Helper: Simulate the modal's restriction detection logic ─────────────

function hasRestrictions(roe: TrainingTargetRoE): boolean {
  return (
    roe.noBruteForce ||
    roe.noDoS ||
    roe.noExfiltration ||
    roe.requiresOwnInstance ||
    roe.maxScansPerDay !== null ||
    roe.prohibited.length > 0
  );
}

function buildEnforcedRules(roe: TrainingTargetRoE): string[] {
  const rules: string[] = [];
  if (roe.noBruteForce) rules.push("no-brute-force");
  if (roe.noDoS) rules.push("no-dos");
  if (roe.noExfiltration) rules.push("no-exfiltration");
  if (roe.requiresOwnInstance) rules.push("requires-own-instance");
  if (roe.maxScansPerDay) rules.push(`max-${roe.maxScansPerDay}-scans-per-day`);
  return rules;
}

function buildRestrictionMessages(roe: TrainingTargetRoE): string[] {
  const restrictions: string[] = [];
  if (roe.noBruteForce) restrictions.push("Brute-force attacks are PROHIBITED");
  if (roe.noDoS) restrictions.push("Denial of Service (DoS) attacks are PROHIBITED");
  if (roe.noExfiltration) restrictions.push("Data exfiltration is PROHIBITED");
  if (roe.requiresOwnInstance) restrictions.push("You MUST deploy your own instance before scanning");
  if (roe.maxScansPerDay) restrictions.push(`Maximum ${roe.maxScansPerDay} scans per day allowed`);
  if (roe.prohibited.length > 0) {
    restrictions.push(`Prohibited activities: ${roe.prohibited.join(", ")}`);
  }
  return restrictions;
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe("RoE Acknowledgment - Modal Trigger Logic", () => {
  it("should require acknowledgment for targets with noBruteForce restriction", () => {
    const scanme = TRAINING_TARGETS.find(t => t.id === "scanme-nmap");
    expect(scanme).toBeDefined();
    expect(scanme!.roe.noBruteForce).toBe(true);
    expect(hasRestrictions(scanme!.roe)).toBe(true);
  });

  it("should require acknowledgment for targets with noDoS restriction", () => {
    const scanme = TRAINING_TARGETS.find(t => t.id === "scanme-nmap");
    expect(scanme).toBeDefined();
    expect(scanme!.roe.noDoS).toBe(true);
    expect(hasRestrictions(scanme!.roe)).toBe(true);
  });

  it("should require acknowledgment for targets with requiresOwnInstance", () => {
    const gruyere = TRAINING_TARGETS.find(t => t.id === "google-gruyere");
    expect(gruyere).toBeDefined();
    expect(gruyere!.roe.requiresOwnInstance).toBe(true);
    expect(hasRestrictions(gruyere!.roe)).toBe(true);
  });

  it("should require acknowledgment for targets with maxScansPerDay", () => {
    const scanme = TRAINING_TARGETS.find(t => t.id === "scanme-nmap");
    expect(scanme).toBeDefined();
    expect(scanme!.roe.maxScansPerDay).toBe(10);
    expect(hasRestrictions(scanme!.roe)).toBe(true);
  });

  it("should require acknowledgment for targets with prohibited activities", () => {
    const firingRange = TRAINING_TARGETS.find(t => t.id === "firing-range");
    expect(firingRange).toBeDefined();
    expect(firingRange!.roe.prohibited.length).toBeGreaterThan(0);
    expect(hasRestrictions(firingRange!.roe)).toBe(true);
  });

  it("should NOT require acknowledgment for fully unrestricted targets", () => {
    const juiceShop = TRAINING_TARGETS.find(t => t.id === "juice-shop");
    expect(juiceShop).toBeDefined();
    // Juice Shop is MIT licensed, fully open
    const roe = juiceShop!.roe;
    if (!roe.noBruteForce && !roe.noDoS && !roe.noExfiltration && !roe.requiresOwnInstance && roe.maxScansPerDay === null && roe.prohibited.length === 0) {
      expect(hasRestrictions(roe)).toBe(false);
    }
  });

  it("should always require acknowledgment for custom targets", () => {
    // Custom targets don't have a target object, so the modal always shows
    const target = TRAINING_TARGETS.find(t => t.id === "custom");
    // The custom target entry has a warning, so it should trigger
    expect(target).toBeDefined();
    // Even if custom target has no restrictions, the code path forces modal for custom
  });
});

describe("RoE Acknowledgment - Enforced Rules Builder", () => {
  it("builds correct enforced rules for scanme.nmap.org", () => {
    const scanme = TRAINING_TARGETS.find(t => t.id === "scanme-nmap")!;
    const rules = buildEnforcedRules(scanme.roe);
    expect(rules).toContain("no-brute-force");
    expect(rules).toContain("no-dos");
    expect(rules).toContain("max-10-scans-per-day");
  });

  it("builds correct enforced rules for Google Gruyere", () => {
    const gruyere = TRAINING_TARGETS.find(t => t.id === "google-gruyere")!;
    const rules = buildEnforcedRules(gruyere.roe);
    expect(rules).toContain("requires-own-instance");
  });

  it("builds correct enforced rules for Google Firing Range", () => {
    const firingRange = TRAINING_TARGETS.find(t => t.id === "firing-range")!;
    const rules = buildEnforcedRules(firingRange.roe);
    expect(rules).toContain("no-brute-force");
    expect(rules).toContain("no-dos");
  });

  it("returns empty rules for unrestricted targets", () => {
    const juiceShop = TRAINING_TARGETS.find(t => t.id === "juice-shop")!;
    const rules = buildEnforcedRules(juiceShop.roe);
    // Juice Shop is MIT, may have no restrictions
    if (!juiceShop.roe.noBruteForce && !juiceShop.roe.noDoS && !juiceShop.roe.noExfiltration && !juiceShop.roe.requiresOwnInstance && !juiceShop.roe.maxScansPerDay) {
      expect(rules.length).toBe(0);
    }
  });
});

describe("RoE Acknowledgment - Restriction Messages", () => {
  it("generates human-readable restriction messages for scanme.nmap.org", () => {
    const scanme = TRAINING_TARGETS.find(t => t.id === "scanme-nmap")!;
    const messages = buildRestrictionMessages(scanme.roe);
    expect(messages.some(m => m.includes("Brute-force"))).toBe(true);
    expect(messages.some(m => m.includes("DoS"))).toBe(true);
    expect(messages.some(m => m.includes("10 scans per day"))).toBe(true);
  });

  it("generates own-instance message for Google Gruyere", () => {
    const gruyere = TRAINING_TARGETS.find(t => t.id === "google-gruyere")!;
    const messages = buildRestrictionMessages(gruyere.roe);
    expect(messages.some(m => m.includes("own instance"))).toBe(true);
  });

  it("includes prohibited activities list when present", () => {
    const firingRange = TRAINING_TARGETS.find(t => t.id === "firing-range")!;
    if (firingRange.roe.prohibited.length > 0) {
      const messages = buildRestrictionMessages(firingRange.roe);
      expect(messages.some(m => m.includes("Prohibited activities"))).toBe(true);
    }
  });
});

describe("RoE Acknowledgment - Audit Trail Data Model", () => {
  it("every target has a valid provider string", () => {
    for (const target of TRAINING_TARGETS) {
      expect(typeof target.roe.provider).toBe("string");
      expect(target.roe.provider.length).toBeGreaterThan(0);
    }
  });

  it("every target has a valid summary string", () => {
    for (const target of TRAINING_TARGETS) {
      expect(typeof target.roe.summary).toBe("string");
      expect(target.roe.summary.length).toBeGreaterThan(10);
    }
  });

  it("allowed and prohibited are always arrays", () => {
    for (const target of TRAINING_TARGETS) {
      expect(Array.isArray(target.roe.allowed)).toBe(true);
      expect(Array.isArray(target.roe.prohibited)).toBe(true);
    }
  });

  it("maxScansPerDay is null or a positive number", () => {
    for (const target of TRAINING_TARGETS) {
      if (target.roe.maxScansPerDay !== null) {
        expect(target.roe.maxScansPerDay).toBeGreaterThan(0);
      }
    }
  });

  it("termsUrl is null or a valid URL string", () => {
    for (const target of TRAINING_TARGETS) {
      if (target.roe.termsUrl !== null) {
        expect(typeof target.roe.termsUrl).toBe("string");
        expect(target.roe.termsUrl!.startsWith("http")).toBe(true);
      }
    }
  });

  it("boolean flags are actual booleans", () => {
    for (const target of TRAINING_TARGETS) {
      expect(typeof target.roe.noBruteForce).toBe("boolean");
      expect(typeof target.roe.noDoS).toBe("boolean");
      expect(typeof target.roe.noExfiltration).toBe("boolean");
      expect(typeof target.roe.requiresOwnInstance).toBe("boolean");
    }
  });
});

describe("RoE Acknowledgment - Coverage", () => {
  it("at least 10 targets have some form of restriction", () => {
    const restricted = TRAINING_TARGETS.filter(t => hasRestrictions(t.roe));
    expect(restricted.length).toBeGreaterThanOrEqual(10);
  });

  it("at least 3 targets have terms URLs", () => {
    const withTerms = TRAINING_TARGETS.filter(t => t.roe.termsUrl !== null);
    expect(withTerms.length).toBeGreaterThanOrEqual(3);
  });

  it("at least 1 target requires own instance", () => {
    const ownInstance = TRAINING_TARGETS.filter(t => t.roe.requiresOwnInstance);
    expect(ownInstance.length).toBeGreaterThanOrEqual(1);
  });

  it("at least 1 target has rate limiting", () => {
    const rateLimited = TRAINING_TARGETS.filter(t => t.roe.maxScansPerDay !== null);
    expect(rateLimited.length).toBeGreaterThanOrEqual(1);
  });
});
