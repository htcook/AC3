/**
 * Training RoE Guard — Vitest Tests
 * Tests enforcement of Rules of Engagement for training targets
 */
import { describe, it, expect } from "vitest";
import {
  enforceTrainingRoE,
  sanitizeNmapFlags,
  filterNucleiTemplates,
  formatRoESummary,
} from "./lib/training-roe-guard";
import { TRAINING_TARGETS } from "./routers/training-lab";
import type { TrainingTarget, TrainingTargetRoE } from "./routers/training-lab";

// ─── Helper ──────────────────────────────────────────────────────────

function findTarget(id: string): TrainingTarget {
  const t = TRAINING_TARGETS.find(t => t.id === id);
  if (!t) throw new Error(`Target ${id} not found`);
  return t;
}

// ─── RoE Data Model Tests ────────────────────────────────────────────

describe("RoE Data Model", () => {
  it("every training target has a valid RoE object", () => {
    for (const target of TRAINING_TARGETS) {
      expect(target.roe).toBeDefined();
      expect(typeof target.roe.provider).toBe("string");
      expect(typeof target.roe.summary).toBe("string");
      expect(Array.isArray(target.roe.allowed)).toBe(true);
      expect(Array.isArray(target.roe.prohibited)).toBe(true);
      expect(typeof target.roe.noBruteForce).toBe("boolean");
      expect(typeof target.roe.noDoS).toBe("boolean");
      expect(typeof target.roe.noExfiltration).toBe("boolean");
      expect(typeof target.roe.requiresOwnInstance).toBe("boolean");
    }
  });

  it("all targets have RoE data", () => {
    expect(TRAINING_TARGETS.length).toBeGreaterThanOrEqual(20);
    const withRoE = TRAINING_TARGETS.filter(t => t.roe && t.roe.summary.length > 0);
    expect(withRoE.length).toBe(TRAINING_TARGETS.length);
  });

  it("scanme.nmap.org has correct restrictions", () => {
    const target = findTarget("scanme-nmap");
    expect(target.roe.noBruteForce).toBe(true);
    expect(target.roe.noDoS).toBe(true);
    expect(target.roe.maxScansPerDay).toBe(10);
    expect(target.roe.prohibited).toContain("SSH brute-force");
  });

  it("google-gruyere requires own instance", () => {
    const target = findTarget("google-gruyere");
    expect(target.roe.requiresOwnInstance).toBe(true);
    expect(target.roe.noBruteForce).toBe(true);
    expect(target.roe.noExfiltration).toBe(true);
  });

  it("firing-range prohibits brute-force and DoS", () => {
    const target = findTarget("firing-range");
    expect(target.roe.noBruteForce).toBe(true);
    expect(target.roe.noDoS).toBe(true);
    expect(target.roe.noExfiltration).toBe(true);
  });

  it("juice-shop has no restrictions (MIT license)", () => {
    const target = findTarget("juice-shop");
    expect(target.roe.noBruteForce).toBe(false);
    expect(target.roe.noDoS).toBe(false);
    expect(target.roe.noExfiltration).toBe(false);
    expect(target.roe.requiresOwnInstance).toBe(false);
    expect(target.roe.maxScansPerDay).toBeNull();
  });

  it("custom target has warning about authorization", () => {
    const target = findTarget("custom");
    expect(target.roe.summary).toContain("YOU must ensure");
    expect(target.roe.notes).toContain("illegal");
  });
});

// ─── Enforcement Tests ───────────────────────────────────────────────

describe("enforceTrainingRoE", () => {
  it("allows standard scan on unrestricted target", () => {
    const target = findTarget("juice-shop");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
    });
    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it("blocks brute-force on noBruteForce target", () => {
    const target = findTarget("scanme-nmap");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
      enableBruteForce: true,
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0].rule).toBe("noBruteForce");
  });

  it("blocks DoS on noDoS target", () => {
    const target = findTarget("vulnweb-php");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
      enableDoS: true,
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.some(v => v.rule === "noDoS")).toBe(true);
  });

  it("blocks exfiltration on noExfiltration target", () => {
    const target = findTarget("firing-range");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
      enableExfiltration: true,
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.some(v => v.rule === "noExfiltration")).toBe(true);
  });

  it("warns about own instance requirement for Google Gruyere", () => {
    const target = findTarget("google-gruyere");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
    });
    // Should be allowed (it's a warning, not a block) but with warnings
    expect(result.warnings.some(w => w.rule === "requiresOwnInstance")).toBe(true);
  });

  it("blocks brute-force nuclei templates on restricted targets", () => {
    const target = findTarget("scanme-nmap");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
      customNucleiTemplates: ["http-brute-force", "ssh-credential-stuffing"],
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.some(v => v.message.includes("brute-force/credential"))).toBe(true);
  });

  it("blocks brute-force nmap scripts on restricted targets", () => {
    const target = findTarget("firing-range");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
      customNmapFlags: "--script=brute -sV",
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.some(v => v.message.includes("brute-force script"))).toBe(true);
  });

  it("returns enforced rules list", () => {
    const target = findTarget("scanme-nmap");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
    });
    expect(result.enforcedRules).toContain("No brute-force attacks");
    expect(result.enforcedRules).toContain("No DoS/DDoS attacks");
    expect(result.enforcedRules.some(r => r.includes("Max"))).toBe(true);
  });

  it("warns about custom target authorization", () => {
    const target = findTarget("custom");
    const result = enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: "standard",
    });
    expect(result.warnings.some(w => w.rule === "customTarget")).toBe(true);
  });
});

// ─── Nmap Flag Sanitization Tests ────────────────────────────────────

describe("sanitizeNmapFlags", () => {
  it("removes brute-force scripts when noBruteForce is true", () => {
    const roe: TrainingTargetRoE = {
      provider: "test", termsUrl: null, summary: "test",
      allowed: [], prohibited: [], rateLimit: null,
      requiresOwnInstance: false, noBruteForce: true, noDoS: false,
      noExfiltration: false, maxScansPerDay: null, notes: null,
    };
    const result = sanitizeNmapFlags("-sV --script=brute -T4", roe);
    expect(result).not.toContain("brute");
    expect(result).toContain("-sV");
    expect(result).toContain("-T4");
  });

  it("downgrades -T5 to -T3 when noDoS is true", () => {
    const roe: TrainingTargetRoE = {
      provider: "test", termsUrl: null, summary: "test",
      allowed: [], prohibited: [], rateLimit: null,
      requiresOwnInstance: false, noBruteForce: false, noDoS: true,
      noExfiltration: false, maxScansPerDay: null, notes: null,
    };
    const result = sanitizeNmapFlags("-sV -T5 --open", roe);
    expect(result).not.toContain("-T5");
    expect(result).toContain("-T3");
  });

  it("leaves flags unchanged for unrestricted targets", () => {
    const roe: TrainingTargetRoE = {
      provider: "test", termsUrl: null, summary: "test",
      allowed: [], prohibited: [], rateLimit: null,
      requiresOwnInstance: false, noBruteForce: false, noDoS: false,
      noExfiltration: false, maxScansPerDay: null, notes: null,
    };
    const flags = "-sV -sC -T5 --script=brute --open";
    const result = sanitizeNmapFlags(flags, roe);
    expect(result).toBe(flags);
  });
});

// ─── Nuclei Template Filtering Tests ─────────────────────────────────

describe("filterNucleiTemplates", () => {
  it("blocks brute-force templates when noBruteForce is true", () => {
    const roe: TrainingTargetRoE = {
      provider: "test", termsUrl: null, summary: "test",
      allowed: [], prohibited: [], rateLimit: null,
      requiresOwnInstance: false, noBruteForce: true, noDoS: false,
      noExfiltration: false, maxScansPerDay: null, notes: null,
    };
    const result = filterNucleiTemplates(
      ["xss-detection", "sqli-check", "http-brute-force", "credential-stuffing", "cve-2024-1234"],
      roe
    );
    expect(result.allowed).toContain("xss-detection");
    expect(result.allowed).toContain("sqli-check");
    expect(result.allowed).toContain("cve-2024-1234");
    expect(result.blocked).toContain("http-brute-force");
    expect(result.blocked).toContain("credential-stuffing");
  });

  it("blocks DoS templates when noDoS is true", () => {
    const roe: TrainingTargetRoE = {
      provider: "test", termsUrl: null, summary: "test",
      allowed: [], prohibited: [], rateLimit: null,
      requiresOwnInstance: false, noBruteForce: false, noDoS: true,
      noExfiltration: false, maxScansPerDay: null, notes: null,
    };
    const result = filterNucleiTemplates(
      ["xss-detection", "dos-slowloris", "flood-test"],
      roe
    );
    expect(result.allowed).toContain("xss-detection");
    expect(result.blocked).toContain("dos-slowloris");
    expect(result.blocked).toContain("flood-test");
  });

  it("allows all templates for unrestricted targets", () => {
    const roe: TrainingTargetRoE = {
      provider: "test", termsUrl: null, summary: "test",
      allowed: [], prohibited: [], rateLimit: null,
      requiresOwnInstance: false, noBruteForce: false, noDoS: false,
      noExfiltration: false, maxScansPerDay: null, notes: null,
    };
    const templates = ["brute-force", "dos-test", "xss-detection"];
    const result = filterNucleiTemplates(templates, roe);
    expect(result.allowed).toHaveLength(3);
    expect(result.blocked).toHaveLength(0);
  });
});

// ─── Format Summary Tests ────────────────────────────────────────────

describe("formatRoESummary", () => {
  it("returns a non-empty string for all targets", () => {
    for (const target of TRAINING_TARGETS) {
      const summary = formatRoESummary(target);
      expect(summary.length).toBeGreaterThan(0);
      expect(summary).toContain("Provider:");
      expect(summary).toContain("Summary:");
    }
  });

  it("includes rate limit info when present", () => {
    const target = findTarget("scanme-nmap");
    const summary = formatRoESummary(target);
    expect(summary).toContain("Max Scans/Day:");
    expect(summary).toContain("Rate Limit:");
  });

  it("includes terms URL when present", () => {
    const target = findTarget("juice-shop");
    const summary = formatRoESummary(target);
    expect(summary).toContain("Terms URL:");
    expect(summary).toContain("owasp.org");
  });
});
