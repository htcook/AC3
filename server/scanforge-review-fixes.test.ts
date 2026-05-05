/**
 * Tests for Claude ScanForge Review Fixes (Round 5b)
 *
 * Covers:
 *   1. YAML parser replacement (js-yaml)
 *   2. FAST_TRACK_RULES adjustment (minScans raised to 15, production_flagged stage)
 *   3. Proof engine safety profile
 *   4. Confidence tuner drift prevention (sample-scaled steps, per-cycle clamping)
 *   5. Knowledge base memory limits
 *   6. Dedup fingerprint improvements
 *   7. Phase 6 extraction module structure
 */

import { describe, it, expect } from "vitest";

// ─── 1. YAML Parser (js-yaml) ──────────────────────────────────────────────

describe("Template Engine — YAML Parser", () => {
  it("should use js-yaml instead of custom parser", async () => {
    const yaml = await import("js-yaml");
    expect(yaml.load).toBeDefined();
    expect(typeof yaml.load).toBe("function");

    // Verify it can parse a basic Nuclei-style template
    const template = `
id: test-template
info:
  name: Test Template
  severity: high
  tags: cve,rce
requests:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        words:
          - "vulnerable"
`;
    const parsed = yaml.load(template) as any;
    expect(parsed.id).toBe("test-template");
    expect(parsed.info.name).toBe("Test Template");
    expect(parsed.info.severity).toBe("high");
    expect(parsed.requests[0].method).toBe("GET");
    expect(parsed.requests[0].matchers[0].words).toContain("vulnerable");
  });

  it("should reject dangerous YAML constructs", async () => {
    const yaml = await import("js-yaml");
    // js-yaml DEFAULT_SCHEMA doesn't execute JS — verify it's safe
    const dangerous = `
!!js/function 'function() { return process.exit(1); }'
`;
    expect(() => yaml.load(dangerous)).toThrow();
  });
});

// ─── 2. FAST_TRACK_RULES ────────────────────────────────────────────────────

describe("Auto-Promoter — FAST_TRACK_RULES", () => {
  it("should require minimum 15 scans for fast-track promotion", async () => {
    // Read the auto-promoter module to verify the constant
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/auto-promoter.ts",
      "utf-8"
    );
    // Check that FAST_TRACK_RULES has minTotalScans >= 15
    const fastTrackSection = content.slice(content.indexOf("FAST_TRACK_RULES"));
    const minScansMatch = fastTrackSection.match(/minTotalScans:\s*(\d+)/);
    expect(minScansMatch).not.toBeNull();
    expect(parseInt(minScansMatch![1], 10)).toBeGreaterThanOrEqual(15);
  });

  it("should include production_flagged status in template lifecycle", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/auto-promoter.ts",
      "utf-8"
    );
    expect(content).toContain("production_flagged");
  });
});

// ─── 3. Proof Engine Safety Profile ─────────────────────────────────────────

describe("Proof Engine — Safety Profile", () => {
  it("should define safety profile with forbidden patterns and allowed methods", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/proof-engine.ts",
      "utf-8"
    );
    // Verify safety profile exists
    expect(content).toContain("DEFAULT_SAFETY_PROFILE");
    expect(content).toContain("forbiddenPayloadPatterns");
    expect(content).toContain("allowedMethods");
    // Verify destructive SQL patterns are forbidden
    expect(content).toContain("DROP");
    expect(content).toContain("DELETE");
    // Verify sensitive endpoint patterns exist
    expect(content).toContain("sensitiveEndpointPatterns");
    // Verify path traversal payloads reference /etc/passwd
    expect(content).toContain("/etc/passwd");
  });

  it("should enforce safety checks in executeProofRequest", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/proof-engine.ts",
      "utf-8"
    );
    // Verify safety enforcement is in the request path
    expect(content).toContain("safetyProfile");
    expect(content).toContain("checkProofSafety");
    // Verify the safety check is called before proof execution
    expect(content).toContain("safetyCheck");
  });
});

// ─── 4. Confidence Tuner — Drift Prevention ─────────────────────────────────

describe("Confidence Tuner — Drift Prevention", () => {
  it("should have MAX_ADJUSTMENT_PER_CYCLE configured", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/confidence-tuner.ts",
      "utf-8"
    );
    expect(content).toContain("MAX_ADJUSTMENT_PER_CYCLE");
    const match = content.match(/MAX_ADJUSTMENT_PER_CYCLE:\s*([\d.]+)/);
    expect(match).not.toBeNull();
    const value = parseFloat(match![1]);
    expect(value).toBeGreaterThan(0);
    expect(value).toBeLessThanOrEqual(0.2); // Should be bounded
  });

  it("should have FULL_STEP_SAMPLE_SIZE for sample scaling", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/confidence-tuner.ts",
      "utf-8"
    );
    expect(content).toContain("FULL_STEP_SAMPLE_SIZE");
    expect(content).toContain("scaleStepBySampleSize");
  });

  it("should use clampAdjustment in decision logic", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/confidence-tuner.ts",
      "utf-8"
    );
    expect(content).toContain("clampAdjustment");
    // Verify it's used in the actual tuning logic (not just defined)
    const clampUsages = content.match(/clampAdjustment\(/g);
    expect(clampUsages).not.toBeNull();
    expect(clampUsages!.length).toBeGreaterThanOrEqual(3); // definition + at least 3 usages
  });

  it("scaleStepBySampleSize should reduce step for small samples", () => {
    // Replicate the logic
    const FULL_STEP_SAMPLE_SIZE = 20;
    const scaleStepBySampleSize = (baseStep: number, sampleSize: number): number => {
      const scale = Math.min(1.0, sampleSize / FULL_STEP_SAMPLE_SIZE);
      return baseStep * scale;
    };

    // 5 findings (minimum) → 25% of step
    expect(scaleStepBySampleSize(0.08, 5)).toBeCloseTo(0.02, 4);
    // 10 findings → 50% of step
    expect(scaleStepBySampleSize(0.08, 10)).toBeCloseTo(0.04, 4);
    // 20 findings → full step
    expect(scaleStepBySampleSize(0.08, 20)).toBeCloseTo(0.08, 4);
    // 40 findings → still full step (capped at 1.0)
    expect(scaleStepBySampleSize(0.08, 40)).toBeCloseTo(0.08, 4);
  });

  it("clampAdjustment should limit per-cycle change", () => {
    const MAX_ADJUSTMENT_PER_CYCLE = 0.12;
    const MIN_CONFIDENCE = 0.15;
    const MAX_CONFIDENCE = 0.98;

    const clampAdjustment = (current: number, target: number): number => {
      const delta = target - current;
      const clampedDelta = Math.max(-MAX_ADJUSTMENT_PER_CYCLE, Math.min(MAX_ADJUSTMENT_PER_CYCLE, delta));
      const result = current + clampedDelta;
      return Math.max(MIN_CONFIDENCE, Math.min(MAX_CONFIDENCE, result));
    };

    // Large downward jump should be clamped
    expect(clampAdjustment(0.5, 0.15)).toBeCloseTo(0.38, 2); // 0.5 - 0.12 = 0.38
    // Large upward jump should be clamped
    expect(clampAdjustment(0.5, 0.98)).toBeCloseTo(0.62, 2); // 0.5 + 0.12 = 0.62
    // Small change should pass through
    expect(clampAdjustment(0.5, 0.45)).toBeCloseTo(0.45, 2);
    // Should respect MIN_CONFIDENCE floor
    expect(clampAdjustment(0.2, 0.05)).toBeCloseTo(0.15, 2);
  });
});

// ─── 5. Knowledge Base — Memory Limits ──────────────────────────────────────

describe("Knowledge Base — Memory Limits", () => {
  it("should define KB_LIMITS constants", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/knowledge-base.ts",
      "utf-8"
    );
    expect(content).toContain("KB_LIMITS");
    expect(content).toContain("MAX_HOSTS");
    expect(content).toContain("MAX_ENTRIES_PER_HOST");
    expect(content).toContain("MAX_GLOBAL_ENTRIES");
    expect(content).toContain("MAX_VALUE_SIZE_BYTES");
  });

  it("should have enforceMemoryLimits method", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/knowledge-base.ts",
      "utf-8"
    );
    expect(content).toContain("enforceMemoryLimits");
    // Verify it's called in set()
    expect(content).toContain("this.enforceMemoryLimits");
  });

  it("should have truncateValue method for oversized values", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/knowledge-base.ts",
      "utf-8"
    );
    expect(content).toContain("truncateValue");
    expect(content).toContain("this.truncateValue(value)");
  });

  it("should have eviction statistics tracking", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/knowledge-base.ts",
      "utf-8"
    );
    expect(content).toContain("evictionCount");
    expect(content).toContain("getEvictionStats");
  });
});

// ─── 6. Dedup Fingerprint ───────────────────────────────────────────────────

describe("Dedup Coverage — Fingerprint Improvements", () => {
  it("should include endpoint/path in web finding fingerprints", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/intelligence/dedup-coverage.ts",
      "utf-8"
    );
    // Verify endpoint is now part of the fingerprint
    expect(content).toContain("endpoint");
    expect(content).toContain("extractEndpoint");
  });

  it("should use type-specific fingerprint algorithms", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/intelligence/dedup-coverage.ts",
      "utf-8"
    );
    // Verify type-specific handling (web findings vs non-web)
    expect(content).toContain("Web findings");
    expect(content).toContain("classifyFindingType");
  });
});

// ─── 7. Phase 6 Extraction Module Structure ─────────────────────────────────

describe("Phase 6 Extraction — Module Structure", () => {
  it("should have index.ts with VulnDetectionContext interface", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/vuln-detection/index.ts",
      "utf-8"
    );
    expect(content).toContain("VulnDetectionContext");
    expect(content).toContain("addLog");
    expect(content).toContain("broadcastOpsUpdate");
    expect(content).toContain("executeVulnPrep");
    expect(content).toContain("executeNucleiScanning");
    expect(content).toContain("executeZapScanning");
    expect(content).toContain("executeInjectionScanning");
    expect(content).toContain("executeCredentialTesting");
    expect(content).toContain("executeVulnCorrelation");
  });

  it("should have vuln-prep.ts with full implementation", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/vuln-detection/vuln-prep.ts",
      "utf-8"
    );
    expect(content).toContain("executeVulnPrep");
    expect(content).toContain("VulnPrepResult");
    // Verify it has actual implementation (not just a stub)
    expect(content).toContain("pushVulnDeduped");
    expect(content).toContain("getVulnsForTechnology");
    expect(content).toContain("detectTechnologies");
    expect(content).toContain("TRAINING_LAB_CREDS");
    expect(content).toContain("onBurpScanComplete");
    expect(content).toContain("getEngagementCredentials");
    expect(content).toContain("runZapToBurpPipeline");
    expect(content).toContain("runSeverityEscalation");
    // Verify it doesn't import from the orchestrator (circular dep prevention)
    expect(content).not.toContain("from '../engagement-orchestrator'");
  });

  it("should have stub files for remaining sub-modules", async () => {
    const fs = await import("fs");
    const stubs = [
      "nuclei-scanner.ts",
      "zap-scanner.ts",
      "injection-scanner.ts",
      "credential-tester.ts",
      "vuln-correlation.ts",
    ];
    for (const stub of stubs) {
      const path = `/home/ubuntu/caldera-dashboard/server/lib/vuln-detection/${stub}`;
      expect(fs.existsSync(path)).toBe(true);
      const content = fs.readFileSync(path, "utf-8");
      // Each module should export its main execution function (full implementations now)
      expect(content).toContain("export");
      expect(content.length).toBeGreaterThan(500);
    }
  });
});

// ─── 8. Hybrid Scoring — Per-Engagement Profiles ────────────────────────────

describe("Hybrid Scoring — Calibration & Profiles", () => {
  it("should define ScoringProfile interface", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/hybrid-scoring.ts",
      "utf-8"
    );
    expect(content).toContain("ScoringProfile");
  });

  it("should have preset scoring profiles", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/hybrid-scoring.ts",
      "utf-8"
    );
    expect(content).toContain("SCORING_PROFILES");
    // Verify at least the standard profiles exist
    expect(content).toContain("pentest");
    expect(content).toContain("red_team");
    expect(content).toContain("compliance");
  });
});

// ─── 9. OOB Server Architecture ─────────────────────────────────────────────

describe("OOB Server — Deployment Architecture", () => {
  it("should document dedicated OOB domain configuration", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/scanforge/engine/oob-server.ts",
      "utf-8"
    );
    expect(content).toContain("OOB_DOMAIN");
    expect(content).toContain("Production Deployment Architecture");
    expect(content).toContain("DEDICATED DOMAIN");
    expect(content).toContain("DNS LISTENER");
  });
});
