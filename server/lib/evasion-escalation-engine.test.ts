/**
 * Tests for the Evasion Escalation Engine
 *
 * Covers:
 * - Block detection from tool output
 * - Escalation level progression
 * - Cooldown enforcement
 * - WAF-specific bypass recommendations
 * - Status code-based block detection
 */
import { describe, it, expect } from "vitest";
import {
  detectBlockReason,
  escalateEvasionProfile,
  analyzeToolOutputForBlocking,
  type BlockReason,
} from "./evasion-escalation-engine";
import type { TargetProfile } from "./context-aware-scanner";

// ─── Test Helpers ──────────────────────────────────────────────────────────

function makeProfile(overrides: Partial<TargetProfile> = {}): TargetProfile {
  return {
    hostname: "test.example.com",
    ips: ["192.168.1.1"],
    fingerprint: {
      serverHeader: "nginx/1.24",
      webServer: "nginx",
      appFramework: null,
      cms: null,
      os: null,
      tls: null,
      languages: [],
      jsFrameworks: [],
      databases: [],
      techTags: ["nginx"],
      serviceBanners: {},
    },
    waf: {
      detected: false,
      vendor: "none",
      type: "none",
      confidence: 0,
      bypassTechniques: [],
    },
    cdn: {
      detected: false,
      provider: "none",
      edgeServers: [],
      originDiscoveryMethods: [],
    },
    firewall: {
      detected: false,
      type: "none",
      filteredPorts: [],
      rateLimiting: { detected: false },
    },
    topology: {
      role: "web_server",
      confidence: 80,
      backend: null,
      services: ["http"],
    },
    environment: "production",
    riskProfile: "medium",
    evasionProfile: null,
    recommendedStrategy: null,
    profiledAt: Date.now(),
    ...overrides,
  } as TargetProfile;
}

// ─── detectBlockReason ────────────────────────────────────────────────────

describe("detectBlockReason", () => {
  it("should detect rate limiting from 429 status", () => {
    expect(detectBlockReason(429)).toBe("rate_limit");
  });

  it("should detect WAF block from 403 status", () => {
    expect(detectBlockReason(403)).toBe("waf_block");
  });

  it("should detect CAPTCHA from 403 with captcha body", () => {
    expect(detectBlockReason(403, "Please complete the CAPTCHA to continue")).toBe("captcha");
  });

  it("should detect WAF block from 403 with WAF body", () => {
    expect(detectBlockReason(403, "Request blocked by Web Application Firewall")).toBe("waf_block");
  });

  it("should detect Cloudflare DDoS protection from 503", () => {
    expect(detectBlockReason(503, "Checking your browser - Cloudflare DDoS protection")).toBe("waf_block");
  });

  it("should detect connection reset from status 0", () => {
    expect(detectBlockReason(0)).toBe("connection_reset");
  });

  it("should return null for normal 200 response", () => {
    expect(detectBlockReason(200)).toBeNull();
  });

  it("should return null for normal 404 response", () => {
    expect(detectBlockReason(404)).toBeNull();
  });
});

// ─── analyzeToolOutputForBlocking ─────────────────────────────────────────

describe("analyzeToolOutputForBlocking", () => {
  it("should detect WAF blocking in tool output", () => {
    const result = analyzeToolOutputForBlocking(
      "Error: Access denied by Web Application Firewall\nRequest blocked\n403 Forbidden",
      1
    );
    expect(result.isBlocked).toBe(true);
    expect(result.reason).toBe("waf_block");
    expect(result.confidence).toBeGreaterThanOrEqual(40);
    expect(result.indicators.length).toBeGreaterThan(0);
  });

  it("should detect rate limiting in tool output", () => {
    const result = analyzeToolOutputForBlocking(
      "HTTP 429 Too Many Requests\nRate limit exceeded. Please slow down.",
      0
    );
    expect(result.isBlocked).toBe(true);
    expect(result.reason).toBe("rate_limit");
  });

  it("should detect CAPTCHA in tool output", () => {
    const result = analyzeToolOutputForBlocking(
      "Response contains hCaptcha challenge\nPlease verify you are human",
      0
    );
    expect(result.isBlocked).toBe(true);
    expect(result.reason).toBe("captcha");
  });

  it("should detect connection reset in tool output", () => {
    const result = analyzeToolOutputForBlocking(
      "Error: ECONNRESET connection reset by peer\nFailed to connect",
      1
    );
    expect(result.isBlocked).toBe(true);
    expect(result.reason).toBe("connection_reset");
  });

  it("should not flag normal tool output as blocked", () => {
    const result = analyzeToolOutputForBlocking(
      "Scanning target...\nFound 3 open ports\nPort 80: HTTP\nPort 443: HTTPS\nScan complete.",
      0
    );
    expect(result.isBlocked).toBe(false);
    expect(result.reason).toBeNull();
  });

  it("should detect high error ratio as blocking", () => {
    const lines = Array(20).fill("error: request blocked by firewall").join("\n");
    const result = analyzeToolOutputForBlocking(lines, 1);
    expect(result.isBlocked).toBe(true);
  });
});

// ─── escalateEvasionProfile ───────────────────────────────────────────────

describe("escalateEvasionProfile", () => {
  it("should escalate from level 1 to level 2 on WAF block", () => {
    const profile = makeProfile();
    const result = escalateEvasionProfile(profile, "waf_block");

    expect(result.escalation.currentLevel).toBe(2);
    expect(result.escalation.reason).toBe("waf_block");
    expect(result.escalation.history).toHaveLength(1);
    expect(result.escalation.history[0].level).toBe(2);
    expect(result.newEvasionProfile).not.toBeNull();
    expect(result.newEvasionProfile!.rateLimit).toBeLessThan(50);
  });

  it("should escalate progressively through all levels", () => {
    let profile = makeProfile();
    let currentLevel = 1;

    for (let i = 0; i < 4; i++) {
      const result = escalateEvasionProfile(profile, "waf_block");
      expect(result.escalation.currentLevel).toBe(currentLevel + 1);
      // Apply escalation to profile for next iteration
      (profile as any).evasionEscalation = {
        ...result.escalation,
        cooldownUntil: 0, // Skip cooldown for test
      };
      currentLevel = result.escalation.currentLevel;
    }

    expect(currentLevel).toBe(5);
  });

  it("should not escalate beyond level 5", () => {
    const profile = makeProfile();
    (profile as any).evasionEscalation = {
      currentLevel: 5,
      maxLevel: 5,
      reason: "waf_block",
      action: "Max level",
      escalatedAt: Date.now(),
      cooldownUntil: 0,
      history: [],
      adaptations: [],
    };

    const result = escalateEvasionProfile(profile, "waf_block");
    expect(result.escalation.currentLevel).toBe(5);
  });

  it("should enforce cooldown period", () => {
    const profile = makeProfile();
    (profile as any).evasionEscalation = {
      currentLevel: 2,
      maxLevel: 5,
      reason: "waf_block",
      action: "Test",
      escalatedAt: Date.now(),
      cooldownUntil: Date.now() + 60_000, // 60s cooldown
      history: [],
      adaptations: [],
    };

    const result = escalateEvasionProfile(profile, "waf_block");
    expect(result.shouldPause).toBe(true);
    expect(result.pauseDurationMs).toBeGreaterThan(0);
    // Should not escalate during cooldown
    expect(result.escalation.currentLevel).toBe(2);
  });

  it("should reduce rate limit at each level", () => {
    const profile = makeProfile();
    const rates: number[] = [];

    let currentProfile = profile;
    for (let i = 0; i < 4; i++) {
      const result = escalateEvasionProfile(currentProfile, "rate_limit");
      if (result.newEvasionProfile) {
        rates.push(result.newEvasionProfile.rateLimit);
      }
      (currentProfile as any).evasionEscalation = {
        ...result.escalation,
        cooldownUntil: 0,
      };
    }

    // Each level should have a lower rate limit
    for (let i = 1; i < rates.length; i++) {
      expect(rates[i]).toBeLessThan(rates[i - 1]);
    }
  });

  it("should recommend pausing at level 4+", () => {
    const profile = makeProfile();
    (profile as any).evasionEscalation = {
      currentLevel: 3,
      maxLevel: 5,
      reason: "waf_block",
      action: "Test",
      escalatedAt: Date.now(),
      cooldownUntil: 0,
      history: [],
      adaptations: [],
    };

    const result = escalateEvasionProfile(profile, "waf_block");
    expect(result.escalation.currentLevel).toBe(4);
    expect(result.shouldPause).toBe(true);
  });

  it("should include WAF-specific recommendations when WAF detected", () => {
    const profile = makeProfile({
      waf: {
        detected: true,
        vendor: "Cloudflare",
        type: "cloud",
        confidence: 90,
        bypassTechniques: ["chunked_transfer", "unicode_normalization"],
      },
    });
    (profile as any).evasionEscalation = {
      currentLevel: 2,
      maxLevel: 5,
      reason: "waf_block",
      action: "Test",
      escalatedAt: Date.now(),
      cooldownUntil: 0,
      history: [],
      adaptations: [],
    };

    const result = escalateEvasionProfile(profile, "waf_block");
    expect(result.recommendations.some(r => r.includes("Cloudflare"))).toBe(true);
  });

  it("should include CDN recommendations when CDN detected", () => {
    const profile = makeProfile({
      cdn: {
        detected: true,
        provider: "Akamai",
        edgeServers: ["edge1.akamai.net"],
        originDiscoveryMethods: ["dns_history"],
      },
    });

    const result = escalateEvasionProfile(profile, "waf_block");
    expect(result.recommendations.some(r => r.includes("Akamai") || r.includes("CDN"))).toBe(true);
  });

  it("should accumulate history across escalations", () => {
    const profile = makeProfile();
    const result1 = escalateEvasionProfile(profile, "waf_block");
    (profile as any).evasionEscalation = { ...result1.escalation, cooldownUntil: 0 };

    const result2 = escalateEvasionProfile(profile, "rate_limit");
    expect(result2.escalation.history).toHaveLength(2);
    expect(result2.escalation.history[0].reason).toBe("waf_block");
    expect(result2.escalation.history[1].reason).toBe("rate_limit");
  });

  it("should enable chunked transfer at level 4", () => {
    const profile = makeProfile();
    (profile as any).evasionEscalation = {
      currentLevel: 3,
      maxLevel: 5,
      reason: "waf_block",
      action: "Test",
      escalatedAt: Date.now(),
      cooldownUntil: 0,
      history: [],
      adaptations: [],
    };

    const result = escalateEvasionProfile(profile, "waf_block");
    expect(result.newEvasionProfile!.chunkedTransfer).toBe(true);
    expect(result.newEvasionProfile!.useHttp2).toBe(true);
  });

  it("should enable Tor routing at level 5", () => {
    const profile = makeProfile();
    (profile as any).evasionEscalation = {
      currentLevel: 4,
      maxLevel: 5,
      reason: "ip_ban",
      action: "Test",
      escalatedAt: Date.now(),
      cooldownUntil: 0,
      history: [],
      adaptations: [],
    };

    const result = escalateEvasionProfile(profile, "ip_ban");
    expect(result.newEvasionProfile!.ipRotation).toBe("tor");
  });

  it("should include CAPTCHA-specific recommendations", () => {
    const profile = makeProfile();
    const result = escalateEvasionProfile(profile, "captcha");
    expect(result.recommendations.some(r => r.toLowerCase().includes("captcha"))).toBe(true);
  });

  it("should include IP ban recommendations", () => {
    const profile = makeProfile();
    const result = escalateEvasionProfile(profile, "ip_ban");
    expect(result.recommendations.some(r => r.toLowerCase().includes("ip") || r.toLowerCase().includes("ban"))).toBe(true);
  });

  it("should set adaptations as applied", () => {
    const profile = makeProfile();
    const result = escalateEvasionProfile(profile, "waf_block");
    for (const adaptation of result.escalation.adaptations) {
      expect(adaptation.applied).toBe(true);
      expect(adaptation.appliedAt).toBeGreaterThan(0);
    }
  });
});
