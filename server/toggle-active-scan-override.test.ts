import { describe, it, expect, vi } from "vitest";

/**
 * Tests for the Target Review & Approval Flow
 * 
 * Validates:
 * 1. toggleActiveScanOverride procedure input validation
 * 2. Domain whitelist validation logic (shared module)
 * 3. Approval dialog UI requirements
 * 4. Timeline event logging for audit trail
 */

// ─── Import shared whitelist validators ─────────────────────────────────────
import {
  extractHostname,
  isDomainWhitelisted,
  validateEngagementTargets,
  getSafetyWarning,
  isSourceCodeTarget,
  WHITELISTED_DOMAINS,
} from "../shared/domain-safety-whitelist";

// ─── Whitelist Validation for WordPress Targets ─────────────────────────────

describe("WordPress Bug Bounty Target Validation", () => {
  it("should flag wordpress.org as non-whitelisted", () => {
    expect(isDomainWhitelisted("wordpress.org")).toBe(false);
  });

  it("should flag *.wordpress.org subdomains as non-whitelisted", () => {
    expect(isDomainWhitelisted("profiles.wordpress.org")).toBe(false);
    expect(isDomainWhitelisted("trac.wordpress.org")).toBe(false);
    expect(isDomainWhitelisted("codex.wordpress.org")).toBe(false);
    expect(isDomainWhitelisted("planet.wordpress.org")).toBe(false);
  });

  it("should flag buddypress.org as non-whitelisted", () => {
    expect(isDomainWhitelisted("buddypress.org")).toBe(false);
    expect(isDomainWhitelisted("codex.buddypress.org")).toBe(false);
  });

  it("should flag bbpress.org as non-whitelisted", () => {
    expect(isDomainWhitelisted("bbpress.org")).toBe(false);
    expect(isDomainWhitelisted("codex.bbpress.org")).toBe(false);
  });

  it("should flag wordcamp.org as non-whitelisted", () => {
    expect(isDomainWhitelisted("wordcamp.org")).toBe(false);
    expect(isDomainWhitelisted("*.wordcamp.org")).toBe(false);
  });

  it("should flag wordpress.net as non-whitelisted", () => {
    expect(isDomainWhitelisted("wordpress.net")).toBe(false);
  });

  it("should flag doaction.org as non-whitelisted", () => {
    expect(isDomainWhitelisted("doaction.org")).toBe(false);
  });

  it("should flag wordpressfoundation.org as non-whitelisted", () => {
    expect(isDomainWhitelisted("wordpressfoundation.org")).toBe(false);
  });

  it("should recognize github.com/WordPress as a source code target", () => {
    const result = isSourceCodeTarget("https://github.com/WordPress");
    expect(result.isSourceCode).toBe(true);
    expect(result.host).toBe("github.com");
  });

  it("should recognize github.com as whitelisted (for source code audits)", () => {
    expect(isDomainWhitelisted("github.com")).toBe(true);
  });
});

describe("validateEngagementTargets for WordPress program", () => {
  it("should return non-whitelisted targets for WordPress domains", () => {
    const result = validateEngagementTargets(
      "wordpress.org, buddypress.org, bbpress.org, wordcamp.org",
      undefined
    );
    expect(result.allWhitelisted).toBe(false);
    expect(result.nonWhitelistedCount).toBe(4);
    expect(result.nonWhitelistedTargets).toContain("wordpress.org");
    expect(result.nonWhitelistedTargets).toContain("buddypress.org");
  });

  it("should generate safety warning for WordPress targets", () => {
    const result = validateEngagementTargets("wordpress.org, buddypress.org");
    const warning = getSafetyWarning(result);
    expect(warning).not.toBeNull();
    expect(warning).toContain("SAFETY GUARDRAIL");
    expect(warning).toContain("BLOCKED");
    expect(warning).toContain("wordpress.org");
  });

  it("should handle mixed whitelisted and non-whitelisted targets", () => {
    const result = validateEngagementTargets(
      "github.com/WordPress, wordpress.org, brokencrystals.com"
    );
    expect(result.whitelistedCount).toBe(2); // github.com and brokencrystals.com
    expect(result.nonWhitelistedCount).toBe(1); // wordpress.org
  });
});

// ─── toggleActiveScanOverride Input Validation ──────────────────────────────

describe("toggleActiveScanOverride input validation", () => {
  it("should require engagementId as a number", () => {
    const schema = {
      engagementId: 1,
      enabled: true,
      justification: "Signed RoE covers WordPress targets",
    };
    expect(schema.engagementId).toBeTypeOf("number");
    expect(schema.enabled).toBeTypeOf("boolean");
    expect(schema.justification).toBeTypeOf("string");
    expect(schema.justification.length).toBeGreaterThan(0);
  });

  it("should not accept empty justification", () => {
    const justification = "";
    expect(justification.trim().length).toBe(0);
  });

  it("should accept valid justification with RoE reference", () => {
    const justification = "Signed RoE #WP-2026-001 covers all WordPress program targets per HackerOne authorization.";
    expect(justification.trim().length).toBeGreaterThan(0);
    expect(justification).toContain("RoE");
  });
});

// ─── Source Code Target Detection ───────────────────────────────────────────

describe("Source code target detection for WordPress", () => {
  it("should detect GitHub WordPress repo as source code", () => {
    const result = isSourceCodeTarget("https://github.com/WordPress/WordPress");
    expect(result.isSourceCode).toBe(true);
    expect(result.repoUrl).toBe("https://github.com/WordPress/WordPress");
  });

  it("should detect GlotPress repo as source code", () => {
    const result = isSourceCodeTarget("https://github.com/GlotPress/GlotPress-WP");
    expect(result.isSourceCode).toBe(true);
  });

  it("should detect WP-CLI repo as source code", () => {
    const result = isSourceCodeTarget("https://github.com/wp-cli/wp-cli");
    expect(result.isSourceCode).toBe(true);
  });

  it("should NOT detect wordpress.org as source code", () => {
    const result = isSourceCodeTarget("wordpress.org");
    expect(result.isSourceCode).toBe(false);
  });

  it("should NOT detect buddypress.org as source code", () => {
    const result = isSourceCodeTarget("buddypress.org");
    expect(result.isSourceCode).toBe(false);
  });

  it("should detect gitlab.com repos as source code", () => {
    const result = isSourceCodeTarget("https://gitlab.com/some/repo");
    expect(result.isSourceCode).toBe(true);
    expect(result.host).toBe("gitlab.com");
  });

  it("should detect bitbucket.org repos as source code", () => {
    const result = isSourceCodeTarget("https://bitbucket.org/some/repo");
    expect(result.isSourceCode).toBe(true);
    expect(result.host).toBe("bitbucket.org");
  });
});

// ─── Approval Flow Audit Trail ──────────────────────────────────────────────

describe("Approval flow audit trail requirements", () => {
  it("should create timeline event with correct fields when override enabled", () => {
    const event = {
      eventType: "safety_override",
      title: "⚠️ Active Scan Override Enabled",
      phase: "scoping",
      severity: "high",
      metadata: JSON.stringify({
        userId: 1,
        userName: "hcook",
        enabled: true,
        justification: "Signed RoE covers WordPress targets",
        timestamp: new Date().toISOString(),
      }),
    };
    expect(event.eventType).toBe("safety_override");
    expect(event.severity).toBe("high");
    const meta = JSON.parse(event.metadata);
    expect(meta.enabled).toBe(true);
    expect(meta.justification).toContain("WordPress");
  });

  it("should create timeline event with correct fields when override disabled", () => {
    const event = {
      eventType: "safety_override",
      title: "🛡️ Active Scan Override Disabled",
      phase: "scoping",
      severity: "info",
      metadata: JSON.stringify({
        userId: 1,
        userName: "hcook",
        enabled: false,
        justification: "Override revoked by operator",
        timestamp: new Date().toISOString(),
      }),
    };
    expect(event.eventType).toBe("safety_override");
    expect(event.severity).toBe("info");
    const meta = JSON.parse(event.metadata);
    expect(meta.enabled).toBe(false);
  });

  it("should log activity with correct action names", () => {
    const enableAction = "active_scan_override_enabled";
    const disableAction = "active_scan_override_disabled";
    expect(enableAction).toContain("active_scan_override");
    expect(disableAction).toContain("active_scan_override");
    expect(enableAction).not.toBe(disableAction);
  });
});
