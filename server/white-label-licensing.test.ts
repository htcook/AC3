import { describe, it, expect, vi, afterEach } from "vitest";

// ─── White-Label Config Tests ────────────────────────────────────────────────

describe("White-Label Configuration", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.resetModules();
  });

  it("returns default config when no WL_ env vars are set", async () => {
    Object.keys(process.env).forEach((k) => {
      if (k.startsWith("WL_")) delete process.env[k];
    });
    const { getPublicWhiteLabelConfig, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    const config = getPublicWhiteLabelConfig();
    expect(config).toBeDefined();
    expect(config.platformName).toBe("AC3");
    expect(config.orgName).toBe("AceofCloud");
  });

  it("reads WL_ORG_NAME from environment", async () => {
    process.env.WL_ORG_NAME = "Test Corp";
    const { getPublicWhiteLabelConfig, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    const config = getPublicWhiteLabelConfig();
    expect(config.orgName).toBe("Test Corp");
  });

  it("reads WL_PLATFORM_NAME from environment", async () => {
    process.env.WL_PLATFORM_NAME = "TestPlatform";
    const { getPublicWhiteLabelConfig, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    const config = getPublicWhiteLabelConfig();
    expect(config.platformName).toBe("TestPlatform");
  });

  it("reads WL_SUPPORT_EMAIL from environment", async () => {
    process.env.WL_SUPPORT_EMAIL = "help@test.com";
    const { getPublicWhiteLabelConfig, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    const config = getPublicWhiteLabelConfig();
    expect(config.supportEmail).toBe("help@test.com");
  });

  it("reads color overrides from environment", async () => {
    process.env.WL_PRIMARY_COLOR = "oklch(0.8 0.1 200)";
    const { getPublicWhiteLabelConfig, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    const config = getPublicWhiteLabelConfig();
    expect(config.primaryColor).toBe("oklch(0.8 0.1 200)");
  });

  it("reads report branding from environment", async () => {
    process.env.WL_REPORT_COMPANY_NAME = "Report Corp";
    process.env.WL_REPORT_FOOTER = "Confidential — Report Corp";
    const { getPublicWhiteLabelConfig, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    const config = getPublicWhiteLabelConfig();
    expect(config.reportCompanyName).toBe("Report Corp");
    expect(config.reportFooterText).toBe("Confidential — Report Corp");
  });

  it("isFeatureEnabled returns true for core features without license", async () => {
    Object.keys(process.env).forEach((k) => {
      if (k.startsWith("WL_")) delete process.env[k];
    });
    const { isFeatureEnabled, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    expect(isFeatureEnabled("domain_intel")).toBe(true);
  });

  it("respects feature overrides from environment", async () => {
    process.env.WL_FEATURE_OVERRIDES = '{"ember_agents":false}';
    process.env.WL_LICENSE_TIER = "enterprise";
    const { isFeatureEnabled, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    expect(isFeatureEnabled("ember_agents")).toBe(false);
    expect(isFeatureEnabled("domain_intel")).toBe(true);
  });

  it("resolves tier-based features correctly for starter", async () => {
    process.env.WL_LICENSE_TIER = "starter";
    const { isFeatureEnabled, resetWhiteLabelCache } = await import("./lib/white-label");
    resetWhiteLabelCache();
    expect(isFeatureEnabled("domain_intel")).toBe(true);
    expect(isFeatureEnabled("ember_agents")).toBe(false);
    expect(isFeatureEnabled("adversary_emulation")).toBe(false);
  });
});

// ─── Licensing System Tests ──────────────────────────────────────────────────

describe("Licensing System", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.resetModules();
  });

  it("getLicenseStatus returns dev mode when no key is set", async () => {
    delete process.env.WL_LICENSE_KEY;
    const { getLicenseStatus } = await import("./lib/licensing");
    const status = getLicenseStatus();
    expect(status.valid).toBe(false);
    expect(status.tier).toBe("enterprise"); // dev mode = all features
    expect(status.orgName).toBe("Development Mode");
    expect(status.warnings.length).toBeGreaterThan(0);
  });

  it("validateLicenseKey rejects empty key", async () => {
    const { validateLicenseKey } = await import("./lib/licensing");
    const result = validateLicenseKey("");
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("validateLicenseKey rejects malformed JWT", async () => {
    const { validateLicenseKey } = await import("./lib/licensing");
    const result = validateLicenseKey("not-a-valid-jwt-token");
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("generateLicenseKey creates a valid JWT", async () => {
    const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
    const key = generateLicenseKey({
      org: "test-org",
      orgName: "Test Organization",
      tier: "professional",
      expiryDays: 30,
    });
    expect(typeof key).toBe("string");
    expect(key.split(".")).toHaveLength(3);

    const result = validateLicenseKey(key);
    expect(result.valid).toBe(true);
    expect(result.claims?.org).toBe("test-org");
    expect(result.claims?.orgName).toBe("Test Organization");
    expect(result.claims?.tier).toBe("professional");
  });

  it("generateLicenseKey respects tier defaults", async () => {
    const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
    const key = generateLicenseKey({
      org: "starter-org",
      orgName: "Starter Org",
      tier: "starter",
      expiryDays: 90,
    });
    const result = validateLicenseKey(key);
    expect(result.valid).toBe(true);
    expect(result.claims?.tier).toBe("starter");
    expect(result.claims?.seats).toBe(5);
    expect(result.claims?.scans).toBe(50);
  });

  it("generateLicenseKey creates enterprise tier with unlimited seats", async () => {
    const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
    const key = generateLicenseKey({
      org: "enterprise-org",
      orgName: "Enterprise Corp",
      tier: "enterprise",
      expiryDays: 365,
    });
    const result = validateLicenseKey(key);
    expect(result.valid).toBe(true);
    expect(result.claims?.tier).toBe("enterprise");
    expect(result.claims?.seats).toBe(-1); // unlimited
    expect(result.claims?.scans).toBe(-1); // unlimited
  });

  it("detects expired license keys beyond grace period", async () => {
    const jwt = await import("jsonwebtoken");
    const secret = process.env.WL_LICENSE_SIGNING_SECRET || process.env.JWT_SECRET || "ac3-license-dev-key";
    const now = Math.floor(Date.now() / 1000);

    const expiredToken = jwt.default.sign(
      {
        org: "expired-org",
        orgName: "Expired Org",
        tier: "starter",
        seats: 5,
        scans: 50,
        exp: now - 10 * 24 * 60 * 60, // 10 days ago
        iat: now - 40 * 24 * 60 * 60,
        iss: "aceofcloud-licensing",
        sub: "deploy-expired-org",
        billingPeriodDays: 30,
        gracePeriodDays: 7,
      },
      secret,
      { algorithm: "HS256" }
    );

    const { validateLicenseKey } = await import("./lib/licensing");
    const result = validateLicenseKey(expiredToken);
    expect(result.isExpired).toBe(true);
    expect(result.isInGracePeriod).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("detects license in grace period", async () => {
    const jwt = await import("jsonwebtoken");
    const secret = process.env.WL_LICENSE_SIGNING_SECRET || process.env.JWT_SECRET || "ac3-license-dev-key";
    const now = Math.floor(Date.now() / 1000);

    const graceToken = jwt.default.sign(
      {
        org: "grace-org",
        orgName: "Grace Org",
        tier: "professional",
        seats: 25,
        scans: 500,
        exp: now - 3 * 24 * 60 * 60, // 3 days ago
        iat: now - 33 * 24 * 60 * 60,
        iss: "aceofcloud-licensing",
        sub: "deploy-grace-org",
        billingPeriodDays: 30,
        gracePeriodDays: 7,
      },
      secret,
      { algorithm: "HS256" }
    );

    const { validateLicenseKey } = await import("./lib/licensing");
    const result = validateLicenseKey(graceToken);
    expect(result.isExpired).toBe(true);
    expect(result.isInGracePeriod).toBe(true);
    expect(result.valid).toBe(true); // still valid during grace
  });

  it("calculates daysUntilExpiry correctly", async () => {
    const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
    const key = generateLicenseKey({
      org: "test-expiry",
      orgName: "Expiry Test",
      tier: "starter",
      expiryDays: 30,
    });
    const result = validateLicenseKey(key);
    expect(result.valid).toBe(true);
    expect(result.daysUntilExpiry).toBeGreaterThan(28);
    expect(result.daysUntilExpiry).toBeLessThanOrEqual(30);
  });

  it("rejects token signed with wrong secret", async () => {
    const jwt = await import("jsonwebtoken");
    const now = Math.floor(Date.now() / 1000);

    const wrongSecretToken = jwt.default.sign(
      {
        org: "wrong-secret",
        orgName: "Wrong Secret Org",
        tier: "enterprise",
        seats: -1,
        scans: -1,
        exp: now + 365 * 24 * 60 * 60,
        iat: now,
        iss: "aceofcloud-licensing",
        sub: "deploy-wrong-secret",
        billingPeriodDays: 30,
        gracePeriodDays: 7,
      },
      "completely-wrong-secret-key",
      { algorithm: "HS256" }
    );

    const { validateLicenseKey } = await import("./lib/licensing");
    const result = validateLicenseKey(wrongSecretToken);
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("isFeatureAllowed works correctly for licensed tier", async () => {
    const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
    const key = generateLicenseKey({
      org: "feature-test",
      orgName: "Feature Test",
      tier: "starter",
      expiryDays: 30,
    });
    const result = validateLicenseKey(key);
    expect(result.valid).toBe(true);
    expect(result.isFeatureAllowed("domain_intel")).toBe(true);
    expect(result.isFeatureAllowed("ember_agents")).toBe(false);
  });

  it("usage metering tracks scans correctly", async () => {
    const { recordScanUsage, getUsage } = await import("./lib/licensing");
    const orgId = `test-usage-${Date.now()}`;
    recordScanUsage(orgId);
    recordScanUsage(orgId);
    recordScanUsage(orgId);
    const usage = getUsage(orgId);
    expect(usage.scans).toBe(3);
  });

  it("isWithinScanLimit enforces limits", async () => {
    const { recordScanUsage, isWithinScanLimit } = await import("./lib/licensing");
    const orgId = `limit-test-${Date.now()}`;
    const claims = {
      org: orgId,
      orgName: "Limit Test",
      tier: "starter" as const,
      seats: 5,
      scans: 2,
      exp: Math.floor(Date.now() / 1000) + 86400,
      iat: Math.floor(Date.now() / 1000),
      iss: "aceofcloud-licensing",
      sub: "deploy-test",
      billingPeriodDays: 30,
      gracePeriodDays: 7,
    };
    expect(isWithinScanLimit(orgId, claims)).toBe(true);
    recordScanUsage(orgId, 30);
    recordScanUsage(orgId, 30);
    expect(isWithinScanLimit(orgId, claims)).toBe(false);
  });
});
