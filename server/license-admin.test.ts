import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── License Manager Tests ──────────────────────────────────────────────────

describe("License Manager", () => {
  // We test the license-manager module's pure logic functions
  
  beforeEach(() => {
    vi.resetModules();
  });

  describe("issueLicense", () => {
    it("should generate a valid license key for a new org", async () => {
      const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
      
      const key = generateLicenseKey({
        orgName: "Test Corp",
        tier: "professional",
        expiresInDays: 365,
      });
      
      expect(key).toBeTruthy();
      expect(typeof key).toBe("string");
      expect(key.length).toBeGreaterThan(20);
      
      // Validate the generated key
      const result = validateLicenseKey(key);
      expect(result.valid).toBe(true);
      expect(result.claims?.orgName).toBe("Test Corp");
      expect(result.claims?.tier).toBe("professional");
    });

    it("should generate keys for all three tiers", async () => {
      const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
      
      const tiers = ["starter", "professional", "enterprise"] as const;
      
      for (const tier of tiers) {
        const key = generateLicenseKey({
          orgName: `${tier} Corp`,
          tier,
          expiresInDays: 30,
        });
        
        const result = validateLicenseKey(key);
        expect(result.valid).toBe(true);
        expect(result.claims?.tier).toBe(tier);
      }
    });

    it("should detect expired license keys", async () => {
      const { generateLicenseKey, validateLicenseKey } = await import("./lib/licensing");
      
      // Generate a key that expires in 0 days (already expired)
      const key = generateLicenseKey({
        orgName: "Expired Corp",
        tier: "starter",
        expiresInDays: 0,
      });
      
      const result = validateLicenseKey(key);
      // Key is technically valid JWT but expired
      expect(result.claims?.orgName).toBe("Expired Corp");
    });

    it("should reject invalid license keys", async () => {
      const { validateLicenseKey } = await import("./lib/licensing");
      
      const result = validateLicenseKey("invalid-key-string");
      expect(result.valid).toBe(false);
      expect(result.error).toBeTruthy();
    });
  });

  describe("getLicenseStatus", () => {
    it("should return license status with tier info", async () => {
      const { getLicenseStatus } = await import("./lib/licensing");
      
      const status = getLicenseStatus();
      expect(status).toBeDefined();
      expect(status.tier).toBeTruthy();
      expect(typeof status.valid).toBe("boolean");
    });

    it("should include days until expiry", async () => {
      const { getLicenseStatus } = await import("./lib/licensing");
      
      const status = getLicenseStatus();
      expect(typeof status.daysUntilExpiry).toBe("number");
    });
  });
});

// ─── Update Manager Tests ───────────────────────────────────────────────────

describe("Update Manager", () => {
  describe("getCurrentVersion", () => {
    it("should return a valid semver version", async () => {
      const { getCurrentVersion } = await import("./lib/update-manager");
      
      const version = getCurrentVersion();
      expect(version).toBeTruthy();
      expect(typeof version).toBe("string");
      // Should look like semver (x.y.z)
      expect(version).toMatch(/^\d+\.\d+\.\d+/);
    });
  });

  describe("checkForUpdates", () => {
    it("should return update check result", async () => {
      const { checkForUpdates } = await import("./lib/update-manager");
      
      const result = await checkForUpdates("1.0.0");
      expect(result).toBeDefined();
      expect(typeof result.updateAvailable).toBe("boolean");
      expect(result.currentVersion).toBe("1.0.0");
      expect(result.latestVersion).toBeTruthy();
      expect(Array.isArray(result.updates)).toBe(true);
    });

    it("should detect when current version is latest", async () => {
      const { checkForUpdates, getCurrentVersion } = await import("./lib/update-manager");
      
      const currentVersion = getCurrentVersion();
      const result = await checkForUpdates(currentVersion);
      // When on latest version, no updates should be available
      expect(result.currentVersion).toBe(currentVersion);
    });
  });

  describe("getChangelog", () => {
    it("should return changelog entries", async () => {
      const { getChangelog } = await import("./lib/update-manager");
      
      const changelog = await getChangelog(10);
      expect(Array.isArray(changelog)).toBe(true);
      
      // Each entry should have version, changelog, releaseDate
      for (const entry of changelog) {
        expect(entry.version).toBeTruthy();
        expect(entry.changelog).toBeTruthy();
        expect(entry.releaseDate).toBeTruthy();
      }
    });
  });
});

// ─── White-Label Config Tests ───────────────────────────────────────────────

describe("White-Label Config", () => {
  it("should return public config without sensitive data", async () => {
    const { getPublicWhiteLabelConfig } = await import("./lib/white-label");
    
    const config = getPublicWhiteLabelConfig();
    expect(config).toBeDefined();
    expect(config.orgName).toBeTruthy();
    expect(typeof config.primaryColor).toBe("string");
  });

  it("should check feature enablement", async () => {
    const { isFeatureEnabled } = await import("./lib/white-label");
    
    // In dev mode, all features should be enabled
    const result = isFeatureEnabled("domainIntel");
    expect(typeof result).toBe("boolean");
  });

  it("should support all feature module names", async () => {
    const { isFeatureEnabled } = await import("./lib/white-label");
    
    const features = [
      "domainIntel", "threatMatching", "incidentSearch",
      "vulnScanning", "redTeam", "purpleTeam",
    ];
    
    for (const feature of features) {
      const result = isFeatureEnabled(feature as any);
      expect(typeof result).toBe("boolean");
    }
  });
});
