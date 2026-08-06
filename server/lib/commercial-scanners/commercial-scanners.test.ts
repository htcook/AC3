import { describe, it, expect, vi } from "vitest";
import { createConnector, getSupportedPlatforms, PLATFORM_METADATA } from "./factory";
import type { CommercialScannerConfig } from "./types";

describe("Commercial Scanner Connector Factory", () => {
  it("should list all 16 supported platforms", () => {
    const platforms = getSupportedPlatforms();
    expect(platforms).toHaveLength(16);
    expect(platforms).toContain("tenable_io");
    expect(platforms).toContain("qualys_vmdr");
    expect(platforms).toContain("rapid7_insightvm");
    expect(platforms).toContain("veracode");
    expect(platforms).toContain("checkmarx_one");
    expect(platforms).toContain("fortify_on_demand");
    expect(platforms).toContain("prisma_cloud");
    expect(platforms).toContain("wiz");
    expect(platforms).toContain("crowdstrike_falcon");
    expect(platforms).toContain("ms_defender_vuln");
    expect(platforms).toContain("anchore_enterprise");
    expect(platforms).toContain("snyk");
    expect(platforms).toContain("burp_suite_enterprise");
    expect(platforms).toContain("hcl_appscan");
    expect(platforms).toContain("acunetix");
    expect(platforms).toContain("sonarqube");
  });

  it("should throw for unsupported platform", () => {
    const config: CommercialScannerConfig = {
      id: "test-1",
      platform: "nonexistent_scanner",
      name: "Test",
      baseUrl: "https://example.com",
      credentials: {},
    };
    expect(() => createConnector(config)).toThrow("Unsupported scanner platform: nonexistent_scanner");
  });

  it("should create a TenableConnector instance", () => {
    const config: CommercialScannerConfig = {
      id: "tenable-1",
      platform: "tenable_io",
      name: "Production Tenable",
      baseUrl: "https://cloud.tenable.com",
      credentials: { accessKey: "test-access", secretKey: "test-secret" },
    };
    const connector = createConnector(config);
    expect(connector.platform).toBe("tenable_io");
  });

  it("should create a QualysConnector instance", () => {
    const config: CommercialScannerConfig = {
      id: "qualys-1",
      platform: "qualys_vmdr",
      name: "Qualys VMDR",
      baseUrl: "https://qualysapi.qualys.com",
      credentials: { username: "admin", password: "pass" },
    };
    const connector = createConnector(config);
    expect(connector.platform).toBe("qualys_vmdr");
  });

  it("should create a CrowdStrikeConnector instance", () => {
    const config: CommercialScannerConfig = {
      id: "cs-1",
      platform: "crowdstrike_falcon",
      name: "CrowdStrike Falcon",
      baseUrl: "https://api.crowdstrike.com",
      credentials: { clientId: "test-id", clientSecret: "test-secret" },
    };
    const connector = createConnector(config);
    expect(connector.platform).toBe("crowdstrike_falcon");
  });

  it("should create a BurpEnterpriseConnector instance", () => {
    const config: CommercialScannerConfig = {
      id: "burp-1",
      platform: "burp_suite_enterprise",
      name: "Burp Enterprise",
      baseUrl: "https://burp.internal.ac3.dev",
      credentials: { apiKey: "test-api-key" },
    };
    const connector = createConnector(config);
    expect(connector.platform).toBe("burp_suite_enterprise");
  });

  it("should create all connectors without errors", () => {
    const platforms = getSupportedPlatforms();
    for (const platform of platforms) {
      const config: CommercialScannerConfig = {
        id: `test-${platform}`,
        platform,
        name: `Test ${platform}`,
        baseUrl: "https://example.com",
        credentials: { token: "test", apiKey: "test", username: "test", password: "test", accessKey: "test", secretKey: "test", clientId: "test", clientSecret: "test", tenantId: "test", tenant: "test", apiId: "test", apiSecret: "test", orgId: "test" },
      };
      const connector = createConnector(config);
      expect(connector.platform).toBe(platform);
    }
  });
});

describe("Platform Metadata", () => {
  it("should have metadata for all supported platforms", () => {
    const platforms = getSupportedPlatforms();
    for (const platform of platforms) {
      expect(PLATFORM_METADATA[platform]).toBeDefined();
      expect(PLATFORM_METADATA[platform].name).toBeTruthy();
      expect(PLATFORM_METADATA[platform].vendor).toBeTruthy();
      expect(PLATFORM_METADATA[platform].fedRampLevel).toBeTruthy();
      expect(PLATFORM_METADATA[platform].scanTypes.length).toBeGreaterThan(0);
      expect(PLATFORM_METADATA[platform].authFields.length).toBeGreaterThan(0);
      expect(PLATFORM_METADATA[platform].defaultBaseUrl).toBeTruthy();
    }
  });

  it("should have FedRAMP High platforms correctly tagged", () => {
    const highPlatforms = ["tenable_io", "qualys_vmdr", "prisma_cloud", "crowdstrike_falcon", "ms_defender_vuln"];
    for (const p of highPlatforms) {
      expect(PLATFORM_METADATA[p].fedRampLevel).toMatch(/High|IL5/i);
    }
  });

  it("should require auth fields for each platform", () => {
    for (const [platform, meta] of Object.entries(PLATFORM_METADATA)) {
      const requiredFields = meta.authFields.filter(f => f.required);
      expect(requiredFields.length).toBeGreaterThan(0);
    }
  });
});

describe("Connector testConnection (mocked)", () => {
  it("should return unhealthy when API is unreachable", async () => {
    // Mock fetch to simulate network error
    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));

    const config: CommercialScannerConfig = {
      id: "tenable-fail",
      platform: "tenable_io",
      name: "Unreachable Tenable",
      baseUrl: "https://unreachable.example.com",
      credentials: { accessKey: "bad", secretKey: "bad" },
    };
    const connector = createConnector(config);
    const health = await connector.testConnection();

    expect(health.reachable).toBe(false);
    expect(health.authenticated).toBe(false);
    expect(health.error).toContain("ECONNREFUSED");
    expect(health.lastChecked).toBeGreaterThan(0);

    global.fetch = originalFetch;
  });

  it("should return healthy when API responds correctly", async () => {
    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ info: { version: "10.6.0", license: { type: "enterprise" } } }),
    });

    const config: CommercialScannerConfig = {
      id: "tenable-ok",
      platform: "tenable_io",
      name: "Working Tenable",
      baseUrl: "https://cloud.tenable.com",
      credentials: { accessKey: "valid", secretKey: "valid" },
    };
    const connector = createConnector(config);
    const health = await connector.testConnection();

    expect(health.reachable).toBe(true);
    expect(health.authenticated).toBe(true);
    expect(health.apiVersion).toBe("10.6.0");
    expect(health.licenseStatus).toBe("enterprise");
    expect(health.latencyMs).toBeGreaterThanOrEqual(0);

    global.fetch = originalFetch;
  });
});
