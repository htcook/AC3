/**
 * Commercial Scanner Connectors Router Tests
 * Tests the tRPC router, SonarQube webhook receiver, and MSF provisioner integration.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Test: Router Structure ──────────────────────────────────────────────────

describe("Commercial Scanners Router", () => {
  it("exports commercialScannersRouter with expected procedures", async () => {
    const { commercialScannersRouter } = await import("./commercial-scanners");
    expect(commercialScannersRouter).toBeDefined();
    const procedures = Object.keys(commercialScannersRouter._def.procedures);
    expect(procedures).toContain("listPlatforms");
    expect(procedures).toContain("addConnector");
    expect(procedures).toContain("listConnectors");
    expect(procedures).toContain("getConnector");
    expect(procedures).toContain("removeConnector");
    expect(procedures).toContain("toggleConnector");
    expect(procedures).toContain("testConnection");
    expect(procedures).toContain("triggerScan");
    expect(procedures).toContain("getScanStatus");
    expect(procedures).toContain("listScans");
    expect(procedures).toContain("importResults");
    expect(procedures).toContain("listFindings");
    expect(procedures).toContain("updateFindingStatus");
    expect(procedures).toContain("getStats");
    expect(procedures).toContain("registerSonarQubeWebhook");
    expect(procedures).toContain("listSonarQubeWebhooks");
    expect(procedures).toContain("provisionMsfInstance");
    expect(procedures).toContain("validateMsfRpc");
    expect(procedures).toContain("destroyMsfInstance");
  });

  it("listPlatforms returns all 16 FedRAMP/NIST/DoD platforms", async () => {
    const { getSupportedPlatforms, PLATFORM_METADATA } = await import("../lib/commercial-scanners/factory");
    const platforms = getSupportedPlatforms();
    expect(platforms.length).toBeGreaterThanOrEqual(16);
    // Verify key platforms are present (using actual IDs from CONNECTOR_MAP)
    expect(platforms).toContain("tenable_io");
    expect(platforms).toContain("qualys_vmdr");
    expect(platforms).toContain("rapid7_insightvm");
    expect(platforms).toContain("veracode");
    expect(platforms).toContain("checkmarx_one");
    expect(platforms).toContain("fortify_on_demand");
    expect(platforms).toContain("crowdstrike_falcon");
    expect(platforms).toContain("prisma_cloud");
    expect(platforms).toContain("ms_defender_vuln");
    expect(platforms).toContain("snyk");
    expect(platforms).toContain("hcl_appscan");
    expect(platforms).toContain("burp_suite_enterprise");
    expect(platforms).toContain("acunetix");
    expect(platforms).toContain("wiz");
    expect(platforms).toContain("anchore_enterprise");
    expect(platforms).toContain("sonarqube");

    // Each platform should have metadata
    for (const p of platforms) {
      const meta = PLATFORM_METADATA[p];
      expect(meta).toBeDefined();
      expect(meta.name).toBeTruthy();
      expect(meta.vendor).toBeTruthy();
      expect(meta.scanTypes).toBeInstanceOf(Array);
      expect(meta.scanTypes.length).toBeGreaterThan(0);
    }
  });
});

// ─── Test: Connector Factory ─────────────────────────────────────────────────

describe("Connector Factory", () => {
  it("creates connector instances for all supported platforms", async () => {
    const { createConnector, getSupportedPlatforms } = await import("../lib/commercial-scanners/factory");
    const platforms = getSupportedPlatforms();

    for (const platform of platforms) {
      const connector = createConnector({
        id: `test_${platform}`,
        platform,
        name: `Test ${platform}`,
        baseUrl: "https://test.example.com",
        credentials: { apiKey: "test-key" },
      });
      expect(connector).toBeDefined();
      expect(typeof connector.testConnection).toBe("function");
      expect(typeof connector.launchScan).toBe("function");
      expect(typeof connector.getResults).toBe("function");
      expect(typeof connector.getScanStatus).toBe("function");
    }
  });

  it("throws for unsupported platform", async () => {
    const { createConnector } = await import("../lib/commercial-scanners/factory");
    expect(() => createConnector({
      id: "test_invalid",
      platform: "nonexistent-platform",
      name: "Invalid",
      baseUrl: "https://test.example.com",
      credentials: {},
    })).toThrow();
  });
});

// ─── Test: SonarQube Webhook Receiver ────────────────────────────────────────

describe("SonarQube Webhook Receiver", () => {
  it("exports registerSonarQubeWebhookRoutes function", async () => {
    const { registerSonarQubeWebhookRoutes } = await import("../lib/sonarqube-webhook-receiver");
    expect(typeof registerSonarQubeWebhookRoutes).toBe("function");
  });

  it("registers POST /api/webhooks/sonarqube/:webhookId route", async () => {
    const { registerSonarQubeWebhookRoutes } = await import("../lib/sonarqube-webhook-receiver");
    const routes: Array<{ method: string; path: string }> = [];
    const mockApp = {
      post: (path: string, handler: any) => {
        routes.push({ method: "POST", path });
      },
    } as any;

    registerSonarQubeWebhookRoutes(mockApp);
    expect(routes).toContainEqual({ method: "POST", path: "/api/webhooks/sonarqube/:webhookId" });
  });
});

// ─── Test: MSF Provisioner ───────────────────────────────────────────────────

describe("MSF Provisioner", () => {
  it("exports provisionMsfServer and destroyMsfServer", async () => {
    const provisioner = await import("../lib/msf-provisioner");
    expect(typeof provisioner.provisionMsfServer).toBe("function");
    expect(typeof provisioner.destroyMsfServer).toBe("function");
    expect(typeof provisioner.provisionMsfInstance).toBe("function");
    expect(typeof provisioner.terminateMsfInstance).toBe("function");
    expect(typeof provisioner.getInstanceIp).toBe("function");
    expect(typeof provisioner.getInstanceStatus).toBe("function");
    expect(typeof provisioner.listMsfInstances).toBe("function");
    expect(typeof provisioner.getAvailableRegions).toBe("function");
  });

  it("provisionMsfInstance fails gracefully without AWS credentials", async () => {
    const { provisionMsfInstance } = await import("../lib/msf-provisioner");
    const result = await provisionMsfInstance({ name: "test-instance" });
    // Should fail gracefully (no real AWS credentials in test env)
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("backward-compat aliases exist", async () => {
    const provisioner = await import("../lib/msf-provisioner");
    expect(typeof provisioner.provisionMsfDroplet).toBe("function");
    expect(typeof provisioner.getDropletIp).toBe("function");
    expect(typeof provisioner.getDropletStatus).toBe("function");
    expect(typeof provisioner.destroyMsfDroplet).toBe("function");
    expect(typeof provisioner.listMsfDroplets).toBe("function");
  });
});

// ─── Test: AWS EC2 Infra ─────────────────────────────────────────────────────

describe("AWS EC2 Infrastructure", () => {
  it("exports all expected functions", async () => {
    const infra = await import("../lib/aws-ec2-infra");
    expect(typeof infra.createInstance).toBe("function");
    expect(typeof infra.deleteInstance).toBe("function");
    expect(typeof infra.getInstance).toBe("function");
    expect(typeof infra.listInstances).toBe("function");
    expect(typeof infra.rebootInstance).toBe("function");
    expect(typeof infra.stopInstance).toBe("function");
    expect(typeof infra.startInstance).toBe("function");
    expect(typeof infra.healthCheckAll).toBe("function");
    expect(typeof infra.listSecurityGroups).toBe("function");
    expect(typeof infra.listKeyPairs).toBe("function");
  });

  it("backward-compat createDroplet alias exists", async () => {
    const infra = await import("../lib/aws-ec2-infra");
    expect(typeof infra.createDroplet).toBe("function");
  });
});

// ─── Test: Platform Metadata Quality ─────────────────────────────────────────

describe("Platform Metadata Quality", () => {
  it("all platforms have FedRAMP level specified", async () => {
    const { getSupportedPlatforms, PLATFORM_METADATA } = await import("../lib/commercial-scanners/factory");
    const platforms = getSupportedPlatforms();

    for (const p of platforms) {
      const meta = PLATFORM_METADATA[p];
      expect(meta.fedRampLevel).toBeTruthy();
      // Just verify it's a non-empty string (levels vary: "FedRAMP High", "FedRAMP Moderate", etc.)
      expect(meta.fedRampLevel.length).toBeGreaterThan(0);
    }
  });

  it("all platforms have authFields defined", async () => {
    const { getSupportedPlatforms, PLATFORM_METADATA } = await import("../lib/commercial-scanners/factory");
    const platforms = getSupportedPlatforms();

    for (const p of platforms) {
      const meta = PLATFORM_METADATA[p];
      expect(meta.authFields).toBeInstanceOf(Array);
      expect(meta.authFields.length).toBeGreaterThan(0);
      // Each authField should have key, label, type, required
      for (const field of meta.authFields) {
        expect(field.key).toBeTruthy();
        expect(field.label).toBeTruthy();
        expect(["text", "password"]).toContain(field.type);
        expect(typeof field.required).toBe("boolean");
      }
    }
  });

  it("all platforms have defaultBaseUrl", async () => {
    const { getSupportedPlatforms, PLATFORM_METADATA } = await import("../lib/commercial-scanners/factory");
    const platforms = getSupportedPlatforms();

    for (const p of platforms) {
      const meta = PLATFORM_METADATA[p];
      expect(meta.defaultBaseUrl).toBeTruthy();
      expect(meta.defaultBaseUrl.startsWith("https://")).toBe(true);
    }
  });
});
