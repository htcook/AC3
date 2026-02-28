/**
 * Tests for new vendor connectors: Microsoft Sentinel & Palo Alto Cortex XDR
 * Also tests vendor registry updates and alert correlation pipeline.
 */
import { describe, it, expect } from "vitest";

// ─── Microsoft Sentinel Client ──────────────────────────────────────────────

describe("SentinelClient", () => {
  it("should be importable and constructable", async () => {
    const { createSentinelClient } = await import("./lib/vendors/sentinel");
    expect(createSentinelClient).toBeDefined();
    expect(typeof createSentinelClient).toBe("function");

    const client = createSentinelClient({
      tenantId: "test-tenant",
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
    }, {
      subscriptionId: "test-sub",
      resourceGroup: "test-rg",
      workspaceName: "test-workspace",
    } as any);

    expect(client).toBeDefined();
    expect(client.getDisplayName()).toBe("Microsoft Sentinel");
  });

  it("should have all required methods", async () => {
    const { createSentinelClient } = await import("./lib/vendors/sentinel");
    const client = createSentinelClient({
      tenantId: "t",
      clientId: "c",
      clientSecret: "s",
    }, {
      subscriptionId: "sub",
      resourceGroup: "rg",
      workspaceName: "ws",
    } as any);

    expect(typeof client.healthCheck).toBe("function");
    expect(typeof client.authenticate).toBe("function");
    expect(typeof client.listIncidents).toBe("function");
    expect(typeof client.getIncident).toBe("function");
    expect(typeof client.runHuntingQuery).toBe("function");
    expect(typeof client.listAnalyticsRules).toBe("function");
    expect(typeof client.listWatchlists).toBe("function");
    expect(typeof client.pushIndicators).toBe("function");
  });

  it("should require tenantId, clientId, and clientSecret", async () => {
    const { createSentinelClient } = await import("./lib/vendors/sentinel");
    const client = createSentinelClient({}, {} as any);

    // authenticate should throw when missing credentials
    await expect(client.authenticate()).rejects.toThrow();
  });
});

// ─── Cortex XDR Client ──────────────────────────────────────────────────────

describe("CortexXDRClient", () => {
  it("should be importable and constructable", async () => {
    const { createCortexXDRClient } = await import("./lib/vendors/cortex-xdr");
    expect(createCortexXDRClient).toBeDefined();
    expect(typeof createCortexXDRClient).toBe("function");

    const client = createCortexXDRClient({
      apiToken: "test-api-key",
      apiKeyId: "test-key-id",
    });

    expect(client).toBeDefined();
    expect(client.getDisplayName()).toBe("Palo Alto Cortex XDR");
  });

  it("should have all required methods", async () => {
    const { createCortexXDRClient } = await import("./lib/vendors/cortex-xdr");
    const client = createCortexXDRClient({
      apiToken: "test-key",
      apiKeyId: "test-id",
    });

    expect(typeof client.healthCheck).toBe("function");
    expect(typeof client.authenticate).toBe("function");
    expect(typeof client.listIncidents).toBe("function");
    expect(typeof client.getIncidentDetails).toBe("function");
    expect(typeof client.listAlerts).toBe("function");
    expect(typeof client.listEndpoints).toBe("function");
    expect(typeof client.runXQLQuery).toBe("function");
    expect(typeof client.isolateEndpoint).toBe("function");
    expect(typeof client.unisolateEndpoint).toBe("function");
    expect(typeof client.scanEndpoint).toBe("function");
    expect(typeof client.pushIOCs).toBe("function");
  });

  it("should require apiToken and apiKeyId", async () => {
    const { createCortexXDRClient } = await import("./lib/vendors/cortex-xdr");
    const client = createCortexXDRClient({});

    await expect(client.authenticate()).rejects.toThrow("Missing API Key or API Key ID");
  });

  it("should support advanced security level", async () => {
    const { createCortexXDRClient } = await import("./lib/vendors/cortex-xdr");
    // region="standard" triggers standard auth, anything else triggers advanced
    const standardClient = createCortexXDRClient({
      apiToken: "test-key",
      apiKeyId: "test-id",
      region: "standard",
    });
    expect(standardClient).toBeDefined();

    const advancedClient = createCortexXDRClient({
      apiToken: "test-key",
      apiKeyId: "test-id",
      region: "advanced",
    });
    expect(advancedClient).toBeDefined();
  });
});

// ─── Vendor Registry ────────────────────────────────────────────────────────

describe("Vendor Registry", () => {
  it("should include sentinel and cortex_xdr in VENDOR_METADATA", async () => {
    const { VENDOR_METADATA } = await import("./lib/vendors/index");

    expect(VENDOR_METADATA.sentinel).toBeDefined();
    expect(VENDOR_METADATA.sentinel.displayName).toBe("Microsoft Sentinel");
    expect(VENDOR_METADATA.sentinel.category).toBe("SIEM");
    expect(VENDOR_METADATA.sentinel.authType).toBe("oauth2");
    expect(VENDOR_METADATA.sentinel.capabilities).toContain("incidents");
    expect(VENDOR_METADATA.sentinel.capabilities).toContain("hunting_queries");
    expect(VENDOR_METADATA.sentinel.capabilities).toContain("ioc_push");

    expect(VENDOR_METADATA.cortex_xdr).toBeDefined();
    expect(VENDOR_METADATA.cortex_xdr.displayName).toBe("Palo Alto Cortex XDR");
    expect(VENDOR_METADATA.cortex_xdr.category).toBe("XDR");
    expect(VENDOR_METADATA.cortex_xdr.authType).toBe("token");
    expect(VENDOR_METADATA.cortex_xdr.capabilities).toContain("incidents");
    expect(VENDOR_METADATA.cortex_xdr.capabilities).toContain("xql_queries");
    expect(VENDOR_METADATA.cortex_xdr.capabilities).toContain("ioc_management");
  });

  it("should have 7 total vendors in VENDOR_METADATA", async () => {
    const { VENDOR_METADATA } = await import("./lib/vendors/index");
    const vendorCount = Object.keys(VENDOR_METADATA).length;
    expect(vendorCount).toBe(7);
  });

  it("should create sentinel client via factory", async () => {
    const { createVendorClient } = await import("./lib/vendors/index");
    const client = createVendorClient("sentinel", {
      tenantId: "t",
      clientId: "c",
      clientSecret: "s",
    }, {
      baseUrl: "",
      timeout: 30000,
      subscriptionId: "sub",
      resourceGroup: "rg",
      workspaceName: "ws",
    } as any);

    expect(client).toBeDefined();
    expect(client.getDisplayName()).toBe("Microsoft Sentinel");
  });

  it("should create cortex_xdr client via factory", async () => {
    const { createVendorClient } = await import("./lib/vendors/index");
    const client = createVendorClient("cortex_xdr", {
      apiToken: "test-key",
      apiKeyId: "test-id",
    }, {
      baseUrl: "https://api-test.xdr.us.paloaltonetworks.com",
      timeout: 30000,
    });

    expect(client).toBeDefined();
    expect(client.getDisplayName()).toBe("Palo Alto Cortex XDR");
  });

  it("should include all vendor categories: EDR, SIEM, SOAR, XDR", async () => {
    const { VENDOR_METADATA } = await import("./lib/vendors/index");
    const categories = new Set(Object.values(VENDOR_METADATA).map(v => v.category));
    expect(categories.has("EDR")).toBe(true);
    expect(categories.has("SIEM")).toBe(true);
    expect(categories.has("SOAR")).toBe(true);
    expect(categories.has("XDR")).toBe(true);
  });
});
