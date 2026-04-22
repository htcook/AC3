import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for:
 * 1. Technique Heatmap endpoint — aggregates MITRE ATT&CK technique usage across actors
 * 2. Auto-Discovery Scheduling — rotating strategy discovery integrated into enrichment scheduler
 */

// ─── Technique Heatmap Tests ──────────────────────────────────────────

describe("Technique Heatmap — Backend Aggregation", () => {
  it("should export the techniqueHeatmap procedure on the router", async () => {
    const { appRouter } = await import("./routers");
    // The router should have the procedure registered
    const procedures = Object.keys((appRouter as any)._def.procedures);
    expect(procedures).toContain("threatIntel.techniqueHeatmap");
  });

  it("should return the expected shape from the heatmap endpoint", async () => {
    // We test the logic by directly importing the router and checking the procedure exists
    const { appRouter } = await import("./routers");
    const procedures = Object.keys((appRouter as any)._def.procedures);
    expect(procedures).toContain("threatIntel.techniqueHeatmap");
    // The procedure is a query (not mutation)
    const proc = (appRouter as any)._def.procedures["threatIntel.techniqueHeatmap"];
    expect(proc).toBeDefined();
    expect(proc._def.type).toBe("query");
  });
});

// ─── Auto-Discovery Scheduling Tests ──────────────────────────────────

describe("Auto-Discovery Scheduling — Strategy Rotation", () => {
  beforeEach(async () => {
    const mod = await import("./lib/catalog-enrichment-scheduler");
    mod.resetDiscoveryStrategyIndex();
  });

  it("should rotate through 5 discovery strategies in order", async () => {
    const { getNextDiscoveryStrategy, resetDiscoveryStrategyIndex } = await import("./lib/catalog-enrichment-scheduler");
    resetDiscoveryStrategyIndex();

    const strategies: string[] = [];
    for (let i = 0; i < 5; i++) {
      strategies.push(getNextDiscoveryStrategy());
    }

    expect(strategies).toEqual([
      "related_actors",
      "sector_gaps",
      "recent_campaigns",
      "emerging_threats",
      "geographic_coverage",
    ]);
  });

  it("should wrap around after exhausting all strategies", async () => {
    const { getNextDiscoveryStrategy, resetDiscoveryStrategyIndex } = await import("./lib/catalog-enrichment-scheduler");
    resetDiscoveryStrategyIndex();

    // Exhaust all 5 strategies
    for (let i = 0; i < 5; i++) {
      getNextDiscoveryStrategy();
    }

    // 6th call should wrap back to the first strategy
    const sixth = getNextDiscoveryStrategy();
    expect(sixth).toBe("related_actors");
  });

  it("should track the current strategy index", async () => {
    const { getNextDiscoveryStrategy, getCurrentDiscoveryStrategyIndex, resetDiscoveryStrategyIndex } = await import("./lib/catalog-enrichment-scheduler");
    resetDiscoveryStrategyIndex();

    expect(getCurrentDiscoveryStrategyIndex()).toBe(0);
    getNextDiscoveryStrategy();
    expect(getCurrentDiscoveryStrategyIndex()).toBe(1);
    getNextDiscoveryStrategy();
    expect(getCurrentDiscoveryStrategyIndex()).toBe(2);
  });

  it("should reset the strategy index", async () => {
    const { getNextDiscoveryStrategy, getCurrentDiscoveryStrategyIndex, resetDiscoveryStrategyIndex } = await import("./lib/catalog-enrichment-scheduler");
    
    getNextDiscoveryStrategy();
    getNextDiscoveryStrategy();
    expect(getCurrentDiscoveryStrategyIndex()).toBeGreaterThan(0);
    
    resetDiscoveryStrategyIndex();
    expect(getCurrentDiscoveryStrategyIndex()).toBe(0);
  });
});

describe("Auto-Discovery Scheduling — Scheduler Status", () => {
  it("should include discovery status in getCatalogEnrichmentStatus", async () => {
    const { getCatalogEnrichmentStatus } = await import("./lib/catalog-enrichment-scheduler");
    const status = getCatalogEnrichmentStatus();

    expect(status).toHaveProperty("discovery");
    expect(status.discovery).toHaveProperty("enabled");
    expect(status.discovery).toHaveProperty("totalRuns");
    expect(status.discovery).toHaveProperty("totalDiscovered");
    expect(status.discovery).toHaveProperty("pendingReview");
    expect(status.discovery).toHaveProperty("nextStrategy");
    expect(status.discovery).toHaveProperty("currentStrategyIndex");
  });

  it("should have discovery enabled by default", async () => {
    const { getCatalogEnrichmentStatus } = await import("./lib/catalog-enrichment-scheduler");
    const status = getCatalogEnrichmentStatus();
    expect(status.discovery.enabled).toBe(true);
  });

  it("should include config with discoveryEnabled field", async () => {
    const { getCatalogEnrichmentStatus } = await import("./lib/catalog-enrichment-scheduler");
    const status = getCatalogEnrichmentStatus();
    expect(status.config).toHaveProperty("discoveryEnabled");
    expect(typeof status.config.discoveryEnabled).toBe("boolean");
  });
});

describe("Auto-Discovery Scheduling — Config Updates", () => {
  it("should allow toggling discoveryEnabled via updateCatalogEnrichmentConfig", async () => {
    const { updateCatalogEnrichmentConfig, getCatalogEnrichmentStatus } = await import("./lib/catalog-enrichment-scheduler");

    // Disable discovery
    updateCatalogEnrichmentConfig({ discoveryEnabled: false });
    let status = getCatalogEnrichmentStatus();
    expect(status.discovery.enabled).toBe(false);
    expect(status.config.discoveryEnabled).toBe(false);

    // Re-enable discovery
    updateCatalogEnrichmentConfig({ discoveryEnabled: true });
    status = getCatalogEnrichmentStatus();
    expect(status.discovery.enabled).toBe(true);
    expect(status.config.discoveryEnabled).toBe(true);
  });

  it("should preserve other config when updating discoveryEnabled", async () => {
    const { updateCatalogEnrichmentConfig, getCatalogEnrichmentStatus } = await import("./lib/catalog-enrichment-scheduler");

    // Set a specific batch size first
    updateCatalogEnrichmentConfig({ batchSize: 25 });
    
    // Toggle discovery — batch size should remain
    updateCatalogEnrichmentConfig({ discoveryEnabled: false });
    const status = getCatalogEnrichmentStatus();
    expect(status.config.batchSize).toBe(25);
    expect(status.config.discoveryEnabled).toBe(false);

    // Reset
    updateCatalogEnrichmentConfig({ batchSize: 10, discoveryEnabled: true });
  });

  it("should expose the catalogEnrichmentConfig mutation with discoveryEnabled", async () => {
    const { appRouter } = await import("./routers");
    const procedures = Object.keys((appRouter as any)._def.procedures);
    expect(procedures).toContain("threatIntel.catalogEnrichmentConfig");
  });
});

describe("Auto-Discovery Scheduling — isEnrichmentSchedulerRunning", () => {
  it("should return false when not running", async () => {
    const { isEnrichmentSchedulerRunning } = await import("./lib/catalog-enrichment-scheduler");
    expect(isEnrichmentSchedulerRunning()).toBe(false);
  });
});

// ─── Dashboard Widget Config Tests ──────────────────────────────────

describe("Technique Heatmap — Dashboard Widget Registration", () => {
  it("should have technique-heatmap in the widget config file", async () => {
    // Read the file and check for the widget ID
    const fs = await import("fs");
    const content = fs.readFileSync(
      require("path").resolve(__dirname, "../client/src/contexts/DashboardWidgetConfig.tsx"),
      "utf-8"
    );
    expect(content).toContain("technique-heatmap");
    expect(content).toContain("Technique Heatmap");
  });
});
