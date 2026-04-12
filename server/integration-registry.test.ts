/**
 * Integration Registry — Comprehensive Test Suite
 * ═══════════════════════════════════════════════════════════════════════
 * Tests for: types, built-in catalog, pipeline wiring, value assessment,
 * registry lifecycle, and coverage analysis.
 * 
 * NOTE: Auto-discovery engine tests are separate since they require LLM mocking.
 */

import { describe, it, expect, beforeEach } from "vitest";

// ─── Types & Constants ──────────────────────────────────────────────

import {
  CATEGORY_METADATA,
  PIPELINE_STAGE_METADATA,
} from "./lib/integration-registry/types";

describe("Integration Registry Types", () => {
  it("should define all 11 categories with metadata", () => {
    const categories = Object.keys(CATEGORY_METADATA);
    expect(categories).toContain("osint");
    expect(categories).toContain("threat_intel");
    expect(categories).toContain("credential");
    expect(categories).toContain("scanner");
    expect(categories).toContain("pentest_tool");
    expect(categories).toContain("exploit_db");
    expect(categories).toContain("phishing");
    expect(categories).toContain("c2");
    expect(categories).toContain("siem_soar");
    expect(categories).toContain("cloud");
    expect(categories).toContain("custom");
    expect(categories.length).toBe(11);
  });

  it("should define all 10 pipeline stages with metadata", () => {
    const stages = Object.keys(PIPELINE_STAGE_METADATA);
    expect(stages).toContain("recon");
    expect(stages).toContain("passive_discovery");
    expect(stages).toContain("enumeration");
    expect(stages).toContain("vuln_detection");
    expect(stages).toContain("social_engineering");
    expect(stages).toContain("exploitation");
    expect(stages).toContain("post_exploit");
    expect(stages).toContain("reporting");
    expect(stages).toContain("monitoring");
    expect(stages).toContain("enrichment");
    expect(stages.length).toBe(10);
  });

  it("each category metadata should have label, description, icon, and color", () => {
    for (const [key, meta] of Object.entries(CATEGORY_METADATA)) {
      expect(meta.label).toBeTruthy();
      expect(meta.description).toBeTruthy();
      expect(meta.icon).toBeTruthy();
      expect(meta.color).toBeTruthy();
    }
  });

  it("each stage metadata should have label, description, and order", () => {
    for (const [key, meta] of Object.entries(PIPELINE_STAGE_METADATA)) {
      expect(meta.label).toBeTruthy();
      expect(meta.description).toBeTruthy();
      expect(typeof meta.order).toBe("number");
    }
  });
});

// ─── Built-In Catalog ───────────────────────────────────────────────

import { BUILTIN_CATALOG, CATALOG_BY_ID } from "./lib/integration-registry/builtin-catalog";

describe("Built-In Catalog", () => {
  it("should have at least 30 built-in integrations", () => {
    expect(BUILTIN_CATALOG.length).toBeGreaterThanOrEqual(30);
  });

  it("CATALOG_BY_ID should index all catalog entries", () => {
    expect(CATALOG_BY_ID.size).toBe(BUILTIN_CATALOG.length);
    for (const entry of BUILTIN_CATALOG) {
      expect(CATALOG_BY_ID.get(entry.id)).toBe(entry);
    }
  });

  it("each catalog entry should have required fields", () => {
    for (const entry of BUILTIN_CATALOG) {
      expect(entry.id).toBeTruthy();
      expect(entry.displayName).toBeTruthy();
      expect(entry.description).toBeTruthy();
      expect(entry.category).toBeTruthy();
      expect(entry.pipelineStages.length).toBeGreaterThan(0);
      expect(entry.dataTypes.length).toBeGreaterThan(0);
      expect(entry.licenseModel).toBeTruthy();
      expect(entry.authMethod).toBeTruthy();
    }
  });

  it("should have integrations across multiple categories", () => {
    const categories = new Set(BUILTIN_CATALOG.map(e => e.category));
    expect(categories.size).toBeGreaterThanOrEqual(6);
  });

  it("should cover all pipeline stages", () => {
    const stages = new Set(BUILTIN_CATALOG.flatMap(e => e.pipelineStages));
    // At minimum: recon, passive_discovery, enumeration, vuln_detection, exploitation, enrichment
    expect(stages.size).toBeGreaterThanOrEqual(6);
  });

  it("should include key integrations: Shodan, Censys, Nuclei, Burp Suite", () => {
    expect(CATALOG_BY_ID.has("shodan")).toBe(true);
    expect(CATALOG_BY_ID.has("censys")).toBe(true);
    expect(CATALOG_BY_ID.has("nuclei")).toBe(true);
    expect(CATALOG_BY_ID.has("burp_suite")).toBe(true);
  });

  it("should include threat intel sources: VirusTotal, AbuseIPDB", () => {
    expect(CATALOG_BY_ID.has("virustotal")).toBe(true);
    expect(CATALOG_BY_ID.has("abuseipdb")).toBe(true);
  });

  it("should include C2 frameworks: Caldera, Sliver", () => {
    expect(CATALOG_BY_ID.has("caldera")).toBe(true);
    expect(CATALOG_BY_ID.has("sliver")).toBe(true);
  });

  it("each entry should have unique ID", () => {
    const ids = BUILTIN_CATALOG.map(e => e.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});

// ─── Pipeline Wiring Engine ─────────────────────────────────────────

import {
  generateWiringConfig,
  analyzePipelineCoverage,
  compareIntegrationValue,
} from "./lib/integration-registry/pipeline-wiring-engine";

describe("Pipeline Wiring Engine", () => {
  describe("generateWiringConfig", () => {
    it("should generate wiring for an OSINT integration", () => {
      const result = generateWiringConfig({
        id: "test-osint",
        category: "osint",
        pipelineStages: ["recon", "passive_discovery"],
        dataTypes: ["subdomains", "ip_addresses"],
        requiresActiveProbing: false,
      });

      expect(result.config).toBeDefined();
      expect(result.config.stages).toEqual(["recon", "passive_discovery"]);
      expect(result.config.parallel).toBe(true); // OSINT runs in parallel
      expect(result.config.failurePolicy).toBe("continue"); // OSINT failure doesn't block
      expect(result.explanation).toBeTruthy();
    });

    it("should generate wiring for a scanner with sequential execution", () => {
      const result = generateWiringConfig({
        id: "test-scanner",
        category: "scanner",
        pipelineStages: ["vuln_detection"],
        dataTypes: ["vulnerabilities"],
        requiresActiveProbing: true,
      });

      expect(result.config.parallel).toBe(false); // Scanners run sequentially
      expect(result.config.failurePolicy).toBe("warn");
      expect(result.config.maxDurationMs).toBe(600_000); // 10 min for scanners
    });

    it("should add RoE condition for active probing", () => {
      const result = generateWiringConfig({
        id: "test-active",
        category: "scanner",
        pipelineStages: ["vuln_detection"],
        dataTypes: ["vulnerabilities"],
        requiresActiveProbing: true,
      });

      const roeCondition = result.config.conditions.find(c => c.type === "if_roe_allows");
      expect(roeCondition).toBeDefined();
    });

    it("should add dependency condition for exploitation stage", () => {
      const result = generateWiringConfig({
        id: "test-exploit",
        category: "pentest_tool",
        pipelineStages: ["exploitation"],
        dataTypes: ["exploit_results"],
        requiresActiveProbing: false,
      });

      const depCondition = result.config.conditions.find(c => c.type === "if_previous_found");
      expect(depCondition).toBeDefined();
      expect(depCondition?.params?.previousStage).toBe("vuln_detection");
    });

    it("should boost priority for high-value integrations", () => {
      const normal = generateWiringConfig({
        id: "test-normal",
        category: "osint",
        pipelineStages: ["recon"],
        dataTypes: ["subdomains"],
        requiresActiveProbing: false,
      });

      const highValue = generateWiringConfig({
        id: "test-highvalue",
        category: "osint",
        pipelineStages: ["recon"],
        dataTypes: ["subdomains"],
        requiresActiveProbing: false,
        valueAssessment: {
          overallScore: 90,
          uniquenessScore: 80,
          coverageScore: 85,
          reliabilityScore: 90,
          overlapPercent: 10,
          overlapSources: [],
          recommendation: "strongly_recommended",
          reasoning: "High value",
        },
      });

      expect(highValue.config.priority).toBeLessThan(normal.config.priority);
    });

    it("should find deduplication targets", () => {
      const result = generateWiringConfig({
        id: "test-dedup",
        category: "osint",
        pipelineStages: ["recon"],
        dataTypes: ["subdomains", "ip_addresses"],
        requiresActiveProbing: false,
      });

      // Should find overlapping built-in integrations
      expect(result.config.deduplicateWith.length).toBeGreaterThan(0);
    });
  });

  describe("analyzePipelineCoverage", () => {
    it("should return coverage for all 10 stages", () => {
      const report = analyzePipelineCoverage([
        { id: "a", category: "osint", stages: ["recon"], dataTypes: ["subdomains"] },
        { id: "b", category: "scanner", stages: ["vuln_detection"], dataTypes: ["vulnerabilities"] },
      ]);

      expect(Object.keys(report.stages).length).toBe(10);
      expect(report.overallScore).toBeGreaterThanOrEqual(0);
      expect(report.overallScore).toBeLessThanOrEqual(100);
    });

    it("should report 'none' coverage for empty stages", () => {
      const report = analyzePipelineCoverage([]);
      for (const [stage, info] of Object.entries(report.stages)) {
        expect(info.coverageLevel).toBe("none");
        expect(info.integrationCount).toBe(0);
      }
    });

    it("should report recommendations for gaps", () => {
      const report = analyzePipelineCoverage([
        { id: "a", category: "osint", stages: ["recon"], dataTypes: ["subdomains"] },
      ]);

      expect(report.topRecommendations.length).toBeGreaterThan(0);
    });

    it("should increase coverage level with more integrations", () => {
      const sparse = analyzePipelineCoverage([
        { id: "a", category: "osint", stages: ["recon"], dataTypes: ["subdomains"] },
      ]);

      const dense = analyzePipelineCoverage([
        { id: "a", category: "osint", stages: ["recon"], dataTypes: ["subdomains"] },
        { id: "b", category: "osint", stages: ["recon"], dataTypes: ["ip_addresses"] },
        { id: "c", category: "osint", stages: ["recon"], dataTypes: ["dns_records"] },
        { id: "d", category: "osint", stages: ["recon"], dataTypes: ["certificates"] },
        { id: "e", category: "osint", stages: ["recon"], dataTypes: ["technologies"] },
        { id: "f", category: "osint", stages: ["recon"], dataTypes: ["whois"] },
      ]);

      const sparseRecon = sparse.stages.recon;
      const denseRecon = dense.stages.recon;
      expect(denseRecon.integrationCount).toBeGreaterThan(sparseRecon.integrationCount);
    });
  });

  describe("compareIntegrationValue", () => {
    it("should strongly recommend an integration covering new stages", () => {
      const result = compareIntegrationValue(
        { id: "new", name: "New Tool", category: "scanner", dataTypes: ["vulnerabilities"], stages: ["vuln_detection"] },
        [{ id: "existing", name: "Existing", category: "osint", dataTypes: ["subdomains"], stages: ["recon"] }],
      );

      expect(result.recommendation).toBe("strongly_recommended");
      expect(result.netNewStages).toContain("vuln_detection");
    });

    it("should mark as redundant when fully overlapping", () => {
      const result = compareIntegrationValue(
        { id: "new", name: "New Tool", category: "osint", dataTypes: ["subdomains"], stages: ["recon"] },
        [{ id: "existing", name: "Existing", category: "osint", dataTypes: ["subdomains"], stages: ["recon"] }],
      );

      expect(result.recommendation).toBe("redundant");
      expect(result.overlaps.length).toBeGreaterThan(0);
    });

    it("should recommend when providing new data types", () => {
      const result = compareIntegrationValue(
        { id: "new", name: "New Tool", category: "osint", dataTypes: ["subdomains", "leaked_credentials"], stages: ["recon"] },
        [{ id: "existing", name: "Existing", category: "osint", dataTypes: ["subdomains"], stages: ["recon"] }],
      );

      expect(result.recommendation).toBe("recommended");
      expect(result.netNewDataTypes).toContain("leaked_credentials");
    });

    it("should calculate overlap percentages correctly", () => {
      const result = compareIntegrationValue(
        { id: "new", name: "New Tool", category: "osint", dataTypes: ["subdomains", "ip_addresses", "dns_records"], stages: ["recon"] },
        [{ id: "existing", name: "Existing", category: "osint", dataTypes: ["subdomains", "ip_addresses"], stages: ["recon"] }],
      );

      const overlap = result.overlaps.find(o => o.existingId === "existing");
      expect(overlap).toBeDefined();
      expect(overlap!.sharedDataTypes).toContain("subdomains");
      expect(overlap!.sharedDataTypes).toContain("ip_addresses");
      expect(overlap!.uniqueToNew).toContain("dns_records");
    });
  });
});

// ─── Registry Lifecycle ─────────────────────────────────────────────

import {
  getAllIntegrations,
  getIntegration,
  getIntegrationsByCategory,
  getIntegrationsByStage,
  getCustomerIntegrations,
  getCategorySummary,
  submitCustomerReview,
  activateIntegration,
  pauseIntegration,
  removeIntegration,
  getHealthSummary,
} from "./lib/integration-registry/registry";

describe("Registry Lifecycle", () => {
  it("getAllIntegrations should include built-in catalog", async () => {
    const all = await getAllIntegrations();
    expect(all.length).toBeGreaterThanOrEqual(BUILTIN_CATALOG.length);
  });

  it("getIntegration should find built-in integrations", async () => {
    const shodan = await getIntegration("shodan");
    expect(shodan).toBeDefined();
    expect((shodan as any).displayName).toContain("Shodan");
  });

  it("getIntegrationsByCategory should filter correctly", async () => {
    const osint = await getIntegrationsByCategory("osint");
    expect(osint.length).toBeGreaterThan(0);
    for (const item of osint) {
      expect(item.category).toBe("osint");
    }
  });

  it("getIntegrationsByStage should filter correctly", async () => {
    const recon = await getIntegrationsByStage("recon");
    expect(recon.length).toBeGreaterThan(0);
    for (const item of recon) {
      const stages = (item as any).pipelineStages || (item as any).capabilities?.pipelineStages || [];
      expect(stages).toContain("recon");
    }
  });

  it("getCategorySummary should return all categories with counts", async () => {
    const summary = await getCategorySummary();
    expect(summary.length).toBe(11);
    const osintSummary = summary.find(s => s.category === "osint");
    expect(osintSummary).toBeDefined();
    expect(osintSummary!.builtInCount).toBeGreaterThan(0);
  });

  it("getHealthSummary should return correct counts", async () => {
    const health = await getHealthSummary();
    expect(health.total).toBeGreaterThanOrEqual(BUILTIN_CATALOG.length);
    expect(health.builtIn).toBe(BUILTIN_CATALOG.length);
  });

  it("activateIntegration should fail for non-existent integration", async () => {
    const result = await activateIntegration("non-existent-id");
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("pauseIntegration should fail for non-existent integration", async () => {
    const result = await pauseIntegration("non-existent-id");
    expect(result.success).toBe(false);
  });

  it("removeIntegration should fail for non-existent integration", async () => {
    const result = await removeIntegration("non-existent-id");
    expect(result.success).toBe(false);
  });

  it("submitCustomerReview should fail for non-existent discovery", async () => {
    const result = await submitCustomerReview("non-existent-discovery", {
      approved: true,
      reviewedBy: "test-user",
      reviewedAt: Date.now(),
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("not found");
  });
});


// ─── DB Persistence Tests ─────────────────────────────────────────

import * as db from "./db";

describe("Customer Integration DB Persistence", () => {
  it("createCustomerIntegration should insert and return an ID", async () => {
    const id = await db.createCustomerIntegration({
      integrationId: `test-persist-${Date.now()}`,
      name: "test-persist",
      displayName: "Test Persistence Integration",
      category: "osint",
      pipelineStages: JSON.stringify(["recon", "passive_discovery"]),
      dataTypes: JSON.stringify(["subdomains"]),
      authMethod: "api_key",
      endpointBaseUrl: "https://api.example.com",
      credentials: JSON.stringify({ apiKey: "test-key" }),
      status: "proposed",
      autoDiscoveryResult: JSON.stringify({ classification: { category: "osint" } }),
      addedBy: "1",
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });
    expect(id).toBeGreaterThan(0);
  });

  it("getCustomerIntegrationsByStatus should filter by status", async () => {
    const uniqueId = `test-status-${Date.now()}`;
    await db.createCustomerIntegration({
      integrationId: uniqueId,
      name: "status-filter-test",
      displayName: "Status Filter Test",
      category: "scanner",
      pipelineStages: JSON.stringify(["vuln_detection"]),
      dataTypes: JSON.stringify(["vulnerabilities"]),
      authMethod: "bearer_token",
      endpointBaseUrl: "https://scanner.example.com",
      credentials: JSON.stringify({}),
      status: "active",
      addedBy: "1",
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    const active = await db.getCustomerIntegrationsByStatus("active");
    const found = active.find(i => i.integrationId === uniqueId);
    expect(found).toBeDefined();
    expect(found?.status).toBe("active");
  });

  it("updateCustomerIntegration should update fields", async () => {
    const uniqueId = `test-update-${Date.now()}`;
    await db.createCustomerIntegration({
      integrationId: uniqueId,
      name: "update-test",
      displayName: "Update Test",
      category: "threat_intel",
      pipelineStages: JSON.stringify(["enrichment"]),
      dataTypes: JSON.stringify(["threat_indicators"]),
      authMethod: "api_key",
      endpointBaseUrl: "https://ti.example.com",
      credentials: JSON.stringify({}),
      status: "proposed",
      addedBy: "1",
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });

    await db.updateCustomerIntegration(uniqueId, {
      status: "approved",
      displayName: "Updated Name",
    } as any);

    const updated = await db.getCustomerIntegrationByIntegrationId(uniqueId);
    expect(updated?.status).toBe("approved");
    expect(updated?.displayName).toBe("Updated Name");
  });
});

// ─── Health Monitor Tests ─────────────────────────────────────────

import {
  getHealthStatusSummary,
} from "./lib/integration-registry/health-monitor";

describe("Health Monitor", () => {
  it("getHealthStatusSummary should return initial empty state", () => {
    const summary = getHealthStatusSummary();
    expect(summary).toBeDefined();
    expect(typeof summary.tracked).toBe("number");
    expect(typeof summary.healthy).toBe("number");
    expect(typeof summary.down).toBe("number");
    expect(typeof summary.authExpired).toBe("number");
    expect(typeof summary.rateLimited).toBe("number");
  });

  it("createHealthCheck should record a check in the DB", async () => {
    const uniqueId = `health-test-${Date.now()}`;
    await db.createHealthCheck({
      integrationId: uniqueId,
      status: "healthy",
      httpStatus: 200,
      latencyMs: 150,
      errorMessage: null,
      checkedAt: Date.now(),
    } as any);

    // hoursBack = 24 by default, our check was just created so it should be within range
    const history = await db.getHealthCheckHistory(uniqueId, 24);
    expect(history.length).toBeGreaterThanOrEqual(1);
    const latest = history.find(h => h.integrationId === uniqueId);
    expect(latest?.status).toBe("healthy");
    expect(latest?.httpStatus).toBe(200);
  });
});

// ─── Pipeline Bridge Tests ────────────────────────────────────────

import {
  getActiveSourcesForStage,
} from "./lib/integration-registry/pipeline-bridge";

describe("Pipeline Bridge", () => {
  it("getActiveIntegrationsForStage should return array for any stage", async () => {
    const integrations = await getActiveSourcesForStage("recon");
    expect(Array.isArray(integrations)).toBe(true);
  });

  it("getActiveSourcesForStage should return array for vuln_detection", async () => {
    const integrations = await getActiveSourcesForStage("vuln_detection");
    expect(Array.isArray(integrations)).toBe(true);
  });

  it("getActiveSourcesForStage should return array for exploitation", async () => {
    const integrations = await getActiveSourcesForStage("exploitation");
    expect(Array.isArray(integrations)).toBe(true);
  });
});

// ─── Scan Scheduler Change Detection Fix Tests ────────────────────

import { detectSubdomainChanges } from "./lib/domain-intel-advanced";

describe("Scan Scheduler Change Detection (Fixed)", () => {
  it("detectSubdomainChanges should accept 10 parameters and return structured result", () => {
    const result = detectSubdomainChanges(
      1,    // currentScanId
      0,    // previousScanId
      "example.com",
      [],   // currentAssets
      [],   // previousAssets
      { discoveredSubdomains: [], discoveredPorts: [] },  // currentPipeline
      { discoveredSubdomains: [], discoveredPorts: [] },  // previousPipeline
      Date.now(),
      Date.now() - 86400000,
    );

    expect(result).toBeDefined();
    expect(result.domain).toBe("example.com");
    expect(result.totalChanges).toBe(0);
    expect(Array.isArray(result.newSubdomains)).toBe(true);
    expect(Array.isArray(result.removedSubdomains)).toBe(true);
    expect(Array.isArray(result.modifiedSubdomains)).toBe(true);
  });

  it("should detect new subdomains from pipeline output", () => {
    const result = detectSubdomainChanges(
      2, 1, "example.com",
      [], [],
      {
        discoveredSubdomains: [
          { name: "new.example.com", ip: "1.2.3.4" },
          { name: "api.example.com", ip: "5.6.7.8" },
        ],
        discoveredPorts: [],
      },
      { discoveredSubdomains: [], discoveredPorts: [] },
      Date.now(),
      Date.now() - 86400000,
    );

    expect(result.totalChanges).toBe(2);
    expect(result.newSubdomains.length).toBe(2);
    expect(result.newSubdomains[0].changeType).toBe("new");
  });

  it("should detect removed subdomains", () => {
    const result = detectSubdomainChanges(
      2, 1, "example.com",
      [], [],
      { discoveredSubdomains: [], discoveredPorts: [] },
      {
        discoveredSubdomains: [
          { name: "old.example.com", ip: "1.2.3.4" },
        ],
        discoveredPorts: [],
      },
      Date.now(),
      Date.now() - 86400000,
    );

    expect(result.removedSubdomains.length).toBe(1);
    expect(result.removedSubdomains[0].changeType).toBe("removed");
  });
});
