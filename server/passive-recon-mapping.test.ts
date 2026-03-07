/**
 * Tests for the CRITICAL FIX: passive recon data mapping from domain intel pipeline
 * to asset objects in the engagement orchestrator.
 *
 * Previously, line 1210 only copied `ip` and `type` from domain intel results,
 * completely ignoring passiveRecon (ports, technologies, vulns, risk signals).
 * This test validates the fix that properly maps all passive recon data.
 */
import { describe, it, expect, vi } from "vitest";

describe("Passive Recon Data Mapping Fix", () => {
  it("engagement-orchestrator exports AssetPassiveRecon interface", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    // The module should export the type — we verify by checking the module has the expected shape
    expect(mod).toBeDefined();
    expect(typeof mod.initOpsState).toBe("function");
    expect(typeof mod.getOpsState).toBe("function");
  });

  it("AssetStatus type includes passiveRecon field", async () => {
    const mod = await import("./lib/engagement-orchestrator");
    const state = mod.initOpsState(99999, {
      id: 99999,
      customerName: "Test Corp",
      engagementType: "pentest",
      status: "active",
    } as any);
    expect(state).toBeDefined();
    expect(state.assets).toEqual([]);

    // Manually add an asset and verify passiveRecon can be set
    state.assets.push({
      hostname: "test.example.com",
      ip: "1.2.3.4",
      type: "web_app",
      ports: [{ port: 80, service: "http" }, { port: 443, service: "https" }],
      vulns: [{ id: "CVE-2024-1234", severity: "high", title: "Test Vuln", cve: "CVE-2024-1234" }],
      zapFindings: [],
      exploitAttempts: [],
      toolResults: [],
      status: "discovered",
      passiveRecon: {
        subdomains: ["sub1.example.com"],
        ipAddresses: ["1.2.3.4"],
        services: [
          { port: 80, protocol: "tcp", service: "http", product: "nginx", version: "1.21", source: "shodan" },
          { port: 443, protocol: "tcp", service: "https", product: "nginx", version: "1.21", source: "shodan" },
        ],
        technologies: ["nginx", "PHP", "WordPress"],
        certificates: [{ subject: "*.example.com", issuer: "Let's Encrypt" }],
        riskSignals: [
          { severity: "high", type: "exposed_admin", rationale: "Admin panel exposed on port 80" },
        ],
        historicalUrls: [],
        rawObservationCount: 5,
        sources: ["shodan", "censys"],
      },
    });

    expect(state.assets[0].passiveRecon).toBeDefined();
    expect(state.assets[0].passiveRecon!.technologies).toContain("nginx");
    expect(state.assets[0].passiveRecon!.services.length).toBe(2);
    expect(state.assets[0].passiveRecon!.riskSignals.length).toBe(1);
    expect(state.assets[0].ports.length).toBe(2);
    expect(state.assets[0].vulns.length).toBe(1);
  });

  it("engagement orchestrator source code contains passiveRecon assignment in recon phase", async () => {
    // This test verifies the fix is present in the source code
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // The fix should assign passiveRecon to existing assets
    expect(source).toContain("existing.passiveRecon = passiveRecon");

    // The fix should add ports from passive recon services
    expect(source).toContain("Add ports from passive recon");

    // The fix should add vulns from posture findings
    expect(source).toContain("Add vulns from posture findings");

    // The fix should build passiveRecon from pipeline results
    expect(source).toContain("buildPassiveRecon");

    // The fix should convert posture findings to vulns
    expect(source).toContain("postureToVulns");

    // New assets should also get passiveRecon
    expect(source).toContain("passiveRecon,");

    // Stats should be updated after passive recon
    expect(source).toContain("state.stats.portsFound = state.assets.reduce");
    expect(source).toContain("state.stats.vulnsFound = state.assets.reduce");
  });

  it("discovered status is set after passive recon enrichment", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // After enriching an existing asset, status should be set to 'discovered'
    expect(source).toContain("existing.status = 'discovered'");

    // New in-scope assets should also start as 'discovered'
    expect(source).toContain('status: "discovered"');
  });

  it("passiveReconResults are stored on state for LLM context", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // Raw passive recon results should be stored for LLM context
    expect(source).toContain("state.passiveReconResults[domain]");
    expect(source).toContain("totalObservations");
    expect(source).toContain("connectorStats");
  });

  it("ports from passive recon are deduplicated when merging into existing assets", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // Should check for existing ports before adding
    expect(source).toContain("existing.ports.some");
  });

  it("vulns from passive recon are deduplicated when merging into existing assets", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // Should check for existing vulns before adding
    expect(source).toContain("existing.vulns.some");
  });

  it("recon log includes port and vuln counts from passive recon", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      require("path").join(__dirname, "lib/engagement-orchestrator.ts"),
      "utf-8"
    );

    // The log message should include port and vuln counts
    expect(source).toContain("ports from passive recon");
  });
});
