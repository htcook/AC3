import { describe, it, expect, vi } from "vitest";

// ---- Metasploit Provisioner Tests ----
describe("Metasploit Provisioner", () => {
  it("exports all expected provisioning functions", async () => {
    const provisioner = await import("./lib/msf-provisioner");
    expect(provisioner.provisionMsfDroplet).toBeDefined();
    expect(provisioner.getDropletIp).toBeDefined();
    expect(provisioner.getDropletStatus).toBeDefined();
    expect(provisioner.destroyMsfDroplet).toBeDefined();
    expect(provisioner.rebootDroplet).toBeDefined();
    expect(provisioner.listMsfDroplets).toBeDefined();
    expect(provisioner.getAvailableRegions).toBeDefined();
  });

  it("exports ProvisionRequest and ProvisionResult types", async () => {
    const provisioner = await import("./lib/msf-provisioner");
    // Verify the module loads without errors
    expect(typeof provisioner.provisionMsfDroplet).toBe("function");
    expect(typeof provisioner.destroyMsfDroplet).toBe("function");
  });

  it("exports DropletStatus interface via getDropletStatus", async () => {
    const provisioner = await import("./lib/msf-provisioner");
    expect(typeof provisioner.getDropletStatus).toBe("function");
    expect(typeof provisioner.listMsfDroplets).toBe("function");
  });
});

// ---- Metasploit MSGRPC Client Tests ----
describe("MsfClient", () => {
  it("constructs with correct connection parameters", async () => {
    const { MsfClient } = await import("./lib/msf-client");
    const client = new MsfClient({
      host: "10.0.0.1",
      port: 55553,
      user: "msf",
      pass: "testpass",
      ssl: true,
    });
    expect(client).toBeDefined();
    expect(client).toHaveProperty("login");
    expect(client).toHaveProperty("searchModules");
    expect(client).toHaveProperty("executeModule");
    expect(client).toHaveProperty("listSessions");
    expect(client).toHaveProperty("listJobs");
  });

  it("has fromServerConfig static factory", async () => {
    const { MsfClient } = await import("./lib/msf-client");
    expect(MsfClient.fromServerConfig).toBeDefined();
    const client = MsfClient.fromServerConfig({
      ipAddress: "192.168.1.1",
      rpcPort: 55553,
      rpcUser: "msf",
      rpcPass: "pass",
    });
    expect(client).toBeDefined();
  });

  it("exposes session management methods", async () => {
    const { MsfClient } = await import("./lib/msf-client");
    const client = new MsfClient({ host: "localhost", port: 55553, user: "msf", pass: "test", ssl: false });
    expect(typeof client.listSessions).toBe("function");
    expect(typeof client.listJobs).toBe("function");
    expect(typeof client.stopJob).toBe("function");
  });
});

// ---- Caldera Agent Stager Tests ----
describe("Caldera Agent Stager Generation", () => {
  it("generates stager payloads for all platforms", async () => {
    const { generateAgentStagers } = await import("./lib/msf-client");
    const calderaUrl = "http://10.0.0.1:8888";
    const stagers = generateAgentStagers(calderaUrl, "red");

    // Should have stagers for windows, linux, darwin
    expect(stagers.length).toBeGreaterThanOrEqual(3);
    const winStager = stagers.find(s => s.platform === "windows" && s.type === "sandcat");
    expect(winStager).toBeDefined();
    expect(winStager!.command).toContain("10.0.0.1");

    const linuxStager = stagers.find(s => s.platform === "linux" && s.type === "sandcat");
    expect(linuxStager).toBeDefined();
    expect(linuxStager!.command).toContain("curl");

    const macStager = stagers.find(s => s.platform === "darwin");
    expect(macStager).toBeDefined();
    expect(macStager!.command).toContain("10.0.0.1");
  });

  it("generates manx stager for shell-based agents", async () => {
    const { generateAgentStagers } = await import("./lib/msf-client");
    const stagers = generateAgentStagers("http://10.0.0.1:8888", "red");
    const manxStager = stagers.find(s => s.type === "manx");
    expect(manxStager).toBeDefined();
    expect(manxStager!.command).toContain("manx");
  });

  it("generates MSF resource script for automated exploitation", async () => {
    const { generateMsfResourceScript } = await import("./lib/msf-client");
    const script = generateMsfResourceScript({
      exploitModule: "exploit/windows/smb/ms17_010_eternalblue",
      targetIp: "192.168.1.100",
      targetPort: 445,
      calderaUrl: "http://10.0.0.1:8888",
      lhost: "10.0.0.5",
    });
    expect(script).toContain("use exploit/windows/smb/ms17_010_eternalblue");
    expect(script).toContain("RHOSTS 192.168.1.100");
    expect(script).toContain("RPORT 445");
    expect(script).toContain("exploit");
  });
});

// ---- Unified Exploit Catalog Tests ----
describe("Unified Exploit Catalog", () => {
  it("imports enrichment pipeline functions", async () => {
    const catalog = await import("./lib/exploit-catalog");
    expect(catalog.runEnrichmentPipeline).toBeDefined();
    expect(catalog.searchCatalog).toBeDefined();
    expect(catalog.getCatalogEntry).toBeDefined();
    expect(catalog.syncToCaldera).toBeDefined();
    expect(catalog.syncAllToCaldera).toBeDefined();
    expect(catalog.getCatalogStats).toBeDefined();
  });

  it("searchCatalog returns items array and total count", async () => {
    const { searchCatalog } = await import("./lib/exploit-catalog");
    const result = await searchCatalog({ limit: 10, offset: 0 });
    expect(result).toHaveProperty("items");
    expect(result).toHaveProperty("total");
    expect(Array.isArray(result.items)).toBe(true);
    expect(typeof result.total).toBe("number");
  });

  it("searchCatalog respects limit parameter", async () => {
    const { searchCatalog } = await import("./lib/exploit-catalog");
    const result = await searchCatalog({ limit: 5, offset: 0 });
    expect(result.items.length).toBeLessThanOrEqual(5);
  });

  it("getCatalogStats returns structured stats", async () => {
    const { getCatalogStats } = await import("./lib/exploit-catalog");
    const stats = await getCatalogStats();
    expect(stats).toHaveProperty("total");
    expect(stats).toHaveProperty("byTier");
    expect(stats.byTier).toHaveProperty("initial_access");
    expect(stats.byTier).toHaveProperty("post_access");
    expect(stats).toHaveProperty("calderaSynced");
    expect(typeof stats.total).toBe("number");
  });
});

// ---- Exploit Catalog Enrichment Tests ----
describe("Exploit Catalog Enrichment", () => {
  it("runEnrichmentPipeline function exists and is callable", async () => {
    const catalog = await import("./lib/exploit-catalog");
    expect(catalog.runEnrichmentPipeline).toBeDefined();
    expect(typeof catalog.runEnrichmentPipeline).toBe("function");
  });

  it("syncAllToCaldera function exists and is callable", async () => {
    const catalog = await import("./lib/exploit-catalog");
    expect(catalog.syncAllToCaldera).toBeDefined();
    expect(typeof catalog.syncAllToCaldera).toBe("function");
  });
});

// ---- Metasploit-Catalog Router Tests ----
describe("Metasploit-Catalog Router", () => {
  it("exports a valid tRPC router", async () => {
    const { metasploitCatalogRouter } = await import("./routers/metasploit-catalog");
    expect(metasploitCatalogRouter).toBeDefined();
    expect(metasploitCatalogRouter._def).toBeDefined();
    expect(metasploitCatalogRouter._def.procedures).toBeDefined();
  });

  it("has all expected procedures", async () => {
    const { metasploitCatalogRouter } = await import("./routers/metasploit-catalog");
    const procedures = Object.keys(metasploitCatalogRouter._def.procedures);
    expect(procedures).toContain("provisionServer");
    expect(procedures).toContain("listServers");
    expect(procedures).toContain("checkServerHealth");
    expect(procedures).toContain("destroyServer");
    expect(procedures).toContain("runEnrichment");
    expect(procedures).toContain("searchCatalog");
    expect(procedures).toContain("syncToCaldera");
    expect(procedures).toContain("executeExploit");
    expect(procedures).toContain("autoExploit");
    expect(procedures).toContain("listSessions");
    expect(procedures).toContain("deployAgent");
  });
});
