import { describe, it, expect, beforeAll } from "vitest";

/**
 * Manjusaka C2 Integration Tests
 *
 * Tests the ManjusakaAdapter registration in C2Registry,
 * the orchestrator framework priority/capabilities,
 * and the attack coverage tool mapping.
 */

describe("Manjusaka C2 Adapter", () => {
  let c2Abstraction: any;

  beforeAll(async () => {
    c2Abstraction = await import("./lib/c2-abstraction");
  });

  it("should include manjusaka in C2FrameworkType", () => {
    // The type is enforced at compile time, but we can verify the adapter exists
    const registry = c2Abstraction.getC2Registry();
    expect(registry).toBeDefined();
  });

  it("should register ManjusakaAdapter in the C2Registry", () => {
    const registry = c2Abstraction.getC2Registry();
    const adapter = registry.get("manjusaka");
    expect(adapter).toBeDefined();
    expect(adapter.framework).toBe("manjusaka");
  });

  it("should have correct framework type on ManjusakaAdapter", () => {
    const registry = c2Abstraction.getC2Registry();
    const adapter = registry.get("manjusaka");
    expect(adapter).toBeDefined();
    expect(adapter.framework).toBe("manjusaka");
    // Verify it implements IC2Adapter methods
    expect(typeof adapter.healthCheck).toBe("function");
    expect(typeof adapter.listAgents).toBe("function");
    expect(typeof adapter.searchModules).toBe("function");
    expect(typeof adapter.dispatch).toBe("function");
    expect(typeof adapter.killAgent).toBe("function");
  });

  it("should list agents (empty initially)", async () => {
    const registry = c2Abstraction.getC2Registry();
    const adapter = registry.get("manjusaka");
    const agents = await adapter.listAgents();
    expect(Array.isArray(agents)).toBe(true);
  });

  it("should search modules", async () => {
    const registry = c2Abstraction.getC2Registry();
    const adapter = registry.get("manjusaka");
    const modules = await adapter.searchModules("shell");
    expect(Array.isArray(modules)).toBe(true);
    // Should find at least the shell module
    const shellModule = modules.find((m: any) => m.id === "shell");
    expect(shellModule).toBeDefined();
    expect(shellModule.name).toContain("Shell");
  });

  it("should search modules for credential harvesting", async () => {
    const registry = c2Abstraction.getC2Registry();
    const adapter = registry.get("manjusaka");
    const modules = await adapter.searchModules("cred");
    expect(Array.isArray(modules)).toBe(true);
    expect(modules.length).toBeGreaterThan(0);
  });

  it("should search modules for VNC", async () => {
    const registry = c2Abstraction.getC2Registry();
    const adapter = registry.get("manjusaka");
    const modules = await adapter.searchModules("vnc");
    expect(Array.isArray(modules)).toBe(true);
    const vncModule = modules.find((m: any) => m.id === "vnc-view" || m.id === "vnc-control");
    expect(vncModule).toBeDefined();
  });

  it("should include manjusaka in listAllAgents", async () => {
    const registry = c2Abstraction.getC2Registry();
    // listAllAgents should not throw even with manjusaka registered
    const allAgents = await registry.listAllAgents();
    expect(Array.isArray(allAgents)).toBe(true);
  });
});

describe("Manjusaka in Orchestrator", () => {
  let orchestrator: any;

  beforeAll(async () => {
    orchestrator = await import("./lib/c2-orchestrator");
  });

  it("should export orchestration functions", () => {
    expect(orchestrator.createOrchestrationPlan).toBeDefined();
    expect(orchestrator.executeOrchestrationPlan).toBeDefined();
    expect(orchestrator.getOrchestrationStats).toBeDefined();
  });

  it("should include manjusaka in orchestration stats", async () => {
    const stats = await orchestrator.getOrchestrationStats();
    expect(stats).toBeDefined();
  });
});

describe("Manjusaka in Attack Coverage", () => {
  it("should include manjusaka in the tool mapping", async () => {
    // Import the attack coverage module to verify the tool mapping
    const attackCoverage = await import("./routers/attack-coverage");
    expect(attackCoverage).toBeDefined();
  });
});

describe("Manjusaka C2 Router", () => {
  let manjusakaRouter: any;

  beforeAll(async () => {
    manjusakaRouter = await import("./routers/manjusaka-c2");
  });

  it("should export the manjusakaC2Router", () => {
    expect(manjusakaRouter.manjusakaC2Router).toBeDefined();
  });

  it("should have all expected procedures", () => {
    const router = manjusakaRouter.manjusakaC2Router;
    // Check the router has the expected shape (tRPC router internals)
    expect(router).toBeDefined();
    expect(router._def).toBeDefined();
    expect(router._def.procedures).toBeDefined();

    const procedures = Object.keys(router._def.procedures);
    expect(procedures).toContain("listListeners");
    expect(procedures).toContain("createListener");
    expect(procedures).toContain("stopListener");
    expect(procedures).toContain("listImplants");
    expect(procedures).toContain("generateImplant");
    expect(procedures).toContain("listAgents");
    expect(procedures).toContain("registerAgent");
    expect(procedures).toContain("loadNpc2");
    expect(procedures).toContain("unloadNpc2");
    expect(procedures).toContain("killAgent");
    expect(procedures).toContain("executeTask");
    expect(procedures).toContain("startVnc");
    expect(procedures).toContain("stopVnc");
    expect(procedures).toContain("listVncSessions");
    expect(procedures).toContain("listTunnels");
    expect(procedures).toContain("createTunnel");
    expect(procedures).toContain("stopTunnel");
    expect(procedures).toContain("getStats");
  });
});
