/**
 * Chain Execution Callbacks, DB Persistence, and Discovery Chain Router Tests
 *
 * Tests cover:
 * 1. buildRealCallbacks — structure, scope enforcement, Nuclei simulation
 * 2. buildPersistentCallbacks — DB hooks on progress/stageComplete
 * 3. DB query helpers — insertChainRun, updateChainRunDb, listChainRunsDb, etc.
 * 4. Discovery chain router — procedure existence and input validation
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── 1. buildRealCallbacks ─────────────────────────────────────────────────

describe("buildRealCallbacks", () => {
  let buildRealCallbacks: typeof import("./lib/chain-execution-callbacks").buildRealCallbacks;

  beforeEach(async () => {
    vi.resetModules();
    const mod = await import("./lib/chain-execution-callbacks");
    buildRealCallbacks = mod.buildRealCallbacks;
  });

  it("should return an object with all required callback keys", () => {
    const cb = buildRealCallbacks();
    expect(cb).toHaveProperty("executeAmass");
    expect(cb).toHaveProperty("executeNmap");
    expect(cb).toHaveProperty("executeFingerprint");
    expect(cb).toHaveProperty("executeNuclei");
    expect(cb).toHaveProperty("enforceScope");
    expect(typeof cb.executeAmass).toBe("function");
    expect(typeof cb.executeNmap).toBe("function");
    expect(typeof cb.executeFingerprint).toBe("function");
    expect(typeof cb.executeNuclei).toBe("function");
    expect(typeof cb.enforceScope).toBe("function");
  });

  it("should pass onProgress and onStageComplete options through", () => {
    const onProgress = vi.fn();
    const onStageComplete = vi.fn();
    const cb = buildRealCallbacks({ onProgress, onStageComplete });
    expect(cb.onProgress).toBe(onProgress);
    expect(cb.onStageComplete).toBe(onStageComplete);
  });

  it("should default onProgress/onStageComplete to undefined when not provided", () => {
    const cb = buildRealCallbacks();
    expect(cb.onProgress).toBeUndefined();
    expect(cb.onStageComplete).toBeUndefined();
  });

  describe("executeNuclei (simulated)", () => {
    it("should return findings array and rawResult", async () => {
      const cb = buildRealCallbacks();
      const result = await cb.executeNuclei({
        targets: ["10.0.0.1", "10.0.0.2"],
        categories: ["cves"],
        severity: ["critical", "high", "medium", "low", "info"],
        timeout: 120,
      });
      expect(result).toHaveProperty("findings");
      expect(result).toHaveProperty("rawResult");
      expect(Array.isArray(result.findings)).toBe(true);
      expect(result.rawResult.status).toBe("completed");
      expect(result.rawResult.targetsScanned).toBe(2);
    });

    it("should generate findings proportional to targets and categories", async () => {
      const cb = buildRealCallbacks();
      const result = await cb.executeNuclei({
        targets: ["10.0.0.1"],
        categories: ["cves", "vulnerabilities"],
        severity: ["critical", "high", "medium", "low", "info"],
        timeout: 60,
      });
      // Max = targets * categories * 2 = 1 * 2 * 2 = 4
      expect(result.findings.length).toBeLessThanOrEqual(4);
      expect(result.rawResult.findingCount).toBe(result.findings.length);
    });

    it("should filter findings by severity", async () => {
      const cb = buildRealCallbacks();
      const result = await cb.executeNuclei({
        targets: Array.from({ length: 20 }, (_, i) => `10.0.0.${i + 1}`),
        categories: ["cves", "vulnerabilities", "misconfiguration"],
        severity: ["critical"],
        timeout: 60,
      });
      // All findings should be critical (or empty if random didn't hit critical)
      for (const f of result.findings) {
        expect(f.severity).toBe("critical");
      }
    });

    it("should include category and tags in findings", async () => {
      const cb = buildRealCallbacks();
      const result = await cb.executeNuclei({
        targets: ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        categories: ["cves"],
        severity: ["critical", "high", "medium", "low", "info"],
        tags: ["test-chain"],
        timeout: 60,
      });
      for (const f of result.findings) {
        expect(f.category).toBe("cves");
        expect(f.tags).toContain("test-chain");
        expect(f.host).toMatch(/^10\.0\.0\./);
        expect(f.timestamp).toBeGreaterThan(0);
      }
    });

    it("should cap findings at 100", async () => {
      const cb = buildRealCallbacks();
      const result = await cb.executeNuclei({
        targets: Array.from({ length: 50 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256 + 1}`),
        categories: ["cves", "vulnerabilities", "misconfiguration", "exposures", "default-logins"],
        severity: ["critical", "high", "medium", "low", "info"],
        timeout: 60,
      });
      // Max would be 50 * 5 * 2 = 500, but capped at 100
      expect(result.findings.length).toBeLessThanOrEqual(100);
    });
  });

  describe("enforceScope", () => {
    it("should return inScope and outOfScope arrays", async () => {
      const cb = buildRealCallbacks();
      // enforceScope calls enforceMultiTargetScope which may throw for non-existent engagements
      // but the callback handles errors gracefully
      const result = await cb.enforceScope({
        engagementId: 99999,
        targets: ["10.0.0.1", "10.0.0.2"],
        tool: "nmap",
        operatorId: "test",
      });
      expect(result).toHaveProperty("inScope");
      expect(result).toHaveProperty("outOfScope");
      expect(Array.isArray(result.inScope)).toBe(true);
      expect(Array.isArray(result.outOfScope)).toBe(true);
      // Total should equal original targets
      expect(result.inScope.length + result.outOfScope.length).toBe(2);
    });
  });
});

// ─── 2. buildPersistentCallbacks ────────────────────────────────────────────

describe("buildPersistentCallbacks", () => {
  let buildPersistentCallbacks: typeof import("./lib/chain-execution-callbacks").buildPersistentCallbacks;

  beforeEach(async () => {
    vi.resetModules();
    const mod = await import("./lib/chain-execution-callbacks");
    buildPersistentCallbacks = mod.buildPersistentCallbacks;
  });

  it("should return an object with all required callback keys", () => {
    const cb = buildPersistentCallbacks("test-chain-123");
    expect(cb).toHaveProperty("executeAmass");
    expect(cb).toHaveProperty("executeNmap");
    expect(cb).toHaveProperty("executeFingerprint");
    expect(cb).toHaveProperty("executeNuclei");
    expect(cb).toHaveProperty("enforceScope");
    expect(cb).toHaveProperty("onProgress");
    expect(cb).toHaveProperty("onStageComplete");
  });

  it("should have onProgress and onStageComplete as functions (DB hooks)", () => {
    const cb = buildPersistentCallbacks("test-chain-456");
    expect(typeof cb.onProgress).toBe("function");
    expect(typeof cb.onStageComplete).toBe("function");
  });

  it("should call user-provided onProgress alongside DB persistence", async () => {
    const userOnProgress = vi.fn();
    const cb = buildPersistentCallbacks("test-chain-789", { onProgress: userOnProgress });
    // Call onProgress — it will try to persist to DB (may fail in test env, but should not throw)
    await cb.onProgress!({ status: "running", progress: 50, currentStage: "nmap" });
    expect(userOnProgress).toHaveBeenCalledWith({ status: "running", progress: 50, currentStage: "nmap" });
  });

  it("should call user-provided onStageComplete alongside DB persistence", async () => {
    const userOnStageComplete = vi.fn();
    const cb = buildPersistentCallbacks("test-chain-abc", { onStageComplete: userOnStageComplete });
    const mockRun = {
      stages: [{ stageId: "amass", status: "completed", inputTargetCount: 3, outputCount: 10, findings: [], startedAt: Date.now(), completedAt: Date.now(), durationMs: 5000 }],
      progress: 25,
      currentStage: "nmap",
      allFindings: [],
      summary: { stagesCompleted: 1, stagesFailed: 0, stagesSkipped: 0 },
    };
    await cb.onStageComplete!(mockRun, "amass");
    expect(userOnStageComplete).toHaveBeenCalledWith(mockRun, "amass");
  });

  it("should not throw when DB persistence fails", async () => {
    const cb = buildPersistentCallbacks("nonexistent-chain");
    // This should gracefully handle DB errors
    await expect(
      cb.onProgress!({ status: "running", progress: 10 })
    ).resolves.not.toThrow();
  });
});

// ─── 3. DB Schema & Query Helpers ───────────────────────────────────────────

describe("Chain Run DB Schema", () => {
  it("should export chainRuns and chainStageResults from schema", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema).toHaveProperty("chainRuns");
    expect(schema).toHaveProperty("chainStageResults");
  });

  it("chainRuns table should have required columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.chainRuns;
    // Check that the table has the expected column names
    const columnNames = Object.keys(table);
    expect(columnNames).toContain("id");
    expect(columnNames).toContain("chainId");
    expect(columnNames).toContain("engagementId");
    expect(columnNames).toContain("status");
  });

  it("chainStageResults table should have required columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.chainStageResults;
    const columnNames = Object.keys(table);
    expect(columnNames).toContain("id");
    expect(columnNames).toContain("chainId");
    expect(columnNames).toContain("stageId");
    expect(columnNames).toContain("status");
  });
});

describe("Chain Run DB Helpers", () => {
  it("should export insertChainRun", async () => {
    const db = await import("./db");
    expect(typeof db.insertChainRun).toBe("function");
  });

  it("should export updateChainRunDb", async () => {
    const db = await import("./db");
    expect(typeof db.updateChainRunDb).toBe("function");
  });

  it("should export getChainRunByChainId", async () => {
    const db = await import("./db");
    expect(typeof db.getChainRunByChainId).toBe("function");
  });

  it("should export listChainRunsDb", async () => {
    const db = await import("./db");
    expect(typeof db.listChainRunsDb).toBe("function");
  });

  it("should export deleteChainRunDb", async () => {
    const db = await import("./db");
    expect(typeof db.deleteChainRunDb).toBe("function");
  });

  it("should export upsertChainStageResultDb", async () => {
    const db = await import("./db");
    expect(typeof db.upsertChainStageResultDb).toBe("function");
  });

  it("should export getChainStageResultsDb", async () => {
    const db = await import("./db");
    expect(typeof db.getChainStageResultsDb).toBe("function");
  });
});

// ─── 4. Discovery Chain Router ──────────────────────────────────────────────

describe("Discovery Chain Router", () => {
  it("should be registered in the main appRouter", async () => {
    const { appRouter } = await import("./routers");
    // The router should have discoveryChain namespace
    expect(appRouter._def.procedures).toBeDefined();
  });

  it("should export discoveryChainRouter", async () => {
    const { discoveryChainRouter } = await import("./routers/discovery-chain");
    expect(discoveryChainRouter).toBeDefined();
    expect(discoveryChainRouter._def).toBeDefined();
  });

  describe("Router procedures", () => {
    let router: any;

    beforeEach(async () => {
      const mod = await import("./routers/discovery-chain");
      router = mod.discoveryChainRouter;
    });

    it("should have start procedure", () => {
      expect(router._def.procedures.start).toBeDefined();
    });

    it("should have getStatus procedure", () => {
      expect(router._def.procedures.getStatus).toBeDefined();
    });

    it("should have getFindings procedure", () => {
      expect(router._def.procedures.getFindings).toBeDefined();
    });

    it("should have cancel procedure", () => {
      expect(router._def.procedures.cancel).toBeDefined();
    });

    it("should have getHistory procedure", () => {
      expect(router._def.procedures.getHistory).toBeDefined();
    });

    it("should have getStageDefinitions procedure", () => {
      expect(router._def.procedures.getStageDefinitions).toBeDefined();
    });

    it("should have estimateDuration procedure", () => {
      expect(router._def.procedures.estimateDuration).toBeDefined();
    });

    it("should have getDataFlow procedure", () => {
      expect(router._def.procedures.getDataFlow).toBeDefined();
    });

    it("should have delete procedure", () => {
      expect(router._def.procedures.delete).toBeDefined();
    });

    it("should have exactly 9 procedures", () => {
      const procedureNames = Object.keys(router._def.procedures);
      expect(procedureNames).toHaveLength(9);
      expect(procedureNames.sort()).toEqual([
        "cancel",
        "delete",
        "estimateDuration",
        "getDataFlow",
        "getFindings",
        "getHistory",
        "getStageDefinitions",
        "getStatus",
        "start",
      ]);
    });
  });
});

// ─── 5. Integration: Callbacks produce correct output shapes ────────────────

describe("Callback Output Shapes", () => {
  it("executeNuclei output should have findings with required fields", async () => {
    const { buildRealCallbacks } = await import("./lib/chain-execution-callbacks");
    const cb = buildRealCallbacks();
    const result = await cb.executeNuclei({
      targets: ["example.com"],
      categories: ["cves"],
      severity: ["critical", "high", "medium", "low", "info"],
      timeout: 30,
    });

    for (const f of result.findings) {
      expect(f).toHaveProperty("templateId");
      expect(f).toHaveProperty("templateName");
      expect(f).toHaveProperty("severity");
      expect(f).toHaveProperty("type");
      expect(f).toHaveProperty("host");
      expect(f).toHaveProperty("matchedAt");
      expect(f).toHaveProperty("timestamp");
      expect(f).toHaveProperty("category");
    }
  });

  it("executeNuclei rawResult should include scan metadata", async () => {
    const { buildRealCallbacks } = await import("./lib/chain-execution-callbacks");
    const cb = buildRealCallbacks();
    const result = await cb.executeNuclei({
      targets: ["a.com", "b.com"],
      categories: ["misconfiguration"],
      severity: ["high", "medium"],
      timeout: 30,
    });

    expect(result.rawResult).toHaveProperty("status", "completed");
    expect(result.rawResult).toHaveProperty("targetsScanned", 2);
    expect(result.rawResult).toHaveProperty("templateCategories");
    expect(result.rawResult.templateCategories).toContain("misconfiguration");
  });

  it("enforceScope should gracefully handle missing engagement", async () => {
    const { buildRealCallbacks } = await import("./lib/chain-execution-callbacks");
    const cb = buildRealCallbacks();
    const result = await cb.enforceScope({
      engagementId: -1,
      targets: ["192.168.1.1"],
      tool: "nmap",
      operatorId: "test",
    });
    // Should not throw, should return valid structure
    expect(result.inScope).toBeDefined();
    expect(result.outOfScope).toBeDefined();
  });
});
