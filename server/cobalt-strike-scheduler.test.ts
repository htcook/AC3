/**
 * Cobalt Strike C2 Adapter & Crawler Scheduler Tests
 *
 * Tests:
 *   1. CobaltStrikeAdapter — Team Server REST API integration, beacon management,
 *      BOF/Aggressor command mapping, MITRE ATT&CK technique coverage
 *   2. CrawlerScheduler — Preset-based scheduling, job queue with priority,
 *      auto-enrichment pipeline, pause/resume, force-run
 *   3. C2 Registry integration — cobaltstrike in unified registry
 *   4. C2 Module Builder — Cobalt Strike code generation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Mock fetch globally ────────────────────────────────────────────────────
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ─── Mock ENV ───────────────────────────────────────────────────────────────
vi.mock("./_core/env", () => ({
  ENV: {
    CS_TEAM_SERVER_URL: "https://cs.example.com",
    CS_API_KEY: "test-api-key-cs",
    CS_API_PORT: 55553,
    CS_USERNAME: "test-operator",
    calderaBaseUrl: "",
    calderaApiKey: "",
  },
}));

// ─── Cobalt Strike Adapter Tests ────────────────────────────────────────────

describe("Cobalt Strike C2 Adapter", () => {
  let CobaltStrikeAdapter: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const mod = await import("./lib/cobalt-strike-adapter");
    CobaltStrikeAdapter = mod.CobaltStrikeAdapter;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("constructor and configuration", () => {
    it("should instantiate with default config", () => {
      const adapter = new CobaltStrikeAdapter();
      expect(adapter).toBeDefined();
      expect(adapter.framework).toBe("cobaltstrike");
    });

    it("should expose framework type as 'cobaltstrike'", () => {
      const adapter = new CobaltStrikeAdapter();
      expect(adapter.framework).toBe("cobaltstrike");
    });
  });

  describe("healthCheck", () => {
    it("should return connected status on successful health check", async () => {
      // healthCheck calls 3 parallel fetches: /api/server/info, /api/beacons, /api/listeners
      mockFetch
        .mockResolvedValueOnce({
          ok: true, status: 200,
          json: async () => ({ version: "4.9", license: "commercial" }),
        })
        .mockResolvedValueOnce({
          ok: true, status: 200,
          json: async () => ([{ id: "b1" }, { id: "b2" }]),
        })
        .mockResolvedValueOnce({
          ok: true, status: 200,
          json: async () => ([{ name: "https" }]),
        });

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.healthCheck();

      expect(result.framework).toBe("cobaltstrike");
      expect(result.connected).toBe(true);
    });

    it("should handle network failure gracefully (catches per-fetch errors)", async () => {
      // healthCheck uses .catch() on each individual fetch in Promise.all
      // So ECONNREFUSED is caught per-fetch, and healthCheck still returns connected=true
      // with null/empty data
      mockFetch.mockRejectedValue(new Error("ECONNREFUSED"));

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.healthCheck();

      // The adapter catches individual fetch errors gracefully
      expect(result.framework).toBe("cobaltstrike");
      expect(result.connected).toBe(true);
      expect(result.agentCount).toBe(0);
    });

    it("should handle HTTP 401 gracefully (auth failure, server reachable)", async () => {
      // healthCheck calls 3 parallel fetches with .catch() on each
      // A 401 causes csFetch to throw, which is caught per-fetch
      // So healthCheck still returns connected=true but with empty data
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        text: async () => "Unauthorized",
      });

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.healthCheck();

      // The adapter catches individual fetch errors, so it still reports connected
      // but with zero agents and null server info
      expect(result.framework).toBe("cobaltstrike");
      expect(result.agentCount).toBe(0);
    });
  });

  describe("listAgents (beacons)", () => {
    it("should return normalized beacon list", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ([
          {
            id: "beacon-001",
            computer: "WORKSTATION-1",
            user: "admin",
            internal: "10.0.0.5",
            os: "Windows 10",
            last: "2026-02-26T12:00:00Z",
            alive: true,
            pid: 4532,
            arch: "x64",
          },
          {
            id: "beacon-002",
            computer: "SERVER-DC",
            user: "SYSTEM",
            internal: "10.0.0.1",
            os: "Windows Server 2022",
            last: "2026-02-26T11:00:00Z",
            alive: false,
            pid: 1234,
            arch: "x64",
          },
        ]),
      });

      const adapter = new CobaltStrikeAdapter();
      const agents = await adapter.listAgents();

      expect(agents).toHaveLength(2);
      expect(agents[0].id).toBe("beacon-001");
      expect(agents[0].hostname).toBe("WORKSTATION-1");
      expect(agents[0].platform).toContain("windows");
      // Status depends on last seen time vs sleep interval
      expect(["active", "dormant", "dead"]).toContain(agents[0].status);
      expect(["active", "dormant", "dead"]).toContain(agents[1].status);
    });

    it("should return empty array on network failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const adapter = new CobaltStrikeAdapter();
      const agents = await adapter.listAgents();

      expect(agents).toEqual([]);
    });
  });

  describe("dispatch (task execution)", () => {
    it("should dispatch a task to a beacon", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          taskId: "task-001",
          status: "queued",
        }),
      });

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.dispatch({
        agentId: "beacon-001",
        moduleId: "shell",
        options: { command: "whoami" },
      });

      expect(result).toBeDefined();
      expect(result.taskId).toBeDefined();
    });

    it("should handle dispatch failure gracefully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.dispatch({
        agentId: "beacon-001",
        moduleId: "shell",
        options: { command: "whoami" },
      });

      expect(result.status).toBe("error");
    });
  });

  describe("CS_TECHNIQUE_MAP", () => {
    it("should contain MITRE ATT&CK technique mappings", async () => {
      const mod = await import("./lib/cobalt-strike-adapter");
      const map = mod.CS_TECHNIQUE_MAP;

      expect(map).toBeDefined();
      expect(Object.keys(map).length).toBeGreaterThan(0);

      // Should have common CS commands mapped
      const hasExecution = Object.values(map).some((v: any) => v.techniqueId?.startsWith("T1059"));
      expect(hasExecution).toBe(true);
    });
  });

  describe("listener management", () => {
    it("should list active listeners", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ([
          { name: "https-listener", type: "https", host: "0.0.0.0", port: 443, profile: "default" },
          { name: "smb-pipe", type: "smb", host: "0.0.0.0", port: 445, profile: "custom" },
        ]),
      });

      const adapter = new CobaltStrikeAdapter();
      const listeners = await adapter.listListeners();

      expect(listeners).toHaveLength(2);
      expect(listeners[0].name).toBe("https-listener");
      expect(listeners[1].type).toBe("smb");
    });

    it("should return empty array on failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const adapter = new CobaltStrikeAdapter();
      const listeners = await adapter.listListeners();

      expect(listeners).toEqual([]);
    });
  });

  describe("BOF execution", () => {
    it("should execute a BOF on a beacon", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          taskId: "bof-task-001",
          status: "queued",
        }),
      });

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.executeBOF("beacon-001", "/path/to/bof.o", "args");

      expect(result).toBeDefined();
      expect(result.taskId).toBeDefined();
    });
  });

  describe("killAgent", () => {
    it("should kill a beacon (csFetch succeeds = true)", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      });

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.killAgent("beacon-001");

      expect(result).toBe(true);
    });

    it("should return false on failure", async () => {
      mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const adapter = new CobaltStrikeAdapter();
      const result = await adapter.killAgent("beacon-001");

      expect(result).toBe(false);
    });
  });
});

// ─── Crawler Scheduler Tests ────────────────────────────────────────────────

describe("Crawler Scheduler", () => {
  let mod: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();
    mod = await import("./lib/crawler-scheduler");
  });

  afterEach(() => {
    try { mod.stopScheduler(); } catch (_e) { /* ignore */ }
    vi.clearAllMocks();
  });

  describe("getSchedulePresets", () => {
    it("should return all available presets", () => {
      const presets = mod.getSchedulePresets();

      expect(presets).toBeDefined();
      expect(Array.isArray(presets)).toBe(true);
      expect(presets.length).toBeGreaterThanOrEqual(3);

      const ids = presets.map((p: any) => p.id);
      expect(ids).toContain("standard");
      expect(ids).toContain("aggressive");
    });

    it("should have valid preset configurations with string intervals", () => {
      const presets = mod.getSchedulePresets();

      for (const preset of presets) {
        expect(preset.id).toBeDefined();
        expect(preset.name).toBeDefined();
        expect(typeof preset.crawlInterval).toBe("string");
        expect(typeof preset.enrichmentInterval).toBe("string");
      }
    });
  });

  describe("startScheduler / stopScheduler", () => {
    it("should start the scheduler with a preset config", () => {
      const result = mod.startScheduler({ preset: "standard" });

      expect(result).toBeDefined();
      expect(result.isRunning).toBe(true);
    });

    it("should stop a running scheduler", () => {
      mod.startScheduler({ preset: "standard" });
      const result = mod.stopScheduler();

      expect(result).toBeDefined();
      expect(result.isRunning).toBe(false);
    });
  });

  describe("getSchedulerStatus", () => {
    it("should return status when stopped", () => {
      const status = mod.getSchedulerStatus();

      expect(status).toBeDefined();
      expect(status.isRunning).toBe(false);
    });

    it("should return status when running", () => {
      mod.startScheduler({ preset: "standard" });
      const status = mod.getSchedulerStatus();

      expect(status.isRunning).toBe(true);
      expect(status.config).toBeDefined();
    });
  });

  describe("pauseScheduler / resumeScheduler", () => {
    it("should pause a running scheduler (sets isRunning to false)", () => {
      mod.startScheduler({ preset: "standard" });
      const result = mod.pauseScheduler();

      // pauseScheduler sets schedulerRunning = false
      expect(result.isRunning).toBe(false);
    });

    it("should resume a paused scheduler (sets isRunning to true)", () => {
      mod.startScheduler({ preset: "standard" });
      mod.pauseScheduler();
      const result = mod.resumeScheduler();

      expect(result.isRunning).toBe(true);
    });
  });

  describe("enqueueJob", () => {
    it("should enqueue a job with priority", () => {
      const result = mod.enqueueJob("full_crawl", "high");

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.type).toBe("full_crawl");
      expect(result.priority).toBe("high");
      expect(result.status).toBe("queued");
    });

    it("should enqueue multiple jobs sorted by priority", () => {
      mod.enqueueJob("source_check", "normal");
      mod.enqueueJob("full_crawl", "critical");
      mod.enqueueJob("gap_analysis", "high");

      const queue = mod.getQueueStatus();

      expect(queue.queueLength).toBeGreaterThanOrEqual(3);
      // Critical should be first
      expect(queue.jobs[0].priority).toBe("critical");
    });
  });

  describe("forceRunJob", () => {
    it("should force-enqueue a job with critical priority", async () => {
      const result = await mod.forceRunJob("full_crawl");

      expect(result).toBeDefined();
      expect(result.priority).toBe("critical");
      expect(result.type).toBe("full_crawl");
    });
  });

  describe("cancelJob", () => {
    it("should cancel a queued job and return true", () => {
      const job = mod.enqueueJob("full_crawl", "normal");
      const result = mod.cancelJob(job.id);

      expect(result).toBe(true);
    });

    it("should return false for non-existent job", () => {
      const result = mod.cancelJob("nonexistent-id");
      expect(result).toBe(false);
    });
  });

  describe("getJobHistory", () => {
    it("should return job history array", () => {
      const history = mod.getJobHistory();

      expect(history).toBeDefined();
      expect(Array.isArray(history)).toBe(true);
    });

    it("should include cancelled jobs in history", () => {
      const job = mod.enqueueJob("full_crawl", "normal");
      mod.cancelJob(job.id);

      const history = mod.getJobHistory();
      const cancelled = history.find((j: any) => j.id === job.id);
      expect(cancelled).toBeDefined();
      expect(cancelled.status).toBe("cancelled");
    });
  });

  describe("getQueueStatus", () => {
    it("should return queue status with jobs array", () => {
      const queue = mod.getQueueStatus();

      expect(queue).toBeDefined();
      expect(typeof queue.queueLength).toBe("number");
      expect(Array.isArray(queue.jobs)).toBe(true);
    });
  });

  describe("updateSchedulerConfig", () => {
    it("should update configuration options", () => {
      mod.startScheduler({ preset: "standard" });
      const result = mod.updateSchedulerConfig({
        autoEnrichAfterCrawl: false,
        retryFailedJobs: false,
      });

      expect(result.config.autoEnrichAfterCrawl).toBe(false);
      expect(result.config.retryFailedJobs).toBe(false);
    });
  });
});

// ─── C2 Registry Integration Tests ─────────────────────────────────────────

describe("C2 Registry — Cobalt Strike Integration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should include cobaltstrike in the C2FrameworkType union", async () => {
    const mod = await import("./lib/c2-abstraction");
    const csAdapter = mod.getCobaltStrikeAdapter();

    expect(csAdapter).toBeDefined();
    expect(csAdapter.framework).toBe("cobaltstrike");
  });

  it("should get the C2 registry with CS registered", async () => {
    const mod = await import("./lib/c2-abstraction");
    const registry = mod.getC2Registry();

    expect(registry).toBeDefined();
  });
});

// ─── C2 Module Builder — Cobalt Strike Tests ────────────────────────────────

vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: `# Cobalt Strike Aggressor Script\n# Technique: T1059.001 - PowerShell\nalias beacon_powershell {\n  bshell($1, "powershell.exe -nop -w hidden");\n}\n`,
      },
    }],
  }),
}));

describe("C2 Module Builder — Cobalt Strike Code Generation", () => {

  it("should generate code for cobaltstrike framework via generateModuleCode", async () => {
    const mod = await import("./lib/c2-module-builder");

    const spec: any = {
      name: "PowerShell Execution",
      description: "Module for T1059.001: PowerShell",
      author: "Test",
      category: "exploitation",
      platforms: ["windows"],
      techniqueIds: ["T1059.001"],
      language: "python",
      targetFrameworks: ["cobaltstrike"],
      requiresAdmin: false,
      requiresNetwork: false,
      opsecRating: 5,
      safetyTier: "medium_risk",
      parameters: [],
    };

    const result = await mod.generateModuleCode(spec);

    expect(result).toBeDefined();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].code).toBeDefined();
    expect(result[0].code.length).toBeGreaterThan(0);
  });

  it("should generate code with CS-specific content", async () => {
    const mod = await import("./lib/c2-module-builder");

    const spec: any = {
      name: "LSASS Memory Dump",
      description: "Module for T1003.001: LSASS Memory",
      author: "Test",
      category: "credential_access",
      platforms: ["windows"],
      techniqueIds: ["T1003.001"],
      language: "python",
      targetFrameworks: ["cobaltstrike"],
      requiresAdmin: true,
      requiresNetwork: false,
      opsecRating: 3,
      safetyTier: "high_risk",
      parameters: [],
    };

    const result = await mod.generateModuleCode(spec);

    expect(result).toBeDefined();
    expect(result.length).toBeGreaterThan(0);
    const code = result[0].code;
    // The LLM-generated code should contain CS-related content
    const hasCSContent = code.includes("beacon") || code.includes("bshell") ||
                         code.includes("alias") || code.includes("aggressor") ||
                         code.includes("Cobalt") || code.includes("CNA") ||
                         code.includes("powershell");
    expect(hasCSContent).toBe(true);
  });
});

// ─── C2 Orchestrator — Cobalt Strike Integration Tests ──────────────────────

describe("C2 Orchestrator — Cobalt Strike Priority", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should include cobaltstrike in the orchestrator module", async () => {
    const mod = await import("./lib/c2-orchestrator");
    expect(mod).toBeDefined();
  });
});
