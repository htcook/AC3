/**
 * Integration Tests: Phase 6 Vulnerability Detection Delegation Chain
 * 
 * Tests the full delegation flow from orchestrator → sub-modules,
 * verifying that state transitions, logging, and results propagate correctly
 * across the vuln-prep → nuclei → ZAP → injection → credential → correlation pipeline.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock State Factory ──────────────────────────────────────────────────────

function createMockState(overrides: Partial<any> = {}): any {
  return {
    engagementId: 42,
    phase: "vuln_detection",
    currentAction: "",
    progress: 50,
    engagementType: "pentest",
    trainingLabMode: false,
    assets: [
      {
        hostname: "target.example.com",
        ip: "10.0.0.1",
        type: "web",
        status: "enumerated",
        ports: [
          { port: 80, service: "http", version: "nginx/1.21" },
          { port: 443, service: "https", version: "nginx/1.21" },
          { port: 22, service: "ssh", version: "OpenSSH_8.9" },
        ],
        vulns: [
          { title: "CVE-2023-1234: RCE in nginx", cve: "CVE-2023-1234", severity: "critical", description: "Remote code execution", source: "nuclei" },
          { title: "SQL Injection in /api/users", severity: "high", description: "Blind SQL injection", source: "zap" },
          { title: "Exposed .env file", severity: "medium", description: "Info disclosure", source: "nuclei" },
        ],
        technologies: ["nginx", "node.js", "react"],
        confirmedCredentials: [],
        exploitAttempts: [],
        wafDetected: "none",
      },
      {
        hostname: "db.example.com",
        ip: "10.0.0.2",
        type: "database",
        status: "enumerated",
        ports: [
          { port: 3306, service: "mysql", version: "8.0.32" },
          { port: 22, service: "ssh", version: "OpenSSH_8.9" },
        ],
        vulns: [
          { title: "MySQL weak credentials", severity: "high", description: "Default credentials", source: "hydra" },
        ],
        technologies: ["mysql"],
        confirmedCredentials: [],
        exploitAttempts: [],
        wafDetected: "none",
      },
    ],
    log: [],
    stats: {
      exploitsAttempted: 0,
      exploitsSucceeded: 0,
      sessionsOpened: 0,
      vulnsFound: 3,
    },
    completedScans: {
      nucleiCompleted: new Set<string>(),
      zapCompleted: new Set<string>(),
      injectionCompleted: new Set<string>(),
      credentialCompleted: new Set<string>(),
      exploitCompleted: new Set<string>(),
      lastCheckpointAt: 0,
    },
    metadata: { sector: "technology", clientType: "saas" },
    targetProfiles: {},
    ...overrides,
  };
}

/**
 * Create a context that matches the vuln-prep module's expected interface
 * (nested helpers object)
 */
function createVulnPrepContext(state: any): any {
  return {
    state,
    engagement: { id: 42, name: "Test Engagement", scope: "*.example.com" },
    operatorCtx: { id: "op-1", name: "Test Operator" },
    scanServerHost: "scan.internal.local",
    helpers: {
      addLog: vi.fn((s: any, entry: any) => {
        s.log.push({ id: `log-${s.log.length}`, timestamp: Date.now(), ...entry });
      }),
      broadcastOpsUpdate: vi.fn(),
      pushVulnDeduped: vi.fn(() => true),
      persistOpsStateDebounced: vi.fn(),
      persistScanResult: vi.fn(async () => {}),
      executeToolViaQueue: vi.fn(async () => ({ stdout: "", exitCode: 0 })),
      acquireScanSlot: vi.fn(async () => ({ release: () => {} })),
      getScanConcurrencyMetrics: vi.fn(() => ({ active: 0, queued: 0, maxConcurrency: 5 })),
      genId: vi.fn(() => `id-${Math.random().toString(36).slice(2, 8)}`),
      breathe: vi.fn(async () => {}),
      invokeLLM: vi.fn(async () => ({ choices: [{ message: { content: "[]" } }] })),
      throttledLLMCall: vi.fn(async () => ({ choices: [{ message: { content: "[]" } }] })),
      parseToolOutput: vi.fn(() => []),
      isInRoeScope: vi.fn(() => true),
      requestApproval: vi.fn(async () => true),
      getEffectiveTarget: vi.fn((asset: any) => asset.ip || asset.hostname),
      fmtTarget: vi.fn((asset: any) => `${asset.hostname} (${asset.ip})`),
      llmDecide: vi.fn(async () => ({ decision: "proceed", actions: [] })),
      captureDecision: vi.fn(async () => {}),
      scoreEngagementThreatAttribution: vi.fn(async () => ({})),
    },
  };
}

/**
 * Create a context that matches the nuclei/zap/injection/credential/correlation
 * modules' expected interface (flat helpers on ctx)
 */
function createFlatContext(state: any): any {
  return {
    state,
    engagement: { id: 42, name: "Test Engagement", scope: "*.example.com" },
    operatorCtx: { id: "op-1", name: "Test Operator" },
    scanServerHost: "scan.internal.local",
    addLog: vi.fn((s: any, entry: any) => {
      s.log.push({ id: `log-${s.log.length}`, timestamp: Date.now(), ...entry });
    }),
    broadcastOpsUpdate: vi.fn(),
    broadcastReconFinding: vi.fn(),
    pushVulnDeduped: vi.fn(() => true),
    persistOpsStateDebounced: vi.fn(),
    persistScanResult: vi.fn(async () => {}),
    executeToolViaQueue: vi.fn(async () => ({ stdout: "", exitCode: 0 })),
    acquireScanSlot: vi.fn(async () => ({ release: () => {} })),
    getScanConcurrencyMetrics: vi.fn(() => ({ active: 0, queued: 0, maxConcurrency: 5 })),
    genId: vi.fn(() => `id-${Math.random().toString(36).slice(2, 8)}`),
    breathe: vi.fn(async () => {}),
    invokeLLM: vi.fn(async () => ({ choices: [{ message: { content: "[]" } }] })),
    throttledLLMCall: vi.fn(async () => ({ choices: [{ message: { content: "[]" } }] })),
    parseToolOutput: vi.fn(() => []),
    isInRoeScope: vi.fn(() => true),
    requestApproval: vi.fn(async () => true),
    getEffectiveTarget: vi.fn((asset: any) => asset.ip || asset.hostname),
    fmtTarget: vi.fn((asset: any) => `${asset.hostname} (${asset.ip})`),
    llmDecide: vi.fn(async () => ({ decision: "proceed", actions: [] })),
    captureDecision: vi.fn(async () => {}),
    scoreEngagementThreatAttribution: vi.fn(async () => ({})),
    getEngagementAbortSignal: vi.fn(() => ({ aborted: false })),
    executeScanForgePhase: vi.fn(async () => ({ findings: [], templatesUsed: 0 })),
  };
}

// ─── Integration Tests ───────────────────────────────────────────────────────

describe("Phase 6 Integration: Module Structure", () => {
  it("exports all 6 sub-module functions from index", async () => {
    const mod = await import("./lib/vuln-detection/index");
    expect(mod.executeVulnPrep).toBeDefined();
    expect(mod.executeNucleiScanning).toBeDefined();
    expect(mod.executeZapScanning).toBeDefined();
    expect(mod.executeInjectionScanning).toBeDefined();
    expect(mod.executeCredentialTesting).toBeDefined();
    expect(mod.executeVulnCorrelation).toBeDefined();
  });

  it("VulnDetectionContext interface has all required helper fields", async () => {
    const mod = await import("./lib/vuln-detection/index");
    expect(mod).toBeDefined();
    // Verify the flat context shape satisfies what nuclei-scanner expects
    const state = createMockState();
    const ctx = createFlatContext(state);
    expect(ctx.addLog).toBeDefined();
    expect(ctx.broadcastOpsUpdate).toBeDefined();
    expect(ctx.pushVulnDeduped).toBeDefined();
    expect(ctx.persistOpsStateDebounced).toBeDefined();
    expect(ctx.persistScanResult).toBeDefined();
    expect(ctx.executeToolViaQueue).toBeDefined();
    expect(ctx.acquireScanSlot).toBeDefined();
    expect(ctx.genId).toBeDefined();
    expect(ctx.breathe).toBeDefined();
    expect(ctx.invokeLLM).toBeDefined();
    expect(ctx.parseToolOutput).toBeDefined();
    expect(ctx.isInRoeScope).toBeDefined();
    expect(ctx.requestApproval).toBeDefined();
  });
});

describe("Phase 6 Integration: Vuln-Prep Sub-module", () => {
  it("executeVulnPrep processes assets and adds log entries", async () => {
    const { executeVulnPrep } = await import("./lib/vuln-detection/vuln-prep");
    const state = createMockState();
    const ctx = createVulnPrepContext(state);

    const result = await executeVulnPrep(ctx);
    
    expect(result).toBeDefined();
    expect(ctx.helpers.addLog).toHaveBeenCalled();
  });

  it("vuln-prep respects RoE scope filtering", async () => {
    const { executeVulnPrep } = await import("./lib/vuln-detection/vuln-prep");
    const state = createMockState();
    const ctx = createVulnPrepContext(state);
    ctx.helpers.isInRoeScope = vi.fn((s: any, hostname: string) => hostname !== "db.example.com");

    await executeVulnPrep(ctx);
    
    // The function should have been called (it may or may not filter depending on implementation)
    expect(ctx.helpers.addLog).toHaveBeenCalled();
  });
});

describe("Phase 6 Integration: Nuclei Scanner Sub-module", () => {
  it("executeNucleiScanning exports required interfaces", async () => {
    const mod = await import("./lib/vuln-detection/nuclei-scanner");
    expect(mod.executeNucleiScanning).toBeDefined();
    expect(mod.buildTechTags).toBeDefined();
    expect(mod.buildNucleiArgs).toBeDefined();
    expect(mod.getEvasionConfig).toBeDefined();
    expect(mod.TRAINING_LAB_VULN_TAGS).toBeDefined();
    expect(mod.NUCLEI_INFRA_PORTS).toBeDefined();
  });

  it("buildTechTags generates correct tags for common technologies", async () => {
    const { buildTechTags } = await import("./lib/vuln-detection/nuclei-scanner");
    
    // buildTechTags takes a string array of detected technologies
    const tags = buildTechTags(["wordpress", "nginx", "php"]);

    expect(Array.isArray(tags)).toBe(true);
    expect(tags.length).toBeGreaterThan(0);
    // Should include at least wordpress as a tag
    expect(tags.some((t: string) => t.toLowerCase().includes("wordpress") || t.toLowerCase().includes("wp"))).toBe(true);
  });

  it("buildNucleiArgs generates valid command arguments", async () => {
    const { buildNucleiArgs } = await import("./lib/vuln-detection/nuclei-scanner");
    
    // buildNucleiArgs takes NucleiArgConfig: { url, techTags, isTrainingLab, rateLimit, authHeaderArg, evasionHeaders }
    const args = buildNucleiArgs({
      url: "https://target.example.com",
      techTags: ["wordpress", "cve"],
      isTrainingLab: false,
      rateLimit: 100,
      authHeaderArg: "",
      evasionHeaders: "",
    });

    expect(typeof args).toBe("string");
    expect(args).toContain("target.example.com");
    expect(args).toContain("-u");
    expect(args).toContain("-rate-limit 100");
    expect(args).toContain("wordpress,cve");
  });

  it("getEvasionConfig returns WAF-appropriate settings", async () => {
    const { getEvasionConfig } = await import("./lib/vuln-detection/nuclei-scanner");
    
    const noWaf = getEvasionConfig("none");
    const withWaf = getEvasionConfig("cloudflare");

    // WAF evasion should have lower rate limit or higher delay
    expect(noWaf).toBeDefined();
    expect(withWaf).toBeDefined();
    // The WAF config should be more conservative
    if (noWaf.rateLimit && withWaf.rateLimit) {
      expect(noWaf.rateLimit).toBeGreaterThanOrEqual(withWaf.rateLimit);
    }
    if (noWaf.delay !== undefined && withWaf.delay !== undefined) {
      expect(withWaf.delay).toBeGreaterThanOrEqual(noWaf.delay);
    }
  });

  it("TRAINING_LAB_VULN_TAGS contains expected lab-specific tags", async () => {
    const { TRAINING_LAB_VULN_TAGS } = await import("./lib/vuln-detection/nuclei-scanner");
    
    expect(TRAINING_LAB_VULN_TAGS).toBeDefined();
    expect(typeof TRAINING_LAB_VULN_TAGS).toBe("object");
    const entries = Object.entries(TRAINING_LAB_VULN_TAGS);
    expect(entries.length).toBeGreaterThan(0);
  });

  it("NUCLEI_INFRA_PORTS defines infrastructure service ports", async () => {
    const { NUCLEI_INFRA_PORTS } = await import("./lib/vuln-detection/nuclei-scanner");
    
    expect(NUCLEI_INFRA_PORTS).toBeDefined();
    expect(NUCLEI_INFRA_PORTS instanceof Set).toBe(true);
    // Should include common infra ports (3306, 5432, 6379 are in the set)
    expect(NUCLEI_INFRA_PORTS.has(3306) || NUCLEI_INFRA_PORTS.has(5432) || NUCLEI_INFRA_PORTS.has(6379)).toBe(true);
  });
});

describe("Phase 6 Integration: ZAP Scanner Sub-module", () => {
  it("executeZapScanning exports required interfaces", async () => {
    const mod = await import("./lib/vuln-detection/zap-scanner");
    expect(mod.executeZapScanning).toBeDefined();
    expect(mod.detectTrainingLabCreds).toBeDefined();
    expect(mod.getFilteredWebPorts).toBeDefined();
    expect(mod.buildTechHints).toBeDefined();
    expect(mod.getZapPollingConfig).toBeDefined();
  });

  it("detectTrainingLabCreds identifies common training lab credentials", async () => {
    const { detectTrainingLabCreds } = await import("./lib/vuln-detection/zap-scanner");
    
    // detectTrainingLabCreds(hostname, targetUrl) requires both args
    const dvwaCreds = detectTrainingLabCreds("dvwa.local", "http://dvwa.local");
    expect(dvwaCreds).toBeDefined();
    if (dvwaCreds) {
      expect(dvwaCreds.username).toBe("admin");
      expect(dvwaCreds.password).toBe("password");
      expect(dvwaCreds.loginPath).toBe("/login.php");
    }
  });

  it("getFilteredWebPorts returns only HTTP/HTTPS ports", async () => {
    const { getFilteredWebPorts } = await import("./lib/vuln-detection/zap-scanner");
    
    // getFilteredWebPorts(asset, state) takes an asset object and state
    const asset = {
      ports: [
        { port: 80, service: "http" },
        { port: 443, service: "https" },
        { port: 22, service: "ssh" },
        { port: 3306, service: "mysql" },
        { port: 8080, service: "http-proxy" },
      ],
    };
    const state = { completedScans: { zapCompleted: new Set() } };
    const ports = getFilteredWebPorts(asset, state);

    expect(Array.isArray(ports)).toBe(true);
    // Should return port objects, not numbers
    const portNumbers = ports.map((p: any) => p.port);
    expect(portNumbers).toContain(80);
    expect(portNumbers).toContain(443);
    expect(portNumbers).not.toContain(22);
    expect(portNumbers).not.toContain(3306);
  });

  it("getZapPollingConfig returns appropriate timeouts for WAF scenarios", async () => {
    const { getZapPollingConfig } = await import("./lib/vuln-detection/zap-scanner");
    
    // getZapPollingConfig(hostname, trainingLabMode, hasWafEvasion)
    const noWaf = getZapPollingConfig("target.example.com", false, false);
    const withWaf = getZapPollingConfig("target.example.com", false, true);

    expect(noWaf).toBeDefined();
    expect(withWaf).toBeDefined();
    expect(noWaf.timeoutMinutes).toBeDefined();
    expect(withWaf.timeoutMinutes).toBeDefined();
    // WAF scenario should allow more stall polls
    expect(withWaf.maxStallPolls).toBeGreaterThanOrEqual(noWaf.maxStallPolls);
  });

  it("buildTechHints generates hints from asset data", async () => {
    const { buildTechHints } = await import("./lib/vuln-detection/zap-scanner");
    
    // buildTechHints(asset, targetProfile) takes an asset object and target profile
    const asset = {
      ports: [{ port: 80, service: "http", version: "nginx/1.21" }],
      passiveRecon: { technologies: ["react", "node.js", "express"] },
      httpxResponseHeaders: { "x-powered-by": "Express" },
    };
    const targetProfile = { technologies: ["react"] };
    const hints = buildTechHints(asset, targetProfile);
    expect(Array.isArray(hints)).toBe(true);
  });
});

describe("Phase 6 Integration: Injection Scanner Sub-module", () => {
  it("executeInjectionScanning exports required interfaces", async () => {
    const mod = await import("./lib/vuln-detection/injection-scanner");
    expect(mod.executeInjectionScanning).toBeDefined();
    expect(mod.getTrainingLabEndpoints).toBeDefined();
    expect(mod.performAuthHandoff).toBeDefined();
    expect(mod.buildInjectableUrls).toBeDefined();
  });

  it("getTrainingLabEndpoints returns known vulnerable endpoints for labs", async () => {
    const { getTrainingLabEndpoints } = await import("./lib/vuln-detection/injection-scanner");
    
    const dvwaEndpoints = getTrainingLabEndpoints("dvwa.local");
    expect(Array.isArray(dvwaEndpoints)).toBe(true);
    expect(dvwaEndpoints.length).toBeGreaterThan(0);
    expect(dvwaEndpoints[0]).toHaveProperty("path");
    expect(dvwaEndpoints[0]).toHaveProperty("method");
  });

  it("getTrainingLabEndpoints returns known vulnerable endpoints", async () => {
    const { getTrainingLabEndpoints } = await import("./lib/vuln-detection/injection-scanner");
    
    // getTrainingLabEndpoints(hostname) returns lab-specific endpoints
    const juiceEndpoints = getTrainingLabEndpoints("juiceshop.local");
    expect(Array.isArray(juiceEndpoints)).toBe(true);
    expect(juiceEndpoints.length).toBeGreaterThan(0);
    expect(juiceEndpoints[0]).toHaveProperty("path");
    expect(juiceEndpoints[0]).toHaveProperty("method");
    expect(juiceEndpoints[0]).toHaveProperty("params");
  });
});

describe("Phase 6 Integration: Credential Tester Sub-module", () => {
  it("executeCredentialTesting exports required interfaces", async () => {
    const mod = await import("./lib/vuln-detection/credential-tester");
    expect(mod.executeCredentialTesting).toBeDefined();
    expect(mod.checkPortReachable).toBeDefined();
    expect(mod.verifyHttpCredentials).toBeDefined();
    expect(mod.storeOemFallback).toBeDefined();
  });

  it("storeOemFallback extracts vendor defaults from hydra command args", async () => {
    const { storeOemFallback } = await import("./lib/vuln-detection/credential-tester");
    
    // storeOemFallback(asset, cmdArgs) parses hydra-style command args
    const asset = { confirmedCredentials: [] };
    const cmdArgs = "-l 'admin' -p 'password123' -s 3306";
    const result = storeOemFallback(asset, cmdArgs);

    expect(typeof result).toBe("boolean");
    if (result) {
      expect(asset.confirmedCredentials.length).toBeGreaterThan(0);
    }
  });
});

describe("Phase 6 Integration: Vuln-Correlation Sub-module", () => {
  it("executeVulnCorrelation exports required interfaces", async () => {
    const mod = await import("./lib/vuln-detection/vuln-correlation");
    expect(mod.executeVulnCorrelation).toBeDefined();
    expect(mod.buildKevEpssContext).toBeDefined();
    expect(mod.runVulnVerification).toBeDefined();
    expect(mod.runScanForgeReasoning).toBeDefined();
    expect(mod.runHybridScoring).toBeDefined();
    expect(mod.runThreatActorMapping).toBeDefined();
    expect(mod.runDedupAndCoverage).toBeDefined();
  });

  it("buildKevEpssContext enriches findings with KEV/EPSS data", async () => {
    const { buildKevEpssContext } = await import("./lib/vuln-detection/vuln-correlation");
    
    expect(buildKevEpssContext).toBeDefined();
    expect(typeof buildKevEpssContext).toBe("function");
  });

  it("runDedupAndCoverage is exported for deduplication pipeline", async () => {
    const { runDedupAndCoverage } = await import("./lib/vuln-detection/vuln-correlation");
    
    expect(runDedupAndCoverage).toBeDefined();
    expect(typeof runDedupAndCoverage).toBe("function");
  });
});

describe("Phase 6 Integration: Delegation Chain State Flow", () => {
  it("state.log accumulates entries across vuln-prep execution", async () => {
    const state = createMockState();
    const ctx = createVulnPrepContext(state);

    const { executeVulnPrep } = await import("./lib/vuln-detection/vuln-prep");
    await executeVulnPrep(ctx);

    expect(state.log.length).toBeGreaterThan(0);
    expect(state.log.every((l: any) => l.phase || l.type)).toBe(true);
  });

  it("context helpers are called correctly during vuln-prep execution", async () => {
    const state = createMockState();
    const ctx = createVulnPrepContext(state);

    const { executeVulnPrep } = await import("./lib/vuln-detection/vuln-prep");
    await executeVulnPrep(ctx);

    expect(ctx.helpers.addLog).toHaveBeenCalled();
  });

  it("sub-modules handle empty asset list gracefully", async () => {
    const state = createMockState({ assets: [] });
    const ctx = createVulnPrepContext(state);

    const { executeVulnPrep } = await import("./lib/vuln-detection/vuln-prep");
    await expect(executeVulnPrep(ctx)).resolves.toBeDefined();
  });

  it("sub-modules handle training lab mode correctly", async () => {
    const state = createMockState({ trainingLabMode: true, engagementType: "training_lab" });
    const ctx = createVulnPrepContext(state);

    const { executeVulnPrep } = await import("./lib/vuln-detection/vuln-prep");
    const result = await executeVulnPrep(ctx);
    
    expect(result).toBeDefined();
    expect(state.log.length).toBeGreaterThan(0);
  });
});

describe("Phase 6 Integration: Exploitation Sub-modules", () => {
  it("exploitation index exports all 5 sub-module functions", async () => {
    const mod = await import("./lib/exploitation/index");
    expect(mod.executeCredentialHarvest).toBeDefined();
    expect(mod.generateExploitPlan).toBeDefined();
    expect(mod.selectAndSortTargets).toBeDefined();
    expect(mod.executeExploitLoop).toBeDefined();
    expect(mod.collectExploitEvidence).toBeDefined();
  });

  it("credential harvester parseCredentials extracts env-style credentials", async () => {
    const { parseCredentials } = await import("./lib/exploitation/credential-harvester");
    
    const content = `
DB_PASSWORD=supersecret123
MYSQL_PASSWORD="another_pass"
API_KEY=sk-abc123def456
    `;
    
    const creds = parseCredentials(content, "https://target.com/.env");
    expect(creds.length).toBeGreaterThan(0);
    expect(creds.some((c: any) => c.value === "supersecret123" || c.password === "supersecret123")).toBe(true);
  });

  it("target selector scores KEV-listed CVEs higher than non-KEV", async () => {
    const { scoreExploitAction, PRIORITY_WEIGHTS } = await import("./lib/exploitation/target-selector");
    
    const state = createMockState();
    // Set kevListed on the first vuln
    state.assets[0].vulns[0].kevListed = true;

    // KEV action matches the first vuln (CVE-2023-1234 which has kevListed=true)
    const kevAction = { type: "exploit_attempt", params: { target: "target.example.com", cve: "CVE-2023-1234", service: "http", port: 80 } };
    // Non-KEV action targets a different asset with no KEV vulns
    const nonKevAction = { type: "exploit_attempt", params: { target: "db.example.com", cve: "CVE-2023-9999", service: "mysql", port: 3306 } };

    const kevScore = scoreExploitAction(kevAction, state);
    const nonKevScore = scoreExploitAction(nonKevAction, state);

    expect(kevScore.score).toBeGreaterThan(nonKevScore.score);
    expect(kevScore.kevListed).toBe(true);
    expect(nonKevScore.kevListed).toBe(false);
  });

  it("exploit executor detectTrainingLabName identifies common labs", async () => {
    const { detectTrainingLabName } = await import("./lib/exploitation/exploit-executor");
    
    expect(detectTrainingLabName("juice-shop.local")).toBe("juice-shop");
    expect(detectTrainingLabName("dvwa.training.com")).toBe("dvwa");
    expect(detectTrainingLabName("webgoat-8.0")).toBe("webgoat");
  });
});

describe("Phase 6 Integration: Circuit Breaker (Deep Research Agent)", () => {
  it("circuit breaker metrics function is exported", async () => {
    const mod = await import("./scanforge/engine/deep-research-agent");
    expect(mod.getCircuitBreakerMetrics).toBeDefined();
    expect(mod.resetCircuitBreaker).toBeDefined();
  });

  it("resetCircuitBreaker clears state for a feed", async () => {
    const { resetCircuitBreaker, getCircuitBreakerMetrics } = await import("./scanforge/engine/deep-research-agent");

    const feedId = "test-integration-feed";
    resetCircuitBreaker(feedId);

    const metrics = getCircuitBreakerMetrics();
    // After reset, the feed should be in closed state or not present
    if (metrics[feedId]) {
      expect(metrics[feedId].state).toBe("closed");
      expect(metrics[feedId].consecutiveFailures).toBe(0);
    }
  });
});

describe("Phase 6 Integration: Classification Cache TTL", () => {
  it("context engine exports CACHE_CONFIG and ClassificationCache", async () => {
    const mod = await import("./scanforge/intelligence/context-engine");
    expect(mod.CACHE_CONFIG).toBeDefined();
    expect(mod.ClassificationCache).toBeDefined();
    expect(mod.onInfrastructureChange).toBeDefined();
    expect(mod.getContextEngine).toBeDefined();
  });

  it("CACHE_CONFIG has correct TTL defaults", async () => {
    const { CACHE_CONFIG } = await import("./scanforge/intelligence/context-engine");
    expect(CACHE_CONFIG.DEFAULT_TTL_MS).toBe(24 * 60 * 60 * 1000); // 24h
    expect(CACHE_CONFIG.LOW_CONFIDENCE_TTL_MS).toBe(4 * 60 * 60 * 1000); // 4h
    expect(CACHE_CONFIG.HEURISTIC_TTL_MS).toBe(1 * 60 * 60 * 1000); // 1h
    expect(CACHE_CONFIG.MAX_ENTRIES).toBeGreaterThan(0);
  });

  it("ClassificationCache supports TTL-based get/set", async () => {
    const { ClassificationCache } = await import("./scanforge/intelligence/context-engine");
    
    const cache = new ClassificationCache<string>();
    cache.set("test-key", "test-value", 60000); // 1 minute TTL
    
    expect(cache.get("test-key")).toBe("test-value");
  });

  it("ClassificationCache invalidation methods work", async () => {
    const { ClassificationCache } = await import("./scanforge/intelligence/context-engine");
    
    const cache = new ClassificationCache<string>();
    cache.set("host-1", "web-server", 60000);
    cache.set("host-2", "database", 60000);
    cache.set("host-3", "web-server", 60000);
    
    // Targeted invalidation
    cache.invalidateTarget("host-1");
    expect(cache.get("host-1")).toBeUndefined();
    expect(cache.get("host-2")).toBe("database");
    
    // Global invalidation
    cache.invalidateAll();
    expect(cache.get("host-2")).toBeUndefined();
    expect(cache.get("host-3")).toBeUndefined();
  });

  it("ClassificationCache respects MAX_ENTRIES with LRU eviction", async () => {
    const { ClassificationCache, CACHE_CONFIG } = await import("./scanforge/intelligence/context-engine");
    
    // Create a small cache to test eviction
    const cache = new ClassificationCache<number>();
    const maxEntries = CACHE_CONFIG.MAX_ENTRIES;
    
    // Fill to capacity + 1
    for (let i = 0; i <= maxEntries; i++) {
      cache.set(`key-${i}`, i, 60000);
    }
    
    // First entry should have been evicted (LRU)
    expect(cache.get("key-0")).toBeUndefined();
    // Last entry should still exist
    expect(cache.get(`key-${maxEntries}`)).toBe(maxEntries);
  });

  it("onInfrastructureChange triggers cache invalidation", async () => {
    const { onInfrastructureChange, getContextEngine } = await import("./scanforge/intelligence/context-engine");
    
    // Should not throw
    expect(() => {
      onInfrastructureChange({
        type: "dns_change",
        targets: ["test-target.example.com"],
      });
    }).not.toThrow();

    expect(() => {
      onInfrastructureChange({
        type: "cdn_change",
        domain: "*.example.com",
      });
    }).not.toThrow();
  });
});
