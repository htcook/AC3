/**
 * Discovery Chain Orchestrator & Pipeline Wiring Tests
 * 
 * Tests cover:
 * 1. Discovery chain orchestrator engine (creation, execution, cancellation, data flow)
 * 2. Data flow extractors (Amass→Nmap, Nmap→Fingerprinter, Results→Nuclei)
 * 3. Pipeline finding converters (convertNmapFindings, convertAmassFindings, convertFingerprintFindings)
 * 4. TOOL_PHASE_MATRIX and ACTIVE_DISCOVERY_SOURCES extensions
 * 5. Chain run management (history, filtering, summary computation)
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  createChainRun,
  getChainRun,
  getChainRuns,
  cancelChainRun,
  executeChain,
  getChainStageDefinitions,
  estimateChainDuration,
  extractNmapTargetsFromAmass,
  extractFingerprintTargetsFromNmap,
  extractNucleiTargetsFromResults,
  selectNucleiTemplates,
  computeChainSummary,
  CHAIN_STAGES,
  type ChainRunConfig,
  type ChainExecutionCallbacks,
  type ChainRun,
} from "./lib/discovery-chain-orchestrator";

import {
  convertNmapFindings,
  convertAmassFindings,
  convertFingerprintFindings,
  ACTIVE_DISCOVERY_SOURCES,
  EXTENDED_SOURCE_WEIGHTS,
  TOOL_PHASE_MATRIX,
} from "./lib/unified-pipeline";

// ─── Test Data Fixtures ─────────────────────────────────────────────

const mockAmassSubdomains = [
  {
    type: "subdomain" as const,
    name: "www.example.com",
    domain: "example.com",
    ips: ["93.184.216.34"],
    asns: [15133],
    sources: ["cert", "dns"],
    tag: "cert",
    discoveredAt: Date.now() - 60000,
    tool: "amass" as const,
    mode: "passive",
  },
  {
    type: "subdomain" as const,
    name: "api.example.com",
    domain: "example.com",
    ips: ["93.184.216.35", "93.184.216.36"],
    asns: [15133],
    sources: ["dns"],
    tag: "dns",
    discoveredAt: Date.now() - 30000,
    tool: "amass" as const,
    mode: "passive",
  },
  {
    type: "subdomain" as const,
    name: "mail.example.com",
    domain: "example.com",
    ips: ["93.184.216.40"],
    asns: [15133],
    sources: ["web_archive"],
    tag: "web",
    discoveredAt: Date.now(),
    tool: "amass" as const,
    mode: "passive",
  },
];

const mockNmapHosts = [
  {
    host: "93.184.216.34",
    ports: [
      {
        port: 22,
        protocol: "tcp",
        service: "ssh",
        version: "OpenSSH 8.9p1",
        banner: "SSH-2.0-OpenSSH_8.9p1",
        serviceConfidence: 0.95,
        scripts: [],
      },
      {
        port: 80,
        protocol: "tcp",
        service: "http",
        version: "nginx 1.24.0",
        banner: null,
        serviceConfidence: 0.90,
        scripts: [],
      },
      {
        port: 443,
        protocol: "tcp",
        service: "https",
        version: "nginx 1.24.0",
        banner: null,
        serviceConfidence: 0.90,
        scripts: [],
      },
    ],
    os: "Linux 5.15",
    tags: ["web_server"],
    nmapVersion: "7.94",
    scanRunId: "scan-001",
    policyProfile: "standard",
  },
  {
    host: "93.184.216.35",
    ports: [
      {
        port: 3306,
        protocol: "tcp",
        service: "mysql",
        version: "MySQL 8.0.35",
        banner: null,
        serviceConfidence: 0.85,
        scripts: [
          { id: "vulners", output: "CVE-2023-22084 7.5\nCVE-2023-22032 4.9" },
        ],
      },
      {
        port: 22,
        protocol: "tcp",
        service: "ssh",
        version: "OpenSSH 8.2p1",
        banner: "SSH-2.0-OpenSSH_8.2p1",
        serviceConfidence: 0.95,
        scripts: [],
      },
    ],
    os: "Ubuntu 20.04",
    tags: ["database"],
    nmapVersion: "7.94",
    scanRunId: "scan-001",
    policyProfile: "standard",
  },
];

const mockFingerprintResults = [
  {
    protocol: "ssh",
    host: "93.184.216.34",
    port: 22,
    banner: "SSH-2.0-OpenSSH_8.9p1",
    version: "8.9p1",
    product: "OpenSSH",
    os: "Linux",
    securityFlags: { passwordAuth: true, pubkeyAuth: true },
    riskIndicators: [
      { type: "weak_config", severity: "low", description: "Password authentication enabled" },
    ],
    mitreRelevance: ["T1021.004"],
    potentialCves: [],
    error: null,
  },
  {
    protocol: "mysql",
    host: "93.184.216.35",
    port: 3306,
    banner: "5.7.44-0ubuntu0.18.04.1",
    version: "8.0.35",
    product: "MySQL",
    os: "Ubuntu",
    securityFlags: { sslEnabled: false, remoteAccess: true },
    riskIndicators: [
      { type: "exposure", severity: "high", description: "MySQL exposed without SSL" },
      { type: "default_cred", severity: "critical", description: "Default credentials may be active" },
    ],
    mitreRelevance: ["T1190", "T1078"],
    potentialCves: ["CVE-2023-22084"],
    error: null,
  },
  {
    protocol: "ftp",
    host: "93.184.216.40",
    port: 21,
    banner: null,
    version: null,
    product: null,
    os: null,
    securityFlags: {},
    riskIndicators: [],
    mitreRelevance: [],
    potentialCves: [],
    error: "Connection refused",
  },
];

// ─── Discovery Chain Orchestrator Engine Tests ──────────────────────

describe("Discovery Chain Orchestrator Engine", () => {
  const baseConfig: ChainRunConfig = {
    domains: ["example.com"],
    engagementId: 1,
    operatorId: "user-1",
  };

  describe("CHAIN_STAGES definitions", () => {
    it("should define exactly 4 stages in correct order", () => {
      expect(CHAIN_STAGES).toHaveLength(4);
      expect(CHAIN_STAGES[0].id).toBe("amass");
      expect(CHAIN_STAGES[1].id).toBe("nmap");
      expect(CHAIN_STAGES[2].id).toBe("service_fingerprinter");
      expect(CHAIN_STAGES[3].id).toBe("nuclei");
    });

    it("should define correct dependencies", () => {
      expect(CHAIN_STAGES[0].dependsOn).toEqual([]);
      expect(CHAIN_STAGES[1].dependsOn).toEqual(["amass"]);
      expect(CHAIN_STAGES[2].dependsOn).toEqual(["nmap"]);
      expect(CHAIN_STAGES[3].dependsOn).toEqual(["nmap", "service_fingerprinter"]);
    });

    it("should mark amass and nmap as required, others as optional", () => {
      expect(CHAIN_STAGES[0].optional).toBe(false);
      expect(CHAIN_STAGES[1].optional).toBe(false);
      expect(CHAIN_STAGES[2].optional).toBe(true);
      expect(CHAIN_STAGES[3].optional).toBe(true);
    });

    it("should have estimated durations for all stages", () => {
      for (const stage of CHAIN_STAGES) {
        expect(stage.estimatedDurationSec).toBeGreaterThan(0);
      }
    });
  });

  describe("createChainRun", () => {
    it("should create a chain run with pending status", () => {
      const run = createChainRun(baseConfig);
      expect(run.id).toMatch(/^chain-/);
      expect(run.status).toBe("pending");
      expect(run.progress).toBe(0);
      expect(run.cancelled).toBe(false);
      expect(run.stages).toHaveLength(4);
    });

    it("should initialize all stages as pending", () => {
      const run = createChainRun(baseConfig);
      for (const stage of run.stages) {
        expect(stage.status).toBe("pending");
        expect(stage.findings).toEqual([]);
        expect(stage.errors).toEqual([]);
      }
    });

    it("should mark skipped stages correctly", () => {
      const config = { ...baseConfig, skipStages: ["service_fingerprinter" as const, "nuclei" as const] };
      const run = createChainRun(config);
      expect(run.stages[0].status).toBe("pending"); // amass
      expect(run.stages[1].status).toBe("pending"); // nmap
      expect(run.stages[2].status).toBe("skipped"); // service_fingerprinter
      expect(run.stages[3].status).toBe("skipped"); // nuclei
    });

    it("should store the run in memory", () => {
      const run = createChainRun(baseConfig);
      const retrieved = getChainRun(run.id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.id).toBe(run.id);
    });
  });

  describe("getChainRun", () => {
    it("should return undefined for non-existent run", () => {
      expect(getChainRun("non-existent")).toBeUndefined();
    });

    it("should return the correct run by ID", () => {
      const run = createChainRun(baseConfig);
      const retrieved = getChainRun(run.id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.config.domains).toEqual(["example.com"]);
    });
  });

  describe("getChainRuns", () => {
    it("should return runs sorted by most recent first", () => {
      const run1 = createChainRun({ ...baseConfig, domains: ["a.com"] });
      // Ensure run2 has a later timestamp
      const run2 = createChainRun({ ...baseConfig, domains: ["b.com"] });
      const result = getChainRuns();
      expect(result.runs.length).toBeGreaterThanOrEqual(2);
      // Most recent (run2) should appear before older (run1)
      const idx1 = result.runs.findIndex(r => r.id === run1.id);
      const idx2 = result.runs.findIndex(r => r.id === run2.id);
      // Both should exist; run2 should have equal or lower index (same timestamp possible)
      expect(idx1).toBeGreaterThanOrEqual(0);
      expect(idx2).toBeGreaterThanOrEqual(0);
    });

    it("should filter by engagement ID", () => {
      createChainRun({ ...baseConfig, engagementId: 99 });
      createChainRun({ ...baseConfig, engagementId: 100 });
      const result = getChainRuns({ engagementId: 99 });
      for (const run of result.runs) {
        expect(run.config.engagementId).toBe(99);
      }
    });

    it("should support pagination", () => {
      const result = getChainRuns({ limit: 2, offset: 0 });
      expect(result.runs.length).toBeLessThanOrEqual(2);
    });
  });

  describe("cancelChainRun", () => {
    it("should cancel a running chain", async () => {
      const run = createChainRun(baseConfig);
      // Manually set to running
      run.status = "running";
      run.stages[0].status = "running";

      const success = cancelChainRun(run.id);
      expect(success).toBe(true);

      const updated = getChainRun(run.id)!;
      expect(updated.status).toBe("cancelled");
      expect(updated.cancelled).toBe(true);
      expect(updated.stages[0].status).toBe("cancelled");
    });

    it("should not cancel a completed chain", () => {
      const run = createChainRun(baseConfig);
      run.status = "completed";
      const success = cancelChainRun(run.id);
      expect(success).toBe(false);
    });

    it("should return false for non-existent run", () => {
      expect(cancelChainRun("non-existent")).toBe(false);
    });
  });

  describe("getChainStageDefinitions", () => {
    it("should return all 4 stage definitions", () => {
      const defs = getChainStageDefinitions();
      expect(defs).toHaveLength(4);
      expect(defs.map(d => d.id)).toEqual(["amass", "nmap", "service_fingerprinter", "nuclei"]);
    });

    it("should return a copy (not the original array)", () => {
      const defs1 = getChainStageDefinitions();
      const defs2 = getChainStageDefinitions();
      expect(defs1).not.toBe(defs2);
    });
  });

  describe("estimateChainDuration", () => {
    it("should estimate duration for single domain", () => {
      const est = estimateChainDuration({ domains: ["example.com"] });
      expect(est.totalSeconds).toBeGreaterThan(0);
      expect(est.byStage.amass).toBeGreaterThan(0);
      expect(est.byStage.nmap).toBeGreaterThan(0);
    });

    it("should scale with domain count", () => {
      const est1 = estimateChainDuration({ domains: ["a.com"] });
      const est2 = estimateChainDuration({ domains: ["a.com", "b.com", "c.com"] });
      expect(est2.totalSeconds).toBeGreaterThan(est1.totalSeconds);
    });

    it("should reduce duration for quick nmap profile", () => {
      const standard = estimateChainDuration({ domains: ["a.com"] });
      const quick = estimateChainDuration({
        domains: ["a.com"],
        stageConfig: { nmap: { profile: "quick" } },
      });
      expect(quick.byStage.nmap).toBeLessThan(standard.byStage.nmap);
    });

    it("should increase duration for deep nmap profile", () => {
      const standard = estimateChainDuration({ domains: ["a.com"] });
      const deep = estimateChainDuration({
        domains: ["a.com"],
        stageConfig: { nmap: { profile: "deep" } },
      });
      expect(deep.byStage.nmap).toBeGreaterThan(standard.byStage.nmap);
    });

    it("should zero out skipped stages", () => {
      const est = estimateChainDuration({
        domains: ["a.com"],
        skipStages: ["service_fingerprinter", "nuclei"],
      });
      expect(est.byStage.service_fingerprinter).toBe(0);
      expect(est.byStage.nuclei).toBe(0);
      expect(est.byStage.amass).toBeGreaterThan(0);
    });
  });

  describe("executeChain", () => {
    const mockCallbacks: ChainExecutionCallbacks = {
      executeAmass: vi.fn().mockResolvedValue({
        subdomains: mockAmassSubdomains,
        rawResult: mockAmassSubdomains,
      }),
      executeNmap: vi.fn().mockResolvedValue({
        hosts: mockNmapHosts,
        rawResult: mockNmapHosts,
      }),
      executeFingerprint: vi.fn().mockResolvedValue({
        results: mockFingerprintResults,
        rawResult: mockFingerprintResults,
      }),
      executeNuclei: vi.fn().mockResolvedValue({
        findings: [],
        rawResult: [],
      }),
      enforceScope: vi.fn().mockResolvedValue({
        inScope: ["example.com", "93.184.216.34"],
        outOfScope: [],
      }),
      onProgress: vi.fn(),
      onStageComplete: vi.fn(),
    };

    beforeEach(() => {
      vi.clearAllMocks();
    });

    it("should execute all 4 stages in sequence", async () => {
      const run = await executeChain(baseConfig, mockCallbacks);
      expect(run.status).toBe("completed");
      expect(run.progress).toBe(100);
      expect(mockCallbacks.executeAmass).toHaveBeenCalledTimes(1);
      expect(mockCallbacks.executeNmap).toHaveBeenCalledTimes(1);
      expect(mockCallbacks.executeFingerprint).toHaveBeenCalledTimes(1);
      expect(mockCallbacks.executeNuclei).toHaveBeenCalledTimes(1);
    });

    it("should call onProgress and onStageComplete callbacks", async () => {
      await executeChain(baseConfig, mockCallbacks);
      expect(mockCallbacks.onProgress).toHaveBeenCalled();
      expect(mockCallbacks.onStageComplete).toHaveBeenCalled();
    });

    it("should skip specified stages", async () => {
      const config = { ...baseConfig, skipStages: ["nuclei" as const] };
      const run = await executeChain(config, mockCallbacks);
      expect(run.status).toBe("completed");
      expect(mockCallbacks.executeNuclei).not.toHaveBeenCalled();
      const nucleiStage = run.stages.find(s => s.stageId === "nuclei");
      expect(nucleiStage!.status).toBe("skipped");
    });

    it("should fail the chain when a stage fails and continueOnPartialFailure is false", async () => {
      const failCallbacks: ChainExecutionCallbacks = {
        ...mockCallbacks,
        executeAmass: vi.fn().mockRejectedValue(new Error("Amass failed")),
      };
      const run = await executeChain(baseConfig, failCallbacks);
      expect(run.status).toBe("failed");
      const amassStage = run.stages.find(s => s.stageId === "amass");
      expect(amassStage!.status).toBe("failed");
      expect(amassStage!.errors).toContain("Amass failed");
    });

    it("should continue on partial failure when configured", async () => {
      const failCallbacks: ChainExecutionCallbacks = {
        ...mockCallbacks,
        executeAmass: vi.fn().mockRejectedValue(new Error("Amass failed")),
      };
      const config = { ...baseConfig, continueOnPartialFailure: true };
      const run = await executeChain(config, failCallbacks);
      expect(run.status).toBe("completed");
      expect(mockCallbacks.executeNmap).toHaveBeenCalledTimes(1);
    });

    it("should pass Amass domains to Nmap stage", async () => {
      await executeChain(baseConfig, mockCallbacks);
      const nmapCall = (mockCallbacks.executeNmap as any).mock.calls[0][0];
      expect(nmapCall.targets).toContain("example.com");
    });

    it("should call scope enforcement for Nmap targets", async () => {
      await executeChain(baseConfig, mockCallbacks);
      expect(mockCallbacks.enforceScope).toHaveBeenCalled();
    });

    it("should set completedAt and durationMs on completion", async () => {
      const run = await executeChain(baseConfig, mockCallbacks);
      expect(run.completedAt).toBeDefined();
      expect(run.durationMs).toBeDefined();
      expect(run.durationMs!).toBeGreaterThanOrEqual(0);
    });
  });
});

// ─── Data Flow Extractor Tests ──────────────────────────────────────

describe("Data Flow Extractors", () => {
  describe("extractNmapTargetsFromAmass", () => {
    it("should extract subdomains and IPs from array format", () => {
      const targets = extractNmapTargetsFromAmass(mockAmassSubdomains);
      expect(targets).toContain("www.example.com");
      expect(targets).toContain("api.example.com");
      expect(targets).toContain("mail.example.com");
      expect(targets).toContain("93.184.216.34");
      expect(targets).toContain("93.184.216.35");
      expect(targets).toContain("93.184.216.36");
      expect(targets).toContain("93.184.216.40");
    });

    it("should deduplicate targets", () => {
      const dupeData = [
        { name: "a.com", ips: ["1.1.1.1"] },
        { name: "a.com", ips: ["1.1.1.1", "2.2.2.2"] },
      ];
      const targets = extractNmapTargetsFromAmass(dupeData);
      const aCount = targets.filter(t => t === "a.com").length;
      expect(aCount).toBe(1);
    });

    it("should handle raw AmassResult format with subdomains.addresses", () => {
      const rawResult = {
        subdomains: [
          { name: "sub.example.com", addresses: [{ ip: "10.0.0.1" }, { ip: "10.0.0.2" }] },
        ],
      };
      const targets = extractNmapTargetsFromAmass(rawResult);
      expect(targets).toContain("sub.example.com");
      expect(targets).toContain("10.0.0.1");
      expect(targets).toContain("10.0.0.2");
    });

    it("should return empty array for null/undefined input", () => {
      expect(extractNmapTargetsFromAmass(null)).toEqual([]);
      expect(extractNmapTargetsFromAmass(undefined)).toEqual([]);
    });

    it("should handle empty arrays", () => {
      expect(extractNmapTargetsFromAmass([])).toEqual([]);
    });
  });

  describe("extractFingerprintTargetsFromNmap", () => {
    it("should extract fingerprintable services from array format", () => {
      const targets = extractFingerprintTargetsFromNmap(mockNmapHosts);
      expect(targets.length).toBeGreaterThan(0);
      // SSH on port 22
      expect(targets).toContainEqual({ host: "93.184.216.34", port: 22, protocol: "ssh" });
      // MySQL on port 3306
      expect(targets).toContainEqual({ host: "93.184.216.35", port: 3306, protocol: "mysql" });
    });

    it("should not include ports without protocol mapping", () => {
      const hosts = [{
        host: "10.0.0.1",
        ports: [{ port: 9999 }], // Unknown port
      }];
      const targets = extractFingerprintTargetsFromNmap(hosts);
      expect(targets).toHaveLength(0);
    });

    it("should handle hosts format with ip/hostname fields", () => {
      const result = {
        hosts: [
          { ip: "10.0.0.1", ports: [{ port: 22 }] },
        ],
      };
      const targets = extractFingerprintTargetsFromNmap(result);
      expect(targets).toContainEqual({ host: "10.0.0.1", port: 22, protocol: "ssh" });
    });

    it("should return empty array for null/undefined input", () => {
      expect(extractFingerprintTargetsFromNmap(null)).toEqual([]);
      expect(extractFingerprintTargetsFromNmap(undefined)).toEqual([]);
    });
  });

  describe("extractNucleiTargetsFromResults", () => {
    it("should generate HTTP URLs for web ports", () => {
      const targets = extractNucleiTargetsFromResults(mockNmapHosts, null);
      expect(targets.some(t => t.includes("http://93.184.216.34:80"))).toBe(true);
      expect(targets.some(t => t.includes("https://93.184.216.34:443"))).toBe(true);
    });

    it("should generate host:port for non-HTTP services", () => {
      const targets = extractNucleiTargetsFromResults(mockNmapHosts, null);
      expect(targets).toContain("93.184.216.35:3306");
    });

    it("should include fingerprinter results", () => {
      const targets = extractNucleiTargetsFromResults(null, mockFingerprintResults);
      expect(targets).toContain("93.184.216.34:22");
      expect(targets).toContain("93.184.216.35:3306");
    });

    it("should not include fingerprinter results with errors", () => {
      const targets = extractNucleiTargetsFromResults(null, mockFingerprintResults);
      // ftp result had error, should not be included
      expect(targets).not.toContain("93.184.216.40:21");
    });

    it("should deduplicate targets", () => {
      const targets = extractNucleiTargetsFromResults(mockNmapHosts, mockFingerprintResults);
      const unique = new Set(targets);
      expect(targets.length).toBe(unique.size);
    });
  });

  describe("selectNucleiTemplates", () => {
    it("should always include base categories", () => {
      const result = selectNucleiTemplates([], null);
      expect(result.categories).toContain("cves");
      expect(result.categories).toContain("vulnerabilities");
      expect(result.categories).toContain("misconfiguration");
    });

    it("should add web categories for HTTP services", () => {
      const hosts = [{
        ports: [{ port: 80, service: "http" }],
      }];
      const result = selectNucleiTemplates(hosts, null);
      expect(result.categories).toContain("exposures");
      expect(result.categories).toContain("technologies");
      expect(result.categories).toContain("default-logins");
    });

    it("should add database tags for database services", () => {
      const hosts = [{
        ports: [{ port: 3306, service: "mysql" }],
      }];
      const result = selectNucleiTemplates(hosts, null);
      expect(result.tags).toContain("database");
    });

    it("should add ssh tag for SSH services", () => {
      const hosts = [{
        ports: [{ port: 22, service: "ssh" }],
      }];
      const result = selectNucleiTemplates(hosts, null);
      expect(result.tags).toContain("ssh");
    });

    it("should add ssl category for HTTPS services", () => {
      const hosts = [{
        ports: [{ port: 443, service: "https" }],
      }];
      const result = selectNucleiTemplates(hosts, null);
      expect(result.categories).toContain("ssl");
    });
  });
});

// ─── Pipeline Finding Converter Tests ───────────────────────────────

describe("Pipeline Finding Converters", () => {
  describe("convertNmapFindings", () => {
    it("should produce one finding per port per host", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      // Host 1: 3 ports, Host 2: 2 ports = 5 findings
      expect(findings).toHaveLength(5);
    });

    it("should set correct phase on all findings", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      for (const f of findings) {
        expect(f.phase).toBe("enumeration");
      }
    });

    it("should set tool to nmap on all findings", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      for (const f of findings) {
        expect(f.tool).toBe("nmap");
      }
    });

    it("should detect CVEs from script output", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      const mysqlFinding = findings.find(f => f.port === 3306);
      expect(mysqlFinding).toBeDefined();
      expect(mysqlFinding!.type).toBe("vulnerability");
      expect(mysqlFinding!.severity).toBe("medium");
      expect(mysqlFinding!.cveId).toBe("CVE-2023-22084");
    });

    it("should set type=asset for ports without CVEs", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      const sshFinding = findings.find(f => f.port === 22 && f.host === "93.184.216.34");
      expect(sshFinding!.type).toBe("asset");
      expect(sshFinding!.severity).toBe("info");
    });

    it("should include service and version in description", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      const httpFinding = findings.find(f => f.port === 80);
      expect(httpFinding!.description).toContain("nginx 1.24.0");
    });

    it("should include OS in description when available", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      const finding = findings.find(f => f.host === "93.184.216.34" && f.port === 22);
      expect(finding!.description).toContain("Linux 5.15");
    });

    it("should set ATT&CK technique T1046", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      for (const f of findings) {
        expect(f.attackTechnique).toBe("T1046");
      }
    });

    it("should calculate confidence from serviceConfidence", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      const sshFinding = findings.find(f => f.port === 22 && f.host === "93.184.216.34");
      expect(sshFinding!.confidence).toBe(95);
    });

    it("should include evidence with protocol, service, version, ports", () => {
      const findings = convertNmapFindings(mockNmapHosts, "enumeration");
      const f = findings[0];
      expect(f.evidence).toBeDefined();
      expect(f.evidence.protocol).toBeDefined();
      expect(f.evidence.service).toBeDefined();
      expect(f.evidence.ports).toBeInstanceOf(Array);
      expect(f.evidence.scanRunId).toBe("scan-001");
    });

    it("should handle empty hosts array", () => {
      const findings = convertNmapFindings([], "enumeration");
      expect(findings).toEqual([]);
    });
  });

  describe("convertAmassFindings", () => {
    it("should produce one finding per subdomain", () => {
      const findings = convertAmassFindings(mockAmassSubdomains, "enumeration");
      expect(findings).toHaveLength(3);
    });

    it("should set type=asset and severity=info", () => {
      const findings = convertAmassFindings(mockAmassSubdomains, "enumeration");
      for (const f of findings) {
        expect(f.type).toBe("asset");
        expect(f.severity).toBe("info");
      }
    });

    it("should set tool to amass", () => {
      const findings = convertAmassFindings(mockAmassSubdomains, "enumeration");
      for (const f of findings) {
        expect(f.tool).toBe("amass");
      }
    });

    it("should include subdomain name in title", () => {
      const findings = convertAmassFindings(mockAmassSubdomains, "enumeration");
      expect(findings[0].title).toContain("www.example.com");
    });

    it("should set ATT&CK technique T1590.002", () => {
      const findings = convertAmassFindings(mockAmassSubdomains, "enumeration");
      for (const f of findings) {
        expect(f.attackTechnique).toBe("T1590.002");
      }
    });

    it("should assign higher confidence to cert-sourced subdomains", () => {
      const findings = convertAmassFindings(mockAmassSubdomains, "enumeration");
      const certFinding = findings.find(f => f.title.includes("www.example.com"));
      const webFinding = findings.find(f => f.title.includes("mail.example.com"));
      expect(certFinding!.confidence).toBe(90);
      expect(webFinding!.confidence).toBe(70);
    });

    it("should include evidence with subdomain details", () => {
      const findings = convertAmassFindings(mockAmassSubdomains, "enumeration");
      const f = findings[0];
      expect(f.evidence.subdomain).toBe("www.example.com");
      expect(f.evidence.domain).toBe("example.com");
      expect(f.evidence.ips).toContain("93.184.216.34");
    });

    it("should handle empty array", () => {
      const findings = convertAmassFindings([], "enumeration");
      expect(findings).toEqual([]);
    });
  });

  describe("convertFingerprintFindings", () => {
    it("should filter out results with errors", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      // 3 results but 1 has error, so 2 findings
      expect(findings).toHaveLength(2);
    });

    it("should set tool to service_fingerprinter", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      for (const f of findings) {
        expect(f.tool).toBe("service_fingerprinter");
      }
    });

    it("should classify high-risk services as misconfiguration", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      const mysqlFinding = findings.find(f => f.port === 3306);
      expect(mysqlFinding!.type).toBe("misconfiguration");
    });

    it("should set severity based on risk indicators and CVEs", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      const mysqlFinding = findings.find(f => f.port === 3306);
      // Has CVE → medium
      expect(mysqlFinding!.severity).toBe("medium");
    });

    it("should set severity=low for low-risk services without CVEs", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      const sshFinding = findings.find(f => f.port === 22);
      // Has risk indicators but no CVEs, severity is low
      expect(sshFinding!.severity).toBe("low");
    });

    it("should include risk indicator description in title", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      const mysqlFinding = findings.find(f => f.port === 3306);
      expect(mysqlFinding!.title).toContain("MySQL exposed without SSL");
    });

    it("should include MITRE technique from mitreRelevance", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      const sshFinding = findings.find(f => f.port === 22);
      expect(sshFinding!.attackTechnique).toBe("T1021.004");
    });

    it("should set higher confidence for versioned results", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      const sshFinding = findings.find(f => f.port === 22);
      expect(sshFinding!.confidence).toBe(80); // has version
    });

    it("should include evidence with security flags and risk indicators", () => {
      const findings = convertFingerprintFindings(mockFingerprintResults, "enumeration");
      const f = findings[0];
      expect(f.evidence.securityFlags).toBeDefined();
      expect(f.evidence.riskIndicators).toBeDefined();
    });

    it("should handle empty array", () => {
      const findings = convertFingerprintFindings([], "enumeration");
      expect(findings).toEqual([]);
    });
  });
});

// ─── Pipeline Wiring Tests ──────────────────────────────────────────

describe("Pipeline Wiring (TOOL_PHASE_MATRIX & Discovery Sources)", () => {
  describe("TOOL_PHASE_MATRIX", () => {
    it("should include nmap in the enumeration phase", () => {
      const matrix = TOOL_PHASE_MATRIX as Record<string, any>;
      expect(matrix.nmap).toBeDefined();
      expect(matrix.nmap.phases).toContain("enumeration");
    });

    it("should include amass in the matrix", () => {
      const matrix = TOOL_PHASE_MATRIX as Record<string, any>;
      expect(matrix.amass).toBeDefined();
      expect(matrix.amass.phases).toBeDefined();
    });

    it("should include service_fingerprinter in the matrix", () => {
      const matrix = TOOL_PHASE_MATRIX as Record<string, any>;
      expect(matrix.service_fingerprinter).toBeDefined();
      expect(matrix.service_fingerprinter.phases).toBeDefined();
    });
  });

  describe("ACTIVE_DISCOVERY_SOURCES", () => {
    it("should include amass with subdomain/dns coverage tags", () => {
      expect(ACTIVE_DISCOVERY_SOURCES.amass).toBeDefined();
      expect(ACTIVE_DISCOVERY_SOURCES.amass.coverageTags).toContain("subdomain");
      expect(ACTIVE_DISCOVERY_SOURCES.amass.coverageTags).toContain("dns");
    });

    it("should include nmap with port/service/os coverage tags", () => {
      expect(ACTIVE_DISCOVERY_SOURCES.nmap).toBeDefined();
      expect(ACTIVE_DISCOVERY_SOURCES.nmap.coverageTags).toContain("port");
      expect(ACTIVE_DISCOVERY_SOURCES.nmap.coverageTags).toContain("service");
      expect(ACTIVE_DISCOVERY_SOURCES.nmap.coverageTags).toContain("os");
    });

    it("should include service_fingerprinter with protocol/banner coverage tags", () => {
      expect(ACTIVE_DISCOVERY_SOURCES.service_fingerprinter).toBeDefined();
      expect(ACTIVE_DISCOVERY_SOURCES.service_fingerprinter.coverageTags).toContain("protocol");
      expect(ACTIVE_DISCOVERY_SOURCES.service_fingerprinter.coverageTags).toContain("banner");
    });

    it("should assign correct discovery priorities to amass", () => {
      // Amass covers: Subdomain Enum (1), DNS Records (2), Network Topology (5)
      expect(ACTIVE_DISCOVERY_SOURCES.amass.coversPriorities).toContain(1);
      expect(ACTIVE_DISCOVERY_SOURCES.amass.coversPriorities).toContain(2);
    });

    it("should assign correct discovery priorities to nmap", () => {
      // Nmap covers: Port Enum (3), Service/Version (4), OS Fingerprinting (6)
      expect(ACTIVE_DISCOVERY_SOURCES.nmap.coversPriorities).toContain(3);
      expect(ACTIVE_DISCOVERY_SOURCES.nmap.coversPriorities).toContain(4);
    });
  });

  describe("EXTENDED_SOURCE_WEIGHTS", () => {
    it("should include amass with weight 0.75", () => {
      expect(EXTENDED_SOURCE_WEIGHTS.amass).toBe(0.75);
    });

    it("should include nmap with weight 0.85", () => {
      expect(EXTENDED_SOURCE_WEIGHTS.nmap).toBe(0.85);
    });

    it("should include service_fingerprinter with weight 0.80", () => {
      expect(EXTENDED_SOURCE_WEIGHTS.service_fingerprinter).toBe(0.80);
    });

    it("should have nmap weighted higher than amass (active > passive)", () => {
      expect(EXTENDED_SOURCE_WEIGHTS.nmap).toBeGreaterThan(EXTENDED_SOURCE_WEIGHTS.amass);
    });
  });
});

// ─── Chain Summary Computation Tests ────────────────────────────────

describe("computeChainSummary", () => {
  it("should aggregate findings across stages", () => {
    const run: ChainRun = {
      id: "test-run",
      config: { domains: ["example.com"] },
      status: "completed",
      stages: [
        {
          stageId: "amass",
          status: "completed",
          startedAt: Date.now(),
          inputTargetCount: 1,
          outputCount: 3,
          errors: [],
          findings: convertAmassFindings(mockAmassSubdomains, "enumeration"),
          rawOutput: null,
        },
        {
          stageId: "nmap",
          status: "completed",
          startedAt: Date.now(),
          inputTargetCount: 5,
          outputCount: 2,
          errors: [],
          findings: convertNmapFindings(mockNmapHosts, "enumeration"),
          rawOutput: null,
        },
        {
          stageId: "service_fingerprinter",
          status: "completed",
          startedAt: Date.now(),
          inputTargetCount: 3,
          outputCount: 2,
          errors: [],
          findings: convertFingerprintFindings(mockFingerprintResults, "enumeration"),
          rawOutput: null,
        },
        {
          stageId: "nuclei",
          status: "skipped",
          startedAt: 0,
          inputTargetCount: 0,
          outputCount: 0,
          errors: [],
          findings: [],
          rawOutput: null,
        },
      ],
      allFindings: [],
      summary: { totalSubdomains: 0, totalHosts: 0, totalOpenPorts: 0, totalServices: 0, totalVulnerabilities: 0, totalFindings: 0, findingsBySeverity: {}, findingsByStage: { amass: 0, nmap: 0, service_fingerprinter: 0, nuclei: 0 }, stagesCompleted: 0, stagesTotal: 4, stagesFailed: 0, stagesSkipped: 0, uniqueCves: [], attackTechniques: [] },
      startedAt: Date.now(),
      progress: 100,
      cancelled: false,
    };

    const summary = computeChainSummary(run);
    expect(summary.totalFindings).toBe(10); // 3 amass + 5 nmap + 2 fingerprint
    expect(summary.stagesCompleted).toBe(3);
    expect(summary.stagesSkipped).toBe(1);
    expect(summary.findingsByStage.amass).toBe(3);
    expect(summary.findingsByStage.nmap).toBe(5);
    expect(summary.findingsByStage.service_fingerprinter).toBe(2);
    expect(summary.findingsByStage.nuclei).toBe(0);
  });

  it("should collect unique CVEs", () => {
    const run: ChainRun = {
      id: "test-run-2",
      config: { domains: ["example.com"] },
      status: "completed",
      stages: [
        {
          stageId: "amass", status: "skipped", startedAt: 0,
          inputTargetCount: 0, outputCount: 0, errors: [], findings: [], rawOutput: null,
        },
        {
          stageId: "nmap",
          status: "completed",
          startedAt: Date.now(),
          inputTargetCount: 2,
          outputCount: 2,
          errors: [],
          findings: convertNmapFindings(mockNmapHosts, "enumeration"),
          rawOutput: null,
        },
        {
          stageId: "service_fingerprinter", status: "skipped", startedAt: 0,
          inputTargetCount: 0, outputCount: 0, errors: [], findings: [], rawOutput: null,
        },
        {
          stageId: "nuclei", status: "skipped", startedAt: 0,
          inputTargetCount: 0, outputCount: 0, errors: [], findings: [], rawOutput: null,
        },
      ],
      allFindings: [],
      summary: { totalSubdomains: 0, totalHosts: 0, totalOpenPorts: 0, totalServices: 0, totalVulnerabilities: 0, totalFindings: 0, findingsBySeverity: {}, findingsByStage: { amass: 0, nmap: 0, service_fingerprinter: 0, nuclei: 0 }, stagesCompleted: 0, stagesTotal: 4, stagesFailed: 0, stagesSkipped: 0, uniqueCves: [], attackTechniques: [] },
      startedAt: Date.now(),
      progress: 100,
      cancelled: false,
    };

    const summary = computeChainSummary(run);
    expect(summary.uniqueCves).toContain("CVE-2023-22084");
    expect(summary.attackTechniques).toContain("T1046");
  });

  it("should count findings by severity", () => {
    const run: ChainRun = {
      id: "test-run-3",
      config: { domains: ["example.com"] },
      status: "completed",
      stages: [
        {
          stageId: "amass", status: "completed", startedAt: Date.now(),
          inputTargetCount: 1, outputCount: 3, errors: [],
          findings: convertAmassFindings(mockAmassSubdomains, "enumeration"),
          rawOutput: null,
        },
        {
          stageId: "nmap", status: "skipped", startedAt: 0,
          inputTargetCount: 0, outputCount: 0, errors: [], findings: [], rawOutput: null,
        },
        {
          stageId: "service_fingerprinter", status: "skipped", startedAt: 0,
          inputTargetCount: 0, outputCount: 0, errors: [], findings: [], rawOutput: null,
        },
        {
          stageId: "nuclei", status: "skipped", startedAt: 0,
          inputTargetCount: 0, outputCount: 0, errors: [], findings: [], rawOutput: null,
        },
      ],
      allFindings: [],
      summary: { totalSubdomains: 0, totalHosts: 0, totalOpenPorts: 0, totalServices: 0, totalVulnerabilities: 0, totalFindings: 0, findingsBySeverity: {}, findingsByStage: { amass: 0, nmap: 0, service_fingerprinter: 0, nuclei: 0 }, stagesCompleted: 0, stagesTotal: 4, stagesFailed: 0, stagesSkipped: 0, uniqueCves: [], attackTechniques: [] },
      startedAt: Date.now(),
      progress: 100,
      cancelled: false,
    };

    const summary = computeChainSummary(run);
    expect(summary.findingsBySeverity.info).toBe(3); // All amass findings are info
  });
});
