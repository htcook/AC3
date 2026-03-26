/**
 * ScanForge Test Suite
 *
 * Tests for the core ScanForge modules:
 *   - Job queue (enqueue, dequeue, priority, concurrency)
 *   - Template engine (load, query, match)
 *   - Protocol registry (register, lookup)
 *   - TI engine (KEV, DFIR, risk scoring)
 *   - AC3 bridge (finding translation)
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { ScanQueue } from "./queue/scan-queue";
import { TemplateEngine } from "./engine/template-engine";
import { ProtocolRegistry } from "./protocols/registry";
import { IntelligenceEngine } from "./intelligence/ti-engine";
import { AC3ScanForgeBridge } from "./bridge/ac3-bridge";
import type {
  ScanRequest,
  ScanTarget,
  ScanFinding,
  ScanTemplate,
  ScanJob,
} from "./types";

// ─── Test Helpers ──────────────────────────────────────────────────────────

function makeScanRequest(overrides?: Partial<ScanRequest>): ScanRequest {
  return {
    id: `test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    type: "full",
    priority: "medium",
    targets: [{ type: "domain", value: "example.com" }],
    config: {},
    createdAt: Date.now(),
    ...overrides,
  };
}

function makeFinding(overrides?: Partial<ScanFinding>): ScanFinding {
  return {
    id: `finding-${Date.now()}`,
    source: "test-scanner",
    title: "Test Finding",
    description: "A test vulnerability finding",
    severity: "high",
    confidence: 85,
    target: "example.com",
    evidence: { matchedPattern: "test-pattern" },
    foundAt: Date.now(),
    ...overrides,
  };
}

function makeTemplate(overrides?: Partial<ScanTemplate>): ScanTemplate {
  return {
    id: "test-template",
    name: "Test Template",
    description: "A test template",
    author: "test",
    severity: "high",
    tags: ["test"],
    protocol: "http",
    matchers: [{ type: "status", values: ["200"] }],
    ...overrides,
  };
}

// ─── Queue Tests ───────────────────────────────────────────────────────────

describe("ScanQueue", () => {
  let queue: ScanQueue;

  beforeEach(() => {
    queue = new ScanQueue({ maxConcurrency: 2, maxQueueDepth: 10, jobTimeoutMs: 60000 });
  });

  it("should enqueue a scan request and return a job", () => {
    const request = makeScanRequest();
    const job = queue.enqueue(request);

    expect(job).toBeDefined();
    expect(job.status).toBe("queued");
    expect(job.request.id).toBe(request.id);
    expect(job.progress).toBe(0);
    expect(job.findings).toEqual([]);
  });

  it("should retrieve a job by scan ID", () => {
    const request = makeScanRequest();
    queue.enqueue(request);

    const job = queue.getJob(request.id);
    expect(job).toBeDefined();
    expect(job!.request.id).toBe(request.id);
  });

  it("should return null for non-existent scan ID", () => {
    const job = queue.getJob("non-existent-id");
    expect(job).toBeNull();
  });

  it("should list all jobs", () => {
    queue.enqueue(makeScanRequest({ id: "scan-1" }));
    queue.enqueue(makeScanRequest({ id: "scan-2" }));
    queue.enqueue(makeScanRequest({ id: "scan-3" }));

    const jobs = queue.getAllJobs();
    expect(jobs.length).toBe(3);
  });

  it("should respect priority ordering (critical before low)", () => {
    queue.enqueue(makeScanRequest({ id: "low-1", priority: "low" }));
    queue.enqueue(makeScanRequest({ id: "critical-1", priority: "critical" }));
    queue.enqueue(makeScanRequest({ id: "high-1", priority: "high" }));

    const status = queue.getStatus();
    expect(status.queued).toBe(3);
  });

  it("should cancel a queued scan", () => {
    const request = makeScanRequest();
    queue.enqueue(request);

    const success = queue.cancel(request.id);
    expect(success).toBe(true);

    const job = queue.getJob(request.id);
    expect(job!.status).toBe("cancelled");
  });

  it("should not cancel a non-existent scan", () => {
    const success = queue.cancel("non-existent");
    expect(success).toBe(false);
  });

  it("should report queue status correctly", () => {
    queue.enqueue(makeScanRequest({ id: "s1" }));
    queue.enqueue(makeScanRequest({ id: "s2" }));

    const status = queue.getStatus();
    expect(status.queued).toBeGreaterThanOrEqual(0);
    expect(status.maxConcurrency).toBe(2);
  });

  it("should reject scans when queue is full", () => {
    const smallQueue = new ScanQueue({ maxConcurrency: 1, maxQueueDepth: 2, jobTimeoutMs: 60000 });
    smallQueue.enqueue(makeScanRequest({ id: "s1" }));
    smallQueue.enqueue(makeScanRequest({ id: "s2" }));

    expect(() => {
      smallQueue.enqueue(makeScanRequest({ id: "s3" }));
    }).toThrow();
  });
});

// ─── Template Engine Tests ─────────────────────────────────────────────────

describe("TemplateEngine", () => {
  let engine: TemplateEngine;

  beforeEach(() => {
    engine = new TemplateEngine();
  });

  it("should register and retrieve a template", () => {
    const template = makeTemplate({ id: "test-1" });
    engine.register(template);

    const retrieved = engine.get("test-1");
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe("test-1");
  });

  it("should query templates by protocol", () => {
    engine.register(makeTemplate({ id: "http-1", protocol: "http" }));
    engine.register(makeTemplate({ id: "ssh-1", protocol: "ssh" }));
    engine.register(makeTemplate({ id: "http-2", protocol: "http" }));

    const httpTemplates = engine.query({ protocol: "http" });
    expect(httpTemplates.length).toBe(2);
  });

  it("should query templates by tags", () => {
    engine.register(makeTemplate({ id: "t1", tags: ["vuln", "xss"] }));
    engine.register(makeTemplate({ id: "t2", tags: ["misconfig"] }));
    engine.register(makeTemplate({ id: "t3", tags: ["vuln", "sqli"] }));

    const vulnTemplates = engine.query({ tags: ["vuln"] });
    expect(vulnTemplates.length).toBe(2);
  });

  it("should query templates by severity", () => {
    engine.register(makeTemplate({ id: "t1", severity: "critical" }));
    engine.register(makeTemplate({ id: "t2", severity: "low" }));
    engine.register(makeTemplate({ id: "t3", severity: "critical" }));

    const criticalTemplates = engine.query({ severity: ["critical"] });
    expect(criticalTemplates.length).toBe(2);
  });

  it("should report correct template count", () => {
    engine.register(makeTemplate({ id: "t1" }));
    engine.register(makeTemplate({ id: "t2" }));

    expect(engine.count).toBe(2);
  });

  it("should not duplicate templates with same ID", () => {
    engine.register(makeTemplate({ id: "t1", name: "First" }));
    engine.register(makeTemplate({ id: "t1", name: "Updated" }));

    expect(engine.count).toBe(1);
    expect(engine.get("t1")!.name).toBe("Updated");
  });
});

// ─── Protocol Registry Tests ───────────────────────────────────────────────

describe("ProtocolRegistry", () => {
  let registry: ProtocolRegistry;

  beforeEach(() => {
    registry = new ProtocolRegistry();
  });

  it("should have built-in protocol scanners", () => {
    expect(registry.count).toBeGreaterThan(0);
    const protocols = registry.listProtocols();
    expect(protocols).toContain("mysql");
    expect(protocols).toContain("redis");
    expect(protocols).toContain("mongodb");
    expect(protocols).toContain("postgresql");
  });

  it("should get a scanner by protocol name", () => {
    const scanner = registry.get("mysql");
    expect(scanner).toBeDefined();
    expect(scanner!.protocol).toBe("mysql");
    expect(scanner!.defaultPorts).toContain(3306);
  });

  it("should find scanners by port number", () => {
    const scanners = registry.getByPort(6379);
    expect(scanners.length).toBeGreaterThan(0);
    expect(scanners.some(s => s.protocol === "redis")).toBe(true);
  });

  it("should return empty array for unknown port", () => {
    const scanners = registry.getByPort(99999);
    expect(scanners.length).toBe(0);
  });
});

// ─── Intelligence Engine Tests ─────────────────────────────────────────────

describe("IntelligenceEngine", () => {
  let engine: IntelligenceEngine;

  beforeEach(() => {
    engine = new IntelligenceEngine();
  });

  it("should get DFIR-informed checks for SMB services", () => {
    const target: ScanTarget = {
      type: "ip",
      value: "10.0.0.1",
      services: { 445: "microsoft-ds" },
    };

    const checks = engine.getDFIRInformedChecks(target);
    expect(checks.length).toBeGreaterThan(0);
    expect(checks.some(c => c.includes("smb"))).toBe(true);
  });

  it("should get DFIR-informed checks for HTTP services", () => {
    const target: ScanTarget = {
      type: "domain",
      value: "example.com",
      services: { 80: "http", 443: "https" },
    };

    const checks = engine.getDFIRInformedChecks(target);
    expect(checks.some(c => c.includes("webshell") || c.includes("waf"))).toBe(true);
  });

  it("should get DFIR-informed checks for database services", () => {
    const target: ScanTarget = {
      type: "ip",
      value: "10.0.0.2",
      services: { 3306: "mysql", 6379: "redis" },
    };

    const checks = engine.getDFIRInformedChecks(target);
    expect(checks.some(c => c.includes("brute") || c.includes("noauth"))).toBe(true);
  });

  it("should return empty checks for target with no services", () => {
    const target: ScanTarget = {
      type: "domain",
      value: "example.com",
    };

    const checks = engine.getDFIRInformedChecks(target);
    expect(checks).toEqual([]);
  });

  it("should enrich a finding with risk score", async () => {
    const finding = makeFinding({
      severity: "critical",
      cves: ["CVE-2021-44228"],
      techniqueIds: ["T1190"],
    });

    const enriched = await engine.enrichFinding(finding);
    expect(enriched.riskScore).toBeDefined();
    expect(enriched.riskScore!.composite).toBeGreaterThan(0);
    expect(enriched.riskScore!.cvss).toBeGreaterThanOrEqual(8.0);
  });

  it("should compute higher risk for critical findings", async () => {
    const criticalFinding = makeFinding({ severity: "critical" });
    const lowFinding = makeFinding({ severity: "low" });

    const enrichedCritical = await engine.enrichFinding(criticalFinding);
    const enrichedLow = await engine.enrichFinding(lowFinding);

    expect(enrichedCritical.riskScore!.composite).toBeGreaterThan(
      enrichedLow.riskScore!.composite
    );
  });

  it("should prioritize templates by relevance", async () => {
    const templates = [
      makeTemplate({ id: "low-sev", severity: "low", tags: ["info"] }),
      makeTemplate({
        id: "critical-kev",
        severity: "critical",
        tags: ["kev"],
        references: { cves: ["CVE-2021-44228"] },
      }),
      makeTemplate({ id: "medium-sev", severity: "medium", tags: ["vuln"] }),
    ];

    const target: ScanTarget = { type: "domain", value: "example.com" };
    const prioritized = await engine.prioritizeTemplates(templates, target);

    // Critical with KEV should be first
    expect(prioritized[0].id).toBe("critical-kev");
    // Low severity should be last
    expect(prioritized[prioritized.length - 1].id).toBe("low-sev");
  });
});

// ─── AC3 Bridge Tests ──────────────────────────────────────────────────────

describe("AC3ScanForgeBridge", () => {
  let bridge: AC3ScanForgeBridge;

  beforeEach(() => {
    bridge = new AC3ScanForgeBridge();
  });

  it("should translate ScanForge findings to AC3 format", () => {
    const findings: ScanFinding[] = [
      makeFinding({
        severity: "critical",
        title: "SQL Injection",
        cves: ["CVE-2024-1234"],
        port: 443,
        protocol: "https",
        riskScore: { composite: 95, cvss: 9.8 },
      }),
      makeFinding({
        severity: "low",
        title: "Missing Header",
      }),
    ];

    const ac3Findings = bridge.translateFindings(findings);

    expect(ac3Findings.length).toBe(2);
    expect(ac3Findings[0].severity).toBe("Critical");
    expect(ac3Findings[0].title).toBe("SQL Injection");
    expect(ac3Findings[0].source).toContain("ScanForge:");
    expect(ac3Findings[0].status).toBe("open");
    expect(ac3Findings[0].riskScore).toBe(95);
    expect(ac3Findings[1].severity).toBe("Low");
  });

  it("should translate scanner results to AC3 format", () => {
    const job: ScanJob = {
      request: makeScanRequest(),
      status: "completed",
      progress: 100,
      findings: [],
      scannerResults: [
        { scanner: "nmap", status: "completed", durationMs: 5000, findingCount: 3 },
        { scanner: "nikto", status: "failed", durationMs: 1000, findingCount: 0, error: "timeout" },
        { scanner: "zap", status: "timeout", durationMs: 30000, findingCount: 1 },
      ],
    };

    const ac3Results = bridge.translateScannerResults(job);

    expect(ac3Results.length).toBe(3);
    expect(ac3Results[0].status).toBe("success");
    expect(ac3Results[1].status).toBe("error");
    expect(ac3Results[2].status).toBe("timeout");
  });

  it("should report not_found for unknown engagement", () => {
    const progress = bridge.getScanProgress(999999);
    expect(progress.status).toBe("not_found");
    expect(progress.scanId).toBeNull();
  });

  it("should map all severity levels correctly", () => {
    const severities: Array<{ input: ScanFinding["severity"]; expected: string }> = [
      { input: "critical", expected: "Critical" },
      { input: "high", expected: "High" },
      { input: "medium", expected: "Medium" },
      { input: "low", expected: "Low" },
      { input: "info", expected: "Informational" },
    ];

    for (const { input, expected } of severities) {
      const findings = bridge.translateFindings([makeFinding({ severity: input })]);
      expect(findings[0].severity).toBe(expected);
    }
  });
});
